## Block Filter Index (blockfilterindex)
## Stores BIP 157/158 compact block filters for light client support
##
## For each block, computes and stores:
##   - GCS filter of all scriptPubKeys (outputs + spent inputs)
##   - Filter hash (SHA256 of encoded filter)
##   - Filter header (chained commitment: SHA256(filterHash || prevHeader))
##
## Filter data is stored in flat files (fltr?????.dat) for efficient storage.
## Filter metadata (hash, header, file position) is indexed by height.
##
## Storage:
##   Key: height (big-endian for ordered iteration)
##   Value: filterHash (32) || filterHeader (32) || fileNum (4) || filePos (4)
##
## Reference: Bitcoin Core /src/index/blockfilterindex.cpp
## Reference: BIP 157 https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
## Reference: BIP 158 https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

import std/[options, os, streams, strformat]
import ./base
import ./gcs
import ../db
import ../../primitives/[types, serialize]
import ../../crypto/hashing

type
  ## Filter metadata stored in database
  FilterIndexEntry* = object
    filterHash*: array[32, byte]    ## SHA256 of encoded filter
    filterHeader*: array[32, byte]  ## Chained filter header
    fileNum*: int32                 ## Filter file number
    filePos*: int32                 ## Position in filter file

  ## Block filter index
  BlockFilterIndex* = ref object of BaseIndex
    filterType*: BlockFilterType
    enabled*: bool
    dataDir*: string               ## Directory for fltr*.dat files
    currentFileNum*: int32         ## Current filter file number
    currentFileSize*: int32        ## Current filter file size
    prevFilterHeader*: array[32, byte]  ## Previous filter header for chaining

const
  DbFilterIndex* = byte('f')       ## Key prefix for filter index entries
  DbFilterByHash* = byte('g')      ## Key prefix for hash-indexed entries
  DbPrevHeader* = byte('P')        ## Key for previous filter header
  FilterFilePrefix* = "fltr"
  FilterFileSuffix* = ".dat"
  MaxFilterFileSize* = 16 * 1024 * 1024  ## 16 MiB per filter file

# ============================================================================
# FilterIndexEntry serialization
# ============================================================================

proc serializeFilterEntry*(entry: FilterIndexEntry): seq[byte] =
  var w = BinaryWriter()
  w.writeBytes(entry.filterHash)
  w.writeBytes(entry.filterHeader)
  w.writeInt32LE(entry.fileNum)
  w.writeInt32LE(entry.filePos)
  w.data

proc deserializeFilterEntry*(data: seq[byte]): FilterIndexEntry =
  if data.len < 72:
    raise newException(IndexError, "invalid FilterIndexEntry data")
  var r = BinaryReader(data: data, pos: 0)
  result.filterHash = r.readHash()
  result.filterHeader = r.readHash()
  result.fileNum = r.readInt32LE()
  result.filePos = r.readInt32LE()

# ============================================================================
# Key construction
# ============================================================================

proc filterHeightKey*(height: int32): seq[byte] =
  ## Key for height-indexed filter entry
  let h = cast[uint32](height)
  result = @[DbFilterIndex]
  result.add(byte((h shr 24) and 0xff))
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))

proc filterHashKey*(blockHash: BlockHash): seq[byte] =
  ## Key for hash-indexed filter entry (for reorg recovery)
  result = @[DbFilterByHash]
  result.add(@(array[32, byte](blockHash)))

proc prevHeaderKey*(): seq[byte] =
  @[DbPrevHeader]

# ============================================================================
# Filter file management
# ============================================================================

proc filterFileName*(fileNum: int32): string =
  fmt"{FilterFilePrefix}{fileNum:05d}{FilterFileSuffix}"

proc filterFilePath*(idx: BlockFilterIndex, fileNum: int32): string =
  idx.dataDir / filterFileName(fileNum)

proc openFilterFile*(idx: BlockFilterIndex, fileNum: int32, forWrite: bool = false): FileStream =
  let path = idx.filterFilePath(fileNum)
  if forWrite:
    createDir(idx.dataDir)
    if not fileExists(path):
      result = newFileStream(path, fmWrite)
    else:
      result = newFileStream(path, fmReadWriteExisting)
  else:
    if fileExists(path):
      result = newFileStream(path, fmRead)
    else:
      result = nil

proc getFilterFileSize*(idx: BlockFilterIndex, fileNum: int32): int32 =
  let path = idx.filterFilePath(fileNum)
  if fileExists(path):
    int32(getFileSize(path))
  else:
    0

# ============================================================================
# BlockFilterIndex implementation
# ============================================================================

proc newBlockFilterIndex*(db: Database, dataDir: string,
                          filterType: BlockFilterType = bftBasic,
                          enabled: bool = true): BlockFilterIndex =
  result = BlockFilterIndex(
    name: "blockfilterindex",
    db: db,
    cfHandle: cfMeta,  # Use meta CF for filter index
    state: isIdle,
    bestHeight: -1,
    stopRequested: false,
    filterType: filterType,
    enabled: enabled,
    dataDir: dataDir / "indexes" / "blockfilter",
    currentFileNum: 0,
    currentFileSize: 0
  )

  if enabled:
    createDir(result.dataDir)
    discard result.loadBestBlock()

    # Load previous filter header
    let prevData = db.get(cfMeta, prevHeaderKey())
    if prevData.isSome and prevData.get().len == 32:
      copyMem(addr result.prevFilterHeader[0], addr prevData.get()[0], 32)

    # Find current file number and size
    while fileExists(result.filterFilePath(result.currentFileNum)):
      let size = result.getFilterFileSize(result.currentFileNum)
      if size < MaxFilterFileSize:
        result.currentFileSize = size
        break
      result.currentFileNum += 1
      result.currentFileSize = 0

method customInit*(idx: BlockFilterIndex): bool =
  idx.enabled

proc writeFilter*(idx: BlockFilterIndex, encodedFilter: seq[byte]): tuple[fileNum: int32, filePos: int32] =
  ## Write encoded filter to flat file, returns position
  let filterSize = encodedFilter.len

  # Check if we need a new file
  if idx.currentFileSize + int32(filterSize) > MaxFilterFileSize:
    idx.currentFileNum += 1
    idx.currentFileSize = 0

  let fileNum = idx.currentFileNum
  let filePos = idx.currentFileSize

  let fs = idx.openFilterFile(fileNum, forWrite = true)
  if fs == nil:
    return (-1, -1)
  defer: fs.close()

  fs.setPosition(int(filePos))
  for b in encodedFilter:
    fs.write(char(b))
  fs.flush()

  idx.currentFileSize += int32(filterSize)
  (fileNum, filePos)

proc readFilter*(idx: BlockFilterIndex, fileNum: int32, filePos: int32,
                 filterSize: int): Option[seq[byte]] =
  ## Read encoded filter from flat file
  let fs = idx.openFilterFile(fileNum, forWrite = false)
  if fs == nil:
    return none(seq[byte])
  defer: fs.close()

  fs.setPosition(int(filePos))
  var data = newSeq[byte](filterSize)
  for i in 0 ..< filterSize:
    data[i] = byte(fs.readChar())

  some(data)

method customAppend*(idx: BlockFilterIndex, blockInfo: BlockInfo): bool =
  ## Process a new block: compute and store filter
  if not idx.enabled:
    return true

  if blockInfo.data.isNone:
    return false

  let blk = blockInfo.data.get()

  # Extract filter elements from block and undo data
  var spentOutputs: seq[gcs.SpentOutput] = @[]
  if blockInfo.undoData.isSome:
    let undo = blockInfo.undoData.get()
    for txUndo in undo.txUndo:
      for spent in txUndo.prevOutputs:
        spentOutputs.add(gcs.SpentOutput(
          output: spent.output,
          height: spent.height,
          isCoinbase: spent.isCoinbase
        ))

  let elements = extractBasicFilterElements(blk, spentOutputs)

  # Build filter
  let filter = newBlockFilter(idx.filterType, blockInfo.hash, elements)
  let encodedFilter = getEncodedFilter(filter)

  # Compute filter hash and header
  let filterHash = getFilterHash(filter)
  let filterHeader = computeFilterHeader(filter, idx.prevFilterHeader)

  # Write filter to flat file
  let (fileNum, filePos) = idx.writeFilter(encodedFilter)
  if fileNum < 0:
    return false

  # Store metadata in database
  let entry = FilterIndexEntry(
    filterHash: filterHash,
    filterHeader: filterHeader,
    fileNum: fileNum,
    filePos: filePos
  )

  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  batch.put(idx.cfHandle, filterHeightKey(blockInfo.height), serializeFilterEntry(entry))
  batch.put(idx.cfHandle, prevHeaderKey(), @filterHeader)

  idx.db.write(batch)

  # Update state
  idx.prevFilterHeader = filterHeader

  true

method customRemove*(idx: BlockFilterIndex, blockInfo: BlockInfo): bool =
  ## Remove a block during reorg: copy height entry to hash index
  if not idx.enabled:
    return true

  # Copy height-indexed entry to hash-indexed for recovery
  let heightData = idx.db.get(idx.cfHandle, filterHeightKey(blockInfo.height))
  if heightData.isSome:
    idx.db.put(idx.cfHandle, filterHashKey(blockInfo.hash), heightData.get())

  # Restore previous filter header from parent block
  if blockInfo.height > 0:
    let parentData = idx.db.get(idx.cfHandle, filterHeightKey(blockInfo.height - 1))
    if parentData.isSome:
      let parentEntry = deserializeFilterEntry(parentData.get())
      idx.prevFilterHeader = parentEntry.filterHeader
      idx.db.put(idx.cfHandle, prevHeaderKey(), @(idx.prevFilterHeader))
  else:
    idx.prevFilterHeader = default(array[32, byte])
    idx.db.put(idx.cfHandle, prevHeaderKey(), @(idx.prevFilterHeader))

  true

# ============================================================================
# Public API
# ============================================================================

proc getFilterEntry*(idx: BlockFilterIndex, height: int32): Option[FilterIndexEntry] =
  ## Get filter metadata by height
  if not idx.enabled:
    return none(FilterIndexEntry)

  let data = idx.db.get(idx.cfHandle, filterHeightKey(height))
  if data.isNone:
    return none(FilterIndexEntry)

  try:
    some(deserializeFilterEntry(data.get()))
  except:
    none(FilterIndexEntry)

proc getFilterEntryByHash*(idx: BlockFilterIndex, blockHash: BlockHash): Option[FilterIndexEntry] =
  ## Get filter metadata by block hash (for reorged blocks)
  if not idx.enabled:
    return none(FilterIndexEntry)

  let data = idx.db.get(idx.cfHandle, filterHashKey(blockHash))
  if data.isNone:
    return none(FilterIndexEntry)

  try:
    some(deserializeFilterEntry(data.get()))
  except:
    none(FilterIndexEntry)

proc getFilter*(idx: BlockFilterIndex, height: int32,
                blockHash: BlockHash): Option[BlockFilter] =
  ## Get full filter by height
  let entryOpt = idx.getFilterEntry(height)
  if entryOpt.isNone:
    return none(BlockFilter)

  let entry = entryOpt.get()

  # We need to read the filter size from the encoded data
  # For now, read a reasonable max and let GCS parsing handle it
  let filterDataOpt = idx.readFilter(entry.fileNum, entry.filePos, 1024 * 1024)
  if filterDataOpt.isNone:
    return none(BlockFilter)

  try:
    some(newBlockFilter(idx.filterType, blockHash, filterDataOpt.get(), skipDecode = true))
  except:
    none(BlockFilter)

proc getFilterHeader*(idx: BlockFilterIndex, height: int32): Option[array[32, byte]] =
  ## Get filter header by height
  let entryOpt = idx.getFilterEntry(height)
  if entryOpt.isNone:
    return none(array[32, byte])
  some(entryOpt.get().filterHeader)

proc getFilterHash*(idx: BlockFilterIndex, height: int32): Option[array[32, byte]] =
  ## Get filter hash by height
  let entryOpt = idx.getFilterEntry(height)
  if entryOpt.isNone:
    return none(array[32, byte])
  some(entryOpt.get().filterHash)
