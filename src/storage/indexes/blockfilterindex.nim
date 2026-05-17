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

import std/[options, os, streams, strformat, strutils]
import ./base
import ./gcs
import ../db
import ../undo as chainundo
import ../../primitives/[types, serialize]
import ../../crypto/hashing
import chronicles

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
  DbCodecVersion* = byte('V')      ## Key for codec format version (FIX-83)
  FilterFilePrefix* = "fltr"
  FilterFileSuffix* = ".dat"
  MaxFilterFileSize* = 16 * 1024 * 1024  ## 16 MiB per filter file

  ## On-disk codec format version for the BIP-158 filter index.
  ##
  ## v1 — Pre-FIX-83: BitWriter/BitReader packed bits LSB-first within each
  ##   byte (the W122 BUG-1 P0-CDIV regression).  `fltr*.dat` files contained
  ##   GCS-encoded filters that round-tripped locally but were byte-incompatible
  ##   with Bitcoin Core and every other BIP-158 impl.
  ## v2 — FIX-83: codec rewritten MSB-first matching Core
  ##   (`bitcoin-core/src/streams.h:303-358`).  `fltr*.dat` files are
  ##   byte-for-byte readable by Core IF the per-record wrapper is also
  ##   present — which v2 did NOT emit (raw GCS bytes only).
  ## v3 — FIX-87 (W121 G25 P1-CDIV): per-record disk layout now matches
  ##   Bitcoin Core's `BlockFilterIndex::WriteFilterToDisk`
  ##   (`bitcoin-core/src/index/blockfilterindex.cpp:177-232`):
  ##     block_hash (32 raw bytes) || CompactSize(filter_len) || filter_bytes
  ##   The read path verifies that the on-disk `block_hash` matches the hash
  ##   recorded for the DB index entry, giving us per-record corruption
  ##   detection (Core's `if (Hash(encoded_filter) != hash)` analogue).
  ##   On node restart with a v1 OR v2 index, the entire filter index is
  ##   dropped and re-built from the chainstate via the auto-rebuild path
  ##   below — v2 records lack the wrapper and cannot be salvaged.
  BlockFilterIndexCodecVersion* = 3'u32

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

proc codecVersionKey*(): seq[byte] =
  ## Key for the on-disk codec format version (FIX-83 / W122).
  @[DbCodecVersion]

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

proc readCodecVersion*(idx: BlockFilterIndex): uint32 =
  ## Read the codec format version stamped on this index.  An index that
  ## was never stamped (legacy fresh-write of unknown vintage, OR a
  ## pre-FIX-83 W122 LSB-first index) returns 0.
  let data = idx.db.get(cfMeta, codecVersionKey())
  if data.isNone or data.get().len < 4:
    return 0
  var r = BinaryReader(data: data.get(), pos: 0)
  let v = r.readInt32LE()
  if v < 0:
    return 0
  uint32(v)

proc writeCodecVersion*(idx: BlockFilterIndex, version: uint32) =
  ## Stamp the on-disk codec format version onto the index.
  var w = BinaryWriter()
  w.writeInt32LE(int32(version))
  idx.db.put(cfMeta, codecVersionKey(), w.data)

proc resetIndex*(idx: BlockFilterIndex) =
  ## Drop the entire filter index — DB entries AND on-disk fltr*.dat
  ## files — and reset best-block/prev-header state so the next sync
  ## pass rebuilds from genesis.  Used by the FIX-83 / W122 codec-version
  ## migration (pre-FIX-83 LSB-first GCS bytes, unreadable by Core peers)
  ## AND the FIX-87 / W121 G25 migration (v2 records lack the
  ## block_hash + CompactSize wrapper Core expects per file record).
  ##
  ## Safe to call when the DB has no prior filter entries (no-op on the
  ## DB side, just deletes any stray .dat files and rewrites the version
  ## stamp).
  warn "blockfilterindex: dropping legacy filter index for codec migration",
       dir = idx.dataDir, target_version = BlockFilterIndexCodecVersion

  # 1. Delete all height-keyed, hash-keyed, prev-header, best-block,
  # best-height entries from the meta CF.  We iterate and collect keys
  # first, then delete, to avoid mutating during iteration.
  var keysToDelete: seq[seq[byte]]
  for kv in idx.db.iterCf(cfMeta):
    if kv.key.len == 0:
      continue
    let prefix = kv.key[0]
    if prefix == DbFilterIndex or prefix == DbFilterByHash or
       prefix == DbPrevHeader or prefix == DbBestBlock or
       prefix == DbBestHeight:
      keysToDelete.add(kv.key)
  for k in keysToDelete:
    idx.db.delete(cfMeta, k)

  # 2. Delete every fltr?????.dat file in the index directory.  The
  # bytes inside them are either LSB-first GCS encodings (v1) or v2
  # records lacking the per-record block_hash + CompactSize wrapper
  # (FIX-87 / W121 G25).  Neither can be salvaged — v1 is poison to
  # Core peers; v2 lacks the wrapper, so the file offsets recorded in
  # the DB index point at bytes that the v3 reader cannot parse.
  if dirExists(idx.dataDir):
    for path in walkDirRec(idx.dataDir, yieldFilter = {pcFile}):
      let name = extractFilename(path)
      if name.startsWith(FilterFilePrefix) and name.endsWith(FilterFileSuffix):
        try:
          removeFile(path)
        except OSError as e:
          warn "blockfilterindex: failed to remove legacy filter file",
               path = path, error = e.msg

  # 3. Reset in-memory state and stamp the new codec version so the
  # next start sees a clean v2 index.
  idx.bestHeight = -1
  idx.bestBlockHash = BlockHash(default(array[32, byte]))
  idx.prevFilterHeader = default(array[32, byte])
  idx.currentFileNum = 0
  idx.currentFileSize = 0
  idx.writeCodecVersion(BlockFilterIndexCodecVersion)

  info "blockfilterindex: legacy index dropped; will rebuild on next sync",
       new_codec_version = BlockFilterIndexCodecVersion

proc maybeMigrateCodec*(idx: BlockFilterIndex): bool =
  ## On startup: if the index has data but a stale (or absent) codec
  ## version stamp, drop it and re-stamp at the current version.  Returns
  ## true if a migration was performed.  Idempotent: a v2 index returns
  ## false without touching disk.
  ##
  ## The "absent version + bestHeight >= 0" branch is the W122 BUG-1
  ## footprint: nodes that built any filters before FIX-83 landed have
  ## v1 (LSB-first) bytes in fltr*.dat AND no version key written.
  let stamped = idx.readCodecVersion()
  if stamped == BlockFilterIndexCodecVersion:
    return false

  # Distinguish "fresh empty index, nothing to migrate" from "legacy
  # index with stale bytes".  A fresh empty index has no best-block key,
  # no fltr*.dat files, and no filter entries — we can just stamp the
  # current version and move on.
  let bestHeightLoaded = idx.bestHeight >= 0
  let hasOldFiles = block:
    var found = false
    if dirExists(idx.dataDir):
      for path in walkDirRec(idx.dataDir, yieldFilter = {pcFile}):
        let name = extractFilename(path)
        if name.startsWith(FilterFilePrefix) and name.endsWith(FilterFileSuffix):
          found = true
          break
    found

  if not bestHeightLoaded and not hasOldFiles:
    # Pristine: just stamp.
    idx.writeCodecVersion(BlockFilterIndexCodecVersion)
    return false

  # Legacy data present (either explicit v1 stamp or unstamped pre-FIX-83
  # filters).  Drop everything and rebuild from genesis on next sync.
  let cause = if stamped <= 1'u32:
                "W122 FIX-83 BIP-158 codec MSB-first rewrite"
              elif stamped == 2'u32:
                "W121 G25 FIX-87 per-record block_hash + CompactSize wrapper"
              else:
                "unknown legacy codec version"
  warn "blockfilterindex: codec version mismatch — rebuilding index",
       stamped_version = stamped,
       target_version = BlockFilterIndexCodecVersion,
       cause = cause
  idx.resetIndex()
  true

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

    # FIX-83 (W122): if the on-disk codec version is missing or stale, drop
    # the index and rebuild on next sync.  See `BlockFilterIndexCodecVersion`
    # commentary at the top of the file.  This runs *before* picking up the
    # current file number/size below so the file-walk sees the (now-empty)
    # directory after migration.
    discard result.maybeMigrateCodec()

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

proc encodeFilterRecord*(blockHash: BlockHash,
                         encodedFilter: openArray[byte]): seq[byte] =
  ## Serialise one on-disk filter record using the Bitcoin Core layout
  ## from `BlockFilterIndex::WriteFilterToDisk`
  ## (bitcoin-core/src/index/blockfilterindex.cpp:177-232):
  ##
  ##   block_hash (32 raw bytes) || CompactSize(filter_len) || filter_bytes
  ##
  ## The Core write path uses CDataStream operator<< which (a) writes
  ## uint256 as 32 raw bytes (uint256.h:111-114) and (b) writes vector<u8>
  ## as CompactSize(len) || raw bytes (serialize.h Serialize for
  ## std::vector<u8>).  This helper is shared by `writeFilterRecord` and
  ## by the Core-compat round-trip test (tests/test_blockfilter.nim).
  ##
  ## Source-level regression guard: callers MUST hand both the canonical
  ## block hash AND the encoded GCS filter bytes.  Emitting the wrapper
  ## without the prefix (raw filter bytes only — the FIX-87 / W121 G25
  ## pre-fix shape) reverts the file to a layout no Core node and no
  ## post-FIX-87 nimrod can decode.
  var w = BinaryWriter()
  w.writeBytes(array[32, byte](blockHash))
  w.writeVarBytes(encodedFilter)
  w.data

proc writeFilterRecord*(idx: BlockFilterIndex, blockHash: BlockHash,
                        encodedFilter: seq[byte]):
                        tuple[fileNum: int32, filePos: int32] =
  ## Append a single filter record to the active fltr*.dat using the
  ## Core-parity per-record format (see `encodeFilterRecord`).  Returns
  ## the (fileNum, filePos) pair to be stored in the DB index — the
  ## position points at the START of the record (i.e. the block_hash
  ## byte), exactly like Core's `FlatFilePos` semantics.
  ##
  ## Reference: bitcoin-core/src/index/blockfilterindex.cpp:177-232
  ## (`WriteFilterToDisk`) — same "if data won't fit, roll to next file"
  ## logic, same record framing.
  let record = encodeFilterRecord(blockHash, encodedFilter)
  let recordSize = record.len

  # If writing the filter would overflow the file, flush and move to the
  # next one (Core's `pos.nPos + data_size > MAX_FLTR_FILE_SIZE` branch).
  if idx.currentFileSize + int32(recordSize) > MaxFilterFileSize:
    idx.currentFileNum += 1
    idx.currentFileSize = 0

  let fileNum = idx.currentFileNum
  let filePos = idx.currentFileSize

  let fs = idx.openFilterFile(fileNum, forWrite = true)
  if fs == nil:
    return (-1, -1)
  defer: fs.close()

  fs.setPosition(int(filePos))
  for b in record:
    fs.write(char(b))
  fs.flush()

  idx.currentFileSize += int32(recordSize)
  (fileNum, filePos)

proc readFilterRecord*(idx: BlockFilterIndex, fileNum: int32, filePos: int32,
                       expectedBlockHash: BlockHash): Option[seq[byte]] =
  ## Read a single filter record from disk at the given position and
  ## verify the on-disk block_hash matches `expectedBlockHash`.  Returns
  ## just the encoded GCS filter bytes (NOT the wrapper) on success.
  ##
  ## Layout (FIX-87 / W121 G25, matching Core):
  ##   block_hash (32 raw bytes) || CompactSize(filter_len) || filter_bytes
  ##
  ## Returns none on file-not-found, truncated record, oversized length,
  ## OR block_hash mismatch (corruption detection — analogue of Core's
  ## `if (Hash(encoded_filter) != hash)` check, but at the block-hash
  ## layer because the GCS hash is stored separately in the DB entry).
  ##
  ## Reference: bitcoin-core/src/index/blockfilterindex.cpp:151-175
  ## (`ReadFilterFromDisk`).
  let path = idx.filterFilePath(fileNum)
  if not fileExists(path):
    return none(seq[byte])
  let fileSize = int(getFileSize(path))

  let fs = idx.openFilterFile(fileNum, forWrite = false)
  if fs == nil:
    return none(seq[byte])
  defer: fs.close()

  # Read the full remaining file segment into a buffer, then parse via
  # the BinaryReader so we get the same CompactSize semantics as the
  # rest of the codebase.  Records are bounded by `MaxFilterFileSize`
  # (16 MiB) so the in-memory copy is safe.
  let segmentSize = fileSize - int(filePos)
  if segmentSize < 32:
    return none(seq[byte])

  fs.setPosition(int(filePos))
  var segment = newSeq[byte](segmentSize)
  for i in 0 ..< segmentSize:
    segment[i] = byte(fs.readChar())

  # First 32 bytes: on-disk block_hash.
  var hashBuf: array[32, byte]
  copyMem(addr hashBuf[0], addr segment[0], 32)
  if BlockHash(hashBuf) != expectedBlockHash:
    warn "blockfilterindex: on-disk block_hash mismatch (corruption?)",
         fileNum = fileNum, filePos = filePos,
         expected = $expectedBlockHash, on_disk = $BlockHash(hashBuf)
    return none(seq[byte])

  # Then CompactSize(filter_len) || filter_bytes.
  var r = BinaryReader(data: segment, pos: 32)
  try:
    let filterLen = r.readCompactSize()
    if filterLen > uint64(segment.len - r.pos):
      return none(seq[byte])
    let filterBytes = r.readBytes(int(filterLen))
    return some(filterBytes)
  except SerializationError:
    return none(seq[byte])
  except CatchableError:
    return none(seq[byte])

proc writeFilter*(idx: BlockFilterIndex, blockHash: BlockHash,
                  encodedFilter: seq[byte]):
                  tuple[fileNum: int32, filePos: int32]
                  {.deprecated: "use writeFilterRecord".} =
  ## Back-compat shim — forwards to `writeFilterRecord` (FIX-87 / W121 G25).
  ## The old raw-bytes signature emitted a record that no Core node could
  ## read and that nimrod's own (post-FIX-87) reader will reject.  Keep
  ## this proc only so out-of-tree callers see a deprecation hint instead
  ## of a hard compile error; in-tree callers MUST use the record API.
  idx.writeFilterRecord(blockHash, encodedFilter)

proc readFilter*(idx: BlockFilterIndex, fileNum: int32, filePos: int32,
                 expectedBlockHash: BlockHash): Option[seq[byte]]
                 {.deprecated: "use readFilterRecord".} =
  ## Back-compat shim — forwards to `readFilterRecord` (FIX-87 / W121 G25).
  idx.readFilterRecord(fileNum, filePos, expectedBlockHash)

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

  # Write filter to flat file using the Core-parity per-record layout
  # (FIX-87 / W121 G25): block_hash + CompactSize(filter_len) + filter_bytes.
  let (fileNum, filePos) = idx.writeFilterRecord(blockInfo.hash, encodedFilter)
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
  ## Get full filter by height.  Reads the per-record on-disk wrapper
  ## (FIX-87 / W121 G25) which carries the GCS filter byte length, so we
  ## return EXACTLY the encoded bytes — no padding, no 1 MiB max read,
  ## no `skipDecode` hand-wave to swallow garbage.
  let entryOpt = idx.getFilterEntry(height)
  if entryOpt.isNone:
    return none(BlockFilter)

  let entry = entryOpt.get()

  # Read the record by its DB-recorded position and verify the on-disk
  # block_hash matches the one the caller asked about (Core's analogue:
  # `if (Hash(encoded_filter) != hash)` corruption check).
  let filterDataOpt = idx.readFilterRecord(entry.fileNum, entry.filePos, blockHash)
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

# ============================================================================
# Block-connect / IBD-backfill entry points
# ============================================================================
#
# These are the population hooks called by the consensus pipeline whenever a
# block is connected to the active chain (live IBD, P2P sync, RPC submitblock,
# regtest mining, genesis init, post-startup catchup).  They translate from
# nimrod's `storage/undo.BlockUndo` (the chainstate-side type) into the
# `storage/indexes/base.BlockInfo` shape that `customAppend` consumes, and
# then go through `processBlock` so `bestBlockHash`/`bestHeight` advance
# atomically with the filter write.
#
# Reference: bitcoin-core/src/index/blockfilterindex.cpp::CustomAppend +
# bitcoin-core/src/index/base.cpp::BaseIndex::ConnectBlock.

proc convertBlockUndo(src: chainundo.BlockUndo): base.BlockUndo =
  ## Convert chainstate-side BlockUndo (storage/undo.BlockUndo) to the
  ## index-side BlockUndo (storage/indexes/base.BlockUndo).  The two types
  ## are field-compatible but distinct (base.nim defines its own to avoid
  ## a circular import on the chainstate module).
  result.txUndo = newSeq[base.TxUndo](src.txUndo.len)
  for i, srcTx in src.txUndo:
    var dstTx = base.TxUndo()
    dstTx.prevOutputs = newSeq[base.SpentOutput](srcTx.prevOutputs.len)
    for j, srcSpent in srcTx.prevOutputs:
      dstTx.prevOutputs[j] = base.SpentOutput(
        output: srcSpent.output,
        height: srcSpent.height,
        isCoinbase: srcSpent.isCoinbase
      )
    result.txUndo[i] = dstTx

proc addBlock*(idx: BlockFilterIndex, blk: Block, blockHash: BlockHash,
               height: int32, blockUndo: chainundo.BlockUndo): bool =
  ## Index a single block: compute + persist its BIP-158 basic filter,
  ## advance the index's best-block tracker.  Safe to no-op when the index
  ## is disabled or already past `height`; callers do NOT need to gate.
  ##
  ## Mirrors Bitcoin Core's BaseIndex::ConnectBlock → CustomAppend →
  ## SetBestBlockIndex sequence.  The combined `processBlock` call writes
  ## both the filter entry AND the bestBlockKey/bestHeightKey in two
  ## separate batches; if the second fails, the index will re-pick-up the
  ## same height on next start (idempotent — `customAppend` overwrites the
  ## same height key, and the flat-file fltr*.dat appends a duplicate
  ## record that is then orphaned by the new metadata pointer).
  if idx == nil or not idx.enabled:
    return true

  # Skip blocks already indexed.  The IBD backfill loop in the daemon may
  # call this for a contiguous range; the live-sync hook calls it block by
  # block.  Either way we only ever advance.
  if height <= idx.bestHeight:
    return true

  let info = base.BlockInfo(
    hash: blockHash,
    prevHash: blk.header.prevBlock,
    height: height,
    data: some(blk),
    undoData: some(convertBlockUndo(blockUndo)),
    fileNum: 0,
    dataPos: 0
  )

  try:
    if not idx.processBlock(info):
      warn "blockfilterindex: customAppend failed",
           height = height, hash = $blockHash
      return false
  except CatchableError as e:
    warn "blockfilterindex: addBlock raised, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  except Exception as e:
    # Defensive: index dispatch goes through a `method`, which Nim cannot
    # raises-track, so a missing handler below in the implementation could
    # surface as a bare `Exception`.  Keep the connect-block path live.
    warn "blockfilterindex: addBlock raised non-Catchable, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  true

proc removeBlock*(idx: BlockFilterIndex, blockHash: BlockHash,
                  prevHash: BlockHash, height: int32): bool =
  ## Roll the filter index back across a single block disconnect.  This is
  ## the symmetric counterpart to `addBlock` and is invoked by the
  ## chainstate disconnect path (legacy `disconnectBlock` and Pattern-D
  ## `handleReorg`).
  ##
  ## Behavior, per Bitcoin Core's BaseIndex::BlockDisconnected →
  ## blockfilterindex.cpp::CustomRemove:
  ##   1. Copy the height-keyed filter entry to the hash-keyed index, so
  ##      the disconnected filter is still retrievable for light-client
  ##      reconciliation while another block re-takes the height slot.
  ##   2. Roll `prevFilterHeader` back to the parent's filter header (read
  ##      from DB at height-1), so the next `customAppend` chains onto
  ##      the correct filter-header history.
  ##   3. Move best-block back to (prevHash, height-1) via
  ##      `BaseIndex::saveBestBlock` (in `revertBlock`).
  ##
  ## Safe to no-op when the index is nil/disabled or when the recorded
  ## bestHeight is already at-or-below height-1 (idempotent re-replay).
  ## Callers do NOT need to gate.
  ##
  ## Reference: bitcoin-core/src/index/base.cpp::BaseIndex::BlockDisconnected
  ## + bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove.
  if idx == nil or not idx.enabled:
    return true

  # Already rolled back past this height — nothing to do.  Either the
  # caller is replaying a disconnect after an earlier crash-recovery, or
  # a reorg-staging error is unwinding us already.
  if idx.bestHeight < height:
    return true

  let info = base.BlockInfo(
    hash: blockHash,
    prevHash: prevHash,
    height: height,
    data: none(Block),
    undoData: none(base.BlockUndo),
    fileNum: 0,
    dataPos: 0
  )

  try:
    if not idx.revertBlock(info):
      warn "blockfilterindex: customRemove failed",
           height = height, hash = $blockHash
      return false
  except CatchableError as e:
    warn "blockfilterindex: removeBlock raised, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  except Exception as e:
    # Defensive: see addBlock for rationale.  Keep the disconnect path live.
    warn "blockfilterindex: removeBlock raised non-Catchable, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  true
