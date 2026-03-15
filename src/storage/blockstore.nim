## Flat file block storage for Bitcoin blocks
## Stores blocks in blk{nnnnn}.dat files matching Bitcoin Core's format
##
## File format: Each block is prefixed with [4-byte magic][4-byte size LE]
## File size capped at 128 MiB (MaxBlockfileSize)
## Pre-allocation in 16 MiB chunks (BlockfileChunkSize)
##
## References:
## - Bitcoin Core: node/blockstorage.cpp (SaveBlockToDisk, ReadBlockFromDisk)
## - Bitcoin Core: flatfile.cpp (FlatFileSeq, FlatFilePos)

import std/[os, options, streams, strformat]
import ./db
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../consensus/params

type
  BlockStoreError* = object of CatchableError

  ## Position within a flat file
  BlockFilePos* = object
    fileNum*: int32       ## File number (blk00000.dat = 0)
    dataPos*: int32       ## Position of block data (after header)

  ## Metadata about a block file
  BlockFileInfo* = object
    nBlocks*: uint32      ## Number of blocks stored in this file
    nSize*: uint32        ## Used bytes in the block file
    nHeightFirst*: uint32 ## Lowest block height in this file
    nHeightLast*: uint32  ## Highest block height in this file
    nTimeFirst*: uint64   ## Earliest block timestamp
    nTimeLast*: uint64    ## Latest block timestamp

  ## Block index entry stored in RocksDB
  ## Maps block hash -> file location + metadata
  BlockIndexEntry* = object
    fileNum*: int32       ## File number
    dataPos*: int32       ## Position of block data in blk file
    undoPos*: int32       ## Position of undo data in rev file (-1 if none)
    height*: int32        ## Block height
    nTx*: uint32          ## Number of transactions
    status*: uint8        ## Block validation status

  ## Manages flat file block storage
  BlockFileManager* = ref object
    dataDir*: string
    currentFileNum*: int32
    currentFileSize*: int32
    fileInfos*: seq[BlockFileInfo]  ## Cached file metadata
    params*: ConsensusParams
    db*: Database         ## RocksDB for block index

const
  BlockFilePrefix* = "blk"
  BlockFileSuffix* = ".dat"
  StorageHeaderBytes* = 8           ## 4 bytes magic + 4 bytes size
  MaxBlockfileSize* = 128 * 1024 * 1024  ## 128 MiB per file
  BlockfileChunkSize* = 0x1000000   ## 16 MiB pre-allocation chunks
  MaxBlockSerializedSize* = 4_000_000  ## Max block size (4MB with witness)

  # Block status flags (matching Bitcoin Core)
  BlockHaveData* = 8'u8
  BlockHaveUndo* = 16'u8
  BlockValidated* = 32'u8
  BlockFailed* = 64'u8

# ============================================================================
# File name helpers
# ============================================================================

proc blockFileName*(fileNum: int32): string =
  ## Generate block file name: blk00000.dat, blk00001.dat, etc.
  fmt"{BlockFilePrefix}{fileNum:05d}{BlockFileSuffix}"

proc blockFilePath*(bfm: BlockFileManager, fileNum: int32): string =
  bfm.dataDir / blockFileName(fileNum)

# ============================================================================
# Position helpers
# ============================================================================

proc isNull*(pos: BlockFilePos): bool =
  pos.fileNum < 0 or pos.dataPos < 0

proc nullPos*(): BlockFilePos =
  BlockFilePos(fileNum: -1, dataPos: -1)

# ============================================================================
# BlockFileInfo serialization
# ============================================================================

proc serializeBlockFileInfo*(info: BlockFileInfo): seq[byte] =
  var w = BinaryWriter()
  w.writeUint32LE(info.nBlocks)
  w.writeUint32LE(info.nSize)
  w.writeUint32LE(info.nHeightFirst)
  w.writeUint32LE(info.nHeightLast)
  w.writeUint64LE(info.nTimeFirst)
  w.writeUint64LE(info.nTimeLast)
  w.data

proc deserializeBlockFileInfo*(data: seq[byte]): BlockFileInfo =
  var r = BinaryReader(data: data, pos: 0)
  result.nBlocks = r.readUint32LE()
  result.nSize = r.readUint32LE()
  result.nHeightFirst = r.readUint32LE()
  result.nHeightLast = r.readUint32LE()
  result.nTimeFirst = r.readUint64LE()
  result.nTimeLast = r.readUint64LE()

# ============================================================================
# BlockIndexEntry serialization
# ============================================================================

proc serializeBlockIndexEntry*(entry: BlockIndexEntry): seq[byte] =
  var w = BinaryWriter()
  w.writeInt32LE(entry.fileNum)
  w.writeInt32LE(entry.dataPos)
  w.writeInt32LE(entry.undoPos)
  w.writeInt32LE(entry.height)
  w.writeUint32LE(entry.nTx)
  w.writeUint8(entry.status)
  w.data

proc deserializeBlockIndexEntry*(data: seq[byte]): BlockIndexEntry =
  var r = BinaryReader(data: data, pos: 0)
  result.fileNum = r.readInt32LE()
  result.dataPos = r.readInt32LE()
  result.undoPos = r.readInt32LE()
  result.height = r.readInt32LE()
  result.nTx = r.readUint32LE()
  result.status = r.readUint8()

# ============================================================================
# Database key helpers
# ============================================================================

proc blockFileInfoKey*(fileNum: int32): seq[byte] =
  ## Key for block file info: 'f' prefix + 4-byte file number BE
  result = @[byte('f')]
  result.add(byte((fileNum shr 24) and 0xff))
  result.add(byte((fileNum shr 16) and 0xff))
  result.add(byte((fileNum shr 8) and 0xff))
  result.add(byte(fileNum and 0xff))

proc blockIndexKey*(hash: BlockHash): seq[byte] =
  ## Key for block index entry: 'b' prefix + block hash
  result = @[byte('b')]
  result.add(@(array[32, byte](hash)))

proc lastBlockFileKey*(): seq[byte] =
  ## Key for storing the current block file number
  @[byte('l')]

# ============================================================================
# File operations
# ============================================================================

proc openBlockFile*(bfm: BlockFileManager, fileNum: int32, forWrite: bool = false): FileStream =
  ## Open a block file for reading or writing
  let path = bfm.blockFilePath(fileNum)
  if forWrite:
    createDir(bfm.dataDir)
    if not fileExists(path):
      # Create new file
      result = newFileStream(path, fmWrite)
    else:
      # Open for read/write (append)
      result = newFileStream(path, fmReadWriteExisting)
  else:
    if fileExists(path):
      result = newFileStream(path, fmRead)
    else:
      result = nil

proc getFileSize*(bfm: BlockFileManager, fileNum: int32): int64 =
  ## Get size of a block file
  let path = bfm.blockFilePath(fileNum)
  if fileExists(path):
    getFileSize(path)
  else:
    0

proc preallocateFile*(bfm: BlockFileManager, fileNum: int32, targetSize: int) =
  ## Pre-allocate file space in chunks for better disk performance
  ## This helps reduce fragmentation during IBD
  let path = bfm.blockFilePath(fileNum)
  let currentSize = if fileExists(path): getFileSize(path).int else: 0

  if targetSize > currentSize:
    # Calculate how many chunks we need
    let currentChunks = (currentSize + BlockfileChunkSize - 1) div BlockfileChunkSize
    let targetChunks = (targetSize + BlockfileChunkSize - 1) div BlockfileChunkSize

    if targetChunks > currentChunks:
      let newSize = targetChunks * BlockfileChunkSize
      # Open file and seek to extend
      let fs = newFileStream(path, fmReadWriteExisting)
      if fs != nil:
        fs.setPosition(newSize - 1)
        fs.write(char(0))
        fs.close()

# ============================================================================
# BlockFileManager initialization
# ============================================================================

proc newBlockFileManager*(dataDir: string, params: ConsensusParams, db: Database = nil): BlockFileManager =
  ## Create a new block file manager
  result = BlockFileManager(
    dataDir: dataDir / "blocks",
    currentFileNum: 0,
    currentFileSize: 0,
    fileInfos: @[],
    params: params,
    db: db
  )
  createDir(result.dataDir)

  # Load last block file number from DB if available
  if db != nil:
    let lastFileData = db.get(cfMeta, lastBlockFileKey())
    if lastFileData.isSome and lastFileData.get().len >= 4:
      var r = BinaryReader(data: lastFileData.get(), pos: 0)
      result.currentFileNum = r.readInt32LE()
      result.currentFileSize = int32(result.getFileSize(result.currentFileNum))

proc close*(bfm: BlockFileManager) =
  ## Close the block file manager (save state to DB)
  if bfm.db != nil:
    var w = BinaryWriter()
    w.writeInt32LE(bfm.currentFileNum)
    bfm.db.put(cfMeta, lastBlockFileKey(), w.data)

# ============================================================================
# Block file info management
# ============================================================================

proc loadFileInfo*(bfm: BlockFileManager, fileNum: int32): Option[BlockFileInfo] =
  ## Load file info from database
  if bfm.db == nil:
    return none(BlockFileInfo)

  let data = bfm.db.get(cfMeta, blockFileInfoKey(fileNum))
  if data.isSome:
    return some(deserializeBlockFileInfo(data.get()))
  none(BlockFileInfo)

proc saveFileInfo*(bfm: BlockFileManager, fileNum: int32, info: BlockFileInfo) =
  ## Save file info to database
  if bfm.db != nil:
    bfm.db.put(cfMeta, blockFileInfoKey(fileNum), serializeBlockFileInfo(info))

proc updateFileInfo*(bfm: BlockFileManager, fileNum: int32, height: uint32, timestamp: uint64, blockSize: uint32) =
  ## Update file info after adding a block
  var info = bfm.loadFileInfo(fileNum).get(BlockFileInfo(
    nBlocks: 0,
    nSize: 0,
    nHeightFirst: high(uint32),
    nHeightLast: 0,
    nTimeFirst: high(uint64),
    nTimeLast: 0
  ))

  inc info.nBlocks
  info.nSize += blockSize + uint32(StorageHeaderBytes)

  if height < info.nHeightFirst:
    info.nHeightFirst = height
  if height > info.nHeightLast:
    info.nHeightLast = height
  if timestamp < info.nTimeFirst:
    info.nTimeFirst = timestamp
  if timestamp > info.nTimeLast:
    info.nTimeLast = timestamp

  bfm.saveFileInfo(fileNum, info)

# ============================================================================
# Find position for new block
# ============================================================================

proc findNextBlockPos*(bfm: BlockFileManager, blockSize: int): BlockFilePos =
  ## Find position for a new block, possibly opening a new file
  ## Returns position where block data will start (after header)

  let totalSize = blockSize + StorageHeaderBytes
  let currentSize = bfm.getFileSize(bfm.currentFileNum).int

  # Check if current file would exceed max size
  if currentSize + totalSize > MaxBlockfileSize:
    # Move to next file
    inc bfm.currentFileNum
    bfm.currentFileSize = 0

    # Save updated file number to DB
    if bfm.db != nil:
      var w = BinaryWriter()
      w.writeInt32LE(bfm.currentFileNum)
      bfm.db.put(cfMeta, lastBlockFileKey(), w.data)

  # Get current file size
  let fileSize = bfm.getFileSize(bfm.currentFileNum).int

  # Pre-allocate if needed
  let neededSize = fileSize + totalSize
  bfm.preallocateFile(bfm.currentFileNum, neededSize)

  # Return position (data starts after header)
  result = BlockFilePos(
    fileNum: bfm.currentFileNum,
    dataPos: int32(fileSize + StorageHeaderBytes)
  )

# ============================================================================
# Write block to disk
# ============================================================================

proc saveBlockToDisk*(bfm: BlockFileManager, blk: Block, height: int32): tuple[pos: BlockFilePos, ok: bool] =
  ## Write a block to disk in flat file format
  ## Returns the file position for later retrieval
  ##
  ## File format per block:
  ##   [magic: 4 bytes] [size: 4 bytes LE] [block data: variable]

  # Serialize the block
  let blockData = serialize(blk)
  let blockSize = blockData.len

  if blockSize > MaxBlockSerializedSize:
    return (nullPos(), false)

  # Find position
  let pos = bfm.findNextBlockPos(blockSize)

  # Open file for writing
  let fs = bfm.openBlockFile(pos.fileNum, forWrite = true)
  if fs == nil:
    return (nullPos(), false)

  defer: fs.close()

  # Seek to write position (header position = dataPos - StorageHeaderBytes)
  let headerPos = pos.dataPos - int32(StorageHeaderBytes)
  fs.setPosition(headerPos.int)

  # Write header: magic + size
  for b in bfm.params.networkMagic:
    fs.write(char(b))

  let size = uint32(blockSize)
  fs.write(char(size and 0xFF))
  fs.write(char((size shr 8) and 0xFF))
  fs.write(char((size shr 16) and 0xFF))
  fs.write(char((size shr 24) and 0xFF))

  # Write block data
  for b in blockData:
    fs.write(char(b))

  fs.flush()

  # Update file info
  bfm.updateFileInfo(pos.fileNum, uint32(height), blk.header.timestamp.uint64, uint32(blockSize))

  # Update current file size
  bfm.currentFileSize = int32(bfm.getFileSize(pos.fileNum))

  result = (pos, true)

# ============================================================================
# Read block from disk
# ============================================================================

proc readBlockFromDisk*(bfm: BlockFileManager, pos: BlockFilePos): tuple[blk: Block, ok: bool] =
  ## Read a block from disk at the given position
  ## Validates magic number and size before reading

  if pos.isNull:
    return (Block(), false)

  let fs = bfm.openBlockFile(pos.fileNum, forWrite = false)
  if fs == nil:
    return (Block(), false)

  defer: fs.close()

  # Seek to header position
  let headerPos = pos.dataPos - int32(StorageHeaderBytes)
  if headerPos < 0:
    return (Block(), false)

  fs.setPosition(headerPos.int)

  # Read and verify magic
  var magic: array[4, byte]
  for i in 0 ..< 4:
    magic[i] = byte(fs.readChar())

  if magic != bfm.params.networkMagic:
    return (Block(), false)

  # Read size
  var size: uint32
  size = uint32(byte(fs.readChar()))
  size = size or (uint32(byte(fs.readChar())) shl 8)
  size = size or (uint32(byte(fs.readChar())) shl 16)
  size = size or (uint32(byte(fs.readChar())) shl 24)

  # Validate size
  if size > uint32(MaxBlockSerializedSize):
    return (Block(), false)

  # Read block data
  var blockData = newSeq[byte](size)
  for i in 0 ..< int(size):
    blockData[i] = byte(fs.readChar())

  # Deserialize block
  try:
    let blk = deserializeBlock(blockData)
    result = (blk, true)
  except:
    result = (Block(), false)

proc readBlockFromDisk*(bfm: BlockFileManager, pos: BlockFilePos, expectedHash: BlockHash): tuple[blk: Block, ok: bool] =
  ## Read a block from disk and verify its hash
  let (blk, ok) = bfm.readBlockFromDisk(pos)
  if not ok:
    return (Block(), false)

  # Verify block hash
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  if hash != expectedHash:
    return (Block(), false)

  result = (blk, true)

# ============================================================================
# Block index operations
# ============================================================================

proc putBlockIndex*(bfm: BlockFileManager, hash: BlockHash, entry: BlockIndexEntry) =
  ## Store block index entry in database
  if bfm.db != nil:
    bfm.db.put(cfBlockIndex, blockIndexKey(hash), serializeBlockIndexEntry(entry))

proc getBlockIndex*(bfm: BlockFileManager, hash: BlockHash): Option[BlockIndexEntry] =
  ## Get block index entry from database
  if bfm.db == nil:
    return none(BlockIndexEntry)

  let data = bfm.db.get(cfBlockIndex, blockIndexKey(hash))
  if data.isSome:
    return some(deserializeBlockIndexEntry(data.get()))
  none(BlockIndexEntry)

proc hasBlockOnDisk*(bfm: BlockFileManager, hash: BlockHash): bool =
  ## Check if block data exists on disk
  let entry = bfm.getBlockIndex(hash)
  if entry.isNone:
    return false
  (entry.get().status and BlockHaveData) != 0

# ============================================================================
# High-level block storage API
# ============================================================================

proc storeBlock*(bfm: BlockFileManager, blk: Block, height: int32): Option[BlockFilePos] =
  ## Store a block and create index entry
  ## Returns position if successful
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check if already stored
  let existing = bfm.getBlockIndex(hash)
  if existing.isSome and (existing.get().status and BlockHaveData) != 0:
    # Already have this block
    return some(BlockFilePos(
      fileNum: existing.get().fileNum,
      dataPos: existing.get().dataPos
    ))

  # Save to disk
  let (pos, ok) = bfm.saveBlockToDisk(blk, height)
  if not ok:
    return none(BlockFilePos)

  # Create index entry
  let entry = BlockIndexEntry(
    fileNum: pos.fileNum,
    dataPos: pos.dataPos,
    undoPos: -1,  # No undo data yet
    height: height,
    nTx: uint32(blk.txs.len),
    status: BlockHaveData
  )
  bfm.putBlockIndex(hash, entry)

  some(pos)

proc loadBlock*(bfm: BlockFileManager, hash: BlockHash): Option[Block] =
  ## Load a block by hash from disk
  let entry = bfm.getBlockIndex(hash)
  if entry.isNone:
    return none(Block)

  if (entry.get().status and BlockHaveData) == 0:
    return none(Block)

  let pos = BlockFilePos(
    fileNum: entry.get().fileNum,
    dataPos: entry.get().dataPos
  )

  let (blk, ok) = bfm.readBlockFromDisk(pos, hash)
  if ok:
    some(blk)
  else:
    none(Block)

proc updateUndoPos*(bfm: BlockFileManager, hash: BlockHash, undoPos: int32) =
  ## Update block index entry with undo position
  let entryOpt = bfm.getBlockIndex(hash)
  if entryOpt.isSome:
    var entry = entryOpt.get()
    entry.undoPos = undoPos
    entry.status = entry.status or BlockHaveUndo
    bfm.putBlockIndex(hash, entry)

proc setBlockValidated*(bfm: BlockFileManager, hash: BlockHash) =
  ## Mark block as validated
  let entryOpt = bfm.getBlockIndex(hash)
  if entryOpt.isSome:
    var entry = entryOpt.get()
    entry.status = entry.status or BlockValidated
    bfm.putBlockIndex(hash, entry)

proc setBlockFailed*(bfm: BlockFileManager, hash: BlockHash) =
  ## Mark block as failed validation
  let entryOpt = bfm.getBlockIndex(hash)
  if entryOpt.isSome:
    var entry = entryOpt.get()
    entry.status = entry.status or BlockFailed
    bfm.putBlockIndex(hash, entry)
