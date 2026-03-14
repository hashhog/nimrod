## Undo data for block disconnection during chain reorganizations
## Stores the UTXOs consumed by each block's transactions
## Uses flat file storage (rev*.dat) with checksums for integrity

import std/[os, options, streams]
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../consensus/params

type
  UndoError* = object of CatchableError

  ## Undo information for a single transaction's inputs
  ## Each entry is the TxOut that was spent, plus metadata
  TxUndo* = object
    prevOutputs*: seq[SpentOutput]

  ## A spent output with its metadata
  SpentOutput* = object
    output*: TxOut        ## The TxOut that was spent
    height*: int32        ## Height at which this output was created
    isCoinbase*: bool     ## Whether this was a coinbase output

  ## Undo information for an entire block
  ## One TxUndo per non-coinbase transaction
  BlockUndo* = object
    txUndo*: seq[TxUndo]

  ## Position within a flat file
  FlatFilePos* = object
    fileNum*: int32       ## File number (rev00000.dat = 0)
    pos*: int32           ## Position within file (after header)

  ## Manages flat file storage for undo data
  UndoFileManager* = ref object
    dataDir*: string
    currentFile*: int32
    currentPos*: int32
    fileHandles*: seq[FileStream]  ## Cached file handles

const
  UndoFilePrefix* = "rev"
  UndoFileSuffix* = ".dat"
  StorageHeaderBytes* = 8  ## 4 bytes magic + 4 bytes size
  UndoDataDiskOverhead* = StorageHeaderBytes + 32  ## header + checksum

# Helper to align a string with leading characters
proc align(s: string, width: int, fill: char): string =
  if s.len >= width:
    return s
  result = newString(width)
  let padding = width - s.len
  for i in 0 ..< padding:
    result[i] = fill
  for i in 0 ..< s.len:
    result[padding + i] = s[i]

# ============================================================================
# Serialization for SpentOutput (matches Bitcoin Core's TxInUndoFormatter)
# ============================================================================

proc serializeSpentOutput*(w: var BinaryWriter, spent: SpentOutput) =
  ## Serialize a spent output in Bitcoin Core compatible format
  ## Format: (height * 2 + isCoinbase) as varint, version dummy if height > 0, compressed txout
  let code = uint64(spent.height) * 2 + (if spent.isCoinbase: 1'u64 else: 0'u64)
  w.writeCompactSize(code)

  # Required for compatibility with older undo format
  if spent.height > 0:
    w.writeUint8(0)  # Version dummy byte

  # Write the TxOut
  w.writeTxOut(spent.output)

proc deserializeSpentOutput*(r: var BinaryReader): SpentOutput =
  ## Deserialize a spent output from Bitcoin Core compatible format
  let code = r.readCompactSize()
  result.height = int32(code shr 1)
  result.isCoinbase = (code and 1) == 1

  # Read version dummy if height > 0 (compatibility)
  if result.height > 0:
    discard r.readUint8()

  result.output = r.readTxOut()

# ============================================================================
# Serialization for TxUndo
# ============================================================================

proc serializeTxUndo*(w: var BinaryWriter, txUndo: TxUndo) =
  ## Serialize undo data for one transaction
  w.writeCompactSize(uint64(txUndo.prevOutputs.len))
  for spent in txUndo.prevOutputs:
    w.serializeSpentOutput(spent)

proc deserializeTxUndo*(r: var BinaryReader): TxUndo =
  ## Deserialize undo data for one transaction
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.prevOutputs.add(r.deserializeSpentOutput())

# ============================================================================
# Serialization for BlockUndo
# ============================================================================

proc serializeBlockUndo*(w: var BinaryWriter, blockUndo: BlockUndo) =
  ## Serialize undo data for an entire block
  ## Note: txUndo.len = number of non-coinbase transactions
  w.writeCompactSize(uint64(blockUndo.txUndo.len))
  for txUndo in blockUndo.txUndo:
    w.serializeTxUndo(txUndo)

proc serializeBlockUndo*(blockUndo: BlockUndo): seq[byte] =
  var w = BinaryWriter()
  w.serializeBlockUndo(blockUndo)
  w.data

proc deserializeBlockUndo*(r: var BinaryReader): BlockUndo =
  ## Deserialize undo data for an entire block
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.txUndo.add(r.deserializeTxUndo())

proc deserializeBlockUndo*(data: seq[byte]): BlockUndo =
  var r = BinaryReader(data: data, pos: 0)
  r.deserializeBlockUndo()

# ============================================================================
# Flat file management
# ============================================================================

proc undoFileName*(fileNum: int32): string =
  ## Generate undo file name: rev00000.dat, rev00001.dat, etc.
  UndoFilePrefix & align($fileNum, 5, '0') & UndoFileSuffix

proc newUndoFileManager*(dataDir: string): UndoFileManager =
  ## Create a new undo file manager
  result = UndoFileManager(
    dataDir: dataDir,
    currentFile: 0,
    currentPos: 0,
    fileHandles: @[]
  )
  createDir(dataDir)

proc undoFilePath*(ufm: UndoFileManager, fileNum: int32): string =
  ufm.dataDir / undoFileName(fileNum)

proc openUndoFile*(ufm: UndoFileManager, fileNum: int32, forWrite: bool = false): FileStream =
  ## Open an undo file for reading or writing
  let path = ufm.undoFilePath(fileNum)
  if forWrite:
    if not fileExists(path):
      # Create new file
      result = newFileStream(path, fmWrite)
    else:
      # Append to existing file
      result = newFileStream(path, fmReadWriteExisting)
  else:
    if fileExists(path):
      result = newFileStream(path, fmRead)
    else:
      result = nil

proc close*(ufm: UndoFileManager) =
  ## Close all open file handles
  for fs in ufm.fileHandles:
    if fs != nil:
      fs.close()
  ufm.fileHandles = @[]

# ============================================================================
# Write undo data to flat files
# ============================================================================

proc writeBlockUndo*(
  ufm: UndoFileManager,
  blockUndo: BlockUndo,
  prevBlockHash: BlockHash,
  params: ConsensusParams
): tuple[pos: FlatFilePos, ok: bool] =
  ## Write block undo data to a rev*.dat file
  ## Returns the file position for later retrieval
  ##
  ## File format per block:
  ##   [magic: 4 bytes] [size: 4 bytes LE] [undo_data: variable] [checksum: 32 bytes]
  ##
  ## Checksum = SHA256d(prev_block_hash || undo_data)

  let undoData = serializeBlockUndo(blockUndo)
  let undoSize = uint32(undoData.len)

  # Open or create the undo file
  let fs = ufm.openUndoFile(ufm.currentFile, forWrite = true)
  if fs == nil:
    return (FlatFilePos(fileNum: -1, pos: -1), false)

  defer: fs.close()

  # Get file size and seek to end
  let path = ufm.undoFilePath(ufm.currentFile)
  let startPos = int32(getFileSize(path))
  fs.setPosition(int(startPos))

  # Write header: magic + size
  for b in params.networkMagic:
    fs.write(char(b))
  fs.write(char(undoSize and 0xFF))
  fs.write(char((undoSize shr 8) and 0xFF))
  fs.write(char((undoSize shr 16) and 0xFF))
  fs.write(char((undoSize shr 24) and 0xFF))

  # Calculate checksum: SHA256d(prev_block_hash || undo_data)
  var checksumData: seq[byte]
  checksumData.add(@(array[32, byte](prevBlockHash)))
  checksumData.add(undoData)
  let checksum = doubleSha256(checksumData)

  # Write undo data
  for b in undoData:
    fs.write(char(b))

  # Write checksum
  for b in checksum:
    fs.write(char(b))

  fs.flush()

  # Return position (after header, points to undo data start)
  let pos = FlatFilePos(
    fileNum: ufm.currentFile,
    pos: startPos + int32(StorageHeaderBytes)
  )

  result = (pos, true)

# ============================================================================
# Read undo data from flat files
# ============================================================================

proc readBlockUndo*(
  ufm: UndoFileManager,
  pos: FlatFilePos,
  prevBlockHash: BlockHash,
  params: ConsensusParams
): tuple[blockUndo: BlockUndo, ok: bool] =
  ## Read block undo data from a rev*.dat file
  ## Verifies checksum against prev_block_hash
  ##
  ## Returns the deserialized BlockUndo or error

  let fs = ufm.openUndoFile(pos.fileNum, forWrite = false)
  if fs == nil:
    return (BlockUndo(), false)

  defer: fs.close()

  # Seek to header position (StorageHeaderBytes before the data position)
  let headerPos = pos.pos - int32(StorageHeaderBytes)
  if headerPos < 0:
    return (BlockUndo(), false)

  fs.setPosition(int(headerPos))

  # Read and verify magic
  var magic: array[4, byte]
  for i in 0 ..< 4:
    magic[i] = byte(fs.readChar())

  if magic != params.networkMagic:
    return (BlockUndo(), false)

  # Read size
  var size: uint32
  size = uint32(fs.readChar())
  size = size or (uint32(fs.readChar()) shl 8)
  size = size or (uint32(fs.readChar()) shl 16)
  size = size or (uint32(fs.readChar()) shl 24)

  # Read undo data
  var undoData = newSeq[byte](size)
  for i in 0 ..< int(size):
    undoData[i] = byte(fs.readChar())

  # Read checksum
  var storedChecksum: array[32, byte]
  for i in 0 ..< 32:
    storedChecksum[i] = byte(fs.readChar())

  # Verify checksum: SHA256d(prev_block_hash || undo_data)
  var checksumData: seq[byte]
  checksumData.add(@(array[32, byte](prevBlockHash)))
  checksumData.add(undoData)
  let computedChecksum = doubleSha256(checksumData)

  if computedChecksum != storedChecksum:
    return (BlockUndo(), false)

  # Deserialize the block undo
  let blockUndo = deserializeBlockUndo(undoData)

  result = (blockUndo, true)

# ============================================================================
# Generate undo data for a block before connecting it
# ============================================================================

type
  UtxoLookup* = proc(outpoint: OutPoint): Option[tuple[output: TxOut, height: int32, isCoinbase: bool]]

proc generateBlockUndo*(blk: Block, utxoLookup: UtxoLookup): BlockUndo =
  ## Generate undo data for a block by looking up all spent UTXOs
  ## This should be called BEFORE the block is connected to preserve UTXO state
  ##
  ## utxoLookup: function to look up UTXO by outpoint

  for txIdx, tx in blk.txs:
    # Skip coinbase (has no inputs to spend)
    if txIdx == 0:
      continue

    var txUndo = TxUndo()

    for input in tx.inputs:
      let utxoOpt = utxoLookup(input.prevOut)
      if utxoOpt.isSome:
        let (output, height, isCoinbase) = utxoOpt.get()
        txUndo.prevOutputs.add(SpentOutput(
          output: output,
          height: height,
          isCoinbase: isCoinbase
        ))

    result.txUndo.add(txUndo)

# ============================================================================
# Helper to check if position is valid
# ============================================================================

proc isNull*(pos: FlatFilePos): bool =
  pos.fileNum < 0 or pos.pos < 0
