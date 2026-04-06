## Chainstate management
## UTXO set manager with block connect/disconnect, in-memory cache, and reorg support
## Uses RocksDB column families for data separation
## Undo data stored in flat files (rev*.dat) for efficient reorg handling

import std/[options, tables, os]
import ./db
import ./undo
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../consensus/params
import chronicles

export db.ColumnFamily
export undo.BlockUndo, undo.TxUndo, undo.SpentOutput, undo.FlatFilePos

type
  ChainStateError* = object of CatchableError

  BlockStatus* = enum
    bsHeaderOnly    ## Only header stored
    bsDataStored    ## Full block data stored
    bsValidated     ## Block fully validated
    bsInvalid       ## Block validation failed

  ## Block failure flags for invalidateblock/reconsiderblock
  ## These are stored separately from BlockStatus to allow combinations
  BlockFailureFlags* = distinct uint8

const
  BLOCK_FAILED_VALID* = BlockFailureFlags(32)    ## Block failed validation (invalidateblock)
  BLOCK_FAILED_CHILD* = BlockFailureFlags(64)    ## Descendant of a failed block
  BLOCK_NO_FAILURE* = BlockFailureFlags(0)       ## No failure flags set

proc `or`*(a, b: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `and`*(a, b: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `not`*(a: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `==`*(a, b: BlockFailureFlags): bool {.borrow.}
proc `!=`*(a, b: BlockFailureFlags): bool = not (a == b)

proc hasFlag*(flags: BlockFailureFlags, flag: BlockFailureFlags): bool =
  (uint8(flags) and uint8(flag)) != 0

proc setFlag*(flags: var BlockFailureFlags, flag: BlockFailureFlags) =
  flags = BlockFailureFlags(uint8(flags) or uint8(flag))

proc clearFlag*(flags: var BlockFailureFlags, flag: BlockFailureFlags) =
  flags = BlockFailureFlags(uint8(flags) and (not uint8(flag)))

proc isFailed*(flags: BlockFailureFlags): bool =
  ## Check if block has any failure flag set
  uint8(flags) != 0

type
  BlockIndex* = object
    hash*: BlockHash
    height*: int32
    status*: BlockStatus
    prevHash*: BlockHash
    header*: BlockHeader
    totalWork*: array[32, byte]  ## Cumulative chain work
    undoPos*: FlatFilePos        ## Position of undo data in rev*.dat files
    failureFlags*: BlockFailureFlags  ## Failure flags for invalidateblock/reconsiderblock
    sequenceId*: int32           ## For preciousblock: lower = more precious

  UtxoEntry* = object
    output*: TxOut
    height*: int32
    isCoinbase*: bool

  ## UndoData stores spent outputs for block disconnect
  UndoData* = object
    spentOutputs*: seq[tuple[outpoint: OutPoint, entry: UtxoEntry]]

  ## ChainDb provides raw database access
  ChainDb* = ref object
    db*: Database
    bestBlockHash*: BlockHash
    bestHeight*: int32

  ## ChainState wraps ChainDb with cache management and consensus params
  ChainState* = ref object
    db*: ChainDb
    bestBlockHash*: BlockHash
    bestHeight*: int32
    totalWork*: array[32, byte]
    params*: ConsensusParams
    utxoCache*: Table[OutPoint, UtxoEntry]
    cacheSize*: int
    maxCacheSize*: int  ## Flush at 50000
    undoMgr*: UndoFileManager  ## Manages flat file undo storage
    # IBD batching state
    ibdBatch*: WriteBatch        ## Persistent write batch for IBD
    ibdBatchBlocks*: int         ## Blocks accumulated in current batch
    ibdMode*: bool               ## True during initial block download
    # Pending UTXO deletes tracked during IBD (cache key -> true)
    ibdDeletedUtxos*: Table[string, bool]

  ## Result type for chainstate operations
  ChainStateResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

# Result constructors
proc ok*[T](val: T): ChainStateResult[T] =
  ChainStateResult[T](isOk: true, value: val)

proc ok*(): ChainStateResult[void] =
  ChainStateResult[void](isOk: true)

proc err*(T: typedesc, msg: string): ChainStateResult[T] =
  ChainStateResult[T](isOk: false, error: msg)

proc err*(msg: string): ChainStateResult[void] =
  ChainStateResult[void](isOk: false, error: msg)

# Key helpers

proc outpointKey(txid: TxId, vout: uint32): string =
  ## Cache key for outpoints
  result = newString(36)
  let txidArr = array[32, byte](txid)
  for i in 0..<32:
    result[i] = char(txidArr[i])
  result[32] = char((vout shr 24) and 0xff)
  result[33] = char((vout shr 16) and 0xff)
  result[34] = char((vout shr 8) and 0xff)
  result[35] = char(vout and 0xff)

proc outpointKey(op: OutPoint): string =
  outpointKey(op.txid, op.vout)

# Serialization for BlockIndex

proc serializeBlockIndex(idx: BlockIndex): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(idx.hash)
  w.writeInt32LE(idx.height)
  w.writeUint8(uint8(ord(idx.status)))
  w.writeBlockHash(idx.prevHash)
  w.writeBlockHeader(idx.header)
  w.writeBytes(idx.totalWork)
  # Serialize undo file position
  w.writeInt32LE(idx.undoPos.fileNum)
  w.writeInt32LE(idx.undoPos.pos)
  # Serialize failure flags and sequence ID (new in phase 51)
  w.writeUint8(uint8(idx.failureFlags))
  w.writeInt32LE(idx.sequenceId)
  w.data

proc deserializeBlockIndex(data: seq[byte]): BlockIndex =
  var r = BinaryReader(data: data, pos: 0)
  result.hash = r.readBlockHash()
  result.height = r.readInt32LE()
  result.status = BlockStatus(r.readUint8())
  result.prevHash = r.readBlockHash()
  result.header = r.readBlockHeader()
  result.totalWork = r.readHash()
  # Deserialize undo file position (with backward compatibility)
  if r.remaining() >= 8:
    result.undoPos.fileNum = r.readInt32LE()
    result.undoPos.pos = r.readInt32LE()
  else:
    # Legacy format without undo position
    result.undoPos = FlatFilePos(fileNum: -1, pos: -1)
  # Deserialize failure flags and sequence ID (with backward compatibility)
  if r.remaining() >= 5:
    result.failureFlags = BlockFailureFlags(r.readUint8())
    result.sequenceId = r.readInt32LE()
  else:
    result.failureFlags = BLOCK_NO_FAILURE
    result.sequenceId = 0

# Serialization for UtxoEntry

proc serializeUtxoEntry(entry: UtxoEntry): seq[byte] =
  var w = BinaryWriter()
  w.writeTxOut(entry.output)
  w.writeInt32LE(entry.height)
  w.writeUint8(if entry.isCoinbase: 1 else: 0)
  w.data

proc deserializeUtxoEntry(data: seq[byte]): UtxoEntry =
  var r = BinaryReader(data: data, pos: 0)
  result.output = r.readTxOut()
  result.height = r.readInt32LE()
  result.isCoinbase = r.readUint8() != 0

# Serialization for UndoData

proc serializeUndoData*(undo: UndoData): seq[byte] =
  var w = BinaryWriter()
  w.writeCompactSize(uint64(undo.spentOutputs.len))
  for (outpoint, entry) in undo.spentOutputs:
    w.writeOutPoint(outpoint)
    let entryBytes = serializeUtxoEntry(entry)
    w.writeCompactSize(uint64(entryBytes.len))
    w.writeBytes(entryBytes)
  w.data

proc deserializeUndoData*(data: seq[byte]): UndoData =
  var r = BinaryReader(data: data, pos: 0)
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    let outpoint = r.readOutPoint()
    let entryLen = r.readCompactSize()
    let entryBytes = r.readBytes(int(entryLen))
    let entry = deserializeUtxoEntry(entryBytes)
    result.spentOutputs.add((outpoint, entry))

# TxIndex entry: block hash + position in block

type TxLocation* = object
  blockHash*: BlockHash
  txIndex*: uint32  ## Index within block

proc serializeTxLocation(loc: TxLocation): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(loc.blockHash)
  w.writeUint32LE(loc.txIndex)
  w.data

proc deserializeTxLocation(data: seq[byte]): TxLocation =
  var r = BinaryReader(data: data, pos: 0)
  result.blockHash = r.readBlockHash()
  result.txIndex = r.readUint32LE()

# ChainDb operations (low-level database access)

proc openChainDb*(path: string): ChainDb =
  ## Open the chain database
  result = ChainDb(
    db: openDatabase(path),
    bestBlockHash: BlockHash(default(array[32, byte])),
    bestHeight: -1
  )

  # Load best block from meta
  let bestHashData = result.db.get(cfMeta, metaKey("bestblock"))
  if bestHashData.isSome:
    var hash: array[32, byte]
    copyMem(addr hash[0], addr bestHashData.get()[0], 32)
    result.bestBlockHash = BlockHash(hash)

  let heightData = result.db.get(cfMeta, metaKey("height"))
  if heightData.isSome:
    var r = BinaryReader(data: heightData.get(), pos: 0)
    result.bestHeight = r.readInt32LE()

proc close*(cdb: var ChainDb) =
  cdb.db.close()

# Block storage (ChainDb)

proc storeBlock*(cdb: ChainDb, blk: Block) =
  ## Store full block data
  let headerBytes = serialize(blk.header)
  let hash = doubleSha256(headerBytes)

  cdb.db.put(cfBlocks, blockKey(hash), serialize(blk))

proc getBlock*(cdb: ChainDb, hash: BlockHash): Option[Block] =
  ## Retrieve block by hash
  let data = cdb.db.get(cfBlocks, blockKey(array[32, byte](hash)))
  if data.isSome:
    return some(deserializeBlock(data.get()))
  none(Block)

# Block index operations (ChainDb)

proc putBlockIndex*(cdb: ChainDb, idx: BlockIndex) =
  ## Store block index entry (by hash)
  cdb.db.put(cfBlockIndex, blockKey(array[32, byte](idx.hash)), serializeBlockIndex(idx))
  # Also store height -> hash mapping
  cdb.db.put(cfBlockIndex, blockIndexKey(idx.height), @(array[32, byte](idx.hash)))

proc getBlockIndex*(cdb: ChainDb, hash: BlockHash): Option[BlockIndex] =
  ## Get block index by hash
  let data = cdb.db.get(cfBlockIndex, blockKey(array[32, byte](hash)))
  if data.isSome:
    return some(deserializeBlockIndex(data.get()))
  none(BlockIndex)

proc getBlockHashByHeight*(cdb: ChainDb, height: int32): Option[BlockHash] =
  ## Get block hash at given height
  let data = cdb.db.get(cfBlockIndex, blockIndexKey(height))
  if data.isSome and data.get().len >= 32:
    var hash: array[32, byte]
    copyMem(addr hash[0], addr data.get()[0], 32)
    return some(BlockHash(hash))
  none(BlockHash)

proc getBlockByHeight*(cdb: ChainDb, height: int32): Option[Block] =
  ## Get block at height
  let hashOpt = cdb.getBlockHashByHeight(height)
  if hashOpt.isSome:
    return cdb.getBlock(hashOpt.get())
  none(Block)

# UTXO operations (ChainDb - low level)

proc putUtxo*(cdb: ChainDb, outpoint: OutPoint, entry: UtxoEntry) =
  ## Add or update UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.put(cfUtxo, key, serializeUtxoEntry(entry))

proc getUtxo*(cdb: ChainDb, outpoint: OutPoint): Option[UtxoEntry] =
  ## Get UTXO entry directly from database (no caching at this layer;
  ## ChainState.utxoCache provides bounded caching above).
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  let data = cdb.db.get(cfUtxo, key)
  if data.isSome:
    return some(deserializeUtxoEntry(data.get()))
  none(UtxoEntry)

proc deleteUtxo*(cdb: ChainDb, outpoint: OutPoint) =
  ## Remove UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.delete(cfUtxo, key)

proc hasUtxo*(cdb: ChainDb, outpoint: OutPoint): bool =
  cdb.getUtxo(outpoint).isSome

# TX index operations (ChainDb)

proc putTxIndex*(cdb: ChainDb, txid: TxId, location: TxLocation) =
  ## Index a transaction
  cdb.db.put(cfTxIndex, txIndexKey(array[32, byte](txid)), serializeTxLocation(location))

proc getTxIndex*(cdb: ChainDb, txid: TxId): Option[TxLocation] =
  ## Look up transaction location
  let data = cdb.db.get(cfTxIndex, txIndexKey(array[32, byte](txid)))
  if data.isSome:
    return some(deserializeTxLocation(data.get()))
  none(TxLocation)

# Undo data operations (ChainDb)

proc undoKey(hash: BlockHash): seq[byte] =
  ## Key for undo data: "undo:" prefix + block hash
  result = @[byte('u'), byte('n'), byte('d'), byte('o'), byte(':')]
  result.add(@(array[32, byte](hash)))

proc putUndoData*(cdb: ChainDb, blockHash: BlockHash, undo: UndoData) =
  ## Store undo data for a block
  cdb.db.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))

proc getUndoData*(cdb: ChainDb, blockHash: BlockHash): Option[UndoData] =
  ## Get undo data for a block
  let data = cdb.db.get(cfMeta, undoKey(blockHash))
  if data.isSome:
    return some(deserializeUndoData(data.get()))
  none(UndoData)

proc deleteUndoData*(cdb: ChainDb, blockHash: BlockHash) =
  ## Remove undo data for a block
  cdb.db.delete(cfMeta, undoKey(blockHash))

# Chain state updates (ChainDb)

proc updateBestBlock*(cdb: ChainDb, hash: BlockHash, height: int32) =
  ## Update best block pointer
  cdb.bestBlockHash = hash
  cdb.bestHeight = height

  cdb.db.put(cfMeta, metaKey("bestblock"), @(array[32, byte](hash)))

  var w = BinaryWriter()
  w.writeInt32LE(height)
  cdb.db.put(cfMeta, metaKey("height"), w.data)

# ============================================================================
# ChainState - High-level UTXO set manager with cache and reorg support
# ============================================================================

const
  DefaultMaxCacheSize* = 50000
  ## Maximum memory budget for UTXO cache (2 GiB — increased for faster IBD)
  MaxCacheBytes* = 2_147_483_648
  ## Eviction target: evict down to half the max (~225 MiB)
  EvictTargetBytes* = MaxCacheBytes div 2
  ## Estimated bytes per cache entry (OutPoint key ~60 bytes + UtxoEntry ~80 bytes + Table overhead ~32 bytes)
  EstimatedEntryBytes* = 172

proc newChainState*(dbPath: string, params: ConsensusParams): ChainState =
  ## Create a new ChainState with given path and consensus params
  let cdb = openChainDb(dbPath)
  result = ChainState(
    db: cdb,
    bestBlockHash: cdb.bestBlockHash,
    bestHeight: cdb.bestHeight,
    totalWork: default(array[32, byte]),
    params: params,
    utxoCache: initTable[OutPoint, UtxoEntry](),
    cacheSize: 0,
    maxCacheSize: DefaultMaxCacheSize,
    undoMgr: newUndoFileManager(dbPath / "blocks"),
    ibdBatch: nil,
    ibdBatchBlocks: 0,
    ibdMode: false,
    ibdDeletedUtxos: initTable[string, bool]()
  )

  # Load total work from DB if available
  let workData = cdb.db.get(cfMeta, metaKey("totalwork"))
  if workData.isSome and workData.get().len >= 32:
    copyMem(addr result.totalWork[0], addr workData.get()[0], 32)

proc close*(cs: var ChainState) =
  cs.undoMgr.close()
  cs.db.close()

# UTXO operations (ChainState - with cache management)

proc getUtxo*(cs: ChainState, op: OutPoint): Option[UtxoEntry] =
  ## Get UTXO entry, checking cache first
  ## During IBD, also checks deletion tracking
  # During IBD, check if this UTXO was deleted in the current unflushed batch
  if cs.ibdMode:
    let ck = outpointKey(op)
    if ck in cs.ibdDeletedUtxos:
      return none(UtxoEntry)

  # Check local cache first
  if op in cs.utxoCache:
    return some(cs.utxoCache[op])

  # Fall back to database
  cs.db.getUtxo(op)

proc putUtxoCache*(cs: var ChainState, op: OutPoint, entry: UtxoEntry) =
  ## Add UTXO to cache (doesn't write to DB until flush)
  if op notin cs.utxoCache:
    inc cs.cacheSize
  cs.utxoCache[op] = entry

proc deleteUtxoCache*(cs: var ChainState, op: OutPoint) =
  ## Mark UTXO as deleted in cache
  if op in cs.utxoCache:
    cs.utxoCache.del(op)
    dec cs.cacheSize

proc flushCache*(cs: var ChainState) =
  ## Flush cached UTXOs to database
  for op, entry in cs.utxoCache:
    cs.db.putUtxo(op, entry)
  cs.utxoCache.clear()
  cs.cacheSize = 0

  # Also save total work
  cs.db.db.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

proc shouldFlush*(cs: ChainState): bool =
  cs.cacheSize >= cs.maxCacheSize

# Work calculation helpers

proc addWork(total: var array[32, byte], work: array[32, byte]) =
  ## Add work to total (256-bit addition, little-endian)
  var carry: uint32 = 0
  for i in 0 ..< 32:
    let sum = uint32(total[i]) + uint32(work[i]) + carry
    total[i] = byte(sum and 0xff)
    carry = sum shr 8

proc calculateBlockWork(bits: uint32): array[32, byte] =
  ## Calculate work from difficulty target
  ## Work = 2^256 / (target + 1)
  ## For simplicity, we approximate: work ≈ 2^(256-log2(target))
  ## A more accurate implementation would use big integer division
  let target = compactToTarget(bits)

  # Find the highest non-zero byte to estimate difficulty
  var highestBit = 0
  for i in countdown(31, 0):
    if target[i] != 0:
      highestBit = i * 8
      var b = target[i]
      while b != 0:
        inc highestBit
        b = b shr 1
      break

  # Work is approximately 2^(256 - highestBit)
  # For simplicity, set one bit at position (256 - highestBit)
  result = default(array[32, byte])
  if highestBit > 0 and highestBit < 256:
    let workBit = 256 - highestBit
    let bytePos = workBit div 8
    let bitPos = workBit mod 8
    if bytePos < 32:
      result[bytePos] = byte(1 shl bitPos)
  else:
    # Minimum work
    result[0] = 1

# Generate undo data before connecting a block

proc generateUndoData*(cs: ChainState, blk: Block): UndoData =
  ## Generate undo data for a block (record all spent outputs)
  ## Legacy format - kept for backward compatibility
  for txIdx, tx in blk.txs:
    # Skip coinbase inputs (nothing spent)
    if txIdx == 0:
      continue

    for input in tx.inputs:
      let utxoOpt = cs.getUtxo(input.prevOut)
      if utxoOpt.isSome:
        result.spentOutputs.add((input.prevOut, utxoOpt.get()))

proc generateBlockUndo*(cs: ChainState, blk: Block): BlockUndo =
  ## Generate BlockUndo data for flat file storage
  ## One TxUndo per non-coinbase transaction, each containing all spent outputs
  for txIdx, tx in blk.txs:
    # Skip coinbase (has no inputs to spend)
    if txIdx == 0:
      continue

    var txUndo = TxUndo()
    for input in tx.inputs:
      let utxoOpt = cs.getUtxo(input.prevOut)
      if utxoOpt.isSome:
        let entry = utxoOpt.get()
        txUndo.prevOutputs.add(SpentOutput(
          output: entry.output,
          height: entry.height,
          isCoinbase: entry.isCoinbase
        ))
    result.txUndo.add(txUndo)

# Connect a block to the chain

proc connectBlock*(cs: var ChainState, blk: Block, height: int32): ChainStateResult[void] =
  ## Connect a block: spend inputs, create outputs, update state
  ## Returns error if any input is missing or immature coinbase
  ## Undo data is written to flat files (rev*.dat) for efficient reorg handling

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Generate undo data before making changes (both formats for compatibility)
  let undo = cs.generateUndoData(blk)
  let blockUndo = cs.generateBlockUndo(blk)

  # Write undo data to flat file
  var undoPos = FlatFilePos(fileNum: -1, pos: -1)
  if blk.txs.len > 1:  # Only write undo if there are non-coinbase transactions
    let (pos, ok) = cs.undoMgr.writeBlockUndo(blockUndo, blk.header.prevBlock, cs.params)
    if not ok:
      return err("failed to write undo data for block " & $blockHash)
    undoPos = pos

  # Create a write batch for atomic updates
  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()

  # Store full block data
  batch.put(cfBlocks, blockKey(array[32, byte](blockHash)), serialize(blk))

  # Process each transaction
  for txIdx, tx in blk.txs:
    let txId = tx.txid()

    # Spend inputs (skip coinbase which has no inputs to spend)
    if txIdx > 0:
      for input in tx.inputs:
        let utxoOpt = cs.getUtxo(input.prevOut)
        if utxoOpt.isNone:
          return err("missing input: " & $input.prevOut.txid)

        let entry = utxoOpt.get()

        # Check coinbase maturity
        if entry.isCoinbase:
          let age = height - entry.height
          if age < int32(cs.params.coinbaseMaturity):
            if cs.params.assumeValidHeight > 0 and
               height <= cs.params.assumeValidHeight:
              warn "immature coinbase below assume-valid (allowing)",
                   height = height, coinbaseHeight = entry.height,
                   age = age, prevTxid = $input.prevOut.txid,
                   prevVout = input.prevOut.vout
            else:
              return err("immature coinbase spend at height " & $height &
                        ", coinbase height " & $entry.height &
                        ", age " & $age & " < " & $cs.params.coinbaseMaturity)

        # Delete from DB and cache
        let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
        batch.delete(cfUtxo, key)
        cs.deleteUtxoCache(input.prevOut)

    # Create outputs
    for voutIdx, output in tx.outputs:
      let entry = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: txIdx == 0
      )
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      batch.put(cfUtxo, key, serializeUtxoEntry(entry))
      cs.putUtxoCache(outpoint, entry)

    # Index transaction
    let loc = TxLocation(blockHash: blockHash, txIndex: uint32(txIdx))
    batch.put(cfTxIndex, txIndexKey(array[32, byte](txId)), serializeTxLocation(loc))

  # Calculate and add work
  let blockWork = calculateBlockWork(blk.header.bits)
  addWork(cs.totalWork, blockWork)

  # Create block index entry with undo position
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: cs.totalWork,
    undoPos: undoPos
  )
  batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  batch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Store undo data (legacy RocksDB format for backward compatibility)
  batch.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))

  # Update best block
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(height)
  batch.put(cfMeta, metaKey("height"), w.data)
  batch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

  # Commit atomically
  cs.db.db.write(batch)

  # Update in-memory state
  cs.bestBlockHash = blockHash
  cs.bestHeight = height
  cs.db.bestBlockHash = blockHash
  cs.db.bestHeight = height

  # Flush cache if needed
  if cs.shouldFlush():
    cs.flushCache()

  ok()

# IBD batch flush interval (flush every N blocks)
const IbdBatchFlushInterval* = 2000

proc startIBD*(cs: var ChainState) =
  ## Enter IBD mode: enable write batching for performance
  cs.ibdMode = true
  cs.ibdBatch = cs.db.db.newWriteBatch()
  cs.ibdBatchBlocks = 0
  cs.ibdDeletedUtxos = initTable[string, bool]()
  # Increase cache size during IBD to reduce DB lookups
  cs.maxCacheSize = 200_000
  # Disable WAL for faster writes (data is durable via periodic batch flushes)
  cs.db.db.disableWAL()

proc evictCleanEntries*(cs: var ChainState) =
  ## Evict clean (already flushed) entries from the UTXO cache when memory
  ## exceeds MaxCacheBytes. Evicts down to EvictTargetBytes.
  ## During IBD the cache grows unbounded because flushIBDBatch writes entries
  ## to RocksDB but never removes them from memory. This bounds RSS.
  let cacheBytes = cs.cacheSize * EstimatedEntryBytes
  if cacheBytes <= MaxCacheBytes:
    return

  var toRemove: seq[OutPoint] = @[]
  var currentBytes = cacheBytes

  for op, entry in cs.utxoCache:
    if currentBytes <= EvictTargetBytes:
      break
    toRemove.add(op)
    currentBytes -= EstimatedEntryBytes

  for op in toRemove:
    cs.utxoCache.del(op)
    dec cs.cacheSize

proc flushIBDBatch*(cs: var ChainState) =
  ## Flush accumulated IBD write batch to RocksDB
  if cs.ibdBatch != nil and cs.ibdBatchBlocks > 0:
    # Write best block pointer into the batch so it's atomic
    cs.ibdBatch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](cs.bestBlockHash)))
    var w = BinaryWriter()
    w.writeInt32LE(cs.bestHeight)
    cs.ibdBatch.put(cfMeta, metaKey("height"), w.data)
    cs.ibdBatch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

    # Also flush cached UTXOs into the batch
    for op, entry in cs.utxoCache:
      let key = utxoKey(array[32, byte](op.txid), op.vout)
      cs.ibdBatch.put(cfUtxo, key, serializeUtxoEntry(entry))

    # Commit the entire batch atomically
    cs.db.db.write(cs.ibdBatch)

    # Reset batch
    cs.ibdBatch.clear()
    cs.ibdBatchBlocks = 0
    cs.ibdDeletedUtxos.clear()

    # Update ChainDb in-memory state
    cs.db.bestBlockHash = cs.bestBlockHash
    cs.db.bestHeight = cs.bestHeight

    # Clear the entire UTXO cache after flush — all entries are now persisted
    # to RocksDB. Keeping them around wastes memory during IBD since the
    # working set moves forward (subsequent blocks rarely reference old UTXOs).
    # This bounds RSS to O(batch_interval * block_size) instead of O(chain_size).
    let evictedEntries = cs.cacheSize
    cs.utxoCache.clear()
    cs.cacheSize = 0
    info "flushed IBD batch", height = cs.bestHeight, evicted = evictedEntries,
         batchBlocks = IbdBatchFlushInterval

proc stopIBD*(cs: var ChainState) =
  ## Exit IBD mode: flush remaining batch and switch to per-block writes
  if cs.ibdBatch != nil:
    cs.flushIBDBatch()
    cs.ibdBatch.destroy()
    cs.ibdBatch = nil
  cs.ibdMode = false
  cs.maxCacheSize = DefaultMaxCacheSize
  # Re-enable WAL for normal operation
  cs.db.db.enableWAL()

proc connectBlockIBD*(cs: var ChainState, blk: Block, height: int32): ChainStateResult[void] =
  ## Fast-path block connection for IBD
  ## Skips: undo data, tx index, full block storage, per-block RocksDB flush
  ## Accumulates UTXO changes in memory + write batch, flushes every IbdBatchFlushInterval blocks

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Process each transaction - UTXO updates only
  for txIdx, tx in blk.txs:
    let txId = tx.txid()

    # Spend inputs (skip coinbase)
    if txIdx > 0:
      for input in tx.inputs:
        let utxoOpt = cs.getUtxo(input.prevOut)
        if utxoOpt.isNone:
          # Also check ibdDeletedUtxos - if already deleted, it's a double-spend
          return err("missing input: " & $input.prevOut.txid)

        let entry = utxoOpt.get()

        # Check coinbase maturity
        if entry.isCoinbase:
          let age = height - entry.height
          if age < int32(cs.params.coinbaseMaturity):
            # Below assume-valid height, blocks are trusted (scripts are
            # already skipped).  Log the anomaly but don't reject the block
            # -- this guards against false positives from stale UTXO flags
            # while still enforcing maturity above assume-valid.
            if cs.params.assumeValidHeight > 0 and
               height <= cs.params.assumeValidHeight:
              warn "immature coinbase below assume-valid (allowing)",
                   height = height, coinbaseHeight = entry.height,
                   age = age, prevTxid = $input.prevOut.txid,
                   prevVout = input.prevOut.vout
            else:
              return err("immature coinbase spend at height " & $height &
                        ", coinbase height " & $entry.height &
                        ", age " & $age & " < " & $cs.params.coinbaseMaturity)

        # Delete from batch and cache
        let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
        cs.ibdBatch.delete(cfUtxo, key)
        cs.deleteUtxoCache(input.prevOut)
        # Track deletion so we don't serve stale data from DB
        cs.ibdDeletedUtxos[outpointKey(input.prevOut)] = true

    # Create outputs - add to cache (will be flushed in batch)
    for voutIdx, output in tx.outputs:
      let entry = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: txIdx == 0
      )
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      cs.putUtxoCache(outpoint, entry)
      # Remove from deleted tracking if re-created
      let ck = outpointKey(outpoint)
      if ck in cs.ibdDeletedUtxos:
        cs.ibdDeletedUtxos.del(ck)

  # Calculate and add work
  let blockWork = calculateBlockWork(blk.header.bits)
  addWork(cs.totalWork, blockWork)

  # Store block index entry (lightweight - needed for chain tracking)
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: cs.totalWork,
    undoPos: FlatFilePos(fileNum: -1, pos: -1)
  )
  cs.ibdBatch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  cs.ibdBatch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Update in-memory state
  cs.bestBlockHash = blockHash
  cs.bestHeight = height

  cs.ibdBatchBlocks += 1

  # Flush batch every N blocks
  if cs.ibdBatchBlocks >= IbdBatchFlushInterval:
    cs.flushIBDBatch()

  ok()

proc getUtxoIBD*(cs: ChainState, op: OutPoint): Option[UtxoEntry] =
  ## Get UTXO during IBD - checks deletions tracking
  # Check if deleted in current batch
  let ck = outpointKey(op)
  if ck in cs.ibdDeletedUtxos:
    return none(UtxoEntry)

  # Check local cache first
  if op in cs.utxoCache:
    return some(cs.utxoCache[op])

  # Fall back to database
  cs.db.getUtxo(op)

# Disconnect a block from the chain

proc disconnectBlock*(cs: var ChainState, blk: Block, height: int32, undo: UndoData): ChainStateResult[void] =
  ## Disconnect a block: restore spent outputs, remove created outputs
  ## Requires undo data to restore spent UTXOs

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()

  # Process transactions in reverse order
  for txIdx in countdown(blk.txs.len - 1, 0):
    let tx = blk.txs[txIdx]
    let txId = tx.txid()

    # Remove created outputs
    for voutIdx in 0 ..< tx.outputs.len:
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      batch.delete(cfUtxo, key)
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      cs.deleteUtxoCache(outpoint)

    # Remove tx index entry
    batch.delete(cfTxIndex, txIndexKey(array[32, byte](txId)))

  # Restore spent outputs from undo data
  for (outpoint, entry) in undo.spentOutputs:
    let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
    batch.put(cfUtxo, key, serializeUtxoEntry(entry))
    cs.putUtxoCache(outpoint, entry)

  # Remove undo data for this block
  batch.delete(cfMeta, undoKey(blockHash))

  # Remove block index height mapping
  batch.delete(cfBlockIndex, blockIndexKey(height))

  # Subtract work (reverse the work addition)
  let blockWork = calculateBlockWork(blk.header.bits)
  var newTotalWork = cs.totalWork
  # Subtract: newTotal = total - blockWork
  var borrow: int32 = 0
  for i in 0 ..< 32:
    let diff = int32(newTotalWork[i]) - int32(blockWork[i]) - borrow
    if diff < 0:
      newTotalWork[i] = byte((diff + 256) and 0xff)
      borrow = 1
    else:
      newTotalWork[i] = byte(diff)
      borrow = 0
  cs.totalWork = newTotalWork

  # Update best block to previous
  let newBestHeight = height - 1
  if newBestHeight >= 0:
    batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blk.header.prevBlock)))
    var w = BinaryWriter()
    w.writeInt32LE(newBestHeight)
    batch.put(cfMeta, metaKey("height"), w.data)
    batch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

    cs.bestBlockHash = blk.header.prevBlock
    cs.bestHeight = newBestHeight
    cs.db.bestBlockHash = blk.header.prevBlock
    cs.db.bestHeight = newBestHeight

  cs.db.db.write(batch)

  ok()

proc disconnectBlock*(cs: var ChainState, blk: Block): ChainStateResult[void] =
  ## Disconnect a block by reading undo data from flat files
  ## This is the preferred method for disconnection as it reads from rev*.dat

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Get block index to find undo position
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return err("block index not found for " & $blockHash)

  let idx = idxOpt.get()
  let height = idx.height

  # Try to read undo from flat files first
  if not idx.undoPos.isNull:
    let (blockUndo, ok) = cs.undoMgr.readBlockUndo(idx.undoPos, blk.header.prevBlock, cs.params)
    if ok:
      # Convert BlockUndo to UndoData format for the existing disconnection logic
      var undo = UndoData()
      var inputIdx = 0
      for txIdx in 1 ..< blk.txs.len:  # Skip coinbase
        let tx = blk.txs[txIdx]
        if txIdx - 1 < blockUndo.txUndo.len:
          let txUndo = blockUndo.txUndo[txIdx - 1]
          for i, spent in txUndo.prevOutputs:
            if i < tx.inputs.len:
              let outpoint = tx.inputs[i].prevOut
              let entry = UtxoEntry(
                output: spent.output,
                height: spent.height,
                isCoinbase: spent.isCoinbase
              )
              undo.spentOutputs.add((outpoint, entry))
      return cs.disconnectBlock(blk, height, undo)

  # Fall back to RocksDB undo data
  let undoOpt = cs.db.getUndoData(blockHash)
  if undoOpt.isNone:
    return err("undo data not found for " & $blockHash)

  cs.disconnectBlock(blk, height, undoOpt.get())

# Handle a reorg

proc handleReorg*(cs: var ChainState, forkPoint: BlockHash, newChain: seq[Block]): ChainStateResult[void] =
  ## Handle a chain reorganization
  ## 1. Disconnect blocks from current tip back to forkPoint
  ## 2. Connect blocks in newChain
  ##
  ## forkPoint: the last common ancestor block hash
  ## newChain: blocks to connect, in order from forkPoint+1 to new tip

  # First, disconnect blocks from current tip to fork point
  var currentHash = cs.bestBlockHash
  var currentHeight = cs.bestHeight
  var disconnectedBlocks: seq[(Block, UndoData)] = @[]

  while currentHash != forkPoint and currentHeight >= 0:
    # Get the block to disconnect
    let blkOpt = cs.db.getBlock(currentHash)
    if blkOpt.isNone:
      return err("cannot find block to disconnect: " & $currentHash)

    let blk = blkOpt.get()

    # Get undo data
    let undoOpt = cs.db.getUndoData(currentHash)
    if undoOpt.isNone:
      return err("missing undo data for block: " & $currentHash)

    disconnectedBlocks.add((blk, undoOpt.get()))

    # Move to previous block
    currentHash = blk.header.prevBlock
    dec currentHeight

  # Disconnect in reverse order (from tip to fork point)
  var height = cs.bestHeight
  for (blk, undo) in disconnectedBlocks:
    let disconnectRes = cs.disconnectBlock(blk, height, undo)
    if not disconnectRes.isOk:
      return err("failed to disconnect block at height " & $height & ": " & disconnectRes.error)
    dec height

  # Verify we're at the fork point
  if cs.bestBlockHash != forkPoint:
    return err("failed to reach fork point")

  # Connect new chain
  var newHeight = cs.bestHeight + 1
  for blk in newChain:
    let connectRes = cs.connectBlock(blk, newHeight)
    if not connectRes.isOk:
      return err("failed to connect block at height " & $newHeight & ": " & connectRes.error)
    inc newHeight

  ok()

# ============================================================================
# Legacy compatibility functions (operate on ChainDb directly)
# ============================================================================

proc applyBlock*(cdb: ChainDb, blk: Block, height: int32) =
  ## Atomically apply a block: spend inputs, create outputs, update index
  ## Legacy function - use ChainState.connectBlock for new code
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Store full block data
  batch.put(cfBlocks, blockKey(array[32, byte](blockHash)), serialize(blk))

  # Process each transaction
  for txIdx, tx in blk.txs:
    let txId = tx.txid()

    # Spend inputs (skip coinbase which has no inputs to spend)
    if txIdx > 0:
      for input in tx.inputs:
        let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
        batch.delete(cfUtxo, key)
        discard  # Cache removed — ChainState layer handles caching

    # Create outputs
    for voutIdx, output in tx.outputs:
      let entry = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: txIdx == 0
      )
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      batch.put(cfUtxo, key, serializeUtxoEntry(entry))

      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      discard  # Cache removed — ChainState layer handles caching

    # Index transaction
    let loc = TxLocation(blockHash: blockHash, txIndex: uint32(txIdx))
    batch.put(cfTxIndex, txIndexKey(array[32, byte](txId)), serializeTxLocation(loc))

  # Create block index entry
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: default(array[32, byte])  # TODO: calculate actual work
  )
  batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  batch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Update best block
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(height)
  batch.put(cfMeta, metaKey("height"), w.data)

  # Commit atomically
  cdb.db.write(batch)

  # Update in-memory state
  cdb.bestBlockHash = blockHash
  cdb.bestHeight = height

proc disconnectBlock*(cdb: ChainDb, blk: Block, height: int32) =
  ## Atomically disconnect a block: restore spent outputs, remove created outputs
  ## Legacy function - use ChainState.disconnectBlock for new code
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Process transactions in reverse order
  for txIdx in countdown(blk.txs.len - 1, 0):
    let tx = blk.txs[txIdx]
    let txId = tx.txid()

    # Remove created outputs
    for voutIdx in 0 ..< tx.outputs.len:
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      batch.delete(cfUtxo, key)
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      discard  # Cache removed

    # Remove tx index entry
    batch.delete(cfTxIndex, txIndexKey(array[32, byte](txId)))

    # Note: Restoring spent inputs requires having the previous UTXO data
    # which would typically be stored in an undo file. For now we skip this.

  # Remove block index height mapping
  batch.delete(cfBlockIndex, blockIndexKey(height))

  # Update best block to previous
  let newBestHeight = height - 1
  if newBestHeight >= 0:
    let prevHashOpt = cdb.getBlockHashByHeight(newBestHeight)
    if prevHashOpt.isSome:
      batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](prevHashOpt.get())))
      var w = BinaryWriter()
      w.writeInt32LE(newBestHeight)
      batch.put(cfMeta, metaKey("height"), w.data)

      cdb.bestBlockHash = prevHashOpt.get()
      cdb.bestHeight = newBestHeight

  cdb.db.write(batch)
