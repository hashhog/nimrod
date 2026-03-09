## Chainstate management
## Tracks UTXO set, block index, and blockchain state
## Uses RocksDB column families for data separation

import std/[options, tables]
import ./db
import ../primitives/[types, serialize]
import ../crypto/hashing

export db.ColumnFamily

type
  ChainStateError* = object of CatchableError

  BlockStatus* = enum
    bsHeaderOnly    ## Only header stored
    bsDataStored    ## Full block data stored
    bsValidated     ## Block fully validated
    bsInvalid       ## Block validation failed

  BlockIndex* = object
    hash*: BlockHash
    height*: int32
    status*: BlockStatus
    prevHash*: BlockHash
    header*: BlockHeader
    totalWork*: array[32, byte]  ## Cumulative chain work

  UtxoEntry* = object
    output*: TxOut
    height*: int32
    isCoinbase*: bool

  ChainDb* = ref object
    db*: Database
    bestBlockHash*: BlockHash
    bestHeight*: int32
    utxoCache*: Table[string, UtxoEntry]  ## In-memory cache for hot UTXOs

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
  w.data

proc deserializeBlockIndex(data: seq[byte]): BlockIndex =
  var r = BinaryReader(data: data, pos: 0)
  result.hash = r.readBlockHash()
  result.height = r.readInt32LE()
  result.status = BlockStatus(r.readUint8())
  result.prevHash = r.readBlockHash()
  result.header = r.readBlockHeader()
  result.totalWork = r.readHash()

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

# ChainDb operations

proc openChainDb*(path: string): ChainDb =
  ## Open the chain database
  result = ChainDb(
    db: openDatabase(path),
    bestBlockHash: BlockHash(default(array[32, byte])),
    bestHeight: -1,
    utxoCache: initTable[string, UtxoEntry]()
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

# Block storage

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

# Block index operations

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

# UTXO operations

proc putUtxo*(cdb: ChainDb, outpoint: OutPoint, entry: UtxoEntry) =
  ## Add or update UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.put(cfUtxo, key, serializeUtxoEntry(entry))
  cdb.utxoCache[outpointKey(outpoint)] = entry

proc getUtxo*(cdb: ChainDb, outpoint: OutPoint): Option[UtxoEntry] =
  ## Get UTXO entry
  let cacheKey = outpointKey(outpoint)

  # Check cache first
  if cacheKey in cdb.utxoCache:
    return some(cdb.utxoCache[cacheKey])

  # Check database
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  let data = cdb.db.get(cfUtxo, key)
  if data.isSome:
    let entry = deserializeUtxoEntry(data.get())
    cdb.utxoCache[cacheKey] = entry
    return some(entry)

  none(UtxoEntry)

proc deleteUtxo*(cdb: ChainDb, outpoint: OutPoint) =
  ## Remove UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.delete(cfUtxo, key)
  cdb.utxoCache.del(outpointKey(outpoint))

proc hasUtxo*(cdb: ChainDb, outpoint: OutPoint): bool =
  cdb.getUtxo(outpoint).isSome

# TX index operations

proc putTxIndex*(cdb: ChainDb, txid: TxId, location: TxLocation) =
  ## Index a transaction
  cdb.db.put(cfTxIndex, txIndexKey(array[32, byte](txid)), serializeTxLocation(location))

proc getTxIndex*(cdb: ChainDb, txid: TxId): Option[TxLocation] =
  ## Look up transaction location
  let data = cdb.db.get(cfTxIndex, txIndexKey(array[32, byte](txid)))
  if data.isSome:
    return some(deserializeTxLocation(data.get()))
  none(TxLocation)

# Chain state updates

proc updateBestBlock*(cdb: ChainDb, hash: BlockHash, height: int32) =
  ## Update best block pointer
  cdb.bestBlockHash = hash
  cdb.bestHeight = height

  cdb.db.put(cfMeta, metaKey("bestblock"), @(array[32, byte](hash)))

  var w = BinaryWriter()
  w.writeInt32LE(height)
  cdb.db.put(cfMeta, metaKey("height"), w.data)

# Atomic block connect/disconnect using write batches

proc applyBlock*(cdb: ChainDb, blk: Block, height: int32) =
  ## Atomically apply a block: spend inputs, create outputs, update index
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
        cdb.utxoCache.del(outpointKey(input.prevOut))

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
      cdb.utxoCache[outpointKey(outpoint)] = entry

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
      cdb.utxoCache.del(outpointKey(outpoint))

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
