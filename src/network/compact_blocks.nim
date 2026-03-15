## BIP152 Compact Block Relay
## Implements efficient block propagation using short transaction IDs
## Reference: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
## Reference: Bitcoin Core /src/blockencodings.cpp

import std/[tables, options]
import ../primitives/[types, serialize]
import ../crypto/[hashing, siphash]
import ../mempool/mempool

const
  ## Short ID length in bytes (6 bytes = 48 bits)
  ShortIdLength* = 6

  ## Compact block protocol version 2 (segwit-aware, uses wtxid)
  CompactBlockVersion* = 2'u64

  ## Maximum transactions that can be prefilled
  ## At minimum, coinbase (index 0) must be prefilled
  MaxPrefilledTxns* = 10000

  ## Maximum transactions per block (sanity check)
  ## MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
  MaxBlockTxns* = 4_000_000 div 60

type
  ## Status codes for compact block operations
  ReadStatus* = enum
    rsOk              ## Successfully processed
    rsInvalid         ## Invalid object, peer is sending bogus data
    rsFailed          ## Failed to process (e.g., short ID collision)

  ## A prefilled transaction in a compact block
  ## Index is stored as a differential offset from the previous prefilled tx
  PrefilledTx* = object
    index*: uint16           ## Index in the block (absolute, after decoding)
    tx*: Transaction

  ## Compact block header and short transaction IDs (cmpctblock message)
  ## BIP152: Contains header, nonce for short ID generation, short IDs, and prefilled txs
  CompactBlock* = object
    header*: BlockHeader
    nonce*: uint64           ## Random nonce for SipHash key generation
    shortIds*: seq[array[ShortIdLength, byte]]  ## 6-byte short IDs for non-prefilled txs
    prefilledTxns*: seq[PrefilledTx]

  ## Request for missing transactions (getblocktxn message)
  BlockTxnRequest* = object
    blockHash*: BlockHash
    indexes*: seq[uint16]    ## Indexes of missing transactions (differential encoded on wire)

  ## Response with missing transactions (blocktxn message)
  BlockTxnResponse* = object
    blockHash*: BlockHash
    transactions*: seq[Transaction]

  ## State for a partially downloaded block
  ## Used to reconstruct a block from a compact block and mempool
  PartiallyDownloadedBlock* = object
    header*: BlockHeader
    txnAvailable*: seq[Option[Transaction]]  ## None for missing txs
    prefilledCount*: int     ## Number of prefilled transactions
    mempoolCount*: int       ## Number found in mempool
    extraCount*: int         ## Number found in extra pool (orphans, etc.)
    shortIdMap*: Table[array[ShortIdLength, byte], int]  ## Short ID -> position
    sipHashK0*, sipHashK1*: uint64  ## SipHash keys derived from header+nonce

  ## Compact block relay state per peer
  CompactBlockState* = object
    wantsCompactBlocks*: bool        ## Peer sent sendcmpct with version >= 1
    highBandwidthMode*: bool         ## Peer sent sendcmpct with announce=true
    compactBlockVersion*: uint64     ## Protocol version (1 or 2)
    pendingPartials*: Table[BlockHash, PartiallyDownloadedBlock]
    ## Stats for monitoring
    blocksReceived*: int
    successfulReconstructions*: int
    failedReconstructions*: int
    txnsRequested*: int

# ============================================================================
# Short ID computation
# ============================================================================

proc computeSipHashKeys*(header: BlockHeader, nonce: uint64): (uint64, uint64) =
  ## Compute SipHash-2-4 keys from block header and nonce
  ## Reference: Bitcoin Core blockencodings.cpp FillShortTxIDSelector()
  ##
  ## Steps:
  ## 1. Serialize header + nonce
  ## 2. SHA256 (single, not double) the serialized data
  ## 3. Use first 8 bytes as k0, second 8 bytes as k1

  var w = BinaryWriter()
  w.writeBlockHeader(header)
  w.writeUint64LE(nonce)

  # Single SHA256 (not double!)
  let hash = sha256Single(w.data)

  # Extract k0 and k1 as little-endian uint64
  var k0, k1: uint64
  for i in 0 ..< 8:
    k0 = k0 or (uint64(hash[i]) shl (i * 8))
    k1 = k1 or (uint64(hash[i + 8]) shl (i * 8))

  (k0, k1)

proc computeShortId*(k0, k1: uint64, wtxid: TxId): array[ShortIdLength, byte] =
  ## Compute 6-byte short ID for a transaction
  ## Reference: Bitcoin Core blockencodings.cpp GetShortID()
  ##
  ## ShortID = SipHash-2-4(k0, k1, wtxid) & 0xffffffffffff

  let hash = sipHash(k0, k1, array[32, byte](wtxid))

  # Take lower 6 bytes (little-endian)
  for i in 0 ..< ShortIdLength:
    result[i] = byte((hash shr (i * 8)) and 0xFF)

proc computeShortId*(header: BlockHeader, nonce: uint64, wtxid: TxId): array[ShortIdLength, byte] =
  ## Convenience function: compute short ID from header, nonce, and wtxid
  let (k0, k1) = computeSipHashKeys(header, nonce)
  computeShortId(k0, k1, wtxid)

# ============================================================================
# CompactBlock creation
# ============================================================================

proc newCompactBlock*(blk: Block, nonce: uint64): CompactBlock =
  ## Create a compact block from a full block
  ## Reference: Bitcoin Core blockencodings.cpp CBlockHeaderAndShortTxIDs()
  ##
  ## - Always prefill coinbase (index 0)
  ## - Use wtxid for short ID computation (BIP152 version 2)

  result.header = blk.header
  result.nonce = nonce

  if blk.txs.len == 0:
    return

  let (k0, k1) = computeSipHashKeys(blk.header, nonce)

  # Prefill coinbase transaction (always at index 0)
  result.prefilledTxns.add(PrefilledTx(index: 0, tx: blk.txs[0]))

  # Compute short IDs for remaining transactions using their wtxid
  for i in 1 ..< blk.txs.len:
    let wtxidVal = wtxid(blk.txs[i])
    result.shortIds.add(computeShortId(k0, k1, wtxidVal))

proc blockTxCount*(cb: CompactBlock): int =
  ## Total number of transactions in the block
  cb.shortIds.len + cb.prefilledTxns.len

# ============================================================================
# Serialization
# ============================================================================

proc writePrefilledTx*(w: var BinaryWriter, tx: PrefilledTx, prevIndex: var int) =
  ## Write a prefilled transaction with differential index encoding
  ## Index is encoded as offset from (previous index + 1)

  let diff = int(tx.index) - prevIndex
  w.writeCompactSize(uint64(diff))
  w.writeTransaction(tx.tx, includeWitness = true)
  prevIndex = int(tx.index) + 1

proc readPrefilledTx*(r: var BinaryReader, prevIndex: var int): PrefilledTx =
  ## Read a prefilled transaction with differential index decoding

  let diff = r.readCompactSize()
  let absoluteIndex = prevIndex + int(diff)

  if absoluteIndex > int(high(uint16)):
    raise newException(SerializationError, "prefilled tx index overflow")

  result.index = uint16(absoluteIndex)
  result.tx = r.readTransaction()
  prevIndex = absoluteIndex + 1

proc writeShortId*(w: var BinaryWriter, shortId: array[ShortIdLength, byte]) =
  ## Write a 6-byte short ID
  for i in 0 ..< ShortIdLength:
    w.writeUint8(shortId[i])

proc readShortId*(r: var BinaryReader): array[ShortIdLength, byte] =
  ## Read a 6-byte short ID
  for i in 0 ..< ShortIdLength:
    result[i] = r.readUint8()

proc writeCompactBlock*(w: var BinaryWriter, cb: CompactBlock) =
  ## Serialize a compact block (cmpctblock message payload)

  w.writeBlockHeader(cb.header)
  w.writeUint64LE(cb.nonce)

  # Short IDs
  w.writeCompactSize(uint64(cb.shortIds.len))
  for shortId in cb.shortIds:
    w.writeShortId(shortId)

  # Prefilled transactions (with differential index encoding)
  w.writeCompactSize(uint64(cb.prefilledTxns.len))
  var prevIndex = 0
  for tx in cb.prefilledTxns:
    w.writePrefilledTx(tx, prevIndex)

proc readCompactBlock*(r: var BinaryReader): CompactBlock =
  ## Deserialize a compact block (cmpctblock message payload)

  result.header = r.readBlockHeader()
  result.nonce = r.readUint64LE()

  # Short IDs
  let shortIdCount = r.readCompactSize()
  if shortIdCount > MaxBlockTxns:
    raise newException(SerializationError, "too many short IDs")

  for i in 0 ..< int(shortIdCount):
    result.shortIds.add(r.readShortId())

  # Prefilled transactions
  let prefilledCount = r.readCompactSize()
  if prefilledCount > MaxPrefilledTxns:
    raise newException(SerializationError, "too many prefilled transactions")

  var prevIndex = 0
  for i in 0 ..< int(prefilledCount):
    result.prefilledTxns.add(r.readPrefilledTx(prevIndex))

  # Validate total count
  if result.blockTxCount() > int(high(uint16)):
    raise newException(SerializationError, "block tx count overflowed 16 bits")

proc writeBlockTxnRequest*(w: var BinaryWriter, req: BlockTxnRequest) =
  ## Serialize a getblocktxn request
  ## Indexes are differential encoded

  w.writeBlockHash(req.blockHash)
  w.writeCompactSize(uint64(req.indexes.len))

  var prevIndex = 0
  for idx in req.indexes:
    let diff = int(idx) - prevIndex
    w.writeCompactSize(uint64(diff))
    prevIndex = int(idx) + 1

proc readBlockTxnRequest*(r: var BinaryReader): BlockTxnRequest =
  ## Deserialize a getblocktxn request

  result.blockHash = r.readBlockHash()
  let count = r.readCompactSize()

  var prevIndex = 0
  for i in 0 ..< int(count):
    let diff = r.readCompactSize()
    let absoluteIndex = prevIndex + int(diff)

    if absoluteIndex > int(high(uint16)):
      raise newException(SerializationError, "getblocktxn index overflow")

    result.indexes.add(uint16(absoluteIndex))
    prevIndex = absoluteIndex + 1

proc writeBlockTxnResponse*(w: var BinaryWriter, resp: BlockTxnResponse) =
  ## Serialize a blocktxn response

  w.writeBlockHash(resp.blockHash)
  w.writeCompactSize(uint64(resp.transactions.len))
  for tx in resp.transactions:
    w.writeTransaction(tx, includeWitness = true)

proc readBlockTxnResponse*(r: var BinaryReader): BlockTxnResponse =
  ## Deserialize a blocktxn response

  result.blockHash = r.readBlockHash()
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.transactions.add(r.readTransaction())

# ============================================================================
# Compact block convenience serializers
# ============================================================================

proc serialize*(cb: CompactBlock): seq[byte] =
  var w = BinaryWriter()
  w.writeCompactBlock(cb)
  result = w.data

proc deserializeCompactBlock*(data: seq[byte]): CompactBlock =
  var r = BinaryReader(data: data, pos: 0)
  r.readCompactBlock()

proc serialize*(req: BlockTxnRequest): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockTxnRequest(req)
  result = w.data

proc deserializeBlockTxnRequest*(data: seq[byte]): BlockTxnRequest =
  var r = BinaryReader(data: data, pos: 0)
  r.readBlockTxnRequest()

proc serialize*(resp: BlockTxnResponse): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockTxnResponse(resp)
  result = w.data

proc deserializeBlockTxnResponse*(data: seq[byte]): BlockTxnResponse =
  var r = BinaryReader(data: data, pos: 0)
  r.readBlockTxnResponse()

# ============================================================================
# Block reconstruction
# ============================================================================

proc initPartiallyDownloadedBlock*(cb: CompactBlock): (PartiallyDownloadedBlock, ReadStatus) =
  ## Initialize a partially downloaded block from a compact block
  ## Reference: Bitcoin Core blockencodings.cpp PartiallyDownloadedBlock::InitData()

  var pdb = PartiallyDownloadedBlock()
  pdb.header = cb.header

  # Validate basic structure
  if cb.shortIds.len == 0 and cb.prefilledTxns.len == 0:
    return (pdb, rsInvalid)

  let txCount = cb.blockTxCount()
  if txCount > MaxBlockTxns:
    return (pdb, rsInvalid)

  # Initialize txnAvailable array
  pdb.txnAvailable = newSeq[Option[Transaction]](txCount)

  # Compute SipHash keys
  (pdb.sipHashK0, pdb.sipHashK1) = computeSipHashKeys(cb.header, cb.nonce)

  # Process prefilled transactions
  var lastPrefilledIndex = -1
  for prefilled in cb.prefilledTxns:
    # Validate index ordering
    if int(prefilled.index) <= lastPrefilledIndex:
      return (pdb, rsInvalid)

    # Validate index is within bounds
    if int(prefilled.index) >= txCount:
      return (pdb, rsInvalid)

    # Validate transaction is not null
    if prefilled.tx.inputs.len == 0 and prefilled.tx.outputs.len == 0:
      return (pdb, rsInvalid)

    pdb.txnAvailable[prefilled.index] = some(prefilled.tx)
    lastPrefilledIndex = int(prefilled.index)

  pdb.prefilledCount = cb.prefilledTxns.len

  # Build map from short ID to position
  var shortIdIndex = 0
  for i in 0 ..< txCount:
    if pdb.txnAvailable[i].isNone:
      if shortIdIndex >= cb.shortIds.len:
        return (pdb, rsInvalid)

      let shortId = cb.shortIds[shortIdIndex]

      # Check for short ID collision (same short ID already seen)
      if shortId in pdb.shortIdMap:
        return (pdb, rsFailed)

      pdb.shortIdMap[shortId] = i
      shortIdIndex += 1

  (pdb, rsOk)

proc fillFromMempool*(pdb: var PartiallyDownloadedBlock, mempool: Mempool) =
  ## Fill missing transactions from mempool
  ## Reference: Bitcoin Core blockencodings.cpp PartiallyDownloadedBlock::InitData()
  ##
  ## Uses wtxid for short ID matching (BIP152 version 2)

  for txidKey, entry in mempool.entries:
    # Compute wtxid and short ID
    let wtxidVal = wtxid(entry.tx)
    let shortId = computeShortId(pdb.sipHashK0, pdb.sipHashK1, wtxidVal)

    # Check if this short ID is in our map
    if shortId in pdb.shortIdMap:
      let pos = pdb.shortIdMap[shortId]

      # Only fill if not already filled
      if pdb.txnAvailable[pos].isNone:
        pdb.txnAvailable[pos] = some(entry.tx)
        pdb.mempoolCount += 1

        # Remove from map to avoid double-matching
        pdb.shortIdMap.del(shortId)
      else:
        # Short ID collision - clear the position so we request it
        pdb.txnAvailable[pos] = none(Transaction)
        pdb.mempoolCount -= 1

    # Early exit if all slots filled
    if pdb.shortIdMap.len == 0:
      break

proc fillFromExtraPool*(pdb: var PartiallyDownloadedBlock,
                        extraTxns: openArray[(TxId, Transaction)]) =
  ## Fill from extra transaction pool (orphans, recently confirmed, etc.)
  ## Reference: Bitcoin Core blockencodings.cpp extra_txn parameter

  for (wtxidVal, tx) in extraTxns:
    let shortId = computeShortId(pdb.sipHashK0, pdb.sipHashK1, wtxidVal)

    if shortId in pdb.shortIdMap:
      let pos = pdb.shortIdMap[shortId]

      if pdb.txnAvailable[pos].isNone:
        pdb.txnAvailable[pos] = some(tx)
        pdb.extraCount += 1
        pdb.shortIdMap.del(shortId)
      else:
        # Check for collision with different transaction
        if pdb.txnAvailable[pos].get().wtxid() != wtxidVal:
          pdb.txnAvailable[pos] = none(Transaction)
          pdb.extraCount -= 1

    if pdb.shortIdMap.len == 0:
      break

proc isTxAvailable*(pdb: PartiallyDownloadedBlock, index: int): bool =
  ## Check if a transaction at the given index is available
  if index < 0 or index >= pdb.txnAvailable.len:
    return false
  pdb.txnAvailable[index].isSome

proc getMissingTxIndexes*(pdb: PartiallyDownloadedBlock): seq[uint16] =
  ## Get list of missing transaction indexes
  for i in 0 ..< pdb.txnAvailable.len:
    if pdb.txnAvailable[i].isNone:
      result.add(uint16(i))

proc isComplete*(pdb: PartiallyDownloadedBlock): bool =
  ## Check if all transactions are available
  for tx in pdb.txnAvailable:
    if tx.isNone:
      return false
  true

proc fillMissingTransactions*(pdb: var PartiallyDownloadedBlock,
                               txns: seq[Transaction]): ReadStatus =
  ## Fill missing transactions from a blocktxn response
  ## Reference: Bitcoin Core blockencodings.cpp PartiallyDownloadedBlock::FillBlock()

  var txIndex = 0
  for i in 0 ..< pdb.txnAvailable.len:
    if pdb.txnAvailable[i].isNone:
      if txIndex >= txns.len:
        return rsInvalid
      pdb.txnAvailable[i] = some(txns[txIndex])
      txIndex += 1

  # Check we used all provided transactions
  if txIndex != txns.len:
    return rsInvalid

  rsOk

proc reconstructBlock*(pdb: PartiallyDownloadedBlock): (Block, ReadStatus) =
  ## Reconstruct the full block from the partially downloaded block
  ## Reference: Bitcoin Core blockencodings.cpp PartiallyDownloadedBlock::FillBlock()

  var blk: Block
  blk.header = pdb.header

  for i, txOpt in pdb.txnAvailable:
    if txOpt.isNone:
      return (blk, rsInvalid)
    blk.txs.add(txOpt.get())

  (blk, rsOk)

# ============================================================================
# Compact block state management
# ============================================================================

proc newCompactBlockState*(): CompactBlockState =
  CompactBlockState(
    wantsCompactBlocks: false,
    highBandwidthMode: false,
    compactBlockVersion: 0,
    pendingPartials: initTable[BlockHash, PartiallyDownloadedBlock]()
  )

proc handleSendCmpct*(state: var CompactBlockState, announce: bool, version: uint64) =
  ## Handle sendcmpct message
  ## Reference: Bitcoin Core net_processing.cpp ProcessMessage("sendcmpct")

  # Only accept version 2 (segwit) or version 1
  if version >= 1 and version <= 2:
    state.wantsCompactBlocks = true
    state.compactBlockVersion = version
    state.highBandwidthMode = announce

proc processCompactBlock*(state: var CompactBlockState, cb: CompactBlock,
                          mempool: Mempool): (BlockHash, ReadStatus, seq[uint16]) =
  ## Process an incoming compact block
  ## Returns: (block hash, status, missing tx indexes)

  state.blocksReceived += 1

  # Compute block hash
  let headerData = serialize(cb.header)
  let blockHash = BlockHash(doubleSha256(headerData))

  # Initialize partially downloaded block
  var (pdb, status) = initPartiallyDownloadedBlock(cb)
  if status != rsOk:
    state.failedReconstructions += 1
    return (blockHash, status, @[])

  # Fill from mempool
  pdb.fillFromMempool(mempool)

  # Check if complete
  if pdb.isComplete():
    state.successfulReconstructions += 1
    state.pendingPartials[blockHash] = pdb
    return (blockHash, rsOk, @[])

  # Get missing indexes
  let missing = pdb.getMissingTxIndexes()
  state.txnsRequested += missing.len

  # Store partial for later completion
  state.pendingPartials[blockHash] = pdb

  (blockHash, rsOk, missing)

proc completeBlock*(state: var CompactBlockState, blockHash: BlockHash,
                    txns: seq[Transaction]): (Block, ReadStatus) =
  ## Complete a partially downloaded block with missing transactions

  if blockHash notin state.pendingPartials:
    var emptyBlock: Block
    return (emptyBlock, rsInvalid)

  var pdb = state.pendingPartials[blockHash]

  let status = pdb.fillMissingTransactions(txns)
  if status != rsOk:
    state.failedReconstructions += 1
    return (Block(), status)

  let (blk, reconstructStatus) = pdb.reconstructBlock()
  if reconstructStatus != rsOk:
    state.failedReconstructions += 1
    return (blk, reconstructStatus)

  # Remove from pending
  state.pendingPartials.del(blockHash)
  state.successfulReconstructions += 1

  (blk, rsOk)

proc hasPending*(state: CompactBlockState, blockHash: BlockHash): bool =
  blockHash in state.pendingPartials

proc removePending*(state: var CompactBlockState, blockHash: BlockHash) =
  state.pendingPartials.del(blockHash)

proc getReconstructionStats*(state: CompactBlockState): (int, int, int, float) =
  ## Get (received, success, failed, success rate)
  let total = state.successfulReconstructions + state.failedReconstructions
  let rate = if total > 0: float(state.successfulReconstructions) / float(total) else: 0.0
  (state.blocksReceived, state.successfulReconstructions, state.failedReconstructions, rate)

# ============================================================================
# High-bandwidth mode helpers
# ============================================================================

proc shouldSendCompactBlock*(state: CompactBlockState): bool =
  ## Check if we should send compact blocks to this peer
  state.wantsCompactBlocks and state.compactBlockVersion >= 2

proc supportsHighBandwidth*(state: CompactBlockState): bool =
  ## Check if peer wants high-bandwidth mode (immediate cmpctblock without inv)
  state.highBandwidthMode

proc createBlockTxnRequest*(blockHash: BlockHash, missingIndexes: seq[uint16]): BlockTxnRequest =
  ## Create a getblocktxn request for missing transactions
  BlockTxnRequest(blockHash: blockHash, indexes: missingIndexes)

proc createBlockTxnResponse*(blockHash: BlockHash, blk: Block,
                             requestedIndexes: seq[uint16]): BlockTxnResponse =
  ## Create a blocktxn response for requested transactions
  var resp = BlockTxnResponse(blockHash: blockHash)

  for idx in requestedIndexes:
    if int(idx) < blk.txs.len:
      resp.transactions.add(blk.txs[idx])

  resp
