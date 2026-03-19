## Transaction Index (txindex)
## Maps TxId -> disk location for fast transaction lookup by hash
##
## Storage format:
##   Key: 't' || txid (33 bytes)
##   Value: fileNum (4 bytes) || dataPos (4 bytes) || txOffset (4 bytes)
##
## txOffset is the offset from the start of block data to the transaction,
## allowing direct seeking to the transaction without parsing the whole block.
##
## Reference: Bitcoin Core /src/index/txindex.cpp
## Reference: Bitcoin Core /src/index/disktxpos.h

import std/options
import ./base
import ../db
import ../../primitives/[types, serialize]

type
  ## Position of a transaction on disk
  DiskTxPos* = object
    fileNum*: int32       ## Block file number (blk?????.dat)
    blockDataPos*: int32  ## Position of block data in file
    txOffset*: int32      ## Offset to transaction within block

  ## Transaction index
  TxIndex* = ref object of BaseIndex
    enabled*: bool

const
  DbTxIndex* = byte('t')  ## Key prefix for transaction index entries

# ============================================================================
# Helper for CompactSize length calculation
# ============================================================================

proc compactSizeLen*(v: uint64): int =
  ## Calculate the serialized length of a CompactSize value
  if v < 0xFD:
    1
  elif v <= 0xFFFF:
    3
  elif v <= 0xFFFFFFFF'u64:
    5
  else:
    9

# ============================================================================
# DiskTxPos serialization
# ============================================================================

proc serializeDiskTxPos*(pos: DiskTxPos): seq[byte] =
  var w = BinaryWriter()
  w.writeInt32LE(pos.fileNum)
  w.writeInt32LE(pos.blockDataPos)
  w.writeInt32LE(pos.txOffset)
  w.data

proc deserializeDiskTxPos*(data: seq[byte]): DiskTxPos =
  if data.len < 12:
    raise newException(IndexError, "invalid DiskTxPos data")
  var r = BinaryReader(data: data, pos: 0)
  result.fileNum = r.readInt32LE()
  result.blockDataPos = r.readInt32LE()
  result.txOffset = r.readInt32LE()

# ============================================================================
# Key construction
# ============================================================================

proc txIndexKey*(txid: TxId): seq[byte] =
  ## Key for transaction index entry
  result = @[DbTxIndex]
  result.add(@(array[32, byte](txid)))

# ============================================================================
# TxIndex implementation
# ============================================================================

proc newTxIndex*(db: Database, enabled: bool = true): TxIndex =
  ## Create a new transaction index
  result = TxIndex(
    name: "txindex",
    db: db,
    cfHandle: cfTxIndex,
    state: isIdle,
    bestHeight: -1,
    stopRequested: false,
    enabled: enabled
  )

  # Load best block from DB
  if enabled:
    discard result.loadBestBlock()

method customInit*(idx: TxIndex): bool =
  ## Initialize txindex
  idx.enabled

method customAppend*(idx: TxIndex, blockInfo: BlockInfo): bool =
  ## Process a new block: index all transactions
  ##
  ## Skip genesis block because its outputs are not spendable
  ## (Bitcoin Core quirk that we match for compatibility)
  if not idx.enabled:
    return true

  if blockInfo.height == 0:
    return true  # Skip genesis block

  if blockInfo.data.isNone:
    return false  # Need block data

  let blk = blockInfo.data.get()
  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  # Calculate initial tx offset (after tx count CompactSize)
  var txOffset = int32(compactSizeLen(uint64(blk.txs.len)))

  for tx in blk.txs:
    let txid = txid(tx)
    let pos = DiskTxPos(
      fileNum: blockInfo.fileNum,
      blockDataPos: blockInfo.dataPos,
      txOffset: txOffset
    )

    batch.put(idx.cfHandle, txIndexKey(txid), serializeDiskTxPos(pos))

    # Advance offset by transaction size (with witness)
    txOffset += int32(serialize(tx).len)

  idx.db.write(batch)
  true

method customRemove*(idx: TxIndex, blockInfo: BlockInfo): bool =
  ## Remove a block during reorg
  ## We don't actually delete entries - they become orphan but harmless
  ## Bitcoin Core also doesn't delete on reorg
  true

method customCommit*(idx: TxIndex): bool =
  ## Commit any pending changes
  true

# ============================================================================
# Public API
# ============================================================================

proc readTxPos*(idx: TxIndex, txid: TxId): Option[DiskTxPos] =
  ## Look up transaction disk position by txid
  ## Returns None if not indexed
  if not idx.enabled:
    return none(DiskTxPos)

  let data = idx.db.get(idx.cfHandle, txIndexKey(txid))
  if data.isNone:
    return none(DiskTxPos)

  try:
    some(deserializeDiskTxPos(data.get()))
  except:
    none(DiskTxPos)

proc hasTx*(idx: TxIndex, txid: TxId): bool =
  ## Check if a transaction is indexed
  idx.readTxPos(txid).isSome

proc writeTxs*(idx: TxIndex, positions: seq[tuple[txid: TxId, pos: DiskTxPos]]) =
  ## Batch write transaction positions
  if not idx.enabled or positions.len == 0:
    return

  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  for (txid, pos) in positions:
    batch.put(idx.cfHandle, txIndexKey(txid), serializeDiskTxPos(pos))

  idx.db.write(batch)