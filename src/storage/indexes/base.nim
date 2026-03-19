## Base index infrastructure for optional indexes
## Provides common functionality for txindex, blockfilterindex, and coinstatsindex
##
## All indexes:
## - Run background sync from genesis to tip
## - Support reorg handling (block disconnection)
## - Track sync progress in database
## - Use async/await with chronos for non-blocking operation
##
## Reference: Bitcoin Core /src/index/base.cpp

import std/[options, os]
import chronos
import ../db
import ../../primitives/[types, serialize]
import ../../crypto/hashing

type
  BlockIndexError* = object of CatchableError

  IndexState* = enum
    isIdle       ## Not started
    isSyncing    ## Catching up to chain tip
    isSynced     ## Fully synced, waiting for new blocks
    isStopping   ## Shutting down

  ## Base class for all indexes
  ## Provides common infrastructure for syncing and persistence
  BaseIndex* = ref object of RootObj
    name*: string              ## Index name for logging
    db*: Database              ## RocksDB database
    cfHandle*: ColumnFamily    ## Column family for this index
    state*: IndexState         ## Current sync state
    bestBlockHash*: BlockHash  ## Last indexed block hash
    bestHeight*: int32         ## Last indexed block height
    stopRequested*: bool       ## Signal to stop background sync

  ## Block info passed to index during sync
  BlockInfo* = object
    hash*: BlockHash
    prevHash*: BlockHash
    height*: int32
    data*: Option[Block]
    undoData*: Option[BlockUndo]
    fileNum*: int32
    dataPos*: int32

  ## Interface for block undo data (import to avoid circular dependency)
  BlockUndo* = object
    txUndo*: seq[TxUndo]

  TxUndo* = object
    prevOutputs*: seq[SpentOutput]

  SpentOutput* = object
    output*: TxOut
    height*: int32
    isCoinbase*: bool

const
  # Database key prefixes
  DbBestBlock* = byte('B')     ## Best block hash
  DbBestHeight* = byte('H')    ## Best block height

# ============================================================================
# Database key helpers
# ============================================================================

proc bestBlockKey*(): seq[byte] =
  ## Key for storing best indexed block
  @[DbBestBlock]

proc bestHeightKey*(): seq[byte] =
  ## Key for storing best indexed height
  @[DbBestHeight]

proc heightKey*(height: int32): seq[byte] =
  ## Key for height-indexed data (big-endian for ordered iteration)
  let h = cast[uint32](height)
  result = @[byte('h')]
  result.add(byte((h shr 24) and 0xff))
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))

proc hashKey*(hash: BlockHash): seq[byte] =
  ## Key for hash-indexed data
  result = @[byte('k')]
  result.add(@(array[32, byte](hash)))

# ============================================================================
# Base index methods
# ============================================================================

proc loadBestBlock*(idx: BaseIndex): bool =
  ## Load best block info from database
  let hashData = idx.db.get(idx.cfHandle, bestBlockKey())
  if hashData.isNone or hashData.get().len != 32:
    idx.bestHeight = -1
    idx.bestBlockHash = BlockHash(default(array[32, byte]))
    return false

  var hashBytes: array[32, byte]
  copyMem(addr hashBytes[0], addr hashData.get()[0], 32)
  idx.bestBlockHash = BlockHash(hashBytes)

  let heightData = idx.db.get(idx.cfHandle, bestHeightKey())
  if heightData.isSome and heightData.get().len >= 4:
    var r = BinaryReader(data: heightData.get(), pos: 0)
    idx.bestHeight = r.readInt32LE()
  else:
    idx.bestHeight = -1

  true

proc saveBestBlock*(idx: BaseIndex, hash: BlockHash, height: int32) =
  ## Save best block info to database atomically
  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  batch.put(idx.cfHandle, bestBlockKey(), @(array[32, byte](hash)))

  var w = BinaryWriter()
  w.writeInt32LE(height)
  batch.put(idx.cfHandle, bestHeightKey(), w.data)

  idx.db.write(batch)

  idx.bestBlockHash = hash
  idx.bestHeight = height

proc copyHeightToHashIndex*(idx: BaseIndex, height: int32, hash: BlockHash) =
  ## Copy height-indexed entry to hash-indexed entry (for reorg handling)
  ## This preserves data for the disconnected block before overwriting
  let heightData = idx.db.get(idx.cfHandle, heightKey(height))
  if heightData.isSome:
    idx.db.put(idx.cfHandle, hashKey(hash), heightData.get())

# ============================================================================
# Virtual methods (to be overridden by specific indexes)
# ============================================================================

method customInit*(idx: BaseIndex): bool {.base.} =
  ## Initialize index-specific state
  true

method customAppend*(idx: BaseIndex, blockInfo: BlockInfo): bool {.base.} =
  ## Process a new block (called during forward sync)
  raise newException(BlockIndexError, "customAppend not implemented")

method customRemove*(idx: BaseIndex, blockInfo: BlockInfo): bool {.base.} =
  ## Remove a block (called during reorg)
  raise newException(BlockIndexError, "customRemove not implemented")

method customCommit*(idx: BaseIndex): bool {.base.} =
  ## Commit any pending changes (called after batch of blocks)
  true

# ============================================================================
# Sync loop
# ============================================================================

proc processBlock*(idx: BaseIndex, blockInfo: BlockInfo): bool =
  ## Process a single block during sync
  if not idx.customAppend(blockInfo):
    return false

  idx.saveBestBlock(blockInfo.hash, blockInfo.height)
  true

proc revertBlock*(idx: BaseIndex, blockInfo: BlockInfo): bool =
  ## Revert a single block during reorg
  # Copy current height entry to hash index before overwriting
  idx.copyHeightToHashIndex(blockInfo.height, blockInfo.hash)

  if not idx.customRemove(blockInfo):
    return false

  # Update best block to previous
  idx.saveBestBlock(blockInfo.prevHash, blockInfo.height - 1)
  true

proc requestStop*(idx: BaseIndex) =
  ## Request background sync to stop
  idx.stopRequested = true
  idx.state = isStopping

proc isRunning*(idx: BaseIndex): bool =
  ## Check if index is currently running
  idx.state in {isSyncing, isSynced}
