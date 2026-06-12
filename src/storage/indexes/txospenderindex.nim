## Transaction-output spender index (txospenderindex)
## Maps a SPENT outpoint -> the transaction that spent it on-chain.
##
## For every input of every NON-coinbase transaction in a connected block this
## index records a single key mapping the SPENT outpoint -> the SPENDING
## transaction (txid, the hash of the confirming block, and the full
## wire-serialized spending tx so `return_spending_tx` can be answered without
## a second DB trip). It is the data source for the CONFIRMED-spend path of the
## `gettxspendingprevout` RPC.
##
## This mirrors Bitcoin Core's `TxoSpenderIndex`
## (bitcoin-core/src/index/txospenderindex.{h,cpp}). Core stores the spending
## tx's on-disk LOCATION (CDiskTxPos) keyed by a per-DB-salted siphash(outpoint)
## and reads the tx back from the block files on lookup (a flat-file
## optimisation that also disambiguates siphash collisions). The
## `txospenderindex.cpp` header comment notes a from-scratch implementation may
## legitimately store `outpoint -> spending-txid` directly; that is the simpler,
## faithful equivalent and is what nimrod does (matching the proven blockbrew /
## ouroboros / rustoshi templates). NO salt and NO separate undo data are
## needed: the disconnect path RE-DERIVES the exact same keys from the
## disconnected block's OWN inputs and erases them, exactly like Core's
## `CustomRemove(BuildSpenderPositions(block))`.
##
## Default-off, gated by `--txospenderindex`, matching Core's
## `DEFAULT_TXOSPENDERINDEX{false}`.
##
## Storage layout (dedicated `cfTxoSpender` column family):
##   key   = 's' || serialized outpoint (1 + 36 bytes: txid[32] || vout[4 LE])
##   value = spending_txid[32] || block_hash[32] || u32 tx_len || tx_bytes
## Best-indexed block is tracked with the shared base-index B/H keys (which use
## a distinct one-byte prefix and never collide with the 's' spend keys), so
## `bestIndexedHeight` / startup reconcile reuse the base-index machinery.
##
## Reorg-safety: the index is folded forward on the PRIMARY block-connect path
## (P2P/IBD live sync + submitblock) and rolled back via nimrod's single unified
## chainstate `disconnectHook`, which fires per disconnected block on BOTH the
## `invalidateblock` path (disconnectBlock) AND the live reorg path
## (handleReorg), disconnect-BEFORE-connect — the same hook coinstatsindex and
## blockfilterindex use. No undo data is consulted: the keys are a pure function
## of the disconnected block's own inputs.
##
## Reference:
##   - bitcoin-core/src/index/txospenderindex.{h,cpp}  (CustomAppend/CustomRemove)
##   - bitcoin-core/src/rpc/mempool.cpp::gettxspendingprevout
##   - nimrod coinstatsindex.nim / txindex.nim (this impl's index plumbing)

import std/options
import ./base
import ../db
import ../undo as chainundo
import ../../primitives/[types, serialize]
import chronicles

type
  ## Decoded value of a spender-index entry.
  TxoSpenderRecord* = object
    spendingTxid*: TxId          ## txid of the spending tx (internal byte order)
    blockHash*: BlockHash        ## hash of the confirming block
    spendingTx*: seq[byte]       ## full wire-serialized spending tx (with witness)

  ## Transaction-output spender index.
  TxoSpenderIndex* = ref object of BaseIndex
    enabled*: bool

const
  DbTxoSpender* = byte('s')  ## Key prefix for spend entries (mirrors Core's
                             ## DB_TXOSPENDERINDEX = 's').

# ============================================================================
# Key / value serialization
# ============================================================================

proc spenderKey*(outpoint: OutPoint): seq[byte] =
  ## Key for a spent outpoint: 's' || txid[32] || vout[4 LE].
  ## A 36-byte outpoint is spent at most once on a single chain, so the key is
  ## unique per chain — no salt and no range query are needed (unlike Core,
  ## which siphashes the outpoint and disambiguates by loading the tx).
  result = @[DbTxoSpender]
  result.add(@(array[32, byte](outpoint.txid)))
  let n = outpoint.vout
  result.add(byte(n and 0xff))
  result.add(byte((n shr 8) and 0xff))
  result.add(byte((n shr 16) and 0xff))
  result.add(byte((n shr 24) and 0xff))

proc serializeSpenderRecord*(rec: TxoSpenderRecord): seq[byte] =
  var w = BinaryWriter()
  w.writeBytes(array[32, byte](rec.spendingTxid))
  w.writeBytes(array[32, byte](rec.blockHash))
  w.writeUint32LE(uint32(rec.spendingTx.len))
  w.writeBytes(rec.spendingTx)
  w.data

proc deserializeSpenderRecord*(data: seq[byte]): TxoSpenderRecord =
  if data.len < 32 + 32 + 4:
    raise newException(IndexError, "invalid TxoSpenderRecord data")
  var r = BinaryReader(data: data, pos: 0)
  result.spendingTxid = TxId(r.readHash())
  result.blockHash = BlockHash(r.readHash())
  let txLen = int(r.readUint32LE())
  if txLen < 0 or 32 + 32 + 4 + txLen > data.len:
    raise newException(IndexError, "invalid TxoSpenderRecord tx length")
  result.spendingTx = r.readBytes(txLen)

# ============================================================================
# Construction
# ============================================================================

proc newTxoSpenderIndex*(db: Database, enabled: bool = true): TxoSpenderIndex =
  ## Create a new txospenderindex. Default-off at the call site (Core's
  ## DEFAULT_TXOSPENDERINDEX{false}); the daemon only constructs this when
  ## --txospenderindex is passed.
  result = TxoSpenderIndex(
    name: "txospenderindex",
    db: db,
    cfHandle: cfTxoSpender,
    state: isIdle,
    bestHeight: -1,
    stopRequested: false,
    enabled: enabled
  )
  if enabled:
    discard result.loadBestBlock()

method customInit*(idx: TxoSpenderIndex): bool =
  idx.enabled

# ============================================================================
# Core BuildSpenderPositions analogue: re-derive every (key, spending-tx) pair
# from a block's own inputs. Used by BOTH connect (write) and disconnect
# (erase), so the keys are a pure function of the block — no undo data.
# ============================================================================

iterator spendsOfBlock(blk: Block): tuple[key: seq[byte], tx: Transaction] =
  for i, tx in blk.txs:
    let coinbase = (i == 0)  # the coinbase is always tx[0]; its single input
                             # has a null prevout and must NOT be indexed.
    if coinbase:
      continue
    for input in tx.inputs:
      yield (spenderKey(input.prevOut), tx)

# ============================================================================
# customAppend / customRemove (BaseIndex virtuals)
# ============================================================================

method customAppend*(idx: TxoSpenderIndex, blockInfo: BlockInfo): bool =
  ## Connect a block: write `spent_outpoint -> spending tx` for every
  ## non-coinbase input. Mirrors Core CustomAppend(BuildSpenderPositions).
  if not idx.enabled:
    return true
  if blockInfo.height == 0:
    return true  # genesis: coinbase-only, nothing to index
  if blockInfo.data.isNone:
    return false

  let blk = blockInfo.data.get()
  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  for (key, tx) in spendsOfBlock(blk):
    let rec = TxoSpenderRecord(
      spendingTxid: txid(tx),
      blockHash: blockInfo.hash,
      spendingTx: serialize(tx)  # full serialization incl. witness
    )
    batch.put(idx.cfHandle, key, serializeSpenderRecord(rec))

  idx.db.write(batch)
  true

method customRemove*(idx: TxoSpenderIndex, blockInfo: BlockInfo): bool =
  ## Disconnect a block (reorg / invalidateblock): RE-DERIVE the block's spend
  ## keys from its own inputs and erase them. Mirrors Core
  ## CustomRemove(BuildSpenderPositions). No undo data needed.
  if not idx.enabled:
    return true
  if blockInfo.data.isNone:
    # Cannot re-derive keys without the block body; leave the index untouched
    # rather than corrupt it. The disconnectHook always supplies the body.
    return false

  let blk = blockInfo.data.get()
  let batch = idx.db.newWriteBatch()
  defer: batch.destroy()

  for (key, _) in spendsOfBlock(blk):
    batch.delete(idx.cfHandle, key)

  idx.db.write(batch)
  true

method customCommit*(idx: TxoSpenderIndex): bool =
  true

# ============================================================================
# Wired connect / disconnect interface (mirrors coinstatsindex.addBlock /
# removeBlock so the daemon wiring in nimrod.nim / sync.nim / rpc/server.nim is
# structurally identical). Safe to no-op when disabled or already-indexed; the
# callers do NOT need to gate.
# ============================================================================

proc addBlock*(idx: TxoSpenderIndex, blk: Block, blockHash: BlockHash,
               height: int32, blockUndo: chainundo.BlockUndo): bool =
  ## Index a single block on the primary connect path. The `blockUndo` argument
  ## is accepted for signature-symmetry with the other indexes' fan-out call
  ## sites (and so the live-sync / submitblock fan-out can pass the same value)
  ## but is UNUSED — txospender keys are derived from the block's own inputs,
  ## not from undo data.
  ##
  ## Mirrors Bitcoin Core BaseIndex::ConnectBlock -> CustomAppend ->
  ## SetBestBlockIndex.
  if idx == nil or not idx.enabled:
    return true
  # Only ever advance; never re-process an already-indexed height (a repeat
  # would re-write identical keys, harmless, but skip for parity with the
  # other indexes and to avoid clobbering a deeper best pointer).
  if height <= idx.bestHeight:
    return true

  let info = base.BlockInfo(
    hash: blockHash,
    prevHash: blk.header.prevBlock,
    height: height,
    data: some(blk),
    undoData: none(base.BlockUndo),
    fileNum: 0,
    dataPos: 0
  )
  try:
    if not idx.processBlock(info):
      warn "txospenderindex: customAppend failed",
           height = height, hash = $blockHash
      return false
  except CatchableError as e:
    warn "txospenderindex: addBlock raised, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  except Exception as e:
    warn "txospenderindex: addBlock raised non-Catchable, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  true

proc removeBlock*(idx: TxoSpenderIndex, blk: Block, blockHash: BlockHash,
                  prevHash: BlockHash, height: int32): bool =
  ## Roll the index back across a single block disconnect (reorg /
  ## invalidateblock): re-derive the disconnected block's spend keys and erase
  ## them. Symmetric counterpart to addBlock.
  ##
  ## Mirrors BaseIndex::BlockDisconnected -> CustomRemove -> revertBlock.
  if idx == nil or not idx.enabled:
    return true
  # Already rolled back past this height — nothing to do (idempotent re-replay).
  if idx.bestHeight < height:
    return true

  let info = base.BlockInfo(
    hash: blockHash,
    prevHash: prevHash,
    height: height,
    data: some(blk),
    undoData: none(base.BlockUndo),
    fileNum: 0,
    dataPos: 0
  )
  try:
    if not idx.revertBlock(info):
      warn "txospenderindex: customRemove failed",
           height = height, hash = $blockHash
      return false
  except CatchableError as e:
    warn "txospenderindex: removeBlock raised, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  except Exception as e:
    warn "txospenderindex: removeBlock raised non-Catchable, skipping",
         height = height, hash = $blockHash, error = e.msg
    return false
  true

# ============================================================================
# Query API (used by gettxspendingprevout / getindexinfo)
# ============================================================================

proc findSpender*(idx: TxoSpenderIndex, outpoint: OutPoint): Option[TxoSpenderRecord] =
  ## Return the on-chain tx that spends `outpoint`, or none when the outpoint is
  ## unspent on-chain. Mirrors Core TxoSpenderIndex::FindSpender (std::nullopt
  ## when unspent).
  if idx == nil or not idx.enabled:
    return none(TxoSpenderRecord)
  let data = idx.db.get(idx.cfHandle, spenderKey(outpoint))
  if data.isNone:
    return none(TxoSpenderRecord)
  try:
    some(deserializeSpenderRecord(data.get()))
  except CatchableError:
    none(TxoSpenderRecord)

proc bestIndexedHeight*(idx: TxoSpenderIndex): int32 =
  ## Highest block height this index has processed (-1 if none).
  ## Mirrors CoinStatsIndex.bestIndexedHeight for getindexinfo parity.
  if idx == nil: return -1
  idx.bestHeight

proc isSynced*(idx: TxoSpenderIndex, tipHeight: int32): bool =
  if idx == nil or not idx.enabled: return false
  idx.bestHeight >= tipHeight
