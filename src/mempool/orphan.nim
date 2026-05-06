## Orphan transaction pool
##
## A transaction is an "orphan" when at least one of its inputs spends an
## outpoint that we have not yet seen — neither in our chainstate UTXO set
## nor in the mempool.  Rather than discarding the tx, we hold it briefly
## in case the parent arrives soon (typical case: tx propagation race
## across the relay graph).
##
## Reference: bitcoin-core/src/node/txorphanage.{h,cpp} (modern), and the
## pre-2021 simpler model documented in net_processing.cpp:
##   - DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100
##   - MAX_STANDARD_TX_SIZE / 100_000 byte cap per tx
##   - per-peer cap to prevent a single peer from filling the pool
##   - eviction = expired-first then oldest-first
##   - on parent arrival: scan orphans whose inputs reference the parent's
##     outputs and re-feed them through `acceptTransaction`.
##
## Threading: not thread-safe; expected to be called from the same async
## task that drives `Mempool.acceptTransaction` (the tx-message dispatch
## path in `nimrod.handleMessage`).

import std/[tables, times, sets, hashes]
import ../primitives/[types, serialize]

const
  ## Maximum total orphan transactions held across all peers.
  ## Mirrors Core DEFAULT_MAX_ORPHAN_TRANSACTIONS (net_processing.cpp).
  MaxOrphanTransactions* = 100

  ## Maximum serialized size of a single orphan tx in bytes.
  ## Mirrors Core's classic 100_000-byte cap; oversized txs would never
  ## make it into the mempool anyway and we don't want to waste memory.
  MaxOrphanTxSize* = 100_000

  ## Per-peer cap.  Picked to allow ~12-13 orphans per peer at the typical
  ## 8-outbound default — Core uses (max / (outbound + 1)) historically;
  ## we hard-code 25 which is generous but still bounded.  An adversarial
  ## peer that exceeds its share has its oldest entries evicted before
  ## another honest peer's are touched.
  MaxOrphansPerPeer* = 25

  ## Stale orphans are dropped after this many seconds (Core: 20 minutes).
  OrphanExpireTime* = 20 * 60

type
  ## Identifies the announcer of an orphan.  We use (address, port) rather
  ## than a numeric NodeId because `Peer` in nimrod doesn't carry one.
  ## The string is owned (not borrowed) so a peer disconnect doesn't
  ## dangle the reference.
  OrphanPeerId* = tuple[address: string, port: uint16]

  OrphanEntry* = object
    tx*: Transaction
    txid*: TxId
    size*: int                 ## Serialized size in bytes (with witness).
    addedAt*: Time             ## Wallclock add time (for expiry).
    fromPeer*: OrphanPeerId    ## Peer that announced the orphan.

  OrphanPool* = ref object
    ## Map from txid to orphan entry.  txid (not wtxid) is the lookup key
    ## because resolution is keyed on which tx-id the parent spends.
    entries*: Table[TxId, OrphanEntry]
    ## Reverse index: which orphans (by their own txid) reference a given
    ## prevout txid as one of their inputs.  Used to make
    ## `processOrphansForParent` O(children) rather than O(pool size).
    childrenOfParent*: Table[TxId, HashSet[TxId]]
    ## Per-peer count.  Updated on add/remove.
    peerCounts*: Table[OrphanPeerId, int]
    ## Max-pool / per-peer / per-tx limits.  Stored as fields so tests can
    ## construct a tiny pool without overflowing the host.
    maxOrphans*: int
    maxPerPeer*: int
    maxTxSize*: int

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

proc newOrphanPool*(maxOrphans: int = MaxOrphanTransactions,
                    maxPerPeer: int = MaxOrphansPerPeer,
                    maxTxSize: int = MaxOrphanTxSize): OrphanPool =
  ## Construct an empty orphan pool with the given limits.
  OrphanPool(
    entries: initTable[TxId, OrphanEntry](),
    childrenOfParent: initTable[TxId, HashSet[TxId]](),
    peerCounts: initTable[OrphanPeerId, int](),
    maxOrphans: maxOrphans,
    maxPerPeer: maxPerPeer,
    maxTxSize: maxTxSize
  )

proc count*(pool: OrphanPool): int =
  ## Number of orphans currently held.
  pool.entries.len

proc contains*(pool: OrphanPool, txid: TxId): bool =
  ## Whether the orphan pool already holds this txid.
  txid in pool.entries

proc countForPeer*(pool: OrphanPool, peer: OrphanPeerId): int =
  ## How many orphans a peer currently has in the pool.
  pool.peerCounts.getOrDefault(peer, 0)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

proc removeFromIndices(pool: OrphanPool, entry: OrphanEntry) =
  ## Remove `entry` from the parent->children reverse index and decrement
  ## the per-peer count.  Caller is responsible for `pool.entries.del`.
  for input in entry.tx.inputs:
    let parentTxid = input.prevOut.txid
    if parentTxid in pool.childrenOfParent:
      var children = pool.childrenOfParent[parentTxid]
      children.excl(entry.txid)
      if children.len == 0:
        pool.childrenOfParent.del(parentTxid)
      else:
        pool.childrenOfParent[parentTxid] = children
  let cur = pool.peerCounts.getOrDefault(entry.fromPeer, 0)
  if cur <= 1:
    pool.peerCounts.del(entry.fromPeer)
  else:
    pool.peerCounts[entry.fromPeer] = cur - 1

proc evictOne*(pool: OrphanPool): bool =
  ## Evict a single orphan to make room.  Strategy:
  ## 1. Drop expired orphans first (added >20 min ago).
  ## 2. Otherwise, drop the oldest orphan in the pool.
  ##
  ## Returns true if an orphan was evicted.  Used by `addOrphan` when
  ## global or per-peer limits are exceeded; also exposed for periodic
  ## housekeeping.
  if pool.entries.len == 0:
    return false

  let now = getTime()
  let cutoff = now - initDuration(seconds = OrphanExpireTime)

  # Pass 1: expired entries.
  var victim: TxId
  var found = false
  for txid, entry in pool.entries:
    if entry.addedAt <= cutoff:
      victim = txid
      found = true
      break

  if not found:
    # Pass 2: oldest entry.  Linear scan; pool is bounded at 100 so this
    # is fine.  We use addedAt as the ordering key.  In the (vanishingly
    # rare) case of identical timestamps we just pick the first hit.
    var oldestTime = now
    for txid, entry in pool.entries:
      if entry.addedAt <= oldestTime:
        oldestTime = entry.addedAt
        victim = txid
        found = true

  if not found:
    return false

  let entry = pool.entries[victim]
  pool.removeFromIndices(entry)
  pool.entries.del(victim)
  true

proc evictPeerOldest(pool: OrphanPool, peer: OrphanPeerId): bool =
  ## Evict the oldest orphan announced by `peer`.  Used when `peer`
  ## exceeds its per-peer cap — we never let one misbehaving peer's
  ## eviction bleed into another peer's slice.  Returns false if `peer`
  ## has no orphans (caller must then call `evictOne` instead).
  var victim: TxId
  var found = false
  let now = getTime()
  var oldestTime = now
  for txid, entry in pool.entries:
    if entry.fromPeer == peer and entry.addedAt <= oldestTime:
      oldestTime = entry.addedAt
      victim = txid
      found = true
  if not found:
    return false
  let entry = pool.entries[victim]
  pool.removeFromIndices(entry)
  pool.entries.del(victim)
  true

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc addOrphan*(pool: OrphanPool, tx: Transaction,
                fromPeer: OrphanPeerId): bool =
  ## Add `tx` to the orphan pool.  Returns true if the tx was added,
  ## false if it was rejected (oversized, already present, or could not
  ## be made to fit).  Mirrors AddOrphanTx in Core's pre-2021 model:
  ##
  ##   - oversized transactions are dropped on the floor (the parent
  ##     would never confirm anyway).
  ##   - already-present orphans are silently skipped.
  ##   - if the per-peer cap is hit, evict that peer's oldest orphan
  ##     before inserting.
  ##   - if the global cap is hit, evict expired-then-oldest until we
  ##     have room.
  let txid = tx.txid()

  # Already known? caller can treat this as success-no-op.
  if txid in pool.entries:
    return false

  # Size cap (with witness, since that's what we'd serialize for relay).
  let serialized = serialize(tx, includeWitness = true)
  if serialized.len > pool.maxTxSize:
    return false

  # Per-peer cap: evict our oldest entry for this peer if we'd overflow.
  let peerCount = pool.peerCounts.getOrDefault(fromPeer, 0)
  if peerCount >= pool.maxPerPeer:
    if not pool.evictPeerOldest(fromPeer):
      # Shouldn't happen — peerCount > 0 implies we have an entry.
      return false

  # Global cap: evict until we fit.  Bounded loop because evictOne()
  # always succeeds when entries.len > 0.
  while pool.entries.len >= pool.maxOrphans:
    if not pool.evictOne():
      return false

  let entry = OrphanEntry(
    tx: tx,
    txid: txid,
    size: serialized.len,
    addedAt: getTime(),
    fromPeer: fromPeer
  )
  pool.entries[txid] = entry
  # Re-read after any evictions above; `peerCount` was captured before
  # the per-peer / global eviction passes, so it can be stale.
  pool.peerCounts[fromPeer] = pool.peerCounts.getOrDefault(fromPeer, 0) + 1

  for input in tx.inputs:
    let parentTxid = input.prevOut.txid
    if parentTxid notin pool.childrenOfParent:
      pool.childrenOfParent[parentTxid] = initHashSet[TxId]()
    var children = pool.childrenOfParent[parentTxid]
    children.incl(txid)
    pool.childrenOfParent[parentTxid] = children

  true

proc remove*(pool: OrphanPool, txid: TxId): bool =
  ## Remove an orphan by txid.  Returns true if removed.  Used internally
  ## and exposed for testing.
  if txid notin pool.entries:
    return false
  let entry = pool.entries[txid]
  pool.removeFromIndices(entry)
  pool.entries.del(txid)
  true

proc removeForPeer*(pool: OrphanPool, peer: OrphanPeerId): int =
  ## Drop every orphan announced by `peer`.  Called when the peer
  ## disconnects so we don't keep waiting on parents that will never
  ## arrive on this announcer's behalf.  Returns the number removed.
  var victims: seq[TxId]
  for txid, entry in pool.entries:
    if entry.fromPeer == peer:
      victims.add(txid)
  for txid in victims:
    discard pool.remove(txid)
  victims.len

proc takeChildrenOf*(pool: OrphanPool, parentTxid: TxId): seq[OrphanEntry] =
  ## Pop and return every orphan that lists `parentTxid` as one of its
  ## input prevouts.  Caller (typically the tx-dispatch path after a
  ## successful `acceptTransaction`) re-feeds these through the mempool
  ## now that a parent is available.  Promoted-or-rejected, the orphan
  ## should not stay in the pool: either it's now in the mempool, or
  ## another input is still missing — but we return it so the caller
  ## can decide.
  ##
  ## NOTE: this returns full OrphanEntry rather than just `Transaction`
  ## so the caller can re-add still-orphaned children (e.g. a tx with
  ## two missing parents, only one of which just resolved) under the
  ## same announcer ID.
  if parentTxid notin pool.childrenOfParent:
    return @[]
  let childTxids = pool.childrenOfParent[parentTxid]
  var entries: seq[OrphanEntry]
  for childTxid in childTxids:
    if childTxid in pool.entries:
      entries.add(pool.entries[childTxid])
  for entry in entries:
    pool.removeFromIndices(entry)
    pool.entries.del(entry.txid)
  entries

proc removeForBlock*(pool: OrphanPool, blk: Block): int =
  ## On block connect: drop any orphan that was confirmed in `blk`, and
  ## any orphan that conflicts with a tx that was confirmed in `blk`
  ## (i.e. the orphan double-spends a now-spent outpoint).  Returns the
  ## number removed.  Mirrors EraseForBlock in Core's modern txorphanage.
  if pool.entries.len == 0:
    return 0
  var spentOutpoints: HashSet[OutPoint]
  var confirmedTxids: HashSet[TxId]
  for tx in blk.txs:
    confirmedTxids.incl(tx.txid())
    for input in tx.inputs:
      spentOutpoints.incl(input.prevOut)

  var victims: seq[TxId]
  for txid, entry in pool.entries:
    if txid in confirmedTxids:
      victims.add(txid)
      continue
    var conflicts = false
    for input in entry.tx.inputs:
      if input.prevOut in spentOutpoints:
        conflicts = true
        break
    if conflicts:
      victims.add(txid)

  for txid in victims:
    discard pool.remove(txid)
  victims.len

proc expireOld*(pool: OrphanPool,
                expireSeconds: int = OrphanExpireTime): int =
  ## Drop every orphan older than `expireSeconds`.  Returns count removed.
  ## Caller is responsible for invoking this periodically (e.g. from the
  ## same housekeeping loop that calls `Mempool.expire`).
  if pool.entries.len == 0:
    return 0
  let now = getTime()
  let cutoff = now - initDuration(seconds = expireSeconds)
  var victims: seq[TxId]
  for txid, entry in pool.entries:
    if entry.addedAt <= cutoff:
      victims.add(txid)
  for txid in victims:
    discard pool.remove(txid)
  victims.len
