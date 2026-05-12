## Orphan transaction pool
##
## A transaction is an "orphan" when at least one of its inputs spends an
## outpoint that we have not yet seen — neither in our chainstate UTXO set
## nor in the mempool.  Rather than discarding the tx, we hold it briefly
## in case the parent arrives soon (typical case: tx propagation race
## across the relay graph).
##
## Reference: bitcoin-core/src/node/txorphanage.{h,cpp} (PR #28196):
##   - PRIMARY key = wtxid (witness transaction ID, includes witness data)
##   - SECONDARY index: txid → wtxid (for child-lookup keyed on prevout txid)
##   - DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100
##   - MAX_STANDARD_TX_SIZE / 100_000 byte cap per tx
##   - per-peer cap to prevent a single peer from filling the pool
##   - eviction = expired-first then oldest-first
##   - on parent arrival: scan orphans whose inputs reference the parent's
##     outputs and re-feed them through `acceptTransaction`.
##
## The wtxid primary key prevents a segwit malleability attack where an
## adversary strips witness data from a transaction and re-announces it under
## a different wtxid but the same txid, causing the honest orphan to be
## evicted (Core PR #28196 / BIP-339).
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
    txid*: TxId                ## Legacy (non-witness) transaction ID.
    wtxid*: TxId               ## Witness transaction ID (primary key).
    size*: int                 ## Serialized size in bytes (with witness).
    addedAt*: Time             ## Wallclock add time (for expiry).
    fromPeer*: OrphanPeerId    ## Peer that announced the orphan.

  OrphanPool* = ref object
    ## Map from wtxid to orphan entry (BIP-339 / Core PR #28196).
    ## wtxid is the primary key so that witness-stripped re-announcements
    ## of the same transaction do not evict the original segwit orphan.
    entries*: Table[TxId, OrphanEntry]
    ## Secondary index: txid → wtxid.  Used to look up orphans by the
    ## non-witness txid that their inputs reference as prevout.txid, and
    ## to check deduplication when the same txid arrives under a different
    ## witness (segwit malleability).
    txidIndex*: Table[TxId, TxId]
    ## Reverse index: which orphans (by their own wtxid) reference a given
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
    txidIndex: initTable[TxId, TxId](),
    childrenOfParent: initTable[TxId, HashSet[TxId]](),
    peerCounts: initTable[OrphanPeerId, int](),
    maxOrphans: maxOrphans,
    maxPerPeer: maxPerPeer,
    maxTxSize: maxTxSize
  )

proc count*(pool: OrphanPool): int =
  ## Number of orphans currently held.
  pool.entries.len

proc contains*(pool: OrphanPool, wtxid: TxId): bool =
  ## Whether the orphan pool already holds this wtxid (primary key lookup).
  wtxid in pool.entries

proc containsByTxid*(pool: OrphanPool, txid: TxId): bool =
  ## Whether the orphan pool holds a tx with this non-witness txid
  ## (secondary index lookup).  For non-segwit transactions txid == wtxid
  ## so this is equivalent to `contains`; for segwit transactions this
  ## checks the txidIndex.
  txid in pool.txidIndex

proc countForPeer*(pool: OrphanPool, peer: OrphanPeerId): int =
  ## How many orphans a peer currently has in the pool.
  pool.peerCounts.getOrDefault(peer, 0)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

proc removeFromIndices(pool: OrphanPool, entry: OrphanEntry) =
  ## Remove `entry` from all secondary indices and decrement the per-peer
  ## count.  Caller is responsible for `pool.entries.del(entry.wtxid)`.
  # txid → wtxid secondary index
  pool.txidIndex.del(entry.txid)
  # parent-txid → child-wtxid reverse index
  for input in entry.tx.inputs:
    let parentTxid = input.prevOut.txid
    if parentTxid in pool.childrenOfParent:
      var children = pool.childrenOfParent[parentTxid]
      children.excl(entry.wtxid)
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
  ## housekeeping.  The entries table is keyed by wtxid.
  if pool.entries.len == 0:
    return false

  let now = getTime()
  let cutoff = now - initDuration(seconds = OrphanExpireTime)

  # Pass 1: expired entries.
  var victim: TxId   # wtxid of victim
  var found = false
  for wtxid, entry in pool.entries:
    if entry.addedAt <= cutoff:
      victim = wtxid
      found = true
      break

  if not found:
    # Pass 2: oldest entry.  Linear scan; pool is bounded at 100 so this
    # is fine.  We use addedAt as the ordering key.  In the (vanishingly
    # rare) case of identical timestamps we just pick the first hit.
    var oldestTime = now
    for wtxid, entry in pool.entries:
      if entry.addedAt <= oldestTime:
        oldestTime = entry.addedAt
        victim = wtxid
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
  var victim: TxId   # wtxid of victim
  var found = false
  let now = getTime()
  var oldestTime = now
  for wtxid, entry in pool.entries:
    if entry.fromPeer == peer and entry.addedAt <= oldestTime:
      oldestTime = entry.addedAt
      victim = wtxid
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
  ## be made to fit).  Mirrors AddOrphanTx in Core's txorphanage (PR #28196):
  ##
  ##   - primary key is wtxid; deduplication is by wtxid so witness-stripped
  ##     re-announcements of the same txid do not evict the segwit orphan.
  ##   - txidIndex is updated so children can be found by prevout txid.
  ##   - oversized transactions are dropped on the floor (the parent
  ##     would never confirm anyway).
  ##   - already-present orphans are silently skipped.
  ##   - if the per-peer cap is hit, evict that peer's oldest orphan
  ##     before inserting.
  ##   - if the global cap is hit, evict expired-then-oldest until we
  ##     have room.
  let txid = tx.txid()
  let wtxid = tx.wtxid()

  # Already known by wtxid? caller can treat this as success-no-op.
  if wtxid in pool.entries:
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
    wtxid: wtxid,
    size: serialized.len,
    addedAt: getTime(),
    fromPeer: fromPeer
  )
  # Primary index: wtxid → entry
  pool.entries[wtxid] = entry
  # Secondary index: txid → wtxid
  pool.txidIndex[txid] = wtxid
  # Re-read after any evictions above; `peerCount` was captured before
  # the per-peer / global eviction passes, so it can be stale.
  pool.peerCounts[fromPeer] = pool.peerCounts.getOrDefault(fromPeer, 0) + 1

  # Reverse index: parent txid → child wtxids
  for input in tx.inputs:
    let parentTxid = input.prevOut.txid
    if parentTxid notin pool.childrenOfParent:
      pool.childrenOfParent[parentTxid] = initHashSet[TxId]()
    var children = pool.childrenOfParent[parentTxid]
    children.incl(wtxid)
    pool.childrenOfParent[parentTxid] = children

  true

proc remove*(pool: OrphanPool, wtxid: TxId): bool =
  ## Remove an orphan by wtxid (primary key).  Returns true if removed.
  ## Used internally and exposed for testing.
  if wtxid notin pool.entries:
    return false
  let entry = pool.entries[wtxid]
  pool.removeFromIndices(entry)
  pool.entries.del(wtxid)
  true

proc removeByTxid*(pool: OrphanPool, txid: TxId): bool =
  ## Remove an orphan by non-witness txid (secondary index lookup).
  ## Returns true if removed.  Useful for removing an orphan when only
  ## the legacy txid is known (e.g. wallet lookups).
  if txid notin pool.txidIndex:
    return false
  let wtxid = pool.txidIndex[txid]
  pool.remove(wtxid)

proc removeForPeer*(pool: OrphanPool, peer: OrphanPeerId): int =
  ## Drop every orphan announced by `peer`.  Called when the peer
  ## disconnects so we don't keep waiting on parents that will never
  ## arrive on this announcer's behalf.  Returns the number removed.
  var victims: seq[TxId]  # wtxids
  for wtxid, entry in pool.entries:
    if entry.fromPeer == peer:
      victims.add(wtxid)
  for wtxid in victims:
    discard pool.remove(wtxid)
  victims.len

proc takeChildrenOf*(pool: OrphanPool, parentTxid: TxId): seq[OrphanEntry] =
  ## Pop and return every orphan that lists `parentTxid` as one of its
  ## input prevouts.  `parentTxid` is a non-witness txid (the value stored
  ## in prevout.txid fields).  The childrenOfParent index maps parent txid →
  ## child wtxids; we look up the full entry via the primary wtxid key.
  ##
  ## Caller (typically the tx-dispatch path after a successful
  ## `acceptTransaction`) re-feeds these through the mempool now that a
  ## parent is available.  Promoted-or-rejected, the orphan should not stay
  ## in the pool: either it's now in the mempool, or another input is still
  ## missing — but we return it so the caller can decide.
  ##
  ## NOTE: this returns full OrphanEntry rather than just `Transaction`
  ## so the caller can re-add still-orphaned children (e.g. a tx with
  ## two missing parents, only one of which just resolved) under the
  ## same announcer ID.
  if parentTxid notin pool.childrenOfParent:
    return @[]
  let childWtxids = pool.childrenOfParent[parentTxid]
  var entries: seq[OrphanEntry]
  for childWtxid in childWtxids:
    if childWtxid in pool.entries:
      entries.add(pool.entries[childWtxid])
  for entry in entries:
    pool.removeFromIndices(entry)
    pool.entries.del(entry.wtxid)
  entries

proc removeForBlock*(pool: OrphanPool, blk: Block): int =
  ## On block connect: drop any orphan that was confirmed in `blk`, and
  ## any orphan that conflicts with a tx that was confirmed in `blk`
  ## (i.e. the orphan double-spends a now-spent outpoint).  Returns the
  ## number removed.  Mirrors EraseForBlock in Core's modern txorphanage.
  ##
  ## Confirmation match uses the orphan's non-witness txid (entry.txid)
  ## against the block's txids, since blocks are identified by legacy txid.
  ## Conflict detection uses prevout comparison (witness-agnostic).
  ## Victims list contains wtxids (primary key).
  if pool.entries.len == 0:
    return 0
  var spentOutpoints: HashSet[OutPoint]
  var confirmedTxids: HashSet[TxId]
  for tx in blk.txs:
    confirmedTxids.incl(tx.txid())
    for input in tx.inputs:
      spentOutpoints.incl(input.prevOut)

  var victims: seq[TxId]  # wtxids
  for wtxid, entry in pool.entries:
    # Match by non-witness txid: a confirmed tx removes the orphan even if
    # the orphan had different witness data (e.g. replaced before confirmation).
    if entry.txid in confirmedTxids:
      victims.add(wtxid)
      continue
    var conflicts = false
    for input in entry.tx.inputs:
      if input.prevOut in spentOutpoints:
        conflicts = true
        break
    if conflicts:
      victims.add(wtxid)

  for wtxid in victims:
    discard pool.remove(wtxid)
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
  var victims: seq[TxId]  # wtxids
  for wtxid, entry in pool.entries:
    if entry.addedAt <= cutoff:
      victims.add(wtxid)
  for wtxid in victims:
    discard pool.remove(wtxid)
  victims.len
