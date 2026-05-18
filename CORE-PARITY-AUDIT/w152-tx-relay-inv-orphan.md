# W152 — Tx relay + inv batching + orphan handling (nimrod)

**Wave:** W152 — RelayTransaction / AddTxAnnouncement /
m_tx_inventory_to_send / m_next_inv_send_time / m_tx_inventory_known_filter,
INVENTORY_BROADCAST_PER_SECOND=14 (poisson trickle, was 7 in older Core),
INVENTORY_BROADCAST_MAX=1000, MAX_INV_SZ=50000, MAX_GETDATA_SZ=1000,
MAX_PEER_TX_REQUEST_IN_FLIGHT=100, MAX_PEER_TX_ANNOUNCEMENTS=5000,
GETDATA_TX_INTERVAL=60s, TXID_RELAY_DELAY=2s (BIP-339),
NONPREF_PEER_TX_DELAY=2s, OVERLOADED_PEER_TX_DELAY=2s,
TxOrphanage (m_reserved_usage_per_peer=404000, max_global_latency_score=3000;
modern multi-announcer model), TxRequestTracker (txrequest.cpp scheduler),
ProcessOrphanTx / GetTxToReconsider / AddChildrenToWorkSet,
RecentConfirmedTransactionsFilter / RecentRejectsFilter,
AlreadyHaveTx (orphan + recent_confirmed + recent_rejects + mempool),
RejectIncomingTxs (block-relay-only / feeler / -blocksonly gate),
Misbehaving on oversized inv/getdata or post-verack wtxidrelay.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/net_processing.cpp:126-128` — `MAX_INV_SZ = 50000`,
  `MAX_GETDATA_SZ = 1000`.
- `bitcoin-core/src/net_processing.cpp:172-178` —
  `INVENTORY_BROADCAST_PER_SECOND = 14`,
  `INVENTORY_BROADCAST_TARGET = 14 * INBOUND_INVENTORY_BROADCAST_INTERVAL`,
  `INVENTORY_BROADCAST_MAX = 1000`, `static_assert` chain.
- `bitcoin-core/src/net_processing.cpp:303` —
  `m_tx_inventory_known_filter{50000, 0.000001}` (per-peer CRollingBloomFilter).
- `bitcoin-core/src/net_processing.cpp:308, 315` —
  `m_tx_inventory_to_send`, `m_next_inv_send_time`.
- `bitcoin-core/src/net_processing.cpp:1142-1148` — `AddKnownTx(peer, hash)`
  inserts into `m_tx_inventory_known_filter` on every inbound inv (line 4086)
  AND every outbound serve (line 4404). Prevents echo-back.
- `bitcoin-core/src/net_processing.cpp:4040-4044` — oversized inv:
  `Misbehaving(peer, strprintf("inv message size = %u", vInv.size()))`.
- `bitcoin-core/src/net_processing.cpp:4046, 4079-4084` —
  `RejectIncomingTxs(pfrom)` gates tx invs (block-only / feeler / -blocksonly).
  Violator: `pfrom.fDisconnect = true; return`.
- `bitcoin-core/src/net_processing.cpp:4086, 4089` — `AddKnownTx(peer, inv.hash);
  if (!m_chainman.IsInitialBlockDownload()) AddTxAnnouncement(...)`.
- `bitcoin-core/src/net_processing.cpp:5969-6086` — SendMessages inv batching
  loop: `m_next_inv_send_time` Poisson gating, `INVENTORY_BROADCAST_MAX`
  per-iteration cap, `m_tx_inventory_known_filter.contains(hash)` skip,
  `m_relay_txs == false → m_tx_inventory_to_send.clear()`.
- `bitcoin-core/src/net_processing.cpp:5984-5986` — Poisson:
  outbound `m_rng.rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)`,
  inbound `NextInvToInbounds(current_time, INBOUND_INVENTORY_BROADCAST_INTERVAL, network_key)`.
- `bitcoin-core/src/net_processing.cpp:3921-3927` — post-verack
  `wtxidrelay` ⇒ `pfrom.fDisconnect = true`. Same shape for
  `sendaddrv2` / `sendcmpct` (must arrive pre-verack).
- `bitcoin-core/src/net_processing.cpp:3225-3260` — `ProcessOrphanTx`: ONE
  orphan per call via `GetTxToReconsider(peer.m_id)`, scheduled per-peer in
  `m_more_work` rather than draining a global worklist.
- `bitcoin-core/src/net_processing.cpp:5598-5606` — `RejectIncomingTxs`:
  block-only ⇒ true, feeler ⇒ true, `ignore_incoming_txs && !HasPermission(Relay)`
  ⇒ true.
- `bitcoin-core/src/node/txdownloadman.h:24-38` — scheduler constants:
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `MAX_PEER_TX_ANNOUNCEMENTS=5000`,
  `TXID_RELAY_DELAY=2s`, `NONPREF_PEER_TX_DELAY=2s`,
  `OVERLOADED_PEER_TX_DELAY=2s`, `GETDATA_TX_INTERVAL=60s`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:125-147` — `AlreadyHaveTx`:
  query by wtxid only (not txid! malleability), checks **orphanage**,
  `RecentConfirmedTransactionsFilter`, `RecentRejectsFilter`,
  `RecentRejectsReconsiderableFilter` (with reconsider flag), mempool.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:210-218, 240-253` — request
  delay derivation: `+NONPREF_PEER_TX_DELAY` if non-preferred connection;
  `+TXID_RELAY_DELAY` if gtxid is txid AND any wtxid-relay peer exists;
  `+OVERLOADED_PEER_TX_DELAY` if `CountInFlight(peer) >=
  MAX_PEER_TX_REQUEST_IN_FLIGHT && !relay_permission`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:278` — `RequestedTx(nodeid,
  hash, current_time + GETDATA_TX_INTERVAL)`: requested-tx is rescheduled on
  the OTHER candidate announcers after the 60-s timeout.
- `bitcoin-core/src/node/txdownloadman_impl.h:120-128` —
  `m_lazy_recent_confirmed_transactions = CRollingBloomFilter(48'000, 0.000001)`.
- `bitcoin-core/src/node/txorphanage.h:19-23` — modern orphanage limits:
  `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER = 404'000` (weight-based, not
  count-based); `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`. **No
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100` constant any more.**
- `bitcoin-core/src/node/txorphanage.h:38-99` — modern API surface:
  `AddTx(tx, NodeId peer)`, **`AddAnnouncer(wtxid, NodeId)` — orphans are
  multi-announcer**; `EraseForPeer(NodeId peer)` only removes orphans whose
  ANNOUNCER set becomes empty; `AddChildrenToWorkSet` reassigns work via
  per-peer work set with rng-selected announcer.
- `bitcoin-core/src/node/txorphanage.cpp:527-559` — `AddChildrenToWorkSet`:
  consults `m_outpoint_to_orphan_wtxids` (an outpoint→wtxid reverse index),
  RNG-picks one announcer per child to "own" the reconsider, marks
  `m_reconsider = true` on the chosen announcement.
- `bitcoin-core/src/policy/policy.h:38` — `MAX_STANDARD_TX_WEIGHT = 400'000`
  (= ~100 000 vbytes; orphan size cap in legacy Core was 100 000 bytes
  serialized).
- `bitcoin-core/src/protocol.h` — `MSG_TX = 1`, `MSG_BLOCK = 2`,
  `MSG_FILTERED_BLOCK = 3`, `MSG_CMPCT_BLOCK = 4`, `MSG_WTX = 5`;
  `MSG_WITNESS_FLAG = 1 << 30` (getdata only).

## Files audited

- `src/network/relay.nim` (715 lines) — `RelayManager`, `PeerRelayState`,
  `queueTxInv`, `queueTxInvWithFee`, `relayBlockImmediate`,
  `relayTxImmediate`, `relayTxImmediateWithFee`, `flushTrickle`,
  `trickleLoop`, `maybeSendFeefilter`, `FeeFilterRounder`, `setIBD`,
  `setMempoolMinFeeRate`. (CALLER GREP: ZERO production references; tests
  only.)
- `src/network/peer.nim:99, 105-110, 1102, 1178, 1262, 1358-1360` —
  `peer.relay` field (BIP-37 fRelay), `wtxidRelay` setter (post-verack
  branch at 1358), `peerBloomFiltersEnabled`, `sendVersion` (relay = true
  hardcoded), `messageLoop` (no Misbehaving on parse exception).
- `src/network/peermanager.nim:918-936, 953-978, 972-978` — `broadcastTx`,
  `broadcastBlock`, `broadcastInventory`, `getReadyPeers`.
- `src/network/messages.nim:15-17, 38-53, 365-378, 786-810` — `MaxInvPerMsg`,
  `MaxGetDataSize`, `InvType` enum, `readInvVector`, `inv/getdata/notfound`
  parse path (`raise newException(ValueError, ...)` on oversize).
- `src/network/sync.nim:984-1011, 1158, 1546-1552` — `requestBlocks`,
  IBD detection (`blocksRemaining > 10`), `MaxBlocksPerPeer`,
  in-flight peer rotation for block download.
- `src/mempool/orphan.nim` (397 lines) — `OrphanPool`, `addOrphan`,
  `remove`, `removeForPeer`, `removeForBlock`, `takeChildrenOf`,
  `evictOne`, `evictPeerOldest`, `expireOld`, constants
  (`MaxOrphanTransactions=100`, `MaxOrphansPerPeer=25`,
  `MaxOrphanTxSize=100_000`, `OrphanExpireTime=20*60`).
- `src/nimrod.nim:140-190, 800-892, 891-932, 934-1031, 1141-1187` —
  `NodeState` (`recentlyRejected`, `orphanPool`), block/tx accept hooks
  on mkBlock/mkTx, mkInv dispatch (line 891), mkGetData dispatch (line
  934), mkMempool (BIP-35) serve (line 1141).
- `tests/test_relay.nim`, `tests/test_feefilter.nim` — exhaustive tests
  of `RelayManager` / `FeeFilterRounder` / `queueTxInv*`. Tests pass
  against the dead-code surface.

---

## Gate matrix (35 sub-gates / 10 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RelayManager production wiring | G1: `RelayManager` instantiated in NodeState init | **BUG-1 (P0-DEAD)** — RelayManager never constructed in production; grep `newRelayManager` returns only `tests/test_relay.nim` and `tests/test_feefilter.nim` |
| 1 | … | G2: `queueTxInv` / `queueTxInvWithFee` called from `acceptTransaction` success path | **BUG-1 cross-cite** — nimrod.nim:841 calls `peerManager.broadcastTx` (immediate, no trickle) instead |
| 1 | … | G3: `relayBlockImmediate` called from `processBlock` success | **BUG-1 cross-cite** — nimrod.nim uses `peerManager.broadcastBlock` (immediate, no per-peer known-block tracking) |
| 1 | … | G4: `trickleLoop` started by node entrypoint | **BUG-1 cross-cite** — `rm.start()` never invoked |
| 1 | … | G5: `setIBD(true/false)` flipped by SyncManager when IBD-state transitions | **BUG-2 (P1)** — `setIBD` defined (relay.nim:506-509) but zero callers; the `isIBD` field in RelayManager (line 90) stays `true` forever even after the (dead) instance would have been told otherwise |
| 1 | … | G6: `setMempoolMinFeeRate` driven by mempool eviction floor | **BUG-2 cross-cite** — same shape, zero callers |
| 2 | INVENTORY_BROADCAST_PER_SECOND Poisson timer | G7: per-peer `m_next_inv_send_time` rescheduled with `rand_exp_duration` | **BUG-3 (P0-CDIV)** — production `broadcastTx` (peermanager.nim:918-936) sends to every ready peer IMMEDIATELY. No trickling, no Poisson timer. Bypasses entire BIP-152 fingerprint-prevention design. The Poisson timer exists in `relay.nim::calculatePoissonDelay` (line 188) but the file is dead |
| 2 | … | G8: outbound vs inbound peer different intervals | PARTIAL (definition only) — `OutboundTrickleInterval=5.0`, `InboundTrickleInterval=2.0` in relay.nim:21-22, never consulted |
| 3 | TXID_RELAY_DELAY / NONPREF / OVERLOADED tx-request scheduler | G9: tx-request scheduler exists | **BUG-4 (P0-CDIV)** — no `TxRequestTracker` / `m_txrequest` analogue anywhere in `src/network/` or `src/mempool/`. mkInv at nimrod.nim:891 sends getdata immediately to every announcer |
| 3 | … | G10: `TXID_RELAY_DELAY = 2s` when any wtxid-relay peer exists | **BUG-4 cross-cite** — constant absent |
| 3 | … | G11: `NONPREF_PEER_TX_DELAY = 2s` for inbound / non-preferred peers | **BUG-4 cross-cite** |
| 3 | … | G12: `OVERLOADED_PEER_TX_DELAY = 2s` when peer has ≥100 in-flight | **BUG-4 cross-cite**; also `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` absent |
| 3 | … | G13: `GETDATA_TX_INTERVAL = 60s` reschedule onto another announcer after timeout | **BUG-5 (P0-CDIV)** — getdata is fire-and-forget. No timeout, no fallback peer rotation, no MAX_PEER_TX_ANNOUNCEMENTS=5000 cap. A peer that announces an inv but never delivers leaves the request to never re-issue |
| 4 | MSG_WTX (5) vs MSG_TX (1) dispatch | G14: ignore invTx from wtxid-relay peer | PASS (`nimrod.nim:906-907`) |
| 4 | … | G15: ignore invWtx from legacy peer | PASS (`nimrod.nim:908-909`) |
| 4 | … | G16: getdata MSG_WTX serves tx looked up by wtxid | **BUG-6 (P0-CDIV)** — mkGetData at `nimrod.nim:1007` matches only `invTx` / `invWitnessTx`; `invWtx` (BIP-339 value 5) falls into `else: notFound`. A wtxid-relay peer that issues a properly-formed `getdata MSG_WTX <wtxid>` receives notfound. (cross-cite: this is the same enum that's accepted on inbound inv at line 899) |
| 5 | DEFAULT_MAX_ORPHAN_TRANSACTIONS | G17: count cap matches Core | **BUG-7 (P1)** — `MaxOrphanTransactions = 100` in orphan.nim:34 with comment "Mirrors Core DEFAULT_MAX_ORPHAN_TRANSACTIONS". **The Core constant no longer exists**; modern Core (`txorphanage.h:19-23`) uses `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER = 404'000` (weight-based per-peer) and `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`. Comment is stale by ~2 Core releases |
| 5 | … | G18: multi-announcer per orphan | **BUG-8 (P0-CDIV)** — `OrphanEntry.fromPeer: OrphanPeerId` (singular). Core: `std::set<NodeId> announcers`. Consequences: (a) when the recorded announcer disconnects, the orphan is dropped even if another honest peer also announced it; (b) `addOrphan` returns `false` on duplicate wtxid (line 237-238) instead of adding the new announcer — eviction-protection breaks for orphans we already know |
| 5 | … | G19: weight-based per-peer reservation, not count | NOT IMPLEMENTED — see BUG-7; nimrod uses per-peer count cap 25 (orphan.nim:46) |
| 6 | OrphanByParent / outpoint→orphan reverse index | G20: lookup children by parent txid | PASS — `childrenOfParent: Table[TxId, HashSet[TxId]]` (orphan.nim:79) populated in addOrphan, drained in takeChildrenOf |
| 6 | … | G21: lookup children by parent OUTPOINT (not just txid) | **BUG-9 (P1)** — Core's `m_outpoint_to_orphan_wtxids` keys on (txid, vout). nimrod's `childrenOfParent` keys on txid alone — false positives if orphan X spends outpoint (T,0) and tx T is confirmed but outpoint 0 is unspent in the confirmation, X is requeued for parent resolution it does not actually need |
| 7 | m_recently_announced_invs / known-tx echo prevention | G22: per-peer rolling-bloom of known-txs (50000 entries, FP=1e-6) | **BUG-10 (P0-CDIV)** — `broadcastTx` (peermanager.nim:918-936) sends to **every** ready peer without consulting any known-tx filter. Specifically: (i) no excludePeer argument, so we echo back to the peer that just sent us the tx (nimrod.nim:841 `state.peerManager.broadcastTx(msg.tx)` is called WITHOUT the announcing `peer`); (ii) no AddKnownTx side-effect on receive (line 891-932) so a peer that announces a tx still receives our inv back |
| 7 | … | G23: AddKnownTx on every inbound inv | **BUG-10 cross-cite** — relay.nim has `addKnownTx`, but RelayManager is dead. The production mkInv path at nimrod.nim:891-932 records nothing per-peer |
| 8 | RejectIncomingTxs gate | G24: block-relay-only conns refuse tx invs (disconnect) | **BUG-11 (P0-SEC)** — mkInv handler (nimrod.nim:899-920) processes invTx/invWtx unconditionally. Block-relay-only outbound (`pctBlockRelayOnly`, peermanager.nim:903) is a privacy-fence connection that Core's `RejectIncomingTxs` enforces by disconnect (`net_processing.cpp:5598-5602`). A block-relay-only peer that sends tx invs is fingerprinting us, and we let it |
| 8 | … | G25: feeler conns refuse tx invs (disconnect) | **BUG-11 cross-cite** — same gate, feeler conns also unguarded |
| 8 | … | G26: -blocksonly mode rejects all tx invs | NOT APPLICABLE — no `-blocksonly` flag exists in nimrod CLI |
| 9 | IBD gate on inbound tx invs | G27: do not call AddTxAnnouncement during IBD | **BUG-12 (P1)** — mkInv at nimrod.nim:891-932 has no IBD gate. Core: `if (!m_chainman.IsInitialBlockDownload())` wraps the `AddTxAnnouncement` call (line 4088-4091). nimrod requests tx data during IBD — wasted bandwidth at the worst time |
| 10 | Misbehaving on protocol violations | G28: oversized inv → Misbehaving | **BUG-13 (P0-SEC)** — `messages.nim:789-790` raises `ValueError` on count > MaxInvPerMsg=50000. `peer.messageLoop` (peer.nim:1583-1591) logs `error` and `break`s, falling through to plain disconnect — **no misbehavior score increment**. Peer can immediately reconnect and re-trigger DoS |
| 10 | … | G29: oversized getdata → Misbehaving | **BUG-13 cross-cite** — same shape at messages.nim:797 |
| 10 | … | G30: post-verack `wtxidrelay` → disconnect | **BUG-14 (P0-SEC)** — peer.nim:1358-1360 (`of mkWtxidRelay: peer.wtxidRelay = true`) accepts the message at any point in the connection lifetime. Core (`net_processing.cpp:3921-3927`): post-verack wtxidrelay sets `pfrom.fDisconnect = true`. A misbehaving peer can flip our wtxidRelay state at runtime — including AFTER we already used it to choose invTx vs invWtx for outbound traffic — causing protocol confusion |
| 10 | … | G31: post-verack `sendaddrv2` → disconnect | **BUG-14 cross-cite** — same shape (peer.nim:1362-1364) |
| 11 | AlreadyHaveTx layered lookup | G32: orphanage included in already-have check on inbound inv | **BUG-15 (P0-CDIV)** — mkInv at nimrod.nim:917 checks `mempool.contains` + `recentlyRejected`. **Does not consult orphan pool.** A tx already in our orphan pool will be re-requested from every announcer who advertises it, including from the same peer that gave it to us originally. Core (`txdownloadman_impl.cpp:140`): `m_orphanage->HaveTx(wtxid) → return true` |
| 11 | … | G33: recent_confirmed_transactions filter included | **BUG-16 (P1)** — no `recentConfirmedTransactions` filter exists. Core: `CRollingBloomFilter(48'000, 0.000001)` — after block-connect, peers may re-announce confirmed txs (race against block propagation) and Core fast-rejects via this filter. nimrod re-requests every confirmed tx that's re-announced |
| 12 | Headers-first reaction to block inv | G34: receive block inv → MaybeSendGetHeaders, not direct getdata | **BUG-17 (P1)** — mkInv at nimrod.nim:896-898 sends `invWitnessBlock` getdata immediately on block inv. Core (`net_processing.cpp:4097-4115`): tracks `best_block`, then issues `MaybeSendGetHeaders(GetLocator(m_best_header))` — preserving headers-first invariant. Direct-block-getdata is the legacy pre-BIP-130 path |
| 13 | filtered-block (BIP-37) getdata serve | G35: serve `merkleblock` for invFilteredBlock when peer has bloom filter loaded | **BUG-18 (P1)** — mkGetData at nimrod.nim:1020-1022 falls through `invFilteredBlock` to `notFound`. Bitcoin Core has `MSG_FILTERED_BLOCK` dispatch (this is the W134 fleet-wide BUG-1 / 7-of-10 pattern; nimrod was one of the 7 prior, audit re-confirms it remains uncovered) |

---

## BUG-1 (P0-DEAD) — Entire `RelayManager` subsystem is dead production code

**Severity:** P0-DEAD (715 LOC, 8 public procs, 2 test files). The
`src/network/relay.nim` module (`RelayManager`, `PeerRelayState`,
`FeeFilterRounder`, `queueTxInv`, `queueTxInvWithFee`,
`relayBlockImmediate`, `relayTxImmediate`, `relayTxImmediateWithFee`,
`flushTrickle`, `trickleLoop`, `start`, `stop`, `setIBD`,
`setMempoolMinFeeRate`, `registerPeer`, `unregisterPeer`,
`maybeSendFeefilter`, `sendFeefilterToAllPeers`) is **never instantiated
in production**. A grep across `src/` for `newRelayManager`,
`RelayManager(`, `queueTxInv`, `relayBlockImmediate`, `relayTxImmediate`,
`relayTxImmediateWithFee`, `queueTxInvWithFee`, `trickleLoop` returns
**zero** hits outside `src/network/relay.nim` itself and the test files
`tests/test_relay.nim` / `tests/test_feefilter.nim`.

What nimrod actually does in production:

- **tx-broadcast on accept** (`src/nimrod.nim:841`):
  `asyncSpawn state.peerManager.broadcastTx(msg.tx)`. `broadcastTx`
  (peermanager.nim:918-936) loops over `getReadyPeers()` and sends the
  inv synchronously to **every single one** with no exclusion, no
  trickling, no feefilter, no known-tx dedup, no per-peer schedule.
- **block-broadcast on accept**:
  `state.peerManager.broadcastBlock(block)` (similar shape, no
  exclusion, no per-peer known-block tracking).
- **mempool-update wiring to relay**: there is no wiring of
  `setMempoolMinFeeRate` to mempool eviction (so even if RelayManager
  WERE alive, its feefilter would never update).
- **IBD-state plumbing to relay**: `setIBD` is never called.

This is the most extreme "dead-data plumbing" pattern observed in the
fleet to date: an entire 715-LOC subsystem with its own test suite,
fully implemented (Poisson trickle, FeeFilterRounder logarithmic
buckets, BIP-339 wtxidRelay dispatch, BIP-133 hysteresis,
MAX_MONEY-on-IBD signal, the lot), zero production callers.

**File:** `src/network/relay.nim` (715 lines).

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_tx_inventory_to_send`, `m_next_inv_send_time`, SendMessages
inv-batching loop (line 5969-6086).

**Excerpt (nimrod, the production path that bypasses RelayManager)**

```nim
# src/network/peermanager.nim:918-936
proc broadcastTx*(pm: PeerManager, tx: Transaction) {.async.} =
  ## Broadcast a transaction to all ready peers.
  let wtxidHash = array[32, byte](tx.wtxid())
  let txidHash  = array[32, byte](tx.txid())
  for peer in pm.getReadyPeers():           # <-- every peer, every tx
    let (itemType, itemHash) =
      if peer.wtxidRelay:                     # <-- only thing we check
        (invWtx, wtxidHash)
      else:
        (invTx, txidHash)
    let inv = @[InvVector(invType: itemType, hash: itemHash)]
    let msg = newInv(inv)
    try:
      await peer.sendMessage(msg)             # <-- synchronous, no trickle
    except CatchableError as e:
      debug "failed to broadcast tx inv", peer = $peer, error = e.msg
```

**Impact:**
- Tx fingerprinting / origin inference: a peer that observes the
  ordering and timing of inv messages from us can correlate the
  emission moment to mempool acceptance, identifying us as the source
  of a tx within ~1 RTT instead of having to wait the average ~5 s
  Poisson trickle window Core uses for outbound peers.
- BIP-133 feefilter ignored on outbound: every peer that sent us
  `feefilter` is still flooded with low-fee tx invs, wasting their
  bandwidth and giving operators a reason to disconnect us.
- Echo-back to sender: see BUG-10 (cross-cite). The fix for BUG-10
  belongs in RelayManager but RelayManager is dead.
- BIP-339 wtxidRelay dispatch IS handled correctly in the production
  path, by accident — peermanager.nim:926-930 keys on `peer.wtxidRelay`
  before sending the right inv type. So that piece doesn't depend on
  RelayManager.
- Test churn: future RelayManager changes will pass their tests and
  break nothing in production because production doesn't use them.

The cheapest fix is probably to wire RelayManager in (start() it from
the node entrypoint, replace peermanager.broadcastTx with a queueTxInv
call, plumb setIBD and setMempoolMinFeeRate). But until that happens,
the entire BIP-133 / BIP-152 / fingerprint-protection design exists on
paper only.

---

## BUG-2 (P1) — `setIBD` / `setMempoolMinFeeRate` are plumb-gate-then-don't-flip

**Severity:** P1 (fleet pattern "plumb-gate-then-flip" — **6th distinct
nimrod instance**; previous: W141 BUG-8 mempoolminfee divisor, etc.).
RelayManager has two setter methods that, even if the dead subsystem
were activated, would never be called from anywhere:

```nim
# src/network/relay.nim:501-509
proc setMempoolMinFeeRate*(rm: RelayManager, feeRate: int64) =
  rm.mempoolMinFeeRate = max(feeRate, DefaultMinRelayFee)

proc setIBD*(rm: RelayManager, isIBD: bool) =
  rm.isIBD = isIBD
```

A grep across the codebase shows **zero callers**. So:
- `RelayManager.isIBD` starts `true` (line 185 default) and stays
  `true` for the life of the (would-be) process. The
  `getCurrentFeefilterValue` proc returns `MaxMoney` forever (line
  515-517), so the dead `maybeSendFeefilter` (line 519-575) would emit
  `feefilter=MAX_MONEY` to every peer for the life of the node, even
  long after IBD finished. This is the IBD-feefilter pattern Core uses
  during IBD only.
- `RelayManager.mempoolMinFeeRate` is initialised to
  `DefaultMinRelayFee = 1000 sat/kvB` and never updated.
  `getCurrentFeefilterValue` (line 511-517) bypasses it during IBD,
  and post-IBD it returns the rounded constant — meaning the
  feefilter would never reflect actual mempool eviction pressure.

This is exactly the same architectural class as W141 BUG-8 (mempoolminfee
1000× divisor regression) and W144 BUG-3 (is_p2sh-not-propagated): a
parameter is plumbed through the type system and even appears in the
public API, but the call site that should drive the flip never exists.

**File:** `src/network/relay.nim:90, 184-186, 501-517`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::MaybeSendFeefilter`
(driven by `m_mempool.GetMinFee()` on every iteration of SendMessages).

**Impact:** even after BUG-1 is fixed (RelayManager wired into
production), these two getters return stale values; the feefilter
gate is effectively a no-op.

---

## BUG-3 (P0-CDIV) — `broadcastTx` sends to every peer immediately, no Poisson trickle

**Severity:** P0-CDIV. Bitcoin Core's outbound tx-inv emission is
strictly Poisson-trickled per peer:

- per-peer `m_next_inv_send_time` field
  (`net_processing.cpp:5984-5986`), refreshed each iteration by
  `rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)` for
  outbound or `NextInvToInbounds(...)` (network-key-modulated) for
  inbound.
- per-iteration cap `INVENTORY_BROADCAST_MAX = 1000` items
  (net_processing.cpp:176).
- per-iteration target `INVENTORY_BROADCAST_TARGET = 14 * 5` = 70
  inbound peers, scaled by mempool size (net_processing.cpp:174).

nimrod's production `broadcastTx` (peermanager.nim:918-936) does NONE
of this. Every accepted tx is announced to every ready peer in a tight
loop, all within microseconds of mempool acceptance. The fingerprint
implications are well-documented in the BIP-152 / Erlay literature
(bitcoinops.org notes Core's trickle interval as "the single most
important privacy property of mempool broadcast").

This is BUG-1's downstream consequence: the trickle infrastructure
exists (relay.nim::calculatePoissonDelay line 188-198, the per-peer
`nextTrickleTime` field at line 76), but the only consumer is the
dead trickleLoop.

**File:** `src/network/peermanager.nim:918-936`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5969-6086`
(SendMessages inv-batching loop), `:5984-5986`
(`rand_exp_duration`), `:172-178` (constants).

**Impact:**
- tx-origin inference: an observer with two peers connected to nimrod
  can correlate inv arrival times to ≤1 RTT, vs ~5 s with Core's
  trickle.
- bandwidth burst on big-mempool-acceptance moments (e.g.,
  many-input tx with chained CPFP): broadcastTx emits N×P sends
  (N txs, P peers) in one tight goroutine spawn.

---

## BUG-4 (P0-CDIV) — No tx-request scheduler; getdata fires for every inv from every announcer

**Severity:** P0-CDIV. Bitcoin Core's `m_txdownloadman` (txrequest.cpp)
is a delay-and-rotate scheduler. When N peers announce the same tx
inv, Core picks one (preferred = outbound first, then RNG among
non-preferred + delays as per
`txdownloadman_impl.cpp:210-218, 240-253`), waits the appropriate delay
window (NONPREF + TXID_RELAY + OVERLOADED, summed), issues one
getdata, and schedules a fallback at
`current_time + GETDATA_TX_INTERVAL = 60s`. If the requested peer
doesn't deliver in 60 s the next-best candidate is requested instead.

nimrod's mkInv handler (nimrod.nim:891-932) has zero scheduling:

```nim
for item in msg.invItems:
  if item.invType == invTx or item.invType == invWitnessTx or
      item.invType == invWtx:
    ...
    if not state.mempool.contains(lookupHash) and
        lookupHash notin state.recentlyRejected:
      txInvs.add(InvVector(invType: invWitnessTx, hash: item.hash))
...
if txInvs.len > 0:
  ...
  asyncSpawn spawnSafe(peer.sendGetData(batch))    # <-- immediate, per-announcer
```

If 8 peers announce the same tx, we send 8 parallel getdata requests
and receive the tx 8 times. Memory + bandwidth cost is 8x.

Beyond that, the missing constants are:
- `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100` — soft cap so a single peer
  can't make us issue more than 100 outstanding getdata requests.
- `MAX_PEER_TX_ANNOUNCEMENTS = 5000` — hard cap so a single peer
  can't flood our request scheduler.
- `TXID_RELAY_DELAY = 2s` — BIP-339: prefer wtxid-relay peers over
  txid peers, give wtxid peers a 2-s head start to deliver.
- `NONPREF_PEER_TX_DELAY = 2s` — outbound peers get first crack;
  inbound are penalised.
- `OVERLOADED_PEER_TX_DELAY = 2s` — peers already at the in-flight
  cap are deprioritised.
- `GETDATA_TX_INTERVAL = 60s` — request timeout + reschedule.

**File:** `src/nimrod.nim:891-932` (mkInv handler); zero implementation
elsewhere.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:24-38`,
`bitcoin-core/src/node/txdownloadman_impl.cpp:210-278`,
`bitcoin-core/src/txrequest.cpp` (the full scheduler).

**Impact:**
- N× bandwidth waste on every popular tx inv (a tx broadcast across
  the network reaches every well-connected node from ~10 peers; we
  download it 10 times).
- DoS asymmetry: a single hostile peer announcing 50 000 distinct
  inv hashes (max per inv message) triggers us to issue 50 000
  getdata requests to that one peer (subject to MaxGetDataSize=1000
  batching but otherwise unbounded). No `MAX_PEER_TX_ANNOUNCEMENTS`
  cap.
- BIP-339 wtxid-preference is destroyed: we don't wait
  TXID_RELAY_DELAY for a wtxid-relay peer to deliver; we issue
  getdata immediately to the first txid-peer that announces.

---

## BUG-5 (P0-CDIV) — No GETDATA_TX_INTERVAL timeout + reschedule

**Severity:** P0-CDIV (cross-cite BUG-4). Even if a single getdata is
issued per inv, Core schedules a 60-s timeout (`GETDATA_TX_INTERVAL`)
after which the request is failed-over to another announcer. nimrod
treats getdata as fire-and-forget: there is no `requested_at`
timestamp, no per-tx in-flight set, no timeout, no fallback.

Failure mode: a peer announces inv(X), we send getdata(X) to it, the
peer never delivers (silent drop / network partition / actively
adversarial). We never request X from any other peer. The tx is
effectively lost until either (a) the peer disconnects (then nothing
re-triggers the request) or (b) some other peer later announces X
again, in which case we re-request from that peer (no de-dup since we
have no per-peer in-flight set).

If the original peer disconnects before delivering, the tx is gone
permanently.

**File:** `src/nimrod.nim:891-932`.

**Core ref:**
`bitcoin-core/src/node/txdownloadman_impl.cpp:278`
(`RequestedTx(nodeid, hash, current_time + GETDATA_TX_INTERVAL)`),
`txrequest.cpp::GetRequestable` (timeout sweep that re-queues failed
requests).

**Impact:**
- tx-relay liveness gap: a slow / lossy / adversarial peer can
  withhold a tx we requested and we'll never know to ask anyone else.
- mempool drift vs Core under partial-partition scenarios.

---

## BUG-6 (P0-CDIV) — `getdata MSG_WTX` returns notfound; lookup case missing

**Severity:** P0-CDIV. BIP-339 defined `MSG_WTX = 5` so wtxid-relay
peers can request transactions by their witness-tx-id, which is
necessary because under wtxid-relay the inv they received was an
invWtx, and the peer has only the wtxid to identify the transaction
they want.

The nimrod mkGetData dispatch:

```nim
# src/nimrod.nim:1007-1022
elif item.invType == invTx or item.invType == invWitnessTx:
  let txid = TxId(item.hash)              # <-- hash treated as TxID
  let entryOpt = ... state.mempool.get(txid) ...
...
else:
  # Unknown / unsupported inv type (filtered-block, etc.)
  notFound.add(item)                       # <-- invWtx lands here
```

There is no branch for `invWtx`. A well-behaved BIP-339 peer that
receives our invWtx announcement and replies with `getdata MSG_WTX`
gets `notfound` instead of the transaction. The peer marks us as
"announced-but-not-served" and may disconnect under stale-peer rules.

Conversely, nimrod's outbound queueTxInv (dead code) and
peermanager.broadcastTx DO send invWtx to wtxid-relay peers, so we
make the announcement we can't honour.

**File:** `src/nimrod.nim:1007, 1020-1022`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
handles `MSG_WTX` by `m_mempool.get(GenTxid::Wtxid(hash))` — the
mempool exposes a wtxid index for this purpose.

**Impact:** BIP-339 wtxid-relay peers see us as broken — we
announce-then-can't-serve. Effectively breaks tx serve for the
majority of modern Core peers.

**Note:** the lookup-by-wtxid would need a mempool API change too;
`mempool.get(txid)` keys on legacy txid. nimrod's mempool has
`entry.tx.wtxid()` available per-entry (used at nimrod.nim:1168 in the
mempool serve loop) but no index. So this needs an O(N) scan today or
a new index.

---

## BUG-7 (P1) — `MaxOrphanTransactions = 100` comment claims to mirror a Core constant that no longer exists

**Severity:** P1 ("stale-Core-anchor" — first explicit instance in
nimrod tracking). `src/mempool/orphan.nim:31-34`:

```nim
const
  ## Maximum total orphan transactions held across all peers.
  ## Mirrors Core DEFAULT_MAX_ORPHAN_TRANSACTIONS (net_processing.cpp).
  MaxOrphanTransactions* = 100
```

The constant `DEFAULT_MAX_ORPHAN_TRANSACTIONS` has been **removed**
from Bitcoin Core. Modern Core (`bitcoin-core/src/node/txorphanage.h:19-23`):

```cpp
/** Default value for TxOrphanage::m_reserved_usage_per_peer. ... */
static constexpr int64_t DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER{404'000};
/** Default value for TxOrphanage::m_max_global_latency_score. ... */
static constexpr unsigned int DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE{3000};
```

The orphanage is now **weight-based, per-peer reserved**. Each peer is
guaranteed 404 kB of orphan weight (≈ 1 max-standard tx); the global
cap is implicit (peers × reservation, plus a latency-score eviction
trigger). nimrod is stuck on a legacy 2-constant world.

Consequences (none currently catastrophic, all defensive-depth):
- nimrod's 100-orphan cap = ~10 max-standard txs total (assuming
  100 kB each); Core's modern cap scales with peer count.
- nimrod's MaxOrphansPerPeer=25 (orphan.nim:46) is fine but uses
  count not weight, so a peer that delivers 25 1-kB orphans uses
  25 kB; a peer that delivers 25 100-kB orphans uses 2.5 MB. Core's
  per-peer cap is byte-uniform.
- nimrod's `MaxOrphanTxSize = 100_000` (orphan.nim:39) is a per-tx
  serialized-byte cap; Core uses weight (`MAX_STANDARD_TX_WEIGHT =
  400'000` = 100 000 vbytes); for a witness-heavy tx the same
  serialized byte count fits a different weight.

**File:** `src/mempool/orphan.nim:31-49`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:19-23` (current);
`git log -- bitcoin-core/src/net_processing.cpp` shows the constant
was removed in PR #28970 / Bitcoin Core 28.0.

**Impact:** defensive-depth gap; stale comment misleads future
contributors into thinking nimrod tracks Core.

---

## BUG-8 (P0-CDIV) — Orphans are single-announcer; eraseForPeer over-evicts

**Severity:** P0-CDIV. Bitcoin Core's modern TxOrphanage
(`txorphanage.h:38-99`) tracks orphans with a **set of announcers**:

```cpp
struct OrphanInfo {
    CTransactionRef tx;
    std::set<NodeId> announcers;
    ...
};
virtual bool AddAnnouncer(const Wtxid& wtxid, NodeId peer) = 0;
virtual void EraseForPeer(NodeId peer) = 0;
```

`EraseForPeer(peer)` walks orphans whose announcer set includes peer,
removes peer from the set, and only erases the orphan when the
announcer set becomes empty.

nimrod's `OrphanEntry` (orphan.nim:58-64) has a single
`fromPeer: OrphanPeerId` field:

```nim
OrphanEntry* = object
  tx*: Transaction
  txid*: TxId
  wtxid*: TxId
  size*: int
  addedAt*: Time
  fromPeer*: OrphanPeerId    # <-- singular
```

Consequences:
- `addOrphan` (orphan.nim:217-283) returns `false` on duplicate wtxid
  (line 237-238). A second announcer of the same orphan is dropped on
  the floor; we cannot "add this peer as another announcer to record
  that they have the tx too". When the original announcer disconnects
  (line 304-314: `removeForPeer`), the orphan is destroyed even
  though another honest peer could re-provide it.
- `removeForPeer` over-evicts: every orphan a peer announced is
  removed, no honest-peer-survives logic.
- Adversarial scenario: an attacker connects, announces a parent X
  whose child Y is in mempool, racing to "claim" the announcer slot.
  Then disconnects. Y is dropped. Honest peers that ALSO would have
  delivered Y get filtered out of the orphan pool because we said
  `addOrphan = false` (already-known by wtxid).

**File:** `src/mempool/orphan.nim:58-64, 217-283, 304-314`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:42-86`,
`bitcoin-core/src/node/txorphanage.cpp::EraseForPeer` (walks
announcers set, removes only when empty).

**Impact:**
- orphan churn under peer-rotation conditions; we forget orphans we
  should still hold.
- DoS primitive: malicious peer can preemptively claim orphan slots
  to make honest peers' announcements be deduplicated as "already
  known" then disconnect to flush them.

---

## BUG-9 (P1) — `childrenOfParent` indexes by txid, not outpoint

**Severity:** P1. Bitcoin Core's `m_outpoint_to_orphan_wtxids`
(`bitcoin-core/src/node/txorphanage.cpp:527-535`) keys child
lookups on the full `COutPoint(txid, vout)`. nimrod's
`childrenOfParent: Table[TxId, HashSet[TxId]]` (orphan.nim:79)
keys on txid only:

```nim
for input in tx.inputs:
  let parentTxid = input.prevOut.txid
  if parentTxid notin pool.childrenOfParent:
    pool.childrenOfParent[parentTxid] = initHashSet[TxId]()
  ...
  pool.childrenOfParent[parentTxid] = children
```

`takeChildrenOf(parentTxid)` (line 316-342) returns all orphans whose
inputs reference `parentTxid` — regardless of which output index they
reference. After a parent confirms, we re-feed orphans referencing
ANY output index of the parent. False positives: an orphan that
spent the parent's output index 5 is re-fed when only output index 0
was created. The acceptTransaction call will reject with
"input not found" again — wasted work, not corruption — but it does
mean every parent-resolve does extra mempool work proportional to
the count of orphans referencing any output of the parent.

Worse failure mode: an orphan whose input references the same txid
but a DIFFERENT output index than the one in the confirming tx will
be re-fed and then "re-orphaned" on the failed acceptance because the
mkTx handler classifies its rejection as "input not found"
(nimrod.nim:834). The orphan is then re-added to the pool. Net result:
the orphan is repeatedly re-fed on every block that contains any tx
with its parent's txid.

**File:** `src/mempool/orphan.nim:79, 274-281, 316-342`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:527-535`.

**Impact:** wasted resolution work; orphan-pool churn proportional to
parent-txid-collisions; minor mempool-acceptance latency.

---

## BUG-10 (P0-CDIV) — `broadcastTx` echoes back to sender, no per-peer known-tx filter

**Severity:** P0-CDIV. Bitcoin Core's
`m_tx_inventory_known_filter` (`net_processing.cpp:303`) is a 50000-
entry `CRollingBloomFilter(FP=1e-6)` per peer. Every inbound inv adds
the hash to the sender's filter (line 4086 `AddKnownTx(peer, inv.hash)`),
and every outbound serve adds the hash to the receiver's filter
(line 4404 `AddKnownTx`). On SendMessages, the per-peer
`m_tx_inventory_to_send` set is filtered through this bloom
(line 6067 `if (tx_relay->m_tx_inventory_known_filter.contains(inv.hash))
continue`) so we never echo back a tx the peer has already announced
or fetched.

nimrod has TWO compounding gaps:

**1. No excludePeer at call site (nimrod.nim:841)**

```nim
if accepted:
  # Relay to peers
  asyncSpawn state.peerManager.broadcastTx(msg.tx)   # <-- no `peer` argument
```

We just accepted a tx from `peer` and immediately rebroadcast to
**every** ready peer including `peer`. The peer sees the inv of the
tx it just sent us, treats it as confirmation we received, but the
inv itself is wasted (and trivially identifies us as the next-hop
relay).

**2. No filter in `broadcastTx` (peermanager.nim:918-936)**

```nim
proc broadcastTx*(pm: PeerManager, tx: Transaction) {.async.} =
  ...
  for peer in pm.getReadyPeers():
    let (itemType, itemHash) = ...
    let inv = @[InvVector(invType: itemType, hash: itemHash)]
    let msg = newInv(inv)
    try:
      await peer.sendMessage(msg)        # <-- no known-tx check
```

The function signature lacks any `excludePeer` parameter and the
function has no concept of "this peer already knows about hash X".

The `addKnownTx` proc in relay.nim:225-230 exists but, per BUG-1, is
dead code. The production path has no equivalent state.

**File:** `src/network/peermanager.nim:918-936`;
`src/nimrod.nim:841, 864`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:303, 1142-1148,
4086, 4404, 6067` (`AddKnownTx` + per-peer
`m_tx_inventory_known_filter`).

**Excerpt (nimrod, the echo-back call site)**

```nim
# src/nimrod.nim:840-841
if accepted:
  # Relay to peers
  asyncSpawn state.peerManager.broadcastTx(msg.tx)
  # ^^^^ msg.tx was just received from `peer`, but `peer` is not excluded
```

**Impact:**
- bandwidth: 2× tx-inv traffic per accepted tx (N peers × 1 inv,
  vs (N-1) peers × 1 inv).
- privacy: peer X can fingerprint nimrod by observing that any tx X
  sends us appears as an inv back from us almost immediately. In
  Core, X never receives back the inv it sent.
- adversarial loop: if peer X and our other peer Y both have us as a
  relay, X sends tx, we echo to Y, Y echoes to X via its own relay
  graph, X echoes back to us... Core's known-tx filter breaks this
  cycle; nimrod relies on `recentlyRejected` (which is only populated
  on rejection) and `mempool.contains` (which prevents re-acceptance,
  not re-announcement on inv).

---

## BUG-11 (P0-SEC) — Block-relay-only and feeler conns accept tx invs

**Severity:** P0-SEC ("privacy-fence-violated" fleet pattern, first
nimrod instance). Bitcoin Core's `RejectIncomingTxs(pfrom)`
(`net_processing.cpp:5598-5606`):

```cpp
bool PeerManagerImpl::RejectIncomingTxs(const CNode& peer) const
{
    if (peer.IsBlockOnlyConn()) return true;
    if (peer.IsFeelerConn()) return true;
    if (m_opts.ignore_incoming_txs && !peer.HasPermission(Relay)) return true;
    return false;
}
```

is called from the mkInv handler at line 4046 with the consequence
that a block-relay-only or feeler peer that sends a tx inv is
**disconnected** (line 4082: `pfrom.fDisconnect = true`).

The privacy rationale: block-relay-only outbound connections exist
specifically so an observer cannot enumerate our entire outbound peer
graph by injecting a tx into one outbound and watching it propagate;
if block-only conns can send us tx invs, the partition is meaningless.

nimrod's mkInv handler (nimrod.nim:891-932) has no equivalent gate.
`pctBlockRelayOnly` connections (defined peermanager.nim:903) are
treated identically to full-relay peers for inbound tx invs:

```nim
of mkInv:
  var blockInvs: seq[InvVector]
  var txInvs: seq[InvVector]
  for item in msg.invItems:
    if item.invType == invBlock or item.invType == invWitnessBlock:
      ...
    elif item.invType == invTx or item.invType == invWitnessTx or
         item.invType == invWtx:
      # <-- no connType check
      ...
```

**File:** `src/nimrod.nim:891-932`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5598-5606`
(`RejectIncomingTxs`), `:4046, 4079-4084` (gate + disconnect).

**Impact:**
- privacy: a remote observer can perform tx-injection-and-watch
  fingerprinting attacks against nimrod's block-relay-only outbound
  graph (exactly what block-relay-only conns exist to prevent).
- feeler-conn pollution: feeler conns are meant as 60-s tip-test
  probes; accepting tx invs from them defeats their purpose and
  inflates their bandwidth.

---

## BUG-12 (P1) — No IBD gate on inbound tx invs

**Severity:** P1. Bitcoin Core's mkInv handler wraps the
`AddTxAnnouncement` call in an IBD check:

```cpp
// net_processing.cpp:4088-4091
if (!m_chainman.IsInitialBlockDownload()) {
    const bool fAlreadyHave{m_txdownloadman.AddTxAnnouncement(...)};
    LogDebug(BCLog::NET, "got inv: %s %s peer=%d", inv.ToString(), ...);
}
```

During IBD, Core silently drops tx invs (peer.relay status is set to
false in our outbound version, so well-behaved peers never send us
invs in the first place, but defensive-depth says drop them if any
arrive). nimrod's mkInv (nimrod.nim:891-932) has no IBD check —
during IBD, we accept tx invs, send getdata for each, accept the
txs, run them through `mempool.acceptTransaction`. Failure modes
during IBD are non-zero: utxos may not exist yet, parent txs aren't
available, fees can't be computed against the IBD-incomplete chain
state.

In nimrod's specific case the result is mostly "input not found" →
orphan pool (nimrod.nim:873-879), which fills the orphan pool with
txs that will never resolve until IBD completes — wasted memory.

**File:** `src/nimrod.nim:891-932`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4088-4091`.

**Impact:**
- bandwidth waste during IBD (we download tx data we can't yet
  validate).
- orphan-pool fill during IBD (100-orphan cap may saturate from
  spurious "missing parent" failures unrelated to actual missing
  parents).
- BIP-37 fRelay=false is advertised on outbound by Core during IBD
  but nimrod's sendVersion (peer.nim:596) hardcodes `relay = true` —
  see BUG-19 cross-cite.

---

## BUG-13 (P0-SEC) — Oversized inv/getdata bumps no misbehavior score; plain disconnect lets peer reconnect

**Severity:** P0-SEC. Bitcoin Core's mkInv handler:

```cpp
// net_processing.cpp:4040-4044
if (vInv.size() > MAX_INV_SZ)
{
    Misbehaving(peer, strprintf("inv message size = %u", vInv.size()));
    return;
}
```

`Misbehaving(peer, "...")` bumps the peer's score and, on threshold,
adds the peer to the discouragement filter (24-h ban). The peer
cannot just reconnect.

nimrod's parse-side check (messages.nim:789-790):

```nim
let count = r.readCompactSize()
if count > MaxInvPerMsg.uint64:
  raise newException(ValueError, "inv message size = " & $count &
                     " exceeds MaxInvPerMsg")
```

The exception bubbles up to `messageLoop` (peer.nim:1583-1591):

```nim
except PeerError as e:
  if not peer.closing:
    error "peer error in message loop", peer = $peer, error = e.msg
  break
except CatchableError as e:
  if not peer.closing:
    error "error in message loop", peer = $peer, error = e.msg
  break

if not peer.closing:
  await peer.disconnect("message loop ended")
```

The peer is disconnected but no misbehavior is recorded, no
discouragement happens. The peer can immediately reconnect and
re-trigger the same DoS. Same shape for oversized getdata
(messages.nim:797) and oversized notfound (messages.nim:805).

This is similar to (but not identical to) the W128 fleet-wide
banman bug — there the issue was conflating ban + discouragement;
here the issue is that the misbehavior signal never reaches the
banman at all.

**File:** `src/network/peer.nim:1583-1594`; `src/network/messages.nim:789-790,
797-798, 805-806`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4040-4044`,
`Misbehaving(peer, ...)`.

**Impact:**
- DoS asymmetry: hostile peer can repeatedly send oversized inv,
  forcing us to disconnect-and-reaccept-handshake (~RTT × 5 cost
  per cycle for us, ~zero cost for them).
- discouragement filter is never populated from inv/getdata abuse —
  the banman exists but doesn't get the signal.

---

## BUG-14 (P0-SEC) — Post-verack `wtxidrelay` / `sendaddrv2` flips state without disconnect

**Severity:** P0-SEC. Bitcoin Core's wtxidrelay handler:

```cpp
// net_processing.cpp:3921-3927
if (msg_type == NetMsgType::WTXIDRELAY) {
    if (pfrom.fSuccessfullyConnected) {
        LogDebug(BCLog::NET, "wtxidrelay received after verack, %s",
                 pfrom.DisconnectMsg());
        pfrom.fDisconnect = true;
        return;
    }
```

Post-verack wtxidrelay is a protocol violation and the peer is
disconnected. Rationale: wtxidrelay is a negotiation that MUST
happen before verack so both sides know the inv-type semantics from
message 1.

nimrod's post-verack handler at peer.nim:1358-1360:

```nim
of mkWtxidRelay:
  peer.wtxidRelay = true
  trace "peer supports wtxidrelay", peer = $peer
```

There is no `if peer.handshakeComplete: disconnect` gate. A peer can
send wtxidrelay long after verack, flipping our `peer.wtxidRelay`
flag from false to true mid-conversation. Consequences:
- if we'd already chosen `invTx` for a tx we recently announced to
  this peer (because at the time `peer.wtxidRelay` was false), the
  peer's known-tx set (if it had one — Core's
  m_tx_inventory_known_filter inserts by inv.hash, which is the
  hash we sent, so the peer's filter has the txid not the wtxid)
  may now mismatch. Re-announcements end up duplicated or skipped.
- attacker tooling can flip our wtxidRelay state at runtime to
  trigger specific dispatch paths (e.g., to force us to honour
  `getdata MSG_WTX` which is what BUG-6 documents we DON'T honour
  correctly — combining BUG-6 and BUG-14 lets the attacker stall
  our tx serve to them).

Same shape for `mkSendAddrV2` post-verack (peer.nim:1362-1364) — Core
treats post-verack sendaddrv2 as a protocol violation; nimrod accepts
it silently.

**File:** `src/network/peer.nim:1358-1364`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3921-3927`
(wtxidrelay), `:3884-3893` (sendaddrv2 same gate).

**Impact:**
- state-flip mid-conversation: peer.wtxidRelay can flip from false
  to true at any time, leading to mixed-namespace inv emissions
  (some txids, some wtxids, same peer).
- DoS / fingerprint vector: attacker uses post-verack feature msgs
  to probe what our internal state looks like in different orderings.

---

## BUG-15 (P0-CDIV) — `AlreadyHave` check skips orphan pool; orphans re-requested from every announcer

**Severity:** P0-CDIV. Bitcoin Core's `AlreadyHaveTx`
(`txdownloadman_impl.cpp:125-147`) checks **four** locations:

```cpp
if (m_orphanage->HaveTx(Wtxid::FromUint256(hash))) return true;         // 1. orphan
if (include_reconsiderable && RecentRejectsReconsiderableFilter().contains(hash)) return true;
if (RecentConfirmedTransactionsFilter().contains(hash)) return true;    // 3. recent confirmed
return RecentRejectsFilter().contains(hash) || ... m_mempool.exists(...); // 2+4
```

nimrod's mkInv check (nimrod.nim:917-918):

```nim
if not state.mempool.contains(lookupHash) and
    lookupHash notin state.recentlyRejected:
  txInvs.add(InvVector(invType: invWitnessTx, hash: item.hash))
```

checks **two** of the four: mempool + recent-rejects. Missing:
- **orphan pool**: a tx already in our orphan pool will be
  re-requested. Multiple peers announcing the same orphan parent
  triggers N redundant getdata requests. The mkTx handler will then
  call `orphanPool.addOrphan` (line 879) which returns `false`
  (already-known) without recording the new announcer (BUG-8) — the
  bandwidth is wasted.
- **recent_confirmed**: BUG-16.

The Core comment at txdownloadman_impl.cpp:129-135 explicitly warns
against indexing the orphan by txid (must use wtxid) because of
malleability — but emphasises that consulting the orphanage IS
required. nimrod skips this entirely.

**File:** `src/nimrod.nim:891-932` (specifically lines 917-918).

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp:125-147`.

**Impact:**
- bandwidth waste: every orphan we hold is re-requested from every
  peer that subsequently announces it. With multiple parents, this
  scales as orphans × peers.
- cross-cite BUG-4 + BUG-8: combined with no tx-request scheduler
  and single-announcer orphans, this is the worst nimrod tx-relay
  perf path.

---

## BUG-16 (P1) — No `recentConfirmedTransactions` filter; confirmed txs re-requested on re-announcement

**Severity:** P1. Bitcoin Core maintains a
`CRollingBloomFilter(48'000, 0.000001)` of recently-confirmed
transaction hashes (`txdownloadman_impl.h:120-128`,
`m_lazy_recent_confirmed_transactions`). After block-connect, every
tx in the new block is inserted into this filter. Then when a peer
re-announces a confirmed tx (race between block propagation and tx
inv propagation), `AlreadyHaveTx` fast-rejects via the filter,
skipping the wasted getdata.

nimrod has no such filter. After block-connect, the mkTx handler
(nimrod.nim:817) clears `recentlyRejected`:

```nim
# Clear recently-rejected filter -- rejection reasons may no longer apply
state.recentlyRejected.clear()
```

so any tx that was in recentlyRejected is now eligible for
re-request. AND the `removeForBlock` (nimrod.nim:811) pops the
confirmed txs out of the mempool. So when a peer re-announces a
just-confirmed tx, nimrod has no record that we just confirmed it —
both `mempool.contains` and `recentlyRejected.contains` return false,
and we send a getdata for a tx we just received in a block.

The bug is most visible in the seconds immediately after a block
arrives, when peers are still gossiping the now-confirmed txs.

**File:** `src/nimrod.nim:811-817` (block-connect bookkeeping);
no `recentConfirmedTransactions` field exists on NodeState.

**Core ref:**
`bitcoin-core/src/node/txdownloadman_impl.h:120-128`
(filter declaration), `txdownloadman_impl.cpp:Confirm` or similar
block-connect hook that inserts into the filter.

**Impact:**
- ~5-10 s post-block-connect bandwidth burst: we re-request every
  just-confirmed tx from every peer that re-announces it.
- benign, but a fleet pattern: this is a known operational waste
  Core fixed in 0.21 (PR #19184); nimrod never had the fix.

---

## BUG-17 (P1) — Block invs trigger direct getdata, not headers-first reaction

**Severity:** P1. Bitcoin Core's mkInv handler tracks `best_block`
across the inv list (`net_processing.cpp:4051, 4077`) and after the
loop:

```cpp
// net_processing.cpp:4097-4115
if (best_block != nullptr) {
    CNodeState& state{*Assert(State(pfrom.GetId()))};
    if (state.fSyncStarted || (!peer.m_inv_triggered_getheaders_before_sync && *best_block != m_last_block_inv_triggering_headers_sync)) {
        if (MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer)) {
            ...
        }
        m_last_block_inv_triggering_headers_sync = *best_block;
    }
}
```

issues a `getheaders` instead of a direct `getdata`. This preserves
the headers-first invariant — we walk the chain via headers before
ever fetching block bodies.

nimrod's mkInv handler at nimrod.nim:896-898 immediately issues
`getdata MSG_WITNESS_BLOCK` for every block inv:

```nim
if item.invType == invBlock or item.invType == invWitnessBlock:
  # Request as witness block for segwit support
  blockInvs.add(InvVector(invType: invWitnessBlock, hash: item.hash))
```

This is the pre-BIP-130 (2014) behaviour. Consequences:
- N peers announcing the same block → N parallel getdata for the
  block → ~1 MB × N download (mainnet). Core's headers-first sync
  picks one peer to serve the block body.
- No `IsBlockRequested` tracking on the receive side. We don't know
  the block is already being fetched. The blocksInFlight counter
  exists (peer.nim:138) but is incremented only by the active sync
  manager request path (sync.nim:1546-1552), not by inv-driven
  getdata.

**File:** `src/nimrod.nim:891-922`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4097-4115`,
`MaybeSendGetHeaders`, `IsBlockRequested`.

**Impact:**
- bandwidth: block inv from N peers triggers N parallel ~1 MB block
  fetches.
- headers-first invariant broken: nimrod can be made to fetch
  arbitrary header chains by sending invBlock for unknown headers
  (BIP-130 explicitly disallows this).

---

## BUG-18 (P1) — `getdata MSG_FILTERED_BLOCK` falls through to notfound (W134 fleet pattern)

**Severity:** P1. The mkGetData handler at nimrod.nim:954-1022
handles `invBlock`/`invWitnessBlock`/`invCmpctBlock`/`invTx`/
`invWitnessTx` but the `else` branch at line 1020-1022 catches
`invFilteredBlock` and emits notfound:

```nim
else:
  # Unknown / unsupported inv type (filtered-block, etc.)
  notFound.add(item)
```

Bitcoin Core's MSG_FILTERED_BLOCK dispatch
(`net_processing.cpp::ProcessGetData`) builds a `CMerkleBlock`
(partial Merkle tree) for the peer's loaded bloom filter and serves
it. Without bloom filter support (BIP-37), this is a serve-side
no-op anyway — BUT the consequence in nimrod is that a peer with
a loaded filter gets notfound for what it expected to be a
merkleblock. Many SPV clients treat this as a protocol violation
and disconnect.

This is the **W134 fleet-wide BUG-1 (7 of 10 impls)** pattern. The
nimrod-specific bug is that the impl claims (peer.nim:572-573) to
intentionally not advertise NODE_BLOOM, which should mean no SPV
client requests merkleblocks from us. But (a) some SPV clients
ignore NODE_BLOOM advertisement and just try anyway, and (b) the
mkMempool handler (nimrod.nim:1141-1187) is BIP-35 specific and is
gated by `peerBloomFiltersEnabled()` (NIMROD_PEER_BLOOM_FILTERS env);
if the env is set, BIP-35 is served but BIP-37 isn't, leaving the
peer in a half-functional state.

**File:** `src/nimrod.nim:1020-1022`; `src/network/messages.nim:42`
(InvType enum has invFilteredBlock = 3 but no dispatch).

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
MSG_FILTERED_BLOCK case.

**Impact:**
- SPV clients that try to use us as a peer get notfound; many
  disconnect.
- fleet pattern consistency: W134 BUG-1 7-of-10 → still 7-of-10 after
  this audit.

---

## BUG-19 (P1) — `sendVersion` hardcodes `relay = true` regardless of IBD or block-relay-only

**Severity:** P1. Bitcoin Core's outbound version (`net.cpp:1572`)
derives the relay bit from `RejectIncomingTxs(pnode)`:

```cpp
my_tx_relay = !RejectIncomingTxs(pnode);
```

so block-relay-only and feeler outbound connections advertise
`relay=false` to the remote peer. This is the BIP-37 wire signal
that says "do not send me tx invs". Honest peers will respect it.

nimrod's `sendVersion` (peer.nim:587-597):

```nim
let msg = newVersionMsg(
  version = ProtocolVersion,
  services = ourServices,
  timestamp = stdtimes.getTime().toUnix(),
  addrRecv = NetAddress(services: NodeNetwork, port: peer.port),
  addrFrom = NetAddress(services: ourServices, port: peer.params.p2pPort),
  nonce = peer.localNonce,
  userAgent = UserAgent,
  startHeight = ourHeight,
  relay = true                                  # <-- always
)
```

hardcodes `relay = true` — even for block-relay-only outbound and
even during IBD when Core would advertise relay=false. Combined with
BUG-11 (we don't reject tx invs from block-relay-only peers
either), block-relay-only connections are NOT relay-only on the
nimrod side: we advertise willingness to receive tx, we accept
tx invs from them, we send tx invs back.

**File:** `src/network/peer.nim:587-597`.

**Core ref:** `bitcoin-core/src/net.cpp:1572`,
`bitcoin-core/src/net_processing.cpp:5598-5606` (RejectIncomingTxs).

**Impact:**
- BIP-37 wire signal broken: honest Core peers receive our
  block-relay-only outbound and treat us as a full-relay peer,
  pushing tx invs across the channel.
- IBD relay-bit broken: we receive tx invs during IBD that Core
  would have suppressed at the wire level.

---

## BUG-20 (P1) — Orphan-resolution worklist capped at 64 iterations; silent drop after

**Severity:** P1. The mkTx orphan-resolution loop (nimrod.nim:847-872):

```nim
if state.orphanPool != nil:
  var work = @[txid]
  var iterations = 0
  while work.len > 0 and iterations < 64:        # <-- hard cap
    inc iterations
    let parent = work.pop()
    let pending = state.orphanPool.takeChildrenOf(parent)
    for child in pending:
      ...
      if childOk:
        ...
        work.add(child.txid)
      else:
        ...
```

The `iterations < 64` cap silently drops remaining work. With a
deeply chained orphan tree (think CPFP packages of 25+ depth), the
DAG walk halts mid-resolution, leaving some orphans in the pool that
COULD have been resolved.

Bitcoin Core's `ProcessOrphanTx` (`net_processing.cpp:3225-3260`)
processes one orphan per call but is rescheduled in
`m_more_work_set` (per-peer work set) so the orphan-resolution
loop's effective depth is bounded only by mempool acceptance
latency, not by an arbitrary 64.

nimrod's 64 is documented nowhere; it's a magic number. Given the
orphan pool cap is 100 (BUG-7), 64 happens to cover most realistic
resolution depths, but a 100-tx chained CPFP package with two roots
arriving in order parent-of-roots-first would hit the cap.

**File:** `src/nimrod.nim:849`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3225-3260` +
`m_more_work_set` per-peer reschedule.

**Impact:**
- deep CPFP packages may have stragglers left in orphan pool that
  resolve only after the orphan times out and re-enters via the
  next inv → getdata cycle.
- not catastrophic, but undocumented.

---

## BUG-21 (P1) — `expireOld` and `removeForPeer` are defined but never called

**Severity:** P1 ("dead-data plumbing" / "plumb-gate-then-don't-flip"
**7th distinct nimrod instance** this audit). The orphan pool
exposes two housekeeping methods:

```nim
# src/mempool/orphan.nim:304-314
proc removeForPeer*(pool: OrphanPool, peer: OrphanPeerId): int

# src/mempool/orphan.nim:382-397
proc expireOld*(pool: OrphanPool, expireSeconds: int = OrphanExpireTime): int
```

Neither is called anywhere in production. A grep over `src/` returns
zero callers for `removeForPeer` (orphan-pool variant), and zero
callers for `expireOld` other than its own declaration.

Consequences:
- when a peer disconnects, every orphan that peer announced stays
  in the pool until it ages out via `evictOne`'s expired-pass
  (orphan.nim:164-170). Since `evictOne` is only called from
  `addOrphan` when the pool is full (line 254), the orphans
  effectively persist until a new orphan arrives and triggers
  eviction. A low-traffic node with one orphan in the pool from a
  long-disconnected peer never expires it.
- the 20-min `OrphanExpireTime` (orphan.nim:49) is observed only by
  `evictOne`'s opportunistic check, not by any periodic sweep.
  No housekeeping loop calls `expireOld`.
- This is exactly the dead-data-plumbing pattern from W138
  (ChainstateManager wiring) — the API is fully defined and tested,
  but the consumer never wires it up.

**File:** `src/mempool/orphan.nim:304-314, 382-397`;
no caller exists in `src/`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::EraseForPeer`
(called from net_processing.cpp peer-disconnect path) and
`LimitOrphans` (called from `m_more_work_set` processing loop).

**Impact:**
- orphan pool fills with disconnected-peer detritus.
- 20-min expiry is a soft suggestion; orphans can live until pool
  fills.

---

## BUG-22 (P0-CDIV / W141 carry-forward) — `mempoolminfee` divisor 1000× too large; **5+ weeks open, 3 audits without closure**

**Severity:** P0-CDIV (W141 BUG-8 still open). `handleGetMempoolInfo`
in `src/rpc/server.nim:1199-1213`:

```nim
proc handleGetMempoolInfo*(rpc: RpcServer): JsonNode =
  let minFee = rpc.mempool.minFeeRate / 100000000.0  # Convert sat/vbyte to BTC/kB
  ...
  %*{
    ...
    "mempoolminfee": minFee,
    "minrelaytxfee": minFee,
    ...
```

`rpc.mempool.minFeeRate` is in sat/vbyte (`src/mempool/mempool.nim:69`
comment: `## Minimum fee rate to accept (sat/vbyte)`). To convert
sat/vbyte to BTC/kvB:

- sat/vbyte × 1000 vB/kvB = sat/kvB
- sat/kvB ÷ 100 000 000 sat/BTC = BTC/kvB
- combined: sat/vbyte × 1000 ÷ 100 000 000 = sat/vbyte ÷ 100 000

The code uses divisor `100 000 000` instead of `100 000`. The
emitted `mempoolminfee` and `minrelaytxfee` values are
**1000× too small**. For a node with `minFeeRate = 1 sat/vbyte`
(the default), `getmempoolinfo` reports `mempoolminfee = 0.00000001`
BTC/kvB instead of `0.00001` BTC/kvB. Any wallet driving fee
selection off this value will under-fee by 3 decimal orders of
magnitude.

This bug was first flagged in **W141 BUG-8** (~5+ weeks ago, per
auto-memory:
"W141 BUG-8 mempoolminfee 1000× divisor 5+ weeks open, 3 audits
without closure"). Three subsequent audits (W141, W144, W150) failed
to close. The fix is a single-character edit
(`/ 100000000.0` → `/ 100000.0`).

**File:** `src/rpc/server.nim:1200`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
emits `mempoolminfee` in BTC/kvB via `ValueFromAmount(
m_node.mempool->GetMinFee().GetFeePerK())` where `GetFeePerK()`
returns sat/kvB then `ValueFromAmount` divides by 100 000 000.

**Excerpt (nimrod, the open bug)**

```nim
# src/rpc/server.nim:1199-1213
proc handleGetMempoolInfo*(rpc: RpcServer): JsonNode =
  let minFee = rpc.mempool.minFeeRate / 100000000.0  # <-- WRONG: should be /100000.0
  # Calculate total fees
  var totalFeeSat: int64 = 0
  for _, entry in rpc.mempool.entries:
    totalFeeSat += int64(entry.fee)
  %*{
    "loaded": true,
    "size": rpc.mempool.count,
    "bytes": rpc.mempool.size,
    "usage": rpc.mempool.size,
    "total_fee": float64(totalFeeSat) / 100000000.0,
    "maxmempool": rpc.mempool.maxSize,
    "mempoolminfee": minFee,          # <-- 1000× too small
    "minrelaytxfee": minFee,          # <-- 1000× too small
```

This is also a tx-relay-adjacent bug: walletbots and fee-estimators
use `mempoolminfee` to set minimum-fee thresholds. A nimrod fleet
node reports a near-zero floor, causing wallets to broadcast at
sub-relay fees that other peers will reject.

**Impact:**
- wallet fee selection driven off nimrod RPC under-fees by 1000×.
- W141/W144/W150 carry-forward: the bug is now ~5 weeks old without
  closure despite 3 follow-up audits, suggesting a systemic
  blind-spot in priority queue execution.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-DEAD:** 1 (BUG-1)
- **P0-CDIV:** 8 (BUG-3, BUG-4, BUG-5, BUG-6, BUG-8, BUG-10, BUG-15, BUG-22)
- **P0-SEC:** 3 (BUG-11, BUG-13, BUG-14)
- **P1:** 10 (BUG-2, BUG-7, BUG-9, BUG-12, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21)

**P0-class total:** 12 (1 P0-DEAD + 8 P0-CDIV + 3 P0-SEC).

**Fleet patterns confirmed:**
- **"dead-data plumbing"** — 715-LOC RelayManager subsystem with full
  test suite, ZERO production callers (BUG-1). Also `setIBD`/
  `setMempoolMinFeeRate` zero callers (BUG-2). Also `removeForPeer`/
  `expireOld` on OrphanPool (BUG-21). Three distinct instances in
  this audit alone — most severe nimrod instance to date.
- **"plumb-gate-then-don't-flip"** — 7th distinct nimrod instance
  (BUG-2 + BUG-21).
- **"W141 carry-forward, 3 audits open"** — mempoolminfee 1000×
  divisor (BUG-22). First confirmed multi-audit carry-forward in
  this audit, mirroring the W123 blockbrew Subsidy carry-forward.
- **"comment-as-confession"** — BUG-7 stale "Mirrors Core
  DEFAULT_MAX_ORPHAN_TRANSACTIONS" comment for a constant that no
  longer exists in Core (8th distinct nimrod instance).
- **"stale-Core-anchor"** — BUG-7 is also first explicit
  stale-anchor instance (legacy DEFAULT_MAX_ORPHAN_TRANSACTIONS).
- **"missing misbehavior signal at parser boundary"** — BUG-13
  raise-then-disconnect-then-no-score; new fleet pattern.
- **"missing privacy-fence enforcement"** — BUG-11 + BUG-19 (block-
  relay-only conns accept and announce tx; new fleet pattern named
  "privacy-fence-violated").
- **"BIP-339 dispatch asymmetric: inv vs getdata"** — BUG-6
  accepts invWtx but doesn't serve getdata MSG_WTX. First
  asymmetric-BIP-339-pipeline instance.
- **"AlreadyHave check incomplete: 2 of 4 layers"** — BUG-15 +
  BUG-16; orphan + recent-confirmed bypass.
- **"post-verack flag-flip without disconnect"** — BUG-14
  wtxidrelay/sendaddrv2 mid-conversation state mutation.

**Top three findings:**
1. **BUG-1 (P0-DEAD) — Entire RelayManager subsystem is dead code.**
   715 LOC, 18 public procs, 2 test files, ZERO production callers.
   Production uses a one-shot `peerManager.broadcastTx(tx)` that
   sends to every peer immediately with no excludePeer, no trickle,
   no feefilter, no known-tx filter, no Poisson schedule. The entire
   BIP-133/BIP-152/origin-privacy design exists on paper only.
2. **BUG-4 + BUG-5 (P0-CDIV) — No tx-request scheduler.** mkInv
   dispatches getdata to every announcer immediately, with no
   TXID_RELAY_DELAY, no NONPREF_PEER_TX_DELAY, no
   OVERLOADED_PEER_TX_DELAY, no MAX_PEER_TX_REQUEST_IN_FLIGHT cap,
   no GETDATA_TX_INTERVAL timeout/reschedule. N peers announcing
   the same inv → N parallel getdata + N copies of the tx. A peer
   that withholds the requested tx leaves us with no fallback;
   the request is fire-and-forget.
3. **BUG-22 (P0-CDIV / W141 carry-forward, 5+ weeks open) —
   `mempoolminfee` divisor 1000× too large.** Single-character edit
   (`/ 100000000.0` → `/ 100000.0`). Open across 3 prior audits
   (W141, W144, W150). Wallets driven off nimrod's RPC under-fee by
   three decimal orders of magnitude. Confirms the priority-queue
   execution gap reported in auto-memory.

**Cross-cite:** BUG-1 + BUG-3 + BUG-4 + BUG-5 + BUG-10 are
architecturally one bug: nimrod has no tx-relay subsystem in
production. The 22 bugs above are the symptom-by-symptom mapping;
the systemic fix is to (a) wire RelayManager into the node
entrypoint, (b) replace `peermanager.broadcastTx` with `RelayManager.
queueTxInv`, (c) implement a TxRequestTracker for mkInv → getdata
scheduling, (d) plumb known-tx filter into peer state.
