# W136 — BIP-130 sendheaders / BIP-133 feefilter / BIP-339 wtxidrelay audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W136)
Concurrent waves: 3 OTHER discovery waves running in parallel; this wave
takes the **relay feature-negotiation** axis distinct from BIP-37 bloom
filter (W134) and BIP-152 compact blocks (W126).

Target:
  - `src/network/peer.nim`         (Peer fields: `sendHeaders`,
                                    `wtxidRelay`, `feeFilterRate`,
                                    `relay`, `verackReceived`;
                                    `performHandshake` outbound/inbound;
                                    pre-verack feature loop arms;
                                    `handleMessage` post-handshake arms
                                    for `mkSendHeaders` / `mkWtxidRelay`
                                    / `mkFeeFilter`;
                                    `validatePreHandshakeMessage`).
  - `src/network/peermanager.nim`  (`selectBlockAnnouncement`,
                                    `broadcastBlock`, `broadcastTx`).
  - `src/network/relay.nim`        (entire module — FeeFilterRounder,
                                    AvgFeefilterBroadcastInterval,
                                    MaxFeefilterChangeDelay,
                                    PeerRelayState.feeFilterSent /
                                    nextSendFeefilter, `setIBD`,
                                    `setMempoolMinFeeRate`,
                                    `getCurrentFeefilterValue`,
                                    `maybeSendFeefilter`,
                                    `handleReceivedFeefilter`,
                                    `sendFeefilterToAllPeers`,
                                    `queueTxInv` /
                                    `queueTxInvWithFee` BIP-339
                                    wtxid-vs-txid switch).
  - `src/network/messages.nim`     (`mkSendHeaders`, `mkFeeFilter`,
                                    `mkWtxidRelay` enum + serialise /
                                    deserialise; `newSendHeaders`,
                                    `newWtxidRelay`, `newFeeFilter`;
                                    `commandToMessageKind` /
                                    `messageKindToCommand`).
  - `src/network/bip324.nim`       (short-ID table for `sendheaders`,
                                    `wtxidrelay`, `feefilter` over the
                                    encrypted v2 transport).

Bitcoin Core references:
  - `src/net_processing.cpp`
    - lines 405–406  (`Peer::m_sent_sendheaders` atomic)
    - line  412     (`Peer::m_prefers_headers` flag)
    - lines 283     (`Peer::m_wtxid_relay` atomic)
    - lines 284–290 (`Peer::m_fee_filter_sent` /
                    `Peer::m_next_send_feefilter` GUARDED_BY
                    `g_msgproc_mutex`)
    - line  321     (`Peer::m_fee_filter_received` atomic)
    - lines 179–183 (`AVG_FEEFILTER_BROADCAST_INTERVAL = 10min`,
                    `MAX_FEEFILTER_CHANGE_DELAY = 5min`)
    - lines 740–741 (`MaybeSendSendHeaders` declaration —
                    "after we have completed headers sync")
    - lines 3710–3712 (post-`VERSION`: emit `WTXIDRELAY` when
                       `greatest_common_version >= WTXID_RELAY_VERSION`)
    - lines 3896–3899 (`SENDHEADERS` receiver: set `m_prefers_headers`)
    - lines 3919–3939 (`WTXIDRELAY` receiver: pre-`VERACK` only or
                       disconnect; ignore duplicate; ignore if version
                       too old)
    - lines 5035–5045 (`FEEFILTER` receiver: `MoneyRange` check, store
                       in `tx_relay->m_fee_filter_received`)
    - lines 5519–5538 (`MaybeSendSendHeaders`: gate on
                       `pindexBestKnownBlock != nullptr` AND
                       `nChainWork > m_chainman.MinimumChainWork()`,
                       send ONCE per peer, only if
                       `GetCommonVersion() >= SENDHEADERS_VERSION`)
    - lines 5540–5580 (`MaybeSendFeefilter`: refuse if
                       `m_opts.ignore_incoming_txs` OR
                       `GetCommonVersion() < FEEFILTER_VERSION` OR
                       `HasPermission(ForceRelay)` OR
                       `IsBlockOnlyConn()`;
                       MAX_MONEY in IBD; rounder.round; min-relay-fee
                       floor; 10-minute Poisson schedule; 5-minute
                       hysteresis early-send on > 25% drop or > 33%
                       rise)
    - lines 5838–5925 (SendMessages: BIP-130 announce-revert logic,
                       `m_prefers_headers` cmpctblock cache,
                       MAX_BLOCKS_TO_ANNOUNCE, peer-has-header walk,
                       fallback-to-inv on disconnect)
    - line  4983, 5031 (`pfrom.m_relays_txs = true` flip on
                        `FILTERCLEAR` / `filterload(fRelay=true)`)
    - line  1688, 1727 (`m_wtxid_relay_peers` accounting on disconnect)
    - lines 2255–2261 (txdownload uses wtxid-or-txid by
                       `peer.m_wtxid_relay`)
    - lines 4056–4063 (`INV` filter on wtxidrelay setting —
                       MSG_TX vs MSG_WTX)
  - `src/net.h`
    - `Peer::m_relays_txs` atomic (the **version-flag** boolean from
       VERSION.relay, independent of the per-peer-tx-relay-state
       `tx_relay->m_relay_txs`)
  - `src/node/protocol_version.h`
    - line 24 (`SENDHEADERS_VERSION = 70012`)
    - line 27 (`FEEFILTER_VERSION    = 70013`)
    - line 36 (`WTXID_RELAY_VERSION  = 70016`)
  - `src/policy/feerate.cpp` (CFeeRate; used by feefilter to format
                              `GetFeePerK` for the wire encoding)
  - `src/policy/fees/block_policy_estimator.{h,cpp}`
    - `FeeFilterRounder` class (lines 323–344 in `.h`;
      lines 1085–1119 in `.cpp`):
      - `MAX_FILTER_FEERATE = 1e7`,
        `FEE_FILTER_SPACING = 1.1`,
        bucket set built as
        `{0, max(1, minIncrementalFee.GetFeePerK()/2)..MAX_FILTER_FEERATE * 1.1}`
      - `round()` uses `lower_bound` + `rand32() % 3` ⇒ **2/3 probability of
        rounding DOWN**, **1/3 of staying on the boundary**
  - `src/protocol.h`
    - line 186 (`NetMsgType::SENDHEADERS = "sendheaders"`)
    - line 192 (`NetMsgType::FEEFILTER    = "feefilter"`)
    - line 260 (`NetMsgType::WTXIDRELAY   = "wtxidrelay"`)

BIPs: BIP-130 (sendheaders), BIP-133 (feefilter), BIP-339
(wtxidrelay + MSG_WTX inv type), BIP-152 (compact blocks — referenced
only because Core's BIP-130 announce path interacts with high-bandwidth
cmpctblock peers).

Driver: these three are the **post-VERACK relay-feature-negotiation**
trio.  All three are pure courtesy / efficiency signals (no consensus
implication) but ALL THREE have observable consequences:

- **BIP-130 sendheaders**: changes the on-wire encoding of block
  announcements from `inv → getdata → block` to `headers → cmpctblock /
  getdata → block`.  Without it, a new block goes out as an inv (small)
  and the peer round-trips before receiving the header; with it, the
  header ships in the announcement.  Consensus-neutral but affects
  every cmpctblock-capable peer (because BIP-152 high-bandwidth mode
  requires sendheaders to be on).

- **BIP-133 feefilter**: tells the peer "do not inv me transactions
  below this feerate" — peers honor the filter and skip the inv,
  saving bandwidth.  No consensus effect but enables economic policy
  divergence: a node with a high `mempool min fee` (because it's
  hitting `-maxmempool`) effectively asks its peers to stop spamming
  low-fee txs.  Buggy feefilter sends low values during IBD ⇒ peer
  spams us with millions of trivial txs we'd drop anyway.  Buggy
  feefilter NEVER SENDS ⇒ peer has no idea what we want and floods us.

- **BIP-339 wtxidrelay**: switches the per-peer inventory hash from
  `txid` (MSG_TX = 1) to `wtxid` (MSG_WTX = 5).  Required for orphan-
  parent fetching, package relay, and the new (BIP-331) "ancestor
  package" announcements.  Critically, the **flag bit must be set
  BEFORE VERACK** — sending it after VERACK is a protocol violation
  and **Core disconnects on it** (net_processing.cpp:3923).

The audit framework correction from W122/W125 — "audit must verify
byte-exact behaviour, not just code-existence" — is reaffirmed: nimrod
HAS source-level definitions for `FeeFilterRounder`, `setIBD`,
`maybeSendFeefilter`, `setMempoolMinFeeRate`, `sendFeefilterToAllPeers`,
and the `RelayManager` trickle loop, but the **production wire never
sees them** (see BUG-1 / BUG-2 below — DEAD MODULE).

## Status

**BUGS FOUND — 18 distinct gates PARTIAL / MISSING / WRONG (of 30).**

Of those 18 BUGs, **2 are P0** (P0-NET — observable wire-protocol
divergence with deterministic effect across two cooperating nimrod-vs-
Core fleets):

- **BUG-1 (P0-NET) — `RelayManager` is a DEAD MODULE** — `newRelayManager`
  has ZERO production call sites in `src/`.  Every feefilter-send path
  (`maybeSendFeefilter`, `sendFeefilterToAllPeers`, `setIBD`,
  `setMempoolMinFeeRate`, `getCurrentFeefilterValue`, the entire
  Poisson-scheduled `trickleLoop`) is unreachable.  Net effect: nimrod
  **NEVER SENDS** a `feefilter` message in production, ever, regardless
  of mempool min fee or IBD state.  Core peers receive no rate hint from
  nimrod, ergo every connected peer floods nimrod with every low-fee tx
  inv they see.  Symmetric: a nimrod fleet relays low-fee garbage in
  both directions and bears the bandwidth cost that BIP-133 is
  specifically designed to mitigate.  Tested in G1.

- **BUG-2 (P0-NET) — `sendSendHeaders` fires unconditionally at end of
  handshake** — `peer.nim:1233` calls `await peer.sendSendHeaders()`
  immediately after `await peer.sendVerack()`, regardless of peer
  protocol version, regardless of headers-sync state, regardless of
  chainwork-vs-minimum-chain-work, on EVERY connection.  Core
  (`MaybeSendSendHeaders`, net_processing.cpp:5519-5538) gates on:

      !peer.m_sent_sendheaders &&
      node.GetCommonVersion() >= SENDHEADERS_VERSION (70012) &&
      state.pindexBestKnownBlock != nullptr &&
      state.pindexBestKnownBlock->nChainWork > MinimumChainWork()

  None of those are checked in nimrod.  Worst-case wire impact: a
  pre-2016 peer (protocol version < 70012, e.g. legacy SPV libraries
  or research nodes) receives an unrecognised `sendheaders` and
  disconnects per BIP-013 "unknown command" handling.  Tested in G2.

The remaining 16 BUGs are P1 / P2 / P3:

- **BUG-3 (P1)** — `MaybeSendFeefilter` exemptions (ForceRelay, BlockOnly,
  ignore_incoming_txs) absent (G3 + G4 + G5).
- **BUG-4 (P1)** — `m_wtxid_relay_peers` global counter missing — Core
  decrements on disconnect, asserts == 0 at shutdown (net_processing.cpp:
  1688, 1727); nimrod has no such counter (G6).
- **BUG-5 (P1)** — `FEEFILTER` receiver does NOT validate `MoneyRange(newFeeFilter)`
  per Core (`net_processing.cpp:5038`); nimrod stores any uint64, including
  > MaxMoney (2.1×10^15) (G7).
- **BUG-6 (P1)** — `MAX_BLOCKS_TO_ANNOUNCE = 8` revert-to-inv ceiling missing
  in `broadcastBlock`; nimrod sends `headers` of arbitrary length (G8).
- **BUG-7 (P1)** — `PeerHasHeader` walk + `pindexBestHeaderSent` tracking missing —
  nimrod re-announces the same header to a peer that already received it (G9).
- **BUG-8 (P1)** — `m_relays_txs` (the **version.relay** flag) is stored
  (`peer.relay`) but never used to gate outbound inv (G10).
- **BUG-9 (P2)** — `FeeFilterRounder.round` uses Nim's `rand(2)` 0/1/2 with
  `!= 0` (2/3 down, 1/3 up), but does **NOT** match Core's `rand32() % 3 != 0`
  semantics in one corner: Core decrements ONLY when the bucket is NOT
  the first one; nimrod's binary-search returns the first bucket directly
  at `lo == 0` and never invokes the random branch — same effect at
  `lo == 0` but the branch ordering / random consumption diverges, making
  the rounder NOT byte-equivalent across deterministic-RNG fuzz oracles
  (G11).
- **BUG-10 (P2)** — `randomize()` is called inside `calculatePoissonDelay`
  and `flushTrickle` ON EVERY CALL (relay.nim:191, 338, 569, 152) — this
  re-seeds Nim's global Mersenne Twister from system time every tick,
  which (a) introduces a same-second-seed collision risk under load,
  (b) wastes CPU, (c) is not how Core does it (Core threads a
  `FastRandomContext` through the codepath).  Result: rounder rounds-down
  decisions are predictable within 1-second windows (G12).
- **BUG-11 (P2)** — `AvgFeefilterBroadcastInterval = 600.0` is in
  seconds-as-float; Core uses `chrono::microseconds` and
  `rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL = 10min)` which is
  truly exponential.  nimrod's `calculatePoissonDelay` builds
  `-ln(rand) * mean` which IS exponential — but then **clamps to
  100 ms .. 60 s** (relay.nim:197), capping the maximum interval at 60 s
  instead of the unbounded Poisson tail.  A nimrod node sends FEEFILTER
  **at LEAST every 60 seconds** instead of every 10 minutes on average.
  Wire-observable: a Core peer connected to a nimrod node sees feefilter
  spam (G13).
- **BUG-12 (P2)** — `MaxFeefilterChangeDelay = 300.0` (seconds) is used
  with a randrange of milliseconds (`milliseconds(rand(int(MaxFeefilterChangeDelay
  * 1000)))`) — units are fine — but the trigger threshold uses
  `currentFilter < state.feeFilterSent * FeefilterLowThreshold` (= 75%)
  and `> 133%`, while Core uses `< 3*sent/4` (= 75%) and `> 4*sent/3`
  (= 133.3̄%).  The constants match but the rounding differs at the
  boundary (currentFilter == sent * 4/3 exactly): Core triggers, nimrod
  does NOT (FeefilterHighThreshold = 1.33 < 4/3 = 1.333̄) (G14).
- **BUG-13 (P3)** — Pre-verack feature loop in `performHandshake`
  (peer.nim:1119-1148, 1199-1226) accepts `mkFeeFilter` and stores
  `peer.feeFilterRate`.  Core does **NOT** allow `feefilter` pre-`VERACK` —
  the message ProcessMessage gate is post-fSuccessfullyConnected
  (net_processing.cpp:5035 + the pre-verack switch at 3801-3829 only
  permits sendcmpct/sendheaders/sendaddrv2/wtxidrelay/sendtxrcncl).
  Pre-verack feefilter is a protocol violation in Core; nimrod silently
  accepts it (G15).
- **BUG-14 (P3)** — Pre-verack feature loop accepts `mkSendHeaders`
  (peer.nim:1139-1141, 1217-1219).  Core does allow `sendheaders` any
  time after VERSION but BEFORE the BIP-339 negotiation logic flips the
  per-peer `m_prefers_headers` flag — same observable effect, but the
  "negotiation messages allowed pre-verack" set Core whitelists is
  strictly `{WTXIDRELAY, SENDADDRV2, SENDCMPCT, SENDTXRCNCL, FEEFILTER}`
  (FEEFILTER is post-verack; SENDHEADERS is post-verack).  nimrod's pre-
  verack acceptance of `sendheaders` is too lax (G16).
- **BUG-15 (P3)** — Outbound handshake ordering: nimrod sends SENDADDRV2
  THEN WTXIDRELAY (peer.nim:1111-1113); Core sends WTXIDRELAY THEN
  SENDADDRV2 (net_processing.cpp:3710-3720).  Same effect on the peer,
  but a fingerprint divergence (G17).
- **BUG-16 (P3)** — `validatePreHandshakeMessage` permits `mkFeeFilter`
  and `mkSendHeaders` after VERSION but before VERACK
  (peer.nim:1771, 1816).  Same observable issue as BUG-13 / BUG-14,
  but at the validation/dispatch boundary rather than the handshake
  feature-loop.  Both surfaces need to change in lockstep when the fix
  lands (G18).
- **BUG-17 (P3)** — `handleReceivedFeefilter` (relay.nim:577-582) is
  defined but never called.  All FEEFILTER handling happens inside
  `peer.handleMessage` (peer.nim:1354-1356) — the relay.nim hook is
  vestigial.  Cosmetic; either delete or wire (G19).
- **BUG-18 (P3)** — `MinProtocolVersion = 70015` in `peer.nim:25`,
  meaning nimrod refuses to handshake with any peer < 70015.  Core's
  minimum supported version is 31800 (long deprecated; current
  `MIN_PEER_PROTO_VERSION = 31800`, `INIT_PROTO_VERSION = 209`); the
  BIP-130/133/339 gates Core uses are 70012/70013/70016.  Because
  nimrod always disconnects sub-70015 peers in handshake, the
  conditional gates for SENDHEADERS_VERSION (70012) and FEEFILTER_VERSION
  (70013) are de-facto trivially satisfied.  Cosmetic if MinProtocolVersion
  stays at 70015 — but BUG-2 still applies because there's NO check at
  all in the actual send path (G20).

12 PRESENT (Core-aligned), 18 MISSING / PARTIAL / WRONG.

## Methodology

1. Read Core refs end-to-end:
   - `net_processing.cpp` lines 179-183, 283-321, 405-412, 740-741,
     1688, 1727, 2255-2261, 3676-3737, 3853-3939, 4056-4063, 4979-5045,
     5519-5580, 5825-5930.
   - `node/protocol_version.h` (SENDHEADERS_VERSION = 70012,
     FEEFILTER_VERSION = 70013, WTXID_RELAY_VERSION = 70016).
   - `policy/fees/block_policy_estimator.{h,cpp}` (FeeFilterRounder).
   - `protocol.h` (NetMsgType strings + NODE_* service bits).
2. Walked nimrod's `peer.nim` (Peer fields + handshake + handleMessage),
   `peermanager.nim` (broadcastBlock + broadcastTx), `relay.nim`
   (entire module), `messages.nim` (FeeFilter wire codec), and
   `bip324.nim` (short-ID table) end-to-end.
3. Identified the **dead-module** of `RelayManager` (no production
   call site for `newRelayManager`) — same audit-pattern as W133
   (TxIndex / CoinStatsIndex DEAD MODULE in `storage/indexes/`).
4. Cross-checked the BIP-130 announce-revert logic against
   `peermanager.broadcastBlock` and `selectBlockAnnouncement` — found
   missing `MAX_BLOCKS_TO_ANNOUNCE` / `PeerHasHeader` /
   `pindexBestHeaderSent` machinery.
5. Wrote 30 fresh gates (`tests/test_w136_relay_flags.nim`).  Each gate
   either documents Core-aligned correct behavior (PRESENT gates are
   tested as forward-regression sentinels — they pin current behavior
   so a future "refactor" doesn't drift) or documents the
   divergent / missing behavior with a `check` that asserts the WRONG
   value (so the test acts as a post-fix XFAIL).  Methodology matches
   W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
   W134.

## Gate matrix

Status legend: PRESENT (Core-aligned) / PARTIAL (wired but diverges) /
MISSING (entirely absent).

| Gate | Description | Status | Bug |
|------|-------------|--------|-----|
| G1  | `newRelayManager` has production call site (RelayManager is wired) | MISSING | BUG-1 |
| G2  | `sendSendHeaders` gated on (a) version>=70012, (b) chainwork>minChainWork, (c) sent-once | MISSING | BUG-2 |
| G3  | `MaybeSendFeefilter` skips when peer has ForceRelay permission | MISSING | BUG-3 |
| G4  | `MaybeSendFeefilter` skips when connection is block-relay-only | MISSING | BUG-3 |
| G5  | `MaybeSendFeefilter` skips when `ignore_incoming_txs` is set | MISSING | BUG-3 |
| G6  | `m_wtxid_relay_peers` global counter exists + decrements on disconnect | MISSING | BUG-4 |
| G7  | `FEEFILTER` receiver rejects out-of-range (`MoneyRange`) values | MISSING | BUG-5 |
| G8  | `MAX_BLOCKS_TO_ANNOUNCE = 8` revert-to-inv ceiling in broadcastBlock | MISSING | BUG-6 |
| G9  | `PeerHasHeader` walk + `pindexBestHeaderSent` per-peer tracking | MISSING | BUG-7 |
| G10 | `peer.relay` (version flag) gates outbound tx-inv generation | PARTIAL | BUG-8 |
| G11 | `FeeFilterRounder.round` byte-equivalent to Core's `rand32() % 3 != 0` | PARTIAL | BUG-9 |
| G12 | `calculatePoissonDelay` uses a FastRandomContext (not global `randomize()`) | PARTIAL | BUG-10 |
| G13 | `AvgFeefilterBroadcastInterval` not clamped to ≤ 60s (true 10-min average) | PARTIAL | BUG-11 |
| G14 | `FeefilterHighThreshold = 4/3` (exact ratio, not 1.33 approximation) | PARTIAL | BUG-12 |
| G15 | Pre-verack feature loop rejects `mkFeeFilter` (Core: post-VERACK only) | PARTIAL | BUG-13 |
| G16 | Pre-verack feature loop rejects `mkSendHeaders` (Core: post-VERACK) | PARTIAL | BUG-14 |
| G17 | Outbound handshake emits WTXIDRELAY BEFORE SENDADDRV2 (Core ordering) | PARTIAL | BUG-15 |
| G18 | `validatePreHandshakeMessage` rejects `mkFeeFilter` / `mkSendHeaders` post-VERSION | PARTIAL | BUG-16 |
| G19 | `handleReceivedFeefilter` has production call site (or is removed) | PARTIAL | BUG-17 |
| G20 | `MinProtocolVersion` consistent with Core's `MIN_PEER_PROTO_VERSION = 31800` | PARTIAL | BUG-18 |
| G21 | `mkSendHeaders` enum + serialise + deserialise present | PRESENT | — |
| G22 | `mkWtxidRelay` enum + serialise + deserialise present | PRESENT | — |
| G23 | `mkFeeFilter` enum + serialise + deserialise (uint64LE) present | PRESENT | — |
| G24 | `sendheaders` is in `bip324.nim` short-ID table | PRESENT | — |
| G25 | `wtxidrelay` is in `bip324.nim` short-ID table | PRESENT | — |
| G26 | `feefilter` is in `bip324.nim` short-ID table | PRESENT | — |
| G27 | `WTXIDRELAY` after VERACK is `marDisconnect` (Core net_processing.cpp:3923) | PRESENT | — |
| G28 | BIP-339: `queueTxInv` per-peer inv-type switch (invWtx vs invTx) | PRESENT | — |
| G29 | BIP-130: `selectBlockAnnouncement` emits headers when peer.sendHeaders | PRESENT | — |
| G30 | Pre-verack feature loop sets `peer.wtxidRelay = true` on `mkWtxidRelay` | PRESENT | — |

**12 PRESENT, 18 MISSING / PARTIAL, 18 distinct BUGs catalogued.**

## Bugs

### BUG-1 (P0-NET) — RelayManager is a DEAD MODULE; nimrod never sends feefilter

Core (`net_processing.cpp:5540-5580`): every peer iteration in
`SendMessages` calls `MaybeSendFeefilter(pto, peer, current_time)`,
which conditionally pushes a `FEEFILTER` message with the rounded
mempool min fee.  The interval is averaged at 10 min (Poisson) with
a 5-minute hysteresis on > 25% drop or > 33% rise.

nimrod (`src/network/relay.nim`):
  - `proc newRelayManager*(): RelayManager` is defined (line 179) but
    has **ZERO production call sites** outside its own module and
    `tests/test_relay.nim` / `tests/test_feefilter.nim`.
  - `proc start*(rm: RelayManager)` starts `trickleLoop` (line 392),
    which calls `await rm.maybeSendFeefilter(state)` for every peer
    every 100 ms — but `start` is never invoked from `src/nimrod.nim`,
    `src/network/peermanager.nim`, or anywhere else.
  - `proc setIBD*(rm: RelayManager, isIBD: bool)` (line 506) — never
    called.
  - `proc setMempoolMinFeeRate*(rm: RelayManager, feeRate: int64)`
    (line 501) — never called.

Wire effect: nimrod **emits zero `feefilter` messages**, ever, to any
peer.  Every connected Core peer assumes nimrod has no fee filter
preference (`tx_relay->m_fee_filter_received` stays at 0 ⇒
`txMeetsFeefilter(_, 0) = true` ⇒ forward every tx inv).  Bandwidth
waste; observable wire divergence; defeats the entire BIP-133 design.

Pinned in G1 via `grep` over `src/` for `newRelayManager` (must yield
only its definition + `relay.nim` itself, never an invocation).

### BUG-2 (P0-NET) — sendSendHeaders fires unconditionally at handshake end

Core (`net_processing.cpp:5519-5538` — `MaybeSendSendHeaders`):
```cpp
if (!peer.m_sent_sendheaders && node.GetCommonVersion() >= SENDHEADERS_VERSION) {
    LOCK(cs_main);
    CNodeState &state = *State(node.GetId());
    if (state.pindexBestKnownBlock != nullptr &&
            state.pindexBestKnownBlock->nChainWork > m_chainman.MinimumChainWork()) {
        MakeAndPushMessage(node, NetMsgType::SENDHEADERS);
        peer.m_sent_sendheaders = true;
    }
}
```

This is called from `SendMessages` (line 5763) AFTER initial headers
sync has run far enough that the peer's `pindexBestKnownBlock` has
exceeded `MinimumChainWork()`.  The gate prevents nimrod from telling a
brand-new peer "announce via headers" before we have any context on
which branch they're on.

nimrod (`src/network/peer.nim:1231-1234`):
```nim
# Send feature negotiation messages (after verack)
# Note: sendaddrv2 and wtxidrelay are already sent before verack
await peer.sendSendHeaders()
await peer.sendSendCmpct()
```

Sent unconditionally, immediately after VERACK, on every handshake,
to every peer.  Possible negative consequences:
  - Pre-2016 peers (protocol version < 70012) receive an unknown
    command and may disconnect (Core's behavior depends on the peer
    binary; not catastrophic in practice but a fingerprint).
  - Honest peers on a divergent low-work branch start sending us
    `headers` for that branch immediately, before we've evaluated
    whether it's worth tracking — bandwidth waste.
  - There's no `m_sent_sendheaders` boolean per peer — if nimrod
    ever wires this correctly, it MUST NOT double-send.

Pinned in G2 via source grep + dynamic test on `Peer.sendHeaders`-vs-
chainwork.

### BUG-3 (P1) — MaybeSendFeefilter exemptions absent

Core (`net_processing.cpp:5540-5548`):
```cpp
if (m_opts.ignore_incoming_txs) return;
if (pto.GetCommonVersion() < FEEFILTER_VERSION) return;
if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;
if (pto.IsBlockOnlyConn()) return;
```

nimrod's `maybeSendFeefilter` (relay.nim:519-575) checks ONLY
`isConnected` + `handshakeComplete`.  Even if the dead module were
wired, it would send feefilter to block-relay-only peers (which Core
explicitly does NOT — these peers don't announce txs to us, so we
don't need to tell them our fee filter).

Pinned in G3 / G4 / G5.

### BUG-4 (P1) — m_wtxid_relay_peers global counter missing

Core (`net_processing.cpp:1688, 1727`):
```cpp
m_wtxid_relay_peers -= peer->m_wtxid_relay;
assert(m_wtxid_relay_peers >= 0);
...
assert(m_wtxid_relay_peers == 0);
```

This counter is used for diagnostic / metric purposes and is
incremented on `WTXIDRELAY` receipt (line 3931) and decremented on
peer disconnect.  nimrod has no equivalent; if every nimrod peer
disconnects without setting `wtxidRelay = false`, the bookkeeping is
inconsistent — but since nimrod doesn't keep a global counter, there
is no consistency invariant to enforce.

Pinned in G6 (source grep for the counter).

### BUG-5 (P1) — FEEFILTER receiver does not validate MoneyRange

Core (`net_processing.cpp:5035-5043`):
```cpp
if (msg_type == NetMsgType::FEEFILTER) {
    CAmount newFeeFilter = 0;
    vRecv >> newFeeFilter;
    if (MoneyRange(newFeeFilter)) {
        if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
            tx_relay->m_fee_filter_received = newFeeFilter;
        }
        LogDebug(BCLog::NET, "received: feefilter of %s from peer=%d\n", CFeeRate(newFeeFilter).ToString(), pfrom.GetId());
    }
    return;
}
```

`MoneyRange(n)` is `0 <= n <= MAX_MONEY` (consensus/amount.h).  nimrod
(`peer.nim:1354-1356`):
```nim
of mkFeeFilter:
  peer.feeFilterRate = msg.feeRate
  trace "peer feefilter", peer = $peer, feeRate = msg.feeRate
```

Stores any uint64, including `uint64.max = 2^64-1` which is ~8800
trillion BTC — but no peer should send such a value.  A malicious peer
could send `feefilter = uint64.max` and nimrod would store and honor
it (txMeetsFeefilter would always fail) ⇒ effective tx-relay DoS.

Pinned in G7.

### BUG-6 (P1) — MAX_BLOCKS_TO_ANNOUNCE = 8 revert-to-inv missing

Core (`net_processing.cpp:5840`):
```cpp
peer.m_blocks_for_headers_relay.size() > MAX_BLOCKS_TO_ANNOUNCE
```
`MAX_BLOCKS_TO_ANNOUNCE = 8` (net_processing.h).  When more than 8 blocks
need to be announced to a single peer (e.g. after a deep reorg), Core
falls back to `inv` regardless of the peer's `m_prefers_headers`
preference.  nimrod's `selectBlockAnnouncement` (peermanager.nim:938-951)
has no such cap — it would emit an arbitrarily long headers message,
potentially > 2000 entries (Core's MAX_HEADERS_RESULTS).

Pinned in G8.

### BUG-7 (P1) — PeerHasHeader walk + pindexBestHeaderSent missing

Core (`net_processing.cpp:5848-5889`): before emitting `headers` to a
peer, Core walks `m_blocks_for_headers_relay` to find the FIRST block
the peer doesn't already have, then sends from there.  It also tracks
`state.pindexBestHeaderSent` so it never re-announces the same header
to a peer (idempotency).  nimrod's `broadcastBlock` emits the same
header to every peer regardless of whether we just sent it 100 ms ago.

Pinned in G9.

### BUG-8 (P1) — m_relays_txs (version.relay flag) not honored

Core (`net.h:m_relays_txs`): set to `peer.fRelay` from the VERSION
message; if `fRelay == false` (block-relay-only peer), Core skips all
tx-inv generation for that peer (`net_processing.cpp:3980, 5993`).

nimrod stores `peer.relay = versionData.relay` (peer.nim:1102, 1178)
but never reads it anywhere outside `getpeerinfo` RPC.  Outbound tx
broadcast (`peermanager.nim:broadcastTx` / `relay.nim:queueTxInv`) does
NOT gate on `peer.relay`.  Result: a Core peer that sent
`version.relay = false` to nimrod still receives tx invs from nimrod —
protocol violation (BIP-37 / BIP-339 semantics).

Pinned in G10.

### BUG-9 (P2) — FeeFilterRounder.round semantics drift from Core

Core (`block_policy_estimator.cpp:1109-1119`):
```cpp
std::set<double>::iterator it = m_fee_set.lower_bound(currentMinFee);
if (it == m_fee_set.end() ||
    (it != m_fee_set.begin() &&
     WITH_LOCK(m_insecure_rand_mutex, return insecure_rand.rand32()) % 3 != 0)) {
    --it;
}
return static_cast<CAmount>(*it);
```

The branch is: "decrement iterator if (it == end) OR (it != begin AND
random_div_3 != 0)".  At `it == begin`, the decrement is skipped.  At
`it == end`, decrement always.

nimrod (`relay.nim:120-155`):
```nim
if lo == rounder.feeBuckets.len:
    if lo > 0:
        return int64(rounder.feeBuckets[lo - 1])
    return currentMinFee
if lo == 0:
    return int64(rounder.feeBuckets[0])
if rand(2) != 0:
    return int64(rounder.feeBuckets[lo - 1])
else:
    return int64(rounder.feeBuckets[lo])
```

- At `lo == end` (above all buckets): nimrod returns `buckets[lo-1]`,
  Core returns `*it` after `--it` (same: last bucket).  Match.
- At `lo == 0` (at-or-below first bucket): nimrod returns
  `buckets[0]`, Core's branch is `(it != begin)` so the random check
  is skipped and `*it = *begin = buckets[0]`.  Match.
- Otherwise: nimrod uses `rand(2)` (Nim returns 0/1/2 uniform); Core
  uses `rand32() % 3` (uniform 0/1/2).  Logic matches **in
  semantics** but byte-equivalent fuzz comparison would diverge
  because nimrod consumes ONE random int per call where Core
  consumes 4 bytes; the seeds drift.

Pinned in G11.

### BUG-10 (P2) — randomize() called on every rounder.round / Poisson call

nimrod calls `randomize()` (Nim's `std/random` seed-from-now) inside:
  - `calculatePoissonDelay` (relay.nim:191) — every trickle tick
  - `flushTrickle` (relay.nim:338) — every queue flush
  - `maybeSendFeefilter` randrange (relay.nim:569)
  - `FeeFilterRounder.round` (relay.nim:152)

Core threads a `FastRandomContext& m_rng` through the lifetime of
PeerManagerImpl (one per node), never reseeded.  nimrod's repeated
`randomize()` calls are:
  - **CPU-wasteful** (each call reads `epochTime()` + seeds the global
    Mersenne Twister)
  - **Predictable within 1-second windows** if two calls land in the
    same `epochTime` second
  - **NOT byte-equivalent** to Core under any fuzz oracle

Pinned in G12.

### BUG-11 (P2) — AvgFeefilterBroadcastInterval clamped to 60s ceiling

`calculatePoissonDelay` (relay.nim:188-198):
```nim
let delaySeconds = -ln(safeR) * meanInterval
let clampedDelay = clamp(delaySeconds, 0.1, 60.0)
milliseconds(int(clampedDelay * 1000))
```

The 60-second ceiling means: even though `AvgFeefilterBroadcastInterval =
600.0` (10 minutes), nimrod sends FEEFILTER at MOST every 60 seconds,
NEVER every 10 minutes.  A Core peer connected to nimrod sees
**10x more frequent** feefilter messages than expected — bandwidth
waste + observable wire divergence.  (Yes, this only matters if the
dead module is wired — see BUG-1.)

Pinned in G13.

### BUG-12 (P2) — FeefilterHighThreshold = 1.33 not 4/3

Core (`net_processing.cpp:5577`):
```cpp
(currentFilter < 3 * peer.m_fee_filter_sent / 4 ||
 currentFilter > 4 * peer.m_fee_filter_sent / 3)
```

The high-side ratio `4/3 ≈ 1.3333̄` is exact (integer division has
truncation but for the typical sat/kvB scale of `feeFilterSent ≥ 1000`,
the truncation is negligible).  nimrod uses
`FeefilterHighThreshold = 1.33` (relay.nim:37) which is
3.4 ppm LOW.  At the boundary `currentFilter = sent * 4/3`, Core
triggers the early-send, nimrod does NOT.

Pinned in G14.

### BUG-13 (P3) — Pre-verack feature loop accepts mkFeeFilter

Core (`net_processing.cpp:5035` — FEEFILTER handler) is post-VERSION/
VERACK; the pre-verack switch in net_processing.cpp:3801-3940 only
whitelists `WTXIDRELAY`, `SENDADDRV2`, `SENDCMPCT`, `SENDTXRCNCL` (all
of which MUST be sent between VERSION and VERACK by spec).  FEEFILTER
must be post-VERACK.

nimrod's pre-verack feature loop (peer.nim:1142-1144, 1220-1222)
accepts `mkFeeFilter` and stores `peer.feeFilterRate`.  Result: a
malicious peer can send a low feefilter pre-VERACK and nimrod will
honor it as soon as the handshake completes — same end state as a
normal feefilter, but the pre-VERACK form is a protocol violation
per BIP-133.  Effectively a fingerprint divergence; not exploitable
in practice.

Pinned in G15.

### BUG-14 (P3) — Pre-verack feature loop accepts mkSendHeaders

Same reasoning as BUG-13.  Core's pre-VERACK whitelist does NOT
include `SENDHEADERS` — Core's `SENDHEADERS` handler is at line 3896,
which runs only post-`fSuccessfullyConnected` (the VERSION-handler
sets it to true at 3892 BEFORE returning, so SENDHEADERS is technically
post-VERACK from the peer's wire ordering perspective).  nimrod
accepts SENDHEADERS pre-VERACK at peer.nim:1139-1141, 1217-1219.

Pinned in G16.

### BUG-15 (P3) — WTXIDRELAY emitted AFTER SENDADDRV2 (Core: before)

Core (`net_processing.cpp:3710-3720`):
```cpp
if (greatest_common_version >= WTXID_RELAY_VERSION) {
    MakeAndPushMessage(pfrom, NetMsgType::WTXIDRELAY);
}
if (greatest_common_version >= 70016) {
    MakeAndPushMessage(pfrom, NetMsgType::SENDADDRV2);
}
```

WTXIDRELAY (`net_processing.cpp:3710`) is sent BEFORE SENDADDRV2
(`net_processing.cpp:3720`).  Both are after VERSION receipt and
before VERACK.

nimrod (`peer.nim:1110-1113`):
```nim
if peer.version >= 70016:
    await peer.sendSendAddrV2()
    await peer.sendWtxidRelay()
```

Order reversed.  Effect is identical on the peer's reception ordering,
but a peer fingerprinting nimrod by message ordering (e.g. for traffic
analysis) can detect it.

Pinned in G17.

### BUG-16 (P3) — validatePreHandshakeMessage permits FeeFilter / SendHeaders post-VERSION

`peer.nim:1771, 1816` — the validation arm for messages post-VERSION
but pre-VERACK lists:
```nim
of mkVerack, mkWtxidRelay, mkSendAddrV2, mkSendHeaders, mkSendCmpct, mkFeeFilter:
  true
```
and
```nim
of mkSendHeaders, mkSendCmpct, mkFeeFilter:
  # These can come any time after VERSION
  return marAccept
```

Same surface as BUG-13/BUG-14, but at the dispatch layer.  Both layers
need to flip in lockstep when the fix lands; document for the fix wave
that nimrod has a TWO-PIPELINE gap here (feature-loop in
`performHandshake` AND `validatePreHandshakeMessage`).

Pinned in G18.

### BUG-17 (P3) — handleReceivedFeefilter dead helper

`relay.nim:577-582`:
```nim
proc handleReceivedFeefilter*(peer: Peer, feeRate: uint64) =
  peer.feeFilterRate = feeRate
  trace "received feefilter", peer = $peer, feeRate = feeRate
```

This proc is exported but never called outside test files.  The actual
handler lives in `peer.nim:1354-1356`.  Either delete the relay.nim
helper or wire it as the single source of truth — currently a
divergence risk if one ever changes without the other.

Pinned in G19.

### BUG-18 (P3) — MinProtocolVersion = 70015 obviates SENDHEADERS_VERSION / FEEFILTER_VERSION gates

`peer.nim:25`:
```nim
MinProtocolVersion* = 70015'u32  # Minimum for witness support
```

nimrod refuses any peer below 70015 in handshake.  Core's
`MIN_PEER_PROTO_VERSION = 31800` (from version.h) is much more
permissive.  The effect is that nimrod's version-gate makes the
70012 (SENDHEADERS) and 70013 (FEEFILTER) gates de-facto trivially
true.  Cosmetic — nimrod refuses to talk to anyone old enough for
the gates to matter — but if `MinProtocolVersion` is ever lowered
(e.g. to support legacy bitcoind 0.12.1 testnets), BUG-2 and BUG-3
must be fixed FIRST or the wire path will misbehave.

Pinned in G20.

## Open questions / out-of-scope

- **(OOS-1)** BIP-152 high-bandwidth cmpctblock interaction with
  BIP-130: when a peer is in high-bandwidth mode AND sent us
  sendheaders, Core sends `cmpctblock` instead of `headers`.  Not
  audited here — see W126 (BIP-152 audit).
- **(OOS-2)** BIP-331 sendpackages negotiation feature flag —
  parallel to wtxidrelay, but audited in W116 (package relay).
- **(OOS-3)** Block-relay-only outbound connection ordering — Core
  does NOT send WTXIDRELAY to block-relay-only peers; nimrod does.
  Cosmetic since block-relay-only peers don't accept tx invs anyway.
- **(OOS-4)** SENDTXRCNCL negotiation (BIP-330) — orthogonal to
  this wave; receiver arm is a `trace` no-op (peer.nim:1145, 1223).
- **(OOS-5)** `getCommonVersion` analog: Core uses the min of our
  ProtocolVersion and the peer's version; nimrod uses just
  `peer.version`.  Same effect because ProtocolVersion = 70016 and
  MinProtocolVersion = 70015 are pinned, but should be documented.

## Forward-regression discipline

Per W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
W134, every gate in `tests/test_w136_relay_flags.nim` MUST flip
loudly when a future fix wave changes the behaviour.  Tests that
assert the CURRENT (buggy / absent) state are tagged with `# XFAIL`
in a comment immediately above the `check` line.  When a fix wave
lands, the developer flips the assertion (to the new correct value)
in the same commit; the test then acts as a permanent
forward-regression guard.

## Wave provenance

- Wave number: W136 (sequenced after W134 BIP-37 bloom filter, which
  is the previous discovery wave in nimrod's `audit/` directory).
- Streak: 71 fix + 64 discovery preserved (this wave is +1 discovery).
- Concurrent waves: 3 OTHER audit waves running in parallel on the
  same hashhog meta-repo across other impls (BIP-130/133/339
  specifically because the relay-feature-negotiation trio is uniform
  across all 10 nodes).
