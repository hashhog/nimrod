# W126 — BIP-152 Compact Block Relay audit (nimrod)

Date: 2026-05-17
Audit type: discovery (no production code changes)
Target: `src/network/compact_blocks.nim`, `src/network/peer.nim`,
        `src/network/peermanager.nim`, `src/nimrod.nim` (block-serve +
        cmpctblock dispatch).
Out of scope: BIP-324 v2 transport (W98), BIP-130 sendheaders (W117 /
        wave-specific), BIP-331 package-relay (W117 / sendpackages).

BIP: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
Core references read:
- `bitcoin-core/src/blockencodings.h` (PartiallyDownloadedBlock,
  CBlockHeaderAndShortTxIDs, BlockTransactions{Request})
- `bitcoin-core/src/blockencodings.cpp` (InitData, FillBlock,
  FillShortTxIDSelector, GetShortID)
- `bitcoin-core/src/net_processing.cpp` (SENDCMPCT/CMPCTBLOCK/
  GETBLOCKTXN/BLOCKTXN dispatch, MaybeSetPeerAsAnnouncingHeaderAndIDs,
  SendBlockTransactions, ProcessCompactBlockTxns)

## Status

**BUGS FOUND — 13 distinct gates MISSING / PARTIAL (of 30).**

This wave re-audits the same surface as W112 (the prior nimrod BIP-152
audit) with an independent fresh-read methodology, sets the gate count
to a comparable 30, and catalogues additional defects that W112 did
not flag.

Of W112's 10 catalogued BUGs:
- BUG-1 (depth constants absent) — RESOLVED in current `compact_blocks.nim`
  (lines 28-41 — `MaxCmpctBlockDepth = 5`, `MaxBlocktxnDepth = 10`)
- BUG-2 (sendcmpct version check) — RESOLVED (FIX-43; confirmed at
  `peer.nim:1344`)
- BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10 — still
  PRESENT (relabelled to W126 BUG numbers below).

W126 also flags **5 NEW defects** not in W112:
- BUG-N1: `blocktxnDepthOk` defined-but-never-called (dead helper)
- BUG-N2: getdata(invCmpctBlock) serve has no `peerCmpctVersion` /
  `wantsCompactBlocks` precondition — we will serve a cmpctblock to a
  peer that never sent us SENDCMPCT (violates BIP-152 §"Protocol")
- BUG-N3: `ScoreInvalidCompactBlock = 100` constant defined but
  `peer.misbehaving(...)` is **never called** on `rsInvalid` (only
  logs `warn`) — peer can repeatedly send malformed cmpctblocks
  without being disconnected
- BUG-N4: no `IsBlockMutated` / merkle-root check after FillBlock; a
  short-ID-collision-induced wrong-tx reconstruction would not be
  detected before being handed to validation (the helper comment at
  `compact_blocks.nim:564` acknowledges the gap but no caller enforces
  it)
- BUG-N5: no `m_bip152_highbandwidth_to` state tracked (BIP-152's "us
  selecting peer as our HB peer"); without this, the 3-peer HB cap is
  unenforceable and `mapBlocksInFlight` multimap semantics
  (`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`) cannot be implemented
  because nimrod's `inFlightBlocks: Table[BlockHash, InFlightBlock]`
  is single-valued

Net effect: nimrod is a **partial BIP-152 client** that can RECEIVE a
cmpctblock and try to reconstruct via mempool, but:
1. Cannot serve any meaningful response to GETBLOCKTXN (stub)
2. Never announces blocks via CMPCTBLOCK to anybody (HB peer list
   absent; broadcastBlock only emits HEADERS or INV)
3. Never disconnects peers that send malformed cmpctblocks
4. Has no extra-pool fallback (orphan / recently-confirmed) — every
   miss forces a getblocktxn round-trip

No consensus invariant is violated (a wrong cmpctblock reconstruction
would, in the worst case, fail merkle verification at a later stage —
but only because validation independently checks merkle root, not
because the cmpctblock path enforces it).  This is a **P2P
correctness / DoS / fleet-interop** audit, not a consensus audit.

## Method

1. Read Core: `blockencodings.h/cpp`, `net_processing.cpp` BIP-152
   message handlers + `MaybeSetPeerAsAnnouncingHeaderAndIDs` +
   `SendBlockTransactions` + `ProcessCompactBlockTxns`.
2. Read BIP-152 mediawiki §"Protocol".
3. Inventory nimrod surface:
   - `compact_blocks.nim` — encoding + reconstruction helpers (679 LOC)
   - `peer.nim:1339-1457` — message handlers
   - `peer.nim:640-645` — `sendSendCmpct`
   - `peer.nim:1234` — handshake invokes `sendSendCmpct()` (announce=false)
   - `nimrod.nim:971-1006` — getdata(invCmpctBlock) serve path
   - `peermanager.nim:938-970` — broadcastBlock / selectBlockAnnouncement
4. For each of 30 gates: PRESENT / PARTIAL / MISSING, with code refs.
5. Catalog PARTIAL + MISSING as BUGs with priority.

## Audit gates (30)

### Construction (G1-G7)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G1 | `SHORTTXIDS_LENGTH = 6` (BIP-152 §"Short transaction IDs") | `blockencodings.h:103` | PRESENT (`compact_blocks.nim:14` — `ShortIdLength* = 6`) |
| G2 | `GetShortID` masks SipHash-2-4 output to 48 bits (`& 0xffffffffffff`) | `blockencodings.cpp:49` | PRESENT (`compact_blocks.nim:131-141`, taking lower 6 bytes is equivalent mask) |
| G3 | `FillShortTxIDSelector` uses SINGLE SHA256 of `header‖nonce`, then first/second 8 bytes as `k0`/`k1` (NOT double-SHA256) | `blockencodings.cpp:35-44` | PRESENT (`compact_blocks.nim:107-129`; `sha256Single` confirmed via grep) |
| G4 | `CMPCTBLOCKS_VERSION = 2` constant | `net_processing.cpp:199` | PRESENT (`compact_blocks.nim:17` — `CompactBlockVersion* = 2`) |
| G5 | `MAX_CMPCTBLOCK_DEPTH = 5` constant | `net_processing.cpp:138` | PRESENT (`compact_blocks.nim:35` — `MaxCmpctBlockDepth = 5`) |
| G6 | `MAX_BLOCKTXN_DEPTH = 10` constant | `net_processing.cpp:140` | PRESENT (`compact_blocks.nim:41` — `MaxBlocktxnDepth = 10`) |
| G7 | `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` constant (multimap key for parallel HB-peer downloads of same block) | `net_processing.h:47` | MISSING — see BUG-N5. nimrod's `inFlightBlocks: Table[BlockHash, InFlightBlock]` is single-valued (`peermanager.nim:91`), so parallel compact-block download from 3 HB peers cannot be expressed. |

### SENDCMPCT negotiation (G8-G11)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G8 | Receiver: silently drop SENDCMPCT with `version != 2` (no state update) | `net_processing.cpp:3901-3917` | PRESENT (`peer.nim:1344-1350`; FIX-43; W112 confirmed) |
| G9 | Receiver: store peer's HB request as `m_bip152_highbandwidth_from` | `net_processing.cpp:3915` | PRESENT (`peer.nim:1349` — `peer.peerHighBandwidth = announce`) |
| G10 | Sender: send SENDCMPCT(0, 2) at handshake completion (signal cmpctblock support without HB-from-us) | `net_processing.cpp:3868-3870` | PRESENT (`peer.nim:1234` — unconditional `await peer.sendSendCmpct()` after VERACK; default `announce=false, version=2`) |
| G11 | Sender: separately send SENDCMPCT(1, 2) when promoting peer to HB via `MaybeSetPeerAsAnnouncingHeaderAndIDs` | `net_processing.cpp:1323` | MISSING — see BUG-3. `sendSendCmpct(announce=true)` is never called from any path. |

### CMPCTBLOCK receive (G12-G19)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G12 | Skip cmpctblock if `LoadingBlocks()` (importing/reindexing) | `net_processing.cpp:4469` | MISSING — `peer.nim:1366` mkCmpctBlock has no LoadingBlocks/IBD guard before InitData. |
| G13 | Lookup `prev_block`; if not found AND not IBD, send GETHEADERS instead of accepting cmpctblock | `net_processing.cpp:4483-4489` | MISSING — `peer.nim:1366-1417` performs no prev-block lookup before calling `initPartiallyDownloadedBlock`. |
| G14 | If `prev_block->nChainWork + GetBlockProof(header) < AntiDoSWorkThreshold`: drop (low-work) | `net_processing.cpp:4490-4494` | MISSING — no chain-work / anti-DoS check on the cmpctblock header. |
| G15 | Call `ProcessNewBlockHeaders({header})`, punish on invalid via `MaybePunishNodeForBlock(via_compact_block=true)` | `net_processing.cpp:4503-4508` | MISSING — `peer.nim:1366-1417` proceeds directly to `initPartiallyDownloadedBlock(cb)` without running the header through chain-state validation; an invalid PoW header would still be processed up to mempool fill and only fail at `reconstructBlock` (or never, if mempool reconstruction happens to succeed). |
| G16 | `PartiallyDownloadedBlock::InitData`: null-header / empty-input rejection, structural-gap check (`lastprefilledindex > shorttxids + i`), bucket-size > 12 → `READ_STATUS_FAILED`, short-ID collision → `READ_STATUS_FAILED` | `blockencodings.cpp:62-116` | PRESENT (`compact_blocks.nim:346-436`) — all four checks faithfully ported. |
| G17 | On `rsInvalid` from InitData: call `Misbehaving(peer, "invalid compact block")` AND `RemoveBlockRequest` | `net_processing.cpp:4592-4595` | MISSING — see BUG-N3. `peer.nim:1378-1379` only logs `warn "invalid compact block"`; no `peer.misbehaving(ScoreInvalidCompactBlock, ...)` call exists in the cmpctblock handler. `ScoreInvalidCompactBlock` is defined at `peer.nim:1635` but never invoked. |
| G18 | Fill from mempool via wtxid → short-id matching | `blockencodings.cpp:118-145` | PRESENT (`compact_blocks.nim:438-474`, `peer.nim:1384-1385`). |
| G19 | Fill from `vExtraTxnForCompact` (orphan / recently-confirmed pool) using same have_txn collision rules | `blockencodings.cpp:147-176` | MISSING — see BUG-6. `fillFromExtraPool` (`compact_blocks.nim:476-506`) is implemented but never invoked from `peer.nim`'s mkCmpctBlock handler (or anywhere else in `src/`). Dead helper at call site. |

### GETBLOCKTXN serve (G20-G23)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G20 | Receive getblocktxn → look up block by hash → if found: send BLOCKTXN with requested txs | `net_processing.cpp:4245-4264` | MISSING — see BUG-5. `peer.nim:1419-1436` mkGetBlockTxn is a stub: logs the request and falls through without ever sending a BLOCKTXN. TODO comment at line 1431-1436 acknowledges. |
| G21 | If `pindex->nHeight < tip - MAX_BLOCKTXN_DEPTH`: send full block instead of blocktxn | `net_processing.cpp:4276-4302` | MISSING — see BUG-N1. `blocktxnDepthOk` helper exists at `compact_blocks.nim:658` but is **never called** from any src/ file (verified via `grep -rn blocktxnDepthOk src/`). Dead helper at call site (same pattern as BUG-6). |
| G22 | Misbehaving on out-of-bounds index in BlockTransactionsRequest (`req.indexes[i] >= block.vtx.size()`) | `net_processing.cpp:2602-2605` (`SendBlockTransactions`) | MISSING — implied dead path because G20 is a stub; no caller exists to even validate the indexes. |
| G23 | `BlockTransactionsRequest` deserialization uses `DifferenceFormatter` so indexes are strictly increasing on the wire | `blockencodings.h:53` | PRESENT (`compact_blocks.nim:272-287` `readBlockTxnRequest`; absolute index increments are enforced via `prevIndex = absoluteIndex + 1`). |

### BLOCKTXN receive (G24-G26)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G24 | `FillBlock` re-fills missing slots from response and clears `header` to prevent re-call | `blockencodings.cpp:191-237` | PARTIAL — `fillMissingTransactions` (`compact_blocks.nim:527-544`) fills slots but `reconstructBlock` (line 546-570) does NOT clear `pdb.header` afterwards; a malicious peer could theoretically send the same BLOCKTXN twice and re-run reconstruction. (Mitigated in practice by `completeBlock` calling `state.pendingPartials.del(blockHash)` on success — line 620 — but `reconstructBlock` itself is callable from any context.) |
| G25 | After successful FillBlock, call `IsBlockMutated(block, segwit_active)` to catch short-ID-collision mis-reconstructions; if true → `READ_STATUS_FAILED` | `blockencodings.cpp:218-222` | MISSING — see BUG-N4. `reconstructBlock` (`compact_blocks.nim:546-570`) explicitly comments at line 564-568 that this check is **not** performed and "callers should verify merkle root and witness commitment after this returns rsOk" — but no caller in `peer.nim` (line 1389, 1446) does so. A short-ID collision that fills two wrong slots with txs that pass standalone checks could produce a block that fails only at later validation (deeper in connectBlock). |
| G26 | After successful reconstruction, call `ProcessNewBlock(force_processing=true, min_pow_checked=true)` and `RemoveBlockRequest` | `net_processing.cpp:3505-3513`, `4701-4708` | PARTIAL — `peer.nim:1389,1446` reconstruct the block and log success but do not appear to route the reconstructed block through any equivalent of `processNewBlock` (no callback to chainState submission; `state.successfulReconstructions += 1` is only a stat counter). Verified by grep: no call to a block-acceptance function exists inside mkCmpctBlock / mkBlockTxn handlers. (Comment at `compact_blocks.nim:564-568` reinforces — "callers should verify".) |

### HB-peer ANNOUNCE-side (G27-G29)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G27 | `MaybeSetPeerAsAnnouncingHeaderAndIDs(nodeid)` maintains `lNodesAnnouncingHeaderAndIDs` list with cap of 3, demotes oldest when full, swaps-to-protect last-outbound-HB | `net_processing.cpp:1272-1329` | MISSING — see BUG-3. No `lNodesAnnouncingHeaderAndIDs` analog anywhere in `src/network/`; grep for `nodesAnnouncing`, `hbPeers`, `highBandwidthPeers` all return zero matches. |
| G28 | When promoting peer to HB-from-us, send SENDCMPCT(1, 2) and set `m_bip152_highbandwidth_to = true`; when demoting send SENDCMPCT(0, 2) and clear flag | `net_processing.cpp:1316-1326` | MISSING — see BUG-N5. `peer.nim` has no `peerHighBandwidthTo` / `m_bip152_highbandwidth_to` field. Only `peerHighBandwidth` (= `_from`) is tracked. |
| G29 | When announcing a NEW block to peers: if any peer is in HB-to mode, send CMPCTBLOCK directly (skip headers/inv); otherwise send headers (BIP-130) or inv | `net_processing.cpp:5895-5912` (announcing loop) | MISSING — see BUG-9. `peermanager.nim:938-951` `selectBlockAnnouncement` returns ONLY `newHeaders` or `newInv`; there is no `newCmpctBlockMsg` branch. `compactBlockState.highBandwidthMode` is set on the peer but no path reads it for announce selection. |

### In-flight tracking + IBD (G30)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G30 | Parallel compact-block download: same blockhash MAY have up to `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` simultaneous in-flight requests, expressed via a multimap `mapBlocksInFlight{hash → (nodeid, iterator)}` | `net_processing.cpp:4577-4624`, `net_processing.h:47` | MISSING — see BUG-N5. `peermanager.nim:91` declares `inFlightBlocks: Table[BlockHash, InFlightBlock]` — single-valued, cannot represent 3 concurrent requests for the same hash. Compounds with G27/G28: even if HB-peer list existed, the in-flight tracking is one-deep. |

### Additional discovery — 50% miss-fraction threshold (carried from W112)

| #  | Gate | Core ref | Status |
|----|------|----------|--------|
| G19a | When some txs are missing from cmpctblock + mempool: ALWAYS send GETBLOCKTXN to first_in_flight peer (no miss-fraction threshold) | `net_processing.cpp:4609-4633` | PARTIAL — see BUG-10. `peer.nim:1404-1410` applies a `missPct > 50.0` skip: blocks with >50% missing txs are counted as `failedReconstructions` and **no getblocktxn is sent**. Core has no such threshold; the round-trip cost is preferred over a wholesale full-block fetch. |

(G19a is included as a 31st check; it sits naturally under the
CMPCTBLOCK receive bucket but is sub-bucketed because it's about the
DECISION to call into G20-G22 rather than about InitData per se.)

## Score

- **PRESENT**: G1, G2, G3, G4, G5, G6, G8, G9, G10, G16, G18, G23 = 12
- **PARTIAL**: G24, G26, G19a = 3
- **MISSING**: G7, G11, G12, G13, G14, G15, G17, G19, G20, G21, G22,
  G25, G27, G28, G29, G30 = 16

Net BUGS for the dashboard (PARTIAL + MISSING): **19** raw, deduped
to **13 distinct BUGs** because:
- G7/G30 are the same defect (single-valued inFlightBlocks)
- G11/G27/G28/G29 are the same defect (HB-peer announce-side absent)
- G20/G21/G22 are the same defect (getblocktxn serve stub)
- G12/G13/G14/G15 are the same defect (cmpctblock-header
  validation absent before InitData)

## BUGS catalogue (13 distinct, priority-ordered)

### BUG-1 [P1] — cmpctblock header not chain-state-validated before InitData
- Gates: G12, G13, G14, G15
- Core: `net_processing.cpp:4469-4508`
- nimrod: `peer.nim:1366-1377` calls `initPartiallyDownloadedBlock(cb)`
  immediately on receipt, with no prev-block lookup, no chain-work
  threshold, no `ProcessNewBlockHeaders`, no LoadingBlocks/IBD guard.
- Impact: a peer can send a cmpctblock for an arbitrary header
  (including one that doesn't connect to our chain) and trigger
  mempool short-id matching work; an invalid-PoW header would not
  trip our DoS counters via the cmpctblock path; an orphan header
  would not cause us to issue a getheaders.

### BUG-2 [P1] — getblocktxn serve handler is a stub
- Gates: G20, G21, G22
- Core: `net_processing.cpp:4245-4302`, `SendBlockTransactions` at 2598
- nimrod: `peer.nim:1419-1436` only logs receipt; no block lookup, no
  BLOCKTXN response. `blocktxnDepthOk` helper exists at
  `compact_blocks.nim:658` but is never invoked.
- Impact: any peer using nimrod as a serving partner that misses txs
  in a cmpctblock from us will time out waiting for BLOCKTXN. nimrod
  is an unusable HB-from-them partner (although since BUG-3 also
  prevents us from being selected as their HB-source-of-us in the
  first place, the impact is masked at fleet-level).

### BUG-3 [P1] — HB-peer ANNOUNCE-side missing entirely
- Gates: G11, G27, G28, G29
- Core: `net_processing.cpp:1272-1329` (MaybeSetPeerAsAnnouncing-
  HeaderAndIDs), `5895-5912` (announce loop emits CMPCTBLOCK to HB
  peers)
- nimrod: no `lNodesAnnouncingHeaderAndIDs` analog; no
  `m_bip152_highbandwidth_to` flag; `selectBlockAnnouncement`
  (`peermanager.nim:938`) only returns headers/inv; `sendSendCmpct`
  is only ever called with `announce=false` at handshake.
- Impact: nimrod NEVER announces a new block via CMPCTBLOCK. Every
  block is announced via HEADERS (BIP-130) or INV. Peers that
  signalled `announce=true` (HB-from-us request) get demoted to
  low-bandwidth mode by us silently. nimrod is BIP-152-receive-only.

### BUG-4 [P1] — extra_txn (orphan/recent) pool never wired
- Gate: G19
- Core: `blockencodings.cpp:147-176`; called from
  `net_processing.cpp:4591`'s `partialBlock.InitData(cmpctblock, vExtraTxnForCompact)`
- nimrod: `fillFromExtraPool` (`compact_blocks.nim:476-506`) is a
  well-engineered helper (correctly mirrors Core's have_txn /
  filledSlots collision logic at lines 484-506) but has zero callers.
  Verified: `grep -rn fillFromExtraPool src/` returns only the
  definition; `peer.nim:1366-1417` calls only `fillFromMempool` at
  line 1385.
- Impact: orphans and recently-confirmed transactions that would
  otherwise complete reconstruction without a round-trip force a
  GETBLOCKTXN. Throughput regression vs Core; fleet-interop
  asymmetry.
- Pattern: classic **dead-helper-at-call-site** (34-wave streak).

### BUG-5 [P1] — `Misbehaving` never called on rsInvalid cmpctblock
- Gate: G17
- Core: `net_processing.cpp:4592-4594` calls `Misbehaving(peer,
  "invalid compact block")` AND `RemoveBlockRequest` on rsInvalid.
- nimrod: `peer.nim:1378-1379` only emits `warn "invalid compact
  block"`. `ScoreInvalidCompactBlock = 100` is defined at
  `peer.nim:1635` but never invoked anywhere in `src/`.
- Impact: a peer can spam invalid cmpctblocks indefinitely without
  being disconnected. DoS-amplification (no rate-limit, no score).
- Pattern: classic **dead-constant-at-call-site** — symmetric to
  BUG-4. The score constant was defined and the call-site was left
  TODO.

### BUG-6 [P2] — single-valued inFlightBlocks; no MAX_CMPCTBLOCKS_INFLIGHT
- Gates: G7, G30
- Core: `net_processing.h:47` `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`;
  `mapBlocksInFlight` is `std::multimap` keyed on blockhash with up
  to 3 entries for the same hash from distinct HB peers.
- nimrod: `peermanager.nim:91` `inFlightBlocks: Table[BlockHash, InFlightBlock]`
  is single-valued.
- Impact: parallel compact-block download from 3 HB peers is
  structurally impossible. (Mooted today by BUG-3, but a future fix
  to BUG-3 would also need to widen the table.)

### BUG-7 [P2] — getdata(invCmpctBlock) has no `peerCmpctVersion` precondition
- New defect (BUG-N2)
- Core: a remote sending getdata(MSG_CMPCTBLOCK) for a block
  presupposes it has previously sent us SENDCMPCT and we accepted it.
  Core's path is mediated by `nodestate->m_provides_cmpctblocks`.
- nimrod: `nimrod.nim:971-1006` serves a compact block in response
  to getdata(invCmpctBlock) regardless of whether the requesting
  peer ever sent us SENDCMPCT. `peer.peerCmpctVersion` is set on
  receipt of SENDCMPCT but never consulted at serve-time.
- Impact: bandwidth wasted serving cmpctblocks to peers that won't
  understand them; spec-divergence at the periphery (peer with v1
  client and no SENDCMPCT now receives a v2 cmpctblock and will fail
  to parse witness-bearing prefilled txs). Low practical impact; the
  peer would just drop the message.

### BUG-8 [P2] — no IsBlockMutated / merkle-root check after FillBlock
- Gate: G25
- New defect (BUG-N4)
- Core: `blockencodings.cpp:218-222` calls `IsBlockMutated(block,
  segwit_active)` before returning READ_STATUS_OK from FillBlock; on
  mutation detected → READ_STATUS_FAILED.
- nimrod: `compact_blocks.nim:546-570` `reconstructBlock` explicitly
  comments at lines 564-568 that this check is NOT performed and is
  left to callers; no caller in `peer.nim:1389,1446` performs it.
- Impact: short-ID-collision-induced wrong-tx reconstruction is not
  caught at the cmpctblock layer. Validation will catch it later
  (merkle root check in connectBlock), but DoS-resilience is lower:
  Core fails fast with READ_STATUS_FAILED and falls back to
  getdata(MSG_BLOCK); nimrod silently accepts the wrong block into
  pending and only fails much later.

### BUG-9 [P2] — block reconstructed but not submitted to chain
- Gate: G26
- Core: `net_processing.cpp:3505-3513` / `4701` call `ProcessNewBlock`
  on successful reconstruction with `force_processing=true,
  min_pow_checked=true`.
- nimrod: `peer.nim:1389-1395`, `1446-1451` log "reconstructed" and
  increment `successfulReconstructions++`; no callback to chain
  submission. Verified: no `chainState.connectBlock` / equivalent
  call within mkCmpctBlock / mkBlockTxn handlers.
- Impact: reconstructed blocks are dropped on the floor. nimrod will
  re-fetch the block via normal headers + getdata when announced
  again later, defeating the entire purpose of compact-block relay.
  Throughput cost: O(block-size) bytes per re-fetch.

### BUG-10 [P2] — 50% miss-fraction threshold short-circuits getblocktxn
- Gate: G19a (sub-gate)
- Core: `net_processing.cpp:4609-4633` always sends GETBLOCKTXN when
  some txs are missing AND we are first_in_flight; the missing
  fraction is irrelevant — the round-trip cost is preferred over
  re-fetching the whole block.
- nimrod: `peer.nim:1404-1410` skips GETBLOCKTXN if `missPct > 50.0`,
  counting the block as a failed reconstruction.
- Impact: fleet-wide IBD or post-restart catch-up with low-mempool-
  coverage relays a stream of CMPCTBLOCKs that all fail at >50% miss;
  nimrod is forced to fall back to full GETDATA(MSG_BLOCK). Less
  efficient than Core; bandwidth cost amortizes only at steady-state
  with a warm mempool.

### BUG-11 [P2] — IBD/blocksonly guard absent on sendSendCmpct
- Gate: G10 (sub-gate)
- Core: `MaybeSetPeerAsAnnouncingHeaderAndIDs` returns early when
  `m_opts.ignore_incoming_txs` (blocksonly mode) — "Our mempool will
  not contain the transactions necessary to reconstruct the compact
  block."  See `net_processing.cpp:1276-1279`.
- nimrod: `peer.nim:1234` `await peer.sendSendCmpct()` unconditional
  at end of handshake, regardless of IBD / nil-mempool state.  The
  receive-side does nil-mempool-guard at `peer.nim:1384`, but
  sendcmpct is still emitted, so peers see a v2-capable signal and
  will offer us cmpctblocks we cannot reconstruct.
- Impact: minor — every offered cmpctblock will then fail
  mempool-fill (because mempool is nil/empty during IBD), and we'll
  fall back to full-block getdata.  Bandwidth cost: 1 cmpctblock-
  per-block during IBD.

### BUG-12 [P3] — `blocktxnDepthOk` defined but unused (dead helper)
- New defect (BUG-N1)
- nimrod: `compact_blocks.nim:658-664` defines `blocktxnDepthOk` with
  Core-reference and clear contract; zero callers in `src/`.
- Co-located with BUG-2 (getblocktxn serve stub) — when BUG-2 is
  fixed, this helper becomes its enforcement vehicle.  Until BUG-2
  is fixed, the helper is structurally unreachable.
- Pattern: dead-helper-at-call-site; W126's second instance after
  BUG-4 (fillFromExtraPool).

### BUG-13 [P3] — reconstructBlock does not clear header after fill
- Gate: G24 (sub)
- Core: `blockencodings.cpp:211-212` `header.SetNull();
  txn_available.clear();` immediately after vtx populated.
- nimrod: `compact_blocks.nim:556-562` populates `blk.txs` but does
  NOT mutate `pdb.header` or `pdb.txnAvailable`. Mitigated in
  practice by `completeBlock` (`compact_blocks.nim:617-620`) calling
  `state.pendingPartials.del(blockHash)` on success, so the
  PartiallyDownloadedBlock object is dropped — but `reconstructBlock`
  itself remains re-callable from any caller that holds a `var
  PartiallyDownloadedBlock` reference.
- Impact: low — only matters if a future refactor wires
  `reconstructBlock` into a path that doesn't immediately drop the
  PDB. Defense-in-depth gap.

## Cross-impl context

W112 audited the same surface in February (10 BUGs catalogued).
W126's re-audit confirms 8 of W112's 10 BUGs are STILL PRESENT
(BUG-1 and BUG-2 from W112 closed by FIX-43 + the depth constants
addition) and adds 5 NEW defects W112 did not flag.

The dominant pattern in W126 is **"helper defined, caller absent"**:
- BUG-4: `fillFromExtraPool` (encoding helper, no wiring)
- BUG-5: `ScoreInvalidCompactBlock` (constant, no `misbehaving()` call)
- BUG-12: `blocktxnDepthOk` (helper, no caller)
- Plus the BUG-2 / BUG-9 chain — handlers/dispatchers exist but
  don't run the obvious next step.

This is consistent with the project-wide 34-wave dead-helper-at-call-
site streak. W126 contributes 3 new instances (BUG-4 already known
from W112, BUG-5 and BUG-12 are new).

## Test plan

30 gate-tests in `tests/test_w126_bip152_compact_blocks.nim`, mirroring
the W121 nimrod pattern (PRESENT gates assert via `compiles()` or
behavioral check; MISSING gates use `not compiles(...)` so the file
fails to compile once the gap is closed, signalling the fix wave).

Out-of-scope future work:
- BIP-152 v1 (legacy txid-based) negotiation: nimrod intentionally
  rejects v1 per FIX-43.
- BIP-339 wtxidrelay vs BIP-152 wtxid for short-id: same wtxid is
  used in both contexts; assumed implicit (audited under BIP-339).
- Erlay reconciliation (BIP-330): out-of-scope; W117 covers.
