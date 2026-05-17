# W123 — Mining / GBT parity (nimrod)

Date: 2026-05-17
Audit type: discovery (W11x cadence)
Target: `src/mining/blocktemplate.nim`, `src/mining/fees.nim`,
`src/rpc/mining.nim`, mining RPC handlers in `src/rpc/server.nim`
(`handleGetBlockTemplate`, `handleGetMiningInfo`, `handleSubmitBlock`,
`handleGetNetworkHashPS`, `handleGenerate*`).
Drivers: W108 (which carved partial coverage; ~3 of 30 bugs fixed in
follow-up commits), and the FIX-72 fleet-wide `prioritisetransaction` work
that nimrod was never wave'd into.

## Status

**Status: 30 / 30 gates audited.  30 BUGS confirmed.**

| Severity | Count |
| -------- | ----- |
| P0-CDIV  | 3     |
| P0-RPC   | 4     |
| P1       | 16    |
| P2       | 7     |

Status distribution: PRESENT (0) / PARTIAL (0) / MISSING (30).
Every gate flagged a bug; no aspect of the audited surface is
on-parity with Bitcoin Core.

The wave continues nimrod's well-engineered-codec / gap-at-system-edges
pattern: the `BlockAssembler::CreateNewBlock`-equivalent path
(`buildBlockTemplate`) is structurally sound (reserved-weight,
consecutive-failure abort, finality check, witness commitment fold-back)
but the RPC surface and the operator-facing fields below it have
material divergences.

## Cross-wave context

14 of the 30 gates were originally flagged by W108 and have not been
fixed since (the W108 fix wave addressed BUG-2 / BUG-3 / BUG-10 / BUG-22
only — the vbavailable, vbrequired, BIP-34 height encoding, and taproot-
rules bugs).  The W108→W123 carry-forwards are mapped:

| W108 BUG | W123 Gate |
| -------- | --------- |
| BUG-1  longpollid                | G1  |
| BUG-4  depends                   | G2  |
| BUG-5  bits LE                   | G3  |
| BUG-6  mintime                   | G4  |
| BUG-7  segwit rule               | G5  |
| BUG-8  IBD/peers                 | G7  |
| BUG-9  proposal mode             | G8  |
| BUG-11 blockmintxfee 1000x       | G15 |
| BUG-13 BIP-94 timewarp           | G10 |
| BUG-15 nBits via GetNextWork     | G11 |
| BUG-16 UpdateUncommittedBlock    | G12 |
| BUG-17 duplicate                 | G13 |
| BUG-18 networkhashps 0.0         | G14 |
| BUG-19 nblocks=0                 | G17 |
| BUG-20 chainwork truncation      | G18 |
| BUG-23 signet rule (partial)     | (subsumed by G6/G20) |
| BUG-25 next.bits stale           | G19 |
| BUG-26 mempool pre-filter        | G23b |
| BUG-27 coinbase additional sigops| G27 |
| BUG-28 peer count guard          | (subsumed by G7) |

The carry-forwards preserve the original BUG-IDs so a future fix wave
can chase either tag.  This is the **2nd carry-forward audit** for
nimrod in this session and is consistent with the universal "weakly
enforced GBT RPC surface" finding emerging across the fleet.

Fresh ground in W123 (not in W108):

- **G6**: signet `consensusParams.signet_blocks` + `signet_challenge`
  field structurally absent.  Without `signet_challenge` in params, a
  signet nimrod node cannot construct a valid `default_witness_commitment`
  for the BIP-325 challenge.  Cascading consequence in G20 (rules array
  never emits `!signet`).
- **G16**: `getmininginfo` emits a `currentblocksize` field that Bitcoin
  Core **removed** years ago (PR #16957).  Monitoring tools that key on
  the field's absence break entirely on nimrod.  See "RPC lies about
  removed-field" pattern below.
- **G21**: `prioritisetransaction` and `getprioritisedtransactions`
  RPCs completely absent — nimrod was never wave'd into FIX-72 work that
  every other fleet impl received.  An honest TODO comment is the only
  trace at `src/mempool/mempool.nim:1129-1133`.
- **G22**: `submitheader` RPC absent — header-only chain extension is
  impossible via JSON-RPC, breaking header-attack regression scenarios.
- **G23**: cluster-aware `GetBlockBuilderChunk` selection absent.
  Nimrod has a `ClusterManager` in `src/mempool/cluster.nim` used for
  RBF Rule 8 diagram validation (FIX-79 wired it) but the cluster API
  has no chunk-by-chunk block-builder consumer.  Block-template selection
  still uses per-entry ancestor-feerate sort.  This is the most material
  GBT-side gap — see "ImprovesFeerateDiagram dead-helper-at-call-site"
  fleet pattern.
- **G25**: BIP-152 high-bandwidth peer count not surfaced from
  `getmininginfo` / `getnetworkinfo`.  Cmpct-block wire codec exists
  (`src/network/compact_blocks.nim`) but the operator dashboard is dark
  about HB peer health.  P2-OBSERVABILITY.
- **G26**: coinbase extra-nonce field is **8 raw zero bytes** in
  `createCoinbaseTx` rather than a single OP_0 placeholder (Core's
  `include_dummy_extranonce` behavior).  At heights ≤ 16 this swells
  the scriptSig from 2 → 9 bytes, burning 7 bytes of mining-pool
  extra-nonce space.
- **G28**: No `MoneyRange` / `IsRange()` guard on accumulated
  `totalFees`.  Nim's runtime overflow detection raises
  `OverflowDefect` (worst-case CRASH rather than silent wrap), which
  is better than C++ undefined behavior but worse than Core's graceful
  reject.
- **G29**: `BlockAssembler::m_last_block_weight` / `m_last_block_num_txs`
  not tracked.  Cascading G16 — the unconditional zeros in
  `currentblockweight` / `currentblocktx` confirm absence.  Core
  emits these fields only after a block has been assembled.
- **G30**: `block_reserved_weight` is a compile-time `const` — no
  `-blockreservedweight` operator override.  Mining pools building
  StratV2 / large OP_RETURN-tagged blocks cannot tune the reserved
  budget.

## Gate-by-gate

The 30 gates are catalogued one-to-one with `tests/test_w123_mining_gbt.nim`.
Each gate has a `suite` + at least one `test` flipping its `hasBug`
sentinel from `true` (current state) → `false` (post-fix).  Below the
file:line column points at the offending site in nimrod.

| #  | Gate                                                            | Status   | Severity | nimrod site                                | Core reference                          |
|----|------------------------------------------------------------------|----------|----------|---------------------------------------------|------------------------------------------|
| G1 | GBT `longpollid` missing (BIP-22 §8)                            | MISSING  | P1       | `src/rpc/server.nim:3642-3668`              | `mining.cpp:1002`                        |
| G2 | GBT tx entries missing `depends`                                | MISSING  | P1       | `src/rpc/server.nim:3600-3607`              | `mining.cpp:917-923`                     |
| G3 | GBT `bits` little-endian (Core: big-endian)                     | MISSING  | P0-CDIV  | `src/rpc/server.nim:3660-3665`              | `mining.cpp:1021`                        |
| G4 | GBT `mintime` conflated with `curtime`                          | MISSING  | P1       | `src/rpc/server.nim:3653`                   | `miner.cpp:36-47`, `mining.cpp:1004`     |
| G5 | GBT must reject when client rules lack `segwit`                 | MISSING  | P0-RPC   | `src/rpc/server.nim:3583`                   | `mining.cpp:854-857`                     |
| G6 | `consensusParams.signet_blocks` + `signet_challenge` absent     | MISSING  | P1       | `src/consensus/params.nim:30-95`            | `chainparams.cpp::SigNet`                |
| G7 | GBT must refuse when no peers / in IBD on mainnet               | MISSING  | P0-RPC   | `src/rpc/server.nim:3577-3590`              | `mining.cpp:766-774`                     |
| G8 | GBT `mode="proposal"` not implemented (BIP-22 §6)               | MISSING  | P1       | `src/rpc/server.nim:3582-3584`              | `mining.cpp:730-752`                     |
| G9 | GBT sigops uses estimate, not entry exact `GetSigOpCost`        | MISSING  | P1       | `src/mining/blocktemplate.nim:234-270`      | `mining.cpp:927-932`                     |
| G10| BIP-94 MAX_TIMEWARP=600 not enforced                            | MISSING  | P0-CDIV  | `src/mining/blocktemplate.nim:489-517`      | `consensus.h:35`, `miner.cpp:43-44`      |
| G11| Template `nBits` from prev.bits, not `GetNextWorkRequired`      | MISSING  | P0-CDIV  | `src/mining/blocktemplate.nim:441-445`      | `miner.cpp:220`                          |
| G12| `submitblock` missing `UpdateUncommittedBlockStructures`        | MISSING  | P1       | `src/rpc/server.nim:3681+`                  | `mining.cpp:1084-1090`                   |
| G13| `submitblock` does not return canonical `"duplicate"`           | MISSING  | P1       | `src/rpc/server.nim:3681+`                  | `mining.cpp:1097-1098`                   |
| G14| `getmininginfo` `networkhashps` hardcoded 0.0                   | MISSING  | P1       | `src/rpc/server.nim:4450`                   | `mining.cpp:472`                         |
| G15| `blockmintxfee` 1000x too high; min-fee floor likewise          | MISSING  | P1       | `src/rpc/server.nim:4449`, `blocktemplate.nim:33` | `policy/policy.h:36`               |
| G16| `getmininginfo` emits removed `currentblocksize` field          | MISSING  | P2       | `src/rpc/server.nim:4443-4445`              | `mining.cpp:467-468` (no longer present) |
| G17| `getnetworkhashps` accepts `nblocks=0` (must reject)            | MISSING  | P0-RPC   | `src/rpc/server.nim:8112-8114`              | `mining.cpp:66-68`                       |
| G18| `getnetworkhashps` truncates 256-bit chainwork to top 8 bytes   | MISSING  | P1       | `src/rpc/server.nim:8128-8132`              | `mining.cpp:105-108`                     |
| G19| `getmininginfo` `next.bits` stale at adjustment boundary        | MISSING  | P1       | `src/rpc/server.nim:4455`                   | `mining.cpp:481-486`                     |
| G20| GBT rules never emits `!signet` on signet                       | MISSING  | P1       | `src/rpc/server.nim:3613-3620`              | `mining.cpp:959-963`                     |
| G21| `prioritisetransaction` + `getprioritisedtransactions` absent   | MISSING  | P0-RPC   | dispatch missing in `handleMethod`          | `mining.cpp:502-583`                     |
| G22| `submitheader` RPC absent                                       | MISSING  | P2       | dispatch missing in `handleMethod`          | `mining.cpp:1108-1146`                   |
| G23| Cluster-aware `GetBlockBuilderChunk` selection absent           | MISSING  | P1       | `src/mempool/mempool.nim:1504-1527`         | `miner.cpp:279-334`                      |
| G24| GBT tx `fee` uses base-fee, not modified-fee (downstream G21)   | MISSING  | P2       | `src/rpc/server.nim:3598-3604`              | `mining.cpp:926`                         |
| G25| BIP-152 HB peer count not surfaced                              | MISSING  | P2       | `src/network/compact_blocks.nim:647-680`    | `net_processing.cpp::CmpctBlockHandler`  |
| G26| Coinbase extra-nonce = 8 raw zeros (Core: single OP_0)          | MISSING  | P2       | `src/mining/blocktemplate.nim:174-175`      | `miner.cpp:187-193`                      |
| G27| `coinbase_output_max_additional_sigops` option absent           | MISSING  | P2       | `src/mining/blocktemplate.nim:278-285`      | `miner.cpp:83, 115`                      |
| G28| No `MoneyRange` / `IsRange()` guard on `totalFees` accumulator  | MISSING  | P2       | `src/mining/blocktemplate.nim:380-385`      | `consensus/amount.h:21`                  |
| G29| `m_last_block_weight` / `m_last_block_num_txs` not tracked      | MISSING  | P1       | (no persistent state)                       | `miner.cpp:159-160`                      |
| G30| `-blockreservedweight` operator override absent                 | MISSING  | P1       | `src/mining/blocktemplate.nim:16, 287`      | `miner.cpp:106-108`                      |

## Severity rationale

- **P0-CDIV** (consensus / on-network divergence — block actually
  rejected by Core peers):
  - **G3** (bits little-endian): would not directly cause block
    rejection because submitblock parses bits from `block.nBits` in
    the serialized block, not from the GBT field — but pool software
    constructing the header from the GBT `bits` field bytes-for-bytes
    would produce an invalid header.  Material in practice.
  - **G10** (BIP-94 MAX_TIMEWARP): consensus rule active on every
    network since the BIP-94 buried activation.  A nimrod-mined block
    at an adjustment boundary with a back-dated timestamp would be
    rejected by every Core peer.
  - **G11** (template `nBits` stale): at every 2016-block boundary the
    template emits the wrong bits, causing block rejection with
    `bad-diffbits`.
  - W108 BUG-10 (G10 there, BIP-34 height) was the 4th P0-CDIV but
    was fixed in commit `0312f25`.  This W123 wave finds 3 new ones.

- **P0-RPC** (RPC behavioral divergence operators rely on):
  - **G5** segwit-rule enforcement absent: silent acceptance of
    non-segwit-aware mining clients.
  - **G7** no-peer / IBD guard absent: orphan-block production on
    isolated mainnet nodes.
  - **G17** `getnetworkhashps` nblocks=0 not rejected: monitoring
    tools that expect the RPC error path see a 0.0 response instead.
  - **G21** `prioritisetransaction` absent: operators cannot manually
    nudge stuck txs into a block, breaking a common ops workflow.

- **P1** (operator-observable / dashboard-visible divergence):
  All "field is wrong / missing / hardcoded" bugs that don't directly
  cause network rejection but degrade the operator UX.

- **P2** (latent / nice-to-have):
  - G16 (removed field still emitted): cosmetic but breaks tools that
    test for field absence.
  - G24 (downstream of G21): only operative once G21 is closed.
  - G25 (BIP-152 HB peer count): observability gap.
  - G26 (coinbase extra-nonce shape): consensus-valid, breaks mining
    pool overlay assumptions.
  - G27 (coinbase output additional-sigops option): only matters for
    operators running custom coinbase scripts.
  - G28 (MoneyRange): pathological mempool entries only.
  - G22 (`submitheader`): test-infrastructure only.

## Universal patterns observed

1. **"RPC lies about removed-field"** — new pattern, distinct from
   W120's "RPC lies about RBF status".  Nimrod's `getmininginfo`
   continues to emit `currentblocksize` years after Core removed it,
   and emits `currentblockweight=0` / `currentblocktx=0` unconditionally
   rather than gating on whether a block was actually assembled.
   Cross-fleet check: this is the first wave to flag it for nimrod;
   future W124/W125 audits should check the other 9 impls for the
   same pattern.

2. **"Well-engineered template builder, weak RPC surface"** — recurs
   from W119/W120/W121.  `buildBlockTemplate` itself is solid
   (reserved-weight, finality, MTP cutoff, witness commitment
   fold-back, consecutive-failure abort) but the RPC handler that
   serializes its output to JSON is a thin pass-through that omits
   half the fields Core emits and uses wrong byte orders / values
   for several of those it does emit.

3. **"FIX-72-shaped absence"** (G21) — nimrod was never wave'd into
   the FIX-72 fleet work on `prioritisetransaction`.  Cross-fleet
   blockbrew (`a4bf6ef`), clearbit (`db24ef8`), and several other
   impls have the RPC + persistence layer fully wired.  This is a
   single-impl-behind divergence — the right shape for a near-future
   FIX wave.

4. **"Constants right, plumbing absent"** (G10, G27, G30) — the
   `BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000`, `MAX_CONSECUTIVE_FAILURES
   = 1000`, `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`, `MINIMUM_BLOCK_-
   RESERVED_WEIGHT = 2000` constants are all defined correctly in
   nimrod (`blocktemplate.nim:11-33`).  The MAX_TIMEWARP=600 constant
   is NOT — neither in `params.nim` nor `validation.nim` nor any
   consensus module.  Pattern: constants that fit nicely into a
   "comment-anchored const block" landed; constants that need a new
   enforcement site did not.

5. **"Dead-helper-at-call-site"** (G14, G24, G23) — recurs from W120
   #6/#9.  `handleGetNetworkHashPS` exists at `server.nim:8100-8134`
   and computes a valid hashps value; `handleGetMiningInfo` (line
   4407) does not call it and emits 0.0 instead.  Likewise the
   cluster mempool (`src/mempool/cluster.nim`) is used for RBF Rule 8
   in FIX-79 but no `getBlockBuilderChunk`-equivalent consumer exists
   for the block-template builder.  Five+ instances of this pattern
   in nimrod alone now (W117 + W119 + W120 + W121 + W123).

## Test coverage

The new test file `tests/test_w123_mining_gbt.nim` has 46 tests
across 30 gates + 9 constant-verification anchors:

- 30 BUG-flip tests (one per gate, asserts `hasBug == true` today,
  flips to `false` on fix)
- 6 additional sub-tests (some gates have multi-aspect bugs — G15a/b,
  G16a/b, G21a/b/c, G6a/b, G18 + value comparison)
- 9 constant-verification tests pinning critical Core values
  (MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST, DEFAULT_BLOCK_RESERVED_-
  WEIGHT, MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_CONSECUTIVE_FAILURES,
  BLOCK_FULL_ENOUGH_WEIGHT_DELTA, MAX_TIMEWARP absence assertion,
  subsidy halving math at heights 0 / 210000 / 33×210000)

All 46 tests pass under `nim c -r tests/test_w123_mining_gbt.nim`.
The pre-existing `tests/test_blockstore` MinBlocksToKeep namespace
conflict remains untouched (per FIX-83/87 notes).

## Recommended fix-wave decomposition

If a future fix wave attacks W123, the cleanest decomposition is:

- **FIX-A (P0-CDIV, 3 bugs)**: G3 (GBT bits big-endian), G10 (BIP-94
  MAX_TIMEWARP), G11 (GetNextWorkRequired in buildBlockTemplate).
  All three are call-site / byte-order fixes with no architecture
  ripple.  Bundle: ~200 LOC across `server.nim` and `blocktemplate.nim`.

- **FIX-B (P0-RPC, 4 bugs)**: G5 (segwit rule), G7 (peer/IBD guard),
  G17 (nblocks=0 reject), G21 (prioritisetransaction).  G21 carries
  the largest delta (~600 LOC: RPC handler + mempool delta table +
  persistence in `mempool/persist.nim` which is already partly
  scaffolded).  G5/G7/G17 are ~50 LOC each.

- **FIX-C (P1 cleanup, 16 bugs)**: G1/G2/G4/G6/G8/G9/G12/G13/G14/
  G15/G18/G19/G20/G23/G29/G30.  Most are simple field-emission tweaks
  in `handleGetBlockTemplate` and `handleGetMiningInfo`.  G6 needs
  a new `signet_blocks` + `signet_challenge` field on ConsensusParams
  threaded through chainparams init.  G23 is the largest — wiring
  cluster-aware chunk selection into the block builder.

- **FIX-D (P2 polish, 7 bugs)**: G16, G22, G24, G25, G26, G27, G28.
  Most are <30 LOC.

## References

- `bitcoin-core/src/node/miner.cpp`
- `bitcoin-core/src/rpc/mining.cpp`
- `bitcoin-core/src/policy/policy.h`
- `bitcoin-core/src/consensus/consensus.h`
- `bitcoin-core/src/util/feefrac.h` / `.cpp`
- BIPs 9 / 22 / 23 / 94 / 141 / 152 / 325
- W108 audit (`tests/test_w108_gbt.nim`) — superseded by this audit
  for the 14 carry-forward gates
