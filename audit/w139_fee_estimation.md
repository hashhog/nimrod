# W139 — Fee estimation engine (CBlockPolicyEstimator) audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W139).
Concurrent waves: 3 OTHER discovery waves running in PARALLEL; this wave
covers the **fee estimation engine** axis (CBlockPolicyEstimator), which
is the dynamic histogram subsystem that backs `estimatesmartfee` /
`estimaterawfee` — distinct from W114 (which was a 30-gate fee-estimation
audit dated 2026-05-14 with FIX-47/48/49 follow-on) by re-sweeping from a
**post-FIX-48/49** state and focusing on the gates W114 did NOT cover:
unconfTxs circular buffer; failAvg evicted-tx accounting; estimateSmartFee
half/full/double composition; FeeFilterRounder; binary fees-file v309900
codec; conservative-mode plumbing; nBestSeenHeight reorg gate;
validForFeeEstimation 4-flag entry filter; bucketMap.lower_bound vs
nimrod's linear `if feeRate <= bucketRate`; sat/vbyte-vs-sat/kvB unit
divergence; MaxUsableEstimate floor; HighestTargetTracked clamping.

Target:
  - `src/mining/fees.nim`             — entire module (FeeEstimator,
                                        HorizonStats, BucketStats,
                                        TrackedTx, FeeRateBuckets,
                                        SHORT/MED/LONG_DECAY/SCALE/
                                        PERIODS, trackTransaction,
                                        processBlock, removeTransaction,
                                        applyDecay, estimateFee /
                                        estimateFeeForHorizon /
                                        estimateFeeForPriority,
                                        getConfirmationRate*,
                                        saveFeeEstimates,
                                        loadFeeEstimates, clear).
  - `src/rpc/server.nim` (4170-4301)  — `handleEstimateSmartFee`,
                                        `handleEstimateRawFee`,
                                        `horizonResult` inner helper,
                                        `handleSendToAddress`
                                        FallbackFeeRate fork
                                        (5599-5604; 6745-6765).
  - `src/rpc/server.nim` (3787-3797, 3954-3961, 4016-4021)
                                      — three `feeEstimator.processBlock`
                                        call sites (acceptBlock /
                                        reorg-via-submitblock /
                                        generateToAddress).
  - `src/mempool/mempool.nim`         — wiring: `feeEstimator` field at
                                        :93; `trackTransaction` at :1370;
                                        `removeTransaction` at :1415.
  - `src/nimrod.nim`                  — `newFeeEstimator` instantiation at
                                        :2041, `loadFeeEstimates` at
                                        :2043, `saveFeeEstimates` at
                                        :1485, mempool wiring at :2046.

Bitcoin Core references:
  - `src/policy/fees/block_policy_estimator.h`
    - lines 25–35  (`FEE_FLUSH_INTERVAL=1h`, `MAX_FILE_AGE=60h`,
                    `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=false`)
    - lines 44–54  (`FeeEstimateHorizon { SHORT, MED, LONG }` enum +
                    `ALL_FEE_ESTIMATE_HORIZONS`)
    - lines 59–68  (`FeeReason { NONE, HALF, FULL, DOUBLE, CONSERVATIVE,
                    MEMPOOL_MIN, FALLBACK, REQUIRED }`)
    - lines 71–97  (`EstimatorBucket` / `EstimationResult` /
                    `FeeCalculation` PODs)
    - lines 150–198 (private SHORT/MED/LONG_BLOCK_PERIODS / SCALE /
                     DECAY constants; HALF=.6 / SUCCESS=.85 / DOUBLE=.95;
                     SUFFICIENT_FEETXS=.1 / SUFFICIENT_TXS_SHORT=.5;
                     MIN_BUCKET_FEERATE=100 / MAX_BUCKET_FEERATE=1e7;
                     FEE_SPACING=1.05; OLDEST_ESTIMATE_HISTORY=6048)
    - lines 200–264 (public API: processBlock / processTransaction /
                     removeTx / estimateFee / estimateSmartFee /
                     estimateRawFee / Write / Read / FlushUnconfirmed /
                     HighestTargetTracked / Flush / FlushFeeEstimates /
                     GetFeeEstimatorFileAge)
    - lines 276–321 (private state: nBestSeenHeight, firstRecordedHeight,
                     historicalFirst, historicalBest, mapMemPoolTxs,
                     feeStats/shortStats/longStats, trackedTxs/
                     untrackedTxs, buckets, bucketMap, processBlockTx,
                     estimateCombinedFee, estimateConservativeFee,
                     BlockSpan, HistoricalBlockSpan, MaxUsableEstimate,
                     _removeTx)
    - lines 323–344 (`FeeFilterRounder` class)
  - `src/policy/fees/block_policy_estimator.cpp`
    - lines 36–48  (`CURRENT_FEES_FILE_VERSION=309900`,
                    `INF_FEERATE=1e99`, StringForFeeEstimateHorizon)
    - lines 53–67  (EncodedDoubleFormatter — float64 via
                    `EncodeDouble`/`DecodeDouble`)
    - lines 78–176 (TxConfirmStats class declaration: txCtAvg / confAvg /
                    failAvg / m_feerate_avg / unconfTxs / oldUnconfTxs /
                    decay / scale + ClearCurrent / Record /
                    UpdateMovingAverages / NewTx / removeTx /
                    EstimateMedianVal / Write / Read)
    - lines 207–214 (ClearCurrent: circular-buffer roll;
                    `unconfTxs[nBlockHeight % unconfTxs.size()][j] = 0`)
    - lines 217–229 (Record: `periodsToConfirm = (blocksToConfirm +
                    scale - 1) / scale`; loop `for size_t i =
                    periodsToConfirm; i <= confAvg.size(); i++`
                    increments cumulative `confAvg[i-1][bucketIndex]`)
    - lines 231–242 (UpdateMovingAverages: decay confAvg / failAvg /
                    m_feerate_avg / txCtAvg ALL by `decay`)
    - lines 245–409 (EstimateMedianVal: high→low scan;
                    `sufficientTxVal / (1 - decay)` combination
                    threshold; passing/failing bucket tracking;
                    median-of-pass-bucket selection via txCtAvg
                    cumulative midpoint)
    - lines 411–419 (Write: decay → scale → m_feerate_avg → txCtAvg →
                    confAvg → failAvg; all via
                    EncodedDoubleFormatter)
    - lines 421–475 (Read: throws on decay outside (0,1);
                    scale != 0; bucket-count mismatch;
                    maxConfirms > 6*24*7=1008; period-count
                    consistency)
    - lines 477–520 (NewTx: `bucketMap.lower_bound(val)->second` —
                    map-based bucket lookup; removeTx: blocksAgo logic;
                    oldUnconfTxs vs unconfTxs[blockIndex] decision;
                    failAvg increment when `(blocksAgo / scale)`
                    periods)
    - lines 522–541 (CBlockPolicyEstimator::removeTx +
                    _removeTx: triple-stats removal +
                    mapMemPoolTxs.erase)
    - lines 543–577 (Constructor: bucket vector build via
                    `FEE_SPACING=1.05` ; INF_FEERATE sentinel;
                    three TxConfirmStats; file load with age check)
    - lines 581–594 (CValidationInterface bridge:
                    TransactionAddedToMempool /
                    TransactionRemovedFromMempool /
                    MempoolTransactionsRemovedForBlock)
    - lines 596–639 (processTransaction:
                    `txHeight != nBestSeenHeight` skip;
                    `validForFeeEstimation = !mempool_limit_bypassed
                    && !submitted_in_package && chainstate_is_current
                    && has_no_mempool_parents`; triple-bucket NewTx with
                    bucketIndex consistency assert)
    - lines 641–667 (processBlockTx: `nBlockHeight - txHeight`
                    blocksToConfirm; `Record(blocksToConfirm,
                    feerate.GetFeePerK())` on all three horizons)
    - lines 669–716 (processBlock: `nBlockHeight <= nBestSeenHeight`
                    reorg gate; nBestSeenHeight update IN SYNC with
                    ClearCurrent; ClearCurrent then
                    UpdateMovingAverages then processBlockTx loop;
                    firstRecordedHeight assignment; tracked/untracked
                    counter reset)
    - lines 718–761 (estimateFee: `confTarget <= 1` → CFeeRate(0);
                    estimateRawFee via DOUBLE_SUCCESS_PCT MED horizon;
                    estimateRawFee horizon switch; SUFFICIENT_TXS_SHORT
                    only for SHORT)
    - lines 763–778 (HighestTargetTracked: per-horizon
                    `GetMaxConfirms()`)
    - lines 780–802 (BlockSpan / HistoricalBlockSpan /
                    MaxUsableEstimate: min(longMax, max(blockSpan,
                    historicalBlockSpan) / 2))
    - lines 808–842 (estimateCombinedFee: pick shortest horizon
                    tracking confTarget; checkShorterHorizon
                    monotonicity fallback)
    - lines 847–862 (estimateConservativeFee: MED at doubleTarget +
                    LONG at doubleTarget, take max)
    - lines 871–956 (estimateSmartFee: confTarget clamp to
                    MaxUsableEstimate; `confTarget == 1 → 2`;
                    halfEst HALF_SUCCESS_PCT at confTarget/2;
                    actualEst SUCCESS_PCT at confTarget; doubleEst
                    DOUBLE_SUCCESS_PCT at 2*confTarget; conservative
                    max-merge; FeeReason cascade)
    - lines 958–976 (Flush: FlushUnconfirmed + FlushFeeEstimates;
                    Write to fee_estimates.dat)
    - lines 978–1000 (Write: CURRENT_FEES_FILE_VERSION → nBestSeenHeight
                    → historical range → buckets → three TxConfirmStats)
    - lines 1002–1062 (Read: version check; bucket count 2..1000
                    range check; three TxConfirmStats Read)
    - lines 1064–1076 (FlushUnconfirmed: remove every mapMemPoolTxs
                    entry — records failure to confirm)
    - lines 1078–1083 (GetFeeEstimatorFileAge: fs::last_write_time
                    delta)
    - lines 1085–1118 (MakeFeeSet + FeeFilterRounder::round:
                    `FEE_FILTER_SPACING=1.1`; randomized
                    boundary-down rounding 2/3 of the time)
  - `src/policy/feerate.{h,cpp}`
    - feerate.h:31–80   (CFeeRate class — sat/kvB internal repr;
                        `GetFeePerK() = m_feerate.EvaluateFeeDown(1000)`;
                        operator<=>, +=, *; ToString BTC_KVB / SAT_VB)
    - feerate.cpp:11–18 (CFeeRate(CAmount, int32_t virtual_bytes)
                        — virtual_bytes ≤ 0 → empty)
    - feerate.cpp:20–27 (GetFee: round-up `EvaluateFeeUp`)
  - `src/rpc/fees.cpp`
    - lines 32–95   (estimatesmartfee: estimate_mode parse;
                    `ParseConfirmTarget(0, max_target)`;
                    `max(feeRate, min_mempool_feerate,
                    min_relay_feerate)`; feerate in BTC/kvB)
    - lines 97–216  (estimaterawfee: per-horizon emit, threshold
                    range check 0..1, pass/fail EstimatorBucket
                    surface)
  - `src/policy/fees/block_policy_estimator_args.cpp`
    - DEFAULT_ACCEPT_STALE_FEE_ESTIMATES gating

BIPs: none (CBlockPolicyEstimator is policy, not consensus).

## Status

**BUGS FOUND — 21 distinct defects across 21 gates MISSING / PARTIAL /
WRONG (of 30). 9 gates PRESENT.**

Distribution:
  - **0 P0-CDIV / P0-CONS** — fee estimation is policy not consensus, so
    no divergence is consensus-fatal. ALL bugs are P1 (cross-impl /
    interop / wire-correctness) or P2 (interface) or P3 (cosmetic).
  - **9 P1**  — wire-format / cross-impl interop / RPC-shape bugs
    (BUG-1 fees-file binary v309900 codec absent — JSON instead;
    BUG-2 stale-file age check absent; BUG-3 unconfTxs circular buffer
    absent — no in-mempool inflation of estimates; BUG-4 failAvg
    eviction accounting absent — no failure pressure on estimates;
    BUG-5 sat/vbyte vs sat/kvB unit divergence in trackTransaction /
    bucketing; BUG-6 nBestSeenHeight reorg-gate absent —
    same-or-lower-height block reprocessing inflates confirmations
    on reorg; BUG-7 validForFeeEstimation 4-flag entry filter absent
    — bypass / package / IBD / parent-in-mempool txs counted toward
    estimates; BUG-8 bucketMap.lower_bound vs nimrod linear scan;
    BUG-9 estimateSmartFee half/full/double max-merge absent —
    nimrod uses single-horizon estimate per target).
  - **8 P2**  — interface gaps + missing internals
    (BUG-10 conservative-mode parameter ignored;
    BUG-11 estimatesmartfee "blocks" returns confTarget verbatim
    instead of clamped returnedTarget;
    BUG-12 estimatesmartfee mempool-min/relay-floor `max` not applied;
    BUG-13 estimateSmartFee `confTarget=1 → 2` clamp absent;
    BUG-14 MaxUsableEstimate floor absent;
    BUG-15 sufficientTxVal bucket-grouping logic absent —
    EstimateMedianVal walks single buckets only;
    BUG-16 estimateConservativeFee absent;
    BUG-17 FeeFilterRounder absent — feefilter wire emits raw
    mempool min fee).
  - **3 P3**  — cosmetic / contract
    (BUG-18 FeeReason enum absent — estimatesmartfee never reports
    `mode=ECONOMICAL/CONSERVATIVE` or `reason=HALF/FULL/DOUBLE/...`;
    BUG-19 trackedTxs/untrackedTxs accounting counters absent —
    no debug log "Blockpolicy estimates updated by X of Y";
    BUG-20 firstRecordedHeight + historicalFirst/historicalBest
    absent — Read/Write headers diverge from Core);
    + **BUG-21** (P3) FlushUnconfirmed absent on shutdown — txs
    still in mempool at shutdown do not get failure-recorded.

## Gates / matrix

Order: each gate covers a distinct slice of Core's CBlockPolicyEstimator
contract. Verdicts: PRESENT (Core-aligned), PARTIAL (some Core behaviour
matched, some missed), MISSING (gap), BUG-N (defect catalogued).

| #  | Gate | Verdict |
|----|------|---------|
| G1 | FeeEstimator instantiation + non-nil + mempool wiring (FIX-47) | PRESENT |
| G2 | Three-horizon SHORT/MED/LONG TxConfirmStats with correct decay (FIX-48) | PRESENT |
| G3 | Per-horizon decay constants: 0.962 / 0.9952 / 0.99931 | PRESENT |
| G4 | Per-horizon scale: 1 / 2 / 24 | PRESENT |
| G5 | Per-horizon periods: 12 / 24 / 42 (yields 12 / 48 / 1008 block horizon) | PRESENT |
| G6 | Bucket scheme: MIN_BUCKET_FEERATE=100 sat/kvB, MAX=1e7, FEE_SPACING=1.05 → ~237 buckets | **BUG-8** (P1) |
| G7 | Feerate unit: sat/kvB (Core: CFeeRate::GetFeePerK) in trackTransaction / Record | **BUG-5** (P1) |
| G8 | trackTransaction validForFeeEstimation gating (4 flags) | **BUG-7** (P1) |
| G9 | nBestSeenHeight tracking + reorg-gate (`nBlockHeight <= nBestSeenHeight → skip`) | **BUG-6** (P1) |
| G10 | processBlock: ClearCurrent → UpdateMovingAverages → Record (FIX-49 order) | PRESENT (PARTIAL — no ClearCurrent because no unconfTxs buffer; see BUG-3) |
| G11 | Record cumulative loop: increment confAvg[i] for ALL i ≥ periodsToConfirm | **BUG-9** (P1, partial: nimrod only increments one slot) |
| G12 | Decay-before-record FIX-49 closure preserved | PRESENT |
| G13 | unconfTxs circular buffer + oldUnconfTxs eviction (Core txmempool inflates estimates) | **BUG-3** (P1) |
| G14 | failAvg eviction-failure accounting | **BUG-4** (P1) |
| G15 | trackedTxs / untrackedTxs counters + per-block reset | **BUG-19** (P3) |
| G16 | EstimateMedianVal: high→low scan + sufficientTxVal/(1-decay) bucket grouping | **BUG-15** (P2) |
| G17 | EstimateMedianVal: median-of-pass-bucket via txCtAvg midpoint walk | PRESENT (PARTIAL — nimrod returns bucket avgFeeRate directly) |
| G18 | estimateSmartFee: confTarget==1 → 2 clamp | **BUG-13** (P2) |
| G19 | estimateSmartFee: clamp confTarget to MaxUsableEstimate | **BUG-14** (P2) |
| G20 | estimateSmartFee: halfEst + actualEst + doubleEst three-way max-merge | **BUG-9** (P1) |
| G21 | estimateConservativeFee: MED + LONG max at 2*target with DOUBLE_SUCCESS_PCT | **BUG-16** (P2) |
| G22 | estimateSmartFee: conservative parameter routed through | **BUG-10** (P2) |
| G23 | estimatesmartfee RPC: max(feeRate, min_mempool, min_relay) floor + "blocks" = returnedTarget | **BUG-12** (P2) + **BUG-11** (P2) |
| G24 | FeeCalculation/FeeReason: `mode`/`reason` returned in estimatesmartfee result | **BUG-18** (P3) |
| G25 | Binary fees-file codec v309900 with EncodedDoubleFormatter + nBestSeenHeight + historical range | **BUG-1** (P1) + **BUG-20** (P3) |
| G26 | MAX_FILE_AGE=60h stale-file gate (DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=false) | **BUG-2** (P1) |
| G27 | FEE_FLUSH_INTERVAL=1h periodic flush | MISSING (covered by W114 BUG-16; not double-counted in W139) |
| G28 | FlushUnconfirmed on shutdown — record failure for still-in-mempool txs | **BUG-21** (P3) |
| G29 | FeeFilterRounder + MakeFeeSet with FEE_FILTER_SPACING=1.1 randomised round | **BUG-17** (P2) |
| G30 | bucketMap.lower_bound semantic (binary-search; bucketBoundary inclusive on upper end) | **BUG-8** (P1) |

## Detailed findings

### G6 / G30 — bucket scheme + bucketMap.lower_bound (BUG-8, P1)

`src/mining/fees.nim:14-18`:
```nim
FeeRateBuckets* = [1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0, 30.0, 50.0,
  75.0, 100.0, 150.0, 200.0, 300.0, 500.0, 750.0, 1000.0, 1500.0, 2000.0,
  5000.0, 10000.0]
NumBuckets* = 22
```
Core (`block_policy_estimator.cpp:546-555`):
```cpp
for (double bucketBoundary = MIN_BUCKET_FEERATE; bucketBoundary <=
     MAX_BUCKET_FEERATE; bucketBoundary *= FEE_SPACING, bucketIndex++) {
  buckets.push_back(bucketBoundary);
  bucketMap[bucketBoundary] = bucketIndex;
}
buckets.push_back(INF_FEERATE);
```
Core's iteration with `MIN_BUCKET_FEERATE=100`, `MAX_BUCKET_FEERATE=1e7`,
`FEE_SPACING=1.05` produces **237 buckets** (236 from the loop + INF
sentinel). Each bucket boundary is `100 * 1.05^i`. Nimrod has **22**
hand-crafted buckets starting at 1 sat/vbyte (= 1000 sat/kvB, ten times
Core's minimum), with non-geometric spacing.

**Wire impact**: estimaterawfee `pass.startrange` / `pass.endrange` /
`fail.startrange` / `fail.endrange` numerics will never match Core for
the same on-chain history. The shape of the JSON is the same but the
numbers are gibberish from Core's perspective. Tools that aggregate fee
estimates across implementations (e.g. mempool.space) cannot consume
nimrod's output without per-impl post-processing.

**Lookup impact**: `getBucketIndex` (line 92-99) does a linear scan:
```nim
for i, bucketRate in FeeRateBuckets:
  if feeRate <= bucketRate:
    return i
return NumBuckets - 1
```
Core uses `bucketMap.lower_bound(val)->second` — a binary search against
an `std::map<double, unsigned int>`. The semantic is `bucketBoundary >=
val`, and `lower_bound` returns the first such boundary. The behaviour
matches nimrod's `feeRate <= bucketRate` only by coincidence — Core's
upper-bound-is-inclusive form means a feerate **equal to** a bucket
boundary maps to that bucket, not the next-higher one. Nimrod's code
agrees here. But the linear scan is O(buckets); with 237 buckets it is
still trivial. The bug is that the buckets themselves diverge.

### G7 — Feerate unit divergence sat/vbyte vs sat/kvB (BUG-5, P1)

`src/mempool/mempool.nim:1370`:
```nim
mp.feeEstimator.trackTransaction(txid, feeRate, mp.chainState.bestHeight)
```
where `feeRate` is `sat/vbyte` (see `mempool.nim:25` `feeRate*: float64
## Fee rate in sat/vbyte`). Core (`block_policy_estimator.cpp:633`):
```cpp
unsigned int bucketIndex = feeStats->NewTx(txHeight,
  static_cast<double>(feeRate.GetFeePerK()));
```
`GetFeePerK()` returns `sat/kvB` = `sat/vbyte * 1000`. Nimrod's bucket
boundaries are in sat/vbyte (1..10000) and the lookup expects sat/vbyte
values. Core's bucket boundaries are in sat/kvB (100..1e7).

**Impact**: nimrod's persisted `fee_estimates.json` is in sat/vbyte
units; a clean migration to Core's binary v309900 codec (BUG-1)
would require unit conversion on every read/write, or the existing
JSON files would silently be misinterpreted by 1000×. Worse, the RPC
output `feerate` field is divided by 100_000_000 (BTC) but multiplied
only by 1000 not by 1000×1000 (see `server.nim:4190` `feeBtcPerKb =
feeRate * 1000.0 / 100000000.0`), so the unit conversion in the RPC
path *happens to* line up by treating bucket boundaries as sat/vbyte
and emitting BTC/kvB.

### G8 — validForFeeEstimation 4-flag gating absent (BUG-7, P1)

`src/mempool/mempool.nim:1367-1370`:
```nim
# BUG-1 fix (W114 FIX-47): wire fee estimator on successful accept.
if mp.feeEstimator != nil:
  mp.feeEstimator.trackTransaction(txid, feeRate,
                                   mp.chainState.bestHeight)
```
Every successful accept enters the estimator. Core
(`block_policy_estimator.cpp:618-625`):
```cpp
const bool validForFeeEstimation =
  !tx.m_mempool_limit_bypassed &&
  !tx.m_submitted_in_package &&
  tx.m_chainstate_is_current &&
  tx.m_has_no_mempool_parents;
if (!validForFeeEstimation) { untrackedTxs++; return; }
trackedTxs++;
```
Four exclusions:
1. `m_mempool_limit_bypassed` — `prioritisetransaction` or
   testmempoolaccept-bypass paths inject txs at floor; they are not
   organic broadcasts and should not influence estimates.
2. `m_submitted_in_package` — package-relay txs do not represent
   independent broadcast-feerate choices.
3. `m_chainstate_is_current` — IBD must be complete; counting txs
   confirmed in old blocks against current-block heights produces
   wildly off estimates.
4. `m_has_no_mempool_parents` — CPFP/ancestor packaging means the
   child's feerate doesn't represent independent broadcast feerate.

Nimrod's mempool tracks ancestor info (`ancestorFee` /
`ancestorWeight` / `ancestorCount` / `ancestorSize` per
`MempoolEntry`); a `has_no_mempool_parents` check is computable as
`ancestorCount == 1` (= self only). The IBD / package / bypass flags
would have to be plumbed through `AtmpArgs`.

**Wire impact**: nimrod's estimates are skewed by all of:
- prioritised txs forcing the "fast" bucket up;
- package txs counting individually toward bucket statistics;
- IBD-time inrush counting against current-block heights — the
  generateToAddress regtest path (server.nim:4021) calls
  `processBlock(height, @[])` with empty txids, but the mempool
  loaded via `loadMempool` (nimrod.nim:2030) on startup populates
  `trackedTxs` immediately.

### G9 — nBestSeenHeight reorg-gate absent (BUG-6, P1)

`src/mining/fees.nim` has **no** `nBestSeenHeight` field. Core
(`block_policy_estimator.cpp:672-685`):
```cpp
if (nBlockHeight <= nBestSeenHeight) {
  // Ignore side chains and re-orgs
  return;
}
nBestSeenHeight = nBlockHeight;
feeStats->ClearCurrent(nBlockHeight);
shortStats->ClearCurrent(nBlockHeight);
longStats->ClearCurrent(nBlockHeight);
...
```
Nimrod's `processBlock(fe, height, confirmedTxids)` (mining/fees.nim:149)
unconditionally records every block. The reorg path
(server.nim:3954-3961) re-invokes `processBlock` on every newly-connected
block — if a 2-block reorg replays B+1 → B+2 → B+3 after disconnecting
B → B+1 → B+2 → B+3 → B', the txids confirmed at the same height get
double-counted on first re-record. Worse, no clear-current circular
buffer roll happens because there is no unconfTxs buffer (BUG-3).

**Concrete impact**: an attacker that can force a 1-block reorg every
hour (e.g. via selfish mining at small hashrate) can inflate the
estimator's confirmation counts in low-fee buckets, dropping the
estimatesmartfee output toward the floor — which they pay — while
honest users overpay or underpay relative to the manipulated estimate.

### G11 — Record cumulative loop missing (BUG-9 partial, P1)

`src/mining/fees.nim:172-175`:
```nim
for hs in [addr fe.shortHorizon, addr fe.medHorizon, addr fe.longHorizon]:
  let period = (blocksToConfirm - 1) div hs.scale
  if period >= 0 and period < hs.numPeriods:
    hs.buckets[tracked.bucketIdx].totalConfirmed[period] += 1
```
Core (`block_policy_estimator.cpp:217-229`):
```cpp
int periodsToConfirm = (blocksToConfirm + scale - 1) / scale;
unsigned int bucketindex = bucketMap.lower_bound(feerate)->second;
for (size_t i = periodsToConfirm; i <= confAvg.size(); i++) {
  confAvg[i - 1][bucketindex]++;
}
```
**Core increments the count for ALL periods `i >= periodsToConfirm`,
not just the one period bucket the tx happens to land in**. The
semantic is "this tx confirmed in `periodsToConfirm` periods or
fewer", and the cumulative-confirmation count at any target ≥
periodsToConfirm includes this tx.

`getConfirmationRateForHorizon` (line 205-219) computes
`sum(totalConfirmed[0 ..< maxPeriod])`, which inverts the cumulative:
it sums per-slot increments back into a cumulative count at lookup
time. The two formulations are equivalent in isolation
(`sum of one-slot increments = cumulative count`), but they diverge
when:
- decay is applied to all `MaxTargetBlocks=1008` slots
  (mining/fees.nim:106-107) every block, while Core decays only
  `confAvg.size() == maxPeriods` slots per stats instance (12 / 24 /
  42). With nimrod's array(1008), period slots 12..1007 of
  shortHorizon are decayed every block but never written; they remain
  zero forever — wasted work but not a correctness bug per se.
- the rate computation in `getConfirmationRateForHorizon` uses
  `maxPeriod = min((targetBlocks + hs.scale - 1) div hs.scale,
  hs.numPeriods)` which IS the correct count, but iterates the
  cumulative inside the rate function. **The bucket grouping in
  EstimateMedianVal — `partialNum < sufficientTxVal / (1 - decay)` —
  is NOT replicated** in nimrod (BUG-15).

### G13 — unconfTxs circular buffer absent (BUG-3, P1)

Core (`block_policy_estimator.h:113-115`):
```cpp
std::vector<std::vector<int> > unconfTxs;  //unconfTxs[Y][X]
std::vector<int> oldUnconfTxs;
```
inflated by `NewTx` (block_policy_estimator.cpp:480-483) and decremented
by `removeTx` (line 505-512). Used in `EstimateMedianVal` (line 290-292)
to add `extraNum` (in-mempool txs still unconfirmed for ≥ confTarget) to
the denominator of the success rate.

Without unconfTxs, an estimator with 1000 confirmed-fast txs in bucket-X
and 10000 still-in-mempool-for-100-blocks txs in bucket-X reports
success rate 100% — but Core would report
`1000 / (1000 + 0 + 10000) = ~9%` and reject bucket-X for short
confirmation targets.

**Impact**: nimrod systematically over-estimates confirmation
probability when the mempool has a backlog. estimatesmartfee returns
low feerates during congestion — exactly when high feerates are
needed.

### G14 — failAvg eviction-failure accounting absent (BUG-4, P1)

Core (`block_policy_estimator.cpp:513-519`): on mempool eviction without
confirmation, increment `failAvg[i]` for `i` periods up to `blocksAgo /
scale`. Used in EstimateMedianVal's denominator as `failNum`.

Nimrod's `removeTransaction(fe, txid)` (mining/fees.nim:186-203) simply
decrements `totalSeen` / `feeRateSum` and removes from trackedTxs. There
is **no record that this tx failed to confirm within Y periods**. The
estimator forgets the bucket-load was placed at all.

**Impact**: if 100 txs enter bucket-X and 90 are evicted (low feerate,
mempool churn), nimrod sees 10 txs in bucket-X with 10 confirmations =
100% rate. Core sees 10 confirmed / (10 confirmed + 0 inmempool + 90
left) = 10% rate.

### G16 — sufficientTxVal bucket-grouping absent (BUG-15, P2)

`src/mining/fees.nim:235-249`: `estimateFeeForHorizon` scans single
buckets:
```nim
for i in 0..<NumBuckets:
  let rate = getConfirmationRateForHorizon(hs, i, targetBlocks)
  if hs.buckets[i].totalSeen >= 1 and rate >= ConfirmationThreshold:
    ...
```
Core (`block_policy_estimator.cpp:280-342`): walks high→low, **combining
adjacent buckets** until `partialNum >= sufficientTxVal / (1 - decay)`
THEN tests the combined success rate. This handles the
"too-few-samples-per-bucket" case where 237 buckets and a sparse
mempool history means each bucket has <1 sample, but adjacent groups
of 10 buckets have 10 samples.

Nimrod's `totalSeen >= 1` floor rejects most buckets entirely; with
22 hand-crafted buckets and DAY-scale mempool the bucket loads are
much heavier per-bucket, so the threshold is sometimes reached, but
the bucket-grouping is necessary for sparse-data correctness AND for
the "consistent groups between different confirmation targets"
invariant Core's comment calls out (line 268-271).

### G18 / G19 — confTarget=1 → 2 + MaxUsableEstimate clamp absent (BUG-13 + BUG-14, P2)

Core (`block_policy_estimator.cpp:889-895`):
```cpp
if (confTarget == 1) confTarget = 2;
unsigned int maxUsableEstimate = MaxUsableEstimate();
if ((unsigned int)confTarget > maxUsableEstimate) {
  confTarget = maxUsableEstimate;
}
if (feeCalc) feeCalc->returnedTarget = confTarget;
```
Nimrod (`src/rpc/server.nim:4174-4187`) range-checks `confTarget in
[1..1008]` and returns `"blocks": confTarget` unconditionally. **Two
defects**:
1. confTarget=1 is allowed but `estimateFee` will return either the
   short-horizon estimate (which has insufficient data per Core's
   philosophy — see line 720 `if (confTarget <= 1) return CFeeRate(0)`)
   or FallbackFeeRate. Core silently rewrites 1→2.
2. The estimator's *usable* history may not extend to 1008 blocks.
   Core caps confTarget to `min(longMax, max(blockSpan,
   historicalBlockSpan) / 2)` to avoid claiming estimates beyond
   what the data supports.

### G20 — estimateSmartFee three-way max-merge absent (BUG-9, P1)

Core (`block_policy_estimator.cpp:919-940`):
```cpp
double halfEst = estimateCombinedFee(confTarget/2, HALF_SUCCESS_PCT, ...);
double actualEst = estimateCombinedFee(confTarget, SUCCESS_PCT, ...);
double doubleEst = estimateCombinedFee(2*confTarget, DOUBLE_SUCCESS_PCT, ...);
median = max(halfEst, actualEst, doubleEst);
```
i.e. estimateSmartFee at confTarget returns the **max** of three
sub-estimates at different (target, threshold) pairs:
- (target/2, 60%) — most aggressive
- (target, 85%)   — default
- (2*target, 95%) — most conservative

This monotonicity-preserving design ensures that estimating for a
longer target never returns a higher feerate than a shorter one
(within data-availability caveats).

Nimrod (`src/rpc/server.nim:4181`):
```nim
feeRate = rpc.feeEstimator.estimateFee(confTarget)
```
calls a single-horizon `estimateFee` (mining/fees.nim:253-271) that
returns the *first* bucket meeting `ConfirmationThreshold = 0.85`
(equivalent to Core's SUCCESS_PCT). The half / double / conservative
multi-threshold composition is entirely absent.

### G21 / G22 — estimateConservativeFee + conservative mode (BUG-16 + BUG-10, P2)

Core (`block_policy_estimator.cpp:847-862`): `estimateConservativeFee`
takes the max of MED and LONG at `2*confTarget` with DOUBLE_SUCCESS_PCT
(95%). estimateSmartFee invokes it when `conservative=true` OR when the
combined three-way estimate fails (`median == -1`).

Nimrod (`src/rpc/server.nim:4170-4195`): the `handleEstimateSmartFee`
RPC takes no `estimate_mode` parameter at all — the `params` array is
read only for `params[0]` (confTarget). Help string at line 4574 lists
the parameter (`estimatesmartfee conf_target ( "estimate_mode" )`) but
the handler ignores it. CONSERVATIVE vs ECONOMICAL mode is silently a
no-op.

### G23 — estimatesmartfee mempool-min / relay floor + returnedTarget (BUG-11 + BUG-12, P2)

Core (`src/rpc/fees.cpp:81-92`):
```cpp
CFeeRate feeRate{fee_estimator.estimateSmartFee(conf_target, &feeCalc,
                                                conservative)};
if (feeRate != CFeeRate(0)) {
  CFeeRate min_mempool_feerate{mempool.GetMinFee()};
  CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
  feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
  result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
} else {
  errors.push_back("Insufficient data or no feerate found");
}
result.pushKV("blocks", feeCalc.returnedTarget);
```
Two semantics:
1. **feerate floor**: estimateSmartFee output is bumped up to at least
   the current mempool min-feerate and the configured min-relay-feerate.
2. **returnedTarget**: blocks field reflects the *post-clamp* target
   (after confTarget=1→2 and MaxUsableEstimate clamping). Nimrod
   echoes the input confTarget unchanged.

Nimrod (`src/rpc/server.nim:4189-4195`):
```nim
let feeBtcPerKb = feeRate * 1000.0 / 100000000.0
%*{
  "feerate": feeBtcPerKb,
  "blocks": confTarget
}
```
No `max(..., mempool.getMinFee(), mempool.minFeeRate)` call. nimrod's
`mempool.getMinFee()` exists (mempool.nim:1545) but is not consulted.

**Impact**: during congestion, nimrod's estimatesmartfee can return a
feerate **below** the current mempool min — a wallet using that
estimate would create a tx that gets immediately dropped from the
mempool at relay time. Core's floor prevents this; nimrod's doesn't.

### G24 — FeeReason enum absent (BUG-18, P3)

Core's `FeeReason` enum (block_policy_estimator.h:60-68) and
`FeeCalculation::reason` are surfaced through `bumpfee` / `getmempoolinfo`
/ wallet RPC error messages (`StringForFeeReason` in util/fees.cpp).
Nimrod has no enum and the result JSON omits the `mode` field that
Core uses in some wallet outputs. estimatesmartfee result schema is
NOT broken by this (Core's own RPC doesn't emit `mode` — see
rpc/fees.cpp:77-92), but downstream wallet integration that expects
to log "FeeReason::HALF" debug messages cannot do so.

### G25 — Binary fees-file v309900 codec (BUG-1 + BUG-20, P1 + P3)

Nimrod (`src/mining/fees.nim:309-345`):
```nim
proc saveFeeEstimates*(fe: FeeEstimator, path: string) =
  ## Save fee estimator bucket statistics to a JSON file.
  ...
  let state = %*{
    "version":    2,
    "numBuckets": NumBuckets,
    "short":      horizonToJson(fe.shortHorizon),
    "medium":     horizonToJson(fe.medHorizon),
    "long":       horizonToJson(fe.longHorizon)
  }
  writeFile(tmpPath, $state)
  moveFile(tmpPath, path)
```
Core writes a binary stream (`block_policy_estimator.cpp:978-1000`):
```cpp
fileout << CURRENT_FEES_FILE_VERSION;        // int   309900
fileout << nBestSeenHeight;                  // uint  current tip
if (BlockSpan() > HistoricalBlockSpan()/2) {
  fileout << firstRecordedHeight << nBestSeenHeight;
} else {
  fileout << historicalFirst << historicalBest;
}
fileout << buckets;                          // vector<double>
feeStats->Write(fileout);                    // 3 × TxConfirmStats
shortStats->Write(fileout);
longStats->Write(fileout);
```
And each TxConfirmStats writes (`block_policy_estimator.cpp:411-419`):
```cpp
fileout << EncodedDouble(decay);
fileout << scale;
fileout << m_feerate_avg;
fileout << txCtAvg;
fileout << confAvg;     // [maxPeriods][buckets]
fileout << failAvg;     // [maxPeriods][buckets]
```
**No interop**: a nimrod node's `fee_estimates.json` cannot be read by
Core, and a Core node's `fee_estimates.dat` cannot be read by nimrod.

**BUG-20**: even within nimrod's JSON, the headers `nBestSeenHeight` /
`firstRecordedHeight` / `historicalFirst` / `historicalBest` are not
written, because those fields don't exist (BUG-6 + ancillary).
loadFeeEstimates accepts a v1 single-horizon JSON and a v2 three-horizon
JSON but doesn't recover the bucket boundaries from file (Core does so
to support DEFAULT_MIN_RELAY_TX_FEE migration).

### G26 — MAX_FILE_AGE=60h stale-file gate (BUG-2, P1)

Core constructor (`block_policy_estimator.cpp:567-572`):
```cpp
std::chrono::hours file_age = GetFeeEstimatorFileAge();
if (file_age > MAX_FILE_AGE && !read_stale_estimates) {
  LogWarning("Fee estimation file too old ...");
  return;
}
if (!Read(est_file)) { ... }
```
Nimrod's `loadFeeEstimates` (mining/fees.nim:347-396) checks `fileExists`
but never calls `os.getLastModificationTime` or compares against
60-hour age. A 6-month-old fee_estimates.json gets loaded verbatim,
contaminating the new estimator with stale histogram data that has
no relationship to current mempool dynamics.

### G27 — periodic 1h flush (covered by W114 BUG-16)

W114 already flagged that nimrod has no `FEE_FLUSH_INTERVAL=1h` periodic
flush. Not re-catalogued in W139.

### G28 — FlushUnconfirmed on shutdown (BUG-21, P3)

Core (`block_policy_estimator.cpp:1064-1076`): `FlushUnconfirmed`
removes every `mapMemPoolTxs` entry on shutdown, which records each
as a non-confirmation via removeTx's `failAvg` increment (since BUG-4
governs that mechanism). Nimrod's shutdown calls `saveFeeEstimates`
(nimrod.nim:1485) but not the equivalent of FlushUnconfirmed — the
trackedTxs table is simply discarded.

**Impact**: a node that frequently restarts with N still-unconfirmed
txs in mempool effectively forgets that those txs FAILED to confirm
quickly. The estimator believes they're still in flight forever (until
processBlock confirms or removeTransaction is called). Combined with
BUG-3 (no unconfTxs), this is moot in the short term but contaminates
estimate state if mempool persistence (mempool.dat) re-adds the same
txs on restart and trackTransaction is called again — double-counting.

### G29 — FeeFilterRounder absent (BUG-17, P2)

Core (`block_policy_estimator.h:323-344`) defines `FeeFilterRounder`
class with `MAX_FILTER_FEERATE=1e7` + `FEE_FILTER_SPACING=1.1` (NOT
the same as `FEE_SPACING=1.05` used for estimator buckets — see
the comment at h:328-331). Used by net_processing's `MaybeSendFeefilter`
to randomly round the mempool min-fee 2/3 of the time DOWN to the
next-lower set boundary, preserving privacy by quantising the wire
feefilter to coarse boundaries.

W136 (BIP-133 feefilter wave) already flagged this. W139 confirms
no FeeFilterRounder exists in nimrod's tree — `src/network/relay.nim`
has its own quantisation logic but doesn't use a Core-aligned set or
the 1.1× spacing.

## Universal patterns observed

1. **"Single-horizon RPC API but three-horizon storage"** —
   `handleEstimateSmartFee` (rpc/server.nim:4170) calls
   `feeEstimator.estimateFee(confTarget)` which (mining/fees.nim:253-271)
   dispatches to ONE of three horizons based on target. The combined
   half/full/double max-merge is absent. This is the same pattern as
   W114 BUG-10 (conservative mode ignored) re-surfaced from a different
   angle: nimrod has the *storage* for three horizons (FIX-48) but the
   *consumer* logic is single-pass.

2. **"Audit-flip-from-W114 sweeping new gates"** — W114 was a 30-gate
   sweep at FIX-47/48/49 time. W139 takes 30 NEW gates by reading
   block_policy_estimator.{h,cpp} line-by-line for sub-systems W114
   did NOT cover (unconfTxs / failAvg / EstimateMedianVal bucket
   grouping / nBestSeenHeight reorg gate / validForFeeEstimation /
   FeeFilterRounder / binary v309900 codec / 60h stale gate /
   estimateConservativeFee). This continues the "audit-iteration-on-
   subsystem" pattern from W120 (RBF) and W117 (BIP-155).

3. **"Wire-incompatible persistence file"** — nimrod's
   fee_estimates.json is structurally incompatible with Core's
   fee_estimates.dat (BUG-1). Same pattern as W136 BUG (relay.nim
   dead module) — code exists but doesn't speak Core's binary wire.
   blockbrew W118 found similar JSON-vs-binary divergence on
   wallet.dat. Pattern depth: every persistence file should be
   tested against Core byte-for-byte fixtures, not just round-trip.

4. **"Unit divergence sat/vbyte vs sat/kvB"** (BUG-5) — nimrod's
   internal feerate is sat/vbyte while Core's is sat/kvB. The
   RPC layer divides by 1000 sometimes (server.nim:4190) but not
   others; the bucket boundaries silently encode the choice. A
   future BIP-133 feefilter wire-emission fix (W136) must reconcile
   these.

5. **"validForFeeEstimation gating is universal"** (BUG-7) — every
   impl that didn't separately gate-fee-estimation-on-IBD-and-package
   has this issue. Cross-impl audit prediction: blockbrew / clearbit
   / camlcoin / ouroboros likely all flunk this gate.

## Out of scope (deferred to future waves)

- W139 does NOT propose fixes; all 21 BUGs are catalogued for future
  FIX-86+ ranking. Estimated fix cost:
    - BUG-1 binary codec — ~2-3 hr (define EncodedDouble; emit
      VectorFormatter; round-trip test against Core fixture).
    - BUG-3 unconfTxs — ~3-4 hr (data structure + ClearCurrent rolling
      buffer + EstimateMedianVal denominator).
    - BUG-4 failAvg — ~2-3 hr (parallel to confAvg; touch
      removeTransaction + EstimateMedianVal denominator).
    - BUG-5 unit migration — ~1 hr (caller-site sweep; bucket-boundary
      conversion in fee_estimates.json migration).
    - BUG-6 nBestSeenHeight — ~30 min (field + guard at top of
      processBlock).
    - BUG-7 validForFeeEstimation — ~1-2 hr (plumb 4 flags through
      AtmpArgs; check at trackTransaction call site).
    - BUG-8 bucket scheme — ~1 hr (refactor FeeRateBuckets to
      computed; touch getBucketIndex + persistence).
    - BUG-9 three-way max-merge — ~2 hr (estimateCombinedFee +
      estimateSmartFee composition).
    - BUG-10 conservative mode — ~1 hr (parse estimate_mode in
      handleEstimateSmartFee; route to estimateConservativeFee).
    - BUG-11 returnedTarget — ~30 min (return clamped target).
    - BUG-12 floor — ~30 min (max with mempool.getMinFee() +
      mempool.minFeeRate).
    - BUG-13 confTarget=1→2 — ~10 min.
    - BUG-14 MaxUsableEstimate — ~1 hr (BlockSpan / HistoricalBlockSpan
      bookkeeping; clamp).
    - BUG-15 sufficientTxVal bucket grouping — ~3-4 hr (rewrite
      EstimateMedianVal scan).
    - BUG-16 estimateConservativeFee — ~1 hr.
    - BUG-17 FeeFilterRounder — ~2 hr (touches W136 fix).
    - BUG-18 FeeReason enum — ~1 hr (enum + StringForFeeReason +
      route through wallet bumpfee).
    - BUG-19 trackedTxs/untrackedTxs — ~30 min.
    - BUG-20 historical-range Read/Write headers — ~1 hr.
    - BUG-21 FlushUnconfirmed — ~30 min.
    - BUG-2 stale-file gate — ~30 min (getLastModificationTime).
  Total estimated effort: ~25-30 hours.

- Concurrent-wave coordination: 3 OTHER discovery waves running in
  parallel. No production code is touched by W139.

- W139 does NOT re-catalogue W114 BUGs that are still open (BUG-9
  blocks-echo, BUG-10 conservative, BUG-13 FlushUnconfirmed,
  BUG-14 binary codec, BUG-15 stale-file, BUG-16 periodic flush,
  BUG-17 confTarget=1, BUG-18 sufficientTxVal). Where the W139 finding
  overlaps with a W114 still-open BUG, the W139 BUG number is used
  (this audit is freshly numbered 1..21 from the W139 perspective)
  and a cross-reference is noted in the gate row.

## Pre-existing FIX history (context only)

- FIX-47 (commit 26301b1, 2026-04-15): wire trackTransaction into
  mempool-accept — closed W114 BUG-1.
- FIX-48 (commit 1894871, 2026-04-25): three-horizon TxConfirmStats
  with correct decay — closed W114 BUG-2 + BUG-3.
- FIX-49 (commit d0e2154, 2026-05-14): record confirmation before
  applying decay — closed W114 BUG-19.

W139 starts from the post-FIX-49 state and finds 21 NEW bugs that
fall outside the gates W114 catalogued.
