## W139 — Fee estimation engine (CBlockPolicyEstimator) audit
## (30 gates, xfail regression guards).
##
## Audit type: discovery (NO production code change in W139).
##
## W139 catalogues 21 NEW bugs (post-FIX-47/48/49) in nimrod's fee
## estimation engine against bitcoin-core/src/policy/fees/
## block_policy_estimator.{h,cpp}, bitcoin-core/src/policy/feerate.{h,cpp},
## and bitcoin-core/src/rpc/fees.cpp.
##
## Distinct from W114 (which audited the basic three-horizon shape
## under FIX-47/48/49) — W139 re-sweeps from a POST-FIX-49 state and
## covers the gates W114 did NOT: unconfTxs circular buffer; failAvg
## eviction accounting; EstimateMedianVal three-way max-merge;
## FeeFilterRounder; binary v309900 codec; conservative-mode plumbing;
## nBestSeenHeight reorg gate; validForFeeEstimation 4-flag entry
## filter; bucketMap.lower_bound vs nimrod linear scan; sat/vbyte vs
## sat/kvB unit divergence; MaxUsableEstimate clamp; estimateSmartFee
## confTarget=1→2 rewrite; floor with mempool min + relay min;
## FeeReason enum; FlushUnconfirmed on shutdown.
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour with
## a `check` that pins the gap.  When a future FIX wave closes the gap,
## the test will fail loudly and the developer must flip the assertion
## (per W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
## W134 / W135 / W136 / W137 methodology).
##
## References:
##   bitcoin-core/src/policy/fees/block_policy_estimator.h
##     - 25-35  (FEE_FLUSH_INTERVAL=1h, MAX_FILE_AGE=60h)
##     - 44-68  (FeeEstimateHorizon / FeeReason enums)
##     - 71-97  (EstimatorBucket / EstimationResult / FeeCalculation)
##     - 150-198 (SHORT/MED/LONG_BLOCK_PERIODS/SCALE/DECAY; HALF/SUCCESS/
##                DOUBLE; SUFFICIENT_FEETXS/SUFFICIENT_TXS_SHORT;
##                MIN_BUCKET_FEERATE=100; MAX_BUCKET_FEERATE=1e7;
##                FEE_SPACING=1.05; OLDEST_ESTIMATE_HISTORY=6048)
##   bitcoin-core/src/policy/fees/block_policy_estimator.cpp
##     - 36-67   (CURRENT_FEES_FILE_VERSION=309900;
##                EncodedDoubleFormatter)
##     - 78-176  (TxConfirmStats with txCtAvg/confAvg/failAvg/
##                m_feerate_avg/unconfTxs/oldUnconfTxs)
##     - 207-242 (ClearCurrent / Record cumulative-loop /
##                UpdateMovingAverages)
##     - 245-409 (EstimateMedianVal high→low scan;
##                sufficientTxVal/(1-decay) bucket grouping)
##     - 543-577 (constructor — 237-bucket build + file-age load)
##     - 596-639 (processTransaction validForFeeEstimation 4-flag gate)
##     - 669-716 (processBlock nBestSeenHeight reorg gate)
##     - 808-862 (estimateCombinedFee / estimateConservativeFee)
##     - 871-956 (estimateSmartFee three-way max-merge +
##                confTarget=1→2 + MaxUsableEstimate)
##     - 1064-1083 (FlushUnconfirmed / GetFeeEstimatorFileAge)
##     - 1085-1118 (MakeFeeSet / FeeFilterRounder::round 2/3-down)
##   bitcoin-core/src/policy/feerate.{h,cpp}
##     (CFeeRate sat/kvB internal repr; GetFeePerK = 1000× sat/vB)
##   bitcoin-core/src/rpc/fees.cpp
##     - 32-95  (estimatesmartfee: estimate_mode; max-floor;
##               returnedTarget)
##     - 97-216 (estimaterawfee per-horizon emit)
##   audit/w139_fee_estimation.md — full gate table + per-BUG detail.

import unittest2
import std/[math, json, os, tempfiles, strutils, times]
import ../src/mining/fees
import ../src/primitives/types

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # block_policy_estimator.cpp:37
  CORE_CURRENT_FEES_FILE_VERSION = 309900
  # block_policy_estimator.h:26
  CORE_FEE_FLUSH_INTERVAL_HOURS = 1
  # block_policy_estimator.h:32
  CORE_MAX_FILE_AGE_HOURS = 60
  # block_policy_estimator.h:160
  CORE_OLDEST_ESTIMATE_HISTORY = 6 * 1008
  # block_policy_estimator.h:163-167
  CORE_SHORT_DECAY = 0.962
  CORE_MED_DECAY   = 0.9952
  CORE_LONG_DECAY  = 0.99931
  # block_policy_estimator.h:151-158
  CORE_SHORT_BLOCK_PERIODS = 12
  CORE_MED_BLOCK_PERIODS   = 24
  CORE_LONG_BLOCK_PERIODS  = 42
  CORE_SHORT_SCALE = 1
  CORE_MED_SCALE   = 2
  CORE_LONG_SCALE  = 24
  # block_policy_estimator.h:170-174
  CORE_HALF_SUCCESS_PCT   = 0.6
  CORE_SUCCESS_PCT        = 0.85
  CORE_DOUBLE_SUCCESS_PCT = 0.95
  # block_policy_estimator.h:177-179 (referenced in source-text gates only)
  CORE_SUFFICIENT_FEETXS_REF    {.used.} = 0.1
  CORE_SUFFICIENT_TXS_SHORT_REF {.used.} = 0.5
  # block_policy_estimator.h:190-198
  CORE_MIN_BUCKET_FEERATE = 100.0   # sat/kvB
  CORE_MAX_BUCKET_FEERATE = 1.0e7   # sat/kvB
  CORE_FEE_SPACING        = 1.05
  # block_policy_estimator.h:326-331
  CORE_FEE_FILTER_SPACING = 1.1
  # block_policy_estimator.h:35
  CORE_DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false

# Read production source files once for source-level pinning.
let
  feesSrc    = readFile("src/mining/fees.nim")
  serverSrc  = readFile("src/rpc/server.nim")
  mempoolSrc = readFile("src/mempool/mempool.nim")
  nimrodSrc  = readFile("src/nimrod.nim")

proc makeTxId(n: int): TxId =
  var arr: array[32, byte]
  arr[0] = byte(n and 0xff)
  arr[1] = byte((n shr 8) and 0xff)
  arr[2] = byte((n shr 16) and 0xff)
  arr[3] = byte((n shr 24) and 0xff)
  TxId(arr)

# ---------------------------------------------------------------------------
# G1 — Estimator instantiation + mempool wiring (PRESENT, FIX-47)
# ---------------------------------------------------------------------------
suite "W139 G1 — estimator instantiation + mempool wiring (PRESENT, FIX-47)":

  test "G1 PRESENT: newFeeEstimator returns non-nil":
    let fe = newFeeEstimator()
    check fe != nil

  test "G1 PRESENT: mempool wires feeEstimator at startup (FIX-47)":
    ## src/nimrod.nim:2046 — `state.mempool.feeEstimator = state.feeEstimator`
    check "state.mempool.feeEstimator = state.feeEstimator" in nimrodSrc

  test "G1 PRESENT: acceptTransactionWithArgs calls trackTransaction (FIX-47)":
    check "mp.feeEstimator.trackTransaction" in mempoolSrc

# ---------------------------------------------------------------------------
# G2 — Three-horizon SHORT/MED/LONG storage (PRESENT, FIX-48)
# ---------------------------------------------------------------------------
suite "W139 G2 — three-horizon storage (PRESENT, FIX-48)":

  test "G2 PRESENT: FeeEstimator has shortHorizon/medHorizon/longHorizon":
    let fe = newFeeEstimator()
    check fe.shortHorizon.numPeriods == CORE_SHORT_BLOCK_PERIODS
    check fe.medHorizon.numPeriods   == CORE_MED_BLOCK_PERIODS
    check fe.longHorizon.numPeriods  == CORE_LONG_BLOCK_PERIODS

# ---------------------------------------------------------------------------
# G3 — Per-horizon decay constants 0.962/0.9952/0.99931 (PRESENT, FIX-48)
# ---------------------------------------------------------------------------
suite "W139 G3 — per-horizon decay (PRESENT, FIX-48)":

  test "G3 PRESENT: SHORT_DECAY = 0.962":
    check abs(SHORT_DECAY - CORE_SHORT_DECAY) < 0.0001

  test "G3 PRESENT: MED_DECAY = 0.9952":
    check abs(MED_DECAY - CORE_MED_DECAY) < 0.0001

  test "G3 PRESENT: LONG_DECAY = 0.99931":
    check abs(LONG_DECAY - CORE_LONG_DECAY) < 0.0001

# ---------------------------------------------------------------------------
# G4 — Per-horizon scale 1/2/24 (PRESENT)
# ---------------------------------------------------------------------------
suite "W139 G4 — per-horizon scale (PRESENT)":

  test "G4 PRESENT: SHORT_SCALE/MED_SCALE/LONG_SCALE":
    check SHORT_SCALE == CORE_SHORT_SCALE
    check MED_SCALE   == CORE_MED_SCALE
    check LONG_SCALE  == CORE_LONG_SCALE

# ---------------------------------------------------------------------------
# G5 — Per-horizon periods 12/24/42 (PRESENT)
# ---------------------------------------------------------------------------
suite "W139 G5 — per-horizon periods (PRESENT)":

  test "G5 PRESENT: SHORT_PERIODS=12, MED_PERIODS=24, LONG_PERIODS=42":
    check SHORT_PERIODS == CORE_SHORT_BLOCK_PERIODS
    check MED_PERIODS   == CORE_MED_BLOCK_PERIODS
    check LONG_PERIODS  == CORE_LONG_BLOCK_PERIODS

  test "G5 PRESENT: derived max-target 12/48/1008":
    check SHORT_MAX_TARGET == 12
    check MED_MAX_TARGET   == 48
    check LONG_MAX_TARGET  == 1008

# ---------------------------------------------------------------------------
# G6 / G30 — Bucket scheme MIN/MAX/FEE_SPACING (BUG-8, P1)
# ---------------------------------------------------------------------------
suite "W139 G6/G30 — bucket scheme (BUG-8, P1)":

  test "G6 BUG-8: nimrod has 22 hand-crafted buckets; Core builds ~237":
    ## Core: 100 sat/kvB * 1.05^i ≤ 1e7 → 236 + 1 INF sentinel = 237.
    var coreCount = 0
    var b = CORE_MIN_BUCKET_FEERATE
    while b <= CORE_MAX_BUCKET_FEERATE:
      inc coreCount
      b *= CORE_FEE_SPACING
    inc coreCount  # INF_FEERATE sentinel at the end
    check coreCount > 200
    check NumBuckets == 22  # documents the divergence

  test "G6 BUG-8: nimrod buckets start at 1 sat/vbyte vs Core 100 sat/kvB":
    ## Core MIN_BUCKET_FEERATE = 100 sat/kvB = 0.1 sat/vbyte;
    ## nimrod FeeRateBuckets[0] = 1.0 sat/vbyte.  10× higher floor.
    check FeeRateBuckets[0] == 1.0
    # In sat/kvB units, nimrod's floor is 1000, vs Core's 100.
    check (FeeRateBuckets[0] * 1000.0) == 1000.0
    check CORE_MIN_BUCKET_FEERATE == 100.0
    check (FeeRateBuckets[0] * 1000.0) > CORE_MIN_BUCKET_FEERATE

  test "G6 BUG-8: nimrod buckets are NOT geometrically spaced at 1.05x":
    var isGeometric = true
    for i in 1 ..< NumBuckets:
      let ratio = FeeRateBuckets[i] / FeeRateBuckets[i - 1]
      if abs(ratio - CORE_FEE_SPACING) > 0.01:
        isGeometric = false
        break
    check not isGeometric

  test "G30 BUG-8: bucketMap.lower_bound semantic is replaced by linear scan":
    ## Core uses std::map<double, unsigned int> bucketMap with
    ## .lower_bound(val) — O(log n).  Nimrod has `getBucketIndex` doing
    ## a linear `for ... if feeRate <= bucketRate`.  Behaviour matches
    ## semantically (lower-bound = first boundary >= val) but the
    ## bucketMap field doesn't exist.
    check "bucketMap" notin feesSrc
    check "lower_bound" notin feesSrc
    check "for i, bucketRate in FeeRateBuckets" in feesSrc

# ---------------------------------------------------------------------------
# G7 — Feerate unit sat/vbyte vs sat/kvB (BUG-5, P1)
# ---------------------------------------------------------------------------
suite "W139 G7 — feerate unit divergence (BUG-5, P1)":

  test "G7 BUG-5: mempool tracks feeRate in sat/vbyte":
    ## Core stores feerate.GetFeePerK() = sat/kvB.  Nimrod's MempoolEntry
    ## stores feeRate in sat/vbyte (mempool.nim:25).
    check "Fee rate in sat/vbyte" in mempoolSrc

  test "G7 BUG-5: trackTransaction takes feeRate in sat/vbyte from mempool":
    ## mempool.nim:1370 — `mp.feeEstimator.trackTransaction(txid, feeRate, ...)`
    ## where `feeRate` is sat/vbyte.  Core passes sat/kvB.
    check "feeEstimator.trackTransaction(txid, feeRate" in mempoolSrc
    # Sanity: track at sat/vbyte
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    # 10 sat/vbyte → bucket index 5 (FeeRateBuckets[5] = 10.0).
    check getBucketIndex(10.0) == 5
    check fe.shortHorizon.buckets[5].totalSeen >= 1.0

  test "G7 BUG-5: bucket boundaries are in sat/vbyte not sat/kvB":
    ## Last bucket is 10000 sat/vbyte = 10,000,000 sat/kvB.  Core last
    ## bucket pre-INF is ~9_500_000 sat/kvB (100 * 1.05^236).  Numbers
    ## happen to be close but the UNITS differ by 1000×.
    check FeeRateBuckets[NumBuckets - 1] == 10000.0  # sat/vbyte
    check FeeRateBuckets[NumBuckets - 1] * 1000.0 == 10_000_000.0  # sat/kvB

# ---------------------------------------------------------------------------
# G8 — validForFeeEstimation 4-flag gating (BUG-7, P1)
# ---------------------------------------------------------------------------
suite "W139 G8 — validForFeeEstimation 4-flag gating (BUG-7, P1)":

  test "G8 BUG-7: no validForFeeEstimation predicate in mempool":
    ## Core: validForFeeEstimation = !mempool_limit_bypassed &&
    ## !submitted_in_package && chainstate_is_current &&
    ## has_no_mempool_parents.  Nimrod tracks none of the four.
    check "validForFeeEstimation" notin mempoolSrc
    check "validForFeeEstimation" notin feesSrc
    check "m_mempool_limit_bypassed" notin mempoolSrc
    check "m_submitted_in_package"  notin mempoolSrc
    check "m_chainstate_is_current" notin mempoolSrc
    check "m_has_no_mempool_parents" notin mempoolSrc

  test "G8 BUG-7: trackTransaction has no gating on ancestor count / IBD":
    ## A tx with mempool parents will still call trackTransaction.
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(2), 5.0, 100)
    check fe.getTrackedCount() == 1

# ---------------------------------------------------------------------------
# G9 — nBestSeenHeight reorg gate (BUG-6, P1)
# ---------------------------------------------------------------------------
suite "W139 G9 — nBestSeenHeight reorg gate (BUG-6, P1)":

  test "G9 BUG-6: FeeEstimator has no nBestSeenHeight field":
    ## Core's CBlockPolicyEstimator declares
    ## `unsigned int nBestSeenHeight GUARDED_BY(m_cs_fee_estimator){0};`.
    ## Nimrod's FeeEstimator object has only shortHorizon/medHorizon/
    ## longHorizon/bucketStats/trackedTxs.
    check "nBestSeenHeight" notin feesSrc
    check "bestSeenHeight"  notin feesSrc

  test "G9 BUG-6: processBlock does not skip on nBlockHeight <= nBestSeenHeight":
    ## Core block_policy_estimator.cpp:673-680 — returns early if
    ## nBlockHeight <= nBestSeenHeight.  Nimrod unconditionally processes.
    let fe = newFeeEstimator()
    # Track 10 distinct txs at the same feerate → bucket 5 (10 sat/vbyte).
    for i in 1 .. 10:
      fe.trackTransaction(makeTxId(100 + i), 10.0, 100)
    let bucketIdx = getBucketIndex(10.0)  # = 5
    let snapBeforeAny = fe.medHorizon.buckets[bucketIdx].totalSeen
    check snapBeforeAny >= 1.0
    # Confirm at height 110 (txs 101-105) — leaves 5 unconfirmed
    fe.processBlock(110'i32, @[makeTxId(101), makeTxId(102),
                                makeTxId(103), makeTxId(104),
                                makeTxId(105)])
    let snapAfterFirst = fe.medHorizon.buckets[bucketIdx].totalSeen
    # Re-process the same block — under Core this would be a no-op
    # (110 <= 110), but nimrod has no reorg gate and will decay AGAIN.
    fe.processBlock(110'i32, @[])  # empty txid set, but decay fires
    let snapAfterSecond = fe.medHorizon.buckets[bucketIdx].totalSeen
    # Second processBlock with same height should be a no-op under
    # Core; nimrod decays totalSeen by MED_DECAY=0.9952 → strict <.
    check snapAfterSecond < snapAfterFirst  # BUG: decay applied twice

# ---------------------------------------------------------------------------
# G10 / G12 — processBlock: record-first, then decay (PRESENT, FIX-49)
# ---------------------------------------------------------------------------
suite "W139 G10/G12 — record-before-decay (PRESENT, FIX-49)":

  test "G10/G12 PRESENT: processBlock records first, then applies decay":
    ## Comment at fees.nim:152-154 documents Core ordering and
    ## FIX-49 closure.
    check "Core order: record confirmed txs FIRST" in feesSrc
    check "Apply decay AFTER recording" in feesSrc

  test "G12 PRESENT: getConfirmationRate ≤ 1.0 after FIX-49":
    ## Pre-FIX-49 ordering allowed totalSeen to decay before
    ## confirmed[i] was incremented → rate > 1.0.  FIX-49 reverses.
    let fe = newFeeEstimator()
    for i in 1 .. 20:
      fe.trackTransaction(makeTxId(i), 5.0, 100)
    fe.processBlock(101'i32, @[makeTxId(1), makeTxId(2), makeTxId(3)])
    let rate = fe.getConfirmationRate(5, 12)
    check rate <= 1.0

# ---------------------------------------------------------------------------
# G11 — Record cumulative loop (BUG-9 partial, P1)
# ---------------------------------------------------------------------------
suite "W139 G11 — Record cumulative loop (BUG-9 partial, P1)":

  test "G11 BUG-9: only ONE period slot is incremented, not cumulative":
    ## Core block_policy_estimator.cpp:222-226 increments confAvg[i] for
    ## ALL i >= periodsToConfirm.  Nimrod's processBlock only writes one
    ## slot (the period the tx happens to land in).  Functionally
    ## equivalent when summed at query time, but means the storage model
    ## is single-slot not cumulative — won't match Core's
    ## fee_estimates.dat byte-for-byte.
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(105'i32, @[makeTxId(1)])  # 5 blocks → MED period 2
    let bucketIdx = getBucketIndex(10.0)  # = 5
    # MED scale = 2, so period = (5-1)/2 = 2.  Only slot 2 is set.
    # Core would set slots 2..23 (all periods >= 2).
    check fe.medHorizon.buckets[bucketIdx].totalConfirmed[2] >= 0.99  # 1 decayed
    # Core would have ≥1 in slot 23 too — nimrod has 0:
    check fe.medHorizon.buckets[bucketIdx].totalConfirmed[23] == 0.0  # BUG-9

# ---------------------------------------------------------------------------
# G13 — unconfTxs circular buffer absent (BUG-3, P1)
# ---------------------------------------------------------------------------
suite "W139 G13 — unconfTxs circular buffer (BUG-3, P1)":

  test "G13 BUG-3: no unconfTxs field on FeeEstimator or HorizonStats":
    ## Core block_policy_estimator.cpp:113-115 declares
    ## `std::vector<std::vector<int>> unconfTxs;` and
    ## `std::vector<int> oldUnconfTxs;`.
    check "unconfTxs"    notin feesSrc
    check "oldUnconfTxs" notin feesSrc

  test "G13 BUG-3: no ClearCurrent circular-buffer roll":
    ## Core block_policy_estimator.cpp:208-214 rolls the circular buffer
    ## `unconfTxs[nBlockHeight % unconfTxs.size()][j] = 0;`.
    check "ClearCurrent" notin feesSrc
    check "clearCurrent" notin feesSrc

  test "G13 BUG-3: no inMempool inflation in getConfirmationRate":
    ## Core EstimateMedianVal (block_policy_estimator.cpp:290-292) adds
    ## extraNum (in-mempool txs still unconfirmed for >= confTarget)
    ## to the denominator.  Nimrod ignores the in-mempool backlog.
    check "extraNum" notin feesSrc
    check "inMempool" notin feesSrc

# ---------------------------------------------------------------------------
# G14 — failAvg eviction-failure accounting absent (BUG-4, P1)
# ---------------------------------------------------------------------------
suite "W139 G14 — failAvg eviction-failure accounting (BUG-4, P1)":

  test "G14 BUG-4: no failAvg field on BucketStats or HorizonStats":
    ## Core block_policy_estimator.cpp:96-97 — `std::vector<std::vector<
    ## double>> failAvg;`.  Tracks moving average of evicted-without-
    ## confirmation tx count per (Y periods, X buckets).
    check "failAvg" notin feesSrc
    check "failAverage" notin feesSrc

  test "G14 BUG-4: removeTransaction doesn't increment any failure counter":
    ## Core block_policy_estimator.cpp:513-519 — `failAvg[i][bucketindex]
    ## ++` for i = 0..periodsAgo.  Nimrod's removeTransaction only
    ## decrements totalSeen / feeRateSum.
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(99), 10.0, 100)
    let bucketIdx = getBucketIndex(10.0)  # = 5
    let seenBefore = fe.medHorizon.buckets[bucketIdx].totalSeen
    check seenBefore >= 1.0
    fe.removeTransaction(makeTxId(99))
    let seenAfter = fe.medHorizon.buckets[bucketIdx].totalSeen
    # totalSeen decremented:
    check seenAfter < seenBefore
    # But there's no failAvg counter to verify failure-was-recorded.
    # The closest proxy: if a failAvg field existed, a future fix would
    # show it non-zero here.  We can only check the gap exists.
    check "failAvg" notin feesSrc

# ---------------------------------------------------------------------------
# G15 — trackedTxs / untrackedTxs counters absent (BUG-19, P3)
# ---------------------------------------------------------------------------
suite "W139 G15 — trackedTxs/untrackedTxs counters (BUG-19, P3)":

  test "G15 BUG-19: no trackedTxs/untrackedTxs uint counters":
    ## Core block_policy_estimator.h:298-299 — `unsigned int trackedTxs
    ## {0}; unsigned int untrackedTxs{0};`.  Reset per-block at end of
    ## processBlock.  Nimrod has `trackedTxs*: Table[TxId, TrackedTx]`
    ## (the unconfirmed-tx map, NOT a counter).
    ## We check that the COUNTER form is absent.
    check "trackedTxs*: uint" notin feesSrc
    check "untrackedTxs" notin feesSrc

  test "G15 BUG-19: no per-block debug log of tracked/untracked":
    ## Core block_policy_estimator.cpp:710-712 LogDebug with
    ## `countedTxs of trackedTxs of trackedTxs + untrackedTxs`.
    check "Blockpolicy estimates updated by" notin feesSrc

# ---------------------------------------------------------------------------
# G16 — sufficientTxVal bucket-grouping (BUG-15, P2)
# ---------------------------------------------------------------------------
suite "W139 G16 — sufficientTxVal bucket grouping (BUG-15, P2)":

  test "G16 BUG-15: no partialNum / sufficientTxVal scan in estimateFee":
    ## Core EstimateMedianVal (block_policy_estimator.cpp:267-303)
    ## combines adjacent buckets until partialNum >= sufficientTxVal /
    ## (1 - decay).  Nimrod's estimateFeeForHorizon (mining/fees.nim:225)
    ## scans single buckets only.
    check "partialNum"      notin feesSrc
    check "sufficientTxVal" notin feesSrc
    check "SUFFICIENT_FEETXS"    notin feesSrc
    check "SUFFICIENT_TXS_SHORT" notin feesSrc

  test "G16 BUG-15: estimator scans low→high not Core's high→low":
    ## Core block_policy_estimator.cpp:280 — `for (int bucket =
    ## maxbucketindex; bucket >= 0; --bucket)`.  Nimrod
    ## mining/fees.nim:235 — `for i in 0 ..< NumBuckets:`.
    ## Note: low→high vs high→low changes which bucket "wins" when
    ## multiple buckets meet the threshold.  Core wins HIGHEST passing
    ## bucket then continues until failure — nimrod wins LOWEST passing
    ## bucket.  Both report "lowest acceptable" but via different walks.
    check "for i in 0..<NumBuckets:" in feesSrc
    check "countdown(NumBuckets - 1" in feesSrc  # only used as fallback

# ---------------------------------------------------------------------------
# G17 — median-of-pass-bucket via txCtAvg midpoint (PARTIAL)
# ---------------------------------------------------------------------------
suite "W139 G17 — median selection (PARTIAL)":

  test "G17 PARTIAL: nimrod returns avgFeeRate directly instead of median walk":
    ## Core block_policy_estimator.cpp:344-369 walks txCtAvg cumulative
    ## sum to find the median feerate within the passing bucket range.
    ## Nimrod returns `avgFeeRate` of the first passing bucket
    ## (mining/fees.nim:239 `return hs.buckets[i].avgFeeRate`).
    ## Behaviour matches when only ONE bucket is in the passing group;
    ## diverges when multiple buckets were combined (which nimrod never
    ## does — BUG-15).
    check "hs.buckets[i].avgFeeRate" in feesSrc
    check "txSum / 2" notin feesSrc  # Core's median midpoint marker

# ---------------------------------------------------------------------------
# G18 — confTarget=1 → 2 clamp (BUG-13, P2)
# ---------------------------------------------------------------------------
suite "W139 G18 — confTarget=1→2 clamp (BUG-13, P2)":

  test "G18 BUG-13: handleEstimateSmartFee does not rewrite confTarget=1→2":
    ## Core block_policy_estimator.cpp:890 — `if (confTarget == 1)
    ## confTarget = 2;`.  Nimrod allows confTarget=1 and tries to
    ## estimate, returning FallbackFeeRate on no-data.
    let smartFeeStart = serverSrc.find("proc handleEstimateSmartFee")
    let smartFeeBlock = serverSrc[smartFeeStart .. smartFeeStart + 1500]
    check "if confTarget == 1: confTarget = 2" notin smartFeeBlock
    check "confTarget = 2"                     notin smartFeeBlock

# ---------------------------------------------------------------------------
# G19 — MaxUsableEstimate clamp (BUG-14, P2)
# ---------------------------------------------------------------------------
suite "W139 G19 — MaxUsableEstimate clamp (BUG-14, P2)":

  test "G19 BUG-14: no MaxUsableEstimate / BlockSpan / HistoricalBlockSpan":
    ## Core block_policy_estimator.cpp:780-802.  Caps confTarget to
    ## min(longMax, max(blockSpan, historicalBlockSpan) / 2).
    check "MaxUsableEstimate" notin feesSrc
    check "BlockSpan" notin feesSrc
    check "HistoricalBlockSpan" notin feesSrc

  test "G19 BUG-14: no firstRecordedHeight / historicalFirst / historicalBest":
    check "firstRecordedHeight" notin feesSrc
    check "historicalFirst"     notin feesSrc
    check "historicalBest"      notin feesSrc

# ---------------------------------------------------------------------------
# G20 — estimateSmartFee three-way max-merge (BUG-9, P1)
# ---------------------------------------------------------------------------
suite "W139 G20 — estimateSmartFee three-way max-merge (BUG-9, P1)":

  test "G20 BUG-9: no HALF_SUCCESS_PCT / SUCCESS_PCT / DOUBLE_SUCCESS_PCT":
    ## Core block_policy_estimator.cpp:170-174.  Nimrod has a single
    ## `ConfirmationThreshold = 0.85` constant which matches
    ## SUCCESS_PCT but not the other two thresholds needed for the
    ## half/full/double max-merge.
    check "HALF_SUCCESS_PCT"   notin feesSrc
    check "DOUBLE_SUCCESS_PCT" notin feesSrc
    check "0.6"  notin feesSrc  # HALF_SUCCESS_PCT
    check "0.95" notin feesSrc  # DOUBLE_SUCCESS_PCT
    check abs(ConfirmationThreshold - CORE_SUCCESS_PCT) < 0.0001

  test "G20 BUG-9: no estimateCombinedFee multi-horizon dispatcher":
    ## Core block_policy_estimator.cpp:808-842.  Nimrod's
    ## estimateFee dispatches to ONE of three horizons and returns
    ## the single answer.
    check "estimateCombinedFee" notin feesSrc

# ---------------------------------------------------------------------------
# G21 — estimateConservativeFee (BUG-16, P2)
# ---------------------------------------------------------------------------
suite "W139 G21 — estimateConservativeFee (BUG-16, P2)":

  test "G21 BUG-16: no estimateConservativeFee proc":
    ## Core block_policy_estimator.cpp:847-862.  Takes MED + LONG at
    ## 2*target with DOUBLE_SUCCESS_PCT and returns the max.
    check "estimateConservativeFee" notin feesSrc
    check "conservativeFee" notin feesSrc

# ---------------------------------------------------------------------------
# G22 — conservative parameter routed through (BUG-10, P2)
# ---------------------------------------------------------------------------
suite "W139 G22 — conservative mode (BUG-10, P2)":

  test "G22 BUG-10: handleEstimateSmartFee ignores estimate_mode parameter":
    ## Core rpc/fees.cpp:42-43 + 73-74 + 80 — parses estimate_mode and
    ## passes conservative=true to estimateSmartFee.  Nimrod's
    ## handler reads only params[0].
    let smartFeeStart = serverSrc.find("proc handleEstimateSmartFee")
    let smartFeeBlock = serverSrc[smartFeeStart .. smartFeeStart + 1500]
    check "estimate_mode" notin smartFeeBlock
    check "FeeEstimateMode" notin smartFeeBlock
    check "conservative" notin smartFeeBlock

  test "G22 BUG-10: help string lists estimate_mode but handler is dead-arg":
    ## server.nim:4574 — `"estimatesmartfee conf_target ( \"estimate_mode\" )"`.
    ## Help advertises a parameter that the handler ignores.
    check "estimatesmartfee conf_target ( \\\"estimate_mode\\\" )" in serverSrc

# ---------------------------------------------------------------------------
# G23 — mempool-min / relay-floor + returnedTarget (BUG-11 + BUG-12, P2)
# ---------------------------------------------------------------------------
suite "W139 G23 — feerate floor + returnedTarget (BUG-11 + BUG-12, P2)":

  test "G23 BUG-12: handleEstimateSmartFee does not floor by mempool min + relay min":
    ## Core rpc/fees.cpp:83-85 — `feeRate = std::max({feeRate,
    ## min_mempool_feerate, min_relay_feerate});`.
    let smartFeeStart = serverSrc.find("proc handleEstimateSmartFee")
    let smartFeeBlock = serverSrc[smartFeeStart .. smartFeeStart + 1500]
    check "getMinFee" notin smartFeeBlock
    check "min_relay_feerate" notin smartFeeBlock
    check "mempool.getMinFee" notin smartFeeBlock

  test "G23 BUG-11: handleEstimateSmartFee returns confTarget unchanged in blocks":
    ## Core rpc/fees.cpp:91 — `result.pushKV("blocks",
    ## feeCalc.returnedTarget);`.  Nimrod server.nim:4194 returns
    ## `"blocks": confTarget` verbatim (no clamp tracking).
    let smartFeeStart = serverSrc.find("proc handleEstimateSmartFee")
    let smartFeeBlock = serverSrc[smartFeeStart .. smartFeeStart + 1500]
    check "\"blocks\": confTarget" in smartFeeBlock
    check "returnedTarget" notin smartFeeBlock

# ---------------------------------------------------------------------------
# G24 — FeeReason enum (BUG-18, P3)
# ---------------------------------------------------------------------------
suite "W139 G24 — FeeReason enum (BUG-18, P3)":

  test "G24 BUG-18: no FeeReason enum or string formatter":
    ## Core block_policy_estimator.h:59-68 declares FeeReason enum
    ## (HALF/FULL/DOUBLE/CONSERVATIVE/MEMPOOL_MIN/FALLBACK/REQUIRED).
    ## util/fees.cpp::StringForFeeReason maps to wire strings.
    check "FeeReason" notin feesSrc
    check "FeeReason" notin serverSrc
    check "StringForFeeReason" notin feesSrc
    check "HALF_ESTIMATE" notin feesSrc

  test "G24 BUG-18: no FeeCalculation struct surfaced via RPC":
    check "FeeCalculation" notin feesSrc
    check "feeCalc" notin serverSrc

# ---------------------------------------------------------------------------
# G25 — Binary fees-file v309900 codec (BUG-1 + BUG-20, P1 + P3)
# ---------------------------------------------------------------------------
suite "W139 G25 — fees-file binary v309900 codec (BUG-1 + BUG-20, P1/P3)":

  test "G25 BUG-1: saveFeeEstimates writes JSON, not Core's binary v309900":
    ## Core block_policy_estimator.cpp:978-1000 writes a binary stream
    ## starting with `int CURRENT_FEES_FILE_VERSION = 309900`.  Nimrod
    ## writes JSON ($state).
    check "writeFile(tmpPath, $state)" in feesSrc
    check "309900" notin feesSrc
    check "EncodedDouble" notin feesSrc

  test "G25 BUG-1: nimrod's v2 JSON is non-interoperable with Core .dat":
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 5.0, 100)
    let (file, path) = createTempFile("nimrod_fee_", ".json")
    file.close()
    fe.saveFeeEstimates(path)
    let contents = readFile(path)
    removeFile(path)
    # Pure JSON, not binary:
    check contents[0] == '{'
    # version 2, not 309900:
    let parsed = parseJson(contents)
    check parsed["version"].getInt() == 2

  test "G25 BUG-20: persistence file has no nBestSeenHeight / historical range":
    ## Core writes nBestSeenHeight + (firstRecordedHeight | historicalFirst)
    ## + (nBestSeenHeight | historicalBest) before bucket data.  Nimrod's
    ## JSON v2 has only `version`, `numBuckets`, `short`, `medium`, `long`.
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 5.0, 100)
    let (file, path) = createTempFile("nimrod_fee_", ".json")
    file.close()
    fe.saveFeeEstimates(path)
    let contents = readFile(path)
    removeFile(path)
    check "nBestSeenHeight" notin contents
    check "firstRecordedHeight" notin contents
    check "historicalFirst" notin contents
    check "historicalBest" notin contents

# ---------------------------------------------------------------------------
# G26 — MAX_FILE_AGE=60h stale-file gate (BUG-2, P1)
# ---------------------------------------------------------------------------
suite "W139 G26 — MAX_FILE_AGE 60h stale-file gate (BUG-2, P1)":

  test "G26 BUG-2: loadFeeEstimates does not check file age":
    ## Core block_policy_estimator.cpp:567-572 — refuses to load when
    ## file_age > MAX_FILE_AGE (60h) AND !read_stale_estimates.
    check "MAX_FILE_AGE" notin feesSrc
    check "getLastModificationTime" notin feesSrc
    check "60" notin feesSrc  # 60-hour threshold
    check "DEFAULT_ACCEPT_STALE_FEE_ESTIMATES" notin feesSrc

  test "G26 BUG-2: a 6-month-old fee_estimates.json would be loaded verbatim":
    let fe = newFeeEstimator()
    let (file, path) = createTempFile("nimrod_fee_stale_", ".json")
    file.close()
    fe.trackTransaction(makeTxId(7), 10.0, 100)
    let bucketIdx = getBucketIndex(10.0)  # = 5
    check fe.medHorizon.buckets[bucketIdx].totalSeen >= 1.0
    fe.saveFeeEstimates(path)
    # Backdate the file 6 months — no age check means this still loads.
    let oldTime = getTime() + initDuration(days = -180)
    setLastModificationTime(path, oldTime)
    let fe2 = newFeeEstimator()
    fe2.loadFeeEstimates(path)
    # buckets[bucketIdx] should have non-zero data because age was not checked.
    check fe2.medHorizon.buckets[bucketIdx].totalSeen > 0.0
    removeFile(path)

# ---------------------------------------------------------------------------
# G27 — periodic flush (covered by W114 BUG-16 — not duplicated in W139)
# ---------------------------------------------------------------------------
suite "W139 G27 — periodic flush 1h (cross-reference W114 BUG-16)":

  test "G27 cross-ref: FEE_FLUSH_INTERVAL constant absent":
    ## W114 BUG-16 already catalogues this.  W139 just confirms it's
    ## still missing.
    check "FEE_FLUSH_INTERVAL" notin feesSrc
    check "FlushFeeEstimates"  notin feesSrc
    check "flushFeeEstimates"  notin feesSrc

# ---------------------------------------------------------------------------
# G28 — FlushUnconfirmed on shutdown (BUG-21, P3)
# ---------------------------------------------------------------------------
suite "W139 G28 — FlushUnconfirmed on shutdown (BUG-21, P3)":

  test "G28 BUG-21: no FlushUnconfirmed proc on FeeEstimator":
    ## Core block_policy_estimator.cpp:1064-1076 — removes every
    ## mapMemPoolTxs entry (records as failure-to-confirm).
    check "FlushUnconfirmed" notin feesSrc
    check "flushUnconfirmed" notin feesSrc

  test "G28 BUG-21: shutdown in nimrod.nim calls saveFeeEstimates but no flush":
    ## src/nimrod.nim:1481-1485 — saveFeeEstimates is called on shutdown
    ## but the trackedTxs table is simply discarded.
    check "saveFeeEstimates" in nimrodSrc
    check "flushUnconfirmed" notin nimrodSrc
    check "FlushUnconfirmed" notin nimrodSrc

# ---------------------------------------------------------------------------
# G29 — FeeFilterRounder (BUG-17, P2)
# ---------------------------------------------------------------------------
suite "W139 G29 — FeeFilterRounder (BUG-17, P2)":

  test "G29 BUG-17: no FeeFilterRounder class / MakeFeeSet helper":
    ## Core block_policy_estimator.h:323-344 declares FeeFilterRounder
    ## with MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1 (NOT 1.05).
    check "FeeFilterRounder" notin feesSrc
    check "MakeFeeSet" notin feesSrc
    check "FEE_FILTER_SPACING" notin feesSrc

  test "G29 BUG-17: 2/3-down randomised quantisation absent":
    ## Core block_policy_estimator.cpp:1109-1118 — `rand32() % 3 != 0`
    ## decision to round down to next-lower set boundary.
    check "rand32() % 3" notin feesSrc
    check "fee_set.lower_bound" notin feesSrc

# ---------------------------------------------------------------------------
# Source-level pinning — overall structure
# ---------------------------------------------------------------------------
suite "W139 source pinning":

  test "fees.nim still imports tables / math / json / os":
    check "import std/[tables, math, json, os]" in feesSrc

  test "FeeEstimator object still has three-horizon fields":
    check "shortHorizon*: HorizonStats" in feesSrc
    check "medHorizon*:   HorizonStats" in feesSrc
    check "longHorizon*:  HorizonStats" in feesSrc

  test "estimateFee dispatches by max-target threshold":
    check "if target <= SHORT_MAX_TARGET:" in feesSrc
    check "elif target <= MED_MAX_TARGET:" in feesSrc
    check "estimateFeeForHorizon(fe.longHorizon, target)" in feesSrc

  test "FallbackFeeRate constant exists":
    check "FallbackFeeRate" in feesSrc
    check FallbackFeeRate == 10.0  # sat/vbyte fallback

  test "W139 audit doc exists":
    check fileExists("audit/w139_fee_estimation.md")

# ---------------------------------------------------------------------------
# Forward-regression guard — if any future FIX wave lands without
# matching a W139 BUG, the gate above will fail loudly.
# ---------------------------------------------------------------------------
suite "W139 forward-regression sentinels":

  test "sentinel: trackTransaction call site unchanged":
    ## If a future FIX-86 rewires trackTransaction to take more args
    ## (e.g. a `validForFeeEstimation` flag), the call site changes
    ## and this assertion fires.
    check "trackTransaction(txid, feeRate, mp.chainState.bestHeight)" in mempoolSrc

  test "sentinel: processBlock signature unchanged":
    check "proc processBlock*(fe: FeeEstimator, height: int32," in feesSrc

  test "sentinel: handleEstimateSmartFee returns 2-key JSON":
    let smartFeeStart = serverSrc.find("proc handleEstimateSmartFee")
    let smartFeeBlock = serverSrc[smartFeeStart .. smartFeeStart + 2000]
    check "\"feerate\": feeBtcPerKb," in smartFeeBlock
    check "\"blocks\": confTarget"     in smartFeeBlock
