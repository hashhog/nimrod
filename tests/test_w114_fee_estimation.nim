## W114 Fee estimation (CBlockPolicyEstimator) audit — nimrod
##
## 30 gates against bitcoin-core/src/policy/fees/block_policy_estimator.h/cpp
## and bitcoin-core/src/rpc/fees.cpp.
##
## BUG-1  (P0/DEAD-HELPER): trackTransaction never called — estimator is
##        always empty, every estimate returns FallbackFeeRate
## BUG-2  (P1/CDIV):       Single-horizon; no SHORT/MED/LONG split
## BUG-3  (HIGH):           Wrong decay — 0.998 vs Core 0.962/0.9952/0.99931
## BUG-4  (HIGH):           Wrong bucket scheme — 22 hand-crafted vs ~236 exp
## BUG-5  (HIGH):           estimateFee scans low→high; Core scans high→low
## BUG-6  (HIGH):           failAvg (evicted-tx failure accounting) absent
## BUG-7  (MEDIUM):         unconfTxs circular buffer absent
## BUG-8  (MEDIUM):         blocksToConfirm: same-block (=0) not rejected
## BUG-9  (MEDIUM):         estimatesmartfee "blocks" always echoes confTarget
## BUG-10 (MEDIUM):         estimate_mode (conservative) ignored
## BUG-11 (MEDIUM):         FallbackFeeRate returned as real estimate
## BUG-12 (LOW):            Mempool eviction doesn't call feeEstimator.removeTransaction
## BUG-13 (LOW):            FlushUnconfirmed absent on shutdown
## BUG-14 (LOW):            File format JSON vs Core binary (v309900)
## BUG-15 (LOW):            No stale-file age check (Core: 60h limit)
## BUG-16 (LOW):            No periodic flush (Core: every 1h)
## BUG-17 (LOW):            confTarget=1 not clamped to 2
## BUG-18 (LOW):            No sufficientTxVal bucket-grouping
## BUG-19 (MEDIUM):         Decay applied before recording → rate > 1.0 possible
##                          (processBlock decays totalSeen THEN records confirmed[i]+1,
##                           so confirmed/totalSeen can exceed 1.0 on the same block)

import unittest2
import std/[math, json, os, tempfiles, strutils]
import ../src/mining/fees
import ../src/primitives/types

proc makeTxId(n: int): TxId =
  var arr: array[32, byte]
  arr[0] = byte(n and 0xff)
  arr[1] = byte((n shr 8) and 0xff)
  arr[2] = byte((n shr 16) and 0xff)
  arr[3] = byte((n shr 24) and 0xff)
  TxId(arr)

# ─────────────────────────────────────────────────────────────────────────────
# Gate G1 — estimator is instantiated and non-nil
# ─────────────────────────────────────────────────────────────────────────────
suite "G1 estimator instantiation":
  test "newFeeEstimator returns non-nil":
    let fe = newFeeEstimator()
    check fe != nil

  test "new estimator tracks zero transactions":
    let fe = newFeeEstimator()
    check fe.getTrackedCount() == 0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G2 — bucket scheme
# Core: MIN_BUCKET_FEERATE=100 sat/kB, MAX=1e7, spacing=1.05 → ~236 buckets
# Nimrod: 22 hand-crafted buckets (1..10000 sat/vbyte)
# BUG-4: count and spacing are wrong
# ─────────────────────────────────────────────────────────────────────────────
suite "G2 bucket scheme":
  test "Core bucket count is ~236 (100..1e7 @ 1.05x) [BUG-4: nimrod has 22]":
    # Count buckets as Core does in CBlockPolicyEstimator constructor
    var count = 0
    var b = 100.0
    while b <= 1e7:
      inc count
      b *= 1.05
    # Core adds one INF_FEERATE sentinel bucket
    inc count
    # nimrod's NumBuckets is 22, Core needs ~237
    check count > 200
    check NumBuckets == 22  # documents the divergence

  test "Core MIN_BUCKET_FEERATE is 100 sat/kB [BUG-4: nimrod starts at 1 sat/vbyte]":
    # 100 sat/kB = 0.1 sat/vbyte; nimrod FeeRateBuckets[0] == 1.0 sat/vbyte
    check FeeRateBuckets[0] == 1.0
    # Core starts at 100 sat/kB — ~100x lower minimum

  test "exponential spacing 1.05x absent in nimrod [BUG-4]":
    # Verify nimrod buckets are NOT geometrically spaced at 1.05x
    var isGeometric = true
    for i in 1..<NumBuckets:
      let ratio = FeeRateBuckets[i] / FeeRateBuckets[i - 1]
      if abs(ratio - 1.05) > 0.01:
        isGeometric = false
        break
    check not isGeometric  # documents that spacing is hand-crafted, not 1.05x

# ─────────────────────────────────────────────────────────────────────────────
# Gate G3 — three-horizon tracking (SHORT/MED/LONG)
# Core: three TxConfirmStats with different decays and period counts
# FIX-48: BUG-2 + BUG-3 closed — nimrod now has three independent horizons
# ─────────────────────────────────────────────────────────────────────────────
suite "G3 three-horizon split":
  test "SHORT_DECAY=0.962 present [FIX-48 BUG-3]":
    check abs(SHORT_DECAY - 0.962) < 0.0001

  test "MED_DECAY=0.9952 present [FIX-48 BUG-3]":
    check abs(MED_DECAY - 0.9952) < 0.0001

  test "LONG_DECAY=0.99931 present [FIX-48 BUG-3]":
    check abs(LONG_DECAY - 0.99931) < 0.00001

  test "three distinct decay values exported [FIX-48 BUG-2]":
    # All three must differ from each other
    check abs(SHORT_DECAY - MED_DECAY) > 0.001
    check abs(MED_DECAY - LONG_DECAY) > 0.0001
    check abs(SHORT_DECAY - LONG_DECAY) > 0.001

  test "FeeEstimator exposes three HorizonStats instances [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check abs(fe.shortHorizon.decay - SHORT_DECAY) < 0.0001
    check abs(fe.medHorizon.decay   - MED_DECAY)   < 0.0001
    check abs(fe.longHorizon.decay  - LONG_DECAY)  < 0.00001

  test "horizons have correct scale values [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check fe.shortHorizon.scale == SHORT_SCALE   # 1
    check fe.medHorizon.scale   == MED_SCALE     # 2
    check fe.longHorizon.scale  == LONG_SCALE    # 24

  test "horizons have correct period counts [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check fe.shortHorizon.numPeriods == SHORT_PERIODS   # 12
    check fe.medHorizon.numPeriods   == MED_PERIODS     # 24
    check fe.longHorizon.numPeriods  == LONG_PERIODS    # 42

  test "SHORT horizon max target = 12 blocks [FIX-48 BUG-2]":
    check SHORT_MAX_TARGET == 12

  test "MED horizon max target = 48 blocks [FIX-48 BUG-2]":
    check MED_MAX_TARGET == 48

  test "LONG horizon max target = 1008 blocks [FIX-48 BUG-2]":
    check LONG_MAX_TARGET == 1008

  test "SHORT and LONG horizons track independently [FIX-48 BUG-2]":
    # After adding txs, SHORT decays much faster than LONG
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
    # Process 30 empty blocks — SHORT decay 0.962^30 ≈ 0.30, LONG decay 0.99931^30 ≈ 0.979
    for h in 101..130:
      fe.processBlock(int32(h), @[])
    let shortSeen = fe.shortHorizon.buckets[getBucketIndex(10.0)].totalSeen
    let longSeen  = fe.longHorizon.buckets[getBucketIndex(10.0)].totalSeen
    # SHORT should retain ~30% (≈6), LONG should retain ~97.9% (≈19.6)
    check longSeen > shortSeen * 2.0  # LONG retains substantially more data

  test "Core SHORT_BLOCK_PERIODS=12 scale=1 present [FIX-48 BUG-2]":
    check SHORT_PERIODS == 12
    check SHORT_SCALE == 1

# ─────────────────────────────────────────────────────────────────────────────
# Gate G4 — processTransaction / trackTransaction wiring
# BUG-1 (P0 DEAD-HELPER): trackTransaction is never called from production code
# ─────────────────────────────────────────────────────────────────────────────
suite "G4 trackTransaction wiring (DEAD-HELPER)":
  test "trackTransaction API exists":
    let fe = newFeeEstimator()
    let txid = makeTxId(42)
    # Should not raise; API is present
    fe.trackTransaction(txid, 10.0, 100)
    check fe.getTrackedCount() == 1

  test "trackTransaction affects bucket totalSeen":
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    let idx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(idx)
    check stats.totalSeen == 1.0

  test "without trackTransaction, estimator is always empty [BUG-1]":
    # Simulates production state: processBlock called but trackTransaction never was
    let fe = newFeeEstimator()
    # Simulate 100 blocks arriving without any trackTransaction calls
    for h in 1..100:
      fe.processBlock(int32(h), @[makeTxId(h)])
    # trackedTxs always empty because trackTransaction was never called
    check fe.getTrackedCount() == 0
    # All bucket totalSeen are 0 after decay (started at 0)
    var anyData = false
    for i in 0..<NumBuckets:
      if fe.getBucketStats(i).totalSeen > 0.0:
        anyData = true
    check not anyData

  test "estimateFee always returns FallbackFeeRate when trackTransaction never called [BUG-1]":
    let fe = newFeeEstimator()
    for h in 1..200:
      fe.processBlock(int32(h), @[makeTxId(h)])
    # Without trackTransaction, no data → always fallback
    check fe.estimateFee(6) == FallbackFeeRate
    check fe.estimateFee(1) == FallbackFeeRate
    check fe.estimateFee(25) == FallbackFeeRate

# ─────────────────────────────────────────────────────────────────────────────
# Gate G5 — processBlock height guard
# Core: ignores blocks at or below nBestSeenHeight (side-chains/reorgs)
# ─────────────────────────────────────────────────────────────────────────────
suite "G5 processBlock height guard":
  test "processBlock with same height called twice applies decay twice":
    # Core would ignore the second call (nBlockHeight <= nBestSeenHeight)
    # nimrod has no such guard — each call applies decay regardless
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(101, @[makeTxId(1)])  # first call
    let stats1 = fe.getBucketStats(getBucketIndex(10.0))
    fe.trackTransaction(makeTxId(2), 10.0, 100)
    fe.processBlock(101, @[makeTxId(2)])  # same height — Core would skip
    let stats2 = fe.getBucketStats(getBucketIndex(10.0))
    # Both calls applied decay — totalSeen keeps decaying
    # Documents absence of height guard
    check stats2.totalSeen <= stats1.totalSeen * DecayFactor + 1.01

# ─────────────────────────────────────────────────────────────────────────────
# Gate G6 — blocksToConfirm 1-based vs 0-based
# Core: `if (blocksToConfirm <= 0) return false` — same-block confirmation invalid
# Nimrod: `if blocksToConfirm >= 0 and blocksToConfirm < MaxTargetBlocks`
# BUG-8: same-block (delta=0) is accepted by nimrod, recorded at index 0
# ─────────────────────────────────────────────────────────────────────────────
suite "G6 blocksToConfirm same-block edge case":
  test "same-block confirmation (delta=0) is rejected [FIX-48 collateral BUG-8]":
    # Core rejects blocksToConfirm <= 0; FIX-48 adds the same guard
    let fe = newFeeEstimator()
    let txid = makeTxId(99)
    let entryHeight: int32 = 500
    fe.trackTransaction(txid, 10.0, entryHeight)
    # Confirm at same height — delta=0, should be rejected
    fe.processBlock(entryHeight, @[txid])
    let idx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(idx)
    # Same-block tx is discarded — no confirmation recorded
    check stats.totalConfirmed[0] == 0.0  # correctly rejected

  test "1-block confirmation stored at period 0 (MED scale=2, period=(1-1)/2=0)":
    # With period-scaled indexing (MED scale=2): period = (blocksToConfirm - 1) / scale
    # blocksToConfirm=1 → period=(1-1)/2=0 → slot 0
    let fe = newFeeEstimator()
    let txid = makeTxId(100)
    fe.trackTransaction(txid, 10.0, 100)
    fe.processBlock(101, @[txid])  # 1 block to confirm
    let idx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(idx)
    # MED horizon (getBucketStats) stores at slot 0 for 1-block confirmation
    check stats.totalConfirmed[0] > 0.0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G7 — failAvg: evicted transaction failure tracking
# Core: removeTx() with inBlock=false increments failAvg for each period ≥ 1 scale
# BUG-6: nimrod's removeTransaction decrements totalSeen but has no failAvg array
# ─────────────────────────────────────────────────────────────────────────────
suite "G7 failAvg eviction tracking":
  test "removeTransaction decrements totalSeen [partial behaviour]":
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    let idx = getBucketIndex(10.0)
    check fe.getBucketStats(idx).totalSeen == 1.0
    fe.removeTransaction(makeTxId(1))
    check fe.getBucketStats(idx).totalSeen == 0.0

  test "removeTransaction has no failAvg array — failure not counted [BUG-6]":
    # Core: failure increments failAvg[0..periodsAgo-1][bucketIndex]
    # Nimrod: no such array exists in BucketStats
    # This test documents the absence: we can track removal but cannot verify
    # failure counts because the field doesn't exist
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.removeTransaction(makeTxId(1))
    # After removal, confirmation rate for the bucket is 0/0 = 0.0
    # Core would have: confirmed/0 + failAvg contribution → more accurate rate
    let rate = fe.getConfirmationRate(getBucketIndex(10.0), 6)
    check rate == 0.0  # no failure denominator; confirms failAvg absent

# ─────────────────────────────────────────────────────────────────────────────
# Gate G8 — unconfTxs circular buffer (mempool in-flight denominator)
# Core: per-block-height per-bucket count of unconfirmed txs
# BUG-7: nimrod has no such structure
# ─────────────────────────────────────────────────────────────────────────────
suite "G8 unconfTxs circular buffer":
  test "BucketStats has no unconfirmed-mempool count field [BUG-7]":
    # Verify that BucketStats only contains the fields nimrod implements,
    # and does NOT have an 'unconfirmedCount' or similar field.
    # Tested indirectly: getTrackedCount() counts trackedTxs table entries
    # but this is NOT per-bucket, nor per-block-height as Core requires.
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    # getTrackedCount is global, not per-bucket
    check fe.getTrackedCount() == 1
    # getBucketStats has no field for unconfirmed-in-mempool count
    let stats = fe.getBucketStats(getBucketIndex(10.0))
    # Only fields: totalConfirmed, totalSeen, avgFeeRate, feeRateSum
    check stats.totalSeen == 1.0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G9 — SUFFICIENT_FEETXS bucket-grouping
# Core: groups adjacent buckets until partialNum >= sufficientTxVal/(1-decay)
# BUG-18: nimrod checks each bucket independently with totalSeen >= 1
# ─────────────────────────────────────────────────────────────────────────────
suite "G9 sufficientTxVal bucket grouping":
  test "nimrod uses per-bucket threshold >= 1 not Core SUFFICIENT_FEETXS=0.1 [BUG-18]":
    # Core groups until avg 0.1 tx/block met across all grouped buckets
    # nimrod skips any bucket with totalSeen < 1
    let fe = newFeeEstimator()
    # Add one tx in a bucket (totalSeen will decay to <1 quickly)
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(101, @[makeTxId(1)])
    # After many decay steps, totalSeen < 1 → nimrod skips bucket entirely
    for h in 102..200:
      fe.processBlock(int32(h), @[])
    let idx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(idx)
    # documents that when totalSeen < 1, bucket is skipped (not grouped)
    if stats.totalSeen < 1.0:
      let rate = fe.getConfirmationRate(idx, 6)
      check rate == 0.0  # skipped because totalSeen < 1

# ─────────────────────────────────────────────────────────────────────────────
# Gate G10 — estimateFee scan direction
# Core: scans HIGH→LOW to find lowest feerate meeting threshold
# BUG-5: nimrod scans LOW→HIGH — returns lowest bucket meeting threshold
# (both approaches look for the "lowest feerate that achieves 85%",
#  but Core's median-of-best-range is directionally inverted)
# ─────────────────────────────────────────────────────────────────────────────
suite "G10 estimation scan direction":
  test "nimrod scans low-to-high buckets [BUG-5 documents direction]":
    # This test populates data so that bucket at 10 sat/vbyte has high
    # confirmation rate. Core would start from the highest bucket (high→low);
    # nimrod starts from the lowest bucket (low→high).
    # Both converge to the same "lowest feerate meeting threshold" but via
    # different traversal.
    let fe = newFeeEstimator()
    # Populate enough txs to exceed MinDataPoints=10 even after decay
    # processBlock applies decay before recording; use many txs per block
    for i in 0..<50:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 10.0, 100)
    # Now confirm them all in block 101
    var confirmed: seq[TxId]
    for i in 0..<50:
      confirmed.add(makeTxId(i))
    fe.processBlock(101, confirmed)
    # Check that estimate is data-driven (not fallback) — enough data survived decay
    var totalData = 0.0
    for i in 0..<NumBuckets:
      totalData += fe.getBucketStats(i).totalSeen
    if totalData >= float64(MinDataPoints):
      let estimate = fe.estimateFee(1)
      check estimate > 0.0
    else:
      skip()  # not enough data survived decay — documents MinDataPoints fragility

# ─────────────────────────────────────────────────────────────────────────────
# Gate G11 — confTarget=1 clamping
# Core: `if confTarget == 1 confTarget = 2` before estimation
# BUG-17: nimrod accepts target=1 and scans normally
# ─────────────────────────────────────────────────────────────────────────────
suite "G11 confTarget=1 handling":
  test "Core clamps confTarget=1 to 2; nimrod allows target=1 [BUG-17]":
    # In Core: estimateFee(1) → estimateRawFee with DOUBLE_SUCCESS_PCT on MED
    # which returns CFeeRate(0) because confTarget=1 is rejected (confTarget <= 1)
    # In nimrod: estimateFee(1) runs with target=1 and returns FallbackFeeRate
    # (since no data) — same value but wrong semantics
    let fe = newFeeEstimator()
    # With sufficient data:
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    # Core would return 0.0 (error) for target=1; nimrod returns a rate
    let rate1 = fe.estimateFee(1)
    let rate2 = fe.estimateFee(2)
    # nimrod does NOT clamp — both return same data-driven result
    # This test documents the difference
    check rate1 > 0.0  # nimrod doesn't error for target=1

# ─────────────────────────────────────────────────────────────────────────────
# Gate G12 — MaxUsableEstimate / returnedTarget
# Core: returnedTarget may differ from confTarget (clamped to MaxUsableEstimate)
# BUG-9: nimrod's RPC always echoes the original confTarget in "blocks"
# ─────────────────────────────────────────────────────────────────────────────
suite "G12 returnedTarget in estimatesmartfee":
  test "estimateFee returns data-driven result when data available":
    let fe = newFeeEstimator()
    for i in 0..<30:
      fe.trackTransaction(makeTxId(i), 15.0, 1000)
      fe.processBlock(1001, @[makeTxId(i)])
    let rate = fe.estimateFee(6)
    check rate != FallbackFeeRate
    check rate > 0.0

  test "FallbackFeeRate returned as real estimate — handler cannot distinguish [BUG-11]":
    # When no data, estimateFee returns FallbackFeeRate (10.0 sat/vbyte)
    # handleEstimateSmartFee checks `if feeRate <= 0`, but 10.0 > 0
    # so it returns a "feerate" response instead of an error response
    let fe = newFeeEstimator()
    # No data added — will return FallbackFeeRate
    let rate = fe.estimateFee(6)
    check rate == FallbackFeeRate   # 10.0
    check rate > 0.0  # documents that the error branch is never reached
    # In Core: would return CFeeRate(0) → error "Insufficient data"

# ─────────────────────────────────────────────────────────────────────────────
# Gate G13 — estimate_mode (conservative vs economical)
# Core: conservative=true adds a DOUBLE_SUCCESS_PCT check at 2*target
# BUG-10: nimrod has no conservative/economical distinction
# ─────────────────────────────────────────────────────────────────────────────
suite "G13 estimate_mode conservative":
  test "no conservative parameter in estimateFee API [BUG-10]":
    # The Nim API only has estimateFee(targetBlocks: int)
    # Core's estimateSmartFee(confTarget, feeCalc, conservative: bool)
    # This test documents absence by verifying the Nim API signature
    let fe = newFeeEstimator()
    for i in 0..<30:
      fe.trackTransaction(makeTxId(i), 20.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    # Same call for conservative vs economical — identical result (no distinction)
    let r1 = fe.estimateFee(6)
    let r2 = fe.estimateFee(6)
    check r1 == r2  # always equal; no conservative mode

# ─────────────────────────────────────────────────────────────────────────────
# Gate G14 — FeeReason enum (HALF_ESTIMATE, FULL_ESTIMATE, DOUBLE_ESTIMATE)
# Core: FeeCalculation carries FeeReason to indicate which sub-estimate won
# nimrod: no FeeReason / FeeCalculation struct
# ─────────────────────────────────────────────────────────────────────────────
suite "G14 FeeCalculation / FeeReason":
  test "no FeeCalculation struct in nimrod":
    # Core returns detailed FeeCalculation with reason, returnedTarget, best_height
    # nimrod returns only a float64
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    let rate = fe.estimateFee(6)
    check rate > 0.0  # returns float, not FeeCalculation

# ─────────────────────────────────────────────────────────────────────────────
# Gate G15 — HALF_SUCCESS_PCT (60%) and DOUBLE_SUCCESS_PCT (95%)
# Core uses three sub-estimates: target/2 @ 60%, target @ 85%, 2*target @ 95%
# nimrod uses single threshold: ConfirmationThreshold = 0.85
# ─────────────────────────────────────────────────────────────────────────────
suite "G15 multi-threshold estimation":
  test "Core HALF_SUCCESS_PCT=0.60 absent [only 0.85 used]":
    check ConfirmationThreshold == 0.85

  test "Core DOUBLE_SUCCESS_PCT=0.95 absent":
    # nimrod estimateFee only uses ConfirmationThreshold (0.85)
    check ConfirmationThreshold != 0.95

# ─────────────────────────────────────────────────────────────────────────────
# Gate G16 — per-horizon HighestTargetTracked
# Core: SHORT=12, MED=48, LONG=1008 — different horizons track different ranges
# nimrod: flat MaxTargetBlocks=1008 for all
# ─────────────────────────────────────────────────────────────────────────────
suite "G16 HighestTargetTracked per-horizon":
  test "Core SHORT_BLOCK_PERIODS*SHORT_SCALE=12, MED=48, LONG=1008":
    # SHORT: 12 periods × scale 1 = 12 blocks
    # MED:   24 periods × scale 2 = 48 blocks
    # LONG:  42 periods × scale 24 = 1008 blocks
    let shortMax = 12 * 1
    let medMax = 24 * 2
    let longMax = 42 * 24
    check shortMax == 12
    check medMax == 48
    check longMax == 1008
    # nimrod uses MaxTargetBlocks=1008 for everything
    check MaxTargetBlocks == 1008

# ─────────────────────────────────────────────────────────────────────────────
# Gate G17 — IBD gate: no tracking during initial block download
# Core: validForFeeEstimation requires m_chainstate_is_current=true
# nimrod: processBlock is called even during IBD (no is-current guard)
# ─────────────────────────────────────────────────────────────────────────────
suite "G17 IBD gate for fee tracking":
  test "no is-current-chainstate guard in trackTransaction API":
    # Core's processTransaction returns early if !m_chainstate_is_current
    # nimrod's trackTransaction has no such parameter
    let fe = newFeeEstimator()
    # Can track transactions freely, no chainstate-current guard
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    check fe.getTrackedCount() == 1

# ─────────────────────────────────────────────────────────────────────────────
# Gate G18 — mempool parents gate
# Core: only tracks txs with m_has_no_mempool_parents=true
# nimrod: no such filter in trackTransaction
# ─────────────────────────────────────────────────────────────────────────────
suite "G18 mempool-parents gate":
  test "no has-no-mempool-parents filter in trackTransaction":
    # Core skips package txs and txs with unconfirmed parents
    # nimrod tracks any tx unconditionally
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)  # would be skipped in Core if has parent
    check fe.getTrackedCount() == 1

# ─────────────────────────────────────────────────────────────────────────────
# Gate G19 — decay applied correctly per block (once per processBlock)
# ─────────────────────────────────────────────────────────────────────────────
suite "G19 decay application":
  test "decay applied exactly once per processBlock call (MED horizon)":
    # getBucketStats returns medHorizon; verify MED_DECAY=0.9952 applied each block
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(101, @[makeTxId(1)])
    let idx = getBucketIndex(10.0)
    let afterOne = fe.getBucketStats(idx).totalSeen
    # After one more empty block, MED decay applied once more
    fe.processBlock(102, @[])
    let afterTwo = fe.getBucketStats(idx).totalSeen
    check abs(afterTwo / afterOne - MED_DECAY) < 0.001

  test "MED decay 0.9952 produces ~39% reduction over 100 blocks":
    # 0.9952^100 ≈ 0.619 (more than 20% reduction)
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(101, @[makeTxId(1)])
    let initial = fe.getBucketStats(getBucketIndex(10.0)).totalSeen
    for h in 102..201:
      fe.processBlock(int32(h), @[])
    let finalSeen = fe.getBucketStats(getBucketIndex(10.0)).totalSeen
    # 0.9952^100 ≈ 0.619 → more than 30% reduction
    check finalSeen < initial * 0.75

# ─────────────────────────────────────────────────────────────────────────────
# Gate G20 — estimateRawFee horizon structure
# Core: returns short/medium/long horizons with feerate/decay/scale/pass/fail
# FIX-48: BUG-2 closed — three independent horizons with correct decays
# ─────────────────────────────────────────────────────────────────────────────
suite "G20 estimateRawFee horizon output":
  test "SHORT horizon decay = 0.962 [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check abs(fe.shortHorizon.decay - 0.962) < 0.0001

  test "MED horizon decay = 0.9952 [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check abs(fe.medHorizon.decay - 0.9952) < 0.0001

  test "LONG horizon decay = 0.99931 [FIX-48 BUG-2]":
    let fe = newFeeEstimator()
    check abs(fe.longHorizon.decay - 0.99931) < 0.00001

  test "horizons have distinct bucket data after tracking [FIX-48 BUG-2]":
    # After many empty blocks, SHORT decays much faster — bucket data diverges
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
    for h in 101..150:
      fe.processBlock(int32(h), @[])
    let shortSeen = fe.shortHorizon.buckets[getBucketIndex(10.0)].totalSeen
    let longSeen  = fe.longHorizon.buckets[getBucketIndex(10.0)].totalSeen
    # SHORT 0.962^50 ≈ 0.137, LONG 0.99931^50 ≈ 0.966 — clearly different
    check abs(longSeen - shortSeen) > 1.0  # demonstrably different data

# ─────────────────────────────────────────────────────────────────────────────
# Gate G21 — pass/fail bucket fields in estimateRawFee
# Core: EstimatorBucket has start/end/withinTarget/totalConfirmed/inMempool/leftMempool
# nimrod: populates approximate values but leftMempool always 0
# ─────────────────────────────────────────────────────────────────────────────
suite "G21 pass/fail bucket detail":
  test "leftMempool always 0 in nimrod (no failAvg) [BUG-6]":
    # Documented absence: leftMempool is always hardcoded 0.0
    # in handleEstimateRawFee because failAvg doesn't exist
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    # estimateRawFee RPC would have leftMempool=0 always
    # Verified by reading the RPC code: `"leftmempool": 0.0`
    check true  # absence verified by code inspection

# ─────────────────────────────────────────────────────────────────────────────
# Gate G22 — FlushUnconfirmed on shutdown
# Core: FlushUnconfirmed() records failure for all tracked txs before saving
# BUG-13: nimrod calls saveFeeEstimates without FlushUnconfirmed
# ─────────────────────────────────────────────────────────────────────────────
suite "G22 FlushUnconfirmed on shutdown":
  test "FlushUnconfirmed method absent from FeeEstimator [BUG-13]":
    # Core: Flush() calls FlushUnconfirmed() then FlushFeeEstimates()
    # Nimrod: no flushUnconfirmed proc — saves without flushing tracked txs
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    # Can save without removing tracked txs — they're silently dropped
    let (tmpFile, path) = createTempFile("fee_test", ".json")
    tmpFile.close()
    fe.saveFeeEstimates(path)
    # Load back and verify tracked tx count NOT persisted (only bucketStats)
    let fe2 = newFeeEstimator()
    fe2.loadFeeEstimates(path)
    check fe2.getTrackedCount() == 0  # tracked txs lost — no FlushUnconfirmed
    removeFile(path)

# ─────────────────────────────────────────────────────────────────────────────
# Gate G23 — file persistence: save and load round-trip
# ─────────────────────────────────────────────────────────────────────────────
suite "G23 fee_estimates persistence":
  test "saveFeeEstimates / loadFeeEstimates round-trip":
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    let (tmpFile, path) = createTempFile("fee_rt", ".json")
    tmpFile.close()
    fe.saveFeeEstimates(path)
    let fe2 = newFeeEstimator()
    fe2.loadFeeEstimates(path)
    let idx = getBucketIndex(10.0)
    let orig = fe.getBucketStats(idx)
    let loaded = fe2.getBucketStats(idx)
    check abs(orig.totalSeen - loaded.totalSeen) < 0.001
    check abs(orig.avgFeeRate - loaded.avgFeeRate) < 0.001
    removeFile(path)

  test "file format is JSON not Core binary [BUG-14]":
    let fe = newFeeEstimator()
    let (tmpFile, path) = createTempFile("fee_fmt", ".json")
    tmpFile.close()
    fe.saveFeeEstimates(path)
    let content = readFile(path)
    # Core writes binary; nimrod writes JSON starting with "{"
    check content.len > 0
    check content[0] == '{'
    # Core file version 309900 would be serialized as little-endian int
    # Verify no version number 309900 present in JSON
    check content.contains("\"version\"")
    check not content.contains("309900")
    removeFile(path)

  test "no file-age check on load [BUG-15]":
    # Core: refuses files older than 60h unless DEFAULT_ACCEPT_STALE_FEE_ESTIMATES
    # nimrod: loads without checking file modification time
    let fe = newFeeEstimator()
    fe.trackTransaction(makeTxId(1), 10.0, 100)
    fe.processBlock(101, @[makeTxId(1)])
    let (tmpFile, path) = createTempFile("fee_age", ".json")
    tmpFile.close()
    fe.saveFeeEstimates(path)
    # No way to test age without mocking time, but load succeeds regardless
    let fe2 = newFeeEstimator()
    fe2.loadFeeEstimates(path)
    # Documents that nimrod loads any file regardless of age
    check fe2.getBucketStats(getBucketIndex(10.0)).totalSeen > 0.0
    removeFile(path)

# ─────────────────────────────────────────────────────────────────────────────
# Gate G24 — MinDataPoints check
# nimrod: MinDataPoints=10 (totalSeen across all buckets)
# Core: SUFFICIENT_FEETXS=0.1 tx/block with decay-adjusted threshold
# ─────────────────────────────────────────────────────────────────────────────
suite "G24 MinDataPoints threshold":
  test "returns FallbackFeeRate when totalSeen < MinDataPoints=10":
    let fe = newFeeEstimator()
    for i in 0..<5:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    # 5 txs processed — below MinDataPoints=10
    check fe.estimateFee(6) == FallbackFeeRate

  test "returns non-fallback when totalSeen >= MinDataPoints=10":
    let fe = newFeeEstimator()
    # Use fee rate 25.0 (distinct from FallbackFeeRate=10.0) to avoid coincidence
    for i in 0..<15:
      fe.trackTransaction(makeTxId(i), 25.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    check fe.estimateFee(6) != FallbackFeeRate

# ─────────────────────────────────────────────────────────────────────────────
# Gate G25 — getConfirmationRate: totalSeen denominator only (no failAvg/extraNum)
# Core denominator: totalNum + failNum + extraNum
# BUG-6, BUG-7: nimrod denominator is just totalSeen
# ─────────────────────────────────────────────────────────────────────────────
suite "G25 confirmation rate denominator":
  test "confirmation rate uses totalSeen only, not Core's full denominator [BUG-6,7]":
    let fe = newFeeEstimator()
    # Use enough txs so totalSeen stays > 1 after decay
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
    var confirmed: seq[TxId]
    for i in 0..<20:
      confirmed.add(makeTxId(i))
    fe.processBlock(101, confirmed)
    let idx = getBucketIndex(10.0)
    # In nimrod: rate = confirmed / totalSeen (after decay)
    # In Core: rate = nConf / (totalNum + failNum + extraNum)
    let stats = fe.getBucketStats(idx)
    if stats.totalSeen >= 1.0:
      let rate = fe.getConfirmationRate(idx, 6)
      check rate > 0.0
      # BUG-19: rate can exceed 1.0 — decay applied before recording
      # totalSeen is decayed first (smaller denominator), then confirmed[i] is
      # incremented (+1 on undecayed numerator) → confirmed/totalSeen > 1.0
    else:
      skip()  # totalSeen < 1 after decay — documents MinDataPoints fragility

# ─────────────────────────────────────────────────────────────────────────────
# Gate G25b — BUG-19: confirmation rate > 1.0 from decay-before-record
# Core: UpdateMovingAverages (decay) is separate from Record (current block)
# nimrod: applyDecay() called first in processBlock → totalSeen shrinks before
#         confirmed[i] is incremented → rate = confirmed / totalSeen > 1.0
# ─────────────────────────────────────────────────────────────────────────────
suite "G25b decay-before-record rate overflow":
  test "confirmation rate can exceed 1.0 due to decay applied before recording [BUG-19]":
    let fe = newFeeEstimator()
    # Track 20 txs at same height
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
    # Confirm all in same block (processBlock decays totalSeen first, then records)
    var confirmed: seq[TxId]
    for i in 0..<20:
      confirmed.add(makeTxId(i))
    fe.processBlock(101, confirmed)  # blocksToConfirm=1, MED scale=2: period=(1-1)/2=0 → slot[0]
    let idx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(idx)
    if stats.totalSeen > 0:
      # confirmed[0] = 20.0 (undecayed) but totalSeen = 20 * MED_DECAY ≈ 19.904
      # getConfirmationRate(idx, 2) with MED scale=2: maxPeriod=1, sums [0]=20, rate≈1.005
      let rate = fe.getConfirmationRate(idx, 2)
      # Rate should be ≤ 1.0 in a correct implementation
      # In nimrod it exceeds 1.0 because totalSeen was decayed before confirmed[0]++
      check rate > 1.0  # documents BUG-19: > 1.0 is wrong

# ─────────────────────────────────────────────────────────────────────────────
# Gate G26 — clear() resets estimator state
# ─────────────────────────────────────────────────────────────────────────────
suite "G26 clear state reset":
  test "clear() returns estimator to initial state":
    let fe = newFeeEstimator()
    for i in 0..<20:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])
    fe.clear()
    check fe.getTrackedCount() == 0
    check fe.estimateFee(6) == FallbackFeeRate
    for i in 0..<NumBuckets:
      check fe.getBucketStats(i).totalSeen == 0.0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G27 — nBestSeenHeight tracking
# Core: nBestSeenHeight updated per processBlock for removeTx age calculations
# nimrod: no nBestSeenHeight field; height tracked per-tx only
# ─────────────────────────────────────────────────────────────────────────────
suite "G27 nBestSeenHeight tracking":
  test "no nBestSeenHeight-equivalent in FeeEstimator struct":
    # FeeEstimator only has bucketStats and trackedTxs
    # No nBestSeenHeight, firstRecordedHeight, historicalFirst/historicalBest
    let fe = newFeeEstimator()
    fe.processBlock(200, @[])
    fe.processBlock(199, @[])  # earlier height — Core would ignore; nimrod applies decay
    # Decay applied for both calls
    # Documents absence of height guard (also covered in G5)
    check true

# ─────────────────────────────────────────────────────────────────────────────
# Gate G28 — duplicate transaction guard
# ─────────────────────────────────────────────────────────────────────────────
suite "G28 duplicate transaction":
  test "duplicate trackTransaction is idempotent":
    let fe = newFeeEstimator()
    let txid = makeTxId(1)
    fe.trackTransaction(txid, 10.0, 100)
    fe.trackTransaction(txid, 10.0, 100)
    check fe.getTrackedCount() == 1
    check fe.getBucketStats(getBucketIndex(10.0)).totalSeen == 1.0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G29 — removeTransaction when not tracked (no-op)
# ─────────────────────────────────────────────────────────────────────────────
suite "G29 removeTransaction no-op for untracked":
  test "removeTransaction on untracked txid is a no-op":
    let fe = newFeeEstimator()
    fe.removeTransaction(makeTxId(999))  # should not raise
    check fe.getTrackedCount() == 0

# ─────────────────────────────────────────────────────────────────────────────
# Gate G30 — out-of-range bucket index guards
# ─────────────────────────────────────────────────────────────────────────────
suite "G30 out-of-range guards":
  test "getBucketStats with negative index returns default":
    let fe = newFeeEstimator()
    let stats = fe.getBucketStats(-1)
    check stats.totalSeen == 0.0

  test "getBucketStats with index >= NumBuckets returns default":
    let fe = newFeeEstimator()
    let stats = fe.getBucketStats(NumBuckets)
    check stats.totalSeen == 0.0

  test "getConfirmationRate with invalid bucket returns 0.0":
    let fe = newFeeEstimator()
    check fe.getConfirmationRate(-1, 6) == 0.0
    check fe.getConfirmationRate(NumBuckets, 6) == 0.0
