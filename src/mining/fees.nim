## Fee estimation using histogram-based confirmation tracking
## Tracks transactions across fee-rate buckets and measures confirmation times

import std/[tables, math]
import ../primitives/types

const
  MaxTargetBlocks* = 1008  ## Maximum confirmation target in blocks

  ## Fee rate buckets in sat/vbyte
  FeeRateBuckets* = [1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0, 30.0, 50.0,
    75.0, 100.0, 150.0, 200.0, 300.0, 500.0, 750.0, 1000.0, 1500.0, 2000.0,
    5000.0, 10000.0]

  NumBuckets* = 22  ## Length of FeeRateBuckets
  ConfirmationThreshold* = 0.85  ## 85% confirmation threshold
  DecayFactor* = 0.998  ## Exponential decay factor for older data
  FallbackFeeRate* = 10.0  ## Fallback fee rate when insufficient data (sat/vbyte)
  MinDataPoints* = 10  ## Minimum data points required for estimation

type
  TrackedTx* = object
    feeRate*: float64
    bucketIdx*: int
    entryHeight*: int32

  BucketStats* = object
    totalConfirmed*: array[MaxTargetBlocks, float64]  ## Confirmed count by blocks-to-confirm
    totalSeen*: float64  ## Total transactions seen in this bucket
    avgFeeRate*: float64  ## Average fee rate of transactions in bucket
    feeRateSum*: float64  ## Running sum for average calculation

  FeeEstimator* = ref object
    bucketStats*: array[NumBuckets, BucketStats]
    trackedTxs*: Table[TxId, TrackedTx]

proc newFeeEstimator*(): FeeEstimator =
  ## Create a new fee estimator
  result = FeeEstimator(
    bucketStats: default(array[NumBuckets, BucketStats]),
    trackedTxs: initTable[TxId, TrackedTx]()
  )

proc getBucketIndex*(feeRate: float64): int =
  ## Find the bucket index for a given fee rate
  ## Returns the index of the first bucket >= feeRate
  for i, bucketRate in FeeRateBuckets:
    if feeRate <= bucketRate:
      return i
  # Fee rate higher than all buckets - use highest bucket
  return NumBuckets - 1

proc applyDecay*(fe: FeeEstimator) =
  ## Apply exponential decay to all bucket statistics
  ## Called periodically to reduce influence of older data
  for i in 0..<NumBuckets:
    fe.bucketStats[i].totalSeen *= DecayFactor
    fe.bucketStats[i].feeRateSum *= DecayFactor
    for j in 0..<MaxTargetBlocks:
      fe.bucketStats[i].totalConfirmed[j] *= DecayFactor

    # Recalculate average
    if fe.bucketStats[i].totalSeen > 0:
      fe.bucketStats[i].avgFeeRate =
        fe.bucketStats[i].feeRateSum / fe.bucketStats[i].totalSeen
    else:
      fe.bucketStats[i].avgFeeRate = 0

proc trackTransaction*(fe: FeeEstimator, txid: TxId, feeRate: float64, height: int32) =
  ## Start tracking a transaction for fee estimation
  ## Called when a transaction enters the mempool

  let bucketIdx = getBucketIndex(feeRate)

  # Don't track if already tracking
  if txid in fe.trackedTxs:
    return

  # Add to tracked transactions
  fe.trackedTxs[txid] = TrackedTx(
    feeRate: feeRate,
    bucketIdx: bucketIdx,
    entryHeight: height
  )

  # Update bucket stats
  fe.bucketStats[bucketIdx].totalSeen += 1
  fe.bucketStats[bucketIdx].feeRateSum += feeRate
  fe.bucketStats[bucketIdx].avgFeeRate =
    fe.bucketStats[bucketIdx].feeRateSum / fe.bucketStats[bucketIdx].totalSeen

proc processBlock*(fe: FeeEstimator, height: int32, confirmedTxids: seq[TxId]) =
  ## Process a confirmed block, updating confirmation statistics
  ## Called when a new block is connected

  # Apply decay first (once per block)
  fe.applyDecay()

  for txid in confirmedTxids:
    if txid notin fe.trackedTxs:
      continue

    let tracked = fe.trackedTxs[txid]
    let blocksToConfirm = height - tracked.entryHeight

    # Only track confirmations within our target range
    if blocksToConfirm >= 0 and blocksToConfirm < MaxTargetBlocks:
      fe.bucketStats[tracked.bucketIdx].totalConfirmed[blocksToConfirm] += 1

    # Remove from tracking
    fe.trackedTxs.del(txid)

proc removeTransaction*(fe: FeeEstimator, txid: TxId) =
  ## Remove a transaction from tracking (e.g., if evicted from mempool)
  if txid in fe.trackedTxs:
    let tracked = fe.trackedTxs[txid]
    # Decrement the seen count (but keep it non-negative)
    if fe.bucketStats[tracked.bucketIdx].totalSeen > 0:
      fe.bucketStats[tracked.bucketIdx].totalSeen -= 1
      fe.bucketStats[tracked.bucketIdx].feeRateSum -= tracked.feeRate
      if fe.bucketStats[tracked.bucketIdx].totalSeen > 0:
        fe.bucketStats[tracked.bucketIdx].avgFeeRate =
          fe.bucketStats[tracked.bucketIdx].feeRateSum / fe.bucketStats[tracked.bucketIdx].totalSeen
      else:
        fe.bucketStats[tracked.bucketIdx].avgFeeRate = 0
    fe.trackedTxs.del(txid)

proc getConfirmationRate*(fe: FeeEstimator, bucketIdx: int, targetBlocks: int): float64 =
  ## Calculate confirmation rate for a bucket within target blocks
  ## Returns the percentage of transactions confirmed within the target

  if bucketIdx < 0 or bucketIdx >= NumBuckets:
    return 0.0

  let stats = fe.bucketStats[bucketIdx]
  if stats.totalSeen < 1:
    return 0.0

  # Sum confirmed within target blocks
  var confirmed = 0.0
  for i in 0..<min(targetBlocks, MaxTargetBlocks):
    confirmed += stats.totalConfirmed[i]

  confirmed / stats.totalSeen

proc estimateFee*(fe: FeeEstimator, targetBlocks: int): float64 =
  ## Estimate the fee rate (sat/vbyte) needed to confirm within targetBlocks
  ## Uses the lowest bucket that achieves >= 85% confirmation rate
  ## Returns fallback rate (10 sat/vbyte) if insufficient data

  let target = min(max(targetBlocks, 1), MaxTargetBlocks)

  # Check if we have enough data
  var totalData = 0.0
  for i in 0..<NumBuckets:
    totalData += fe.bucketStats[i].totalSeen

  if totalData < float64(MinDataPoints):
    return FallbackFeeRate

  # Find the lowest bucket with >= 85% confirmation rate
  for i in 0..<NumBuckets:
    let rate = fe.getConfirmationRate(i, target)

    # Need some data in this bucket and meet threshold
    if fe.bucketStats[i].totalSeen >= 1 and rate >= ConfirmationThreshold:
      # Return the bucket's fee rate (use average if available, else bucket boundary)
      if fe.bucketStats[i].avgFeeRate > 0:
        return fe.bucketStats[i].avgFeeRate
      else:
        return FeeRateBuckets[i]

  # No bucket meets the threshold - use the highest bucket rate or fallback
  for i in countdown(NumBuckets - 1, 0):
    if fe.bucketStats[i].totalSeen >= 1:
      # Return highest fee rate we've seen
      if fe.bucketStats[i].avgFeeRate > 0:
        return fe.bucketStats[i].avgFeeRate
      else:
        return FeeRateBuckets[i]

  # No data at all - return fallback
  return FallbackFeeRate

proc estimateFeeForPriority*(fe: FeeEstimator, priority: int): float64 =
  ## Estimate fee for common priority levels
  ## priority 1: high (next block), priority 2: medium (6 blocks), priority 3: low (25 blocks)
  case priority
  of 1: fe.estimateFee(1)
  of 2: fe.estimateFee(6)
  of 3: fe.estimateFee(25)
  else: fe.estimateFee(6)

proc getTrackedCount*(fe: FeeEstimator): int =
  ## Get the number of currently tracked transactions
  fe.trackedTxs.len

proc getBucketStats*(fe: FeeEstimator, bucketIdx: int): BucketStats =
  ## Get statistics for a specific bucket
  if bucketIdx >= 0 and bucketIdx < NumBuckets:
    fe.bucketStats[bucketIdx]
  else:
    default(BucketStats)

proc clear*(fe: FeeEstimator) =
  ## Clear all tracked data and statistics
  fe.trackedTxs.clear()
  for i in 0..<NumBuckets:
    fe.bucketStats[i] = default(BucketStats)
