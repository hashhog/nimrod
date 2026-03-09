## Tests for fee estimation

import unittest2
import ../src/mining/fees
import ../src/primitives/types

proc makeTxId(n: int): TxId =
  ## Create a unique TxId for testing
  var arr: array[32, byte]
  arr[0] = byte(n and 0xff)
  arr[1] = byte((n shr 8) and 0xff)
  arr[2] = byte((n shr 16) and 0xff)
  arr[3] = byte((n shr 24) and 0xff)
  TxId(arr)

suite "Fee Estimation":
  test "new fee estimator starts empty":
    let fe = newFeeEstimator()
    check fe.getTrackedCount() == 0
    # Fallback fee with no data
    check fe.estimateFee(1) == FallbackFeeRate

  test "bucket index calculation":
    # Test fee rate to bucket mapping
    check getBucketIndex(0.5) == 0   # <= 1.0 -> bucket 0
    check getBucketIndex(1.0) == 0   # == 1.0 -> bucket 0
    check getBucketIndex(1.5) == 1   # <= 2.0 -> bucket 1
    check getBucketIndex(10.0) == 5  # == 10.0 -> bucket 5
    check getBucketIndex(11.0) == 6  # <= 15.0 -> bucket 6
    check getBucketIndex(100.0) == 11  # == 100.0 -> bucket 11
    check getBucketIndex(20000.0) == NumBuckets - 1  # Above max -> highest bucket

  test "track transaction":
    let fe = newFeeEstimator()
    let txid = makeTxId(1)

    fe.trackTransaction(txid, 5.0, 100)

    check fe.getTrackedCount() == 1

    let bucketIdx = getBucketIndex(5.0)
    let stats = fe.getBucketStats(bucketIdx)
    check stats.totalSeen == 1.0
    check stats.avgFeeRate == 5.0

  test "process block updates confirmation stats":
    let fe = newFeeEstimator()

    # Track some transactions at height 100
    for i in 0..<10:
      fe.trackTransaction(makeTxId(i), 10.0, 100)

    check fe.getTrackedCount() == 10

    # Confirm all in block 101 (1 block to confirm)
    var confirmedTxids: seq[TxId]
    for i in 0..<10:
      confirmedTxids.add(makeTxId(i))

    fe.processBlock(101, confirmedTxids)

    check fe.getTrackedCount() == 0

    # Check confirmation stats
    let bucketIdx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(bucketIdx)

    # Due to decay, totalSeen is slightly less than 10
    check stats.totalSeen > 9.0
    # Confirmed in 1 block (index 1 since blocksToConfirm = 101 - 100 = 1)
    check stats.totalConfirmed[1] > 9.0

  test "fallback on empty data":
    let fe = newFeeEstimator()

    # No data - should return fallback
    check fe.estimateFee(1) == FallbackFeeRate
    check fe.estimateFee(6) == FallbackFeeRate
    check fe.estimateFee(25) == FallbackFeeRate

  test "fallback on insufficient data":
    let fe = newFeeEstimator()

    # Add only a few transactions (less than MinDataPoints)
    for i in 0..<5:
      fe.trackTransaction(makeTxId(i), 10.0, 100)
      fe.processBlock(101, @[makeTxId(i)])

    # Still not enough data - should return fallback
    check fe.estimateFee(1) == FallbackFeeRate

  test "target=1 fee >= target=6 fee":
    let fe = newFeeEstimator()

    # Add transactions at different fee rates
    # High fee rate txs - confirm in 1 block
    for i in 0..<20:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 50.0, 100)
      fe.processBlock(101, @[txid])

    # Medium fee rate txs - confirm in 3 blocks
    for i in 20..<40:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 10.0, 100)
      fe.processBlock(103, @[txid])

    # Low fee rate txs - confirm in 10 blocks
    for i in 40..<60:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 3.0, 100)
      fe.processBlock(110, @[txid])

    # target=1 should require higher fee than target=6
    let feeTarget1 = fe.estimateFee(1)
    let feeTarget6 = fe.estimateFee(6)

    check feeTarget1 >= feeTarget6

  test "remove transaction":
    let fe = newFeeEstimator()
    let txid = makeTxId(1)

    fe.trackTransaction(txid, 10.0, 100)
    check fe.getTrackedCount() == 1

    fe.removeTransaction(txid)
    check fe.getTrackedCount() == 0

    # Bucket stats should be decremented
    let bucketIdx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(bucketIdx)
    check stats.totalSeen == 0.0

  test "clear resets all data":
    let fe = newFeeEstimator()

    # Add some data
    for i in 0..<10:
      fe.trackTransaction(makeTxId(i), 10.0, 100)

    check fe.getTrackedCount() == 10

    fe.clear()

    check fe.getTrackedCount() == 0
    check fe.estimateFee(1) == FallbackFeeRate

  test "estimation with mixed confirmation times":
    let fe = newFeeEstimator()

    # Simulate realistic fee estimation scenario
    # Track 100 transactions at various fee rates

    # 30 txs at 100 sat/vbyte - all confirm in 1 block
    for i in 0..<30:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 100.0, 1000)
      fe.processBlock(1001, @[txid])

    # 30 txs at 20 sat/vbyte - confirm in 2-3 blocks
    for i in 30..<60:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 20.0, 1000)
      fe.processBlock(1002 + (i mod 2).int32, @[txid])

    # 20 txs at 5 sat/vbyte - confirm in 6-10 blocks
    for i in 60..<80:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 5.0, 1000)
      fe.processBlock(1006 + (i mod 5).int32, @[txid])

    # 20 txs at 2 sat/vbyte - confirm in 20+ blocks
    for i in 80..<100:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 2.0, 1000)
      fe.processBlock(1020 + (i mod 10).int32, @[txid])

    # Now test estimation
    let fee1 = fe.estimateFee(1)
    let fee6 = fe.estimateFee(6)
    let fee25 = fe.estimateFee(25)

    # Should have reasonable estimates
    check fee1 > 0
    check fee6 > 0
    check fee25 > 0

    # Higher priority should have higher or equal fees
    check fee1 >= fee6
    check fee6 >= fee25

  test "duplicate tracking is ignored":
    let fe = newFeeEstimator()
    let txid = makeTxId(1)

    fe.trackTransaction(txid, 10.0, 100)
    fe.trackTransaction(txid, 10.0, 100)  # Duplicate

    check fe.getTrackedCount() == 1

    let bucketIdx = getBucketIndex(10.0)
    let stats = fe.getBucketStats(bucketIdx)
    check stats.totalSeen == 1.0  # Not doubled

  test "exponential decay reduces old data influence":
    let fe = newFeeEstimator()

    # Add initial data
    for i in 0..<10:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, 10.0, 100)
      fe.processBlock(101, @[txid])

    let bucketIdx = getBucketIndex(10.0)
    let initialStats = fe.getBucketStats(bucketIdx)
    let initialSeen = initialStats.totalSeen

    # Process many empty blocks (applies decay each time)
    for h in 102..<202:
      fe.processBlock(int32(h), @[])

    let finalStats = fe.getBucketStats(bucketIdx)

    # After 100 decay applications, data should be significantly reduced
    check finalStats.totalSeen < initialSeen * 0.9

  test "priority-based estimation":
    let fe = newFeeEstimator()

    # Add enough data for estimation
    for i in 0..<50:
      let txid = makeTxId(i)
      fe.trackTransaction(txid, float64(10 + i), 100)
      fe.processBlock(101 + int32(i div 10), @[txid])

    let highPriority = fe.estimateFeeForPriority(1)
    let mediumPriority = fe.estimateFeeForPriority(2)
    let lowPriority = fe.estimateFeeForPriority(3)

    check highPriority > 0
    check mediumPriority > 0
    check lowPriority > 0
