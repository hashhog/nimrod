## BIP133 feefilter tests
## Tests fee filter quantization, peer filtering, and incremental relay fee

import unittest2
import std/[random, math, tables, strutils]
import chronos
import ../src/network/relay
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params

suite "FeeFilterRounder":
  test "creates logarithmic buckets":
    let rounder = newFeeFilterRounder()
    check rounder.feeBuckets.len > 0
    check rounder.feeBuckets[0] == 0.0

    # Buckets should increase by ~10% each step
    for i in 2 ..< rounder.feeBuckets.len:
      let ratio = rounder.feeBuckets[i] / rounder.feeBuckets[i - 1]
      # Allow small floating point tolerance
      check ratio >= 1.09
      check ratio <= 1.11

  test "round returns valid bucket value":
    let rounder = newFeeFilterRounder()

    for _ in 0 ..< 100:
      let input = int64(rand(10_000_000))
      let rounded = rounder.round(input)
      check rounded >= 0
      check rounded <= input + int64(float64(input) * 0.11)  # Allow one bucket up

  test "round returns 0 for zero input":
    let rounder = newFeeFilterRounder()
    check rounder.round(0) == 0

  test "round never exceeds max filter rate":
    let rounder = newFeeFilterRounder()
    let hugeRate = 100_000_000'i64
    let rounded = rounder.round(hugeRate)
    check rounded <= hugeRate

  test "round provides privacy by quantizing":
    let rounder = newFeeFilterRounder()

    # Two close values should often round to the same bucket
    var sameCount = 0
    for _ in 0 ..< 100:
      let base = 5000'i64
      let r1 = rounder.round(base)
      let r2 = rounder.round(base + 100)  # Small difference

      # Not always the same due to randomization, but often
      if r1 == r2:
        inc sameCount

    # Should be same bucket most of the time
    check sameCount > 50

suite "Fee rate calculation":
  test "calculateFeeRate computes sat/kvB":
    # 1000 satoshis / 1000 vbytes = 1000 sat/kvB
    check calculateFeeRate(1000, 1000) == 1000

    # 500 satoshis / 250 vbytes = 2000 sat/kvB
    check calculateFeeRate(500, 250) == 2000

    # 1 satoshi / 1 vbyte = 1000 sat/kvB
    check calculateFeeRate(1, 1) == 1000

  test "calculateFeeRate handles edge cases":
    check calculateFeeRate(0, 100) == 0
    check calculateFeeRate(100, 0) == 0
    check calculateFeeRate(0, 0) == 0

  test "txMeetsFeefilter with no filter":
    # No filter (0) means accept all
    check txMeetsFeefilter(100, 0) == true
    check txMeetsFeefilter(1, 0) == true

  test "txMeetsFeefilter with filter set":
    # Filter at 1000 sat/kvB (1 sat/vB)
    check txMeetsFeefilter(1000, 1000) == true   # Equal
    check txMeetsFeefilter(1001, 1000) == true   # Above
    check txMeetsFeefilter(999, 1000) == false   # Below

  test "txMeetsFeefilter with high filter":
    # High fee filter (10 sat/vB = 10000 sat/kvB)
    check txMeetsFeefilter(10000, 10000) == true
    check txMeetsFeefilter(5000, 10000) == false

suite "Incremental relay fee":
  test "checkIncrementalRelayFee passes for valid replacement":
    # Original: 1000 sats, Replacement: 2000 sats, 200 vbytes
    # Additional fee: 1000 sats >= 1000 sat/kvB * 200 / 1000 = 200 sats
    let (ok, error) = checkIncrementalRelayFee(1000, 2000, 200)
    check ok == true
    check error == ""

  test "checkIncrementalRelayFee fails if fee not higher":
    # Original: 1000 sats, Replacement: 1000 sats (not higher)
    let (ok, error) = checkIncrementalRelayFee(1000, 1000, 200)
    check ok == false
    check "not higher" in error

  test "checkIncrementalRelayFee fails if fee lower":
    let (ok, error) = checkIncrementalRelayFee(1000, 500, 200)
    check ok == false
    check "not higher" in error

  test "checkIncrementalRelayFee fails if additional fee too low":
    # Original: 1000 sats, Replacement: 1001 sats, 200 vbytes
    # Additional fee: 1 sat < 200 sats required
    let (ok, error) = checkIncrementalRelayFee(1000, 1001, 200)
    check ok == false
    check "additional fee" in error

  test "checkIncrementalRelayFee with custom incremental fee":
    # Use 2000 sat/kvB (2 sat/vB) incremental fee
    # Original: 1000, Replacement: 1500, 200 vbytes
    # Required: 2000 * 200 / 1000 = 400 sats, but we only have 500
    let (ok, error) = checkIncrementalRelayFee(1000, 1500, 200, 2000)
    check ok == true

    # Now with only 300 additional (not enough)
    let (ok2, error2) = checkIncrementalRelayFee(1000, 1300, 200, 2000)
    check ok2 == false

  test "checkIncrementalRelayFee with large transaction":
    # Large tx: 10000 vbytes
    # Required additional: 1000 * 10000 / 1000 = 10000 sats
    let (ok, error) = checkIncrementalRelayFee(5000, 20000, 10000)
    check ok == true  # 15000 > 10000

    let (ok2, error2) = checkIncrementalRelayFee(5000, 10000, 10000)
    check ok2 == false  # 5000 < 10000

suite "RelayManager feefilter state":
  test "new relay manager has default fee rate":
    let rm = newRelayManager()
    check rm.mempoolMinFeeRate == DefaultMinRelayFee
    check rm.isIBD == true

  test "setMempoolMinFeeRate updates rate":
    let rm = newRelayManager()
    rm.setMempoolMinFeeRate(5000)
    check rm.mempoolMinFeeRate == 5000

  test "setMempoolMinFeeRate enforces minimum":
    let rm = newRelayManager()
    rm.setMempoolMinFeeRate(100)  # Below default
    check rm.mempoolMinFeeRate == DefaultMinRelayFee

  test "getCurrentFeefilterValue during IBD":
    let rm = newRelayManager()
    rm.isIBD = true
    check rm.getCurrentFeefilterValue() == MaxMoney

  test "getCurrentFeefilterValue after IBD":
    let rm = newRelayManager()
    rm.isIBD = false
    rm.mempoolMinFeeRate = 5000
    let value = rm.getCurrentFeefilterValue()
    # Should be rounded for privacy but close to 5000
    check value >= 4500
    check value <= 5500

  test "setIBD changes IBD state":
    let rm = newRelayManager()
    check rm.isIBD == true
    rm.setIBD(false)
    check rm.isIBD == false

suite "PeerRelayState feefilter state":
  test "new state has zero feeFilterSent":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)
    check state.feeFilterSent == 0

  test "nextSendFeefilter is initialized":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)
    # Should be set to now or soon
    let now = Moment.now()
    check state.nextSendFeefilter <= now + milliseconds(1000)

suite "Transaction relay with feefilter":
  test "queueTxInvWithFee skips peers below filter":
    let rm = newRelayManager()

    let peer1 = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let peer2 = newPeer("127.0.0.2", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer1)
    rm.registerPeer(peer2)

    # Set high feefilter on peer1
    peer1.feeFilterRate = 10000  # 10 sat/vB

    # Queue tx with 5000 sat/kvB (5 sat/vB) - below peer1's filter
    var txHash: array[32, byte]
    txHash[0] = 0xAB
    rm.queueTxInvWithFee(txHash, 500, 100)  # 500 sats / 100 vB = 5000 sat/kvB

    # peer1 should not receive (feefilter)
    # peer2 should receive (no feefilter)
    check rm.getQueuedCount(peer1) == 0
    check rm.getQueuedCount(peer2) == 1

  test "queueTxInvWithFee includes peers above filter":
    let rm = newRelayManager()

    let peer1 = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    rm.registerPeer(peer1)

    # Set feefilter on peer1
    peer1.feeFilterRate = 1000  # 1 sat/vB

    # Queue tx with 2000 sat/kvB - above filter
    var txHash: array[32, byte]
    txHash[0] = 0xCD
    rm.queueTxInvWithFee(txHash, 200, 100)  # 200 sats / 100 vB = 2000 sat/kvB

    check rm.getQueuedCount(peer1) == 1

  test "queueTxInv without fee info ignores feefilter":
    let rm = newRelayManager()

    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    rm.registerPeer(peer)

    # Set high feefilter
    peer.feeFilterRate = 100000  # Very high

    # Queue tx without fee info (legacy API)
    var txHash: array[32, byte]
    txHash[0] = 0xEF
    rm.queueTxInv(txHash)

    # Should still be queued (legacy behavior)
    check rm.getQueuedCount(peer) == 1

suite "Feefilter constants":
  test "default min relay fee is 1000 sat/kvB":
    check DefaultMinRelayFee == 1000

  test "default incremental relay fee is 1000 sat/kvB":
    check DefaultIncrementalRelayFee == 1000

  test "feefilter interval is 10 minutes":
    check AvgFeefilterBroadcastInterval == 600.0

  test "max feefilter change delay is 5 minutes":
    check MaxFeefilterChangeDelay == 300.0

  test "hysteresis thresholds are correct":
    check FeefilterLowThreshold == 0.75
    check FeefilterHighThreshold == 1.33

when isMainModule:
  waitFor(chronos.sleepAsync(1.milliseconds))  # Initialize chronos
