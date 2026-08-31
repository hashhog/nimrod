## BIP133 feefilter tests
## Tests fee filter quantization, peer filtering, and incremental relay fee

import unittest2
import std/[random, math, tables, strutils, sets]
import chronos
import ../src/network/relay
import ../src/util/rng
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

  test "round matches Bitcoin Core's published feerounder vectors":
    ## Replaces a statistical assertion that was FLAKY BY CONSTRUCTION: it drew
    ## 100 samples of `round(5000) == round(5100)` and required > 50 matches,
    ## while the expected count is 100 * ((1/3)^2 + (2/3)^2) = 55.6 with
    ## sd ~= 5.0 — roughly a 1-in-8 failure, which is exactly what it did.
    ##
    ## Core has the same problem and solves it by seeding deterministically
    ## (test/feerounder_tests.cpp: FastRandomContext rng{/*fDeterministic=*/true}).
    ## nimrod cannot do that yet because round() re-seeds the global RNG on every
    ## call, so instead assert Core's published VALUES, which are exact.
    ##
    ##   FeeFilterRounder fee_rounder{CFeeRate{1000}, rng};
    ##   // check that 1000 rounds to 974 or 1071
    ##   BOOST_CHECK_EQUAL(*results.begin(),   974);
    ##   BOOST_CHECK_EQUAL(*++results.begin(), 1071);
    ##   BOOST_CHECK_EQUAL(fee_rounder.round(-0),        0);
    ##   BOOST_CHECK_EQUAL(fee_rounder.round(-1),        0);
    ##   BOOST_CHECK_EQUAL(fee_rounder.round(MAX_MONEY), 9170997);
    let rounder = newFeeFilterRounder(1000)

    var seen = initHashSet[int64]()
    for _ in 0 ..< 2000:
      seen.incl(rounder.round(1000))
    # Exactly the two adjacent buckets Core names — no third value, ever.
    check seen.len == 2
    check 974'i64 in seen
    check 1071'i64 in seen

    check rounder.round(0) == 0'i64
    check rounder.round(-1) == 0'i64
    check rounder.round(2_100_000_000_000_000'i64) == 9_170_997'i64   # MAX_MONEY

  test "round is REPRODUCIBLE under a pinned seed (was impossible before)":
    ## This test could not exist before src/util/rng.nim.
    ##
    ## round() used to call std/random's randomize() on every invocation, which
    ## overwrote any seed a test set, so the generator could never be pinned —
    ## which is why the test above it has to be phrased as a property rather
    ## than a value, and why the older version of it was flaky about one run in
    ## eight. Core has the same randomness and pins it the same way:
    ##   src/test/feerounder_tests.cpp
    ##     FastRandomContext rng{/*fDeterministic=*/true};
    ##
    ## Seeding now works, so the same seed must reproduce the same sequence.
    let rounder = newFeeFilterRounder(1000)

    proc sequence(seed: int64): seq[int64] =
      seedNodeRngForTest(seed)
      for _ in 0 ..< 64:
        result.add(rounder.round(1000))

    let a = sequence(20260830)
    let b = sequence(20260830)
    check a == b                       # same seed -> same sequence
    check a.len == 64

    # Control: a DIFFERENT seed must not reproduce it, otherwise the check
    # above would pass for a generator that ignores the seed entirely.
    let c = sequence(20260831)
    check c != a

    # And every draw is still one of Core's two published buckets.
    for v in a: check v == 974'i64 or v == 1071'i64

  test "round quantizes: a value only ever lands on an adjacent bucket":
    ## The privacy property the old test was reaching for, stated so it cannot
    ## flake: whatever the coin flip, the answer is one of the two buckets
    ## bracketing the input — never the exact input, never something further out.
    let rounder = newFeeFilterRounder()
    for input in [1000'i64, 5000'i64, 5100'i64, 123_456'i64]:
      var lo = 0.0
      var hi = 0.0
      for b in rounder.feeBuckets:
        if b <= float64(input): lo = b
        elif hi == 0.0: hi = b
      for _ in 0 ..< 200:
        let r = rounder.round(input)
        check (r == int64(lo) or r == int64(hi))

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
    # FIX-69: default incremental = 100 sat/kvB; required = 100 * 200 / 1000 = 20 sats.
    # Additional fee: 1000 sats >= 20 sats → passes.
    let (ok, error) = checkIncrementalRelayFee(1000, 2000, 200)
    check ok == true
    check error == ""

  test "checkIncrementalRelayFee: equal fees pass Rule #3 but fail Rule #4":
    # Original: 1000 sats, Replacement: 1000 sats.
    # Rule #3: replacement_fees >= original_fees → 1000 >= 1000 → passes (Core uses <, not <=).
    # FIX-69: Rule #4 required = 100 * 200 / 1000 = 20 sats; additional = 0 < 20 → fails.
    # BIP-125 / Bitcoin Core src/policy/rbf.cpp PaysForRBF() line 109.
    let (ok, error) = checkIncrementalRelayFee(1000, 1000, 200)
    check ok == false
    check "additional fee" in error  # Rule #4 fires, not Rule #3

  test "checkIncrementalRelayFee fails if fee lower":
    # replacement < original → Rule #3 rejects.
    let (ok, error) = checkIncrementalRelayFee(1000, 500, 200)
    check ok == false
    check "less than" in error

  test "checkIncrementalRelayFee fails if additional fee too low":
    # Original: 1000 sats, Replacement: 1001 sats, 200 vbytes.
    # FIX-69: default incremental 100 sat/kvB → required = 100 * 200 / 1000 = 20 sats.
    # Additional fee: 1 sat < 20 sats required → rejected.
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
    # FIX-69: default 100 sat/kvB → required = 100 * 10000 / 1000 = 1000 sats.
    # First call: additional = 15000 >> 1000 → accepted.
    let (ok, error) = checkIncrementalRelayFee(5000, 20000, 10000)
    check ok == true  # 15000 > 1000

    # Second call: additional = 5000 >> 1000 → also accepted under
    # FIX-69 defaults. To force rejection on a 10000-vbyte tx we pass a
    # higher incremental rate explicitly.
    let (ok2, error2) = checkIncrementalRelayFee(5000, 5500, 10000)
    check ok2 == false  # additional 500 < required 1000

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
    rm.setMempoolMinFeeRate(50)  # Below default (DefaultMinRelayFee = 100 sat/kvB)
    check rm.mempoolMinFeeRate == DefaultMinRelayFee
    # A value at/above the floor passes through unclamped.
    rm.setMempoolMinFeeRate(5000)
    check rm.mempoolMinFeeRate == 5000

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
  test "default min relay fee is 100 sat/kvB (matches Core DEFAULT_MIN_RELAY_TX_FEE)":
    ## Core: src/policy/policy.h:70 DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB.
    ## Was 1000 sat/kvB (10x Core) before the fee-floor honesty fix; reconciled
    ## with mempool.nim DefaultMinFeeRate = 0.1 sat/vB = 100 sat/kvB.
    check DefaultMinRelayFee == 100

  test "default incremental relay fee is 100 sat/kvB (FIX-69 W120 BUG-1)":
    ## Core: src/policy/policy.h:48 DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.
    ## Was 1000 sat/kvB pre-FIX-69 (10x Core).
    check DefaultIncrementalRelayFee == 100

  test "feefilter interval is 10 minutes":
    check AvgFeefilterBroadcastInterval == 600.0

  test "max feefilter change delay is 5 minutes":
    check MaxFeefilterChangeDelay == 300.0

  test "hysteresis thresholds are correct":
    check FeefilterLowThreshold == 0.75
    check FeefilterHighThreshold == 1.33

when isMainModule:
  waitFor(chronos.sleepAsync(1.milliseconds))  # Initialize chronos
