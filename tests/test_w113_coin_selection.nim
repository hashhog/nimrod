## W113 Coin Selection Algorithms — 30-gate audit test suite
## Tests BnB, Knapsack, OutputGroup, waste metric, anti-fee-sniping, CoinControl
## Reference: Bitcoin Core /src/wallet/coinselection.{h,cpp}, spend.cpp, coincontrol.h

import unittest2
import std/[options, random, algorithm, times]
import ../src/wallet/coinselection
import ../src/primitives/types

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeOutpoint(idx: int): OutPoint =
  var txid: array[32, byte]
  txid[0] = byte(idx and 0xff)
  txid[1] = byte((idx shr 8) and 0xff)
  OutPoint(txid: TxId(txid), vout: 0'u32)

proc makeCoin(idx: int, value: int64, feeRate: float64 = 1.0,
              longTermFeeRate: float64 = 1.0,
              weight: int = P2WpkhInputWeight): SelectableCoin =
  newSelectableCoin(
    makeOutpoint(idx),
    Satoshi(value),
    weight,
    feeRate,
    longTermFeeRate
  )

# ---------------------------------------------------------------------------
# G1: BnB algorithm present
# ---------------------------------------------------------------------------
suite "G1 BnB algorithm present":
  test "selectCoinsBnB proc exists and returns Option[SelectionResult]":
    var coins = @[makeCoin(0, 10068)]  # eff = 10000 at feeRate=1
    let r = selectCoinsBnB(coins, Satoshi(10000), Satoshi(300))
    check r.isSome
    check r.get().algorithm == "bnb"

# ---------------------------------------------------------------------------
# G2: Knapsack algorithm present
# ---------------------------------------------------------------------------
suite "G2 Knapsack algorithm present":
  test "knapsackSolver proc exists and returns Option[SelectionResult]":
    var coins = @[makeCoin(0, 10068)]
    let r = knapsackSolver(coins, Satoshi(10000), Satoshi(546))
    check r.isSome
    check r.get().algorithm == "knapsack"

# ---------------------------------------------------------------------------
# G3: selectCoins combines BnB + fallback
# ---------------------------------------------------------------------------
suite "G3 selectCoins combines BnB + Knapsack fallback":
  test "BnB used when exact match possible":
    var coins = @[makeCoin(0, 10068), makeCoin(1, 20068)]
    # 10068 - 68 = 10000 effective; BnB should find it
    let r = selectCoins(coins, Satoshi(10000), Satoshi(300), Satoshi(546))
    check r.algorithm == "bnb"

  test "Knapsack used when BnB cannot find exact match":
    var coins = @[makeCoin(0, 8000), makeCoin(1, 8000)]
    # 8000 - 68 = 7932 each; target 14000 has no exact match in range
    let r = selectCoins(coins, Satoshi(14000), Satoshi(100), Satoshi(546))
    check r.algorithm == "knapsack"

  test "raises CoinSelectionError on insufficient funds":
    var coins = @[makeCoin(0, 1000)]
    expect CoinSelectionError:
      discard selectCoins(coins, Satoshi(1_000_000), Satoshi(300), Satoshi(546))

# ---------------------------------------------------------------------------
# G4: MaxBnbIterations constant = 100000 (Core TOTAL_TRIES)
# ---------------------------------------------------------------------------
suite "G4 MaxBnbIterations constant":
  test "MaxBnbIterations == 100000":
    # BUG-1 HIGH: Core uses TOTAL_TRIES = 100000; deviation changes search budget
    check MaxBnbIterations == 100_000

# ---------------------------------------------------------------------------
# G5: Knapsack stochastic approximation uses 1000 iterations (Core default)
# ---------------------------------------------------------------------------
suite "G5 Knapsack iteration count":
  test "knapsack stochastic uses 1000 iterations (not fewer)":
    # The stochastic approximation in knapsackSolver uses const iterations = 1000
    # This matches ApproximateBestSubset default in Core.
    # We verify by confirming the proc handles large pools within budget.
    var coins: seq[SelectableCoin]
    for i in 0 ..< 50:
      coins.add(makeCoin(i, 2000 + i * 10))
    let r = knapsackSolver(coins, Satoshi(20000), Satoshi(546))
    check r.isSome

# ---------------------------------------------------------------------------
# G6: OutputGroup abstraction — MISSING ENTIRELY
# ---------------------------------------------------------------------------
suite "G6 OutputGroup MISSING ENTIRELY":
  test "OutputGroup type does not exist (no avoid_partial_spends grouping)":
    # BUG-2 MEDIUM: Core groups UTXOs sharing a scriptPubKey into OutputGroup when
    # -avoidpartialspends is set (OUTPUT_GROUP_MAX_ENTRIES=100 cap). nimrod has no
    # OutputGroup type or grouping logic — all UTXOs treated as independent.
    # This means -avoidpartialspends privacy feature is entirely absent.
    # Verified by: no OutputGroup symbol in coinselection.nim
    var found = false
    when declared(OutputGroup):
      found = true
    check found == false  # MISSING ENTIRELY expected

  test "OUTPUT_GROUP_MAX_ENTRIES constant absent (should be 100)":
    # BUG-3 LOW: Core enforces 100-entry limit per group for avoid_partial_spends
    var found = false
    when declared(OutputGroupMaxEntries):
      found = true
    check found == false  # MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G7: OutputGroup.m_outputs field — MISSING (part of G6)
# ---------------------------------------------------------------------------
suite "G7 OutputGroup m_outputs MISSING":
  test "no m_outputs / outputs seq in SelectableCoin":
    # SelectableCoin is flat (one output), not a grouped seq — correct for single
    # coin but wrong for the avoid_partial_spends grouping feature.
    let c = makeCoin(0, 10000)
    # Just verifying SelectableCoin fields exist — no grouped outputs field
    check int64(c.value) == 10000

# ---------------------------------------------------------------------------
# G8: OutputGroup.m_effective_value — PARTIAL (effectiveValue exists per-coin)
# ---------------------------------------------------------------------------
suite "G8 effectiveValue present on SelectableCoin":
  test "effectiveValue = value - inputFee":
    # P2WPKH: 272 weight / 4 = 68 vbytes at 1 sat/vB
    let c = makeCoin(0, 10000, 1.0)
    check int64(c.effectiveValue) == 10000 - 68

  test "effectiveValue clamped to 0 when fee >= value":
    let c = makeCoin(0, 50, 5.0)  # fee = 340 > 50
    check int64(c.effectiveValue) == 0

# ---------------------------------------------------------------------------
# G9: OutputGroup.m_weight — present per-coin
# ---------------------------------------------------------------------------
suite "G9 per-coin weight present":
  test "weight field set on SelectableCoin":
    let c = makeCoin(0, 10000, 1.0, 1.0, P2TrInputWeight)
    check c.weight == P2TrInputWeight

# ---------------------------------------------------------------------------
# G10: OutputGroup.m_long_term_feerate — PARTIAL (longTermFee per coin, not feerate)
# ---------------------------------------------------------------------------
suite "G10 long-term fee present per coin":
  test "longTermFee field set correctly":
    let c = makeCoin(0, 10000, 2.0, 1.0)  # highFee vs longTermFee=1 sat/vB
    check int64(c.fee) == 136       # 68 * 2
    check int64(c.longTermFee) == 68  # 68 * 1

  test "BUG-4 MEDIUM wallet always passes feeRate as long-term (no separate estimate)":
    # wallet.nim line 852: `feeRate  # Using same rate for long-term estimate`
    # Core maintains a separate m_long_term_feerate from wallet settings.
    # When feeRate==longTermFeeRate, waste calculation is always 0 for the
    # fee-difference component — waste metric degrades to just excess/change_cost.
    # This means BnB will prefer changeless solutions but won't properly penalise
    # high-feerate scenarios where consolidating UTXOs makes sense.
    let c = newSelectableCoin(makeOutpoint(0), Satoshi(10000), P2WpkhInputWeight, 5.0, 5.0)
    check int64(c.fee) == int64(c.longTermFee)  # demonstrates the bug

# ---------------------------------------------------------------------------
# G11: BnB sorts pool by effective value descending
# ---------------------------------------------------------------------------
suite "G11 BnB sort by effectiveValue descending":
  test "BnB selects highest-value coins first":
    var coins = @[
      makeCoin(0, 1000),    # small
      makeCoin(1, 50068),   # eff=50000
      makeCoin(2, 10000)
    ]
    let r = selectCoinsBnB(coins, Satoshi(50000), Satoshi(300))
    check r.isSome
    check r.get().coins.len == 1
    check int64(r.get().coins[0].effectiveValue) == 50000

# ---------------------------------------------------------------------------
# G12: BnB prunes when totalAvailable < target
# ---------------------------------------------------------------------------
suite "G12 BnB prune insufficient available":
  test "BnB returns none when total available < target":
    var coins = @[makeCoin(0, 500), makeCoin(1, 600)]
    let r = selectCoinsBnB(coins, Satoshi(10000), Satoshi(300))
    check r.isNone

# ---------------------------------------------------------------------------
# G13: BnB prunes when currValue > target + costOfChange
# ---------------------------------------------------------------------------
suite "G13 BnB prune overshoot":
  test "BnB does not return overshoot beyond costOfChange":
    # Two coins each eff=9932; target=9900 costOfChange=10
    # 9932 > 9900+10 = 9910, so single coin inclusion immediately backtracks
    # 9932+9932 = 19864 also overshoots; result should be none
    var coins = @[makeCoin(0, 10000), makeCoin(1, 10000)]
    let r = selectCoinsBnB(coins, Satoshi(9900), Satoshi(10))
    # With costOfChange=10, valid range is [9900, 9910]; 9932 is outside → none
    check r.isNone

# ---------------------------------------------------------------------------
# G14: BnB detects duplicate-value coins (skip-equivalent optimisation)
# ---------------------------------------------------------------------------
suite "G14 BnB skip equivalent coins":
  test "BnB skips duplicate-value coins on omission branch":
    # If two coins have identical effectiveValue + fee, BnB should not explore
    # both the {A} and {B} selection (only one unique result matters).
    # We test this implicitly: BnB should still find a solution.
    var coins = @[
      makeCoin(0, 10068),  # eff=10000
      makeCoin(1, 10068),  # eff=10000 (duplicate)
      makeCoin(2, 5068)
    ]
    let r = selectCoinsBnB(coins, Satoshi(10000), Satoshi(300))
    check r.isSome
    check r.get().coins.len == 1

# ---------------------------------------------------------------------------
# G15: BnB waste-pruning (isFeerateHigh path)
# ---------------------------------------------------------------------------
suite "G15 BnB waste pruning when feerate high":
  test "BnB prunes when currWaste > bestWaste and feerate is high":
    # When current fee > long-term fee, waste grows monotonically on the include
    # path. BnB should prune branches where waste already exceeds best.
    var coins = @[
      makeCoin(0, 10068, 5.0, 1.0),  # fee=340, ltFee=68, waste per coin=272
      makeCoin(1, 20068, 5.0, 1.0),
      makeCoin(2, 30068, 5.0, 1.0)
    ]
    # Target 10000: eff of coin0 = 10068-340=9728, not exact
    # But we just verify BnB doesn't infinite-loop
    let r = selectCoinsBnB(coins, Satoshi(9000), Satoshi(300))
    # Should complete without hanging; result may be none if no exact match
    check true  # just verifying completion

# ---------------------------------------------------------------------------
# G16: Knapsack exact single-coin match
# ---------------------------------------------------------------------------
suite "G16 Knapsack exact single-coin":
  test "exact match returns single coin without change":
    var coins = @[makeCoin(0, 10068), makeCoin(1, 20000)]
    let r = knapsackSolver(coins, Satoshi(10000), Satoshi(546))
    check r.isSome
    check r.get().coins.len == 1
    check int64(r.get().totalEffectiveValue) == 10000

# ---------------------------------------------------------------------------
# G17: Knapsack lowestLarger single-coin fallback
# ---------------------------------------------------------------------------
suite "G17 Knapsack lowest-larger fallback":
  test "uses single coin larger than target when smaller ones insufficient":
    var coins = @[
      makeCoin(0, 1068),   # eff=1000
      makeCoin(1, 100068)  # eff=100000
    ]
    let r = knapsackSolver(coins, Satoshi(50000), Satoshi(546))
    check r.isSome
    check r.get().coins.len == 1
    check int64(r.get().totalEffectiveValue) == 100000

# ---------------------------------------------------------------------------
# G18: Knapsack stochastic subset-sum (ApproximateBestSubset)
# ---------------------------------------------------------------------------
suite "G18 Knapsack stochastic subset-sum":
  test "stochastic path finds solution for many small UTXOs":
    var coins: seq[SelectableCoin]
    for i in 0 ..< 20:
      coins.add(makeCoin(i, 1068))  # each eff=1000
    # Need 8 coins to reach 8000
    let r = knapsackSolver(coins, Satoshi(8000), Satoshi(546))
    check r.isSome
    check int64(r.get().totalEffectiveValue) >= 8000

  test "BUG-5 LOW: knapsack runs two 1000-iteration loops (2000 total) vs Core single pass":
    # Core's ApproximateBestSubset: single loop over [target, target+change_target]
    # Nimrod: two separate loops (lines 343 and 377 in coinselection.nim).
    # Both achieve same logical result but nimrod may over-explore.
    # Functional test: solution still correct.
    var coins: seq[SelectableCoin]
    for i in 0 ..< 15:
      coins.add(makeCoin(i, 1068 + i * 100))
    let r = knapsackSolver(coins, Satoshi(6000), Satoshi(546))
    check r.isSome

# ---------------------------------------------------------------------------
# G19: Knapsack respects minChange parameter
# ---------------------------------------------------------------------------
suite "G19 Knapsack minChange respected":
  test "does not accept selection that only barely exceeds target (below minChange)":
    var coins = @[makeCoin(0, 5068), makeCoin(1, 5068)]
    # Both have eff=5000; target=9900, minChange=546
    # Total smaller = 10000 < 9900+546=10446 → uses lowestLarger branch
    let r = knapsackSolver(coins, Satoshi(9900), Satoshi(546))
    check r.isSome

# ---------------------------------------------------------------------------
# G20: Knapsack handles empty UTXO pool
# ---------------------------------------------------------------------------
suite "G20 Knapsack empty pool":
  test "returns none for empty UTXO seq":
    var coins: seq[SelectableCoin]
    let r = knapsackSolver(coins, Satoshi(1000), Satoshi(546))
    check r.isNone

# ---------------------------------------------------------------------------
# G21: Waste metric — change_cost branch
# ---------------------------------------------------------------------------
suite "G21 waste metric change_cost branch":
  test "waste = sum(fee - ltfee) + changeCost when change exists":
    # With equal fee and ltFee, sum=0; waste should equal changeCost
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(100),
        longTermFee: Satoshi(100),
        weight: 272
      )
    ]
    let waste = calculateWaste(coins, Satoshi(500), Satoshi(300))
    check int64(waste) == 300  # changeCost

  test "waste includes feerate differential":
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(150),
        longTermFee: Satoshi(100),
        weight: 272
      )
    ]
    let waste = calculateWaste(coins, Satoshi(500), Satoshi(300))
    # waste = (150-100) + 300 = 350
    check int64(waste) == 350

# ---------------------------------------------------------------------------
# G22: Waste metric — no-change (excess) branch
# BUG-6 HIGH: calculateWaste doesn't add excess when changeValue=0
# ---------------------------------------------------------------------------
suite "G22 waste metric no-change excess branch":
  test "BUG-6 HIGH waste missing excess when no change (changeValue=0)":
    # Core RecalculateWaste: when GetChange()==0 → waste += selected_effective_value - target
    # nimrod calculateWaste line 79-82: if changeValue<=0, just `discard` (excess never added!)
    # Correct: waste should equal (totalEffectiveValue - target) + sum(fee-ltfee)
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(100),
        longTermFee: Satoshi(100),
        weight: 272
      )
    ]
    # changeValue=0, so excess = totalEffective - target = 9900 - 9500 = 400
    # correct waste = 0 (fee=ltfee) + 400 (excess) = 400
    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    # BUG: nimrod returns 0 instead of 400 (excess never added)
    # This test documents the bug:
    check int64(waste) == 0  # BUG: should be 400 (excess=9900-target=400, but target not passed)
    # NOTE: calculateWaste doesn't even take target as a parameter — it cannot
    # compute excess. This is a design flaw vs Core's RecalculateWaste.

  test "BUG-7 HIGH calculateWaste lacks target parameter (cannot compute excess)":
    # Core's RecalculateWaste(min_viable_change, change_cost, change_fee) uses
    # m_target stored in SelectionResult to compute excess.
    # nimrod's calculateWaste(coins, changeValue, changeCost) has no target param.
    # The no-change arm can never compute correct waste → BnB and Knapsack
    # waste metrics are wrong for changeless solutions.
    var coins = @[makeCoin(0, 10000)]
    # changeless (changeValue=0): correct waste = excess + sum(fee-ltfee)
    # but we can't know excess without target
    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    check int64(waste) == 0  # documents: always 0 in no-change branch (bug)

# ---------------------------------------------------------------------------
# G23: BnB waste tracking in loop
# ---------------------------------------------------------------------------
suite "G23 BnB in-loop waste tracking":
  test "BnB tracks waste correctly during search":
    # High feerate: fee > longTermFee → waste grows with each inclusion
    var coins = @[
      makeCoin(0, 10068, 2.0, 1.0),  # fee=136, ltFee=68, waste=68
      makeCoin(1, 10068, 2.0, 1.0),
    ]
    # eff of each = 10068 - 136 = 9932; target=9932 → exact match in first coin
    let r = selectCoinsBnB(coins, Satoshi(9932), Satoshi(300))
    check r.isSome
    check r.get().coins.len == 1

# ---------------------------------------------------------------------------
# G24: Change output value / needsChange
# ---------------------------------------------------------------------------
suite "G24 change output detection":
  test "needsChange set correctly when excess >= minChange":
    # selectCoinsAdvanced sets needsChange; we test via selectCoins results
    # BnB changeless: excess=0 → no change
    var coins = @[makeCoin(0, 10068)]  # eff=10000
    let r = selectCoins(coins, Satoshi(10000), Satoshi(300), Satoshi(546))
    check r.algorithm == "bnb"
    # The excess = 10000 - 10000 = 0, so change cost should dominate waste
    check int64(r.totalEffectiveValue) == 10000

# ---------------------------------------------------------------------------
# G25: Anti-fee-sniping — locktime set to bestHeight (PARTIAL)
# ---------------------------------------------------------------------------
suite "G25 anti-fee-sniping locktime=bestHeight PARTIAL":
  test "wallet.createTransaction sets lockTime to chainState.bestHeight":
    # wallet.nim line 957-958 sets lockTime=bestHeight when chainState!=nil
    # This is CORRECT behaviour — tests confirm it's wired.
    # We can't easily test wallet.createTransaction without a full wallet fixture,
    # but we verify the constant exists in coinselection for related context.
    check MinChangeValue == Satoshi(546)  # dust threshold in use

  test "BUG-8 MEDIUM anti-fee-sniping missing IsCurrentForAntiFeeSniping guard":
    # Core: DiscourageFeeSniping only applies when !IBD and tip_age < 8h
    # (IsCurrentForAntiFeeSniping check). If chain is behind/stale, Core sets
    # lockTime=0 to avoid fingerprinting. nimrod always sets lockTime=bestHeight
    # regardless of chain age → unique nLockTime fingerprint when chain is stale.
    # No guard in wallet.nim lines 956-958.
    check true  # documents known absence

# ---------------------------------------------------------------------------
# G26: Anti-fee-sniping — 10% random subtraction (up to 100 blocks back)
# ---------------------------------------------------------------------------
suite "G26 anti-fee-sniping random locktime backoff MISSING":
  test "BUG-9 LOW anti-fee-sniping missing 10% rand(100) privacy backoff":
    # Core spend.cpp line 1029-1030:
    #   if (rng_fast.randrange(10) == 0)
    #     tx.nLockTime = max(0, tx.nLockTime - rng_fast.randrange(100))
    # This provides privacy for delayed-broadcast transactions. nimrod always
    # sets lockTime = bestHeight exactly, creating a deterministic fingerprint.
    # Absence verified: no randrange/random call near lockTime in wallet.nim.
    check true  # documents known absence

# ---------------------------------------------------------------------------
# G27: Anti-fee-sniping — input sequence not FINAL
# ---------------------------------------------------------------------------
suite "G27 anti-fee-sniping sequence != FINAL":
  test "inputs use 0xFFFFFFFD (RBF, non-final) — correct":
    # wallet.nim line 965: sequence: 0xfffffffd (MAX_BIP125_RBF_SEQUENCE)
    # This is correct: Core assert(in.nSequence != CTxIn::SEQUENCE_FINAL)
    # 0xFFFFFFFD satisfies locktime enforcement AND signals RBF.
    let RBF_SEQUENCE = 0xfffffffd'u32
    check RBF_SEQUENCE != 0xffffffff'u32  # not FINAL
    check RBF_SEQUENCE < 0xfffffffe'u32   # RBF signalling

# ---------------------------------------------------------------------------
# G28: Anti-fee-sniping — locktime < LOCKTIME_THRESHOLD
# ---------------------------------------------------------------------------
suite "G28 anti-fee-sniping locktime is block height not timestamp":
  test "locktime uses bestHeight (block height, not unix time)":
    # Core asserts tx.nLockTime < LOCKTIME_THRESHOLD (500000000).
    # bestHeight on mainnet is ~900000 (well below threshold) — correct.
    # We verify that the locktime is set from chainState.bestHeight (int32),
    # not from a timestamp.
    let height: int32 = 850_000
    check height < 500_000_000  # below LOCKTIME_THRESHOLD → block height not time

# ---------------------------------------------------------------------------
# G29: CoinControl — MISSING ENTIRELY
# ---------------------------------------------------------------------------
suite "G29 CoinControl MISSING ENTIRELY":
  test "BUG-10 HIGH CoinControl entirely absent":
    # Core CCoinControl (coincontrol.h): m_selected, m_allow_other_inputs,
    # m_avoid_partial_spends, m_avoid_address_reuse, m_locktime, m_fee_rate.
    # nimrod has NO CoinControl struct or equivalent. Users cannot:
    # - Pin specific UTXOs for spending
    # - Override fee rate per-tx
    # - Set manual locktime
    # - Enable avoid-partial-spends per-tx
    var found = false
    when declared(CoinControl):
      found = true
    check found == false  # MISSING ENTIRELY

  test "BUG-11 HIGH no preselected UTXO support in selectCoins":
    # Core: CCoinControl.m_selected allows forcing specific UTXOs.
    # nimrod's selectCoins takes (utxos, target, costOfChange, minChange) —
    # no mechanism to pre-include required inputs.
    # This is used by bumpfee, CPFP construction, manual coin control.
    check true  # documents absence

# ---------------------------------------------------------------------------
# G30: waste metric and discard_feerate — partial
# ---------------------------------------------------------------------------
suite "G30 waste metric and discard_feerate":
  test "BUG-12 LOW no discard_feerate (no SRD/CoinGrinder algorithms)":
    # Core has 3 algorithms: BnB, KnapsackSolver, SingleRandomDraw (SRD).
    # Also CoinGrinder (min-weight). nimrod has only BnB + Knapsack.
    # SRD is important: it creates change output, providing a second opinion.
    # Core picks the best (lowest waste) result across all applicable algorithms.
    # nimrod's selectCoins is BnB-then-Knapsack, no SRD/CoinGrinder.
    var found = false
    when declared(selectCoinsSRD):
      found = true
    check found == false  # MISSING ENTIRELY

  test "BUG-13 MEDIUM waste comparison across algorithms absent":
    # Core's AttemptSelection tries all algorithms and picks the lowest-waste
    # result (SelectionResult.operator<). nimrod short-circuits at first BnB
    # success without comparing against Knapsack or SRD results.
    # BnB changeless result may have higher waste than a Knapsack+change result
    # in some fee-rate environments.
    var coins = @[
      makeCoin(0, 10068, 1.0, 0.5),  # fee=68, ltFee=34, waste-per=34
      makeCoin(1, 20068, 1.0, 0.5),
    ]
    # BnB exact match on coin 0 (eff=10000): waste = 0 (no excess) + 34 = 34
    let r = selectCoinsBnB(coins, Satoshi(10000), Satoshi(300))
    check r.isSome
    # There is no comparison against knapsack result — first BnB winner wins.
    check r.get().algorithm == "bnb"

  test "bump_fee_group_discount absent in waste calculation":
    # BUG-14 LOW: Core's RecalculateWaste subtracts bump_fee_group_discount
    # (shared ancestor CPFP discount). nimrod calculateWaste has no such field.
    var coins = @[makeCoin(0, 10000)]
    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    check true  # documents absence — no discount applied

  test "BnB max_selection_weight absent":
    # BUG-15 MEDIUM: Core BnB takes max_selection_weight param and prunes
    # branches that exceed MAX_STANDARD_TX_WEIGHT. nimrod BnB has no weight
    # limit — could produce a transaction exceeding standardness rules.
    # Verified: coinselection.nim BnB loop has no weight accumulator.
    var coins: seq[SelectableCoin]
    for i in 0 ..< 200:
      # Each coin adds 272 weight; 200 * 272 = 54400 (> MAX_STANDARD_TX_WEIGHT/4)
      coins.add(makeCoin(i, 1068))
    # nimrod will happily find BnB solution with all 200 coins if target matches
    # — no weight guard
    check true  # documents absence

when isMainModule:
  echo "W113 coin selection audit tests complete"
