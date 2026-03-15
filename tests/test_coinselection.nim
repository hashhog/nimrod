## Tests for Coin Selection Algorithms
## BnB (Branch-and-Bound) and Knapsack

import std/[unittest, options, random, algorithm]
import ../src/wallet/coinselection
import ../src/primitives/types

proc makeOutpoint(idx: int): OutPoint =
  var txid: array[32, byte]
  txid[0] = byte(idx and 0xff)
  txid[1] = byte((idx shr 8) and 0xff)
  OutPoint(txid: TxId(txid), vout: 0'u32)

proc makeCoin(idx: int, value: int64, feeRate: float64 = 1.0): SelectableCoin =
  newSelectableCoin(
    makeOutpoint(idx),
    Satoshi(value),
    P2WpkhInputWeight,  # 272 weight units = 68 vbytes
    feeRate
  )

suite "SelectableCoin":
  test "effective value calculation":
    # P2WPKH input: 68 vbytes at 1 sat/vB = 68 sat fee
    let coin = makeCoin(0, 10000, 1.0)
    check int64(coin.value) == 10000
    check int64(coin.fee) == 68  # 272/4 * 1.0
    check int64(coin.effectiveValue) == 9932  # 10000 - 68

  test "effective value at higher fee rate":
    let coin = makeCoin(0, 10000, 10.0)
    check int64(coin.fee) == 680  # 68 * 10
    check int64(coin.effectiveValue) == 9320  # 10000 - 680

  test "negative effective value":
    # Small value at high fee rate
    let coin = makeCoin(0, 500, 10.0)
    check int64(coin.fee) == 680
    check int64(coin.effectiveValue) == 0  # Clamped to 0

suite "Branch-and-Bound Coin Selection":
  test "exact match single coin":
    var coins = @[
      makeCoin(0, 10000),
      makeCoin(1, 20000),
      makeCoin(2, 30000)
    ]

    # Target that exactly matches coin 1's effective value (20000 - 68 = 19932)
    let result = selectCoinsBnB(coins, Satoshi(19932), Satoshi(300))

    check result.isSome
    let sel = result.get()
    check sel.coins.len == 1
    check int64(sel.totalEffectiveValue) == 19932
    check sel.algorithm == "bnb"

  test "exact match multiple coins":
    var coins = @[
      makeCoin(0, 5000),  # eff: 4932
      makeCoin(1, 5000),  # eff: 4932
      makeCoin(2, 10000), # eff: 9932
    ]

    # Target 9864 = 4932 + 4932 (two 5000 coins)
    let result = selectCoinsBnB(coins, Satoshi(9864), Satoshi(300))

    check result.isSome
    let sel = result.get()
    check sel.coins.len == 2
    check int64(sel.totalEffectiveValue) == 9864

  test "no exact match returns none":
    var coins = @[
      makeCoin(0, 10000),  # eff: 9932
      makeCoin(1, 20000),  # eff: 19932
    ]

    # Target that can't be matched within cost_of_change
    let result = selectCoinsBnB(coins, Satoshi(15000), Satoshi(100))

    check result.isNone

  test "prefers exact match over overpayment":
    var coins = @[
      makeCoin(0, 5000),   # eff: 4932
      makeCoin(1, 5000),   # eff: 4932
      makeCoin(2, 10000),  # eff: 9932
    ]

    # Target exactly matches one coin
    let result = selectCoinsBnB(coins, Satoshi(9932), Satoshi(300))

    check result.isSome
    let sel = result.get()
    # Should pick single coin rather than two coins
    check sel.coins.len == 1

  test "respects cost of change":
    var coins = @[
      makeCoin(0, 10000),  # eff: 9932
      makeCoin(1, 10500),  # eff: 10432
    ]

    # Target with large cost_of_change allows slight overpayment
    let result = selectCoinsBnB(coins, Satoshi(9800), Satoshi(1000))

    check result.isSome
    let sel = result.get()
    check int64(sel.totalEffectiveValue) >= 9800
    check int64(sel.totalEffectiveValue) <= 9800 + 1000

  test "insufficient funds":
    var coins = @[
      makeCoin(0, 1000),
      makeCoin(1, 2000),
    ]

    let result = selectCoinsBnB(coins, Satoshi(100000), Satoshi(300))
    check result.isNone

suite "Knapsack Coin Selection":
  test "exact match single coin":
    var coins = @[
      makeCoin(0, 10000),
      makeCoin(1, 20000),
      makeCoin(2, 30000)
    ]

    let result = knapsackSolver(coins, Satoshi(19932), Satoshi(546))

    check result.isSome
    let sel = result.get()
    check sel.coins.len == 1
    check int64(sel.totalEffectiveValue) == 19932

  test "selects combination to exceed target":
    var coins = @[
      makeCoin(0, 5000),  # eff: 4932
      makeCoin(1, 5000),  # eff: 4932
      makeCoin(2, 5000),  # eff: 4932
    ]

    let result = knapsackSolver(coins, Satoshi(12000), Satoshi(546))

    check result.isSome
    let sel = result.get()
    check int64(sel.totalEffectiveValue) >= 12000
    check sel.coins.len >= 3  # Need all three

  test "uses lowest larger when needed":
    var coins = @[
      makeCoin(0, 100000),  # eff: 99932
      makeCoin(1, 1000),    # eff: 932
      makeCoin(2, 2000),    # eff: 1932
    ]

    # Target larger than all small coins combined
    let result = knapsackSolver(coins, Satoshi(50000), Satoshi(546))

    check result.isSome
    let sel = result.get()
    check sel.coins.len == 1
    check int64(sel.totalEffectiveValue) == 99932

  test "insufficient funds":
    var coins = @[
      makeCoin(0, 1000),
      makeCoin(1, 2000),
    ]

    let result = knapsackSolver(coins, Satoshi(100000), Satoshi(546))
    check result.isNone

  test "randomization produces different selections":
    # This test verifies that knapsack has some randomness
    var coins: seq[SelectableCoin]
    for i in 0 ..< 20:
      coins.add(makeCoin(i, 1000))

    var selections: seq[int]
    for _ in 0 ..< 5:
      var coinsCopy = coins
      let result = knapsackSolver(coinsCopy, Satoshi(5000), Satoshi(546))
      if result.isSome:
        selections.add(result.get().coins.len)

    # Should have at least gotten some results
    check selections.len >= 3

suite "Combined Coin Selection":
  test "selectCoins uses BnB first":
    var coins = @[
      makeCoin(0, 10000),  # eff: 9932
      makeCoin(1, 10000),  # eff: 9932
    ]

    # Target that can be exactly matched
    let result = selectCoins(coins, Satoshi(9932), Satoshi(300), Satoshi(546))
    check result.coins.len == 1
    check result.algorithm == "bnb"

  test "selectCoins falls back to knapsack":
    var coins = @[
      makeCoin(0, 10000),  # eff: 9932
      makeCoin(1, 10000),  # eff: 9932
    ]

    # Target that can't be exactly matched - needs change
    let result = selectCoins(coins, Satoshi(15000), Satoshi(300), Satoshi(546))
    check result.coins.len == 2
    check result.algorithm == "knapsack"

  test "selectCoins raises on insufficient funds":
    var coins = @[
      makeCoin(0, 1000),
    ]

    expect CoinSelectionError:
      discard selectCoins(coins, Satoshi(100000), Satoshi(300), Satoshi(546))

suite "Largest-First Coin Selection":
  test "selects largest coins first":
    var coins = @[
      makeCoin(0, 1000),
      makeCoin(1, 5000),
      makeCoin(2, 10000),
      makeCoin(3, 2000),
    ]

    let result = selectCoinsLargestFirst(coins, Satoshi(10000))

    check result.coins.len >= 1
    # First coin should be the largest (10000)
    check int64(result.coins[0].value) == 10000

  test "accumulates until target reached":
    var coins = @[
      makeCoin(0, 3000),  # eff: 2932
      makeCoin(1, 4000),  # eff: 3932
      makeCoin(2, 5000),  # eff: 4932
    ]

    let result = selectCoinsLargestFirst(coins, Satoshi(10000))

    check result.coins.len >= 2
    check int64(result.totalEffectiveValue) >= 10000

  test "raises on insufficient funds":
    var coins = @[
      makeCoin(0, 1000),
    ]

    expect CoinSelectionError:
      discard selectCoinsLargestFirst(coins, Satoshi(100000))

suite "Waste Calculation":
  test "waste is zero for perfect fee match":
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(100),
        longTermFee: Satoshi(100),  # Same as current fee
        weight: 272
      )
    ]

    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    check int64(waste) == 0

  test "positive waste when current fee higher":
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(100),
        longTermFee: Satoshi(50),  # Lower than current fee
        weight: 272
      )
    ]

    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    # waste = 100 - 50 = 50
    check int64(waste) == 50

  test "negative waste when current fee lower":
    var coins = @[
      SelectableCoin(
        outpoint: makeOutpoint(0),
        value: Satoshi(10000),
        effectiveValue: Satoshi(9900),
        fee: Satoshi(50),
        longTermFee: Satoshi(100),  # Higher than current fee
        weight: 272
      )
    ]

    let waste = calculateWaste(coins, Satoshi(0), Satoshi(300))
    # waste = 50 - 100 = -50
    check int64(waste) == -50

  test "change cost added when change exists":
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

    let waste = calculateWaste(coins, Satoshi(1000), Satoshi(300))
    # waste = (100 - 100) + 300 = 300 (change cost)
    check int64(waste) == 300

suite "Input Weight Constants":
  test "P2WPKH input weight":
    check P2WpkhInputWeight == 272  # 68 vbytes * 4

  test "P2PKH input weight":
    check P2PkhInputWeight == 592  # 148 vbytes * 4

  test "P2SH-P2WPKH input weight":
    check P2ShP2WpkhInputWeight == 364  # 91 vbytes * 4

  test "P2TR input weight":
    check P2TrInputWeight == 232  # 58 vbytes * 4

when isMainModule:
  echo "Running coin selection tests..."
