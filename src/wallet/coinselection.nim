## Coin Selection Algorithms
## Implements Branch-and-Bound (BnB) and Knapsack coin selection
## Reference: Bitcoin Core /src/wallet/coinselection.cpp

import std/[algorithm, options, random]
import ../primitives/types

type
  CoinSelectionError* = object of CatchableError

  ## A coin available for selection with effective value calculated
  SelectableCoin* = object
    outpoint*: OutPoint
    value*: Satoshi              ## Actual output value
    effectiveValue*: Satoshi     ## Value minus input fee cost
    fee*: Satoshi                ## Fee cost to spend this input
    longTermFee*: Satoshi        ## Long-term fee estimate
    weight*: int                 ## Input weight (vsize * 4)

  ## Result of coin selection
  SelectionResult* = object
    coins*: seq[SelectableCoin]  ## Selected coins
    totalValue*: Satoshi         ## Sum of selected values
    totalEffectiveValue*: Satoshi ## Sum of effective values
    totalFee*: Satoshi           ## Total input fees
    waste*: Satoshi              ## Waste metric
    algorithm*: string           ## Algorithm used

const
  ## Maximum number of iterations for BnB search
  MaxBnbIterations* = 100_000

  ## Minimum change output value to avoid dust
  MinChangeValue* = Satoshi(546)

  ## Weight of a P2WPKH input (68 vbytes * 4)
  P2WpkhInputWeight* = 272

  ## Weight of a P2PKH input (148 vbytes * 4)
  P2PkhInputWeight* = 592

  ## Weight of a P2SH-P2WPKH input (91 vbytes * 4)
  P2ShP2WpkhInputWeight* = 364

  ## Weight of a P2TR input (58 vbytes * 4)
  P2TrInputWeight* = 232

  ## Weight of a P2WPKH output (31 vbytes * 4)
  P2WpkhOutputWeight* = 124

  ## Weight of a P2PKH output (34 vbytes * 4)
  P2PkhOutputWeight* = 136

  ## Transaction overhead weight (version + locktime + segwit marker)
  TxOverheadWeight* = 42

proc calculateEffectiveValue*(value: Satoshi, inputWeight: int, feeRate: float64): Satoshi =
  ## Calculate effective value: value - (inputWeight/4 * feeRate)
  ## feeRate is in sat/vbyte
  let inputFee = int64((float64(inputWeight) / 4.0) * feeRate)
  result = Satoshi(int64(value) - inputFee)

proc calculateInputFee*(inputWeight: int, feeRate: float64): Satoshi =
  ## Calculate fee for a single input
  Satoshi(int64((float64(inputWeight) / 4.0) * feeRate))

proc calculateWaste*(coins: seq[SelectableCoin], changeValue: Satoshi, changeCost: Satoshi): Satoshi =
  ## Calculate waste metric for a selection
  ## waste = sum(fee - longTermFee) + (change > 0 ? changeCost : excess)
  var waste = int64(0)

  # Sum up fee - longTermFee for each input
  for coin in coins:
    waste += int64(coin.fee) - int64(coin.longTermFee)

  # Add change cost or excess
  if int64(changeValue) > 0:
    waste += int64(changeCost)
  else:
    # No change means we're paying the excess as fee
    # This is calculated by caller as: totalEffective - target
    discard

  Satoshi(waste)

proc newSelectableCoin*(outpoint: OutPoint, value: Satoshi, inputWeight: int,
                        feeRate: float64, longTermFeeRate: float64 = 0): SelectableCoin =
  ## Create a selectable coin with calculated effective value
  let fee = calculateInputFee(inputWeight, feeRate)
  let ltFee = if longTermFeeRate > 0:
    calculateInputFee(inputWeight, longTermFeeRate)
  else:
    fee

  SelectableCoin(
    outpoint: outpoint,
    value: value,
    effectiveValue: Satoshi(max(0'i64, int64(value) - int64(fee))),
    fee: fee,
    longTermFee: ltFee,
    weight: inputWeight
  )

proc selectCoinsBnB*(utxos: var seq[SelectableCoin], target: Satoshi,
                      costOfChange: Satoshi): Option[SelectionResult] =
  ## Branch-and-Bound coin selection algorithm
  ## Searches for an exact match (no change output needed)
  ##
  ## The algorithm:
  ## 1. Sort UTXOs by effective value (descending)
  ## 2. Use depth-first search with backtracking
  ## 3. Try including each UTXO, then excluding
  ## 4. Prune branches that can't reach target
  ## 5. Track best solution by waste metric
  ##
  ## Reference: Bitcoin Core SelectCoinsBnB in coinselection.cpp

  # Filter out coins with non-positive effective value
  var pool: seq[SelectableCoin]
  for utxo in utxos:
    if int64(utxo.effectiveValue) > 0:
      pool.add(utxo)

  if pool.len == 0:
    return none(SelectionResult)

  # Sort by effective value descending
  pool.sort(proc(a, b: SelectableCoin): int =
    cmp(int64(b.effectiveValue), int64(a.effectiveValue)))

  let targetVal = int64(target)
  let costOfChangeVal = int64(costOfChange)

  # Calculate total available value
  var totalAvailable: int64 = 0
  for utxo in pool:
    totalAvailable += int64(utxo.effectiveValue)

  if totalAvailable < targetVal:
    return none(SelectionResult)

  # BnB search state
  var currSelection: seq[int]      # Indices of selected UTXOs
  var currValue: int64 = 0
  var currWaste: int64 = 0
  var currAvailable = totalAvailable

  var bestSelection: seq[int]
  var bestWaste: int64 = int64.high

  # Check if current fee rate is higher than long-term fee rate
  let isFeerateHigh = pool[0].fee > pool[0].longTermFee

  var idx = 0
  var tries = 0

  while tries < MaxBnbIterations:
    inc tries

    # Check conditions for backtracking
    var backtrack = false

    if currValue + currAvailable < targetVal:
      # Cannot reach target with remaining coins
      backtrack = true
    elif currValue > targetVal + costOfChangeVal:
      # Selected too much
      backtrack = true
    elif currWaste > bestWaste and isFeerateHigh:
      # Waste already worse than best and will only increase
      backtrack = true
    elif currValue >= targetVal and currValue <= targetVal + costOfChangeVal:
      # Valid solution found!
      let excessWaste = currValue - targetVal
      let totalWaste = currWaste + excessWaste

      if totalWaste <= bestWaste:
        bestSelection = currSelection
        bestWaste = totalWaste

      backtrack = true

    if backtrack:
      if currSelection.len == 0:
        # Exhausted search space
        break

      # Backtrack: restore available value for skipped coins
      while idx > currSelection[^1] + 1:
        dec idx
        currAvailable += int64(pool[idx].effectiveValue)

      # Remove last selected coin
      let lastIdx = currSelection[^1]
      currValue -= int64(pool[lastIdx].effectiveValue)
      currWaste -= int64(pool[lastIdx].fee) - int64(pool[lastIdx].longTermFee)
      currSelection.setLen(currSelection.len - 1)

      idx = lastIdx + 1
      if idx >= pool.len:
        continue

    # Check if we've exhausted the pool
    if idx >= pool.len:
      if currSelection.len == 0:
        break

      # Backtrack to try omission branch
      let lastIdx = currSelection[^1]
      currValue -= int64(pool[lastIdx].effectiveValue)
      currWaste -= int64(pool[lastIdx].fee) - int64(pool[lastIdx].longTermFee)
      currSelection.setLen(currSelection.len - 1)

      idx = lastIdx + 1
      continue

    # Remove this UTXO from available
    currAvailable -= int64(pool[idx].effectiveValue)

    # Skip equivalent coins (same effective value and fee)
    var skipEquivalent = false
    if currSelection.len > 0 and idx > 0:
      let prevIdx = idx - 1
      if prevIdx != currSelection[^1]:
        # Previous coin was skipped, check if current is equivalent
        if pool[idx].effectiveValue == pool[prevIdx].effectiveValue and
           pool[idx].fee == pool[prevIdx].fee:
          skipEquivalent = true

    if not skipEquivalent:
      # Include this coin
      currSelection.add(idx)
      currValue += int64(pool[idx].effectiveValue)
      currWaste += int64(pool[idx].fee) - int64(pool[idx].longTermFee)

    inc idx

  # Build result if we found a solution
  if bestSelection.len == 0:
    return none(SelectionResult)

  var result = SelectionResult(algorithm: "bnb")

  for i in bestSelection:
    result.coins.add(pool[i])
    result.totalValue = Satoshi(int64(result.totalValue) + int64(pool[i].value))
    result.totalEffectiveValue = Satoshi(int64(result.totalEffectiveValue) + int64(pool[i].effectiveValue))
    result.totalFee = Satoshi(int64(result.totalFee) + int64(pool[i].fee))

  result.waste = Satoshi(bestWaste)

  some(result)

proc knapsackSolver*(utxos: var seq[SelectableCoin], target: Satoshi,
                      minChange: Satoshi): Option[SelectionResult] =
  ## Knapsack coin selection algorithm (stochastic approximation)
  ## Used as fallback when BnB doesn't find exact match
  ##
  ## Algorithm:
  ## 1. If any single coin exactly matches target, use it
  ## 2. If all coins < target, use largest-first selection
  ## 3. Otherwise use stochastic subset-sum approximation
  ##
  ## Reference: Bitcoin Core KnapsackSolver in coinselection.cpp

  if utxos.len == 0:
    return none(SelectionResult)

  let targetVal = int64(target)
  let minChangeVal = int64(minChange)

  # Shuffle UTXOs for randomization
  shuffle(utxos)

  # Check for exact match
  for utxo in utxos:
    if int64(utxo.effectiveValue) == targetVal:
      var result = SelectionResult(algorithm: "knapsack")
      result.coins.add(utxo)
      result.totalValue = utxo.value
      result.totalEffectiveValue = utxo.effectiveValue
      result.totalFee = utxo.fee
      result.waste = Satoshi(int64(utxo.fee) - int64(utxo.longTermFee))
      return some(result)

  # Separate coins smaller than target+minChange and find smallest larger
  var smallerCoins: seq[SelectableCoin]
  var lowestLarger: Option[SelectableCoin]
  var totalSmaller: int64 = 0

  for utxo in utxos:
    let effVal = int64(utxo.effectiveValue)
    if effVal <= 0:
      continue

    if effVal < targetVal + minChangeVal:
      smallerCoins.add(utxo)
      totalSmaller += effVal
    else:
      if lowestLarger.isNone or effVal < int64(lowestLarger.get().effectiveValue):
        lowestLarger = some(utxo)

  # If total of smaller coins matches target exactly, use all of them
  if totalSmaller == targetVal:
    var result = SelectionResult(algorithm: "knapsack")
    for utxo in smallerCoins:
      result.coins.add(utxo)
      result.totalValue = Satoshi(int64(result.totalValue) + int64(utxo.value))
      result.totalEffectiveValue = Satoshi(int64(result.totalEffectiveValue) + int64(utxo.effectiveValue))
      result.totalFee = Satoshi(int64(result.totalFee) + int64(utxo.fee))
      result.waste = Satoshi(int64(result.waste) + int64(utxo.fee) - int64(utxo.longTermFee))
    return some(result)

  # If smaller coins can't reach target, use lowest larger if available
  if totalSmaller < targetVal:
    if lowestLarger.isNone:
      return none(SelectionResult)

    var result = SelectionResult(algorithm: "knapsack")
    let utxo = lowestLarger.get()
    result.coins.add(utxo)
    result.totalValue = utxo.value
    result.totalEffectiveValue = utxo.effectiveValue
    result.totalFee = utxo.fee
    result.waste = Satoshi(int64(utxo.fee) - int64(utxo.longTermFee) +
                           int64(utxo.effectiveValue) - targetVal)
    return some(result)

  # Stochastic approximation (ApproximateBestSubset)
  # Sort smaller coins by descending effective value
  smallerCoins.sort(proc(a, b: SelectableCoin): int =
    cmp(int64(b.effectiveValue), int64(a.effectiveValue)))

  var bestSelection = newSeq[bool](smallerCoins.len)
  for i in 0 ..< bestSelection.len:
    bestSelection[i] = true
  var bestValue = totalSmaller

  # Run multiple iterations to find better approximation
  const iterations = 1000
  var rng = initRand()

  for rep in 0 ..< iterations:
    if bestValue == targetVal:
      break

    var included = newSeq[bool](smallerCoins.len)
    var total: int64 = 0
    var reachedTarget = false

    # Two passes: first random, second fill remaining
    for pass in 0 ..< 2:
      if reachedTarget:
        break

      for i in 0 ..< smallerCoins.len:
        let shouldInclude = if pass == 0:
          rng.rand(1) == 1
        else:
          not included[i]

        if shouldInclude:
          total += int64(smallerCoins[i].effectiveValue)
          included[i] = true

          if total >= targetVal:
            reachedTarget = true
            if total < bestValue:
              bestValue = total
              bestSelection = included

            # Backtrack this coin to try other combinations
            total -= int64(smallerCoins[i].effectiveValue)
            included[i] = false

  # Also try with target + minChange to allow for change output
  for rep in 0 ..< iterations:
    if bestValue == targetVal or bestValue == targetVal + minChangeVal:
      break

    var included = newSeq[bool](smallerCoins.len)
    var total: int64 = 0
    var reachedTarget = false
    let adjustedTarget = targetVal + minChangeVal

    for pass in 0 ..< 2:
      if reachedTarget:
        break

      for i in 0 ..< smallerCoins.len:
        let shouldInclude = if pass == 0:
          rng.rand(1) == 1
        else:
          not included[i]

        if shouldInclude:
          total += int64(smallerCoins[i].effectiveValue)
          included[i] = true

          if total >= adjustedTarget:
            reachedTarget = true
            if total < bestValue:
              bestValue = total
              bestSelection = included

            total -= int64(smallerCoins[i].effectiveValue)
            included[i] = false

  # Check if lowest larger is better than our approximation
  if lowestLarger.isSome:
    let largerVal = int64(lowestLarger.get().effectiveValue)
    if bestValue != targetVal and bestValue < targetVal + minChangeVal:
      # Use lowest larger if approximation couldn't find good solution
      if largerVal <= bestValue:
        var result = SelectionResult(algorithm: "knapsack")
        let utxo = lowestLarger.get()
        result.coins.add(utxo)
        result.totalValue = utxo.value
        result.totalEffectiveValue = utxo.effectiveValue
        result.totalFee = utxo.fee
        result.waste = Satoshi(int64(utxo.fee) - int64(utxo.longTermFee) +
                               int64(utxo.effectiveValue) - targetVal)
        return some(result)

  # Build result from best selection
  var result = SelectionResult(algorithm: "knapsack")

  for i in 0 ..< smallerCoins.len:
    if bestSelection[i]:
      let utxo = smallerCoins[i]
      result.coins.add(utxo)
      result.totalValue = Satoshi(int64(result.totalValue) + int64(utxo.value))
      result.totalEffectiveValue = Satoshi(int64(result.totalEffectiveValue) + int64(utxo.effectiveValue))
      result.totalFee = Satoshi(int64(result.totalFee) + int64(utxo.fee))
      result.waste = Satoshi(int64(result.waste) + int64(utxo.fee) - int64(utxo.longTermFee))

  if result.coins.len == 0 or int64(result.totalEffectiveValue) < targetVal:
    return none(SelectionResult)

  # Add excess to waste
  result.waste = Satoshi(int64(result.waste) + int64(result.totalEffectiveValue) - targetVal)

  some(result)

proc selectCoins*(utxos: var seq[SelectableCoin], target: Satoshi,
                   costOfChange: Satoshi, minChange: Satoshi): SelectionResult =
  ## Main coin selection function
  ## Tries BnB first, falls back to Knapsack
  ##
  ## Arguments:
  ## - utxos: Available UTXOs (will be modified for sorting/shuffling)
  ## - target: Target amount including outputs (not including fees)
  ## - costOfChange: Cost to create and spend a change output
  ## - minChange: Minimum viable change output value
  ##
  ## Returns: SelectionResult with selected coins
  ## Raises: CoinSelectionError if selection fails

  # Try BnB first for exact match (no change)
  let bnbResult = selectCoinsBnB(utxos, target, costOfChange)
  if bnbResult.isSome:
    return bnbResult.get()

  # Fall back to Knapsack
  let knapsackResult = knapsackSolver(utxos, target, minChange)
  if knapsackResult.isSome:
    return knapsackResult.get()

  raise newException(CoinSelectionError, "insufficient funds")

proc selectCoinsLargestFirst*(utxos: var seq[SelectableCoin], target: Satoshi): SelectionResult =
  ## Simple largest-first coin selection (for comparison/fallback)
  ## Selects largest UTXOs until target is reached

  if utxos.len == 0:
    raise newException(CoinSelectionError, "no UTXOs available")

  # Sort by effective value descending
  utxos.sort(proc(a, b: SelectableCoin): int =
    cmp(int64(b.effectiveValue), int64(a.effectiveValue)))

  var result = SelectionResult(algorithm: "largest-first")
  let targetVal = int64(target)

  for utxo in utxos:
    if int64(utxo.effectiveValue) <= 0:
      continue

    result.coins.add(utxo)
    result.totalValue = Satoshi(int64(result.totalValue) + int64(utxo.value))
    result.totalEffectiveValue = Satoshi(int64(result.totalEffectiveValue) + int64(utxo.effectiveValue))
    result.totalFee = Satoshi(int64(result.totalFee) + int64(utxo.fee))
    result.waste = Satoshi(int64(result.waste) + int64(utxo.fee) - int64(utxo.longTermFee))

    if int64(result.totalEffectiveValue) >= targetVal:
      # Add excess to waste
      result.waste = Satoshi(int64(result.waste) + int64(result.totalEffectiveValue) - targetVal)
      return result

  raise newException(CoinSelectionError, "insufficient funds")
