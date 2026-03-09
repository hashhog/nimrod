## Fee estimation
## Estimates appropriate transaction fees based on mempool state

import std/[algorithm, tables, times]
import ../primitives/types
import ../mempool/mempool

type
  FeeEstimator* = ref object
    mempool*: Mempool
    feeHistory*: seq[tuple[timestamp: Time, feeRate: float]]
    maxHistory*: int

  FeePriority* = enum
    Low       # Next 6+ blocks
    Medium    # Next 2-6 blocks
    High      # Next block

const
  # Target confirmation blocks for each priority
  LOW_TARGET = 25
  MEDIUM_TARGET = 6
  HIGH_TARGET = 1

proc newFeeEstimator*(mempool: Mempool): FeeEstimator =
  FeeEstimator(
    mempool: mempool,
    feeHistory: @[],
    maxHistory: 1000
  )

proc getMempoolFeePercentile*(mp: Mempool, percentile: float): float =
  ## Get fee rate at given percentile of mempool
  var rates: seq[float]
  for entry in mp.entries.values:
    rates.add(entry.feeRate)

  if rates.len == 0:
    return 1.0  # Minimum 1 sat/byte

  rates.sort()
  let idx = int(float(rates.len - 1) * percentile)
  rates[idx]

proc estimateFee*(fe: FeeEstimator, priority: FeePriority): Satoshi =
  ## Estimate fee rate in satoshis per byte
  let percentile = case priority
    of Low: 0.25
    of Medium: 0.50
    of High: 0.85

  let feeRate = getMempoolFeePercentile(fe.mempool, percentile)

  # Convert to satoshis per 1000 bytes (standard unit)
  Satoshi(int64(feeRate * 1000) + 1)

proc estimateFeeForTx*(fe: FeeEstimator, txSize: int, priority: FeePriority): Satoshi =
  ## Estimate total fee for a transaction of given size
  let feePerKb = fe.estimateFee(priority)
  Satoshi(int64(feePerKb) * int64(txSize) div 1000 + 1)

proc recordFee*(fe: FeeEstimator, feeRate: float) =
  ## Record a confirmed transaction's fee rate for history
  fe.feeHistory.add((getTime(), feeRate))

  # Trim old history
  while fe.feeHistory.len > fe.maxHistory:
    fe.feeHistory.delete(0)

proc getHistoricalMedian*(fe: FeeEstimator, window: Duration): float =
  ## Get median fee rate over a time window
  let cutoff = getTime() - window
  var rates: seq[float]

  for (timestamp, rate) in fe.feeHistory:
    if timestamp >= cutoff:
      rates.add(rate)

  if rates.len == 0:
    return 1.0

  rates.sort()
  rates[rates.len div 2]

proc getSmartFeeEstimate*(fe: FeeEstimator, confirmTarget: int): Satoshi =
  ## Smart fee estimation based on target confirmation blocks
  # Use mempool analysis
  let percentile = if confirmTarget <= 1: 0.90
    elif confirmTarget <= 3: 0.75
    elif confirmTarget <= 6: 0.50
    elif confirmTarget <= 12: 0.25
    else: 0.10

  let mempoolRate = getMempoolFeePercentile(fe.mempool, percentile)

  # Consider historical data if available
  var rate = mempoolRate
  if fe.feeHistory.len > 100:
    let historical = fe.getHistoricalMedian(initDuration(hours = 24))
    rate = max(mempoolRate, historical * 0.8)

  # Minimum fee
  rate = max(rate, 1.0)

  Satoshi(int64(rate * 1000))
