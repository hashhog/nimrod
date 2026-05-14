## Fee estimation using histogram-based confirmation tracking
## Tracks transactions across fee-rate buckets and measures confirmation times
## Three-horizon design matching Bitcoin Core's CBlockPolicyEstimator:
##   SHORT (decay=0.962, scale=1, 12 periods), MED (decay=0.9952, scale=2, 24 periods),
##   LONG (decay=0.99931, scale=24, 42 periods).

import std/[tables, math, json, os]
import ../primitives/types

const
  MaxTargetBlocks* = 1008  ## Maximum confirmation target in blocks

  ## Fee rate buckets in sat/vbyte
  FeeRateBuckets* = [1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0, 30.0, 50.0,
    75.0, 100.0, 150.0, 200.0, 300.0, 500.0, 750.0, 1000.0, 1500.0, 2000.0,
    5000.0, 10000.0]

  NumBuckets* = 22  ## Length of FeeRateBuckets
  ConfirmationThreshold* = 0.85  ## 85% confirmation threshold
  # Legacy single-decay kept for backward compatibility (equals MED_DECAY)
  DecayFactor* = 0.998

  ## Per-horizon decay factors matching Bitcoin Core's CBlockPolicyEstimator
  SHORT_DECAY* = 0.962     ## SHORT horizon decay  (Core: SHORT_DECAY)
  MED_DECAY*   = 0.9952    ## MEDIUM horizon decay (Core: MED_DECAY)
  LONG_DECAY*  = 0.99931   ## LONG horizon decay   (Core: LONG_DECAY)

  ## Per-horizon period counts (Core: SHORT/MED/LONG_BLOCK_PERIODS)
  SHORT_PERIODS* = 12      ## Track 12 periods
  MED_PERIODS*   = 24      ## Track 24 periods
  LONG_PERIODS*  = 42      ## Track 42 periods

  ## Per-horizon scale factors — number of blocks per period
  SHORT_SCALE* = 1         ## SHORT: 1 block per period  → 12 blocks max
  MED_SCALE*   = 2         ## MED:   2 blocks per period → 48 blocks max
  LONG_SCALE*  = 24        ## LONG:  24 blocks per period → 1008 blocks max

  ## Derived horizon block horizons
  SHORT_MAX_TARGET* = SHORT_PERIODS * SHORT_SCALE   ## 12
  MED_MAX_TARGET*   = MED_PERIODS   * MED_SCALE     ## 48
  LONG_MAX_TARGET*  = LONG_PERIODS  * LONG_SCALE    ## 1008

  FallbackFeeRate* = 10.0  ## Fallback fee rate when insufficient data (sat/vbyte)
  MinDataPoints* = 10      ## Minimum data points required for estimation

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

  ## Per-horizon tracking state (one per SHORT/MED/LONG)
  HorizonStats* = object
    decay*: float64        ## Exponential decay factor for this horizon
    scale*: int            ## Number of blocks per period
    numPeriods*: int       ## Number of periods tracked
    buckets*: array[NumBuckets, BucketStats]

  FeeEstimator* = ref object
    ## Three independent TxConfirmStats instances, one per horizon
    shortHorizon*: HorizonStats
    medHorizon*:   HorizonStats
    longHorizon*:  HorizonStats
    ## Legacy single-horizon view (points at medHorizon.buckets for compatibility)
    bucketStats*: array[NumBuckets, BucketStats]
    trackedTxs*: Table[TxId, TrackedTx]

proc initHorizonStats(decay: float64, scale: int, numPeriods: int): HorizonStats =
  HorizonStats(
    decay: decay,
    scale: scale,
    numPeriods: numPeriods,
    buckets: default(array[NumBuckets, BucketStats])
  )

proc newFeeEstimator*(): FeeEstimator =
  ## Create a new fee estimator with three independent horizons
  result = FeeEstimator(
    shortHorizon: initHorizonStats(SHORT_DECAY, SHORT_SCALE, SHORT_PERIODS),
    medHorizon:   initHorizonStats(MED_DECAY,   MED_SCALE,   MED_PERIODS),
    longHorizon:  initHorizonStats(LONG_DECAY,  LONG_SCALE,  LONG_PERIODS),
    bucketStats:  default(array[NumBuckets, BucketStats]),
    trackedTxs:   initTable[TxId, TrackedTx]()
  )

proc getBucketIndex*(feeRate: float64): int =
  ## Find the bucket index for a given fee rate
  ## Returns the index of the first bucket >= feeRate
  for i, bucketRate in FeeRateBuckets:
    if feeRate <= bucketRate:
      return i
  # Fee rate higher than all buckets - use highest bucket
  return NumBuckets - 1

proc applyDecayToHorizon(hs: var HorizonStats) =
  ## Apply exponential decay to all bucket statistics for one horizon
  for i in 0..<NumBuckets:
    hs.buckets[i].totalSeen *= hs.decay
    hs.buckets[i].feeRateSum *= hs.decay
    for j in 0..<MaxTargetBlocks:
      hs.buckets[i].totalConfirmed[j] *= hs.decay
    if hs.buckets[i].totalSeen > 0:
      hs.buckets[i].avgFeeRate =
        hs.buckets[i].feeRateSum / hs.buckets[i].totalSeen
    else:
      hs.buckets[i].avgFeeRate = 0

proc applyDecay*(fe: FeeEstimator) =
  ## Apply exponential decay to all horizons (called once per block)
  applyDecayToHorizon(fe.shortHorizon)
  applyDecayToHorizon(fe.medHorizon)
  applyDecayToHorizon(fe.longHorizon)
  # Keep legacy bucketStats in sync with medHorizon
  fe.bucketStats = fe.medHorizon.buckets

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

  # Update all three horizon bucket stats
  for hs in [addr fe.shortHorizon, addr fe.medHorizon, addr fe.longHorizon]:
    hs.buckets[bucketIdx].totalSeen += 1
    hs.buckets[bucketIdx].feeRateSum += feeRate
    hs.buckets[bucketIdx].avgFeeRate =
      hs.buckets[bucketIdx].feeRateSum / hs.buckets[bucketIdx].totalSeen

  # Keep legacy bucketStats in sync with medHorizon
  fe.bucketStats = fe.medHorizon.buckets

proc processBlock*(fe: FeeEstimator, height: int32, confirmedTxids: seq[TxId]) =
  ## Process a confirmed block, updating confirmation statistics
  ## Called when a new block is connected

  # Apply decay first (once per block, to all horizons)
  fe.applyDecay()

  for txid in confirmedTxids:
    if txid notin fe.trackedTxs:
      continue

    let tracked = fe.trackedTxs[txid]
    let blocksToConfirm = int(height) - int(tracked.entryHeight)

    # Core rejects same-block (blocksToConfirm <= 0)
    if blocksToConfirm <= 0:
      fe.trackedTxs.del(txid)
      continue

    # Record in each horizon using period-scaled indexing
    # SHORT: slot = (blocksToConfirm - 1) / scale = blocksToConfirm - 1 (scale=1)
    # MED:   slot = (blocksToConfirm - 1) / 2
    # LONG:  slot = (blocksToConfirm - 1) / 24
    for hs in [addr fe.shortHorizon, addr fe.medHorizon, addr fe.longHorizon]:
      let period = (blocksToConfirm - 1) div hs.scale
      if period >= 0 and period < hs.numPeriods:
        hs.buckets[tracked.bucketIdx].totalConfirmed[period] += 1

    # Remove from tracking
    fe.trackedTxs.del(txid)

  # Keep legacy bucketStats in sync with medHorizon
  fe.bucketStats = fe.medHorizon.buckets

proc removeTransaction*(fe: FeeEstimator, txid: TxId) =
  ## Remove a transaction from tracking (e.g., if evicted from mempool)
  if txid in fe.trackedTxs:
    let tracked = fe.trackedTxs[txid]
    # Decrement the seen count across all horizons
    for hs in [addr fe.shortHorizon, addr fe.medHorizon, addr fe.longHorizon]:
      if hs.buckets[tracked.bucketIdx].totalSeen > 0:
        hs.buckets[tracked.bucketIdx].totalSeen -= 1
        hs.buckets[tracked.bucketIdx].feeRateSum -= tracked.feeRate
        if hs.buckets[tracked.bucketIdx].totalSeen > 0:
          hs.buckets[tracked.bucketIdx].avgFeeRate =
            hs.buckets[tracked.bucketIdx].feeRateSum /
              hs.buckets[tracked.bucketIdx].totalSeen
        else:
          hs.buckets[tracked.bucketIdx].avgFeeRate = 0
    fe.trackedTxs.del(txid)
  # Keep legacy bucketStats in sync with medHorizon
  fe.bucketStats = fe.medHorizon.buckets

proc getConfirmationRateForHorizon*(hs: HorizonStats, bucketIdx: int,
                                    targetBlocks: int): float64 =
  ## Calculate confirmation rate for a bucket within target blocks for a given horizon.
  ## Uses period-scaled indexing matching the horizon's scale.
  if bucketIdx < 0 or bucketIdx >= NumBuckets:
    return 0.0
  let stats = hs.buckets[bucketIdx]
  if stats.totalSeen < 1:
    return 0.0
  # Number of periods that cover targetBlocks under this horizon's scale
  let maxPeriod = min((targetBlocks + hs.scale - 1) div hs.scale, hs.numPeriods)
  var confirmed = 0.0
  for i in 0..<maxPeriod:
    confirmed += stats.totalConfirmed[i]
  confirmed / stats.totalSeen

proc getConfirmationRate*(fe: FeeEstimator, bucketIdx: int, targetBlocks: int): float64 =
  ## Calculate confirmation rate using the MED horizon (legacy compatibility)
  getConfirmationRateForHorizon(fe.medHorizon, bucketIdx, targetBlocks)

proc estimateFeeForHorizon*(hs: HorizonStats, targetBlocks: int): float64 =
  ## Estimate fee for a specific horizon. Scans low→high to find lowest bucket
  ## achieving >= ConfirmationThreshold within target blocks.
  ## Returns 0.0 if insufficient data.
  var totalData = 0.0
  for i in 0..<NumBuckets:
    totalData += hs.buckets[i].totalSeen
  if totalData < float64(MinDataPoints):
    return 0.0

  for i in 0..<NumBuckets:
    let rate = getConfirmationRateForHorizon(hs, i, targetBlocks)
    if hs.buckets[i].totalSeen >= 1 and rate >= ConfirmationThreshold:
      if hs.buckets[i].avgFeeRate > 0:
        return hs.buckets[i].avgFeeRate
      else:
        return FeeRateBuckets[i]

  # No bucket meets threshold — return highest available
  for i in countdown(NumBuckets - 1, 0):
    if hs.buckets[i].totalSeen >= 1:
      if hs.buckets[i].avgFeeRate > 0:
        return hs.buckets[i].avgFeeRate
      else:
        return FeeRateBuckets[i]

  return 0.0

proc estimateFee*(fe: FeeEstimator, targetBlocks: int): float64 =
  ## Estimate the fee rate (sat/vbyte) needed to confirm within targetBlocks.
  ## Dispatches to SHORT (<= 12), MED (<= 48), or LONG (<= 1008) horizon.
  ## Returns FallbackFeeRate if insufficient data.

  let target = min(max(targetBlocks, 1), MaxTargetBlocks)

  # Select the appropriate horizon
  let rate =
    if target <= SHORT_MAX_TARGET:
      estimateFeeForHorizon(fe.shortHorizon, target)
    elif target <= MED_MAX_TARGET:
      estimateFeeForHorizon(fe.medHorizon, target)
    else:
      estimateFeeForHorizon(fe.longHorizon, target)

  if rate <= 0.0:
    return FallbackFeeRate
  rate

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
  ## Get statistics for a specific bucket (MED horizon)
  if bucketIdx >= 0 and bucketIdx < NumBuckets:
    fe.medHorizon.buckets[bucketIdx]
  else:
    default(BucketStats)

proc getHorizonBucketStats*(hs: HorizonStats, bucketIdx: int): BucketStats =
  ## Get statistics for a specific bucket within a horizon
  if bucketIdx >= 0 and bucketIdx < NumBuckets:
    hs.buckets[bucketIdx]
  else:
    default(BucketStats)

proc clear*(fe: FeeEstimator) =
  ## Clear all tracked data and statistics
  fe.trackedTxs.clear()
  for i in 0..<NumBuckets:
    fe.shortHorizon.buckets[i] = default(BucketStats)
    fe.medHorizon.buckets[i]   = default(BucketStats)
    fe.longHorizon.buckets[i]  = default(BucketStats)
    fe.bucketStats[i]          = default(BucketStats)

proc saveFeeEstimates*(fe: FeeEstimator, path: string) =
  ## Save fee estimator bucket statistics to a JSON file.
  ## Persists all three horizons. Only bucketStats (not tracked transactions) are saved.
  proc horizonToJson(hs: HorizonStats): JsonNode =
    var bucketsArr = newJArray()
    for i in 0..<NumBuckets:
      let stats = hs.buckets[i]
      var confirmedArr = newJArray()
      for j in 0..<MaxTargetBlocks:
        confirmedArr.add(%stats.totalConfirmed[j])
      bucketsArr.add(%*{
        "totalSeen": stats.totalSeen,
        "avgFeeRate": stats.avgFeeRate,
        "feeRateSum": stats.feeRateSum,
        "totalConfirmed": confirmedArr
      })
    %*{
      "decay":      hs.decay,
      "scale":      hs.scale,
      "numPeriods": hs.numPeriods,
      "buckets":    bucketsArr
    }

  let state = %*{
    "version":    2,
    "numBuckets": NumBuckets,
    "short":      horizonToJson(fe.shortHorizon),
    "medium":     horizonToJson(fe.medHorizon),
    "long":       horizonToJson(fe.longHorizon)
  }

  let tmpPath = path & ".tmp"
  try:
    writeFile(tmpPath, $state)
    moveFile(tmpPath, path)
  except CatchableError:
    discard

proc loadFeeEstimates*(fe: FeeEstimator, path: string) =
  ## Load fee estimator bucket statistics from a JSON file.
  ## Supports version 2 (three-horizon) and version 1 (single-horizon, loaded into MED).
  if not fileExists(path):
    return

  proc loadHorizon(node: JsonNode, hs: var HorizonStats) =
    let bucketsNode = node{"buckets"}
    if bucketsNode.isNil or bucketsNode.kind != JArray:
      return
    if bucketsNode.len != NumBuckets:
      return
    for i in 0..<NumBuckets:
      let bucket = bucketsNode[i]
      if bucket.kind != JObject:
        continue
      hs.buckets[i].totalSeen  = bucket{"totalSeen"}.getFloat()
      hs.buckets[i].avgFeeRate = bucket{"avgFeeRate"}.getFloat()
      hs.buckets[i].feeRateSum = bucket{"feeRateSum"}.getFloat()
      let confirmedNode = bucket{"totalConfirmed"}
      if confirmedNode.isNil or confirmedNode.kind != JArray:
        continue
      for j in 0..<min(confirmedNode.len, MaxTargetBlocks):
        hs.buckets[i].totalConfirmed[j] = confirmedNode[j].getFloat()

  try:
    let contents = readFile(path)
    let state = parseJson(contents)
    if state.kind != JObject:
      return

    let version = state{"version"}.getInt()
    if version == 2:
      # Three-horizon format
      let shortNode = state{"short"}
      let medNode   = state{"medium"}
      let longNode  = state{"long"}
      if not shortNode.isNil: loadHorizon(shortNode, fe.shortHorizon)
      if not medNode.isNil:   loadHorizon(medNode,   fe.medHorizon)
      if not longNode.isNil:  loadHorizon(longNode,  fe.longHorizon)
    else:
      # Version 1: single-horizon — load into medHorizon for compatibility
      let bucketsNode = state{"buckets"}
      if not bucketsNode.isNil:
        loadHorizon(state, fe.medHorizon)

    # Keep legacy bucketStats in sync
    fe.bucketStats = fe.medHorizon.buckets
  except CatchableError:
    discard
