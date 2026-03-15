## BIP9 Version Bits Deployment State Machine
## Implements soft fork activation via version signaling
## Reference: Bitcoin Core versionbits.cpp
##
## State machine:
##   DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
##              └─────────> FAILED
##
## Transitions occur only at retarget boundaries (every 2016 blocks).
## During STARTED, count blocks that signal the deployment bit in nVersion.
## If count >= threshold (1815/2016 = 90% mainnet), transition to LOCKED_IN.
## After one full period of LOCKED_IN, transition to ACTIVE.
## If timeout reached while STARTED, transition to FAILED.

import std/[tables, options, algorithm]
import ../primitives/types
import ../storage/chainstate
import ./params

type
  ThresholdState* = enum
    ## BIP9 deployment states
    tsDefined     ## Initial state before start time
    tsStarted     ## Signaling period active
    tsLockedIn    ## Threshold reached, waiting for activation
    tsActive      ## Deployment fully active (terminal)
    tsFailed      ## Timeout reached without activation (terminal)

  BIP9Deployment* = object
    ## Parameters for a BIP9 soft fork deployment
    name*: string
    bit*: int                  ## Bit position in nVersion (0-28)
    startTime*: int64          ## MedianTimePast to start signaling
    timeout*: int64            ## MedianTimePast for timeout
    minActivationHeight*: int  ## Earliest height for ACTIVE
    period*: int               ## Retarget period (2016)
    threshold*: int            ## Required signaling blocks (1815 mainnet, 1512 testnet)

  BIP9Stats* = object
    ## Statistics for current signaling period
    period*: int
    threshold*: int
    elapsed*: int              ## Blocks elapsed in current period
    count*: int                ## Signaling blocks in current period
    possible*: bool            ## Can still reach threshold this period?

  VersionBitsCache* = ref object
    ## Per-deployment state caches indexed by block hash
    ## Cache entries are for blocks at retarget boundaries
    stateCaches*: Table[int, Table[BlockHash, ThresholdState]]
    ## Computed block versions
    versionCache*: Table[BlockHash, int32]

# Special values for startTime
const
  AlwaysActive* = -1'i64       ## Deployment always active (for testing)
  NeverActive* = -2'i64        ## Deployment never active

  # Version bits constants
  VersionBitsTopBits* = 0x20000000'i32   ## Top 3 bits = 001 for BIP9 signaling
  VersionBitsTopMask* = 0xE0000000'i32   ## Mask for top 3 bits
  VersionBitsNumBits* = 29               ## Number of available bits

  # Standard deployment parameters
  MainnetPeriod* = 2016
  MainnetThreshold* = 1815     ## 90% of 2016
  TestnetThreshold* = 1512     ## 75% of 2016

# Standard deployment indices (matches Bitcoin Core DeploymentPos)
type
  DeploymentPos* = enum
    dpTestDummy = 0
    dpTaproot = 1

# Helper to get deployment mask for a bit position
proc deploymentMask*(bit: int): uint32 {.inline.} =
  1'u32 shl bit

proc isVersionBitsSignaling*(version: int32): bool {.inline.} =
  ## Check if block version has BIP9 signaling bit pattern (top 3 bits = 001)
  (version and VersionBitsTopMask) == VersionBitsTopBits

proc signalsBit*(version: int32, bit: int): bool {.inline.} =
  ## Check if a block version signals a specific deployment bit
  ## Must have BIP9 top bits AND the deployment bit set
  isVersionBitsSignaling(version) and ((version and int32(deploymentMask(bit))) != 0)

proc stateName*(state: ThresholdState): string =
  ## Human-readable state name (matches Bitcoin Core)
  case state
  of tsDefined: "defined"
  of tsStarted: "started"
  of tsLockedIn: "locked_in"
  of tsActive: "active"
  of tsFailed: "failed"

# ============================================================================
# State Machine
# ============================================================================

proc getAncestorAtRetargetBoundary*(
  hash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex],
  period: int
): Option[BlockIndex] =
  ## Find the ancestor block at the start of the current retarget period
  ## The state of a block is the same as the first block of its period
  let idxOpt = getBlockIndex(hash)
  if idxOpt.isNone:
    return none(BlockIndex)

  let idx = idxOpt.get()
  if idx.height < 0:
    return none(BlockIndex)

  # Find height of last block in previous period (or genesis)
  # Period boundary: height mod period == period - 1
  let heightInPeriod = (idx.height + 1) mod period
  let ancestorHeight = idx.height - heightInPeriod

  if ancestorHeight < 0:
    return none(BlockIndex)

  # Walk back to find this ancestor
  var current = idx
  while current.height > ancestorHeight:
    let prevOpt = getBlockIndex(current.prevHash)
    if prevOpt.isNone:
      return none(BlockIndex)
    current = prevOpt.get()

  some(current)

proc getMtpForBlock*(
  hash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex]
): int64 =
  ## Get Median Time Past for a block
  ## MTP is the median of the timestamps of the previous 11 blocks
  var timestamps: seq[uint32]
  var current = hash

  for i in 0 ..< MedianTimeSpan:
    let idxOpt = getBlockIndex(current)
    if idxOpt.isNone:
      break
    timestamps.add(idxOpt.get().header.timestamp)
    current = idxOpt.get().prevHash

  if timestamps.len == 0:
    return 0

  # Sort and take median
  timestamps.sort()
  int64(timestamps[timestamps.len div 2])

proc countSignalingBlocks(
  periodStartPrev: BlockIndex,
  period: int,
  bit: int,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex]
): int =
  ## Count blocks in a retarget period that signal the deployment bit
  ## periodStartPrev is the last block of the PREVIOUS period
  ## We count blocks from (periodStartPrev.height + 1) to (periodStartPrev.height + period)
  result = 0

  # The periodStartPrev is at height that is a multiple of period - 1
  # We need to count the NEXT period, so we look at children
  # Actually, we need to walk through the period ending at periodStartPrev + period
  # Since we're caching state, periodStartPrev.height + 1 is the start of the period we're evaluating

  # We need to iterate through blocks in this period
  # The caller passes us the index at the end of the previous period
  # We need to find the current period's blocks

  # Walk forward from periodStartPrev to count signaling blocks
  # But we don't have forward links, so instead we take a different approach:
  # The cache is indexed by the parent of the first block in each period
  # which is the last block of the previous period

  # For counting, we receive the block at the end of the period we want to count
  # Let's trace through: GetStateFor receives pindexPrev (parent of block being evaluated)
  # If we're at a period boundary, pindexPrev is at height = k*period - 1
  # The period to count is blocks from height k*period - period to k*period - 1

  # Actually let me re-read the Bitcoin Core logic...
  # pindexPrev is adjusted to be at height = multiple of period - 1
  # Then we count from pindexPrev going backwards period blocks

  var pindex = some(periodStartPrev)
  for i in 0 ..< period:
    if pindex.isNone:
      break
    let idx = pindex.get()
    if signalsBit(idx.header.version, bit):
      inc result
    pindex = getBlockIndex(idx.prevHash)

proc getStateFor*(
  deployment: BIP9Deployment,
  prevHash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex],
  getMtp: proc(h: BlockHash): int64,
  cache: var Table[BlockHash, ThresholdState]
): ThresholdState =
  ## Get the deployment state for a block, given its parent's hash
  ## State transitions happen at retarget boundaries

  # Always active deployments
  if deployment.startTime == AlwaysActive:
    return tsActive

  # Never active deployments
  if deployment.startTime == NeverActive:
    return tsFailed

  let period = deployment.period

  # Get block index
  let prevIdxOpt = getBlockIndex(prevHash)
  if prevIdxOpt.isNone:
    # Genesis block's parent - defined state
    return tsDefined

  let prevIdx = prevIdxOpt.get()

  # A block's state is the same as the first block of its period
  # Find the ancestor at the period boundary
  # Height of first block in period containing prevIdx.height + 1
  let targetHeight = prevIdx.height - ((prevIdx.height + 1) mod period)

  var pindexPrev: Option[BlockIndex]
  if targetHeight < 0:
    pindexPrev = none(BlockIndex)
  else:
    var current = prevIdx
    while current.height > targetHeight:
      let ancestorOpt = getBlockIndex(current.prevHash)
      if ancestorOpt.isNone:
        pindexPrev = none(BlockIndex)
        break
      current = ancestorOpt.get()
    if current.height == targetHeight:
      pindexPrev = some(current)
    else:
      pindexPrev = none(BlockIndex)

  # Walk backwards to find a cached state
  var toCompute: seq[BlockIndex]

  while true:
    if pindexPrev.isNone:
      # Genesis block is by definition in DEFINED state
      cache[BlockHash(default(array[32, byte]))] = tsDefined
      break

    let idx = pindexPrev.get()

    if idx.hash in cache:
      break

    # Optimization: if MTP < start time, we know it's DEFINED
    let mtp = getMtp(idx.hash)
    if mtp < deployment.startTime:
      cache[idx.hash] = tsDefined
      break

    toCompute.add(idx)

    # Move back one period
    let newTargetHeight = idx.height - period
    if newTargetHeight < 0:
      pindexPrev = none(BlockIndex)
    else:
      var current = idx
      while current.height > newTargetHeight:
        let ancestorOpt = getBlockIndex(current.prevHash)
        if ancestorOpt.isNone:
          pindexPrev = none(BlockIndex)
          break
        current = ancestorOpt.get()
      if current.height == newTargetHeight:
        pindexPrev = some(current)
      else:
        pindexPrev = none(BlockIndex)

  # Get the known state from cache
  var state: ThresholdState
  if pindexPrev.isNone:
    state = cache.getOrDefault(BlockHash(default(array[32, byte])), tsDefined)
  else:
    state = cache.getOrDefault(pindexPrev.get().hash, tsDefined)

  # Walk forward computing states
  while toCompute.len > 0:
    let idx = toCompute.pop()
    var stateNext = state

    case state
    of tsDefined:
      let mtp = getMtp(idx.hash)
      if mtp >= deployment.startTime:
        stateNext = tsStarted

    of tsStarted:
      let mtp = getMtp(idx.hash)
      # Count signaling blocks in this period
      let count = countSignalingBlocks(idx, period, deployment.bit, getBlockIndex)
      if count >= deployment.threshold:
        stateNext = tsLockedIn
      elif mtp >= deployment.timeout:
        stateNext = tsFailed

    of tsLockedIn:
      # Progress to ACTIVE if we've passed min activation height
      # idx.height + 1 is the height of the first block of the next period
      if idx.height + 1 >= deployment.minActivationHeight:
        stateNext = tsActive

    of tsActive, tsFailed:
      # Terminal states - no transitions
      discard

    cache[idx.hash] = stateNext
    state = stateNext

  state

proc getStateStatistics*(
  deployment: BIP9Deployment,
  blockIndex: BlockIndex,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex]
): BIP9Stats =
  ## Get signaling statistics for the current period
  result.period = deployment.period
  result.threshold = deployment.threshold

  if blockIndex.height < 0:
    return

  # Find how many blocks are in the current period
  let blocksInPeriod = 1 + (blockIndex.height mod deployment.period)
  result.elapsed = blocksInPeriod

  # Count signaling blocks from current block back to start of period
  var idx = some(blockIndex)
  var remaining = blocksInPeriod
  while remaining > 0 and idx.isSome:
    let curIdx = idx.get()
    if signalsBit(curIdx.header.version, deployment.bit):
      inc result.count
    idx = getBlockIndex(curIdx.prevHash)
    dec remaining

  # Can we still reach threshold?
  let blocksRemaining = deployment.period - result.elapsed
  result.possible = (blocksRemaining + result.count) >= deployment.threshold

proc getStateSinceHeight*(
  deployment: BIP9Deployment,
  prevHash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex],
  getMtp: proc(h: BlockHash): int64,
  cache: var Table[BlockHash, ThresholdState]
): int =
  ## Get the height at which the current state started
  let startTime = deployment.startTime

  if startTime == AlwaysActive or startTime == NeverActive:
    return 0

  let currentState = getStateFor(deployment, prevHash, getBlockIndex, getMtp, cache)

  if currentState == tsDefined:
    return 0

  let period = deployment.period

  # Get the period boundary
  let prevIdxOpt = getBlockIndex(prevHash)
  if prevIdxOpt.isNone:
    return 0

  var prevIdx = prevIdxOpt.get()

  # Adjust to period boundary
  let targetHeight = prevIdx.height - ((prevIdx.height + 1) mod period)
  while prevIdx.height > targetHeight:
    let ancestorOpt = getBlockIndex(prevIdx.prevHash)
    if ancestorOpt.isNone:
      return 0
    prevIdx = ancestorOpt.get()

  # Walk back while state is the same
  # Bitcoin Core's logic: walk back period by period while GetStateFor returns same state
  # GetStateFor(pindexPrev) returns state for block at pindexPrev.height + 1

  # Find the previous period's boundary (parent of first block in previous period)
  var prevPeriodParentHeight = prevIdx.height - period
  while prevPeriodParentHeight >= 0:
    # Walk to the block at prevPeriodParentHeight
    var prevPeriodParent = prevIdx
    while prevPeriodParent.height > prevPeriodParentHeight:
      let ancestorOpt = getBlockIndex(prevPeriodParent.prevHash)
      if ancestorOpt.isNone:
        return prevIdx.height + 1
      prevPeriodParent = ancestorOpt.get()

    # Check if state at this period boundary matches current state
    let prevState = getStateFor(deployment, prevPeriodParent.hash, getBlockIndex, getMtp, cache)
    if prevState != currentState:
      break

    # State is the same, move back one more period
    prevIdx = prevPeriodParent
    prevPeriodParentHeight = prevIdx.height - period

  # Return height of first block in the period where state started
  prevIdx.height + 1

# ============================================================================
# Block Version Computation
# ============================================================================

proc computeBlockVersion*(
  deployments: openArray[BIP9Deployment],
  prevHash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex],
  getMtp: proc(h: BlockHash): int64,
  caches: var seq[Table[BlockHash, ThresholdState]]
): int32 =
  ## Compute the block version to use for new blocks
  ## Sets bits for deployments in STARTED or LOCKED_IN state
  result = VersionBitsTopBits

  for i, deployment in deployments:
    if i >= caches.len:
      caches.add(initTable[BlockHash, ThresholdState]())

    let state = getStateFor(deployment, prevHash, getBlockIndex, getMtp, caches[i])

    if state == tsStarted or state == tsLockedIn:
      result = result or int32(deploymentMask(deployment.bit))

proc isDeploymentActive*(
  deployment: BIP9Deployment,
  prevHash: BlockHash,
  getBlockIndex: proc(h: BlockHash): Option[BlockIndex],
  getMtp: proc(h: BlockHash): int64,
  cache: var Table[BlockHash, ThresholdState]
): bool =
  ## Check if a deployment is active for the block after prevHash
  getStateFor(deployment, prevHash, getBlockIndex, getMtp, cache) == tsActive

# ============================================================================
# VersionBitsCache Management
# ============================================================================

proc newVersionBitsCache*(): VersionBitsCache =
  VersionBitsCache(
    stateCaches: initTable[int, Table[BlockHash, ThresholdState]](),
    versionCache: initTable[BlockHash, int32]()
  )

proc clear*(cache: VersionBitsCache) =
  cache.stateCaches.clear()
  cache.versionCache.clear()

proc getDeploymentCache*(cache: VersionBitsCache, deploymentIdx: int): var Table[BlockHash, ThresholdState] =
  if deploymentIdx notin cache.stateCaches:
    cache.stateCaches[deploymentIdx] = initTable[BlockHash, ThresholdState]()
  cache.stateCaches[deploymentIdx]

# ============================================================================
# Standard Deployments
# ============================================================================

proc taprootDeployment*(network: Network): BIP9Deployment =
  ## Get Taproot deployment parameters for a network
  case network
  of Mainnet:
    BIP9Deployment(
      name: "taproot",
      bit: 2,
      startTime: 1619222400,          # April 24, 2021
      timeout: 1628640000,            # August 11, 2021
      minActivationHeight: 709632,    # Block height for activation
      period: MainnetPeriod,
      threshold: MainnetThreshold
    )
  of Testnet3, Testnet4, Signet:
    BIP9Deployment(
      name: "taproot",
      bit: 2,
      startTime: AlwaysActive,        # Always active on testnets
      timeout: 0,
      minActivationHeight: 0,
      period: MainnetPeriod,
      threshold: TestnetThreshold
    )
  of Regtest:
    BIP9Deployment(
      name: "taproot",
      bit: 2,
      startTime: AlwaysActive,        # Always active on regtest
      timeout: 0,
      minActivationHeight: 0,
      period: 144,                    # Shorter period for testing
      threshold: 108
    )

proc testDummyDeployment*(): BIP9Deployment =
  ## Test deployment for verification (matches Bitcoin Core TESTDUMMY)
  BIP9Deployment(
    name: "testdummy",
    bit: 28,
    startTime: NeverActive,
    timeout: 0,
    minActivationHeight: 0,
    period: MainnetPeriod,
    threshold: MainnetThreshold
  )

proc getDeployments*(network: Network): seq[BIP9Deployment] =
  ## Get all deployments for a network
  @[
    testDummyDeployment(),
    taprootDeployment(network)
  ]
