## Proof of Work validation and difficulty adjustment
## Implements GetNextWorkRequired matching Bitcoin Core's pow.cpp

import ../primitives/[types, uint256]

# Forward declare params types to avoid circular dependency
type
  NetworkKind* = enum
    Mainnet
    Testnet3
    Testnet4
    Regtest
    Signet

  # Minimal params needed for PoW calculations
  PowParams* = object
    network*: NetworkKind
    powLimit*: array[32, byte]
    powTargetTimespan*: int     # 14 days in seconds (1_209_600)
    powTargetSpacing*: int      # 10 minutes in seconds (600)
    powAllowMinDifficultyBlocks*: bool  # True for testnet/regtest
    powNoRetargeting*: bool     # True for regtest
    enforceBIP94*: bool         # True for testnet4

const
  DifficultyAdjustmentInterval* = 2016
  TargetTimespan* = 1_209_600    # 14 days
  TargetSpacing* = 600           # 10 minutes
  MaxCompactTarget* = 0x1d00ffff'u32

# Block index type for chain traversal
type
  BlockIndex* = object
    height*: int32
    header*: BlockHeader
    hash*: BlockHash

  # Function type for looking up previous blocks
  GetAncestorFn* = proc(index: BlockIndex, height: int32): BlockIndex

proc getPowLimit*(params: PowParams): UInt256 =
  ## Get the maximum allowed target (minimum difficulty) for this network
  initUInt256(params.powLimit)

proc getPowLimitCompact*(params: PowParams): uint32 =
  ## Get the maximum allowed target in compact format
  getPowLimit(params).getCompact()

proc checkProofOfWork*(hash: BlockHash, bits: uint32, params: PowParams): bool =
  ## Check that the block hash meets the target difficulty
  ## Returns true if hash <= target

  let target = setCompact(bits)

  # Check for negative or zero or overflow
  if target.isZero():
    return false

  # Check target doesn't exceed powLimit
  let limit = getPowLimit(params)
  if target > limit:
    return false

  # Check hash <= target
  let hashInt = initUInt256(array[32, byte](hash))
  hashInt <= target

proc calculateNextWorkRequired*(
  lastIndex: BlockIndex,
  firstBlockTime: int64,
  params: PowParams,
  firstBlockBits: uint32 = 0
): uint32 =
  ## Calculate the next difficulty target based on the time to mine the previous period
  ##
  ## lastIndex: The last block of the difficulty period
  ## firstBlockTime: Timestamp of the first block in the period
  ## params: Network parameters
  ## firstBlockBits: For BIP94 (testnet4), use the first block's bits instead of last
  ##
  ## Reference: Bitcoin Core CalculateNextWorkRequired() in pow.cpp

  # Regtest never retargets
  if params.powNoRetargeting:
    return lastIndex.header.bits

  # Calculate actual timespan
  var actualTimespan = int64(lastIndex.header.timestamp) - firstBlockTime

  # Clamp to [targetTimespan/4, targetTimespan*4]
  let minTimespan = int64(params.powTargetTimespan) div 4
  let maxTimespan = int64(params.powTargetTimespan) * 4

  if actualTimespan < minTimespan:
    actualTimespan = minTimespan
  elif actualTimespan > maxTimespan:
    actualTimespan = maxTimespan

  # Get the target to adjust
  # BIP94 (testnet4): use first block's bits to prevent time-warp attack
  let bitsToUse = if params.enforceBIP94 and firstBlockBits != 0:
    firstBlockBits
  else:
    lastIndex.header.bits

  var target = setCompact(bitsToUse)

  # newTarget = oldTarget * actualTimespan / targetTimespan
  target = target * uint64(actualTimespan)
  target = target div uint64(params.powTargetTimespan)

  # Clamp to powLimit
  let limit = getPowLimit(params)
  if target > limit:
    target = limit

  target.getCompact()

proc getNextWorkRequired*(
  lastIndex: BlockIndex,
  blockTime: uint32,
  params: PowParams,
  getAncestor: GetAncestorFn
): uint32 =
  ## Get the required difficulty for the next block
  ##
  ## lastIndex: The tip of the chain (block before the one being mined)
  ## blockTime: Timestamp of the block being mined (for testnet special rules)
  ## params: Network parameters
  ## getAncestor: Function to look up ancestor blocks
  ##
  ## Reference: Bitcoin Core GetNextWorkRequired() in pow.cpp

  let powLimitCompact = getPowLimitCompact(params)
  let nextHeight = lastIndex.height + 1

  # Check if this is a difficulty adjustment boundary
  let isRetargetBlock = (nextHeight mod DifficultyAdjustmentInterval) == 0

  if not isRetargetBlock:
    # Not a retarget block

    # Special testnet rules: allow min-difficulty blocks
    if params.powAllowMinDifficultyBlocks:
      # If the new block's timestamp is more than 2*targetSpacing after the previous block,
      # allow minimum difficulty
      if int64(blockTime) > int64(lastIndex.header.timestamp) + int64(params.powTargetSpacing * 2):
        return powLimitCompact

      # Otherwise, walk back to find the last non-min-difficulty block
      # This ensures difficulty doesn't permanently collapse after a slow block
      var pindex = lastIndex
      while pindex.height > 0 and
            (pindex.height mod DifficultyAdjustmentInterval) != 0 and
            pindex.header.bits == powLimitCompact:
        pindex = getAncestor(pindex, pindex.height - 1)

      return pindex.header.bits

    # Mainnet/Signet: just return previous block's bits
    return lastIndex.header.bits

  # Retarget block - calculate new difficulty

  # Go back to first block of the difficulty period
  # The period spans blocks [height - 2015, height] (2016 blocks total)
  let firstHeight = lastIndex.height - (DifficultyAdjustmentInterval - 1)
  let firstIndex = getAncestor(lastIndex, firstHeight)

  # For BIP94 (testnet4), we need to use the first block's bits to prevent time-warp
  let firstBlockBits = if params.enforceBIP94:
    firstIndex.header.bits
  else:
    0'u32

  calculateNextWorkRequired(lastIndex, int64(firstIndex.header.timestamp), params, firstBlockBits)

# Helper to derive target from compact bits (for validation)
proc deriveTarget*(bits: uint32, powLimit: array[32, byte]): tuple[valid: bool, target: UInt256] =
  ## Derive target from compact bits and validate it
  ## Returns (valid, target) where valid indicates if the target is acceptable

  let target = setCompact(bits)

  # Check for zero
  if target.isZero():
    return (false, target)

  # Check doesn't exceed limit
  let limit = initUInt256(powLimit)
  if target > limit:
    return (false, target)

  (true, target)

# Validate that difficulty transition is permitted
proc permittedDifficultyTransition*(
  params: PowParams,
  height: int32,
  oldBits: uint32,
  newBits: uint32
): bool =
  ## Check that a difficulty transition is within allowed bounds
  ## Used to validate headers during sync
  ##
  ## Reference: Bitcoin Core PermittedDifficultyTransition() in pow.cpp

  # Testnets allow any difficulty transition
  if params.powAllowMinDifficultyBlocks:
    return true

  # Not a retarget boundary - bits must be identical
  if (height mod DifficultyAdjustmentInterval) != 0:
    return oldBits == newBits

  # At retarget boundary, check the new difficulty is within bounds
  let smallestTimespan = int64(params.powTargetTimespan) div 4
  let largestTimespan = int64(params.powTargetTimespan) * 4

  let powLimit = getPowLimit(params)
  let observedTarget = setCompact(newBits)

  # Calculate maximum allowed target (difficulty decrease)
  var largestTarget = setCompact(oldBits)
  largestTarget = largestTarget * uint64(largestTimespan)
  largestTarget = largestTarget div uint64(params.powTargetTimespan)
  if largestTarget > powLimit:
    largestTarget = powLimit

  # Round through compact and compare
  let maxNewTarget = setCompact(largestTarget.getCompact())
  if maxNewTarget < observedTarget:
    return false

  # Calculate minimum allowed target (difficulty increase)
  var smallestTarget = setCompact(oldBits)
  smallestTarget = smallestTarget * uint64(smallestTimespan)
  smallestTarget = smallestTarget div uint64(params.powTargetTimespan)
  if smallestTarget > powLimit:
    smallestTarget = powLimit

  # Round through compact and compare
  let minNewTarget = setCompact(smallestTarget.getCompact())
  if minNewTarget > observedTarget:
    return false

  true
