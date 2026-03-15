## Checkpoint verification for anti-DoS and long-range attack prevention
##
## This module implements:
## - Checkpoint hash verification at known heights
## - Fork rejection below the last checkpoint
## - Minimum chain work validation
## - AssumeValid optimization for script verification
##
## Reference: Bitcoin Core chainparams.cpp, validation.cpp

import std/[algorithm, options, tables]
import ./params
import ../primitives/types

type
  CheckpointState* = object
    ## Tracks checkpoint verification state
    lastCheckpointHeight*: uint32   ## Height of the last known checkpoint
    lastCheckpointHash*: BlockHash  ## Hash at the last checkpoint
    checkpointMap*: Table[uint32, BlockHash]  ## Quick lookup for checkpoints
    minimumChainWork*: array[32, byte]
    assumeValidHash*: BlockHash

  CheckpointError* = enum
    ceOk = "checkpoint verification passed"
    ceCheckpointMismatch = "block hash does not match checkpoint"
    ceForkBelowCheckpoint = "cannot fork before the last checkpoint"
    ceInsufficientWork = "chain does not meet minimum work requirement"

  CheckpointResult* = object
    case isOk*: bool
    of true:
      discard
    of false:
      error*: CheckpointError

# Result constructors
proc checkpointOk*(): CheckpointResult =
  CheckpointResult(isOk: true)

proc checkpointErr*(e: CheckpointError): CheckpointResult =
  CheckpointResult(isOk: false, error: e)

proc initCheckpointState*(params: ConsensusParams): CheckpointState =
  ## Initialize checkpoint state from consensus params
  result.checkpointMap = initTable[uint32, BlockHash]()
  result.minimumChainWork = params.minimumChainWork
  result.assumeValidHash = params.assumeValidBlockHash

  # Build checkpoint map and find last checkpoint
  result.lastCheckpointHeight = 0
  result.lastCheckpointHash = params.genesisBlockHash

  for checkpoint in params.checkpoints:
    result.checkpointMap[checkpoint.height] = checkpoint.hash
    if checkpoint.height > result.lastCheckpointHeight:
      result.lastCheckpointHeight = checkpoint.height
      result.lastCheckpointHash = checkpoint.hash

proc getCheckpointHash*(state: CheckpointState, height: uint32): Option[BlockHash] =
  ## Get the expected block hash at a checkpoint height, if any
  if height in state.checkpointMap:
    some(state.checkpointMap[height])
  else:
    none(BlockHash)

proc isCheckpointHeight*(state: CheckpointState, height: uint32): bool =
  ## Check if a height is a known checkpoint
  height in state.checkpointMap

proc getLastCheckpointHeight*(state: CheckpointState): uint32 =
  ## Get the height of the last (highest) checkpoint
  state.lastCheckpointHeight

proc verifyCheckpoint*(state: CheckpointState, height: uint32,
                        hash: BlockHash): CheckpointResult =
  ## Verify that a block at a checkpoint height has the expected hash
  ##
  ## Returns:
  ## - ceOk if not a checkpoint height or hash matches
  ## - ceCheckpointMismatch if hash doesn't match checkpoint
  if height notin state.checkpointMap:
    return checkpointOk()

  let expectedHash = state.checkpointMap[height]
  if hash != expectedHash:
    return checkpointErr(ceCheckpointMismatch)

  checkpointOk()

proc canForkAt*(state: CheckpointState, forkHeight: uint32): bool =
  ## Check if a fork is allowed at the given height
  ##
  ## Fork rejection rule: No fork is allowed below the last checkpoint.
  ## This prevents long-range attacks where an attacker builds a hidden
  ## chain from early in Bitcoin's history.
  ##
  ## Returns true if fork is allowed (height > lastCheckpointHeight)
  if state.lastCheckpointHeight == 0:
    return true  # No checkpoints configured

  forkHeight > state.lastCheckpointHeight

proc verifyForkPoint*(state: CheckpointState, forkHeight: uint32): CheckpointResult =
  ## Verify that a fork point is valid (not below last checkpoint)
  if not state.canForkAt(forkHeight):
    return checkpointErr(ceForkBelowCheckpoint)

  checkpointOk()

proc isAssumeValidBlock*(state: CheckpointState, hash: BlockHash): bool =
  ## Check if a block hash matches the assume-valid block
  ## If so, script verification can be skipped for this block and all ancestors
  let zeroHash = BlockHash(default(array[32, byte]))
  if state.assumeValidHash == zeroHash:
    return false  # No assume-valid configured

  hash == state.assumeValidHash

proc shouldSkipScriptVerification*(state: CheckpointState,
                                    blockHash: BlockHash,
                                    isAncestorOfAssumeValid: bool): bool =
  ## Determine if script verification can be skipped for a block
  ##
  ## Script verification can be skipped if:
  ## 1. The block IS the assume-valid block, OR
  ## 2. The block is an ancestor of the assume-valid block
  ##
  ## This optimization significantly speeds up IBD by skipping
  ## expensive signature verification for old, well-established blocks.
  if state.isAssumeValidBlock(blockHash):
    return true

  isAncestorOfAssumeValid

# 256-bit work comparison utilities
proc compareWork256*(a, b: array[32, byte]): int =
  ## Compare two 256-bit work values stored in little-endian byte arrays
  ## Returns: -1 if a < b, 0 if a == b, 1 if a > b
  for i in countdown(31, 0):
    if a[i] < b[i]:
      return -1
    elif a[i] > b[i]:
      return 1
  0

proc isZeroWork*(w: array[32, byte]): bool =
  ## Check if work is zero (no minimum work requirement)
  for b in w:
    if b != 0:
      return false
  true

proc meetsMinimumWork*(state: CheckpointState,
                        chainWork: array[32, byte]): bool =
  ## Check if chain work meets the minimum requirement
  ##
  ## This is used during IBD to ensure we're syncing to a chain
  ## with sufficient proof-of-work, preventing low-work attacks.
  if isZeroWork(state.minimumChainWork):
    return true  # No minimum work requirement

  compareWork256(chainWork, state.minimumChainWork) >= 0

proc verifyMinimumWork*(state: CheckpointState,
                         chainWork: array[32, byte]): CheckpointResult =
  ## Verify chain meets minimum work requirement
  if not state.meetsMinimumWork(chainWork):
    return checkpointErr(ceInsufficientWork)

  checkpointOk()

# High-level validation combining all checkpoint checks
proc validateHeaderCheckpoint*(state: CheckpointState,
                                height: uint32,
                                hash: BlockHash,
                                isForkFromMainChain: bool = false,
                                forkPointHeight: uint32 = 0): CheckpointResult =
  ## Full checkpoint validation for a header
  ##
  ## Checks:
  ## 1. If at checkpoint height, hash must match
  ## 2. If this is a fork (isForkFromMainChain=true), verify fork point is above last checkpoint
  ##
  ## Note: Normal header chain extension (not a fork) does not need fork point validation.
  ## Fork point validation only applies when processing headers from an alternative chain.

  # Check if this is a checkpoint height
  let checkResult = state.verifyCheckpoint(height, hash)
  if not checkResult.isOk:
    return checkResult

  # Only check fork point if this is actually a fork from the main chain
  if isForkFromMainChain:
    let forkResult = state.verifyForkPoint(forkPointHeight)
    if not forkResult.isOk:
      return forkResult

  checkpointOk()

proc validateChainCheckpoint*(state: CheckpointState,
                               tipHeight: uint32,
                               tipWork: array[32, byte],
                               peerTipHeight: uint32): CheckpointResult =
  ## Validate that a peer's chain passes checkpoint requirements
  ##
  ## During IBD, only accept headers from peers that can demonstrate
  ## a chain passing the most recent checkpoint. This prevents wasting
  ## bandwidth on chains that will be rejected.
  ##
  ## Checks:
  ## 1. Chain work meets minimum requirement
  ## 2. If peer claims height past last checkpoint, we must have reached it

  # Verify minimum chain work
  let workResult = state.verifyMinimumWork(tipWork)
  if not workResult.isOk:
    return workResult

  # If peer's tip is past last checkpoint but we haven't reached it,
  # this is potentially suspicious during IBD
  # (Note: This is informational - actual enforcement happens during header processing)

  checkpointOk()

# Utility functions for checkpoint management
proc getCheckpoints*(params: ConsensusParams): seq[Checkpoint] =
  ## Get the list of checkpoints for a network
  params.checkpoints

proc getCheckpointsSorted*(params: ConsensusParams): seq[Checkpoint] =
  ## Get checkpoints sorted by height (ascending)
  var checkpoints = params.checkpoints
  checkpoints.sort(proc(a, b: Checkpoint): int = cmp(a.height, b.height))
  checkpoints

proc findLastCheckpointBelow*(state: CheckpointState,
                               height: uint32): Option[tuple[height: uint32, hash: BlockHash]] =
  ## Find the highest checkpoint at or below the given height
  var bestHeight: uint32 = 0
  var bestHash: BlockHash
  var found = false

  for cpHeight, cpHash in state.checkpointMap:
    if cpHeight <= height and cpHeight >= bestHeight:
      bestHeight = cpHeight
      bestHash = cpHash
      found = true

  if found:
    some((height: bestHeight, hash: bestHash))
  else:
    none(tuple[height: uint32, hash: BlockHash])

proc isBlockOnCheckpointChain*(state: CheckpointState,
                                blockHeight: uint32,
                                blockHash: BlockHash,
                                getAncestorHash: proc(height: uint32): Option[BlockHash]): bool =
  ## Check if a block is on a chain that passes all checkpoints up to its height
  ##
  ## This requires being able to look up ancestor hashes, so it needs
  ## a callback that can retrieve block hashes by height.
  ##
  ## Returns true if all checkpoints at or below blockHeight are satisfied.
  for cpHeight, cpHash in state.checkpointMap:
    if cpHeight > blockHeight:
      continue  # Checkpoint is above our block, skip

    if cpHeight == blockHeight:
      # This block IS at a checkpoint height
      if blockHash != cpHash:
        return false
    else:
      # Check ancestor at checkpoint height
      let ancestorOpt = getAncestorHash(cpHeight)
      if ancestorOpt.isNone:
        return false  # Can't verify - assume invalid
      if ancestorOpt.get() != cpHash:
        return false

  true
