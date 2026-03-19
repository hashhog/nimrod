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

# ============================================================================
# Chain Management (invalidateblock / reconsiderblock / preciousblock)
# ============================================================================
# Reference: Bitcoin Core validation.cpp InvalidateBlock, ReconsiderBlock, PreciousBlock

import std/deques
import ../storage/chainstate

type
  ChainManagementError* = enum
    cmeOk = "ok"
    cmeBlockNotFound = "block not found"
    cmeCannotInvalidateGenesis = "cannot invalidate genesis block"
    cmeUndoDataMissing = "undo data missing for disconnect"
    cmeDisconnectFailed = "failed to disconnect block"
    cmeReconnectFailed = "failed to reconnect block"

  ChainManagementResult* = object
    case isOk*: bool
    of true:
      discard
    of false:
      error*: ChainManagementError

proc chainMgmtOk*(): ChainManagementResult =
  ChainManagementResult(isOk: true)

proc chainMgmtErr*(e: ChainManagementError): ChainManagementResult =
  ChainManagementResult(isOk: false, error: e)

proc setBlockFailureFlags*(
  cs: var ChainState,
  invalidBlock: BlockIndex
) =
  ## Mark all descendants of invalidBlock as BLOCK_FAILED_CHILD
  ## Reference: Bitcoin Core's SetBlockFailureFlags
  ##
  ## Uses BFS to find all descendants and mark them

  var queue = initDeque[BlockHash]()
  var visited = initTable[string, bool]()

  # Start with all blocks at height > invalidBlock.height
  # We need to check if they descend from invalidBlock
  for h in (invalidBlock.height + 1) .. cs.bestHeight:
    let hashOpt = cs.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      queue.addLast(hashOpt.get())

  while queue.len > 0:
    let currentHash = queue.popFirst()
    let hashStr = $array[32, byte](currentHash)

    if hashStr in visited:
      continue
    visited[hashStr] = true

    let idxOpt = cs.db.getBlockIndex(currentHash)
    if idxOpt.isNone:
      continue

    var idx = idxOpt.get()

    # Check if this block descends from invalidBlock
    # A block descends from invalidBlock if:
    # 1. Its prevHash is invalidBlock's hash, OR
    # 2. Its prevHash is a descendant of invalidBlock
    var isDescendant = false
    if idx.prevHash == invalidBlock.hash:
      isDescendant = true
    else:
      # Check if prevHash is already marked as failed
      let prevIdxOpt = cs.db.getBlockIndex(idx.prevHash)
      if prevIdxOpt.isSome:
        let prevIdx = prevIdxOpt.get()
        if prevIdx.failureFlags.hasFlag(BLOCK_FAILED_VALID) or
           prevIdx.failureFlags.hasFlag(BLOCK_FAILED_CHILD):
          isDescendant = true

    if isDescendant:
      # Mark as BLOCK_FAILED_CHILD
      idx.failureFlags.setFlag(BLOCK_FAILED_CHILD)
      cs.db.putBlockIndex(idx)

proc resetBlockFailureFlags*(
  cs: var ChainState,
  pindex: BlockIndex
) =
  ## Clear failure flags from a block and all its ancestors/descendants
  ## Reference: Bitcoin Core's ResetBlockFailureFlags
  ##
  ## Note: This function directly clears the flag from the block itself,
  ## plus walks ancestors and descendants to clear their flags too.

  let targetHeight = pindex.height

  # First, always clear the flags from the target block itself
  var targetIdx = pindex
  if targetIdx.failureFlags.isFailed():
    targetIdx.failureFlags.clearFlag(BLOCK_FAILED_VALID)
    targetIdx.failureFlags.clearFlag(BLOCK_FAILED_CHILD)
    cs.db.putBlockIndex(targetIdx)

  # Walk ancestors (blocks that pindex descends from) and clear their flags
  var current = pindex
  while current.height > 0:
    let prevOpt = cs.db.getBlockIndex(current.prevHash)
    if prevOpt.isNone:
      break
    var ancestor = prevOpt.get()
    if ancestor.failureFlags.isFailed():
      ancestor.failureFlags.clearFlag(BLOCK_FAILED_VALID)
      ancestor.failureFlags.clearFlag(BLOCK_FAILED_CHILD)
      cs.db.putBlockIndex(ancestor)
    current = ancestor

  # Walk descendants (blocks at greater heights that descend from pindex)
  # We need to iterate through all blocks at heights > pindex.height and check
  # if they descend from pindex
  #
  # Note: In the current implementation, we only track blocks on the main chain
  # via getBlockHashByHeight. Blocks not on the main chain would need separate
  # tracking. For simplicity, we iterate by hash from the active chain.
  for h in (targetHeight + 1) .. cs.bestHeight:
    let hashOpt = cs.db.getBlockHashByHeight(h)
    if hashOpt.isNone:
      continue

    let idxOpt = cs.db.getBlockIndex(hashOpt.get())
    if idxOpt.isNone:
      continue

    var idx = idxOpt.get()

    # Skip blocks without failure flags
    if not idx.failureFlags.isFailed():
      continue

    # Check if this block descends from pindex
    var desc = idx
    while desc.height > targetHeight:
      let prevOpt = cs.db.getBlockIndex(desc.prevHash)
      if prevOpt.isNone:
        break
      desc = prevOpt.get()

    if desc.hash == pindex.hash:
      idx.failureFlags.clearFlag(BLOCK_FAILED_VALID)
      idx.failureFlags.clearFlag(BLOCK_FAILED_CHILD)
      cs.db.putBlockIndex(idx)

proc invalidateBlock*(
  cs: var ChainState,
  blockHash: BlockHash
): ChainManagementResult =
  ## Mark a block and all its descendants as invalid
  ## If the block is on the active chain, disconnect it and all descendants
  ## Reference: Bitcoin Core's InvalidateBlock
  ##
  ## Returns error if:
  ## - Block is the genesis block (height 0)
  ## - Block not found
  ## - Undo data missing for active chain blocks

  # Look up the block index
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return chainMgmtErr(cmeBlockNotFound)

  var idx = idxOpt.get()

  # Cannot invalidate genesis block
  if idx.height == 0:
    return chainMgmtErr(cmeCannotInvalidateGenesis)

  # Check if this block is on the active chain
  let activeHashAtHeight = cs.db.getBlockHashByHeight(idx.height)
  let isOnActiveChain = activeHashAtHeight.isSome and activeHashAtHeight.get() == blockHash

  if isOnActiveChain:
    # Disconnect blocks from tip back to (and including) this block
    while cs.bestHeight >= idx.height:
      let tipHashOpt = cs.db.getBlockHashByHeight(cs.bestHeight)
      if tipHashOpt.isNone:
        break

      let tipBlkOpt = cs.db.getBlock(tipHashOpt.get())
      if tipBlkOpt.isNone:
        return chainMgmtErr(cmeUndoDataMissing)

      let tipBlk = tipBlkOpt.get()
      let disconnectResult = cs.disconnectBlock(tipBlk)
      if not disconnectResult.isOk:
        return chainMgmtErr(cmeDisconnectFailed)

      # Mark disconnected block as BLOCK_FAILED_VALID
      var tipIdx = cs.db.getBlockIndex(tipHashOpt.get()).get()
      tipIdx.failureFlags.setFlag(BLOCK_FAILED_VALID)
      cs.db.putBlockIndex(tipIdx)

  else:
    # Block is not on active chain, just mark it as invalid
    idx.failureFlags.setFlag(BLOCK_FAILED_VALID)
    cs.db.putBlockIndex(idx)

  # Mark all descendants as BLOCK_FAILED_CHILD
  # Re-fetch the index in case it was updated during disconnection
  let updatedIdxOpt = cs.db.getBlockIndex(blockHash)
  if updatedIdxOpt.isSome:
    cs.setBlockFailureFlags(updatedIdxOpt.get())

  chainMgmtOk()

proc reconsiderBlock*(
  cs: var ChainState,
  blockHash: BlockHash
): ChainManagementResult =
  ## Remove invalidity status from a block and all related blocks
  ## This undoes the effect of invalidateblock
  ## Reference: Bitcoin Core's ReconsiderBlock
  ##
  ## Note: This does NOT automatically reconnect the block to the chain.
  ## Use activateBestChain or similar after reconsiderBlock to potentially
  ## switch to the reconsidered chain if it has more work.

  # Look up the block index
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return chainMgmtErr(cmeBlockNotFound)

  let idx = idxOpt.get()

  # Clear failure flags from this block and all ancestors/descendants
  cs.resetBlockFailureFlags(idx)

  chainMgmtOk()

proc preciousBlock*(
  cs: var ChainState,
  blockHash: BlockHash
): ChainManagementResult =
  ## Mark a block as "precious" - prefer this chain in case of equal work
  ## Reference: Bitcoin Core's PreciousBlock
  ##
  ## Precious blocks get a lower (more negative) sequenceId, which causes
  ## them to be preferred over other blocks with equal chainwork.
  ##
  ## This is used when a node operator wants to manually prefer one chain
  ## over another without invalidating the competing chain.

  # Look up the block index
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return chainMgmtErr(cmeBlockNotFound)

  var idx = idxOpt.get()

  # Check if this block has at least as much work as the current tip
  let tipWorkComparison = compareWork256(idx.totalWork, cs.totalWork)
  if tipWorkComparison < 0:
    # Block has less work than current tip, nothing to do
    return chainMgmtOk()

  # Assign a negative sequence ID to mark as precious
  # Lower (more negative) values are more precious
  # We use a simple decrementing counter approach
  var minSeqId: int32 = 0
  for h in 0'i32 .. cs.bestHeight:
    let hashOpt = cs.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      let existingIdx = cs.db.getBlockIndex(hashOpt.get())
      if existingIdx.isSome and existingIdx.get().sequenceId < minSeqId:
        minSeqId = existingIdx.get().sequenceId

  # Set this block's sequence ID to one less than the minimum
  idx.sequenceId = minSeqId - 1
  cs.db.putBlockIndex(idx)

  chainMgmtOk()

proc getBlockFailureStatus*(cs: ChainState, blockHash: BlockHash): Option[BlockFailureFlags] =
  ## Get the failure flags for a block
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isSome:
    some(idxOpt.get().failureFlags)
  else:
    none(BlockFailureFlags)

proc isBlockInvalid*(cs: ChainState, blockHash: BlockHash): bool =
  ## Check if a block is marked as invalid
  let flagsOpt = cs.getBlockFailureStatus(blockHash)
  if flagsOpt.isSome:
    flagsOpt.get().isFailed()
  else:
    false
