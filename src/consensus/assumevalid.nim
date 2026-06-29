## Assume-valid ancestor-check semantics
##
## Bitcoin Core v28.0 reference: src/validation.cpp lines 2345-2383
##
## Script verification is SKIPPED if and only if ALL six conditions hold:
##   1. assumedValid hash is configured (non-zero).
##   2. The assumed-valid block is in the local block index.
##   3. The block being connected is an ancestor of the assumed-valid block
##      on the active chain (ancestor check, NOT a height check).
##   4. The block is an ancestor of the best known header.
##   5. The best-known-header chainwork >= minimumChainWork.
##   6. The best-known-header is at least 2 weeks of equivalent work past
##      the block being connected (anti-fake-header-chain safety guard).
##
## What this does NOT skip:
##   - PoW, merkle root, coinbase, BIP30, block weight, transaction structure
##   - UTXO updates — the UTXO set is always built correctly
##
## Regtest: assumedValid is always None/zero => every block verifies scripts.

import std/options
import ./params
import ../primitives/types
import ../primitives/uint256

## Two weeks in seconds — matches Bitcoin Core's TWO_WEEKS_IN_SECONDS constant.
## Used for the GetBlockProofEquivalentTime safety guard (condition 6).
const TwoWeeksInSeconds* = 60 * 60 * 24 * 7 * 2  # 1,209,600

## Legacy block-count proxy (kept for documentation; no longer used in condition 6).
const TwoWeeksInBlocks* = TwoWeeksInSeconds div 600  # 2016

## ScriptSkipReason documents why scripts will or will not be skipped.
## A nil/empty string means "skip". A non-empty string means "verify".
## Matches Bitcoin Core's `script_check_reason` pattern.
type ScriptSkipReason* = enum
  ssrSkip                     ## All conditions pass — skip scripts
  ssrAssumeValidUnset         ## assumevalid hash is zero/unset
  ssrHashNotInIndex           ## assumevalid hash not in local block index
  ssrNotAncestorOfAssumeValid ## block not on the assumed-valid chain
  ssrNotAncestorOfBestHeader  ## block not in best header chain
  ssrBelowMinimumChainWork    ## best-header chainwork < minimumChainWork
  ssrTooRecentForBestHeader   ## block too recent relative to best header

proc `$`*(r: ScriptSkipReason): string =
  case r
  of ssrSkip:                     "skip"
  of ssrAssumeValidUnset:         "assumevalid=0 (always verify)"
  of ssrHashNotInIndex:           "assumevalid hash not in headers"
  of ssrNotAncestorOfAssumeValid: "block not in assumevalid chain"
  of ssrNotAncestorOfBestHeader:  "block not in best header chain"
  of ssrBelowMinimumChainWork:    "best header chainwork below minimumchainwork"
  of ssrTooRecentForBestHeader:   "block too recent relative to best header"

## Context passed to shouldSkipScripts.  All fields are required; the caller
## fills them in from whatever source is appropriate (ChainState, SyncManager,
## etc.).  Using an explicit context struct avoids threading N parameters
## through every call site.
type AssumeValidContext* = object
  ## Hash of the block being connected.
  blockHash*: BlockHash
  ## Height of the block being connected.
  blockHeight*: int32
  ## Hash recorded in the block INDEX at blockHeight (header chain / pindex).
  ## NOT the active chain — Bitcoin Core's GetAncestor walks block-index
  ## pointers and does not require the ancestor to be on the active chain,
  ## which is essential during IBD where headers reach assumeValidHeight
  ## long before the active chain does.  If none, the header chain has not
  ## covered this height and we cannot confirm the ancestor relation.
  activeHashAtBlockHeight*: Option[BlockHash]
  ## Height of the assumevalid block (from params.assumeValidHeight,
  ## or obtained from the block index when the hash is found).
  assumeValidHeight*: int32
  ## Hash recorded in the block INDEX at assumeValidHeight.  Again, this is
  ## a header-chain / pindex lookup, NOT an active-chain lookup.  If none,
  ## we have not header-synced to assumeValidHeight yet — scripts must
  ## verify.  If some but != params.assumeValidBlockHash, we are on a fork
  ## that does not include the hardcoded assumevalid hash.
  activeHashAtAssumeValidHeight*: Option[BlockHash]
  ## Best-header chain tip height.
  bestHeaderHeight*: int32
  ## Best-header chainwork (256-bit, little-endian bytes).
  bestHeaderChainWork*: array[32, byte]
  ## nBits of the best-known header tip, used by GetBlockProof in condition 6.
  bestHeaderBits*: uint32
  ## Cumulative chainwork of the block being connected (pindex.nChainWork).
  ## Populated from the block index entry written during header sync (bsHeaderOnly).
  ## Zero when not available (new block not yet in index); condition 6 still applies.
  blockChainWork*: array[32, byte]

proc compareWork(a, b: array[32, byte]): int =
  ## Compare two 256-bit little-endian chainwork values.
  ## Returns -1, 0, or 1.
  for i in countdown(31, 0):
    if a[i] < b[i]: return -1
    elif a[i] > b[i]: return 1
  0

proc getBlockProofFromBits(bits: uint32): UInt256 =
  ## Compute the proof-of-work value for a compact nBits target.
  ## Mirrors Bitcoin Core GetBitsProof (chain.cpp:121-133):
  ##   proof = ~target / (target+1) + 1
  ## Returns zero for invalid bits (zero target, negative flag, overflow).
  ## A zero return means the caller must treat the check as "too recent" (fail-safe).
  let target = setCompact(bits)
  if target.isZero():
    return initUInt256()
  let notTarget = bitnot(target)
  let targetPlus1 = target + initUInt256(1'u64)
  if targetPlus1.isZero():
    return initUInt256(1'u64)
  (notTarget div targetPlus1) + initUInt256(1'u64)

proc isZeroHash(h: BlockHash): bool =
  for b in array[32, byte](h):
    if b != 0: return false
  true

proc shouldSkipScripts*(
  ctx: AssumeValidContext,
  params: ConsensusParams
): ScriptSkipReason =
  ## Evaluate all six conditions and return the reason scripts will or will not
  ## be skipped.  Returns ssrSkip when scripts may be safely omitted.
  ##
  ## Re-evaluated per block; do NOT persist the result across restarts.

  # Condition 1: assumedValid hash must be configured (non-zero).
  # Regtest sets this to zero — always verify.
  if isZeroHash(params.assumeValidBlockHash):
    return ssrAssumeValidUnset

  # Condition 2: The assumed-valid block must be in the local block index.
  # We approximate this by checking that we have the active-chain hash at
  # assumeValidHeight.  If activeHashAtAssumeValidHeight is none, the index
  # entry does not exist yet.
  if ctx.activeHashAtAssumeValidHeight.isNone:
    return ssrHashNotInIndex

  # Condition 3: The block being connected is an ancestor of the assumed-valid
  # block on the active chain.
  #
  # Bitcoin Core check: assumeValidIndex.GetAncestor(pindex->nHeight) == pindex
  #
  # Equivalent via the active-chain height map:
  #   - The block must be at or below the assumevalid height.
  #   - The active-chain block at blockHeight must BE this block.
  #   - The active-chain block at assumeValidHeight must BE the assumevalid hash.
  #
  # Together these imply blockHash is an ancestor of assumeValidBlockHash on
  # the active chain.
  if ctx.blockHeight > ctx.assumeValidHeight:
    # Block is above the assumevalid block — cannot be its ancestor.
    return ssrNotAncestorOfAssumeValid

  if ctx.activeHashAtBlockHeight.isNone or
     ctx.activeHashAtBlockHeight.get() != ctx.blockHash:
    # Block is not the active-chain block at this height — different chain.
    return ssrNotAncestorOfAssumeValid

  if ctx.activeHashAtAssumeValidHeight.get() != params.assumeValidBlockHash:
    # The active chain at assumeValidHeight is a different block — we are on a
    # fork that does not include the hardcoded assumevalid hash.
    return ssrNotAncestorOfAssumeValid

  # Condition 4: The block is an ancestor of the best known header.
  # If the best header is below this block's height we cannot confirm this.
  if ctx.bestHeaderHeight < ctx.blockHeight:
    return ssrNotAncestorOfBestHeader

  # Condition 5: Best-header chainwork >= minimumChainWork.
  if compareWork(ctx.bestHeaderChainWork, params.minimumChainWork) < 0:
    return ssrBelowMinimumChainWork

  # Condition 6: GetBlockProofEquivalentTime(best_header, pindex, best_header, params)
  # must be > TWO_WEEKS_IN_SECONDS (1 209 600 s).
  #
  # Exact formula per Bitcoin Core chain.cpp:136-151:
  #   r = (best_header.nChainWork - pindex.nChainWork) * nPowTargetSpacing
  #       / GetBlockProof(best_header.nBits)
  # If r <= 1 209 600, the block is "too recent" → verify scripts.
  #
  # Uses nimrod's exact 256-bit UInt256 arithmetic (no float).
  # A zero GetBlockProof (invalid bits → proof = 0) is treated as "too recent"
  # (conservative fail-safe).
  let proof = getBlockProofFromBits(ctx.bestHeaderBits)
  if proof.isZero():
    # bestHeaderBits unset or invalid → cannot compute → verify scripts
    return ssrTooRecentForBestHeader

  let bestWork = initUInt256(ctx.bestHeaderChainWork)
  let pindexWork = initUInt256(ctx.blockChainWork)
  if bestWork <= pindexWork:
    # pindex work >= best-header work → no progress → equivalent time ≤ 0 → too recent
    return ssrTooRecentForBestHeader

  # workDiff * powTargetSpacing / proof.
  # The multiplication may wrap a 256-bit value in extreme artificial scenarios
  # (e.g. test vectors with workDiff = 2^256-1), but for any realistic Bitcoin
  # chainwork the result is far below 2^256 and the division is exact.
  let workDiff = bestWork - pindexWork
  let r = workDiff * uint64(params.powTargetSpacing)
  let equivalentTime = r div proof

  let twoWeeks = initUInt256(uint64(TwoWeeksInSeconds))
  if equivalentTime <= twoWeeks:
    return ssrTooRecentForBestHeader

  # All six conditions satisfied — scripts may be skipped.
  ssrSkip
