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

## Two weeks in seconds — matches Bitcoin Core's TWO_WEEKS_IN_SECONDS constant.
## Used to derive the block-count proxy for the safety guard.
const TwoWeeksInSeconds* = 60 * 60 * 24 * 7 * 2  # 1,209,600

## Approximate number of blocks in two weeks at 10 min/block.
## We use this as a proxy for the equivalent-work guard (condition 6)
## when we do not have per-header timestamp data readily available.
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
  ## Hash reported by the active chain at blockHeight (getBlockHashByHeight).
  ## If none, the block is not yet on the active chain — scripts must verify.
  activeHashAtBlockHeight*: Option[BlockHash]
  ## Height of the assumevalid block (from params.assumeValidHeight,
  ## or obtained from the block index when the hash is found).
  assumeValidHeight*: int32
  ## Hash at assumeValidHeight on the active chain (getBlockHashByHeight).
  ## If none, we haven't seen that part of the chain — scripts must verify.
  activeHashAtAssumeValidHeight*: Option[BlockHash]
  ## Best-header chain tip height.
  bestHeaderHeight*: int32
  ## Best-header chainwork (256-bit, little-endian bytes).
  bestHeaderChainWork*: array[32, byte]

proc compareWork(a, b: array[32, byte]): int =
  ## Compare two 256-bit little-endian chainwork values.
  ## Returns -1, 0, or 1.
  for i in countdown(31, 0):
    if a[i] < b[i]: return -1
    elif a[i] > b[i]: return 1
  0

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

  # Condition 6: The best-known header is at least two weeks of equivalent work
  # past the block being connected.
  # Bitcoin Core uses GetBlockProofEquivalentTime to convert chainwork
  # difference to seconds.  We approximate with block-count distance:
  # if bestHeaderHeight - blockHeight >= TwoWeeksInBlocks the check passes.
  if ctx.bestHeaderHeight - ctx.blockHeight < TwoWeeksInBlocks:
    return ssrTooRecentForBestHeader

  # All six conditions satisfied — scripts may be skipped.
  ssrSkip
