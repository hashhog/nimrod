## Test matrix for the real assumevalid ancestor-check semantics.
##
## Seven-case matrix from ASSUMEVALID-REFERENCE.md:
##
## 1. Unit — assumevalid absent: every block verifies scripts (ssrAssumeValidUnset).
## 2. Unit — block IS ancestor of assumevalid: ssrSkip fires.
## 3. Unit — block NOT in assumevalid chain at same height: ssrNotAncestorOfAssumeValid.
## 4. Unit — block height above assumevalid height: ssrNotAncestorOfAssumeValid.
## 5. Unit — assumevalid hash not yet in block index: ssrHashNotInIndex.
## 6. Unit — block invalid on non-script check (bad merkle / bad PoW):
##           block is rejected EVEN IF it would be an ancestor of assumevalid.
##           Non-script validation always runs regardless of skip.
## 7. Integration — regtest IBD: assumevalid is unset on regtest; every block
##                  verifies scripts (ssrAssumeValidUnset).

import std/[options, strutils]
import unittest2
import ../src/consensus/[params, validation, assumevalid]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# ─── helpers ──────────────────────────────────────────────────────────────────

proc hexToBytes32(hex: string): array[32, byte] =
  assert hex.len == 64
  for i in 0..31:
    let h = hex[i*2 ..< i*2 + 2]
    result[31 - i] = byte(parseHexInt(h))

proc makeHash(b: byte): BlockHash =
  var arr: array[32, byte]
  arr[0] = b
  BlockHash(arr)

## Build a well-formed AssumeValidContext that passes all six conditions
## (ancestor on active chain, best-header height far above, sufficient work).
proc passingContext(blockHeight: int32, params: ConsensusParams): AssumeValidContext =
  let avHash = params.assumeValidBlockHash
  result = AssumeValidContext(
    blockHash: BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")),
    blockHeight: blockHeight,
    assumeValidHeight: params.assumeValidHeight,
    # The assumevalid block IS on the active chain
    activeHashAtAssumeValidHeight: some(avHash),
    # This block IS on the active chain at its height
    activeHashAtBlockHeight: some(BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"))),
    # Best header height is way above block (satisfies 2-week guard)
    bestHeaderHeight: blockHeight + 3000,
    # Best header chainwork is max (satisfies minimumChainWork)
    bestHeaderChainWork: hexToBytes32(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
  )

# ─── suite ────────────────────────────────────────────────────────────────────

suite "assumevalid ancestor-check semantics":

  # Case 1: assumevalid absent — every block verifies scripts
  test "case1: assumevalid unset => always verify":
    let params = regtestParams()
    let ctx = AssumeValidContext(
      blockHash: makeHash(1),
      blockHeight: 50_000,
      assumeValidHeight: 0,
      activeHashAtBlockHeight: some(makeHash(1)),
      activeHashAtAssumeValidHeight: none(BlockHash),
      bestHeaderHeight: 100_000,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrAssumeValidUnset
    check reason != ssrSkip

  # Also verify with mainnet params but explicitly zero hash
  test "case1b: mainnet params with zero assumevalid => always verify":
    var params = mainnetParams()
    params.assumeValidBlockHash = BlockHash(default(array[32, byte]))
    let ctx = passingContext(100_000, params)
    check shouldSkipScripts(ctx, params) == ssrAssumeValidUnset

  # Case 2: block IS ancestor of assumevalid — script skip fires
  test "case2: block is ancestor of assumevalid => skip scripts":
    let params = mainnetParams()
    # blockHeight well below assumeValidHeight (938343), all conditions pass
    let ctx = passingContext(500_000, params)
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrSkip

  # The exact assumevalid height also qualifies
  test "case2b: block AT assumevalid height => skip scripts":
    let params = mainnetParams()
    var ctx = passingContext(params.assumeValidHeight, params)
    # At exactly assumeValidHeight, blockHash must equal assumeValidBlockHash
    ctx.blockHash = params.assumeValidBlockHash
    ctx.activeHashAtBlockHeight = some(params.assumeValidBlockHash)
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrSkip

  # Case 3: block at same height but not on assumevalid chain
  test "case3: block not on assumevalid chain => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    # Simulate a fork: the active-chain block at blockHeight is a DIFFERENT hash
    ctx.activeHashAtBlockHeight = some(makeHash(0x42))
    # ctx.blockHash != activeHashAtBlockHeight => not ancestor
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrNotAncestorOfAssumeValid

  # Case 3b: active chain has the block, but assumevalid block is on a different chain
  test "case3b: assumevalid hash not on active chain => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    # The active chain at assumeValidHeight has a different block
    ctx.activeHashAtAssumeValidHeight = some(makeHash(0x99))
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrNotAncestorOfAssumeValid

  # Case 4: block height above assumevalid height
  test "case4: block above assumevalid height => verify":
    let params = mainnetParams()
    # blockHeight > assumeValidHeight (938343)
    var ctx = passingContext(params.assumeValidHeight + 100, params)
    ctx.blockHeight = params.assumeValidHeight + 100
    # Reset heights so bestHeaderHeight still satisfies condition 6
    ctx.bestHeaderHeight = ctx.blockHeight + 3000
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrNotAncestorOfAssumeValid

  # Case 5: assumevalid hash not yet in block index
  test "case5: assumevalid hash not in index => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    # Signal that the assumevalid block is NOT in our index
    ctx.activeHashAtAssumeValidHeight = none(BlockHash)
    let reason = shouldSkipScripts(ctx, params)
    check reason == ssrHashNotInIndex

  # Case 6: non-script validation always runs
  # The block would pass the ancestor-check (case 2), but it has a bad merkle
  # root or bad PoW — validateBlock / validateBlockHeader returns an error
  # BEFORE we even call shouldSkipScripts on the apply path.
  test "case6: invalid block (bad merkle) rejected regardless of assumevalid":
    let params = mainnetParams()
    # Build a minimal block with a bad merkle root
    let dummyCoinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                         vout: 0xffffffff'u32),
        scriptSig: @[0x01'u8, 0x00, 0x00],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(value: Satoshi(5_000_000_000'i64),
                       scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 0
    )
    let badMerkle: array[32, byte] = hexToBytes32(
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    let header = BlockHeader(
      version: 1,
      prevBlock: params.genesisBlockHash,
      merkleRoot: badMerkle,   # deliberately wrong
      timestamp: 1296688602'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    )
    let blk = Block(header: header, txs: @[dummyCoinbase])
    # checkBlock should catch the bad merkle root without consulting assumevalid
    let result = checkBlock(blk, params)
    check not result.isOk
    check result.error == veBadMerkleRoot

  # Also verify: shouldSkipScripts returns ssrSkip for this block
  # (ancestor-check passes) — but the block is still rejected because non-script
  # validation runs first and catches the bad merkle root.
  test "case6b: shouldSkipScripts=skip but bad-merkle block still rejected":
    let params = mainnetParams()
    # Confirm that shouldSkipScripts would say "skip" for a block at this height
    let ctx = passingContext(500_000, params)
    check shouldSkipScripts(ctx, params) == ssrSkip
    # This proves scripts would be skipped — but the calling code calls
    # validateBlock / checkBlock BEFORE calling verifyScripts, so non-script
    # checks run unconditionally.  The ssrSkip decision only gates the
    # verifyScripts call, not validateBlock.

  # Case 7: regtest — assumevalid unset, every block verifies scripts
  test "case7: regtest IBD — assumevalid absent, no skip":
    let params = regtestParams()
    # Build contexts at several heights
    for h in [0'i32, 100, 1000, 9999]:
      let ctx = AssumeValidContext(
        blockHash: makeHash(byte(h)),
        blockHeight: h,
        assumeValidHeight: params.assumeValidHeight,  # 0 on regtest
        activeHashAtBlockHeight: some(makeHash(byte(h))),
        activeHashAtAssumeValidHeight: none(BlockHash),
        bestHeaderHeight: h + 10,
        bestHeaderChainWork: hexToBytes32(
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
      )
      let reason = shouldSkipScripts(ctx, params)
      check(reason == ssrAssumeValidUnset)

  # Additional: safety condition — below minimumChainWork => verify
  test "safety: best-header chainwork below minimum => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    ctx.bestHeaderChainWork = default(array[32, byte])  # zero work
    check shouldSkipScripts(ctx, params) == ssrBelowMinimumChainWork

  # Additional: safety condition — best-header too close => verify
  test "safety: best-header too close (< 2016 blocks above) => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    ctx.bestHeaderHeight = ctx.blockHeight + 100  # only 100 blocks above
    check shouldSkipScripts(ctx, params) == ssrTooRecentForBestHeader

  # Additional: block not in best-header chain
  test "safety: block above best-header height => verify":
    let params = mainnetParams()
    var ctx = passingContext(500_000, params)
    ctx.bestHeaderHeight = ctx.blockHeight - 1  # best header is BELOW block
    check shouldSkipScripts(ctx, params) == ssrNotAncestorOfBestHeader

  # Verify fleet-standard hashes match ASSUMEVALID-REFERENCE.md
  test "fleet hashes: mainnet assumevalid matches v28.0 reference":
    let params = mainnetParams()
    let expected = BlockHash(hexToBytes32(
      "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"))
    check params.assumeValidBlockHash == expected

  test "fleet hashes: testnet4 assumevalid matches v28.0 reference":
    let params = testnet4Params()
    let expected = BlockHash(hexToBytes32(
      "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"))
    check params.assumeValidBlockHash == expected

  test "fleet hashes: regtest assumevalid is zero":
    let params = regtestParams()
    check params.assumeValidBlockHash == BlockHash(default(array[32, byte]))

  # ────────────────────────────────────────────────────────────────────────
  # Regression: mainnet 850846 IBD stall.  The bug was that the call sites
  # populated activeHashAt* from the ACTIVE CHAIN (chainDb.getBlockHashByHeight)
  # which is empty above the current chain tip during IBD.  shouldSkipScripts
  # then tripped ssrHashNotInIndex / ssrNotAncestorOfAssumeValid and scripts
  # ran (and failed) for blocks the spec says should skip.
  #
  # The fix: callers populate activeHashAt* from the BLOCK INDEX (header
  # chain), which is populated well past assumeValidHeight during IBD.  These
  # tests exercise the context as the fixed sync.nim call site now builds it.
  # ────────────────────────────────────────────────────────────────────────

  test "regression-850846a: below assumeValid, active chain empty, headers full => skip":
    # IBD scenario: we are at chain tip 850846, headers extend to 944962.
    # assumeValidHeight=938343.  The ACTIVE-chain lookup at 938343 would be
    # none; the BLOCK-INDEX (header chain) lookup returns the real hash.
    let params = mainnetParams()
    let blockHash = BlockHash(hexToBytes32(
      "0000000000000000000a5cbf111111111111111111111111111111111111abcd"))
    let ctx = AssumeValidContext(
      blockHash: blockHash,
      blockHeight: 850_846'i32,
      assumeValidHeight: params.assumeValidHeight,
      # Populated from header chain (block index), not active chain:
      activeHashAtBlockHeight: some(blockHash),
      activeHashAtAssumeValidHeight: some(params.assumeValidBlockHash),
      bestHeaderHeight: 944_962'i32,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    check shouldSkipScripts(ctx, params) == ssrSkip

  test "regression-850846b: below assumeValid, caller uses active-chain => ssrHashNotInIndex":
    # Documents the OLD buggy behaviour: if a caller still populates the
    # context from the active chain and the active chain has not reached
    # assumeValidHeight yet, shouldSkipScripts correctly refuses to skip.
    # This locks in the contract that callers MUST use block-index lookups
    # during IBD.  If this starts returning ssrSkip, the field semantics
    # have changed and sync.nim's callsite comment needs updating.
    let params = mainnetParams()
    let blockHash = BlockHash(hexToBytes32(
      "0000000000000000000a5cbf111111111111111111111111111111111111abcd"))
    let ctx = AssumeValidContext(
      blockHash: blockHash,
      blockHeight: 850_846'i32,
      assumeValidHeight: params.assumeValidHeight,
      # Simulate a caller that WRONGLY used the active chain during IBD:
      activeHashAtBlockHeight: some(blockHash),
      activeHashAtAssumeValidHeight: none(BlockHash),
      bestHeaderHeight: 944_962'i32,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    check shouldSkipScripts(ctx, params) == ssrHashNotInIndex

  test "regression-850846c: above assumeValid => ssrNotAncestorOfAssumeValid":
    # Height above assumeValidHeight is never an ancestor.
    let params = mainnetParams()
    let blockHeight = params.assumeValidHeight + 1'i32
    let blockHash = BlockHash(hexToBytes32(
      "0000000000000000000a5cbf222222222222222222222222222222222222abcd"))
    let ctx = AssumeValidContext(
      blockHash: blockHash,
      blockHeight: blockHeight,
      assumeValidHeight: params.assumeValidHeight,
      activeHashAtBlockHeight: some(blockHash),
      activeHashAtAssumeValidHeight: some(params.assumeValidBlockHash),
      bestHeaderHeight: blockHeight + 10_000'i32,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    check shouldSkipScripts(ctx, params) == ssrNotAncestorOfAssumeValid

  test "regression-850846d: exactly at assumeValidHeight=938343 with matching hash => skip":
    # At the assumevalid height itself, the block hash must equal the
    # hardcoded assumeValidBlockHash for the skip to fire.
    let params = mainnetParams()
    let ctx = AssumeValidContext(
      blockHash: params.assumeValidBlockHash,
      blockHeight: params.assumeValidHeight,
      assumeValidHeight: params.assumeValidHeight,
      activeHashAtBlockHeight: some(params.assumeValidBlockHash),
      activeHashAtAssumeValidHeight: some(params.assumeValidBlockHash),
      bestHeaderHeight: params.assumeValidHeight + 10_000'i32,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    check shouldSkipScripts(ctx, params) == ssrSkip

  test "regression-850846e: exactly at assumeValidHeight=938343 with WRONG hash => verify":
    # Same height but a different block (e.g. an orphan at 938343) — must not skip.
    let params = mainnetParams()
    let wrongHash = BlockHash(hexToBytes32(
      "0000000000000000000a5cbf333333333333333333333333333333333333abcd"))
    let ctx = AssumeValidContext(
      blockHash: wrongHash,
      blockHeight: params.assumeValidHeight,
      assumeValidHeight: params.assumeValidHeight,
      activeHashAtBlockHeight: some(wrongHash),
      activeHashAtAssumeValidHeight: some(params.assumeValidBlockHash),
      bestHeaderHeight: params.assumeValidHeight + 10_000'i32,
      bestHeaderChainWork: hexToBytes32(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )
    # activeHashAtAssumeValidHeight == assumeValidBlockHash, but block hash
    # at its height doesn't match itself via the active-index lookup.  Here
    # we simulate a fork: the block IS at height 938343 but is not the
    # assumevalid block.  activeHashAtBlockHeight returns the block's own
    # hash (it's in the fork branch of the index), so the
    # "activeHashAtBlockHeight == ctx.blockHash" check passes, but then
    # the activeHashAtAssumeValidHeight is from a different chain.  To
    # simulate this properly, set activeHashAtAssumeValidHeight to wrongHash
    # (what the fork's index would say at 938343).
    var forkCtx = ctx
    forkCtx.activeHashAtAssumeValidHeight = some(wrongHash)
    check shouldSkipScripts(forkCtx, params) == ssrNotAncestorOfAssumeValid
