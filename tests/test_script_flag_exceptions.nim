## Bitcoin Core script_flag_exceptions parity tests.
##
## Reference: bitcoin-core/src/validation.cpp:2249-2289 (GetBlockScriptFlags)
##            bitcoin-core/src/kernel/chainparams.cpp:85-88 (mainnet table)
##            bitcoin-core/src/kernel/chainparams.cpp:210-211 (testnet3 table)
##
## Core's flag computation is THREE steps and the ORDER IS LOAD-BEARING:
##
##   1. BASE      P2SH | WITNESS | TAPROOT, seeded unconditionally for every
##                block at every height (:2262).  There is no BIP16Height and
##                no taprootHeight in this path.
##   2. EXCEPTION a block-hash hit in script_flag_exceptions REPLACES the whole
##                set with the table's value (:2264-2267).  Assignment, not an
##                early return.
##   3. HEIGHT    DERSIG (BIP66), CLTV (BIP65), CSV (BIP68/112/113) and
##                NULLDUMMY (BIP147) are OR-ed ON TOP of step 2's result
##                (:2268-2286).
##
## The bug these tests pin: an early `return` at step 2 for mainnet block
## 692261 (exception value = P2SH|WITNESS) drops DERSIG|CLTV|CSV|NULLDUMMY,
## all four of which ARE active at height 692261.  That is a FALSE-ACCEPT of
## scripts Core rejects under BIP-66/65/112/147.

import std/[options, strutils]
import unittest2
import ../src/script/interpreter
import ../src/consensus/[params, validation]

const
  ## Mainnet activation heights (kernel/chainparams.cpp:88-92).
  MainnetBip66Height = 363725'i32
  MainnetBip65Height = 388381'i32
  MainnetCsvHeight   = 419328'i32
  MainnetSegwitHeight = 481824'i32

  ## The two mainnet exception blocks, at their REAL heights.
  Bip16ExceptionHeight   = 170060'i32
  TaprootExceptionHeight = 692261'i32

  ## Everything Core's block path may ever set.
  AllConsensusFlags: set[ScriptFlags] = {
    sfP2SH, sfWitness, sfTaproot,
    sfDERSig, sfCheckLockTimeVerify, sfCheckSequenceVerify, sfNullDummy}

  ## STANDARD_SCRIPT_VERIFY_FLAGS-only members (policy/policy.h:125).
  ## None of these may ever appear in a BLOCK script-flag set.
  PolicyOnlyFlags: set[ScriptFlags] = {
    sfNullFail, sfCleanStack, sfLowS, sfStrictEnc, sfMinimalData, sfMinimalIf,
    sfWitnessPubkeyType, sfSigPushOnly, sfDiscourageUpgradableNops,
    sfDiscourageUpgradableWitnessProgram, sfDiscourageOpSuccess,
    sfDiscourageUpgradableTaprootVersion, sfDiscourageUpgradablePubkeyType}

proc reverseHexBytes(hexHash: string): string =
  ## Flip a 32-byte hex string end-for-end (display order <-> internal order).
  ## Used as a NEGATIVE CONTROL: nimrod stores exception keys in display order
  ## because that is what `$BlockHash` emits (primitives/types.nim:28-31), so
  ## the reversed form must NOT match.
  doAssert hexHash.len == 64
  result = newStringOfCap(64)
  for i in countdown(31, 0):
    result.add(hexHash[i * 2])
    result.add(hexHash[i * 2 + 1])

suite "script_flag_exceptions — Core GetBlockScriptFlags three-step parity":

  test "step 1: BASE seeds P2SH|WITNESS|TAPROOT unconditionally":
    ## validation.cpp:2262. No height gate on any of the three — not at
    ## genesis, not below BIP16Height, not below the Taproot activation.
    let params = mainnetParams()
    for h in [0'i32, 1'i32, 100'i32, 170059'i32, 480000'i32, 709631'i32]:
      let flags = getBlockScriptFlags(h, params, "")
      check sfP2SH in flags
      check sfWitness in flags
      check sfTaproot in flags

  test "step 3: the four height gates activate exactly at their heights":
    let params = mainnetParams()
    check sfDERSig notin getBlockScriptFlags(MainnetBip66Height - 1, params)
    check sfDERSig in     getBlockScriptFlags(MainnetBip66Height, params)
    check sfCheckLockTimeVerify notin getBlockScriptFlags(MainnetBip65Height - 1, params)
    check sfCheckLockTimeVerify in     getBlockScriptFlags(MainnetBip65Height, params)
    check sfCheckSequenceVerify notin getBlockScriptFlags(MainnetCsvHeight - 1, params)
    check sfCheckSequenceVerify in     getBlockScriptFlags(MainnetCsvHeight, params)
    check sfNullDummy notin getBlockScriptFlags(MainnetSegwitHeight - 1, params)
    check sfNullDummy in     getBlockScriptFlags(MainnetSegwitHeight, params)

  # -------------------------------------------------------------------------
  # The three acceptance criteria, at the REAL heights.
  # -------------------------------------------------------------------------

  test "[170060] BIP16 violator -> SCRIPT_VERIFY_NONE (exactly {})":
    ## chainparams.cpp:85-86 maps this hash to SCRIPT_VERIFY_NONE.  At height
    ## 170060 all four height gates are still inactive (BIP66 363725,
    ## BIP65 388381, CSV 419328, SegWit 481824), so step 3 adds nothing and
    ## the final set is empty.
    let flags = getBlockScriptFlags(Bip16ExceptionHeight, mainnetParams(),
                                    BIP16_EXCEPTION_HASH)
    check flags == ScriptVerifyNone
    check flags == {}

  test "[692261] Taproot violator -> P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY":
    ## THE REGRESSION THIS SUITE EXISTS FOR.  chainparams.cpp:87-88 maps this
    ## hash to SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS.  Because step 3 runs
    ## AFTER step 2, the four height-gated flags — every one of which is active
    ## at 692261 — must still be OR-ed in.  Only TAPROOT is stripped.
    ## An early return here would false-accept BIP-66/65/112/147 violations.
    let flags = getBlockScriptFlags(TaprootExceptionHeight, mainnetParams(),
                                    TAPROOT_EXCEPTION_HASH)
    check flags == {sfP2SH, sfWitness,
                    sfDERSig, sfCheckLockTimeVerify, sfCheckSequenceVerify,
                    sfNullDummy}
    check sfTaproot notin flags        ## the exception's whole purpose
    check sfDERSig in flags             ## BIP66 active at 692261
    check sfCheckLockTimeVerify in flags  ## BIP65 active at 692261
    check sfCheckSequenceVerify in flags  ## BIP112 active at 692261
    check sfNullDummy in flags          ## BIP147 active at 692261

  test "[control] non-exception hash at 692261 KEEPS taproot":
    ## Any other block at the same height must get the full base set.
    let controlHash = "00000000000000000001b2f4d3e5a7c9081726354453627180a9b8c7d6e5f403"
    let flags = getBlockScriptFlags(TaprootExceptionHeight, mainnetParams(),
                                    controlHash)
    check sfTaproot in flags
    check flags == AllConsensusFlags

  test "[control] no blockHash at 692261 also keeps taproot":
    ## The hash-less form cannot see the exception table at all; it must still
    ## produce the full base set, never the exception's stripped set.
    let flags = getBlockScriptFlags(TaprootExceptionHeight, mainnetParams(), "")
    check sfTaproot in flags
    check flags == AllConsensusFlags

  # -------------------------------------------------------------------------
  # Negative controls
  # -------------------------------------------------------------------------

  test "byte-reversed exception hashes do NOT match (byte-order control)":
    ## nimrod keys the table in DISPLAY order because `$BlockHash` reverses the
    ## internal little-endian array (primitives/types.nim:28-31).  Feeding the
    ## internal (reversed) orientation must therefore MISS the table.  If this
    ## test ever starts passing the exception with a reversed key, someone has
    ## "fixed" the byte order in the wrong direction.
    let params = mainnetParams()
    let revBip16 = reverseHexBytes(BIP16_EXCEPTION_HASH)
    let revTaproot = reverseHexBytes(TAPROOT_EXCEPTION_HASH)
    check revBip16 != BIP16_EXCEPTION_HASH
    check revTaproot != TAPROOT_EXCEPTION_HASH
    ## Reversed BIP16 key at 170060: no hit -> base flags, not {}.
    let flagsRevBip16 = getBlockScriptFlags(Bip16ExceptionHeight, params, revBip16)
    check flagsRevBip16 == {sfP2SH, sfWitness, sfTaproot}
    check flagsRevBip16 != ScriptVerifyNone
    ## Reversed Taproot key at 692261: no hit -> taproot retained.
    let flagsRevTaproot = getBlockScriptFlags(TaprootExceptionHeight, params, revTaproot)
    check sfTaproot in flagsRevTaproot
    check flagsRevTaproot == AllConsensusFlags
    ## And the round trip is an involution (proves reverseHexBytes is sane).
    check reverseHexBytes(revBip16) == BIP16_EXCEPTION_HASH

  test "uppercase hex does NOT match (producers emit lowercase)":
    ## `$BlockHash` lower-cases; the table compares exactly, like Core's
    ## uint256 equality.  Documented, not aspirational.
    let flags = getBlockScriptFlags(Bip16ExceptionHeight, mainnetParams(),
                                    BIP16_EXCEPTION_HASH.toUpperAscii())
    check flags != ScriptVerifyNone

  test "exception tables are per-network":
    ## chainparams.cpp: mainnet has two entries, testnet3 one, and regtest /
    ## testnet4 / signet none.  A mainnet hash must not fire on another chain.
    check scriptFlagException(Mainnet, BIP16_EXCEPTION_HASH).isSome
    check scriptFlagException(Mainnet, TAPROOT_EXCEPTION_HASH).isSome
    check scriptFlagException(Testnet3, TESTNET3_BIP16_EXCEPTION_HASH).isSome
    ## Cross-network misses:
    check scriptFlagException(Testnet3, BIP16_EXCEPTION_HASH).isNone
    check scriptFlagException(Testnet3, TAPROOT_EXCEPTION_HASH).isNone
    check scriptFlagException(Mainnet, TESTNET3_BIP16_EXCEPTION_HASH).isNone
    check scriptFlagException(Regtest, BIP16_EXCEPTION_HASH).isNone
    check scriptFlagException(Testnet4, BIP16_EXCEPTION_HASH).isNone
    check scriptFlagException(Signet, TAPROOT_EXCEPTION_HASH).isNone
    ## Empty hash never matches.
    check scriptFlagException(Mainnet, "").isNone

  test "testnet3 BIP16 violator -> SCRIPT_VERIFY_NONE below the height gates":
    ## chainparams.cpp:210-211.  testnet3 BIP66Height = 330776, and the
    ## violating block is well below that, so the final set is empty.
    let params = testnet3Params()
    let flags = getBlockScriptFlags(21111'i32, params,
                                    TESTNET3_BIP16_EXCEPTION_HASH)
    check flags == ScriptVerifyNone
    ## The same hash on regtest is not an exception at all.
    check getBlockScriptFlags(21111'i32, regtestParams(),
                              TESTNET3_BIP16_EXCEPTION_HASH) != ScriptVerifyNone

  test "no policy flags ever leak into the block path":
    ## policy/policy.h:125 — STANDARD_SCRIPT_VERIFY_FLAGS are mempool-only.
    let heights = [0'i32, 1'i32, Bip16ExceptionHeight, MainnetBip66Height,
                   MainnetBip65Height, MainnetCsvHeight, MainnetSegwitHeight,
                   TaprootExceptionHeight, 900000'i32]
    for p in [mainnetParams(), testnet3Params(), testnet4Params(),
              regtestParams(), signetParams()]:
      for h in heights:
        for hashArg in ["", BIP16_EXCEPTION_HASH, TAPROOT_EXCEPTION_HASH,
                        TESTNET3_BIP16_EXCEPTION_HASH]:
          let flags = getBlockScriptFlags(h, p, hashArg)
          check (flags * PolicyOnlyFlags) == {}
          check (flags - AllConsensusFlags) == {}

  # -------------------------------------------------------------------------
  # Sigop gating must consume the SAME exception-aware flags.
  # -------------------------------------------------------------------------

  test "sigop gating booleans come from the final exception-aware flags":
    ## Core: GetTransactionSigOpCost(tx, view, flags) gates P2SH sigops on
    ## SCRIPT_VERIFY_P2SH (consensus/tx_verify.cpp:150-152), and
    ## CountWitnessSigOps returns 0 when SCRIPT_VERIFY_WITNESS is clear
    ## (script/interpreter.cpp:2141-2143).  On the BIP16 exception block the
    ## flags are SCRIPT_VERIFY_NONE, so NEITHER may be counted.  A height-only
    ## `useP2SH = true` / `useWitness = height >= segwitHeight` derivation
    ## over-counts here and diverges on the block sigop limit.
    let excFlags = getBlockScriptFlags(Bip16ExceptionHeight, mainnetParams(),
                                       BIP16_EXCEPTION_HASH)
    check (sfP2SH in excFlags) == false
    check (sfWitness in excFlags) == false

    ## The Taproot exception block keeps both, so both are still counted.
    let taprootExcFlags = getBlockScriptFlags(TaprootExceptionHeight,
                                              mainnetParams(),
                                              TAPROOT_EXCEPTION_HASH)
    check (sfP2SH in taprootExcFlags) == true
    check (sfWitness in taprootExcFlags) == true

    ## Witness sigops are counted on PRE-SegWit mainnet blocks too, because
    ## SCRIPT_VERIFY_WITNESS is a base flag, not a height gate.  (Pre-SegWit
    ## blocks carry no witness data so the count is 0 in practice — but the
    ## gate must come from the flags, not from segwitHeight.)
    check sfWitness in getBlockScriptFlags(MainnetSegwitHeight - 1,
                                           mainnetParams(), "")

when isMainModule:
  discard
