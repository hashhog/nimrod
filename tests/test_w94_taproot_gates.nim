## W94 — regression tests for BIP-341/342 Taproot + tapscript consensus
## gates that nimrod previously elided. Each suite below corresponds to
## a real divergence from Bitcoin Core's `VerifyWitnessProgram` /
## `ExecuteWitnessScript` / `EvalChecksigTapscript` (interpreter.cpp).
##
## Pre-W94 nimrod:
##   * ignored SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS (interpreter.cpp:1847)
##   * ignored SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION (:1985)
##   * ignored SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE (:379)
##   * did not enforce the MAX_SCRIPT_ELEMENT_SIZE (520) check on
##     initial witness stack items in v0 or tapscript paths (:1858-1861)
##   * did not enforce the MAX_STACK_SIZE (1000) check on initial
##     tapscript witness stack items (:1855)
##   * leaf-version branch ran BEFORE the merkle commitment check, so
##     unknown leaf versions skipped the commitment entirely
##     (Core checks commitment first, leaf version after — :1973-1988)
##   * OP_CHECKSIGADD did not match Core's EvalChecksigTapscript for
##     empty / unknown-type pubkeys — empty silently failed instead of
##     erroring; unknown-type with non-empty sig added 0 instead of 1.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1
import ../src/crypto/hashing

# --- shared fixtures (mirror test_taproot_op_success.nim) --------------------

proc trivialDummyTx(): Transaction =
  result = Transaction()
  result.version = 2
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: default(TxId), vout: 0),
    scriptSig: @[],
    sequence: 0xffffffff'u32
  )]
  result.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
  result.lockTime = 0

proc deriveXonly(privkey: PrivateKey): array[32, byte] =
  let compressed = derivePublicKey(privkey)
  for i in 0 ..< 32:
    result[i] = compressed[1 + i]

proc tapleafHashOfVer(tapscript: seq[byte], leafVersion: uint8): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(leafVersion)
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  result = taggedHash("TapLeaf", leafData)

proc taptweakOf(internalPk: array[32, byte], merkleRoot: array[32, byte]): array[32, byte] =
  var data: seq[byte]
  for b in internalPk: data.add(b)
  for b in merkleRoot: data.add(b)
  result = taggedHash("TapTweak", data)

const TEST_PRIVKEY: PrivateKey = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
]

let G_INTERNAL = deriveXonly(TEST_PRIVKEY)

proc makeControlBlockVer(tapscript: seq[byte], leafVersion: uint8):
    tuple[cb: seq[byte], prog: seq[byte]] =
  let tlh = tapleafHashOfVer(tapscript, leafVersion)
  let tw = taptweakOf(G_INTERNAL, tlh)
  let (q, parity) = tweakXonlyPubkey(G_INTERNAL, tw)
  var cb: seq[byte] = @[byte(leafVersion or uint8(parity and 0x01))]
  for b in G_INTERNAL: cb.add(b)
  (cb, @q)

proc makeControlBlock(tapscript: seq[byte]): tuple[cb: seq[byte], prog: seq[byte]] =
  makeControlBlockVer(tapscript, 0xC0'u8)

# ============================================================================
# 1. SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS (BIP-342)
# ============================================================================

suite "W94 SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:1847-1849.
  ## When set, OP_SUCCESSx tapscripts MUST be rejected at the relay /
  ## IBD policy layer; consensus-wise they still succeed.

  test "OP_SUCCESS-80 + discourage flag UNSET: succeeds":
    let tapscript: seq[byte] = @[80'u8]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot}) == true

  test "OP_SUCCESS-80 + discourage flag SET: rejected":
    let tapscript: seq[byte] = @[80'u8]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageOpSuccess})
    check res == false

  test "OP_SUCCESS-200 + discourage flag SET: rejected (error path)":
    let tapscript: seq[byte] = @[200'u8]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgramWithError(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageOpSuccess})
    check res == seDiscourageOpSuccess

  test "non-OP_SUCCESS tapscript + discourage flag SET: unaffected":
    # The discourage flag only fires on actually-present OP_SUCCESSx;
    # vanilla OP_TRUE must still validate normally.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageOpSuccess}) == true

# ============================================================================
# 2. SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION (BIP-341)
# ============================================================================

suite "W94 SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:1985-1988.
  ## Unknown leaf versions are anyone-can-spend by default; this flag
  ## turns them into a relay-level reject.

  test "leaf version 0xC2 + flag UNSET: succeeds (forward compat)":
    # 0xC2 has parity bit 0 -> leafVersion masks to 0xC2 (unknown).
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot}) == true

  test "leaf version 0xC2 + flag SET: rejected":
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageUpgradableTaprootVersion}) == false

  test "leaf version 0xC2 + flag SET: error path returns specific code":
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgramWithError(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageUpgradableTaprootVersion})
    check res == seDiscourageUpgradableTaprootVersion

  test "leaf 0xC2 with BROKEN commitment: rejected even without discourage flag":
    # Pre-W94 fix: nimrod returned 'true' for unknown leaf versions
    # BEFORE the merkle/commitment check. Post-fix: commitment is
    # verified first, only-then the leaf version is examined. So a
    # broken-control-block leaf-0xC2 spend must still be rejected.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    var bogusProg = prog
    bogusProg[0] = bogusProg[0] xor 0x01'u8
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, bogusProg, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot}) == false

  test "leaf 0xC0 (tapscript) + flag SET: unaffected":
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageUpgradableTaprootVersion}) == true

# ============================================================================
# 3. SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE (BIP-342)
# ============================================================================

suite "W94 SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:367-385
  ## (EvalChecksigTapscript). In tapscript CHECKSIG/CHECKSIGADD, an
  ## unknown (non-32-byte, non-empty) pubkey is anyone-can-spend by
  ## default; this flag turns it into a relay-level reject.

  test "CHECKSIG with unknown 33-byte pubkey + flag UNSET: succeeds":
    # Tapscript: <empty-sig> <33-byte-pubkey> OP_CHECKSIG
    # An empty sig with unknown-type pubkey: Core leaves success=false,
    # then we land on the unknown-type branch and the call returns true
    # (with success unchanged). CHECKSIG then pushes empty on the
    # stack, so the script fails cleanstack/eval-false. For a clearer
    # test, use OP_CHECKSIG followed by OP_NOT — we just want to make
    # sure the script doesn't HARD-error on the unknown pubkey type.
    var tapscript: seq[byte]
    tapscript.add(0'u8)         # OP_0 (empty sig)
    tapscript.add(33'u8)        # push 33 bytes (unknown pubkey type)
    for _ in 0 ..< 33: tapscript.add(0xAB'u8)
    tapscript.add(byte(OP_CHECKSIG))
    tapscript.add(byte(OP_NOT))  # invert so empty-stack-push becomes true
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot}) == true

  test "CHECKSIG with unknown 33-byte pubkey + flag SET: rejected":
    var tapscript: seq[byte]
    tapscript.add(0'u8)
    tapscript.add(33'u8)
    for _ in 0 ..< 33: tapscript.add(0xAB'u8)
    tapscript.add(byte(OP_CHECKSIG))
    tapscript.add(byte(OP_NOT))
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgramWithError(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot, sfDiscourageUpgradablePubkeyType})
    check res == seDiscourageUpgradablePubkeyType

# ============================================================================
# 4. OP_CHECKSIGADD: empty-pubkey + unknown-type semantics
# ============================================================================

suite "W94 OP_CHECKSIGADD pubkey-type semantics":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:1084-1101
  ## (OP_CHECKSIGADD) + 347-385 (EvalChecksigTapscript). Key facts:
  ##   - empty pubkey + any sig: HARD ERROR (TAPSCRIPT_EMPTY_PUBKEY)
  ##   - unknown-type pubkey + non-empty sig: success = TRUE (so n is
  ##     incremented), unless discourage-upgradable-pubkeytype is set
  ##   - 32-byte pubkey + bad sig: success = false, n unchanged
  ## Pre-W94 nimrod treated empty pubkey as a silent failure (n
  ## unchanged) and treated unknown-type pubkey + non-empty sig as
  ## n unchanged (should have been n+1).

  test "CHECKSIGADD with empty pubkey: hard error":
    # Tapscript: <non-empty-fake-sig> OP_0 <empty-pubkey> OP_CHECKSIGADD
    # i.e. push sig (1 byte 0x01), push num 0, push empty pubkey, CHECKSIGADD.
    var tapscript: seq[byte]
    tapscript.add(1'u8)              # push 1 byte
    tapscript.add(0x01'u8)           # sig (non-empty, garbage)
    tapscript.add(byte(OP_0))        # n = 0
    tapscript.add(byte(OP_0))        # empty pubkey
    tapscript.add(byte(OP_CHECKSIGADD))
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgramWithError(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == seTapscriptEmptyPubkey

  test "CHECKSIGADD with empty sig + 32-byte pubkey: n unchanged (success=false)":
    # Tapscript: OP_0 (empty sig) OP_0 (n=0) <32-byte pubkey> OP_CHECKSIGADD OP_NOT
    # n stays 0 -> OP_NOT turns 0 into 1, script returns true.
    var tapscript: seq[byte]
    tapscript.add(byte(OP_0))     # empty sig
    tapscript.add(byte(OP_0))     # n = 0
    tapscript.add(32'u8)
    for _ in 0 ..< 32: tapscript.add(0x02'u8)  # arbitrary 32-byte pubkey
    tapscript.add(byte(OP_CHECKSIGADD))
    tapscript.add(byte(OP_NOT))
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

  test "CHECKSIGADD with unknown 33-byte pubkey + non-empty sig: n + 1":
    # Tapscript: <1-byte garbage sig> OP_0 <33-byte pubkey> OP_CHECKSIGADD
    # Per Core EvalChecksigTapscript: success = !sig.empty() = true, and
    # the unknown-type pubkey doesn't override that. So n -> 0 + 1 = 1.
    # Script ends with OP_1 EQUAL to verify the result.
    var tapscript: seq[byte]
    tapscript.add(1'u8)
    tapscript.add(0xAB'u8)              # sig (non-empty garbage)
    tapscript.add(byte(OP_0))           # n = 0
    tapscript.add(33'u8)
    for _ in 0 ..< 33: tapscript.add(0x02'u8)  # unknown 33-byte pubkey
    tapscript.add(byte(OP_CHECKSIGADD))
    tapscript.add(byte(OP_1))
    tapscript.add(byte(OP_EQUAL))
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    # Make sure tapscript size is within budget — non-empty sig still
    # decrements the validation weight, so the witness stack needs to
    # be big enough to seed a budget >= 50. The control block (33
    # bytes) + tapscript (~40 bytes) easily covers that.
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

# ============================================================================
# 5. MAX_SCRIPT_ELEMENT_SIZE on initial tapscript witness stack
# ============================================================================

suite "W94 tapscript initial witness-stack element-size gate":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:1858-1861.
  ## A 521+-byte initial witness stack item must be rejected before
  ## the tapscript executes, even if the tapscript itself is harmless.

  test "521-byte witness arg rejected":
    let tapscript: seq[byte] = @[byte(OP_DROP), byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    # Stack arg = 521 bytes (one over the 520 limit).
    var oversized: seq[byte] = @[]
    for _ in 0 ..< 521: oversized.add(0xAA'u8)
    let witness = @[oversized, tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "520-byte witness arg accepted":
    let tapscript: seq[byte] = @[byte(OP_DROP), byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    var maxsized: seq[byte] = @[]
    for _ in 0 ..< 520: maxsized.add(0xAA'u8)
    let witness = @[maxsized, tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

  test "OP_SUCCESS bypasses the element-size gate":
    # Per Core (interpreter.cpp:1837-1855), OP_SUCCESSx pre-pass runs
    # BEFORE the element-size loop. So a 521-byte stack item with an
    # OP_SUCCESS tapscript must still succeed.
    let tapscript: seq[byte] = @[80'u8]
    let (cb, prog) = makeControlBlock(tapscript)
    var oversized: seq[byte] = @[]
    for _ in 0 ..< 521: oversized.add(0xAA'u8)
    let witness = @[oversized, tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

# ============================================================================
# 6. MAX_SCRIPT_ELEMENT_SIZE on initial v0 witness stack
# ============================================================================

suite "W94 SegWit v0 initial witness-stack element-size gate":
  ## Reference: bitcoin-core/src/script/interpreter.cpp:1858-1861.
  ## Applies to BOTH v0 (P2WPKH / P2WSH) and tapscript. Pre-W94
  ## nimrod never enforced it; a 600-byte witness signature would
  ## reach OP_CHECKSIG (which then rejects it for being non-DER) but
  ## per Core consensus the witness program must reject FIRST.

  test "P2WSH 521-byte witness arg rejected":
    # Witness script: OP_DROP OP_TRUE. Program = sha256(script).
    let witnessScript: seq[byte] = @[byte(OP_DROP), byte(OP_TRUE)]
    var prog: seq[byte] = @[]
    let h = sha256(witnessScript)
    for b in h: prog.add(b)

    var oversized: seq[byte] = @[]
    for _ in 0 ..< 521: oversized.add(0xAA'u8)
    let witness = @[oversized, witnessScript]
    let res = verifyWitnessProgram(
      witness, 0, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness})
    check res == false

  test "P2WSH 520-byte witness arg accepted":
    let witnessScript: seq[byte] = @[byte(OP_DROP), byte(OP_TRUE)]
    var prog: seq[byte] = @[]
    let h = sha256(witnessScript)
    for b in h: prog.add(b)

    var maxsized: seq[byte] = @[]
    for _ in 0 ..< 520: maxsized.add(0xAA'u8)
    let witness = @[maxsized, witnessScript]
    let res = verifyWitnessProgram(
      witness, 0, prog, trivialDummyTx(), 0, Satoshi(0),
      {sfWitness})
    check res == true
