## Regression tests for BIP-342 OP_SUCCESSx handling in tapscript.
##
## Pre-fix nimrod fell through to seUnknownOpcode / seDisabledOpcode
## on opcodes 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153,
## 187-254 — all of which are OP_SUCCESSx per Core's `IsOpSuccess`
## (script/script.cpp:364). Any future soft fork that activates one
## would split nimrod off the chain.
##
## Reference: bitcoin-core/src/script/interpreter.cpp:1837-1852
## (`ExecuteWitnessScript` OP_SUCCESS pre-pass).

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1

# --- shared fixtures ----------------------------------------------------------

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

proc tapleafHashOf(tapscript: seq[byte]): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(0xC0'u8)
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

# --- IsOpSuccess unit tests --------------------------------------------------

suite "BIP-342 IsOpSuccess opcode classifier":
  test "exact-match opcodes":
    check isOpSuccess(80'u8) == true
    check isOpSuccess(98'u8) == true

  test "ranges 126-129, 131-134, 137-138, 141-142, 149-153, 187-254":
    for op in 126'u8..129'u8: check isOpSuccess(op) == true
    for op in 131'u8..134'u8: check isOpSuccess(op) == true
    for op in 137'u8..138'u8: check isOpSuccess(op) == true
    for op in 141'u8..142'u8: check isOpSuccess(op) == true
    for op in 149'u8..153'u8: check isOpSuccess(op) == true
    for op in 187'u8..254'u8: check isOpSuccess(op) == true

  test "non-success opcodes":
    check isOpSuccess(0'u8) == false        # OP_0
    check isOpSuccess(81'u8) == false       # OP_1
    check isOpSuccess(82'u8) == false       # OP_2
    check isOpSuccess(99'u8) == false       # OP_IF
    check isOpSuccess(125'u8) == false      # OP_2ROT
    check isOpSuccess(130'u8) == false      # OP_SIZE
    check isOpSuccess(135'u8) == false      # OP_EQUAL
    check isOpSuccess(136'u8) == false      # OP_EQUALVERIFY
    check isOpSuccess(139'u8) == false
    check isOpSuccess(140'u8) == false
    check isOpSuccess(143'u8) == false
    check isOpSuccess(148'u8) == false
    check isOpSuccess(154'u8) == false
    check isOpSuccess(186'u8) == false      # OP_CHECKSIGADD
    check isOpSuccess(255'u8) == false

# --- Pre-pass walker -----------------------------------------------------------

suite "tapscriptOpSuccessPrePass walker":
  test "empty script: no short-circuit":
    check tapscriptOpSuccessPrePass(@[]) == seUnknownOpcode

  test "OP_TRUE: no short-circuit":
    check tapscriptOpSuccessPrePass(@[byte(OP_TRUE)]) == seUnknownOpcode

  test "OP_RESERVED (80) at start: short-circuit":
    check tapscriptOpSuccessPrePass(@[80'u8]) == seOk

  test "OP_VER (98) at start: short-circuit":
    check tapscriptOpSuccessPrePass(@[98'u8]) == seOk

  test "OP_SUCCESS in 187-254 range: short-circuit":
    check tapscriptOpSuccessPrePass(@[187'u8]) == seOk
    check tapscriptOpSuccessPrePass(@[200'u8]) == seOk
    check tapscriptOpSuccessPrePass(@[254'u8]) == seOk

  test "push-data 1-75 then OP_SUCCESS: short-circuit AFTER skipping payload":
    # 0x05 push 5 bytes, then 80 (OP_SUCCESS).
    let s: seq[byte] = @[0x05'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 80'u8]
    check tapscriptOpSuccessPrePass(s) == seOk

  test "OP_PUSHDATA1 then OP_SUCCESS: short-circuit":
    let s: seq[byte] = @[byte(OP_PUSHDATA1), 3'u8, 0'u8, 0'u8, 0'u8, 80'u8]
    check tapscriptOpSuccessPrePass(s) == seOk

  test "malformed push-data (length runs off end): seInvalidStack":
    # 0x05 says push 5 bytes but only 3 follow.
    let s: seq[byte] = @[0x05'u8, 1'u8, 2'u8, 3'u8]
    check tapscriptOpSuccessPrePass(s) == seInvalidStack

  test "byte 80 inside push-data payload: NOT short-circuited":
    # 0x01 push 1 byte (which is 80), then OP_TRUE.
    let s: seq[byte] = @[0x01'u8, 80'u8, byte(OP_TRUE)]
    check tapscriptOpSuccessPrePass(s) == seUnknownOpcode

# --- End-to-end via verifyWitnessProgram --------------------------------------

suite "BIP-342 OP_SUCCESS short-circuit at the witness-program boundary":
  ## Construct a valid commitment (correct internal pubkey + merkle
  ## root) so the pre-pass actually runs. Use OP_SUCCESS as the
  ## tapscript; result must be true (bool) / seOk (WithError).

  let internalPk = deriveXonly(TEST_PRIVKEY)

  proc makeControlBlockFor(tapscript: seq[byte]): tuple[cb: seq[byte], program: seq[byte]] =
    let tlh = tapleafHashOf(tapscript)
    let tw = taptweakOf(internalPk, tlh)
    let (q, parity) = tweakXonlyPubkey(internalPk, tw)
    var cb: seq[byte] = @[byte(0xC0'u8 or uint8(parity and 0x01))]
    for b in internalPk: cb.add(b)
    var prog: seq[byte] = @q
    (cb, prog)

  test "OP_SUCCESS-80 tapscript with valid commitment: succeeds":
    let tapscript: seq[byte] = @[80'u8]
    let (cb, prog) = makeControlBlockFor(tapscript)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, prog, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true
    let resErr = verifyWitnessProgramWithError(
      witness, 1, prog, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seOk

  test "OP_SUCCESS-200 tapscript with valid commitment: succeeds":
    let tapscript: seq[byte] = @[200'u8]
    let (cb, prog) = makeControlBlockFor(tapscript)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, prog, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

  test "OP_SUCCESS bypasses normally-failing prefix":
    # Tapscript: OP_2DUP (which would fail on empty stack) then
    # OP_SUCCESS-187. Pre-fix nimrod would error on OP_2DUP; post-fix
    # OP_SUCCESS short-circuits BEFORE any execution, so the script
    # succeeds. 0x6e is OP_2DUP, 187 (0xbb) is OP_SUCCESS.
    let tapscript: seq[byte] = @[0x6e'u8, 187'u8]
    let (cb, prog) = makeControlBlockFor(tapscript)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, prog, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

  test "no OP_SUCCESS, valid commitment + OP_TRUE: still succeeds":
    # Sanity check: the pre-pass must not turn valid-but-not-OP_SUCCESS
    # tapscripts into failures.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockFor(tapscript)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, prog, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

  test "OP_SUCCESS with broken commitment: still rejected":
    # OP_SUCCESS only short-circuits AFTER the commitment passes,
    # matching Core's order (VerifyTaprootCommitment runs in the
    # outer VerifyWitnessProgram before ExecuteWitnessScript fires
    # the OP_SUCCESS pre-pass).
    let tapscript: seq[byte] = @[80'u8]
    let (cb, prog) = makeControlBlockFor(tapscript)
    var bogusProgram = prog
    bogusProgram[0] = bogusProgram[0] xor 0x01'u8
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, bogusProgram, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false
