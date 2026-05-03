## Regression tests for the BIP-341 taproot commitment check
## (`Q == lift_x(P) + int(t)*G`) in script-path tapscript spends.
##
## Pre-fix bug (closed in this commit): both `verifyWitnessProgram`
## and `verifyWitnessProgramWithError` skipped the
## `VerifyTaprootCommitment` step (Core
## script/interpreter.cpp:1980-1990). This let any control block
## spend any P2TR output via the script path. Severity: P0 silent
## consensus divergence on adversarial input.
##
## Reference: BIP-341 §"Script validation rules" step 5.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1

# --- shared fixtures ----------------------------------------------------------

proc trivialDummyTx(): Transaction =
  ## A minimum-viable Transaction so verifyWitnessProgram can run.
  ## The bug is in commitment dispatch, so signature checking does
  ## not need to succeed for the rejection tests.
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
  ## Derive a 32-byte x-only pubkey from a 32-byte private key.
  let compressed = derivePublicKey(privkey)
  for i in 0 ..< 32:
    result[i] = compressed[1 + i]

proc tapleafHashOf(tapscript: seq[byte]): array[32, byte] =
  ## TaggedHash("TapLeaf", 0xC0 || compactSize(script) || script).
  var leafData: seq[byte]
  leafData.add(0xC0'u8)
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  result = taggedHash("TapLeaf", leafData)

proc taptweakOf(internalPk: array[32, byte], merkleRoot: array[32, byte]): array[32, byte] =
  ## TaggedHash("TapTweak", internalPk || merkleRoot).
  var data: seq[byte]
  for b in internalPk: data.add(b)
  for b in merkleRoot: data.add(b)
  result = taggedHash("TapTweak", data)

# Test fixture: privkey=1, internalPk = derived x-only.
const TEST_PRIVKEY: PrivateKey = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
]

suite "BIP-341 taproot commitment check (script-path)":
  ## Build a minimal but valid script-path spend: tapscript = OP_TRUE,
  ## empty merkle path, internalPk derived from privkey=1, control
  ## block = (0xC0 | parity) || internalPk, witness program = derived Q.

  let internalPk = deriveXonly(TEST_PRIVKEY)
  let tapscript = @[byte(OP_TRUE)]
  let tapleafHash = tapleafHashOf(tapscript)
  # Empty merkle path: merkle root == tapleaf hash.
  let merkleRoot = tapleafHash
  let taptweak = taptweakOf(internalPk, merkleRoot)
  let (computedQ, computedParity) = tweakXonlyPubkey(internalPk, taptweak)
  let program: seq[byte] = @computedQ

  proc makeControlBlock(parity: int, ipk: array[32, byte]): seq[byte] =
    result = @[]
    result.add(byte(0xC0'u8 or uint8(parity and 0x01)))
    for b in ipk: result.add(b)

  test "valid script-path spend (OP_TRUE, no merkle path) succeeds":
    # End-to-end sanity: tweakXonlyPubkey + taggedHash agree with the
    # interpreter's recomputation of Q.
    let cb = makeControlBlock(computedParity, internalPk)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

    let resErr = verifyWitnessProgramWithError(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seOk

  test "mismatched parity bit is rejected":
    # Flip the parity bit in the control block; commitment must fail
    # because tweakXonlyPubkey returns the OTHER parity.
    let cb = makeControlBlock(1 - computedParity, internalPk)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

    let resErr = verifyWitnessProgramWithError(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seTaprootError

  test "wrong witness program (Q mismatch) is rejected":
    # Same control block, but flip a byte in the program. The recomputed
    # Q from tweak no longer matches; commitment must fail.
    var bogusProgram = program
    bogusProgram[0] = bogusProgram[0] xor 0x01'u8
    let cb = makeControlBlock(computedParity, internalPk)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, bogusProgram, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

    let resErr = verifyWitnessProgramWithError(
      witness, 1, bogusProgram, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seTaprootError

  test "control block with unrelated internal pubkey is rejected":
    # Adversary's control block uses internalPk derived from a
    # DIFFERENT private key. They cannot reach the original `program`
    # via any tweak from this internalPk, so the commitment fails.
    var attackerPriv: PrivateKey
    attackerPriv[31] = 0x02'u8
    let attackerPk = deriveXonly(attackerPriv)
    let cb = makeControlBlock(0, attackerPk)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

    let resErr = verifyWitnessProgramWithError(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seTaprootError

  test "WithError variant rejects fake merkle path (1-step)":
    # Pre-fix the WithError variant did NOT walk the merkle path at
    # all; this regression test ensures the recompute-then-compare loop
    # is actually wired in. We construct a 1-step merkle proof that
    # pretends to derive the tapleaf hash from a sibling 0xff..0xff
    # but supply a program that does not match the resulting Q.
    var sibling: array[32, byte]
    for i in 0 ..< 32: sibling[i] = 0xff'u8
    var cb: seq[byte] = @[byte(0xC0'u8)]
    for b in internalPk: cb.add(b)
    for b in sibling: cb.add(b)
    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    # `program` is the no-merkle-path Q; with a 1-step path that Q is
    # no longer correct, so commitment must fail.
    let resErr = verifyWitnessProgramWithError(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seTaprootError

    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "1-step merkle proof with correct Q succeeds":
    # Sanity check that a non-trivial merkle path is actually walked
    # (not just length-checked). Use sibling = 0xff..0xff, recompute
    # the merkle root via TapBranch, then derive the matching Q.
    var sibling: array[32, byte]
    for i in 0 ..< 32: sibling[i] = 0xff'u8

    # Lex order: tapleafHash < sibling almost certainly. Compute
    # combined to match interpreter's branch logic exactly.
    var combined: seq[byte]
    var kLess = false
    for j in 0 ..< 32:
      if tapleafHash[j] < sibling[j]:
        kLess = true; break
      elif tapleafHash[j] > sibling[j]:
        break
    if kLess:
      for b in tapleafHash: combined.add(b)
      for b in sibling: combined.add(b)
    else:
      for b in sibling: combined.add(b)
      for b in tapleafHash: combined.add(b)
    let newRoot = taggedHash("TapBranch", combined)

    let newTweak = taptweakOf(internalPk, newRoot)
    let (newQ, newParity) = tweakXonlyPubkey(internalPk, newTweak)
    let newProgram: seq[byte] = @newQ

    var cb: seq[byte] = @[byte(0xC0'u8 or uint8(newParity and 0x01))]
    for b in internalPk: cb.add(b)
    for b in sibling: cb.add(b)

    let witness = @[tapscript, cb]
    let dummyTx = trivialDummyTx()
    let res = verifyWitnessProgram(
      witness, 1, newProgram, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == true

    let resErr = verifyWitnessProgramWithError(
      witness, 1, newProgram, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seOk
