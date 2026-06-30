## Regression tests: P2SH-wrapped witness v1+32 must be anyone-can-spend,
## NOT run through Taproot verification.
##
## Bitcoin Core interpreter.cpp:1947 gates the BIP-341 Taproot verifier on
##   `witversion == 1 && program.size() == 32 && !is_p2sh`
## A P2SH-wrapped v1+32 redeemScript falls through to Core's else branch
## (interpreter.cpp:1992-1997) and returns true unconditionally (forward
## soft-fork compatibility, anyone-can-spend).
##
## Pre-fix nimrod: verifyWitnessProgram and verifyWitnessProgramWithError had
## no `isP2SH` parameter, so P2SH-wrapped v1+32 programs entered the Taproot
## verifier and were rejected (false-reject) when the witness didn't contain a
## valid Taproot key-path or script-path spend.
##
## Post-fix: both functions accept `isP2SH: bool = false`.  The P2SH dispatch
## sites in verifyScript / verifyScriptWithError pass `isP2SH = true`, causing
## a v1+32 program to return true (or seOk) immediately.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeP2SHTaproot32Program(): tuple[scriptPubKey, redeemScript: seq[byte], program: seq[byte]] =
  ## Build a P2SH scriptPubKey wrapping OP_1 <32-byte program>.
  ## The 32 bytes are arbitrary; we're not doing real Taproot here.
  var prog: seq[byte] = newSeq[byte](32)
  for i in 0 ..< 32:
    prog[i] = byte(i + 1)

  # redeemScript = OP_1 (0x51) PUSH32 (0x20) <32 bytes>
  var rs: seq[byte] = @[0x51'u8, 0x20'u8]
  rs.add(prog)

  let rsHash = hash160(rs)
  # P2SH scriptPubKey = OP_HASH160 <20-byte hash> OP_EQUAL
  var spk: seq[byte] = @[OP_HASH160, 0x14'u8]
  spk.add(rsHash)
  spk.add(OP_EQUAL)

  (spk, rs, prog)

proc makeP2SHScriptSig(redeemScript: seq[byte]): seq[byte] =
  ## Minimal canonical single-push scriptSig: <len> <redeemScript>
  ## redeemScript is 34 bytes (OP_1 + PUSH32 + 32 bytes), length < 0x4c.
  var s: seq[byte] = @[byte(redeemScript.len)]
  s.add(redeemScript)
  s

proc makeDummyTx(scriptSig: seq[byte]): Transaction =
  result = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
    witnesses: @[],
    lockTime: 0
  )

# ---------------------------------------------------------------------------
# Tests for verifyWitnessProgram (bool path)
# ---------------------------------------------------------------------------

suite "P2SH-wrapped v1+32 taproot gate — bool path":

  let (_, redeemScript, program) = makeP2SHTaproot32Program()

  test "isP2SH=true: v1+32 with garbage witness succeeds (anyone-can-spend)":
    ## Pre-fix: entered Taproot verifier → false (garbage is not a valid sig)
    ## Post-fix: returns true immediately (isP2SH gate)
    let garbage: seq[seq[byte]] = @[@[0xde'u8, 0xad, 0xbe, 0xef]]
    let dummyTx = makeDummyTx(@[])
    let ok = verifyWitnessProgram(
      garbage, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot},
      isP2SH = true
    )
    check ok == true

  test "isP2SH=true: v1+32 with empty witness succeeds":
    ## Pre-fix: Taproot verifier returned false (seWitnessProgramMismatch — empty witness)
    ## Post-fix: returns true immediately
    let emptyWitness: seq[seq[byte]] = @[]
    let dummyTx = makeDummyTx(@[])
    let ok = verifyWitnessProgram(
      emptyWitness, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot},
      isP2SH = true
    )
    check ok == true

  test "isP2SH=false (default): v1+32 with empty witness is rejected (Taproot enforcement)":
    ## Without isP2SH gate, Taproot verifier runs and rejects empty witness.
    ## This confirms the gate is not vacuous.
    let emptyWitness: seq[seq[byte]] = @[]
    let dummyTx = makeDummyTx(@[])
    let ok = verifyWitnessProgram(
      emptyWitness, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot}
    )
    check ok == false

  test "isP2SH=true with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: returns false (policy only)":
    ## Core's else branch (which P2SH-wrapped v1+32 falls to) still respects
    ## DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM. This is policy-only — not in
    ## GetBlockScriptFlags — so it doesn't matter for block validation.
    let garbage: seq[seq[byte]] = @[@[0xff'u8]]
    let dummyTx = makeDummyTx(@[])
    let ok = verifyWitnessProgram(
      garbage, 1, program, dummyTx, 0, Satoshi(0),
      {sfTaproot, sfDiscourageUpgradableWitnessProgram},
      isP2SH = true
    )
    check ok == false

# ---------------------------------------------------------------------------
# Tests for verifyWitnessProgramWithError (error-returning path)
# ---------------------------------------------------------------------------

suite "P2SH-wrapped v1+32 taproot gate — WithError path":

  let (_, redeemScript, program) = makeP2SHTaproot32Program()

  test "isP2SH=true: v1+32 with garbage witness returns seOk":
    ## Pre-fix: returned seTaprootError or seWitnessProgramMismatch
    ## Post-fix: returns seOk (anyone-can-spend)
    let garbage: seq[seq[byte]] = @[@[0xde'u8, 0xad, 0xbe, 0xef]]
    let dummyTx = makeDummyTx(@[])
    let err = verifyWitnessProgramWithError(
      garbage, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot},
      isP2SH = true
    )
    check err == seOk

  test "isP2SH=true: v1+32 with empty witness returns seOk":
    let emptyWitness: seq[seq[byte]] = @[]
    let dummyTx = makeDummyTx(@[])
    let err = verifyWitnessProgramWithError(
      emptyWitness, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot},
      isP2SH = true
    )
    check err == seOk

  test "isP2SH=false (default): v1+32 with empty witness is rejected":
    ## Taproot verifier enforced for native v1+32 — empty witness fails.
    let emptyWitness: seq[seq[byte]] = @[]
    let dummyTx = makeDummyTx(@[])
    let err = verifyWitnessProgramWithError(
      emptyWitness, 1, program, dummyTx, 0, Satoshi(0), {sfTaproot}
    )
    check err != seOk

  test "isP2SH=true with DISCOURAGE flag: seDiscourageUpgradableWitnessProgram":
    let garbage: seq[seq[byte]] = @[@[0xff'u8]]
    let dummyTx = makeDummyTx(@[])
    let err = verifyWitnessProgramWithError(
      garbage, 1, program, dummyTx, 0, Satoshi(0),
      {sfTaproot, sfDiscourageUpgradableWitnessProgram},
      isP2SH = true
    )
    check err == seDiscourageUpgradableWitnessProgram

# ---------------------------------------------------------------------------
# End-to-end via verifyScript / verifyScriptWithError
# ---------------------------------------------------------------------------

suite "P2SH-wrapped v1+32 taproot — verifyScript end-to-end":
  ## The verifyScript / verifyScriptWithError call sites must pass isP2SH=true
  ## automatically; the caller does not need to know about the gate.

  let (scriptPubKey, redeemScript, _) = makeP2SHTaproot32Program()
  let scriptSig = makeP2SHScriptSig(redeemScript)

  test "verifyScript: P2SH-wrapped v1+32 spend with empty witness succeeds":
    ## Consensus block flags: sfP2SH + sfWitness + sfTaproot (no MINIMALDATA).
    ## Pre-fix: false (Taproot verifier ran, empty witness rejected).
    ## Post-fix: true (isP2SH gate fires, anyone-can-spend).
    let tx = makeDummyTx(scriptSig)
    let ok = verifyScript(
      scriptSig, scriptPubKey, tx, 0, Satoshi(0),
      {sfP2SH, sfWitness, sfTaproot},
      @[]  # empty witness
    )
    check ok == true

  test "verifyScript: P2SH-wrapped v1+32 spend with non-empty witness succeeds":
    ## A non-empty witness doesn't affect the anyone-can-spend result.
    let tx = makeDummyTx(scriptSig)
    let witness: seq[seq[byte]] = @[@[0xde'u8, 0xad]]
    let ok = verifyScript(
      scriptSig, scriptPubKey, tx, 0, Satoshi(0),
      {sfP2SH, sfWitness, sfTaproot},
      witness
    )
    check ok == true

  test "verifyScriptWithError: P2SH-wrapped v1+32 spend returns seOk":
    let tx = makeDummyTx(scriptSig)
    let err = verifyScriptWithError(
      scriptSig, scriptPubKey, tx, 0, Satoshi(0),
      {sfP2SH, sfWitness, sfTaproot},
      @[]
    )
    check err == seOk
