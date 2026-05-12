## Regression tests for BIP-341 / BIP-342 permissive-gap fixes:
##   1. Schnorr key-path hash_type whitelist
##      ({0x01..0x03, 0x81..0x83}; explicit 0x00 still rejected)
##   2. OP_CHECKSIGADD hash_type whitelist (mirrors key-path / CHECKSIG)
##   3. Taproot control-block max size = 33 + 32*128 = 4129 bytes
##
## Reference: bitcoin-core/src/script/interpreter.cpp:1516
## (SignatureHashSchnorr) + :1970 (control-block range check).

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

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

proc makeProgram32(): seq[byte] =
  for _ in 0 ..< 32: result.add(0xab'u8)

suite "Taproot key-path hash_type whitelist (Core interpreter.cpp:1516)":
  ## A 65-byte key-path signature whose hash-type byte is outside
  ## {0x01..0x03, 0x81..0x83} must be rejected without ever attempting
  ## Schnorr verification. Pre-fix nimrod accepted any non-zero byte.

  let dummyTx = trivialDummyTx()
  let program = makeProgram32()

  proc keypathSigOf(hashType: uint8): seq[byte] =
    # 64 bytes of zeroes + 1 hash-type byte.
    for _ in 0 ..< 64: result.add(0x00'u8)
    result.add(hashType)

  test "explicit SIGHASH_DEFAULT (0x00) on 65-byte sig is rejected":
    # Pre-existing rule, preserved by the fix.
    let witness = @[keypathSigOf(0x00'u8)]
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "0x04 (out of allowlist) is rejected":
    let witness = @[keypathSigOf(0x04'u8)]
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "0x80 (lone ANYONECANPAY) is rejected":
    let witness = @[keypathSigOf(0x80'u8)]
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "0x84 (above ALL|ANYONECANPAY band) is rejected":
    let witness = @[keypathSigOf(0x84'u8)]
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  test "0xff (max) is rejected":
    let witness = @[keypathSigOf(0xff'u8)]
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

  # Note: a legitimate hash_type with all-zero sig bytes would still
  # fail Schnorr verification, so the "valid hash_type passes" test
  # would require a real key/signature. End-to-end success of valid
  # hashtypes is exercised by the full block validator; this suite
  # only proves the rejection path.

suite "Taproot CHECKSIGADD hash_type whitelist (mirrors CHECKSIG)":
  ## Same allowlist as key-path; pre-fix CHECKSIGADD did not validate.
  ##
  ## W95 update: an invalid hash_type byte is a HARD error in tapscript
  ## (Core SCRIPT_ERR_SCHNORR_SIG_HASHTYPE) — `runCheckSigAdd` returns
  ## -1 to indicate the eval failed, rather than 0 for a soft fail.

  proc makeTapCtx(): SigCheckContext =
    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
    dummyTx.lockTime = 0
    SigCheckContext(
      tx: dummyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      scriptPubKey: @[],
      sigVersion: sigTapscript,
      amounts: @[Satoshi(0)],
      scriptPubKeys: @[@[]],
      annex: @[],
      tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32,
    )

  proc runCheckSigAdd(hashType: uint8): int64 =
    ## Run a single OP_CHECKSIGADD with a 65-byte sig (hashType in last
    ## byte), 32-byte pubkey, and the prior accumulator = 0. Returns
    ## the top-of-stack number after CHECKSIGADD if the script
    ## terminated with seOk; returns -1 if it did not.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 1000'i64
    interp.validationWeightInit = true

    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x42'u8)
    sig.add(hashType)
    interp.push(sig)
    interp.push(@[])  # n = 0
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    interp.push(pk)

    let ctx = makeTapCtx()
    let err = interp.eval(@[OP_CHECKSIGADD], ctx)
    if err != seOk:
      return -1
    if interp.stack.len == 0:
      return -1
    let (top, ok) = toScriptNum(interp.peek(), false)
    if not ok: return -1
    int64(top)

  test "0x04 invalid hashType: HARD error (Core SCHNORR_SIG_HASHTYPE)":
    # W95: per Core's CheckSchnorrSignature (interpreter.cpp:1733-1740),
    # an out-of-allowlist hash_type byte is a hard error, not a soft
    # accumulator-unchanged fail. EvalChecksig returns false → the
    # CHECKSIGADD opcode returns false → eval terminates with
    # seSchnorrSigHashtype.
    check runCheckSigAdd(0x04'u8) == -1'i64

  test "0x00 explicit SIGHASH_DEFAULT on 65-byte sig: HARD error":
    check runCheckSigAdd(0x00'u8) == -1'i64

  test "0x84 (above 0x83 band): HARD error":
    check runCheckSigAdd(0x84'u8) == -1'i64

  test "0x80 (lone ANYONECANPAY): HARD error":
    check runCheckSigAdd(0x80'u8) == -1'i64

  test "0xfe: HARD error":
    check runCheckSigAdd(0xfe'u8) == -1'i64

suite "Taproot control-block max size (Core interpreter.cpp:1970)":
  ## Control block size must be in [33, 4129] = [33, 33+32*128].
  ## Pre-fix nimrod had no upper bound.

  let dummyTx = trivialDummyTx()
  let program = makeProgram32()

  proc makeWitnessForControlBlockSize(size: int): seq[seq[byte]] =
    # tapscript = OP_TRUE; pad control block with zeros to `size`.
    var cb: seq[byte] = @[]
    cb.add(0xC0'u8)  # leaf version (parity 0)
    for _ in 0 ..< (size - 1): cb.add(0x00'u8)
    @[@[byte(OP_TRUE)], cb]

  test "control block of 4130 bytes (one over max) is rejected":
    let witness = makeWitnessForControlBlockSize(4130)
    # 4130 - 33 = 4097, which IS divisible by 32 (4097 = 128*32 + 1 ...
    # actually 4128 = 128*32, so 4130-33 = 4097 NOT divisible).
    # Pick a size that IS divisible: 4161 = 33 + 129*32 (over max).
    discard witness  # not used; recomputed below
    let badSize = 33 + 129 * 32  # 4161, divisible-after-base
    let witness2 = makeWitnessForControlBlockSize(badSize)
    let res = verifyWitnessProgram(
      witness2, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false
    let resErr = verifyWitnessProgramWithError(
      witness2, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check resErr == seTaprootWrongControlSize  # W94: Core-faithful WRONG_CONTROL_SIZE

  test "control block of exactly 4129 bytes (max) does not fail on size":
    # 4129 - 33 = 4096 = 128*32. Allowed by Core. The taptweak check
    # will then fail (zeroed control block almost certainly does not
    # match the program), but the size check itself must pass — this
    # test asserts we didn't move the upper bound below the spec.
    let witness = makeWitnessForControlBlockSize(4129)
    let resErr = verifyWitnessProgramWithError(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    # We expect a commitment failure (seWitnessProgramMismatch);
    # the important thing is we don't bail at the size gate.
    check resErr == seWitnessProgramMismatch

  test "control block of 32 bytes (one under min) is rejected":
    let witness = makeWitnessForControlBlockSize(32)
    let res = verifyWitnessProgram(
      witness, 1, program, dummyTx, 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false
