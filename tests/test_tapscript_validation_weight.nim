## Tests for BIP-342 tapscript validation-weight budget tracking
## (Bitcoin Core interpreter.cpp:362, VALIDATION_WEIGHT_PER_SIGOP_PASSED).
##
## The DoS-protection counter limits non-empty CHECKSIG / CHECKSIGADD /
## CHECKSIGVERIFY operations to (witness_serialized_size + 50) / 50.
## Empty signatures do NOT consume budget. Unknown-pubkey-type
## forward-compat success DOES consume budget (Core comment:
## "Passing with an upgradable public key version is also counted").

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

suite "BIP-342 tapscript validation-weight helpers":
  test "compactSizeLen matches Core":
    check compactSizeLen(0'u64) == 1'u64
    check compactSizeLen(0xfc'u64) == 1'u64
    check compactSizeLen(0xfd'u64) == 3'u64
    check compactSizeLen(0xffff'u64) == 3'u64
    check compactSizeLen(0x10000'u64) == 5'u64
    check compactSizeLen(0xffffffff'u64) == 5'u64
    check compactSizeLen(0x100000000'u64) == 9'u64

  test "serializedWitnessStackSize matches Core GetSerializeSize":
    # Empty stack = just the count compact-size byte.
    check serializedWitnessStackSize(@[]) == 1'u64

    # One 64-byte item: 1 (count) + 1 (item len prefix) + 64 (bytes).
    var s64: seq[byte]
    for _ in 0 ..< 64: s64.add(0'u8)
    check serializedWitnessStackSize(@[s64]) == 66'u64

    # Two items, 100 + 33 bytes:
    var s100: seq[byte]
    for _ in 0 ..< 100: s100.add(0'u8)
    var s33: seq[byte]
    for _ in 0 ..< 33: s33.add(0'u8)
    check serializedWitnessStackSize(@[s100, s33]) ==
      uint64(1 + (1 + 100) + (1 + 33))

suite "BIP-342 tapscript validation-weight budget":
  ## Build a minimal SigCheckContext for tapscript so we can drive
  ## OP_CHECKSIG / OP_CHECKSIGADD through the budget gate without a
  ## real BIP-340 Schnorr signature.
  proc makeTapscriptCtx(): SigCheckContext =
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

  test "exhausted budget aborts CHECKSIG":
    # OP_CHECKSIG with a 32-byte pubkey and a 64-byte non-empty sig
    # and budget = 49 must trip seTapscriptValidationWeight.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 49'i64
    interp.validationWeightInit = true

    # Push sig (deeper) then pubkey (top).
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x42'u8)
    interp.push(sig)
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    interp.push(pk)

    let ctx = makeTapscriptCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err == seTapscriptValidationWeight

  test "sufficient budget runs CHECKSIG to completion":
    var interp = newInterpreter({sfWitness, sfTaproot})
    # Budget = 50: 50 - 50 = 0 (not negative).
    interp.validationWeightLeft = 50'i64
    interp.validationWeightInit = true

    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x42'u8)
    interp.push(sig)
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    interp.push(pk)

    # CHECKSIG with a fake sig will return false (verify fails) and
    # since NULLFAIL is not set on these flags, push false. The point
    # of the test is that the budget gate did NOT fire.
    let ctx = makeTapscriptCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    # Either seOk (push false) or seNullFail/seInvalidSig — but
    # NOT seTapscriptValidationWeight.
    check err != seTapscriptValidationWeight
    check interp.validationWeightLeft == 0'i64

  test "empty sig consumes no budget":
    # Even with budget = 0, an empty sig must NOT trip the weight gate.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 0'i64
    interp.validationWeightInit = true

    interp.push(@[])  # empty sig
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    interp.push(pk)

    let ctx = makeTapscriptCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err != seTapscriptValidationWeight
    check interp.validationWeightLeft == 0'i64

  test "unknown pubkey type with non-empty sig also consumes budget":
    # Per Core: "Passing with an upgradable public key version is also
    # counted." Non-32-byte pubkey, non-empty sig, budget=0 must fail.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 0'i64
    interp.validationWeightInit = true

    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x42'u8)
    interp.push(sig)
    var pk: seq[byte]
    for _ in 0 ..< 33: pk.add(0x02'u8)  # 33 bytes (not 32)
    interp.push(pk)

    let ctx = makeTapscriptCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err == seTapscriptValidationWeight

  test "exhausted budget aborts CHECKSIGADD":
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 0'i64
    interp.validationWeightInit = true

    # Stack (top-down): pubkey, num, sig
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x42'u8)
    interp.push(sig)
    interp.push(@[])  # num = 0
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    interp.push(pk)

    let ctx = makeTapscriptCtx()
    let err = interp.eval(@[OP_CHECKSIGADD], ctx)
    check err == seTapscriptValidationWeight

  test "legacy (non-tapscript) CHECKSIG unaffected by budget":
    # A SegWit-v0 / legacy CHECKSIG must not consult the validation-
    # weight counter. Verify by leaving the budget uninitialized and
    # confirming the legacy path runs without seTapscriptValidationWeight.
    var interp = newInterpreter({sfWitness})
    # Default: validationWeightInit = false.

    # Empty sig + valid 33-byte pubkey: legacy path pushes false, no
    # budget consult.
    interp.push(@[])
    var pk: seq[byte]
    pk.add(0x02'u8)
    for _ in 0 ..< 32: pk.add(0x00'u8)
    interp.push(pk)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
    dummyTx.lockTime = 0
    let ctx = SigCheckContext(
      tx: dummyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      scriptPubKey: @[],
      sigVersion: sigWitnessV0,
      amounts: @[Satoshi(0)],
      scriptPubKeys: @[@[]],
      codesepPos: 0xFFFFFFFF'u32,
    )

    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err != seTapscriptValidationWeight
