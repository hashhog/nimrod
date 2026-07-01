## Glass-box interpreter parity regression tests (2026-07-01).
##
## Three confirmed script-interpreter divergences vs Bitcoin Core
## (bitcoin-core/src/script/interpreter.cpp is authoritative):
##
##   F1 — MAX_STACK_SIZE (1000) not enforced after data-push opcodes.
##        Core runs the "Size limits" check (interpreter.cpp:1221-1223) at the
##        bottom of the opcode loop after EVERY opcode, INCLUDING pushes, so a
##        scriptPubKey of 1001 one-byte pushes yields stack.size()=1001 >
##        MAX_STACK_SIZE -> SCRIPT_ERR_STACK_SIZE. nimrod's push branches all
##        `continue` before the only size check, so the 1001-element stack was
##        accepted. Exactly 1000 must stay valid.
##
##   F2 — bool verifyScript did not reset codesepByteOffset between scriptSig
##        and scriptPubKey. Core resets pbegincodehash to script.begin() at the
##        start of each EvalScript (interpreter.cpp:422), so an OP_CODESEPARATOR
##        in the scriptSig must NOT carry into the scriptPubKey's sighash
##        subscript. Stale offset -> wrong scriptCode -> valid sig rejected.
##
##   F3 — bool verifyScript omitted SCRIPT_ERR_WITNESS_UNEXPECTED. Core
##        (interpreter.cpp:2115-2116) rejects a non-witness input that carries
##        witness data when SCRIPT_VERIFY_WITNESS is set. nimrod accepted it.
##
## Reference: bitcoin-core/src/script/interpreter.cpp:1221-1223, :422, :2115-2116
##
## Run:
##   nim c -r tests/test_interpreter_glassbox_fixes.nim

import unittest2

import ../src/primitives/types
import ../src/script/interpreter
import ../src/crypto/secp256k1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32:
    result[i] = 0
  result[31] = b

proc compactToDer(sig: Signature, hashType: uint32): seq[byte] =
  ## Minimal compact(r||s) -> DER + sighash-type encoder (mirrors the wallet's
  ## private compactSigToDer; replicated here to keep the test self-contained).
  var r: array[32, byte]
  var s: array[32, byte]
  copyMem(addr r[0], addr sig[0], 32)
  copyMem(addr s[0], addr sig[32], 32)

  var rBytes: seq[byte]
  rBytes.add(@r)
  while rBytes.len > 1 and rBytes[0] == 0 and (rBytes[1] and 0x80) == 0:
    rBytes.delete(0)
  if (rBytes[0] and 0x80) != 0:
    rBytes.insert(0, 0)

  var sBytes: seq[byte]
  sBytes.add(@s)
  while sBytes.len > 1 and sBytes[0] == 0 and (sBytes[1] and 0x80) == 0:
    sBytes.delete(0)
  if (sBytes[0] and 0x80) != 0:
    sBytes.insert(0, 0)

  result = @[0x30'u8]
  result.add(byte(2 + rBytes.len + 2 + sBytes.len))
  result.add(0x02); result.add(byte(rBytes.len)); result.add(rBytes)
  result.add(0x02); result.add(byte(sBytes.len)); result.add(sBytes)
  result.add(byte(hashType and 0xff))

proc mkSpendingTx(): Transaction =
  ## 1-in / 1-out spending tx with a scriptSig placeholder.
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
    witnesses: @[@[]],
    lockTime: 0
  )

proc evalPushScript(nPushes: int): ScriptError =
  ## Build a script of `nPushes` one-byte pushes (0x01 0x01 ...) and eval it.
  var script: seq[byte]
  for _ in 0 ..< nPushes:
    script.add(0x01'u8)   # push 1 byte
    script.add(0x01'u8)   # the byte
  var interp = newInterpreter()
  var tx = Transaction()
  var ctx = SigCheckContext(
    tx: tx, inputIndex: 0, amount: Satoshi(0), sigVersion: sigBase,
    codesepPos: 0xFFFFFFFF'u32
  )
  interp.eval(script, ctx)

# ---------------------------------------------------------------------------
# F1: MAX_STACK_SIZE enforced after data pushes
# ---------------------------------------------------------------------------

suite "F1 — MAX_STACK_SIZE (1000) enforced after pushes":

  test "F1a: 1001 one-byte pushes -> SCRIPT_ERR_STACK_SIZE (the failing input)":
    ## Pre-fix: nimrod's push branches `continue` before any size check, so the
    ## 1001-element stack was never rejected and eval returned seOk (ACCEPT).
    ## Core rejects at the bottom-of-loop size check. Must now be seStackSize.
    check evalPushScript(1001) == seStackSize

  test "F1b: exactly 1000 one-byte pushes stays valid (boundary not regressed)":
    ## The legitimate 1000-element boundary must still pass (seOk).
    check evalPushScript(1000) == seOk

  test "F1c: 1001 via OP_PUSHDATA1 pushes also -> SCRIPT_ERR_STACK_SIZE":
    var script: seq[byte]
    for _ in 0 ..< 1001:
      script.add(0x4c'u8)  # OP_PUSHDATA1
      script.add(0x01'u8)  # length 1
      script.add(0x01'u8)  # the byte
    var interp = newInterpreter()
    var tx = Transaction()
    var ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0), sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )
    check interp.eval(script, ctx) == seStackSize

# ---------------------------------------------------------------------------
# F2: codesepByteOffset reset between scriptSig and scriptPubKey
# ---------------------------------------------------------------------------

suite "F2 — verifyScript resets codesep offset scriptSig->scriptPubKey":

  test "F2a: OP_CODESEPARATOR in scriptSig must not corrupt CHECKSIG sighash":
    ## Bare CHECKSIG spend. scriptSig = OP_CODESEPARATOR <sig>. The signature
    ## is computed over the FULL scriptPubKey (Core's scriptCode). Pre-fix the
    ## stale codesepByteOffset=1 truncated the scriptCode in scriptPubKey eval,
    ## producing a wrong sighash -> verifyScript returned false (REJECT). Core
    ## ACCEPTS. Post-fix nimrod must ACCEPT (return true).
    let priv = mkPriv(0x07)
    let pub = derivePublicKey(priv)         # 33-byte compressed

    var scriptPubKey: seq[byte] = @[0x21'u8]  # push 33 bytes
    scriptPubKey.add(@pub)
    scriptPubKey.add(0xac'u8)                 # OP_CHECKSIG

    var tx = mkSpendingTx()
    # Legacy sighash over scriptCode = the full scriptPubKey (Core behavior).
    let sighash = computeSighashLegacy(tx, 0, scriptPubKey, uint32(1))  # SIGHASH_ALL
    let sig = sign(priv, sighash)
    let derSig = compactToDer(sig, uint32(1))

    # scriptSig = OP_CODESEPARATOR, then push the signature.
    var scriptSig: seq[byte] = @[0xab'u8]     # OP_CODESEPARATOR
    scriptSig.add(byte(derSig.len))
    scriptSig.add(derSig)
    tx.inputs[0].scriptSig = scriptSig

    check verifyScript(scriptSig, scriptPubKey, tx, 0, Satoshi(0), {}) == true

  test "F2b: control — same spend WITHOUT the leading OP_CODESEPARATOR verifies":
    let priv = mkPriv(0x07)
    let pub = derivePublicKey(priv)
    var scriptPubKey: seq[byte] = @[0x21'u8]
    scriptPubKey.add(@pub)
    scriptPubKey.add(0xac'u8)
    var tx = mkSpendingTx()
    let sighash = computeSighashLegacy(tx, 0, scriptPubKey, uint32(1))
    let sig = sign(priv, sighash)
    let derSig = compactToDer(sig, uint32(1))
    var scriptSig: seq[byte] = @[byte(derSig.len)]
    scriptSig.add(derSig)
    tx.inputs[0].scriptSig = scriptSig
    check verifyScript(scriptSig, scriptPubKey, tx, 0, Satoshi(0), {}) == true

# ---------------------------------------------------------------------------
# F3: WITNESS_UNEXPECTED — witness data on a non-witness input
# ---------------------------------------------------------------------------

suite "F3 — verifyScript rejects witness on a non-witness input":

  test "F3a: non-witness scriptPubKey + non-empty witness + WITNESS flag -> reject":
    ## Pre-fix nimrod validated the (non-witness) scriptPubKey and returned true
    ## without ever inspecting the witness -> ACCEPT. Core rejects with
    ## SCRIPT_ERR_WITNESS_UNEXPECTED (interpreter.cpp:2115-2116). Must now reject.
    let scriptSig: seq[byte] = @[]
    let scriptPubKey: seq[byte] = @[0x51'u8]           # OP_1 (non-witness, valid)
    let witness: seq[seq[byte]] = @[@[0x00'u8]]        # non-empty witness stack
    var tx = mkSpendingTx()
    check verifyScript(scriptSig, scriptPubKey, tx, 0, Satoshi(0),
                       {sfWitness}, witness) == false

  test "F3b: control — same input with EMPTY witness is accepted (no over-correction)":
    let scriptSig: seq[byte] = @[]
    let scriptPubKey: seq[byte] = @[0x51'u8]
    let witness: seq[seq[byte]] = @[]                  # empty
    var tx = mkSpendingTx()
    check verifyScript(scriptSig, scriptPubKey, tx, 0, Satoshi(0),
                       {sfWitness}, witness) == true

when isMainModule:
  echo "Running glass-box interpreter fix regression tests..."
