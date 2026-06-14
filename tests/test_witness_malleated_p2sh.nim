## Non-vacuous regression test: WITNESS_MALLEATED_P2SH byte-exact scriptSig check.
##
## Bitcoin Core interpreter.cpp:2082-2086 requires that, for a P2SH-wrapped
## witness program, scriptSig MUST be byte-for-byte equal to the minimal
## canonical single push of the redeemScript:
##
##   if (scriptSig != CScript() << redeemScript)
##       return SCRIPT_ERR_WITNESS_MALLEATED_P2SH
##
## A "push-only" check (isPushOnly) or a residual-stack check ("one item left
## on stack after P2SH eval") does NOT catch a non-minimal push encoding.
## For a 22-byte redeemScript W (e.g. P2WPKH = OP_0 <20-byte hash>):
##
##   Canonical (minimal):     0x16 <W>          -- 23 bytes total
##   Non-canonical (malleated): 0x4c 0x16 <W>   -- 24 bytes, OP_PUSHDATA1 form
##
## Both are push-only.  Both push exactly [W] onto the stack.  Both leave an
## empty residual stack after P2SH HASH<>EQUAL.  Under ConnectBlock flags
## MINIMALDATA is OFF, so the byte-exact comparison is the ONLY guard.
##
## This test uses verifyScriptWithError (the error-returning path) and
## verifyScript (the bool path) to confirm:
##   (A) REJECT: non-canonical scriptSig → seWitnessMalleatedP2SH
##   (B) CANONICAL path does NOT trigger seWitnessMalleatedP2SH (it passes the
##       byte check and proceeds into witness verification; with an empty witness
##       it will fail for a different reason, confirming the check is real and
##       positioned correctly).

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/hashing

suite "WITNESS_MALLEATED_P2SH byte-exact scriptSig check":

  # Shared setup: redeemScript = P2WPKH program (OP_0 <20-byte hash>), 22 bytes.
  # This is the canonical wrapped-witness-program spend target.
  let witnessKeyHash: array[20, byte] = [
    0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14
  ]

  # redeemScript = OP_0 <20-byte witnessKeyHash>  (22 bytes)
  let redeemScript: seq[byte] = block:
    var s: seq[byte] = @[OP_0, 0x14'u8]
    for b in witnessKeyHash: s.add(b)
    s

  # P2SH scriptPubKey = OP_HASH160 <hash160(redeemScript)> OP_EQUAL
  let redeemHash = hash160(redeemScript)
  let scriptPubKey: seq[byte] = block:
    var s: seq[byte] = @[OP_HASH160, 0x14'u8]
    for b in redeemHash: s.add(b)
    s.add(OP_EQUAL)
    s

  # Minimal canonical scriptSig: 0x16 <redeemScript>  (23 bytes)
  # redeemScript.len == 22 < 0x4c (76), so Core uses a direct length byte.
  let canonicalScriptSig: seq[byte] = block:
    var s: seq[byte] = @[byte(redeemScript.len)]
    for b in redeemScript: s.add(b)
    s

  # Non-canonical (malleated) scriptSig: OP_PUSHDATA1 0x16 <redeemScript> (24 bytes).
  # OP_PUSHDATA1 = 0x4c.  For a 22-byte payload, the minimal encoding is
  # 0x16 <payload> (direct push), NOT 0x4c 0x16 <payload>.
  # isPushOnly() returns true; stack after eval = [redeemScript].
  let malleatedScriptSig: seq[byte] = block:
    var s: seq[byte] = @[OP_PUSHDATA1, byte(redeemScript.len)]
    for b in redeemScript: s.add(b)
    s

  proc makeTx(sig: seq[byte]): Transaction =
    var tx = Transaction()
    tx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: sig,
      sequence: 0xFFFFFFFF'u32
    ))
    tx.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: @[]))
    tx

  test "sanity: redeemScript is 22 bytes (P2WPKH program)":
    # OP_0 (1 byte) + 0x14 length prefix (1 byte) + 20 bytes hash = 22 bytes
    check redeemScript.len == 22
    check redeemScript[0] == OP_0
    check redeemScript[1] == 0x14'u8

  test "sanity: canonical scriptSig is 23 bytes (0x16 + 22 bytes)":
    # Direct length byte 0x16 (=22) + 22 bytes payload
    check canonicalScriptSig.len == 23
    check canonicalScriptSig[0] == 0x16'u8

  test "sanity: malleated scriptSig is 24 bytes (0x4c 0x16 + 22 bytes)":
    # OP_PUSHDATA1 (0x4c) + length byte 0x16 + 22 bytes payload
    check malleatedScriptSig.len == 24
    check malleatedScriptSig[0] == OP_PUSHDATA1
    check malleatedScriptSig[1] == 0x16'u8

  test "sanity: malleated scriptSig is push-only (confirms isPushOnly alone is insufficient)":
    # The pre-fix code relied on isPushOnly to gate the P2SH arm.
    # A non-minimal push IS push-only — this confirms the gap.
    check isPushOnly(malleatedScriptSig) == true

  test "(A) REJECT — non-minimal OP_PUSHDATA1 scriptSig → seWitnessMalleatedP2SH":
    # Block-validation flags: sfP2SH + sfWitness (MINIMALDATA intentionally OFF).
    # Under ConnectBlock GetBlockScriptFlags, MINIMALDATA is not set — the
    # byte-exact check at Core:2082 is the ONLY guard.
    let tx = makeTx(malleatedScriptSig)
    let err = verifyScriptWithError(
      malleatedScriptSig,
      scriptPubKey,
      tx, 0, Satoshi(0),
      {sfP2SH, sfWitness},
      @[]  # empty witness
    )
    check err == seWitnessMalleatedP2SH

  test "(A) REJECT — verifyScript (bool path) also rejects non-minimal encoding":
    let tx = makeTx(malleatedScriptSig)
    let ok = verifyScript(
      malleatedScriptSig,
      scriptPubKey,
      tx, 0, Satoshi(0),
      {sfP2SH, sfWitness},
      @[]
    )
    check ok == false

  test "(B) CANONICAL scriptSig does NOT trigger seWitnessMalleatedP2SH":
    # With the canonical 0x16 <W> scriptSig, the byte-exact check passes.
    # With an empty witness the spend will fail (no signature), but the error
    # must NOT be seWitnessMalleatedP2SH — any other error is acceptable here
    # because it proves the check is positioned correctly and the canonical
    # path gets through it.
    let tx = makeTx(canonicalScriptSig)
    let err = verifyScriptWithError(
      canonicalScriptSig,
      scriptPubKey,
      tx, 0, Satoshi(0),
      {sfP2SH, sfWitness},
      @[]
    )
    check err != seWitnessMalleatedP2SH
