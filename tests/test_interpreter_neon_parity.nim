## Script-interpreter divergences from Bitcoin Core v31.1 found by the
## 2026-11-24 Neon audit of nimrod (findings 2, 6 and 7), each checked
## against Core v31.1 src/script/interpreter.cpp and src/pubkey.cpp.
##
##   N2 (consensus) Core's CHECKMULTISIG runs FindAndDelete(scriptCode,
##      CScript() << vchSig) for EVERY signature (interpreter.cpp:1141-1150),
##      including an empty one: CScript() << {} is OP_0, so every
##      opcode-aligned OP_0 leaves the legacy scriptCode and the sighash of the
##      other signatures changes. nimrod's findAndDelete returned early for an
##      empty sig, so a signature valid in Core failed in nimrod (and the
##      reverse), and with DERSIG on that decides whether the loop reaches a
##      later badly-encoded signature: Core and nimrod gave opposite verdicts.
##
##   N6 (script flags) a disabled OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY
##      is a plain NOP in Core (interpreter.cpp:524-527, :563-566) with no
##      DISCOURAGE_UPGRADABLE_NOPS check. nimrod returned
##      seDiscourageUpgradableNops.
##
##   N7 (policy) Core's LOW_S test (IsLowDERSignature -> CPubKey::CheckLowS,
##      pubkey.cpp:424-430) parses with ecdsa_signature_parse_der_lax, which
##      zeroes BOTH R and S when either is >= N, so R >= N with a high S is
##      "low". nimrod parsed strictly (R zeroed alone, S kept) and returned
##      SIG_HIGH_S.

import unittest2

import ../src/primitives/types
import ../src/script/interpreter
import ../src/crypto/secp256k1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc mkTx(version: int32, sequence: uint32, lockTime: uint32 = 0): Transaction =
  Transaction(
    version: version,
    inputs: @[TxIn(prevOut: OutPoint(txid: default(TxId), vout: 0),
                   scriptSig: @[], sequence: sequence)],
    outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
    witnesses: @[],
    lockTime: lockTime)

proc runOp(op: byte, arg: seq[byte], tx: Transaction,
           flags: set[ScriptFlags]): tuple[err: ScriptError, raised: string] =
  ## Push `arg`, run one opcode. A raised Defect/exception is reported by
  ## name instead of aborting the test binary, so the test fails by name.
  var interp = newInterpreter(flags)
  interp.push(arg)
  var ctx = SigCheckContext(tx: tx, inputIndex: 0, amount: Satoshi(0),
                            sigVersion: sigBase, codesepPos: 0xFFFFFFFF'u32)
  try:
    result = (err: interp.eval(@[op], ctx), raised: "")
  except Exception as e:
    result = (err: seOk, raised: $e.name & ": " & e.msg)

proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32:
    result[i] = 0
  result[31] = b

proc derInt(v: openArray[byte]): seq[byte] =
  var b = @v
  while b.len > 1 and b[0] == 0 and (b[1] and 0x80) == 0:
    b.delete(0)
  if (b[0] and 0x80) != 0:
    b.insert(0'u8, 0)
  result = @[0x02'u8, byte(b.len)] & b

proc compactToDer(sig: Signature, hashType: byte): seq[byte] =
  var r, s: array[32, byte]
  copyMem(addr r[0], unsafeAddr sig[0], 32)
  copyMem(addr s[0], unsafeAddr sig[32], 32)
  let body = derInt(r) & derInt(s)
  result = @[0x30'u8, byte(body.len)] & body & @[hashType]

proc pushData(d: seq[byte]): seq[byte] =
  doAssert d.len < 0x4c
  if d.len == 0: return @[0x00'u8]
  @[byte(d.len)] & d

# ---------------------------------------------------------------------------
# N2: CHECKMULTISIG FindAndDelete of an EMPTY signature removes OP_0
# ---------------------------------------------------------------------------
#
# scriptPubKey = OP_0 OP_DROP OP_3 <k2> <k1> <k0> OP_3 OP_CHECKMULTISIG OP_NOT
# scriptSig    = OP_0(dummy) OP_0(empty sig s2) <bad-DER s1> <s0>
# Core processes s0 against k0 first. If s0 verifies the loop moves on to s1,
# whose bad DER encoding is a hard SCRIPT_ERR_SIG_DER under DERSIG. If s0 does
# not verify, nSigs(3) > nKeys(2) ends the loop with false and OP_NOT makes the
# script succeed. Which branch runs depends on the scriptCode s0 is checked
# against: Core's has the opcode-aligned OP_0 removed (FindAndDelete of the
# empty s2).

proc multisigCase(signOverStripped: bool): tuple[spk, scriptSig: seq[byte],
                                                  tx: Transaction] =
  let k0 = derivePublicKey(mkPriv(0x11))
  let k1 = derivePublicKey(mkPriv(0x12))
  let k2 = derivePublicKey(mkPriv(0x13))
  var spk = @[0x00'u8, 0x75'u8, 0x53'u8]          # OP_0 OP_DROP OP_3
  spk.add pushData(@k2)
  spk.add pushData(@k1)
  spk.add pushData(@k0)
  spk.add @[0x53'u8, 0xae'u8, 0x91'u8]            # OP_3 CHECKMULTISIG OP_NOT
  # Core's scriptCode after FindAndDelete of every sig: only the leading
  # opcode-aligned OP_0 matches (no sig push occurs in the scriptPubKey).
  let stripped = spk[1 .. ^1]
  var tx = mkTx(1, 0xFFFFFFFF'u32)
  let sighash = computeSighashLegacy(tx, 0,
                  (if signOverStripped: stripped else: spk), 1'u32)
  let s0 = compactToDer(sign(mkPriv(0x11), sighash), 0x01)
  let badDer = @[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x01]
  var scriptSig = @[0x00'u8, 0x00'u8]               # dummy, empty s2
  scriptSig.add pushData(badDer)
  scriptSig.add pushData(s0)
  tx.inputs[0].scriptSig = scriptSig
  (spk, scriptSig, tx)

suite "N2 CHECKMULTISIG FindAndDelete with an empty signature (consensus)":
  test "N2a: s0 signed over the OP_0-stripped scriptCode -> Core rejects SIG_DER":
    let c = multisigCase(signOverStripped = true)
    check verifyScriptWithError(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                                {sfP2SH, sfDERSig}) == seSigDer
    check verifyScript(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                       {sfP2SH, sfDERSig}) == false

  test "N2b: s0 signed over the unstripped scriptCode -> Core accepts":
    let c = multisigCase(signOverStripped = false)
    check verifyScriptWithError(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                                {sfP2SH, sfDERSig}) == seOk
    check verifyScript(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                       {sfP2SH, sfDERSig}) == true

  test "N2c: findAndDelete of an empty sig removes opcode-aligned OP_0 only":
    # OP_0 <push 0x00> OP_0 : the 0x00 inside the push is not opcode-aligned.
    let script = @[0x00'u8, 0x01, 0x00, 0x00]
    check findAndDelete(script, @[]) == @[0x01'u8, 0x00]

  test "N2e: CONST_SCRIPTCODE: an empty CHECKMULTISIG sig over a scriptCode with OP_0 is SIG_FINDANDDELETE":
    # Core interpreter.cpp:1146-1148: FindAndDelete(scriptCode, CScript() << {})
    # finds the opcode-aligned OP_0 -> found > 0 -> SIG_FINDANDDELETE when
    # CONST_SCRIPTCODE is set (policy only; block flags never carry it).
    let c = multisigCase(signOverStripped = true)
    check verifyScriptWithError(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                                {sfP2SH, sfDERSig, sfConstScriptCode}) == seSigFindAndDelete

  test "N2f: control: CONST_SCRIPTCODE with no signature to delete is not SIG_FINDANDDELETE":
    # scriptPubKey = OP_1 OP_DROP OP_0 OP_0 CHECKMULTISIG: a 0-of-0 multisig.
    # The scriptCode holds OP_0s, but with no signature nothing is deleted,
    # so CONST_SCRIPTCODE does not fire and the script succeeds.
    let spk = @[0x51'u8, 0x75, 0x00, 0x00, 0xae]   # 1 DROP 0 0 CHECKMULTISIG
    let scriptSig = @[0x00'u8]                     # dummy
    var tx = mkTx(1, 0xFFFFFFFF'u32)
    tx.inputs[0].scriptSig = scriptSig
    check verifyScriptWithError(scriptSig, spk, tx, 0, Satoshi(0),
                                {sfP2SH, sfDERSig, sfConstScriptCode}) == seOk

  test "N2d: control: findAndDelete of a non-empty sig is unchanged":
    let sig = @[0xAA'u8, 0xBB]
    let script = @[0x02'u8, 0xAA, 0xBB, 0x51]
    check findAndDelete(script, sig) == @[0x51'u8]

# ---------------------------------------------------------------------------
# N6: disabled CLTV / CSV are NOPs even under DISCOURAGE_UPGRADABLE_NOPS
# ---------------------------------------------------------------------------

suite "N6 disabled CLTV/CSV ignore DISCOURAGE_UPGRADABLE_NOPS":
  test "N6a: CLTV without its flag is a NOP under DISCOURAGE_UPGRADABLE_NOPS":
    let r = runOp(OP_CHECKLOCKTIMEVERIFY, @[0x64'u8], mkTx(1, 0),
                  {sfDiscourageUpgradableNops})
    check r.err == seOk

  test "N6b: CSV without its flag is a NOP under DISCOURAGE_UPGRADABLE_NOPS":
    let r = runOp(OP_CHECKSEQUENCEVERIFY, @[0x01'u8], mkTx(1, 0),
                  {sfDiscourageUpgradableNops})
    check r.err == seOk

  test "N6c: control: OP_NOP4 is still discouraged":
    let r = runOp(OP_NOP4, @[0x01'u8], mkTx(1, 0), {sfDiscourageUpgradableNops})
    check r.err == seDiscourageUpgradableNops

# ---------------------------------------------------------------------------
# N7: LOW_S uses the lax DER parse (R >= N zeroes the whole signature)
# ---------------------------------------------------------------------------

const
  # secp256k1 order N - 1 (high S: above N/2)
  NMinus1 = [0xFF'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
             0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
             0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]

proc sigRS(r, s: openArray[byte]): seq[byte] =
  let body = derInt(r) & derInt(s)
  @[0x30'u8, byte(body.len)] & body & @[0x01'u8]

suite "N7 LOW_S parses the signature laxly like CPubKey::CheckLowS (policy)":
  test "N7a: R = 2^256-1 (>= N) with S = N-1 is not SIG_HIGH_S":
    var rMax: array[32, byte]
    for i in 0 ..< 32: rMax[i] = 0xFF
    let sig = sigRS(rMax, NMinus1)
    check sig.len == 73
    check checkSignatureEncoding(sig, {sfDERSig, sfLowS}) == seOk

  test "N7b: <sig R>=N> <pk> CHECKSIG NOT passes with LOW_S and no NULLFAIL":
    var rMax: array[32, byte]
    for i in 0 ..< 32: rMax[i] = 0xFF
    let sig = sigRS(rMax, NMinus1)
    let pk = derivePublicKey(mkPriv(0x21))
    var spk = pushData(@pk)
    spk.add @[0xac'u8, 0x91'u8]                     # CHECKSIG NOT
    let scriptSig = @[byte(sig.len)] & sig
    var tx = mkTx(1, 0xFFFFFFFF'u32)
    tx.inputs[0].scriptSig = scriptSig
    check verifyScriptWithError(scriptSig, spk, tx, 0, Satoshi(0),
                                {sfP2SH, sfDERSig, sfLowS}) == seOk

  test "N7c: control: valid R with S = N-1 is still SIG_HIGH_S":
    var r: array[32, byte]
    r[31] = 0x01
    check checkSignatureEncoding(sigRS(r, NMinus1), {sfDERSig, sfLowS}) == seSigHighS
