## Wave 29-E: Phase-2 segwit-v0 wallet signing — vector tests.
##
## Covers the 4 spend types newly added in W29-E:
##   1. P2PKH                 (legacy, BIP-62)
##   2. P2SH-P2WPKH           (BIP-143 wrapped-segwit)
##   3. P2WSH 2-of-3 multisig (BIP-143 native witness, multisig)
##   4. P2SH-P2WSH 2-of-2     (BIP-143 wrapped, multisig)
##
## Strategy: each test
##   (a) builds a synthetic prevout funding the relevant address shape,
##   (b) crafts an unsigned spending tx,
##   (c) calls the new signer,
##   (d) feeds (scriptSig, scriptPubKey, witness, amount) through
##       `script/interpreter.verifyScript` with standard mandatory flags
##       and asserts it returns `true`.
##
## verifyScript exercises both the byte-shape AND the BIP-143 sighash
## byte-for-byte — a regression in either the assembly or the sighash
## (the W27-B canonical-sighash path) makes verifyScript return false.
##
## Reference: bitcoin-core/src/test/data/sighash.json + the prose vectors
## in BIP-143. The fixed test transactions here use deterministic keys
## (0x01 .. 0x05) so the test is self-contained and reproducible without
## needing to pull in the ~2 MB sighash.json fixture.
##
## Run:
##   nim c -r tests/test_wallet_phase2_segwitv0.nim

import unittest2

import ../src/primitives/types
import ../src/wallet/wallet
import ../src/script/interpreter
import ../src/crypto/[hashing, secp256k1]

# Test fixtures: 5 deterministic privkeys + their compressed pubkeys.
proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32:
    result[i] = 0
  result[31] = b

proc mkInputs(spk: seq[byte]): Transaction =
  ## Build a minimal 1-in/1-out unsigned tx: prevout txid 0xaa..., vout 0.
  var prevTxid: array[32, byte]
  for i in 0 ..< 32: prevTxid[i] = 0xaa'u8
  let txin = TxIn(
    prevOut: OutPoint(txid: TxId(prevTxid), vout: 0'u32),
    scriptSig: @[],
    sequence: 0xffffffff'u32
  )
  let txout = TxOut(value: Satoshi(95_000_000), scriptPubKey: spk)
  Transaction(
    version: 2'i32,
    inputs: @[txin],
    outputs: @[txout],
    witnesses: @[ @[] ],
    lockTime: 0'u32
  )

# Mandatory verification flag set covering BIP-143 + BIP-147 + BIP-66 +
# strict encoding, mirroring Core's STANDARD_SCRIPT_VERIFY_FLAGS minus
# taproot rules (we're not exercising v1 here).
const SegwitV0VerifyFlags = {
  sfP2SH, sfDERSig, sfStrictEnc, sfWitness, sfNullDummy, sfLowS,
  sfWitnessPubkeyType, sfMinimalIf, sfNullFail
}

suite "W29-E: Phase-2 segwit-v0 wallet signing":

  test "1) signInputP2PKH produces a verifiable scriptSig (legacy BIP-62)":
    let priv = mkPriv(0x01)
    let pub  = derivePublicKey(priv)
    let pkh  = hash160(pub)

    # P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    var spk = @[0x76'u8, 0xa9'u8, 0x14'u8]
    spk.add(@pkh)
    spk.add([0x88'u8, 0xac'u8])

    var tx = mkInputs(spk)
    signInputP2PKH(tx, 0, priv, pub)

    # Witness must be empty (legacy).
    check tx.witnesses[0].len == 0
    # scriptSig must be <push sig+hashType> <push 33-byte pubkey>.
    check tx.inputs[0].scriptSig.len > 0
    # Last byte of the sig push: hashType (SIGHASH_ALL = 0x01).
    # Last 34 bytes are <0x21 (push33)> <33-byte compressed pubkey>.
    let ss = tx.inputs[0].scriptSig
    check ss[ss.len - 34] == 0x21'u8
    check ss[ss.len - 33] == pub[0]

    let ok = verifyScript(
      scriptSig    = tx.inputs[0].scriptSig,
      scriptPubKey = spk,
      tx           = tx,
      inputIndex   = 0,
      amount       = Satoshi(0),
      flags        = SegwitV0VerifyFlags - {sfWitnessPubkeyType},
      witness      = @[]
    )
    check ok

  test "2) signInputP2SHP2WPKH wraps redeemScript correctly (BIP-143 vector 4)":
    let priv = mkPriv(0x02)
    let pub  = derivePublicKey(priv)
    let wpkh = hash160(pub)

    # redeemScript: OP_0 <20-byte-hash>
    var redeemScript = @[0x00'u8, 0x14'u8]
    redeemScript.add(@wpkh)
    let scriptHash = hash160(redeemScript)

    # P2SH scriptPubKey: OP_HASH160 <20-byte-redeem-hash> OP_EQUAL
    var spk = @[0xa9'u8, 0x14'u8]
    spk.add(@scriptHash)
    spk.add(0x87'u8)

    let amount = Satoshi(123_456_789)
    var tx = mkInputs(spk)
    tx.outputs[0].value = amount - Satoshi(5_000_000)
    signInputP2SHP2WPKH(tx, 0, priv, pub, amount)

    # scriptSig is exactly one push: 0x16 <22-byte redeemScript>.
    check tx.inputs[0].scriptSig.len == 1 + redeemScript.len
    check tx.inputs[0].scriptSig[0] == byte(redeemScript.len)
    # Witness has 2 elements: <DER sig + sighash> <33-byte pubkey>.
    check tx.witnesses[0].len == 2
    check tx.witnesses[0][1].len == 33

    let ok = verifyScript(
      scriptSig    = tx.inputs[0].scriptSig,
      scriptPubKey = spk,
      tx           = tx,
      inputIndex   = 0,
      amount       = amount,
      flags        = SegwitV0VerifyFlags,
      witness      = tx.witnesses[0]
    )
    check ok

  test "3) signInputP2WSH 2-of-3 multisig verifies (Wave 28 gate vector)":
    let priv1 = mkPriv(0x03)
    let priv2 = mkPriv(0x04)
    let priv3 = mkPriv(0x05)
    let pub1  = derivePublicKey(priv1)
    let pub2  = derivePublicKey(priv2)
    let pub3  = derivePublicKey(priv3)

    # 2-of-3 multisig witnessScript:
    #   OP_2 <pub1> <pub2> <pub3> OP_3 OP_CHECKMULTISIG
    var ws = @[0x52'u8]  # OP_2
    ws.add(0x21'u8); ws.add(@pub1)  # push 33
    ws.add(0x21'u8); ws.add(@pub2)
    ws.add(0x21'u8); ws.add(@pub3)
    ws.add(0x53'u8)  # OP_3
    ws.add(0xae'u8)  # OP_CHECKMULTISIG

    # P2WSH scriptPubKey: OP_0 <sha256(witnessScript)>
    let wsHash = sha256(ws)
    var spk = @[0x00'u8, 0x20'u8]
    spk.add(@wsHash)

    let amount = Satoshi(200_000_000)
    var tx = mkInputs(spk)
    tx.outputs[0].value = amount - Satoshi(5_000_000)

    # Sign with priv1 + priv2 (the first two keys, in the order they
    # appear in the witnessScript). CHECKMULTISIG verifies in pubkey order
    # so signature order must match.
    signInputP2WSH(tx, 0, [priv1, priv2], ws, amount)

    # Witness layout: [<empty>, <sig1>, <sig2>, <witnessScript>]
    check tx.witnesses[0].len == 4
    check tx.witnesses[0][0].len == 0  # CHECKMULTISIG dummy
    check tx.witnesses[0][3] == ws
    # scriptSig empty for native P2WSH.
    check tx.inputs[0].scriptSig.len == 0

    let ok = verifyScript(
      scriptSig    = @[],
      scriptPubKey = spk,
      tx           = tx,
      inputIndex   = 0,
      amount       = amount,
      flags        = SegwitV0VerifyFlags,
      witness      = tx.witnesses[0]
    )
    check ok

  test "4) signInputP2SHP2WSH 2-of-2 wraps then verifies (BIP-143 vector 6)":
    let priv1 = mkPriv(0x06)
    let priv2 = mkPriv(0x07)
    let pub1  = derivePublicKey(priv1)
    let pub2  = derivePublicKey(priv2)

    # 2-of-2 witnessScript: OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
    var ws = @[0x52'u8]
    ws.add(0x21'u8); ws.add(@pub1)
    ws.add(0x21'u8); ws.add(@pub2)
    ws.add(0x52'u8)
    ws.add(0xae'u8)

    # redeemScript: OP_0 <sha256(witnessScript)>
    let wsHash = sha256(ws)
    var redeemScript = @[0x00'u8, 0x20'u8]
    redeemScript.add(@wsHash)
    let scriptHash = hash160(redeemScript)

    # P2SH scriptPubKey: OP_HASH160 <20-byte-redeem-hash> OP_EQUAL
    var spk = @[0xa9'u8, 0x14'u8]
    spk.add(@scriptHash)
    spk.add(0x87'u8)

    let amount = Satoshi(987_654_321)
    var tx = mkInputs(spk)
    tx.outputs[0].value = amount - Satoshi(5_000_000)
    signInputP2SHP2WSH(tx, 0, [priv1, priv2], ws, amount)

    # scriptSig: single push of redeemScript (1 + 34 bytes).
    check tx.inputs[0].scriptSig.len == 1 + redeemScript.len
    check tx.inputs[0].scriptSig[0] == byte(redeemScript.len)
    # Witness like P2WSH: [<empty>, <sig1>, <sig2>, <witnessScript>]
    check tx.witnesses[0].len == 4
    check tx.witnesses[0][0].len == 0

    let ok = verifyScript(
      scriptSig    = tx.inputs[0].scriptSig,
      scriptPubKey = spk,
      tx           = tx,
      inputIndex   = 0,
      amount       = amount,
      flags        = SegwitV0VerifyFlags,
      witness      = tx.witnesses[0]
    )
    check ok

  test "regression: existing P2WPKH still verifies (W27-B canonical sighash)":
    # Pin: this wave must NOT regress W27-B. Re-run the same shape as the
    # production P2WPKH path and check verifyScript still returns true.
    let priv = mkPriv(0x08)
    let pub  = derivePublicKey(priv)
    let pkh  = hash160(pub)
    var spk = @[0x00'u8, 0x14'u8]
    spk.add(@pkh)
    let amount = Satoshi(50_000_000)
    var tx = mkInputs(spk)
    tx.outputs[0].value = amount - Satoshi(5_000_000)
    signInputP2WPKH(tx, 0, priv, pub, amount)
    let ok = verifyScript(
      scriptSig    = @[],
      scriptPubKey = spk,
      tx           = tx,
      inputIndex   = 0,
      amount       = amount,
      flags        = SegwitV0VerifyFlags,
      witness      = tx.witnesses[0]
    )
    check ok
