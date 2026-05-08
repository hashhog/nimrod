## Wave 31: P2SH / P2WSH script-commitment verification.
##
## Before the wallet signs (or finalizes) a P2SH-wrapped or P2WSH input it
## MUST prove that the supplied redeemScript / witnessScript actually
## commits to the bytes of the prevout's scriptPubKey. Skipping this check
## turns a forged redeemScript into a free signing oracle: the wallet would
## happily produce a signature against an attacker-chosen sighash.
##
## Reference (Bitcoin Core):
##   src/script/sign.cpp::ProduceSignature → SignStep dispatch confirms
##     hash160(redeem) == spk[2..21]    (TX_SCRIPTHASH)
##     sha256(witness) == spk[2..33]    (TX_WITNESS_V0_SCRIPTHASH)
##   before calling SignSignature on the inner script.
##
## Reference (camlcoin, the porter's reference impl):
##   lib/wallet.ml:1262
##     `Crypto.hash160 redeem |> Cstruct.equal script_hash`
##
## Three tests:
##   1) Positive — correct redeemScript / witnessScript: helper accepts,
##      PSBT finalizer succeeds.
##   2) Negative P2SH — forged redeemScript: helper rejects, PSBT
##      finalizer returns false (no scriptSig emitted, NO signature
##      laundered).
##   3) Negative P2WSH — forged witnessScript: helper rejects, PSBT
##      finalizer returns false (no witness emitted).
##
## Run:
##   nim c -r tests/test_p2sh_commitment.nim

import unittest2
import std/[options, tables]

import ../src/primitives/types
import ../src/wallet/psbt
import ../src/crypto/hashing
import ../src/crypto/secp256k1

# Deterministic privkey helper.
proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32:
    result[i] = 0
  result[31] = b

suite "W31: P2SH/P2WSH commitment checks":

  # -------------------------------------------------------------------------
  # Test 1: positive — verifyP2SHCommitment / verifyP2WSHCommitment accept
  # the matching redeemScript / witnessScript, and the PSBT finalizer
  # succeeds on a well-formed P2SH-P2WPKH input.
  # -------------------------------------------------------------------------
  test "1) positive: matching redeemScript+witnessScript pass commitment helper":
    let priv = mkPriv(0x11)
    let pub  = derivePublicKey(priv)
    let pkh  = hash160(pub)

    # P2SH-P2WPKH redeemScript: OP_0 <20-byte hash160(pubkey)>.
    var redeemScript = @[0x00'u8, 0x14'u8]
    redeemScript.add(@pkh)

    # P2SH scriptPubKey: OP_HASH160 <20-byte hash160(redeem)> OP_EQUAL.
    let scriptHash = hash160(redeemScript)
    var spk = @[0xa9'u8, 0x14'u8]
    spk.add(@scriptHash)
    spk.add(0x87'u8)

    check verifyP2SHCommitment(redeemScript, spk)

    # And the matching P2WSH path: a 2-of-2 multisig witnessScript.
    let priv2 = mkPriv(0x12)
    let pub2  = derivePublicKey(priv2)
    var ws = @[0x52'u8]                     # OP_2
    ws.add(0x21'u8); ws.add(@pub)           # push <pub1>
    ws.add(0x21'u8); ws.add(@pub2)          # push <pub2>
    ws.add(0x52'u8)                         # OP_2
    ws.add(0xae'u8)                         # OP_CHECKMULTISIG
    let wsHash = sha256(ws)
    var p2wshSpk = @[0x00'u8, 0x20'u8]
    p2wshSpk.add(@wsHash)

    check verifyP2WSHCommitment(ws, p2wshSpk)

    # P2SH-P2WSH chain: redeemScript=OP_0 <sha256(ws)>, spk hashes redeem.
    var p2shP2wshRedeem = @[0x00'u8, 0x20'u8]
    p2shP2wshRedeem.add(@wsHash)
    let p2shP2wshScriptHash = hash160(p2shP2wshRedeem)
    var p2shP2wshSpk = @[0xa9'u8, 0x14'u8]
    p2shP2wshSpk.add(@p2shP2wshScriptHash)
    p2shP2wshSpk.add(0x87'u8)
    check verifyP2SHCommitment(p2shP2wshRedeem, p2shP2wshSpk)
    check verifyP2SHWrappedP2WSHCommitment(ws, p2shP2wshRedeem)

    # End-to-end: PSBT finalizer accepts a correctly-committed
    # P2SH-P2WPKH input with one partialSig and emits the canonical
    # finalScriptSig (single push of the 22-byte redeemScript).
    var input: PsbtInput
    input.witnessUtxo = some(TxOut(value: Satoshi(1_000_000), scriptPubKey: spk))
    input.redeemScript = redeemScript
    # Synthetic 71-byte DER+hashtype signature; the finalizer doesn't
    # cryptographically verify it, only that one partialSig is present.
    var sig = newSeq[byte](71)
    for i in 0 ..< sig.len: sig[i] = byte(0x30 + (i mod 16))
    input.partialSigs[@pub] = sig

    check finalizePsbtInput(input)
    check input.finalScriptSig.len == 1 + redeemScript.len
    check input.finalScriptSig[0] == byte(redeemScript.len)
    check input.finalScriptWitness.len == 2

  # -------------------------------------------------------------------------
  # Test 2: negative P2SH — forged redeemScript whose hash160 does NOT
  # match spk[2..21]. Helper rejects, finalizer refuses to emit scriptSig
  # (NO laundering of the partialSig).
  # -------------------------------------------------------------------------
  test "2) negative P2SH: forged redeemScript rejected; no scriptSig emitted":
    # The "real" scriptPubKey commits to a different pubkey-hash entirely.
    let realPriv = mkPriv(0x21)
    let realPub  = derivePublicKey(realPriv)
    let realPkh  = hash160(realPub)
    var realRedeem = @[0x00'u8, 0x14'u8]
    realRedeem.add(@realPkh)
    let realScriptHash = hash160(realRedeem)

    # Attacker-controlled scriptPubKey: commits to realRedeem.
    var spk = @[0xa9'u8, 0x14'u8]
    spk.add(@realScriptHash)
    spk.add(0x87'u8)

    # Forged redeemScript (different pubkey) — does NOT hash to spk[2..21].
    let forgedPriv = mkPriv(0x22)
    let forgedPub  = derivePublicKey(forgedPriv)
    let forgedPkh  = hash160(forgedPub)
    var forgedRedeem = @[0x00'u8, 0x14'u8]
    forgedRedeem.add(@forgedPkh)

    # Helper must reject.
    check (not verifyP2SHCommitment(forgedRedeem, spk))

    # PSBT finalizer must refuse to finalize, and no scriptSig should be
    # emitted (the forged signature must NOT leak into a final tx).
    var input: PsbtInput
    input.witnessUtxo = some(TxOut(value: Satoshi(1_000_000), scriptPubKey: spk))
    input.redeemScript = forgedRedeem
    var sig = newSeq[byte](71)
    for i in 0 ..< sig.len: sig[i] = byte(0x44)
    input.partialSigs[@forgedPub] = sig

    check (not finalizePsbtInput(input))
    check input.finalScriptSig.len == 0
    check input.finalScriptWitness.len == 0

  # -------------------------------------------------------------------------
  # Test 3: negative P2WSH — forged witnessScript whose sha256 does NOT
  # match spk[2..33]. Helper rejects, finalizer refuses to emit a witness.
  # -------------------------------------------------------------------------
  test "3) negative P2WSH: forged witnessScript rejected; no witness emitted":
    let priv1 = mkPriv(0x31)
    let priv2 = mkPriv(0x32)
    let pub1  = derivePublicKey(priv1)
    let pub2  = derivePublicKey(priv2)

    # The "real" witnessScript that the spk commits to.
    var realWs = @[0x52'u8]                  # OP_2
    realWs.add(0x21'u8); realWs.add(@pub1)
    realWs.add(0x21'u8); realWs.add(@pub2)
    realWs.add(0x52'u8)                      # OP_2
    realWs.add(0xae'u8)                      # OP_CHECKMULTISIG
    let realWsHash = sha256(realWs)

    var spk = @[0x00'u8, 0x20'u8]
    spk.add(@realWsHash)

    # Forged witnessScript: 1-of-2 instead of 2-of-2 (OP_1, OP_2).
    var forgedWs = @[0x51'u8]                # OP_1
    forgedWs.add(0x21'u8); forgedWs.add(@pub1)
    forgedWs.add(0x21'u8); forgedWs.add(@pub2)
    forgedWs.add(0x52'u8)                    # OP_2
    forgedWs.add(0xae'u8)                    # OP_CHECKMULTISIG

    # Helper must reject.
    check (not verifyP2WSHCommitment(forgedWs, spk))

    # PSBT finalizer must return false and emit NO witness stack — the
    # attacker-supplied witnessScript must not slip into a final tx.
    var input: PsbtInput
    input.witnessUtxo = some(TxOut(value: Satoshi(1_000_000), scriptPubKey: spk))
    input.witnessScript = forgedWs
    var sig1 = newSeq[byte](71)
    for i in 0 ..< sig1.len: sig1[i] = byte(0x55)
    input.partialSigs[@pub1] = sig1

    check (not finalizePsbtInput(input))
    check input.finalScriptSig.len == 0
    check input.finalScriptWitness.len == 0

  # -------------------------------------------------------------------------
  # Defensive shape checks for the helpers themselves.
  # -------------------------------------------------------------------------
  test "helpers reject malformed scriptPubKeys (defensive shape gates)":
    # Empty / wrong-length / wrong-opcode scriptPubKeys must always be
    # rejected so callers fail closed even on garbage input.
    let bogus = @[0x00'u8]
    check (not verifyP2SHCommitment(@[0x00'u8, 0x14'u8], bogus))
    check (not verifyP2WSHCommitment(@[0x00'u8, 0x14'u8], bogus))

    # 22-byte spk shaped like P2WPKH (not P2SH) must be rejected by the
    # P2SH helper.
    var almostP2sh = newSeq[byte](22)
    almostP2sh[0] = 0xa9'u8; almostP2sh[1] = 0x14'u8
    check (not verifyP2SHCommitment(@[0x00'u8], almostP2sh))

    # 34-byte spk with leading 0x51 (P2TR shape) must be rejected by the
    # P2WSH helper.
    var p2tr = newSeq[byte](34)
    p2tr[0] = 0x51'u8; p2tr[1] = 0x20'u8
    check (not verifyP2WSHCommitment(@[0x51'u8], p2tr))
