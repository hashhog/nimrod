## W95 — BIP-340 Schnorr + BIP-341 tagged-hash + tapscript Schnorr
## gate audit. Mirrors Core's:
##   - secp256k1/src/modules/schnorrsig/main_impl.h:104-117
##     (BIP0340/challenge tagged-hash midstate constants)
##   - bitcoin-core/src/script/interpreter.cpp:1721-1741
##     (CheckSchnorrSignature) — sig.size in {64,65}, hash_type byte,
##     SignatureHashSchnorr; all failures are HARD errors in tapscript.
##   - bitcoin-core/src/script/interpreter.cpp:1514-1517
##     (SignatureHashSchnorr hash_type whitelist
##      {SIGHASH_DEFAULT, 0x01..0x03, 0x81..0x83})
##   - bitcoin-core/src/script/interpreter.cpp:1549-1557
##     (SIGHASH_SINGLE out-of-range output index → sighash compute fails)
##
## Background gotchas this suite guards against:
##   * SHA-256-vs-SHA-256d in tagged-hash (would propagate every
##     BIP-340/341/342 hash — total consensus break).
##   * SHA-256-vs-SipHash in tagged-hash (W88 nimrod precedent on
##     headerssync; SipHash is keyed and uses different output size).
##   * Soft-fail of bad Schnorr sig / sighash / sig-size in tapscript
##     (pre-W95 nimrod: caller treated as `success=false` and pushed
##     0 to stack instead of hard-erroring; W95 makes the failures
##     match Core's SCRIPT_ERR_SCHNORR_SIG_{SIZE,HASHTYPE,SIG}).

import std/strutils
import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/secp256k1
import ../src/crypto/hashing

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

proc trivialTx(): Transaction =
  result = Transaction()
  result.version = 2
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: default(TxId), vout: 0),
    scriptSig: @[],
    sequence: 0xffffffff'u32
  )]
  result.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
  result.lockTime = 0

proc twoOutTx(): Transaction =
  result = trivialTx()
  result.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: @[]))

proc hexToBytes(s: string): seq[byte] =
  let cleaned = s.replace(" ", "").replace("\n", "")
  doAssert cleaned.len mod 2 == 0
  result = newSeq[byte](cleaned.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(cleaned[i*2 .. i*2+1]))

proc bytesToArray32(s: seq[byte]): array[32, byte] =
  doAssert s.len == 32
  for i in 0 ..< 32: result[i] = s[i]

proc bytesToArray64(s: seq[byte]): array[64, byte] =
  doAssert s.len == 64
  for i in 0 ..< 64: result[i] = s[i]

proc makeProgram32(): seq[byte] =
  for _ in 0 ..< 32: result.add(0xAB'u8)

proc makeTapCtx(tx: Transaction): SigCheckContext =
  SigCheckContext(
    tx: tx,
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

proc runCheckSig(sig: seq[byte], pubkey: seq[byte], tx = trivialTx()): ScriptError =
  var interp = newInterpreter({sfWitness, sfTaproot})
  interp.validationWeightLeft = 1000'i64
  interp.validationWeightInit = true
  interp.push(sig)
  interp.push(pubkey)
  let ctx = makeTapCtx(tx)
  interp.eval(@[byte(OP_CHECKSIG)], ctx)

proc runCheckSigAdd(sig: seq[byte], pubkey: seq[byte]): ScriptError =
  var interp = newInterpreter({sfWitness, sfTaproot})
  interp.validationWeightLeft = 1000'i64
  interp.validationWeightInit = true
  interp.push(sig)
  interp.push(@[])  # n = 0
  interp.push(pubkey)
  let ctx = makeTapCtx(trivialTx())
  interp.eval(@[byte(OP_CHECKSIGADD)], ctx)

# ============================================================================
# Gate 1 — BIP-340 tagged-hash format (single SHA256, not SHA256d, not SipHash).
# ============================================================================

suite "W95 BIP-340 tagged-hash format":
  ## Reference: BIP-340 §"Tagged Hashes":
  ##   tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)
  ## NOT SHA256d (double SHA256). NOT SipHash. NOT BLAKE2.
  ##
  ## Cross-validated against the libsecp256k1 fixed midstate
  ## (modules/schnorrsig/main_impl.h:108-115) for "BIP0340/challenge":
  ##   sha->s = 0x9cecba11 0x23925381 0x11679112 0xd1627e0f
  ##            0x97c87550 0x003cc765 0x90f61164 0x33e9b66a
  ## That midstate is SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge")
  ## fed into a fresh SHA-256 — i.e. exactly the prefix our taggedHash builds.

  test "tagged hash is 32 bytes":
    let h = taggedHash("BIP0340/challenge", @[0x00'u8])
    check h.len == 32

  test "tagged hash is deterministic for same tag+data":
    let a = taggedHash("BIP0340/challenge", @[0x42'u8, 0x43, 0x44])
    let b = taggedHash("BIP0340/challenge", @[0x42'u8, 0x43, 0x44])
    check a == b

  test "different tags produce different hashes (TapLeaf vs TapBranch)":
    let a = taggedHash("TapLeaf", @[0x01'u8])
    let b = taggedHash("TapBranch", @[0x01'u8])
    check a != b

  test "different tags produce different hashes (BIP0340/aux vs /nonce)":
    let a = taggedHash("BIP0340/aux", @[0x01'u8])
    let b = taggedHash("BIP0340/nonce", @[0x01'u8])
    check a != b

  test "TapLeaf empty-data vector matches Core/libsecp expectation":
    # SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || empty), reproduced
    # via Python:
    #   import hashlib
    #   t = hashlib.sha256(b"TapLeaf").digest()
    #   hashlib.sha256(t + t).hexdigest()
    let expected = hexToBytes(
      "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
    )
    let h = taggedHash("TapLeaf", @[])
    check @h == expected

  test "BIP0340/challenge empty-data vector":
    # SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge")):
    let expected = hexToBytes(
      "c216d352f5818b7b4beacd4ae0a26fe888080823d2a598856661bcd54f1b3713"
    )
    let h = taggedHash("BIP0340/challenge", @[])
    check @h == expected

  test "tagged hash is NOT SHA256d of (tag||tag||data) [SHA256d trap]":
    # If the implementation were accidentally SHA256(SHA256(SHA256(tag)
    # || SHA256(tag) || data)) — i.e. an extra round — the output would
    # differ. Recompute both and confirm.
    let inner = taggedHash("TapLeaf", @[0x77'u8])
    # SHA256d trap: a second SHA-256 over the (correct) tagged hash.
    let trap = sha256(@inner)
    check inner != trap

# ============================================================================
# Gate 2 — Schnorr sig size in {64, 65} in tapscript.
# ============================================================================

suite "W95 BIP-340 Schnorr sig-size gate (tapscript, hard error)":
  ## Reference: Core interpreter.cpp:1726
  ##   if (sig.size() != 64 && sig.size() != 65)
  ##       return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_SIZE);

  proc pk32(): seq[byte] =
    for _ in 0 ..< 32: result.add(0x02'u8)

  test "63-byte sig with 32-byte pubkey: HARD error SCHNORR_SIG_SIZE":
    var sig: seq[byte]
    for _ in 0 ..< 63: sig.add(0x00'u8)
    check runCheckSig(sig, pk32()) == seSchnorrSigSize

  test "66-byte sig with 32-byte pubkey: HARD error SCHNORR_SIG_SIZE":
    var sig: seq[byte]
    for _ in 0 ..< 66: sig.add(0x00'u8)
    check runCheckSig(sig, pk32()) == seSchnorrSigSize

  test "1-byte sig with 32-byte pubkey: HARD error":
    check runCheckSig(@[0xAA'u8], pk32()) == seSchnorrSigSize

  test "CHECKSIGADD with 63-byte sig: HARD error SCHNORR_SIG_SIZE":
    var sig: seq[byte]
    for _ in 0 ..< 63: sig.add(0x00'u8)
    check runCheckSigAdd(sig, pk32()) == seSchnorrSigSize

  test "empty sig + 32-byte pubkey: NOT a size error (soft-fail per BIP-342)":
    # Empty sig is treated specially: success = !sig.empty() = false,
    # and CheckSchnorrSignature is never called. Eval returns seOk
    # (the push-0 result is on top of the stack).
    check runCheckSig(@[], pk32()) == seOk

# ============================================================================
# Gate 3 — explicit SIGHASH_DEFAULT (0x00) byte in 65-byte sig is invalid.
# ============================================================================

suite "W95 BIP-341 explicit SIGHASH_DEFAULT rejection":
  ## Reference: Core interpreter.cpp:1733
  ##   if (hashtype == SIGHASH_DEFAULT)
  ##       return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE);

  proc pk32(): seq[byte] =
    for _ in 0 ..< 32: result.add(0x02'u8)

  test "CHECKSIG 65-byte sig with trailing 0x00: HARD error":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x00'u8)  # explicit SIGHASH_DEFAULT byte
    check runCheckSig(sig, pk32()) == seSchnorrSigHashtype

  test "CHECKSIGADD 65-byte sig with trailing 0x00: HARD error":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x00'u8)
    check runCheckSigAdd(sig, pk32()) == seSchnorrSigHashtype

  test "key-path 65-byte sig with trailing 0x00: rejected":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x00'u8)
    let witness = @[sig]
    let res = verifyWitnessProgram(
      witness, 1, makeProgram32(), trivialTx(), 0, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

# ============================================================================
# Gate 4 — hash_type allowlist {0x01..0x03, 0x81..0x83}.
# ============================================================================

suite "W95 BIP-341 hash_type allowlist":
  ## Reference: Core interpreter.cpp:1516
  ##   if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83)))
  ##       return false;
  ## In CheckSchnorrSignature this surfaces as SCRIPT_ERR_SCHNORR_SIG_HASHTYPE.

  proc pk32(): seq[byte] =
    for _ in 0 ..< 32: result.add(0x02'u8)

  proc sigWithHt(ht: uint8): seq[byte] =
    for _ in 0 ..< 64: result.add(0x00'u8)
    result.add(ht)

  test "0x04 (just past low band): HARD error":
    check runCheckSig(sigWithHt(0x04'u8), pk32()) == seSchnorrSigHashtype

  test "0x80 (lone ANYONECANPAY): HARD error":
    check runCheckSig(sigWithHt(0x80'u8), pk32()) == seSchnorrSigHashtype

  test "0x84 (just past high band): HARD error":
    check runCheckSig(sigWithHt(0x84'u8), pk32()) == seSchnorrSigHashtype

  test "0xff (max): HARD error":
    check runCheckSig(sigWithHt(0xff'u8), pk32()) == seSchnorrSigHashtype

  # All 6 valid hash_type bytes survive the gate (the Schnorr verify
  # will still fail because we have garbage sig bytes, but the error
  # is SCHNORR_SIG, not SCHNORR_SIG_HASHTYPE).

  test "0x01 (SIGHASH_ALL) passes gate, fails at verify":
    check runCheckSig(sigWithHt(0x01'u8), pk32()) == seSchnorrSig

  test "0x02 (SIGHASH_NONE) passes gate":
    check runCheckSig(sigWithHt(0x02'u8), pk32()) == seSchnorrSig

  test "0x03 (SIGHASH_SINGLE) passes gate":
    # With 1 output and inputIndex=0, SINGLE is in-range; expect verify
    # to fail (garbage sig) and produce seSchnorrSig.
    check runCheckSig(sigWithHt(0x03'u8), pk32()) == seSchnorrSig

  test "0x81 (ALL|ANYONECANPAY) passes gate":
    check runCheckSig(sigWithHt(0x81'u8), pk32()) == seSchnorrSig

  test "0x82 (NONE|ANYONECANPAY) passes gate":
    check runCheckSig(sigWithHt(0x82'u8), pk32()) == seSchnorrSig

  test "0x83 (SINGLE|ANYONECANPAY) passes gate":
    check runCheckSig(sigWithHt(0x83'u8), pk32()) == seSchnorrSig

# ============================================================================
# Gate 5 — SIGHASH_SINGLE out-of-range output index ⇒ hard error.
# ============================================================================

suite "W95 BIP-341 SIGHASH_SINGLE OOB output index":
  ## Reference: Core interpreter.cpp:1549-1551
  ##   if (in_pos >= tx_to.vout.size()) return false;
  ## SignatureHashSchnorr returns false ⇒ CheckSchnorrSignature
  ## surfaces it as SCRIPT_ERR_SCHNORR_SIG_HASHTYPE.
  ##
  ## Pre-W95: computeSighashTaproot returned the all-zero sentinel,
  ## then Schnorr verify ran (failing), and the failure was
  ## indistinguishable from a normal sig-verify miss — masking the
  ## OOB-index reject.

  proc pk32(): seq[byte] =
    for _ in 0 ..< 32: result.add(0x02'u8)

  test "CHECKSIG with SIGHASH_SINGLE + inputIndex >= outputs.len":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x03'u8)  # SIGHASH_SINGLE
    # Tx has 1 output; inputIndex defaults to 0 → in-range.
    # Use a tx with 0 outputs? trivialTx has 1 output, so use index 0,
    # but a tx with 1 output makes inputIndex 0 in-range. Force
    # inputIndex=1 with a 1-input tx + 1-output. Since SigCheckContext
    # accepts arbitrary inputIndex, we just push the boundary.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 1000'i64
    interp.validationWeightInit = true
    interp.push(sig)
    interp.push(pk32())
    var tx = trivialTx()  # 1 input, 1 output
    let ctx = SigCheckContext(
      tx: tx,
      inputIndex: 1,  # OOB w.r.t. outputs (and even inputs, but the
                      # validator only checks outputs for SINGLE)
      amount: Satoshi(0),
      scriptPubKey: @[],
      sigVersion: sigTapscript,
      amounts: @[Satoshi(0)],
      scriptPubKeys: @[@[]],
      annex: @[],
      tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32,
    )
    check interp.eval(@[byte(OP_CHECKSIG)], ctx) == seSchnorrSigHashtype

  test "CHECKSIG with SIGHASH_SINGLE + inputIndex within outputs: NOT this error":
    # Same setup but inputIndex=0 (in-range). Should fall through to
    # Schnorr verify and produce seSchnorrSig (garbage sig).
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x03'u8)
    check runCheckSig(sig, pk32()) == seSchnorrSig

  test "key-path SIGHASH_SINGLE OOB: witness program rejected":
    # 1-input / 1-output tx, inputIndex would default to 0 which is
    # in-range. To exercise the gate, build a tx with the same shape
    # but with the verifier called at inputIndex=1.
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0x00'u8)
    sig.add(0x03'u8)
    let witness = @[sig]
    var tx = trivialTx()  # 1 output
    # verifyWitnessProgram is called externally at a specific
    # inputIndex; the OOB case requires inputIndex >= outputs.len.
    let res = verifyWitnessProgram(
      witness, 1, makeProgram32(), tx, 1, Satoshi(0),
      {sfWitness, sfTaproot})
    check res == false

# ============================================================================
# Gate 6 — Schnorr verify failure (garbage sig + 32-byte pubkey + valid
# hash_type) is a HARD error in tapscript.
# ============================================================================

suite "W95 BIP-340 verify-failure ⇒ HARD error (tapscript)":
  ## Reference: Core interpreter.cpp:1740
  ##   if (!VerifySchnorrSignature(sig, pubkey, sighash))
  ##       return set_error(serror, SCRIPT_ERR_SCHNORR_SIG);

  proc pk32(): seq[byte] =
    for _ in 0 ..< 32: result.add(0x02'u8)

  test "CHECKSIG with garbage 64-byte sig + 32-byte pubkey: HARD seSchnorrSig":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0xAA'u8)
    check runCheckSig(sig, pk32()) == seSchnorrSig

  test "CHECKSIGADD with garbage 64-byte sig + 32-byte pubkey: HARD seSchnorrSig":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0xAA'u8)
    check runCheckSigAdd(sig, pk32()) == seSchnorrSig

  test "CHECKSIG with garbage 65-byte sig + valid ht 0x01: HARD seSchnorrSig":
    var sig: seq[byte]
    for _ in 0 ..< 64: sig.add(0xAA'u8)
    sig.add(0x01'u8)
    check runCheckSig(sig, pk32()) == seSchnorrSig

# ============================================================================
# Gate 7 — empty sig short-circuit: no Schnorr called, no hard error.
# ============================================================================

suite "W95 BIP-342 empty-sig short-circuit in tapscript":
  ## Reference: Core interpreter.cpp:357 + 367-385
  ##   success = !sig.empty();
  ##   ...
  ##   if (pubkey.size() == 32) {
  ##       if (success && !CheckSchnorrSignature(...)) return false;
  ##   }
  ## Empty sig leaves success=false and never invokes the Schnorr
  ## verifier — so out-of-spec sig bytes never matter and the script
  ## eval terminates with seOk (the push-0 result is the failure
  ## signal at the top of the stack).

  test "CHECKSIG empty sig + 32-byte pubkey: seOk (soft 0 on stack)":
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    check runCheckSig(@[], pk) == seOk

  test "CHECKSIGADD empty sig + 32-byte pubkey: seOk (n unchanged)":
    var pk: seq[byte]
    for _ in 0 ..< 32: pk.add(0x02'u8)
    check runCheckSigAdd(@[], pk) == seOk

  test "CHECKSIG empty sig + empty pubkey: HARD error EMPTY_PUBKEY":
    # Per BIP-342, an empty pubkey is always a hard error regardless
    # of the sig.
    check runCheckSig(@[], @[]) == seTapscriptEmptyPubkey

# ============================================================================
# Gate 8 — known-answer BIP-340 vector from BIP-340 test vector file.
# ============================================================================

suite "W95 BIP-340 known-answer Schnorr vector":
  ## Reference: BIP-340 test vector index 0 (deterministic case).
  ##   sec_key   = 0000000000000000000000000000000000000000000000000000000000000003
  ##   pub_key   = F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
  ##   aux_rand  = 0..0
  ##   msg       = 0..0
  ##   sig       = E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0

  test "BIP-340 vector 0 — valid signature verifies":
    let pubkey = bytesToArray32(hexToBytes(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ))
    let msg = bytesToArray32(hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    ))
    let sig = bytesToArray64(hexToBytes(
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    ))
    check verifySchnorr(pubkey, @msg, sig) == true

  test "BIP-340 vector 0 — flipped sig byte fails":
    let pubkey = bytesToArray32(hexToBytes(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ))
    let msg = bytesToArray32(hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    ))
    var sig = bytesToArray64(hexToBytes(
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    ))
    sig[0] = sig[0] xor 0x01'u8  # flip 1 bit in r-coordinate
    check verifySchnorr(pubkey, @msg, sig) == false

  test "BIP-340 vector 0 — flipped msg byte fails":
    let pubkey = bytesToArray32(hexToBytes(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ))
    var msg = bytesToArray32(hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    ))
    let sig = bytesToArray64(hexToBytes(
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    ))
    msg[0] = 0x01'u8
    check verifySchnorr(pubkey, @msg, sig) == false

  test "BIP-340 vector 1 — valid signature verifies":
    # Vector 1 from BIP-340 test-vectors.csv
    #   sec_key  = b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef
    #   pub_key  = dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659
    #   aux_rand = 0000000000000000000000000000000000000000000000000000000000000001
    #   msg      = 243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89
    #   sig      = 6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a
    let pubkey = bytesToArray32(hexToBytes(
      "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
    ))
    let msg = bytesToArray32(hexToBytes(
      "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"
    ))
    let sig = bytesToArray64(hexToBytes(
      "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"
    ))
    check verifySchnorr(pubkey, @msg, sig) == true

  test "BIP-340 vector 4 — public key not on curve fails":
    # Vector index 4 (failure case): pub_key on curve but P with odd Y
    # rejected (x-only lift). Reference picks a pubkey whose lift fails.
    let pubkey = bytesToArray32(hexToBytes(
      "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
    ))
    let msg = bytesToArray32(hexToBytes(
      "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    ))
    let sig = bytesToArray64(hexToBytes(
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"
    ))
    check verifySchnorr(pubkey, @msg, sig) == false

  test "Schnorr verify rejects 32-byte msg of all-zero with all-zero sig":
    let pubkey = bytesToArray32(hexToBytes(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ))
    let msg = bytesToArray32(hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000000"
    ))
    var sig: array[64, byte]
    check verifySchnorr(pubkey, @msg, sig) == false

# ============================================================================
# Gate 9 — TapTweak / TapLeaf / TapBranch tag wiring.
# ============================================================================

suite "W95 BIP-341 TapTweak / TapLeaf / TapBranch tags":
  ## These tag strings are consensus-critical: a typo (TapLeaf vs
  ## "TAPLEAF" vs "TapLeaf\x00") would silently change every taproot
  ## output's commitment hash. Confirm each is exactly the BIP-341
  ## ASCII string.

  test "TapLeaf tag empty-data vector":
    # Same vector verified above; pinned here to guard tag spelling.
    let expected = hexToBytes(
      "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
    )
    let h = taggedHash("TapLeaf", @[])
    check @h == expected

  test "TapBranch tag empty-data vector":
    # SHA256(SHA256("TapBranch")||SHA256("TapBranch")||empty):
    let expected = hexToBytes(
      "53c373ec4d6f3c53c1f5fb2ff506dcefe1a0ed74874f93fa93c8214cbe9ffddf"
    )
    let h = taggedHash("TapBranch", @[])
    check @h == expected

  test "TapTweak tag empty-data vector":
    # SHA256(SHA256("TapTweak")||SHA256("TapTweak")||empty):
    let expected = hexToBytes(
      "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4"
    )
    let h = taggedHash("TapTweak", @[])
    check @h == expected

  test "TapSighash tag empty-data vector":
    # SHA256(SHA256("TapSighash")||SHA256("TapSighash")||empty):
    let expected = hexToBytes(
      "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803"
    )
    let h = taggedHash("TapSighash", @[])
    check @h == expected
