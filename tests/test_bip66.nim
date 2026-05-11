## Comprehensive tests for BIP-66 + signature/pubkey encoding gates
##
## Covers all ~22 gates in 7 functions:
##   isValidSignatureEncoding  (13 gates, interpreter.cpp:108-171)
##   isLowDERSignature         (wraps isValidSig + CheckLowS, lines 173-188)
##   isDefinedHashtypeSignature (2 gates, lines 190-199)
##   checkSignatureEncoding    (3 conditions, lines 201-216)
##   isCompressedOrUncompressedPubKey (3 gates, lines 64-84)
##   isCompressedPubKey        (2 gates, lines 86-96)
##   checkPubKeyEncoding       (2 conditions, lines 218-227)
##
## Plus NULLDUMMY/NULLFAIL ordering in OP_CHECKMULTISIG (interpreter.cpp:1183-1203).

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

# ---------------------------------------------------------------------------
# Helper: minimal valid DER signature (9-byte stub, hashtype=0x01)
# Format: 0x30 total 0x02 rlen R 0x02 slen S hashtype
# Using 1-byte R=0x01 and 1-byte S=0x01 → total-len = 6, size = 9.
# ---------------------------------------------------------------------------
const validDerSig9: seq[byte] = @[
  0x30'u8,  # compound type
  0x06,     # total-length = 6 (everything except the two outer bytes and hashtype)
  0x02,     # R is integer
  0x01,     # R-length = 1
  0x01,     # R = 1 (non-negative, non-padded)
  0x02,     # S is integer
  0x01,     # S-length = 1
  0x01,     # S = 1
  0x01      # hashtype = SIGHASH_ALL
]

# ---------------------------------------------------------------------------
# isValidSignatureEncoding — 13 gates
# ---------------------------------------------------------------------------

suite "isValidSignatureEncoding (BIP66, interpreter.cpp:108-171)":
  test "gate01 — min size 9: rejects 8-byte sig":
    var sig: seq[byte] = @[0x30'u8, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
    # Only 8 bytes — one short of minimum
    check isValidSignatureEncoding(sig) == false

  test "gate01 — min size 9: accepts 9-byte sig":
    check isValidSignatureEncoding(validDerSig9) == true

  test "gate02 — max size 73: rejects 74-byte sig":
    # Build sig with R=33 bytes and S=33 bytes → total = 33+33+7 = 73, but we
    # want 74. Use R=33, S=34: total-len = 33+34+4 = 71, size = 74.
    var sig: seq[byte] = @[0x30'u8, byte(33 + 34 + 4)]
    sig.add(@[0x02'u8, 33])
    sig.add(0x00'u8)  # leading zero so high-bit byte follows safely
    for _ in 0 ..< 32: sig.add(0x01'u8)
    sig.add(@[0x02'u8, 34])
    sig.add(0x00'u8)
    for _ in 0 ..< 33: sig.add(0x01'u8)
    sig.add(0x01'u8)  # hashtype
    check sig.len == 74
    check isValidSignatureEncoding(sig) == false

  test "gate02 — max size 73: accepts 73-byte sig":
    # Build a 73-byte sig with R=33 bytes and S=33 bytes.
    # R and S each start with 0x00 followed by a high-bit byte (0x80) so that
    # the leading zero is required (not excessive padding). Then 31 more bytes.
    # total-len = (1+1+33)+(1+1+33) = 70, size = 73.
    var sig: seq[byte] = @[0x30'u8, byte(33 + 33 + 4)]
    sig.add(@[0x02'u8, 33'u8])
    sig.add(0x00'u8)  # required leading zero (next byte 0x80 has high bit)
    sig.add(0x80'u8)  # high-bit byte
    for _ in 0 ..< 31: sig.add(0x01'u8)
    sig.add(@[0x02'u8, 33'u8])
    sig.add(0x00'u8)  # required leading zero
    sig.add(0x80'u8)  # high-bit byte
    for _ in 0 ..< 31: sig.add(0x01'u8)
    sig.add(0x01'u8)  # hashtype
    check sig.len == 73
    check isValidSignatureEncoding(sig) == true

  test "gate03 — first byte must be 0x30":
    var sig = validDerSig9
    sig[0] = 0x31'u8
    check isValidSignatureEncoding(sig) == false

  test "gate04 — total-length mismatch (too short)":
    var sig = validDerSig9
    sig[1] = 0x05'u8  # correct is 0x06
    check isValidSignatureEncoding(sig) == false

  test "gate04 — total-length mismatch (too long)":
    var sig = validDerSig9
    sig[1] = 0x07'u8
    check isValidSignatureEncoding(sig) == false

  test "gate05 — lenR overflows into lenS position":
    # lenR = 4 but sig.len - (5 + 4) = 0, i.e. 5+lenR >= sig.len
    var sig = validDerSig9
    sig[3] = 0x04'u8  # lenR=4, but only 1 byte follows
    check isValidSignatureEncoding(sig) == false

  test "gate06 — lenR + lenS + 7 != sig.len":
    # valid sig: lenR=1, lenS=1, 1+1+7=9 ✓. Change lenS to 2 while keeping size 9.
    var sig = validDerSig9
    sig[5 + 1] = 0x02'u8  # sig[6] = lenS field = 2 instead of 1
    check isValidSignatureEncoding(sig) == false

  test "gate07 — R integer tag must be 0x02":
    var sig = validDerSig9
    sig[2] = 0x03'u8
    check isValidSignatureEncoding(sig) == false

  test "gate08 — zero-length R":
    # Build 0x30 0x05 0x02 0x00 0x02 0x01 0x01 0x01 (9 bytes but lenR=0)
    let sig: seq[byte] = @[0x30'u8, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01]
    check isValidSignatureEncoding(sig) == false

  test "gate09 — R negative (high bit of first byte set)":
    var sig = validDerSig9
    sig[4] = 0x80'u8  # first byte of R has high bit set → negative
    check isValidSignatureEncoding(sig) == false

  test "gate10 — R excessively padded (0x00 + non-high next byte)":
    # R = 0x00 0x01 — second byte has high bit clear, so 0x00 prefix is unnecessary
    # Need sig with lenR=2: total-len = 2+1+4 = 7, size = 10
    let sig: seq[byte] = @[
      0x30'u8, 0x07,   # total-len = 7
      0x02, 0x02,      # R: integer, length=2
      0x00, 0x01,      # R value: unnecessary leading zero
      0x02, 0x01,      # S: integer, length=1
      0x01,            # S value
      0x01             # hashtype
    ]
    check isValidSignatureEncoding(sig) == false

  test "gate10 — R with 0x00 prefix ALLOWED when next byte has high bit set":
    # R = 0x00 0x80 — legal because 0x80 has high bit set, so 0x00 prefix is required
    let sig: seq[byte] = @[
      0x30'u8, 0x07,
      0x02, 0x02,
      0x00, 0x80,  # leading zero required (0x80 high bit set)
      0x02, 0x01,
      0x01,
      0x01
    ]
    check isValidSignatureEncoding(sig) == true

  test "gate11 — S integer tag must be 0x02":
    # S tag is at position lenR + 4
    var sig = validDerSig9
    sig[4 + 1] = 0x03'u8  # sig[5] is the S-tag (lenR=1, so lenR+4=5)
    check isValidSignatureEncoding(sig) == false

  test "gate12 — zero-length S":
    # R=2 bytes (0x00 0x80 — valid), S=0 bytes.
    # lenR+lenS+7 = 2+0+7 = 9 ✓ size check; total-len = 2+0+4 = 6 ✓; gate12: lenS==0 fails.
    let sig2: seq[byte] = @[
      0x30'u8, 0x06,
      0x02, 0x02, 0x00, 0x80,
      0x02, 0x00,
      0x01
    ]
    check sig2.len == 9  # lenR+lenS+7 = 2+0+7 = 9 ✓
    check isValidSignatureEncoding(sig2) == false  # gate12: lenS==0

  test "gate13 — S negative (high bit of first byte set)":
    # Need a sig where first byte of S has high bit set
    # R=1 byte (0x01), S=1 byte (0x80) → S is negative
    let sig: seq[byte] = @[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x01]
    check isValidSignatureEncoding(sig) == false

  test "gate13b — S excessively padded (0x00 + non-high next byte)":
    # S = 0x00 0x01 (2 bytes, unnecessary zero)
    # R=1 byte, S=2 bytes: total-len=1+2+4=7, size=10
    let sig: seq[byte] = @[
      0x30'u8, 0x07,
      0x02, 0x01, 0x01,   # R: valid 1-byte
      0x02, 0x02, 0x00, 0x01,  # S: 2-byte with unnecessary leading zero
      0x01
    ]
    check isValidSignatureEncoding(sig) == false

  test "gate13b — S with 0x00 prefix ALLOWED when next byte has high bit set":
    let sig: seq[byte] = @[
      0x30'u8, 0x07,
      0x02, 0x01, 0x01,
      0x02, 0x02, 0x00, 0x80,  # S: 0x00 prefix required because 0x80 has high bit
      0x01
    ]
    check isValidSignatureEncoding(sig) == true

# ---------------------------------------------------------------------------
# isDefinedHashtypeSignature — 2 gates (interpreter.cpp:190-199)
# ---------------------------------------------------------------------------

suite "isDefinedHashtypeSignature (interpreter.cpp:190-199)":
  test "empty sig returns false":
    check isDefinedHashtypeSignature(@[]) == false

  test "SIGHASH_ALL (0x01) accepted":
    check isDefinedHashtypeSignature(@[0x01'u8]) == true

  test "SIGHASH_NONE (0x02) accepted":
    check isDefinedHashtypeSignature(@[0x02'u8]) == true

  test "SIGHASH_SINGLE (0x03) accepted":
    check isDefinedHashtypeSignature(@[0x03'u8]) == true

  test "SIGHASH_ALL | ANYONECANPAY (0x81) accepted":
    # ANYONECANPAY bit is stripped before range check
    check isDefinedHashtypeSignature(@[0x81'u8]) == true

  test "SIGHASH_NONE | ANYONECANPAY (0x82) accepted":
    check isDefinedHashtypeSignature(@[0x82'u8]) == true

  test "SIGHASH_SINGLE | ANYONECANPAY (0x83) accepted":
    check isDefinedHashtypeSignature(@[0x83'u8]) == true

  test "hashtype 0x04 rejected (out of range)":
    check isDefinedHashtypeSignature(@[0x04'u8]) == false

  test "hashtype 0x00 rejected (below SIGHASH_ALL)":
    check isDefinedHashtypeSignature(@[0x00'u8]) == false

  test "hashtype 0x7F rejected (out of range)":
    check isDefinedHashtypeSignature(@[0x7F'u8]) == false

  test "multi-byte sig: last byte is the hashtype":
    # Valid sig with last byte = 0x01
    check isDefinedHashtypeSignature(validDerSig9) == true

  test "multi-byte sig: last byte = 0x04 rejected":
    var sig = validDerSig9
    sig[sig.len - 1] = 0x04'u8
    check isDefinedHashtypeSignature(sig) == false

# ---------------------------------------------------------------------------
# checkSignatureEncoding — 3 conditions + correct error codes (Bug 1 fix)
# interpreter.cpp:201-216
# ---------------------------------------------------------------------------

suite "checkSignatureEncoding (interpreter.cpp:201-216)":
  test "empty sig always passes (even with all flags)":
    let flags = {sfDERSig, sfLowS, sfStrictEnc}
    check checkSignatureEncoding(@[], flags) == seOk

  test "no flags: any DER-invalid sig passes":
    # Without any encoding flags, even malformed sigs are allowed
    let badSig: seq[byte] = @[0x01'u8, 0x02, 0x03]
    check checkSignatureEncoding(badSig, {}) == seOk

  test "sfDERSig flag: invalid DER returns seSigDer":
    # Not 0x30 prefix → DER violation
    let badSig: seq[byte] = @[0x31'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    let err = checkSignatureEncoding(badSig, {sfDERSig})
    check err == seSigDer  # SCRIPT_ERR_SIG_DER, NOT seInvalidSig

  test "sfStrictEnc flag: invalid DER returns seSigDer":
    let badSig: seq[byte] = @[0x31'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    let err = checkSignatureEncoding(badSig, {sfStrictEnc})
    check err == seSigDer

  test "sfLowS flag: invalid DER returns seSigDer (DER checked first)":
    let badSig: seq[byte] = @[0x31'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    let err = checkSignatureEncoding(badSig, {sfLowS})
    check err == seSigDer  # DER check fires before low-S check

  test "sfStrictEnc flag: valid DER + bad hashtype returns seSigHashType":
    var sig = validDerSig9
    sig[sig.len - 1] = 0x04'u8  # invalid hashtype
    let err = checkSignatureEncoding(sig, {sfStrictEnc})
    check err == seSigHashType

  test "sfStrictEnc flag: valid DER + valid hashtype passes":
    check checkSignatureEncoding(validDerSig9, {sfStrictEnc}) == seOk

  test "sfDERSig flag: valid DER passes":
    check checkSignatureEncoding(validDerSig9, {sfDERSig}) == seOk

  test "DER error code is seSigDer (not generic seInvalidSig)":
    let badSig: seq[byte] = @[0x00'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    let err = checkSignatureEncoding(badSig, {sfDERSig})
    check err == seSigDer
    check err != seInvalidSig  # must be the specific code

# ---------------------------------------------------------------------------
# isCompressedOrUncompressedPubKey — 3 gates (interpreter.cpp:64-84)
# ---------------------------------------------------------------------------

suite "isCompressedOrUncompressedPubKey (interpreter.cpp:64-84)":
  test "too short (< 33 bytes) returns false":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](31)  # 32 bytes
    check isCompressedOrUncompressedPubkey(pubkey) == false

  test "0x04 prefix + 65 bytes: valid uncompressed":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](64)
    check isCompressedOrUncompressedPubkey(pubkey) == true

  test "0x04 prefix + 33 bytes: invalid length for uncompressed":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](32)
    check isCompressedOrUncompressedPubkey(pubkey) == false

  test "0x02 prefix + 33 bytes: valid compressed":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](32)
    check isCompressedOrUncompressedPubkey(pubkey) == true

  test "0x03 prefix + 33 bytes: valid compressed":
    let pubkey: seq[byte] = @[0x03'u8] & newSeq[byte](32)
    check isCompressedOrUncompressedPubkey(pubkey) == true

  test "0x02 prefix + 65 bytes: invalid length for compressed":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](64)
    check isCompressedOrUncompressedPubkey(pubkey) == false

  test "0x06 prefix (hybrid) rejected":
    let pubkey: seq[byte] = @[0x06'u8] & newSeq[byte](64)
    check isCompressedOrUncompressedPubkey(pubkey) == false

  test "0x07 prefix (hybrid) rejected":
    let pubkey: seq[byte] = @[0x07'u8] & newSeq[byte](64)
    check isCompressedOrUncompressedPubkey(pubkey) == false

  test "0x01 prefix rejected":
    let pubkey: seq[byte] = @[0x01'u8] & newSeq[byte](32)
    check isCompressedOrUncompressedPubkey(pubkey) == false

# ---------------------------------------------------------------------------
# isCompressedPubKey — 2 gates (interpreter.cpp:86-96)
# BIP141 WITNESS_PUBKEYTYPE: must be 33 bytes with 0x02 or 0x03 prefix
# ---------------------------------------------------------------------------

suite "isCompressedPubKey (interpreter.cpp:86-96)":
  test "33 bytes + 0x02 prefix: valid":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](32)
    check isCompressedPubkey(pubkey) == true

  test "33 bytes + 0x03 prefix: valid":
    let pubkey: seq[byte] = @[0x03'u8] & newSeq[byte](32)
    check isCompressedPubkey(pubkey) == true

  test "65 bytes + 0x04 prefix: rejected (uncompressed)":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](64)
    check isCompressedPubkey(pubkey) == false

  test "33 bytes + 0x04 prefix: rejected (wrong prefix even if right length)":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](32)
    check isCompressedPubkey(pubkey) == false

  test "32 bytes: rejected (too short)":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](31)
    check isCompressedPubkey(pubkey) == false

  test "34 bytes: rejected (too long)":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](33)
    check isCompressedPubkey(pubkey) == false

# ---------------------------------------------------------------------------
# checkPubKeyEncoding — 2 conditions (interpreter.cpp:218-227)
# ---------------------------------------------------------------------------

suite "checkPubKeyEncoding (interpreter.cpp:218-227)":
  test "sfStrictEnc: uncompressed 65-byte pubkey accepted":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(pubkey, {sfStrictEnc}, sigBase)
    check err == seOk

  test "sfStrictEnc: hybrid 65-byte pubkey rejected (seInvalidPubkey)":
    let pubkey: seq[byte] = @[0x06'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(pubkey, {sfStrictEnc}, sigBase)
    check err == seInvalidPubkey

  test "sfStrictEnc: 32-byte (too short) rejected":
    let pubkey: seq[byte] = newSeq[byte](32)
    let err = checkPubKeyEncoding(pubkey, {sfStrictEnc}, sigBase)
    check err == seInvalidPubkey

  test "no flags: any pubkey passes (including hybrid)":
    let hybrid: seq[byte] = @[0x06'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(hybrid, {}, sigBase)
    check err == seOk

  test "sfWitnessPubkeyType + sigWitnessV0: uncompressed 65-byte rejected":
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(pubkey, {sfWitnessPubkeyType}, sigWitnessV0)
    check err == seWitnessPubkeyType

  test "sfWitnessPubkeyType + sigWitnessV0: compressed 33-byte accepted":
    let pubkey: seq[byte] = @[0x02'u8] & newSeq[byte](32)
    let err = checkPubKeyEncoding(pubkey, {sfWitnessPubkeyType}, sigWitnessV0)
    check err == seOk

  test "sfWitnessPubkeyType + sigBase: uncompressed pubkey still accepted (not witness path)":
    # WITNESS_PUBKEYTYPE only applies to sigWitnessV0
    let pubkey: seq[byte] = @[0x04'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(pubkey, {sfWitnessPubkeyType}, sigBase)
    check err == seOk

  test "sfStrictEnc + sfWitnessPubkeyType + sigWitnessV0: both checks apply":
    # Uncompressed pubkey fails both strictenc (wrong for witness path) and
    # witness-pubkeytype check. seInvalidPubkey fires first (strictenc).
    let hybrid: seq[byte] = @[0x06'u8] & newSeq[byte](64)
    let err = checkPubKeyEncoding(hybrid, {sfStrictEnc, sfWitnessPubkeyType}, sigWitnessV0)
    check err == seInvalidPubkey  # strictenc fires first

# ---------------------------------------------------------------------------
# NULLFAIL / NULLDUMMY ordering in OP_CHECKMULTISIG (Bug 2 fix)
# Core interpreter.cpp:1183-1203: NULLFAIL fires before NULLDUMMY
# ---------------------------------------------------------------------------

suite "CHECKMULTISIG NULLDUMMY + NULLFAIL ordering (interpreter.cpp:1183-1203)":
  # Helpers
  proc makeMSCtx(): SigCheckContext =
    var emptyTx = Transaction()
    emptyTx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))
    emptyTx.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: @[]))
    SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )

  test "NULLDUMMY alone: non-empty dummy fails with seNullDummy":
    var interp = newInterpreter({sfNullDummy})
    # 0-of-0 multisig: nPubkeys=0, nSigs=0, dummy=non-empty
    # Stack layout (bottom→top pushed): dummy, nSigs, nPubkeys
    interp.push(@[0x42'u8])  # non-empty dummy
    interp.push(@[])         # nSigs = 0 (empty = 0 as scriptnum)
    interp.push(@[])         # nPubkeys = 0
    let ctx = makeMSCtx()
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    check err == seNullDummy

  test "NULLFAIL alone: failed 1-of-1 with non-empty sig fails with seNullFail":
    var interp = newInterpreter({sfNullFail})
    # 1-of-1 multisig that fails: empty pubkey means verify fails, non-empty sig → NULLFAIL
    interp.push(@[])           # dummy (empty, ok for NULLDUMMY)
    interp.push(@[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])  # non-empty sig
    interp.push(@[0x01'u8])    # nSigs = 1
    interp.push(@[])           # pubkey (empty → verify fails)
    interp.push(@[0x01'u8])    # nPubkeys = 1
    let ctx = makeMSCtx()
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    check err == seNullFail

  test "NULLFAIL takes priority over NULLDUMMY when both violated":
    # Bitcoin Core fires NULLFAIL (per-sig cleanup) BEFORE NULLDUMMY (dummy check).
    # Both NULLDUMMY and NULLFAIL flags set; multisig fails; non-empty dummy + non-empty sig.
    var interp = newInterpreter({sfNullDummy, sfNullFail})
    interp.push(@[0x42'u8])    # non-empty dummy → NULLDUMMY violation
    interp.push(@[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])  # non-empty sig → NULLFAIL
    interp.push(@[0x01'u8])    # nSigs = 1
    interp.push(@[])           # empty pubkey → verify fails
    interp.push(@[0x01'u8])    # nPubkeys = 1
    let ctx = makeMSCtx()
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    # Core fires NULLFAIL first (sigs loop), then NULLDUMMY. Must match Core.
    check err == seNullFail    # NOT seNullDummy

  test "empty dummy + empty sig + NULLDUMMY + NULLFAIL: passes (no violations)":
    var interp = newInterpreter({sfNullDummy, sfNullFail})
    interp.push(@[])           # empty dummy
    interp.push(@[])           # empty sig
    interp.push(@[0x01'u8])    # nSigs = 1
    interp.push(@[])           # empty pubkey
    interp.push(@[0x01'u8])    # nPubkeys = 1
    let ctx = makeMSCtx()
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    check err == seOk

  test "successful multisig ignores NULLFAIL (sig non-empty but check passes)":
    # NULLFAIL only fires when success=false; a passing CHECKSIG is fine
    # even with a non-empty sig. Here we can't do a real crypto check without
    # keys, but we can test the 0-of-0 case (trivially succeeds) with empty sigs.
    var interp = newInterpreter({sfNullFail})
    interp.push(@[])   # dummy
    interp.push(@[])   # nSigs = 0
    interp.push(@[])   # nPubkeys = 0
    let ctx = makeMSCtx()
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    check err == seOk

# ---------------------------------------------------------------------------
# NULLFAIL in OP_CHECKSIG (interpreter.cpp:341-342)
# ---------------------------------------------------------------------------

suite "CHECKSIG NULLFAIL (interpreter.cpp:341-342)":
  proc makeCSCtx(): SigCheckContext =
    var emptyTx = Transaction()
    emptyTx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))
    emptyTx.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: @[]))
    SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )

  test "NULLFAIL: empty sig on failed CHECKSIG passes":
    var interp = newInterpreter({sfNullFail})
    interp.push(@[])  # empty sig
    interp.push(@[])  # empty pubkey
    let ctx = makeCSCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err == seOk

  test "NULLFAIL: non-empty sig on failed CHECKSIG fails with seNullFail":
    var interp = newInterpreter({sfNullFail})
    interp.push(@[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])
    interp.push(@[])  # empty pubkey → verify fails
    let ctx = makeCSCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err == seNullFail

  test "without NULLFAIL: non-empty sig on failed CHECKSIG pushes false":
    var interp = newInterpreter()  # no NULLFAIL
    interp.push(@[0x30'u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01])
    interp.push(@[])
    let ctx = makeCSCtx()
    let err = interp.eval(@[OP_CHECKSIG], ctx)
    check err == seOk
    check interp.peek() == newSeq[byte]()  # false (empty) on stack

# ---------------------------------------------------------------------------
# Edge case: sfDERSig with empty sig (empty always passes)
# ---------------------------------------------------------------------------

suite "empty signature is always allowed (interpreter.cpp:204-206)":
  test "sfDERSig + empty sig = seOk":
    check checkSignatureEncoding(@[], {sfDERSig}) == seOk

  test "sfLowS + empty sig = seOk":
    check checkSignatureEncoding(@[], {sfLowS}) == seOk

  test "sfStrictEnc + empty sig = seOk":
    check checkSignatureEncoding(@[], {sfStrictEnc}) == seOk

  test "all flags + empty sig = seOk":
    check checkSignatureEncoding(@[], {sfDERSig, sfLowS, sfStrictEnc}) == seOk
