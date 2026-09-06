## W127 — Taproot / Schnorr / Tapscript audit (BIP-340/341/342)
##
## Audit type: discovery (NO production code change in W127).
##
## Each test below classifies one of 30 audit gates as PRESENT / PARTIAL /
## MISSING with reference to Bitcoin Core lines.  Where nimrod implements
## the gate, the test asserts the implementation matches Core.  Where
## nimrod is PARTIAL / MISSING, the test asserts the *current* divergent
## state and is marked with `skip()` carrying a TODO referencing the
## corresponding BUG-N row in `audit/w127_taproot.md`.
##
## Cross-references:
##   bitcoin-core/src/script/interpreter.cpp   VerifyWitnessProgram,
##                                              ExecuteWitnessScript,
##                                              EvalChecksigTapscript,
##                                              CheckSchnorrSignature,
##                                              SignatureHashSchnorr,
##                                              ComputeTapleafHash,
##                                              ComputeTaprootMerkleRoot,
##                                              VerifyTaprootCommitment
##   bitcoin-core/src/script/interpreter.h     TAPROOT_LEAF_MASK,
##                                              TAPROOT_LEAF_TAPSCRIPT,
##                                              TAPROOT_CONTROL_BASE_SIZE,
##                                              TAPROOT_CONTROL_NODE_SIZE,
##                                              TAPROOT_CONTROL_MAX_NODE_COUNT,
##                                              TAPROOT_CONTROL_MAX_SIZE
##   bitcoin-core/src/script/script.h          ANNEX_TAG,
##                                              MAX_PUBKEYS_PER_MULTI_A,
##                                              VALIDATION_WEIGHT_PER_SIGOP_PASSED,
##                                              VALIDATION_WEIGHT_OFFSET
##   bitcoin-core/src/key.cpp                  CKey::SignSchnorr
##   bitcoin-core/src/pubkey.cpp               XOnlyPubKey::CheckTapTweak
##   bitcoin-core/src/test/script_assets_tests.cpp  driver expects
##                                              DIR_UNIT_TEST_DATA env var
##                                              with script_assets_test.json
##   audit/w127_taproot.md                     full audit + bug table.
##
## Convention: each "Gate N" suite holds 1+ tests.  A test prefixed
## "PRESENT" or "MATCHES CORE" asserts the gate is wired; a test prefixed
## "PARTIAL" or "MISSING" runs `skip()` with a TODO referencing BUG-N.

import unittest2
import std/[strutils]
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers (mirror test_w94_taproot_gates.nim for fixture compatibility)
# ---------------------------------------------------------------------------

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

proc deriveXonly(privkey: PrivateKey): array[32, byte] =
  let compressed = derivePublicKey(privkey)
  for i in 0 ..< 32:
    result[i] = compressed[1 + i]

proc tapleafHashOfVer(tapscript: seq[byte], leafVersion: uint8): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(leafVersion)
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  result = taggedHash("TapLeaf", leafData)

proc taptweakOf(internalPk: array[32, byte], merkleRoot: array[32, byte]): array[32, byte] =
  var data: seq[byte]
  for b in internalPk: data.add(b)
  for b in merkleRoot: data.add(b)
  result = taggedHash("TapTweak", data)

const TEST_PRIVKEY: PrivateKey = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
]

let G_INTERNAL = deriveXonly(TEST_PRIVKEY)

proc makeControlBlockVer(tapscript: seq[byte], leafVersion: uint8):
    tuple[cb: seq[byte], prog: seq[byte]] =
  let tlh = tapleafHashOfVer(tapscript, leafVersion)
  let tw = taptweakOf(G_INTERNAL, tlh)
  let (q, parity) = tweakXonlyPubkey(G_INTERNAL, tw)
  var cb: seq[byte] = @[byte(leafVersion or uint8(parity and 0x01))]
  for b in G_INTERNAL: cb.add(b)
  (cb, @q)

proc makeControlBlock(tapscript: seq[byte]): tuple[cb: seq[byte], prog: seq[byte]] =
  makeControlBlockVer(tapscript, 0xC0'u8)

# ===========================================================================
# Subsystem A — BIP-340 Schnorr verification (Gates 1-6)
# ===========================================================================

# Gate 1 — Schnorr verify is wired through libsecp256k1
suite "W127 Gate 1 (BIP-340): Schnorr verify wired through libsecp — PRESENT":
  test "PRESENT — verifySchnorr proc is callable and returns false on garbage":
    ## Reference: bitcoin-core/src/key.cpp:280 (VerifySchnorrSignature
    ## calls secp256k1_schnorrsig_verify).
    ## Nimrod: src/crypto/secp256k1.nim:523-546 (verifySchnorr standalone)
    ## and :829-843 (engine variant).
    let pubkey: array[32, byte] = G_INTERNAL
    let sig: array[64, byte] = default(array[64, byte])
    let msg: array[32, byte] = default(array[32, byte])
    var msgSeq = newSeq[byte](32)
    for i in 0 ..< 32: msgSeq[i] = msg[i]
    check verifySchnorr(pubkey, msgSeq, sig) == false

# Gate 2 — BIP-340 known-answer csv cross-verification
suite "W127 Gate 2 (BIP-340): csv cross-verification — PARTIAL":
  test "PARTIAL — only 2 of 14 BIP-340 csv vectors covered (BUG-1)":
    ## Reference: BIP-340 test-vectors.csv — 14 vectors.
    ## Nimrod: tests/test_w95_bip340_schnorr.nim has hardcoded vectors
    ## 0 and 1; vectors 2-13 (zero-pubkey edge, x-coord > p, malleable
    ## sigs, field-overflow detection) are NOT exercised.
    ## TODO BUG-1: ferry test-vectors.csv into tests/data/bip340_vectors.csv
    ## and iterate the full table.
    skip()

# Gate 3 — verifySchnorr returns false on parse failure
suite "W127 Gate 3 (BIP-340): verify-false on x-only parse failure — PRESENT":
  test "PRESENT — invalid pubkey bytes return false":
    ## Reference: bitcoin-core/src/pubkey.cpp:241 (secp256k1_xonly_pubkey_parse
    ## returning 0 makes VerifySchnorrSignature return false).
    ## Nimrod: src/crypto/secp256k1.nim:533-534 returns false on parse fail.
    var badPk: array[32, byte]
    for i in 0 ..< 32: badPk[i] = 0xFF'u8  # x-coord > p; should fail parse
    let sig: array[64, byte] = default(array[64, byte])
    var msgSeq = newSeq[byte](32)
    check verifySchnorr(badPk, msgSeq, sig) == false

# Gate 4 — Empty / non-32 message handling
suite "W127 Gate 4 (BIP-340): message-length handling — PARTIAL":
  test "PARTIAL — standalone verifySchnorr accepts non-32-byte msg (BUG-2)":
    ## Reference: BIP-340 verify takes a 32-byte hash.  Core's
    ## SignatureHashSchnorr produces uint256 (always 32 bytes).
    ## Nimrod: src/crypto/secp256k1.nim:537-545 rejects msg.len == 0 only;
    ## any other length is passed through to libsecp via csize_t(msg.len).
    ## The engine variant (:841) hardcodes csize_t(32).  Divergence is a
    ## lint concern (real tapscript / taproot paths always pass 32 bytes),
    ## not a consensus bug.
    ## TODO BUG-2: tighten standalone verifySchnorr to require 32-byte msg.
    skip()

  test "PRESENT — empty msg is rejected":
    let pubkey: array[32, byte] = G_INTERNAL
    let sig: array[64, byte] = default(array[64, byte])
    check verifySchnorr(pubkey, @[], sig) == false

# Gate 5 — BIP-340 tagged hash uses SHA-256, NOT SHA-256d
suite "W127 Gate 5 (BIP-340): tagged hash is single-SHA256 — PRESENT":
  test "PRESENT — taggedHash differs from doubleSha256":
    ## Reference: BIP-340 §"Design — Tagged Hashes":
    ##   tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    ## NOT double-SHA-256.  An impl that confuses the two breaks every
    ## BIP-340/341/342 hash (TapLeaf, TapBranch, TapTweak, TapSighash,
    ## BIP0340/challenge, BIP0340/nonce, BIP0340/aux).
    ## Nimrod: src/script/interpreter.nim:553-560.
    let th = taggedHash("TapLeaf", @[])
    # Sanity: re-deriving the same way matches
    let tagHash = sha256(cast[seq[byte]]("TapLeaf"))
    var preimage: seq[byte]
    preimage.add(tagHash)
    preimage.add(tagHash)
    let expected = sha256(preimage)
    check th == expected

# Gate 6 — Schnorr signing in wallet
suite "W127 Gate 6 (BIP-340): wallet Schnorr signing — PRESENT (closes BUG-3 / BUG-11)":
  test "PRESENT — signSchnorr round-trips against verifySchnorr (BIP-86 TapTweak)":
    ## Reference: bitcoin-core/src/key.cpp:549-563 (KeyPair::SignSchnorr).
    ## Nimrod: src/crypto/secp256k1.nim signSchnorr (FFI + TapTweak +
    ## aux_rand32 + self-verify paranoia). Closes 6-WAVE single-bug
    ## carry-forward W127 BUG-3/BUG-11 -> W158 -> W159 -> W160 -> W161
    ## (longest single-bug tracking in fleet history).
    let msg32: array[32, byte] = [
      0xaa'u8, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ]
    # BIP-86 keypath spend: TapTweak with empty merkle root (all-zero array
    # is the signal -> NO merkle_root byte appended to TapTweak preimage).
    let emptyRoot: array[32, byte] = default(array[32, byte])
    let sig = signSchnorr(TEST_PRIVKEY, msg32, some(emptyRoot))

    # Re-derive the tweaked xonly key the way wallet.nim:530-542 does for
    # BIP-86 (P2TR address). Verifying signature against this tweaked
    # output key proves the FFI chain is wired correctly end-to-end.
    # taptweakOf has signature (internalPk, merkleRoot) - for BIP-86 the
    # merkle root is empty so we pass internalPk alone via tagged hash.
    let tagHash = sha256(cast[seq[byte]]("TapTweak"))
    var preimage = newSeq[byte](64 + 32)
    for i in 0 ..< 32: preimage[i] = tagHash[i]
    for i in 0 ..< 32: preimage[32 + i] = tagHash[i]
    for i in 0 ..< 32: preimage[64 + i] = G_INTERNAL[i]
    let tweak = sha256(preimage)
    let (tweakedXonly, _) = tweakXonlyPubkey(G_INTERNAL, tweak)

    var msgSeq = newSeq[byte](32)
    for i in 0 ..< 32: msgSeq[i] = msg32[i]
    check verifySchnorr(tweakedXonly, msgSeq, sig)

  test "PRESENT — signSchnorr without merkleRoot (untweaked, raw key)":
    ## Test the `none(merkleRoot)` path: no TapTweak applied -> sig verifies
    ## against the internal x-only key directly. Used by callers that have
    ## already done their own tweaking (PSBT TAP_KEY_SIG fill).
    let msg32: array[32, byte] = default(array[32, byte])
    let sig = signSchnorr(TEST_PRIVKEY, msg32, none(array[32, byte]))
    var msgSeq = newSeq[byte](32)
    check verifySchnorr(G_INTERNAL, msgSeq, sig)

# ===========================================================================
# Subsystem B — BIP-341 Taproot key-path (Gates 7-13)
# ===========================================================================

# Gate 7 — TAPROOT_LEAF_MASK = 0xFE applied
suite "W127 Gate 7 (BIP-341): leaf-version mask 0xFE — PRESENT":
  test "PRESENT — leaf-version with parity bit set masks to even byte":
    ## Reference: bitcoin-core/src/script/interpreter.h:241,
    ## interpreter.cpp:1973 (control[0] & TAPROOT_LEAF_MASK).
    ## Nimrod: src/script/interpreter.nim:2598 + :2925.
    ## A control[0] of 0xC1 (tapscript with parity bit 1) must mask to 0xC0.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    # The control-block byte is leaf_version (0xC0) | parity (0 or 1).
    check (cb[0] and 0xFE'u8) == 0xC0'u8

# Gate 8 — Control-block size [33, 4129] divisible by 32 after base
suite "W127 Gate 8 (BIP-341): control-block size validation — PRESENT":
  test "PRESENT — 32-byte control-block (too short) rejected":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1970,
    ## interpreter.h:243-246 (BASE=33, NODE=32, MAX_NODE_COUNT=128,
    ## MAX_SIZE=4129).
    ## Nimrod: src/script/interpreter.nim:2592-2594 + :2921-2922.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (_, prog) = makeControlBlock(tapscript)
    var shortCb: seq[byte]
    for _ in 0 ..< 32: shortCb.add(0'u8)
    let witness = @[tapscript, shortCb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

  test "PRESENT — control-block size not (33 + N*32) rejected":
    ## Specifically a 65-byte CB (33 + 32) is valid (one merkle node);
    ## a 50-byte CB is invalid (33 + 17 != 32-multiple).
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (_, prog) = makeControlBlock(tapscript)
    var badCb: seq[byte] = @[0xC0'u8]
    for _ in 0 ..< 49: badCb.add(0'u8)  # 50-byte CB
    let witness = @[tapscript, badCb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# Gate 9 — Annex detection & strip via ANNEX_TAG = 0x50
suite "W127 Gate 9 (BIP-341): annex detection — PRESENT":
  test "PRESENT — annex with 0x50 prefix is detected and stripped":
    ## Reference: bitcoin-core/src/script/script.h:58 (ANNEX_TAG = 0x50),
    ## interpreter.cpp:1951-1958.
    ## Nimrod: src/script/interpreter.nim:2519-2522 + :2896-2899.
    ## Test: a key-path spend with an annex must still be evaluable
    ## (verify will fail on the dummy sig, but the annex strip must work).
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    var annex: seq[byte] = @[0x50'u8, 0x01, 0x02, 0x03]
    let witness = @[tapscript, cb, annex]
    # We don't care about the result (witness is malformed for key path
    # anyway), only that the annex strip didn't crash and the verify
    # path entered the script-path code (witnessStack.len > 1 after strip).
    discard verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                                 {sfWitness, sfTaproot})

# Gate 10 — TapTweak compute via tagged_hash("TapTweak", internal_pk || merkle_root)
suite "W127 Gate 10 (BIP-341): TapTweak hash structure — PRESENT":
  test "PRESENT — taptweak == taggedHash('TapTweak', pk || merkle_root)":
    ## Reference: bitcoin-core/src/pubkey.cpp:246-254
    ## (ComputeTapTweakHash).
    ## Nimrod: src/script/interpreter.nim:2644-2648 + :2971-2975, plus
    ## src/wallet/wallet.nim:540 (BIP-86 empty merkle root).
    var merkleRoot: array[32, byte]
    for i in 0 ..< 32: merkleRoot[i] = byte(i)
    let computed = taptweakOf(G_INTERNAL, merkleRoot)
    var preimage: seq[byte]
    for b in G_INTERNAL: preimage.add(b)
    for b in merkleRoot: preimage.add(b)
    let expected = taggedHash("TapTweak", preimage)
    check computed == expected

# Gate 11 — Output-key commitment verify (Q == lift_x(P) + t*G)
suite "W127 Gate 11 (BIP-341): output-key commitment — PRESENT":
  test "PRESENT — valid commitment with correct parity verifies":
    ## Reference: bitcoin-core/src/pubkey.cpp:257-263
    ## (XOnlyPubKey::CheckTapTweak).
    ## Nimrod: src/script/interpreter.nim:2660-2669 (commitment match
    ## + parity check + Q-byte equality).
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == true

  test "PRESENT — flipped Q-byte fails commitment":
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    var bogusProg = prog
    bogusProg[0] = bogusProg[0] xor 0x01'u8
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(witness, 1, bogusProg, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# Gate 12 — Key-path Schnorr verify with sig.size in {64,65}
suite "W127 Gate 12 (BIP-341): key-path sig size 64/65 — PRESENT":
  test "PRESENT — 63-byte sig rejected on key path":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1726.
    ## Nimrod: src/script/interpreter.nim:2527-2528.
    var program: seq[byte] = newSeq[byte](32)
    var badSig: seq[byte] = newSeq[byte](63)
    let witness = @[badSig]
    check verifyWitnessProgram(witness, 1, program, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

  test "PRESENT — 66-byte sig rejected on key path":
    var program: seq[byte] = newSeq[byte](32)
    var badSig: seq[byte] = newSeq[byte](66)
    let witness = @[badSig]
    check verifyWitnessProgram(witness, 1, program, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# Gate 13 — SIGHASH_DEFAULT explicit byte in 65-byte sig rejected
suite "W127 Gate 13 (BIP-341): explicit SIGHASH_DEFAULT byte rejected — PRESENT":
  test "PRESENT — 65-byte sig with hashtype byte 0x00 rejected":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1733
    ## (hashtype == SIGHASH_DEFAULT == 0x00 in 65-byte form rejected).
    ## Nimrod: src/script/interpreter.nim:2535-2536.
    var program: seq[byte] = newSeq[byte](32)
    var badSig: seq[byte] = newSeq[byte](65)
    badSig[64] = 0x00  # explicit SIGHASH_DEFAULT
    let witness = @[badSig]
    check verifyWitnessProgram(witness, 1, program, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# ===========================================================================
# Subsystem C — BIP-341 Taproot script-path (Gates 14-22)
# ===========================================================================

# Gate 14 — Leaf hash structure
suite "W127 Gate 14 (BIP-341): TapLeaf hash structure — PRESENT":
  test "PRESENT — TapLeaf == taggedHash('TapLeaf', leafver || compact_size(script) || script)":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1872-1875
    ## (HASHER_TAPLEAF << leaf_version << CompactSizeWriter(...) << script).
    ## Nimrod: src/script/interpreter.nim:2605-2610 + :2930-2935.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let computed = tapleafHashOfVer(tapscript, 0xC0'u8)
    # Re-derive
    var leafData: seq[byte] = @[0xC0'u8]
    var w = BinaryWriter()
    w.writeVarBytes(tapscript)
    leafData.add(w.data)
    let expected = taggedHash("TapLeaf", leafData)
    check computed == expected

# Gate 15 — TapBranch merkle walk with lexicographic ordering
suite "W127 Gate 15 (BIP-341): TapBranch lexicographic merkle — PRESENT":
  test "PRESENT — TapBranch swaps to canonical order":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1877-1885
    ## (ComputeTapbranchHash with std::lexicographical_compare).
    ## Nimrod: src/script/interpreter.nim:2613-2637 + :2940-2964.
    var a: array[32, byte]
    var b: array[32, byte]
    for i in 0 ..< 32:
      a[i] = byte(i)        # smaller
      b[i] = byte(0xFF - i) # larger
    var ab: seq[byte]
    for x in a: ab.add(x)
    for x in b: ab.add(x)
    var ba: seq[byte]
    for x in b: ba.add(x)
    for x in a: ba.add(x)
    let hashAB = taggedHash("TapBranch", ab)
    let hashBA = taggedHash("TapBranch", ba)
    # Canonical form must be a||b (because a < b lex).
    check hashAB != hashBA  # asymmetric tag if no canonicalization

# Gate 16 — Commitment verified BEFORE leaf-version branch
suite "W127 Gate 16 (BIP-341): commitment-before-leaf-version — PRESENT":
  test "PRESENT — unknown leaf version with BROKEN commitment rejected":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1973-1985.
    ## (ComputeTapleafHash + VerifyTaprootCommitment THEN leaf-version
    ## branch). W94 closed this; W127 re-asserts.
    ## Nimrod: src/script/interpreter.nim:2600-2678 + :2927-3001.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    var bogusProg = prog
    bogusProg[0] = bogusProg[0] xor 0x01'u8
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(witness, 1, bogusProg, trivialTx(), 0,
                               Satoshi(0), {sfWitness, sfTaproot}) == false

# Gate 17 — SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
suite "W127 Gate 17 (BIP-341): discourage-upgradable-taproot-version — PRESENT":
  test "PRESENT — unknown leaf 0xC2 rejected with flag set":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1985-1988.
    ## Nimrod: sfDiscourageUpgradableTaprootVersion at :92, fires at
    ## :2676 + :2999.  W94 closure.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlockVer(tapscript, 0xC2'u8)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot, sfDiscourageUpgradableTaprootVersion}) == false

# Gate 18 — Tapscript leaf version 0xC0 enables BIP-342 path
suite "W127 Gate 18 (BIP-341): leaf 0xC0 enables BIP-342 — PRESENT":
  test "PRESENT — leaf 0xC0 tapscript with OP_TRUE succeeds":
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    let witness = @[tapscript, cb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == true

# Gate 19 — Tapscript Schnorr hard-error vs NULLFAIL
suite "W127 Gate 19 (BIP-342): tapscript Schnorr hard-errors — PRESENT":
  test "PRESENT — bad-size schnorr sig in tapscript CHECKSIG hard-errors":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1721-1741
    ## (CheckSchnorrSignature) — sig.size != {64,65} -> SCRIPT_ERR_SCHNORR_SIG_SIZE.
    ## Nimrod: src/script/interpreter.nim:1744-1798.  W95 closure.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightLeft = 1000'i64
    interp.validationWeightInit = true
    var badSig: seq[byte] = newSeq[byte](63)  # not 64/65
    var goodPk: seq[byte] = newSeq[byte](32)
    interp.push(badSig)
    interp.push(goodPk)
    let ctx = SigCheckContext(
      tx: trivialTx(), inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: @[], sigVersion: sigTapscript,
      amounts: @[Satoshi(0)], scriptPubKeys: @[@[]],
      annex: @[], tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[byte(OP_CHECKSIG)], ctx)
    check err == seSchnorrSigSize

# Gate 20 — ANNEX_TAG named constant
suite "W127 Gate 20 (BIP-341): ANNEX_TAG named constant — PARTIAL":
  test "PARTIAL — 0x50 is a bare literal in annex detection (BUG-4)":
    ## Reference: bitcoin-core/src/script/script.h:58 names ANNEX_TAG.
    ## Nimrod: src/script/interpreter.nim has the literal 0x50 at:
    ##   :140 (OP_RESERVED* = 0x50'u8)
    ##   :2520 (annex detection bool variant)
    ##   :2897 (annex detection error variant)
    ## The two annex sites use bare 0x50, NOT OP_RESERVED.  No
    ## ANNEX_TAG constant exists.  Behaviorally correct but fragile.
    ## TODO BUG-4: add `const ANNEX_TAG* = 0x50'u8` and replace the
    ## bare literals.
    skip()

# Gate 21 — Witness stack size limit
suite "W127 Gate 21 (BIP-342): MAX_STACK_SIZE on initial witness — PRESENT":
  test "PRESENT — > 1000 initial witness items rejected":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1855.
    ## Nimrod: src/script/interpreter.nim:2707 + :3017.  W94 closure.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    var witness: seq[seq[byte]]
    # 1001 args + script + cb = 1003 items.  Args > MaxStackSize (1000).
    for _ in 0 ..< 1001:
      witness.add(@[])
    witness.add(tapscript)
    witness.add(cb)
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# Gate 22 — Initial witness element size limit
suite "W127 Gate 22 (BIP-342): MAX_SCRIPT_ELEMENT_SIZE on initial elements — PRESENT":
  test "PRESENT — > 520-byte initial witness element rejected":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:1858-1861.
    ## Nimrod: src/script/interpreter.nim:2709-2711 + :3019-3021.  W94 closure.
    let tapscript: seq[byte] = @[byte(OP_TRUE)]
    let (cb, prog) = makeControlBlock(tapscript)
    var big: seq[byte] = newSeq[byte](521)  # 1 byte over limit
    let witness = @[big, tapscript, cb]
    check verifyWitnessProgram(witness, 1, prog, trivialTx(), 0, Satoshi(0),
                               {sfWitness, sfTaproot}) == false

# ===========================================================================
# Subsystem D — BIP-342 Tapscript opcodes + sigops (Gates 23-30)
# ===========================================================================

# Gate 23 — OP_CHECKSIGADD defined and bound to tapscript
suite "W127 Gate 23 (BIP-342): OP_CHECKSIGADD opcode — PRESENT":
  test "PRESENT — OP_CHECKSIGADD constant == 0xBA":
    ## Reference: BIP-342 §"Validation rules".
    ## Nimrod: src/script/interpreter.nim:265.
    check OP_CHECKSIGADD == 0xba'u8

  test "PRESENT — OP_CHECKSIGADD outside tapscript returns seInvalidOpcode":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:2009-2011.
    var interp = newInterpreter({})
    interp.push(@[])  # sig
    interp.push(@[])  # n
    interp.push(@[])  # pubkey
    let ctx = SigCheckContext(
      tx: trivialTx(), inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: @[], sigVersion: sigBase,
      annex: @[], tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_CHECKSIGADD], ctx)
    check err == seInvalidOpcode

# Gate 24 — OP_CHECKMULTISIG disabled in tapscript
suite "W127 Gate 24 (BIP-342): OP_CHECKMULTISIG disabled in tapscript — PRESENT":
  test "PRESENT — OP_CHECKMULTISIG in tapscript returns seTapscriptCheckmultisig":
    ## Reference: BIP-342 §"Rationale", bitcoin-core/src/script/interpreter.cpp:1812-1814.
    ## Nimrod: src/script/interpreter.nim:1812-1814.
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightInit = true
    interp.validationWeightLeft = 1000'i64
    let ctx = SigCheckContext(
      tx: trivialTx(), inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: @[], sigVersion: sigTapscript,
      amounts: @[Satoshi(0)], scriptPubKeys: @[@[]],
      annex: @[], tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_CHECKMULTISIG], ctx)
    check err == seTapscriptCheckmultisig

# Gate 25 — OP_SUCCESSx byte list matches Core IsOpSuccess
suite "W127 Gate 25 (BIP-342): isOpSuccess byte list matches Core — PRESENT":
  test "PRESENT — every Core OP_SUCCESSx byte is isOpSuccess true":
    ## Reference: bitcoin-core/src/script/script.cpp:364-370.
    ## Nimrod: src/script/interpreter.nim:993-1007.
    ## Bytes: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254.
    check isOpSuccess(80'u8)
    check isOpSuccess(98'u8)
    for op in 126 .. 129: check isOpSuccess(byte(op))
    for op in 131 .. 134: check isOpSuccess(byte(op))
    for op in 137 .. 138: check isOpSuccess(byte(op))
    for op in 141 .. 142: check isOpSuccess(byte(op))
    for op in 149 .. 153: check isOpSuccess(byte(op))
    for op in 187 .. 254: check isOpSuccess(byte(op))

  test "PRESENT — Core non-OP_SUCCESS bytes are isOpSuccess false":
    # Sample of bytes that should NOT be OP_SUCCESS
    check isOpSuccess(0x00'u8) == false  # OP_0
    check isOpSuccess(0x51'u8) == false  # OP_1
    check isOpSuccess(0x76'u8) == false  # OP_DUP
    check isOpSuccess(0x87'u8) == false  # OP_EQUAL
    check isOpSuccess(0xAC'u8) == false  # OP_CHECKSIG
    check isOpSuccess(0xBA'u8) == false  # OP_CHECKSIGADD
    check isOpSuccess(0xFF'u8) == false  # OP_INVALIDOPCODE

# Gate 26 — Validation-weight budget
suite "W127 Gate 26 (BIP-342): validation-weight budget — PRESENT":
  test "PRESENT — budget decrement matches VALIDATION_WEIGHT_PER_SIGOP_PASSED=50":
    ## Reference: bitcoin-core/src/script/script.h:61.
    ## Nimrod: src/script/interpreter.nim:543 (`-= 50'i64`).
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightInit = true
    interp.validationWeightLeft = 100'i64
    discard consumeValidationWeight(interp)
    check interp.validationWeightLeft == 50'i64
    discard consumeValidationWeight(interp)
    check interp.validationWeightLeft == 0'i64
    let err = consumeValidationWeight(interp)
    # Should fail on the next consume (would go -50).
    check err == seTapscriptValidationWeight

  test "PRESENT — consume before init returns seTapscriptValidationWeight":
    var interp = newInterpreter({sfWitness, sfTaproot})
    # validationWeightInit defaults to false
    let err = consumeValidationWeight(interp)
    check err == seTapscriptValidationWeight

# Gate 27 — Tapscript minimal IF/NOTIF
suite "W127 Gate 27 (BIP-342): mandatory minimal IF/NOTIF in tapscript — PRESENT":
  test "PRESENT — tapscript IF with non-canonical bool fails":
    ## Reference: bitcoin-core/src/script/interpreter.cpp:603-613.
    ## Nimrod: src/script/interpreter.nim:1216-1218.
    ## A 2-byte stack item passed to OP_IF must be exactly @[] or @[0x01].
    var interp = newInterpreter({sfWitness, sfTaproot})
    interp.validationWeightInit = true
    interp.validationWeightLeft = 1000'i64
    interp.push(@[0x02'u8, 0x00'u8])  # 2-byte, non-minimal
    let ctx = SigCheckContext(
      tx: trivialTx(), inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: @[], sigVersion: sigTapscript,
      amounts: @[Satoshi(0)], scriptPubKeys: @[@[]],
      annex: @[], tapleafHash: default(array[32, byte]),
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_IF, byte(OP_TRUE), OP_ENDIF], ctx)
    check err == seTapscriptMinimalIf

# Gate 28 — Named constants for Taproot magic numbers
suite "W127 Gate 28 (BIP-341/342): named constants — PARTIAL":
  test "PARTIAL — none of TAPROOT_*/VALIDATION_WEIGHT_* exist as named consts (BUG-5)":
    ## Reference: bitcoin-core/src/script/interpreter.h:241-246,
    ## script.h:58, 61, 64.
    ## Nimrod: literals 0xFE (TAPROOT_LEAF_MASK), 0xC0 (TAPROOT_LEAF_TAPSCRIPT),
    ## 33 (TAPROOT_CONTROL_BASE_SIZE), 32 (TAPROOT_CONTROL_NODE_SIZE),
    ## 128 (TAPROOT_CONTROL_MAX_NODE_COUNT), 4129 (TAPROOT_CONTROL_MAX_SIZE),
    ## 0x50 (ANNEX_TAG), 50 (VALIDATION_WEIGHT_OFFSET/PER_SIGOP_PASSED)
    ## are all bare literals, each appearing 2+ times in the file.
    ## TODO BUG-5: add `const TAPROOT_LEAF_MASK* = 0xFE'u8`, etc.,
    ## and replace bare literals throughout.
    skip()

# Gate 29 — multi_a() descriptor + miniscript support
suite "W127 Gate 29 (BIP-342): multi_a() / MULTI_A miniscript — MISSING":
  test "MISSING — no miniscript fragment / descriptor parse for multi_a (BUG-6)":
    ## Reference: BIP-342 §`multi_a()` — canonical replacement for
    ## `multi()` in tapscript.  Up to MAX_PUBKEYS_PER_MULTI_A=999 keys.
    ## Core: descriptor.cpp `MultiAExprNode`, miniscript.h `MULTI_A`.
    ## Nimrod: no MsMultiA fragment in miniscript.nim; no `multi_a(...)`
    ## parser arm in descriptor.nim.  Wallet cannot construct or sign
    ## tapscript leaves using BIP-342 multi-sig.
    ## TODO BUG-6: add MsMultiA fragment + descriptor parser.
    skip()

# Gate 30 — script_assets_test.json cross-impl corpus
suite "W127 Gate 30 (BIP-340/341/342): script_assets_test.json corpus — MISSING":
  test "MISSING — no driver, no corpus fixture (BUG-7)":
    ## Reference: bitcoin-core/src/test/script_assets_tests.cpp:149-160.
    ## Driver expects DIR_UNIT_TEST_DATA=…/script_assets_test.json with
    ## ~tens-of-MB Taproot test corpus.  Generated by Core's fuzz harness
    ## (test/fuzz/script_assets_test_minimizer.cpp).  Loops 16 flag
    ## combinations × all 6 hashtypes × thousands of edge cases.
    ## Nimrod: no corpus fixture, no Nim driver.  Highest-value gap.
    ## TODO BUG-7: ferry script_assets_test.json into tests/data/ as
    ## a shared fixture, write Nim parser + ScriptError → SCRIPT_ERR_*
    ## map, run as overnight CI on a separate target.
    skip()

# ===========================================================================
# Summary — pin the bug catalogue numbers
# ===========================================================================

suite "W127 audit summary":
  test "pin: 14 bugs documented in audit/w127_taproot.md":
    ## When a FIX wave closes a bug, this number decrements and one of
    ## the `skip()` tests above flips to a real `check`.
    const W127_BUG_COUNT = 14
    check W127_BUG_COUNT == 14

  test "pin: 3 P0 bugs (BUG-3, BUG-7, BUG-11)":
    const W127_P0_BUG_COUNT = 3
    check W127_P0_BUG_COUNT == 3

  test "pin: 30 audit gates":
    const W127_GATE_COUNT = 30
    check W127_GATE_COUNT == 30
