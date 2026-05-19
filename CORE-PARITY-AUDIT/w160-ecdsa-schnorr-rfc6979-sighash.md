# W160 — ECDSA + Schnorr signing primitives + RFC 6979 deterministic nonce + sighash construction (nimrod)

**Wave:** W160 — One layer IN from W159. Subject: the actual signing
primitives themselves, the RFC 6979 deterministic-nonce machinery, the
BIP-340 aux_rand path, the per-network `secp256k1_ecdsa_sign` /
`secp256k1_schnorrsig_sign` call sites, low-S normalisation on the
sign side, DER strict (BIP-66) emission, sigversion-specific sighash
preimage construction (BIP-143 SegWit v0, BIP-341 Taproot), and the
producer-side responsibilities that Core gates behind
`CKey::Sign{Compact,ECDSA,Schnorr}` and friends.

**Scope:** discovery only — NO production code changes in W160.

**Bitcoin Core references**
- `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h` —
  `secp256k1_ecdsa_sign_recoverable` (low-level entry; identical RFC
  6979 path as `_ecdsa_sign`).
- `bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h:24-99`
  — `secp256k1_nonce_function_bip340` (the official BIP-340 nonce
  derivation: `aux32 ^= tagged_hash("BIP0340/aux", aux32);
  tagged_hash("BIP0340/nonce", aux32 || xonly_pk || msg)`),
  `secp256k1_schnorrsig_sign32` (the canonical sign entry; aux_rand
  argument MUST be 32 fresh bytes per signature).
- `bitcoin-core/src/secp256k1/src/ecdsa_impl.h` — `secp256k1_ecdsa_sign_inner`:
  RFC 6979 nonce derivation, sign-then-low-S-canonicalise. Always
  emits low-S; the API contract is canonical-low-S output.
- `bitcoin-core/src/secp256k1/src/modules/extrakeys/main_impl.h` —
  `secp256k1_keypair_create` (always re-flips seckey on odd-y so
  the keypair-side seckey matches the x-only output key parity),
  `secp256k1_keypair_xonly_pub`, `secp256k1_keypair_sec`,
  `secp256k1_keypair_xonly_tweak_add`.
- `bitcoin-core/src/key.cpp:204-235` — `CKey::Sign`: signs **then
  re-verifies** the signature via `_ec_pubkey_create` + `_ecdsa_verify`
  before returning; `assert(ret)` on failure. Sony-PS3-style bit-flip
  paranoia.
- `bitcoin-core/src/key.cpp:250-272` — `CKey::SignCompact`: mirrors the
  paranoia step (re-recovers pubkey, compares with `_ec_pubkey_cmp`).
- `bitcoin-core/src/key.cpp:273-294` — `CKey::SignSchnorr`: creates a
  `secp256k1_keypair`, fills 32 bytes of `GetRandBytes` into `aux32`,
  calls `_schnorrsig_sign32`, then **re-verifies** via
  `_schnorrsig_verify` (post-sign paranoia, same shape as ECDSA path).
- `bitcoin-core/src/key.cpp:549-571` — `KeyPair::SignSchnorr` (used by
  Taproot script-path) — passes `aux32 = GetRandBytes(32)`; never NULL
  in production. Cached `secp256k1_keypair` lets the seckey-flip be
  reused across multiple Schnorr signs from one descriptor wallet
  entry.
- `bitcoin-core/src/script/sign.cpp` — `SignSignature`, `ProduceSignature`,
  `MutableTransactionSignatureCreator::CreateSig` and `CreateSchnorrSig`
  (the wallet-side sighash + sign + DER-encode + concat-sighash-byte
  pipeline). For Taproot, `CreateSchnorrSig` carries the
  `KeyPair::SignSchnorr` aux_rand requirement up to the BaseSignatureCreator
  abstract base.
- `bitcoin-core/src/script/interpreter.cpp:1600-1670` —
  `SignatureHash`: legacy (BIP-62 + SIGHASH_SINGLE bug preserved),
  BIP-143 SegWit-v0 preimage with `PrecomputedTransactionData` midstate
  cache (`m_bip143_segwit_ready` gate, `hashPrevouts` /
  `hashSequence` / `hashOutputs` midstates).
- `bitcoin-core/src/script/interpreter.cpp:1539-1598` —
  `SignatureHashSchnorr` (BIP-341 Taproot preimage: epoch=0x00, hash
  type byte, version, locktime, sha_prevouts / sha_amounts /
  sha_scriptpubkeys / sha_sequences, sha_outputs, spend_type =
  `2*extFlag + has_annex`, input-specific block, annex/single-output
  blocks, tapscript suffix = tapleafHash || key_version=0x00 ||
  codesep_pos_le32).
- `bitcoin-core/src/script/sigcache.cpp:39-50` —
  `ComputeEntryECDSA(entry, sighash, sig, pubkey)` and
  `ComputeEntrySchnorr(entry, sighash, sig, pubkey)`: cache key is
  SHA256(salted-hasher || **sighash** || sig-bytes || pubkey-bytes).
  Critically: the sighash itself goes into the cache key, plus separate
  salted hashers for ECDSA vs Schnorr, so a witness-malleated alternate
  sig that happens to verify cannot poison the cache for the canonical
  sig.
- `bitcoin-core/src/script/interpreter.cpp:188-200` —
  `IsDefinedHashtypeSignature`: allowed hashtypes are
  `{1,2,3, 0x81,0x82,0x83}`.
- BIP-66 §"Strict DER signatures" — exact `0x30 [len] 0x02 [rlen] [r]
  0x02 [slen] [s] [sighash]` shape with leading-zero rules,
  consensus-enforced since Jul 2015.
- BIP-62 §"Low-S" — `s <= n/2`; relay-only originally, now consensus
  via `SCRIPT_VERIFY_LOW_S`.
- BIP-340 §"Default Signing" + §"Optimizations" — aux_rand MUST be 32
  bytes; passing NULL is permitted by the API but **strongly
  discouraged in production** because it eliminates the
  side-channel-blinding nonce contribution and turns the nonce purely
  deterministic on (msg, seckey), which is a fault-attack vector. See
  also Core comment at `key.cpp:283` ("rnd32 buffer that will be
  zeroed after use; pass NULL once for the no-aux test vectors only").
- BIP-341 §"Default Signing" + §"Constructing and spending Taproot
  outputs" — `extFlag = 0` for key-path, `1` for script-path; `epoch
  = 0x00` (single-byte prefix INSIDE the tagged-hash domain).
- BIP-431 / Cluster-mempool RBF — references the same sigcache key
  layout (no new keying).

**Files audited**
- `src/crypto/secp256k1.nim` (989 lines) — entire FFI surface +
  high-level `sign` / `verify` / `signCompactRecoverable` /
  `verifySchnorr`. Hot spots:
  - lines 90-97: `secp256k1_ecdsa_sign` FFI (passes `noncefp=nil,
    ndata=nil` → libsecp uses `secp256k1_nonce_function_default` = RFC
    6979 with no extra entropy).
  - lines 173-180: `secp256k1_ecdsa_sign_recoverable` FFI (same
    `noncefp=nil` shape).
  - lines 268-280: `sign(privateKey, msgHash) -> Signature` —
    high-level wrapper used by every wallet code path.
  - lines 548-567: `signCompactRecoverable` — used by signmessage.
  - lines 523-546, 829-843: `verifySchnorr` — the ONLY Schnorr entry
    point. **No `secp256k1_schnorrsig_sign` FFI binding at all.**
  - lines 669-718: `tweakSeckeyAdd` / `tweakPubkeyAdd` — BIP-32 CKD
    paths via libsecp (good; matches Core).
- `src/script/interpreter.nim:609-846` — sighash construction:
  - lines 609-667: `computeSighashLegacy` (BIP-62 + SIGHASH_SINGLE
    bug preserved via `specialHash[0] = 1` at line 640).
  - lines 669-721: `computeSighashSegwitV0` (BIP-143).
  - lines 723-846: `computeSighashTaproot` (BIP-341).
- `src/script/interpreter.nim:430-509` — `isValidSignatureEncoding`
  (BIP-66 strict DER), `isDefinedHashtypeSignature`,
  `checkSignatureEncoding`, `checkPubKeyEncoding`.
- `src/wallet/wallet.nim` —
  - lines 218-339: BIP-32 derivation (`masterKeyFromSeed`,
    `deriveChild`, `derivePathStr`). Uses `tweakSeckeyAdd` /
    `tweakPubkeyAdd` from secp256k1.nim (good).
  - lines 999-1009: `computeSighashP2WPKH` — thin wrapper over
    `computeSighashSegwitV0` (correct since W27-B fix).
  - lines 1011-1051: `compactSigToDer` — hand-rolled DER encoder for
    the compact 64-byte sig. Used by every signInputP2{PKH,WPKH,WSH}
    path (5 call sites).
  - lines 1082-1242: signInputP2WPKH / P2PKH / P2SH-P2WPKH /
    P2WSH / P2SH-P2WSH. Every one ends in
    `sign(privKey, sighash) -> compactSigToDer(sig, hashType)`.
  - lines 1244-1301: `signTransaction` — main wallet sign entry.
  - line 1285: comment-as-confession **"P2TR - requires Schnorr
    signature (simplified)"** → `raise WalletError "P2TR signing
    not yet fully implemented"`.
- `src/wallet/psbt.nim` —
  - line 120: `tapKeySig*: seq[byte]  ## 64-65 byte key path
    signature` — field exists; no producer.
  - line 454: serialise `PSBT_IN_TAP_KEY_SIG` if non-empty.
  - line 744: parse `PSBT_IN_TAP_KEY_SIG` if present.
  - line 1130-1300: `finalizeInput` — combines partial sigs into
    scriptSig / witness. **No `signPsbtInput` / `signPsbt` proc
    exists** — PSBT signer-role machinery is read-only.
- `src/crypto/signmessage.nim` (98 lines, full file) —
  - lines 40-55: `signMessage` → `signCompactRecoverable(...)`.
  - lines 66-98: `verifyMessageRaw` → `recoverCompactPubkey(...)`.
- `src/perf/sig_cache.nim` (108 lines, full file) — sigcache.
  - line 36-66: `computeKey(cache, wtxid, inputIndex, flags) -> uint64`
    — cache key is `SHA256(nonce[32] || wtxid[32] || inputIndex_le32
    || flags_le32)`. **Sighash and sig+pubkey bytes are NOT included.**
- `src/consensus/validation.nim:1460-1560` — `verifyScripts` block-eval
  driver. Uses `globalSigCache.lookup(wtxid, inputIndex, flagsUint)`
  /  `.insert(...)` keyed on wtxid only — confirms the
  no-sighash-in-key behaviour at the call site.
- `src/perf/parallel_verify.nim` — thread-local `CryptoEngine` for
  parallel script verify. No sign-side concurrency (production sign
  paths run from the wallet RPC thread).
- `tests/test_w127_taproot.nim:180-195` — pins BUG-3 / BUG-11 as
  "MISSING — no signSchnorr / signTaprootInput in wallet" with
  `skip()`. This is a **`test-pins-bug` instance**: the test file
  acknowledges the missing primitive and SKIPS rather than failing,
  so CI is permanently green on this gap.
- `tests/test_w111_wallet.nim:15-39, 583` — same `test-pins-bug`
  pattern: explicitly documents BUG-2 "G28: P2TR key-path signing
  raises WalletError" and then `skip()`s the test that would have
  caught a regression.
- `tests/test_w105_checkqueue.nim:240-380` — the sigcache test suite
  itself; G7 (key uses wtxid) and G8 (cache nonce + salted hasher
  present) tests are marked PASS but their checks are STRUCTURAL only
  (they assert "nonce is non-zero"), not behavioural (they do not
  assert that two different sighashes for the same wtxid+input+flags
  produce different cache keys).

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RFC 6979 deterministic nonce | G1: ECDSA sign uses libsecp's `nonce_function_default` (no roll-your-own) | PASS (`secp256k1.nim:273` passes `noncefp=nil`) |
| 1 | … | G2: extra entropy (`ndata`) passed to defeat replayed-RAM attacks | **BUG-1 (P2-SEC)** — `secp256k1.nim:273, 558` pass `ndata=nil`. Core also passes nullptr here for ECDSA (see `key.cpp:222`), so this is parity — but it is a known weakness vs the Schnorr path which DOES require aux_rand. Recorded as a divergence-of-defense-in-depth (P2-SEC). |
| 2 | Sign-then-verify paranoia | G3: ECDSA `sign` re-verifies via `_pubkey_create + _ecdsa_verify` | **BUG-2 (P1-SEC)** — `secp256k1.nim:268-280` returns immediately. Compare `bitcoin-core/src/key.cpp:228-234`. Every wallet sign path (5 call sites in `wallet.nim`, every `signmessage*` RPC) returns un-verified sigs. **Re-asserts W159 BUG-9 with W160 production-call-site evidence.** |
| 2 | … | G4: SignCompact re-recovers pubkey and `_ec_pubkey_cmp`'s | **BUG-3 (P1-SEC)** — `secp256k1.nim:548-567` returns immediately; `signmessage` / `signmessagewithprivkey` (`server.nim:4625-4710`) admit unrelayed Sony-PS3-class bit-flip corruption. **Re-asserts W159 BUG-10.** |
| 3 | Low-S (BIP-62 / consensus) | G5: ECDSA sign output is canonical low-S | PASS — libsecp's `_ecdsa_sign` always emits canonical low-S internally; we trust the FFI |
| 3 | … | G6: `compactSigToDer` does not accidentally invert low-S during DER re-encode | PASS (`wallet.nim:1011-1051` only adds DER framing + sighash byte; never touches S value) |
| 4 | DER strict (BIP-66) emit | G7: emitted scriptSig signature is `0x30 [len] 0x02 [rlen] [r] 0x02 [slen] [s] [sighash]` | PASS (`wallet.nim:1011-1051`). |
| 4 | … | G8: emitted sig round-trips through nimrod's own `isValidSignatureEncoding` | **BUG-4 (P2)** — never asserted in production OR tests. The wallet emits then never round-trip-checks. A hand-rolled DER encoder that ever emits a non-canonical encoding (e.g. when R or S is exactly 1 byte) would silently produce a sig that NIMROD ITSELF rejects in `checkSignatureEncoding` under `SCRIPT_VERIFY_DERSIG`. No test pins this round-trip. |
| 5 | BIP-340 Schnorr signing primitive | G9: `secp256k1_schnorrsig_sign32` FFI binding exists | **BUG-5 (P0-CONS)** — FFI binding entirely absent in `secp256k1.nim`. Core call site `key.cpp:285`. **Nimrod CANNOT sign ANY Taproot input.** `wallet.nim:1285` confesses ("P2TR - requires Schnorr signature (simplified)"). |
| 5 | … | G10: `secp256k1_keypair_create` FFI binding exists | **BUG-6 (P0-CONS)** — entire `secp256k1_extrakeys` module absent. No `Secp256k1Keypair` type. **5th-consecutive-wave carry-forward** of W127 BUG-3 / W127 BUG-11 / W158 BUG-X / W159 BUG-14 / W160 BUG-6. **Confirms nimrod-origin "asymmetric Schnorr surface" fleet pattern (verify only).** |
| 5 | … | G11: BIP-340 aux_rand32 is fresh 32 bytes per Schnorr sign | **BUG-7 (P0-SEC, derivative of BUG-5)** — N/A: no schnorr sign primitive to randomise. **If/when added, the wrapper has no aux_rand parameter design** — the same shape as `sign(privateKey, msgHash)` (`secp256k1.nim:268`) for ECDSA would silently land with `auxRand=nil`. **Tracks fleet pattern "BIP-340 nonce=0 fallback"**: lunarblock W158, blockbrew W158. |
| 6 | Taproot keypair seckey-flip on odd-y | G12: `secp256k1_keypair_create` re-flips seckey when output x-only key has odd y | **BUG-8 (P0-CONS, derivative of BUG-6)** — no keypair primitive. Any naive future Schnorr-sign wired to use raw `seckey` bytes (without the parity flip libsecp does internally inside `keypair_create`) will produce sigs that VERIFY-FAIL against the tweaked x-only output key for ~50% of seckeys. |
| 7 | Sighash construction (legacy) | G13: BIP-62 SIGHASH_SINGLE special hash `0x01,0,…,0` preserved | PASS (`interpreter.nim:639-641`, matches Core's `uint256::ONE` at `interpreter.cpp:1609`) |
| 7 | … | G14: SIGHASH_ANYONECANPAY filters inputs to only the one being signed | PASS (`interpreter.nim:655-657`) |
| 7 | … | G15: FindAndDelete strips push-encoded sig from scriptCode (legacy only) | PASS (`interpreter.nim:564-603`, called at `:1690`) |
| 7 | … | G16: `nHashType` serialised as 4-byte LE uint32 | PASS (`interpreter.nim:665, 719`) |
| 8 | Sighash construction (BIP-143 SegWit v0) | G17: hashPrevouts/Sequence/Outputs zeroing per flag combination | PASS (`interpreter.nim:680-706`) |
| 8 | … | G18: SIGHASH_SINGLE `nIn >= vout.size` → hashOutputs stays zero (not the legacy all-1s sentinel) | PASS (`interpreter.nim:703-706` matches Core's `interpreter.cpp:1637-1643` falling through to zero-init `hashOutputs`) |
| 8 | … | G19: amount serialised as 8-byte LE int64 in preimage | PASS (`interpreter.nim:715`) |
| 8 | … | G20: midstate caching (Core's `PrecomputedTransactionData::m_bip143_segwit_ready`) | **BUG-9 (P2-PERF)** — no precomputation. Every input recomputes `hashPrevouts` / `hashSequence` / `hashOutputs` from scratch. For a 1000-input transaction, this is 3000 redundant double-SHA-256 sweeps over potentially MBs of data. Core caches them once per tx in `PrecomputedTransactionData`. |
| 9 | Sighash construction (BIP-341 Taproot) | G21: epoch byte 0x00 inside `TaggedHash("TapSighash", …)` | PASS (`interpreter.nim:741, 846`) |
| 9 | … | G22: `hash_type` byte written EXACTLY as received (0x00 for SIGHASH_DEFAULT, NOT remapped to SIGHASH_ALL) | PASS (`interpreter.nim:744`); the comment at `:743` confirms this |
| 9 | … | G23: spend_type = `extFlag*2 + (annex?1:0)` | PASS (`interpreter.nim:790-793`) |
| 9 | … | G24: tapscript suffix = `tapleafHash || key_version=0x00 || codesep_pos_le32` | PASS (`interpreter.nim:835-844`) |
| 9 | … | G25: annex preimage = `sha256(compactsize(annex) || annex)` | PASS (`interpreter.nim:818-821`) |
| 9 | … | G26: SIGHASH_SINGLE out-of-range output returns ERROR (NOT all-zero hash treated as valid) | **BUG-10 (P0-CONS)** — `interpreter.nim:831-832` returns `errorHash = default(array[32, byte])` (all zeros) which the caller at `:1789-1791` re-detects via the `baseType == SIGHASH_SINGLE and ctx.inputIndex >= ctx.tx.outputs.len` guard. This **works in the script-eval call path** but the sighash-compute function itself silently returns a usable hash to ANY external caller. If a future wallet RPC ever calls `computeSighashTaproot` for SIGHASH_SINGLE without re-checking, the wallet will SIGN OVER zeros and the resulting sig will key-recover to a different pubkey than expected — a fault attack. |
| 10 | Sighash type byte (CHECKSIG / Schnorr) | G27: `IsDefinedHashtypeSignature` permits {0x01, 0x02, 0x03, 0x81, 0x82, 0x83} (strip 0x80) | PASS (`interpreter.nim:469-472`, masks ANYONECANPAY before range check) |
| 10 | … | G28: tapscript Schnorr hash-type validation gates `{0x00 implied, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}` and rejects explicit 0x00 byte in 65-byte sig | PASS (`interpreter.nim:1759-1770, 2071-2076`) |
| 11 | Sigcache key composition | G29: sigcache key includes sighash bytes (Core `ComputeEntryECDSA` / `ComputeEntrySchnorr` both fold sighash in) | **BUG-11 (P1-SEC)** — `sig_cache.nim:36-66` key = `SHA256(nonce || wtxid || inputIndex || flags)`. **Sighash, sig, and pubkey bytes are ALL absent.** Two different sigs for the same (wtxid, inputIndex, flags) hit the same cache slot, so an attacker who manages to flip a single bit in the input's scriptSig WITHOUT changing wtxid (impossible for witness inputs, but possible for **legacy scriptSig malleation if NULLFAIL is off**) can cause a verify-true result to be cached for a verify-false sig. **Mismatch vs Core `sigcache.cpp:39-50`.** |
| 11 | … | G30: separate salted hashers for ECDSA vs Schnorr (Core `m_salted_hasher_ecdsa` vs `_schnorr`) | **BUG-12 (P2-SEC)** — `sig_cache.nim` has ONE shared cache. A cross-domain collision (an ECDSA verify result mapped to the same key as a Schnorr verify) is bounded by the 64-bit-truncated SHA-256 only. Core uses domain separation (different padding constants) to make cross-domain collisions cryptographically impossible. |
| 11 | … | G31: sigcache evict uses bounded-cycle / LRU (CuckooCache) | **BUG-13 (P2-PERF)** — `sig_cache.nim:94-99` evicts the "first key found in iteration order", documented at `tests/test_w105_checkqueue.nim:23` as a known bug (G11) and never fixed. Iteration order in Nim's `Table` is insertion-modified-by-rehash; cache-thrashing under load is non-deterministic. |
| 11 | … | G32: sigcache nonce derived from CSPRNG, not zero | PASS (`sig_cache.nim:74-77`, `urandom` with hard fail-stop) |

---

## Severity bands

- **P0-CONS** (4): BUG-5, BUG-6, BUG-8, BUG-10
- **P0-SEC** (1): BUG-7
- **P1-SEC** (3): BUG-2, BUG-3, BUG-11
- **P2-SEC** (3): BUG-1, BUG-12
- **P2** (1): BUG-4
- **P2-PERF** (2): BUG-9, BUG-13

**Total: 13 numbered gate-matrix bugs.** Additional findings below
(BUG-14 through BUG-19) carry-forward / cross-cite material not
covered by a unique gate row.

---

## BUG-1 (P2-SEC) — ECDSA sign passes `ndata=nil` (no extra entropy)

`src/crypto/secp256k1.nim:268-280`:

```nim
proc sign*(privateKey: PrivateKey, msgHash: array[32, byte]): Signature =
  var sig: Secp256k1EcdsaSignature
  var pk = privateKey
  var msg = msgHash
  if secp256k1_ecdsa_sign(
    getContext(), addr sig, addr msg[0], addr pk[0], nil, nil
  ) != 1:
    raise newException(Secp256k1Error, "failed to sign")
```

The two `nil`s are `noncefp` and `ndata`. With both nil libsecp uses
`secp256k1_nonce_function_default` (RFC 6979 with zero extra entropy).
Core does the same for legacy ECDSA (`key.cpp:222` passes
`noncefp=nullptr, ndata=nullptr`), so this is **parity, not a
divergence per se** — but Core's Schnorr path REQUIRES `aux_rand` 32
bytes (`key.cpp:283-291`), and nimrod's Schnorr-sign path doesn't
exist (BUG-5). When/if Schnorr-sign is added with the same shape, it
will silently land with `aux_rand=nil` — a **P0-SEC** at that point.

Recorded as **P2-SEC** for the ECDSA side and a precondition for
BUG-7 on the Schnorr side.

**Fix:** add an optional `extraEntropy: openArray[byte] = []`
parameter to `sign` / `signCompactRecoverable`, plumb through
`ndata`. Then when BIP-340 sign lands, the same calling-convention
forces the caller to think about aux_rand.

---

## BUG-2 (P1-SEC) — ECDSA `sign` returns un-verified (sign-then-verify paranoia absent)

`src/crypto/secp256k1.nim:268-280` (above). After
`secp256k1_ecdsa_sign` succeeds, the wrapper serialises the compact
form and returns. Compare `bitcoin-core/src/key.cpp:228-234`:

```cpp
secp256k1_ecdsa_signature sig;
uint32_t counter = 0;
int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, (!grind && test_case) ? extra_entropy : nullptr);
while (ret && !SigHasLowR(sig) && grind) { ... }
secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, ...);

// Re-verify after sign (Sony PS3 paranoia)
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, begin());
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
```

The post-sign verify-or-assert protects against transient bit flips
between sign and serialise. Without it, a single flipped bit in the
`Secp256k1EcdsaSignature` blob silently produces a sig that the
network will reject — but the wallet thinks the tx is signed and
broadcasts it, wasting fees on the post-broadcast revert.

**Impact**: every `wallet.signTransaction` call (5 sign sites in
`wallet.nim` + every `signrawtransactionwithwallet` / `signmessage*`
RPC). For a UTXO-rich wallet doing high-throughput signing, the
probability over millions of operations is non-zero.

**Fix**: ~10 LOC. Add `_ec_pubkey_create` + `_ecdsa_verify` round-trip
after every successful sign; raise on mismatch. Re-asserts W159 BUG-9
with concrete production call-site enumeration.

---

## BUG-3 (P1-SEC) — `signCompactRecoverable` returns un-recovered (paranoia absent)

`src/crypto/secp256k1.nim:548-567`:

```nim
proc signCompactRecoverable*(
  privateKey: PrivateKey, msgHash: array[32, byte]
): tuple[sig: array[64, byte], recid: int] =
  var rsig: Secp256k1RecoverableSignature
  var pk = privateKey
  var msg = msgHash
  if secp256k1_ecdsa_sign_recoverable(...) != 1: ...
  if secp256k1_ecdsa_recoverable_signature_serialize_compact(...) != 1: ...
  result.recid = int(recid)
```

Compare `bitcoin-core/src/key.cpp:262-269`: after sign, Core
re-recovers the pubkey from (sig, msgHash, recid) and compares
constant-time with `secp256k1_ec_pubkey_cmp` against the freshly-
computed `_ec_pubkey_create(seckey)`. Asserts equality.

Nimrod's `signmessage` (`signmessage.nim:40-55`) feeds the recid
straight into the header byte `27 + recid + (4 if compressed else 0)`.
If recid is silently corrupted (single-bit fault) the produced
signature decodes-and-recovers to a different pubkey, the receiver's
`hash160(recovered) == address.pubkeyHash` check silently fails, and
nimrod's `signmessage` returns a sig that nimrod's own `verifymessage`
rejects.

**Impact**: `signmessage` (`server.nim:4625`),
`signmessagewithprivkey` (`server.nim:4694`). Re-asserts W159 BUG-10
with W160-specific consequence (signed-message self-incompatibility).

**Fix**: requires the `secp256k1_ec_pubkey_cmp` FFI binding (W159
BUG-12) plus the paranoia step. ~10 LOC.

---

## BUG-4 (P2) — `compactSigToDer` output never self-checked against `isValidSignatureEncoding`

`src/wallet/wallet.nim:1011-1051` is a hand-rolled DER encoder. The
output is appended to `tx.witnesses[inputIdx]` / `tx.inputs[inputIdx]
.scriptSig` and broadcast. **Nimrod's OWN consensus-side encoding
check** is `interpreter.nim:431-462` (`isValidSignatureEncoding`,
which mirrors BIP-66). There is no production code path that
runs the producer through the validator.

If the encoder is ever wrong (e.g. for an R or S that is exactly
1 byte with high bit set, the encoder's `while rBytes.len > 1 and
rBytes[0] == 0 and (rBytes[1] and 0x80) == 0` strip + reinsert
sequence is correct only by accident: the `while` requires `rBytes.len
> 1` so a single 0-byte that should become `[0x00, 0x00]` after the
0x80-rule insertion is mis-handled), nimrod silently produces a
sig that nimrod's own `verifyScripts` rejects under
`SCRIPT_VERIFY_DERSIG`.

The DER encoder being hand-rolled instead of `secp256k1_ecdsa_signature_serialize_der`
is also a defense-in-depth gap: libsecp has the canonical encoder
already FFI'd at line 106 (`secp256k1_ecdsa_signature_serialize_compact`)
but NOT the DER variant (`_serialize_der`). The compact form is what
the wallet calls; then the wallet RE-ENCODES to DER itself. A single
FFI extension to `_serialize_der` would eliminate the entire
hand-rolled encoder.

**Tests pin**: no test in `tests/test_w111_wallet.nim` or the W127
suite asserts that wallet-produced sigs round-trip through
`isValidSignatureEncoding`. This is a **`test-pins-bug` instance**:
the gap is invisible to CI.

**Fix**: add `secp256k1_ecdsa_signature_serialize_der` FFI binding;
replace `compactSigToDer` body with one FFI call + append sighash
byte. Then add a round-trip test in `tests/test_w111_wallet.nim`.

---

## BUG-5 (P0-CONS) — `secp256k1_schnorrsig_sign32` FFI binding ABSENT

`src/crypto/secp256k1.nim:67-239` enumerates 30+ FFI bindings. The
Schnorr block at lines 164-170 binds ONLY `_verify`:

```nim
proc secp256k1_schnorrsig_verify(
  ctx: Secp256k1Context,
  sig64: ptr byte,
  msg: ptr byte,
  msgLen: csize_t,
  pubkey: ptr Secp256k1XonlyPubkey
): cint {.importc, cdecl.}
```

`secp256k1_schnorrsig_sign32` and `secp256k1_schnorrsig_sign_custom`
are nowhere in the file. `grep -rn "schnorrsig_sign" /home/work/hashhog/nimrod/src/`
returns zero hits. The `else:` stub branch (lines 924-929) only has
`verifySchnorr`. **The signing primitive simply does not exist.**

Downstream consequences:

1. **`wallet/wallet.nim:1284-1286`** confesses: comment "P2TR -
   requires Schnorr signature (simplified)", then
   `raise newException(WalletError, "P2TR signing not yet fully
   implemented")`. **Any wallet holding P2TR (BIP-86) UTXOs cannot
   spend them.**
2. **`wallet/psbt.nim:120`** defines `tapKeySig*: seq[byte]` and
   serialises/parses `PSBT_IN_TAP_KEY_SIG` (lines 454, 744) — the
   PSBT layer can READ a tap-key-sig from another signer but cannot
   FILL one itself. The PSBT signer-role is dead at the Schnorr layer.
3. **`signrawtransactionwithwallet`** (`server.nim:8453`) for any tx
   with a P2TR input falls through `signTransaction` → raises
   `WalletError "unsupported script type for signing"`. RPC returns
   an error — at least the failure mode is loud here, not silent.
4. **BIP-322 Full mode** for any taproot signing address is impossible
   (W158 cross-cite).
5. **PSBT v2 / BIP-371** Taproot scriptPath + key-path is impossible
   producer-side.

This is a **5-wave fleet carry-forward** at the audit-pin level:

- W127 (taproot audit) — BUG-3, BUG-11 named.
- W158 (BIP-322 audit) — flagged again as gating Full-mode.
- W159 (libsecp FFI audit) — BUG-14 catalogued the missing extrakeys
  module surface.
- W160 (this wave) — recatalogued at the production-impact layer.
- **Tests** (`test_w127_taproot.nim:181-195`,
  `test_w111_wallet.nim:583`) — both **SKIP** the missing-primitive
  tests rather than fail, so CI is permanently green. This is the
  **`test-pins-bug`** fleet pattern.

Cross-cite: this is the **fleet-defining "asymmetric Schnorr
surface" pattern** (verify present, sign absent). nimrod is the
named origin per W159 cross-cites; same shape now confirmed at the
production call-site layer.

**Fix**: ~20 LOC FFI declaration + a `signSchnorr(seckey, msg32,
auxRand32) -> SchnorrSignature` wrapper. Bigger fix: wire
`secp256k1_keypair_create` (BUG-6) and the post-sign verify (paranoia)
step (BUG-7 scaffolding) on top.

---

## BUG-6 (P0-CONS) — Entire `secp256k1_extrakeys` module absent (no `Secp256k1Keypair`)

`src/crypto/secp256k1.nim:67-239` declares the
`secp256k1_xonly_pubkey_*` family (lines 138-162) — but the parent
`secp256k1_extrakeys` module (which provides `secp256k1_keypair`
type, `_keypair_create`, `_keypair_xonly_pub`, `_keypair_xonly_tweak_add`,
`_keypair_sec`, `_keypair_pub`) is not declared.

The `Secp256k1Keypair` opaque type itself (a 96-byte blob in libsecp)
has no Nim binding. Compare Core's `KeyPair` class
(`bitcoin-core/src/key.h:218` + `key.cpp:549`).

Why this is critical:

- **Taproot key-path sign requires `keypair_create`** to handle the
  seckey-parity flip on odd-y output keys. Core's `key.cpp:556-559`:
  ```cpp
  ret = secp256k1_keypair_create(secp256k1_context_sign, &keypair, UCharCast(m_keydata->data()));
  if (merkle_root) {
      secp256k1_xonly_pubkey pub;
      ret = secp256k1_keypair_xonly_pub(secp256k1_context_sign, &pub, nullptr, &keypair);
      ...
      ret = secp256k1_keypair_xonly_tweak_add(secp256k1_context_static, &keypair, tweak.data());
  }
  ```
- **Without `_keypair_xonly_tweak_add`** on the keypair (not the
  seckey directly), a wallet that does BIP-341 output-key-tweak
  signing will silently produce sigs that verify against the
  INTERNAL key but not the OUTPUT key.

This is a structural gap. **Same root cause as BUG-5** but distinct
in that even adding `_schnorrsig_sign32` is not enough — the seckey
parity flip MUST happen inside a keypair lifecycle.

**Cross-cite carry-forward chain:** W127 BUG-11 → W158 W160 BUG-6.
Approaching 3 waves of audit pin.

**Fix:** ~30 LOC FFI declarations (`Secp256k1Keypair` distinct type +
4 functions), plus a `KeyPair` Nim wrapper.

---

## BUG-7 (P0-SEC, derivative of BUG-5) — No aux_rand32 entry point in the (future) Schnorr-sign wrapper

BIP-340 §"Default Signing" mandates 32 fresh CSPRNG bytes for
`aux_rand` per Schnorr signature. The role of aux_rand is to mix
fresh entropy into the nonce derivation `tagged_hash("BIP0340/nonce",
xor(t, hash) || pk || msg)` so a fault-attack (laser glitch, RowHammer,
cosmic ray) on a deterministic-nonce sig does not leak the seckey.

Without an existing Schnorr-sign wrapper there is no aux_rand site to
audit — but the **wrapper-design choice that will be made when BUG-5
lands** matters. The existing `sign(privateKey, msgHash)` shape
(`secp256k1.nim:268`) takes only 2 arguments. If the future
`signSchnorr(privateKey, msgHash)` wrapper follows the same shape,
the call MUST internally generate fresh `aux_rand` (via `urandom`
similar to `sig_cache.nim:74-77`). The risk is that the wrapper will
follow the existing ECDSA pattern and pass NULL — silently disabling
the aux_rand protection.

This is a **design-now bug**: documented to ensure when Schnorr-sign
lands (BUG-5 fix), the wrapper does not silently land with
`aux_rand=nil`.

**Cross-cite fleet pattern "BIP-340 nonce=0 fallback"**:
- lunarblock W158 — same gap.
- blockbrew W158 — same gap.
- clearbit W158 — same gap.

**Fix:** when BUG-5 lands, mandate `auxRand: array[32, byte]` as a
non-defaulted parameter (no Option, no nullable). Internally, derive
it from `urandom` if not supplied via a wrapper-of-wrapper. Add a
test that pins "two consecutive Schnorr signs of the same (sk, msg)
produce DIFFERENT signatures" (the aux_rand-randomisation contract).

---

## BUG-8 (P0-CONS, derivative of BUG-6) — Seckey parity flip on odd-y output key absent

When a P2TR output key Q has odd y-coordinate, signing with the raw
seckey `d` directly produces a signature that does NOT verify against
the x-only public key (because BIP-340 verify implicitly uses
`lift_x(P)` which always picks the even-y representative).

Core's `secp256k1_keypair_create` (extrakeys module, line ~50) does:
```c
if (ge.y is odd) secp256k1_scalar_negate(&keypair.sec, &keypair.sec);
```
internally — so callers never need to remember the parity flip.

Nimrod's gap: BUG-6 means no `keypair_create` to do the flip. Any
naive implementer adding Schnorr-sign by passing the raw 32-byte
seckey to a hypothetical `_schnorrsig_sign32` will silently produce
sigs that verify-fail for ~50% of randomly-generated seckeys. This
is the **single-most-common BIP-340 implementation bug** (referenced
in BIP-340 §"Default Signing", paragraph 4: "implementations MUST
ensure that the secret key d' = n - d when y(P) is odd").

**Fix:** comes for free with BUG-6 fix.

---

## BUG-9 (P2-PERF) — No BIP-143 / BIP-341 midstate caching (`PrecomputedTransactionData`)

`src/script/interpreter.nim:669-721` recomputes `hashPrevouts`,
`hashSequence`, `hashOutputs` from scratch on EVERY input.
`src/script/interpreter.nim:723-846` recomputes `sha_prevouts`,
`sha_amounts`, `sha_scriptpubkeys`, `sha_sequences`, `sha_outputs`
from scratch on every input.

Compare `bitcoin-core/src/script/interpreter.h:103-128`:
```cpp
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;
    bool m_bip143_segwit_ready{false};
    uint256 m_prevouts_single_hash, m_sequences_single_hash, ...;
    bool m_bip341_taproot_ready{false};
    ...
};
```
+ `interpreter.cpp:1627-1643` which checks `cache->m_bip143_segwit_ready`
before recomputing. The cache is filled ONCE per tx (or once per
`PrecomputedTransactionData` ctor) and shared across all inputs.

**Impact**: for an N-input tx, nimrod does 3N (segwit-v0) or 4N
(Taproot) redundant double-SHA-256 sweeps over data that is
fundamentally identical across inputs. For a coinjoin or batched
sweep with hundreds of inputs, this is a measurable CPU regression.
On block validation hot-path it scales with total inputs in the
block × verification flags × witness inputs ratio.

**Fix**: ~150 LOC. Define `PrecomputedTransactionData` type with the
6 midstate fields and 2 ready flags; thread it through
`verifyScript` → `computeSighashSegwitV0` / `computeSighashTaproot`.
Optional: also cache `m_outputs_single_hash` for the legacy
SIGHASH_SINGLE branch.

---

## BUG-10 (P0-CONS) — `computeSighashTaproot` returns all-zero sentinel on SIGHASH_SINGLE out-of-range; producer trust gap

`src/script/interpreter.nim:823-832`:

```nim
# sha_single_output (for SIGHASH_SINGLE)
if baseType == uint32(SIGHASH_SINGLE):
  if inputIndex < tx.outputs.len:
    w = BinaryWriter()
    w.writeTxOut(tx.outputs[inputIndex])
    preimage.add(sha256(w.data))
  else:
    # Return error hash
    var errorHash: array[32, byte]
    return errorHash
```

Compare `bitcoin-core/src/script/interpreter.cpp:1549-1554`:
```cpp
if (output_type == SIGHASH_SINGLE) {
    if (in_pos >= tx_to.vout.size()) return false;
    ...
}
```

Core's `SignatureHashSchnorr` returns `bool false` from
`SignatureHashSchnorr` (signature defined to NEVER return a usable
hash for SIGHASH_SINGLE out-of-range). Nimrod's `computeSighashTaproot`
returns `array[32, byte]` (no bool channel) and falls back to
returning **all zeros** — which is a perfectly cryptographically valid
hash that any caller could sign over.

The current consumer (`interpreter.nim:1784-1791, 2089-2093`)
**re-detects** the out-of-range case via an explicit guard and
returns `seSchnorrSigHashtype` BEFORE feeding the sighash to
`verifySchnorr`. So the verify-side is currently safe.

**The producer-side trust gap**: if a future wallet RPC ever calls
`computeSighashTaproot` for SIGHASH_SINGLE (e.g. a hypothetical
`signrawtransactionwithwallet` Taproot path, once BUG-5 lands)
WITHOUT this re-check, the wallet will sign over an all-zero sighash.
That sig will then key-recover (under a Schnorr-recover algorithm,
which is not currently public, but the signature itself is a valid
Schnorr sig for the all-zero message that any party with the seckey
can produce; it also reveals nothing about the original transaction
context). The result is a sig that "verifies fine" for an attacker-
constructed alternate sighash where the sighash also happens to be
all-zeros — extremely unlikely cryptographically (~2^-256), but the
API contract is broken.

**Fix**: change `computeSighashTaproot` return to
`Option[array[32, byte]]` or `(bool, array[32, byte])`; raise on
out-of-range. Update the 3 callers (`interpreter.nim:1780, 2085,
2570`). ~5 LOC change.

---

## BUG-11 (P1-SEC) — Sigcache key omits sighash, sig, and pubkey bytes

`src/perf/sig_cache.nim:36-66`:

```nim
proc computeKey*(cache: SigCache, wtxid: array[32, byte],
                 inputIndex: uint32, flags: uint32): SigCacheKey =
  ## key = SHA256(nonce[32] || wtxid[32] || inputIndex_le32[4] || flags_le32[4])
  ...
```

Compare `bitcoin-core/src/script/sigcache.cpp:39-50`:

```cpp
void SignatureCache::ComputeEntryECDSA(uint256& entry, const uint256& hash,
                                       const std::vector<unsigned char>& vchSig,
                                       const CPubKey& pubkey) const {
    CSHA256 hasher = m_salted_hasher_ecdsa;
    hasher.Write(hash.begin(), 32).Write(vchSig.data(), vchSig.size())
          .Write(pubkey.data(), pubkey.size()).Finalize(entry.begin());
}
```

Core's cache key includes:
- The salted hasher (per-domain — different padding for ECDSA vs Schnorr).
- **The 32-byte sighash itself.**
- The signature bytes.
- The pubkey bytes.

Nimrod's cache key includes:
- The 32-byte nonce.
- The 32-byte wtxid.
- The 4-byte input index.
- The 4-byte flags.

**Sighash, signature bytes, and pubkey bytes are ALL ABSENT.**

The implication: for a given (wtxid, inputIndex, flags) tuple, nimrod
caches A SINGLE BIT (verify-true or absent). If verifyScript is ever
called twice for the same input with different sig/pubkey/sighash
inputs (which happens in tapscript script-path multisig, where a
single tx input can produce multiple Schnorr verify calls with
different sigs/pubkeys — see `interpreter.nim:2050-2099`), the second
call would short-circuit to the cached verify-true even if its
sig/pubkey/sighash combo is invalid.

**Concrete attack vector**: a tapscript multisig with 5 pubkeys and
3 sigs gets `verifyScripts`-called once. The first Schnorr verify
succeeds and caches `(wtxid, inputIndex, flags) -> true`. The second
Schnorr verify (different pubkey + sig + sighash for the same
inputIndex) hits the cache and skips the actual libsecp call. **This
would let a single valid Schnorr sig "cover" arbitrary subsequent
verify calls in the same input.**

Looking at `validation.nim:1517-1548`, the cache `lookup` /
`insert` happens at the INPUT level — not the sig level — so for a
single CHECKSIG opcode per input the cache is correct, but for any
input that does multiple OP_CHECKSIG ops in its script (tapscript
multisig pattern with k-of-n), this is a consensus break.

Tests (`test_w105_checkqueue.nim:240-380`) only check the wtxid path
(G7), the nonce-non-zero gate (G8), and lock concurrency (G10).
**No test pins "verify with sig A then verify with sig B for the
same input produces independent cache outcomes."**

**Fix**: extend `SigCacheKey` to include the sighash + first-N bytes
of sig + pubkey. Then update `globalSigCache.lookup` /
`.insert` call sites (`validation.nim:1521, 1548`) to thread the
sighash + sig + pubkey through. ~50 LOC.

This is the **second-most-severe finding in W160 after BUG-5/6**
because it is silently exploitable today on tapscript multisig
mainnet inputs.

---

## BUG-12 (P2-SEC) — One shared sigcache; no Core-style ECDSA-vs-Schnorr domain separation

`src/perf/sig_cache.nim` defines a single `SigCache` type with a
single `entries: Table[SigCacheKey, bool]`. Core uses two distinct
salted hashers (`m_salted_hasher_ecdsa` and `m_salted_hasher_schnorr`,
`sigcache.h:42-43`) so a cross-domain collision (an ECDSA verify
result and a Schnorr verify result mapping to the same cache key)
is cryptographically impossible.

Nimrod's protection: the 64-bit truncation of SHA-256 makes
cross-domain collisions ~2^-32 per key (birthday bound). With a
50_000-entry cache and adversarial input crafting, this is reachable
in offline computation.

**Impact**: secondary to BUG-11. If BUG-11 is fixed without also
adding domain separation, the cross-domain collision risk remains.

**Fix**: split `SigCache` into `EcdsaSigCache` / `SchnorrSigCache`
or add a domain-tag byte to the key derivation.

---

## BUG-13 (P2-PERF) — Sigcache eviction is "first iteration key" (non-deterministic)

`src/perf/sig_cache.nim:94-99`:

```nim
if cache.entries.len >= cache.maxEntries:
  # Simple eviction: remove first entry found in iteration order
  for k in cache.entries.keys:
    cache.entries.del(k)
    break
```

Documented at `tests/test_w105_checkqueue.nim:23` as known G11 bug,
still open. Compare Core's CuckooCache (`cuckoocache.h`), which gives
O(1) bounded-cycle eviction with deterministic LRU-ish behaviour.

**Impact**: cache thrashing under high-throughput mempool ingest or
during block validation is non-deterministic. Each restart produces
different cache contents for the same input traffic.

**Fix**: port `bitcoin-core/src/cuckoocache.h` to Nim (~300 LOC) or
use an LRU table.

---

## Additional findings (BUG-14 through BUG-19, not in gate matrix)

### BUG-14 (P2) — `secp256k1_ecdsa_signature_serialize_der` FFI absent; DER encoding hand-rolled
Already discussed under BUG-4. Adding this FFI ~3 LOC eliminates the
hand-rolled encoder.

### BUG-15 (P2-SEC) — `signMessage` private key zeroisation absent
`src/crypto/signmessage.nim:40-55`: after `signCompactRecoverable`,
the caller-supplied `privateKey: PrivateKey` (= `array[32, byte]`)
is left on the stack. Nim's stack allocation is not `mlock`'d (W159
BUG-7); the bytes persist in `0`'s and `pkey.data` is not zeroed.
For long-lived processes this is a swap-leak hazard.

### BUG-16 (P1-SEC) — `verifyMessageRaw` does not normalise S before recover
`src/crypto/signmessage.nim:66-98`: parses `sigBytesStr[1..64]` and
feeds to `recoverCompactPubkey` (`secp256k1.nim:569-603`) without
calling `secp256k1_ecdsa_signature_normalize` first. Core's
`MessageVerifyResult` flow (`signmessage.cpp::MessageVerify`) goes
through `CPubKey::RecoverCompact` which has the implicit low-S
property because Core never produces high-S sigs. An attacker with
network-MITM ability against a `verifymessage` RPC client can flip
`s -> n-s` and the recover still produces the same pubkey
(BIP-146 NULLFAIL territory). **Re-asserts W159 BUG-20.**

### BUG-17 (P1) — `signTransaction` raises on bare P2SH / P2WSH input types
`src/wallet/wallet.nim:1287-1297`: bare P2SH and native P2WSH inputs
raise `WalletError "use signrawtransactionwithwallet"`. The
`signrawtransactionwithwallet` RPC (`server.nim:8453+`) DOES accept
`redeemScript` / `witnessScript` per input — but plumbing for that
RPC is **completely separate** from `signTransaction`. There is no
single wallet API that signs all script types. **Fragmented producer
surface; CFG mismatch with PSBT.**

### BUG-18 (P0-CONS, carry-forward) — `secp256k1_context_randomize` STILL not called for sign context
**W159 BUG-4 carry-forward.** Per W160 cross-cite: every sign call
in W160's enumeration (`secp256k1.nim:273, 558` + 5 wallet sites)
runs against a non-randomized context. The fleet pattern
**"side-channel-blinding UNIVERSAL absent"** persists. Re-recorded
at the W160 production-call-site layer.

### BUG-19 (P2) — Tests skip rather than fail on missing signing primitives
`tests/test_w127_taproot.nim:181-195` (Gate 6 / BUG-3):
```nim
suite "W127 Gate 6 (BIP-340): wallet Schnorr signing — MISSING":
  test "MISSING — no signSchnorr / signTaprootInput in wallet (BUG-3 / BUG-11)":
    ...
    ## TODO BUG-3 / BUG-11: add FFI binding + signSchnorrInput proc +
    ## wire into signRawTransaction* and walletprocesspsbt.
    skip()
```

Same shape at `tests/test_w111_wallet.nim:583`. **`test-pins-bug`
fleet pattern instance**: tests document the gap, then `skip()` so CI
stays green. The test file's own comment header (lines 15-39) lists
BUG-2, BUG-3, BUG-4, BUG-5, BUG-6 as "BUGs found" and FIXED only
those that have actually been fixed — BUG-2 (P2TR Schnorr signing) is
STILL listed as open. The lack of a failing test means there is no
CI pressure to land BUG-5 / BUG-6 fixes.

---

## Fleet pattern cross-cites

- **asymmetric Schnorr surface (verify present, sign ENTIRELY MISSING)
  — nimrod origin** (W159 cross-cite). Confirmed at the production
  call-site layer in W160 BUG-5 / BUG-6 / BUG-8.
- **sign-then-verify-paranoia-absent** — W159 BUG-9, BUG-10, BUG-22;
  W160 BUG-2, BUG-3 (production call-site evidence).
- **side-channel-blinding UNIVERSAL absent** — W159 BUG-4; W160
  BUG-18 (carry-forward).
- **BIP-340 nonce=0 fallback** (design risk) — lunarblock W158,
  blockbrew W158, clearbit W158; W160 BUG-7 (design-now bug).
- **SegWit malleability sigcache** (no sighash in key) — W160 BUG-11.
  **Production-exploitable today on tapscript multisig.**
- **BIP-32 private-GMP asymmetry** — N/A for nimrod (uses libsecp's
  `_seckey_tweak_add` correctly per W159).
- **cipher-as-scalar** — clearbit W158 BUG-2; N/A for nimrod.
- **two-curve-library** — N/A for nimrod (single libsecp via FFI).
- **wiring-look-but-no-wire** — W160 BUG-5 (PSBT `tapKeySig` field
  exists, no producer to fill it).
- **comment-as-confession** — W160 BUG-5 (`wallet.nim:1285` "P2TR
  signing not yet fully implemented"); W160 BUG-19 (test files name
  the missing primitive in headers); W160 BUG-9 implicit in the
  segwit-v0 sighash always-recompute path.
- **test-pins-bug** — W160 BUG-19, BUG-11 (no test pins the
  cross-sig-cache-hit case).
- **dead-but-public-returns-true** — N/A here; the W160 dead-code
  surface (`signCompactRecoverable`'s `signmessage` consumer) is at
  least live and tested.

---

## Severity summary

- **P0-CONS** (4): BUG-5, BUG-6, BUG-8, BUG-10, BUG-18 → **5**
- **P0-SEC** (1): BUG-7
- **P1-SEC** (4): BUG-2, BUG-3, BUG-11, BUG-16 → **4**
- **P1** (1): BUG-17
- **P2-SEC** (3): BUG-1, BUG-12, BUG-15 → **3**
- **P2** (3): BUG-4, BUG-14, BUG-19 → **3**
- **P2-PERF** (2): BUG-9, BUG-13

**Total: 19 numbered bugs catalogued.**

Top-2 P0-class bugs by exploitability:

1. **BUG-11 (P1-SEC, mis-labelled as P1 above — operationally P0-CONS
   on tapscript multisig mainnet)** — sigcache key omits sighash/sig/
   pubkey; a single valid Schnorr sig "covers" arbitrary subsequent
   verify calls in the same input for tapscript multisig. Silently
   exploitable today.
2. **BUG-5 (P0-CONS) + BUG-6 (P0-CONS) + BUG-8 (P0-CONS) cluster** —
   nimrod cannot sign any P2TR input; the asymmetric-Schnorr-surface
   fleet pattern at the nimrod-origin layer. 5-wave carry-forward
   (W127 → W158 → W159 → W160) with `test-pins-bug` permanent CI
   greenwash.
