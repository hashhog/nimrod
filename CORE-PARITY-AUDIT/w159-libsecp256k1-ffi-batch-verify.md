# W159 — libsecp256k1 FFI wrapping + batch verification (nimrod)

**Wave:** W159 — libsecp256k1 FFI bindings: process-singleton
`secp256k1_context` lifecycle, `secp256k1_context_create` /
`_clone` / `_destroy`, **`secp256k1_context_randomize` (side-channel
blinding)**, `secp256k1_context_static` vs sign-context split,
`SECP256K1_CONTEXT_NONE` (post-v0.4.0) vs deprecated
`SECP256K1_CONTEXT_VERIFY` / `SECP256K1_CONTEXT_SIGN` flag pair,
`secp256k1_selftest`, `secp256k1_ec_seckey_verify` (scalar range
check), `secp256k1_ec_pubkey_parse` (on-curve check),
`secp256k1_ec_pubkey_cmp` (sign-then-verify paranoia step),
`secp256k1_ecdsa_signature_normalize` (low-S), `secp256k1_schnorrsig_verify`
(BIP-340), Schnorr verify batching (TODO upstream), `secp256k1_keypair`
(extrakeys taproot signing), `secp256k1_tagged_sha256`,
`secp256k1_ec_seckey_tweak_add` (BIP-32 CKD), `secp256k1_xonly_pubkey_*`,
`secp256k1_ecdsa_sign_recoverable`, `secp256k1_ellswift_*` (BIP-324),
sign-then-verify paranoia (`CKey::Sign` + `CKey::SignCompact` re-verify
step), `memory_cleanse` of private keys / nonces, `LockedPool` / `mlock`
secret storage, Nim-side `=destroy` / `proc` finalizer for context cleanup.

**Scope:** discovery only — NO production code change in W159.

**Bitcoin Core references**
- `bitcoin-core/src/secp256k1/include/secp256k1.h:212-221` — `SECP256K1_CONTEXT_NONE`
  is the only flag callers should pass. `SECP256K1_CONTEXT_VERIFY` and
  `SECP256K1_CONTEXT_SIGN` are explicitly marked **"Deprecated context flags.
  These flags are treated equivalent to SECP256K1_CONTEXT_NONE."** (post
  v0.4.0; the function-pointer tables are now per-call, not per-context).
- `bitcoin-core/src/secp256k1/include/secp256k1.h:245-249` — `secp256k1_context_static`
  is the static context for verify-only work. Renamed from the deprecated
  `secp256k1_context_no_precomp`. **Cannot be cloned and must NOT be
  passed to `_destroy`.**
- `bitcoin-core/src/secp256k1/include/secp256k1.h:267` — `secp256k1_selftest()` —
  callers SHOULD run this once before any consensus-critical verify call,
  *especially* before using `secp256k1_context_static`.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:286-290` — context-create
  documentation: "*It is highly recommended to call
  `secp256k1_context_randomize` on the context before calling
  signing functions. This will provide enhanced protection against
  side-channel leakage*."
- `bitcoin-core/src/secp256k1/include/secp256k1.h:685-714` —
  `secp256k1_ec_seckey_verify` (returns 1 if scalar in `[1, n-1]`),
  `secp256k1_ec_seckey_negate` (returns 0 if invalid). Callers SHOULD
  always seckey-verify untrusted inputs before passing to `_sign`,
  `_tweak`, or `_pubkey_create`.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:838` — `secp256k1_context_randomize`
  (returns 1 on success, 0 on failure; must be invoked with 32 bytes of
  fresh entropy after `_create` and ideally re-invoked periodically).
- `bitcoin-core/src/secp256k1/include/secp256k1.h:875` — `secp256k1_tagged_sha256(out32, tag, taglen, msg, msglen)`
  computes `SHA256(SHA256(tag) || SHA256(tag) || msg)`. Wrapping this in
  the official FFI avoids re-implementing the 64-byte tag-hash prefix in
  application code (one less off-by-one).
- `bitcoin-core/src/key.cpp:79` — `ec_seckey_import_der` calls
  `secp256k1_ec_seckey_verify(ctx, out32)` and `memset`s on failure;
  blocking malformed DER from poisoning downstream sign calls.
- `bitcoin-core/src/key.cpp:159` — `CKey::Check(vch)` (= `secp256k1_ec_seckey_verify`
  against `secp256k1_context_static`). Called by `MakeNewKey` in a
  rejection-sampling loop.
- `bitcoin-core/src/key.cpp:162-168` — `CKey::MakeNewKey` rejection-samples
  with `GetStrongRandBytes(*keydata)` until `Check()` returns true.
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: signs **and then
  re-verifies** the signature by calling `secp256k1_ec_pubkey_create` +
  `secp256k1_ecdsa_verify`, with `assert(ret)` if the post-sign verify
  fails. This is Bitcoin Core's defense against bit-flip RAM corruption
  between sign and downstream broadcast (the same paranoia that bit Sony
  on the PS3 in 2010).
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact` mirrors the
  same paranoia step: after `_sign_recoverable` + `_serialize_compact`,
  it does `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_recover` +
  `secp256k1_ec_pubkey_cmp` and asserts equality.
- `bitcoin-core/src/key.cpp:571-587` — `ECC_Start`: creates a sign
  context with `SECP256K1_CONTEXT_NONE` (NOT the deprecated `_SIGN`
  flag), then **immediately** calls `secp256k1_context_randomize(ctx,
  vseed.data())` with 32 bytes of `GetRandBytes`. `assert(ret)` on
  failure: refuses to run with side-channel mitigation disabled.
- `bitcoin-core/src/key.cpp:560-563` — `CKey::Sign`'s call to
  `secp256k1_ecdsa_sign_recoverable` is wrapped in a `memory_cleanse`
  fallback: `if (!ret) memory_cleanse(sig.data(), sig.size())`.
- `bitcoin-core/src/pubkey.cpp:29` — `ECC_Context::ECC_Context()`
  calls `secp256k1_selftest()` immediately on construction (paired
  with `ECC_Start`).
- `bitcoin-core/src/support/lockedpool.cpp` — `LockedPool` / `mlock`-backed
  arena for `secure_allocator<unsigned char>`, used by `CKey::keydata`
  storage so swap-out pages cannot leak the secret. `key.cpp:580`
  uses `secure_allocator` on the blinding-seed vector too.
- BIP-340 §"Default Signing" — Schnorr nonce derivation is
  `aux_rand`-mixed with `BIP0340/aux` and `BIP0340/nonce` tags; libsecp's
  `secp256k1_nonce_function_bip340` implements this. Callers MUST pass
  fresh `aux_rand` per signature for side-channel resistance.
- BIP-340 §"Batch Verification" — algorithm exists in the spec, but
  upstream libsecp256k1 has **not yet exposed `secp256k1_schnorrsig_verify_batch`**
  (see `bitcoin-core/src/secp256k1/src/modules/schnorrsig/tests_impl.h:197`
  and lines 854/877: every test stub has a `(TODO)` next to verify_batch).
  So this gate is "absent fleet-wide" by upstream design — but Nim
  callers should at least know the API will appear and plan for it.

**Files audited**
- `src/crypto/secp256k1.nim` — entire file (990 lines). FFI bindings
  + high-level wrappers. Hot spots:
  - lines 22-28: context-flag constants (the `_VERIFY` / `_SIGN` /
    `_NONE` values, defined locally).
  - lines 67: build gate `when defined(useSystemSecp256k1)`; the
    `else:` branch (lines 888-989) is the stub fallback.
  - lines 70-239: FFI declarations.
  - lines 241-252: `globalContext: Secp256k1Context` (process
    singleton), `initSecp256k1()`, `getContext()` (lazy init).
  - lines 254-266: `derivePublicKey` (calls
    `secp256k1_ec_pubkey_create` without prior seckey-verify).
  - lines 268-302: `sign` / `verify` (compact ECDSA).
  - lines 334-505: `ecdsaSignatureParseDerLax`, `verifyDerLax`,
    `isLowS`.
  - lines 523-546: `verifySchnorr` (BIP-340).
  - lines 548-567: `signCompactRecoverable` — **no sign-then-verify
    paranoia step**.
  - lines 569-603: `recoverCompactPubkey`.
  - lines 631-663: `tweakXonlyPubkey` — BIP-341 taproot tweak.
  - lines 669-718: `tweakSeckeyAdd` / `tweakPubkeyAdd` (BIP-32 CKD).
  - lines 724-774: `ellswiftCreate` / `computeBIP324ECDHSecret`.
  - lines 776-843: `CryptoEngine` (per-instance context).
  - lines 849-886: benchmark helpers (production code path).
- `src/crypto/signmessage.nim` — `MessageMagic`, `messageHash`,
  `signMessage`, `verifyMessageRaw`. Uses
  `signCompactRecoverable` / `recoverCompactPubkey` from secp256k1.
- `src/perf/parallel_verify.nim` — thread-local `CryptoEngine` for
  per-thread context. **W159 hot spot**:
  - line 36: `var threadCrypto {.threadvar.}: CryptoEngine`
  - lines 39-43: `getThreadCrypto()` — creates a new
    `CryptoEngine` (= new full `secp256k1_context`) per worker
    thread; never destroys.
- `src/script/interpreter.nim` — script eval. Schnorr / ECDSA verify
  call sites:
  - line 553-560: `taggedHash(tag, data)` — Nim-side
    re-implementation of BIP-340's `SHA256(SHA256(tag) ||
    SHA256(tag) || data)`. Bypasses `secp256k1_tagged_sha256`.
  - lines 1693, 1717, 1893, 1901: `verifyDerLax` (legacy / segwit-v0
    ECDSA verify).
  - lines 1793, 2095, 2578: `verifySchnorr` (BIP-340 schnorr verify;
    key-path Taproot, tapscript CHECKSIG).
  - lines 2662, 2983: `tweakXonlyPubkey` (BIP-341 taproot output
    commitment check).
- `src/wallet/wallet.nim` — wallet signing.
  - lines 219-255: BIP-32 master-key derivation; `result.publicKey =
    derivePublicKey(result.key)` without `seckey_verify`.
  - lines 312-339: `deriveChild` BIP-32 CKD via `tweakSeckeyAdd` /
    `tweakPubkeyAdd`.
  - lines 1102, 1128, 1165, 1205, 1237: ECDSA `sign(privKey, sighash)`
    call sites (P2WPKH, P2PKH, P2SH-P2WPKH, P2WSH, P2SH-P2WSH).
  - lines 1390-1452: `unlock` / `lock` paths — clears `wallet.seed`,
    `wallet.masterKeyCache`, `wallet.masterKey.key` (manual loop,
    not `memory_cleanse`-style barrier).
- `src/wallet/crypter.nim` — `WalletCrypter` AES-256-CBC. Lines 187-193:
  `clearKey` (manual zero loop).
- `src/network/bip324.nim` — BIP-324 wrapper.
  - lines 143-149: `ellswiftCreate` call.
  - lines 247-254: `memory_cleanse`-equivalent zeroing of
    `ecdhSecretMut`, `hkdfMut`, `c.privateKey`. Good.
- `src/rpc/server.nim:2722-2740` — `isFullyValidPubkeyBytes`:
  uncompressed branch (lines 2732-2738) skips `secp256k1_ec_pubkey_parse`
  on-curve check by self-confession ("Structural check only … we accept
  well-formed uncompressed keys as valid").
- `src/rpc/server.nim:4625-4710` — `signmessage` / `verifymessage` /
  `signmessagewithprivkey` RPC handlers; `signMessageWithPrivkey`
  decodes WIF without calling `seckey_verify` on the bytes.
- `src/storage/snapshot.nim:35,170-250` — pubkey decompression in the
  UTXO snapshot decoder; calls `decompressPubkey` (which does the
  parse step but not seckey-verify, which is N/A there).
- `tests/test_crypto.nim:109-167` — only "sign and verify roundtrip"
  + "verify fails with wrong message" + `CryptoEngine` lifecycle
  test. No test pins the side-channel blinding, the sign-then-verify
  paranoia, the seckey scalar-range check, or the on-curve gate
  for uncompressed pubkeys.
- `tests/test_bench_crypto.nim` — referenced by the benchmark helper
  (file exists; only timing assertions).

---

## Gate matrix (28 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Context lifecycle | G1: process-singleton context | PARTIAL (`secp256k1.nim:241` + per-thread via `parallel_verify.nim:36` + per-engine via `CryptoEngine`) — **BUG-7 (P2)** below |
| 1 | … | G2: context destroyed on shutdown | **BUG-1 (P2)** — `globalContext` never destroyed; no `=destroy` hook; no `addQuitProc` |
| 1 | … | G3: `secp256k1_selftest()` called once at startup | **BUG-2 (P1-SEC)** — FFI declaration absent; never invoked |
| 1 | … | G4: `SECP256K1_CONTEXT_NONE` for sign context (post v0.4.0) | **BUG-3 (P2)** — uses deprecated `SECP256K1_CONTEXT_SIGN \| SECP256K1_CONTEXT_VERIFY` (`secp256k1.nim:246, 785`) |
| 2 | **Side-channel blinding** | G5: `secp256k1_context_randomize` called after `_create` | **BUG-4 (P0-SEC)** — FFI declaration absent; never invoked. Every sign path uses non-blinded scalar arithmetic. **Cross-cite: lunarblock W158 BUG-7, clearbit W158 BUG-7, blockbrew W158 BUG-7.** |
| 2 | … | G6: blinding re-randomized periodically | **BUG-5 (P2-SEC)** — derivative of BUG-4: can't re-randomize what was never randomized in the first place |
| 3 | Secret-key hygiene | G7: `secp256k1_ec_seckey_verify` called on untrusted seckey bytes | **BUG-6 (P1-SEC)** — FFI declaration absent; `derivePublicKey`, `sign`, `signCompactRecoverable`, `tweakSeckeyAdd` all accept arbitrary 32-byte arrays. `signMessageWithPrivkey` (`server.nim:4707`) is the public RPC entry-point. |
| 3 | … | G8: `LockedPool` / `mlock`-backed `secure_allocator` for keydata | **BUG-7 (P2-SEC)** — Nim `array[32, byte]` stack storage; nothing prevents page-out / swap to disk |
| 3 | … | G9: `memory_cleanse`-style barrier on key zero (compiler can't elide) | **BUG-8 (P1-SEC)** — `crypter.nim:188-193`, `wallet.nim:1443-1450` use plain Nim `for i in 0..<.len: x[i] = 0` loops; LLVM/GCC `-O3` will elide these. `bip324.nim:247-254` uses `zeroMem`, which *also* can be DSE'd unless the compiler treats it as a barrier (which Nim's `zeroMem` does NOT guarantee). |
| 4 | Sign-then-verify paranoia | G10: `CKey::Sign` re-verifies the signature before returning | **BUG-9 (P2-SEC)** — `secp256k1.nim:268-280` (`sign`) returns immediately; no `_ec_pubkey_create` + `_ecdsa_verify` round-trip. Compare `bitcoin-core/src/key.cpp:228-234`. |
| 4 | … | G11: `CKey::SignCompact` re-recovers pubkey and compares | **BUG-10 (P2-SEC)** — `secp256k1.nim:548-567` (`signCompactRecoverable`) returns immediately; no `_ecdsa_recover` + `_ec_pubkey_cmp` round-trip. Compare `bitcoin-core/src/key.cpp:262-269`. Affects every `signmessage` / `signmessagewithprivkey` call. |
| 5 | Pubkey validity | G12: `secp256k1_ec_pubkey_parse` for `IsFullyValid` semantics | **BUG-11 (P1-CONS)** — `rpc/server.nim:2722-2740` `isFullyValidPubkeyBytes`: uncompressed branch is **structural check only** by self-confession. Mismatch vs Core CPubKey::IsFullyValid (which always calls `secp256k1_ec_pubkey_parse`). |
| 5 | … | G13: `secp256k1_ec_pubkey_cmp` FFI declaration | **BUG-12 (P2)** — FFI declaration absent; cannot do constant-time pubkey equality. |
| 6 | Schnorr / Taproot | G14: `verifySchnorr` wires `secp256k1_schnorrsig_verify` | PASS (`secp256k1.nim:523-546`) |
| 6 | … | G15: `secp256k1_schnorrsig_verify_batch` (BIP-340 batch) | **BUG-13 (P3)** — FFI absent. Upstream libsecp doesn't yet ship the function (TODO in `secp256k1/src/modules/schnorrsig/tests_impl.h:197`), so this gate is "blocked upstream" rather than a near-term fix — but the wrapper layer has no plan / no extension point. |
| 6 | … | G16: `secp256k1_keypair_create` + `_schnorrsig_sign_custom` for Taproot signing | **BUG-14 (P1)** — entire extrakeys module absent: no `secp256k1_keypair` type, no Schnorr signing FFI. Nim cannot sign Taproot key-path or script-path spends. Verify-only Taproot impl. |
| 6 | … | G17: `secp256k1_tagged_sha256` FFI declaration | **BUG-15 (P2)** — FFI absent; `script/interpreter.nim:553-560` re-implements the `SHA256(SHA256(tag) || SHA256(tag) || data)` recipe inline. Re-implementation works on tested vectors but is a duplicate code path with no upstream test sync. |
| 7 | Lax-DER / low-S | G18: lax-DER parser matches Core's `ecdsa_signature_parse_der_lax` | PASS (`secp256k1.nim:334-470`, ported from Core almost byte-for-byte) |
| 7 | … | G19: `secp256k1_ecdsa_signature_normalize` for LOW_S | PASS (`secp256k1.nim:521`, `isLowS`; also `verifyDerLax:502`) |
| 8 | Context wrapping | G20: Nim `=destroy` / finalizer on `CryptoEngine` calls `_destroy` | **BUG-16 (P2)** — `CryptoEngine` is `type ... object` with no `=destroy` hook (`secp256k1.nim:776-792`). Only the explicit `close()` proc destroys; if a thread panics in `verifyInputScript` (`parallel_verify.nim:45-74`) between `newCryptoEngine()` and a `defer: engine.close()`, the context leaks. |
| 8 | … | G21: `parallel_verify.nim` per-thread context destroyed on thread exit | **BUG-17 (P2)** — `threadCrypto {.threadvar.}` is set on first use (`parallel_verify.nim:39-43`), never destroyed. Each worker thread leaks one full `secp256k1_context` for the lifetime of the process. With Nim's `threadpool` recycling workers, this is bounded by core count, but still untracked. |
| 8 | … | G22: thread-local context randomized before first use | **BUG-18 (P1-SEC)** — `getThreadCrypto()` calls `newCryptoEngine()` which calls `secp256k1_context_create(SIGN | VERIFY)` with no `context_randomize`. Per-thread blinding identical to BUG-4. |
| 8 | … | G23: NULL/error-return checked on `_destroy` (must not pass static ctx) | **BUG-19 (P3)** — `CryptoEngine.close()` (`secp256k1.nim:790`) calls `_destroy` unconditionally; if a future refactor switches `e.ctx` to `secp256k1_context_static` (the recommended verify context), the unconditional `_destroy` will crash inside libsecp256k1. Defensive null check exists; static-context check does not. |
| 9 | Recoverable / message-sign | G24: header byte range check `[27, 34]` | PASS (`signmessage.nim:80`) |
| 9 | … | G25: low-S enforced on the recoverable sig (defense in depth) | **BUG-20 (P2-SEC)** — `signmessage.nim:90` and `secp256k1.nim:587-590` accept any S value on recovery. Core's libsecp implicitly always produces low-S, but `verifyMessageRaw` (the verify path) does not normalize before recover, so a malicious peer can flip `s -> n-s` and the recover still succeeds with the same pubkey (BIP-146 NULLFAIL territory). |
| 9 | … | G26: `secp256k1_context_static` for verify-only paths | **BUG-21 (P2)** — `secp256k1_context_static` not bound; every `_ecdsa_verify`, `_xonly_pubkey_parse`, `_ec_pubkey_parse` call uses the sign+verify context. Wastes ~256 KB of precomputed sign tables for verify-only nodes (e.g. headers-only / IBD-only configurations). |
| 9 | … | G27: `signmessagewithprivkey` WIF path validates scalar range | **BUG-22 (P1-SEC)** — `server.nim:4694-4707` decodes WIF and immediately signs; no `seckey_verify` on the 32-byte payload. A WIF that decodes to all-zeros or > `n` reaches `secp256k1_ecdsa_sign_recoverable` which will return 0 and the RPC raises `"Sign failed"` — but the user-facing error is generic and the failure is non-distinguished from a real RPC error. |
| 10 | Tests | G28: tests pin the security gates (blinding, paranoia, scalar range, on-curve) | **BUG-23 (P2)** — `tests/test_crypto.nim:109-167` covers only happy-path sign / verify roundtrip + `CryptoEngine` lifecycle. No test asserts side-channel blinding, sign-then-verify paranoia, scalar-range guard, or the uncompressed-pubkey on-curve check. **W158 cross-cite "test-pins-bug" pattern**: tests don't *pin* the wrong behaviour, but they don't pin the right behaviour either, so any regression here will be silent. |

---

## Severity bands

- **P0-SEC** (1): BUG-4
- **P1-SEC** (5): BUG-2, BUG-6, BUG-8, BUG-18, BUG-22
- **P1-CONS** (1): BUG-11
- **P1** (1): BUG-14
- **P2-SEC** (5): BUG-5, BUG-7, BUG-9, BUG-10, BUG-20
- **P2** (8): BUG-1, BUG-3, BUG-12, BUG-15, BUG-16, BUG-17, BUG-21, BUG-23
- **P3** (2): BUG-13, BUG-19

**Total: 23 bugs catalogued.**

---

## BUG-1 (P2) — `globalContext` never destroyed; no `=destroy` / `addQuitProc`

`src/crypto/secp256k1.nim:241-252`:

```nim
var globalContext: Secp256k1Context

proc initSecp256k1*() =
  if pointer(globalContext) == nil:
    globalContext = secp256k1_context_create(
      SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
    )

proc getContext(): Secp256k1Context =
  if pointer(globalContext) == nil:
    initSecp256k1()
  globalContext
```

The module-level `globalContext` is created lazily on first use and
**never destroyed**. There is no `=destroy` hook, no `addQuitProc`,
no `bind` to the Nim runtime exit path. On clean shutdown the
~256 KB sign+verify context is leaked; valgrind / heaptrack / sanitizer
runs against the node will report a "still reachable" allocation.

For a long-running node this is cosmetic, but it diverges from
`bitcoin-core/src/key.cpp:590-597` `ECC_Stop` (which is explicitly
ordered before main exit by the `ECC_Context` RAII guard at
`pubkey.cpp:25`).

**Fix:** add a `proc destroySecp256k1*()` and register it via
`addQuitProc destroySecp256k1`. Or use Nim's `=destroy` on a
distinct wrapper object held at module scope.

---

## BUG-2 (P1-SEC) — `secp256k1_selftest` FFI absent; never invoked

`src/crypto/secp256k1.nim:67-239` — the FFI block declares
`secp256k1_context_create`, `_destroy`, `_pubkey_create`, all the
sign / verify primitives, and the ellswift / tweak helpers. It does
NOT declare `secp256k1_selftest`.

Bitcoin Core's `ECC_Context::ECC_Context()`
(`bitcoin-core/src/pubkey.cpp:29`) calls `secp256k1_selftest()`
immediately. The selftest is documented in
`bitcoin-core/src/secp256k1/include/secp256k1.h:251-265` as
"highly recommended" before using any context, and it is the only
safeguard against a corrupted / mis-built libsecp256k1.so on the
system.

**Impact**: on a system where libsecp256k1 is corrupted (cosmic-ray /
mis-linked) the selftest is the canary. Without it, the node will
silently produce wrong signatures or accept wrong signatures. Given
nimrod operators may run against `-lsecp256k1` from any distro
package version, this is a real (if low-frequency) gap.

**Fix:** add the FFI line `proc secp256k1_selftest() {.importc, cdecl.}`
and invoke it once at startup (alongside the proposed `destroySecp256k1`).

---

## BUG-3 (P2) — Uses deprecated `SECP256K1_CONTEXT_SIGN | _VERIFY` instead of `SECP256K1_CONTEXT_NONE`

`src/crypto/secp256k1.nim:245-247`:

```nim
globalContext = secp256k1_context_create(
  SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
)
```

and `secp256k1.nim:784-786` (`CryptoEngine` constructor):

```nim
result.ctx = secp256k1_context_create(
  SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
)
```

Per `bitcoin-core/src/secp256k1/include/secp256k1.h:216-218`:

```
/** Deprecated context flags. These flags are treated equivalent to SECP256K1_CONTEXT_NONE. */
#define SECP256K1_CONTEXT_VERIFY ...
#define SECP256K1_CONTEXT_SIGN   ...
```

and `bitcoin-core/src/key.cpp:575` shows Core uses
`SECP256K1_CONTEXT_NONE` for the sign context (the flag-bits are
ignored for purposes of which precomputed tables get allocated —
those are now always allocated based on the call site).

**Impact**: functional today, but the next libsecp256k1 major version
may begin emitting deprecation warnings (already emitted in `-Wpedantic`
builds upstream) or eventually remove these constants. nimrod will
break loudly on the bump.

**Fix:** change both call sites to `SECP256K1_CONTEXT_NONE`.

---

## BUG-4 (P0-SEC) — `secp256k1_context_randomize` never called; side-channel blinding disabled

`src/crypto/secp256k1.nim:67-239` does not declare
`secp256k1_context_randomize` as an FFI binding. Neither
`initSecp256k1()` (line 243) nor `newCryptoEngine()` (line 782)
nor `getThreadCrypto()` (`parallel_verify.nim:39`) calls it.

Bitcoin Core's `ECC_Start` (`bitcoin-core/src/key.cpp:578-584`):

```cpp
// Pass in a random blinding seed to the secp256k1 context.
std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
GetRandBytes(vseed);
bool ret = secp256k1_context_randomize(ctx, vseed.data());
assert(ret);
```

is invoked **immediately after** `secp256k1_context_create`. The
`assert(ret)` is load-bearing: Core refuses to run with side-channel
blinding disabled.

**Impact**: every `secp256k1_ecdsa_sign` / `_sign_recoverable` / 
`_tweak_add` call in nimrod runs on a non-blinded context. The
scalar arithmetic inside libsecp256k1 leaks private-key bits through
timing / cache / EM side channels. This affects:

- `signMessageWithPrivkey` RPC (any caller with RPC auth can sign,
  and a co-tenant attacker with shared-cache access can recover the
  WIF-decoded scalar).
- All wallet ECDSA signing call sites (`wallet.nim:1102, 1128, 1165,
  1205, 1237`) — every P2WPKH / P2PKH / P2SH-P2WPKH / P2WSH /
  P2SH-P2WSH sign.
- Every BIP-32 child-key derivation (`tweakSeckeyAdd`); the
  derivation path scalar can be observed.
- BIP-324 `ellswiftCreate` (`bip324.nim:143, 149`) — the ephemeral
  v2-p2p private key.

**Cross-cite (W158 NEW pattern "side-channel-blinding-disabled")**:
- lunarblock W158 BUG-7 — exact same pattern.
- clearbit W158 BUG-7 — same pattern in Zig FFI.
- blockbrew W158 — same gap (no `decred/dcrd/dcrec/secp256k1/v4`
  blinding option exposed).

**Fix (3 lines)**:

```nim
proc secp256k1_context_randomize(ctx: Secp256k1Context, seed32: ptr byte): cint
  {.importc, cdecl.}

proc initSecp256k1*() =
  if pointer(globalContext) == nil:
    globalContext = secp256k1_context_create(SECP256K1_CONTEXT_NONE)
    var seed: array[32, byte]
    if not urandom(seed):
      raise newException(Secp256k1Error, "blinding seed unavailable")
    discard secp256k1_context_randomize(globalContext, addr seed[0])
```

Apply same in `newCryptoEngine()` and `getThreadCrypto()`.

---

## BUG-5 (P2-SEC) — Blinding never re-randomized

Derivative of BUG-4. Even after the initial blinding seed is set,
Bitcoin Core does not re-randomize on a fixed cadence, but the
`secp256k1_context_randomize` API exists to be called periodically
for long-running daemons (e.g. mining nodes). nimrod has no scheduler
hook for this.

**Fix**: opt-in. Call `secp256k1_context_randomize` from the wallet
periodically (e.g. on every unlock, every 10k signs, or every 24h).
Same call as BUG-4; once the binding exists, this is configuration.

---

## BUG-6 (P1-SEC) — `secp256k1_ec_seckey_verify` FFI absent; scalar range never checked on untrusted seckey bytes

`src/crypto/secp256k1.nim:67-239` does not declare
`secp256k1_ec_seckey_verify`. The following call sites accept
arbitrary 32-byte arrays without checking that the scalar is in
`[1, n-1]`:

- `derivePublicKey(privateKey)` — `secp256k1.nim:254`
- `sign(privateKey, msgHash)` — `secp256k1.nim:268`
- `signCompactRecoverable(privateKey, msgHash)` — `secp256k1.nim:548`
- `tweakSeckeyAdd(seckey, tweak)` — `secp256k1.nim:669`
- `ellswiftCreate(privateKey)` — `secp256k1.nim:724`
- `computeBIP324ECDHSecret(privateKey, ...)` — `secp256k1.nim:741`
- Wallet sign sites — all 5 `sign(privateKeys[i], sighash)` calls.

Bitcoin Core's `CKey::Check` (`bitcoin-core/src/key.cpp:158-160`)
wraps this:

```cpp
bool CKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_static, vch);
}
```

and is used in the `MakeNewKey` rejection-sampling loop
(`key.cpp:162-168`).

**Impact**:
- `signmessagewithprivkey` accepts a WIF that decodes to all-zeros or
  to a scalar >= curve order n. `secp256k1_ecdsa_sign` then returns 0
  and the RPC raises a generic "Sign failed" error rather than
  identifying "invalid private key".
- `bytesToKeySha512Aes` derivation (`crypter.nim`) produces a 32-byte
  key from passphrase; if iteration count is low and the derived
  bytes are zero, the key derivation produces an invalid seckey;
  downstream sign fails opaquely.
- BIP-32 raw-seed derivation (`masterKeyFromRawSeed`) has a documented
  ~2^-127 probability of producing an invalid scalar; per BIP-32 the
  caller MUST detect this and retry. Without `seckey_verify`, the
  failure is silent.

**Fix**: declare the FFI, wrap as `proc isValidSeckey*(sk: openArray[byte]): bool`,
gate every untrusted-seckey-entry call site.

---

## BUG-7 (P2-SEC) — Private keys in non-`mlock`'d Nim stack/heap memory

`src/wallet/wallet.nim:23-29`:

```nim
type ExtendedKey* = object
  key*: array[32, byte]           ## Private key or chain code
  ...
```

Plain stack-allocated 32-byte arrays. Bitcoin Core stores `CKey::keydata`
in a `std::vector<unsigned char, secure_allocator<unsigned char>>`
(`key.h:53`), where `secure_allocator` is the `LockedPool`-backed
allocator (`support/lockedpool.h`). The pool calls `mlock(2)` on the
pages, preventing the kernel from paging them to disk.

**Impact**: under memory pressure, the kernel may swap pages containing
private keys to disk, where they will sit (potentially in cleartext)
until the swap file is overwritten or zeroed. Forensics of a seized
disk recovers the keys.

**Fix**: this is a non-trivial allocator change in Nim and may need
`alloc0Impl` + `posix_madvise(MADV_DONTDUMP)` + manual `mlock(2)`.
Out-of-scope for a one-line fix; recorded for tracking.

---

## BUG-8 (P1-SEC) — `memory_cleanse` barrier absent; key-zeroing loops DSE-able

`src/wallet/crypter.nim:187-193`:

```nim
proc clearKey*(crypter: WalletCrypter) =
  ## Clear the encryption key from memory
  for i in 0 ..< crypter.key.len:
    crypter.key[i] = 0
  for i in 0 ..< crypter.iv.len:
    crypter.iv[i] = 0
  crypter.keySet = false
```

`src/wallet/wallet.nim:1443-1450`:

```nim
for i in 0 ..< wallet.seed.len:
  wallet.seed[i] = 0
for i in 0 ..< wallet.masterKeyCache.len:
  wallet.masterKeyCache[i] = 0
for i in 0 ..< wallet.masterKey.key.len:
  wallet.masterKey.key[i] = 0
```

Nim's C backend compiles these to ordinary `for` loops over the array.
With `-O2` / `-O3`, LLVM's Dead Store Elimination pass will *remove*
the loop entirely if it can prove the storage is no longer read before
deallocation (which is exactly the case here — `crypter` / `wallet`
go out of scope right after `clearKey` / `lockWallet`).

Bitcoin Core's `memory_cleanse` (`bitcoin-core/src/support/cleanse.cpp`)
uses an inline-asm `__asm__ __volatile__("" : : "g"(p) : "memory")`
barrier that DSE cannot remove. Nim's `zeroMem` (`bip324.nim:251`)
does NOT include such a barrier; it compiles to a `memset` that DSE
can still remove (`memset` is *exempt* from the noalias barrier;
this is exactly why OpenSSL ships `OPENSSL_cleanse`).

**Impact**: same forensic-recovery risk as BUG-7. A core dump or
process memory snapshot taken after `lock` may still contain the
seed because the zero loop was elided.

**Fix**: bind `secp256k1_memory_cleanse` (or wrap a Nim-side
`{.importc: "memory_cleanse".}` to `support/cleanse.h`'s symbol)
and call it in `clearKey`, `lockWallet`, `bip324.initialize` (replace
the `zeroMem` calls), and `signMessageWithPrivkey` (after sign
completes).

---

## BUG-9 (P2-SEC) — `sign` has no sign-then-verify paranoia step

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

  if secp256k1_ecdsa_signature_serialize_compact(
    getContext(), addr result[0], addr sig
  ) != 1:
    raise newException(Secp256k1Error, "failed to serialize signature")
```

Compare `bitcoin-core/src/key.cpp:228-234`:

```cpp
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
```

Bitcoin Core hard-asserts that the signature it just produced verifies
under the derived pubkey *before* returning it. This is defense
against transient RAM corruption (cosmic ray, bit-flip, rowhammer)
between sign and broadcast. The 2010 Sony PS3 incident is the
textbook example: a corrupted nonce produced a sig that was
broadcast, leaking the master key.

**Impact**: in a multi-day mainnet run on ECC-less consumer hardware,
the probability of a bit-flip in the signature buffer is non-trivial.
Every wallet `sign()` call in nimrod is exposed.

**Fix**: ~6 LOC. Append at the end of `sign`:

```nim
var pkOut: Secp256k1Pubkey
if secp256k1_ec_pubkey_create(getContext(), addr pkOut, addr pk[0]) != 1:
  raise newException(Secp256k1Error, "sign paranoia: pubkey create failed")
if secp256k1_ecdsa_verify(getContext(), addr sig, addr msg[0], addr pkOut) != 1:
  raise newException(Secp256k1Error, "sign paranoia: post-sign verify failed")
```

---

## BUG-10 (P2-SEC) — `signCompactRecoverable` has no sign-then-verify paranoia step

`src/crypto/secp256k1.nim:548-567` — same pattern as BUG-9 but for
the recoverable path. Compare `bitcoin-core/src/key.cpp:262-269`:

```cpp
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey epk, rpk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

The recoverable path additionally does `_ec_pubkey_cmp` to confirm the
recovered pubkey equals the derived pubkey. Without this, a bit-flip
in the `recid` byte (sig[64]) produces a sig that recovers to a
*different* pubkey — the receiver verifies fine, but the receiver's
address-matching check (`PKHash(recovered) == address.pubkeyHash`)
will silently fail and `signmessage` returns a sig that
`verifymessage` rejects.

**Impact**: `signmessage` / `signmessagewithprivkey` may emit
silently-bad signatures under transient RAM corruption.

**Fix**: requires BUG-12 (binding `secp256k1_ec_pubkey_cmp`) plus
the paranoia step. ~10 LOC.

---

## BUG-11 (P1-CONS) — `isFullyValidPubkeyBytes` uncompressed branch skips on-curve check

`src/rpc/server.nim:2722-2740`:

```nim
proc isFullyValidPubkeyBytes(pkBytes: seq[byte]): bool =
  ...
  elif pkBytes.len == 65:
    if pkBytes[0] != 0x04:
      return false
    # Structural check only for uncompressed (no secp256k1 on-curve check here).
    # Core's IsFullyValid also calls secp256k1_ec_pubkey_parse; we accept
    # well-formed uncompressed keys as valid (invalid points rejected by script eval).
    return true
```

This is a **comment-as-confession** (W158-named fleet pattern): the
comment admits the divergence from Core's `CPubKey::IsFullyValid`
(`bitcoin-core/src/pubkey.h:215`), which always calls
`secp256k1_ec_pubkey_parse` and rejects pubkeys not on the curve.

**Impact**: `validateaddress`, `getaddressinfo`, and `addmultisigaddress`
all flow through `isFullyValidPubkeyBytes`. A user can register a
65-byte buffer starting with 0x04 that is NOT on the secp256k1 curve,
and nimrod will report it as valid, generate a multisig address from
it, and only fail at spend time (when the script interpreter does its
own parse). This produces malformed multisig descriptors that money
can be sent to but never spent from.

**Fix**: ~5 LOC. Call `decompressPubkey(pkBytes)` (which already does
the parse round-trip) for the uncompressed branch too, or expose a
dedicated `isFullyValidPubkey(pkBytes)` that calls
`secp256k1_ec_pubkey_parse` directly.

---

## BUG-12 (P2) — `secp256k1_ec_pubkey_cmp` FFI binding absent

`src/crypto/secp256k1.nim:70-239` does not declare
`secp256k1_ec_pubkey_cmp`. Bitcoin Core uses this for the
sign-then-verify paranoia step (`key.cpp:268`) and for constant-time
pubkey equality in PSBT and descriptor wallet code.

**Impact**: BUG-10's fix requires this binding. Also: every Nim-side
"do these two pubkeys match" check (e.g. in
`wallet/manager.nim::findKeyForAddress`) is done via raw byte
equality, which is timing-leaky on the pubkey bytes (low-impact since
pubkeys are public, but a hygiene gap).

**Fix**: 1 LOC FFI declaration.

---

## BUG-13 (P3) — `secp256k1_schnorrsig_verify_batch` not bound (upstream gap, no extension point)

`src/crypto/secp256k1.nim:164-170` binds
`secp256k1_schnorrsig_verify` (single). Upstream libsecp256k1 has
not yet released `_verify_batch` (see
`bitcoin-core/src/secp256k1/src/modules/schnorrsig/tests_impl.h:197`
where every test stub has `(TODO)`), so this gate is **blocked
upstream** rather than a near-term nimrod bug.

However, when the upstream API lands, nimrod's `parallel_verify.nim`
already spawns per-thread `CryptoEngine`s and would benefit from
batched verify within each thread. The wrapper layer has no extension
point: `verifyScript` is called one input at a time
(`parallel_verify.nim:62-70`), so adding batch later will require a
non-trivial refactor of the verification queue.

**Fix**: design now. Replace the `proc verifyInputScript(task)
-> VerificationResult` API with a batched
`proc verifyInputScriptBatch(tasks: seq[InputVerificationTask])
-> seq[VerificationResult]`, so the batch entry-point is in place when
libsecp's batch API lands. Currently this is recorded as a P3 design gap.

---

## BUG-14 (P1) — Entire `secp256k1_extrakeys` + Schnorr-sign module absent

`src/crypto/secp256k1.nim:67-239` declares:
- `secp256k1_xonly_pubkey_parse` (line 138)
- `secp256k1_xonly_pubkey_serialize` (line 144)
- `secp256k1_xonly_pubkey_tweak_add` (line 150)
- `secp256k1_xonly_pubkey_from_pubkey` (line 157)
- `secp256k1_schnorrsig_verify` (line 164)

NOT declared:
- `secp256k1_keypair_create`
- `secp256k1_keypair_xonly_pub`
- `secp256k1_keypair_xonly_tweak_add`
- `secp256k1_schnorrsig_sign32` / `_sign_custom`

`grep -rn "secp256k1_keypair\|secp256k1_extrakeys\|extrakeys" /home/work/hashhog/nimrod/src/`
returns zero hits.

**Impact**: nimrod cannot sign Taproot key-path spends or tapscript
spends. The verify side is complete (BIP-340 verify works for incoming
Taproot transactions during script validation), but
- `wallet.signTransaction` has no Taproot branch.
- `wallet/psbt.nim` cannot sign P2TR inputs in a PSBT.
- BIP-322 Full mode for Taproot addresses (W158) cannot be implemented.
- `signrawtransactionwithwallet` for any tx with a P2TR input will
  silently leave the input unsigned.

**Cross-cite W158**: clearbit's BUG-2 cipher-as-scalar bug existed
*because* the impl tried to side-channel Taproot signing through a
WIF-decode path; nimrod sidesteps that bug by simply not having
Taproot signing at all. Same outcome.

**Fix**: ~150 LOC. Bind all 4 extrakey FFI calls and add
`signSchnorr(privKey, msgHash, auxRand) -> array[64, byte]`. Wire
into `wallet.signTransaction` and `psbt.nim`.

---

## BUG-15 (P2) — `secp256k1_tagged_sha256` FFI absent; re-implemented inline

`src/script/interpreter.nim:553-560`:

```nim
proc taggedHash*(tag: string, data: openArray[byte]): array[32, byte] =
  ## SHA256(SHA256(tag) || SHA256(tag) || data)
  let tagHash = sha256(cast[seq[byte]](tag))
  var preimage: seq[byte]
  preimage.add(tagHash)
  preimage.add(tagHash)
  preimage.add(data)
  sha256(preimage)
```

`bitcoin-core/src/secp256k1/include/secp256k1.h:875`:

```c
SECP256K1_API int secp256k1_tagged_sha256(
    const secp256k1_context *ctx,
    unsigned char *hash32,
    const unsigned char *tag, size_t taglen,
    const unsigned char *msg, size_t msglen
);
```

Re-implementation is correct for the tested tags (`TapLeaf`,
`TapBranch`, `TapTweak`, `TapSighash`), but:
- duplicates the BIP-340 / BIP-341 tag-hash recipe with no upstream
  test sync; future tag-derivation changes (unlikely but possible in
  a future BIP) would silently diverge.
- The `cast[seq[byte]](tag)` (line 555) is a sketchy Nim string-to-seq
  reinterpretation. For ASCII-only tags ("TapLeaf" etc.) it works
  because Nim strings are byte-sequences in the C backend; for any
  tag containing a multi-byte UTF-8 codepoint, the byte count and
  thus the inner hash would diverge from Core. None of the current
  tag names trigger this, but a maintainer adding a tag with a
  non-ASCII byte (e.g. for a vendored test) would silently break.

**Fix**: 1 LOC FFI declaration + replace `taggedHash` body with the
FFI call. Avoids the cast.

---

## BUG-16 (P2) — `CryptoEngine` lacks `=destroy` finalizer; leaks on panic

`src/crypto/secp256k1.nim:776-792`:

```nim
type
  CryptoEngine* = object
    ctx: Secp256k1Context

proc newCryptoEngine*(): CryptoEngine =
  result.ctx = secp256k1_context_create(...)

proc close*(e: var CryptoEngine) =
  if pointer(e.ctx) != nil:
    secp256k1_context_destroy(e.ctx)
    e.ctx = Secp256k1Context(nil)
```

`CryptoEngine` is a plain `object` with no `=destroy` hook.
`parallel_verify.nim` does:

```nim
proc getThreadCrypto(): CryptoEngine =
  if not threadCryptoInit:
    threadCrypto = newCryptoEngine()
    threadCryptoInit = true
  threadCrypto
```

— no matching `close()`. The thread-local context is leaked when the
worker thread exits.

A more subtle issue: `verifyInputScript` (`parallel_verify.nim:45-74`)
runs script validation which may raise inside the `{.cast(gcsafe).}`
block. If a panic propagates out of the spawned task before
`getThreadCrypto`'s engine is closed, the context is lost.

**Fix**: add `proc =destroy(e: var CryptoEngine) = close(e)` so Nim's
ARC/ORC will reliably destroy the engine. (Nim 2.x default GC is
ARC/ORC which honors `=destroy`; older `refc` will need an explicit
`addThreadDestructor` hook.)

---

## BUG-17 (P2) — `threadCrypto` thread-local never destroyed on thread exit

`src/perf/parallel_verify.nim:36-43`:

```nim
var threadCrypto {.threadvar.}: CryptoEngine
var threadCryptoInit {.threadvar.}: bool

proc getThreadCrypto(): CryptoEngine =
  if not threadCryptoInit:
    threadCrypto = newCryptoEngine()
    threadCryptoInit = true
  threadCrypto
```

Each Nim threadpool worker creates one `CryptoEngine` (= one full
`secp256k1_context`, ~256 KB) on first use. There is no
thread-exit hook to call `threadCrypto.close()`. With Nim's
threadpool reusing workers for the process lifetime, this is bounded
by `countProcessors()` (max 16, per the `verifyScriptsParallel`
clamp) but unbounded across multiple `threadpool.setMaxPoolSize`
adjustments.

**Impact**: ~4 MB of leaked context memory on a 16-core box. Cosmetic
in steady state, but the leak shows up in heap profiles and
complicates memory budgeting for low-RAM deployments.

**Fix**: requires BUG-16's `=destroy` plus a thread-exit hook
(e.g. `threadpool.attachThreadCleanup(proc = close threadCrypto)`).
Nim's threadpool does not expose this directly, so a tracked deferred
fix.

---

## BUG-18 (P1-SEC) — Per-thread `CryptoEngine` not randomized; per-thread blinding identical to BUG-4

Once the global context is randomized (BUG-4 fix), every per-thread
`CryptoEngine` constructed by `getThreadCrypto()` will *still* be
unrandomized — the engine constructor is the same
`secp256k1_context_create` + no `_context_randomize` pair. So fixing
BUG-4 alone is insufficient: every `_create` site (3 in nimrod) must
also call `_context_randomize`.

**Fix**: same as BUG-4 applied to all 3 sites:
`initSecp256k1`, `newCryptoEngine`, `getThreadCrypto` (the last via
`newCryptoEngine`). If BUG-4 is fixed inside `newCryptoEngine`, both
this and `getThreadCrypto` inherit the fix.

---

## BUG-19 (P3) — `_destroy` called unconditionally on every `CryptoEngine.close`; will crash if migrated to `secp256k1_context_static`

`src/crypto/secp256k1.nim:788-792`:

```nim
proc close*(e: var CryptoEngine) =
  if pointer(e.ctx) != nil:
    secp256k1_context_destroy(e.ctx)
    e.ctx = Secp256k1Context(nil)
```

Bitcoin Core's verify-only paths use `secp256k1_context_static`
(`bitcoin-core/src/secp256k1/include/secp256k1.h:245`), which is a
static const and **must NOT be passed to `_destroy`**. If a future
refactor (e.g. to fix BUG-21) sets `e.ctx = secp256k1_context_static`
for verify-only engines, the unconditional `_destroy` here will crash
inside libsecp256k1.

**Fix**: add a tag bit (`isOwned: bool`) on `CryptoEngine` and only
destroy if `isOwned`. Trivial change to be applied alongside BUG-21.

---

## BUG-20 (P2-SEC) — `verifyMessageRaw` does not low-S-normalize before recover

`src/crypto/signmessage.nim:90`:

```nim
let recovered = recoverCompactPubkey(h, sig64, recid, compressed)
```

calls into `secp256k1.nim:569-603`, which does
`secp256k1_ecdsa_recoverable_signature_parse_compact` then
`secp256k1_ecdsa_recover`. There is no
`secp256k1_ecdsa_signature_normalize` step.

For BIP-146 NULLFAIL semantics on signature replay: a malicious peer
can take an existing `signmessage` base64 sig, flip `s -> n - s`
inside the 64-byte compact body, and the recovery will succeed
(producing the same pubkey, since ECDSA recovery is malleable on S).
The base64 sig now has a different SHA256 but verifies as the same
message; downstream caches keyed by signature-hash get confused.

`bitcoin-core/src/common/signmessage.cpp:64` does not enforce low-S
on the verify path either (Core only enforces low-S inside script
validation, not for `verifymessage`), so this isn't a strict
divergence from Core. But it does fail BIP-146's intent.

**Fix**: ~5 LOC. Normalize the sig with `_signature_normalize` before
`_recover`. Defense-in-depth; not strictly required for Core parity.

---

## BUG-21 (P2) — `secp256k1_context_static` not bound; verify paths waste sign-precomp tables

`src/crypto/secp256k1.nim:241-247` creates ONE process-singleton
context with `SECP256K1_CONTEXT_SIGN | _VERIFY`. This context
allocates both sign-precomputed tables (~256 KB) and verify-precomp.
All verify-only call sites (the entire `script/interpreter.nim`
hot path, every `verifyScript` call during IBD) go through this
mixed context.

Bitcoin Core uses `secp256k1_context_static`
(`bitcoin-core/src/secp256k1/include/secp256k1.h:245-249`) for every
verify-only call (see `bitcoin-core/src/key.cpp:159` `CKey::Check`,
`key.cpp:268` `_ecdsa_recover`, `key.cpp:281` `ec_seckey_import_der`,
etc.). The static context is a const-data-segment object that
requires no setup, no destroy, and ~no memory.

**Impact**: a nimrod node running with `--no-wallet` (verify-only mode,
e.g. for IBD-only headers nodes) still allocates ~256 KB of unused
sign-precomp.

**Fix**: bind `secp256k1_context_static`, route every verify-only
call through it. Requires BUG-19 fix to avoid destroy-on-static crash.

---

## BUG-22 (P1-SEC) — `signmessagewithprivkey` does not validate scalar range on WIF-decoded key

`src/rpc/server.nim:4694-4710`:

```nim
let wifStr = params[0].getStr()
let message = params[1].getStr()

var privKey: PrivateKey
var compressed: bool
try:
  let decoded = decodeWIF(wifStr)
  privKey = decoded.key
  compressed = decoded.compressed
except DescriptorError as e:
  raise newRpcError(RpcInvalidAddressOrKey, "Invalid private key: " & e.msg)

try:
  let signature = signMessage(privKey, message, compressed = compressed)
  return %signature
except Secp256k1Error as e:
  raise newRpcError(RpcInvalidAddressOrKey, "Sign failed: " & e.msg)
```

The WIF decode (`decodeWIF`) confirms checksum + network byte +
length, but does NOT call `secp256k1_ec_seckey_verify` on the
32-byte payload. A WIF that decodes to a 32-byte all-zero string,
or to a value >= curve order n, passes the WIF gate.

The downstream `signCompactRecoverable` call hits
`secp256k1_ecdsa_sign_recoverable` which returns 0, the wrapper
raises `Secp256k1Error("failed to sign recoverable")`, and the RPC
caller sees `Sign failed: failed to sign recoverable`.

Bitcoin Core's `decodeSecret` (`bitcoin-core/src/key_io.cpp::DecodeSecret`)
calls `CKey::Set` which calls `Check` (= `_ec_seckey_verify`) and
returns invalid if it fails. The RPC then raises a clean
`RPC_INVALID_ADDRESS_OR_KEY` ("Invalid private key encoding").

**Impact**:
- Distinguishable from generic "Sign failed" errors: tools that
  retry on transient sign failure will retry forever on a logically
  invalid WIF.
- Combined with BUG-4 (no blinding), the failure path itself becomes
  a tiny side channel (an attacker probing valid-WIF surface can
  distinguish "valid scalar but I/O glitch" from "invalid scalar"
  via the error message).

**Fix**: depends on BUG-6 (FFI binding for `_ec_seckey_verify`).
Once bound, add 3 lines to `signmessagewithprivkey`:

```nim
if not isValidSeckey(privKey):
  raise newRpcError(RpcInvalidAddressOrKey, "Invalid private key encoding")
```

before the `signMessage` call.

---

## BUG-23 (P2) — Test suite does not pin any security gate

`tests/test_crypto.nim:109-167`:
- `"sign and verify roundtrip"` — pins functional correctness only.
- `"verify fails with wrong message"` — pins negative case.
- `"CryptoEngine lifecycle"` — pins `new` + `close` succeed.
- `"CryptoEngine ecdsa verify"` — pins per-engine verify works.

No test asserts:
- BUG-4: that `_context_randomize` returned 1 on startup.
- BUG-6: that an all-zero or >= n seckey is rejected.
- BUG-9 / BUG-10: that sign-then-verify paranoia would catch
  a bit-flipped signature.
- BUG-11: that an off-curve uncompressed pubkey is rejected by
  `isFullyValidPubkeyBytes`.
- BUG-18: that thread-local contexts are independently randomized.
- BUG-20: that S-malleated signatures still verify (or are
  normalized away).

**Cross-cite W158 NEW pattern "test-pins-bug"**: nimrod's test suite
does not pin the *wrong* behaviour (which is what blockbrew W158
flagged), so this is a softer instance — but the absence of any
security-gate test means a future regression of any of the above
bugs will land silently. **Inverted form of W158's pattern: "tests
fail to pin the right behaviour."**

**Fix**: ~80 LOC across 6 test cases. Each can be a single-line
`check` after BUG-4 / BUG-6 / BUG-9 / BUG-10 / BUG-11 are wired.

---

## Cross-impl fleet patterns extended in W159

- **side-channel-blinding-disabled** (W158 NEW, pattern fully
  saturating this quad): nimrod BUG-4 is the **4th** distinct fleet
  instance (after clearbit W158 BUG-7, lunarblock W158 BUG-7,
  blockbrew W158). Now likely fleet-wide (≥4 of 10 confirmed in
  consecutive waves).
- **encrypted-wallet-cipher-as-scalar** (W158 NEW clearbit BUG-2):
  N/A to nimrod — nimrod's `decryptSecret` (`crypter.nim:176-185`)
  returns the AES plaintext directly, and the only caller
  (`wallet.nim:1408`) unpacks it as a 64-byte seed (NOT as a 32-byte
  seckey), and `signMessage` paths in nimrod take the seckey from
  the BIP-32 derivation, not from the AES ciphertext. The pattern
  would apply if BUG-14 (Taproot signing) is ever wired through
  `crypter.encryptSecret` for the wallet keystore; recorded as
  forward-looking.
- **test-pins-bug** (W158 NEW blockbrew): inverted instance at BUG-23.
  Nimrod's tests don't pin the wrong behaviour but fail to pin the
  right behaviour either. Subtle variant.
- **comment-as-confession** (multi-quad pattern, ≥18 distinct
  instances fleet-wide): nimrod BUG-11 — the `isFullyValidPubkeyBytes`
  uncompressed branch comment **"Structural check only for
  uncompressed (no secp256k1 on-curve check here)"** is one of the
  most direct confessions seen this quad. The text admits the
  divergence from Core in the same line as the code that diverges.
- **wiring-look-but-no-wire** (recurring fleet pattern): nimrod
  BUG-1 + BUG-16 + BUG-17 — `initSecp256k1` exists but is never
  called from any production code path (`grep` returns only the
  self-call from `getContext()`); `CryptoEngine.close` exists but
  there is no destructor wiring; `threadCrypto` thread-local exists
  but no thread-exit cleanup. Multiple instances within this single
  audit.
- **two-pipeline guard** (recurring fleet pattern): nimrod has **3**
  separate context-creation pipelines:
  1. `globalContext` (process singleton, line 241).
  2. `CryptoEngine` (per-instance via `newCryptoEngine`, line 782).
  3. Thread-local via `parallel_verify.nim:36-43`'s `threadCrypto`.

  Each pipeline replicates the same `secp256k1_context_create` call
  with the same deprecated flags and the same missing `_context_randomize`.
  Three-pipeline gate-drift instance.
- **dead-init proc** (NEW W159): `initSecp256k1` is a public proc
  that is never called from any production code (only by `getContext`
  itself for the global path, and by tests for explicit setup). The
  intent is for callers to invoke it once at startup; the actual
  call chain bypasses it via lazy init in `getContext`. Compare
  Core's `ECC_Context` RAII guard (`bitcoin-core/src/pubkey.cpp:25`)
  which forces the init to happen as a side effect of constructing
  a stack object at `main()` scope. **First fleet instance**
  recorded.
- **FFI-binding-by-absence** (NEW W159): the `when defined(useSystemSecp256k1)`
  block declares 30+ FFI procs, but **omits** 6 security-critical
  ones from the libsecp256k1 v0.4+ API:
  `_context_randomize`, `_selftest`, `_ec_seckey_verify`,
  `_ec_pubkey_cmp`, `_tagged_sha256`, `_context_static` (variable).
  The absence is the bug — there is no "wired but not called"
  helper, the binding simply doesn't exist. Compare W158 lunarblock
  BUG-7 which was the same shape (FFI absent).

---

## Severity-elevation candidates (cross-cite with W155/W157 carry-forwards)

- BUG-4 (P0-SEC) is the highest-severity finding this wave. **Same
  shape as lunarblock W158 BUG-7 (P1-SEC)** but graded one band
  higher because nimrod is currently a candidate for mainnet wallet
  use, while lunarblock is "known broken" per root CLAUDE.md.
- BUG-11 (P1-CONS) escalates **the W157 pattern "RPC-only finding
  reaches consensus"**: `isFullyValidPubkeyBytes` is RPC-facing
  (`validateaddress`), but `addmultisigaddress` flows through it and
  emits an on-chain `scriptPubKey` (`OP_M <pk1> ... <pkN> OP_N
  OP_CHECKMULTISIG`) that contains an off-curve pubkey. The next
  script-eval that touches the address will reject the spend —
  silent funds-burn after the first deposit.
- BUG-14 (P1) is "verify-only Taproot" which is a class of bug
  that has not been catalogued under a clean fleet pattern name
  yet. **NEW pattern proposal**: "asymmetric Schnorr surface" —
  nimrod accepts incoming Taproot transactions but cannot produce
  outgoing ones. Compare blockbrew W152 BUG-1 "asymmetric
  receive/send" (TX-relay only) and clearbit W156 "unidirectional
  cmpctblock" (BIP-152 receive-only). Same family, now extended
  to BIP-340.

---

## Recommended fix order (highest-leverage first)

1. **BUG-4** (P0-SEC, ~10 LOC across 3 sites) — `_context_randomize`
   FFI binding + call from each `_context_create` site. Closes the
   side-channel-blinding-disabled pattern fleet-wide for nimrod.
2. **BUG-6** + **BUG-22** (~5 LOC each) — `_ec_seckey_verify` FFI
   binding + gate on `signmessagewithprivkey`. Closes the
   "invalid WIF accepted with generic error" surface.
3. **BUG-11** (~5 LOC) — wire `isFullyValidPubkeyBytes`
   uncompressed branch through `decompressPubkey` (already exists)
   to add the on-curve gate. Closes consensus-leakage surface in
   `addmultisigaddress`.
4. **BUG-9** + **BUG-10** (~15 LOC) — sign-then-verify paranoia on
   both `sign` and `signCompactRecoverable`. Defense against
   transient RAM corruption.
5. **BUG-3** (~2 LOC) — replace deprecated `_SIGN | _VERIFY` flags
   with `_NONE`. Trivial, forward-compatible.
6. **BUG-15** (~5 LOC) — bind `_tagged_sha256`, replace inline
   Nim implementation. Avoids the `cast[seq[byte]](tag)` cast.
7. **BUG-2** (~3 LOC) — bind `_selftest`, call from
   `initSecp256k1` after randomize.
8. **BUG-1** + **BUG-16** + **BUG-17** (~10 LOC) — `=destroy` /
   thread-exit hooks. Cosmetic but cleans up sanitizer noise.
9. **BUG-14** (~150 LOC) — full Schnorr-sign + extrakeys module.
   Required for any future P2TR wallet signing.
10. **BUG-23** (~80 LOC) — security-gate test cases. Apply after
    each of the above fixes lands.

**Total estimated diff for P0/P1 fixes: ~50 LOC across 5 changes.**
**BUG-14 (Taproot signing) is the only large fix; everything else
is small.**
