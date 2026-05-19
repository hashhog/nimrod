# W158 — BIP-322 + Legacy BIP-137 message signing (nimrod)

**Wave:** W158 — `MessageSign`, `MessageVerify`, `MessageHash`,
`MESSAGE_MAGIC = "Bitcoin Signed Message:\n"`, `CKey::SignCompact`,
`CPubKey::RecoverCompact`, header byte `27 + recid + (4 if compressed)`,
base64 standard alphabet, `MessageVerificationResult` enum,
`SigningResult` enum, `EnsureWalletIsUnlocked`, P2PKH-only address gate,
BIP-322 three modes (Legacy / Simple / Full), BIP-322 virtual-tx
construction (`to_spend` + `to_sign`), BIP-322 sighash, BIP-322 NUMS-point
fallback for taproot script-path, BIP-322 multi-input full mode,
`signmessage` / `verifymessage` / `signmessagewithprivkey` RPCs.

**Scope:** discovery only — NO production code change in W158.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp:24` — `MESSAGE_MAGIC =
  "Bitcoin Signed Message:\n"` (literal, length 24, **with** trailing
  `\n`).
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash(msg)`:
  `HashWriter << MESSAGE_MAGIC << message; return hasher.GetHash();`
  where `<<` for a `std::string` serializes
  `compactSize(len) || raw_bytes`. The hash is `SHA256(SHA256(...))`
  via `HashWriter::GetHash()`.
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign`:
  `privkey.SignCompact(MessageHash(message), signature_bytes);
  signature = EncodeBase64(signature_bytes);` — note `SignCompact`
  prepends the 1-byte header internally (Bitcoin Core's `key.cpp:344`)
  so the bytes-to-encode are 65.
- `bitcoin-core/src/key.cpp:329-346` — `CKey::SignCompact`:
  `secp256k1_ecdsa_sign_recoverable(..., extra_entropy = nullptr_RFC6979)`
  → serialize-compact-with-recid → write header byte
  `27 + rec + (fCompressed ? 4 : 0)`. **No explicit S-normalize**
  (libsecp256k1 default emits canonical low-S).
- `bitcoin-core/src/pubkey.cpp:300-321` — `CPubKey::RecoverCompact`:
  `vchSig.size() == 65` REQUIRED; `header < 27 || header > 34` →
  return false (range `[27, 34]` inclusive accepted);
  `recid = (header - 27) & 3`; `fComp = ((header - 27) & 4) != 0`;
  `parse_compact + ecdsa_recover + serialize`. Returns serialized
  pubkey in `fComp ? COMPRESSED : UNCOMPRESSED` form.
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify`:
  decode address → MUST be `PKHash` (legacy P2PKH) else
  `ERR_ADDRESS_NO_KEY`; `DecodeBase64(signature)` else
  `ERR_MALFORMED_SIGNATURE`; `pubkey.RecoverCompact(MessageHash(msg),
  *bytes)` else `ERR_PUBKEY_NOT_RECOVERED`; `PKHash(pubkey) ==
  *PKHash(&dest)` else `ERR_NOT_SIGNED`. Comparator uses `PKHash`
  which is `hash160(serialized_pubkey)` — meaning Core compares the
  hash of the EXACT serialization produced by `RecoverCompact` (so
  whether the original signer compressed must match the signer's
  recorded compressed-flag, which then matches the address's PKHash).
- `bitcoin-core/src/util/strencodings.cpp:110-143` — `DecodeBase64`:
  STRICT standard alphabet `A-Z a-z 0-9 + /`; `size % 4 != 0` →
  reject; at most TWO trailing `=` permitted; everything else (incl
  `-` `_` URL-safe alphabet, embedded whitespace, partial-padding)
  returns `nullopt`.
- `bitcoin-core/src/rpc/signmessage.cpp:17-60` — `verifymessage` RPC:
  maps `ERR_INVALID_ADDRESS` → `RPC_INVALID_ADDRESS_OR_KEY` (-5),
  `ERR_ADDRESS_NO_KEY` → **`RPC_TYPE_ERROR` (-3)**,
  `ERR_MALFORMED_SIGNATURE` → **`RPC_TYPE_ERROR` (-3)**,
  `ERR_PUBKEY_NOT_RECOVERED` → return `false` (NOT error),
  `ERR_NOT_SIGNED` → return `false`, `OK` → return `true`. The
  `RPC_TYPE_ERROR` code is distinct from `RPC_INVALID_ADDRESS_OR_KEY`
  in Core's `protocol.h:24` and is what clients filter on.
- `bitcoin-core/src/rpc/signmessage.cpp:62-101` — `signmessagewithprivkey`:
  `DecodeSecret(WIF)` → if invalid raise `RPC_INVALID_ADDRESS_OR_KEY`;
  `MessageSign(key, msg, sig)` → if false raise
  `RPC_INVALID_ADDRESS_OR_KEY` "Sign failed". `CKey::IsCompressed()`
  decided by WIF format (33 bytes vs 34 with 0x01 suffix).
- `bitcoin-core/src/wallet/rpc/signmessage.cpp:14-71` — wallet
  `signmessage`: `EnsureWalletIsUnlocked(*pwallet)` BEFORE address
  decode; `DecodeDestination(addr)` → require `PKHash`; map
  `SigningResult::SIGNING_FAILED` → `RPC_INVALID_ADDRESS_OR_KEY`,
  any other non-OK → **`RPC_WALLET_ERROR` (-4)** (e.g.
  `PRIVATE_KEY_NOT_AVAILABLE` is `RPC_WALLET_ERROR` not
  `RPC_INVALID_ADDRESS_OR_KEY`).
- `bitcoin-core/src/wallet/wallet.cpp` — `CWallet::SignMessage`:
  returns `PRIVATE_KEY_NOT_AVAILABLE` if the spk-manager can't
  produce the key; this maps to `RPC_WALLET_ERROR` not
  `RPC_INVALID_ADDRESS_OR_KEY`.
- `bitcoin-core/src/wallet/rpc/util.cpp::EnsureWalletIsUnlocked` —
  Bitcoin Core fires this BEFORE any other validation (address
  decode, message length checks) so that a locked-wallet client gets
  a clean error path without leaking whether the address belongs to
  the wallet.
- **BIP-322 reference (Bitcoin Core):** *NOT MERGED IN CORE* — the
  reference text lives at <https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki>;
  Core PR #24058 (still open as of 2026-05) tracks Simple-mode
  support for P2WPKH / P2WSH / P2TR / P2SH-P2WPKH using a virtual
  `to_spend` tx (locked to challenge: `OP_0 PUSH32 sha256(MAGIC ||
  message_hash)`, version 0, locktime 0, prev txid = 0, vout =
  0xFFFFFFFF) and a `to_sign` tx (version 0, locktime 0, prevout =
  to_spend:0, witness = signature stack, scriptPubKey = OP_RETURN).
  Full mode is multi-input, supports arbitrary scripts including
  taproot script-path with NUMS-point internal key fallback to mark
  the spend "script-path only".

**Files audited**
- `src/crypto/signmessage.nim` (entire file, 98 lines) —
  `MessageMagic = "Bitcoin Signed Message:\n"` (line 25),
  `messageHash` (27-38), `signMessage` (40-55),
  `MessageVerifyResult` enum (57-64), `verifyMessageRaw` (66-98).
- `src/rpc/server.nim:4575-4578` — help-text entries.
- `src/rpc/server.nim:4605-4710` — `handleSignMessage` (4609-4650),
  `handleVerifyMessage` (4652-4684),
  `handleSignMessageWithPrivkey` (4686-4710).
- `src/rpc/server.nim:8357-8362` — dispatch table cases for the
  three RPCs.
- `src/rpc/server.nim:79-93` — RPC error code constants
  (no `RpcTypeError` = -3 defined — confirmed by
  `tests/test_w125_error_parity.nim:159-167` "Gate 7 …
  MISSING").
- `src/rpc/server.nim:5196-5225` — `getTargetWallet`.
- `src/crypto/secp256k1.nim:548-603` — `signCompactRecoverable`,
  `recoverCompactPubkey`.
- `src/crypto/secp256k1.nim:931-939` — stub branch (when not
  compiled with `-d:useSystemSecp256k1`) raises `Secp256k1Error`
  on every call.
- `src/crypto/address.nim:19-39` — `Address` variant object with
  `AddressType = {P2PKH, P2SH, P2WPKH, P2WSH, P2TR}`.
- `src/wallet/wallet.nim:702-711` — `findKeyForAddress`.
- `src/wallet/wallet.nim:1433-1512` — `lockWallet`,
  `checkUnlockExpiry`, `isWalletLocked`.
- `src/wallet/descriptor.nim:325-353` — `decodeWIF`.
- `tests/test_rpc.nim:1037-1116` — `RPC signmessage / verifymessage`
  suite (6 tests, ALL compressed-roundtrip; none exercise the RPC
  dispatch path, address-kind rejection, uncompressed flag, or
  base64-alphabet edges).

**No grep hits for**
- `bip322` / `BIP322` / `bip-322` / `BIP-322` anywhere in the
  source tree (verified
  `grep -rni "bip322\|bip-322\|BIP322\|BIP-322" --include="*.nim"`
  returns ZERO matches).
- `to_spend`, `to_sign`, `tospend`, `tosign`, `virtual_tx`,
  `BIP322_HASH_TAG` — none.
- `NUMS`, `nums_point`, `H_NUMS` — none.

**Reference comparison matrix (BIP-137 legacy + BIP-322 modes)**

| # | Aspect | Core gate / requirement | nimrod status |
|---|--------|-------------------------|---------------|
| 1 | MESSAGE_MAGIC literal | `"Bitcoin Signed Message:\n"` length 24, trailing `\n` REQUIRED (`common/signmessage.cpp:24`) | PASS — `signmessage.nim:25` exact match; test `MessageMagic constant matches Bitcoin Core` (`test_rpc.nim:1061-1063`) pins both string and length. |
| 2 | `MessageHash` framing | `compactSize(magic.len) || magic || compactSize(msg.len) || msg`, then double-SHA-256 (`HashWriter`) | PASS — `signmessage.nim:32-38` mirrors framing; `doubleSha256` (`hashing.nim:23-25`) = sha256d. |
| 3 | Header byte encoding | `27 + recid + (4 if compressed else 0)` (`key.cpp:344`) — range `[27..34]` accepted by `RecoverCompact` (`pubkey.cpp:300-321`) | PASS — `signmessage.nim:48` writes `27 + recid + (4 if compressed else 0)`; `signmessage.nim:80` validates `header in [27, 34]`. |
| 4 | Compact-sig serialization | `SignCompact` produces 65 bytes (`header || r || s`); RFC6979 deterministic nonce | PASS — `secp256k1_ecdsa_sign_recoverable(..., nil_noncefunc)` = RFC6979 default; `signCompactRecoverable` (`secp256k1.nim:548-567`) serializes compact with recid. |
| 5 | Low-S normalization on **sign** | libsecp256k1 default produces canonical low-S sig (Core does not re-normalize) | PASS — same libsecp default applies. |
| 6 | Low-S normalization on **verify** | Core's `RecoverCompact` does NOT re-normalize (any S is recoverable) | PASS by mirroring; nimrod does not re-normalize either. |
| 7 | Address gate (verify) | MUST be `PKHash` (legacy P2PKH) else `ERR_ADDRESS_NO_KEY` (`common/signmessage.cpp:36-38`) | PASS shape — `handleVerifyMessage` (`server.nim:4670-4671`) rejects non-`P2PKH`. **But the error code is WRONG** — see BUG-2. |
| 8 | Address gate (wallet sign) | MUST be `PKHash` else `RPC_TYPE_ERROR` (-3) "Address does not refer to key" (`wallet/rpc/signmessage.cpp:54-57`) | PARTIAL — `handleSignMessage` (`server.nim:4627-4631`) rejects non-`P2PKH` but raises `RpcInvalidAddressOrKey` (-5). Inline comment at 4628-4630 literally documents the gap: "Bitcoin Core uses RPC_TYPE_ERROR (-3) here. We don't have a constant for that yet". **Comment-as-confession 9th nimrod instance.** See BUG-2. |
| 9 | Base64 alphabet (verify) | STRICT standard alphabet `+ /` only; `-` / `_` REJECTED (`util/strencodings.cpp:110-143`) | **BUG-1 (P0-CDIV)** — `verifyMessageRaw` (`signmessage.nim:72`) calls Nim std/base64 `decode` (`lib/pure/base64.nim:214`) which tolerates BOTH `+/` AND URL-safe `-_` interchangeably (decode-table at line 207-208 maps `-` → 62 and `_` → 63 alongside `+` and `/`). A URL-safe-encoded 65-byte sig payload that Core's `DecodeBase64` rejects with `ERR_MALFORMED_SIGNATURE` will be silently accepted by nimrod and verified normally. **Wire-format divergence on `verifymessage`.** |
| 10 | Base64 size discipline (verify) | `size % 4 != 0` → reject (`util/strencodings.cpp:128`); `>2` trailing `=` → reject; embedded whitespace → reject | **BUG-9 (P1-RPC)** — Nim std/base64 `decode` `lib/pure/base64.nim:248-249` STRIPS trailing `\n` `\r` ` ` `=` then walks the body skipping embedded `\n` `\r` ` ` whitespace (line 253-254), and accepts arbitrary `len % 4`. Inputs that Core rejects (e.g., `"AAAA " + 64-char-sig"` with embedded space, or a sig with `===` padding) are silently accepted and may decode to a not-65-byte payload that then falls through to the `sigBytesStr.len != 65` guard with the right shape but wrong byte content. Less severe than BUG-1 because the length gate at line 76 catches most cases — but ONE-character padding inputs slip through to a length-mismatch reject path with a different downstream profile. |
| 11 | `verifymessage` error → return-value mapping | `ERR_PUBKEY_NOT_RECOVERED` → return false (no RPC error); `ERR_NOT_SIGNED` → return false (`rpc/signmessage.cpp:50-52`) | PASS — `handleVerifyMessage:4681-4684` collapses both to `%false`. |
| 12 | `verifymessage` error → `RPC_TYPE_ERROR` mapping | `ERR_ADDRESS_NO_KEY` and `ERR_MALFORMED_SIGNATURE` BOTH raise `RPC_TYPE_ERROR` (-3) (`rpc/signmessage.cpp:46-49`) | **BUG-2 (P1-RPC)** — `handleVerifyMessage` (`server.nim:4676,4680`) raises `RpcInvalidAddressOrKey` (-5) for BOTH cases. The reject **message strings** match Core ("Malformed base64 encoding", "Address does not refer to key") but the **error code** differs — clients that filter on `error.code == -3` (Core idiom for "wrong type") see no errors and silently mistreat the response. Same root cause as the **W125 Gate 7** finding (no `RpcTypeError` constant defined in `server.nim`). |
| 13 | Header-byte error path (verify) | `vchSig[0] - 27` underflow in unsigned arithmetic when `header < 27` is harmless in Core because the range check fires first (`pubkey.cpp:303`) | **BUG-7 (P1)** — `signmessage.nim:79-82` declares `let header = uint8(sigBytesStr[0])` then `if header < 27 or header > 27 + 4 + 3`. If a future refactor moves the range check below the recid/compressed extraction (line 82-83), `(header - 27) and 3` would underflow `uint8` to e.g. `0xfd and 3 = 1`, producing a bogus recid that survives validation. The current code is correct; the latent fragility is the `uint8(header - 27)` pattern with no helper enforcing the precondition. Add an `assertInRange(header, 27, 34)` or a sealed `parseHeaderByte` helper to lock the invariant. |
| 14 | `signmessagewithprivkey` WIF parse | `DecodeSecret(privkey)` returns invalid `CKey` → raise `RPC_INVALID_ADDRESS_OR_KEY` "Invalid private key" (`rpc/signmessage.cpp:87-89`) | PASS — `handleSignMessageWithPrivkey:4699-4704` raises `RpcInvalidAddressOrKey` with prefix "Invalid private key: " + Nim exception message. Core does NOT append the libsecp error string — nimrod leaks parser-internal text into the RPC error, which is a minor info-leak but not a security issue. |
| 15 | `signmessagewithprivkey` compressed flag | Reads `CKey::IsCompressed()` from WIF (33 vs 34 byte payload with 0x01 suffix) and passes through to `MessageSign` | PASS — `handleSignMessageWithPrivkey:4707` reads `decoded.compressed` from `decodeWIF` (`descriptor.nim:332-350`) and forwards. Symmetric with Core. |
| 16 | `signmessage` (wallet) `EnsureWalletIsUnlocked` ordering | Locked-wallet check fires FIRST, before address decode (`wallet/rpc/util.h`) so a non-existent address on a locked wallet returns "wallet is locked" (NOT "address does not refer to key") | **BUG-3 (P1-RPC)** — `handleSignMessage` order is (1) parse address (`server.nim:4621-4625`), (2) reject non-P2PKH (4627-4631), (3) get wallet (4633), (4) check `isLocked` (4634-4636). Core's order is wallet-first. **Information disclosure:** a client probing whether address `X` is in the wallet can distinguish "wallet locked but address valid" from "wallet locked AND address invalid" — nimrod returns "Invalid address" first, then "wallet locked"; Core ALWAYS returns "wallet locked" first. Same shape as previous wallet-leak findings on listunspent / getbalance address probing. |
| 17 | `signmessage` (wallet) unlock-expiry check | `EnsureWalletIsUnlocked` consults `nUnlockTime` and re-locks if expired before serving (`wallet.cpp::Unlock` timeout) | **BUG-8 (P1-SEC, fleet-pattern "dead-helper at call-site")** — `checkUnlockExpiry` is DEFINED at `wallet.nim:1502-1506` but called from ZERO RPC handlers (verified `grep -n "checkUnlockExpiry" src/rpc/server.nim` → no matches). `handleSignMessage:4634` consults `wallet.isLocked` directly. If a user passphrased the wallet 60 seconds ago for a 30-second unlock window, `isLocked` is still `false` until `getwalletinfo` or another expiry-checking method fires; `signmessage` slips through the expired window. **Comment-as-confession pre-condition** — the function exists, it's exported, it's not called from the security-critical RPC path. Pattern: same as W141 BUG-5 "dead-helper at call-site where function exists + exported + called but no-op" (sub-variant: defined + exported + NEVER called). |
| 18 | Error code for "Private key not available" | Core's `wallet.cpp::SignMessage` returns `PRIVATE_KEY_NOT_AVAILABLE` → wallet RPC maps to **`RPC_WALLET_ERROR` (-4)** (`wallet/rpc/signmessage.cpp:63-65`), NOT `RPC_INVALID_ADDRESS_OR_KEY` | **BUG-4 (P1-RPC)** — `handleSignMessage:4639-4641` raises `RpcInvalidAddressOrKey` (-5) "Private key not available". Core uses -4. Clients filtering for `RPC_WALLET_ERROR` to retry-with-unlock vs `RPC_INVALID_ADDRESS_OR_KEY` to error-to-user will misclassify. Same class as BUG-2 (wrong code, right message). |
| 19 | `Secp256k1Error` propagation through verify | Bitcoin Core's `RecoverCompact` returns `false` on any libsecp failure (never throws C++ exception) | **BUG-5 (P1)** — when the stub branch is active (`secp256k1.nim:931-939`, `-d:useSystemSecp256k1` NOT set), `signCompactRecoverable` and `recoverCompactPubkey` BOTH `raise newException(Secp256k1Error, ...)`. `handleSignMessage:4646-4650` and `handleSignMessageWithPrivkey:4706-4710` catch `Secp256k1Error` correctly. But `handleVerifyMessage:4673` calls `verifyMessageRaw` with NO try/except. `verifyMessageRaw` calls `recoverCompactPubkey` which under the stub raises uncaught `Secp256k1Error` → the JSON-RPC framework returns generic `RPC_INTERNAL_ERROR` rather than `false` / `ERR_PUBKEY_NOT_RECOVERED`. Stub-build clients see internal-error spam instead of false. |
| 20 | Verify result enum coverage | Core's `MessageVerificationResult` has 6 variants including `OK` (`common/signmessage.h:23-41`); switch is `case`-exhaustive at the call site | PASS — `MessageVerifyResult` (`signmessage.nim:57-64`) has 6 variants matching Core 1:1. |
| 21 | `signmessage` for non-BIP44 addresses (P2WPKH / P2SH-P2WPKH / P2WSH / P2TR) — BIP-322 entry path | Core: no support in mainline, but a `signrawmessage` / BIP-322 RPC is the open-PR replacement; nimrod has neither | **BUG-12 (P1-CAP, fleet-wide BIP-322 absence)** — **No BIP-322 implementation in nimrod**. Grep for `bip322` / `BIP322` / `to_spend` / `to_sign` / `NUMS` returns ZERO hits. Wallets that derive P2WPKH (BIP84, m/84'/) or P2TR (BIP86, m/86'/) addresses cannot sign messages at all — `handleSignMessage` rejects with "Address does not refer to key" because the address kind is not `P2PKH`. Modern users with bech32-only wallets cannot use nimrod's `signmessage`. Note: this is a FLEET-WIDE gap (no impl in hashhog implements BIP-322; Bitcoin Core itself does not have BIP-322 in main as of 2026-05). |
| 22 | BIP-322 virtual `to_spend` tx | spec: `version = 0; locktime = 0; vin = [{prev_txid = 0, vout = 0xFFFFFFFF, sequence = 0, scriptSig = OP_0 PUSH32 sha256(MAGIC || msghash)}]; vout = [{value = 0, scriptPubKey = scriptPubKey_for_address}]` | ABSENT — no virtual-tx construction anywhere in `src/crypto/` or `src/wallet/`. |
| 23 | BIP-322 virtual `to_sign` tx | spec: `version = 0; locktime = 0; vin = [{prev_txid = to_spend.txid, vout = 0, sequence = 0, scriptSig = empty, witness = sig_stack}]; vout = [{value = 0, scriptPubKey = OP_RETURN}]` | ABSENT — no `to_sign` construction. |
| 24 | BIP-322 sighash | BIP-143 / BIP-341 sighash of the `to_sign` tx using `to_spend` as the spent output | ABSENT — no BIP-322-specific sighash plumbing. |
| 25 | BIP-322 NUMS-point fallback for script-path taproot | spec: when signing with a script-path-only key, the internal key is set to NUMS point `lift_x(0x50929b74…)` so spend cannot use key-path | ABSENT — `grep -rn "NUMS\|nums\|H_NUMS\|0x50929b74" --include="*.nim"` returns 0 hits. |
| 26 | BIP-322 Full mode multi-input | spec: full mode signs over multi-input `to_sign` tx allowing arbitrary scripts | ABSENT. |
| 27 | BIP-322 magic tag | `BIP322 ChallengeMessage` SHA256 tagged hash | ABSENT. |
| 28 | RPC dispatch for BIP-322 variants | Core's open PR adds `signmessagewithprivkey` and `verifymessage` overloads accepting bech32 addresses; nimrod's dispatch (`server.nim:8357-8362`) has no BIP-322-specific routes | ABSENT. |
| 29 | `signmessage` (wallet) always `compressed = true` | Core uses `CKey::IsCompressed()` per-key (`wallet.cpp::SignMessage`) | **BUG-6 (P1)** — `handleSignMessage:4647` hardcodes `compressed = true`. Inline comment at 4644-4646 says "nimrod-derived P2PKH addresses always use the compressed pubkey (see wallet.derivePath BIP44 branch)". For wallets imported via `importprivkey` (not yet implemented?) or any future code path that produces uncompressed keys, this would produce a signature whose recovered pubkey hash does NOT match the stored uncompressed address. **Comment-as-confession 10th nimrod instance** — the comment LITERALLY documents the latent fragility ("derived ... always use" — assumes the only key source). |
| 30 | Test coverage of negative paths | Core fuzzers and unit tests at `test/fuzz/message.cpp` cover header-byte edges, base64-alphabet edges, recid > 3, address-kind rejection, locked-wallet path | **BUG-10 (P2-TEST)** — `tests/test_rpc.nim:1042-1115` has 6 tests, ALL using compressed-roundtrip via primitives directly. ZERO tests exercise: (a) RPC handler dispatch (`handleSignMessage` etc.); (b) non-P2PKH address rejection; (c) URL-safe-base64-alphabet acceptance gap (BUG-1); (d) uncompressed `compressed=false` round-trip; (e) header byte edge values (26, 35); (f) locked-wallet rejection ordering (BUG-3); (g) expired-unlock fallthrough (BUG-8); (h) `signmessagewithprivkey` WIF roundtrip end-to-end. The test surface guarantees primitive byte-level correctness but NOT RPC-level Core parity. |
| 31 | Help text exposes the gap | Core's `help signmessage` documents that the address must be legacy; bech32 addresses error out | **BUG-13 (P2)** — nimrod help text at `server.nim:4575-4578` says `"signmessage \"address\" \"message\""` and `"verifymessage \"address\" \"signature\" \"message\""` with NO note that only P2PKH is supported (despite the runtime rejection). User runs `signmessage tb1q... msg`, gets "Address does not refer to key" with no breadcrumb that BIP-322 is the missing feature. Core's RPC help similarly lacks BIP-322 documentation, but Core's wallet UI surfaces "legacy address only" — nimrod has no such surface. |
| 32 | Reject-string wire-parity | Core: `"Invalid address"`, `"Address does not refer to key"`, `"Malformed base64 encoding"`, `"Sign failed"`, `"Private key not available"`, `"Error: Please enter the wallet passphrase with walletpassphrase first."` | PASS for strings — `server.nim:4625, 4631, 4641, 4650, 4671, 4676, 4680, 4636, 4704, 4710` all match Core's exact strings. **But the message-string parity is undercut by the error-code divergence in BUG-2 + BUG-4** — string-matching clients pass, code-matching clients fail. (Echoes W155 BUG-15 / W125 reject-string wire-parity slippage.) |
| 33 | `signMessage` output base64 padding | Core's `EncodeBase64` always pads to `% 4 == 0` (`util/strencodings.cpp:105-107`) | PASS — Nim std/base64 `encode` also pads. 65-byte input → 88-char output (66 chars data + 2 `=` pad). |
| 34 | `messageHash` performance — per-byte loop | Core uses `HashWriter::operator<<` which writes the string in one chunk via `Serialize` | **BUG-11 (P2-PERF)** — `signmessage.nim:33-34` and `36-37` iterate the message **byte-by-byte** with `for c in MessageMagic: w.writeUint8(uint8(c))` and same for the user message. For a 1-MiB user message (no length cap in the handler — see BUG-14), this is 1M individual `seq.add` calls. Use `writeBytes(w, cast[seq[byte]](message))` or equivalent for O(1) call count. |
| 35 | Message length cap | Core has no explicit cap; the JSON-RPC body size limit (`-rpcmaxsize`) bounds it indirectly | **BUG-14 (P2)** — `handleSignMessage`, `handleSignMessageWithPrivkey`, `handleVerifyMessage` accept arbitrary-length `params[i].getStr()`. Combined with BUG-11's O(n) per-byte loop, a 100-MiB message-arg DoS-amplifies the per-RPC cost. Add a sanity cap (e.g., 100k chars, matching `MAX_SCRIPT_ELEMENT_SIZE * 256`) at handler entry. Core's `-rpcmaxsize` is the right knob — nimrod's RPC server should enforce a similar cap. |
| 36 | `messageHash` overload — bytes vs string | Core's `MessageHash(const std::string& message)` accepts arbitrary bytes (Nim `string` is byte-sequence-compatible, so this works) | PASS — Nim `string` is a byte sequence and `uint8(char)` for any 0..255 value works (verified). |
| 37 | byte-order divergence inside `signmessage` module | W155 BUG-15 echo: nimrod has 20+ documented two-pipeline-guard extensions; check the sign + verify pair for symmetric byte handling | PASS — both paths construct `sig64` and `header` byte-identically; no LE/BE drift inside `signmessage.nim` itself. (The fleet pattern doesn't show up in this module.) |
| 38 | Multi-key sign attempt (wallet has many addresses) | Core's `SignMessage` finds the correct key via the spk-manager regardless of which account/keypool the address lives in | PASS — `findKeyForAddress` (`wallet.nim:702-711`) walks every account's external + internal keys. |
| 39 | Re-derive after wallet decryption | Wallet keys are re-derived on unlock (per CLAUDE comment `wallet.nim:503-504`) — so `findKeyForAddress` MAY return `none` immediately after unlock if the derivation cache hasn't been rebuilt | **BUG-15 (P2)** — `wallet.nim:503-504` comment says "Keys are not loaded - they will be re-derived when needed after the wallet is unlocked (for encrypted wallets) or on first use". `handleSignMessage:4638` calls `findKeyForAddress` directly without checking whether the post-unlock derivation has run. Race: unlock → first signmessage may return `none` ("Private key not available") even though the address IS in the wallet. Subsequent calls succeed. **Comment-as-confession** — the comment documents the race precondition and the handler ignores it. |
| 40 | `signmessage` RPC docs anchor | Core's `signmessage` reference URL: `bitcoin-core/src/wallet/rpc/signmessage.cpp` | PASS — `server.nim:4613` cites the Core path. |

---

## BUG-1 (P0-CDIV) — `verifyMessageRaw` accepts URL-safe base64 alphabet (`-` `_`); Core's `DecodeBase64` rejects

**File:** `src/crypto/signmessage.nim:72`
**Severity:** P0-CDIV (wire-format divergence on `verifymessage` RPC).

`verifyMessageRaw` calls Nim std/base64 `decode` to parse the
signature. Nim's `decode` proc (`lib/pure/base64.nim:200-209,214`)
shares a single decode-table that treats `+`/`-` as 62 and `/`/`_`
as 63 — both standard and URL-safe alphabets are accepted
interchangeably. Bitcoin Core's `DecodeBase64`
(`util/strencodings.cpp:110-143`) hard-codes a strict standard-alphabet
table where every URL-safe character maps to `-1` (reject).

Consequence: a signature presented as URL-safe-encoded 65 bytes
(common output from JavaScript libraries that default to URL-safe)
is silently accepted by nimrod and verified normally; Bitcoin Core
returns `ERR_MALFORMED_SIGNATURE` → RPC raises `RPC_TYPE_ERROR` (-3).
A multi-node fleet probe that compares `verifymessage` results
between nimrod and Core sees a TRUE / ERROR split for the same
input — and an attacker can craft inputs where this asymmetry leaks
information about which implementation the verifier runs.

**Fix:** import the bitcoin-core-style strict decoder. Either bundle
a local 256-entry decode table that maps `-` and `_` to -1, or wrap
the std decode with a pre-validation regex `^[A-Za-z0-9+/]+=*$`.

**Verify-fix.sh corpus:** synthesise a known-good 65-byte sig, swap
`+` → `-` and `/` → `_` in the base64 output, and assert nimrod
post-fix returns `ERR_MALFORMED_SIGNATURE` (matching Core).

---

## BUG-2 (P1-RPC) — `verifymessage` uses wrong RPC error code for `ERR_ADDRESS_NO_KEY` + `ERR_MALFORMED_SIGNATURE` (-5 instead of -3)

**File:** `src/rpc/server.nim:4671, 4676, 4680, 4631`
**Severity:** P1-RPC (wire-shape divergence on error response).

Bitcoin Core's `rpc/signmessage.cpp:46-49` maps
`ERR_ADDRESS_NO_KEY` and `ERR_MALFORMED_SIGNATURE` to
`RPC_TYPE_ERROR` (-3). nimrod has no `RpcTypeError` constant
(verified by `tests/test_w125_error_parity.nim:159-167` Gate 7
which explicitly asserts the absence) and raises
`RpcInvalidAddressOrKey` (-5) instead.

Comment-as-confession at `server.nim:4628-4630` literally says
"Bitcoin Core uses RPC_TYPE_ERROR (-3) here. We don't have a
constant for that yet, but RpcInvalidAddressOrKey communicates the
same intent to clients that just check the message string." This
is the **9th instance** of the comment-as-confession pattern in
nimrod (W141 BUG-5 was 4th, W155 had additional, plus W156/W157).

**Impact:** RPC clients that filter on `error.code == -3` (the
universal Bitcoin Core idiom for "wrong type / wrong format") miss
the error and surface a misleading "-5 invalid address" message.

**Fix:** add `RpcTypeError* = -3` to `server.nim:79-93` (closes
W125 Gate 7), then route the three relevant raises through it. Net
~10 LOC.

---

## BUG-3 (P1-RPC) — `handleSignMessage` checks address validity BEFORE wallet-lock state; Core checks wallet first

**File:** `src/rpc/server.nim:4621-4636`
**Severity:** P1-RPC (information leak + RPC-ordering divergence).

Bitcoin Core's `wallet/rpc/signmessage.cpp:42-44` calls
`EnsureWalletIsUnlocked(*pwallet)` BEFORE
`DecodeDestination(addr)`. nimrod inverts this order: parse address
(4621-4625) → reject non-P2PKH (4627-4631) → get wallet (4633) →
check locked (4634-4636).

**Impact:** an unauthenticated probe of "does wallet X have
address A loaded?" can distinguish three cases:

| State                                 | Core response                                           | nimrod response                          |
|---------------------------------------|---------------------------------------------------------|------------------------------------------|
| wallet locked, address valid P2PKH    | "Error: Please enter the wallet passphrase..."          | "Error: Please enter the wallet passphrase..." |
| wallet locked, address valid non-P2PKH | "Error: Please enter the wallet passphrase..."          | "Address does not refer to key"          |
| wallet locked, address invalid format | "Error: Please enter the wallet passphrase..."          | "Invalid address"                        |

So nimrod LEAKS via timing/error-message whether the input is a
syntactically valid bech32 / P2SH / etc. address vs total
gibberish, even when the wallet is locked.

**Fix:** in `handleSignMessage`, move the `getTargetWallet` +
`isLocked` check to the top (before `decodeAddress`). 5 LOC reorder.

---

## BUG-4 (P1-RPC) — "Private key not available" raises `RpcInvalidAddressOrKey` (-5); Core uses `RPC_WALLET_ERROR` (-4)

**File:** `src/rpc/server.nim:4639-4641`
**Severity:** P1-RPC (wire-shape divergence).

Bitcoin Core's `wallet/rpc/signmessage.cpp:63-65` maps
`SigningResult::PRIVATE_KEY_NOT_AVAILABLE` (and any non-SIGNING_FAILED
non-OK result) to `RPC_WALLET_ERROR` (-4). nimrod raises
`RpcInvalidAddressOrKey` (-5).

**Impact:** smart wallets that retry-with-unlock on -4 vs prompt-user
on -5 misroute. Same root cause as BUG-2 (mis-mapping to the
nearest available constant rather than adding the right one).

**Fix:** use `RpcWalletError` (already defined at `server.nim:89`).
1-line change at `:4640`.

---

## BUG-5 (P1) — `handleVerifyMessage` does NOT catch `Secp256k1Error`; stub-build (`-d:useSystemSecp256k1` absent) crashes the request with `RPC_INTERNAL_ERROR`

**File:** `src/rpc/server.nim:4673` (no try/except wrapping the
`verifyMessageRaw` call)
**Severity:** P1 (build-config-specific failure mode).

When nimrod is compiled WITHOUT `-d:useSystemSecp256k1`,
`src/crypto/secp256k1.nim:931-939` provides stubs that
`raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")`
on every call. `verifyMessageRaw` calls `recoverCompactPubkey` which
hits the stub.

`handleSignMessage:4646-4650` and `handleSignMessageWithPrivkey:4706-4710`
both wrap their `signMessage` calls in try/except `Secp256k1Error`.
`handleVerifyMessage:4673` does not — the exception propagates
through the RPC dispatch and surfaces as `RPC_INTERNAL_ERROR`.

Core never produces an exception path for verify; it returns false
on any libsecp failure.

**Fix:** wrap the `verifyMessageRaw` call in `try/except
Secp256k1Error` and return `mvrPubkeyNotRecovered` → `%false`. 5 LOC.

---

## BUG-6 (P1) — `handleSignMessage` hardcodes `compressed = true`; ignores wallet-key compression state

**File:** `src/rpc/server.nim:4644-4647`
**Severity:** P1 (latent fragility; comment-as-confession 10th).

Comment at 4644-4646 reads "nimrod-derived P2PKH addresses always
use the compressed pubkey (see wallet.derivePath BIP44 branch), so
set the compressed flag accordingly." `signMessage(key.extKey.key,
message, compressed = true)` at 4647 hardcodes the flag.

This is correct TODAY because BIP44 derivation always yields
compressed pubkeys (`wallet.nim:506-522`). It breaks the moment
nimrod adds `importprivkey`, `importwallet`, or any third-party
key-import path that may carry an uncompressed key (mostly historic
2009-era addresses). The signature header byte would be `27 + recid + 4`
but the address's `pkh = hash160(uncompressed_pubkey)` would not
match `hash160(compressed_pubkey_from_recovery)`, so verify always
fails — silent sign-then-can-never-verify.

**Fix:** read the compressed flag from the wallet key. Need to
plumb `compressed: bool` through `DerivedKey` (currently absent —
verified by grep). 10-20 LOC including type-shape change.

---

## BUG-7 (P1) — `verifyMessageRaw` header range check + recid extraction live in two adjacent statements; future refactor could underflow `uint8`

**File:** `src/crypto/signmessage.nim:79-83`
**Severity:** P1 (latent; current code is correct).

```nim
let header = uint8(sigBytesStr[0])
if header < 27 or header > 27 + 4 + 3:
  return mvrMalformedSignature
let recid = int((header - 27) and 3)
let compressed = ((header - 27) and 4) != 0
```

If a future refactor moves the bounds check below the recid
extraction (e.g., factoring into a `parseSig` helper), `header - 27`
for `header < 27` underflows `uint8` to a value like `0xff - X`,
yielding a bogus recid that survives the `and 3` mask and feeds a
nonsense `recid` to `recoverCompactPubkey`. libsecp256k1's
`recoverable_signature_parse_compact` validates `0 ≤ recid ≤ 3` so
it would reject — but the recid value reported in error logs would
be misleading.

**Fix:** sealed `parseHeaderByte(header: uint8): tuple[recid: int,
compressed: bool, ok: bool]` helper that bundles range check +
extraction; impossible to call extraction without the check.

---

## BUG-8 (P1-SEC) — `checkUnlockExpiry` defined + exported but called from ZERO RPC handlers; `signmessage` can fire after passphrase timeout

**File:** `src/wallet/wallet.nim:1502-1506` (defined),
`src/rpc/server.nim:4634` (not consulted)
**Severity:** P1-SEC (privilege-escalation window).

`checkUnlockExpiry` is defined at `wallet.nim:1502-1506` and
re-locks the wallet if `getTime() >= unlockExpiry`. Verified by
`grep -n "checkUnlockExpiry" src/rpc/server.nim src/wallet/*.nim`
that it is called from NO production RPC. `handleSignMessage:4634`
consults `wallet.isLocked` directly, which is only flipped to true
by `lockWallet()` — which is in turn only called by manual
`walletlock` RPC or `changePassphrase`.

**Attack window:** user unlocks for 30 seconds (`walletpassphrase
"pw" 30`). At T+45s, `unlockExpiry` is in the past but `isLocked`
is still false because no path has called `checkUnlockExpiry`. An
attacker who has captured the RPC socket can call `signmessage` at
T+60s and the wallet signs.

Same fleet pattern as the W141 BUG-5 / W144 dead-helper-at-call-site
class. **Fleet-pattern "dead-helper": function exists + exported +
NOT called from the security-critical path.**

**Fix:** `handleSignMessage` (and every other RPC that signs/spends)
calls `wallet.checkUnlockExpiry()` BEFORE consulting `isLocked`. Add
a single helper `proc ensureUnlocked(rpc, wallet) = ...` and route
all wallet-write RPCs through it.

---

## BUG-9 (P1-RPC) — Nim std/base64 tolerates `len % 4 != 0`, embedded whitespace, partial padding; Core rejects all

**File:** `src/crypto/signmessage.nim:72`
**Severity:** P1-RPC (companion to BUG-1; less severe because the
65-byte length gate catches most cases).

Nim std/base64 `decode` (`lib/pure/base64.nim:248-249`) strips
trailing `\n` `\r` ` ` `=` characters from input and then
walks the body skipping embedded `\n` `\r` ` ` whitespace (line
253-254). Core's `DecodeBase64` rejects on `size % 4 != 0`
(`util/strencodings.cpp:128`) AND on embedded whitespace AND on
non-alphabet bytes.

**Real-world:** a JSON-RPC client that posts a sig containing a
stray newline (common when manually pasted) is accepted by nimrod
and decoded to bytes that may or may not be 65 — Core hard-rejects
with `ERR_MALFORMED_SIGNATURE`. Combined with BUG-1, the wire-shape
divergence covers ~4 distinct input classes.

**Fix:** as BUG-1 (strict decoder).

---

## BUG-10 (P2-TEST) — Test coverage limited to compressed-roundtrip via primitives; ZERO tests exercise RPC handlers, address-kind rejection, base64 alphabet, locked-wallet ordering

**File:** `tests/test_rpc.nim:1042-1115`
**Severity:** P2 (test gap).

The suite has 6 tests:

1. `messageHash matches MESSAGE_MAGIC || msg framing` — primitive
2. `MessageMagic constant matches Bitcoin Core` — primitive constant
3. `signCompactRecoverable -> recoverCompactPubkey roundtrip` — primitive
4. `signMessage -> verifyMessageRaw roundtrip (compressed)` — primitive
5. `verifyMessageRaw rejects malformed base64` — primitive
6. `verifyMessageRaw NotSigned for unrelated address` — primitive

ZERO tests for any of:

- RPC handler dispatch (`handleSignMessage` etc.)
- BUG-1 base64-alphabet divergence
- BUG-2 / BUG-4 error code mapping (Bitcoin Core uses -3 / -4)
- BUG-3 locked-wallet ordering (information leak)
- BUG-6 uncompressed flag round-trip
- BUG-7 header byte boundary values (26 / 35)
- BUG-8 expired-unlock fallthrough
- `signmessagewithprivkey` end-to-end (no test at all — verified
  `grep -n "signmessagewithprivkey" tests/`)
- BIP-322 absence (we should at least assert that bech32 addresses
  produce a clear error message)

Add a `test_w158_signmessage_parity.nim` with one test per gate
above. Run against running RPC server (CI pattern) for the
dispatch-level checks.

---

## BUG-11 (P2-PERF) — `messageHash` writes the magic + message byte-by-byte instead of using `writeBytes`

**File:** `src/crypto/signmessage.nim:33-37`
**Severity:** P2 (perf; amplifies BUG-14 DoS surface).

```nim
w.writeCompactSize(uint64(MessageMagic.len))
for c in MessageMagic:
  w.writeUint8(uint8(c))
w.writeCompactSize(uint64(message.len))
for c in message:
  w.writeUint8(uint8(c))
```

Each `writeUint8` calls `seq[byte].add` (`serialize.nim:19-20`).
For an N-byte message, this is N individual `seq.add` calls vs one
`writeBytes` call. Combined with BUG-14 (no length cap), a 100-MiB
message costs ~100M function calls plus the inevitable seq grow-
and-copy.

**Fix:**

```nim
w.writeCompactSize(uint64(MessageMagic.len))
w.writeBytes(cast[seq[byte]](MessageMagic))  # or .toOpenArrayByte(0, MessageMagic.high)
w.writeCompactSize(uint64(message.len))
w.writeBytes(cast[seq[byte]](message))
```

`writeBytes` is defined at `serialize.nim:40-42` (uses `data.add(b)`
which is single-call for openArray).

---

## BUG-12 (P1-CAP / fleet-wide) — No BIP-322 implementation anywhere in nimrod; bech32 addresses cannot sign messages

**File:** `src/crypto/` (entire directory) + `src/rpc/server.nim`
**Severity:** P1-CAP (capability gap; fleet-wide).

Verified absences:

- `grep -rni "bip322\|bip-322\|BIP322\|BIP-322" --include="*.nim"`
  → 0 matches.
- `grep -rni "to_spend\|to_sign\|tospend\|tosign\|virtual_tx"
  --include="*.nim"` → 0 matches.
- `grep -rni "NUMS\|nums_point\|H_NUMS\|0x50929b74" --include="*.nim"`
  → 0 matches.
- `grep -rni "BIP322 ChallengeMessage\|BIP322_HASH_TAG"` → 0
  matches.

**Fleet context:** Bitcoin Core itself does not have BIP-322 in
mainline as of 2026-05 (PR #24058 open since 2022). However, modern
wallets that use BIP-84 (m/84'/) or BIP-86 (m/86'/) derivation
produce only bech32 addresses. Users of those wallets CANNOT use
nimrod's `signmessage` at all — `handleSignMessage:4627-4631`
rejects every non-P2PKH address with "Address does not refer to
key" (and with the wrong error code per BUG-2).

**Mitigation steps (in priority order):**

1. (W158 audit) — document the gap.
2. (Fleet sweep) — quad-audit other 9 impls to confirm fleet-wide
   absence; treat as a fleet-pattern carry-forward.
3. (Future) — implement BIP-322 Simple mode for P2WPKH (the
   common case) when Core PR #24058 merges; build the virtual-tx
   primitives in `src/crypto/bip322.nim`.

---

## BUG-13 (P2) — Help text does not advertise the P2PKH-only limitation

**File:** `src/rpc/server.nim:4575-4578`
**Severity:** P2 (UX).

Help entries:

```
signmessage "address" "message"
signmessagewithprivkey "privkey" "message"
verifymessage "address" "signature" "message"
```

No mention of "address must be legacy P2PKH". Users running
`signmessage bc1q...` get "Address does not refer to key" with
zero breadcrumb that BIP-322 is the missing feature. Core's help
also lacks the BIP-322 note but Core's wallet GUI surfaces the
limitation.

**Fix:** append " (legacy P2PKH only — BIP-322 not yet supported)"
to each entry.

---

## BUG-14 (P2) — No message-length cap; combined with BUG-11 amplifies DoS surface

**File:** `src/rpc/server.nim:4619, 4662, 4695` (every
`params[i].getStr()` returning the message)
**Severity:** P2 (DoS).

`handleSignMessage`, `handleSignMessageWithPrivkey`, `handleVerifyMessage`
each call `params[i].getStr()` on the message and forward to
`signMessage` / `verifyMessageRaw` without a length sanity check.
Combined with BUG-11's per-byte loop, a 100-MiB message argument
DoS-amplifies cost.

Core bounds this indirectly via `-rpcmaxsize` (default 32 MiB JSON
body). nimrod's RPC server should enforce a similar bound globally
and the handler should reject anything > 32 KiB before hitting the
hash function (no realistic Bitcoin-signed-message use case needs
even 1 KiB).

**Fix:** add `if message.len > 32 * 1024: raise newRpcError(...)`
at handler entry.

---

## BUG-15 (P2) — Wallet key re-derivation race; first `signmessage` after `walletpassphrase` may return "Private key not available"

**File:** `src/wallet/wallet.nim:503-504` (comment),
`src/rpc/server.nim:4638` (consumer)
**Severity:** P2 (intermittent UX glitch; race).

Comment at `wallet.nim:503-504` reads "Keys are not loaded - they
will be re-derived when needed after the wallet is unlocked (for
encrypted wallets) or on first use".

`handleSignMessage:4638` calls `findKeyForAddress` directly. If
`unlockWallet` does NOT trigger re-derivation immediately (the
comment implies it doesn't), the first signmessage after unlock
hits an empty `account.externalKeys` / `account.internalKeys`
table → `findKeyForAddress` returns `none` → raise "Private key
not available". A subsequent call (after listunspent or
getnewaddress triggers re-derivation) succeeds.

**Comment-as-confession:** the comment LITERALLY documents the
race precondition and the handler ignores it.

**Fix:** post-unlock, `unlockWallet` should re-derive all keys
synchronously OR `findKeyForAddress` should fall back to deriving
on-demand. Either way, the race surface vanishes.

---

# Carry-forwards from earlier waves

- **W141 BUG-8 (mempoolminfee divisor):** CLOSED today by user via
  commit `591733b`. The bug-class — "1000× unit divisor" — is
  unrelated to this wave but the closure validates the
  "open-bug carry-forward" hygiene. Verified
  `src/rpc/server.nim:1200` and `src/rpc/rest.nim:780` now divide
  by the right scalar (post-FIX).
- **W155 BUG-15 (GBT `bits` LE vs Core BE):** STILL OPEN; not in
  W158 scope (`signmessage` module byte-handling is internally
  symmetric so no new instance — see row 37 in matrix).
- **W155 BUG-17 (submitblock side-branch persistence skips
  acceptBlock; 5th nimrod consensus-bypass entry point):** STILL
  OPEN; orthogonal to W158.
- **W125 Gate 7 (`RpcTypeError = -3` MISSING):** STILL OPEN; surfaces
  again as W158 BUG-2 and BUG-4 root cause. Fixing W125 Gate 7
  would let W158 BUG-2 / BUG-4 close trivially via 3-line code
  reroute.

# Fleet pattern observations new in this wave

- **Comment-as-confession (9th + 10th nimrod instance):**
  - BUG-2 root: server.nim:4628-4630 ("Bitcoin Core uses
    RPC_TYPE_ERROR (-3) here. We don't have a constant for that
    yet" — 9th).
  - BUG-6 root: server.nim:4644-4646 ("nimrod-derived P2PKH
    addresses always use the compressed pubkey" — 10th).
  - BUG-15 root: wallet.nim:503-504 (race race documented in
    comment, handler ignores it).
- **Dead-helper-at-call-site (W141 BUG-5 / W144 / W150 echoes):**
  - BUG-8: `checkUnlockExpiry` defined + exported + called from
    ZERO security-critical RPC paths. Sub-variant of the W141
    pattern (which was "function exists, exported, called but
    no-op"). New sub-variant: "function exists, exported, NEVER
    called from the path that needs it."
- **"Wrong-code, right-message" (W125 echo, extended):** BUG-2,
  BUG-4 both raise the wrong RPC error code but use the exact
  Core message string. Clients that string-match pass; clients
  that code-match fail. Same shape as W155's reject-string wire-
  parity slippage.
- **Plumb-gate-then-flip 8th instance (nimrod fleet pattern):**
  Not present in this wave's code (no new plumbing). But BUG-6's
  hardcoded `compressed = true` IS plumb-gate-then-don't-flip in
  the wallet→sign direction: the wallet HAS the compressed flag
  but the RPC handler hardcodes the bool instead of plumbing it.
- **Latent uint8-underflow guarded only by adjacency (BUG-7):**
  pattern adjacent to "two-pipeline-guard" — here it's a
  one-pipeline-with-precondition-not-encapsulated.

---

# Severity tallies

- **P0-CONS:** 0 (no consensus rules touched by message signing)
- **P0-CDIV:** 1 (BUG-1 base64 alphabet divergence on `verifymessage`)
- **P0-SEC:** 0
- **P1:** 9 (BUG-2 wrong error code -5 vs -3; BUG-3 wallet check
  ordering / info leak; BUG-4 wrong error code -5 vs -4; BUG-5
  uncaught Secp256k1Error; BUG-6 hardcoded compressed flag; BUG-7
  latent uint8 underflow; BUG-8 dead checkUnlockExpiry; BUG-9 lax
  base64 size discipline; BUG-12 BIP-322 absent / bech32 sign
  unsupported)
- **P2:** 5 (BUG-10 test coverage; BUG-11 per-byte loop; BUG-13
  help text; BUG-14 no message-length cap; BUG-15 wallet key
  re-derivation race)

**Total: 15 bugs** (1 P0-CDIV, 9 P1, 5 P2).

---

# Priority fix ranking (single-impl, not fleet-wide)

1. **BUG-1 (P0-CDIV)** — strict base64 decoder. 1 module addition
   (~30 LOC). Closes wire-format divergence. ★ TOP PRIORITY.
2. **BUG-8 (P1-SEC)** — wire `checkUnlockExpiry` into every wallet-
   write RPC. ~5 LOC + carry-forward fleet hygiene. ★ SECURITY.
3. **BUG-2 + BUG-4 (P1-RPC) + W125 Gate 7** — add `RpcTypeError =
   -3` constant; reroute 3 raises. ~5 LOC; closes 3 bugs across
   2 audits in one commit.
4. **BUG-3 (P1-RPC)** — reorder wallet check before address
   decode. ~5 LOC; closes info-leak.
5. **BUG-5 (P1)** — wrap `verifyMessageRaw` in try/except
   `Secp256k1Error`. ~5 LOC.
6. **BUG-6 (P1)** — plumb compressed flag through DerivedKey;
   stop hardcoding. ~15 LOC.
7. **BUG-9 (P1)** — bundled with BUG-1's strict decoder.
8. **BUG-12 (P1-CAP)** — fleet-wide quad-audit BIP-322 absence
   first; defer impl until Core PR #24058 merges.
9. **BUG-15 (P2)** — derive keys synchronously on unlock. ~10 LOC.
10. **BUG-7, BUG-10, BUG-11, BUG-13, BUG-14** — P2 cleanup batch
    in a single PR. ~40 LOC.

---

# Notes for fleet-wide W158 cross-audit

The following gates are likely fleet-wide patterns (predictions
for sibling-impl agents to verify):

- **BIP-322 absent in 10 of 10 impls** (fleet-wide capability gap;
  none of the 10 has even started the virtual-tx plumbing).
- **Base64 alphabet divergence on verify** — likely present in any
  impl whose host language's stdlib `base64.decode` tolerates
  URL-safe (Python `base64.b64decode`, Go `base64.StdEncoding` vs
  `URLEncoding`, JS `atob`, Lua varies). Hashkoin / Lua impls
  likely most-affected; Go is strict (uses `StdEncoding` explicitly).
- **Wrong error-code mapping** — fleet's RPC error tables are
  likely missing or mis-defining `RPC_TYPE_ERROR = -3` since it's
  rarely-emitted from Core in other contexts; nimrod and clearbit
  are the known offenders pre-W158.
- **`signmessage` hardcodes `compressed = true`** — likely 6+ of
  10 impls (Lua impls in particular use compressed-only key
  pipelines).
- **`checkUnlockExpiry`-class helper defined but not called** —
  fleet-pattern dead-helper sub-variant; estimate 5+ of 10.
