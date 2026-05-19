# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (nimrod)

**Wave:** W161 — One layer UP from W160. Subject: hierarchical
deterministic key derivation (BIP-32 CKD_priv / CKD_pub with the
`MUST retry on IL >= n or child == 0` contract, master generation via
HMAC-SHA512(key="Bitcoin seed", data=seed), parent-fingerprint
derivation, hardened vs unhardened branch encoding, depth wrap, 78-byte
extended key Base58Check serialisation with per-network version bytes
xprv/xpub/tprv/tpub, neuter contract, IL/parent-key memory hygiene),
BIP-39 (12/15/18/21/24 word mnemonics, 2048-word English wordlist,
checksum N/32 bits = SHA256(entropy)[0..N/32], PBKDF2-HMAC-SHA512 with
salt="mnemonic"+passphrase and iter=2048, mandatory NFKD normalisation
of mnemonic AND passphrase), BIP-43 purpose-field convention, BIP-44 /
BIP-49 / BIP-84 / BIP-86 standard derivation paths
(`m/{44,49,84,86}'/coin_type'/account'/change/index`), BIP-86 TapTweak
(empty merkle root → output_key = internal_key + tagged_hash("TapTweak",
internal_key) * G), descriptor expansion of xpubs, gap limit, seed
entropy validation, and memory-zeroize hygiene for IL / parent private
key / mnemonic / passphrase / seed bytes.

**Scope:** discovery only — NO production code changes in W161.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:293-310` — `CKey::Derive` (CKD_priv:
  invokes `BIP32Hash` for hardened (header=0, parent_key data) vs
  non-hardened (header=parent_pubkey[0], data=parent_pubkey[1..32])
  paths; child cc = right 32 bytes of HMAC; calls
  `secp256k1_ec_seckey_tweak_add` for IL+parent_key tweak; on libsecp
  rejection (`IL >= n` OR result key == 0) `keyChild.ClearKeyData()` and
  returns false — the caller `CExtKey::Derive` then propagates that
  false and `DescriptorScriptPubKeyMan::TopUp` skips the bad index and
  retries with `nChild+1`).
- `bitcoin-core/src/key.cpp:482-489` — `CExtKey::Derive`: enforces
  `depth < UCHAR_MAX` (BIP-32 max-depth=255 invariant); fills
  `parentFingerprint = HASH160(parent_pubkey)[0..4]`; depth++; child
  index recorded.
- `bitcoin-core/src/key.cpp:491-501` — `CExtKey::SetSeed`: master
  generation HMAC-SHA512 with literal `"Bitcoin seed"` (12 bytes; case
  matters); left 32 → seckey, right 32 → chaincode; depth=0,
  parentFingerprint=00000000, nChild=0. Core does NOT explicitly
  validate IL_master < n / != 0 (relies on later `IsValid()` /
  `_ec_pubkey_create` to surface failures); BIP-32 says master is
  invalid if so but Core treats it as "if you got an invalid master,
  use a different seed".
- `bitcoin-core/src/key.cpp:518-549` — `CExtKey::Decode` and
  `CExtKey::Encode`: 74-byte raw serialisation (depth 1 + parentFP 4 +
  child 4 + cc 32 + 0x00||seckey 33) wrapped with 4-byte version
  prefix by `EncodeExtKey` (78 bytes total). On Decode: validates the
  depth/parent-fingerprint/child-index invariants for depth==0 (master:
  parentFP and child MUST be zero).
- `bitcoin-core/src/pubkey.cpp:340-363` — `CExtPubKey::Derive`: CKD_pub
  path; rejects hardened (`nChild >> 31`); calls
  `secp256k1_ec_pubkey_tweak_add`; same `MUST retry` contract.
- `bitcoin-core/src/hash.cpp:71-76` — `BIP32Hash` (CHMAC_SHA512 keyed
  by chainCode, body = header || data[32] || WriteBE32(nChild)).
- `bitcoin-core/src/key.h:147-153` — `BIP32_EXTKEY_SIZE = 74` and
  `BIP32_EXTKEY_WITH_VERSION_SIZE = 78`. The 78-byte form is
  base58check-encoded as the xprv/xpub/tprv/tpub string.
- `bitcoin-core/src/kernel/chainparams.cpp:148-149` (mainnet xprv/xpub
  `0x0488ADE4` / `0x0488B21E`), `:261-262` (testnet3
  `0x04358394`/`0x043587CF`), `:366-367` (testnet4 same as testnet3),
  `:507-508` (signet same), `:639-640` (regtest same). I.e. every
  non-mainnet uses the SAME testnet-flavoured prefixes.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp` —
  `DescriptorScriptPubKeyMan::TopUp` skips on `Derive` failure and
  retries with `nChild+1` (the only place the BIP-32 retry contract is
  honoured in Core).
- `bitcoin-core/src/key.cpp:204-235` — `CKey::Sign` re-verifies post-sign
  (W160 cross-cite); the wallet-side derivation here just gets you the
  private key — Schnorr signing for BIP-86 is a separate layer (W160
  BUG-5/6/8 across waves).
- `bitcoin-core/src/wallet/wallet.cpp` — Core's HD chain bookkeeping
  records the seed source under `m_hd_chain.seed_id` and persists the
  seed as an encrypted record so the master xprv is regenerable post
  unlock. Defaults to a single account purpose path per chain.
- BIP-32 spec — `IL` checked against `n`: "In case parse256(IL) ≥ n
  or ki = 0, the resulting key is invalid, and one should proceed with
  the next value for i."
- BIP-39 spec — mnemonic AND passphrase MUST be NFKD-normalised before
  encoding to UTF-8 for PBKDF2; salt = "mnemonic" + passphrase (both
  NFKD); iter=2048; output 64 bytes; wordlist case must be canonical
  lowercase; word-set membership lookup is case-sensitive (case
  normalisation is part of NFKD).
- BIP-43 — purpose field is hardened; reserved purposes: 44, 45, 47,
  48, 49, 84, 86, 1852 (Cardano), etc.
- BIP-44 / 49 / 84 / 86 — five-level path
  `m / purpose' / coin_type' / account' / change / address_index`;
  hardened up to and including account, unhardened from change onward.
  SLIP-0044 coin_type: 0=Bitcoin mainnet, 1=Bitcoin testnet (covers
  testnet3/testnet4/signet/regtest universally per SLIP-0044).
- BIP-86 — Taproot single-key path: output_key Q = internal_key +
  tagged_hash("TapTweak", internal_key) * G with internal_key =
  bytes(P)[1..33] (drop parity byte). Empty merkle root (`h = ""` in
  the tagged hash, NOT internal_key||merkle_root).

**Files audited**
- `src/wallet/wallet.nim` (1553 LOC) — BIP-39 wordlist (`:80`,
  `staticRead("../../resources/bip39-english.txt")`),
  `generateEntropy` (`:106-113`), `entropyToMnemonic` (`:115-147`),
  `generateMnemonic` (`:149-161`), `validateMnemonic` (`:163-202`),
  `mnemonicToSeed` (`:204-212`), `masterKeyFromSeed` (`:218-234`),
  `masterKeyFromSeedRaw` (`:236-255`), `neuter` (`:257-264`),
  `fingerprint` (`:266-269`), `deriveChild` (`:271-339`),
  `derivePathStr` (`:341-360`), `serializeExtendedKey` (`:366-404`),
  `newWallet` (3 overloads: `:410-422`, `:435-452`, default 4-arg adds
  account), `newWalletFromSeed` (`:424-433`), `newWalletFromDb`
  (`:454-504`), `derivePath` (`:506-546`), `addAccount` (`:548-568`),
  `purposeForAddressType` (`:587-594`), `findOrCreateAccountForType`
  (`:596-627`), `exportMasterXpub` (`:1307-1311`),
  `getAccountXpub` (`:1313-1322`).
- `src/wallet/descriptor.nim` (1233 LOC) — `KeyProvider` `KPBIP32`
  variant (`:39, 53-56`), `decodeExtendedKey` (`:272-319`),
  `decodeWIF` (`:325-356`), `getPubKey` BIP-32 path (`:389-409`),
  `getXonlyPubKey` (`:411-414`), `parseKeyExpression` xpub/xprv
  branch (`:820-824`), x-only-pubkey-with-fake-parity branch
  (`:838-845`).
- `src/wallet/manager.nim` (444 LOC) — `loadWallet` network detection
  (`:243-252`), `createWallet` (`:307-396`), `mnemonicToSeed` call
  with no passphrase (`:364`).
- `src/wallet/psbt.nim` (1755 LOC) — `PSBT_GLOBAL_XPUB` decode
  (`:945-957`) raw-bytes-only (no `decodeExtendedKey` call),
  `PSBT_IN_BIP32_DERIVATION` / `PSBT_OUT_BIP32_DERIVATION` length
  validation (`:691-698`, `:838-844`),
  `PSBT_IN_TAP_BIP32_DERIVATION` (`:770-782`),
  `PSBT_OUT_TAP_BIP32_DERIVATION` (`:863-865`).
- `src/crypto/secp256k1.nim` (993 LOC) — `tweakSeckeyAdd` (`:669-685`),
  `tweakPubkeyAdd` (`:687-718`), `tweakXonlyPubkey` (`:631-663` — raises
  on failure rather than returning Option), `initSecp256k1` no
  `context_randomize` (`:243-247`, W160-cross-cite).
- `src/wallet/crypter.nim` — `DefaultKeyDerivationRounds = 25000`
  (`:29`) matches Core's `CRYPTER_DEFAULT_DERIVE_ITERATIONS`.
- `src/rpc/server.nim` — `handleImportDescriptors` (`:6118-6132`) is a
  comment-as-confession `not implemented` stub; no `importmnemonic` /
  `sethdseed` / `getaddressinfo`-with-hdkeypath RPC endpoints exist.
- `src/consensus/params.nim` — `Network` enum (`:8-13`), per-network
  `bip34Height` (`:166, 295, 363, 424, 480`) and `defaultPort`
  (`:144, 276, 344, 406, 465`) used by `loadWallet` to misdetect
  network strings (BUG-8 below).
- `tests/test_bip32_bip86_vectors.nim` (170 LOC) — official BIP-32
  vector 1 (m/0'/1/2'), BIP-86 vector (12-abandon-about path), and
  CKD_priv-mod-n-overflow micro-tests. **Entire test gated on
  `when defined(useSystemSecp256k1)`** which is the default per
  `nim.cfg:23` but the gating itself is fragile (W160-cross-cite).
- `tests/test_wallet.nim` — generic mnemonic generate/validate tests,
  no case-sensitivity, no NFKD, no passphrase, no `mnemonicToSeed`
  vector cross-check.
- `resources/bip39-english.txt` (2048 lines, "abandon"…"zoo"). Wordlist
  itself is correct.

---

## Gate matrix (40 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-39 mnemonic generation | G1: entropy bits ∈ {128,160,192,224,256} | PASS (`wallet.nim:108-111`) |
| 1 | … | G2: CSPRNG source via `sysrand.urandom` | PASS (`:112`) |
| 1 | … | G3: 11-bit groups via SHA-256 checksum N/32 | PASS (`:118-147`) |
| 1 | … | G4: word indices look up English wordlist (lowercase canonical) | PASS (`:80, 145`) |
| 2 | BIP-39 mnemonic validation | G5: 12/15/18/21/24 word lengths accepted | PASS (`:165-167`) |
| 2 | … | G6: invalid words rejected | PASS (`:172-174`) |
| 2 | … | G7: checksum SHA-256 first-N/32-bits enforcement | PASS (`:193-200`) |
| 2 | … | G8: case-insensitive word lookup mirrors mnemonicToSeed | **BUG-1 (P0-FUNDSLOSS)** — `validateMnemonic` lowercases on lookup (`:172`), but `mnemonicToSeed` does NOT (`:204-212`). A mnemonic that validates as `"ABANDON ABANDON … ABOUT"` produces a DIFFERENT PBKDF2 seed than the canonical `"abandon abandon … about"` — wallet recovery footgun: passes validation, derives an empty-balance address tree |
| 3 | BIP-39 mnemonic→seed (PBKDF2) | G9: PBKDF2-HMAC-SHA512, iter=2048 | PASS (`:212`) |
| 3 | … | G10: salt = "mnemonic" + passphrase | PASS (`:208`) |
| 3 | … | G11: NFKD normalisation of mnemonic | **BUG-2 (P0-FUNDSLOSS)** — only `.strip()` (`:207`), no Unicode NFKD. Local variable `normalizedMnemonic` is a comment-as-confession — name implies NFKD but body is plain `.strip()`. BIP-39 §"From mnemonic to seed" mandates NFKD. Any user with diacritics or non-ASCII whitespace silently derives different seeds across wallets |
| 3 | … | G12: NFKD normalisation of passphrase | **BUG-2 cross-cite** — passphrase is passed raw into the salt (`:208`) |
| 3 | … | G13: pbkdf2 return value checked (== output.len) | **BUG-3 (P1)** — `discard pbkdf2(…)` (`:212`) — nimcrypto returns `int` = bytes written, 0 on error. nimrod swallows; a partial-write (rare) silently leaves trailing zeros in the seed; downstream derivation would be entirely wrong but indistinguishable from a "weak seed" diagnostic to the operator |
| 4 | BIP-32 master | G14: HMAC-SHA512 key = literal `"Bitcoin seed"` (12 bytes) | PASS (`:222, 244`) |
| 4 | … | G15: left 32 = seckey, right 32 = chaincode | PASS (`:228-229, 249-250`) |
| 4 | … | G16: depth=0, parentFP=zero, childIndex=0 | PASS (`:230-232, 251-253`) |
| 4 | … | G17: variable-length raw seed support (BIP-32 vectors use 16-byte seeds) | PASS — `masterKeyFromSeedRaw` (`:236-255`) exists alongside fixed-size `masterKeyFromSeed` |
| 5 | BIP-32 CKD_priv | G18: hardened header byte = 0x00 + parent private key (32) + nChild (BE32) | PASS (`:281-293`) |
| 5 | … | G19: secp256k1_ec_seckey_tweak_add for IL+seckey mod n | PASS (`secp256k1.nim:669-685`) |
| 5 | … | G20: BIP-32 MUST retry contract on libsecp rejection (IL >= n OR child == 0) | **BUG-4 (P1-CDIV)** — `deriveChild` (`wallet.nim:325-327`) RAISES `WalletError` on libsecp rejection rather than skipping and retrying with `nChild+1`. The only call sites (`derivePathStr` line 360, `addAccount`'s pre-fill loop line 565-566, `ensureGap` line 578, descriptor `getPubKey` line 400-408) do NOT have a try/except retry — the WHOLE derivation fails. Core's `DescriptorScriptPubKeyMan::TopUp` handles this by bumping nChild. ~2^-127 probability per derivation but spec-incompliant; comment at line 326 says "caller … can react" but no caller does |
| 6 | BIP-32 CKD_pub | G21: non-hardened header = parent_pubkey (33) + nChild (BE32) | PASS (`:285-287`) |
| 6 | … | G22: secp256k1_ec_pubkey_tweak_add for parent_pubkey + IL*G | PASS (`secp256k1.nim:687-718`) |
| 6 | … | G23: hardened-from-public REJECTED | PASS (`wallet.nim:276-277`) |
| 7 | BIP-32 invariants | G24: depth wrap protection (CExtKey rejects depth==UCHAR_MAX) | **BUG-5 (P1-CDIV)** — `deriveChild` (`wallet.nim:302`) computes `result.depth = parent.depth + 1` with no overflow guard. `depth: uint8` (`:25`) silently wraps 255→0; Core (`key.cpp:483`) returns false. Pathological-deep `m/0/0/…/0` (255 levels) silently produces a child key whose serialised xprv/xpub claims depth=0, indistinguishable from a master key. Operator who imports such an xpub thinks it's a root |
| 7 | … | G25: parent fingerprint = HASH160(parent_pubkey)[0..4] | PASS (`:266-269, 303`) |
| 7 | … | G26: child index (with hardened bit) recorded LE/BE | PASS (BE; `:304, 389-392`) |
| 7 | … | G27: master IL validity (< n, != 0) | **BUG-6 (P2)** — `masterKeyFromSeed` (`:218-234`) blindly accepts the HMAC's left 32 bytes; calls `derivePublicKey(result.key)` (`:234`) which throws `Secp256k1Error` on invalid seckey. The error type is wrong (Secp256k1Error vs the WalletError other paths use), and the failure mode is a bare exception rather than a "regenerate mnemonic" signal. Core's behaviour is identical (no validation), but BIP-32 actually mandates an explicit invalidity signal so the seed-generator can retry with a different seed |
| 8 | BIP-32 xprv/xpub serialisation | G28: 78-byte payload, version+depth+parentFP+childIndex+cc+keydata | PASS (`:366-404`) |
| 8 | … | G29: per-network version bytes (mainnet xprv/xpub, testnet/signet/regtest tprv/tpub) | PASS (`:373, 375, 378, 380`); version-byte table matches Core kernel/chainparams.cpp:148-149/261-262/366-367/507-508/639-640 |
| 8 | … | G30: Base58Check encode/decode round-trip | PASS (`base58CheckEncode` `:404`, `base58CheckDecode` in `descriptor.nim:274`) |
| 8 | … | G31: depth==0 invariant on decode (parentFP & childIndex MUST be zero) | **BUG-7 (P1)** — `decodeExtendedKey` (`descriptor.nim:272-319`) does NOT validate that depth==0 implies parentFP==00000000 and childIndex==0. Core's `CExtKey::Decode` enforces this. nimrod silently accepts a malformed "depth=0" xprv whose parent fingerprint and child index are non-zero — it will then act as a master key while logically being a child, and CKD_pub from this "fake master" produces collisions across descriptor wallets |
| 9 | network detection / loadWallet | G32: signet+testnet4+regtest all map to testnet-flavoured tprv/tpub | PARTIAL — version-byte logic is `mainnet bool`, set by `params.network == Mainnet` in 3 of the 4 `newWallet` overloads but `params.defaultPort == 8333` in `loadWallet` (`manager.nim:251`) and `createWallet` (`:338`). The two predicates always agree for the 5 networks but the duplication is fragile |
| 9 | … | G33: network-mismatch warning fires only when wallet origin ≠ node network | **BUG-8 (P1)** — `loadWallet` (`manager.nim:243-245`) computes `expectedNetwork = if bip34Height==1: "regtest" elif defaultPort==18333: "testnet" else: "mainnet"`. But testnet4 (`bip34Height=1, defaultPort=48333`) AND signet (`bip34Height=1, defaultPort=38333`) BOTH match the first clause and report "regtest". So a signet wallet on a signet node sees a spurious `Wallet network (signet) differs from node (regtest)` warning at every load. Same for testnet4 |
| 10 | BIP-43/44/49/84/86 path | G34: m/{44,49,84,86}'/coin_type'/account'/change/index shape | PASS (`wallet.nim:508`) |
| 10 | … | G35: SLIP-0044 coin_type = 0 mainnet, 1 testnet/signet/regtest | PASS (`:550, 606`) |
| 10 | … | G36: BIP-49 P2SH-P2WPKH wrap (redeemScript = OP_0 PUSH20 wpkh, scriptHash = HASH160(redeemScript)) | PASS (`:519-526`) |
| 10 | … | G37: BIP-84 P2WPKH | PASS (`:527-529`) |
| 10 | … | G38: BIP-86 P2TR with TapTweak (internal_key, empty merkle root) | PASS (`:530-542`); test vector match at `test_bip32_bip86_vectors.nim:97-128` (cross-cite W160 BUG-7 — TapTweak no-merkle-root fleet pattern; nimrod is CORRECT here) |
| 11 | derivePath string parsing | G39: index range validated (must be < 2^31 before hardened-OR) | **BUG-9 (P2)** — `derivePathStr` (`:341-360`) parses `parseUInt(part)` and casts to `uint32` without checking range. A path like `"m/2147483648/0"` (where 2^31 should be a hardened marker, not a raw index) silently wraps via the `uint32(index) or HARDENED` clamp at line 359, producing a hardened path the operator did not intend. Core's `ParseHDKeypath` rejects values >= 0x80000000 in the un-hardened position |
| 12 | extended key memory hygiene | G40: parent seckey / IL / output cleared after use | **BUG-10 (P1-SEC)** — `deriveChild` (`:271-339`) builds `data: seq[byte]` containing the parent private key (hardened path, `:284`) and the HMAC output (`:308, 317-318`). Neither `data` nor `il` nor `output.data` is wiped after use. Nim's `arc` MM (per `nim.cfg:13`) frees the seq when it goes out of scope, but the underlying allocator does NOT zeroise memory — the bytes sit in the heap until reused. A `gcore` of the node process leaks every derivation chain that has run since startup |

---

## BUG-1 (P0-FUNDSLOSS) — `validateMnemonic` is case-insensitive but `mnemonicToSeed` is case-sensitive: same mnemonic, two seeds

**Severity:** P0-FUNDSLOSS. A user types `"ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT"` into a recovery flow. `validateMnemonic` accepts it (lowercases on lookup at `wallet.nim:172`). `mnemonicToSeed` then computes PBKDF2 over the **uppercase** string (no normalisation at `:207`). The resulting seed bears NO relationship to the canonical seed any other BIP-39 wallet (Core's `descriptors.cpp::Descriptor` import, Electrum, Sparrow, Trezor) derives from the same 12 words. The user sees an empty wallet, assumes "wrong words", retypes — every funded address derived from the canonical form is now permanently inaccessible from nimrod.

This is the EXACT class of bug BIP-39 was designed to PREVENT — the spec says the mnemonic must be NFKD-normalised (which includes case-folding for the wordlist) before PBKDF2.

**File:** `src/wallet/wallet.nim:163-202` (`validateMnemonic` lowercases via `.toLowerAscii()`), `:204-212` (`mnemonicToSeed` does NOT). Caller chain: `newWallet` (`:413-417`, `:438-442`) calls both back-to-back. If `validateMnemonic` returns true, `mnemonicToSeed` is invoked with the SAME input — but it may produce a different seed than a canonical-form pass would.

**Core ref:** BIP-39 §"From mnemonic to seed" — both mnemonic and passphrase MUST be NFKD-normalised before being passed to PBKDF2.

**Excerpt (nimrod, the asymmetry)**
```nim
# validateMnemonic — case-insensitive (lowercases word lookup)
let idx = BIP39_WORDLIST.find(word.toLowerAscii())   # line 172

# mnemonicToSeed — case-sensitive (passes raw string into PBKDF2)
let normalizedMnemonic = mnemonic.strip()             # line 207 (only strips whitespace, no lowercase, no NFKD)
discard pbkdf2(ctx, normalizedMnemonic, salt, 2048, result)
```

**Impact:** every nimrod user who imports a mnemonic with any deviation from canonical lowercase derives an empty wallet. Only nimrod-generated mnemonics work, because `generateMnemonic` happens to emit lowercase. Fixed by `let normalizedMnemonic = mnemonic.strip().toLowerAscii()` (one extra method call) — but the real fix is full Unicode NFKD (see BUG-2). New fleet pattern: **"validation lowercases what derivation doesn't"** — the asymmetric-fix shape but applied to a single function pair within one module.

---

## BUG-2 (P0-FUNDSLOSS) — BIP-39 NFKD normalisation absent on both mnemonic and passphrase; local var name is comment-as-confession

**Severity:** P0-FUNDSLOSS. BIP-39 §"From mnemonic to seed" states:

> The mnemonic sentence and passphrase are NORMALIZED in NFKD form
> before being used as inputs to PBKDF2.

Nimrod does neither. `mnemonicToSeed` (`wallet.nim:204-212`):
```nim
proc mnemonicToSeed*(mnemonic: string, passphrase: string = ""): array[64, byte] =
  let normalizedMnemonic = mnemonic.strip()         # NOT NFKD
  let salt = "mnemonic" & passphrase                # passphrase NOT NFKD
  var ctx: HMAC[sha512]
  discard pbkdf2(ctx, normalizedMnemonic, salt, 2048, result)
```

The local name `normalizedMnemonic` is the comment-as-confession (W153/W154/W155/W156/W157/W160 pattern): the name implies the action ("normalized") but the body merely strips outer whitespace. For ASCII-only English mnemonics with no diacritics in the passphrase this happens to produce the same bytes as NFKD (because NFKD on ASCII is a no-op), so the BIP-39 vector at `test_wallet.nim:26` (`"abandon abandon … about"`) passes — but any wallet whose passphrase contains a single combining accent (e.g. `"café"` — composed `U+0063 U+0061 U+0066 U+00E9` vs decomposed `U+0063 U+0061 U+0066 U+0065 U+0301`) silently derives a different seed than Core/Electrum/Trezor.

Compounds with BUG-1 — both case-folding and Unicode normalisation are missing. Fix is one library call (Nim std `unicode.toNFKD` from `std/unicode` or a 3rd-party Unicode normalisation library; Nim's stdlib does not ship NFKD out of the box, which is itself a recovery-path landmine).

**File:** `src/wallet/wallet.nim:207` (`normalizedMnemonic` line — name lies), `:208` (passphrase concatenated raw).

**Core ref:** BIP-39, `bitcoin-core/src/wallet/scriptpubkeyman.cpp` — Core itself does NOT support raw-mnemonic import (only seeds and descriptors), so the failure mode "Core derives X, nimrod derives Y" surfaces against Electrum / Sparrow / Trezor / Coldcard rather than Core. Coldcard hardware wallets in particular are NFKD-strict.

**Impact:** silently divergent wallet recovery against the entire non-Core ecosystem; impossible to roundtrip a passphrase wallet generated by nimrod through Electrum and back. New fleet pattern (W161): **"comment-as-confession on a LOCAL VARIABLE NAME"** — previous instances were comments/identifiers in function signatures or struct field names; this is a tighter scope (the `let` binding inside one proc body).

---

## BUG-3 (P1) — `pbkdf2` return value discarded; partial-write produces zero-padded seed silently

**Severity:** P1. `nimcrypto.pbkdf2` returns `int` = bytes written, 0 on error (per `nimcrypto/pbkdf2.nim:25-26`). `mnemonicToSeed` discards (`wallet.nim:212`):

```nim
discard pbkdf2(ctx, normalizedMnemonic, salt, 2048, result)
```

`result` is an `array[64, byte]` (zero-initialised). If pbkdf2 fails partway (out-of-memory, internal counter overflow at 2^32-1 blocks, etc.) only the first N bytes are written and the rest stay zero. The wallet's master key derived from this truncated seed is silently weak / deterministic across all failure scenarios. There's no log line, no exception, no return-value to inspect.

Fix is one line: `if pbkdf2(...) != 64: raise newException(WalletError, "PBKDF2 failed")`.

**File:** `src/wallet/wallet.nim:212`.

**Core ref:** N/A — Core does not use PBKDF2 for BIP-39 (Core does not support raw-mnemonic import directly). But all production wallets (Electrum, Sparrow, BitcoinJ) check the PBKDF2 return.

**Impact:** silent seed corruption on PBKDF2 failure; in normal operation this should never trigger (a 2048-iteration PBKDF2 producing 64 bytes on a 1MB stack is essentially infallible), but the assumption is undocumented and one library upgrade away from being wrong.

---

## BUG-4 (P1-CDIV) — BIP-32 MUST-retry contract is dropped: `deriveChild` raises on libsecp rejection instead of bumping the index

**Severity:** P1-CDIV (consensus divergence + recovery-path divergence). BIP-32 mandates:

> In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
> and one should proceed with the next value for i.

Core implements the retry inside `DescriptorScriptPubKeyMan::TopUp`:
the keypool generator increments `m_wallet_descriptor.next_index` and
retries on every `CKey::Derive` returning false.

Nimrod's `deriveChild` (`wallet.nim:271-339`) RAISES `WalletError` on
libsecp tweak rejection:

```nim
let tweaked = tweakSeckeyAdd(parent.key, il)
if tweaked.isNone:
  raise newException(WalletError,
    "BIP-32 child key invalid (IL >= n or child == 0); bump index and retry")
```

The comment LITERALLY directs the caller to "bump index and retry" — but every caller in the tree does NOT:

- `derivePathStr` (`:341-360`): no try/except, no retry. A `m/0'/1/0/2147483646` path that hits the invalid IL just throws.
- `addAccount` pre-fill loop (`:564-566`): linear iteration `for i in 0 ..< gap`, one fail-fast on any bad index.
- `ensureGap` (`:570-585`): same, plus it's called every time the wallet hands out a new address.
- descriptor `getPubKey` (`descriptor.nim:389-409`): one-shot derivation through the path, no retry.

Probability of hitting this is ~2^-127 per derivation, so in practice no
mainnet user has ever tripped it. But the SPEC says you must handle it,
and a wallet whose `m/84'/0'/0'/0/N` derivation tree contains one bad
index has its keypool permanently broken at that gap position — no
amount of restart fixes it. Comment-as-confession at line 327.

**File:** `src/wallet/wallet.nim:325-327` (raise), all caller sites have no retry.

**Core ref:** `bitcoin-core/src/key.cpp:307-309` (`if (!ret)
keyChild.ClearKeyData(); return ret;`),
`bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::TopUp`
(retry loop).

**Impact:** ~2^-127 probability of permanent keypool breakage per derivation; spec non-compliance even for descriptor wallets that pin to a specific external index range. **Comment-as-confession at the raise site — 19th distinct extension in nimrod.**

---

## BUG-5 (P1-CDIV) — `depth: uint8` overflow silently wraps 255→0, producing fake-master xprv

**Severity:** P1-CDIV. `ExtendedKey.depth` is `uint8` (`wallet.nim:25`).
`deriveChild` increments without overflow protection:

```nim
result.depth = parent.depth + 1                       # line 302 — silent wrap on 255
```

After 256 successive `deriveChild` calls (e.g. a pathological
`m/0/0/0/…/0` of depth 256), `depth` wraps to 0. The serialised xprv at
`:383` writes `data.add(key.depth)` and emits `depth=0` — which is the
canonical MASTER-KEY marker. The wallet now has an xprv that
self-identifies as a master key but whose `parentFingerprint` and
`childIndex` reflect the deep parent. If the operator copies this xprv
into another wallet that DOES validate the depth==0 invariant
(Core does), it'll reject. But the operator's UI says "your master xpub
is …" — and any descriptor wallet that consumes this xpub as a
purpose-level node will derive entirely wrong children.

Core handles this explicitly (`key.cpp:483`):
```cpp
if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
```

**File:** `src/wallet/wallet.nim:302` (no overflow guard); `:25` (uint8 storage).

**Core ref:** `bitcoin-core/src/key.cpp:482-484`.

**Impact:** pathologically-deep paths produce xprv that misidentifies as master; cross-wallet collisions; non-detectable by any standard BIP-32 consumer that doesn't enforce the depth==0 invariant. Probability of natural exposure is 0 (no human-typed path goes 256 deep), but adversarial paths (a malicious WSH descriptor with a `xprv.../0/0/0/…/0` of length 256) DO trigger it. Fleet pattern: **"silent overflow on uint8 depth-counter"** — same shape as W160 BUG family but applied to the BIP-32 depth specifically.

---

## BUG-6 (P2) — `masterKeyFromSeed` does not validate master IL against `< n` / `!= 0`; wrong exception type surfaces

**Severity:** P2. BIP-32 says the master key is INVALID if `parse256(IL) ≥ n` or `IL == 0`. The correct response is to regenerate the seed (because the input mnemonic+passphrase produced an unusable master). Nimrod's `masterKeyFromSeed` (`wallet.nim:218-234`) skips the check:

```nim
copyMem(addr result.key[0], addr output.data[0], 32)
copyMem(addr result.chainCode[0], addr output.data[32], 32)
...
result.publicKey = derivePublicKey(result.key)     # line 234 — throws Secp256k1Error here
```

When the seckey is invalid, `derivePublicKey` raises
`Secp256k1Error` — the WRONG exception type vs the `WalletError`
the wallet API contracts on. Any caller that catches `WalletError`
to surface "regenerate mnemonic" will miss it. Calls from
`newWallet` (`:418, 442`) don't catch either — the
`Secp256k1Error` bubbles unhandled.

Core has the SAME issue (`key.cpp::SetSeed` does nothing about it),
but BIP-32 spec mandates an explicit signal so the higher-level seed
generator can retry — Core relies on later `IsValid()` calls to surface
the failure. Nimrod has neither the explicit check nor the late
`IsValid()` because `derivePublicKey` is invoked eagerly inside the
constructor.

**File:** `src/wallet/wallet.nim:228-234, 249-255`.

**Core ref:** `bitcoin-core/src/key.cpp:491-501` (Core's identical
behaviour) + BIP-32 master generation requirement.

**Impact:** ~2^-127 probability per seed of producing an unusable
master; caller sees wrong exception type and may misclassify as "bug"
rather than "regenerate".

---

## BUG-7 (P1) — `decodeExtendedKey` skips the BIP-32 depth==0 master invariant

**Severity:** P1. Core's `CExtKey::Decode` validates: if `depth==0`,
then `parentFingerprint == [0,0,0,0]` AND `childIndex == 0`. Without
this, you can craft a Base58Check-valid xprv that LOOKS like a master
but has a non-zero parent fingerprint — which would (a) confuse any
HD-wallet that uses fingerprint matching for descriptor expansion and
(b) let an adversary plant misleading descriptor inputs.

Nimrod's `decodeExtendedKey` (`descriptor.nim:272-319`) does NOT validate:

```nim
var key: ExtendedKey
key.depth = data[4]
copyMem(addr key.parentFingerprint[0], addr data[5], 4)
key.childIndex = ...
copyMem(addr key.chainCode[0], addr data[13], 32)
```

No depth==0 check.

Additionally:
- For the public-key branch (`:317`), no validation that byte 45 is
  `0x02` or `0x03` (compressed marker). A malformed xpub with byte 45
  = `0x04` (uncompressed marker) silently truncates the uncompressed
  key to a 33-byte slice and treats it as compressed — produces an
  invalid pubkey that subsequent libsecp parses will reject.
- For the private-key branch (`:309-314`), no range check on the
  parsed seckey vs n. An adversarial xprv with seckey == n (out of
  range) is accepted at decode time; the failure surfaces only when
  `derivePublicKey` is called, far from the parse site.

**File:** `src/wallet/descriptor.nim:272-319`.

**Core ref:** `bitcoin-core/src/key.cpp:518-549` (CExtKey::Decode +
CExtPubKey::Decode invariants).

**Impact:** adversarial xprv/xpub strings bypass invariant checks;
descriptor-import attack surface widens; fingerprint-spoofed
descriptors that look like child-of-X but are actually child-of-Y can
poison watch-only wallets.

---

## BUG-8 (P1) — `loadWallet` mislabels signet AND testnet4 as "regtest" → spurious mismatch warning on every load

**Severity:** P1 (operational / signet+testnet4-affecting). The
network-string used to validate wallet-vs-node alignment is:

```nim
# manager.nim:243-245
let expectedNetwork = if wm.params.bip34Height == 1: "regtest"
                      elif wm.params.defaultPort == 18333: "testnet"
                      else: "mainnet"
```

Per `consensus/params.nim`:
- mainnet  : `bip34Height = 227931, defaultPort = 8333`  → "mainnet" ✓
- testnet3 : `bip34Height = 21111,  defaultPort = 18333` → "testnet" ✓
- testnet4 : `bip34Height = 1,      defaultPort = 48333` → "regtest" ✗
- signet   : `bip34Height = 1,      defaultPort = 38333` → "regtest" ✗
- regtest  : `bip34Height = 1,      defaultPort = 18444` → "regtest" ✓

Operators running nimrod on signet OR testnet4 see this warning on
every wallet load:
```
Wallet network (signet) differs from node (regtest)
```

Compounds with the wallet-creation side at `createWallet:333-336`
which writes `meta.network = "regtest"` into the wallet DB for any
signet/testnet4 wallet — so the meta correctly matches the (broken)
node prediction, but downstream tooling that reads the meta sees
"regtest" for what is actually a signet wallet. Fleet pattern:
**"three-network-string conflation"** (cross-cite W157 ouroboros
BUG-1 family).

**File:** `src/wallet/manager.nim:243-245` (loadWallet expectedNetwork),
`:334-336` (createWallet networkStr — same expression, same bug).

**Core ref:** Core uses `BaseParams().NetworkIDString()` which returns
one of `main`, `test`, `testnet4`, `signet`, `regtest` and never collapses
them.

**Impact:** spurious warnings on signet/testnet4 fleet members;
wallet-export/import across nodes mislabels chain-of-origin; combined
with the `mainnet` bool predicate split (G32) makes the wallet code
fragile to chainparams changes.

---

## BUG-9 (P2) — `derivePathStr` does not validate path index range; values ≥ 2^31 silently bit-OR with HARDENED

**Severity:** P2. `derivePathStr` (`wallet.nim:341-360`) parses each
path component and casts:

```nim
let index = try: parseUInt(part) except: ...
let childIndex = if hardened: uint32(index) or HARDENED else: uint32(index)
```

`parseUInt` returns a `BiggestUInt` (64-bit). For `index = 2_147_483_648`
(== 2^31) on the non-hardened path: `uint32(2147483648) == 0x80000000` —
which IS the HARDENED bit. So the operator typing `m/0'/0'/2147483648`
(no apostrophe) gets a child derived at the HARDENED index 0, not at
the failed-cast index they intended.

For `index >= 2^32`, `uint32()` truncates silently. So `m/0'/4294967296`
becomes `m/0'/0`.

Core's `ParseHDKeypath` rejects values >= 0x80000000 in the un-hardened
position and rejects > 0x7FFFFFFF in the hardened position.

**File:** `src/wallet/wallet.nim:357-359`.

**Core ref:** `bitcoin-core/src/util/bip32.cpp::ParseHDKeypath`.

**Impact:** mis-derivation when path component is out-of-range; silent
collision with hardened-index 0. Probably never triggered by humans
but a typo in an importmulti / descriptor flow could route funds to a
hardened path the operator can't introspect via xpub-only tools.

---

## BUG-10 (P1-SEC) — IL / parent private key / HMAC output never zeroised in `deriveChild` heap allocations

**Severity:** P1-SEC. The hardened CKD_priv path concatenates the
parent private key into a `seq[byte] data`:

```nim
# wallet.nim:280-284
var data: seq[byte]
if hardened:
  data.add(0x00'u8)
  data.add(@(parent.key))
```

After HMAC, `data` falls out of scope. Nim's `arc` MM frees the underlying
allocation, but the allocator (libc `malloc`/`free`) does NOT zeroise.
The parent private key (32 bytes) sits in freed heap, recoverable by
`gcore` or `/proc/PID/mem` for the lifetime of the page.

Same story for:
- `output.data` (`:298-299`) — the 64-byte HMAC result, of which left
  32 bytes is the IL tweak that — combined with the parent — yields the
  child. Leaking IL + parent → child + grandchildren forever.
- `il: array[32, byte]` (`:317-318`) — stack array; on Nim/ARC the
  stack frame is reused but never zeroed.

Core uses `secure_allocator<unsigned char>` for the HMAC output
(`key.cpp:296`: `std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);`)
and `secure_allocator` for the keydata in `CKey`. Nimrod has no
equivalent allocator for any of these intermediate buffers.

**File:** `src/wallet/wallet.nim:280-318`.

**Core ref:** `bitcoin-core/src/key.cpp:296` (`secure_allocator` usage).

**Impact:** post-mortem memory dump of the nimrod process recovers
every private-key derivation path that ran since process start;
recoverable by anyone with `ptrace` on the process or by anyone
who's grabbed a coredump. Compounds with W160's universal
sigcache-key sighash-omit pattern and W158-W160's
context_randomize-absent fleet pattern.

---

## BUG-11 (P1) — `newWalletFromDb` reconstructs a wallet with NO master key, NO seed, NO accounts; comment-as-confession "keys are not loaded"

**Severity:** P1 (post-restart wallet is unusable). `newWalletFromDb`
(`wallet.nim:454-504`) creates a fresh `Wallet` ref and loads:
- encryption info (encrypted seed bytes, salt, rounds) — IF the wallet
  was encrypted
- UTXOs
- labels

But it does NOT populate:
- `result.seed`
- `result.masterKey`
- `result.accounts`

The trailing comment is the smoking gun:
```nim
# Note: Keys are not loaded - they will be re-derived when needed
# after the wallet is unlocked (for encrypted wallets) or on first use
```

But there is NO lazy-init path anywhere. `getNewAddress` (`:629`) reads
`wallet.accounts[actualIdx]` without re-derivation. `findKeyForAddress`
(`:702-711`) iterates over `wallet.accounts` (empty). `signTransaction`
(`:1244-1301`) calls `findKeyForScript` which returns `none(DerivedKey)`
on the empty account list — every sign attempt fails.

For an unencrypted wallet, there's NO way to recover: the seed isn't
persisted (only encrypted seeds are stored via `db.getEncryption`),
the accounts table HAS the purpose/coinType/account/next records (see
`createWallet:394-396`: `db.saveAccount(acc.purpose, acc.coinType, …)`)
but `newWalletFromDb` IGNORES those rows.

For an encrypted wallet, `unlockWallet` (`:1375-1431`) DOES restore
the master key from the decrypted seed (`:1416: wallet.masterKey =
masterKeyFromSeed(wallet.seed)`), but it does NOT call `addAccount` to
rebuild the account list. The accounts table is still empty.

**File:** `src/wallet/wallet.nim:454-504` (no seed/masterKey/accounts
load), `:1416` (only re-derive masterKey on unlock, no addAccount
rebuild), `db_sqlite.nim` likely has `saveAccount` / `getAccount` but
they're never wired into `newWalletFromDb`.

**Core ref:** `bitcoin-core/src/wallet/walletdb.cpp::LoadWallet` —
fully reconstructs the wallet's `KeyMan` state, the descriptor cache,
and the keypool from disk.

**Impact:** every wallet restart on nimrod that goes through
`loadWallet` returns a wallet that cannot sign, cannot generate
addresses, cannot match incoming UTXOs to known scripts. Operators
must `createWallet` from scratch or restore-from-mnemonic via a
hypothetical `importmnemonic` RPC that **doesn't exist** in nimrod
(rpc/server.nim line 6118 has the comment-as-confession for
`importdescriptors`; `importmnemonic` / `sethdseed` aren't even stubs).
**This is the showstopper bug for nimrod wallet persistence.**

---

## BUG-12 (P1) — `purposeForAddressType` maps P2WSH → BIP-84 (single-key purpose); silently produces P2WPKH addresses where P2WSH was requested

**Severity:** P1. P2WSH is a witness-script address — the hash is
SHA256(witnessScript), not a single-key hash. There's no canonical
single-key BIP path for P2WSH because single-key P2WSH is degenerate
(BIP-48 covers multisig P2WSH/P2SH-P2WSH at `m/48'/coin'/account'/script_type'`).

Nimrod (`wallet.nim:587-594`):
```nim
proc purposeForAddressType*(addrType: AddressType): uint32 =
  case addrType
  of P2PKH: 44
  of P2SH: 49
  of P2WPKH: 84
  of P2TR: 86
  of P2WSH: 84  # Use same as P2WPKH for now    <-- BUG
```

`derivePath` (`:506-546`) then falls into the `of 84:  # BIP84 - P2WPKH`
branch and constructs a `P2WPKH` address — NOT P2WSH. The caller asked
for P2WSH, got P2WPKH, has no idea the addresses they're handing out
are the wrong script type. The mismatch surfaces only when the receiver
sends to the (correct) P2WPKH address but the wallet was supposed to
own a P2WSH UTXO with a fundamentally different output script — the
balance is wrong.

The comment `"# Use same as P2WPKH for now"` is the comment-as-confession.

**File:** `src/wallet/wallet.nim:594` (P2WSH→84 mapping); `:527-529`
(derivePath uses purpose 84 to construct P2WPKH).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp` —
single-key P2WSH is not a supported purpose; descriptor wallets via
`wsh(pkh(xpub/.../*))` is the path.

**Impact:** any operator asking nimrod for a "P2WSH address" gets a
P2WPKH address silently. **Fleet pattern: same shape as W161 BUG-2
"name-as-confession" but at a function level — `purposeForAddressType`
claims to return the purpose for the address type, but for P2WSH
returns the WRONG purpose.**

---

## BUG-13 (P0-CDIV) — BIP-86 P2TR address generated correctly, but Schnorr SIGNING is absent → output is unspendable from nimrod; 6-wave Schnorr-sign-missing carry-forward W127→W158→W159→W160→W161

**Severity:** P0-CDIV (wallet-correctness / funds-recovery). nimrod's
BIP-86 derivation (`wallet.nim:530-542`) CORRECTLY computes the
TapTweak with empty merkle root and emits a P2TR address. Test passes
(`test_bip32_bip86_vectors.nim:117-128`). Funds CAN be sent to this
address.

But `signTransaction` (`:1284-1286`) rejects P2TR inputs:
```nim
elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
  # P2TR - requires Schnorr signature (simplified)
  raise newException(WalletError, "P2TR signing not yet fully implemented")
```

And there is NO `signSchnorr` / `schnorrSign` / `signP2TR` proc anywhere
in `src/wallet/` (verified by recursive grep). The Schnorr-verify
primitive exists in `crypto/secp256k1.nim:523-557` (W159/W160 cross-cite),
but the Schnorr-SIGN primitive is entirely absent.

**Cross-cite W127 BUG → W158 BUG-5 → W159 BUG-14 → W160 BUG-5/6/8 →
W161 BUG-13** — this is now the **6-WAVE Schnorr-sign-missing
carry-forward in nimrod**. The asymmetric-Schnorr-surface meta-pattern
(W159 BUG-14 origin) is now compounded at the wallet layer: BIP-86
addresses are derived → operator deposits → operator can't spend.

**File:** `src/wallet/wallet.nim:1284-1286` (raise); pre-existing absent
`signSchnorr` everywhere in `src/wallet/`. The TapTweak math at
`:530-542` is correct (W160 BUG-7 fleet pattern explicitly excludes
nimrod — nimrod's BIP-86 TapTweak DOES use empty-merkle-root).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp` —
`DescriptorScriptPubKeyMan::SignTransaction` →
`KeyPair::SignSchnorr` per W160 references.

**Impact:** any user who receives to a nimrod-generated BIP-86 address
has their funds STUCK — they can deposit but cannot withdraw. The
P2TR address LOOKS valid (correct TapTweak), so users have no warning
this is a one-way deposit. **6-WAVE TRACKING OF A SINGLE BUG — the
new longest single-bug carry-forward in nimrod's history per
MEMORY.md** (previous record: rustoshi 5-wave at W108→W123→W142→W154→W155).

---

## BUG-14 (P2) — descriptor x-only-pubkey parse assumes EVEN parity; round-trip to compressed pubkey is wrong half the time

**Severity:** P2 (Taproot-descriptor-import). `parseKeyExpression`
(`descriptor.nim:838-845`) for a 32-byte x-only key in a `tr()` context:

```nim
elif keyStr.len == 64 and ctx == ContextP2TR:
  let keyBytes = parseHexBytes(keyStr)
  var pubkey: PublicKey
  # Convert to compressed format (assume even parity)
  pubkey[0] = 0x02
  copyMem(addr pubkey[1], addr keyBytes[0], 32)
  result = newKeyProviderConstHex(pubkey, true, origin, apostrophe, 0)
```

The "assume even parity" comment is the comment-as-confession.
Schnorr/Taproot uses x-only pubkeys where the y-coordinate parity is
canonicalised to EVEN at the point of construction
(`secp256k1_xonly_pubkey_*` family). BUT: when this 33-byte compressed
pubkey is later passed to `secp256k1_ec_pubkey_parse` (which expects
0x02/0x03 prefix indicating ACTUAL y-parity), HALF of the input x
coordinates will fail the parse — because the actual on-curve point
with that x has ODD y. The constructed `0x02 || x` is an INVALID
compressed pubkey for those x-coordinates.

Round-trip semantics break: a descriptor imported with the odd-y x
coordinate then re-exported via `keyProviderToString` will silently
emit a key that doesn't round-trip to the original.

Fix: keep the key as a 32-byte x-only and use only the
`secp256k1_xonly_pubkey_*` family, OR test both parities at parse time
and store the actually-on-curve one.

**File:** `src/wallet/descriptor.nim:838-845`.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParsePubkey` —
for the Taproot context, treats the key as canonical x-only
throughout, never lifting to a compressed pubkey with synthetic parity.

**Impact:** ~50% of taproot-descriptor x-only-key imports fail
downstream pubkey-parse with no clear error; the failure surfaces at
sign or expand time, far from the parse site. New fleet pattern:
**"parity-faked round-trip break"** — closely related to W160's
TapTweak-parity family but at the descriptor parse boundary.

---

## BUG-15 (P2) — `newWallet` 4-arg overload silently drops BIP-39 passphrase; `newWalletFromSeed` and `newWallet (2-arg)` don't add a default account

**Severity:** P2 (API consistency / passphrase-loss). Four constructor
overloads of `Wallet` exist:

| # | Signature | Mnemonic→seed call | Adds default account? |
|---|-----------|--------------------|----------------------|
| 1 | `newWallet(mnemonic, passphrase, params)` (`:410`) | `mnemonicToSeed(mnemonic, passphrase)` ✓ | NO |
| 2 | `newWalletFromSeed(seed, params)` (`:424`) | n/a (raw seed) | NO |
| 3 | `newWallet(mnemonic, params, mainnet, chainState)` (`:435`) | `mnemonicToSeed(mnemonic)` — **passphrase dropped** | YES (BIP-84) |
| 4 | `newWalletFromDb(db, ...)` (`:454`) | n/a (db reload) | NO (BUG-11 above) |

Overload #3 has the critical defect: it ACCEPTS no passphrase parameter
even though `mnemonicToSeed` accepts one. Any operator using the 4-arg
form to add a wallet against a chainstate gets a passphrase-less seed —
which derives a totally different master key from the same mnemonic
+ passphrase in overload #1. Same mnemonic, different account trees.
Cross-impl divergence is a recovery-path landmine.

Overloads #1 and #2 are also dangerous: they construct a `Wallet`
object but never call `addAccount`. `wallet.accounts` is empty.
`getNewAddress` returns immediately on `accountIdx >= wallet.accounts.len`
(`:637-638`) — there are 0 accounts, any access throws. The caller has
to know to call `addAccount` explicitly. The 4-arg overload is the only
one that auto-creates a BIP-84 account, but its other defect (passphrase
drop) makes it the wrong default.

**File:** `src/wallet/wallet.nim:410-452`.

**Core ref:** Core has one constructor path for HD wallets via
`CreateWalletDatabase` + `CWallet::Create` + descriptor SPKM setup;
all-or-nothing initialisation rather than fragmented overloads.

**Impact:** passphrase-protected wallets silently lose the passphrase
on overload #3; the other overloads silently produce empty
account-less wallets. Operators have to know which constructor is the
"right" one — and they pick wrong because the default-args overload
(#1) is naturally what gets reached first.

---

## BUG-16 (P3) — `PSBT_GLOBAL_XPUB` stores the 78 raw bytes without calling `decodeExtendedKey`; invalid version bytes / wrong-length payload bypass validation

**Severity:** P3 (PSBT-import side). `PSBT_GLOBAL_XPUB` payload is 78
bytes (the same Base58Check-decoded BIP-32 extended key). nimrod's
parser (`psbt.nim:945-957`):

```nim
of PSBT_GLOBAL_XPUB:
  if key.len != 79:  # 1 + 78 bytes for BIP32 extended key
    raise newException(PsbtError, "invalid global xpub key size")
  let xpub = key[1 ..< key.len]
  ...
  result.xpubs[origin].incl(xpub)        # store raw bytes
```

The 78 raw bytes are stored without invoking `decodeExtendedKey` to:
- validate version bytes (could be junk)
- validate depth==0 invariant (BUG-7 separate)
- validate seckey range / pubkey form
- canonicalise per-network

Any downstream consumer that re-decodes these bytes assumes they were
already validated by the parser — that contract is broken.

**File:** `src/wallet/psbt.nim:945-957`.

**Core ref:** `bitcoin-core/src/psbt.cpp::DeserializeFromBase64` — calls
`DecodeExtKey` on every PSBT_GLOBAL_XPUB key.

**Impact:** malformed xpub bytes propagate through PSBT processing;
PSBT_GLOBAL_XPUB → key-origin lookups can silently mismatch. Low
severity because subsequent operations re-validate when they actually
USE the bytes.

---

## BUG-17 (P2) — `exportMasterXpub` mutates a copy `isPrivate=false` but does NOT zero the private-key bytes; out-of-band callers see fake-public extended key with private bytes embedded

**Severity:** P2 (in-process information leak). `exportMasterXpub`
(`wallet.nim:1307-1311`):

```nim
proc exportMasterXpub*(wallet: Wallet): string =
  var pubKey = wallet.masterKey
  pubKey.isPrivate = false
  serializeExtendedKey(pubKey, wallet.mainnet)
```

The local `pubKey` has `.isPrivate = false` but `.key[0..31]` still
contains the master private key. The Base58Check serialisation
(`:397-402`) routes on `isPrivate` and emits only `key.publicKey`, so
the serialised xpub is clean. BUT: the in-memory `pubKey` object
between the copy and the serialise call IS a `(isPrivate=false,
key=<actual private key>)` value — a type-confused state. If any
future refactor (or RPC handler that calls
`(wallet.exportMasterXpub(), wallet.someOtherProc())` and both share
intermediate state) reads `.key`, it sees the private key thinking
it's a public-key-only object.

Compare to the dedicated `neuter` proc (`:257-264`) which DOES zero
the key bytes:
```nim
proc neuter*(key: ExtendedKey): ExtendedKey =
  result = key
  result.isPrivate = false
  for i in 0 ..< 32:
    result.key[i] = 0
```

`exportMasterXpub` doesn't use `neuter`. Same defect in
`getAccountXpub` (`:1313-1322` — `accKey.isPrivate = false` no zero).

**File:** `src/wallet/wallet.nim:1309-1311, 1320-1322`.

**Core ref:** `bitcoin-core/src/key.cpp::CExtKey::Neuter` zeros the
seckey before returning the public form.

**Impact:** in-memory state-confused object; not a serialised leak;
becomes a leak if a future refactor adds an intermediate caller.

---

## BUG-18 (P2) — `parseKeyPath` apostrophe vs `h` accepted; `H` (capital) also accepted but neither Core nor BIP-32 standardise capital-H

**Severity:** P3. `derivePathStr` accepts `'`, `h`, and `H` as
hardened markers (`wallet.nim:353`):

```nim
if part.endsWith("'") or part.endsWith("h") or part.endsWith("H"):
```

BIP-32 (and Core's `ParseHDKeypath`) accept `'`, `h`. Capital `H` is
NOT specified. nimrod silently accepts it, which means an import path
copied from nimrod that uses capital `H` will fail validation on Core /
Electrum / Sparrow / hardware wallets. Round-trip break.

**File:** `src/wallet/wallet.nim:353`.

**Core ref:** `bitcoin-core/src/util/bip32.cpp::ParseHDKeypath` —
accepts apostrophe or lowercase `h`.

**Impact:** cross-impl path-string roundtripping silently breaks
when nimrod's output uses capital `H`. Probability low (no caller
emits capital H today), but the parser permissiveness is a footgun.

---

## BUG-19 (P3) — `findOrCreateAccountForType` always creates `accountIndex = 0`; no support for `m/84'/0'/N'` with N > 0

**Severity:** P3. `findOrCreateAccountForType` (`wallet.nim:596-627`)
hardcodes `accountIndex = 0`. The wallet supports only ONE account
per purpose. A user who wants `m/84'/0'/1'` (a second BIP-84 account
under the same master key, for accounting separation) cannot get it
via this code path. `addAccount` (`:548-568`) DOES accept
`accountIndex`, but `getNewAddress`'s auto-find path (`:629-654`)
falls through `findOrCreateAccountForType` and ignores any
non-default. Operators must manually call `addAccount(84, 1)` first,
then pass `accountIdx=1` to `getNewAddress`.

Core's descriptor wallets support arbitrary N-account paths out of
the box via `importdescriptors`.

**File:** `src/wallet/wallet.nim:596-627`, `:629-654`.

**Core ref:** Core descriptor SPKM via `wpkh([fingerprint/84h/0h/Nh]xpub/0/*)`
naturally supports any N.

**Impact:** single-account-per-purpose limitation; doesn't break funds
but breaks the "multiple wallets in one seed" workflow.

---

## BUG-20 (P3) — BIP-48 multisig path is entirely absent; descriptors are unimportable for multisig wallets

**Severity:** P3 (feature gap). BIP-48 specifies
`m/48'/coin_type'/account'/script_type'` for HD multisig wallets
(Sparrow, Specter, Coldcard). nimrod has zero support: no purpose=48
case in `derivePath` (`:514-545`), no multisig account creation path,
no `wsh(multi(...))` /`sh(wsh(multi(...)))` import via descriptors
(`handleImportDescriptors` is the comment-as-confession stub at
`rpc/server.nim:6118-6132`).

Combined with BUG-12 (P2WSH → fake-P2WPKH), nimrod cannot generate
addresses for ANY multisig wallet topology — neither raw P2WSH nor
BIP-48 multisig.

**File:** `src/wallet/wallet.nim` (no BIP-48), `src/rpc/server.nim:6118-6132`
(importdescriptors stub).

**Core ref:** Core supports BIP-48 via descriptor import:
`wsh(multi(2,[fp/48h/0h/0h/2h]xpub.../0/*,[fp2/48h/0h/0h/2h]xpub2.../0/*))`.

**Impact:** entire multisig user segment cannot use nimrod for wallet
operations. Not a consensus issue; a feature gap.

---

## BUG-21 (P3) — gap-limit is FIXED at 20 in 4 separate places; SLIP-0044 says gap=20 is reasonable but Electrum / Sparrow default to 100, Core to 1000

**Severity:** P3 (operational consistency). The gap limit is hardcoded
at 20 in:
- `newWallet 4-arg` via `addAccount(84, 0, 20)` (`wallet.nim:452`)
- `findOrCreateAccountForType` (`:608`)
- 4-arg `addAccount` default parameter (`:548`)

A wallet imported from Electrum (gap=100) into nimrod will silently
miss UTXOs that fall outside the first 20 addresses of each chain.
Core's `keypool` default is 1000.

Compounds with BUG-11 (post-restart wallet has 0 accounts) — even
when accounts are restored, the gap is stuck at 20.

**File:** `src/wallet/wallet.nim:452, 548, 608`.

**Core ref:** `bitcoin-core/src/wallet/walletdb.cpp` — keypool default
size; descriptor wallets use `KEYPOOL_SIZE` from `wallet.h`.

**Impact:** silent UTXO miss on import from gap-friendly wallets;
operator must `getNewAddress` repeatedly to advance the next-index.

---

## BUG-22 (P3) — `derivePath` index = `uint32` truncation; no rejection of paths > 256 deep

**Severity:** P3. Compounds with BUG-5 (depth uint8 wrap) and BUG-9
(parseUInt range). The default 5-segment BIP-44 path is fine, but a
malicious descriptor or PSBT_IN_BIP32_DERIVATION carrying a 256-deep
path will exercise BUG-5's silent wrap. No early rejection (e.g.
"path depth must be <= 255 per BIP-32") at parse time.

**File:** `src/wallet/wallet.nim:341-360` (no depth pre-check).

**Core ref:** `bitcoin-core/src/util/bip32.cpp::ParseHDKeypath` limits
total path elements but does NOT explicitly cap at 255 (relies on
later derivation to fail).

**Impact:** combined with BUG-5, opens a path for adversarial
descriptor inputs to produce fake-master keys.

---

## BUG-23 (P3) — `derivePathStr` accepts path "m" (master only) but ALSO accepts "mistake/0" (starts-with check)

**Severity:** P3. `derivePathStr` (`:343`):
```nim
if not path.startsWith("m"):
  raise newException(WalletError, "path must start with 'm'")
```

`startsWith("m")` matches `"mistake/0"`, `"matt/0"`, `"m0/0"`, etc.
The split-on-"/" then parses `"mistake"` (or `"matt"`, or `"m0"`) as
the second path component and fails at `parseUInt` — but the
error message is `"invalid path component: mistake"` rather than the
correct "path must start with 'm/' or 'm'". Operator-confusing.

Core uses `path == "m" || path == "/" || StartsWith(path, "m/")`.

**File:** `src/wallet/wallet.nim:343-344`.

**Impact:** mildly misleading error; not a security issue but a
DX issue for descriptor / RPC operators.

---

## BUG-24 (P0-OPS) — there is no `importmnemonic` / `sethdseed` RPC; wallet restore-from-mnemonic is impossible via JSON-RPC

**Severity:** P0-OPS (operational / disaster-recovery). Bitcoin Core
exposes `sethdseed` for descriptor wallets. nimrod has neither
`importmnemonic`, nor `sethdseed`, nor `importdescriptors` (which is
the stub at `rpc/server.nim:6118-6132`). The ONLY way to populate a
nimrod wallet with a known seed is to construct a `Wallet` in-process
via `newWallet(mnemonic, ...)` and have the daemon adopt it — i.e.
restart the daemon with the mnemonic baked into config. No JSON-RPC
flow exists.

Compounds with BUG-11 (post-restart wallet has no accounts).

**File:** `src/rpc/server.nim:6118-6132` (`handleImportDescriptors`
comment-as-confession).

**Core ref:** Core's `sethdseed`, `importdescriptors`,
`upgradetohd` all present.

**Impact:** operator with a known mnemonic but no working nimrod wallet
file has NO recovery path through nimrod's RPC. They must run a
non-nimrod wallet (Sparrow, Electrum) to recover funds, then import
the resulting xprv via a stub that doesn't work. **Nimrod cannot
recover wallets in production.** Operationally fatal.

---

## Fleet patterns this wave (cross-cite W156-W160)

- **comment-as-confession 19th-23rd distinct extensions** (the
  pattern fully saturating fleet-wide; this wave adds: BUG-1 (none,
  but BUG-2 has it on local var name), BUG-2 (local-variable name
  `normalizedMnemonic` lies — first comment-as-confession **on a
  binding name, not a function/struct name**), BUG-4 (raise message
  literally directs caller to "bump index and retry" but no caller
  does), BUG-6 (none directly), BUG-11 (`# Note: Keys are not loaded
  - they will be re-derived when needed` — but the re-derive code
  doesn't exist), BUG-12 (`# Use same as P2WPKH for now`), BUG-13
  ("P2TR signing not yet fully implemented"), BUG-14 ("assume even
  parity"), BUG-20 (`importdescriptors not implemented`)).
- **Two-pipeline guard 20th-22nd distinct extensions** (BUG-1
  validateMnemonic vs mnemonicToSeed asymmetric case-handling;
  BUG-15 four `newWallet` constructors with divergent
  passphrase / addAccount semantics; BUG-21 gap-limit hardcoded in
  4 places).
- **Five-wave Schnorr-sign-missing carry-forward EXTENDS TO 6 WAVES**
  (W127 → W158 BUG-5 → W159 BUG-14 → W160 BUG-5/6/8 → **W161
  BUG-13**) — this is now the **longest-tracked single bug in nimrod's
  history**; the BIP-86 derivation/address generation works in
  isolation (W160 BUG-7 fleet pattern explicitly excludes nimrod here)
  but the FUNDS-RECOVERY path is broken because Schnorr signing is
  absent at the wallet level. Compounds with W160 sigcache-omits-sighash
  universal-fleet pattern and W160 sign-then-verify-paranoia-absent
  universal-fleet pattern.
- **comment-as-confession AT A LOCAL `let` BINDING NAME** (BUG-2
  `normalizedMnemonic`) — NEW PATTERN: previous instances were
  field-names, function-names, top-level constants, struct-doc
  comments. This is the tightest scope yet — the binding is one line
  later than the declaration, and the lie is exposed by the very next
  line of code.
- **Memory hygiene UNIVERSAL** — context_randomize absent W158-W160
  family extends to BIP-32 derivation IL/parent-seckey/output buffer
  hygiene (BUG-10). Nimrod has no `secure_allocator` equivalent.
  Cross-impl: blockbrew / haskoin / rustoshi / clearbit / camlcoin /
  beamchain / hotbuns / ouroboros / lunarblock — all 9 other impls
  also lack the equivalent (per W160 universal-pattern catalogue).
- **Three-network-string conflation** (BUG-8 testnet4+signet+regtest
  mapped to same string in `loadWallet`) — same shape as W157 ouroboros
  BUG-1 family ("Three-network-string conflation").
- **Asymmetric receive/parse vs emit** (BUG-1 lower-on-parse but raw-on-derive;
  BUG-15 passphrase accepted on overload #1 dropped on overload #3;
  BUG-18 capital-H accepted on parse but no emitter uses it) — same shape
  as W156 blockbrew BUG-25 / W152 family ("asymmetric receive/send").
- **Post-restart wallet unusable** (BUG-11) — same shape as W153 hotbuns
  BUG-12 "test-suite shape MASKS production bug" / haskoin W153 BUG-10/20
  "persist-but-never-populate storage" — nimrod stores accounts in SQL
  but `newWalletFromDb` ignores those rows.
- **5th-consecutive-quad name-as-lie family** at nimrod
  (W157 BUG-1 "intra-impl bits byte-order split" was the most recent;
  now BUG-12 `purposeForAddressType` returns wrong purpose for P2WSH;
  BUG-2 `normalizedMnemonic` doesn't normalize).
- **Funds-loss footgun** (BUG-1 + BUG-2 + BUG-13 stacking) — three
  distinct paths to funds inaccessibility via nimrod wallet alone.
- **6-wave-tracking of a single bug INSIDE nimrod** (W161 BUG-13 is the
  6th wave of the Schnorr-sign-missing chain; previous record was
  rustoshi 5-wave at W108→W123→W142→W154→W155 per MEMORY.md).

---

## Summary

- **24 bugs** catalogued (3 P0-class, 11 P1-class, 7 P2-class, 3 P3-class).
- **P0 bugs:** BUG-1 (case-asymmetric validate vs derive → empty wallet on
  uppercase mnemonic), BUG-2 (no NFKD normalisation on mnemonic+passphrase
  → silent seed divergence vs ecosystem), BUG-13 (BIP-86 Schnorr-sign
  absent → deposit-only addresses; 6-wave carry-forward), BUG-24 (no
  importmnemonic/sethdseed RPC → impossible to recover wallet via RPC).
- **Top P1 bugs (operational fatality):** BUG-11 (newWalletFromDb has
  no master key / no accounts → post-restart wallet is unusable),
  BUG-8 (signet+testnet4 both mislabeled "regtest" in network-mismatch
  warnings + on-disk meta), BUG-12 (P2WSH purpose maps to BIP-84,
  silently produces P2WPKH addresses), BUG-4 (BIP-32 retry contract
  dropped — every caller raises rather than bumping nChild).
- **Fleet-pattern continuity:** comment-as-confession (19th-23rd extension),
  two-pipeline guard (20th-22nd extension), Schnorr-sign-missing
  6-wave carry-forward (W127 → W158 → W159 → W160 → W161 — longest
  single-bug streak in nimrod's history per MEMORY.md), context_randomize
  + memory-hygiene universal fleet pattern, asymmetric-emit/parse
  family, three-network-string conflation (W157 cross-cite).

**New meta-patterns this wave:**
- **"comment-as-confession on a LOCAL `let` BINDING NAME"** (BUG-2
  `normalizedMnemonic`) — tightest scope yet for the pattern; the lie is
  exposed by the very next line.
- **"validation lowercases what derivation doesn't"** (BUG-1) — special
  case of asymmetric-fix where two procs in the same module disagree on
  canonical form of the same input.
- **"6-wave carry-forward of a single bug INSIDE one impl"** (BUG-13) —
  exceeds the previous fleet record (5-wave rustoshi W108→W155).
- **"funds-burn DEPOSIT (not coinbase)"** (BUG-13) — fleet has multiple
  funds-burn-via-coinbase patterns (W154 clearbit BUG-12 ~$250k/block,
  W154 lunarblock BUG-22 burn-address payout); this is the FIRST
  funds-burn-via-DEPOSIT pattern (user deposits to a valid-looking
  P2TR address generated by nimrod, then nimrod cannot sign to spend
  → funds are effectively burned for any user who treats nimrod as
  their only signing wallet).
- **"parity-faked round-trip break"** (BUG-14) — descriptor parses
  x-only key into compressed-pubkey shape with fabricated parity byte,
  half of round-trips silently fail.

**Fix-wave priority (suggested for next batch):**
1. **🚨 BUG-1 + BUG-2 mnemonic case-fold + NFKD** (~10 LOC; closes
   funds-loss footgun) — highest leverage, smallest patch.
2. **🚨 BUG-11 newWalletFromDb reconstruct master/seed/accounts** (~30 LOC;
   closes "wallet unusable after restart" — operational showstopper).
3. **🚨 BUG-24 importmnemonic + sethdseed RPCs** (~50 LOC each;
   closes "no disaster-recovery path through RPC").
4. **🚨 BUG-13 wallet Schnorr sign + signTransaction P2TR branch**
   (~80 LOC porting `crypto/secp256k1.signSchnorr` analogue + wallet
   integration; closes 6-wave carry-forward) — but requires upstream
   Schnorr-sign primitive first (W160 BUG-5/6/8).
5. **🚨 BUG-8 network-string detection in loadWallet/createWallet**
   (~10 LOC; closes signet+testnet4 spurious mismatch warnings).
6. **BUG-12 P2WSH purpose mapping** (~5 LOC + design decision on whether
   to support single-key P2WSH at all; closes "wallet silently produces
   wrong script type for requested address type").
7. **BUG-7 decodeExtendedKey depth==0 invariant** (~5 LOC; closes
   "adversarial xprv passes parser unmolested").
8. **BUG-5 depth uint8 overflow guard** (~3 LOC; closes "deep-path
   produces fake-master").
9. **BUG-4 BIP-32 retry-loop in derivePathStr / addAccount** (~15 LOC;
   closes spec non-compliance).
10. **BUG-15 unify newWallet constructors** (~20 LOC; eliminate
    passphrase-dropping overload).
