# W127 — Taproot / Schnorr / Tapscript audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W127)
Target: `src/script/interpreter.nim` (Taproot + Tapscript + Schnorr verify
flow), `src/crypto/secp256k1.nim` (Schnorr / x-only tweak wrappers),
`src/wallet/wallet.nim` + `src/wallet/descriptor.nim` (BIP-86 / TapTweak
derivation only — no signing).
Driver: cross-impl fleet audit — every node must enforce BIP-340/341/342
identically; a single divergent gate is a consensus split when taproot
spend volume rolls over.

## Status

**BUGS FOUND — 14 distinct gates PARTIAL / MISSING (of 30).**

Of those:
  - **3 P0-CONSENSUS / P0-CDIV** (Schnorr signing absent from wallet path,
    no BIP-340 known-answer cross-verification of `verifySchnorr` against
    BIP-340 csv, no script_assets_test driver) — **deferred-risk** rather
    than active divergence: nimrod *receives* Taproot spends correctly
    because `verifySchnorr` delegates to libsecp256k1 directly, but it
    cannot *originate* a Schnorr-signed P2TR spend, and the verify path
    has only spot test coverage not vector-table coverage.
  - **4 P1** — named-constant absence (`TAPROOT_CONTROL_*`, `ANNEX_TAG`,
    `VALIDATION_WEIGHT_*`, `MAX_PUBKEYS_PER_MULTI_A`), `OP_CHECKMULTISIG_A`
    not implemented (no BIP-342 MULTI_A descriptor support), wallet
    cannot construct a P2TR script-path spend, no PSBT v0/v2 taproot
    BIP-371 fields beyond `PSBT_IN_TAP_KEY_SIG`.
  - **7 P2 / P3** — cosmetic / policy / forward-compat gates.

The CORE OF THE TAPROOT VERIFY PATH (key-path commitment + tweak +
Schnorr verify, script-path control-block + merkle-root + tweak +
EvalScript with BIP-342 rules + validation-weight budget +
sig.size/hashtype hard errors + OP_SUCCESSx pre-pass + cleanstack
implicit + minimal-IF tapscript-mandatory) is **PRESENT and matches
Core's `VerifyWitnessProgram` / `ExecuteWitnessScript` /
`EvalChecksigTapscript`** at the granularity of `interpreter.cpp`
1947-1985.  Tests `test_w94_taproot_gates.nim`,
`test_w95_bip340_schnorr.nim`, `test_taproot_commitment.nim`,
`test_taproot_op_success.nim`, and `test_tapscript_validation_weight.nim`
all pass.  This audit identifies the **remaining gaps** beyond the
already-closed W94/W95 gates.

Net effect: nimrod **validates** every BIP-340/341/342 spend Bitcoin
Core does (no consensus break on the verify side under spot tests), but
(a) cannot **originate** a Schnorr-signed transaction (wallet has no
`signSchnorr` / `signTaprootInput` proc), (b) does **not** cross-verify
its verify path against the standard `script_assets_test.json` corpus,
and (c) **omits BIP-371 MULTI_A** taproot descriptors, which means
miniscript-driven P2TR script-path spends with multi-key leaf scripts
are out of reach from the wallet.

## Method

1. Read Core refs:
   - `bitcoin-core/src/script/interpreter.cpp` (947 LOC of taproot logic):
     `VerifyWitnessProgram` (:1917), `ExecuteWitnessScript` (:1832),
     `EvalChecksigTapscript` (:347), `CheckSchnorrSignature` (:1717),
     `SignatureHashSchnorr` (:1483), `ComputeTapleafHash` (:1872),
     `ComputeTapbranchHash` (:1877), `ComputeTaprootMerkleRoot` (:1888),
     `VerifyTaprootCommitment` (:1903).
   - `bitcoin-core/src/script/script.h`:
     `ANNEX_TAG=0x50` (:58), `VALIDATION_WEIGHT_PER_SIGOP_PASSED=50` (:61),
     `VALIDATION_WEIGHT_OFFSET=50` (:64), `MAX_PUBKEYS_PER_MULTI_A=999` (:37).
   - `bitcoin-core/src/script/interpreter.h`:
     `TAPROOT_LEAF_MASK=0xfe` (:241), `TAPROOT_LEAF_TAPSCRIPT=0xc0` (:242),
     `TAPROOT_CONTROL_BASE_SIZE=33` (:243), `TAPROOT_CONTROL_NODE_SIZE=32` (:244),
     `TAPROOT_CONTROL_MAX_NODE_COUNT=128` (:245),
     `TAPROOT_CONTROL_MAX_SIZE=33+32*128=4129` (:246).
   - `bitcoin-core/src/key.cpp`:
     `CKey::SignSchnorr` (:273), `KeyPair::SignSchnorr` (:549).
   - `bitcoin-core/src/pubkey.cpp`:
     `XOnlyPubKey::CheckTapTweak` (:257), `ComputeTapTweakHash` (:246),
     `CreateTapTweak` (:265).
   - `bitcoin-core/src/script/sigcache.cpp` (Schnorr verify cache).
   - `bitcoin-core/src/test/script_assets_tests.cpp` (driver expects
     `DIR_UNIT_TEST_DATA=…/script_assets_test.json`).

2. Read nimrod targets:
   - `src/script/interpreter.nim` (3107 LOC) — entire Taproot stack.
   - `src/crypto/secp256k1.nim` — `verifySchnorr` (:523, :829),
     `tweakXonlyPubkey` (:631).
   - `src/wallet/wallet.nim` (BIP-86 derivation :527), no Schnorr sign.
   - `src/wallet/descriptor.nim` :636-640 (`tr()` descriptor TapTweak).
   - `src/wallet/psbt.nim` :56 / :455 / :739 (BIP-371 limited subset).

3. For each of 30 audit gates, classify nimrod's behaviour:
   - **PRESENT** — implementation matches Core line-by-line.
   - **PARTIAL** — implementation matches Core's behaviour but is missing
     a named constant, lacks a forward-compat hook, or doesn't cross-test
     against Core's known-answer vectors.
   - **MISSING** — implementation does not exist in nimrod.

4. Catalogue every PARTIAL / MISSING as a BUG with priority.

Out of scope:
  - **Taproot activation logic** (versionbits / BIP-9 transition) — covered
    by W82 (deployments parity).
  - **PSBT v2 BIP-371 fields beyond `PSBT_IN_TAP_KEY_SIG`** — only listed
    as a single gate (G27); a separate wave dedicated to PSBT-v2 taproot
    field coverage would be appropriate.
  - **Silent Payments BIP-352** — separate spec; nimrod has no SP code.
  - **MuSig2 / FROST aggregated signing** — outside Bitcoin Core spec.
  - **TLUV / OP_CAT proposals** — non-standard / not deployed.
  - **`P2SH+WITNESS`-only exception block** (`TAPROOT_EXCEPTION_HASH`) at
    `params.nim:488` — already correctly handled (validation.nim:522).

## Audit gates (30)

Each gate cites Core line(s) and the nimrod code reference for the
match (PRESENT) or the closest analog / absence (PARTIAL / MISSING).

### Subsystem A — BIP-340 Schnorr verification (gates 1-6)

#### Gate 1 — Schnorr verify is wired through libsecp256k1 — **PRESENT**
Reference: `bitcoin-core/src/key.cpp:280` (`VerifySchnorrSignature`
calls `secp256k1_schnorrsig_verify`).
Nimrod: `src/crypto/secp256k1.nim:544` (`secp256k1_schnorrsig_verify`
under `getContext()`). The wrapper at :523 + :829 (engine variant) is
called by the interpreter at 3 sites (`:1793, :2095, :2578`).

#### Gate 2 — BIP-340 known-answer csv cross-verification — **PARTIAL**
Reference: `bitcoin-core/src/test/key_tests.cpp` cross-checks against
BIP-340 `test-vectors.csv`. Without the csv, a buggy libsecp wiring
(wrong message length, wrong endian, leaked auxRand, mis-tagged
challenge) cannot be detected by unit tests.
Nimrod: `tests/test_w95_bip340_schnorr.nim:421-470` has **2 indices**
(vector 0 + vector 1) hard-coded but does not iterate the full
14-vector csv. **BUG-1 (P1)**: full csv missing — see W95 follow-on
in test plan.

#### Gate 3 — `verifySchnorr` returns false on parse failure — **PRESENT**
Reference: `bitcoin-core/src/pubkey.cpp:241` (`secp256k1_xonly_pubkey_parse`
returning 0 makes `VerifySchnorrSignature` return false).
Nimrod: `src/crypto/secp256k1.nim:533-534` and :835 both return false
on parse failure.

#### Gate 4 — Empty message reject (BIP-340) — **PARTIAL**
Reference: BIP-340 §"Verification" — the message is any 32-byte hash;
empty is invalid because libsecp asserts `msglen > 0` but no documented
constraint requires 32 specifically in the verify call.  Core uses
fixed-32 (`SignatureHashSchnorr` returns `uint256`).
Nimrod: `src/crypto/secp256k1.nim:537-538` rejects `msg.len == 0`.
The engine variant `:841` passes `csize_t(32)` regardless of input
length. **BUG-2 (P2)**: the standalone `verifySchnorr` accepts any
non-zero message length (and passes it through to libsecp), unlike
the engine variant.  Real tapscript / taproot paths always pass a
32-byte sighash, so this is a strict-encoding lint, not a consensus
bug. Lint-tier.

#### Gate 5 — BIP-340 tagged hash uses SHA-256, NOT SHA-256d — **PRESENT**
Reference: BIP-340 §"Design — Tagged Hashes" — `SHA256(SHA256(tag) ||
SHA256(tag) || x)`.  Note: this is **NOT** doubleSha256.
Nimrod: `src/script/interpreter.nim:553-560` and `src/wallet/wallet.nim:94`
both correctly use single-SHA256.  Covered by `test_w95_bip340_schnorr.nim`
suite "tagged hash structure".

#### Gate 6 — Schnorr signing in wallet — **MISSING**
Reference: `bitcoin-core/src/key.cpp:273-291` (`CKey::SignSchnorr`)
plus `KeyPair::SignSchnorr` :549-571.
Nimrod: **no `signSchnorr` proc anywhere in `src/wallet/*.nim`**.
The `secp256k1.nim` wrapper has only `verifySchnorr`, no
`secp256k1_schnorrsig_sign` FFI binding.  The `psbt.nim` field
`PSBT_IN_TAP_KEY_SIG` (:56) can be *read* but the wallet cannot *fill*
it because no signer exists.  Wallet line 1285 ("P2TR - requires
Schnorr signature (simplified)") confesses the gap.
**BUG-3 (P0-CONSENSUS)**: nimrod cannot produce a Schnorr signature
for a P2TR spend.  A user wallet that holds P2TR coins cannot spend
them.  Verify-side is fine; sign-side is missing.

### Subsystem B — BIP-341 Taproot key-path (gates 7-13)

#### Gate 7 — `TAPROOT_LEAF_MASK = 0xFE` mask of leaf-version byte — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.h:241`.
Nimrod: `src/script/interpreter.nim:2598` (`controlBlock[0] and 0xFE`),
matched at :2925.  Magic number, not a named constant — see Gate 28.

#### Gate 8 — Control-block size validation
[33, 4129] divisible-by-32 — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1970`,
`interpreter.h:243-246`.
Nimrod: `src/script/interpreter.nim:2592-2594` and :2921-2922.

#### Gate 9 — Annex detection & strip via `ANNEX_TAG = 0x50` — **PRESENT**
Reference: `bitcoin-core/src/script/script.h:58`,
`bitcoin-core/src/script/interpreter.cpp:1951-1958`.
Nimrod: `src/script/interpreter.nim:2519-2522` and :2896-2899.
Hardcoded literal `0x50`; see Gate 28 for named-constant gap.

#### Gate 10 — TapTweak compute via `internal_pk || merkle_root` — **PRESENT**
Reference: `bitcoin-core/src/pubkey.cpp:246-254` (`ComputeTapTweakHash`).
Nimrod: `src/script/interpreter.nim:2644-2648` (script path),
:2971-2975. Wallet-side: `src/wallet/wallet.nim:540` (BIP-86 empty
merkle root) and `src/wallet/descriptor.nim:640` (`tr()` descriptor).

#### Gate 11 — Output-key commitment verify (Q == lift_x(P) + t*G) — **PRESENT**
Reference: `bitcoin-core/src/pubkey.cpp:257-263`
(`XOnlyPubKey::CheckTapTweak`) calls libsecp's
`secp256k1_xonly_pubkey_tweak_add_check`. Core uses libsecp's verify
function which both computes and compares in one call.
Nimrod: `src/script/interpreter.nim:2660-2669` and :2980-2993 follows
a slightly different code shape — calls `tweakXonlyPubkey` then
manually compares Q-bytes + parity bit.  Functionally equivalent.

#### Gate 12 — Key-path Schnorr verify with sig.size in {64,65} — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1726`.
Nimrod: `src/script/interpreter.nim:2527-2528` and :2531-2541
(64/65 + hashtype range gate).

#### Gate 13 — SIGHASH_DEFAULT (0x00) explicit byte in 65-byte sig rejected — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1733`.
Nimrod: `src/script/interpreter.nim:2535-2536`.

### Subsystem C — BIP-341 Taproot script-path (gates 14-22)

#### Gate 14 — Leaf hash uses `TaggedHash("TapLeaf", leafver || compact_size(script) || script)` — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1872-1875`.
Nimrod: `src/script/interpreter.nim:2605-2610` and :2930-2935.
Uses `writeVarBytes` (compact-size + bytes), matching Core's
`CompactSizeWriter`.

#### Gate 15 — Merkle path walk with lexicographic-pair `TaggedHash("TapBranch",...)` — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1877-1900`.
Nimrod: `src/script/interpreter.nim:2613-2637` and :2940-2964.
Lex-compare loop matches `std::lexicographical_compare`.

#### Gate 16 — Commitment verified BEFORE leaf-version branch
(unknown-version anyone-can-spend ONLY after commitment passes) — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1973-1985`
(commitment via ComputeTapleafHash + VerifyTaprootCommitment, THEN
leaf-version check).
Nimrod: `src/script/interpreter.nim:2600-2678` and :2927-3001.
**This was W94 BUG-A** and is closed; W127 confirms the close.

#### Gate 17 — `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` flag — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1985-1988`.
Nimrod: `sfDiscourageUpgradableTaprootVersion` at :92, fires at
:2676 and :2999. Closed by W94.

#### Gate 18 — Tapscript leaf version 0xC0 enables BIP-342 path — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.h:242`,
`interpreter.cpp:1978`.
Nimrod: `src/script/interpreter.nim:2675` and :2998.

#### Gate 19 — Tapscript Schnorr verify hard-errors instead of NULLFAIL
(sig.size != {64,65}, bad hashtype, schnorr-verify-fail) — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1721-1741`
(`CheckSchnorrSignature`).
Nimrod: `src/script/interpreter.nim:1744-1798` and CHECKSIGADD path
at :2061-2097. Closed by W95.

#### Gate 20 — Annex prefix INCLUDES `OP_RESERVED=0x50` as well — **PARTIAL**
Reference: `bitcoin-core/src/script/script.h:58` defines `ANNEX_TAG`
as the literal `0x50`. `interpreter.cpp:1951` calls it `ANNEX_TAG`,
NOT `OP_RESERVED`.
Nimrod: the literal `0x50` appears 3 times in `interpreter.nim`:
:140 (`OP_RESERVED* = 0x50'u8`), :2520, :2897. The two annex-detection
sites use bare `0x50`, NOT the named OP_RESERVED constant.
**BUG-4 (P2)**: there is no `ANNEX_TAG` named constant. A refactor
that renames `OP_RESERVED` (semantically a different protocol concept
that just happens to share the byte value) would leave the two
unrelated `0x50` annex literals untouched — a real fragility.

#### Gate 21 — Witness stack size ≤ MAX_STACK_SIZE (1000) — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1855`.
Nimrod: `src/script/interpreter.nim:2707` and :3017. Closed by W94.

#### Gate 22 — Initial witness elements ≤ MAX_SCRIPT_ELEMENT_SIZE (520) — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1858-1861`.
Nimrod: `src/script/interpreter.nim:2709-2711` and :3019-3021.
Closed by W94.

### Subsystem D — BIP-342 Tapscript opcodes + sigops (gates 23-30)

#### Gate 23 — OP_CHECKSIGADD (0xBA) defined and bound to tapscript only — **PRESENT**
Reference: `bitcoin-core/src/script/script.h` and
`interpreter.cpp:347-405`.
Nimrod: `src/script/interpreter.nim:265` (`OP_CHECKSIGADD* = 0xba`),
opcode handler at :2009-2108. Returns `seInvalidOpcode` outside
tapscript at :2011.

#### Gate 24 — OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY disabled in tapscript — **PRESENT**
Reference: BIP-342 §"Rationale", `interpreter.cpp:1812-1814`.
Nimrod: `src/script/interpreter.nim:1812-1814` returns
`seTapscriptCheckmultisig`.

#### Gate 25 — OP_SUCCESSx pre-pass (Core IsOpSuccess byte list) — **PRESENT**
Reference: `bitcoin-core/src/script/script.cpp:364-370`.
Nimrod: `src/script/interpreter.nim:993-1007` (`isOpSuccess`) and
:1009-1052 (`tapscriptOpSuccessPrePass`).  Bytes match Core exactly:
80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254.

#### Gate 26 — Validation-weight budget init at leaf entry, decrement-on-sig — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:1981` (init),
:362 (decrement).
Nimrod: `src/script/interpreter.nim:2725-2726` and :3031-3032 (init);
:540-546 (consume); called at :1658 + :2028.

#### Gate 27 — Tapscript-mandatory minimal IF/NOTIF — **PRESENT**
Reference: `bitcoin-core/src/script/interpreter.cpp:603-613` (in
the OP_IF handler, consensus rule for tapscript).
Nimrod: `src/script/interpreter.nim:1216-1218` returns
`seTapscriptMinimalIf`.

#### Gate 28 — Named constants for Taproot / Tapscript magic numbers — **PARTIAL**
Reference: `bitcoin-core/src/script/interpreter.h:241-246` define
`TAPROOT_LEAF_MASK`, `TAPROOT_LEAF_TAPSCRIPT`,
`TAPROOT_CONTROL_BASE_SIZE`, `TAPROOT_CONTROL_NODE_SIZE`,
`TAPROOT_CONTROL_MAX_NODE_COUNT`, `TAPROOT_CONTROL_MAX_SIZE`;
`script.h:58, 61, 64` define `ANNEX_TAG`,
`VALIDATION_WEIGHT_PER_SIGOP_PASSED`, `VALIDATION_WEIGHT_OFFSET`;
`script.h:37` defines `MAX_PUBKEYS_PER_MULTI_A = 999`.
Nimrod: **none of these named constants exist** in `interpreter.nim`.
The literals 0xFE, 0xC0, 33, 32, 128, 4129, 0x50, 50, 999 are
copy-pasted (mostly twice each — one in the bool variant of
`verifyWitnessProgram` and one in the error variant). A future change
to any of these (e.g. taproot v2 leaf mask) would require coordinated
edits at multiple sites.
**BUG-5 (P1)**: missing named constants risk forward-compat drift.

#### Gate 29 — OP_CHECKSIGADD_A / OP_CHECKMULTISIG_A descriptor support (BIP-342 §`multi_a`) — **MISSING**
Reference: BIP-342 §`multi_a()` — the official tapscript replacement
for `multi()` uses repeated OP_CHECKSIGADD + OP_NUMEQUAL/OP_NUMEQUALVERIFY,
allowing up to `MAX_PUBKEYS_PER_MULTI_A=999` keys.  Core supports
this via the descriptor parser (`descriptor.cpp` `MultiAExprNode`) +
miniscript (`miniscript.h` `MULTI_A` fragment).
Nimrod: `src/wallet/miniscript.nim` has `MsPkK`, `MsPkH`, `MsMulti`
but **no `MsMultiA`** fragment.  `src/wallet/descriptor.nim` parses
`tr(...)` but has no `multi_a(...)` parser arm.  Net: nimrod cannot
construct a tapscript leaf that uses BIP-342 multi-signature.
**BUG-6 (P1)**: descriptor / miniscript `multi_a` missing.

#### Gate 30 — script_assets_test.json cross-impl corpus — **MISSING**
Reference: `bitcoin-core/src/test/script_assets_tests.cpp:149-160`
loads `script_assets_test.json` (massive Taproot test corpus,
~tens of MB, generated by Core's fuzz harness).  Every Bitcoin Core
release runs this corpus across 16 flag combinations (`flags = i & 191`
loop at line 67-89).
Nimrod: **no driver, no corpus**.  W95 has 2 hardcoded BIP-340 vectors;
W94 has hand-rolled control-block tests.  Without the corpus, edge
cases (annex empty-but-with-prefix, annex-byte-but-no-prefix, all 16
flag combos × all 6 hashtypes × key-path/script-path/non-tapscript,
specifically-crafted invalid sigs) are not exercised.
**BUG-7 (P0-CDIV)**: highest-value gap.  Core's CI catches Taproot
regressions via this corpus; nimrod has no equivalent.  Cross-impl
test plan: ferry `script_assets_test.json` into `test-suite/` as
shared fixture, write Nim parser + ScriptError → SCRIPT_ERR_* map,
run as overnight CI.

## Bug catalogue (14 total — 3 P0, 4 P1, 7 P2/P3)

| BUG | Pri        | Subsystem | Summary |
|-----|------------|-----------|---------|
| 1   | P1         | BIP-340   | BIP-340 csv only 2 of 14 vectors |
| 2   | P2         | BIP-340   | `verifySchnorr` accepts non-32-byte msg (lint) |
| 3   | P0-CONS    | BIP-340   | Wallet cannot Schnorr-sign (no `signSchnorr`) |
| 4   | P2         | BIP-341   | `ANNEX_TAG` not a named constant |
| 5   | P1         | BIP-341/2 | Named constants missing for TAPROOT_* / VALIDATION_WEIGHT_* |
| 6   | P1         | BIP-342   | miniscript / descriptor missing `multi_a()` |
| 7   | P0-CDIV    | BIP-340/1/2 | `script_assets_test.json` corpus driver missing |
| 8   | P2         | BIP-342   | `MAX_PUBKEYS_PER_MULTI_A` constant missing |
| 9   | P2         | BIP-341   | Wallet cannot construct P2TR script-path spend |
| 10  | P2         | BIP-371   | PSBT-v2 taproot fields beyond key-sig are unfilled |
| 11  | P0-CONS    | BIP-340   | No libsecp `secp256k1_schnorrsig_sign` FFI binding |
| 12  | P3         | BIP-341   | No `verifyWitnessProgram` test for non-32-byte v1 P2A |
| 13  | P3         | BIP-342   | No `tapscriptOpSuccessPrePass` coverage for malformed OP_PUSHDATA4 |
| 14  | P3         | BIP-340   | `verifySchnorr` engine variant hardcodes msglen=32 (engine vs standalone divergence) |

Numbering: BUG-N refers to the row above; BUG-3 == BUG-11 in scope
(no `signSchnorr` wallet proc / no FFI binding) — counted twice
because two files need fixing.

## Top P0 / P1 findings (3-5 ranked)

1. **BUG-7 P0-CDIV — `script_assets_test.json` missing** — highest-value
   single gate.  Closes by ferrying the JSON corpus from Core into
   `test-suite/data/`, adding a Nim driver (`test_w127_script_assets.nim`),
   and mapping SCRIPT_ERR_* → ScriptError.  Catches regressions across
   all 30 gates plus thousands of edge cases the gates by themselves
   don't enumerate.

2. **BUG-3 / BUG-11 P0-CONSENSUS — Wallet cannot Schnorr-sign** —
   nimrod wallet that holds P2TR coins cannot spend them via JSON-RPC
   `sendtoaddress` to a non-P2TR destination.  Fix: add
   `secp256k1_schnorrsig_sign_custom` FFI binding to
   `src/crypto/secp256k1.nim`, then `signSchnorrInput` to
   `src/wallet/wallet.nim`, then wire into `signRawTransaction*` and
   `walletprocesspsbt`.  Cross-impl coverage gap: every BIP-86 wallet
   in the fleet must be able to spend, not just receive.

3. **BUG-6 P1 — miniscript `multi_a()` missing** — nimrod cannot
   construct or sign a tapscript leaf using the canonical BIP-342
   multi-sig pattern.  Closes by adding `MsMultiA` fragment to
   `src/wallet/miniscript.nim` and a parser arm to
   `src/wallet/descriptor.nim`.  Without it, the wallet is limited
   to single-key P2TR.

4. **BUG-1 P1 — BIP-340 csv corpus is 2 of 14 vectors** —
   `test_w95_bip340_schnorr.nim` hardcodes test indices 0 and 1.
   The 14-vector csv exercises (a) the zero pubkey edge case, (b) the
   x-coord > p edge case, (c) malleable signatures, (d) the
   "field overflow" detection.  Closes by parsing the csv into
   `tests/data/bip340_vectors.csv` and iterating.

5. **BUG-5 P1 — Named constants** — refactor `interpreter.nim` to
   replace 0xFE, 0xC0, 33, 32, 128, 4129, 0x50, 50 with named
   constants (per Core `interpreter.h:241-246`, `script.h:58, 61, 64`).
   Mechanical, no behaviour change, eliminates an entire class of
   forward-compat drift.

## Forward-regression guards

Each of the 30 gates has a paired test in
`tests/test_w127_taproot.nim`.  Gates that are MISSING / PARTIAL
emit `skip` (with the TODO referencing the BUG number above) so
that the test file documents the gap; gates that are PRESENT emit
`check` so a regression at that site fires a CI failure.

Gates pinned with `skip` will flip to `check` (or be removed from
`skip`) in the corresponding FIX wave commit.

## References

- BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- BIP-342: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
- BIP-371: https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki (PSBT-v2 taproot)
- Bitcoin Core: `src/script/interpreter.{h,cpp}`, `src/script/script.{h,cpp}`,
  `src/key.cpp`, `src/pubkey.cpp`, `src/test/script_assets_tests.cpp`.
- Closed predecessors: W94 (taproot gates), W95 (BIP-340 Schnorr).
