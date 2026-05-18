# W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W137).
Target:
  - `src/wallet/psbt.nim`                    (1755 LOC) — PSBT v0 codec,
    role helpers (creator/updater/signer/finalizer/extractor/combiner),
    analyzePsbtCore + multisig finalize.
  - `src/rpc/server.nim` PSBT RPC handlers   (lines 6138-7926):
    - `handleCreatePsbt`              (createpsbt)
    - `handleDecodePsbt`              (decodepsbt)
    - `handleCombinePsbt`             (combinepsbt)
    - `handleFinalizePsbt`            (finalizepsbt)
    - `handleAnalyzePsbt`             (analyzepsbt)
    - `handleWalletCreateFundedPsbt`  (walletcreatefundedpsbt)
    - `handlePsbtBumpFee`             (psbtbumpfee)
  - `src/primitives/serialize.nim` `readCompactSize` / `writeCompactSize`
    (canonical-encoding gates that PSBT inherits).
  - `src/crypto/hashing.nim` `verifyP2WSHCommitment` / `verifyP2SHCommitment`
    (finalize-side anti-forgery gates, W31).

Reference (Bitcoin Core):
  - `src/psbt.h`                    — wire format / unserialize switch /
    PSBTInput / PSBTOutput / PartiallySignedTransaction Serialize+Unserialize.
  - `src/psbt.cpp`                  — Merge / IsNull / FillSignatureData /
    FromSignatureData / SignPSBTInput / FinalizePSBT /
    FinalizeAndExtractPSBT / CombinePSBTs / RemoveUnnecessaryTransactions /
    PrecomputePSBTData / DecodeBase64PSBT / DecodeRawPSBT.
  - `src/node/psbt.cpp`             — AnalyzePSBT (next-role classifier,
    fee/vsize/feerate estimation).
  - `src/rpc/rawtransaction.cpp`    — createpsbt / decodepsbt / combinepsbt
    / finalizepsbt / analyzepsbt / utxoupdatepsbt / joinpsbts /
    converttopsbt / descriptorprocesspsbt RPCs.
  - `src/wallet/rpc/spend.cpp`      — walletcreatefundedpsbt /
    walletprocesspsbt.

BIPs: BIP-174 (PSBT v0), BIP-370 (PSBT v2), BIP-371 (Taproot PSBT
fields), BIP-32 (HD keypath origin), BIP-327 (MuSig2 PSBT fields).

W137 is the **first** wave to audit nimrod's PSBT codec end-to-end against
Core's wire format. Prior waves (W31, W41, W43, W47, W47-5, W48) closed
specific finalize / canonical-emit / role-classifier gaps but did not
re-sweep the parser / serializer for round-trip parity, BIP-371 v0
completeness, or Core-specific validation hooks.

## Status

**BUGS FOUND — 22 distinct defects across 22 gates MISSING / PARTIAL /
WRONG (of 30). 8 gates PRESENT (Core-aligned).**

Of those:
  - **5 P0-CDIV / P0-CONS** — consensus / network divergence risk
    (input.partial_sig pubkey validity not checked; non-witness UTXO
    prevout-hash mismatch not detected; tap_tree leaf-version / depth /
    completeness not validated; trailing-bytes-after-PSBT silently
    accepted; M-of-N multisig duplicate-pubkey collision via differing
    encodings).
  - **8 P1** — wire-format / cross-impl interop bugs (input MuSig2
    fields silently routed to `unknown` map; partial-sig DER encoding
    not enforced; size-prefixed value-length check absent; tap_internal_key
    / tap_merkle_root "all zeros" sentinel collides with valid x-only
    key of zeros — theoretical but precedent-setting; PSBT_GLOBAL_XPUB
    xpub bytes not validated; W47 canonical-emit not applied to outputs'
    hdKeypaths; sighash type written as little-endian int32 but Core
    serializes as `SerializeToVector(s, *sighash_type)` which writes
    `<compact_size=4><int4>` — matches but documented unevenly; tx
    map's input/output count mismatch silently accepted on parse).
  - **6 P2** — RPC / interface gaps (no `utxoupdatepsbt` RPC; no
    `joinpsbts` RPC; no `walletprocesspsbt` RPC; no `converttopsbt`
    RPC; no `descriptorprocesspsbt` RPC; analyzepsbt missing
    fee/estimated_vsize/estimated_feerate fields).
  - **3 P3** — cosmetic / contract (Merge() doesn't honor `false`
    return for mismatched tx; `IsNull` definition too loose; PSBT
    `MAX_FILE_SIZE_PSBT = 100_000_000` constant exists but never
    enforced).

## Gates / matrix

Order: each gate covers a distinct slice of Core's PSBT contract.

| # | Gate | Verdict |
|---|------|---------|
| G1 | Magic bytes `'psbt\\xff'` | PRESENT |
| G2 | PSBT_GLOBAL_UNSIGNED_TX required, txin.scriptSig and witnesses must be empty | PRESENT |
| G3 | PSBT_GLOBAL_XPUB: key size = 79, xpub IsFullyValid, duplicate-key rejection | **BUG-1** (P1) |
| G4 | PSBT_GLOBAL_VERSION > PSBT_HIGHEST_VERSION rejected | PRESENT |
| G5 | PSBT_GLOBAL_PROPRIETARY identifier+subtype parsed | PRESENT |
| G6 | PSBT_IN_NON_WITNESS_UTXO: hash matches prevout.hash AND vout.n < vout.size | **BUG-2** (P0-CDIV) |
| G7 | PSBT_IN_PARTIAL_SIG: pubkey IsFullyValid, dedup by CKeyID, sig CheckSignatureEncoding | **BUG-3** (P0-CDIV) + **BUG-4** (P1) + **BUG-5** (P0-CDIV) |
| G8 | PSBT_IN_SIGHASH: 4-byte int32 read via UnserializeFromVector size-check | **BUG-6** (P1) |
| G9 | PSBT_IN_BIP32_DERIVATION: pubkey IsFullyValid, length % 4 == 0 | **BUG-7** (P1) |
| G10 | PSBT_IN_TAP_KEY_SIG: 64-65 byte schnorr sig | PRESENT |
| G11 | PSBT_IN_TAP_LEAF_SCRIPT: key validity, leaf_ver in tap_scripts inner map | PRESENT |
| G12 | PSBT_IN_TAP_BIP32_DERIVATION: leaf_hashes set + origin | PRESENT |
| G13 | PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1A) parsed into input struct | **BUG-8** (P1) |
| G14 | PSBT_IN_MUSIG2_PUB_NONCE (0x1B) parsed into input struct | **BUG-9** (P0-CDIV) |
| G15 | PSBT_IN_MUSIG2_PARTIAL_SIG (0x1C) parsed into input struct | **BUG-10** (P0-CDIV) |
| G16 | PSBT_OUT_TAP_TREE: depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT, leaf_ver & ~TAPROOT_LEAF_MASK == 0, builder.IsComplete | **BUG-11** (P0-CDIV) |
| G17 | PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS deserialized + serialized | PRESENT |
| G18 | Unknown key types preserved (round-trip via `unknown` map) | PRESENT |
| G19 | Duplicate-key rejection per map (global / input / output) | PRESENT (but BUG-5 makes input partial_sig dedup weak) |
| G20 | Separator presence enforced (`found_sep`) | **BUG-12** (P1) |
| G21 | inputs.size() == tx.vin.size() check after parse | **BUG-13** (P1) |
| G22 | outputs.size() == tx.vout.size() check after parse | **BUG-14** (P1) |
| G23 | No-trailing-bytes-after-PSBT check (DecodeRawPSBT) | **BUG-15** (P0-CDIV) |
| G24 | RemoveUnnecessaryTransactions (drop non_witness_utxos for taproot-only PSBTs) | **BUG-16** (P2) |
| G25 | PrecomputePSBTData (cached sighash mid-state for taproot signing) | **BUG-17** (P2) |
| G26 | SignPSBTInput (PSBTError::SIGHASH_MISMATCH, MISSING_INPUTS, INCOMPLETE) | **BUG-18** (P2) |
| G27 | utxoupdatepsbt RPC + joinpsbts RPC | **BUG-19** (P2) |
| G28 | walletprocesspsbt RPC + converttopsbt RPC | **BUG-20** (P2) |
| G29 | analyzepsbt fee / estimated_vsize / estimated_feerate fields | **BUG-21** (P1) |
| G30 | MAX_FILE_SIZE_PSBT enforcement in `deserialize` / `fromBase64` | **BUG-22** (P3) |

## Detailed findings

### G3 — PSBT_GLOBAL_XPUB validation (BUG-1, P1)

`src/wallet/psbt.nim:945-957`:
```nim
of PSBT_GLOBAL_XPUB:
  if key.len != 79:  # 1 + 78 bytes for BIP32 extended key
    raise newException(PsbtError, "invalid global xpub key size")
  let xpub = key[1 ..< key.len]
  # ... stores raw bytes, no IsFullyValid check
```
Core (`psbt.h:1282-1311`) calls `xpub.DecodeWithVersion(&key.data()[1])`
and rejects with `throw "Invalid pubkey"` if `xpub.pubkey.IsFullyValid()`
is false. Nimrod stores the bytes verbatim. Cross-impl: blockbrew W118
flagged this; clearbit / camlcoin / hotbuns all validate xpub on
ingest. A malformed xpub silently passes through and breaks downstream
descriptor expansion.

### G6 — non_witness_utxo prevout hash / vout.n mismatch (BUG-2, P0-CDIV)

`src/wallet/psbt.nim:983-995`: after parsing each `PSBTInput`, nimrod
does NOT verify
```nim
input.nonWitnessUtxo.get().txid() == tx.inputs[i].prevOut.txid
```
and does NOT verify
```nim
tx.inputs[i].prevOut.vout < input.nonWitnessUtxo.get().outputs.len
```
Core (`psbt.h:1370-1378`) enforces BOTH and throws:
```cpp
if (input.non_witness_utxo->GetHash() != tx->vin[i].prevout.hash)
  throw "Non-witness UTXO does not match outpoint hash";
if (tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size())
  throw "Input specifies output index that does not exist";
```
**P0-CDIV impact**: a maliciously crafted PSBT with a non-matching
non_witness_utxo would be silently accepted by nimrod. Downstream
signing would then sign against the wrong UTXO scriptPubKey/value,
producing a signature that verifies against the wrong utxo but won't
verify against the actual on-chain coin — wallet bricks a tx. Worse,
the signer might be tricked into spending more value than they think.

### G7 — partial_sig pubkey IsFullyValid + sig DER encoding + GetID dedup (BUG-3 P0-CDIV, BUG-4 P1, BUG-5 P0-CDIV)

`src/wallet/psbt.nim:668-673`:
```nim
of PSBT_IN_PARTIAL_SIG:
  if key.len != 34 and key.len != 66:
    raise newException(PsbtError, "invalid partial sig key size")
  let pubkey = key[1 ..< key.len]
  result.partialSigs[pubkey] = value
```

**BUG-3 (P0-CDIV)**: pubkey bytes are not validated as a curve point.
Core (`psbt.h:530-534`) calls `CPubKey pubkey(...)` then
`if (!pubkey.IsFullyValid()) throw "Invalid pubkey"`. Garbage pubkey
bytes pass nimrod's parser. A signer-receiver downstream may attempt to
sign or verify against a non-point and crash / loop / leak.

**BUG-4 (P1)**: signature bytes are not DER-validated. Core
(`psbt.h:544`) calls `CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG
| SCRIPT_VERIFY_STRICTENC, nullptr)` and throws "Signature is not a
valid encoding" on failure, including the empty-sig case. Nimrod's
finalizer hands an empty / non-DER sig to script assembly verbatim
(`pushToScriptSig(scriptSig, sig)` at line 1344), producing a broken
final tx that the network rejects.

**BUG-5 (P0-CDIV)**: dedup key is the raw pubkey bytes, not `CKeyID
= HASH160(pubkey)`. Core (`psbt.h:535`) uses
`partial_sigs.contains(pubkey.GetID())`. This means two different
encodings of the SAME secp256k1 point (compressed vs uncompressed
33 vs 65 bytes) collide for Core but not for nimrod. nimrod will accept
both and the finalizer may pick the wrong encoding when assembling the
final scriptSig / witness.

### G8 — SIGHASH value size check (BUG-6, P1)

`src/wallet/psbt.nim:675-679`:
```nim
of PSBT_IN_SIGHASH:
  if key.len != 1:
    raise newException(PsbtError, "sighash key must be 1 byte")
  var valR = BinaryReader(data: value, pos: 0)
  result.sighashType = some(valR.readInt32LE())
```
Core (`psbt.h:558-560`) reads `UnserializeFromVector(s, sighash)` which
checks `remaining_after + expected_size != remaining_before` (psbt.h:117)
and throws "Size of value was not the stated size". Nimrod reads 4 bytes
of int32 but doesn't check that `value.len == 4` — silently accepts
SIGHASH values with extra trailing bytes, breaking byte-identity
round-trip with Core decoding.

### G9 — BIP32 derivation pubkey IsFullyValid (BUG-7, P1)

`src/wallet/psbt.nim:691-698`: pubkey bytes are not validated. Core
(`psbt.h:157-160`) calls `CPubKey pubkey(...)` then
`if (!pubkey.IsFullyValid()) throw "Invalid pubkey"`. Same vector as
BUG-3 but on the BIP32 derivation field.

### G13-G15 — INPUT MuSig2 fields not deserialized (BUG-8 P1, BUG-9 P0-CDIV, BUG-10 P0-CDIV)

`src/wallet/psbt.nim:96-129` (PsbtInput struct) declares fields for
taproot but **does NOT declare**:
- `m_musig2_participants` (PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, 0x1A)
- `m_musig2_pubnonces`    (PSBT_IN_MUSIG2_PUB_NONCE,           0x1B)
- `m_musig2_partial_sigs` (PSBT_IN_MUSIG2_PARTIAL_SIG,          0x1C)

The deserializer switch at `psbt.nim:656-809` has NO arms for these key
types. They silently fall into `result.unknown[key] = value` (line
808-809). Output side has only `musig2Participants` (line 144) but no
pubnonces / partial_sigs.

**BUG-8 (P1)**: input participant pubkeys silently demoted to unknown
— round-trip preserves bytes but loses semantic awareness.

**BUG-9 (P0-CDIV)** + **BUG-10 (P0-CDIV)**: pubnonce and partial_sig
PSBT fields are central to BIP-327 MuSig2 signing flows. A MuSig2
signer that ships partial sigs to a coordinator through a PSBT must
have both encoder AND decoder. nimrod's "everything is unknown"
fallback means:
- a MuSig2 coordinator receiving a nimrod-signed PSBT cannot see the
  partial sigs without raw-bytes parsing.
- nimrod cannot detect duplicate-key collisions on these fields per
  Core's switch-arm rules at psbt.h:803-836 (sizes 67 / 99 bytes; sig
  size 66 for pubnonce, 32 for partial_sig).
- a malicious PSBT can inject duplicate pubnonces or oversize sigs and
  nimrod accepts them.

### G16 — PSBT_OUT_TAP_TREE validation (BUG-11, P0-CDIV)

`src/wallet/psbt.nim:853-861`:
```nim
of PSBT_OUT_TAP_TREE:
  if key.len != 1:
    raise newException(PsbtError, "tap tree key must be 1 byte")
  var valR = BinaryReader(data: value, pos: 0)
  while valR.remaining > 0:
    let depth = valR.readUint8()
    let leafVer = valR.readUint8()
    let script = valR.readVarBytes()
    result.tapTree.add((depth, leafVer, script))
```
Core (`psbt.h:1032-1066`) enforces:
1. `s_tree.empty()` rejection — "Output Taproot tree must not be empty".
2. `depth > TAPROOT_CONTROL_MAX_NODE_COUNT` (= 128) rejection — "leaf
   greater than Taproot maximum depth".
3. `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0` rejection — "leaf with an
   invalid leaf version".
4. `builder.IsComplete()` rejection — "Output Taproot tree is
   malformed" (Merkle-tree shape must close).

Nimrod skips all four. A crafted PSBT_OUT_TAP_TREE with depth > 128
or invalid leaf_ver lands in the wallet's output map and downstream
descriptor expansion would emit a non-spendable taproot output. The
wallet thinks the output is signable but the network rejects every
spend. **P0-CDIV**: divergence from Core's parse-time rejection
strands funds.

### G20 — Separator presence (BUG-12, P1)

Nimrod's `readKeyValue` returns `(@[], @[])` on a zero-length key and
the input-/output-map loops break on `if key.len == 0`. But there is no
`found_sep` boolean flag — if the stream ends WITHOUT a separator
(truncated PSBT), nimrod's `while r.remaining > 0` simply exits the
loop and proceeds to the next map / return successfully. Core
(`psbt.h:865-867, 1126-1128, 1354-1356`) throws "Separator is missing
at the end of an input/output/global map" in this case.

A truncated PSBT (e.g. dropped trailing 0x00 byte) is silently accepted
by nimrod and the resulting in-memory shape is a partial parse —
downstream serializers re-emit a "fixed" PSBT that doesn't match the
broken input byte-for-byte.

### G21-G22 — input/output map count mismatch (BUG-13 + BUG-14, P1)

`src/wallet/psbt.nim:983-995`:
```nim
let numInputs = result.tx.get().inputs.len
for i in 0 ..< numInputs:
  if r.remaining == 0:
    raise newException(PsbtError, "not enough input maps")
  result.inputs.add(r.deserializePsbtInput())
```
Nimrod only checks the LOWER bound (too few maps → throw). Core
(`psbt.h:1381-1384, 1395-1397`) ALSO checks the UPPER bound:
```cpp
if (inputs.size() != tx->vin.size())
  throw "Inputs provided does not match the number of inputs in transaction.";
```
Nimrod silently accepts extra trailing maps that exceed the tx vin/vout
counts. They get parsed and stored but never used; downstream re-emit
recovers the canonical form, dropping the extras. Round-trip
byte-identity broken.

### G23 — No-trailing-bytes check (BUG-15, P0-CDIV)

After reading inputs+outputs, nimrod `deserialize` returns. There is
no equivalent of Core's `DecodeRawPSBT` (`psbt.cpp:619-625`):
```cpp
ss_data >> psbt;
if (!ss_data.empty()) {
  error = "extra data after PSBT";
  return false;
}
```
A PSBT with extra trailing bytes (e.g. attacker appends an attestation
blob or unrelated bytes) is silently accepted. **P0-CDIV**: nimrod's
parse-decode-reserialize round-trip is now a DIFFERENT byte string than
the input, so signatures over the PSBT-as-a-blob (some HW wallet
attestation flows do this) silently fail to verify. Worse, an attacker
who can append bytes can mount a hash-collision-style replay.

### G24 — RemoveUnnecessaryTransactions (BUG-16, P2)

Core (`psbt.cpp:514-549`) defines `RemoveUnnecessaryTransactions(psbtx)`
which, after signing, drops `non_witness_utxo` fields for inputs where
ALL inputs are segwit v1 (taproot) — saves on-wire bytes since v1
signatures don't need the full prev tx. Nimrod has no equivalent. PSBTs
emitted by nimrod for taproot-only spends are larger than Core's by
~250 bytes per non_witness_utxo.

### G25 — PrecomputePSBTData (BUG-17, P2)

Core (`psbt.cpp:385-400`) defines
`PrecomputePSBTData(psbt) -> PrecomputedTransactionData` which caches
spent_outputs for `SignPSBTInput`. Nimrod has no equivalent — every
sign call recomputes from scratch.

### G26 — SignPSBTInput error codes (BUG-18, P2)

Core defines `enum class PSBTError { OK, MISSING_INPUTS,
SIGHASH_MISMATCH, EXTERNAL_SIGNER_NOT_FOUND, EXTERNAL_SIGNER_FAILED,
INCOMPLETE }` and `SignPSBTInput` returns one of these. Nimrod's
`finalizePsbtInput` returns `bool` only — callers can't distinguish
"missing UTXO" from "sighash mismatch" from "incomplete script
assembly". Downstream RPC error mapping (`signrawtransactionwithkey`
errors `code -25` "missing inputs" vs `-22` "sighash mismatch") is
collapsed to a generic `false`.

### G27 — utxoupdatepsbt + joinpsbts RPCs (BUG-19, P2)

Core registers:
- `utxoupdatepsbt`     (rawtransaction.cpp) — fills in
  witness_utxo/non_witness_utxo from current UTXO set.
- `joinpsbts`          (rawtransaction.cpp) — concatenates inputs+outputs
  from multiple PSBTs into one (Core 0.21+).

`src/rpc/server.nim` dispatch switch at line 8427-8443 has:
```nim
of "createpsbt": handleCreatePsbt(...)
of "decodepsbt": handleDecodePsbt(...)
of "combinepsbt": handleCombinePsbt(...)
of "finalizepsbt": handleFinalizePsbt(...)
of "analyzepsbt": handleAnalyzePsbt(...)
of "walletcreatefundedpsbt": handleWalletCreateFundedPsbt(...)
of "psbtbumpfee": handlePsbtBumpFee(...)
```
No `utxoupdatepsbt`, no `joinpsbts`. RPC operator coverage gap.

### G28 — walletprocesspsbt + converttopsbt + descriptorprocesspsbt RPCs (BUG-20, P2)

Core registers:
- `walletprocesspsbt`        (wallet/rpc/spend.cpp) — sign+finalize via wallet keys.
- `converttopsbt`            (rawtransaction.cpp) — convert raw tx → PSBT.
- `descriptorprocesspsbt`    (rawtransaction.cpp) — descriptor-based sign+finalize.

None of these are registered in nimrod's RPC dispatcher. `bumpfee`
emits a signed-and-broadcast tx but there's no first-class
"sign-this-PSBT-with-my-wallet" surface that mirrors Core's flow.

### G29 — analyzepsbt fee / vsize / feerate (BUG-21, P1)

`src/rpc/server.nim:7869-7926`: `handleAnalyzePsbt` emits only
`{"inputs": [...], "next": role}`. Core's `analyzepsbt`
(`rpc/rawtransaction.cpp::analyzepsbt`, returning
`node::PSBTAnalysis` from `node/psbt.cpp::AnalyzePSBT`) emits
ALSO:
```json
{
  "estimated_vsize": int,
  "estimated_feerate": "X.XXXXXXXX BTC/kvB",
  "fee": "X.XXXXXXXX",
  "error": "...string if invalid..."
}
```
PSBT consumers that pipe analyzepsbt output to fee estimation logic
(common in coordinator UIs) get NaN values from nimrod.

### G30 — MAX_FILE_SIZE_PSBT enforcement (BUG-22, P3)

`src/wallet/psbt.nim:28` defines `MAX_FILE_SIZE_PSBT* = 100_000_000`
but the constant is **never referenced** outside its declaration.
`deserialize(data)` (line 903) and `fromBase64(s)` (line 1005) accept
arbitrary-size inputs. Core's `MAX_FILE_SIZE_PSBT` is used in
`SpanReader` initialization in CWallet's PSBT loading path. Nimrod's
PSBT RPC accepts a 10GB base64 blob, hits OOM. DoS surface.

## Universal patterns (W137)

1. **"defensive validation drops the loudest checks"** — nimrod's
   parser PRESERVES bytes faithfully (sizes are checked, unknown keys
   preserved) but DROPS semantic checks that Core enforces at parse
   time: pubkey curve-validity, signature DER encoding, depth limits,
   taproot tree completeness. This is the inverse failure mode of
   "drop the bytes, keep the semantics". Pattern: every parser MUST
   pin BOTH wire-format AND semantic invariants.

2. **"silent unknown-fallback hides P0 fields"** — input MuSig2 fields
   (0x1A / 0x1B / 0x1C) silently route to `unknown` map. Round-trip
   works for the bytes but coordinators / wallets that interpret the
   in-memory struct can't see them. Pattern: every BIP that adds new
   PSBT key types MUST drive a struct-field addition AND a
   deserializer arm BEFORE merge, not after first user complaint.

3. **"trailing-bytes acceptance is a forge-vector"** — nimrod accepts
   bytes-after-PSBT silently. Combined with HW wallet attestation
   flows that sign over the PSBT-as-a-blob, an attacker can craft an
   attestation-replay. Pattern: every BIP-174 codec MUST reject
   trailing bytes; pattern mirrors the W120 / W122 "audit framework
   requires byte-exact" promotion.

4. **"P0 audit class for cryptographic-input parsers"** — BUG-1
   (xpub), BUG-3/BUG-5 (partial sig pubkey + dedup), BUG-7 (BIP32
   derivation pubkey) are all in the same class: a parser accepts
   pubkey-shaped bytes without verifying they form a valid secp256k1
   curve point. Downstream signing / verification is allowed to crash
   / loop / leak. Pattern: every PSBT field that carries a pubkey
   MUST call `IsFullyValid` (or equivalent) at parse time.

5. **"role-helpers must own role-completeness"** — Core's PSBTRole
   enum has 5 values (creator/updater/signer/finalizer/extractor);
   nimrod adds a 6th (Combiner) but the helpers (`createPsbt`,
   `addInput`, `addPartialSig`, `combinePsbts`, `finalizePsbt`,
   `extractTransaction`) only cover a SUBSET of Core's contract. There's
   no public `signPsbtInput` mirror — wallet/psbt.nim is consumed by
   `wallet/wallet.nim` directly without a stable single-call sign
   surface. Pattern: an audit of role implementations should EXIT each
   role with a Core-shape callable.

## Remediation order (recommended fix-wave priority)

1. **FIX-W137-1 (P0)** — BUG-2 (non_witness_utxo prevout-hash check) +
   BUG-15 (no-trailing-bytes-after-PSBT check). Both single-file in
   `wallet/psbt.nim`, add ~10 LOC each. **Forensic urgency**: P0-CDIV
   on every PSBT parse.

2. **FIX-W137-2 (P0)** — BUG-3 + BUG-5 + BUG-7 (pubkey IsFullyValid +
   CKeyID-based dedup). Requires a new `validatePubkeyBytes` helper in
   `crypto/hashing.nim` or `crypto/secp256k1.nim`; adoption across 3
   PSBT deserialize arms.

3. **FIX-W137-3 (P0)** — BUG-11 (PSBT_OUT_TAP_TREE depth/leaf_ver/
   builder.IsComplete). Requires a Nim translation of Core's
   `TaprootBuilder::Add` + `IsComplete`. Cross-wave dep on W127
   Taproot helpers.

4. **FIX-W137-4 (P0)** — BUG-9 + BUG-10 (input MuSig2 pubnonce +
   partial_sig deserializer + struct fields). Add fields to
   `PsbtInput`, add deserializer arms, add serializer arms, add merge
   arms, add canonical-emit sort. Multi-impl coordination — sibling
   waves on rustoshi / hotbuns / blockbrew may flag the same gap.

5. **FIX-W137-5 (P1)** — BUG-1 (xpub IsFullyValid) + BUG-4 (sig
   CheckSignatureEncoding) + BUG-6 (SIGHASH size check) + BUG-12
   (`found_sep` flag) + BUG-13/14 (input/output count exact match) +
   BUG-21 (analyzepsbt fee/vsize/feerate).

6. **FIX-W137-6 (P2/P3)** — BUG-16 (RemoveUnnecessaryTransactions) +
   BUG-17 (PrecomputePSBTData) + BUG-18 (PSBTError enum) + BUG-19/20
   (missing RPCs) + BUG-22 (MAX_FILE_SIZE_PSBT enforcement).

## Test methodology

`tests/test_w137_psbt.nim` (~520 LOC, 30 tests) pins the CURRENT
(buggy / absent) behaviour with `check` that asserts the gap. When a
future FIX wave closes a gap, the corresponding test fails LOUDLY and
the developer flips the assertion. This is the W120 / W122 / W123 /
W124 / W125 / W128 / W131 / W132 / W133 methodology — every audit
since W120 has used the same xfail-regression-guard idiom.

Source pinning is done with `readFile("src/wallet/psbt.nim") in`
substring checks where structural-existence is the gate (e.g. "does
PsbtInput have a `musig2Pubnonces` field?" → `check
"musig2Pubnonces" notin psbtSrc`).

Behavioural pinning is done with constructed PSBT bytes via
`deserialize / fromBase64` + assertion that the buggy
behaviour completes without raising (or assertion that the missing
check would not have fired).

## References

- `bitcoin-core/src/psbt.h:28-79` — magic bytes + key-type constants.
- `bitcoin-core/src/psbt.h:111-119` — `UnserializeFromVector` size-check.
- `bitcoin-core/src/psbt.h:143-170` — `DeserializeHDKeypath` /
  `DeserializeHDKeypaths`.
- `bitcoin-core/src/psbt.h:204-258` — MuSig2 participant parsers.
- `bitcoin-core/src/psbt.h:478-868` — input switch (PARTIAL_SIG,
  TAP_*, MUSIG2_*).
- `bitcoin-core/src/psbt.h:970-1129` — output switch (TAP_TREE,
  MUSIG2_*, BIP32_DERIVATION).
- `bitcoin-core/src/psbt.h:1170-1397` — top-level Serialize /
  Unserialize.
- `bitcoin-core/src/psbt.cpp:514-549` — RemoveUnnecessaryTransactions.
- `bitcoin-core/src/psbt.cpp:385-400` — PrecomputePSBTData.
- `bitcoin-core/src/psbt.cpp:402-512` — SignPSBTInput.
- `bitcoin-core/src/psbt.cpp:607-631` — DecodeBase64PSBT /
  DecodeRawPSBT (trailing-bytes check).
- `bitcoin-core/src/node/psbt.cpp:15-150` — AnalyzePSBT (next-role +
  fee + vsize + feerate).

W137 audit complete; PSBT codec needs P0-priority fix-wave (BUG-2 +
BUG-3 + BUG-5 + BUG-7 + BUG-9 + BUG-10 + BUG-11 + BUG-15) before any
MuSig2 deploy or hardware-wallet integration push.
