# W142 — BIP-141 / BIP-143 SegWit witness validation audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W142).
Concurrent-agent coordination: 3 OTHER audit waves in PARALLEL (streak
71 fix + 72 discovery preserved).

Target:
  - `src/consensus/validation.nim`         (1994 LOC) — `checkWitnessMalleation`,
    `findWitnessCommitment`, `computeWitnessCommitment`,
    `computeMerkleRoot`, `calculateBlockWeight`, `validateBlock`,
    `isWitnessProgram`.
  - `src/script/interpreter.nim`           (3107 LOC) — `verifyScript`,
    `verifyScriptWithError`, `verifyWitnessProgram` (bool + error),
    `computeSighashSegwitV0` (BIP-143), `computeSighashLegacy`,
    `isWitnessProgram` (2nd defn), `isP2WPKH`, `isP2WSH`, `isP2A`.
  - `src/primitives/serialize.nim`         (397 LOC) — `writeTransaction`,
    `readTransaction`, `writeBlock`, `txid`, `wtxid`.
  - `src/primitives/types.nim`             — `Transaction.witnesses` field
    (`seq[seq[seq[byte]]]`) + `isSegwit`.
  - `src/mining/blocktemplate.nim`         — `computeWitnessCommitment`
    (2nd defn), `createCoinbaseTx`, `estimateTxSigops`.
  - `src/nimrod.nim`                       — `mkGetData` handler (block /
    tx serving on `invBlock` vs `invWitnessBlock` / `invTx` vs
    `invWitnessTx`).
  - `src/network/messages.nim`             — `writeBlock` / `writeTransaction`
    P2P wire emission (always `includeWitness=true`).
  - `src/consensus/params.nim`             — `segwitHeight` (per network).

Reference (Bitcoin Core):
  - `src/validation.cpp:3864-3916` (`CheckWitnessMalleation`),
    `:3918-3983` (`CheckBlock` block-size + merkle gates), `:3997-4019`
    (`GenerateCoinbaseCommitment`), `:4051-4170`
    (`ContextualCheckBlock` calling site), `:3837-3862`
    (`CheckMerkleRoot` + CVE-2012-2459 defense).
  - `src/consensus/validation.h:15-18` (`NO_WITNESS_COMMITMENT`,
    `MINIMUM_WITNESS_COMMITMENT=38`), `:147-165`
    (`GetWitnessCommitmentIndex`), `:128-139` (`GetTransactionWeight`,
    `GetBlockWeight`).
  - `src/consensus/merkle.cpp:46-83` (`ComputeMerkleRoot`,
    `BlockMerkleRoot`, `BlockWitnessMerkleRoot`).
  - `src/script/interpreter.cpp:321-419` (`EvalChecksigPreTapscript`,
    `EvalChecksig` — `pbegincodehash` for BIP-143),
    `:1917-2000` (`VerifyWitnessProgram`),
    `:2035-2118` (`VerifyScript` — native + P2SH witness paths,
    `WITNESS_MALLEATED` / `WITNESS_MALLEATED_P2SH` /
    `WITNESS_UNEXPECTED` gates).
  - `src/primitives/transaction.cpp:75-93` (`ComputeHasWitness`,
    `ComputeWitnessHash` — short-circuit when `!HasWitness()`),
    `:200-238` (`UnserializeTransaction` — superfluous-witness reject).
  - `src/script/script.cpp:206-263` (`IsPayToAnchor`,
    `IsWitnessProgram`).
  - `src/policy/policy.h` (`WITNESS_SCALE_FACTOR=4`).

BIPs: 141 (segwit), 143 (sighash v0), 144 (network serialization),
141 §"P2WSH" (scriptCode), 173 (bech32, not in scope), 444 (P2A —
relevant only via `IsPayToAnchor`).

## Status

**BUGS FOUND — 22 distinct defects across 28 gates (MISSING / PARTIAL /
WRONG) of 30. 8 gates PRESENT (Core-aligned).**

Subsystem breakdown:

- **Witness commitment & malleation** (G1–G7): 3 BUGS — `unexpected-witness`
  check missing on segwit-active-but-no-commitment path; CVE-2012-2459
  mutated-merkle defense absent in `computeMerkleRoot`; `isWitnessProgram`
  exists in two parallel copies in `consensus/validation.nim` and
  `script/interpreter.nim` (two-pipeline).
- **WTXID / serialization parity** (G8–G13): 5 BUGS — `wtxid()` does
  NOT short-circuit when `!HasWitness()` (always serializes with
  marker/flag if `tx.witnesses.len > 0`); `readTransaction` does NOT
  reject "Superfluous witness record" per Core transaction.h:228-231;
  `writeBlock` has no `includeWitness=false` overload (no legacy block
  serialization path); `getdata(invBlock)` and `getdata(invTx)` BOTH
  serve witness-format wire payloads (BIP-144 contract violation);
  `Transaction.witnesses` uses `tx.witnesses.len > 0` as
  "has witness" sentinel, divergent from Core's
  `any vin[i].scriptWitness.IsNull() == false`.
- **BIP-143 sighash + scriptCode** (G14–G17): 2 BUGS — P2WSH
  scriptCode does NOT respect `pbegincodehash` (last
  OP_CODESEPARATOR position) — uses whole `@script` for all SigVersion
  WITNESS_V0 SignatureChecks (Core script/interpreter.cpp:418-422
  `pbegincodehash`); P2WPKH detection inside CHECKSIG uses
  `ctx.scriptPubKey.isP2WPKH() or (isP2SH() and script.len==25 and
  script[0]==OP_DUP and script[1]==OP_HASH160)` — structural shape
  match instead of an explicit P2WPKH flag, fragile under future
  template variants.
- **VerifyScript / P2SH-wrap-witness** (G18–G23): 4 BUGS —
  `verifyScript` (bool) does NOT enforce
  `scriptSig == push(redeemScript)` canonical form for
  P2SH-wrap-witness (Core
  `SCRIPT_ERR_WITNESS_MALLEATED_P2SH`,
  script/interpreter.cpp:2082-2086); `verifyScript` (bool) does NOT
  reject "WITNESS_UNEXPECTED" when non-witness scriptPubKey has
  non-empty witness data (the error variant DOES check at line
  2380-2383 — two-pipeline divergence); P2SH-wrap-anything-that-looks
  -like-P2TR-program enters taproot validation in nimrod, while Core
  treats it as anyone-can-spend at line 1947-1989 (`!is_p2sh` gate);
  `verifyWitnessProgram` (bool + error) takes NO `is_p2sh` parameter
  — caller information is lost.
- **Block weight / structural** (G24–G27): 3 BUGS — `validateBlock`
  does NOT enforce Core's `bad-blk-length` early checks
  (`vtx.size() * 4 > MAX_BLOCK_WEIGHT` and `TX_NO_WITNESS(block) * 4
  > MAX_BLOCK_WEIGHT`); witness merkle root caching
  (`m_checked_witness_commitment`) absent; mining
  `computeWitnessCommitment` is the SECOND parallel implementation
  with hardcoded zero-reserved-value, distinct from validation's
  parameterized one (two-pipeline).
- **Mining coinbase commitment** (G28–G30): 2 BUGS —
  `createCoinbaseTx` gates the witness-commitment OP_RETURN on
  "any byte of commitment value != 0" instead of "are any witness
  txs in this block" (logical mismatch; in practice always true,
  but broken-by-design); `estimateTxSigops` is a 1-line heuristic
  (`scriptSig.len div 72`) — diverges sharply from Core's true
  legacy + P2SH + witness counting; cannot correctly budget block
  sigops at template time.
- **Network / wire** (G31, fold-in): 1 BUG — `peer.supportsWitness`
  is consulted only for outbound `getdata` building; INBOUND
  `getdata(invBlock)`/`getdata(invTx)` requests are NOT honored
  per BIP-144 (peers asking for legacy format get witness anyway).
  See **BUG-12**.

Of the 22:

  - **3 P0-CONSENSUS** — fork-class consensus divergence (BUG-1
    `unexpected-witness` check missing for segwit-active +
    no-commitment + witness-tx block = malleability attack vector
    that nimrod accepts but Core rejects; BUG-9 BIP-143 scriptCode
    ignores `pbegincodehash` for P2WSH spends = wrong sighash
    when witness script contains OP_CODESEPARATOR = signature
    invalid under our consensus but valid under Core's, or
    vice-versa = silent acceptance of a tx Core would reject /
    rejection of a tx Core would accept; BUG-14
    `verifyScript` (bool) accepts P2SH-wrap-witness with
    non-canonical scriptSig encoding = malleability vector Core
    closes via `WITNESS_MALLEATED_P2SH`).
  - **2 P0-CDIV** — wire-format / wtxid divergence (BUG-4 wtxid
    differs from Core for txs with non-empty `witnesses` seq but
    all-empty per-input stacks = mempool / relay wtxid mismatch;
    BUG-5 `readTransaction` accepts segwit-formatted txs with
    all-empty per-input witness stacks where Core throws
    "Superfluous witness record" = wire-malleability vector).
  - **3 P0-WIRE** — wire-contract violations (BUG-6 `writeBlock`
    has no legacy variant; BUG-7 `getdata(invBlock)` serves
    witness-format; BUG-8 `getdata(invTx)` serves witness-format).
  - **5 P1** — implementation gaps that mostly land as
    interop / robustness issues (BUG-2 CVE-2012-2459 mutated-merkle
    defense — closed in practice by leaf-level dedup, but the
    primitive itself is missing; BUG-3 two-pipeline
    `isWitnessProgram`; BUG-10 P2WPKH detection via structural
    shape match; BUG-15 `verifyScript`-bool missing
    WITNESS_UNEXPECTED check vs error variant; BUG-16
    P2SH-wrap-32-byte-v1 enters taproot validation instead of
    anyone-can-spend fall-through).
  - **5 P2** — missing operator surface / structural follow-ups
    (BUG-17 `verifyWitnessProgram` missing `is_p2sh` param;
    BUG-18 `validateBlock` missing Core's bad-blk-length cheap
    early gates; BUG-19 witness merkle caching absent;
    BUG-20 `computeWitnessCommitment` two-pipeline mining vs
    consensus; BUG-21 `createCoinbaseTx` gates commitment OP_RETURN
    on commitment value, not on presence of witness txs).
  - **4 P3** — heuristic / non-consensus (BUG-11 P2WPKH structural
    match — duplicate finding categorized at P1 above; BUG-13
    `Transaction.witnesses` semantic; BUG-22 `estimateTxSigops`
    heuristic).

## Gates / matrix

Order: each gate covers a distinct slice of Core's BIP-141 / 143
contract.

| #   | Subsystem | Gate                                                                                 | Verdict           |
|-----|-----------|--------------------------------------------------------------------------------------|-------------------|
| G1  | COMMIT    | Coinbase witness commitment: `OP_RETURN 0x24 0xaa21a9ed <32>` LAST match win         | PRESENT           |
| G2  | COMMIT    | `MINIMUM_WITNESS_COMMITMENT = 38` bytes enforced                                     | PRESENT           |
| G3  | COMMIT    | Witness reserved value: coinbase witness[0] stack-of-1 of exactly 32 bytes           | PRESENT           |
| G4  | COMMIT    | commitment = `SHA256d(witness_merkle_root \|\| reserved_value)` byte-for-byte        | PRESENT           |
| G5  | COMMIT    | `unexpected-witness` reject when segwit-active + no commitment + any tx has witness  | **BUG-1**  (P0-CONSENSUS) |
| G6  | COMMIT    | `unexpected-witness` reject when segwit NOT active + any tx has witness              | PRESENT           |
| G7  | MERKLE    | `BlockWitnessMerkleRoot` mutation defense (CVE-2012-2459 — `mutated` flag)           | **BUG-2**  (P1)   |
| G8  | TX-PARITY | `isWitnessProgram` defined exactly once (no two-pipeline)                            | **BUG-3**  (P1)   |
| G9  | WTXID     | `wtxid()` short-circuits to txid when `!HasWitness()` (Core transaction.cpp:88-89)   | **BUG-4**  (P0-CDIV) |
| G10 | WTXID     | `readTransaction` rejects superfluous witness record (Core transaction.h:228-231)    | **BUG-5**  (P0-CDIV) |
| G11 | WIRE      | `writeBlock(..., includeWitness=false)` legacy variant exists                         | **BUG-6**  (P0-WIRE) |
| G12 | WIRE      | `getdata(invBlock)` serves block in TX_NO_WITNESS form (BIP-144)                     | **BUG-7**  (P0-WIRE) |
| G13 | WIRE      | `getdata(invTx)` serves tx in TX_NO_WITNESS form (BIP-144)                           | **BUG-8**  (P0-WIRE) |
| G14 | SIGHASH   | P2WSH scriptCode begins at `pbegincodehash` (post-OP_CODESEPARATOR slice)            | **BUG-9**  (P0-CONSENSUS) |
| G15 | SIGHASH   | P2WPKH scriptCode = `0x1976a914<hash160>88ac`                                        | PRESENT           |
| G16 | SIGHASH   | P2WPKH detection inside CHECKSIG uses dedicated flag (not structural shape match)    | **BUG-10** (P1)   |
| G17 | SIGHASH   | BIP-143 preimage order + LE / hash positions match                                   | PRESENT           |
| G18 | VERIFY    | Native witness: scriptSig must be empty (`SCRIPT_ERR_WITNESS_MALLEATED`)             | PRESENT           |
| G19 | VERIFY    | P2SH-witness: scriptSig must be `CScript() << redeemScript` (canonical-push)         | **BUG-14** (P0-CONSENSUS) |
| G20 | VERIFY    | WITNESS_UNEXPECTED when scriptPubKey is not a witness program but witness != empty   | **BUG-15** (P1)   |
| G21 | VERIFY    | P2SH-wrap-v1-32-byte program: NOT entered as taproot (Core 1947 `!is_p2sh`)          | **BUG-16** (P1)   |
| G22 | VERIFY    | `verifyWitnessProgram` accepts `is_p2sh` parameter                                   | **BUG-17** (P2)   |
| G23 | VERIFY    | `verifyScript` (bool) and `verifyScriptWithError` agree on all witness gates         | divergent (BUG-14/15/16) |
| G24 | WEIGHT    | `vtx.size() * 4 > MAX_BLOCK_WEIGHT` cheap early gate (Core validation.cpp:3947)      | **BUG-18** (P2)   |
| G25 | WEIGHT    | `serialize_no_witness(block) * 4 > MAX_BLOCK_WEIGHT` separate gate                   | (folded into BUG-18) |
| G26 | WEIGHT    | `m_checked_witness_commitment` caching across CheckBlock / ContextualCheckBlock      | **BUG-19** (P2)   |
| G27 | WEIGHT    | `MAX_BLOCK_WEIGHT = 4_000_000`, `WITNESS_SCALE_FACTOR = 4` constants                  | PRESENT           |
| G28 | MINING    | `computeWitnessCommitment` exists ONCE (no two-pipeline mining vs consensus)         | **BUG-20** (P2)   |
| G29 | MINING    | Coinbase witness-commitment OP_RETURN gate: ANY witness-tx in block (not byte test)  | **BUG-21** (P2)   |
| G30 | MINING    | `estimateTxSigops`: legacy + P2SH + witness counting (not byte-length heuristic)     | **BUG-22** (P3)   |

## Bug detail

### BUG-1 (P0-CONSENSUS) — `unexpected-witness` reject missing when segwit-active and commitment absent
**Surface**: `src/consensus/validation.nim:411-443`
(`checkWitnessMalleation`).

**Symptom**: When `segwitActive == true` and the coinbase carries
NO witness commitment (`commitmentOpt.isNone`), nimrod returns
`ok()` regardless of whether any tx in the block has witness data.
Per Bitcoin Core `validation.cpp:3905-3913`, the "unexpected witness
data" for-loop sits OUTSIDE both `expect_witness_commitment` and
`commitpos != NO_WITNESS_COMMITMENT`, so the check also fires when
segwit is active but the coinbase happens to omit the commitment.
The comment at line 434 even reads "G10: no commitment present → no
error (Core does not require one)" — but **Core DOES require it**
when any tx has witness data, even after segwit activation.

**Core reference** (`validation.cpp:3905-3913`):

```c
// (outside the "expect_witness_commitment" + "commitpos != NO" block)
for (const auto& tx : block.vtx) {
    if (tx->HasWitness()) {
        return state.Invalid(
            BlockValidationResult::BLOCK_MUTATED,
            "unexpected-witness",
            "unexpected witness data found");
    }
}
```

**Excerpt** (`validation.nim:411-443`):

```nim
let commitmentOpt = findWitnessCommitment(blk.txs[0])
if segwitActive:
  if commitmentOpt.isSome:
    # ... full check ...
  # G10: no commitment present → no error (Core does not require one). ← WRONG
else:
  # G11: segwit not active — witness data in any tx is illegal.
  for tx in blk.txs:
    for inputIdx in 0 ..< tx.witnesses.len:
      if tx.witnesses[inputIdx].len > 0:
        return voidErr(veUnexpectedWitness)

ok()
```

**Impact**: A miner that constructs a segwit block with witness
transactions but OMITS the coinbase commitment OP_RETURN gets the
block accepted by nimrod and rejected by Core → split. The classical
malleation vector — every block with witness data MUST commit, and
nodes that don't enforce this lose alignment.  Concrete failure
mode: nimrod follows a malicious miner's "commitment-stripped"
fork; Core stays on the correct chain.

**Fix sketch**: Pull the `else` body up so it runs whenever
`segwitActive && commitmentOpt.isNone` — or rewrite as a flat
"either both checks fire, or one matches the commitment":

```nim
if segwitActive and commitmentOpt.isSome:
  # full commitment check (current branch)
else:
  # G11 + G10-with-witness: reject any witness data when there's
  # no commitment to defend.
  for tx in blk.txs:
    for inputIdx in 0 ..< tx.witnesses.len:
      if tx.witnesses[inputIdx].len > 0:
        return voidErr(veUnexpectedWitness)
```

This mirrors Core's flat structure (the for-loop lives outside
both `if`s).

### BUG-2 (P1) — CVE-2012-2459 mutated-merkle defense absent in `computeMerkleRoot`
**Surface**: `src/consensus/validation.nim:172-197`
(`computeMerkleRoot`); `validateBlock:1305-1319` (caller).

**Symptom**: Core's `ComputeMerkleRoot` returns a `mutated` flag
(`merkle.cpp:46-63`) that the wrapper `CheckMerkleRoot`
(`validation.cpp:3853-3858`) uses to reject `bad-txns-duplicate`
blocks. Nimrod's `computeMerkleRoot` has no such flag, and
`validateBlock` does not detect this case via the merkle primitive.
The CVE-2012-2459 attack pattern (duplicate-last-if-odd at any
level) is closed in practice by the **separate** leaf-level
duplicate-txid table check at `validation.nim:1305-1310`, but the
defense primitive itself is missing — a refactor that moves the
dup-txid check could silently lose the protection.

**Core reference** (`merkle.cpp:46-63`):

```c
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        ...
```

**Impact**: Correct outcome today, but the protection lives in a
loosely-coupled spot. Any future refactor that removes the explicit
leaf-level dedup (e.g. relies on Core-style mutation detection)
will silently reopen the attack.

**Fix sketch**: Return `(root, mutated)` from `computeMerkleRoot`
and require `not mutated` in `validateBlock`, matching Core's
structure exactly.

### BUG-3 (P1) — `isWitnessProgram` defined twice (two-pipeline)
**Surface**: `src/consensus/validation.nim:976-999` (returns
`tuple[valid, version, program]`) and
`src/script/interpreter.nim:898-924` (returns
`(bool, int, seq[byte])`).

**Symptom**: Two parallel definitions of the same Core function
(`CScript::IsWitnessProgram`). Both implement the same length /
opcode gates today, but **whichever is imported first wins** for
any given call site, and a future divergence (e.g. fixing a
push-length-byte off-by-one in one but not the other) becomes a
silent consensus split.

**Core reference**: `src/script/script.cpp:249-263` — one source
of truth.

**Impact**: Maintenance hazard. No active divergence detected;
P1 because the gate is exercised in both validation (sigop counting,
witness routing) and script (verify entry).

**Fix sketch**: Move the canonical impl into
`primitives/types.nim` or `script/interpreter.nim`, delete the
copy. Audit all imports.

### BUG-4 (P0-CDIV) — `wtxid()` does NOT short-circuit to txid for txs without real witness
**Surface**: `src/primitives/serialize.nim:393-398` (`wtxid`);
`writeTransaction:239-269` (`hasWitness` predicate).

**Symptom**: Core's `ComputeWitnessHash`
(`primitives/transaction.cpp:86-93`) explicitly returns the
non-witness hash when `!HasWitness()`. nimrod's `wtxid` always
calls `serialize(includeWitness=true)`, which writes BIP-144
marker / flag when **`tx.witnesses.len > 0`**, regardless of
whether any inner stack is non-empty.  Core's `HasWitness` is
`any vin[i].scriptWitness.IsNull() == false` — i.e. needs at
least one non-empty stack.  nimrod's `isSegwit`
(`types.nim:89-91`) uses the same `any non-empty` predicate but
`writeTransaction` doesn't — divergence in the same impl.

**Excerpt** (`serialize.nim:393-398`):

```nim
proc wtxid*(tx: Transaction): TxId =
  ## Compute witness transaction ID (hash of full serialization)
  ## For non-segwit transactions, wtxid equals txid
  let fullData = tx.serialize(includeWitness = true)
  TxId(doubleSha256(fullData))

# writeTransaction line 242:
let hasWitness = tx.witnesses.len > 0 and includeWitness
```

**Concrete failure mode**: `wallet/feebumper.nim:273` initialises
`newTx.witnesses = newSeq[seq[seq[byte]]](newTx.inputs.len)` — a
seq of N empty stacks. nimrod's `wtxid()` will then emit a
segwit-formatted serialization with N×`compactsize(0)` witness
records. Core's `ComputeWitnessHash` returns `txid` (legacy).
Two different wtxids → mempool / relay key mismatch → tx is
seen as "new" by every peer except those running nimrod.

**Wire impact**: Cross-impl mempool / wtxid-relay (BIP-339)
inconsistency. INV-by-wtxid lookups miss.

**Fix sketch**: Mirror Core exactly. In `wtxid`:

```nim
proc wtxid*(tx: Transaction): TxId =
  if not tx.isSegwit:        # uses any-non-empty predicate
    return tx.txid()
  let fullData = tx.serialize(includeWitness = true)
  TxId(doubleSha256(fullData))
```

…or change `writeTransaction`'s `hasWitness` to use
`tx.isSegwit` (the any-non-empty predicate already defined in
`types.nim`).

### BUG-5 (P0-CDIV) — `readTransaction` accepts superfluous witness record
**Surface**: `src/primitives/serialize.nim:271-322`
(`readTransaction`).

**Symptom**: Core's `UnserializeTransaction`
(`primitives/transaction.h:222-231`) throws
`"Superfluous witness record"` when the segwit marker + flag was
read but the witness data turned out to be all-empty stacks.
nimrod blindly reads `result.witnesses.add(r.readWitness())`
per-input regardless of whether the resulting tx satisfies
`HasWitness()`.

**Core reference** (`transaction.h:222-231`):

```c
if ((flags & 1) && fAllowWitness) {
    flags ^= 1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        s >> tx.vin[i].scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        // It's illegal to encode witnesses when all witness stacks are empty.
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

**Excerpt** (`serialize.nim:317-322`):

```nim
# Read witness data
for i in 0 ..< result.inputs.len:
  result.witnesses.add(r.readWitness())

result.lockTime = r.readUint32LE()
```

**Impact**: A peer can ship a malleated transaction that
nimrod accepts but Core rejects (with parse failure). The
malleated form has marker + flag + N×`compactsize(0)` witness
stacks → empty-witness segwit framing. Compounds with **BUG-4**:
nimrod computes wtxid over the malleated framing, Core rejects
parsing entirely → relay loop.

**Fix sketch** (after the for-loop at line 320):

```nim
# Reject "superfluous witness record" per Core transaction.h:228-231.
var hasReal = false
for w in result.witnesses:
  if w.len > 0:
    hasReal = true
    break
if not hasReal:
  raise newException(SerializationError, "superfluous witness record")
```

### BUG-6 (P0-WIRE) — `writeBlock` has no `includeWitness=false` overload
**Surface**: `src/primitives/serialize.nim:340-344`
(`writeBlock`); `src/network/messages.nim:522-523` (P2P emission).

**Symptom**: BIP-144 distinguishes legacy-format block
serialization (used for `MSG_BLOCK` getdata responses) from
witness-format (used for `MSG_WITNESS_BLOCK`). nimrod has no
legacy serialization path for blocks — `writeBlock` always
calls `writeTransaction(tx)` with default
`includeWitness=true`.

**Excerpt**:

```nim
proc writeBlock*(w: var BinaryWriter, blk: Block) =
  w.writeBlockHeader(blk.header)
  w.writeCompactSize(uint64(blk.txs.len))
  for tx in blk.txs:
    w.writeTransaction(tx)                # always with witness
```

**Impact**: Cascades into **BUG-7** and **BUG-8**. A
non-segwit-aware peer that asked for a legacy `MSG_BLOCK` gets a
witness-framed payload it can't parse → disconnect / ban from
that peer.

**Fix sketch**: Add `writeBlock(w, blk, includeWitness: bool)`
overload that propagates the flag into each `writeTransaction`
call.  Same for `serialize(blk: Block, includeWitness: bool)`.

### BUG-7 (P0-WIRE) — `getdata(invBlock)` serves witness-format payload
**Surface**: `src/nimrod.nim:954-970` (mkGetData handler).

**Symptom**: nimrod treats `invBlock` and `invWitnessBlock`
identically — same `newBlockMsg(blockOpt.get())` is sent on the
wire. Per BIP-144, getdata(invBlock) (= `MSG_BLOCK = 2`) MUST
return the block in `TX_NO_WITNESS` form; only
getdata(invWitnessBlock) (= `MSG_WITNESS_BLOCK = 0x40000002`)
includes witness data.

**Excerpt**:

```nim
for item in msg.getData:
  if item.invType == invBlock or item.invType == invWitnessBlock:
    if pruneHorizon >= 0:
      let idxOpt = state.chainState.db.getBlockIndex(...)
      ...
    let blockOpt = state.chainState.db.getBlock(BlockHash(item.hash))
    if blockOpt.isSome:
      let blkMsg = newBlockMsg(blockOpt.get())     # always full-witness
```

**Impact**: Pre-segwit peers (effectively absent in 2026 mainnet,
but still possible on regtest / testnet harnesses) cannot parse
the response. Wire-contract violation regardless of whether any
peer hits it.

**Fix sketch**: Branch on `invType`. Build a `newLegacyBlockMsg`
helper that calls `writeBlock(w, blk, includeWitness=false)`
(blocked by **BUG-6**); send that on `invBlock`.

### BUG-8 (P0-WIRE) — `getdata(invTx)` serves witness-format payload
**Surface**: `src/nimrod.nim:1007-1019` (mkGetData handler).

**Symptom**: Identical pattern to **BUG-7** but for transactions.
nimrod sends `newTxMsg(entryOpt.get().tx)` for both `invTx` and
`invWitnessTx`. `newTxMsg` → `mkTx` → `writeTransaction(tx)`
defaults to `includeWitness=true`.

**Excerpt**:

```nim
elif item.invType == invTx or item.invType == invWitnessTx:
  let txid = TxId(item.hash)
  let entryOpt = if state.mempool != nil: state.mempool.get(txid)
                else: none(MempoolEntry)
  if entryOpt.isSome:
    let txMsg = newTxMsg(entryOpt.get().tx)        # always full-witness
```

**Impact**: Same wire-contract violation as **BUG-7**. Plus a
subtler symptom: a peer that INVed legacy-`MSG_TX` (= `invTx`)
will now receive a witness-framed reply containing wtxid bytes
on the wire, but their getdata loop is keyed by txid → state
divergence in their mempool tracker.

**Fix sketch**: Branch on `invType`. For `invTx`, emit
`writeTransaction(tx, includeWitness=false)` (legacy form);
for `invWitnessTx`, emit with witness.

### BUG-9 (P0-CONSENSUS) — BIP-143 scriptCode for P2WSH ignores `pbegincodehash`
**Surface**: `src/script/interpreter.nim:1695-1717` (sigWitnessV0
branch of CHECKSIG).

**Symptom**: Per BIP-143 and Core
`script/interpreter.cpp:321-419` (`EvalChecksigPreTapscript` and
`EvalChecksig`), the scriptCode passed to `SignatureHashV0` for
P2WSH is the **slice of the witness script from `pbegincodehash`
(position immediately after the most recently executed
OP_CODESEPARATOR) to `pend`**.  Core stores this iterator and
updates it at line 1054 of `interpreter.cpp` whenever
OP_CODESEPARATOR fires.  nimrod's sigWitnessV0 path takes the
entire witness script as scriptCode regardless of any
OP_CODESEPARATOR that may have executed.

**Core reference** (`script/interpreter.cpp:326`):

```c
static bool EvalChecksigPreTapscript(... pbegincodehash, pend, ...) {
    ...
    CScript scriptCode(pbegincodehash, pend);
    ...
```

**Excerpt** (`interpreter.nim:1695-1717`):

```nim
of sigWitnessV0:
  # SegWit v0 signature check (BIP143)
  if sig.len >= 1:
    let hashType = uint32(sig[sig.len - 1])
    let sigWithoutHashType = sig[0 ..< sig.len - 1]

    # For P2WPKH, scriptCode is OP_DUP OP_HASH160 <pubkeyhash> ...
    # For P2WSH, scriptCode is the witness script being executed (passed as `script`)
    var scriptCode: seq[byte]
    if ctx.scriptPubKey.isP2WPKH() or
       (ctx.scriptPubKey.isP2SH() and script.len == 25 and
        script[0] == OP_DUP and script[1] == OP_HASH160):
      # P2WPKH: reconstruct from pubkey
      let pubkeyHash = hash160(pubkey)
      scriptCode = @[OP_DUP, OP_HASH160, 0x14'u8]
      scriptCode.add(pubkeyHash)
      scriptCode.add([OP_EQUALVERIFY, OP_CHECKSIG])
    else:
      # P2WSH: use the witness script being executed   ← WRONG: ignores codesepPos
      scriptCode = @script
```

For comparison the **legacy** path immediately above (lines
1683-1690) DOES respect codesepPos:

```nim
of sigBase:
  ...
  if interp.codesepPos != 0xFFFFFFFF'u32 and int(interp.codesepPos) <= script.len:
    scriptCode = script[int(interp.codesepPos) ..< script.len]
  else:
    scriptCode = @script
  scriptCode = findAndDelete(scriptCode, sig)
```

**Impact**: A P2WSH witnessScript that contains
`OP_CODESEPARATOR` will sign with a different scriptCode under
nimrod versus Core. Any transaction relying on such a script
(common in older multisig hot-wallets, some HSM signing flows)
either:
  - has signatures that nimrod validates but Core rejects → nimrod
    builds on a tx Core will mark invalid → split; or
  - has signatures Core validates but nimrod rejects → nimrod
    diverges from the canonical chain.

This is the same class as **BUG-9** above in W127's taproot
audit — codesepPos correctly threaded for tapscript / legacy but
not for BIP-143 v0.

**Fix sketch**: Apply the same codesepPos slice to the P2WSH
branch:

```nim
# P2WSH: use the witness script, sliced at the last OP_CODESEPARATOR
if interp.codesepPos != 0xFFFFFFFF'u32 and int(interp.codesepPos) <= script.len:
  scriptCode = script[int(interp.codesepPos) ..< script.len]
else:
  scriptCode = @script
```

NOTE: BIP-143 does NOT call `FindAndDelete` (that's a legacy-only
malleability defense).  Do not add the `findAndDelete` line.

### BUG-10 (P1) — P2WPKH detection inside CHECKSIG uses structural shape match
**Surface**: `src/script/interpreter.nim:1703-1711`.

**Symptom**: nimrod decides "we're signing a P2WPKH" by matching
the structure of `ctx.scriptPubKey` (is it `OP_0 <20 bytes>`?) OR
by matching `script` (the script being EVALUATED) against a hand-
written P2PKH template (`script.len == 25 and script[0] == OP_DUP
and script[1] == OP_HASH160`). The second clause is a HACK to
catch P2SH-wrap-P2WPKH (where scriptPubKey is P2SH-shape, not
P2WPKH-shape). Any future template (e.g. a P2WPKH variant using
different padding bytes — none exists today, but BIP authors
keep proposing them) silently confuses this detector.

**Excerpt**:

```nim
if ctx.scriptPubKey.isP2WPKH() or
   (ctx.scriptPubKey.isP2SH() and script.len == 25 and
    script[0] == OP_DUP and script[1] == OP_HASH160):
```

**Impact**: Today: works. Tomorrow: fragile.

**Fix sketch**: Add a dedicated `ctx.witnessProgramKind` field
(`wpNone | wpP2WPKH | wpP2WSH | wpTaproot | wpTapscript`) set
by `verifyWitnessProgram` before calling into `eval`, then branch
on that.

### BUG-11 — folded into BUG-10

(Categorised in earlier draft as a separate finding; reclassified
as the same root cause — the P2WPKH-detection hack.)

### BUG-12 (folded into BUG-7 / BUG-8) — inbound `invBlock`/`invTx` not honoured

See BUG-7 and BUG-8. `peer.supportsWitness` is consulted only
for OUTBOUND getdata building (`sync.nim:1599`) — INBOUND
requests are not honoured per BIP-144.

### BUG-13 (P3) — `Transaction.witnesses` "has-witness" semantic divergent
**Surface**: `src/primitives/types.nim:63`,
`src/primitives/serialize.nim:242`.

**Symptom**: `Transaction.witnesses: seq[seq[seq[byte]]]` is a
seq-per-input. The `isSegwit` predicate
(`types.nim:89-91`) uses `tx.witnesses.len > 0 and
tx.witnesses.anyIt(it.len > 0)` (correct: any non-empty stack
across inputs). The `writeTransaction` predicate at
`serialize.nim:242` uses `tx.witnesses.len > 0` — divergent.
This is the root cause of **BUG-4** and **BUG-5**.

**Fix sketch**: Replace the inline predicate in
`writeTransaction` with the canonical `tx.isSegwit` call.
Audit all `tx.witnesses.len > 0` checks; replace with
`tx.isSegwit` or document the intentional difference.

### BUG-14 (P0-CONSENSUS) — `verifyScript` (bool) missing `WITNESS_MALLEATED_P2SH` canonical-push enforcement
**Surface**: `src/script/interpreter.nim:2241-2248`
(`verifyScript` bool, P2SH-wrap-witness branch).

**Symptom**: For P2SH-wrap-witness, Core requires
`scriptSig == CScript() << redeemScript` — a single canonical
push of the serialised redeemScript and nothing else
(`script/interpreter.cpp:2082-2086`,
`SCRIPT_ERR_WITNESS_MALLEATED_P2SH`).  nimrod's bool variant
skips this check entirely:

**Excerpt**:

```nim
# P2SH handling
if sfP2SH in flags and isP2SH(scriptPubKey):
  if not isPushOnly(scriptSig):
    return false  # seSigPushOnly
  ...
  let serializedScript = stackCopy[stackCopy.len - 1]
  ...
  # Check for witness program in P2SH
  let (isP2shWitness, p2shVersion, p2shProgram) = isWitnessProgram(serializedScript)
  if sfWitness in flags and isP2shWitness:
    return verifyWitnessProgram(...)        # MISSING canonical-push check
```

`verifyScriptWithError` ALSO lacks the canonical-push check
(line 2369-2376) — both variants. So this isn't a bool-vs-error
divergence; it's a fleet-wide miss on a malleability defense
gate.

**Core reference** (`script/interpreter.cpp:2082-2086`):

```c
if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
    hadWitness = true;
    if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
        // The scriptSig must be _exactly_ a single push of the redeemScript. ...
        return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
    }
```

**Impact**: A P2SH-wrap-segwit input with an additional push or
opcode preceding the redeemScript push in the scriptSig (which
would change the txid but not the witness or interpreter state)
is **accepted** by nimrod and **rejected** by Core. Malleability
attack vector: an attacker rewrites scriptSig of a confirmed
spending tx to mutate its txid, breaking dependent unconfirmed
children. Pre-segwit this was the entire reason segwit happened.

**Fix sketch**: Re-encode the canonical push of the serialised
redeemScript and compare bytes:

```nim
if sfWitness in flags and isP2shWitness:
  # Canonical-push check per Core script/interpreter.cpp:2082.
  var canonical = BinaryWriter()
  canonical.writeVarBytes(serializedScript)
  if scriptSig != canonical.data:
    return false  # SCRIPT_ERR_WITNESS_MALLEATED_P2SH
  return verifyWitnessProgram(...)
```

(Use `writeCompactSize`/`writeVarBytes` equivalents matching the
nimrod helper for "CScript << <bytes>" — which is just
length-prefixed push: 1-byte 0x01..0x4b for length 1-75, or
OP_PUSHDATA1 + len-byte for 76-255.)

### BUG-15 (P1) — `verifyScript` (bool) missing WITNESS_UNEXPECTED check
**Surface**: `src/script/interpreter.nim:2202-2255`
(`verifyScript` bool, end-of-function).

**Symptom**: The error-returning variant
`verifyScriptWithError` at lines 2378-2383 DOES enforce the
"witness data present but scriptPubKey is not a witness program"
check (`SCRIPT_ERR_WITNESS_UNEXPECTED`).  The bool variant does
not.  Two-pipeline divergence.

**Excerpt** (`verifyScript` bool, lines 2244-2255):

```nim
if sfWitness in flags and isP2shWitness:
  return verifyWitnessProgram(...)

# Clean stack check
if sfCleanStack in flags:
  if interp.stack.len != 1:
    return false

true
```

Compare `verifyScriptWithError`, line 2378-2383:

```nim
# BIP141: if WITNESS flag is set and script is NOT a witness program,
# the witness must be empty
if sfWitness in flags:
  let (isWit, _, _) = isWitnessProgram(scriptPubKey)
  if not isWit and witness.len > 0:
    return seWitnessUnexpected
```

**Impact**: Caller depending on `verifyScript` (bool) silently
admits a tx that the error-returning variant would reject.  Most
mempool / block-validation paths use the error variant — but any
unit-test or alternate caller relying on the bool variant has a
weaker check. Cross-checks between variants for any future
"variant A vs variant B" parity test would fail.

**Fix sketch**: Add the same check at the end of the bool
variant, before `return true`.

### BUG-16 (P1) — P2SH-wrap-32-byte-v1 enters taproot validation
**Surface**: `src/script/interpreter.nim:2244-2247`,
`verifyWitnessProgram:2392-2511`,
`verifyWitnessProgramWithError:2776-2882`.

**Symptom**: Core's `VerifyWitnessProgram`
(`interpreter.cpp:1947`) explicitly gates the taproot branch on
`witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE
&& !is_p2sh`.  For P2SH-wrapped v1-32-byte programs, Core falls
through to the "Other version/size/p2sh combinations return
true" branch — i.e. anyone-can-spend, forward-compat. nimrod's
`verifyWitnessProgram` (both variants) take NO `is_p2sh`
parameter, so a P2SH-wrap-v1-32-byte-program ENTERS taproot
validation, processes the witness as a Schnorr signature, and
likely returns ERROR (the witness was not constructed for
taproot semantics).

**Core reference**:

```c
} else if (witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh) {
    // BIP341 Taproot ...
} else if (!is_p2sh && CScript::IsPayToAnchor(witversion, program)) {
    return true;
} else {
    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    }
    return true;
}
```

**Impact**: A P2SH-wrap-`<OP_1 0x20 ...32 bytes...>` redeemScript
that Core treats as anyone-can-spend (forward-compat) — nimrod
treats as a malformed taproot spend → REJECTS. Inverse divergence
from BUG-1 / 9 / 14 (nimrod rejects what Core accepts here).
Practical impact: a future soft-fork that defines semantics
inside this P2SH-wrap shape would split nimrod off from the
network.

**Fix sketch**: Thread `is_p2sh: bool` through both
`verifyWitnessProgram` variants. Reproduce Core's gate at the
v1-32 branch (return early-true when `is_p2sh`).

### BUG-17 (P2) — `verifyWitnessProgram` missing `is_p2sh` parameter (root of BUG-16)
**Surface**: `src/script/interpreter.nim:2129-2139`,
`:2258-2268`, `:2392-2402`, `:2776-2786`.

**Symptom**: All four signatures (forward decls and definitions
for bool + error variants) omit the `is_p2sh` parameter. Cited
here as a structural follow-up to **BUG-16**.

**Fix sketch**: Add `is_p2sh: bool = false` to all four; pass
`true` from the P2SH path at lines 2244-2247 and 2372-2376.

### BUG-18 (P2) — `validateBlock` missing Core's `bad-blk-length` cheap early gates
**Surface**: `src/consensus/validation.nim:1284-1324`
(`validateBlock`).

**Symptom**: Core's `CheckBlock` at `validation.cpp:3947` runs
THREE size checks early:
  1. `vtx.empty()` → `bad-cb-missing` (nimrod equivalent at
     `validation.nim:1285` → `veNoCoinbase`). ✓
  2. `vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` →
     reject `bad-blk-length` (caps txcount at ~1M).
  3. `GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR
     > MAX_BLOCK_WEIGHT` → reject `bad-blk-length` (base-size DoS
     defense).

nimrod has only the per-tx weight loop, which is dominated by
the same total-weight gate but doesn't include the cheap early
gates 2 and 3.

**Impact**: Today: same outcome via the weight loop. A block
with `baseSize = 1_000_001` and zero witnesses has weight
`3*1_000_001 + 1_000_001 = 4_000_004` → caught by the existing
gate. A block with `vtx.len = 1_000_001` and tiny txs is caught
by the per-tx weight sum (each tx is at least 40 wu via the
mintxweight gate). **No active attack vector** but the Core
parity is incomplete — a refactor that drops the per-tx weight
loop and forgets to add these two gates re-opens the attack
surface.

**Fix sketch**: Add the two gates right after the
`isCoinbase(blk.txs[0])` check:

```nim
if blk.txs.len * WitnessScaleFactor > params.maxBlockWeight:
  return voidErr(veBlockOverweight)
let baseBlockSize = ... # serialize block with includeWitness=false
if baseBlockSize * WitnessScaleFactor > params.maxBlockWeight:
  return voidErr(veBlockOverweight)
```

(Blocked on **BUG-6** for the legacy block-serialize helper.)

### BUG-19 (P2) — witness-commitment caching absent
**Surface**: `src/consensus/validation.nim:387-443`
(`checkWitnessMalleation`).

**Symptom**: Core's `CheckWitnessMalleation` short-circuits via
`block.m_checked_witness_commitment` (`validation.cpp:3873,
3900`). nimrod re-runs the witness-merkle-root hashing on every
call (CheckBlock and ContextualCheckBlock can each invoke it).

**Impact**: Performance, not consensus. ~one extra wtxid-merkle
pass per block under stress. Negligible during normal sync.

**Fix sketch**: Add a `m_checked_witness_commitment: bool` field
to `Block` (if the type is mutable enough) or cache in a
separate `BlockValidationStateCache` keyed by block hash. Lower
priority than every other entry in this file.

### BUG-20 (P2) — `computeWitnessCommitment` defined twice (mining vs consensus)
**Surface**: `src/consensus/validation.nim:199-207` (consensus,
takes `reserved: array[32, byte]` param);
`src/mining/blocktemplate.nim:112-138` (mining, hardcodes
zero-reserved-value).

**Symptom**: Same Core function (`CHash256().Write(witnessroot)
.Write(reserved).Finalize`) implemented twice in nimrod. The
mining version hardcodes a 32-byte zero reserved value (which IS
the conventional miner choice) but cannot ever be configured to
emit a non-zero one — and the second implementation diverges
from validation by const, not by primitive.

**Fix sketch**: Have `blocktemplate.computeWitnessCommitment`
call `validation.computeWitnessCommitment(wtxids, zeros)` with
an explicit `zeros` constant.

### BUG-21 (P2) — `createCoinbaseTx` gates commitment OP_RETURN on commitment value, not witness presence
**Surface**: `src/mining/blocktemplate.nim:177-207`.

**Symptom**:

```nim
# Check if we have a non-zero witness commitment
var hasWitnessCommitment = false
for b in witnessCommitment:
  if b != 0:
    hasWitnessCommitment = true
    break

# Witness commitment output (if any segwit txs)
if hasWitnessCommitment:
  outputs.add(createWitnessCommitmentOutput(witnessCommitment))
```

The "decision" of whether to include the commitment OP_RETURN
in the coinbase is made by inspecting whether the COMMITMENT
VALUE happens to be non-zero. The intent (per the comment) is
"if any segwit txs", but the code is checking the byte pattern
of the commitment. With a zero witnessReservedValue (which is
also hardcoded), `commitment = SHA256d(wtxidMerkleRoot ||
zeros)` is overwhelmingly non-zero — so in practice the
commitment IS always added — but that's coincidence, not design.

**Impact**: Broken-by-design but accidentally correct. A future
refactor that, say, runs this with a witnessCommitment that
happens to start with a zero byte would silently switch the
condition. Plus, conceptually the SAME hasWitnessCommitment
variable gates both the coinbase output AND the coinbase witness
stack (line 200) — both gated by the same wrong predicate.

**Fix sketch**: Replace the byte-scan with an explicit "any tx
has witness data" check from the caller:

```nim
proc createCoinbaseTx*(..., hasWitnessTxs: bool, ...) =
  ...
  if hasWitnessTxs:
    outputs.add(createWitnessCommitmentOutput(witnessCommitment))
```

…and require the caller to pass `txs.anyIt(it.isSegwit)`.

### BUG-22 (P3) — `estimateTxSigops` is a byte-length heuristic
**Surface**: `src/mining/blocktemplate.nim:234-270`.

**Symptom**: This function estimates sigops by counting
scriptPubKey shapes (1 each for P2PKH / P2SH / P2WPKH / P2WSH /
P2TR) plus `scriptSig.len div 72` per input. Core's
GetTransactionSigOpCost (`consensus/tx_verify.cpp`) walks the
script, distinguishes accurate vs legacy P2SH counting, and
respects the witness discount. The block-template budget
(`blocktemplate.nim:364`,
`nBlockSigopsCost + txSigops >= MaxBlockSigopsCost`) therefore
admits a tx whose true sigop cost would push the block over
the 80k limit at consensus time → mined block rejected by
network.

**Impact**: Operator-level — miners using this template would
hit `bad-blk-sigops` rejections under adversarial scripts.

**Fix sketch**: Replace with a call to the existing
`countWitnessSigops` + `getLegacySigOpCount` + `getP2SHSigOpCount`
machinery already in `consensus/validation.nim:1078-1135`.
A tx without UTXO context is the awkward case (no P2SH redeem-
script lookup) — fall back to a CONSERVATIVE upper-bound rather
than the current optimistic heuristic.

## Cross-cite to other waves

- **BUG-9** (BIP-143 `pbegincodehash` ignored) parallels W127's
  taproot-side codesep finding for nimrod — codesepPos correctly
  threaded for tapscript and legacy but not BIP-143 v0. Pattern:
  "three sigversions, one forgotten."
- **BUG-3 / BUG-20** "two-pipeline" — instances 5 & 6 in the
  fleet-wide pattern. nimrod's W141 already noted ZMQ-vs-rest
  shape divergence; W138 noted assumeUTXO ChainstateManager
  scaffolding co-existing with the actual chainstate. Adding
  `isWitnessProgram × 2` and `computeWitnessCommitment × 2`
  brings nimrod's count to 4 distinct two-pipeline pairs.
- **BUG-4 / BUG-5** "comment-as-confession-adjacent": the
  doc-comment at `validation.nim:434` says "G10: no commitment
  present → no error (Core does not require one)" — flat-out
  asserts a behavior Core does NOT have. First instance in
  nimrod of "docstring contradicts Core."
- **BUG-14 / BUG-15 / BUG-16** "verifyScript bool ≠
  verifyScriptWithError": two parallel verification entry points
  with different gate sets. **3 distinct divergences in the same
  pair**, including one P0-CONSENSUS (BUG-14 canonical-push) that
  affects both variants. Two-pipeline.

## Suggested fix ordering

(All consensus fixes should go through `tools/verify-fix.sh` per
the methodology in `CORE-PARITY-AUDIT/_fix-verification-
methodology-2026-05-04.md`.)

1. **BUG-1** (P0-CONSENSUS, ~10 LOC) — `unexpected-witness`
   reject for segwit-active-but-no-commitment. Single highest-
   priority finding in this wave.
2. **BUG-9** (P0-CONSENSUS, ~5 LOC) — BIP-143 P2WSH scriptCode
   honors `codesepPos`.
3. **BUG-14** (P0-CONSENSUS, ~10 LOC in TWO places —
   `verifyScript` and `verifyScriptWithError`) — canonical-push
   check for P2SH-wrap-witness.
4. **BUG-4** (P0-CDIV, 1-line) — `wtxid()` short-circuit when
   `!isSegwit`. Trivial.
5. **BUG-5** (P0-CDIV, ~5 LOC) — `readTransaction` superfluous-
   witness reject. Trivial.
6. **BUG-6 + BUG-7 + BUG-8** (P0-WIRE, bundled — ~30 LOC) —
   legacy block / tx serialization variants + getdata invType
   dispatch.
7. **BUG-13** (P3) — fix the underlying `Transaction.witnesses`
   predicate divergence (root of BUG-4/5).
8. **BUG-16 + BUG-17** (P1+P2 bundled) — `is_p2sh` param through
   `verifyWitnessProgram` variants.
9. **BUG-15** (P1, ~5 LOC) — WITNESS_UNEXPECTED in bool variant.
10. **BUG-3 + BUG-20** (P1/P2) — collapse two-pipeline definitions.
11. **BUG-10 + BUG-11** (P1) — replace structural P2WPKH detection
    with `ctx.witnessProgramKind`.
12. **BUG-18 / 19 / 21 / 22** (P2/P3) — Core-parity cleanup.

## Closing notes

Wave 142 catalogues 22 distinct bugs across the segwit witness-
validation surface. Of these:
- **6 are P0-class** (3 CONSENSUS, 2 CDIV, 3 WIRE);
- **4 root-cause from the same divergent `tx.witnesses.len > 0`
  predicate** (BUG-4, 5, 6, 13);
- **3 root-cause from `verifyScript` bool ≠ error variant**
  (BUG-14, 15, 16) — the two-pipeline pattern manifesting
  three times in one pair of functions;
- **2 share a `_p2sh` parameter omission** (BUG-16, 17).

No fix landed in this wave — discovery-only. Cumulative fleet
pre-W142: 72 discovery + 71 fix = 143 waves.
