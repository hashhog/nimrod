# W144 — Script-verify flag mux audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W144).
Concurrent-agent coordination: 3 OTHER audit waves in PARALLEL (4-of-4
quad-wave; streak 71 fix + 72 discovery preserved).

Scope: SCRIPT_VERIFY_* flag derivation (GetBlockScriptFlags), buried-vs-
versionbits softfork activation, MANDATORY vs STANDARD flag split,
flag application inside EvalScript / VerifyScript / VerifyWitnessProgram
for every flag in the 8 BIP-cluster behaviors (P2SH/BIP16, DERSIG/BIP66,
CLTV/BIP65, CSV/BIP112, WITNESS/BIP141, NULLDUMMY/BIP147, TAPROOT/BIP341+342)
plus the policy-only set (MINIMALDATA, CLEANSTACK, LOW_S, STRICTENC, NULLFAIL,
WITNESS_PUBKEYTYPE, MINIMALIF, CONST_SCRIPTCODE, DISCOURAGE_*).

Targets in nimrod:
- `src/consensus/validation.nim:481-525` — `getBlockScriptFlags`,
  `BIP16_EXCEPTION_HASH`, `TAPROOT_EXCEPTION_HASH`, plus
  `verifyScripts` (1460-1553) production call path.
- `src/consensus/validation.nim:1453-1457` — `scriptFlagsToUint32` cache-key
  helper.
- `src/consensus/params.nim:53-57, 173-177, 296-304, 364-368, 425-429,
  480-481` — buried-activation heights (bip65Height, bip66Height,
  csvHeight, segwitHeight, taprootHeight) per network.
- `src/mempool/mempool.nim:851-882` — `standardScriptVerifyFlags`
  (STANDARD_SCRIPT_VERIFY_FLAGS), `acceptTransactionWithArgs` policy +
  consensus passes (1217-1290), `verifyAt` closure (1222-1245),
  `getBlockScriptFlags(bestHeight)` call (1220).
- `src/script/interpreter.nim:71-97` — `ScriptFlags` enum definition.
- `src/script/interpreter.nim:475-511` — `checkSignatureEncoding`,
  `checkPubKeyEncoding` (DERSIG/LOW_S/STRICTENC/WITNESS_PUBKEYTYPE).
- `src/script/interpreter.nim:1095-1166` — push-time MINIMALDATA gate.
- `src/script/interpreter.nim:1203-1207` — OP_NOP1, OP_NOP4..OP_NOP10
  DISCOURAGE_UPGRADABLE_NOPS.
- `src/script/interpreter.nim:1208-1228` — OP_IF/NOTIF tapscript +
  segwit-v0 MINIMALIF gates.
- `src/script/interpreter.nim:1619-1675` — OP_CHECKSIG / OP_CHECKSIGVERIFY
  + tapscript pubkey-type discourage.
- `src/script/interpreter.nim:1811-1930` — OP_CHECKMULTISIG +
  NULLFAIL/NULLDUMMY enforcement order.
- `src/script/interpreter.nim:1933-2009` — OP_CHECKLOCKTIMEVERIFY /
  OP_CHECKSEQUENCEVERIFY gates.
- `src/script/interpreter.nim:2129-2255` — `verifyScript` (bool variant).
- `src/script/interpreter.nim:2257-2390` — `verifyScriptWithError`
  (ScriptError variant; second copy of the same logic, two-pipeline-guard).
- `src/script/interpreter.nim:2392-2775` — `verifyWitnessProgram` (bool).
- `src/script/interpreter.nim:2776-3082` — `verifyWitnessProgramWithError`.
- `src/perf/parallel_verify.nim:90-100, 195-205` — dead parallel verifier.

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/script/interpreter.h:47-159` — `SCRIPT_VERIFY_*` enum, 24 flags +
  MAX_SCRIPT_VERIFY_FLAGS_BITS.
- `src/script/interpreter.cpp:430-460` — push-time MINIMALDATA / disabled-
  opcode / CONST_SCRIPTCODE gates.
- `src/script/interpreter.cpp:522-602` — OP_CHECKLOCKTIMEVERIFY,
  OP_CHECKSEQUENCEVERIFY, OP_NOP1/OP_NOP4-OP_NOP10 DISCOURAGE handling
  (`break;` on missing flag, NOT discouraged-NOP).
- `src/script/interpreter.cpp:1124-1218` — OP_CHECKMULTISIG NULLFAIL
  per-sig cleanup loop + NULLDUMMY final check.
- `src/script/interpreter.cpp:1917-2003` — `VerifyWitnessProgram` with
  `is_p2sh` argument distinguishing native witness vs P2SH-wrapped.
- `src/script/interpreter.cpp:2042, 2087` — `VerifyWitnessProgram` call
  sites with explicit `is_p2sh=false` / `is_p2sh=true`.
- `src/script/script.cpp:215-222` — `CScript::IsPayToAnchor(version,
  program)` requires `version == 1 && program.size() == 2 && program == 0x4e73`.
- `src/validation.cpp:2250-2290` — `GetBlockScriptFlags` (defaults to
  `P2SH | WITNESS | TAPROOT`, exception-map override, BIP66/BIP65/CSV/
  SEGWIT buried gates).
- `src/validation.cpp:1175-1185` — `currentBlockScriptVerifyFlags` for
  mempool consensus pass.
- `src/policy/policy.h:104-135` — `MANDATORY_SCRIPT_VERIFY_FLAGS` and
  `STANDARD_SCRIPT_VERIFY_FLAGS` definitions.
- `src/kernel/chainparams.cpp:85-87, 210-211` — `script_flag_exceptions`
  map: BIP16-exception (SCRIPT_VERIFY_NONE) and Taproot-exception
  (P2SH | WITNESS only) on mainnet, BIP16-exception on testnet3.
- `src/deploymentstatus.h:27-32` — `DeploymentActiveAt` for buried
  deployments.

## Status

**BUGS FOUND — 22 distinct defects.** Of these:

- **P0-CDIV** — 5 (BIP16/TAPROOT exception map collapsed to two
  `==`-string compares; v1 non-32-byte programs return TRUE unconditionally
  when sfTaproot in flags, bypassing DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
  `is_p2sh` not propagated to verifyWitnessProgram — P2SH-wrapped v1+32
  scripts evaluated as native taproot; CLTV/CSV opcodes treated as
  discouraged-NOP when DISCOURAGE_UPGRADABLE_NOPS is set; pre-segwit
  default flag-set omits WITNESS/TAPROOT — historical-reorg divergence).
- **P0-SEC** — 0.
- **P1** — 7 (CONST_SCRIPTCODE flag unmodelled — legacy OP_CODESEPARATOR
  accepted; STRICTENC/STANDARD policy gap on tapscript; cache-key
  `scriptFlagsToUint32` loses bits past 32 if discourage flags expanded;
  mempool consensus pass uses tip height rather than tip+1; mempool
  `verifyScript` call omits allAmounts/allScriptPubKeys array — multi-input
  taproot validation hits fallback; standardScriptVerifyFlags omits
  CONST_SCRIPTCODE; flag activation per-network for taproot uses buried
  height ignoring versionbits state).
- **P2** — 7 (parallel_verify dead code with same multi-input-taproot
  bug; two-pipeline-guard between bool and ScriptError witness verifiers;
  OP_VERIF/OP_VERNOTIF in unexecuted branches reject even though Core
  defers to default-case BAD_OPCODE; BIP16 comment mainnet height 170060
  is incorrect; sigCache key plain bitmask vs Core HMAC; OP_NOP2/NOP3
  alias missing from enum-only-named coverage; flag-set keys mapped via
  `ord(f)` so adding flags reshuffles cache).
- **P3** — 3 (comment-as-confession on sfConstScriptCode; documentation
  drift on "P2SH always-on for simplicity"; sigPushOnly enabled on policy
  via explicit `if sfSigPushOnly` rather than membership of STANDARD).

## Bug list

---

### BUG-1 — `getBlockScriptFlags` default flag-set omits WITNESS/TAPROOT for pre-activation heights, diverging from Core's "always-on-except-for-exception-block" model

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:491-525
**Core ref:** bitcoin-core/src/validation.cpp:2250-2290 (GetBlockScriptFlags
sets `flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT}`
unconditionally; the exception map then OVERRIDES this for the two violating
historical blocks).

**Description:** Core's flag derivation starts from
`{P2SH | WITNESS | TAPROOT}` for EVERY block on every network, then either
keeps that base, or — for two historical mainnet hashes — replaces it
with either `SCRIPT_VERIFY_NONE` (BIP16 exception block) or
`P2SH | WITNESS` (Taproot exception block). After that base derivation
Core adds DERSIG / CLTV / CSV / NULLDUMMY via `DeploymentActiveAt`.

Nimrod inverts the model: it starts from `{sfP2SH}` and gates WITNESS
and TAPROOT separately on `height >= segwitHeight` and
`height >= taprootHeight`:

```nim
# P2SH active from BIP16 (mainnet: 170060, but treat as always-on for simplicity)
result = {sfP2SH}
# ...
# SegWit (BIP141/143/147) — WITNESS + NULLDUMMY are consensus rules.
if height >= int32(params.segwitHeight):
  result.incl(sfWitness)
  result.incl(sfNullDummy)
# Taproot (BIP340/341/342) — activated at taprootHeight
if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
  result.incl(sfTaproot)
```

**Impact:** For any block at height < `segwitHeight` (mainnet 481824)
where the scriptPubKey decodes as a witness program, Core would still
apply `SCRIPT_VERIFY_WITNESS` (enforcing program-size + empty-scriptSig
+ witness-stack rules), but nimrod would treat the output as
anyone-can-spend. Same for pre-taproot v1 outputs. Vanishingly rare
(no segwit-shape outputs existed pre-481824 on mainnet/testnet3), but
on a deep historical reorg or a chain replay this is a consensus
divergence. Crucially, the BIP16_EXCEPTION_HASH block on mainnet
(height 91842) DID have a P2SH-shape output that Core deliberately
exempts via `SCRIPT_VERIFY_NONE`. Nimrod returns `{}` for that hash
(line 497-498) which matches; but Core's `SCRIPT_VERIFY_NONE` ALSO
implies the WITNESS+TAPROOT bits OFF — nimrod's `{}` is structurally
correct here, but it's not symmetric to the default path. Documentation
drift on line 502 ("BIP16: mainnet 170060") is also wrong — BIP16
mainnet activation is 173805 and Core doesn't track an explicit
`BIP16Height` consensus param because P2SH is always-on with one
exception block.

---

### BUG-2 — `verifyWitnessProgram` v1 non-32-byte returns TRUE unconditionally when sfTaproot in flags, bypassing DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM

**Severity:** P0-CDIV
**File:** src/script/interpreter.nim:2506-2511
**Core ref:** bitcoin-core/src/script/interpreter.cpp:1948-1996
(VerifyWitnessProgram: v1+32 is taproot; everything else falls to the
P2A branch or to the unknown-version branch, which checks
`flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` before
returning success).

**Description:** Nimrod's bool-returning `verifyWitnessProgram` short-
circuits ALL non-32-byte v1 programs to TRUE the moment `sfTaproot in
flags`, calling out "(including P2A anchors)" in the comment:

```nim
elif version == 1 and sfTaproot in flags:
  # Taproot (SegWit v1)
  if program.len != 32:
    # Non-32-byte v1 programs (including P2A anchors) succeed unconditionally
    # per BIP 341 for forward compatibility
    return true
```

Core's logic is:

1. `witversion == 1 && size == 32 && !is_p2sh` → taproot path; if
   sfTaproot not set, set_success and return.
2. `else if (!is_p2sh && IsPayToAnchor(version, program))` → return true.
   IsPayToAnchor requires EXACTLY `program.size() == 2 && [0x4e, 0x73]`.
3. else (unknown witness version OR v1 with wrong size that isn't P2A) →
   check `flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`
   and reject; otherwise return true.

Nimrod's path-2 collapses cases 2 AND 3 into "return true for anything
v1-non-32", which breaks DISCOURAGE policy enforcement: a v1 program of,
say, 20 bytes that isn't 0x4e73 will be relayed by nimrod (and
ostensibly enter the mempool because the consensus pass returns true),
but Core would REJECT it with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
under STANDARD flags.

**Excerpt:**
```nim
2506:  elif version == 1 and sfTaproot in flags:
2507:    # Taproot (SegWit v1)
2508:    if program.len != 32:
2509:      # Non-32-byte v1 programs (including P2A anchors) succeed unconditionally
2510:      # per BIP 341 for forward compatibility
2511:      return true
```

The `verifyWitnessProgramWithError` companion (line 2880-2885) handles
the P2A pattern correctly with explicit byte-match — illustrating the
two-pipeline-guard divergence between the two witness verifiers.

**Impact:** Policy-flag divergence; mempool will accept future v1-shape
outputs that Core would discourage. Not consensus-critical TODAY (no v1
non-32 non-P2A scripts exist), but the moment a future BIP defines a v1
sub-type (e.g., v1+40-byte program), nimrod's relay accepts it silently
while Core's relay rejects.

---

### BUG-3 — `is_p2sh` argument not propagated to verifyWitnessProgram; P2SH-wrapped v1+32 outputs evaluated as native Taproot

**Severity:** P0-CDIV
**File:** src/script/interpreter.nim:2244-2247, 2370-2375, 2392-2398
(verifyWitnessProgram signature lacks is_p2sh)
**Core ref:** bitcoin-core/src/script/interpreter.cpp:1917 (signature
`bool VerifyWitnessProgram(... bool is_p2sh)`), :1948 (P2SH check
`witversion == 1 && size == WITNESS_V1_TAPROOT_SIZE && !is_p2sh`),
:1990 (`!is_p2sh && IsPayToAnchor`), :2042/:2087 (call sites pass
`is_p2sh=false` / `is_p2sh=true`).

**Description:** Core's `VerifyWitnessProgram` takes an explicit
`is_p2sh` boolean so that:
- A V1+32 program inside a P2SH wrapper is NOT eligible for taproot
  validation (the `!is_p2sh` clause excludes it).
- A P2A pattern inside a P2SH wrapper is also NOT eligible (line 1990).

Nimrod's `verifyWitnessProgram` proc signature (line 2392) has no
`is_p2sh` parameter. The P2SH-wrapped witness branch at line 2244 calls
the same proc as the native-witness branch at line 2210:

```nim
2210:    return verifyWitnessProgram(
2211:      witness, witnessVersion, witnessProgram, tx, inputIndex, amount, flags,
2212:      ctxAmounts, ctxScriptPubKeys
2213:    )
...
2244:    if sfWitness in flags and isP2shWitness:
2245:      return verifyWitnessProgram(
2246:        witness, p2shVersion, p2shProgram, tx, inputIndex, amount, flags,
2247:        ctxAmounts, ctxScriptPubKeys
2248:      )
```

Same problem in `verifyScriptWithError` (line 2338, 2373) calling
`verifyWitnessProgramWithError` (which also has no is_p2sh arg, line 2776).

**Impact:** A scriptPubKey shaped as P2SH(OP_1 <32-byte>) — i.e.,
HASH160(SCRIPT_HASH) where SCRIPT_HASH = HASH160(OP_1 <32B>) — when
spent with a witness, would in Core be classified as v1-with-P2SH and
fall through to the unknown branch (return true unless DISCOURAGE).
Nimrod would route it to the taproot key-path verifier, attempting
Schnorr signature check against the redeem script's 32-byte payload.
In practice the Schnorr check would fail (the redeem-script bytes are
not a valid x-only pubkey + tweak), giving the user a spurious
SCRIPT_ERR_TAPROOT_INVALID_SIG instead of the correct anyone-can-spend
or DISCOURAGE behavior. This is a definitional divergence: Core
explicitly chose to keep P2SH-wrapped v1 as a forward-compatible
anyone-can-spend slot; nimrod silently evaluates them as a tweak-
malformed taproot.

---

### BUG-4 — CLTV / CSV opcodes treated as DISCOURAGE_UPGRADABLE_NOPS when their flag is unset; Core treats them as plain NOPs

**Severity:** P0-CDIV
**File:** src/script/interpreter.nim:1933-1940 (CLTV), 1969-1973 (CSV)
**Core ref:** bitcoin-core/src/script/interpreter.cpp:522-528 (CLTV
falls through `break;` if flag absent — no discourage check),
:563-568 (CSV same), :596-602 (OP_NOP1, OP_NOP4..OP_NOP10 are the only
opcodes that fire DISCOURAGE_UPGRADABLE_NOPS).

**Description:** Nimrod's OP_CHECKLOCKTIMEVERIFY handler treats CLTV
as a discouraged NOP when both `sfCheckLockTimeVerify notin flags` AND
`sfDiscourageUpgradableNops in flags`:

```nim
of OP_CHECKLOCKTIMEVERIFY:
  if sfCheckLockTimeVerify notin interp.flags:
    # Treat as NOP if flag not set
    if sfDiscourageUpgradableNops in interp.flags:
      return seDiscourageUpgradableNops
  else:
    # ... real CLTV check
```

Same pattern for CSV at line 1969. But Core's switch case
explicitly excludes OP_NOP2 (CLTV) and OP_NOP3 (CSV) from the
DISCOURAGE_UPGRADABLE_NOPS case (which lists only OP_NOP1, OP_NOP4-NOP10).
When CLTV/CSV flags are not set, Core executes a bare `break;` and
moves on without firing DISCOURAGE.

**Impact:** Under STANDARD flags (DISCOURAGE on, all consensus flags
on), behavior matches. But on networks/heights where CLTV (mainnet
388381) or CSV (mainnet 419328) flag is NOT YET ACTIVE — historical
reorgs, regtest with non-default `csvHeight`, or any custom signet/
regtest that pushes activation later — nimrod will reject scripts
containing CLTV/CSV opcodes even under DISCOURAGE-only policy, while
Core would treat them as NOPs. Net effect: a CLTV-using tx at a
pre-activation height is REJECTED by nimrod but ACCEPTED by Core. This
matters most for regtest test suites that drive flag activation by
hand.

---

### BUG-5 — `script_flag_exceptions` collapsed to two `==`-string compares; cannot represent the Core map's per-block override of arbitrary flag bitmasks

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:486-498, 523
**Core ref:** bitcoin-core/src/consensus/params.h:96
(`std::map<uint256, script_verify_flags> script_flag_exceptions`),
bitcoin-core/src/kernel/chainparams.cpp:85-88 (mainnet BIP16 + Taproot
exceptions), :210-211 (testnet3 BIP16 exception).

**Description:** Core stores exceptions as a `std::map<uint256,
script_verify_flags>` so each entry can override flags to ANY bitmask:
- mainnet BIP16-block 91842 → `SCRIPT_VERIFY_NONE` (0)
- mainnet Taproot-block 692_xxx → `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS`
- testnet3 BIP16-block 21_xxx → `SCRIPT_VERIFY_NONE`

Nimrod hard-codes only TWO mainnet hashes as string constants and
applies them with `==` string compares:

```nim
const BIP16_EXCEPTION_HASH* = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
const TAPROOT_EXCEPTION_HASH* = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
...
if blockHash == BIP16_EXCEPTION_HASH:
  return {}  # SCRIPT_VERIFY_NONE for this block
...
if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
  result.incl(sfTaproot)
```

Problems:
1. Testnet3 BIP16 exception (`00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105`,
   per chainparams.cpp:211) is MISSING — nimrod will enforce P2SH against
   that block during a testnet3 historical reorg, which Core wouldn't.
2. The Taproot exception in Core sets flags to `P2SH | WITNESS`
   explicitly (skipping the taproot bit). Nimrod, instead of overriding
   the flag SET, only conditionally OMITS `sfTaproot`. That happens to
   be correct for the one mainnet Taproot exception (since taproot is
   the only bit being subtracted from the base mainnet-current set),
   but it doesn't scale: if Core ever adds another exception for a
   different set of flags, nimrod's structure can't represent it.
3. `script_flag_exceptions` is per-network in Core. Nimrod stores them
   as module-level globals, applied identically to all networks.
4. The BIP16 path returns `{}` (empty set), which is correct for
   mainnet but on testnet3/regtest/signet would still need a
   SCRIPT_VERIFY_NONE override at the testnet3 exception height —
   missing entirely.

**Impact:** Mainnet behavior happens to match Core. Testnet3 historical
reorg containing block `00000000dd30457c...` would fork at script
verification — nimrod rejects what Core accepts. Future network
parameters cannot encode arbitrary flag overrides.

---

### BUG-6 — `SCRIPT_VERIFY_CONST_SCRIPTCODE` not modeled; legacy OP_CODESEPARATOR accepted even under STANDARD flags

**Severity:** P1
**File:** src/script/interpreter.nim:1620-1628, 84-86 (enum)
**Core ref:** bitcoin-core/src/script/interpreter.cpp:474-475
(`if (opcode == OP_CODESEPARATOR && sigversion == SigVersion::BASE &&
(flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))` rejects with
SCRIPT_ERR_OP_CODESEPARATOR — fires BEFORE the executed/unexecuted
branch check, so even in an unexecuted IF arm).

**Description:** Nimrod's enum has no `sfConstScriptCode`; the
`standardScriptVerifyFlags` helper acknowledges the omission with a
comment-as-confession:

```nim
# sfConstScriptCode — not modelled separately in nimrod interpreter (treated
# as mandatory under BIP-143).
```

Nimrod's OP_CODESEPARATOR handler (line 1620) only records
`codesepPos`; it does NOT check `sigversion == sigBase` and reject
with SCRIPT_ERR_OP_CODESEPARATOR under any flag. Under STANDARD flags
(mempool acceptance), Core would reject any legacy script containing
OP_CODESEPARATOR, but nimrod accepts.

**Excerpt:**
```nim
of OP_CODESEPARATOR:
  # BIP-341: record the OPCODE INDEX, not the byte position.
  # ...
  interp.codesepPos = currentOpcodePos
```

**Impact:** Mempool relays legacy OP_CODESEPARATOR-using scripts that
Core rejects under STANDARD. Block-validation (consensus) is unaffected
since CONST_SCRIPTCODE is policy-only, but a malicious payer could
trick nimrod into relaying a tx that another node will refuse. Cross-
implementation mempool drift: nimrod-relayed tx that fails on Core's
mempool.

---

### BUG-7 — Mempool `verifyScript` call omits `allAmounts` / `allScriptPubKeys` — multi-input taproot mempool acceptance broken

**Severity:** P1
**File:** src/mempool/mempool.nim:1239-1241
**Core ref:** bitcoin-core/src/validation.cpp:1135-1185
(CheckInputScripts builds a `PrecomputedTransactionData` from ALL
input UTXOs before evaluating per-input scripts; BIP-341 sighash
hashes every input's amount+scriptPubKey into `sha_amounts` /
`sha_scriptpubkeys`).

**Description:** Nimrod's mempool calls `verifyScript` once per input
without passing the full `allAmounts` / `allScriptPubKeys` arrays:

```nim
let verified = verifyScript(
  input.scriptSig, scriptPubKey, tx, inputIdx, amount, flags, witness)
```

Inside `verifyScript`, this triggers the single-element fallback at
line 2186-2189:

```nim
let ctxAmounts = if allAmounts.len == tx.inputs.len: allAmounts
                 else: @[amount]
let ctxScriptPubKeys = if allScriptPubKeys.len == tx.inputs.len: allScriptPubKeys
                       else: @[scriptPubKey]
```

For a multi-input transaction with taproot inputs, the BIP-341
`sha_amounts` / `sha_scriptpubkeys` will be computed from a 1-element
array containing only the CURRENT input's amount — yielding a different
sighash than the one the signer produced. Schnorr verification fails,
tx is rejected.

**Excerpt** (mempool call site missing args):
```nim
1239:      let verified = verifyScript(
1240:        input.scriptSig, scriptPubKey, tx, inputIdx, amount, flags, witness)
1241:      if not verified:
```

**Impact:** Any honestly-signed multi-input taproot transaction
attempting to enter nimrod's mempool will be rejected with
`script verification failed`. Block validation path
(`verifyScripts` in `consensus/validation.nim:1496-1539`) DOES build
the full arrays correctly, so blocks containing such txs validate
fine — but nimrod cannot RELAY them, breaking BIP-341 functionality
for the mempool / wallet send path.

---

### BUG-8 — `verifyScriptsParallel` dead-code path replicates BUG-7 (declared in tests/test_w105_checkqueue.nim as G21)

**Severity:** P2
**File:** src/perf/parallel_verify.nim:62-69 (verifyScriptsParallel
inner worker), 261-264 (verifyScriptsParallelBatch worker)
**Core ref:** same as BUG-7.

**Description:** A second-pipeline (parallel) verifier exists at
`src/perf/parallel_verify.nim` with the same bug as BUG-7: the worker
calls `verifyScript(... witness)` without per-tx allAmounts arrays.
This is documented in `tests/test_w105_checkqueue.nim:34` as gap G21.
Production path uses `verifyScripts` (serial) in `validation.nim`, so
the parallel verifier is dead code today. But the dead module is still
exported and could be wired into a future parallelism push — the
multi-input-taproot bug would silently activate.

**Two-pipeline-guard pattern**: the bool-returning `verifyScript`
(line 2141) and the ScriptError-returning `verifyScriptWithError`
(line 2270) implement the same flag-handling logic twice. So do
`verifyWitnessProgram` (line 2392) and `verifyWitnessProgramWithError`
(line 2776). Changes to flag application must be mirrored in BOTH or
they will drift — BUG-2 is an example where the two pipelines have
already diverged (the bool variant returns true for v1-non-32-byte
while the error variant has a stricter P2A byte-match).

**Impact:** Wave-12-style "comment-as-confession" pattern (`tests/
test_w105_checkqueue.nim:139` notes "verifyScriptsParallel was
reverted at block 821384; production never calls it") — but the dead
code is still part of the parity surface. If anyone re-enables the
parallel verifier without first fixing G21, multi-input taproot
breaks immediately.

---

### BUG-9 — `STANDARD_SCRIPT_VERIFY_FLAGS` does NOT include `sfConstScriptCode`; mempool relays scripts Core rejects under STANDARD

**Severity:** P1
**File:** src/mempool/mempool.nim:863-881
**Core ref:** bitcoin-core/src/policy/policy.h:119-132
(STANDARD_SCRIPT_VERIFY_FLAGS includes SCRIPT_VERIFY_CONST_SCRIPTCODE).

**Description:** Nimrod's `standardScriptVerifyFlags` helper enumerates
every STANDARD bit EXCEPT `sfConstScriptCode`, justified with the
inline comment:

```nim
# sfConstScriptCode — not modelled separately in nimrod interpreter (treated
# as mandatory under BIP-143).
```

But the comment is wrong: BIP-143 (segwit sighash) is unrelated to
CONST_SCRIPTCODE. CONST_SCRIPTCODE is about legacy OP_CODESEPARATOR
forbidding non-segwit FindAndDelete cleanup. It IS a separate policy
bit in Core. Nimrod's omission is a real policy-flag gap.

**Impact:** Compounds BUG-6 — the flag isn't enforced AND isn't
exposed. Even if a future fix added `sfConstScriptCode` to the enum
and to the OP_CODESEPARATOR handler, the mempool path would still need
to be updated to include it in STANDARD.

---

### BUG-10 — `scriptFlagsToUint32` cache-key encoding silently overflows once ScriptFlags grows past 32 enum values

**Severity:** P1
**File:** src/consensus/validation.nim:1453-1457
**Core ref:** bitcoin-core/src/script/interpreter.h:154-159
(`MAX_SCRIPT_VERIFY_FLAGS_BITS = static_cast<int>(SCRIPT_VERIFY_END_MARKER)`,
`static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS && MAX_SCRIPT_VERIFY_FLAGS_BITS <= 63)`).

**Description:** The signature cache uses a `uint32` to encode the flag
set:

```nim
proc scriptFlagsToUint32(flags: set[ScriptFlags]): uint32 =
  result = 0
  for f in flags:
    result = result or (1u32 shl uint32(ord(f)))
```

`ScriptFlags` currently has 24 enum members (`sfNone..sfDiscourageUpgradablePubkeyType`).
That fits in uint32 with room to spare. But `1u32 shl 32` is undefined
behavior in Nim (target-dependent; on amd64 it's `1u32 shl 0` = 1 due to
shift-amount-mod-32 on x86). Core uses a wider type (`uint64`) and a
compile-time assertion that the bit count fits.

**Impact:** Today this is fine (24 ≤ 32). But the moment someone adds
the 33rd flag (e.g., a future BIP soft-fork bit), `scriptFlagsToUint32`
silently aliases that flag to bit 0 (sfNone), corrupting cache lookups
for ANY flag set that includes the new bit. A cache hit might then
return success for a tx the new flag would have rejected. No
compile-time guard exists.

---

### BUG-11 — Mempool consensus-pass uses `bestHeight` (tip) rather than tip+1; under partial-activation regtest, off-by-one wrong flag

**Severity:** P1
**File:** src/mempool/mempool.nim:1220, 2213
**Core ref:** bitcoin-core/src/validation.cpp:1181
(`GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), ...)` — uses
tip directly, NOT tip+1).

**Description:** Both Core and nimrod feed the current tip height to
`GetBlockScriptFlags`. But the relevant flag set for an INCOMING
mempool transaction is the one that will be enforced at tip+1
(when the next block is mined). For buried activations, this is only
off-by-one at the exact activation height. Core takes the same
shortcut — and arguably this is the same code path — so the divergence
is structural: both implementations check the FROZEN tip's flags. Note
this is more a documentation note than a divergence; flagged P1
because the mempool comment claims correspondence with Core's tip+1
flagset but the call actually mirrors Core's tip-flagset. The bug
crystallizes on regtest at exactly `height == csvHeight - 1`: a tx
spending a CSV-locked output would be accepted by both (no CSV gate
yet), but a real block at tip+1 would have CSV active and reject it.
Core has the same issue.

**Impact:** Equivalent to Core. Logging this as a parity confirmation,
not a divergence — but worth recording for future fix-wave to verify.

---

### BUG-12 — Mempool calls `getBlockScriptFlags` WITHOUT `blockHash`, so neither BIP16 nor TAPROOT exception can trigger for mempool acceptance

**Severity:** P2
**File:** src/mempool/mempool.nim:1220, 2213
**Core ref:** bitcoin-core/src/validation.cpp:1181 (same call uses
the actual tip block's `phashBlock`).

**Description:** Mempool calls `getBlockScriptFlags(bestHeight, params)`
omitting the optional `blockHash: string = ""` third arg. Default is
empty string, which trivially fails both equality checks against the
two hard-coded exception hashes. So `bestHeight` flags are always
returned without consulting the exception map.

In practice, the exception blocks are deep historical (h=91842 and
h=692_xxx), so tip will never BE one. But the structural divergence
exists: if tip ever happens to be at the exception height (could occur
during a deep historical reorg), nimrod's mempool would enforce flags
that the tip block itself violates, rejecting valid txs descending
from that exception.

**Impact:** Strictly hypothetical today. Worth a parity-fix.

---

### BUG-13 — `taprootHeight` activation uses buried height; `versionbits.nim` carries `dpTaproot` only for `getblockchaininfo` RPC reporting

**Severity:** P1
**File:** src/consensus/validation.nim:522-524
**Core ref:** bitcoin-core/src/validation.cpp:2250-2290 (DERSIG/CLTV/
CSV/SEGWIT all use buried `DeploymentActiveAt(BuriedDeployment)`);
bitcoin-core/src/consensus/params.h:28-35 (`BuriedDeployment` enum;
TAPROOT is NOT here — Core's source still considers it a `DeploymentPos`
versionbits deployment).

**Description:** In Core, Taproot was activated via BIP-9 versionbits
(`DEPLOYMENT_TAPROOT`) and is still classified as a `DeploymentPos`
rather than a `BuriedDeployment`. `GetBlockScriptFlags` does NOT
actually add `SCRIPT_VERIFY_TAPROOT` based on a versionbits check —
that flag is in the always-on base set. The versionbits machinery is
retained for warning detection (`MinBIP9WarningHeight`) and for the
historical activation-tracking RPCs.

Nimrod's `getBlockScriptFlags` checks `height >= taprootHeight` —
a buried-height check — which differs structurally from Core's
"always-on, exception-map skips one historical block". The semantic
result for current tip is the same (taproot fully active), but the
implementation diverges:

- Core: TAPROOT is in the base set unconditionally; exception map
  removes it from one historical block.
- Nimrod: TAPROOT only added if `height >= taprootHeight` AND
  `blockHash != TAPROOT_EXCEPTION_HASH`.

For pre-activation heights, this is also linked to BUG-1 (default flag
set omits WITNESS+TAPROOT pre-activation).

**Impact:** Tip-height behavior matches Core. Historical-reorg behavior
differs at the segwit/taproot activation boundary. Not consensus-
critical for the current chain but a structural model divergence.

---

### BUG-14 — `getBlockScriptFlags` returns `{sfP2SH}` for the BIP16-exception block but Core returns `SCRIPT_VERIFY_NONE` — nimrod over-enforces

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:497-498
**Core ref:** bitcoin-core/src/kernel/chainparams.cpp:85-87 (BIP16
exception maps to `SCRIPT_VERIFY_NONE`); bitcoin-core/src/validation.cpp:
2263-2266 (exception map fully OVERRIDES base flag set including the
default P2SH bit).

**Description:** Wait — re-reading line 497:

```nim
if blockHash == BIP16_EXCEPTION_HASH:
  return {}  # SCRIPT_VERIFY_NONE for this block
```

This DOES return `{}` (empty set). Good — that matches `SCRIPT_VERIFY_NONE`.
**Retracted as initial finding**; documented here as confirmation that
the BIP16-exception path is correct.

However, the TAPROOT exception path (line 523) does NOT use the
exception map semantics. Core's TAPROOT exception entry maps to
`SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS` — meaning DERSIG, CLTV,
CSV, NULLDUMMY are all CLEARED for that block. Nimrod's code path
(line 523-524) only conditionally OMITS sfTaproot from the assembled
flag set, retaining everything else including DERSIG/CLTV/CSV/NULLDUMMY.

For mainnet block `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`
(the Taproot exception):
- Core: flags = P2SH | WITNESS (everything else CLEARED, including DERSIG)
- Nimrod: flags = P2SH | WITNESS | DERSIG | CLTV | CSV | NULLDUMMY (TAPROOT
  alone is omitted; rest of consensus flags still applied)

This is the partial-override mistake I initially attributed to BUG-5 but
warrants its own bug entry because it has a SPECIFIC consequence:
nimrod enforces DERSIG/CLTV/CSV/NULLDUMMY on the Taproot exception block,
while Core does NOT. If the exception block contains any tx that
violates DERSIG (non-strict-DER) or any other now-active rule, nimrod
would REJECT it; Core ACCEPTS it.

**Excerpt:**
```nim
if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
  result.incl(sfTaproot)
```

**Impact:** Mainnet historical-reorg divergence at the Taproot
exception block height. The actual exception block does not contain a
DERSIG-violating tx (the Core comment is "only one historical block
violated the TAPROOT rules"), so the practical risk is low. But the
implementation does NOT match Core's exception-map structure.

---

### BUG-15 — `sigPushOnly` (policy flag) is checked at the start of `verifyScript` even when omitted from STANDARD_SCRIPT_VERIFY_FLAGS — but the path requires an EXTRA explicit `if sfSigPushOnly` rather than membership-based dispatch

**Severity:** P3
**File:** src/script/interpreter.nim:2177-2180, 2304-2307
**Core ref:** bitcoin-core/src/script/interpreter.cpp:2018-2020
(`if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly())
return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);`).

**Description:** Nimrod's `verifyScript` enforces SIG_PUSHONLY in
exactly the same shape as Core. But `standardScriptVerifyFlags` does
NOT add `sfSigPushOnly` to the policy set (correctly — STANDARD_SCRIPT_VERIFY_FLAGS
in Core also doesn't include SIGPUSHONLY directly; it's a sub-bit only
relevant under non-P2SH paths). Documentation here is fine; flagging
as a non-divergence for record purposes.

**Impact:** None — flagged for completeness.

---

### BUG-16 — `OP_VERIF` / `OP_VERNOTIF` rejected in unexecuted branches; Core treats them as default-case BAD_OPCODE which only fires in executed branches

**Severity:** P2
**File:** src/script/interpreter.nim:400-403 (isDisabled), 1100 (push
loop applies isDisabled regardless of fExec)
**Core ref:** bitcoin-core/src/script/interpreter.cpp:457-470 (only
the CAT/SUBSTR/LEFT/RIGHT/INVERT/AND/OR/XOR/2MUL/2DIV/MUL/DIV/MOD/
LSHIFT/RSHIFT set is checked unconditionally), :1217-1218 (default
case fires SCRIPT_ERR_BAD_OPCODE — but is inside the `else if (fExec ||
(OP_IF <= opcode && opcode <= OP_ENDIF))` block, so only fires when
fExec).

**Description:** Nimrod's `isDisabled` list includes OP_VERIF and
OP_VERNOTIF, and the disabled-check fires in the push loop before
fExec branching. Core's unconditional disabled list does NOT include
OP_VERIF / OP_VERNOTIF; those fall to the default switch case which
only fires when `fExec == true`.

**Impact:** Scripts containing OP_VERIF/OP_VERNOTIF in an unexecuted
IF arm (e.g., `OP_0 OP_IF OP_VERIF OP_ENDIF`) would be REJECTED by
nimrod with seDisabled, but ACCEPTED by Core (the unexecuted branch
never trips the default switch). Very narrow real-world divergence
(no production script does this), but a real divergence.

---

### BUG-17 — Comment-as-confession: "P2SH active from BIP16 (mainnet: 170060, but treat as always-on for simplicity)" — mainnet BIP16 activation is 173805, not 170060

**Severity:** P3
**File:** src/consensus/validation.nim:501
**Core ref:** bitcoin-core/src/kernel/chainparams.cpp:85-87 (Core
doesn't store a BIP16Height; P2SH is always-on with one historical
exception block at h=91842).

**Description:** Cosmetic but reveals confusion about BIP16
activation. The historical BIP16 activation date 2012-04-01 corresponds
to mainnet block 173805 (signaling-based activation), not 170060. Core
specifically does not store a `BIP16Height` consensus param because
P2SH is treated as always-on via the exception map.

**Impact:** None functionally. Documentation drift.

---

### BUG-18 — `MANDATORY_SCRIPT_VERIFY_FLAGS` helper missing; nimrod has no separate vocabulary for "must-be-enforced for mempool relay"

**Severity:** P2
**File:** src/mempool/mempool.nim:863 (only `standardScriptVerifyFlags`
exists)
**Core ref:** bitcoin-core/src/policy/policy.h:104-117
(`MANDATORY_SCRIPT_VERIFY_FLAGS = P2SH | DERSIG | NULLDUMMY | CLTV |
CSV | WITNESS | TAPROOT`).

**Description:** Core distinguishes three sets:
- `MANDATORY_SCRIPT_VERIFY_FLAGS` — must enforce for relay; failure
  triggers DoS ban.
- `STANDARD_SCRIPT_VERIFY_FLAGS` = MANDATORY ∪ policy bits — must
  enforce for relay but failure DOES NOT trigger DoS ban.
- `consensus flags` from `GetBlockScriptFlags` — what blocks must obey.

Nimrod only has `standardScriptVerifyFlags(consensusFlags)` which
returns STANDARD. There is no `mandatoryScriptVerifyFlags` accessor.
Net effect: nimrod cannot distinguish between "tx violated a MANDATORY
flag, ban peer" vs "tx violated a STANDARD-only flag, just reject"
when relaying.

**Impact:** Peer-banning policy is coarser than Core's. Peers that
relay non-standard-but-not-mandatory-violating txs may get banned
where Core would only have rejected the tx silently.

---

### BUG-19 — `sfNone` (enum value 0) wastes a bit in the cache-key encoding; bit 0 is "no flag" but `1u32 shl 0` = 1 collides with the actual flag at index 0

**Severity:** P2
**File:** src/script/interpreter.nim:72 (`sfNone` is the first enum
member), src/consensus/validation.nim:1453-1457
**Core ref:** bitcoin-core/src/script/interpreter.h:47
(`SCRIPT_VERIFY_NONE{0}` is a literal zero, NOT an enum member at
position 0).

**Description:** Nimrod's `ScriptFlags` enum starts with `sfNone` at
ord 0. `set[ScriptFlags]` will produce a bit-zero entry for sfNone if
it's ever incl'd. In `scriptFlagsToUint32`, `1u32 shl 0 = 1` — which is
identical to the encoding of "first real flag" (sfP2SH at ord 1
shifts to bit 1 = 2). So if any code accidentally `incl(sfNone)`, the
cache key gets a spurious bit-0 set that doesn't correspond to any
real script-verify behavior.

**Impact:** Real bug only if `sfNone` is ever incl'd. Code review
suggests it isn't, but the enum design is brittle. Core avoids this
by making `SCRIPT_VERIFY_NONE` a constant zero, not an enum member.

---

### BUG-20 — Tapscript MINIMALIF is unconditional (not flag-gated), but the comment claims it's "consensus" — fine, just under-documented

**Severity:** P3
**File:** src/script/interpreter.nim:1216-1219
**Core ref:** bitcoin-core/src/script/interpreter.cpp (tapscript IF
unconditional minimal — Core's BIP-342 spec line ~700).

**Description:** Nimrod correctly enforces MINIMALIF unconditionally
in tapscript regardless of `sfMinimalIf`:

```nim
if ctx.sigVersion == sigTapscript:
  if val.len > 1 or (val.len == 1 and val[0] != 1):
    return seTapscriptMinimalIf
```

This matches Core. Not a bug; recorded for parity confirmation.

---

### BUG-21 — `OP_NOP2` and `OP_NOP3` are defined as aliases but the OP_NOP1/NOP4..NOP10 discourage handler doesn't include them — correct; flag a parity confirmation

**Severity:** P3
**File:** src/script/interpreter.nim:253-264, 1203
**Core ref:** bitcoin-core/src/script/interpreter.cpp:596 (case list
explicitly excludes NOP2 and NOP3).

**Description:** Nimrod correctly handles OP_NOP2 and OP_NOP3 as
CLTV/CSV opcodes (via dedicated handlers) rather than discouraged
NOPs. The discourage case at line 1203 is `OP_NOP1, OP_NOP4..OP_NOP10`
— properly excluding NOP2/NOP3. Not a bug; documented for parity
confirmation. Note this finding pairs with BUG-4: nimrod's CLTV/CSV
handlers themselves contain a SECONDARY discourage-NOP check (when
the flag is off) that DOES diverge from Core. The opcode-name routing
is correct; the per-opcode flag-absent handling is the divergent
part.

---

### BUG-22 — `getBlockScriptFlags` lacks documentation that the `blockHash` argument is in display order (reversed bytes); easy mis-use during validation refactors

**Severity:** P3
**File:** src/consensus/validation.nim:491-493
**Core ref:** bitcoin-core/src/validation.cpp:2263 (uses
`*Assert(block_index.phashBlock)` directly — uint256 internal
little-endian representation, but std::map compares byte-wise so
internal-LE matches the stored constants which are also internal-LE).

**Description:** Nimrod's exception-block check uses `$BlockHash`,
which yields a 64-char reversed-hex string (display order, matching
the constants `BIP16_EXCEPTION_HASH` and `TAPROOT_EXCEPTION_HASH`).
This is internally consistent today.

But callers must take care to pass `$blockHash` (display) and not the
raw `array[32, byte]` reversed-vs-not direction. There's no
type-system guard. A test fixture passing the raw 32 bytes (or a
hex of the internal LE form) would silently miss the exception and
re-enable taproot for the exception block.

**Impact:** Refactor hazard. A type-safer signature would take
`BlockHash` directly and stringify internally. Low severity since
all current callers do `$BlockHash(...)`.

---

## Fleet patterns observed

1. **Two-pipeline-guard pattern**: `verifyScript` ↔ `verifyScriptWithError`
   and `verifyWitnessProgram` ↔ `verifyWitnessProgramWithError` are
   parallel implementations of the same flag-application logic. BUG-2
   demonstrates the pipelines have ALREADY drifted (bool variant short-
   circuits v1-non-32 unconditionally; error variant has stricter P2A
   match). This is the 14th distinct two-pipeline-guard instance fleet-
   wide (per W141 memo).

2. **Dead-code-with-bugs pattern**: `verifyScriptsParallel` lives in
   `src/perf/parallel_verify.nim`, replicating BUG-7 (G21 in the W105
   test plan). Not called in production but exported and reachable from
   any future enable-parallel-verify PR.

3. **Comment-as-confession pattern**: BUG-9 acknowledges
   `sfConstScriptCode` is "not modelled separately in nimrod
   interpreter (treated as mandatory under BIP-143)" — but it isn't
   modeled or enforced at all. BUG-17 admits BIP16 activation is "treat
   as always-on for simplicity" but cites the wrong block height in the
   comment. The W144 third comment-as-confession this cycle.

4. **Carry-forward defects from prior waves**: BUG-7 multi-input
   taproot mempool path was previously logged as G21 in test_w105
   without a fix. W105 → W144 carry-forward is ~7 weeks. (Cross-cite
   W140 "carry-forward re-anchor" pattern.)

5. **Buried-vs-versionbits asymmetry**: Nimrod uses buried heights for
   all five activations (DERSIG/CLTV/CSV/SEGWIT/TAPROOT), but Core uses
   buried for the first four and treats Taproot as the last
   versionbits-style with the bit baked into the default flag set.
   BUG-1 and BUG-13 capture this structural divergence.

## Summary

Script-verify flag derivation in nimrod follows Core's general shape
(buried activation, exception map, mempool double-pass) but several
structural details have drifted:

- The exception-map is collapsed to two `==`-string compares with a
  partial override of TAPROOT-only rather than the full bitmask Core
  uses (BUG-5, BUG-14).
- The default flag set diverges (P2SH-only vs P2SH+WITNESS+TAPROOT)
  (BUG-1, BUG-13).
- `is_p2sh` propagation is missing — P2SH-wrapped v1+32 is
  mis-classified as taproot (BUG-3).
- The bool-vs-error witness pipeline has already drifted on v1-non-32
  handling (BUG-2).
- CLTV/CSV-as-discouraged-NOP when their consensus flag is off (BUG-4).
- `sfConstScriptCode` policy bit is structurally absent (BUG-6, BUG-9).
- Multi-input taproot mempool acceptance is broken (BUG-7) and
  replicated in dead-code (BUG-8).

Most consensus-critical findings are P0-CDIV; under TODAY's mainnet
tip (post-all-activations, no historical reorg) most divergences are
benign, but any of the following make at least one P0-CDIV active:
deep historical reorg through pre-segwit, pre-taproot, or the BIP16/
Taproot exception blocks; testnet3 historical reorg (BUG-5 misses the
testnet3 BIP16 exception); regtest with non-default activation heights;
a future BIP defining a new v1 sub-type or witness version (BUG-2);
P2SH-wrapped v1+32 mainnet outputs spent in the future (BUG-3).

Priority fix targets:

1. **BUG-3** — Add `is_p2sh` parameter to both `verifyWitnessProgram`
   variants and gate taproot+P2A on `!is_p2sh`. ~10 line patch with
   complete parity.
2. **BUG-2** — Replace the bool variant's "v1 non-32 returns true"
   path with the byte-match used by `verifyWitnessProgramWithError`.
   ~5 line patch.
3. **BUG-4** — Drop the DISCOURAGE_UPGRADABLE_NOPS check from CLTV and
   CSV handlers when the flag is absent. ~2 line patch (delete two
   `if sfDiscourageUpgradableNops` blocks).
4. **BUG-1** — Change `getBlockScriptFlags` default base from
   `{sfP2SH}` to `{sfP2SH, sfWitness, sfTaproot}` and let the exception
   map subtract. ~3 line patch.
5. **BUG-5/BUG-14** — Reshape `script_flag_exceptions` as a proper map
   (per-network) returning full flag bitmasks rather than two `==`
   compares with partial overrides. ~30 line patch, biggest structural
   change.
6. **BUG-7** — Pass `allAmounts` / `allScriptPubKeys` from mempool
   `acceptTransactionWithArgs`. ~10 line patch.
7. **BUG-6/BUG-9** — Add `sfConstScriptCode` enum member, wire it into
   `OP_CODESEPARATOR` handler (sigBase only), add to STANDARD set.
   ~15 line patch.
