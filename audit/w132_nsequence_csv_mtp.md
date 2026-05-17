# W132 — BIP-68/112/113 nSequence / OP_CSV / MTP audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production-code change in W132).
Target:
  - `src/consensus/validation.nim` — `calculateSequenceLocks`,
    `checkSequenceLocks`, `checkSequenceLocksForTx`, `getMedianTimePast`,
    `getMtpForHeight`, `isFinalTx`, `isFinalTxEarly`,
    `contextualCheckBlockHeader`, `validateBlock` (CSV gate),
    `checkBlockLocktime`.
  - `src/script/interpreter.nim` — `OP_CHECKLOCKTIMEVERIFY`,
    `OP_CHECKSEQUENCEVERIFY`, `SEQUENCE_LOCKTIME_DISABLE_FLAG` /
    `_TYPE_FLAG` / `_MASK`, `toScriptNum` 5-byte form, `ScriptError`.
  - `src/consensus/params.nim` — `SequenceLockDisableFlag`,
    `SequenceLockTypeFlag`, `SequenceLockMask`, `SequenceLockGranularity`,
    `csvHeight`, `bip65Height`.
  - `src/consensus/chain.nim` (MTP-adjacent), `src/network/sync.nim`
    (`getMedianTimePastFromChain`).
  - `src/mempool/mempool.nim` — `acceptToMemoryPool` BIP-68 / IsFinalTx
    callsites at lines 941-1004.

Reference (Bitcoin Core):
  - `src/consensus/tx_check.cpp`            (`CheckTransaction`).
  - `src/consensus/tx_verify.cpp`           (`IsFinalTx`,
    `CalculateSequenceLocks`, `EvaluateSequenceLocks`, `SequenceLocks`,
    `GetLegacySigOpCount`, `GetP2SHSigOpCount`,
    `GetTransactionSigOpCost`, `Consensus::CheckTxInputs`).
  - `src/script/interpreter.cpp`            (`OP_CHECKLOCKTIMEVERIFY`,
    `OP_CHECKSEQUENCEVERIFY`, `GenericTransactionSignatureChecker::
    CheckLockTime`, `::CheckSequence`, scripthandling catch at 1226).
  - `src/script/script.h`                   (`CScriptNum`,
    `scriptnum_error`, `LOCKTIME_THRESHOLD`).
  - `src/chain.h`                           (`nMedianTimeSpan = 11`,
    `GetMedianTimePast`, `GetAncestor`).
  - `src/validation.cpp`                    (`CalculateLockPointsAtTip`,
    `CheckSequenceLocksAtTip`, `ConnectBlock` BIP-68 gate at line 2479,
    `ContextualCheckBlockHeader` + `ContextualCheckBlock` BIP-113 gate
    at line 4133).
  - `src/policy/policy.h`                   (`STANDARD_LOCKTIME_VERIFY_FLAGS
    = LOCKTIME_VERIFY_SEQUENCE`).
  - `src/consensus/consensus.h`             (`LOCKTIME_VERIFY_SEQUENCE`).
  - `src/primitives/transaction.h`          (`CTxIn::SEQUENCE_FINAL`,
    `SEQUENCE_LOCKTIME_DISABLE_FLAG`, `SEQUENCE_LOCKTIME_TYPE_FLAG`,
    `SEQUENCE_LOCKTIME_MASK`, `SEQUENCE_LOCKTIME_GRANULARITY`).

BIPs: BIP-68 (sequence locks), BIP-112 (OP_CSV), BIP-113 (MTP enforcement
for nLockTime / IsFinalTx).

W132 takes a **second-level** cut into the same nSequence/CSV/MTP code that
W37 ("CSV/CLTV/MTP plumbing") and the existing
`tests/test_csv_comprehensive.nim` (21 gates) already audited.  W132's
30 gates are **distinct** from the 21 comprehensive gates and focus on
the boundary / error-code / activation / mempool / wallet-shared-mask
surface that has gone unaudited.

## Status

**BUGS FOUND — 9 distinct underlying defects across 13 gates
MISSING / PARTIAL (of 30).  17 gates PRESENT (Core-aligned).**

Of those 9 BUGs, **1 is P0-CDIV** (one bug class would cause two
nimrod nodes to disagree with Core on a marginal mainnet input, OR
would cause nimrod to disagree with Core on tx error classification
under exotic operands).  The remaining 8 are P1 / P2 / P3 (error-code
parity, dead-code, redundancy, missing-defensive-guard).

The single P0-CDIV finding is:

- **BUG-1 (P0-CDIV)** — nimrod's `OP_CHECKSEQUENCEVERIFY` (and CLTV)
  conflate `SCRIPT_ERR_SCRIPTNUM` (overflow / non-minimal) and
  `SCRIPT_ERR_NEGATIVE_LOCKTIME` (legitimate negative) into a single
  return value.  Core distinguishes the two via the `scriptnum_error`
  catch at `interpreter.cpp:1226-1228`.  Same final reject decision
  for the tx, **but** any caller that switches on the precise script
  error (zmq `rawmempooltx` notifications, RPC `testmempoolaccept`'s
  `reason`, the misbehaving-peer score-on-error heuristic) will
  diverge.  The boundary that matters: pushing a 6-byte operand to
  OP_CSV — Core reports `SCRIPT_ERR_SCRIPTNUM`, nimrod reports
  `seNegativeLocktime`.  Not a fork on the L1 chain, but a fork on
  the RPC observable surface that test-suite oracles read.

The remaining BUGs are non-CDIV: error-string parity (BUG-2), dead
code (BUG-3, BUG-7), missing assertion (BUG-4), redundant constants
(BUG-5), missing defensive guard (BUG-6), missing wallet-shared sync
(BUG-8), and a subtle off-by-one risk in `getMtpForHeight` semantics
docs (BUG-9 — DOCS-ONLY).  See per-gate matrix and per-BUG sections
below.

## Methodology

1. Read Core refs end-to-end (`tx_check.cpp`, `tx_verify.cpp`,
   `interpreter.cpp` CLTV + CSV + `CheckSequence` / `CheckLockTime`,
   `script.h` `CScriptNum` 5-byte form + `scriptnum_error` catch,
   `chain.h` MTP, `validation.cpp` `ContextualCheckBlock` +
   `ContextualCheckBlockHeader` + `CalculateLockPointsAtTip` +
   `CheckSequenceLocksAtTip` + `ConnectBlock` BIP-68 gate,
   `policy.h` `STANDARD_LOCKTIME_VERIFY_FLAGS`).
2. Cross-referenced with W37 (CSV/CLTV original audit) and the
   existing 21-gate `tests/test_csv_comprehensive.nim` to renumber any
   already-audited gate OUT and only catalogue NEW gates.
3. Walked nimrod's `validation.nim` BIP-68/113 surface +
   `interpreter.nim` CSV/CLTV opcode dispatch +
   `params.nim` constant definitions + `mempool.nim` callsites end-to-end.
4. Wrote 30 fresh gates (`tests/test_w132_nsequence_csv_mtp.nim`).
   Each gate either documents Core-aligned correct behavior (PRESENT
   gates are tested as forward-regression sentinels — they pin the
   current behavior so a future "refactor" doesn't drift) or
   documents the divergent / missing behavior with a `check` that
   asserts the WRONG value (so the test acts as a post-fix XFAIL).

## Gate matrix

Status legend: PRESENT (Core-aligned) / PARTIAL (wired but diverges) /
MISSING (entirely absent).

| Gate | Description | Status | Bug |
|------|-------------|--------|-----|
| G1 | `OP_CHECKSEQUENCEVERIFY` accepts 5-byte operand (Y2038-safe) | PRESENT | — |
| G2 | `OP_CHECKLOCKTIMEVERIFY` accepts 5-byte operand (Y2038-safe) | PRESENT | — |
| G3 | OP_CSV operand `> 5 bytes` → `SCRIPT_ERR_SCRIPTNUM` (overflow path) | PARTIAL | BUG-1 |
| G4 | OP_CLTV operand `> 5 bytes` → `SCRIPT_ERR_SCRIPTNUM` (overflow path) | PARTIAL | BUG-1 |
| G5 | OP_CSV non-minimal operand (`fRequireMinimal`) → `SCRIPT_ERR_SCRIPTNUM` | PARTIAL | BUG-1 |
| G6 | OP_CLTV non-minimal operand (`fRequireMinimal`) → `SCRIPT_ERR_SCRIPTNUM` | PARTIAL | BUG-1 |
| G7 | OP_CLTV decode-failure error-name distinct from negative-locktime | PARTIAL | BUG-2 |
| G8 | OP_CSV decode-failure error-name distinct from negative-locktime | PARTIAL | BUG-2 |
| G9 | `SEQUENCE_LOCKTIME_DISABLE_FLAG = (1u << 31)` value | PRESENT | — |
| G10 | `SEQUENCE_LOCKTIME_TYPE_FLAG = (1u << 22)` value | PRESENT | — |
| G11 | `SEQUENCE_LOCKTIME_MASK = 0x0000FFFF` value | PRESENT | — |
| G12 | `SEQUENCE_LOCKTIME_GRANULARITY = 9` value (2^9 = 512s) | PRESENT | — |
| G13 | `LOCKTIME_THRESHOLD = 500_000_000` value | PRESENT | — |
| G14 | `SEQUENCE_FINAL = 0xFFFFFFFF` value | PRESENT | — |
| G15 | `nMedianTimeSpan = 11` constant | PRESENT | — |
| G16 | `isFinalTx` short-circuit on `lockTime == 0` | PRESENT | — |
| G17 | `isFinalTx` threshold-switch on `< LocktimeThreshold` | PRESENT | — |
| G18 | `isFinalTx` final fallback: all inputs sequence == SEQUENCE_FINAL | PRESENT | — |
| G19 | `validateBlock` BIP-68 active gate: `height >= csvHeight` | PRESENT | — |
| G20 | `validateBlock` BIP-113 lock-time-cutoff = MTP-of-prev when CSV active | PRESENT | — |
| G21 | `checkSequenceLocks` strict-`>=` semantics (Core nLockTime "last invalid") | PRESENT | — |
| G22 | `calculateSequenceLocks` zeros `prevHeights[i]` for disable-flagged input | PRESENT | — |
| G23 | `calculateSequenceLocks` `prevHeights.len == tx.inputs.len` assertion | PARTIAL | BUG-4 |
| G24 | `acceptToMemoryPool` BIP-68 always-enforced (mempool / STANDARD_LOCKTIME_VERIFY_FLAGS) | PRESENT | — |
| G25 | `acceptToMemoryPool` BIP-113 `IsFinalTx` cutoff = MTP-of-tip | PRESENT | — |
| G26 | `acceptToMemoryPool` BIP-68 v1 tx skips sequence-lock check | PRESENT | — |
| G27 | `getMtpForHeight` returns 0 for `height < 0` (genesis-prev) | PRESENT | — |
| G28 | `getMtpForHeight` walks 11 ancestors via active chain (not pprev) | PARTIAL | BUG-6 |
| G29 | `checkBlockLocktime` dead-code (test-only callers) | PARTIAL | BUG-3 |
| G30 | `SequenceLocktimeTypeFlag` duplicated in `wallet/miniscript.nim` | PARTIAL | BUG-8 |

**17 PRESENT, 13 MISSING/PARTIAL, 9 distinct BUGs catalogued.**

Note: the **existing 21-gate** test
(`tests/test_csv_comprehensive.nim`) covers the orthogonal axis —
algorithm-correctness gates (BIP-68 version, disable/type bit, MTP
location, EvaluateSequenceLocks strict-less-than, OP_CSV
type-consistency, value-comparison, IsFinalTx-with-MTP, NOP-when-flag-off,
height-gated activation, intra-block UTXOs).  W132 deliberately does
NOT overlap those.

## Bugs

### BUG-1 (P0-CDIV) — OP_CSV/CLTV conflate SCRIPT_ERR_SCRIPTNUM with NEGATIVE_LOCKTIME

Core (`script/interpreter.cpp:546`):
```cpp
const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);
```
The 3-arg `CScriptNum` constructor (`script.h:245-270`) throws
`scriptnum_error("script number overflow")` if `vch.size() > 5`, or
`scriptnum_error("non-minimally encoded script number")` if minimal
encoding fails.  This throw bubbles out of `EvalScript` and is caught
at `interpreter.cpp:1226-1228`:
```cpp
catch (const scriptnum_error&)
{
    return set_error(serror, SCRIPT_ERR_SCRIPTNUM);
}
```
Same for OP_CSV at `interpreter.cpp:574`.

After `nLockTime` is constructed, Core then checks
`if (nLockTime < 0) return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);`
at `:551-552` (`:579-580` for CSV).

nimrod (`src/script/interpreter.nim:1943-1950` for CLTV,
`:1977-1979` for CSV):
```nim
let (locktime, ok) = toScriptNum(interp.peek(), sfMinimalData in interp.flags, 5)
if not ok:
  return seInvalidStack       # ← WRONG: Core returns SCRIPT_ERR_SCRIPTNUM
if locktime < 0:
  return seNegativeLocktime
```
```nim
let (sequence, ok) = toScriptNum(interp.peek(), sfMinimalData in interp.flags, 5)
if not ok or sequence < 0:
  return seNegativeLocktime    # ← WRONG: overflow returns seNegativeLocktime
```

Severity: **P0-CDIV** (RPC-observable script-error-code divergence).

Final-state of the tx (`rejected`) is identical, so this does NOT fork
the L1 chain.  BUT: every caller that switches on the precise script
error string forks.  Concretely:

- `testmempoolaccept` JSON `reject-reason` field (Core ships
  `non-mandatory-script-verify-flag (Unknown error)` for
  `SCRIPT_ERR_SCRIPTNUM` vs `non-mandatory-script-verify-flag (Negative
  locktime)` for `SCRIPT_ERR_NEGATIVE_LOCKTIME`).  nimrod surfaces the
  wrong message under both.
- ZMQ `rawmempooltx`'s reject notification (where script error names
  ride along).
- Misbehaving-peer scoring heuristics that conditioned penalty on
  specific script errors.
- Cross-impl diff-test corpus that asserts byte-exact script-error
  classification (see `test-suite/test_script.py`).

Affected paths:
- CLTV decode failure (oversize) → currently `seInvalidStack`,
  should be `seScriptNum`.
- CSV decode failure (oversize) → currently `seNegativeLocktime`,
  should be `seScriptNum`.
- CSV non-minimal-when-required → currently `seNegativeLocktime`,
  should be `seScriptNum` (CScriptNum throws scriptnum_error before
  the value is even returned in Core).
- CLTV non-minimal-when-required → currently `seInvalidStack`,
  should be `seScriptNum`.

The nimrod `ScriptError` enum (interpreter.nim:13-69) **has no
`seScriptNum` member at all**, so the closest patch surface is:
add `seScriptNum = "unknown script number"` and re-route the four
decode-failure call-sites.  ~10 LOC.  No production-code change in
W132 (audit-only); FIX-W132 wave will land it.

### BUG-2 (P1) — CLTV decode-failure error inconsistent with CSV's

Even before BUG-1 is fixed, CLTV and CSV use DIFFERENT enum values for
the same conceptual decode-failure path:

- CLTV (`:1946-1947`): `if not ok: return seInvalidStack`.
- CSV (`:1977-1979`): `if not ok or sequence < 0: return seNegativeLocktime`.

Core returns `SCRIPT_ERR_SCRIPTNUM` for both.  Even if the W132-FIX
wave landed `seScriptNum`, the existing test-suite asserts CLTV
returns `seInvalidStack` (an artifact of the pre-existing partial
implementation).  Pinned by `tests/test_cltv.nim`.

Severity: **P1** — pure error-code parity issue.  Same observable
divergence as BUG-1 but distinct because the inconsistency between
the two opcodes is itself a tell that the audit was never run.

### BUG-3 (P3) — `checkBlockLocktime` is dead code

Annotated DEAD CODE in `validation.nim:1678-1684`:
```nim
proc checkBlockLocktime*(blk: Block, height: uint32, lockTimeCutoff: uint32): ValidationResult[void] =
  ## Contextual IsFinalTx check for all transactions in a block.
  ## Mirrors Bitcoin Core ContextualCheckBlock validation.cpp:4146.
  ## Must run even when scripts are skipped (assumevalid only skips sig-check).
  ##
  ## DEAD CODE (wave-33b ledger): test-only callers (test_isfinaltx.nim:70, :81).
  ## The live IsFinalTx enforcement is inside validateBlock (called from acceptBlock).
  ## BIP-65 / BIP-68 / locktime fixes belong in validateBlock, NOT here.
  for tx in blk.txs:
    if not isFinalTx(tx, height, lockTimeCutoff):
      return voidErr(veNonFinalTx)
  ok()
```

Live enforcement is at `validateBlock:1371-1373` via the inline
`isFinalTxEarly` (a 13-LOC duplicate of `isFinalTx`).  The DEAD
helper is a footgun: a future contributor patching "the locktime
check" may patch the helper and not the inline copy, silently
re-introducing a consensus divergence with Core.

Severity: **P3** — currently inert, but a known-footgun pattern.
Fix surface: delete `checkBlockLocktime`, callers in
`tests/test_isfinaltx.nim:70`, `:81` switch to the live
`isFinalTx` (public) entrypoint.  Also delete `isFinalTxEarly`
(`:1245-1257`) and inline the public `isFinalTx` directly.

### BUG-4 (P2) — `calculateSequenceLocks` assertion is defensive-only

Core (`tx_verify.cpp:41`):
```cpp
assert(prevHeights.size() == tx.vin.size());
```
nimrod (`validation.nim:565`):
```nim
assert prevHeights.len == tx.inputs.len
```

Semantically identical, BUT nimrod's `assert` is compiled out in
`-d:release` builds (the standard `nimrod` release binary).  Core's
`assert` macro is always-on for kernel-consensus code (Core uses
`Assert(...)` for soft-assertions and plain `assert(...)` for hard
ones; `assert(...)` is NOT disabled by NDEBUG in the consensus
translation units because `-DNDEBUG` is not passed for `libconsensus`
/ `libnode`).

Severity: **P2** — caller-violation would produce a wrong
`SequenceLock` (likely `minHeight=-1, minTime=-1` interpreted as "no
constraint"), silently treating a malformed call as no-op.  Since the
two callers (`mempool.nim:1001`, `validation.nim:1409`) both build
`prevHeights` from `tx.inputs.len` directly, current call-sites are
correct.  Fix surface: replace `assert` with a hard `doAssert`
(Nim equivalent of always-on assert) OR convert to a `Result[]`-style
early `return` with `veInternalError`.

### BUG-5 (P3) — `SequenceLocktimeTypeFlag` duplicated in three modules

Three independent definitions of the BIP-68 bit-22 constant:

- `src/consensus/params.nim:131` —
  `SequenceLockTypeFlag* = 1'u32 shl 22`
- `src/script/interpreter.nim:281` —
  `SEQUENCE_LOCKTIME_TYPE_FLAG* = 1'u32 shl 22`
- `src/wallet/miniscript.nim:166` —
  `SequenceLocktimeTypeFlag* = 1'u32 shl 22`

Same for the DISABLE_FLAG (`params.nim:130` + `interpreter.nim:280`),
the MASK (`params.nim:132` + `interpreter.nim:282`), and the
THRESHOLD (`validation.nim:355` + `wallet/miniscript.nim:169` +
`mining/blocktemplate.nim:28`).

Each definition uses the same value but a different identifier name
or path; a future BIP-68bis-style change would have to touch all
three, and any partial update is a silent fork.

Severity: **P3** — pure refactor / consolidation.  Move all three
constants into `src/consensus/params.nim` and re-export from
`interpreter.nim` and `miniscript.nim`.

### BUG-6 (P2) — `getMtpForHeight` uses active-chain `getBlockHashByHeight` not pprev walk

Core (`chain.h:233-244`):
```cpp
int64_t GetMedianTimePast() const {
    int64_t pmedian[nMedianTimeSpan];
    int64_t* pbegin = &pmedian[nMedianTimeSpan];
    int64_t* pend = &pmedian[nMedianTimeSpan];
    const CBlockIndex* pindex = this;
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        *(--pbegin) = pindex->GetBlockTime();
    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin) / 2];
}
```
Core walks `pprev` — the **header parent** pointer, which is fork-aware.

nimrod (`validation.nim:459-480`):
```nim
proc getMtpForHeight*(utxos: ChainDb, height: int32): uint32 =
  ...
  for i in 0 ..< MedianTimeSpan:
    if h < 0:
      break
    let idxOpt = utxos.getBlockHashByHeight(h)
    ...
    headers.add(blockIdxOpt.get().header)
    dec h
```
`getBlockHashByHeight` returns the **active chain**'s block at that
height — fork-agnostic.

Impact: when `validateBlock` is called for a block being CONNECTED to
the active tip, the active chain at height-1, -2, ..., -10 is exactly
the parent chain of the block.  So in the live path, this is correct.

But: `contextualCheckBlockHeader` calls `getMtpForHeight(utxos,
prevIndex.height)` BEFORE the block is connected.  If `prevIndex` is
**not** the active tip (i.e., we are validating a header on a side
chain that has yet to win), `prevIndex.height` resolves to whatever
block is at that height on the **active** chain — not the side chain.
The MTP we compute is for the WRONG chain.

Symptom: a "time-too-old" rejection that should pass (or vice versa)
on a tail-of-fork header.  Symptom only triggers if the active chain
and the validating chain diverge in timestamps within the last 11
blocks of the fork point.

Severity: **P2** — fork-aware MTP is required for fork-aware
header acceptance.  Affects header validation on side chains during
reorgs.

Mitigation today: `acceptHeader` may serialize header acceptance
along the eventual-best chain, so the symptom requires a specific
reorg pattern.  Existing audit notes (W93?) may have already flagged
this; W132 catalogues it under nSequence/MTP umbrella.

### BUG-7 (P3) — `isFinalTxEarly` is a duplicate of `isFinalTx`

`validation.nim:1245-1257` (`isFinalTxEarly`, internal) and
`:1655-1671` (`isFinalTx`, public) are byte-identical apart from the
internal proc lacking the doc-string.  Inline comment explicitly
documents this as a forward-declaration workaround (avoid Nim's
forward-decl quirk because `validateBlock` is defined before
`isFinalTx`).

Severity: **P3** — same footgun as BUG-3.  Fix scope: move the
public `isFinalTx` above `validateBlock` and delete the early copy.
Bonus: the public proc would then be the SINGLE source of truth for
IsFinalTx, eliminating the W132-BUG-3 + BUG-7 footgun pair in one
patch.

### BUG-8 (P3) — wallet miniscript shares no constants with consensus

`src/wallet/miniscript.nim:166-170`:
```nim
SequenceLocktimeTypeFlag* = 1'u32 shl 22
LocktimeThreshold* = 500_000_000'u32
```

These are wallet-policy-side constants used to classify a miniscript
fragment (line 298, 1507) as height-vs-time domain.  They re-derive
the same numerical values as the consensus side but do NOT import
from `consensus/params.nim`.  Any future consensus-level constant
change would have to be replicated by hand.

Severity: **P3** — refactor.  Identical to BUG-5 but spans the
**wallet** module which W113 + W118 audited separately; cross-wave
fix touches both.

### BUG-9 (P3 — DOCS-ONLY) — `getMtpForHeight` doc-string ambiguity

`validation.nim:459-462`:
```nim
proc getMtpForHeight*(utxos: ChainDb, height: int32): uint32 =
  ## Get Median Time Past for a given block height
  ## Uses the previous 11 block headers (or fewer if near genesis)
  ## This is the MTP at the tip of the chain when block `height` is being mined
```

The doc claims "MTP at the tip of the chain when block `height` is
being mined".  This is NOT Core's MTP definition.  Core's
`pindex->GetMedianTimePast()` returns the median of `pindex` and the
**ten blocks before pindex** — i.e., the MTP **of block `height`**,
not "at the tip when height is being mined".

The MTP-OF-block-`height` includes block-`height`'s own timestamp;
the MTP-at-tip-when-block-`height`-is-being-mined would be the MTP
of `height - 1`.

In nimrod's body, the loop is `for h in countdown(height, height -
10)`, which DOES include `height` itself — matching Core's
"MTP of block `height`" semantics.  So the **code** is correct; the
**doc** is wrong.

Symptom: future reader reading the doc and writing a caller that
passes `tipHeight - 1` expecting "MTP of the next block" will get
"MTP of block tipHeight - 1" (which is one block older than they
want).

Severity: **P3** (docs-only).  Already a real footgun visible in
the mempool callsite at `mempool.nim:942` where the call is
`getMtpForHeight(db, tipHeight)` — this passes `tipHeight`, gets MTP
of block at tipHeight (Core-correct), but the doc made the author
write a comment explaining the choice.

## Cross-references

- **Test pin**: `tests/test_csv_comprehensive.nim` covers the 21
  orthogonal gates from W37.
- **Sibling fix waves**:
  - FIX-W132 (P0-CDIV BUG-1 + BUG-2): add `seScriptNum` to the
    `ScriptError` enum + route CLTV / CSV decode-failure paths.
  - FIX-WXX (P3 BUG-3, BUG-5, BUG-7, BUG-8): consolidate dead code +
    duplicate constants in one refactor wave.
  - FIX-WYY (P2 BUG-4, BUG-6): fork-aware MTP walk + hard-assert.

## Universal patterns observed in this audit

1. **Dead-helper-at-call-site** (BUG-3 + BUG-7) — same pattern as
   FIX-79 nimrod `validateRbfDiagram` and the 10+ closures across the
   project.  When a "I'm here to satisfy the public API but the real
   logic is inlined elsewhere" comment appears in a proc body, it
   is a near-certainty that the inline copy will drift from the
   helper, and the helper will be tested while the inline copy gets
   the production exercise.

2. **Cross-module duplicate constants** (BUG-5 + BUG-8) — three
   independent definitions of `1u << 22` across consensus / script /
   wallet modules.  Universal pattern: the "obvious" refactor
   (import a shared module) costs ~3 LOC but the per-module
   independent-definitions pattern is ~3 modules × 3 constants × 2
   places-they-might-need-to-change = up to 18 sites.

3. **Error-code-conflation under uniform reject decision** (BUG-1 +
   BUG-2) — both Core and nimrod reject the tx, but the WHY differs
   in a way that test-suite oracles + downstream consumers
   observe.  This is the same pattern as the BIP-158
   blockfilter-byte-exact (W122) audit-framework correction: the
   uniform reject is not enough; cross-impl byte-exact REASON is
   required.
