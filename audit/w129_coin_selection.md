# W129 — Coin selection (BnB / Knapsack / SRD / CoinGrinder) audit (nimrod)

Date: 2026-05-17
Audit type: discovery
Target: `src/wallet/coinselection.nim` (BnB, KnapsackSolver, waste,
effective value, helpers) and the in-wallet callsite
`src/wallet/wallet.nim:selectCoinsAdvanced` /
`selectCoinsSimple` / `createTransaction`. Bump-fee re-funding
in `src/wallet/feebumper.nim` is *not* in scope for the selection
algorithm itself (it reuses the original tx's inputs) but is a
downstream consumer that the audit cross-references for
`m_cost_of_change` / `min_viable_change` / SFFO behavior.
Reference: Bitcoin Core
`src/wallet/coinselection.{h,cpp}` (SelectCoinsBnB, CoinGrinder,
SelectCoinsSRD, KnapsackSolver, OutputGroup, CoinSelectionParams,
GenerateChangeTarget, RecalculateWaste, GetChange),
`src/wallet/spend.cpp` (AttemptSelection algorithm orchestration,
CoinSelectionParams plumbing, anti-fee-sniping in
`DiscourageFeeSniping`).

Cross-reference with W113 ("coin selection algorithms") — that wave
covered the same module at the BnB/Knapsack and waste-metric *plumbing*
level (G1-G30). W129 takes the next-deeper cut: ordering tie-breakers,
algorithm orchestration / multi-algo waste comparison, SFFO interaction
with BnB skip-policy, `GenerateChangeTarget` privacy randomization,
`OutputGroup` aggregation, change-output dust / `min_viable_change`,
and the four selection algorithms versus the two implemented (BnB +
Knapsack).

The W113 P0-CDIV findings (BUG-6/7 missing-excess in `calculateWaste`,
BUG-10/11 missing CoinControl) are NOT re-classified here; this audit
re-confirms them as still-open and folds them into gates that match
W129's stricter scope where applicable. New BUGs are numbered fresh
(BUG-1-W129 .. BUG-N-W129) to keep the corpus deduplicable.

## Status

**BUGS FOUND — 21 distinct gates MISSING / PARTIAL (of 30).**

Of those 21, 4 are universal correctness divergence (CDIV) and would
cause nimrod to construct a transaction with a different input set
than Bitcoin Core given identical wallet state and identical
`CoinSelectionParams`. The CDIVs are concentrated in three clusters:

- **No SRD or CoinGrinder algorithm at all** (G11, G12) — nimrod runs
  BnB then Knapsack and short-circuits at the first success.  Core
  runs all four applicable algorithms and picks `std::min_element` on
  the waste metric.  In any wallet state where Knapsack and SRD both
  produce results, nimrod will use Knapsack while Core may pick SRD,
  and vice-versa — different input set, different fee, different
  txid.

- **BnB sort tie-breaker is wrong** (G6) — Core's `descending`
  comparator breaks ties on equal `GetSelectionAmount()` by
  `fee - long_term_fee` ascending (prefer lower waste). nimrod sorts
  by effective value only with no tie-breaker, so the deterministic
  order diverges whenever two UTXOs have the same effective value.

- **Waste metric is structurally wrong for changeless solutions**
  (G19, G20) — `calculateWaste` doesn't take `target`, so the no-change
  arm cannot add the `excess = selected_eff_value - target` term that
  Core's `RecalculateWaste` adds. BnB compares `currWaste +
  excessWaste` inline, but the public `calculateWaste` helper used by
  Knapsack/largest-first cannot. Cross-algorithm waste comparison is
  therefore meaningless even if it existed.

The remaining 17 BUGs are MEDIUM / LOW (privacy / parametrization /
plumbing) and would not by themselves change the input set, but they
mean a downstream `bumpfee` or `walletcreatefundedpsbt` call with
specific CoinControl flags (preset inputs, custom fee rate, custom
change address, avoidpartialspends) will silently fall back to the
nimrod default behavior since none of those flags exist.

## Methodology

1. Read Core refs.  Synthesized the 30-gate matrix from
   `coinselection.{h,cpp}` (algorithms, params, waste, SFFO, change
   target, output groups) and `spend.cpp` (AttemptSelection orchestrator,
   anti-fee-sniping in `DiscourageFeeSniping`).
2. Cross-referenced with W113 to avoid re-numbering the same bugs.
3. Walked `coinselection.nim` and the callsite chain in `wallet.nim`
   end-to-end. Confirmed each gate's PRESENT / PARTIAL / MISSING
   status with a grep/read of the relevant symbol.
4. Wrote 30 test gates (`tests/test_w129_coin_selection.nim`).
   Each gate either documents behavior that is correct (`check` passes
   today and would regress if a future fix breaks it) or documents the
   current wrong/missing behavior with an inline TODO + a `check` that
   asserts the WRONG value so the test acts as a post-fix xfail.

## Gate matrix

Status legend: PRESENT (Core-aligned) / PARTIAL (wired but diverges) /
MISSING (entirely absent).

| Gate | Description | Status | Bug |
|------|-------------|--------|-----|
| G1 | `SelectCoinsBnB` exists and returns Optional / Option | PRESENT | — |
| G2 | `KnapsackSolver` exists | PRESENT | — |
| G3 | `TOTAL_TRIES` constant = 100000 for BnB | PRESENT | — |
| G4 | `ApproximateBestSubset` iterations = 1000 | PRESENT | — |
| G5 | BnB sorts by effective value descending | PRESENT | — |
| G6 | BnB sort tie-breaker on `fee - long_term_fee` ascending | MISSING | BUG-1-W129 |
| G7 | BnB exact-range backtrack `[target, target+cost_of_change]` | PRESENT | — |
| G8 | BnB lookahead pruning `curr_value + curr_available < target` | PRESENT | — |
| G9 | BnB skip-equivalent-coin optimization | PARTIAL | BUG-2-W129 |
| G10 | BnB `is_feerate_high` waste-pruning gate | PRESENT | — |
| G11 | `SelectCoinsSRD` algorithm | MISSING | BUG-3-W129 |
| G12 | `CoinGrinder` algorithm | MISSING | BUG-4-W129 |
| G13 | Multi-algorithm waste comparison (`std::min_element`) | MISSING | BUG-5-W129 |
| G14 | `OutputGroup` aggregation (avoid_partial_spends) | MISSING | BUG-6-W129 |
| G15 | `CoinSelectionParams` struct | MISSING | BUG-7-W129 |
| G16 | `GenerateChangeTarget` privacy randomization | MISSING | BUG-8-W129 |
| G17 | `CHANGE_LOWER` / `CHANGE_UPPER` constants | MISSING | BUG-9-W129 |
| G18 | Per-coin `effective_value = value - fee` | PRESENT | — |
| G19 | Waste metric no-change arm: `+ excess` term | MISSING | BUG-10-W129 |
| G20 | `RecalculateWaste(min_viable_change, change_cost, change_fee)` 3-arg signature | MISSING | BUG-11-W129 |
| G21 | `m_subtract_fee_outputs` / SFFO support | MISSING | BUG-12-W129 |
| G22 | BnB skipped when SFFO active (spend.cpp:751) | MISSING | BUG-13-W129 |
| G23 | `m_long_term_feerate` separate from effective feerate | PARTIAL | BUG-14-W129 |
| G24 | `m_consolidate_feerate` wallet config | MISSING | BUG-15-W129 |
| G25 | `m_discard_feerate` separate from effective feerate | MISSING | BUG-16-W129 |
| G26 | `m_cost_of_change = discard_feerate * change_spend_size + change_fee` | PARTIAL | BUG-17-W129 |
| G27 | `min_viable_change = max(change_spend_fee + 1, dust)` | PARTIAL | BUG-18-W129 |
| G28 | `max_selection_weight` enforcement (BnB / Knapsack) | MISSING | BUG-19-W129 |
| G29 | `bump_fee_group_discount` tracking | MISSING | BUG-20-W129 |
| G30 | Anti-fee-sniping `IsCurrentForAntiFeeSniping` guard + rand-100 backoff | MISSING | BUG-21-W129 |

21 BUGs, 9 PRESENT.

## Bugs

### BUG-1-W129 (P0-CDIV) — BnB sort tie-breaker missing

Core's `descending` comparator in `coinselection.cpp:29-37`:

```cpp
struct {
    bool operator()(const OutputGroup& a, const OutputGroup& b) const {
        if (a.GetSelectionAmount() == b.GetSelectionAmount()) {
            // Lower waste is better when effective_values are tied
            return (a.fee - a.long_term_fee) < (b.fee - b.long_term_fee);
        }
        return a.GetSelectionAmount() > b.GetSelectionAmount();
    }
} descending;
```

nimrod's BnB sort in `coinselection.nim:128-129`:

```nim
pool.sort(proc(a, b: SelectableCoin): int =
  cmp(int64(b.effectiveValue), int64(a.effectiveValue)))
```

Effective-value-only with no tie-break. When two UTXOs have the same
effective value (e.g. two wallet outputs to the same scriptPubKey
seen via different blocks), Nim's `sort` falls back to `algorithm.sort`
which is *not* documented stable on `cmp == 0` — meaning the
deterministic search order, the equivalence-skip detection
(G9 / `coinselection.cpp:174-177`), and the final waste comparison
all become non-deterministic. Two nimrod nodes given the same UTXO
set may select different inputs.

Severity: **P0-CDIV** (input set divergence under identical inputs).
Fix scope: 5-LOC sort comparator change.

### BUG-2-W129 (P1) — BnB skip-equivalent optimization checks fee but not fee-vs-prev

`coinselection.nim:220-228`:

```nim
if pool[idx].effectiveValue == pool[prevIdx].effectiveValue and
   pool[idx].fee == pool[prevIdx].fee:
  skipEquivalent = true
```

This matches Core's check on effective value + fee. BUT it requires
the previous index to be the one immediately preceding the current
index and previously SKIPPED. nimrod checks `prevIdx != currSelection[^1]`
(meaning previous was not included), which is correct. The bug is more
subtle: Core skips equivalent coins via the `!= curr_selection.back()`
test only at one specific point (entering the inclusion branch), not
when re-entering on omission. nimrod's `skipEquivalent` gate is reached
on every loop iteration where `currSelection.len > 0 and idx > 0`,
which over-prunes when the previous coin was *omitted on backtrack but
the current coin is being considered fresh*. Net effect: BnB may miss
valid solutions where two coins have equal effective value + fee but
the algorithm needs to try both inclusion paths.

Severity: **P1** (correctness on coin sets with duplicate eff value;
rare on mainnet but reproducible).

### BUG-3-W129 (P0-CDIV) — SRD algorithm entirely missing

`coinselection.cpp:536-588` defines `SelectCoinsSRD` (Single Random
Draw): shuffle UTXOs, accumulate until target + `CHANGE_LOWER +
change_fee` is met, evict-by-priority-queue when weight exceeds
`max_selection_weight`. Used by Core's `AttemptSelection` as one of
four candidates whose waste is compared.

nimrod has no SRD. `selectCoins` (line 445-469) tries BnB then
Knapsack and returns on first success. In a wallet with many small
UTXOs where BnB cannot find an exact match and Knapsack happens to
pick the largest-coin fallback, SRD would have produced a smaller-fee
result by including only a random subset — nimrod will always pick
the Knapsack result.

Severity: **P0-CDIV** (different input set vs Core given same wallet).
Fix scope: new ~50-LOC `selectCoinsSRD` proc + wiring into
`selectCoins`.

### BUG-4-W129 (P0-CDIV) — CoinGrinder algorithm entirely missing

`coinselection.cpp:325-525` defines `CoinGrinder`: DFS-based
minimum-weight search activated when `m_effective_feerate > 3 *
m_long_term_feerate` (i.e. when fee rate is unusually high relative to
the wallet's consolidate target — see `spend.cpp:769`). It produces
a transaction *with* a change output and is preferred over BnB's
changeless solution at high feerates because a smaller-weight tx is
cheaper even with the change-output overhead.

nimrod has no CoinGrinder and no notion of a 3× feerate threshold.
At feerates ≥ 30 sat/vB nimrod will systematically build heavier
transactions than Core would, costing the user fee. This is not just
a privacy issue — it's a measurable extra cost to the user.

Severity: **P0-CDIV** (different input set + larger user-paid fees at
high feerates).
Fix scope: large; full new algorithm (~200 LOC) + waste-comparison
wiring.

### BUG-5-W129 (P0-CDIV) — Multi-algorithm waste comparison missing

`spend.cpp:809-811`:

```cpp
// Choose the result with the least waste
return *std::min_element(results.begin(), results.end());
```

with `operator<` on `SelectionResult` comparing `m_waste` ascending,
tie-breaking on more inputs. nimrod's `selectCoins` in
`coinselection.nim:459-468`:

```nim
let bnbResult = selectCoinsBnB(utxos, target, costOfChange)
if bnbResult.isSome:
  return bnbResult.get()
let knapsackResult = knapsackSolver(utxos, target, minChange)
if knapsackResult.isSome:
  return knapsackResult.get()
```

First-success-wins. BnB is *always* picked when it succeeds, even if
Knapsack would produce a lower-waste selection (e.g. when the BnB
changeless solution has high excess and Knapsack would have only a
small change cost). This is the "BnB short-circuit" anti-pattern.

Severity: **P0-CDIV** (different selection at the choose-best step).
Fix scope: run both, compare waste, pick min. ~20 LOC.

### BUG-6-W129 (P1) — OutputGroup aggregation missing

`coinselection.h:228-270` defines `OutputGroup`: a set of UTXOs paid
to the same scriptPubKey, treated as one unit for selection. Required
for `-avoidpartialspends` (default OFF on mainnet, default ON for
some wallets / privacy mode). Caps at `OUTPUT_GROUP_MAX_ENTRIES=100`
to avoid excessive tx size from accidental address reuse.

nimrod has no OutputGroup, no `m_outputs` aggregation. The
`SelectableCoin` is flat — every UTXO is independent. A wallet that
received 200 small payments to the same reused address will see 200
separate coin selection candidates, where Core would see ≤ 2 groups.
This affects both selection quality and privacy of which inputs end
up in the same tx.

Severity: **P1** (correctness + privacy when avoid_partial_spends set).
Fix scope: new type `OutputGroup`, `m_outputs: seq[SelectableCoin]`,
GroupOutputs procedure, ~150 LOC.

### BUG-7-W129 (P1) — CoinSelectionParams struct missing

`coinselection.h:134-196` defines `CoinSelectionParams` — the bag of
all parameters consumed by every selection algorithm:
`change_output_size`, `change_spend_size`, `m_min_change_target`,
`min_viable_change`, `m_change_fee`, `m_cost_of_change`,
`m_effective_feerate`, `m_long_term_feerate`, `m_discard_feerate`,
`tx_noinputs_size`, `m_subtract_fee_outputs`,
`m_avoid_partial_spends`, `m_include_unsafe_inputs`,
`m_version`, `m_max_tx_weight`.

nimrod's `selectCoins(utxos, target, costOfChange, minChange)` carries
only 3 of those. The rest are wired ad-hoc or absent. This makes it
structurally impossible to thread settings like `m_long_term_feerate`
(for the BnB `is_feerate_high` decision) or `m_subtract_fee_outputs`
(for SFFO + BnB skip).

Severity: **P1** (plumbing prerequisite for several CDIVs).
Fix scope: new type, ~30 LOC + wiring.

### BUG-8-W129 (P1) — GenerateChangeTarget randomization missing

`coinselection.cpp:809-818`: Core randomizes the minimum change target
on every tx to make wallet fingerprinting harder. Without this,
wallets produce change outputs at exactly the dust threshold, which is
a strong fingerprint that "wallet X always uses min change = 546".

nimrod's `selectCoinsAdvanced` in `wallet.nim:861-862` uses
`max(MinChangeValue=546, changeCost)` — a deterministic value with no
random component. Every nimrod-built tx has a recognizable change
pattern.

Severity: **P1** (privacy / fingerprinting; user-visible on chain).
Fix scope: ~10 LOC adding `generateChangeTarget(payment, change_fee)`.

### BUG-9-W129 (LOW) — CHANGE_LOWER / CHANGE_UPPER constants missing

`coinselection.h:23-25`: `CHANGE_LOWER=50000`, `CHANGE_UPPER=1000000`.
Used by `GenerateChangeTarget` and `SelectCoinsSRD`. Both missing in
nimrod.

Severity: **LOW** (constants).
Fix scope: 2-LOC const addition.

### BUG-10-W129 (P0-CDIV, dupe of W113 BUG-6) — Waste excess term missing in no-change arm

Already filed as W113 BUG-6 / G22. Re-confirmed open at
`coinselection.nim:79-82`:

```nim
if int64(changeValue) > 0:
  waste += int64(changeCost)
else:
  # No change means we're paying the excess as fee
  # This is calculated by caller as: totalEffective - target
  discard
```

The comment claims the caller does it; in practice neither
`knapsackSolver` nor `selectCoinsLargestFirst` adds the excess back
into `result.waste` for the changeless case. `selectCoinsBnB` adds
it inline at line 174-175 only inside its own loop, then assigns
`result.waste = Satoshi(bestWaste)`. So BnB is correct *only when its
own bestWaste is used as the final answer*; Knapsack and largest-first
have a structurally wrong waste field. When the multi-algorithm
comparison is added (BUG-5), this gap becomes visible.

Severity: **P0-CDIV** in the post-fix-5 world; **P1** today.

### BUG-11-W129 (P0-CDIV, dupe of W113 BUG-7) — calculateWaste signature missing target

Already filed as W113 BUG-7. Re-confirmed: `calculateWaste(coins,
changeValue, changeCost)` lacks the `target` parameter needed to
compute excess. Core's `RecalculateWaste(min_viable_change,
change_cost, change_fee)` uses the `m_target` field stored on
`SelectionResult`. nimrod's `SelectionResult` doesn't carry target
either.

Severity: structurally the same bug as BUG-10 from the type-signature
side. Fix decomposition: add `target` to `SelectionResult`, add
`change_fee` param, re-emit excess.

### BUG-12-W129 (P1) — SFFO (subtract-fee-from-outputs) support missing

`coinselection.h:163`: `m_subtract_fee_outputs`. When true, the
selection target is the *gross* recipient sum (no fee subtraction)
because the recipient absorbs the fee. OutputGroup's
`GetSelectionAmount()` returns `m_value` (real, not effective) in this
case (line 789-792).

nimrod has no SFFO concept; recipient amounts are always treated as
net. `sendmany` / `sendtoaddress` with `subtractfeefromamount` arrays
will compute wrong fees and may either underpay or overpay.

Severity: **P1** (RPC API parity).

### BUG-13-W129 (P1) — BnB-skip-when-SFFO missing

`spend.cpp:750-755`:

```cpp
// SFFO frequently causes issues in the context of changeless input sets:
// skip BnB when SFFO is active
if (!coin_selection_params.m_subtract_fee_outputs) {
    if (auto bnb_result{SelectCoinsBnB(...)}) ...
}
```

Even if SFFO were implemented (BUG-12), nimrod's `selectCoins` would
still run BnB and produce a wrong changeless solution because the
target it computes does not include the fee that SFFO would absorb.

Severity: P1 (correctness post-SFFO-fix).

### BUG-14-W129 (P1) — long-term-feerate degenerates to effective feerate at wallet callsite

`wallet.nim:852`: `feeRate  # Using same rate for long-term estimate`.
The `newSelectableCoin` proc takes a separate `longTermFeeRate`
parameter and the BnB algorithm uses the difference to decide
`is_feerate_high` (waste-pruning), but the only caller passes the same
value. Net effect: `is_feerate_high = false` always, BnB never prunes
on waste, and the waste metric for every selection collapses to
just-the-excess.

Severity: **P1** (degrades BnB search quality + waste comparison).
Fix scope: ~5 LOC, but requires adding `m_consolidate_feerate` to the
wallet config (BUG-15).

### BUG-15-W129 (MEDIUM) — m_consolidate_feerate wallet config missing

Core's wallet stores a per-wallet `m_consolidate_feerate` (default 10
sat/vB) that is used as the long-term fee estimate for waste decisions.
nimrod's `WalletConfig` has no such field; the value passed through to
`newSelectableCoin` is the same as the effective feerate.

Severity: MEDIUM (prerequisite for BUG-14 fix).

### BUG-16-W129 (MEDIUM) — m_discard_feerate missing

Core's `m_discard_feerate` (default `DEFAULT_DISCARD_FEE=10000` sat/kB)
is used to decide whether a change output is "economic to spend" later:
if the future spend fee would exceed the change value, drop it to
fees instead.

nimrod has no discard feerate; the only fee rate in play is the
effective (current) fee rate. Tiny change outputs that should be
dropped to fees will be kept as dust.

Severity: MEDIUM (privacy + economics).

### BUG-17-W129 (MEDIUM) — m_cost_of_change formula incorrect

`spend.cpp:1175`: `m_cost_of_change = m_discard_feerate.GetFee(
change_spend_size) + m_change_fee`. That is: future spend cost at the
discard rate, plus current change-output creation cost at the
effective rate. Two different fee rates.

nimrod's `wallet.nim:861`: `changeCost = (P2WpkhOutputWeight/4 +
P2WpkhInputWeight/4) * feeRate`. One rate (the effective feerate)
applied to both the output and the future input. This will over-cost
change at low effective feerates relative to discard, and under-cost
at high effective feerates.

Severity: MEDIUM (BnB range over-/under-approximation, costing the
user fee).

### BUG-18-W129 (MEDIUM) — min_viable_change formula incorrect

`spend.cpp:1184`: `min_viable_change = std::max(change_spend_fee + 1,
dust)`.  That is: the change must at least pay its future spend fee
plus one sat, or be at least the dust threshold, whichever is larger.

nimrod's `wallet.nim:862`: `minChange = max(MinChangeValue=546,
changeCost)`. Uses 546 as a hardcoded "dust" (Core's dust depends on
`dustRelayFee` and the output type, not a constant) and uses the
combined creation+spend cost (BUG-17) instead of just spend cost.

Severity: MEDIUM (false-positive change creation at wrong threshold).

### BUG-19-W129 (P1) — max_selection_weight enforcement missing

Already filed as W113 BUG-15. Re-confirmed: nimrod BnB and Knapsack
have no `max_selection_weight` parameter. Core uses
`MAX_STANDARD_TX_WEIGHT - tx_noinputs_size * 4 - change_outputs_weight`
to cap selection. nimrod could produce a transaction over the standardness
weight limit that would be rejected by relay nodes.

Severity: P1 (standardness violation).

### BUG-20-W129 (LOW) — bump_fee_group_discount tracking missing

`coinselection.h:350`: `bump_fee_group_discount`. When multiple
selected inputs share unconfirmed ancestors, the per-input
ancestor-bump fee over-counts. Core's
`SelectionResult::SetBumpFeeDiscount` subtracts the overestimate from
waste. Used at `spend.cpp:798-805`.

nimrod has no `ancestor_bump_fees` on `SelectableCoin` and no discount
on `SelectionResult`. When the wallet spends multiple unconfirmed
inputs sharing a parent, the fee will be slightly over-paid.

Severity: LOW (small fee overpay; correctness still ok).

### BUG-21-W129 (P1, dupe of W113 BUG-8/9) — anti-fee-sniping guard + rand-100 backoff missing

Already filed as W113 BUG-8 (`IsCurrentForAntiFeeSniping` guard
missing) and BUG-9 (10% rand(100) backoff missing). Re-confirmed at
`wallet.nim:956-958`:

```nim
result.lockTime = uint32(wallet.params.bip34Height)  # Anti-fee-sniping
if wallet.chainState != nil:
  result.lockTime = uint32(wallet.chainState.bestHeight)
```

No `IsCurrentForAntiFeeSniping` check (Core only sets bestHeight when
tip is fresh; otherwise sets 0). No `randrange(10) == 0 → randrange(100)`
backoff (Core occasionally jitters the locktime back up to 100 blocks
for privacy). Net effect: nimrod wallet txes always carry
`nLockTime = bestHeight`, which is a strong fingerprint.

Severity: P1 (privacy fingerprint).

## Universal observations (across the fleet)

These are patterns worth surfacing at the meta level rather than
per-bug. Likely to recur in sibling impls and worth filing fleet-wide
tracking issues for.

1. **"Two-algo wallet" pattern** — nimrod implements BnB + Knapsack
   and short-circuits at first success. This is the original Bitcoin
   Core ~2019 design (pre-SRD, pre-CoinGrinder, pre-waste-comparison).
   Most non-Rust impls in the fleet (haskoin, camlcoin, blockbrew per
   prior W113-era audits, presumably others) ALSO stop at BnB +
   Knapsack and have not added SRD or CoinGrinder. This is the
   "implementing the textbook" anti-pattern: every impl reads
   `coinselection.h` once when it ships and freezes — the post-2020
   waste-comparison refactor in Core was missed across the fleet.
   Likely fleet-wide closure: a single multi-impl "add SRD + waste
   comparison" wave covering ≥ 5 impls.

2. **"Params struct refactor missed"** — Core moved every parameter
   from per-algorithm signatures into `CoinSelectionParams` in 2021.
   Every impl that started before that ships with the old "3-arg
   selectCoins" signature.  Adding new params (long-term feerate,
   discard feerate, consolidate feerate, max weight) becomes a
   signature-rippling fix because the params struct was never adopted.
   Fleet pattern likely recurs.

3. **"OutputGroup omission"** — `OutputGroup` aggregation is the most
   often-omitted feature because it interacts with the wallet's
   address-reuse policy *and* the selection algorithms.  Implementing
   only the algorithm side without the wallet side is half a fix.
   Impls that did not start with avoid_partial_spends in mind
   typically lack BOTH halves.

4. **"Anti-fee-sniping degenerate"** — `IsCurrentForAntiFeeSniping`
   + rand(10)/rand(100) is a Core privacy refinement that nearly every
   non-Core impl misses. Same shape across the fleet; would benefit
   from a single fleet-wide "anti-fee-sniping parity" sweep.

5. **"Tie-breaker erosion"** — When porting an algorithm, the
   comparator lambda is often simplified to "by value descending"
   without the tie-breaker. This is the "stable sort assumed but
   actually unspecified" trap.  Every BnB port that I've reviewed in
   the fleet appears to drop the `fee - long_term_fee` tie-breaker.
   Fleet sweep candidate.

6. **"Waste comparison after-the-fact"** — Even impls that *do* run
   multiple algorithms (e.g. some Rust impls per prior W118 audit)
   often run them in sequence and pick the first success rather than
   storing all results and `min_element`ing on waste. This is a
   distinct anti-pattern from #1 — running multiple algorithms is the
   *first* step but is necessary-not-sufficient. Worth checking in a
   future fleet audit whether impls that have SRD also have the
   `min_element` step.

## Recommended fix decomposition

Future fix waves (NO production change in W129):

- **FIX-N (P0-CDIV, nimrod)**: BnB sort tie-breaker (BUG-1). 5-LOC
  fix, smallest correctness gain, candidate for an "I-can't-believe-this-shipped"
  micro-PR.
- **FIX-N+1 (P0-CDIV, fleet)**: SRD + multi-algo waste comparison
  (BUG-3, BUG-5). Pair as one wave because adding SRD without the
  comparison would not change selected inputs. ~80 LOC.
- **FIX-N+2 (P0-CDIV, nimrod)**: waste metric `+ excess` term fix
  in calculateWaste, including the `target` parameter rework
  (BUG-10 + BUG-11). Prerequisite for the comparison being meaningful.
  ~25 LOC.
- **FIX-N+3 (P1, nimrod)**: `CoinSelectionParams` struct (BUG-7) +
  thread through long-term/discard/consolidate feerates (BUG-14,
  BUG-15, BUG-16). Plumbing for BUG-17 and BUG-18.
- **FIX-N+4 (P0-CDIV, nimrod)**: CoinGrinder (BUG-4). Largest single
  fix; defer until FIX-N+3 lands so it can consume the params struct.
- **FIX-N+5 (P1, nimrod)**: OutputGroup + avoid_partial_spends
  (BUG-6).
- **FIX-N+6 (P1, nimrod)**: SFFO + BnB skip (BUG-12, BUG-13).
- **FIX-N+7 (P1, nimrod)**: GenerateChangeTarget privacy randomization
  (BUG-8, BUG-9). Self-contained.
- **FIX-N+8 (P1, nimrod)**: anti-fee-sniping IsCurrent guard +
  randomization (BUG-21).
- **FIX-N+9 (P1, nimrod)**: max_selection_weight enforcement (BUG-19).
  Self-contained.
- **FIX-N+10 (LOW, nimrod)**: bump_fee_group_discount tracking
  (BUG-20). Self-contained but requires `ancestor_bump_fees` on the
  coin record.

Pair-with-W113 note: FIX-N+2 would close W113 BUG-6 (G22) and W113
BUG-7 (G22) simultaneously. FIX-N+8 would close W113 BUG-8/9
(G25/G26). FIX-N+9 would close W113 BUG-15 (G30).

## References

- `bitcoin-core/src/wallet/coinselection.h` — types, params, constants
- `bitcoin-core/src/wallet/coinselection.cpp` — algorithm bodies
  (`SelectCoinsBnB`:93, `CoinGrinder`:325, `SelectCoinsSRD`:536,
  `KnapsackSolver`:652, `GenerateChangeTarget`:809,
  `RecalculateWaste`:827)
- `bitcoin-core/src/wallet/spend.cpp` — `AttemptSelection`:740,
  `DiscourageFeeSniping`:993, `CreateTransactionInternal`:1063
- `bitcoin-core/src/wallet/feebumper.cpp` — bumpfee re-uses inputs;
  consumes `CoinSelectionParams` for the rebuild

## Test file

xfail regression guards live at
`tests/test_w129_coin_selection.nim`. Each MISSING / PARTIAL gate has
a `test` that documents the current (wrong / missing) behavior with a
`check` that asserts the WRONG value, plus a TODO comment naming the
expected behavior. When a future FIX wave lands, the `check` flips to
the correct value and the test acts as a post-fix regression guard.
