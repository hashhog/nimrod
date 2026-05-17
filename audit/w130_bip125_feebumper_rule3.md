# W130 — BIP-125 RBF feebumper Rule 3 audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change)
Target: `src/wallet/feebumper.nim` (`createRateBumpTransaction`,
`preconditionChecks`, `isWalletInput`), with cross-checks against
`src/mempool/mempool.nim` (`checkRbfRules`, `isRbfOptIn`,
`signalsOptInRBF`) and the bumpfee RPC harness at
`src/rpc/server.nim:doBumpFee` / `handleBumpFee` /
`handlePsbtBumpFee`.
Reference: Bitcoin Core
- `src/wallet/feebumper.{h,cpp}` — `PreconditionChecks`,
  `CheckFeeRate`, `EstimateFeeRate`, `CreateRateBumpTransaction`,
  `CommitTransaction`, `MarkReplaced`
- `src/policy/rbf.{cpp,h}` — `PaysForRBF`, `GetEntriesForConflicts`,
  `EntriesAndTxidsDisjoint`, `ImprovesFeerateDiagram`
- `src/policy/feerate.{cpp,h}` — `CFeeRate::GetFee`,
  `EvaluateFeeUp` (rounds up)
- `src/wallet/wallet.h:124` — `WALLET_INCREMENTAL_RELAY_FEE = 5000`
- BIP-125 (replace-by-fee signalling and the 5-rule replacement
  policy)

Cross-reference with **W120** ("mempool RBF rules"). W120 covered the
mempool-side `checkRbfRules` (rules 1-5 + Rule #8 cluster diagram).
W130 takes the next-deeper cut: the **wallet-side `feebumper`** —
`PreconditionChecks` (5 distinct checks) and `CheckFeeRate` (5
distinct precise-invariant checks), plus the `EstimateFeeRate`
fall-through. These checks happen BEFORE the replacement tx ever
hits the mempool; a wallet that diverges here will construct a
replacement that the mempool subsequently rejects, surfacing as
RPC-level confusion ("bumpfee" claimed success then "Mempool
rejected replacement" on submit), or — worse — that the mempool
accepts but with insufficient fee under Core's rules.

The W120 P1/P2 findings (BUG-1 / BUG-2 incremental relay fee 10x
off; BUG-3 hardcoded `bip125-replaceable=true`; BUG-4 Rule #5 tx-
count vs cluster-count; BUG-5 cluster diagram dead-helper; BUG-7 /
BUG-8 / BUG-9 RPC field divergence) are **NOT** re-classified here.
FIX-69 closed BUG-1 / BUG-2 / BUG-10 (the unit-bug cluster); FIX-79
closed BUG-5 (dead-helper validateRbfDiagram). W130 picks up where
W120 left off and audits the wallet-facing surface that W120 only
glanced at (W120 G25-G27 named `createRateBumpTransaction` as
PRESENT but did not audit its 5+5 internal checks). New BUGs are
numbered fresh (BUG-1-W130 .. BUG-N-W130).

## Status

**BUGS FOUND — 14 distinct gates MISSING / PARTIAL (of 30).**

Of those 14:

- **3 are universal correctness divergence (CDIV)** that would cause
  nimrod's wallet to construct a replacement transaction that
  diverges from Core given identical wallet state.
- **5 are precise-invariant divergence (CDIV-precise)** — nimrod
  applies the constraint conceptually but with a different formula
  (different operand, different ordering, different rounding) than
  Core, so for specific (vsize, fee) combinations at the boundary
  nimrod will either accept-where-Core-rejects or reject-where-
  Core-accepts.
- **3 are MISSING precondition checks** — nimrod skips guards that
  Core enforces, so bumpfee can be invoked on transactions Core
  refuses to bump (mined / already-bumped / has-wallet-spend).
- **2 are wallet-bookkeeping** (no `MarkReplaced` /
  `replaces_txid` / `replaced_by_txid` mapValue bookkeeping; no
  bumpfee idempotency guard via `replaced_by_txid`).
- **1 is missing combined_bump_fee plumbing** (Core's
  `calculateCombinedBumpFee` for unconfirmed-UTXO ancestors).

The CDIV cluster is concentrated in:

1. **Rule 3 precise invariant is wrong** (G14, G15, BUG-1) —
   nimrod enforces:
   `newFeeRate >= max(minRelayFee, oldFeeRateSatVb + incrementalRelayFeeSatVb)`
   (feebumper.nim:290-292). Core's `CheckFeeRate` enforces an
   ADDITIVE invariant on the **total fee at the maxTxSize**:
   `new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`
   (feebumper.cpp:93-99). The two are equivalent only when
   `vsize_old == vsize_new`; for any replacement that picks up
   additional inputs (Core's common case under
   `m_allow_other_inputs=true`), nimrod's feerate-only check
   admits replacements Core rejects (replacement has higher
   feerate but lower absolute fee bump than Core's
   `incrementalRelayFee.GetFee(maxTxSize)` floor).

2. **WALLET_INCREMENTAL_RELAY_FEE floor missing** (G16, BUG-2) —
   Core's `EstimateFeeRate` uses
   `std::max(node_incremental_relay_fee, wallet_incremental_relay_fee)`
   where `wallet_incremental_relay_fee = CFeeRate(5000)` =
   5 sat/vB (Core wallet.h:124; feebumper.cpp:135-137). This is
   ~50x the network default (0.1 sat/vB) and is explicit future-
   proofing against network-wide bumps. nimrod's
   `createRateBumpTransaction` consumes only the caller-supplied
   `incrementalRelayFeeSatVb` and has no wallet-side floor — so
   the auto-bump (no user feeRate) is at risk of being too low to
   actually evict if the network later raises its incremental
   relay fee.

3. **`+1 sat` Rule 3 strict-gt floor missing** (G13, BUG-3) —
   Core's `EstimateFeeRate` adds `+1` sat to the original
   feerate (feebumper.cpp:124-126) before adding the
   incremental — this is the "always strictly above the old
   feerate" pre-floor that ensures Rule 3's `>=` doesn't become
   a tie under integer rounding when the bump originally needed
   only a few sats. nimrod has no equivalent — it computes
   `oldFeeRateSatVb` as floating point and uses it directly.

The remaining 11 BUGs are MEDIUM / LOW (missing precondition
guards, wallet bookkeeping, edge-case rounding) and would not by
themselves cause a chain split / mempool consensus mismatch, but
they mean a real `bumpfee` invocation on nimrod can succeed where
Core refuses (bumping a mined tx via stale wallet state, bumping
a tx that's already been bumped, etc.) — surface area for wallet-
to-wallet incompatibility and operator confusion.

## Methodology

1. Read Bitcoin Core refs end-to-end:
   `src/wallet/feebumper.cpp` (386 LOC), `feebumper.h` (128 LOC),
   `src/policy/rbf.cpp` (141 LOC), `rbf.h` (110 LOC),
   `src/policy/feerate.{cpp,h}` (38+82 LOC), and the relevant
   bits of `src/wallet/wallet.h:124` (WALLET_INCREMENTAL_RELAY_FEE).
2. Re-read BIP-125 and confirmed Core's wallet-side enforcement
   is **strictly stronger** than the BIP's mempool-side rules
   (the wallet adds: rejects re-bump, requires-mine option,
   uses wallet incremental fee floor, max_tx_fee guard, requires
   all original inputs reused even though BIP only requires
   conflict-with-one).
3. Synthesised a 30-gate audit matrix split as:
   - G1-G5  : BIP-125 wire constants + signaling (W120 carry-
     forward, audited again at wallet boundary)
   - G6-G10 : `PreconditionChecks` 5 checks + edge cases
   - G11-G18: `CheckFeeRate` 5 checks + Rule 3 PRECISE INVARIANT
     (the wave's headline)
   - G19-G22: `EstimateFeeRate` 4-stage formula
   - G23-G26: `CreateRateBumpTransaction` orchestration
   - G27-G30: `CommitTransaction` + `MarkReplaced` + RPC error
     mapping + bumpfee/psbtbumpfee parity
4. Walked `src/wallet/feebumper.nim` (362 LOC) end-to-end,
   cross-referencing each Core construct with grep on the nimrod
   side. Found 14 gates that are MISSING or PARTIAL.
5. Cross-checked with W120 / FIX-69 / FIX-79 / FIX-70 to confirm
   none of the W130 BUGs duplicate already-known surface.
6. Wrote 30 test gates at
   `tests/test_w130_bip125_feebumper_rule3.nim`. Each gate either
   confirms a Core-aligned behaviour (`check` passes today; would
   regress if a future change broke it) or documents the CURRENT
   (wrong / missing) behaviour with an inline TODO comment and a
   `check` that asserts the CURRENT (wrong) value so the test acts
   as a post-fix xfail / regression guard. The mid-suite tests
   that require a live wallet + mempool + chainState fixture use
   the same skeleton as W120 (`newChainState`, `newMempool`,
   `MempoolEntry` direct insert) — no SQL / no network — so they
   run in <2s on the smoke harness.

## Gate matrix

### BIP-125 wire constants / signaling (W120 carry-forward)

#### G1: `MAX_BIP125_RBF_SEQUENCE == 0xfffffffd` — **PRESENT**
nimrod `src/mempool/mempool.nim:125` (`MaxBip125RbfSequence`
constant). Core `src/util/rbf.h:8`. Cross-confirmed by W118 / FIX-70.

#### G2: `signalsOptInRBF` predicate — **PRESENT**
nimrod `src/mempool/mempool.nim:1763` — any input with `sequence
<= 0xfffffffd` → opt-in. Matches Core `util/rbf.cpp:SignalsOptInRBF`.

#### G3: `isRbfOptIn` ancestor inheritance — **PRESENT**
nimrod `src/mempool/mempool.nim:1774` walks ancestors. Matches
Core `policy/rbf.cpp:IsRBFOptIn`.

#### G4: `MAX_REPLACEMENT_CANDIDATES == 100` — **PRESENT**
nimrod `src/mempool/mempool.nim:127`. Cross-confirmed by W120 G2.

#### G5: `MaxBip125RbfSequence` exposed to wallet — **PRESENT**
nimrod feebumper.nim:339-340 sets `replaceableSeq` to `0xfffffffd`
when `req.replaceable` else `0xfffffffe` (NOT `0xffffffff`, which
would disable locktime — matches Core `wallet/rpc/spend.cpp:990`).

### PreconditionChecks 5 distinct checks (Core feebumper.cpp:23-57)

#### G6: HasWalletSpend (tx has descendants in wallet) — **MISSING — BUG-4**

Core `feebumper.cpp:25-28`:
```cpp
if (wallet.HasWalletSpend(wtx.tx)) {
    errors.emplace_back("Transaction has descendants in the wallet");
    return Result::INVALID_PARAMETER;
}
```

nimrod `feebumper.nim:99-186` (`preconditionChecks`) has **no
equivalent check** — it only checks `mempool.isSpent(op)` for
in-mempool descendants (G7 below). A wallet that has built a
chain of unconfirmed transactions in its own wallet store
(without yet broadcasting children) can still call bumpfee on
the parent, breaking the child chain locally.

File: `src/wallet/feebumper.nim:99-186`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:25-28`,
`bitcoin-core/src/wallet/wallet.cpp:HasWalletSpend`.
Severity: P2-WALLET (wallet-only, no consensus impact).

#### G7: hasDescendantsInMempool — **PRESENT**

nimrod `feebumper.nim:129-133`:
```nim
for outIdx in 0 ..< origTx.outputs.len:
  let op = OutPoint(txid: origTxid, vout: uint32(outIdx))
  if mempool.isSpent(op):
    raiseBfe(bfeInvalidParameter,
      "Transaction has descendants in the mempool")
```

Matches Core `feebumper.cpp:31-35` (via `wallet.chain().
hasDescendantsInMempool`). Maps correctly to `INVALID_PARAMETER`.

#### G8: GetTxDepthInMainChain != 0 (mined-or-conflicted) — **MISSING — BUG-5**

Core `feebumper.cpp:37-40`:
```cpp
if (wallet.GetTxDepthInMainChain(wtx) != 0) {
    errors.emplace_back("Transaction has been mined, or is conflicted with a mined transaction");
    return Result::WALLET_ERROR;
}
```

nimrod relies solely on the `mempool.contains(origTxid)` check
(feebumper.nim:124). If the wallet UI / RPC caller passes a
txid for a transaction that **was** in the mempool but has since
been mined into a block, `mempool.contains` returns false and
nimrod raises `bfeInvalidAddressOrKey` ("Invalid or non-wallet
transaction id") rather than Core's distinct `WALLET_ERROR`
("Transaction has been mined"). Operator gets a confusing error
mapping (the txid IS valid, it's just confirmed).

File: `src/wallet/feebumper.nim:124-126`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:37-40`.
Severity: P2-RPC (error-code parity).

#### G9: `replaced_by_txid` mapValue guard — **MISSING — BUG-6**

Core `feebumper.cpp:42-45`:
```cpp
if (wtx.mapValue.contains("replaced_by_txid")) {
    errors.push_back(strprintf("Cannot bump transaction %s which was already bumped by transaction %s", ...));
    return Result::WALLET_ERROR;
}
```

nimrod has **no equivalent**. The wallet `WalletTx` type does
not even have a `mapValue` / metadata blob (grep on
`src/wallet/wallet.nim` and `src/wallet/types.nim` finds zero
references to `replaced_by_txid`, `replaces_txid`, or
`mapValue`). Consequence: calling bumpfee twice on the same
original txid produces TWO replacement transactions instead of
returning `WALLET_ERROR`. The second succeeds in nimrod, fails
in Core. (Both may be subsequently evicted by the mempool's
RBF rules, but the wallet-side bookkeeping diverges from
Core's invariant that a bumped tx is permanently retired in
the wallet.)

File: `src/wallet/feebumper.nim:99-186` (entire
preconditionChecks function), `src/wallet/wallet.nim` (no
mapValue / replaced_by_txid plumbing anywhere).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:42-45`,
`bitcoin-core/src/wallet/feebumper.cpp:371-380` (commit-side
sets `mapValue["replaces_txid"]`, then `MarkReplaced`).
Severity: P1-WALLET (idempotency / double-bump prevention).

#### G10: AllInputsMine (require_mine path) — **PRESENT**

nimrod `feebumper.nim:140-185` walks every input and checks
`isWalletInput`. When `requireMine` is set (bumpfee, not
psbtbumpfee — see `doBumpFee:6972`), a non-wallet input raises
`bfeWalletError`. Matches Core `feebumper.cpp:47-54`.

### CheckFeeRate 5 distinct checks (Core feebumper.cpp:60-117) — **HEADLINE**

#### G11: minMempoolFeeRate floor (mempool minimum fee) — **MISSING — BUG-7**

Core `feebumper.cpp:67-75`:
```cpp
CFeeRate minMempoolFeeRate = wallet.chain().mempoolMinFee();
if (newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) {
    errors.push_back("New fee rate (%s) is lower than the minimum fee rate (%s) to get into the mempool");
    return Result::WALLET_ERROR;
}
```

nimrod has a `minRelayFeeSatVb` arg (feebumper.nim:197) but the
caller passes `rpc.mempool.minFeeRate` (server.nim:6957), which
is the **static** `minFeeRate` field on the mempool (constant
from constructor). It is NOT the rolling minimum / dynamic
`mempoolMinFee` that Core's `mempoolMinFee()` returns (which
incorporates the rolling-floor eviction-rate bump from
`incrementalRelayFeeRate`). nimrod has a separate
`getMinFee` proc (mempool.nim:1545) that IS rolling-floor-aware
(returns `max(rollingMinimumFeeRate, incrementalRelayFeeRate)`
in sat/vbyte) but it isn't plumbed through here. Net: nimrod
uses the wrong floor when the mempool is congested — exactly
the case where the operator most needs an accurate floor.

File: `src/wallet/feebumper.nim:290`,
`src/rpc/server.nim:6957`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:67-75`,
`bitcoin-core/src/txmempool.cpp:CTxMemPool::GetMinFee`.
Severity: P1-CDIV (different bumpfee accept/reject under
congestion).

#### G12: calculateCombinedBumpFee for unconfirmed UTXO ancestors — **MISSING — BUG-8**

Core `feebumper.cpp:77-87`:
```cpp
std::vector<COutPoint> reused_inputs;
...
const std::optional<CAmount> combined_bump_fee = wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate);
if (!combined_bump_fee.has_value()) {
    errors.push_back("Failed to calculate bump fees, because unconfirmed UTXOs depend on an enormous cluster of unconfirmed transactions.");
    return Result::WALLET_ERROR;
}
CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
```

nimrod has **no `calculateCombinedBumpFee` helper**. The
formula it uses for the new total fee is
`newFeeTarget = ceil(newFeeRate * vsizeEst)`
(feebumper.nim:299) — the ancestor-bump contribution is zero.
If the replacement tx ends up using an unconfirmed input
(CPFP ancestor in the mempool), nimrod under-funds the
replacement vs Core's accounting. (In practice nimrod's
`new_coin_control.m_min_depth = 1` equivalent is not even
plumbed — see BUG-12 — so unconfirmed inputs CAN be picked
up by the rebuild, compounding the gap.)

File: `src/wallet/feebumper.nim:299`,
`src/storage/chainstate.nim` (no
`calculateCombinedBumpFee` proc).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:77-87`,
`bitcoin-core/src/node/interfaces.cpp` (chain impl).
Severity: P1-CDIV (CPFP-input replacement underfunded).

#### G13: `+1 sat` strict-gt pre-floor on oldFeeRate — **MISSING — BUG-3**

Core `feebumper.cpp:122-126`:
```cpp
int64_t txSize = GetVirtualTransactionSize(*(wtx.tx));
CFeeRate feerate(old_fee, txSize);
feerate += CFeeRate(1);   // +1 sat/kvB (NOT sat/vB; CFeeRate ctor is per-kvB)
```

This is Core's "always above the rounded-down feerate" pre-
floor, explicitly there to make Rule 3 strict-gt after
`CFeeRate` integer rounding. The `CFeeRate(1)` constructor
takes sat/**kvB** (`feerate.h:41`).

nimrod's equivalent at feebumper.nim:288-289:
```nim
let oldFeeRateSatVb =
  if vsizeEst <= 0: 0.0 else: float64(int64(oldFee)) / float64(vsizeEst)
```

Uses floating-point division — no `+1 sat/kvB` adjustment.
Edge case: an original tx with `old_fee=300 sat, vsize=300vB`
gives `oldFeeRateSatVb=1.0`. nimrod's `minReqFeeRate = max(
minRelay, 1.0 + 0.1) = 1.1 sat/vB`. Core: `feerate(300, 300) =
1000 sat/kvB`, then `+= CFeeRate(1) = 1001 sat/kvB`, then
`+= max(100, 5000) = 6001 sat/kvB = 6.001 sat/vB`. Vast
divergence: nimrod's auto-bump pays 1.1 sat/vB where Core
pays 6 sat/vB.

File: `src/wallet/feebumper.nim:288-289`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:122-126`,
`src/policy/feerate.h:41`.
Severity: **P0-CDIV** (combined with BUG-2 the auto-bump
diverges from Core by a factor of ~5-6x).

#### G14: Rule 3 precise invariant — additive total-fee form — **WRONG FORMULA — BUG-1**

This is the wave's headline.

Core `feebumper.cpp:88-99` (Rule 3 precise invariant):
```cpp
CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
CFeeRate incrementalRelayFee = wallet.chain().relayIncrementalFee();
CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
if (new_total_fee < minTotalFee) {
    errors.push_back(strprintf("Insufficient total fee %s, must be at least %s ...",
        FormatMoney(new_total_fee), FormatMoney(minTotalFee), ...));
    return Result::INVALID_PARAMETER;
}
```

Note three precise details:
1. The invariant is on **total fee** (absolute sats), not on
   the feerate (sats/vB).
2. The bandwidth charge is `incrementalRelayFee.GetFee(maxTxSize)`
   — **the replacement's maxTxSize**, not the original's vsize.
3. `CFeeRate::GetFee` rounds the result **up** via
   `EvaluateFeeUp` (`feerate.cpp:24`).

nimrod's check at feebumper.nim:287-295:
```nim
let oldFeeRateSatVb =
  if vsizeEst <= 0: 0.0 else: float64(int64(oldFee)) / float64(vsizeEst)
let minReqFeeRate = max(minRelayFeeSatVb,
                        oldFeeRateSatVb + incrementalRelayFeeSatVb)
if newFeeRate < minReqFeeRate:
  raiseBfe(bfeInvalidParameter, "Insufficient fee rate (must exceed " &
    $minReqFeeRate & " sat/vB; got " & $newFeeRate & ")")
```

This is a **feerate** check, not a **total-fee** check.
It is equivalent to Core's check **only when**
`vsize_old == vsize_new`. For replacements that pick up
additional inputs (Core's common case with
`m_allow_other_inputs=true` at feebumper.cpp:309), nimrod's
formula misses entirely:

- Example: original tx is `old_fee=1000, vsize=200vB` (5 sat/vB).
  Replacement adds one input → `vsize_new=300vB`. New fee
  required by Core: `1000 + 0.1 * 300 = 1030 sat`. nimrod's
  check passes anything at `>= 5.1 sat/vB * 300 = 1530 sat`
  — **over-charges** by 500 sats.
- Example: original tx is `old_fee=1000, vsize=200vB` (5 sat/vB).
  Replacement REMOVES one input + uses new outputs → `vsize_new
  =100vB`. New fee required by Core: `1000 + 0.1 * 100 = 1010
  sat`. nimrod accepts anything at `>= 5.1 * 100 = 510 sat`
  — **under-charges** by 500 sats. Mempool then rejects.

File: `src/wallet/feebumper.nim:287-295`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:88-99`.
Severity: **P0-CDIV** (Rule 3 precise invariant diverges from
Core; both directions: over- and under-charge depending on
input-set change).

#### G15: `incrementalRelayFee.GetFee(maxTxSize)` rounds up — **MISSING — BUG-9**

`CFeeRate::GetFee` always rounds up via `EvaluateFeeUp`
(`feerate.cpp:24`). nimrod's
`int64(incrementalRelayFee * float64(txVsize))` at
`mempool.nim:1891` does float multiplication then truncates to
int64 — **rounds toward zero**, not up. For a 200vB replacement
at 0.1 sat/vB incremental, Core charges
`ceil(0.1 * 200) = 20` sats; nimrod charges `int64(20.0) = 20`
— same. But for 199vB: Core charges `ceil(0.1 * 199) =
ceil(19.9) = 20`; nimrod `int64(19.9) = 19`. Off-by-one in
nimrod's favor, but it's a Core-invariant violation. Same bug
applies to feebumper-side (which goes through the same path).

File: `src/mempool/mempool.nim:1891`,
`src/wallet/feebumper.nim:299` (`ceil`-based, **correct here**,
but inconsistent with the mempool path).
Reference: `bitcoin-core/src/policy/feerate.cpp:24`
(`EvaluateFeeUp`).
Severity: P3-LOW (off-by-one round, but cross-impl divergence
worth pinning).

#### G16: `WALLET_INCREMENTAL_RELAY_FEE = 5000` wallet-side floor — **MISSING — BUG-2**

Core `feebumper.cpp:135-137`:
```cpp
CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);
```

Core's `WALLET_INCREMENTAL_RELAY_FEE` is 5000 sat/kvB = 5 sat/vB
(wallet.h:124). This is 50x the network default
(`DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB`).
Comment at feebumper.cpp:128-134:
> The node has a configurable incremental relay fee. Increment
> the fee by the minimum of that and the wallet's conservative
> WALLET_INCREMENTAL_RELAY_FEE value to **future proof against
> changes to network wide policy for incremental relay fee that
> our node may not be aware of**.

nimrod uses only `incrementalRelayFeeSatVb` from the caller
(feebumper.nim:291), no `WALLET_INCREMENTAL_RELAY_FEE` constant
exists in nimrod (grep confirms). For the auto-bump (no user
feeRate), nimrod's auto-bump can be 50x lower than Core's.

File: `src/wallet/feebumper.nim:290-291`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:135-137`,
`bitcoin-core/src/wallet/wallet.h:124`.
Severity: **P0-CDIV** (auto-bump diverges from Core by ~50x).

#### G17: GetRequiredFee floor — **MISSING — BUG-10**

Core `feebumper.cpp:101-106`:
```cpp
CAmount requiredFee = GetRequiredFee(wallet, maxTxSize);
if (new_total_fee < requiredFee) {
    errors.push_back("Insufficient total fee (cannot be less than required fee %s)");
    return Result::INVALID_PARAMETER;
}
```

`GetRequiredFee` is the wallet's `m_min_fee` (or
`DEFAULT_TRANSACTION_MINFEE` = 1000 sat/kvB if unset).
nimrod has no equivalent — no `GetRequiredFee` proc, no
`min_fee` wallet setting in `wallet.params`.

File: `src/wallet/feebumper.nim` (entire), `src/wallet/wallet.nim`
(no `minFee` / `requiredFee` field).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:101-106`,
`bitcoin-core/src/wallet/fees.cpp:GetRequiredFee`.
Severity: P2-WALLET (Core wallet absolute-minimum-fee
parameter not honored).

#### G18: maxTxFee guard (`m_default_max_tx_fee`) — **MISSING — BUG-11**

Core `feebumper.cpp:109-114`:
```cpp
const CAmount max_tx_fee = wallet.m_default_max_tx_fee;
if (new_total_fee > max_tx_fee) {
    errors.push_back(strprintf("Specified or calculated fee %s is too high (cannot be higher than -maxtxfee %s)"));
    return Result::WALLET_ERROR;
}
```

Default `m_default_max_tx_fee = DEFAULT_TRANSACTION_MAXFEE =
0.1 BTC` = 10_000_000 sats — a safety guard against fat-finger
"specify 5000 sat/vB instead of 5" mistakes.

nimrod has no `maxTxFee` / `defaultMaxTxFee` field anywhere
(grep on `src/wallet/`). A user typo (sat/vB instead of sat/kvB)
would let bumpfee build a tx that pays the entire wallet
balance as fee.

File: `src/wallet/feebumper.nim` (entire), `src/wallet/wallet.nim`,
`src/consensus/params.nim` (no `defaultMaxTxFee`).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:109-114`,
`bitcoin-core/src/wallet/wallet.h:DEFAULT_TRANSACTION_MAXFEE`.
Severity: **P1-WALLET** (no fat-finger guard — operator UX +
"don't burn the wallet").

### EstimateFeeRate (auto-bump) — Core feebumper.cpp:119-144

#### G19: oldFeeRate base derived from `GetVirtualTransactionSize` — **PARTIAL**

Core: `int64_t txSize = GetVirtualTransactionSize(*(wtx.tx))` —
the ACTUAL signed tx size from the on-chain wire image.

nimrod feebumper.nim:279-285 uses
`validation.calculateTransactionWeight(origTx)` then `/4` —
correct in principle. But the fallback at line 281-285 adds
`newTx.inputs.len * 110` (assumed P2WPKH witness budget) only
when weight is 0, which is a very rough heuristic; Core uses
the actual witness bytes. Minor.

File: `src/wallet/feebumper.nim:279-285`.
Severity: P3-MINOR (only affects degenerate "stripped witness"
case).

#### G20: `+= CFeeRate(1)` — see G13 / BUG-3 — **MISSING**

#### G21: `+= std::max(node_incremental, wallet_incremental)` — see G16 / BUG-2 — **MISSING**

#### G22: `std::max(feerate, min_feerate)` final clamp — **MISSING — BUG-12**

Core `feebumper.cpp:139-143`:
```cpp
CFeeRate min_feerate(GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr));
return std::max(feerate, min_feerate);
```

The wallet's `GetMinimumFeeRate` derives from
`coin_control.m_feerate`, `m_confirm_target`, or estimator —
and is used as the **lower bound** on the auto-bump feerate.

nimrod's auto-bump path at feebumper.nim:257-261:
```nim
var newFeeRate = req.feeRate
if newFeeRate <= 0.0:
  newFeeRate = estimatorFeeRate
if newFeeRate <= 0.0:
  raiseBfe(bfeWalletError, "Unable to determine new fee rate ...")
```

— if `req.feeRate` is provided, the estimator-based floor is
never consulted; in particular, the wallet's
`coin_control.m_feerate` floor isn't applied. nimrod's auto-
bump can be LOWER than the wallet's configured minimum-feerate.

File: `src/wallet/feebumper.nim:257-261`.
Reference: `bitcoin-core/src/wallet/feebumper.cpp:139-143`.
Severity: P2-WALLET (wallet-configured floor bypassed).

### CreateRateBumpTransaction orchestration

#### G23: original_change_index OOB validation — **MISSING — BUG-13**

Core `feebumper.cpp:181-184`:
```cpp
if (original_change_index.has_value() && original_change_index.value() >= wtx.tx->vout.size()) {
    errors.emplace_back("Change position is out of range");
    return Result::INVALID_PARAMETER;
}
```

nimrod has no `original_change_index` field on `BumpFeeRequest`
(feebumper.nim:42-49). Caller cannot designate which output to
recycle as change.

File: `src/wallet/feebumper.nim:42-49`.
Severity: P2-RPC (option not exposed to user).

#### G24: `new_coin_control.m_min_depth = 1` (Rule 2 wallet-side) — **MISSING — BUG-14**

Core `feebumper.cpp:311-312`:
```cpp
// We cannot source new unconfirmed inputs(bip125 rule 2)
new_coin_control.m_min_depth = 1;
```

This is the wallet-side BIP-125 Rule 2 enforcement (replacement
can't spend a conflict's output). nimrod's createRateBumpTransaction
does NOT add new inputs at all (comment at feebumper.nim:222-231
documents this as a deliberate simplification — "stuck-without-
change is the documented failure mode"). However if any future
fix wave wires up `selectCoins` for the rebuild, the
`m_min_depth=1` constraint must be threaded in.

File: `src/wallet/feebumper.nim:222-231` (current scope) and
`src/wallet/coinselection.nim` (no `minDepth` parameter).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:311-312`.
Severity: P3-LATENT (gap will surface when stuck-without-change
gets fixed; not currently exploitable).

#### G25: `m_allow_other_inputs = true` — **MISSING** (related to G24)

Same scope: nimrod doesn't reuse selectCoins on rebuild, so
this flag is moot. Documented for parity.

#### G26: `wtx.vin` re-selected via `new_coin_control.Select` — **PRESENT (different mechanism)**

Core re-selects every original input. nimrod retains the
original inputs (feebumper.nim:267) and doesn't add new ones.
Net effect: BIP-125 sender-side requirement that the
replacement consumes the same inputs is honored.

### CommitTransaction / MarkReplaced / RPC

#### G27: `mapValue["replaces_txid"]` recorded — **MISSING — BUG-15**

Core `feebumper.cpp:371-372`:
```cpp
mapValue_t mapValue = oldWtx.mapValue;
mapValue["replaces_txid"] = oldWtx.GetHash().ToString();
```

nimrod has no `mapValue` plumbing. The replacement tx is
submitted via `mempool.acceptTransaction` (server.nim:7000) but
no provenance link is stored in the wallet's tx records. A
subsequent RPC `gettransaction` cannot tell that one tx
replaced another.

File: `src/rpc/server.nim:7000`,
`src/wallet/wallet.nim` (no mapValue).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:371-372`.
Severity: P2-WALLET (provenance not tracked).

#### G28: MarkReplaced sets `mapValue["replaced_by_txid"]` on original — **MISSING — BUG-16** (pairs with BUG-6)

Core `feebumper.cpp:378-380`:
```cpp
if (!wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)) {
    errors.emplace_back("Created new bumpfee transaction but could not mark the original transaction as replaced");
}
```

nimrod has no `MarkReplaced` proc on Wallet. The original tx
remains in wallet records without any "this was bumped"
marker. (This is the write-side of G9 / BUG-6.)

File: `src/wallet/wallet.nim` (no `markReplaced`).
Reference: `bitcoin-core/src/wallet/feebumper.cpp:378-380`,
`src/wallet/wallet.cpp:CWallet::MarkReplaced`.
Severity: P1-WALLET (pairs with BUG-6 — no idempotency
on double-bump).

#### G29: bumpFeeKindToRpcCode maps all 4 BumpFeeErrorKind — **PRESENT**

nimrod `src/rpc/server.nim:6936-6941` maps each
`BumpFeeErrorKind` to the correct Core RPC code:
- `bfeInvalidAddressOrKey` → `RpcInvalidAddressOrKey` (-5)
- `bfeInvalidParameter` → `RpcInvalidParams` (-8)
- `bfeWalletError` → `RpcWalletError` (-4)
- `bfeMiscError` → `RpcMiscError` (-1)

Matches Core's mapping in `wallet/rpc/spend.cpp:bumpfee_helper`.

#### G30: bumpfee vs psbtbumpfee `require_mine` distinction — **PRESENT**

nimrod `src/rpc/server.nim:6972` flips `requireMine = not
wantPsbt`. Matches Core: bumpfee requires-mine, psbtbumpfee
permits foreign inputs (caller fills via PSBT later).

## BUGs summary table

| ID | Gate | Severity | One-line |
|----|------|----------|----------|
| BUG-1-W130 | G14 | **P0-CDIV** | Rule 3 enforced as feerate, Core enforces total-fee; diverges whenever vsize changes |
| BUG-2-W130 | G16 | **P0-CDIV** | No `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB` floor; auto-bump ~50x lower than Core |
| BUG-3-W130 | G13 | **P0-CDIV** | No `+1 sat/kvB` strict-gt pre-floor on oldFeeRate |
| BUG-4-W130 | G6  | P2-WALLET | No `HasWalletSpend` check |
| BUG-5-W130 | G8  | P2-RPC | No `GetTxDepthInMainChain != 0` check (mined-tx error parity) |
| BUG-6-W130 | G9  | P1-WALLET | No `replaced_by_txid` idempotency guard |
| BUG-7-W130 | G11 | P1-CDIV | Uses static `minFeeRate`, not dynamic `mempoolMinFee` (rolling-floor-aware) |
| BUG-8-W130 | G12 | P1-CDIV | No `calculateCombinedBumpFee` for unconfirmed-UTXO ancestors |
| BUG-9-W130 | G15 | P3-LOW  | Mempool path truncates incremental fee, Core rounds up via `CFeeRate::GetFee` |
| BUG-10-W130 | G17 | P2-WALLET | No `GetRequiredFee` floor |
| BUG-11-W130 | G18 | **P1-WALLET** | No `m_default_max_tx_fee` fat-finger guard |
| BUG-12-W130 | G22 | P2-WALLET | No `std::max(feerate, min_feerate)` final clamp |
| BUG-13-W130 | G23 | P2-RPC | No `original_change_index` parameter |
| BUG-14-W130 | G24 | P3-LATENT | No `m_min_depth = 1` for replacement-rebuild (gap surfaces if stuck-without-change is fixed) |
| BUG-15-W130 | G27 | P2-WALLET | No `mapValue["replaces_txid"]` provenance |
| BUG-16-W130 | G28 | P1-WALLET | No `MarkReplaced` (pairs with BUG-6) |

**Total: 16 BUGs across 14 distinct gates** (BUG-3 and BUG-2 both
hit G13/G16/G21 in the EstimateFeeRate path; BUG-6/BUG-16 both
land at the `replaced_by_txid` mapValue surface). Counting by
distinct gate-coverage gaps: **14 of 30 gates** are
MISSING / PARTIAL.

## Patterns surfaced

1. **"Precise invariant differs from intuition-equivalent
   formula"** (BUG-1, headline). The replacement Rule 3 is a
   total-fee invariant on the **replacement's maxTxSize**, but
   it's intuitive to re-formulate as a feerate invariant on the
   **original's vsize**. The two formulas agree only when the
   replacement's vsize == original's vsize. nimrod's `oldFeeRateSatVb
   + incrementalRelayFeeSatVb` form is the intuitive one.
   This is the same pattern as W120 BUG-1/2 (incremental fee
   in wrong units), but one level deeper: the formula structure
   is wrong, not just the constant. **Cross-impl audit
   implication**: future BIP-125 audits should grep all 10 impls
   for "feerate + incremental" arithmetic and check whether the
   total-fee form is preserved.

2. **"Wallet-side has stricter rules than the BIP, and the
   strictness is conservative future-proofing"** (BUG-2,
   `WALLET_INCREMENTAL_RELAY_FEE`). Core's comment is explicit:
   the wallet floor is 50x the network default specifically to
   protect users when the network later raises its policy.
   Impls that ship a "minimal correct BIP-125" wallet without
   this floor will start failing wallet-to-mempool RPC
   roundtrips the moment the network bumps DEFAULT_INCREMENTAL_
   RELAY_FEE. **Pattern**: wallet-side defaults can be
   intentionally conservative, not just "what the BIP says".

3. **"5+5 cluster of single-line checks easy to miss in a port"**
   (BUG-4 / BUG-5 / BUG-6 / BUG-7 / BUG-8 / BUG-10 / BUG-11 /
   BUG-12). Core's `PreconditionChecks` + `CheckFeeRate` are
   each ~30 LOC of straight-line `if-return` guards. nimrod
   ported the structural skeleton (one for-loop, one
   raiseBfe-per-failure) but skipped 7 of the 10 individual
   guards. **Pattern**: short Core functions with N flat
   `if-return` checks are exactly the shape where N-1 get
   ported as a cluster and the rest silently drop.

4. **"mapValue / metadata blob universally absent"** (BUG-6 /
   BUG-15 / BUG-16). Wallets ported from Core often skip the
   `mapValue` metadata blob (because it's a string→string
   map with no schema). Three distinct BUGs trace to the
   same missing primitive. **Pattern**: a missing storage
   primitive can manifest as 3+ apparently-unrelated
   feature gaps.

5. **"Comment-as-confession in feebumper.nim:222-231"**: the
   simplification comment ("stuck-without-change is the
   documented failure mode") is explicit and helpful — but
   masks BUG-14 (which is a true latent gap that surfaces
   only after the comment's deliberate simplification is
   removed). **Pattern**: deliberate simplifications need to
   be tracked separately from bugs; they're "deferred BUGs"
   rather than "no BUGs".

## Cross-cutting context

- **W120 carry-forward** (mempool RBF). The mempool-side
  `checkRbfRules` was audited at W120; FIX-69 closed the
  P1/P2 unit-bug cluster (BUG-1/2/10) and FIX-79 closed the
  dead-helper validateRbfDiagram (BUG-5). The wallet-side
  surface audited here is downstream of those fixes — a
  bumpfee that passes nimrod's wallet checks then submits via
  `acceptTransaction`, which now correctly invokes the
  cluster-aware path. **Net effect**: even with W130's wallet-
  side gaps, the mempool's final RBF rules still apply, so a
  replacement that under-pays per BUG-1 is rejected by the
  mempool's Rule 4 — manifesting as RPC error "Mempool
  rejected replacement" rather than as a chain split.

- **FIX-70 carry-forward** (wallet default nSequence). FIX-70
  set the wallet's default sequence to `0xfffffffd` so newly
  built txs are BIP-125 opt-in by default — a prerequisite for
  bumpfee to work at all. G5 confirms feebumper preserves this
  on rebuild.

- **W118 wallet audit** previously flagged "feebumper MISSING"
  at G22 BUG-1; FIX-61 created the file. W130 is the deep audit
  of FIX-61's internals.

- **Out of scope**: package-RBF interaction (W116 territory);
  external-signer / hardware wallet paths (feebumper.cpp:330-348
  `SignTransaction` branch); the size-checking
  `SignatureWeights` / `SignatureWeightChecker` machinery
  (feebumper.h:75-122; nimrod uses estimated weights, not
  Signature-Weight tracking).

## Recommended fix decomposition

Future fix waves (NO production change in W130):

- **FIX-N (P0-CDIV, nimrod)**: rewrite the Rule 3 check in
  `feebumper.nim:287-295` as the additive total-fee form
  (BUG-1). 5-LOC core change + 1 new error string. Smallest
  correctness gain in the audit. Candidate for first FIX wave
  of the next session.

- **FIX-N+1 (P0-CDIV, nimrod)**: add `WALLET_INCREMENTAL_RELAY_FEE`
  constant + `std::max(node, wallet)` floor at feebumper.nim:291
  (BUG-2). 3-LOC change.

- **FIX-N+2 (P0-CDIV, nimrod)**: add `+1 sat/kvB` strict-gt
  pre-floor on oldFeeRate (BUG-3). Pairs naturally with FIX-N+1
  because both touch the EstimateFeeRate path; bundle as a single
  "auto-bump parity" wave (~15 LOC).

- **FIX-N+3 (P1-WALLET, nimrod)**: add `defaultMaxTxFee` field to
  wallet params + maxTxFee guard at end of CheckFeeRate
  (BUG-11). Self-contained, ~10 LOC, prevents fat-finger
  burn-the-wallet bug.

- **FIX-N+4 (P1-WALLET, nimrod)**: add `mapValue: Table[string,
  string]` to `WalletTx` + `replaces_txid` / `replaced_by_txid`
  bookkeeping + `markReplaced` proc (BUG-6 / BUG-15 / BUG-16).
  Single wave because the missing primitive is the same. ~30
  LOC + storage migration.

- **FIX-N+5 (P1-CDIV, nimrod)**: wire `mempool.getMinFee()`
  (the rolling-floor-aware accessor at mempool.nim:1545) into
  `doBumpFee` instead of `mempool.minFeeRate` (BUG-7). 3-LOC
  change in server.nim.

- **FIX-N+6 (P1-CDIV, nimrod)**: add `calculateCombinedBumpFee`
  to chainState (BUG-8). Larger wave (~40 LOC) because it
  requires the chainstate to look up ancestor mempool entries
  and sum their bump fees; defer until package-relay
  consolidation lands.

- **FIX-N+7 (P2 cluster, nimrod)**: bundle BUG-4 / BUG-5 / BUG-10
  / BUG-12 / BUG-13 / BUG-14 as a "remaining wallet polish"
  wave. Each is <10 LOC; together ~50 LOC + a few tests.

Pair-with-W120 note: FIX-N+5 also closes part of W120's BUG-7
(getmempoolinfo "incrementalrelayfee" hardcode) if the rolling-
floor accessor is exposed alongside.

## References

- `bitcoin-core/src/wallet/feebumper.cpp` — `PreconditionChecks`:23,
  `CheckFeeRate`:60, `EstimateFeeRate`:119,
  `CreateRateBumpTransaction`:159, `CommitTransaction`:350
- `bitcoin-core/src/wallet/feebumper.h` — `Result` enum,
  `SignatureWeights`
- `bitcoin-core/src/policy/rbf.cpp` — `PaysForRBF`:100 (mempool-
  side Rule 3+4, distinct from wallet-side)
- `bitcoin-core/src/policy/feerate.{cpp,h}` — `CFeeRate::GetFee`
  rounds up via `EvaluateFeeUp`
- `bitcoin-core/src/wallet/wallet.h:124` — `WALLET_INCREMENTAL_RELAY_FEE`
- BIP-125 — mempool-side replacement rules (Rules 1-5)

## Test file

xfail regression guards live at
`tests/test_w130_bip125_feebumper_rule3.nim`. Each MISSING /
PARTIAL gate has a `test` that documents the current (wrong /
missing) behaviour with a `check` that asserts the WRONG value,
plus a TODO comment naming the expected behaviour. When a future
FIX wave lands, the `check` flips to the correct value and the
test acts as a post-fix regression guard.
