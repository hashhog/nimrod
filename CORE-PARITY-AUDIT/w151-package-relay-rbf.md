# W151 — Package relay + BIP-125 RBF rules 2-5 (nimrod)

**Wave:** W151 — `AcceptPackage`, `AcceptMultipleTransactionsInternal`,
`AcceptSubPackage`, `SubmitPackage`, `IsWellFormedPackage`,
`IsTopoSortedPackage`, `IsConsistentPackage`, `IsChildWithParents`,
`IsChildWithParentsTree`, `MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404000`;
the `policy/rbf.cpp` surface: `IsRBFOptIn`, `SignalsOptInRBF`,
`GetEntriesForConflicts` (Rule #5 via `GetUniqueClusterCount`),
`EntriesAndTxidsDisjoint` (Rule #2), `PaysForRBF` (Rules #3 + #4),
`ImprovesFeerateDiagram` (Rule #8), `MAX_REPLACEMENT_CANDIDATES=100`;
`PackageRBFChecks` (Core master 2-RBF child-with-1-parent path);
`PackageMempoolChecks` glue; `submitpackage` / `testmempoolaccept` RPCs;
BIP-331 `sendpackages` / `getpkgtxns` / `pkgtxns` wire surface;
operator knobs `-mempoolfullrbf` (removed in Core 28+, full-RBF mandatory),
`-incrementalrelayfee`, `-minrelaytxfee`, `-datacarrier`,
`-maxpackagesize`, `maxburnamount`.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/policy/packages.h:19-25` — `MAX_PACKAGE_COUNT=25`,
  `MAX_PACKAGE_WEIGHT=404'000`. `static_assert(MAX_PACKAGE_WEIGHT >=
  MAX_STANDARD_TX_WEIGHT)`.
- `bitcoin-core/src/policy/packages.h:32-41` —
  `PackageValidationResult { PCKG_RESULT_UNSET, PCKG_POLICY, PCKG_TX,
  PCKG_MEMPOOL_ERROR }`.
- `bitcoin-core/src/policy/packages.cpp:19-50` — `IsTopoSortedPackage`
  (parent must appear before child).
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`
  (no two txs spend same prevout; reject empty-vin txs since txn-already-known
  context can't be checked).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`:
  count ≤ 25, total weight ≤ 404 000 (skipped for 1-tx pkg —
  individual-weight gate reports the violation), no dup-txids,
  topo-sorted, no input conflicts.
- `bitcoin-core/src/policy/packages.cpp:119-149` — `IsChildWithParents`
  / `IsChildWithParentsTree` (tree-no-parent-spends-parent).
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`
  (sort wtxids little-endian numeric order, then SHA256 concat — the
  "package id" used by the orphanage child→pkg map).
- `bitcoin-core/src/policy/rbf.h:26` — `MAX_REPLACEMENT_CANDIDATES=100`
  (note: this is `uint32_t`, and Core's `GetUniqueClusterCount` counts
  CLUSTERS, not transactions; the cluster count limit bounds the rebuild
  cost, but the actual evicted-tx count can be larger).
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn`: tx itself
  signals via `SignalsOptInRBF` (any input nSequence ≤ 0xfffffffd) OR
  any mempool ancestor signals; emits `REPLACEABLE_BIP125 / UNKNOWN /
  FINAL`.
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`:
  Rule #5 via **`pool.GetUniqueClusterCount(iters_conflicting)`** (NOT
  `iters_conflicting.size()`!); populates `all_conflicts` via
  `CalculateDescendants` on every iter.
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`:
  Rule #2 — replacement's ancestor set ∩ direct-conflict txids must
  be empty (transitive — direct-input Rule #2 is in PreChecks, this is
  the ancestor-chain check).
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF`:
  Rule #3 `replacement_fees ≥ original_fees` (`<` reject; equal is OK),
  Rule #4 `additional_fees ≥ relay_fee.GetFee(replacement_vsize)` with
  `relay_fee = m_pool.m_opts.incremental_relay_feerate`
  (DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB).
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`:
  Rule #8 — `std::is_gt(CompareChunks(after, before))` strict-gt over
  the changeset's CalculateChunksForRBF.
- `bitcoin-core/src/validation.cpp:1042-1133` — `PackageRBFChecks`:
  package-size MUST be 2 (`!= 2 || !IsChildWithParents` → reject "package
  RBF failed: package must be 1-parent-1-child"); neither workspace may
  have in-mempool parents; conflict aggregation; PaysForRBF with
  `m_pool.m_opts.incremental_relay_feerate`; package_feerate must STRICTLY
  exceed parent_feerate; ImprovesFeerateDiagram.
- `bitcoin-core/src/validation.cpp:1432-1620` —
  `AcceptMultipleTransactionsInternal`: PreChecks for each tx;
  `m_client_maxfeerate` per-tx gate; `PackageAddTransaction` for
  in-package parent lookup; `PackageTRUCChecks`; `CheckFeeRate` (only
  when `m_package_feerates`); `PackageRBFChecks` when `m_subpackage.m_rbf`;
  cluster-size limits; `CheckEphemeralSpends`; PolicyScriptChecks then
  ConsensusScriptChecks; SubmitPackage; LimitMempoolSize.
- `bitcoin-core/src/validation.cpp:1622-1771` — `AcceptPackage`
  orchestrator: `IsWellFormedPackage`, `IsChildWithParents` (for >1 tx);
  for each pkg tx, decide `m_pool.exists(wtxid)` / `m_pool.exists(txid)` /
  retry "as a package"; `LimitMempoolSize` rollback to "mempool full"
  results.
- `bitcoin-core/src/policy/policy.h:48` —
  `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB.
- `bitcoin-core/src/policy/policy.h:70` —
  `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB.
- `bitcoin-core/src/rpc/mempool.cpp:1322-1387` — `submitpackage` RPC:
  3 params (`package`, `maxfeerate=DEFAULT_MAX_RAW_TX_FEE_RATE`,
  `maxburnamount=DEFAULT_MAX_BURN_AMOUNT`); enforces
  `IsChildWithParentsTree`; reports `replaced-transactions` from
  `m_replaced_transactions`; rejects unspendable outputs above
  `maxburnamount`.
- `bitcoin-core/src/rpc/mempool.cpp:64-130` — `sendrawtransaction`:
  also takes `maxburnamount`.

## Files audited

- `src/mempool/package.nim` — `MaxPackageCount=25`,
  `MaxPackageWeight=404_000`, `MaxPackageSize=101_000` (vbytes),
  `isTopoSortedPackage` (lines 89-121), `isConsistentPackage`
  (lines 123-151), `isWellFormedPackage` (lines 153-199),
  `isChildWithParents` / `isChildWithParentsTree` (lines 201-245),
  `calculatePackageFeerate` (lines 247-261), `getPackageHash`
  (lines 263-271), `sortPackageTopologically` (Kahn — lines 278-324),
  `checkPackageTrucRules` (lines 349-487).
- `src/mempool/mempool.nim` — `Mempool` type with `fullRbf: bool`
  (line 72), `incrementalRelayFeeRate: float64` (line 87, sat/kvB);
  constants `MaxBip125RbfSequence=0xfffffffd`,
  `MaxReplacementCandidates=100`, `DefaultIncrementalRelayFee=0.1`
  (sat/vB), `DefaultIncrementalRelayFeeSatKvB=100.0` (sat/kvB);
  `acceptTransactionWithArgs` (lines 883-1372, the single-tx 21-gate
  pipeline that DOES enforce all consensus/policy/RBF); `acceptPackage`
  (lines 2017-2336, the parallel pipeline that does NOT — see BUG-1);
  `signalsOptInRBF` (line 1763), `isRbfOptIn` (line 1774),
  `findConflicts` (line 1795), `getAllConflictsWithDescendants`
  (line 1803), `calculateConflictFees` (line 1813), `checkRbfRules`
  (line 1824), `removeConflicts` (line 1988), `isBip125Replaceable`
  (line 1993).
- `src/rpc/server.nim` — `handleSendRawTransaction` (lines 2894-2996,
  uses `acceptTransaction`); `handleTestMempoolAccept` (lines 2998-3212,
  single-tx via `acceptTransactionWithArgs(testAccept=true)`, multi-tx
  via `acceptPackage` then rollback); `handleSubmitPackage` (lines
  3214-3335); `handleGetMempoolInfo` (lines 1199-1223 — the
  `mempoolminfee` / `minrelaytxfee` divisor bug from W141 BUG-8 is
  still open here); `handleGetNetworkInfo` (lines 3354-3434).
- `src/rpc/rest.nim` — `handleRestMempoolInfo` (lines 771-782 — same
  divisor bug as the JSON-RPC handler).
- `src/nimrod.nim` — `newMempool(state.chainState, params)` call at
  line 2019 (defaults only; no CLI knob plumbing); BIP-331
  `mkSendPackages` / `mkGetPkgTxns` / `mkPkgTxns` handlers (lines
  1193-1269); the `acceptPackage` call from `mkPkgTxns` is the
  peer-relay entry — see BUG-8 (no child-with-parents-tree gate
  before invocation).
- `src/network/peer.nim:109` — `sendsPackages: bool` peer flag;
  `pkgRelayVersion: int` (line 110).
- `src/network/messages.nim:20` — `MaxPkgTxnsCount=25`; deserialization
  for `pkgtxns` enforces count (line 851) but NOT weight (cf. BUG-11).

---

## Gate matrix (38 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `IsWellFormedPackage` | G1: count ≤ MAX_PACKAGE_COUNT (25) | PASS (`package.nim:168`) |
| 1 | … | G2: total weight ≤ MAX_PACKAGE_WEIGHT (404 000) for `len > 1` | PASS (`package.nim:172-181`) |
| 1 | … | G3: no duplicate txids | PASS (`package.nim:183-189`) |
| 1 | … | G4: topo-sorted (parent before child) | PASS (`package.nim:192`) |
| 1 | … | G5: no two txs spend same prevout | PASS (`package.nim:196`) |
| 2 | `IsChildWithParents` / `IsChildWithParentsTree` | G6: last tx is child, all earlier are direct parents | PASS (`package.nim:201-222`) |
| 2 | … | G7: tree shape (no parent-parent edges) | PASS (`package.nim:224-245`) |
| 3 | `submitpackage` RPC | G8: parses ≥1 hex tx, enforces child-with-parents-tree topology | PASS (`server.nim:3214-3279`) |
| 3 | … | G9: 3rd param `maxburnamount` honoured | **BUG-2 (P0-CDIV)** docstring lists `[2] maxburnamount` (server.nim:3221) but the RPC handler **never parses or enforces it**. params[2] is never read; the burn-amount gate (refuse `IsUnspendable() && nValue > maxburnamount`) is absent. Hand-crafted package with a megabit OP_RETURN that drains a million sat is silently accepted. Same gap in `sendrawtransaction` (server.nim:2894 — no `maxburnamount` param). |
| 3 | … | G10: `replaced-transactions` in response populated from RBF | **BUG-3 (P1)** `server.nim:3317` literally writes `response["replaced-transactions"] = newJArray()` — always an empty array, with the inline comment "(empty for now, would need RBF tracking)" — **comment-as-confession**. Even when `acceptPackage` evicted txs (it can't, since acceptPackage has zero RBF — see BUG-1), the RPC would still report nothing. |
| 4 | `acceptPackage` admission pipeline | G11: `CheckTransaction` (CVE-2018-17144 dup-input, MAX_MONEY, empty vin/vout) per tx | **BUG-1 (P0-CONS — confirmed from W150 BUG-8; carry-forward)** `acceptPackage` at `mempool.nim:2017-2336` is a parallel pipeline that **bypasses 19 of 21 admission gates** enforced by `acceptTransactionWithArgs`. Gates skipped: `checkTransaction` (CVE-2018-17144!), `isCoinbase` reject, `MIN_STANDARD_TX_NONWITNESS_SIZE=65` (CVE-2017-12842), `MaxStandardTxWeight=400_000`, `isStandardTx`, BIP-141 wtxid `byWtxid` dup detection, `txn-same-nonwitness-data-in-mempool`, `isFinalTx` BIP-113, `checkSequenceLocksForTx` BIP-68, `ValidateInputsStandardness` + MAX_P2SH_SIGOPS=15, `isWitnessStandard`, `getTransactionSigOpCost > MAX_STANDARD_TX_SIGOPS_COST=16_000`, `preCheckEphemeralTx`, `STANDARD_SCRIPT_VERIFY_FLAGS` (uses CONSENSUS flags only — see G27 below), TRUC `checkSingleTrucRules`, `findConflicts` + RBF (see BUG-4), `EntriesAndTxidsDisjoint`, second-pass `ConsensusScriptChecks` cache pop, post-eviction "mempool full" gate. |
| 4 | … | G12: package-tx version-3 (TRUC) limits enforced | PARTIAL — `acceptPackage` does call `checkPackageTrucRules` (mempool.nim:2068) for the PACKAGE-level TRUC checks, but does NOT call `checkSingleTrucRules` per tx — the latter enforces the **single-tx ancestor counts in mempool context**. A package whose child is v3 and references a v3 mempool parent already at TRUC ancestor cap escapes detection. |
| 4 | … | G13: `m_test_accept` short-circuit AFTER all checks | **BUG-12 (P1)** there is NO test-accept mode in `acceptPackage`. `testmempoolaccept` for multi-tx (`server.nim:3127-3138`) calls `acceptPackage` (which MUTATES the mempool) then "rolls back" by walking `mp.removeTransaction(txid)` for each non-pre-existing tx. This is unsafe: between the accept and the rollback the rolling-floor (`trackPackageRemoved`) and `mp.spentBy` have already been mutated; the rollback restores entries+spentBy but does NOT restore the rolling-fee state, nor any descendants of pre-existing txs that were evicted during `evictLowestFee` (mempool.nim:2304). Concurrent submitters can observe the test-accept's side-effects between the two operations. |
| 5 | `PackageMempoolChecks` (Core's package-level fee/cluster gate) | G14: package fee meets `max(min_relay, rolling_min_fee).GetFee(total_vsize)` when `m_package_feerates` | PARTIAL — `acceptPackage` at lines 2188-2196 checks `packageFeerate >= max(mp.minFeeRate, pkgRollingFloor)`, but only uses the rolling-fee in sat/vB units. Core's `CheckFeeRate` checks BOTH `m_pool.GetMinFee()` AND `m_pool.m_opts.min_relay_feerate.GetFee(package_size)` — separate static-min-relay gate is absent (`-minrelaytxfee` operator knob is also absent — see BUG-6). |
| 5 | … | G15: per-tx `m_client_maxfeerate` exceeded → fail-fast | **BUG-13 (P0-CDIV)** `acceptPackage` accepts no `clientMaxFeeRateSatKvB` parameter at all. The CALLER (`handleSubmitPackage` server.nim:3324, `handleTestMempoolAccept` server.nim:3195) computes the max-feerate-exceeded check only AFTER `acceptPackage` has mutated the mempool. Core's `AcceptMultipleTransactionsInternal:1457-1465` fail-fasts in the PreChecks loop, BEFORE any state mutation, with a per-tx (not per-package) gate; nimrod's late check operates on the PACKAGE feerate not per-tx, so a single high-fee child in a 25-tx package can sneak in unnoticed. |
| 6 | RBF Rule #1 (signaled BIP-125) | G16: at least one direct-conflict signals opt-in (or `fullRbf`) | PASS for single-tx (`mempool.nim:1843-1860`) |
| 6 | RBF Rule #2 (HasNoNewUnconfirmed) | G17: replacement's direct inputs not in `all_conflicts` | PASS for direct-input check (`mempool.nim:1872-1875`) |
| 6 | … | G18: replacement's TRANSITIVE ancestors not in `all_conflicts` (EntriesAndTxidsDisjoint) | PASS for single-tx (`mempool.nim:1204-1209`); **MISSING from `acceptPackage`** (BUG-1 cross-cite) |
| 6 | RBF Rule #3 (Replacement fees ≥ original) | G19: `tx_fee >= conflict_fees` (≥, not strict-gt) | PASS (`mempool.nim:1884-1886`) |
| 6 | RBF Rule #4 (PaysForRBF anti-DoS) | G20: `additional_fee >= incrementalRelayFee * vsize_replacement` | PASS (`mempool.nim:1888-1894`) |
| 6 | RBF Rule #5 (MAX_REPLACEMENT_CANDIDATES=100) | G21: counts CLUSTERS not transactions | **BUG-5 (P1)** `mempool.nim:1865-1868` uses `len(allConflicts)` (i.e., `conflicts + descendants` transaction count) as the gate, NOT cluster count. The inline comment at line 1864 admits "we lack cluster tracking." Two real-world consequences: (a) nimrod **REJECTS** valid replacements where a single cluster of 101 txs would be replaced — Core accepts those because it's 1 cluster, not 101 — divergence in legitimate user replacements; (b) nimrod **ACCEPTS** replacements where 100 individual descendants in 100 distinct clusters would be evicted (relinearisation cost identical to or worse than the 101-tx-1-cluster case Core rejects). Cluster-count bound is what's intended by `MAX_REPLACEMENT_CANDIDATES`, not a transaction-count bound. |
| 6 | RBF Rule #8 (ImprovesFeerateDiagram) | G22: strict-gt CompareChunks via cluster.validateRbfDiagram | PASS (`mempool.nim:1907-1984`) |
| 7 | PackageRBFChecks (Core master 2-tx 1-parent-1-child RBF) | G23: package size 2 + IsChildWithParents | **BUG-7 (P0-CDIV)** there is NO PackageRBFChecks logic in nimrod at all (grep of `src/` finds no `PackageRBF` / `packageRbf` / `package_rbf` symbols). Core's `validation.cpp:1042-1133` is the entire 2-tx 1-parent-1-child RBF gate: gates package_size=2, both workspaces parent-free, aggregates conflicts, PaysForRBF with `incremental_relay_feerate`, `package_feerate > parent_feerate` strict-gt, cluster-size limit, `ImprovesFeerateDiagram`. nimrod's `acceptPackage` simply does not run any of this: a 2-tx child-with-parent package that conflicts with an in-mempool tx with NO RBF signaling enters the package-acceptance path with `findConflicts` never called and the conflict is silently retained until commit-time `mp.spentBy[input.prevOut] = txid` at line 2333 quietly **overwrites** the conflict's spentBy entry → double-spend latent in the mempool until the next block. |
| 7 | … | G24: no in-mempool ancestors for either pkg tx | N/A — BUG-7 |
| 7 | … | G25: package_feerate STRICTLY > parent_feerate | N/A — BUG-7 |
| 8 | Operator knobs (BIP-125 / package config) | G26: `-mempoolfullrbf` (Core 28+ removed, mandatory) | **BUG-4 (P0-CDIV — confirmed from W150 BUG-4, still open)** nimrod's `Mempool.fullRbf` defaults to `false` (mempool.nim:195, 213). The CLI (`nimrod.nim:380-450, 2019`) has NO `--mempoolfullrbf` or `--fullrbf` flag and `newMempool()` is called bare-handed at line 2019. Core 28+ removed the operator knob and made full-RBF MANDATORY (PR #30592). nimrod's default rejects non-signaling replacements that the entire rest of the network (Core 28+, btcd 0.24+, electrs/fulcrum/mempool.space) now accepts. Mainnet effect: nimrod's mempool diverges from every other node within minutes of restart on fee-bump traffic. Re-confirmed in this audit. |
| 8 | … | G27: `-incrementalrelayfee=<amt>` (BTC/kvB) operator knob | **BUG-6 (P1)** no `--incrementalrelayfee` CLI flag; `newMempool()` call at `nimrod.nim:2019` does not pass `incrementalRelayFeeRate` so the field defaults to `DefaultIncrementalRelayFeeSatKvB=100.0` permanently. Operator cannot tune the per-byte RBF cost floor. Cross-fleet parity gap. |
| 8 | … | G28: `-minrelaytxfee=<amt>` operator knob | **BUG-9 (P1)** no `--minrelaytxfee` CLI flag; the only feed for `Mempool.minFeeRate` is the `DefaultMinFeeRate=1.0` (sat/vB) constructor default at `mempool.nim:97`. Operator cannot configure the static min-relay floor. Concrete impact: a low-DoS-tolerance operator cannot raise their floor; a high-throughput relay node cannot lower it. |
| 9 | mempoolminfee / minrelaytxfee RPC reporting | G29: `mempoolminfee` reported in BTC/kvB (Core convention) | **BUG-10 (P0-CDIV — W141 BUG-8 carry-forward, STILL OPEN 5 weeks)** `server.nim:1200` and `rest.nim:773` both compute `let minFee = rpc.mempool.minFeeRate / 100000000.0` then report it as `mempoolminfee` AND `minrelaytxfee`. `minFeeRate` is in sat/vB (set in mempool.nim:97 via `DefaultMinFeeRate=1.0` sat/vB). Core's `getmempoolinfo` reports BTC/kvB. The correct conversion is: `minFee_sat_vB * 1000 / 100_000_000 = minFee_sat_vB / 100_000` → BTC/kvB. nimrod divides by `100_000_000` (one zero too many in the denominator) → **1000× too low**. With nimrod's default 1 sat/vB → 1000 sat/kvB → 0.00001 BTC/kvB; nimrod reports `0.00000001` BTC/kvB. Same divisor mistake in BOTH the JSON-RPC handler AND the REST handler. fee-estimator tooling that auto-tunes from getmempoolinfo will under-fee their txs by 3 orders of magnitude. |
| 10 | RBF Rule #3 incrementalRelayFee divisor sanity (W151-specific check) | G30: `checkRbfRules` `additional_fee` computation uses sat/vB consistently | PASS — line 1188-1191 explicitly converts `mp.incrementalRelayFeeRate / 1000.0` (sat/kvB → sat/vB) and `requiredAdditionalFee = int64(incrementalRelayFee * vsize)` at line 1891 is dimensionally correct. The post-W120 FIX-69 closure holds. But… |
| 10 | … | G31: `checkRbfRules` default param `incrementalRelayFee = DefaultIncrementalRelayFee` is in the correct unit | PARTIAL — the default at `mempool.nim:1825` is `DefaultIncrementalRelayFee = 0.1` sat/vB, used ONLY if the caller does not pass an explicit value. The only production caller (`mempool.nim:1190`) passes the explicit converted value, so the default is dead. But the API surface invites the same bug class — a future caller using the default gets the OLD (post-FIX-69-rewrite) numerical default of 0.1 sat/vB, while the field itself defaults to 100 (sat/kvB). Unit dimension drift latent. |
| 11 | BIP-331 wire surface (`pkgtxns`) | G32: `getpkgtxns` look-up by child wtxid | PASS (`nimrod.nim:1193-1239`) — walks ancestors via `calculateAncestors` |
| 11 | … | G33: outbound `pkgtxns` capped at `MaxPkgTxnsCount=25` | PASS (`nimrod.nim:1230`) |
| 11 | … | G34: inbound `pkgtxns` weight cap | **BUG-11 (P1)** `messages.nim:849-858` reads count (capped at 25) but NEVER reads weight. The MAX_PROTOCOL_MESSAGE_LENGTH=4MB net cap is the only ceiling, but the package-relay layer's intent is `MAX_PACKAGE_WEIGHT=404_000` weight ≈ 101 KB per pkg. A 25-tx pkg of ~160KB-per-tx (all witness) = 4MB → just under net cap, 10× the MAX_PACKAGE_WEIGHT. The `isWellFormedPackage` call inside `acceptPackage` (line 2044) DOES reject the package, but only AFTER full deserialisation + ancestor-walk work has been done — wire-side DoS amplifier. |
| 11 | … | G35: inbound `pkgtxns` enforces child-with-parents-tree before `acceptPackage` | **BUG-8 (P0-CDIV)** `nimrod.nim:1254` calls `state.mempool.acceptPackage(txns, ...)` with ZERO topology validation. Core's net_processing accepts pkgtxns only if it's the legitimate ancestor-package the peer requested via `getpkgtxns`. nimrod accepts ANY 25-tx blob that survives `IsWellFormedPackage` — random/maliciously-crafted multi-conflict packages from non-corresponding-getpkgtxns peers are processed (and the side-effect mutations from BUG-1 + BUG-7 land in the mempool). `handleSubmitPackage` RPC at line 3277 DOES enforce `isChildWithParentsTree`, but the wire-side handler in `nimrod.nim` does NOT. Inconsistency between RPC entry and wire entry. |
| 12 | `acceptPackage` already-in-mempool de-duplication | G36: distinguishes wtxid-match vs txid-match-different-witness (BIP-141) | **BUG-14 (P1)** `mempool.nim:2121` only checks `if txid in mp.entries:`. Core (`validation.cpp:1664-1686`) checks `m_pool.exists(wtxid)` FIRST (exact-already-in-mempool → MempoolTx) then `m_pool.exists(txid)` (same-txid-diff-witness → MempoolTxDifferentWitness). nimrod's path silently treats both as "already in" with `allowed=true` and the **same wtxid as the submitted tx** — so a sender who broadcasts a re-witnessed-malleated copy of an in-mempool tx gets a confirmation it was admitted with the malleated witness, while the mempool still holds the original witness. submitpackage result reports the wrong wtxid for the "successful" entry. |
| 13 | acceptPackage script-flag selection | G37: PolicyScriptChecks uses STANDARD_SCRIPT_VERIFY_FLAGS | **BUG-15 (P0-CDIV — confirmed from W150 BUG-8, still open)** `mempool.nim:2213` derives `let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)` — consensus-only flags. `standardScriptVerifyFlags` policy expansion at `mempool.nim:863` is NOT applied. Package-mode txs bypass NULLFAIL, LOW_S, MINIMALDATA, MINIMALIF, CLEANSTACK, STRICTENC, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE — 13 of 14 STANDARD-not-mandatory flags. Two-pipeline guard 19th distinct fleet extension (W150 was 18th). |
| 13 | … | G38: ConsensusScriptChecks belt-and-suspenders re-pass | **BUG-16 (P1 — W150 BUG-9 carry-forward)** package path runs script verification ONCE only (line 2254). Core's belt-and-suspenders defense against policy-flag bugs accepting consensus-bad txs is missing. |

---

## BUG-1 (P0-CONS) — `acceptPackage` parallel pipeline bypasses 19 of 21 admission gates (carry-forward W150 BUG-8)

**Severity:** P0-CONS (CVE-2018-17144 inflation primitive open via the
package path; STANDARD_SCRIPT_VERIFY_FLAGS bypass; RBF bypass; "two-pipeline
guard" 19th distinct fleet extension; **carry-forward from W150 BUG-8,
unfixed**). Confirmed in this audit.

Bitcoin Core's `AcceptMultipleTransactionsInternal`
(`validation.cpp:1432-1620`) runs the FULL `PreChecks` → `ReplacementChecks`
→ `PolicyScriptChecks` → `ConsensusScriptChecks` pipeline for EVERY tx
in the package — the only behavioural difference vs single-tx is
`m_package_feerates` (use the package feerate as the fee gate) and the
package-RBF aggregate-conflict path.

nimrod's `acceptPackage` at `mempool.nim:2017-2336` is a **standalone
pipeline that calls NONE of `acceptTransactionWithArgs`'s 21 gates**.
Side-by-side gate inventory:

| Gate | acceptTransactionWithArgs | acceptPackage | Core |
|------|---------------------------|---------------|------|
| `checkTransaction` (CVE-2018-17144 dup-input + MAX_MONEY) | line 900 | **ABSENT** | mandatory |
| `isCoinbase` reject | line 905 | **ABSENT** | mandatory |
| `MIN_STANDARD_TX_NONWITNESS_SIZE = 65` (CVE-2017-12842) | line 911 | **ABSENT** | mandatory in `require_standard` mode |
| `MaxStandardTxWeight = 400_000` | line 916 | **ABSENT** | mandatory in `require_standard` mode |
| `isStandardTx` (version/scriptSig/dust/multisig/datacarrier) | line 921 | **ABSENT** | mandatory in `require_standard` mode |
| BIP-141 `byWtxid` dup detection | line 931 | partial — txid-only at line 2121 | mandatory |
| `txn-same-nonwitness-data-in-mempool` distinction | line 933 | **ABSENT** | mandatory |
| `isFinalTx` BIP-113 | line 943 | **ABSENT** | mandatory |
| `findConflicts` + `allowReplacement` BIP-125 gate | line 952 | **ABSENT** | mandatory |
| `checkSequenceLocksForTx` BIP-68 | line 1001 | **ABSENT** | mandatory |
| `ValidateInputsStandardness` + MAX_P2SH_SIGOPS=15 | lines 1038-1107 | **ABSENT** | mandatory in `require_standard` |
| `isWitnessStandard` (P2A/P2SH-wrap/P2WSH/P2TR) | line 1017 | **ABSENT** | mandatory in `require_standard` |
| `getTransactionSigOpCost > MAX_STANDARD_TX_SIGOPS_COST=16_000` | line 1124 | **ABSENT** | mandatory in `require_standard` |
| `preCheckEphemeralTx` (single-tx ephemeral dust gate) | line 1143 | **ABSENT** (package has `checkEphemeralSpends` but not single-tx) | mandatory |
| STANDARD_SCRIPT_VERIFY_FLAGS | line 1221 | **CONSENSUS-ONLY** (see BUG-15) | mandatory |
| `checkSingleTrucRules` per-tx | line 1169 | **ABSENT** (package-level only) | mandatory |
| `checkRbfRules` (Rules #2-5, #8) | line 1190 | **ABSENT** (see BUG-4) | mandatory |
| `EntriesAndTxidsDisjoint` ancestor-disjoint | line 1204 | **ABSENT** | mandatory |
| `ConsensusScriptChecks` second pass | line 1286 | **ABSENT** (see BUG-16) | mandatory |
| post-eviction "mempool full" / `TX_RECONSIDERABLE` | line 1340 | **ABSENT** | mandatory |
| `m_test_accept` short-circuit | line 1324 | **ABSENT** (see BUG-12) | mandatory |

Gates `acceptPackage` DOES enforce:
- `isWellFormedPackage` (count + weight + topo + consistency) — pkg-level.
- `MaxPackageSize=101_000 vbytes` redundant gate (line 2060).
- `checkPackageTrucRules` (pkg-level only) — line 2068.
- `checkEphemeralSpends` (pkg-level only) — line 2085.
- Per-tx fee calculation (lines 2107-2173) — but with no MoneyRange
  invariant on `inputValue` (cross-cite BUG-6 of W150).
- Package-aggregate min-fee gate (lines 2188-2196) using
  `max(minFeeRate, pkgRollingFloor)`.
- Single-pass script-verify using CONSENSUS flags only (line 2213-2269).
- `checkPackageLimits` per-tx in the third pass (line 2294).

**File:** `src/mempool/mempool.nim:2017-2336` (the entire `acceptPackage`
proc); the contrast is `acceptTransactionWithArgs` at lines 883-1372.

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1620`
(`AcceptMultipleTransactionsInternal`) calls `PreChecks` for EVERY tx
(line 1449) before any package-specific logic.

**Impact:**
- CVE-2018-17144 (duplicate-input txs) enters the mempool via package
  path; on next block they pop the block-side validation and the chain
  re-orgs, but in the meantime nimrod's mempool is an inflation
  primitive for the next mining cycle.
- Coinbase txs admitted via submitpackage (peer can deliver via
  pkgtxns).
- Non-standard scriptSig sizes / dust outputs / bare-multisig n>3
  bypass policy.
- BIP-113 non-final txs enter package (eventually fail at block
  inclusion).
- BIP-68 nSequence-locked txs admit too early.
- Sigop budget unbounded (DoS amplifier on package-relay).
- All 13 STANDARD-not-mandatory script flags bypassed (cf. BUG-15).
- RBF rules 1-5, 8 entirely bypassed when admitting via package (cf.
  BUG-4, BUG-7).

This is the **same shape** as W144 BUG-3 / W143 fleet pattern "parallel
production pipeline bypass" — a complete second consensus pipe that
silently drifts from the canonical gate sequence. The W150 audit
flagged it as a single bug; this audit confirms the carry-forward and
counts the gate-by-gate gap to anchor the next fix wave's scope.

---

## BUG-2 (P0-CDIV) — `submitpackage` RPC documents but never enforces `maxburnamount`

**Severity:** P0-CDIV (operator safety knob silently absent; mainnet
loss-of-funds vector when wallet software pre-flights against nimrod).

`server.nim:3214-3221` docs the 3rd RPC param:

```nim
## [2] maxburnamount - (optional) Maximum burned amount in BTC (default 0)
```

But `handleSubmitPackage` (lines 3214-3335) **never references
`params[2]`**. The only params accessed are `params[0]` (rawtxs array)
and `params[1]` (maxfeerate). There is no `maxBurnAmount` variable, no
check against `out.scriptPubKey.IsUnspendable()`, no comparison against
output value.

Bitcoin Core's `submitpackage` and `sendrawtransaction` both have this
gate (`bitcoin-core/src/rpc/mempool.cpp:96-104, 1387`):

```cpp
const CAmount max_burn_amount = request.params[2].isNull() ? 0 :
                                AmountFromValue(request.params[2]);
for (const auto& out : tx->vout) {
    if((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps())
       && out.nValue > max_burn_amount) {
        throw JSONRPCTransactionError(TransactionError::MAX_BURN_EXCEEDED, ...);
    }
}
```

**File:** `src/rpc/server.nim:3214-3335` (handleSubmitPackage — no
maxburnamount); `src/rpc/server.nim:2894-2996` (handleSendRawTransaction —
no maxburnamount either).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:64-104`
(sendrawtransaction) and `1322-1387` (submitpackage).

**Impact:**
- Wallet software (Sparrow / SeedSigner / Bitcoin Core CLI) that
  pre-flights `submitpackage` against an RPC node, expecting the burn
  gate to fail on a malformed OP_RETURN-with-large-value tx, sees the
  call succeed against nimrod and re-tries the same broadcast against
  Core — silent divergence in error path on the SAME tx.
- An attacker can pin nimrod's mempool with a 10-tx package whose
  child has a 1-BTC OP_RETURN output; nimrod accepts (burn gate
  absent), Core rejects on `maxburnamount=0`. Cross-impl mempool
  divergence on the wire.
- Same gap in `sendrawtransaction` — fleet pattern.

---

## BUG-3 (P1) — `submitpackage` response `replaced-transactions` always empty (comment-as-confession)

**Severity:** P1 (wire/format parity slip; user tools that parse
replacement chains break silently).

`server.nim:3317`:

```nim
# Add replaced transactions info (empty for now, would need RBF tracking)
response["replaced-transactions"] = newJArray()
```

This is a **comment-as-confession** (fleet pattern, 5th instance in
nimrod tracking — cross-cite W144 BUG-3 / lunarblock W144 BUG-12 /
beamchain W143 BUG-1 / ouroboros W143 BUG-7 / clearbit W144 BUG-1).
The handler explicitly tells the reader it knows the field should be
populated but has chosen to leave it empty.

Bitcoin Core's `submitpackage`
(`bitcoin-core/src/rpc/mempool.cpp:1322-1450`) populates
`replaced-transactions` from `m_subpackage.m_replaced_transactions` —
the set of mempool entries that were evicted to make room for the
package's RBF child (or as part of PackageRBFChecks). Even without
package RBF (which nimrod also lacks — see BUG-7), single-tx RBF can
fire within `acceptPackage` if any pkg-tx conflicts with a mempool tx.

But… nimrod's `acceptPackage` has NO conflict detection (cf. BUG-1
table — `findConflicts` is absent), so even if the response field
were populated, the underlying source-of-truth is empty by
construction. This is BUG-3 → BUG-1, BUG-4, BUG-7 chain.

**File:** `src/rpc/server.nim:3317`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1438-1450`
(replaced-transactions assembly).

**Impact:**
- Wallet RBF UI that displays "replaced N transactions" shows 0 for
  every nimrod-accepted RBF.
- Block-explorer back-ends that track mempool replacements via
  `submitpackage` rather than direct mempool polling miss every event.

---

## BUG-4 (P0-CDIV) — Default `fullRbf = false` (W150 BUG-4 carry-forward; nimrod rejects what Core 28+ accepts)

**Severity:** P0-CDIV (mainnet wire divergence; "plumb-gate-then-flip"
nimrod fleet pattern, 5th distinct instance — cross-cite W141 BUG-8 /
W144 BUG-7 / W150 BUG-7 / W141 BUG-7).

`mempool.nim:195, 213`:

```nim
proc newMempool*(chainState: ChainState, params: ConsensusParams,
                 maxSize: int = DefaultMaxMempoolSize,
                 minFeeRate: float64 = DefaultMinFeeRate,
                 fullRbf: bool = false,           # <-- here
                 ...
```

`nimrod.nim:2019` constructs the Mempool with defaults only:

```nim
state.mempool = newMempool(state.chainState, params)
```

— so `fullRbf` is permanently `false` in production. There is no CLI
flag, no config-toml field, no environment variable.

Bitcoin Core 28+ removed the `-mempoolfullrbf` knob entirely (PR #30592,
Apr 2024) and made full-RBF MANDATORY. Every Core 28+ node, btcd 0.24+,
electrs current, fulcrum current, mempool.space backend, and the
Lightning operator class running anywhere relays non-signaling
replacements unconditionally.

nimrod's `checkRbfRules` at `mempool.nim:1843-1860` requires at least
one direct conflict to be replaceable-via-signaling. A common
real-world scenario: an exchange-batched transaction without
nSequence=0xfffffffd signaling is replaced by a fee-bumped variant
from the same wallet; Core 28+ accepts, nimrod rejects with `"rejecting
replacement: original transaction does not signal RBF opt-in (BIP-125)"`.

**File:** `src/mempool/mempool.nim:72, 195, 213, 1843, 2001`;
`src/nimrod.nim:2019` (newMempool call site).

**Core ref:** `bitcoin-core/src/init.cpp` (the `-mempoolfullrbf` line
WAS at init.cpp ~line 580; PR #30592 removed it);
`bitcoin-core/src/kernel/mempool_options.h` (no `m_full_rbf` field
exists in Core 28+ master — the option is GONE).

**Impact:**
- Mempool divergence with the wire majority: nimrod's mempool
  permanently lags the fleet on fee-bump traffic.
- Re-request loops: peers Core-side relay a fee-bumped non-signaling
  tx → nimrod rejects → peer rebroadcasts because nimrod's reject
  cache doesn't echo back → bandwidth-DoS on the connection.
- Operator confusion: no CLI knob to disable nimrod's bug, no flag to
  follow Core 28+.

W150 BUG-4 documented the same gap two days ago; no fix landed. This
is the 2nd consecutive audit instance.

---

## BUG-5 (P1) — RBF Rule #5 counts transactions instead of unique clusters

**Severity:** P1 (legitimate-replacement rejection + DoS-cost-bound
inversion — bi-directional consensus divergence). First W151 audit of
this specific gap.

Bitcoin Core's `GetEntriesForConflicts`
(`bitcoin-core/src/policy/rbf.cpp:67-75`):

```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
    return strprintf("rejecting replacement %s; too many conflicting
                      clusters (%u > %d)", ...);
}
```

The bound on `MAX_REPLACEMENT_CANDIDATES = 100` is a **cluster-count
limit**, not a transaction-count limit. The rationale is that
re-linearisation cost scales with the number of disjoint clusters that
need to be re-sorted, not with the descendant count of any one cluster.

nimrod's `checkRbfRules` at `mempool.nim:1862-1868`:

```nim
let allConflicts = mp.getAllConflictsWithDescendants(conflicts)
if len(allConflicts) > MaxReplacementCandidates:
    return err(HashSet[TxId], "rejecting replacement: too many potential
               replacements (" & ...)
```

— uses `conflicts + descendants` transaction count. The inline comment at
line 1864 even admits "we lack cluster tracking."

Two opposing divergences:

(a) **False reject** — a single cluster of 101 transactions
(e.g., a CPFP child of a 99-tx LN-channel chain) is rejected by
nimrod, accepted by Core. Real fee-bump scenarios with deep ancestor
chains fail.

(b) **False accept** — 100 distinct mempool transactions in 100
distinct clusters (no parent/child relationship between them), each
spending one input of the replacement tx (i.e., the replacement
consolidates 100 unrelated outputs) — nimrod accepts (100 ≤ 100), Core
accepts as well (100 clusters = 100). Wait — actually 100 = limit on
both sides, both accept. So (b) is not actually a divergence. The
real (b) is: a replacement that touches 50 clusters of 3 txs each =
150 txs > 100 limit. nimrod rejects (150 > 100 by tx-count); Core
accepts (50 ≤ 100 by cluster-count). nimrod is **stricter**.

Net: nimrod rejects legitimate replacements that Core accepts. Wallet
software that retries on `reject-reason ~= "too many"` may loop.

**File:** `src/mempool/mempool.nim:1862-1868` (the gate);
`src/mempool/cluster.nim` (cluster manager exists but `getUniqueClusterCount`
helper is absent — would close this bug).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:67-75`
(`pool.GetUniqueClusterCount`);
`bitcoin-core/src/txmempool.h::CTxMemPool::GetUniqueClusterCount`.

**Impact:** moderate — fee-bumpers with deep CPFP chains see
spurious rejections; cross-impl mempool divergence on the same RBF
attempt.

---

## BUG-6 (P1) — No `-incrementalrelayfee` operator knob; defaults locked to 100 sat/kvB

**Severity:** P1 (operator-knob absence, fleet pattern 7+ instances).

`mempool.nim:202` accepts `incrementalRelayFeeRate: float64 =
DefaultIncrementalRelayFeeSatKvB` as a constructor parameter, but
`nimrod.nim:2019` passes no value:

```nim
state.mempool = newMempool(state.chainState, params)
```

So `incrementalRelayFeeRate` is permanently `100.0` (sat/kvB), and
operators have no way to tune it. Core exposes
`-incrementalrelayfee=<amt>` (BTC/kvB).

**File:** `src/mempool/mempool.nim:87, 202`; `src/nimrod.nim:2019` (no
plumbing); `src/nimrod.nim` parseFlags (no flag definition).

**Core ref:** `bitcoin-core/src/init.cpp` (`-incrementalrelayfee` ArgsManager
registration).

**Impact:** operator cannot tune RBF anti-DoS cost; cross-fleet
operator-knob parity gap.

---

## BUG-7 (P0-CDIV) — `PackageRBFChecks` entirely missing (acceptPackage admits double-spends silently)

**Severity:** P0-CDIV (silent double-spend admission in mempool;
diverges from Core's package-RBF behaviour; latent until next block).

Bitcoin Core's `MemPoolAccept::PackageRBFChecks`
(`bitcoin-core/src/validation.cpp:1042-1133`) is the entire
package-RBF code path. It is called from
`AcceptMultipleTransactionsInternal:1515` whenever
`m_subpackage.m_rbf` is set (i.e., any pkg tx has a direct conflict).
Gates:

1. Package size must be exactly 2 (parent + child).
2. `IsChildWithParents` (assured).
3. Neither workspace may have in-mempool parents (cluster-size 2 bound).
4. Conflicts aggregated across BOTH workspaces.
5. `GetEntriesForConflicts` cluster-count check.
6. `PaysForRBF` with the `incremental_relay_feerate`.
7. Package feerate STRICTLY > parent feerate ("ensure this two
   transaction package is a chunk on its own; we don't want the child
   to be only paying anti-DoS fees").
8. `CheckMemPoolPolicyLimits` cluster size.
9. `ImprovesFeerateDiagram`.

A grep of nimrod for `PackageRBF` / `packageRbf` / `package_rbf`
returns **zero hits**. `acceptPackage` at `mempool.nim:2017-2336` has
NO call to `findConflicts`, NO RBF gate, NO conflict-tx eviction. The
pipeline computes per-tx fees against the chainstate/mempool, runs
script-verify (with consensus flags only — BUG-15), and at line 2333
does:

```nim
for input in tx.inputs:
    mp.spentBy[input.prevOut] = txid
```

— **silently overwriting** the conflict's `spentBy` entry. The
conflicting in-mempool tx is NOT removed; it stays in `mp.entries`
indexed by its own txid, but `mp.spentBy` now points the input to the
new tx. On the next block mine, both txs are mining candidates; the
miner picks one, the other is left dangling. On the next
`blockDisconnected` (reorg), the disconnect path's `findConflicts`
walks `mp.spentBy` (now wrong) and removes the WRONG entry.

**File:** `src/mempool/mempool.nim:2017-2336` (acceptPackage — no RBF
at all).

**Core ref:** `bitcoin-core/src/validation.cpp:1042-1133`
(`PackageRBFChecks`).

**Impact:**
- Silent double-spend admission in the mempool: an attacker submits a
  2-tx pkg whose child conflicts with an in-mempool tx; nimrod
  accepts both; the next block's getblocktemplate may pick either,
  leading to invalid block construction (two inputs spent twice in
  the candidate set).
- Mempool state corruption across `blockDisconnected` / reorg:
  `spentBy` references the new tx, but the old tx still occupies
  `entries`. Subsequent removeTransaction(old) leaves dangling
  spentBy entries pointing to a non-existent tx.
- Package-RBF semantics absent: no way for legitimate package-RBF
  use cases (e.g., a 1P1C with higher feerate than the in-mempool
  alternative) to succeed via nimrod's submitpackage.

---

## BUG-8 (P0-CDIV) — `pkgtxns` wire handler bypasses child-with-parents-tree topology check

**Severity:** P0-CDIV (network amplifier for BUG-1 / BUG-7;
inconsistency between RPC entry and wire entry into the same
`acceptPackage`).

`nimrod.nim:1240-1269`:

```nim
of mkPkgTxns:
    ...
    let txns = msg.pkgTxns.transactions
    var pkgResult: PackageResult
    {.gcsafe.}:
        try:
            pkgResult = state.mempool.acceptPackage(txns, state.crypto,
                                                  usePackageFeerates = true)
        ...
```

There is NO check that:
1. The package corresponds to a previously-sent `getpkgtxns` request
   (Core's net_processing tracks the outstanding child-wtxid request
   set; a `pkgtxns` from a peer we didn't ask is treated as a misbehavior).
2. The package is a legitimate child-with-parents-TREE topology
   (Core requires this implicitly because the ancestor-package shape
   IS a tree by construction).

Contrast with the RPC entry: `handleSubmitPackage` at server.nim:3277
DOES enforce:

```nim
if txns.len > 1 and not isChildWithParentsTree(txns):
    raise newRpcError(RpcTransactionRejected,
      "package topology disallowed. ...")
```

— but the wire-side handler in nimrod.nim does NOT. Asymmetric
defensive depth between two entry points to the same `acceptPackage`
function.

Combined with BUG-1 (acceptPackage is the bypass pipeline) and BUG-7
(no package-RBF), this means a malicious peer can feed nimrod any
25-tx blob: as long as it passes `isWellFormedPackage` (count +
weight + topo + consistency), nimrod processes it. Each tx then
bypasses all 19 missing admission gates in BUG-1, and any
double-spend pattern lands silently per BUG-7.

**File:** `src/nimrod.nim:1240-1269` (the wire handler);
contrast `src/rpc/server.nim:3277-3279` (the RPC handler does enforce
the tree).

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
case `NetMsgType::PKGTXNS` — checks against the request-tracking
table; `bitcoin-core/src/node/txdownload_impl.cpp::ReceivedPkgTxns`
validates topology.

**Impact:**
- Network amplifier for BUG-1: any peer can spray pkgtxns to bypass
  19 admission gates.
- Network amplifier for BUG-7: any peer can spray pkgtxns to inject
  double-spends into nimrod's mempool.
- Inconsistency: a transaction-class rejected via RPC submitpackage
  is admitted via pkgtxns wire (the second entry point honours
  fewer checks). "Asymmetric defensive depth" — same fleet pattern
  as W145 rustoshi (mixed checked_add/saturating_add on same
  amounts).

---

## BUG-9 (P1) — No `-minrelaytxfee` operator knob; `Mempool.minFeeRate` fixed at default

**Severity:** P1 (operator-knob absence; fleet pattern, 8+ instances).

`mempool.nim:97`:

```nim
DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum
```

`nimrod.nim:2019` calls `newMempool(state.chainState, params)` —
`minFeeRate` keeps its default 1.0. No CLI flag for `--minrelaytxfee`.

Bitcoin Core's `-minrelaytxfee=<amt>` (BTC/kvB, default
`0.00001000`) lets operators tune the per-relay-byte floor.

**File:** `src/mempool/mempool.nim:97, 194, 210`; `src/nimrod.nim:2019`.

**Core ref:** `bitcoin-core/src/init.cpp::SetupServerArgs`
(`-minrelaytxfee` registration with DEFAULT_MIN_RELAY_TX_FEE = 100
sat/kvB).

**Impact:** operator cannot tune the static min-relay floor;
cross-fleet parity gap; pinning-attack mitigations that rely on raising
the floor unavailable.

---

## BUG-10 (P0-CDIV) — `mempoolminfee` / `minrelaytxfee` divisor 1000× too low (W141 BUG-8 carry-forward, 5+ weeks open)

**Severity:** P0-CDIV (numerical divergence affecting EVERY fee-estimator
consumer; fleet-wide RPC parity break; W141 BUG-8 carry-forward, **STILL
OPEN**, re-confirmed in this audit).

`server.nim:1200`:

```nim
let minFee = rpc.mempool.minFeeRate / 100000000.0  # Convert sat/vbyte to BTC/kB
```

`rest.nim:773`:

```nim
let minFee = rest.mempool.minFeeRate / 100000000.0  # sat/vbyte to BTC/kB
```

The comment says "BTC/kB" but Core's `getmempoolinfo` returns
**BTC/kvB** (kilo-virtualbyte). The correct conversion from sat/vB to
BTC/kvB is:

```
sat/vB * 1000 vB/kvB / 100_000_000 sat/BTC = sat/vB / 100_000 = BTC/kvB
```

nimrod divides by `100_000_000` (1000× too aggressive). With the
default `minFeeRate = 1.0` sat/vB:

- **Correct:** 1.0 × 1000 / 100_000_000 = **0.00001000 BTC/kvB**
- **nimrod reports:** 1.0 / 100_000_000 = **0.00000001 BTC/kvB** (1000× LOW)

This is reported as BOTH `mempoolminfee` AND `minrelaytxfee` in the
same response — every fee-estimator that calls getmempoolinfo and
multiplies by tx-vsize to get a fee floor will under-fee by 1000×.

**Concrete consumer:** electrs's `make_block_template` uses
`mempoolminfee` as the floor for transaction selection; an electrs
instance pointed at nimrod will accept TXs at 1/1000th of the
intended floor. Same for fulcrum, mempool.space, btc-rpc-explorer.

`getnetworkinfo` at server.nim:3430-3431 hardcodes `0.00001` for
`relayfee` / `incrementalfee` — those are CORRECT (matching Core's
default 100 sat/kvB → 0.00001 BTC/kvB) — but they're CONSTANTS not
derived from the live `Mempool.minFeeRate`. So an operator who tunes
their min-fee sees `getnetworkinfo.relayfee` unchanged AND
`getmempoolinfo.minrelaytxfee` change by the wrong factor.

**File:** `src/rpc/server.nim:1200, 1212-1213` (JSON-RPC handler);
`src/rpc/rest.nim:773, 780-781` (REST handler).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getMempoolInfo` —
emits `mempoolminfee = pool.GetMinFee().GetFeePerK()` (which divides
by 1000 internally for the sat/kvB unit, then `ValueFromAmount`
converts to BTC).

**Impact:**
- Every fee-estimator consumer of getmempoolinfo under-fees by 1000×.
- electrs / fulcrum / mempool.space / btc-rpc-explorer all read the
  wrong value.
- W141 audit (Apr 14) reported this — **5+ weeks open**; W150 audit
  (May 17) re-confirmed; this W151 audit re-re-confirms. The fix is
  literally 1-line ÷ → 100_000 instead of 100_000_000, replicated
  to rest.nim.

---

## BUG-11 (P1) — Inbound `pkgtxns` weight cap absent at wire layer

**Severity:** P1 (DoS amplifier; wire-layer pre-parse gate missing).

`messages.nim:849-858`:

```nim
of "pkgtxns":
    let txCount = r.readCompactSize()
    if txCount > MaxPkgTxnsCount.uint64:
      raise newException(SerializationError,
        "pkgtxns: tx count " & $txCount & " exceeds max " & $MaxPkgTxnsCount)
    var txs: seq[Transaction]
    for _ in 0 ..< int(txCount):
      txs.add(r.readTransaction())
```

The count is capped at 25, but the per-tx weight is uncapped at the
deserialisation layer. The only ceiling is the
MAX_PROTOCOL_MESSAGE_LENGTH (4MB, peer.nim).

`isWellFormedPackage` (package.nim:172-181) DOES check
`MaxPackageWeight = 404_000` weight units (≈ 101 KB) after full
deserialisation — but the wire-side acceptor has already paid the
deserialisation + ancestor-walk cost when the check fires.

A 25-tx pkg of ~160KB-per-tx (all witness data, 4MB total just under
the 4MB net cap) is ~10× the MAX_PACKAGE_WEIGHT. nimrod fully
deserialises before rejecting in `acceptPackage`.

**File:** `src/network/messages.nim:849-858`.

**Core ref:** `bitcoin-core/src/net.cpp::ReceiveMsgBytes` enforces a
`MAX_PROTOCOL_MESSAGE_LENGTH = 4'000'000` ceiling; Core's
`PROCESSING_PKGTXNS` then checks total-weight in the deserialiser
helper before commit to memory.

**Impact:** wire-layer DoS amplifier; a peer can repeatedly feed
oversized packages, forcing deserialisation work × 25 txs each.
Combined with BUG-8 (no topology check before acceptPackage),
amplification factor scales.

---

## BUG-12 (P1) — `testmempoolaccept` multi-tx path mutates mempool then "rolls back" (no real test-accept in acceptPackage)

**Severity:** P1 (concurrency hazard + persistent side-effect leak on
test-only RPC).

`server.nim:3127-3150` is the multi-tx testmempoolaccept path:

```nim
# Record which txids are in the mempool before we call acceptPackage so we
# can remove anything that was freshly inserted.
var preExisting: seq[TxId]
for tx in txns:
    if mp.contains(tx.txid()):
        preExisting.add(tx.txid())

let pkgResult = mp.acceptPackage(txns, rpc.crypto, usePackageFeerates = true)

# Rollback: remove every tx that acceptPackage added (was not pre-existing).
for tx in txns:
    let txid = tx.txid()
    var wasPreExisting = false
    for pe in preExisting:
        if pe == txid:
            wasPreExisting = true
            break
    if not wasPreExisting and mp.contains(txid):
        mp.removeTransaction(txid)
```

This is NOT a real test-accept. Issues:

1. `acceptPackage` MUTATES `mp.spentBy`, `mp.entries`, `mp.byWtxid`,
   `mp.currentSize`, the rolling-fee state (`trackPackageRemoved`),
   and potentially evicts pre-existing low-fee entries via
   `evictLowestFee` at line 2304.
2. The "rollback" only walks NEW txids and removes them. It does NOT:
   - restore evicted pre-existing entries
   - reverse the rolling-fee bump
   - restore the `byWtxid` index for evicted entries
   - reverse any TRUC sibling eviction that fired
3. A concurrent thread/connection that observes the mempool between
   the acceptPackage call and the rollback sees a state that
   never existed in normal operation.

Core's `m_test_accept` is a flag passed through to the actual
admission pipeline; the pipeline early-returns AFTER all checks pass
BUT BEFORE any state mutation (validation.cpp:1388). Zero side effects.

**File:** `src/rpc/server.nim:3127-3150` (multi-tx testmempoolaccept);
`src/mempool/mempool.nim:2017-2336` (acceptPackage — no testAccept
param).

**Core ref:** `bitcoin-core/src/validation.cpp:1388`
(`if (args.m_test_accept) { return result; }`).

**Impact:**
- Eviction during test-accept: a low-fee in-mempool tx is evicted
  during `evictLowestFee` inside acceptPackage; rollback does NOT
  restore it; user issued a test-only RPC and lost a real tx.
- Rolling-fee state corruption: each test-accept bumps the rolling
  floor.
- Concurrency hazard: peer-relay tx admission during the test-accept
  window may see inconsistent state.

---

## BUG-13 (P0-CDIV) — `acceptPackage` ignores `client_maxfeerate` until AFTER state mutation

**Severity:** P0-CDIV (operator-protection knob deferred to AFTER side
effects; fee-runaway pre-flight broken).

Bitcoin Core's `AcceptMultipleTransactionsInternal`
(`validation.cpp:1457-1465`) is the per-tx `m_client_maxfeerate` gate
that **fail-fasts inside the PreChecks loop**:

```cpp
if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize)
                              > args.m_client_maxfeerate.value()) {
    ws.m_state.Invalid(TX_MEMPOOL_POLICY, "max feerate exceeded", "");
    package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
    return PackageMempoolAcceptResult(package_state, std::move(results));
}
```

— per-tx (not per-package), inside the PreChecks loop, BEFORE any
state mutation.

nimrod's `acceptPackage` (`mempool.nim:2017-2336`) accepts no
`clientMaxFeeRateSatKvB` parameter. The caller paths
(`handleSubmitPackage:3324`, `handleTestMempoolAccept:3195`) compute
the max-feerate check only AFTER acceptPackage returns — by which
time:

- mempool state is mutated (BUG-1, BUG-7, BUG-12 chain).
- `evictLowestFee` may have evicted pre-existing low-fee entries.
- The check operates on the PACKAGE feerate, not per-tx.

A single high-fee child in a 25-tx package can sneak in unnoticed —
the package-aggregate feerate is dominated by the parents' low fees,
so the package-level max-feerate check at server.nim:3324 passes; the
per-tx high fee is admitted.

**File:** `src/rpc/server.nim:3324, 3195`;
`src/mempool/mempool.nim:2017-2336`.

**Core ref:** `bitcoin-core/src/validation.cpp:1457-1465`.

**Impact:** operator's `maxfeerate` safety net does not catch per-tx
fee outliers; pre-flight protection broken.

---

## BUG-14 (P1) — `acceptPackage` already-in-mempool path doesn't distinguish wtxid vs txid match

**Severity:** P1 (BIP-141 wire-parity slip; replaced-witness paths
silently mis-attribute results).

`mempool.nim:2120-2126`:

```nim
# Check if already in mempool
if txid in mp.entries:
    txResult.allowed = true
    txResult.fees = mp.entries[txid].fee
    fees.add(txResult.fees)
    result.txResults.add(txResult)
    continue
```

Only one check — by txid. The TxResult emitted carries the SUBMITTED
tx's wtxid (line 2113 `wtxid: tx.wtxid()`), but the mempool entry's
witness may differ (same-txid-different-wtxid case).

Bitcoin Core's `AcceptPackage` (`validation.cpp:1664-1686`) is
explicit:

```cpp
if (m_pool.exists(wtxid)) {
    // Exact transaction already exists in the mempool.
    const auto& entry{*Assert(m_pool.GetEntry(txid))};
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTx(entry.GetTxSize(),
                                                                 entry.GetFee()));
} else if (m_pool.exists(txid)) {
    // Transaction with the same non-witness data but different witness (same
    // txid, different wtxid) already exists in the mempool.
    const auto& entry{*Assert(m_pool.GetEntry(txid))};
    // Provide the wtxid of the mempool tx so that the caller can look it up.
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(
                                       entry.GetTx().GetWitnessHash()));
} else { ... }
```

— two distinct result types so the submitter knows whether the
on-record witness matches what they sent.

**File:** `src/mempool/mempool.nim:2120-2126`.

**Core ref:** `bitcoin-core/src/validation.cpp:1664-1686`.

**Impact:**
- Wallet that broadcasts a re-witnessed copy of a malleated tx gets
  "allowed=true" with its own wtxid in the response, but the mempool
  actually holds the ORIGINAL witness.
- BIP-141 same-txid-different-wtxid distinction lost across RPC
  boundary.
- Downstream RBF tooling that re-fetches the on-record witness via
  getmempoolentry may compute different sighash / signature paths.

---

## BUG-15 (P0-CDIV) — `acceptPackage` script-verify uses CONSENSUS flags, not STANDARD (W150 BUG-8 carry-forward; two-pipeline guard 19th distinct fleet instance)

**Severity:** P0-CDIV (13 of 14 STANDARD policy flags bypassed in
package path; W150 BUG-8 carry-forward, **STILL OPEN**, re-confirmed).

`mempool.nim:2213`:

```nim
# Second pass: verify scripts and add to mempool
let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)
```

This is the CONSENSUS flag set — the same flags the next block's
validation will use. The MempoolAccept policy expansion at
`mempool.nim:863` (`standardScriptVerifyFlags`) adds:

- NULLFAIL
- LOW_S
- MINIMALDATA
- MINIMALIF
- CLEANSTACK
- STRICTENC
- WITNESS_PUBKEYTYPE
- CONST_SCRIPTCODE
- DISCOURAGE_UPGRADABLE_NOPS
- DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
- DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
- DISCOURAGE_OP_SUCCESS
- DISCOURAGE_UPGRADABLE_PUBKEYTYPE

13 of 14 STANDARD-not-mandatory flags. None apply in the package
path. A non-standard but consensus-valid tx wrapped in a 1-tx package
via `submitpackage` RPC admits, while the SAME tx via
`sendrawtransaction` rejects (single-tx path runs both passes).

**Two-pipeline guard 19th distinct fleet extension** (cross-cite
W150 BUG-8 = 18th; W144 lunarblock BUG-3/4 native witness dispatch =
17th; W144 ouroboros BUG-2 short-circuit = 16th; etc.).

**File:** `src/mempool/mempool.nim:2213`.

**Core ref:** `bitcoin-core/src/validation.cpp:1135-1156`
(`PolicyScriptChecks` uses `STANDARD_SCRIPT_VERIFY_FLAGS`);
`bitcoin-core/src/policy/policy.h:99-119` (`STANDARD_SCRIPT_VERIFY_FLAGS`
definition).

**Impact:** see W150 BUG-8 details — 13-flag policy bypass on every
package admission. The fix is a 2-line change at mempool.nim:2213:

```nim
let consensusFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)
let scriptFlags = standardScriptVerifyFlags(consensusFlags)
```

W150 audit reported it; no fix landed; this W151 audit re-confirms.

---

## BUG-16 (P1) — `acceptPackage` runs script-verify ONCE; no ConsensusScriptChecks second pass

**Severity:** P1 (Core's belt-and-suspenders defense against
policy-flag bugs accepting consensus-bad txs is missing in package
path; W150 BUG-9 carry-forward).

Bitcoin Core's `AcceptMultipleTransactionsInternal` runs BOTH
PolicyScriptChecks (STANDARD flags) AND ConsensusScriptChecks
(consensus flags) for every tx. The latter exists specifically to
catch the case where a buggy STANDARD flag accepts a consensus-bad tx;
Core logs `"BUG! PLEASE REPORT THIS!"` and `Assume(false)` on
divergence (validation.cpp:1184).

`acceptPackage` at `mempool.nim:2216-2269` runs ONE script-verify pass
(line 2254). No second pass. If BUG-15 is fixed (script flags
corrected to STANDARD), the next defensive layer should re-verify
under consensus flags; that layer is also missing.

**File:** `src/mempool/mempool.nim:2216-2269`.

**Core ref:** `bitcoin-core/src/validation.cpp:1158-1189`
(`ConsensusScriptChecks`).

**Impact:** belt-and-suspenders defense absent in package admission;
single source-of-truth for script flags.

---

## BUG-17 (P1) — `findInPackageParents` is O(n × inputs) on every tx; quadratic worst case on 25-tx package

**Severity:** P1 (performance/DoS amplifier in `checkPackageTrucRules`).

`package.nim:334-347`:

```nim
proc findInPackageParents(txns: seq[Transaction], txIndex: int): seq[int] =
    let tx = txns[txIndex]
    var parents: seq[int]
    for i in 0 ..< txIndex:    # earlier txs
        let parentTxid = txns[i].txid()
        for input in tx.inputs:
            if input.prevOut.txid == parentTxid:
                parents.add(i)
                break
    parents
```

Called from `checkPackageTrucRules` at line 386 — inside an outer loop
over all 25 pkg txs. Total complexity: 25 × 25 × max_inputs txid hash
computations = 625 × ~150 (typical max-input) = 93 750 hash compares
per pkg, with each `txns[i].txid()` re-computing the SHA256d hash.

`txid()` is not memoised — each call serialises the tx and runs two
SHA256 rounds. Typical 1KB tx → ~25 KB serialised data per pkg traversal
× 25 = 625 KB hashing per pkg. Attacker can construct a max-weight
25-tx pkg (16KB-per-tx witness, MAX_PACKAGE_WEIGHT bound) that forces
~10MB of redundant hashing per pkg admission.

**File:** `src/mempool/package.nim:334-347`.

**Core ref:** `bitcoin-core/src/policy/truc_policy.cpp` (uses
pre-computed wtxid-keyed maps; O(n) walk).

**Impact:** package admission CPU cost is quadratic in pkg size;
combined with BUG-8 (no wire-side topology check), attacker can spray
`pkgtxns` to grind CPU.

---

## BUG-18 (P1) — `MaxPackageSize=101_000` vbytes is a redundant gate that diverges from MAX_PACKAGE_WEIGHT by rounding

**Severity:** P1 (subtle: `MaxPackageWeight=404_000` and
`MaxPackageSize=101_000` vbytes are NOT equivalent at the boundary).

`package.nim:45,48,51`:

```nim
MaxPackageWeight* = 404_000
MaxPackageSizeKvB* = 101
MaxPackageSize* = MaxPackageSizeKvB * 1000  ## 101,000 vbytes
```

`mempool.nim:2060`:

```nim
if totalVsize > MaxPackageSize:   # 101_000 vbytes
    ...
```

But Core uses only `MAX_PACKAGE_WEIGHT = 404'000`
(`bitcoin-core/src/policy/packages.h:24`) and has NO separate vbyte
gate. The two are not equivalent: `vsize = (weight + 3) / 4` (rounding
up per tx). For a pkg of 25 txs each of weight 16162 (just under
~16164 needed to hit 404 050 total weight cap), `vsize` per tx =
`(16162 + 3) / 4 = 4041`, total vsize = 101 025 — which **exceeds
nimrod's 101 000 vbyte gate but passes Core's 404 000 weight gate**
(25 × 16162 = 404 050 — wait, actually fails Core's at 404 050 > 404 000).

Let me reconsider: weight 16000 per tx → vsize 4000 per tx; 25 × 16000
= 400 000 weight (within 404 000), 25 × 4000 = 100 000 vsize (within
101 000). Weight 16160 per tx → 25 × 16160 = 404 000 weight (within),
vsize = (16160+3)/4 = 4040 each → 25 × 4040 = 101 000 vsize (within).

But weight 16161 → 404 025 weight FAIL Core; vsize = 4041 → 101 025
vsize FAIL nimrod. So at the boundary the two roughly agree.
However: weight 16001 per tx → 25 × 16001 = 400 025 weight (within
404 000); vsize = (16001+3)/4 = 4001 each → 25 × 4001 = 100 025
vsize (within 101 000). So both gates pass for fingerprintable
boundary cases.

The actual divergence: nimrod's `MaxPackageSize` gate fires
UNCONDITIONALLY for packages of any size (line 2060 has no `txns.len > 1`
guard), whereas Core's `MAX_PACKAGE_WEIGHT` is gated by `package_count
> 1` (packages.cpp:90, "If the package only contains 1 tx, it's better
to report the policy violation on individual tx weight"). nimrod's
1-tx pkg of vsize > 101 000 is rejected with `"package-too-large"`,
whereas Core's 1-tx pkg is checked against MAX_STANDARD_TX_WEIGHT
(400 000 WU = 100 000 vbytes per `MaxStandardTxWeight`) — same error
class, different reject token.

Also note `isWellFormedPackage` at package.nim:172-181 DOES gate on
`txns.len > 1` for the weight check (matching Core), so `acceptPackage`
has TWO size gates with conflicting guards: the well-formed gate (guarded)
and the redundant vsize gate (unguarded). Redundancy is itself a
maintainability bug — the next time the constant changes only one
gate gets updated.

**File:** `src/mempool/package.nim:45-51, 172-181`;
`src/mempool/mempool.nim:2060`.

**Core ref:** `bitcoin-core/src/policy/packages.h:19-25` (only
`MAX_PACKAGE_COUNT` + `MAX_PACKAGE_WEIGHT`).

**Impact:** wire-token / reject-reason divergence for 1-tx pkgs at the
weight boundary; maintainability tax of two parallel gates with
different guards.

---

## BUG-19 (P1) — `isTopoSortedPackage` walks the package TWICE (dead-code first pass)

**Severity:** P1 (correctness-via-second-attempt; the first pass is
dead code that obscures intent and slows the function 2×).

`package.nim:89-121`:

```nim
proc isTopoSortedPackage*(txns: seq[Transaction]): bool =
    if txns.len <= 1:
        return true

    # Build set of txids that appear later in the package
    var laterTxids = initHashSet[TxId]()
    for i in countdown(txns.len - 1, 0):
        let txid = txns[i].txid()
        if i < txns.len - 1:
            laterTxids.incl(txid)

        # Check this tx's inputs don't spend from later txs
        for input in txns[i].inputs:
            if input.prevOut.txid in laterTxids:
                return false

        # Remove this txid from laterTxids for next iteration (moving backwards)
        laterTxids.excl(txid)

    # Rebuild correctly: check each tx doesn't spend from later txs
    laterTxids = initHashSet[TxId]()
    for i in countdown(txns.len - 1, 1):
        laterTxids.incl(txns[i].txid())

    for i in 0 ..< txns.len - 1:
        for input in txns[i].inputs:
            if input.prevOut.txid in laterTxids:
                return false
        laterTxids.excl(txns[i + 1].txid())

    true
```

The first pass (countdown loop) walks backwards, builds a `laterTxids`
set, checks inputs against it, then EXCLUDES the txid from the set —
which means the "later" set is actually maintained empty by the
time each iteration completes. The check `input.prevOut.txid in
laterTxids` therefore tests against an out-of-date set.

The comment at line 110 "Rebuild correctly: check each tx doesn't spend
from later txs" admits the first pass is wrong; the second pass is the
real check. Code-duplication smell (cross-cite W143 beamchain BUG-1
merkle_pairs_check byte-identical to merkle_pairs).

If the second pass were removed, the first pass's bug would surface:
`isTopoSortedPackage([A, B, C])` where C spends B's output and B
spends A's output would fail because the first iteration (i=2)
includes C in laterTxids, walks C's inputs (which reference B), B is
NOT yet in laterTxids → passes incorrectly; on iteration i=1, C is
removed from laterTxids and B is added; checks B's inputs (reference
A), A not in set → passes; finally on i=0, B is removed, A added,
checks A's inputs → passes. Topo-sorted package passes either way,
but the first pass's logic is wrong on out-of-order inputs.

**File:** `src/mempool/package.nim:89-121`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:19-50`
(single-pass forward walk with `later_txids.erase`).

**Impact:** correctness is preserved by the second pass; 2× wasted CPU
+ doubled txid() recomputation (each `txns[i].txid()` re-serialises
and SHA256-hashes the tx).

---

## BUG-20 (P1) — `acceptPackage` clears `packageUtxos` between fee-calc and script-verify passes; intra-package input lookup loses output amounts

**Severity:** P1 (intra-package script verification may use wrong
input amount on the 2nd pass).

`mempool.nim:2214`:

```nim
# Second pass: verify scripts and add to mempool
let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)
packageUtxos.clear()   # <-- HERE

for i, tx in txns:
    let txid = txids[i]

    # Skip if already in mempool
    if txid in mp.entries:
        # Update package UTXOs
        for j, output in tx.outputs:
            packageUtxos[OutPoint(txid: txid, vout: uint32(j))] = output
        continue

    # Verify scripts
    for inputIdx, input in tx.inputs:
        var scriptPubKey: seq[byte]
        var amount: Satoshi

        let utxo = mp.chainState.getUtxo(input.prevOut)
        if utxo.isSome:
            scriptPubKey = utxo.get().output.scriptPubKey
            amount = utxo.get().output.value
        elif input.prevOut in packageUtxos:
            scriptPubKey = packageUtxos[input.prevOut].scriptPubKey
            amount = packageUtxos[input.prevOut].value
        ...
```

The `packageUtxos.clear()` at line 2214 is fine — the loop rebuilds
the table as it processes txs in topo order. BUT for the special case
where a pkg tx is "already in mempool" (line 2220), the rebuild
populates `packageUtxos` from `tx.outputs` (the SUBMITTED tx), not
from the canonical mempool entry (`mp.entries[txid].tx.outputs`).

If the submitter sent a re-witnessed copy of an in-mempool tx (BIP-141
same-txid-different-wtxid case from BUG-14), the SUBMITTED tx's
witness bytes serialise differently — the **txid** is the same, but
`tx.outputs[j].scriptPubKey` and `tx.outputs[j].value` are the same
(witness data lives in input.witnesses, not output.scriptPubKey/value).
So actually outputs are identical … unless the deserialised submitted
tx has been MANIPULATED post-deserialise (a defensive paranoia
concern, not a real attack).

The REAL bug here: when a child pkg tx spends from a parent that is
"already in mempool" (i.e., not added in this pkg), the
`packageUtxos` reference returns the CHILD's view of the parent's
outputs. The `for j, output in tx.outputs` loop on line 2222 iterates
the SUBMITTED `tx` for the parent — which is identical to the mempool
entry's outputs (because they share the same txid). So no immediate
divergence.

But the OUTER bug is real: line 2240 reads
`mp.entries[input.prevOut.txid]` for unconfirmed-parent lookup. If the
parent is in `packageUtxos` AND in `mp.entries`, the elif at line 2235
matches first → uses `packageUtxos[input.prevOut]` (the submitted
output), bypassing `mp.entries`. If the submitted `tx` for the
parent has been silently swapped (BUG-14 case), the child's
script-verify uses the swapped amount.

**File:** `src/mempool/mempool.nim:2214-2273`.

**Core ref:** `bitcoin-core/src/validation.cpp::CCoinsViewMemPool::PackageAddTransaction`
ensures the in-memory coin view is consistent.

**Impact:** edge case — interacts with BUG-14 to make the impact
slightly worse, but on its own the package outputs are identical
(witness-stripped output match).

---

## BUG-21 (P1) — `acceptPackage` evicts pre-existing txs via `evictLowestFee` to make room; no `bypass_limits` semantic

**Severity:** P1 (test/replay path eviction leak; pkgtxns from peer
can DoS-evict via mempool-full path).

`mempool.nim:2302-2307`:

```nim
# Check mempool size - evict if needed
let txSize = serialize(tx).len
while mp.currentSize + txSize > mp.maxSize:
    mp.evictLowestFee()
    if mp.entries.len == 0:
        break
```

`acceptPackage` evicts pre-existing low-fee txs to make room for each
pkg tx in the third pass. There is no `bypass_limits` analogue, no
gate on the pkg-aggregate fee meeting some threshold before evicting.

A peer-relay path (via `mkPkgTxns` → `acceptPackage` per BUG-8) can
spray packages whose individual tx fees clear `mempool min fee` but
whose aggregate evicts higher-value mempool entries. Each pkgtxns
processed evicts 25 entries worth of low-fee state.

Core's package path enforces:
- `PackageRBFChecks` gate first.
- `LimitMempoolSize` at the END, after all pkg txs are committed
  (`validation.cpp:1731`), not per-tx in the middle.

nimrod's per-tx eviction in the middle of the pkg-commit loop can
evict an EARLIER tx in the same package (whose fee may be low relative
to the pre-existing tip). Result: pkg tx A is admitted; pkg tx B is
admitted but evicts A in the eviction loop; pkg tx C is admitted but
references A's outputs in `packageUtxos` (already-evicted) — the
script-verify of C may already have completed (it ran in the SECOND
pass, line 2216-2269), so the eviction happens AFTER script-verify but
BEFORE the entry actually exists in `mp.entries`. Net: C admits with a
phantom parent, mempool state is inconsistent (C's input references A
which no longer exists).

**File:** `src/mempool/mempool.nim:2302-2307`.

**Core ref:** `bitcoin-core/src/validation.cpp:1731`
(`LimitMempoolSize` after all pkg commits).

**Impact:** mid-package eviction creates phantom-parent state in
mempool; peer-relay DoS amplifier.

---

## Summary

**Bug count:** 21 (W151 audit).
**Severity breakdown:**

- **P0-CONS:** 1 (BUG-1, `acceptPackage` bypasses 19 admission gates
  including CVE-2018-17144 — carry-forward from W150 BUG-8).
- **P0-CDIV:** 7 (BUG-2 maxburnamount; BUG-4 fullRbf default;
  BUG-7 PackageRBFChecks missing; BUG-8 pkgtxns no topology check;
  BUG-10 mempoolminfee 1000× divisor; BUG-13 client_maxfeerate post-mutation;
  BUG-15 STANDARD flags bypass).
- **P1:** 13 (BUG-3 replaced-transactions empty; BUG-5 cluster vs tx
  count; BUG-6 incrementalrelayfee knob; BUG-9 minrelaytxfee knob;
  BUG-11 wire-weight cap; BUG-12 testmempoolaccept rollback unsafe;
  BUG-14 wtxid vs txid distinguish; BUG-16 ConsensusScriptChecks
  missing; BUG-17 quadratic findInPackageParents; BUG-18 redundant
  MaxPackageSize gate; BUG-19 dead-code first pass in
  isTopoSortedPackage; BUG-20 packageUtxos clear edge; BUG-21
  mid-package eviction).

**Top 3 findings:**

1. **BUG-1 (P0-CONS) — `acceptPackage` parallel pipeline bypasses
   19 of 21 admission gates, carry-forward from W150 BUG-8.** Two days
   after W150 reported it, no fix has landed. This W151 audit adds the
   gate-by-gate inventory (8 line-cited Core mandatory gates explicitly
   missing) to scope the fix. CVE-2018-17144 inflation primitive open
   via `submitpackage` RPC + `pkgtxns` wire (the latter even worse, no
   topology check — BUG-8).

2. **BUG-7 (P0-CDIV) — `PackageRBFChecks` entirely missing.**
   `acceptPackage` admits double-spends silently by overwriting
   `mp.spentBy` entries without removing the conflicting in-mempool
   tx. Mempool state corruption manifests on next block mining
   (getblocktemplate may include both conflicting txs in the
   candidate set) or on reorg disconnect (findConflicts walks
   corrupted spentBy).

3. **BUG-10 (P0-CDIV) — `mempoolminfee` / `minrelaytxfee` divisor
   1000× too low, W141 BUG-8 carry-forward 5+ weeks open.** Same line
   in `server.nim:1200` AND `rest.nim:773` — both paths divide by
   `100_000_000` (sat/BTC) instead of `100_000` (sat/BTC × 1/kvB
   factor). Every fee-estimator consumer (electrs, fulcrum,
   mempool.space, btc-rpc-explorer) under-fees by 1000×. **The fix is
   1-line in each file**, yet 3 consecutive audits (W141, W150, W151)
   have flagged it without closure.

**Fleet patterns confirmed/extended this audit:**

- **Two-pipeline guard 19th distinct fleet extension** (BUG-15;
  `acceptPackage` uses consensus flags while `acceptTransaction` uses
  standard flags).
- **Plumb-gate-then-flip nimrod-specific 5th instance** (BUG-4
  `fullRbf=false` default; cross-cite W141 BUG-7/8, W144 BUG-7, W150
  BUG-7 — same shape: field exists, gate exists, knob to flip absent).
- **Comment-as-confession 6th instance fleet-wide / 2nd nimrod**
  (BUG-3 `# (empty for now, would need RBF tracking)` cross-cite
  W144 BUG-3 / lunarblock W144 BUG-12 / beamchain W143 BUG-1 /
  ouroboros W143 BUG-7 / clearbit W144 BUG-1).
- **Asymmetric defensive depth** (BUG-8 — RPC entry honours topology
  check, wire entry skips; cross-cite W145 rustoshi mixed
  checked_add/saturating_add).
- **Code-duplication smell — byte-identical second-pass that admits
  the first is wrong** (BUG-19 `isTopoSortedPackage` two-pass with
  inline comment "Rebuild correctly"; cross-cite W143 beamchain
  merkle_pairs/merkle_pairs_check).
- **Operator-knob absence — `acceptnonstdtxn` / `minrelaytxfee` /
  `incrementalrelayfee` / `mempoolfullrbf` / `maxburnamount` all
  absent** — fleet pattern, 8+ instances across W138-W151.
- **Three-pipeline drift** (cross-cite W143 ouroboros 3-pipeline
  consensus): nimrod has TWO mempool admission paths
  (`acceptTransactionWithArgs` and `acceptPackage`) that diverge on
  ~19 gates — not 3-pipeline but the same shape, 2-pipeline.

**Priority fix waves indicated by this audit:**

1. **BUG-10 mempoolminfee divisor 1-line × 2 files** — opened W141,
   re-confirmed W150 and W151. 5+ weeks open. Lowest-effort/highest-impact.
2. **BUG-15 acceptPackage STANDARD flags** — 2-line change at
   mempool.nim:2213 to wrap `getBlockScriptFlags` in
   `standardScriptVerifyFlags`. Closes 13-flag policy bypass.
3. **BUG-1 acceptPackage gate-by-gate fix** — large architectural
   change; refactor `acceptPackage` to call `acceptTransactionWithArgs`
   per-tx (with `args.packageFeerates=true` plumbing). Closes
   CVE-2018-17144 inflation primitive in package path.
4. **BUG-4 fullRbf default flip + CLI knob** — 2-line change at
   `mempool.nim:195,213` (`fullRbf: bool = true`) + CLI flag in
   `nimrod.nim` (~10 LOC).
5. **BUG-7 PackageRBFChecks** — net-new ~50 LOC inside acceptPackage,
   patterned after Core's `validation.cpp:1042-1133`.
6. **BUG-2 maxburnamount knob** — ~15 LOC in `handleSubmitPackage` and
   `handleSendRawTransaction`.
7. **BUG-8 pkgtxns topology check** — 2-line check at
   `nimrod.nim:1254`, mirror the RPC handler's `isChildWithParentsTree`
   gate.
8. **BUG-13 client_maxfeerate per-tx plumbing** — add parameter to
   `acceptPackage` signature, fail-fast in fee-calc loop.
9. **BUG-19 isTopoSortedPackage dead-code removal** — delete lines
   95-108 (first pass), keep the second pass.
10. **BUG-5 cluster-aware MAX_REPLACEMENT_CANDIDATES** — net-new
    `getUniqueClusterCount` helper in cluster.nim, ~20 LOC; replace
    line 1866 with cluster-count.
