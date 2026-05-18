# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (nimrod)

**Wave:** W150 — `AcceptToMemoryPool`, `AcceptSingleTransaction`,
`MemPoolAccept::PreChecks`, `MemPoolAccept::PolicyScriptChecks`,
`MemPoolAccept::ConsensusScriptChecks`, `MemPoolAccept::ReplacementChecks`,
`Finalize`; the `ATMPArgs` struct (`m_test_accept`, `m_bypass_limits`,
`m_allow_replacement`, `m_package_feerates`, `m_client_maxfeerate`,
`m_allow_sibling_eviction`); the policy gates `IsStandardTx`,
`IsWitnessStandard`, `ValidateInputsStandardness`, `GetDustThreshold`,
`PreCheckEphemeralTx`, `CheckEphemeralSpends`; the wire-relay surface:
`STANDARD_SCRIPT_VERIFY_FLAGS`, `MANDATORY_SCRIPT_VERIFY_FLAGS`,
`MIN_STANDARD_TX_NONWITNESS_SIZE = 65`, `MAX_STANDARD_TX_WEIGHT =
400000`, `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5`,
`DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB`, `DEFAULT_INCREMENTAL_RELAY_FEE
= 100 sat/kvB`, the `-acceptnonstdtxn` / `-minrelaytxfee` /
`-incrementalrelayfee` operator knobs; the wire-token reject strings
(`txn-already-in-mempool`, `txn-same-nonwitness-data-in-mempool`,
`bad-txns-inputs-missingorspent`, `txn-already-known`,
`bad-txns-inputs-duplicate`, `bad-txns-nonstandard-inputs`,
`bad-witness-nonstandard`, `bad-txns-too-many-sigops`,
`mempool min fee not met`, `non-final`, `non-BIP68-final`,
`bad-txns-premature-spend-of-coinbase`, `dust`, `tx-size-small`,
`bip125-replacement-disallowed`, `insufficient fee`,
`mandatory-script-verify-flag-failed`, `non-mandatory-script-verify-flag`,
`witness-stripped`); `sendrawtransaction` + `testmempoolaccept` RPC
glue.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/validation.cpp:430-700` — `MemPoolAccept` class
  + `Workspace` + `SubPackageState`. Holds `m_view` (CCoinsViewCache),
  `m_viewmempool`, `m_changeset`.
- `bitcoin-core/src/validation.cpp:700-715` — `CheckFeeRate(package_size,
  package_fee, state)`: BOTH the mempool's `GetMinFee().GetFee(size)` AND
  the static `m_pool.m_opts.min_relay_feerate.GetFee(size)` must pass;
  the latter is `DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB`. State error
  is `TX_RECONSIDERABLE` (retryable in package context).
- `bitcoin-core/src/validation.cpp:782-982` — `PreChecks` (the 21-gate
  per-tx admission pipeline). In order: `CheckTransaction`,
  IsCoinBase, IsStandardTx (gated on `require_standard`),
  MIN_STANDARD_TX_NONWITNESS_SIZE (65) post-CVE-2017-12842,
  CheckFinalTxAtTip, `m_pool.exists(wtxid|txid)`, GetConflictTx +
  `m_allow_replacement`, HaveCoin loop + `txn-already-known`
  short-circuit, CalculateLockPointsAtTip / CheckSequenceLocksAtTip,
  Consensus::CheckTxInputs, ValidateInputsStandardness, IsWitnessStandard,
  GetTransactionSigOpCost (against STANDARD_SCRIPT_VERIFY_FLAGS),
  spends-coinbase flag, ChangeSet::StageAddition (with entry_sequence=0
  when `bypass_limits`), PreCheckEphemeralTx (gated on `require_standard`),
  MAX_STANDARD_TX_SIGOPS_COST, CheckFeeRate (gated on
  `!bypass_limits && !package_feerates`), SingleTRUCChecks (gated on
  `!bypass_limits`).
- `bitcoin-core/src/validation.cpp:984-1035` — `ReplacementChecks`
  (Rule #5 via `GetEntriesForConflicts`, Rule #3+#4 via `PaysForRBF`
  with `incremental_relay_feerate`, cluster-limits via
  `CheckMemPoolPolicyLimits`, Rule #8 via `ImprovesFeerateDiagram`).
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`:
  `CheckInputScripts(tx, state, m_view, STANDARD_SCRIPT_VERIFY_FLAGS,
  true, false, ...)` — `cacheSigStore=true`, `cacheFullScriptStore=false`.
  Failure detects `TX_WITNESS_STRIPPED` via `SpendsNonAnchorWitnessProg`.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`:
  `CheckInputsFromMempoolAndCache` with `GetBlockScriptFlags(tip,
  chainman)` — divergence from policy flags is "BUG! PLEASE REPORT
  THIS!" (asserts in debug).
- `bitcoin-core/src/validation.cpp:1317-1431` —
  `AcceptSingleTransactionInternal` orchestrator (PreChecks →
  ReplacementChecks → PolicyScriptChecks → ConsensusScriptChecks →
  CheckEphemeralSpends → Finalize). `EntriesAndTxidsDisjoint` is asserted
  at line 1349 to defend against ancestor-set ∩ replaced-set.
- `bitcoin-core/src/validation.cpp:1388` — `m_test_accept` short-circuit
  AFTER all checks pass but BEFORE state mutation.
- `bitcoin-core/src/validation.cpp:1402-1406` — post-eviction
  "mempool full" check returning `TX_RECONSIDERABLE`.
- `bitcoin-core/src/policy/policy.cpp:8-60` — `GetDustThreshold` uses
  output spend-size estimate (P2WPKH: 67 vB, P2WSH: 41 vB, legacy: 148 vB);
  `IsDust` returns `value < GetDustThreshold(output, dust_relay_feerate)`.
- `bitcoin-core/src/policy/policy.cpp:130-220` — `IsStandardTx`:
  version range (TX_MIN_STANDARD_VERSION=1..TX_MAX_STANDARD_VERSION=3),
  weight gate, per-input scriptSig size + push-only, per-output
  classification + datacarrier budget + bare-multisig + dust count.
- `bitcoin-core/src/policy/policy.cpp:225-260` — `AreInputsStandard` /
  `ValidateInputsStandardness`: rejects bare-NONSTANDARD inputs;
  rejects WITNESS_UNKNOWN inputs; caps P2SH redeemScript sigops at
  `MAX_P2SH_SIGOPS = 15`.
- `bitcoin-core/src/policy/policy.cpp:265-351` — `IsWitnessStandard`:
  6 gates as enumerated in `nimrod/src/mempool/standard.nim:296-305`.
- `bitcoin-core/src/policy/policy.h:38-95` — `MIN_STANDARD_TX_NONWITNESS_SIZE
  = 65`, `MAX_P2SH_SIGOPS = 15`, `MAX_STANDARD_TX_SIGOPS_COST =
  MAX_BLOCK_SIGOPS_COST/5 = 16000`, `MAX_STANDARD_TX_WEIGHT = 400000`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS = 100`, `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE
  = 80`, `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80`,
  `MAX_STANDARD_SCRIPTSIG_SIZE = 1650`, `DUST_RELAY_TX_FEE = 3000`,
  `DEFAULT_MIN_RELAY_TX_FEE = 100`, `DEFAULT_INCREMENTAL_RELAY_FEE =
  100`, `DEFAULT_PERMIT_BAREMULTISIG = true`,
  `DEFAULT_ACCEPT_DATACARRIER = true`, `EXTRA_DESCENDANT_TX_SIZE_LIMIT
  = 10000`, `MAX_DUST_OUTPUTS_PER_TX = 1`.
- `bitcoin-core/src/policy/policy.h:97-135` — `MANDATORY_SCRIPT_VERIFY_FLAGS
  = P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT`;
  `STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY | STRICTENC | MINIMALDATA |
  DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL | LOW_S |
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE |
  CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
  DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_PUBKEYTYPE`.
- `bitcoin-core/src/policy/ephemeral_policy.cpp:1-25` — `PreCheckEphemeralTx`
  rejects "tx with dust output must be 0-fee" via `GetDust(tx,
  dust_relay_rate)` (dust-threshold-based, NOT value==0).
- `bitcoin-core/src/init.cpp` — `-acceptnonstdtxn` (regtest-only knob
  for `m_pool.m_opts.require_standard`), `-minrelaytxfee=<amt>` (BTC/kvB),
  `-incrementalrelayfee=<amt>`, `-maxmempool`, `-mempoolexpiry`,
  `-mempoolfullrbf` (REMOVED in Core 28+; full-RBF is now mandatory),
  `-permitbaremultisig`, `-datacarrier`, `-datacarriersize`,
  `-bytespersigop`.
- `bitcoin-core/src/rpc/mempool.cpp` — `sendrawtransaction` (returns
  RPC_VERIFY_REJECTED -26 for mempool reject, RPC_TRANSACTION_ALREADY_IN_CHAIN
  -27 for confirmed, RPC_VERIFY_ERROR -25 for malformed),
  `testmempoolaccept` (test_accept array of 1..25 hex strings + optional
  maxfeerate).
- `bitcoin-core/src/rpc/net.cpp::getnetworkinfo` — `relayfee` and
  `incrementalfee` reported in BTC/kvB from `m_opts.min_relay_feerate`
  and `m_opts.incremental_relay_feerate` (defaults: 0.000001 BTC/kvB
  each, i.e. 100 sat/kvB).

## Files audited

- `src/mempool/mempool.nim` — `Mempool` type, `AtmpArgs`,
  `AtmpAcceptInfo`, `acceptTransactionWithArgs` (the canonical ATMP
  composing PreChecks / ReplacementChecks / PolicyScriptChecks /
  ConsensusScriptChecks at lines 883-1372), `acceptTransaction` thin
  wrapper, `acceptPackage` (parallel pipeline at lines 2017-2300),
  `evictLowestFee`, `getMinFee`, `findConflicts`,
  `checkRbfRules`, `signalsOptInRBF`, `calculateFee`,
  `calculateAncestors` / `calculateAncestorStats`, `checkPackageLimits`,
  `preCheckEphemeralTx` (line 489), `hasEphemeralDust` (line 470),
  `checkEphemeralSpends` (line 509), `getDustThreshold` (line 437),
  `standardScriptVerifyFlags` (line 863).
- `src/mempool/standard.nim` — `isStandardTx` (line 226),
  `isStandardTxOk`, `classifyStdTxout` (line 150),
  `isStandardOpReturn`, `isStandardP2PK`, `isStandardMultisig`,
  `dustThreshold` (line 189), `isDustOutput`, `isWitnessStandard`
  (line 394), `evalScriptSigPushes` (line 330); constants
  `TxMinStandardVersion = 1`, `TxMaxStandardVersion = 3`,
  `MaxStandardScriptSigSize = 1650`, `MaxOpReturnRelayBytes`,
  `MaxStandardMultisigN = 3`, `StdMaxDustOutputsPerTx = 1`,
  `StdDustRelayTxFee = 3000`, the W72 6-gate witness policy.
- `src/mempool/package.nim` — `isWellFormedPackage`,
  `isTopoSortedPackage`, `isConsistentPackage`, `checkPackageTrucRules`,
  `MaxPackageCount = 25`, `MaxPackageWeight = 404_000`,
  `MaxPackageSize = 101_000`.
- `src/mempool/cluster.nim` — `ClusterManager`, `validateRbfDiagram`
  (Rule #8 ImprovesFeerateDiagram delegate).
- `src/mempool/orphan.nim` — `OrphanPool`, `MaxOrphanTransactions=100`,
  `MaxOrphansPerPeer=25`, `MaxOrphanTxSize=100_000`,
  `OrphanExpireTime=20*60`; BIP-339 wtxid primary key.
- `src/consensus/validation.nim:1589-1653` — `checkTransaction` (the
  9-gate context-free CheckTransaction; nimrod's CVE-2018-17144
  enforcement), `isFinalTx` (line 1655), `getBlockScriptFlags`
  (line 491-524), `getTransactionSigOpCost` (called from mempool.nim
  line 1124); the `ValidationError` enum (lines 19-62) which carries
  the wire-token strings used by callers.
- `src/consensus/validation.nim:1453-1473` — `scriptFlagsToUint32`
  helper (consumed by RPC layer).
- `src/script/interpreter.nim:2141-2255` — `verifyScript`,
  :2129-2129 forward-decl of `verifyWitnessProgram`, :2392-2509
  the actual implementation (no `is_p2sh` argument — W144 BUG-3
  carry-forward); :886-896 `isP2A` / `isP2AFromProgram`.
- `src/rpc/server.nim:2894-2996` — `handleSendRawTransaction` (the
  RPC entry into ATMP). :2998-3225 `handleTestMempoolAccept` (single
  + multi-tx paths). :1199-1223 `handleGetMempoolInfo`
  (`mempoolminfee` / `minrelaytxfee` / `incrementalrelayfee` reporting).
  :3417-3434 `handleGetNetworkInfo` (`relayfee` / `incrementalfee`).
  Error codes `RpcTransactionError=-25`, `RpcTransactionRejected=-26`,
  `RpcTransactionAlreadyInChain=-27` at lines 90-92.
- `src/nimrod.nim:380-450, 826-857` — CLI parse path (no
  `-acceptnonstdtxn`, no `-minrelaytxfee`, no `-incrementalrelayfee`,
  no `-mempoolfullrbf`); `handleMessage` tx-relay path that calls
  `state.mempool.acceptTransaction(msg.tx, state.crypto)` with
  default args (no `bypassLimits`).
- `src/storage/chainstate.nim:1620-1968` — `handleReorg`
  (Pattern D single-batch); calls back into `mempool.blockDisconnected`
  (mempool.nim:1485-1501) which feeds disconnected-block txs through
  `acceptTransaction` with default args (`bypassLimits=false`) — same
  pipeline as a fresh user submission.

---

## Gate matrix (40 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `CheckTransaction` (context-free) | G1: vin not empty | PASS (`validation.nim:1605`) |
| 1 | … | G2: vout not empty | PASS (`validation.nim:1608`) |
| 1 | … | G3: base-size × 4 ≤ MAX_BLOCK_WEIGHT | PASS (`validation.nim:1614-1616`) |
| 1 | … | G4: per-output value ≥ 0 and ≤ MAX_MONEY | PASS (`validation.nim:1623-1626`) |
| 1 | … | G5: running sum ≤ MAX_MONEY | PASS (`validation.nim:1628-1629`) |
| 1 | … | G6: no duplicate inputs (CVE-2018-17144) | PASS but **BUG-1** below: wire-token slip |
| 1 | … | G7: coinbase scriptSig 2..100 bytes | PASS (`validation.nim:1644`) |
| 1 | … | G8: non-coinbase null-prevout reject | PASS (`validation.nim:1649-1651`) |
| 2 | Coinbase rejection from mempool | G9: `isCoinbase(tx)` → "coinbase" | PASS (`mempool.nim:905-906`) |
| 3 | MIN_STANDARD_TX_NONWITNESS_SIZE | G10: nonwitness < 65 → "tx-size-small" | PASS (`mempool.nim:908-912`) |
| 4 | MAX_STANDARD_TX_WEIGHT | G11: weight > 400 000 → reject | PASS (`mempool.nim:914-918`) |
| 5 | `IsStandardTx` policy | G12: version range / scriptSig size / push-only / scriptPubKey kind / dust / multisig / datacarrier | PASS (`mempool.nim:921-923` → `standard.nim:226-285`) |
| 5 | … | G13: `-acceptnonstdtxn` operator knob | **BUG-2 (P1)** `mempool.nim:1142` literally says "nimrod always runs in require_standard=true equivalent." There is no CLI flag, no field on Mempool, no escape hatch. Regtest test suites that send non-standard transactions to nimrod cannot succeed. Cross-fleet: blockbrew W137 had the same gap (W137 nimrod BUG list also flagged this in other contexts). |
| 6 | wtxid / txid duplicate gate (BIP-141) | G14: `wtxid in mp.byWtxid` → "txn-already-in-mempool" | PASS (`mempool.nim:931-932`) |
| 6 | … | G15: `txid in mp.entries` but different wtxid → "txn-same-nonwitness-data-in-mempool" | PASS (`mempool.nim:933-935`) |
| 7 | IsFinalTx + CheckSequenceLocks | G16: `isFinalTx(tx, tipHeight+1, mtp)` → "non-final" | PASS (`mempool.nim:942-944`) |
| 7 | … | G17: `checkSequenceLocksForTx` → "non-BIP68-final" | PASS (`mempool.nim:1001-1004`) |
| 8 | Conflict detection / RBF gate | G18: spentBy lookup → `findConflicts` | PASS for direct-conflict shape, **BUG-3** below for the conflict-set completeness |
| 8 | … | G19: `args.allow_replacement=false` → "bip125-replacement-disallowed" | PASS (`mempool.nim:953-954`) |
| 8 | … | G20: default fullRbf = TRUE (Core 28+) | **BUG-4 (P0-CDIV)** `mempool.nim:195, 213` — `fullRbf: bool = false` is the constructor default. Bitcoin Core 28+ removed the `-mempoolfullrbf` knob and made full-RBF mandatory. nimrod's default forces BIP-125 opt-in signaling on each direct conflict and rejects non-signaling replacements. Conversation between nimrod and a Core-28+ peer that relays a non-signaling RBF tx will diverge on relay; nimrod rejects with "BIP-125 not signaled" while Core accepts. Bandwidth-DoS class: nimrod refuses to forward txs Core mined into a block, creating perpetual re-request loops. |
| 9 | UTXO-lookup gates | G21: "txn-already-known" (any output of this txid already in cache) | PASS but **BUG-5 (P1)** scope: `mempool.nim:970-976` only short-circuits when `input.prevOut.txid notin mp.entries`. Core checks ALL outputs of `hash` against `coins_cache.HaveCoinInCache(COutPoint(hash, out))` UNCONDITIONALLY whenever ANY input is missing (validation.cpp:858-864). If an input's prevout-txid IS in the mempool but its specific outpoint isn't, nimrod returns "bad-txns-inputs-missingorspent: bad vout" rather than the more-specific "txn-already-known". Wire-cache mismatch with Core: peer rejects-cache routes the misnamed tx differently. |
| 9 | … | G22: "bad-txns-inputs-missingorspent" generic | PASS (`mempool.nim:977`) |
| 9 | … | G23: coinbase maturity gate | PASS (`mempool.nim:984-988`) |
| 10 | Fee computation + ValidateInputsStandardness | G24: fee = inputs − outputs, MoneyRange | PARTIAL — `mempool.nim:1010-1013` (`calculateFee`). The proc returns `none` on `inputValue < outputValue` OR missing parent, but does NOT distinguish "bad-txns-in-belowout" from "bad-txns-fee-outofrange". The error string at line 1012 collapses both into "bad-txns-in-belowout / bad-txns-fee-outofrange". Wire-token parity slip + non-Core error format. |
| 10 | … | G25: MoneyRange on totalInput | **BUG-6 (P1)** `mempool.nim:627-654` (`calculateFee`) does NOT check `inputValue > MaxMoney` at any step. A malicious tx that references a confirmed (or in-flight) parent UTXO with `value` near MAX_MONEY can wrap `int64` (via `inputValue += int64(...)` at line 634/641) — though in practice consensus ensures UTXOs ≤ MAX_MONEY, the missing per-step MoneyRange invariant means a future bug elsewhere (e.g. coin-import via assumeUTXO) could feed an out-of-range value into the mempool without rejection. Same shape as W145 BUG-5 (coinbase int64 wrap) on the mempool side. |
| 10 | … | G26: `ValidateInputsStandardness` (bare-NONSTANDARD inputs, WITNESS_UNKNOWN inputs, MAX_P2SH_SIGOPS=15) | PASS (`mempool.nim:1038-1107`) |
| 10 | … | G27: `IsWitnessStandard` (P2A / P2SH-wrapped / P2WSH stack-item / P2TR annex+tapscript) | PASS via `standard.nim:394-486` |
| 11 | Sigop cost gate | G28: `getTransactionSigOpCost > MAX_STANDARD_TX_SIGOPS_COST` → "bad-txns-too-many-sigops" | PASS (`mempool.nim:1124-1127`) |
| 12 | Fee policy + bypass_limits | G29: feeRate < max(minFeeRate, rollingFloor) → "mempool min fee not met" | PASS (`mempool.nim:1150-1156`) |
| 12 | … | G30: `bypass_limits` consumer for reorg-replay | **BUG-7 (P0-CDIV)** the AtmpArgs `bypassLimits` field is plumbed everywhere (lines 40, 1150, 1168, 1340) but a fleet-wide grep shows NO production caller ever constructs an AtmpArgs with `bypassLimits=true`. `mempool.blockDisconnected` (line 1485-1501) — the post-reorg mempool-refill — calls `mp.acceptTransaction(tx, crypto)` which delegates to `defaultAtmpArgs()` (line 162-173) where `bypassLimits=false`. Result: txs that were valid in a now-disconnected block can be rejected on replay if the tip-min-fee floor moved up between the original-block-mining and the disconnect. Core sets `bypass_limits=true` for the disconnected-block resurrection path precisely to avoid this (validation.cpp:948 + reorg path). This is "plumb-gate-then-don't-flip" — fleet pattern, 4th distinct nimrod instance (W141 BUG-8 mempoolminfee was 2-of-2; W144 BUG-7 was 3rd; this is the 4th). |
| 12 | … | G31: `client_maxfeerate` (sat/kvB) | PASS (`mempool.nim:1161-1164`) |
| 13 | PolicyScriptChecks vs ConsensusScriptChecks | G32: PolicyScriptChecks uses STANDARD_SCRIPT_VERIFY_FLAGS | PASS for single-tx path (`mempool.nim:1221, 1246`) but **BUG-8 (P0-CDIV)** for the parallel `acceptPackage` pipeline — see G33. |
| 13 | … | G33: PolicyScriptChecks in package path | **BUG-8 (P0-CDIV)** `mempool.nim:2213` (acceptPackage) does `let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)` — i.e., uses CONSENSUS flags only. The W96 `standardScriptVerifyFlags` policy expansion is NOT applied. Package-mode txs bypass NULLFAIL, LOW_S, MINIMALDATA, MINIMALIF, CLEANSTACK, STRICTENC, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE — i.e., 13 of 14 STANDARD-not-mandatory flags. A tx sender that wraps a non-standard but consensus-valid tx in a 1-tx package (`submitpackage` RPC) admits a tx the same node would reject from single-tx `sendrawtransaction`. Two-pipeline guard 18th distinct fleet extension. |
| 13 | … | G34: ConsensusScriptChecks re-verify with `GetBlockScriptFlags(tip)` | PASS for single-tx (`mempool.nim:1286-1289`) but **BUG-9 (P1)** for package: the package path does not run a second ConsensusScriptChecks pass at all — line 2254 is the single script-verify pass. Drop of Core's belt-and-suspenders defense against policy-flag bugs accepting consensus-bad txs. |
| 13 | … | G35: `is_p2sh` propagated to `verifyWitnessProgram` | **BUG-10 (P0-CDIV — W144 BUG-3 carry-forward, still open)** `interpreter.nim:2129-2139, 2392-2402` — neither `verifyWitnessProgram` signature accepts an `is_p2sh` argument. P2SH-wrapped v1+32 outputs evaluated as native Taproot; CLTV/CSV opcodes treated as discouraged-NOP when DISCOURAGE_UPGRADABLE_NOPS is set; pre-segwit flag-set omits WITNESS/TAPROOT. Carry-forward from W144; no fix landed in 2 weeks. |
| 13 | … | G36: `TX_WITNESS_STRIPPED` detection on policy-fail | PASS (`mempool.nim:1248-1278`) |
| 14 | RBF rules (Replacement) | G37: Rule #5 (MAX_REPLACEMENT_CANDIDATES=100), Rule #2 (HasNoNewUnconfirmed), Rule #3 (replacement_fees ≥ original_fees), Rule #4 (additional ≥ incrementalRelayFee × vsize), Rule #8 (ImprovesFeerateDiagram strict-gt) | PASS (`mempool.nim:1824-1986`) |
| 14 | … | G38: EntriesAndTxidsDisjoint for single-tx submission (ancestor-disjoint) | PASS (`mempool.nim:1197-1209` "W96 GAP #9") |
| 15 | Ephemeral dust pre-check | G39: `PreCheckEphemeralTx` rejects dust-bearing tx with non-zero fee | PASS for tx-with-dust-outputs (`mempool.nim:489-507`) but **BUG-11 (P1)** semantic: the standalone-tx guard at `mempool.nim:1309` calls `hasEphemeralDust(tx)` which only matches `value == 0` outputs (`mempool.nim:464-475`). Core's `CheckEphemeralSpends` matches `IsDust(output, dust_relay_rate)` — i.e., any output BELOW the dust threshold (typically ~330-546 sat). A tx with a 1-sat or 100-sat output (still dust at default 3000 sat/kvB dust-relay-feerate, dust threshold ~330 sat for P2WPKH) is NOT classified as "ephemeral dust" by nimrod and bypasses the "must be spent by a child" gate. Comment-as-confession at line 464-467 explicitly admits "0-value outputs". |
| 16 | Wire-token / reject-reason parity | G40: nimrod's mempool errors use Core's exact reject tokens | PARTIAL — many errors are paraphrases or contain extra context (filenames, vouts, custom prefixes). Examples: `"invalid transaction: " & error` prefix at `mempool.nim:902`; `"coinbase"` matches Core; `"non-standard tx (" & reason & ")"` adds parens not present in Core; `"bad-txns-inputs-missingorspent: " & $input.prevOut.txid` adds the hash to a reject-token that Core leaves bare; the ValidationError enum at `validation.nim:19-62` uses human English ("duplicate transaction input") where Core uses tokens ("bad-txns-inputs-duplicate"). 11-token sweep below in BUG-12. |

---

## BUG-1 (P1) — `veDuplicateInput` error string diverges from Core's `bad-txns-inputs-duplicate` wire token

**Severity:** P1 (reject-string wire-parity slippage, fleet pattern,
9th distinct nimrod instance per W125 / W145 tracking).

`src/consensus/validation.nim:40` defines:

```nim
veDuplicateInput = "duplicate transaction input"
```

Bitcoin Core's `bitcoin-core/src/consensus/tx_check.cpp:50` emits the
exact token `bad-txns-inputs-duplicate`. The wire-format mismatch
propagates through `acceptTransaction → checkTransaction → return
voidErr(veDuplicateInput)`, and ultimately surfaces as the
`reject-reason` field in `sendrawtransaction` / `testmempoolaccept`.

**Affected RPC consumers:** electrs, fulcrum, mempool.space, every
monitoring stack that grep's reject-reasons against Bitcoin Core's
token set.

**File:** `src/consensus/validation.nim:40, 1637`.
**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:50` (`return
state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate")`).

**Impact:** wire-parity slip. Same severity class as W145 lunarblock
9-token sweep, W125 reject-string companion. Operators that grep for
`bad-txns-inputs-duplicate` will miss the nimrod variant.

---

## BUG-2 (P1) — No `-acceptnonstdtxn` operator knob; `require_standard=true` permanently hardcoded

**Severity:** P1 (operator-knob absence, fleet pattern, cross-fleet 6+
instances).

`src/mempool/mempool.nim:1141-1142` carries the literal confession:

```nim
# PreCheckEphemeralTx — relay-only.  Core validation.cpp:935 gates this on
# require_standard.  nimrod always runs in require_standard=true equivalent.
```

Bitcoin Core exposes `-acceptnonstdtxn` (default false on
mainnet/testnet, automatically true on regtest) which sets
`m_pool.m_opts.require_standard` (validation.cpp:806-810). When false,
PreChecks SKIPS `IsStandardTx`, `IsWitnessStandard`,
`ValidateInputsStandardness`, `PreCheckEphemeralTx`, and (importantly)
runs script-checks against `MANDATORY_SCRIPT_VERIFY_FLAGS` only, not
STANDARD_SCRIPT_VERIFY_FLAGS.

nimrod has NO such knob. There is no CLI flag in `src/nimrod.nim:380-450`,
no field on `Mempool` (mempool.nim:63-93), no plumbing through `AtmpArgs`
(mempool.nim:37-51). Every mempool call enforces full standardness.

**Consequences:**

- **Regtest test suites** that submit non-standard txs (e.g., bare
  multisig with N > 3, OP_RETURN > 80 bytes pre-32.0, deliberately
  non-standard scriptPubKey shapes to test consensus edge cases)
  cannot execute against nimrod. Test-vector parity gap with the
  test-suite.
- **Functional-test cross-impl harness** that runs the Core test
  suite against nimrod fails on every test that uses
  `node.send_to_address(..., subtract_fee=False, addr=non_standard_addr)`
  or `node.send_raw_transaction(non_standard_hex)` patterns.
- **Operator escape-hatch absent** — a CVE in a standardness check
  cannot be worked around with `-acceptnonstdtxn=1`; the operator
  must hot-patch the source and rebuild.

**File:** `src/mempool/mempool.nim:1141-1142` (confession), `src/nimrod.nim:380-450` (no flag registered).
**Core ref:** `bitcoin-core/src/init.cpp` (`-acceptnonstdtxn`),
`bitcoin-core/src/kernel/mempool_options.h` (`require_standard`).

**Impact:** functional-test parity gap; operator-knob absence; cross-fleet pattern.

---

## BUG-3 (P0-CDIV) — `findConflicts` only returns the FIRST spender of each outpoint; loses cluster info

**Severity:** P0-CDIV.

`src/mempool/mempool.nim:1795-1801`:

```nim
proc findConflicts*(mp: Mempool, tx: Transaction): HashSet[TxId] =
  result = initHashSet[TxId]()
  for input in tx.inputs:
    if input.prevOut in mp.spentBy:
      result.incl(mp.spentBy[input.prevOut])
```

`mp.spentBy` is a `Table[OutPoint, TxId]` (line 66). It records the
single spender of each outpoint. Bitcoin Core's `m_spends` is a
multi-map: a SINGLE outpoint can be claimed by multiple in-mempool txs
during the brief window where two spenders coexist (e.g., after a
package admit before TrimToSize). Core's `GetConflictTx(outpoint)`
returns all of them.

In nimrod, the second-spender write OVERWRITES the first in `spentBy`
(see `mempool.nim:1364-1365`). The first-spender record is lost. When a
NEW tx that conflicts with the original first-spender arrives later,
`findConflicts` returns ONLY the second-spender; the first-spender's
RBF rules (BIP-125 inheritance check, ancestor signaling) never trigger
against it.

**Failure mode**: a 3-tx race —

1. Tx A (signaling RBF) lands at t=0.
2. Tx B (NOT signaling RBF) replaces A via a different path (e.g.,
   sibling eviction). `spentBy[A.outpoint]` is overwritten to B.txid.
3. Tx C tries to replace A. nimrod's `findConflicts(C)` returns
   `{B.txid}` only. Since B doesn't signal RBF, C is rejected with
   "BIP-125 not signaled" EVEN THOUGH A (the original conflict A)
   DID signal RBF and would have been replaceable.

In addition, the BIP-125 Rule-#2 check at line 1872 (`if
input.prevOut.txid in allConflicts`) is similarly under-cautious: it
only checks `allConflicts` (derived from `findConflicts`), not the
broader cluster, so a tx that spends from a sibling of the conflict
chain passes.

**File:** `src/mempool/mempool.nim:66, 1364-1365, 1795-1801`.
**Core ref:** `bitcoin-core/src/txmempool.cpp::GetConflictTx`,
`bitcoin-core/src/txmempool.h::m_spends` (multi-map / setEntries).

**Impact:** RBF correctness drift on concurrent-replacement traffic;
narrow window but reachable with adversarial relay patterns. Same
shape as W128 banman conflation (one-channel vs two-channel).

---

## BUG-4 (P0-CDIV) — Default `fullRbf = false`; nimrod requires BIP-125 opt-in even though Core 28+ removed the knob

**Severity:** P0-CDIV (fleet-wide relay-divergence with Core 28+).

`src/mempool/mempool.nim:195, 213`:

```nim
proc newMempool*(..., fullRbf: bool = false, ...): Mempool =
  Mempool(..., fullRbf: fullRbf, ...)
```

Default constructor value is `false`. Result: `checkRbfRules`
(`mempool.nim:1843-1860`) requires that at least one directly-conflicting
tx (or one of its ancestors) signal opt-in via `nSequence <=
0xfffffffd`. Non-signaling conflicts are rejected:

```nim
if not anySignals:
  return err(HashSet[TxId], "rejecting replacement: original transaction does not signal RBF opt-in (BIP-125)")
```

Bitcoin Core master/28+ removed the `-mempoolfullrbf` CLI option and
the gating logic — full-RBF is now mandatory. The `m_pool.m_signals`
field was deleted; `SignalsOptInRBF` is dead code retained only for
backwards-compatible RPC reporting. The Core changelog explicitly
labels this a "full-RBF deployment".

**Consequences:**

- **Relay divergence with mainnet fleet**: a tx broadcast on Core that
  silently replaces a non-signaling parent gets relayed by Core peers
  but rejected by nimrod. nimrod's mempool will NOT contain the new
  tx; mining-related RPCs (`getblocktemplate`) will offer the OLD
  tx; if the miner accepts and mines it, nimrod connects but blockbrew
  / hotbuns / Core all expected the new tx — relay forks the in-flight
  mempool view across the fleet.
- **No operator escape hatch**: BUG-2's "no operator knob" cascade
  applies here too — there's no `-mempoolfullrbf=1` CLI flag, no
  RPC method to flip the field, no config-file knob. Operators
  must rebuild nimrod with `fullRbf=true` injected at the call site
  in `src/nimrod.nim`.
- **`getmempoolinfo.fullrbf` field reports `false`** (server.nim:1222
  with FIX-68 attribution); operator monitoring scripts see the
  divergence but cannot fix it.

**File:** `src/mempool/mempool.nim:72, 195, 213, 1843-1860`,
`src/rpc/server.nim:1222`.
**Core ref:** Bitcoin Core 28 release notes "RBF: removed
-mempoolfullrbf option; full-RBF is now always enabled".

**Impact:** mainnet relay-fork class; cross-impl RBF semantics drift;
operator-knob absent for forward compat.

---

## BUG-5 (P1) — `txn-already-known` short-circuit narrower than Core's; mis-routes some rejects

**Severity:** P1.

Core's PreChecks at `validation.cpp:858-864`:

```cpp
if (!m_view.HaveCoin(txin.prevout)) {
    // Are inputs missing because we already have the tx?
    for (size_t out = 0; out < tx.vout.size(); out++) {
        if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
            return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
        }
    }
    return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
}
```

Note: the "txn-already-known" scan runs ONCE per missing input — but
the EARLY-RETURN means it short-circuits as soon as ANY output of the
hash is in cache. Importantly, the check is unconditional on whether
the missing-input's prevout-txid is in the mempool.

nimrod's equivalent (`mempool.nim:962-981`):

```nim
for input in tx.inputs:
  let utxo = mp.chainState.getUtxo(input.prevOut)
  if utxo.isNone:
    if input.prevOut.txid notin mp.entries:
      # ... txn-already-known scan over tx.outputs ...
      if alreadyKnown:
        return err(AtmpAcceptInfo, "txn-already-known")
      return err(AtmpAcceptInfo, "bad-txns-inputs-missingorspent: ...")
    let parentEntry = mp.entries[input.prevOut.txid]
    if int(input.prevOut.vout) >= parentEntry.tx.outputs.len:
      return err(AtmpAcceptInfo, "bad-txns-inputs-missingorspent: bad vout ...")
```

The `txn-already-known` short-circuit only fires when `input.prevOut.txid
notin mp.entries`. If the parent IS in the mempool but the specific
outpoint doesn't exist (a transient race), nimrod returns
"bad-txns-inputs-missingorspent" rather than "txn-already-known" —
the wrong wire-token for the situation.

**Failure mode**: re-broadcast of a tx whose outputs are already cached
(after an internal reorg flush that demoted the cache entry but kept
the in-mempool parent record) routes to the wrong rejection reason,
which routes to the wrong peer-DoS-cache slot, which causes the peer
to keep re-sending.

**File:** `src/mempool/mempool.nim:965-981`.
**Core ref:** `bitcoin-core/src/validation.cpp:849-867`.

**Impact:** wire-token mis-routing; peer-relay caching divergence.

---

## BUG-6 (P1) — `calculateFee` accumulator has no MoneyRange invariant; potential int64 wrap

**Severity:** P1.

`src/mempool/mempool.nim:627-654`:

```nim
proc calculateFee(tx: Transaction, mp: Mempool): Option[Satoshi] =
  var inputValue = int64(0)
  for input in tx.inputs:
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      inputValue += int64(utxo.get().output.value)
    else:
      let parentEntry = mp.get(input.prevOut.txid)
      if parentEntry.isSome:
        let parentTx = parentEntry.get().tx
        if int(input.prevOut.vout) < parentTx.outputs.len:
          inputValue += int64(parentTx.outputs[input.prevOut.vout].value)
        ...
  var outputValue = int64(0)
  for output in tx.outputs:
    outputValue += int64(output.value)
  if inputValue >= outputValue:
    some(Satoshi(inputValue - outputValue))
  ...
```

Each `inputValue += int64(...)` accumulates without checking
`inputValue > MaxMoney` (21M × 1e8 ≈ 2.1e15 << INT64_MAX ≈ 9.2e18 so a
single overflow needs ~4400 inputs at MAX_MONEY each, well above the
~5000-input practical limit). The check `if inputValue >= outputValue`
at line 651 is the only invariant. Compare Core's
`Consensus::CheckTxInputs` which performs `MoneyRange(coin.out.nValue)`
per-step and `MoneyRange(nValueIn)` cumulatively
(`bitcoin-core/src/consensus/tx_verify.cpp:208-232`).

**Failure mode (theoretical, but reaches assumeUTXO-derived attacks):**

- assumeUTXO loads a snapshot whose UTXO ledger was tampered to inject
  one UTXO with `value = INT64_MAX/2`.
- An attacker submits a tx with 3 inputs spending that UTXO + two other
  valid UTXOs of value 1 sat each. `inputValue` wraps to a small
  positive number; the inequality check at line 651 passes; the fee
  is computed as small positive; the tx admits.
- ConsensusScriptChecks runs at line 1286 but does NOT recompute
  CheckTxInputs (it only re-verifies scripts), so the inflation
  passes through to a mined block.

**File:** `src/mempool/mempool.nim:627-654`.
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:208-232`
(`CheckTxInputs` MoneyRange invariants); cross-cite W145 BUG-5
(nimrod coinbase int64 wrap defeats bad-cb-amount).

**Impact:** defense-in-depth gap; identical class to the W145 nimrod
coinbase int64 wrap finding (BUG-5) carried over to the mempool side.

---

## BUG-7 (P0-CDIV) — `args.bypassLimits` is plumbed but no production caller ever flips it to true; reorg-replay drops valid txs

**Severity:** P0-CDIV ("plumb-gate-then-don't-flip" fleet pattern,
4th distinct nimrod instance).

The `AtmpArgs.bypassLimits` field at `src/mempool/mempool.nim:40`:

```nim
bypassLimits*: bool            ## Core ATMPArgs::m_bypass_limits — used for
                               ## reorg replay; skip min-fee + TRUC limits.
```

Consumed at three sites (mempool.nim:1150, 1168, 1340) to gate the
per-tx min-fee check, the TRUC check, and the post-eviction "mempool
full" check. A grep for `bypassLimits: true` over the entire nimrod
tree returns ZERO matches:

```
$ grep -rn "bypassLimits: true\|bypassLimits = true\|AtmpArgs(.*bypass" /home/work/hashhog/nimrod/src/
(no output)
```

The reorg-replay path (`mempool.blockDisconnected` at line 1485-1501)
calls `mp.acceptTransaction(tx, crypto)` with no AtmpArgs override; the
thin wrapper at line 1376-1382 falls through to `defaultAtmpArgs()`
which sets `bypassLimits: false`.

**Consequences on reorg:** Bitcoin Core sets `bypass_limits=true` for
EVERY tx fed back into the mempool via `MaybeUpdateMempoolForReorg`
(validation.cpp:1700-1750, and the comment at validation.cpp:922-923
documents WHY: "Set entry_sequence to 0 when bypass_limits is used;
this allows txs from a block reorg to be marked earlier than any
child txs that were already in the mempool"). The bypass exists
because:

1. **Min-fee gate**: between original-mining-time and reorg-time, the
   mempool's `rollingMinimumFeeRate` can have bumped UP (e.g., a fee
   spike during the orphaned blocks). Without `bypass_limits`, a tx
   that was perfectly valid 10 minutes ago is now rejected; the
   re-org silently DROPS it.
2. **Post-eviction "mempool full"**: same problem; the eviction phase
   can have raised the floor above the original tx's feerate.
3. **TRUC checks**: a TRUC v3 tx that violates the 2-ancestor /
   2-descendant rule may have been valid when its block was mined
   if the rest of the cluster was confirmed (so the limit didn't bind);
   on disconnect, those previously-confirmed txs are also being
   resurrected and the cluster constraint suddenly binds at a window
   where the order of re-admission matters. Core's bypass sidesteps
   this transient.

**Failure mode (real-world):** ouroboros mainnet node observes a
6-block reorg (heights 850000..850005 → alternate chain at 850001..850006).
Original chain had a 1000-sat-fee tx in block 850002. During the orphan
window, mempool fee floor bumped to 5 sat/vB (rolling-fee escalation
from heavy traffic). On replay through `mp.acceptTransaction` with
`bypassLimits=false`, the 1000-sat tx (at ~1 sat/vB) is rejected; it
falls off the mempool. The sender now has a tx that was confirmed
twice (in the orphaned and reorged-to block), then erased. In Core
the tx would have been re-admitted at the original feerate.

**File:** `src/mempool/mempool.nim:40, 162-173, 1485-1501`.
**Core ref:** `bitcoin-core/src/validation.cpp:920-924, 1700-1750`
(`MaybeUpdateMempoolForReorg` sets `bypass_limits=true`).

**Impact:** reorg-replay silently drops txs; user-confirmed-then-evicted
class. Fleet pattern: plumb-gate-then-don't-flip, 4th distinct
nimrod instance (W141 BUG-8 mempoolminfee; W141 BUG-? ZMQ flag;
W144 BUG-3 is_p2sh — companion).

---

## BUG-8 (P0-CDIV) — `acceptPackage` parallel pipeline bypasses STANDARD_SCRIPT_VERIFY_FLAGS and most of PreChecks

**Severity:** P0-CDIV ("two-pipeline guard 18th distinct fleet
extension"; first nimrod-mempool 2-pipeline finding).

`src/mempool/mempool.nim:2017-2300` (`acceptPackage`) is a completely
separate per-tx admission pipeline from
`acceptTransactionWithArgs`. It does NOT delegate to the single-tx
ATMP. Concretely, the package path runs:

1. `isWellFormedPackage` (count, weight, sort, conflict) — package-level
2. `checkPackageTrucRules`
3. `checkEphemeralSpends`
4. Per-tx fee calculation (via inline arithmetic at line 2128-2173,
   NOT via `calculateFee` — divergent code)
5. `getBlockScriptFlags(mp.chainState.bestHeight, mp.params)` →
   per-input `verifyScript` at line 2213, 2254

The package path **OMITS** every gate that `acceptTransactionWithArgs`
runs:

| Gate | Single-tx (acceptTransactionWithArgs) | Package (acceptPackage) |
|------|---|---|
| `checkTransaction` (CVE-2018-17144 + 8 others) | line 900 | **MISSING** |
| `isCoinbase` reject | line 905 | **MISSING** (only via isWellFormedPackage's "tx.inputs.len == 0" line 137 — coinbase has 1 input, passes!) |
| MIN_STANDARD_TX_NONWITNESS_SIZE=65 | line 908-912 | **MISSING** |
| MaxStandardTxWeight | line 914-918 | **MISSING** (only per-package cap) |
| `isStandardTx` | line 921-923 | **MISSING** |
| BIP-141 wtxid/txid duplicate gate | line 931-935 | **MISSING** |
| `isFinalTx` BIP-113 | line 942-944 | **MISSING** |
| `checkSequenceLocksForTx` BIP-68 | line 1001-1004 | **MISSING** |
| Coinbase-maturity | line 984-988 | **MISSING** |
| `isWitnessStandard` (6-gate W72) | line 1017-1026 | **MISSING** |
| ValidateInputsStandardness (MAX_P2SH_SIGOPS=15) | line 1038-1107 | **MISSING** |
| `getTransactionSigOpCost > MAX_STANDARD_TX_SIGOPS_COST` | line 1124-1127 | **MISSING** |
| `preCheckEphemeralTx` (non-zero-fee dust gate) | line 1143-1145 | **MISSING** (only the spent-by-child gate runs) |
| `client_maxfeerate` per-tx | line 1161-1164 | **MISSING** |
| `STANDARD_SCRIPT_VERIFY_FLAGS` PolicyScriptChecks | line 1221, 1246 | **MISSING** — uses consensus flags only at line 2213 |
| `ConsensusScriptChecks` second-pass cache-populate | line 1286-1289 | **MISSING** |
| TX_WITNESS_STRIPPED detection | line 1248-1278 | **MISSING** |
| RBF rules (Rule #2, #3, #4, #5, #8) | line 1182-1209, 1824-1986 | **MISSING** — package path can REPLACE without RBF gates |
| EntriesAndTxidsDisjoint | line 1197-1209 | **MISSING** |
| `checkPackageLimits` (ancestor/descendant/cluster) | line 1299-1301 | **MISSING** (only TRUC + ephemeral) |

**Concrete failure modes:**

1. **Sender wraps a non-standard tx in a 1-tx package**. `submitpackage
   ["non_standard_hex"]` admits a tx that `sendrawtransaction
   non_standard_hex` would reject with `non-standard tx (...)`. The
   policy/standardness gate is bypassed.

2. **Sender wraps a tx whose witness has high-S signatures, non-MINIMALDATA
   pushes, NULLFAIL'd CHECKMULTISIG, or any of the other 13 policy-only
   flags into a package**. The package admits (consensus flags only);
   single-tx would reject ("non-mandatory-script-verify-flag").

3. **Sender wraps a CVE-2018-17144-class duplicate-input tx in a
   package**. `checkTransaction` is the canonical CVE-2018-17144
   detector; the package path SKIPS IT. The tx admits to the mempool;
   when miners include it in a block, the BLOCK is rejected by Core
   at `CheckTransaction` (consensus enforcement) — but nimrod's miner
   selecting from its own polluted mempool produces an invalid block.

4. **Sender wraps a tx with weight > 400000 (above
   MAX_STANDARD_TX_WEIGHT but below the package-wide MaxPackageWeight=404000)
   in a single-tx package**. The package's 404000 cap allows ONE
   weight=404000 tx; the per-tx 400000 cap is not enforced. The
   admitted tx exceeds policy. Consensus accepts (block weight cap is
   4000000), so the tx CAN mine, but creates a mempool/policy divergence.

**This is the "two-pipeline guard" fleet pattern at the in-impl level**
— nimrod has both `acceptTransactionWithArgs` AND `acceptPackage`, the
latter does NOT delegate to the former, and they enforce DIFFERENT
gate sets. 17 prior fleet-wide two-pipeline findings have been
catalogued (most recent: W145 rustoshi 3-merkle / ouroboros 3-pipeline
/ camlcoin 5-pipeline); this is the 18th distinct extension and the
first to land inside the mempool subsystem specifically.

**File:** `src/mempool/mempool.nim:2017-2300`.
**Core ref:** `bitcoin-core/src/validation.cpp::AcceptMultipleTransactions`
calls `AcceptSubPackage` → `AcceptSingleTransaction` per-tx, which
runs the FULL PreChecks → PolicyScriptChecks → ConsensusScriptChecks
pipeline. The single-tx and package paths share their PER-TX
admission gates 1:1.

**Impact:** **mempool/policy divergence reachable via 1-tx package**;
CVE-2018-17144 detection bypassed in package path; all 14 STANDARD
flags bypassed; ALL RBF rules bypassed. The testmempoolaccept path
in `rpc/server.nim:3127-3225` routes multi-tx via this very pipeline,
so `testmempoolaccept ["tx1_hex", "tx2_hex"]` may say "allowed=true"
for a tx that single-tx submission rejects.

---

## BUG-9 (P1) — Package path drops the ConsensusScriptChecks belt-and-suspenders pass

**Severity:** P1 (cross-cite BUG-8; subset).

Core's MemPoolAccept runs `PolicyScriptChecks` (STANDARD flags) THEN
`ConsensusScriptChecks` (block-flags) precisely because policy-flag
bugs have historically let consensus-bad txs into the mempool (the
STRICTENC / CHECKSIG NOT example documented in
`validation.cpp:1173-1177` is "useful in case of bugs in the standard
flags that cause transactions to pass as valid when they're actually
invalid"). When PolicyScriptChecks passes but ConsensusScriptChecks
fails, Core logs `"BUG! PLEASE REPORT THIS!"` and asserts.

nimrod's `acceptTransactionWithArgs` correctly runs both passes
(`mempool.nim:1220-1289`). `acceptPackage` runs only ONE pass with
consensus flags (`mempool.nim:2213, 2254`). Result: the bug-class
that ConsensusScriptChecks is designed to catch (policy-flag bug
admits consensus-bad tx) is NOT caught in the package path; the tx
admits and propagates to peers via tx-relay where Core peers will
reject it as `mandatory-script-verify-flag-failed`. Bandwidth-DoS
class: nimrod sends txs to Core that Core rejects.

**File:** `src/mempool/mempool.nim:2213, 2254` (single script-verify
pass with consensus flags only).
**Core ref:** `bitcoin-core/src/validation.cpp:1135-1189` (the
PolicyScriptChecks / ConsensusScriptChecks split).

**Impact:** loss of belt-and-suspenders defense; relay-DoS class.

---

## BUG-10 (P0-CDIV — W144 BUG-3 carry-forward, still open) — `is_p2sh` not propagated to `verifyWitnessProgram`

**Severity:** P0-CDIV.

**Carry-forward status:** **2 weeks open** from W144 (committed
2026-05-04 in nimrod meta), no fix landed. This wave re-confirms
the bug is still in place in the mempool/PolicyScriptChecks call
path:

`src/mempool/mempool.nim:1239-1240`:

```nim
let verified = verifyScript(
  input.scriptSig, scriptPubKey, tx, inputIdx, amount, flags, witness)
```

calls `src/script/interpreter.nim:2141` which calls (at line 2210-2213
or 2244-2248) `verifyWitnessProgram(witness, witnessVersion, ...)`.
The `verifyWitnessProgram` signature (line 2129-2139 forward-decl,
2392-2402 impl) does NOT accept an `is_p2sh` argument.

**Consequences in the PolicyScriptChecks context (same as the W144
ConnectBlock context):**

- P2SH-wrapped v1+32 outputs (witness program length 32 wrapped in
  P2SH) are evaluated as **native Taproot** — Core distinguishes
  `is_p2sh=true` and returns `set_success` without taproot semantics
  (P2SH-wrapped Taproot is not a real script type).
- The CLTV / CSV opcodes can be confused with DISCOURAGE_UPGRADABLE_NOPS
  for some witness flag combinations.

**Cross-cite:** W144 BUG-3 ledger entry — same primitive, just
re-confirmed at the mempool entry-point. Two-pipeline divergence
between block-validation and mempool-validation does NOT exist for
this bug (both share `verifyScript`); but the bug is still active.

**File:** `src/script/interpreter.nim:2129-2139, 2210-2213, 2244-2248,
2392-2402`.
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1917, 2042, 2087`
(call sites with `is_p2sh=false/true`).

**Impact:** P0-CDIV carry-forward; closed-on-fix-side-only candidates
exhausted.

---

## BUG-11 (P1) — Ephemeral-dust standalone guard uses `value == 0` instead of Core's `IsDust(output, dust_relay_rate)`

**Severity:** P1.

`src/mempool/mempool.nim:464-475`:

```nim
proc isEphemeralDust*(output: TxOut): bool =
  ## Check if an output is ephemeral dust (0-value dust output)
  ## Ephemeral dust is specifically 0-value outputs that are meant to be
  ## immediately spent by a child transaction (for fee bumping via CPFP)
  int64(output.value) == 0

proc hasEphemeralDust*(tx: Transaction): bool =
  for output in tx.outputs:
    if isEphemeralDust(output):
      return true
  false
```

Bitcoin Core's `CheckEphemeralSpends` (`policy/ephemeral_policy.cpp`)
uses `GetDust(tx, dust_relay_rate)` — i.e., any output with
`value < GetDustThreshold(output, dust_relay_rate)`. At the default
`DUST_RELAY_TX_FEE=3000 sat/kvB`, the dust threshold is ~330 sat for
P2WPKH and ~546 sat for legacy P2PKH (the canonical "546 satoshi" Bitcoin
folklore).

**Failure mode at the standalone-tx guard (line 1309):**

```nim
if hasEphemeralDust(tx):
  return err(AtmpAcceptInfo,
             "ephemeral-dust-must-be-spent: standalone tx has ephemeral dust output but no child spending it; use package relay")
```

A tx with one 100-sat P2WPKH output is below the 330-sat dust
threshold → IS dust per Core → must be spent by a child → MUST come
in a package. nimrod's check returns FALSE (value 100 ≠ 0); the
standalone-tx admit succeeds. The dust output sits in the mempool as a
standalone "ephemeral but undetected" entry, never gets spent (no child
arrives because the sender intended package-relay), and EVENTUALLY
gets evicted by the 14-day expiry. Cumulative resource leak for
adversarial submission patterns.

Crucially, the `preCheckEphemeralTx` function at line 489 DOES use
`getDustOutputs` (which uses `isDust` → real dust-threshold check) at
line 499. So the per-tx "must be 0-fee" gate is correct. But the
"must-be-spent" guard at line 1309 uses the value==0 helper — the
two paths use DIFFERENT semantics for what counts as "ephemeral dust".
Intra-file two-pipeline guard.

**Comment-as-confession** (5th-distinct fleet instance): the docstring
at line 464-467 explicitly says "0-value outputs" — the implementation
matches the comment, but the comment itself documents the divergence
from Core's threshold-based semantics.

**File:** `src/mempool/mempool.nim:464-475, 1309`.
**Core ref:** `bitcoin-core/src/policy/ephemeral_policy.cpp::PreCheckEphemeralTx`
+ `::CheckEphemeralSpends` (both use `GetDust(tx, dust_relay_rate)`).

**Impact:** resource leak via undetected ephemeral-dust standalone txs;
two-pipeline within one module.

---

## BUG-12 (P1) — Reject-string token sweep: 11 nimrod tokens diverge from Core's wire format

**Severity:** P1 (reject-string wire-parity slippage, multi-token
sweep, fleet pattern — companion to lunarblock W145 9-token sweep,
camlcoin W143 multi-token sweep, W125 reject-string companion).

Comparison table (nimrod string vs Core token):

| nimrod (file:line) | Core token (file:line) |
|---|---|
| `veDuplicateInput = "duplicate transaction input"` (validation.nim:40) | `bad-txns-inputs-duplicate` (tx_check.cpp:50) |
| `veInputsMissing = "transaction inputs missing"` (validation.nim:29) | `bad-txns-vin-empty` (tx_check.cpp:11) |
| `veBadOutputValue = "invalid output value"` (validation.nim:41) | `bad-txns-vout-empty` (tx_check.cpp:14) |
| `veNegativeOutput = "negative output value"` (validation.nim:42) | `bad-txns-vout-negative` (tx_check.cpp:25) |
| `veOutputTooLarge = "output value exceeds MAX_MONEY"` (validation.nim:43) | `bad-txns-vout-toolarge` (tx_check.cpp:27) |
| `veImmatureCoinbase = "spending immature coinbase"` (validation.nim:32) | `bad-txns-premature-spend-of-coinbase` (tx_verify.cpp:174) |
| `veBadCoinbaseSize = "coinbase script size invalid"` (validation.nim:26) | `bad-cb-length` (tx_check.cpp:48) |
| `"invalid transaction: " & error` (mempool.nim:902) | (Core never prefixes — emits the token directly) |
| `"non-standard tx (" & reason & ")"` (mempool.nim:923) | direct: `<reason>` (the reason IS the token: "version", "tx-size", etc.) |
| `"bad-txns-inputs-missingorspent: " & $input.prevOut.txid` (mempool.nim:977) | `bad-txns-inputs-missingorspent` (bare — Core's debug message carries the txid, not the wire-token) |
| `"non-final"` (mempool.nim:944) | `non-final` (PASS — token matches) |
| `"non-BIP68-final: " & error` (mempool.nim:1004) | `non-BIP68-final` (Core's debug-only suffix is the lockpoints; nimrod leaks internal seqlock error format) |
| `"bad-txns-fee-outofrange / bad-txns-in-belowout"` (mempool.nim:1012) | EITHER `bad-txns-in-belowout` OR `bad-txns-fee-outofrange` (Core separates) |

For nimrod's `sendrawtransaction` / `testmempoolaccept` / `getrawmempool`
RPC consumers (electrs, fulcrum, mempool.space, nbxplorer, the entire
ecosystem of explorer/wallet tools that grep reject-reasons for the
~30 canonical Bitcoin Core tokens), these mismatches mean:

- Alert pipelines that match `bad-txns-inputs-duplicate` miss every
  nimrod CVE-2018-17144 reject.
- Wallet flows that handle `bad-txns-premature-spend-of-coinbase`
  specifically (to surface "your tx is spending immature coins, wait
  until block depth X") see the nimrod variant as an opaque "spending
  immature coinbase" string.
- Cross-impl test-suite assertions that `assert reject_reason ==
  "bad-cb-length"` fail.

**File:** `src/consensus/validation.nim:29-62` (the ValidationError
enum table), `src/mempool/mempool.nim:902, 912, 917, 923, 944, 977,
1004, 1012, 1026, 1049, 1052, 1057, 1062, 1106, 1127, 1145, 1154,
1163, 1171, 1175, 1178, 1193, 1207, 1243, 1277, 1278, 1289, 1301,
1311, 1342` (every `err(...)` call site).

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp`,
`bitcoin-core/src/consensus/tx_verify.cpp`,
`bitcoin-core/src/validation.cpp`,
`bitcoin-core/src/policy/policy.cpp` (all `state.Invalid(...)` call
sites).

**Impact:** wire-token divergence affects ecosystem tools, cross-impl
test-suite parity, peer rejection-cache routing (a Core peer routes
rejection by token; a non-matching token routes to a different DoS
cache slot, breaking the de-duplication that protects against
re-relay storms).

---

## BUG-13 (P1) — `DefaultMinFeeRate = 1 sat/vbyte` is 10× Core's `DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB`

**Severity:** P1 (operator-default divergence, fleet pattern,
cross-cite W141 BUG-8 mempoolminfee divisor).

`src/mempool/mempool.nim:97`:

```nim
DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum
```

Bitcoin Core's `bitcoin-core/src/policy/policy.h:70`:

```cpp
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};   // 100 sat/kvB
```

100 sat/kvB = 0.1 sat/vB. nimrod is **10× Core**. The implication:
nimrod's default mempool refuses any tx below 1 sat/vB; Core's
default mempool accepts down to 0.1 sat/vB. A tx broadcast at 0.5
sat/vB (legitimate low-fee, low-priority transfer) is relayed by
Core peers but rejected by nimrod. Pure relay divergence.

**Operator-knob absent (cross-cite BUG-2 family):** no
`-minrelaytxfee=<amt>` CLI flag in `src/nimrod.nim:380-450`. The
`minFeeRate` field is a constructor argument
(`mempool.nim:194`) but the only call site that constructs the
mempool (`src/nimrod.nim` setup path) uses the default. Operators
cannot lower it.

Additionally, the `incrementalRelayFeeRate` constructor parameter
defaults to `DefaultIncrementalRelayFeeSatKvB = 100.0` (line 102, 202)
which IS Core's default. So nimrod's `min_relay_feerate / incremental_relay_feerate`
ratio is `1000 / 100 = 10` — Core's ratio is `100 / 100 = 1`. RBF Rule
#4 ("additional ≥ incrementalRelayFee × vsize") therefore needs
**10× less** extra fee to RBF on nimrod than on Core for the same tx —
a NIM RBF is much cheaper than a Core RBF. Defensive-mempool DoS gap.

**File:** `src/mempool/mempool.nim:97, 194`; `src/nimrod.nim:380-450`
(no `-minrelaytxfee` flag).
**Core ref:** `bitcoin-core/src/policy/policy.h:70` (default 100 sat/kvB).

**Impact:** relay-floor divergence (10× Core); RBF-cost divergence
(10× cheaper); operator-knob absence (cannot match Core's value).

---

## BUG-14 (P1) — `getmempoolinfo` reports `mempoolminfee` in wrong units (per the W141 BUG-8 carry-forward)

**Severity:** P1 (W141 BUG-8 carry-forward; reported earlier; **still
open** ~3 weeks after first ticketing).

`src/rpc/server.nim:1199-1223` (`handleGetMempoolInfo`):

```nim
let minFee = rpc.mempool.minFeeRate / 100000000.0  # Convert sat/vbyte to BTC/kB
...
"mempoolminfee": minFee,
"minrelaytxfee": minFee,
```

Bitcoin Core reports `mempoolminfee` and `minrelaytxfee` in **BTC/kvB**,
not BTC/kB. The conversion from sat/vB is:

- sat/vB → sat/kvB: × 1000
- sat/kvB → BTC/kvB: ÷ 100_000_000

Therefore sat/vB → BTC/kvB: × 1000 / 100_000_000 = ÷ 100_000.

nimrod divides by 100_000_000 — **off by factor 1000**. Concretely:

- `mp.minFeeRate = 1.0` (1 sat/vB)
- Correct: `1.0 / 100_000 = 0.00001 BTC/kvB`
- nimrod emits: `1.0 / 100_000_000 = 0.00000001 BTC/kvB` (0.001 sat/kvB)

A monitoring stack scraping nimrod sees `mempoolminfee = 1e-8`, which
is below Core's `DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB = 1e-6 BTC/kvB`;
the operator concludes nimrod's policy is wide-open, when in fact it
is 10× MORE restrictive than Core.

**Carry-forward status:** flagged in W141 (committed 2026-05-15 in
nimrod meta) as "P1 mempoolminfee 1000× divisor regression". No
fix landed in ~3 weeks. Same line is still in production.

**File:** `src/rpc/server.nim:1200, 1212, 1213`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::MempoolInfoToJSON`
(emits `m_opts.min_relay_feerate.GetFeePerK()` which is sat/kvB,
divided by COIN to yield BTC/kvB).

**Impact:** monitoring-stack mis-report; operator confusion; W141
BUG-8 carry-forward.

---

## BUG-15 (P1) — `getnetworkinfo` `relayfee` and `incrementalfee` hardcoded at 0.00001 BTC/kvB (10× Core default)

**Severity:** P1.

`src/rpc/server.nim:3430-3431`:

```nim
"relayfee": 0.00001,
"incrementalfee": 0.00001,
```

Core emits `m_pool.m_opts.min_relay_feerate.GetFeePerK() / COIN` (the
per-kvB value in BTC) and `incremental_relay_feerate.GetFeePerK() /
COIN`. With defaults (100 sat/kvB each), Core reports
`0.000001 BTC/kvB` for both.

nimrod hardcodes `0.00001` (which is 1000 sat/kvB = 10× Core). The
value:
- Doesn't match `mp.minFeeRate` (which is 1 sat/vB = 1000 sat/kvB =
  0.00001 BTC/kvB — happens to coincide IF the units in BUG-14 were
  computed correctly, which they aren't).
- Doesn't match Core's default (100 sat/kvB = 0.000001 BTC/kvB).
- Is also hardcoded — a runtime change to `mp.minFeeRate` or
  `mp.incrementalRelayFeeRate` is NOT reflected.

Three sources of relay-fee truth (BUG-13, BUG-14, BUG-15) all disagree
internally:

1. `mp.minFeeRate = 1.0 sat/vB = 1000 sat/kvB` (mempool default)
2. `getmempoolinfo.mempoolminfee` reports `1e-8 BTC/kvB` (BUG-14 divisor)
3. `getnetworkinfo.relayfee` hardcodes `1e-5 BTC/kvB`

**File:** `src/rpc/server.nim:3430-3431`.
**Core ref:** `bitcoin-core/src/rpc/net.cpp::getnetworkinfo`.

**Impact:** monitoring contract gap; three sources of truth disagree.

---

## BUG-16 (P1) — `handleSendRawTransaction` swallows already-in-mempool as idempotent success; Core distinguishes

**Severity:** P1.

`src/rpc/server.nim:2947-2952`:

```nim
if rpc.mempool.contains(txid):
  # Already in mempool, just return the txid (idempotent)
  # Re-broadcast to peers to help propagation
  if rpc.peerManager != nil:
    asyncSpawn rpc.peerManager.broadcastTx(tx)
  return %txidHex
```

Bitcoin Core's `sendrawtransaction` (`bitcoin-core/src/rpc/mempool.cpp`)
also accepts already-in-mempool as success, BUT returns
`RPC_TRANSACTION_ALREADY_IN_CHAIN (-27)` if the tx is in chain or in
mempool AND `args.dont_drop_anyway` is set. nimrod's idempotent path
re-broadcasts to peers unconditionally. The re-broadcast is fine,
but the re-broadcast does NOT respect any peer-rate-limit that Core
imposes — a script that loops `sendrawtransaction` 1000× per second
on the same tx will trigger a relay storm in nimrod's outbound queues
(no rate limit in `peerManager.broadcastTx` per a parallel grep).

**Lesser concern**: the operator (or some integration that relies on
Bitcoin Core's `-27` to distinguish "already confirmed" from "just
admitted") cannot distinguish via nimrod's response — nimrod returns
`%txidHex` for both "freshly admitted" and "already in mempool", and
returns `-27` only for `getUtxo.isSome` / `txIndex.isSome` (already
on-chain). The "freshly accepted" status is lost.

**File:** `src/rpc/server.nim:2947-2952`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction`.

**Impact:** integration divergence; minor relay-DoS surface.

---

## BUG-17 (P1) — `maxfeerate` enforced POST-admit on `sendrawtransaction`; tx is added then removed if fee too high

**Severity:** P1.

`src/rpc/server.nim:2959-2987`:

```nim
let acceptResult = mp.acceptTransaction(tx, rpc.crypto)   # <-- ADMITS

if not acceptResult.isOk:
  ...

# Get the fee from mempool entry to check maxfeerate
let entry = rpc.mempool.get(txid)
if entry.isSome:
  ...
  if maxFeeRate > 0 and actualFeeRate > maxFeeRateSatPerVb:
    # Remove from mempool - fee too high
    mp.removeTransaction(txid)                              # <-- ROLLBACK
    raise newRpcError(RpcTransactionRejected, ...)
```

The tx is admitted via `acceptTransaction`, then removed if its
feerate exceeds `maxfeerate`. Bitcoin Core's flow is the opposite:
ATMPArgs::m_client_maxfeerate is passed INTO `AcceptSingleTransaction`,
checked at `validation.cpp:1366-1372` BEFORE any state mutation. If
maxfeerate is exceeded, the tx is rejected and NEVER admitted.

**Consequences of the post-admit rollback in nimrod:**

1. **Mempool-eviction collateral damage**: `acceptTransaction` calls
   `evictLowestFee` when `currentSize + txSize > maxSize` (line 1329).
   If admitting the new tx caused other txs to be evicted, those
   evictions are NOT rolled back. The mempool ends up smaller AND
   missing the new tx — both worse than Core's behavior.
2. **RBF rollback collateral**: if the new tx replaced N existing txs
   (line 1295-1296), those replaced txs are GONE. Rollback only
   removes the new tx; the replaced ones don't come back.
3. **Fee-estimator state pollution**: line 1369-1370 calls
   `feeEstimator.trackTransaction(txid, feeRate, mp.chainState.bestHeight)`;
   the subsequent `removeTransaction` at line 2983 doesn't call
   `feeEstimator.removeTransaction` (wait, it does — line 1414-1415,
   so this one is OK; cross-cite W114 FIX-47).
4. **Race condition with peer relay**: between `acceptTransaction`
   admitting the tx and `removeTransaction` rolling it back, a peer
   may have already received the inv (since `peerManager.broadcastTx`
   is async-spawned at line 2990 AFTER the removeTransaction check —
   actually wait, the broadcastTx is in the success path after the
   maxfeerate check. OK, no race here.). But the `acceptTransaction`
   call itself may have caused inv to be broadcast via internal
   triggers? Re-check.

Actually re-reading: the `broadcastTx` only fires in the success path
(line 2988-2990), AFTER the maxfeerate check. So race-with-peer-relay
is not a concern. But the collateral-damage points (1, 2) above are
real: RBF replacements and lowest-fee evictions are not reversible.

`testmempoolaccept` (line 3083-3092) correctly uses `args.testAccept =
true` and `clientMaxFeeRateSatKvB` IS supported via AtmpArgs at line
1158-1164. So the bug is specifically in `sendrawtransaction`
NOT plumbing `maxfeerate` through `args.clientMaxFeeRateSatKvB`.

**File:** `src/rpc/server.nim:2959-2987` (post-admit rollback);
`src/mempool/mempool.nim:48-51` (AtmpArgs has clientMaxFeeRateSatKvB,
unused in sendrawtransaction).

**Core ref:** `bitcoin-core/src/validation.cpp:1366-1372`
(maxfeerate check INSIDE AcceptSingleTransaction; rejects before
mutation).

**Impact:** RBF-rollback collateral damage; lowest-fee-eviction
collateral damage. Operator who guards against runaway fees via
maxfeerate gets unexpected state churn.

---

## BUG-18 (P1) — `MaxOrphanTransactions = 100` is hardcoded; not params-aware and not operator-configurable

**Severity:** P1 (operator-knob absence + hardcoded constant).

`src/mempool/orphan.nim:34`:

```nim
MaxOrphanTransactions* = 100
```

Bitcoin Core's `bitcoin-core/src/node/txorphanage.h` ships
`DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100` as the default AND exposes
`-maxorphantxs=<N>` as a CLI flag. Operators with high relay traffic
or low memory pressure tune this. nimrod hardcodes 100 with no flag.

In addition, the per-peer cap `MaxOrphansPerPeer = 25` is hardcoded
(`orphan.nim:46`); Core derives it from `(max / (outbound + 1))` at
runtime, which scales with the `-maxconnections` value.

**File:** `src/mempool/orphan.nim:34, 46`; `src/nimrod.nim:380-450`
(no flag registered).
**Core ref:** `bitcoin-core/src/node/txorphanage.h`,
`bitcoin-core/src/init.cpp` (`-maxorphantxs`).

**Impact:** operator-knob absence (cross-cite BUG-2, BUG-13). Test
ergonomics; high-traffic node tuning.

---

## BUG-19 (P1) — Two parallel fee-computation pipelines (`calculateFee` vs inline package math); diverge on edge cases

**Severity:** P1 (intra-impl two-pipeline guard, 19th distinct fleet
extension, 2nd nimrod-mempool 2-pipeline finding this wave —
companion to BUG-8).

Single-tx path: `src/mempool/mempool.nim:1010-1013` calls
`calculateFee(tx, mp)` (line 627-654). Returns `none` on
underflow / missing parent; surfaces as
"bad-txns-in-belowout / bad-txns-fee-outofrange".

Package path: `src/mempool/mempool.nim:2128-2173` re-implements the
same calculation INLINE:

```nim
for input in tx.inputs:
  let utxo = mp.chainState.getUtxo(input.prevOut)
  if utxo.isSome:
    inputValue += int64(utxo.get().output.value)
  elif input.prevOut in packageUtxos:                 # <-- only here
    inputValue += int64(packageUtxos[input.prevOut].value)
  elif input.prevOut.txid in mp.entries:
    let parentEntry = mp.entries[input.prevOut.txid]
    if int(input.prevOut.vout) < parentEntry.tx.outputs.len:
      inputValue += int64(parentEntry.tx.outputs[input.prevOut.vout].value)
```

Differences:

1. **`packageUtxos` lookup** is package-only; single-tx path has no
   such notion. Correct for the package case, BUT the inline
   re-implementation means future changes to `calculateFee` (e.g.,
   adding the MoneyRange invariant noted in BUG-6) must be made
   in TWO places.
2. **Error surface diverges**. Single-tx returns
   `"bad-txns-in-belowout / bad-txns-fee-outofrange"`; package
   returns `"outputs exceed inputs"` (line 2165) — completely
   different wire string.
3. **MoneyRange check ABSENT in both** (cross-cite BUG-6); but the
   ABSENCE is in two places.
4. **No `bad-txns-inputvalues-outofrange` check** in either path
   (Core's `Consensus::CheckTxInputs` line 219); both versions trust
   the UTXO set.

**File:** `src/mempool/mempool.nim:627-654, 2128-2173`.
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:208-232`
(single canonical `CheckTxInputs`).

**Impact:** code-duplication smell; two-pipeline drift; reject-wire-token
divergence; future-fix-must-land-in-two-places risk.

---

## BUG-20 (P2) — `evictLowestFee` selects the worst-package by root-tx fee-rate; Core uses descendant-score chunk linearization

**Severity:** P2 (algorithmic divergence; correctness within tolerance
but not Core-equivalent).

`src/mempool/mempool.nim:1600-1692` (`evictLowestFee`). The loop at
line 1617-1647 identifies a "root" (a tx with no in-mempool parents)
and computes the combined `(rootFee + sum(descFees)) / (rootWeight +
sum(descWeights))` — a single-rate-per-package metric. The selected
root + its full descendant set is removed.

Bitcoin Core's `CTxMemPool::TrimToSize` uses cluster linearization
chunks: a "chunk" is a feerate-monotone-decreasing partition of a
cluster, computed by the cluster-mempool linearization algorithm
(Core 28+ via `clustermempool` PR). Eviction targets the LOWEST-CHUNK
across all clusters, which can be a sub-set of a cluster's tail
descendants — not necessarily the whole package.

**Failure mode**: a CPFP cluster `parent(low-fee) → child(high-fee)`
has an aggregate rate that "covers" the parent. If a NEW tx
unrelated to this cluster arrives at a feerate between the parent's
and the package's combined rate, Core's chunk-eviction may take ONLY
the parent (forcing the child to detach into the orphan pool, but
preserving the high-rate child). nimrod's package eviction takes
BOTH parent AND child, losing the high-rate child entirely.

In practice the cluster-mempool semantics are subtle and nimrod's
simplification is documented at the doc-comment (line 1595-1599 —
"Crucially, Core evaluates each 'chunk' (root tx + all descendants)
as a unit..."). The comment is half-right: Core's chunk IS not the
whole package; it's a sub-tree.

**File:** `src/mempool/mempool.nim:1600-1692`.
**Core ref:** `bitcoin-core/src/cluster_linearize.h` /
`bitcoin-core/src/txmempool.cpp::TrimToSize` (Core 28+ cluster
linearization).

**Impact:** sub-optimal eviction; mempool-throughput regression
(loses some high-fee CPFP children); algorithmic correctness within
tolerance; not Core-equivalent.

---

## BUG-21 (P1) — `evictLowestFee` runs BEFORE adding the new entry; collateral-damage to existing high-feerate txs even when the new tx would lose the fight

**Severity:** P1 (eviction-ordering divergence).

`src/mempool/mempool.nim:1327-1343`:

```nim
# Check mempool size limit - evict if needed.
let txSize = serialize(tx).len
while mp.currentSize + txSize > mp.maxSize:
  mp.evictLowestFee()
  if mp.entries.len == 0:
    break

# W96 GAP #12: post-eviction "mempool full" check
let rollingFloorAfter = mp.getMinFee()
let effectiveMinFeeRateAfter = max(mp.minFeeRate, rollingFloorAfter)
if not args.bypassLimits and feeRate < effectiveMinFeeRateAfter:
  return err(AtmpAcceptInfo,
             "mempool full: post-eviction floor " & $effectiveMinFeeRateAfter &
             " > tx feerate " & $feeRate)
```

Order of operations:

1. **Evict** lowest-fee packages until `currentSize + txSize <= maxSize`.
2. **Check** the new tx's feerate against the (now possibly
   bumped-up) rolling floor.
3. If the new tx feerate < new floor, RETURN ERROR. The new tx is
   NOT added. The evictions stand.

Core's order (`bitcoin-core/src/validation.cpp:1395-1410`):

1. **Add** the new tx to the changeset.
2. `LimitMempoolSize` (which is TrimToSize): evict lowest-chunks
   while pool > target. The new tx MAY be evicted in this step
   (Core's design).
3. **Check** the changeset post-trim: if the new tx was evicted,
   return `TX_RECONSIDERABLE` (retryable for package context).

The semantic distinction: in Core, an arriving tx with feerate
below the current floor is rejected with "min relay fee not met"
at PreChecks (line 948) and NEVER reaches TrimToSize. So Core's
TrimToSize only runs for txs that beat the floor. nimrod's order
runs eviction even for txs that won't be admitted, causing eviction
of perfectly good incumbent txs in service of a doomed admission.

**Concrete failure mode:** mempool is at 99% capacity; rolling floor
is 5 sat/vB. A new tx arrives at 2 sat/vB. nimrod evicts ~100 KB of
existing txs at 5 sat/vB to make room, then runs the post-eviction
floor check, sees 2 < new-floor-after-eviction (~6 sat/vB), rejects
the new tx. The mempool now has 100 KB of newly-empty space AND has
lost ~100 KB of paying-fee txs. The "min relay fee not met" gate at
line 1150-1156 SHOULD have caught the 2 sat/vB tx before any eviction
ran (and probably DOES, depending on rollingFloor state) — but the
double-check architecture means the second eviction loop can fire on
edge cases (high-stakes RBF, TRUC, package-feerate fold-in).

**File:** `src/mempool/mempool.nim:1327-1343`.
**Core ref:** `bitcoin-core/src/validation.cpp:1395-1410` (LimitMempoolSize
AFTER changeset apply; TX_RECONSIDERABLE on self-evict).

**Impact:** collateral-damage eviction; mempool quality regression
under adversarial submission patterns.

---

## BUG-22 (P2) — `clientMaxFeeRate` plumbed through ATMP but `sendrawtransaction` doesn't pass `maxfeerate` via `args.clientMaxFeeRateSatKvB`

**Severity:** P2 (cross-cite BUG-17; subset).

The `AtmpArgs.clientMaxFeeRateSatKvB` field exists (`mempool.nim:48-51`)
and is correctly consumed at `mempool.nim:1161-1164`:

```nim
if args.clientMaxFeeRateSatKvB > 0.0 and feeRateSatKvB > args.clientMaxFeeRateSatKvB:
  return err(AtmpAcceptInfo,
             "max feerate exceeded: tx feerate " & $feeRateSatKvB & ...)
```

But `handleSendRawTransaction` (`rpc/server.nim:2929-2996`) does NOT
build an AtmpArgs at all. It calls the thin wrapper:

```nim
let acceptResult = mp.acceptTransaction(tx, rpc.crypto)
```

which delegates to `defaultAtmpArgs()` (line 162-173, `clientMaxFeeRateSatKvB:
0.0`). The `maxFeeRate` user-supplied value is checked only POST-admit
via direct compare-and-rollback (line 2978-2986, see BUG-17).

The single-tx `testmempoolaccept` path (rpc/server.nim:3083-3092) DOES
construct an AtmpArgs but sets `clientMaxFeeRateSatKvB: 0.0` (it
performs the maxfeerate check separately at line 3105-3111 in the
RPC layer). So even the test_accept path doesn't use the proper
plumbing.

**Net result**: the `clientMaxFeeRateSatKvB` AtmpArgs field is
DEAD-DATA (defined and consumed but no production caller sets it).
4th dead-data nimrod instance this wave (cross-cite BUG-7
bypassLimits dead-data).

**File:** `src/rpc/server.nim:2929-2996, 3083-3092`;
`src/mempool/mempool.nim:48-51, 162-173`.
**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction`
(passes `max_raw_tx_fee` directly into AcceptSingleTransaction via
ATMPArgs).

**Impact:** dead-data; BUG-17 collateral.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**

- **P0-CDIV:** 5 (BUG-3 findConflicts; BUG-4 fullRbf default; BUG-7
  bypassLimits dead-plumb; BUG-8 acceptPackage 2-pipeline; BUG-10
  is_p2sh W144 carry-forward)
- **P1:** 14 (BUG-1 token slip; BUG-2 acceptnonstdtxn knob; BUG-5
  txn-already-known scope; BUG-6 MoneyRange in calculateFee; BUG-9
  ConsensusScriptChecks skip in package; BUG-11 ephemeral-dust
  value==0; BUG-12 11-token sweep; BUG-13 DefaultMinFeeRate 10×;
  BUG-14 mempoolminfee divisor W141 carry-forward; BUG-15 relayfee
  hardcoded; BUG-16 sendrawtransaction idempotent; BUG-17 maxfeerate
  post-admit; BUG-18 MaxOrphanTransactions hardcoded; BUG-19
  calculateFee 2-pipeline; BUG-21 eviction order)
- **P2:** 2 (BUG-20 eviction algorithm; BUG-22 clientMaxFeeRate
  dead-data)

Verify: 5 + 14 + 2 = 21. Recount P1: BUG-1, 2, 5, 6, 9, 11, 12, 13,
14, 15, 16, 17, 18, 19, 21 = 15. Total: 5 + 15 + 2 = 22. ✓

**Carry-forwards verified open this wave:**

- **W141 BUG-8** (mempoolminfee 1000× divisor) — BUG-14 here, still open
  ~3 weeks. `src/rpc/server.nim:1200, 1212`.
- **W144 BUG-3** (`is_p2sh` not propagated) — BUG-10 here, still
  open ~2 weeks. `src/script/interpreter.nim:2129, 2392`.
- **W143 BUG-1** (`checkBlock` skips CheckTransaction on coinbase) —
  NOT mempool path; out of scope here, still confirmed open at
  `src/consensus/validation.nim:1836-1840`.
- **W145 BUG-1** (`--reindex` skips full pipeline) — NOT mempool path;
  out of scope here.
- **W149 BUG-15** (hardcoded predicates) — companion shape; this wave
  catalogues 4+ hardcoded constants (BUG-13 DefaultMinFeeRate; BUG-18
  MaxOrphanTransactions; the hardcoded `relayfee=0.00001` /
  `incrementalfee=0.00001` in BUG-15).

**Fleet patterns confirmed/extended:**

- **Two-pipeline guard 18th distinct extension** (BUG-8) — first
  nimrod-mempool two-pipeline finding; `acceptTransactionWithArgs` vs
  `acceptPackage` enforce different gate sets.
- **Two-pipeline guard 19th** (BUG-19) — `calculateFee` vs inline
  package math.
- **Plumb-gate-then-don't-flip 4th nimrod instance** (BUG-7) —
  `args.bypassLimits` defined + consumed in 3 places + ZERO production
  caller sets it true. Companion to W141 nimrod mempoolminfee 2×,
  W144 BUG-3 carry-forward.
- **Dead-data plumbing 4th nimrod instance** (BUG-22) —
  `clientMaxFeeRateSatKvB` defined + consumed + ZERO production caller
  sets it. Cross-cite W141 nimrod dead-data findings.
- **Reject-string wire-parity slippage 11-token sweep** (BUG-12) —
  fleet companion to lunarblock W145 9-token sweep, camlcoin W143
  multi-token sweep.
- **Operator-knob absence pattern** (BUG-2, BUG-13, BUG-18) — at
  least 3 missing CLI flags: `-acceptnonstdtxn`, `-minrelaytxfee`,
  `-maxorphantxs`. Cross-cite W149 BUG-13 (`-assumevalid` absent),
  W149 BUG-5 (`-prune=N` semantics).
- **Comment-as-confession 5th-6th nimrod instances** (BUG-11 ephemeral
  dust 0-value docstring; BUG-2 "nimrod always runs in
  require_standard=true equivalent").
- **CVE-2018-17144 detection bypass via pipeline-2** (BUG-8) —
  cross-cite haskoin W145 BUG-3 "CVE-2018-17144 cache-mutation gap";
  same root-cause shape (the canonical detector is in `checkTransaction`,
  and a non-canonical path skips it).
- **Defense-in-depth coinbase int64 wrap class** (BUG-6) — cross-cite
  W145 BUG-5 nimrod coinbase int64 wrap.

**Top three findings:**

1. **BUG-8 (P0-CDIV — acceptPackage parallel pipeline bypasses
   STANDARD_SCRIPT_VERIFY_FLAGS and most of PreChecks)** —
   `submitpackage` / `testmempoolaccept` multi-tx route through a
   path that skips `checkTransaction` (CVE-2018-17144 detector),
   `isStandardTx`, MIN_STANDARD_TX_NONWITNESS_SIZE, BIP-141 wtxid
   gate, IsFinalTx, BIP-68 seqlock, sigops cost, ALL 13 STANDARD
   policy flags, ALL 5 RBF rules, ConsensusScriptChecks
   belt-and-suspenders pass, EntriesAndTxidsDisjoint, and
   checkPackageLimits. 19 of the 21 single-tx gates are absent
   in the package path. Cross-cite first nimrod-mempool 2-pipeline
   guard extension.
2. **BUG-7 (P0-CDIV — bypassLimits plumbed-gate-then-don't-flip;
   reorg-replay drops valid txs)** — `AtmpArgs.bypassLimits` field
   defined + consumed in 3 places + ZERO production caller ever sets
   it to true. `mempool.blockDisconnected` (reorg-replay path) uses
   defaultAtmpArgs → bypassLimits=false → rejects txs whose feerate
   < current rolling floor. User-confirmed-then-evicted class.
   4th distinct nimrod plumb-gate-then-don't-flip finding.
3. **BUG-4 (P0-CDIV — default `fullRbf=false`; nimrod requires BIP-125
   opt-in even though Core 28+ removed the knob)** — relay-divergence
   with Core 28+ peers; nimrod refuses to forward txs that Core mines;
   no operator escape-hatch (cross-cite BUG-2 family of missing CLI
   flags). Bandwidth-DoS via perpetual re-request loop.

**Operational implication:** the W150 finding-set adds 5 P0-CDIV to
nimrod's open backlog. Two of them (BUG-8 acceptPackage, BUG-7
bypassLimits) are independently reachable in production today.
BUG-10 (is_p2sh) is a re-confirm of W144's unfixed P0-CDIV.
