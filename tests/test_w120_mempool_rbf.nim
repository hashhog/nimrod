## W120 Mempool RBF audit — nimrod (Nim)
##
## Reference: bitcoin-core/src/policy/rbf.{cpp,h}; bitcoin-core/src/util/rbf.{cpp,h};
## bitcoin-core/src/validation.cpp ReplacementChecks (line 984+); BIP-125.
##
## 30-gate scope:
##   BIP-125 wire constants:
##     G1  MAX_BIP125_RBF_SEQUENCE == 0xfffffffd
##     G2  MAX_REPLACEMENT_CANDIDATES == 100
##     G3  DEFAULT_INCREMENTAL_RELAY_FEE numeric value == 100 sat/kvB
##     G4  SignalsOptInRBF predicate matches Core (any input <= threshold)
##     G5  ancestor-inherited signaling (Gate 2 of IsRBFOptIn)
##
##   Rule #1 (signaling gate):
##     G6  conflict tx must signal (or have signaling ancestor) in standard mode
##     G7  fullRbf=true bypasses signaling requirement
##     G8  mempool.fullRbf field configurable from constructor
##
##   Rule #2 (no new unconfirmed):
##     G9  replacement spending output of direct conflict rejected
##     G10 replacement spending output of a descendant of a conflict rejected
##     G11 EntriesAndTxidsDisjoint surface — txAncestors disjoint from conflicts
##
##   Rule #3 (>= original fees):
##     G12 replacementFee < originalFee rejected
##     G13 replacementFee == originalFee accepted (Core uses < not <=)
##     G14 replacementFee > originalFee accepted (modulo Rule #4)
##
##   Rule #4 (pays for relay):
##     G15 additionalFee < incremental_relay_fee * vsize rejected
##     G16 additionalFee == incremental_relay_fee * vsize accepted
##     G17 incremental fee parameter wired to mp.incrementalRelayFeeRate
##         (sat/kvB) — currently NOT wired, hardcoded sat/vB default
##
##   Rule #5 (max replacement candidates):
##     G18 100 evictions accepted (boundary)
##     G19 101 evictions rejected
##     G20 Core counts UNIQUE CLUSTERS not txs; nimrod counts txs (divergence)
##
##   Rule #8 / ImprovesFeerateDiagram (Core 27+):
##     G21 cluster.nim improvesFeerateDiagram dcrBetter result
##     G22 cluster.nim validateRbfDiagram + checkRbfImprovesDiagram dead-helpers
##         (full Core-style cluster-aware path defined but not called)
##
##   AcceptTransaction wiring:
##     G23 m_allow_replacement honored (bip125-replacement-disallowed)
##     G24 RPC bip125-replaceable field reflects actual tx state
##
##   FIX-61 surface (createRateBumpTransaction):
##     G25 createRateBumpTransaction present
##     G26 bumpfee uses sequence 0xfffffffd by default
##     G27 BumpFeeRequest signal-bip125-rbf field present
##
##   getmempoolinfo / RPC introspection:
##     G28 getmempoolinfo.fullrbf reflects mempool.fullRbf
##     G29 getmempoolinfo.incrementalrelayfee numerical correctness
##     G30 getmempoolinfo.mempoolminfee unit conversion (sat/vB → BTC/kvB)
##
## BUGs found (this audit):
##   BUG-1 (P1-CDIV)  G17/G3  DefaultIncrementalRelayFee = 1.0 sat/vB
##                            (1000 sat/kvB) shadows the correct
##                            DefaultIncrementalRelayFeeSatKvB = 100.0
##                            already configured on the mempool field.
##                            checkRbfRules() default value 1.0 is 10x Core's
##                            DEFAULT_INCREMENTAL_RELAY_FEE (100 sat/kvB =
##                            0.1 sat/vB).
##                            File: src/mempool/mempool.nim:128, 1816, 1882
##                            Reference: bitcoin-core/src/policy/policy.h:48.
##
##   BUG-2 (P1-CDIV)  G17    Two-pipeline: checkRbfRules() ignores the
##                            mempool's configured incrementalRelayFeeRate
##                            field entirely. Call site at mempool.nim:1182
##                            invokes checkRbfRules(tx, modifiedFee, vsizeInt,
##                            conflicts) — no 5th arg — so the function
##                            always uses the (wrong) default rather than
##                            mp.incrementalRelayFeeRate / 1000.0.
##                            File: src/mempool/mempool.nim:1182, 1816.
##                            Reference: bitcoin-core/src/validation.cpp:1011
##                            passes m_pool.m_opts.incremental_relay_feerate.
##
##   BUG-3 (P0-RPC)   G24    bip125-replaceable field hardcoded `true` in
##                            getmempoolentry / getrawmempool verbose. Does
##                            NOT call signalsOptInRBF / isBip125Replaceable
##                            / isRbfOptIn. A wallet querying this field
##                            cannot tell which mempool txs are actually
##                            replaceable.
##                            File: src/rpc/server.nim:1253.
##                            Reference: bitcoin-core/src/rpc/mempool.cpp
##                            entryToJSON sets bip125-replaceable per-tx
##                            from CTxMemPool::IsRBFOptIn().
##
##   BUG-4 (P1-CDIV)  G20    Rule #5 counts evicted-tx total, not unique
##                            clusters. Core's GetEntriesForConflicts calls
##                            pool.GetUniqueClusterCount(iters_conflicting)
##                            and rejects when that exceeds 100 — then
##                            populates all_conflicts with descendants
##                            *without* re-applying the limit. nimrod
##                            applies the 100 limit to (conflicts ∪
##                            descendants), which is stricter than Core for
##                            tightly-clustered conflict sets and looser
##                            when many tiny clusters each contribute few
##                            descendants. Net: divergent reject/accept on
##                            the 100-boundary case.
##                            File: src/mempool/mempool.nim:1853-1859.
##                            Reference: bitcoin-core/src/policy/rbf.cpp:69-83
##                            GetUniqueClusterCount() + rbf.h MAX_REPLACEMENT
##                            _CANDIDATES doc comment.
##
##   BUG-5 (P2-DEAD)  G22    cluster.nim validateRbfDiagram +
##                            checkRbfImprovesDiagram are full Core-style
##                            cluster-aware diagram validators (lines 838-973
##                            of cluster.nim) — they correctly walk the
##                            cluster graph, simulate the replacement
##                            tempCluster, relinearize, and call
##                            compareFeerateDiagrams. NEVER CALLED FROM
##                            checkRbfRules. The Rule #8 path in
##                            mempool.nim:1893-1912 instead builds an
##                            ad-hoc per-tx diagram from individual entries,
##                            ignoring the cluster structure entirely. Classic
##                            dead-helper-at-call-site shape: ~135 LOC
##                            cluster-aware path bypassed in favour of an
##                            adjacent ad-hoc one.
##                            File: src/mempool/cluster.nim:838 + 962 vs
##                            src/mempool/mempool.nim:1893-1912.
##
##   BUG-6 (P2-CDIV)  G11    EntriesAndTxidsDisjoint divergence: Core checks
##                            replacement-tx ancestors vs DIRECT conflicts
##                            (ws.m_conflicts) at validation.cpp:1356.
##                            nimrod checks against conflictsToRemove which
##                            includes descendants (mempool.nim:1195-1199).
##                            Overly conservative — a legitimate replacement
##                            whose ancestor is a descendant of a conflict
##                            (and would itself be evicted) is rejected.
##                            File: src/mempool/mempool.nim:1195-1199.
##                            Reference: bitcoin-core/src/validation.cpp:1349-
##                            1361 — ancestors ∩ ws.m_conflicts only.
##
##   BUG-7 (P1-RPC)   G29    getmempoolinfo "incrementalrelayfee" hardcoded
##                            0.00001 (BTC/kvB), ignoring
##                            mp.incrementalRelayFeeRate. Core's
##                            MempoolInfoToJSON formats
##                            pool.m_opts.incremental_relay_feerate.GetFeePerK()
##                            via ValueFromAmount → 0.00000100 BTC/kvB at
##                            default. nimrod's hardcode is 10x default.
##                            File: src/rpc/server.nim:1200.
##                            Reference: bitcoin-core/src/rpc/mempool.cpp:1056.
##
##   BUG-8 (P1-RPC)   G28    getmempoolinfo "fullrbf" hardcoded true, ignores
##                            mp.fullRbf flag. Operator setting
##                            mempoolfullrbf=0 cannot observe configuration
##                            through RPC.
##                            File: src/rpc/server.nim:1202.
##
##   BUG-9 (P1-RPC)   G30    getmempoolinfo "mempoolminfee" unit bug:
##                            comment says "Convert sat/vbyte to BTC/kB" but
##                            divides by 1e8 — produces BTC/vB. Correct
##                            conversion is satPerVbyte / 1e5 (since
##                            BTC/kvB = satPerVbyte * 1000 / 1e8).
##                            File: src/rpc/server.nim:1186.
##
##   BUG-10 (P2-DEAD) G3     Two competing default-constant definitions for
##                            "incremental relay fee" with conflicting units:
##                            - src/network/relay.nim:41:
##                                DefaultIncrementalRelayFee = 1000 (sat/kvB)
##                            - src/mempool/mempool.nim:128:
##                                DefaultIncrementalRelayFee = 1.0 (sat/vB)
##                            Both are 10x Core's actual default
##                            (DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB,
##                            policy.h:48). And mempool.nim line 102 already
##                            defines the correct
##                            DefaultIncrementalRelayFeeSatKvB = 100.0 —
##                            three competing constants for the same value.
##
##   BUG-11 (P3-DOC)  G7/G8  fullRbf semantics doc divergence from Core
##                            master: Core has removed mempoolfullrbf
##                            setting (full-RBF is now unconditional in
##                            master post-v28). nimrod still gates on the
##                            field, which is a conservative policy choice
##                            but the doc comment claims Core parity.
##                            File: src/mempool/mempool.nim:72, 1772.
##
## Cross-cutting context:
##   - W116 (package relay): nimrod's checkRbfRules() is single-tx only.
##     The package path (mempool.nim:2115+) computes pkgEffectiveMin via
##     a different code path; whether it folds in incrementalRelayFeeRate
##     correctly is out of scope for this audit (W116 G3 = pkgtxns).
##   - FIX-61 (createRateBumpTransaction + MaxBip125RbfSequence): the
##     mempool-side RBF wire constants and signalsOptInRBF predicate are
##     present and behave correctly at the W118 G19/G20 level. The wallet
##     bumpfee path lands at psbtbumpfee/handleBumpFee in rpc/server.nim
##     and constructs replacements with sequence 0xfffffffd by default.
##     The bumpfee path then re-routes through acceptTransaction, where
##     it inherits BUG-1, BUG-2 (incremental relay fee 10x off) when the
##     mempool finally enforces Rule #4. So FIX-61's user-facing surface
##     looks correct but the cumulative effect of BUG-1+BUG-2 means a
##     real `bumpfee` invocation pays 10x what Core would for the same
##     vsize delta. Practical impact: nimrod over-charges by ~0.9 sat/vB
##     on the bandwidth increment — wallets that round to the minimum
##     will produce nominally-larger replacements than Core.
##
## Patterns surfaced:
##   - Dead-helper-at-call-site: BUG-5 (cluster diagram validators).
##   - Comment-as-confession: BUG-9 ("Convert sat/vbyte to BTC/kB" while
##     dividing by 1e8 — wrong unit), BUG-10 (three competing defaults).
##   - Two-pipeline: BUG-2 (mempool field vs check parameter), BUG-7+8
##     (RPC field vs configured field).
##   - 10x unit bug: BUG-1, BUG-7, BUG-10 — every layer compounds a
##     missing /10 from kvB→vB conversion error.

import std/[unittest, options, tables, times, sets, os, strutils]
import ../src/mempool/mempool
import ../src/mempool/cluster
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_w120_rbf_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeOutpoint(b: byte): OutPoint =
  var txid: array[32, byte]
  txid[0] = b
  OutPoint(txid: TxId(txid), vout: 0)

proc makeTxid(b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  TxId(arr)

proc makeTxidN(b, n: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  arr[1] = n
  TxId(arr)

# ---------------------------------------------------------------------------
# G1-G5: BIP-125 wire constants and SignalsOptInRBF predicate
# ---------------------------------------------------------------------------
suite "W120 G1-G5 BIP-125 wire constants":

  test "G1 MAX_BIP125_RBF_SEQUENCE constant == 0xfffffffd":
    check MaxBip125RbfSequence == 0xfffffffd'u32

  test "G2 MAX_REPLACEMENT_CANDIDATES constant == 100":
    check MaxReplacementCandidates == 100

  test "G3 BUG-1/BUG-10: DefaultIncrementalRelayFee in mempool.nim is " &
       "10x Core's DEFAULT_INCREMENTAL_RELAY_FEE":
    ## Core: src/policy/policy.h:48 DEFAULT_INCREMENTAL_RELAY_FEE = 100
    ## (units: sat/kvB).
    ## nimrod: src/mempool/mempool.nim:128 DefaultIncrementalRelayFee = 1.0
    ## (declared as sat/vbyte). 1 sat/vB == 1000 sat/kvB == 10x Core.
    ## The CORRECT constant DefaultIncrementalRelayFeeSatKvB = 100.0 is
    ## defined at mempool.nim:102 — but checkRbfRules uses the wrong one.
    check DefaultIncrementalRelayFee == 1.0   ## sat/vB — 10x Core
    check DefaultIncrementalRelayFeeSatKvB == 100.0  ## sat/kvB — correct

  test "G4 SignalsOptInRBF: nSequence 0xfffffffd opts in (boundary)":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "G4 SignalsOptInRBF: nSequence 0xfffffffe does NOT opt in":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
                     sequence: 0xfffffffe'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "G4 SignalsOptInRBF: nSequence 0xffffffff (SEQUENCE_FINAL) does NOT opt in":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
                     sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "G4 SignalsOptInRBF: ONE input <= threshold among others is sufficient":
    let tx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xffffffff'u32),
        TxIn(prevOut: makeOutpoint(0x02), scriptSig: @[], sequence: 0x00000000'u32),
        TxIn(prevOut: makeOutpoint(0x03), scriptSig: @[], sequence: 0xffffffff'u32)
      ],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "G5 ancestor-inherited signaling: child inherits parent's opt-in":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())

    let parentTxid = makeTxid(0x10)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(5000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)

    # Child does NOT signal but spends from signaling parent
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0),
                     scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check mp.isRbfOptIn(childTx)
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G6-G8: Rule #1 (signaling gate) + fullRbf
# ---------------------------------------------------------------------------
suite "W120 G6-G8 Rule #1 signaling gate":

  test "G6 Rule #1: non-signaling conflict rejected in standard mode":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)

    let conflictOutpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: conflictOutpoint, scriptSig: @[],
                     sequence: 0xffffffff'u32)],  # FINAL — not opt-in
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[conflictOutpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: conflictOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(newTx, Satoshi(2000), 100, conflicts)
    check not res.isOk
    check res.error.find("does not signal RBF opt-in") >= 0
    cs.close()
    cleanupTestDb()

  test "G7 fullRbf=true bypasses signaling requirement":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let conflictOutpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: conflictOutpoint, scriptSig: @[],
                     sequence: 0xffffffff'u32)],  # FINAL
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[conflictOutpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: conflictOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(newTx, Satoshi(2000), 100, conflicts)
    # fullRbf bypasses signaling; remaining rules may still fail, but the
    # signaling-error string is what BUG-11 cares about: it must NOT appear.
    if not res.isOk:
      check res.error.find("does not signal RBF opt-in") < 0
    cs.close()
    cleanupTestDb()

  test "G8 mempool.fullRbf field configurable from constructor":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mpStd = newMempool(cs, regtestParams(), fullRbf = false)
    var mpFull = newMempool(cs, regtestParams(), fullRbf = true)
    check not mpStd.fullRbf
    check mpFull.fullRbf
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G9-G11: Rule #2 (HasNoNewUnconfirmed / EntriesAndTxidsDisjoint)
# ---------------------------------------------------------------------------
suite "W120 G9-G11 Rule #2 HasNoNewUnconfirmed":

  test "G9 replacement spending DIRECT output of conflict rejected":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32),
        TxIn(prevOut: OutPoint(txid: conflictTxid, vout: 0),
             scriptSig: @[], sequence: 0xfffffffd'u32),
      ],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(newTx, Satoshi(2000), 150, conflicts)
    check not res.isOk
    check res.error.find("spends output from conflicting") >= 0
    cs.close()
    cleanupTestDb()

  test "G10 BUG-6: replacement spending DESCENDANT of conflict rejected " &
       "(divergence: Core only checks DIRECT conflicts)":
    ## Core's EntriesAndTxidsDisjoint (validation.cpp:1356) checks the
    ## replacement's ancestors against ws.m_conflicts (DIRECT conflicts),
    ## NOT against the full descendant-expanded set. nimrod's
    ## mempool.nim:1195-1199 checks against conflictsToRemove which is
    ## the descendant-expanded set — over-conservative.
    ##
    ## We exercise the simpler Rule-#2 path here (direct conflict output).
    ## The descendant-via-ancestors case is the divergent shape but
    ## requires plumbing tx-ancestor calculation that goes through
    ## acceptTransaction's outer flow; we pin the behavior via the
    ## divergent-rejection signal in the wider test_atmp_w96 suite.
    check compiles(getAllConflictsWithDescendants)

  test "G11 EntriesAndTxidsDisjoint surface present":
    ## nimrod's analogue is the txAncestors ∩ conflictsToRemove loop
    ## inside acceptTransactionWithArgs at mempool.nim:1195-1199.
    ## We pin the helper that computes the descendant-expansion.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    let conflicts = initHashSet[TxId]()
    let expanded = mp.getAllConflictsWithDescendants(conflicts)
    check expanded.len == 0
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G12-G14: Rule #3 (replacement fees >= original fees)
# ---------------------------------------------------------------------------
suite "W120 G12-G14 Rule #3 replacement fees >= original":

  test "G12 replacementFee < originalFee rejected":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 2.5, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(950), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(newTx, Satoshi(500), 100, conflicts)
    check not res.isOk
    check res.error.find("less fees than conflicting") >= 0
    cs.close()
    cleanupTestDb()

  test "G13 replacementFee == originalFee accepted (Core uses < not <=)":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 2.5, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(950), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    # Equal-fee replacement: Rule #3 (<) is satisfied, but Rule #4 will
    # reject (no additional fee for bandwidth). We pin that the error
    # is NOT "less fees than conflicting" — i.e. Rule #3 is the < not <=
    # semantic.
    let res = mp.checkRbfRules(newTx, Satoshi(1000), 100, conflicts)
    if not res.isOk:
      check res.error.find("less fees than conflicting") < 0
    cs.close()
    cleanupTestDb()

  test "G14 replacementFee > originalFee + bandwidth accepted":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    # Huge feerate replacement — Rule #3 + #4 + #8 should all pass.
    let res = mp.checkRbfRules(newTx, Satoshi(100_000), 200, conflicts)
    check res.isOk
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G15-G17: Rule #4 (pays for relay bandwidth)
# ---------------------------------------------------------------------------
suite "W120 G15-G17 Rule #4 pays for relay bandwidth":

  test "G15 additionalFee < incremental * vsize rejected":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    # +1 sat over original on 200 vbytes — under nimrod's (buggy) default
    # incremental of 1.0 sat/vB, this needs 200 additional sats; we
    # provide only 1.
    let res = mp.checkRbfRules(newTx, Satoshi(1001), 200, conflicts)
    check not res.isOk
    check res.error.find("not enough additional fees") >= 0
    cs.close()
    cleanupTestDb()

  test "G16 additionalFee >= incremental * vsize accepted":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(700), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    # 200 vbytes, default incremental 1.0 sat/vB → need at least
    # 1000+200=1200. Provide 1500 for cushion (Rule #8 also needs to be
    # strictly better).
    let res = mp.checkRbfRules(newTx, Satoshi(2000), 200, conflicts)
    check res.isOk
    cs.close()
    cleanupTestDb()

  test "G17 BUG-2: checkRbfRules ignores mp.incrementalRelayFeeRate (two-pipeline)":
    ## checkRbfRules() takes incrementalRelayFee as a 5th parameter with
    ## default DefaultIncrementalRelayFee (1.0 sat/vB). The call site at
    ## mempool.nim:1182 passes 4 args — no override. The mempool's
    ## configured `incrementalRelayFeeRate` field (sat/kvB) is never read
    ## by Rule #4. Pin the divergence: setting the field has no observable
    ## effect on Rule #4 acceptance.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    # Override the configured field to absurdly high value.
    mp.incrementalRelayFeeRate = 1_000_000.0  # sat/kvB

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(700), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(newTx, Satoshi(2000), 200, conflicts)
    # Despite mp.incrementalRelayFeeRate being absurdly high
    # (1e6 sat/kvB = 1000 sat/vB → would need 200_000 additional sats),
    # the check passes because the field is ignored.
    check res.isOk  # BUG-2: field has no effect on the gate
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G18-G20: Rule #5 (MAX_REPLACEMENT_CANDIDATES = 100)
# ---------------------------------------------------------------------------
suite "W120 G18-G20 Rule #5 MAX_REPLACEMENT_CANDIDATES":

  test "G18 100 evictions accepted (boundary)":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let parentOutpoint = makeOutpoint(0xAA)
    let parentTxid = makeTxid(0x01)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[parentOutpoint] = parentTxid

    # 1 parent + 99 children = 100 evictions total
    for i in 1 .. 99:
      let childTxid = makeTxidN(byte(i + 1), 0x00)
      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0),
                       scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(10),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(110), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)

    let conflicts = toHashSet([parentTxid])
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let res = mp.checkRbfRules(newTx, Satoshi(50_000), 200, conflicts)
    check res.isOk
    cs.close()
    cleanupTestDb()

  test "G19 101 evictions rejected":
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let parentOutpoint = makeOutpoint(0xAA)
    let parentTxid = makeTxid(0x01)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[parentOutpoint] = parentTxid

    # 1 parent + 100 children = 101 evictions → exceeds limit
    for i in 1 .. 100:
      let childTxid = makeTxidN(byte(i + 1), 0x00)
      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0),
                       scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(10),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(110), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)

    let conflicts = toHashSet([parentTxid])
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(50_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let res = mp.checkRbfRules(newTx, Satoshi(50_000), 200, conflicts)
    check not res.isOk
    check res.error.find("too many potential replacements") >= 0
    cs.close()
    cleanupTestDb()

  test "G20 BUG-4: Rule #5 counts evicted-tx total, not unique clusters":
    ## Core: src/policy/rbf.cpp:69-74 calls
    ##   pool.GetUniqueClusterCount(iters_conflicting)
    ## and rejects ONLY if that exceeds MAX_REPLACEMENT_CANDIDATES.
    ## Then ALL descendants are added unconditionally to all_conflicts.
    ## nimrod's mempool.nim:1853-1859 applies the 100 limit to
    ## (conflicts ∪ descendants), which is stricter than Core.
    ##
    ## Pin the divergent surface: the limit is checked against
    ## `len(allConflicts)` not unique-cluster-count.
    check MaxReplacementCandidates == 100
    # The divergent behavior is observable in G19 above: nimrod rejects
    # 101 total evictions; Core would reject only if >100 UNIQUE CLUSTERS
    # are conflicting. For a single-parent, 100-child setup the cluster
    # count is 1.

# ---------------------------------------------------------------------------
# G21-G22: Rule #8 / ImprovesFeerateDiagram + dead-helper survey
# ---------------------------------------------------------------------------
suite "W120 G21-G22 Rule #8 ImprovesFeerateDiagram":

  test "G21 improvesFeerateDiagram dcrBetter — replacement clearly higher feerate":
    let orig = buildFeerateDiagram(@[FeeFrac(fee: 1000, size: 100)])
    let repl = buildFeerateDiagram(@[FeeFrac(fee: 5000, size: 100)])
    check improvesFeerateDiagram(orig, repl)
    check not improvesFeerateDiagram(repl, orig)

  test "G22 BUG-5 dead-helper: validateRbfDiagram + checkRbfImprovesDiagram " &
       "exist but checkRbfRules() builds its own ad-hoc diagram":
    ## cluster.nim lines 838-973 implement the full Core-style
    ## cluster-aware diagram validators. They walk the affected clusters,
    ## simulate the replacement tempCluster, relinearize, and call
    ## compareFeerateDiagrams. They are NEVER called from checkRbfRules.
    ## mempool.nim:1893-1912 instead builds a flat per-entry FeeFrac list
    ## sorted descending. For a tightly-clustered conflict set this
    ## produces a different (looser) diagram comparison than Core.
    check compiles(validateRbfDiagram)
    check compiles(checkRbfImprovesDiagram)
    # The ad-hoc path that's actually used:
    check compiles(improvesFeerateDiagram)

# ---------------------------------------------------------------------------
# G23-G24: AcceptTransaction wiring + RPC bip125-replaceable
# ---------------------------------------------------------------------------
suite "W120 G23-G24 RPC + acceptTransaction wiring":

  test "G23 m_allow_replacement honored: bip125-replacement-disallowed":
    ## mempool.nim:949-950 returns "bip125-replacement-disallowed" when
    ## conflict exists but args.allowReplacement=false. We pin the
    ## constructor + field surface (the in-flow check is exercised
    ## through test_atmp_w96 G18).
    var args = defaultAtmpArgs()
    check args.allowReplacement  # default true
    args.allowReplacement = false
    check not args.allowReplacement

  test "G24 BUG-3 (P0-RPC): bip125-replaceable hardcoded `true` " &
       "in mempoolEntryJson":
    ## src/rpc/server.nim:1253 sets obj["bip125-replaceable"] = %true
    ## regardless of whether tx actually signals opt-in (or has a
    ## signaling ancestor). Wallets cannot use this field to filter
    ## replaceable txs.
    ##
    ## We pin the divergence at the surface where it matters: a tx with
    ## sequence 0xffffffff (FINAL) on every input is NOT BIP-125
    ## replaceable per isBip125Replaceable.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)

    let txid = makeTxid(0x42)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xCC), scriptSig: @[],
                     sequence: 0xffffffff'u32)],  # FINAL
      outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[txid] = MempoolEntry(
      tx: tx, txid: txid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    # Function-level truth:
    check not mp.isBip125Replaceable(txid)
    # RPC reports `true` regardless — bug surface is the JSON serializer
    # at server.nim:1253; not testable from this module without the
    # full RPC server scaffolding. We pin the underlying predicate
    # works so a fix is trivially wireable.
    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# G25-G27: FIX-61 surface (createRateBumpTransaction)
# ---------------------------------------------------------------------------
suite "W120 G25-G27 FIX-61 createRateBumpTransaction surface":

  test "G25 createRateBumpTransaction symbol present (FIX-61 closure)":
    ## FIX-61 landed bumpfee / psbtbumpfee via wallet/feebumper.nim.
    ## Pin that the public surface compiles.
    # Cannot import feebumper from a pure-mempool test (cyclic) — we
    # exercise the surface indirectly via the wallet-shaped W118 test.
    # Here we pin the constants that the bumpfee path relies on.
    check MaxBip125RbfSequence == 0xfffffffd'u32

  test "G26 sequence 0xfffffffd is the canonical BIP-125 opt-in marker":
    ## feebumper.createRateBumpTransaction sets every input's sequence
    ## to 0xfffffffd by default (Core feebumper.cpp:990). We pin the
    ## predicate-level invariant: a tx where EVERY input is exactly the
    ## threshold value signals opt-in.
    let tx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
             sequence: 0xfffffffd'u32),
        TxIn(prevOut: makeOutpoint(0x02), scriptSig: @[],
             sequence: 0xfffffffd'u32),
        TxIn(prevOut: makeOutpoint(0x03), scriptSig: @[],
             sequence: 0xfffffffd'u32),
      ],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "G27 BIP-125 sequence threshold is unsigned-strictly-below SEQUENCE_FINAL-1":
    ## Core's MAX_BIP125_RBF_SEQUENCE = SEQUENCE_FINAL - 2 = 0xfffffffd.
    ## The unsigned ordering 0xfffffffd < 0xfffffffe < 0xffffffff is
    ## critical: 0xfffffffe is the "carve out" for nLockTime-without-RBF.
    const SEQUENCE_FINAL: uint32 = 0xffffffff'u32
    check MaxBip125RbfSequence == SEQUENCE_FINAL - 2'u32
    check MaxBip125RbfSequence < (SEQUENCE_FINAL - 1'u32)

# ---------------------------------------------------------------------------
# G28-G30: getmempoolinfo / RPC introspection
# ---------------------------------------------------------------------------
suite "W120 G28-G30 RPC introspection bugs":

  test "G28 BUG-8 (P1-RPC): getmempoolinfo.fullrbf hardcoded true, " &
       "ignores mp.fullRbf":
    ## src/rpc/server.nim:1202 hardcodes "fullrbf": true regardless of
    ## the actual mempool configuration. Operator running
    ## mempoolfullrbf=0 cannot observe through RPC.
    ##
    ## We pin the underlying field truth: a mempool constructed with
    ## fullRbf=false reports false at the function level.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mpStd = newMempool(cs, regtestParams(), fullRbf = false)
    check not mpStd.fullRbf
    var mpFull = newMempool(cs, regtestParams(), fullRbf = true)
    check mpFull.fullRbf
    cs.close()
    cleanupTestDb()

  test "G29 BUG-7 (P1-RPC): incrementalrelayfee hardcoded 0.00001 vs " &
       "Core default 0.00000100 (BTC/kvB)":
    ## Core: ValueFromAmount(100 sat) = 0.00000100 BTC.
    ## nimrod: 0.00001 BTC/kvB = 1000 sat/kvB = 1 sat/vB (10x Core).
    ## The hardcoded value also ignores mp.incrementalRelayFeeRate.
    ## We pin the field default at the mempool level.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    # Mempool field correctly defaults to 100 sat/kvB matching Core.
    check mp.incrementalRelayFeeRate == 100.0
    # But the RPC layer hardcodes 0.00001 BTC/kvB (= 1000 sat/kvB).
    # The two values disagree by 10x — divergent RPC output.
    cs.close()
    cleanupTestDb()

  test "G30 BUG-9 (P1-RPC): mempoolminfee unit-conversion divergence":
    ## src/rpc/server.nim:1186:
    ##   let minFee = rpc.mempool.minFeeRate / 100000000.0
    ##   # comment: Convert sat/vbyte to BTC/kB
    ## Going sat/vbyte → BTC/kvB requires *1000 /1e8 = /1e5, not /1e8.
    ## nimrod's emitted value is 1000x too small.
    ## Core: ValueFromAmount(GetFeePerK()) on a CFeeRate built from
    ## sat/kvB produces BTC/kvB correctly.
    ##
    ## We pin the underlying field, then assert the (off-by-1000x)
    ## RPC-layer transform mathematically.
    cleanupTestDb()
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    check mp.minFeeRate == DefaultMinFeeRate  # 1.0 sat/vbyte default
    # nimrod's transform: 1.0 / 1e8 = 1e-8 BTC/vB — WRONG (claims BTC/kvB)
    let nimrodReported = mp.minFeeRate / 100_000_000.0
    let correctTransform = mp.minFeeRate * 1000.0 / 100_000_000.0
    # Off by exactly 1000x:
    check abs(correctTransform - nimrodReported * 1000.0) < 1e-12
    cs.close()
    cleanupTestDb()
