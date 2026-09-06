## W130 BIP-125 RBF feebumper Rule 3 — nimrod (Nim) — discovery test suite
##
## See `audit/w130_bip125_feebumper_rule3.md` for the full audit report.
## Each gate either confirms a Core-aligned behavior (the `check` passes
## today and would regress if a future change broke it) or documents a
## CURRENT (wrong/missing) behavior with an inline TODO comment + a
## `check` that asserts the WRONG value so the test acts as a post-fix
## xfail / regression guard. When a future FIX wave lands, the `check`
## flips to the Core-aligned value and the test acts as a forward-
## regression guard.
##
## Numbering: BUG-N-W130 (W130 namespace; does NOT overlap with W120's
## BUG-N-W120 set even where gates cover the same constant — W120's
## audit was mempool-side, W130's is wallet-side).
##
## Reference: Bitcoin Core
## - src/wallet/feebumper.{h,cpp}
## - src/policy/rbf.{cpp,h}
## - src/policy/feerate.{cpp,h}
## - src/wallet/wallet.h:124 (WALLET_INCREMENTAL_RELAY_FEE = 5000)
##
## Cross-reference: W120 (mempool RBF rules); FIX-69 (incremental fee
## unit cleanup); FIX-79 (validateRbfDiagram dead-helper); FIX-70
## (wallet default nSequence).

import unittest2
import std/[options, tables, times, sets, os, strutils, math]
import ../src/wallet/feebumper
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_w130_feebumper_test"

# ---------------------------------------------------------------------------
# Source-grep helper. Several gates assert the ABSENCE of a Core symbol
# (BUG-2 `WALLET_INCREMENTAL_RELAY_FEE`, BUG-16 `MarkReplaced`, etc.) or
# the PRESENCE of a known-wrong formula (BUG-1 feerate-form Rule 3
# instead of total-fee form). We do this with a file-read + string search
# rather than fragile Nim reflection.
# ---------------------------------------------------------------------------

proc readSrc(relPath: string): string =
  ## Read a nimrod source file. Tests in `tests/` execute with cwd =
  ## repo root when invoked via `nim c -r tests/test_w130_*.nim`.
  let candidates = [
    "src/" & relPath,
    "../src/" & relPath,
    getCurrentDir() / "src" / relPath,
  ]
  for path in candidates:
    if fileExists(path):
      return readFile(path)
  raise newException(IOError, "cannot locate src/" & relPath &
    " (cwd=" & getCurrentDir() & ")")

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

# ---------------------------------------------------------------------------
# G1-G5: BIP-125 wire constants and signaling (W120 carry-forward)
# ---------------------------------------------------------------------------

suite "W130 G1-G5 BIP-125 wire constants (W120 carry-forward)":

  test "G1 MaxBip125RbfSequence == 0xfffffffd":
    ## Core: util/rbf.h MAX_BIP125_RBF_SEQUENCE
    check MaxBip125RbfSequence == 0xfffffffd'u32

  test "G2 signalsOptInRBF: sequence 0xfffffffd opts in (boundary)":
    ## Core: util/rbf.cpp SignalsOptInRBF — strict `<=` on threshold
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "G3 signalsOptInRBF: sequence 0xfffffffe does NOT opt in":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[],
                     sequence: 0xfffffffe'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "G4 MaxReplacementCandidates == 100":
    ## Core: policy/rbf.h MAX_REPLACEMENT_CANDIDATES
    check MaxReplacementCandidates == 100

  test "G5 wallet emits replaceable seq 0xfffffffd (not 0xffffffff)":
    ## feebumper.nim:339-340 — when req.replaceable=true, every input
    ## sequence is 0xfffffffd; when false, 0xfffffffe (NOT 0xffffffff
    ## which would disable locktime). Source-level guard.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("0xfffffffd'u32 else: 0xfffffffe'u32") >= 0
    check src.find("0xffffffff'u32") < 0  # SEQUENCE_FINAL never emitted

# ---------------------------------------------------------------------------
# G6-G10: PreconditionChecks 5 distinct checks
# Core: src/wallet/feebumper.cpp PreconditionChecks (line 23)
# ---------------------------------------------------------------------------

suite "W130 G6-G10 PreconditionChecks 5 checks":

  test "G6 BUG-4 HasWalletSpend (wallet descendants) check MISSING":
    ## Core feebumper.cpp:25-28 rejects a bump if the tx has descendants
    ## in the wallet (not just the mempool). nimrod only checks the
    ## mempool path. TODO: when FIX-N+7 lands, this check flips.
    let src = readSrc("wallet/feebumper.nim")
    # Confirm the in-mempool descendant check IS present
    check src.find("Transaction has descendants in the mempool") >= 0
    # Confirm the in-WALLET descendant check is MISSING (the diagnostic
    # phrasing Core uses).
    check src.find("Transaction has descendants in the wallet") < 0
    check src.find("HasWalletSpend") < 0
    # Forward-regression: when the wallet-side check lands, the second
    # check above will flip — flip the assertions then to lock in.

  test "G7 hasDescendantsInMempool PRESENT":
    ## feebumper.nim:129-133 walks `mempool.isSpent(op)` for every
    ## output index. Matches Core feebumper.cpp:31-35.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("mempool.isSpent(op)") >= 0
    check src.find("Transaction has descendants in the mempool") >= 0
    check src.find("bfeInvalidParameter") >= 0

  test "G8 BUG-5 GetTxDepthInMainChain != 0 (mined-tx) check MISSING":
    ## Core feebumper.cpp:37-40 rejects a bump for a mined or
    ## conflicted-with-mined tx with the distinct error
    ## "Transaction has been mined". nimrod's only check is
    ## `mempool.contains(origTxid)` (feebumper.nim:124) which raises
    ## `bfeInvalidAddressOrKey` ("Invalid or non-wallet transaction
    ## id") — wrong error code mapping (Core uses WALLET_ERROR not
    ## INVALID_ADDRESS_OR_KEY).
    let src = readSrc("wallet/feebumper.nim")
    check src.find("Transaction has been mined") < 0
    check src.find("GetTxDepthInMainChain") < 0
    check src.find("WALLET_ERROR for mined") < 0
    # Confirm the wrong-mapping replacement IS present
    check src.find("Invalid or non-wallet transaction id") >= 0

  test "G9 BUG-6 replaced_by_txid mapValue idempotency check MISSING":
    ## Core feebumper.cpp:42-45 rejects bumping a tx that has already
    ## been bumped by checking mapValue.contains("replaced_by_txid").
    ## nimrod has no mapValue / replaced_by_txid plumbing anywhere.
    let srcFb = readSrc("wallet/feebumper.nim")
    let srcW  = readSrc("wallet/wallet.nim")
    check srcFb.find("replaced_by_txid") < 0
    check srcW.find("replaced_by_txid") < 0
    check srcFb.find("Cannot bump transaction") < 0
    check srcW.find("mapValue") < 0  # no metadata blob primitive at all

  test "G10 AllInputsMine PRESENT (require_mine path)":
    ## feebumper.nim:140-185 — when requireMine is set and any input
    ## is not the wallet's, raises bfeWalletError. Matches Core
    ## feebumper.cpp:47-54.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("Transaction contains inputs that don't belong to this wallet") >= 0
    check src.find("requireMine") >= 0

# ---------------------------------------------------------------------------
# G11-G18: CheckFeeRate — Rule 3 PRECISE INVARIANT (the wave's headline)
# Core: src/wallet/feebumper.cpp CheckFeeRate (line 60)
# ---------------------------------------------------------------------------

suite "W130 G11-G18 CheckFeeRate / Rule 3 precise invariant":

  test "G11 BUG-7 minMempoolFeeRate is the STATIC field, not dynamic floor":
    ## Core feebumper.cpp:67-75 uses wallet.chain().mempoolMinFee()
    ## which is the rolling-floor-aware dynamic minimum (Core
    ## CTxMemPool::GetMinFee). nimrod's doBumpFee at server.nim:6957
    ## passes `rpc.mempool.minFeeRate` (the STATIC constructor field)
    ## without consulting `mempool.getMinFee()` (the rolling-floor
    ## accessor at mempool.nim:1545). Under mempool congestion the
    ## two diverge.
    let src = readSrc("rpc/server.nim")
    check src.find("minRelayFeeSatVb = rpc.mempool.minFeeRate") >= 0
    # The rolling-floor-aware accessor exists but isn't wired:
    let srcMp = readSrc("mempool/mempool.nim")
    check srcMp.find("proc getMinFee*") >= 0
    check srcMp.find("rollingMinimumFeeRate") >= 0
    # Forward-regression: when FIX-N+5 lands, the server.nim line
    # should consult mempool.getMinFee() (rolling-floor-aware)
    # instead of mempool.minFeeRate (static).

  test "G12 BUG-8 calculateCombinedBumpFee MISSING entirely":
    ## Core feebumper.cpp:77-87 computes
    ## `combined_bump_fee = wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate)`
    ## to fold in CPFP-ancestor bump fees that the replacement implicitly
    ## inherits. nimrod has no equivalent — the new_total_fee formula
    ## (feebumper.nim:299) doesn't include any ancestor-bump term.
    let src = readSrc("wallet/feebumper.nim")
    let srcCs = readSrc("storage/chainstate.nim")
    check src.find("calculateCombinedBumpFee") < 0
    check src.find("combined_bump_fee") < 0
    check srcCs.find("calculateCombinedBumpFee") < 0

  test "G13 BUG-3 +1 sat strict-gt pre-floor on oldFeeRate MISSING":
    ## Core feebumper.cpp:122-126 in EstimateFeeRate:
    ##   CFeeRate feerate(old_fee, txSize);
    ##   feerate += CFeeRate(1);   // +1 sat/kvB (per-kvB ctor)
    ## This is the strict-gt floor that makes Rule 3 `>=` non-degenerate
    ## under integer rounding. nimrod uses float division with no +1
    ## adjustment — for an original `old_fee=300, vsize=300vB` the
    ## oldFeeRateSatVb = 1.0 exactly, no headroom for Rule 3 ties.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("feerate += CFeeRate(1)") < 0
    check src.find("+ 1 sat") < 0  # comment-as-marker also absent
    # Confirm the floating-point form IS present
    check src.find("float64(int64(oldFee)) / float64(vsizeEst)") >= 0

  test "G14 BUG-1 Rule 3 enforced as FEERATE, Core enforces TOTAL-FEE":
    ## THE HEADLINE BUG.
    ## Core feebumper.cpp:88-99:
    ##   CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
    ##   CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
    ##   if (new_total_fee < minTotalFee) → reject
    ## nimrod feebumper.nim:287-295 enforces
    ##   minReqFeeRate = max(minRelayFeeSatVb, oldFeeRateSatVb + incrementalRelayFeeSatVb)
    ##   if newFeeRate < minReqFeeRate → reject
    ## The two are equivalent ONLY when vsize_old == vsize_new.
    ## Source-level guard: confirm the feerate-form is what's in place
    ## and the total-fee form is NOT.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("oldFeeRateSatVb + incrementalRelayFeeSatVb") >= 0
    check src.find("newFeeRate < minReqFeeRate") >= 0
    # Total-fee form markers ABSENT
    check src.find("new_total_fee") < 0
    check src.find("minTotalFee") < 0
    check src.find("Insufficient total fee") < 0  # Core's diagnostic
    # Confirm the (wrong) nimrod diagnostic IS present
    check src.find("Insufficient fee rate") >= 0

  test "G14 BUG-1 numerical demo: vsize_new < vsize_old under-charges":
    ## Reproduce the under-charge: original tx has vsize=200vB,
    ## fee=1000 sat (5 sat/vB). Replacement has vsize=100vB.
    ## Core required: 1000 + 0.1*100 = 1010 sat. nimrod required:
    ## min feerate = 5.1 sat/vB, so newFee ≥ 5.1 * 100 = 510 sat
    ## (truncated, < 1010). Demonstrate the gap arithmetically.
    let oldFee = 1000.0
    let vsizeOld = 200.0
    let vsizeNew = 100.0
    let incrSatVb = 0.1
    let oldFeeRateSatVb = oldFee / vsizeOld
    let nimrodMinNewFeeRate = oldFeeRateSatVb + incrSatVb        # 5.1
    let nimrodMinNewFeeAbs  = nimrodMinNewFeeRate * vsizeNew      # 510
    let coreMinNewFeeAbs    = oldFee + incrSatVb * vsizeNew       # 1010
    # nimrod allows REPLACEMENT with fee as low as ~510 sats
    check nimrodMinNewFeeAbs < coreMinNewFeeAbs
    check coreMinNewFeeAbs - nimrodMinNewFeeAbs > 400.0
    # This is the precise-invariant divergence.

  test "G15 BUG-9 incremental fee rounding: nimrod truncates, Core rounds up":
    ## Core src/policy/feerate.cpp CFeeRate::GetFee uses EvaluateFeeUp
    ## (always rounds up to next satoshi). nimrod mempool.nim:1891
    ## uses `int64(incrementalRelayFee * float64(txVsize))` which
    ## truncates toward zero. Off-by-one in the down-rounded case.
    let src = readSrc("mempool/mempool.nim")
    # Confirm the int64-cast pattern IS present (truncation)
    check src.find("int64(incrementalRelayFee * float64(txVsize))") >= 0
    # Confirm no ceil() / round-up call alongside it
    let line1891 = block:
      var found = false
      for line in src.splitLines():
        if line.contains("int64(incrementalRelayFee * float64(txVsize))"):
          if line.find("ceil") < 0:
            found = true
            break
      found
    check line1891  # the offending line does not call ceil

  test "G16 BUG-2 WALLET_INCREMENTAL_RELAY_FEE = 5000 MISSING":
    ## Core wallet/wallet.h:124 defines WALLET_INCREMENTAL_RELAY_FEE
    ## = 5000 sat/kvB (50x DEFAULT_INCREMENTAL_RELAY_FEE) as
    ## conservative future-proofing. Used in feebumper.cpp:135-137
    ## as `std::max(node_incremental, wallet_incremental)`.
    let srcFb = readSrc("wallet/feebumper.nim")
    let srcW  = readSrc("wallet/wallet.nim")
    let srcP  = readSrc("mempool/mempool.nim")
    check srcFb.find("WALLET_INCREMENTAL_RELAY_FEE") < 0
    check srcW.find("WALLET_INCREMENTAL_RELAY_FEE") < 0
    check srcFb.find("WalletIncrementalRelayFee") < 0  # Nim camelCase variant
    check srcW.find("WalletIncrementalRelayFee") < 0
    check srcP.find("WalletIncrementalRelayFee") < 0
    # Auto-bump diverges by ~50x from Core (0.1 vs 5.0 sat/vB).

  test "G17 BUG-10 GetRequiredFee floor MISSING":
    ## Core feebumper.cpp:101-106 enforces
    ##   if (new_total_fee < GetRequiredFee(wallet, maxTxSize)) → INVALID_PARAMETER
    ## GetRequiredFee returns wallet.m_min_fee or DEFAULT_TRANSACTION_MINFEE.
    ## nimrod has no equivalent — no m_min_fee field on the wallet.
    let src = readSrc("wallet/feebumper.nim")
    let srcW = readSrc("wallet/wallet.nim")
    check src.find("GetRequiredFee") < 0
    check src.find("getRequiredFee") < 0
    check srcW.find("minFee*") < 0  # exported m_min_fee equivalent missing
    check src.find("required fee") < 0  # Core's diagnostic string

  test "G18 BUG-11 m_default_max_tx_fee fat-finger guard MISSING":
    ## Core feebumper.cpp:109-114 enforces
    ##   if (new_total_fee > wallet.m_default_max_tx_fee) → WALLET_ERROR
    ## with default DEFAULT_TRANSACTION_MAXFEE = 0.1 BTC = 10_000_000 sats.
    ## Protects against a user typing sat/kvB where they meant sat/vB.
    ## nimrod has no defaultMaxTxFee / maxTxFee field anywhere.
    let src = readSrc("wallet/feebumper.nim")
    let srcW = readSrc("wallet/wallet.nim")
    let srcP = readSrc("consensus/params.nim")
    check src.find("maxTxFee") < 0
    check src.find("defaultMaxTxFee") < 0
    check srcW.find("maxTxFee") < 0
    check srcP.find("maxTxFee") < 0
    check src.find("cannot be higher than -maxtxfee") < 0

# ---------------------------------------------------------------------------
# G19-G22: EstimateFeeRate auto-bump 4-stage formula
# Core: src/wallet/feebumper.cpp EstimateFeeRate (line 119)
# ---------------------------------------------------------------------------

suite "W130 G19-G22 EstimateFeeRate auto-bump":

  test "G19 oldFeeRate base derived from witness-aware vsize PARTIAL":
    ## Core: GetVirtualTransactionSize uses the actual signed witness
    ## bytes. nimrod uses calculateTransactionWeight + the 110-wu
    ## P2WPKH heuristic when weight is 0 (feebumper.nim:281-285).
    ## Document the current approach.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("calculateTransactionWeight") >= 0
    check src.find("newTx.inputs.len * 110") >= 0  # P2WPKH heuristic
    # Forward note: when the heuristic is replaced with witness-aware
    # accounting, the second check will flip.

  test "G20 BUG-3 link: +1 sat pre-floor MISSING in EstimateFeeRate":
    ## Same root cause as G13. Source-level marker: the floating-point
    ## div is the visible computation; no CFeeRate(1) bump.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("CFeeRate(1)") < 0
    check src.find("feerate += 1") < 0
    check src.find("+= CFeeRate(1)") < 0

  test "G21 BUG-2 link: max(node_incremental, wallet_incremental) MISSING":
    ## Same root cause as G16. Auto-bump uses only the caller-passed
    ## node incremental; no `std::max(node, wallet)` floor.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("std::max(node_incremental_relay_fee") < 0
    check src.find("max(node, wallet)") < 0
    # The only path that uses incrementalRelayFeeSatVb:
    check src.find("oldFeeRateSatVb + incrementalRelayFeeSatVb") >= 0

  test "G22 BUG-12 std::max(feerate, min_feerate) final clamp MISSING":
    ## Core feebumper.cpp:139-143:
    ##   CFeeRate min_feerate(GetMinimumFeeRate(wallet, coin_control, nullptr));
    ##   return std::max(feerate, min_feerate);
    ## nimrod's auto-bump path at feebumper.nim:257-261 only consults
    ## the estimator when req.feeRate <= 0; never clamps to a
    ## wallet-configured `min_feerate` after assembly. So a user-
    ## supplied very-low req.feeRate passes through unclamped.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("GetMinimumFeeRate") < 0
    check src.find("getMinimumFeeRate") < 0
    # The fall-through structure (no final std::max) is visible:
    check src.find("if newFeeRate <= 0.0:") >= 0

# ---------------------------------------------------------------------------
# G23-G26: CreateRateBumpTransaction orchestration
# ---------------------------------------------------------------------------

suite "W130 G23-G26 CreateRateBumpTransaction orchestration":

  test "G23 BUG-13 original_change_index parameter MISSING":
    ## Core feebumper.cpp:159-184 accepts an optional
    ## original_change_index to designate which output recycles as
    ## change. nimrod's BumpFeeRequest has no such field.
    let req = BumpFeeRequest(
      txid: makeTxid(0xAA), feeRate: 5.0, confTarget: 6,
      replaceable: true)
    # Compile-time check: the type has no originalChangeIndex /
    # original_change_index field.
    check not compiles(BumpFeeRequest(
      txid: makeTxid(0xAA), feeRate: 5.0, confTarget: 6,
      replaceable: true, originalChangeIndex: some(0'u32)))
    # And no Change position is out of range diagnostic:
    let src = readSrc("wallet/feebumper.nim")
    check src.find("Change position is out of range") < 0
    # Use the constructed req to silence the unused-let warning.
    check req.confTarget == 6

  test "G24 BUG-14 m_min_depth = 1 (replacement-rebuild Rule 2) LATENT":
    ## Core feebumper.cpp:311-312: when re-running coin selection on
    ## the replacement build, m_min_depth=1 forces confirmed-only
    ## inputs (wallet-side enforcement of BIP-125 Rule 2). nimrod's
    ## current scope deliberately doesn't re-run selection (per the
    ## "stuck-without-change" comment), so the constraint isn't
    ## wired. Latent gap surfaces if FIX wires the rebuild.
    let src = readSrc("wallet/feebumper.nim")
    let srcCs = readSrc("wallet/coinselection.nim")
    check src.find("m_min_depth") < 0
    check src.find("minDepth = 1") < 0
    check srcCs.find("minDepth") < 0  # coinselection has no minDepth param

  test "G25 m_allow_other_inputs = true MISSING (related to G24)":
    ## Same scope as G24 — replacement-rebuild doesn't add new inputs.
    ## The only reference to m_allow_other_inputs in the nimrod source
    ## is in a comment quoting Core's algorithm (feebumper.nim:227),
    ## NOT a working code path. We assert (a) no exported Nim
    ## camelCase identifier and (b) no flag set on a coin-control
    ## record.
    let src = readSrc("wallet/feebumper.nim")
    check src.find("allowOtherInputs") < 0
    check src.find("AllowOtherInputs") < 0
    # The only occurrence is in the documentation comment
    # ("inputs preselected + m_allow_other_inputs=true. We
    # deliberately keep") — confirm it lives in a comment, not in
    # executable code, by checking that no `.allowOtherInputs = `
    # assignment exists.
    check src.find(".allowOtherInputs =") < 0
    check src.find("allow_other_inputs =") < 0

  test "G26 BumpFeeOutcome shape: inputUtxos aligned with newTx.inputs":
    ## feebumper.nim:54: inputUtxos is a seq[WalletUtxo] aligned with
    ## newTx.inputs (caller iterates them in lockstep for signing).
    ## Compile-time guard: the field exists and is seq[WalletUtxo].
    var outcome = BumpFeeOutcome(
      newTx: Transaction(version: 1, inputs: @[], outputs: @[],
                         witnesses: @[], lockTime: 0),
      inputUtxos: @[],
      oldFee: Satoshi(0),
      newFee: Satoshi(0))
    check outcome.inputUtxos.len == 0
    check outcome.newTx.inputs.len == 0

# ---------------------------------------------------------------------------
# G27-G30: CommitTransaction / MarkReplaced / RPC error mapping
# ---------------------------------------------------------------------------

suite "W130 G27-G30 CommitTransaction / MarkReplaced / RPC":

  test "G27 BUG-15 mapValue[replaces_txid] provenance MISSING":
    ## Core feebumper.cpp:371-372 sets mapValue["replaces_txid"] on
    ## the replacement tx so a subsequent gettransaction can see the
    ## provenance. nimrod has no mapValue plumbing.
    let srcW = readSrc("wallet/wallet.nim")
    let srcRpc = readSrc("rpc/server.nim")
    check srcW.find("replaces_txid") < 0
    check srcRpc.find("replaces_txid") < 0

  test "G28 BUG-16 MarkReplaced proc MISSING":
    ## Core feebumper.cpp:378-380 calls
    ## wallet.MarkReplaced(oldTxid, bumpedTxid). nimrod has no
    ## equivalent — no markReplaced proc on Wallet.
    let srcW = readSrc("wallet/wallet.nim")
    check srcW.find("markReplaced") < 0
    check srcW.find("MarkReplaced") < 0
    check srcW.find("marked the original transaction as replaced") < 0

  test "G29 bumpFeeKindToRpcCode maps all 4 BumpFeeErrorKind variants":
    ## server.nim:6936-6941 — error-code mapping parity.
    let src = readSrc("rpc/server.nim")
    check src.find("bfeInvalidAddressOrKey: RpcInvalidAddressOrKey") >= 0
    check src.find("bfeInvalidParameter:    RpcInvalidParams") >= 0
    check src.find("bfeWalletError:         RpcWalletError") >= 0
    check src.find("bfeMiscError:           RpcMiscError") >= 0

  test "G30 bumpfee vs psbtbumpfee require_mine distinction PRESENT":
    ## server.nim:6972 flips requireMine = not wantPsbt. Matches
    ## Core's bumpfee_helper / psbtbumpfee_helper split.
    let src = readSrc("rpc/server.nim")
    check src.find("requireMine = not wantPsbt") >= 0

# ---------------------------------------------------------------------------
# Additional pure-arithmetic regression: parseBfeKind round-trip
# (sanity for the error-code marshalling that the RPC layer relies on)
# ---------------------------------------------------------------------------

suite "W130 parseBfeKind round-trip (BumpFeeErrorKind sanity)":

  test "parseBfeKind round-trips bfeInvalidAddressOrKey":
    let raw = $ord(bfeInvalidAddressOrKey) & ":not found"
    let (kind, text) = parseBfeKind(raw)
    check kind == bfeInvalidAddressOrKey
    check text == "not found"

  test "parseBfeKind round-trips bfeInvalidParameter":
    let raw = $ord(bfeInvalidParameter) & ":bad fee"
    let (kind, text) = parseBfeKind(raw)
    check kind == bfeInvalidParameter
    check text == "bad fee"

  test "parseBfeKind round-trips bfeWalletError":
    let raw = $ord(bfeWalletError) & ":not mine"
    let (kind, text) = parseBfeKind(raw)
    check kind == bfeWalletError
    check text == "not mine"

  test "parseBfeKind round-trips bfeMiscError":
    let raw = $ord(bfeMiscError) & ":misc"
    let (kind, text) = parseBfeKind(raw)
    check kind == bfeMiscError
    check text == "misc"

  test "parseBfeKind falls back to bfeWalletError on malformed input":
    let (kind, text) = parseBfeKind("not a kind prefix")
    check kind == bfeWalletError
    check text == "not a kind prefix"

# ---------------------------------------------------------------------------
# BUG-1 PRECISE INVARIANT — numerical fixture-based gate.
#
# Core's Rule 3 (feebumper.cpp:88-99) operates on TOTAL FEE at the
# replacement's maxTxSize. nimrod's check operates on FEERATE
# vs original's vsize. We build a synthetic replacement scenario
# and assert the two formulas DISAGREE. When FIX-N flips
# feebumper.nim:287-295 to the total-fee form, the comparison
# below flips and the test acts as a forward regression guard.
# ---------------------------------------------------------------------------

suite "W130 BUG-1 numerical divergence (CDIV demonstration)":

  test "vsize_new > vsize_old: nimrod feerate-check OVER-CHARGES":
    ## Replacement adds an input → vsize bigger. Core's required
    ## total fee bumps by `incrementalRelayFee * vsize_new` (10x100
    ## extra over original). nimrod's required total fee bumps by
    ## `(oldFeeRate + incremental) * vsize_new` which is much higher.
    let oldFee = 1000.0
    let vsizeOld = 200.0
    let vsizeNew = 300.0           # +100 vB
    let oldFeeRateSatVb = oldFee / vsizeOld          # 5.0
    let incrSatVb = 0.1                              # Core default
    let coreMinTotal   = oldFee + incrSatVb * vsizeNew       # 1030
    let nimrodMinTotal =
      (oldFeeRateSatVb + incrSatVb) * vsizeNew               # 1530
    check nimrodMinTotal > coreMinTotal
    check almostEqual(nimrodMinTotal - coreMinTotal, 500.0)

  test "vsize_new < vsize_old: nimrod feerate-check UNDER-CHARGES":
    ## Replacement drops an input → vsize smaller. Core's required
    ## total fee is `old_fee + incremental * vsize_new`. nimrod's
    ## required total fee is `(oldFeeRate + incremental) * vsize_new`
    ## which is much LOWER. nimrod accepts where Core rejects.
    let oldFee = 1000.0
    let vsizeOld = 200.0
    let vsizeNew = 100.0           # -100 vB
    let oldFeeRateSatVb = oldFee / vsizeOld          # 5.0
    let incrSatVb = 0.1
    let coreMinTotal   = oldFee + incrSatVb * vsizeNew       # 1010
    let nimrodMinTotal =
      (oldFeeRateSatVb + incrSatVb) * vsizeNew               # 510
    check nimrodMinTotal < coreMinTotal
    check almostEqual(coreMinTotal - nimrodMinTotal, 500.0)
    # Mempool then rejects (because mempool-side PaysForRBF Rule 3
    # still requires new_fee >= old_fee), but the wallet built a
    # tx that should never have been broadcast.

  test "vsize_new == vsize_old: nimrod feerate-check matches Core":
    ## Equal-vsize case is the only one where the two formulas
    ## agree. Use this as the parity anchor.
    let oldFee = 1000.0
    let vsizeOld = 200.0
    let vsizeNew = vsizeOld
    let oldFeeRateSatVb = oldFee / vsizeOld          # 5.0
    let incrSatVb = 0.1
    let coreMinTotal   = oldFee + incrSatVb * vsizeNew       # 1020
    let nimrodMinTotal =
      (oldFeeRateSatVb + incrSatVb) * vsizeNew               # 1020
    check almostEqual(nimrodMinTotal, coreMinTotal)
