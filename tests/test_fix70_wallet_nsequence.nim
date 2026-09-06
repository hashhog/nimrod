## FIX-70 — Wallet default nSequence = MAX_BIP125_RBF_SEQUENCE (0xfffffffd).
##
## W120 BUG-2 (P0-RPC) cross-impl audit: camlcoin + rustoshi were emitting
## `createpsbt` inputs with nSequence = 0xFFFFFFFE (non-RBF-signaling) by
## default, even though Core's `AddInputs()` in
## bitcoin-core/src/rpc/rawtransaction_util.cpp uses
##   rbf.value_or(true)  // default TRUE when caller omits replaceable
## and `CWallet::m_signal_rbf` has defaulted to true since v23 — so
## Core-equivalent wallets default to MAX_BIP125_RBF_SEQUENCE = 0xfffffffd.
##
## Pre-FIX-70 nimrod audit:
##   - handleCreatePsbt: BUG — defaulted `replaceable` to false, so when the
##     RPC caller omitted the flag the inputs emerged with sequence
##     0xffffffff (SEQUENCE_FINAL). Non-RBF, non-locktime-enforcing — strict
##     Core divergence.
##   - handleWalletCreateFundedPsbt: was already correct on the common
##     (replaceable defaults true) path, but the post-loop upgrade logic
##     unconditionally flipped 0xffffffff → 0xfffffffd whenever
##     `replaceable OR locktime>0` was true, breaking the !rbf+locktime
##     carve-out where Core uses 0xfffffffe (MAX_SEQUENCE_NONFINAL).
##
## FIX-70 changes:
##   - handleCreatePsbt: default `replaceable` to true (Core parity).
##     Per-input default sequence derived from {rbf, locktime} using Core's
##     three-way table (0xfffffffd / 0xfffffffe / 0xffffffff).
##   - handleWalletCreateFundedPsbt: same three-way default for pre-selected
##     inputs; post-fund pass walks RBF-signaling inputs back to the
##     non-RBF default when caller explicitly passed replaceable=false.
##
## Reference:
##   - bitcoin-core/src/wallet/wallet.h:132 — DEFAULT_WALLET_RBF = true
##   - bitcoin-core/src/wallet/wallet.h — MAX_BIP125_RBF_SEQUENCE = 0xfffffffd
##   - bitcoin-core/src/rpc/rawtransaction_util.cpp:25-71 — AddInputs()
##   - bitcoin-core/src/rpc/rawtransaction.cpp:1620-1642 — createpsbt
##   - bitcoin-core/src/wallet/rpc/spend.cpp:1748 — walletcreatefundedpsbt rbf

import unittest2
import std/[options, json, os, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/psbt

const TestDbPath = "/tmp/nimrod_fix70_test"

# A valid regtest address (bcrt1q… P2WPKH). Decoder lives in
# src/crypto/address.nim; we only need one whose scriptPubKey parses.
const RegtestAddr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeRpc(): RpcServer =
  cleanupTestDb()
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)

proc makeInputJson(): JsonNode =
  ## One input — txid all-1s, vout 0, NO `sequence` field so we exercise
  ## the default-sequence code path.
  let txidHex = repeat('1', 64)
  %*[{"txid": txidHex, "vout": 0}]

proc makeOutputsJson(): JsonNode =
  %*[{RegtestAddr: 0.001}]

proc psbtSequences(b64: string): seq[uint32] =
  ## Decode the PSBT and yank the on-the-wire nSequence values out of the
  ## embedded unsigned tx.
  let p = fromBase64(b64)
  doAssert p.tx.isSome, "psbt has no unsigned tx"
  for txin in p.tx.get().inputs:
    result.add(txin.sequence)

# ---------------------------------------------------------------------------
# handleCreatePsbt — Core defaults rbf to true when replaceable is omitted.
# ---------------------------------------------------------------------------
suite "FIX-70 createpsbt default nSequence":

  test "replaceable omitted → default MAX_BIP125_RBF_SEQUENCE (0xfffffffd)":
    ## REGRESSION GUARD: pre-FIX-70 nimrod emitted 0xffffffff here, against
    ## Core's `rbf.value_or(true)` default of MAX_BIP125_RBF_SEQUENCE.
    let rpc = makeRpc()
    let params = %*[
      makeInputJson(),
      makeOutputsJson()
      # NOTE: locktime + replaceable BOTH omitted.
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs.len == 1
    check seqs[0] == 0xfffffffd'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "replaceable=true explicit → 0xfffffffd":
    let rpc = makeRpc()
    let params = %*[
      makeInputJson(),
      makeOutputsJson(),
      0,
      true
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == 0xfffffffd'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "replaceable=false, locktime=0 → 0xffffffff (SEQUENCE_FINAL)":
    let rpc = makeRpc()
    let params = %*[
      makeInputJson(),
      makeOutputsJson(),
      0,
      false
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == 0xffffffff'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "replaceable=false, locktime>0 → 0xfffffffe (MAX_SEQUENCE_NONFINAL)":
    ## Core's AddInputs() picks MAX_SEQUENCE_NONFINAL in the !rbf branch
    ## when locktime is set so that the locktime is actually enforced.
    let rpc = makeRpc()
    let params = %*[
      makeInputJson(),
      makeOutputsJson(),
      500,    # locktime > 0
      false
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == 0xfffffffe'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "replaceable=true, locktime>0 → still 0xfffffffd (rbf wins)":
    let rpc = makeRpc()
    let params = %*[
      makeInputJson(),
      makeOutputsJson(),
      500,
      true
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == 0xfffffffd'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "explicit per-input sequence overrides the default":
    ## Core honours an explicit `sequence` field on a per-input basis even
    ## when `rbf` is at its default.
    let rpc = makeRpc()
    let txidHex = repeat('1', 64)
    let params = %*[
      [{"txid": txidHex, "vout": 0, "sequence": 0xffffffff'i64}],
      makeOutputsJson()
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == 0xffffffff'u32
    rpc.chainState.close()
    cleanupTestDb()

  test "multiple inputs all pick up the same default":
    let rpc = makeRpc()
    let txidA = repeat('a', 64)
    let txidB = repeat('b', 64)
    let txidC = repeat('c', 64)
    let params = %*[
      [
        {"txid": txidA, "vout": 0},
        {"txid": txidB, "vout": 1},
        {"txid": txidC, "vout": 2}
      ],
      makeOutputsJson()
    ]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs.len == 3
    for s in seqs:
      check s == 0xfffffffd'u32
    rpc.chainState.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# walletcreatefundedpsbt — explicit pre-selected inputs path.
#
# We exercise only the pre-selected-inputs branch here because the
# auto-fund branch needs a populated wallet UTXO set; the W118 / W120
# audits already cover wallet.createTransaction's 0xfffffffd default
# in test_wallet / test_rbf. The pre-selected-inputs default has the
# same Core-parity bug surface as createpsbt and is the one fixed
# directly in FIX-70.
# ---------------------------------------------------------------------------
suite "FIX-70 walletcreatefundedpsbt pre-selected input default nSequence":

  test "no-wallet call surfaces wallet-required error (not silent 0xffff)":
    ## Anti-regression: handleWalletCreateFundedPsbt MUST reach
    ## getTargetWallet() before computing the default sequence. If it ever
    ## starts emitting inputs without a wallet attached (silent fallback),
    ## the default-sequence algorithm would still be wrong by definition.
    ## This guards the "fail fast / wallet required" precondition that
    ## sister tests in test_w118_wallet rely on.
    let rpc = makeRpc()
    let txidHex = repeat('1', 64)
    let params = %*[
      [{"txid": txidHex, "vout": 0}],
      makeOutputsJson()
    ]
    var raised = false
    try:
      discard rpc.handleMethod("walletcreatefundedpsbt", params)
    except CatchableError:
      raised = true
    check raised
    rpc.chainState.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# Cross-RPC anti-regression: the per-input default sequence for createpsbt
# must equal MAX_BIP125_RBF_SEQUENCE everywhere the wallet emits inputs.
# ---------------------------------------------------------------------------
suite "FIX-70 anti-regression: 0xfffffffd is the wallet-emission default":

  test "constant MAX_BIP125_RBF_SEQUENCE in mempool matches default":
    ## The mempool's BIP-125 threshold constant must equal the default
    ## sequence we emit. If someone bumps one and forgets the other,
    ## getmempoolentry.bip125-replaceable will lie about freshly-emitted
    ## wallet txs.
    check MaxBip125RbfSequence == 0xfffffffd'u32

  test "createpsbt default sequence equals MaxBip125RbfSequence":
    let rpc = makeRpc()
    let params = %*[makeInputJson(), makeOutputsJson()]
    let b64 = rpc.handleMethod("createpsbt", params).getStr()
    let seqs = psbtSequences(b64)
    check seqs[0] == MaxBip125RbfSequence
    rpc.chainState.close()
    cleanupTestDb()
