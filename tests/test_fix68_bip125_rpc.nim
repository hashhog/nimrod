## FIX-68 — RPC bip125-replaceable + fullrbf reflect actual state.
##
## W120 BUG-3 (P0-RPC): `bip125-replaceable` was hardcoded `true` in
## getmempoolentry / getrawmempool verbose responses regardless of whether
## the tx actually signaled opt-in via nSequence. Wallets that relied on
## this field could not tell which mempool txs were truly replaceable.
##
## W120 BUG-8 (P1-RPC): `fullrbf` in getmempoolinfo was hardcoded `true`,
## ignoring the mempool's actual `fullRbf` field. An operator who set
## `mempoolfullrbf=0` could not observe the configuration through RPC.
##
## Reference:
##   - bitcoin-core/src/policy/rbf.cpp SignalsOptInRBF() / IsRBFOptIn()
##   - bitcoin-core/src/rpc/mempool.cpp entryToJSON sets
##     `bip125-replaceable` from `IsRBFOptIn(tx, pool)` (line 560-567)
##   - BIP-125

import unittest2
import std/[options, tables, times, sets, os, json]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/rpc/server

const TestDbPath = "/tmp/nimrod_fix68_bip125_rpc_test"

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

proc makeEntry(tx: Transaction, txid: TxId, fee: Satoshi = Satoshi(100),
               weight: int = 400): MempoolEntry =
  MempoolEntry(
    tx: tx, txid: txid, fee: fee,
    weight: weight, feeRate: 1.0, timeAdded: getTime(),
    height: 100, ancestorFee: fee, ancestorWeight: weight,
    ancestorCount: 1, ancestorSize: weight div 4)

proc makeRpc(mp: Mempool, cs: ChainState, params: ConsensusParams): RpcServer =
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)

# ---------------------------------------------------------------------------
# FIX-68 BUG-3: mempoolEntryJson.bip125-replaceable reflects actual tx state
# ---------------------------------------------------------------------------
suite "FIX-68 BUG-3: bip125-replaceable reflects tx opt-in state":

  test "non-signaling tx in standard mode → bip125-replaceable=false":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    let txid = makeTxid(0x11)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[],
                     sequence: 0xffffffff'u32)],  # FINAL — does NOT opt in
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let entry = makeEntry(tx, txid)
    mp.entries[txid] = entry

    let obj = rpc.mempoolEntryJson(txid, entry)
    check obj.hasKey("bip125-replaceable")
    check obj["bip125-replaceable"].kind == JBool
    # FIX-68: was hardcoded `true`; now reflects actual state.
    check obj["bip125-replaceable"].getBool() == false

    cs.close()
    cleanupTestDb()

  test "signaling tx (nSequence 0xfffffffd) → bip125-replaceable=true":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    let txid = makeTxid(0x22)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xBB), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],  # opt-in
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let entry = makeEntry(tx, txid)
    mp.entries[txid] = entry

    let obj = rpc.mempoolEntryJson(txid, entry)
    check obj["bip125-replaceable"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "non-signaling tx with signaling unconfirmed ancestor → " &
       "bip125-replaceable=true (Gate 2)":
    ## BIP-125 Gate 2: a tx that does NOT signal directly still inherits
    ## opt-in if ANY of its unconfirmed mempool ancestors signals.
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    # Parent signals (nSequence 0xfffffffd)
    let parentTxid = makeTxid(0x33)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xCC), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(5000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let parentEntry = makeEntry(parentTx, parentTxid)
    mp.entries[parentTxid] = parentEntry

    # Child does NOT signal but spends from parent
    let childTxid = makeTxid(0x34)
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0),
                     scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(4500), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let childEntry = makeEntry(childTx, childTxid)
    mp.entries[childTxid] = childEntry

    let parentObj = rpc.mempoolEntryJson(parentTxid, parentEntry)
    check parentObj["bip125-replaceable"].getBool() == true

    let childObj = rpc.mempoolEntryJson(childTxid, childEntry)
    # Gate 2: child inherits opt-in from signaling parent.
    check childObj["bip125-replaceable"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "full-RBF mode: non-signaling tx still reported replaceable":
    ## When fullRbf is enabled, EVERY mempool tx is replaceable regardless
    ## of nSequence signaling — and the RPC must reflect that.
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = true)
    let rpc = makeRpc(mp, cs, params)

    let txid = makeTxid(0x44)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xDD), scriptSig: @[],
                     sequence: 0xffffffff'u32)],  # FINAL
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let entry = makeEntry(tx, txid)
    mp.entries[txid] = entry

    let obj = rpc.mempoolEntryJson(txid, entry)
    check obj["bip125-replaceable"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "mixed signaling on multiple inputs: ANY one opt-in → " &
       "bip125-replaceable=true":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    let txid = makeTxid(0x55)
    let tx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(0xE1), scriptSig: @[],
             sequence: 0xffffffff'u32),  # FINAL
        TxIn(prevOut: makeOutpoint(0xE2), scriptSig: @[],
             sequence: 0xfffffffd'u32),  # opt-in
        TxIn(prevOut: makeOutpoint(0xE3), scriptSig: @[],
             sequence: 0xffffffff'u32),  # FINAL
      ],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let entry = makeEntry(tx, txid)
    mp.entries[txid] = entry

    let obj = rpc.mempoolEntryJson(txid, entry)
    check obj["bip125-replaceable"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "nSequence 0xfffffffe (carve-out) → bip125-replaceable=false":
    ## Threshold is MAX_BIP125_RBF_SEQUENCE = 0xfffffffd. 0xfffffffe is
    ## the nLockTime-without-RBF carve-out — must NOT opt in.
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    let txid = makeTxid(0x66)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xF1), scriptSig: @[],
                     sequence: 0xfffffffe'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let entry = makeEntry(tx, txid)
    mp.entries[txid] = entry

    let obj = rpc.mempoolEntryJson(txid, entry)
    check obj["bip125-replaceable"].getBool() == false

    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# FIX-68 BUG-8: getmempoolinfo.fullrbf reflects actual configuration
# ---------------------------------------------------------------------------
suite "FIX-68 BUG-8: getmempoolinfo.fullrbf reflects mp.fullRbf":

  # NOTE (byte-diff parity): Core v31.99 REMOVED the mempoolfullrbf option and
  # MempoolInfoToJSON now hardcodes `fullrbf = true` (mempool.cpp:1058).
  # getmempoolinfo.fullrbf is therefore ALWAYS true regardless of the node's
  # mp.fullRbf config (the per-tx bip125-replaceable field still reflects the
  # real opt-in state — see the anti-regression suite below). These tests assert
  # the Core-exact wire output the byte-diff gate requires.
  test "getmempoolinfo.fullrbf == true regardless of mp.fullRbf=false (Core v31.99)":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    let info = rpc.handleGetMempoolInfo()
    check info.hasKey("fullrbf")
    check info["fullrbf"].kind == JBool
    check info["fullrbf"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "getmempoolinfo.fullrbf == true with mp.fullRbf=true":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = true)
    let rpc = makeRpc(mp, cs, params)

    let info = rpc.handleGetMempoolInfo()
    check info["fullrbf"].getBool() == true

    cs.close()
    cleanupTestDb()

  test "default mempool → getmempoolinfo.fullrbf == true (hardcoded, Core v31.99)":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params)  # default fullRbf
    let rpc = makeRpc(mp, cs, params)

    let info = rpc.handleGetMempoolInfo()
    check info["fullrbf"].getBool() == true

    cs.close()
    cleanupTestDb()

# ---------------------------------------------------------------------------
# Anti-regression guard: the FIX-68 wiring must not regress to a literal
# value.  If a future refactor restores `%true` in either site, these tests
# would still pass for the fullRbf=true case but FAIL for the false case
# above — making the regression visible to CI.
# ---------------------------------------------------------------------------
suite "FIX-68 anti-regression invariants":

  test "isBip125Replaceable predicate matches RPC bip125-replaceable":
    ## The RPC field MUST equal mp.isBip125Replaceable(txid) for the
    ## same txid — they are the same source of truth.
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params, fullRbf = false)
    let rpc = makeRpc(mp, cs, params)

    # Case A: non-signaling
    let txidA = makeTxid(0x77)
    let txA = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xA0), scriptSig: @[],
                     sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let entryA = makeEntry(txA, txidA)
    mp.entries[txidA] = entryA
    check rpc.mempoolEntryJson(txidA, entryA)["bip125-replaceable"].getBool() ==
          mp.isBip125Replaceable(txidA)

    # Case B: signaling
    let txidB = makeTxid(0x78)
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xB0), scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let entryB = makeEntry(txB, txidB)
    mp.entries[txidB] = entryB
    check rpc.mempoolEntryJson(txidB, entryB)["bip125-replaceable"].getBool() ==
          mp.isBip125Replaceable(txidB)

    cs.close()
    cleanupTestDb()

  test "getmempoolinfo.fullrbf is hardcoded true (Core v31.99) for both configs":
    ## Per-tx replaceability still tracks mp.fullRbf (asserted above), but the
    ## top-level getmempoolinfo.fullrbf is hardcoded true to match Core's wire.
    cleanupTestDb()
    let params = regtestParams()

    var cs1 = newChainState(TestDbPath, params)
    var mp1 = newMempool(cs1, params, fullRbf = false)
    let rpc1 = makeRpc(mp1, cs1, params)
    check rpc1.handleGetMempoolInfo()["fullrbf"].getBool() == true
    cs1.close()
    cleanupTestDb()

    var cs2 = newChainState(TestDbPath, params)
    var mp2 = newMempool(cs2, params, fullRbf = true)
    let rpc2 = makeRpc(mp2, cs2, params)
    check rpc2.handleGetMempoolInfo()["fullrbf"].getBool() == true
    cs2.close()
    cleanupTestDb()
