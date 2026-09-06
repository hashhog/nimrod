## prioritisetransaction + getprioritisedtransactions — roundtrip + shape parity.
##
## Mirrors bitcoin-core/src/rpc/mining.cpp prioritisetransaction /
## getprioritisedtransactions and txmempool.cpp PrioritiseTransaction /
## GetPrioritisedTransactions / GetModifiedFee / mapDeltas.
##
## Behaviour under test (Core-exact):
##   - prioritisetransaction(txid, dummy, fee_delta): dummy MUST be 0 / null /
##     omitted (non-zero rejected); fee_delta STACKS additively; a net delta of
##     0 ERASES the entry; the delta is recorded whether or not the tx is in the
##     mempool.
##   - getprioritisedtransactions: a JSON OBJECT keyed by txid (display hex);
##     each value = { fee_delta: i64 (always), in_mempool: bool,
##     modified_fee: i64 (ONLY when in_mempool=true) }.
##   - GetModifiedFee = base fee + delta (surfaced as modified_fee).
##   - deltas survive a mempool.dat dump/load round-trip.
##
## Proven-teeth: builds a real RpcServer, inserts a real MempoolEntry, drives
## both RPCs via handleMethod, and asserts the exact JSON shape and values.

import unittest2
import std/[os, options, json, times, tables]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mempool/persist
import ../src/mining/fees
import ../src/rpc/server
import ../src/crypto/[hashing, secp256k1]

const TestDbPath = "/tmp/nimrod_prioritise_test"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc reverseHexLocal(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc toHexLower(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc dispTxid(txid: TxId): string =
  reverseHexLocal(toHexLower(array[32, byte](txid)))

proc makeTx(seed: byte): Transaction =
  ## Deterministic, simple tx referencing a made-up parent.
  var parent: array[32, byte]
  for i in 0 ..< 32: parent[i] = seed xor 0x5A'u8
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(parent), vout: 0'u32),
      scriptSig: @[byte(seed), byte(0x51)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(50_000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc buildRpc(mp: Mempool, cs: ChainState): RpcServer =
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = cs.params)

proc insertEntry(mp: Mempool, tx: Transaction, baseFee: int64) =
  ## Insert a tx directly as a mempool entry with a known base fee.
  let txid = tx.txid()
  let weight = 400
  mp.entries[txid] = MempoolEntry(
    tx: tx,
    txid: txid,
    wtxid: tx.wtxid(),
    fee: Satoshi(baseFee),
    weight: weight,
    feeRate: float64(baseFee) / (weight.float64 / 4.0),
    timeAdded: getTime(),
    height: 0'i32,
    ancestorFee: Satoshi(baseFee),
    ancestorWeight: weight,
    ancestorCount: 1,
    ancestorSize: (weight + 3) div 4)
  mp.byWtxid[tx.wtxid()] = txid

suite "prioritisetransaction — roundtrip + shape":

  test "full roundtrip: stack, dummy reject, erase, out-of-mempool":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)
    let rpc = buildRpc(mp, cs)

    # --- A tx T that we OWN in the mempool, base fee = 2000 sat ----------------
    let tx = makeTx(0x11'u8)
    let baseFee = 2000'i64
    insertEntry(mp, tx, baseFee)
    let txid = tx.txid()
    let disp = dispTxid(txid)

    # Empty initially.
    block:
      let resp = rpc.handleMethod("getprioritisedtransactions", %*[])
      check resp.kind == JObject
      check resp.len == 0

    # --- prioritisetransaction(T, 0, +1000) -----------------------------------
    block:
      let r = rpc.handleMethod("prioritisetransaction", %*[disp, 0, 1000])
      check r.kind == JBool
      check r.getBool() == true

      let g = rpc.handleMethod("getprioritisedtransactions", %*[])
      check g.kind == JObject
      check g.len == 1
      check g.hasKey(disp)
      let e = g[disp]
      check e["fee_delta"].kind == JInt
      check e["fee_delta"].getBiggestInt() == 1000
      check e["in_mempool"].getBool() == true
      check e.hasKey("modified_fee")
      check e["modified_fee"].getBiggestInt() == baseFee + 1000
      # GetModifiedFee at the mempool level matches.
      check mp.getModifiedFee(txid) == baseFee + 1000

    # --- prioritisetransaction(T, 0, +500) → STACKS to 1500 -------------------
    block:
      discard rpc.handleMethod("prioritisetransaction", %*[disp, 0, 500])
      let g = rpc.handleMethod("getprioritisedtransactions", %*[])
      check g[disp]["fee_delta"].getBiggestInt() == 1500
      check g[disp]["modified_fee"].getBiggestInt() == baseFee + 1500
      check mp.getFeeDelta(txid) == 1500

    # --- non-zero dummy → rejected --------------------------------------------
    block:
      var raised = false
      try:
        discard rpc.handleMethod("prioritisetransaction", %*[disp, 1, 100])
      except RpcError as e:
        raised = true
        check e.code == RpcInvalidParameter
      check raised
      # Float non-zero dummy also rejected.
      raised = false
      try:
        discard rpc.handleMethod("prioritisetransaction", %*[disp, 0.5, 100])
      except RpcError:
        raised = true
      check raised
      # Delta unchanged after the rejected calls.
      check mp.getFeeDelta(txid) == 1500

    # --- zero dummy (and float 0.0) accepted -----------------------------------
    block:
      let r1 = rpc.handleMethod("prioritisetransaction", %*[disp, 0.0, 0])
      check r1.getBool() == true   # net delta unchanged, no-op add of 0
      check mp.getFeeDelta(txid) == 1500
      # Omitted dummy via named-style positional: [txid, null, delta].
      let r2 = rpc.handleMethod("prioritisetransaction", %*[disp, newJNull(), 0])
      check r2.getBool() == true

    # --- prioritisetransaction(T, 0, -1500) → entry ERASED --------------------
    block:
      discard rpc.handleMethod("prioritisetransaction", %*[disp, 0, -1500])
      let g = rpc.handleMethod("getprioritisedtransactions", %*[])
      check not g.hasKey(disp)        # gone from the map
      check g.len == 0
      check mp.getFeeDelta(txid) == 0
      # Modified fee with no delta == base fee.
      check mp.getModifiedFee(txid) == baseFee

    # --- delta on a txid NOT in the mempool → in_mempool=false, no modified_fee
    block:
      let ghostTx = makeTx(0x99'u8)
      let ghostTxid = ghostTx.txid()
      let ghostDisp = dispTxid(ghostTxid)
      check ghostTxid notin mp.entries
      discard rpc.handleMethod("prioritisetransaction", %*[ghostDisp, 0, 7777])
      let g = rpc.handleMethod("getprioritisedtransactions", %*[])
      check g.hasKey(ghostDisp)
      let e = g[ghostDisp]
      check e["fee_delta"].getBiggestInt() == 7777
      check e["in_mempool"].getBool() == false
      check not e.hasKey("modified_fee")   # ABSENT when not in mempool

  test "deltas survive mempool.dat dump/load round-trip":
    cleanupTest()
    defer: cleanupTest()
    createDir(TestDbPath)
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)

    # An in-mempool tx with a delta, plus an out-of-mempool ghost delta.
    let tx = makeTx(0x21'u8)
    insertEntry(mp, tx, 3000'i64)
    mp.prioritiseTransaction(tx.txid(), 1234'i64)

    let ghost = makeTx(0x77'u8)
    mp.prioritiseTransaction(ghost.txid(), -500'i64)

    let dumpPath = TestDbPath / "mempool.dat"
    check dumpMempool(mp, dumpPath)

    # Load into a fresh mempool.
    let mp2 = newMempool(cs, params, fullRbf = false)
    let crypto = newCryptoEngine()
    # The in-mempool tx won't re-accept (made-up parent / no UTXO), but its
    # nFeeDelta and the ghost mapDeltas entry must still be restored.
    discard loadMempool(mp2, dumpPath, crypto)

    check mp2.getFeeDelta(tx.txid()) == 1234
    check mp2.getFeeDelta(ghost.txid()) == -500

  test "getprioritisedtransactions returns an object, never an array":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)
    let rpc = buildRpc(mp, cs)
    let resp = rpc.handleMethod("getprioritisedtransactions", %*[])
    check resp.kind == JObject

  # --------------------------------------------------------------------------
  # FIX-72 EFFECT TESTS: the prioritise delta drives MINING + EVICTION, not just
  # the RPC-reported modified_fee.  Mirrors rustoshi FIX-72 (W120 BUG-9/10) and
  # Core txmempool.cpp:636-643 (UpdateModifiedFee + SetTransactionFee).
  # --------------------------------------------------------------------------

  test "mining rank: a prioritised low-base-fee tx is selected ahead of a higher-base-fee tx":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)

    # Two independent single-entry txs (distinct made-up parents, no in-mempool
    # ancestors), same weight (400 WU = 100 vbytes).
    #   A: LOW base fee  = 1000 sat  → base rate 10 sat/vB
    #   B: HIGH base fee = 5000 sat  → base rate 50 sat/vB
    let txA = makeTx(0x41'u8)
    let txB = makeTx(0x42'u8)
    insertEntry(mp, txA, 1000'i64)
    insertEntry(mp, txB, 5000'i64)
    let idA = txA.txid()
    let idB = txB.txid()

    # BEFORE prioritisation: B (higher base) must rank ahead of A.
    block:
      let ordered = mp.getTransactionsByFeeRate(10_000_000)
      check ordered.len == 2
      check ordered[0].txid == idB
      check ordered[1].txid == idA

    # Prioritise A by +9000 sat → A modified fee = 10000 (rate 100 sat/vB),
    # which now EXCEEDS B's 5000 (rate 50 sat/vB).
    mp.prioritiseTransaction(idA, 9000'i64)
    check mp.getModifiedFee(idA) == 10000
    check mp.getModifiedFee(idB) == 5000   # B unchanged

    # AFTER prioritisation: A must now rank AHEAD of B in the mining sort.
    block:
      let ordered = mp.getTransactionsByFeeRate(10_000_000)
      check ordered.len == 2
      check ordered[0].txid == idA
      check ordered[1].txid == idB

  test "mining rank: un-prioritised order is unchanged (delta 0 == base behaviour)":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)

    let txA = makeTx(0x51'u8)   # low base
    let txB = makeTx(0x52'u8)   # high base
    insertEntry(mp, txA, 1000'i64)
    insertEntry(mp, txB, 5000'i64)
    # No prioritisetransaction calls — pure base-fee ordering, B ahead of A.
    let ordered = mp.getTransactionsByFeeRate(10_000_000)
    check ordered.len == 2
    check ordered[0].txid == txB.txid()
    check ordered[1].txid == txA.txid()

  test "eviction: a prioritised low-base-fee tx survives; the lowest MODIFIED feerate is evicted":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)

    # Two independent single-entry txs.
    #   A: LOW base = 1000 sat  → base rate 10 sat/vB
    #   B: HIGH base = 5000 sat → base rate 50 sat/vB
    let txA = makeTx(0x61'u8)
    let txB = makeTx(0x62'u8)
    insertEntry(mp, txA, 1000'i64)
    insertEntry(mp, txB, 5000'i64)
    let idA = txA.txid()
    let idB = txB.txid()

    # Prioritise A so its MODIFIED feerate (100 sat/vB) exceeds B's base 50.
    mp.prioritiseTransaction(idA, 9000'i64)

    # Under pressure, evictLowestFee removes the lowest-MODIFIED-feerate package.
    # B (50 sat/vB modified == base) is now the lowest; the prioritised A (100
    # sat/vB modified) must SURVIVE despite its low base fee.
    mp.evictLowestFee()
    check idA in mp.entries          # prioritised tx survived
    check idB notin mp.entries       # higher-base but lower-MODIFIED tx evicted

  test "eviction: un-prioritised picks the lowest BASE feerate (delta 0 == base behaviour)":
    cleanupTest()
    defer: cleanupTest()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)

    let txA = makeTx(0x71'u8)   # low base → should be evicted
    let txB = makeTx(0x72'u8)   # high base → should survive
    insertEntry(mp, txA, 1000'i64)
    insertEntry(mp, txB, 5000'i64)
    # No prioritisation: lowest base feerate (A) is evicted, B survives.
    mp.evictLowestFee()
    check txA.txid() notin mp.entries
    check txB.txid() in mp.entries
