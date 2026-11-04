## RBF rule 5 counts distinct conflicted CLUSTERS, not evicted transactions.
##
## Core v31.1 policy/rbf.cpp GetEntriesForConflicts():
##   pool.GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES
## then every descendant is added with no further count.  core-regtest group
## rbf, scenario `clusters`: five clusters of 21 txs (105 evictions) are
## replaced by one tx; Core accepts, nimrod used to answer
## "too many potential replacements (105 > 100)".
##
## Command:  nim c -r tests/test_rbf_clusters.nim

import unittest2
import std/[os, times, sets, tables, strutils]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_rbf_clusters_test"

proc txidOf(a, b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = a
  arr[1] = b
  TxId(arr)

proc addEntry(mp: var Mempool, id: TxId, prev: OutPoint) =
  let tx = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)
  mp.entries[id] = MempoolEntry(
    tx: tx, txid: id, fee: Satoshi(10), weight: 400, feeRate: 1.0,
    timeAdded: getTime(), height: 100, ancestorFee: Satoshi(10),
    ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
  mp.spentBy[prev] = id

proc addRoot(mp: var Mempool, n: int, children: int): (TxId, OutPoint) =
  ## A root spending an outside coin plus `children` children: one cluster.
  var coin: array[32, byte]
  coin[0] = 0xEE
  coin[1] = byte(n)
  let rootId = txidOf(byte(n), 0)
  let coinOp = OutPoint(txid: TxId(coin), vout: 0)
  mp.addEntry(rootId, coinOp)
  for c in 1 .. children:
    mp.addEntry(txidOf(byte(n), byte(c)), OutPoint(txid: rootId, vout: uint32(c - 1)))
  (rootId, coinOp)

proc replacementFor(ops: seq[OutPoint]): Transaction =
  var ins: seq[TxIn]
  for o in ops:
    ins.add TxIn(prevOut: o, scriptSig: @[], sequence: 0xfffffffd'u32)
  Transaction(version: 1, inputs: ins,
              outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
              witnesses: @[], lockTime: 0)

proc fresh(): (ChainState, Mempool) =
  if dirExists(TestDbPath): removeDir(TestDbPath)
  var cs = newChainState(TestDbPath, regtestParams())
  (cs, newMempool(cs, regtestParams(), fullRbf = true))

suite "RBF rule 5 counts clusters (Core v31.1 GetEntriesForConflicts)":
  test "five clusters of 21 txs (105 evictions) are not refused by rule 5":
    var (cs, mp) = fresh()
    var conflicts = initHashSet[TxId]()
    var ops: seq[OutPoint]
    for n in 1 .. 5:
      let (root, coin) = mp.addRoot(n, 20)
      conflicts.incl(root)
      ops.add(coin)
    let res = mp.checkRbfRules(replacementFor(ops), Satoshi(1_000_000), 200, conflicts)
    if res.isOk:
      check res.value.len == 105
    else:
      check "too many potential replacements" notin res.error
      check res.isOk   # the replacement pays far more than it evicts
    cs.close()

  test "one cluster of 101 txs is not refused by rule 5":
    var (cs, mp) = fresh()
    let (root, coin) = mp.addRoot(1, 100)
    let res = mp.checkRbfRules(replacementFor(@[coin]), Satoshi(1_000_000), 200,
                               toHashSet([root]))
    if not res.isOk:
      check "too many potential replacements" notin res.error
    check res.isOk
    cs.close()

  test "101 distinct conflicted clusters are refused, message counts clusters":
    var (cs, mp) = fresh()
    var conflicts = initHashSet[TxId]()
    var ops: seq[OutPoint]
    for n in 1 .. 101:
      let (root, coin) = mp.addRoot(n, 0)
      conflicts.incl(root)
      ops.add(coin)
    let res = mp.checkRbfRules(replacementFor(ops), Satoshi(1_000_000), 200, conflicts)
    check not res.isOk
    check "too many potential replacements (101 > 100)" in res.error
    cs.close()

  test "100 distinct conflicted clusters are not refused by rule 5":
    var (cs, mp) = fresh()
    var conflicts = initHashSet[TxId]()
    var ops: seq[OutPoint]
    for n in 1 .. 100:
      let (root, coin) = mp.addRoot(n, 0)
      conflicts.incl(root)
      ops.add(coin)
    let res = mp.checkRbfRules(replacementFor(ops), Satoshi(1_000_000), 200, conflicts)
    if not res.isOk:
      check "too many potential replacements" notin res.error
    cs.close()
