## RBF conflict expansion must not scan the whole mempool per descendant.
##
## Core v31.1 policy/rbf.cpp GetEntriesForConflicts() calls
## pool.CalculateDescendants(it, all_conflicts) once per direct conflict with one
## shared set; CalculateDescendants (txmempool.cpp) walks children through the
## mempool graph, so the work is O(evicted set).  nimrod's
## getAllConflictsWithDescendants called calculateDescendants per conflict, and
## that rescanned every pool entry per BFS step: conflicts x descendants x pool,
## paid before Rules 2/3/4 and before any script check, so by a replacement that
## never pays for itself.
##
## Fixture: 4 chains x 16 conflicts.  Each chain is 16 txs; tx i spends its own
## outside coin (so all 64 are direct conflicts of a replacement spending those
## 64 coins) and, for i > 0, tx i-1's output.  Every conflict therefore has up to
## 15 in-pool descendants.  Filler: unrelated single-input txs.
##
## Command:  nim c -r tests/test_cffix_rbf_descendants_index.nim

import unittest2
import std/[os, times, sets, tables, monotimes]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_cffix_rbf_descendants_index_test"
const Chains = 4
const ChainLen = 16

proc tid(a, b, c: byte): TxId =
  var arr: array[32, byte]
  arr[0] = a
  arr[1] = b
  arr[2] = c
  TxId(arr)

proc coin(a, b, c: byte): OutPoint =
  var arr: array[32, byte]
  arr[0] = 0xEE
  arr[1] = a
  arr[2] = b
  arr[3] = c
  OutPoint(txid: TxId(arr), vout: 0)

proc addEntry(mp: var Mempool, id: TxId, prevs: seq[OutPoint]) =
  var ins: seq[TxIn]
  for p in prevs:
    ins.add TxIn(prevOut: p, scriptSig: @[], sequence: 0xfffffffd'u32)
  let tx = Transaction(
    version: 2, inputs: ins,
    outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)
  mp.entries[id] = MempoolEntry(
    tx: tx, txid: id, fee: Satoshi(10), weight: 400, feeRate: 1.0,
    timeAdded: getTime(), height: 100, ancestorFee: Satoshi(10),
    ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
  for p in prevs:
    mp.spentBy[p] = id

proc fresh(tag: string): (ChainState, Mempool) =
  ## One RocksDB dir per chainstate: two open on one path collide on LOCK.
  let path = TestDbPath & "_" & tag
  if dirExists(path): removeDir(path)
  var cs = newChainState(path, regtestParams())
  (cs, newMempool(cs, regtestParams(), fullRbf = true))

proc build(mp: var Mempool, filler: int): (HashSet[TxId], seq[OutPoint]) =
  ## Returns (direct conflicts, coins the replacement spends).
  var conflicts = initHashSet[TxId]()
  var coins: seq[OutPoint]
  for c in 0 ..< Chains:
    for i in 0 ..< ChainLen:
      let id = tid(0x01, byte(c), byte(i))
      let own = coin(0x01, byte(c), byte(i))
      var prevs = @[own]
      if i > 0:
        prevs.add OutPoint(txid: tid(0x01, byte(c), byte(i - 1)), vout: 0)
      mp.addEntry(id, prevs)
      conflicts.incl(id)
      coins.add(own)
  for f in 0 ..< filler:
    mp.addEntry(tid(0x02, byte(f shr 8), byte(f and 0xff)),
                @[coin(0x02, byte(f shr 8), byte(f and 0xff))])
  (conflicts, coins)

proc oldExpansion(mp: Mempool, conflicts: HashSet[TxId]): HashSet[TxId] =
  ## The pre-fix result: each conflict plus calculateDescendants of it.
  result = initHashSet[TxId]()
  for c in conflicts:
    result.incl(c)
    for d in mp.calculateDescendants(c):
      result.incl(d)

proc expectedSet(): HashSet[TxId] =
  result = initHashSet[TxId]()
  for c in 0 ..< Chains:
    for i in 0 ..< ChainLen:
      result.incl(tid(0x01, byte(c), byte(i)))

proc replacementFor(ops: seq[OutPoint]): Transaction =
  var ins: seq[TxIn]
  for o in ops:
    ins.add TxIn(prevOut: o, scriptSig: @[], sequence: 0xfffffffd'u32)
  Transaction(version: 2, inputs: ins,
              outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
              witnesses: @[], lockTime: 0)

suite "cffix RBF conflict expansion walks spentBy (Core CalculateDescendants)":
  test "RBF conflict expansion work is independent of unrelated mempool entries":
    var (cs0, mp0) = fresh("t1")
    let (conf0, _) = mp0.build(0)
    var (cs1, mp1) = fresh("t2")
    let (conf1, _) = mp1.build(1000)
    check mp0.entries.len == Chains * ChainLen
    check mp1.entries.len == Chains * ChainLen + 1000
    when declared(mempoolScanSteps):
      mempoolScanSteps = 0
      discard mp0.getAllConflictsWithDescendants(conf0)
      let steps0 = mempoolScanSteps
      mempoolScanSteps = 0
      discard mp1.getAllConflictsWithDescendants(conf1)
      let steps1 = mempoolScanSteps
      echo "    entries examined: filler 0 -> " & $steps0 &
                 ", filler 1000 -> " & $steps1
      check steps1 == steps0
      # Linear in the evicted set: each of the 64 txs is walked once.
      check steps0 <= 2 * Chains * ChainLen
    else:
      # Master has no step counter; measure the same property by time.  The
      # pre-fix cost is proportional to pool size: 544 full scans over 64 vs
      # 1064 entries, a ~16x ratio.  Best of 5 to drop scheduler noise.
      proc best(mp: Mempool, conf: HashSet[TxId]): int64 =
        result = int64.high
        for _ in 0 ..< 5:
          let t0 = getMonoTime()
          discard mp.getAllConflictsWithDescendants(conf)
          result = min(result, (getMonoTime() - t0).inNanoseconds)
      let t0 = best(mp0, conf0)
      let t1 = best(mp1, conf1)
      echo "    best ns: filler 0 -> " & $t0 & ", filler 1000 -> " & $t1
      check t1 < 4 * max(t0, 1)
    cs0.close()
    cs1.close()

  test "the evicted set is identical to the pre-fix expansion":
    for filler in [0, 1000]:
      var (cs, mp) = fresh("t3")
      let (conf, _) = mp.build(filler)
      let got = mp.getAllConflictsWithDescendants(conf)
      check got == expectedSet()
      check got == mp.oldExpansion(conf)
      cs.close()

  test "one root conflict still evicts every descendant, filler excluded":
    var (cs, mp) = fresh("t4")
    discard mp.build(1000)
    # Only the first tx of each chain is a direct conflict: its 15 descendants
    # must come in through the spentBy walk.
    var roots = initHashSet[TxId]()
    for c in 0 ..< Chains:
      roots.incl(tid(0x01, byte(c), 0))
    let got = mp.getAllConflictsWithDescendants(roots)
    check got == expectedSet()
    check got == mp.oldExpansion(roots)
    cs.close()

  test "a diamond descendant shared by two conflicts is evicted once":
    var (cs, mp) = fresh("t5")
    let a = tid(0x03, 0, 1)
    let b = tid(0x03, 0, 2)
    let d = tid(0x03, 0, 3)
    let e = tid(0x03, 0, 4)
    mp.addEntry(a, @[coin(0x03, 0, 1)])
    mp.addEntry(b, @[coin(0x03, 0, 2)])
    mp.addEntry(d, @[OutPoint(txid: a, vout: 0), OutPoint(txid: b, vout: 0)])
    mp.addEntry(e, @[OutPoint(txid: d, vout: 0)])
    discard mp.build(100)
    let conf = toHashSet([a, b])
    let got = mp.getAllConflictsWithDescendants(conf)
    check got == toHashSet([a, b, d, e])
    check got == mp.oldExpansion(conf)
    cs.close()

  test "checkRbfRules returns the full evicted set with 1000 filler entries":
    var (cs, mp) = fresh("t6")
    let (conf, coins) = mp.build(1000)
    let res = mp.checkRbfRules(replacementFor(coins), Satoshi(1_000_000), 200, conf)
    check res.isOk
    if res.isOk:
      check res.value == expectedSet()
    cs.close()
