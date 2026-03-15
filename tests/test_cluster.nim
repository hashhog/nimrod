## Cluster mempool tests
## Tests cluster formation, linearization, mining scores, and eviction

import unittest2
import std/[tables, sets, options, algorithm, strutils]
import ../src/mempool/cluster
import ../src/primitives/types

# Helper to create a test TxId
proc makeTxId(n: int): TxId =
  var arr: array[32, byte]
  arr[0] = byte(n and 0xff)
  arr[1] = byte((n shr 8) and 0xff)
  TxId(arr)

suite "FeeFrac operations":
  test "fee rate calculation":
    let f = FeeFrac(fee: 1000, size: 100)
    check f.feeRate() == 10.0

  test "fee rate comparison":
    let a = FeeFrac(fee: 1000, size: 100)  # 10 sat/vbyte
    let b = FeeFrac(fee: 500, size: 100)   # 5 sat/vbyte
    let c = FeeFrac(fee: 2000, size: 200)  # 10 sat/vbyte (same as a)

    check a > b
    check b < a
    check a == c
    check a >= c
    check a <= c

  test "fee frac addition":
    let a = FeeFrac(fee: 1000, size: 100)
    let b = FeeFrac(fee: 500, size: 50)
    let c = a + b

    check c.fee == 1500
    check c.size == 150

  test "fee frac subtraction":
    let a = FeeFrac(fee: 1000, size: 100)
    let b = FeeFrac(fee: 400, size: 40)
    let c = a - b

    check c.fee == 600
    check c.size == 60

suite "DepGraph basic operations":
  test "add transaction":
    var g = newDepGraph()
    let idx = g.addTransaction(FeeFrac(fee: 1000, size: 100))

    check idx == TxIndex(0)
    check g.txCount() == 1
    check idx in g.used
    check idx in g.ancestors[idx]
    check idx in g.descendants[idx]

  test "add multiple transactions":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let c = g.addTransaction(FeeFrac(fee: 2000, size: 200))

    check g.txCount() == 3
    check a in g.used
    check b in g.used
    check c in g.used

  test "add dependency":
    var g = newDepGraph()
    let parent = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let child = g.addTransaction(FeeFrac(fee: 500, size: 50))

    g.addDependency(parent, child)

    # Child should have parent as ancestor
    check parent in g.ancestors[child]
    check child in g.ancestors[child]

    # Parent should have child as descendant
    check child in g.descendants[parent]
    check parent in g.descendants[parent]

  test "transitive ancestors":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let c = g.addTransaction(FeeFrac(fee: 200, size: 20))

    # a -> b -> c (a is grandparent of c)
    g.addDependency(a, b)
    g.addDependency(b, c)

    # c should have both a and b as ancestors
    check a in g.ancestors[c]
    check b in g.ancestors[c]
    check c in g.ancestors[c]

    # a should have all as descendants
    check a in g.descendants[a]
    check b in g.descendants[a]
    check c in g.descendants[a]

suite "DepGraph fee rate calculations":
  test "single transaction fee rate":
    var g = newDepGraph()
    let idx = g.addTransaction(FeeFrac(fee: 1000, size: 100))

    var subset = initHashSet[TxIndex]()
    subset.incl(idx)
    let feerate = g.feeRate(subset)

    check feerate.fee == 1000
    check feerate.size == 100

  test "aggregate fee rate":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)
    let feerate = g.feeRate(subset)

    check feerate.fee == 1500
    check feerate.size == 150

suite "DepGraph connected components":
  test "single transaction is connected":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))

    var subset = initHashSet[TxIndex]()
    subset.incl(a)

    check g.isConnected(subset)

  test "unconnected transactions":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)

    # Two unrelated transactions are not connected
    check not g.isConnected(subset)

  test "connected via dependency":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))

    g.addDependency(a, b)

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)

    check g.isConnected(subset)

  test "find connected component":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let c = g.addTransaction(FeeFrac(fee: 200, size: 20))  # Unconnected

    g.addDependency(a, b)

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)
    subset.incl(c)

    let component = g.getConnectedComponent(subset, a)
    check a in component
    check b in component
    check c notin component

suite "DepGraph topological ordering":
  test "simple chain":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let c = g.addTransaction(FeeFrac(fee: 200, size: 20))

    g.addDependency(a, b)
    g.addDependency(b, c)

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)
    subset.incl(c)

    let topo = g.appendTopo(subset)

    # a must come before b, b must come before c
    let aPos = topo.find(a)
    let bPos = topo.find(b)
    let cPos = topo.find(c)

    check aPos < bPos
    check bPos < cPos

  test "diamond dependency":
    var g = newDepGraph()
    #     a
    #    / \
    #   b   c
    #    \ /
    #     d
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))
    let b = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let c = g.addTransaction(FeeFrac(fee: 500, size: 50))
    let d = g.addTransaction(FeeFrac(fee: 200, size: 20))

    g.addDependency(a, b)
    g.addDependency(a, c)
    g.addDependency(b, d)
    g.addDependency(c, d)

    var subset = initHashSet[TxIndex]()
    subset.incl(a)
    subset.incl(b)
    subset.incl(c)
    subset.incl(d)

    let topo = g.appendTopo(subset)

    let aPos = topo.find(a)
    let bPos = topo.find(b)
    let cPos = topo.find(c)
    let dPos = topo.find(d)

    # a must be first, d must be last
    check aPos < bPos
    check aPos < cPos
    check bPos < dPos
    check cPos < dPos

suite "Linearization algorithm":
  test "linearize single transaction":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))

    let lin = g.linearize()

    check lin.len == 1
    check lin[0] == a

  test "linearize by fee rate":
    var g = newDepGraph()
    let low = g.addTransaction(FeeFrac(fee: 100, size: 100))   # 1 sat/vbyte
    let high = g.addTransaction(FeeFrac(fee: 1000, size: 100)) # 10 sat/vbyte

    # No dependency, so they're independent
    let lin = g.linearize()

    check lin.len == 2
    # Higher fee rate should come first
    check lin[0] == high
    check lin[1] == low

  test "linearize respects dependencies":
    var g = newDepGraph()
    # Child has higher fee rate but must come after parent
    let parent = g.addTransaction(FeeFrac(fee: 100, size: 100))  # 1 sat/vbyte
    let child = g.addTransaction(FeeFrac(fee: 1000, size: 100))  # 10 sat/vbyte

    g.addDependency(parent, child)

    let lin = g.linearize()

    let parentPos = lin.find(parent)
    let childPos = lin.find(child)

    # Parent must come before child despite lower fee rate
    check parentPos < childPos

  test "CPFP chunking":
    var g = newDepGraph()
    # Classic CPFP: low-fee parent, high-fee child
    let parent = g.addTransaction(FeeFrac(fee: 100, size: 100))   # 1 sat/vbyte
    let child = g.addTransaction(FeeFrac(fee: 900, size: 100))    # 9 sat/vbyte
    # Combined: 1000/200 = 5 sat/vbyte

    g.addDependency(parent, child)

    let lin = g.linearize()
    let chunks = g.computeChunks(lin)

    # Should form a single chunk (child pulls up parent)
    check chunks.len == 1
    check chunks[0].txIndices.len == 2
    check chunks[0].feerate.fee == 1000
    check chunks[0].feerate.size == 200

suite "Chunk computation":
  test "compute chunks single tx":
    var g = newDepGraph()
    let a = g.addTransaction(FeeFrac(fee: 1000, size: 100))

    let lin = g.linearize()
    let chunks = g.computeChunks(lin)

    check chunks.len == 1
    check chunks[0].txIndices == @[a]

  test "chunks absorb higher-feerate followers":
    var g = newDepGraph()
    # Three independent transactions: high, low, medium fee rate
    let high = g.addTransaction(FeeFrac(fee: 1000, size: 100))   # 10 sat/vbyte
    let low = g.addTransaction(FeeFrac(fee: 100, size: 100))     # 1 sat/vbyte
    let med = g.addTransaction(FeeFrac(fee: 500, size: 100))     # 5 sat/vbyte

    let lin = @[high, low, med]  # Manual order for testing
    let chunks = g.computeChunks(lin)

    # high stays alone (10), low absorbs med (combined 3), so two chunks
    # Actually: high (10), then low (1), then med (5) which is > low
    # so med absorbs low, giving (low+med) = 600/200 = 3 sat/vbyte
    check chunks.len == 2
    check chunks[0].txIndices == @[high]

suite "Cluster operations":
  test "create empty cluster":
    let c = newCluster()
    check c.size == 0

  test "add transaction to cluster":
    var c = newCluster()
    let txid = makeTxId(1)
    let result = c.addTransaction(txid, 1000, 100)

    check result.isOk
    check c.size == 1
    check c.contains(txid)

  test "cluster size limit":
    var c = newCluster()
    # Add MaxClusterSize transactions
    for i in 0 ..< MaxClusterSize:
      let result = c.addTransaction(makeTxId(i), 1000, 100)
      check result.isOk

    # One more should fail
    let result = c.addTransaction(makeTxId(MaxClusterSize + 1), 1000, 100)
    check not result.isOk
    check "limit" in result.error

  test "add dependency and relinearize":
    var c = newCluster()
    let parentTxid = makeTxId(1)
    let childTxid = makeTxId(2)

    discard c.addTransaction(parentTxid, 100, 100)   # 1 sat/vbyte
    discard c.addTransaction(childTxid, 1000, 100)   # 10 sat/vbyte

    c.addDependency(parentTxid, childTxid)
    c.relinearize()

    # Parent should come before child in linearization
    let linearized = c.getLinearizedTxids()
    let parentPos = linearized.find(parentTxid)
    let childPos = linearized.find(childTxid)

    check parentPos < childPos

  test "get mining score":
    var c = newCluster()
    let parentTxid = makeTxId(1)
    let childTxid = makeTxId(2)

    discard c.addTransaction(parentTxid, 100, 100)   # 1 sat/vbyte alone
    discard c.addTransaction(childTxid, 900, 100)    # 9 sat/vbyte alone
    # Combined CPFP: 1000/200 = 5 sat/vbyte

    c.addDependency(parentTxid, childTxid)
    c.relinearize()

    # Both should have the same mining score (chunk fee rate)
    let parentScore = c.getMiningScore(parentTxid)
    let childScore = c.getMiningScore(childTxid)

    # Should be 5 sat/vbyte
    check parentScore == 5.0
    check childScore == 5.0

  test "get worst transaction":
    var c = newCluster()
    let highTxid = makeTxId(1)
    let lowTxid = makeTxId(2)

    discard c.addTransaction(highTxid, 1000, 100)  # 10 sat/vbyte
    discard c.addTransaction(lowTxid, 100, 100)    # 1 sat/vbyte

    c.relinearize()

    let worst = c.getWorstTransaction()
    check worst.isSome
    check worst.get() == lowTxid

suite "ClusterManager operations":
  test "create cluster manager":
    let cm = newClusterManager()
    check cm.clusterCount() == 0
    check cm.totalTransactionCount() == 0

  test "add standalone transaction":
    var cm = newClusterManager()
    let txid = makeTxId(1)

    let result = cm.addTransaction(txid, 1000, 100, @[])

    check result.isOk
    check cm.clusterCount() == 1
    check cm.totalTransactionCount() == 1
    check cm.getClusterIndex(txid).isSome

  test "add child to same cluster":
    var cm = newClusterManager()
    let parentTxid = makeTxId(1)
    let childTxid = makeTxId(2)

    discard cm.addTransaction(parentTxid, 1000, 100, @[])
    discard cm.addTransaction(childTxid, 500, 50, @[parentTxid])

    # Should be in same cluster
    check cm.clusterCount() == 1
    check cm.totalTransactionCount() == 2

    let parentIdx = cm.getClusterIndex(parentTxid).get()
    let childIdx = cm.getClusterIndex(childTxid).get()
    check parentIdx == childIdx

  test "merge clusters":
    var cm = newClusterManager()
    # Two independent transactions
    let tx1 = makeTxId(1)
    let tx2 = makeTxId(2)

    discard cm.addTransaction(tx1, 1000, 100, @[])
    discard cm.addTransaction(tx2, 1000, 100, @[])

    check cm.clusterCount() == 2

    # Add a child that depends on both
    let childTxid = makeTxId(3)
    discard cm.addTransaction(childTxid, 500, 50, @[tx1, tx2])

    # Now all should be in one cluster
    check cm.clusterCount() == 1
    check cm.totalTransactionCount() == 3

  test "get mining score from manager":
    var cm = newClusterManager()
    let parentTxid = makeTxId(1)
    let childTxid = makeTxId(2)

    discard cm.addTransaction(parentTxid, 100, 100, @[])
    discard cm.addTransaction(childTxid, 900, 100, @[parentTxid])

    let parentScore = cm.getMiningScore(parentTxid)
    let childScore = cm.getMiningScore(childTxid)

    # Both in same chunk with 5 sat/vbyte
    check parentScore == 5.0
    check childScore == 5.0

  test "get worst transaction from manager":
    var cm = newClusterManager()
    let highTxid = makeTxId(1)
    let lowTxid = makeTxId(2)

    discard cm.addTransaction(highTxid, 1000, 100, @[])  # 10 sat/vbyte
    discard cm.addTransaction(lowTxid, 100, 100, @[])    # 1 sat/vbyte

    let worst = cm.getWorstTransaction()
    check worst.isSome
    check worst.get()[0] == lowTxid
    check worst.get()[1] == 1.0

  test "remove transaction":
    var cm = newClusterManager()
    let txid = makeTxId(1)

    discard cm.addTransaction(txid, 1000, 100, @[])
    check cm.totalTransactionCount() == 1

    cm.removeTransaction(txid)
    check cm.totalTransactionCount() == 0
    check cm.getClusterIndex(txid).isNone

  test "select transactions for block":
    var cm = newClusterManager()
    let tx1 = makeTxId(1)
    let tx2 = makeTxId(2)
    let tx3 = makeTxId(3)

    discard cm.addTransaction(tx1, 1000, 100, @[])  # 10 sat/vbyte
    discard cm.addTransaction(tx2, 500, 100, @[])   # 5 sat/vbyte
    discard cm.addTransaction(tx3, 100, 100, @[])   # 1 sat/vbyte

    let selected = cm.selectTransactionsForBlock(400_000)

    check selected.len == 3
    # Should be ordered by mining score (highest first)
    check selected[0][0] == tx1
    check selected[0][1] == 10.0
    check selected[1][0] == tx2
    check selected[1][1] == 5.0
    check selected[2][0] == tx3
    check selected[2][1] == 1.0

suite "Mining score edge cases":
  test "long chain CPFP":
    var c = newCluster()
    # Long chain: each tx has 100 fee, 100 vsize (1 sat/vbyte each)
    # Last tx has high fee to pay for all
    let n = 10
    var txids: seq[TxId]

    for i in 0 ..< n - 1:
      let txid = makeTxId(i)
      txids.add(txid)
      discard c.addTransaction(txid, 100, 100)

    # High-fee child that pays for all
    let childTxid = makeTxId(n)
    txids.add(childTxid)
    discard c.addTransaction(childTxid, 10000, 100)

    # Chain dependencies
    for i in 1 ..< n:
      c.addDependency(txids[i - 1], txids[i])

    c.relinearize()

    # Total: 900 (9 * 100) + 10000 = 10900 fee, 1000 vsize
    # Expected chunk fee rate: 10.9 sat/vbyte
    let score = c.getMiningScore(txids[0])
    check score > 10.0
    check score < 11.0

  test "parallel chains":
    var cm = newClusterManager()
    # Two parallel chains that don't interact
    # Chain A: low-fee parent, high-fee child (CPFP)
    # Chain B: low-fee parent, high-fee child (CPFP)
    let a1 = makeTxId(1)
    let a2 = makeTxId(2)
    let b1 = makeTxId(3)
    let b2 = makeTxId(4)

    discard cm.addTransaction(a1, 100, 100, @[])    # 1 sat/vbyte
    discard cm.addTransaction(a2, 1400, 100, @[a1]) # 14 sat/vbyte (CPFP)
    discard cm.addTransaction(b1, 200, 100, @[])    # 2 sat/vbyte
    discard cm.addTransaction(b2, 2800, 100, @[b1]) # 28 sat/vbyte (CPFP)

    # Should be two separate clusters
    check cm.clusterCount() == 2

    # Check scores are independent
    let a1Score = cm.getMiningScore(a1)
    let b1Score = cm.getMiningScore(b1)

    # a chain: (100+1400)/(100+100) = 1500/200 = 7.5 sat/vbyte
    # b chain: (200+2800)/(100+100) = 3000/200 = 15 sat/vbyte
    check a1Score > 7.0
    check a1Score < 8.0
    check b1Score > 14.0
    check b1Score < 16.0
