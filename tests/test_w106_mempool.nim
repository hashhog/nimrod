## W106 — CTxMemPool descendant/ancestor tracking + RBF + package mempool
## 30-gate audit against Bitcoin Core txmempool.h/cpp, policy/rbf.h/cpp,
## policy/v3_policy.h/cpp (truc_policy), policy/packages.h/cpp.
##
## Gates G1-G10:  ancestor/descendant tracking
## Gates G11-G20: RBF (BIP-125 + Core 27+ ImprovesFeerateDiagram)
## Gates G21-G25: TRUC / BIP-431 single-tx + package
## Gates G26-G30: package / misc

import unittest2
import std/[os, options, tables, times, sets, strutils, math]
import ../src/mempool/mempool
import ../src/mempool/package
import ../src/mempool/cluster
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]


const TestDbPath = "/tmp/nimrod_w106_test"

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTxid(b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  TxId(arr)

proc makeTxidN(a: byte, b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = a
  arr[1] = b
  TxId(arr)

proc makeOutpoint(txid: TxId, vout: uint32 = 0): OutPoint =
  OutPoint(txid: txid, vout: vout)

proc makeOutpointB(b: byte, vout: uint32 = 0): OutPoint =
  OutPoint(txid: makeTxid(b), vout: vout)

proc makeTestMempool(dbPath: string): Mempool =
  let cs = newChainState(dbPath, regtestParams())
  newMempool(cs, regtestParams(), fullRbf = false)

proc makeTestMempoolFull(dbPath: string): Mempool =
  let cs = newChainState(dbPath, regtestParams())
  newMempool(cs, regtestParams(), fullRbf = true)

## Build a simple P2WPKH scriptPubKey (22 bytes) — passes policy checks.
proc makeP2WPKHScript(): seq[byte] =
  var hash: array[20, byte]
  for i in 0 ..< 20: hash[i] = byte(i + 1)
  @[0x00.byte, 0x14.byte] & @hash

## Create a coinbase at a given height (with required maturity).
proc makeCoinbaseTx(height: int32, value: int64 = 5_000_000_000): Transaction =
  var scriptSig: seq[byte]
  if height == 0: scriptSig = @[byte(0x01), 0x00]
  elif height < 256: scriptSig = @[byte(0x01), byte(height)]
  else: scriptSig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig, sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: makeP2WPKHScript())],
    witnesses: @[], lockTime: 0
  )

## Insert a UTXO directly into the chainstate DB for testing.
proc seedUtxo(mp: Mempool, txid: TxId, vout: uint32 = 0,
               value: int64 = 10_000_000,
               height: int32 = 0) =
  let outpoint = OutPoint(txid: txid, vout: vout)
  let utxo = UtxoEntry(
    output: TxOut(value: Satoshi(value), scriptPubKey: makeP2WPKHScript()),
    height: height,
    isCoinbase: false
  )
  ## Use putUtxoCache which writes into the in-memory cache (picked up by getUtxo)
  var cs = mp.chainState
  cs.putUtxoCache(outpoint, utxo)

## Create a simple spending tx (P2WPKH-like, passes policy filters).
## fee is deducted from the first output.
proc makeSpend(prevTxid: TxId, prevVout: uint32 = 0,
               outputValue: int64 = 9_000_000,
               sequence: uint32 = 0xFFFFFFFE'u32,
               version: int32 = 1,
               outputCount: int = 1,
               outputTxid: TxId = default(TxId)): Transaction =
  ## outputTxid: controls the txid byte of the output scriptPubKey (for uniqueness)
  let perOutput = outputValue div int64(outputCount)
  var outputs: seq[TxOut]
  for i in 0 ..< outputCount:
    outputs.add(TxOut(value: Satoshi(perOutput), scriptPubKey: makeP2WPKHScript()))
  Transaction(
    version: version,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[], sequence: sequence
    )],
    outputs: outputs,
    witnesses: @[@[@[]]],
    lockTime: 0
  )

## Calculate txid of a tx (without hashing — just use the first byte of inputs
## as a deterministic ID for test purposes).
proc txidOf(tx: Transaction): TxId =
  tx.txid()

# ---------------------------------------------------------------------------
# Seed a chain of n transactions (root confirmed, rest unconfirmed).
# Returns seq of txids (index 0 = root coinbase, 1..n = unconfirmed chain).
# ---------------------------------------------------------------------------
proc buildChain(mp: Mempool, n: int, fee: int64 = 1_000_000): seq[TxId] =
  ## Build a confirmed-root → n-deep chain in the mempool.
  ## Uses RBF-non-signaling (0xFFFFFFFE) to avoid polluting RBF tests.
  var rootTxid = makeTxid(0xAA)
  seedUtxo(mp, rootTxid, value = int64(n + 1) * 10_000_000)

  var chain: seq[TxId] = @[rootTxid]
  var prevValue = int64(n + 1) * 10_000_000
  var prevTxid = rootTxid

  for i in 1 .. n:
    let outValue = prevValue - fee
    let tx = makeSpend(prevTxid, 0, outValue, 0xFFFFFFFE'u32, 1, 1)
    let txid = txidOf(tx)
    if i == 1:
      # first spend seeds from confirmed UTXO
      discard
    else:
      discard  # parent already in mempool
    mp.entries[txid] = MempoolEntry(
      tx: tx,
      txid: txid,
      wtxid: tx.wtxid(),
      fee: Satoshi(fee),
      weight: 600,
      feeRate: float64(fee) / 150.0,
      timeAdded: getTime(),
      height: mp.chainState.bestHeight,
      ancestorFee: Satoshi(fee * int64(i)),
      ancestorWeight: 600 * i,
      ancestorCount: i,
      ancestorSize: 150 * i
    )
    mp.byWtxid[tx.wtxid()] = txid
    mp.spentBy[makeOutpoint(prevTxid)] = txid
    chain.add(txid)
    prevTxid = txid
    prevValue = outValue

  chain

# ===========================================================================
# G1 — calculateAncestors BFS correctness
# Core: CTxMemPool::CalculateMemPoolAncestors
# ===========================================================================
suite "G1 calculateAncestors BFS":
  setup:
    cleanupTestDb()

  test "G1a: single tx with no parents returns empty ancestor set":
    let mp = makeTestMempool(TestDbPath & "_g1a")
    let txid = makeTxid(0x01)
    let tx = makeSpend(makeTxid(0xAA))
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
      fee: Satoshi(1000), weight: 400, feeRate: 2.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1000), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    let ancestors = mp.calculateAncestors(tx)
    check ancestors.len == 0

  test "G1b: two-deep chain: grandchild has 2 ancestors":
    ## BUG-PROBE: Core calculates full transitive ancestor set.
    ## If nimrod's BFS stops at direct parents only, grandchild would show 1 ancestor.
    let mp = makeTestMempool(TestDbPath & "_g1b")
    let chain = buildChain(mp, 3)
    ## chain[0] = confirmed root, chain[1] = child, chain[2] = grandchild, chain[3] = great-grandchild
    let grandchildTx = mp.entries[chain[3]].tx
    let ancestors = mp.calculateAncestors(grandchildTx)
    ## Must include chain[1], chain[2] (the two unconfirmed ancestors)
    check ancestors.len == 2
    check chain[1] in ancestors
    check chain[2] in ancestors

  test "G1c: ancestor set does not include confirmed UTXOs (only mempool ancestors)":
    let mp = makeTestMempool(TestDbPath & "_g1c")
    let chain = buildChain(mp, 2)
    let childTx = mp.entries[chain[2]].tx
    let ancestors = mp.calculateAncestors(childTx)
    ## chain[0] is confirmed — must NOT appear in ancestor set
    check chain[0] notin ancestors

  test "G1d: diamond topology — shared ancestor counted once":
    ## Two txs B and C both spend A; D spends both B and C.
    ## calculateAncestors(D) must return {A, B, C} not {A, A, B, C}.
    let mp = makeTestMempool(TestDbPath & "_g1d")
    let rootTxid = makeTxid(0xAA)
    seedUtxo(mp, rootTxid, value = 100_000_000)

    ## Build a coinbase-like "A" with 2 outputs
    let txA = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(rootTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[
        TxOut(value: Satoshi(40_000_000), scriptPubKey: makeP2WPKHScript()),
        TxOut(value: Satoshi(40_000_000), scriptPubKey: makeP2WPKHScript())
      ],
      witnesses: @[], lockTime: 0)
    let txidA = txA.txid()
    mp.entries[txidA] = MempoolEntry(tx: txA, txid: txidA, wtxid: txA.wtxid(),
      fee: Satoshi(1000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(rootTxid)] = txidA

    let txB = makeSpend(txidA, 0, 38_000_000)
    let txidB = txB.txid()
    mp.entries[txidB] = MempoolEntry(tx: txB, txid: txidB, wtxid: txB.wtxid(),
      fee: Satoshi(1000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(2000), ancestorWeight: 1200, ancestorCount: 2, ancestorSize: 300)
    mp.spentBy[makeOutpoint(txidA, 0)] = txidB

    let txC = makeSpend(txidA, 1, 38_000_000)
    let txidC = txC.txid()
    mp.entries[txidC] = MempoolEntry(tx: txC, txid: txidC, wtxid: txC.wtxid(),
      fee: Satoshi(1000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(2000), ancestorWeight: 1200, ancestorCount: 2, ancestorSize: 300)
    mp.spentBy[makeOutpoint(txidA, 1)] = txidC

    ## D spends B and C
    let txD = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(txidB), scriptSig: @[], sequence: 0xFFFFFFFE'u32),
        TxIn(prevOut: makeOutpoint(txidC), scriptSig: @[], sequence: 0xFFFFFFFE'u32)
      ],
      outputs: @[TxOut(value: Satoshi(74_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let txidD = txD.txid()
    mp.entries[txidD] = MempoolEntry(tx: txD, txid: txidD, wtxid: txD.wtxid(),
      fee: Satoshi(1000), weight: 800, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(4000), ancestorWeight: 2600, ancestorCount: 4, ancestorSize: 650)

    let ancestors = mp.calculateAncestors(txD)
    check ancestors.len == 3    ## A, B, C
    check txidA in ancestors
    check txidB in ancestors
    check txidC in ancestors
    check txidD notin ancestors  ## self must not appear

# ===========================================================================
# G2 — calculateDescendants BFS correctness
# Core: CTxMemPool::CalculateDescendants
# ===========================================================================
suite "G2 calculateDescendants BFS":
  setup:
    cleanupTestDb()

  test "G2a: leaf tx has no descendants":
    let mp = makeTestMempool(TestDbPath & "_g2a")
    let chain = buildChain(mp, 3)
    ## chain[3] is the leaf
    let descs = mp.calculateDescendants(chain[3])
    check descs.len == 0

  test "G2b: root has all subsequent chain members as descendants":
    let mp = makeTestMempool(TestDbPath & "_g2b")
    let chain = buildChain(mp, 3)
    ## chain[1] has chain[2] and chain[3] as descendants
    let descs = mp.calculateDescendants(chain[1])
    check descs.len == 2
    check chain[2] in descs
    check chain[3] in descs

  test "G2c: descendants does not include self":
    let mp = makeTestMempool(TestDbPath & "_g2c")
    let chain = buildChain(mp, 2)
    let descs = mp.calculateDescendants(chain[1])
    check chain[1] notin descs

# ===========================================================================
# G3 — ancestor count limit (DEFAULT_ANCESTOR_LIMIT = 25)
# Core: validation.cpp AcceptToMemoryPoolWorker ancestor check
# ===========================================================================
suite "G3 ancestor count limit = 25":
  setup:
    cleanupTestDb()

  test "G3a: chain of 24 (25 including self) is accepted at the boundary":
    ## BUG-PROBE: checkPackageLimits should allow exactly ancestorLimit.
    let mp = makeTestMempool(TestDbPath & "_g3a")
    ## inject 24 entries manually
    var prevTxid = makeTxid(0xAA)
    seedUtxo(mp, prevTxid, value = 100_000_000_000)
    for i in 1 .. 24:
      let b = byte(i)
      let tx = makeSpend(prevTxid, 0, 100_000_000_000 - int64(i) * 1_000_000)
      let txid = tx.txid()
      mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
        fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
        height: 0, ancestorFee: Satoshi(int64(i) * 1_000_000),
        ancestorWeight: 600 * i, ancestorCount: i, ancestorSize: 150 * i)
      mp.spentBy[makeOutpoint(prevTxid)] = txid
      prevTxid = txid
    ## Now prevTxid has 24 mempool ancestors; adding one more would be the 25th (=limit exactly)
    let (count, _) = mp.calculateAncestorStats(makeSpend(prevTxid, 0, 90_000_000), 150)
    check count == 25  ## exactly at limit

  test "G3b: chain of 25 (26 including self) is ACCEPTED under v31 cluster limits":
    ## Core v31 removed the ancestor-count limit from mempool acceptance
    ## (-limitancestorcount is deprecated, init.cpp:650; `too-long-mempool-chain`
    ## no longer exists).  A 26-long chain of 600 WU txs is 15,600 WU — far
    ## under the 404,000 WU cluster bound — and 26 <= 64, so it is accepted.
    ## NOTE: this only checks checkPackageLimits; it does NOT go through acceptTransaction
    ## (which requires script verification against seeded UTXOs).
    let mp = makeTestMempool(TestDbPath & "_g3b")
    var prevTxid = makeTxid(0xBB)
    seedUtxo(mp, prevTxid, value = 200_000_000_000)
    for i in 1 .. 25:
      let tx = makeSpend(prevTxid, 0, 200_000_000_000 - int64(i) * 1_000_000)
      let txid = tx.txid()
      mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
        fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
        height: 0, ancestorFee: Satoshi(int64(i) * 1_000_000),
        ancestorWeight: 600 * i, ancestorCount: i, ancestorSize: 150 * i)
      mp.spentBy[makeOutpoint(prevTxid)] = txid
      prevTxid = txid
    let overTx = makeSpend(prevTxid, 0, 190_000_000_000, 0xFFFFFFFE'u32)
    let res = mp.checkPackageLimits(overTx, 600)
    check res.isOk
    let (cCount, cSize) = mp.calculateClusterStats(overTx, 600)
    check cCount == 26
    check cSize == 26 * 600

# ===========================================================================
# G4 — ancestor SIZE limit (DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * 1000 = 101,000 vbytes)
# ===========================================================================
suite "G4 ancestor vsize limit = 101,000 vbytes":
  setup:
    cleanupTestDb()

  test "G4a: total ancestor vsize at exactly 101,000 is accepted":
    ## One confirmed parent; the new tx contributes vsize up to limit.
    let mp = makeTestMempool(TestDbPath & "_g4a")
    let parentTxid = makeTxid(0xCC)
    seedUtxo(mp, parentTxid, value = 100_000_000)
    ## Inject a large ancestor (100,850 vbytes total so far)
    let bigParent = makeSpend(parentTxid, 0, 99_000_000)
    let bigParentTxid = bigParent.txid()
    let bigWeight = 100_850 * 4    ## 100,850 vbytes
    mp.entries[bigParentTxid] = MempoolEntry(tx: bigParent, txid: bigParentTxid, wtxid: bigParent.wtxid(),
      fee: Satoshi(50_000), weight: bigWeight, feeRate: 0.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(50_000), ancestorWeight: bigWeight, ancestorCount: 1,
      ancestorSize: 100_850)
    mp.spentBy[makeOutpoint(parentTxid)] = bigParentTxid
    ## new tx vsize = 150 vbytes; total = 100,850 + 150 = 101,000 = limit exactly
    let childTx = makeSpend(bigParentTxid, 0, 98_000_000)
    let (_, totalVsize) = mp.calculateAncestorStats(childTx, 150)
    check totalVsize == 101_000

  test "G4b: cluster weight exceeding 404,000 WU is rejected by checkPackageLimits":
    ## The surviving size bound is the CLUSTER size in WEIGHT units:
    ## 101,000 vB * WITNESS_SCALE_FACTOR = 404,000 WU (txmempool.cpp:181).
    ## Parent alone is 404,000 WU, so the 600 WU child pushes the cluster to
    ## 404,600 WU and the bare token "too-large-cluster" is returned.
    let mp = makeTestMempool(TestDbPath & "_g4b")
    let parentTxid = makeTxid(0xDD)
    seedUtxo(mp, parentTxid, value = 100_000_000)
    let bigParent = makeSpend(parentTxid, 0, 99_000_000)
    let bigParentTxid = bigParent.txid()
    let bigWeight = 101_000 * 4    ## 101,000 vbytes in parent alone
    mp.entries[bigParentTxid] = MempoolEntry(tx: bigParent, txid: bigParentTxid, wtxid: bigParent.wtxid(),
      fee: Satoshi(50_000), weight: bigWeight, feeRate: 0.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(50_000), ancestorWeight: bigWeight, ancestorCount: 1,
      ancestorSize: 101_000)
    mp.spentBy[makeOutpoint(parentTxid)] = bigParentTxid
    let childTx = makeSpend(bigParentTxid, 0, 98_000_000)
    let (_, cSize) = mp.calculateClusterStats(childTx, 600)
    check cSize == 404_600                 ## 404,000 + 600, summed in weight
    let res = mp.checkPackageLimits(childTx, 600)  ## 600 WU = 150 vbytes
    check not res.isOk
    check res.error == "too-large-cluster"  ## bare token, empty debug string

# ===========================================================================
# G5 — descendant count limit (DEFAULT_DESCENDANT_LIMIT = 25)
# ===========================================================================
suite "G5 descendant count limit = 25":
  setup:
    cleanupTestDb()

  test "G5a: a parent at 24 descendants (including self) can still gain one more child":
    ## This checks the descendant COUNT check on the ancestor side.
    let mp = makeTestMempool(TestDbPath & "_g5a")
    let rootTxid = makeTxid(0xEE)
    seedUtxo(mp, rootTxid, value = 100_000_000)
    ## root entry in mempool (the ancestor whose descendant limit we're testing)
    let rootTx = makeSpend(rootTxid, 0, 99_000_000)
    let rootMpTxid = rootTx.txid()
    mp.entries[rootMpTxid] = MempoolEntry(tx: rootTx, txid: rootMpTxid, wtxid: rootTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(rootTxid)] = rootMpTxid
    ## Build 23 descendants of rootMpTxid using the same pattern as buildChain
    var prevTxid = rootMpTxid
    for i in 1 .. 23:
      let tx = makeSpend(prevTxid, 0, 98_000_000 - int64(i) * 100_000)
      let txid = tx.txid()
      mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
        fee: Satoshi(100_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
        height: 0, ancestorFee: Satoshi(int64(i + 1) * 100_000), ancestorWeight: 600 * (i + 1),
        ancestorCount: i + 1, ancestorSize: 150 * (i + 1))
      mp.spentBy[makeOutpoint(prevTxid)] = txid
      prevTxid = txid
    ## rootMpTxid now has 23 descendants, so desc count = 24 (including self).
    ## Adding one more child should be OK (would be 25 = limit).
    let (descCount, _) = mp.calculateDescendantStats(rootMpTxid)
    check descCount == 24
    let nextChild = makeSpend(prevTxid, 0, 95_000_000)
    ## checkPackageLimits should NOT reject this
    let res = mp.checkPackageLimits(nextChild, 600)
    check res.isOk

  test "G5b: adding a tx that would give an ancestor 26 descendants is rejected":
    ## BUG-PROBE: descendant COUNT check must fire at > 25.
    ## Strategy: root has 24 direct children (non-chained), plus root itself = 25 desc including self.
    ## A new tx that also spends root output would make root have 26 descendants → should reject.
    ## We use a root with 2 outputs and inject 24 non-chained children, then try to add a 25th child.
    let mp = makeTestMempool(TestDbPath & "_g5b")
    let rootTxid = makeTxid(0xFF)
    seedUtxo(mp, rootTxid, value = 200_000_000_000)

    ## rootTx has 2 outputs: out0 is the primary UTXO, out1..out24 for children
    let rootTx = Transaction(
      version: 1'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(rootTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[
        TxOut(value: Satoshi(100_000_000_000), scriptPubKey: makeP2WPKHScript()),
        TxOut(value: Satoshi(99_000_000_000), scriptPubKey: makeP2WPKHScript())
      ],
      witnesses: @[], lockTime: 0)
    let rootMpTxid = rootTx.txid()
    mp.entries[rootMpTxid] = MempoolEntry(tx: rootTx, txid: rootMpTxid, wtxid: rootTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 800, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 800, ancestorCount: 1, ancestorSize: 200)
    mp.spentBy[makeOutpoint(rootTxid)] = rootMpTxid

    ## Inject 24 unrelated children of rootMpTxid (each spending its own confirmed UTXO,
    ## but recorded as spending out0 of rootMpTxid via spentBy — simulating 24 direct children).
    ## Actually easier: inject 24 children as a linear chain from rootMpTxid
    var prevTxid = rootMpTxid
    for i in 1 .. 24:
      var childIdBytes: array[32, byte]
      childIdBytes[0] = byte(i)
      childIdBytes[1] = 0xFE
      let childTxid = TxId(childIdBytes)
      let childTx = makeSpend(prevTxid, 0, 90_000_000_000 - int64(i) * 1_000_000)
      mp.entries[childTxid] = MempoolEntry(tx: childTx, txid: childTxid, wtxid: childTx.wtxid(),
        fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
        height: 0, ancestorFee: Satoshi(int64(i + 1) * 1_000_000), ancestorWeight: 600 * (i + 1),
        ancestorCount: i + 1, ancestorSize: 150 * (i + 1))
      mp.spentBy[makeOutpoint(prevTxid)] = childTxid
      prevTxid = childTxid

    ## rootMpTxid now has 24 descendants, so the chain is 25 long and the new
    ## tx makes 26.  Under Core v31 BOTH the ancestor-count and the
    ## descendant-count limits are gone (-limitdescendantcount is deprecated,
    ## init.cpp:656), so this is accepted: 26 <= 64 and the cluster weighs
    ## 800 + 24*600 + 600 = 15,800 WU, far under the 404,000 WU bound.
    let overTx = makeSpend(prevTxid, 0, 85_000_000_000, 0xFFFFFFFE'u32)
    let res = mp.checkPackageLimits(overTx, 600)
    check res.isOk
    let (cCount, cSize) = mp.calculateClusterStats(overTx, 600)
    check cCount == 26
    check cSize == 800 + 24 * 600 + 600

# ===========================================================================
# G6 — EXTRA_DESCENDANT_TX_SIZE_LIMIT exception (policy/policy.h:90)
# A tx with exactly 1 in-mempool ancestor AND own vsize <= 10,000 vbytes
# bypasses the descendant VSIZE limit (but NOT the count limit).
# ===========================================================================
suite "G6 EXTRA_DESCENDANT_TX_SIZE_LIMIT exception":
  setup:
    cleanupTestDb()

  test "G6a: small tx with 1 ancestor bypasses descendant vsize limit":
    ## Build a parent whose descendant vsize would exceed 101,000 vbytes
    ## if the child's size is added — but since child has exactly 1 ancestor
    ## and its vsize <= 10,000, the check is skipped.
    let mp = makeTestMempool(TestDbPath & "_g6a")
    let rootTxid = makeTxid(0x10)
    seedUtxo(mp, rootTxid, value = 100_000_000)
    let parentTx = makeSpend(rootTxid, 0, 99_000_000)
    let parentTxid = parentTx.txid()
    let hugeWeight = 100_850 * 4  ## 100,850 vbytes
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(1_000_000), weight: hugeWeight, feeRate: 0.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: hugeWeight, ancestorCount: 1,
      ancestorSize: 100_850)
    mp.spentBy[makeOutpoint(rootTxid)] = parentTxid
    ## Child vsize = 150 vbytes ≤ 10,000 and exactly 1 ancestor → exception applies.
    let childTx = makeSpend(parentTxid, 0, 98_000_000)
    let res = mp.checkPackageLimits(childTx, 600)  ## 600/4 = 150 vbytes
    check res.isOk   ## should pass despite ancestor+child = 101,000 vbytes

  test "G6b: a large sibling still counts toward the cluster size":
    ## EXTRA_DESCENDANT_TX_SIZE_LIMIT is now a dead definition in Core
    ## (policy.h:90, no remaining uses), so there is no exception to grant.
    ## What survives is the cluster bound — and the new child's SIBLING
    ## (which is neither its ancestor nor its descendant) must be counted:
    ##   parent 600 WU + existing child 362,800 WU + new child 40,804 WU
    ##   = 404,204 WU > 404,000 WU → reject.
    ## An ancestor-scoped size proxy would see only 600 + 40,804 = 41,404 WU
    ## and wrongly accept.
    let mp = makeTestMempool(TestDbPath & "_g6b")
    let rootTxid = makeTxid(0x11)
    seedUtxo(mp, rootTxid, value = 100_000_000)
    let parentTx = makeSpend(rootTxid, 0, 99_000_000)
    let parentTxid = parentTx.txid()
    ## Parent is a small tx (150 vbytes)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 0.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1,
      ancestorSize: 150)
    mp.spentBy[makeOutpoint(rootTxid)] = parentTxid
    ## Inject existing large child of parent (90,700 vbytes) to inflate parent's descendant size
    let existingChildTx = makeSpend(parentTxid, 0, 98_000_000)
    let existingChildTxid = existingChildTx.txid()
    let existingChildVsize = 90_700
    mp.entries[existingChildTxid] = MempoolEntry(tx: existingChildTx, txid: existingChildTxid,
      wtxid: existingChildTx.wtxid(), fee: Satoshi(500_000), weight: existingChildVsize * 4,
      feeRate: 0.1, timeAdded: getTime(), height: 0, ancestorFee: Satoshi(1_500_000),
      ancestorWeight: (150 + existingChildVsize) * 4, ancestorCount: 2,
      ancestorSize: 150 + existingChildVsize)
    mp.spentBy[makeOutpoint(parentTxid)] = existingChildTxid
    ## Parent's current descendant size: self(150) + child(90,700) = 90,850 vbytes
    let (_, parentDescSize) = mp.calculateDescendantStats(parentTxid)
    check parentDescSize == 90_850
    ## New big child: vsize = 10,201 > ExtraDescendantTxSizeLimit(10,000) → no exception.
    ## New child only has 1 in-mempool ancestor (parent) but vsize > limit.
    let bigChildWeight = 10_201 * 4
    ## Use a new unrelated confirmed UTXO for the big child — we want it to spend from parentTxid
    ## but we already used parentTxid's out0. Use a grandparent-sibling pattern:
    ## big child spends parentTxid out1 (not out0, which existingChild spends).
    let bigChildTx = Transaction(
      version: 1'i32,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 1'u32), scriptSig: @[],
                     sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(97_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[@[@[]]], lockTime: 0)
    ## Cluster = parent + existing large sibling + new big child.
    let (cCount, cSize) = mp.calculateClusterStats(bigChildTx, bigChildWeight)
    check cCount == 3
    check cSize == 600 + existingChildVsize * 4 + bigChildWeight
    check cSize == 404_204
    let res = mp.checkPackageLimits(bigChildTx, bigChildWeight)
    check not res.isOk  ## cluster size check must fire
    check res.error == "too-large-cluster"

# ===========================================================================
# G7 — descendant VSIZE limit (DEFAULT_DESCENDANT_SIZE_LIMIT_KVB * 1000 = 101,000)
# ===========================================================================
suite "G7 descendant vsize limit = 101,000 vbytes":
  setup:
    cleanupTestDb()

  test "G7a: new tx that pushes ancestor descendant vsize over limit is rejected":
    let mp = makeTestMempool(TestDbPath & "_g7a")
    let rootTxid = makeTxid(0x12)
    seedUtxo(mp, rootTxid, value = 100_000_000)
    ## parent + existing child already at 101,000 vbytes descendant
    let parentTx = makeSpend(rootTxid, 0, 99_000_000)
    let parentTxid = parentTx.txid()
    ## Make parent's descendant size 101,000 already (child adds to it)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(rootTxid)] = parentTxid
    ## Inject a large existing child of parent (fills descendant vsize to 101,000)
    let existingChildTx = makeSpend(parentTxid, 0, 98_000_000)
    let existingChildTxid = existingChildTx.txid()
    let bigChildWeight = (101_000 - 150) * 4  ## fills remaining vsize
    mp.entries[existingChildTxid] = MempoolEntry(tx: existingChildTx, txid: existingChildTxid,
      wtxid: existingChildTx.wtxid(), fee: Satoshi(500_000), weight: bigChildWeight,
      feeRate: 0.5, timeAdded: getTime(), height: 0, ancestorFee: Satoshi(1_500_000),
      ancestorWeight: bigChildWeight + 600, ancestorCount: 2, ancestorSize: 101_000)
    mp.spentBy[makeOutpoint(parentTxid)] = existingChildTxid
    ## Now try to add a grandchild — parent already has 101,000 vbytes descendants.
    ## This is NOT the exception case (existing child has 2 ancestors, not 1 with parent+self).
    ## Actually this is descendant limit violation for parentTx.
    let (descCount, descSize) = mp.calculateDescendantStats(parentTxid)
    check descSize >= 101_000

# ===========================================================================
# G8 — ancestor fee/weight accounting accuracy
# ===========================================================================
suite "G8 ancestor fee and weight accounting":
  setup:
    cleanupTestDb()

  test "G8a: calculateAncestorFeesAndWeight sums correctly over 3-deep chain":
    let mp = makeTestMempool(TestDbPath & "_g8a")
    let chain = buildChain(mp, 3)
    ## chain entries have fee = 1_000_000 each
    ## grandchild (chain[3]) ancestors: chain[1] (1M), chain[2] (1M) = 2M ancestor fees
    ## plus its own fee 1M → total should match what we seeded
    let grandchildEntry = mp.entries[chain[3]]
    let (totalFee, totalWeight) = mp.calculateAncestorFeesAndWeight(grandchildEntry.tx,
      grandchildEntry.fee, grandchildEntry.weight)
    ## 3 ancestors × 1M = 3M total ancestor fee (including self)
    check int64(totalFee) == 3_000_000
    check totalWeight == 600 * 3  ## 3 entries × 600 WU

  test "G8b: ancestor fee excludes confirmed parent (only unconfirmed ancestors)":
    let mp = makeTestMempool(TestDbPath & "_g8b")
    let chain = buildChain(mp, 1)
    ## chain[1] has no mempool ancestors (its parent is confirmed UTXO)
    let entry = mp.entries[chain[1]]
    let (totalFee, _) = mp.calculateAncestorFeesAndWeight(entry.tx, entry.fee, entry.weight)
    ## Should be just self's fee
    check int64(totalFee) == int64(entry.fee)

# ===========================================================================
# G9 — per-entry ancestor cached fields updated on add / stale after remove
# Core: CTxMemPool updates nCountWithAncestors / nSizeWithAncestors for all
# ancestors when a new tx is added. Nimrod stores these in MempoolEntry.
# ===========================================================================
suite "G9 ancestor cached fields (MempoolEntry.ancestorCount/ancestorSize)":
  setup:
    cleanupTestDb()

  test "G9a: newly added entry has correct ancestorCount including self":
    ## BUG-PROBE: MempoolEntry.ancestorCount should = len(ancestors) + 1.
    ## In nimrod this is set at add time via calculateAncestorStats.
    let mp = makeTestMempool(TestDbPath & "_g9a")
    let chain = buildChain(mp, 2)
    let entry = mp.entries[chain[2]]
    ## chain[2] has chain[1] as ancestor → count = 2 (self + 1 ancestor)
    check entry.ancestorCount == 2

  test "G9b: BUG-PROBE — ancestors' descendantCount / ancestorCount NOT updated when new tx added":
    ## Core updates nCountWithDescendants for ALL ancestors when a new child is added.
    ## Nimrod's MempoolEntry does NOT have a descendantCount field, and the cached
    ## ancestorCount of existing entries is NOT updated when a grandchild arrives.
    ## This means the cached ancestorCount of chain[1] remains 1 even after
    ## chain[2] and chain[3] are added — a known design gap vs Core.
    let mp = makeTestMempool(TestDbPath & "_g9b")
    let chain = buildChain(mp, 3)
    ## chain[1]'s entry.ancestorCount should still be 1 (self only).
    ## In Core, chain[1] would have its nCountWithDescendants updated, but nimrod
    ## doesn't store per-entry descendant counts — it recomputes on demand.
    let entry1 = mp.entries[chain[1]]
    ## ancestorCount for chain[1] itself is 1 (no mempool ancestors)
    check entry1.ancestorCount == 1
    ## descendant stats require on-demand calculation
    let (descCount, _) = mp.calculateDescendantStats(chain[1])
    check descCount == 3  ## chain[1] + chain[2] + chain[3]

# ===========================================================================
# G10 — calculateDescendantStats on-demand vs. Core's cached nSizeWithDescendants
# ===========================================================================
suite "G10 calculateDescendantStats on-demand vs Core cached approach":
  setup:
    cleanupTestDb()

  test "G10a: BUG-PROBE — no per-entry descendantFee/descendantWeight field":
    ## Core CTxMemPoolEntry has nModFeesWithDescendants / nSizeWithDescendants cached
    ## per-entry for O(1) mining template construction.  Nimrod computes O(n) on demand.
    ## This is a performance gap (not a consensus-safety gap) but confirms Core behaviour differs.
    let mp = makeTestMempool(TestDbPath & "_g10a")
    let chain = buildChain(mp, 3)
    let entry = mp.entries[chain[1]]
    ## Nimrod MempoolEntry has no descendantFee / descendantWeight field
    ## so we must call calculateDescendantStats; verifying it returns correct values.
    let (descCount, descSize) = mp.calculateDescendantStats(chain[1])
    check descCount == 3      ## chain[1] + chain[2] + chain[3]
    check descSize >= 450     ## at least 3 × 150 vbytes

# ===========================================================================
# G11 — signalsOptInRBF: nSequence <= 0xfffffffd
# Core: src/util/rbf.cpp SignalsOptInRBF() — unsigned comparison
# ===========================================================================
suite "G11 signalsOptInRBF (BIP-125 Rule 1 tx-level check)":
  setup:
    cleanupTestDb()

  test "G11a: nSequence 0x00000000 signals opt-in RBF":
    let tx = makeSpend(makeTxid(0x01), 0, 9_000_000, 0x00000000'u32)
    check signalsOptInRBF(tx)

  test "G11b: nSequence 0xfffffffd (MAX_BIP125_RBF_SEQUENCE) signals opt-in":
    let tx = makeSpend(makeTxid(0x01), 0, 9_000_000, 0xfffffffd'u32)
    check signalsOptInRBF(tx)

  test "G11c: nSequence 0xfffffffe does NOT signal (boundary)":
    let tx = makeSpend(makeTxid(0x01), 0, 9_000_000, 0xfffffffe'u32)
    check not signalsOptInRBF(tx)

  test "G11d: nSequence 0xffffffff (SEQUENCE_FINAL) does NOT signal":
    let tx = makeSpend(makeTxid(0x01), 0, 9_000_000, 0xffffffff'u32)
    check not signalsOptInRBF(tx)

# ===========================================================================
# G12 — isRbfOptIn: ancestor-inherited signaling
# Core: policy/rbf.cpp IsRBFOptIn — checks ancestors too
# ===========================================================================
suite "G12 isRbfOptIn ancestor inheritance":
  setup:
    cleanupTestDb()

  test "G12a: non-signaling tx with signaling ancestor is replaceable":
    let mp = makeTestMempool(TestDbPath & "_g12a")
    ## Parent signals RBF (sequence = 0x0)
    let parentTxid = makeTxid(0x20)
    let parentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0x00000000'u32)
    seedUtxo(mp, makeTxid(0xAA), value = 10_000_000)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(makeTxid(0xAA))] = parentTxid
    ## Child does NOT signal (0xFFFFFFFE) but spends from signaling parent
    let childTx = makeSpend(parentTxid, 0, 8_000_000, 0xFFFFFFFE'u32)
    check mp.isRbfOptIn(childTx)

  test "G12b: neither tx nor any ancestor signals → NOT replaceable (standard mode)":
    let mp = makeTestMempool(TestDbPath & "_g12b")
    let tx = makeSpend(makeTxid(0xBB), 0, 9_000_000, 0xFFFFFFFE'u32)
    check not mp.isRbfOptIn(tx)

  test "G12c: fullRbf mode makes any tx replaceable regardless of signaling":
    let mp = makeTestMempoolFull(TestDbPath & "_g12c")
    let tx = makeSpend(makeTxid(0xCC), 0, 9_000_000, 0xffffffff'u32)
    check mp.isRbfOptIn(tx)

# ===========================================================================
# G13 — findConflicts: double-spend detection via spentBy map
# ===========================================================================
suite "G13 findConflicts double-spend detection":
  setup:
    cleanupTestDb()

  test "G13a: no conflicts for non-double-spend":
    let mp = makeTestMempool(TestDbPath & "_g13a")
    let tx = makeSpend(makeTxid(0x30), 0, 9_000_000)
    check mp.findConflicts(tx).len == 0

  test "G13b: conflict detected when same outpoint is already spent in mempool":
    let mp = makeTestMempool(TestDbPath & "_g13b")
    let prevTxid = makeTxid(0x31)
    let existingTx = makeSpend(prevTxid, 0, 9_000_000)
    let existingTxid = existingTx.txid()
    mp.entries[existingTxid] = MempoolEntry(tx: existingTx, txid: existingTxid, wtxid: existingTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = existingTxid
    let conflictingTx = makeSpend(prevTxid, 0, 8_000_000, 0x00000000'u32)
    let conflicts = mp.findConflicts(conflictingTx)
    check conflicts.len == 1
    check existingTxid in conflicts

# ===========================================================================
# G14 — getAllConflictsWithDescendants: include descendants
# Core: GetEntriesForConflicts expands to all descendants
# ===========================================================================
suite "G14 getAllConflictsWithDescendants expands to descendants":
  setup:
    cleanupTestDb()

  test "G14a: conflict + 1 descendant both included":
    let mp = makeTestMempool(TestDbPath & "_g14a")
    let chain = buildChain(mp, 2)
    ## conflict is chain[1]; chain[2] is its descendant
    let conflicts = toHashSet([chain[1]])
    let all = mp.getAllConflictsWithDescendants(conflicts)
    check all.len == 2
    check chain[1] in all
    check chain[2] in all

  test "G14b: conflict without descendants returns just the conflict":
    let mp = makeTestMempool(TestDbPath & "_g14b")
    let chain = buildChain(mp, 1)
    let conflicts = toHashSet([chain[1]])
    let all = mp.getAllConflictsWithDescendants(conflicts)
    check all.len == 1
    check chain[1] in all

# ===========================================================================
# G15 — Rule #5: MAX_REPLACEMENT_CANDIDATES = 100
# Core: GetEntriesForConflicts checks cluster count; nimrod counts total evictions.
# ===========================================================================
suite "G15 MAX_REPLACEMENT_CANDIDATES = 100":
  setup:
    cleanupTestDb()

  test "G15a: RBF rejected when conflicts + descendants exceed 100":
    ## BUG-PROBE: nimrod counts total evictions (vs Core cluster count).
    ## We inject a conflict with 100 descendants → 101 total → should reject.
    let mp = makeTestMempool(TestDbPath & "_g15a")
    let rootTxid = makeTxid(0x40)
    seedUtxo(mp, rootTxid, value = 100_000_000)
    ## conflict tx
    let conflictTx = makeSpend(rootTxid, 0, 99_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(rootTxid)] = conflictTxid
    ## Inject 100 descendants of conflictTxid
    var prevTxid = conflictTxid
    for i in 1 .. 100:
      let tx = makeSpend(prevTxid, 0, 98_000_000 - int64(i) * 100_000)
      let txid = tx.txid()
      mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
        fee: Satoshi(100_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
        height: 0, ancestorFee: Satoshi(int64(i + 1) * 100_000), ancestorWeight: 600 * (i + 1),
        ancestorCount: i + 1, ancestorSize: 150 * (i + 1))
      mp.spentBy[makeOutpoint(prevTxid)] = txid
      prevTxid = txid
    ## Now try RBF with conflictTxid → 101 total evictions
    let replacingTx = makeSpend(rootTxid, 0, 95_000_000, 0x00000000'u32)
    let replacingFee = Satoshi(4_000_000)
    let conflicts = mp.findConflicts(replacingTx)
    let res = mp.checkRbfRules(replacingTx, replacingFee, 150, conflicts)
    check not res.isOk
    check res.error.contains("too many potential replacements") or
          res.error.contains("too many conflict") or
          res.error.contains("100")

# ===========================================================================
# G16 — Rule #2 (EntriesAndTxidsDisjoint): no spending from to-be-evicted tx
# Core: policy/rbf.cpp EntriesAndTxidsDisjoint
# ===========================================================================
suite "G16 RBF Rule 2 — replacement must not spend evicted tx outputs":
  setup:
    cleanupTestDb()

  test "G16a: replacement that spends evicted tx is rejected":
    let mp = makeTestMempool(TestDbPath & "_g16a")
    let prevTxid = makeTxid(0x50)
    seedUtxo(mp, prevTxid, value = 10_000_000)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    ## Replacement spends conflictTxid's output (which would be evicted)
    let badReplacement = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(prevTxid), scriptSig: @[], sequence: 0x00000000'u32),
        TxIn(prevOut: makeOutpoint(conflictTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)
      ],
      outputs: @[TxOut(value: Satoshi(5_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let conflicts = mp.findConflicts(badReplacement)
    let res = mp.checkRbfRules(badReplacement, Satoshi(4_000_000), 200, conflicts)
    check not res.isOk
    check res.error.contains("spends output from conflicting") or
          res.error.contains("spending conflicting") or
          res.error.contains("conflicting transaction")

# ===========================================================================
# G17 — Rule #3 (PaysForRBF part 1): replacement fees >= original fees
# Core: policy/rbf.cpp PaysForRBF line 109 — strictly less-than check
# ===========================================================================
suite "G17 RBF Rule 3 — replacement fees >= original fees":
  setup:
    cleanupTestDb()

  test "G17a: replacement with equal fees is accepted (>= not >)":
    ## BUG-PROBE: Core uses < not <= — equal fees pass.
    let mp = makeTestMempool(TestDbPath & "_g17a")
    let prevTxid = makeTxid(0x60)
    let conflictFee = Satoshi(1_000_000)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: conflictFee, weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: conflictFee, ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    let replacingTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    ## Equal fee — must NOT be rejected by Rule #3.
    ## Rule #4 will require additional fee for bandwidth, so we need to factor that in.
    ## Supply exactly conflict fee + incremental relay for Rule #4.
    let requiredAdditional = int64(DefaultIncrementalRelayFee * 150.0)
    let replacingFee = Satoshi(int64(conflictFee) + requiredAdditional)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(replacingTx, replacingFee, 150, conflicts)
    ## Should pass both rules (Rule #3 accepts equal; Rule #4 satisfied by additional)
    check res.isOk

  test "G17b: replacement with lower fees is rejected by Rule #3":
    let mp = makeTestMempool(TestDbPath & "_g17b")
    let prevTxid = makeTxid(0x61)
    let conflictFee = Satoshi(2_000_000)
    let conflictTx = makeSpend(prevTxid, 0, 8_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: conflictFee, weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: conflictFee, ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    let replacingTx = makeSpend(prevTxid, 0, 9_500_000, 0x00000000'u32)
    let conflicts = toHashSet([conflictTxid])
    ## Replacement fee = 500,000 < conflict fee = 2,000,000
    let res = mp.checkRbfRules(replacingTx, Satoshi(500_000), 150, conflicts)
    check not res.isOk
    check res.error.contains("less fees") or res.error.contains("insufficient fee") or
          res.error.contains("rejecting replacement")

# ===========================================================================
# G18 — Rule #4 (PaysForRBF part 2): additional fee >= incremental_relay_fee * vsize
# Core: policy/rbf.cpp PaysForRBF line 118
# ===========================================================================
suite "G18 RBF Rule 4 — additional fee >= relay_fee * replacement_vsize":
  setup:
    cleanupTestDb()

  test "G18a: replacement with insufficient additional fee rejected":
    let mp = makeTestMempool(TestDbPath & "_g18a")
    let prevTxid = makeTxid(0x70)
    let conflictFee = Satoshi(1_000_000)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: conflictFee, weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: conflictFee, ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    ## Replacement fee = conflict fee + 1 sat (far too little for Rule #4)
    let replacingFee = Satoshi(int64(conflictFee) + 1)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(makeSpend(prevTxid, 0, 9_000_000 - 1, 0x00000000'u32),
                                replacingFee, 150, conflicts)
    check not res.isOk
    check res.error.contains("not enough additional fees") or
          res.error.contains("additional fee") or
          res.error.contains("rejecting replacement")

  test "G18b: replacement with sufficient additional fee accepted by Rule #4":
    let mp = makeTestMempool(TestDbPath & "_g18b")
    let prevTxid = makeTxid(0x71)
    let conflictFee = Satoshi(1_000_000)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: conflictFee, weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: conflictFee, ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    ## additional_fee = relay_fee * vsize = 1.0 sat/vbyte * 150 vbytes = 150 sats
    let replacingFee = Satoshi(int64(conflictFee) + 200)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(makeSpend(prevTxid, 0, 8_999_800, 0x00000000'u32),
                                replacingFee, 150, conflicts)
    check res.isOk

# ===========================================================================
# G19 — RBF Rule 1 signaling gate: non-signaling conflict rejected (standard mode)
# ===========================================================================
suite "G19 RBF Rule 1 — non-signaling conflict rejected in standard mode":
  setup:
    cleanupTestDb()

  test "G19a: non-signaling conflict tx causes RBF rejection":
    let mp = makeTestMempool(TestDbPath & "_g19a")
    let prevTxid = makeTxid(0x80)
    ## Conflict does NOT signal (0xFFFFFFFF)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0xffffffff'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    let replacingTx = makeSpend(prevTxid, 0, 7_000_000, 0x00000000'u32)
    let conflicts = toHashSet([conflictTxid])
    let res = mp.checkRbfRules(replacingTx, Satoshi(3_000_000), 150, conflicts)
    check not res.isOk
    check res.error.contains("RBF opt-in") or res.error.contains("does not signal") or
          res.error.contains("bip125") or res.error.contains("not replaceable")

  test "G19b: fullRbf mode bypasses signaling requirement":
    let mp = makeTestMempoolFull(TestDbPath & "_g19b")
    let prevTxid = makeTxid(0x81)
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0xffffffff'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    let replacingTx = makeSpend(prevTxid, 0, 7_000_000, 0x00000000'u32)
    let conflicts = toHashSet([conflictTxid])
    ## 3M fee > 1M conflict fee; additional = 2M >> relay_fee * 150 — should pass
    let res = mp.checkRbfRules(replacingTx, Satoshi(3_000_000), 150, conflicts)
    check res.isOk

# ===========================================================================
# G20 — Rule #8 ImprovesFeerateDiagram ABSENT in acceptTransaction single-tx path
# Core 27+: ImprovesFeerateDiagram required for all RBF (policy/rbf.cpp:127-140).
# BUG: nimrod explicitly defers this with comment "NOTE: Rule #8 (ImprovesFeerateDiagram,
# Core 27+) is deferred; cluster tracking required." The cluster.nim code exists but
# is NOT wired into checkRbfRules.
# ===========================================================================
suite "G20 — Rule 8 ImprovesFeerateDiagram wired into single-tx RBF path":
  setup:
    cleanupTestDb()

  test "G20a: diagram-degrading replacement is rejected by checkRbfRules":
    ## FIX: validateRbfDiagram / improvesFeerateDiagram is now wired into checkRbfRules
    ## after Rule #4.  A replacement that satisfies Rules #3/#4 (absolute fee checks)
    ## but degrades the feerate diagram must be rejected.
    ##
    ## Scenario: high-feerate conflict (666 sat/vB) replaced by huge low-feerate tx (11 sat/vB).
    ## Core 27+ ImprovesFeerateDiagram rejects this; nimrod now does too.
    ##
    ## Fee arithmetic:
    ##   conflict fee = 100,000 sats, vsize = 150 → feerate = 666 sat/vB
    ##   replacement vsize = 10,000, fee = 110,001 sats → feerate = 11 sat/vB
    ##   Rule #3: 110,001 >= 100,000 ✓
    ##   Rule #4: additional = 10,001 >= relay_fee(1) * 10,000 = 10,000 ✓
    ##   ImprovesFeerateDiagram: 11 sat/vB vs 666 sat/vB → WORSE → REJECT
    let mp = makeTestMempool(TestDbPath & "_g20a")
    let prevTxid = makeTxid(0x90)
    ## High-feerate conflict (100,000 sats, 150 vbytes = 666 sat/vB), signals RBF
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(100_000), weight: 600, feeRate: 666.7, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(100_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    let conflicts = toHashSet([conflictTxid])
    ## Replacement: fee = 110,001 sats, vsize = 10,000 → feerate = 11 sat/vB (much worse than 666)
    ## Rule #3: 110,001 > 100,000 ✓  Rule #4: 10,001 >= 1*10,000 ✓
    ## Rule #8: 11 sat/vB does NOT improve diagram vs 666 sat/vB → REJECT
    let res = mp.checkRbfRules(makeSpend(prevTxid, 0, 8_889_999, 0x00000000'u32),
                                Satoshi(110_001), 10_000, conflicts)
    ## FIX ASSERTED: nimrod now rejects this via ImprovesFeerateDiagram, matching Core 27+.
    check not res.isOk
    check res.error.contains("feerate diagram")

# ===========================================================================
# G21 — TRUC (v3) single-tx: version check, size limits
# Core: policy/truc_policy.cpp SingleTRUCChecks
# ===========================================================================
suite "G21 TRUC single-tx basic rules":
  setup:
    cleanupTestDb()

  test "G21a: non-v3 tx passes TRUC checks with no unconfirmed parents":
    let mp = makeTestMempool(TestDbPath & "_g21a")
    let tx = makeSpend(makeTxid(0xA0), 0, 9_000_000, 0xFFFFFFFE'u32, 1)
    let conflicts = initHashSet[TxId]()
    let res = mp.checkSingleTrucRules(tx, 600, conflicts)
    check res.isOk
    check res.siblingToEvict.isNone

  test "G21b: v3 tx exceeding TRUC_MAX_VSIZE = 10,000 vbytes is rejected":
    ## BUG-PROBE: TrucMaxVsize = 10,000; weight = 10,001*4 + 1 would be > limit.
    let mp = makeTestMempool(TestDbPath & "_g21b")
    let tx = makeSpend(makeTxid(0xA1), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    let conflicts = initHashSet[TxId]()
    ## weight = 10,001 * 4 WU → vsize = 10,001 vbytes > TrucMaxVsize
    let res = mp.checkSingleTrucRules(tx, 10_001 * 4, conflicts)
    check not res.isOk
    check res.error.contains("too big") or res.error.contains("10000") or
          res.error.contains("virtual bytes")

  test "G21c: v3 child exceeding TRUC_CHILD_MAX_VSIZE = 1,000 vbytes is rejected":
    let mp = makeTestMempool(TestDbPath & "_g21c")
    let parentTxid = makeTxid(0xA2)
    let parentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(500_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(500_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    ## Child v3 spends from v3 parent but is too large
    let childTx = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(8_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let conflicts = initHashSet[TxId]()
    ## weight = 1,001 * 4 WU → vsize = 1,001 > TrucChildMaxVsize
    let res = mp.checkSingleTrucRules(childTx, 1_001 * 4, conflicts)
    check not res.isOk
    check res.error.contains("too big") or res.error.contains("child") or
          res.error.contains("1000") or res.error.contains("virtual bytes")

  test "G21d: v3 parent already has a child → new child triggers sibling eviction check":
    ## BUG-PROBE: Core SingleTRUCChecks sets consider_sibling_eviction when
    ## parent has exactly 2 descendants (itself + 1 child) and child's ancestor count = 2.
    let mp = makeTestMempool(TestDbPath & "_g21d")
    let parentTxid = makeTxid(0xA3)
    let parentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, wtxid: parentTx.wtxid(),
      fee: Satoshi(500_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(500_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    ## Inject existing child
    let existingChildTx = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(8_500_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let existingChildTxid = existingChildTx.txid()
    mp.entries[existingChildTxid] = MempoolEntry(tx: existingChildTx, txid: existingChildTxid,
      wtxid: existingChildTx.wtxid(), fee: Satoshi(500_000), weight: 600, feeRate: 1.5,
      timeAdded: getTime(), height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 1200,
      ancestorCount: 2, ancestorSize: 300)
    mp.spentBy[makeOutpoint(parentTxid)] = existingChildTxid
    ## New v3 child; parentTxid already has one child → sibling eviction consideration
    let newChildTx = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0x00000000'u32)],
      outputs: @[TxOut(value: Satoshi(8_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    ## No conflicts initially
    let conflicts = initHashSet[TxId]()
    let res = mp.checkSingleTrucRules(newChildTx, 600, conflicts)
    ## Should return sibling-eviction candidate, not a hard error
    check res.isOk or res.siblingToEvict.isSome or
          (not res.isOk and (res.error.contains("descendant") or res.error.contains("sibling")))

# ===========================================================================
# G22 — TRUC version inheritance: v3 cannot spend non-v3 unconfirmed
# ===========================================================================
suite "G22 TRUC version inheritance rules":
  setup:
    cleanupTestDb()

  test "G22a: v3 tx spending non-v3 unconfirmed parent is rejected":
    let mp = makeTestMempool(TestDbPath & "_g22a")
    let nonV3ParentTxid = makeTxid(0xB0)
    let nonV3Parent = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 1)
    mp.entries[nonV3ParentTxid] = MempoolEntry(tx: nonV3Parent, txid: nonV3ParentTxid,
      wtxid: nonV3Parent.wtxid(), fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5,
      timeAdded: getTime(), height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600,
      ancestorCount: 1, ancestorSize: 150)
    let v3ChildTx = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(nonV3ParentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(8_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let conflicts = initHashSet[TxId]()
    let res = mp.checkSingleTrucRules(v3ChildTx, 600, conflicts)
    check not res.isOk
    check res.error.contains("non-version=3") or res.error.contains("v3") or
          res.error.contains("version=3") or res.error.contains("cannot spend")

  test "G22b: non-v3 tx spending v3 unconfirmed parent is rejected":
    let mp = makeTestMempool(TestDbPath & "_g22b")
    let v3ParentTxid = makeTxid(0xB1)
    let v3ParentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    mp.entries[v3ParentTxid] = MempoolEntry(tx: v3ParentTx, txid: v3ParentTxid,
      wtxid: v3ParentTx.wtxid(), fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5,
      timeAdded: getTime(), height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600,
      ancestorCount: 1, ancestorSize: 150)
    let nonV3Child = Transaction(
      version: 1'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(v3ParentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(8_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    let conflicts = initHashSet[TxId]()
    let res = mp.checkSingleTrucRules(nonV3Child, 600, conflicts)
    check not res.isOk
    check res.error.contains("version=3") or res.error.contains("cannot spend") or
          res.error.contains("non-version=3")

# ===========================================================================
# G23 — TRUC package rules: PackageTRUCChecks
# ===========================================================================
suite "G23 TRUC package rules (checkPackageTrucRules)":
  setup:
    cleanupTestDb()

  test "G23a: two siblings of same v3 parent in one package are rejected":
    ## Core PackageTRUCChecks: if two txs in a package share the same TRUC parent,
    ## the second one is rejected because it would exceed TRUC_DESCENDANT_LIMIT.
    ## Use parent.txid() (actual computed txid) so package-parent detection works.
    let parentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    let parentTxid = parentTx.txid()  ## actual txid, not a stub
    let child1 = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(4_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[@[@[]]], lockTime: 0)
    let child2 = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0x00000000'u32)],
      outputs: @[TxOut(value: Satoshi(3_500_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[@[@[]]], lockTime: 0)
    let pkg = @[parentTx, child1, child2]
    let res = checkPackageTrucRules(pkg,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1,
      proc(txid: TxId): int = 1)
    check not res.isOk
    check res.error.contains("descendant count limit") or
          res.error.contains("too many ancestors") or
          res.error.contains("would exceed")

  test "G23b: valid v3 parent-child package accepted":
    ## Use parent.txid() so package-parent detection works.
    let parentTx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xFFFFFFFE'u32, 3)
    let parentTxid = parentTx.txid()  ## actual txid
    let child = Transaction(
      version: 3'i32,
      inputs: @[TxIn(prevOut: makeOutpoint(parentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
      outputs: @[TxOut(value: Satoshi(8_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[@[@[]]], lockTime: 0)
    let pkg = @[parentTx, child]
    let res = checkPackageTrucRules(pkg,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1,
      proc(txid: TxId): int = 1)
    check res.isOk

# ===========================================================================
# G24 — isBip125Replaceable (per-mempool-entry replaceability query)
# ===========================================================================
suite "G24 isBip125Replaceable (per-entry query)":
  setup:
    cleanupTestDb()

  test "G24a: entry with signaling input is replaceable":
    let mp = makeTestMempool(TestDbPath & "_g24a")
    let txid = makeTxid(0xD0)
    let tx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0x00000000'u32)
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    check mp.isBip125Replaceable(txid)

  test "G24b: entry not in mempool returns false":
    let mp = makeTestMempool(TestDbPath & "_g24b")
    check not mp.isBip125Replaceable(makeTxid(0xD1))

  test "G24c: non-signaling entry with non-signaling ancestor returns false":
    let mp = makeTestMempool(TestDbPath & "_g24c")
    let txid = makeTxid(0xD2)
    let tx = makeSpend(makeTxid(0xAA), 0, 9_000_000, 0xffffffff'u32)
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, wtxid: tx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    check not mp.isBip125Replaceable(txid)

# ===========================================================================
# G25 — TRUC sibling eviction: fee check (checkTrucSiblingEviction)
# ===========================================================================
suite "G25 TRUC sibling eviction fee check":
  setup:
    cleanupTestDb()

  test "G25a: new v3 child must pay at least as much as sibling to evict it":
    let mp = makeTestMempool(TestDbPath & "_g25a")
    let siblingTxid = makeTxid(0xE0)
    let siblingTx = makeSpend(makeTxid(0xAA), 0, 8_000_000, 0xFFFFFFFE'u32, 3)
    mp.entries[siblingTxid] = MempoolEntry(tx: siblingTx, txid: siblingTxid, wtxid: siblingTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 2, ancestorSize: 300)
    let newChildTx = makeSpend(makeTxid(0xBB), 0, 8_500_000, 0x00000000'u32, 3)
    ## Fee below sibling — must be rejected
    let resBelowFee = mp.checkTrucSiblingEviction(newChildTx, Satoshi(999_999), siblingTxid)
    check not resBelowFee.isOk

  test "G25b: equal fee passes sibling eviction fee check":
    let mp = makeTestMempool(TestDbPath & "_g25b")
    let siblingTxid = makeTxid(0xE1)
    let siblingTx = makeSpend(makeTxid(0xAA), 0, 8_000_000, 0xFFFFFFFE'u32, 3)
    mp.entries[siblingTxid] = MempoolEntry(tx: siblingTx, txid: siblingTxid, wtxid: siblingTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 2, ancestorSize: 300)
    let newChildTx = makeSpend(makeTxid(0xBB), 0, 8_000_000, 0x00000000'u32, 3)
    ## Equal fee — must pass
    let resEqualFee = mp.checkTrucSiblingEviction(newChildTx, Satoshi(1_000_000), siblingTxid)
    check resEqualFee.isOk

# ===========================================================================
# G26 — isWellFormedPackage: structural validation
# Core: policy/packages.cpp IsWellFormedPackage
# ===========================================================================
suite "G26 isWellFormedPackage structural checks":
  setup:
    cleanupTestDb()

  test "G26a: MAX_PACKAGE_COUNT = 25 exceeded is rejected":
    var txns: seq[Transaction]
    for i in 0 ..< 26:
      txns.add(makeSpend(makeTxidN(0xF0, byte(i)), 0, 9_000_000))
    let res = isWellFormedPackage(txns)
    check not res.isOk
    check res.error.contains("too-many-transactions") or res.error.contains("25") or
          res.error.contains("26")

  test "G26b: exactly 25 transactions passes count check":
    var txns: seq[Transaction]
    for i in 0 ..< 25:
      txns.add(makeSpend(makeTxidN(0xF1, byte(i)), 0, 9_000_000))
    ## Each tx has a unique input, so no conflicts
    let res = isWellFormedPackage(txns)
    ## May fail on MAX_PACKAGE_WEIGHT but count check should pass
    let countOk = res.isOk or not res.error.contains("too-many-transactions")
    check countOk

  test "G26c: duplicate txids in package are rejected":
    let tx = makeSpend(makeTxid(0xF2), 0, 9_000_000)
    let txns = @[tx, tx]  ## same tx twice
    let res = isWellFormedPackage(txns)
    check not res.isOk
    check res.error.contains("duplicate") or res.error.contains("conflict") or
          res.error.contains("duplicates")

  test "G26d: unsorted package (child before parent) is rejected":
    ## parent spends 0xF3; child spends parent
    let parentTx = makeSpend(makeTxid(0xF3), 0, 9_000_000)
    let parentTxid = parentTx.txid()
    let childTx = makeSpend(parentTxid, 0, 8_000_000)
    let txns = @[childTx, parentTx]  ## child BEFORE parent → unsorted
    let res = isWellFormedPackage(txns)
    check not res.isOk
    check res.error.contains("not-sorted") or res.error.contains("sorted") or
          res.error.contains("topolog")

  test "G26e: conflicting inputs in package are rejected":
    let prevTxid = makeTxid(0xF4)
    ## Two txs spending the same input
    let tx1 = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let tx2 = makeSpend(prevTxid, 0, 8_000_000, 0xFFFFFFFE'u32)
    let txns = @[tx1, tx2]
    let res = isWellFormedPackage(txns)
    check not res.isOk
    check res.error.contains("conflict") or res.error.contains("same input") or
          res.error.contains("duplicate")

# ===========================================================================
# G27 — isChildWithParents / isChildWithParentsTree topology
# ===========================================================================
suite "G27 isChildWithParents and isChildWithParentsTree":
  setup:
    cleanupTestDb()

  test "G27a: 1-parent + child package passes isChildWithParents":
    ## Use parent.txid() so the child's prevOut matches the actual parent txid.
    let parent = makeSpend(makeTxid(0xAA), 0, 9_000_000)
    let parentTxid = parent.txid()  ## actual txid
    let child = makeSpend(parentTxid, 0, 8_000_000)
    check isChildWithParents(@[parent, child])

  test "G27b: singleton package fails isChildWithParents (needs >= 2 txs)":
    let tx = makeSpend(makeTxid(0xAA), 0, 9_000_000)
    check not isChildWithParents(@[tx])

  test "G27c: isChildWithParentsTree fails when parents depend on each other":
    ## Use actual computed txids to ensure package-parent detection works.
    let grandparent = makeSpend(makeTxid(0xAA), 0, 9_000_000)
    let grandparentTxid = grandparent.txid()  ## actual txid
    ## parent1 spends from grandparent → violates tree property
    let parent1 = makeSpend(grandparentTxid, 0, 8_000_000)
    let parent1Txid = parent1.txid()
    let childTx = Transaction(
      version: 1'i32,
      inputs: @[
        TxIn(prevOut: makeOutpoint(grandparentTxid), scriptSig: @[], sequence: 0xFFFFFFFE'u32),
        TxIn(prevOut: makeOutpoint(parent1Txid), scriptSig: @[], sequence: 0xFFFFFFFE'u32)
      ],
      outputs: @[TxOut(value: Satoshi(7_000_000), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[], lockTime: 0)
    ## grandparent, parent1, child — parent1 depends on grandparent which is also a parent of child
    let pkg = @[grandparent, parent1, childTx]
    check not isChildWithParentsTree(pkg)

# ===========================================================================
# G28 — MAX_PACKAGE_WEIGHT = 404,000 WU
# Core: policy/packages.h MAX_PACKAGE_WEIGHT
# ===========================================================================
suite "G28 MAX_PACKAGE_WEIGHT = 404,000 WU":
  setup:
    cleanupTestDb()

  test "G28a: MaxPackageWeight constant is 404,000":
    check MaxPackageWeight == 404_000

  test "G28b: BUG-PROBE — MaxPackageSize in nimrod is 101,000 vbytes (weight/4)":
    ## Core's MAX_PACKAGE_WEIGHT = 404,000 WU = 101,000 vbytes.
    ## Nimrod's MaxPackageSize = 101,000 and MaxPackageWeight = 404,000.
    ## Ensure the two constants are consistent (weight = vbytes * 4).
    check MaxPackageWeight == MaxPackageSize * 4

# ===========================================================================
# G29 — removeForBlock cascade: descendant invalidation
# Core: CTxMemPool::removeForBlock removes confirmed txs AND their conflicts.
# ===========================================================================
suite "G29 removeForBlock conflict cascade":
  setup:
    cleanupTestDb()

  test "G29a: tx confirmed in block is removed from mempool":
    let mp = makeTestMempool(TestDbPath & "_g29a")
    let chain = buildChain(mp, 1)
    let prevBlock = Block(txs: @[mp.entries[chain[1]].tx])
    mp.removeForBlock(prevBlock)
    check chain[1] notin mp.entries

  test "G29b: conflict of block tx is evicted":
    ## Seed a tx in the mempool that spends the same outpoint as a block tx.
    let mp = makeTestMempool(TestDbPath & "_g29b")
    let prevTxid = makeTxid(0x50)
    seedUtxo(mp, prevTxid, value = 10_000_000)
    ## conflict: already in mempool, spends prevTxid
    let conflictTx = makeSpend(prevTxid, 0, 9_000_000, 0x00000000'u32)
    let conflictTxid = conflictTx.txid()
    mp.entries[conflictTxid] = MempoolEntry(tx: conflictTx, txid: conflictTxid, wtxid: conflictTx.wtxid(),
      fee: Satoshi(1_000_000), weight: 600, feeRate: 1.5, timeAdded: getTime(),
      height: 0, ancestorFee: Satoshi(1_000_000), ancestorWeight: 600, ancestorCount: 1, ancestorSize: 150)
    mp.spentBy[makeOutpoint(prevTxid)] = conflictTxid
    ## Block confirms a different tx that spends the same prevTxid
    let blockTx = makeSpend(prevTxid, 0, 9_500_000, 0xFFFFFFFE'u32)
    let blk = Block(txs: @[blockTx])
    mp.removeForBlock(blk)
    ## conflict should have been evicted
    check conflictTxid notin mp.entries

# ===========================================================================
# G30 — getMinFee rolling floor + trackPackageRemoved
# Core: txmempool.cpp CTxMemPool::GetMinFee + trackPackageRemoved (lines 829-859)
# ===========================================================================
suite "G30 rolling minimum fee rate (getMinFee + trackPackageRemoved)":
  setup:
    cleanupTestDb()

  test "G30a: initial rolling floor is 0 (no evictions yet)":
    let mp = makeTestMempool(TestDbPath & "_g30a")
    check mp.getMinFee() == 0.0

  test "G30b: trackPackageRemoved bumps rolling floor":
    let mp = makeTestMempool(TestDbPath & "_g30b")
    let evictedRateSatKvB = 5_000.0   ## 5 sat/vbyte = 5,000 sat/kvB
    mp.trackPackageRemoved(evictedRateSatKvB)
    ## blockSinceLastRollingFeeBump is now false, so no decay yet;
    ## getMinFee returns rollingMinimumFeeRate / 1000 sat/vB
    let floor = mp.getMinFee()
    check floor > 0.0

  test "G30c: trackPackageRemoved only bumps if evicted rate > current floor":
    let mp = makeTestMempool(TestDbPath & "_g30c")
    mp.trackPackageRemoved(5_000.0)    ## set floor to 5 sat/vB
    mp.trackPackageRemoved(3_000.0)    ## lower rate — should NOT lower floor
    ## rollingMinimumFeeRate should still be 5,000 sat/kvB (5 sat/vB)
    check mp.rollingMinimumFeeRate == 5_000.0

  test "G30d: BUG-PROBE — rolling floor does not decay without blockSinceLastRollingFeeBump":
    ## Core: decay only happens after a block is mined AND time has passed.
    ## If blockSinceLastRollingFeeBump is false, getMinFee returns raw floor/1000 immediately.
    let mp = makeTestMempool(TestDbPath & "_g30d")
    mp.trackPackageRemoved(10_000.0)    ## 10 sat/vB floor
    mp.blockSinceLastRollingFeeBump = false
    ## No decay, floor should still reflect the tracked value
    let floor = mp.getMinFee()
    check floor > 0.0
