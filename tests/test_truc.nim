## TRUC (v3) policy tests
## Tests v3 transaction relay policy: topologically restricted until confirmation

import unittest2
import std/[os, options, tables, strutils, times, sets]
import ../src/mempool/[mempool, package]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter

const TestDbPath = "/tmp/nimrod_truc_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# Create a simple P2PKH scriptPubKey
proc makeP2PKHScript(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] & @(default(array[20, byte])) & @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

# Create a coinbase transaction at a given height
proc makeCoinbaseTx(height: int32, value: int64 = 5_000_000_000): Transaction =
  var scriptSig: seq[byte]
  if height == 0:
    scriptSig = @[byte(0x01), 0x00]
  elif height < 256:
    scriptSig = @[byte(0x01), byte(height)]
  else:
    scriptSig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff)]

  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xFFFFFFFF'u32
      ),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: makeP2PKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

# Create a v3 (TRUC) transaction
proc makeTrucTx(
  prevTxid: TxId,
  prevVout: uint32,
  outputValue: int64
): Transaction =
  Transaction(
    version: 3,  # TRUC version
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(outputValue),
      scriptPubKey: makeP2PKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

# Create a regular (non-TRUC) transaction
proc makeRegularTx(
  prevTxid: TxId,
  prevVout: uint32,
  outputValue: int64
): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(outputValue),
      scriptPubKey: makeP2PKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeTestBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: txs
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeCoinbaseTx(height)
  makeTestBlock(prevHash, height, @[coinbase])

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

suite "TRUC constants":
  test "v3 policy constants":
    check TrucVersion == 3
    check TrucAncestorLimit == 2
    check TrucDescendantLimit == 2
    check TrucMaxVsize == 10_000
    check TrucMaxWeight == 40_000
    check TrucChildMaxVsize == 1_000
    check TrucChildMaxWeight == 4_000

suite "TRUC isTruc helper":
  test "v3 transaction is TRUC":
    let tx = Transaction(version: 3, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    check tx.isTruc

  test "v2 transaction is not TRUC":
    let tx = Transaction(version: 2, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    check not tx.isTruc

  test "v1 transaction is not TRUC":
    let tx = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    check not tx.isTruc

suite "TRUC version inheritance":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "v3 cannot spend from unconfirmed non-v3":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add a v2 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 2,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Try to add a v3 child that spends from the v2 parent
    let childTx = makeTrucTx(TxId(parentTxid), 0, 500)

    let trucResult = mp.checkSingleTrucRules(childTx, 400, initHashSet[TxId]())
    check not trucResult.isOk
    check "cannot spend from non-version=3" in trucResult.error

    cs.close()

  test "non-v3 cannot spend from unconfirmed v3":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add a v3 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Try to add a v2 child that spends from the v3 parent
    let childTx = makeRegularTx(TxId(parentTxid), 0, 500)

    let trucResult = mp.checkSingleTrucRules(childTx, 400, initHashSet[TxId]())
    check not trucResult.isOk
    check "non-version=3 tx" in trucResult.error
    check "cannot spend from version=3" in trucResult.error

    cs.close()

  test "v3 can spend from confirmed outputs (no version restriction)":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # v3 tx spending confirmed output (no mempool parents)
    var confirmedTxid: array[32, byte]
    confirmedTxid[0] = 0xAA
    let childTx = makeTrucTx(TxId(confirmedTxid), 0, 500)

    # No mempool parents, so version inheritance check should pass
    let trucResult = mp.checkSingleTrucRules(childTx, 400, initHashSet[TxId]())
    check trucResult.isOk

    cs.close()

suite "TRUC ancestor limits":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "v3 tx can have one unconfirmed parent":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add a v3 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # v3 child with one parent should pass
    let childTx = makeTrucTx(TxId(parentTxid), 0, 500)
    let trucResult = mp.checkSingleTrucRules(childTx, 400, initHashSet[TxId]())
    check trucResult.isOk

    cs.close()

  test "v3 tx cannot have two unconfirmed parents":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add two v3 parents to mempool
    var parent1Txid: array[32, byte]
    parent1Txid[0] = 0x01
    var parent2Txid: array[32, byte]
    parent2Txid[0] = 0x02

    for parentTxid in [parent1Txid, parent2Txid]:
      let parentTx = Transaction(
        version: 3,
        inputs: @[],
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
        witnesses: @[],
        lockTime: 0
      )
      mp.entries[TxId(parentTxid)] = MempoolEntry(
        tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
        ancestorCount: 1, ancestorSize: 100
      )

    # v3 child spending from both parents (2 unconfirmed ancestors)
    let childTx = Transaction(
      version: 3,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: TxId(parent1Txid), vout: 0), scriptSig: @[byte(0x00)], sequence: 0),
        TxIn(prevOut: OutPoint(txid: TxId(parent2Txid), vout: 0), scriptSig: @[byte(0x00)], sequence: 0)
      ],
      outputs: @[TxOut(value: Satoshi(1500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let trucResult = mp.checkSingleTrucRules(childTx, 400, initHashSet[TxId]())
    check not trucResult.isOk
    check "too many ancestors" in trucResult.error

    cs.close()

suite "TRUC descendant limits":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "v3 parent cannot have two children":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add v3 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript()), TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Add first child
    var child1Txid: array[32, byte]
    child1Txid[0] = 0x02
    let child1Tx = Transaction(
      version: 3,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[byte(0x00)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(child1Txid)] = MempoolEntry(
      tx: child1Tx, txid: TxId(child1Txid), fee: Satoshi(500),
      weight: 400, feeRate: 5.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(600), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200
    )

    # Try to add second child - should fail
    let child2Tx = Transaction(
      version: 3,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 1), scriptSig: @[byte(0x00)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let trucResult = mp.checkSingleTrucRules(child2Tx, 400, initHashSet[TxId]())
    check not trucResult.isOk or trucResult.siblingToEvict.isSome  # Either fails or suggests sibling eviction

    cs.close()

suite "TRUC size limits":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "v3 tx cannot exceed 10k vbytes":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create a v3 tx (no mempool parents)
    var confirmedTxid: array[32, byte]
    confirmedTxid[0] = 0xAA
    let tx = makeTrucTx(TxId(confirmedTxid), 0, 500)

    # Simulate weight that exceeds 10k vbytes (40k WU)
    let trucResult = mp.checkSingleTrucRules(tx, 50000, initHashSet[TxId]())  # 50k WU = 12.5k vbytes
    check not trucResult.isOk
    check "is too big" in trucResult.error
    check "10000" in trucResult.error

    cs.close()

  test "v3 child cannot exceed 1k vbytes":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add v3 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # v3 child with weight exceeding 1k vbytes (4k WU)
    let childTx = makeTrucTx(TxId(parentTxid), 0, 9000)
    let trucResult = mp.checkSingleTrucRules(childTx, 5000, initHashSet[TxId]())  # 5k WU = 1.25k vbytes
    check not trucResult.isOk
    check "child tx" in trucResult.error
    check "is too big" in trucResult.error
    check "1000" in trucResult.error

    cs.close()

  test "v3 child at 1k vbytes passes":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add v3 parent to mempool
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # v3 child with weight exactly 1k vbytes (4k WU)
    let childTx = makeTrucTx(TxId(parentTxid), 0, 9000)
    let trucResult = mp.checkSingleTrucRules(childTx, 4000, initHashSet[TxId]())  # 4k WU = 1k vbytes
    check trucResult.isOk

    cs.close()

suite "TRUC sibling eviction":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "sibling eviction suggested when adding second child":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add v3 parent
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 3,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(2000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Add first child (the sibling)
    var siblingTxid: array[32, byte]
    siblingTxid[0] = 0x02
    let siblingTx = Transaction(
      version: 3,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[byte(0x00)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(1500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )
    mp.entries[TxId(siblingTxid)] = MempoolEntry(
      tx: siblingTx, txid: TxId(siblingTxid), fee: Satoshi(500),
      weight: 400, feeRate: 5.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(600), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200
    )

    # Try to add second child that also spends from parent
    let newChildTx = Transaction(
      version: 3,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[byte(0x01)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    # Since this tx conflicts with the sibling (same input), RBF would be involved
    # For sibling eviction to apply, the sibling must be in conflicts
    var conflicts = initHashSet[TxId]()
    conflicts.incl(TxId(siblingTxid))

    let trucResult = mp.checkSingleTrucRules(newChildTx, 400, conflicts)
    # With sibling in conflicts, should pass or suggest sibling eviction
    check trucResult.isOk

    cs.close()

  test "sibling eviction requires sufficient fee":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var siblingTxid: array[32, byte]
    siblingTxid[0] = 0x02
    let siblingTx = Transaction(version: 3, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[TxId(siblingTxid)] = MempoolEntry(
      tx: siblingTx, txid: TxId(siblingTxid), fee: Satoshi(1000),  # High fee
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Sibling eviction with lower fee should fail
    let evictionResult = mp.checkTrucSiblingEviction(siblingTx, Satoshi(500), TxId(siblingTxid))
    check not evictionResult.isOk
    check "insufficient fee" in evictionResult.error

    cs.close()

  test "sibling eviction with sufficient fee passes":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var siblingTxid: array[32, byte]
    siblingTxid[0] = 0x02
    let siblingTx = Transaction(version: 3, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[TxId(siblingTxid)] = MempoolEntry(
      tx: siblingTx, txid: TxId(siblingTxid), fee: Satoshi(500),
      weight: 400, feeRate: 5.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(500), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Sibling eviction with higher fee should pass
    let evictionResult = mp.checkTrucSiblingEviction(siblingTx, Satoshi(600), TxId(siblingTxid))
    check evictionResult.isOk

    cs.close()

suite "TRUC v3 package validation":
  test "v3 cannot spend from non-v3 in package":
    let parent = Transaction(
      version: 2,  # Non-TRUC
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = Transaction(
      version: 3,  # TRUC child trying to spend from non-TRUC parent
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = checkPackageTrucRules(
      @[parent, child],
      proc(txid: TxId): bool = false,  # No mempool parents
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1
    )
    check not result.isOk
    check "cannot spend from non-version=3" in result.error

  test "non-v3 cannot spend from v3 in package":
    let parent = Transaction(
      version: 3,  # TRUC parent
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = Transaction(
      version: 2,  # Non-TRUC child trying to spend from TRUC parent
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = checkPackageTrucRules(
      @[parent, child],
      proc(txid: TxId): bool = false,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1
    )
    check not result.isOk
    check "non-version=3 tx" in result.error

  test "valid v3 parent-child package":
    let parent = Transaction(
      version: 3,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = Transaction(
      version: 3,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = checkPackageTrucRules(
      @[parent, child],
      proc(txid: TxId): bool = false,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1
    )
    check result.isOk

  test "package with two children of same parent fails":
    let parent = Transaction(
      version: 3,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(2000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child1 = Transaction(
      version: 3,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child2 = Transaction(
      version: 3,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x01)],  # Different scriptSig to make different txid
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(700), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = checkPackageTrucRules(
      @[parent, child1, child2],
      proc(txid: TxId): bool = false,
      proc(txid: TxId): bool = false,
      proc(txid: TxId): int = 1
    )
    check not result.isOk
    check "descendant count limit" in result.error

when isMainModule:
  discard
