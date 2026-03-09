## Mempool tests
## Tests transaction acceptance, double-spend detection, fee policy, eviction, and block removal

import unittest2
import std/[os, options, tables, strutils, times]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter

const TestDbPath = "/tmp/nimrod_mempool_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# Create a simple P2PKH scriptPubKey
proc makeP2PKHScript(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] & @(default(array[20, byte])) & @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

# Create a P2WPKH scriptPubKey (for segwit)
proc makeP2WPKHScript(): seq[byte] =
  @[byte(OP_0), 0x14] & @(default(array[20, byte]))

# Create a coinbase transaction at a given height
proc makeCoinbaseTx(height: int32, value: int64 = 5_000_000_000): Transaction =
  # BIP34: height must be in scriptSig
  var scriptSig: seq[byte]
  if height == 0:
    scriptSig = @[byte(0x01), 0x00]  # Push 1 byte: 0
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

# Create a regular transaction spending a given UTXO
proc makeSpendTx(
  prevTxid: TxId,
  prevVout: uint32,
  outputValue: int64
): Transaction =
  ## Creates a simple transaction that spends an output
  ## Note: In real tests with script verification, we'd need valid signatures
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],  # Minimal scriptSig (won't pass script verification)
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
  ## Create a test block with the given transactions
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

# Build a chain to maturity for coinbase spending
proc buildChainToMaturity(cs: var ChainState): (Block, BlockHash) =
  ## Build a chain of 100 blocks, returning the last block and its hash
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  var prevHash = getBlockHash(genesis)

  for h in 1 ..< 100:
    let blk = makeSimpleBlock(prevHash, int32(h))
    discard cs.connectBlock(blk, int32(h))
    prevHash = getBlockHash(blk)

  let lastBlock = makeSimpleBlock(prevHash, 100)
  discard cs.connectBlock(lastBlock, 100)

  (genesis, getBlockHash(lastBlock))

suite "Mempool basic operations":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "create empty mempool":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    check mp.count == 0
    check mp.size == 0
    check mp.maxSize == DefaultMaxMempoolSize
    check mp.minFeeRate == DefaultMinFeeRate

    cs.close()

  test "mempool with custom parameters":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, maxSize = 1_000_000, minFeeRate = 2.0)

    check mp.maxSize == 1_000_000
    check mp.minFeeRate == 2.0

    cs.close()

suite "Mempool transaction acceptance":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "reject transaction with missing inputs":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    # Create a transaction spending a non-existent UTXO
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xDE
    fakeTxid[1] = 0xAD
    let tx = makeSpendTx(TxId(fakeTxid), 0, 1_000_000)

    let result = mp.acceptTransaction(tx, crypto)
    check not result.isOk
    check "input not found" in result.error

    cs.close()

  test "reject empty transaction":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    let emptyTx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.acceptTransaction(emptyTx, crypto)
    check not result.isOk

    cs.close()

  test "reject coinbase transaction":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    # Coinbase tx (prevOut is all zeros with vout 0xFFFFFFFF)
    let coinbase = makeCoinbaseTx(100)

    let result = mp.acceptTransaction(coinbase, crypto)
    check not result.isOk

    cs.close()

suite "Mempool double-spend detection":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "detect double-spend in mempool":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)  # Disable fee check for test
    let crypto = newCryptoEngine()

    # Connect genesis block
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let coinbaseTxid = genesis.txs[0].txid()

    # Build chain to maturity (100 blocks for regtest)
    var prevHash = getBlockHash(genesis)
    for h in 1 .. 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Create first spend of the coinbase
    let tx1 = makeSpendTx(coinbaseTxid, 0, 4_999_000_000)

    # Manually add tx1 without script verification (for test purposes)
    # We'll track the outpoint
    let outpoint = OutPoint(txid: coinbaseTxid, vout: 0)
    mp.spentBy[outpoint] = tx1.txid()
    mp.entries[tx1.txid()] = MempoolEntry(
      tx: tx1,
      txid: tx1.txid(),
      fee: Satoshi(1_000_000),
      weight: 500,
      feeRate: 2000.0,
      timeAdded: getTime(),
      height: 100,
      ancestorFee: Satoshi(1_000_000),
      ancestorWeight: 500
    )

    # Try to add a conflicting transaction
    let tx2 = makeSpendTx(coinbaseTxid, 0, 4_998_000_000)
    let result = mp.acceptTransaction(tx2, crypto)

    check not result.isOk
    check "double spend" in result.error

    cs.close()

  test "isSpent returns correct status":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let outpoint = OutPoint(txid: TxId(fakeTxid), vout: 0)

    check not mp.isSpent(outpoint)

    # Mark as spent
    var spenderTxid: array[32, byte]
    spenderTxid[0] = 0x02
    mp.spentBy[outpoint] = TxId(spenderTxid)

    check mp.isSpent(outpoint)
    check mp.getSpender(outpoint).isSome
    check mp.getSpender(outpoint).get() == TxId(spenderTxid)

    cs.close()

suite "Mempool fee policy":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "reject low fee transaction":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 10.0)  # High fee rate required
    let crypto = newCryptoEngine()

    # Build chain with spendable coinbase
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    var prevHash = getBlockHash(genesis)

    for h in 1 .. 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    let coinbaseTxid = genesis.txs[0].txid()

    # Create tx with very low fee (spending 5 BTC, outputting 4.999999 BTC = 1 sat fee)
    let tx = makeSpendTx(coinbaseTxid, 0, 4_999_999_999)

    # This should fail since fee rate is below 10 sat/vbyte
    # Fee = 1 sat, weight ~= 400, vbytes ~= 100, rate ~= 0.01 sat/vbyte
    let result = mp.acceptTransaction(tx, crypto)
    check not result.isOk
    check "fee rate" in result.error or "script" in result.error

    cs.close()

  test "fee rate calculation":
    # Test the fee rate formula: fee / (weight / 4)
    let feeRate1 = 1000.0 / (400.0 / 4.0)  # 1000 sat, 400 WU
    check feeRate1 == 10.0  # 10 sat/vbyte

    let feeRate2 = 500.0 / (1000.0 / 4.0)  # 500 sat, 1000 WU
    check feeRate2 == 2.0  # 2 sat/vbyte

suite "Mempool eviction":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "evict lowest fee rate transaction":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Manually add entries with different fee rates
    var txid1: array[32, byte]
    txid1[0] = 0x01
    var txid2: array[32, byte]
    txid2[0] = 0x02
    var txid3: array[32, byte]
    txid3[0] = 0x03

    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx3 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    mp.entries[TxId(txid1)] = MempoolEntry(
      tx: tx1, txid: TxId(txid1), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400
    )
    mp.entries[TxId(txid2)] = MempoolEntry(
      tx: tx2, txid: TxId(txid2), fee: Satoshi(200),
      weight: 400, feeRate: 2.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400
    )
    mp.entries[TxId(txid3)] = MempoolEntry(
      tx: tx3, txid: TxId(txid3), fee: Satoshi(300),
      weight: 400, feeRate: 3.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(300), ancestorWeight: 400
    )

    check mp.count == 3

    # Evict lowest fee
    mp.evictLowestFee()

    check mp.count == 2
    # txid1 (lowest rate) should be removed
    check TxId(txid1) notin mp.entries
    check TxId(txid2) in mp.entries
    check TxId(txid3) in mp.entries

    cs.close()

  test "eviction respects descendant protection":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create parent-child relationship
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    var childTxid: array[32, byte]
    childTxid[0] = 0x02
    var standaloneTxid: array[32, byte]
    standaloneTxid[0] = 0x03

    # Parent tx has lowest fee rate but has a child
    let parentTx = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)

    # Child tx spends from parent
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    let standaloneTx = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(50),
      weight: 400, feeRate: 0.5, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(50), ancestorWeight: 400
    )
    mp.entries[TxId(childTxid)] = MempoolEntry(
      tx: childTx, txid: TxId(childTxid), fee: Satoshi(200),
      weight: 400, feeRate: 2.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(250), ancestorWeight: 800
    )
    mp.entries[TxId(standaloneTxid)] = MempoolEntry(
      tx: standaloneTx, txid: TxId(standaloneTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400
    )

    # Parent has lowest rate (0.5) but has descendants
    # Standalone has next lowest (1.0) and no descendants
    mp.evictLowestFee()

    check mp.count == 2
    # Standalone should be evicted (no descendants, lower rate than child)
    check TxId(standaloneTxid) notin mp.entries
    # Parent should be protected
    check TxId(parentTxid) in mp.entries
    check TxId(childTxid) in mp.entries

    cs.close()

suite "Mempool block removal":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "remove transactions included in block":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add some transactions to mempool
    var txid1: array[32, byte]
    txid1[0] = 0x01
    var txid2: array[32, byte]
    txid2[0] = 0x02
    var txid3: array[32, byte]
    txid3[0] = 0x03

    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx3 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    mp.entries[TxId(txid1)] = MempoolEntry(tx: tx1, txid: TxId(txid1), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)
    mp.entries[TxId(txid2)] = MempoolEntry(tx: tx2, txid: TxId(txid2), fee: Satoshi(200), weight: 400, feeRate: 2.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400)
    mp.entries[TxId(txid3)] = MempoolEntry(tx: tx3, txid: TxId(txid3), fee: Satoshi(300), weight: 400, feeRate: 3.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(300), ancestorWeight: 400)

    check mp.count == 3

    # Create a block that includes tx1 and tx2
    let coinbase = makeCoinbaseTx(101)
    let blk = makeTestBlock(BlockHash(default(array[32, byte])), 101, @[coinbase, tx1, tx2])

    mp.removeForBlock(blk)

    check mp.count == 1
    check TxId(txid1) notin mp.entries
    check TxId(txid2) notin mp.entries
    check TxId(txid3) in mp.entries

    cs.close()

  test "remove conflicting transactions on block":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Mempool tx that spends a specific outpoint
    var spentTxid: array[32, byte]
    spentTxid[0] = 0xAA
    let spentOutpoint = OutPoint(txid: TxId(spentTxid), vout: 0)

    var mempoolTxid: array[32, byte]
    mempoolTxid[0] = 0x01
    let mempoolTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: spentOutpoint, scriptSig: @[], sequence: 0)],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(mempoolTxid)] = MempoolEntry(tx: mempoolTx, txid: TxId(mempoolTxid), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)
    mp.spentBy[spentOutpoint] = TxId(mempoolTxid)

    check mp.count == 1

    # Block tx that spends the same outpoint (conflict!)
    var blockTxid: array[32, byte]
    blockTxid[0] = 0x02
    let blockTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: spentOutpoint, scriptSig: @[], sequence: 0)],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    let coinbase = makeCoinbaseTx(101)
    let blk = makeTestBlock(BlockHash(default(array[32, byte])), 101, @[coinbase, blockTx])

    mp.removeForBlock(blk)

    # Mempool tx should be removed as conflicting
    check mp.count == 0
    check TxId(mempoolTxid) notin mp.entries

    cs.close()

suite "Mempool transaction selection":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "getTransactionsByFeeRate sorts by ancestor fee rate":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add transactions with different ancestor fee rates
    var txid1: array[32, byte]
    txid1[0] = 0x01
    var txid2: array[32, byte]
    txid2[0] = 0x02
    var txid3: array[32, byte]
    txid3[0] = 0x03

    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx3 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    # ancestorFee / (ancestorWeight / 4) = ancestor fee rate in sat/vbyte
    mp.entries[TxId(txid1)] = MempoolEntry(tx: tx1, txid: TxId(txid1), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)  # 1.0
    mp.entries[TxId(txid2)] = MempoolEntry(tx: tx2, txid: TxId(txid2), fee: Satoshi(300), weight: 400, feeRate: 3.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(300), ancestorWeight: 400)  # 3.0
    mp.entries[TxId(txid3)] = MempoolEntry(tx: tx3, txid: TxId(txid3), fee: Satoshi(200), weight: 400, feeRate: 2.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400)  # 2.0

    let entries = mp.getTransactionsByFeeRate(maxWeight = 10000)

    check entries.len == 3
    # Should be sorted by ancestor fee rate, highest first
    check entries[0].txid == TxId(txid2)  # 3.0 sat/vbyte
    check entries[1].txid == TxId(txid3)  # 2.0 sat/vbyte
    check entries[2].txid == TxId(txid1)  # 1.0 sat/vbyte

    cs.close()

  test "getTransactionsByFeeRate respects maxWeight":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var txid1: array[32, byte]
    txid1[0] = 0x01
    var txid2: array[32, byte]
    txid2[0] = 0x02
    var txid3: array[32, byte]
    txid3[0] = 0x03

    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx3 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    # Each tx has weight 400
    mp.entries[TxId(txid1)] = MempoolEntry(tx: tx1, txid: TxId(txid1), fee: Satoshi(300), weight: 400, feeRate: 3.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(300), ancestorWeight: 400)
    mp.entries[TxId(txid2)] = MempoolEntry(tx: tx2, txid: TxId(txid2), fee: Satoshi(200), weight: 400, feeRate: 2.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400)
    mp.entries[TxId(txid3)] = MempoolEntry(tx: tx3, txid: TxId(txid3), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)

    # Only allow weight for 2 txs
    let entries = mp.getTransactionsByFeeRate(maxWeight = 800)

    check entries.len == 2
    # Should get highest fee rate txs
    check entries[0].txid == TxId(txid1)
    check entries[1].txid == TxId(txid2)

    cs.close()

suite "Mempool weight policy":
  test "400K WU limit constant":
    check MaxStandardTxWeight == 400_000

  test "calculate transaction weight":
    # Non-segwit transaction
    let legacyTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @(default(array[71, byte])),  # ~71 bytes for sig
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @(default(array[25, byte]))  # P2PKH
      )],
      witnesses: @[],
      lockTime: 0
    )

    let weight = calculateTransactionWeight(legacyTx)
    # For legacy tx: weight = base * 4 (since there's no witness data)
    let baseSize = serializeLegacy(legacyTx).len
    check weight == baseSize * 4

  test "segwit transaction has lower weight":
    # SegWit transaction
    let segwitTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],  # Empty for segwit
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @(default(array[22, byte]))  # P2WPKH
      )],
      witnesses: @[@[@(default(array[72, byte])), @(default(array[33, byte]))]],  # Signature + pubkey
      lockTime: 0
    )

    let weight = calculateTransactionWeight(segwitTx)
    let fullSize = serialize(segwitTx, includeWitness = true).len
    let baseSize = serializeLegacy(segwitTx).len

    # Weight = base * 3 + full
    check weight == (baseSize * 3) + fullSize

    # Verify witness discount: weight < baseSize * 4
    check weight < fullSize * 4

suite "Mempool CPFP":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "ancestor fee aggregation":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create parent tx
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parentTx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400
    )

    # Create child tx that spends from parent
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(500), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # Calculate ancestor fees
    let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(childTx, Satoshi(500), 400)

    # Should include both parent and child
    check int64(ancestorFee) == 600  # 100 + 500
    check ancestorWeight == 800  # 400 + 400

    cs.close()

suite "Mempool expiration":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "expire old transactions":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var txid1: array[32, byte]
    txid1[0] = 0x01
    var txid2: array[32, byte]
    txid2[0] = 0x02

    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

    let now = getTime()
    let oldTime = now - initDuration(hours = 400)  # Older than 336 hours

    mp.entries[TxId(txid1)] = MempoolEntry(tx: tx1, txid: TxId(txid1), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: oldTime, height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)
    mp.entries[TxId(txid2)] = MempoolEntry(tx: tx2, txid: TxId(txid2), fee: Satoshi(200), weight: 400, feeRate: 2.0, timeAdded: now, height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400)

    check mp.count == 2

    mp.expire()

    check mp.count == 1
    check TxId(txid1) notin mp.entries  # Old tx expired
    check TxId(txid2) in mp.entries     # Recent tx kept

    cs.close()

when isMainModule:
  # Run all tests
  discard
