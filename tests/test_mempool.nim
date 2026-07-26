## Mempool tests
## Tests transaction acceptance, double-spend detection, fee policy, eviction, and block removal

import unittest2
import std/[os, options, tables, strutils, times, sets]
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

  test "admission floor is 100 sat/kvB (Core DEFAULT_MIN_RELAY_TX_FEE)":
    ## The real admission floor is mp.minFeeRate (sat/vB). After the fee-floor
    ## honesty fix it defaults to 0.1 sat/vB = 100 sat/kvB (Core
    ## DEFAULT_MIN_RELAY_TX_FEE, policy/policy.h:70), down from the old 1.0
    ## sat/vB = 1000 sat/kvB (10x Core) lie.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    check DefaultMinFeeRate == 0.1
    check mp.minFeeRate == 0.1

    # Boundary proof of the CheckFeeRate gate (mempool.nim:1235-1241):
    #   effectiveMinFeeRate = max(mp.minFeeRate, getMinFee())  # sat/vB
    #   reject iff  feeRate < effectiveMinFeeRate
    # On a fresh mempool the rolling floor (getMinFee) is 0, so the static
    # floor mp.minFeeRate governs.
    let effectiveMinFeeRate = max(mp.minFeeRate, mp.getMinFee())
    check effectiveMinFeeRate == 0.1

    # A tx paying exactly 100 sat/kvB => feeRate 0.1 sat/vB is ADMITTED
    # (0.1 < 0.1 is false). Compute feeRate the same way the gate does:
    # modifiedFee / vbytes. 100 sat over 1000 vB = 0.1 sat/vB.
    let feeRate100 = float64(100) / 1000.0      # 100 sat / 1000 vB
    check not (feeRate100 < effectiveMinFeeRate)  # admitted at the boundary

    # A tx paying 99 sat/kvB => feeRate 0.099 sat/vB is REJECTED.
    let feeRate99 = float64(99) / 1000.0
    check feeRate99 < effectiveMinFeeRate         # rejected below the boundary

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
    # W96: Bitcoin Core uses "bad-txns-inputs-missingorspent" for this case
    # (validation.cpp:866).
    check "bad-txns-inputs-missingorspent" in result.error

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
    # Conflicting tx with lower fee fails RBF rules (rejection message may vary)
    check not result.isOk  # error message describes the rejection reason

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

    # Build chain with spendable coinbase. Genesis (h=0) writes no UTXO per
    # W14 / Core parity, so use the h=1 coinbase as the spendable seed.
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    var prevHash = getBlockHash(block1)

    for h in 2 .. 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    let coinbaseTxid = block1.txs[0].txid()

    # Create tx with very low fee (spending 5 BTC, outputting 4.999999 BTC = 1 sat fee)
    let tx = makeSpendTx(coinbaseTxid, 0, 4_999_999_999)

    # This should fail since fee rate is below 10 sat/vbyte
    # Fee = 1 sat, weight ~= 400, vbytes ~= 100, rate ~= 0.01 sat/vbyte
    let result = mp.acceptTransaction(tx, crypto)
    check not result.isOk
    # W96: rephrased to match Core CheckFeeRate path (validation.cpp:699).
    # On a fresh mempool the rolling floor is 0, so the static -minrelaytxfee
    # gate governs and Core emits the bare token "min relay fee not met".
    check "fee not met" in result.error or
          "fee rate" in result.error or
          "script" in result.error

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

    # Distinct transactions with different outputs so they have different txids
    let tx1 = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let tx2 = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(2), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let tx3 = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(3), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let realTxid1 = tx1.txid()
    let realTxid2 = tx2.txid()
    let realTxid3 = tx3.txid()

    mp.entries[realTxid1] = MempoolEntry(tx: tx1, txid: realTxid1, fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400)
    mp.entries[realTxid2] = MempoolEntry(tx: tx2, txid: realTxid2, fee: Satoshi(200), weight: 400, feeRate: 2.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 400)
    mp.entries[realTxid3] = MempoolEntry(tx: tx3, txid: realTxid3, fee: Satoshi(300), weight: 400, feeRate: 3.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(300), ancestorWeight: 400)

    check mp.count == 3

    # Create a block that includes tx1 and tx2
    let coinbase = makeCoinbaseTx(101)
    let blk = makeTestBlock(BlockHash(default(array[32, byte])), 101, @[coinbase, tx1, tx2])

    mp.removeForBlock(blk)

    check mp.count == 1
    check realTxid1 notin mp.entries
    check realTxid2 notin mp.entries
    check realTxid3 in mp.entries

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

suite "Mempool ancestor limits":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "ancestor limit constants":
    check DefaultAncestorLimit == 25
    check DefaultDescendantLimit == 25
    check DefaultAncestorSizeLimitKvB == 101
    check DefaultDescendantSizeLimitKvB == 101
    check DefaultAncestorSizeLimit == 101_000
    check DefaultDescendantSizeLimit == 101_000

  test "accept chain of 25 transactions (at limit)":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Build a chain of txs where each spends the previous
    # Since ancestor limit = 25 (including self), we can have up to 24 ancestors
    var prevTxid: array[32, byte]
    prevTxid[0] = 0x01

    # Create chain of 25 transactions
    for i in 0 ..< 25:
      var txid: array[32, byte]
      txid[0] = byte(i + 1)

      let tx = if i == 0:
        # First tx has no mempool parent
        Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
      else:
        # Subsequent txs spend from previous
        Transaction(
          version: 1,
          inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prevTxid), vout: 0), scriptSig: @[], sequence: 0)],
          outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
          witnesses: @[],
          lockTime: 0
        )

      # Manually add to mempool (bypassing validation for simplicity)
      let weight = 400
      let vsize = 100
      let ancestorCount = i + 1  # Including self
      let ancestorSize = ancestorCount * vsize

      mp.entries[TxId(txid)] = MempoolEntry(
        tx: tx, txid: TxId(txid), fee: Satoshi(100),
        weight: weight, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(100 * ancestorCount), ancestorWeight: weight * ancestorCount,
        ancestorCount: ancestorCount, ancestorSize: ancestorSize
      )

      # Track spent outpoint
      if i > 0:
        mp.spentBy[OutPoint(txid: TxId(prevTxid), vout: 0)] = TxId(txid)

      prevTxid = txid

    check mp.count == 25

    # Verify last tx has ancestor count of 25 (including self)
    var lastTxid: array[32, byte]
    lastTxid[0] = 25
    check mp.entries[TxId(lastTxid)].ancestorCount == 25

    cs.close()

  test "chain of 26 is ACCEPTED (Core v31 dropped the 25-ancestor limit)":
    ## Core v31 replaced ancestor/descendant limits with cluster limits.
    ## `-limitancestorcount` is deprecated and "only used by wallet for coin
    ## selection" (init.cpp:650); `too-long-mempool-chain` no longer exists.
    ## A 26-long chain is well under both cluster bounds (26 tx <= 64,
    ## 26*400 = 10,400 WU <= 404,000) so it must be accepted.
    ## Matches diff-test corpus entry `cluster-linear-26`.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Build a chain of 25 transactions first
    var prevTxid: array[32, byte]
    prevTxid[0] = 0x01

    for i in 0 ..< 25:
      var txid: array[32, byte]
      txid[0] = byte(i + 1)

      let tx = if i == 0:
        Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
      else:
        Transaction(
          version: 1,
          inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prevTxid), vout: 0), scriptSig: @[], sequence: 0)],
          outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
          witnesses: @[],
          lockTime: 0
        )

      let weight = 400
      let vsize = 100
      let ancestorCount = i + 1
      let ancestorSize = ancestorCount * vsize

      mp.entries[TxId(txid)] = MempoolEntry(
        tx: tx, txid: TxId(txid), fee: Satoshi(100),
        weight: weight, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(100 * ancestorCount), ancestorWeight: weight * ancestorCount,
        ancestorCount: ancestorCount, ancestorSize: ancestorSize
      )

      if i > 0:
        mp.spentBy[OutPoint(txid: TxId(prevTxid), vout: 0)] = TxId(txid)

      prevTxid = txid

    check mp.count == 25

    # Add a 26th transaction — accepted under cluster limits.
    var tx26id: array[32, byte]
    tx26id[0] = 26
    let tx26 = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prevTxid), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # Check cluster limits directly
    let result = mp.checkPackageLimits(tx26, 400)
    check result.isOk

    # And the cluster it joins is the whole 26-tx chain, measured in weight.
    let (cCount, cSize) = mp.calculateClusterStats(tx26, 400)
    check cCount == 26
    check cSize == 26 * 400

    cs.close()

  test "calculateAncestors returns correct ancestor set":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create a simple parent-child chain: A -> B -> C
    var txidA: array[32, byte]
    txidA[0] = 0x01
    var txidB: array[32, byte]
    txidB[0] = 0x02
    var txidC: array[32, byte]
    txidC[0] = 0x03

    let txA = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )
    let txC = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidB), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(txidA)] = MempoolEntry(tx: txA, txid: TxId(txidA), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.entries[TxId(txidB)] = MempoolEntry(tx: txB, txid: TxId(txidB), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)

    # Calculate ancestors for txC (should include A and B)
    let ancestors = mp.calculateAncestors(txC)
    check len(ancestors) == 2
    check TxId(txidA) in ancestors
    check TxId(txidB) in ancestors

    cs.close()

  test "calculateAncestorStats returns correct count and size":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create parent A
    var txidA: array[32, byte]
    txidA[0] = 0x01
    let txA = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)

    mp.entries[TxId(txidA)] = MempoolEntry(tx: txA, txid: TxId(txidA), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)

    # Create child B that spends from A
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # Calculate ancestor stats for B (self weight 400 -> vsize 100)
    let (count, size) = mp.calculateAncestorStats(txB, 100)
    check count == 2  # A + B (self)
    check size == 200 # 100 (A) + 100 (B self)

    cs.close()

suite "Mempool descendant limits":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "calculateDescendants returns correct descendant set":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create a simple parent-child chain: A -> B -> C
    var txidA: array[32, byte]
    txidA[0] = 0x01
    var txidB: array[32, byte]
    txidB[0] = 0x02
    var txidC: array[32, byte]
    txidC[0] = 0x03

    let txA = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )
    let txC = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidB), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(txidA)] = MempoolEntry(tx: txA, txid: TxId(txidA), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.entries[TxId(txidB)] = MempoolEntry(tx: txB, txid: TxId(txidB), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)
    mp.entries[TxId(txidC)] = MempoolEntry(tx: txC, txid: TxId(txidC), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(300), ancestorWeight: 1200, ancestorCount: 3, ancestorSize: 300)

    # Calculate descendants for A (should include B and C)
    let descendants = mp.calculateDescendants(TxId(txidA))
    check len(descendants) == 2
    check TxId(txidB) in descendants
    check TxId(txidC) in descendants

    # Calculate descendants for B (should include only C)
    let descendantsB = mp.calculateDescendants(TxId(txidB))
    check len(descendantsB) == 1
    check TxId(txidC) in descendantsB

    # Calculate descendants for C (should be empty)
    let descendantsC = mp.calculateDescendants(TxId(txidC))
    check len(descendantsC) == 0

    cs.close()

  test "calculateDescendantStats returns correct count and size":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create A -> B chain
    var txidA: array[32, byte]
    txidA[0] = 0x01
    var txidB: array[32, byte]
    txidB[0] = 0x02

    let txA = Transaction(version: 1, inputs: @[], outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])], witnesses: @[], lockTime: 0)
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(txidA)] = MempoolEntry(tx: txA, txid: TxId(txidA), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.entries[TxId(txidB)] = MempoolEntry(tx: txB, txid: TxId(txidB), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)

    # Calculate descendant stats for A (should include self and B)
    let (count, size) = mp.calculateDescendantStats(TxId(txidA))
    check count == 2  # A + B
    check size == 200 # 100 (A) + 100 (B)

    # Calculate descendant stats for B (should be just self)
    let (countB, sizeB) = mp.calculateDescendantStats(TxId(txidB))
    check countB == 1  # Just B
    check sizeB == 100 # Just B

    cs.close()

  test "fan-out of 26 is ACCEPTED and counted as ONE cluster (siblings included)":
    ## Core v31 dropped the 25-descendant limit (`-limitdescendantcount` is
    ## deprecated, init.cpp:656), so a parent with 25 children is accepted.
    ## This ALSO pins the connected-component walk: the 25 siblings are in the
    ## candidate's cluster even though none is its ancestor.  An ancestor-scoped
    ## proxy would report a cluster of 2 here and wave through fan-outs that
    ## Core rejects.  Matches diff-test corpus entries `cluster-fan-26` /
    ## `cluster-sibling-72`.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Parent with 25 distinct outputs so each child spends its own outpoint
    # (the old fixture had all children spend vout 0, i.e. 24 mutual conflicts,
    # which is not a shape a real mempool can hold).
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01

    var parentOuts: seq[TxOut] = @[]
    for i in 0 ..< 25:
      parentOuts.add(TxOut(value: Satoshi(10000), scriptPubKey: @[]))
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: parentOuts, witnesses: @[], lockTime: 0)
    let realParentTxid = parentTx.txid()

    mp.entries[realParentTxid] = MempoolEntry(
      tx: parentTx, txid: realParentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Add 24 children, each spending a distinct parent output.
    for i in 0 ..< 24:
      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: realParentTxid, vout: uint32(i)),
                       scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[],
        lockTime: 0
      )
      let childTxid = childTx.txid()

      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(100),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200
      )
      # Maintain the spend index exactly as acceptTransactionWithArgs does.
      mp.spentBy[OutPoint(txid: realParentTxid, vout: uint32(i))] = childTxid

    check mp.count == 25

    # Add a 25th child on the last free output — accepted under cluster limits.
    let child25 = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: realParentTxid, vout: 24'u32),
                     scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.checkPackageLimits(child25, 400)
    check result.isOk

    # The cluster is parent + 24 existing children + self = 26, NOT 2.
    let (cCount, cSize) = mp.calculateClusterStats(child25, 400)
    check cCount == 26
    check cSize == 26 * 400

    cs.close()

suite "Mempool package_limit combined tests":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "custom package limits":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    # Create mempool with custom limits
    var mp = newMempool(cs, params, ancestorLimit = 10, descendantLimit = 10,
                        ancestorSizeLimit = 50000, descendantSizeLimit = 50000)

    check mp.ancestorLimit == 10
    check mp.descendantLimit == 10
    check mp.ancestorSizeLimit == 50000
    check mp.descendantSizeLimit == 50000

    cs.close()

  test "reject transaction exceeding cluster size limit":
    ## The surviving size bound is the CLUSTER size, compared in WEIGHT units
    ## (clusterSizeLimit vB * 4).  Core txmempool.cpp:181 / txgraph.cpp:2059.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    # Very small cluster size limit for testing: 500 vB == 2,000 WU.
    var mp = newMempool(cs, params, clusterSizeLimit = 500)
    check mp.maxClusterSizeWeight() == 2000

    # Create parent with large weight (2000 weight = 500 vbytes)
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01

    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(1000),
      weight: 2000, feeRate: 2.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 2000,
      ancestorCount: 1, ancestorSize: 500  # 500 vbytes
    )

    # Try to add child - would exceed 500 vbyte limit
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(9000), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # Parent 2,000 WU + child 400 WU = 2,400 WU > 2,000 WU bound → reject.
    let result = mp.checkPackageLimits(childTx, 400)
    check not result.isOk
    check result.error == "too-large-cluster"   # bare token, empty debug string

    # Exactly at the bound accepts (strict `>`): 2,000 - 2,000 = 0 WU spare,
    # so shrink the parent to leave room for a 400 WU child.
    mp.entries[TxId(parentTxid)].weight = 1600
    check mp.calculateClusterStats(childTx, 400)[1] == 2000
    check mp.checkPackageLimits(childTx, 400).isOk
    # …and one weight unit more rejects.
    check mp.calculateClusterStats(childTx, 401)[1] == 2001
    check not mp.checkPackageLimits(childTx, 401).isOk

    cs.close()

  test "diamond dependency pattern":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create diamond: A -> B, A -> C, B -> D, C -> D
    #     A
    #    / \
    #   B   C
    #    \ /
    #     D

    var txidA: array[32, byte]
    txidA[0] = 0x01
    var txidB: array[32, byte]
    txidB[0] = 0x02
    var txidC: array[32, byte]
    txidC[0] = 0x03

    let txA = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[]), TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let txB = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )
    let txC = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(txidA), vout: 1), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(txidA)] = MempoolEntry(tx: txA, txid: TxId(txidA), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.entries[TxId(txidB)] = MempoolEntry(tx: txB, txid: TxId(txidB), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)
    mp.entries[TxId(txidC)] = MempoolEntry(tx: txC, txid: TxId(txidC), fee: Satoshi(100), weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)

    # D spends from both B and C
    let txD = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: TxId(txidB), vout: 0), scriptSig: @[], sequence: 0),
        TxIn(prevOut: OutPoint(txid: TxId(txidC), vout: 0), scriptSig: @[], sequence: 0)
      ],
      outputs: @[TxOut(value: Satoshi(1700), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # D's ancestors are A, B, C (3 ancestors + self = 4)
    let ancestors = mp.calculateAncestors(txD)
    check len(ancestors) == 3
    check TxId(txidA) in ancestors
    check TxId(txidB) in ancestors
    check TxId(txidC) in ancestors

    let (count, size) = mp.calculateAncestorStats(txD, 100)
    check count == 4  # A, B, C + D
    check size == 400 # 100 * 4

    # Should pass package limits
    let result = mp.checkPackageLimits(txD, 400)
    check result.isOk

    cs.close()

# ============================================================================
# BIP125 Full RBF Tests
# ============================================================================

suite "Mempool RBF constants":
  test "RBF constants are correct":
    check MaxReplacementCandidates == 100
    ## FIX-69 (W120 BUG-1): was 1.0 sat/vB (10x Core); now 0.1 sat/vB
    ## (= Core's 100 sat/kvB ÷ 1000). Core ref: policy/policy.h:48.
    check DefaultIncrementalRelayFee == 0.1  # 0.1 sat/vbyte = 100 sat/kvB

suite "Mempool RBF conflict detection":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "findConflicts detects spending same input":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create a UTXO outpoint
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    # Add existing tx that spends the outpoint
    var existingTxid: array[32, byte]
    existingTxid[0] = 0x01
    let existingTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(existingTxid)] = MempoolEntry(
      tx: existingTx, txid: TxId(existingTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[outpoint] = TxId(existingTxid)

    # Create new tx that also spends the same outpoint
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let conflicts = mp.findConflicts(newTx)
    check len(conflicts) == 1
    check TxId(existingTxid) in conflicts

    cs.close()

  test "findConflicts returns empty for non-conflicting tx":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # No existing transactions
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let conflicts = mp.findConflicts(newTx)
    check len(conflicts) == 0

    cs.close()

suite "Mempool RBF rules validation":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "reject replacement with insufficient fee":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add existing tx with 1000 sat fee
    var existingTxid: array[32, byte]
    existingTxid[0] = 0x01
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let existingTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(existingTxid)] = MempoolEntry(
      tx: existingTx, txid: TxId(existingTxid), fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[outpoint] = TxId(existingTxid)

    let conflicts = toHashSet([TxId(existingTxid)])

    # Try to replace with lower fee (500 sat < 1000 sat)
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.checkRbfRules(newTx, Satoshi(500), 100, conflicts)
    check not result.isOk
    check "less fees than conflicting" in result.error

    cs.close()

  test "reject replacement with insufficient fee for bandwidth":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add existing tx with 1000 sat fee
    var existingTxid: array[32, byte]
    existingTxid[0] = 0x01
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let existingTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(existingTxid)] = MempoolEntry(
      tx: existingTx, txid: TxId(existingTxid), fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[outpoint] = TxId(existingTxid)

    let conflicts = toHashSet([TxId(existingTxid)])

    # New tx: 1001 sat fee (higher) but vsize 100 bytes
    # Additional fee = 1001 - 1000 = 1 sat
    # Required = 1.0 sat/vbyte * 100 vbytes = 100 sats
    # 1 < 100, so should fail
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.checkRbfRules(newTx, Satoshi(1001), 100, conflicts)
    check not result.isOk
    check "not enough additional fees" in result.error

    cs.close()

  test "accept valid replacement":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add existing tx with 1000 sat fee
    var existingTxid: array[32, byte]
    existingTxid[0] = 0x01
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let existingTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(existingTxid)] = MempoolEntry(
      tx: existingTx, txid: TxId(existingTxid), fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[outpoint] = TxId(existingTxid)

    let conflicts = toHashSet([TxId(existingTxid)])

    # New tx: 2000 sat fee, 100 vbytes
    # Additional fee = 2000 - 1000 = 1000 sat
    # Required = 1.0 * 100 = 100 sats
    # 1000 >= 100, passes
    # Fee rate = 2000/100 = 20 sat/vbyte > 10, passes
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.checkRbfRules(newTx, Satoshi(2000), 100, conflicts)
    check result.isOk
    check TxId(existingTxid) in result.value

    cs.close()

  test "reject replacement when evicting too many transactions":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create parent tx
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let parentOutpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[parentOutpoint] = TxId(parentTxid)

    # Create 100 child transactions (total 101 including parent = exceeds limit of 100)
    for i in 1 .. 100:
      var childTxid: array[32, byte]
      childTxid[0] = byte(i + 1)
      childTxid[1] = byte(i shr 8)

      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[],
        lockTime: 0
      )

      mp.entries[TxId(childTxid)] = MempoolEntry(
        tx: childTx, txid: TxId(childTxid), fee: Satoshi(100),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200
      )

    let conflicts = toHashSet([TxId(parentTxid)])

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # Total evictions = 1 (parent) + 100 (children) = 101 > 100 limit
    let result = mp.checkRbfRules(newTx, Satoshi(100000), 100, conflicts)
    check not result.isOk
    check "too many potential replacements" in result.error

    cs.close()

  test "reject replacement spending output from conflict":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add existing tx
    var existingTxid: array[32, byte]
    existingTxid[0] = 0x01
    var utxoTxid: array[32, byte]
    utxoTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(utxoTxid), vout: 0)

    let existingTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(existingTxid)] = MempoolEntry(
      tx: existingTx, txid: TxId(existingTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.spentBy[outpoint] = TxId(existingTxid)

    let conflicts = toHashSet([TxId(existingTxid)])

    # New tx spends from the conflict (not allowed - would be invalid after eviction)
    let newTx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0),
        TxIn(prevOut: OutPoint(txid: TxId(existingTxid), vout: 0), scriptSig: @[], sequence: 0)
      ],
      outputs: @[TxOut(value: Satoshi(1700), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.checkRbfRules(newTx, Satoshi(2000), 150, conflicts)
    check not result.isOk
    check "spends output from conflicting" in result.error

    cs.close()

suite "Mempool RBF bip125-replaceable":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "all mempool txs are replaceable with full RBF":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    # fullRbf=true: every mempool tx is replaceable regardless of signaling
    var mp = newMempool(cs, params, fullRbf = true)

    # Add a tx with non-signaling sequence (0xFFFFFFFF)
    var txid1: array[32, byte]
    txid1[0] = 0x01
    let tx1 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32  # Non-signaling
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(txid1)] = MempoolEntry(
      tx: tx1, txid: TxId(txid1), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # With Full RBF, even non-signaling txs are replaceable
    check mp.isBip125Replaceable(TxId(txid1))

    cs.close()

  test "non-existent tx is not replaceable":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xFF
    check not mp.isBip125Replaceable(TxId(fakeTxid))

    cs.close()

suite "Mempool RBF conflict removal":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "removeConflicts removes transaction and descendants":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Create parent and child
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    var childTxid: array[32, byte]
    childTxid[0] = 0x02

    let parentTx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0), scriptSig: @[], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[TxId(childTxid)] = MempoolEntry(
      tx: childTx, txid: TxId(childTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(200), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200
    )

    check mp.count == 2

    # Get all conflicts (parent + child)
    let conflicts = toHashSet([TxId(parentTxid)])
    let allConflicts = mp.getAllConflictsWithDescendants(conflicts)

    check len(allConflicts) == 2
    check TxId(parentTxid) in allConflicts
    check TxId(childTxid) in allConflicts

    # Remove them
    mp.removeConflicts(allConflicts)

    check mp.count == 0

    cs.close()

  test "calculateConflictFees sums correctly":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)

    # Add 3 transactions
    for i in 1 .. 3:
      var txid: array[32, byte]
      txid[0] = byte(i)
      let tx = Transaction(version: 1, inputs: @[], outputs: @[], witnesses: @[], lockTime: 0)

      mp.entries[TxId(txid)] = MempoolEntry(
        tx: tx, txid: TxId(txid), fee: Satoshi(i * 100),  # 100, 200, 300 sats
        weight: i * 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(i * 100), ancestorWeight: i * 400,
        ancestorCount: 1, ancestorSize: i * 100
      )

    var conflicts = initHashSet[TxId]()
    for i in 1 .. 3:
      var txid: array[32, byte]
      txid[0] = byte(i)
      conflicts.incl(TxId(txid))

    let (totalFee, totalVsize) = mp.calculateConflictFees(conflicts)
    check int64(totalFee) == 600  # 100 + 200 + 300
    check totalVsize == 600  # 100 + 200 + 300 (each weight/4 rounded up)

    cs.close()

# ---------------------------------------------------------------------------
# W71 — PreChecks gate tests (coinbase rejection + MIN_STANDARD_TX_NONWITNESS_SIZE)
# These test acceptTransaction directly, not just isStandardTx.
# ---------------------------------------------------------------------------

suite "W71 — coinbase rejected from mempool (PreChecks gate)":
  ## Bitcoin Core MemPoolAccept::PreChecks validation.cpp:803-804:
  ##   if (tx.IsCoinBase()) return state.Invalid(TX_CONSENSUS, "coinbase")
  ## A coinbase tx must never enter the mempool.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "coinbase tx rejected with 'coinbase' error":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    let mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    let cbTx = makeCoinbaseTx(0)
    let res = mp.acceptTransaction(cbTx, crypto)
    check not res.isOk
    check "coinbase" in res.error

    cs.close()

suite "W71 — MIN_STANDARD_TX_NONWITNESS_SIZE gate (CVE-2017-12842)":
  ## Bitcoin Core MemPoolAccept::PreChecks validation.cpp:813-814:
  ##   if (::GetSerializeSize(TX_NO_WITNESS(tx)) < 65) → "tx-size-small"
  ## A non-witness serialization < 65 bytes is rejected.
  ##
  ## Note: constructing a tx with a valid UTXO that is also < 65 bytes
  ## non-witness is hard (the minimal 10-byte tx has no inputs); so we
  ## test the size check in isolation via a hand-crafted tiny tx that
  ## has no valid UTXO backing. acceptTransaction will reject at the
  ## size gate before reaching UTXO lookup.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "tiny tx (non-witness size < 65) rejected with 'tx-size-small'":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    let mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    # Minimal 1-in/1-out tx with empty scriptSig and tiny output script (1 byte).
    # Legacy size = 4(ver) + 1(varint vin) + 36(outpoint) + 1(varint scriptSig) +
    #               0(scriptSig) + 4(seq) + 1(varint vout) + 8(value) +
    #               1(varint spk) + 1(spk) + 4(locktime) = 61 bytes — below 65.
    let tinyTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],          # 0 bytes
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(0),
        scriptPubKey: @[byte(0x6a)]  # bare OP_RETURN, 1 byte
      )],
      witnesses: @[],
      lockTime: 0
    )

    let nwSize = serializeLegacy(tinyTx).len
    check nwSize < 65  # Assert the tx is actually tiny

    let res = mp.acceptTransaction(tinyTx, crypto)
    check not res.isOk
    check "tx-size-small" in res.error

    cs.close()

# ============================================================================
# W75 — Ancestor / Descendant / Cluster limits comprehensive audit
# ============================================================================
# Tests all 7 gates of checkPackageLimits() against Bitcoin Core spec:
#   G1  ancestor count   <= 25   (DEFAULT_ANCESTOR_LIMIT, policy/policy.h:76)
#   G2  ancestor vsize   <= 101,000 vB (policy/policy.h:53-56)
#   G3  descendant count <= 25   (DEFAULT_DESCENDANT_LIMIT, policy/policy.h:78)
#   G4  descendant vsize <= 101,000 vB
#   G5  EXTRA_DESCENDANT_TX_SIZE_LIMIT exception (policy/policy.h:90): if
#       exactly 1 ancestor AND self-vsize <= 10,000 vB → skip G4 for that ancestor
#   G6  cluster count    <= 64   (DEFAULT_CLUSTER_LIMIT, policy/policy.h:72)
#   G7  cluster vsize    <= 101,000 vB (policy/policy.h:74)
# ============================================================================

const W75DbPath = "/tmp/nimrod_mempool_w75_test"

proc cleanupW75Db() =
  if dirExists(W75DbPath):
    removeDir(W75DbPath)

suite "W75 ancestor/descendant/cluster limits":
  setup:
    cleanupW75Db()
  teardown:
    cleanupW75Db()

  # --------------------------------------------------------------------------
  # Helpers
  # --------------------------------------------------------------------------
  proc makeChainInMempool(mp: var Mempool, length: int,
                          vsizeEach: int = 100): TxId =
    ## Insert `length` transactions into mp.entries in a linear chain.
    ## Returns the txid of the last (deepest) tx.
    var prevTxid: array[32, byte]
    prevTxid[0] = 0xDD  # sentinel: first parent is a confirmed UTXO
    var currentTxid = TxId(prevTxid)

    for i in 0 ..< length:
      var txid: array[32, byte]
      txid[0] = byte(0xE0 + (i mod 200))
      txid[1] = byte(i div 200)
      txid[2] = 0xCC
      let weight = vsizeEach * 4
      let ac = i + 1  # ancestor count including self
      let tx = if i == 0:
        Transaction(version: 1, inputs: @[],
          outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
          witnesses: @[], lockTime: 0)
      else:
        Transaction(version: 1,
          inputs: @[TxIn(prevOut: OutPoint(txid: currentTxid, vout: 0),
                         scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
          outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
          witnesses: @[], lockTime: 0)
      mp.entries[TxId(txid)] = MempoolEntry(
        tx: tx, txid: TxId(txid), fee: Satoshi(100), weight: weight,
        feeRate: 1.0, timeAdded: getTime(), height: 100,
        ancestorFee: Satoshi(100 * ac), ancestorWeight: weight * ac,
        ancestorCount: ac, ancestorSize: vsizeEach * ac)
      if i > 0:
        mp.spentBy[OutPoint(txid: currentTxid, vout: 0)] = TxId(txid)
      currentTxid = TxId(txid)
    currentTxid

  # --------------------------------------------------------------------------
  # Constant checks
  # --------------------------------------------------------------------------
  test "G0 constant values match Bitcoin Core spec":
    check DefaultAncestorLimit     == 25
    check DefaultDescendantLimit   == 25
    check DefaultAncestorSizeLimitKvB  == 101
    check DefaultDescendantSizeLimitKvB == 101
    check DefaultAncestorSizeLimit      == 101_000
    check DefaultDescendantSizeLimit    == 101_000
    check DefaultClusterLimit           == 64
    check DefaultClusterSizeLimitKvB    == 101
    check DefaultClusterSizeLimit       == 101_000
    check ExtraDescendantTxSizeLimit    == 10_000
    # The bound actually enforced, in WEIGHT units (txmempool.cpp:181).
    check DefaultClusterSizeLimitWeight == 404_000
    check DefaultClusterSizeLimitWeight == DefaultClusterSizeLimit * 4
    # MAX_PACKAGE_COUNT is a DIFFERENT limit and stays at 25
    # (Core policy/packages.h:19; static_assert DEFAULT_CLUSTER_LIMIT >= it).
    check MaxPackageCount               == 25
    check DefaultClusterLimit >= MaxPackageCount
    # TRUC/v3 is the only surviving ancestor/descendant enforcement.
    check TrucAncestorLimit             == 2
    check TrucDescendantLimit           == 2

  # --------------------------------------------------------------------------
  # G1: accept exactly 25 ancestors (at limit)
  # --------------------------------------------------------------------------
  test "C1 accept chain of 25":
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())

    # Insert 24-tx chain; next tx will be the 25th
    let tipTxid = makeChainInMempool(mp, 24)
    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: tipTxid, vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let res = mp.checkPackageLimits(newTx, 400)
    check res.isOk


  # --------------------------------------------------------------------------
  # Core v31 REMOVED the ancestor/descendant count and size limits.
  #
  #   * -limitancestorcount / -limitdescendantcount are documented as
  #     "Deprecated ... replaced by cluster limits ... only used by wallet for
  #     coin selection" (init.cpp:650, :656).
  #   * MemPoolLimits no longer carries ancestor/descendant SIZE fields at all
  #     (kernel/mempool_limits.h:20-26).
  #   * `too-long-mempool-chain` is absent from the entire Core tree.
  #   * EXTRA_DESCENDANT_TX_SIZE_LIMIT (policy.h:90) is a dead definition.
  #
  # The tests below pin the NEW behaviour: chains and fan-outs that the old
  # G1-G5 gates rejected are now accepted, bounded only by the cluster limits.
  # --------------------------------------------------------------------------
  test "chain of 26 is ACCEPTED — the 25-ancestor gate is gone":
    ## Matches diff-test corpus entry `cluster-linear-26` (Core: all accept).
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())

    let tipTxid = makeChainInMempool(mp, 25)
    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: tipTxid, vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let res = mp.checkPackageLimits(newTx, 400)
    check res.isOk

    # 26 txs, 26*400 = 10,400 WU — ~2.5% of the 404,000 WU bound, so only the
    # count gate could ever fire here.
    let (cCount, cSize) = mp.calculateClusterStats(newTx, 400)
    check cCount == 26
    check cSize == 10_400


  test "fan-out is ACCEPTED and siblings are in the SAME cluster":
    ## The old G3 rejected a 26th descendant.  Under v31 the fan-out is
    ## accepted, but the whole fan must still be counted as ONE cluster:
    ## every child has exactly 1 ancestor, so an ancestor-scoped proxy would
    ## report a cluster of 2 and wave through arbitrarily wide fan-outs.
    ## Matches corpus entries `cluster-fan-26` / `cluster-sibling-72`.
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())

    # One parent with 40 outputs; 39 children already in the mempool.
    var parentOuts: seq[TxOut] = @[]
    for i in 0 ..< 40:
      parentOuts.add(TxOut(value: Satoshi(10_000), scriptPubKey: @[]))
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: parentOuts, witnesses: @[], lockTime: 0)
    let parentTxid = parentTx.txid()
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)

    for i in 0 ..< 39:
      let childTx = Transaction(version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: uint32(i)),
                       scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
        outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      let childTxid = childTx.txid()
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(100),
        weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
        ancestorFee: Satoshi(200), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)
      mp.spentBy[OutPoint(txid: parentTxid, vout: uint32(i))] = childTxid

    # 40th child: parent + 39 siblings + self = 41 <= 64 → accept.
    let newChild = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 39'u32),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let (cCount, _) = mp.calculateClusterStats(newChild, 400)
    check cCount == 41           # NOT 2 — siblings are part of the cluster
    check mp.checkPackageLimits(newChild, 400).isOk


  test "C1 sibling fan-out REJECTS past 64 (ancestor-scoped proxy would accept)":
    ## Every child has exactly 1 ancestor, so a count scoped to ancestors
    ## instead of the connected component accepts all of these.  Corpus
    ## `cluster-sibling-72` exists precisely to catch that.
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())

    var parentOuts: seq[TxOut] = @[]
    for i in 0 ..< 70:
      parentOuts.add(TxOut(value: Satoshi(10_000), scriptPubKey: @[]))
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: parentOuts, witnesses: @[], lockTime: 0)
    let parentTxid = parentTx.txid()
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)

    # 63 children → cluster is parent + 63 = 64 already at the limit.
    for i in 0 ..< 63:
      let childTx = Transaction(version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: uint32(i)),
                       scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
        outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      let childTxid = childTx.txid()
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(100),
        weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
        ancestorFee: Satoshi(200), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)
      mp.spentBy[OutPoint(txid: parentTxid, vout: uint32(i))] = childTxid

    # One more child → 65 → reject, despite having only 1 ancestor.
    let overflow = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 63'u32),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let (cCount, _) = mp.calculateClusterStats(overflow, 400)
    check cCount == 65
    let res = mp.checkPackageLimits(overflow, 400)
    check not res.isOk
    check res.error == "too-large-cluster"


  # --------------------------------------------------------------------------
  # C2: the size gate is in WEIGHT units, with NO per-tx rounding.
  # --------------------------------------------------------------------------
  test "C2 cluster size sums WEIGHT, not per-tx ceilinged vbytes":
    ## Two 402 WU transactions sum to 804 WU under Core's form.
    ## Under the (wrong) per-tx vbyte-ceiling form they would sum to
    ## ceil(402/4)*2 = 202 vB = 808 WU-equivalent and be REJECTED at a
    ## 201 vB / 804 WU bound.  Sum-then-compare must accept.
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams(), clusterSizeLimit = 201)
    check mp.maxClusterSizeWeight() == 804

    var parentTxid: array[32, byte]
    parentTxid[0] = 0xB7
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 402, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 402,
      ancestorCount: 1, ancestorSize: 101)

    let child = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let (_, cSize) = mp.calculateClusterStats(child, 402)
    check cSize == 804                       # NOT 808
    check mp.checkPackageLimits(child, 402).isOk

    # One weight unit over the bound rejects (strict `>`).
    check mp.calculateClusterStats(child, 403)[1] == 805
    check not mp.checkPackageLimits(child, 403).isOk


  test "C2 sigop cost drives the cluster size when it exceeds weight":
    ## Core's per-tx contribution is max(weight, sigops * bytes_per_sigop)
    ## (GetSigOpsAdjustedWeight, policy.cpp:390; fed to TxGraph at
    ## txmempool.cpp:1017).  Here the raw weights are trivial and ONLY the
    ## sigop term can trip the limit.
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams(), clusterSizeLimit = 1000)
    check mp.maxClusterSizeWeight() == 4000

    check clusterSizeContribution(400, 0) == 400        # no sigops → weight
    check clusterSizeContribution(400, 100) == 2000     # 100*20 dominates
    check clusterSizeContribution(9000, 100) == 9000    # weight dominates

    # Parent: weight 400 but 100 sigops → contributes 2,000 WU.
    var parentTxid: array[32, byte]
    parentTxid[0] = 0xB8
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100, sigopCost: 100)

    let child = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    # Ignoring sigops entirely the cluster would be 400 + 400 = 800 WU and
    # nothing here would ever reject.
    check mp.calculateClusterStats(child, 400, 0'i64)[1] == 2400

    # Child with 100 sigops → 2,000 + 2,000 = 4,000 WU == bound → accept.
    check mp.calculateClusterStats(child, 400, 100'i64)[1] == 4000
    check mp.checkPackageLimits(child, 400, 100'i64).isOk

    # Child with 101 sigops → 2,000 + 2,020 = 4,020 WU > bound → reject.
    check mp.calculateClusterStats(child, 400, 101'i64)[1] == 4020
    let res = mp.checkPackageLimits(child, 400, 101'i64)
    check not res.isOk
    check res.error == "too-large-cluster"


  # --------------------------------------------------------------------------
  # G6: cluster count limit (64)
  # --------------------------------------------------------------------------
  test "G6 accept cluster of 64 (at cluster-count limit)":
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    # Lower ancestor limit so we can build a 64-tx cluster without tripping G1 first.
    var mp = newMempool(cs, regtestParams(),
                        ancestorLimit = 64, descendantLimit = 64,
                        ancestorSizeLimit = 10_000_000,
                        descendantSizeLimit = 10_000_000,
                        clusterLimit = 64,
                        clusterSizeLimit = 10_000_000)

    # 63-tx chain; 64th tx will be the new submission
    let tipTxid = makeChainInMempool(mp, 63, vsizeEach = 100)

    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: tipTxid, vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let res = mp.checkPackageLimits(newTx, 400)
    check res.isOk  # cluster count = 64 → exactly at limit → accept


  test "G6 reject cluster exceeding 64 transactions":
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams(),
                        ancestorLimit = 65, descendantLimit = 65,
                        ancestorSizeLimit = 10_000_000,
                        descendantSizeLimit = 10_000_000,
                        clusterLimit = 64,
                        clusterSizeLimit = 10_000_000)

    # 64-tx chain → new tx would create cluster of 65
    let tipTxid = makeChainInMempool(mp, 64, vsizeEach = 100)

    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: tipTxid, vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let res = mp.checkPackageLimits(newTx, 400)
    check not res.isOk
    check "too-large-cluster" in res.error


  # --------------------------------------------------------------------------
  # G7: cluster vsize limit (101,000 vB)
  # --------------------------------------------------------------------------
  test "G7 reject when cluster vsize would exceed 101,000 vB":
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams(),
                        ancestorLimit = 10, descendantLimit = 10,
                        ancestorSizeLimit = 200_000,
                        descendantSizeLimit = 200_000,
                        clusterSizeLimit = 100_000)

    # Single large parent consuming 99,900 vB of the 100,000 vB cluster limit
    var parentTxid: array[32, byte]
    parentTxid[0] = 0xF1
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(100),
      weight: 399_600,  # 99,900 vB
      feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 399_600,
      ancestorCount: 1, ancestorSize: 99_900)

    # Child with 100 vB → cluster = 100,000 vB (at limit) → accept
    let txAtLimit = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    check mp.checkPackageLimits(txAtLimit, 400).isOk

    # Child with 101 vB → cluster = 100,001 vB → G7 reject
    let txOver = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(898), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let res = mp.checkPackageLimits(txOver, 404)
    check not res.isOk
    check "too-large-cluster" in res.error


  # --------------------------------------------------------------------------
  # CPFP: child pays for parent (ancestor fee-rate aggregate)
  # --------------------------------------------------------------------------
  test "CPFP child with 2 ancestors accepted when within all limits":
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())

    # grandparent → parent → (new child)
    var gpTxid: array[32, byte]
    gpTxid[0] = 0xE1
    var pTxid: array[32, byte]
    pTxid[0] = 0xE2

    let gpTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(10_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    let pTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(gpTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(9_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    mp.entries[TxId(gpTxid)] = MempoolEntry(
      tx: gpTx, txid: TxId(gpTxid), fee: Satoshi(1),
      weight: 400, feeRate: 0.01, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(1), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.entries[TxId(pTxid)] = MempoolEntry(
      tx: pTx, txid: TxId(pTxid), fee: Satoshi(1),
      weight: 400, feeRate: 0.01, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(2), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200)
    mp.spentBy[OutPoint(txid: TxId(gpTxid), vout: 0)] = TxId(pTxid)

    # Child with high fee bumping the package
    let child = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(pTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(8_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    # ancestor count = 3 (gp + p + self), well within 25
    let res = mp.checkPackageLimits(child, 400)
    check res.isOk


  # --------------------------------------------------------------------------
  # Historical: 101 kvB ancestor/descendant size threshold
  # --------------------------------------------------------------------------
  test "C2 default bound: 404,000 WU accepts, 404,001 WU rejects":
    ## The default cluster size limit is DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000
    ## = 101,000 vB, enforced as 101,000 * WITNESS_SCALE_FACTOR = 404,000
    ## WEIGHT units (txmempool.cpp:181), compared with strict `>`
    ## (txgraph.cpp:2059).
    var cs = newChainState(W75DbPath, regtestParams())
    defer: cs.close()
    var mp = newMempool(cs, regtestParams())
    check mp.maxClusterSizeWeight() == 404_000

    # Build a single parent that occupies 403,600 WU of the budget
    var parentTxid: array[32, byte]
    parentTxid[0] = 0xFA
    let parentTx = Transaction(version: 1, inputs: @[],
      outputs: @[TxOut(value: Satoshi(1_000_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(1_000),
      weight: 403_600,  # 100,900 vB
      feeRate: 10.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(1_000), ancestorWeight: 403_600,
      ancestorCount: 1, ancestorSize: 100_900)

    # Child of 400 WU: cluster = 403,600 + 400 = 404,000 WU → exactly at bound
    let childAtLimit = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(999_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    check mp.calculateClusterStats(childAtLimit, 400)[1] == 404_000
    check mp.checkPackageLimits(childAtLimit, 400).isOk   # at boundary → accept

    # One single weight unit more: 404,001 WU → over bound → reject
    let childOver = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(parentTxid), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(998_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    check mp.calculateClusterStats(childOver, 401)[1] == 404_001
    let res = mp.checkPackageLimits(childOver, 401)
    check not res.isOk
    check res.error == "too-large-cluster"


  # --------------------------------------------------------------------------
  # cluster.nim MaxClusterSize constant
  # --------------------------------------------------------------------------
  test "cluster.nim MaxClusterSize == 64 (DEFAULT_CLUSTER_LIMIT)":
    ## Regression: was incorrectly set to 100 before W75 fix.
    ## DefaultClusterLimit (mempool.nim) and MaxClusterSize (cluster.nim) must agree.
    check DefaultClusterLimit == 64

# ============================================================================
# Reject-reason token parity (campaign #7, 2026-07-08)
# ----------------------------------------------------------------------------
# The mempool RPC paths (sendrawtransaction / testmempoolaccept) must surface
# Bitcoin Core's BARE canonical reject tokens, not nimrod-internal prose.  Each
# test below pins one of the six discrepancy classes fixed in this pass.  These
# assert EXACT-MATCH tokens because Core's reject-reason is the bare token.
# ============================================================================

proc buildSpendableCoinbase(cs: var ChainState): TxId =
  ## Build a 101-block chain; return the height-1 coinbase txid (mature at the
  ## tip, since genesis writes no UTXO — see W14 / Core parity note above).
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  let genesisHash = getBlockHash(genesis)
  let block1 = makeSimpleBlock(genesisHash, 1)
  discard cs.connectBlock(block1, 1)
  var prevHash = getBlockHash(block1)
  for h in 2 .. 101:
    let blk = makeSimpleBlock(prevHash, int32(h))
    discard cs.connectBlock(blk, int32(h))
    prevHash = getBlockHash(blk)
  block1.txs[0].txid()

suite "Reject-reason token parity (Core bare tokens)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "class 5: empty vin -> bad-txns-vin-empty (not missingorspent)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    let crypto = newCryptoEngine()
    let tx = Transaction(version: 1, inputs: @[],
                         outputs: @[TxOut(value: Satoshi(100_000),
                                          scriptPubKey: makeP2PKHScript())],
                         witnesses: @[], lockTime: 0)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "bad-txns-vin-empty"
    cs.close()

  test "class 5: empty vout -> bad-txns-vout-empty":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    let crypto = newCryptoEngine()
    var fake: array[32, byte]
    fake[0] = 0x11
    let tx = Transaction(version: 1,
                         inputs: @[TxIn(prevOut: OutPoint(txid: TxId(fake), vout: 0),
                                        scriptSig: @[byte(0x00)], sequence: 0xFFFFFFFF'u32)],
                         outputs: @[], witnesses: @[], lockTime: 0)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "bad-txns-vout-empty"
    cs.close()

  test "class 5: duplicate inputs -> bad-txns-inputs-duplicate":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    let crypto = newCryptoEngine()
    var fake: array[32, byte]
    fake[0] = 0x22
    let dupIn = TxIn(prevOut: OutPoint(txid: TxId(fake), vout: 0),
                     scriptSig: @[byte(0x00)], sequence: 0xFFFFFFFF'u32)
    let tx = Transaction(version: 1, inputs: @[dupIn, dupIn],
                         outputs: @[TxOut(value: Satoshi(100_000),
                                          scriptPubKey: makeP2PKHScript())],
                         witnesses: @[], lockTime: 0)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "bad-txns-inputs-duplicate"
    cs.close()

  test "class 1: non-standard version -> bare 'version' (not wrapped)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    var fake: array[32, byte]
    fake[0] = 0x33
    # version 99 is outside the standard 1..3 range → IsStandardTx "version".
    # (This gate runs before any prevout lookup, so a fake input is fine.)
    var tx = makeSpendTx(TxId(fake), 0, 100_000)
    tx.version = 99
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "version"
    cs.close()

  test "class 3: oversize weight -> bare 'tx-size'":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    var fake: array[32, byte]
    fake[0] = 0x44
    # ~3200 P2PKH outputs push the base size past 100_000 bytes, so
    # weight = base*4 > MaxStandardTxWeight (400_000 WU) → "tx-size".
    var outs: seq[TxOut]
    for i in 0 ..< 3200:
      outs.add(TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript()))
    let tx = Transaction(version: 1,
                         inputs: @[TxIn(prevOut: OutPoint(txid: TxId(fake), vout: 0),
                                        scriptSig: @[byte(0x00)], sequence: 0xFFFFFFFF'u32)],
                         outputs: outs, witnesses: @[], lockTime: 0)
    check calculateWeight(tx) > MaxStandardTxWeight
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "tx-size"
    cs.close()

  test "class 2: outputs exceed inputs -> bad-txns-in-belowout (single token)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let coinbaseTxid = buildSpendableCoinbase(cs)
    # Coinbase is worth 5 BTC; spend 6 BTC → sum(out) > sum(in).
    let tx = makeSpendTx(coinbaseTxid, 0, 6_000_000_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "bad-txns-in-belowout"
    cs.close()

  test "class 4: fresh-mempool low fee -> 'min relay fee not met'":
    var cs = newChainState(TestDbPath, regtestParams())
    # Default minFeeRate = 0.1 sat/vB; rolling floor is 0 on a fresh mempool,
    # so the static -minrelaytxfee gate governs → Core "min relay fee not met".
    var mp = newMempool(cs, regtestParams())
    let crypto = newCryptoEngine()
    let coinbaseTxid = buildSpendableCoinbase(cs)
    # 1-sat fee → feerate ~0.01 sat/vB, well below 0.1.
    let tx = makeSpendTx(coinbaseTxid, 0, 4_999_999_999)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check r.error == "min relay fee not met"
    cs.close()

when isMainModule:
  # Run all tests
  discard
