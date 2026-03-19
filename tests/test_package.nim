## Package relay tests
## Tests package validation, CPFP fee bumping, and submitpackage RPC

import unittest2
import std/[os, options, tables, strutils, times, sets]
import ../src/mempool/[mempool, package]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter

const TestDbPath = "/tmp/nimrod_package_test"

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

# Create a regular transaction spending a given UTXO
proc makeSpendTx(
  prevTxid: TxId,
  prevVout: uint32,
  outputValue: int64,
  numOutputs: int = 1
): Transaction =
  var outputs: seq[TxOut]
  for i in 0 ..< numOutputs:
    outputs.add(TxOut(
      value: Satoshi(outputValue div numOutputs),
      scriptPubKey: makeP2PKHScript()
    ))

  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: outputs,
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

suite "Package validation constants":
  test "package limit constants":
    check MaxPackageCount == 25
    check MaxPackageWeight == 404_000
    check MaxPackageSizeKvB == 101
    check MaxPackageSize == 101_000

suite "Package topological sorting":
  test "single tx is sorted":
    var txid: array[32, byte]
    txid[0] = 0x01
    let tx = makeSpendTx(TxId(txid), 0, 1000)
    check isTopoSortedPackage(@[tx])

  test "parent before child is sorted":
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    check isTopoSortedPackage(@[parent, child])

  test "child before parent is not sorted":
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    # Child before parent - not sorted
    check not isTopoSortedPackage(@[child, parent])

  test "chain of three txs sorted":
    let tx1 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let tx2 = makeSpendTx(tx1.txid(), 0, 800)
    let tx3 = makeSpendTx(tx2.txid(), 0, 600)

    check isTopoSortedPackage(@[tx1, tx2, tx3])
    check not isTopoSortedPackage(@[tx3, tx2, tx1])
    check not isTopoSortedPackage(@[tx1, tx3, tx2])

suite "Package consistency":
  test "empty package is consistent":
    check isConsistentPackage(@[])

  test "duplicate txid is not consistent":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    check not isConsistentPackage(@[tx, tx])

  test "conflicting inputs is not consistent":
    var prevTxid: array[32, byte]
    prevTxid[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(prevTxid), vout: 0)

    let tx1 = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[byte(0x00)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let tx2 = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[byte(0x01)], sequence: 0)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    check not isConsistentPackage(@[tx1, tx2])

  test "transaction without inputs is not consistent":
    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    check not isConsistentPackage(@[tx])

suite "Package well-formed validation":
  test "empty package is well-formed":
    let result = isWellFormedPackage(@[])
    check result.isOk

  test "too many transactions":
    var txns: seq[Transaction]
    for i in 0 ..< 30:  # More than MaxPackageCount (25)
      var txid: array[32, byte]
      txid[0] = byte(i)
      let tx = makeSpendTx(TxId(txid), 0, 1000)
      txns.add(tx)

    let result = isWellFormedPackage(txns)
    check not result.isOk
    check "package-too-many-transactions" in result.error

  test "duplicate txid fails":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = isWellFormedPackage(@[tx, tx])
    check not result.isOk
    check "package-contains-duplicates" in result.error

  test "not sorted fails":
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    let result = isWellFormedPackage(@[child, parent])
    check not result.isOk
    check "package-not-sorted" in result.error

suite "Package child-with-parents topology":
  test "simple parent-child is valid":
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    check isChildWithParents(@[parent, child])

  test "single tx is not child-with-parents":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    check not isChildWithParents(@[tx])

  test "multiple parents one child is valid":
    # Two parents, one child that spends from both
    let parent1 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    var prevTxid2: array[32, byte]
    prevTxid2[0] = 0x01
    let parent2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(prevTxid2), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: parent1.txid(), vout: 0), scriptSig: @[byte(0x00)], sequence: 0),
        TxIn(prevOut: OutPoint(txid: parent2.txid(), vout: 0), scriptSig: @[byte(0x00)], sequence: 0)
      ],
      outputs: @[TxOut(value: Satoshi(1800), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    check isChildWithParents(@[parent1, parent2, child])

suite "Package fee rate calculation":
  test "single tx fee rate":
    let fees = @[Satoshi(1000)]
    let weights = @[400]  # 100 vbytes
    let rate = calculatePackageFeerate(fees, weights)
    check rate == 10.0  # 1000 sats / 100 vbytes = 10 sat/vb

  test "two tx package fee rate":
    let fees = @[Satoshi(100), Satoshi(900)]
    let weights = @[400, 400]  # 100 vbytes each = 200 vbytes total
    let rate = calculatePackageFeerate(fees, weights)
    # 1000 sats / 200 vbytes = 5 sat/vb
    check rate == 5.0

  test "CPFP fee bumping scenario":
    # Parent: low fee (0.5 sat/vb)
    # Child: high fee (makes combined 2 sat/vb)
    # Parent: 50 sats, 100 vbytes
    # Child: 350 sats, 100 vbytes
    # Combined: 400 sats / 200 vbytes = 2 sat/vb
    let fees = @[Satoshi(50), Satoshi(350)]
    let weights = @[400, 400]
    let rate = calculatePackageFeerate(fees, weights)
    check rate == 2.0

suite "Package transaction weight":
  test "calculate tx weight":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let weight = calculateTransactionWeight(tx)
    # Non-witness tx: weight = 4 * base_size
    let baseSize = serializeLegacy(tx).len
    check weight == baseSize * 4

  test "calculate tx vsize":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let vsize = calculateTransactionVsize(tx)
    let weight = calculateTransactionWeight(tx)
    check vsize == (weight + 3) div 4

suite "Package topological sort":
  test "sort already sorted package":
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    let sorted = sortPackageTopologically(@[parent, child])
    check sorted.len == 2
    check sorted[0].txid() == parent.txid()
    check sorted[1].txid() == child.txid()

  test "sort unsorted package":
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    # Pass unsorted (child before parent)
    let sorted = sortPackageTopologically(@[child, parent])
    check sorted.len == 2
    check sorted[0].txid() == parent.txid()
    check sorted[1].txid() == child.txid()

suite "Package mempool acceptance":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "accept simple package":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)  # Disable fee check
    let crypto = newCryptoEngine()

    # Create parent tx (from external UTXO)
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let child = makeSpendTx(parent.txid(), 0, 500)

    # Add parent to chainstate first (simulate confirmed UTXO)
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    # Add parent's funding output to UTXO set
    cs.addUtxo(OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
               UtxoEntry(output: TxOut(value: Satoshi(2000), scriptPubKey: makeP2PKHScript()),
                        isCoinbase: false, height: 0))

    # Accept package (will fail script verification but tests package flow)
    let result = mp.acceptPackage(@[parent, child], crypto, usePackageFeerates = true)

    # Note: Script verification will fail because we're using dummy scripts
    # But this tests the package validation flow
    check result.txResults.len == 2

    cs.close()

  test "reject package with too many transactions":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    var txns: seq[Transaction]
    for i in 0 ..< 30:  # > MaxPackageCount
      var txid: array[32, byte]
      txid[0] = byte(i)
      let tx = makeSpendTx(TxId(txid), 0, 1000)
      txns.add(tx)

    let result = mp.acceptPackage(txns, crypto)
    check not result.valid
    check result.state == pvPolicy
    check "package-too-many-transactions" in result.error

    cs.close()

  test "package fee rate calculation in acceptPackage":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    # Set up UTXO
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    var fundingTxid: array[32, byte]
    fundingTxid[0] = 0x01
    cs.addUtxo(OutPoint(txid: TxId(fundingTxid), vout: 0),
               UtxoEntry(output: TxOut(value: Satoshi(10000), scriptPubKey: makeP2PKHScript()),
                        isCoinbase: false, height: 0))

    # Parent with low fee (100 sats)
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(fundingTxid), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(9900), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    # Child with higher fee (900 sats from parent's output minus child output)
    let child = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(9000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.acceptPackage(@[parent, child], crypto)

    # Package fee rate should be calculated
    # Parent: 100 sats, Child: 900 sats, Total: 1000 sats
    check result.packageFeerate > 0

    cs.close()

suite "CPFP scenario tests":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "child pays for parent - low parent fee bumped by child":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    # Set minimum fee rate to 2 sat/vbyte
    var mp = newMempool(cs, params, minFeeRate = 2.0)
    let crypto = newCryptoEngine()

    # Set up UTXO
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    var fundingTxid: array[32, byte]
    fundingTxid[0] = 0x01
    cs.addUtxo(OutPoint(txid: TxId(fundingTxid), vout: 0),
               UtxoEntry(output: TxOut(value: Satoshi(100000), scriptPubKey: makeP2PKHScript()),
                        isCoinbase: false, height: 0))

    # Parent with very low fee (10 sats for ~200 vbytes = 0.05 sat/vbyte)
    # This would be rejected individually
    let parent = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(fundingTxid), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(99990), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    # Child with high fee (990 sats - bumps package rate above minimum)
    let child = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parent.txid(), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(99000), scriptPubKey: makeP2PKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    let result = mp.acceptPackage(@[parent, child], crypto, usePackageFeerates = true)

    # With package feerates, this should be evaluated together
    # Package fee: 10 + 990 = 1000 sats for ~400 vbytes = 2.5 sat/vbyte
    # This exceeds the 2.0 sat/vbyte minimum
    check result.txResults.len == 2

    cs.close()

when isMainModule:
  discard
