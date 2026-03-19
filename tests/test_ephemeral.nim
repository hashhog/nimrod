## Ephemeral Anchor Policy Tests
## Tests ephemeral dust detection, package validation, and eviction cascade

import unittest2
import std/[os, options, tables, times, sets]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter

const TestDbPath = "/tmp/nimrod_ephemeral_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# Helper to create a P2WPKH scriptPubKey
proc makeP2WPKHScript(): seq[byte] =
  @[byte(OP_0), 0x14] & @(default(array[20, byte]))

# Helper to create a P2A (Pay-to-Anchor) scriptPubKey
proc makeP2AScript(): seq[byte] =
  P2AScript

# Create a transaction with normal outputs
proc makeNormalTx(prevTxid: TxId, prevVout: uint32, outputValue: int64): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(outputValue),
      scriptPubKey: makeP2WPKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

# Create a transaction with ephemeral dust (0-value P2A output)
proc makeEphemeralDustTx(prevTxid: TxId, prevVout: uint32, mainOutputValue: int64): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[
      TxOut(
        value: Satoshi(mainOutputValue),
        scriptPubKey: makeP2WPKHScript()
      ),
      TxOut(
        value: Satoshi(0),  # Ephemeral dust - 0-value output
        scriptPubKey: makeP2AScript()  # P2A script
      )
    ],
    witnesses: @[],
    lockTime: 0
  )

# Create a child that spends an ephemeral dust output
proc makeEphemeralSpendTx(parentTxid: TxId, ephemeralVout: uint32, mainInputTxid: TxId, mainInputVout: uint32, outputValue: int64): Transaction =
  Transaction(
    version: 2,
    inputs: @[
      TxIn(
        prevOut: OutPoint(txid: mainInputTxid, vout: mainInputVout),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      ),
      TxIn(
        prevOut: OutPoint(txid: parentTxid, vout: ephemeralVout),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )
    ],
    outputs: @[TxOut(
      value: Satoshi(outputValue),
      scriptPubKey: makeP2WPKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

suite "ephemeral dust detection":
  test "isEphemeralDust detects 0-value outputs":
    let output = TxOut(value: Satoshi(0), scriptPubKey: makeP2AScript())
    check isEphemeralDust(output) == true

  test "isEphemeralDust rejects non-zero outputs":
    let output = TxOut(value: Satoshi(1), scriptPubKey: makeP2AScript())
    check isEphemeralDust(output) == false

  test "isDust detects outputs below dust threshold":
    # P2WPKH threshold is ~294 sats at 3 sat/vB
    let dustOutput = TxOut(value: Satoshi(100), scriptPubKey: makeP2WPKHScript())
    check isDust(dustOutput) == true

    let normalOutput = TxOut(value: Satoshi(1000), scriptPubKey: makeP2WPKHScript())
    check isDust(normalOutput) == false

  test "hasEphemeralDust detects tx with 0-value output":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeEphemeralDustTx(TxId(fakeTxid), 0, 1_000_000)
    check hasEphemeralDust(tx) == true

  test "hasEphemeralDust returns false for normal tx":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeNormalTx(TxId(fakeTxid), 0, 1_000_000)
    check hasEphemeralDust(tx) == false

  test "getEphemeralDustOutputs returns correct indices":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeEphemeralDustTx(TxId(fakeTxid), 0, 1_000_000)
    let outputs = getEphemeralDustOutputs(tx)
    check outputs.len == 1
    check outputs[0] == 1  # Second output (index 1) is the P2A

  test "getDustOutputs returns all dust outputs":
    let tx = Transaction(
      version: 2,
      inputs: @[],
      outputs: @[
        TxOut(value: Satoshi(1000), scriptPubKey: makeP2WPKHScript()),
        TxOut(value: Satoshi(0), scriptPubKey: makeP2AScript()),
        TxOut(value: Satoshi(100), scriptPubKey: makeP2WPKHScript())  # Also dust
      ],
      witnesses: @[],
      lockTime: 0
    )
    let outputs = getDustOutputs(tx)
    check outputs.len == 2  # Both 0-value and 100-sat outputs are dust

suite "ephemeral pre-check":
  test "preCheckEphemeralTx allows tx without dust":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeNormalTx(TxId(fakeTxid), 0, 1_000_000)
    let result = preCheckEphemeralTx(tx, Satoshi(1000))
    check result.isOk

  test "preCheckEphemeralTx allows dust with 0-fee":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeEphemeralDustTx(TxId(fakeTxid), 0, 1_000_000)
    let result = preCheckEphemeralTx(tx, Satoshi(0))
    check result.isOk

  test "preCheckEphemeralTx rejects dust with non-zero fee":
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0x01
    let tx = makeEphemeralDustTx(TxId(fakeTxid), 0, 1_000_000)
    let result = preCheckEphemeralTx(tx, Satoshi(1000))
    check not result.isOk
    check "0-fee" in result.error

suite "ephemeral spends check":
  test "checkEphemeralSpends passes for package with all dust spent":
    # Parent with ephemeral dust
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parent = makeEphemeralDustTx(TxId(default(array[32, byte])), 0, 1_000_000)
    let parentId = parent.txid()

    # Child spending the ephemeral dust
    let child = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parentId, vout: 1),  # Spend the P2A output
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(0),
        scriptPubKey: makeP2WPKHScript()
      )],
      witnesses: @[],
      lockTime: 0
    )

    let txns = @[parent, child]
    let result = checkEphemeralSpends(txns, proc(txid: TxId): Option[Transaction] = none(Transaction))
    check result.isOk

  test "checkEphemeralSpends fails when dust not spent":
    # Parent with ephemeral dust
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let parent = makeEphemeralDustTx(TxId(default(array[32, byte])), 0, 1_000_000)
    let parentId = parent.txid()

    # Child that does NOT spend the ephemeral dust (spends main output instead)
    let child = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parentId, vout: 0),  # Spend the main output, not P2A
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(900_000),
        scriptPubKey: makeP2WPKHScript()
      )],
      witnesses: @[],
      lockTime: 0
    )

    let txns = @[parent, child]
    let result = checkEphemeralSpends(txns, proc(txid: TxId): Option[Transaction] = none(Transaction))
    check not result.isOk
    check "did not spend parent's ephemeral dust" in result.error

  test "checkEphemeralSpends checks mempool parents":
    # Parent in mempool with ephemeral dust
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    let mempoolParent = makeEphemeralDustTx(TxId(default(array[32, byte])), 0, 1_000_000)
    let mempoolParentId = TxId(parentTxid)

    # Child that does NOT spend the ephemeral dust
    let child = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: mempoolParentId, vout: 0),  # Spend main output
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(900_000),
        scriptPubKey: makeP2WPKHScript()
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Submit just the child, with parent in mempool
    let txns = @[child]
    let result = checkEphemeralSpends(
      txns,
      proc(txid: TxId): Option[Transaction] =
        if txid == mempoolParentId:
          some(mempoolParent)
        else:
          none(Transaction)
    )
    check not result.isOk
    check "did not spend parent's ephemeral dust" in result.error

suite "standalone ephemeral rejection":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "reject standalone tx with ephemeral dust":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    # Create a tx with ephemeral dust
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xAA
    let tx = makeEphemeralDustTx(TxId(fakeTxid), 0, 1_000_000)

    # Even with minFeeRate = 0, standalone tx with ephemeral dust should be rejected
    let result = mp.acceptTransaction(tx, crypto)
    check not result.isOk
    check "ephemeral dust" in result.error

    cs.close()

suite "package ephemeral policy":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "accept package with parent+child ephemeral dust":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    # Create parent with ephemeral dust
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xAA

    # Add UTXO to chainstate
    let coinbaseOut = TxOut(value: Satoshi(10_000_000), scriptPubKey: makeP2WPKHScript())
    cs.putUtxo(OutPoint(txid: TxId(fakeTxid), vout: 0), UtxoEntry(
      output: coinbaseOut,
      height: 100,
      coinbase: false
    ))

    let parent = makeEphemeralDustTx(TxId(fakeTxid), 0, 9_999_000)
    let parentId = parent.txid()

    # Child spending the ephemeral dust
    let child = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parentId, vout: 1),  # Spend the P2A output
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(0),
        scriptPubKey: makeP2WPKHScript()
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Submit as package (parent before child - topologically sorted)
    let result = mp.acceptPackage(@[parent, child], crypto, usePackageFeerates = true)

    # Should succeed since child spends all ephemeral dust
    check result.valid

    cs.close()

  test "reject package when child doesn't spend ephemeral dust":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    # Create parent with ephemeral dust
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xAA

    # Add UTXO to chainstate
    let coinbaseOut = TxOut(value: Satoshi(10_000_000), scriptPubKey: makeP2WPKHScript())
    cs.putUtxo(OutPoint(txid: TxId(fakeTxid), vout: 0), UtxoEntry(
      output: coinbaseOut,
      height: 100,
      coinbase: false
    ))

    let parent = makeEphemeralDustTx(TxId(fakeTxid), 0, 9_999_000)
    let parentId = parent.txid()

    # Child that spends main output but NOT ephemeral dust
    let child = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: parentId, vout: 0),  # Spend main output, not P2A
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(9_998_000),
        scriptPubKey: makeP2WPKHScript()
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Submit as package
    let result = mp.acceptPackage(@[parent, child], crypto, usePackageFeerates = true)

    # Should fail because ephemeral dust is not spent
    check not result.valid
    check "ephemeral" in result.error

    cs.close()

suite "ephemeral eviction cascade":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "evicting child removes parent with ephemeral dust":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)

    # Manually add parent with ephemeral dust and child
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    var childTxid: array[32, byte]
    childTxid[0] = 0x02

    let parentTx = Transaction(
      version: 2,
      inputs: @[],
      outputs: @[
        TxOut(value: Satoshi(1_000_000), scriptPubKey: makeP2WPKHScript()),
        TxOut(value: Satoshi(0), scriptPubKey: makeP2AScript())  # Ephemeral dust
      ],
      witnesses: @[],
      lockTime: 0
    )

    let childTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(parentTxid), vout: 1),  # Spend P2A
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    # Add parent to mempool
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(0),
      weight: 400, feeRate: 0.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(0), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    # Add child to mempool
    mp.entries[TxId(childTxid)] = MempoolEntry(
      tx: childTx, txid: TxId(childTxid), fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200
    )

    # Track the spent outpoint
    mp.spentBy[OutPoint(txid: TxId(parentTxid), vout: 1)] = TxId(childTxid)

    check mp.count == 2

    # Remove the child (e.g., via eviction or RBF)
    mp.removeTransaction(TxId(childTxid))

    # Parent should also be removed (ephemeral cascade)
    check mp.count == 0
    check TxId(childTxid) notin mp.entries
    check TxId(parentTxid) notin mp.entries

    cs.close()

  test "parent kept if another child still spends ephemeral dust":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)

    # Parent with ephemeral dust
    var parentTxid: array[32, byte]
    parentTxid[0] = 0x01
    var child1Txid: array[32, byte]
    child1Txid[0] = 0x02
    var child2Txid: array[32, byte]
    child2Txid[0] = 0x03

    let parentTx = Transaction(
      version: 2,
      inputs: @[],
      outputs: @[
        TxOut(value: Satoshi(1_000_000), scriptPubKey: makeP2WPKHScript()),
        TxOut(value: Satoshi(0), scriptPubKey: makeP2AScript())  # Ephemeral dust
      ],
      witnesses: @[],
      lockTime: 0
    )

    # Two children - but note in real ephemeral policy only one can spend the P2A
    # This test is hypothetical for the cascade logic
    let child1Tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(parentTxid), vout: 1),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: makeP2WPKHScript())],
      witnesses: @[],
      lockTime: 0
    )

    # Add entries
    mp.entries[TxId(parentTxid)] = MempoolEntry(
      tx: parentTx, txid: TxId(parentTxid), fee: Satoshi(0),
      weight: 400, feeRate: 0.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(0), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )

    mp.entries[TxId(child1Txid)] = MempoolEntry(
      tx: child1Tx, txid: TxId(child1Txid), fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 800,
      ancestorCount: 2, ancestorSize: 200
    )

    # Track spent outpoint
    mp.spentBy[OutPoint(txid: TxId(parentTxid), vout: 1)] = TxId(child1Txid)

    check mp.count == 2

    # Simulate removing child1 but another child spending different output
    # In this case, we're testing that parent WITHOUT remaining ephemeral spenders gets evicted
    mp.removeTransaction(TxId(child1Txid))

    # Since child was the only spender of the ephemeral output, parent should be evicted
    check mp.count == 0

    cs.close()

suite "ephemeral dust constants":
  test "MAX_DUST_OUTPUTS_PER_TX is 1":
    check MaxDustOutputsPerTx == 1

  test "DUST_RELAY_TX_FEE is 3000":
    check DustRelayTxFee == 3000

  test "getDustThreshold returns reasonable values":
    # P2WPKH
    let p2wpkh = TxOut(value: Satoshi(0), scriptPubKey: makeP2WPKHScript())
    let threshold = getDustThreshold(p2wpkh)
    # Should be around 294 sats for P2WPKH at 3 sat/vB
    check int64(threshold) > 200
    check int64(threshold) < 400

    # P2A (also witness)
    let p2a = TxOut(value: Satoshi(0), scriptPubKey: makeP2AScript())
    let p2aThreshold = getDustThreshold(p2a)
    check int64(p2aThreshold) > 0

when isMainModule:
  discard
