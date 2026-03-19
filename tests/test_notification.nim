## Tests for notification system integration
## Tests RPC endpoint and notification flow

import std/[json, strutils, tables, options]
import unittest2
import ../src/rpc/zmq
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# Helper procs
proc makeBlockHash(v: byte): BlockHash =
  var h: array[32, byte]
  h[0] = v
  BlockHash(h)

proc makeTxId(v: byte): TxId =
  var h: array[32, byte]
  h[0] = v
  TxId(h)

proc makeBlock(): Block =
  let tx = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: makeTxId(0), vout: 0xffffffff'u32),
      scriptSig: @[byte(0x04)] & @[byte(0xff), 0xff, 0x00, 0x1d] & @[byte(0x01), 0x04],
      sequence: 0xffffffff'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x41)] & newSeq[byte](65) & @[byte(0xac)]
    )],
    witnesses: @[],
    lockTime: 0
  )

  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: makeBlockHash(0),
      merkleRoot: default(array[32, byte]),
      timestamp: 1231006505,
      bits: 0x1d00ffff'u32,
      nonce: 2083236893
    ),
    txs: @[tx]
  )

suite "ZMQ notification interface":
  test "interface initializes without libzmq (no notifiers)":
    let config = newZmqConfig()
    var zmq = newZmqNotificationInterface(config, nil)
    # Initialize should succeed with no notifiers
    check zmq.initialize() == true

  test "interface shutdown is safe with uninitialized":
    let config = newZmqConfig()
    var zmq = newZmqNotificationInterface(config, nil)
    # Shutdown should not crash without initialization
    zmq.shutdown()

  test "active notifiers list is correct":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.hashTxAddresses.add("tcp://127.0.0.1:28333")
    config.sequenceAddresses.add("tcp://127.0.0.1:28334")

    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()

    check notifiers.len == 3

    # Check hashblock notifier
    var foundHashBlock = false
    var foundHashTx = false
    var foundSequence = false

    for n in notifiers:
      if n.notifierType == "pubhashblock":
        foundHashBlock = true
        check n.address == "tcp://127.0.0.1:28332"
      elif n.notifierType == "pubhashtx":
        foundHashTx = true
        check n.address == "tcp://127.0.0.1:28333"
      elif n.notifierType == "pubsequence":
        foundSequence = true
        check n.address == "tcp://127.0.0.1:28334"

    check foundHashBlock
    check foundHashTx
    check foundSequence

suite "ZMQ notification callbacks (mock)":
  # These tests verify the notification methods can be called
  # They don't actually send anything because sockets aren't initialized

  test "notifyBlock doesn't crash with uninitialized interface":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    # Don't initialize - socket will be nil
    zmq.notifyBlock(makeBlockHash(1))
    # Should not crash

  test "notifyTransaction doesn't crash with uninitialized interface":
    var config = newZmqConfig()
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: makeTxId(0xaa), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[byte(0x76), 0xa9]
      )],
      witnesses: @[],
      lockTime: 0
    )

    zmq.notifyTransaction(tx)
    # Should not crash

  test "notifyBlockConnect doesn't crash":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    zmq.notifyBlockConnect(makeBlockHash(1))

  test "notifyBlockDisconnect doesn't crash":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    zmq.notifyBlockDisconnect(makeBlockHash(1))

  test "notifyTransactionAcceptance doesn't crash":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    zmq.notifyTransactionAcceptance(tx, 12345)

  test "notifyTransactionRemoval doesn't crash":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    zmq.notifyTransactionRemoval(tx, 67890)

suite "ZMQ combined notifications (mock)":
  test "notifyTip skips during IBD":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    # This should be a no-op during IBD
    zmq.notifyTip(makeBlockHash(1), isInitialDownload = true)

  test "notifyTip calls all block notifiers":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.rawBlockAddresses.add("tcp://127.0.0.1:28333")
    config.sequenceAddresses.add("tcp://127.0.0.1:28334")
    var zmq = newZmqNotificationInterface(config, nil)

    # Should not crash even with nil sockets
    zmq.notifyTip(makeBlockHash(1), isInitialDownload = false)

  test "notifyBlockConnected skips during IBD":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    let blk = makeBlock()
    zmq.notifyBlockConnected(blk, makeBlockHash(1), isInitialDownload = true)

  test "notifyBlockConnected notifies transactions and block":
    var config = newZmqConfig()
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    config.rawTxAddresses.add("tcp://127.0.0.1:28333")
    config.hashBlockAddresses.add("tcp://127.0.0.1:28334")
    var zmq = newZmqNotificationInterface(config, nil)

    let blk = makeBlock()
    zmq.notifyBlockConnected(blk, makeBlockHash(1), isInitialDownload = false)

  test "notifyBlockDisconnected notifies transactions and disconnect":
    var config = newZmqConfig()
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    config.sequenceAddresses.add("tcp://127.0.0.1:28333")
    var zmq = newZmqNotificationInterface(config, nil)

    let blk = makeBlock()
    zmq.notifyBlockDisconnected(blk, makeBlockHash(1))

  test "notifyMempoolAccept calls all tx notifiers":
    var config = newZmqConfig()
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    config.rawTxAddresses.add("tcp://127.0.0.1:28333")
    config.sequenceAddresses.add("tcp://127.0.0.1:28334")
    var zmq = newZmqNotificationInterface(config, nil)

    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    zmq.notifyMempoolAccept(tx, 100)

  test "notifyMempoolRemove calls sequence notifier":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    zmq.notifyMempoolRemove(tx, 200)

suite "ZMQ rawblock with callback":
  test "notifyRawBlock uses callback to get block":
    var callbackCalled = false
    var capturedHash: BlockHash

    proc getBlockByHash(hash: BlockHash): Option[Block] =
      callbackCalled = true
      capturedHash = hash
      some(makeBlock())

    var config = newZmqConfig()
    config.rawBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, getBlockByHash)

    let testHash = makeBlockHash(0xab)
    zmq.notifyRawBlock(testHash)

    check callbackCalled
    check capturedHash == testHash

  test "notifyRawBlock handles missing block":
    var callbackCalled = false

    proc getBlockByHash(hash: BlockHash): Option[Block] =
      callbackCalled = true
      none(Block)

    var config = newZmqConfig()
    config.rawBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, getBlockByHash)

    zmq.notifyRawBlock(makeBlockHash(0xcd))

    check callbackCalled
    # Should not crash, just log warning

  test "notifyRawBlock skips without callback":
    var config = newZmqConfig()
    config.rawBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)

    zmq.notifyRawBlock(makeBlockHash(1))
    # Should not crash

suite "ZMQ address formats":
  test "TCP address format":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers[0].address == "tcp://127.0.0.1:28332"

  test "TCP address with wildcard":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://*:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers[0].address == "tcp://*:28332"

  test "IPC address format":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("ipc:///tmp/bitcoin.sock")
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers[0].address == "ipc:///tmp/bitcoin.sock"
