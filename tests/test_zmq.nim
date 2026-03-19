## Tests for ZMQ notification module
## Tests configuration, message formatting, and notification logic

import std/[json, strutils, tables, options]
import unittest2
import ../src/rpc/zmq
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# Helper procs
proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc bytesToHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

proc makeBlockHash(v: byte): BlockHash =
  var h: array[32, byte]
  h[0] = v
  BlockHash(h)

proc makeTxId(v: byte): TxId =
  var h: array[32, byte]
  h[0] = v
  TxId(h)

proc makeTransaction(version: int32 = 1): Transaction =
  Transaction(
    version: version,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: makeTxId(0xaa),
        vout: 0
      ),
      scriptSig: @[byte(0x00)],
      sequence: 0xffffffff'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(1000),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & newSeq[byte](20) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )

suite "ZMQ topic names":
  test "topic names match Bitcoin Core":
    check MSG_HASHBLOCK == "hashblock"
    check MSG_HASHTX == "hashtx"
    check MSG_RAWBLOCK == "rawblock"
    check MSG_RAWTX == "rawtx"
    check MSG_SEQUENCE == "sequence"

  test "notifier type to topic name conversion":
    check zntHashBlock.topicName == MSG_HASHBLOCK
    check zntHashTx.topicName == MSG_HASHTX
    check zntRawBlock.topicName == MSG_RAWBLOCK
    check zntRawTx.topicName == MSG_RAWTX
    check zntSequence.topicName == MSG_SEQUENCE

  test "notifier type to full name conversion":
    check zntHashBlock.notifierTypeName == "pubhashblock"
    check zntHashTx.notifierTypeName == "pubhashtx"
    check zntRawBlock.notifierTypeName == "pubrawblock"
    check zntRawTx.notifierTypeName == "pubrawtx"
    check zntSequence.notifierTypeName == "pubsequence"

suite "ZMQ sequence labels":
  test "sequence labels match Bitcoin Core":
    check byte(SEQ_ADDED) == byte('A')
    check byte(SEQ_REMOVED) == byte('R')
    check byte(SEQ_CONNECTED) == byte('C')
    check byte(SEQ_DISCONNECTED) == byte('D')

suite "ZMQ byte encoding":
  test "writeLE32 encodes correctly":
    var data: array[4, byte]
    writeLE32(data, 0, 0x12345678'u32)
    check data == [byte(0x78), 0x56, 0x34, 0x12]

  test "writeLE32 encodes zero":
    var data: array[4, byte]
    writeLE32(data, 0, 0'u32)
    check data == [byte(0), 0, 0, 0]

  test "writeLE32 encodes max value":
    var data: array[4, byte]
    writeLE32(data, 0, 0xffffffff'u32)
    check data == [byte(0xff), 0xff, 0xff, 0xff]

  test "writeLE64 encodes correctly":
    var data: array[8, byte]
    writeLE64(data, 0, 0x0102030405060708'u64)
    check data == [byte(0x08), 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]

  test "writeLE64 encodes mempool sequence":
    # Test typical mempool sequence number
    var data: array[8, byte]
    writeLE64(data, 0, 12345'u64)
    check data[0] == byte(12345 and 0xff)
    check data[1] == byte((12345 shr 8) and 0xff)
    check data[2] == 0
    check data[3] == 0
    check data[4] == 0
    check data[5] == 0
    check data[6] == 0
    check data[7] == 0

suite "ZMQ hash reversal":
  test "reverseBytes produces correct output":
    var input: array[32, byte]
    for i in 0 ..< 32:
      input[i] = byte(i)

    let result = reverseBytes(input)

    for i in 0 ..< 32:
      check result[i] == byte(31 - i)

  test "reverseBytes with zeros":
    var input: array[32, byte]
    let result = reverseBytes(input)
    check result == input

  test "reverseBytes double reversal returns original":
    var input: array[32, byte]
    for i in 0 ..< 32:
      input[i] = byte((i * 17) mod 256)

    let result = reverseBytes(reverseBytes(input))
    check result == input

suite "ZMQ configuration":
  test "newZmqConfig creates empty config":
    let config = newZmqConfig()
    check config.hashBlockAddresses.len == 0
    check config.hashTxAddresses.len == 0
    check config.rawBlockAddresses.len == 0
    check config.rawTxAddresses.len == 0
    check config.sequenceAddresses.len == 0

  test "hasNotifiers returns false for empty config":
    let config = newZmqConfig()
    check config.hasNotifiers == false

  test "hasNotifiers returns true with hashblock":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    check config.hasNotifiers == true

  test "hasNotifiers returns true with hashtx":
    var config = newZmqConfig()
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    check config.hasNotifiers == true

  test "hasNotifiers returns true with rawblock":
    var config = newZmqConfig()
    config.rawBlockAddresses.add("tcp://127.0.0.1:28332")
    check config.hasNotifiers == true

  test "hasNotifiers returns true with rawtx":
    var config = newZmqConfig()
    config.rawTxAddresses.add("tcp://127.0.0.1:28332")
    check config.hasNotifiers == true

  test "hasNotifiers returns true with sequence":
    var config = newZmqConfig()
    config.sequenceAddresses.add("tcp://127.0.0.1:28332")
    check config.hasNotifiers == true

suite "ZMQ notification interface creation":
  test "creates interface with no notifiers from empty config":
    let config = newZmqConfig()
    var zmq = newZmqNotificationInterface(config, nil)
    check zmq != nil
    check zmq.getActiveNotifiers().len == 0

  test "creates interface with hashblock notifier":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers.len == 1
    check notifiers[0].notifierType == "pubhashblock"
    check notifiers[0].address == "tcp://127.0.0.1:28332"

  test "creates interface with multiple notifiers":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.hashTxAddresses.add("tcp://127.0.0.1:28333")
    config.rawBlockAddresses.add("tcp://127.0.0.1:28334")
    config.rawTxAddresses.add("tcp://127.0.0.1:28335")
    config.sequenceAddresses.add("tcp://127.0.0.1:28336")

    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers.len == 5

  test "creates interface with same address for multiple notifiers":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")

    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers.len == 2
    check notifiers[0].address == "tcp://127.0.0.1:28332"
    check notifiers[1].address == "tcp://127.0.0.1:28332"

  test "uses default high water mark":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers[0].hwm == DEFAULT_ZMQ_SNDHWM.int

  test "uses custom high water mark":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.highWaterMarks["tcp://127.0.0.1:28332-hashblock"] = 5000
    var zmq = newZmqNotificationInterface(config, nil)
    let notifiers = zmq.getActiveNotifiers()
    check notifiers[0].hwm == 5000

suite "ZMQ constants":
  test "ZMQ socket type PUB":
    check ZMQ_PUB == 1

  test "ZMQ socket options":
    check ZMQ_SNDHWM == 23
    check ZMQ_TCP_KEEPALIVE == 34
    check ZMQ_LINGER == 17
    check ZMQ_IPV6 == 42

  test "ZMQ send flags":
    check ZMQ_SNDMORE == 2

  test "default high water mark":
    check DEFAULT_ZMQ_SNDHWM == 1000

suite "ZMQ message format":
  # These tests verify the data structures that would be sent
  # without actually sending (no libzmq dependency needed)

  test "hashblock message body is 32 bytes reversed":
    var hash: array[32, byte]
    for i in 0 ..< 32:
      hash[i] = byte(i)

    let reversed = reverseBytes(hash)
    check reversed.len == 32
    check reversed[0] == 31
    check reversed[31] == 0

  test "sequence block connect body format":
    # Format: [32-byte hash (reversed)][1-byte label 'C']
    var data: array[33, byte]
    var hash: array[32, byte]
    hash[0] = 0xab

    let hashBytes = reverseBytes(hash)
    copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
    data[32] = byte(SEQ_CONNECTED)

    check data.len == 33
    check data[31] == 0xab  # Original byte 0 is now at position 31
    check data[32] == byte('C')

  test "sequence block disconnect body format":
    var data: array[33, byte]
    data[32] = byte(SEQ_DISCONNECTED)
    check data[32] == byte('D')

  test "sequence tx acceptance body format":
    # Format: [32-byte txid (reversed)][1-byte label 'A'][8-byte mempool sequence (LE)]
    var data: array[41, byte]
    var txidBytes: array[32, byte]
    txidBytes[0] = 0xcd

    let hashBytes = reverseBytes(txidBytes)
    copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
    data[32] = byte(SEQ_ADDED)
    writeLE64(data, 33, 12345'u64)

    check data.len == 41
    check data[31] == 0xcd  # Original byte 0 is now at position 31
    check data[32] == byte('A')
    # Mempool sequence 12345 in LE
    check data[33] == byte(12345 and 0xff)
    check data[34] == byte((12345 shr 8) and 0xff)

  test "sequence tx removal body format":
    var data: array[41, byte]
    data[32] = byte(SEQ_REMOVED)
    check data[32] == byte('R')
