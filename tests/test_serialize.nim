## Tests for serialization

import unittest2
import std/streams
import ../src/primitives/[types, serialize]

suite "serialization":
  test "compact size encoding":
    # Test various compact size values
    let s = newStringStream()

    s.writeCompactSize(CompactSize(0))
    s.writeCompactSize(CompactSize(252))
    s.writeCompactSize(CompactSize(253))
    s.writeCompactSize(CompactSize(0xFFFF))
    s.writeCompactSize(CompactSize(0x10000))
    s.writeCompactSize(CompactSize(0xFFFFFFFF'u64))

    s.setPosition(0)

    check s.readCompactSize() == CompactSize(0)
    check s.readCompactSize() == CompactSize(252)
    check s.readCompactSize() == CompactSize(253)
    check s.readCompactSize() == CompactSize(0xFFFF)
    check s.readCompactSize() == CompactSize(0x10000)
    check s.readCompactSize() == CompactSize(0xFFFFFFFF'u64)

  test "little endian integers":
    let s = newStringStream()

    s.writeUint16LE(0x1234)
    s.writeUint32LE(0x12345678)
    s.writeUint64LE(0x123456789ABCDEF0'u64)

    s.setPosition(0)

    check s.readUint16LE() == 0x1234'u16
    check s.readUint32LE() == 0x12345678'u32
    check s.readUint64LE() == 0x123456789ABCDEF0'u64

  test "transaction serialization roundtrip":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0
        ),
        scriptSig: ScriptBytes(@[0x01'u8, 0x02, 0x03]),
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: ScriptBytes(@[0x76'u8, 0xa9])
      )],
      lockTime: 0
    )

    let serialized = serialize(tx)
    let s = newStringStream(cast[string](serialized))
    let decoded = s.readTransaction()

    check decoded.version == tx.version
    check decoded.inputs.len == tx.inputs.len
    check decoded.outputs.len == tx.outputs.len
    check decoded.outputs[0].value == tx.outputs[0].value
    check decoded.lockTime == tx.lockTime

  test "block header serialization":
    var header = BlockHeader(
      version: 1,
      prevHash: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1231006505,
      bits: 0x1d00ffff,
      nonce: 2083236893
    )

    let serialized = serialize(header)
    check serialized.len == 80  # Block header is always 80 bytes

    let s = newStringStream(cast[string](serialized))
    let decoded = s.readBlockHeader()

    check decoded.version == header.version
    check decoded.timestamp == header.timestamp
    check decoded.bits == header.bits
    check decoded.nonce == header.nonce
