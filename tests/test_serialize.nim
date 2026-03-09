## Tests for binary serialization

import unittest2
import ../src/primitives/[types, serialize]

suite "BinaryWriter and BinaryReader":
  test "compact size encoding edge cases":
    # Test boundary values for CompactSize encoding
    var w = BinaryWriter()

    # Single byte values (0x00 to 0xFC)
    w.writeCompactSize(0)
    w.writeCompactSize(252)

    # Two byte values (0xFD prefix)
    w.writeCompactSize(253)
    w.writeCompactSize(0xFFFF)

    # Four byte values (0xFE prefix)
    w.writeCompactSize(0x10000)
    w.writeCompactSize(0xFFFFFFFF'u64)

    # Eight byte values (0xFF prefix)
    w.writeCompactSize(0x100000000'u64)
    w.writeCompactSize(0xFFFFFFFFFFFFFFFF'u64)

    var r = BinaryReader(data: w.data, pos: 0)

    check r.readCompactSize() == 0'u64
    check r.readCompactSize() == 252'u64
    check r.readCompactSize() == 253'u64
    check r.readCompactSize() == 0xFFFF'u64
    check r.readCompactSize() == 0x10000'u64
    check r.readCompactSize() == 0xFFFFFFFF'u64
    check r.readCompactSize() == 0x100000000'u64
    check r.readCompactSize() == 0xFFFFFFFFFFFFFFFF'u64

  test "little endian integer round-trip":
    var w = BinaryWriter()

    w.writeUint8(0xAB)
    w.writeUint16LE(0x1234)
    w.writeUint32LE(0x12345678)
    w.writeUint64LE(0x123456789ABCDEF0'u64)
    w.writeInt32LE(-12345)
    w.writeInt64LE(-9876543210'i64)

    var r = BinaryReader(data: w.data, pos: 0)

    check r.readUint8() == 0xAB'u8
    check r.readUint16LE() == 0x1234'u16
    check r.readUint32LE() == 0x12345678'u32
    check r.readUint64LE() == 0x123456789ABCDEF0'u64
    check r.readInt32LE() == -12345'i32
    check r.readInt64LE() == -9876543210'i64

  test "bytes and hash round-trip":
    var w = BinaryWriter()

    let testBytes = @[0x01'u8, 0x02, 0x03, 0x04, 0x05]
    var testHash: array[32, byte]
    for i in 0 ..< 32:
      testHash[i] = byte(i)

    w.writeBytes(testBytes)
    w.writeHash(testHash)
    w.writeVarBytes(testBytes)

    var r = BinaryReader(data: w.data, pos: 0)

    check r.readBytes(5) == testBytes
    check r.readHash() == testHash
    check r.readVarBytes() == testBytes

  test "underflow raises SerializationError":
    var r = BinaryReader(data: @[0x01'u8, 0x02], pos: 0)

    discard r.readUint8()
    discard r.readUint8()

    expect SerializationError:
      discard r.readUint8()

  test "underflow on hash read":
    var r = BinaryReader(data: newSeq[byte](20), pos: 0)

    expect SerializationError:
      discard r.readHash()

suite "genesis block header":
  test "genesis block header deserialization":
    # Bitcoin mainnet genesis block header (80 bytes, little-endian)
    let genesisHeaderHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

    proc hexToBytes(s: string): seq[byte] =
      result = newSeq[byte](s.len div 2)
      for i in 0 ..< result.len:
        result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

    let headerBytes = hexToBytes(genesisHeaderHex)
    check headerBytes.len == 80

    let header = deserializeBlockHeader(headerBytes)

    check header.version == 1
    check header.timestamp == 1231006505  # 2009-01-03 18:15:05 UTC
    check header.bits == 0x1d00ffff'u32
    check header.nonce == 2083236893'u32

    # Verify round-trip
    let reserialized = serialize(header)
    check reserialized == headerBytes

suite "legacy transaction":
  test "legacy transaction serialization round-trip":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0
        ),
        scriptSig: @[0x01'u8, 0x02, 0x03],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[0x76'u8, 0xa9]
      )],
      witnesses: @[],
      lockTime: 0
    )

    let serialized = serialize(tx)
    let decoded = deserializeTransaction(serialized)

    check decoded.version == tx.version
    check decoded.inputs.len == tx.inputs.len
    check decoded.inputs[0].scriptSig == tx.inputs[0].scriptSig
    check decoded.inputs[0].sequence == tx.inputs[0].sequence
    check decoded.outputs.len == tx.outputs.len
    check decoded.outputs[0].value == tx.outputs[0].value
    check decoded.outputs[0].scriptPubKey == tx.outputs[0].scriptPubKey
    check decoded.lockTime == tx.lockTime
    check decoded.witnesses.len == 0

  test "txid computation for legacy transaction":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[0x04'u8, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[0x41'u8, 0x04]  # simplified
      )],
      witnesses: @[],
      lockTime: 0
    )

    let computedTxid = txid(tx)
    let computedWtxid = wtxid(tx)

    # For legacy tx, txid == wtxid
    check computedTxid == computedWtxid

suite "segwit transaction":
  test "segwit transaction serialization round-trip":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0
        ),
        scriptSig: @[],  # Empty for native segwit
        sequence: 0xFFFFFFFE'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(10000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)  # P2WPKH
      )],
      witnesses: @[@[
        @[0x30'u8, 0x44],  # Signature (simplified)
        @[0x02'u8, 0x33]   # Pubkey (simplified)
      ]],
      lockTime: 500000
    )

    let serialized = serialize(tx)

    # Check segwit marker and flag are present
    check serialized[4] == 0x00  # Marker
    check serialized[5] == 0x01  # Flag

    let decoded = deserializeTransaction(serialized)

    check decoded.version == tx.version
    check decoded.inputs.len == tx.inputs.len
    check decoded.outputs.len == tx.outputs.len
    check decoded.witnesses.len == tx.witnesses.len
    check decoded.witnesses[0].len == tx.witnesses[0].len
    check decoded.witnesses[0][0] == tx.witnesses[0][0]
    check decoded.witnesses[0][1] == tx.witnesses[0][1]
    check decoded.lockTime == tx.lockTime

  test "txid excludes witness, wtxid includes witness":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[@[
        @[0x30'u8, 0x45],  # Signature
        @[0x02'u8, 0x21]   # Pubkey
      ]],
      lockTime: 0
    )

    let computedTxid = txid(tx)
    let computedWtxid = wtxid(tx)

    # For segwit tx, txid != wtxid (witness changes wtxid)
    check computedTxid != computedWtxid

    # Verify txid is hash of legacy serialization
    let legacySerialized = serializeLegacy(tx)
    check legacySerialized[4] != 0x00  # No segwit marker in legacy

  test "segwit with multiple inputs and witnesses":
    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
          scriptSig: @[],
          sequence: 0xFFFFFFFF'u32
        ),
        TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 1),
          scriptSig: @[],
          sequence: 0xFFFFFFFF'u32
        )
      ],
      outputs: @[TxOut(
        value: Satoshi(5000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[
        @[@[0x01'u8, 0x02], @[0x03'u8, 0x04]],  # Witness for input 0
        @[@[0x05'u8, 0x06], @[0x07'u8, 0x08]]   # Witness for input 1
      ],
      lockTime: 0
    )

    let serialized = serialize(tx)
    let decoded = deserializeTransaction(serialized)

    check decoded.inputs.len == 2
    check decoded.witnesses.len == 2
    check decoded.witnesses[0].len == 2
    check decoded.witnesses[1].len == 2
    check decoded.witnesses[0][0] == @[0x01'u8, 0x02]
    check decoded.witnesses[1][1] == @[0x07'u8, 0x08]

suite "block serialization":
  test "block header serialization":
    var header = BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1231006505,
      bits: 0x1d00ffff,
      nonce: 2083236893
    )

    let serialized = serialize(header)
    check serialized.len == 80  # Block header is always 80 bytes

    let decoded = deserializeBlockHeader(serialized)

    check decoded.version == header.version
    check decoded.timestamp == header.timestamp
    check decoded.bits == header.bits
    check decoded.nonce == header.nonce

  test "full block serialization round-trip":
    let coinbaseTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[0x04'u8],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[0x76'u8, 0xa9]
      )],
      witnesses: @[],
      lockTime: 0
    )

    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: default(array[32, byte]),
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 2083236893
      ),
      txs: @[coinbaseTx]
    )

    let serialized = serialize(blk)
    let decoded = deserializeBlock(serialized)

    check decoded.header.version == blk.header.version
    check decoded.header.timestamp == blk.header.timestamp
    check decoded.txs.len == 1
    check decoded.txs[0].inputs.len == 1
    check decoded.txs[0].outputs.len == 1

import std/strutils

when isMainModule:
  # Run tests
  echo "Running serialization tests..."
