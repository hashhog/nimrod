## Binary serialization for Bitcoin protocol
## Little-endian encoding for all integer types
## CompactSize/VarInt encoding for variable-length data

import std/[streams]
import ./types

type
  SerializeError* = object of CatchableError

# Reading primitives
proc readUint8*(s: Stream): uint8 =
  if s.readData(addr result, 1) != 1:
    raise newException(SerializeError, "unexpected end of stream")

proc readUint16LE*(s: Stream): uint16 =
  var buf: array[2, byte]
  if s.readData(addr buf[0], 2) != 2:
    raise newException(SerializeError, "unexpected end of stream")
  result = uint16(buf[0]) or (uint16(buf[1]) shl 8)

proc readUint32LE*(s: Stream): uint32 =
  var buf: array[4, byte]
  if s.readData(addr buf[0], 4) != 4:
    raise newException(SerializeError, "unexpected end of stream")
  result = uint32(buf[0]) or (uint32(buf[1]) shl 8) or
           (uint32(buf[2]) shl 16) or (uint32(buf[3]) shl 24)

proc readUint64LE*(s: Stream): uint64 =
  var buf: array[8, byte]
  if s.readData(addr buf[0], 8) != 8:
    raise newException(SerializeError, "unexpected end of stream")
  for i in 0..7:
    result = result or (uint64(buf[i]) shl (i * 8))

proc readInt32LE*(s: Stream): int32 =
  cast[int32](s.readUint32LE())

proc readInt64LE*(s: Stream): int64 =
  cast[int64](s.readUint64LE())

proc readCompactSize*(s: Stream): CompactSize =
  let first = s.readUint8()
  if first < 0xFD:
    result = CompactSize(first)
  elif first == 0xFD:
    result = CompactSize(s.readUint16LE())
  elif first == 0xFE:
    result = CompactSize(s.readUint32LE())
  else:
    result = CompactSize(s.readUint64LE())

proc readBytes*(s: Stream, count: int): seq[byte] =
  result = newSeq[byte](count)
  if count > 0:
    if s.readData(addr result[0], count) != count:
      raise newException(SerializeError, "unexpected end of stream")

proc readArray32*(s: Stream): array[32, byte] =
  if s.readData(addr result[0], 32) != 32:
    raise newException(SerializeError, "unexpected end of stream")

# Writing primitives
proc writeUint8*(s: Stream, v: uint8) =
  s.write(v)

proc writeUint16LE*(s: Stream, v: uint16) =
  s.write(byte(v and 0xFF))
  s.write(byte((v shr 8) and 0xFF))

proc writeUint32LE*(s: Stream, v: uint32) =
  for i in 0..3:
    s.write(byte((v shr (i * 8)) and 0xFF))

proc writeUint64LE*(s: Stream, v: uint64) =
  for i in 0..7:
    s.write(byte((v shr (i * 8)) and 0xFF))

proc writeInt32LE*(s: Stream, v: int32) =
  s.writeUint32LE(cast[uint32](v))

proc writeInt64LE*(s: Stream, v: int64) =
  s.writeUint64LE(cast[uint64](v))

proc writeCompactSize*(s: Stream, v: CompactSize) =
  let n = uint64(v)
  if n < 0xFD:
    s.writeUint8(uint8(n))
  elif n <= 0xFFFF:
    s.writeUint8(0xFD)
    s.writeUint16LE(uint16(n))
  elif n <= 0xFFFFFFFF'u64:
    s.writeUint8(0xFE)
    s.writeUint32LE(uint32(n))
  else:
    s.writeUint8(0xFF)
    s.writeUint64LE(n)

proc writeBytes*(s: Stream, data: openArray[byte]) =
  if data.len > 0:
    s.writeData(unsafeAddr data[0], data.len)

proc writeArray32*(s: Stream, data: array[32, byte]) =
  s.writeData(unsafeAddr data[0], 32)

# High-level serialization
proc readTxId*(s: Stream): TxId =
  TxId(s.readArray32())

proc readBlockHash*(s: Stream): BlockHash =
  BlockHash(s.readArray32())

proc writeTxId*(s: Stream, txid: TxId) =
  s.writeArray32(array[32, byte](txid))

proc writeBlockHash*(s: Stream, hash: BlockHash) =
  s.writeArray32(array[32, byte](hash))

proc readScriptBytes*(s: Stream): ScriptBytes =
  let length = s.readCompactSize()
  ScriptBytes(s.readBytes(int(uint64(length))))

proc writeScriptBytes*(s: Stream, script: ScriptBytes) =
  s.writeCompactSize(CompactSize(seq[byte](script).len))
  s.writeBytes(seq[byte](script))

proc readOutPoint*(s: Stream): OutPoint =
  result.txid = s.readTxId()
  result.vout = s.readUint32LE()

proc writeOutPoint*(s: Stream, op: OutPoint) =
  s.writeTxId(op.txid)
  s.writeUint32LE(op.vout)

proc readTxIn*(s: Stream): TxIn =
  result.prevout = s.readOutPoint()
  result.scriptSig = s.readScriptBytes()
  result.sequence = s.readUint32LE()

proc writeTxIn*(s: Stream, txin: TxIn) =
  s.writeOutPoint(txin.prevout)
  s.writeScriptBytes(txin.scriptSig)
  s.writeUint32LE(txin.sequence)

proc readTxOut*(s: Stream): TxOut =
  result.value = Satoshi(s.readInt64LE())
  result.scriptPubKey = s.readScriptBytes()

proc writeTxOut*(s: Stream, txout: TxOut) =
  s.writeInt64LE(int64(txout.value))
  s.writeScriptBytes(txout.scriptPubKey)

proc readTransaction*(s: Stream): Transaction =
  result.version = s.readInt32LE()
  let inputCount = s.readCompactSize()
  for i in 0 ..< int(uint64(inputCount)):
    result.inputs.add(s.readTxIn())
  let outputCount = s.readCompactSize()
  for i in 0 ..< int(uint64(outputCount)):
    result.outputs.add(s.readTxOut())
  result.lockTime = s.readUint32LE()

proc writeTransaction*(s: Stream, tx: Transaction) =
  s.writeInt32LE(tx.version)
  s.writeCompactSize(CompactSize(tx.inputs.len))
  for input in tx.inputs:
    s.writeTxIn(input)
  s.writeCompactSize(CompactSize(tx.outputs.len))
  for output in tx.outputs:
    s.writeTxOut(output)
  s.writeUint32LE(tx.lockTime)

proc readBlockHeader*(s: Stream): BlockHeader =
  result.version = s.readInt32LE()
  result.prevHash = s.readBlockHash()
  result.merkleRoot = s.readArray32()
  result.timestamp = s.readUint32LE()
  result.bits = s.readUint32LE()
  result.nonce = s.readUint32LE()

proc writeBlockHeader*(s: Stream, header: BlockHeader) =
  s.writeInt32LE(header.version)
  s.writeBlockHash(header.prevHash)
  s.writeArray32(header.merkleRoot)
  s.writeUint32LE(header.timestamp)
  s.writeUint32LE(header.bits)
  s.writeUint32LE(header.nonce)

proc readBlock*(s: Stream): Block =
  result.header = s.readBlockHeader()
  let txCount = s.readCompactSize()
  for i in 0 ..< int(uint64(txCount)):
    result.transactions.add(s.readTransaction())

proc writeBlock*(s: Stream, blk: Block) =
  s.writeBlockHeader(blk.header)
  s.writeCompactSize(CompactSize(blk.transactions.len))
  for tx in blk.transactions:
    s.writeTransaction(tx)

# Convenience functions
proc serialize*(tx: Transaction): seq[byte] =
  let s = newStringStream()
  s.writeTransaction(tx)
  s.setPosition(0)
  result = cast[seq[byte]](s.readAll())

proc serialize*(header: BlockHeader): seq[byte] =
  let s = newStringStream()
  s.writeBlockHeader(header)
  s.setPosition(0)
  result = cast[seq[byte]](s.readAll())

proc serialize*(blk: Block): seq[byte] =
  let s = newStringStream()
  s.writeBlock(blk)
  s.setPosition(0)
  result = cast[seq[byte]](s.readAll())
