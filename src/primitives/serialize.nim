## Binary serialization for Bitcoin protocol
## Stream-based BinaryWriter/BinaryReader for wire format
## Little-endian encoding for all integer types
## CompactSize (varint) encoding for variable-length data
## Segwit transaction support with txid/wtxid computation

import ./types

type
  BinaryWriter* = object
    data*: seq[byte]

  BinaryReader* = object
    data*: seq[byte]
    pos*: int

# BinaryWriter procedures

proc writeUint8*(w: var BinaryWriter, v: uint8) =
  w.data.add(v)

proc writeUint16LE*(w: var BinaryWriter, v: uint16) =
  w.data.add(byte(v and 0xFF))
  w.data.add(byte((v shr 8) and 0xFF))

proc writeUint32LE*(w: var BinaryWriter, v: uint32) =
  for i in 0 ..< 4:
    w.data.add(byte((v shr (i * 8)) and 0xFF))

proc writeUint64LE*(w: var BinaryWriter, v: uint64) =
  for i in 0 ..< 8:
    w.data.add(byte((v shr (i * 8)) and 0xFF))

proc writeInt32LE*(w: var BinaryWriter, v: int32) =
  w.writeUint32LE(cast[uint32](v))

proc writeInt64LE*(w: var BinaryWriter, v: int64) =
  w.writeUint64LE(cast[uint64](v))

proc writeBytes*(w: var BinaryWriter, b: openArray[byte]) =
  for x in b:
    w.data.add(x)

proc writeHash*(w: var BinaryWriter, h: array[32, byte]) =
  w.writeBytes(h)

proc writeCompactSize*(w: var BinaryWriter, v: uint64) =
  if v < 0xFD:
    w.writeUint8(uint8(v))
  elif v <= 0xFFFF:
    w.writeUint8(0xFD)
    w.writeUint16LE(uint16(v))
  elif v <= 0xFFFFFFFF'u64:
    w.writeUint8(0xFE)
    w.writeUint32LE(uint32(v))
  else:
    w.writeUint8(0xFF)
    w.writeUint64LE(v)

proc writeVarBytes*(w: var BinaryWriter, b: openArray[byte]) =
  w.writeCompactSize(uint64(b.len))
  w.writeBytes(b)

# BinaryReader procedures

proc remaining*(r: BinaryReader): int =
  r.data.len - r.pos

proc readUint8*(r: var BinaryReader): uint8 =
  if r.pos >= r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  result = r.data[r.pos]
  inc r.pos

proc readUint16LE*(r: var BinaryReader): uint16 =
  if r.pos + 2 > r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  result = uint16(r.data[r.pos]) or (uint16(r.data[r.pos + 1]) shl 8)
  r.pos += 2

proc readUint32LE*(r: var BinaryReader): uint32 =
  if r.pos + 4 > r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  for i in 0 ..< 4:
    result = result or (uint32(r.data[r.pos + i]) shl (i * 8))
  r.pos += 4

proc readUint64LE*(r: var BinaryReader): uint64 =
  if r.pos + 8 > r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  for i in 0 ..< 8:
    result = result or (uint64(r.data[r.pos + i]) shl (i * 8))
  r.pos += 8

proc readInt32LE*(r: var BinaryReader): int32 =
  cast[int32](r.readUint32LE())

proc readInt64LE*(r: var BinaryReader): int64 =
  cast[int64](r.readUint64LE())

proc readBytes*(r: var BinaryReader, n: int): seq[byte] =
  if r.pos + n > r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  result = r.data[r.pos ..< r.pos + n]
  r.pos += n

proc readHash*(r: var BinaryReader): array[32, byte] =
  if r.pos + 32 > r.data.len:
    raise newException(SerializationError, "unexpected end of data")
  copyMem(addr result[0], addr r.data[r.pos], 32)
  r.pos += 32

proc readCompactSize*(r: var BinaryReader): uint64 =
  let first = r.readUint8()
  if first < 0xFD:
    result = uint64(first)
  elif first == 0xFD:
    result = uint64(r.readUint16LE())
  elif first == 0xFE:
    result = uint64(r.readUint32LE())
  else:
    result = r.readUint64LE()

proc readVarBytes*(r: var BinaryReader): seq[byte] =
  let length = r.readCompactSize()
  r.readBytes(int(length))

# High-level serialization for Bitcoin types

proc writeTxId*(w: var BinaryWriter, txid: TxId) =
  w.writeHash(array[32, byte](txid))

proc writeBlockHash*(w: var BinaryWriter, hash: BlockHash) =
  w.writeHash(array[32, byte](hash))

proc readTxId*(r: var BinaryReader): TxId =
  TxId(r.readHash())

proc readBlockHash*(r: var BinaryReader): BlockHash =
  BlockHash(r.readHash())

proc writeOutPoint*(w: var BinaryWriter, op: OutPoint) =
  w.writeTxId(op.txid)
  w.writeUint32LE(op.vout)

proc readOutPoint*(r: var BinaryReader): OutPoint =
  result.txid = r.readTxId()
  result.vout = r.readUint32LE()

proc writeTxIn*(w: var BinaryWriter, txin: TxIn) =
  w.writeOutPoint(txin.prevOut)
  w.writeVarBytes(txin.scriptSig)
  w.writeUint32LE(txin.sequence)

proc readTxIn*(r: var BinaryReader): TxIn =
  result.prevOut = r.readOutPoint()
  result.scriptSig = r.readVarBytes()
  result.sequence = r.readUint32LE()

proc writeTxOut*(w: var BinaryWriter, txout: TxOut) =
  w.writeInt64LE(int64(txout.value))
  w.writeVarBytes(txout.scriptPubKey)

proc readTxOut*(r: var BinaryReader): TxOut =
  result.value = Satoshi(r.readInt64LE())
  result.scriptPubKey = r.readVarBytes()

proc writeWitness*(w: var BinaryWriter, witness: seq[seq[byte]]) =
  ## Write a single input's witness stack
  w.writeCompactSize(uint64(witness.len))
  for item in witness:
    w.writeVarBytes(item)

proc readWitness*(r: var BinaryReader): seq[seq[byte]] =
  ## Read a single input's witness stack
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.add(r.readVarBytes())

proc writeTransaction*(w: var BinaryWriter, tx: Transaction, includeWitness: bool = true) =
  ## Write transaction in wire format
  ## If includeWitness is true and tx has witness data, writes segwit format
  let hasWitness = tx.witnesses.len > 0 and includeWitness

  w.writeInt32LE(tx.version)

  if hasWitness:
    # Segwit marker and flag
    w.writeUint8(0x00)
    w.writeUint8(0x01)

  # Inputs
  w.writeCompactSize(uint64(tx.inputs.len))
  for input in tx.inputs:
    w.writeTxIn(input)

  # Outputs
  w.writeCompactSize(uint64(tx.outputs.len))
  for output in tx.outputs:
    w.writeTxOut(output)

  # Witness data (if segwit)
  if hasWitness:
    for i in 0 ..< tx.inputs.len:
      if i < tx.witnesses.len:
        w.writeWitness(tx.witnesses[i])
      else:
        w.writeCompactSize(0)  # Empty witness stack

  w.writeUint32LE(tx.lockTime)

proc readTransaction*(r: var BinaryReader): Transaction =
  ## Read transaction from wire format, auto-detecting segwit
  result.version = r.readInt32LE()

  # Check for segwit marker
  let marker = r.readUint8()
  var isSegwit = false

  if marker == 0x00:
    # Potential segwit transaction
    let flag = r.readUint8()
    if flag != 0x01:
      raise newException(SerializationError, "invalid segwit flag")
    isSegwit = true
  else:
    # Legacy transaction - marker was actually the input count
    # We need to handle this carefully since we already read the first byte
    # Reconstruct the compact size
    var inputCount: uint64
    if marker < 0xFD:
      inputCount = uint64(marker)
    elif marker == 0xFD:
      inputCount = uint64(r.readUint16LE())
    elif marker == 0xFE:
      inputCount = uint64(r.readUint32LE())
    else:
      inputCount = r.readUint64LE()

    for i in 0 ..< int(inputCount):
      result.inputs.add(r.readTxIn())

    let outputCount = r.readCompactSize()
    for i in 0 ..< int(outputCount):
      result.outputs.add(r.readTxOut())

    result.lockTime = r.readUint32LE()
    return

  # Continue reading segwit transaction
  let inputCount = r.readCompactSize()
  for i in 0 ..< int(inputCount):
    result.inputs.add(r.readTxIn())

  let outputCount = r.readCompactSize()
  for i in 0 ..< int(outputCount):
    result.outputs.add(r.readTxOut())

  # Read witness data
  for i in 0 ..< result.inputs.len:
    result.witnesses.add(r.readWitness())

  result.lockTime = r.readUint32LE()

proc writeBlockHeader*(w: var BinaryWriter, header: BlockHeader) =
  w.writeInt32LE(header.version)
  w.writeBlockHash(header.prevBlock)
  w.writeHash(header.merkleRoot)
  w.writeUint32LE(header.timestamp)
  w.writeUint32LE(header.bits)
  w.writeUint32LE(header.nonce)

proc readBlockHeader*(r: var BinaryReader): BlockHeader =
  result.version = r.readInt32LE()
  result.prevBlock = r.readBlockHash()
  result.merkleRoot = r.readHash()
  result.timestamp = r.readUint32LE()
  result.bits = r.readUint32LE()
  result.nonce = r.readUint32LE()

proc writeBlock*(w: var BinaryWriter, blk: Block) =
  w.writeBlockHeader(blk.header)
  w.writeCompactSize(uint64(blk.txs.len))
  for tx in blk.txs:
    w.writeTransaction(tx)

proc readBlock*(r: var BinaryReader): Block =
  result.header = r.readBlockHeader()
  let txCount = r.readCompactSize()
  for i in 0 ..< int(txCount):
    result.txs.add(r.readTransaction())

# Convenience serialization functions

proc serialize*(tx: Transaction, includeWitness: bool = true): seq[byte] =
  var w = BinaryWriter()
  w.writeTransaction(tx, includeWitness)
  result = w.data

proc serializeLegacy*(tx: Transaction): seq[byte] =
  ## Serialize without witness data (for txid computation)
  serialize(tx, includeWitness = false)

proc serialize*(header: BlockHeader): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHeader(header)
  result = w.data

proc serialize*(blk: Block): seq[byte] =
  var w = BinaryWriter()
  w.writeBlock(blk)
  result = w.data

proc deserializeTransaction*(data: seq[byte]): Transaction =
  var r = BinaryReader(data: data, pos: 0)
  r.readTransaction()

proc deserializeBlockHeader*(data: seq[byte]): BlockHeader =
  var r = BinaryReader(data: data, pos: 0)
  r.readBlockHeader()

proc deserializeBlock*(data: seq[byte]): Block =
  var r = BinaryReader(data: data, pos: 0)
  r.readBlock()

# txid and wtxid computation
import ../crypto/hashing

proc txid*(tx: Transaction): TxId =
  ## Compute transaction ID (hash of legacy serialization, excludes witness)
  let legacyData = tx.serializeLegacy()
  TxId(doubleSha256(legacyData))

proc wtxid*(tx: Transaction): TxId =
  ## Compute witness transaction ID (hash of full serialization)
  ## For non-segwit transactions, wtxid equals txid
  let fullData = tx.serialize(includeWitness = true)
  TxId(doubleSha256(fullData))
