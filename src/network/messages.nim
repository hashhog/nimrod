## Bitcoin P2P network messages
## Protocol message serialization and deserialization

import std/[streams, endians]
import ../primitives/[types, serialize]
import ../crypto/hashing

const
  PROTOCOL_VERSION* = 70016
  USER_AGENT* = "/nimrod:0.1.0/"

type
  MessageHeader* = object
    magic*: array[4, byte]
    command*: array[12, byte]
    length*: uint32
    checksum*: array[4, byte]

  NetAddr* = object
    services*: uint64
    ip*: array[16, byte]  # IPv6 or IPv4-mapped
    port*: uint16

  VersionMessage* = object
    version*: int32
    services*: uint64
    timestamp*: int64
    addrRecv*: NetAddr
    addrFrom*: NetAddr
    nonce*: uint64
    userAgent*: string
    startHeight*: int32
    relay*: bool

  VerackMessage* = object
    # Empty

  PingMessage* = object
    nonce*: uint64

  PongMessage* = object
    nonce*: uint64

  InvType* = enum
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_WITNESS_TX = 0x40000001
    MSG_WITNESS_BLOCK = 0x40000002

  InvVector* = object
    invType*: uint32
    hash*: array[32, byte]

  InvMessage* = object
    inventory*: seq[InvVector]

  GetDataMessage* = object
    inventory*: seq[InvVector]

  GetBlocksMessage* = object
    version*: uint32
    locatorHashes*: seq[array[32, byte]]
    hashStop*: array[32, byte]

  GetHeadersMessage* = object
    version*: uint32
    locatorHashes*: seq[array[32, byte]]
    hashStop*: array[32, byte]

  HeadersMessage* = object
    headers*: seq[BlockHeader]

  BlockMessage* = object
    blk*: Block

  TxMessage* = object
    tx*: Transaction

  AddrMessage* = object
    addresses*: seq[tuple[time: uint32, addr: NetAddr]]

  RejectMessage* = object
    message*: string
    code*: byte
    reason*: string

proc commandToBytes(cmd: string): array[12, byte] =
  for i in 0 ..< min(cmd.len, 12):
    result[i] = byte(cmd[i])

proc bytesToCommand(cmd: array[12, byte]): string =
  result = ""
  for b in cmd:
    if b == 0:
      break
    result.add(char(b))

proc readNetAddr*(s: Stream, includeTime: bool = false): NetAddr =
  if includeTime:
    discard s.readUint32LE()  # timestamp
  result.services = s.readUint64LE()
  if s.readData(addr result.ip[0], 16) != 16:
    raise newException(SerializeError, "unexpected end of stream")
  var portBuf: array[2, byte]
  if s.readData(addr portBuf[0], 2) != 2:
    raise newException(SerializeError, "unexpected end of stream")
  result.port = (uint16(portBuf[0]) shl 8) or uint16(portBuf[1])  # Big endian

proc writeNetAddr*(s: Stream, addr: NetAddr, includeTime: bool = false) =
  if includeTime:
    s.writeUint32LE(0)  # timestamp
  s.writeUint64LE(addr.services)
  s.writeData(unsafeAddr addr.ip[0], 16)
  s.write(byte((addr.port shr 8) and 0xff))
  s.write(byte(addr.port and 0xff))

proc readVarString*(s: Stream): string =
  let len = s.readCompactSize()
  result = ""
  for i in 0 ..< int(uint64(len)):
    result.add(char(s.readUint8()))

proc writeVarString*(s: Stream, str: string) =
  s.writeCompactSize(CompactSize(str.len))
  for c in str:
    s.write(byte(c))

proc readVersionMessage*(s: Stream): VersionMessage =
  result.version = s.readInt32LE()
  result.services = s.readUint64LE()
  result.timestamp = s.readInt64LE()
  result.addrRecv = s.readNetAddr()
  result.addrFrom = s.readNetAddr()
  result.nonce = s.readUint64LE()
  result.userAgent = s.readVarString()
  result.startHeight = s.readInt32LE()
  if result.version >= 70001:
    result.relay = s.readUint8() != 0

proc writeVersionMessage*(s: Stream, msg: VersionMessage) =
  s.writeInt32LE(msg.version)
  s.writeUint64LE(msg.services)
  s.writeInt64LE(msg.timestamp)
  s.writeNetAddr(msg.addrRecv)
  s.writeNetAddr(msg.addrFrom)
  s.writeUint64LE(msg.nonce)
  s.writeVarString(msg.userAgent)
  s.writeInt32LE(msg.startHeight)
  if msg.version >= 70001:
    s.writeUint8(if msg.relay: 1 else: 0)

proc readInvVector*(s: Stream): InvVector =
  result.invType = s.readUint32LE()
  result.hash = s.readArray32()

proc writeInvVector*(s: Stream, inv: InvVector) =
  s.writeUint32LE(inv.invType)
  s.writeArray32(inv.hash)

proc readInvMessage*(s: Stream): InvMessage =
  let count = s.readCompactSize()
  for i in 0 ..< int(uint64(count)):
    result.inventory.add(s.readInvVector())

proc writeInvMessage*(s: Stream, msg: InvMessage) =
  s.writeCompactSize(CompactSize(msg.inventory.len))
  for inv in msg.inventory:
    s.writeInvVector(inv)

proc readHeadersMessage*(s: Stream): HeadersMessage =
  let count = s.readCompactSize()
  for i in 0 ..< int(uint64(count)):
    result.headers.add(s.readBlockHeader())
    discard s.readCompactSize()  # txn_count (always 0)

proc writeHeadersMessage*(s: Stream, msg: HeadersMessage) =
  s.writeCompactSize(CompactSize(msg.headers.len))
  for header in msg.headers:
    s.writeBlockHeader(header)
    s.writeCompactSize(CompactSize(0))  # txn_count

proc serializeMessage*(magic: array[4, byte], command: string, payload: seq[byte]): seq[byte] =
  ## Wrap a payload with message header
  let s = newStringStream()

  # Header
  s.writeData(unsafeAddr magic[0], 4)
  let cmdBytes = commandToBytes(command)
  s.writeData(unsafeAddr cmdBytes[0], 12)
  s.writeUint32LE(uint32(payload.len))

  # Checksum is first 4 bytes of double SHA256
  let checksum = doubleSha256(payload)
  s.writeData(unsafeAddr checksum[0], 4)

  # Payload
  if payload.len > 0:
    s.writeData(unsafeAddr payload[0], payload.len)

  s.setPosition(0)
  result = cast[seq[byte]](s.readAll())

proc parseMessageHeader*(data: openArray[byte]): MessageHeader =
  if data.len < 24:
    raise newException(SerializeError, "header too short")
  copyMem(addr result.magic[0], unsafeAddr data[0], 4)
  copyMem(addr result.command[0], unsafeAddr data[4], 12)
  result.length = uint32(data[16]) or (uint32(data[17]) shl 8) or
                  (uint32(data[18]) shl 16) or (uint32(data[19]) shl 24)
  copyMem(addr result.checksum[0], unsafeAddr data[20], 4)

proc verifyChecksum*(header: MessageHeader, payload: openArray[byte]): bool =
  let checksum = doubleSha256(payload)
  for i in 0..3:
    if header.checksum[i] != checksum[i]:
      return false
  true
