## Bitcoin P2P protocol messages
## Serialization and deserialization for all P2P message types
## Wire format: header envelope + payload

import ../primitives/[types, serialize]
import ../crypto/hashing
import ./compact_blocks
import ./addr
export addr
import std/options

const
  MaxMessagePayload* = 33_554_432  # 32 MiB
  MaxHeadersPerMsg* = 2000
  MaxInvPerMsg* = 50_000
  ProtocolVersion* = 70016'u32
  UserAgent* = "/nimrod:0.1.0/"
  NodeNetwork* = 1'u64
  NodeBloom* = 4'u64           ## BIP-111 / BIP-35: served bloom filters + mempool
  NodeWitness* = 8'u64
  NodeNetworkLimited* = 1024'u64

type
  MessageHeader* = object
    magic*: array[4, byte]
    command*: array[12, byte]
    length*: uint32
    checksum*: array[4, byte]

  InvType* = enum
    invError = 0
    invTx = 1
    invBlock = 2
    invFilteredBlock = 3
    invCmpctBlock = 4
    invWitnessTx = 0x40000001
    invWitnessBlock = 0x40000002

  InvVector* = object
    invType*: InvType
    hash*: array[32, byte]

  # NetAddress and TimestampedAddr are defined in addr.nim (imported + exported above)

  VersionMsg* = object
    version*: uint32
    services*: uint64
    timestamp*: int64
    addrRecv*: NetAddress
    addrFrom*: NetAddress
    nonce*: uint64
    userAgent*: string
    startHeight*: int32
    relay*: bool

  GetHeadersMsg* = object
    version*: uint32
    locatorHashes*: seq[array[32, byte]]
    hashStop*: array[32, byte]

  GetBlocksMsg* = object
    version*: uint32
    locatorHashes*: seq[array[32, byte]]
    hashStop*: array[32, byte]

  RejectMsg* = object
    message*: string
    code*: uint8
    reason*: string

  SendCmpctMsg* = object
    announce*: bool
    version*: uint64

  ## SendPackages message for package relay negotiation (BIP 331)
  ## Indicates peer supports package relay
  SendPackagesMsg* = object
    version*: uint32  ## Package relay protocol version

  ## BIP330 sendtxrcncl - signal transaction reconciliation support
  SendTxRcnclMsg* = object
    version*: uint32   ## Reconciliation protocol version (currently 1)
    salt*: uint64      ## Local salt for short ID computation

  ## BIP330 reqrecon - request reconciliation sketch from peer
  ReqReconMsg* = object
    setSize*: uint16      ## Our local set size estimate
    q*: uint16            ## Parameter for sketch capacity (capacity = setSize + q)

  ## BIP330 sketch - reconciliation sketch message
  SketchMsg* = object
    sketchData*: seq[byte]  ## Serialized minisketch data

  ## BIP330 reconcildiff - request missing short IDs
  ReconcilDiffMsg* = object
    success*: bool                ## True if sketch decoding succeeded
    shortIds*: seq[uint32]        ## Short IDs we need (decoded from sketch)

  ## BIP330 reqsketchext - request extended sketch (larger capacity)
  ReqSketchExtMsg* = object
    discard  ## Empty message

  MessageKind* = enum
    mkVersion
    mkVerack
    mkPing
    mkPong
    mkAddr
    mkAddrV2
    mkInv
    mkGetData
    mkNotFound
    mkGetBlocks
    mkGetHeaders
    mkHeaders
    mkBlock
    mkTx
    mkGetAddr
    mkReject
    mkSendHeaders
    mkSendCmpct
    mkFeeFilter
    mkWtxidRelay
    mkSendAddrV2
    mkCmpctBlock
    mkGetBlockTxn
    mkBlockTxn
    mkSendPackages
    mkMempool
    # BIP330 Erlay messages
    mkSendTxRcncl
    mkReqRecon
    mkSketch
    mkReconcilDiff
    mkReqSketchExt

  P2PMessage* = object
    case kind*: MessageKind
    of mkVersion:
      version*: VersionMsg
    of mkVerack, mkGetAddr, mkSendHeaders, mkWtxidRelay, mkSendAddrV2, mkSendPackages, mkReqSketchExt, mkMempool:
      discard
    of mkPing:
      pingNonce*: uint64
    of mkPong:
      pongNonce*: uint64
    of mkAddr:
      addresses*: seq[TimestampedAddr]
    of mkAddrV2:
      addressesV2*: seq[TimestampedAddrV2]
    of mkInv:
      invItems*: seq[InvVector]
    of mkGetData:
      getData*: seq[InvVector]
    of mkNotFound:
      notFound*: seq[InvVector]
    of mkGetBlocks:
      getBlocks*: GetBlocksMsg
    of mkGetHeaders:
      getHeaders*: GetHeadersMsg
    of mkHeaders:
      headers*: seq[BlockHeader]
    of mkBlock:
      blk*: Block
    of mkTx:
      tx*: Transaction
    of mkReject:
      reject*: RejectMsg
    of mkSendCmpct:
      sendCmpct*: SendCmpctMsg
    of mkFeeFilter:
      feeRate*: uint64
    of mkCmpctBlock:
      cmpctBlock*: CompactBlock
    of mkGetBlockTxn:
      getBlockTxn*: BlockTxnRequest
    of mkBlockTxn:
      blockTxn*: BlockTxnResponse
    # BIP330 Erlay messages
    of mkSendTxRcncl:
      sendTxRcncl*: SendTxRcnclMsg
    of mkReqRecon:
      reqRecon*: ReqReconMsg
    of mkSketch:
      sketch*: SketchMsg
    of mkReconcilDiff:
      reconcilDiff*: ReconcilDiffMsg

# Command name conversion

proc commandToBytes*(cmd: string): array[12, byte] =
  ## Convert command string to 12-byte null-padded array
  for i in 0 ..< min(cmd.len, 12):
    result[i] = byte(cmd[i])
  # Remaining bytes are already zero-initialized

proc bytesToCommand*(b: array[12, byte]): string =
  ## Convert 12-byte array to command string, stripping null padding
  result = ""
  for c in b:
    if c == 0:
      break
    result.add(char(c))

# NetAddress serialization (port is big-endian, rest is little-endian)

proc writeNetAddress*(w: var BinaryWriter, a: NetAddress) =
  w.writeUint64LE(a.services)
  w.writeBytes(a.ip)
  # Port is big-endian
  w.data.add(byte((a.port shr 8) and 0xFF))
  w.data.add(byte(a.port and 0xFF))

proc readNetAddress*(r: var BinaryReader): NetAddress =
  result.services = r.readUint64LE()
  let ipBytes = r.readBytes(16)
  for i in 0 ..< 16:
    result.ip[i] = ipBytes[i]
  # Port is big-endian
  let portHi = r.readUint8()
  let portLo = r.readUint8()
  result.port = (uint16(portHi) shl 8) or uint16(portLo)

proc writeTimestampedAddr*(w: var BinaryWriter, ta: TimestampedAddr) =
  w.writeUint32LE(ta.timestamp)
  w.writeNetAddress(ta.address)

proc readTimestampedAddr*(r: var BinaryReader): TimestampedAddr =
  result.timestamp = r.readUint32LE()
  result.address = r.readNetAddress()

# VarString serialization

proc writeVarString*(w: var BinaryWriter, s: string) =
  w.writeCompactSize(uint64(s.len))
  for c in s:
    w.data.add(byte(c))

proc readVarString*(r: var BinaryReader): string =
  let length = r.readCompactSize()
  result = ""
  for i in 0 ..< int(length):
    result.add(char(r.readUint8()))

# InvVector serialization

proc writeInvVector*(w: var BinaryWriter, inv: InvVector) =
  w.writeUint32LE(uint32(ord(inv.invType)))
  w.writeHash(inv.hash)

proc readInvVector*(r: var BinaryReader): InvVector =
  let invTypeVal = r.readUint32LE()
  # Map to InvType enum
  case invTypeVal
  of 0: result.invType = invError
  of 1: result.invType = invTx
  of 2: result.invType = invBlock
  of 3: result.invType = invFilteredBlock
  of 4: result.invType = invCmpctBlock
  of 0x40000001'u32: result.invType = invWitnessTx
  of 0x40000002'u32: result.invType = invWitnessBlock
  else: result.invType = invError
  result.hash = r.readHash()

# VersionMsg serialization

proc writeVersionMsg*(w: var BinaryWriter, msg: VersionMsg) =
  w.writeUint32LE(msg.version)
  w.writeUint64LE(msg.services)
  w.writeInt64LE(msg.timestamp)
  w.writeNetAddress(msg.addrRecv)
  w.writeNetAddress(msg.addrFrom)
  w.writeUint64LE(msg.nonce)
  w.writeVarString(msg.userAgent)
  w.writeInt32LE(msg.startHeight)
  w.writeUint8(if msg.relay: 1 else: 0)

proc readVersionMsg*(r: var BinaryReader): VersionMsg =
  result.version = r.readUint32LE()
  result.services = r.readUint64LE()
  result.timestamp = r.readInt64LE()
  result.addrRecv = r.readNetAddress()
  result.addrFrom = r.readNetAddress()
  result.nonce = r.readUint64LE()
  result.userAgent = r.readVarString()
  result.startHeight = r.readInt32LE()
  # relay field is optional for older versions
  if r.remaining() >= 1:
    result.relay = r.readUint8() != 0
  else:
    result.relay = true  # Default for older versions

# GetHeaders/GetBlocks serialization

proc writeGetHeadersMsg*(w: var BinaryWriter, msg: GetHeadersMsg) =
  w.writeUint32LE(msg.version)
  w.writeCompactSize(uint64(msg.locatorHashes.len))
  for h in msg.locatorHashes:
    w.writeHash(h)
  w.writeHash(msg.hashStop)

proc readGetHeadersMsg*(r: var BinaryReader): GetHeadersMsg =
  result.version = r.readUint32LE()
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.locatorHashes.add(r.readHash())
  result.hashStop = r.readHash()

proc writeGetBlocksMsg*(w: var BinaryWriter, msg: GetBlocksMsg) =
  w.writeUint32LE(msg.version)
  w.writeCompactSize(uint64(msg.locatorHashes.len))
  for h in msg.locatorHashes:
    w.writeHash(h)
  w.writeHash(msg.hashStop)

proc readGetBlocksMsg*(r: var BinaryReader): GetBlocksMsg =
  result.version = r.readUint32LE()
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.locatorHashes.add(r.readHash())
  result.hashStop = r.readHash()

# RejectMsg serialization

proc writeRejectMsg*(w: var BinaryWriter, msg: RejectMsg) =
  w.writeVarString(msg.message)
  w.writeUint8(msg.code)
  w.writeVarString(msg.reason)

proc readRejectMsg*(r: var BinaryReader): RejectMsg =
  result.message = r.readVarString()
  result.code = r.readUint8()
  result.reason = r.readVarString()

# SendCmpctMsg serialization

proc writeSendCmpctMsg*(w: var BinaryWriter, msg: SendCmpctMsg) =
  w.writeUint8(if msg.announce: 1 else: 0)
  w.writeUint64LE(msg.version)

proc readSendCmpctMsg*(r: var BinaryReader): SendCmpctMsg =
  result.announce = r.readUint8() != 0
  result.version = r.readUint64LE()

# Headers message serialization (with dummy tx count after each header)

proc writeHeadersPayload*(w: var BinaryWriter, headers: seq[BlockHeader]) =
  w.writeCompactSize(uint64(headers.len))
  for header in headers:
    w.writeBlockHeader(header)
    w.writeCompactSize(0)  # Dummy tx count

proc readHeadersPayload*(r: var BinaryReader): seq[BlockHeader] =
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    result.add(r.readBlockHeader())
    discard r.readCompactSize()  # Dummy tx count

# Payload serialization for P2PMessage

proc serializePayload*(msg: P2PMessage): seq[byte] =
  ## Serialize just the payload (without header)
  var w = BinaryWriter()

  case msg.kind
  of mkVersion:
    w.writeVersionMsg(msg.version)
  of mkVerack, mkGetAddr, mkSendHeaders, mkWtxidRelay, mkSendAddrV2, mkSendPackages, mkMempool:
    discard  # Empty payload
  of mkPing:
    w.writeUint64LE(msg.pingNonce)
  of mkPong:
    w.writeUint64LE(msg.pongNonce)
  of mkAddr:
    w.writeCompactSize(uint64(msg.addresses.len))
    for taddr in msg.addresses:
      w.writeTimestampedAddr(taddr)
  of mkAddrV2:
    w.writeCompactSize(uint64(msg.addressesV2.len))
    for taddr in msg.addressesV2:
      w.writeTimestampedAddrV2(taddr)
  of mkInv:
    w.writeCompactSize(uint64(msg.invItems.len))
    for inv in msg.invItems:
      w.writeInvVector(inv)
  of mkGetData:
    w.writeCompactSize(uint64(msg.getData.len))
    for inv in msg.getData:
      w.writeInvVector(inv)
  of mkNotFound:
    w.writeCompactSize(uint64(msg.notFound.len))
    for inv in msg.notFound:
      w.writeInvVector(inv)
  of mkGetBlocks:
    w.writeGetBlocksMsg(msg.getBlocks)
  of mkGetHeaders:
    w.writeGetHeadersMsg(msg.getHeaders)
  of mkHeaders:
    w.writeHeadersPayload(msg.headers)
  of mkBlock:
    w.writeBlock(msg.blk)
  of mkTx:
    w.writeTransaction(msg.tx)
  of mkReject:
    w.writeRejectMsg(msg.reject)
  of mkSendCmpct:
    w.writeSendCmpctMsg(msg.sendCmpct)
  of mkFeeFilter:
    w.writeUint64LE(msg.feeRate)
  of mkCmpctBlock:
    w.writeCompactBlock(msg.cmpctBlock)
  of mkGetBlockTxn:
    w.writeBlockTxnRequest(msg.getBlockTxn)
  of mkBlockTxn:
    w.writeBlockTxnResponse(msg.blockTxn)
  # BIP330 Erlay messages
  of mkSendTxRcncl:
    w.writeUint32LE(msg.sendTxRcncl.version)
    w.writeUint64LE(msg.sendTxRcncl.salt)
  of mkReqRecon:
    w.writeUint16LE(msg.reqRecon.setSize)
    w.writeUint16LE(msg.reqRecon.q)
  of mkSketch:
    w.writeCompactSize(uint64(msg.sketch.sketchData.len))
    w.writeBytes(msg.sketch.sketchData)
  of mkReconcilDiff:
    w.writeUint8(if msg.reconcilDiff.success: 1 else: 0)
    w.writeCompactSize(uint64(msg.reconcilDiff.shortIds.len))
    for shortId in msg.reconcilDiff.shortIds:
      w.writeUint32LE(shortId)
  of mkReqSketchExt:
    discard  # Empty message

  result = w.data

proc messageKindToCommand*(kind: MessageKind): string =
  case kind
  of mkVersion: "version"
  of mkVerack: "verack"
  of mkPing: "ping"
  of mkPong: "pong"
  of mkAddr: "addr"
  of mkAddrV2: "addrv2"
  of mkInv: "inv"
  of mkGetData: "getdata"
  of mkNotFound: "notfound"
  of mkGetBlocks: "getblocks"
  of mkGetHeaders: "getheaders"
  of mkHeaders: "headers"
  of mkBlock: "block"
  of mkTx: "tx"
  of mkGetAddr: "getaddr"
  of mkReject: "reject"
  of mkSendHeaders: "sendheaders"
  of mkSendCmpct: "sendcmpct"
  of mkFeeFilter: "feefilter"
  of mkWtxidRelay: "wtxidrelay"
  of mkSendAddrV2: "sendaddrv2"
  of mkCmpctBlock: "cmpctblock"
  of mkGetBlockTxn: "getblocktxn"
  of mkBlockTxn: "blocktxn"
  of mkSendPackages: "sendpackages"
  of mkMempool: "mempool"
  # BIP330 Erlay
  of mkSendTxRcncl: "sendtxrcncl"
  of mkReqRecon: "reqrecon"
  of mkSketch: "sketch"
  of mkReconcilDiff: "reconcildiff"
  of mkReqSketchExt: "reqsketchext"

proc commandToMessageKind*(cmd: string): MessageKind =
  case cmd
  of "version": mkVersion
  of "verack": mkVerack
  of "ping": mkPing
  of "pong": mkPong
  of "addr": mkAddr
  of "addrv2": mkAddrV2
  of "inv": mkInv
  of "getdata": mkGetData
  of "notfound": mkNotFound
  of "getblocks": mkGetBlocks
  of "getheaders": mkGetHeaders
  of "headers": mkHeaders
  of "block": mkBlock
  of "tx": mkTx
  of "getaddr": mkGetAddr
  of "reject": mkReject
  of "sendheaders": mkSendHeaders
  of "sendcmpct": mkSendCmpct
  of "feefilter": mkFeeFilter
  of "wtxidrelay": mkWtxidRelay
  of "sendaddrv2": mkSendAddrV2
  of "cmpctblock": mkCmpctBlock
  of "getblocktxn": mkGetBlockTxn
  of "blocktxn": mkBlockTxn
  of "sendpackages": mkSendPackages
  of "mempool": mkMempool
  # BIP330 Erlay
  of "sendtxrcncl": mkSendTxRcncl
  of "reqrecon": mkReqRecon
  of "sketch": mkSketch
  of "reconcildiff": mkReconcilDiff
  of "reqsketchext": mkReqSketchExt
  else:
    raise newException(SerializationError, "unknown command: " & cmd)

# Message header serialization

proc serializeMessageHeader*(magic: array[4, byte], command: string,
                              payloadLen: uint32, checksum: array[4, byte]): seq[byte] =
  var w = BinaryWriter()
  w.writeBytes(magic)
  let cmdBytes = commandToBytes(command)
  w.writeBytes(cmdBytes)
  w.writeUint32LE(payloadLen)
  w.writeBytes(checksum)
  result = w.data

proc deserializeMessageHeader*(r: var BinaryReader): MessageHeader =
  let magicBytes = r.readBytes(4)
  for i in 0 ..< 4:
    result.magic[i] = magicBytes[i]
  let cmdBytes = r.readBytes(12)
  for i in 0 ..< 12:
    result.command[i] = cmdBytes[i]
  result.length = r.readUint32LE()
  let checksumBytes = r.readBytes(4)
  for i in 0 ..< 4:
    result.checksum[i] = checksumBytes[i]

proc computeChecksum*(payload: seq[byte]): array[4, byte] =
  ## Compute checksum as first 4 bytes of double SHA256
  let hash = doubleSha256(payload)
  for i in 0 ..< 4:
    result[i] = hash[i]

proc verifyChecksum*(header: MessageHeader, payload: seq[byte]): bool =
  let expected = computeChecksum(payload)
  for i in 0 ..< 4:
    if header.checksum[i] != expected[i]:
      return false
  true

# Full message serialization

proc serializeMessage*(magic: array[4, byte], msg: P2PMessage): seq[byte] =
  ## Serialize a P2PMessage with header envelope
  let payload = serializePayload(msg)
  let command = messageKindToCommand(msg.kind)
  let checksum = computeChecksum(payload)

  var w = BinaryWriter()
  w.writeBytes(magic)
  let cmdBytes = commandToBytes(command)
  w.writeBytes(cmdBytes)
  w.writeUint32LE(uint32(payload.len))
  w.writeBytes(checksum)
  w.writeBytes(payload)

  result = w.data

proc deserializePayload*(cmd: string, payload: seq[byte]): P2PMessage =
  ## Deserialize a payload given the command name
  var r = BinaryReader(data: payload, pos: 0)

  case cmd
  of "version":
    result = P2PMessage(kind: mkVersion, version: r.readVersionMsg())
  of "verack":
    result = P2PMessage(kind: mkVerack)
  of "ping":
    result = P2PMessage(kind: mkPing, pingNonce: r.readUint64LE())
  of "pong":
    result = P2PMessage(kind: mkPong, pongNonce: r.readUint64LE())
  of "addr":
    var addresses: seq[TimestampedAddr]
    let count = r.readCompactSize()
    for i in 0 ..< int(count):
      addresses.add(r.readTimestampedAddr())
    result = P2PMessage(kind: mkAddr, addresses: addresses)
  of "addrv2":
    var addressesV2: seq[TimestampedAddrV2]
    let count = r.readCompactSize()
    for i in 0 ..< int(count):
      let addrOpt = r.readTimestampedAddrV2()
      if addrOpt.isSome:
        addressesV2.add(addrOpt.get())
      # Unknown network types are silently skipped
    result = P2PMessage(kind: mkAddrV2, addressesV2: addressesV2)
  of "inv":
    var invItems: seq[InvVector]
    let count = r.readCompactSize()
    for i in 0 ..< int(count):
      invItems.add(r.readInvVector())
    result = P2PMessage(kind: mkInv, invItems: invItems)
  of "getdata":
    var getData: seq[InvVector]
    let count = r.readCompactSize()
    for i in 0 ..< int(count):
      getData.add(r.readInvVector())
    result = P2PMessage(kind: mkGetData, getData: getData)
  of "notfound":
    var notFound: seq[InvVector]
    let count = r.readCompactSize()
    for i in 0 ..< int(count):
      notFound.add(r.readInvVector())
    result = P2PMessage(kind: mkNotFound, notFound: notFound)
  of "getblocks":
    result = P2PMessage(kind: mkGetBlocks, getBlocks: r.readGetBlocksMsg())
  of "getheaders":
    result = P2PMessage(kind: mkGetHeaders, getHeaders: r.readGetHeadersMsg())
  of "headers":
    result = P2PMessage(kind: mkHeaders, headers: r.readHeadersPayload())
  of "block":
    result = P2PMessage(kind: mkBlock, blk: r.readBlock())
  of "tx":
    result = P2PMessage(kind: mkTx, tx: r.readTransaction())
  of "getaddr":
    result = P2PMessage(kind: mkGetAddr)
  of "reject":
    result = P2PMessage(kind: mkReject, reject: r.readRejectMsg())
  of "sendheaders":
    result = P2PMessage(kind: mkSendHeaders)
  of "sendcmpct":
    result = P2PMessage(kind: mkSendCmpct, sendCmpct: r.readSendCmpctMsg())
  of "feefilter":
    result = P2PMessage(kind: mkFeeFilter, feeRate: r.readUint64LE())
  of "wtxidrelay":
    result = P2PMessage(kind: mkWtxidRelay)
  of "sendaddrv2":
    result = P2PMessage(kind: mkSendAddrV2)
  of "cmpctblock":
    result = P2PMessage(kind: mkCmpctBlock, cmpctBlock: r.readCompactBlock())
  of "getblocktxn":
    result = P2PMessage(kind: mkGetBlockTxn, getBlockTxn: r.readBlockTxnRequest())
  of "blocktxn":
    result = P2PMessage(kind: mkBlockTxn, blockTxn: r.readBlockTxnResponse())
  of "sendpackages":
    result = P2PMessage(kind: mkSendPackages)
  of "mempool":
    # BIP35: empty body, peer is requesting our mempool inv
    result = P2PMessage(kind: mkMempool)
  # BIP330 Erlay
  of "sendtxrcncl":
    result = P2PMessage(kind: mkSendTxRcncl, sendTxRcncl: SendTxRcnclMsg(
      version: r.readUint32LE(),
      salt: r.readUint64LE()
    ))
  of "reqrecon":
    result = P2PMessage(kind: mkReqRecon, reqRecon: ReqReconMsg(
      setSize: r.readUint16LE(),
      q: r.readUint16LE()
    ))
  of "sketch":
    let dataLen = r.readCompactSize()
    var sketchData = newSeq[byte](dataLen)
    if dataLen > 0:
      let bytes = r.readBytes(int(dataLen))
      for i in 0 ..< int(dataLen):
        sketchData[i] = bytes[i]
    result = P2PMessage(kind: mkSketch, sketch: SketchMsg(sketchData: sketchData))
  of "reconcildiff":
    let success = r.readUint8() != 0
    let count = r.readCompactSize()
    var shortIds: seq[uint32]
    for i in 0 ..< int(count):
      shortIds.add(r.readUint32LE())
    result = P2PMessage(kind: mkReconcilDiff, reconcilDiff: ReconcilDiffMsg(
      success: success,
      shortIds: shortIds
    ))
  of "reqsketchext":
    result = P2PMessage(kind: mkReqSketchExt)
  else:
    raise newException(SerializationError, "unknown command: " & cmd)

# Convenience constructors

proc newVersionMsg*(version: uint32 = ProtocolVersion,
                    services: uint64 = NodeNetwork or NodeWitness,
                    timestamp: int64 = 0,
                    addrRecv: NetAddress = NetAddress(),
                    addrFrom: NetAddress = NetAddress(),
                    nonce: uint64 = 0,
                    userAgent: string = UserAgent,
                    startHeight: int32 = 0,
                    relay: bool = true): P2PMessage =
  P2PMessage(kind: mkVersion, version: VersionMsg(
    version: version,
    services: services,
    timestamp: timestamp,
    addrRecv: addrRecv,
    addrFrom: addrFrom,
    nonce: nonce,
    userAgent: userAgent,
    startHeight: startHeight,
    relay: relay
  ))

proc newVerack*(): P2PMessage =
  P2PMessage(kind: mkVerack)

proc newPing*(nonce: uint64): P2PMessage =
  P2PMessage(kind: mkPing, pingNonce: nonce)

proc newPong*(nonce: uint64): P2PMessage =
  P2PMessage(kind: mkPong, pongNonce: nonce)

proc newGetHeaders*(version: uint32, locatorHashes: seq[array[32, byte]],
                    hashStop: array[32, byte]): P2PMessage =
  P2PMessage(kind: mkGetHeaders, getHeaders: GetHeadersMsg(
    version: version,
    locatorHashes: locatorHashes,
    hashStop: hashStop
  ))

proc newGetBlocks*(version: uint32, locatorHashes: seq[array[32, byte]],
                   hashStop: array[32, byte]): P2PMessage =
  P2PMessage(kind: mkGetBlocks, getBlocks: GetBlocksMsg(
    version: version,
    locatorHashes: locatorHashes,
    hashStop: hashStop
  ))

proc newInv*(items: seq[InvVector]): P2PMessage =
  P2PMessage(kind: mkInv, invItems: items)

proc newGetData*(items: seq[InvVector]): P2PMessage =
  P2PMessage(kind: mkGetData, getData: items)

proc newHeaders*(headers: seq[BlockHeader]): P2PMessage =
  P2PMessage(kind: mkHeaders, headers: headers)

proc newGetAddr*(): P2PMessage =
  P2PMessage(kind: mkGetAddr)

proc newSendHeaders*(): P2PMessage =
  P2PMessage(kind: mkSendHeaders)

proc newFeeFilter*(feeRate: uint64): P2PMessage =
  P2PMessage(kind: mkFeeFilter, feeRate: feeRate)

proc newWtxidRelay*(): P2PMessage =
  P2PMessage(kind: mkWtxidRelay)

proc newMempoolReq*(): P2PMessage =
  ## BIP35 mempool request (empty body). The handler is on the *server*
  ## side: when we receive this we send back inv messages enumerating
  ## our mempool. We never originate this currently, but expose the
  ## constructor for tests and future symmetry.
  P2PMessage(kind: mkMempool)

proc newSendAddrV2*(): P2PMessage =
  P2PMessage(kind: mkSendAddrV2)

proc newAddr*(addresses: seq[TimestampedAddr]): P2PMessage =
  P2PMessage(kind: mkAddr, addresses: addresses)

proc newAddrV2*(addresses: seq[TimestampedAddrV2]): P2PMessage =
  P2PMessage(kind: mkAddrV2, addressesV2: addresses)

proc newBlockMsg*(blk: Block): P2PMessage =
  P2PMessage(kind: mkBlock, blk: blk)

proc newTxMsg*(tx: Transaction): P2PMessage =
  P2PMessage(kind: mkTx, tx: tx)

proc newCmpctBlockMsg*(cb: CompactBlock): P2PMessage =
  P2PMessage(kind: mkCmpctBlock, cmpctBlock: cb)

proc newGetBlockTxnMsg*(blockHash: BlockHash, indexes: seq[uint16]): P2PMessage =
  P2PMessage(kind: mkGetBlockTxn, getBlockTxn: BlockTxnRequest(
    blockHash: blockHash,
    indexes: indexes
  ))

proc newBlockTxnMsg*(blockHash: BlockHash, txns: seq[Transaction]): P2PMessage =
  P2PMessage(kind: mkBlockTxn, blockTxn: BlockTxnResponse(
    blockHash: blockHash,
    transactions: txns
  ))

proc newSendPackages*(): P2PMessage =
  ## Signal support for package relay (BIP 331)
  P2PMessage(kind: mkSendPackages)

# BIP330 Erlay message constructors

proc newSendTxRcncl*(version: uint32, salt: uint64): P2PMessage =
  ## Signal transaction reconciliation support (BIP 330)
  P2PMessage(kind: mkSendTxRcncl, sendTxRcncl: SendTxRcnclMsg(
    version: version,
    salt: salt
  ))

proc newReqRecon*(setSize: uint16, q: uint16): P2PMessage =
  ## Request reconciliation sketch from peer
  P2PMessage(kind: mkReqRecon, reqRecon: ReqReconMsg(
    setSize: setSize,
    q: q
  ))

proc newSketch*(sketchData: seq[byte]): P2PMessage =
  ## Send reconciliation sketch
  P2PMessage(kind: mkSketch, sketch: SketchMsg(sketchData: sketchData))

proc newReconcilDiff*(success: bool, shortIds: seq[uint32]): P2PMessage =
  ## Send reconciliation difference (missing short IDs)
  P2PMessage(kind: mkReconcilDiff, reconcilDiff: ReconcilDiffMsg(
    success: success,
    shortIds: shortIds
  ))

proc newReqSketchExt*(): P2PMessage =
  ## Request extended sketch (larger capacity)
  P2PMessage(kind: mkReqSketchExt)
