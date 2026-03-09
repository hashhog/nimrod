## P2P peer connection handling
## Uses chronos for async networking

import std/[strformat, times]
import chronos
import chronicles
import ../primitives/[types, serialize]
import ../consensus/params
import ./messages

export chronicles

type
  PeerState* = enum
    Disconnected
    Connecting
    Connected
    Handshaking
    Ready

  Peer* = ref object
    address*: string
    port*: uint16
    transport*: StreamTransport
    state*: PeerState
    version*: uint32
    services*: uint64
    userAgent*: string
    startHeight*: int32
    lastSeen*: Time
    params*: ConsensusParams
    recvBuffer*: seq[byte]

  PeerError* = object of CatchableError

proc newPeer*(address: string, port: uint16, params: ConsensusParams): Peer =
  Peer(
    address: address,
    port: port,
    state: Disconnected,
    params: params,
    recvBuffer: @[]
  )

proc `$`*(peer: Peer): string =
  fmt"{peer.address}:{peer.port}"

proc connect*(peer: Peer): Future[bool] {.async.} =
  ## Connect to the peer
  if peer.state != Disconnected:
    return false

  peer.state = Connecting

  try:
    let ta = initTAddress(peer.address, Port(peer.port))
    peer.transport = await connect(ta)
    peer.state = Connected
    peer.lastSeen = getTime()
    info "connected to peer", peer = $peer
    return true
  except CatchableError as e:
    error "failed to connect", peer = $peer, error = e.msg
    peer.state = Disconnected
    return false

proc disconnect*(peer: Peer) {.async.} =
  ## Disconnect from the peer
  if peer.transport != nil and not peer.transport.closed:
    try:
      await peer.transport.closeWait()
    except CatchableError:
      discard
  peer.state = Disconnected
  info "disconnected from peer", peer = $peer

proc sendP2PMessage*(peer: Peer, msg: P2PMessage) {.async.} =
  ## Send a P2P message to the peer
  if peer.state == Disconnected or peer.transport == nil:
    raise newException(PeerError, "not connected")

  let data = serializeMessage(peer.params.magic, msg)
  let written = await peer.transport.write(data)
  if written != data.len:
    raise newException(PeerError, "failed to send complete message")

  trace "sent message", peer = $peer, kind = msg.kind, size = data.len - 24

proc sendVersion*(peer: Peer, ourHeight: int32) {.async.} =
  ## Send version message
  let msg = newVersionMsg(
    version = ProtocolVersion,
    services = NodeNetwork or NodeWitness,
    timestamp = getTime().toUnix(),
    addrRecv = NetAddress(services: NodeNetwork, port: peer.port),
    addrFrom = NetAddress(services: NodeNetwork, port: peer.params.p2pPort),
    nonce = 0,  # Should be random
    userAgent = UserAgent,
    startHeight = ourHeight,
    relay = true
  )

  await peer.sendP2PMessage(msg)
  peer.state = Handshaking

proc sendVerack*(peer: Peer) {.async.} =
  await peer.sendP2PMessage(newVerack())

proc sendPing*(peer: Peer, nonce: uint64) {.async.} =
  await peer.sendP2PMessage(newPing(nonce))

proc sendPong*(peer: Peer, nonce: uint64) {.async.} =
  await peer.sendP2PMessage(newPong(nonce))

proc sendGetHeaders*(peer: Peer, locators: seq[BlockHash], hashStop: BlockHash) {.async.} =
  var locatorHashes: seq[array[32, byte]]
  for loc in locators:
    locatorHashes.add(array[32, byte](loc))

  let msg = newGetHeaders(
    ProtocolVersion,
    locatorHashes,
    array[32, byte](hashStop)
  )
  await peer.sendP2PMessage(msg)

proc sendGetData*(peer: Peer, inventory: seq[InvVector]) {.async.} =
  let msg = newGetData(inventory)
  await peer.sendP2PMessage(msg)

proc readMessage*(peer: Peer): Future[P2PMessage] {.async.} =
  ## Read a complete message from the peer
  if peer.transport == nil or peer.transport.closed:
    raise newException(PeerError, "not connected")

  # Read header (24 bytes)
  while peer.recvBuffer.len < 24:
    var buf: array[4096, byte]
    let bytesRead = await peer.transport.readOnce(addr buf[0], buf.len)
    if bytesRead == 0:
      raise newException(PeerError, "connection closed")
    peer.recvBuffer.add(buf[0 ..< bytesRead])

  var r = BinaryReader(data: peer.recvBuffer[0 ..< 24], pos: 0)
  let header = r.deserializeMessageHeader()

  # Verify magic
  if header.magic != peer.params.magic:
    raise newException(PeerError, "invalid magic")

  # Check length
  if header.length > MaxMessagePayload:
    raise newException(PeerError, "message too large")

  # Read payload
  let totalSize = 24 + int(header.length)
  while peer.recvBuffer.len < totalSize:
    var buf: array[4096, byte]
    let bytesRead = await peer.transport.readOnce(addr buf[0], buf.len)
    if bytesRead == 0:
      raise newException(PeerError, "connection closed")
    peer.recvBuffer.add(buf[0 ..< bytesRead])

  let payload = peer.recvBuffer[24 ..< totalSize]

  # Verify checksum
  if not verifyChecksum(header, payload):
    raise newException(PeerError, "invalid checksum")

  # Remove processed message from buffer
  peer.recvBuffer = peer.recvBuffer[totalSize .. ^1]
  peer.lastSeen = getTime()

  let command = bytesToCommand(header.command)
  trace "received message", peer = $peer, command = command, size = payload.len

  return deserializePayload(command, @payload)

proc handleMessage*(peer: Peer, msg: P2PMessage): Future[void] {.async.} =
  ## Process an incoming message
  case msg.kind
  of mkVersion:
    peer.version = msg.version.version
    peer.services = msg.version.services
    peer.userAgent = msg.version.userAgent
    peer.startHeight = msg.version.startHeight
    info "received version", peer = $peer, version = msg.version.version,
         height = msg.version.startHeight
    await peer.sendVerack()

  of mkVerack:
    peer.state = Ready
    info "handshake complete", peer = $peer

  of mkPing:
    await peer.sendPong(msg.pingNonce)

  of mkPong:
    discard  # Could track latency

  of mkAddr:
    trace "received addr", peer = $peer, count = msg.addresses.len

  of mkInv:
    trace "received inv", peer = $peer, count = msg.invItems.len

  of mkHeaders:
    trace "received headers", peer = $peer, count = msg.headers.len

  of mkBlock:
    trace "received block", peer = $peer

  of mkTx:
    trace "received tx", peer = $peer

  of mkGetAddr:
    discard  # TODO: respond with addr

  of mkGetHeaders:
    discard  # TODO: respond with headers

  of mkGetBlocks:
    discard  # TODO: respond with inv

  of mkGetData:
    discard  # TODO: respond with block/tx

  of mkNotFound:
    trace "received notfound", peer = $peer, count = msg.notFound.len

  of mkReject:
    warn "received reject", peer = $peer, message = msg.reject.message,
         reason = msg.reject.reason

  of mkSendHeaders:
    trace "peer prefers headers", peer = $peer

  of mkSendCmpct:
    trace "peer supports compact blocks", peer = $peer,
          version = msg.sendCmpct.version

  of mkFeeFilter:
    trace "peer feefilter", peer = $peer, feeRate = msg.feeRate

  of mkWtxidRelay:
    trace "peer supports wtxidrelay", peer = $peer

  of mkSendAddrV2:
    trace "peer supports addrv2", peer = $peer
