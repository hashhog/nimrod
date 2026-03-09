## P2P peer connection handling
## Uses chronos for async networking

import std/[streams, strformat, options, times]
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
    version*: int32
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

proc sendMessage*(peer: Peer, command: string, payload: seq[byte]) {.async.} =
  ## Send a message to the peer
  if peer.state == Disconnected or peer.transport == nil:
    raise newException(PeerError, "not connected")

  let msg = serializeMessage(peer.params.magic, command, payload)
  let written = await peer.transport.write(msg)
  if written != msg.len:
    raise newException(PeerError, "failed to send complete message")

  trace "sent message", peer = $peer, command = command, size = payload.len

proc sendVersion*(peer: Peer, ourHeight: int32) {.async.} =
  ## Send version message
  let msg = VersionMessage(
    version: PROTOCOL_VERSION,
    services: 1,  # NODE_NETWORK
    timestamp: getTime().toUnix(),
    addrRecv: NetAddr(services: 1, port: peer.port),
    addrFrom: NetAddr(services: 1, port: peer.params.p2pPort),
    nonce: 0,  # Should be random
    userAgent: USER_AGENT,
    startHeight: ourHeight,
    relay: true
  )

  let s = newStringStream()
  s.writeVersionMessage(msg)
  s.setPosition(0)
  let payload = cast[seq[byte]](s.readAll())

  await peer.sendMessage("version", payload)
  peer.state = Handshaking

proc sendVerack*(peer: Peer) {.async.} =
  await peer.sendMessage("verack", @[])

proc sendPing*(peer: Peer, nonce: uint64) {.async.} =
  let s = newStringStream()
  s.writeUint64LE(nonce)
  s.setPosition(0)
  await peer.sendMessage("ping", cast[seq[byte]](s.readAll()))

proc sendPong*(peer: Peer, nonce: uint64) {.async.} =
  let s = newStringStream()
  s.writeUint64LE(nonce)
  s.setPosition(0)
  await peer.sendMessage("pong", cast[seq[byte]](s.readAll()))

proc sendGetHeaders*(peer: Peer, locators: seq[BlockHash], hashStop: BlockHash) {.async.} =
  let s = newStringStream()
  s.writeUint32LE(PROTOCOL_VERSION.uint32)
  s.writeCompactSize(CompactSize(locators.len))
  for loc in locators:
    s.writeArray32(array[32, byte](loc))
  s.writeArray32(array[32, byte](hashStop))
  s.setPosition(0)
  await peer.sendMessage("getheaders", cast[seq[byte]](s.readAll()))

proc sendGetData*(peer: Peer, inventory: seq[InvVector]) {.async.} =
  let s = newStringStream()
  s.writeCompactSize(CompactSize(inventory.len))
  for inv in inventory:
    s.writeInvVector(inv)
  s.setPosition(0)
  await peer.sendMessage("getdata", cast[seq[byte]](s.readAll()))

proc readMessage*(peer: Peer): Future[tuple[command: string, payload: seq[byte]]] {.async.} =
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

  let header = parseMessageHeader(peer.recvBuffer[0 ..< 24])

  # Verify magic
  if header.magic != peer.params.magic:
    raise newException(PeerError, "invalid magic")

  # Check length
  if header.length > 32 * 1024 * 1024:  # 32 MB max
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

  return (command, @payload)

proc bytesToCommand(cmd: array[12, byte]): string =
  result = ""
  for b in cmd:
    if b == 0:
      break
    result.add(char(b))

proc handleMessage*(peer: Peer, command: string, payload: seq[byte]): Future[void] {.async.} =
  ## Process an incoming message
  let s = newStringStream(cast[string](payload))

  case command
  of "version":
    let msg = s.readVersionMessage()
    peer.version = msg.version
    peer.services = msg.services
    peer.userAgent = msg.userAgent
    peer.startHeight = msg.startHeight
    info "received version", peer = $peer, version = msg.version, height = msg.startHeight
    await peer.sendVerack()

  of "verack":
    peer.state = Ready
    info "handshake complete", peer = $peer

  of "ping":
    let nonce = s.readUint64LE()
    await peer.sendPong(nonce)

  of "pong":
    discard  # Could track latency

  else:
    trace "unhandled message", peer = $peer, command = command
