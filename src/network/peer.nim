## P2P peer connection handling
## TCP connection with message framing, version handshake, and ping/pong
## Uses chronos for async networking

import std/[strformat, random]
import std/times as stdtimes
import chronos
import chronos/timer as ctimer
import chronicles
import ../primitives/[types, serialize]
import ../consensus/params
import ./messages

export chronicles

const
  HandshakeTimeoutSec* = 10  # 10 seconds
  PingTimeoutSec* = 30       # 30 seconds
  ReadTimeoutSec* = 120      # 2 minutes

type
  PeerState* = enum
    psDisconnected
    psConnecting
    psConnected
    psHandshaking
    psReady

  PeerDirection* = enum
    pdInbound
    pdOutbound

  PeerCallback* = proc(peer: Peer, msg: P2PMessage): Future[void] {.async.}

  Peer* = ref object
    address*: string
    port*: uint16
    transport*: StreamTransport
    state*: PeerState
    direction*: PeerDirection
    # Peer info from version message
    version*: uint32
    services*: uint64
    userAgent*: string
    startHeight*: int32
    # Timing
    lastSeen*: stdtimes.Time
    lastPing*: stdtimes.Time
    pingNonce*: uint64
    latencyMs*: int
    # Network params
    params*: ConsensusParams
    networkMagic*: array[4, byte]
    # Feature negotiation
    feeFilterRate*: uint64
    sendHeaders*: bool
    wtxidRelay*: bool
    handshakeComplete*: bool
    # Misbehavior scoring (Bitcoin Core: 100 = ban threshold)
    misbehaviorScore*: uint32
    shouldDisconnect*: bool
    # Internal state
    recvBuffer*: seq[byte]
    closing*: bool

  PeerError* = object of CatchableError

proc newPeer*(address: string, port: uint16, params: ConsensusParams,
              direction: PeerDirection = pdOutbound): Peer =
  Peer(
    address: address,
    port: port,
    state: psDisconnected,
    direction: direction,
    params: params,
    networkMagic: params.magic,
    recvBuffer: @[],
    closing: false,
    misbehaviorScore: 0,
    shouldDisconnect: false
  )

proc `$`*(peer: Peer): string =
  fmt"{peer.address}:{peer.port}"

proc isConnected*(peer: Peer): bool =
  peer.state in {psConnected, psHandshaking, psReady} and
    peer.transport != nil and not peer.transport.closed

proc connect*(peer: Peer): Future[bool] {.async.} =
  ## Connect to the peer (outbound connection)
  if peer.state != psDisconnected:
    return false

  peer.state = psConnecting

  try:
    let ta = initTAddress(peer.address, Port(peer.port))
    peer.transport = await connect(ta)
    peer.state = psConnected
    peer.lastSeen = stdtimes.getTime()
    info "connected to peer", peer = $peer
    return true
  except CatchableError as e:
    error "failed to connect", peer = $peer, error = e.msg
    peer.state = psDisconnected
    return false

proc disconnect*(peer: Peer, reason: string = "") {.async.} =
  ## Disconnect from the peer gracefully
  if peer.closing:
    return

  peer.closing = true

  if peer.transport != nil and not peer.transport.closed:
    try:
      # Use cancelAndWait to properly handle pending reads (chronos pitfall)
      await peer.transport.closeWait()
    except CatchableError:
      discard

  peer.state = psDisconnected
  peer.closing = false

  if reason.len > 0:
    info "disconnected from peer", peer = $peer, reason = reason
  else:
    info "disconnected from peer", peer = $peer

proc sendMessage*(peer: Peer, msg: P2PMessage) {.async.} =
  ## Send a P2P message to the peer
  if not peer.isConnected():
    raise newException(PeerError, "not connected")

  let data = serializeMessage(peer.networkMagic, msg)
  let written = await peer.transport.write(data)
  if written != data.len:
    raise newException(PeerError, "failed to send complete message")

  trace "sent message", peer = $peer, kind = msg.kind, size = data.len - 24

proc readMessage*(peer: Peer): Future[P2PMessage] {.async.} =
  ## Read a complete message from the peer
  ## Reads 24-byte header, validates magic, reads payload, verifies checksum
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
  if header.magic != peer.networkMagic:
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
  peer.lastSeen = stdtimes.getTime()

  let command = bytesToCommand(header.command)
  trace "received message", peer = $peer, command = command, size = payload.len

  return deserializePayload(command, @payload)

proc sendVersion*(peer: Peer, ourHeight: int32) {.async.} =
  ## Send version message
  randomize()
  let nonce = uint64(rand(high(int)))

  let msg = newVersionMsg(
    version = ProtocolVersion,
    services = NodeNetwork or NodeWitness,
    timestamp = stdtimes.getTime().toUnix(),
    addrRecv = NetAddress(services: NodeNetwork, port: peer.port),
    addrFrom = NetAddress(services: NodeNetwork or NodeWitness, port: peer.params.p2pPort),
    nonce = nonce,
    userAgent = UserAgent,
    startHeight = ourHeight,
    relay = true
  )

  await peer.sendMessage(msg)
  peer.state = psHandshaking

proc sendVerack*(peer: Peer) {.async.} =
  await peer.sendMessage(newVerack())

proc sendPing*(peer: Peer) {.async.} =
  ## Send a ping and record the nonce/time for latency measurement
  randomize()
  peer.pingNonce = uint64(rand(high(int)))
  peer.lastPing = stdtimes.getTime()
  await peer.sendMessage(newPing(peer.pingNonce))

proc sendPong*(peer: Peer, nonce: uint64) {.async.} =
  await peer.sendMessage(newPong(nonce))

proc sendGetHeaders*(peer: Peer, locators: seq[BlockHash], hashStop: BlockHash) {.async.} =
  var locatorHashes: seq[array[32, byte]]
  for loc in locators:
    locatorHashes.add(array[32, byte](loc))

  let msg = newGetHeaders(
    ProtocolVersion,
    locatorHashes,
    array[32, byte](hashStop)
  )
  await peer.sendMessage(msg)

proc sendGetData*(peer: Peer, inventory: seq[InvVector]) {.async.} =
  let msg = newGetData(inventory)
  await peer.sendMessage(msg)

proc sendWtxidRelay*(peer: Peer) {.async.} =
  await peer.sendMessage(newWtxidRelay())

proc sendSendHeaders*(peer: Peer) {.async.} =
  await peer.sendMessage(newSendHeaders())

proc sendSendCmpct*(peer: Peer, announce: bool = false, version: uint64 = 2) {.async.} =
  let msg = P2PMessage(kind: mkSendCmpct, sendCmpct: SendCmpctMsg(
    announce: announce,
    version: version
  ))
  await peer.sendMessage(msg)

proc sendFeeFilter*(peer: Peer, feeRate: uint64) {.async.} =
  await peer.sendMessage(newFeeFilter(feeRate))

proc performHandshake*(peer: Peer, ourHeight: int32) {.async.} =
  ## Perform version handshake with peer
  ## Outbound: send version -> recv version -> send verack -> recv verack
  ## Then send wtxidrelay, sendheaders, sendcmpct
  if peer.direction == pdOutbound:
    # Send our version first
    await peer.sendVersion(ourHeight)

    # Wait for their version
    let recvVersionFut = peer.readMessage()
    if not await recvVersionFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
      raise newException(PeerError, "handshake timeout waiting for version")

    let versionMsg = recvVersionFut.value()
    if versionMsg.kind != mkVersion:
      raise newException(PeerError, "expected version message")

    peer.version = versionMsg.version.version
    peer.services = versionMsg.version.services
    peer.userAgent = versionMsg.version.userAgent
    peer.startHeight = versionMsg.version.startHeight

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # Send verack
    await peer.sendVerack()

    # Wait for their verack
    let recvVerackFut = peer.readMessage()
    if not await recvVerackFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
      raise newException(PeerError, "handshake timeout waiting for verack")

    let verackMsg = recvVerackFut.value()
    if verackMsg.kind != mkVerack:
      raise newException(PeerError, "expected verack message")

  else:
    # Inbound: wait for version first
    let recvVersionFut = peer.readMessage()
    if not await recvVersionFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
      raise newException(PeerError, "handshake timeout waiting for version")

    let versionMsg = recvVersionFut.value()
    if versionMsg.kind != mkVersion:
      raise newException(PeerError, "expected version message")

    peer.version = versionMsg.version.version
    peer.services = versionMsg.version.services
    peer.userAgent = versionMsg.version.userAgent
    peer.startHeight = versionMsg.version.startHeight

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # Send our version
    await peer.sendVersion(ourHeight)

    # Send verack
    await peer.sendVerack()

    # Wait for their verack
    let recvVerackFut = peer.readMessage()
    if not await recvVerackFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
      raise newException(PeerError, "handshake timeout waiting for verack")

    let verackMsg = recvVerackFut.value()
    if verackMsg.kind != mkVerack:
      raise newException(PeerError, "expected verack message")

  # Send feature negotiation messages
  # These should be sent after verack but before other messages
  if peer.version >= 70016:
    await peer.sendWtxidRelay()
  await peer.sendSendHeaders()
  await peer.sendSendCmpct()

  peer.state = psReady
  peer.handshakeComplete = true
  info "handshake complete", peer = $peer

proc handlePing(peer: Peer, nonce: uint64) {.async.} =
  ## Respond to ping with pong
  await peer.sendPong(nonce)

proc handlePong(peer: Peer, nonce: uint64) =
  ## Handle pong response, calculate latency
  if nonce == peer.pingNonce:
    let now = stdtimes.getTime()
    let elapsed = now - peer.lastPing
    peer.latencyMs = int(elapsed.inMilliseconds())
    trace "pong received", peer = $peer, latencyMs = peer.latencyMs
  else:
    trace "pong nonce mismatch", peer = $peer

proc handleMessage*(peer: Peer, msg: P2PMessage): Future[void] {.async.} =
  ## Process an incoming message (internal handling)
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
    peer.state = psReady
    info "handshake complete", peer = $peer

  of mkPing:
    await peer.handlePing(msg.pingNonce)

  of mkPong:
    peer.handlePong(msg.pongNonce)

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
    peer.sendHeaders = true
    trace "peer prefers headers", peer = $peer

  of mkSendCmpct:
    trace "peer supports compact blocks", peer = $peer,
          version = msg.sendCmpct.version

  of mkFeeFilter:
    peer.feeFilterRate = msg.feeRate
    trace "peer feefilter", peer = $peer, feeRate = msg.feeRate

  of mkWtxidRelay:
    peer.wtxidRelay = true
    trace "peer supports wtxidrelay", peer = $peer

  of mkSendAddrV2:
    trace "peer supports addrv2", peer = $peer

proc messageLoop*(peer: Peer, callback: PeerCallback) {.async.} =
  ## Main message loop - auto-handles ping/pong, dispatches others to callback
  ## Runs until peer disconnects or error occurs
  while peer.isConnected() and not peer.closing:
    try:
      let msg = await peer.readMessage()

      # Auto-handle ping/pong
      case msg.kind
      of mkPing:
        await peer.handlePing(msg.pingNonce)
      of mkPong:
        peer.handlePong(msg.pongNonce)
      else:
        # Dispatch to callback for all other messages
        if callback != nil:
          await callback(peer, msg)
        else:
          await peer.handleMessage(msg)

    except PeerError as e:
      if not peer.closing:
        error "peer error in message loop", peer = $peer, error = e.msg
      break
    except CatchableError as e:
      if not peer.closing:
        error "error in message loop", peer = $peer, error = e.msg
      break

  if not peer.closing:
    await peer.disconnect("message loop ended")

# IPv4 to IPv6 mapped address helpers

proc ipv4ToMapped*(ip: array[4, byte]): array[16, byte] =
  ## Convert IPv4 address to IPv6-mapped format (::ffff:a.b.c.d)
  # First 10 bytes are zero
  # Bytes 10-11 are 0xFF
  result[10] = 0xFF
  result[11] = 0xFF
  # Last 4 bytes are the IPv4 address
  result[12] = ip[0]
  result[13] = ip[1]
  result[14] = ip[2]
  result[15] = ip[3]

proc isIPv4Mapped*(ip: array[16, byte]): bool =
  ## Check if IPv6 address is an IPv4-mapped address
  for i in 0 ..< 10:
    if ip[i] != 0:
      return false
  ip[10] == 0xFF and ip[11] == 0xFF

proc extractIPv4*(ip: array[16, byte]): array[4, byte] =
  ## Extract IPv4 address from IPv6-mapped format
  result[0] = ip[12]
  result[1] = ip[13]
  result[2] = ip[14]
  result[3] = ip[15]

# Misbehavior scoring constants (Bitcoin Core compatible)
# See net_processing.cpp Misbehaving() - threshold is 100 points
const
  MisbehaviorThreshold* = 100'u32
  # Score values (from Bitcoin Core)
  ScoreInvalidBlockHeader* = 100'u32    # Instant ban
  ScoreInvalidBlock* = 100'u32          # Instant ban
  ScoreInvalidTransaction* = 10'u32
  ScoreUnsolicitedMessage* = 20'u32
  ScoreProtocolViolation* = 10'u32
  ScoreInvalidHeaders* = 100'u32        # Instant ban (invalid PoW/structure)
  ScoreInvalidCompactBlock* = 100'u32   # Instant ban
  ScoreOversizedMessage* = 20'u32

proc misbehaving*(peer: var Peer, howmuch: uint32, message: string) =
  ## Add misbehavior points to a peer. At 100 points, peer is flagged for disconnect.
  ## Match Bitcoin Core's Misbehaving() behavior from net_processing.cpp
  let oldScore = peer.misbehaviorScore
  peer.misbehaviorScore = min(peer.misbehaviorScore + howmuch, MisbehaviorThreshold)

  let messagePart = if message.len > 0: ": " & message else: ""
  warn "peer misbehaving", peer = $peer, score = howmuch,
       total = peer.misbehaviorScore, reason = messagePart

  if peer.misbehaviorScore >= MisbehaviorThreshold and oldScore < MisbehaviorThreshold:
    peer.shouldDisconnect = true
    warn "peer exceeded misbehavior threshold, flagged for ban", peer = $peer

proc shouldBan*(peer: Peer): bool =
  ## Check if peer should be banned (score >= threshold)
  peer.misbehaviorScore >= MisbehaviorThreshold

proc resetMisbehavior*(peer: var Peer) =
  ## Reset misbehavior score (used during testing)
  peer.misbehaviorScore = 0
  peer.shouldDisconnect = false
