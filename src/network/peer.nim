## P2P peer connection handling
## TCP connection with message framing, version handshake, and ping/pong
## Uses chronos for async networking

import std/[strformat, random, hashes, tables]
import std/times as stdtimes
import chronos
import chronos/timer as ctimer
import chronicles
import ../primitives/[types, serialize]
import ../consensus/params
from ../crypto/hashing import doubleSha256
import ../mempool/mempool as mempool_mod
import ./messages
import ./compact_blocks
import ./bip324

export chronicles

const
  HandshakeTimeoutSec* = 60  # 60 seconds (Bitcoin Core compatible)
  PingTimeoutSec* = 30       # 30 seconds
  ReadTimeoutSec* = 120      # 2 minutes
  MinProtocolVersion* = 70015'u32  # Minimum for witness support
  ScorePreHandshakeMessage* = 10'u32  # Misbehavior for pre-handshake messages
  ScoreDuplicateVersion* = 1'u32      # Misbehavior for duplicate version

  # BIP-324 V2 transport constants
  V2HandshakeTimeoutSec* = 30  # Timeout for V2 key exchange

  # Stale peer detection constants (Bitcoin Core net_processing.cpp)
  ChainSyncTimeoutSec* = 20 * 60      # 20 minutes - timeout for peer to catch up to our chain
  HeadersResponseTimeSec* = 2 * 60    # 2 minutes - time to wait for headers response
  StaleTipCheckIntervalSec* = 10 * 60 # 10 minutes - how often to check for stale tip
  ExtraPeerCheckIntervalSec* = 45     # 45 seconds - how often to evict extra outbound peers
  PingIntervalSec* = 2 * 60           # 2 minutes - interval between ping messages
  PingTimeoutIntervalSec* = 20 * 60   # 20 minutes - disconnect if no pong received
  MinimumConnectTimeSec* = 30         # 30 seconds - minimum time before eviction allowed
  BlockStallingTimeoutDefaultSec* = 2  # 2 seconds - default block stalling timeout
  BlockStallingTimeoutMaxSec* = 64    # 64 seconds - maximum block stalling timeout

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

  TransportProtocol* = enum
    tpV1         # Legacy unencrypted transport
    tpV2         # BIP-324 encrypted transport

  PeerCallback* = proc(peer: Peer, msg: P2PMessage): Future[void] {.async.}

  ## Chain sync state for outbound peer eviction
  ## Reference: Bitcoin Core net_processing.cpp ChainSyncTimeoutState
  ChainSyncState* = object
    timeout*: int64              # Deadline for peer to catch up (unix seconds, 0 = not set)
    workHeaderHeight*: int32     # Height of our tip when timeout was set
    sentGetheaders*: bool        # Whether we've sent getheaders since timeout started
    protect*: bool               # Protected from chain sync eviction

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
    # Per-peer I/O counters (for getpeerinfo)
    bytesSent*: uint64
    bytesRecv*: uint64
    relay*: bool                 # Relay flag from version message
    timeOffset*: int64           # peer_version_timestamp - our_time_at_receipt (seconds)
    # Network params
    params*: ConsensusParams
    networkMagic*: array[4, byte]
    # Feature negotiation
    feeFilterRate*: uint64
    sendHeaders*: bool
    wtxidRelay*: bool
    wantsAddrV2*: bool           # Peer signaled ADDRv2 support (BIP155)
    # Handshake state tracking (Bitcoin Core: pfrom.nVersion != 0, fSuccessfullyConnected)
    handshakeComplete*: bool     # True after both VERSION and VERACK exchanged
    versionReceived*: bool       # True after receiving VERSION
    versionSent*: bool           # True after sending VERSION
    verackReceived*: bool        # True after receiving VERACK
    verackSent*: bool            # True after sending VERACK
    localNonce*: uint64          # Our nonce for self-connection detection
    remoteNonce*: uint64         # Their nonce from version message
    handshakeStartTime*: stdtimes.Time  # When handshake started (for timeout)
    # Misbehavior scoring (Bitcoin Core: 100 = ban threshold)
    misbehaviorScore*: uint32
    shouldDisconnect*: bool
    # Internal state
    recvBuffer*: seq[byte]
    closing*: bool
    # Stale peer tracking (Bitcoin Core net_processing.cpp)
    connectedTime*: chronos.Moment     # When connection was established
    lastBlockTime*: chronos.Moment     # When peer last sent us a block
    lastTxTime*: chronos.Moment        # When peer last sent us a transaction
    lastBlockAnnouncement*: int64      # Unix time of last block announcement (for eviction)
    bestKnownHeight*: int32            # Best known block height from this peer
    pingStartTime*: chronos.Moment     # When current ping was sent (for timeout)
    pingPending*: bool                 # Whether we're waiting for a pong
    headersRequested*: bool            # Whether we've requested headers from this peer
    headersRequestTime*: chronos.Moment  # When headers were requested
    syncStarted*: bool                 # Whether we've started syncing from this peer
    chainSyncState*: ChainSyncState    # Chain sync timeout state
    blocksInFlight*: int               # Number of blocks we're downloading from this peer
    # BIP 152 compact block relay
    compactBlockState*: CompactBlockState  # Compact block relay state
    peerCmpctVersion*: uint64              # Compact block version peer supports (0 = none)
    peerHighBandwidth*: bool               # Peer wants high-bandwidth mode
    # Mempool reference for compact block reconstruction
    mempool*: mempool_mod.Mempool          # May be nil during IBD

  PeerError* = object of CatchableError

  # Callback type for self-connection detection
  # Must be {.raises: [].} for chronos async compatibility
  SelfConnectChecker* = proc(nonce: uint64): bool {.gcsafe, raises: [].}

proc newPeer*(address: string, port: uint16, params: ConsensusParams,
              direction: PeerDirection = pdOutbound): Peer =
  randomize()
  let now = chronos.Moment.now()
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
    shouldDisconnect: false,
    # Handshake state
    handshakeComplete: false,
    versionReceived: false,
    versionSent: false,
    verackReceived: false,
    verackSent: false,
    localNonce: uint64(rand(high(int))),  # Generate unique nonce for self-connection detection
    remoteNonce: 0,
    # BIP 152 compact blocks
    compactBlockState: newCompactBlockState(),
    peerCmpctVersion: 0,
    peerHighBandwidth: false,
    # Stale peer tracking
    connectedTime: now,
    lastBlockTime: now,              # Initialize to now, not epoch
    lastTxTime: now,
    lastBlockAnnouncement: 0,
    bestKnownHeight: 0,
    pingStartTime: now,
    pingPending: false,
    headersRequested: false,
    headersRequestTime: now,
    syncStarted: false,
    chainSyncState: ChainSyncState(),
    blocksInFlight: 0
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
  ## Send a P2P message to the peer.
  ##
  ## Raises only PeerError on failure. Chronos transport errors
  ## (TransportUseClosedError, TransportIncompleteError, OSError on a
  ## torn-down socket) are caught and re-raised as PeerError so callers
  ## have a single catch type, and so spawned writers (asyncSpawn at the
  ## inv handler in nimrod.nim and the addr broadcast in peermanager.nim)
  ## don't promote a transport race into a process-killing FutureDefect.
  ## Reference: 2026-04-25 nimrod crash post-tip when peer
  ## 139.162.155.229 closed mid-getdata-write.
  if not peer.isConnected():
    raise newException(PeerError, "not connected")

  let data = serializeMessage(peer.networkMagic, msg)

  var written: int
  try:
    written = await peer.transport.write(data)
  except CatchableError as e:
    raise newException(PeerError, "transport write failed: " & e.msg)

  if written != data.len:
    raise newException(PeerError, "failed to send complete message")

  peer.bytesSent += uint64(data.len)
  trace "sent message", peer = $peer, kind = msg.kind, size = data.len - 24

proc spawnSafe*(fut: Future[void]) {.async.} =
  ## Wrapper for asyncSpawn'd peer operations. Awaits the inner future
  ## and swallows any CatchableError so a transport/peer error does not
  ## escape an unhandled async future and crash the runtime with a
  ## FutureDefect. Pair with `asyncSpawn`:
  ##
  ##   asyncSpawn spawnSafe(peer.sendGetData(invs))
  ##
  ## The inner peer-op is expected to log its own context (sendMessage
  ## logs "sent message" on success); on failure we log at debug level
  ## since the message-loop catch path will see and report the
  ## subsequent disconnect.
  try:
    await fut
  except CatchableError as e:
    debug "spawned peer op failed", error = e.msg

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
  peer.bytesRecv += uint64(totalSize)
  peer.lastSeen = stdtimes.getTime()

  let command = bytesToCommand(header.command)
  trace "received message", peer = $peer, command = command, size = payload.len

  return deserializePayload(command, @payload)

proc sendVersion*(peer: Peer, ourHeight: int32) {.async.} =
  ## Send version message
  let msg = newVersionMsg(
    version = ProtocolVersion,
    services = NodeNetwork or NodeWitness,
    timestamp = stdtimes.getTime().toUnix(),
    addrRecv = NetAddress(services: NodeNetwork, port: peer.port),
    addrFrom = NetAddress(services: NodeNetwork or NodeWitness, port: peer.params.p2pPort),
    nonce = peer.localNonce,  # Use our unique nonce for self-connection detection
    userAgent = UserAgent,
    startHeight = ourHeight,
    relay = true
  )

  await peer.sendMessage(msg)
  peer.versionSent = true
  peer.state = psHandshaking
  peer.handshakeStartTime = stdtimes.getTime()

proc sendVerack*(peer: Peer) {.async.} =
  await peer.sendMessage(newVerack())
  peer.verackSent = true

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

proc sendSendAddrV2*(peer: Peer) {.async.} =
  ## Signal ADDRv2 support to peer (BIP155)
  ## Must be sent between VERSION and VERACK
  await peer.sendMessage(newSendAddrV2())

proc performHandshake*(peer: Peer, ourHeight: int32,
                       checkSelfConnect: SelfConnectChecker = nil) {.async.} =
  ## Perform version handshake with peer
  ## Outbound: send version -> recv version -> send verack -> recv verack
  ## Inbound: recv version -> send version -> send verack -> recv verack
  ## Then send wtxidrelay, sendheaders, sendcmpct
  ##
  ## Enforces:
  ## - Minimum protocol version (70015 for witness support)
  ## - Self-connection detection via nonce
  ## - 60 second handshake timeout
  ##
  ## Reference: Bitcoin Core net_processing.cpp ProcessMessage()

  peer.handshakeStartTime = stdtimes.getTime()

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

    # Validate version (protocol version, etc.)
    let versionData = versionMsg.version
    if versionData.version < MinProtocolVersion:
      raise newException(PeerError, "peer using obsolete protocol version: " &
                         $versionData.version & " < " & $MinProtocolVersion)

    peer.version = versionData.version
    peer.services = versionData.services
    peer.userAgent = versionData.userAgent
    peer.startHeight = versionData.startHeight
    peer.relay = versionData.relay
    peer.timeOffset = versionData.timestamp - getTime().toUnix()
    peer.versionReceived = true
    peer.remoteNonce = versionData.nonce

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # BIP155: Send sendaddrv2 BEFORE verack (protocol version 70016+)
    if peer.version >= 70016:
      await peer.sendSendAddrV2()
      await peer.sendWtxidRelay()

    # Send verack
    await peer.sendVerack()

    # Wait for their verack (consuming pre-verack feature messages)
    # Remote peer may send wtxidrelay, sendaddrv2, sendcmpct, etc. before verack
    block waitForVerack:
      for attempt in 0 ..< 20:  # Safety limit to avoid infinite loop
        let recvFut = peer.readMessage()
        if not await recvFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
          raise newException(PeerError, "handshake timeout waiting for verack")

        let msg = recvFut.value()
        case msg.kind
        of mkVerack:
          peer.verackReceived = true
          break waitForVerack
        of mkWtxidRelay:
          peer.wtxidRelay = true
          trace "peer supports wtxidrelay (pre-verack)", peer = $peer
        of mkSendAddrV2:
          peer.wantsAddrV2 = true
          trace "peer supports addrv2 (pre-verack)", peer = $peer
        of mkSendCmpct:
          trace "peer supports compact blocks (pre-verack)", peer = $peer
        of mkSendHeaders:
          peer.sendHeaders = true
          trace "peer prefers headers (pre-verack)", peer = $peer
        of mkFeeFilter:
          peer.feeFilterRate = msg.feeRate
          trace "peer feefilter (pre-verack)", peer = $peer
        of mkSendTxRcncl:
          trace "peer supports tx reconciliation (pre-verack)", peer = $peer
        else:
          raise newException(PeerError, "unexpected message during handshake: " & $msg.kind)

    if not peer.verackReceived:
      raise newException(PeerError, "did not receive verack during handshake")

  else:
    # Inbound: wait for version first
    let recvVersionFut = peer.readMessage()
    if not await recvVersionFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
      raise newException(PeerError, "handshake timeout waiting for version")

    let versionMsg = recvVersionFut.value()
    if versionMsg.kind != mkVersion:
      raise newException(PeerError, "expected version message")

    let versionData = versionMsg.version

    # Check minimum protocol version
    if versionData.version < MinProtocolVersion:
      raise newException(PeerError, "peer using obsolete protocol version: " &
                         $versionData.version & " < " & $MinProtocolVersion)

    # Check for self-connection (inbound only)
    if checkSelfConnect != nil and not checkSelfConnect(versionData.nonce):
      raise newException(PeerError, "connected to self")

    peer.version = versionData.version
    peer.services = versionData.services
    peer.userAgent = versionData.userAgent
    peer.startHeight = versionData.startHeight
    peer.relay = versionData.relay
    peer.timeOffset = versionData.timestamp - getTime().toUnix()
    peer.versionReceived = true
    peer.remoteNonce = versionData.nonce

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # Send our version
    await peer.sendVersion(ourHeight)

    # BIP155: Send sendaddrv2 BEFORE verack (protocol version 70016+)
    if peer.version >= 70016:
      await peer.sendSendAddrV2()
      await peer.sendWtxidRelay()

    # Send verack
    await peer.sendVerack()

    # Wait for their verack (consuming pre-verack feature messages)
    block waitForVerackInbound:
      for attempt in 0 ..< 20:
        let recvFut = peer.readMessage()
        if not await recvFut.withTimeout(ctimer.seconds(HandshakeTimeoutSec)):
          raise newException(PeerError, "handshake timeout waiting for verack")

        let msg = recvFut.value()
        case msg.kind
        of mkVerack:
          peer.verackReceived = true
          break waitForVerackInbound
        of mkWtxidRelay:
          peer.wtxidRelay = true
          trace "peer supports wtxidrelay (pre-verack)", peer = $peer
        of mkSendAddrV2:
          peer.wantsAddrV2 = true
          trace "peer supports addrv2 (pre-verack)", peer = $peer
        of mkSendCmpct:
          trace "peer supports compact blocks (pre-verack)", peer = $peer
        of mkSendHeaders:
          peer.sendHeaders = true
          trace "peer prefers headers (pre-verack)", peer = $peer
        of mkFeeFilter:
          peer.feeFilterRate = msg.feeRate
          trace "peer feefilter (pre-verack)", peer = $peer
        of mkSendTxRcncl:
          trace "peer supports tx reconciliation (pre-verack)", peer = $peer
        else:
          raise newException(PeerError, "unexpected message during handshake: " & $msg.kind)

    if not peer.verackReceived:
      raise newException(PeerError, "did not receive verack during handshake")

  # Send feature negotiation messages (after verack)
  # Note: sendaddrv2 and wtxidrelay are already sent before verack
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
    peer.relay = msg.version.relay
    peer.timeOffset = msg.version.timestamp - getTime().toUnix()
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

  of mkAddrV2:
    trace "received addrv2", peer = $peer, count = msg.addressesV2.len

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

  of mkMempool:
    # BIP35: real handler lives in nimrod.handleMessage which has access
    # to NodeState.mempool. This trace is the peer-loop's record; the
    # PeerCallback in nimrod.nim performs the inv flush.
    trace "received mempool", peer = $peer

  of mkNotFound:
    trace "received notfound", peer = $peer, count = msg.notFound.len

  of mkReject:
    warn "received reject", peer = $peer, message = msg.reject.message,
         reason = msg.reject.reason

  of mkSendHeaders:
    peer.sendHeaders = true
    trace "peer prefers headers", peer = $peer

  of mkSendCmpct:
    # BIP 152: Handle sendcmpct negotiation
    let version = msg.sendCmpct.version
    let announce = msg.sendCmpct.announce
    if version >= 1 and version <= 2:
      peer.peerCmpctVersion = version
      peer.peerHighBandwidth = announce
      peer.compactBlockState.handleSendCmpct(announce, version)
      info "peer supports compact blocks", peer = $peer,
           version = version, highBandwidth = announce
    else:
      trace "peer sent unsupported compact block version", peer = $peer,
            version = version

  of mkFeeFilter:
    peer.feeFilterRate = msg.feeRate
    trace "peer feefilter", peer = $peer, feeRate = msg.feeRate

  of mkWtxidRelay:
    peer.wtxidRelay = true
    trace "peer supports wtxidrelay", peer = $peer

  of mkSendAddrV2:
    peer.wantsAddrV2 = true
    trace "peer supports addrv2", peer = $peer

  of mkCmpctBlock:
    # BIP 152: Reconstruct block from compact block + mempool
    let cb = msg.cmpctBlock
    let headerData = serialize(cb.header)
    let blockHash = BlockHash(doubleSha256(headerData))
    info "received compact block", peer = $peer,
         hash = $blockHash,
         shortIds = cb.shortIds.len,
         prefilled = cb.prefilledTxns.len

    # Initialize the partially downloaded block
    var (pdb, status) = initPartiallyDownloadedBlock(cb)
    if status != rsOk:
      warn "invalid compact block", peer = $peer, status = $status
    else:
      peer.compactBlockState.blocksReceived += 1

      # Fill from mempool if available
      if peer.mempool != nil:
        pdb.fillFromMempool(peer.mempool)

      if pdb.isComplete():
        # Fully reconstructed from mempool + prefilled
        let (blk, rStatus) = pdb.reconstructBlock()
        if rStatus == rsOk:
          info "compact block reconstructed from mempool", peer = $peer,
               hash = $blockHash,
               prefilled = pdb.prefilledCount,
               mempoolHits = pdb.mempoolCount
          peer.compactBlockState.successfulReconstructions += 1
        else:
          warn "compact block reconstruction failed", peer = $peer,
               hash = $blockHash
          peer.compactBlockState.failedReconstructions += 1
      else:
        # Still missing some transactions
        let missing = pdb.getMissingTxIndexes()
        let totalTx = cb.blockTxCount()
        let missPct = if totalTx > 0: missing.len.float / totalTx.float * 100.0 else: 100.0
        if missPct > 50.0:
          # Too many missing — don't bother with getblocktxn, request full block
          info "compact block too many missing txns, skipping", peer = $peer,
               hash = $blockHash, missingPct = missPct
          peer.compactBlockState.failedReconstructions += 1
        else:
          info "requesting missing txns for compact block", peer = $peer,
               hash = $blockHash, missing = missing.len,
               mempoolHits = pdb.mempoolCount
          # Store partial and send getblocktxn
          peer.compactBlockState.pendingPartials[blockHash] = pdb
          await peer.sendMessage(newGetBlockTxnMsg(blockHash, missing))
          peer.compactBlockState.txnsRequested += missing.len

  of mkGetBlockTxn:
    # BIP 152: Peer requests missing transactions for a compact block
    # We respond with the requested transactions if we have the block
    let req = msg.getBlockTxn
    info "received getblocktxn", peer = $peer,
         hash = $req.blockHash,
         indexes = req.indexes.len
    # Note: Actual block lookup requires chain integration.
    # For now, log the request. The higher-level sync code should register
    # a callback to handle this by looking up the block and sending blocktxn.

  of mkBlockTxn:
    # BIP 152: Response with missing transactions for a compact block
    let resp = msg.blockTxn
    info "received blocktxn", peer = $peer,
         hash = $resp.blockHash,
         txns = resp.transactions.len

    if peer.compactBlockState.hasPending(resp.blockHash):
      let (blk, status) = peer.compactBlockState.completeBlock(
        resp.blockHash, resp.transactions)
      if status == rsOk:
        info "compact block reconstructed", peer = $peer,
             hash = $resp.blockHash,
             txCount = blk.txs.len
      else:
        warn "compact block reconstruction failed", peer = $peer,
             hash = $resp.blockHash, status = $status
    else:
      trace "unexpected blocktxn (no pending compact block)", peer = $peer,
            hash = $resp.blockHash

  of mkSendPackages:
    trace "peer supports packages", peer = $peer

  of mkSendTxRcncl:
    trace "peer supports tx reconciliation", peer = $peer

  of mkReqRecon:
    discard  # TODO: handle reconciliation request

  of mkSketch:
    discard  # TODO: handle sketch

  of mkReconcilDiff:
    discard  # TODO: handle reconciliation diff

  of mkReqSketchExt:
    discard  # TODO: handle sketch extension request

# Pre-handshake message validation types and forward declarations
type
  MessageAcceptResult* = enum
    marAccept           # Accept and process the message
    marDropSilent       # Drop without misbehavior (e.g., redundant verack)
    marDropMisbehave    # Drop with misbehavior points
    marDisconnect       # Disconnect immediately (self-connect, old version)

proc messageLoop*(peer: Peer, callback: PeerCallback) {.async.} =
  ## Main message loop - auto-handles ping/pong, dispatches others to callback
  ## Runs until peer disconnects or error occurs
  ## Note: For full pre-handshake validation, use messageLoopWithValidation
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
  ScoreHeadersDontConnect* = 20'u32   # Headers that don't connect to our chain
  ScoreBlockDownloadStall* = 50'u32   # Stalling block download
  ScoreUnrequestedData* = 5'u32       # Sending unrequested data

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

# Pre-handshake message validation
# Reference: Bitcoin Core net_processing.cpp ProcessMessage()
# - Non-version messages before version: drop and misbehave
# - Messages before verack (except allowed ones): drop and misbehave
# - Duplicate version: misbehave
# - Self-connection detection via nonce
# - Minimum protocol version check

proc isPreHandshakeMessageAllowed*(peer: Peer, kind: MessageKind): bool =
  ## Check if a message type is allowed before handshake completes
  ## Reference: Bitcoin Core net_processing.cpp
  ##
  ## Before VERSION received: only VERSION allowed
  ## After VERSION, before VERACK: VERSION, VERACK, and negotiation messages
  ## After VERACK: all messages allowed

  if peer.handshakeComplete:
    return true

  if not peer.versionReceived:
    # Only VERSION allowed before we receive VERSION
    return kind == mkVersion

  # After VERSION received, before VERACK
  # Allowed: VERACK, and some negotiation messages (wtxidrelay, sendaddrv2, sendheaders)
  case kind
  of mkVerack, mkWtxidRelay, mkSendAddrV2, mkSendHeaders, mkSendCmpct, mkFeeFilter:
    true
  else:
    false

proc validatePreHandshakeMessage*(peer: var Peer, kind: MessageKind): MessageAcceptResult =
  ## Validate if a message should be accepted during handshake
  ## Returns what action to take (accept, drop, misbehave, disconnect)

  if peer.handshakeComplete:
    return marAccept

  if not peer.versionReceived:
    # Before VERSION received, only VERSION is allowed
    if kind == mkVersion:
      return marAccept
    else:
      # Non-version message before version handshake
      warn "pre-version message rejected", peer = $peer, kind = kind
      misbehaving(peer, ScorePreHandshakeMessage, "non-version message before version")
      return marDropMisbehave

  # VERSION received, check specific messages
  case kind
  of mkVersion:
    # Duplicate VERSION - misbehave (score 1 per Bitcoin Core)
    warn "duplicate version message", peer = $peer
    misbehaving(peer, ScoreDuplicateVersion, "duplicate version")
    return marDropMisbehave

  of mkVerack:
    if peer.verackReceived:
      # Redundant verack - drop silently (Bitcoin Core ignores)
      debug "ignoring redundant verack", peer = $peer
      return marDropSilent
    return marAccept

  of mkWtxidRelay, mkSendAddrV2:
    # These must come between VERSION and VERACK
    if peer.verackReceived:
      # wtxidrelay/sendaddrv2 after verack is a protocol violation
      warn "negotiation message after verack", peer = $peer, kind = kind
      return marDisconnect
    return marAccept

  of mkSendHeaders, mkSendCmpct, mkFeeFilter:
    # These can come any time after VERSION
    return marAccept

  else:
    # Other messages before verack
    if not peer.verackReceived:
      warn "unsupported message prior to verack", peer = $peer, kind = kind
      misbehaving(peer, ScorePreHandshakeMessage, "message before verack")
      return marDropMisbehave
    return marAccept

proc validateVersionMessage*(peer: var Peer, version: uint32, nonce: uint64,
                             checkSelfConnect: SelfConnectChecker): MessageAcceptResult =
  ## Validate a version message
  ## - Check minimum protocol version (70015 for witness)
  ## - Check for self-connection via nonce
  ## - Mark version as received

  # Check minimum protocol version
  if version < MinProtocolVersion:
    warn "peer using obsolete version", peer = $peer, version = version,
         minimum = MinProtocolVersion
    return marDisconnect

  # Check for self-connection (only for inbound connections)
  # Reference: Bitcoin Core net_processing.cpp CheckIncomingNonce()
  if peer.direction == pdInbound:
    if checkSelfConnect != nil and not checkSelfConnect(nonce):
      warn "connected to self, disconnecting", peer = $peer
      return marDisconnect

  # Store remote nonce and mark version received
  peer.remoteNonce = nonce
  peer.versionReceived = true

  return marAccept

proc checkHandshakeTimeout*(peer: Peer): bool =
  ## Check if handshake has timed out (60 seconds)
  ## Returns true if timed out
  if peer.handshakeComplete:
    return false

  if peer.handshakeStartTime == stdtimes.Time():
    # Handshake hasn't started yet
    return false

  let elapsed = stdtimes.getTime() - peer.handshakeStartTime
  result = elapsed.inSeconds >= HandshakeTimeoutSec

  if result:
    warn "handshake timeout", peer = $peer, elapsed = elapsed.inSeconds

proc markHandshakeComplete*(peer: var Peer) =
  ## Mark the handshake as complete after both VERSION and VERACK exchanged
  if peer.versionReceived and peer.versionSent and
     peer.verackReceived and peer.verackSent:
    peer.handshakeComplete = true
    peer.state = psReady
    info "handshake complete", peer = $peer

# Stale peer detection functions
# Reference: Bitcoin Core net_processing.cpp

proc recordBlockReceived*(peer: var Peer) =
  ## Record that we received a block from this peer
  peer.lastBlockTime = chronos.Moment.now()

proc recordTxReceived*(peer: var Peer) =
  ## Record that we received a transaction from this peer
  peer.lastTxTime = chronos.Moment.now()

proc recordBlockAnnouncement*(peer: var Peer, unixTime: int64) =
  ## Record when this peer announced a block to us
  peer.lastBlockAnnouncement = unixTime

proc updateBestKnownHeight*(peer: var Peer, height: int32) =
  ## Update the best known block height from this peer
  if height > peer.bestKnownHeight:
    peer.bestKnownHeight = height

proc startPing*(peer: var Peer) =
  ## Record that we're starting a ping
  peer.pingStartTime = chronos.Moment.now()
  peer.pingPending = true

proc completePing*(peer: var Peer) =
  ## Record that we received a pong
  peer.pingPending = false
  let elapsed = chronos.Moment.now() - peer.pingStartTime
  peer.latencyMs = int(elapsed.milliseconds)

proc isPingTimedOut*(peer: Peer): bool =
  ## Check if a pending ping has timed out (20 minutes)
  ## Reference: Bitcoin Core TIMEOUT_INTERVAL = 20min
  if not peer.pingPending:
    return false
  let elapsed = chronos.Moment.now() - peer.pingStartTime
  result = elapsed > chronos.minutes(PingTimeoutIntervalSec div 60)
  if result:
    warn "ping timeout", peer = $peer,
         elapsedSec = elapsed.seconds

proc shouldSendPing*(peer: Peer): bool =
  ## Check if it's time to send a ping (every 2 minutes)
  ## Reference: Bitcoin Core PING_INTERVAL = 2min
  if peer.pingPending:
    return false  # Still waiting for pong
  let elapsed = chronos.Moment.now() - peer.pingStartTime
  elapsed > chronos.minutes(PingIntervalSec div 60)

proc startHeadersRequest*(peer: var Peer) =
  ## Record that we've requested headers
  peer.headersRequested = true
  peer.headersRequestTime = chronos.Moment.now()

proc completeHeadersRequest*(peer: var Peer) =
  ## Record that we've received headers
  peer.headersRequested = false

proc isHeadersRequestTimedOut*(peer: Peer): bool =
  ## Check if a headers request has timed out (2 minutes)
  ## Reference: Bitcoin Core HEADERS_RESPONSE_TIME = 2min
  if not peer.headersRequested:
    return false
  let elapsed = chronos.Moment.now() - peer.headersRequestTime
  result = elapsed > chronos.minutes(HeadersResponseTimeSec div 60)
  if result:
    warn "headers request timeout", peer = $peer,
         elapsedSec = elapsed.seconds

proc connectionAge*(peer: Peer): chronos.Duration =
  ## Get how long this peer has been connected
  chronos.Moment.now() - peer.connectedTime

proc hasMinimumConnectTime*(peer: Peer): bool =
  ## Check if peer has been connected long enough for eviction consideration
  ## Reference: Bitcoin Core MINIMUM_CONNECT_TIME = 30s
  peer.connectionAge() >= chronos.seconds(MinimumConnectTimeSec)

proc isOutbound*(peer: Peer): bool =
  ## Check if this is an outbound connection
  peer.direction == pdOutbound

proc isInbound*(peer: Peer): bool =
  ## Check if this is an inbound connection
  peer.direction == pdInbound

proc hasBlocksInFlight*(peer: Peer): bool =
  ## Check if we're downloading blocks from this peer
  peer.blocksInFlight > 0

proc resetChainSyncTimeout*(peer: var Peer) =
  ## Reset chain sync timeout when peer catches up
  ## Reference: Bitcoin Core ConsiderEviction() - reset when peer has sufficient work
  peer.chainSyncState.timeout = 0
  peer.chainSyncState.workHeaderHeight = 0
  peer.chainSyncState.sentGetheaders = false

proc setChainSyncTimeout*(peer: var Peer, ourHeight: int32, unixTime: int64) =
  ## Set chain sync timeout for an outbound peer that's behind
  ## Reference: Bitcoin Core ConsiderEviction()
  peer.chainSyncState.timeout = unixTime + ChainSyncTimeoutSec
  peer.chainSyncState.workHeaderHeight = ourHeight
  peer.chainSyncState.sentGetheaders = false

proc isChainSyncTimedOut*(peer: Peer, nowUnix: int64): bool =
  ## Check if chain sync has timed out
  peer.chainSyncState.timeout > 0 and nowUnix > peer.chainSyncState.timeout

proc markChainSyncGetheadersSent*(peer: var Peer, nowUnix: int64) =
  ## Mark that we've sent getheaders and reduce timeout to HEADERS_RESPONSE_TIME
  ## Reference: Bitcoin Core ConsiderEviction() - after sending getheaders
  peer.chainSyncState.sentGetheaders = true
  peer.chainSyncState.timeout = nowUnix + HeadersResponseTimeSec

proc shouldDisconnectForChainSync*(peer: Peer, nowUnix: int64): bool =
  ## Check if peer should be disconnected for chain sync timeout
  ## Returns true if timeout expired AND we already sent getheaders
  if not peer.isChainSyncTimedOut(nowUnix):
    return false
  peer.chainSyncState.sentGetheaders

proc isProtectedFromChainSyncEviction*(peer: Peer): bool =
  ## Check if peer is protected from chain sync eviction
  peer.chainSyncState.protect

proc protectFromChainSyncEviction*(peer: var Peer) =
  ## Protect this peer from chain sync eviction
  peer.chainSyncState.protect = true
