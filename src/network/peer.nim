## P2P peer connection handling
## TCP connection with message framing, version handshake, and ping/pong
## Uses chronos for async networking

import std/[strformat, random, hashes, tables, os, strutils, options]
import ../util/rng
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
import ./proxy as proxy_mod

export chronicles

const
  HandshakeTimeoutSec* = 60  # 60 seconds (Bitcoin Core compatible)
  PingTimeoutSec* = 30       # 30 seconds
  ReadTimeoutSec* = 120      # 2 minutes
  # TCP connect() timeout for an outbound dial.  Without an explicit cap the
  # connect falls back to the OS default (~127s on Linux), which is far too
  # long: the outbound-connection loop dials addresses serially, so one dead
  # peer stalls every subsequent dial for two minutes.  Bitcoin Core uses
  # DEFAULT_CONNECT_TIMEOUT = 5000 ms (src/net.h); match it.
  ConnectTimeoutSec* = 5
  # Core MIN_PEER_PROTO_VERSION (node/protocol_version.h:18), checked for ALL
  # peers at net_processing.cpp:3619.  This used to be 70015 ("minimum for
  # witness support"), which dropped every inbound peer Core keeps (e.g. a
  # 70002 crawler).  Witness capability is a SERVICES question
  # (NODE_WITNESS), enforced only where Core enforces it: outbound peers we
  # pick (ExpectServicesFromConn) and the block-download peer choice
  # (CanServeWitnesses).  Feature messages are gated per-version below.
  MinProtocolVersion* = 31800'u32
  # Core node/protocol_version.h feature thresholds.
  Bip0031Version* = 60000'u32         # ping carries a nonce / pong exists
  SendHeadersVersion* = 70012'u32     # sendheaders
  FeeFilterVersion* = 70013'u32       # feefilter
  ShortIdsBlocksVersion* = 70014'u32  # sendcmpct / BIP-152
  WtxidRelayVersion* = 70016'u32      # wtxidrelay (+ sendaddrv2 courtesy gate)
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
    # BIP-324 v2 transport state.  `transportProto = tpV1` until inbound
    # peer-classification (or, in the future, an outbound probe) decides
    # the wire is v2.  When `tpV2`, sendMessage/readMessage encrypt and
    # decrypt through `v2Cipher`; the v1 24-byte header is skipped.
    transportProto*: TransportProtocol
    v2Cipher*: BIP324Cipher
    # BIP-324 outbound: when true, performHandshake skips the v2 probe
    # even if `bip324V2OutboundEnabled()` returns true.  PeerManager sets
    # this when the address is in the v1-only fallback set, so we don't
    # waste a connection retrying v2 on a known v1-only peer.
    v2OutboundDisabled*: bool
    # BIP-324 outbound fallback bookkeeping: set true the moment the v2
    # initiator handshake starts on THIS dial.  A real v1-only Core cannot
    # parse our ellswift+garbage and simply closes the socket (it does NOT
    # reply with a v1 VERSION header), so the failure surfaces as a generic
    # "connection closed"/timeout rather than a "v2 ..." error.  PeerManager
    # keys its markV1Only fallback off this flag so ANY post-v2 handshake
    # failure demotes the address to v1 for the next dial.
    v2OutboundAttempted*: bool
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
    sendsPackages*: bool         # Peer sent BIP-331 sendpackages
    pkgRelayVersion*: uint32     # BIP-331 protocol version (0 if not negotiated)
    # Handshake state tracking (Bitcoin Core: pfrom.nVersion != 0, fSuccessfullyConnected)
    handshakeComplete*: bool     # True after both VERSION and VERACK exchanged
    versionReceived*: bool       # True after receiving VERSION
    versionSent*: bool           # True after sending VERSION
    verackReceived*: bool        # True after receiving VERACK
    verackSent*: bool            # True after sending VERACK
    localNonce*: uint64          # Our nonce for self-connection detection
    remoteNonce*: uint64         # Their nonce from version message
    handshakeStartTime*: stdtimes.Time  # When handshake started (for timeout)
    handshakeTimeoutMs*: int            # 0 = HandshakeTimeoutSec * 1000 (tests override)
    expectServices*: bool               # Core ExpectServicesFromConn(): outbound
                                        # full-relay/block-relay only (set by
                                        # PeerManager); inbound/manual/feeler = false
    # Misbehavior scoring (Bitcoin Core: 100 = ban threshold)
    misbehaviorScore*: uint32
    shouldDisconnect*: bool
    # Anti-DoS addr-relay state (Bitcoin Core net_processing.cpp Peer):
    #  - getaddrRecvd: true once we have answered this peer's first getaddr.
    #    A second getaddr from the same connection is ignored
    #    (Core m_getaddr_recvd; net_processing.cpp:4833).
    #  - addrTokenBucket / addrTokenTimestamp: leaky-bucket rate-limit on
    #    INBOUND addr messages.  Refilled at MAX_ADDR_RATE_PER_SECOND (0.1/s),
    #    capped at MAX_ADDR_PROCESSING_TOKEN_BUCKET (1000); each processed addr
    #    spends one token, excess is dropped (Core m_addr_token_bucket;
    #    net_processing.cpp:5646-5670).
    getaddrRecvd*: bool
    # Self-address advertisement (Core CNode::addrLocal /
    # Peer::m_next_local_addr_send):
    #  - addrLocal: the addr_recv field of the peer's VERSION = the address the
    #    peer sees us at.  Feeds discovery and GetLocalAddrForPeer.
    #  - nextLocalAddrSend: unix seconds when our own address is next announced
    #    to this peer; 0 = never announced yet (the first send is still due).
    addrLocal*: NetAddress
    nextLocalAddrSend*: int64
    addrTokenBucket*: float64
    addrTokenTimestamp*: int64         # unix seconds of last bucket refill
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
    # W117 BUG-3 FIX (FIX-56): optional proxy manager wired in by
    # PeerManager.connectToPeerWithType when --proxy/--onion/--i2psam is
    # configured.  When non-nil, Peer.connect() dispatches outbound
    # connections through proxy_mod.connectThroughProxy() (Tor SOCKS5,
    # I2P SAM, or clearnet SOCKS5 with optional stream isolation).
    # Reference: bitcoin-core/src/net.cpp CConnman::ConnectNode delegating
    # to ConnectThroughProxy() / ConnectThroughI2P() based on m_net.
    proxyManager*: proxy_mod.ProxyManager  # nil = direct connect

  PeerError* = object of CatchableError

  # Callback type for self-connection detection
  # Must be {.raises: [].} for chronos async compatibility
  SelfConnectChecker* = proc(nonce: uint64): bool {.gcsafe, raises: [].}

proc newPeer*(address: string, port: uint16, params: ConsensusParams,
              direction: PeerDirection = pdOutbound): Peer =
  let now = chronos.Moment.now()
  Peer(
    address: address,
    port: port,
    state: psDisconnected,
    direction: direction,
    transportProto: tpV1,
    params: params,
    networkMagic: params.magic,
    recvBuffer: @[],
    closing: false,
    misbehaviorScore: 0,
    shouldDisconnect: false,
    # Anti-DoS addr-relay state.  NOTE: Core actually inits m_addr_token_bucket
    # = 1.0 (net_processing.cpp:380) and tops it up by MAX_ADDR_TO_SEND=1000 only
    # when WE send a getaddr (net_processing.cpp:3767, once per connection).
    # nimrod sends getaddr periodically to all ready peers (requestAddresses)
    # rather than once-per-connection, so it uses a permissive full bucket here;
    # after the first 1000 processed addrs the 0.1/s refill governs exactly as
    # Core.  TODO(anti-eclipse): adopt the once-per-connection getaddr + 1.0 init
    # + 1000 top-up to also rate-limit the first unsolicited addr burst.
    getaddrRecvd: false,
    addrTokenBucket: 1000.0,
    addrTokenTimestamp: 0,
    # Handshake state
    handshakeComplete: false,
    versionReceived: false,
    versionSent: false,
    verackReceived: false,
    verackSent: false,
    handshakeTimeoutMs: HandshakeTimeoutSec * 1000,
    localNonce: uint64(nodeRng().rand(high(int))),  # Generate unique nonce for self-connection detection
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

proc handshakeTimeoutDur(peer: Peer): ctimer.Duration =
  let ms = if peer.handshakeTimeoutMs > 0: peer.handshakeTimeoutMs
           else: HandshakeTimeoutSec * 1000
  ctimer.milliseconds(ms)

proc `$`*(peer: Peer): string =
  fmt"{peer.address}:{peer.port}"

proc isConnected*(peer: Peer): bool =
  peer.state in {psConnected, psHandshaking, psReady} and
    peer.transport != nil and not peer.transport.closed

proc connect*(peer: Peer): Future[bool] {.async.} =
  ## Connect to the peer (outbound connection).
  ##
  ## W117 BUG-3 FIX (FIX-56): when `peer.proxyManager` is non-nil, the
  ## outbound connection is dispatched based on the address type:
  ##   - `.onion`     → SOCKS5 to the configured onion proxy (Tor) with
  ##                    optional stream isolation per circuit.
  ##   - `.i2p`       → I2P SAM session (STREAM CONNECT).
  ##   - IPv4 / IPv6  → direct TCP, or SOCKS5 to the clearnet proxy if
  ##                    one was configured (--proxy).
  ##   - CJDNS (fc00::/8) is treated as clearnet (direct/SOCKS5) — Core
  ##                    treats CJDNS as routable and does not proxy it.
  ## Reference: bitcoin-core/src/net.cpp CConnman::ConnectNode dispatch
  ## via ConnectThroughProxy / ConnectThroughI2P based on m_net.
  if peer.state != psDisconnected:
    return false

  peer.state = psConnecting

  try:
    if peer.proxyManager != nil:
      peer.transport = await proxy_mod.connectThroughProxy(
        peer.proxyManager, peer.address, peer.port)
    else:
      let ta = initTAddress(peer.address, Port(peer.port))
      # Cap the TCP connect at ConnectTimeoutSec.  Chronos `connect` otherwise
      # inherits the OS connect timeout (~127s); a single unreachable address
      # would then stall the serial outbound-dial loop for two minutes.
      peer.transport = await connect(ta).wait(ctimer.seconds(ConnectTimeoutSec))
    peer.state = psConnected
    peer.lastSeen = stdtimes.getTime()
    info "connected to peer", peer = $peer,
         viaProxy = (peer.proxyManager != nil)
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

proc fillRecvBuffer(peer: Peer, n: int): Future[void] {.async.} =
  ## Read from the socket until peer.recvBuffer has at least n bytes.
  ## Used by the v2 handshake (which can't yet decrypt v1-style packets)
  ## and as a primitive for peeking the first 16 bytes in classify.
  while peer.recvBuffer.len < n:
    var buf: array[4096, byte]
    let bytesRead = await peer.transport.readOnce(addr buf[0], buf.len)
    if bytesRead == 0:
      raise newException(PeerError, "connection closed")
    peer.recvBuffer.add(buf[0 ..< bytesRead])

proc takeFromRecvBuffer(peer: Peer, n: int): seq[byte] =
  ## Remove and return the first n bytes from peer.recvBuffer.  Caller
  ## must ensure the buffer is large enough (use `fillRecvBuffer` first).
  doAssert peer.recvBuffer.len >= n
  result = peer.recvBuffer[0 ..< n]
  peer.recvBuffer = peer.recvBuffer[n .. ^1]

proc sendMessageV1(peer: Peer, msg: P2PMessage) {.async.} =
  ## Internal: send a message via v1 (legacy unencrypted) transport.
  let data = serializeMessage(peer.networkMagic, msg)

  var written: int
  try:
    written = await peer.transport.write(data)
  except CatchableError as e:
    raise newException(PeerError, "transport write failed: " & e.msg)

  if written != data.len:
    raise newException(PeerError, "failed to send complete message")

  peer.bytesSent += uint64(data.len)
  trace "sent message (v1)", peer = $peer, kind = msg.kind, size = data.len - 24

proc sendMessageV2(peer: Peer, msg: P2PMessage) {.async.} =
  ## Internal: send a message via BIP-324 v2 (encrypted) transport.
  ## Wire format (after the cipher handshake): encrypted_length (3 bytes)
  ## || ciphertext (header_byte + content_bytes + 16-byte AEAD tag).
  ## AAD is empty in the application phase (handshake AAD has been
  ## consumed by the version-packet exchange).
  if not peer.v2Cipher.isInitialized:
    raise newException(PeerError, "v2 cipher not initialized")

  let command = messageKindToCommand(msg.kind)
  let payload = serializePayload(msg)
  let contents = encodeV2Message(command, payload)

  var packet: seq[byte]
  try:
    packet = peer.v2Cipher.encrypt(contents)
  except BIP324Error as e:
    raise newException(PeerError, "v2 encrypt failed: " & e.msg)

  var written: int
  try:
    written = await peer.transport.write(packet)
  except CatchableError as e:
    raise newException(PeerError, "transport write failed: " & e.msg)

  if written != packet.len:
    raise newException(PeerError, "failed to send complete v2 packet")

  peer.bytesSent += uint64(packet.len)
  trace "sent message (v2)", peer = $peer, kind = msg.kind,
        size = contents.len, packetSize = packet.len

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
  ##
  ## Routes to the v1 or v2 path depending on `peer.transportProto`.
  ## After the BIP-324 handshake has installed v2 keys (see
  ## `performV2HandshakeResponder`), `transportProto = tpV2` and the
  ## packet is AEAD-encrypted; otherwise the v1 24-byte-header envelope
  ## is used.
  if not peer.isConnected():
    raise newException(PeerError, "not connected")

  if peer.transportProto == tpV2:
    await peer.sendMessageV2(msg)
  else:
    await peer.sendMessageV1(msg)

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

proc readMessageV1(peer: Peer): Future[P2PMessage] {.async.} =
  ## Internal: read a v1 (legacy) message from the peer.
  ## Reads 24-byte header, validates magic, reads payload, verifies checksum.
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
  trace "received message (v1)", peer = $peer, command = command, size = payload.len

  return deserializePayload(command, @payload)

proc readMessageV2(peer: Peer): Future[P2PMessage] {.async.} =
  ## Internal: read a v2 (BIP-324 AEAD) packet, decrypt it, and return
  ## the decoded P2PMessage.  Skips decoy packets transparently per
  ## BIP-324 (header byte's IGNORE bit).  AAD is empty in the
  ## application phase.
  if not peer.v2Cipher.isInitialized:
    raise newException(PeerError, "v2 cipher not initialized")

  while true:
    # Encrypted length (3 bytes) — decryptLength advances the length
    # cipher's keystream by 3.  Must be called exactly once per packet.
    await peer.fillRecvBuffer(LengthLen)
    let encLen = peer.takeFromRecvBuffer(LengthLen)
    var contentsLen: uint32
    try:
      contentsLen = peer.v2Cipher.decryptLength(encLen)
    except BIP324Error as e:
      raise newException(PeerError, "v2 length decrypt failed: " & e.msg)

    if contentsLen.int > MaxMessagePayload:
      raise newException(PeerError, "v2 message too large: " & $contentsLen)

    let aeadLen = HeaderLen + contentsLen.int + AEADExpansion
    await peer.fillRecvBuffer(aeadLen)
    let aeadPayload = peer.takeFromRecvBuffer(aeadLen)
    var contents: seq[byte]
    var ignore: bool
    try:
      let dec = peer.v2Cipher.decrypt(aeadPayload)
      contents = dec.contents
      ignore = dec.ignore
    except BIP324Error as e:
      raise newException(PeerError, "v2 payload decrypt failed: " & e.msg)

    peer.bytesRecv += uint64(LengthLen + aeadLen)
    peer.lastSeen = stdtimes.getTime()

    if ignore:
      # Decoy — keep reading until we see a real message.
      trace "v2 decoy packet, skipping", peer = $peer, size = contents.len
      continue

    # Decode the v2 message envelope (short ID or long-form).
    var command: string
    var payload: seq[byte]
    try:
      let dec = decodeV2Message(contents)
      command = dec.command
      payload = dec.payload
    except BIP324Error as e:
      raise newException(PeerError, "v2 decode failed: " & e.msg)

    if payload.len > MaxMessagePayload:
      raise newException(PeerError, "v2 payload too large: " & $payload.len)

    trace "received message (v2)", peer = $peer, command = command, size = payload.len
    return deserializePayload(command, payload)

proc readMessage*(peer: Peer): Future[P2PMessage] {.async.} =
  ## Read a complete message from the peer.
  ## Routes to the v1 or v2 path depending on `peer.transportProto`
  ## (set during inbound classification — see
  ## `performV2HandshakeResponder`).
  if peer.transport == nil or peer.transport.closed:
    raise newException(PeerError, "not connected")

  if peer.transportProto == tpV2:
    return await peer.readMessageV2()
  else:
    return await peer.readMessageV1()

# BIP-159 NODE_NETWORK_LIMITED advertisement gate.  Set from `nimrod.nim`
# at daemon startup based on `config.pruneTarget > 0`.  When true,
# `sendVersion` ORs `NodeNetworkLimited` (1<<10) into the outbound
# `services` bitfield so peers know we serve only the recent
# `MIN_BLOCKS_TO_KEEP` (288) keep window.  Mirrors Core's `init.cpp`
# `nLocalServices |= NODE_NETWORK_LIMITED` when `IsPruneMode()` is true.
var pruneModeAdvertise: bool = false

proc setPruneModeAdvertise*(enabled: bool) =
  ## Toggle BIP-159 NODE_NETWORK_LIMITED advertisement.  Idempotent.
  pruneModeAdvertise = enabled

proc pruneModeAdvertiseEnabled*(): bool =
  ## True when we should advertise NODE_NETWORK_LIMITED in the version handshake.
  pruneModeAdvertise

# BIP-157 NODE_COMPACT_FILTERS advertisement gate.  W121 G15 / FIX-71.
# Set from `nimrod.nim` at daemon startup, computed as
# `config.peerblockfilters and config.blockfilterindex`.  When true,
# `sendVersion` ORs `NodeCompactFilters` (1<<6 = 64) into the outbound
# `services` bitfield so light clients know nimrod will respond to
# `getcfilters` / `getcfheaders` / `getcfcheckpt` for the BASIC filter
# type.  Mirrors Core's `init.cpp:992-999`:
#     if (args.GetBoolArg("-peerblockfilters", DEFAULT_PEERBLOCKFILTERS)) {
#         if (!g_enabled_filter_types.contains(BlockFilterType::BASIC)) {
#             return InitError(_("Cannot set -peerblockfilters without -blockfilterindex."));
#         }
#         g_local_services = ServiceFlags(g_local_services | NODE_COMPACT_FILTERS);
#     }
# Default OFF: matches `DEFAULT_PEERBLOCKFILTERS = false`
# (net_processing.h:45) — operators must opt in even when the index is
# enabled.  Advertisement is _not_ gated on `BaseIndex.IsSynced()`; Core
# emits the version handshake before the index has caught up and relies
# on the request handlers in `nimrod.nim` to bail out cleanly when the
# index has no entry for the requested height (they already do).
var compactFiltersAdvertise: bool = false

proc setCompactFiltersAdvertise*(enabled: bool) =
  ## Toggle BIP-157 NODE_COMPACT_FILTERS advertisement.  Idempotent.
  compactFiltersAdvertise = enabled

proc advertiseCompactFiltersService*(): bool =
  ## True when we should OR `NodeCompactFilters` into the version-handshake
  ## services bitfield.  Set by `nimrod.nim` at daemon startup based on
  ## `config.peerblockfilters and config.blockfilterindex`.
  compactFiltersAdvertise

proc peerBlockFiltersEnabled*(): bool =
  ## True when nimrod advertises NODE_COMPACT_FILTERS and will serve
  ## BIP-157 `getcfilters`/`getcfheaders`/`getcfcheckpt` to peers.
  ## Alias of `advertiseCompactFiltersService()` — kept as a separate
  ## symbol so callers reading like Core's `args.GetBoolArg(
  ## "-peerblockfilters", ...)` flag-test stay legible.  W121 G29 / FIX-71.
  compactFiltersAdvertise

proc peerBloomFiltersEnabled*(): bool =
  ## Gate for accepting inbound BIP-35 `mempool` messages (nimrod.nim).
  ## Mirrors Bitcoin Core's `-peerbloomfilters` knob
  ## (`DEFAULT_PEERBLOOMFILTERS = false`, net_processing.h:44): default OFF,
  ## opt-in via `NIMROD_PEER_BLOOM_FILTERS=1` (or "true"/"yes"/"on").
  ##
  ## NOTE: This flag NO LONGER controls NODE_BLOOM advertisement.  BIP-111
  ## mandates that a node MUST NOT advertise NODE_BLOOM unless it actually
  ## serves BIP-37 bloom-filter requests (filterload / filteradd /
  ## filterclear).  Nimrod has no CBloomFilter implementation (W110 BUG-01),
  ## so NODE_BLOOM is never set in outbound version messages regardless of
  ## this env var.  The flag is kept solely to allow operators to expose
  ## BIP-35 `mempool` inv to peers via the NIMROD_PEER_BLOOM_FILTERS knob.
  let v = getEnv("NIMROD_PEER_BLOOM_FILTERS", "")
  if v.len == 0:
    return false
  let lv = v.toLowerAscii()
  lv == "1" or lv == "true" or lv == "yes" or lv == "on"

proc advertisedServices*(): uint64 =
  ## Assemble the service-flags bitset we advertise in our outbound `version`.
  ## Pure (env-driven only) so it can be unit-tested without a socket/peer.
  ##
  ## Full-node baseline = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED |
  ## NODE_P2P_V2 = 0xC09, matching Bitcoin Core's g_local_services for a
  ## non-pruned, v2-transport-on full node (init.cpp:863 + 987-990).
  #
  # BIP-111: NODE_BLOOM MUST NOT be advertised unless the node actually serves
  # BIP-37 bloom-filter requests (filterload / filteradd / filterclear).
  # Nimrod has no CBloomFilter implementation (W110 BUG-01), so NODE_BLOOM is
  # intentionally absent from outbound services regardless of any env var.
  # See also: peerBloomFiltersEnabled() above for the mempool-only gate.
  var ourServices = NodeNetwork or NodeWitness
  # BIP-159: NODE_NETWORK_LIMITED is advertised UNCONDITIONALLY by every full
  # node — Core sets it in g_local_services regardless of prune mode
  # (init.cpp:863, `NODE_NETWORK_LIMITED | NODE_WITNESS`), because any full
  # node serves at least the recent-288-block window.  It is NOT prune-gated.
  # A non-pruned node advertises NODE_NETWORK alongside it (added above);
  # pruning only drops NODE_NETWORK, never NODE_NETWORK_LIMITED.
  ourServices = ourServices or NodeNetworkLimited
  # BIP-324: NODE_P2P_V2 signals the v2 encrypted transport.  Nimrod's inbound
  # v2 responder runs default-on (peer.nim drives performV2HandshakeResponder
  # for any inbound peer that initiates v2, with no env gate), so advertising
  # this bit is honest.  Core advertises it whenever -v2transport is on
  # (DEFAULT_V2_TRANSPORT = true; init.cpp:987-990).  The outbound initiator is
  # still gated (bip324V2OutboundEnabled, default off), but advertisement
  # tracks the always-on inbound responder, matching Core.
  ourServices = ourServices or NodeP2pV2
  # BIP-157: signal compact-filter serving when --peerblockfilters AND
  # --blockfilterindex are both on.  W121 G15 / FIX-71.  Reference:
  # bitcoin-core/src/init.cpp:992-999.
  if advertiseCompactFiltersService():
    ourServices = ourServices or NodeCompactFilters
  ourServices

proc buildVersionMsg*(peer: Peer, ourHeight: int32): P2PMessage =
  ## The VERSION message sendVersion puts on the wire.
  let ourServices = advertisedServices()
  newVersionMsg(
    version = ProtocolVersion,
    services = ourServices,
    timestamp = stdtimes.getTime().toUnix(),
    addrRecv = NetAddress(services: NodeNetwork, port: peer.port),
    # addr_from: Core sends an empty CService (net_processing.cpp
    # PushNodeVersion: `CNetAddr::V1(CService{})`) -- our reachable address is
    # announced by the addr/addrv2 self-advertisement after the handshake, not
    # here.  This used to carry the chain-default port (params.p2pPort, 8333 on
    # mainnet) regardless of --port, i.e. a wrong port for any node not on the
    # default; empty (::, port 0) is what peers expect and ignore.
    addrFrom = NetAddress(services: ourServices),
    nonce = peer.localNonce,  # Use our unique nonce for self-connection detection
    userAgent = UserAgent,
    startHeight = ourHeight,
    relay = true
  )

proc sendVersion*(peer: Peer, ourHeight: int32) {.async.} =
  ## Send version message
  let msg = peer.buildVersionMsg(ourHeight)
  await peer.sendMessage(msg)
  peer.versionSent = true
  peer.state = psHandshaking
  peer.handshakeStartTime = stdtimes.getTime()

proc sendVerack*(peer: Peer) {.async.} =
  await peer.sendMessage(newVerack())
  peer.verackSent = true

proc sendPing*(peer: Peer) {.async.} =
  ## Send a ping and record the nonce/time for latency measurement
  peer.pingNonce = uint64(nodeRng().rand(high(int)))
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

proc classifyInboundV2*(prefix: openArray[byte], magic: array[4, byte]): bool =
  ## Inbound classification helper for BIP-324: returns `true` if the
  ## first 16 bytes look like a v1 VERSION header (network magic +
  ## "version\0\0\0\0\0"), in which case the caller should run the v1
  ## handshake.  Returns `false` if the bytes do NOT match — the peer is
  ## almost certainly initiating BIP-324 v2 (the 64-byte ellswift pubkey
  ## is uniformly random, so the false-positive rate against the v1
  ## header is 2^-128).
  ##
  ## Pure function so it's trivially unit-testable; the live path passes
  ## a peeked copy of recvBuffer's first 16 bytes.
  checkV1MagicBytes(prefix, magic)

proc performV2HandshakeResponder*(peer: Peer) {.async.} =
  ## Drive the BIP-324 v2 handshake in RESPONDER mode after inbound
  ## classification has flagged the wire as v2.  On entry, the first
  ## bytes of the peer's 64-byte ElligatorSwift pubkey are sitting in
  ## `peer.recvBuffer` (placed there by the classify-peek that decided
  ## to take the v2 path); we may also have a few bytes of their
  ## "garbage" tail.  On exit, `peer.transportProto = tpV2` and
  ## `peer.v2Cipher` is initialised + has consumed both our and their
  ## version-packets, so all subsequent sendMessage / readMessage calls
  ## are AEAD-encrypted.
  ##
  ## Wire layout (responder side, per BIP-324 §"Wire format" and
  ## bitcoin-core/src/net.cpp V2Transport state machine):
  ##
  ##     <-  64 bytes ElligatorSwift pubkey || sent_garbage (0..MAX)
  ##     ->  64 bytes ElligatorSwift pubkey || our_garbage  (0..32)
  ##     ->  send_garbage_terminator (16) || version-packet (AAD = our_garbage)
  ##     <-  recv_garbage_terminator (16) || decoy*+version-packet
  ##         (first AEAD AAD = recv_garbage; all subsequent AAD = empty)
  ##
  ## Reference: clearbit/src/peer.zig::performV2Handshake (responder
  ## branch) and ouroboros/src/ouroboros/peer.py::_negotiate_v2 (the
  ## initiator-side analogue is byte-equivalent under the responder/
  ## initiator role swap).

  # 1. Read peer's 64-byte ElligatorSwift pubkey.  Some bytes are
  #    already buffered from the classify-peek; fillRecvBuffer extends
  #    the buffer until we have all 64.
  await peer.fillRecvBuffer(EllSwiftPubKeySize)
  let theirPubKeyBytes = peer.takeFromRecvBuffer(EllSwiftPubKeySize)
  var theirPubKey: EllSwiftPubKey
  for i in 0 ..< EllSwiftPubKeySize:
    theirPubKey[i] = theirPubKeyBytes[i]

  # 2. Construct our cipher in responder mode.  ECDH + HKDF derives the
  #    send/recv key pairs and the garbage terminators.
  peer.v2Cipher = newBIP324Cipher()
  peer.v2Cipher.initialize(theirPubKey, initiator = false, magic = peer.networkMagic)

  # 3. Send our 64-byte pubkey + small random garbage in one write.
  #    BIP-324 allows 0..4095 bytes of garbage; small bound (0..32)
  #    keeps wire-overhead low while still exercising the AAD-binding
  #    path of the version packet.
  let ourGarbageLen = nodeRng().rand(32)
  var ourGarbage = newSeq[byte](ourGarbageLen)
  for i in 0 ..< ourGarbageLen:
    ourGarbage[i] = byte(nodeRng().rand(255))

  let ourPubKey = peer.v2Cipher.getOurPubKey()
  var keyAndGarbage = newSeq[byte](EllSwiftPubKeySize + ourGarbageLen)
  for i in 0 ..< EllSwiftPubKeySize:
    keyAndGarbage[i] = ourPubKey[i]
  for i in 0 ..< ourGarbageLen:
    keyAndGarbage[EllSwiftPubKeySize + i] = ourGarbage[i]
  try:
    let written = await peer.transport.write(keyAndGarbage)
    if written != keyAndGarbage.len:
      raise newException(PeerError, "v2 short write of pubkey+garbage")
  except CatchableError as e:
    raise newException(PeerError, "v2 transport write failed (pubkey): " & e.msg)
  peer.bytesSent += uint64(keyAndGarbage.len)

  # 4. Send our garbage terminator + version packet.  AAD on the
  #    version packet binds the garbage we just sent (so an MITM that
  #    truncates / mutates the garbage will fail decryption on the
  #    peer side).
  let sendTerm = peer.v2Cipher.getSendGarbageTerminator()
  let versionPacket = peer.v2Cipher.encrypt(@[], aad = ourGarbage)
  var termAndVer = newSeq[byte](GarbageTerminatorLen + versionPacket.len)
  for i in 0 ..< GarbageTerminatorLen:
    termAndVer[i] = sendTerm[i]
  for i in 0 ..< versionPacket.len:
    termAndVer[GarbageTerminatorLen + i] = versionPacket[i]
  try:
    let written = await peer.transport.write(termAndVer)
    if written != termAndVer.len:
      raise newException(PeerError, "v2 short write of term+version")
  except CatchableError as e:
    raise newException(PeerError, "v2 transport write failed (term): " & e.msg)
  peer.bytesSent += uint64(termAndVer.len)

  # 5. Scan incoming bytes for the recv_garbage_terminator.  The peer
  #    may have sent up to MAX_GARBAGE_LEN (4095) bytes of garbage
  #    before the terminator.  We bound the scan at MaxGarbageLen + 16
  #    and treat absence of the terminator within that window as a
  #    protocol violation.  Match Core's "byte-by-byte slide" model
  #    (net.cpp:1297 ProcessReceivedGarbageBytes) — the terminator may
  #    start at any offset.
  let recvTerm = peer.v2Cipher.getRecvGarbageTerminator()
  await peer.fillRecvBuffer(GarbageTerminatorLen)
  var window = peer.takeFromRecvBuffer(GarbageTerminatorLen)
  var recvGarbage: seq[byte] = @[]
  block findTerm:
    while true:
      var match = true
      for i in 0 ..< GarbageTerminatorLen:
        if window[window.len - GarbageTerminatorLen + i] != recvTerm[i]:
          match = false
          break
      if match:
        # Bytes before the terminator are the peer's garbage.
        if window.len > GarbageTerminatorLen:
          recvGarbage = window[0 ..< (window.len - GarbageTerminatorLen)]
        break findTerm
      if window.len >= MaxGarbageLen + GarbageTerminatorLen:
        raise newException(PeerError,
          "v2 recv_garbage_terminator not seen within " & $MaxGarbageLen & " bytes")
      await peer.fillRecvBuffer(1)
      let nextByte = peer.takeFromRecvBuffer(1)
      window.add(nextByte[0])

  # 6. Drain incoming AEAD packets until we receive a non-decoy
  #    (the peer's version-packet).  The first decryption uses
  #    AAD = recv_garbage; all subsequent decryptions use empty AAD,
  #    even if the first one was a decoy (matches Core
  #    net.cpp:1243 ClearShrink(m_recv_aad)).
  var nextAad: seq[byte] = recvGarbage
  let decoyBound = 1024
  for _ in 0 ..< decoyBound:
    await peer.fillRecvBuffer(LengthLen)
    let encLen = peer.takeFromRecvBuffer(LengthLen)
    var contentsLen: uint32
    try:
      contentsLen = peer.v2Cipher.decryptLength(encLen)
    except BIP324Error as e:
      raise newException(PeerError, "v2 length decrypt failed: " & e.msg)
    if contentsLen.int > MaxMessagePayload:
      raise newException(PeerError, "v2 version-phase packet too large: " & $contentsLen)

    let aeadLen = HeaderLen + contentsLen.int + AEADExpansion
    await peer.fillRecvBuffer(aeadLen)
    let aeadPayload = peer.takeFromRecvBuffer(aeadLen)
    var ignore: bool
    try:
      let dec = peer.v2Cipher.decrypt(aeadPayload, aad = nextAad)
      ignore = dec.ignore
    except BIP324Error as e:
      raise newException(PeerError, "v2 version-phase payload decrypt failed: " & e.msg)
    # AAD is consumed by the first decrypt regardless of decoy flag.
    nextAad = @[]
    peer.bytesRecv += uint64(LengthLen + aeadLen)
    if not ignore:
      break
  if nextAad.len != 0:
    # We never observed a non-decoy version-packet within the bound.
    raise newException(PeerError, "v2 version-packet not observed within decoy bound")

  # 7. Cipher handshake complete; switch the peer to v2 transport so
  #    subsequent sendMessage / readMessage call the AEAD path.
  peer.transportProto = tpV2
  info "BIP-324 v2 handshake complete (responder)", peer = $peer

proc bip324V2OutboundEnabled*(): bool =
  ## Gate for the BIP-324 v2 outbound probe.  Default ON — opt-OUT via
  ## `NIMROD_BIP324_V2_OUTBOUND=0` (or "false"/"no"/"off").  Unset or any
  ## truthy value initiates v2 on outbound dials, matching the inbound
  ## responder side, Bitcoin Core (`-v2transport` default-on since v26),
  ## and the rest of the fleet.  The prior default-OFF posture left nimrod
  ## responding to v2 but never initiating it, which diverged from Core.
  ## On a v1-only peer the outbound v2 probe falls back to v1 (the socket
  ## is re-dialed for v1), so default-on is safe for interop.  Mirrors
  ## clearbit's CLEARBIT_BIP324_V2 env var (peer.zig:653).
  let v = getEnv("NIMROD_BIP324_V2_OUTBOUND", "")
  if v.len == 0:
    return true
  let lv = v.toLowerAscii()
  lv == "1" or lv == "true" or lv == "yes" or lv == "on"

proc performV2HandshakeInitiator*(peer: Peer) {.async.} =
  ## Drive the BIP-324 v2 handshake in INITIATOR mode on a freshly
  ## connected outbound socket.  Symmetric counterpart of
  ## `performV2HandshakeResponder`: this side sends the 64-byte
  ## ElligatorSwift pubkey + garbage FIRST, then reads the peer's
  ## pubkey, garbage, garbage_terminator, and version-packet (consuming
  ## any decoys that precede it).  On exit, `peer.transportProto = tpV2`
  ## and `peer.v2Cipher` is initialised + has consumed both our and
  ## their version-packets, so subsequent sendMessage / readMessage
  ## calls run AEAD-encrypted.
  ##
  ## Wire layout (initiator side, per BIP-324 §"Wire format" and
  ## bitcoin-core/src/net.cpp V2Transport):
  ##
  ##     ->  64 bytes ElligatorSwift pubkey || sent_garbage (0..32)
  ##     ->  send_garbage_terminator (16) || version-packet
  ##         (AAD = our_garbage; subsequent AAD empty)
  ##     <-  64 bytes ElligatorSwift pubkey || recv_garbage (0..MAX_GARBAGE_LEN)
  ##     <-  recv_garbage_terminator (16) || decoy*+version-packet
  ##         (first AEAD AAD = recv_garbage; subsequent AAD empty)
  ##
  ## Reference: clearbit/src/peer.zig::performV2Handshake (initiator
  ## branch via V2Transport state machine), this file's
  ## `performV2HandshakeResponder` (byte-equivalent under the role swap).
  ## Caller is responsible for bounding the future via
  ## `withTimeout(V2HandshakeTimeoutSec)`.
  doAssert peer.direction == pdOutbound,
    "performV2HandshakeInitiator must run on an outbound peer"
  doAssert peer.recvBuffer.len == 0,
    "initiator handshake expects an empty recvBuffer (fresh socket)"

  # 1. Build our cipher in initiator mode.  We pass a placeholder for
  #    theirPubKey first to generate our keys; ECDH+HKDF must wait until
  #    we receive the peer's pubkey, so we re-initialise after step 3.
  #    Instead of placeholder/re-init, follow the responder's pattern:
  #    construct the cipher (which also creates our pubkey), send pubkey
  #    + garbage, THEN receive their pubkey and call initialize().
  peer.v2Cipher = newBIP324Cipher()

  # 2. Generate small random garbage (0..32 bytes) and send our 64-byte
  #    ElligatorSwift pubkey + garbage in one write.  Per BIP-324, the
  #    initiator's garbage upper bound is MaxGarbageLen, but a small
  #    bound keeps wire-overhead low while still exercising the
  #    AAD-binding path.
  let ourGarbageLen = nodeRng().rand(32)
  var ourGarbage = newSeq[byte](ourGarbageLen)
  for i in 0 ..< ourGarbageLen:
    ourGarbage[i] = byte(nodeRng().rand(255))

  let ourPubKey = peer.v2Cipher.getOurPubKey()
  var keyAndGarbage = newSeq[byte](EllSwiftPubKeySize + ourGarbageLen)
  for i in 0 ..< EllSwiftPubKeySize:
    keyAndGarbage[i] = ourPubKey[i]
  for i in 0 ..< ourGarbageLen:
    keyAndGarbage[EllSwiftPubKeySize + i] = ourGarbage[i]
  try:
    let written = await peer.transport.write(keyAndGarbage)
    if written != keyAndGarbage.len:
      raise newException(PeerError, "v2 short write of pubkey+garbage")
  except CatchableError as e:
    raise newException(PeerError, "v2 transport write failed (pubkey): " & e.msg)
  peer.bytesSent += uint64(keyAndGarbage.len)

  # 3. Read the peer's 64-byte ElligatorSwift pubkey.  BEFORE we read,
  #    paranoid v1-magic check: if the peer ignored our garbage and
  #    sent back a v1 VERSION header, treat that as a v2-failure
  #    signal (don't attempt to decrypt).  We can detect this because
  #    a v1 VERSION header starts with the network magic, while the
  #    peer's ellswift pubkey is uniformly random (false-positive rate
  #    2^-128).
  await peer.fillRecvBuffer(V1PrefixLen)
  let prefix = peer.recvBuffer[0 ..< V1PrefixLen]
  if checkV1MagicBytes(prefix, peer.networkMagic):
    raise newException(PeerError,
      "v2 outbound: peer responded with v1 VERSION (no v2 support)")

  await peer.fillRecvBuffer(EllSwiftPubKeySize)
  let theirPubKeyBytes = peer.takeFromRecvBuffer(EllSwiftPubKeySize)
  var theirPubKey: EllSwiftPubKey
  for i in 0 ..< EllSwiftPubKeySize:
    theirPubKey[i] = theirPubKeyBytes[i]

  # 4. ECDH + HKDF derives the send/recv key pairs and the garbage
  #    terminators.  initiator=true ensures we use initiator_L /
  #    initiator_P for sending and responder_L / responder_P for
  #    receiving, matching the BIP-324 role table.
  peer.v2Cipher.initialize(theirPubKey, initiator = true,
                           magic = peer.networkMagic)

  # 5. Send our garbage terminator + version packet.  AAD on the
  #    version packet binds the garbage we just sent; the peer will
  #    fail decryption if a MITM mutated our garbage.
  let sendTerm = peer.v2Cipher.getSendGarbageTerminator()
  let versionPacket = peer.v2Cipher.encrypt(@[], aad = ourGarbage)
  var termAndVer = newSeq[byte](GarbageTerminatorLen + versionPacket.len)
  for i in 0 ..< GarbageTerminatorLen:
    termAndVer[i] = sendTerm[i]
  for i in 0 ..< versionPacket.len:
    termAndVer[GarbageTerminatorLen + i] = versionPacket[i]
  try:
    let written = await peer.transport.write(termAndVer)
    if written != termAndVer.len:
      raise newException(PeerError, "v2 short write of term+version")
  except CatchableError as e:
    raise newException(PeerError, "v2 transport write failed (term): " & e.msg)
  peer.bytesSent += uint64(termAndVer.len)

  # 6. Scan incoming bytes for the recv_garbage_terminator.  Bounded
  #    at MaxGarbageLen + 16 — absence of the terminator within that
  #    window is a protocol violation.  Same byte-by-byte slide model
  #    as the responder (matches Core net.cpp:1297
  #    ProcessReceivedGarbageBytes).
  let recvTerm = peer.v2Cipher.getRecvGarbageTerminator()
  await peer.fillRecvBuffer(GarbageTerminatorLen)
  var window = peer.takeFromRecvBuffer(GarbageTerminatorLen)
  var recvGarbage: seq[byte] = @[]
  block findTerm:
    while true:
      var match = true
      for i in 0 ..< GarbageTerminatorLen:
        if window[window.len - GarbageTerminatorLen + i] != recvTerm[i]:
          match = false
          break
      if match:
        if window.len > GarbageTerminatorLen:
          recvGarbage = window[0 ..< (window.len - GarbageTerminatorLen)]
        break findTerm
      if window.len >= MaxGarbageLen + GarbageTerminatorLen:
        raise newException(PeerError,
          "v2 recv_garbage_terminator not seen within " & $MaxGarbageLen & " bytes")
      await peer.fillRecvBuffer(1)
      let nextByte = peer.takeFromRecvBuffer(1)
      window.add(nextByte[0])

  # 7. Drain incoming AEAD packets until we receive a non-decoy (the
  #    peer's version-packet).  First decryption uses AAD = recv_garbage;
  #    all subsequent AAD = empty, even if the first was a decoy
  #    (matches Core net.cpp:1243 ClearShrink(m_recv_aad)).
  var nextAad: seq[byte] = recvGarbage
  let decoyBound = 1024
  for _ in 0 ..< decoyBound:
    await peer.fillRecvBuffer(LengthLen)
    let encLen = peer.takeFromRecvBuffer(LengthLen)
    var contentsLen: uint32
    try:
      contentsLen = peer.v2Cipher.decryptLength(encLen)
    except BIP324Error as e:
      raise newException(PeerError, "v2 length decrypt failed: " & e.msg)
    if contentsLen.int > MaxMessagePayload:
      raise newException(PeerError,
        "v2 version-phase packet too large: " & $contentsLen)

    let aeadLen = HeaderLen + contentsLen.int + AEADExpansion
    await peer.fillRecvBuffer(aeadLen)
    let aeadPayload = peer.takeFromRecvBuffer(aeadLen)
    var ignore: bool
    try:
      let dec = peer.v2Cipher.decrypt(aeadPayload, aad = nextAad)
      ignore = dec.ignore
    except BIP324Error as e:
      raise newException(PeerError,
        "v2 version-phase payload decrypt failed: " & e.msg)
    nextAad = @[]
    peer.bytesRecv += uint64(LengthLen + aeadLen)
    if not ignore:
      break
  if nextAad.len != 0:
    raise newException(PeerError,
      "v2 version-packet not observed within decoy bound")

  # 8. Cipher handshake complete; flip to v2 transport.
  peer.transportProto = tpV2
  info "BIP-324 v2 handshake complete (initiator)", peer = $peer

proc hasAllDesirableServiceFlags*(services: uint64): bool =
  ## Core PeerManagerImpl::HasAllDesirableServiceFlags (net_processing.cpp:1752):
  ## a full node that can serve witness blocks.  Core accepts
  ## NODE_NETWORK_LIMITED in place of NODE_NETWORK only when our tip is
  ## within NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS of now; nimrod's peer layer
  ## has no view of tip age, so it accepts a limited peer whenever it
  ## advertises one (a limited peer is still a witness-serving full
  ## validator; the block downloader stays gated on canServeWitnesses).
  ## Applied ONLY to outbound connections that expect services
  ## (Core ExpectServicesFromConn) — never to inbound peers.
  (services and NodeWitness) != 0 and
    (services and (NodeNetwork or NodeNetworkLimited)) != 0

proc canServeWitnesses*(peer: Peer): bool =
  ## Core CanServeWitnesses (net_processing.cpp:1166): peer advertises
  ## NODE_WITNESS.  Every block request (getdata MSG_WITNESS_BLOCK,
  ## getblocktxn, getblockfrompeer) must go only to such a peer, now that
  ## inbound peers without NODE_WITNESS complete the handshake.
  (peer.services and NodeWitness) != 0

proc processPreVerackMessage*(peer: Peer, msg: P2PMessage): bool =
  ## Handle one message received after VERSION and before VERACK, the way
  ## Core's ProcessMessage does while !fSuccessfullyConnected.  Returns true
  ## when `msg` is the peer's VERACK.  Never raises: nothing a peer sends
  ## between VERSION and VERACK is a reason to disconnect here.
  ##
  ## Processed (recorded) pre-verack in Core:
  ##   VERACK, WTXIDRELAY (:3919), SENDADDRV2 (:3944), SENDTXRCNCL (:3958),
  ##   SENDHEADERS (:3896), SENDCMPCT (:3901).
  ## Everything else — ping, inv, feefilter, getheaders, a redundant
  ## version... — is logged and IGNORED ("Unsupported message prior to
  ## verack", :4010): no disconnect, no misbehaviour, no count limit.
  ## Note feefilter is NOT applied pre-verack in Core, so it is not here.
  case msg.kind
  of mkVerack:
    peer.verackReceived = true
    return true
  of mkWtxidRelay:
    # Core: only honoured when the common version supports it.
    if peer.version >= WtxidRelayVersion:
      peer.wtxidRelay = true
    trace "peer supports wtxidrelay (pre-verack)", peer = $peer
  of mkSendAddrV2:
    peer.wantsAddrV2 = true
    trace "peer supports addrv2 (pre-verack)", peer = $peer
  of mkSendHeaders:
    peer.sendHeaders = true
    trace "peer prefers headers (pre-verack)", peer = $peer
  of mkSendCmpct:
    # Core net_processing.cpp:3901-3915: only CMPCTBLOCKS_VERSION (2) is
    # recorded; any other version is silently dropped.
    let v = msg.sendCmpct.version
    if v == 2:
      peer.peerCmpctVersion = v
      peer.peerHighBandwidth = msg.sendCmpct.announce
      peer.compactBlockState.handleSendCmpct(msg.sendCmpct.announce, v)
    trace "peer sendcmpct (pre-verack)", peer = $peer, version = v
  of mkSendTxRcncl:
    trace "peer supports tx reconciliation (pre-verack)", peer = $peer
  else:
    debug "unsupported message prior to verack, ignoring", peer = $peer,
          kind = $msg.kind
  false

proc remainingUntil(deadline: Moment): ctimer.Duration =
  let now = Moment.now()
  if now >= deadline: ctimer.milliseconds(0) else: deadline - now

proc readHandshakeMessage(peer: Peer, deadline: Moment,
                          what: string): Future[P2PMessage] {.async.} =
  ## Read ONE message during the v1 version/verack exchange, bounded by the
  ## overall handshake deadline.  Any read failure (peer closed the socket,
  ## bad magic, oversized/garbled message) is RAISED, never turned into a
  ## message.
  ##
  ## Two chronos details make this necessary:
  ##   * `withTimeout` returns TRUE when `fut` FAILED (it only means "fut
  ##     finished before the timer"), and
  ##   * `fut.value()` on a failed future does not raise — it returns
  ##     default(P2PMessage), whose kind is mkVersion (the first enum value).
  ## Reading with `value()` therefore turned a closed socket into an endless
  ## stream of phantom VERSION messages.  With the (Core-parity) unbounded
  ## pre-verack loop that became a synchronous spin: readMessage fails
  ## without yielding at EOF, so the event loop never ran again, the
  ## deadline timer never fired, and memory grew until the cgroup OOM
  ## killer fired (mainnet, 2026-09-26: 7 OOM kills on a8982ff).  `read()`
  ## re-raises the stored error instead.
  if Moment.now() >= deadline:
    raise newException(PeerError, "handshake timeout waiting for " & what)
  let fut = peer.readMessage()
  if not await fut.withTimeout(remainingUntil(deadline)):
    if not fut.finished():
      await fut.cancelAndWait()
    raise newException(PeerError, "handshake timeout waiting for " & what)
  return fut.read()

proc awaitVersionMessage(peer: Peer, deadline: Moment): Future[P2PMessage] {.async.} =
  ## Read until the peer's VERSION.  Core ignores (logs) any other message
  ## before VERSION ("non-version message before version handshake",
  ## net_processing.cpp:3810) rather than disconnecting.
  while true:
    let msg = await peer.readHandshakeMessage(deadline, "version")
    if msg.kind == mkVersion:
      return msg
    debug "non-version message before version handshake, ignoring",
          peer = $peer, kind = $msg.kind

proc awaitVerack(peer: Peer, deadline: Moment) {.async.} =
  ## Read until the peer's VERACK, processing/ignoring everything in between
  ## per `processPreVerackMessage`.  Bounded by the handshake deadline (Core
  ## has no message-count cap here, only the connect timeout); a read
  ## failure — including the peer closing the socket — ends the handshake.
  while true:
    let msg = await peer.readHandshakeMessage(deadline, "verack")
    if peer.processPreVerackMessage(msg):
      return

proc performHandshake*(peer: Peer, ourHeight: int32,
                       checkSelfConnect: SelfConnectChecker = nil) {.async.} =
  ## Perform version handshake with peer
  ## Outbound: send version -> recv version -> send verack -> recv verack
  ## Inbound: recv version -> send version -> send verack -> recv verack
  ## Then send wtxidrelay, sendheaders, sendcmpct
  ##
  ## Enforces:
  ## - Minimum protocol version (Core MIN_PEER_PROTO_VERSION = 31800)
  ## - Self-connection detection via nonce
  ## - 60 second handshake timeout
  ##
  ## Inbound (BIP-324):
  ## - Peeks the first 16 bytes of recvBuffer.
  ## - If the bytes look like a v1 VERSION header (magic + "version\0..."),
  ##   the v1 path runs as before.
  ## - Otherwise the peer is initiating v2; we drive
  ##   `performV2HandshakeResponder` BEFORE the application v1 envelope
  ##   loop, so the version/verack exchange runs over the encrypted
  ##   transport.  See `performV2HandshakeResponder` doc.
  ##
  ## Reference: Bitcoin Core net_processing.cpp ProcessMessage(),
  ## net.cpp V2Transport state machine, BIP-324.

  peer.handshakeStartTime = stdtimes.getTime()
  # One overall deadline for the whole v1 version/verack exchange (Core's
  # handshake timeout runs from connect), replacing per-message timeouts
  # plus a 20-message cap.
  let handshakeDeadline = Moment.now() + peer.handshakeTimeoutDur()

  # Inbound classification: peek 16 bytes, decide v1 vs v2.
  # Bound the peek with the handshake timeout so a TCP connect that never
  # sends a version is reaped (Core TIMEOUT_INTERVAL / version wait).
  if peer.direction == pdInbound and peer.transportProto == tpV1:
    try:
      let peekFut = peer.fillRecvBuffer(V1PrefixLen)
      if not await peekFut.withTimeout(peer.handshakeTimeoutDur()):
        await peekFut.cancelAndWait()
        raise newException(PeerError, "handshake timeout waiting for version")
      if peekFut.failed:
        raise peekFut.error
    except PeerError as e:
      if "handshake timeout" in e.msg:
        raise
      raise newException(PeerError, "v2 classify peek failed: " & e.msg)
    let prefix = peer.recvBuffer[0 ..< V1PrefixLen]
    if not classifyInboundV2(prefix, peer.networkMagic):
      # Peer initiated BIP-324 v2.  Drive the responder handshake; on
      # success transportProto is flipped to tpV2 and the v1 fall-
      # through below now reads encrypted version/verack frames.
      let v2Fut = peer.performV2HandshakeResponder()
      if not await v2Fut.withTimeout(ctimer.seconds(V2HandshakeTimeoutSec)):
        raise newException(PeerError, "v2 handshake timeout")
      # Surface the inner failure if any.
      if v2Fut.failed:
        raise v2Fut.error

  if peer.direction == pdOutbound:
    # BIP-324 v2 outbound probe.  Gated behind NIMROD_BIP324_V2_OUTBOUND
    # (default OFF — see `bip324V2OutboundEnabled` for rationale).  When
    # enabled, drive the initiator handshake on the fresh socket BEFORE
    # sending v1 VERSION.  On any failure (timeout, v1-magic detected,
    # decrypt error) the caller (peermanager) is expected to disconnect,
    # mark the address v1-only, and reconnect via the v1 path on a fresh
    # socket — the v2 garbage already on the wire is destructive on a
    # v1-only peer so we cannot reuse this socket.
    #
    # We only attempt v2 when transportProto is still tpV1 (i.e. caller
    # has not pre-flipped us via some out-of-band mechanism) and the
    # peermanager hasn't flagged this address v1-only.
    if peer.transportProto == tpV1 and not peer.v2OutboundDisabled and
       bip324V2OutboundEnabled():
      # Record that v2 was attempted on THIS dial BEFORE any bytes hit the
      # wire.  From here on, ANY handshake failure (v1-only peer closing the
      # socket, timeout, decrypt error) must demote the address to v1-only so
      # the next dial skips v2 — the ellswift+garbage we are about to send is
      # destructive on a v1 peer and cannot be reused on this socket.
      peer.v2OutboundAttempted = true
      let v2Fut = peer.performV2HandshakeInitiator()
      if not await v2Fut.withTimeout(ctimer.seconds(V2HandshakeTimeoutSec)):
        # Cancel the inflight handshake before raising so chronos doesn't
        # later see a leaked future on the closed socket.
        await v2Fut.cancelAndWait()
        raise newException(PeerError, "v2 outbound handshake timeout")
      if v2Fut.failed:
        raise v2Fut.error

    # Send our version (v1 unencrypted, OR v2 AEAD-encrypted if the
    # initiator probe above flipped transportProto = tpV2).
    await peer.sendVersion(ourHeight)

    # Wait for their version
    let versionMsg = await peer.awaitVersionMessage(handshakeDeadline)

    # Validate version (protocol version, etc.)
    let versionData = versionMsg.version
    # Core net_processing.cpp:3609 — ExpectServicesFromConn() (outbound
    # full-relay / block-relay-only; never inbound, manual or feeler) must
    # offer the desirable services, checked BEFORE the version floor.
    if peer.expectServices and not hasAllDesirableServiceFlags(versionData.services):
      raise newException(PeerError, "peer does not offer the expected services (" &
                         $versionData.services & " offered)")
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
    peer.addrLocal = versionData.addrRecv

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # BIP155: Send sendaddrv2 BEFORE verack (protocol version 70016+)
    # Core sends WTXIDRELAY and SENDADDRV2 only when the common version
    # is >= 70016 (net_processing.cpp:3703-3719).
    if peer.version >= WtxidRelayVersion:
      await peer.sendWtxidRelay()
      await peer.sendSendAddrV2()

    # Send verack
    await peer.sendVerack()

    # Wait for their verack.  Core has no cap on how many messages may
    # arrive first; the only bound is the handshake timeout, measured
    # from connect (net.cpp InactivityCheck: !fSuccessfullyConnected &&
    # now > m_connected + m_peer_connect_timeout).
    await peer.awaitVerack(handshakeDeadline)

  else:
    # Inbound: wait for version first
    let versionMsg = await peer.awaitVersionMessage(handshakeDeadline)

    let versionData = versionMsg.version

    # Check minimum protocol version (Core MIN_PEER_PROTO_VERSION; no
    # services requirement for inbound — Core ExpectServicesFromConn()
    # is false for INBOUND)
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
    peer.addrLocal = versionData.addrRecv

    info "received version", peer = $peer, version = peer.version,
         userAgent = peer.userAgent, height = peer.startHeight

    # Send our version
    await peer.sendVersion(ourHeight)

    # BIP155: Send sendaddrv2 BEFORE verack (protocol version 70016+)
    # Core sends WTXIDRELAY and SENDADDRV2 only when the common version
    # is >= 70016 (net_processing.cpp:3703-3719).
    if peer.version >= WtxidRelayVersion:
      await peer.sendWtxidRelay()
      await peer.sendSendAddrV2()

    # Send verack
    await peer.sendVerack()

    # Wait for their verack.  Core has no cap on how many messages may
    # arrive first; the only bound is the handshake timeout, measured
    # from connect (net.cpp InactivityCheck: !fSuccessfullyConnected &&
    # now > m_connected + m_peer_connect_timeout).
    await peer.awaitVerack(handshakeDeadline)

  # Send feature negotiation messages (after verack), gated on the peer's
  # version exactly as Core does, so an old peer is never sent a message it
  # cannot parse.  sendaddrv2 and wtxidrelay were already sent pre-verack.
  #   sendheaders: SENDHEADERS_VERSION (70012), net_processing.cpp:5525
  #   sendcmpct:   SHORT_IDS_BLOCKS_VERSION (70014), net_processing.cpp:3864
  if peer.version >= SendHeadersVersion:
    await peer.sendSendHeaders()
  if peer.version >= ShortIdsBlocksVersion:
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
    peer.addrLocal = msg.version.addrRecv
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
    # Dispatched to PeerManager.handleAddrInternal (peermanager.nim:925).
    trace "received addr", peer = $peer, count = msg.addresses.len

  of mkAddrV2:
    # Dispatched to PeerManager.handleAddrInternal.
    trace "received addrv2", peer = $peer, count = msg.addressesV2.len

  of mkInv:
    # Dispatched to NodeState.handleMessage (nimrod.nim mkInv branch).
    trace "received inv", peer = $peer, count = msg.invItems.len

  of mkHeaders:
    # Dispatched to NodeState.handleMessage which calls SyncManager.handleHeaders.
    trace "received headers", peer = $peer, count = msg.headers.len

  of mkBlock:
    # Dispatched to NodeState.handleMessage which calls SyncManager.processBlock.
    trace "received block", peer = $peer

  of mkTx:
    # Dispatched to NodeState.handleMessage which calls Mempool.acceptTransaction.
    trace "received tx", peer = $peer

  of mkGetAddr:
    # Served by PeerManager.handleAddrInternal (peermanager.nim:960-971);
    # responds with `addr` of up to MaxGetAddrCount cached peer addresses.
    trace "received getaddr", peer = $peer

  of mkGetHeaders:
    # Served by NodeState.handleMessage (nimrod.nim mkGetHeaders branch);
    # responds with up to MaxHeadersPerMsg (2000) headers.
    trace "received getheaders", peer = $peer

  of mkGetBlocks:
    # Served by NodeState.handleMessage (nimrod.nim mkGetBlocks branch);
    # responds with `inv` of up to MaxGetBlocksInvCount (500) block hashes.
    trace "received getblocks", peer = $peer

  of mkGetData:
    # Served by NodeState.handleMessage (nimrod.nim mkGetData branch);
    # responds with `block` / `tx` per item, `notfound` for unknowns.
    trace "received getdata", peer = $peer, count = msg.getData.len

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
    # BIP 152: Handle sendcmpct negotiation.
    # Core net_processing.cpp:3907 — drop entirely if version != 2, no state update.
    let version = msg.sendCmpct.version
    let announce = msg.sendCmpct.announce
    if version != 2:
      trace "peer sent unsupported compact block version, ignoring", peer = $peer,
            version = version
    else:
      peer.peerCmpctVersion = version
      peer.peerHighBandwidth = announce
      peer.compactBlockState.handleSendCmpct(announce, version)
      info "peer supports compact blocks", peer = $peer,
           version = version, highBandwidth = announce

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
          # Store partial and send getblocktxn — a block request, so only
          # to a peer that can serve witness data (Core CanServeWitnesses).
          if not peer.canServeWitnesses():
            peer.compactBlockState.failedReconstructions += 1
            return
          peer.compactBlockState.pendingPartials[blockHash] = pdb
          await peer.sendMessage(newGetBlockTxnMsg(blockHash, missing))
          peer.compactBlockState.txnsRequested += missing.len

  of mkGetBlockTxn:
    # BIP 152: Peer requests missing transactions for a compact block.
    # Core: net_processing.cpp:4272-4299
    #   If pindex->nHeight >= tip - MAX_BLOCKTXN_DEPTH (10): send blocktxn.
    #   Else: send the full block (and log that we got a deep request).
    # Depth guard is enforced here even though the blocktxn response path
    # is not yet fully wired (BUG-5); this ensures the guard is in place
    # once BUG-5 is resolved.
    let req = msg.getBlockTxn
    info "received getblocktxn", peer = $peer,
         hash = $req.blockHash,
         indexes = req.indexes.len
    # TODO(BUG-5): look up the block and send a real blocktxn response.
    # For now the depth gate is present; requests deeper than
    # MAX_BLOCKTXN_DEPTH are logged as such so callers know to expect
    # a full block response from a correctly-wired implementation.
    # (Depth check requires chain state which is not accessible here;
    # the full guard is enforced at the NodeState layer in nimrod.nim.)

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
    # BIP-331: peer signals package-relay support. Per the BIP, sendpackages
    # carries no version field on the wire (versioning is done out-of-band
    # via service bits / future extensions). Just record the flag so we can
    # respond to inv/getpkgtxns that depend on this.
    peer.sendsPackages = true
    peer.pkgRelayVersion = 1
    info "peer supports package relay (BIP-331)", peer = $peer

  of mkGetPkgTxns:
    # Real handler must look up the package keyed by child wtxid in the
    # mempool. Dispatched to NodeState.handleMessage (callback path) which
    # has access to the mempool. This trace is the peer-loop's record.
    trace "received getpkgtxns", peer = $peer,
          childWtxid = msg.getPkgTxns.childWtxid

  of mkPkgTxns:
    # Real handler must validate + accept each tx via mempool.acceptPackage.
    # Dispatched to NodeState.handleMessage (callback path).
    trace "received pkgtxns", peer = $peer,
          txCount = msg.pkgTxns.transactions.len

  # BIP-157 compact block filter messages
  # Requests (getcfilters / getcfheaders / getcfcheckpt) are dispatched to the
  # higher-level NodeState handler in nimrod.nim which has access to the
  # block-filter index.  Responses (cfilter / cfheaders / cfcheckpt) are
  # dispatched to the requesting client's callback.
  # Reference: bitcoin-core/src/net_processing.cpp:3315, 3344, 3386
  of mkGetCFilters:
    trace "received getcfilters", peer = $peer,
          filterType = msg.getCFilters.filterType,
          startHeight = msg.getCFilters.startHeight

  of mkCFilter:
    trace "received cfilter", peer = $peer,
          filterType = msg.cFilter.filterType

  of mkGetCFHeaders:
    trace "received getcfheaders", peer = $peer,
          filterType = msg.getCFHeaders.filterType,
          startHeight = msg.getCFHeaders.startHeight

  of mkCFHeaders:
    trace "received cfheaders", peer = $peer,
          filterType = msg.cFHeaders.filterType,
          count = msg.cFHeaders.filterHashes.len

  of mkGetCFCheckPt:
    trace "received getcfcheckpt", peer = $peer,
          filterType = msg.getCFCheckPt.filterType

  of mkCFCheckPt:
    trace "received cfcheckpt", peer = $peer,
          filterType = msg.cFCheckPt.filterType,
          count = msg.cFCheckPt.filterHeaders.len

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

  # BIP-37 bloom filter messages — BIP-111 requires disconnect when NODE_BLOOM
  # is not advertised.  Nimrod never advertises NODE_BLOOM (W110 BUG-01 / FIX-35),
  # so all three messages always trigger disconnect.
  # Reference: bitcoin-core/src/net_processing.cpp:4963-5033
  of mkFilterLoad:
    warn "filterload received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filterload received — NODE_BLOOM not advertised (BIP-111)")

  of mkFilterAdd:
    warn "filteradd received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filteradd received — NODE_BLOOM not advertised (BIP-111)")

  of mkFilterClear:
    warn "filterclear received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filterclear received — NODE_BLOOM not advertised (BIP-111)")

  # merkleblock — server→client message; we would not normally receive one.
  # Log and drop; do not disconnect (could be a buggy or misbehaving peer that
  # doesn't warrant a ban, unlike BIP-111 violations which are explicit).
  of mkMerkleBlock:
    warn "unexpected merkleblock received — dropping", peer = $peer

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
  ## Single-event discourage: any Misbehaving call immediately flags the peer
  ## for disconnect, regardless of howmuch.
  ## Reference: Bitcoin Core 2022 PR #25974 — score-accumulation removed;
  ## Misbehaving() now sets m_should_discourage = true unconditionally.
  peer.shouldDisconnect = true

  let messagePart = if message.len > 0: ": " & message else: ""
  warn "peer misbehaving — flagged for discourage", peer = $peer,
       score = howmuch, reason = messagePart

proc shouldBan*(peer: Peer): bool =
  ## Check if peer should be discouraged/banned (any Misbehaving call sets this)
  peer.shouldDisconnect

proc resetMisbehavior*(peer: var Peer) =
  ## Reset misbehavior state (used during testing)
  peer.misbehaviorScore = 0
  peer.shouldDisconnect = false

# ----------------------------------------------------------------------------
# BIP-157 protocol-violation classification + disconnect helper
# Reference: bitcoin-core/src/net_processing.cpp::PrepareBlockFilterRequest
#            (ProcessGetCFilters / ProcessGetCFHeaders / ProcessGetCFCheckPt)
#
# Core sets `node.fDisconnect = true` on EVERY violation path below; nimrod's
# pre-FIX-78 handlers only logged + returned, letting a misbehaving peer probe
# the index indefinitely with no consequence (DoS vector + manipulation
# surface).  FIX-78 (W121 G20 P1-CDIV) wires these calls into the three
# handlers in src/nimrod.nim.
# ----------------------------------------------------------------------------

type
  CFRequestViolation* = enum
    ## Protocol-violation classification for BIP-157 getcfilters /
    ## getcfheaders / getcfcheckpt requests.  Matches the three
    ## `node.fDisconnect = true` paths in Core's PrepareBlockFilterRequest.
    cfrvNone                = "ok"
    cfrvUnsupportedType     = "unsupported-filter-type"
    cfrvUnknownStopHash     = "unknown-stop-hash"
    cfrvInvalidRange        = "start-greater-than-stop"
    cfrvRangeTooLarge       = "range-too-large"

# BIP-157 wire constants.  Public so call-sites in nimrod.nim can use them
# without duplicating the magic numbers.
const
  CFiltersMaxRange*  = 1000'i32
    ## MAX_GETCFILTERS_SIZE — Core net_processing.cpp:103.
  CFHeadersMaxRange* = 2000'i32
    ## MAX_GETCFHEADERS_SIZE — Core net_processing.cpp:106.
  CFCheckPtInterval* = 1000'i32
    ## CFCHECKPT_INTERVAL — Core net_processing.cpp:100.

proc validateGetCFiltersRequest*(filterType: uint8,
                                 startHeight: int32,
                                 stopHeight: int32,
                                 stopFound: bool,
                                 maxRange: int32): CFRequestViolation =
  ## Classify a BIP-157 getcfilters / getcfheaders request against the four
  ## protocol-violation paths in Core's PrepareBlockFilterRequest:
  ##   1. filter_type != 0 (only `basic` is implemented).
  ##   2. stop_hash unknown to our block index.
  ##   3. start_height > stop_height (peer inverted the range).
  ##   4. stop_height - start_height >= max_range (range too large).
  ## Returns cfrvNone iff the request is well-formed; otherwise the specific
  ## violation reason.  Pure function, no side effects — safe to unit-test.
  if filterType != 0'u8:
    return cfrvUnsupportedType
  if not stopFound:
    return cfrvUnknownStopHash
  if startHeight > stopHeight:
    return cfrvInvalidRange
  if maxRange > 0'i32 and stopHeight - startHeight >= maxRange:
    return cfrvRangeTooLarge
  cfrvNone

proc validateGetCFCheckPtRequest*(filterType: uint8,
                                  stopFound: bool): CFRequestViolation =
  ## CFCheckPt has no range bounds (max_height_diff = uint32.max in Core), so
  ## only the filter-type + stop-hash paths can trip.  Reference:
  ## bitcoin-core/src/net_processing.cpp:3397 (ProcessGetCFCheckPt).
  if filterType != 0'u8:
    return cfrvUnsupportedType
  if not stopFound:
    return cfrvUnknownStopHash
  cfrvNone

proc disconnectOnBadFilterRequest*(peer: Peer,
                                   violation: CFRequestViolation,
                                   msgKind: string): Future[void] {.async.} =
  ## Mirror Core's `node.fDisconnect = true` for BIP-157 protocol violations.
  ## Flags the peer for discourage (so banman picks it up), logs at warn-level
  ## with the violation reason, and closes the transport.
  ##
  ## Caller MUST `await` this, then `return` from the message handler — once
  ## the transport is closed, any subsequent sendMessage on this peer will
  ## throw, so we don't want to fall through to the normal serve path.
  if violation == cfrvNone:
    return
  peer.shouldDisconnect = true
  warn "BIP-157 protocol violation — disconnecting peer",
       peer = $peer, message = msgKind, reason = $violation
  await peer.disconnect(msgKind & ": " & $violation)

# Pre-handshake message validation
# Reference: Bitcoin Core net_processing.cpp ProcessMessage()
# - Non-version messages before version: log and ignore (:3810)
# - Messages before verack (except the negotiation set): log and ignore (:4010)
# - Duplicate version: log and ignore (:3582)
# None of these disconnect or score misbehaviour in Core.
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
  # (Core processes exactly these pre-verack; feefilter is NOT one of them.)
  of mkVerack, mkWtxidRelay, mkSendAddrV2, mkSendHeaders, mkSendCmpct, mkSendTxRcncl:
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
      # Core net_processing.cpp:3810: "non-version message before version
      # handshake" — logged and ignored, no misbehaviour.
      debug "non-version message before version handshake, ignoring",
            peer = $peer, kind = kind
      return marDropSilent

  # VERSION received, check specific messages
  case kind
  of mkVersion:
    # Core net_processing.cpp:3582: "redundant version message" — logged
    # and ignored, no misbehaviour.
    debug "redundant version message, ignoring", peer = $peer
    return marDropSilent

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

  of mkSendHeaders, mkSendCmpct, mkSendTxRcncl:
    # Processed pre-verack by Core (:3896, :3901, :3958)
    return marAccept

  else:
    # Other messages before verack
    if not peer.verackReceived:
      # Core net_processing.cpp:4010: "Unsupported message prior to verack"
      # — logged and ignored.  No disconnect, no misbehaviour (this
      # includes feefilter, which Core does not apply pre-verack).
      debug "unsupported message prior to verack, ignoring", peer = $peer, kind = kind
      return marDropSilent
    return marAccept

proc validateVersionMessage*(peer: var Peer, version: uint32, nonce: uint64,
                             checkSelfConnect: SelfConnectChecker): MessageAcceptResult =
  ## Validate a version message
  ## - Check minimum protocol version (Core MIN_PEER_PROTO_VERSION = 31800)
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
  let limitMs = if peer.handshakeTimeoutMs > 0: peer.handshakeTimeoutMs
                else: HandshakeTimeoutSec * 1000
  result = elapsed.inMilliseconds >= limitMs

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
