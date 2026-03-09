## Peer connection management
## Handles peer discovery, DNS resolution, connection limits, banning, and message routing
## 8 outbound + 117 inbound connections, 24h ban duration

import std/[tables, sets, sequtils, random, times, net, strutils, algorithm]
import chronos
import chronicles
import ./peer
import ./messages
import ../consensus/params
import ../primitives/[types, serialize]
import ../crypto/hashing

const
  BanDuration* = initDuration(hours = 24)
  ReconnectInterval* = 30  # seconds
  PingInterval* = 120      # seconds
  GetAddrInterval* = 300   # seconds
  DefaultMaxOutbound* = 8
  DefaultMaxInbound* = 117

type
  PeerCallback* = proc(peer: Peer, msg: P2PMessage): Future[void] {.async.}

  InFlightBlock* = object
    hash*: BlockHash
    peer*: Peer
    requestTime*: Time

  PeerManager* = ref object
    peers*: Table[string, Peer]
    maxOutbound*: int
    maxInbound*: int
    networkMagic*: array[4, byte]
    params*: ConsensusParams
    localVersion*: VersionMsg
    knownAddresses*: seq[NetAddress]
    bannedPeers*: Table[string, Time]
    listener*: StreamServer
    onMessage*: PeerCallback
    ourHeight*: int32
    seedNodes*: seq[tuple[host: string, port: uint16]]
    fallbackPeers*: seq[tuple[host: string, port: uint16]]
    inFlightBlocks*: Table[BlockHash, InFlightBlock]
    running*: bool

proc peerKey(host: string, port: uint16): string =
  host & ":" & $port

proc peerKey(peer: Peer): string =
  peerKey(peer.address, peer.port)

proc newPeerManager*(params: ConsensusParams, maxOut: int = DefaultMaxOutbound,
                     maxIn: int = DefaultMaxInbound): PeerManager =
  result = PeerManager(
    params: params,
    peers: initTable[string, Peer](),
    maxOutbound: maxOut,
    maxInbound: maxIn,
    networkMagic: params.magic,
    knownAddresses: @[],
    bannedPeers: initTable[string, Time](),
    seedNodes: @[],
    fallbackPeers: @[],
    ourHeight: 0,
    inFlightBlocks: initTable[BlockHash, InFlightBlock](),
    running: false
  )

  # Set up local version message
  result.localVersion = VersionMsg(
    version: ProtocolVersion,
    services: NodeNetwork or NodeWitness,
    timestamp: getTime().toUnix(),
    addrRecv: NetAddress(services: NodeNetwork, port: params.defaultPort),
    addrFrom: NetAddress(services: NodeNetwork or NodeWitness, port: params.defaultPort),
    nonce: uint64(rand(high(int))),
    userAgent: UserAgent,
    startHeight: 0,
    relay: true
  )

  # Network-specific seeds and fallbacks
  case params.network
  of Mainnet:
    result.seedNodes = @[
      ("seed.bitcoin.sipa.be", 8333'u16),
      ("dnsseed.bluematt.me", 8333'u16),
      ("dnsseed.bitcoin.dashjr.org", 8333'u16),
      ("seed.bitcoinstats.com", 8333'u16),
      ("seed.bitcoin.jonasschnelli.ch", 8333'u16),
      ("seed.btc.petertodd.net", 8333'u16)
    ]
  of Testnet3:
    result.seedNodes = @[
      ("testnet-seed.bitcoin.jonasschnelli.ch", 18333'u16),
      ("seed.tbtc.petertodd.net", 18333'u16),
      ("testnet-seed.bluematt.me", 18333'u16)
    ]
    # Fallback peers for testnet (DNS can be unreliable)
    result.fallbackPeers = @[
      ("18.27.79.17", 18333'u16),
      ("85.10.199.56", 18333'u16),
      ("91.203.5.166", 18333'u16)
    ]
  of Regtest:
    # Regtest: no DNS seeds, use localhost or explicit peers
    result.fallbackPeers = @[
      ("127.0.0.1", 18444'u16)
    ]

proc connectedPeerCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result += 1

proc outboundCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.direction == pdOutbound and peer.state == psReady:
      result += 1

proc inboundCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.direction == pdInbound and peer.state == psReady:
      result += 1

proc isBanned*(pm: PeerManager, address: string): bool =
  if address notin pm.bannedPeers:
    return false
  let banTime = pm.bannedPeers[address]
  if getTime() > banTime + BanDuration:
    pm.bannedPeers.del(address)
    return false
  true

proc banPeer*(pm: PeerManager, address: string, duration: Duration = BanDuration) =
  ## Ban a peer for the specified duration (default 24h)
  pm.bannedPeers[address] = getTime()
  info "peer banned", address = address, duration = $duration

  # Disconnect if currently connected
  var toRemove: seq[string]
  for key, peer in pm.peers:
    if peer.address == address:
      toRemove.add(key)

  for key in toRemove:
    let peer = pm.peers[key]
    asyncSpawn peer.disconnect("banned")
    pm.peers.del(key)

proc unbanPeer*(pm: PeerManager, address: string) =
  ## Remove ban on a peer
  pm.bannedPeers.del(address)
  info "peer unbanned", address = address

proc cleanupBans(pm: PeerManager) =
  ## Remove expired bans
  var expired: seq[string]
  let now = getTime()
  for address, banTime in pm.bannedPeers:
    if now > banTime + BanDuration:
      expired.add(address)
  for address in expired:
    pm.bannedPeers.del(address)

proc resolveDnsSeeds*(pm: PeerManager): Future[seq[string]] {.async.} =
  ## Resolve DNS seed nodes to IP addresses
  ## Shuffles results for randomization
  var addresses: seq[string]

  for (host, port) in pm.seedNodes:
    try:
      # Use getAddrInfo for DNS resolution
      let resolvedAddrs = resolveTAddress(host, Port(port))
      for ta in resolvedAddrs:
        addresses.add($ta.address)
    except CatchableError as e:
      debug "DNS resolution failed", host = host, error = e.msg

  # Shuffle results
  if addresses.len > 0:
    randomize()
    shuffle(addresses)

  # Add fallback peers if DNS fails or returns few results
  if addresses.len < pm.maxOutbound:
    for (host, port) in pm.fallbackPeers:
      if host notin addresses:
        addresses.add(host)

  return addresses

proc connectToPeer*(pm: PeerManager, address: string, port: uint16): Future[bool] {.async.} =
  ## Connect to a peer at the given address
  let key = peerKey(address, port)

  # Check ban status
  if pm.isBanned(address):
    debug "peer is banned", address = address
    return false

  # Check if already connected
  if key in pm.peers:
    return false

  # Check connection limits
  if pm.outboundCount >= pm.maxOutbound:
    return false

  let peer = newPeer(address, port, pm.params, pdOutbound)
  pm.peers[key] = peer

  if await peer.connect():
    try:
      await peer.performHandshake(pm.ourHeight)
      info "connected to peer", peer = $peer, height = peer.startHeight
      return true
    except CatchableError as e:
      error "handshake failed", peer = $peer, error = e.msg
      await peer.disconnect()
      pm.peers.del(key)
      return false
  else:
    pm.peers.del(key)
    return false

proc removePeer*(pm: PeerManager, peer: Peer) {.async.} =
  let key = peerKey(peer)
  if key in pm.peers:
    await peer.disconnect()
    pm.peers.del(key)

    # Re-queue any in-flight blocks from this peer
    var toRequeue: seq[BlockHash]
    for hash, inflight in pm.inFlightBlocks:
      if inflight.peer == peer:
        toRequeue.add(hash)

    for hash in toRequeue:
      pm.inFlightBlocks.del(hash)
      debug "re-queued in-flight block on peer disconnect", hash = $hash

proc startOutboundConnections*(pm: PeerManager) {.async.} =
  ## Discover peers and establish outbound connections
  info "starting outbound connections", maxOutbound = pm.maxOutbound

  # Resolve DNS seeds
  let addresses = await pm.resolveDnsSeeds()
  info "resolved addresses", count = addresses.len

  # Connect to peers
  for address in addresses:
    if pm.outboundCount >= pm.maxOutbound:
      break

    let port = pm.params.defaultPort
    discard await pm.connectToPeer(address, port)

    # Small delay between connection attempts
    await sleepAsync(100.milliseconds)

proc handleInboundConnection(pm: PeerManager, transp: StreamTransport) {.async.} =
  ## Handle a new inbound connection
  let remoteAddr = transp.remoteAddress()
  let address = $remoteAddr.address
  let port = uint16(remoteAddr.port)
  let key = peerKey(address, port)

  # Check ban status
  if pm.isBanned(address):
    debug "rejecting banned inbound connection", address = address
    await transp.closeWait()
    return

  # Check connection limits
  if pm.inboundCount >= pm.maxInbound:
    debug "rejecting inbound connection (limit reached)", address = address
    await transp.closeWait()
    return

  # Check if already connected
  if key in pm.peers:
    debug "rejecting duplicate connection", address = address
    await transp.closeWait()
    return

  let peer = newPeer(address, port, pm.params, pdInbound)
  peer.transport = transp
  peer.state = psConnected
  pm.peers[key] = peer

  info "accepted inbound connection", peer = $peer

  try:
    await peer.performHandshake(pm.ourHeight)
    info "inbound handshake complete", peer = $peer, height = peer.startHeight

    # Start message loop for this peer
    if pm.onMessage != nil:
      asyncSpawn peer.messageLoop(pm.onMessage)
    else:
      asyncSpawn peer.messageLoop(nil)
  except CatchableError as e:
    error "inbound handshake failed", peer = $peer, error = e.msg
    await peer.disconnect()
    pm.peers.del(key)

proc inboundConnectionCallback(server: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
  ## Callback for StreamServer when a new connection arrives
  let pm = cast[PeerManager](server.udata)
  try:
    await pm.handleInboundConnection(transp)
  except CatchableError as e:
    error "error handling inbound connection", error = e.msg
    try:
      await transp.closeWait()
    except CatchableError:
      discard

proc startListener*(pm: PeerManager, bindAddr: string, port: uint16) {.async.} =
  ## Start listening for inbound connections
  let ta = initTAddress(bindAddr, Port(port))

  pm.listener = createStreamServer(
    ta,
    inboundConnectionCallback,
    {},  # flags
    udata = cast[pointer](pm)
  )
  pm.listener.start()
  info "listening for connections", address = bindAddr, port = port

proc stopListener*(pm: PeerManager) =
  ## Stop the listener
  if pm.listener != nil:
    pm.listener.stop()
    pm.listener.close()
    pm.listener = nil

proc getReadyPeers*(pm: PeerManager): seq[Peer] =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result.add(peer)

proc getBestPeer*(pm: PeerManager): Peer =
  ## Get peer with highest reported height
  var best: Peer = nil
  var bestHeight: int32 = -1

  for peer in pm.peers.values:
    if peer.state == psReady and peer.startHeight > bestHeight:
      best = peer
      bestHeight = peer.startHeight

  best

proc broadcastTx*(pm: PeerManager, tx: Transaction) {.async.} =
  ## Broadcast a transaction to all ready peers via inv
  let txBytes = serialize(tx)
  let txHash = doubleSha256(txBytes)

  let inv = @[InvVector(invType: invWitnessTx, hash: txHash)]
  let msg = newInv(inv)

  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast tx inv", peer = $peer, error = e.msg

proc broadcastBlock*(pm: PeerManager, blk: Block) {.async.} =
  ## Broadcast a block to all ready peers via inv
  let headerBytes = serialize(blk.header)
  let blockHash = doubleSha256(headerBytes)

  let inv = @[InvVector(invType: invBlock, hash: blockHash)]
  let msg = newInv(inv)

  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast block inv", peer = $peer, error = e.msg

proc broadcastInventory*(pm: PeerManager, inventory: seq[InvVector]) {.async.} =
  ## Broadcast inventory to all ready peers
  let msg = newInv(inventory)
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast inv", peer = $peer, error = e.msg

proc buildBlockLocator*(pm: PeerManager, tip: BlockHash): seq[array[32, byte]] =
  ## Build block locator with exponential backoff
  ## Returns: 10 single steps, then 2, 4, 8, 16... gaps, ending with genesis
  ##
  ## This requires access to the chainstate to walk back from tip.
  ## For now, we return just the tip and genesis as a minimal locator.
  ## The full implementation needs integration with ChainState.

  result = @[]

  # Add the tip
  result.add(array[32, byte](tip))

  # Always include genesis
  let genesisHash = array[32, byte](pm.params.genesisBlockHash)
  if result[^1] != genesisHash:
    result.add(genesisHash)

proc buildBlockLocatorFromChain*(heights: proc(h: int32): Option[BlockHash],
                                  tipHeight: int32,
                                  genesisHash: BlockHash): seq[array[32, byte]] =
  ## Build block locator with exponential backoff from a height->hash function
  ## 10 single steps, then exponentially increasing gaps, always ending with genesis
  result = @[]
  var step = 1
  var height = tipHeight

  while height >= 0:
    let hashOpt = heights(height)
    if hashOpt.isSome:
      result.add(array[32, byte](hashOpt.get()))

    # After 10 hashes, start exponential backoff
    if result.len > 10:
      step *= 2

    height -= step

  # Always include genesis if not already present
  let genesisArr = array[32, byte](genesisHash)
  if result.len == 0 or result[^1] != genesisArr:
    result.add(genesisArr)

proc maintainConnections(pm: PeerManager) {.async.} =
  ## Periodic connection maintenance
  ## Remove stale peers, reconnect if needed

  # Remove disconnected peers
  var toRemove: seq[string]
  for key, peer in pm.peers:
    if peer.state == psDisconnected:
      toRemove.add(key)

  for key in toRemove:
    pm.peers.del(key)

  # Cleanup expired bans
  pm.cleanupBans()

  # Try to maintain minimum outbound connections
  if pm.outboundCount < pm.maxOutbound div 2:
    info "reconnecting to maintain peer count", current = pm.outboundCount, target = pm.maxOutbound
    await pm.startOutboundConnections()

proc pingPeers(pm: PeerManager) {.async.} =
  ## Send ping to all ready peers
  for peer in pm.getReadyPeers():
    try:
      await peer.sendPing()
    except CatchableError as e:
      debug "failed to ping peer", peer = $peer, error = e.msg

proc requestAddresses(pm: PeerManager) {.async.} =
  ## Request addresses from peers
  let msg = newGetAddr()
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to request addresses", peer = $peer, error = e.msg

proc mainLoop*(pm: PeerManager) {.async.} =
  ## Main peer manager loop
  ## 30s: reconnect check
  ## 120s: ping all peers
  ## 300s: request addresses
  pm.running = true

  var lastReconnect = getTime()
  var lastPing = getTime()
  var lastGetAddr = getTime()

  info "peer manager main loop started"

  while pm.running:
    let now = getTime()

    # 30s: check connections and reconnect
    if (now - lastReconnect).inSeconds >= ReconnectInterval:
      await pm.maintainConnections()
      lastReconnect = now

    # 120s: ping all peers
    if (now - lastPing).inSeconds >= PingInterval:
      await pm.pingPeers()
      lastPing = now

    # 300s: request addresses
    if (now - lastGetAddr).inSeconds >= GetAddrInterval:
      await pm.requestAddresses()
      lastGetAddr = now

    # Process any peer state changes
    var disconnected: seq[Peer]
    for peer in pm.peers.values:
      if peer.state == psDisconnected:
        disconnected.add(peer)

    for peer in disconnected:
      await pm.removePeer(peer)

    await sleepAsync(1000.milliseconds)

  info "peer manager main loop stopped"

proc stop*(pm: PeerManager) =
  ## Stop the peer manager
  pm.running = false
  pm.stopListener()

  # Disconnect all peers
  for peer in pm.peers.values:
    asyncSpawn peer.disconnect()

  pm.peers.clear()

proc addKnownAddress*(pm: PeerManager, addr: NetAddress) =
  ## Add a known address for future connection attempts
  pm.knownAddresses.add(addr)

proc getKnownAddresses*(pm: PeerManager): seq[NetAddress] =
  pm.knownAddresses

proc setMessageCallback*(pm: PeerManager, callback: PeerCallback) =
  pm.onMessage = callback

proc updateHeight*(pm: PeerManager, height: int32) =
  pm.ourHeight = height
  pm.localVersion.startHeight = height

proc registerInFlightBlock*(pm: PeerManager, hash: BlockHash, peer: Peer) =
  pm.inFlightBlocks[hash] = InFlightBlock(
    hash: hash,
    peer: peer,
    requestTime: getTime()
  )

proc completeInFlightBlock*(pm: PeerManager, hash: BlockHash) =
  pm.inFlightBlocks.del(hash)

proc getInFlightBlocks*(pm: PeerManager): seq[BlockHash] =
  for hash in pm.inFlightBlocks.keys:
    result.add(hash)
