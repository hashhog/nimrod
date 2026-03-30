## Peer connection management
## Handles peer discovery, DNS resolution, connection limits, banning, and message routing
## 8 full-relay outbound + 2 block-relay-only outbound + 117 inbound connections
## 24h ban duration, misbehavior scoring: 100 points = ban (Bitcoin Core compatible)
##
## Eclipse attack protections:
## - Network group diversity: no two outbound peers share same /16 (IPv4) or /32 (IPv6)
## - Anchor connections: persist 2 block-relay-only peers to anchors.dat
## - Inbound eviction: protect diverse categories when slots are full
##
## Reference: Bitcoin Core net.cpp, node/eviction.cpp

import std/[tables, sets, sequtils, random, times, net, strutils, algorithm, options]
import chronos
import chronicles
import ./peer
import ./messages
import ./banman
import ./netgroup
import ./eviction
import ./anchors
import ../consensus/params
import ../primitives/[types, serialize]
import ../crypto/hashing

export banman, netgroup, eviction, anchors

const
  BanDuration* = initDuration(hours = 24)
  ReconnectInterval* = 30  # seconds
  PingInterval* = 120      # seconds
  GetAddrInterval* = 300   # seconds
  DefaultMaxOutboundFullRelay* = 8
  DefaultMaxOutboundBlockRelay* = 2
  DefaultMaxInbound* = 117
  NetgroupKey* = 0x6c0edd8036ef4036'u64  # SHA256("netgroup")[0:8]

type
  PeerCallback* = proc(peer: Peer, msg: P2PMessage): Future[void] {.async.}

  PeerConnectionType* = enum
    pctFullRelay       # Full-relay outbound (8 slots)
    pctBlockRelayOnly  # Block-relay-only outbound (2 slots)
    pctInbound         # Inbound

  ExtendedPeer* = ref object
    ## Extended peer info for eclipse protection
    peer*: Peer
    connType*: PeerConnectionType
    connectedTime*: Time
    lastBlockTime*: Time
    lastTxTime*: Time
    minPingTime*: times.Duration
    netGroup*: NetGroup
    keyedNetGroup*: uint64
    noBan*: bool

  InFlightBlock* = object
    hash*: BlockHash
    peer*: Peer
    requestTime*: Time

  PeerManager* = ref object
    peers*: Table[string, Peer]
    extendedPeers*: Table[string, ExtendedPeer]
    maxOutboundFullRelay*: int
    maxOutboundBlockRelay*: int
    maxInbound*: int
    networkMagic*: array[4, byte]
    params*: ConsensusParams
    localVersion*: VersionMsg
    knownAddresses*: seq[NetAddress]
    banManager*: BanManager
    anchorList*: AnchorList
    listener*: StreamServer
    onMessage*: PeerCallback
    ourHeight*: int32
    seedNodes*: seq[tuple[host: string, port: uint16]]
    fallbackPeers*: seq[tuple[host: string, port: uint16]]
    inFlightBlocks*: Table[BlockHash, InFlightBlock]
    running*: bool
    dataDir*: string
    # Eclipse protection state
    outboundNetGroups*: HashSet[NetGroup]  # Network groups of current outbound peers
    netgroupKey*: uint64
    # Stale tip detection state (Bitcoin Core net_processing.cpp)
    lastTipUpdate*: chronos.Moment          # When we last received a new block
    staleTipCheckTime*: chronos.Moment      # When we next check for stale tip
    lastExtraPeerCheckTime*: chronos.Moment # When we last checked for extra peers
    tryNewOutboundPeer*: bool               # Whether to try connecting to an extra peer
    initialSyncFinished*: bool              # Whether initial block download is complete
    blockStallingTimeout*: chronos.Duration # Adaptive timeout for block stalling

# Forward declarations
proc removePeer*(pm: PeerManager, peer: Peer) {.async.}
proc tryEvictInbound(pm: PeerManager): Option[string]
proc runStalePeerChecks*(pm: PeerManager) {.async.}

proc peerKey(host: string, port: uint16): string =
  host & ":" & $port

proc peerKey(peer: Peer): string =
  peerKey(peer.address, peer.port)

proc newPeerManager*(params: ConsensusParams,
                     maxOutFullRelay: int = DefaultMaxOutboundFullRelay,
                     maxOutBlockRelay: int = DefaultMaxOutboundBlockRelay,
                     maxIn: int = DefaultMaxInbound,
                     dataDir: string = "."): PeerManager =
  randomize()
  let now = chronos.Moment.now()
  result = PeerManager(
    params: params,
    peers: initTable[string, Peer](),
    extendedPeers: initTable[string, ExtendedPeer](),
    maxOutboundFullRelay: maxOutFullRelay,
    maxOutboundBlockRelay: maxOutBlockRelay,
    maxInbound: maxIn,
    networkMagic: params.magic,
    knownAddresses: @[],
    banManager: newBanManager(dataDir),
    anchorList: newAnchorList(dataDir),
    seedNodes: @[],
    fallbackPeers: @[],
    ourHeight: 0,
    inFlightBlocks: initTable[BlockHash, InFlightBlock](),
    running: false,
    dataDir: dataDir,
    outboundNetGroups: initHashSet[NetGroup](),
    netgroupKey: NetgroupKey,
    # Stale tip detection
    lastTipUpdate: now,
    staleTipCheckTime: now + chronos.minutes(StaleTipCheckIntervalSec div 60),
    lastExtraPeerCheckTime: now,
    tryNewOutboundPeer: false,
    initialSyncFinished: false,
    blockStallingTimeout: chronos.seconds(BlockStallingTimeoutDefaultSec)
  )

  # Load existing ban list and anchors
  result.banManager.load()
  discard result.anchorList.load()

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
    result.fallbackPeers = @[
      ("18.27.79.17", 18333'u16),
      ("85.10.199.56", 18333'u16),
      ("91.203.5.166", 18333'u16)
    ]
  of Regtest:
    # Regtest has no seeds or fallback peers - connections are manual only
    discard
  of Testnet4:
    result.seedNodes = @[
      ("seed.testnet4.bitcoin.sprovoost.nl", 48333'u16),
      ("seed.testnet4.wiz.biz", 48333'u16)
    ]
  of Signet:
    result.seedNodes = @[
      ("seed.signet.bitcoin.sprovoost.nl", 38333'u16)
    ]

# Legacy compatibility constructor
proc newPeerManager*(params: ConsensusParams, maxOut: int, maxIn: int,
                     dataDir: string = "."): PeerManager =
  newPeerManager(params, maxOut, 2, maxIn, dataDir)

proc connectedPeerCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result += 1

proc outboundCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.direction == pdOutbound and peer.state == psReady:
      result += 1

proc outboundFullRelayCount*(pm: PeerManager): int =
  for key, ext in pm.extendedPeers:
    if ext.connType == pctFullRelay and ext.peer.state == psReady:
      result += 1

proc outboundBlockRelayCount*(pm: PeerManager): int =
  for key, ext in pm.extendedPeers:
    if ext.connType == pctBlockRelayOnly and ext.peer.state == psReady:
      result += 1

proc inboundCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.direction == pdInbound and peer.state == psReady:
      result += 1

proc isBanned*(pm: PeerManager, address: string): bool =
  pm.banManager.isBanned(address)

proc banPeer*(pm: PeerManager, address: string, duration: times.Duration = BanDuration,
              reason: BanReason = brMisbehaving) =
  pm.banManager.ban(address, duration, reason)

  let normalizedAddr = normalizeAddress(address)
  var toRemove: seq[string]
  for key, peer in pm.peers:
    if normalizeAddress(peer.address) == normalizedAddr:
      toRemove.add(key)

  for key in toRemove:
    let peer = pm.peers[key]
    # Remove from netgroup tracking if outbound
    if key in pm.extendedPeers:
      let ext = pm.extendedPeers[key]
      if ext.connType in {pctFullRelay, pctBlockRelayOnly}:
        pm.outboundNetGroups.excl(ext.netGroup)
      pm.extendedPeers.del(key)
    asyncSpawn peer.disconnect("banned")
    pm.peers.del(key)

proc unbanPeer*(pm: PeerManager, address: string): bool =
  pm.banManager.unban(address)

proc cleanupBans(pm: PeerManager) =
  pm.banManager.sweepExpired()

proc misbehavingPeer*(pm: PeerManager, peer: Peer, score: uint32, message: string) =
  var p = peer
  misbehaving(p, score, message)

  if p.shouldBan():
    pm.banPeer(peer.address, BanDuration, brMisbehaving)
    asyncSpawn pm.removePeer(peer)

proc listBanned*(pm: PeerManager): seq[BanEntry] =
  pm.banManager.listBanned()

proc clearBanned*(pm: PeerManager) =
  pm.banManager.clearBanned()

proc getNetGroupForAddress*(pm: PeerManager, address: string): NetGroup =
  ## Get network group for an address
  getNetGroup(address)

proc hasNetGroupCollision*(pm: PeerManager, address: string): bool =
  ## Check if connecting to this address would cause a netgroup collision
  ## with existing outbound peers (eclipse protection)
  let ng = getNetGroup(address)
  ng in pm.outboundNetGroups

proc resolveDnsSeeds*(pm: PeerManager): Future[seq[string]] {.async.} =
  var addresses: seq[string]

  for (host, port) in pm.seedNodes:
    try:
      let resolvedAddrs = resolveTAddress(host, Port(port))
      for ta in resolvedAddrs:
        addresses.add($ta.address)
    except CatchableError as e:
      debug "DNS resolution failed", host = host, error = e.msg

  if addresses.len > 0:
    shuffle(addresses)

  if addresses.len < pm.maxOutboundFullRelay:
    for (host, port) in pm.fallbackPeers:
      if host notin addresses:
        addresses.add(host)

  return addresses

proc connectToPeerWithType*(pm: PeerManager, address: string, port: uint16,
                            connType: PeerConnectionType): Future[bool] {.async.} =
  ## Connect to a peer with specific connection type
  let key = peerKey(address, port)

  if pm.isBanned(address):
    debug "peer is banned", address = address
    return false

  if key in pm.peers:
    return false

  # Check netgroup diversity for outbound connections
  if connType in {pctFullRelay, pctBlockRelayOnly}:
    let ng = getNetGroup(address)
    if ng in pm.outboundNetGroups:
      debug "skipping peer due to netgroup collision", address = address, netgroup = $ng
      return false

  # Check connection limits
  case connType
  of pctFullRelay:
    if pm.outboundFullRelayCount >= pm.maxOutboundFullRelay:
      return false
  of pctBlockRelayOnly:
    if pm.outboundBlockRelayCount >= pm.maxOutboundBlockRelay:
      return false
  of pctInbound:
    if pm.inboundCount >= pm.maxInbound:
      return false

  let peer = newPeer(address, port, pm.params, pdOutbound)
  pm.peers[key] = peer

  if await peer.connect():
    try:
      await peer.performHandshake(pm.ourHeight)

      # Create extended peer info
      let ip = parseIpAddr(address)
      let ng = getNetGroup(ip)
      let ext = ExtendedPeer(
        peer: peer,
        connType: connType,
        connectedTime: getTime(),
        lastBlockTime: Time(),
        lastTxTime: Time(),
        minPingTime: initDuration(seconds = 60),
        netGroup: ng,
        keyedNetGroup: getKeyedNetGroup(ip, pm.netgroupKey),
        noBan: false
      )
      pm.extendedPeers[key] = ext

      # Add to netgroup tracking for outbound
      if connType in {pctFullRelay, pctBlockRelayOnly}:
        pm.outboundNetGroups.incl(ng)

      info "connected to peer", peer = $peer, height = peer.startHeight, connType = $connType

      # Start message loop for outbound peer (same as inbound)
      if pm.onMessage != nil:
        asyncSpawn peer.messageLoop(pm.onMessage)
      else:
        asyncSpawn peer.messageLoop(nil)

      return true
    except CatchableError as e:
      error "handshake failed", peer = $peer, error = e.msg
      await peer.disconnect()
      pm.peers.del(key)
      return false
  else:
    pm.peers.del(key)
    return false

proc connectToPeer*(pm: PeerManager, address: string, port: uint16): Future[bool] {.async.} =
  ## Connect to a peer (full-relay outbound)
  return await pm.connectToPeerWithType(address, port, pctFullRelay)

proc removePeer*(pm: PeerManager, peer: Peer) {.async.} =
  let key = peerKey(peer)
  if key in pm.peers:
    # Remove from netgroup tracking
    if key in pm.extendedPeers:
      let ext = pm.extendedPeers[key]
      if ext.connType in {pctFullRelay, pctBlockRelayOnly}:
        pm.outboundNetGroups.excl(ext.netGroup)
      pm.extendedPeers.del(key)

    await peer.disconnect()
    pm.peers.del(key)

    var toRequeue: seq[BlockHash]
    for hash, inflight in pm.inFlightBlocks:
      if inflight.peer == peer:
        toRequeue.add(hash)

    for hash in toRequeue:
      pm.inFlightBlocks.del(hash)
      debug "re-queued in-flight block on peer disconnect", hash = $hash

proc connectToAnchors*(pm: PeerManager) {.async.} =
  ## Connect to anchor peers first (block-relay-only)
  ## Reference: Bitcoin Core net.cpp ThreadOpenConnections
  while not pm.anchorList.isEmpty():
    let anchorOpt = pm.anchorList.pop()
    if anchorOpt.isNone:
      break

    let anchor = anchorOpt.get()
    let address = ipToString(anchor.ip)
    let port = anchor.port

    if pm.isBanned(address):
      continue

    # Check netgroup collision
    if pm.hasNetGroupCollision(address):
      continue

    if pm.outboundBlockRelayCount >= pm.maxOutboundBlockRelay:
      break

    info "connecting to anchor peer", address = address, port = port
    discard await pm.connectToPeerWithType(address, port, pctBlockRelayOnly)

proc startOutboundConnections*(pm: PeerManager) {.async.} =
  info "starting outbound connections",
       maxFullRelay = pm.maxOutboundFullRelay,
       maxBlockRelay = pm.maxOutboundBlockRelay

  # Regtest: no automatic outbound connections (manual/addnode only)
  if pm.params.network == Regtest:
    info "regtest mode: skipping automatic outbound connections"
    return

  # First, try to connect to anchor peers
  await pm.connectToAnchors()

  # Resolve DNS seeds
  let addresses = await pm.resolveDnsSeeds()
  info "resolved addresses", count = addresses.len

  # Connect to full-relay peers with netgroup diversity
  for address in addresses:
    if pm.outboundFullRelayCount >= pm.maxOutboundFullRelay:
      break

    # Skip if netgroup collision
    if pm.hasNetGroupCollision(address):
      debug "skipping address due to netgroup collision", address = address
      continue

    let port = pm.params.defaultPort
    discard await pm.connectToPeerWithType(address, port, pctFullRelay)
    await sleepAsync(100)

  # Fill remaining block-relay-only slots
  for address in addresses:
    if pm.outboundBlockRelayCount >= pm.maxOutboundBlockRelay:
      break

    if pm.hasNetGroupCollision(address):
      continue

    let port = pm.params.defaultPort
    discard await pm.connectToPeerWithType(address, port, pctBlockRelayOnly)
    await sleepAsync(100)

proc tryEvictInbound(pm: PeerManager): Option[string] =
  ## Try to select an inbound peer to evict
  ## Returns peer key if eviction candidate found
  var candidates: seq[EvictionCandidate]

  var peerId: int64 = 0
  for key, ext in pm.extendedPeers:
    if ext.connType != pctInbound:
      continue

    let ip = parseIpAddr(ext.peer.address)
    candidates.add(EvictionCandidate(
      id: peerId,
      address: ext.peer.address,
      connected: ext.connectedTime,
      minPingTime: ext.minPingTime,
      lastBlockTime: ext.lastBlockTime,
      lastTxTime: ext.lastTxTime,
      relevantServices: (ext.peer.services and (NodeNetwork or NodeWitness)) != 0,
      relayTxs: true,  # TODO: track this properly
      bloomFilter: false,
      keyedNetGroup: ext.keyedNetGroup,
      preferEvict: false,
      isLocal: ip.isLocal(),
      netGroup: ext.netGroup,
      noBan: ext.noBan,
      connType: ctInbound
    ))
    inc peerId

  let evictIdOpt = selectNodeToEvict(candidates)
  if evictIdOpt.isSome:
    let evictId = evictIdOpt.get()
    # Find the key for this ID
    var idx: int64 = 0
    for key, ext in pm.extendedPeers:
      if ext.connType == pctInbound:
        if idx == evictId:
          return some(key)
        inc idx

  return none(string)

proc handleInboundConnection(pm: PeerManager, transp: StreamTransport) {.async.} =
  let remoteAddr = transp.remoteAddress()
  let address = $remoteAddr.address
  let port = uint16(remoteAddr.port)
  let key = peerKey(address, port)

  if pm.isBanned(address):
    debug "rejecting banned inbound connection", address = address
    await transp.closeWait()
    return

  if key in pm.peers:
    debug "rejecting duplicate connection", address = address
    await transp.closeWait()
    return

  # Check connection limits - try eviction if full
  if pm.inboundCount >= pm.maxInbound:
    let evictKeyOpt = pm.tryEvictInbound()
    if evictKeyOpt.isSome:
      let evictKey = evictKeyOpt.get()
      info "evicting inbound peer to make room", evictKey = evictKey
      if evictKey in pm.peers:
        let evictPeer = pm.peers[evictKey]
        await pm.removePeer(evictPeer)
    else:
      debug "rejecting inbound connection (limit reached, no eviction candidate)", address = address
      await transp.closeWait()
      return

  let peer = newPeer(address, port, pm.params, pdInbound)
  peer.transport = transp
  peer.state = psConnected
  pm.peers[key] = peer

  info "accepted inbound connection", peer = $peer

  try:
    await peer.performHandshake(pm.ourHeight)

    # Create extended peer info
    let ip = parseIpAddr(address)
    let ng = getNetGroup(ip)
    let ext = ExtendedPeer(
      peer: peer,
      connType: pctInbound,
      connectedTime: getTime(),
      lastBlockTime: Time(),
      lastTxTime: Time(),
      minPingTime: initDuration(seconds = 60),
      netGroup: ng,
      keyedNetGroup: getKeyedNetGroup(ip, pm.netgroupKey),
      noBan: false
    )
    pm.extendedPeers[key] = ext

    info "inbound handshake complete", peer = $peer, height = peer.startHeight

    if pm.onMessage != nil:
      asyncSpawn peer.messageLoop(pm.onMessage)
    else:
      asyncSpawn peer.messageLoop(nil)
  except CatchableError as e:
    error "inbound handshake failed", peer = $peer, error = e.msg
    await peer.disconnect()
    pm.peers.del(key)
    if key in pm.extendedPeers:
      pm.extendedPeers.del(key)

proc inboundConnectionCallback(server: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
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
  let ta = initTAddress(bindAddr, Port(port))

  pm.listener = createStreamServer(
    ta,
    inboundConnectionCallback,
    {ServerFlags.ReuseAddr},
    udata = cast[pointer](pm)
  )
  pm.listener.start()
  info "listening for connections", address = bindAddr, port = port

proc stopListener*(pm: PeerManager) =
  if pm.listener != nil:
    pm.listener.stop()
    pm.listener.close()
    pm.listener = nil

proc getReadyPeers*(pm: PeerManager): seq[Peer] =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result.add(peer)

proc getBestPeer*(pm: PeerManager): Peer =
  var best: Peer = nil
  var bestHeight: int32 = -1

  for peer in pm.peers.values:
    if peer.state == psReady and peer.startHeight > bestHeight:
      best = peer
      bestHeight = peer.startHeight

  best

proc getBlockRelayOnlyPeers*(pm: PeerManager): seq[Peer] =
  ## Get all block-relay-only outbound peers
  for key, ext in pm.extendedPeers:
    if ext.connType == pctBlockRelayOnly and ext.peer.state == psReady:
      result.add(ext.peer)

proc saveAnchors*(pm: PeerManager) =
  ## Save current block-relay-only connections as anchors
  var addresses: seq[(string, uint16, uint64)]
  for peer in pm.getBlockRelayOnlyPeers():
    addresses.add((peer.address, peer.port, peer.services))

  if addresses.len > 0:
    let anchors = getCurrentBlockRelayOnlyAddresses(addresses)
    pm.anchorList.anchors = anchors
    pm.anchorList.isDirty = true
    pm.anchorList.save()

proc broadcastTx*(pm: PeerManager, tx: Transaction) {.async.} =
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
  let msg = newInv(inventory)
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast inv", peer = $peer, error = e.msg

proc buildBlockLocator*(pm: PeerManager, tip: BlockHash): seq[array[32, byte]] =
  result = @[]
  result.add(array[32, byte](tip))
  let genesisHash = array[32, byte](pm.params.genesisBlockHash)
  if result[^1] != genesisHash:
    result.add(genesisHash)

proc buildBlockLocatorFromChain*(heights: proc(h: int32): Option[BlockHash],
                                  tipHeight: int32,
                                  genesisHash: BlockHash): seq[array[32, byte]] =
  result = @[]
  var step: int32 = 1
  var height = tipHeight

  while height >= 0:
    let hashOpt = heights(height)
    if hashOpt.isSome:
      result.add(array[32, byte](hashOpt.get()))

    if result.len > 10:
      step *= 2

    height -= step

  let genesisArr = array[32, byte](genesisHash)
  if result.len == 0 or result[^1] != genesisArr:
    result.add(genesisArr)

proc updatePeerPingTime*(pm: PeerManager, peer: Peer, pingTime: times.Duration) =
  ## Update minimum ping time for a peer (for eviction scoring)
  let key = peerKey(peer)
  if key in pm.extendedPeers:
    if pingTime < pm.extendedPeers[key].minPingTime:
      pm.extendedPeers[key].minPingTime = pingTime

proc updatePeerBlockTime*(pm: PeerManager, peer: Peer) =
  ## Update last block time for a peer (for eviction scoring)
  let key = peerKey(peer)
  if key in pm.extendedPeers:
    pm.extendedPeers[key].lastBlockTime = getTime()

proc updatePeerTxTime*(pm: PeerManager, peer: Peer) =
  ## Update last tx time for a peer (for eviction scoring)
  let key = peerKey(peer)
  if key in pm.extendedPeers:
    pm.extendedPeers[key].lastTxTime = getTime()

proc maintainConnections(pm: PeerManager) {.async.} =
  var toRemove: seq[string]
  for key, peer in pm.peers:
    if peer.state == psDisconnected:
      toRemove.add(key)

  for key in toRemove:
    if key in pm.extendedPeers:
      let ext = pm.extendedPeers[key]
      if ext.connType in {pctFullRelay, pctBlockRelayOnly}:
        pm.outboundNetGroups.excl(ext.netGroup)
      pm.extendedPeers.del(key)
    pm.peers.del(key)

  pm.cleanupBans()

  # Try to maintain connections
  let fullRelayDeficit = pm.maxOutboundFullRelay - pm.outboundFullRelayCount
  let blockRelayDeficit = pm.maxOutboundBlockRelay - pm.outboundBlockRelayCount

  if fullRelayDeficit > 0 or blockRelayDeficit > 0:
    info "reconnecting to maintain peer count",
         fullRelay = pm.outboundFullRelayCount,
         blockRelay = pm.outboundBlockRelayCount
    await pm.startOutboundConnections()

proc pingPeers(pm: PeerManager) {.async.} =
  for peer in pm.getReadyPeers():
    try:
      await peer.sendPing()
    except CatchableError as e:
      debug "failed to ping peer", peer = $peer, error = e.msg

proc requestAddresses(pm: PeerManager) {.async.} =
  let msg = newGetAddr()
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to request addresses", peer = $peer, error = e.msg

proc mainLoop*(pm: PeerManager) {.async.} =
  pm.running = true

  var lastReconnect = getTime()
  var lastPing = getTime()
  var lastGetAddr = getTime()
  var lastStalePeerCheck = chronos.Moment.now()

  info "peer manager main loop started"

  while pm.running:
    let now = getTime()
    let nowMoment = chronos.Moment.now()

    if (now - lastReconnect).inSeconds >= ReconnectInterval:
      await pm.maintainConnections()
      lastReconnect = now

    if (now - lastPing).inSeconds >= PingInterval:
      await pm.pingPeers()
      lastPing = now

    if (now - lastGetAddr).inSeconds >= GetAddrInterval:
      await pm.requestAddresses()
      lastGetAddr = now

    # Run stale peer checks every second (the functions handle their own intervals)
    if nowMoment - lastStalePeerCheck >= chronos.seconds(1):
      await pm.runStalePeerChecks()
      lastStalePeerCheck = nowMoment

    var disconnected: seq[Peer]
    for peer in pm.peers.values:
      if peer.state == psDisconnected:
        disconnected.add(peer)
      elif peer.shouldDisconnect:
        disconnected.add(peer)

    for peer in disconnected:
      await pm.removePeer(peer)

    await sleepAsync(1000)

  info "peer manager main loop stopped"

proc stop*(pm: PeerManager) =
  pm.running = false
  pm.stopListener()

  # Save anchors before shutdown
  pm.saveAnchors()

  for peer in pm.peers.values:
    asyncSpawn peer.disconnect()

  pm.peers.clear()
  pm.extendedPeers.clear()
  pm.outboundNetGroups.clear()

proc addKnownAddress*(pm: PeerManager, address: NetAddress) =
  pm.knownAddresses.add(address)

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

# Legacy compatibility: keep maxOutbound as alias
proc maxOutbound*(pm: PeerManager): int =
  pm.maxOutboundFullRelay + pm.maxOutboundBlockRelay

# =============================================================================
# Stale peer eviction and ping timeout handling
# Reference: Bitcoin Core net_processing.cpp ConsiderEviction, EvictExtraOutboundPeers,
#            CheckForStaleTipAndEvictPeers, MaybeSendPing
# =============================================================================

proc tipMayBeStale*(pm: PeerManager): bool =
  ## Check if our tip may be stale (no new block in > 30 minutes)
  ## Reference: Bitcoin Core TipMayBeStale()
  let elapsed = chronos.Moment.now() - pm.lastTipUpdate
  elapsed > chronos.minutes(30)

proc recordNewTip*(pm: PeerManager) =
  ## Record that we received a new block at our tip
  pm.lastTipUpdate = chronos.Moment.now()

proc getExtraBlockRelayCount*(pm: PeerManager): int =
  ## Get count of block-relay-only peers beyond our target
  let current = pm.outboundBlockRelayCount()
  max(0, current - pm.maxOutboundBlockRelay)

proc getExtraFullOutboundCount*(pm: PeerManager): int =
  ## Get count of full-relay outbound peers beyond our target
  let current = pm.outboundFullRelayCount()
  max(0, current - pm.maxOutboundFullRelay)

proc hasMultipleOutboundConnections*(pm: PeerManager, peer: Peer): bool =
  ## Check if we have other outbound connections besides this peer
  ## Used to protect the only connection to a network
  var count = 0
  for key, ext in pm.extendedPeers:
    if ext.connType in {pctFullRelay, pctBlockRelayOnly} and ext.peer != peer:
      if ext.peer.state == psReady:
        inc count
  count > 0

proc considerEviction*(pm: PeerManager, peer: var Peer) =
  ## Consider whether to evict an outbound peer for having a stale chain
  ## Reference: Bitcoin Core ConsiderEviction()
  ##
  ## Logic:
  ## 1. If peer's best known height >= our height, reset timeout
  ## 2. If timeout not set or peer made progress, set new timeout (20 min)
  ## 3. If timeout expired and we haven't sent getheaders, send it and reduce timeout
  ## 4. If timeout expired and we already sent getheaders, disconnect

  # Only consider outbound peers that have started syncing
  if not peer.isOutbound() or not peer.syncStarted:
    return

  # Don't evict protected peers
  if peer.isProtectedFromChainSyncEviction():
    return

  let nowUnix = getTime().toUnix()

  # If peer's chain has at least as much work as ours, reset timeout
  if peer.bestKnownHeight >= pm.ourHeight:
    if peer.chainSyncState.timeout != 0:
      peer.resetChainSyncTimeout()
    return

  # Peer is behind - manage timeout
  if peer.chainSyncState.timeout == 0:
    # First time we notice peer is behind - set initial timeout
    peer.setChainSyncTimeout(pm.ourHeight, nowUnix)
    debug "peer behind our chain, setting timeout",
          peer = $peer,
          peerHeight = peer.bestKnownHeight,
          ourHeight = pm.ourHeight
  elif peer.chainSyncState.workHeaderHeight > 0 and
       peer.bestKnownHeight >= peer.chainSyncState.workHeaderHeight:
    # Peer caught up to where we were when timeout was set, but we've advanced
    # Reset timeout based on current tip
    peer.setChainSyncTimeout(pm.ourHeight, nowUnix)
    debug "peer caught up to old tip, resetting timeout",
          peer = $peer
  elif peer.isChainSyncTimedOut(nowUnix):
    # Timeout expired
    if peer.chainSyncState.sentGetheaders:
      # We already sent getheaders and they didn't respond in time
      warn "outbound peer has stale chain, disconnecting",
           peer = $peer,
           peerHeight = peer.bestKnownHeight,
           ourHeight = pm.ourHeight
      peer.shouldDisconnect = true
    else:
      # First timeout - send getheaders to give them a chance
      debug "sending getheaders to verify chain work",
            peer = $peer
      peer.markChainSyncGetheadersSent(nowUnix)
      # Note: Actual getheaders message should be sent by caller

proc evictExtraBlockRelayPeers*(pm: PeerManager) {.async.} =
  ## Evict extra block-relay-only peers beyond our target
  ## Prefer to evict the youngest unless it gave us a block recently
  ## Reference: Bitcoin Core EvictExtraOutboundPeers() - block-relay section

  if pm.getExtraBlockRelayCount() <= 0:
    return

  let now = chronos.Moment.now()

  # Find youngest and second-youngest block-relay-only peers
  var youngest: tuple[key: string, peer: Peer, lastBlock: chronos.Moment]
  var nextYoungest: tuple[key: string, peer: Peer, lastBlock: chronos.Moment]
  youngest.key = ""
  nextYoungest.key = ""

  for key, ext in pm.extendedPeers:
    if ext.connType != pctBlockRelayOnly:
      continue
    if ext.peer.state != psReady or ext.peer.shouldDisconnect:
      continue

    # "Youngest" = most recently connected (we use connectedTime)
    # Bitcoin Core uses nodeId, but we'll use connection time as proxy
    if youngest.key == "" or ext.peer.connectedTime > youngest.peer.connectedTime:
      nextYoungest = youngest
      youngest = (key, ext.peer, ext.peer.lastBlockTime)

  if youngest.key == "":
    return

  # Decide which to evict
  var toEvictKey = youngest.key
  if nextYoungest.key != "" and youngest.lastBlock > nextYoungest.lastBlock:
    # Youngest gave us a block more recently - evict second youngest
    toEvictKey = nextYoungest.key

  let peer = pm.peers[toEvictKey]

  # Don't evict if:
  # - Connected too recently (< MINIMUM_CONNECT_TIME)
  # - Currently downloading blocks
  if not peer.hasMinimumConnectTime():
    debug "keeping block-relay peer, too recently connected",
          peer = $peer
    return

  if peer.hasBlocksInFlight():
    debug "keeping block-relay peer, blocks in flight",
          peer = $peer
    return

  info "evicting extra block-relay-only peer",
       peer = $peer
  await pm.removePeer(peer)

proc evictExtraFullOutboundPeers*(pm: PeerManager) {.async.} =
  ## Evict extra full-relay outbound peers beyond our target
  ## Evict the peer with oldest block announcement
  ## Reference: Bitcoin Core EvictExtraOutboundPeers() - full-relay section

  if pm.getExtraFullOutboundCount() <= 0:
    return

  let now = chronos.Moment.now()

  # Find the peer with oldest block announcement
  var worstKey = ""
  var oldestAnnouncement = high(int64)

  for key, ext in pm.extendedPeers:
    if ext.connType != pctFullRelay:
      continue
    if ext.peer.state != psReady or ext.peer.shouldDisconnect:
      continue

    # Don't evict protected peers
    if ext.peer.isProtectedFromChainSyncEviction():
      continue

    # Don't evict if this is our only connection (protect network diversity)
    if not pm.hasMultipleOutboundConnections(ext.peer):
      continue

    if ext.peer.lastBlockAnnouncement < oldestAnnouncement:
      oldestAnnouncement = ext.peer.lastBlockAnnouncement
      worstKey = key

  if worstKey == "":
    return

  let peer = pm.peers[worstKey]

  # Don't evict if:
  # - Connected too recently (< MINIMUM_CONNECT_TIME)
  # - Currently downloading blocks
  if not peer.hasMinimumConnectTime():
    debug "keeping full-relay peer, too recently connected",
          peer = $peer
    return

  if peer.hasBlocksInFlight():
    debug "keeping full-relay peer, blocks in flight",
          peer = $peer
    return

  info "evicting extra full-relay outbound peer",
       peer = $peer,
       lastAnnouncement = oldestAnnouncement
  await pm.removePeer(peer)

  # If we disconnected, don't try more extra peers until stale tip detected again
  pm.tryNewOutboundPeer = false

proc evictExtraOutboundPeers*(pm: PeerManager) {.async.} =
  ## Evict extra outbound peers (both block-relay and full-relay)
  ## Called every EXTRA_PEER_CHECK_INTERVAL (45 seconds)
  ## Reference: Bitcoin Core EvictExtraOutboundPeers()
  await pm.evictExtraBlockRelayPeers()
  await pm.evictExtraFullOutboundPeers()

proc checkForStaleTipAndEvictPeers*(pm: PeerManager) {.async.} =
  ## Main stale tip detection and peer eviction loop
  ## Called every EXTRA_PEER_CHECK_INTERVAL (45 seconds)
  ## Reference: Bitcoin Core CheckForStaleTipAndEvictPeers()

  let now = chronos.Moment.now()

  # First evict any extra outbound peers
  await pm.evictExtraOutboundPeers()

  # Then check if we should allow an extra outbound peer due to stale tip
  if now > pm.staleTipCheckTime:
    if pm.initialSyncFinished and pm.tipMayBeStale():
      info "potential stale tip detected, allowing extra outbound peer",
           lastTipUpdate = (now - pm.lastTipUpdate).seconds
      pm.tryNewOutboundPeer = true
    elif pm.tryNewOutboundPeer:
      pm.tryNewOutboundPeer = false

    pm.staleTipCheckTime = now + chronos.minutes(StaleTipCheckIntervalSec div 60)

proc checkPingTimeouts*(pm: PeerManager) {.async.} =
  ## Check all peers for ping timeouts
  ## Reference: Bitcoin Core MaybeSendPing() timeout logic

  var toDisconnect: seq[Peer]

  for key, peer in pm.peers:
    if peer.state != psReady:
      continue

    if peer.isPingTimedOut():
      warn "peer ping timeout, disconnecting",
           peer = $peer
      toDisconnect.add(peer)

  for peer in toDisconnect:
    await pm.removePeer(peer)

proc sendPings*(pm: PeerManager) {.async.} =
  ## Send pings to peers that need them
  ## Reference: Bitcoin Core MaybeSendPing()

  for key, peer in pm.peers.mpairs:
    if peer.state != psReady:
      continue

    if peer.shouldSendPing():
      try:
        peer.startPing()
        await peer.sendPing()
      except CatchableError as e:
        debug "failed to send ping", peer = $peer, error = e.msg

proc checkHeadersTimeouts*(pm: PeerManager) {.async.} =
  ## Check for headers request timeouts
  ## Reference: Bitcoin Core HEADERS_RESPONSE_TIME

  for key, peer in pm.peers.mpairs:
    if peer.state != psReady:
      continue

    if peer.isHeadersRequestTimedOut():
      warn "headers request timeout, marking peer misbehaving",
           peer = $peer
      misbehaving(peer, ScoreProtocolViolation, "headers timeout")

proc checkChainSyncTimeouts*(pm: PeerManager) =
  ## Check all outbound peers for chain sync timeouts
  ## Reference: Bitcoin Core ConsiderEviction()

  for key, peer in pm.peers.mpairs:
    if peer.state != psReady:
      continue

    if peer.isOutbound() and peer.syncStarted:
      pm.considerEviction(peer)

proc runStalePeerChecks*(pm: PeerManager) {.async.} =
  ## Run all stale peer checks
  ## Called periodically from main loop

  let now = chronos.Moment.now()

  # Check for extra peer eviction every 45 seconds
  if now - pm.lastExtraPeerCheckTime >= chronos.seconds(ExtraPeerCheckIntervalSec):
    await pm.checkForStaleTipAndEvictPeers()
    pm.lastExtraPeerCheckTime = now

  # Check chain sync timeouts for outbound peers
  pm.checkChainSyncTimeouts()

  # Check ping timeouts
  await pm.checkPingTimeouts()

  # Check headers timeouts
  await pm.checkHeadersTimeouts()

proc markInitialSyncComplete*(pm: PeerManager) =
  ## Mark that initial block download is complete
  pm.initialSyncFinished = true
