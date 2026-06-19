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
import ./addr
import ./addrman
import ./proxy as proxy_mod
import ../consensus/params
import ../primitives/[types, serialize]
import ../crypto/hashing

export banman, netgroup, eviction, anchors

const
  BanDuration* = initDuration(hours = 24)
  ReconnectInterval* = 30  # seconds
  PingInterval* = 120      # seconds
  GetAddrInterval* = 300   # seconds
  # Periodic addrman flush (Bitcoin Core net.cpp DumpAddresses /
  # DUMP_PEERS_INTERVAL = 15min): the addrman is persisted to peers.dat on a
  # 900s cadence WHILE RUNNING so a SIGKILL/OOM does not lose every address
  # learned since boot (the graceful-shutdown save in stop() still runs too).
  DumpPeersInterval* = 900 # seconds (Core DUMP_PEERS_INTERVAL = 15min)
  # Feeler connections (Bitcoin Core net.cpp): every ~FEELER_INTERVAL the
  # connection-open loop opens ONE short-lived FEELER to a NEW-table address,
  # completes the handshake, promotes it NEW->TRIED via addrman Good(), then
  # disconnects.  Bounded at MaxFeelerConnections=1 (Core
  # MAX_FEELER_CONNECTIONS).  Feelers do NOT count toward the full-outbound
  # slots — they keep TRIED fresh = the primary eclipse-attack mitigation.
  FeelerInterval* = 120        # seconds (Core FEELER_INTERVAL = 2min)
  MaxFeelerConnections* = 1    # Core MAX_FEELER_CONNECTIONS
  # GETADDR anti-DoS (Bitcoin Core net_processing.cpp):
  #  - MaxAddrToSend: hard cap on a getaddr response (Core MAX_ADDR_TO_SEND).
  #  - MaxPctAddrToSend: getaddr response also capped at 23% of addrman size
  #    (Core MAX_PCT_ADDR_TO_SEND); the effective cap is the min of the two.
  MaxAddrToSend* = 1000        # Core MAX_ADDR_TO_SEND
  MaxPctAddrToSend* = 23       # Core MAX_PCT_ADDR_TO_SEND
  # Inbound addr-message rate limiting (token bucket; Core net_processing.cpp):
  #  - MaxAddrRatePerSecond: bucket refill rate (Core MAX_ADDR_RATE_PER_SECOND).
  #  - MaxAddrProcessingTokenBucket: soft cap on accumulated tokens
  #    (Core MAX_ADDR_PROCESSING_TOKEN_BUCKET = MAX_ADDR_TO_SEND).
  MaxAddrRatePerSecond* = 0.1
  MaxAddrProcessingTokenBucket* = 1000.0
  # 3F FIX: relay gate — Core net_processing.cpp:5688 only relays addr/addrv2
  # when the incoming message has <= 10 entries (large responses are getaddr
  # replies and must NOT be forwarded).
  # Reference: bitcoin-core/src/net_processing.cpp:5688.
  AddrRelayMaxEntries* = 10
  DefaultMaxOutboundFullRelay* = 8
  DefaultMaxOutboundBlockRelay* = 2
  DefaultMaxInbound* = 117
  NetgroupKey* = 0x6c0edd8036ef4036'u64  # SHA256("netgroup")[0:8]
  # BIP-324: cap the v1-only address cache.  Mirrors clearbit's
  # V2_FALLBACK_CACHE_MAX = 4096.  Bounded so a churn-y network doesn't
  # leak memory; eviction is a single-pop on insert when full.
  V2FallbackCacheMax* = 4096

type
  PeerCallback* = proc(peer: Peer, msg: P2PMessage): Future[void] {.async.}

  PeerConnectionType* = enum
    pctFullRelay       # Full-relay outbound (8 slots)
    pctBlockRelayOnly  # Block-relay-only outbound (2 slots)
    pctInbound         # Inbound
    pctManual          # Manual/addnode — always noBan, never counted against limits
    pctFeeler          # Short-lived feeler probe (Core ConnectionType::FEELER).
                       # Selected from the NEW table only; on a successful
                       # handshake the address is promoted NEW->TRIED (Good())
                       # and the connection is dropped. Does NOT consume a
                       # full-relay/block-relay slot. The primary eclipse-attack
                       # mitigation: keeps the TRIED table fresh by probing.

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
    ## BUG-4 FIX (W117): store Tor v3, I2P, and CJDNS addresses received in
    ## addrv2 messages here (they cannot be represented in the legacy 16-byte
    ## NetAddress format).  Relayed as addrv2 to peers that signaled wantsAddrV2.
    knownAddressesV2*: seq[TimestampedAddrV2]
    ## AXIS #2: Core-bucketed address manager (CAddrMan).  knownAddresses above
    ## stays as the rich getnodeaddresses/addr-sharing metadata store; this
    ## table is the NEW[1024][64]/TRIED[256][64] placement + anti-Sybil engine +
    ## peers.dat persistence.  Fed under addKnownAddress; loaded at construction
    ## from <dataDir>/peers.dat; saved on stop().  Mirrors rustoshi 361d81b.
    addrMan*: AddrManTable
    banManager*: BanManager
    anchorList*: AnchorList
    listener*: StreamServer
    onMessage*: PeerCallback
    ourHeight*: int32
    seedNodes*: seq[tuple[host: string, port: uint16]]
    fallbackPeers*: seq[tuple[host: string, port: uint16]]
    # -connect peer pinning (Core/clearbit semantics).  When non-empty the node
    # connects to ONLY these peers and disables DNS-seed resolution AND the
    # auto-outbound fill (addrman/diversity dialing).  Mirrors clearbit's
    # PeerManager.connect_address branch (peer.zig:7009) + the
    # `connect_address == null` gate on the outbound-fill loop (peer.zig:7050),
    # and Bitcoin Core's `-connect` which implies `-dnsseed=0`.  Pinned peers
    # are dialed as manual connections (NoBan, bypass slot/netgroup/routability
    # gates) and re-dialed by maintainConnections when dropped.
    connectPeers*: seq[tuple[host: string, port: uint16]]
    # Independent DNS-seed switch (`--nodnsseed` / `-dnsseed=0`).  Default true.
    # Set false to suppress DNS-seed resolution without pinning peers; also
    # forced false implicitly when connectPeers is non-empty.
    dnsSeedEnabled*: bool
    inFlightBlocks*: Table[BlockHash, InFlightBlock]
    running*: bool
    dataDir*: string
    # Eclipse protection state
    outboundNetGroups*: HashSet[NetGroup]  # Network groups of current outbound peers
    netgroupKey*: uint64
    # ASN-aware eclipse protection (FIX-51 / W115 G25+G27)
    # When an asmap file is loaded this manager yields ASN-keyed groups instead
    # of /16 or /32 prefixes, mirroring Bitcoin Core's CConnman::m_netgroupman.
    # Reference: bitcoin-core/src/net.h CConnman::m_netgroupman
    netGroupManager*: NetGroupManager
    # Stale tip detection state (Bitcoin Core net_processing.cpp)
    lastTipUpdate*: chronos.Moment          # When we last received a new block
    staleTipCheckTime*: chronos.Moment      # When we next check for stale tip
    lastExtraPeerCheckTime*: chronos.Moment # When we last checked for extra peers
    tryNewOutboundPeer*: bool               # Whether to try connecting to an extra peer
    initialSyncFinished*: bool              # Whether initial block download is complete
    blockStallingTimeout*: chronos.Duration # Adaptive timeout for block stalling
    # BIP-324 outbound v2 fallback cache.  Addresses (host:port) that have
    # failed v2 negotiation get inserted; future outbound attempts to the
    # same address skip the v2 probe and go straight to v1.  Bounded by
    # `V2FallbackCacheMax` (FIFO-ish eviction — Nim's HashSet iteration
    # order is implementation-defined).  Mirrors clearbit's
    # `v2_fallback_set` (peer.zig:1759).
    v2FallbackSet*: HashSet[string]
    # W117 BUG-3 FIX (FIX-56): proxy / onion / I2P / CJDNS configuration.
    # Wires the previously dead-helper src/network/proxy.nim subsystems
    # (SOCKS5, Tor control, I2P SAM, ProxyManager, stream isolation) into
    # the outbound connect path.  Built from CLI flags --proxy / --onion /
    # --i2psam / --cjdnsreachable in src/nimrod.nim.  nil = no proxy
    # configured (direct connect, .onion/.i2p outbound rejected).
    # Reference: bitcoin-core/src/init.cpp -proxy / -onion / -i2psam /
    # -cjdnsreachable; CConnman::m_proxy_for_net.
    proxyManager*: proxy_mod.ProxyManager
    cjdnsReachable*: bool
    # The `addnode`-managed persistent-peer list, keyed by the exact node string
    # the operator supplied. Mirrors Bitcoin Core's CConnman::m_added_node_params
    # (src/net.cpp): membership is what addnode "add"/"remove" toggle, and the
    # list's contents — not the live connection state — decide whether a
    # duplicate add or a stale remove is an RPC error. Distinct from the addrman
    # address book (which also holds gossiped/seed addresses); only
    # operator-pinned entries live here.
    addedNodes*: seq[string]

# Forward declarations
proc removePeer*(pm: PeerManager, peer: Peer) {.async.}
proc tryEvictInbound(pm: PeerManager): Option[string]
proc runStalePeerChecks*(pm: PeerManager) {.async.}
proc handleAddrInternal*(pm: PeerManager, peer: Peer, msg: P2PMessage)
proc markAddressGood*(pm: PeerManager, address: string, port: uint16) {.raises: [], gcsafe.}
proc markAddressAttempt*(pm: PeerManager, address: string, port: uint16) {.raises: [], gcsafe.}
proc selectAddress*(pm: PeerManager, newOnly: bool = false): Option[tuple[ip: array[16, byte], port: uint16]] {.raises: [], gcsafe.}

proc peerKey(host: string, port: uint16): string =
  host & ":" & $port

proc peerKey(peer: Peer): string =
  peerKey(peer.address, peer.port)

proc addAddedNode*(pm: PeerManager, node: string): bool =
  ## Record `node` on the `addnode`-managed list. nimrod equivalent of Bitcoin
  ## Core's CConnman::AddNode (src/net.cpp). Returns false — and makes NO change
  ## — when the node is already on the list (Core returns false on a string
  ## collision); the RPC layer turns that into RPC_CLIENT_NODE_ALREADY_ADDED
  ## (-23). Returns true when a fresh entry is recorded.
  for n in pm.addedNodes:
    if n == node:
      return false
  pm.addedNodes.add(node)
  true

proc removeAddedNode*(pm: PeerManager, node: string): bool =
  ## Remove `node` from the `addnode`-managed list. nimrod equivalent of Bitcoin
  ## Core's CConnman::RemoveAddedNode (src/net.cpp). Returns false when the node
  ## was never added (Core returns false after scanning the list), which the RPC
  ## layer turns into RPC_CLIENT_NODE_NOT_ADDED (-24). Returns true on removal.
  for i in 0 ..< pm.addedNodes.len:
    if pm.addedNodes[i] == node:
      pm.addedNodes.delete(i)
      return true
  false

proc addedNodesList*(pm: PeerManager): seq[string] =
  ## Snapshot of the current `addnode`-managed node strings (for
  ## getaddednodeinfo / tests). Mirrors reading CConnman::m_added_node_params.
  pm.addedNodes

# ─────────────────────────────────────────────────────────────────────────────
# W117 BUG-3 FIX (FIX-56): proxy/network-type configuration helpers.
# These wire CLI flags (--proxy / --onion / --i2psam / --cjdnsreachable) into
# the dead-helper src/network/proxy.nim subsystems (SOCKS5, Tor control, I2P
# SAM, ProxyManager) so that outbound connect dispatch in
# `connectToPeerWithType` can route .onion through Tor, .i2p through SAM, and
# clearnet through SOCKS5 (or direct).
# Reference: bitcoin-core/src/init.cpp -proxy / -onion / -i2psam /
# -cjdnsreachable; CConnman::m_proxy_for_net dispatch in ConnectNode.
proc ensureProxyManager(pm: PeerManager) =
  ## Lazily allocate the ProxyManager when the first --proxy/--onion/--i2psam
  ## flag is wired in.
  if pm.proxyManager == nil:
    pm.proxyManager = proxy_mod.newProxyManager()

proc configureProxy*(pm: PeerManager, host: string, port: uint16,
                     username: string = "", password: string = "") =
  ## Configure the clearnet SOCKS5 proxy (used for IPv4/IPv6 outbound).
  ## Mirrors Core's `-proxy=host:port` flag.
  ensureProxyManager(pm)
  let auth =
    if username.len > 0 or password.len > 0:
      some(proxy_mod.ProxyCredentials(username: username, password: password))
    else:
      none(proxy_mod.ProxyCredentials)
  pm.proxyManager.configureProxy(host, port, auth)
  info "configured clearnet SOCKS5 proxy", host = host, port = port,
       auth = (username.len > 0)

proc configureOnionProxy*(pm: PeerManager, host: string, port: uint16,
                          randomizeCredentials: bool = true) =
  ## Configure the Tor SOCKS5 proxy used for .onion connections.  Stream
  ## isolation is enabled by default so each outbound .onion connect gets a
  ## fresh Tor circuit (mirrors Core's per-destination credentials).
  ## Mirrors Core's `-onion=host:port` flag.
  ensureProxyManager(pm)
  pm.proxyManager.configureOnionProxy(host, port, randomizeCredentials)
  info "configured Tor SOCKS proxy", host = host, port = port,
       streamIsolation = randomizeCredentials

proc configureI2PSam*(pm: PeerManager, host: string, port: uint16,
                      privateKeyFile: string = "", transient: bool = false) =
  ## Configure the I2P SAM bridge used for .i2p connections.
  ## Mirrors Core's `-i2psam=host:port` flag.
  ensureProxyManager(pm)
  pm.proxyManager.configureI2P(host, port, privateKeyFile, transient)
  info "configured I2P SAM bridge", host = host, port = port,
       transient = transient

proc setCjdnsReachable*(pm: PeerManager, reachable: bool) =
  ## Mirrors Core's `-cjdnsreachable` flag.  When false (default), CJDNS
  ## peers (fc00::/8) are skipped on outbound — Core's policy is "we don't
  ## have a CJDNS route so don't try".  When true, CJDNS addresses are
  ## directly dialed (CJDNS exposes a TCP-over-mesh socket locally).
  pm.cjdnsReachable = reachable

proc isOnionHost(host: string): bool {.inline.} =
  host.endsWith(".onion")

proc isI2pHost(host: string): bool {.inline.} =
  host.endsWith(".i2p")

proc isCjdnsHost(host: string): bool {.inline.} =
  ## CJDNS uses native IPv6 fc00::/8.  Detect by parsing the host as IPv6
  ## and checking the fc00::/8 prefix (the same predicate netgroup.nim
  ## isCJDNS uses for routability classification).
  let ip = parseIpAddr(host)
  ip.isV6 and ip.isCJDNS()

proc markV1Only*(pm: PeerManager, address: string, port: uint16) =
  ## BIP-324: mark `address:port` as v1-only.  Subsequent outbound
  ## attempts will skip the v2 probe and go straight to v1.  Bounded by
  ## `V2FallbackCacheMax`; on overflow, drop one arbitrary entry (Nim's
  ## HashSet iteration order is implementation-defined — same as
  ## clearbit's behaviour).
  let key = peerKey(address, port)
  if pm.v2FallbackSet.len >= V2FallbackCacheMax:
    # Pop one arbitrary element.
    for k in pm.v2FallbackSet:
      pm.v2FallbackSet.excl(k)
      break
  pm.v2FallbackSet.incl(key)

proc isV1Only*(pm: PeerManager, address: string, port: uint16): bool =
  ## BIP-324: returns true if `address:port` previously failed v2
  ## negotiation and should skip the v2 probe.
  peerKey(address, port) in pm.v2FallbackSet

proc newPeerManager*(params: ConsensusParams,
                     maxOutFullRelay: int = DefaultMaxOutboundFullRelay,
                     maxOutBlockRelay: int = DefaultMaxOutboundBlockRelay,
                     maxIn: int = DefaultMaxInbound,
                     dataDir: string = ".",
                     netGroupMgr: NetGroupManager = nil): PeerManager =
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
    knownAddressesV2: @[],
    banManager: newBanManager(dataDir),
    anchorList: newAnchorList(dataDir),
    seedNodes: @[],
    fallbackPeers: @[],
    connectPeers: @[],
    dnsSeedEnabled: true,
    ourHeight: 0,
    inFlightBlocks: initTable[BlockHash, InFlightBlock](),
    running: false,
    dataDir: dataDir,
    outboundNetGroups: initHashSet[NetGroup](),
    netgroupKey: NetgroupKey,
    # Use provided NetGroupManager or a no-asmap fallback.
    # Reference: bitcoin-core/src/net.cpp CConnman constructor passes m_netgroupman
    netGroupManager: if netGroupMgr != nil: netGroupMgr else: newNetGroupManager(),
    # Stale tip detection
    lastTipUpdate: now,
    staleTipCheckTime: now + chronos.minutes(StaleTipCheckIntervalSec div 60),
    lastExtraPeerCheckTime: now,
    tryNewOutboundPeer: false,
    initialSyncFinished: false,
    blockStallingTimeout: chronos.seconds(BlockStallingTimeoutDefaultSec),
    v2FallbackSet: initHashSet[string](),
    # W117 BUG-3 FIX (FIX-56): proxy fields default to nil/false — the
    # caller (src/nimrod.nim startNode) wires them after construction
    # when --proxy / --onion / --i2psam / --cjdnsreachable are set.
    proxyManager: nil,
    cjdnsReachable: false
  )

  # AXIS #2: load the Core-bucketed addrman from <dataDir>/peers.dat (or a
  # cold empty table on first run / corrupt file).  Re-bucketed from the
  # persisted nKey so placement is reproduced exactly across restarts.
  result.addrMan = addrman.load(dataDir, result.netGroupManager)

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
    # Fixed-seed fallback (Core chainparamsseeds / vFixedSeeds, net.cpp:2606-2644
    # ThreadOpenConnections).  Consumed by resolveDnsSeeds (lines below): when
    # DNS resolution yields fewer than maxOutboundFullRelay addresses (DNS empty
    # OR --nodnsseed OR --connect short-circuit), these hard-coded IPv4 peers are
    # appended so a node with an empty address book can still bootstrap.  This is
    # a last-resort fallback layered AFTER normal DNS resolution, never a bypass.
    # The 40 IPs are curated routable IPv4 mainnet peers (port 8333).
    result.fallbackPeers = @[
      ("2.121.116.198", 8333'u16),
      ("3.86.179.235", 8333'u16),
      ("4.2.51.251", 8333'u16),
      ("5.2.23.226", 8333'u16),
      ("12.11.29.34", 8333'u16),
      ("14.49.142.41", 8333'u16),
      ("18.27.125.103", 8333'u16),
      ("23.93.18.82", 8333'u16),
      ("24.16.202.74", 8333'u16),
      ("27.83.109.113", 8333'u16),
      ("31.41.23.249", 8333'u16),
      ("34.65.45.157", 8333'u16),
      ("35.78.97.86", 8333'u16),
      ("37.15.61.236", 8333'u16),
      ("38.52.3.192", 8333'u16),
      ("40.160.1.232", 8333'u16),
      ("44.223.26.178", 8333'u16),
      ("45.19.130.200", 8333'u16),
      ("46.126.216.3", 8333'u16),
      ("47.90.137.13", 8333'u16),
      ("50.4.123.66", 8333'u16),
      ("51.154.0.142", 8333'u16),
      ("52.182.185.242", 8333'u16),
      ("60.241.1.72", 8333'u16),
      ("62.34.57.141", 8333'u16),
      ("63.247.147.166", 8333'u16),
      ("64.23.97.128", 8333'u16),
      ("65.94.134.253", 8333'u16),
      ("66.35.84.14", 8333'u16),
      ("67.4.139.122", 8333'u16),
      ("68.61.69.53", 8333'u16),
      ("69.4.94.226", 8333'u16),
      ("70.44.20.24", 8333'u16),
      ("71.56.178.136", 8333'u16),
      ("72.88.192.74", 8333'u16),
      ("73.42.33.255", 8333'u16),
      ("74.48.195.218", 8333'u16),
      ("75.80.3.4", 8333'u16),
      ("76.124.35.108", 8333'u16),
      ("77.38.72.37", 8333'u16)
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
  ## Apply misbehavior score and, if the threshold is reached, ban + disconnect
  ## the peer.  Mirrors Bitcoin Core net_processing.cpp Misbehaving():
  ##   if HasPermission(NoBan) → return (no ban, no disconnect)
  ##   if IsManualConn()       → return (no ban, no disconnect)
  ##   if addr.IsLocal()       → disconnect-only (no ban entry)
  ##   else                    → Discourage (24h ban) + disconnect
  var p = peer
  misbehaving(p, score, message)

  if not p.shouldBan():
    return

  # Look up extended peer info for connection-type + noBan checks.
  # Key format is "address:port" (peerKey).
  let key = peerKey(peer.address, peer.port)
  if key in pm.extendedPeers:
    let ext = pm.extendedPeers[key]

    # G2 guard 1: NoBan permission (whitelist / whitebind / addnode).
    if ext.noBan:
      debug "misbehavingPeer: skip ban — noBan peer", peer = key, message = message
      return

    # G2 guard 2: manual connection (addnode).
    if ext.connType == pctManual:
      debug "misbehavingPeer: skip ban — manual peer", peer = key, message = message
      return

    # G2 guard 3: local address → disconnect-only, no ban entry.
    try:
      let ip = parseIpAddr(peer.address)
      if ip.isLocal():
        debug "misbehavingPeer: local peer — disconnect only", peer = key, message = message
        asyncSpawn pm.removePeer(peer)
        return
    except CatchableError:
      discard  # unparseable address → fall through to normal ban path

  pm.banPeer(peer.address, BanDuration, brMisbehaving)
  asyncSpawn pm.removePeer(peer)

proc listBanned*(pm: PeerManager): seq[BanEntry] =
  pm.banManager.listBanned()

proc clearBanned*(pm: PeerManager) =
  pm.banManager.clearBanned()

proc getNetGroupForAddress*(pm: PeerManager, address: string): NetGroup =
  ## Get network group for an address, using ASN-keyed groups when an asmap
  ## is loaded in pm.netGroupManager.
  ## Reference: bitcoin-core/src/net.cpp CConnman::GetGroup() — delegates to
  ##   m_netgroupman.GetGroup(addr) which is ASN-keyed when asmap present.
  let ip = parseIpAddr(address)
  getNetGroupAsn(pm.netGroupManager, ip)

proc hasNetGroupCollision*(pm: PeerManager, address: string): bool =
  ## Check if connecting to this address would cause a netgroup collision
  ## with existing outbound peers (eclipse protection).
  ## Uses ASN-keyed groups when asmap is loaded (G25/G27 FIX-51).
  ## Reference: bitcoin-core/src/net.cpp CConnman::FindNode + ThreadOpenConnections
  let ng = pm.getNetGroupForAddress(address)
  ng in pm.outboundNetGroups

proc dnsSeedingEnabled*(pm: PeerManager): bool =
  ## DNS-seed resolution is on only when explicitly enabled AND no `-connect`
  ## peers are pinned.  Mirrors Core (`-connect` implies `-dnsseed=0`) and
  ## clearbit's connect-branch which skips dnsSeeds() (peer.zig:7009/7039).
  pm.dnsSeedEnabled and pm.connectPeers.len == 0

proc resolveDnsSeeds*(pm: PeerManager): Future[seq[string]] {.async.} =
  var addresses: seq[string]

  # `--connect` (peer-pinned) bypasses ThreadOpenConnections entirely — no DNS
  # AND no fixed-seed fallback (Core: -connect skips the fixed-seed logic, see
  # net.cpp ThreadOpenConnections gating + the dnsSeedingEnabled() comment).
  # Short-circuit hard so neither path runs.
  if pm.connectPeers.len > 0:
    debug "DNS seeding disabled (--connect set): no DNS, no fixed-seed fallback"
    return addresses

  # `--nodnsseed` / `-dnsseed=0`: skip DNS resolution but STILL fall through to
  # the fixed-seed fallback below.  This is Core's `!dnsseed && !use_seednodes`
  # immediate-fire path (net.cpp:2620-2625): with DNS off and no other peer
  # source, the curated fixed seeds are the only bootstrap and must fire — the
  # `addresses.len < maxOutboundFullRelay` guard is then trivially satisfied
  # (addresses is empty), so all fallbackPeers are appended right away.
  if pm.dnsSeedingEnabled():
    for (host, port) in pm.seedNodes:
      try:
        let resolvedAddrs = resolveTAddress(host, Port(port))
        for ta in resolvedAddrs:
          addresses.add($ta.address)
      except CatchableError as e:
        debug "DNS resolution failed", host = host, error = e.msg

    if addresses.len > 0:
      shuffle(addresses)
  else:
    debug "DNS seeding disabled (--nodnsseed): falling back to fixed seeds"

  # Fixed-seed fallback (Core net.cpp:2606-2644).  Fires whenever the DNS pass
  # produced fewer than the outbound target — DNS empty, DNS off, or DNS
  # returned too few — appending the curated fixed peers.  Last-resort layer
  # AFTER normal DNS, never a bypass of it.
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

  # W117 BUG-3 FIX (FIX-56): network-type gating + routability gate for
  # automatic outbound dials.  Manual peers (addnode) bypass these so an
  # operator can always force-dial a specific peer for debugging.
  # Reference: bitcoin-core/src/net.cpp CConnman::ConnectNode early
  # return on !IsReachable(addr.GetNetwork()).
  if connType in {pctFullRelay, pctBlockRelayOnly}:
    let onion = isOnionHost(address)
    let i2p   = isI2pHost(address)
    let cjdns = (not onion and not i2p) and isCjdnsHost(address)

    if onion:
      # .onion requires either the onion proxy (--onion) or the clearnet
      # SOCKS5 proxy (--proxy, fallback) configured.
      if pm.proxyManager == nil or
         (pm.proxyManager.onionProxy.isNone and pm.proxyManager.clearnetProxy.isNone):
        debug "skipping .onion peer: no Tor SOCKS proxy configured",
              address = address
        return false
    elif i2p:
      # .i2p requires an active I2P SAM session (--i2psam).
      if pm.proxyManager == nil or pm.proxyManager.i2pSession.isNone:
        debug "skipping .i2p peer: no I2P SAM configured",
              address = address
        return false
    elif cjdns:
      if not pm.cjdnsReachable:
        debug "skipping CJDNS peer: --cjdnsreachable not set",
              address = address
        return false
    else:
      # IPv4 / IPv6 routability check (mirrors Core's IsRoutable() gate
      # in ThreadOpenConnections + AddrMan::Select_).  Skip RFC1918 / loopback
      # / link-local / RFC6598 etc.  Manual peers (above) bypass this.
      try:
        let ip = parseIpAddr(address)
        if not isRoutable(ip):
          debug "skipping unroutable address", address = address
          return false
      except CatchableError:
        debug "skipping unparseable address", address = address
        return false

  # Check netgroup diversity for outbound connections.
  # FIX-51 (W115 G27): use ASN-keyed group via pm.netGroupManager when asmap
  # is loaded, mirroring Core's CConnman::ThreadOpenConnections which calls
  # m_netgroupman.GetGroup(addr) for the collision check.
  if connType in {pctFullRelay, pctBlockRelayOnly}:
    let ng = pm.getNetGroupForAddress(address)
    if ng in pm.outboundNetGroups:
      debug "skipping peer due to netgroup collision", address = address, netgroup = $ng
      return false

  # Check connection limits (manual peers bypass slot limits)
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
  of pctManual:
    discard  # manual/addnode peers bypass slot limits
  of pctFeeler:
    discard  # feelers do not consume a full-relay/block-relay slot.
             # Boundedness (one feeler at a time, every FeelerInterval) is
             # enforced by the mainLoop feeler tick, mirroring Core's
             # MAX_FEELER_CONNECTIONS=1 single-FEELER-per-open-loop rule.

  let peer = newPeer(address, port, pm.params, pdOutbound)
  # BIP-324: if this address has previously failed a v2 probe, skip v2
  # this round — the peer is already known to be v1-only.  Mirrors
  # clearbit's `try_v2 = v2_enabled and !self.isV1Only(address)` gate
  # (peer.zig:1868).  performHandshake reads this field on the outbound
  # branch.
  if pm.isV1Only(address, port):
    peer.v2OutboundDisabled = true
  # W117 BUG-3 FIX (FIX-56): hand the configured ProxyManager (if any) to
  # the Peer so Peer.connect() dispatches based on address type
  # (.onion → Tor SOCKS, .i2p → SAM, IPv4/IPv6 → direct/SOCKS5).
  peer.proxyManager = pm.proxyManager
  pm.peers[key] = peer

  if await peer.connect():
    try:
      await peer.performHandshake(pm.ourHeight)

      # Create extended peer info.
      # FIX-51 (W115 G25): store the ASN-keyed group so outboundNetGroups
      # uses ASN granularity when asmap is loaded.
      # Reference: bitcoin-core/src/net.cpp CConnman::CreateNodeFromAcceptedSocket
      let ip = parseIpAddr(address)
      let ng = getNetGroupAsn(pm.netGroupManager, ip)
      let ext = ExtendedPeer(
        peer: peer,
        connType: connType,
        connectedTime: getTime(),
        lastBlockTime: Time(),
        lastTxTime: Time(),
        minPingTime: initDuration(seconds = 60),
        netGroup: ng,
        keyedNetGroup: getKeyedNetGroup(ip, pm.netgroupKey),
        # Manual/addnode peers get NoBan permission (Core: HasPermission(NoBan))
        noBan: connType == pctManual
      )
      pm.extendedPeers[key] = ext

      # Add to netgroup tracking for outbound
      if connType in {pctFullRelay, pctBlockRelayOnly}:
        pm.outboundNetGroups.incl(ng)

      # AXIS #2: a successful outbound handshake promotes the address NEW->TRIED
      # in the bucketed addrman (Core marks Good() on connection success).
      pm.markAddressGood(address, port)

      # Feeler: the probe has done its job — the NEW-table address handshook
      # successfully and has just been promoted to TRIED above.  Now disconnect
      # immediately (Core: "For feelers, disconnect immediately after successful
      # handshake").  We do NOT start the message loop, send feefilter, or keep
      # the peer in our tables — a feeler is short-lived and must not occupy a
      # connection slot.
      if connType == pctFeeler:
        info "feeler connection succeeded, promoting NEW->TRIED and disconnecting",
             peer = $peer
        pm.extendedPeers.del(key)
        await peer.disconnect()
        pm.peers.del(key)
        return true

      info "connected to peer", peer = $peer, height = peer.startHeight, connType = $connType

      # Start message loop for outbound peer (same as inbound)
      # Wrap callback to handle addr/addrv2/getaddr/feefilter internally
      let wrappedCb = proc(p: Peer, msg: P2PMessage) {.async.} =
        {.gcsafe.}:
          try:
            pm.handleAddrInternal(p, msg)
          except Exception:
            discard
        if pm.onMessage != nil:
          await pm.onMessage(p, msg)
      asyncSpawn peer.messageLoop(wrappedCb)

      # BIP133: Send initial feefilter after handshake
      # 100 sat/vbyte = 100,000 sat/kvB to discourage tx relay during sync
      let feeMsg = newFeeFilter(100_000'u64)
      asyncSpawn spawnSafe(peer.sendMessage(feeMsg))

      return true
    except CatchableError as e:
      # BIP-324 fallback bookkeeping: if the failure is in the v2 outbound
      # path, mark the address v1-only so the next reconnect (driven by
      # `mainLoop`'s ReconnectInterval) skips the v2 probe and goes
      # straight to v1.  We can't retry inline because the v2 garbage on
      # the wire is destructive on a v1 peer — the socket is poisoned.
      # We detect by error-message prefix; the v2 paths in peer.nim raise
      # PeerError with "v2 ..." messages, never anything ambiguous with
      # v1.  Mirrors clearbit's `markV1Only` call (peer.zig:1899).
      if e.msg.startsWith("v2 ") and bip324V2OutboundEnabled():
        debug "BIP-324 v2 outbound failed, marking v1-only",
              peer = $peer, error = e.msg
        pm.markV1Only(address, port)
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

proc connectManualPeer*(pm: PeerManager, address: string, port: uint16): Future[bool] {.async.} =
  ## Connect to a manually-added peer (addnode / whitebind).
  ## Manual peers bypass slot limits and receive NoBan permission —
  ## they will never be banned by misbehavingPeer().
  return await pm.connectToPeerWithType(address, port, pctManual)

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

  # -connect peer pinning (Core/clearbit): when pinned peers are set, connect
  # to ONLY those, as manual connections (NoBan + bypass slot/netgroup/
  # routability gates), and do NOT resolve DNS seeds or fill auto-outbound
  # slots.  Re-runs on each maintainConnections pass to re-dial any pinned peer
  # that has dropped (the "retry the dead pinned peer" behavior).  Mirrors
  # clearbit's connect_address branch (peer.zig:7009) + the
  # `connect_address == null` gate on the outbound-fill loop (peer.zig:7050).
  if pm.connectPeers.len > 0:
    info "connect mode: dialing only pinned peers, DNS + auto-outbound disabled",
         pinned = pm.connectPeers.len
    try:
      for (host, port) in pm.connectPeers:
        if peerKey(host, port) in pm.peers:
          continue  # already connected — nothing to do this pass
        discard await pm.connectManualPeer(host, port)
        await sleepAsync(100)
    except CatchableError as e:
      error "connect-mode dial failed", error = e.msg
    return

  # Regtest: no automatic outbound connections (manual/addnode only)
  if pm.params.network == Regtest:
    info "regtest mode: skipping automatic outbound connections"
    return

  # This proc runs as a detached background task (asyncSpawn from nimrod.nim):
  # it MUST NOT let an exception escape, or asyncSpawn aborts the process.
  # DNS resolution in particular can fail.  connectToPeerWithType already
  # swallows per-peer connect errors internally.
  try:
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
  except CatchableError as e:
    error "outbound connection setup failed", error = e.msg

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

    # Create extended peer info.
    # FIX-51: use ASN-keyed group for inbound peers too so eviction's
    # keyedNetGroup reflects the same grouping as the outbound diversity check.
    let ip = parseIpAddr(address)
    let ng = getNetGroupAsn(pm.netGroupManager, ip)
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

    # Wrap callback to handle addr/addrv2/getaddr/feefilter internally
    let wrappedCb = proc(p: Peer, msg: P2PMessage) {.async.} =
      {.gcsafe.}:
        try:
          pm.handleAddrInternal(p, msg)
        except Exception:
          discard
      if pm.onMessage != nil:
        await pm.onMessage(p, msg)
    asyncSpawn peer.messageLoop(wrappedCb)

    # BIP133: Send initial feefilter after handshake
    let feeMsg = newFeeFilter(100_000'u64)
    asyncSpawn spawnSafe(peer.sendMessage(feeMsg))
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
  ## Broadcast a transaction to all ready peers.
  ## G20 (BIP-339): wtxid-relay peers receive invWtx (MSG_WTX=5) with the
  ## wtxid; legacy peers receive invTx (MSG_TX=1) with the txid.
  let wtxidHash = array[32, byte](tx.wtxid())
  let txidHash  = array[32, byte](tx.txid())

  for peer in pm.getReadyPeers():
    let (itemType, itemHash) =
      if peer.wtxidRelay:
        (invWtx, wtxidHash)
      else:
        (invTx, txidHash)
    let inv = @[InvVector(invType: itemType, hash: itemHash)]
    let msg = newInv(inv)
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast tx inv", peer = $peer, error = e.msg

proc selectBlockAnnouncement*(
  header: BlockHeader,
  blockHash: array[32, byte],
  peerSendHeaders: bool
): P2PMessage =
  ## Pure helper for BIP-130 announce-message selection.  Peers that sent us
  ## `sendheaders` get a `headers` payload; the rest get an `inv`.  Pulled
  ## out of broadcastBlock to make the branch unit-testable without a
  ## live transport.  Reference: camlcoin lib/peer_manager.ml::announce_block,
  ## bitcoin-core/src/net_processing.cpp::PeerManagerImpl::SendMessages.
  if peerSendHeaders:
    newHeaders(@[header])
  else:
    newInv(@[InvVector(invType: invBlock, hash: blockHash)])

proc broadcastBlock*(pm: PeerManager, blk: Block) {.async.} =
  ## Announce a new block to all connected peers, honoring the BIP-130
  ## sendheaders preference (Pattern A).  Peers that sent us `sendheaders`
  ## receive the header directly via a `headers` message; the rest get an
  ## inv pointing at the block hash.
  ## Reference: bitcoin-core/src/net_processing.cpp::PeerManagerImpl::SendMessages
  ##   ("Try to find a peer to send announcements via headers");
  ##   camlcoin lib/peer_manager.ml::announce_block.
  let headerBytes = serialize(blk.header)
  let blockHash = doubleSha256(headerBytes)

  for peer in pm.getReadyPeers():
    try:
      let msg = selectBlockAnnouncement(blk.header, blockHash, peer.sendHeaders)
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast block announcement",
            peer = $peer, sendHeaders = peer.sendHeaders, error = e.msg

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

  # -connect mode: re-dial only the pinned peers (no DNS, no auto-fill).
  # startOutboundConnections handles the connect branch + skips already-
  # connected pins.  Mirrors clearbit's per-tick maintainManualConnections.
  if pm.connectPeers.len > 0:
    await pm.startOutboundConnections()
    return

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

proc tryFeelerConnection*(pm: PeerManager) {.async.} =
  ## Open ONE short-lived feeler connection to an address selected from the
  ## NEW table (Core ThreadOpenConnections FEELER branch: addrman.Select(true)).
  ## On a successful handshake connectToPeerWithType promotes the address
  ## NEW->TRIED (Good()) and disconnects.  Feelers keep the TRIED table fresh
  ## by probing NEW entries, which is the primary eclipse-attack mitigation.
  ## Bounded to MaxFeelerConnections=1 by the single call site (the mainLoop
  ## feeler tick).  No-op when there is no NEW-table address to probe.
  if pm.connectPeers.len > 0:
    # -connect mode: addrman is intentionally unused (Core skips feelers when
    # -connect is set).
    return
  let sel = pm.selectAddress(newOnly = true)
  if sel.isNone:
    return
  let (ip16, port) = sel.get()
  let address = ipToString(ip16)
  let key = peerKey(address, port)
  if key in pm.peers:
    # Already connected to this address — Core would mark it Good() and pick
    # another; the simplest faithful behavior is to promote it (it is reachable)
    # and skip the redundant dial.
    pm.markAddressGood(address, port)
    return
  debug "opening feeler connection", address = address, port = port
  try:
    discard await pm.connectToPeerWithType(address, port, pctFeeler)
  except CatchableError as e:
    debug "feeler connection failed", address = address, error = e.msg

proc mainLoop*(pm: PeerManager) {.async.} =
  pm.running = true

  var lastReconnect = getTime()
  var lastPing = getTime()
  var lastGetAddr = getTime()
  var lastFeeler = getTime()
  var lastAddrDump = getTime()
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

    # Feeler tick (Core FEELER_INTERVAL=120s): open ONE short-lived probe to a
    # NEW-table address to keep TRIED fresh (anti-eclipse).  Single call site =
    # MaxFeelerConnections=1.
    if (now - lastFeeler).inSeconds >= FeelerInterval:
      await pm.tryFeelerConnection()
      lastFeeler = now

    # Periodic addrman flush (Core DumpAddresses / DUMP_PEERS_INTERVAL=900s):
    # persist peers.dat while running so a SIGKILL/OOM does not lose addresses
    # learned since boot.  Atomic temp+rename, best-effort (never fatal).
    if (now - lastAddrDump).inSeconds >= DumpPeersInterval:
      if pm.addrMan != nil:
        # save() is best-effort (atomic temp+rename, swallows its own
        # CatchableError); guard here so a periodic-flush failure can never
        # abort the async main loop.
        try:
          pm.addrMan.save(pm.dataDir)
        except Exception:
          discard
      lastAddrDump = now

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

  # AXIS #2: persist the Core-bucketed addrman to <dataDir>/peers.dat so the
  # bucket placement survives restarts (atomic temp+rename; best-effort).
  if pm.addrMan != nil:
    pm.addrMan.save(pm.dataDir)

  for peer in pm.peers.values:
    asyncSpawn peer.disconnect()

  pm.peers.clear()
  pm.extendedPeers.clear()
  pm.outboundNetGroups.clear()

proc addKnownAddress*(pm: PeerManager, address: NetAddress,
                      source: array[16, byte] = default(array[16, byte])) =
  ## Add address to the known-address pool.
  ## Non-routable addresses (RFC1918 private, loopback, link-local, etc.)
  ## are silently dropped — mirroring Bitcoin Core's IsRoutable() filter
  ## applied before CAddrMan::Add() in net_processing.cpp.
  if not isRoutable(address.ip):
    return
  var a = address
  # DATA-GAP FIX (2026-06): if the caller did not supply a wire timestamp,
  # stamp the connect/advertise time so getnodeaddresses emits a real `time`.
  if a.lastSeen == 0:
    a.lastSeen = uint32(epochTime().int)
  pm.knownAddresses.add(a)
  # AXIS #2: also place the address in the Core-bucketed addrman (NEW table).
  # The source group defaults to the address itself (self-announce) when the
  # caller has no source peer.  This is the anti-Sybil + persistence engine;
  # the flat knownAddresses seq above stays as the rich-metadata store.
  var src = source
  var allZero = true
  for b in src:
    if b != 0: allZero = false; break
  if allZero:
    src = address.ip
  discard pm.addrMan.add(address.ip, address.port, src, address.services,
                         int64(a.lastSeen), pm.netGroupManager)

proc getKnownAddresses*(pm: PeerManager): seq[NetAddress] =
  pm.knownAddresses

proc addrToIp16(address: string): array[16, byte] =
  ## Parse an address string into the 16-byte IPv4-mapped / native-IPv6 form
  ## used by the addrman tables.  Returns all-zero on parse failure.
  try:
    let ip = parseIpAddr(address)
    if ip.isV6:
      return ip.v6
    else:
      result[10] = 0xFF
      result[11] = 0xFF
      result[12] = ip.v4[0]
      result[13] = ip.v4[1]
      result[14] = ip.v4[2]
      result[15] = ip.v4[3]
  except CatchableError:
    discard

proc markAddressGood*(pm: PeerManager, address: string, port: uint16) {.raises: [], gcsafe.} =
  ## AXIS #2: promote an address NEW->TRIED on a successful connection
  ## (Core CAddrMan::Good).  No-op if the address is not tracked.  Swallows
  ## all errors so it is safe to call from the async connect path.
  if pm.addrMan == nil: return
  try:
    let ip16 = addrToIp16(address)
    discard pm.addrMan.good(ip16, port, getTime().toUnix(), pm.netGroupManager)
  except Exception:
    discard

proc markAddressAttempt*(pm: PeerManager, address: string, port: uint16) {.raises: [], gcsafe.} =
  ## AXIS #2: record a connection attempt (Core CAddrMan::Attempt).  Swallows
  ## all errors so it is safe to call from the async connect path.
  if pm.addrMan == nil: return
  try:
    let ip16 = addrToIp16(address)
    pm.addrMan.attempt(ip16, port, getTime().toUnix())
  except Exception:
    discard

proc selectAddress*(pm: PeerManager, newOnly: bool = false): Option[tuple[ip: array[16, byte], port: uint16]] {.raises: [], gcsafe.} =
  ## AXIS #2: weighted (50/50 new/tried) bucketed peer selection
  ## (Core CAddrMan::Select).  Feeler probing passes newOnly=true to draw only
  ## from the NEW table (Core addrman.Select(true)).
  if pm.addrMan == nil: return none(tuple[ip: array[16, byte], port: uint16])
  try:
    return pm.addrMan.select(newOnly)
  except Exception:
    return none(tuple[ip: array[16, byte], port: uint16])

type
  KnownAddrEntry* = object
    ## Core-shaped (rpc/net.cpp:959-965) row for the getnodeaddresses dump.
    ## One per addrman entry; `network` is the GetNetworkName(GetNetClass())
    ## string (netbase.cpp:114-128).
    time*: int64       ## unix seconds (CAddress::nTime)
    services*: uint64  ## raw services bitfield (emitted as a JSON integer)
    address*: string   ## ToStringAddr — ip literal / .onion / .b32.i2p, no port
    port*: uint16
    network*: string   ## ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable|internal

proc netClassOfIp(ip: array[16, byte]): string =
  ## Map a 16-byte IPv4-mapped / native-IPv6 address to its Core network string.
  ## Mirrors CNetAddr::GetNetClass() → GetNetworkName(): an unroutable address
  ## reports "not_publicly_routable" (Core netbase.cpp:117), routable IPv4-mapped
  ## reports "ipv4", routable native-IPv6 reports "ipv6". CJDNS (fc00::/8) is its
  ## own class.
  # IPv4-mapped detection: bytes 0-9 zero, bytes 10-11 = 0xFF.
  var isV4Mapped = true
  for i in 0..<10:
    if ip[i] != 0: isV4Mapped = false; break
  if isV4Mapped and (ip[10] != 0xFF or ip[11] != 0xFF):
    isV4Mapped = false
  if not isRoutable(ip):
    return "not_publicly_routable"
  if isV4Mapped:
    return "ipv4"
  if ip[0] == 0xFC'u8:
    return "cjdns"
  return "ipv6"

proc dumpKnownAddresses*(pm: PeerManager, count: int,
                         network: Option[string]): seq[KnownAddrEntry] =
  ## Core-faithful getnodeaddresses backend
  ## (rpc/net.cpp:954-967 → CConnman::GetAddressesUnsafe(count, max_pct=0, net)).
  ##  - walks BOTH the legacy IPv4/IPv6 pool and the addrv2 pool (onion/i2p/cjdns),
  ##  - maps each entry to a Core-shaped row (time/services/address/port/network),
  ##  - filters by `network` when set,
  ##  - SHUFFLES the result (order is non-deterministic, per Core),
  ##  - `count == 0` means "return all", otherwise cap at `count`.
  var rows: seq[KnownAddrEntry]

  # Legacy pool: IPv4 / IPv6 (and CJDNS folded in as IPv4-mapped/native form).
  for na in pm.knownAddresses:
    let net = netClassOfIp(na.ip)
    rows.add(KnownAddrEntry(
      time: int64(na.lastSeen),
      services: na.services,
      address: ipToString(na.ip),
      port: na.port,
      network: net))

  # addrv2 pool: Tor v3 / I2P / CJDNS.
  for ta in pm.knownAddressesV2:
    var net = ""
    case ta.address.networkId
    of netTorV3: net = "onion"
    of netI2P:   net = "i2p"
    of netCJDNS: net = "cjdns"
    of netIPv4:  net = "ipv4"
    of netIPv6:  net = "ipv6"
    else: continue  # deprecated torv2 — skip
    rows.add(KnownAddrEntry(
      time: int64(ta.timestamp),
      services: ta.services,
      address: $ta.address,
      port: ta.port,
      network: net))

  # Network filter (post-classification, like Core's GetAddressesUnsafe(net)).
  if network.isSome:
    let want = network.get()
    var filtered: seq[KnownAddrEntry]
    for r in rows:
      if r.network == want:
        filtered.add(r)
    rows = filtered

  # Shuffle — Core returns a shuffled CAddress vector; callers/tests must be
  # order-insensitive.
  shuffle(rows)

  # count == 0 → all; otherwise cap.
  if count > 0 and rows.len > count:
    rows.setLen(count)
  rows

proc injectKnownAddress*(pm: PeerManager, address: string, port: uint16,
                         services: uint64, time: uint32): bool =
  ## Core-shaped addpeeraddress backend (rpc/net.cpp:992-1013): parse the IP
  ## literal, build the 16-byte IPv4-mapped / native-IPv6 form, stamp the
  ## supplied time, and insert into the known-address pool (deduped by ip+port).
  ## Returns false on an unparseable IP or a non-routable address (Core's Add()
  ## drops unroutable entries), true on a successful insert.
  let ip = parseIpAddr(address)
  var ipBytes: array[16, byte]
  if ip.isV6:
    ipBytes = ip.v6
  else:
    ipBytes[10] = 0xFF
    ipBytes[11] = 0xFF
    ipBytes[12] = ip.v4[0]
    ipBytes[13] = ip.v4[1]
    ipBytes[14] = ip.v4[2]
    ipBytes[15] = ip.v4[3]
  if not isRoutable(ipBytes):
    return false
  # Dedup by ip+port (mirrors the addr-message insert path).
  for ka in pm.knownAddresses:
    if ka.ip == ipBytes and ka.port == port:
      return true
  pm.knownAddresses.add(NetAddress(
    services: services,
    ip: ipBytes,
    port: port,
    lastSeen: (if time == 0: uint32(epochTime().int) else: time)))
  true

proc relayAddresses(pm: PeerManager, source: Peer) =
  ## Relay addresses to up to 2 random peers (not back to source).
  ## BUG-7 FIX (W117): peers that signaled wantsAddrV2 receive addrv2;
  ## others receive the legacy addr message.  Mirrors Core's
  ## CConnman::RelayAddress() which calls PushAddress with CAddress → addrv2 or
  ## addr depending on the peer's SENDADDRV2 negotiation state.
  var candidates: seq[Peer]
  for _, p in pm.peers:
    if p != source and p.isConnected() and not p.closing:
      candidates.add(p)
  if candidates.len == 0:
    return
  shuffle(candidates)
  let n = min(2, candidates.len)

  # Build legacy addr payload (IPv4/IPv6 only)
  let addrCount = min(10, pm.knownAddresses.len)
  var legacyMsg: P2PMessage
  if addrCount > 0:
    var timestamped: seq[TimestampedAddr]
    for i in 0..<addrCount:
      let a = pm.knownAddresses[i]
      timestamped.add(TimestampedAddr(
        timestamp: uint32(epochTime().int),
        address: a
      ))
    legacyMsg = newAddr(timestamped)

  # Build addrv2 payload (all network types: IPv4/IPv6 + Tor/I2P/CJDNS)
  let v2Count = min(10, pm.knownAddressesV2.len + pm.knownAddresses.len)
  var v2Msg: P2PMessage
  if v2Count > 0:
    var v2addrs: seq[TimestampedAddrV2]
    # Add Tor/I2P/CJDNS addresses first
    let privCount = min(10, pm.knownAddressesV2.len)
    for i in 0..<privCount:
      v2addrs.add(pm.knownAddressesV2[i])
    # Fill remaining slots from IPv4/IPv6
    let ipCount = min(10 - v2addrs.len, pm.knownAddresses.len)
    for i in 0..<ipCount:
      v2addrs.add(toTimestampedAddrV2(
        TimestampedAddr(
          timestamp: uint32(epochTime().int),
          address: pm.knownAddresses[i]
        )
      ))
    if v2addrs.len > 0:
      v2Msg = newAddrV2(v2addrs)

  for i in 0..<n:
    let p = candidates[i]
    if p.wantsAddrV2 and v2Msg.kind == mkAddrV2:
      asyncSpawn spawnSafe(p.sendMessage(v2Msg))
    elif addrCount > 0:
      asyncSpawn spawnSafe(p.sendMessage(legacyMsg))

proc buildGetAddrResponse*(pm: PeerManager, peer: Peer): seq[TimestampedAddr] =
  ## Build the addr-message payload to send in reply to a peer's getaddr,
  ## applying the GETADDR anti-DoS guards (Core net_processing.cpp:4815-4848):
  ##  (a) Ignore getaddr from OUTBOUND connections — answering them enables a
  ##      fingerprinting attack (Core: "if (!pfrom.IsInboundConn()) return").
  ##  (b) Answer only the FIRST getaddr per connection; later getaddr from the
  ##      same peer are ignored (Core m_getaddr_recvd) — returns empty.
  ##  (c) Cap the response at min(MaxAddrToSend, 23% of addrman size)
  ##      (Core MAX_PCT_ADDR_TO_SEND, integer floor; addrman.cpp GetAddr_).
  ## Returns an empty seq when the request is ignored or there is nothing to
  ## send.  Exposed so the anti-DoS guards can be proven without a live socket.
  if peer.direction != pdInbound:
    debug "ignoring getaddr from non-inbound connection", peer = $peer
    return @[]
  if peer.getaddrRecvd:
    debug "ignoring repeated getaddr", peer = $peer
    return @[]
  peer.getaddrRecvd = true
  let total = pm.knownAddresses.len
  # 23%-cap (floor), then the hard MaxAddrToSend cap — Core takes the min.
  var cap = (MaxPctAddrToSend * total) div 100
  if cap > MaxAddrToSend:
    cap = MaxAddrToSend
  let count = min(total, cap)
  var addrs: seq[TimestampedAddr]
  for i in 0..<count:
    addrs.add(TimestampedAddr(
      timestamp: uint32(epochTime().int),
      address: pm.knownAddresses[i]))
  addrs

proc handleAddrInternal*(pm: PeerManager, peer: Peer, msg: P2PMessage) =
  ## Process addr/addrv2/getaddr/feefilter messages internally.
  case msg.kind
  of mkAddr:
    # Add addresses to known list (max 1000 per message)
    let count = min(msg.addresses.len, 1000)
    # Inbound addr rate limiting — leaky token bucket (Core net_processing.cpp
    # 5646-5670).  Refill the bucket by elapsed_seconds * MaxAddrRatePerSecond,
    # capped at MaxAddrProcessingTokenBucket; each address we process spends one
    # token.  When the bucket is empty, further addresses from a rate-limited
    # (non-NoBan) peer are dropped.  NoBan/manual peers (Core
    # HasPermission(Addr)) bypass the limit entirely.
    let nowSec = getTime().toUnix()
    if peer.addrTokenBucket < MaxAddrProcessingTokenBucket:
      if peer.addrTokenTimestamp != 0:
        let elapsed = float64(max(0'i64, nowSec - peer.addrTokenTimestamp))
        peer.addrTokenBucket = min(MaxAddrProcessingTokenBucket,
          peer.addrTokenBucket + elapsed * MaxAddrRatePerSecond)
    peer.addrTokenTimestamp = nowSec
    # rate_limited = !HasPermission(Addr): NoBan/manual peers are exempt.
    var rateLimited = true
    let pkey = peerKey(peer.address, peer.port)
    if pkey in pm.extendedPeers:
      let ext = pm.extendedPeers[pkey]
      if ext.noBan or ext.connType == pctManual:
        rateLimited = false
    for i in 0..<count:
      # Apply rate limiting (Core: spend a token per processed addr; drop excess
      # for rate-limited peers).
      if peer.addrTokenBucket < 1.0:
        if rateLimited:
          continue
      else:
        peer.addrTokenBucket -= 1.0
      var na = msg.addresses[i].address
      # DATA-GAP FIX (2026-06): carry the wire timestamp onto the stored record
      # so getnodeaddresses emits a real `time`. The legacy addr message ships a
      # per-entry uint32 timestamp (TimestampedAddr.timestamp); without this the
      # NetAddress lost it and `time` would be 0/fabricated.
      # 3G FIX: clamp received timestamp before storing.
      # Core net_processing.cpp:5678-5680: if nTime <= 100000000 (pre-2001)
      # or nTime > now + 10 minutes, replace with now - 5 days.
      # Reference: bitcoin-core/src/net_processing.cpp:5678-5680.
      let addrWireTs = msg.addresses[i].timestamp
      let addrNowSec = uint32(getTime().toUnix())
      na.lastSeen =
        if addrWireTs <= 100_000_000'u32 or addrWireTs > addrNowSec + 600'u32:
          addrNowSec - 5'u32 * 24'u32 * 3600'u32
        else:
          addrWireTs
      var found = false
      for ka in pm.knownAddresses:
        if ka.ip == na.ip and ka.port == na.port:
          found = true
          break
      if not found:
        pm.knownAddresses.add(na)
    # Relay to up to 2 random peers (not back to source).
    # 3F FIX: Core net_processing.cpp:5688 only relays when vAddr.size() <= 10.
    # A large addr message is a getaddr response — those are not relayed.
    # Reference: bitcoin-core/src/net_processing.cpp:5688.
    if msg.addresses.len <= AddrRelayMaxEntries and msg.addresses.len > 0:
      pm.relayAddresses(peer)
  of mkAddrV2:
    # BUG-4 FIX (W117): store all valid addrv2 addresses.  IPv4/IPv6 go into
    # knownAddresses (legacy pool); Tor v3, I2P, and CJDNS go into
    # knownAddressesV2 so they can be relayed as addrv2 to peers that want it.
    # Previously only IPv4/IPv6 were stored; Tor/I2P/CJDNS were silently dropped.
    let count = min(msg.addressesV2.len, 1000)
    # Inbound addr rate limiting — shares the SAME per-peer leaky token bucket as
    # mkAddr.  Core routes both ADDR and ADDRV2 through ProcessAddrs
    # (net_processing.cpp:4022), so addrv2 must spend from the same bucket;
    # otherwise a peer bypasses MAX_ADDR_RATE_PER_SECOND by sending addrv2.
    # Refill by elapsed_seconds * MaxAddrRatePerSecond, capped; spend one token
    # per processed addr; drop the excess for rate-limited (non-NoBan) peers.
    let nowSec = getTime().toUnix()
    if peer.addrTokenBucket < MaxAddrProcessingTokenBucket:
      if peer.addrTokenTimestamp != 0:
        let elapsed = float64(max(0'i64, nowSec - peer.addrTokenTimestamp))
        peer.addrTokenBucket = min(MaxAddrProcessingTokenBucket,
          peer.addrTokenBucket + elapsed * MaxAddrRatePerSecond)
    peer.addrTokenTimestamp = nowSec
    var rateLimited = true
    let pkey = peerKey(peer.address, peer.port)
    if pkey in pm.extendedPeers:
      let ext = pm.extendedPeers[pkey]
      if ext.noBan or ext.connType == pctManual:
        rateLimited = false
    for i in 0..<count:
      # Spend a token per processed addr; drop excess for rate-limited peers
      # (Core spends before the routability/validity filter).
      if peer.addrTokenBucket < 1.0:
        if rateLimited:
          continue
      else:
        peer.addrTokenBucket -= 1.0
      let ta = msg.addressesV2[i]
      if not ta.address.isValid():
        continue
      let legacy = toLegacyTimestampedAddr(ta)
      if legacy.isSome:
        # IPv4 or IPv6 — store in legacy pool
        var la = legacy.get()
        # DATA-GAP FIX (2026-06): carry the addrv2 wire timestamp onto the
        # stored NetAddress so getnodeaddresses emits a real `time`.
        # 3G FIX: clamp received timestamp before storing.
        # Core net_processing.cpp:5678-5680: same clamp applies to addrv2.
        # Reference: bitcoin-core/src/net_processing.cpp:5678-5680.
        let v2NowSec = uint32(getTime().toUnix())
        la.address.lastSeen =
          if la.timestamp <= 100_000_000'u32 or la.timestamp > v2NowSec + 600'u32:
            v2NowSec - 5'u32 * 24'u32 * 3600'u32
          else:
            la.timestamp
        if isRoutable(la.address.ip):
          var found = false
          for ka in pm.knownAddresses:
            if ka.ip == la.address.ip and ka.port == la.address.port:
              found = true
              break
          if not found:
            pm.knownAddresses.add(la.address)
      else:
        # Tor v3, I2P, or CJDNS — store in v2 pool
        var found = false
        for ka in pm.knownAddressesV2:
          if ka.address.networkId == ta.address.networkId and ka.port == ta.port:
            # Simple duplicate check by network type + port; deep byte comparison
            # below avoids false negatives.
            case ta.address.networkId
            of netTorV3:
              if ka.address.torv3 == ta.address.torv3:
                found = true; break
            of netI2P:
              if ka.address.i2p == ta.address.i2p:
                found = true; break
            of netCJDNS:
              if ka.address.cjdns == ta.address.cjdns:
                found = true; break
            else: discard
        if not found:
          # 3G FIX: clamp the wire timestamp before storing (Tor/I2P/CJDNS path).
          # Core net_processing.cpp:5678-5680: same clamp applies to addrv2.
          var taStored = ta
          let torNowSec = uint32(getTime().toUnix())
          if taStored.timestamp <= 100_000_000'u32 or
              taStored.timestamp > torNowSec + 600'u32:
            taStored.timestamp = torNowSec - 5'u32 * 24'u32 * 3600'u32
          pm.knownAddressesV2.add(taStored)
    # 3F FIX: Core net_processing.cpp:5688 only relays when vAddr.size() <= 10.
    # A large addrv2 message is a getaddr response — those are not relayed.
    # Reference: bitcoin-core/src/net_processing.cpp:5688.
    if msg.addressesV2.len <= AddrRelayMaxEntries and msg.addressesV2.len > 0:
      pm.relayAddresses(peer)
  of mkGetAddr:
    let addrs = pm.buildGetAddrResponse(peer)
    if addrs.len > 0:
      let response = newAddr(addrs)
      asyncSpawn peer.sendMessage(response)
  of mkFeeFilter:
    # Already handled in peer.handleMessage
    discard
  else:
    discard

proc runAsmapHealthCheck*(pm: PeerManager) =
  ## Run the ASMap health-check diagnostic against the known-address pool.
  ## Logs unique ASNs, mapped count, and unmapped count.
  ## Reference: bitcoin-core/src/netgroup.cpp NetGroupManager::ASMapHealthCheck()
  ## Call once at startup and then every ~3600 s from the main loop.
  if not pm.netGroupManager.usingAsmap:
    return
  var ips: seq[array[16, byte]]
  for na in pm.knownAddresses:
    ips.add(na.ip)
  asmapHealthCheck(pm.netGroupManager, ips)

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
