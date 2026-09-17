## Inbound P2P readiness — CHARTER "full P2P, outbound AND inbound".
##
## Control for QUEUES.md nimrod item 0. Each requirement has a regtest
## assertion that does not need mainnet:
##
##   (1) configurable bind, default 0.0.0.0 + [::], restrict via --bind
##   (2) inbound version/verack appears in getpeerinfo with inbound: true
##   (3) inbound slots are separate from outbound (flood cannot starve sync)
##   (4) half-open handshake is reaped and frees the slot
##   (5) inbound peer is served getheaders + getdata (a block) like outbound
##
## Negative control: a TCP connect that never sends version is disconnected
## on the handshake timeout and does not keep occupying an inbound slot.
##
## Default bind address (report in the commit body): 0.0.0.0 and ::
##
## Command:
##   nim c -r tests/test_inbound_p2p.nim

import unittest2
import std/[os, strutils, json, options, times, monotimes, tempfiles]
import chronos
import ../src/network/[peer, peermanager, messages]
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/rpc/server
import ../src/storage/chainstate
import ../src/nimrod as nimrod_main

const HandshakeMs = 1000

proc waitUntil(pred: proc(): bool, timeoutMs: int, label: string) =
  let t0 = getMonoTime()
  while not pred():
    if (getMonoTime() - t0).inMilliseconds > timeoutMs:
      checkpoint(label & " timeout after " & $timeoutMs & "ms")
      require false
    waitFor sleepAsync(10)

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc cannedHeader(): BlockHeader =
  BlockHeader(
    version: 1,
    prevBlock: default(BlockHash),
    merkleRoot: default(array[32, byte]),
    timestamp: 1296688602'u32,
    bits: 0x207fffff'u32,
    nonce: 2'u32
  )

proc isAllInterfacesHost(h: string): bool =
  h in ["0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0"]

# ── Raw Bitcoin P2P client that dials an already-listening node (inbound) ──

type
  InboundClient = ref object
    transp: StreamTransport
    buf: seq[byte]
    messages: seq[P2PMessage]
    closed: bool
    magic: array[4, byte]

proc parseBuf(c: InboundClient) =
  while c.buf.len >= 24:
    var r = BinaryReader(data: c.buf[0 ..< 24], pos: 0)
    let header = r.deserializeMessageHeader()
    let total = 24 + int(header.length)
    if c.buf.len < total:
      break
    let payload = c.buf[24 ..< total]
    c.buf = c.buf[total .. ^1]
    let cmd = bytesToCommand(header.command)
    try:
      c.messages.add(deserializePayload(cmd, @payload))
    except CatchableError:
      discard

proc readLoop(c: InboundClient) {.async.} =
  try:
    while c.transp != nil and not c.transp.closed:
      var tmp: array[4096, byte]
      let n = await c.transp.readOnce(addr tmp[0], tmp.len)
      if n == 0:
        c.closed = true
        return
      c.buf.add(tmp[0 ..< n])
      c.parseBuf()
  except CatchableError:
    c.closed = true

proc connectTo(c: InboundClient, host: string, port: uint16) {.async.} =
  c.transp = await connect(initTAddress(host, Port(port)))
  asyncSpawn c.readLoop()

proc sendMsg(c: InboundClient, msg: P2PMessage) {.async.} =
  if c.transp == nil:
    raise newException(IOError, "not connected")
  let data = serializeMessage(c.magic, msg)
  discard await c.transp.write(data)

proc sendVersion(c: InboundClient) {.async.} =
  let msg = newVersionMsg(
    version = 70016'u32,
    services = 9'u64,
    timestamp = getTime().toUnix(),
    nonce = 0x1122334455667788'u64,
    userAgent = "/inbound-readiness:0.0.1/",
    startHeight = 0,
    relay = true)
  await c.sendMsg(msg)

proc sendVerack(c: InboundClient) {.async.} =
  await c.sendMsg(newVerack())

proc close(c: InboundClient) {.async.} =
  c.closed = true
  if c.transp != nil:
    try:
      await c.transp.closeWait()
    except CatchableError:
      discard
    c.transp = nil

proc hasKind(c: InboundClient, k: MessageKind): bool =
  for m in c.messages:
    if m.kind == k:
      return true
  false

# ── Outbound-side mock that accepts a dial from the node under test ──

type
  MockPeerServer = ref object
    server: StreamServer
    port: uint16
    handshakeComplete: bool
    magic: array[4, byte]

proc handleMockClient(mock: MockPeerServer, transp: StreamTransport) {.async.} =
  var buf: seq[byte]
  try:
    while not transp.closed:
      var tmp: array[4096, byte]
      let n = await transp.readOnce(addr tmp[0], tmp.len)
      if n == 0:
        return
      buf.add(tmp[0 ..< n])
      while buf.len >= 24:
        var r = BinaryReader(data: buf[0 ..< 24], pos: 0)
        let header = r.deserializeMessageHeader()
        let total = 24 + int(header.length)
        if buf.len < total:
          break
        let payload = buf[24 ..< total]
        buf = buf[total .. ^1]
        let cmd = bytesToCommand(header.command)
        let msg = deserializePayload(cmd, @payload)
        if msg.kind == mkVersion:
          let reply = newVersionMsg(
            version = 70016'u32,
            services = 9'u64,
            timestamp = getTime().toUnix(),
            nonce = 0xaabbccddeeff0011'u64,
            userAgent = "/mock-outbound-target:0.0.1/",
            startHeight = 0,
            relay = true)
          discard await transp.write(serializeMessage(mock.magic, reply))
          discard await transp.write(serializeMessage(mock.magic, newVerack()))
        if msg.kind == mkVerack:
          mock.handshakeComplete = true
  except CatchableError:
    discard

proc startMock(magic: array[4, byte]): MockPeerServer =
  result = MockPeerServer(magic: magic)
  let mock = result
  proc cb(server: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
    try:
      await mock.handleMockClient(transp)
    except CatchableError:
      discard
  let ta = initTAddress("127.0.0.1", Port(0))
  result.server = createStreamServer(ta, cb, {ServerFlags.ReuseAddr})
  result.server.start()
  result.port = uint16(result.server.localAddress.port)

proc stopMock(mock: MockPeerServer) =
  if mock.server != nil:
    mock.server.stop()
    mock.server.close()
    mock.server = nil

# ── Fixtures ──

proc makePm(extraDir: string, maxInbound = 8, maxOutFull = 0,
            maxOutBlock = 0, handshakeMs = HandshakeMs,
            bindSpecs: seq[string] = @["127.0.0.1"],
            listenPort: uint16 = 0): PeerManager =
  result = newPeerManager(
    regtestParams(),
    maxOutFullRelay = maxOutFull,
    maxOutBlockRelay = maxOutBlock,
    maxIn = maxInbound,
    dataDir = extraDir)
  result.handshakeTimeoutMs = handshakeMs
  result.bindSpecs = bindSpecs
  result.listenPort = listenPort
  result.dnsSeedEnabled = false

proc listenPortOf(pm: PeerManager): uint16 =
  let live = pm.getListeningBinds()
  require live.len > 0
  live[0].port

proc inboundHandshake(pm: PeerManager, clients: var seq[
    InboundClient]): InboundClient =
  let client = InboundClient(magic: regtestParams().magic)
  clients.add(client)
  let before = pm.inboundCount
  waitFor client.connectTo("127.0.0.1", listenPortOf(pm))
  waitUntil(proc(): bool = pm.inboundCount > before, 2000, "accept inbound")
  waitFor client.sendVersion()
  waitUntil(proc(): bool = client.hasKind(mkVersion), 3000, "inbound version")
  waitFor client.sendVerack()
  waitUntil(proc(): bool = client.hasKind(mkVerack), 3000, "inbound verack")
  waitUntil(proc(): bool =
    for p in pm.getReadyPeers():
      if p.direction == pdInbound:
        return true
    false, 3000, "inbound established")
  client

proc getpeerinfo(pm: PeerManager): JsonNode =
  let rpc = RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false,
    peerManager: pm,
    chainState: ChainState(bestHeight: 0'i32),
    params: regtestParams())
  rpc.handleMethod("getpeerinfo", %*[])

proc registerServeHandlers(pm: PeerManager): BlockHash =
  let header = cannedHeader()
  let genesisHash = hashOf(header)
  let blk = Block(header: header, txs: @[])
  pm.onMessage = proc(p: Peer, msg: P2PMessage): Future[void] {.async.} =
    case msg.kind
    of mkGetHeaders:
      await p.sendMessage(newHeaders(@[header]))
    of mkGetData:
      for item in msg.getData:
        if item.invType == invBlock or item.invType == invWitnessBlock:
          await p.sendMessage(newBlockMsg(blk))
    else:
      discard
  genesisHash

type
  TestNode = ref object
    pm*: PeerManager
    clients*: seq[InboundClient]
    dir: string

proc startNode(maxInbound = 8, maxOutFull = 0,
               bindSpecs: seq[string] = @["127.0.0.1"],
               handshakeMs = HandshakeMs): TestNode =
  result = TestNode(dir: createTempDir("nimrod-inbound-", ""), clients: @[])
  result.pm = makePm(result.dir, maxInbound = maxInbound, maxOutFull = maxOutFull,
                     handshakeMs = handshakeMs, bindSpecs = bindSpecs)
  waitFor result.pm.startListeners(bindSpecs, 0)

proc cleanup(n: TestNode) =
  for c in n.clients:
    try:
      waitFor c.close()
    except CatchableError:
      discard
  n.pm.stopListener()
  waitFor sleepAsync(20)
  try:
    removeDir(n.dir)
  except OSError:
    discard



# =============================================================================

suite "inbound P2P (1) bind configuration":

  test "default bind hosts are all-interfaces IPv4 and IPv6, not loopback":
    check DEFAULT_BIND_HOSTS.len == 2
    check DEFAULT_BIND_HOSTS[0] == "0.0.0.0"
    check DEFAULT_BIND_HOSTS[1] == "::"
    check "127.0.0.1" notin DEFAULT_BIND_HOSTS
    check "::1" notin DEFAULT_BIND_HOSTS

  test "parses IPv4, IPv4:port, bracketed IPv6, and bare IPv6":
    let a = parseBindSpec("0.0.0.0", 8333'u16)
    check a.host == "0.0.0.0"
    check a.port == 8333'u16
    let b = parseBindSpec("127.0.0.1:8334", 8333'u16)
    check b.host == "127.0.0.1"
    check b.port == 8334'u16
    let c = parseBindSpec("[::]", 8333'u16)
    check c.host == "::"
    check c.port == 8333'u16
    let d = parseBindSpec("[::1]:18444", 8333'u16)
    check d.host == "::1"
    check d.port == 18444'u16
    let e = parseBindSpec("::", 8333'u16)
    check e.host == "::"
    check e.port == 8333'u16

  test "parseArgs --bind is repeatable and --maxconnections is parsed":
    let parsed = nimrod_main.parseArgs(@[
      "--bind=127.0.0.1",
      "--bind=[::1]",
      "--maxconnections=20"
    ])
    check parsed.config.bindSpecs.len == 2
    check parsed.config.bindSpecs[0] == "127.0.0.1"
    check parsed.config.bindSpecs[1] == "[::1]"
    check parsed.config.maxConnections == 20

  test "parseArgs default bind is unset so the listener uses 0.0.0.0 and [::]":
    let parsed = nimrod_main.parseArgs(@[])
    check parsed.config.bindSpecs.len == 0
    check parsed.config.listenEnabled == true
    check parsed.config.maxConnections == DEFAULT_MAX_CONNECTIONS

  test "default getBindAddresses is 0.0.0.0 and :: on the listen port":
    let dir = createTempDir("nimrod-inbound-bind-", "")
    defer: removeDir(dir)
    let pm = newPeerManager(regtestParams(), dataDir = dir)
    pm.listenPort = 18444'u16
    let addrs = pm.getBindAddresses()
    check addrs.len == 2
    check addrs[0].host == "0.0.0.0"
    check addrs[0].port == 18444'u16
    check addrs[1].host == "::"
    check addrs[1].port == 18444'u16

  test "--bind=127.0.0.1 restricts the listener to loopback":
    let n = startNode(bindSpecs = @["127.0.0.1"])
    defer: n.cleanup()
    let addrs = n.pm.getBindAddresses()
    check addrs.len == 1
    check addrs[0].host == "127.0.0.1"
    let live = n.pm.getListeningBinds()
    check live.len >= 1
    for b in live:
      check b.host == "127.0.0.1"
      check b.port > 0'u16

  test "default listen binds all interfaces, not loopback":
    let dir = createTempDir("nimrod-inbound-default-", "")
    let pm = newPeerManager(regtestParams(), dataDir = dir)
    pm.handshakeTimeoutMs = HandshakeMs
    pm.dnsSeedEnabled = false
    try:
      waitFor pm.startListeners(@[], 0)
      let live = pm.getListeningBinds()
      check live.len >= 1
      var hosts: seq[string] = @[]
      for b in live:
        hosts.add(b.host)
      var sawAll = false
      for h in hosts:
        if isAllInterfacesHost(h):
          sawAll = true
      check sawAll
      check "127.0.0.1" notin hosts
      check "::1" notin hosts
      let port = live[0].port
      let probe = waitFor connect(initTAddress("127.0.0.1", Port(port)))
      check not probe.closed
      waitFor probe.closeWait()
    finally:
      pm.stopListener()
      waitFor sleepAsync(20)
      try: removeDir(dir)
      except OSError: discard

# =============================================================================

suite "inbound P2P (2)(5) handshake + getpeerinfo + serve":

  test "inbound version/verack appears in getpeerinfo with inbound:true and is served a block":
    let n = startNode(maxInbound = 4, maxOutFull = 0)
    defer: n.cleanup()
    let genesisHash = registerServeHandlers(n.pm)
    let client = inboundHandshake(n.pm, n.clients)

    let info = getpeerinfo(n.pm)
    check info.kind == JArray
    check info.len >= 1
    var inbound: JsonNode
    for p in info:
      if p{"inbound"}.getBool():
        inbound = p
        break
    check inbound != nil
    check inbound["inbound"].getBool() == true
    check inbound["connection_type"].getStr() == "inbound"
    check inbound["subver"].getStr() == "/inbound-readiness:0.0.1/"

    waitFor client.sendMsg(newGetHeaders(70016'u32, @[], default(array[32, byte])))
    waitUntil(proc(): bool = client.hasKind(mkHeaders), 3000, "served headers")
    var nHeaders = 0
    for m in client.messages:
      if m.kind == mkHeaders:
        nHeaders = m.headers.len
    check nHeaders >= 1

    waitFor client.sendMsg(newGetData(@[InvVector(invType: invBlock,
        hash: array[32, byte](genesisHash))]))
    waitUntil(proc(): bool = client.hasKind(mkBlock), 3000, "served block")
    check client.hasKind(mkBlock)

# =============================================================================

suite "inbound P2P (4) half-open handshake reap":

  test "half-open inbound is reaped on handshake timeout and frees the slot":
    let n = startNode(maxInbound = 2, maxOutFull = 0)
    defer: n.cleanup()
    let client = InboundClient(magic: regtestParams().magic)
    n.clients.add(client)
    waitFor client.connectTo("127.0.0.1", listenPortOf(n.pm))
    waitUntil(proc(): bool = n.pm.inboundCount == 1, 2000, "slot held")
    check n.pm.inboundCount == 1

    waitUntil(proc(): bool = n.pm.inboundCount == 0, HandshakeMs + 1500, "slot freed")
    check n.pm.inboundCount == 0
    check n.pm.getReadyPeers().len == 0
    let info = getpeerinfo(n.pm)
    check info.len == 0

# =============================================================================

suite "inbound P2P (3) inbound slots separate from outbound":

  test "inbound flood cannot starve an outbound slot":
    putEnv("NIMROD_BIP324_V2_OUTBOUND", "0")
    let n = startNode(maxInbound = 2, maxOutFull = 1)
    defer: n.cleanup()
    let mock = startMock(regtestParams().magic)
    try:
      discard inboundHandshake(n.pm, n.clients)
      discard inboundHandshake(n.pm, n.clients)
      check n.pm.inboundCount == 2

      let third = InboundClient(magic: regtestParams().magic)
      n.clients.add(third)
      waitFor third.connectTo("127.0.0.1", listenPortOf(n.pm))
      waitFor sleepAsync(80)
      check n.pm.inboundCount <= 2

      let ok = waitFor n.pm.connectToPeerWithType("127.0.0.1", mock.port,
                                                  pctFullRelay,
                                                  skipReachability = true)
      check ok
      waitUntil(proc(): bool = mock.handshakeComplete or n.pm.outboundFullRelayCount == 1,
                3000, "outbound handshake")
      check n.pm.outboundFullRelayCount == 1
      check n.pm.inboundCount <= 2
    finally:
      stopMock(mock)
    delEnv("NIMROD_BIP324_V2_OUTBOUND")

  test "max_inbound is reserved from max_peers - max_outbound when unset":
    check inboundSlotsFor(20, 8) == 12
    check inboundSlotsFor(125, 8 + 2 + 1) == 114
    let budget = connectionBudget(125)
    check budget.fullRelay == 8
    check budget.blockRelay == 2
    check budget.inbound == 114
    check DEFAULT_MAX_CONNECTIONS == 125
