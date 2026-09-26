## Handshake Core parity — inbound/outbound VERSION..VERACK behaviour.
##
## Bitcoin Core (net_processing.cpp):
##   * rejects a peer only below MIN_PEER_PROTO_VERSION = 31800 (:3619);
##   * holds only OUTBOUND full-relay/block-relay peers to the desirable
##     services (ExpectServicesFromConn, :3609) — never inbound;
##   * between VERSION and VERACK processes VERACK / WTXIDRELAY / SENDADDRV2 /
##     SENDTXRCNCL / SENDHEADERS (:3896) / SENDCMPCT (:3901) and logs+ignores
##     everything else ("Unsupported message prior to verack", :4010) — no
##     disconnect, no misbehaviour, no count cap; feefilter is NOT applied;
##   * gates its own feature messages on the peer's version (sendheaders
##     70012, feefilter 70013, sendcmpct 70014, wtxidrelay/sendaddrv2 70016);
##   * requests blocks only from peers that CanServeWitnesses (:1166).
##
## The socket tests drive a real PeerManager listener with a raw client.
##
## Command:
##   nim c -r tests/test_handshake_core_parity.nim

import unittest2
import std/[times, monotimes, tempfiles, os, tables]
import chronos
import ../src/network/[peer, peermanager, messages]
import ../src/consensus/params
import ../src/primitives/[types, serialize]

const HandshakeMs = 2000

proc waitUntil(pred: proc(): bool, timeoutMs: int): bool =
  let t0 = getMonoTime()
  while not pred():
    if (getMonoTime() - t0).inMilliseconds > timeoutMs:
      return false
    waitFor sleepAsync(10)
  true

proc settle(ms: int) =
  waitFor sleepAsync(ms)

# ── raw client ──────────────────────────────────────────────────────────────

type
  RawClient = ref object
    transp: StreamTransport
    buf: seq[byte]
    messages: seq[P2PMessage]
    closed: bool
    magic: array[4, byte]

proc parseBuf(c: RawClient) =
  while c.buf.len >= 24:
    var r = BinaryReader(data: c.buf[0 ..< 24], pos: 0)
    let header = r.deserializeMessageHeader()
    let total = 24 + int(header.length)
    if c.buf.len < total:
      break
    let payload = c.buf[24 ..< total]
    c.buf = c.buf[total .. ^1]
    try:
      c.messages.add(deserializePayload(bytesToCommand(header.command), @payload))
    except CatchableError:
      discard

proc readLoop(c: RawClient) {.async.} =
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

proc send(c: RawClient, msg: P2PMessage) =
  discard waitFor c.transp.write(serializeMessage(c.magic, msg))

proc has(c: RawClient, k: MessageKind): bool =
  for m in c.messages:
    if m.kind == k: return true
  false

proc close(c: RawClient) =
  c.closed = true
  if c.transp != nil:
    try: waitFor c.transp.closeWait()
    except CatchableError: discard
    c.transp = nil

# ── node fixture ────────────────────────────────────────────────────────────

type TestNode = ref object
  pm: PeerManager
  dir: string
  clients: seq[RawClient]

proc startNode(): TestNode =
  result = TestNode(dir: createTempDir("nimrod-hs-parity-", ""))
  result.pm = newPeerManager(regtestParams(), maxOutFullRelay = 0,
                             maxOutBlockRelay = 0, maxIn = 8,
                             dataDir = result.dir)
  result.pm.handshakeTimeoutMs = HandshakeMs
  result.pm.bindSpecs = @["127.0.0.1"]
  result.pm.dnsSeedEnabled = false
  waitFor result.pm.startListeners(@["127.0.0.1"], 0)

proc cleanup(n: TestNode) =
  for c in n.clients: c.close()
  n.pm.stopListener()
  settle(20)
  try: removeDir(n.dir) except OSError: discard

proc dial(n: TestNode): RawClient =
  let c = RawClient(magic: regtestParams().magic)
  n.clients.add(c)
  c.transp = waitFor connect(initTAddress("127.0.0.1",
                             Port(n.pm.getListeningBinds()[0].port)))
  asyncSpawn c.readLoop()
  c

proc versionMsg(version: uint32, services: uint64): P2PMessage =
  newVersionMsg(version = version, services = services,
                timestamp = getTime().toUnix(), nonce = 0x5151515151'u64,
                userAgent = "/hs-parity:0.1/", startHeight = 0, relay = true)

proc inboundPeer(n: TestNode): Peer =
  for p in n.pm.peers.values:
    if p.direction == pdInbound: return p
  nil

proc inboundReady(n: TestNode): bool =
  for p in n.pm.getReadyPeers():
    if p.direction == pdInbound: return true
  false

# ── socket tests ────────────────────────────────────────────────────────────

suite "handshake Core parity (socket)":

  test "inbound VERSION(70002) completes the handshake":
    # Core MIN_PEER_PROTO_VERSION = 31800; master dropped this peer with
    # "obsolete protocol version: 70002 < 70015".
    let n = startNode()
    try:
      let c = n.dial()
      c.send(versionMsg(70002'u32, NodeNetwork))  # pre-segwit: no NODE_WITNESS
      check waitUntil(proc(): bool = c.has(mkVerack), 3000)
      c.send(newVerack())
      check waitUntil(proc(): bool = n.inboundReady(), 3000)
      settle(HandshakeMs + 500)   # past the handshake timeout: still connected
      check not c.closed
      check n.inboundReady()
      # Never sent a message a 70002 peer cannot parse (Core version gates).
      check not c.has(mkWtxidRelay)
      check not c.has(mkSendAddrV2)
      check not c.has(mkSendHeaders)
      check not c.has(mkSendCmpct)
      check not c.has(mkFeeFilter)
      # A non-witness peer is kept, but is not a block-download peer.
      let p = n.inboundPeer()
      check not p.isNil
      check p.isNil or not p.canServeWitnesses()
      check n.pm.getBlockDownloadPeers().len == 0
    finally:
      n.cleanup()

  test "pre-verack sendheaders is recorded and does not disconnect":
    let n = startNode()
    try:
      let c = n.dial()
      c.send(versionMsg(70016'u32, NodeNetwork or NodeWitness))
      check waitUntil(proc(): bool = c.has(mkVerack), 3000)
      c.send(newSendHeaders())
      settle(200)
      check not c.closed
      c.send(newVerack())
      check waitUntil(proc(): bool = n.inboundReady(), 3000)
      let p = n.inboundPeer()
      check not p.isNil
      check (not p.isNil) and p.sendHeaders
      settle(300)
      check not c.closed
      # witness-capable peer IS a block-download peer
      check n.pm.getBlockDownloadPeers().len == 1
    finally:
      n.cleanup()

  test "pre-verack ping and inv are ignored and do not disconnect":
    let n = startNode()
    try:
      let c = n.dial()
      c.send(versionMsg(70016'u32, NodeNetwork or NodeWitness))
      check waitUntil(proc(): bool = c.has(mkVerack), 3000)
      c.send(newPing(7'u64))
      c.send(newInv(@[InvVector(invType: invTx, hash: default(array[32, byte]))]))
      settle(300)
      check not c.closed
      c.send(newVerack())
      check waitUntil(proc(): bool = n.inboundReady(), 3000)
      settle(300)
      check not c.closed
      # Ignored, not processed: Core does not answer a pre-verack ping.
      check not c.has(mkPong)
    finally:
      n.cleanup()

  test "more than 20 pre-verack messages (old cap) do not disconnect":
    let n = startNode()
    try:
      let c = n.dial()
      c.send(versionMsg(70016'u32, NodeNetwork or NodeWitness))
      check waitUntil(proc(): bool = c.has(mkVerack), 3000)
      for i in 0 ..< 30:
        c.send(newPing(uint64(i)))
      c.send(newVerack())
      check waitUntil(proc(): bool = n.inboundReady(), 3000)
      check not c.closed
    finally:
      n.cleanup()

# ── outbound: services required only for outbound connections we pick ──────

type Mock = ref object
  server: StreamServer
  port: uint16
  services: uint64
  gotVerack: bool

proc serveMock(m: Mock, transp: StreamTransport) {.async.} =
  let magic = regtestParams().magic
  var buf: seq[byte]
  try:
    while not transp.closed:
      var tmp: array[4096, byte]
      let n = await transp.readOnce(addr tmp[0], tmp.len)
      if n == 0: return
      buf.add(tmp[0 ..< n])
      while buf.len >= 24:
        var r = BinaryReader(data: buf[0 ..< 24], pos: 0)
        let h = r.deserializeMessageHeader()
        let total = 24 + int(h.length)
        if buf.len < total: break
        let payload = buf[24 ..< total]
        buf = buf[total .. ^1]
        let msg = deserializePayload(bytesToCommand(h.command), @payload)
        if msg.kind == mkVersion:
          discard await transp.write(serializeMessage(magic,
            versionMsg(70016'u32, m.services)))
          discard await transp.write(serializeMessage(magic, newVerack()))
        elif msg.kind == mkVerack:
          m.gotVerack = true
  except CatchableError:
    discard

proc startMock(services: uint64): Mock =
  result = Mock(services: services)
  let m = result
  proc cb(server: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
    try: await m.serveMock(transp)
    except CatchableError: discard
  result.server = createStreamServer(initTAddress("127.0.0.1", Port(0)), cb,
                                     {ServerFlags.ReuseAddr})
  result.server.start()
  result.port = uint16(result.server.localAddress.port)

proc stop(m: Mock) =
  m.server.stop()
  m.server.close()

suite "handshake Core parity (outbound services)":

  test "outbound full-relay peer without NODE_WITNESS is refused":
    let m = startMock(NodeNetwork)
    let dir = createTempDir("nimrod-hs-out-", "")
    let pm = newPeerManager(regtestParams(), maxOutFullRelay = 2,
                            maxOutBlockRelay = 0, maxIn = 0, dataDir = dir)
    pm.handshakeTimeoutMs = HandshakeMs
    pm.dnsSeedEnabled = false
    let w = startMock(NodeNetwork or NodeWitness)
    # v1 only: these mocks do not speak BIP-324 (else the dial fails on
    # the v2 timeout and the refusal would be measuring nothing).
    pm.markV1Only("127.0.0.1", m.port)
    pm.markV1Only("127.0.0.1", w.port)
    try:
      let ok = waitFor pm.connectToPeerWithType("127.0.0.1", m.port,
                                                pctFullRelay,
                                                skipReachability = true)
      check not ok
      check pm.outboundFullRelayCount == 0
      # Control: the identical dial to a witness-capable mock succeeds, so
      # the refusal above is the services check, not the transport.
      let okW = waitFor pm.connectToPeerWithType("127.0.0.1", w.port,
                                                 pctFullRelay,
                                                 skipReachability = true)
      check okW
      check pm.outboundFullRelayCount == 1
    finally:
      m.stop()
      w.stop()
      try: removeDir(dir) except OSError: discard

  test "manual (addnode) peer without NODE_WITNESS is kept; witness full-relay is kept":
    let m = startMock(NodeNetwork)
    let w = startMock(NodeNetwork or NodeWitness)
    let dir = createTempDir("nimrod-hs-out-", "")
    let pm = newPeerManager(regtestParams(), maxOutFullRelay = 2,
                            maxOutBlockRelay = 0, maxIn = 0, dataDir = dir)
    pm.handshakeTimeoutMs = HandshakeMs
    pm.dnsSeedEnabled = false
    pm.markV1Only("127.0.0.1", m.port)
    pm.markV1Only("127.0.0.1", w.port)
    try:
      check waitFor pm.connectToPeerWithType("127.0.0.1", m.port, pctManual,
                                             skipReachability = true)
      check waitFor pm.connectToPeerWithType("127.0.0.1", w.port, pctFullRelay,
                                             skipReachability = true)
      check pm.getReadyPeers().len == 2
      # only the witness peer may be asked for blocks
      let dl = pm.getBlockDownloadPeers()
      check dl.len == 1
      check dl.len == 1 and dl[0].port == w.port
    finally:
      m.stop()
      w.stop()
      try: removeDir(dir) except OSError: discard

# ── pure-logic tests ────────────────────────────────────────────────────────

proc readyPeer(version: uint32): Peer =
  result = newPeer("127.0.0.1", 18444, regtestParams(), pdInbound)
  result.version = version
  result.versionReceived = true

suite "handshake Core parity (logic)":

  test "minimum peer protocol version is Core's 31800":
    check MinProtocolVersion == 31800'u32

  test "pre-verack feefilter is ignored, not applied":
    let p = readyPeer(70016)
    check not p.processPreVerackMessage(newFeeFilter(5000'u64))
    check p.feeFilterRate == 0'u64

  test "pre-verack sendcmpct v2 is recorded, other versions dropped":
    let p = readyPeer(70016)
    discard p.processPreVerackMessage(P2PMessage(kind: mkSendCmpct,
      sendCmpct: SendCmpctMsg(announce: true, version: 1)))
    check p.peerCmpctVersion == 0'u64
    discard p.processPreVerackMessage(P2PMessage(kind: mkSendCmpct,
      sendCmpct: SendCmpctMsg(announce: true, version: 2)))
    check p.peerCmpctVersion == 2'u64
    check p.peerHighBandwidth

  test "pre-verack wtxidrelay honoured only for version >= 70016":
    let old = readyPeer(70015)
    discard old.processPreVerackMessage(newWtxidRelay())
    check not old.wtxidRelay
    let cur = readyPeer(70016)
    discard cur.processPreVerackMessage(newWtxidRelay())
    check cur.wtxidRelay

  test "verack ends the pre-verack phase; everything else never raises":
    let p = readyPeer(70016)
    for m in [newPing(1'u64), newVersionMsg(), newGetAddr(), newSendAddrV2()]:
      check not p.processPreVerackMessage(m)
    check p.wantsAddrV2
    check p.processPreVerackMessage(newVerack())
    check p.verackReceived

  test "desirable services apply to outbound selection only":
    check hasAllDesirableServiceFlags(NodeNetwork or NodeWitness)
    check hasAllDesirableServiceFlags(NodeNetworkLimited or NodeWitness)
    check not hasAllDesirableServiceFlags(NodeNetwork)
    check not hasAllDesirableServiceFlags(NodeWitness)
    check not hasAllDesirableServiceFlags(0'u64)

  test "MSG_BLOCK / MSG_TX are served without witness data":
    # A segwit tx: serialized with witness it carries the 0x00 0x01 marker.
    var tx = Transaction(version: 2, lockTime: 0)
    tx.inputs = @[TxIn(prevOut: OutPoint(vout: 0), scriptSig: @[], sequence: 0xffffffff'u32)]
    tx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])]
    tx.witnesses = @[@[@[0x01'u8, 0x02]]]
    let withW = serialize(tx, includeWitness = true)
    let noW = serialize(tx, includeWitness = false)
    check withW.len > noW.len
    let magic = regtestParams().magic
    var m = newTxMsg(tx)
    let fullWire = serializeMessage(magic, m)
    m.txNoWitness = true
    let strippedWire = serializeMessage(magic, m)
    check fullWire.len - 24 == withW.len
    check strippedWire.len - 24 == noW.len
    var b = newBlockMsg(Block(header: BlockHeader(), txs: @[tx]))
    let blkFull = serializeMessage(magic, b)
    b.blkNoWitness = true
    let blkStripped = serializeMessage(magic, b)
    check blkFull.len - blkStripped.len == withW.len - noW.len
