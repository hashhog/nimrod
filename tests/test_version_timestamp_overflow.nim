## VERSION timestamp at the int64 extremes must not crash the node.
##
## Security audit 2026-10-31, C1: the three places that record a peer's
## clock offset computed `versionData.timestamp - getTime().toUnix()` on the
## raw wire int64.  A stranger's very first message, `version` with
## `timestamp = low(int64)`, underflows that subtraction; with overflow checks
## on (-d:release keeps them) Nim raises OverflowDefect, chronos re-raises it
## out of poll(), and the handshake/peer loops only catch CatchableError, so
## the whole process exits.  One pre-handshake packet, no proof of work.
##
## Core (net_processing.cpp:3788) computes
##   m_time_offset = NodeSeconds{std::chrono::seconds{nTime}} - Now<NodeSeconds>()
## and never aborts; the offset only feeds warnings and getpeerinfo.
##
## The three sites are each driven here:
##   * performHandshake, inbound  — real PeerManager listener + raw client
##   * performHandshake, outbound — raw server answering our dial
##   * handleMessage(mkVersion)   — the legacy dispatcher
## On the unfixed code every low(int64) case dies with OverflowDefect, which
## each test catches and reports as a failure by name.
##
## Command:
##   nim c -r tests/test_version_timestamp_overflow.nim

import unittest2
import std/[times, monotimes, tempfiles, os, tables]
import chronos
import ../src/network/[peer, peermanager, messages]
import ../src/consensus/params
import ../src/primitives/serialize

const HandshakeMs = 2000

proc waitUntil(pred: proc(): bool, timeoutMs: int): bool =
  let t0 = getMonoTime()
  while not pred():
    if (getMonoTime() - t0).inMilliseconds > timeoutMs:
      return false
    waitFor sleepAsync(10)
  true

# ── raw client (dials the PeerManager listener) ─────────────────────────────

type
  RawClient = ref object
    transp: StreamTransport
    buf: seq[byte]
    messages: seq[P2PMessage]
    closed: bool

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

proc has(c: RawClient, k: MessageKind): bool =
  for m in c.messages:
    if m.kind == k: return true
  false

proc versionAt(ts: int64): P2PMessage =
  newVersionMsg(version = 70016'u32, services = NodeNetwork or NodeWitness,
                timestamp = ts, nonce = 0x7157_7157'u64,
                userAgent = "/ts-overflow:0.1/", startHeight = 0, relay = true)

proc inboundPeer(pm: PeerManager): Peer =
  for p in pm.peers.values:
    if p.direction == pdInbound: return p
  nil

proc inboundHandshake(ts: int64): tuple[ok: bool, offset: int64, err: string] =
  ## Inbound: a stranger dials us and sends VERSION(ts).  Returns whether the
  ## handshake completed (we answered verack and the peer went ready) and the
  ## recorded offset.  An OverflowDefect escaping the loop is reported in err.
  let dir = createTempDir("nimrod-ts-overflow-", "")
  let pm = newPeerManager(regtestParams(), maxOutFullRelay = 0,
                          maxOutBlockRelay = 0, maxIn = 8, dataDir = dir)
  pm.handshakeTimeoutMs = HandshakeMs
  pm.bindSpecs = @["127.0.0.1"]
  pm.dnsSeedEnabled = false
  var c: RawClient
  try:
    try:
      waitFor pm.startListeners(@["127.0.0.1"], 0)
      c = RawClient()
      c.transp = waitFor connect(initTAddress("127.0.0.1",
                                 Port(pm.getListeningBinds()[0].port)))
      asyncSpawn c.readLoop()
      discard waitFor c.transp.write(
        serializeMessage(regtestParams().magic, versionAt(ts)))
      let gotVerack = waitUntil(proc(): bool = c.has(mkVerack), 3000)
      if gotVerack:
        discard waitFor c.transp.write(
          serializeMessage(regtestParams().magic, newVerack()))
      let ready = gotVerack and waitUntil(proc(): bool =
        (let p = pm.inboundPeer(); not p.isNil and p.handshakeComplete), 3000)
      let p = pm.inboundPeer()
      result = (ok: ready, offset: (if p.isNil: 0'i64 else: p.timeOffset), err: "")
    except Defect as e:
      result = (ok: false, offset: 0'i64, err: $e.name & ": " & e.msg)
  finally:
    if c != nil and c.transp != nil:
      try: waitFor c.transp.closeWait()
      except CatchableError, Defect: discard
    try: pm.stopListener()
    except CatchableError, Defect: discard
    try: waitFor sleepAsync(20)
    except CatchableError, Defect: discard
    try: removeDir(dir) except OSError: discard

proc outboundHandshake(ts: int64): tuple[ok: bool, offset: int64, err: string] =
  ## Outbound: we dial a raw server that answers with VERSION(ts) + VERACK.
  proc onConn(srv: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
    try:
      let magic = regtestParams().magic
      discard await transp.write(serializeMessage(magic, versionAt(ts)))
      discard await transp.write(serializeMessage(magic, newVerack()))
      # Hold the socket open; drain whatever we are sent.
      var tmp: array[4096, byte]
      while true:
        let n = await transp.readOnce(addr tmp[0], tmp.len)
        if n == 0: break
    except CatchableError:
      discard
    try: await transp.closeWait()
    except CatchableError: discard

  let server = createStreamServer(initTAddress("127.0.0.1", Port(0)), onConn,
                                  {ServerFlags.ReuseAddr})
  server.start()
  let peer = newPeer("127.0.0.1", uint16(server.local.port), regtestParams(),
                     pdOutbound)
  peer.handshakeTimeoutMs = HandshakeMs
  peer.v2OutboundDisabled = true   # the raw server speaks v1 only
  try:
    try:
      doAssert waitFor peer.connect()
      waitFor peer.performHandshake(0'i32)
      result = (ok: peer.handshakeComplete, offset: peer.timeOffset, err: "")
    except CatchableError as e:
      result = (ok: false, offset: peer.timeOffset, err: $e.name & ": " & e.msg)
    except Defect as e:
      result = (ok: false, offset: 0'i64, err: $e.name & ": " & e.msg)
  finally:
    try: waitFor peer.disconnect()
    except CatchableError, Defect: discard
    server.stop()
    try: waitFor server.closeWait()
    except CatchableError, Defect: discard

proc dispatchVersion(ts: int64): tuple[offset: int64, err: string] =
  ## handleMessage(mkVersion) on an unconnected peer: the offset is recorded
  ## before the verack send, which then fails with the catchable PeerError
  ## "not connected".  The defect, if any, comes first.
  let peer = newPeer("127.0.0.1", 18444, regtestParams(), pdInbound)
  try:
    waitFor peer.handleMessage(versionAt(ts))
    result = (offset: peer.timeOffset, err: "")
  except CatchableError:
    result = (offset: peer.timeOffset, err: "")
  except Defect as e:
    result = (offset: 0'i64, err: $e.name & ": " & e.msg)

suite "version timestamp overflow (audit C1)":

  test "inbound VERSION with timestamp low(int64) completes the handshake":
    let r = inboundHandshake(low(int64))
    checkpoint("err=" & r.err)
    check r.err == ""
    check r.ok
    check r.offset == low(int64)       # saturated, sign preserved

  test "inbound VERSION with timestamp high(int64) completes the handshake":
    let r = inboundHandshake(high(int64))
    checkpoint("err=" & r.err)
    check r.err == ""
    check r.ok
    check r.offset > 0

  test "inbound VERSION with the current time completes the handshake (control)":
    let r = inboundHandshake(getTime().toUnix())
    check r.err == ""
    check r.ok
    check abs(r.offset) <= 5

  test "outbound peer answering VERSION with timestamp low(int64) does not crash":
    let r = outboundHandshake(low(int64))
    checkpoint("err=" & r.err)
    check r.ok
    check r.offset == low(int64)

  test "outbound peer answering VERSION with timestamp high(int64) does not crash":
    let r = outboundHandshake(high(int64))
    checkpoint("err=" & r.err)
    check r.ok
    check r.offset > 0

  test "outbound VERSION with the current time completes the handshake (control)":
    let r = outboundHandshake(getTime().toUnix())
    checkpoint("err=" & r.err)
    check r.ok
    check abs(r.offset) <= 5

  test "handleMessage(version) with timestamp low(int64) saturates the offset":
    let r = dispatchVersion(low(int64))
    checkpoint("err=" & r.err)
    check r.err == ""
    check r.offset == low(int64)

  test "handleMessage(version) with timestamp high(int64) records a positive offset":
    let r = dispatchVersion(high(int64))
    check r.err == ""
    check r.offset > 0

  test "handleMessage(version) offsets for ordinary timestamps are exact":
    let now = getTime().toUnix()
    let r = dispatchVersion(now - 3600)
    check r.err == ""
    check r.offset in -3602'i64 .. -3598'i64
