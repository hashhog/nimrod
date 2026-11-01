## VERSION user agent is capped at 256 bytes (Core MAX_SUBVERSION_LENGTH).
##
## Security audit 2026-10-31, H2: `readVersionMsg` read the user agent with a
## plain `readVarString`, bounded only by the 4 MB payload cap, and
## performHandshake logged it in full at INF before the handshake completed.
## Twenty pre-handshake connections wrote 80 MB of log.
##
## Core (net_processing.cpp:3636) reads it as
##   vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
## and LimitedStringFormatter (serialize.h:617) throws "String length limit
## exceeded" as soon as the CompactSize length is above 256, before reading
## any of the string.  The VERSION is then never processed.
##
## Command:
##   nim c -r tests/test_version_useragent_cap.nim

import unittest2
import std/[monotimes, times, tempfiles, os, tables, strutils]
import chronos
import ../src/network/[peer, peermanager, messages]
import ../src/consensus/params
import ../src/primitives/[types, serialize]

const
  HandshakeMs = 2000
  CoreMaxSubversionLength = 256  # net.h MAX_SUBVERSION_LENGTH; local so the
                                 # file builds (and fails by name) on base

proc versionWithUa(ua: string): P2PMessage =
  newVersionMsg(version = 70016'u32, services = NodeNetwork or NodeWitness,
                timestamp = getTime().toUnix(), nonce = 0x5ab5_5ab5'u64,
                userAgent = ua, startHeight = 0, relay = true)

proc versionPayload(ua: string): seq[byte] =
  var w = BinaryWriter()
  w.writeVersionMsg(versionWithUa(ua).version)
  w.data

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

proc readyInbound(pm: PeerManager): Peer =
  for p in pm.peers.values:
    if p.direction == pdInbound and p.handshakeComplete: return p
  nil

proc inboundHandshake(ua: string): tuple[answered, ready, closed: bool, ua: string] =
  ## A stranger dials us and sends VERSION(ua).  `answered` = we replied with
  ## our own VERSION or VERACK; `ready` = the peer completed the handshake;
  ## `closed` = we dropped the socket.
  let dir = createTempDir("nimrod-ua-cap-", "")
  let pm = newPeerManager(regtestParams(), maxOutFullRelay = 0,
                          maxOutBlockRelay = 0, maxIn = 8, dataDir = dir)
  pm.handshakeTimeoutMs = HandshakeMs
  pm.bindSpecs = @["127.0.0.1"]
  pm.dnsSeedEnabled = false
  var c: RawClient
  try:
    waitFor pm.startListeners(@["127.0.0.1"], 0)
    c = RawClient()
    c.transp = waitFor connect(initTAddress("127.0.0.1",
                               Port(pm.getListeningBinds()[0].port)))
    asyncSpawn c.readLoop()
    discard waitFor c.transp.write(
      serializeMessage(regtestParams().magic, versionWithUa(ua)))
    # Either we answer with verack, or we drop the connection.
    discard waitUntil(proc(): bool = c.has(mkVerack) or c.closed, 3000)
    if c.has(mkVerack):
      discard waitFor c.transp.write(
        serializeMessage(regtestParams().magic, newVerack()))
      discard waitUntil(proc(): bool = not pm.readyInbound().isNil, 3000)
    let p = pm.readyInbound()
    result = (answered: c.has(mkVersion) or c.has(mkVerack),
              ready: not p.isNil, closed: c.closed,
              ua: (if p.isNil: "" else: p.userAgent))
  finally:
    if c != nil and c.transp != nil:
      try: waitFor c.transp.closeWait()
      except CatchableError: discard
    try: pm.stopListener()
    except CatchableError: discard
    try: waitFor sleepAsync(20)
    except CatchableError: discard
    try: removeDir(dir) except OSError: discard

suite "VERSION user agent cap (Core MAX_SUBVERSION_LENGTH = 256)":

  test "a 256-byte user agent deserializes":
    let ua = repeat('A', CoreMaxSubversionLength)
    let msg = deserializePayload("version", versionPayload(ua))
    check msg.kind == mkVersion
    check msg.version.userAgent == ua

  test "a 257-byte user agent is rejected at deserialization":
    var raised = false
    var emsg = ""
    try:
      discard deserializePayload("version", versionPayload(repeat('A', CoreMaxSubversionLength + 1)))
    except SerializationError as e:
      raised = true
      emsg = e.msg
    check raised
    check "limit" in emsg

  test "a 3,999,000-byte user agent is rejected before the string is read":
    # The audit's repro size.  Core throws on the CompactSize length alone.
    var raised = false
    var emsg = ""
    try:
      discard deserializePayload("version", versionPayload(repeat('A', 3_999_000)))
    except SerializationError as e:
      raised = true
      emsg = e.msg
    check raised
    check "limit" in emsg

  test "a declared oversize length is rejected even with no string bytes":
    # Length prefix 1,000,000 followed by nothing: the limit error must fire
    # on the length, not "unexpected end of data" after a read loop.
    var w = BinaryWriter()
    let v = versionWithUa("").version
    w.writeUint32LE(v.version)
    w.writeUint64LE(v.services)
    w.writeInt64LE(v.timestamp)
    w.writeNetAddress(v.addrRecv)
    w.writeNetAddress(v.addrFrom)
    w.writeUint64LE(v.nonce)
    w.writeCompactSize(1_000_000'u64)
    var emsg = ""
    try:
      discard deserializePayload("version", w.data)
    except SerializationError as e:
      emsg = e.msg
    check "limit" in emsg

  test "our own user agent fits the cap":
    check UserAgent.len <= CoreMaxSubversionLength

  test "inbound VERSION with a 256-byte user agent completes the handshake":
    let ua = repeat('B', CoreMaxSubversionLength)
    let r = inboundHandshake(ua)
    check r.answered
    check r.ready
    check r.ua == ua

  test "inbound VERSION with a 257-byte user agent is disconnected unanswered":
    let r = inboundHandshake(repeat('B', CoreMaxSubversionLength + 1))
    check not r.answered
    check not r.ready
    check r.closed
