## A Defect raised while handling one peer's input must disconnect that peer,
## not exit the node.
##
## Security audit 2026-10-31, M1 (the class behind C1): the handshake caller
## (`handleInboundConnection`), `messageLoop`, the wrapped message callbacks and
## the frames that run `deserializePayload` caught only `CatchableError`.  Nim
## keeps overflow/index/range checks under -d:release, and chronos re-raises a
## Defect eagerly out of the closure iterator and out of `poll()`, so an
## IndexDefect in a message handler, or the OverflowDefect of C1 in the
## handshake, exited the whole process.
##
## The PeerManager tests drive a real listener with a raw v1 client and inject
## the Defect on one path:
##   * a message handler raising IndexDefect (the wrapped callback frame)
##   * the handshake itself: VERSION with timestamp low(int64) (audit C1). The
##     overflow happens after `awaitVersionMessage` suspended, i.e. in a frame
##     chronos resumes from poll(), where no caller's `except` can see it.
## and then check that the attacking peer is disconnected and the node still
## serves: a second, honest client completes a handshake and gets a pong.
## A last test calls the legacy `peer.handleMessage` dispatcher directly.
## On the unfixed code the Defect escapes `waitFor`; each test catches it and
## fails by name.
##
## Not covered, by construction: a Defect raised after an `await` in an async
## frame that carries no boundary.  chronos raises it out of poll(), past every
## caller.  The production frames that run on peer input carry the boundary
## (peerDefectBoundary on performHandshake, readMessageV1/V2, the wrapped
## callbacks, peer.handleMessage and nimrod.nim's handleMessage).
##
## Command:
##   nim c -r tests/test_p2p_defect_containment.nim

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

# ── raw v1 client ───────────────────────────────────────────────────────────

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

proc send(c: RawClient, msg: P2PMessage) =
  discard waitFor c.transp.write(serializeMessage(regtestParams().magic, msg))

proc versionAt(ts: int64, nonce: uint64): P2PMessage =
  newVersionMsg(version = 70016'u32, services = NodeNetwork or NodeWitness,
                timestamp = ts, nonce = nonce,
                userAgent = "/defect-containment:0.1/", startHeight = 0,
                relay = true)

proc dial(pm: PeerManager): RawClient =
  result = RawClient()
  result.transp = waitFor connect(initTAddress("127.0.0.1",
                                  Port(pm.getListeningBinds()[0].port)))
  asyncSpawn result.readLoop()

proc handshake(c: RawClient, ts: int64, nonce: uint64): bool =
  ## Send VERSION(ts); on our verack, answer verack.  True once we got verack.
  c.send(versionAt(ts, nonce))
  result = waitUntil(proc(): bool = c.has(mkVerack) or c.closed, 3000) and
           c.has(mkVerack)
  if result:
    c.send(newVerack())

proc close(c: RawClient) =
  if c != nil and c.transp != nil:
    try: waitFor c.transp.closeWait()
    except CatchableError, Defect: discard

# ── scenario ────────────────────────────────────────────────────────────────

type Outcome = object
  err: string            ## a Defect that escaped to the event loop ("" = none)
  attackerDropped: bool  ## the attacker's socket was closed by the node
  attackerGone: bool     ## and no peer the PeerManager tracks is still connected
  honestPong: bool       ## a second client still handshakes and gets a pong

proc noneConnected(pm: PeerManager): bool =
  for p in pm.peers.values:
    if p.isConnected(): return false
  true

proc honestServed(pm: PeerManager): bool =
  ## The node still works: a fresh client completes the handshake and its
  ## ping is answered.
  let h = pm.dial()
  try:
    if not h.handshake(getTime().toUnix(), 0x0b0b_0b0b'u64):
      return false
    h.send(newPing(0x5151'u64))
    result = waitUntil(proc(): bool = h.has(mkPong), 3000)
  finally:
    h.close()

proc runScenario(onMessage: peermanager.PeerCallback, attackTs: int64,
                 trigger: P2PMessage, sendTrigger: bool): Outcome =
  let dir = createTempDir("nimrod-defect-containment-", "")
  let pm = newPeerManager(regtestParams(), maxOutFullRelay = 0,
                          maxOutBlockRelay = 0, maxIn = 8, dataDir = dir)
  pm.handshakeTimeoutMs = HandshakeMs
  pm.bindSpecs = @["127.0.0.1"]
  pm.dnsSeedEnabled = false
  pm.onMessage = onMessage
  var a: RawClient
  try:
    try:
      waitFor pm.startListeners(@["127.0.0.1"], 0)
      a = pm.dial()
      discard a.handshake(attackTs, 0xa77a_c4e7'u64)
      if sendTrigger:
        a.send(trigger)
      result.attackerDropped = waitUntil(proc(): bool = a.closed, 3000)
      result.attackerGone = waitUntil(proc(): bool = pm.noneConnected(), 3000)
      result.honestPong = pm.honestServed()
    except Defect as e:
      result.err = $e.name & ": " & e.msg
  finally:
    a.close()
    try: pm.stopListener()
    except CatchableError, Defect: discard
    try: waitFor sleepAsync(20)
    except CatchableError, Defect: discard
    try: removeDir(dir) except OSError: discard

proc indexDefect() =
  var s: seq[int]
  let i = s.len + 3             # out of range at run time, not compile time
  discard s[i]

let syncDefect: peermanager.PeerCallback = proc(p: Peer, msg: P2PMessage) {.async.} =
  if msg.kind == mkInv:
    indexDefect()

let quietHandler: peermanager.PeerCallback = proc(p: Peer, msg: P2PMessage) {.async.} =
  discard

proc invMsg(): P2PMessage =
  newInv(@[InvVector(invType: invTx, hash: default(array[32, byte]))])

suite "P2P defect containment (audit M1)":

  test "message handler raising IndexDefect before its first await disconnects the peer":
    let r = runScenario(syncDefect, getTime().toUnix(), invMsg(), true)
    checkpoint("err=" & r.err)
    check r.err == ""
    check r.attackerDropped
    check r.attackerGone
    check r.honestPong

  test "a Defect in the handshake (VERSION timestamp low(int64)) does not exit the node":
    # Audit C1 through the handshake frame.  With only this containment the
    # peer is dropped; with the saturating offset fix it completes instead.
    # Either way no Defect may escape and the node must keep serving.
    let r = runScenario(quietHandler, low(int64), invMsg(), false)
    checkpoint("err=" & r.err)
    check r.err == ""
    check r.honestPong

  test "peer.handleMessage(version) with timestamp low(int64) raises a PeerError, not a Defect":
    # Unconnected peer: whatever the offset handling, the verack send after it
    # fails with the catchable "not connected".  A Defect must not get out.
    let p = newPeer("127.0.0.1", 18444, regtestParams(), pdInbound)
    var err = ""
    var peerErr = false
    try:
      waitFor p.handleMessage(versionAt(low(int64), 1'u64))
    except PeerError:
      peerErr = true
    except CatchableError as e:
      err = $e.name & ": " & e.msg
    except Defect as e:
      err = $e.name & ": " & e.msg
    checkpoint("err=" & err)
    check err == ""
    check peerErr

  test "control: an ordinary message to a sane handler keeps the peer":
    let r = runScenario(quietHandler, getTime().toUnix(), invMsg(), true)
    checkpoint("err=" & r.err)
    check r.err == ""
    check not r.attackerDropped
    check not r.attackerGone
    check r.honestPong
