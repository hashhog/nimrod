## Pre-auth RPC sockets must not hold the request slots (cfaudit
## nimrod/rpc/processClient-preauth-connection-slot-starvation).
##
## The H6 fix (PR #34) capped concurrent RPC connections at 64, but counted
## a connection at accept, before a single byte was read or any credential
## checked. Any local UID could open 64 idle sockets and every later
## connection, authenticated or not, was answered 503. The header phase had
## only a per-line 30 s timeout, so a client sending one short header line
## every 29 s held its slot until the 8 KiB header budget ran out (~19 h).
##
## Core: the 64 is the depth of the work queue of parsed, dispatched requests
## (httpserver.cpp:255, `queue.size() >= g_max_queue_depth` -> 503 "Work
## queue depth exceeded"), checked only once libevent has read a complete
## request. Connections that have not sent a request do not count.
##
## These tests drive the real RpcServer.start on an ephemeral port:
##   * 64 idle sockets held: an authenticated getblockcount is still 200
##     (master: 503);
##   * a client trickling header lines inside the per-line timeout is cut off
##     by a whole-header 30 s deadline (master: kept open);
##   * control: the H6 8 KiB header cap still answers 400;
##   * control: 64 authenticated requests in flight still make the next one
##     503, so the cap still exists where Core has it;
##   * control: a slot is given back after every answered request, and when
##     the client is gone before the answer (a leak would turn every request
##     past the 64th into 503).

import unittest2
import std/[base64, os, strutils, tempfiles]
import chronos
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/util/tip_notifier

const
  Cap = 64
    ## Core DEFAULT_HTTP_WORKQUEUE.
  AnswerBound = chronos.seconds(5)
  HeaderDeadlineBound = chronos.seconds(40)
    ## Generous bound over the 30 s whole-header deadline.
  TrickleFor = chronos.seconds(50)
    ## How long the trickling client keeps going if nobody stops it.
  TrickleEvery = chronos.seconds(2)
    ## Well inside the 30 s per-read timeout.
  User = "u"
  Pass = "p"

proc freePort(): uint16 =
  let s = createStreamServer(initTAddress("127.0.0.1", Port(0)))
  result = uint16(s.localAddress().port)
  s.close()
  waitFor s.join()

type Fixture = object
  dir: string
  rpc: RpcServer

proc setupFixture(): Fixture =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_rpc_preauth_slot_", "")
  let cs = newChainState(result.dir / "db", params)
  let mp = newMempool(cs, params, fullRbf = false)
  # Credentials configured, so "authenticated" means it: an unauthenticated
  # request is answered 401, an authenticated one 200.
  result.rpc = newRpcServer(port = freePort(), chainState = cs, mempool = mp,
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = params, authUser = User, authPass = Pass)
  # Lets waitfornewblock hold a request in flight for its timeout.
  result.rpc.tipNotifier = newTipNotifier()
  asyncSpawn result.rpc.start()
  waitFor sleepAsync(chronos.milliseconds(100))

proc teardown(f: Fixture) =
  f.rpc.stop()
  f.rpc.chainState.close()
  removeDir(f.dir)

proc connectRpc(f: Fixture): StreamTransport =
  waitFor connect(initTAddress("127.0.0.1", Port(f.rpc.port)))

proc request(body: string): string =
  "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n" &
    "Authorization: Basic " & encode(User & ":" & Pass) & "\r\n" &
    "Content-Type: application/json\r\nContent-Length: " & $body.len &
    "\r\n\r\n" & body

const GetBlockCount = """{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"""

proc readAnswer(t: StreamTransport, bound: Duration): string =
  let fut = t.read()
  if not waitFor fut.withTimeout(bound):
    return ""
  cast[string](fut.read())

proc statusLine(answer: string): string =
  let i = answer.find("\r\n")
  if i < 0: answer else: answer[0 ..< i]

suite "RPC pre-auth connections do not hold request slots":

  test "64 idle sockets held: an authenticated getblockcount is answered 200":
    let f = setupFixture()
    defer: f.teardown()
    var idle: seq[StreamTransport]
    defer:
      for s in idle: waitFor s.closeWait()
    for _ in 0 ..< Cap:
      idle.add f.connectRpc()
    waitFor sleepAsync(chronos.milliseconds(200))
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    discard waitFor t.write(request(GetBlockCount))
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 200 OK"
    check "\"error\":null" in answer

  test "trickled header lines are cut off by a whole-header 30 s deadline":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    discard waitFor t.write("POST / HTTP/1.1\r\n")
    let start = Moment.now()
    var closedAt = ZeroDuration
    # One 6-byte header line every 2 s: each read is far inside the per-read
    # timeout and 25 lines are far inside the 8 KiB budget, so only a
    # deadline on the header phase as a whole can end this.
    # One read for the whole test, never cancelled (withTimeout would cancel
    # it on the first timeout, and a cancelled future reads as finished).
    let eof = t.read()
    while Moment.now() - start < TrickleFor:
      waitFor (eof or sleepAsync(TrickleEvery))
      if eof.finished:
        closedAt = Moment.now() - start
        break
      try:
        discard waitFor t.write("X: a\r\n")
      except CatchableError:
        closedAt = Moment.now() - start
        break
    check closedAt > ZeroDuration
    check closedAt <= HeaderDeadlineBound

  test "control: the H6 8 KiB header cap still answers 400":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    let sent = "POST / HTTP/1.1\r\nX: " & repeat('A', 9000)
    check (waitFor t.write(sent)) == sent.len
    check t.readAnswer(AnswerBound).statusLine == "HTTP/1.1 400 Bad Request"

  test "control: 64 authenticated requests in flight make the next one 503":
    let f = setupFixture()
    defer: f.teardown()
    var busy: seq[StreamTransport]
    defer:
      for s in busy: waitFor s.closeWait()
    # waitfornewblock with a 6 s timeout on a chain whose tip never moves:
    # each holds an authenticated, dispatched request for 6 s.
    let wait = """{"jsonrpc":"1.0","id":1,"method":"waitfornewblock","params":[6000]}"""
    for _ in 0 ..< Cap:
      let s = f.connectRpc()
      discard waitFor s.write(request(wait))
      busy.add s
    # Probe until the 64 are all dispatched and a probe is refused, rather
    # than guess how long dispatch takes. Without a cap every probe is 200.
    var refused = false
    let start = Moment.now()
    while not refused and Moment.now() - start < chronos.seconds(4):
      let t = f.connectRpc()
      discard waitFor t.write(request(GetBlockCount))
      refused = t.readAnswer(AnswerBound).statusLine ==
                "HTTP/1.1 503 Service Unavailable"
      waitFor t.closeWait()
      if not refused: waitFor sleepAsync(chronos.milliseconds(100))
    check refused
    # The held requests are answered normally when they time out, and their
    # slots come back: a request after that is answered 200 again.
    for s in busy:
      check s.readAnswer(chronos.seconds(10)).statusLine == "HTTP/1.1 200 OK"
    let after = f.connectRpc()
    defer: waitFor after.closeWait()
    discard waitFor after.write(request(GetBlockCount))
    check after.readAnswer(AnswerBound).statusLine == "HTTP/1.1 200 OK"

  test "control: slots come back after answered requests (100 in a row)":
    let f = setupFixture()
    defer: f.teardown()
    # More than the cap, one after another on one server: a slot that was
    # never given back would turn request 65 and every later one into 503.
    var ok = 0
    for _ in 0 ..< 100:
      let t = f.connectRpc()
      discard waitFor t.write(request(GetBlockCount))
      if t.readAnswer(AnswerBound).statusLine == "HTTP/1.1 200 OK": inc ok
      waitFor t.closeWait()
    check ok == 100

  test "control: slots come back when the client is gone before the answer":
    let f = setupFixture()
    defer: f.teardown()
    # 100 clients that send a request and reset the connection without
    # reading: the answer write can fail, and the slot must still be freed.
    for _ in 0 ..< 100:
      let t = f.connectRpc()
      discard waitFor t.write(request(GetBlockCount))
      waitFor t.closeWait()
    # Once those have drained, a request must be answered 200.
    var answered = false
    let start = Moment.now()
    while not answered and Moment.now() - start < chronos.seconds(5):
      waitFor sleepAsync(chronos.milliseconds(100))
      let t = f.connectRpc()
      discard waitFor t.write(request(GetBlockCount))
      answered = t.readAnswer(AnswerBound).statusLine == "HTTP/1.1 200 OK"
      waitFor t.closeWait()
    check answered
