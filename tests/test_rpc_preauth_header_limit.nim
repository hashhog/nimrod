## RPC listener hardening before auth (security audit 2026-10-31, H6 + M8).
##
## processClient read each header line with `transp.readLine()` (chronos
## limit 0 = unlimited) and applied the 8 KiB MaxHeadersSize cap only after
## the whole line was buffered, so one unauthenticated header line with no
## CRLF grew the node without bound (1 GiB of header bytes took a regtest
## node from 25 MB to 3.1 GB RSS). There was also no read timeout, no cap on
## concurrent connections and no cap on Content-Length.
##
## Core: libevent enforces MAX_HEADERS_SIZE while it reads
## (httpserver.cpp evhttp_set_max_headers_size), caps the body at MAX_SIZE
## (32 MiB, evhttp_set_max_body_size), drops idle connections after
## -rpcservertimeout (DEFAULT_HTTP_SERVER_TIMEOUT = 30 s) and answers 503
## "Work queue depth exceeded" past its 64-deep work queue.
##
## These tests drive the real RpcServer.start on an ephemeral port and check
## what a client sees:
##   * a 9000-byte header line with no CRLF is answered 400 while the client
##     still holds the line open (base never answers: it waits for a CRLF);
##   * a Content-Length over 32 MiB is answered 413 before any body is read;
##   * a connection that sends nothing is closed within the 30 s timeout;
##   * past the connection cap a new connection is answered 503;
##   * a real request is still answered 200 while silent sockets are held.

import unittest2
import std/[os, strutils, tempfiles]
import chronos
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

const
  OversizeHeaderLine = 9000
    ## > MaxHeadersSize (8192), the audit's control size.
  ExpectedCap = 64
    ## Concurrent RPC connections served (Core's -rpcworkqueue default).
  AnswerBound = chronos.seconds(5)
    ## How long a client waits for an answer that should come at once.
  IdleUpperBound = chronos.seconds(40)
    ## Generous bound over the 30 s read timeout; base never closes at all.
  ValidRequest = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n" &
                 "Content-Type: application/json\r\nContent-Length: 49\r\n\r\n" &
                 """{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"""

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
  result.dir = createTempDir("nimrod_rpc_preauth_", "")
  let cs = newChainState(result.dir / "db", params)
  let mp = newMempool(cs, params, fullRbf = false)
  # No credentials configured: auth is open, so a request that gets past the
  # listener's limits is answered 200 and the limits are what is measured.
  result.rpc = newRpcServer(port = freePort(), chainState = cs, mempool = mp,
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = params)
  asyncSpawn result.rpc.start()
  waitFor sleepAsync(chronos.milliseconds(100))

proc teardown(f: Fixture) =
  f.rpc.stop()
  f.rpc.chainState.close()
  removeDir(f.dir)

proc connectRpc(f: Fixture): StreamTransport =
  waitFor connect(initTAddress("127.0.0.1", Port(f.rpc.port)))

proc readAnswer(t: StreamTransport, bound: Duration): string =
  ## Bytes the server sent before closing, or "" if nothing came within
  ## `bound`. Does not close `t`.
  let fut = t.read()
  if not waitFor fut.withTimeout(bound):
    return ""
  cast[string](fut.read())

proc statusLine(answer: string): string =
  let i = answer.find("\r\n")
  if i < 0: answer else: answer[0 ..< i]

proc closedWithin(t: StreamTransport, bound: Duration): bool =
  ## True iff the server closed `t` (EOF) within `bound`.
  let fut = t.read()
  if not waitFor fut.withTimeout(bound):
    return false
  discard fut.read()
  true

suite "RPC pre-auth header limit (audit H6)":

  test "a 9000-byte header line without CRLF is answered 400 while still open":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    # No CRLF and no EOF: base buffers waiting for a line end that never
    # comes, so it can only answer once the client gives up.
    let sent = "POST / HTTP/1.1\r\nX: " & repeat('A', OversizeHeaderLine)
    check (waitFor t.write(sent)) == sent.len
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 400 Bad Request"

  test "1 MiB of one header line is cut off by MaxHeadersSize, not buffered":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    discard waitFor t.write("POST / HTTP/1.1\r\nX: ")
    # The server answers and closes after MaxHeadersSize bytes, so writing
    # the rest of the MiB either fails (peer reset) or lands in a socket
    # nobody reads. Either way the 400 has to be there.
    let chunk = repeat('A', 64 * 1024)
    for _ in 0 ..< 16:
      try:
        if not waitFor t.write(chunk).withTimeout(AnswerBound): break
      except CatchableError:
        break
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 400 Bad Request"

  test "a header line of exactly the remaining budget is still accepted":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    let head = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n" &
               "Content-Type: application/json\r\nContent-Length: 49\r\n"
    let body = """{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"""
    # Fill the 8192-byte budget exactly: head + "X: <pad>\r\n" + "\r\n".
    let padLen = MaxHeadersSize - head.len - "X: ".len - 2 - 2
    let req = head & "X: " & repeat('A', padLen) & "\r\n\r\n" & body
    check (waitFor t.write(req)) == req.len
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 200 OK"

suite "RPC body cap (audit M8)":

  test "Content-Length over 32 MiB is answered 413 before the body is read":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    let req = "POST / HTTP/1.1\r\nContent-Length: " & $(32 * 1024 * 1024 + 1) &
              "\r\n\r\n{"
    check (waitFor t.write(req)) == req.len
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 413 Payload Too Large"

  test "a negative Content-Length is answered 400":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    let req = "POST / HTTP/1.1\r\nContent-Length: -5\r\n\r\n"
    check (waitFor t.write(req)) == req.len
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 400 Bad Request"

suite "RPC idle timeout and connection cap (audit H6)":

  test "a connection that sends nothing is closed within the 30 s timeout":
    let f = setupFixture()
    defer: f.teardown()
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    check t.closedWithin(IdleUpperBound)

  test "past the connection cap a new connection is answered 503":
    let f = setupFixture()
    defer: f.teardown()
    var silent: seq[StreamTransport]
    defer:
      for s in silent: waitFor s.closeWait()
    for _ in 0 ..< ExpectedCap:
      silent.add f.connectRpc()
    waitFor sleepAsync(chronos.milliseconds(200))
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    discard waitFor t.write(ValidRequest)
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 503 Service Unavailable"

  test "a real request is still answered under the cap while silent sockets are held":
    let f = setupFixture()
    defer: f.teardown()
    var silent: seq[StreamTransport]
    defer:
      for s in silent: waitFor s.closeWait()
    for _ in 0 ..< ExpectedCap - 1:
      silent.add f.connectRpc()
    waitFor sleepAsync(chronos.milliseconds(200))
    let t = f.connectRpc()
    defer: waitFor t.closeWait()
    discard waitFor t.write(ValidRequest)
    let answer = t.readAnswer(AnswerBound)
    check answer.statusLine == "HTTP/1.1 200 OK"
    check "\"error\":null" in answer
