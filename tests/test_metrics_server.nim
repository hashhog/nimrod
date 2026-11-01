## Metrics listener hardening (security audit 2026-10-31, H1).
##
## The Prometheus listener used to bind 0.0.0.0 with no flag to change it,
## read the request with no timeout, and spawn one handler per accept with
## no cap: a socket that sends nothing was held forever, so a stranger could
## pile up fds (3,000 silent sockets took the node from 25 to 3,025 fds).
##
## These tests drive the real startMetricsServer on an ephemeral port and
## check, from the outside, what a client sees:
##   * the default listen address is 127.0.0.1 (read from /proc/net/tcp);
##   * --metricsbind changes it;
##   * a connection that sends nothing is closed within the read timeout;
##   * past the connection cap a new connection is closed at once;
##   * a real request still gets its 200 answer while silent sockets are held.

import unittest2
import std/[os, strutils, tempfiles]
import chronos
import ../src/nimrod {.all.}
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/network/peermanager
import ../src/consensus/params

const
  TimeoutUpperBound = chronos.seconds(9)
    ## Generous bound over the 5 s read timeout; base never closes at all.
  CapUnderTest = 16

proc freePort(): uint16 =
  let s = createStreamServer(initTAddress("127.0.0.1", Port(0)))
  result = uint16(s.localAddress().port)
  s.close()
  waitFor s.join()

proc listenAddrHex(port: uint16): string =
  ## Local address (hex, /proc/net/tcp byte order) of the LISTEN socket on
  ## `port` in this process's network namespace; "" if none.
  let want = ":" & toHex(int(port), 4)
  for line in lines("/proc/net/tcp"):
    let f = line.splitWhitespace()
    if f.len > 3 and f[1].endsWith(want) and f[3] == "0A":
      return f[1].split(':')[0]
  ""

type Fixture = object
  dir: string
  cs: ChainState
  state: NodeState
  port: uint16

proc setupFixture(cfg: NimrodConfig): Fixture =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_metrics_", "")
  result.cs = newChainState(result.dir / "db", params)
  result.port = freePort()
  var c = cfg
  c.metricsPort = result.port
  result.state = NodeState(
    config: c, params: params, chainState: result.cs,
    mempool: newMempool(result.cs, params, minFeeRate = 0.0),
    peerManager: newPeerManager(params, 8, 2, 117, result.dir),
    running: true)
  asyncSpawn startMetricsServer(result.state, result.port)
  # Let the accept loop bind before the test connects.
  waitFor sleepAsync(chronos.milliseconds(100))

proc teardownFixture(f: var Fixture) =
  f.state.running = false
  # Unblock the pending accept so the loop sees running == false.
  try:
    let t = waitFor connect(initTAddress("127.0.0.1", Port(f.port)))
    waitFor t.closeWait()
  except CatchableError: discard
  waitFor sleepAsync(chronos.milliseconds(50))
  f.cs.close()
  removeDir(f.dir)

proc connectSilent(port: uint16): StreamTransport =
  waitFor connect(initTAddress("127.0.0.1", Port(port)))

proc closedWithin(t: StreamTransport, d: Duration): bool =
  ## True if the server closes `t` (EOF or reset) within `d`.
  var buf: array[64, byte]
  let fut = t.readOnce(addr buf[0], buf.len)
  try:
    if not waitFor fut.withTimeout(d):
      return false
    return fut.read() == 0
  except CatchableError:
    return true

proc httpGet(port: uint16): string =
  let t = waitFor connect(initTAddress("127.0.0.1", Port(port)))
  discard waitFor t.write("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
  let data = waitFor t.read().wait(chronos.seconds(5))
  waitFor t.closeWait()
  result = newString(data.len)
  if data.len > 0: copyMem(addr result[0], unsafeAddr data[0], data.len)

suite "metrics server: bind address":
  test "metrics listener binds 127.0.0.1 by default":
    var f = setupFixture(defaultConfig())
    defer: teardownFixture(f)
    let a = listenAddrHex(f.port)
    checkpoint "listen address hex: '" & a & "'"
    check a == "0100007F"

  test "--metricsbind sets the metrics listen address":
    when compiles(defaultConfig().metricsBind):
      let parsed = parseArgs(@["--metricsbind=0.0.0.0", "start"])
      check parsed.config.metricsBind == "0.0.0.0"
      var f = setupFixture(parsed.config)
      defer: teardownFixture(f)
      check listenAddrHex(f.port) == "00000000"
    else:
      checkpoint "this build has no --metricsbind flag"
      fail()

suite "metrics server: slow and silent clients":
  test "a silent metrics connection is closed within the read timeout":
    var f = setupFixture(defaultConfig())
    defer: teardownFixture(f)
    let t = connectSilent(f.port)
    let start = Moment.now()
    let closed = closedWithin(t, TimeoutUpperBound)
    checkpoint "closed=" & $closed & " after " & $(Moment.now() - start)
    check closed
    waitFor t.closeWait()

  test "connections past the cap are closed at once":
    var f = setupFixture(defaultConfig())
    defer: teardownFixture(f)
    var held: seq[StreamTransport]
    for i in 0 ..< CapUnderTest:
      held.add connectSilent(f.port)
    waitFor sleepAsync(chronos.milliseconds(200))
    let extra = connectSilent(f.port)
    check closedWithin(extra, chronos.seconds(2))
    waitFor extra.closeWait()
    for t in held: waitFor t.closeWait()

  test "a real request is still answered while silent sockets are held":
    var f = setupFixture(defaultConfig())
    defer: teardownFixture(f)
    var held: seq[StreamTransport]
    for i in 0 ..< 4:
      held.add connectSilent(f.port)
    let resp = httpGet(f.port)
    check resp.startsWith("HTTP/1.1 200 OK")
    check "bitcoin_blocks_total" in resp
    for t in held: waitFor t.closeWait()
