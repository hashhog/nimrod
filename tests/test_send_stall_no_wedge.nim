## A peer that stops READING must not wedge nimrod's shared loops.
##
## Bitcoin Core never blocks on a peer's socket: SocketSendData
## (net.cpp ~1640-1680) writes what the kernel takes, keeps the rest in the
## per-peer vSendMsg queue and sets fPauseSend past the send-buffer limit;
## InactivityCheck (net.cpp ~2013) disconnects a peer whose sends make no
## progress for TIMEOUT_INTERVAL. One stuck peer costs only that peer.
##
## nimrod 8c55fea: Peer.sendMessageV1/V2 did `await peer.transport.write(data)`
## with no bound — chronos completes the write only when every byte has left
## for the kernel, i.e. never, for a peer that has stopped reading. Callers
## awaited per peer in SHARED loops:
##   - PeerManager.mainLoop -> pingPeers -> sendPingsNow: serial
##     `await peer.sendPing()` — one parked ping freezes the PM main loop
##     (ping-timeout eviction, reconnects, stale-tip eviction all live there,
##     so the backstops that would drop the peer can never run);
##   - SyncManager.syncLoop -> requestBlocks -> `await sendGetData` before
##     the in-flight bookkeeping and timeout handling — the tip stalls.
##
## Every test drives real chronos TCP sockets on 127.0.0.1 (fixed ports
## below 32768). The stall bound is shortened through
## NIMROD_SEND_STALL_TIMEOUT_MS so the suite runs in seconds; on a tree
## without the bound the variable is simply ignored and the wedge shows.
##
## Command:  nim c -r tests/test_send_stall_no_wedge.nim

import unittest2
import std/[os, options, tables, sets, times, posix]
import chronos
import ../src/network/peer
import ../src/network/peermanager {.all.}
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/messages
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const
  StallMs = 1500
  BasePort = 29341

putEnv("NIMROD_SEND_STALL_TIMEOUT_MS", $StallMs)

proc applyStallBound() =
  ## In the aggregate another module may already have read the env var.
  ## The hook does not exist on a tree without the bound — nothing to set.
  when declared(setSendStallTimeoutMs):
    setSendStallTimeoutMs(StallMs)

# ---------------------------------------------------------------------------
# Remote ends
# ---------------------------------------------------------------------------

type
  RemoteMode = enum rmNoRead, rmRead, rmSlowRead
  Remote = ref object
    server: StreamServer
    mode: RemoteMode
    received: int
    clients: seq[StreamTransport]

proc shrinkBuffers(fd: AsyncFD) =
  ## Small, fixed kernel buffers so backpressure appears after ~100 KB
  ## instead of the ~10 MB loopback autotuning allows.
  var v: cint = 32 * 1024
  discard posix.setsockopt(SocketHandle(fd), SOL_SOCKET, SO_RCVBUF,
                           addr v, SockLen(sizeof(v)))
  discard posix.setsockopt(SocketHandle(fd), SOL_SOCKET, SO_SNDBUF,
                           addr v, SockLen(sizeof(v)))

proc startRemote(port: int, mode: RemoteMode): Remote =
  let r = Remote(mode: mode)
  proc onClient(server: StreamServer, t: StreamTransport) {.async: (raises: []).} =
    r.clients.add(t)
    shrinkBuffers(t.fd)
    var buf = newSeq[byte](64 * 1024)
    try:
      case r.mode
      of rmNoRead:
        await sleepAsync(chronos.hours(1))   # connected, never reads
      of rmRead:
        while true:
          let n = await t.readOnce(addr buf[0], buf.len)
          if n == 0: break
          r.received += n
      of rmSlowRead:
        # Drains steadily (~640 KB/s) but far slower than the sender:
        # never a gap anywhere near the stall bound.
        while true:
          let n = await t.readOnce(addr buf[0], buf.len)
          if n == 0: break
          r.received += n
          await sleepAsync(chronos.milliseconds(100))
    except CatchableError:
      discard
  r.server = createStreamServer(initTAddress("127.0.0.1", Port(port)), onClient,
                                {ServerFlags.ReuseAddr})
  r.server.start()
  r

proc stop(r: Remote) =
  for c in r.clients:
    if not c.closed: c.close()
  r.server.stop()
  r.server.close()

proc connectedPeer(port: int): Peer =
  let params = regtestParams()
  let p = newPeer("127.0.0.1", uint16(port), params, pdOutbound)
  p.transport = waitFor connect(initTAddress("127.0.0.1", Port(port)))
  shrinkBuffers(p.transport.fd)
  p.state = psReady
  p.services = NodeNetwork or NodeWitness
  p.startHeight = 100
  p

proc wedge(p: Peer) =
  ## Queue far more than both kernel buffers hold. The remote never reads,
  ## so this write — and everything queued behind it — can never finish.
  discard p.transport.write(newSeq[byte](4 * 1024 * 1024))

proc pump(ms: int) = waitFor sleepAsync(chronos.milliseconds(ms))

proc finishesWithin(f: FutureBase, ms: int): bool =
  ## Run the loop until `f` finishes or `ms` elapses. Never cancels `f`.
  let deadline = Moment.now() + chronos.milliseconds(ms)
  while not f.finished and Moment.now() < deadline:
    pump(20)
  f.finished

proc eventually(pred: proc(): bool, ms: int): bool =
  let deadline = Moment.now() + chronos.milliseconds(ms)
  while not pred() and Moment.now() < deadline:
    pump(20)
  pred()

# ---------------------------------------------------------------------------

suite "send stall: a non-reading peer is dropped, never waited on forever":
  setup:
    applyStallBound()

  test "sendMessage to a non-reading peer fails within the stall bound":
    let r = startRemote(BasePort, rmNoRead)
    let p = connectedPeer(BasePort)
    p.wedge()
    let t0 = Moment.now()
    let f = p.sendMessage(newPing(7))
    check finishesWithin(f, StallMs * 4)
    check f.finished and f.failed           # raised, not "sent"
    let took = (Moment.now() - t0).milliseconds
    check took >= StallMs - 100             # not cut before the bound
    check eventually(proc(): bool = p.state != psReady, 2000)
    r.stop()

  test "keepalive fan-out (PM main loop pingPeers) is not parked by it":
    let stuck = startRemote(BasePort + 1, rmNoRead)
    let good = startRemote(BasePort + 2, rmRead)
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, getTempDir())
    let a = connectedPeer(BasePort + 1)
    let b = connectedPeer(BasePort + 2)
    pm.peers["127.0.0.1:" & $(BasePort + 1)] = a
    pm.peers["127.0.0.1:" & $(BasePort + 2)] = b
    a.wedge()
    let before = good.received
    let f = pm.pingPeers()
    # The PM main loop awaits this. It must come back promptly — well
    # inside the stall bound — whatever order the peers are visited in.
    check finishesWithin(f, StallMs div 2)
    # The healthy peer got its ping without waiting on the stuck one.
    check eventually(proc(): bool = good.received > before, StallMs div 2)
    # The stuck peer is dropped by the send bound (no other backstop runs).
    check eventually(proc(): bool = a.state != psReady, StallMs * 3)
    check b.state == psReady
    stuck.stop()
    good.stop()

  test "block download (syncLoop requestBlocks) does not wait on it":
    let r = startRemote(BasePort + 3, rmNoRead)
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, getTempDir())
    let p = connectedPeer(BasePort + 3)
    pm.peers["127.0.0.1:" & $(BasePort + 3)] = p

    let genesis = buildGenesisBlock(params)
    let gh = params.genesisBlockHash
    let sm = SyncManager(
      state: ssDownloadingBlocks,
      headerChain: initHeaderChain(genesis.header, gh),
      params: params, headerTip: gh, headerTipHeight: 0,
      chainTipNoState: gh, chainTipHeightNoState: 0,
      peerHeadersSync: initTable[int64, HeadersSyncState](),
      headersPresyncStats: initTable[int64, HeadersPresyncStats](),
      presyncBestPeer: -1, presyncBestWork: initUInt256(),
      minimumChainWork: initUInt256(params.minimumChainWork),
      unconnectingHeaders: initTable[int64, int]())
    sm.peerManager = pm
    var prev = gh
    var ts = genesis.header.timestamp
    for i in 0 ..< 8:
      ts += 600
      var h = BlockHeader(version: 1, prevBlock: prev,
                          merkleRoot: default(array[32, byte]),
                          timestamp: ts, bits: 0x207fffff'u32, nonce: 0)
      while not validateHeaderPoW(h): h.nonce += 1
      let hh = BlockHash(doubleSha256(serialize(h)))
      let idx = sm.headerChain.headers.len
      sm.headerChain.headers.add(h)
      sm.headerChain.hashes.add(hh)
      sm.headerChain.byHash[hh] = idx
      sm.headerChain.totalWork = addWork(sm.headerChain.totalWork,
                                         calculateWork(h.bits))
      sm.headerChain.tip = hh
      sm.headerChain.tipHeight = int32(idx)
      sm.headerTip = hh
      sm.headerTipHeight = int32(idx)
      prev = hh

    p.wedge()
    let f = sm.requestBlocks(p)
    # syncLoop awaits this; it must return without waiting on the socket.
    check finishesWithin(f, StallMs div 2)
    check sm.requestedHashes.len > 0          # the getdata was issued
    # When the send bound drops the peer its requests are released so the
    # next pass can re-request them elsewhere.
    check eventually(proc(): bool = p.state != psReady, StallMs * 3)
    check eventually(proc(): bool = sm.requestedHashes.len == 0 and
                                 sm.pendingBlocks == 0, StallMs * 3)
    r.stop()

  test "control: a slow-but-reading peer is never cut off":
    ## The bound is on PROGRESS, not on total send time: ~3 MB to a reader
    ## draining ~640 KB/s takes several stall windows and must succeed.
    let r = startRemote(BasePort + 4, rmSlowRead)
    let p = connectedPeer(BasePort + 4)
    var items: seq[InvVector]
    for i in 0 ..< 20_000:
      var h: array[32, byte]
      h[0] = byte(i and 0xff); h[1] = byte((i shr 8) and 0xff)
      items.add InvVector(invType: invTx, hash: h)
    let msg = newInv(items)                 # ~720 KB on the wire
    let t0 = Moment.now()
    var futs: seq[Future[void]]
    for i in 0 ..< 4:
      futs.add p.sendMessage(msg)
    let all = allFutures(futs)
    check finishesWithin(all, 30_000)
    for f in futs:
      check f.completed                     # every send succeeded
    let took = (Moment.now() - t0).milliseconds
    checkpoint("slow-reader send took " & $took & " ms")
    check took > StallMs                    # the bound really was spanned
    check p.state == psReady
    r.stop()
