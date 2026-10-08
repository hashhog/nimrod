## NI-6 (fleet audit 2026-10-07): RPC handlers must not drive peer transports
## from the RPC thread.
##
## The RPC server runs its own chronos loop on its own thread; peers and their
## transports belong to the main loop. `ping`, the broadcast paths
## (sendrawtransaction, submitblock, generate*, wallet sends), getblockfrompeer,
## disconnectnode, addnode and setban used to write / close / dial from the RPC
## thread. A write that cannot complete there registers the fd with the RPC
## selector, fails, and leaves the transport's queue paused for good: the peer
## is silently wedged (tools/repro_rpc_thread_send.py: deployed 5215491 WEDGED,
## our ping never answered after the RPC-written pings filled the socket).
##
## Core: RPC methods only queue (RelayTransaction, m_ping_queued,
## fDisconnect, AddNode); the network threads do the I/O.
##
## Pinned here: the handlers POST commands (p2p_cmd_queue) instead of acting,
## and a transport refuses a thread that is not its loop's.

import unittest2
import std/[os, json]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/network/[peer, peermanager, p2p_cmd_queue]
import ../src/rpc/server

const TestDb = "/tmp/nimrod_test_rpc_p2p_main_loop"

proc offLoopProbe(res: ptr bool) {.thread.} =
  res[] = onP2PLoop("test-foreign-thread")

suite "NI-6: RPC P2P side effects are posted to the main loop":

  test "ping / addnode onetry / setban post commands, touch no transport":
    removeDir(TestDb)
    defer: removeDir(TestDb)
    let params = regtestParams()
    var cs = newChainState(TestDb / "cs", params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)
    let pm = newPeerManager(params, 8, 8, TestDb)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = pm, feeEstimator = newFeeEstimator(),
                           params = params)
    let q = newP2PCmdQueue()
    rpc.p2pQueue = q
    discard rpc.handleMethod("ping", %*[])
    discard rpc.handleMethod("addnode", %*["127.0.0.1:18444", "onetry"])
    discard rpc.handleMethod("setban", %*["10.1.2.3", "add", 3600])
    let cmds = q.takeAll()
    check cmds.len == 3
    if cmds.len == 3:
      check cmds[0].kind == pcPingAll
      check cmds[1].kind == pcConnectManual
      check cmds[1].host == "127.0.0.1"
      check cmds[1].port == 18444'u16
      check cmds[2].kind == pcDisconnectAddress
      check cmds[2].host == "10.1.2.3"
    # The ban itself is recorded synchronously (Core: Ban() before the reply).
    check pm.isBanned("10.1.2.3")

  test "a peer transport refuses a thread that is not its loop's":
    setP2PLoopThread()
    defer: clearP2PLoopThread()
    let before = p2pOffLoopCount()
    check onP2PLoop("test-main-thread")
    var res = true
    var t: Thread[ptr bool]
    createThread(t, offLoopProbe, addr res)
    joinThread(t)
    check not res
    check p2pOffLoopCount() == before + 1
