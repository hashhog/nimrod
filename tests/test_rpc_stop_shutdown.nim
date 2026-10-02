## Gate 5: RPC `stop` must actually shut the node down.
##
## Core (rpc/server.cpp `stop`): type-check the hidden `wait` argument, call
## StartShutdown(), answer "Bitcoin Core stopping"; the process then exits via
## the same path as SIGTERM. nimrod's `stop` branch used to only answer, so
## tools/crash-restart-harness.py reported `rpc-stop-ignored`.
##
## The fix: the handler sets `rpc.shutdownRequested`; processClient, after the
## reply is written, raises SIGTERM to self (requestNodeShutdown), which runs
## the same sigHandler an operator's `kill -TERM` runs. This test pins the
## handler half (in-process; sending SIGTERM would kill the test runner). The
## end-to-end half is the harness's `rpc-stop` verdict on regtest.

import unittest2
import std/[os, json]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

const TestDbPath = "/tmp/nimrod_rpc_stop_shutdown_test"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc buildRpc(): RpcServer =
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
               peerManager = nil, feeEstimator = newFeeEstimator(),
               params = params)

suite "RPC stop requests shutdown (gate 5)":

  test "stop answers and sets shutdownRequested":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    check not rpc.shutdownRequested
    let resp = rpc.handleMethod("stop", %*[])
    check resp.kind == JString
    check resp.getStr() == "nimrod server stopping"
    check rpc.shutdownRequested

  test "numeric wait is accepted":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    discard rpc.handleMethod("stop", %*[1])
    check rpc.shutdownRequested

  test "wrong-typed wait is RPC_TYPE_ERROR and does NOT request shutdown":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    var code = 0
    try:
      discard rpc.handleMethod("stop", %*["x"])
    except RpcError as e:
      code = e.code
    check code == -3
    check not rpc.shutdownRequested
