## createwallet / loadwallet / unloadwallet carry Core's warnings shape.
##
## Core v31.1 regtest differential, wallet group (row
## `wallet/create/wallet:warning`): Core's createwallet answers
## {"name":"w"} with no "warning" key; nimrod answered
## {"name":"w","warning":""}.
##
## Core: rpc/util.cpp:1393-1403 PushWarnings adds a "warnings" string array
## only when there is at least one warning, and nothing otherwise. It is used
## by createwallet (wallet/rpc/wallet.cpp:427), loadwallet (:271),
## unloadwallet (:482) and restorewallet (wallet/rpc/backup.cpp:658). There
## is no singular "warning" field in v31.
##
## Pins the exact key set of each reply, plus the non-empty warnings array.

import std/[json, os, tempfiles, algorithm]
import unittest2
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/manager

proc keysOf(n: JsonNode): seq[string] =
  for k, _ in n.pairs:
    result.add(k)
  result.sort()

suite "wallet load/create/unload warnings shape (Core PushWarnings)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let params = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_walletwarn_", "_regtest")
    cs = newChainState(tempDir, params)
    if cs.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      let res = cs.connectBlock(genesis, 0)
      doAssert res.isOk, "Failed to connect genesis"
    let mp = newMempool(cs, params)
    let fe = newFeeEstimator()
    rpc = newRpcServer(
      port         = 18443'u16,
      chainState   = cs,
      mempool      = mp,
      peerManager  = nil,
      feeEstimator = fe,
      params       = params
    )
    wm = newWalletManager(tempDir, params, cs)
    rpc.walletManager = wm

  teardown:
    if wm != nil:
      wm.close()
    cs.close()
    removeDir(tempDir)

  test "createwallet with no warnings answers exactly {name}":
    let resp = rpc.handleMethod("createwallet", %*["w"])
    check resp.keysOf() == @["name"]
    check resp["name"].getStr() == "w"

  test "loadwallet with no warnings answers exactly {name}":
    discard rpc.handleMethod("createwallet", %*["w2"])
    discard rpc.handleMethod("unloadwallet", %*["w2"])
    let resp = rpc.handleMethod("loadwallet", %*["w2"])
    check resp.keysOf() == @["name"]
    check resp["name"].getStr() == "w2"

  test "unloadwallet with no warnings answers {}":
    discard rpc.handleMethod("createwallet", %*["w3"])
    let resp = rpc.handleMethod("unloadwallet", %*["w3"])
    check resp.kind == JObject
    check resp.len == 0

  test "non-empty warnings become a 'warnings' string array, no 'warning'":
    when declared(pushWarnings):
      var obj = %*{"name": "w"}
      obj.pushWarnings(@["first", "second"])
      check obj.keysOf() == @["name", "warnings"]
      check obj["warnings"] == %*["first", "second"]
      var empty = %*{"name": "w"}
      empty.pushWarnings(@[])
      check empty.keysOf() == @["name"]
    else:
      checkpoint "server.nim has no pushWarnings (Core PushWarnings) helper"
      check false
