## Wallet management RPC dispatch test
##
## Smoke test that the 5 wallet management RPC methods are reachable through
## handleMethod's case dispatch. Prior to this test, the handlers were defined
## but not wired into the dispatch case (Cat H wallet audit), so they returned
## "method not found" (RpcMethodNotFound, -32601) at runtime.
##
## Methods covered:
##   createwallet, loadwallet, unloadwallet, listwallets, listwalletdir
##
## Strategy: spin up an in-memory regtest RpcServer with a real WalletManager,
## call each method through handleMethod, and assert the response is non-error
## (i.e., the dispatch matches and the handler runs to completion). For the
## listwallets / listwalletdir / createwallet path we get a real result; for
## loadwallet / unloadwallet we accept either a valid result or a domain
## RpcError (NOT RpcMethodNotFound) since those depend on filesystem state.
##
## Run with:
##   nim c -r tests/test_wallet_dispatch.nim
##
## Or via the full suite:
##   nim c -r tests/test_all.nim

import std/[json, os, tempfiles]
import unittest2
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/manager

suite "wallet management RPC dispatch (createwallet/loadwallet/unloadwallet/listwallets/listwalletdir)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let params = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_walletdisp_", "_regtest")
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

  test "listwallets is reachable via handleMethod (returns JArray)":
    # Empty manager -> empty array, but the key thing is dispatch reaches the
    # handler and we don't get RpcMethodNotFound.
    let resp = rpc.handleMethod("listwallets", newJArray())
    check resp.kind == JArray
    check resp.len == 0

  test "listwalletdir is reachable via handleMethod (returns object with wallets array)":
    let resp = rpc.handleMethod("listwalletdir", newJArray())
    check resp.kind == JObject
    check resp.hasKey("wallets")
    check resp["wallets"].kind == JArray

  test "createwallet is reachable via handleMethod and creates a wallet":
    var p = newJArray()
    p.add(%"smoke_w1")
    let resp = rpc.handleMethod("createwallet", p)
    check resp.kind == JObject
    check resp.hasKey("name")
    check resp["name"].getStr() == "smoke_w1"
    check resp.hasKey("warning")

    # listwallets should now reflect the new wallet
    let lw = rpc.handleMethod("listwallets", newJArray())
    check lw.kind == JArray
    check lw.len == 1
    check lw[0].getStr() == "smoke_w1"

  test "unloadwallet is reachable via handleMethod and removes a loaded wallet":
    # Create then unload. This exercises a real success path so we know the
    # case dispatch is wired (not just falling through to method-not-found).
    var pCreate = newJArray()
    pCreate.add(%"smoke_w2")
    discard rpc.handleMethod("createwallet", pCreate)

    var pUnload = newJArray()
    pUnload.add(%"smoke_w2")
    let resp = rpc.handleMethod("unloadwallet", pUnload)
    check resp.kind == JObject
    check resp.hasKey("warning")

    # Should be gone now
    let lw = rpc.handleMethod("listwallets", newJArray())
    check lw.kind == JArray
    check lw.len == 0

  test "loadwallet is reachable via handleMethod (round-trip create/unload/load)":
    # Create -> unload -> load. If dispatch were broken this would raise
    # RpcMethodNotFound, not a wallet-domain error.
    var pCreate = newJArray()
    pCreate.add(%"smoke_w3")
    discard rpc.handleMethod("createwallet", pCreate)

    var pUnload = newJArray()
    pUnload.add(%"smoke_w3")
    discard rpc.handleMethod("unloadwallet", pUnload)

    var pLoad = newJArray()
    pLoad.add(%"smoke_w3")
    let resp = rpc.handleMethod("loadwallet", pLoad)
    check resp.kind == JObject
    check resp.hasKey("name")
    check resp["name"].getStr() == "smoke_w3"
    check resp.hasKey("warning")

  test "all 5 methods are NOT routed to method-not-found":
    ## Regression guard: if someone deletes the dispatch entries again, this
    ## test fails loudly. We catch any RpcError and assert its code is not
    ## RpcMethodNotFound (-32601). Domain errors (e.g. wallet missing) are OK
    ## because they prove the case branch was matched.
    let methods = ["createwallet", "loadwallet", "unloadwallet",
                   "listwallets", "listwalletdir"]
    for m in methods:
      var p = newJArray()
      # Provide a unique nonexistent name to force a domain error path on
      # load/unload. createwallet will succeed; list* take no params.
      p.add(%("nonexistent_" & m))
      var caught: ref RpcError = nil
      try:
        discard rpc.handleMethod(m, p)
      except RpcError as e:
        caught = e
      if caught != nil:
        check caught.code != RpcMethodNotFound
