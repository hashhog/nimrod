## T3 R5 wallet-lane parity vs Bitcoin Core (tools/r5-probes.d/wallet.jsonl).
##
## CONTROL: `nim c -r tests/test_t3_r5_parity.nim`
##
## Encodes the T3 FAILs from the 2026-09-17 regtest lane
## (`bash tools/regtest-harness.sh --r5-lane=nimrod`): credit-on-connect,
## lastprocessedblock, missing methods, and Core error-code mapping.
## A handler that accepts what Core rejects, or returns the wrong JSON-RPC
## code, fails these.

import unittest2
import std/[json, os, tables, options, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/[wallet, manager]
import ../src/primitives/[types, serialize]
import ../src/crypto/address

var testDbSeq = 0

proc makeRpc(): RpcServer =
  inc testDbSeq
  let dbPath = "/tmp/nimrod_t3_r5_parity_" & $getCurrentProcessId() & "_" & $testDbSeq
  if dirExists(dbPath):
    removeDir(dbPath)
  createDir(dbPath)
  let params = regtestParams()
  var cs = newChainState(dbPath, params)
  if cs.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    doAssert cs.connectBlock(genesis, 0).isOk
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  result = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)
  result.walletManager = newWalletManager(dbPath, params, cs)
  let wm = result.walletManager
  cs.connectHook = proc(blk: Block, height: int32) {.gcsafe, raises: [].} =
    try:
      wm.scanBlockIntoLoadedWallets(blk, height)
    except CatchableError:
      discard

proc rpcErr(rpc: RpcServer, methodName: string,
            params: JsonNode): tuple[code: int, msg: string] =
  try:
    discard rpc.handleMethod(methodName, params)
    (code: 0, msg: "(no error)")
  except RpcError as e:
    (code: e.code, msg: e.msg)

proc rpcOk(rpc: RpcServer, methodName: string, params: JsonNode): JsonNode =
  rpc.handleMethod(methodName, params)

suite "t3_r5":

  test "createwallet no-name is -1":
    let rpc = makeRpc()
    let r = rpc.rpcErr("createwallet", %*[])
    check r.code == -1
    rpc.chainState.close()

  test "getwalletinfo wrong-arity is -1 and lastprocessedblock is present":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let r = rpc.rpcErr("getwalletinfo", %*["unexpected"])
    check r.code == -1
    let info = rpc.rpcOk("getwalletinfo", %*[])
    check info["walletname"].getStr() == "r5"
    check info["descriptors"].getBool() == true
    check info.hasKey("lastprocessedblock")
    check info["lastprocessedblock"].hasKey("hash")
    check info["lastprocessedblock"].hasKey("height")
    rpc.chainState.close()

  test "getnewaddress bad-address-type is -5":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let r = rpc.rpcErr("getnewaddress", %*["", "bogustype"])
    check r.code == -5
    rpc.chainState.close()

  test "listwallets wrong-arity is -1":
    let rpc = makeRpc()
    let r = rpc.rpcErr("listwallets", %*["unexpected"])
    check r.code == -1
    rpc.chainState.close()

  test "stop wrong-type is -3":
    let rpc = makeRpc()
    let r = rpc.rpcErr("stop", %*["notanumber"])
    check r.code == -3
    let ok = rpc.rpcOk("stop", %*[])
    check ok.kind == JString
    rpc.chainState.close()

  test "getbalances is dispatched and has mine + lastprocessedblock":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let r = rpc.rpcOk("getbalances", %*[])
    check r.hasKey("mine")
    check r["mine"].hasKey("trusted")
    check r["mine"].hasKey("untrusted_pending")
    check r["mine"].hasKey("immature")
    check r.hasKey("lastprocessedblock")
    let arity = rpc.rpcErr("getbalances", %*["unexpected"])
    check arity.code == -1
    rpc.chainState.close()

  test "listunspent invalid-address is -5 and duplicate is -8":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let inv = rpc.rpcErr("listunspent", %*[1, 9999999, %*["notanaddress"]])
    check inv.code == -5
    let dup = rpc.rpcErr("listunspent",
      %*[1, 9999999, %*["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                        "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]])
    check dup.code == -8
    rpc.chainState.close()

  test "listtransactions negative-count/skip are -8":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    check rpc.rpcErr("listtransactions", %*["*", -1]).code == -8
    check rpc.rpcErr("listtransactions", %*["*", 10, -1]).code == -8
    rpc.chainState.close()

  test "sendtoaddress invalid-amount is -3":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let r = rpc.rpcErr("sendtoaddress",
      %*["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", -1])
    check r.code == -3
    rpc.chainState.close()

  test "loadwallet not-found is -18; already-loaded is -35":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    check rpc.rpcErr("loadwallet", %*["r5probe_missing"]).code == -18
    check rpc.rpcErr("loadwallet", %*["r5"]).code == -35
    rpc.chainState.close()

  test "unloadwallet not-loaded is -18":
    let rpc = makeRpc()
    check rpc.rpcErr("unloadwallet", %*["r5probe_missing"]).code == -18
    rpc.chainState.close()

  test "backupwallet bad-destination is -4; restorewallet missing-backup is -8":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    check rpc.rpcErr("backupwallet",
      %*["/nonexistent-r5probe-dir/backup.dat"]).code == -4
    check rpc.rpcErr("restorewallet",
      %*["r5probe_fresh", "/nonexistent/r5probe-nope.bak"]).code == -8
    rpc.chainState.close()

  test "send no-outputs is -8; invalid-address is -5":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    check rpc.rpcErr("send", %*[%*[]]).code == -8
    check rpc.rpcErr("send", %*[%*[{"notanaddress": 0.001}]]).code == -5
    rpc.chainState.close()

  test "scanBlockForWallet credits a getnewaddress output":
    let rpc = makeRpc()
    discard rpc.rpcOk("createwallet", %*["r5"])
    let addrStr = rpc.rpcOk("getnewaddress", %*[]).getStr()
    check addrStr.startsWith("bcrt1q")
    let info = rpc.rpcOk("getaddressinfo", %*[addrStr])
    check info["ismine"].getBool()
    check info.hasKey("desc")
    var w = rpc.walletManager.getWallet("r5").get().wallet
    let spk = scriptPubKeyForAddress(decodeAddress(addrStr))
    var mockTxid: array[32, byte]
    mockTxid[0] = 0xab
    let mockTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
            vout: 0xffffffff'u32),
        scriptSig: @[0x04'u8, 0xff, 0xff, 0xff, 0xff],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(value: Satoshi(250_000_000), scriptPubKey: spk)],
      witnesses: @[],
      lockTime: 0
    )
    let mockBlock = Block(
      header: BlockHeader(
        version: 0x20000000,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: default(array[32, byte]),
        timestamp: 1234567890,
        bits: 0x1d00ffff'u32,
        nonce: 0
      ),
      txs: @[mockTx]
    )
    w.scanBlockForWallet(mockBlock, 50)
    check w.utxos.len == 1
    check w.txHistory.len == 1
    rpc.chainState.close()

  test "walletprocesspsbt is listed in help":
    let rpc = makeRpc()
    let h = rpc.rpcOk("help", %*[]).getStr()
    check "walletprocesspsbt" in h
    check "getbalances" in h
    check "backupwallet" in h
    check "restorewallet" in h
    check "send " in h or "send [" in h
    rpc.chainState.close()
