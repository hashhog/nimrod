## T1 R5 probe parity vs live Bitcoin Core (tools/r5-probes.d).
##
## CONTROL: `nim c -r tests/test_t1_r5_parity.nim`
##
## Encodes the T1 FAILs from the 2026-09-17 r5_probe sweep
## (tools/diff-test-artifacts/r5-probe/20260917T053858Z.json nimrod T1 40/46).
## A handler that accepts what Core rejects, or returns the wrong JSON-RPC
## code, fails these.

import unittest2
import std/[json, os, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/mining/fees

var testDbSeq = 0

proc makeRpc(): RpcServer =
  inc testDbSeq
  let dbPath = "/tmp/nimrod_t1_r5_parity_" & $getCurrentProcessId() & "_" & $testDbSeq
  if dirExists(dbPath):
    removeDir(dbPath)
  let params = regtestParams()
  let cs = newChainState(dbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  result = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)

proc rpcErr(rpc: RpcServer, methodName: string,
            params: JsonNode): tuple[code: int, msg: string] =
  try:
    discard rpc.handleMethod(methodName, params)
    (code: 0, msg: "(no error)")
  except RpcError as e:
    (code: e.code, msg: e.msg)

proc rpcOk(rpc: RpcServer, methodName: string, params: JsonNode): JsonNode =
  rpc.handleMethod(methodName, params)

suite "t1_r5":

  test "getnetworkhashps type-error is -3":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getnetworkhashps", %*["foo"])
    check r.code == -3
    check "Position 1 (nblocks)" in r.msg
    check "JSON value of type string is not of expected type number" in r.msg
    rpc.chainState.close()

  test "getnetworkhashps nblocks=0 is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getnetworkhashps", %*[0])
    check r.code == -8
    check r.msg == "Invalid nblocks. Must be a positive number or -1."
    rpc.chainState.close()

  test "getblocktemplate missing-segwit-rule is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getblocktemplate", %*[%*{}])
    check r.code == -8
    check r.msg ==
      "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})"
    rpc.chainState.close()

  test "getblocktemplate with segwit rule succeeds and bits is %08x":
    let rpc = makeRpc()
    let res = rpc.rpcOk("getblocktemplate", %*[%*{"rules": ["segwit"]}])
    check res.hasKey("version")
    check res.hasKey("previousblockhash")
    check res.hasKey("height")
    check res.hasKey("bits")
    let bits = res["bits"].getStr()
    check bits.len == 8
    for c in bits:
      check c in {'0'..'9', 'a'..'f'}
    rpc.chainState.close()

  test "addnode invalid-command is -1":
    let rpc = makeRpc()
    let r = rpc.rpcErr("addnode", %*["192.0.2.1:8333", "notacommand"])
    check r.code == -1
    check r.msg.startsWith("addnode ")
    rpc.chainState.close()

  test "sendrawtransaction deadbeef is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("sendrawtransaction", %*["deadbeef"])
    check r.code == -22
    check r.msg == "TX decode failed. Make sure the tx has at least one input."
    rpc.chainState.close()

  test "testmempoolaccept deadbeef is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("testmempoolaccept", %*[["deadbeef"]])
    check r.code == -22
    check r.msg ==
      "TX decode failed: deadbeef Make sure the tx has at least one input."
    rpc.chainState.close()
