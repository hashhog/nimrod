## getblockheader with a non-bool `verbose` must be -3 "Wrong type passed".
##
## Found by the Core regtest ratchet (nimrod, 2026-11-05):
##   operator/getblockheader/bad-verbose:$  core -3, nimrod returned the header
## Core type-checks every argument in RPCHelpMan::HandleRequest before the
## handler (hash parse / lookup) runs; a JSON null is the default.

import unittest2
import std/[json, os, tempfiles]
import ../src/rpc/server
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/mempool/mempool
import ../src/mining/fees

template rpcErr(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error - call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

const Zero = "0000000000000000000000000000000000000000000000000000000000000000"

suite "getblockheader verbose type check":
  test "string verbose is -3 with the Position 2 wrapper, before the lookup":
    let params = regtestParams()
    let dir = createTempDir("nimrod_gbh_", "")
    defer: removeDir(dir)
    var cs = newChainState(dir / "db", params)
    defer: cs.close()
    let rpc = newRpcServer(port = 18443'u16, chainState = cs,
                           mempool = newMempool(cs, params), peerManager = nil,
                           feeEstimator = newFeeEstimator(), params = params)
    # the hash is absent: a -5 would mean the lookup ran before the type check
    let e = rpcErr(rpc.handleMethod("getblockheader", %*[Zero, "x"]))
    check e.code == -3
    check e.msg == "Wrong type passed:\n{\n    \"Position 2 (verbose)\": " &
      "\"JSON value of type string is not of expected type bool\"\n}"
    let n = rpcErr(rpc.handleMethod("getblockheader", %*[Zero, 1]))
    check n.code == -3
    check n.msg == "Wrong type passed:\n{\n    \"Position 2 (verbose)\": " &
      "\"JSON value of type number is not of expected type bool\"\n}"

  test "bool and null verbose still reach the lookup (-5 Block not found)":
    let params = regtestParams()
    let dir = createTempDir("nimrod_gbh_", "")
    defer: removeDir(dir)
    var cs = newChainState(dir / "db", params)
    defer: cs.close()
    let rpc = newRpcServer(port = 18443'u16, chainState = cs,
                           mempool = newMempool(cs, params), peerManager = nil,
                           feeEstimator = newFeeEstimator(), params = params)
    for v in [%false, %true, newJNull()]:
      let e = rpcErr(rpc.handleMethod("getblockheader", %*[Zero, v]))
      check e.code == -5
