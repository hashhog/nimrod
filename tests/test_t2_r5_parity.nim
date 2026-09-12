## T2 R5 probe parity vs live Bitcoin Core (tools/r5-probes.d).
##
## CONTROL: `nim c -r tests/test_t2_r5_parity.nim`
##
## Encodes the T2 FAILs from the 2026-09-01 r5_probe sweep
## (tools/diff-test-artifacts/r5-probe/20260901T182642Z.json nimrod T2 12/41).
## A production handler that reverts to -32602 / method-not-found fails these.

import unittest2
import std/[json, os, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/mining/fees

var testDbSeq = 0
const PsbtA = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
const RawHex = "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"
const WifPriv1 = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
const Key1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
const Key2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
const DescNoCsum = "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)"
const DescCsum = "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#e72f49hy"

proc makeRpc(): RpcServer =
  inc testDbSeq
  let dbPath = "/tmp/nimrod_t2_r5_parity_" & $getCurrentProcessId() & "_" & $testDbSeq
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

suite "t2_r5":

  test "decoderawtransaction nonhex is -22 TX decode failed":
    let rpc = makeRpc()
    let r = rpc.rpcErr("decoderawtransaction", %*["zz"])
    check r.code == -22
    check r.msg == "TX decode failed"
    rpc.chainState.close()

  test "validateaddress exact-invalid matches Core Base58 checksum/length":
    let rpc = makeRpc()
    let res = rpc.rpcOk("validateaddress", %*["notanaddress"])
    check res["isvalid"].getBool() == false
    check res["error"].getStr() ==
      "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
    rpc.chainState.close()

  test "decodescript nonhex is -8 ParseHexV":
    let rpc = makeRpc()
    let r = rpc.rpcErr("decodescript", %*["zz"])
    check r.code == -8
    check r.msg == "argument must be hexadecimal string (not 'zz')"
    rpc.chainState.close()

  test "verifytxoutproof nonhex is -8 ParseHexV":
    let rpc = makeRpc()
    let r = rpc.rpcErr("verifytxoutproof", %*["zz"])
    check r.code == -8
    check r.msg == "proof must be hexadecimal string (not 'zz')"
    rpc.chainState.close()

  test "gettxspendingprevout missing vout is -3":
    let rpc = makeRpc()
    let r = rpc.rpcErr("gettxspendingprevout",
      %*[[%*{"txid": "0".repeat(64)}]])
    check r.code == -3
    rpc.chainState.close()

  test "pruneblockchain string height is -3 before prune-mode gate":
    let rpc = makeRpc()
    let r = rpc.rpcErr("pruneblockchain", %*["zz"])
    check r.code == -3
    check "not of expected type number" in r.msg
    rpc.chainState.close()

  test "getindexinfo numeric arg is -3":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getindexinfo", %*[123])
    check r.code == -3
    check "not of expected type string" in r.msg
    rpc.chainState.close()

  test "scantxoutset bogus action is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("scantxoutset", %*["bogus"])
    check r.code == -8
    check r.msg == "Invalid action 'bogus'"
    rpc.chainState.close()

  test "scanblocks bogus action is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("scanblocks", %*["bogus"])
    check r.code == -8
    check r.msg == "Invalid action 'bogus'"
    rpc.chainState.close()

  test "submitpackage empty array is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("submitpackage", %*[[]])
    check r.code == -8
    check r.msg.startsWith("Array must contain between 1 and")
    rpc.chainState.close()

  test "submitpackage nonhex is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("submitpackage", %*[["zz"]])
    check r.code == -22
    rpc.chainState.close()

  test "combinepsbt empty array is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("combinepsbt", %*[[]])
    check r.code == -8
    check r.msg == "Parameter 'txs' cannot be empty"
    rpc.chainState.close()

  test "createmultisig not-enough-keys is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("createmultisig", %*[3, [Key1, Key2]])
    check r.code == -8
    check "not enough keys supplied" in r.msg
    rpc.chainState.close()

  test "deriveaddresses missing checksum is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("deriveaddresses", %*[DescNoCsum])
    check r.code == -5
    check r.msg == "Missing checksum"
    rpc.chainState.close()

  test "deriveaddresses range on unranged is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("deriveaddresses", %*[DescCsum, [0, 2]])
    check r.code == -8
    check r.msg == "Range should not be specified for an un-ranged descriptor"
    rpc.chainState.close()

  test "getdescriptorinfo invalid descriptor is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getdescriptorinfo", %*["notadescriptor"])
    check r.code == -5
    rpc.chainState.close()

  test "getdescriptorinfo bad checksum is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getdescriptorinfo", %*[DescNoCsum & "#00000000"])
    check r.code == -5
    rpc.chainState.close()

  test "createpsbt canonical-exact matches Core ConstructTransaction PSBT":
    let rpc = makeRpc()
    let inputs = %*[%*{"txid": "a".repeat(64), "vout": 0}]
    let outputs = %*{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001}
    let res = rpc.rpcOk("createpsbt", %*[inputs, outputs])
    check res.getStr() == PsbtA
    rpc.chainState.close()

  test "createpsbt bad-txid is -8":
    let rpc = makeRpc()
    let inputs = %*[%*{"txid": "zz", "vout": 0}]
    let outputs = %*{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001}
    let r = rpc.rpcErr("createpsbt", %*[inputs, outputs])
    check r.code == -8
    rpc.chainState.close()

  test "prioritisetransaction bad-txid is -8":
    let rpc = makeRpc()
    let r = rpc.rpcErr("prioritisetransaction", %*["zz", 0, 1000])
    check r.code == -8
    rpc.chainState.close()

  test "analyzepsbt bad-base64 is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("analyzepsbt", %*["notbase64!!"])
    check r.code == -22
    rpc.chainState.close()

  test "finalizepsbt bad-base64 is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("finalizepsbt", %*["notbase64!!"])
    check r.code == -22
    rpc.chainState.close()

  test "decodepsbt bad-base64 is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("decodepsbt", %*["notbase64!!"])
    check r.code == -22
    rpc.chainState.close()

  test "verifymessage malformed-sig is -3":
    let rpc = makeRpc()
    let r = rpc.rpcErr("verifymessage",
      %*["1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S", "not-base64!!",
          "hashhog r5 probe"])
    check r.code == -3
    check r.msg == "Malformed base64 encoding"
    rpc.chainState.close()

  test "getdeploymentinfo notfound is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("getdeploymentinfo", %*["0".repeat(63) & "1"])
    check r.code == -5
    check r.msg == "Block not found"
    rpc.chainState.close()

  test "importmempool missing file is -1":
    let rpc = makeRpc()
    let r = rpc.rpcErr("importmempool",
      %*["/nonexistent/r5-probe-no-such-file.dat"])
    check r.code == -1
    check r.msg == "Unable to import mempool file, see debug log for details."
    rpc.chainState.close()

  test "utxoupdatepsbt bad-base64 is -22":
    let rpc = makeRpc()
    let r = rpc.rpcErr("utxoupdatepsbt", %*["notbase64!!"])
    check r.code == -22
    rpc.chainState.close()

  test "utxoupdatepsbt unknown-inputs passthrough is a PSBT string":
    let rpc = makeRpc()
    let res = rpc.rpcOk("utxoupdatepsbt", %*[PsbtA])
    check res.kind == JString
    check res.getStr().startsWith("cHNidP8")
    rpc.chainState.close()

  test "descriptorprocesspsbt bad-descriptor is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("descriptorprocesspsbt", %*[PsbtA, ["nonsense(desc)"]])
    check r.code == -5
    rpc.chainState.close()

  test "descriptorprocesspsbt update of unknown-input PSBT returns complete=false":
    let rpc = makeRpc()
    let res = rpc.rpcOk("descriptorprocesspsbt",
      %*[PsbtA, ["wpkh(" & WifPriv1 & ")"]])
    check res["complete"].getBool() == false
    check res.hasKey("psbt")
    rpc.chainState.close()

  test "signrawtransactionwithkey bad-privkey is -5":
    let rpc = makeRpc()
    let r = rpc.rpcErr("signrawtransactionwithkey", %*[RawHex, ["notakey"]])
    check r.code == -5
    rpc.chainState.close()

  test "signrawtransactionwithkey sign-complete is complete=true":
    let rpc = makeRpc()
    let prev = %*[%*{
      "txid": "a".repeat(64),
      "vout": 0,
      "scriptPubKey": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      "amount": 0.002
    }]
    let res = rpc.rpcOk("signrawtransactionwithkey",
      %*[RawHex, [WifPriv1], prev])
    check res["complete"].getBool() == true
    check res.hasKey("hex")
    rpc.chainState.close()

  test "combinerawtransaction unknown-input is -25":
    let rpc = makeRpc()
    let r = rpc.rpcErr("combinerawtransaction", %*[[RawHex, RawHex]])
    check r.code == -25
    check r.msg == "Input not found or already spent"
    rpc.chainState.close()
