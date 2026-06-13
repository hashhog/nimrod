## W135 — ParseHashV parse-boundary parity (RPC_INVALID_PARAMETER, -8)
##
## Bitcoin Core's ParseHashV (rpc/util.cpp:117) rejects a malformed
## txid/blockhash argument at the PARSE boundary, BEFORE any lookup, with
## RPC_INVALID_PARAMETER (-8) and one of two messages:
##   - wrong length: "<name> must be of length 64 (not N, for '<hex>')"
##   - 64 chars but non-hex: "<name> must be hexadecimal string (not '<hex>')"
## A WELL-FORMED 64-hex hash that is simply absent stays at the handler's
## -5 (RPC_INVALID_ADDRESS_OR_KEY) / null behavior — that case is NOT changed
## by this wave and is exercised by the W125 suite / live RPC tests.
##
## This suite proves BOTH directions of the parse boundary:
##   (a) malformed arg (too-short hex AND 64 non-hex 'z' chars) -> code -8,
##       for every fixed method (getrawtransaction, gettxout, getblock,
##       getmempoolentry, getblockheader) via handleMethod on a nil-state
##       RpcServer — the guard fires before any chainstate/mempool access.
##   (b) a well-formed 64-zero hash PASSES validateHashV (no exception),
##       confirming the guard does not steal the absent-hash -5/null path.
##
## References:
##   bitcoin-core/src/rpc/util.cpp:117      ParseHashV
##   bitcoin-core/src/rpc/protocol.h        RPC_INVALID_PARAMETER = -8
##   bitcoin-core/src/rpc/rawtransaction.cpp:287,300  "parameter 1"/"parameter 3"
##   bitcoin-core/src/rpc/blockchain.cpp:639,842,1224 "hash"/"blockhash"/"txid"
##   bitcoin-core/src/rpc/mempool.cpp:844            "txid"

import std/[unittest, json, strutils]
import ../src/rpc/server

proc minimalRpcServer(): RpcServer =
  ## Bare-bones RpcServer (nil chainstate/mempool). Sufficient because the
  ## ParseHashV guard runs before any of those fields are touched.
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "internal error: " & e.msg)
  captured

proc methodErr(rpc: RpcServer, name: string, params: JsonNode):
    tuple[code: int, msg: string] =
  captureRpcError(rpc.handleMethod(name, params))

let
  tooShort = "abc"             # wrong length (3 chars)
  nonHex64 = 'z'.repeat(64)    # 64 'z' chars: right length, non-hex
  zero64   = '0'.repeat(64)    # well-formed 64-hex (absent → handler -5/null)

# The (method, paramsBuilder) table: each entry places the hash in the slot
# the RPC actually parses (getrawtransaction blockhash is param index 2).
proc rawtxParams(h: string): JsonNode = %*[h]
proc rawtxBlockhashParams(h: string): JsonNode =
  # well-formed txid, malformed blockhash in slot 3 ("parameter 3")
  %*[zero64, true, h]
proc txoutParams(h: string): JsonNode = %*[h, 0]
proc getblockParams(h: string): JsonNode = %*[h]
proc getmempoolentryParams(h: string): JsonNode = %*[h]
proc getblockheaderParams(h: string): JsonNode = %*[h]

suite "W135: ParseHashV malformed -> -8 (parse boundary)":

  test "getrawtransaction txid too-short -> -8, length message":
    let r = minimalRpcServer().methodErr("getrawtransaction", rawtxParams(tooShort))
    check r.code == -8
    check "parameter 1 must be of length 64" in r.msg

  test "getrawtransaction txid 64-non-hex -> -8, hexadecimal message":
    let r = minimalRpcServer().methodErr("getrawtransaction", rawtxParams(nonHex64))
    check r.code == -8
    check "parameter 1 must be hexadecimal string" in r.msg

  test "getrawtransaction blockhash too-short -> -8 (parameter 3)":
    let r = minimalRpcServer().methodErr(
      "getrawtransaction", rawtxBlockhashParams(tooShort))
    check r.code == -8
    check "parameter 3 must be of length 64" in r.msg

  test "getrawtransaction blockhash 64-non-hex -> -8 (parameter 3)":
    let r = minimalRpcServer().methodErr(
      "getrawtransaction", rawtxBlockhashParams(nonHex64))
    check r.code == -8
    check "parameter 3 must be hexadecimal string" in r.msg

  test "gettxout txid too-short -> -8, length message":
    let r = minimalRpcServer().methodErr("gettxout", txoutParams(tooShort))
    check r.code == -8
    check "txid must be of length 64" in r.msg

  test "gettxout txid 64-non-hex -> -8, hexadecimal message":
    let r = minimalRpcServer().methodErr("gettxout", txoutParams(nonHex64))
    check r.code == -8
    check "txid must be hexadecimal string" in r.msg

  test "getblock blockhash too-short -> -8, length message":
    let r = minimalRpcServer().methodErr("getblock", getblockParams(tooShort))
    check r.code == -8
    check "blockhash must be of length 64" in r.msg

  test "getblock blockhash 64-non-hex -> -8, hexadecimal message":
    let r = minimalRpcServer().methodErr("getblock", getblockParams(nonHex64))
    check r.code == -8
    check "blockhash must be hexadecimal string" in r.msg

  test "getmempoolentry txid too-short -> -8, length message":
    let r = minimalRpcServer().methodErr(
      "getmempoolentry", getmempoolentryParams(tooShort))
    check r.code == -8
    check "txid must be of length 64" in r.msg

  test "getmempoolentry txid 64-non-hex -> -8, hexadecimal message":
    let r = minimalRpcServer().methodErr(
      "getmempoolentry", getmempoolentryParams(nonHex64))
    check r.code == -8
    check "txid must be hexadecimal string" in r.msg

  test "getblockheader blockhash too-short -> -8 (name 'hash')":
    let r = minimalRpcServer().methodErr(
      "getblockheader", getblockheaderParams(tooShort))
    check r.code == -8
    check "hash must be of length 64" in r.msg

  test "getblockheader blockhash 64-non-hex -> -8 (name 'hash')":
    let r = minimalRpcServer().methodErr(
      "getblockheader", getblockheaderParams(nonHex64))
    check r.code == -8
    check "hash must be hexadecimal string" in r.msg

suite "W135: well-formed 64-hex hash passes the parse boundary (stays -5/null)":

  test "validateHashV accepts a 64-zero hash without raising (absent case kept)":
    ## A well-formed-but-absent hash must NOT be stolen by the -8 guard; the
    ## downstream handler still returns -5 / null. Proven here at the guard
    ## level: validateHashV does not raise for a valid 64-hex string.
    var raised = false
    try:
      validateHashV(zero64, "txid")
    except RpcError:
      raised = true
    check not raised

  test "validateHashV accepts mixed-case 64-hex without raising":
    var raised = false
    try:
      validateHashV("ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789", "blockhash")
    except RpcError:
      raised = true
    check not raised

  test "validateHashV too-short raises -8 with Core length message":
    var code = 0
    var msg = ""
    try:
      validateHashV(tooShort, "txid")
    except RpcError as e:
      code = e.code
      msg = e.msg
    check code == -8
    check msg == "txid must be of length 64 (not 3, for 'abc')"

  test "validateHashV 64-non-hex raises -8 with Core hexadecimal message":
    var code = 0
    var msg = ""
    try:
      validateHashV(nonHex64, "blockhash")
    except RpcError as e:
      code = e.code
      msg = e.msg
    check code == -8
    check msg == "blockhash must be hexadecimal string (not '" & nonHex64 & "')"
