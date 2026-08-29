## RPC integer arguments must be read at CORE'S WIDTH — and honoured.
##
## Core reads every numeric RPC argument through `UniValue::getInt<T>()`
## (univalue.h), which runs std::from_chars INTO THE DESTINATION WIDTH. The
## width check therefore lives inside the CONVERSION and fires BEFORE the
## handler's own domain test:
##
##   out of width / fractional  ->  RPC_MISC_ERROR (-1) "JSON integer out of
##                                  range"     (rpc/server.cpp:514-515)
##   converts, violates range   ->  RPC_INVALID_PARAMETER (-8)
##
## Nim's `getInt` hands back a 64-bit `int`, so nothing overflows and nothing
## crashes — the handler simply ACTS on a value Core refuses. Measured against
## a regtest Bitcoin Core oracle (tools/rpc-arg-differential.py), nimrod
## ACCEPTED 7 such arguments:
##
##   waitforblockheight 2^31 / -2^31-1   height and timeout both unbounded
##   getnodeaddresses 2^31               count unbounded, before its -8 test
##   gettxout <txid> -1 / 2^32           answered `null` — a legitimate-looking
##                                       "no such output" — for an argument
##                                       Core rejects outright. Core reads n as
##                                       getInt<uint32_t>, and from_chars
##                                       accepts NO SIGN for an unsigned
##                                       destination, so a negative vout is a
##                                       CONVERSION failure, not a lookup miss.
##
## TEETH: every case here is a rejection, and a handler that rejected
## EVERYTHING would satisfy all of them. The CONTROLS keep that honest: an
## in-range negative timeout must still say "Negative timeout", an in-range
## negative count must still say "Address count out of range", and vout
## 2147483648 / 4294967295 must still be ACCEPTED (they are valid uint32
## values, and an int32 bound here would wrongly reject half the range).
##
## References:
##   bitcoin-core/src/univalue/include/univalue.h   getInt<Int>
##   bitcoin-core/src/rpc/blockchain.cpp            gettxout n is uint32_t
##   bitcoin-core/src/rpc/net.cpp                   getnodeaddresses count

import std/[unittest, json]
import ../src/rpc/server

const TestTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

const OutOfInt32 = [2147483648'i64, -2147483649'i64, 4294967296'i64, -4294967297'i64]

proc minimalRpcServer(): RpcServer =
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error — call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

proc callErr(mth: string, params: JsonNode): tuple[code: int, msg: string] =
  captureRpcError(minimalRpcServer().handleMethod(mth, params))

const RangeErr = (code: -1, msg: "JSON integer out of range")

suite "wait family reads height/timeout at Core's width":
  test "waitforblockheight height outside int32 -> -1":
    for v in OutOfInt32:
      check callErr("waitforblockheight", %*[v]) == RangeErr

  test "waitforblockheight timeout outside int32 -> -1":
    for v in OutOfInt32:
      check callErr("waitforblockheight", %*[1, v]) == RangeErr

  test "CONTROL an in-range negative timeout keeps Core's own message":
    check callErr("waitforblockheight", %*[1, -1]) ==
      (code: -1, msg: "Negative timeout")

suite "getnodeaddresses count is getInt<int>, then -8":
  test "count outside int32 -> -1 (the CONVERSION, not the range test)":
    for v in OutOfInt32:
      check callErr("getnodeaddresses", %*[v]) == RangeErr

  test "CONTROL an in-range negative count keeps the -8 domain error":
    check callErr("getnodeaddresses", %*[-1]) ==
      (code: -8, msg: "Address count out of range")

suite "estimatesmartfee conf_target / estimate_mode":
  # These were NOT in the hostile-integer findings: the differential's CONTROL
  # (an in-range call with the baseline "" mode) is what exposed the mode being
  # ignored, and the conf_target error carried our own code and text.
  test "conf_target outside int32 -> -1":
    for v in OutOfInt32:
      check callErr("estimatesmartfee", %*[v]) == RangeErr

  test "conf_target outside [1,1008] -> -8 with Core's message":
    for v in [0, -1, 1009, 99999]:
      check callErr("estimatesmartfee", %*[v]) ==
        (code: -8, msg: "Invalid conf_target, must be between 1 and 1008")

  test "an unknown estimate_mode is rejected, not ignored":
    for m in ["", "garbage", "ECONOMICALLY"]:
      check callErr("estimatesmartfee", %*[6, m]) ==
        (code: -8, msg: "Invalid estimate_mode parameter, must be one of: " &
                        "\"unset\", \"economical\", \"conservative\"")

  test "CONTROL the three fee modes and in-range targets are accepted":
    for m in ["unset", "economical", "CONSERVATIVE", "Economical"]:
      check callErr("estimatesmartfee", %*[6, m]).code == 0
    for v in [1, 6, 1008]:
      check callErr("estimatesmartfee", %*[v]).code == 0

suite "gettxout n is getInt<uint32_t>":
  test "a negative or >uint32 vout is a conversion failure":
    for v in [-1'i64, -2147483649'i64, 4294967296'i64]:
      check callErr("gettxout", %*[TestTxid, v]) == RangeErr

  test "CONTROL vout 2^31 and uint32 MAX are VALID (uint32, not int32)":
    # An int32 bound here would reject HALF the legal vout range. This asserts
    # the bound itself rather than driving the handler, because gettxout's
    # SUCCESS path dereferences the mempool and this suite builds a bare
    # RpcServer with no mempool attached — the rejection cases above all return
    # before that point, which is exactly why they can be driven end-to-end.
    check coreUint32Bound(2147483648'i64) == 2147483648
    check coreUint32Bound(4294967295'i64) == 4294967295

  test "CONTROL the int32 bound accepts its own boundary values":
    check coreInt32Bound(2147483647'i64) == 2147483647
    check coreInt32Bound(-2147483648'i64) == -2147483648
