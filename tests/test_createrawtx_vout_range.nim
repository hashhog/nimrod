## createrawtransaction — `vout` must be range-checked against int32
##
## THE DEFECT (regression pinned by this suite)
## --------------------------------------------
## `createrawtransaction`'s input parser only asked "is vout negative?".  It
## never asked "is vout too big?".  The value was then narrowed to the 32-bit
## `vout` field of the outpoint, so anything at or above 2^32 silently WRAPPED:
##
##     vout 4294967296 (2^32)   -->  outpoint index 0
##     vout 8589934592 (2^33)   -->  outpoint index 0
##
## Both were observed on the live mainnet node.  The RPC returned SUCCESS and a
## perfectly well-formed transaction hex — one that spends a COMPLETELY
## DIFFERENT outpoint from the one the caller asked for, and index 0 of a real
## txid is very likely a real, fundable output.  A caller that signs and
## broadcasts what it was handed spends the wrong coin, with no error and no
## log line anywhere.  Silent redirection of a spend is the worst shape a bug
## can take in this RPC.
##
## WHAT BITCOIN CORE DOES
## ----------------------
## Core reads the field with `find_value(o, "vout").getInt<int>()` —
## `int`, i.e. THIRTY-TWO bits (bitcoin-core/src/rpc/rawtransaction_util.cpp,
## AddInputs:38-45).  univalue's `getInt<Int>` (src/univalue/include/univalue.h)
## range-checks the parsed integer against the destination type and throws
## `std::runtime_error("JSON integer out of range")` when it does not fit; the
## RPC layer surfaces that as RPC_MISC_ERROR (-1).
##
## The ORDERING IS DELIBERATE AND IS UNIVALUE'S, NOT OURS: the range check
## lives inside the *conversion*, so it fires BEFORE the handler's own
## `if (nOutput < 0) throw ... "vout cannot be negative"` sign test ever runs.
## That is why -1 gets the vout-specific -8 message while 2147483648 — also
## "not a valid vout" in any human sense — gets the generic -1
## "JSON integer out of range" instead.  Matching Core here means matching that
## order, not just the two checks.
##
## The fix therefore adds, BEFORE the existing sign test:
##     if nOutput < low(int32) or nOutput > high(int32):
##       raise newRpcError(RpcMiscError, "JSON integer out of range")
##
## TEETH
## -----
## Cases 1-6 are all rejections, and a handler that rejected EVERY input would
## satisfy every one of them.  The two CONTROL cases exist to make that
## impossible: they drive the real handler to success and then DECODE the
## returned hex with the node's own deserializer, asserting the outpoint index
## that actually landed in the bytes.  In particular the int32-MAX control
## (2147483647) fails loudly if the new bound is off by one in the tight
## direction.
##
## References:
##   bitcoin-core/src/rpc/rawtransaction_util.cpp:38-45   AddInputs
##   bitcoin-core/src/univalue/include/univalue.h         getInt<Int>
##   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
##                                                        RPC_INVALID_PARAMETER = -8

import std/[unittest, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/rpc/server

const
  # Well-formed 64-hex txid; content is irrelevant, createrawtransaction never
  # looks it up (it builds an UNSIGNED tx and touches no chainstate).
  TestTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  Int32Max = 2147483647
  Int32MaxPlus1 = 2147483648'i64
  TwoPow32 = 4294967296'i64
  TwoPow33 = 8589934592'i64

proc minimalRpcServer(): RpcServer =
  ## createrawtransaction builds an unsigned transaction from its arguments
  ## alone — no chainstate, no mempool, no wallet — so a bare RpcServer is
  ## enough to drive the REAL handler (same rig as test_w135_parsehashv_neg8).
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

proc hexToBytesLocal(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc outputsObj(): JsonNode =
  ## A single OP_RETURN output. Deliberately data-only: it keeps the test
  ## independent of address encoding/network so a failure can only mean the
  ## input parser, never the output parser.
  %*{"data": "deadbeef"}

proc callCreateRaw(inputs: JsonNode): JsonNode =
  minimalRpcServer().handleMethod("createrawtransaction",
                                  %*[inputs, outputsObj()])

proc callCreateRawFull(params: JsonNode): JsonNode =
  minimalRpcServer().handleMethod("createrawtransaction", params)

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  ## Returns (0, "(no error)") when the call SUCCEEDS — so a test that expects
  ## a rejection fails loudly rather than silently passing on a success.
  var captured = (code: 0, msg: "(no error — call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

proc voutErr(v: int64): tuple[code: int, msg: string] =
  captureRpcError(callCreateRaw(%*[{"txid": TestTxid, "vout": v}]))

proc firstInputVout(txHex: string): uint32 =
  ## Decode with the node's own transaction deserializer and report the
  ## outpoint index that actually reached the wire bytes.
  let tx = deserializeTransaction(hexToBytesLocal(txHex))
  doAssert tx.inputs.len == 1, "expected exactly one input in the built tx"
  tx.inputs[0].prevOut.vout

suite "createrawtransaction vout range (int32) — REGRESSION":

  test "vout 4294967296 (2^32) -> -1 JSON integer out of range":
    ## PRE-FIX: returned a tx whose outpoint index was 0 (silent wrap).
    let r = voutErr(TwoPow32)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout 8589934592 (2^33) -> -1 JSON integer out of range":
    ## PRE-FIX: also wrapped to 0 — two different requests, one wrong spend.
    let r = voutErr(TwoPow33)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout 2147483648 (int32 MAX + 1) -> -1 JSON integer out of range":
    ## The exact boundary: one past what Core's getInt<int> can hold.
    let r = voutErr(Int32MaxPlus1)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout -2147483649 (int32 MIN - 1) -> -1, range beats the sign test":
    ## Negative AND out of int32 range. Core's range check lives inside the
    ## conversion, so it wins over the "cannot be negative" message. This is
    ## the ordering assertion.
    let r = voutErr(-2147483649'i64)
    check r.code == -1
    check r.msg == "JSON integer out of range"

suite "createrawtransaction — neighbouring guards still report Core's codes":

  test "vout -1 -> -8 Invalid parameter, vout cannot be negative":
    ## In int32 range, so the range check passes and the sign test speaks.
    let r = voutErr(-1)
    check r.code == -8
    check r.msg == "Invalid parameter, vout cannot be negative"

  test "sequence 4294967296 -> -8 sequence number is out of range":
    let r = captureRpcError(callCreateRaw(
      %*[{"txid": TestTxid, "vout": 0, "sequence": TwoPow32}]))
    check r.code == -8
    check r.msg == "Invalid parameter, sequence number is out of range"

  test "locktime -1 -> -8 locktime out of range":
    let r = captureRpcError(callCreateRawFull(
      %*[[{"txid": TestTxid, "vout": 0}], outputsObj(), -1]))
    check r.code == -8
    check r.msg == "Invalid parameter, locktime out of range"

suite "createrawtransaction — CONTROLS (an over-tight bound must fail here)":

  test "vout 2147483647 (int32 MAX) is ACCEPTED and lands in the tx bytes":
    ## Mandatory teeth: proves the new upper bound is `> high(int32)`, not
    ## `>= high(int32)` or some smaller cap. Fails if the guard is over-tight.
    let hex = callCreateRaw(%*[{"txid": TestTxid, "vout": Int32Max}]).getStr()
    check hex.len > 0
    check firstInputVout(hex) == 2147483647'u32

  test "an ordinary vout 7 is ACCEPTED and lands in the tx bytes":
    ## Mandatory teeth: proves the handler still does its normal job, so the
    ## rejection tests above cannot be satisfied by a reject-everything stub.
    let hex = callCreateRaw(%*[{"txid": TestTxid, "vout": 7}]).getStr()
    check hex.len > 0
    check firstInputVout(hex) == 7'u32
