## createrawtransaction must HONOUR the `version` argument, not ignore it.
##
## THE DEFECT
## ----------
## Core's createrawtransaction takes a 5th argument, `version`
## (bitcoin-core/src/rpc/rawtransaction.cpp:122). It reads it as
## `self.Arg<uint32_t>("version")`, bounds it to
## [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] = [1, 3]
## (src/policy/policy.h:152-153) and ASSIGNS it to the transaction
## (src/rpc/rawtransaction_util.cpp:158-161).
##
## nimrod hardcoded `version: 2'i32` and ignored the argument. Asked for
## version 1, 2 or 3 it returned 02000000 every time, and version 4 — which
## Core rejects — was accepted. A success reply for a request that was not
## honoured, and not cosmetic: version 3 is TRUC (BIP 431), so a caller who
## asked for v3 and received v2 holds a transaction with different relay
## behaviour from the one they requested, with nothing in the reply saying so.
##
## Measured 2026-08-29 by tools/rpc-arg-differential.py against a real regtest
## Core: seven of the ten implementations behaved identically here.
##
## THE UNSIGNED WIDTH DECIDES WHICH ERROR YOU GET
## ---------------------------------------------
## `version` is read as uint32, unlike the int32 used for `vout`, so
## 2147483648 SURVIVES the conversion and reaches the DOMAIN error (-8), while
## -1 and 4294967296 fail the CONVERSION first (-1). Those two are asserted
## separately below; collapsing them would look close enough and be wrong in
## both directions.
##
## A NIM-SPECIFIC HAZARD, guarded explicitly: `getInt()` silently returns 0 for
## any node that is not a JInt. Without the `kind != JInt` check, a float or a
## string version would become 0 and be reported as out of DOMAIN (-8) rather
## than as a conversion failure (-1).
##
## THE ASSERTIONS READ THE VERSION BYTES off the returned transaction, decoded
## with the node's own deserializer. Checking only that the call was accepted
## is exactly the pre-fix behaviour.
##
## References:
##   bitcoin-core/src/rpc/rawtransaction.cpp:122           the argument
##   bitcoin-core/src/rpc/rawtransaction_util.cpp:158-161  bound + assign
##   bitcoin-core/src/policy/policy.h:152-153              [1, 3]

import std/[unittest, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/rpc/server

const
  TestTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

proc minimalRpcServer(): RpcServer =
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

proc hexToBytesLocal(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc inputsArr(): JsonNode = %*[{"txid": TestTxid, "vout": 0}]
proc outputsObj(): JsonNode = %*{"data": "deadbeef"}

proc callWithVersion(v: JsonNode): JsonNode =
  if v.isNil:
    minimalRpcServer().handleMethod("createrawtransaction",
                                    %*[inputsArr(), outputsObj(), 0, false])
  else:
    minimalRpcServer().handleMethod("createrawtransaction",
                                    %*[inputsArr(), outputsObj(), 0, false, v])

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error — call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

proc versionErr(v: int64): tuple[code: int, msg: string] =
  captureRpcError(callWithVersion(%v))

proc txVersionOf(node: JsonNode): int32 =
  ## Decode with the node's OWN deserializer and report the version that
  ## actually reached the wire bytes.
  deserializeTransaction(hexToBytesLocal(node.getStr())).version

suite "createrawtransaction version — REGRESSION (was hardcoded 2)":
  test "version 1 is emitted, not forced to 2":
    check txVersionOf(callWithVersion(%1)) == 1'i32

  test "version 2 is emitted":
    check txVersionOf(callWithVersion(%2)) == 2'i32

  test "version 3 (TRUC) is emitted, not silently downgraded":
    check txVersionOf(callWithVersion(%3)) == 3'i32

suite "createrawtransaction version — out of DOMAIN is -8":
  # In range for a uint32, out of range for a transaction version: Core
  # answers -8 AFTER a successful conversion.
  test "version 0":
    check versionErr(0) == (code: -8,
      msg: "Invalid parameter, version out of range(1~3)")
  test "version 4":
    check versionErr(4) == (code: -8,
      msg: "Invalid parameter, version out of range(1~3)")
  test "version 2147483648 (int32 MAX + 1, still inside uint32)":
    check versionErr(2147483648'i64) == (code: -8,
      msg: "Invalid parameter, version out of range(1~3)")

suite "createrawtransaction version — outside uint32 fails CONVERSION first":
  # Paired with the suite above, this is what pins the boundary in BOTH
  # directions: -1 here, -8 there, and the split is at the uint32 edge.
  test "version -1":
    check versionErr(-1) == (code: -1, msg: "JSON integer out of range")
  test "version -2147483649":
    check versionErr(-2147483649'i64) == (code: -1, msg: "JSON integer out of range")
  test "version 4294967296 (2^32)":
    check versionErr(4294967296'i64) == (code: -1, msg: "JSON integer out of range")

suite "createrawtransaction version — CONTROLS":
  # Without these, a handler that rejected every version would satisfy every
  # rejection test above.
  test "absent version defaults to 2 (Core DEFAULT_RAWTX_VERSION)":
    check txVersionOf(callWithVersion(nil)) == 2'i32

  test "explicit null version defaults to 2":
    check txVersionOf(callWithVersion(newJNull())) == 2'i32

  test "a non-integer version is a conversion failure, not version 0":
    # Nim's getInt() returns 0 for a non-JInt node. If that 0 reached the
    # domain check the answer would be -8; Core's is -1.
    check captureRpcError(callWithVersion(%"3")) ==
      (code: -1, msg: "JSON integer out of range")
