## getblockhash: an out-of-domain height is an ERROR, never a real block hash.
##
## FOUND 2026-08-29. nimrod answered the REAL mainnet genesis hash
## `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, with
## `error:null`, to heights that are not heights at all:
##
##     getblockhash 1.5                    -> genesis hash
##     getblockhash 9223372036854775808    -> genesis hash
##     getblockhash 18446744073709551616   -> genesis hash
##
## byte-identical to `getblockhash 0`. Bitcoin Core answers
## -1 "JSON integer out of range" to all three.
##
## MECHANISM: the handler read the height with `params[0].getInt()`, which
## returns 0 for every JSON value Nim's parser does not store as a JInt — and
## 0 is a VALID height. Nim stores 1.5 as JFloat and stores an integer literal
## larger than int64 as a JString, so all three collapsed to height 0. What did
## parse as JInt was then narrowed with `int32(height)`, which truncates rather
## than raising because range checks are compiled out of the release build.
##
## WHY THIS IS WORSE THAN A CRASH: the returned value is a genuine, valid
## mainnet block hash. Nothing downstream looks wrong, so a caller that
## computed a height incorrectly gets a confident answer about a completely
## different block. Same fabrication family as the createrawtransaction sweep
## (a plausible result manufactured from input that could not be honoured).
##
## ORDERING: Core reads the height with getInt<int>() — univalue parsing into a
## 32-bit int — so the RANGE failure (-1) fires BEFORE getblockhash's own
## `nHeight < 0 || nHeight > tip` check (-8 "Block height out of range"). An
## out-of-int32 height is therefore -1, not -8, even though it is also out of
## range for the chain. That ordering is Core's and is pinned below.
##
## References:
##   bitcoin-core/src/rpc/blockchain.cpp  getblockhash
##   bitcoin-core/src/univalue/include/univalue.h  getInt<Int>
##   bitcoin-core/src/rpc/protocol.h  RPC_MISC_ERROR = -1,
##                                    RPC_INVALID_PARAMETER = -8

import std/[unittest, json]
import ../src/rpc/server

proc minimalRpcServer(): RpcServer =
  ## Bare RpcServer (nil chainstate). Sufficient because the height-domain
  ## guard runs BEFORE any chainstate access — which is exactly the property
  ## under test: a nonsense height must never reach a lookup.
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error raised)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  captured

suite "getblockhash — height domain (Core parity)":

  test "a float height is -1, not a fabricated genesis hash":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash", %*[1.5]))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "2^63 (overflows int64, parsed as JString) is -1":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash",
        parseJson("[9223372036854775808]")))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "2^64 is -1":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash",
        parseJson("[18446744073709551616]")))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "2^31 (int32 max + 1) is -1, NOT -8 — Core's range check fires first":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash", %*[2147483648'i64]))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "2^32 is -1":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash", %*[4294967296'i64]))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "a genuine string argument is a type error, still -1":
    let r = captureRpcError(
      minimalRpcServer().handleMethod("getblockhash", %*["notaheight"]))
    check r.code == -1
    check r.msg == "JSON value is not an integer as expected"

  ## WHERE THE ACCEPT-SIDE CONTROL LIVES, and why it is not here.
  ##
  ## Every assertion above is a REJECTION, and a suite of only rejections is
  ## satisfied by a handler that rejects every height — which would break
  ## getblockhash entirely. The control that rules that out has to actually
  ## reach the chain lookup, and this rig deliberately uses a nil-chainstate
  ## server so the domain guard can be tested in isolation; an in-range height
  ## therefore reaches `getBlockHashByHeight` and segfaults on the nil state.
  ## That is a property of the RIG, not of the node.
  ##
  ## The accept-side control is covered twice elsewhere, both verified for this
  ## fix:
  ##   - tools/rpc-arg-parity.py --suite getblockhash carries explicit
  ##     "CONTROL height 0 (genesis)" and "CONTROL height 1" rows compared
  ##     against the live Core oracle.
  ##   - Direct regtest run of this build:
  ##       getblockhash 0      -> 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb43...
  ##                              (regtest genesis, error:null)
  ##       getblockhash -1     -> -8 "Block height out of range"
  ##       getblockhash 999999 -> -8 "Block height out of range"
  ##     confirming an in-int32 height passes the domain guard and is judged by
  ##     the CHAIN check (-8), not the domain guard (-1).
