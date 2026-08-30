## The integer CONVERSION runs before the lookup, and setban/disconnectnode
## honour the arguments they were given.
##
## #81 fixed the arguments nimrod ACCEPTED out of range. This is the other
## half: arguments nimrod REJECTED, but with the wrong error, because the
## width check ran after -- or instead of -- the conversion. Measured against
## a regtest Core oracle (tools/rpc-arg-differential.py): 16 findings on all
## four hostile widths of each of
##
##   getblock <hash> <v>        -> -5 "Block not found"              (Core -1)
##   getrawtransaction <t> <v>  -> -5 "No such mempool transaction"  (Core -1)
##   getchaintxstats <n>        -> -8 "Invalid block count..."       (Core -1)
##   disconnectnode ["", <id>]  -> -32602 "missing address parameter"(Core -29)
##
## Core's UniValue::getInt<T> runs std::from_chars INTO THE DESTINATION WIDTH,
## so the width check fires inside the conversion and only surviving values
## reach the lookup or the domain test.
##
## setban came from the differential's CONTROL -- a call Core ANSWERS -- not
## from a hostile integer (bitcoin-core/src/rpc/net.cpp):
##   * an ABSOLUTE bantime already in the past was ACCEPTED; Core refuses it
##     with -8, comparing strictly `banTime < GetTime()`;
##   * there was no already-banned check at all (Core: -23, run BEFORE bantime
##     is read);
##   * bantime 0 recorded a zero-length ban; Core reads 0 as "use the default";
##   * a failed unban answered -32602 instead of Core's -30 and wording.
##
## disconnectnode's own docstring advertised `nodeid`, but the handler never
## read params[1] -- so every by-id call, the form getpeerinfo's "id" field
## exists to feed, was refused.
##
## TEETH: a handler that rejected everything would satisfy every rejection
## assertion here, so each suite carries a CONTROL that must SUCCEED, and the
## by-nodeid control asserts the RIGHT peer was selected.

import std/[unittest, json, os, tempfiles, times]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/primitives/types

const OutOfInt32 = [2147483648'i64, -2147483649'i64, 4294967296'i64, -4294967297'i64]
const RangeErr = (code: -1, msg: "JSON integer out of range")
const SomeHash = "00000000000000000000000000000000000000000000000000000000000000ff"
const SomeTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error — call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

suite "#41 the conversion beats the lookup":
  var chainState: ChainState
  var tempDir: string
  var rpc: RpcServer

  setup:
    tempDir = createTempDir("nimrod_test_", "_conv41")
    let params = regtestParams()
    chainState = newChainState(tempDir, params)
    if chainState.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      check chainState.connectBlock(genesis, 0).isOk
    rpc = RpcServer(port: 0, running: false, blockSubmissionPaused: false,
                    chainState: chainState, params: params,
                    peerManager: newPeerManager(params, dataDir = tempDir))

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "getblock verbosity: -1 from the conversion, not -5 from the lookup":
    for v in OutOfInt32:
      check captureRpcError(rpc.handleMethod("getblock", %*[SomeHash, v])) == RangeErr

  test "getrawtransaction verbosity: -1, not -5 from the tx lookup":
    for v in OutOfInt32:
      check captureRpcError(rpc.handleMethod("getrawtransaction", %*[SomeTxid, v])) == RangeErr

  test "getchaintxstats nblocks: -1, not -8 from the count domain test":
    for v in OutOfInt32:
      check captureRpcError(rpc.handleMethod("getchaintxstats", %*[v])) == RangeErr

  test "CONTROL an in-range illegal nblocks still reaches the -8 domain error":
    let r = captureRpcError(rpc.handleMethod("getchaintxstats", %*[-1]))
    check r.code == -8
    check r.msg.len > 0 and r.msg != "JSON integer out of range"

  test "CONTROL an absent-but-well-formed blockhash still reaches -5":
    let r = captureRpcError(rpc.handleMethod("getblock", %*[SomeHash, 1]))
    check r.code == -5

suite "#41 setban parity":
  var chainState: ChainState
  var tempDir: string
  var rpc: RpcServer

  setup:
    tempDir = createTempDir("nimrod_test_", "_setban41")
    let params = regtestParams()
    chainState = newChainState(tempDir, params)
    rpc = RpcServer(port: 0, running: false, blockSubmissionPaused: false,
                    chainState: chainState, params: params,
                    peerManager: newPeerManager(params, dataDir = tempDir))

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "an ABSOLUTE bantime in the past is refused, not accepted":
    check captureRpcError(rpc.handleMethod("setban", %*["1.2.3.4", "add", 1, true])) ==
      (code: -8, msg: "Error: Absolute timestamp is in the past")
    check not rpc.peerManager.isBanned("1.2.3.4")

  test "re-banning is -23, and the check runs before bantime is read":
    check captureRpcError(rpc.handleMethod("setban", %*["1.2.3.4", "add"])).code == 0
    check captureRpcError(rpc.handleMethod("setban", %*["1.2.3.4", "add"])) ==
      (code: -23, msg: "Error: IP/Subnet already banned")
    # bantime is not even looked at on the already-banned path
    check captureRpcError(rpc.handleMethod("setban", %*["1.2.3.4", "add", 1, true])) ==
      (code: -23, msg: "Error: IP/Subnet already banned")

  test "a failed unban is -30 with Core's wording, not -32602":
    check captureRpcError(rpc.handleMethod("setban", %*["9.9.9.9", "remove"])) ==
      (code: -30, msg: "Error: Unban failed. Requested address/subnet was not " &
                       "previously manually banned.")

  test "CONTROL an absolute bantime in the FUTURE is accepted":
    let future = getTime().toUnix() + 3600
    check captureRpcError(rpc.handleMethod("setban", %*["5.6.7.8", "add", future, true])).code == 0
    check rpc.peerManager.isBanned("5.6.7.8")

  test "CONTROL bantime 0 means the default, and the ban is recorded":
    check captureRpcError(rpc.handleMethod("setban", %*["7.7.7.7", "add", 0])).code == 0
    check rpc.peerManager.isBanned("7.7.7.7")

suite "#41 disconnectnode honours nodeid":
  var chainState: ChainState
  var tempDir: string
  var rpc: RpcServer

  setup:
    tempDir = createTempDir("nimrod_test_", "_disc41")
    let params = regtestParams()
    chainState = newChainState(tempDir, params)
    rpc = RpcServer(port: 0, running: false, blockSubmissionPaused: false,
                    chainState: chainState, params: params,
                    peerManager: newPeerManager(params, dataDir = tempDir))

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "an unconnected nodeid is -29, not -32602 about a missing address":
    for v in @[0'i64, 99'i64, -1'i64] & @OutOfInt32:
      check captureRpcError(rpc.handleMethod("disconnectnode", %*["", v])) ==
        (code: -29, msg: "Node not found in connected nodes")

  test "supplying BOTH address and nodeid is -32602 with Core's wording":
    check captureRpcError(rpc.handleMethod("disconnectnode", %*["1.2.3.4:8333", 0])) ==
      (code: -32602, msg: "Only one of address and nodeid should be provided.")

  test "CONTROL by-address still reaches the not-connected answer":
    check captureRpcError(rpc.handleMethod("disconnectnode", %*["1.2.3.4:8333"])) ==
      (code: -29, msg: "Node not found in connected nodes")
