## W125 follow-up — node-management RPC error-code parity (FIX, not tombstone).
##
## Ports the verified rustoshi RPC error-code parity fixes into nimrod:
##   getblockhash  out-of-range height  -> RPC_INVALID_PARAMETER          (-8)
##   addnode "add" already-added node   -> RPC_CLIENT_NODE_ALREADY_ADDED  (-23)
##   addnode "remove" un-added node     -> RPC_CLIENT_NODE_NOT_ADDED      (-24)
##   disconnectnode not-connected peer  -> RPC_CLIENT_NODE_NOT_CONNECTED  (-29)
##   setban invalid IP/subnet string    -> RPC_CLIENT_INVALID_IP_OR_SUBNET(-30)
##
## Each asserts the numeric code AND Bitcoin Core's exact message, driven
## through the live `handleMethod` RPC dispatch layer. Where the handler
## requires a non-nil PeerManager to reach the fixed branch (addnode / setban /
## disconnectnode), a real regtest PeerManager is constructed (datadir /tmp),
## mirroring tests/test_getnodeaddresses.nim.
##
## References:
##   bitcoin-core/src/rpc/protocol.h     enum RPCErrorCode (-8/-23/-24/-29/-30)
##   bitcoin-core/src/rpc/blockchain.cpp getblockhash    (-8)
##   bitcoin-core/src/rpc/net.cpp        addnode / setban / disconnectnode
##   rustoshi ee86d76 / 7b94ef1 / 980a31d / 845f7e4

import unittest2
import std/[os, json]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

const TestDbPath = "/tmp/nimrod_w125_nodemgmt_test"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc rpcWithChainState(cs: ChainState): RpcServer =
  ## RpcServer over a real (regtest) ChainState — needed for getblockhash,
  ## which dereferences chainState before raising its range error.
  let params = regtestParams()
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)

proc rpcWithPeerManager(): RpcServer =
  ## RpcServer carrying a real regtest PeerManager (empty added-node list,
  ## no connected peers). Datadir /tmp like test_getnodeaddresses.nim.
  let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false,
    peerManager: pm
  )

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "internal error: " & e.msg)
  captured

proc rpcMethodErr(rpc: RpcServer, methodName: string,
                  params: JsonNode = newJArray()): tuple[code: int, msg: string] =
  captureRpcError(rpc.handleMethod(methodName, params))

# ===========================================================================
# Constants present
# ===========================================================================
suite "W125-fix: node-management error-code constants present":
  test "the four ported constants equal Core protocol.h values":
    check RpcClientNodeAlreadyAdded == -23
    check RpcClientNodeNotAdded == -24
    check RpcClientNodeNotConnected == -29
    check RpcClientInvalidIpOrSubnet == -30

# ===========================================================================
# Fix 1 — getblockhash out-of-range -> -8 "Block height out of range"
# (rustoshi ee86d76; Core rpc/blockchain.cpp:590-591)
# ===========================================================================
suite "W125-fix: getblockhash height out of range -> -8":
  test "negative height -> -8 with Core message":
    cleanupTest()
    defer: cleanupTest()
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcMethodErr("getblockhash", %*[-1])
    check r.code == -8
    check r.msg == "Block height out of range"

  test "above-tip height -> -8 with Core message":
    cleanupTest()
    defer: cleanupTest()
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcMethodErr("getblockhash", %*[99999999])
    check r.code == -8
    check r.msg == "Block height out of range"

# ===========================================================================
# Fix 2 — addnode add-dup / remove-unknown -> -23 / -24
# (rustoshi 7b94ef1; Core rpc/net.cpp:359-369)
# ===========================================================================
suite "W125-fix: addnode add-dup -> -23, remove-unknown -> -24":
  test "remove of a never-added node -> -24 with Core message":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("addnode", %*["127.0.0.1:18444", "remove"])
    check r.code == -24
    check r.msg == "Error: Node could not be removed. It has not been added previously."

  test "second add of the same node -> -23 with Core message":
    let rpc = rpcWithPeerManager()
    # First add succeeds (records on the list, spawns a connect attempt).
    let r1 = rpc.rpcMethodErr("addnode", %*["127.0.0.1:18444", "add"])
    check r1.code == 0
    # Second add of the identical node string is the error.
    let r2 = rpc.rpcMethodErr("addnode", %*["127.0.0.1:18444", "add"])
    check r2.code == -23
    check r2.msg == "Error: Node already added"

  test "add then remove round-trips (remove of an added node succeeds)":
    let rpc = rpcWithPeerManager()
    check rpc.rpcMethodErr("addnode", %*["10.0.0.5:18444", "add"]).code == 0
    check rpc.rpcMethodErr("addnode", %*["10.0.0.5:18444", "remove"]).code == 0
    # And a second remove now fails -24 (the entry is gone).
    let r = rpc.rpcMethodErr("addnode", %*["10.0.0.5:18444", "remove"])
    check r.code == -24

# ===========================================================================
# Fix 3 — setban invalid IP/subnet -> -30 "Error: Invalid IP/Subnet"
# (rustoshi 980a31d; Core rpc/net.cpp:779-781)
# ===========================================================================
suite "W125-fix: setban invalid IP/subnet -> -30":
  test "non-IP garbage -> -30 with Core message":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("setban", %*["not-an-ip", "add"])
    check r.code == -30
    check r.msg == "Error: Invalid IP/Subnet"

  test "malformed dotted-quad (octet > 255) -> -30":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("setban", %*["999.1.1.1", "add"])
    check r.code == -30

  test "invalid subnet prefix length -> -30":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("setban", %*["192.168.0.0/40", "add"])
    check r.code == -30

  test "well-formed IPv4 does NOT hit -30 (success path preserved)":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("setban", %*["192.168.0.6", "add", 1])
    check r.code != -30
    check r.code == 0

  test "well-formed CIDR subnet does NOT hit -30 (success path preserved)":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("setban", %*["192.168.0.0/24", "add", 1])
    check r.code != -30
    check r.code == 0

# ===========================================================================
# Fix 4 — disconnectnode not-connected -> -29 "Node not found in connected nodes"
# (rustoshi 845f7e4; Core rpc/net.cpp:477-479)
# ===========================================================================
suite "W125-fix: disconnectnode not-connected -> -29":
  test "unknown address -> -29 with Core message":
    let rpc = rpcWithPeerManager()
    let r = rpc.rpcMethodErr("disconnectnode", %*["203.0.113.7:18444"])
    check r.code == -29
    check r.msg == "Node not found in connected nodes"
