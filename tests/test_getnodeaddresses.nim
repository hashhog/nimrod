## Regression test for the `getnodeaddresses` RPC.
##
## Core reference: bitcoin-core/src/rpc/net.cpp:911-970 (getnodeaddresses)
##                 + src/netbase.cpp:100-128 (ParseNetwork / GetNetworkName).
##
## Contract this suite locks in (byte-faithful to Core):
##   * Result is a JSON ARRAY of objects, each with EXACTLY 5 keys in THIS
##     SERIALIZED order: time, services, address, port, network.
##   * `time`     -> integer (unix seconds), NOT a string.
##   * `services` -> raw services bitfield as a bare INTEGER (e.g. 1033),
##                   NOT a hex string and NOT quoted.
##   * `port`     -> integer.
##   * `network`  -> ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable|internal.
##   * count (positional 0, default 1) = max returned; 0 = ALL; <0 -> error
##     -8 with message EXACTLY 'Address count out of range'.
##   * network (positional 1) lowercased; only ipv4|ipv6|onion|i2p|cjdns are
##     accepted; anything else -> error -8 'Network not recognized: <raw arg>'
##     (raw case preserved verbatim).
##   * Empty addrman (or nil peerManager) -> [] (NOT an error).
##
## The SERIALIZED key order is asserted against the actual emitted JSON bytes
## (toUgly), never an order-insensitive key lookup — Nim's std/json is
## OrderedTable-backed so the insertion order in the handler is the wire order.

import std/[unittest, json, strutils]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc rpcWithPeerManager(): RpcServer =
  ## Bare-bones RpcServer carrying a real PeerManager (regtest params).
  ## Sufficient for getnodeaddresses, whose only dependency is rpc.peerManager.
  let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false,
    peerManager: pm
  )

proc rpcNoPeerManager(): RpcServer =
  ## RpcServer with peerManager == nil — models a fresh node with no addrman.
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false
  )

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  ## Run `body`, catch any RpcError, return its code+msg. No exception -> code 0.
  var captured = (code: 0, msg: "(no error)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  captured

const
  # 1033 = NODE_NETWORK (1) | NODE_WITNESS (8) | NODE_NETWORK_LIMITED (1024).
  # Chosen to prove `services` renders as a bare integer, not a hex string.
  TestServices: uint64 = 1033
  TestTime: uint32 = 1_700_000_000'u32
  TestPort: uint16 = 18333

proc injectV4(rpc: RpcServer, ip: string, port: uint16 = TestPort) =
  ## Insert a routable IPv4 address into the addrman so the dump is non-empty.
  let ok = rpc.peerManager.injectKnownAddress(ip, port, TestServices, TestTime)
  doAssert ok, "injectKnownAddress should accept routable IPv4 " & ip

# ===========================================================================
# Shape + serialized key order
# ===========================================================================
suite "getnodeaddresses: shape and serialized key order":
  test "single ipv4 entry: 5 keys in EXACT serialized order time,services,address,port,network":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")

    let res = rpc.handleMethod("getnodeaddresses", %*[])
    check res.kind == JArray
    check res.len == 1

    let row = res[0]
    check row.kind == JObject
    # Exactly 5 keys, no extras (e.g. no Core "mapped_as").
    check row.len == 5
    check row.hasKey("time")
    check row.hasKey("services")
    check row.hasKey("address")
    check row.hasKey("port")
    check row.hasKey("network")

    # SERIALIZED byte order — assert against the actual emitted JSON, not a
    # key lookup. toUgly gives the compact wire form.
    var wire = ""
    toUgly(wire, res)
    let iTime    = wire.find("\"time\":")
    let iSvc     = wire.find("\"services\":")
    let iAddr    = wire.find("\"address\":")
    let iPort    = wire.find("\"port\":")
    let iNetwork = wire.find("\"network\":")
    check iTime >= 0
    check iSvc >= 0
    check iAddr >= 0
    check iPort >= 0
    check iNetwork >= 0
    check iTime < iSvc
    check iSvc < iAddr
    check iAddr < iPort
    check iPort < iNetwork

    # Literal wire shape (services as bare int 1033, not "0x409"/quoted).
    check wire == "[{\"time\":" & $TestTime &
      ",\"services\":1033,\"address\":\"1.2.3.4\",\"port\":18333," &
      "\"network\":\"ipv4\"}]"

  test "types: time integer, services bare integer (not hex string), port integer":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("8.8.8.8")
    let row = rpc.handleMethod("getnodeaddresses", %*[])[0]

    check row["time"].kind == JInt
    check row["services"].kind == JInt        # NOT JString, NOT a hex literal
    check row["port"].kind == JInt
    check row["address"].kind == JString
    check row["network"].kind == JString

    check row["time"].getBiggestInt() == int64(TestTime)
    check row["services"].getBiggestInt() == 1033
    check row["port"].getInt() == int(TestPort)
    check row["address"].getStr() == "8.8.8.8"
    check row["network"].getStr() == "ipv4"

# ===========================================================================
# count behavior
# ===========================================================================
suite "getnodeaddresses: count behavior":
  test "default (no args) caps to 1":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    rpc.injectV4("5.6.7.8")
    rpc.injectV4("9.10.11.12")
    let res = rpc.handleMethod("getnodeaddresses", %*[])
    check res.kind == JArray
    check res.len == 1

  test "count == 1 caps to 1":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    rpc.injectV4("5.6.7.8")
    rpc.injectV4("9.10.11.12")
    let res = rpc.handleMethod("getnodeaddresses", %*[1])
    check res.len == 1

  test "count == 0 returns ALL":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    rpc.injectV4("5.6.7.8")
    rpc.injectV4("9.10.11.12")
    let res = rpc.handleMethod("getnodeaddresses", %*[0])
    check res.kind == JArray
    check res.len == 3

  test "count larger than pool returns all available":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    rpc.injectV4("5.6.7.8")
    let res = rpc.handleMethod("getnodeaddresses", %*[100])
    check res.len == 2

# ===========================================================================
# network filter (lowercasing + acceptance)
# ===========================================================================
suite "getnodeaddresses: network filter":
  test "network='ipv4' returns the ipv4 entry":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    let res = rpc.handleMethod("getnodeaddresses", %*[0, "ipv4"])
    check res.len == 1
    check res[0]["network"].getStr() == "ipv4"

  test "network='IPV4' (uppercase) is accepted (lowercased)":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    let res = rpc.handleMethod("getnodeaddresses", %*[0, "IPV4"])
    check res.len == 1
    check res[0]["network"].getStr() == "ipv4"

  test "network='ipv6' with only ipv4 entries returns empty array":
    let rpc = rpcWithPeerManager()
    rpc.injectV4("1.2.3.4")
    let res = rpc.handleMethod("getnodeaddresses", %*[0, "ipv6"])
    check res.kind == JArray
    check res.len == 0

# ===========================================================================
# Empty addrman -> [] (not an error)
# ===========================================================================
suite "getnodeaddresses: empty addrman":
  test "nil peerManager returns []":
    let rpc = rpcNoPeerManager()
    let res = rpc.handleMethod("getnodeaddresses", %*[])
    check res.kind == JArray
    check res.len == 0

  test "empty addrman (count==0) returns []":
    let rpc = rpcWithPeerManager()
    let res = rpc.handleMethod("getnodeaddresses", %*[0])
    check res.kind == JArray
    check res.len == 0

# ===========================================================================
# Error paths (-8 with EXACT messages)
# ===========================================================================
suite "getnodeaddresses: error paths":
  test "count < 0 -> -8 'Address count out of range'":
    let rpc = rpcWithPeerManager()
    let e = captureRpcError(rpc.handleMethod("getnodeaddresses", %*[-1]))
    check e.code == RpcInvalidParameter   # -8
    check e.code == -8
    check e.msg == "Address count out of range"

  test "network='bogus' -> -8 'Network not recognized: bogus' (raw case kept)":
    let rpc = rpcWithPeerManager()
    let e = captureRpcError(rpc.handleMethod("getnodeaddresses", %*[0, "bogus"]))
    check e.code == -8
    check e.msg == "Network not recognized: bogus"

  test "network='IPv9' -> raw arg preserved verbatim in the message":
    let rpc = rpcWithPeerManager()
    let e = captureRpcError(rpc.handleMethod("getnodeaddresses", %*[0, "IPv9"]))
    check e.code == -8
    check e.msg == "Network not recognized: IPv9"
