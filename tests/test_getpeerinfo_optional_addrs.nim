## getpeerinfo optional address fields must follow Core (rpc/net.cpp):
##   * addrlocal  - present only when the peer's reported view of us is a valid
##                  address ("ip:port", "[v6]:port"); absent for 0.0.0.0/::.
##   * mapped_as  - present only when non-zero (an asmap is loaded and mapped
##                  the peer). nimrod emitted `mapped_as: 0` on every entry.
##   * addrbind   - present when the connection has a bound local address
##                  (covered end to end by the Core-regtest operator group,
##                  operator/peer/shape:[0].addrbind; needs a real socket).
## Found by operator/peer/shape:[0].{addrlocal,addrbind,mapped_as}.
##   nim c -r tests/test_getpeerinfo_optional_addrs.nim

import unittest2
import std/[json, times, tables, sequtils]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/network/peer
import ../src/storage/chainstate
import ../src/consensus/params

proc v4(a, b, c, d: byte): array[16, byte] =
  result[10] = 0xFF
  result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc rpcWith(p: Peer): RpcServer =
  let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
  pm.peers["127.0.0.1:18333"] = p
  RpcServer(peerManager: pm, chainState: ChainState(bestHeight: 1'i32))

proc readyPeer(): Peer =
  result = newPeer("127.0.0.1", 18333'u16, regtestParams(), pdInbound)
  result.state = psReady
  result.lastSeen = getTime()

suite "getpeerinfo optional address fields":
  test "mapped_as is absent when there is no AS mapping":
    let row = rpcWith(readyPeer()).handleMethod("getpeerinfo", %*[])[0]
    check not row.hasKey("mapped_as")

  test "addrlocal is the peer's view of us, absent when unspecified":
    let p = readyPeer()
    let unset = rpcWith(p).handleMethod("getpeerinfo", %*[])[0]
    check not unset.hasKey("addrlocal")
    p.addrLocal.ip = v4(0, 0, 0, 0)
    p.addrLocal.port = 0
    check not rpcWith(p).handleMethod("getpeerinfo", %*[])[0].hasKey("addrlocal")
    p.addrLocal.ip = v4(203, 0, 113, 7)
    p.addrLocal.port = 8333
    let row = rpcWith(p).handleMethod("getpeerinfo", %*[])[0]
    check row.hasKey("addrlocal")
    if row.hasKey("addrlocal"):
      check row["addrlocal"].getStr() == "203.0.113.7:8333"
      let keys = toSeq(row.keys)
      check keys.find("addrlocal") == keys.find("addr") + 1

  test "an IPv6 addrlocal is bracketed":
    let p = readyPeer()
    p.addrLocal.ip[15] = 1            # ::1
    p.addrLocal.port = 18444
    let row = rpcWith(p).handleMethod("getpeerinfo", %*[])[0]
    check row.hasKey("addrlocal")
    if row.hasKey("addrlocal"):
      check row["addrlocal"].getStr() == "[::1]:18444"
