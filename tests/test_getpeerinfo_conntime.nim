## getpeerinfo `conntime` must be the time the connection was established
## (Core CNode::m_connected), fixed at connect and not advanced by traffic.
## Non-consensus RPC shape only.

import unittest2
import std/[json, times, os, tables]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/network/peer
import ../src/storage/chainstate
import ../src/consensus/params

proc rpcWith(p: Peer): RpcServer =
  let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
  pm.peers["127.0.0.1:18333"] = p
  RpcServer(peerManager: pm, chainState: ChainState(bestHeight: 1'i32))

suite "getpeerinfo conntime":
  test "conntime is the connect time, stable across calls and traffic":
    let connected = getTime().toUnix() - 3600   # connected an hour ago
    let p = newPeer("127.0.0.1", 18333'u16, regtestParams(), pdOutbound)
    p.state = psReady
    p.connectedAt = fromUnix(connected)
    p.lastSeen = getTime()                      # traffic just now
    let rpc = rpcWith(p)
    let a = rpc.handleMethod("getpeerinfo", %*[])[0]["conntime"].getInt()
    sleep(2000)
    p.lastSeen = getTime()                      # more traffic
    let b = rpc.handleMethod("getpeerinfo", %*[])[0]["conntime"].getInt()
    check a == connected
    check b == connected
