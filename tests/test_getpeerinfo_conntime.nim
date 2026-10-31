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
    let p = newPeer("127.0.0.1", 18333'u16, regtestParams(), pdOutbound)
    p.state = psReady
    p.lastSeen = getTime()                      # traffic
    let rpc = rpcWith(p)
    let a = rpc.handleMethod("getpeerinfo", %*[])[0]
    sleep(2000)
    p.lastSeen = getTime()                      # more traffic, 2s later
    let later = p.lastSeen.toUnix()
    let b = rpc.handleMethod("getpeerinfo", %*[])[0]
    check a["conntime"].getInt() == b["conntime"].getInt()
    check b["lastsend"].getInt() == later
    check b["lastsend"].getInt() > a["lastsend"].getInt()
