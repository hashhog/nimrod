## Regression test for the `getpeerinfo` RPC field set + wire order.
##
## Core reference: bitcoin-core/src/rpc/net.cpp (getpeerinfo).
##   * relaytxes (242) -> last_inv_sequence (243) -> inv_to_send (244)
##     -> lastsend (245): the two NUM fields are emitted CONTIGUOUSLY between
##     relaytxes and lastsend.
##   * bip152_hb_from (269) -> presynced_headers (270): Core v31.99 NO LONGER
##     emits `startingheight` (m_starting_height was removed from RPC output).
##
## nimrod's std/json is OrderedTable-backed, so the insertion order in the
## handler IS the serialized wire order — these checks assert against the
## actual emitted JSON bytes from the real handleGetPeerInfo handler, not an
## order-insensitive key lookup.
##
## This is RPC response shape only — non-consensus, never reachable from
## block/tx/script validation.

import std/[unittest, json, strutils, times, sequtils, tables]
import ../src/rpc/server
import ../src/network/peermanager
import ../src/network/peer
import ../src/storage/chainstate
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc rpcWithReadyPeer(): RpcServer =
  ## RpcServer carrying a real PeerManager with one psReady peer + a bare
  ## ChainState (only bestHeight is read by handleGetPeerInfo).
  let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
  let p = Peer(
    address: "127.0.0.1",
    port: 18333'u16,
    state: psReady,
    direction: pdOutbound,
    services: 0x0409'u64,           # NETWORK | WITNESS | NETWORK_LIMITED
    relay: true,
    lastSeen: fromUnix(1_700_000_000),
    latencyMs: 50,
    version: 70016'u32,
    userAgent: "/nimrod:test/",
    bytesSent: 1000'u64,
    bytesRecv: 2000'u64,
    timeOffset: 0'i64,
    feeFilterRate: 1000'u64,
    startHeight: 123456'i32
  )
  pm.peers["127.0.0.1:18333"] = p
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false,
    peerManager: pm,
    chainState: ChainState(bestHeight: 100100'i32)
  )

# ===========================================================================

suite "getpeerinfo: Core v31.99 field set + wire order":

  test "single peer entry is a JSON object":
    let rpc = rpcWithReadyPeer()
    let res = rpc.handleMethod("getpeerinfo", %*[])
    check res.kind == JArray
    check res.len == 1
    check res[0].kind == JObject

  test "last_inv_sequence + inv_to_send present (NUM) and contiguous after relaytxes, before lastsend":
    let rpc = rpcWithReadyPeer()
    let row = rpc.handleMethod("getpeerinfo", %*[])[0]

    check row.hasKey("last_inv_sequence")
    check row.hasKey("inv_to_send")
    check row["last_inv_sequence"].kind == JInt
    check row["inv_to_send"].kind == JInt

    # Serialized wire order: relaytxes -> last_inv_sequence -> inv_to_send -> lastsend.
    let keys = toSeq(row.keys)
    let iRelay = keys.find("relaytxes")
    let iLastInv = keys.find("last_inv_sequence")
    let iInvToSend = keys.find("inv_to_send")
    let iLastsend = keys.find("lastsend")
    check iRelay >= 0
    check iLastsend >= 0
    check iLastInv == iRelay + 1
    check iInvToSend == iRelay + 2
    check iLastsend == iRelay + 3

  test "startingheight is NOT emitted (removed in Core v31.99); bip152_hb_from -> presynced_headers":
    let rpc = rpcWithReadyPeer()
    let res = rpc.handleMethod("getpeerinfo", %*[])
    let row = res[0]

    check not row.hasKey("startingheight")
    # And the raw serialized bytes must not contain the key either.
    check "startingheight" notin ($res)

    let keys = toSeq(row.keys)
    let iHbFrom = keys.find("bip152_hb_from")
    let iPresync = keys.find("presynced_headers")
    check iHbFrom >= 0
    check iPresync == iHbFrom + 1
