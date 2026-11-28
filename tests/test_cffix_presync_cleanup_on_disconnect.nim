## A peer's PRESYNC/REDOWNLOAD header-sync state and its unconnecting-headers
## counter must be freed when the peer is removed.
##
## Bitcoin Core frees per-peer header-sync state when the node is finalized:
## PeerManagerImpl::FinalizeNode (net_processing.cpp) erases the Peer, and with
## it m_headers_sync and m_num_unconnecting_headers_msgs, and drops the node's
## entry from m_headers_presync_stats (releasing m_headers_presync_bestpeer if
## it held it).
##
## Before this fix nimrod freed SyncManager.peerHeadersSync /
## headersPresyncStats only on an empty `headers` reply or on the sync's own
## success/failure, and unconnectingHeaders only on ban or on a connecting
## batch. PeerManager's removal paths (removePeer, the ban path
## disconnectMatching, the maintainConnections sweep) had no SyncManager hook.
## The keys hash address:port, and inbound peers come from ephemeral ports, so
## every peer that left mid-PRESYNC left its HeadersSyncState (commitment
## deque and redownload buffer included) in memory for the life of the
## process, and presyncBestPeer could keep naming a peer that was gone.
##
## Each test builds a real PRESYNC entry through tryLowWorkHeadersSync (a full
## 2000-header batch from genesis under a non-zero minimumChainWork), removes
## the peer through one PeerManager path, and checks that peer A's entries are
## gone while peer B's are untouched.

import unittest2
import std/[os, tables]
import chronos
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const EASY_BITS = 0x207fffff'u32

proc presyncParams(): ConsensusParams =
  ## Regtest PoW rules with a NON-ZERO minimumChainWork, so a 2000-header
  ## regtest batch (work ~2 per header) stays below the anti-DoS threshold
  ## and tryLowWorkHeadersSync starts a PRESYNC sync.
  result = regtestParams()
  var mcw: array[32, byte]
  mcw[2] = 0x01 # ~2^16
  result.minimumChainWork = mcw

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc headerChainFrom(startHash: BlockHash, startTime: uint32,
                     count: int, salt: byte): seq[BlockHeader] =
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    var root: array[32, byte]
    root[0] = salt
    var hdr = BlockHeader(version: 1, prevBlock: prev, merkleRoot: root,
                          timestamp: ts, bits: EASY_BITS, nonce: 0)
    while not validateHeaderPoW(hdr):
      hdr.nonce += 1
    result.add(hdr)
    prev = hashOf(hdr)

type Fix = object
  path: string
  cs: ChainState
  pm: PeerManager
  sm: SyncManager
  a, b: Peer

proc addPeer(pm: PeerManager, ip: string, p: ConsensusParams): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.state = psReady
  pm.peers[ip & ":8333"] = result

proc startPresync(f: Fix, peer: Peer, count: int, salt: byte) =
  let p = f.sm.params
  let g = buildGenesisBlock(p)
  var hdrs = headerChainFrom(p.genesisBlockHash, g.header.timestamp,
                             count, salt)
  let routed = f.sm.tryLowWorkHeadersSync(peer, 0'i32, p.genesisBlockHash,
      g.header.bits, getBlockProof(g.header), hdrs,
      g.header.timestamp, g.header.timestamp)
  doAssert routed, "fixture: batch did not enter PRESYNC"

proc buildFix(path: string): Fix =
  removeDir(path)
  createDir(path)
  let p = presyncParams()
  var cs = newChainState(path / "chain", p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  createDir(path / "pm")
  let pm = newPeerManager(p, 8, 2, 117, path / "pm")
  pm.networkActive = false # maintainConnections must not dial anything
  let sm = newSyncManager(pm, cs.db, p, cs)
  result = Fix(path: path, cs: cs, pm: pm, sm: sm,
               a: pm.addPeer("198.51.100.71", p),
               b: pm.addPeer("198.51.100.72", p))
  # Equal work: B does not displace A (strictly-greater rule), so A is best.
  result.startPresync(result.a, MaxHeadersPerRequest, 0xA1)
  result.startPresync(result.b, MaxHeadersPerRequest, 0xB2)
  let aid = getPeerId(result.a)
  let bid = getPeerId(result.b)
  sm.unconnectingHeaders[aid] = 3
  sm.unconnectingHeaders[bid] = 4
  doAssert aid in sm.peerHeadersSync and bid in sm.peerHeadersSync
  doAssert aid in sm.headersPresyncStats and bid in sm.headersPresyncStats
  doAssert sm.peerHeadersSync[aid].getState() == Presync

proc close(f: var Fix) =
  f.cs.close()
  removeDir(f.path)

proc checkAGoneBKept(f: Fix) =
  let aid = getPeerId(f.a)
  let bid = getPeerId(f.b)
  check aid notin f.sm.peerHeadersSync
  check aid notin f.sm.headersPresyncStats
  check aid notin f.sm.unconnectingHeaders
  # The other peer's state is untouched.
  check bid in f.sm.peerHeadersSync
  check bid in f.sm.headersPresyncStats
  check f.sm.unconnectingHeaders.getOrDefault(bid, -1) == 4
  # presyncBestPeer must not name a removed peer.
  check f.sm.presyncBestPeer != aid

suite "cffix: per-peer PRESYNC state is freed on disconnect (Core FinalizeNode)":

  test "removePeer frees peerHeadersSync, headersPresyncStats and unconnectingHeaders":
    var f = buildFix("/tmp/nimrod_cffix_presync_rm")
    doAssert f.pm.peers.len == 2
    waitFor f.pm.removePeer(f.a)
    check f.pm.peers.len == 1
    f.checkAGoneBKept()
    f.close()

  test "ban (banPeer -> disconnectMatching) frees the banned peer's sync state":
    var f = buildFix("/tmp/nimrod_cffix_presync_ban")
    f.pm.banPeer(f.a.address)
    check f.pm.peers.len == 1
    f.checkAGoneBKept()
    f.close()

  test "maintainConnections' disconnected-peer sweep frees sync state":
    var f = buildFix("/tmp/nimrod_cffix_presync_sweep")
    f.a.state = psDisconnected
    when declared(peermanager.maintainConnections):
      waitFor f.pm.maintainConnections()
    check f.pm.peers.len == 1
    f.checkAGoneBKept()
    f.close()

  test "presyncBestPeer moves to the remaining peer when the best one leaves":
    var f = buildFix("/tmp/nimrod_cffix_presync_best")
    let bid = getPeerId(f.b)
    check f.sm.presyncBestPeer == getPeerId(f.a)
    waitFor f.pm.removePeer(f.a)
    check f.sm.presyncBestPeer == bid
    check f.sm.presyncBestWork == f.sm.headersPresyncStats[bid].work
    f.close()

  test "removing a peer with no sync state is harmless":
    var f = buildFix("/tmp/nimrod_cffix_presync_nostate")
    let c = f.pm.addPeer("198.51.100.73", f.sm.params)
    waitFor f.pm.removePeer(c)
    check getPeerId(f.a) in f.sm.peerHeadersSync
    check getPeerId(f.b) in f.sm.peerHeadersSync
    check f.sm.unconnectingHeaders.len == 2
    f.close()
