## cffix-nimrod-evict-halfopen-inbound
## (fingerprint nimrod:peermanager:halfopen-inbound-not-eviction-candidates)
##
## inboundCount counts every inbound socket that holds a slot, including
## half-open ones still in the version handshake (psConnected/psHandshaking),
## but tryEvictInbound used to draw its candidates only from extendedPeers,
## which handleInboundConnection fills in AFTER the handshake. With the slots
## full of half-open sockets, every new raw TCP connect therefore evicted an
## established, handshaked inbound peer, so an attacker could churn honest
## inbound peers off the node without ever sending a VERSION.
##
## Core CConnman::AttemptToEvictConnection (net.cpp:1689) builds its candidate
## list from every node in m_nodes that is not fDisconnect, handshake or not;
## a pre-VERSION node has no ping, no block/tx time, no wanted services and
## relays no txs, so it earns none of SelectNodeToEvict's protections.

import unittest2
import std/[os, options, sets, tables, times]
import ../src/network/peer
import ../src/network/messages
import ../src/network/peermanager {.all.}
import ../src/network/netgroup
import ../src/consensus/params

var scratchDirs: seq[string]

proc freshDataDir(tag: string): string =
  result = getTempDir() / ("nimrod-test-evict-halfopen-" & tag & "-" & $getCurrentProcessId())
  removeDir(result)
  createDir(result)
  scratchDirs.add result

proc addHandshaked(pm: PeerManager, address: string, ping: int,
                   txAgoSec, blockAgoSec: int, connectedAgoSec: int): string =
  ## An honest inbound peer that finished the handshake and has been useful.
  let peer = newPeer(address, 8333, pm.params, pdInbound)
  peer.state = psReady
  peer.services = NodeNetwork or NodeWitness
  peer.connectedAt = getTime() - initDuration(seconds = connectedAgoSec)
  let key = address & ":8333"
  pm.peers[key] = peer
  let ip = parseIpAddr(address)
  pm.extendedPeers[key] = ExtendedPeer(
    peer: peer,
    connType: pctInbound,
    connectedTime: peer.connectedAt,
    lastBlockTime: getTime() - initDuration(seconds = blockAgoSec),
    lastTxTime: getTime() - initDuration(seconds = txAgoSec),
    minPingTime: initDuration(milliseconds = ping),
    netGroup: getNetGroupAsn(pm.netGroupManager, ip),
    keyedNetGroup: getKeyedNetGroup(ip, pm.netgroupKey),
    noBan: false)
  key

proc addHalfOpen(pm: PeerManager, address: string, state: PeerState): string =
  ## A raw TCP connect that never sent VERSION: it holds a slot in pm.peers
  ## (handleInboundConnection sets psConnected before performHandshake) but has
  ## no ExtendedPeer yet.
  let peer = newPeer(address, 8333, pm.params, pdInbound)
  peer.state = state
  peer.connectedAt = getTime()
  let key = address & ":8333"
  pm.peers[key] = peer
  key

suite "cffix: half-open inbound sockets are eviction candidates (Core AttemptToEvictConnection)":
  teardown:
    for d in scratchDirs: removeDir(d)
    scratchDirs.setLen(0)

  test "full slots of 4 handshaked + 4 half-open: the evicted peer is a half-open one":
    let pm = newPeerManager(mainnetParams(), maxIn = 4,
                            dataDir = freshDataDir("mixed"))
    var honest, halfOpen: HashSet[string]
    # Honest peers in four distinct /16s; two win the ping protection, two
    # the recent-tx protection, all four have sent blocks.
    honest.incl pm.addHandshaked("8.8.8.8", 10, 3600, 30, 7200)
    honest.incl pm.addHandshaked("9.9.9.9", 12, 3600, 40, 7100)
    honest.incl pm.addHandshaked("1.1.1.1", 300, 5, 50, 7000)
    honest.incl pm.addHandshaked("4.4.4.4", 310, 6, 60, 6900)
    # The attacker: four raw connects from one /16, never handshaked.
    halfOpen.incl pm.addHalfOpen("203.0.113.1", psConnected)
    halfOpen.incl pm.addHalfOpen("203.0.113.2", psHandshaking)
    halfOpen.incl pm.addHalfOpen("203.0.113.3", psConnected)
    halfOpen.incl pm.addHalfOpen("203.0.113.4", psHandshaking)

    # Slots are full: this is the branch handleInboundConnection takes.
    check pm.inboundCount >= pm.maxInbound
    let evicted = pm.tryEvictInbound()
    check evicted.isSome
    if evicted.isSome:
      check evicted.get() in halfOpen
      check evicted.get() notin honest

  test "slots full of half-open sockets only: one of them is evictable":
    let pm = newPeerManager(mainnetParams(), maxIn = 4,
                            dataDir = freshDataDir("allhalf"))
    var halfOpen: HashSet[string]
    halfOpen.incl pm.addHalfOpen("203.0.113.1", psConnected)
    halfOpen.incl pm.addHalfOpen("203.0.113.2", psConnected)
    halfOpen.incl pm.addHalfOpen("198.51.100.1", psHandshaking)
    halfOpen.incl pm.addHalfOpen("198.51.100.2", psHandshaking)
    check pm.inboundCount >= pm.maxInbound
    let evicted = pm.tryEvictInbound()
    check evicted.isSome
    if evicted.isSome:
      check evicted.get() in halfOpen

  test "a disconnected inbound peer is never selected (Core skips fDisconnect)":
    let pm = newPeerManager(mainnetParams(), maxIn = 2,
                            dataDir = freshDataDir("disc"))
    let gone = pm.addHalfOpen("203.0.113.9", psDisconnected)
    let live = pm.addHalfOpen("198.51.100.9", psConnected)
    let evicted = pm.tryEvictInbound()
    check evicted.isSome
    if evicted.isSome:
      check evicted.get() == live
      check evicted.get() != gone
