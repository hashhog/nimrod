## Block relay: a block connected via P2P must be announced to peers.
##
## Regtest relay test 2026-09-26: two Bitcoin Core nodes connected ONLY to
## nimrod never converged — nimrod downloaded and connected Core A's blocks but
## never announced them to Core B, because PeerManager.broadcastBlock was only
## called from the mining RPCs. Core relays every new tip from
## PeerManagerImpl::UpdatedBlockTip (net_processing.cpp:2158) unless in IBD.

import unittest2
import std/strutils
import ../src/network/sync

let syncSrc = readFile("src/network/sync.nim")

suite "block relay: announce the connected tip":
  test "shouldAnnounceTip follows Core DEFAULT_MAX_TIP_AGE (24h)":
    let now = 1_800_000_000'i64
    check shouldAnnounceTip(uint32(now), now)
    check shouldAnnounceTip(uint32(now - 24 * 3600), now)       # boundary
    check not shouldAnnounceTip(uint32(now - 24 * 3600 - 1), now)
    check shouldAnnounceTip(uint32(now + 600), now)             # future ts

  test "both P2P connect paths (applyBlock, processReceivedBlocks) announce":
    check syncSrc.count("sm.announceConnectedTip(blk)") == 2
    let ap = syncSrc.find("proc applyBlock*")
    let prb = syncSrc.find("proc processReceivedBlocks*")
    check ap >= 0 and prb >= 0
    check syncSrc.find("sm.announceConnectedTip(blk)", ap) < prb
    check syncSrc.find("sm.announceConnectedTip(blk)", prb) > prb

  test "announceConnectedTip forwards to broadcastBlock":
    let i = syncSrc.find("proc announceConnectedTip(")
    check i >= 0
    check syncSrc.find("sm.peerManager.broadcastBlock(blk)", i) > i

suite "getheaders is served from the connected chain only":
  let nimrodSrc = readFile("src/nimrod.nim")
  test "the mkGetHeaders loop is bounded by the connected tip":
    let i = nimrodSrc.find("of mkGetHeaders:")
    check i >= 0
    let loopAt = nimrodSrc.find("while headers.len < MaxHeadersPerMsg and height <= servedCeiling:", i)
    check loopAt > i
    check nimrodSrc.find("connectedServeCeiling(state.chainState.bestHeight)", i) in i ..< loopAt
  test "connectedServeCeiling is the connected tip":
    check connectedServeCeiling(16) == 16

suite "no announcement of a block whose body is still in the IBD batch":
  test "announceConnectedTip bails in ibdMode; IBD completion announces after stopIBD":
    let i = syncSrc.find("proc announceConnectedTip(")
    check syncSrc.find("if sm.chainState != nil and sm.chainState.ibdMode:", i) > i
    let c = syncSrc.find("# IBD complete - flush remaining batched writes")
    check c >= 0
    let stop = syncSrc.find("sm.chainState.stopIBD()", c)
    check syncSrc.find("sm.announceTipAfterIBDFlush()", c) > stop

