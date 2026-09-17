## Control: header-sync from a dense (non-snapshot) chain at height H must
## request from H and accept the response; a mute sync peer must be
## rotated/disconnected on timeout.
##
## Live (v1.0.2 dac3234, 2026-09-17): stuck at 966301, locatorLen=30,
## `WRN sync timeout, resetting state=ssSyncingHeaders` every 60s,
## re-selecting the same IPv6 peer. Operator addnode of Core at
## 127.0.0.1:8333 (answers headers instantly) did not move the tip —
## selectSyncPeer is getBestPeer() and the timeout path only nil'd
## syncPeer, so the mute high-startHeight peer was picked again.
## 22a60b8 (snapshot-graft rework) was the only sync change since the
## pre-rework pin that held tip; the v1.0.2 gate never exercised
## public-peer header sync from an existing chainstate.
##
## STILL BROKEN after 0675bde (live 2026-09-17T03:04Z, tip 967057):
## rotation works, but every answering peer times out 60s after
## `requested headers locatorLen=30` with zero `processed headers`.
## Rolled back to b89aba8: `processed headers accepted=N` in ~1s on
## the same datadir. 0675bde's fake peer answered whatever locator it
## got and called handleHeaders with a pre-made H+n batch, so it could
## not see 22a60b8 mis-routing a tip-extend as hbrAntiDoS then dropping
## a <2000 batch as "incomplete low-work" (no log).
##
## Bitcoin Core: net_processing.cpp HEADERS_DOWNLOAD_TIMEOUT disconnects
## a stalling headers-sync peer when another preferred peer exists.
## TryLowWorkHeadersSync is for from-genesis / low-work chains, not a
## tip-extend on a node that already has height H>0.
##
## Command:
##   nim c -r tests/test_header_sync_from_tip.nim

import unittest2
import std/[os, tables]
import chronos
import ../src/network/sync
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/headerssync
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mineHeader(prev: BlockHash, ts: uint32): BlockHeader =
  result = BlockHeader(
    version: 1,
    prevBlock: prev,
    merkleRoot: default(array[32, byte]),
    timestamp: ts,
    bits: 0x207fffff'u32,
    nonce: 0
  )
  while not validateHeaderPoW(result):
    result.nonce += 1

proc mineChain(startHash: BlockHash, startTime: uint32,
               count: int): seq[BlockHeader] =
  result = @[]
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    let hdr = mineHeader(prev, ts)
    result.add(hdr)
    prev = hashOf(hdr)

proc readyPeer(address: string, port: uint16, params: ConsensusParams,
               startHeight: int32): Peer =
  result = newPeer(address, port, params, pdOutbound)
  result.state = psReady
  result.handshakeComplete = true
  result.startHeight = startHeight
  result.bestKnownHeight = startHeight

proc peerKeyOf(p: Peer): string =
  p.address & ":" & $p.port

proc peerAnswerHeaders(peerHeaders: seq[BlockHeader], genesisHash: BlockHash,
                       locator: seq[array[32, byte]],
                       expectedTip: BlockHash): seq[BlockHeader] =
  ## Core FindForkInGlobalIndex + Next(). Answers only from the first
  ## locator hash this peer knows. A locator whose head is not the node's
  ## active tip is not a tip-extend — the peer walks for a common ancestor
  ## (typically genesis) and does NOT invent an H+n batch.
  var known = initTable[array[32, byte], int]()
  known[array[32, byte](genesisHash)] = -1
  for i, h in peerHeaders:
    known[array[32, byte](hashOf(h))] = i
  var forkIdx = -2
  var found = false
  for loc in locator:
    if loc in known:
      forkIdx = known[loc]
      found = true
      break
  if not found:
    return @[]
  # Locator head must be the node's active tip or this is not a tip-extend.
  if locator.len == 0 or BlockHash(locator[0]) != expectedTip:
    let start = forkIdx + 1
    if start < 0:
      return peerHeaders[0 ..< min(2000, peerHeaders.len)]
    if start >= peerHeaders.len:
      return @[]
    return peerHeaders[start ..< min(start + 2000, peerHeaders.len)]
  let start = forkIdx + 1
  if start < 0:
    return peerHeaders[0 ..< min(2000, peerHeaders.len)]
  if start >= peerHeaders.len:
    return @[]
  peerHeaders[start ..< min(start + 2000, peerHeaders.len)]

proc buildDenseDb(path: string, params: ConsensusParams,
                  count: int): tuple[cdb: ChainDb, headers: seq[BlockHeader]] =
  removeDir(path)
  let cdb = openChainDb(path)
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  let headers = mineChain(genesisHash, genesis.header.timestamp, count)
  var cumWork = calculateWork(genesis.header.bits)
  var prevHash = genesisHash
  for i, hdr in headers:
    let h = hashOf(hdr)
    cumWork = addWork(cumWork, calculateWork(hdr.bits))
    cdb.putBlockIndex(BlockIndex(
      hash: h,
      height: int32(i + 1),
      status: bsValidated,
      prevHash: prevHash,
      header: hdr,
      totalWork: cumWork,
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0,
      nTx: 1
    ))
    prevHash = h
  cdb.bestHeight = int32(count)
  cdb.bestBlockHash = prevHash
  result = (cdb, headers)

suite "header sync from a dense chain at height H":
  test "locator is the active tip and handleHeaders accepts H+n":
    ## (a) Non-snapshot chainstate at H: getheaders locator must start at
    ## H, and a connecting batch must be accepted. Regression for 22a60b8
    ## (graft path must not break a dense genesis-rooted chain).
    let params = regtestParams()
    let path = "/tmp/nimrod_hdr_sync_from_tip_dense"
    let (cdb, headers) = buildDenseDb(path, params, 12)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let pm = newPeerManager(params, 8, 2, 117, path / "pm")
    let answering = readyPeer("127.0.0.1", 8333, params, 20)
    pm.peers[peerKeyOf(answering)] = answering

    let sm = newSyncManager(pm, cdb, params)
    check sm.headerChain.tipHeight == 12
    check sm.locatorStartHeight() == 12
    let locator = sm.buildBlockLocator()
    check locator.len > 0
    check locator[0] == array[32, byte](hashOf(headers[^1]))
    # Dense exponential locator, not a 2-hash graft (tip+genesis).
    check locator.len >= 10

    let ahead = mineChain(hashOf(headers[^1]), headers[^1].timestamp, 5)
    waitFor sm.handleHeaders(answering, ahead)
    check sm.headerChain.tipHeight == 17
    check sm.headerChain.tip == hashOf(ahead[^1])
    check sm.buildBlockLocator()[0] == array[32, byte](hashOf(ahead[^1]))

  test "mute high-height peer is disconnected on timeout; answering peer is selected":
    ## (b) Live bug: timeout only nil'd syncPeer; getBestPeer() re-picked
    ## the same mute peer. Core disconnects a stalling headers peer when
    ## another preferred peer exists.
    let params = regtestParams()
    let path = "/tmp/nimrod_hdr_sync_from_tip_rotate"
    let (cdb, _) = buildDenseDb(path, params, 8)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let pm = newPeerManager(params, 8, 2, 117, path / "pm")
    let mute = readyPeer("192.0.2.1", 8333, params, 200)
    let answering = readyPeer("127.0.0.1", 8333, params, 150)
    pm.peers[peerKeyOf(mute)] = mute
    pm.peers[peerKeyOf(answering)] = answering

    let sm = newSyncManager(pm, cdb, params)
    sm.syncPeer = mute
    check sm.selectSyncPeer() == mute

    sm.handleHeadersSyncTimeout()

    check mute.shouldDisconnect
    check not answering.shouldDisconnect
    check sm.syncPeer.isNil
    check sm.state == ssIdle
    check sm.selectSyncPeer() == answering

  test "after rotating off a mute peer, answering-peer headers advance H to H+n":
    let params = regtestParams()
    let path = "/tmp/nimrod_hdr_sync_from_tip_combined"
    let (cdb, headers) = buildDenseDb(path, params, 10)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let pm = newPeerManager(params, 8, 2, 117, path / "pm")
    let mute = readyPeer("192.0.2.1", 8333, params, 200)
    let answering = readyPeer("127.0.0.1", 8333, params, 150)
    pm.peers[peerKeyOf(mute)] = mute
    pm.peers[peerKeyOf(answering)] = answering

    let sm = newSyncManager(pm, cdb, params)
    check sm.headerChain.tipHeight == 10
    sm.syncPeer = mute
    check sm.selectSyncPeer() == mute

    sm.handleHeadersSyncTimeout()
    let peer = sm.selectSyncPeer()
    check peer == answering

    let ahead = mineChain(hashOf(headers[^1]), headers[^1].timestamp, 4)
    waitFor sm.handleHeaders(peer, ahead)
    check sm.headerChain.tipHeight == 14
    check sm.headerChain.tip == hashOf(ahead[^1])

  test "sole sync peer is not disconnected (nothing to rotate to)":
    ## Core only disconnects a stalling headers peer when another
    ## preferred download peer exists. With one peer, keep retrying it.
    let params = regtestParams()
    let path = "/tmp/nimrod_hdr_sync_from_tip_sole"
    let (cdb, _) = buildDenseDb(path, params, 4)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let pm = newPeerManager(params, 8, 2, 117, path / "pm")
    let only = readyPeer("192.0.2.1", 8333, params, 50)
    pm.peers[peerKeyOf(only)] = only

    let sm = newSyncManager(pm, cdb, params)
    sm.syncPeer = only
    sm.handleHeadersSyncTimeout()
    check not only.shouldDisconnect
    check sm.selectSyncPeer() == only

  test "fake peer answers only from the common ancestor; locator head must be the active tip":
    ## 22a60b8 used cached headerChain.totalWork at the tip instead of
    ## summing getBlockProof (b89aba8). When that cache is below
    ## nMinimumChainWork — zero, quantised, or a different work formula —
    ## a tip-extending batch of <2000 headers is classified hbrAntiDoS
    ## and tryLowWorkHeadersSync CLEARS it as an incomplete low-work
    ## message. handleHeaders then returns without "processed headers".
    ## Live: 301 headers from Satoshi:31.1.0 at 967057, 60s timeout on
    ## every peer. The previous test fed H+n straight to handleHeaders
    ## on regtest (threshold 0) so it could not fail.
    let params = regtestParams()
    let path = "/tmp/nimrod_hdr_sync_from_tip_locator"
    let (cdb, headers) = buildDenseDb(path, params, 12)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let pm = newPeerManager(params, 8, 2, 117, path / "pm")
    let answering = readyPeer("127.0.0.1", 8333, params, 20)
    pm.peers[peerKeyOf(answering)] = answering

    let sm = newSyncManager(pm, cdb, params)
    let activeTip = hashOf(headers[^1])
    check sm.headerChain.tipHeight == 12
    check cdb.bestBlockHash == activeTip
    check sm.headerChain.tip == activeTip

    let locator = sm.buildBlockLocator()
    check locator.len > 0
    # REAL locator check: head is the ACTIVE chain tip, not a graft row.
    check locator[0] == array[32, byte](activeTip)
    check locator[0] == array[32, byte](cdb.bestBlockHash)

    let ahead = mineChain(activeTip, headers[^1].timestamp, 5)
    var peerChain = headers
    peerChain.add(ahead)

    # Negative: a locator whose head is not the active tip (campaign /
    # graft hash, then genesis) must NOT yield the H+n tip-extend.
    var graftHash: array[32, byte]
    graftHash[0] = 0xCA
    graftHash[1] = 0xFE
    let badLocator = @[graftHash, array[32, byte](params.genesisBlockHash)]
    let badAnswer = peerAnswerHeaders(peerChain, params.genesisBlockHash,
                                      badLocator, activeTip)
    check badAnswer.len > 0
    check badAnswer[0].prevBlock != activeTip

    let answer = peerAnswerHeaders(peerChain, params.genesisBlockHash,
                                   locator, activeTip)
    check answer.len == 5
    check answer[0].prevBlock == activeTip
    check answer[^1] == ahead[^1]

    # Reproduce the 22a60b8 mis-route: cached totalWork does not meet
    # the anti-DoS threshold, but the dense chain's getBlockProof sum
    # does (b89aba8). 5 new headers alone do not.
    let oneProof = getBlockProof(headers[0])
    sm.minimumChainWork = oneProof * 8'u64
    sm.headerChain.totalWork = default(array[32, byte])

    let cls = sm.classifyHeaderBatch(answer)
    check cls.routing == hbrDirect
    check cls.connectHash == activeTip
    check cls.connectHeight == 12

    waitFor sm.handleHeaders(answering, answer)
    check sm.headerChain.tipHeight == 17
    check sm.headerChain.tip == hashOf(ahead[^1])
