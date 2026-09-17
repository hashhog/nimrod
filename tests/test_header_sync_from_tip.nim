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
## Bitcoin Core: net_processing.cpp HEADERS_DOWNLOAD_TIMEOUT disconnects
## a stalling headers-sync peer when another preferred peer exists.
##
## Command:
##   nim c -r tests/test_header_sync_from_tip.nim

import unittest2
import std/[os, tables]
import chronos
import ../src/network/sync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
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
