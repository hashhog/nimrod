## Security audit C2 (2026-10-31): a non-continuous headers batch bypassed the
## anti-DoS work gate and stored unbounded fork headers.
##
## classifyHeaderBatch routes a batch whose LAST header is already known as
## hbrDirect (minPowChecked=true) — Core's "those headers cost no memory"
## shortcut (net_processing.cpp:3043-3052).  That shortcut is only sound when
## the batch is continuous: then every header before the known last one is one
## of its ancestors, so it is known too.  nimrod never checked continuity, so
## an attacker sent a fresh low-work fork off genesis followed by OUR block-1
## header; the batch went direct and every fork header landed in sideHeaders
## (and a RocksDB row).  Audit repro: 499,850 headers on one connection,
## RSS 28 MB -> 802 MB, zero misbehaviour.
##
## Core runs CheckHeadersPoW (net_processing.cpp:2617-2631) — PoW of every
## header against powLimit, then CheckHeadersAreContinuous (:2671-2681) —
## BEFORE any routing, and Misbehaves on failure.
##
## Regtest params, chain at height 300: the anti-DoS threshold is tip work
## minus 144 blocks, so a 100-header fork off genesis is low work and must not
## be stored (the control test proves the gate bites, so the attack test is
## measuring the shortcut and not a gate that never fires).

import unittest2
import chronos
import std/[tables]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc buildHeaderChain(startHash: BlockHash, startTime: uint32,
                      count: int): seq[BlockHeader] =
  result = @[]
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    var hdr = BlockHeader(version: 1, prevBlock: prev,
                          merkleRoot: default(array[32, byte]),
                          timestamp: ts, bits: 0x207fffff'u32, nonce: 0)
    while not validateHeaderPoW(hdr):
      hdr.nonce += 1
    result.add(hdr)
    prev = hashOf(hdr)

proc syncManagerAtGenesis(params: ConsensusParams): SyncManager =
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  result = SyncManager(
    state: ssIdle,
    headerChain: initHeaderChain(genesis.header, genesisHash),
    params: params,
    headerTip: genesisHash,
    headerTipHeight: 0,
    chainTipNoState: genesisHash,
    chainTipHeightNoState: 0,
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

proc extendActiveChain(sm: SyncManager, headers: seq[BlockHeader]) =
  for h in headers:
    let hash = hashOf(h)
    let idx = sm.headerChain.headers.len
    sm.headerChain.headers.add(h)
    sm.headerChain.hashes.add(hash)
    sm.headerChain.byHash[hash] = idx
    sm.headerChain.totalWork = addWork(sm.headerChain.totalWork,
                                       calculateWork(h.bits))
    sm.headerChain.tip = hash
    sm.headerChain.tipHeight = int32(idx)
    sm.headerTip = hash
    sm.headerTipHeight = int32(idx)
  # Blocks are connected too: the anti-DoS threshold is measured from here.
  sm.chainTip = sm.headerChain.tip
  sm.chainTipHeight = sm.headerChain.tipHeight

type Fixture = object
  params: ConsensusParams
  pm: PeerManager
  peer: Peer
  sm: SyncManager
  chainA: seq[BlockHeader]
  genesisTime: uint32

proc setup300(ip: string): Fixture =
  result.params = regtestParams()
  result.pm = newPeerManager(result.params, 8, 2, 117, "/tmp")
  result.peer = newPeer(ip, 8333, result.params, pdInbound)
  result.peer.services = NodeNetwork or NodeWitness
  result.pm.peers[ip & ":8333"] = result.peer
  result.sm = syncManagerAtGenesis(result.params)
  result.sm.peerManager = result.pm
  result.genesisTime = buildGenesisBlock(result.params).header.timestamp
  result.chainA = buildHeaderChain(result.params.genesisBlockHash,
                                   result.genesisTime, 300)
  result.sm.extendActiveChain(result.chainA)

suite "C2: non-continuous headers batch is rejected before routing":

  test "control: 100-header low-work fork off genesis is not stored":
    var f = setup300("203.0.113.61")
    check f.sm.headerChain.tipHeight == 300
    let fork = buildHeaderChain(f.params.genesisBlockHash, f.genesisTime + 1, 100)
    check f.sm.classifyHeaderBatch(fork).routing == hbrAntiDoS
    waitFor f.sm.handleHeaders(f.peer, fork)
    check f.sm.headerChain.sideHeaders.len == 0
    check f.sm.headerChain.tipHeight == 300

  test "attack: low-work fork + our block-1 header is rejected with misbehaviour":
    var f = setup300("203.0.113.62")
    var batch = buildHeaderChain(f.params.genesisBlockHash, f.genesisTime + 1, 100)
    batch.add(f.chainA[0])            # our own block-1 header, already known
    waitFor f.sm.handleHeaders(f.peer, batch)
    check f.sm.headerChain.sideHeaders.len == 0
    check f.pm.isBanned(f.peer.address)
    check f.sm.headerChain.tipHeight == 300

  test "a gap inside an otherwise valid tip extension is rejected":
    var f = setup300("203.0.113.63")
    let ext = buildHeaderChain(hashOf(f.chainA[^1]), f.chainA[^1].timestamp, 3)
    let batch = @[ext[0], ext[2]]     # ext[1] missing
    waitFor f.sm.handleHeaders(f.peer, batch)
    check f.pm.isBanned(f.peer.address)
    check f.sm.headerChain.tipHeight == 300
    check f.sm.headerChain.sideHeaders.len == 0

  test "a PoW-invalid header ahead of a known last header is rejected":
    var f = setup300("203.0.113.64")
    var bad = BlockHeader(version: 1, prevBlock: f.params.genesisBlockHash,
                          merkleRoot: default(array[32, byte]),
                          timestamp: f.genesisTime + 7, bits: 0x03000001'u32,
                          nonce: 0)
    check not validateHeaderPoW(bad)
    waitFor f.sm.handleHeaders(f.peer, @[bad, f.chainA[0]])
    check f.pm.isBanned(f.peer.address)
    check f.sm.headerChain.sideHeaders.len == 0

  test "a header whose target exceeds powLimit is rejected":
    ## Core CheckProofOfWork: target > powLimit fails even if hash <= target.
    var f = setup300("203.0.113.65")
    var easy = BlockHeader(version: 1, prevBlock: hashOf(f.chainA[^1]),
                           merkleRoot: default(array[32, byte]),
                           timestamp: f.chainA[^1].timestamp + 600,
                           bits: 0x2100ffff'u32, nonce: 0)
    while not validateHeaderPoW(easy):
      easy.nonce += 1
    waitFor f.sm.handleHeaders(f.peer, @[easy])
    check f.pm.isBanned(f.peer.address)
    check f.sm.headerChain.tipHeight == 300

suite "C2: honest batches still pass the continuity gate":

  test "re-sent known headers (continuous) cost no misbehaviour":
    var f = setup300("203.0.113.71")
    waitFor f.sm.handleHeaders(f.peer, f.chainA[100 .. 199])
    check f.peer.misbehaviorScore == 0
    check not f.pm.isBanned("203.0.113.71")
    check f.sm.headerChain.tipHeight == 300

  test "overlapping batch: known headers then new tip extension is accepted":
    var f = setup300("203.0.113.72")
    let ext = buildHeaderChain(hashOf(f.chainA[^1]), f.chainA[^1].timestamp, 5)
    waitFor f.sm.handleHeaders(f.peer, f.chainA[290 .. 299] & ext)
    check f.peer.misbehaviorScore == 0
    check f.sm.headerChain.tipHeight == 305
    check f.sm.headerChain.tip == hashOf(ext[^1])

  test "honest continuous fork off a below-tip ancestor is still stored":
    ## The reorg-drop arm: a fork near the tip (work above the anti-DoS
    ## threshold) is accepted into sideHeaders without penalty.
    var f = setup300("203.0.113.73")
    let forkPoint = f.chainA[289]     # height 290
    let fork = buildHeaderChain(hashOf(forkPoint), forkPoint.timestamp + 1, 12)
    waitFor f.sm.handleHeaders(f.peer, fork)
    check f.peer.misbehaviorScore == 0
    check not f.pm.isBanned("203.0.113.73")
    check f.sm.headerChain.sideHeaders.len == 12
    check f.sm.headerChain.tipHeight == 300

  test "single-header announcement is trivially continuous":
    var f = setup300("203.0.113.74")
    let ext = buildHeaderChain(hashOf(f.chainA[^1]), f.chainA[^1].timestamp, 1)
    waitFor f.sm.handleHeaders(f.peer, ext)
    check f.peer.misbehaviorScore == 0
    check f.sm.headerChain.tipHeight == 301
