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
import std/[tables, strutils]
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

# checkHeadersBatchPoW is the helper this fix adds.  Guarding the suite that
# calls it directly lets this file compile on a base without the fix, so the
# behaviour suites above fail there by assertion instead of the whole file
# failing to compile.
when declared(checkHeadersBatchPoW):
  proc hdrFromHex(s: string): BlockHeader =
    var b = newSeq[byte](s.len div 2)
    for i in 0 ..< b.len:
      b[i] = byte(fromHex[uint8](s[2*i .. 2*i+1]))
    deserializeBlockHeader(b)

  proc displayHash(h: BlockHeader): string =
    let a = array[32, byte](hashOf(h))
    for i in countdown(31, 0):
      result.add(toHex(a[i], 2).toLowerAscii)

  suite "C2: what a valid header could now be refused for":
    ## The new gate is Core's CheckHeadersPoW: CheckProofOfWork (the same
    ## pow.checkProofOfWork the block path runs at validation.nim:1269) plus
    ## continuity.  A valid chain is continuous and every block's target is
    ## <= powLimit, so the boundary to pin is a header sitting exactly AT
    ## powLimit (mainnet blocks 1-2, nBits 0x1d00ffff == powLimit compact).

    test "real mainnet genesis + blocks 1-2 pass the batch gate":
      let p = mainnetParams()
      let g = buildGenesisBlock(p).header
      let b1 = hdrFromHex("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")
      let b2 = hdrFromHex("010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61")
      check displayHash(b1) == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
      check displayHash(b2) == "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
      check checkHeadersBatchPoW(@[g, b1, b2], p) == ""
      check checkHeadersBatchPoW(@[b1, b2], p) == ""
      # Same valid headers out of order are refused, as Core refuses them.
      check checkHeadersBatchPoW(@[b2, b1], p) == "non-continuous headers sequence"
      # Mainnet powLimit is not regtest's: a regtest-difficulty header fails.
      let rt = buildHeaderChain(BlockHash(default(array[32, byte])), 0, 1)
      check checkHeadersBatchPoW(rt, p) == "header with invalid proof of work"

    test "every network's real genesis header passes its own gate":
      for p in [mainnetParams(), testnet3Params(), testnet4Params(),
                signetParams(), regtestParams()]:
        var g = buildGenesisBlock(p).header
        if p.network == Testnet4:
          # buildGenesisBlock uses the 2009 coinbase for every network; testnet4's
          # genesis has its own, so put in its real merkle root
          # (7aa0a7ae...2b7b4e, chainparams.cpp CreateGenesisBlock for testnet4).
          let mr = "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
          for i in 0 ..< 32:
            g.merkleRoot[31 - i] = byte(fromHex[uint8](mr[2*i .. 2*i+1]))
        check hashOf(g) == p.genesisBlockHash      # it IS the real genesis
        check checkHeadersBatchPoW(@[g], p) == ""
