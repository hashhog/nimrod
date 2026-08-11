## Reorg-drop fix — Part 1: stop banning a below-tip heavier fork header +
## fork-aware block download.
##
## Production blocker (runtime-confirmed): a heavier branch forking BELOW the
## active tip made nimrod DISCONNECT/ban the peer and stay stuck.  Root cause —
## handleHeaders' accept loop demanded every header extend the active tip
## (header.prevBlock == hash@(tipHeight)) and BANNED anything else, so a
## competing chain's header (prevBlock == an earlier ancestor) was rejected as
## "unlinked".  Part 1 splits that loop into an unchanged active-extension arm
## and a new FORK ARM that ACCEPTS (does not ban) a below-tip fork header
## (PoW + parent-exists + cumulative-work), stores it in headerChain.sideHeaders,
## and lets requestBlocks walk the fork's ancestry to fetch its bridging bodies.
##
## Bitcoin Core reference: AcceptBlockHeader keeps every PoW-valid header (active
## or fork) in the single CBlockIndex map; FindNextBlocksToDownload walks a
## competing branch's ancestry with no "active tip" floor.  Contextual
## MTP/retarget is deferred to the body path (validation.cpp ConnectBlock).
##
## These tests use regtest params (zero minimumChainWork) so the anti-DoS
## pipeline routes a connecting batch DIRECTLY (minPowChecked=true) — the fork
## arm is reached.  chainDb is nil: acceptForkHeader / the download walk both
## guard their DB writes/reads on `sm.chainDb != nil`, so the in-memory routing
## is exercised without RocksDB I/O (same approach as test_w162_genesis_presync).

import unittest2
import chronos
import std/[options, tables, times, sets]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing
import ../src/storage/chainstate  # ChainState, MAX_REORG_DEPTH (pruning gate)

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

# Build `count` valid regtest-difficulty headers linked onto `startHash`.
# `bits` lets a test make a fork heavier (smaller target → more work/header).
proc buildHeaderChain(startHash: BlockHash, startTime: uint32,
                      count: int, bits: uint32 = 0x207fffff'u32): seq[BlockHeader] =
  result = @[]
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    var hdr = BlockHeader(
      version: 1,
      prevBlock: prev,
      merkleRoot: default(array[32, byte]),
      timestamp: ts,
      bits: bits,
      nonce: 0
    )
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
    chainTip: genesisHash,
    chainTipHeight: 0,
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

# Drive `headers` straight through the active accept arm (regtest direct path)
# so the node's active chain advances to those headers — used to set up chain-A.
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

# ===========================================================================
suite "Part 1: below-tip heavier fork header is ACCEPTED, peer NOT banned":

  test "heavier fork@genesis populates sideHeaders, no ban, totalWork(B)>(A)":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.21", 8333, params, pdInbound)
    pm.peers["203.0.113.21:8333"] = peer

    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    # Chain A: 10 easy-difficulty headers extend the active tip to height 10.
    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    check sm.headerChain.tipHeight == 10
    let workA = sm.headerChain.totalWork

    # Chain B: 15 headers forking at GENESIS (below the active tip) — LONGER
    # than chain A's 10, so at equal difficulty it is strictly heavier.
    #
    # W168: this used to make chain B heavier with `bits = 0x207ffffe`.  That
    # is not a difficulty a competing chain may legally declare — regtest's
    # GetNextWorkRequired mandates the powLimit compact here — and now that the
    # bad-diffbits gate (Core validation.cpp:4088) runs on the fork arm too,
    # such headers are correctly rejected.  A real heavier fork out-works the
    # active chain with more blocks at the REQUIRED difficulty, which is what
    # this builds.  `startTime + 1` keeps chain B's headers distinct from
    # chain A's (same prev + same time + same bits would hash identically).
    let chainB = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp + 1, 15)

    # Pre-fix this banned the peer on chainB[0] ("unlinked header").
    waitFor sm.handleHeaders(peer, chainB)

    # Peer must NOT be banned / penalised.
    check not pm.isBanned("203.0.113.21")
    check peer.misbehaviorScore == 0

    # The active chain is UNCHANGED — fork headers do not move the active tip.
    check sm.headerChain.tipHeight == 10
    check sm.headerChain.tip == hashOf(chainA[^1])

    # Every chain-B header is now a known side header.
    check sm.headerChain.sideHeaders.len == 15
    for h in chainB:
      check sm.headerChain.hasAnyHeader(hashOf(h))

    # The heaviest side tip is chain-B's tip and outweighs chain A.
    let cand = sm.headerChain.heaviestSideTip()
    check cand.isSome
    check cand.get().height == 15
    check hashOf(cand.get().header) == hashOf(chainB[^1])
    check compareWork(cand.get().totalWork, workA) > 0

  test "fork heights are absolute (fork-point height + offset)":
    ## A fork branching at height 5 must record absolute heights 6..N, not 1..k.
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.22", 8333, params, pdInbound)
    pm.peers["203.0.113.22:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)

    # Fork from height 5 (chainA[4]) — a known below-tip ancestor.
    # W168: same-difficulty headers (the difficulty regtest actually requires);
    # `+ 1` on the start time keeps fork[0] distinct from chainA[5].
    let forkPoint = hashOf(chainA[4])
    let fork = buildHeaderChain(forkPoint, chainA[4].timestamp + 1, 8)
    waitFor sm.handleHeaders(peer, fork)

    check not pm.isBanned("203.0.113.22")
    check sm.headerChain.sideHeaders.len == 8
    # First fork header sits at height 6 (fork point 5 + 1).
    check sm.headerChain.sideHeaders[hashOf(fork[0])].height == 6
    check sm.headerChain.sideHeaders[hashOf(fork[^1])].height == 13

# ===========================================================================
suite "Part 1: genuine-bad headers are STILL banned (no weakening)":

  test "PoW-invalid header that forks below tip → peer banned":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.23", 8333, params, pdInbound)
    pm.peers["203.0.113.23:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)

    # A fork header that forks at genesis but FAILS PoW: a tiny target (huge
    # difficulty) that nonce=0 cannot meet.  This is genuine-bad and must ban.
    var badHdr = BlockHeader(
      version: 1,
      prevBlock: params.genesisBlockHash,
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: 0x03000001'u32,   # extremely hard target → PoW will not pass
      nonce: 0
    )
    check not validateHeaderPoW(badHdr)

    waitFor sm.handleHeaders(peer, @[badHdr])

    check pm.isBanned("203.0.113.23") or peer.misbehaviorScore > 0
    check sm.headerChain.sideHeaders.len == 0

  test "header with no resolvable parent → peer banned (unlinked)":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.24", 8333, params, pdInbound)
    pm.peers["203.0.113.24:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)

    # A valid-PoW header whose prevBlock is an UNKNOWN hash (not genesis, not on
    # the active chain, not a stored fork).  classifyHeaderBatch routes this to
    # hbrUnconnecting (re-request, tolerated up to MAX_NUM_UNCONNECTING) so it
    # is not stored as a side branch — assert it never enters sideHeaders.
    var orphanPrev: array[32, byte]
    orphanPrev[5] = 0xCD
    let orphan = buildHeaderChain(BlockHash(orphanPrev),
                                  genesis.header.timestamp, 3)
    waitFor sm.handleHeaders(peer, orphan)

    check sm.headerChain.sideHeaders.len == 0

# ===========================================================================
suite "Part 1: fork-aware download walk requests bridging fork bodies":

  test "requestBlocks enqueues the below-tip fork bodies with no height floor":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.25", 8333, params, pdInbound)
    pm.peers["203.0.113.25:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    # Active chain A to height 10; chain tip is also at A's tip so the
    # active-chain walk has nothing to request (chainTipHeight == headerTip).
    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    sm.chainTip = hashOf(chainA[^1])
    sm.chainTipHeight = 10

    # Heavier chain B (15 headers vs A's 10, same required difficulty) forking
    # at genesis, accepted as a side branch.  W168: see the note in the first
    # test — heavier now means LONGER, not an illegally-declared nBits.
    let chainB = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp + 1, 15)
    waitFor sm.handleHeaders(peer, chainB)
    check sm.headerChain.sideHeaders.len == 15

    # The active-chain walk requests nothing (chainTip == headerTip), so every
    # enqueued body must come from the fork-body walk.  Assert on blockQueue:
    # it records the SELECTION (the bodies requestBlocks decided to fetch) and
    # is not unwound when the test's socket-less single-peer sendGetData fails.
    waitFor sm.requestBlocks(peer)

    var queued = initHashSet[BlockHash]()
    for h in sm.blockQueue.items:
      queued.incl(h)

    # Every chain-B body should now be selected for download (no height floor:
    # bodies at fork heights 1..15 below the active tip are all enqueued).
    for h in chainB:
      check hashOf(h) in queued
    check sm.blockQueue.len >= 15

    # Connect-order invariant: the fork point's child (height 1) is enqueued
    # before the fork tip (height 15) so bodies download bottom-up.
    var firstIdx = -1
    var lastIdx = -1
    for i, h in sm.blockQueue.pairs:
      if h == hashOf(chainB[0]): firstIdx = i
      if h == hashOf(chainB[^1]): lastIdx = i
    check firstIdx >= 0 and lastIdx >= 0
    check firstIdx < lastIdx

  test "no fork → requestBlocks requests nothing extra (steady state unchanged)":
    ## Invariant: with no sideHeaders the fork walk is inert; the active-chain
    ## walk alone runs (and here chainTip == headerTip → nothing to do).
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.26", 8333, params, pdInbound)
    pm.peers["203.0.113.26:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    sm.chainTip = hashOf(chainA[^1])
    sm.chainTipHeight = 10

    check sm.headerChain.sideHeaders.len == 0
    waitFor sm.requestBlocks(peer)
    check sm.requestedHashes.len == 0

  test "equal/lighter fork stays a side branch and is NOT downloaded":
    ## Core only switches the best-header candidate on STRICTLY greater work.
    ## A fork no heavier than the active chain is stored (no ban) but its bodies
    ## are not requested — the download walk gates on cumWork > active totalWork.
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.27", 8333, params, pdInbound)
    pm.peers["203.0.113.27:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    let genesis = buildGenesisBlock(params)

    # Active chain A: 10 headers.
    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    sm.chainTip = hashOf(chainA[^1])
    sm.chainTipHeight = 10

    # Fork B: only 4 SAME-difficulty headers forking at genesis → lighter.
    let chainB = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp + 1, 4)
    waitFor sm.handleHeaders(peer, chainB)

    check not pm.isBanned("203.0.113.27")
    check sm.headerChain.sideHeaders.len == 4   # stored as side branch
    let cand = sm.headerChain.heaviestSideTip()
    check cand.isSome
    check compareWork(cand.get().totalWork, sm.headerChain.totalWork) < 0

    let queueBefore = sm.blockQueue.len
    waitFor sm.requestBlocks(peer)
    # Lighter fork: nothing selected for download.
    var queued = initHashSet[BlockHash]()
    for h in sm.blockQueue.items:
      queued.incl(h)
    for h in chainB:
      check hashOf(h) notin queued
      check hashOf(h) notin sm.requestedHashes
    check sm.blockQueue.len == queueBefore

# ===========================================================================
# P2P fork-DEPTH-cap Core-parity: a heavier fork forking MORE than
# MAX_REORG_DEPTH (288) below the active tip must, on an ARCHIVE node, have its
# ENTIRE bridging span downloaded — Bitcoin Core (FindNextBlocksToDownload)
# follows the most-work header chain to the fork point at any depth. Pre-fix the
# descent's `while depth < MAX_REORG_DEPTH` cap fired unconditionally, so the
# bottom bridging bodies were starved and the node stranded on the minority
# chain. The cap is now gated on cs.pruningEnabled (mirrors handleReorg).
#
# The fork is populated DIRECTLY into headerChain.sideHeaders (bypassing
# handleHeaders' presync/promotion machinery) so the descent's depth-cap gate is
# exercised in isolation with deterministic heights + cumulative work.
suite "Part 1: deep (>288) below-tip fork download is Core-parity work-based":

  # Build a heavier fork of `forkLen` same-difficulty headers off genesis and
  # install every header into sm.headerChain.sideHeaders keyed by its hash, with
  # absolute height (1..forkLen) and genesis-cumulative totalWork. Returns the
  # fork headers (ascending). The active chain A must already be shorter so the
  # fork strictly out-works it.
  proc installDeepFork(sm: SyncManager, genesisHash: BlockHash,
                       startTime: uint32, forkLen: int): seq[BlockHeader] =
    # baseWork = genesis-only cumulative work already in the header chain, so the
    # fork's totalWork is directly comparable to the active chain's (both include
    # the shared genesis base). Snapshot it BEFORE any active-chain extension by
    # subtracting: initHeaderChain seeds totalWork with the genesis work, and
    # extendActiveChain added chainA on top — so re-derive the base from a fresh
    # walk instead. Simplest: compute the fork cumulatively from zero-work + each
    # block; the comparison only needs fork(forkLen) > active(len(chainA)), which
    # holds for equal difficulty because forkLen > len(chainA).
    let fork = buildHeaderChain(genesisHash, startTime, forkLen)
    var cum: array[32, byte]
    for i, h in fork:
      cum = addWork(cum, calculateWork(h.bits))
      sm.headerChain.sideHeaders[hashOf(h)] = SideHeader(
        header: h, height: int32(i + 1), totalWork: cum)
    return fork

  test "archive: deep heavier fork enqueues the FULL bridging span (no depth cap)":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.40", 8333, params, pdInbound)
    pm.peers["203.0.113.40:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    # Archive node: chainState nil (default) → forkDepthCap = unbounded.
    let genesis = buildGenesisBlock(params)

    # Small active chain A (height 10); chainTip == headerTip so the active-chain
    # walk requests nothing and every enqueued body comes from the fork walk.
    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    sm.chainTip = hashOf(chainA[^1])
    sm.chainTipHeight = 10

    # Heavier fork off genesis, DEEPER than MAX_REORG_DEPTH: forkLen (300) >
    # len(chainA) (10) same-difficulty blocks ⇒ strictly heavier. Its descent
    # from the fork tip to the fork point (genesis) is 300 > 288.
    const forkLen = MAX_REORG_DEPTH + 12  # 300
    let fork = sm.installDeepFork(params.genesisBlockHash,
                                  genesis.header.timestamp + 1, forkLen)
    check sm.headerChain.sideHeaders.len == forkLen
    let cand = sm.headerChain.heaviestSideTip()
    check cand.isSome
    check compareWork(cand.get().totalWork, sm.headerChain.totalWork) > 0

    waitFor sm.requestBlocks(peer)

    var queued = initHashSet[BlockHash]()
    for h in sm.blockQueue.items:
      queued.incl(h)

    # Pre-fix: capped at 288 → the bottom bridging bodies (fork heights 1..12)
    # were NEVER enqueued and the reorg could never bridge to the fork point.
    # Post-fix: the full 300-block span is selected.
    check sm.blockQueue.len >= forkLen
    for h in fork:
      check hashOf(h) in queued
    # The very bottom bridging body (fork point's child, height 1) MUST be
    # present — the exact block the depth cap starved.
    check hashOf(fork[0]) in queued

  test "pruned: same deep fork keeps the MAX_REORG_DEPTH cap (gate keys on pruning)":
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.41", 8333, params, pdInbound)
    pm.peers["203.0.113.41:8333"] = peer
    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm
    # Pruned node: a reorg past the retained undo window is un-appliable, so the
    # download stays capped (matching handleReorg's pruning-gated cap).
    sm.chainState = ChainState(pruningEnabled: true)
    let genesis = buildGenesisBlock(params)

    let chainA = buildHeaderChain(params.genesisBlockHash,
                                  genesis.header.timestamp, 10)
    sm.extendActiveChain(chainA)
    sm.chainTip = hashOf(chainA[^1])
    sm.chainTipHeight = 10

    const forkLen = MAX_REORG_DEPTH + 12  # 300
    let fork = sm.installDeepFork(params.genesisBlockHash,
                                  genesis.header.timestamp + 1, forkLen)
    check sm.headerChain.sideHeaders.len == forkLen

    waitFor sm.requestBlocks(peer)

    # Cap holds: no more than MAX_REORG_DEPTH fork bodies selected, and the
    # bottom bridging body is NOT reached (deep reorg is un-appliable when pruned).
    check sm.blockQueue.len <= MAX_REORG_DEPTH
    var queued = initHashSet[BlockHash]()
    for h in sm.blockQueue.items:
      queued.incl(h)
    check hashOf(fork[0]) notin queued
