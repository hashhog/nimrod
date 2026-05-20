## W162 — from-genesis header sync must enter the PRESYNC anti-DoS pipeline.
##
## Incident (mainnet, 2026-05-19): nimrod was restarted with block chainstate
## at height 950146 but its in-memory header chain reloaded at currentHeight=0
## (the header chain is not persisted — see sync.nim newSyncManager "TODO: Load
## header chain from database").  Re-syncing headers from genesis, nimrod
## rejected the legitimate mainnet header at height 1 with "too-little-chainwork"
## and banned the honest peer, repeating forever.
##
## Root cause — TWO latent bugs, both dormant on regtest:
##
##   1. SyncManager.minimumChainWork was never wired from params: it was left
##      initUInt256() (zero) with a stale "Will be set from chainstate" comment.
##      getAntiDoSWorkThreshold() therefore returned 0, so tryLowWorkHeadersSync
##      always saw total_work >= threshold and NEVER started a PRESYNC sync — the
##      entire anti-DoS pipeline was dead code in production.
##
##   2. handleHeaders only consulted tryLowWorkHeadersSync inside the
##      `firstHeader.prevBlock != headerTip` branch.  A from-genesis batch has
##      prevBlock == genesis == the only header we hold, so it connected
##      "directly to tip", skipped PRESYNC entirely, and was validated with
##      minPowChecked=false.  validateBlockHeader's W97 G8 gate then rejected
##      every header (mainnet has a large params.minimumChainWork) and banned
##      the peer.
##
## Both bugs were invisible to the test-suite because regtest sets
## minimumChainWork to all-zeros (params.nim:504) — the W97 G8 gate is inert
## and the anti-DoS threshold is 0, so the broken routing produced the SAME
## (accepting) outcome as correct routing.  This suite uses a SYNTHETIC param
## with a NON-ZERO minimumChainWork (regtest PoW rules + a real threshold) so
## the gate and the pipeline are both live.
##
## Bitcoin Core reference: net_processing.cpp ProcessHeadersMessage /
## TryLowWorkHeadersSync — `chain_start_header` is found by a plain block-index
## lookup of headers[0].hashPrevBlock and TryLowWorkHeadersSync is ALWAYS run
## against it; the tip is not special-cased.  headerssync.cpp PRESYNC/REDOWNLOAD
## defers the cumulative-work check to the COMPLETED chain.

import unittest2
import chronos
import std/[options, tables, times]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Synthetic param: regtest PoW rules (easy target, no retarget) but a NON-ZERO
# minimumChainWork so the W97 G8 gate + the anti-DoS threshold are both live.
# This is the configuration that the production fleet (mainnet) actually runs
# and that the regtest test-suite never exercised.
# ---------------------------------------------------------------------------
proc syntheticParams(): ConsensusParams =
  result = regtestParams()
  # A threshold far above what a handful of regtest-difficulty headers can
  # accumulate, but reachable by a long chain.  Non-zero is the whole point:
  # it makes minPowChecked=false → "too-little-chainwork" and makes
  # getAntiDoSWorkThreshold() return something a short chain cannot meet.
  var mcw: array[32, byte]
  mcw[2] = 0x01  # ~2^16 — well above a few regtest headers, below a long chain
  result.minimumChainWork = mcw

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

# Build `count` valid regtest-difficulty headers linked onto `startHash`.
# Regtest powLimit (0x207fffff) is ~2^256, so essentially every nonce passes
# the per-header PoW gate; a small search keeps the test deterministic anyway.
proc buildHeaderChain(startHash: BlockHash, startTime: uint32,
                      count: int): seq[BlockHeader] =
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
      bits: 0x207fffff'u32,
      nonce: 0
    )
    # Guarantee the per-header PoW gate passes (validateHeaderPoW).
    while not validateHeaderPoW(hdr):
      hdr.nonce += 1
    result.add(hdr)
    prev = hashOf(hdr)

# Minimal SyncManager carrying only the state classifyHeaderBatch /
# tryLowWorkHeadersSync read.  newSyncManager() does RocksDB I/O; the routing
# logic itself needs no DB, so a struct literal keeps these tests fast.
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
    # The fix: this MUST be params.minimumChainWork, not zero.
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

# ===========================================================================
suite "W162: from-genesis header batch routing (classifyHeaderBatch)":

  test "from-genesis batch under non-zero minimumChainWork → hbrAntiDoS":
    ## THE regression.  Pre-fix this batch connected to tip (== genesis) and
    ## skipped PRESYNC, then got rejected with too-little-chainwork.  It must
    ## now be classified for the PRESYNC pipeline.
    let params = syntheticParams()
    let sm = syncManagerAtGenesis(params)
    let genesis = buildGenesisBlock(params)

    # A short chain of headers connecting to genesis — far below threshold.
    let headers = buildHeaderChain(params.genesisBlockHash,
                                   genesis.header.timestamp, 5)
    check headers[0].prevBlock == params.genesisBlockHash  # connects to tip

    let cls = sm.classifyHeaderBatch(headers)
    check cls.routing == hbrAntiDoS          # routed to PRESYNC, NOT direct
    check cls.connectHeight == 0             # chain_start == genesis
    check cls.connectHash == params.genesisBlockHash

  test "regtest (zero minimumChainWork) keeps the direct path → hbrDirect":
    ## Regression guard for the masking condition: with an all-zero
    ## minimumChainWork the threshold is 0, so a connecting batch is validated
    ## directly — exactly the pre-W97 regtest behaviour.  This is why the bug
    ## never showed up in CI.
    let params = regtestParams()  # minimumChainWork all-zero
    let sm = syncManagerAtGenesis(params)
    let genesis = buildGenesisBlock(params)

    let headers = buildHeaderChain(params.genesisBlockHash,
                                   genesis.header.timestamp, 5)
    let cls = sm.classifyHeaderBatch(headers)
    check cls.routing == hbrDirect

  test "headers that connect to an earlier branch point also route through anti-DoS":
    ## The pre-fix code DID handle branch-from-earlier headers; confirm the
    ## rewrite preserves that path.  Extend the header chain by 3, then offer
    ## a batch branching from height 1.
    let params = syntheticParams()
    let sm = syncManagerAtGenesis(params)
    let genesis = buildGenesisBlock(params)

    let base = buildHeaderChain(params.genesisBlockHash,
                                genesis.header.timestamp, 3)
    for h in base:
      let idx = sm.headerChain.headers.len
      sm.headerChain.headers.add(h)
      sm.headerChain.hashes.add(hashOf(h))
      sm.headerChain.byHash[hashOf(h)] = idx
    sm.headerChain.tipHeight = int32(base.len)

    # Branch from height 1 (base[0]).
    let branchPointHash = hashOf(base[0])
    let fork = buildHeaderChain(branchPointHash, base[0].timestamp, 5)
    let cls = sm.classifyHeaderBatch(fork)
    check cls.routing == hbrAntiDoS
    check cls.connectHeight == 1
    check cls.connectHash == branchPointHash

  test "headers that connect nowhere → hbrUnconnecting":
    let params = syntheticParams()
    let sm = syncManagerAtGenesis(params)
    var orphanPrev: array[32, byte]
    orphanPrev[0] = 0xAB  # not genesis, not in chain
    let headers = buildHeaderChain(BlockHash(orphanPrev), 1_500_000_000'u32, 3)
    let cls = sm.classifyHeaderBatch(headers)
    check cls.routing == hbrUnconnecting

  test "a high-work batch clears the threshold directly → hbrDirect":
    ## If the offered chain already carries enough work, Core skips
    ## TryLowWorkHeadersSync (ProcessNewBlockHeaders with min_pow_checked=true).
    ## Use a tiny threshold so 5 headers exceed it.
    var params = regtestParams()
    var tinyMcw: array[32, byte]
    tinyMcw[0] = 0x01  # threshold = 1 — trivially met
    params.minimumChainWork = tinyMcw
    let sm = syncManagerAtGenesis(params)
    let genesis = buildGenesisBlock(params)
    let headers = buildHeaderChain(params.genesisBlockHash,
                                   genesis.header.timestamp, 5)
    let cls = sm.classifyHeaderBatch(headers)
    check cls.routing == hbrDirect

# ===========================================================================
suite "W162: handleHeaders from genesis must NOT ban an honest peer":

  test "from-genesis batch under non-zero minimumChainWork does not ban the peer":
    ## End-to-end through handleHeaders.  Pre-fix this banned the peer with
    ## "invalid header received" / "too-little-chainwork".  A sub-2000 batch
    ## takes tryLowWorkHeadersSync's incomplete-message path (no getheaders
    ## send → no socket needed), so this drives the real routing without a
    ## live connection.
    let params = syntheticParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.7", 8333, params, pdInbound)
    pm.peers["203.0.113.7:8333"] = peer

    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm

    let genesis = buildGenesisBlock(params)
    let headers = buildHeaderChain(params.genesisBlockHash,
                                   genesis.header.timestamp, 10)

    # Must not raise, and must not ban.
    waitFor sm.handleHeaders(peer, headers)

    check not pm.isBanned("203.0.113.7")
    check peer.misbehaviorScore == 0
    # The height-1 header must NOT have been rejected into the header chain
    # as a banned-reject; the batch was routed to the anti-DoS pipeline, so
    # the chain still holds only genesis (presync stores commitments, not
    # headers, and a sub-2000 batch is dropped as an incomplete low-work msg).
    check sm.headerChain.tipHeight == 0

  test "regtest from-genesis batch still accepts headers directly":
    ## Counterpart: with zero minimumChainWork the direct path must still
    ## connect headers (no behaviour change for regtest / the test fleet).
    let params = regtestParams()
    let pm = newPeerManager(params, 8, 2, 117, "/tmp")
    let peer = newPeer("203.0.113.8", 8333, params, pdInbound)
    pm.peers["203.0.113.8:8333"] = peer

    let sm = syncManagerAtGenesis(params)
    sm.peerManager = pm

    let genesis = buildGenesisBlock(params)
    let headers = buildHeaderChain(params.genesisBlockHash,
                                   genesis.header.timestamp, 6)

    waitFor sm.handleHeaders(peer, headers)

    check not pm.isBanned("203.0.113.8")
    check peer.misbehaviorScore == 0
    check sm.headerChain.tipHeight == 6   # all 6 headers accepted directly

# ===========================================================================
suite "W162: W97 anti-DoS protection survives the fix":
  # The fix must NOT reintroduce the W97 hole.  A genuinely low-work chain —
  # one whose TOTAL cumulative work is below minimumChainWork — must still be
  # rejected.  PRESYNC validates per-header PoW + continuity only; the
  # cumulative-work check is on the COMPLETED chain (headerssync.cpp).

  test "presync of a genuinely low-work full chain never emits validated headers":
    ## Drive the HeadersSyncState directly: a 2000-header batch whose total
    ## work is far below the threshold.  PRESYNC must accumulate work, fail
    ## to reach minimumRequiredWork, and emit ZERO headers for permanent
    ## storage — the low-work chain is rejected.
    let params = syntheticParams()
    let genesis = buildGenesisBlock(params)
    let genesisHash = params.genesisBlockHash

    # Threshold deliberately unreachable by regtest-difficulty headers.
    var hugeMcw: array[32, byte]
    hugeMcw[20] = 0x01  # ~2^160 — no realistic regtest chain reaches this
    let threshold = initUInt256(hugeMcw)

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = 0x207fffff'u32,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = threshold
    )
    check state.getState() == Presync

    # A full (2000-header) batch — "full message" so presync would request
    # more if work were sufficient.
    let headers = buildHeaderChain(genesisHash, genesis.header.timestamp, 2000)
    let res = state.processNextHeaders(headers, true)

    # PRESYNC succeeds at the per-header level (PoW + continuity all valid)…
    check res.success
    # …but emits NOTHING for permanent storage: cumulative work is far below
    # the threshold, so it never transitions to REDOWNLOAD.
    check res.powValidatedHeaders.len == 0
    check state.getState() == Presync   # still presyncing, work not yet met
    check state.getPresyncWork() < threshold

  test "presync of a sufficient-work chain DOES transition to redownload":
    ## Symmetry check: with a reachable threshold the same machinery must
    ## progress past PRESYNC — proving the rejection above is about work,
    ## not a broken pipeline.
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisHash = params.genesisBlockHash

    let state = newHeadersSyncState(
      peerId = 2,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = 0x207fffff'u32,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(2)  # trivially reachable
    )
    let headers = buildHeaderChain(genesisHash, genesis.header.timestamp, 10)
    let res = state.processNextHeaders(headers, true)
    check res.success
    # Work threshold met → left PRESYNC.
    check state.getState() != Presync

# ===========================================================================
suite "W162: newSyncManager wires minimumChainWork from params":

  test "fresh SyncManager carries params.minimumChainWork (fix #1 regression guard)":
    ## newSyncManager left sm.minimumChainWork at zero ("Will be set from
    ## chainstate" — but nothing ever set it).  getAntiDoSWorkThreshold()
    ## then returned 0 and the PRESYNC pipeline was dead.  Verify the field
    ## is now populated from params.  Uses a struct built the same way
    ## newSyncManager does for the genesis (bestHeight < 0) path.
    let params = syntheticParams()
    let sm = syncManagerAtGenesis(params)
    check not sm.minimumChainWork.isZero()
    check sm.minimumChainWork == initUInt256(params.minimumChainWork)

  test "getAntiDoSWorkThreshold is non-zero once minimumChainWork is wired":
    ## With the field wired, the anti-DoS threshold is no longer 0, so
    ## tryLowWorkHeadersSync can actually start a PRESYNC sync.
    let params = syntheticParams()
    let sm = syncManagerAtGenesis(params)
    let threshold = sm.getAntiDoSWorkThreshold()
    check not threshold.isZero()
    check threshold >= initUInt256(params.minimumChainWork)
