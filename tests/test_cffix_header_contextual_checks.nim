## cffix-nimrod-header-contextual-checks
##
## Bitcoin Core runs ContextualCheckBlockHeader on EVERY header it admits
## (AcceptBlockHeader, validation.cpp:4224), active-tip extension and
## competing fork alike.  Its gates, in order (validation.cpp:4080-4121):
##
##   4088  bad-diffbits          nBits != GetNextWorkRequired(pindexPrev)
##   4092  time-too-old          nTime <= pindexPrev->GetMedianTimePast()
##   4102  time-timewarp-attack  BIP94 (testnet4/regtest): first block of a
##                               retarget period more than MAX_TIMEWARP (600 s)
##                               before its parent
##   4108  time-too-new          nTime > now + MAX_FUTURE_BLOCK_TIME (2 h)
##   4113  bad-version           nVersion < 2/3/4 once BIP34/66/65 are active
##
## Before this fix nimrod's P2P header admission ran only part of that:
##   * ACTIVE arm (validateHeader): bad-diffbits, time-too-old, time-too-new.
##     No BIP94 timewarp, no bad-version.
##   * FORK arm (acceptForkHeader): bad-diffbits only.  A fork header could be
##     dated three hours ahead, older than its own branch's MTP, or carry an
##     obsolete version, and it was still stored in `sideHeaders` and written
##     to RocksDB as a header-only row.
##
## The params below are testnet4's rules (min-difficulty blocks, BIP94,
## BIP34/65/66 active from height 1, 2016-block retarget) on regtest's
## mineable powLimit, so headers can be mined in a unit test.  The same
## shape is used by tests/test_w168_header_diffbits.nim.

import unittest2
import chronos
import std/[tables, times, os]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/[params, pow]
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const POWLIMIT_BITS = 0x207fffff'u32
const HARD_BITS     = 0x207ffffe'u32
const T0            = 1_700_000_000'u32

proc testnet4Shaped(): ConsensusParams =
  result = regtestParams()
  result.network = Testnet4
  result.powAllowMinDifficultyBlocks = true
  result.powNoRetargeting = false
  result.enforceBIP94 = true
  # testnet4 activates BIP34/65/66 at height 1 (chainparams.cpp); regtestParams
  # already does, restate it so the test does not depend on that.
  result.bip34Height = 1
  result.bip65Height = 1
  result.bip66Height = 1
  result.difficultyAdjustmentInterval = 2016

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mine(prev: BlockHash, ts: uint32, bits: uint32, version: int32 = 4,
          salt: uint32 = 0): BlockHeader =
  var mr: array[32, byte]
  mr[0] = byte(salt and 0xFF)
  mr[1] = byte((salt shr 8) and 0xFF)
  result = BlockHeader(version: version, prevBlock: prev, merkleRoot: mr,
                       timestamp: ts, bits: bits, nonce: 0)
  while not validateHeaderPoW(result):
    result.nonce += 1

proc rootChain(): HeaderChain =
  let root = mine(BlockHash(default(array[32, byte])), T0, HARD_BITS)
  initHeaderChain(root, hashOf(root))

proc pushActive(hc: var HeaderChain, h: BlockHeader) =
  let hash = hashOf(h)
  let idx = hc.headers.len
  hc.headers.add(h)
  hc.hashes.add(hash)
  hc.byHash[hash] = idx
  hc.totalWork = addWork(hc.totalWork, calculateWork(h.bits))
  hc.tip = hash
  hc.tipHeight = int32(idx)

proc extendActive(hc: var HeaderChain, count: int, spacing: uint32 = 600):
    seq[BlockHeader] =
  for i in 0 ..< count:
    let h = mine(hc.tip, hc.headers[^1].timestamp + spacing, HARD_BITS)
    hc.pushActive(h)
    result.add(h)

proc syncManagerOn(hc: HeaderChain, params: ConsensusParams): SyncManager =
  SyncManager(
    state: ssIdle,
    headerChain: hc,
    params: params,
    headerTip: hc.tip,
    headerTipHeight: hc.tipHeight,
    chainTipNoState: hc.tip,
    chainTipHeightNoState: hc.tipHeight,
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

proc peerOn(sm: SyncManager, ip: string,
            params: ConsensusParams): tuple[pm: PeerManager, p: Peer] =
  ## Isolated ban-list datadir (see test_w168_header_diffbits.nim:158).
  let dir = getTempDir() / ("nimrod_cffix_hcc_pm_" & ip)
  removeDir(dir)
  createDir(dir)
  let pm = newPeerManager(params, 8, 2, 117, dir)
  let p = newPeer(ip, 8333, params, pdInbound)
  pm.peers[ip & ":8333"] = p
  sm.peerManager = pm
  (pm, p)

proc requiredBits(hc: HeaderChain, h: BlockHeader, p: ConsensusParams): uint32 =
  let r = hc.requiredBitsForHeader(h, p)
  doAssert r.outcome == dboOk
  r.required

proc mineAtRequired(hc: HeaderChain, prev: BlockHash, ts: uint32,
                    p: ConsensusParams, version: int32 = 4,
                    salt: uint32 = 0): BlockHeader =
  ## Mine a header at exactly GetNextWorkRequired for its own ancestry, so
  ## bad-diffbits cannot be the gate that rejects it.
  var probe = BlockHeader(version: version, prevBlock: prev, timestamp: ts,
                          bits: HARD_BITS)
  mine(prev, ts, hc.requiredBits(probe, p), version, salt)

template checkForkRejected(sm: SyncManager, h: BlockHeader, expected: untyped) =
  ## The header must not be admitted.  On a build with the fix, it must be
  ## refused for the expected reason (the outcome names do not exist on the
  ## base commit, so the stronger check is guarded and the base build still
  ## compiles and fails on the first check).
  let outcome = sm.acceptForkHeader(h, hashOf(h), true)
  check outcome != fhoAccepted
  when declared(expected):
    check outcome == expected
  check hashOf(h) notin sm.headerChain.sideHeaders

proc chainToBoundary(p: ConsensusParams): HeaderChain =
  ## Root (height 0) + 2015 headers: the next header is height 2016, the
  ## first block of a retarget period, where BIP94's timewarp floor applies.
  result = rootChain()
  discard result.extendActive(p.difficultyAdjustmentInterval - 1)
  doAssert result.tipHeight == int32(p.difficultyAdjustmentInterval - 1)

# ===========================================================================
suite "cffix header contextual checks: ACTIVE arm (validateHeader / handleHeaders)":

  test "a version-1 min-difficulty header extending the tip is rejected (bad-version)":
    let p = testnet4Shaped()
    var hc = rootChain()
    discard hc.extendActive(5)
    # 20+ minutes after the tip, so testnet4's min-difficulty rule makes
    # powLimit the REQUIRED nBits: bad-diffbits passes, MTP passes.
    let ts = hc.headers[^1].timestamp + uint32(p.powTargetSpacing * 2) + 1
    let v1 = mine(hc.tip, ts, POWLIMIT_BITS, version = 1)
    check hc.checkHeaderDiffbits(v1, p) == dboOk
    let (valid, err) = validateHeader(v1, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "bad-version"

  test "versions 2 and 3 are rejected too once BIP66/BIP65 are active":
    let p = testnet4Shaped()
    var hc = rootChain()
    discard hc.extendActive(5)
    for v in [2'i32, 3'i32]:
      let h = mine(hc.tip, hc.headers[^1].timestamp + 600, HARD_BITS, version = v)
      let (valid, err) = validateHeader(h, hc, hc.tipHeight + 1, p)
      check (not valid)
      check err == "bad-version"

  test "the version-1 header sent by a peer does not enter byHash":
    let p = testnet4Shaped()
    var hc = rootChain()
    discard hc.extendActive(5)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.71", p)
    let ts = sm.headerChain.headers[^1].timestamp +
             uint32(p.powTargetSpacing * 2) + 1
    let v1 = mine(sm.headerChain.tip, ts, POWLIMIT_BITS, version = 1)
    let tipBefore = sm.headerChain.tipHeight

    waitFor sm.handleHeaders(peer, @[v1])

    check hashOf(v1) notin sm.headerChain.byHash
    check not sm.headerChain.hasAnyHeader(hashOf(v1))
    check sm.headerChain.tipHeight == tipBefore
    # An invalid header (BLOCK_INVALID_HEADER in Core) is a fair penalty.
    check peer.misbehaviorScore > 0 or pm.isBanned("203.0.113.71")

  test "control: the same min-difficulty header at version 4 is admitted":
    let p = testnet4Shaped()
    var hc = rootChain()
    discard hc.extendActive(5)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.72", p)
    let ts = sm.headerChain.headers[^1].timestamp +
             uint32(p.powTargetSpacing * 2) + 1
    let v4 = mine(sm.headerChain.tip, ts, POWLIMIT_BITS, version = 4)
    check validateHeader(v4, sm.headerChain, sm.headerChain.tipHeight + 1, p).valid

    waitFor sm.handleHeaders(peer, @[v4])

    check hashOf(v4) in sm.headerChain.byHash
    check sm.headerChain.tip == hashOf(v4)
    check peer.misbehaviorScore == 0
    check not pm.isBanned("203.0.113.72")

  test "BIP94: a retarget-boundary header >600 s before its parent is rejected (time-timewarp-attack)":
    let p = testnet4Shaped()
    let hc = chainToBoundary(p)
    let prevTs = hc.headers[^1].timestamp
    # 601 s before the parent: breaks the timewarp floor, still above MTP
    # (the parent's MTP is 3000 s before it at 600 s spacing).
    let warp = hc.mineAtRequired(hc.tip, prevTs - 601, p)
    check hc.checkHeaderDiffbits(warp, p) == dboOk
    check warp.timestamp > hc.getMedianTimePastFromChain(hc.tipHeight)
    let (valid, err) = validateHeader(warp, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "time-timewarp-attack"

  test "control: a retarget-boundary header exactly 600 s before its parent is admitted":
    let p = testnet4Shaped()
    let hc = chainToBoundary(p)
    let edge = hc.mineAtRequired(hc.tip, hc.headers[^1].timestamp - 600, p)
    let (valid, err) = validateHeader(edge, hc, hc.tipHeight + 1, p)
    check valid
    check err == ""

  test "control: without BIP94 (mainnet rules) the same boundary header is admitted":
    var p = testnet4Shaped()
    p.enforceBIP94 = false
    let hc = chainToBoundary(p)
    let warp = hc.mineAtRequired(hc.tip, hc.headers[^1].timestamp - 601, p)
    check validateHeader(warp, hc, hc.tipHeight + 1, p).valid

# ===========================================================================
suite "cffix header contextual checks: FORK arm (acceptForkHeader)":

  test "a fork header dated now+3h is not stored (time-too-new)":
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let future = uint32(getTime().toUnix()) + 3 * 3600
    # Far past the parent, so min-difficulty makes powLimit the required nBits.
    let f = mine(hashOf(active[4]), future, POWLIMIT_BITS, salt = 21)
    check sm.headerChain.checkHeaderDiffbits(f, p) == dboOk
    checkForkRejected(sm, f, fhoTimeTooNew)
    check not sm.headerChain.hasAnyHeader(hashOf(f))

  test "a fork header with an obsolete version is not stored (bad-version)":
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let f = mine(hashOf(active[4]), active[4].timestamp + 600, HARD_BITS,
                 version = 1, salt = 22)
    check sm.headerChain.checkHeaderDiffbits(f, p) == dboOk
    checkForkRejected(sm, f, fhoBadHeader)

  test "a fork header at or below its parent's MTP is not stored (time-too-old)":
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    # MTP of active[4] (height 5) is the median of heights 0..5 = height 3.
    let mtp = active[2].timestamp
    let f = mine(hashOf(active[4]), mtp, HARD_BITS, salt = 23)
    check sm.headerChain.checkHeaderDiffbits(f, p) == dboOk
    checkForkRejected(sm, f, fhoBadHeader)

  test "MTP is taken from the fork's own ancestry, not the active chain's heights":
    ## Fork off A2 with 1000 s spacing (under 2*600, so no min-difficulty
    ## exception), so by height 8 the fork's timestamps run ahead of the
    ## active chain's.  A candidate at height 9 dated between the two MTPs:
    ##   active-chain MTP at height 8 (A4.ts = A2.ts + 1200)  <  cand.ts
    ##   fork MTP at height 8 (F4.ts = A2.ts + 2000)          >= cand.ts
    ## (window R,A1,A2,F3..F8 = 9 timestamps; the median is the 5th, F4.)
    ## Core walks pprev, so it is time-too-old; reading the active height
    ## index would wrongly admit it.
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    var prev = hashOf(active[1])                 # A2, height 2
    var ts = active[1].timestamp
    var fork: seq[BlockHeader]
    for i in 0 ..< 6:                            # F3..F8
      ts += 1000
      let f = mine(prev, ts, HARD_BITS, salt = uint32(100 + i))
      check sm.acceptForkHeader(f, hashOf(f), true) == fhoAccepted
      fork.add(f)
      prev = hashOf(f)
    check sm.headerChain.sideHeaders[prev].height == 8
    let candTs = active[1].timestamp + 1800
    check candTs > sm.headerChain.getMedianTimePastFromChain(8)  # active view
    check candTs <= fork[1].timestamp                             # F4: fork MTP
    let cand = mine(prev, candTs, HARD_BITS, salt = 200)
    check sm.headerChain.checkHeaderDiffbits(cand, p) == dboOk
    checkForkRejected(sm, cand, fhoBadHeader)

  test "control: a fork header above its own MTP is admitted even when below the active chain's":
    ## The other direction: fork timestamps 1 s apart, so the fork's MTP is
    ## far below the active chain's at the same height.  A candidate between
    ## them is VALID by its own ancestry and must not be refused.
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    var prev = hashOf(active[1])
    var ts = active[1].timestamp
    var fork: seq[BlockHeader]
    for i in 0 ..< 6:
      ts += 1
      let f = mine(prev, ts, HARD_BITS, salt = uint32(300 + i))
      check sm.acceptForkHeader(f, hashOf(f), true) == fhoAccepted
      fork.add(f)
      prev = hashOf(f)
    # Fork MTP at height 8 is F4 (A2.ts + 2): window R,A1,A2,F3..F8, 5th of 9.
    let candTs = fork[^1].timestamp + 1
    check candTs > fork[1].timestamp                              # fork MTP
    check candTs <= sm.headerChain.getMedianTimePastFromChain(8)  # active view
    let cand = mine(prev, candTs, HARD_BITS, salt = 400)
    check sm.acceptForkHeader(cand, hashOf(cand), true) == fhoAccepted
    check sm.headerChain.sideHeaders[hashOf(cand)].height == 9

  test "BIP94: a fork header on a retarget boundary >600 s before its parent is not stored":
    let p = testnet4Shaped()
    var hc = chainToBoundary(p)
    let a2014 = hc.hashes[2014]
    let sm = syncManagerOn(hc, p)
    # F2015 off A2014, then the boundary header F2016.
    let f2015 = sm.headerChain.mineAtRequired(a2014,
                  sm.headerChain.headers[2014].timestamp + 600, p, salt = 31)
    check sm.acceptForkHeader(f2015, hashOf(f2015), true) == fhoAccepted
    let warp = sm.headerChain.mineAtRequired(hashOf(f2015),
                 f2015.timestamp - 601, p, salt = 32)
    check sm.headerChain.checkHeaderDiffbits(warp, p) == dboOk
    checkForkRejected(sm, warp, fhoBadHeader)
    # Control at the floor: exactly 600 s before the parent is valid.
    let edge = sm.headerChain.mineAtRequired(hashOf(f2015),
                 f2015.timestamp - 600, p, salt = 33)
    check sm.acceptForkHeader(edge, hashOf(edge), true) == fhoAccepted
    check sm.headerChain.sideHeaders[hashOf(edge)].height == 2016

  test "control: a valid fork header is admitted":
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let f = mine(hashOf(active[4]), active[4].timestamp + 600, HARD_BITS,
                 salt = 24)
    check sm.acceptForkHeader(f, hashOf(f), true) == fhoAccepted
    check sm.headerChain.sideHeaders[hashOf(f)].height == 6

  test "a peer's bad-version fork header is not stored on the handleHeaders path":
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.73", p)
    let f = mine(hashOf(active[4]), active[4].timestamp + 600, HARD_BITS,
                 version = 1, salt = 25)

    waitFor sm.handleHeaders(peer, @[f])

    check sm.headerChain.sideHeaders.len == 0
    check sm.headerChain.tipHeight == 10
    check peer.misbehaviorScore > 0 or pm.isBanned("203.0.113.73")

  test "a peer's future-dated fork header is not stored and the peer is not punished":
    ## Core: time-too-new is BLOCK_TIME_FUTURE, which MaybePunishNodeForBlock
    ## does not punish (net_processing.cpp:1943) — the header may become
    ## valid later, so it is dropped, not held against the sender.
    let p = testnet4Shaped()
    var hc = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.74", p)
    let future = uint32(getTime().toUnix()) + 3 * 3600
    let f = mine(hashOf(active[4]), future, POWLIMIT_BITS, salt = 26)

    waitFor sm.handleHeaders(peer, @[f])

    check sm.headerChain.sideHeaders.len == 0
    check peer.misbehaviorScore == 0
    check not pm.isBanned("203.0.113.74")
