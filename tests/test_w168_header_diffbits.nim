## W168 — the `bad-diffbits` gate at HEADER ADMISSION.
##
## Bitcoin Core, validation.cpp:4083-4089 (ContextualCheckBlockHeader, called
## for EVERY header from AcceptBlockHeader at validation.cpp:4224):
##
##     assert(pindexPrev != nullptr);                              // :4083
##     const int nHeight = pindexPrev->nHeight + 1;                // :4084
##     if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
##         return state.Invalid(..., "bad-diffbits", ...);         // :4088-4089
##
## This is NOT the high-hash check.  CheckBlockHeader (validation.cpp:3832)
## only proves the hash meets the target the header ITSELF declares; for a
## difficulty-1 claim that is nearly free.  The gate here compares the DECLARED
## nBits with the REQUIRED nBits.
##
## What was broken before this suite existed:
##
##   HOLE 1 — the FORK arm.  `acceptForkHeader` admitted any below-tip branch
##     after PoW + parent-exists only, on EVERY network including mainnet, and
##     stored each header in an unevicted Table plus a persisted RocksDB row.
##     That is the header-spam DoS Core documents at validation.cpp:4076-4078.
##
##   HOLE 2 — the ACTIVE arm on testnet3/testnet4.  The non-retarget branch
##     delegated to `permittedDifficultyTransition`, which returns `true`
##     unconditionally when powAllowMinDifficultyBlocks (pow.nim:216-217).
##     Core uses that proc only as the PRESYNC commitment heuristic
##     (headerssync.cpp:189, 237), never as the admission gate.  Any nBits was
##     accepted at any non-retarget height.
##
##   HOLE 2b — REGTEST.  The whole check sat behind `params.network != Regtest`.
##     Core enforces bad-diffbits on regtest too.
##
## LESSON-5 NOTE (why these params look odd): plain regtest is a no-op test bed
## for this rule — `powNoRetargeting` short-circuits the expected value, and the
## old code skipped the check on regtest by network name.  Every suite below
## therefore keeps regtest's easy, mineable powLimit but sets `network` and the
## PoW flags to MAINNET-shaped or TESTNET4-shaped values.  `pow.PowParams.network`
## is declared (pow.nim:17) but never read by any PoW computation, so swapping it
## changes only the code paths under test, not the arithmetic.

import unittest2
import chronos
import std/[options, tables, times, os]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/[params, pow]
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Difficulties.  Regtest powLimit compacts to 0x207fffff (an astronomically
# large target: essentially every nonce passes, so headers are mineable in a
# unit test).  HARD_BITS is one mantissa step below it — still trivially
# mineable, but NOT equal to powLimit, which is what makes the min-difficulty
# walk-back and the "declared vs required" comparison observable.
# ---------------------------------------------------------------------------
const POWLIMIT_BITS = 0x207fffff'u32
const HARD_BITS     = 0x207ffffe'u32
const T0            = 1_700_000_000'u32   ## chain root timestamp (Nov 2023)

# ---------------------------------------------------------------------------
# Params shapes
# ---------------------------------------------------------------------------
proc mainnetShaped(): ConsensusParams =
  ## Mainnet PoW semantics (no min-difficulty exception, real retargeting) on
  ## regtest's mineable powLimit.  Non-retarget required nBits == parent's nBits
  ## (Core pow.cpp:38 `return pindexLast->nBits`).
  result = regtestParams()
  result.network = Mainnet
  result.powAllowMinDifficultyBlocks = false
  result.powNoRetargeting = false
  result.enforceBIP94 = false

proc testnet4Shaped(): ConsensusParams =
  ## Testnet4 PoW semantics: min-difficulty exception + BIP94, real retargeting.
  ## This is the shape that HOLE 2 lived in.
  result = regtestParams()
  result.network = Testnet4
  result.powAllowMinDifficultyBlocks = true
  result.powNoRetargeting = false
  result.enforceBIP94 = true

# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------
proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mineHeader(prev: BlockHash, ts: uint32, bits: uint32,
                salt: uint32 = 0): BlockHeader =
  ## Build a header and mine a nonce satisfying its OWN declared target.
  ## `salt` goes in the merkle root so two headers with identical prev/ts/bits
  ## can still be distinct.
  var mr: array[32, byte]
  mr[0] = byte(salt and 0xFF)
  mr[1] = byte((salt shr 8) and 0xFF)
  result = BlockHeader(
    version: 4,
    prevBlock: prev,
    merkleRoot: mr,
    timestamp: ts,
    bits: bits,
    nonce: 0
  )
  while not validateHeaderPoW(result):
    result.nonce += 1

proc rootChain(rootBits: uint32 = HARD_BITS): tuple[hc: HeaderChain,
                                                    root: BlockHeader] =
  ## A header chain rooted at a synthetic height-0 header.  Using our own root
  ## (rather than buildGenesisBlock) lets the root carry HARD_BITS, so the
  ## min-difficulty walk-back has a non-powLimit ancestor to terminate on.
  let root = mineHeader(BlockHash(default(array[32, byte])), T0, rootBits)
  (initHeaderChain(root, hashOf(root)), root)

proc pushActive(hc: var HeaderChain, h: BlockHeader) =
  ## Append a header to the ACTIVE chain (what handleHeaders' accept arm does).
  let hash = hashOf(h)
  let idx = hc.headers.len
  hc.headers.add(h)
  hc.hashes.add(hash)
  hc.byHash[hash] = idx
  hc.totalWork = addWork(hc.totalWork, calculateWork(h.bits))
  hc.tip = hash
  hc.tipHeight = int32(idx)

proc extendActive(hc: var HeaderChain, count: int,
                  bits: uint32 = HARD_BITS, spacing: uint32 = 600): seq[BlockHeader] =
  ## Extend the active chain by `count` headers at `bits`, `spacing` apart.
  result = @[]
  for i in 0 ..< count:
    let h = mineHeader(hc.tip, hc.headers[^1].timestamp + spacing, bits)
    hc.pushActive(h)
    result.add(h)

proc syncManagerOn(hc: HeaderChain, params: ConsensusParams): SyncManager =
  ## A SyncManager carrying only the state the header-admission path reads.
  ## chainDb/chainState stay nil — every DB write on this path is guarded by
  ## `sm.chainDb != nil` (same approach as tests/test_reorg_p2p.nim).
  result = SyncManager(
    state: ssIdle,
    headerChain: hc,
    params: params,
    headerTip: hc.tip,
    headerTipHeight: hc.tipHeight,
    chainTip: hc.tip,
    chainTipHeight: hc.tipHeight,
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

proc peerOn(sm: SyncManager, ip: string,
            params: ConsensusParams): tuple[pm: PeerManager, p: Peer] =
  ## PeerManager on an ISOLATED datadir.
  ##
  ## Most suites pass "/tmp" here, which makes every run share one
  ## `/tmp/banlist.json`: a ban written by one test binary is still there for
  ## the next, and a `check not pm.isBanned(...)` then fails for reasons that
  ## have nothing to do with the code under test.  These tests deliberately ban
  ## peers, so they must not contribute to that shared file.
  let dir = "/tmp/nimrod_w168_pm_" & ip
  removeDir(dir)
  createDir(dir)
  let pm = newPeerManager(params, 8, 2, 117, dir)
  let p = newPeer(ip, 8333, params, pdInbound)
  pm.peers[ip & ":8333"] = p
  sm.peerManager = pm
  (pm, p)

# ===========================================================================
suite "W168 HOLE 2: testnet4 active arm — any-nBits is no longer accepted":

  test "difficulty-1 header extending a harder tip is REJECTED (bad-diffbits)":
    ## Core pow.cpp:22-39: the min-difficulty exception fires ONLY when
    ## `pblock->GetBlockTime() > pindexLast->GetBlockTime() + spacing*2`.
    ## With a 600s gap it does not, and the walk-back exits immediately because
    ## the parent's nBits != powLimit — so required == HARD_BITS.
    ## PRE-W168 this header was ACCEPTED: sync.nim delegated to
    ## permittedDifficultyTransition, which returns true unconditionally when
    ## powAllowMinDifficultyBlocks (pow.nim:216-217).
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)

    let cheat = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, POWLIMIT_BITS)
    # It passes the high-hash check against its OWN declared target …
    check validateHeaderPoW(cheat)
    # … and is still rejected, because that is not the rule.
    let (valid, err) = validateHeader(cheat, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "bad-diffbits"

  test "a header at the REQUIRED difficulty is accepted (no over-correction)":
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)

    let good = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, HARD_BITS)
    let (valid, err) = validateHeader(good, hc, hc.tipHeight + 1, p)
    check valid
    check err == ""

  test "the min-difficulty exception is still honoured (>2*spacing → powLimit)":
    ## Core pow.cpp:26-28.  A >20-minute gap MUST take powLimit, and only that.
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)
    let prevTs = hc.headers[^1].timestamp
    let lateTs = prevTs + uint32(p.powTargetSpacing * 2) + 1

    let minDiff = mineHeader(hc.tip, lateTs, POWLIMIT_BITS)
    let (okValid, _) = validateHeader(minDiff, hc, hc.tipHeight + 1, p)
    check okValid

    # …and a HARDER-than-required header at the same timestamp is bad-diffbits.
    # Core's rule is equality, not "at least as hard".
    let tooHard = mineHeader(hc.tip, lateTs, HARD_BITS)
    let (hardValid, hardErr) = validateHeader(tooHard, hc, hc.tipHeight + 1, p)
    check (not hardValid)
    check hardErr == "bad-diffbits"

  test "bad-diffbits is checked BEFORE time-too-old (Core's order)":
    ## validation.cpp:4088 (bad-diffbits) precedes :4092 (time-too-old).
    ## A header violating both must report bad-diffbits.
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)

    # Timestamp far in the PAST (fails MTP) and nBits wrong.  The past
    # timestamp also means the min-difficulty exception cannot fire, so the
    # required value is HARD_BITS.
    let both = mineHeader(hc.tip, T0 - 10_000, POWLIMIT_BITS)
    let (valid, err) = validateHeader(both, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "bad-diffbits"

# ===========================================================================
suite "W168: mainnet-shaped active arm":

  test "difficulty-1 header extending a harder mainnet tip is REJECTED":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)

    let cheat = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, POWLIMIT_BITS)
    let (valid, err) = validateHeader(cheat, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "bad-diffbits"

  test "correct-difficulty header is accepted on mainnet-shaped params":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)
    let good = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, HARD_BITS)
    check validateHeader(good, hc, hc.tipHeight + 1, p).valid

# ===========================================================================
suite "W168 HOLE 2b: regtest is no longer exempt":

  test "regtest rejects a wrong-nBits header at header admission":
    ## Pre-W168 sync.nim gated the entire difficulty check on
    ## `if params.network != Regtest`, so this header was admitted.
    ## Core applies ContextualCheckBlockHeader on regtest as well.
    let p = regtestParams()          # untouched: network == Regtest
    var (hc, _) = rootChain()
    discard hc.extendActive(5)

    let cheat = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, POWLIMIT_BITS)
    let (valid, err) = validateHeader(cheat, hc, hc.tipHeight + 1, p)
    check (not valid)
    check err == "bad-diffbits"

    let good = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, HARD_BITS)
    check validateHeader(good, hc, hc.tipHeight + 1, p).valid

# ===========================================================================
suite "W168 HOLE 1: the FORK arm enforces bad-diffbits too":

  test "difficulty-1 fork header below the tip is REJECTED, sideHeaders stays empty":
    ## PRE-W168 acceptForkHeader returned fhoAccepted here — on EVERY network —
    ## and stored the header in an unevicted Table plus a RocksDB row.  Repeat
    ## 2000 at a time and that is the header-spam DoS of
    ## validation.cpp:4076-4078.
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)

    # Branch off height 5 — a KNOWN below-tip ancestor, so the parent resolves
    # and the ONLY thing that can reject this is the difficulty gate.
    let forkParent = hashOf(active[4])      # active[4] is height 5
    let cheat = mineHeader(forkParent, active[4].timestamp + 600, POWLIMIT_BITS)
    check validateHeaderPoW(cheat)          # high-hash check passes
    check sm.headerChain.resolveParentWork(cheat.prevBlock).isSome

    check sm.acceptForkHeader(cheat, hashOf(cheat), true) == fhoBadDiffbits
    check sm.headerChain.sideHeaders.len == 0

  test "a fork header at the REQUIRED difficulty is still accepted (no over-correction)":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)

    let forkParent = hashOf(active[4])
    # salt=7 keeps it distinct from the active chain's own height-6 header.
    let good = mineHeader(forkParent, active[4].timestamp + 600, HARD_BITS, salt = 7)
    check sm.acceptForkHeader(good, hashOf(good), true) == fhoAccepted
    check sm.headerChain.sideHeaders.len == 1
    check sm.headerChain.sideHeaders[hashOf(good)].height == 6

# ===========================================================================
# THE POINTER-WALK / HEIGHT-INDEX NEGATIVE TEST  (wave-1 lesson 1).
#
# nimrod HAS a height index on this path — `hc.headers[h]` / `hc.hashes[h]`,
# which the pre-W168 `validateDifficultyRetarget` read directly.  Resolving a
# candidate's ancestors through it is the camlcoin inversion: at a fork the
# index describes OUR chain, not the candidate's, so the honest header is
# rejected and an attacker matching the poisoned answer is ADMITTED.
#
# The fixture below makes the two answers DISAGREE, then pins both directions.
#
#   height 0   R          bits=HARD    ts=T0
#   height 1-5 A1..A5     bits=HARD    ts=T0+600i           (active chain)
#   height 3   F3 (fork)  bits=POWLIM  ts=A2.ts+5000        (side branch off A2)
#   height 4   F4 (cand)  ts=F3.ts+600
#
#   Pointer answer for F4: parent is F3 (bits==powLimit).  F4.ts is only 600s
#     after F3, so the min-difficulty exception does NOT fire; Core walks back
#     over powLimit ancestors (pow.cpp:33) to A2, whose bits != powLimit
#     ⇒ required = HARD_BITS.
#   Height-index answer for F4: "parent at height 3" would be A3
#     (bits=HARD, ts=T0+1800).  F4.ts is >1200s after A3
#     ⇒ the min-difficulty exception fires ⇒ required = POWLIMIT_BITS.
#
# So the two disagree in BOTH directions, and each direction is asserted.
# ===========================================================================
suite "W168: retarget ancestors resolve by POINTER, never by height index":

  proc buildPoisonFixture(p: ConsensusParams):
      tuple[sm: SyncManager, f3: BlockHeader, a3: BlockHeader] =
    var (hc, _) = rootChain()
    let active = hc.extendActive(5)          # A1..A5 at HARD, 600s apart
    let sm = syncManagerOn(hc, p)

    let a2 = active[1]                       # height 2
    let f3 = mineHeader(hashOf(a2), a2.timestamp + 5000, POWLIMIT_BITS)
    # F3 is legitimately a min-difficulty block: 5000 > 2*600, so Core's
    # exception (pow.cpp:26-28) mandates powLimit — proving the fork arm still
    # admits genuinely valid min-difficulty forks.
    check sm.acceptForkHeader(f3, hashOf(f3), true) == fhoAccepted
    (sm, f3, active[2])                      # active[2] is A3, height 3

  test "the height index and the pointer walk really do disagree here":
    ## Guard for the fixture itself: if these two ever agreed, the tests below
    ## would pass without proving anything.
    let p = testnet4Shaped()
    let (sm, f3, a3) = buildPoisonFixture(p)
    let f4Ts = f3.timestamp + 600

    # Same nominal height (3), different headers, reached different ways.
    check sm.headerChain.sideHeaders[hashOf(f3)].height == 3
    check sm.headerChain.hashes[3] == hashOf(a3)
    check hashOf(f3) != hashOf(a3)

    # Pointer parent (F3) is a powLimit block only 600s before F4 →
    # exception does NOT fire.
    check f3.bits == POWLIMIT_BITS
    check int64(f4Ts) <= int64(f3.timestamp) + int64(p.powTargetSpacing * 2)
    # Height-index parent (A3) is a HARD block >1200s before F4 →
    # exception WOULD fire.
    check a3.bits == HARD_BITS
    check int64(f4Ts) > int64(a3.timestamp) + int64(p.powTargetSpacing * 2)

  test "required nBits comes from the fork's own ancestry (walk-back to A2)":
    let p = testnet4Shaped()
    let (sm, f3, _) = buildPoisonFixture(p)
    let cand = mineHeader(hashOf(f3), f3.timestamp + 600, HARD_BITS)
    let r = sm.headerChain.requiredBitsForHeader(cand, p)
    check r.outcome == dboOk
    check r.required == HARD_BITS            # pointer answer
    check r.required != POWLIMIT_BITS        # NOT the height-index answer

  test "the header matching the HEIGHT-INDEX answer is REJECTED (attacker not admitted)":
    let p = testnet4Shaped()
    let (sm, f3, _) = buildPoisonFixture(p)
    let attacker = mineHeader(hashOf(f3), f3.timestamp + 600, POWLIMIT_BITS)
    check sm.headerChain.checkHeaderDiffbits(attacker, p) == dboBadDiffbits
    check sm.acceptForkHeader(attacker, hashOf(attacker), true) == fhoBadDiffbits

  test "the header matching the POINTER answer is ACCEPTED (honest not rejected)":
    let p = testnet4Shaped()
    let (sm, f3, _) = buildPoisonFixture(p)
    let honest = mineHeader(hashOf(f3), f3.timestamp + 600, HARD_BITS)
    check sm.headerChain.checkHeaderDiffbits(honest, p) == dboOk
    check sm.acceptForkHeader(honest, hashOf(honest), true) == fhoAccepted
    check sm.headerChain.sideHeaders[hashOf(honest)].height == 4

# ===========================================================================
suite "W168: 'we cannot evaluate' is not 'the header is invalid'":

  test "unknown parent yields dboUnevaluable, not dboBadDiffbits":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)
    var unknown: array[32, byte]
    unknown[7] = 0xAB
    let orphan = mineHeader(BlockHash(unknown), T0 + 6000, POWLIMIT_BITS)
    check hc.checkHeaderDiffbits(orphan, p) == dboUnevaluable

  test "a fork whose ancestry is truncated → fhoCannotEvaluate, never fhoBadDiffbits":
    ## A side header stored before a restart (sideHeaders is in-memory only, so
    ## it does not survive one) leaves a dangling parent link.  Walking back
    ## over it fails.  That is OUR gap: the header is not known-invalid.
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)
    let sm = syncManagerOn(hc, p)

    # A dangling side header: powLimit bits (so the walk-back must step past
    # it) whose own parent is a hash we do not have.
    var gone: array[32, byte]
    gone[3] = 0x5E
    let dangling = mineHeader(BlockHash(gone), T0 + 4000, POWLIMIT_BITS)
    sm.headerChain.sideHeaders[hashOf(dangling)] = SideHeader(
      header: dangling, height: 3'i32, totalWork: default(array[32, byte]))

    # Child 600s later → no min-difficulty exception → walk-back needed → the
    # hop off `dangling` fails.
    let child = mineHeader(hashOf(dangling), dangling.timestamp + 600, HARD_BITS)
    check sm.headerChain.checkHeaderDiffbits(child, p) == dboUnevaluable
    check sm.acceptForkHeader(child, hashOf(child), true) == fhoCannotEvaluate
    check hashOf(child) notin sm.headerChain.sideHeaders

  test "handleHeaders applies NO peer penalty when WE cannot evaluate the rule":
    ## wave-1 lesson 2: our gap must never look like peer misbehaviour.
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.60", p)

    var gone: array[32, byte]
    gone[3] = 0x5E
    let dangling = mineHeader(BlockHash(gone), T0 + 4000, POWLIMIT_BITS)
    sm.headerChain.sideHeaders[hashOf(dangling)] = SideHeader(
      header: dangling, height: 3'i32, totalWork: default(array[32, byte]))

    # Batch: [legit fork header off height 5, then the unevaluable child].
    # The first header makes the batch CONNECT (classifyHeaderBatch looks up
    # headers[0].prevBlock in byHash), so the fork arm is genuinely reached.
    let ok1 = mineHeader(hashOf(active[4]), active[4].timestamp + 600,
                         HARD_BITS, salt = 11)
    let child = mineHeader(hashOf(dangling), dangling.timestamp + 600, HARD_BITS)

    waitFor sm.handleHeaders(peer, @[ok1, child])

    check not pm.isBanned("203.0.113.60")
    check peer.misbehaviorScore == 0
    check hashOf(ok1) in sm.headerChain.sideHeaders
    check hashOf(child) notin sm.headerChain.sideHeaders

# ===========================================================================
# DEAD-CODE PROOF (wave-1 lesson 6): the new gate must execute on the real
# inbound P2P path.  Wire:
#   messages.nim:835 parses "headers" -> nimrod.nim:1040-1044 dispatches
#   `mkHeaders` -> syncManager.handleHeaders (sync.nim) -> the two accept arms.
# These tests enter at handleHeaders — the first nimrod-side proc after
# dispatch — and drive it with a real Peer/PeerManager.
# ===========================================================================
suite "W168 dead-code proof: the gate runs on the inbound handleHeaders path":

  test "ACTIVE arm: a difficulty-1 header chain from a peer advances nothing":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.61", p)

    # 5 headers extending the ACTIVE tip, all claiming difficulty-1.
    var spam: seq[BlockHeader] = @[]
    var prev = sm.headerChain.tip
    var ts = sm.headerChain.headers[^1].timestamp
    for i in 0 ..< 5:
      ts += 600
      let h = mineHeader(prev, ts, POWLIMIT_BITS)
      spam.add(h)
      prev = hashOf(h)

    let tipBefore = sm.headerChain.tipHeight
    waitFor sm.handleHeaders(peer, spam)

    check sm.headerChain.tipHeight == tipBefore     # nothing admitted
    for h in spam:
      check not sm.headerChain.hasAnyHeader(hashOf(h))
    # These headers ARE invalid (not "unevaluable"), so a penalty is fair.
    check peer.misbehaviorScore > 0 or pm.isBanned("203.0.113.61")

  test "FORK arm: a difficulty-1 branch below the tip stores nothing":
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    let active = hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.62", p)

    # 5 headers branching at height 5, all claiming difficulty-1.
    var spam: seq[BlockHeader] = @[]
    var prev = hashOf(active[4])
    var ts = active[4].timestamp
    for i in 0 ..< 5:
      ts += 600
      let h = mineHeader(prev, ts, POWLIMIT_BITS)
      spam.add(h)
      prev = hashOf(h)

    waitFor sm.handleHeaders(peer, spam)

    check sm.headerChain.sideHeaders.len == 0
    check sm.headerChain.tipHeight == 10
    check peer.misbehaviorScore > 0 or pm.isBanned("203.0.113.62")

  test "honest headers still flow through handleHeaders untouched":
    ## The gate must not break the normal path: correct-difficulty headers
    ## extending the tip are admitted and the peer is not penalised.
    let p = mainnetShaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(10)
    let sm = syncManagerOn(hc, p)
    let (pm, peer) = sm.peerOn("203.0.113.63", p)

    var honest: seq[BlockHeader] = @[]
    var prev = sm.headerChain.tip
    var ts = sm.headerChain.headers[^1].timestamp
    for i in 0 ..< 5:
      ts += 600
      let h = mineHeader(prev, ts, HARD_BITS)
      honest.add(h)
      prev = hashOf(h)

    waitFor sm.handleHeaders(peer, honest)

    check sm.headerChain.tipHeight == 15
    check sm.headerChain.tip == hashOf(honest[^1])
    check not pm.isBanned("203.0.113.63")
    check peer.misbehaviorScore == 0

  test "processHeaders (the synchronous sibling entry) is gated too":
    ## sync.nim's legacy `processHeaders` runs the SAME validateHeader, so the
    ## gate covers it as well — it must not become a bypass.
    let p = testnet4Shaped()
    var (hc, _) = rootChain()
    discard hc.extendActive(5)
    let sm = syncManagerOn(hc, p)

    let cheat = mineHeader(sm.headerChain.tip,
                           sm.headerChain.headers[^1].timestamp + 600,
                           POWLIMIT_BITS)
    check sm.processHeaders(@[cheat]) == 0
    check sm.headerChain.tipHeight == 5

    let good = mineHeader(sm.headerChain.tip,
                          sm.headerChain.headers[^1].timestamp + 600,
                          HARD_BITS)
    check sm.processHeaders(@[good]) == 1
    check sm.headerChain.tipHeight == 6
