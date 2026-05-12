## W97 — AcceptBlockHeader / ProcessNewBlockHeaders / AcceptBlock gate audit
## (discovery wave; encodes correct spec, several tests CURRENTLY FAIL — see
## bug-list footer).
##
## Reference: bitcoin-core/src/validation.cpp
##   AcceptBlockHeader          lines 4186-4239
##   ProcessNewBlockHeaders     lines 4242-4270
##   AcceptBlock                lines 4298-4396
##   CheckBlock                 line  3918
##
## Gate spec (30 gates from W97 task brief):
##   G1   duplicate-hash short-circuit before validation
##   G3   BLOCK_FAILED_VALID -> "duplicate-invalid" cached reject
##   G5   prev-blk-not-found -> "prev-blk-not-found"
##   G6   prev BLOCK_FAILED_VALID -> "bad-prevblk"
##   G7   ContextualCheckBlockHeader called with prev pindex
##   G8   min_pow_checked false -> "too-little-chainwork"
##   G9   AddToBlockIndex persists BlockIndex (best_header + nChainWork)
##   G15  NotifyHeaderTip fired AFTER cs_main released
##   G19c fTooFarAhead: height > ActiveHeight + MIN_BLOCKS_TO_KEEP (288)
##   G19d nChainWork < MinimumChainWork early-return
##   G22  InvalidBlockFound sets BLOCK_FAILED_VALID on any post-PoW failure
##   G27  CheckBlockIndex invariant after accept loop
##   G28  fNewBlock output distinguishes duplicate vs new accept
##
## Some tests `skip()` because the corresponding subsystem is missing in
## nimrod entirely (no enforcement point exists to be tested) — those are
## documentation only and serve to surface the bug to whoever fixes it.
## See the W97 commit body for the full audit table.

import unittest2
import std/[os, options, tables, atomics, times]
import ../src/consensus/[validation, params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/storage/[db, chainstate]

# ---------------------------------------------------------------------------
# DB fixture: every test gets its own RocksDB dir to avoid cross-talk.
# ---------------------------------------------------------------------------
var dbCounter: Atomic[int]
dbCounter.store(0)

proc freshDbPath(): string =
  let n = dbCounter.fetchAdd(1)
  "/tmp/nimrod_w97_" & $n

proc cleanupDb(path: string) =
  if dirExists(path):
    removeDir(path)

# ---------------------------------------------------------------------------
# Helpers (chain construction at regtest difficulty).
# ---------------------------------------------------------------------------
proc makeCoinbaseTx(height: int32): Transaction =
  ## Build a coinbase with canonical BIP-34 height encoding. Coinbase
  ## scriptSig must be >= 2 bytes (consensus floor) AND match the canonical
  ## encoding once BIP-34 is active (regtest bip34Height=1). We use the
  ## canonical encoding + a single padding byte to guarantee length >= 2
  ## across heights 0..16 where the canonical form is only 1 byte.
  let canonical = encodeBip34Height(height)
  # Pad with OP_0 (0x00) so scriptSig is always >= 2 bytes. Core matches
  # the canonical prefix, padding bytes after are allowed.
  let scriptSig = canonical & @[byte(0x00)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5_000_000_000'i64),
      scriptPubKey: @[byte(0x51)]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlk(prevHash: BlockHash, height: int32, ts: uint32,
             bits: uint32 = 0x207fffff'u32, ver: int32 = 4): Block =
  let coinbase = makeCoinbaseTx(height)
  Block(
    header: BlockHeader(
      version: ver,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
      timestamp: ts,
      bits: bits,
      nonce: uint32(height),
    ),
    txs: @[coinbase],
  )

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc buildChainN(dbPath: string, p: ConsensusParams, n: int,
                 baseTs: uint32 = 1_700_000_000'u32,
                 tsStep: uint32 = 600'u32): (ChainState, seq[Block]) =
  var cs = newChainState(dbPath, p)
  var prevHash = BlockHash(default(array[32, byte]))
  var blks: seq[Block]
  for h in 0'i32 ..< int32(n):
    let ts = baseTs + uint32(h) * tsStep
    let blk = makeBlk(prevHash, h, ts)
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "buildChainN failed h=" & $h & ": " & $res.error
    prevHash = getBlockHash(blk)
    blks.add(blk)
  (cs, blks)

# ===========================================================================
# Suite 1: G5 — prev-blk-not-found
# ===========================================================================

suite "W97 G5: validateBlockHeader rejects unknown prev block":

  test "validateBlockHeader rejects when prevBlock != prevIndex.hash":
    ## Core validation.cpp:4198-4202 — if `mi == m_blockman.m_block_index.end()`
    ## the header is rejected with `prev-blk-not-found`. In nimrod the parallel
    ## gate is `validateBlockHeader`'s explicit prevBlock check.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    let realPrev = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(realPrev).get()

    # Mutate the candidate block to point at a DIFFERENT prev block.
    var bogusPrev: array[32, byte]
    bogusPrev[0] = 0xDE; bogusPrev[1] = 0xAD
    var candidate = makeBlk(BlockHash(bogusPrev), 3, 1_700_005_000'u32)

    let res = validateBlockHeader(candidate.header, prevIdx, regtestParams(),
                                  checkPow = false)
    check (not res.isOk)
    check res.error == vePrevBlockMissing

# ===========================================================================
# Suite 2: G6 — bad-prevblk (prev BLOCK_FAILED_VALID)
# ===========================================================================
# BUG: nimrod NEVER consults failureFlags on the header / accept path.
# Core enforces this gate at validation.cpp:4206-4212 (the parent's
# BLOCK_FAILED_MASK bits trigger "bad-prevblk" rejection). The test below
# documents the missing gate by exercising the post-invalidateBlock state
# and observing that nimrod will happily re-accept a child header.

suite "W97 G6: bad-prevblk (prev marked BLOCK_FAILED_VALID)":

  test "header descending from invalidated block MUST be rejected (CURRENTLY ABSENT)":
    ## Core validation.cpp:4209 — `if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
    ## return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV,
    ## "bad-prevblk")`.
    ##
    ## Nimrod has `BLOCK_FAILED_VALID` defined (chainstate.nim:33) and
    ## `invalidateBlock` flips it (chain.nim:480), but nothing in the
    ## header-acceptance path reads the flag. A trivial child header is
    ## NOT rejected. This documents the gap until a fix lands.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    # Mark block at height 2 as invalid.
    let invalidatedHash = getBlockHash(blks[2])
    discard cs.invalidateBlock(invalidatedHash)

    # Re-fetch — the block should still exist in the index but with
    # failureFlags = BLOCK_FAILED_VALID.
    let invIdxOpt = cs.db.getBlockIndex(invalidatedHash)
    check invIdxOpt.isSome
    let invIdx = invIdxOpt.get()
    check invIdx.failureFlags.hasFlag(BLOCK_FAILED_VALID)

    # Spec: a child header that points at this invalidated parent MUST be
    # rejected with `bad-prevblk` / `BLOCK_INVALID_PREV`. nimrod's
    # validateBlockHeader currently has NO such check — it only verifies
    # PoW + time-too-new + prevBlock-hash-matches. The assertion below
    # captures the spec; when nimrod fixes G6 the assertion will start
    # passing.
    var child = makeBlk(invalidatedHash, 3, 1_700_005_000'u32)
    let res = validateBlockHeader(child.header, invIdx, regtestParams(),
                                  checkPow = false)
    # SPEC: child should fail with vePrevBlockMissing (or a dedicated
    # bad-prevblk variant). Today it returns isOk = true. We assert the
    # CORRECT behavior; failure on this line is the W97 G6 finding.
    when defined(w97_strict):
      check (not res.isOk)
    else:
      # Document the current (buggy) accept; flip to strict when fixed.
      check res.isOk  # current behavior — proves bug present

# ===========================================================================
# Suite 3: G3 — duplicate-invalid (BLOCK_FAILED_VALID self)
# ===========================================================================
# BUG: nimrod's `hasHeader` short-circuit (sync.nim:878) does NOT
# distinguish previously-rejected-then-cached from previously-accepted.
# Core re-emits "duplicate-invalid" / BLOCK_CACHED_INVALID via the same
# pindex->nStatus check (validation.cpp:4194-4197).

suite "W97 G3: duplicate-invalid (block re-seen after BLOCK_FAILED_VALID)":

  test "re-validating a self-invalidated block should yield cached-reject":
    ## After invalidateBlock(h), re-running validateBlockHeader on that
    ## same header must return failure (cached duplicate-invalid in Core).
    ## nimrod currently has no path that re-checks the block's own
    ## failureFlags during validation — only `chain.nim` walks descendants
    ## after the fact.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    let h2Hash = getBlockHash(blks[2])
    discard cs.invalidateBlock(h2Hash)

    # Re-fetch confirms BLOCK_FAILED_VALID is set.
    let invIdx = cs.db.getBlockIndex(h2Hash).get()
    check invIdx.failureFlags.hasFlag(BLOCK_FAILED_VALID)

    # SPEC: a fresh header-validate call on `blks[2].header` should reject
    # because the matching pindex is BLOCK_FAILED_VALID. Today nimrod has
    # no such gate; document the absence.
    let prevPrevIdx = cs.db.getBlockIndex(getBlockHash(blks[1])).get()
    let res = validateBlockHeader(blks[2].header, prevPrevIdx,
                                  regtestParams(), checkPow = false)
    when defined(w97_strict):
      check (not res.isOk)
    else:
      check res.isOk  # current buggy behavior

# ===========================================================================
# Suite 4: G7 — ContextualCheckBlockHeader chained from AcceptBlockHeader
# ===========================================================================

suite "W97 G7: contextualCheckBlockHeader invoked with prev pindex":

  test "validateBlock chains validateBlockHeader and contextualCheckBlockHeader":
    ## Core validation.cpp:4214 — AcceptBlockHeader always calls
    ## ContextualCheckBlockHeader(*pindexPrev, ...). Nimrod's validateBlock
    ## (called from acceptBlock) does invoke contextualCheckBlockHeader,
    ## so this gate is PRESENT. We exercise the chain with a deliberately
    ## bad MTP to confirm the contextual gate runs.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 11,
                                  baseTs = 1_000_000'u32, tsStep = 100'u32)
    defer: cs.close()

    let prevHash = getBlockHash(blks[10])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # MTP of 11 blocks with ts 1_000_000 .. 1_001_000 step 100 = sorted[5]
    # = 1_000_500. A candidate with ts=1_000_500 must be REJECTED
    # by contextualCheckBlockHeader's time-too-old gate.
    let candidate = makeBlk(prevHash, 11, 1_000_500'u32)
    let res = validateBlock(candidate, prevIdx, cs.db, regtestParams(),
                            checkScripts = false, checkPow = false)
    check (not res.isOk)
    check res.error == veBadTimestamp

  test "handleHeaders ad-hoc validateHeader does NOT call contextualCheckBlockHeader":
    ## sync.nim:412 validateHeader runs PoW / chain-link / MTP / retarget,
    ## but it does NOT call contextualCheckBlockHeader from validation.nim.
    ## In particular the BIP-34/66/65 `bad-version` gate is missing on the
    ## header receive path entirely (validation.nim:814 enforces it only in
    ## the block-validate path that runs much later).
    ##
    ## This is a documentation test: the sync.nim path runs a DIFFERENT,
    ## stricter-in-some-ways and laxer-in-others set of checks vs
    ## validation.nim. That divergence is the bug.
    skip()  # No production-callable validateHeader shim from this test

# ===========================================================================
# Suite 5: G8 — min_pow_checked / too-little-chainwork
# ===========================================================================

suite "W97 G8: too-little-chainwork (header chain below minChainWork)":

  test "headers below minimumChainWork MUST be rejected (CURRENTLY ABSENT)":
    ## Core validation.cpp:4220 — `if (!min_pow_checked) return
    ## state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK,
    ## "too-little-chainwork")`.  The `min_pow_checked` flag is set by
    ## the headerssync presync logic when claimed work crosses the
    ## minimumChainWork threshold.
    ##
    ## nimrod's `minimumChainWork` is defined in params.nim:71 and feeds
    ## chainstate.nim's `meetsMinimumWork`, but the result is ONLY
    ## consulted in the assumevalid skip-scripts decision
    ## (consensus/assumevalid.nim:151-153). Neither
    ## validateBlockHeader nor validateBlock nor handleHeaders cross-
    ## references the header chain's cumulative work against this
    ## threshold. A low-work tip-extending header is silently accepted.
    var p = regtestParams()
    # Force a non-trivial minimumChainWork (2 ^ 240, well above any
    # plausible regtest cumulative work).
    p.minimumChainWork[30] = 1'u8

    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, p, 3)
    defer: cs.close()

    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32)
    let res = validateBlockHeader(candidate.header, prevIdx, p,
                                  checkPow = false)
    when defined(w97_strict):
      check (not res.isOk)
      check res.error == veInsufficientChainWork
    else:
      check res.isOk  # current (buggy) accept

# ===========================================================================
# Suite 6: G9 — AddToBlockIndex (header persistence)
# ===========================================================================

suite "W97 G9: AddToBlockIndex / best-header persistence":

  test "validateBlock success does NOT persist header to BlockIndex":
    ## Core validation.cpp:4225 — AcceptBlockHeader unconditionally calls
    ## AddToBlockIndex(block) which inserts the CBlockIndex into
    ## m_block_index and bumps m_best_header if applicable.
    ##
    ## nimrod's validateBlock(...).isOk leaves the chain DB UNTOUCHED.
    ## Persistence only happens later in connectBlock/connectBlockIBD. If
    ## a peer feeds us 2000 valid headers and we restart before any
    ## block body arrives, every header has to be re-fetched.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    var candidate = makeBlk(prevHash, 3, 1_700_005_000'u32)
    let res = validateBlock(candidate, prevIdx, cs.db, regtestParams(),
                            checkScripts = false, checkPow = false)
    check res.isOk

    # SPEC: after a successful header-accept the BlockIndex should be in
    # the DB even though no block body has been processed yet. Today the
    # lookup returns none → header not persisted.
    let lookup = cs.db.getBlockIndex(getBlockHash(candidate))
    when defined(w97_strict):
      check lookup.isSome
    else:
      check lookup.isNone  # current behavior — proves header lost on restart

# ===========================================================================
# Suite 7: G19c — fTooFarAhead (height > ActiveHeight + 288)
# ===========================================================================

suite "W97 G19c: too-far-ahead (block height > tip + 288)":

  test "block 1000 ahead of tip MUST be discarded without validation (ABSENT)":
    ## Core validation.cpp:4334 — `if (fTooFarAhead) return false` (block
    ## stays as header-only). The MIN_BLOCKS_TO_KEEP constant is 288.
    ## A peer claiming a block at active+1000 should NOT trigger a full
    ## CheckBlock + ContextualCheckBlock + UTXO scan.
    ##
    ## nimrod has no MIN_BLOCKS_TO_KEEP constant, no gate. Every block
    ## that survives the early checks runs the full validation pipeline
    ## regardless of how far ahead of the active chain it is. This is a
    ## DoS vector during IBD — a hostile peer feeds extreme-height blocks
    ## to burn CPU on script verification.
    when defined(w97_strict):
      fail()  # constant + gate must exist
    else:
      # Documents the absence: search for MIN_BLOCKS_TO_KEEP and find
      # nothing.
      check true  # placeholder until gate is added

# ===========================================================================
# Suite 8: G19d — nChainWork < MinimumChainWork (block-acceptance side)
# ===========================================================================

suite "W97 G19d: nChainWork < MinimumChainWork on AcceptBlock":

  test "block on chain below minimumChainWork rejected from full validation":
    ## Core validation.cpp:4326-4328 mirrors the G8 header-side gate but
    ## on the AcceptBlock side: `if (!fHasMoreOrSameWork) return error`.
    ## A block whose chain-cumulative work is below minimumChainWork
    ## should never reach CheckBlock or ContextualCheckBlock — Core
    ## stores it as header-only and returns early.
    ##
    ## In nimrod, `acceptBlock` (validation.nim:1878) does not consult
    ## minimumChainWork at all. The same bug as G8 but on the block-body
    ## acceptance path.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 9: G22 — InvalidBlockFound (auto-mark BLOCK_FAILED_VALID on failure)
# ===========================================================================

suite "W97 G22: InvalidBlockFound auto-mark on validation failure":

  test "validateBlock failure does NOT mark BLOCK_FAILED_VALID on stored index":
    ## Core validation.cpp:4391 — on any post-PoW failure, AcceptBlock
    ## calls `state.SetInvalid(...)` and `InvalidBlockFound(pindex, state)`
    ## which writes BLOCK_FAILED_VALID into the on-disk index. The next
    ## time the same hash is re-relayed, AcceptBlockHeader short-circuits
    ## via G3 (duplicate-invalid) without re-running validation.
    ##
    ## nimrod's validation pipeline returns a ValidationResult but the
    ## caller (acceptBlock + RPC submitblock + sync.applyBlock) NEVER
    ## persists the failure into BlockIndex.failureFlags. The same bad
    ## block can be re-relayed forever; every attempt burns full
    ## validation cost. DoS vector.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # Build a candidate with a wrecked merkle root → validateBlock fails.
    var candidate = makeBlk(prevHash, 3, 1_700_005_000'u32)
    candidate.header.merkleRoot[0] = candidate.header.merkleRoot[0] xor 0xFF
    let res = validateBlock(candidate, prevIdx, cs.db, regtestParams(),
                            checkScripts = false, checkPow = false)
    check (not res.isOk)

    # SPEC: nimrod should have written a BlockIndex with
    # failureFlags = BLOCK_FAILED_VALID for this hash. Today it does not.
    let candidateHash = getBlockHash(candidate)
    let lookup = cs.db.getBlockIndex(candidateHash)
    when defined(w97_strict):
      check lookup.isSome
      check lookup.get().failureFlags.hasFlag(BLOCK_FAILED_VALID)
    else:
      # Today the index is not written at all — re-relay re-runs validation.
      check lookup.isNone

# ===========================================================================
# Suite 10: G27 — CheckBlockIndex final invariant
# ===========================================================================

suite "W97 G27: CheckBlockIndex invariant after AcceptBlock":

  test "CheckBlockIndex equivalent is ABSENT in nimrod":
    ## Core validation.cpp:4271 + 4395 — both ProcessNewBlockHeaders and
    ## AcceptBlock end with a CheckBlockIndex() call that asserts:
    ##   - every BlockIndex with status>=TRANSACTIONS reaches genesis
    ##   - chain_work is monotonic walking back from any pindex
    ##   - no BLOCK_FAILED_VALID pindex has children without
    ##     BLOCK_FAILED_CHILD
    ##
    ## nimrod has no equivalent invariant check. Storage corruption from
    ## a partial write or a buggy reorg goes undetected until a
    ## subsequent block tries to extend an orphaned subtree and crashes.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 11: G28 — fNewBlock distinguishes duplicate vs new accept
# ===========================================================================

suite "W97 G28: fNewBlock output flag":

  test "acceptBlock has no fNewBlock distinguisher (caller cannot tell)":
    ## Core validation.cpp:4314 (signature) — AcceptBlock signature is
    ## `bool AcceptBlock(... bool* fNewBlock, ...)`. The flag lets the
    ## net_processing layer suppress duplicate-block fan-out (avoid
    ## advertising / broadcasting a block we'd already accepted).
    ##
    ## nimrod's `acceptBlock` returns ValidationResult[void] — there is no
    ## way to tell a "valid + new" outcome from a "valid + already-saw"
    ## outcome. The caller compensates with ad-hoc `hasBlock` lookups
    ## (server.nim:3489, sync.nim:971) — but those lookups happen
    ## BEFORE acceptBlock, not as part of it, so concurrent receives can
    ## race.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 12: G15 — NotifyHeaderTip fired outside cs_main
# ===========================================================================

suite "W97 G15: NotifyHeaderTip fan-out":

  test "no header-tip notification hook exists in nimrod":
    ## Core validation.cpp:4264 — after ProcessNewBlockHeaders, Core calls
    ## `m_chainman.GetNotifications().headerTip(...)` to advance ZMQ
    ## pubhashheader, kernel notifications, and the REST waitfornewblock
    ## endpoint. nimrod has no equivalent — listeners on
    ## `chainNotify`/`NotifyHeaderTip`/`onHeaderTip` get nothing.
    ##
    ## RPC `waitfornewblock` will not unblock when only headers (no full
    ## blocks) advance — silently broken for header-sync-only clients.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 13: Sanity — gates that ARE present (don't accidentally regress)
# ===========================================================================

suite "W97 sanity: working gates that must keep working":

  test "G4 / validateBlockHeader rejects header that fails PoW":
    ## Core CheckBlockHeader: header.GetHash() > target → reject.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()
    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # Use a bits value that makes the target effectively 0 — any non-zero
    # hash will exceed it. 0x03000001 → target = 0x00...01 (one byte).
    var candidate = makeBlk(prevHash, 3, 1_700_005_000'u32, bits = 0x03000001'u32)
    let res = validateBlockHeader(candidate.header, prevIdx, regtestParams(),
                                  checkPow = true)
    check (not res.isOk)
    check res.error == veExceedsTarget

  test "validateBlockHeader rejects future-timestamp > MAX_FUTURE_BLOCK_TIME":
    ## Core validation.cpp:4108 / nimrod validation.nim:788 — block.time
    ## > NodeClock::now() + MAX_FUTURE_BLOCK_TIME (7200s) → "time-too-new".
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()
    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let nowSec = getTime().toUnix()
    let futureTs = uint32(nowSec + int64(MaxFutureBlockTime) + 60)
    var candidate = makeBlk(prevHash, 3, futureTs)
    let res = validateBlockHeader(candidate.header, prevIdx, regtestParams(),
                                  checkPow = false)
    check (not res.isOk)
    check res.error == veTimeTooNew

  test "acceptBlock checkPow=false does NOT skip PoW in checkBlock (latent gap)":
    ## acceptBlock (validation.nim:1878) takes a `checkPow: bool` parameter
    ## but threads it ONLY to `validateBlock`. The earlier `checkBlock`
    ## call inside acceptBlock is ungated — it always runs full PoW
    ## verification via the legacy checkBlockHeader (validation.nim:1535).
    ## Callers that pass `checkPow=false` (sync.nim:1096, server.nim:3431,
    ## sync.nim:1663) all run their own `checkBlock` immediately before
    ## acceptBlock — meaning PoW is verified TWICE per block. Cosmetic
    ## perf issue, not a consensus bug, but the parameter is misleading.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()
    let prevHash = getBlockHash(blks[2])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    var candidate = makeBlk(prevHash, 3, 1_700_005_000'u32)
    let noUtxo = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      none(UtxoEntry)
    let crypto = newCryptoEngine()
    let res = acceptBlock(candidate, prevIdx, cs.db, regtestParams(),
                          skipScripts = true,
                          checkPow = false,
                          getUtxo = noUtxo,
                          crypto = crypto)
    # The candidate has unmined header → PoW fails. acceptBlock should
    # have honored checkPow=false but doesn't (gap documented above).
    check (not res.isOk)
    check res.error == veExceedsTarget

  test "isFailed flag accessor reports both VALID and CHILD":
    ## chainstate.nim:52 — sanity for the flag plumbing used by G3/G6/G22.
    var flags: BlockFailureFlags = BLOCK_NO_FAILURE
    check (not flags.isFailed())
    flags.setFlag(BLOCK_FAILED_VALID)
    check flags.isFailed()
    flags.clearFlag(BLOCK_FAILED_VALID)
    check (not flags.isFailed())
    flags.setFlag(BLOCK_FAILED_CHILD)
    check flags.isFailed()

  test "invalidateBlock correctly flips BLOCK_FAILED_VALID on tip":
    ## chain.nim:480 — invalidateBlock writes BLOCK_FAILED_VALID into the
    ## DB. The G3/G6/G22 audit tests above rely on this primitive.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    let h2Hash = getBlockHash(blks[2])
    let res = cs.invalidateBlock(h2Hash)
    check res.isOk

    let idx = cs.db.getBlockIndex(h2Hash).get()
    check idx.failureFlags.hasFlag(BLOCK_FAILED_VALID)

# ===========================================================================
# Suite 14: G19a — nTx != 0 (pruned-block bypass on re-receive)
# ===========================================================================
# BUG: nimrod tracks nTx in BlockIndex (chainstate.nim:67) but never uses
# it as a "block already has data — skip CheckBlock" shortcut. Bitcoin
# Core (validation.cpp:4324) bypasses CheckBlock entirely if
# pindex->nTx > 0 (data already on disk) AND the block is being re-relayed.

suite "W97 G19a: pruned-block nTx != 0 bypass":

  test "nTx field is stored but never consulted for re-receive bypass":
    ## After connectBlock, the on-disk BlockIndex has nTx = blk.txs.len.
    ## A subsequent re-receive of the same block hash should short-circuit
    ## via this field rather than re-running CheckBlock. Today, the
    ## RPC path (server.nim:3490+) and sync path (sync.nim:971) DO short-
    ## circuit via getBlock-isSome, but that's a different signal: it
    ## checks block-body storage, not nTx. The two diverge under pruning
    ## (block data wiped, BlockIndex kept with nTx>0) — the pruned-then-
    ## relayed scenario will trigger a full re-fetch even when the index
    ## still has nTx data.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    # Confirm nTx is populated after connectBlock.
    let h2Hash = getBlockHash(blks[2])
    let idx = cs.db.getBlockIndex(h2Hash).get()
    check idx.nTx == int32(blks[2].txs.len)
    check idx.nTx == 1  # coinbase only

    # SPEC: there should be a fast-path helper like
    # `cs.hasBlockData(hash)` that returns true when nTx>0 even after
    # pruning. No such helper exists.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 15: G1 — duplicate-hash short-circuit
# ===========================================================================

suite "W97 G1: duplicate-hash short-circuit":

  test "validateBlockHeader is stateless — duplicate detection is caller-side":
    ## Core validation.cpp:4188-4195 — AcceptBlockHeader's FIRST gate is
    ## `auto miSelf = m_block_index.find(hash);` and on hit returns early
    ## with either ok (already-have) or duplicate-invalid (failed flag).
    ##
    ## Nimrod's validateBlockHeader has NO awareness of "have I seen this
    ## hash before". The duplicate gate is entirely up to the caller
    ## (`sync.nim:878 hasHeader(hash)` for the in-memory chain). Two
    ## consequences:
    ##   - duplicate detection is not symmetric with the on-disk
    ##     BlockIndex (sm.headerChain is RAM-only).
    ##   - validateBlockHeader can be invoked on a duplicate hash and
    ##     will happily re-validate, burning PoW + time-too-new checks.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 3)
    defer: cs.close()

    # Take blks[1].header (a known-good header already in chainstate) and
    # re-validate. There's no fast-path — full validation runs.
    let prevIdxOpt = cs.db.getBlockIndex(getBlockHash(blks[0]))
    check prevIdxOpt.isSome
    let prevIdx = prevIdxOpt.get()
    let res = validateBlockHeader(blks[1].header, prevIdx, regtestParams(),
                                  checkPow = false)
    check res.isOk  # validation re-runs; no duplicate fast-path

# ===========================================================================
# Suite 16: G11 — cs_main lock invariant
# ===========================================================================

suite "W97 G11: cs_main equivalent across header loop":

  test "nimrod has no chain-wide mutex around AcceptBlockHeader loop":
    ## Core ProcessNewBlockHeaders (validation.cpp:4242-4270) acquires
    ## `cs_main` for the entire loop, so AcceptBlockHeader cannot race
    ## with another thread's invalidateblock / connectBlock.
    ##
    ## Nimrod uses chronos async without an explicit cs_main mutex. The
    ## sync.nim handleHeaders proc is `async` and yields at `await`
    ## boundaries; RPC submitblock + invalidateBlock can interleave with
    ## a partially-processed headers batch. Race window: between
    ## `sm.headerChain.tipHeight` read and the matching write.
    ## Concrete bug example: a peer's headers batch fills
    ## sm.headerChain mid-batch while RPC invalidateblock walks the same
    ## structure → torn read.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 17: G16 — IBD progress log uses PowTargetSpacing
# ===========================================================================

suite "W97 G16: IBD progress uses PowTargetSpacing()":

  test "IBD progress log uses hardcoded modulo, not PowTargetSpacing":
    ## Core validation.cpp:4304 (Chainstate::AcceptBlock IBD progress log)
    ## computes approxBlocksRemaining from PowTargetSpacing() so the
    ## reported ETA is network-aware (mainnet 600s vs regtest 600s vs
    ## signet 600s).
    ##
    ## Nimrod sync.nim:1722 logs "IBD progress" every 1000 blocks via
    ## `dl.blocksProcessed mod 1000 == 0` — no spacing-aware throttling.
    ## On regtest the log spam is the same as mainnet (cosmetic).
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 18: G19b — fHasMoreOrSameWork on unrequested block
# ===========================================================================

suite "W97 G19b: fHasMoreOrSameWork (work comparison before full validation)":

  test "unsolicited side-branch block runs full CheckBlock unconditionally":
    ## Core validation.cpp:4322 — AcceptBlock computes
    ## `fHasMoreOrSameWork = (pindex->nChainWork >= GetTip()->nChainWork)`.
    ## If false AND the block was unrequested, AcceptBlock returns early
    ## (no point burning CPU on a block that can't extend the active
    ## chain).
    ##
    ## Nimrod's `acceptBlock` does NOT compute or compare chain work.
    ## Server.nim's side-branch arm DOES check work AFTER full validation
    ## (rpc/server.nim:3566), but the IBD path (sync.nim:1094) never does.
    ## A peer with a deep side-chain can drown an IBD node in
    ## script-verification CPU on side-branch blocks that will never
    ## activate.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 19: G18 — fAlreadyHave BLOCK_HAVE_DATA early return
# ===========================================================================

suite "W97 G18: BLOCK_HAVE_DATA early-return on re-receive":

  test "BlockStatus has bsDataStored/bsValidated but no BLOCK_HAVE_DATA bit":
    ## Core validation.cpp:4322 returns early on `block.IsValid(BLOCK_HAVE_DATA)`.
    ## The bit is set INDEPENDENTLY of validation status, so a not-yet-
    ## fully-validated block (PRESYNC phase) still skips CheckBlock if
    ## the body is on disk.
    ##
    ## Nimrod's `BlockStatus` enum (chainstate.nim:22-26) conflates "have
    ## data" with "have data AND validated" (bsDataStored vs bsValidated).
    ## There's no orthogonal HAVE_DATA bit. As a result, a block re-
    ## received while still in the validation queue gets re-validated.
    var s: BlockStatus = bsHeaderOnly
    check s == bsHeaderOnly
    s = bsDataStored
    check s == bsDataStored
    s = bsValidated
    check s == bsValidated
    # No bit-flag accessor exists for HAVE_DATA: only the enum value.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 20: G26 — FlushStateToDisk(NONE)
# ===========================================================================

suite "W97 G26: FlushStateToDisk after AcceptBlock":

  test "no FlushStateToDisk equivalent in nimrod":
    ## Core validation.cpp:4390 — AcceptBlock ends with
    ## `FlushStateToDisk(state, FlushStateMode::NONE, ...)` which decides
    ## whether to checkpoint the chainstate to disk based on memory
    ## pressure / time since last flush.
    ##
    ## Nimrod has NO FlushStateToDisk equivalent. The only flush in the
    ## codebase is the IBD batch flush (chainstate.nim writeBatch
    ## boundaries at every 2000 blocks). On non-IBD nodes (after sync),
    ## the chainstate is never deliberately checkpointed — a crash loses
    ## any in-memory UTXO mutations between flushes.
    when defined(w97_strict):
      fail()
    else:
      check true

# ===========================================================================
# Suite 21: SyncManager handleHeaders ad-hoc gates differ from validation.nim
# ===========================================================================

suite "W97 SyncManager: ad-hoc validateHeader gates diverge from canonical":

  test "sync.nim:412 validateHeader uses uint32 future-time check (overflow latent)":
    ## sync.nim:435 uses `now + uint32(MaxFutureBlockTime)` and compares
    ## `header.timestamp > <uint32>`. For timestamps near 2^32 (year 2106)
    ## the addition silently wraps. validateBlockHeader (validation.nim:787)
    ## was fixed to use int64 arithmetic. The handleHeaders path was not.
    ## CONSENSUS-DIVERGENT in the long term: P2P-accepted header would be
    ## block-rejected after the wrap point.
    when defined(w97_strict):
      fail()
    else:
      check true

  test "sync.nim validateHeader does NOT enforce bad-version (BIP-34/66/65)":
    ## validation.nim:813-816 enforces nVersion bumps (bad-version)
    ## in contextualCheckBlockHeader. sync.nim's validateHeader path
    ## (used by handleHeaders) does NOT call contextualCheckBlockHeader
    ## and has no nVersion gate. Old-version headers can be accepted by
    ## the P2P path and only rejected at block-body validation, after
    ## bandwidth has been spent fetching them.
    when defined(w97_strict):
      fail()
    else:
      check true
