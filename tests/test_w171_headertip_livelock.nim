## W171 — TWO mainnet liveness wedges found on 2026-08-23, both in the
## header/block sync state machine, both of which the node could NOT leave on
## its own.
##
## ---------------------------------------------------------------------------
## (A) header tip froze 1,010 blocks BEHIND the validated chain
## ---------------------------------------------------------------------------
## Incident (mainnet, 2026-08-16 06:41 -> 2026-08-23 11:00, PID 394900, 7d18h
## uptime, 9 peers, no restarts):
##
##   INF processed headers   accepted=0 tipHeight=962722 totalHeaders=1020
##   INF reached header tip  height=962722
##   WRN sync timeout, resetting  state=ssDownloadingBlocks
##       chainTipHeight=963732 headerTipHeight=962722 pendingBlocks=0
##
## `SyncManager` tracks `headerChain.tipHeight` separately from the validated
## `chainTipHeight`, and the side-branch/reorg arm advances the chain tip
## WITHOUT extending the header chain — applyBlock says so in its own comment
## ("Update chain tip (NOT header tip - they're tracked separately)"), and
## `processSideBranchBody`'s sboReorged arm sets only chainTip/chainTipHeight.
## Live proof from the log: 9 consecutive
##   "accepted competing-fork header (side branch) forkHeight=9637NN"
##   "P2P reorg: switched active tip to heavier competing branch newHeight=9637NN"
## pairs walked the chain from 962722 to 963732 one block at a time while the
## header chain never moved.
##
## `buildBlockLocator` seeds from the HEADER tip, so every getheaders asked
## peers to resume 1,010 blocks behind the node's own chain; the answers were
## all headers the node already had (`hasAnyHeader` -> `continue`), every batch
## graded accepted=0, and the pointer never advanced.  A restart cleared it
## instantly because boot re-seeds the header chain from the block index
## (`loadHeaderChainFromDb`) — the recovery already existed, it was just
## unreachable without killing the process.
##
## Bitcoin Core cannot express this state.  `AcceptBlock`'s first act is
## `AcceptBlockHeader` (validation.cpp:4308), so a block cannot connect unless
## its CBlockIndex — the SAME object the header index is made of — exists.
## And the pointer every getheaders locator is built from is explicitly floored
## at the active tip: `ChainstateManager::RecalculateBestHeader`
## (validation.cpp:6256-6264) starts `m_best_header = ActiveChain().Tip();`
## and only ever raises it; net_processing.cpp:5771-5772 re-applies the same
## floor.  Locators are then `GetLocator(m_best_header)`
## (net_processing.cpp:2657, :3106, :4110) walking one index via GetAncestor
## (chain.cpp:26-44).
##
## FIX (A): `locatorStartHeight` = max(headerTip, chainTip) + a block-index
## fallback in `buildLocatorFromHeight`, and `reconcileHeaderTip` — a runtime
## self-heal that re-seeds the header chain from the block index whenever
## headerTip < chainTip, wired into requestHeaders / startHeaderSync /
## handleHeaders / processHeaders / the sync-timeout path.
##
## ---------------------------------------------------------------------------
## (B) downloader idle in ssDownloadingBlocks with an OPEN GAP and no getdata
## ---------------------------------------------------------------------------
## Found only because the node was re-examined AFTER the restart instead of
## being assumed healthy.  The restart fixed (A) — "processed headers
## accepted=9 tipHeight=963741" — the node connected exactly ONE block and then
## stalled again, this time permanently:
##
##   WRN sync timeout, resetting  state=ssDownloadingBlocks
##       chainTipHeight=963733 headerTipHeight=963741 pendingBlocks=0
##
## with ZERO block-request log lines in 25 minutes and 8-9 healthy peers all
## reporting height=963741.
##
## Root cause: `requestBlocks` skips any height whose body `chainDb.getBlock`
## already returns — correct on its own, fatal without a counterpart that
## CONNECTS it.  nimrod's only connect trigger was a block arriving over P2P.
## `acceptSideBranchBlock` persists every side-branch body it accepts
## (storage/chainstate.nim:3152 `cs.db.storeBlock(blk)`) and can return
## `sboSideBranch` without connecting, so bodies 963734..963741 — fetched by
## the (A)-era fork-body walk between 10:17 and 10:48 — sat on disk: never
## re-requested (we "have" them), never connected (nothing arrived).  Unlike
## (A), a restart does NOT clear this: the state is on disk.
##
## Core skips BLOCK_HAVE_DATA in FindNextBlocksToDownload for the same reason
## and is safe because ActivateBestChain / setBlockIndexCandidates connect from
## disk independently of the network.
##
## FIX (B): `connectStoredBlocks` — connect already-persisted successors of the
## chain tip before deciding what to fetch — plus a loud warning when the
## downloader declines to enqueue anything while it is behind (that `return`
## used to be silent, which is why 25 minutes of stall left no evidence).
##
## These tests use ONLY entry points that exist both before and after the fix
## (`buildBlockLocator`, `processHeaders`, `requestBlocks`), so the suite is
## a genuine fail-before / pass-after regression test rather than a test of
## new API.

import unittest2
import std/[options, os, tables, sets]
import chronos
import ../src/network/sync
import ../src/network/peer
import ../src/consensus/[params, validation, chain]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers (same shape as tests/test_w164_apply_block_diffbits.nim)
# ---------------------------------------------------------------------------
const EASY_BITS = 0x207fffff'u32

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc makeCoinbaseTx(height: int32): Transaction =
  let scriptSig = encodeBip34Height(height) & @[byte(0x00)]
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

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32): Block =
  let coinbase = makeCoinbaseTx(height)
  var hdr = BlockHeader(
    version: 4,
    prevBlock: prevHash,
    merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
    timestamp: ts,
    bits: EASY_BITS,
    nonce: 0
  )
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[coinbase])

const BaseTs = 1_700_000_000'u32

proc buildDatadir(path: string, p: ConsensusParams,
                  count: int): tuple[cs: ChainState, blks: seq[Block]] =
  ## Canonical genesis + `count` mined blocks, all CONNECTED — a real datadir
  ## at the moment of a clean shutdown.
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  let res0 = cs.connectBlock(genesis, 0'i32)
  doAssert res0.isOk, "connect genesis: " & $res0.error
  var blks: seq[Block] = @[genesis]
  var prevHash = p.genesisBlockHash
  var ts = BaseTs
  for h in 1'i32 .. int32(count):
    let blk = mineBlock(prevHash, h, ts)
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "connect h=" & $h & ": " & $res.error
    prevHash = hashOf(blk.header)
    blks.add(blk)
    ts += 600
  result = (cs, blks)

proc mineOnTop(tip: Block, fromHeight: int32, count: int): seq[Block] =
  ## `count` blocks extending `tip`, heights fromHeight .. fromHeight+count-1.
  result = @[]
  var prevHash = hashOf(tip.header)
  var ts = tip.header.timestamp + 600
  for i in 0 ..< count:
    let blk = mineBlock(prevHash, fromHeight + int32(i), ts)
    result.add(blk)
    prevHash = hashOf(blk.header)
    ts += 600

proc headersOf(blks: seq[Block]): seq[BlockHeader] =
  result = @[]
  for b in blks:
    result.add(b.header)

proc freezeHeaderTipAt(sm: SyncManager, at: int32, blks: seq[Block]) =
  ## Reproduce the mainnet (A) state EXACTLY: the header chain is frozen at
  ## `at` while the validated chain is at `blks.high`, and the real-chain
  ## headers above `at` were mis-filed into `sideHeaders` by the fork arm —
  ## so every subsequent batch grades "already known" (`hasAnyHeader`) and
  ## scores accepted=0, which is what the live log showed for a week.
  let keep = int(at) + 1
  doAssert keep < sm.headerChain.headers.len

  # 1. Mis-file the above-`at` real-chain headers into sideHeaders.
  var cum: array[32, byte]
  for i in 0 ..< sm.headerChain.headers.len:
    cum = addWork(cum, calculateWork(sm.headerChain.headers[i].bits))
    if int32(i) > at:
      sm.headerChain.sideHeaders[sm.headerChain.hashes[i]] =
        SideHeader(header: sm.headerChain.headers[i],
                   height: int32(i), totalWork: cum)

  # 2. Truncate the active header chain to `at` (what the node's in-memory
  #    header chain actually looked like: the reorg arm never extended it).
  var activeWork: array[32, byte]
  for i in 0 ..< keep:
    activeWork = addWork(activeWork, calculateWork(sm.headerChain.headers[i].bits))
  for i in keep ..< blks.len:
    sm.headerChain.byHash.del(hashOf(blks[i].header))
  sm.headerChain.headers.setLen(keep)
  sm.headerChain.hashes.setLen(keep)
  sm.headerChain.tip = sm.headerChain.hashes[^1]
  sm.headerChain.tipHeight = at
  sm.headerChain.totalWork = activeWork
  sm.headerTip = sm.headerChain.tip
  sm.headerTipHeight = at

# ===========================================================================
suite "W171(A): header tip BEHIND the validated chain must self-heal at runtime":

  test "the getheaders locator is never seeded behind the validated chain":
    ## THE mainnet bug, minimal form.  headerTip=20, chainTip=30 -> pre-fix the
    ## locator's first entry is the height-20 hash, so peers resume 10 blocks
    ## behind our own chain and every header they send back is already known.
    ## Core floors the locator anchor at the active tip
    ## (validation.cpp:6256-6264), which is exactly what max() restores.
    let p = regtestParams()
    let path = "/tmp/nimrod_w171_locator"
    let (cs, blks) = buildDatadir(path, p, 30)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    check sm.headerChain.tipHeight == 30
    check sm.chainTipHeight == 30

    sm.freezeHeaderTipAt(20'i32, blks)
    check sm.headerChain.tipHeight == 20      # header pointer frozen
    check sm.chainTipHeight == 30             # chain advanced past it
    check sm.headerChain.sideHeaders.len == 10

    let locator = sm.buildBlockLocator()
    check locator.len > 0
    # PRE-FIX: locator[0] == hash@20 (the frozen header tip).
    # POST-FIX: locator[0] == hash@30 (the validated chain tip).
    check locator[0] == array[32, byte](hashOf(blks[30].header))

  test "an incoming header batch heals the pointer and then CONNECTS":
    ## The livelock proper: pre-fix every header in the batch is graded against
    ## the frozen chain, fails to connect, and the tip never moves — the
    ## "accepted=0 / reached header tip 962722" loop.  Post-fix the invariant
    ## violation is repaired first (re-seed from the block index, the same work
    ## a restart did) and the batch then connects normally.
    let p = regtestParams()
    let path = "/tmp/nimrod_w171_selfheal"
    let (cs, blks) = buildDatadir(path, p, 30)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    sm.freezeHeaderTipAt(20'i32, blks)

    # The peer answers with the 5 headers that really follow OUR chain tip.
    let ahead = mineOnTop(blks[30], 31'i32, 5)
    let accepted = sm.processHeaders(headersOf(ahead))

    # PRE-FIX: accepted == 0, tipHeight stays 20 (livelock — no restart, no exit).
    # POST-FIX: the pointer self-heals to 30, then all 5 connect.
    check accepted == 5
    check sm.headerChain.tipHeight == 35
    check sm.headerTipHeight == 35
    check sm.headerTip == hashOf(ahead[^1].header)
    # The mis-filed real-chain headers are dropped from sideHeaders by the
    # re-seed: leaving them would keep `hasAnyHeader` answering "already
    # known" for headers we need to re-accept.
    check sm.headerChain.sideHeaders.len == 0
    # And the node is no longer wedged: the locator now leads the chain.
    check sm.buildBlockLocator()[0] == array[32, byte](hashOf(ahead[^1].header))

  test "a healthy node is untouched (no spurious re-seed)":
    ## Regression guard: the repair must be a no-op whenever the invariant
    ## holds, including the normal headers-ahead-of-blocks IBD shape.
    let p = regtestParams()
    let path = "/tmp/nimrod_w171_healthy"
    let (cs, blks) = buildDatadir(path, p, 12)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    check sm.headerChain.tipHeight == 12
    check sm.chainTipHeight == 12

    # Headers legitimately run AHEAD of the block chain during IBD.
    let ahead = mineOnTop(blks[12], 13'i32, 4)
    check sm.processHeaders(headersOf(ahead)) == 4
    check sm.headerChain.tipHeight == 16
    check sm.chainTipHeight == 12          # blocks still behind: legal
    # Locator anchors on the header tip, which is the greater of the two.
    check sm.buildBlockLocator()[0] == array[32, byte](hashOf(ahead[^1].header))

# ===========================================================================
suite "W171(B): bodies already on disk must be CONNECTED, not silently skipped":

  test "an open gap whose bodies are all persisted is closed without any getdata":
    ## THE post-restart mainnet stall: chainTip 963733, headerTip 963741,
    ## pendingBlocks=0, and not one getdata in 25 minutes because every missing
    ## body was already on disk (persisted by acceptSideBranchBlock, never
    ## connected).  requestBlocks skipped them as "have it"; nothing connected
    ## them.  A restart does NOT clear this.
    let p = regtestParams()
    let path = "/tmp/nimrod_w171_stored"
    let (cs, blks) = buildDatadir(path, p, 30)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)

    # 8 blocks whose BODIES are persisted but which were never connected —
    # exactly what `acceptSideBranchBlock` leaves behind (chainstate.nim:3152).
    let stored = mineOnTop(blks[30], 31'i32, 8)
    for b in stored:
      csv.db.storeBlock(b)
    check sm.processHeaders(headersOf(stored)) == 8
    check sm.headerTipHeight == 38
    check sm.chainTipHeight == 30          # the open gap
    for b in stored:
      check csv.db.getBlock(hashOf(b.header)).isSome   # bodies really on disk

    let noPeer: Peer = nil
    waitFor sm.requestBlocks(noPeer)

    # PRE-FIX: nothing is enqueued (bodies "already present") and nothing
    # connects -> chainTipHeight stays 30 forever, the live wedge.
    # POST-FIX: the stored bodies are connected from disk, gap closed.
    check sm.chainTipHeight == 38
    check sm.chainTip == hashOf(stored[^1].header)
    # Nothing was asked for over the network in either case — that is the
    # "zero getdata lines" signature from the incident.
    check sm.requestedHashes.len == 0
    check sm.blockQueue.len == 0

  test "connecting from disk stops at the header tip and never runs past it":
    ## Guard against the opposite failure: bodies present ABOVE the header tip
    ## must not be connected, because their headers have not been validated.
    let p = regtestParams()
    let path = "/tmp/nimrod_w171_bound"
    let (cs, blks) = buildDatadir(path, p, 30)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)

    # 8 bodies on disk, but only 5 headers validated.
    let stored = mineOnTop(blks[30], 31'i32, 8)
    for b in stored:
      csv.db.storeBlock(b)
    check sm.processHeaders(headersOf(stored[0 ..< 5])) == 5
    check sm.headerTipHeight == 35

    let noPeer: Peer = nil
    waitFor sm.requestBlocks(noPeer)

    # PRE-FIX: 30 (nothing connects at all).
    # POST-FIX: exactly 35 — the header tip is the ceiling, not 38.
    check sm.chainTipHeight == 35
    check sm.chainTip == hashOf(stored[4].header)
