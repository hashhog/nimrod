## W163 — header chain must be reloaded from the persisted block index on
## startup, and the header sync must kick off + complete a catch-up.
##
## Incident (mainnet, 2026-05-20): nimrod was restarted with block chainstate
## at height 950146 but sat idle forever — connected to peers, 0% CPU, never
## sending a `getheaders`, block height frozen at the restart height.
##
## Root cause — TWO bugs:
##
##   1. newSyncManager carried a long-standing "TODO: Load header chain from
##      database": the in-memory header chain was re-initialised to genesis
##      only (tipHeight == 0) on every restart, even though the block index
##      held every header on the active chain.  nimrod then had to re-sync all
##      headers from genesis on each restart.
##
##   2. THE idle bug: nimrod.nim `await`ed peerManager.startOutboundConnections()
##      *before* `asyncSpawn`-ing syncManager.syncLoop().  startOutboundConnections
##      dials DNS-seed addresses serially; an unreachable address blocks for the
##      full TCP connect timeout (~127s with no cap).  When the connection phase
##      was slow, the `await` never returned, so syncLoop() was never spawned at
##      all — the node connected to peers but ran no sync state machine.
##
## This suite covers bug #1 directly (loadHeaderChainFromDb / newSyncManager
## rebuild the header chain from the block index), and the catch-up routing a
## node slightly behind tip must perform once the sync loop runs.  Bug #2 is a
## startup-ordering fix in nimrod.nim (asyncSpawn instead of await) — verified
## operationally; it has no unit-testable surface of its own.
##
## Bitcoin Core reference: BlockManager::LoadBlockIndex / CChainState::
## LoadChainTip load the block tree (headers included) from disk on startup,
## never re-downloading; ThreadOpenConnections dials peers in its own thread,
## fully decoupled from chain sync.

import std/[unittest, tables, options, os]
import ../src/network/sync
import ../src/network/headerssync
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/storage/undo
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

# Build `count` valid regtest-difficulty headers linked onto `startHash`.
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
    while not validateHeaderPoW(hdr):
      hdr.nonce += 1
    result.add(hdr)
    prev = hashOf(hdr)

## Open a fresh ChainDb at `path` and populate the block index with a chain of
## `count` headers above genesis (so bestHeight == count).  Returns the ChainDb
## and the headers written (heights 1..count) so the test can cross-check.
proc buildChainDbWithHeaders(path: string, params: ConsensusParams,
                             count: int): tuple[cdb: ChainDb,
                                                headers: seq[BlockHeader]] =
  removeDir(path)
  let cdb = openChainDb(path)
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash

  let headers = buildHeaderChain(genesisHash, genesis.header.timestamp, count)

  # The block index caches CUMULATIVE work per block (Core: nChainWork).
  var cumWork = calculateWork(genesis.header.bits)
  var prevHash = genesisHash
  for i, hdr in headers:
    let h = hashOf(hdr)
    cumWork = addWork(cumWork, calculateWork(hdr.bits))
    let idx = BlockIndex(
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
    )
    cdb.putBlockIndex(idx)
    prevHash = h

  # newSyncManager reads chainDb.bestHeight / bestBlockHash directly.
  cdb.bestHeight = int32(count)
  cdb.bestBlockHash = prevHash
  result = (cdb, headers)

# ===========================================================================
suite "W163: loadHeaderChainFromDb rebuilds the header chain":

  test "reload reconstructs the full chain from the block index":
    ## THE persistence bug.  Pre-fix the header chain was genesis-only after a
    ## restart; loadHeaderChainFromDb must rebuild it to match bestHeight.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_reload_full"
    let (cdb, headers) = buildChainDbWithHeaders(path, params, 25)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let hc = loadHeaderChainFromDb(cdb, params)

    # tipHeight matches the persisted chain — not 0.
    check hc.tipHeight == 25
    check hc.tipHeight == cdb.bestHeight
    # genesis + 25 headers.
    check hc.headers.len == 26
    check hc.hashes.len == 26
    # Every reloaded header is byHash-indexed and at the right height.
    for i, hdr in headers:
      let h = hashOf(hdr)
      check hc.byHash.hasKey(h)
      check hc.byHash[h] == i + 1
      check hc.getHeaderByHeight(int32(i + 1)).get() == hdr
    # Tip hash + cumulative work were carried over from the index.
    check hc.tip == hashOf(headers[^1])
    check not isZeroWork(hc.totalWork)

  test "reload of a genesis-only datadir yields a genesis-only chain":
    ## bestHeight <= 0 → nothing beyond genesis; must still be a valid chain.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_reload_genesis"
    let (cdb, _) = buildChainDbWithHeaders(path, params, 0)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let hc = loadHeaderChainFromDb(cdb, params)
    check hc.tipHeight == 0
    check hc.headers.len == 1
    check hc.tip == params.genesisBlockHash

  test "reload stops cleanly at a missing block-index row":
    ## If the index is inconsistent (a height present in the height->hash map
    ## but its BlockIndex entry absent), the reload must stop at the clean
    ## prefix instead of crashing — the live header sync then rebuilds the
    ## rest.  Simulate by claiming a bestHeight beyond what was written.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_reload_gap"
    let (cdb, _) = buildChainDbWithHeaders(path, params, 10)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    # Lie: claim the chain is 40 tall though only 10 indices exist.
    cdb.bestHeight = 40

    let hc = loadHeaderChainFromDb(cdb, params)
    # Stopped at the clean prefix (genesis + 10), did not raise.
    check hc.tipHeight == 10
    check hc.headers.len == 11

# ===========================================================================
suite "W163: newSyncManager reloads the header chain (no from-genesis re-sync)":

  test "SyncManager built on a populated datadir has a non-genesis header tip":
    ## Pre-fix, newSyncManager left headerChain at tipHeight==0 even when the
    ## block chainstate was far ahead — forcing a from-genesis header re-sync
    ## on every restart.  It must now match chainDb.bestHeight.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_sm_reload"
    let (cdb, headers) = buildChainDbWithHeaders(path, params, 30)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let sm = newSyncManager(nil, cdb, params)

    # The header chain reflects the persisted chain.
    check sm.headerChain.tipHeight == cdb.bestHeight
    check sm.headerChain.tipHeight == 30
    # The cheap summary fields are consistent with the reloaded chain.
    check sm.headerTipHeight == 30
    check sm.headerTip == hashOf(headers[^1])
    check sm.headerTip == sm.headerChain.tip
    # Block-chain tip fields still reflect the chainstate.
    check sm.chainTipHeight == 30

  test "a fresh (empty) datadir still starts the SyncManager at genesis":
    ## Regression guard: the bestHeight < 0 path must be untouched.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_sm_fresh"
    removeDir(path)
    let cdb = openChainDb(path)  # bestHeight == -1
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let sm = newSyncManager(nil, cdb, params)
    check sm.headerChain.tipHeight == 0
    check sm.headerTipHeight == 0
    check sm.headerChain.tip == params.genesisBlockHash

# ===========================================================================
suite "W163: a node slightly behind tip kicks off + completes a catch-up sync":
  # With the header chain reloaded to its restart height, a node only a few
  # headers behind the network must (a) classify the small catch-up batch for
  # DIRECT validation — it connects to the tip and on regtest the anti-DoS
  # threshold is zero — and (b) actually connect those headers when handled.

  test "a small catch-up batch connecting to the reloaded tip routes hbrDirect":
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_catchup_classify"
    # Datadir is 20 blocks deep; the network is at 24 (4 headers ahead).
    let (cdb, headers) = buildChainDbWithHeaders(path, params, 20)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let sm = newSyncManager(nil, cdb, params)
    check sm.headerChain.tipHeight == 20

    # The 4 missing headers, linked onto the reloaded tip.
    let tipHdr = headers[^1]
    let catchUp = buildHeaderChain(hashOf(tipHdr), tipHdr.timestamp, 4)
    check catchUp[0].prevBlock == sm.headerChain.tip

    let cls = sm.classifyHeaderBatch(catchUp)
    # Connects to our tip; regtest threshold == 0 → validate directly.
    check cls.routing == hbrDirect
    check cls.connectHeight == 20
    check cls.connectHash == sm.headerChain.tip

  test "processHeaders applies the catch-up batch onto the reloaded chain":
    ## End-to-end: feed the missing headers through processHeaders (the direct
    ## validation+store path) and confirm the header chain advances to the
    ## network tip — proving the reloaded chain is a valid base to sync from.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_catchup_apply"
    let (cdb, headers) = buildChainDbWithHeaders(path, params, 18)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let sm = newSyncManager(nil, cdb, params)
    check sm.headerChain.tipHeight == 18

    let tipHdr = headers[^1]
    let catchUp = buildHeaderChain(hashOf(tipHdr), tipHdr.timestamp, 6)

    let accepted = sm.processHeaders(catchUp)

    # All 6 catch-up headers connected; the chain reached the network tip.
    check accepted == 6
    check sm.headerChain.tipHeight == 24
    check sm.headerChain.tip == hashOf(catchUp[^1])
    # The new headers are byHash-indexed.
    for i, hdr in catchUp:
      check sm.headerChain.byHash.hasKey(hashOf(hdr))
      check sm.headerChain.byHash[hashOf(hdr)] == 19 + i

  test "re-applying an already-known catch-up batch is idempotent":
    ## Reloaded headers are already in the chain; a peer re-announcing them
    ## must not double-append or regress the tip.
    let params = regtestParams()
    let path = "/tmp/nimrod_w163_catchup_idem"
    let (cdb, headers) = buildChainDbWithHeaders(path, params, 15)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let sm = newSyncManager(nil, cdb, params)
    let before = sm.headerChain.tipHeight
    check before == 15

    # Offer headers the reload already placed (heights 11..15).
    let known = headers[10 .. 14]
    let accepted = sm.processHeaders(known)
    check accepted == 0                       # nothing new
    check sm.headerChain.tipHeight == before  # tip unchanged
    check sm.headerChain.headers.len == 16    # genesis + 15, no duplicates
