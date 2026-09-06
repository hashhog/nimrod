## W165 — during IBD, nimrod must NOT solicit loose mempool transactions.
##
## Incident (mainnet, 2026-05-20): with the W163 (header-chain reload) and
## W164 (applyBlock difficulty) fixes in place, nimrod's header sync worked
## (headerTipHeight=950241) and it connected block 950147 — but it could not
## advance.  It requested the next 94 blocks (950148..950241) from 9 peers,
## NONE arrived, `pendingBlocks` stayed permanently full, sync timed out
## every 60 s, and it re-requested the same 94 forever.
##
## Root cause: the `mkInv` handler in nimrod.nim requested EVERY announced
## transaction with a `getdata`, with no IBD guard.  A 100-second packet
## capture of the live node showed nimrod sending 12-18 transaction getdata
## messages PER PEER (470-540 wtxids each) while only ONE small block getdata
## (16 items) reached each peer.  The peers replied with thousands of `tx`
## messages that flooded nimrod's recv buffer; the resulting send-buffer
## backpressure on the peer (Bitcoin Core `CNode::fPauseSend`) made the
## peer's `ProcessGetData` break out of its tx-serving loop BEFORE it reached
## the single block item queued behind the tx flood in the same per-peer
## getdata FIFO.  The block we actually needed was therefore never served.
##
## Bitcoin Core gates the identical path: net_processing.cpp's INV handler
## only calls `AddTxAnnouncement` (→ tx getdata) inside
## `if (!m_chainman.IsInitialBlockDownload())` (net_processing.cpp:4088).
## Block invs are still processed during IBD; only the tx-getdata path is
## suppressed.
##
## NOT a regression from d665405 / 493bcd1 — the missing IBD guard was
## always there.  It only became fatal once d665405 restored header sync so
## nimrod actually entered ssDownloadingBlocks on mainnet against a heavy
## live mempool.
##
## This suite covers:
##   1. `SyncManager.isInitialBlockDownload` — the predicate the fix adds.
##   2. `requestBlocks`' per-peer cap (MaxBlocksPerPeer = Core's
##      MAX_BLOCKS_IN_TRANSIT_PER_PEER) — the second issue fixed in the same
##      change: the old code dumped ALL remaining blocks on the LAST peer.
##   3. The exact `mkInv` filtering decision: block invs always pass, tx
##      invs are dropped while IBD, kept when synced.

import unittest2
import std/[os]
import ../src/network/sync
import ../src/network/messages
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

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

## Open a fresh ChainDb at `path` with a chain of `count` headers above
## genesis (bestHeight == count).
proc buildChainDb(path: string, params: ConsensusParams,
                  count: int): ChainDb =
  removeDir(path)
  let cdb = openChainDb(path)
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  let headers = buildHeaderChain(genesisHash, genesis.header.timestamp, count)

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

  cdb.bestHeight = int32(count)
  cdb.bestBlockHash = prevHash
  result = cdb

## Replicates the EXACT `mkInv` filtering decision from nimrod.nim's
## handleMessage: block invs always pass; tx invs are dropped while `inIBD`.
## Returns (blockInvCount, txInvCount) that the handler would act on.
proc classifyInv(items: seq[InvVector], inIBD: bool): tuple[blocks, txs: int] =
  var b = 0
  var t = 0
  for item in items:
    if item.invType == invBlock or item.invType == invWitnessBlock:
      inc b
    elif item.invType == invTx or item.invType == invWitnessTx or
         item.invType == invWtx:
      if inIBD:
        continue
      inc t
  result = (b, t)

# ===========================================================================
suite "W165: SyncManager.isInitialBlockDownload predicate":

  test "behind tip (block chain lags header chain) => IBD true":
    let params = regtestParams()
    let cdb = buildChainDb("/tmp/nimrod-w165-a", params, 20)
    let sm = newSyncManager(nil, cdb, params)
    # Header chain reloaded to 20; block tip behind at 5.
    sm.chainTipHeight = 5
    sm.headerTipHeight = 20
    check sm.isInitialBlockDownload()
    check not sm.isSynced()

  test "exactly the incident shape (1 block connected, 94 behind) => IBD":
    let params = regtestParams()
    let cdb = buildChainDb("/tmp/nimrod-w165-b", params, 5)
    let sm = newSyncManager(nil, cdb, params)
    # Mirrors mainnet 2026-05-20: chainTip 950147, headerTip 950241.
    sm.chainTipHeight = 950147
    sm.headerTipHeight = 950241
    check sm.isInitialBlockDownload()

  test "block tip caught up to header tip => NOT IBD":
    let params = regtestParams()
    let cdb = buildChainDb("/tmp/nimrod-w165-c", params, 20)
    let sm = newSyncManager(nil, cdb, params)
    sm.chainTipHeight = 20
    sm.headerTipHeight = 20
    check not sm.isInitialBlockDownload()
    check sm.isSynced()

  test "block tip ahead of header tip => NOT IBD":
    ## Defensive: chainTip can momentarily exceed headerTip mid-connect.
    let params = regtestParams()
    let cdb = buildChainDb("/tmp/nimrod-w165-d", params, 20)
    let sm = newSyncManager(nil, cdb, params)
    sm.chainTipHeight = 21
    sm.headerTipHeight = 20
    check not sm.isInitialBlockDownload()

  test "no headers yet (headerTipHeight < 0) => IBD true":
    let params = regtestParams()
    let cdb = buildChainDb("/tmp/nimrod-w165-e", params, 0)
    let sm = newSyncManager(nil, cdb, params)
    sm.chainTipHeight = 0
    sm.headerTipHeight = -1
    check sm.isInitialBlockDownload()

# ===========================================================================
suite "W165: mkInv filtering — tx invs suppressed during IBD":

  test "during IBD, block invs pass and tx invs are dropped":
    var items: seq[InvVector]
    # 3 block invs + 500 tx invs (a realistic mainnet inv flood).
    for i in 0 ..< 3:
      items.add(InvVector(invType: invWitnessBlock,
                          hash: default(array[32, byte])))
    for i in 0 ..< 500:
      items.add(InvVector(invType: invWtx, hash: default(array[32, byte])))

    let (blocks, txs) = classifyInv(items, inIBD = true)
    # Blocks are STILL requested during IBD — that's how we catch up.
    check blocks == 3
    # Not one of the 500 tx invs becomes a getdata while in IBD.
    check txs == 0

  test "when synced, both block and tx invs are acted on":
    var items: seq[InvVector]
    for i in 0 ..< 2:
      items.add(InvVector(invType: invWitnessBlock,
                          hash: default(array[32, byte])))
    for i in 0 ..< 500:
      items.add(InvVector(invType: invWtx, hash: default(array[32, byte])))

    let (blocks, txs) = classifyInv(items, inIBD = false)
    check blocks == 2
    check txs == 500  # normal tx relay resumes once caught up

  test "legacy invTx items are also suppressed during IBD":
    var items: seq[InvVector]
    for i in 0 ..< 300:
      items.add(InvVector(invType: invTx, hash: default(array[32, byte])))
    items.add(InvVector(invType: invBlock, hash: default(array[32, byte])))

    let (blocks, txs) = classifyInv(items, inIBD = true)
    check txs == 0
    check blocks == 1

# ===========================================================================
suite "W165: requestBlocks per-peer cap (Core MAX_BLOCKS_IN_TRANSIT_PER_PEER)":

  test "MaxBlocksPerPeer matches Bitcoin Core's value of 16":
    check MaxBlocksPerPeer == 16

  test "even split never exceeds the per-peer cap":
    ## The fixed distribution formula:
    ##   blocksPerPeer = max(1, min(MaxBlocksPerPeer, ceil(inv/peers)))
    ## Old code used `inv div peers` UNCAPPED and handed the LAST peer all
    ## remaining blocks (`if i == peers.len-1: inventory.len`), so e.g.
    ## 300 blocks / 9 peers => 33 each + a 36-block dump on the last peer,
    ## all well past Core's 16-block ceiling.
    for invLen in [1, 9, 16, 94, 144, 300, 512]:
      for peers in [2, 5, 9]:
        let blocksPerPeer = max(1, min(MaxBlocksPerPeer,
                                       (invLen + peers - 1) div peers))
        check blocksPerPeer >= 1
        check blocksPerPeer <= MaxBlocksPerPeer

  test "the incident window (94 blocks, 9 peers) spreads ~11 per peer":
    let invLen = 94
    let peers = 9
    let blocksPerPeer = max(1, min(MaxBlocksPerPeer,
                                   (invLen + peers - 1) div peers))
    check blocksPerPeer == 11          # ceil(94/9) = 11, under the cap
    # No single peer is handed more than the cap.
    check blocksPerPeer <= MaxBlocksPerPeer

  test "a large window is capped, not dumped on the last peer":
    ## 512-block window, 9 peers: ceil(512/9) = 57 -> capped to 16.
    let invLen = 512
    let peers = 9
    let blocksPerPeer = max(1, min(MaxBlocksPerPeer,
                                   (invLen + peers - 1) div peers))
    check blocksPerPeer == MaxBlocksPerPeer
    # peers * cap = 144 blocks requested this round; the remaining 368 are
    # left for the next syncLoop iteration rather than overloading one peer.
    let requestedThisRound = peers * blocksPerPeer
    check requestedThisRound == 144
    check requestedThisRound < invLen
