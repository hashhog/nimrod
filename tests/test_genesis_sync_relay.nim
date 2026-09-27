## Genesis-sync block relay (2026-09-26, QUEUES "tools / operator" item 0).
##
## Regtest harness: Core A and Core B each connect ONLY to nimrod; A mines
## 101 blocks; B must follow. On nimrod 835a197 B stayed at 0 in every phase,
## and nimrod itself stayed at 0 while A was at 101:
##
##   1. a block `inv` from a peer that is not the header-sync peer was
##      answered with getdata for the BODY; the header was unknown, so the
##      body could not connect and was dropped. Headers were only ever asked
##      of the single polled sync peer (Core B), which had nothing.
##      Core (net_processing.cpp:4051-4122): inv -> getheaders to the
##      ANNOUNCING peer; bodies only from peers known to have them
##      (FindNextBlocksToDownload up to pindexBestKnownBlock).
##   2. genesis IBD stored no bodies while advertising NODE_NETWORK, so the
##      blocks nimrod had validated were notfound for Core B.
##   3. NODE_NETWORK was advertised unconditionally — also by pruned and
##      snapshot-bootstrapped datadirs (Core init.cpp:1947-1952).
##
##   nim c -r tests/test_genesis_sync_relay.nim

import unittest2
import std/[options, os, tables]
import chronos
import ../src/network/sync
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/[params, validation, chain]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const EASY_BITS = 0x207fffff'u32
const BaseTs = 1_700_000_000'u32

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

proc buildDatadir(path: string, p: ConsensusParams,
                  count: int): tuple[cs: ChainState, blks: seq[Block]] =
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  doAssert cs.connectBlock(genesis, 0'i32).isOk
  var blks: seq[Block] = @[genesis]
  var prevHash = p.genesisBlockHash
  var ts = BaseTs
  for h in 1'i32 .. int32(count):
    let blk = mineBlock(prevHash, h, ts)
    doAssert cs.connectBlock(blk, h).isOk
    prevHash = hashOf(blk.header)
    blks.add(blk)
    ts += 600
  result = (cs, blks)

proc mineOnTop(tip: Block, fromHeight: int32, count: int): seq[Block] =
  var prevHash = hashOf(tip.header)
  var ts = tip.header.timestamp + 600
  for i in 0 ..< count:
    let blk = mineBlock(prevHash, fromHeight + int32(i), ts)
    result.add(blk)
    prevHash = hashOf(blk.header)
    ts += 600

proc headersOf(blks: seq[Block]): seq[BlockHeader] =
  for b in blks:
    result.add(b.header)

proc witnessPeer(port: uint16, startHeight: int32 = 0): Peer =
  ## Unconnected peer: a getheaders to it is recorded (lastGetHeadersMs is
  ## stamped before the send) and the send then fails harmlessly.
  result = newPeer("127.0.0.1", port, regtestParams(), pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.startHeight = startHeight

# ===========================================================================
suite "block inv from ANY peer -> getheaders to that peer (headers-first)":

  test "inv for an unknown block asks the ANNOUNCING peer for headers":
    let p = regtestParams()
    let path = "/tmp/nimrod_gsr_inv_unknown"
    let (cs, blks) = buildDatadir(path, p, 5)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let syncPeer = witnessPeer(1001)
    let announcer = witnessPeer(1002)
    sm.syncPeer = syncPeer

    let ahead = mineOnTop(blks[5], 6'i32, 3)
    waitFor sm.handleBlockAnnouncement(announcer, @[hashOf(ahead[^1].header)])
    # PRE-FIX: nimrod.nim sent getdata(body) and never getheaders.
    check announcer.lastGetHeadersMs != 0
    check syncPeer.lastGetHeadersMs == 0

  test "inv for a known header records availability and sends nothing":
    let p = regtestParams()
    let path = "/tmp/nimrod_gsr_inv_known"
    let (cs, blks) = buildDatadir(path, p, 5)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let announcer = witnessPeer(1003)
    waitFor sm.handleBlockAnnouncement(announcer, @[hashOf(blks[4].header)])
    check announcer.bestKnownHeight == 4
    check announcer.lastGetHeadersMs == 0

  test "one getheaders in flight per peer; a headers reply re-arms it":
    let p = regtestParams()
    let path = "/tmp/nimrod_gsr_inflight"
    let (cs, blks) = buildDatadir(path, p, 5)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let announcer = witnessPeer(1004)
    sm.syncPeer = announcer          # fSyncStarted with this peer
    let ahead = mineOnTop(blks[5], 6'i32, 4)

    waitFor sm.handleBlockAnnouncement(announcer, @[hashOf(ahead[0].header)])
    let first = announcer.lastGetHeadersMs
    check first != 0
    waitFor sm.handleBlockAnnouncement(announcer, @[hashOf(ahead[1].header)])
    check announcer.lastGetHeadersMs == first      # still in flight: no resend

    # The reply: headers extend our chain and mark the peer as having them.
    waitFor sm.handleHeaders(announcer, headersOf(ahead[0 .. 1]))
    check announcer.lastGetHeadersMs == 0
    check announcer.bestKnownHeight == 7
    check sm.headerChain.tipHeight == 7

    waitFor sm.handleBlockAnnouncement(announcer, @[hashOf(ahead[3].header)])
    check announcer.lastGetHeadersMs != 0

  test "far from tip: one new peer per new block (Core 4109-4121)":
    let prior = BlockHash(default(array[32, byte]))
    var h1: array[32, byte]
    h1[0] = 1
    var h2: array[32, byte]
    h2[0] = 2
    # sync peer / recent tip: always
    check invShouldTriggerGetHeaders(true, false, true, BlockHash(h1), BlockHash(h1))
    check invShouldTriggerGetHeaders(false, true, true, BlockHash(h1), BlockHash(h1))
    # far from tip, other peer: once per peer, and not for the same block
    check invShouldTriggerGetHeaders(false, false, false, BlockHash(h1), prior)
    check not invShouldTriggerGetHeaders(false, false, true, BlockHash(h2), BlockHash(h1))
    check not invShouldTriggerGetHeaders(false, false, false, BlockHash(h1), BlockHash(h1))

  test "HEADERS_RESPONSE_TIME gate":
    check getHeadersRequestAllowed(0, 1_000)
    check not getHeadersRequestAllowed(1_000, 1_000 + HeadersResponseTimeMs)
    check getHeadersRequestAllowed(1_000, 1_001 + HeadersResponseTimeMs)

# ===========================================================================
suite "bodies are requested only from peers that have them":

  test "fetch peer is the one with the chain, not the idle sync peer":
    let syncPeer = witnessPeer(2001)          # knows nothing past genesis
    let announcer = witnessPeer(2002)
    announcer.noteBestKnownHeight(101)
    check selectFetchPeer(syncPeer, @[syncPeer, announcer]) == announcer
    # tie -> keep the sync peer (pre-fix choice)
    syncPeer.noteBestKnownHeight(101)
    check selectFetchPeer(syncPeer, @[announcer, syncPeer]) == syncPeer

  test "version start height still counts (multi-peer IBD keeps all peers)":
    let a = witnessPeer(2003, startHeight = 500)
    let b = witnessPeer(2004)
    check a.availableHeight() == 500
    check selectFetchPeer(b, @[a, b]) == a

  test "assignment skips peers without the block and stops at the first gap":
    let low = witnessPeer(2005)
    low.noteBestKnownHeight(3)
    let high = witnessPeer(2006)
    high.noteBestKnownHeight(10)
    let none0 = witnessPeer(2007)
    let a = assignBlocksToPeers(@[1'i32, 2, 3, 4, 5, 11], @[none0, low, high], 16)
    check a.len == 5                  # height 11: nobody has it
    for k in 0 ..< a.len:
      check a[k] != 0                 # never the peer that has nothing
    check a[3] == 2 and a[4] == 2     # 4, 5 only on `high`
    # per-peer cap
    let c = assignBlocksToPeers(@[1'i32, 2, 3], @[high], 2)
    check c.len == 2
    # fork bodies (-1) may go to any peer
    check assignBlocksToPeers(@[-1'i32], @[none0], 16) == @[0]

# ===========================================================================
suite "NODE_NETWORK only when every body is served":

  setup:
    delEnv("NIMROD_PEER_BLOCK_FILTERS")
    delEnv("NIMROD_BLOCK_FILTER_INDEX")
    setPruneModeAdvertise(false)
    setFullHistoryAdvertise(true)

  teardown:
    setPruneModeAdvertise(false)
    setFullHistoryAdvertise(true)

  test "pruned node drops NODE_NETWORK, keeps NODE_NETWORK_LIMITED":
    setPruneModeAdvertise(true)
    # PRE-FIX: 0xC09 regardless of prune (NODE_NETWORK always set).
    check (advertisedServices() and NodeNetwork) == 0
    check (advertisedServices() and NodeNetworkLimited) != 0
    check (advertisedServices() and NodeWitness) != 0

  test "snapshot / bodiless datadir drops NODE_NETWORK":
    setFullHistoryAdvertise(false)
    check (advertisedServices() and NodeNetwork) == 0
    check (advertisedServices() and NodeNetworkLimited) != 0
    check not servesFullHistory()

  test "archive node keeps 0xC09":
    check advertisedServices() == 0xC09'u64
    check servesFullHistory()
