## Fork-download stall (gate 7, mainnet 2026-10-04, natural fork at 969888).
##
## nimrod held the winning 969888 but could not get 969889..969894 for 35+
## min: one getdata per new block, every one to the same outbound peer, none
## delivered, none re-asked. That peer had advertised start height 975538
## (real tip 969894), its chain stopped near 955k, and it answered every
## getheaders with the same 2000 already-known headers from 953496.
##
##   1. selectFetchPeer ranked peers by availableHeight = max(version start
##      height, announced height), so the unverified 975538 claim beat every
##      honest peer that had announced 969889. Core asks a peer only for
##      blocks up to its pindexBestKnownBlock, learned from inv/headers
##      (net_processing.cpp:1406, :1456).
##   2. requestedHashes had no owner and no age. The only release was the
##      60 s global sync timeout, which every directly-processed headers
##      message re-arms. Core: BLOCK_DOWNLOAD_TIMEOUT_BASE/PER_PEER
##      (net_processing.cpp:148-150, :6110-6120) disconnects the peer and its
##      blocks are fetched elsewhere.
##   3. After a FULL headers message nimrod re-sent its own tip locator, so a
##      peer whose answer starts below our tip repeated it forever. Core sends
##      GetLocator(pindexLast) (net_processing.cpp:3104-3109).
##   4. Headers already held as ancestors of the best header were sent through
##      PRESYNC on a dense chain. Core skips anti-DoS for them
##      (net_processing.cpp:3043-3052).
##
## Every test below FAILS on 1408e8e (the deployed commit).
##
##   nim c -r tests/test_fork_download_stall.nim

import unittest2
import std/[options, os, sets, tables, times]
import chronos except Duration, Moment
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
  ## count < 150: every coinbase pays the full regtest subsidy.
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

proc witnessPeer(port: uint16, startHeight: int32 = 0): Peer =
  result = newPeer("127.0.0.1", port, regtestParams(), pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.startHeight = startHeight
  result.state = psReady

proc fakeHash(b: byte): BlockHash =
  var a: array[32, byte]
  a[0] = b
  a[31] = 0x5a
  BlockHash(a)

# ===========================================================================
suite "a block is asked of a peer that announced it, not of a height claim":

  test "liar's version height loses to an honest announcer (mainnet replay)":
    # 1408e8e: selectFetchPeer(liar, @[liar, honest]) == liar.
    let liar = witnessPeer(3001, startHeight = 975538)
    liar.noteBestKnownHeight(955496)      # the headers it actually sent
    let honest = witnessPeer(3002, startHeight = 969880)
    honest.noteBestKnownHeight(969889)    # announced the new block
    check selectFetchPeer(liar, @[liar, honest], 969889) == honest
    check selectFetchPeer(liar, @[honest, liar], 969889) == honest

  test "no announcer yet -> the start-height fallback still works (IBD)":
    let a = witnessPeer(3003, startHeight = 500)
    let b = witnessPeer(3004)
    check selectFetchPeer(b, @[a, b], 1) == a

  test "a short headers answer caps the version-height claim":
    let liar = witnessPeer(3005, startHeight = 975538)
    check liar.availableHeight() == 975538
    liar.noteHeadersTip(955496)
    check liar.availableHeight() == 955496
    liar.noteBestKnownHeight(969889)      # later real announcements still count
    check liar.availableHeight() == 969889

  test "handleHeaders records the peer's tip from a short batch":
    let p = regtestParams()
    let path = "/tmp/nimrod_fds_short"
    let (cs, blks) = buildDatadir(path, p, 30)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let liar = witnessPeer(3006, startHeight = 6030)
    var hdrs: seq[BlockHeader]
    for i in 1 .. 12:
      hdrs.add(blks[i].header)
    waitFor sm.handleHeaders(liar, hdrs)
    # Its chain ends at 12 by its own account: no longer a candidate for 31.
    check liar.availableHeight() == 12

# ===========================================================================
suite "header continuation and already-known headers (Core ProcessHeadersMessage)":

  test "the getheaders after a full batch starts at the LAST header sent":
    let p = regtestParams()
    let path = "/tmp/nimrod_fds_cont"
    let (cs, blks) = buildDatadir(path, p, 40)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let last = hashOf(blks[12].header)
    let loc = sm.continuationLocator(last)
    check BlockHash(loc[0]) == last
    check BlockHash(loc[^1]) == p.genesisBlockHash
    # our own tip locator starts at 40, which is what 1408e8e re-sent
    check BlockHash(sm.buildBlockLocator()[0]) == hashOf(blks[40].header)
    # an unknown last header is put in front of our locator
    let unk = fakeHash(7)
    let loc2 = sm.continuationLocator(unk)
    check BlockHash(loc2[0]) == unk
    check BlockHash(loc2[1]) == hashOf(blks[40].header)

  test "headers we already hold below the tip skip PRESYNC":
    let p = regtestParams()
    let path = "/tmp/nimrod_fds_known"
    let (cs, blks) = buildDatadir(path, p, 149)
    defer:
      var c = cs
      c.close()
      removeDir(path)
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    var hdrs: seq[BlockHeader]
    for i in 1 .. 3:
      hdrs.add(blks[i].header)
    # 1408e8e: hbrAntiDoS (total work of 4 blocks < tip - 144 blocks).
    check sm.classifyHeaderBatch(hdrs).routing == hbrDirect

# ===========================================================================
suite "block download timeout (Core BLOCK_DOWNLOAD_TIMEOUT_BASE/PER_PEER)":
  # regtest nPowTargetSpacing is 600 s too; the harness-only override is off.
  var csKeep: ChainState
  var smPath = ""
  var smN = 0

  proc mkSm(): SyncManager =
    inc smN
    smPath = "/tmp/nimrod_fds_to_" & $smN
    let (cs, _) = buildDatadir(smPath, regtestParams(), 1)
    csKeep = cs
    var csv = cs
    newSyncManager(nil, csv.db, regtestParams(), csv)

  setup:
    delEnv("NIMROD_BLOCK_DOWNLOAD_TIMEOUT_SECS")

  teardown:
    if smPath.len > 0:
      csKeep.close()
      removeDir(smPath)
      smPath = ""

  test "timeout is nPowTargetSpacing * (1 + 0.5 * other downloading peers)":
    let sm = mkSm()
    check sm.blockDownloadTimeoutSecs(0) == 600
    check sm.blockDownloadTimeoutSecs(2) == 1200

  test "a block the peer never delivers is released and re-assignable":
    let sm = mkSm()
    let mute = witnessPeer(3010)
    let honest = witnessPeer(3011)
    honest.noteBestKnownHeight(101)
    mute.noteBestKnownHeight(101)
    let h = fakeHash(1)
    let t0 = getTime()
    sm.requestedHashes.incl(h)
    sm.pendingBlocks = 1
    sm.noteBlockRequested(h, mute, t0)
    # inside the window: nothing happens
    check sm.expireBlockRequests(t0 + initDuration(seconds = 599)) == 0
    check h in sm.requestedHashes
    # past it: released, the staller is dropped and never asked again
    check sm.expireBlockRequests(t0 + initDuration(seconds = 601)) == 1
    check h notin sm.requestedHashes
    check sm.pendingBlocks == 0
    check mute.shouldDisconnect
    check not sm.peerCanFetch(mute)
    check sm.peerCanFetch(honest)

  test "a disconnected peer's requests are released at once (FinalizeNode)":
    let sm = mkSm()
    let gone = witnessPeer(3012)
    let h = fakeHash(2)
    sm.requestedHashes.incl(h)
    sm.pendingBlocks = 1
    sm.noteBlockRequested(h, gone, getTime())
    gone.state = psDisconnected
    check sm.expireBlockRequests(getTime()) == 1
    check h notin sm.requestedHashes

  test "only delivering the OLDEST block restarts a peer's clock":
    let sm = mkSm()
    let p = witnessPeer(3013)
    let (a, b, c) = (fakeHash(3), fakeHash(4), fakeHash(5))
    let t0 = getTime()
    for (hh, dt) in [(a, 0), (b, 10), (c, 20)]:
      sm.requestedHashes.incl(hh)
      sm.pendingBlocks += 1
      sm.noteBlockRequested(hh, p, t0 + initDuration(seconds = dt))
    # serving a later block while withholding the front one does not help
    sm.requestedHashes.excl(c)
    sm.noteBlockDelivered(c, p, t0 + initDuration(seconds = 500))
    check sm.expireBlockRequests(t0 + initDuration(seconds = 601)) == 2
    check p.shouldDisconnect
    # the front block arriving restarts the clock for the rest
    csKeep.close()
    removeDir(smPath)
    let sm2 = mkSm()
    let q = witnessPeer(3014)
    for (hh, dt) in [(a, 0), (b, 10)]:
      sm2.requestedHashes.incl(hh)
      sm2.pendingBlocks += 1
      sm2.noteBlockRequested(hh, q, t0 + initDuration(seconds = dt))
    sm2.requestedHashes.excl(a)
    sm2.noteBlockDelivered(a, q, t0 + initDuration(seconds = 500))
    check sm2.expireBlockRequests(t0 + initDuration(seconds = 601)) == 0
    check sm2.expireBlockRequests(t0 + initDuration(seconds = 1101)) == 1
