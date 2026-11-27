## cffix-nimrod-tip-extend-min-chainwork: a tip-extending headers batch must
## clear the minimumChainWork anti-DoS gate like any other batch.
##
## Finding (fingerprint
## nimrod/sync/classifyHeaderBatch-tip-extend-bypasses-min-chainwork):
## classifyHeaderBatch returned hbrDirect for `firstPrev == headerChain.tip and
## tipHeight > 0` BEFORE comparing chain_start work + claimed work against
## GetAntiDoSWorkThreshold(), and handleHeaders then set minPowChecked=true, so
## validateHeader's too-little-chainwork gate never ran. tryLowWorkHeadersSync
## had the same unconditional tip exemption for an incomplete (<2000) message.
## While the header chain is below minimumChainWork (REDOWNLOAD releasing
## headers, restart mid-IBD) any peer could extend the tip with cheap headers
## that were stored in RAM and as two RocksDB rows each.
##
## Bitcoin Core: ProcessHeadersMessage -> TryLowWorkHeadersSync compares
## chain_start->nChainWork + CalculateClaimedHeadersWork(headers) against
## GetAntiDoSWorkThreshold() (net_processing.cpp:2633); there is no tip
## shortcut. A low-work message that is not full is ignored.
##
## The 967057 livelock fix (test_header_sync_from_tip.nim) must survive: when
## the cached headerChain.totalWork is wrong (zero) but the chain really has
## the work, a tip-extend still routes direct. The controls below cover that.
##
## Command:
##   nim c -r tests/test_cffix_tip_extend_min_chainwork.nim

import unittest2
import std/[os, tables, options]
import chronos
import ../src/network/sync
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/headerssync
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mineHeader(prev: BlockHash, ts: uint32): BlockHeader =
  result = BlockHeader(
    version: 1,
    prevBlock: prev,
    merkleRoot: default(array[32, byte]),
    timestamp: ts,
    bits: 0x207fffff'u32,
    nonce: 0
  )
  while not validateHeaderPoW(result):
    result.nonce += 1

proc mineChain(startHash: BlockHash, startTime: uint32,
               count: int): seq[BlockHeader] =
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    let hdr = mineHeader(prev, ts)
    result.add(hdr)
    prev = hashOf(hdr)

proc readyPeer(address: string, port: uint16, params: ConsensusParams,
               startHeight: int32): Peer =
  result = newPeer(address, port, params, pdOutbound)
  result.state = psReady
  result.handshakeComplete = true
  result.startHeight = startHeight
  result.bestKnownHeight = startHeight

proc peerKeyOf(p: Peer): string =
  p.address & ":" & $p.port

proc buildDenseDb(path: string, params: ConsensusParams,
                  count: int): tuple[cdb: ChainDb, headers: seq[BlockHeader]] =
  removeDir(path)
  let cdb = openChainDb(path)
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  let headers = mineChain(genesisHash, genesis.header.timestamp, count)
  var cumWork = calculateWork(genesis.header.bits)
  var prevHash = genesisHash
  for i, hdr in headers:
    let h = hashOf(hdr)
    cumWork = addWork(cumWork, calculateWork(hdr.bits))
    cdb.putBlockIndex(BlockIndex(
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
    ))
    prevHash = h
  cdb.bestHeight = int32(count)
  cdb.bestBlockHash = prevHash
  result = (cdb, headers)

proc chainProofSum(sm: SyncManager): UInt256 =
  ## Core's chain_start->nChainWork for the tip: GetBlockProof summed from
  ## genesis through the tip.
  result = initUInt256()
  for i in 0 .. int(sm.headerChain.tipHeight):
    result = result + getBlockProof(sm.headerChain.headers[i])

template withDenseChain(name: string, count: int, body: untyped) =
  let params {.inject.} = regtestParams()
  let path = getTempDir() / ("nimrod_cffix_tip_extend_" & name & "_" &
                             $getCurrentProcessId())
  let built = buildDenseDb(path, params, count)
  let cdb {.inject.} = built.cdb
  let headers {.inject.} = built.headers
  defer:
    var c = cdb
    c.close()
    removeDir(path)
  let pm = newPeerManager(params, 8, 2, 117, path / "pm")
  let peer {.inject.} = readyPeer("127.0.0.1", 8333, params, int32(count + 5))
  pm.peers[peerKeyOf(peer)] = peer
  let sm {.inject.} = newSyncManager(pm, cdb, params)
  body

suite "cffix tip-extend min chainwork: tip-extending headers clear the minimumChainWork gate":

  test "classifyHeaderBatch routes a 1-header tip-extend below minimumChainWork to hbrAntiDoS":
    withDenseChain("classify", 5):
      check sm.headerChain.tipHeight == 5
      let tip = sm.headerChain.tip
      let proof = getBlockProof(headers[0])
      # The whole chain (6 proofs) plus the new header (1 proof) is far below.
      sm.minimumChainWork = proof * 1000'u64
      check initUInt256(sm.headerChain.totalWork) < sm.minimumChainWork
      let one = mineChain(tip, headers[^1].timestamp, 1)
      let cls = sm.classifyHeaderBatch(one)
      check cls.routing == hbrAntiDoS
      check cls.connectHash == tip
      check cls.connectHeight == 5

  test "handleHeaders does not store a low-work tip-extend (tip, index, DB unchanged)":
    withDenseChain("handle", 5):
      let tip = sm.headerChain.tip
      sm.minimumChainWork = getBlockProof(headers[0]) * 1000'u64
      let one = mineChain(tip, headers[^1].timestamp, 1)
      let newHash = hashOf(one[0])
      waitFor sm.handleHeaders(peer, one)
      check sm.headerChain.tipHeight == 5
      check sm.headerChain.tip == tip
      check newHash notin sm.headerChain.byHash
      check newHash notin sm.headerChain.sideHeaders
      check cdb.getBlockIndex(newHash).isNone
      check cdb.getBlockHashByHeight(6).isNone
      # Core ignores a non-full low-work message: no PRESYNC state either.
      check sm.peerHeadersSync.len == 0

  test "tryLowWorkHeadersSync drops an incomplete low-work tip-extend":
    withDenseChain("trylow", 5):
      let tip = sm.headerChain.tip
      sm.minimumChainWork = getBlockProof(headers[0]) * 1000'u64
      var batch = mineChain(tip, headers[^1].timestamp, 3)
      let handled = sm.tryLowWorkHeadersSync(peer, 5'i32, tip,
                                             headers[^1].bits,
                                             sm.chainProofSum(), batch)
      check handled
      check batch.len == 0

  test "a full 2000-header low-work tip-extend enters PRESYNC instead of being stored":
    withDenseChain("presync", 5):
      let tip = sm.headerChain.tip
      sm.minimumChainWork = getBlockProof(headers[0]) * 100_000'u64
      let full = mineChain(tip, headers[^1].timestamp, 2000)
      check sm.classifyHeaderBatch(full).routing == hbrAntiDoS
      try:
        waitFor sm.handleHeaders(peer, full)
      except CatchableError:
        discard # the follow-up getheaders has no socket to go out on
      check sm.headerChain.tipHeight == 5
      check sm.headerChain.tip == tip
      check hashOf(full[0]) notin sm.headerChain.byHash
      check cdb.getBlockHashByHeight(6).isNone
      # Core TryLowWorkHeadersSync: a full low-work message starts a
      # HeadersSyncState anchored at chain_start (our tip).
      check sm.peerHeadersSync.len == 1

  test "snapshot-grafted chain: persisted index work below minimum still gates the tip-extend":
    withDenseChain("graft_low", 5):
      # Holes below the tip (byHash shorter than headers): the dense proof sum
      # is unavailable, so the persisted index row's work is the connect work.
      for i in 1 .. 3:
        sm.headerChain.byHash.del(sm.headerChain.hashes[i])
      sm.headerChain.totalWork = default(array[32, byte])
      let tip = sm.headerChain.tip
      sm.minimumChainWork = getBlockProof(headers[0]) * 1000'u64
      let one = mineChain(tip, headers[^1].timestamp, 1)
      check sm.classifyHeaderBatch(one).routing == hbrAntiDoS

  test "restart mid-IBD below minimum: an honest enough-work chain from the tip completes PRESYNC+REDOWNLOAD and is stored":
    ## The fix sends a below-minimum chain's tip-extends through PRESYNC
    ## anchored at the tip (Core's chain_start), where the old shortcut
    ## stored them directly. An honest peer whose chain does reach the
    ## minimum must still get its headers accepted from a non-genesis
    ## chain_start, or a node restarted mid-IBD would livelock. (Master
    ## fails the PRESYNC-phase checks: it stores the first message directly.)
    withDenseChain("ctl_presync_e2e", 5):
      let tip = sm.headerChain.tip
      # 6 (chain) + 2000 (first message) proofs < 2300 <= 6 + 2500 (whole
      # peer chain): the first message alone is low work, the chain is not.
      sm.minimumChainWork = getBlockProof(headers[0]) * 2300'u64
      let peerChain = mineChain(tip, headers[^1].timestamp, 2500)
      proc feed(batch: seq[BlockHeader]) =
        try:
          waitFor sm.handleHeaders(peer, batch)
        except CatchableError:
          discard # follow-up getheaders has no socket to go out on
      # PRESYNC: two messages (full + final partial) carry the commitments.
      feed(peerChain[0 ..< 2000])
      check sm.headerChain.tipHeight == 5
      check sm.peerHeadersSync.len == 1
      feed(peerChain[2000 ..< 2500])
      check sm.headerChain.tipHeight == 5
      # REDOWNLOAD: the peer re-sends the chain from chain_start (our tip).
      feed(peerChain[0 ..< 2000])
      feed(peerChain[2000 ..< 2500])
      check sm.headerChain.tipHeight == 2505
      check sm.headerChain.tip == hashOf(peerChain[^1])
      check cdb.getBlockHashByHeight(2505).isSome

  test "restart mid-IBD below minimum with a zeroed totalWork cache: PRESYNC starts from the tip's real chain work":
    ## Core seeds HeadersSyncState with chain_start->nChainWork. If PRESYNC
    ## were seeded from the (zeroed) cache instead, an honest peer whose
    ## chain clears the minimum only together with ours would fail PRESYNC
    ## on every attempt (the 967057 cache fault turned into a livelock).
    withDenseChain("ctl_presync_zero_cache", 5):
      let tip = sm.headerChain.tip
      # peer chain alone: 2500 proofs < 2503 <= 6 + 2500 (ours + peer's).
      sm.minimumChainWork = getBlockProof(headers[0]) * 2503'u64
      sm.headerChain.totalWork = default(array[32, byte])
      let peerChain = mineChain(tip, headers[^1].timestamp, 2500)
      let cls = sm.classifyHeaderBatch(peerChain[0 ..< 2000])
      check cls.routing == hbrAntiDoS
      check cls.connectWork == sm.chainProofSum()
      proc feed(batch: seq[BlockHeader]) =
        try:
          waitFor sm.handleHeaders(peer, batch)
        except CatchableError:
          discard # follow-up getheaders has no socket to go out on
      feed(peerChain[0 ..< 2000])
      check sm.headerChain.tipHeight == 5
      check sm.peerHeadersSync.len == 1
      feed(peerChain[2000 ..< 2500])
      check sm.headerChain.tipHeight == 5
      feed(peerChain[0 ..< 2000])
      feed(peerChain[2000 ..< 2500])
      check sm.headerChain.tipHeight == 2505
      check sm.headerChain.tip == hashOf(peerChain[^1])

  test "boundary: chain + claimed work == minimum routes direct, minimum + 1 does not":
    withDenseChain("ctl_boundary", 5):
      let tip = sm.headerChain.tip
      sm.headerChain.totalWork = default(array[32, byte])
      let one = mineChain(tip, headers[^1].timestamp, 1)
      let exact = sm.chainProofSum() + getBlockProof(one[0])
      sm.minimumChainWork = exact
      check sm.classifyHeaderBatch(one).routing == hbrDirect
      sm.minimumChainWork = exact + initUInt256(1'u64)
      check sm.classifyHeaderBatch(one).routing == hbrAntiDoS

  # ---- negative controls: the 967057 livelock fix must keep working ----

  test "control: chain work >= minimum, zeroed totalWork cache, tip-extend routes direct and is stored":
    withDenseChain("ctl_direct", 5):
      let tip = sm.headerChain.tip
      # Real chain work (6 proofs) clears a minimum of 4 proofs; the cached
      # totalWork is zeroed exactly as in the 967057 livelock.
      sm.minimumChainWork = getBlockProof(headers[0]) * 4'u64
      sm.headerChain.totalWork = default(array[32, byte])
      let one = mineChain(tip, headers[^1].timestamp, 1)
      check sm.classifyHeaderBatch(one).routing == hbrDirect
      var copy = one
      check not sm.tryLowWorkHeadersSync(peer, 5'i32, tip, headers[^1].bits,
                                         initUInt256(), copy)
      waitFor sm.handleHeaders(peer, one)
      check sm.headerChain.tipHeight == 6
      check sm.headerChain.tip == hashOf(one[0])

  test "control: snapshot-grafted chain whose persisted index work meets the minimum routes direct":
    withDenseChain("graft_ok", 5):
      for i in 1 .. 3:
        sm.headerChain.byHash.del(sm.headerChain.hashes[i])
      sm.headerChain.totalWork = default(array[32, byte])
      let tip = sm.headerChain.tip
      sm.minimumChainWork = getBlockProof(headers[0]) * 4'u64
      let one = mineChain(tip, headers[^1].timestamp, 1)
      check sm.classifyHeaderBatch(one).routing == hbrDirect

  test "control: minimumChainWork zero (regtest) keeps every tip-extend direct":
    withDenseChain("ctl_regtest", 5):
      check sm.minimumChainWork.isZero()
      sm.headerChain.totalWork = default(array[32, byte])
      let one = mineChain(sm.headerChain.tip, headers[^1].timestamp, 1)
      check sm.classifyHeaderBatch(one).routing == hbrDirect
      waitFor sm.handleHeaders(peer, one)
      check sm.headerChain.tipHeight == 6

