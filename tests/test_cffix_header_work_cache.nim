## cffix-nimrod-header-work-cache — the work at an active ancestor is READ,
## not recomputed from genesis, for every incoming header.
##
## Finding (nimrod/sync/header-work-recomputed-from-genesis-per-message): for a
## `headers` message whose first header's parent is an active header BELOW the
## tip, `classifyHeaderBatch` summed `getBlockProof` over heights 0..connectIdx,
## and `acceptForkHeader` -> `resolveParentWork` then summed `calculateWork`
## (repeated-subtraction 256-bit division) over 0..idx again. Both ran before
## the bad-diffbits gate. One difficulty-1 header off tip-1 is reusable from
## any IP and cost two O(chain height) passes of 256-bit arithmetic on the
## event loop (mainnet: ~978k headers per pass), per message.
##
## Bitcoin Core reads pindexPrev->nChainWork in O(1) (CBlockIndex::nChainWork,
## set once in AddToBlockIndex), and ContextualCheckBlockHeader's bad-diffbits
## check runs before any work is summed.
##
## How the tests see it:
##   * `headerWorkEvals` (added by the fix) counts per-header work
##     evaluations. Its use is guarded with `when declared`, so this file
##     compiles on master.
##   * The SENTINEL works on master too: after the chain is built, the bits of
##     the header at height 1 are overwritten in place. A lookup that re-sums
##     from genesis returns a different number; a lookup that reads the
##     recorded cumulative work does not. That is the master-fails-by-name
##     discriminator, and also a negative control on the counter (if the
##     counter were dead, the sentinel would still catch a re-sum).
##   * Negative control: prev = tip was already O(1) on master (it reads
##     `totalWork`), so its sentinel check passes on both.
##   * Equivalence: across truncation, side-branch promotion, re-extension and
##     reload from the block index, every cached answer equals the cold sum.
##     The cache holds exactly what master's walk returned, never a stored
##     row's totalWork: rows written before 0be5041 can be quantised LOW, and
##     reading them would send a batch off tip-1 into PRESYNC (tested). On a
##     snapshot-grafted reload the cache equals the grafted-chain walk.
##
## CONTROL: nim c -r tests/test_cffix_header_work_cache.nim

import unittest2
import std/[tables, options, os]
import ../src/network/sync
import ../src/network/headerssync
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/storage/undo
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const PowLimitBits = 0x207fffff'u32   ## regtest powLimit: ~every nonce passes
const HardBits = 0x207ffffe'u32       ## one mantissa step harder, still minable
const T0 = 1_700_000_000'u32

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mineHeader(prev: BlockHash, ts: uint32, bits: uint32,
                salt: uint32 = 0): BlockHeader =
  var mr: array[32, byte]
  mr[0] = byte(salt and 0xFF)
  mr[1] = byte((salt shr 8) and 0xFF)
  mr[2] = byte((salt shr 16) and 0xFF)
  result = BlockHeader(version: 4, prevBlock: prev, merkleRoot: mr,
                       timestamp: ts, bits: bits, nonce: 0)
  while not validateHeaderPoW(result):
    result.nonce += 1

proc pushActive(hc: var HeaderChain, h: BlockHeader) =
  ## Extend the ACTIVE chain the way handleHeaders' accept arm does.
  let hash = hashOf(h)
  when declared(appendActiveHeader):
    hc.appendActiveHeader(h, hash, int32(hc.headers.len))
  else:
    let idx = hc.headers.len
    hc.headers.add(h)
    hc.hashes.add(hash)
    hc.byHash[hash] = idx
    hc.totalWork = addWork(hc.totalWork, calculateWork(h.bits))
    hc.tip = hash
    hc.tipHeight = int32(idx)

proc denseChain(n: int): HeaderChain =
  ## A genesis-rooted chain of `n` headers (heights 0..n-1), powLimit bits.
  let root = mineHeader(BlockHash(default(array[32, byte])), T0, PowLimitBits)
  result = initHeaderChain(root, hashOf(root))
  for i in 1 ..< n:
    let h = mineHeader(result.tip, T0 + uint32(i) * 600, PowLimitBits)
    result.pushActive(h)

proc coldWork(hc: HeaderChain, idx: int): array[32, byte] =
  ## The old full walk: cumulative work of heights 0..idx.
  for i in 0 .. idx:
    result = addWork(result, calculateWork(hc.headers[i].bits))

proc syncManagerOn(hc: HeaderChain, params: ConsensusParams): SyncManager =
  ## Header-admission state only; chainDb/chainState stay nil (every DB write
  ## on these paths is guarded by `sm.chainDb != nil`).
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
    unconnectingHeaders: initTable[int64, int]())

proc resetEvals() =
  when declared(headerWorkEvals):
    headerWorkEvals = 0

proc evals(): int =
  when declared(headerWorkEvals):
    headerWorkEvals
  else:
    -1

const SentinelBits = 0x1d00ffff'u32   ## mainnet difficulty-1: work ~2^32

proc plantSentinel(hc: var HeaderChain) =
  ## Change the work of height 1 in place (no cache update). At regtest
  ## difficulty every header is worth 2; 0x1d00ffff is worth ~2^32, so any
  ## re-sum from genesis now differs from the recorded value. (HardBits would
  ## not do: 0x207ffffe is also worth exactly 2.)
  doAssert calculateWork(SentinelBits) != calculateWork(PowLimitBits)
  hc.headers[1].bits = SentinelBits

suite "cffix header work cache: work at a non-tip active parent is O(1)":
  let params = regtestParams()
  const Sizes = [20_000, 40_000]
  var chains: seq[HeaderChain]
  for n in Sizes:
    chains.add denseChain(n)

  test "classifyHeaderBatch off tip-1 does not re-sum work from genesis":
    var counts: seq[int]
    for k, n in Sizes:
      let sm = syncManagerOn(chains[k], params)
      let hc = addr sm.headerChain
      let parentIdx = int(hc.tipHeight) - 1
      let fork = mineHeader(hc.hashes[parentIdx],
                            hc.headers[parentIdx].timestamp + 600,
                            PowLimitBits, salt = 1)
      let want = initUInt256(coldWork(hc[], parentIdx))
      resetEvals()
      let r = sm.classifyHeaderBatch(@[fork])
      counts.add evals()
      check r.connectHeight == int32(parentIdx)
      check r.connectWork == want
      # Sentinel: a re-sum from genesis would now see height 1's new bits.
      plantSentinel(hc[])
      let r2 = sm.classifyHeaderBatch(@[fork])
      check r2.connectWork == want
    when declared(headerWorkEvals):
      check counts[0] == counts[1]   # independent of chain height
      check counts[1] <= 2

  test "acceptForkHeader off tip-1 reads the parent's work in O(1)":
    var counts: seq[int]
    for k, n in Sizes:
      # syncManagerOn copies the chain, so the previous test's sentinel did
      # not touch chains[k].
      let sm = syncManagerOn(chains[k], params)
      let hc = addr sm.headerChain
      let parentIdx = int(hc.tipHeight) - 1
      let parentHash = hc.hashes[parentIdx]
      let want = coldWork(hc[], parentIdx)
      let pw = hc[].resolveParentWork(parentHash)
      check pw.isSome
      check pw.get().totalWork == want
      let fork = mineHeader(parentHash, hc.headers[parentIdx].timestamp + 600,
                            PowLimitBits, salt = 1)
      let fh = hashOf(fork)
      resetEvals()
      check sm.acceptForkHeader(fork, fh, minPowChecked = true) == fhoAccepted
      counts.add evals()
      check fh in hc.sideHeaders
      check hc.sideHeaders[fh].height == int32(parentIdx + 1)
      check hc.sideHeaders[fh].totalWork ==
        addWork(want, calculateWork(PowLimitBits))
      # Sentinel: a second fork header after height 1 changed in place.
      plantSentinel(hc[])
      let fork2 = mineHeader(parentHash, hc.headers[parentIdx].timestamp + 600,
                             PowLimitBits, salt = 2)
      check sm.acceptForkHeader(fork2, hashOf(fork2),
                                minPowChecked = true) == fhoAccepted
      check hc.sideHeaders[hashOf(fork2)].totalWork ==
        addWork(want, calculateWork(PowLimitBits))
      check hc[].resolveParentWork(parentHash).get().totalWork == want
    when declared(headerWorkEvals):
      check counts[0] == counts[1]   # independent of chain height
      check counts[1] <= 2           # the new header's own work, nothing more

  test "negative control: prev = tip is O(1) on master and head":
    for k, n in Sizes:
      let sm = syncManagerOn(denseChain(n), params)
      let hc = addr sm.headerChain
      let tipIdx = int(hc.tipHeight)
      let want = coldWork(hc[], tipIdx)
      plantSentinel(hc[])
      resetEvals()
      check hc[].resolveParentWork(hc.tip).get().totalWork == want
      let next = mineHeader(hc.tip, hc.headers[tipIdx].timestamp + 600,
                            PowLimitBits, salt = 3)
      check sm.classifyHeaderBatch(@[next]).connectWork == initUInt256(want)
      when declared(headerWorkEvals):
        check evals() <= 2

  test "a bad-diffbits fork header is refused before any parent-work lookup":
    ## Order only: the outcome is the same on master. The counter (head only)
    ## shows no work is evaluated for a header the diffbits gate refuses.
    let sm = syncManagerOn(denseChain(2_000), params)
    let hc = addr sm.headerChain
    let parentIdx = int(hc.tipHeight) - 1
    # Regtest requires the parent's bits (powNoRetargeting); HardBits differs.
    let bad = mineHeader(hc.hashes[parentIdx],
                         hc.headers[parentIdx].timestamp + 600, HardBits,
                         salt = 4)
    resetEvals()
    check sm.acceptForkHeader(bad, hashOf(bad),
                              minPowChecked = true) == fhoBadDiffbits
    check hashOf(bad) notin hc.sideHeaders
    when declared(headerWorkEvals):
      check evals() == 0
    # Unknown parent is still fhoNotFork (caller's unlinked-header path), not
    # "cannot evaluate", after the reorder.
    var orphanPrev: array[32, byte]
    orphanPrev[0] = 0xEE
    let orphan = mineHeader(BlockHash(orphanPrev), T0, PowLimitBits, salt = 5)
    check sm.acceptForkHeader(orphan, hashOf(orphan),
                              minPowChecked = true) == fhoNotFork

suite "cffix header work cache: the cache always equals the cold sum":
  let params = regtestParams()

  proc checkAllHeights(hc: HeaderChain) =
    for i in 0 .. int(hc.tipHeight):
      let r = hc.resolveParentWork(hc.hashes[i])
      check r.isSome
      check r.get().totalWork == coldWork(hc, i)
    check hc.totalWork == coldWork(hc, int(hc.tipHeight))
    when compiles(hc.cumWork):
      check hc.cumWork.len == hc.headers.len

  test "truncate + promote a heavier side branch + re-extend":
    let sm = syncManagerOn(denseChain(300), params)
    let hc = addr sm.headerChain
    # A 150-header fork from height 200: heavier than the 99 headers above it.
    var prev = hc.hashes[200]
    var ts = hc.headers[200].timestamp
    for i in 0 ..< 150:
      ts += 600
      let h = mineHeader(prev, ts, PowLimitBits, salt = uint32(1000 + i))
      check sm.acceptForkHeader(h, hashOf(h), minPowChecked = true) == fhoAccepted
      prev = hashOf(h)
    # Validated tip below the fork point, then the active branch above it fails.
    sm.chainTipHeightNoState = 150
    sm.chainTipNoState = hc.hashes[150]
    let oldAt201 = hc.hashes[201]
    sm.invalidChainFound(oldAt201)
    check hc.tipHeight == 350
    check hc.tip == prev
    check hc.hashes[201] != oldAt201
    checkAllHeights(hc[])
    # Plain extension after the promotion keeps the cache in step.
    for i in 0 ..< 20:
      let h = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, PowLimitBits,
                         salt = uint32(5000 + i))
      hc[].pushActive(h)
    checkAllHeights(hc[])

  proc tmpDbPath(tag: string): string =
    getTempDir() / ("nimrod_cffix_hwc_" & tag & "_" & $getCurrentProcessId())

  proc smallWork(n: int): array[32, byte] =
    result[0] = byte(n and 0xff)
    result[1] = byte((n shr 8) and 0xff)

  proc writeRows(cdb: ChainDb, prev: BlockHash, ts0: uint32,
                 heights: seq[int], storedWork: proc(h: int): array[32, byte]):
      seq[BlockHeader] =
    ## Block-index rows (with height slots) for a linked run of headers at
    ## `heights`, the first linking onto `prev`. Each row's totalWork is
    ## whatever `storedWork` says, so a test can store values that differ
    ## from the exact sum (pre-0be5041 quantised rows).
    var prevHash = prev
    var ts = ts0
    for h in heights:
      ts += 600
      let hdr = mineHeader(prevHash, ts, PowLimitBits, salt = uint32(h))
      cdb.putBlockIndex(BlockIndex(
        hash: hashOf(hdr), height: int32(h), status: bsValidated,
        prevHash: prevHash, header: hdr, totalWork: storedWork(h),
        undoPos: FlatFilePos(fileNum: -1, pos: -1),
        failureFlags: BLOCK_NO_FAILURE, sequenceId: 0, nTx: 1))
      prevHash = hashOf(hdr)
      result.add hdr
    cdb.bestHeight = int32(heights[^1])
    cdb.bestBlockHash = prevHash

  proc fallbackWork(hc: HeaderChain, hash: BlockHash): array[32, byte] =
    ## The same lookup with the cache disabled: master's walk.
    var c = hc
    when compiles(c.cumWork):
      c.cumWork.setLen(0)
    c.resolveParentWork(hash).get().totalWork

  test "reload from the block index carries the per-height work":
    let path = tmpDbPath("reload")
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)
    let genesis = buildGenesisBlock(params)
    const Count = 400
    var hs: seq[int]
    for i in 1 .. Count: hs.add i
    # Exact rows: genesis work + 2 per regtest header.
    discard cdb.writeRows(params.genesisBlockHash, genesis.header.timestamp, hs,
                          proc(h: int): array[32, byte] = smallWork(2 * (h + 1)))
    check calculateWork(genesis.header.bits) == smallWork(2)
    var hc = loadHeaderChainFromDb(cdb, params)
    check hc.tipHeight == int32(Count)
    checkAllHeights(hc)
    let want = coldWork(hc, Count - 1)
    plantSentinel(hc)
    resetEvals()
    check hc.resolveParentWork(hc.hashes[Count - 1]).get().totalWork == want
    when declared(headerWorkEvals):
      check evals() == 0

  test "stored rows below the exact work do not misroute a batch off tip-1":
    ## Rows written before 0be5041 carry quantised totalWork that can be LOWER
    ## than the exact sum. The tip's totalWork comes from that row (unchanged),
    ## but the work at a non-tip parent is the exact sum on master and on head,
    ## so the anti-DoS comparison of a batch connecting at tip-1 is unchanged.
    let path = tmpDbPath("lowrows")
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)
    let genesis = buildGenesisBlock(params)
    const Count = 400
    var hs: seq[int]
    for i in 1 .. Count: hs.add i
    # Stored: 1 per header instead of the exact 2.
    discard cdb.writeRows(params.genesisBlockHash, genesis.header.timestamp, hs,
                          proc(h: int): array[32, byte] = smallWork(2 + h))
    let hc = loadHeaderChainFromDb(cdb, params)
    check hc.totalWork == smallWork(2 + Count)            # the stored tip row
    let exact = coldWork(hc, Count - 1)
    check exact == smallWork(2 * Count)
    check hc.resolveParentWork(hc.hashes[Count - 1]).get().totalWork == exact
    check fallbackWork(hc, hc.hashes[Count - 1]) == exact
    let sm = syncManagerOn(hc, params)
    # Threshold between the stored and the exact work at tip-1 (+ the batch).
    sm.minimumChainWork = initUInt256(smallWork(2 * Count - 4))
    let parentIdx = Count - 1
    let fork = mineHeader(hc.hashes[parentIdx],
                          hc.headers[parentIdx].timestamp + 600, PowLimitBits,
                          salt = 77)
    let r = sm.classifyHeaderBatch(@[fork])
    check r.connectWork == initUInt256(exact)
    check r.routing == hbrDirect

  test "snapshot-grafted reload: cached work equals the grafted-chain walk":
    let path = tmpDbPath("graft")
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)
    let genesis = buildGenesisBlock(params)
    # Heights 1..7 are holes; 8..12 are the persisted suffix, linked to
    # genesis like the snapshot base band. Stored tip work 1000 (any value).
    discard cdb.writeRows(params.genesisBlockHash,
                          genesis.header.timestamp + 4800, @[8, 9, 10, 11, 12],
                          proc(h: int): array[32, byte] = smallWork(1000 - 2 * (12 - h)))
    var hc = loadHeaderChainFromDb(cdb, params)
    check hc.tipHeight == 12
    check len(hc.byHash) < hc.headers.len                 # really grafted
    check hc.totalWork == smallWork(1000)
    for h in [0, 8, 9, 10, 11]:
      let got = hc.resolveParentWork(hc.hashes[h]).get().totalWork
      check got == fallbackWork(hc, hc.hashes[h])
      # Tip work minus the filled headers above h (5 above genesis).
      check got == smallWork(if h == 0: 1000 - 2 * 5 else: 1000 - 2 * (12 - h))
    # Extension keeps the cache equal to the walk.
    for i in 0 ..< 3:
      let h = mineHeader(hc.tip, hc.headers[^1].timestamp + 600, PowLimitBits,
                         salt = uint32(900 + i))
      hc.pushActive(h)
    for h in [0, 8, 9, 10, 11, 12, 13, 14]:
      check hc.resolveParentWork(hc.hashes[h]).get().totalWork ==
        fallbackWork(hc, hc.hashes[h])
    when compiles(hc.cumWork):
      check hc.cumWork.len == hc.headers.len
