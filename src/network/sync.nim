## Headers-first block synchronization
## Download and validate all headers before block data
## Most-work chain wins (not longest chain)
## Phase 13: Parallel block download with sliding window for IBD

import std/[options, deques, tables, algorithm, sequtils, sets, strutils]
import std/times
import chronos
import chronicles
import ./peer
import ./peermanager
import ./messages
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/hashing

# Use std/times for Time and Duration (not chronos/timer)
type
  SyncTime = times.Time
  SyncDuration = times.Duration

type
  SyncState* = enum
    ssIdle            ## Not syncing
    ssSyncingHeaders  ## Downloading and validating headers
    ssDownloadingBlocks  ## Downloading full block data
    ssSynced          ## Fully synchronized

  HeaderChain* = object
    headers*: seq[BlockHeader]
    byHash*: Table[BlockHash, int]  ## Hash -> index mapping
    tip*: BlockHash
    tipHeight*: int32
    totalWork*: array[32, byte]  ## Cumulative work of the chain

  SyncManager* = ref object
    state*: SyncState
    headerChain*: HeaderChain
    peerManager*: PeerManager
    chainDb*: ChainDb
    params*: ConsensusParams
    syncPeer*: Peer
    # Block download state
    blockQueue*: Deque[BlockHash]
    pendingBlocks*: int
    lastSyncTime*: SyncTime
    # Separate tracking for header tip vs chain tip (CRITICAL pitfall)
    headerTip*: BlockHash       ## Tip of validated headers
    headerTipHeight*: int32     ## Height of header tip
    chainTip*: BlockHash        ## Tip of fully validated blocks
    chainTipHeight*: int32      ## Height of chain tip

const
  MaxHeadersPerRequest* = 2000
  MaxBlocksInFlight* = 16
  SyncTimeoutSeconds* = 60

  # Block download constants
  DownloadWindow* = 1024            ## Sliding window size for block requests
  MaxBlocksPerPeer* = 16            ## Per-peer in-flight cap (avoid one slow peer blocking others)
  BaseRequestTimeout* = 5           ## Base timeout in seconds
  MaxRequestTimeout* = 64           ## Max timeout after adaptive scaling
  BatchGetDataSize* = 16            ## Blocks per getdata message (batched)
  UtxoFlushInterval* = 2000         ## Flush UTXO set every N blocks during IBD
  InvWitnessBlockType* = 0x40000002'u32  ## Segwit block inv type

type
  BlockRequest* = object
    hash*: BlockHash
    height*: int32
    peer*: Peer
    requestTime*: SyncTime
    timeout*: SyncDuration        ## Adaptive timeout per request

  PeerBlockState* = object
    inFlight*: int                ## Blocks currently in-flight for this peer
    lastStall*: SyncTime          ## Last time this peer stalled
    currentTimeout*: int          ## Current timeout in seconds (adaptive)
    consecutiveSuccess*: int      ## Consecutive successful block receipts

  BlockDownloader* = ref object
    syncManager*: SyncManager
    pendingRequests*: Table[BlockHash, BlockRequest]
    downloadWindow*: int          ## 1024 blocks
    nextDownloadHeight*: int32    ## Next height to request
    nextProcessHeight*: int32     ## Next height to process (in-order)
    receivedBlocks*: Table[int32, Block]  ## Out-of-order buffer
    requestTimeout*: SyncDuration ## Base timeout (30s default)
    peerStates*: Table[string, PeerBlockState]  ## Per-peer tracking
    ibdActive*: bool              ## True during initial block download
    lastUtxoFlush*: int32         ## Height of last UTXO flush
    blocksProcessed*: int         ## Total blocks processed
    startTime*: SyncTime          ## IBD start time for stats

# =============================================================================
# 256-bit arithmetic for proof of work calculations
# =============================================================================

proc calculateWork*(bits: uint32): array[32, byte] =
  ## Calculate work for a block: 2^256 / (target+1)
  ## This represents the expected number of hashes to find this block
  let target = compactToTarget(bits)

  # Check for zero target (invalid)
  var isZero = true
  for b in target:
    if b != 0:
      isZero = false
      break
  if isZero:
    return default(array[32, byte])

  # We need to compute 2^256 / (target + 1)
  # Since we're dealing with 256-bit numbers, we use long division

  # First, compute target + 1
  var targetPlusOne: array[32, byte]
  var carry: uint16 = 1
  for i in 0 ..< 32:
    let sum = uint16(target[i]) + carry
    targetPlusOne[i] = byte(sum and 0xFF)
    carry = sum shr 8

  # If carry overflowed (target was 2^256-1), result is 1
  if carry != 0:
    result[0] = 1
    return result

  # Now divide 2^256 by targetPlusOne
  # We represent 2^256 as [0, 0, ..., 0, 1] (256 zeros followed by a 1)
  # This is equivalent to having the dividend be a 33-byte number where
  # the first 32 bytes are 0 and the 33rd byte is 1

  # Long division algorithm
  var dividend: array[33, byte]
  dividend[32] = 1  # This represents 2^256

  # Result will be 32 bytes
  var remainder: array[33, byte]

  # Process from most significant byte
  for i in countdown(32, 0):
    # Shift remainder left by 8 bits and add next byte of dividend
    for j in countdown(32, 1):
      remainder[j] = remainder[j - 1]
    remainder[0] = dividend[i]

    if i < 32:  # Result bytes are for indices 0..31
      # Find how many times targetPlusOne fits into remainder
      var quotient: byte = 0
      while true:
        # Check if remainder >= targetPlusOne
        var ge = true
        for k in countdown(32, 0):
          let rByte = if k < 33: remainder[k] else: 0'u8
          let tByte = if k < 32: targetPlusOne[k] else: 0'u8
          if rByte < tByte:
            ge = false
            break
          elif rByte > tByte:
            break

        if not ge:
          break

        # Subtract targetPlusOne from remainder
        var borrow: int16 = 0
        for k in 0 ..< 32:
          let diff = int16(remainder[k]) - int16(targetPlusOne[k]) - borrow
          if diff < 0:
            remainder[k] = byte((diff + 256) and 0xFF)
            borrow = 1
          else:
            remainder[k] = byte(diff)
            borrow = 0
        if borrow != 0:
          remainder[32] = byte(int16(remainder[32]) - 1)

        quotient += 1
        if quotient == 255:
          break  # Prevent infinite loop

      result[i] = quotient

proc addWork*(a, b: array[32, byte]): array[32, byte] =
  ## Add two 256-bit work values
  var carry: uint16 = 0
  for i in 0 ..< 32:
    let sum = uint16(a[i]) + uint16(b[i]) + carry
    result[i] = byte(sum and 0xFF)
    carry = sum shr 8

proc compareWork*(a, b: array[32, byte]): int =
  ## Compare two 256-bit work values
  ## Returns: -1 if a < b, 0 if a == b, 1 if a > b
  for i in countdown(31, 0):
    if a[i] < b[i]:
      return -1
    elif a[i] > b[i]:
      return 1
  0

proc isZeroWork*(w: array[32, byte]): bool =
  for b in w:
    if b != 0:
      return false
  true

# =============================================================================
# HeaderChain management
# =============================================================================

proc initHeaderChain*(): HeaderChain =
  HeaderChain(
    headers: @[],
    byHash: initTable[BlockHash, int](),
    tip: BlockHash(default(array[32, byte])),
    tipHeight: -1,
    totalWork: default(array[32, byte])
  )

proc initHeaderChain*(genesisHeader: BlockHeader, genesisHash: BlockHash): HeaderChain =
  ## Initialize header chain with genesis block
  result = initHeaderChain()
  result.headers.add(genesisHeader)
  result.byHash[genesisHash] = 0
  result.tip = genesisHash
  result.tipHeight = 0
  result.totalWork = calculateWork(genesisHeader.bits)

proc hasHeader*(hc: HeaderChain, hash: BlockHash): bool =
  hash in hc.byHash

proc getHeader*(hc: HeaderChain, hash: BlockHash): Option[BlockHeader] =
  if hash in hc.byHash:
    some(hc.headers[hc.byHash[hash]])
  else:
    none(BlockHeader)

proc getHeaderByHeight*(hc: HeaderChain, height: int32): Option[BlockHeader] =
  if height >= 0 and height < int32(hc.headers.len):
    some(hc.headers[height])
  else:
    none(BlockHeader)

proc getHashByHeight*(hc: HeaderChain, height: int32): Option[BlockHash] =
  let headerOpt = hc.getHeaderByHeight(height)
  if headerOpt.isSome:
    let h = serialize(headerOpt.get())
    some(BlockHash(doubleSha256(h)))
  else:
    none(BlockHash)

# =============================================================================
# Header validation
# =============================================================================

proc validateHeaderPoW*(header: BlockHeader): bool =
  ## Check that the header hash meets its difficulty target
  let headerBytes = serialize(header)
  let hash = BlockHash(doubleSha256(headerBytes))
  hashMeetsTarget(hash, header.bits)

proc validateHeaderChainLink*(header: BlockHeader, prevHeader: BlockHeader): bool =
  ## Check that header links correctly to previous header
  let prevBytes = serialize(prevHeader)
  let prevHash = BlockHash(doubleSha256(prevBytes))
  header.prevBlock == prevHash

proc getMedianTimePastFromChain*(hc: HeaderChain, height: int32): uint32 =
  ## Calculate MTP from the header chain
  ## Uses timestamps of the previous 11 blocks
  var timestamps: seq[uint32]

  let startHeight = max(0, height - MedianTimeSpan + 1)
  for h in startHeight .. height:
    if h < int32(hc.headers.len):
      timestamps.add(hc.headers[h].timestamp)

  if timestamps.len == 0:
    return 0

  timestamps.sort()
  timestamps[timestamps.len div 2]

proc validateHeaderMTP*(header: BlockHeader, hc: HeaderChain, height: int32): bool =
  ## Validate that header timestamp is greater than MTP of previous 11 blocks
  if height == 0:
    return true  # Genesis has no MTP requirement

  let mtp = getMedianTimePastFromChain(hc, height - 1)
  header.timestamp > mtp

proc validateDifficultyRetarget*(header: BlockHeader, hc: HeaderChain,
                                  height: int32, params: ConsensusParams): bool =
  ## Validate difficulty adjustment at retarget boundaries (every 2016 blocks)
  ## Also handles testnet special rules

  if height == 0:
    return true  # Genesis

  let prevHeight = height - 1
  if prevHeight >= int32(hc.headers.len):
    return false

  let prevHeader = hc.headers[prevHeight]

  # Check if this is a retarget boundary
  if height mod int32(params.difficultyAdjustmentInterval) != 0:
    # Not a retarget block - difficulty should stay the same
    # (except for testnet special rules which we ignore for now)
    return header.bits == prevHeader.bits

  # This is a retarget block - calculate expected difficulty
  let intervalStart = height - int32(params.difficultyAdjustmentInterval)
  if intervalStart < 0 or intervalStart >= int32(hc.headers.len):
    return false

  let firstHeader = hc.headers[intervalStart]
  let lastHeader = prevHeader

  # Calculate actual timespan
  var actualTimespan = int64(lastHeader.timestamp) - int64(firstHeader.timestamp)

  # Clamp timespan
  let minTimespan = int64(params.powTargetTimespan) div 4
  let maxTimespan = int64(params.powTargetTimespan) * 4

  if actualTimespan < minTimespan:
    actualTimespan = minTimespan
  elif actualTimespan > maxTimespan:
    actualTimespan = maxTimespan

  # Calculate new target
  let expectedBits = calculateNextTarget(prevHeader.bits, actualTimespan, params)

  header.bits == expectedBits

proc validateHeader*(header: BlockHeader, hc: HeaderChain, height: int32,
                     params: ConsensusParams): tuple[valid: bool, error: string] =
  ## Full header validation

  # Check proof of work
  if not validateHeaderPoW(header):
    return (false, "invalid proof of work")

  # Check chain linkage for non-genesis
  if height > 0:
    if height - 1 >= int32(hc.headers.len):
      return (false, "previous header not found")

    let prevHeader = hc.headers[height - 1]
    if not validateHeaderChainLink(header, prevHeader):
      return (false, "header does not link to previous")

    # Check MTP
    if not validateHeaderMTP(header, hc, height):
      return (false, "timestamp not greater than MTP")

  # Check timestamp not too far in future
  let now = getTime().toUnix().uint32
  if header.timestamp > now + uint32(MaxFutureBlockTime):
    return (false, "timestamp too far in future")

  # Check difficulty retarget (skip for regtest which has simpler rules)
  if params.network != Regtest:
    if not validateDifficultyRetarget(header, hc, height, params):
      return (false, "invalid difficulty adjustment")

  (true, "")

# =============================================================================
# SyncManager
# =============================================================================

proc newSyncManager*(pm: PeerManager, chainDb: ChainDb,
                     params: ConsensusParams): SyncManager =
  result = SyncManager(
    state: ssIdle,
    headerChain: initHeaderChain(),
    peerManager: pm,
    chainDb: chainDb,
    params: params,
    syncPeer: nil,
    blockQueue: initDeque[BlockHash](),
    pendingBlocks: 0,
    lastSyncTime: getTime(),
    headerTip: BlockHash(default(array[32, byte])),
    headerTipHeight: -1,
    chainTip: BlockHash(default(array[32, byte])),
    chainTipHeight: -1
  )

  # Initialize with genesis if chain is empty
  if chainDb.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))
    result.headerChain = initHeaderChain(genesis.header, genesisHash)
    result.headerTip = genesisHash
    result.headerTipHeight = 0
    result.chainTip = genesisHash
    result.chainTipHeight = 0
  else:
    # Load existing chain tip
    result.chainTip = chainDb.bestBlockHash
    result.chainTipHeight = chainDb.bestHeight
    result.headerTip = chainDb.bestBlockHash
    result.headerTipHeight = chainDb.bestHeight

    # TODO: Load header chain from database
    # For now, start fresh and re-sync headers
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))
    result.headerChain = initHeaderChain(genesis.header, genesisHash)

proc selectSyncPeer*(sm: SyncManager): Peer =
  ## Select the best peer for syncing (highest reported height)
  sm.peerManager.getBestPeer()

proc buildBlockLocator*(sm: SyncManager): seq[array[32, byte]] =
  ## Build block locator with exponential backoff
  ## Returns hashes at heights: tip, tip-1, ..., tip-9, tip-11, tip-15, ..., 0
  result = @[]

  var step = 1
  var height = sm.headerChain.tipHeight

  while height >= 0:
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isSome:
      result.add(array[32, byte](hashOpt.get()))

    # After 10 hashes, use exponential backoff
    if result.len > 10:
      step *= 2

    height -= int32(step)

  # Always include genesis
  let genesisHash = array[32, byte](sm.params.genesisBlockHash)
  if result.len == 0 or result[^1] != genesisHash:
    result.add(genesisHash)

proc requestHeaders*(sm: SyncManager, peer: Peer) {.async.} =
  ## Request headers from peer using getheaders message
  let locator = sm.buildBlockLocator()
  let hashStop = default(array[32, byte])  # Get as many as possible

  await peer.sendGetHeaders(
    @(locator.mapIt(BlockHash(it))),
    BlockHash(hashStop)
  )

  sm.lastSyncTime = getTime()
  info "requested headers", peer = $peer, locatorLen = locator.len,
       tipHeight = sm.headerChain.tipHeight

proc handleHeaders*(sm: SyncManager, peer: Peer,
                    headers: seq[BlockHeader]) {.async.} =
  ## Handle received headers message
  ## Validate PoW, chain linkage, MTP, difficulty retarget
  ## Request more if 2000 headers received, tip reached if < 2000

  if headers.len == 0:
    # No headers = we're at tip
    info "header sync complete", tipHeight = sm.headerChain.tipHeight
    sm.state = ssDownloadingBlocks
    return

  var accepted = 0
  var lastValidHeight = sm.headerChain.tipHeight

  for header in headers:
    # Calculate hash
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))

    # Skip if already have this header
    if sm.headerChain.hasHeader(hash):
      continue

    # Check that this header connects to our chain
    let expectedHeight = sm.headerChain.tipHeight + 1

    if expectedHeight > 0:
      let prevHashOpt = sm.headerChain.getHashByHeight(expectedHeight - 1)
      if prevHashOpt.isNone:
        warn "cannot find previous header", height = expectedHeight - 1
        break

      if header.prevBlock != prevHashOpt.get():
        # Header doesn't connect - peer sent unlinked headers
        warn "received unlinked header", peer = $peer,
             expected = $prevHashOpt.get(), got = $header.prevBlock
        # Disconnect misbehaving peer
        sm.peerManager.banPeer(peer.address)
        await sm.peerManager.removePeer(peer)
        sm.syncPeer = nil
        sm.state = ssIdle
        return

    # Validate the header
    let (valid, error) = validateHeader(header, sm.headerChain, expectedHeight, sm.params)
    if not valid:
      warn "invalid header", peer = $peer, height = expectedHeight, error = error
      # Disconnect peer sending invalid headers
      sm.peerManager.banPeer(peer.address)
      await sm.peerManager.removePeer(peer)
      sm.syncPeer = nil
      sm.state = ssIdle
      return

    # Add header to chain
    let idx = sm.headerChain.headers.len
    sm.headerChain.headers.add(header)
    sm.headerChain.byHash[hash] = idx

    # Update chain work
    let headerWork = calculateWork(header.bits)
    sm.headerChain.totalWork = addWork(sm.headerChain.totalWork, headerWork)

    # Update tip
    sm.headerChain.tip = hash
    sm.headerChain.tipHeight = expectedHeight
    sm.headerTip = hash
    sm.headerTipHeight = expectedHeight

    lastValidHeight = expectedHeight
    accepted += 1

  sm.lastSyncTime = getTime()

  info "processed headers", accepted = accepted,
       tipHeight = sm.headerChain.tipHeight,
       totalHeaders = headers.len

  # If we received 2000 headers, request more
  if headers.len >= MaxHeadersPerRequest:
    await sm.requestHeaders(peer)
  else:
    # Received less than 2000 = reached peer's tip
    info "reached header tip", height = sm.headerChain.tipHeight
    sm.state = ssDownloadingBlocks

proc requestBlocks*(sm: SyncManager, peer: Peer) {.async.} =
  ## Request blocks for validated headers
  var inventory: seq[InvVector]

  # Find blocks we need (headers we have but blocks we don't)
  var height = sm.chainTipHeight + 1

  while height <= sm.headerTipHeight and
        sm.pendingBlocks + inventory.len < MaxBlocksInFlight:
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isSome:
      let hash = hashOpt.get()
      # Check if we already have this block
      if sm.chainDb.getBlock(hash).isNone:
        inventory.add(InvVector(
          invType: invBlock,
          hash: array[32, byte](hash)
        ))
        sm.blockQueue.addLast(hash)
    height += 1

  if inventory.len > 0:
    await peer.sendGetData(inventory)
    sm.pendingBlocks += inventory.len
    info "requesting blocks", count = inventory.len,
         fromHeight = sm.chainTipHeight + 1

proc processBlock*(sm: SyncManager, blk: Block): bool =
  ## Process a received block, returns true if valid
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check this block connects to our chain
  let expectedHeight = sm.chainTipHeight + 1

  if expectedHeight > 0:
    if blk.header.prevBlock != sm.chainTip:
      warn "block does not connect to chain",
           expected = $sm.chainTip, got = $blk.header.prevBlock
      return false

  # Validate block
  let checkResult = checkBlock(blk, sm.params)
  if not checkResult.isOk:
    warn "invalid block", error = $checkResult.error
    return false

  # Apply block to chainstate
  sm.chainDb.applyBlock(blk, expectedHeight)

  # Update chain tip (NOT header tip - they're tracked separately)
  sm.chainTip = hash
  sm.chainTipHeight = expectedHeight

  sm.pendingBlocks -= 1
  if sm.blockQueue.len > 0:
    discard sm.blockQueue.popFirst()

  sm.lastSyncTime = getTime()

  info "processed block", height = expectedHeight, hash = $hash
  true

proc isSynced*(sm: SyncManager): bool =
  ## Check if we're fully synchronized
  sm.chainTipHeight >= sm.headerTipHeight and
    sm.headerTipHeight >= 0

proc startHeaderSync*(sm: SyncManager) {.async.} =
  ## Start header synchronization
  sm.syncPeer = sm.selectSyncPeer()

  if sm.syncPeer == nil:
    warn "no peers available for sync"
    sm.state = ssIdle
    return

  info "starting header sync", peer = $sm.syncPeer,
       currentHeight = sm.headerChain.tipHeight,
       peerHeight = sm.syncPeer.startHeight

  sm.state = ssSyncingHeaders
  await sm.requestHeaders(sm.syncPeer)

proc syncLoop*(sm: SyncManager) {.async.} =
  ## Main sync loop
  while true:
    let peer = sm.selectSyncPeer()

    if peer == nil:
      await sleepAsync(1000)
      continue

    case sm.state
    of ssIdle:
      # Check if we need to sync
      if peer.startHeight > sm.headerChain.tipHeight:
        await sm.startHeaderSync()
      elif not sm.isSynced():
        sm.state = ssDownloadingBlocks
      else:
        sm.state = ssSynced

    of ssSyncingHeaders:
      # Wait for headers response (handled by message callback)
      await sleepAsync(100)

    of ssDownloadingBlocks:
      # Request blocks if needed
      if sm.pendingBlocks < MaxBlocksInFlight div 2 and
         sm.chainTipHeight < sm.headerTipHeight:
        await sm.requestBlocks(peer)

      if sm.chainTipHeight >= sm.headerTipHeight:
        sm.state = ssSynced
        info "block sync complete", height = sm.chainTipHeight

      await sleepAsync(100)

    of ssSynced:
      # Check for new blocks periodically
      if peer.startHeight > sm.headerChain.tipHeight:
        sm.state = ssIdle
      await sleepAsync(5000)

    # Timeout handling
    if getTime() - sm.lastSyncTime > initDuration(seconds = SyncTimeoutSeconds):
      warn "sync timeout, resetting", state = $sm.state

      # Switch to different peer if available
      if sm.syncPeer != nil:
        sm.syncPeer = nil

      sm.state = ssIdle

# =============================================================================
# Legacy compatibility (for existing code that uses BlockSync)
# =============================================================================

type
  BlockSync* = SyncManager

proc newBlockSync*(pm: PeerManager, cs: ChainState,
                   params: ConsensusParams): BlockSync =
  newSyncManager(pm, cs.db, params)

proc getBlockLocator*(sync: BlockSync): seq[BlockHash] =
  let locator = sync.buildBlockLocator()
  result = @[]
  for h in locator:
    result.add(BlockHash(h))

proc processHeaders*(sync: BlockSync, headers: seq[BlockHeader]): int =
  ## Legacy sync interface - process headers
  var accepted = 0

  for header in headers:
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))

    if sync.headerChain.hasHeader(hash):
      continue

    let expectedHeight = sync.headerChain.tipHeight + 1

    # Basic validation
    if expectedHeight > 0:
      let prevHashOpt = sync.headerChain.getHashByHeight(expectedHeight - 1)
      if prevHashOpt.isNone or header.prevBlock != prevHashOpt.get():
        continue

    let (valid, _) = validateHeader(header, sync.headerChain, expectedHeight, sync.params)
    if not valid:
      continue

    # Add to chain
    let idx = sync.headerChain.headers.len
    sync.headerChain.headers.add(header)
    sync.headerChain.byHash[hash] = idx

    let headerWork = calculateWork(header.bits)
    sync.headerChain.totalWork = addWork(sync.headerChain.totalWork, headerWork)

    sync.headerChain.tip = hash
    sync.headerChain.tipHeight = expectedHeight
    sync.headerTip = hash
    sync.headerTipHeight = expectedHeight

    accepted += 1

  if accepted > 0:
    sync.lastSyncTime = getTime()

  accepted

# =============================================================================
# BlockDownloader - Parallel block download for IBD
# =============================================================================

proc peerKey(peer: Peer): string =
  ## Get unique key for peer state tracking
  peer.address & ":" & $peer.port

proc newBlockDownloader*(sm: SyncManager): BlockDownloader =
  ## Create a new block downloader attached to a sync manager
  result = BlockDownloader(
    syncManager: sm,
    pendingRequests: initTable[BlockHash, BlockRequest](),
    downloadWindow: DownloadWindow,
    nextDownloadHeight: sm.chainTipHeight + 1,
    nextProcessHeight: sm.chainTipHeight + 1,
    receivedBlocks: initTable[int32, Block](),
    requestTimeout: initDuration(seconds = BaseRequestTimeout),
    peerStates: initTable[string, PeerBlockState](),
    ibdActive: false,
    lastUtxoFlush: sm.chainTipHeight,
    blocksProcessed: 0,
    startTime: getTime()
  )

proc getPeerState*(dl: BlockDownloader, peer: Peer): var PeerBlockState =
  ## Get or create peer state for tracking
  let key = peerKey(peer)
  if key notin dl.peerStates:
    dl.peerStates[key] = PeerBlockState(
      inFlight: 0,
      lastStall: getTime() - initDuration(hours = 1),  # Far in past
      currentTimeout: BaseRequestTimeout,
      consecutiveSuccess: 0
    )
  dl.peerStates[key]

proc supportsWitness*(peer: Peer): bool =
  ## Check if peer supports segwit (NODE_WITNESS = 8)
  (peer.services and NodeWitness) != 0

proc selectPeerForRequest*(dl: BlockDownloader): Peer =
  ## Round-robin selection with per-peer in-flight cap
  ## Returns nil if no suitable peer available
  let peers = dl.syncManager.peerManager.getReadyPeers()
  if peers.len == 0:
    return nil

  # Find peer with fewest in-flight blocks that's under the cap
  var bestPeer: Peer = nil
  var minInFlight = high(int)

  for peer in peers:
    let state = dl.getPeerState(peer)
    if state.inFlight < MaxBlocksPerPeer and state.inFlight < minInFlight:
      bestPeer = peer
      minInFlight = state.inFlight

  bestPeer

proc requestBlocks*(dl: BlockDownloader) {.async.} =
  ## Request blocks using round-robin getdata(invWitnessBlock) across peers
  ## Batches multiple inv items per message for efficiency

  let sm = dl.syncManager
  let headerTipHeight = sm.headerTipHeight

  # Don't request past header tip
  if dl.nextDownloadHeight > headerTipHeight:
    return

  # Calculate how many blocks we can request (within window)
  let windowEnd = dl.nextProcessHeight + int32(dl.downloadWindow)
  let maxHeight = min(headerTipHeight, windowEnd)

  # Group requests by peer for batching
  var peerRequests: Table[string, tuple[peer: Peer, inv: seq[InvVector]]]

  var height = dl.nextDownloadHeight
  while height <= maxHeight:
    # Check if already requested or received
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isNone:
      height += 1
      continue

    let hash = hashOpt.get()
    if hash in dl.pendingRequests or height in dl.receivedBlocks:
      height += 1
      continue

    # Select peer for this request
    let peer = dl.selectPeerForRequest()
    if peer == nil:
      break  # No available peers

    let key = peerKey(peer)

    # Initialize peer batch if needed
    if key notin peerRequests:
      peerRequests[key] = (peer: peer, inv: @[])

    # Determine inv type (witness block for segwit peers)
    let invType = if peer.supportsWitness(): invWitnessBlock else: invBlock

    # Add to batch
    peerRequests[key].inv.add(InvVector(
      invType: invType,
      hash: array[32, byte](hash)
    ))

    # Track request
    var peerState = dl.getPeerState(peer)
    let timeout = initDuration(seconds = peerState.currentTimeout)

    dl.pendingRequests[hash] = BlockRequest(
      hash: hash,
      height: height,
      peer: peer,
      requestTime: getTime(),
      timeout: timeout
    )
    peerState.inFlight += 1
    dl.peerStates[key] = peerState

    # Check if we should send batch (BatchGetDataSize reached)
    if peerRequests[key].inv.len >= BatchGetDataSize:
      try:
        await peer.sendGetData(peerRequests[key].inv)
        trace "sent batched getdata", peer = $peer, count = peerRequests[key].inv.len
      except CatchableError as e:
        warn "failed to send getdata", peer = $peer, error = e.msg
      peerRequests[key].inv = @[]

    height += 1

  # Send remaining batched requests
  for key, batch in peerRequests:
    if batch.inv.len > 0:
      try:
        await batch.peer.sendGetData(batch.inv)
        trace "sent batched getdata", peer = $batch.peer, count = batch.inv.len
      except CatchableError as e:
        warn "failed to send getdata", peer = $batch.peer, error = e.msg

  dl.nextDownloadHeight = height

proc processReceivedBlocks*(dl: BlockDownloader) =
  ## Process received blocks in sequential order
  ## Only processes blocks at nextProcessHeight

  let sm = dl.syncManager

  while dl.nextProcessHeight in dl.receivedBlocks:
    let blk = dl.receivedBlocks[dl.nextProcessHeight]
    let height = dl.nextProcessHeight

    # Validate block
    let checkResult = checkBlock(blk, sm.params)
    if not checkResult.isOk:
      warn "invalid block during IBD", height = height, error = $checkResult.error
      # Remove from buffer and continue (don't process)
      dl.receivedBlocks.del(height)
      # TODO: Consider banning the peer that sent this
      continue

    # Apply block to chainstate
    sm.chainDb.applyBlock(blk, height)

    # Update chain tip
    let headerBytes = serialize(blk.header)
    let hash = BlockHash(doubleSha256(headerBytes))
    sm.chainTip = hash
    sm.chainTipHeight = height

    # Update stats
    dl.blocksProcessed += 1
    dl.receivedBlocks.del(height)
    dl.nextProcessHeight = height + 1

    # Progress logging every 1000 blocks
    if dl.blocksProcessed mod 1000 == 0:
      let elapsed = getTime() - dl.startTime
      let rate = float(dl.blocksProcessed) / max(1.0, elapsed.inSeconds.float)
      info "IBD progress", height = height, processed = dl.blocksProcessed,
           buffered = dl.receivedBlocks.len, pending = dl.pendingRequests.len,
           rate = rate.formatFloat(ffDecimal, 1) & " blk/s"

    # UTXO flush interval check
    if height - dl.lastUtxoFlush >= UtxoFlushInterval:
      # Trigger UTXO flush (the applyBlock uses write batches which are atomic)
      # For now we rely on RocksDB's WAL for durability
      dl.lastUtxoFlush = height
      debug "UTXO checkpoint", height = height

proc handleBlock*(dl: BlockDownloader, peer: Peer, blk: Block) {.async.} =
  ## Handle a received block - buffer out-of-order, process sequentially

  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check if this was a requested block
  if hash notin dl.pendingRequests:
    # Unsolicited block - ignore during IBD
    trace "received unsolicited block during IBD", hash = $hash
    return

  let request = dl.pendingRequests[hash]
  let height = request.height

  # Update peer state - successful delivery
  let key = peerKey(peer)
  if key in dl.peerStates:
    var peerState = dl.peerStates[key]
    peerState.inFlight = max(0, peerState.inFlight - 1)
    peerState.consecutiveSuccess += 1

    # Adaptive timeout: decay timeout on success
    if peerState.consecutiveSuccess >= 3:
      peerState.currentTimeout = max(BaseRequestTimeout,
                                      peerState.currentTimeout div 2)
      peerState.consecutiveSuccess = 0

    dl.peerStates[key] = peerState

  # Remove from pending
  dl.pendingRequests.del(hash)
  dl.syncManager.peerManager.completeInFlightBlock(hash)

  # Buffer block (may be out of order)
  dl.receivedBlocks[height] = blk

  trace "received block", height = height, hash = $hash,
        buffered = dl.receivedBlocks.len

  # Try to process in-order blocks
  dl.processReceivedBlocks()

proc handleStaleRequests*(dl: BlockDownloader) {.async.} =
  ## Handle timed-out requests with adaptive stalling
  ## Double timeout on stall, reassign to different peer

  let now = getTime()
  var staleRequests: seq[BlockHash]
  var stalePeers: HashSet[string]

  # Find stale requests
  for hash, request in dl.pendingRequests:
    if now - request.requestTime > request.timeout:
      staleRequests.add(hash)
      stalePeers.incl(peerKey(request.peer))

  if staleRequests.len == 0:
    return

  info "handling stale block requests", count = staleRequests.len

  # Update timeout for stalling peers (adaptive)
  for key in stalePeers:
    if key in dl.peerStates:
      var peerState = dl.peerStates[key]
      peerState.lastStall = now
      peerState.consecutiveSuccess = 0

      # Double timeout, capped at max
      peerState.currentTimeout = min(MaxRequestTimeout,
                                      peerState.currentTimeout * 2)
      peerState.inFlight = 0  # Reset in-flight count (requests will be re-queued)
      dl.peerStates[key] = peerState

      debug "increased peer timeout due to stall", peer = key,
            newTimeout = peerState.currentTimeout

  # Re-queue stale requests for reassignment
  for hash in staleRequests:
    let request = dl.pendingRequests[hash]

    # Clear from pending (will be re-requested)
    dl.pendingRequests.del(hash)

    # Reset download height to re-request this block
    if request.height < dl.nextDownloadHeight:
      dl.nextDownloadHeight = request.height

  # Request blocks again (will use round-robin to different peers)
  await dl.requestBlocks()

proc startIBD*(dl: BlockDownloader) {.async.} =
  ## Start Initial Block Download
  ## Downloads blocks in parallel using sliding window

  let sm = dl.syncManager
  dl.ibdActive = true
  dl.startTime = getTime()
  dl.blocksProcessed = 0
  dl.nextDownloadHeight = sm.chainTipHeight + 1
  dl.nextProcessHeight = sm.chainTipHeight + 1
  dl.lastUtxoFlush = sm.chainTipHeight

  info "starting IBD", fromHeight = sm.chainTipHeight,
       toHeight = sm.headerTipHeight,
       blocksToDownload = sm.headerTipHeight - sm.chainTipHeight

  # Skip mempool during IBD (don't relay or accept txs)
  # This is handled by the sync state check in mempool

  while dl.ibdActive and dl.nextProcessHeight <= sm.headerTipHeight:
    # Request more blocks if window allows
    let pendingCount = dl.pendingRequests.len
    let bufferedCount = dl.receivedBlocks.len

    if pendingCount + bufferedCount < dl.downloadWindow:
      await dl.requestBlocks()

    # Handle stale requests
    await dl.handleStaleRequests()

    # Process any in-order blocks we have
    dl.processReceivedBlocks()

    # Check if IBD complete
    if dl.nextProcessHeight > sm.headerTipHeight:
      break

    # Small sleep to avoid busy loop
    await sleepAsync(50)

    # Check for peer availability
    if dl.syncManager.peerManager.connectedPeerCount() == 0:
      warn "no peers available during IBD, waiting"
      await sleepAsync(5000)

  # IBD complete
  dl.ibdActive = false
  let elapsed = getTime() - dl.startTime
  let rate = float(dl.blocksProcessed) / max(1.0, elapsed.inSeconds.float)

  info "IBD complete", blocks = dl.blocksProcessed,
       elapsed = $elapsed,
       rate = rate.formatFloat(ffDecimal, 1) & " blk/s",
       chainHeight = sm.chainTipHeight

  # Switch to relay mode
  sm.state = ssSynced

proc stopIBD*(dl: BlockDownloader) =
  ## Stop IBD (e.g., on shutdown)
  dl.ibdActive = false

proc isIBDActive*(dl: BlockDownloader): bool =
  dl.ibdActive
