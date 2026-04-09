## Headers-first block synchronization
## Download and validate all headers before block data
## Most-work chain wins (not longest chain)
## Phase 13: Parallel block download with sliding window for IBD
## Phase 13+: PRESYNC/REDOWNLOAD anti-DoS header sync protection

import std/[options, deques, tables, algorithm, sequtils, sets, strutils]
import std/times
import chronos
import chronicles
import ./peer
import ./peermanager
import ./messages
import ./headerssync
import ../primitives/[types, serialize, uint256]
import ../consensus/[params, pow, validation]
import ../storage/chainstate
import ../crypto/[hashing, secp256k1]

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
    hashes*: seq[BlockHash]        ## Index -> hash mapping
    byHash*: Table[BlockHash, int]  ## Hash -> index mapping
    tip*: BlockHash
    tipHeight*: int32
    totalWork*: array[32, byte]  ## Cumulative work of the chain

  ## Statistics for header presync (anti-DoS tracking)
  HeadersPresyncStats* = object
    work*: UInt256              ## Total verified work accumulated
    height*: int64              ## Height reached (only valid in PRESYNC)
    timestamp*: uint32          ## Block timestamp of last header (only valid in PRESYNC)
    inPresync*: bool            ## True if in PRESYNC phase, false if in REDOWNLOAD

  SyncManager* = ref object
    state*: SyncState
    headerChain*: HeaderChain
    peerManager*: PeerManager
    chainDb*: ChainDb
    chainState*: ChainState  ## Full chain state for block connection
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
    # Anti-DoS header sync state (per-peer PRESYNC/REDOWNLOAD)
    peerHeadersSync*: Table[int64, HeadersSyncState]  ## peerId -> sync state
    headersPresyncStats*: Table[int64, HeadersPresyncStats]  ## Per-peer stats
    presyncBestPeer*: int64     ## Peer with most work in presync
    presyncBestWork*: UInt256   ## Best work seen in presync
    minimumChainWork*: UInt256  ## Anti-DoS work threshold
    # Block failure tracking
    failedBlockHeight*: int32   ## Height of last failed block
    failedBlockRetries*: int    ## Number of retries for the same block
    maxBlockRetries*: int       ## Max retries before skipping script check (default 3)
    # Out-of-order block buffer (blocks received ahead of chainTip)
    receivedBlocks*: Table[int32, Block]  ## height -> block buffer
    requestedHashes*: HashSet[BlockHash]  ## hashes currently in-flight

const
  MaxHeadersPerRequest* = 2000
  MaxBlocksInFlight* = 128
  SyncTimeoutSeconds* = 60

  # Block download constants
  DownloadWindow* = 1024            ## Sliding window size for block requests
  MaxBlocksPerPeer* = 16            ## Per-peer in-flight cap (avoid one slow peer blocking others)
  BaseRequestTimeout* = 5           ## Base timeout in seconds
  MaxRequestTimeout* = 64           ## Max timeout after adaptive scaling
  BatchGetDataSize* = 64            ## Blocks per getdata message (batched for IBD throughput)
  UtxoFlushInterval* = 500          ## Flush UTXO set every N blocks during IBD
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
  result.hashes.add(genesisHash)
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
  if height >= 0 and height < int32(hc.hashes.len):
    some(hc.hashes[height])
  else:
    none(BlockHash)

proc getHeight*(hc: HeaderChain, hash: BlockHash): Option[int32] =
  ## Look up the height of a block by its hash
  if hash in hc.byHash:
    some(int32(hc.byHash[hash]))
  else:
    none(int32)

# =============================================================================
# Header validation
# =============================================================================

proc validateHeaderPoW*(header: BlockHeader): bool =
  ## Check that the header hash meets its difficulty target
  let headerBytes = serialize(header)
  let hash = BlockHash(doubleSha256(headerBytes))
  hashMeetsTarget(hash, header.bits)

proc validateHeaderChainLink*(header: BlockHeader, prevHeader: BlockHeader): bool =
  ## Check that header links correctly to previous header (recomputes hash)
  let prevBytes = serialize(prevHeader)
  let prevHash = BlockHash(doubleSha256(prevBytes))
  header.prevBlock == prevHash

proc validateHeaderChainLinkByHash*(header: BlockHeader, prevHash: BlockHash): bool =
  ## Check that header links correctly to previous header using stored hash
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
    # Not a retarget block
    if params.powAllowMinDifficultyBlocks:
      # Testnet special rules: min-difficulty blocks are allowed when timestamp
      # is more than 2*targetSpacing after the previous block. Also, difficulty
      # can revert to the last non-min-difficulty block's value.
      # Use permittedDifficultyTransition which already handles this correctly.
      let powParams = toPowParams(params)
      return permittedDifficultyTransition(powParams, int32(height),
                                           prevHeader.bits, header.bits)
    # Mainnet/Signet: difficulty must stay the same
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
  # BIP94 (testnet4): use the first block's bits to prevent time-warp attack
  let bitsForCalc = if params.enforceBIP94: firstHeader.bits else: prevHeader.bits
  let expectedBits = calculateNextTarget(bitsForCalc, actualTimespan, params)

  header.bits == expectedBits

proc validateHeader*(header: BlockHeader, hc: HeaderChain, height: int32,
                     params: ConsensusParams): tuple[valid: bool, error: string] =
  ## Full header validation

  # Check proof of work
  if not validateHeaderPoW(header):
    return (false, "invalid proof of work")

  # Check chain linkage for non-genesis
  if height > 0:
    if height - 1 >= int32(hc.hashes.len):
      return (false, "previous header not found")

    let prevHash = hc.hashes[height - 1]
    if not validateHeaderChainLinkByHash(header, prevHash):
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
                     params: ConsensusParams,
                     chainState: ChainState = nil): SyncManager =
  result = SyncManager(
    state: ssIdle,
    headerChain: initHeaderChain(),
    peerManager: pm,
    chainDb: chainDb,
    chainState: chainState,
    params: params,
    syncPeer: nil,
    blockQueue: initDeque[BlockHash](),
    pendingBlocks: 0,
    lastSyncTime: getTime(),
    headerTip: BlockHash(default(array[32, byte])),
    headerTipHeight: -1,
    chainTip: BlockHash(default(array[32, byte])),
    chainTipHeight: -1,
    # Anti-DoS header sync state
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(),  # Will be set from chainstate
    receivedBlocks: initTable[int32, Block](),
    requestedHashes: initHashSet[BlockHash]()
  )

  # Initialize with genesis if chain is empty
  if chainDb.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    # Use the canonical genesis hash from params (buildGenesisBlock may not
    # produce a byte-identical coinbase for all networks)
    let genesisHash = params.genesisBlockHash
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

    # At genesis height, use the canonical hash from params to avoid mismatch
    # between buildGenesisBlock's computed hash and the well-known genesis hash
    if chainDb.bestHeight == 0:
      result.chainTip = params.genesisBlockHash
      result.headerTip = params.genesisBlockHash

    # TODO: Load header chain from database
    # For now, start fresh and re-sync headers
    let genesis = buildGenesisBlock(params)
    let genesisHash = params.genesisBlockHash
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

# =============================================================================
# Anti-DoS Header Sync (PRESYNC/REDOWNLOAD)
# =============================================================================

proc getPeerId*(peer: Peer): int64 =
  ## Generate a stable peer ID from address and port
  ## Used for tracking per-peer header sync state
  ## Uses unsigned arithmetic to avoid overflow on long address strings
  var h: uint64 = 0
  for c in peer.address:
    h = h * 31 + uint64(ord(c))
  h = h * 31 + uint64(peer.port)
  cast[int64](h)

proc getAntiDoSWorkThreshold*(sm: SyncManager): UInt256 =
  ## Calculate the minimum chain work to accept headers without anti-DoS protection
  ## Returns max(near_chaintip_work, minimumChainWork)
  ## Reference: Bitcoin Core GetAntiDoSWorkThreshold() in net_processing.cpp

  # Start with the configured minimum chain work
  var threshold = sm.minimumChainWork

  # If we have a chain tip, use work within 144 blocks of tip
  if sm.chainTipHeight >= 0:
    # Get current tip work from header chain
    let tipWork = initUInt256(sm.headerChain.totalWork)

    # Calculate work for ~144 blocks (1 day)
    # Approximate: each block adds some work based on current difficulty
    # For simplicity, we use 144 times minimum block work
    # In practice, this should be calculated from actual difficulty
    let bufferBlocks = 144
    let tipHeader = sm.headerChain.getHeaderByHeight(sm.chainTipHeight)
    if tipHeader.isSome:
      let blockWork = headerssync.getBlockProof(tipHeader.get())
      let bufferWork = blockWork * uint64(bufferBlocks)

      # near_chaintip_work = tip_work - buffer_work (clamped to 0)
      var nearTipWork = initUInt256()
      if tipWork > bufferWork:
        nearTipWork = tipWork - bufferWork

      # Return max of near-tip work and configured minimum
      if nearTipWork > threshold:
        threshold = nearTipWork

  threshold

proc calculateClaimedHeadersWork*(headers: seq[BlockHeader]): UInt256 =
  ## Calculate the claimed work from a batch of headers
  result = initUInt256()
  for header in headers:
    result = result + headerssync.getBlockProof(header)

proc tryLowWorkHeadersSync*(sm: SyncManager, peer: Peer,
                             chainStartHeight: int32,
                             chainStartHash: BlockHash,
                             chainStartBits: uint32,
                             chainStartWork: UInt256,
                             headers: var seq[BlockHeader]): bool =
  ## Try to initiate low-work header sync for a peer
  ## Returns true if headers should be processed through anti-DoS sync
  ## Reference: Bitcoin Core TryLowWorkHeadersSync() in net_processing.cpp

  let peerId = getPeerId(peer)

  # Calculate total claimed work
  let claimedWork = calculateClaimedHeadersWork(headers)
  let totalWork = chainStartWork + claimedWork

  # Get anti-DoS threshold
  let threshold = sm.getAntiDoSWorkThreshold()

  # If claimed work meets threshold, no need for anti-DoS sync
  if totalWork >= threshold:
    return false

  # Only trigger if message is full (peer has more headers)
  if headers.len < MaxHeadersPerRequest:
    debug "ignoring low-work headers (incomplete message)",
          peer = $peer, headers = headers.len, work = $totalWork
    headers = @[]  # Clear headers to prevent normal processing
    return true

  # Initialize header sync state for this peer
  info "starting low-work header sync",
       peer = $peer, height = chainStartHeight, work = $totalWork

  let syncState = newHeadersSyncState(
    peerId = peerId,
    params = sm.params,
    chainStartHeight = chainStartHeight,
    chainStartHash = chainStartHash,
    chainStartBits = chainStartBits,
    chainStartWork = chainStartWork,
    minimumRequiredWork = threshold
  )

  sm.peerHeadersSync[peerId] = syncState

  # Process the initial batch of headers through the sync state
  let result = syncState.processNextHeaders(headers, headers.len >= MaxHeadersPerRequest)

  if result.success:
    # Update presync stats
    sm.headersPresyncStats[peerId] = HeadersPresyncStats(
      work: syncState.getPresyncWork(),
      height: syncState.getPresyncHeight(),
      timestamp: syncState.getPresyncTime(),
      inPresync: syncState.getState() == Presync
    )

    # Track best peer for presync
    if syncState.getPresyncWork() > sm.presyncBestWork:
      sm.presyncBestWork = syncState.getPresyncWork()
      sm.presyncBestPeer = peerId

  # Clear original headers (processed through sync state)
  headers = result.powValidatedHeaders
  true

proc isContinuationOfLowWorkHeadersSync*(sm: SyncManager, peer: Peer,
                                          headers: var seq[BlockHeader]): bool =
  ## Check if this peer has an active low-work header sync and process headers
  ## Returns true if headers were processed through anti-DoS sync
  ## Reference: Bitcoin Core IsContinuationOfLowWorkHeadersSync()

  let peerId = getPeerId(peer)

  if peerId notin sm.peerHeadersSync:
    return false

  let syncState = sm.peerHeadersSync[peerId]

  if syncState.getState() == Done:
    # Sync is complete, clean up
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)
    return false

  # Process headers through the sync state
  let fullMessage = headers.len >= MaxHeadersPerRequest
  let result = syncState.processNextHeaders(headers, fullMessage)

  if not result.success:
    # Peer misbehaved during sync
    warn "low-work header sync failed",
         peer = $peer, state = $syncState.getState()
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)
    headers = @[]
    return true

  # Update stats
  if syncState.getState() != Done:
    sm.headersPresyncStats[peerId] = HeadersPresyncStats(
      work: syncState.getPresyncWork(),
      height: syncState.getPresyncHeight(),
      timestamp: syncState.getPresyncTime(),
      inPresync: syncState.getState() == Presync
    )

    # Update best peer tracking
    if syncState.getPresyncWork() > sm.presyncBestWork:
      sm.presyncBestWork = syncState.getPresyncWork()
      sm.presyncBestPeer = peerId

    # Request more headers if needed
    if result.requestMore:
      let locator = syncState.nextHeadersRequestLocator()
      if locator.len > 0:
        debug "requesting more headers for low-work sync",
              peer = $peer, locatorLen = locator.len
        # Note: caller should send getheaders with this locator
  else:
    # Sync complete
    info "low-work header sync complete",
         peer = $peer, height = syncState.getRedownloadHeight()
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)

  # Return validated headers for normal processing
  headers = result.powValidatedHeaders
  true

proc cleanupPeerHeadersSync*(sm: SyncManager, peerId: int64) =
  ## Clean up header sync state for a disconnected peer
  sm.peerHeadersSync.del(peerId)
  sm.headersPresyncStats.del(peerId)

  # Update best peer if this was the best
  if sm.presyncBestPeer == peerId:
    sm.presyncBestPeer = -1
    sm.presyncBestWork = initUInt256()

    # Find new best peer
    for pid, stats in sm.headersPresyncStats:
      if stats.work > sm.presyncBestWork:
        sm.presyncBestWork = stats.work
        sm.presyncBestPeer = pid

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
  ## Implements PRESYNC/REDOWNLOAD anti-DoS protection for low-work headers
  ## Request more if 2000 headers received, tip reached if < 2000

  if headers.len == 0:
    # No headers = we're at tip (or peer has nothing more)
    # Check if we have an active low-work sync for this peer
    if getPeerId(peer) in sm.peerHeadersSync:
      let syncState = sm.peerHeadersSync[getPeerId(peer)]
      if syncState.getState() != Done:
        # Empty response during low-work sync - peer stopped early
        debug "peer stopped sending during low-work sync",
              peer = $peer, state = $syncState.getState()
        sm.cleanupPeerHeadersSync(getPeerId(peer))

    info "header sync complete", tipHeight = sm.headerChain.tipHeight
    sm.state = ssDownloadingBlocks
    return

  # Make a mutable copy for anti-DoS processing
  var headersToProcess = headers

  # Check if this is a continuation of an active low-work header sync
  if sm.isContinuationOfLowWorkHeadersSync(peer, headersToProcess):
    # Headers were processed through anti-DoS sync
    if headersToProcess.len == 0:
      # All headers consumed by presync phase, request more
      if getPeerId(peer) in sm.peerHeadersSync:
        let syncState = sm.peerHeadersSync[getPeerId(peer)]
        if syncState.getState() != Done:
          let locator = syncState.nextHeadersRequestLocator()
          if locator.len > 0:
            await peer.sendGetHeaders(locator, BlockHash(default(array[32, byte])))
      return
    # Otherwise, fall through to normal processing with validated headers
  else:
    # Check if we need to start a new low-work header sync
    # This happens when headers don't connect to our best chain
    # and have low claimed work

    # Find where headers connect to our chain
    if headersToProcess.len > 0:
      let firstHeader = headersToProcess[0]

      # Check if headers connect directly to our tip
      if firstHeader.prevBlock != sm.headerTip and sm.headerTipHeight >= 0:
        # Headers don't connect to tip - check if they branch from our chain
        let prevHashOpt = sm.headerChain.getHeader(firstHeader.prevBlock)

        if prevHashOpt.isNone:
          # Headers don't connect to any known block
          # Could be a fork from earlier or completely disconnected
          warn "headers don't connect to our chain",
               peer = $peer, prevBlock = $firstHeader.prevBlock
          # For now, reject unconnected headers
          sm.peerManager.misbehavingPeer(peer, 20, "unconnected headers")
          return

        # Headers branch from an earlier point - check work threshold
        let branchHeight = sm.headerChain.byHash.getOrDefault(firstHeader.prevBlock, -1)
        if branchHeight >= 0:
          let branchHeader = sm.headerChain.headers[branchHeight]
          let branchHash = firstHeader.prevBlock

          # Calculate work up to branch point
          var branchWork = initUInt256()
          for i in 0..branchHeight:
            let w = headerssync.getBlockProof(sm.headerChain.headers[i])
            branchWork = branchWork + w

          # Try low-work sync if claimed work is below threshold
          if sm.tryLowWorkHeadersSync(peer, int32(branchHeight), branchHash,
                                       branchHeader.bits, branchWork, headersToProcess):
            # Headers being processed through anti-DoS sync
            if headersToProcess.len == 0:
              # Request more headers through low-work sync
              if getPeerId(peer) in sm.peerHeadersSync:
                let syncState = sm.peerHeadersSync[getPeerId(peer)]
                let locator = syncState.nextHeadersRequestLocator()
                if locator.len > 0:
                  await peer.sendGetHeaders(locator, BlockHash(default(array[32, byte])))
              return

  # Normal header processing (either direct or validated through anti-DoS)
  var accepted = 0
  var lastValidHeight = sm.headerChain.tipHeight

  for header in headersToProcess:
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
    sm.headerChain.hashes.add(hash)
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
  ## During IBD, distributes requests across multiple peers for parallel download
  var inventory: seq[InvVector]

  # Find blocks we need (headers we have but blocks we don't)
  var height = sm.chainTipHeight + 1

  while height <= sm.headerTipHeight and
        sm.pendingBlocks + inventory.len < MaxBlocksInFlight:
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isSome:
      let hash = hashOpt.get()
      # Skip blocks already buffered out-of-order or already in-flight
      if height in sm.receivedBlocks or hash in sm.requestedHashes:
        height += 1
        continue
      # Check if we already have this block in the database
      # Skip DB lookup during IBD - we know we don't have blocks above chain tip
      if sm.chainState != nil and sm.chainState.ibdMode or
         sm.chainDb.getBlock(hash).isNone:
        inventory.add(InvVector(
          invType: invWitnessBlock,
          hash: array[32, byte](hash)
        ))
        sm.requestedHashes.incl(hash)
        sm.blockQueue.addLast(hash)
    height += 1

  if inventory.len == 0:
    return

  # During IBD, distribute block requests across all available peers
  # to maximize download throughput (parallel download from multiple peers)
  let peers = sm.peerManager.getReadyPeers()
  if peers.len > 1 and sm.chainState != nil and sm.chainState.ibdMode:
    let blocksPerPeer = max(1, inventory.len div peers.len)
    var idx = 0
    var totalSent = 0
    for i, p in peers:
      if idx >= inventory.len:
        break
      let endIdx = if i == peers.len - 1: inventory.len
                   else: min(idx + blocksPerPeer, inventory.len)
      let batch = inventory[idx ..< endIdx]
      if batch.len > 0:
        try:
          await p.sendGetData(batch)
          totalSent += batch.len
        except CatchableError as e:
          warn "failed to send getdata to peer", peer = $p, error = e.msg
          for inv in batch:
            sm.requestedHashes.excl(BlockHash(inv.hash))
      idx = endIdx
    sm.pendingBlocks += totalSent
    sm.lastSyncTime = getTime()
    info "requesting blocks", count = totalSent, peers = peers.len,
         fromHeight = sm.chainTipHeight + 1
  else:
    # Single-peer fallback
    try:
      await peer.sendGetData(inventory)
    except CatchableError as e:
      warn "failed to send getdata", peer = $peer, error = e.msg
      for inv in inventory:
        sm.requestedHashes.excl(BlockHash(inv.hash))
      return
    sm.pendingBlocks += inventory.len
    sm.lastSyncTime = getTime()
    info "requesting blocks", count = inventory.len,
         fromHeight = sm.chainTipHeight + 1

proc applyBlock(sm: SyncManager, blk: Block, height: int32): bool =
  ## Validate and apply a single block at the given height.
  ## Returns true if the block was successfully applied.
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check this block connects to our chain
  if height > 0:
    let expectedPrev = if height == 1: sm.params.genesisBlockHash
                       else: sm.chainTip
    if blk.header.prevBlock != expectedPrev:
      warn "block does not connect", height = height,
           expected = $expectedPrev, got = $blk.header.prevBlock
      return false

  # Validate block
  let checkResult = checkBlock(blk, sm.params)
  if not checkResult.isOk:
    warn "invalid block", height = height, error = $checkResult.error
    return false

  # Script verification (skip only if below assume-valid height)
  let skipScripts = sm.params.assumeValidHeight > 0 and
                    height <= sm.params.assumeValidHeight
  if not skipScripts and sm.chainState != nil:
    try:
      {.gcsafe.}:
        let cs = sm.chainState
        let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] =
          cs.getUtxo(op)
        let crypto = newCryptoEngine()
        let scriptResult = verifyScripts(blk, utxoLookup, height, crypto, sm.params)
        if not scriptResult.isOk:
          warn "script verification failed", height = height,
               error = $scriptResult.error, txCount = blk.txs.len,
               hasWitness = (blk.txs.len > 1 and blk.txs[1].witnesses.len > 0)
          if sm.failedBlockHeight == height:
            sm.failedBlockRetries += 1
          else:
            sm.failedBlockHeight = height
            sm.failedBlockRetries = 1
          return false
    except Exception as e:
      warn "script verification error", height = height, error = e.msg
      return false

  # Apply block to chainstate
  # Use IBD fast path when catching up (skips undo data, batches writes)
  if sm.chainState != nil:
    let blocksRemaining = sm.headerTipHeight - height
    let isIBD = blocksRemaining > 1000

    # Enter IBD mode if catching up and not already in IBD
    if isIBD and not sm.chainState.ibdMode:
      sm.chainState.startIBD()
      info "entering IBD mode for block sync", height = height,
           remaining = blocksRemaining

    # Exit IBD mode when nearly caught up
    if not isIBD and sm.chainState.ibdMode:
      sm.chainState.stopIBD()
      info "exiting IBD mode, switching to normal sync", height = height

    let connectResult = if sm.chainState.ibdMode:
                          sm.chainState.connectBlockIBD(blk, height)
                        else:
                          sm.chainState.connectBlock(blk, height)
    if not connectResult.isOk:
      warn "failed to connect block to chainstate", error = $connectResult.error
      return false
  else:
    sm.chainDb.applyBlock(blk, height)

  # Update chain tip (NOT header tip - they're tracked separately)
  sm.chainTip = hash
  sm.chainTipHeight = height

  if sm.blockQueue.len > 0:
    discard sm.blockQueue.popFirst()

  # Reset failure tracking on success
  if height == sm.failedBlockHeight:
    sm.failedBlockHeight = 0
    sm.failedBlockRetries = 0

  if height mod 1000 == 0 or height == sm.headerTipHeight:
    info "processed block", height = height, hash = $hash

  true

proc drainBlockBuffer(sm: SyncManager) =
  ## Process buffered out-of-order blocks sequentially starting from chainTip+1
  while true:
    let nextHeight = sm.chainTipHeight + 1
    if nextHeight notin sm.receivedBlocks:
      break
    let blk = sm.receivedBlocks[nextHeight]
    sm.receivedBlocks.del(nextHeight)
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    if not sm.applyBlock(blk, nextHeight):
      warn "failed to apply buffered block", height = nextHeight
      break

proc processBlock*(sm: SyncManager, blk: Block): bool =
  ## Process a received block, returns true if valid
  ## Buffers out-of-order blocks and processes sequentially
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Remove from in-flight tracking
  sm.requestedHashes.excl(hash)

  # Determine what height this block belongs to by looking up its hash
  # in the header chain
  let heightOpt = sm.headerChain.getHeight(hash)

  if heightOpt.isNone:
    # Unknown block - not in our header chain
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    return false

  let blockHeight = heightOpt.get()
  let expectedHeight = sm.chainTipHeight + 1

  if blockHeight == expectedHeight:
    # Block connects directly - apply it
    if not sm.applyBlock(blk, expectedHeight):
      sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
      return false
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    sm.lastSyncTime = getTime()  # Reset timeout on progress
    # Drain any buffered blocks that now connect
    sm.drainBlockBuffer()
    return true
  elif blockHeight > expectedHeight and blockHeight <= sm.headerTipHeight:
    # Out-of-order block - buffer it for later processing
    sm.receivedBlocks[int32(blockHeight)] = blk
    trace "buffered out-of-order block", height = blockHeight,
          expectedHeight = expectedHeight, buffered = sm.receivedBlocks.len
    # Don't decrement pendingBlocks here - it will be decremented when
    # the block is actually processed from the buffer in drainBlockBuffer
    return true  # Successfully received, just not yet applied
  else:
    # Block is behind our chain tip or too far ahead - discard
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    return false

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
  sm.maxBlockRetries = 3  # Skip script verification after 3 failures on same block
  var consecutiveTimeouts = 0

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
        sm.lastSyncTime = getTime()  # Reset timer on state transition
      else:
        sm.state = ssSynced
      # Always sleep in ssIdle to prevent tight loop when cycling states
      await sleepAsync(200)

    of ssSyncingHeaders:
      # Wait for headers response (handled by message callback)
      await sleepAsync(100)

    of ssDownloadingBlocks:
      # Verify chain tip matches header chain before requesting blocks.
      # If there was a reorg, our stored chain tip may be on a stale fork.
      block chainTipCheck:
        let headerHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
        if headerHashOpt.isSome and headerHashOpt.get() != sm.chainTip:
          # Chain tip mismatch - roll back to common ancestor
          while sm.chainTipHeight > 0:
            let hashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
            if hashOpt.isSome and hashOpt.get() == sm.chainTip:
              break
            if hashOpt.isNone:
              break
            warn "chain tip mismatch, rolling back",
                 height = sm.chainTipHeight,
                 storedTip = $sm.chainTip,
                 headerChainHash = $hashOpt.get()
            sm.chainTipHeight -= 1
            let prevHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
            if prevHashOpt.isSome:
              sm.chainTip = prevHashOpt.get()
            else:
              break
          info "rolled back to common ancestor",
               height = sm.chainTipHeight, tip = $sm.chainTip
          if sm.chainState != nil:
            sm.chainState.bestHeight = sm.chainTipHeight
            sm.chainState.bestBlockHash = sm.chainTip

      # Request blocks if needed
      if sm.pendingBlocks < MaxBlocksInFlight div 2 and
         sm.chainTipHeight < sm.headerTipHeight:
        await sm.requestBlocks(peer)

      if sm.chainTipHeight >= sm.headerTipHeight:
        sm.state = ssSynced
        info "block sync complete", height = sm.chainTipHeight
        consecutiveTimeouts = 0

      await sleepAsync(100)

    of ssSynced:
      # Periodically request new headers to discover blocks mined since
      # we reached tip.  peer.startHeight is stale (set at connect time),
      # so we can't rely on it to detect new blocks.  Instead, send
      # getheaders every 5s — if there are new blocks, the peer responds
      # with headers and we transition back to ssIdle → download.
      await sm.startHeaderSync()
      # If new headers arrived, the handler updates headerTipHeight.
      # Check if we need to download blocks.
      if sm.headerTipHeight > sm.chainTipHeight:
        sm.state = ssIdle
      await sleepAsync(5000)

    # Timeout handling (skip when already synced — no activity expected)
    if sm.state != ssSynced and
       getTime() - sm.lastSyncTime > initDuration(seconds = SyncTimeoutSeconds):
      consecutiveTimeouts += 1
      warn "sync timeout, resetting", state = $sm.state,
           chainTipHeight = sm.chainTipHeight,
           headerTipHeight = sm.headerTipHeight,
           pendingBlocks = sm.pendingBlocks,
           consecutiveTimeouts = consecutiveTimeouts

      # Switch to different peer if available
      if sm.syncPeer != nil:
        sm.syncPeer = nil

      # Reset download state so we can re-request blocks from scratch
      sm.pendingBlocks = 0
      sm.blockQueue.clear()
      sm.requestedHashes.clear()
      sm.receivedBlocks.clear()

      # Reset timer so we don't immediately timeout again on next iteration
      sm.lastSyncTime = getTime()

      sm.state = ssIdle

      # Exponential backoff: 2s, 4s, 8s, 16s, 30s max
      let backoff = min(30000, 2000 * (1 shl min(consecutiveTimeouts - 1, 4)))
      await sleepAsync(backoff)

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
    sync.headerChain.hashes.add(hash)
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
  ## Uses IBD fast path: batched RocksDB writes, no undo data, no tx index

  let sm = dl.syncManager

  # Ensure IBD mode is active on chainstate for batched writes
  if sm.chainState != nil and not sm.chainState.ibdMode:
    sm.chainState.startIBD()

  while dl.nextProcessHeight in dl.receivedBlocks:
    let blk = dl.receivedBlocks[dl.nextProcessHeight]
    let height = dl.nextProcessHeight

    # Validate block structure (cheap checks: merkle root, weight, etc.)
    let checkResult = checkBlock(blk, sm.params)
    if not checkResult.isOk:
      warn "invalid block during IBD", height = height, error = $checkResult.error
      dl.receivedBlocks.del(height)
      continue

    # Apply block to chainstate using IBD fast path
    if sm.chainState != nil:
      let connectResult = sm.chainState.connectBlockIBD(blk, height)
      if not connectResult.isOk:
        warn "failed to connect block during IBD", height = height, error = $connectResult.error
        dl.receivedBlocks.del(height)
        continue
    else:
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

  # Score misbehavior for stalling block downloads (+50)
  for hash, request in dl.pendingRequests:
    let pk = peerKey(request.peer)
    if pk in stalePeers:
      dl.syncManager.peerManager.misbehavingPeer(request.peer, ScoreBlockDownloadStall, "block download stalling")
      break  # One score per peer is enough

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

  # IBD complete - flush remaining batched writes
  dl.ibdActive = false
  if sm.chainState != nil and sm.chainState.ibdMode:
    sm.chainState.stopIBD()

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
  # Flush any pending IBD batch
  let sm = dl.syncManager
  if sm.chainState != nil and sm.chainState.ibdMode:
    sm.chainState.stopIBD()

proc isIBDActive*(dl: BlockDownloader): bool =
  dl.ibdActive
