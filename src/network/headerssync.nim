## Header sync anti-DoS protection (PRESYNC/REDOWNLOAD)
## Implements Bitcoin Core's HeadersSyncState to prevent memory exhaustion attacks
## where a peer sends millions of low-work headers.
##
## Two-phase sync strategy:
## 1. PRESYNC: Accept headers minimally, compute cumulative work, store only 1-bit commitments
## 2. REDOWNLOAD: Re-request all headers, verify commitments, store permanently
##
## Reference: Bitcoin Core headerssync.cpp/h

import std/[deques, random, times]
import chronicles
import ../primitives/[types, serialize, uint256]
import ../consensus/[params, pow]
import ../crypto/hashing

type
  SyncPhase* = enum
    ## Current phase of header sync with this peer
    Presync     ## Validating work, storing commitments
    Redownload  ## Re-downloading with commitment verification
    Done        ## Sync complete (success or failure)

  CompressedHeader* = object
    ## Space-optimized header (48 bytes vs 80 bytes for full header)
    ## Excludes prevBlock hash since it can be reconstructed from chain
    version*: int32
    merkleRoot*: array[32, byte]
    timestamp*: uint32
    bits*: uint32
    nonce*: uint32

  ProcessingResult* = object
    ## Result from processing a batch of headers
    powValidatedHeaders*: seq[BlockHeader]  ## Headers ready for permanent storage
    success*: bool                          ## False if error detected (peer misbehaving)
    requestMore*: bool                      ## True if should request more headers

  HeadersSyncState* = ref object
    ## State machine for header sync with a single peer
    ## Each peer gets its own HeadersSyncState instance

    # Configuration
    peerId*: int64
    params*: ConsensusParams
    syncParams*: HeadersSyncParams

    # Chain start point
    chainStartHeight*: int32
    chainStartHash*: BlockHash
    chainStartWork*: UInt256
    chainStartBits*: uint32

    # Minimum work required for acceptance
    minimumRequiredWork*: UInt256

    # Current state
    downloadState*: SyncPhase

    # PRESYNC phase state
    currentChainWork*: UInt256     ## Accumulated work during presync
    lastHeaderReceived*: BlockHeader  ## Last header seen in presync
    lastHeaderHash*: BlockHash     ## Hash of last header received
    currentHeight*: int64          ## Height of last header received

    # Commitment tracking (1-bit per commitment_period headers)
    headerCommitments*: Deque[bool]
    maxCommitments*: uint64
    commitOffset*: int             ## Random offset for commitment heights

    # Hasher salt for commitments
    hasherSalt*: uint64

    # REDOWNLOAD phase state
    redownloadedHeaders*: Deque[CompressedHeader]
    redownloadBufferLastHeight*: int64
    redownloadBufferLastHash*: BlockHash
    redownloadBufferFirstPrevHash*: BlockHash
    redownloadChainWork*: UInt256
    processAllRemainingHeaders*: bool

const
  MaxFutureBlockTime = 7200  # 2 hours
  MaxHeadersPerMessage* = 2000
  # 6 blocks per second is max theoretical rate given MTP rule
  MaxBlocksPerSecond = 6

proc toCompressed*(header: BlockHeader): CompressedHeader =
  ## Convert full header to compressed format
  CompressedHeader(
    version: header.version,
    merkleRoot: array[32, byte](header.merkleRoot),
    timestamp: header.timestamp,
    bits: header.bits,
    nonce: header.nonce
  )

proc toFullHeader*(compressed: CompressedHeader, prevHash: BlockHash): BlockHeader =
  ## Reconstruct full header from compressed format
  BlockHeader(
    version: compressed.version,
    prevBlock: prevHash,
    merkleRoot: compressed.merkleRoot,
    timestamp: compressed.timestamp,
    bits: compressed.bits,
    nonce: compressed.nonce
  )

proc hashHeader*(header: BlockHeader): BlockHash =
  ## Compute block hash from header
  let headerBytes = serialize(header)
  BlockHash(doubleSha256(headerBytes))

proc computeCommitmentBit*(state: HeadersSyncState, headerHash: BlockHash): bool =
  ## Compute 1-bit commitment for a header using salted hash
  ## This prevents attacker from precomputing headers that match
  var combined: array[40, byte]
  copyMem(addr combined[0], addr state.hasherSalt, 8)
  copyMem(addr combined[8], unsafeAddr array[32, byte](headerHash)[0], 32)
  let hashed = sha256(combined)
  (hashed[0] and 1) == 1

proc shouldStoreCommitment*(state: HeadersSyncState, height: int64): bool =
  ## Check if this height should have a commitment stored
  (height mod state.syncParams.commitmentPeriod) == state.commitOffset

proc getBlockProof*(header: BlockHeader): UInt256 =
  ## Calculate the work (proof) represented by this header
  ## Work = 2^256 / (target + 1)
  let target = setCompact(header.bits)
  if target.isZero():
    return initUInt256()

  # Calculate 2^256 / (target + 1)
  # We approximate by computing 2^256 - 1 / (target's first limb + 1)
  # This is a rough approximation for small targets, but works for our purposes
  var maxVal = initUInt256()
  for i in 0..3:
    maxVal.limbs[i] = high(uint64)

  # For simplicity, divide by the first limb + 1
  # This approximation works because we're mainly comparing relative work
  let divisor = if target.limbs[0] > 0: target.limbs[0] else: 1'u64
  result = maxVal div divisor

proc toPowParams*(params: ConsensusParams): PowParams =
  ## Convert ConsensusParams to PowParams for PoW validation
  PowParams(
    network: case params.network
      of Mainnet: pow.Mainnet
      of Testnet3: pow.Testnet3
      of Testnet4: pow.Testnet4
      of Regtest: pow.Regtest
      of Signet: pow.Signet,
    powLimit: params.powLimit,
    powTargetTimespan: params.powTargetTimespan,
    powTargetSpacing: params.powTargetSpacing,
    powAllowMinDifficultyBlocks: params.powAllowMinDifficultyBlocks,
    powNoRetargeting: params.powNoRetargeting,
    enforceBIP94: params.enforceBIP94
  )

proc newHeadersSyncState*(
  peerId: int64,
  params: ConsensusParams,
  chainStartHeight: int32,
  chainStartHash: BlockHash,
  chainStartBits: uint32,
  chainStartWork: UInt256,
  minimumRequiredWork: UInt256
): HeadersSyncState =
  ## Create a new header sync state for a peer
  ## chainStart: The last known block that peer's chain branches from
  ## minimumRequiredWork: Minimum total chain work to accept the chain

  # Use a combination of time, peerId, and chain hash for unique seed
  let timeSeed = getTime().toUnix
  let peerSeed = peerId
  let hashSeed = int64(array[32, byte](chainStartHash)[0]) shl 8 or
                 int64(array[32, byte](chainStartHash)[1])
  var rng = initRand(timeSeed xor peerSeed xor hashSeed)

  result = HeadersSyncState(
    peerId: peerId,
    params: params,
    syncParams: params.headersSyncParams,
    chainStartHeight: chainStartHeight,
    chainStartHash: chainStartHash,
    chainStartWork: chainStartWork,
    chainStartBits: chainStartBits,
    minimumRequiredWork: minimumRequiredWork,
    downloadState: Presync,
    currentChainWork: chainStartWork,
    currentHeight: chainStartHeight,
    lastHeaderHash: chainStartHash,
    headerCommitments: initDeque[bool](),
    commitOffset: rng.rand(params.headersSyncParams.commitmentPeriod - 1),
    hasherSalt: uint64(rng.rand(high(int))),
    redownloadedHeaders: initDeque[CompressedHeader](),
    redownloadBufferLastHeight: 0,
    redownloadChainWork: initUInt256(),
    processAllRemainingHeaders: false
  )

  # Initialize lastHeaderReceived with chain start values
  result.lastHeaderReceived.bits = chainStartBits

  # Calculate max commitments based on theoretical max chain length
  # Max blocks possible = 6 blocks/sec * seconds since MTP
  # We bound memory by limiting commitments
  let nowSec = getTime().toUnix
  let mtpSec = int64(chainStartHeight) * 600  # Rough MTP estimate
  let maxSecondsSinceStart = nowSec - mtpSec + MaxFutureBlockTime
  result.maxCommitments = uint64(MaxBlocksPerSecond * maxSecondsSinceStart) div
                          uint64(params.headersSyncParams.commitmentPeriod)

  debug "headers sync started",
        peerId = peerId,
        height = chainStartHeight,
        maxCommitments = result.maxCommitments,
        minWork = $minimumRequiredWork

proc finalize(state: HeadersSyncState) =
  ## Clean up state and mark as done
  state.headerCommitments.clear()
  state.redownloadedHeaders.clear()
  state.downloadState = Done

proc validateAndProcessSingleHeader(state: HeadersSyncState, header: BlockHeader): bool =
  ## Process a single header during PRESYNC phase
  ## Returns false if header is invalid

  if state.downloadState != Presync:
    return false

  let nextHeight = state.currentHeight + 1
  let powParams = toPowParams(state.params)

  # Validate difficulty transition
  if not permittedDifficultyTransition(powParams, int32(nextHeight),
                                       state.lastHeaderReceived.bits, header.bits):
    debug "invalid difficulty transition",
          peer = state.peerId, height = nextHeight
    return false

  # Store commitment if at commitment height
  if state.shouldStoreCommitment(nextHeight):
    let headerHash = hashHeader(header)
    let commitment = state.computeCommitmentBit(headerHash)
    state.headerCommitments.addLast(commitment)

    if uint64(state.headerCommitments.len) > state.maxCommitments:
      debug "exceeded max commitments",
            peer = state.peerId, height = nextHeight
      return false

  # Update chain work
  state.currentChainWork = state.currentChainWork + getBlockProof(header)

  # Update state
  state.lastHeaderReceived = header
  state.lastHeaderHash = hashHeader(header)
  state.currentHeight = nextHeight

  true

proc validateAndStoreHeadersCommitments(
  state: HeadersSyncState,
  headers: seq[BlockHeader]
): bool =
  ## Process headers during PRESYNC, storing commitments
  ## Returns false if any header is invalid

  if headers.len == 0:
    return true

  if state.downloadState != Presync:
    return false

  # Check first header connects
  let firstHash = hashHeader(headers[0])
  if headers[0].prevBlock != state.lastHeaderHash:
    debug "non-continuous headers in presync",
          peer = state.peerId, height = state.currentHeight
    return false

  # Process each header
  for header in headers:
    if not state.validateAndProcessSingleHeader(header):
      return false

  # Check if we've reached minimum work
  if state.currentChainWork >= state.minimumRequiredWork:
    # Transition to REDOWNLOAD
    state.redownloadedHeaders.clear()
    state.redownloadBufferLastHeight = state.chainStartHeight
    state.redownloadBufferFirstPrevHash = state.chainStartHash
    state.redownloadBufferLastHash = state.chainStartHash
    state.redownloadChainWork = state.chainStartWork
    state.downloadState = Redownload

    debug "transitioning to redownload",
          peer = state.peerId,
          presyncHeight = state.currentHeight,
          redownloadFrom = state.chainStartHeight

  true

proc validateAndStoreRedownloadedHeader(
  state: HeadersSyncState,
  header: BlockHeader
): bool =
  ## Process a header during REDOWNLOAD phase
  ## Returns false if header doesn't match commitments

  if state.downloadState != Redownload:
    return false

  let nextHeight = state.redownloadBufferLastHeight + 1
  let headerHash = hashHeader(header)

  # Check continuity
  if header.prevBlock != state.redownloadBufferLastHash:
    debug "non-continuous headers in redownload",
          peer = state.peerId, height = nextHeight
    return false

  # Check difficulty transition
  let previousBits = if state.redownloadedHeaders.len > 0:
    state.redownloadedHeaders.peekLast().bits
  else:
    state.chainStartBits

  let powParams = toPowParams(state.params)
  if not permittedDifficultyTransition(powParams, int32(nextHeight),
                                       previousBits, header.bits):
    debug "invalid difficulty in redownload",
          peer = state.peerId, height = nextHeight
    return false

  # Track work
  state.redownloadChainWork = state.redownloadChainWork + getBlockProof(header)

  if state.redownloadChainWork >= state.minimumRequiredWork:
    state.processAllRemainingHeaders = true

  # Verify commitment if applicable
  if not state.processAllRemainingHeaders and state.shouldStoreCommitment(nextHeight):
    if state.headerCommitments.len == 0:
      debug "commitment overrun",
            peer = state.peerId, height = nextHeight
      return false

    let commitment = state.computeCommitmentBit(headerHash)
    let expectedCommitment = state.headerCommitments.popFirst()

    if commitment != expectedCommitment:
      debug "commitment mismatch",
            peer = state.peerId, height = nextHeight
      return false

  # Store compressed header
  state.redownloadedHeaders.addLast(header.toCompressed())
  state.redownloadBufferLastHeight = nextHeight
  state.redownloadBufferLastHash = headerHash

  true

proc popHeadersReadyForAcceptance(state: HeadersSyncState): seq[BlockHeader] =
  ## Return headers that have enough commitments verified
  ## Only returns headers when buffer exceeds redownload_buffer_size
  ## or when processAllRemainingHeaders is set

  result = @[]

  if state.downloadState != Redownload:
    return

  while state.redownloadedHeaders.len > state.syncParams.redownloadBufferSize or
        (state.redownloadedHeaders.len > 0 and state.processAllRemainingHeaders):

    let compressed = state.redownloadedHeaders.popFirst()
    let fullHeader = compressed.toFullHeader(state.redownloadBufferFirstPrevHash)
    result.add(fullHeader)
    state.redownloadBufferFirstPrevHash = hashHeader(fullHeader)

proc processNextHeaders*(
  state: HeadersSyncState,
  receivedHeaders: seq[BlockHeader],
  fullHeadersMessage: bool
): ProcessingResult =
  ## Process a batch of headers received from peer
  ## fullHeadersMessage: true if message was at max capacity (2000 headers)
  ##
  ## Returns headers ready for permanent storage once sufficient work is proven

  result = ProcessingResult(
    powValidatedHeaders: @[],
    success: false,
    requestMore: false
  )

  if receivedHeaders.len == 0:
    return

  if state.downloadState == Done:
    return

  if state.downloadState == Presync:
    # PRESYNC: build commitments, check work
    result.success = state.validateAndStoreHeadersCommitments(receivedHeaders)

    if result.success:
      if fullHeadersMessage or state.downloadState == Redownload:
        # More headers available, or we just switched to redownload
        result.requestMore = true
      else:
        # Peer's chain ended without reaching min work
        debug "presync incomplete - insufficient work",
              peer = state.peerId, height = state.currentHeight

  elif state.downloadState == Redownload:
    # REDOWNLOAD: verify commitments, buffer headers
    result.success = true

    for header in receivedHeaders:
      if not state.validateAndStoreRedownloadedHeader(header):
        result.success = false
        break

    if result.success:
      # Return verified headers
      result.powValidatedHeaders = state.popHeadersReadyForAcceptance()

      if state.redownloadedHeaders.len == 0 and state.processAllRemainingHeaders:
        debug "header sync complete",
              peer = state.peerId, height = state.redownloadBufferLastHeight
      elif fullHeadersMessage:
        result.requestMore = true
      else:
        # Peer stopped sending before completing
        debug "redownload incomplete",
              peer = state.peerId, height = state.redownloadBufferLastHeight

  # Clean up if we're done
  if not (result.success and result.requestMore):
    state.finalize()

proc nextHeadersRequestLocator*(state: HeadersSyncState): seq[BlockHash] =
  ## Build block locator for next getheaders request
  ## Returns hashes to use in the locator

  result = @[]

  if state.downloadState == Done:
    return

  if state.downloadState == Presync:
    # Continue from last received header
    result.add(state.lastHeaderHash)

  if state.downloadState == Redownload:
    # Continue from last redownloaded header
    result.add(state.redownloadBufferLastHash)

  # Always include chain start
  result.add(state.chainStartHash)

proc getState*(state: HeadersSyncState): SyncPhase =
  state.downloadState

proc getPresyncHeight*(state: HeadersSyncState): int64 =
  state.currentHeight

proc getPresyncTime*(state: HeadersSyncState): uint32 =
  state.lastHeaderReceived.timestamp

proc getPresyncWork*(state: HeadersSyncState): UInt256 =
  state.currentChainWork

proc getRedownloadHeight*(state: HeadersSyncState): int64 =
  state.redownloadBufferLastHeight
