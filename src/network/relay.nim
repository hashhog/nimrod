## Inventory trickling and relay management
## Batches and randomizes transaction announcements for privacy and bandwidth efficiency
## Blocks are always relayed immediately; transactions use Poisson-distributed delays
##
## BIP133 feefilter: peers announce their minimum fee rate, senders skip
## transactions below threshold. Prevents bandwidth waste for low-fee txs.
##
## Reference: Bitcoin Core net_processing.cpp SendMessages(), MaybeSendFeefilter()

import std/[tables, random, math, algorithm, sets]
import chronos
import chronicles
import ./peer
import ./messages
import ../primitives/types

export chronicles

const
  ## Trickling intervals (Poisson mean)
  OutboundTrickleInterval* = 5.0  ## 5 seconds average for outbound peers
  InboundTrickleInterval* = 2.0   ## 2 seconds average for inbound peers

  ## Maximum inventory items per announcement
  InventoryBroadcastMax* = 1000

  ## Maximum items per inv message (protocol limit)
  MaxInvPerMessage* = 50_000

  ## BIP133 feefilter constants (Bitcoin Core: net_processing.cpp)
  AvgFeefilterBroadcastInterval* = 600.0  ## 10 minutes average between feefilter sends
  MaxFeefilterChangeDelay* = 300.0        ## 5 minutes max delay after significant change

  ## Fee filter hysteresis thresholds to avoid spamming on tiny changes
  ## Bitcoin Core: trigger if currentFilter < 75% or > 133% of last sent
  FeefilterLowThreshold* = 0.75   ## Send update if filter drops to 75% of last
  FeefilterHighThreshold* = 1.33  ## Send update if filter rises to 133% of last

  ## Fee rate constants (in sat/kvB, 1000 sat/kvB = 1 sat/vB)
  DefaultMinRelayFee* = 1000'i64          ## 1000 sat/kvB = 1 sat/vB
  DefaultIncrementalRelayFee* = 1000'i64  ## 1000 sat/kvB = 1 sat/vB

  ## FeeFilterRounder privacy constants
  MaxFilterFeeRate* = 10_000_000.0  ## 10^7 sat/kvB max for fee filter buckets
  FeeFilterSpacing* = 1.1           ## 10% bucket spacing for privacy

type
  ## Transaction info for relay filtering
  TxRelayInfo* = object
    txid*: array[32, byte]
    wtxid*: array[32, byte]
    fee*: int64           ## Fee in satoshis
    vsize*: int           ## Virtual size in vbytes

  ## Inventory item for relay queue
  InvItem* = object
    invType*: InvType
    hash*: array[32, byte]
    fee*: int64           ## Fee in satoshis (for feefilter checking)
    vsize*: int           ## Virtual size in vbytes (for feefilter checking)

  ## FeeFilterRounder quantizes fee rates for privacy
  ## Uses logarithmic buckets with 10% spacing to prevent fingerprinting
  FeeFilterRounder* = object
    feeBuckets*: seq[float64]  ## Pre-computed bucket boundaries

  ## Per-peer relay state
  PeerRelayState* = ref object
    peer*: Peer
    invQueue*: seq[InvItem]           ## Queued transaction inventory
    knownTxs*: seq[array[32, byte]]   ## Recently announced tx hashes (bloom filter substitute)
    knownBlocks*: seq[array[32, byte]] ## Recently announced block hashes
    nextTrickleTime*: Moment          ## Next scheduled trickle flush
    trickleInterval*: float64         ## Poisson mean interval for this peer
    ## BIP133 feefilter state
    feeFilterSent*: int64             ## Last feefilter rate sent to this peer (sat/kvB)
    nextSendFeefilter*: Moment        ## Next scheduled feefilter send time

  ## Relay manager coordinates inventory trickling across all peers
  RelayManager* = ref object
    peerStates*: Table[string, PeerRelayState]
    running*: bool
    trickleLoopFuture: Future[void]
    feeFilterRounder*: FeeFilterRounder
    ## Current mempool minimum fee rate (updated by mempool)
    mempoolMinFeeRate*: int64         ## Current mempool minimum fee in sat/kvB
    isIBD*: bool                      ## Whether we're in initial block download

const
  ## Rolling window for known items (simple substitute for bloom filter)
  MaxKnownItems = 5000

  ## MAX_MONEY in satoshis (used during IBD to reject all tx inv)
  MaxMoney* = 2_100_000_000_000_000'i64

proc peerKey(peer: Peer): string =
  peer.address & ":" & $peer.port

# ============================================================================
# FeeFilterRounder - Privacy quantization of fee rates
# Reference: Bitcoin Core policy/fees/block_policy_estimator.cpp FeeFilterRounder
# ============================================================================

proc newFeeFilterRounder*(minIncrementalFee: int64 = DefaultIncrementalRelayFee): FeeFilterRounder =
  ## Create a FeeFilterRounder with logarithmic bucket spacing
  ## Buckets start at half the minimum incremental fee and go up to MaxFilterFeeRate
  ## with 10% spacing (FeeFilterSpacing = 1.1) for privacy
  result.feeBuckets = @[0.0]

  let minFeeLimit = max(1.0, float64(minIncrementalFee) / 2.0)
  var boundary = minFeeLimit

  while boundary <= MaxFilterFeeRate:
    result.feeBuckets.add(boundary)
    boundary *= FeeFilterSpacing

proc round*(rounder: FeeFilterRounder, currentMinFee: int64): int64 =
  ## Round a fee rate to the nearest bucket for privacy
  ## 2/3 of the time rounds down, 1/3 uses exact bucket boundary
  ## This prevents peers from fingerprinting exact mempool state
  if rounder.feeBuckets.len == 0:
    return currentMinFee

  let feeAsFloat = float64(currentMinFee)

  # Find the first bucket >= currentMinFee using binary search
  var lo = 0
  var hi = rounder.feeBuckets.len
  while lo < hi:
    let mid = (lo + hi) div 2
    if rounder.feeBuckets[mid] < feeAsFloat:
      lo = mid + 1
    else:
      hi = mid

  # lo is now the index of the first bucket >= feeAsFloat, or len if none found
  if lo == rounder.feeBuckets.len:
    # Above all buckets, use the last bucket
    if lo > 0:
      return int64(rounder.feeBuckets[lo - 1])
    return currentMinFee

  if lo == 0:
    # At or below first bucket
    return int64(rounder.feeBuckets[0])

  # 2/3 of the time, round down to the previous bucket
  randomize()
  if rand(2) != 0:  # 2/3 probability (rand(2) returns 0, 1, or 2)
    return int64(rounder.feeBuckets[lo - 1])
  else:
    return int64(rounder.feeBuckets[lo])

# ============================================================================
# PeerRelayState and RelayManager constructors
# ============================================================================

proc newPeerRelayState*(peer: Peer): PeerRelayState =
  ## Create relay state for a peer with appropriate trickle interval
  let interval = case peer.direction
    of pdOutbound: OutboundTrickleInterval
    of pdInbound: InboundTrickleInterval

  let now = Moment.now()
  PeerRelayState(
    peer: peer,
    invQueue: @[],
    knownTxs: @[],
    knownBlocks: @[],
    nextTrickleTime: now,
    trickleInterval: interval,
    feeFilterSent: 0,
    nextSendFeefilter: now  # Will be updated on first send
  )

proc newRelayManager*(): RelayManager =
  RelayManager(
    peerStates: initTable[string, PeerRelayState](),
    running: false,
    feeFilterRounder: newFeeFilterRounder(),
    mempoolMinFeeRate: DefaultMinRelayFee,
    isIBD: true  # Start in IBD mode
  )

proc calculatePoissonDelay*(meanInterval: float64): Duration =
  ## Calculate Poisson-distributed delay: -ln(rand) * mean
  ## This produces exponentially distributed intervals with given mean
  randomize()
  let r = rand(1.0)
  # Avoid ln(0) by clamping to small positive value
  let safeR = max(r, 1e-10)
  let delaySeconds = -ln(safeR) * meanInterval
  # Clamp to reasonable bounds (min 100ms, max 60s)
  let clampedDelay = clamp(delaySeconds, 0.1, 60.0)
  milliseconds(int(clampedDelay * 1000))

# ============================================================================
# BIP133 Feefilter Helper Functions (defined early for forward reference)
# ============================================================================

proc calculateFeeRate*(fee: int64, vsize: int): int64 =
  ## Calculate fee rate in sat/kvB (satoshis per 1000 virtual bytes)
  ## This is the standard Bitcoin fee rate unit used in feefilter
  if vsize <= 0:
    return 0
  # fee * 1000 / vsize gives sat/kvB
  (fee * 1000) div int64(vsize)

proc txMeetsFeefilter*(feeRate: int64, peerFeeFilter: int64): bool =
  ## Check if a transaction fee rate meets the peer's feefilter threshold
  ## feeRate is in sat/kvB (satoshis per 1000 virtual bytes)
  ## Returns true if tx should be announced to peer
  if peerFeeFilter == 0:
    return true  # No feefilter set, relay everything
  feeRate >= peerFeeFilter

proc scheduleNextTrickle(state: PeerRelayState) =
  ## Schedule the next trickle time using Poisson delay
  let delay = calculatePoissonDelay(state.trickleInterval)
  state.nextTrickleTime = Moment.now() + delay

proc addKnownTx*(state: PeerRelayState, hash: array[32, byte]) =
  ## Mark a transaction as known to this peer
  state.knownTxs.add(hash)
  # Trim old entries
  if state.knownTxs.len > MaxKnownItems:
    state.knownTxs.delete(0)

proc addKnownBlock*(state: PeerRelayState, hash: array[32, byte]) =
  ## Mark a block as known to this peer
  state.knownBlocks.add(hash)
  if state.knownBlocks.len > MaxKnownItems:
    state.knownBlocks.delete(0)

proc isKnownTx*(state: PeerRelayState, hash: array[32, byte]): bool =
  ## Check if peer already knows about this transaction
  hash in state.knownTxs

proc isKnownBlock*(state: PeerRelayState, hash: array[32, byte]): bool =
  ## Check if peer already knows about this block
  hash in state.knownBlocks

proc registerPeer*(rm: RelayManager, peer: Peer) =
  ## Register a new peer for relay management
  let key = peerKey(peer)
  if key notin rm.peerStates:
    let state = newPeerRelayState(peer)
    state.scheduleNextTrickle()
    rm.peerStates[key] = state
    debug "registered peer for relay", peer = $peer,
          direction = $peer.direction,
          interval = state.trickleInterval

proc unregisterPeer*(rm: RelayManager, peer: Peer) =
  ## Remove a peer from relay management
  let key = peerKey(peer)
  if key in rm.peerStates:
    rm.peerStates.del(key)
    debug "unregistered peer from relay", peer = $peer

proc queueTxInv*(rm: RelayManager, txHash: array[32, byte],
                 excludePeer: Peer = nil) =
  ## Queue a transaction for relay to all peers (except sender)
  ## Transaction will be trickled according to per-peer schedule
  ## Note: This version does not check feefilter. Use queueTxInvWithFee for
  ## feefilter-aware relay.
  let item = InvItem(invType: invWitnessTx, hash: txHash, fee: 0, vsize: 0)

  for key, state in rm.peerStates.mpairs:
    # Skip the peer that sent us this tx
    if excludePeer != nil and state.peer == excludePeer:
      continue

    # Skip if peer already knows this tx
    if state.isKnownTx(txHash):
      continue

    # Add to queue
    state.invQueue.add(item)
    trace "queued tx inv", peer = $state.peer, hash = $txHash

proc relayBlockImmediate*(rm: RelayManager, blockHash: array[32, byte],
                          excludePeer: Peer = nil) {.async.} =
  ## Relay a block immediately to all peers (no trickling)
  ## Blocks are always announced immediately for fast propagation
  let inv = @[InvVector(invType: invBlock, hash: blockHash)]
  let msg = newInv(inv)

  for key, state in rm.peerStates.mpairs:
    # Skip sender
    if excludePeer != nil and state.peer == excludePeer:
      continue

    # Skip if peer already knows this block
    if state.isKnownBlock(blockHash):
      continue

    # Mark as known
    state.addKnownBlock(blockHash)

    # Send immediately
    if state.peer.isConnected() and state.peer.handshakeComplete:
      try:
        await state.peer.sendMessage(msg)
        debug "relayed block inv", peer = $state.peer, hash = $blockHash
      except CatchableError as e:
        warn "failed to relay block", peer = $state.peer, error = e.msg

proc flushTrickle(state: PeerRelayState) {.async.} =
  ## Flush queued inventory for a peer
  ## BIP133: Items with fee info are checked against peer's feefilter
  if state.invQueue.len == 0:
    return

  if not state.peer.isConnected() or not state.peer.handshakeComplete:
    return

  # Randomize order for privacy
  randomize()
  shuffle(state.invQueue)

  # Take up to InventoryBroadcastMax items, filtering by feefilter
  let peerFeeFilter = int64(state.peer.feeFilterRate)
  var invVectors: seq[InvVector]
  var newQueue: seq[InvItem]
  var sentCount = 0

  for item in state.invQueue:
    if sentCount >= InventoryBroadcastMax:
      # Keep remaining items in queue
      newQueue.add(item)
      continue

    # Check feefilter for items with fee info
    if item.fee > 0 and item.vsize > 0:
      let feeRate = calculateFeeRate(item.fee, item.vsize)
      if not txMeetsFeefilter(feeRate, peerFeeFilter):
        # Skip this tx - peer doesn't want it
        # Don't add to queue either - it will never meet filter
        trace "dropping tx from trickle queue due to feefilter",
              peer = $state.peer, feeRate = feeRate, peerFilter = peerFeeFilter
        continue

    invVectors.add(InvVector(invType: item.invType, hash: item.hash))
    state.addKnownTx(item.hash)
    inc sentCount

  # Update queue with remaining items
  state.invQueue = newQueue

  if invVectors.len == 0:
    return

  # Send in batches respecting MaxInvPerMessage
  var offset = 0
  while offset < invVectors.len:
    let batchEnd = min(offset + MaxInvPerMessage, invVectors.len)
    let batch = invVectors[offset ..< batchEnd]
    let msg = newInv(batch)

    try:
      await state.peer.sendMessage(msg)
      debug "flushed inv trickle", peer = $state.peer,
            count = batch.len, remaining = state.invQueue.len
    except CatchableError as e:
      warn "failed to flush inv trickle", peer = $state.peer, error = e.msg
      break

    offset = batchEnd

proc trickleLoop(rm: RelayManager) {.async.} =
  ## Main loop that checks peers and flushes trickling queues
  ## Also sends feefilter messages on schedule
  ## Runs every 100ms to check which peers are due for flushing
  const CheckInterval = milliseconds(100)

  while rm.running:
    let now = Moment.now()

    for key, state in rm.peerStates.mpairs:
      # Check if it's time to trickle for this peer
      if now >= state.nextTrickleTime:
        await flushTrickle(state)
        state.scheduleNextTrickle()

      # Check if we should send feefilter (BIP133)
      await rm.maybeSendFeefilter(state)

    await sleepAsync(CheckInterval)

proc start*(rm: RelayManager) =
  ## Start the relay manager's trickle loop
  if rm.running:
    return

  rm.running = true
  rm.trickleLoopFuture = rm.trickleLoop()
  info "relay manager started"

proc stop*(rm: RelayManager) {.async.} =
  ## Stop the relay manager
  if not rm.running:
    return

  rm.running = false
  if rm.trickleLoopFuture != nil:
    await rm.trickleLoopFuture.cancelAndWait()
    rm.trickleLoopFuture = nil

  info "relay manager stopped"

proc getPeerState*(rm: RelayManager, peer: Peer): PeerRelayState =
  ## Get relay state for a peer (for testing/inspection)
  let key = peerKey(peer)
  if key in rm.peerStates:
    return rm.peerStates[key]
  return nil

proc getQueuedCount*(rm: RelayManager, peer: Peer): int =
  ## Get number of queued items for a peer
  let state = rm.getPeerState(peer)
  if state != nil:
    return state.invQueue.len
  return 0

proc getTotalQueuedCount*(rm: RelayManager): int =
  ## Get total queued items across all peers
  for state in rm.peerStates.values:
    result += state.invQueue.len

proc clearQueue*(rm: RelayManager, peer: Peer) =
  ## Clear the queue for a specific peer (for testing)
  let state = rm.getPeerState(peer)
  if state != nil:
    state.invQueue.setLen(0)

proc clearAllQueues*(rm: RelayManager) =
  ## Clear all queues (for testing)
  for state in rm.peerStates.mvalues:
    state.invQueue.setLen(0)

# Convenience proc for immediate relay of transactions (bypasses trickling)
proc relayTxImmediate*(rm: RelayManager, txHash: array[32, byte],
                       excludePeer: Peer = nil) {.async.} =
  ## Relay a transaction immediately to all peers (bypasses trickling)
  ## Use sparingly - normally transactions should be trickled
  let inv = @[InvVector(invType: invWitnessTx, hash: txHash)]
  let msg = newInv(inv)

  for key, state in rm.peerStates.mpairs:
    if excludePeer != nil and state.peer == excludePeer:
      continue

    if state.isKnownTx(txHash):
      continue

    state.addKnownTx(txHash)

    if state.peer.isConnected() and state.peer.handshakeComplete:
      try:
        await state.peer.sendMessage(msg)
      except CatchableError as e:
        warn "failed to relay tx", peer = $state.peer, error = e.msg

# ============================================================================
# BIP133 Feefilter Support
# Reference: Bitcoin Core net_processing.cpp MaybeSendFeefilter()
# ============================================================================

proc setMempoolMinFeeRate*(rm: RelayManager, feeRate: int64) =
  ## Update the mempool minimum fee rate (called when mempool state changes)
  ## feeRate should be in sat/kvB
  rm.mempoolMinFeeRate = max(feeRate, DefaultMinRelayFee)

proc setIBD*(rm: RelayManager, isIBD: bool) =
  ## Set whether we're in initial block download mode
  ## During IBD, we signal MAX_MONEY feefilter to reject all tx announcements
  rm.isIBD = isIBD

proc getCurrentFeefilterValue*(rm: RelayManager): int64 =
  ## Get the current feefilter value we should send to peers
  ## During IBD: MAX_MONEY to reject all tx announcements
  ## Otherwise: rounded mempool min fee rate
  if rm.isIBD:
    return MaxMoney
  rm.feeFilterRounder.round(rm.mempoolMinFeeRate)

proc maybeSendFeefilter*(rm: RelayManager, state: PeerRelayState) {.async.} =
  ## Send feefilter to peer if conditions are met
  ## Reference: Bitcoin Core net_processing.cpp MaybeSendFeefilter()
  ##
  ## Logic:
  ## 1. On regular schedule (avg 10 min): send if value changed
  ## 2. On significant change (>25% drop or >33% rise): reschedule soon
  ## 3. During IBD: send MAX_MONEY to reject all tx announcements
  ## 4. After IBD: immediately send current filter
  if not state.peer.isConnected() or not state.peer.handshakeComplete:
    return

  let now = Moment.now()
  let currentFilter = rm.getCurrentFeefilterValue()

  # After coming out of IBD, immediately send our filter if we had sent MAX_MONEY
  if state.feeFilterSent == MaxMoney and not rm.isIBD:
    state.nextSendFeefilter = now  # Force immediate send

  # Check if it's time to send (regular interval)
  if now >= state.nextSendFeefilter:
    # Always ensure we send at least min relay fee
    let filterToSend = max(currentFilter, DefaultMinRelayFee)

    if filterToSend != state.feeFilterSent:
      try:
        await state.peer.sendFeeFilter(uint64(filterToSend))
        state.feeFilterSent = filterToSend
        trace "sent feefilter", peer = $state.peer, feeRate = filterToSend
      except CatchableError as e:
        warn "failed to send feefilter", peer = $state.peer, error = e.msg

    # Schedule next send with Poisson delay (average 10 minutes)
    let delay = calculatePoissonDelay(AvgFeefilterBroadcastInterval)
    state.nextSendFeefilter = now + delay

  else:
    # Check for significant change that warrants early update (hysteresis)
    # Trigger if currentFilter < 75% or > 133% of last sent
    let hasSignificantChange =
      state.feeFilterSent > 0 and (
        float64(currentFilter) < float64(state.feeFilterSent) * FeefilterLowThreshold or
        float64(currentFilter) > float64(state.feeFilterSent) * FeefilterHighThreshold
      )

    if hasSignificantChange:
      # Only reschedule if we're more than 5 minutes away from next send
      let maxChangeDelay = milliseconds(int(MaxFeefilterChangeDelay * 1000))
      if now + maxChangeDelay < state.nextSendFeefilter:
        # Reschedule to within 5 minutes (random)
        randomize()
        let randomDelay = milliseconds(rand(int(MaxFeefilterChangeDelay * 1000)))
        state.nextSendFeefilter = now + randomDelay
        trace "rescheduled feefilter due to significant change",
              peer = $state.peer,
              currentFilter = currentFilter,
              lastSent = state.feeFilterSent

proc handleReceivedFeefilter*(peer: Peer, feeRate: uint64) =
  ## Handle an incoming feefilter message from a peer
  ## Stores the peer's minimum fee rate for filtering outgoing tx announcements
  ## Note: This is called from message handling code, not relay.nim
  peer.feeFilterRate = feeRate
  trace "received feefilter", peer = $peer, feeRate = feeRate

proc sendFeefilterToAllPeers*(rm: RelayManager) {.async.} =
  ## Send feefilter update to all connected peers
  ## Called periodically or when mempool min fee changes significantly
  for key, state in rm.peerStates.mpairs:
    await rm.maybeSendFeefilter(state)

# ============================================================================
# Transaction relay with feefilter checking
# ============================================================================

proc queueTxInvWithFee*(rm: RelayManager, txHash: array[32, byte],
                        fee: int64, vsize: int,
                        excludePeer: Peer = nil) =
  ## Queue a transaction for relay with fee info for feefilter checking
  ## Transactions below peer's feefilter are skipped
  let feeRate = calculateFeeRate(fee, vsize)
  let item = InvItem(invType: invWitnessTx, hash: txHash, fee: fee, vsize: vsize)

  for key, state in rm.peerStates.mpairs:
    # Skip the peer that sent us this tx
    if excludePeer != nil and state.peer == excludePeer:
      continue

    # Skip if peer already knows this tx
    if state.isKnownTx(txHash):
      continue

    # BIP133: Check peer's feefilter before queueing
    let peerFeeFilter = int64(state.peer.feeFilterRate)
    if not txMeetsFeefilter(feeRate, peerFeeFilter):
      trace "skipping tx inv due to feefilter",
            peer = $state.peer,
            txFeeRate = feeRate,
            peerFilter = peerFeeFilter
      continue

    # Add to queue
    state.invQueue.add(item)
    trace "queued tx inv", peer = $state.peer, hash = $txHash, feeRate = feeRate

proc relayTxImmediateWithFee*(rm: RelayManager, txHash: array[32, byte],
                              fee: int64, vsize: int,
                              excludePeer: Peer = nil) {.async.} =
  ## Relay a transaction immediately with feefilter checking
  let feeRate = calculateFeeRate(fee, vsize)
  let inv = @[InvVector(invType: invWitnessTx, hash: txHash)]
  let msg = newInv(inv)

  for key, state in rm.peerStates.mpairs:
    if excludePeer != nil and state.peer == excludePeer:
      continue

    if state.isKnownTx(txHash):
      continue

    # BIP133: Check peer's feefilter
    let peerFeeFilter = int64(state.peer.feeFilterRate)
    if not txMeetsFeefilter(feeRate, peerFeeFilter):
      trace "skipping immediate tx relay due to feefilter",
            peer = $state.peer,
            txFeeRate = feeRate,
            peerFilter = peerFeeFilter
      continue

    state.addKnownTx(txHash)

    if state.peer.isConnected() and state.peer.handshakeComplete:
      try:
        await state.peer.sendMessage(msg)
        trace "relayed tx immediately", peer = $state.peer, feeRate = feeRate
      except CatchableError as e:
        warn "failed to relay tx", peer = $state.peer, error = e.msg

# ============================================================================
# Incremental Relay Fee Helper
# Reference: Bitcoin Core policy/rbf.cpp PaysForRBF()
# ============================================================================

proc checkIncrementalRelayFee*(originalFees: int64, replacementFees: int64,
                               replacementVsize: int,
                               incrementalRelayFee: int64 = DefaultIncrementalRelayFee): tuple[ok: bool, error: string] =
  ## Check if a replacement transaction pays sufficient incremental relay fee
  ## This is Rule #4 of RBF (BIP125): the fee increase must pay for bandwidth
  ##
  ## Args:
  ##   originalFees: Total fees of all transactions being replaced (satoshis)
  ##   replacementFees: Fee of the replacement transaction (satoshis)
  ##   replacementVsize: Virtual size of the replacement transaction (vbytes)
  ##   incrementalRelayFee: Incremental relay fee rate (sat/kvB, default 1000)
  ##
  ## Returns (ok: true, error: "") if check passes, (ok: false, error: message) otherwise

  # Rule #3: New tx must pay higher absolute fee
  if replacementFees <= originalFees:
    return (false, "replacement fee " & $replacementFees &
                   " not higher than original fee " & $originalFees)

  # Rule #4: Additional fee must cover bandwidth cost
  # additional_fee >= incrementalRelayFee * replacementVsize / 1000
  let additionalFee = replacementFees - originalFees
  let requiredAdditionalFee = (incrementalRelayFee * int64(replacementVsize)) div 1000

  if additionalFee < requiredAdditionalFee:
    return (false, "additional fee " & $additionalFee &
                   " < required " & $requiredAdditionalFee &
                   " (incremental relay: " & $incrementalRelayFee & " sat/kvB * " &
                   $replacementVsize & " vB / 1000)")

  (true, "")
