## Inventory trickling and relay management
## Batches and randomizes transaction announcements for privacy and bandwidth efficiency
## Blocks are always relayed immediately; transactions use Poisson-distributed delays
##
## Reference: Bitcoin Core net_processing.cpp SendMessages()

import std/[tables, random, math, algorithm]
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

type
  ## Inventory item for relay queue
  InvItem* = object
    invType*: InvType
    hash*: array[32, byte]

  ## Per-peer relay state
  PeerRelayState* = ref object
    peer*: Peer
    invQueue*: seq[InvItem]           ## Queued transaction inventory
    knownTxs*: seq[array[32, byte]]   ## Recently announced tx hashes (bloom filter substitute)
    knownBlocks*: seq[array[32, byte]] ## Recently announced block hashes
    nextTrickleTime*: Moment          ## Next scheduled trickle flush
    trickleInterval*: float64         ## Poisson mean interval for this peer

  ## Relay manager coordinates inventory trickling across all peers
  RelayManager* = ref object
    peerStates*: Table[string, PeerRelayState]
    running*: bool
    trickleLoopFuture: Future[void]

const
  ## Rolling window for known items (simple substitute for bloom filter)
  MaxKnownItems = 5000

proc peerKey(peer: Peer): string =
  peer.address & ":" & $peer.port

proc newPeerRelayState*(peer: Peer): PeerRelayState =
  ## Create relay state for a peer with appropriate trickle interval
  let interval = case peer.direction
    of pdOutbound: OutboundTrickleInterval
    of pdInbound: InboundTrickleInterval

  PeerRelayState(
    peer: peer,
    invQueue: @[],
    knownTxs: @[],
    knownBlocks: @[],
    nextTrickleTime: Moment.now(),
    trickleInterval: interval
  )

proc newRelayManager*(): RelayManager =
  RelayManager(
    peerStates: initTable[string, PeerRelayState](),
    running: false
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
  let item = InvItem(invType: invWitnessTx, hash: txHash)

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
  if state.invQueue.len == 0:
    return

  if not state.peer.isConnected() or not state.peer.handshakeComplete:
    return

  # Randomize order for privacy
  randomize()
  shuffle(state.invQueue)

  # Take up to InventoryBroadcastMax items
  let toSend = min(state.invQueue.len, InventoryBroadcastMax)
  var invVectors: seq[InvVector]

  for i in 0 ..< toSend:
    let item = state.invQueue[i]
    invVectors.add(InvVector(invType: item.invType, hash: item.hash))
    state.addKnownTx(item.hash)

  # Remove sent items from queue
  if toSend >= state.invQueue.len:
    state.invQueue.setLen(0)
  else:
    state.invQueue = state.invQueue[toSend .. ^1]

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
  ## Runs every 100ms to check which peers are due for flushing
  const CheckInterval = milliseconds(100)

  while rm.running:
    let now = Moment.now()

    for key, state in rm.peerStates.mpairs:
      # Check if it's time to trickle for this peer
      if now >= state.nextTrickleTime:
        await flushTrickle(state)
        state.scheduleNextTrickle()

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
