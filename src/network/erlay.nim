## BIP330 Erlay - Efficient Transaction Relay via Set Reconciliation
##
## Erlay is a bandwidth-efficient transaction relay protocol that uses
## Minisketch set reconciliation instead of full inventory flooding.
##
## Protocol flow:
## 1. Negotiation: exchange sendtxrcncl messages during handshake
## 2. Short ID computation: SipHash(salt1 xor salt2, wtxid) truncated to 32 bits
## 3. Set reconciliation: periodically exchange sketches to find missing txs
## 4. Fallback: for large differences, fall back to regular inv flooding
##
## Reference: BIP-330 https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki
## Reference: Bitcoin Core /src/node/txreconciliation.cpp

import std/[tables, random, hashes, options]
import chronos
import chronicles
import ../primitives/[types, serialize]
import ../crypto/[siphash, hashing, minisketch]

const
  ## Supported transaction reconciliation protocol version
  TxReconciliationVersion* = 1'u32

  ## BIP-330 static salt used for tagged hash
  ReconStaticSalt = "Tx Relay Salting"

  ## Maximum number of short IDs in a single reconciliation round
  MaxReconciliationShortIds* = 5000

  ## Sketch capacity for initial reconciliation (number of differences)
  DefaultSketchCapacity* = 32

  ## Extension round sketch capacity multiplier
  ExtensionCapacityMultiplier* = 2

  ## Reconciliation interval for outbound peers (initiators)
  ## Bitcoin Core: ~2 seconds
  OutboundReconIntervalMs* = 2000

  ## Reconciliation interval for inbound peers (responders request sketches)
  ## Actually, responders don't initiate - initiators request from them
  ## This is for rate limiting inbound requests
  InboundReconIntervalMs* = 8000

  ## False positive bits for sketch capacity calculation
  ReconciliationFpBits* = 16'u32

type
  ReconciliationRegisterResult* = enum
    ## Result of peer registration
    rrNotFound           ## Peer was not pre-registered
    rrSuccess            ## Successfully registered
    rrAlreadyRegistered  ## Peer was already registered
    rrProtocolViolation  ## Protocol violation (e.g., version < 1)

  ReconciliationRole* = enum
    ## Role in reconciliation (determined by connection direction)
    rrInitiator  ## We request sketches (outbound connections)
    rrResponder  ## We send sketches when requested (inbound connections)

  ReconciliationPhase* = enum
    ## Current phase of reconciliation for a peer
    rpIdle           ## No reconciliation in progress
    rpRequested      ## We sent REQRECON, waiting for sketch
    rpExtension      ## Extension round after initial failure
    rpFailed         ## Reconciliation failed, fallback to inv

  TxReconciliationState* = object
    ## Per-peer reconciliation state
    role*: ReconciliationRole     ## Our role with this peer
    k0*, k1*: uint64              ## SipHash keys from combined salt
    localSalt*: uint64            ## Our salt contribution
    remoteSalt*: uint64           ## Peer's salt contribution
    phase*: ReconciliationPhase   ## Current reconciliation phase
    pendingSet*: seq[uint64]      ## Short IDs of transactions to reconcile
    lastReconTime*: chronos.Moment  ## Last reconciliation time
    extensionUsed*: bool          ## Whether extension round was used

  TxReconciliationTracker* = object
    ## Tracks reconciliation state for all peers
    ## Reference: Bitcoin Core TxReconciliationTracker
    version: uint32
    states: Table[int64, TxReconciliationState]  ## NodeId -> state
    preSalts: Table[int64, uint64]  ## NodeId -> local salt (pre-registration)

# ============================================================================
# Salt computation (BIP-330)
# ============================================================================

proc computeReconSalt*(salt1, salt2: uint64): array[32, byte] =
  ## Compute the combined salt using tagged hash
  ## Reference: BIP-330 and Bitcoin Core ComputeSalt()
  ##
  ## TaggedHash("Tx Relay Salting", min(salt1, salt2) || max(salt1, salt2))

  # Compute the tag hash (SHA256(tag) || SHA256(tag))
  let tagHash = sha256Single(cast[seq[byte]](ReconStaticSalt))
  var taggedInput: seq[byte]
  taggedInput.add(tagHash)
  taggedInput.add(tagHash)

  # Append salts in ascending order
  var w = BinaryWriter()
  w.writeUint64LE(min(salt1, salt2))
  w.writeUint64LE(max(salt1, salt2))
  taggedInput.add(w.data)

  # Final SHA256
  result = sha256Single(taggedInput)

proc extractSipHashKeys*(salt: array[32, byte]): (uint64, uint64) =
  ## Extract k0 and k1 from the 256-bit combined salt
  ## First 64 bits = k0, second 64 bits = k1 (little-endian)
  var k0, k1: uint64
  for i in 0 ..< 8:
    k0 = k0 or (uint64(salt[i]) shl (i * 8))
    k1 = k1 or (uint64(salt[i + 8]) shl (i * 8))
  (k0, k1)

# ============================================================================
# Short ID computation
# ============================================================================

proc computeReconciliationShortId*(k0, k1: uint64, wtxid: TxId): uint64 =
  ## Compute 32-bit short ID for transaction reconciliation
  ## Reference: BIP-330 short ID computation
  ##
  ## ShortID = SipHash-2-4(k0, k1, wtxid) & 0xFFFFFFFF (32-bit truncation)
  let hash = sipHash(k0, k1, array[32, byte](wtxid))
  hash and 0xFFFFFFFF'u64

proc computeReconciliationShortId*(state: TxReconciliationState, wtxid: TxId): uint64 =
  ## Compute short ID using state's keys
  computeReconciliationShortId(state.k0, state.k1, wtxid)

# ============================================================================
# TxReconciliationTracker implementation
# ============================================================================

proc newTxReconciliationTracker*(version: uint32 = TxReconciliationVersion): TxReconciliationTracker =
  ## Create a new transaction reconciliation tracker
  result.version = version
  result.states = initTable[int64, TxReconciliationState]()
  result.preSalts = initTable[int64, uint64]()

proc preRegisterPeer*(tracker: var TxReconciliationTracker, peerId: int64): uint64 =
  ## Pre-register a peer and generate our salt
  ## Returns the local salt to send in sendtxrcncl message
  ## Reference: Bitcoin Core TxReconciliationTracker::PreRegisterPeer()

  randomize()
  let localSalt = uint64(rand(high(int64)))

  # Store for later registration
  tracker.preSalts[peerId] = localSalt

  debug "pre-registered peer for reconciliation", peerId = peerId
  localSalt

proc registerPeer*(tracker: var TxReconciliationTracker, peerId: int64,
                   isPeerInbound: bool, peerVersion: uint32,
                   remoteSalt: uint64): ReconciliationRegisterResult =
  ## Complete peer registration after receiving their salt
  ## Reference: Bitcoin Core TxReconciliationTracker::RegisterPeer()

  # Check if peer was pre-registered
  if peerId notin tracker.preSalts:
    return rrNotFound

  # Check if already registered
  if peerId in tracker.states:
    return rrAlreadyRegistered

  let localSalt = tracker.preSalts[peerId]

  # Version negotiation: use minimum of both versions
  let reconVersion = min(peerVersion, tracker.version)

  # v1 is the lowest valid version
  if reconVersion < 1:
    return rrProtocolViolation

  # Compute combined salt and extract SipHash keys
  let fullSalt = computeReconSalt(localSalt, remoteSalt)
  let (k0, k1) = extractSipHashKeys(fullSalt)

  # Determine role: initiators are outbound connections (we initiate reconciliation)
  let role = if isPeerInbound: rrResponder else: rrInitiator

  # Create state
  var state = TxReconciliationState(
    role: role,
    k0: k0,
    k1: k1,
    localSalt: localSalt,
    remoteSalt: remoteSalt,
    phase: rpIdle,
    pendingSet: @[],
    lastReconTime: chronos.Moment.now(),
    extensionUsed: false
  )

  tracker.states[peerId] = state

  # Remove from pre-registration
  tracker.preSalts.del(peerId)

  debug "registered peer for reconciliation",
        peerId = peerId, role = role, version = reconVersion

  rrSuccess

proc forgetPeer*(tracker: var TxReconciliationTracker, peerId: int64) =
  ## Remove all reconciliation state for a peer
  ## Reference: Bitcoin Core TxReconciliationTracker::ForgetPeer()

  if peerId in tracker.states:
    tracker.states.del(peerId)
    debug "forgot reconciliation state", peerId = peerId

  if peerId in tracker.preSalts:
    tracker.preSalts.del(peerId)

proc isPeerRegistered*(tracker: TxReconciliationTracker, peerId: int64): bool =
  ## Check if a peer is registered for reconciliation
  peerId in tracker.states

proc getPeerState*(tracker: TxReconciliationTracker, peerId: int64): Option[TxReconciliationState] =
  ## Get the reconciliation state for a peer
  if peerId in tracker.states:
    some(tracker.states[peerId])
  else:
    none(TxReconciliationState)

proc updatePeerState*(tracker: var TxReconciliationTracker, peerId: int64,
                       state: TxReconciliationState) =
  ## Update the reconciliation state for a peer
  if peerId in tracker.states:
    tracker.states[peerId] = state

# ============================================================================
# Transaction set management
# ============================================================================

proc addTransaction*(tracker: var TxReconciliationTracker, peerId: int64,
                      wtxid: TxId) =
  ## Add a transaction to the pending reconciliation set for a peer
  if peerId notin tracker.states:
    return

  var state = tracker.states[peerId]
  let shortId = state.computeReconciliationShortId(wtxid)

  # Avoid duplicates
  if shortId notin state.pendingSet:
    state.pendingSet.add(shortId)
    tracker.states[peerId] = state

proc addTransactionToAll*(tracker: var TxReconciliationTracker, wtxid: TxId) =
  ## Add a transaction to all registered peers' pending sets
  for peerId in tracker.states.keys:
    tracker.addTransaction(peerId, wtxid)

proc removeTransaction*(tracker: var TxReconciliationTracker, peerId: int64,
                         wtxid: TxId) =
  ## Remove a transaction from the pending set (e.g., after it's been requested)
  if peerId notin tracker.states:
    return

  var state = tracker.states[peerId]
  let shortId = state.computeReconciliationShortId(wtxid)

  let idx = state.pendingSet.find(shortId)
  if idx >= 0:
    state.pendingSet.del(idx)
    tracker.states[peerId] = state

proc getPendingCount*(tracker: TxReconciliationTracker, peerId: int64): int =
  ## Get the number of pending transactions for a peer
  if peerId in tracker.states:
    tracker.states[peerId].pendingSet.len
  else:
    0

proc clearPendingSet*(tracker: var TxReconciliationTracker, peerId: int64) =
  ## Clear the pending transaction set for a peer
  if peerId in tracker.states:
    var state = tracker.states[peerId]
    state.pendingSet = @[]
    tracker.states[peerId] = state

# ============================================================================
# Sketch operations
# ============================================================================

proc createSketch*(state: TxReconciliationState,
                   capacity: uint = DefaultSketchCapacity): Minisketch =
  ## Create a sketch from the pending transaction set
  ## Uses 32-bit field size as specified in BIP-330

  result = newMinisketch32(capacity)

  for shortId in state.pendingSet:
    result.add(shortId)

proc createSketch*(tracker: TxReconciliationTracker, peerId: int64,
                   capacity: uint = DefaultSketchCapacity): Option[Minisketch] =
  ## Create a sketch for a peer
  if peerId notin tracker.states:
    return none(Minisketch)

  let state = tracker.states[peerId]
  some(state.createSketch(capacity))

proc reconcileSketch*(tracker: var TxReconciliationTracker, peerId: int64,
                       remoteSketch: Minisketch): (seq[uint64], seq[uint64], bool) =
  ## Perform set reconciliation with a remote sketch
  ## Returns (we_have_they_need, we_need_they_have, success)
  ##
  ## Process:
  ## 1. Create our local sketch
  ## 2. Merge (XOR) with remote sketch
  ## 3. Decode to get symmetric difference
  ## 4. Partition into what we have and what we need

  if peerId notin tracker.states:
    return (@[], @[], false)

  let state = tracker.states[peerId]

  # Create local sketch with same capacity
  var localSketch = state.createSketch(remoteSketch.getCapacity())

  # Clone remote sketch for merging (merge modifies the sketch)
  var mergedSketch = remoteSketch.clone()

  # Merge (XOR) - result contains symmetric difference
  let newCapacity = mergedSketch.merge(localSketch)
  if newCapacity == 0:
    # Merge failed (different parameters)
    localSketch.destroy()
    mergedSketch.destroy()
    return (@[], @[], false)

  # Decode the symmetric difference
  let (difference, success) = mergedSketch.decode()

  localSketch.destroy()
  mergedSketch.destroy()

  if not success:
    # Too many differences to decode
    return (@[], @[], false)

  # Partition: elements in our set are ones we have, others we need
  var weHaveTheyNeed: seq[uint64]
  var weNeedTheyHave: seq[uint64]

  for shortId in difference:
    if shortId in state.pendingSet:
      weHaveTheyNeed.add(shortId)
    else:
      weNeedTheyHave.add(shortId)

  (weHaveTheyNeed, weNeedTheyHave, true)

# ============================================================================
# Reconciliation protocol state machine
# ============================================================================

proc shouldRequestReconciliation*(tracker: TxReconciliationTracker,
                                   peerId: int64): bool =
  ## Check if we should initiate reconciliation with a peer
  ## Only initiators (outbound connections) request reconciliation

  if peerId notin tracker.states:
    return false

  let state = tracker.states[peerId]

  # Only initiators request
  if state.role != rrInitiator:
    return false

  # Must be idle
  if state.phase != rpIdle:
    return false

  # Check interval
  let now = chronos.Moment.now()
  let elapsed = now - state.lastReconTime

  elapsed >= chronos.milliseconds(OutboundReconIntervalMs)

proc markReconciliationRequested*(tracker: var TxReconciliationTracker,
                                   peerId: int64) =
  ## Mark that we've sent a reconciliation request
  if peerId in tracker.states:
    var state = tracker.states[peerId]
    state.phase = rpRequested
    state.lastReconTime = chronos.Moment.now()
    tracker.states[peerId] = state

proc markReconciliationComplete*(tracker: var TxReconciliationTracker,
                                  peerId: int64) =
  ## Mark reconciliation as complete
  if peerId in tracker.states:
    var state = tracker.states[peerId]
    state.phase = rpIdle
    state.extensionUsed = false
    tracker.states[peerId] = state

proc markReconciliationFailed*(tracker: var TxReconciliationTracker,
                                peerId: int64) =
  ## Mark reconciliation as failed (need to fall back to flooding)
  if peerId in tracker.states:
    var state = tracker.states[peerId]
    state.phase = rpFailed
    tracker.states[peerId] = state

proc requestExtension*(tracker: var TxReconciliationTracker,
                        peerId: int64): bool =
  ## Request an extension round with larger capacity
  ## Returns false if extension already used
  if peerId notin tracker.states:
    return false

  var state = tracker.states[peerId]

  if state.extensionUsed:
    return false

  state.phase = rpExtension
  state.extensionUsed = true
  tracker.states[peerId] = state

  true

proc isReconciling*(tracker: TxReconciliationTracker, peerId: int64): bool =
  ## Check if we're in an active reconciliation with a peer
  if peerId in tracker.states:
    let state = tracker.states[peerId]
    state.phase in {rpRequested, rpExtension}
  else:
    false

proc getRole*(tracker: TxReconciliationTracker, peerId: int64): Option[ReconciliationRole] =
  ## Get our role with a peer
  if peerId in tracker.states:
    some(tracker.states[peerId].role)
  else:
    none(ReconciliationRole)

# ============================================================================
# Short ID mapping
# ============================================================================

type
  ShortIdMapper* = object
    ## Maps short IDs back to full wtxids
    k0, k1: uint64
    shortIdToWtxid: Table[uint64, TxId]

proc newShortIdMapper*(k0, k1: uint64): ShortIdMapper =
  ## Create a new short ID mapper
  result.k0 = k0
  result.k1 = k1
  result.shortIdToWtxid = initTable[uint64, TxId]()

proc newShortIdMapper*(state: TxReconciliationState): ShortIdMapper =
  ## Create from reconciliation state
  newShortIdMapper(state.k0, state.k1)

proc addTransaction*(mapper: var ShortIdMapper, wtxid: TxId) =
  ## Add a transaction to the mapper
  let shortId = computeReconciliationShortId(mapper.k0, mapper.k1, wtxid)
  mapper.shortIdToWtxid[shortId] = wtxid

proc getWtxid*(mapper: ShortIdMapper, shortId: uint64): Option[TxId] =
  ## Get the wtxid for a short ID
  if shortId in mapper.shortIdToWtxid:
    some(mapper.shortIdToWtxid[shortId])
  else:
    none(TxId)

proc resolveShortIds*(mapper: ShortIdMapper,
                       shortIds: seq[uint64]): (seq[TxId], seq[uint64]) =
  ## Resolve short IDs to wtxids
  ## Returns (resolved, unresolved)
  var resolved: seq[TxId]
  var unresolved: seq[uint64]

  for shortId in shortIds:
    if shortId in mapper.shortIdToWtxid:
      resolved.add(mapper.shortIdToWtxid[shortId])
    else:
      unresolved.add(shortId)

  (resolved, unresolved)
