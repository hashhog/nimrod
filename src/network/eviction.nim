## Inbound peer eviction with protections
## Reference: Bitcoin Core node/eviction.cpp SelectNodeToEvict()
##
## When inbound slots are full, evict the "worst" peer while protecting:
## - 4 peers with fastest ping (lowest latency)
## - 4 peers that most recently sent us transactions
## - 4 peers that most recently sent us blocks
## - 8 block-relay-only peers that sent blocks
## - 4 peers from distinct network groups
## - Half of remaining peers by longest connection time
##   (1/4 of those slots reserved for Tor/localhost/I2P/CJDNS)
##
## After protections, evict peer from the netgroup with most connections

import std/[algorithm, tables, sets, times, options, sequtils]
import chronicles
import ./netgroup

type
  ConnectionType* = enum
    ctInbound
    ctOutboundFullRelay
    ctOutboundBlockRelay
    ctFeeler

  EvictionCandidate* = object
    ## Candidate for eviction consideration
    id*: int64                        # Unique peer ID
    address*: string                  # Peer address
    connected*: Time                  # When connected
    minPingTime*: Duration            # Minimum observed ping time
    lastBlockTime*: Time              # Last time peer sent us a block
    lastTxTime*: Time                 # Last time peer sent us a transaction
    relevantServices*: bool           # Has useful services (NODE_NETWORK, NODE_WITNESS)
    relayTxs*: bool                   # Peer relays transactions
    bloomFilter*: bool                # Peer uses bloom filters
    keyedNetGroup*: uint64            # Randomized netgroup ID
    preferEvict*: bool                # Prefer to evict (manually flagged)
    isLocal*: bool                    # Connected via localhost
    netGroup*: NetGroup               # Network group
    noBan*: bool                      # Protected from eviction (whitelisted)
    connType*: ConnectionType         # Connection type

proc `<`(a, b: Time): bool =
  ## Compare times (earlier is less)
  a.toUnix() < b.toUnix()

proc `>`(a, b: Time): bool =
  b < a

# Comparison functions matching Bitcoin Core

proc reverseCompareMinPingTime(a, b: EvictionCandidate): int =
  ## Sort by ping time descending (longest ping first, shortest last)
  ## This protects peers with shortest ping times
  if a.minPingTime > b.minPingTime: -1
  elif a.minPingTime < b.minPingTime: 1
  else: 0

proc reverseCompareTimeConnected(a, b: EvictionCandidate): int =
  ## Sort by connection time descending (most recent first, oldest last)
  ## This protects longest-connected peers
  if a.connected > b.connected: -1
  elif a.connected < b.connected: 1
  else: 0

proc compareNetGroupKeyed(a, b: EvictionCandidate): int =
  ## Sort by keyed netgroup
  if a.keyedNetGroup < b.keyedNetGroup: -1
  elif a.keyedNetGroup > b.keyedNetGroup: 1
  else: 0

proc compareNodeBlockTime(a, b: EvictionCandidate): int =
  ## Sort by last block time ascending (oldest first, newest protected)
  ## Fall through to services and connection time
  if a.lastBlockTime != b.lastBlockTime:
    if a.lastBlockTime < b.lastBlockTime: return -1
    else: return 1
  if a.relevantServices != b.relevantServices:
    if b.relevantServices: return -1
    else: return 1
  # Tie-breaker: most recently connected first
  if a.connected > b.connected: -1
  elif a.connected < b.connected: 1
  else: 0

proc compareNodeTxTime(a, b: EvictionCandidate): int =
  ## Sort by last tx time ascending (oldest first, newest protected)
  if a.lastTxTime != b.lastTxTime:
    if a.lastTxTime < b.lastTxTime: return -1
    else: return 1
  if a.relayTxs != b.relayTxs:
    if b.relayTxs: return -1
    else: return 1
  if a.bloomFilter != b.bloomFilter:
    if a.bloomFilter: return -1
    else: return 1
  # Tie-breaker: most recently connected first
  if a.connected > b.connected: -1
  elif a.connected < b.connected: 1
  else: 0

proc compareNodeBlockRelayOnlyTime(a, b: EvictionCandidate): int =
  ## Sort block-relay-only peers by last block time
  if a.relayTxs != b.relayTxs:
    if a.relayTxs: return -1  # relayTxs=true first (less protected)
    else: return 1
  if a.lastBlockTime != b.lastBlockTime:
    if a.lastBlockTime < b.lastBlockTime: return -1
    else: return 1
  if a.relevantServices != b.relevantServices:
    if b.relevantServices: return -1
    else: return 1
  if a.connected > b.connected: -1
  elif a.connected < b.connected: 1
  else: 0

type
  NetworkProtection = object
    isLocal: bool
    netType: uint8
    count: int

proc compareNodeNetworkTime(isLocal: bool, netType: uint8, a, b: EvictionCandidate): int =
  ## Sort by network/localhost and connection uptime
  ## Candidates near beginning are less protected, near end more protected
  if isLocal and a.isLocal != b.isLocal:
    if b.isLocal: return -1
    else: return 1
  if (a.netGroup.data.len > 0 and a.netGroup.data[0] == netType) !=
     (b.netGroup.data.len > 0 and b.netGroup.data[0] == netType):
    if b.netGroup.data.len > 0 and b.netGroup.data[0] == netType: return -1
    else: return 1
  # Connection time - most recently connected first (less protected)
  if a.connected > b.connected: -1
  elif a.connected < b.connected: 1
  else: 0

proc eraseLastKElements[T](elements: var seq[T], compare: proc(a, b: T): int,
                           k: int, predicate: proc(n: T): bool = nil) =
  ## Sort and erase the last K elements (where predicate is true)
  ## This protects those elements from eviction
  elements.sort(compare)
  let eraseSize = min(k, elements.len)
  var i = elements.len - eraseSize
  var removed = 0
  while i < elements.len and removed < k:
    if predicate == nil or predicate(elements[i]):
      elements.delete(i)
      inc removed
    else:
      inc i

proc protectNoBanConnections*(candidates: var seq[EvictionCandidate]) =
  ## Remove peers with noBan flag (whitelisted)
  candidates.keepItIf(not it.noBan)

proc protectOutboundConnections*(candidates: var seq[EvictionCandidate]) =
  ## Remove outbound connections (only evict inbound)
  candidates.keepItIf(it.connType == ctInbound)

proc protectEvictionCandidatesByRatio*(candidates: var seq[EvictionCandidate]) =
  ## Protect half of remaining peers by longest connection time
  ## Reserve up to half of protected slots for disadvantaged networks
  ## (Tor, localhost, I2P, CJDNS)
  ##
  ## Reference: Bitcoin Core eviction.cpp ProtectEvictionCandidatesByRatio()

  let initialSize = candidates.len
  let totalProtectSize = initialSize div 2

  # Disadvantaged networks to protect
  var networks = @[
    NetworkProtection(isLocal: false, netType: NetCJDNS, count: 0),
    NetworkProtection(isLocal: false, netType: NetI2P, count: 0),
    NetworkProtection(isLocal: true, netType: NetLocal, count: 0),
    NetworkProtection(isLocal: false, netType: NetOnion, count: 0)
  ]

  # Count candidates per network
  for net in networks.mitems:
    for c in candidates:
      if net.isLocal:
        if c.isLocal:
          inc net.count
      else:
        if c.netGroup.data.len > 0 and c.netGroup.data[0] == net.netType:
          inc net.count

  # Sort by ascending count (fewer candidates = higher priority)
  networks.sort(proc(a, b: NetworkProtection): int =
    if a.count < b.count: -1
    elif a.count > b.count: 1
    else: 0
  )

  # Protect up to 25% by disadvantaged network
  let maxProtectByNetwork = totalProtectSize div 2
  var numProtected = 0

  while numProtected < maxProtectByNetwork:
    var numNetworks = 0
    for net in networks:
      if net.count > 0:
        inc numNetworks
    if numNetworks == 0:
      break

    let disadvantagedToProtect = maxProtectByNetwork - numProtected
    let protectPerNetwork = max(disadvantagedToProtect div numNetworks, 1)
    var protectedAtLeastOne = false

    for net in networks.mitems:
      if net.count == 0:
        continue

      let before = candidates.len
      let netIsLocal = net.isLocal
      let netType = net.netType

      candidates.sort(proc(a, b: EvictionCandidate): int =
        compareNodeNetworkTime(netIsLocal, netType, a, b))

      var removed = 0
      var i = candidates.len - 1
      while i >= 0 and removed < protectPerNetwork:
        let c = candidates[i]
        let matches = if netIsLocal: c.isLocal
                      else: c.netGroup.data.len > 0 and c.netGroup.data[0] == netType
        if matches:
          candidates.delete(i)
          inc removed
        dec i

      let after = candidates.len
      if before > after:
        protectedAtLeastOne = true
        let delta = before - after
        numProtected += delta
        if numProtected >= maxProtectByNetwork:
          break
        net.count -= delta

    if not protectedAtLeastOne:
      break

  # Protect remaining slots by longest connection time
  let remainingToProtect = totalProtectSize - numProtected
  if remainingToProtect > 0:
    candidates.sort(reverseCompareTimeConnected)
    let eraseCount = min(remainingToProtect, candidates.len)
    candidates.delete(candidates.len - eraseCount, candidates.len - 1)

proc selectNodeToEvict*(candidates: var seq[EvictionCandidate]): Option[int64] =
  ## Select an inbound peer to evict
  ## Returns the peer ID to evict, or none if no candidate
  ##
  ## Reference: Bitcoin Core node/eviction.cpp SelectNodeToEvict()
  ##
  ## Protection order:
  ## 1. Remove noBan peers (whitelisted)
  ## 2. Remove outbound connections (only evict inbound)
  ## 3. Protect 4 peers by netgroup diversity
  ## 4. Protect 8 peers with lowest ping time
  ## 5. Protect 4 peers with recent tx
  ## 6. Protect up to 8 block-relay-only peers that sent blocks
  ## 7. Protect 4 peers with recent blocks
  ## 8. Protect by ratio (half of remaining)
  ##
  ## Note: With few candidates, many will be protected and none evicted.
  ## This is intentional - we only evict when slots are truly full.

  # Protect noBan peers
  protectNoBanConnections(candidates)

  # Protect outbound connections
  protectOutboundConnections(candidates)

  if candidates.len == 0:
    return none(int64)

  # For small candidate sets, we need to be less aggressive with protection
  # to ensure we can still evict when needed
  let protectCount = max(1, candidates.len div 4)

  # Protect peers by netgroup diversity (up to 4)
  candidates.sort(compareNetGroupKeyed)
  let netgroupProtect = min(protectCount, min(4, candidates.len - 1))
  if netgroupProtect > 0 and candidates.len > netgroupProtect:
    candidates.setLen(candidates.len - netgroupProtect)

  if candidates.len == 0:
    return none(int64)

  # Protect peers with lowest ping time (up to 8)
  candidates.sort(reverseCompareMinPingTime)
  let pingProtect = min(protectCount, min(8, candidates.len - 1))
  if pingProtect > 0 and candidates.len > pingProtect:
    candidates.setLen(candidates.len - pingProtect)

  if candidates.len == 0:
    return none(int64)

  # Protect peers that most recently sent transactions (up to 4)
  candidates.sort(compareNodeTxTime)
  let txProtect = min(protectCount, min(4, candidates.len - 1))
  if txProtect > 0 and candidates.len > txProtect:
    candidates.setLen(candidates.len - txProtect)

  if candidates.len == 0:
    return none(int64)

  # Protect block-relay-only peers that sent blocks (up to 8)
  candidates.sort(compareNodeBlockRelayOnlyTime)
  var blockRelayProtect = 0
  var i = candidates.len - 1
  while i >= 0 and blockRelayProtect < min(8, candidates.len - 1) and candidates.len > 1:
    let c = candidates[i]
    if not c.relayTxs and c.relevantServices:
      candidates.delete(i)
      inc blockRelayProtect
    dec i

  if candidates.len == 0:
    return none(int64)

  # Protect peers that most recently sent blocks (up to 4)
  candidates.sort(compareNodeBlockTime)
  let blockProtect = min(protectCount, min(4, candidates.len - 1))
  if blockProtect > 0 and candidates.len > blockProtect:
    candidates.setLen(candidates.len - blockProtect)

  if candidates.len == 0:
    return none(int64)

  # Protect by ratio (disadvantaged networks and longest connected)
  # Only apply if we have enough candidates
  if candidates.len > 4:
    protectEvictionCandidatesByRatio(candidates)

  if candidates.len == 0:
    return none(int64)

  # If any remaining are preferred for eviction, only consider those
  let hasPreferred = candidates.anyIt(it.preferEvict)
  if hasPreferred:
    candidates.keepItIf(it.preferEvict)

  # Identify netgroup with most connections and youngest member
  var netgroupCounts: Table[uint64, seq[EvictionCandidate]]
  for c in candidates:
    if c.keyedNetGroup notin netgroupCounts:
      netgroupCounts[c.keyedNetGroup] = @[]
    netgroupCounts[c.keyedNetGroup].add(c)

  var mostConnections = 0
  var mostConnectionsTime: Time
  var targetNetgroup: uint64 = 0

  for netgroup, members in netgroupCounts:
    # Sort members by connection time to find youngest
    var sortedMembers = members
    sortedMembers.sort(proc(a, b: EvictionCandidate): int =
      if a.connected > b.connected: -1
      elif a.connected < b.connected: 1
      else: 0)

    let groupTime = sortedMembers[0].connected
    if members.len > mostConnections or
       (members.len == mostConnections and groupTime > mostConnectionsTime):
      mostConnections = members.len
      mostConnectionsTime = groupTime
      targetNetgroup = netgroup

  # Evict the most recently connected peer from the largest netgroup
  var targetCandidates = netgroupCounts[targetNetgroup]
  targetCandidates.sort(proc(a, b: EvictionCandidate): int =
    if a.connected > b.connected: -1
    elif a.connected < b.connected: 1
    else: 0)

  return some(targetCandidates[0].id)

proc newEvictionCandidate*(id: int64, address: string, netgroupKey: uint64): EvictionCandidate =
  ## Create a new eviction candidate with defaults
  let ip = parseIpAddr(address)
  result = EvictionCandidate(
    id: id,
    address: address,
    connected: getTime(),
    minPingTime: initDuration(seconds = 60),  # High default
    lastBlockTime: Time(),  # epoch
    lastTxTime: Time(),
    relevantServices: true,
    relayTxs: true,
    bloomFilter: false,
    keyedNetGroup: getKeyedNetGroup(ip, netgroupKey),
    preferEvict: false,
    isLocal: ip.isLocal(),
    netGroup: getNetGroup(ip),
    noBan: false,
    connType: ctInbound
  )
