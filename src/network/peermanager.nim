## Peer connection management
## Handles peer discovery, connection limits, and peer lifecycle

import std/[tables, sets, sequtils, random, times]
import chronos
import chronicles
import ./peer
import ./messages
import ../consensus/params
import ../primitives/[types, serialize]

type
  PeerManager* = ref object
    params*: ConsensusParams
    peers*: Table[string, Peer]
    maxOutbound*: int
    maxInbound*: int
    seedNodes*: seq[tuple[host: string, port: uint16]]
    bannedPeers*: HashSet[string]
    ourHeight*: int32

proc newPeerManager*(params: ConsensusParams, maxOutbound: int = 8, maxInbound: int = 117): PeerManager =
  result = PeerManager(
    params: params,
    peers: initTable[string, Peer](),
    maxOutbound: maxOutbound,
    maxInbound: maxInbound,
    seedNodes: @[],
    bannedPeers: initHashSet[string](),
    ourHeight: 0
  )

  # Default seed nodes (mainnet)
  if params.network == Mainnet:
    result.seedNodes = @[
      ("seed.bitcoin.sipa.be", 8333'u16),
      ("dnsseed.bluematt.me", 8333'u16),
      ("dnsseed.bitcoin.dashjr.org", 8333'u16),
      ("seed.bitcoinstats.com", 8333'u16),
      ("seed.bitcoin.jonasschnelli.ch", 8333'u16),
      ("seed.btc.petertodd.org", 8333'u16)
    ]
  elif params.network == Testnet3:
    result.seedNodes = @[
      ("testnet-seed.bitcoin.jonasschnelli.ch", 18333'u16),
      ("seed.tbtc.petertodd.org", 18333'u16),
      ("testnet-seed.bluematt.me", 18333'u16)
    ]

proc peerKey(host: string, port: uint16): string =
  host & ":" & $port

proc connectedPeerCount*(pm: PeerManager): int =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result += 1

proc addPeer*(pm: PeerManager, host: string, port: uint16): Future[bool] {.async.} =
  let key = peerKey(host, port)

  if key in pm.bannedPeers:
    return false

  if key in pm.peers:
    return false

  if pm.connectedPeerCount >= pm.maxOutbound:
    return false

  let peer = newPeer(host, port, pm.params)
  pm.peers[key] = peer

  if await peer.connect():
    try:
      await peer.sendVersion(pm.ourHeight)
      return true
    except CatchableError as e:
      error "failed to send version", error = e.msg
      await peer.disconnect()
      pm.peers.del(key)
      return false
  else:
    pm.peers.del(key)
    return false

proc removePeer*(pm: PeerManager, host: string, port: uint16) {.async.} =
  let key = peerKey(host, port)
  if key in pm.peers:
    await pm.peers[key].disconnect()
    pm.peers.del(key)

proc banPeer*(pm: PeerManager, host: string, port: uint16) {.async.} =
  let key = peerKey(host, port)
  pm.bannedPeers.incl(key)
  await pm.removePeer(host, port)

proc getReadyPeers*(pm: PeerManager): seq[Peer] =
  for peer in pm.peers.values:
    if peer.state == psReady:
      result.add(peer)

proc getBestPeer*(pm: PeerManager): Peer =
  ## Get peer with highest reported height
  var best: Peer = nil
  var bestHeight: int32 = -1

  for peer in pm.peers.values:
    if peer.state == psReady and peer.startHeight > bestHeight:
      best = peer
      bestHeight = peer.startHeight

  best

proc connectToSeeds*(pm: PeerManager) {.async.} =
  ## Connect to seed nodes
  randomize()
  var shuffled = pm.seedNodes
  shuffle(shuffled)

  for (host, port) in shuffled:
    if pm.connectedPeerCount >= pm.maxOutbound:
      break
    discard await pm.addPeer(host, port)

proc maintainConnections*(pm: PeerManager) {.async.} =
  ## Periodic maintenance of peer connections
  # Remove stale peers
  var toRemove: seq[string]
  for key, peer in pm.peers:
    if peer.state == psDisconnected:
      toRemove.add(key)
    elif peer.state == psReady and getTime() - peer.lastSeen > initDuration(minutes = 30):
      try:
        await peer.sendPing()
      except CatchableError:
        toRemove.add(key)

  for key in toRemove:
    pm.peers.del(key)

  # Try to maintain minimum connections
  if pm.connectedPeerCount < pm.maxOutbound div 2:
    await pm.connectToSeeds()

proc broadcastTransaction*(pm: PeerManager, tx: Transaction) {.async.} =
  ## Broadcast a transaction to all ready peers
  let msg = newTxMsg(tx)
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast tx", peer = $peer, error = e.msg

proc broadcastInventory*(pm: PeerManager, inventory: seq[InvVector]) {.async.} =
  ## Broadcast inventory to all ready peers
  let msg = newInv(inventory)
  for peer in pm.getReadyPeers():
    try:
      await peer.sendMessage(msg)
    except CatchableError as e:
      debug "failed to broadcast inv", peer = $peer, error = e.msg
