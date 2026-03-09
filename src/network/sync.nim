## Block synchronization
## Initial block download and staying in sync

import std/[options, times, deques]
import chronos
import chronicles
import ./peer
import ./peermanager
import ./messages
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/hashing

type
  SyncState* = enum
    Idle
    DownloadingHeaders
    DownloadingBlocks
    Synced

  BlockSync* = ref object
    pm*: PeerManager
    chainState*: ChainState
    params*: ConsensusParams
    state*: SyncState
    headerQueue*: Deque[BlockHeader]
    blockQueue*: Deque[BlockHash]
    pendingBlocks*: int
    lastSyncTime*: Time

const
  MAX_HEADERS_PER_REQUEST = 2000
  MAX_BLOCKS_IN_FLIGHT = 16

proc newBlockSync*(pm: PeerManager, cs: ChainState, params: ConsensusParams): BlockSync =
  BlockSync(
    pm: pm,
    chainState: cs,
    params: params,
    state: Idle,
    headerQueue: initDeque[BlockHeader](),
    blockQueue: initDeque[BlockHash](),
    pendingBlocks: 0,
    lastSyncTime: getTime()
  )

proc getBlockLocator*(sync: BlockSync): seq[BlockHash] =
  ## Build a block locator for getheaders
  result = @[]
  var height = sync.chainState.bestHeight
  var step = 1

  while height >= 0:
    let blk = sync.chainState.getBlockByHeight(height)
    if blk.isSome:
      let headerBytes = serialize(blk.get().header)
      result.add(BlockHash(doubleSha256(headerBytes)))
    height -= step
    if result.len > 10:
      step *= 2

  # Always include genesis
  result.add(sync.params.genesisBlockHash)

proc requestHeaders*(sync: BlockSync, peer: Peer) {.async.} =
  ## Request headers from peer
  let locator = sync.getBlockLocator()
  let hashStop = BlockHash(default(array[32, byte]))
  await peer.sendGetHeaders(locator, hashStop)
  sync.state = DownloadingHeaders
  info "requesting headers", peer = $peer, locatorLen = locator.len

proc processHeaders*(sync: BlockSync, headers: seq[BlockHeader]): int =
  ## Process received headers, returns number accepted
  var accepted = 0

  for header in headers:
    # Validate header
    let result = checkBlockHeader(header, sync.params)
    if not result.valid:
      warn "invalid header", error = result.error
      continue

    # Add to queue for block download
    sync.headerQueue.addLast(header)
    accepted += 1

  if accepted > 0:
    sync.lastSyncTime = getTime()

  accepted

proc requestBlocks*(sync: BlockSync, peer: Peer) {.async.} =
  ## Request blocks from header queue
  var inventory: seq[InvVector]

  while sync.headerQueue.len > 0 and
        sync.pendingBlocks + inventory.len < MAX_BLOCKS_IN_FLIGHT:
    let header = sync.headerQueue.popFirst()
    let headerBytes = serialize(header)
    let hash = doubleSha256(headerBytes)

    inventory.add(InvVector(
      invType: invBlock,
      hash: hash
    ))
    sync.blockQueue.addLast(BlockHash(hash))

  if inventory.len > 0:
    await peer.sendGetData(inventory)
    sync.pendingBlocks += inventory.len
    sync.state = DownloadingBlocks
    info "requesting blocks", count = inventory.len

proc processBlock*(sync: BlockSync, blk: Block): bool =
  ## Process a received block, returns true if valid
  let checkResult = checkBlock(blk, sync.params)
  if not checkResult.valid:
    warn "invalid block", error = checkResult.error
    return false

  let headerBytes = serialize(blk.header)
  let hash = doubleSha256(headerBytes)
  let height = sync.chainState.bestHeight + 1

  # Use atomic block apply (handles storage, UTXOs, and index atomically)
  sync.chainState.applyBlock(blk, height)

  sync.pendingBlocks -= 1
  if sync.blockQueue.len > 0:
    discard sync.blockQueue.popFirst()

  sync.lastSyncTime = getTime()
  info "processed block", height = height, hash = $BlockHash(hash)
  true

proc isSynced*(sync: BlockSync): bool =
  ## Check if we're caught up
  let bestPeer = sync.pm.getBestPeer()
  if bestPeer == nil:
    return false
  sync.chainState.bestHeight >= bestPeer.startHeight - 1

proc syncLoop*(sync: BlockSync) {.async.} =
  ## Main sync loop
  while true:
    let peer = sync.pm.getBestPeer()
    if peer == nil:
      await sleepAsync(1000.milliseconds)
      continue

    case sync.state
    of Idle:
      if not sync.isSynced():
        await sync.requestHeaders(peer)
      else:
        sync.state = Synced

    of DownloadingHeaders:
      # Wait for headers response
      await sleepAsync(100.milliseconds)

    of DownloadingBlocks:
      if sync.pendingBlocks < MAX_BLOCKS_IN_FLIGHT div 2 and
         sync.headerQueue.len > 0:
        await sync.requestBlocks(peer)
      await sleepAsync(100.milliseconds)

    of Synced:
      # Periodic check for new blocks
      if not sync.isSynced():
        sync.state = Idle
      await sleepAsync(5000.milliseconds)

    # Timeout handling
    if getTime() - sync.lastSyncTime > initDuration(seconds = 60):
      warn "sync timeout, resetting"
      sync.state = Idle
