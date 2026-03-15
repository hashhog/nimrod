## Relay and inventory trickling tests
## Tests Poisson timing, per-peer queues, block immediate relay, and tx trickling

import unittest2
import std/[random, math, tables]
import chronos
import ../src/network/relay
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params

suite "Poisson delay calculation":
  test "delay is always positive":
    for _ in 0 ..< 100:
      let delay = calculatePoissonDelay(5.0)
      check delay > milliseconds(0)

  test "delay respects minimum bound":
    for _ in 0 ..< 100:
      let delay = calculatePoissonDelay(0.001)  # Very short mean
      check delay >= milliseconds(100)  # Clamped to 100ms minimum

  test "delay respects maximum bound":
    for _ in 0 ..< 100:
      let delay = calculatePoissonDelay(1000.0)  # Very long mean
      check delay <= milliseconds(60_000)  # Clamped to 60s maximum

  test "delays have reasonable distribution around mean":
    # Generate many samples and check mean is roughly correct
    var totalMs: float64 = 0
    let samples = 1000
    let meanInterval = 5.0

    for _ in 0 ..< samples:
      let delay = calculatePoissonDelay(meanInterval)
      totalMs += float64(delay.milliseconds)

    let avgSeconds = (totalMs / float64(samples)) / 1000.0
    # Allow 50% tolerance due to randomness and clamping
    check avgSeconds > meanInterval * 0.5
    check avgSeconds < meanInterval * 1.5

suite "Inventory trickling constants":
  test "outbound interval is 5 seconds":
    check OutboundTrickleInterval == 5.0

  test "inbound interval is 2 seconds":
    check InboundTrickleInterval == 2.0

  test "max broadcast per tick is 1000":
    check InventoryBroadcastMax == 1000

suite "PeerRelayState":
  test "outbound peer gets 5s interval":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)
    check state.trickleInterval == OutboundTrickleInterval

  test "inbound peer gets 2s interval":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdInbound)
    let state = newPeerRelayState(peer)
    check state.trickleInterval == InboundTrickleInterval

  test "queue starts empty":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)
    check state.invQueue.len == 0

  test "known tx tracking":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)

    var txHash: array[32, byte]
    txHash[0] = 0xAB

    check not state.isKnownTx(txHash)
    state.addKnownTx(txHash)
    check state.isKnownTx(txHash)

  test "known block tracking":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)

    var blockHash: array[32, byte]
    blockHash[0] = 0xCD

    check not state.isKnownBlock(blockHash)
    state.addKnownBlock(blockHash)
    check state.isKnownBlock(blockHash)

suite "RelayManager peer registration":
  test "register peer creates state":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)
    check rm.peerStates.len == 1

    let state = rm.getPeerState(peer)
    check state != nil
    check state.peer == peer

  test "unregister peer removes state":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)
    check rm.peerStates.len == 1

    rm.unregisterPeer(peer)
    check rm.peerStates.len == 0

  test "register multiple peers":
    let rm = newRelayManager()
    let peer1 = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let peer2 = newPeer("127.0.0.2", 8333, mainnetParams(), pdInbound)
    let peer3 = newPeer("127.0.0.3", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer1)
    rm.registerPeer(peer2)
    rm.registerPeer(peer3)

    check rm.peerStates.len == 3

suite "Inventory queueing":
  test "queue tx to all peers":
    let rm = newRelayManager()
    let peer1 = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let peer2 = newPeer("127.0.0.2", 8333, mainnetParams(), pdInbound)

    rm.registerPeer(peer1)
    rm.registerPeer(peer2)

    var txHash: array[32, byte]
    txHash[0] = 0x11
    txHash[1] = 0x22

    rm.queueTxInv(txHash)

    check rm.getQueuedCount(peer1) == 1
    check rm.getQueuedCount(peer2) == 1
    check rm.getTotalQueuedCount() == 2

  test "exclude sender from relay":
    let rm = newRelayManager()
    let sender = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let other = newPeer("127.0.0.2", 8333, mainnetParams(), pdInbound)

    rm.registerPeer(sender)
    rm.registerPeer(other)

    var txHash: array[32, byte]
    txHash[0] = 0x33

    rm.queueTxInv(txHash, excludePeer = sender)

    check rm.getQueuedCount(sender) == 0  # Excluded
    check rm.getQueuedCount(other) == 1   # Included

  test "skip known transactions":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)

    var txHash: array[32, byte]
    txHash[0] = 0x44

    # Mark as known first
    let state = rm.getPeerState(peer)
    state.addKnownTx(txHash)

    rm.queueTxInv(txHash)

    check rm.getQueuedCount(peer) == 0  # Not queued because already known

  test "queue multiple transactions":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)

    for i in 0 ..< 100:
      var txHash: array[32, byte]
      txHash[0] = byte(i)
      rm.queueTxInv(txHash)

    check rm.getQueuedCount(peer) == 100

  test "clear queue":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)

    for i in 0 ..< 10:
      var txHash: array[32, byte]
      txHash[0] = byte(i)
      rm.queueTxInv(txHash)

    check rm.getQueuedCount(peer) == 10

    rm.clearQueue(peer)
    check rm.getQueuedCount(peer) == 0

  test "clear all queues":
    let rm = newRelayManager()
    let peer1 = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let peer2 = newPeer("127.0.0.2", 8333, mainnetParams(), pdInbound)

    rm.registerPeer(peer1)
    rm.registerPeer(peer2)

    var txHash: array[32, byte]
    txHash[0] = 0x55
    rm.queueTxInv(txHash)

    check rm.getTotalQueuedCount() == 2

    rm.clearAllQueues()
    check rm.getTotalQueuedCount() == 0

suite "Trickling behavior":
  test "trickle interval set correctly for outbound":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)
    check state.trickleInterval == 5.0

  test "trickle interval set correctly for inbound":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdInbound)
    let state = newPeerRelayState(peer)
    check state.trickleInterval == 2.0

  test "next trickle time is scheduled":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let rm = newRelayManager()

    rm.registerPeer(peer)
    let state = rm.getPeerState(peer)

    # Next trickle time should be set
    let now = Moment.now()
    # Allow some tolerance for timing
    check state.nextTrickleTime >= now

suite "Inventory item types":
  test "tx items use witness tx type":
    let rm = newRelayManager()
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)

    rm.registerPeer(peer)

    var txHash: array[32, byte]
    txHash[0] = 0x66

    rm.queueTxInv(txHash)

    let state = rm.getPeerState(peer)
    check state.invQueue.len == 1
    check state.invQueue[0].invType == invWitnessTx

suite "RelayManager lifecycle":
  test "start and stop":
    let rm = newRelayManager()

    rm.start()
    check rm.running == true

    waitFor rm.stop()
    check rm.running == false

  test "stop when not running":
    let rm = newRelayManager()
    check rm.running == false

    waitFor rm.stop()
    check rm.running == false

  test "double start is safe":
    let rm = newRelayManager()

    rm.start()
    rm.start()  # Should not crash
    check rm.running == true

    waitFor rm.stop()

suite "Known items tracking limits":
  test "known txs list is bounded":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)

    # Add more than MaxKnownItems
    for i in 0 ..< 6000:
      var txHash: array[32, byte]
      txHash[0] = byte(i and 0xFF)
      txHash[1] = byte((i shr 8) and 0xFF)
      state.addKnownTx(txHash)

    # Should be bounded to MaxKnownItems (5000)
    check state.knownTxs.len <= 5000

  test "old items are removed when list grows":
    let peer = newPeer("127.0.0.1", 8333, mainnetParams(), pdOutbound)
    let state = newPeerRelayState(peer)

    # Add a tx we'll track
    var firstTx: array[32, byte]
    firstTx[0] = 0xFF

    state.addKnownTx(firstTx)
    check state.isKnownTx(firstTx)

    # Add many more to push out the first
    for i in 0 ..< 5500:
      var txHash: array[32, byte]
      txHash[0] = byte(i and 0xFF)
      txHash[1] = byte((i shr 8) and 0xFF)
      state.addKnownTx(txHash)

    # First tx should be pushed out
    check not state.isKnownTx(firstTx)

when isMainModule:
  waitFor(chronos.sleepAsync(1.milliseconds))  # Initialize chronos
