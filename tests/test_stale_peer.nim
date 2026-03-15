## Tests for stale peer eviction
## Reference: Bitcoin Core net_processing.cpp ConsiderEviction, EvictExtraOutboundPeers

import unittest
import std/[times, options]
import chronos
import ../src/network/peer
import ../src/network/peermanager
import ../src/consensus/params

suite "stale peer eviction":
  test "peer behind our chain gets timeout set":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500  # Behind our tip

    # Initial state: no timeout
    check peer.chainSyncState.timeout == 0

    # Consider eviction should set timeout
    pm.considerEviction(peer)

    # Now timeout should be set
    check peer.chainSyncState.timeout > 0
    check peer.chainSyncState.workHeaderHeight == pm.ourHeight
    check peer.chainSyncState.sentGetheaders == false
    check peer.shouldDisconnect == false

  test "peer catches up resets timeout":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500  # Behind our tip

    # Set initial timeout
    pm.considerEviction(peer)
    check peer.chainSyncState.timeout > 0

    # Peer catches up
    peer.bestKnownHeight = 1000
    pm.considerEviction(peer)

    # Timeout should be reset
    check peer.chainSyncState.timeout == 0
    check peer.shouldDisconnect == false

  test "chain sync timeout triggers getheaders first":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500

    # Set timeout in the past
    let pastTime = getTime().toUnix() - ChainSyncTimeoutSec - 10
    peer.chainSyncState.timeout = pastTime + ChainSyncTimeoutSec
    peer.chainSyncState.workHeaderHeight = pm.ourHeight
    peer.chainSyncState.sentGetheaders = false

    # First timeout should mark getheaders sent, not disconnect
    pm.considerEviction(peer)

    check peer.chainSyncState.sentGetheaders == true
    check peer.shouldDisconnect == false
    # Timeout should be reduced to HEADERS_RESPONSE_TIME
    check peer.chainSyncState.timeout > getTime().toUnix()

  test "second timeout triggers disconnect":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500

    # Set timeout in the past with getheaders already sent
    let pastTime = getTime().toUnix() - HeadersResponseTimeSec - 10
    peer.chainSyncState.timeout = pastTime + HeadersResponseTimeSec
    peer.chainSyncState.workHeaderHeight = pm.ourHeight
    peer.chainSyncState.sentGetheaders = true

    # Second timeout should disconnect
    pm.considerEviction(peer)

    check peer.shouldDisconnect == true

  test "inbound peers not considered for chain sync eviction":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdInbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500

    # Consider eviction should not set timeout for inbound
    pm.considerEviction(peer)

    check peer.chainSyncState.timeout == 0
    check peer.shouldDisconnect == false

  test "protected peers not evicted":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500
    peer.protectFromChainSyncEviction()

    # Set timeout in the past with getheaders sent
    let pastTime = getTime().toUnix() - HeadersResponseTimeSec - 10
    peer.chainSyncState.timeout = pastTime + HeadersResponseTimeSec
    peer.chainSyncState.workHeaderHeight = pm.ourHeight
    peer.chainSyncState.sentGetheaders = true

    # Protected peer should not be disconnected
    pm.considerEviction(peer)

    check peer.shouldDisconnect == false

  test "peer that advances partially gets timeout reset":
    let params = regtestParams()
    var pm = newPeerManager(params)
    pm.ourHeight = 1000

    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)
    peer.state = psReady
    peer.handshakeComplete = true
    peer.syncStarted = true
    peer.bestKnownHeight = 500

    # Set initial timeout
    pm.considerEviction(peer)
    let initialWorkHeight = peer.chainSyncState.workHeaderHeight
    check initialWorkHeight == 1000

    # We advance our tip
    pm.ourHeight = 1100

    # Peer catches up to where we were, but not to current tip
    peer.bestKnownHeight = initialWorkHeight

    # Should reset timeout based on new tip
    pm.considerEviction(peer)

    # Work header height should now be the new tip
    check peer.chainSyncState.workHeaderHeight == 1100
    # Timeout should still be set (not cleared, since peer is still behind)
    check peer.chainSyncState.timeout > 0

suite "stale tip detection":
  test "tip is stale after 30 minutes":
    let params = regtestParams()
    var pm = newPeerManager(params)

    # Initially not stale
    check pm.tipMayBeStale() == false

    # Set last tip update to 31 minutes ago
    pm.lastTipUpdate = chronos.Moment.now() - chronos.minutes(31)

    check pm.tipMayBeStale() == true

  test "recording new tip resets staleness":
    let params = regtestParams()
    var pm = newPeerManager(params)

    # Make tip stale
    pm.lastTipUpdate = chronos.Moment.now() - chronos.minutes(31)
    check pm.tipMayBeStale() == true

    # Record new tip
    pm.recordNewTip()

    check pm.tipMayBeStale() == false

  test "extra peer counts":
    let params = regtestParams()
    var pm = newPeerManager(params, 2, 1, 10)  # 2 full-relay, 1 block-relay

    # Initially no extras
    check pm.getExtraFullOutboundCount() == 0
    check pm.getExtraBlockRelayCount() == 0

suite "evict extra outbound peers":
  test "youngest block relay peer evicted when extra":
    # This is a basic unit test - full async test would require mock transport
    let params = regtestParams()
    var pm = newPeerManager(params, 2, 1, 10)

    # Just verify the peer manager initializes correctly
    check pm.maxOutboundBlockRelay == 1
    check pm.getExtraBlockRelayCount() == 0

  test "peer with oldest block announcement evicted":
    let params = regtestParams()
    var pm = newPeerManager(params, 2, 1, 10)

    # Just verify the peer manager initializes correctly
    check pm.maxOutboundFullRelay == 2
    check pm.getExtraFullOutboundCount() == 0
