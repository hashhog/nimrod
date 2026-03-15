## Tests for ping timeout handling
## Reference: Bitcoin Core net_processing.cpp MaybeSendPing

import unittest
import std/times
import chronos
import ../src/network/peer
import ../src/consensus/params

suite "ping timeout":
  test "ping not pending initially":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.pingPending == false
    check peer.isPingTimedOut() == false

  test "starting ping sets pending":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startPing()

    check peer.pingPending == true
    check peer.isPingTimedOut() == false  # Just started, not timed out

  test "completing ping clears pending":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startPing()
    check peer.pingPending == true

    peer.completePing()
    check peer.pingPending == false

  test "ping times out after 20 minutes":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startPing()
    check peer.isPingTimedOut() == false

    # Simulate 21 minutes passing
    peer.pingStartTime = chronos.Moment.now() - chronos.minutes(21)

    check peer.isPingTimedOut() == true

  test "ping not timed out at 19 minutes":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startPing()

    # Simulate 19 minutes passing
    peer.pingStartTime = chronos.Moment.now() - chronos.minutes(19)

    check peer.isPingTimedOut() == false

  test "should send ping after 2 minutes":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Initially should not send ping (just connected)
    check peer.shouldSendPing() == false

    # After 3 minutes, should send ping
    peer.pingStartTime = chronos.Moment.now() - chronos.minutes(3)
    check peer.shouldSendPing() == true

  test "should not send ping while one is pending":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Wait long enough to need a ping
    peer.pingStartTime = chronos.Moment.now() - chronos.minutes(3)
    check peer.shouldSendPing() == true

    # Start ping
    peer.startPing()

    # Should not send another while pending
    check peer.shouldSendPing() == false

  test "latency is calculated on pong":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Start ping
    let before = chronos.Moment.now()
    peer.pingStartTime = before - chronos.milliseconds(150)
    peer.pingPending = true

    # Complete ping
    peer.completePing()

    # Latency should be approximately 150ms (within a reasonable margin)
    check peer.latencyMs >= 150
    check peer.latencyMs < 200

suite "headers timeout":
  test "headers request not pending initially":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.headersRequested == false
    check peer.isHeadersRequestTimedOut() == false

  test "starting headers request sets flag":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startHeadersRequest()

    check peer.headersRequested == true
    check peer.isHeadersRequestTimedOut() == false

  test "completing headers request clears flag":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startHeadersRequest()
    check peer.headersRequested == true

    peer.completeHeadersRequest()
    check peer.headersRequested == false

  test "headers request times out after 2 minutes":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startHeadersRequest()
    check peer.isHeadersRequestTimedOut() == false

    # Simulate 3 minutes passing
    peer.headersRequestTime = chronos.Moment.now() - chronos.minutes(3)

    check peer.isHeadersRequestTimedOut() == true

  test "headers request not timed out at 1 minute":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.startHeadersRequest()

    # Simulate 1 minute passing
    peer.headersRequestTime = chronos.Moment.now() - chronos.minutes(1)

    check peer.isHeadersRequestTimedOut() == false

suite "connection age":
  test "new peer has zero connection age":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Just created, so very small age
    let age = peer.connectionAge()
    check age < chronos.seconds(1)

  test "peer has minimum connect time after 30 seconds":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Simulate 40 seconds ago connection
    peer.connectedTime = chronos.Moment.now() - chronos.seconds(40)

    check peer.hasMinimumConnectTime() == true

  test "peer does not have minimum connect time immediately":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    # Just connected
    check peer.hasMinimumConnectTime() == false

suite "peer direction helpers":
  test "outbound peer is outbound":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.isOutbound() == true
    check peer.isInbound() == false

  test "inbound peer is inbound":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdInbound)

    check peer.isOutbound() == false
    check peer.isInbound() == true

suite "blocks in flight tracking":
  test "no blocks in flight initially":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.hasBlocksInFlight() == false
    check peer.blocksInFlight == 0

  test "blocks in flight when count > 0":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    peer.blocksInFlight = 3

    check peer.hasBlocksInFlight() == true

suite "block and tx tracking":
  test "recording block updates time":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    let before = peer.lastBlockTime
    # Small delay
    peer.lastBlockTime = chronos.Moment.now() - chronos.seconds(10)
    let oldTime = peer.lastBlockTime

    peer.recordBlockReceived()

    check peer.lastBlockTime > oldTime

  test "recording tx updates time":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    let before = peer.lastTxTime
    # Small delay
    peer.lastTxTime = chronos.Moment.now() - chronos.seconds(10)
    let oldTime = peer.lastTxTime

    peer.recordTxReceived()

    check peer.lastTxTime > oldTime

  test "best known height updates":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.bestKnownHeight == 0

    peer.updateBestKnownHeight(500)
    check peer.bestKnownHeight == 500

    peer.updateBestKnownHeight(1000)
    check peer.bestKnownHeight == 1000

    # Should not decrease
    peer.updateBestKnownHeight(800)
    check peer.bestKnownHeight == 1000

  test "block announcement recorded":
    let params = regtestParams()
    var peer = newPeer("192.168.1.1", 18444, params, pdOutbound)

    check peer.lastBlockAnnouncement == 0

    let nowUnix = getTime().toUnix()
    peer.recordBlockAnnouncement(nowUnix)

    check peer.lastBlockAnnouncement == nowUnix
