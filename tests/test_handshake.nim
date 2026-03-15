## Tests for pre-handshake message rejection and handshake validation
## Phase 16: Reject messages before VERSION/VERACK exchange
## Reference: Bitcoin Core net_processing.cpp ProcessMessage()

import unittest2
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params

suite "pre-handshake message rejection":
  test "version message allowed before handshake":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    # Before any handshake, only VERSION should be allowed
    check peer.handshakeComplete == false
    check peer.versionReceived == false

    check isPreHandshakeMessageAllowed(peer, mkVersion) == true
    check isPreHandshakeMessageAllowed(peer, mkVerack) == false
    check isPreHandshakeMessageAllowed(peer, mkPing) == false
    check isPreHandshakeMessageAllowed(peer, mkInv) == false
    check isPreHandshakeMessageAllowed(peer, mkGetHeaders) == false

  test "negotiation messages allowed after version received":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true

    # After VERSION received, these are allowed
    check isPreHandshakeMessageAllowed(peer, mkVerack) == true
    check isPreHandshakeMessageAllowed(peer, mkWtxidRelay) == true
    check isPreHandshakeMessageAllowed(peer, mkSendAddrV2) == true
    check isPreHandshakeMessageAllowed(peer, mkSendHeaders) == true
    check isPreHandshakeMessageAllowed(peer, mkSendCmpct) == true
    check isPreHandshakeMessageAllowed(peer, mkFeeFilter) == true

    # But not regular messages
    check isPreHandshakeMessageAllowed(peer, mkPing) == false
    check isPreHandshakeMessageAllowed(peer, mkInv) == false
    check isPreHandshakeMessageAllowed(peer, mkGetHeaders) == false
    check isPreHandshakeMessageAllowed(peer, mkBlock) == false

  test "all messages allowed after handshake complete":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.handshakeComplete = true

    check isPreHandshakeMessageAllowed(peer, mkVersion) == true
    check isPreHandshakeMessageAllowed(peer, mkVerack) == true
    check isPreHandshakeMessageAllowed(peer, mkPing) == true
    check isPreHandshakeMessageAllowed(peer, mkInv) == true
    check isPreHandshakeMessageAllowed(peer, mkGetHeaders) == true
    check isPreHandshakeMessageAllowed(peer, mkBlock) == true

  test "validate pre-version messages get misbehavior":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    # Send ping before version
    let result = validatePreHandshakeMessage(peer, mkPing)
    check result == marDropMisbehave
    check peer.misbehaviorScore == ScorePreHandshakeMessage

  test "validate version before version returns accept":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    let result = validatePreHandshakeMessage(peer, mkVersion)
    check result == marAccept
    check peer.misbehaviorScore == 0

  test "duplicate version message gets misbehavior":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true  # First version already received

    let result = validatePreHandshakeMessage(peer, mkVersion)
    check result == marDropMisbehave
    check peer.misbehaviorScore == ScoreDuplicateVersion

  test "redundant verack dropped silently":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true  # Already received verack

    let result = validatePreHandshakeMessage(peer, mkVerack)
    check result == marDropSilent
    check peer.misbehaviorScore == 0  # No misbehavior

  test "wtxidrelay after verack causes disconnect":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true

    let result = validatePreHandshakeMessage(peer, mkWtxidRelay)
    check result == marDisconnect

  test "sendaddrv2 after verack causes disconnect":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true

    let result = validatePreHandshakeMessage(peer, mkSendAddrV2)
    check result == marDisconnect

suite "protocol version validation":
  test "version below minimum rejected":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    let result = validateVersionMessage(peer, 31800'u32, 12345'u64, nil)
    check result == marDisconnect

  test "version at minimum accepted":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    let result = validateVersionMessage(peer, MinProtocolVersion, 12345'u64, nil)
    check result == marAccept
    check peer.versionReceived == true
    check peer.remoteNonce == 12345'u64

  test "modern protocol version accepted":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    let result = validateVersionMessage(peer, 70016'u32, 67890'u64, nil)
    check result == marAccept
    check peer.versionReceived == true

suite "self-connection detection":
  test "self-connection detected on inbound":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    let ourNonce = peer.localNonce

    # Simulate receiving our own nonce back
    proc checkSelfConnect(nonce: uint64): bool =
      nonce != ourNonce  # Return false if it's our nonce

    let result = validateVersionMessage(peer, 70016'u32, ourNonce, checkSelfConnect)
    check result == marDisconnect

  test "non-self-connection accepted":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    let ourNonce = peer.localNonce
    let theirNonce = ourNonce + 1  # Different nonce

    proc checkSelfConnect(nonce: uint64): bool =
      nonce != ourNonce  # Return true if not our nonce

    let result = validateVersionMessage(peer, 70016'u32, theirNonce, checkSelfConnect)
    check result == marAccept

  test "self-connection check only on inbound":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdOutbound)  # Outbound
    let ourNonce = peer.localNonce

    proc checkSelfConnect(nonce: uint64): bool =
      false  # Would trigger self-connect for inbound

    # Outbound connections don't check for self-connection
    let result = validateVersionMessage(peer, 70016'u32, ourNonce, checkSelfConnect)
    check result == marAccept

suite "handshake state tracking":
  test "initial handshake state":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdOutbound)

    check peer.handshakeComplete == false
    check peer.versionReceived == false
    check peer.versionSent == false
    check peer.verackReceived == false
    check peer.verackSent == false
    check peer.localNonce != 0  # Should have a nonce

  test "mark handshake complete":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdOutbound)
    peer.state = psHandshaking

    # Not complete yet
    peer.versionReceived = true
    peer.versionSent = true
    markHandshakeComplete(peer)
    check peer.handshakeComplete == false

    # Still not complete
    peer.verackSent = true
    markHandshakeComplete(peer)
    check peer.handshakeComplete == false

    # Now complete
    peer.verackReceived = true
    markHandshakeComplete(peer)
    check peer.handshakeComplete == true
    check peer.state == psReady

  test "unique nonces for each peer":
    let params = regtestParams()
    let peer1 = newPeer("127.0.0.1", 18444, params, pdOutbound)
    let peer2 = newPeer("127.0.0.1", 18445, params, pdOutbound)

    # Nonces should be different (extremely high probability)
    # Note: This could theoretically fail with 1/(2^64) probability
    check peer1.localNonce != peer2.localNonce

suite "handshake timeout":
  test "timeout not detected when handshake not started":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdOutbound)

    # Handshake hasn't started, so no timeout
    check checkHandshakeTimeout(peer) == false

  test "timeout not detected when handshake complete":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdOutbound)
    peer.handshakeComplete = true

    # Handshake is complete, no timeout possible
    check checkHandshakeTimeout(peer) == false

  test "timeout constant is 60 seconds":
    check HandshakeTimeoutSec == 60

suite "misbehavior score constants":
  test "pre-handshake message score":
    check ScorePreHandshakeMessage == 10'u32

  test "duplicate version score":
    check ScoreDuplicateVersion == 1'u32

  test "minimum protocol version":
    check MinProtocolVersion == 70015'u32

when isMainModule:
  echo "Running handshake tests..."
