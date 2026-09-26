## Additional tests for pre-handshake message rejection
## Focus on Bitcoin Core compatibility and edge cases

import unittest2
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params

suite "pre-handshake message rejection (Bitcoin Core compatible)":
  test "non-version message before version handshake":
    # Reference: net_processing.cpp line 3815-3818
    # "Must have a version message before anything else"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    # All these are logged and IGNORED before VERSION — Core returns
    # without Misbehaving() or a disconnect.
    for kind in [mkPing, mkPong, mkAddr, mkInv, mkGetData, mkGetHeaders,
                 mkHeaders, mkBlock, mkTx, mkGetAddr, mkNotFound]:
      var testPeer = newPeer("127.0.0.1", 18444, params, pdInbound)
      let result = validatePreHandshakeMessage(testPeer, kind)
      check result == marDropSilent
      check testPeer.shouldDisconnect == false

  test "unsupported message prior to verack":
    # Reference: net_processing.cpp line 4016-4018
    # "Unsupported message prior to verack"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.versionSent = true
    peer.verackSent = true
    # But verackReceived is false

    # These regular messages are logged and IGNORED before verack — Core
    # "Unsupported message prior to verack" (no disconnect, no misbehaviour).
    for kind in [mkAddr, mkInv, mkGetData, mkGetHeaders, mkHeaders, mkBlock,
                 mkTx, mkPing, mkFeeFilter]:
      var testPeer = newPeer("127.0.0.1", 18444, params, pdInbound)
      testPeer.versionReceived = true
      let result = validatePreHandshakeMessage(testPeer, kind)
      check result == marDropSilent
      check testPeer.shouldDisconnect == false

  test "redundant version message":
    # Reference: net_processing.cpp line 3586-3588
    # "redundant version message from peer"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    # First version is OK
    var result = validatePreHandshakeMessage(peer, mkVersion)
    check result == marAccept
    peer.versionReceived = true

    # Second version is duplicate — ignored, no misbehaviour
    result = validatePreHandshakeMessage(peer, mkVersion)
    check result == marDropSilent
    check peer.shouldDisconnect == false

  test "ignoring redundant verack message":
    # Reference: net_processing.cpp line 3822-3824
    # "ignoring redundant verack message"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true

    let result = validatePreHandshakeMessage(peer, mkVerack)
    check result == marDropSilent
    check peer.shouldDisconnect == false  # no penalty for a redundant verack

  test "wtxidrelay received after verack disconnects":
    # Reference: net_processing.cpp line 3928-3932
    # "wtxidrelay received after verack"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true

    let result = validatePreHandshakeMessage(peer, mkWtxidRelay)
    check result == marDisconnect

  test "sendaddrv2 received after verack disconnects":
    # Reference: net_processing.cpp line 3950-3954
    # "sendaddrv2 received after verack"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    peer.verackReceived = true

    let result = validatePreHandshakeMessage(peer, mkSendAddrV2)
    check result == marDisconnect

suite "protocol version checks":
  test "minimum peer protocol version is Core's 31800":
    # Reference: node/protocol_version.h MIN_PEER_PROTO_VERSION = 31800.
    # Witness is a services question (NODE_WITNESS), not a version floor.
    check MinProtocolVersion == 31800'u32

  test "reject obsolete protocol versions":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)

    # Below Core's MIN_PEER_PROTO_VERSION
    check validateVersionMessage(peer, 31799'u32, 1'u64, nil) == marDisconnect

    var peer2 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer2, 209'u32, 1'u64, nil) == marDisconnect

    # Pre-witness versions at/above the floor are KEPT (Core parity)
    var peer3 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer3, 31800'u32, 1'u64, nil) == marAccept
    var peer4 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer4, 70002'u32, 1'u64, nil) == marAccept

  test "accept witness-compatible versions":
    let params = regtestParams()

    var peer1 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer1, 70015'u32, 1'u64, nil) == marAccept

    var peer2 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer2, 70016'u32, 1'u64, nil) == marAccept

    var peer3 = newPeer("127.0.0.1", 18444, params, pdInbound)
    check validateVersionMessage(peer3, ProtocolVersion, 1'u64, nil) == marAccept

suite "self-connection detection":
  test "self-connection on inbound":
    # Reference: net_processing.cpp line 3649-3653
    # "Disconnect if we connected to ourself"
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    let myNonce = 0xDEADBEEFCAFE'u64

    proc checkSelfConnect(nonce: uint64): bool =
      # Returns false if this is our nonce (self-connection)
      nonce != myNonce

    # Receiving our own nonce back = self-connection
    let result = validateVersionMessage(peer, 70016'u32, myNonce, checkSelfConnect)
    check result == marDisconnect

  test "different nonce accepted":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    let myNonce = 0xDEADBEEFCAFE'u64
    let theirNonce = 0x123456789ABC'u64

    proc checkSelfConnect(nonce: uint64): bool =
      nonce != myNonce

    let result = validateVersionMessage(peer, 70016'u32, theirNonce, checkSelfConnect)
    check result == marAccept

  test "outbound does not check self-connect":
    # Outbound connections don't need self-connect check
    # because we initiated the connection
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdOutbound)

    # Even with a self-connect checker, outbound should pass
    proc alwaysFail(nonce: uint64): bool =
      false  # Would fail for inbound

    let result = validateVersionMessage(peer, 70016'u32, 12345'u64, alwaysFail)
    check result == marAccept

suite "handshake timeout":
  test "handshake timeout is 60 seconds":
    # Reference: Bitcoin Core uses a similar timeout
    check HandshakeTimeoutSec == 60

  test "no timeout if handshake not started":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdOutbound)
    check checkHandshakeTimeout(peer) == false

  test "no timeout after handshake complete":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdOutbound)
    peer.handshakeComplete = true
    check checkHandshakeTimeout(peer) == false

suite "feature negotiation timing":
  test "wtxidrelay allowed between version and verack":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true
    # verackReceived is false

    let result = validatePreHandshakeMessage(peer, mkWtxidRelay)
    check result == marAccept

  test "sendaddrv2 allowed between version and verack":
    let params = regtestParams()
    var peer = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer.versionReceived = true

    let result = validatePreHandshakeMessage(peer, mkSendAddrV2)
    check result == marAccept

  test "sendheaders allowed any time after version":
    let params = regtestParams()

    # Before verack
    var peer1 = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer1.versionReceived = true
    check validatePreHandshakeMessage(peer1, mkSendHeaders) == marAccept

    # After verack (unlike wtxidrelay/sendaddrv2)
    var peer2 = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer2.versionReceived = true
    peer2.verackReceived = true
    check validatePreHandshakeMessage(peer2, mkSendHeaders) == marAccept

  test "feefilter ignored before verack, accepted after":
    let params = regtestParams()

    # Core does not process feefilter before verack ("Unsupported message
    # prior to verack", net_processing.cpp:4010) — ignored, no penalty.
    var peer1 = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer1.versionReceived = true
    check validatePreHandshakeMessage(peer1, mkFeeFilter) == marDropSilent
    check peer1.shouldDisconnect == false

    var peer2 = newPeer("127.0.0.1", 18444, params, pdInbound)
    peer2.versionReceived = true
    peer2.verackReceived = true
    check validatePreHandshakeMessage(peer2, mkFeeFilter) == marAccept

when isMainModule:
  echo "Running pre-handshake tests..."
