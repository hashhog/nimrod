## Tests for peer misbehavior scoring
## Validates Bitcoin Core compatible misbehavior tracking

import unittest
import std/times
import ../src/network/peer
import ../src/consensus/params

suite "misbehavior scoring":
  test "initial score is zero":
    let params = mainnetParams()
    let peer = newPeer("192.168.1.1", 8333, params)
    check peer.misbehaviorScore == 0
    check peer.shouldDisconnect == false

  test "misbehaving adds score":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "test violation")
    check peer.misbehaviorScore == 10
    check peer.shouldDisconnect == false

  test "scores accumulate":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "first")
    misbehaving(peer, 20, "second")
    misbehaving(peer, 30, "third")
    check peer.misbehaviorScore == 60
    check peer.shouldDisconnect == false

  test "threshold triggers disconnect flag":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 50, "first")
    check peer.shouldDisconnect == false
    misbehaving(peer, 50, "second - reaches threshold")
    check peer.misbehaviorScore == 100
    check peer.shouldDisconnect == true

  test "instant ban with high score":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    # Invalid block header = 100 points = instant ban
    misbehaving(peer, ScoreInvalidBlockHeader, "invalid block header")
    check peer.misbehaviorScore == 100
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "score capped at threshold":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 200, "excessive")
    check peer.misbehaviorScore == 100  # Capped at threshold

  test "shouldBan returns true at threshold":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    check peer.shouldBan() == false
    misbehaving(peer, 99, "almost there")
    check peer.shouldBan() == false
    misbehaving(peer, 1, "one more")
    check peer.shouldBan() == true

  test "resetMisbehavior clears score":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 100, "bad peer")
    check peer.shouldBan() == true
    check peer.shouldDisconnect == true
    resetMisbehavior(peer)
    check peer.misbehaviorScore == 0
    check peer.shouldDisconnect == false
    check peer.shouldBan() == false

  test "score constants are correct":
    # Match Bitcoin Core's scoring values
    check ScoreInvalidBlockHeader == 100
    check ScoreInvalidBlock == 100
    check ScoreInvalidTransaction == 10
    check ScoreUnsolicitedMessage == 20
    check ScoreProtocolViolation == 10
    check ScoreInvalidHeaders == 100
    check MisbehaviorThreshold == 100
