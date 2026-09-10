## Tests for peer misbehavior scoring
## Validates Bitcoin Core compatible misbehavior tracking.
##
## Core 2022 PR #25974 removed score accumulation: Misbehaving() now sets
## m_should_discourage = true unconditionally, whatever the old point value
## was. nimrod matches that (peer.nim misbehaving() -> shouldDisconnect).
## Assert the flag that actually carries the decision; misbehaviorScore is
## a leftover field that is no longer updated.

import unittest2
import ../src/network/peer
import ../src/consensus/params

suite "misbehavior scoring":
  test "initial score is zero":
    let params = mainnetParams()
    let peer = newPeer("192.168.1.1", 8333, params)
    check peer.misbehaviorScore == 0
    check peer.shouldDisconnect == false

  test "misbehaving immediately discourages (PR #25974)":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "test violation")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "first of several small events already discourages":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "first")
    check peer.shouldDisconnect == true
    misbehaving(peer, 20, "second")
    misbehaving(peer, 30, "third")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "sub-threshold howmuch still disconnects":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 50, "first")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "instant ban with high score":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    # Invalid block header: any Misbehaving call is an instant discourage
    misbehaving(peer, ScoreInvalidBlockHeader, "invalid block header")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "howmuch above old threshold still just discourages":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 200, "excessive")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "shouldBan is true after any misbehaving call":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    check peer.shouldBan() == false
    misbehaving(peer, 1, "one point used to be sub-threshold")
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
    # Historical Bitcoin Core scoring values, still used as log labels
    check ScoreInvalidBlockHeader == 100
    check ScoreInvalidBlock == 100
    check ScoreInvalidTransaction == 10
    check ScoreUnsolicitedMessage == 20
    check ScoreProtocolViolation == 10
    check ScoreInvalidHeaders == 100
    check MisbehaviorThreshold == 100
