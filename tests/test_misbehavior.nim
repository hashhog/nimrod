## Tests for peer misbehavior handling
## Validates Bitcoin Core compatible misbehavior tracking.
##
## Core PR #25974 (v24.0): score accumulation was REMOVED — Misbehaving()
## now sets m_should_discourage unconditionally on the first call. nimrod
## mirrors this: misbehaving() sets peer.shouldDisconnect = true and the
## misbehaviorScore field is no longer accumulated (peer.nim:1708-1721).

import unittest2
import std/times
import ../src/network/peer
import ../src/consensus/params

suite "misbehavior scoring":
  test "initial score is zero":
    let params = mainnetParams()
    let peer = newPeer("192.168.1.1", 8333, params)
    check peer.misbehaviorScore == 0
    check peer.shouldDisconnect == false

  test "misbehaving flags peer for discourage (PR #25974)":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "test violation")
    # Any Misbehaving call discourages immediately — no accumulation
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "repeated misbehavior keeps discourage flag (no accumulation)":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 10, "first")
    misbehaving(peer, 20, "second")
    misbehaving(peer, 30, "third")
    # Core removed the score counter; the flag is set exactly once
    check peer.misbehaviorScore == 0
    check peer.shouldDisconnect == true

  test "single low-score violation triggers disconnect flag (PR #25974)":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 1, "minor violation")
    check peer.shouldDisconnect == true

  test "instant ban with high score":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    # Invalid block header = instant discourage
    misbehaving(peer, ScoreInvalidBlockHeader, "invalid block header")
    check peer.shouldDisconnect == true
    check peer.shouldBan() == true

  test "score field stays zero (accumulation removed by PR #25974)":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    misbehaving(peer, 200, "excessive")
    check peer.misbehaviorScore == 0
    check peer.shouldBan() == true

  test "shouldBan mirrors the discourage flag":
    let params = mainnetParams()
    var peer = newPeer("192.168.1.1", 8333, params)
    check peer.shouldBan() == false
    misbehaving(peer, 1, "one violation is enough")
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
