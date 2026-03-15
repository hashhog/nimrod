## Tests for ban manager
## Validates persistent ban list with jsony storage

import unittest
import std/[times, os, tables]
import ../src/network/banman

suite "ban manager":
  var testDir: string

  setup:
    testDir = getTempDir() / "nimrod_banman_test_" & $getTime().toUnix()
    createDir(testDir)

  teardown:
    if dirExists(testDir):
      removeDir(testDir)

  test "new ban manager starts empty":
    let bm = newBanManager(testDir)
    check bm.bannedPeers.len == 0
    check bm.listBanned().len == 0

  test "ban adds entry":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    check bm.isBanned("192.168.1.1") == true
    check bm.bannedPeers.len == 1

  test "ban with address:port normalizes":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1:8333", initDuration(hours = 1))
    check bm.isBanned("192.168.1.1") == true
    check bm.isBanned("192.168.1.1:9999") == true  # Same IP, different port

  test "isBanned returns false for non-banned":
    let bm = newBanManager(testDir)
    check bm.isBanned("192.168.1.1") == false

  test "unban removes entry":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    check bm.isBanned("192.168.1.1") == true
    discard bm.unban("192.168.1.1")
    check bm.isBanned("192.168.1.1") == false

  test "clearBanned removes all":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    bm.ban("192.168.1.2", initDuration(hours = 1))
    bm.ban("192.168.1.3", initDuration(hours = 1))
    check bm.bannedPeers.len == 3
    bm.clearBanned()
    check bm.bannedPeers.len == 0

  test "listBanned returns all entries":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    bm.ban("192.168.1.2", initDuration(hours = 1))
    let banned = bm.listBanned()
    check banned.len == 2

  test "persistence saves and loads":
    # Create and save
    block:
      let bm = newBanManager(testDir)
      bm.ban("192.168.1.1", initDuration(hours = 24), brMisbehaving)
      bm.ban("10.0.0.1", initDuration(hours = 12), brManuallyAdded)
      bm.save()

    # Check file exists
    check fileExists(testDir / BanListFileName)

    # Load in new manager
    block:
      let bm = newBanManager(testDir)
      bm.load()
      check bm.bannedPeers.len == 2
      check bm.isBanned("192.168.1.1") == true
      check bm.isBanned("10.0.0.1") == true

  test "expired bans are removed on load":
    # Create with short ban
    block:
      let bm = newBanManager(testDir)
      # Ban until 1 second ago (already expired)
      bm.banAbsolute("192.168.1.1", getTime().toUnix() - 1)
      # Force save
      bm.isDirty = true
      bm.save()

    # Load - expired ban should not be loaded
    block:
      let bm = newBanManager(testDir)
      bm.load()
      check bm.isBanned("192.168.1.1") == false

  test "banAbsolute sets specific time":
    let bm = newBanManager(testDir)
    let futureTime = getTime().toUnix() + 3600  # 1 hour from now
    bm.banAbsolute("192.168.1.1", futureTime, brManuallyAdded)
    check bm.isBanned("192.168.1.1") == true
    let entry = bm.bannedPeers["192.168.1.1"]
    check entry.banUntil == futureTime

  test "getBanTimeRemaining returns correct duration":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    let remaining = bm.getBanTimeRemaining("192.168.1.1")
    # Should be close to 1 hour (allow some margin for test execution time)
    check remaining.inSeconds >= 3500
    check remaining.inSeconds <= 3600

  test "getBanTimeRemaining returns zero for unbanned":
    let bm = newBanManager(testDir)
    let remaining = bm.getBanTimeRemaining("192.168.1.1")
    check remaining.inSeconds == 0

  test "sweepExpired removes old bans":
    let bm = newBanManager(testDir)
    # Add an expired ban directly
    bm.bannedPeers["192.168.1.1"] = BanEntry(
      address: "192.168.1.1",
      banCreated: getTime().toUnix() - 7200,
      banUntil: getTime().toUnix() - 3600,  # Expired 1 hour ago
      reason: brMisbehaving
    )
    check bm.bannedPeers.len == 1
    bm.sweepExpired()
    check bm.bannedPeers.len == 0

  test "normalizeAddress handles IPv4":
    check normalizeAddress("192.168.1.1") == "192.168.1.1"
    check normalizeAddress("192.168.1.1:8333") == "192.168.1.1"
    check normalizeAddress("10.0.0.1:18333") == "10.0.0.1"

  test "normalizeAddress handles IPv6":
    check normalizeAddress("[::1]") == "::1"
    check normalizeAddress("[::1]:8333") == "::1"
    check normalizeAddress("[2001:db8::1]:8333") == "2001:db8::1"

  test "ban reason is preserved":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1), brMisbehaving)
    bm.ban("192.168.1.2", initDuration(hours = 1), brManuallyAdded)

    check bm.bannedPeers["192.168.1.1"].reason == brMisbehaving
    check bm.bannedPeers["192.168.1.2"].reason == brManuallyAdded

  test "longer ban extends existing":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 1))
    let firstBan = bm.bannedPeers["192.168.1.1"].banUntil
    bm.ban("192.168.1.1", initDuration(hours = 2))
    let secondBan = bm.bannedPeers["192.168.1.1"].banUntil
    check secondBan > firstBan

  test "shorter ban does not replace longer":
    let bm = newBanManager(testDir)
    bm.ban("192.168.1.1", initDuration(hours = 2))
    let firstBan = bm.bannedPeers["192.168.1.1"].banUntil
    bm.ban("192.168.1.1", initDuration(hours = 1))
    let secondBan = bm.bannedPeers["192.168.1.1"].banUntil
    check secondBan == firstBan  # Unchanged
