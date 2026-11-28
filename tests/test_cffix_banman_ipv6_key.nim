## cffix-nimrod-banman-ipv6-key: the ban key for a bare IPv6 address must be
## the whole address.
##
## Inbound peers reach the ban manager as `$remoteAddr.address`
## (peermanager.handleInboundConnection), which for an IPv6 peer is a bare,
## unbracketed literal such as "2001:db8::1".  normalizeAddress used to treat
## the text after the last ':' as a port and cut it off, so the ban key became
## "2001:db8:" and a ban on one IPv6 peer also banned (and disconnected) every
## neighbour that differs only in the last group.
##
## Core's BanMan bans an exact CNetAddr (or an explicit subnet); it never
## derives a /112-ish range from a single address.  CNetAddr compares bytes,
## so every spelling of one address (the inbound compressed form, the
## eight-group form anchors.ipToString writes, an upper-case setban argument,
## an IPv4-mapped IPv6 address) must land on one key.

import unittest2
import std/[times, os, tables]
import ../src/network/banman

suite "cffix banman ipv6 key":
  var testDir: string

  setup:
    testDir = getTempDir() / "nimrod_cffix_banman_ipv6_" & $getTime().toUnix() &
      "_" & $getCurrentProcessId()
    createDir(testDir)

  teardown:
    if dirExists(testDir):
      removeDir(testDir)

  test "bare IPv6 address is its own ban key":
    check normalizeAddress("2001:db8::1") == "2001:db8::1"
    check normalizeAddress("fe80::1:2:3:4") == "fe80::1:2:3:4"
    check normalizeAddress("::1") == "::1"
    check normalizeAddress("2001:db8:0:0:0:0:0:8333") == "2001:db8::8333"

  test "banning one bare IPv6 peer does not ban its neighbour":
    let bm = newBanManager(testDir)
    bm.ban("2001:db8::1", initDuration(hours = 1))
    check bm.isBanned("2001:db8::1") == true
    check bm.isBanned("2001:db8::2") == false
    check bm.isBanned("2001:db8::ffff") == false

  test "unban of a neighbour does not lift the ban":
    let bm = newBanManager(testDir)
    bm.ban("2001:db8::1", initDuration(hours = 1))
    check bm.unban("2001:db8::2") == false
    check bm.isBanned("2001:db8::1") == true

  test "control: IPv4 with port strips the port":
    check normalizeAddress("1.2.3.4:8333") == "1.2.3.4"
    check normalizeAddress("1.2.3.4") == "1.2.3.4"

  test "control: bracketed IPv6 with port strips brackets and port":
    check normalizeAddress("[::1]:8333") == "::1"
    check normalizeAddress("[2001:db8::1]:8333") == "2001:db8::1"
    check normalizeAddress("[2001:db8::1]") == "2001:db8::1"

  test "a bracketed v6 ban matches the bare inbound form":
    let bm = newBanManager(testDir)
    bm.ban("[2001:db8::1]:8333", initDuration(hours = 1))
    check bm.isBanned("2001:db8::1") == true
    check bm.isBanned("2001:db8::2") == false

  test "IPv6 text that is not an address is never cut":
    check normalizeAddress("2001:db8::/32") == "2001:db8::/32"
    check normalizeAddress("1.2.3.0/24") == "1.2.3.0/24"
    # Nine groups: not an address, and not IPv4:port or [v6]:port either, so
    # no "port" is stripped from it.
    check normalizeAddress("2001:db8:1:2:3:4:5:6:8333") == "2001:db8:1:2:3:4:5:6:8333"

  test "every spelling of one IPv6 address is one ban key":
    # anchors.ipToString writes all eight groups, zero-padded.
    check normalizeAddress("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    # setban accepts upper case; inbound is lower-case compressed.
    check normalizeAddress("2001:DB8::1") == "2001:db8::1"
    check normalizeAddress("[2001:0DB8::0001]:8333") == "2001:db8::1"
    let bm = newBanManager(testDir)
    bm.ban("2001:DB8::1", initDuration(hours = 1))
    check bm.isBanned("2001:0db8:0000:0000:0000:0000:0000:0001") == true
    check bm.isBanned("2001:db8::1") == true
    check bm.isBanned("2001:db8::2") == false

  test "an IPv4-mapped IPv6 address is keyed as its IPv4 address":
    # Core keeps ::ffff:a.b.c.d as IPv4; master cut it to "::ffff", one key
    # for every mapped peer.
    check normalizeAddress("::ffff:1.2.3.4") == "1.2.3.4"
    let bm = newBanManager(testDir)
    bm.ban("1.2.3.4", initDuration(hours = 1))
    check bm.isBanned("::ffff:1.2.3.4") == true
    check bm.isBanned("::ffff:1.2.3.5") == false

  test "load re-keys a non-canonical entry from banlist.json":
    block:
      let bm = newBanManager(testDir)
      bm.bannedPeers["2001:DB8::1"] = BanEntry(address: "2001:DB8::1",
        banCreated: getTime().toUnix(),
        banUntil: getTime().toUnix() + 3600, reason: brManuallyAdded)
      bm.isDirty = true
      bm.save()
    let bm = newBanManager(testDir)
    bm.load()
    check bm.isBanned("2001:db8::1") == true
    check bm.listBanned().len == 1
    check bm.listBanned()[0].address == "2001:db8::1"
