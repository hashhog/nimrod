## Tests for anchor connection persistence
## Reference: Bitcoin Core net.cpp ANCHORS_DATABASE_FILENAME

import unittest
import std/[os, times, options, strutils]
import ../src/network/anchors
import ../src/network/netgroup
import ../src/primitives/serialize

suite "anchor connections":
  let testDir = getTempDir() / "nimrod_anchor_test"

  setup:
    # Clean up test directory
    if dirExists(testDir):
      removeDir(testDir)
    createDir(testDir)

  teardown:
    if dirExists(testDir):
      removeDir(testDir)

  test "new anchor list is empty":
    let al = newAnchorList(testDir)
    check al.isEmpty()
    check al.count() == 0

  test "add anchor address":
    let al = newAnchorList(testDir)
    al.add(1'u64, [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1], 8333)
    check al.count() == 1
    check not al.isEmpty()

  test "add from string IPv4":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    check al.count() == 1
    let anchor = al.anchors[0]
    # Check IPv4-mapped format
    check anchor.ip[10] == 0xFF
    check anchor.ip[11] == 0xFF
    check anchor.ip[12] == 192
    check anchor.ip[13] == 168
    check anchor.ip[14] == 1
    check anchor.ip[15] == 1

  test "maximum anchors limit":
    let al = newAnchorList(testDir)
    al.addFromString("1.1.1.1", 8333, 1)
    al.addFromString("2.2.2.2", 8333, 1)
    al.addFromString("3.3.3.3", 8333, 1)  # Should replace oldest
    check al.count() == MaxBlockRelayOnlyAnchors  # Should be limited to 2

  test "pop returns and removes anchor":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    check al.count() == 1

    let popped = al.pop()
    check popped.isSome
    check al.count() == 0
    check al.isEmpty()

  test "pop from empty returns none":
    let al = newAnchorList(testDir)
    let popped = al.pop()
    check popped.isNone

  test "save and load":
    # Save
    let al1 = newAnchorList(testDir)
    al1.addFromString("192.168.1.1", 8333, 1)
    al1.addFromString("10.0.0.1", 18333, 9)
    al1.isDirty = true
    al1.save()

    # Load
    let al2 = newAnchorList(testDir)
    let loaded = al2.load()
    check loaded == true
    check al2.count() == 2

    # Verify content
    check al2.anchors[0].port == 8333 or al2.anchors[1].port == 8333
    check al2.anchors[0].port == 18333 or al2.anchors[1].port == 18333

  test "load nonexistent file returns false":
    let al = newAnchorList(testDir / "nonexistent")
    let loaded = al.load()
    check loaded == false
    check al.isEmpty()

  test "clear anchors":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    al.addFromString("10.0.0.1", 18333, 9)
    check al.count() == 2

    al.clear()
    check al.isEmpty()
    check al.isDirty == true

  test "duplicate anchors not added":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    al.addFromString("192.168.1.1", 8333, 1)  # Duplicate
    check al.count() == 1

  test "different ports are different anchors":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    al.addFromString("192.168.1.1", 18333, 1)  # Different port
    check al.count() == 2

  test "ipToString for IPv4-mapped":
    let ip: array[16, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1]
    let s = ipToString(ip)
    check s == "192.168.1.1"

  test "ipToString for IPv6":
    let ip: array[16, byte] = [0x20'u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    let s = ipToString(ip)
    check s.contains("2001")
    check s.contains("0db8")

  test "getCurrentBlockRelayOnlyAddresses":
    let addresses = @[
      ("192.168.1.1", 8333'u16, 1'u64),
      ("10.0.0.1", 18333'u16, 9'u64)
    ]
    let anchors = getCurrentBlockRelayOnlyAddresses(addresses)
    check anchors.len == 2
    check anchors[0].port == 8333
    check anchors[1].port == 18333

  test "getCurrentBlockRelayOnlyAddresses limits to max":
    let addresses = @[
      ("1.1.1.1", 8333'u16, 1'u64),
      ("2.2.2.2", 8333'u16, 1'u64),
      ("3.3.3.3", 8333'u16, 1'u64),
      ("4.4.4.4", 8333'u16, 1'u64)
    ]
    let anchors = getCurrentBlockRelayOnlyAddresses(addresses)
    check anchors.len == MaxBlockRelayOnlyAnchors

  test "serialization roundtrip":
    let original = AnchorAddress(
      services: 0x0409'u64,
      ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4],
      port: 8333,
      timestamp: 1234567890
    )

    let serialized = serialize(original)
    var r = BinaryReader(data: serialized, pos: 0)
    let deserialized = deserializeAnchor(r)

    check deserialized.services == original.services
    check deserialized.ip == original.ip
    check deserialized.port == original.port
    check deserialized.timestamp == original.timestamp

  test "delete anchors file":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    al.isDirty = true
    al.save()

    check fileExists(al.anchorsPath())

    al.delete()

    check not fileExists(al.anchorsPath())
    check al.isEmpty()

  test "anchors file format has correct magic":
    let al = newAnchorList(testDir)
    al.addFromString("192.168.1.1", 8333, 1)
    al.isDirty = true
    al.save()

    let content = readFile(al.anchorsPath())
    check content.len >= 4
    check content[0] == 'a'
    check content[1] == 'n'
    check content[2] == 'c'
    check content[3] == 'h'

  test "timestamp is set on add":
    let al = newAnchorList(testDir)
    let beforeAdd = getTime().toUnix()
    al.addFromString("192.168.1.1", 8333, 1)
    let afterAdd = getTime().toUnix()

    check al.anchors[0].timestamp >= beforeAdd
    check al.anchors[0].timestamp <= afterAdd

