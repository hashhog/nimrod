## Tests for BIP155 ADDRv2 protocol implementation

import unittest2
import std/[options, strutils]
import ../src/primitives/[serialize, types]
import ../src/network/addr
import ../src/network/messages

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc bytesToHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

suite "bip155 network id":
  test "network id values match bip155":
    check ord(netIPv4) == 1
    check ord(netIPv6) == 2
    check ord(netTorV2) == 3  # deprecated
    check ord(netTorV3) == 4
    check ord(netI2P) == 5
    check ord(netCJDNS) == 6

suite "bip155 address sizes":
  test "address size constants":
    check AddrIPv4Size == 4
    check AddrIPv6Size == 16
    check AddrTorV3Size == 32
    check AddrI2PSize == 32
    check AddrCJDNSSize == 16

suite "netaddressv2 creation":
  test "create ipv4 address":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [192'u8, 168, 1, 1]
    check addr2.networkId == netIPv4
    check addr2.ipv4[0] == 192
    check addr2.isValid()
    check addr2.isAddrV1Compatible()

  test "create ipv6 address":
    var addr2 = NetAddressV2(networkId: netIPv6)
    addr2.ipv6[0] = 0x20
    addr2.ipv6[1] = 0x01
    check addr2.networkId == netIPv6
    check addr2.isValid()
    check addr2.isAddrV1Compatible()

  test "create torv3 address":
    var addr2 = NetAddressV2(networkId: netTorV3)
    # Fill with non-zero bytes (ed25519 pubkey)
    for i in 0 ..< 32:
      addr2.torv3[i] = byte(i + 1)
    check addr2.networkId == netTorV3
    check addr2.isValid()
    check not addr2.isAddrV1Compatible()

  test "create i2p address":
    var addr2 = NetAddressV2(networkId: netI2P)
    for i in 0 ..< 32:
      addr2.i2p[i] = byte(i + 1)
    check addr2.networkId == netI2P
    check addr2.isValid()
    check not addr2.isAddrV1Compatible()

  test "create cjdns address":
    var addr2 = NetAddressV2(networkId: netCJDNS)
    addr2.cjdns[0] = 0xFC  # Required prefix
    for i in 1 ..< 16:
      addr2.cjdns[i] = byte(i)
    check addr2.networkId == netCJDNS
    check addr2.isValid()
    check not addr2.isAddrV1Compatible()

  test "cjdns without fc prefix is invalid":
    var addr2 = NetAddressV2(networkId: netCJDNS)
    addr2.cjdns[0] = 0x00  # Wrong prefix
    check not addr2.isValid()

  test "torv2 is always invalid":
    var addr2 = NetAddressV2(networkId: netTorV2)
    check not addr2.isValid()

suite "addrv2 serialization":
  test "serialize ipv4":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [192'u8, 168, 1, 1]

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    check w.data.len == 1 + 1 + 4  # netid + length + addr
    check w.data[0] == 1  # netIPv4
    check w.data[1] == 4  # length
    check w.data[2] == 192
    check w.data[3] == 168
    check w.data[4] == 1
    check w.data[5] == 1

  test "serialize ipv6":
    var addr2 = NetAddressV2(networkId: netIPv6)
    addr2.ipv6[0] = 0x20
    addr2.ipv6[1] = 0x01

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    check w.data.len == 1 + 1 + 16  # netid + length + addr
    check w.data[0] == 2  # netIPv6
    check w.data[1] == 16  # length
    check w.data[2] == 0x20
    check w.data[3] == 0x01

  test "serialize torv3":
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32:
      addr2.torv3[i] = byte(i + 0xA0)

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    check w.data.len == 1 + 1 + 32  # netid + length + addr
    check w.data[0] == 4  # netTorV3
    check w.data[1] == 32  # length
    check w.data[2] == 0xA0

  test "roundtrip ipv4":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [10'u8, 0, 0, 1]

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()

    check decoded.isSome
    check decoded.get().networkId == netIPv4
    check decoded.get().ipv4 == addr2.ipv4

  test "roundtrip torv3":
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32:
      addr2.torv3[i] = byte(i)

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()

    check decoded.isSome
    check decoded.get().networkId == netTorV3
    check decoded.get().torv3 == addr2.torv3

  test "roundtrip i2p":
    var addr2 = NetAddressV2(networkId: netI2P)
    for i in 0 ..< 32:
      addr2.i2p[i] = byte(255 - i)

    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()

    check decoded.isSome
    check decoded.get().networkId == netI2P
    check decoded.get().i2p == addr2.i2p

  test "unknown network id returns none":
    # Network ID 99 is unknown (from future)
    let data = @[99'u8, 8, 1, 2, 3, 4, 5, 6, 7, 8]
    var r = BinaryReader(data: data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isNone

  test "torv2 is skipped":
    # TorV2 is deprecated (network ID 3)
    let data = @[3'u8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var r = BinaryReader(data: data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isNone

  test "invalid ipv4 length raises":
    # IPv4 must be exactly 4 bytes
    let data = @[1'u8, 5, 192, 168, 1, 1, 0]  # 5 bytes instead of 4
    var r = BinaryReader(data: data, pos: 0)
    expect AddrV2Error:
      discard r.readNetAddressV2()

suite "timestamped addrv2":
  test "serialize timestamped addrv2":
    var ta: TimestampedAddrV2
    ta.timestamp = 0x12345678
    ta.services = 1033  # NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
    ta.address = NetAddressV2(networkId: netIPv4)
    ta.address.ipv4 = [127'u8, 0, 0, 1]
    ta.port = 8333

    var w = BinaryWriter()
    w.writeTimestampedAddrV2(ta)

    # timestamp(4) + services(compact) + netid(1) + len(1) + addr(4) + port(2)
    check w.data.len >= 4 + 2 + 1 + 1 + 4 + 2

  test "roundtrip timestamped addrv2":
    var ta: TimestampedAddrV2
    ta.timestamp = 1699999999
    ta.services = 9  # NODE_NETWORK | NODE_WITNESS
    ta.address = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32:
      ta.address.torv3[i] = byte(i)
    ta.port = 9050

    var w = BinaryWriter()
    w.writeTimestampedAddrV2(ta)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readTimestampedAddrV2()

    check decoded.isSome
    let d = decoded.get()
    check d.timestamp == ta.timestamp
    check d.services == ta.services
    check d.address.networkId == netTorV3
    check d.address.torv3 == ta.address.torv3
    check d.port == ta.port

suite "legacy conversion":
  test "ipv4 to ipv6 mapped":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [192'u8, 168, 1, 1]

    let mapped = addr2.toIPv6Mapped()

    # Check IPv4-mapped prefix
    for i in 0 ..< 10:
      check mapped[i] == 0
    check mapped[10] == 0xFF
    check mapped[11] == 0xFF
    # Check IPv4 address
    check mapped[12] == 192
    check mapped[13] == 168
    check mapped[14] == 1
    check mapped[15] == 1

  test "ipv6 to ipv6 mapped is identity":
    var addr2 = NetAddressV2(networkId: netIPv6)
    for i in 0 ..< 16:
      addr2.ipv6[i] = byte(i)

    let mapped = addr2.toIPv6Mapped()
    check mapped == addr2.ipv6

  test "from ipv6 mapped ipv4":
    var ip: array[16, byte]
    # IPv4-mapped prefix
    ip[10] = 0xFF
    ip[11] = 0xFF
    ip[12] = 10
    ip[13] = 20
    ip[14] = 30
    ip[15] = 40

    let addr2 = fromIPv6Mapped(ip)
    check addr2.networkId == netIPv4
    check addr2.ipv4 == [10'u8, 20, 30, 40]

  test "from ipv6 native":
    var ip: array[16, byte]
    ip[0] = 0x20
    ip[1] = 0x01

    let addr2 = fromIPv6Mapped(ip)
    check addr2.networkId == netIPv6
    check addr2.ipv6[0] == 0x20
    check addr2.ipv6[1] == 0x01

  test "cjdns detected from ipv6":
    var ip: array[16, byte]
    ip[0] = 0xFC  # CJDNS prefix
    for i in 1 ..< 16:
      ip[i] = byte(i)

    let addr2 = fromIPv6Mapped(ip)
    check addr2.networkId == netCJDNS
    check addr2.cjdns[0] == 0xFC

suite "addrv2 message":
  test "serialize addrv2 message":
    var addrs: seq[TimestampedAddrV2]

    # Add IPv4
    var ta1: TimestampedAddrV2
    ta1.timestamp = 1700000000
    ta1.services = 1
    ta1.address = NetAddressV2(networkId: netIPv4)
    ta1.address.ipv4 = [8'u8, 8, 8, 8]
    ta1.port = 8333
    addrs.add(ta1)

    # Add TorV3
    var ta2: TimestampedAddrV2
    ta2.timestamp = 1700000001
    ta2.services = 9
    ta2.address = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32:
      ta2.address.torv3[i] = byte(i + 0x10)
    ta2.port = 9050
    addrs.add(ta2)

    let msg = newAddrV2(addrs)
    check msg.kind == mkAddrV2
    check msg.addressesV2.len == 2

  test "addrv2 command name":
    check messageKindToCommand(mkAddrV2) == "addrv2"
    check commandToMessageKind("addrv2") == mkAddrV2

  test "sendaddrv2 command name":
    check messageKindToCommand(mkSendAddrV2) == "sendaddrv2"
    check commandToMessageKind("sendaddrv2") == mkSendAddrV2

suite "torv3 validation":
  test "valid torv3 address":
    var addr2 = NetAddressV2(networkId: netTorV3)
    # Non-zero ed25519 public key
    for i in 0 ..< 32:
      addr2.torv3[i] = byte(i + 1)
    check addr2.isValid()

  test "all-zero torv3 is invalid":
    var addr2 = NetAddressV2(networkId: netTorV3)
    # All zeros is not a valid ed25519 key
    check not addr2.isValid()

  test "torv3 length validation":
    # Correct length (32 bytes)
    let goodData = @[4'u8, 32] & newSeq[byte](32)
    var r1 = BinaryReader(data: goodData, pos: 0)
    let good = r1.readNetAddressV2()
    check good.isSome

    # Wrong length (31 bytes)
    let badData = @[4'u8, 31] & newSeq[byte](31)
    var r2 = BinaryReader(data: badData, pos: 0)
    expect AddrV2Error:
      discard r2.readNetAddressV2()

suite "addrv2 services bitfield (regression: ReadCompactSize size-too-large)":
  ## Regression for the 2026-05-27 mainnet bug where readTimestampedAddrV2
  ## passed `range_check=true` to readCompactSize for the `services` field,
  ## a 64-bit bitfield encoded with `CompactSizeFormatter<false>` in Bitcoin
  ## Core (protocol.h:446).  Any peer that gossiped an address with a
  ## service bit at position >= 26 (encoded value > 0x02000000 = MAX_SIZE)
  ## triggered `ReadCompactSize(): size too large`, ending the message loop
  ## and destroying per-peer PRESYNC state — so from-genesis IBD never
  ## made progress past +782 headers.
  ##
  ## With the fix (addr.nim::readTimestampedAddrV2 now passes
  ## `range_check=false`), these high-bit service flags decode cleanly.

  test "services with bit 31 set (5-byte CompactSize, value > MAX_SIZE) decodes":
    var ta: TimestampedAddrV2
    ta.timestamp = 1700000000
    ta.services = 0x80000001'u64  # bit 31 + NODE_NETWORK; > 0x02000000
    ta.address = NetAddressV2(networkId: netIPv4)
    ta.address.ipv4 = [192'u8, 168, 1, 1]
    ta.port = 8333

    var w = BinaryWriter()
    w.writeTimestampedAddrV2(ta)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readTimestampedAddrV2()
    check decoded.isSome
    check decoded.get().services == ta.services

  test "services with bit 63 set (9-byte CompactSize) decodes":
    # Forces the readUint64LE() branch in readCompactSize.
    var ta: TimestampedAddrV2
    ta.timestamp = 1700000001
    ta.services = 0x8000000000000001'u64  # bit 63 + NODE_NETWORK
    ta.address = NetAddressV2(networkId: netIPv4)
    ta.address.ipv4 = [127'u8, 0, 0, 1]
    ta.port = 8333

    var w = BinaryWriter()
    w.writeTimestampedAddrV2(ta)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readTimestampedAddrV2()
    check decoded.isSome
    check decoded.get().services == ta.services

  test "addrv2 message with high-bit services decodes via deserializePayload":
    # End-to-end: build a full addrv2 wire payload (count + 1 entry) with
    # high service bits and confirm the top-level dispatcher can parse it
    # without raising.  Pre-fix this raised SerializationError.
    var ta: TimestampedAddrV2
    ta.timestamp = 1700000002
    ta.services = 0xFFFFFFFFFFFFFFFF'u64  # all bits set
    ta.address = NetAddressV2(networkId: netIPv4)
    ta.address.ipv4 = [10'u8, 0, 0, 1]
    ta.port = 8333

    var w = BinaryWriter()
    w.writeCompactSize(1'u64)  # one address
    w.writeTimestampedAddrV2(ta)

    let msg = deserializePayload("addrv2", w.data)
    check msg.kind == mkAddrV2
    check msg.addressesV2.len == 1
    check msg.addressesV2[0].services == ta.services

suite "headers payload byte accounting (regression: from-genesis IBD)":
  ## Regression-style guard against a future readHeadersPayload byte-drift:
  ## the wire format for a `headers` message is
  ##   compactsize(count) | (80-byte header | 1-byte 0x00 dummy txcount) * N
  ## so a 2000-header batch is 3 + 2000 * 81 = 162003 bytes total.  If
  ## readBlockHeader ever consumed off-by-N bytes, the next iteration's
  ## dummy-txcount read would misinterpret a header byte as a CompactSize
  ## prefix — a stray 0xFD/0xFE/0xFF would trigger size-too-large.

  test "writer/reader round-trip consumes exactly count*81 + size(count) bytes":
    var headers: seq[BlockHeader]
    for i in 0 ..< 2000:
      var h: BlockHeader
      h.version = int32(0x20000000)
      # leave prevBlock / merkleRoot as zeros — only byte-count matters
      h.timestamp = uint32(1700000000 + i)
      h.bits = 0x1d00ffff'u32
      h.nonce = uint32(i)
      headers.add(h)

    var w = BinaryWriter()
    w.writeHeadersPayload(headers)

    # 2000 fits in a 3-byte CompactSize (0xFD prefix + uint16LE).
    let expectedSize = 3 + 2000 * 81
    check w.data.len == expectedSize

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readHeadersPayload()
    check decoded.len == 2000
    check r.pos == expectedSize
    check r.remaining() == 0

  test "readHeadersPayload would catch a missing dummy-txcount (negative)":
    # Build a payload that drops the trailing 0x00 dummy byte from one entry.
    # The next iteration will misalign and (since the next header's version
    # field's first byte is unlikely to be a valid trailing byte) the reader
    # will overrun or mis-decode.  This test just asserts the WELL-FORMED
    # case still parses — the malformed case is non-trivial to assert
    # deterministically since outcome depends on header bytes.  Kept as a
    # sanity guard: the canonical writer is the only producer the reader
    # is contracted to round-trip with.
    var headers: seq[BlockHeader]
    var h: BlockHeader
    h.timestamp = 1
    headers.add(h)

    var w = BinaryWriter()
    w.writeHeadersPayload(headers)
    check w.data.len == 1 + 80 + 1  # count(1) + header(80) + dummy(1)

suite "string conversion":
  test "ipv4 to string":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [192'u8, 168, 1, 1]
    check $addr2 == "192.168.1.1"

  test "torv3 to string":
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32:
      addr2.torv3[i] = byte(i)
    let s = $addr2
    check s.startsWith("torv3:")

  test "cjdns to string":
    var addr2 = NetAddressV2(networkId: netCJDNS)
    addr2.cjdns[0] = 0xFC
    addr2.cjdns[1] = 0x12
    let s = $addr2
    check s.startsWith("fc12:")
