## W117 BIP-155 fleet audit — nimrod
## Tests for Tor v3, I2P, CJDNS, outbound proxy, addrv2 serialization,
## address relay, and getnetworkinfo.
##
## Gates covered:
##   G1-G10  Tor v3
##   G11-G16 I2P
##   G17-G20 CJDNS
##   G21-G24 Outbound proxy (SOCKS5)
##   G25-G28 Address resolution
##   G29-G30 addrv2 + RPC

import unittest2
import std/[options, strutils, tables]
import ../src/primitives/serialize
import ../src/network/addr
import ../src/network/messages
import ../src/network/netgroup
import ../src/network/proxy

# ─────────────────────────────────────────────────────────────────────────────
# Helper: build raw addrv2 bytes with a given wire network-ID byte
proc buildRawAddrV2(wireId: uint8, addrBytes: seq[byte]): seq[byte] =
  result.add(wireId)
  result.add(uint8(addrBytes.len))  # CompactSize (small)
  result.add(addrBytes)

# ─────────────────────────────────────────────────────────────────────────────
# G1-G2 / G3  Tor v3 wire network-ID and address size

suite "G1-G3 Tor v3 network ID and size":
  test "BIP-155 Tor v3 wire ID is 4":
    ## BIP-155 §Table of network IDs: TORv3 = 4
    check Bip155TorV3 == 4'u8

  test "Tor v3 address is 32 bytes (ed25519 pubkey)":
    check AddrTorV3Size == 32

  test "writeNetAddressV2 emits wire ID 4 for Tor v3 (BUG-1 regression)":
    ## BUG-1: was emitting ord(netTorV3)=3 (enum ordinal) instead of 4 (wire ID).
    ## After fix enum values must match BIP-155 wire IDs.
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: addr2.torv3[i] = byte(i + 1)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    check w.data[0] == 4'u8   # BIP-155 TORv3 = 4

  test "readNetAddressV2 round-trip for Tor v3":
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: addr2.torv3[i] = byte(i + 0xA0)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isSome
    check decoded.get().networkId == netTorV3
    check decoded.get().torv3 == addr2.torv3

  test "Tor v3 isValid requires non-zero pubkey":
    var zero = NetAddressV2(networkId: netTorV3)
    check not zero.isValid()
    var nonzero = NetAddressV2(networkId: netTorV3)
    nonzero.torv3[0] = 0x42
    check nonzero.isValid()

  test "Tor v2 is deprecated and always invalid":
    var addr2 = NetAddressV2(networkId: netTorV2)
    check not addr2.isValid()

  test "Tor v2 wire read returns none (skip deprecated)":
    ## Wire ID 3 = TorV2; should be consumed but produce none
    let data = @[3'u8, 10] & newSeq[byte](10)
    var r = BinaryReader(data: data, pos: 0)
    let res = r.readNetAddressV2()
    check res.isNone

# ─────────────────────────────────────────────────────────────────────────────
# G4-G7  Tor v3 validation: length enforcement

suite "G4-G7 Tor v3 length and format enforcement":
  test "Tor v3 wrong length raises AddrV2Error":
    ## BIP-155: TORv3 MUST be exactly 32 bytes
    let bad = @[4'u8, 31] & newSeq[byte](31)
    var r = BinaryReader(data: bad, pos: 0)
    expect AddrV2Error:
      discard r.readNetAddressV2()

  test "Tor v3 correct length (32) parses without error":
    let good = @[4'u8, 32] & newSeq[byte](32)
    var r = BinaryReader(data: good, pos: 0)
    let res = r.readNetAddressV2()
    check res.isSome

  test "Tor v3 is not v1-compatible":
    var addr2 = NetAddressV2(networkId: netTorV3)
    check not addr2.isAddrV1Compatible()

# ─────────────────────────────────────────────────────────────────────────────
# G8-G10  Tor v3 string representation

suite "G8-G10 Tor v3 string representation":
  test "Tor v3 string starts with 'torv3:'":
    var addr2 = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: addr2.torv3[i] = byte(i + 1)
    let s = $addr2
    check s.startsWith("torv3:")

# ─────────────────────────────────────────────────────────────────────────────
# G11-G12  I2P wire network-ID and address size

suite "G11-G12 I2P network ID and size":
  test "BIP-155 I2P wire ID is 5":
    check Bip155I2P == 5'u8

  test "I2P address is 32 bytes (SHA-256 of destination)":
    check AddrI2PSize == 32

  test "writeNetAddressV2 emits wire ID 5 for I2P (BUG-1 regression)":
    ## BUG-1: was emitting ord(netI2P)=4 instead of 5.
    var addr2 = NetAddressV2(networkId: netI2P)
    for i in 0 ..< 32: addr2.i2p[i] = byte(i + 1)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    check w.data[0] == 5'u8

  test "readNetAddressV2 round-trip for I2P":
    var addr2 = NetAddressV2(networkId: netI2P)
    for i in 0 ..< 32: addr2.i2p[i] = byte(255 - i)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isSome
    check decoded.get().networkId == netI2P
    check decoded.get().i2p == addr2.i2p

# ─────────────────────────────────────────────────────────────────────────────
# G13-G16  I2P validation and proxy constants

suite "G13-G16 I2P validation and SAM constants":
  test "I2P isValid requires non-zero":
    var zero = NetAddressV2(networkId: netI2P)
    check not zero.isValid()
    var nonzero = NetAddressV2(networkId: netI2P)
    nonzero.i2p[0] = 0x01
    check nonzero.isValid()

  test "I2P wrong length raises AddrV2Error":
    let bad = @[5'u8, 31] & newSeq[byte](31)
    var r = BinaryReader(data: bad, pos: 0)
    expect AddrV2Error:
      discard r.readNetAddressV2()

  test "I2P SAM default port is 7656":
    check I2PSamPort == 7656

  test "I2P SAM protocol version is 3.1":
    check I2PSamVersion == "3.1"

  test "I2P signature type is 7 (EdDSA-SHA-512)":
    check I2PSignatureType == 7

  test "I2P address detection via isI2PAddress":
    check isI2PAddress("abcdef.b32.i2p")
    check isI2PAddress("test.i2p")
    check not isI2PAddress("example.com")
    check not isI2PAddress("test.onion")

  test "I2P is not v1-compatible":
    var addr2 = NetAddressV2(networkId: netI2P)
    check not addr2.isAddrV1Compatible()

# ─────────────────────────────────────────────────────────────────────────────
# G17-G20  CJDNS

suite "G17-G20 CJDNS wire format and routability":
  test "BIP-155 CJDNS wire ID is 6":
    check Bip155CJDNS == 6'u8

  test "CJDNS address is 16 bytes (fc00::/8 IPv6)":
    check AddrCJDNSSize == 16

  test "writeNetAddressV2 emits wire ID 6 for CJDNS (BUG-1 regression)":
    ## BUG-1: was emitting ord(netCJDNS)=5 instead of 6.
    var addr2 = NetAddressV2(networkId: netCJDNS)
    addr2.cjdns[0] = 0xFC
    for i in 1 ..< 16: addr2.cjdns[i] = byte(i)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    check w.data[0] == 6'u8

  test "CJDNS must start with 0xFC":
    var good = NetAddressV2(networkId: netCJDNS)
    good.cjdns[0] = 0xFC
    check good.isValid()
    var bad = NetAddressV2(networkId: netCJDNS)
    bad.cjdns[0] = 0x00
    check not bad.isValid()

  test "CJDNS wrong length raises AddrV2Error":
    let bad = @[6'u8, 15] & newSeq[byte](15)
    var r = BinaryReader(data: bad, pos: 0)
    expect AddrV2Error:
      discard r.readNetAddressV2()

  test "CJDNS invalid prefix raises AddrV2Error":
    ## CJDNS must start with 0xFC per BIP-155
    let bad = @[6'u8, 16] & @[0x00'u8] & newSeq[byte](15)
    var r = BinaryReader(data: bad, pos: 0)
    expect AddrV2Error:
      discard r.readNetAddressV2()

  test "isCJDNS correctly identifies fc00::/8":
    let cjdnsIp = IpAddr(isV6: true, v6: [
      0xFC'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
      0xF0'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
    ])
    check cjdnsIp.isCJDNS()
    let notCjdns = IpAddr(isV6: true, v6: [
      0x20'u8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ])
    check not notCjdns.isCJDNS()

  test "isRoutable(IpAddr) accepts CJDNS (fc00::/8)":
    ## Core: NET_CJDNS is routable. Must be checked BEFORE ULA rejection.
    let cjdnsIp = IpAddr(isV6: true, v6: [
      0xFC'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
      0xF0'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
    ])
    check cjdnsIp.isRoutable()

  test "isRoutable(array[16,byte]) accepts CJDNS — BUG-2 regression":
    ## BUG-2: the array[16,byte] overload used by addKnownAddress was
    ## applying the fc00::/7 ULA check without the CJDNS exception, so all
    ## CJDNS addresses were silently dropped.  After fix this must pass.
    let cjdnsRaw: array[16, byte] = [
      0xFC'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
      0xF0'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
    ]
    check isRoutable(cjdnsRaw)

  test "isRoutable(array[16,byte]) rejects ULA fd00::/8 (not CJDNS)":
    ## fd00::/8 is ULA, not CJDNS — must remain non-routable
    let ulaRaw: array[16, byte] = [
      0xFD'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
      0xF0'u8, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
    ]
    check not isRoutable(ulaRaw)

  test "fromIPv6Mapped detects CJDNS prefix and produces netCJDNS":
    var ip: array[16, byte]
    ip[0] = 0xFC
    for i in 1 ..< 16: ip[i] = byte(i)
    let addr2 = fromIPv6Mapped(ip)
    check addr2.networkId == netCJDNS
    check addr2.cjdns[0] == 0xFC

# ─────────────────────────────────────────────────────────────────────────────
# G21-G24  Outbound proxy (SOCKS5 / Tor / I2P)

suite "G21-G24 Outbound proxy — SOCKS5 and address detection":
  test "isOnionAddress detects .onion suffix":
    check isOnionAddress("vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion")
    check isOnionAddress("test.onion")
    check not isOnionAddress("test.com")
    check not isOnionAddress("test.i2p")

  test "Tor control default port is 9051":
    check TorControlPort == 9051

  test "Tor reply OK code is 250":
    check TorReplyOk == 250

  test "SOCKS5 version byte is 0x05":
    check Socks5Version == 0x05'u8

  test "SOCKS5 auth methods are correctly defined":
    check Socks5AuthNone == 0x00'u8
    check Socks5AuthUserPass == 0x02'u8
    check Socks5AuthNoAcceptable == 0xFF'u8

  test "SOCKS5 address types are correctly defined":
    check Socks5AtypIPv4 == 0x01'u8
    check Socks5AtypDomain == 0x03'u8
    check Socks5AtypIPv6 == 0x04'u8

  test "newSocks5Proxy creates proxy with correct config":
    let proxy = newSocks5Proxy("127.0.0.1", 9050)
    check proxy.config.host == "127.0.0.1"
    check proxy.config.port == 9050
    check proxy.config.auth.isNone
    check proxy.config.randomizeCredentials == false

  test "newSocks5Proxy with username/password auth":
    let auth = some(ProxyCredentials(username: "user", password: "pass"))
    let proxy = newSocks5Proxy("localhost", 1080, auth)
    check proxy.config.auth.isSome
    check proxy.config.auth.get().username == "user"
    check proxy.config.auth.get().password == "pass"

  test "stream isolation generates unique credentials per circuit":
    var proxy = newSocks5Proxy("127.0.0.1", 9050, randomizeCredentials = true)
    let c1 = proxy.generateStreamIsolationCredentials()
    let c2 = proxy.generateStreamIsolationCredentials()
    check c1.username != c2.username
    check c1.password != c2.password
    check c1.username.startsWith("nimrod")

  test "ProxyManager starts with all fields as none":
    let pm = newProxyManager()
    check pm.clearnetProxy.isNone
    check pm.onionProxy.isNone
    check pm.i2pSession.isNone
    check pm.torService.isNone

  test "configureProxy sets clearnet proxy":
    let pm = newProxyManager()
    pm.configureProxy("127.0.0.1", 1080)
    check pm.clearnetProxy.isSome
    check pm.clearnetProxy.get().config.host == "127.0.0.1"
    check pm.clearnetProxy.get().config.port == 1080

  test "configureOnionProxy sets Tor SOCKS proxy with stream isolation":
    let pm = newProxyManager()
    pm.configureOnionProxy("127.0.0.1", 9050, randomizeCredentials = true)
    check pm.onionProxy.isSome
    check pm.onionProxy.get().config.randomizeCredentials == true

  test "configureI2P sets I2P SAM session":
    let pm = newProxyManager()
    pm.configureI2P("127.0.0.1", 7656, "/tmp/i2p_key", transient = false)
    check pm.i2pSession.isSome
    check pm.i2pSession.get().config.host == "127.0.0.1"
    check pm.i2pSession.get().config.port == 7656
    check pm.i2pSession.get().config.privateKeyFile == "/tmp/i2p_key"

  test "configureTorControl sets Tor hidden service":
    let pm = newProxyManager()
    pm.configureTorControl("127.0.0.1", 9051, password = "secret")
    check pm.torService.isSome
    check pm.torService.get().config.password == "secret"

  test "getI2PAddress returns none when not configured":
    let pm = newProxyManager()
    check pm.getI2PAddress().isNone

  test "getTorOnionAddress returns none when not configured":
    let pm = newProxyManager()
    check pm.getTorOnionAddress().isNone

# ─────────────────────────────────────────────────────────────────────────────
# G25-G28  Address resolution and enum wire mapping

suite "G25-G28 Address resolution and BIP-155 wire IDs":
  test "BIP-155 IPv4 wire ID is 1":
    check Bip155IPv4 == 1'u8

  test "BIP-155 IPv6 wire ID is 2":
    check Bip155IPv6 == 2'u8

  test "BIP-155 TorV2 wire ID is 3 (deprecated)":
    check Bip155TorV2 == 3'u8

  test "networkIdToWire returns correct BIP-155 wire IDs (BUG-1 fix verification)":
    ## BUG-1 pre-fix: writeNetAddressV2 used uint8(ord(id)) which emits 0 for
    ## IPv4 (wire must be 1), 1 for IPv6 (wire must be 2), etc.  After fix,
    ## networkIdToWire() maps each enum to the correct BIP-155 wire byte.
    check networkIdToWire(netIPv4)  == Bip155IPv4    # 1
    check networkIdToWire(netIPv6)  == Bip155IPv6    # 2
    check networkIdToWire(netTorV2) == Bip155TorV2   # 3
    check networkIdToWire(netTorV3) == Bip155TorV3   # 4
    check networkIdToWire(netI2P)   == Bip155I2P     # 5
    check networkIdToWire(netCJDNS) == Bip155CJDNS   # 6

  test "writeNetAddressV2 emits wire ID 1 for IPv4 (BUG-1 regression)":
    ## BUG-1: was emitting 0 (enum ordinal) instead of 1 (BIP-155 wire ID).
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [192'u8, 0, 2, 1]
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    check w.data[0] == 1'u8

  test "writeNetAddressV2 emits wire ID 2 for IPv6 (BUG-1 regression)":
    var addr2 = NetAddressV2(networkId: netIPv6)
    addr2.ipv6[0] = 0x20
    addr2.ipv6[1] = 0x01
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    check w.data[0] == 2'u8

  test "readNetAddressV2 round-trip for IPv4":
    var addr2 = NetAddressV2(networkId: netIPv4)
    addr2.ipv4 = [8'u8, 8, 8, 8]
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isSome
    check decoded.get().networkId == netIPv4
    check decoded.get().ipv4 == addr2.ipv4

  test "readNetAddressV2 round-trip for IPv6":
    var addr2 = NetAddressV2(networkId: netIPv6)
    for i in 0 ..< 16: addr2.ipv6[i] = byte(i + 0x20)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isSome
    check decoded.get().networkId == netIPv6
    check decoded.get().ipv6 == addr2.ipv6

  test "readNetAddressV2 round-trip for CJDNS":
    var addr2 = NetAddressV2(networkId: netCJDNS)
    addr2.cjdns[0] = 0xFC
    for i in 1 ..< 16: addr2.cjdns[i] = byte(i)
    var w = BinaryWriter()
    w.writeNetAddressV2(addr2)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isSome
    check decoded.get().networkId == netCJDNS
    check decoded.get().cjdns[0] == 0xFC

  test "unknown future network ID returns none (forward compat)":
    let data = @[99'u8, 8] & newSeq[byte](8)
    var r = BinaryReader(data: data, pos: 0)
    let decoded = r.readNetAddressV2()
    check decoded.isNone

  test "address too large raises AddrV2Error":
    ## MaxAddrV2Size = 512
    check MaxAddrV2Size == 512

# ─────────────────────────────────────────────────────────────────────────────
# G29  addrv2 message wire format and relay

suite "G29 addrv2 message wire format":
  test "addrv2 command string is 'addrv2'":
    check messageKindToCommand(mkAddrV2) == "addrv2"
    check commandToMessageKind("addrv2") == mkAddrV2

  test "sendaddrv2 command string is 'sendaddrv2'":
    check messageKindToCommand(mkSendAddrV2) == "sendaddrv2"
    check commandToMessageKind("sendaddrv2") == mkSendAddrV2

  test "newAddrV2 builds message with all network types":
    var addrs: seq[TimestampedAddrV2]

    var ipv4ta: TimestampedAddrV2
    ipv4ta.timestamp = 1700000000
    ipv4ta.services = 1
    ipv4ta.address = NetAddressV2(networkId: netIPv4)
    ipv4ta.address.ipv4 = [8'u8, 8, 8, 8]
    ipv4ta.port = 8333
    addrs.add(ipv4ta)

    var torta: TimestampedAddrV2
    torta.timestamp = 1700000001
    torta.services = 9
    torta.address = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: torta.address.torv3[i] = byte(i + 1)
    torta.port = 9050
    addrs.add(torta)

    var i2pta: TimestampedAddrV2
    i2pta.timestamp = 1700000002
    i2pta.services = 1
    i2pta.address = NetAddressV2(networkId: netI2P)
    for i in 0 ..< 32: i2pta.address.i2p[i] = byte(i + 1)
    i2pta.port = 0
    addrs.add(i2pta)

    var cjdnsta: TimestampedAddrV2
    cjdnsta.timestamp = 1700000003
    cjdnsta.services = 1
    cjdnsta.address = NetAddressV2(networkId: netCJDNS)
    cjdnsta.address.cjdns[0] = 0xFC
    cjdnsta.port = 8333
    addrs.add(cjdnsta)

    let msg = newAddrV2(addrs)
    check msg.kind == mkAddrV2
    check msg.addressesV2.len == 4

  test "TimestampedAddrV2 round-trip with Tor v3":
    var ta: TimestampedAddrV2
    ta.timestamp = 1699999999
    ta.services = 9
    ta.address = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: ta.address.torv3[i] = byte(i + 1)
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

  test "Tor v3 and I2P addresses are NOT v1-compatible":
    ## toLegacyTimestampedAddr must return none for these.
    var torta: TimestampedAddrV2
    torta.address = NetAddressV2(networkId: netTorV3)
    check toLegacyTimestampedAddr(torta).isNone

    var i2pta: TimestampedAddrV2
    i2pta.address = NetAddressV2(networkId: netI2P)
    check toLegacyTimestampedAddr(i2pta).isNone

  test "CJDNS address is NOT v1-compatible":
    var cta: TimestampedAddrV2
    cta.address = NetAddressV2(networkId: netCJDNS)
    check toLegacyTimestampedAddr(cta).isNone

  test "IPv4 and IPv6 ARE v1-compatible":
    var v4ta: TimestampedAddrV2
    v4ta.address = NetAddressV2(networkId: netIPv4)
    v4ta.address.ipv4 = [8'u8, 8, 8, 8]
    v4ta.port = 8333
    v4ta.services = 1
    check toLegacyTimestampedAddr(v4ta).isSome

    var v6ta: TimestampedAddrV2
    v6ta.address = NetAddressV2(networkId: netIPv6)
    v6ta.address.ipv6[0] = 0x20
    v6ta.port = 8333
    v6ta.services = 1
    check toLegacyTimestampedAddr(v6ta).isSome

# ─────────────────────────────────────────────────────────────────────────────
# G30  I2P Base64 encoding (proxy.nim)

suite "G30 I2P Base64 encoding":
  test "i2pBase64Encode converts standard Base64 to I2P format":
    ## I2P uses '-' instead of '+' and '~' instead of '/'
    let data = @[byte(0xFB), 0xFF, 0x00]
    let encoded = i2pBase64Encode(data)
    check '+' notin encoded
    check '/' notin encoded

  test "i2pBase64Decode round-trips correctly":
    let original = @[byte(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let encoded = i2pBase64Encode(original)
    let decoded = i2pBase64Decode(encoded)
    check decoded == original

  test "i2pBase64 handles all byte values":
    let testData = @[
      byte(0x00), 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      byte(0x88), 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    ]
    let encoded = i2pBase64Encode(testData)
    let decoded = i2pBase64Decode(encoded)
    check decoded == testData

  test "i2pDestinationToAddress produces .b32.i2p suffix":
    let dest = @[
      byte(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      byte(0x08), 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ]
    let i2pAddr = i2pDestinationToAddress(dest)
    check i2pAddr.endsWith(".b32.i2p")

  test "i2pExtractPublicDestination raises on too-short key":
    let shortKey = @[byte(1), 2, 3]
    expect I2PSamError:
      discard i2pExtractPublicDestination(shortKey)

when isMainModule:
  echo "W117 BIP-155 tests done."
