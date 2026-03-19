## BIP155 ADDRv2 protocol implementation
## Variable-length network addresses for Tor v3, I2P, and CJDNS
## Reference: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
##
## Key differences from legacy addr:
## - Services field uses CompactSize encoding (vs fixed uint64)
## - Network ID byte identifies address type (IPv4=1, IPv6=2, TorV3=4, I2P=5, CJDNS=6)
## - Variable-length address field with explicit length
## - sendaddrv2 feature negotiation between VERSION and VERACK

import ../primitives/serialize
import std/[options, strutils]

const
  # BIP155 address sizes
  AddrIPv4Size* = 4
  AddrIPv6Size* = 16
  AddrTorV3Size* = 32    # Ed25519 public key
  AddrI2PSize* = 32      # SHA256 of destination
  AddrCJDNSSize* = 16    # fc00::/8 IPv6 address
  AddrInternalSize* = 10 # Internal address for tracking (not gossiped)

  # Maximum ADDRv2 address size (from BIP155)
  MaxAddrV2Size* = 512

  # Maximum addresses per addrv2 message
  MaxAddrPerMsg* = 1000

type
  NetworkId* = enum
    ## BIP155 network identifiers (internal enum, wire values are different)
    ## TorV2 is deprecated and should be ignored
    netIPv4 = 0
    netIPv6 = 1
    netTorV2 = 2  # Deprecated, ignore
    netTorV3 = 3
    netI2P = 4
    netCJDNS = 5

  NetAddressV2* = object
    ## Variable-length network address (BIP155)
    case networkId*: NetworkId
    of netIPv4:
      ipv4*: array[4, byte]
    of netIPv6:
      ipv6*: array[16, byte]
    of netTorV2:
      torv2*: array[10, byte]  # Deprecated but need to parse
    of netTorV3:
      torv3*: array[32, byte]  # Ed25519 public key
    of netI2P:
      i2p*: array[32, byte]    # SHA256 of destination
    of netCJDNS:
      cjdns*: array[16, byte]  # Must start with 0xFC

  NetAddress* = object
    ## Legacy network address (pre-BIP155)
    services*: uint64
    ip*: array[16, byte]  # IPv6 or IPv4-mapped
    port*: uint16

  TimestampedAddr* = object
    timestamp*: uint32
    address*: NetAddress

const
  # BIP155 wire format network IDs (these are the values sent on wire)
  Bip155IPv4* = 1'u8
  Bip155IPv6* = 2'u8
  Bip155TorV2* = 3'u8
  Bip155TorV3* = 4'u8
  Bip155I2P* = 5'u8
  Bip155CJDNS* = 6'u8

type
  TimestampedAddrV2* = object
    ## Address with timestamp and services for addrv2 message
    timestamp*: uint32
    services*: uint64  # Encoded as CompactSize on wire
    address*: NetAddressV2
    port*: uint16

  AddrV2Error* = object of CatchableError

# Helper: IPv4 to IPv6 mapped address
const IPv4InIPv6Prefix*: array[12, byte] = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
]

# Helper: CJDNS prefix
const CJDNSPrefix* = 0xFC'u8

proc isValid*(addr2: NetAddressV2): bool =
  ## Validate an ADDRv2 address
  case addr2.networkId
  of netIPv4:
    # IPv4: any 4 bytes are valid (validation of routable-ness done elsewhere)
    true
  of netIPv6:
    # IPv6: any 16 bytes are valid (validation of routable-ness done elsewhere)
    # Check it's not IPv4-mapped (should use netIPv4 instead)
    var isIPv4Mapped = true
    for i in 0 ..< 12:
      if addr2.ipv6[i] != IPv4InIPv6Prefix[i]:
        isIPv4Mapped = false
        break
    not isIPv4Mapped
  of netTorV2:
    # TorV2 is deprecated, always invalid
    false
  of netTorV3:
    # TorV3: must be a valid ed25519 public key (32 bytes)
    # Basic validation: non-zero
    var allZero = true
    for b in addr2.torv3:
      if b != 0:
        allZero = false
        break
    not allZero
  of netI2P:
    # I2P: must be a valid SHA256 hash (32 bytes)
    # Basic validation: non-zero
    var allZero = true
    for b in addr2.i2p:
      if b != 0:
        allZero = false
        break
    not allZero
  of netCJDNS:
    # CJDNS: must start with 0xFC
    addr2.cjdns[0] == CJDNSPrefix

proc isAddrV1Compatible*(addr2: NetAddressV2): bool =
  ## Check if address can be represented in legacy addr format (16 bytes)
  case addr2.networkId
  of netIPv4, netIPv6:
    true
  of netTorV2, netTorV3, netI2P, netCJDNS:
    false

proc toIPv6Mapped*(addr2: NetAddressV2): array[16, byte] =
  ## Convert to 16-byte format for legacy addr message
  ## Only valid for IPv4 and IPv6 addresses
  case addr2.networkId
  of netIPv4:
    # IPv4-mapped IPv6: ::ffff:a.b.c.d
    for i in 0 ..< 12:
      result[i] = IPv4InIPv6Prefix[i]
    for i in 0 ..< 4:
      result[12 + i] = addr2.ipv4[i]
  of netIPv6:
    result = addr2.ipv6
  else:
    # Return zeros for incompatible types
    discard

proc fromIPv6Mapped*(ip: array[16, byte]): NetAddressV2 =
  ## Convert from 16-byte legacy format to NetAddressV2
  # Check for IPv4-mapped
  var isIPv4Mapped = true
  for i in 0 ..< 12:
    if ip[i] != IPv4InIPv6Prefix[i]:
      isIPv4Mapped = false
      break

  if isIPv4Mapped:
    result = NetAddressV2(networkId: netIPv4)
    for i in 0 ..< 4:
      result.ipv4[i] = ip[12 + i]
  else:
    # Check for CJDNS (starts with 0xFC)
    if ip[0] == CJDNSPrefix:
      result = NetAddressV2(networkId: netCJDNS)
      result.cjdns = ip
    else:
      result = NetAddressV2(networkId: netIPv6)
      result.ipv6 = ip

# Serialization for ADDRv2

proc writeNetAddressV2*(w: var BinaryWriter, addr2: NetAddressV2) =
  ## Serialize a NetAddressV2 (network ID + length + address bytes)
  w.writeUint8(uint8(ord(addr2.networkId)))

  case addr2.networkId
  of netIPv4:
    w.writeCompactSize(uint64(AddrIPv4Size))
    w.writeBytes(addr2.ipv4)
  of netIPv6:
    w.writeCompactSize(uint64(AddrIPv6Size))
    w.writeBytes(addr2.ipv6)
  of netTorV2:
    w.writeCompactSize(uint64(10))
    w.writeBytes(addr2.torv2)
  of netTorV3:
    w.writeCompactSize(uint64(AddrTorV3Size))
    w.writeBytes(addr2.torv3)
  of netI2P:
    w.writeCompactSize(uint64(AddrI2PSize))
    w.writeBytes(addr2.i2p)
  of netCJDNS:
    w.writeCompactSize(uint64(AddrCJDNSSize))
    w.writeBytes(addr2.cjdns)

proc readNetAddressV2*(r: var BinaryReader): Option[NetAddressV2] =
  ## Deserialize a NetAddressV2
  ## Returns none for unknown network IDs (from future)
  let netIdByte = r.readUint8()
  let addrLen = r.readCompactSize()

  if addrLen > MaxAddrV2Size:
    raise newException(AddrV2Error, "address too long: " & $addrLen)

  # Validate network ID and address length
  case netIdByte
  of 1: # IPv4
    if addrLen != AddrIPv4Size:
      raise newException(AddrV2Error, "IPv4 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netIPv4)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrIPv4Size:
      addr2.ipv4[i] = bytes[i]
    return some(addr2)

  of 2: # IPv6
    if addrLen != AddrIPv6Size:
      raise newException(AddrV2Error, "IPv6 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netIPv6)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrIPv6Size:
      addr2.ipv6[i] = bytes[i]
    return some(addr2)

  of 3: # TorV2 (deprecated)
    # Skip but don't error - just consume the bytes
    discard r.readBytes(int(addrLen))
    return none(NetAddressV2)

  of 4: # TorV3
    if addrLen != AddrTorV3Size:
      raise newException(AddrV2Error, "TorV3 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netTorV3)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrTorV3Size:
      addr2.torv3[i] = bytes[i]
    return some(addr2)

  of 5: # I2P
    if addrLen != AddrI2PSize:
      raise newException(AddrV2Error, "I2P address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netI2P)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrI2PSize:
      addr2.i2p[i] = bytes[i]
    return some(addr2)

  of 6: # CJDNS
    if addrLen != AddrCJDNSSize:
      raise newException(AddrV2Error, "CJDNS address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netCJDNS)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrCJDNSSize:
      addr2.cjdns[i] = bytes[i]
    # Validate CJDNS prefix
    if addr2.cjdns[0] != CJDNSPrefix:
      raise newException(AddrV2Error, "CJDNS address with invalid prefix")
    return some(addr2)

  else:
    # Unknown network ID - skip the address bytes and return none
    # This allows forward compatibility with future network types
    discard r.readBytes(int(addrLen))
    return none(NetAddressV2)

proc writeTimestampedAddrV2*(w: var BinaryWriter, ta: TimestampedAddrV2) =
  ## Serialize a timestamped address for addrv2 message
  ## Format: time(4) | services(compact) | networkID(1) | addrLen(compact) | addr(var) | port(2 BE)
  w.writeUint32LE(ta.timestamp)
  w.writeCompactSize(ta.services)
  w.writeNetAddressV2(ta.address)
  # Port is big-endian
  w.data.add(byte((ta.port shr 8) and 0xFF))
  w.data.add(byte(ta.port and 0xFF))

proc readTimestampedAddrV2*(r: var BinaryReader): Option[TimestampedAddrV2] =
  ## Deserialize a timestamped address from addrv2 message
  ## Returns none for unknown network types (from future)
  var ta: TimestampedAddrV2
  ta.timestamp = r.readUint32LE()
  ta.services = r.readCompactSize()

  let addrOpt = r.readNetAddressV2()
  if addrOpt.isNone:
    # Unknown network type - skip the port and return none
    discard r.readBytes(2)
    return none(TimestampedAddrV2)

  ta.address = addrOpt.get()

  # Port is big-endian
  let portHi = r.readUint8()
  let portLo = r.readUint8()
  ta.port = (uint16(portHi) shl 8) or uint16(portLo)

  return some(ta)

# Conversion helpers between legacy NetAddress and NetAddressV2

# NetAddress and TimestampedAddr defined here (used by messages.nim via import/export)
# This avoids circular imports since messages.nim imports addr.nim

proc toNetAddressV2*(addr1: NetAddress): NetAddressV2 =
  ## Convert legacy NetAddress to NetAddressV2
  fromIPv6Mapped(addr1.ip)

proc toNetAddress*(addr2: NetAddressV2, services: uint64, port: uint16): NetAddress =
  ## Convert NetAddressV2 to legacy NetAddress
  ## Only valid for IPv4 and IPv6 addresses
  result.services = services
  result.port = port
  result.ip = addr2.toIPv6Mapped()

proc toLegacyTimestampedAddr*(ta: TimestampedAddrV2): Option[TimestampedAddr] =
  ## Convert TimestampedAddrV2 to legacy TimestampedAddr
  ## Returns none if address type is not v1-compatible
  if not ta.address.isAddrV1Compatible():
    return none(TimestampedAddr)

  var legacy: TimestampedAddr
  legacy.timestamp = ta.timestamp
  legacy.address = ta.address.toNetAddress(ta.services, ta.port)
  return some(legacy)

proc toTimestampedAddrV2*(ta: TimestampedAddr): TimestampedAddrV2 =
  ## Convert legacy TimestampedAddr to TimestampedAddrV2
  result.timestamp = ta.timestamp
  result.services = ta.address.services
  result.address = ta.address.toNetAddressV2()
  result.port = ta.address.port

# String conversion helpers for debugging

proc `$`*(addr2: NetAddressV2): string =
  case addr2.networkId
  of netIPv4:
    $addr2.ipv4[0] & "." & $addr2.ipv4[1] & "." &
    $addr2.ipv4[2] & "." & $addr2.ipv4[3]
  of netIPv6:
    var s = ""
    for i in 0 ..< 8:
      if i > 0: s.add(":")
      let hi = addr2.ipv6[i*2]
      let lo = addr2.ipv6[i*2 + 1]
      let val = (uint16(hi) shl 8) or uint16(lo)
      s.add(toHex(val, 1))
    s
  of netTorV2:
    "torv2(deprecated)"
  of netTorV3:
    var s = "torv3:"
    for i in 0 ..< 8:
      s.add(toHex(addr2.torv3[i], 2))
    s.add("...")
    s
  of netI2P:
    var s = "i2p:"
    for i in 0 ..< 8:
      s.add(toHex(addr2.i2p[i], 2))
    s.add("...")
    s
  of netCJDNS:
    "fc" & toHex(addr2.cjdns[1], 2) & ":" &
    toHex(addr2.cjdns[2], 2) & toHex(addr2.cjdns[3], 2) & ":..."

proc `$`*(ta: TimestampedAddrV2): string =
  $ta.address & ":" & $ta.port
