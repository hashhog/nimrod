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
    ## BIP155 network identifiers (internal enum; 0-based for Nim case objects).
    ## Wire IDs are obtained via `networkIdToWire(id)`.
    ## BUG-1 FIX (W117): the original code used `uint8(ord(networkId))` as the
    ## wire byte, but Nim enum ordinals (0-5) differ from BIP-155 wire IDs (1-6).
    ## `writeNetAddressV2` now calls `networkIdToWire` to get the correct byte.
    netIPv4  = 0
    netIPv6  = 1
    netTorV2 = 2  # Deprecated, should be ignored on receipt
    netTorV3 = 3
    netI2P   = 4
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
    lastSeen*: uint32     # Unix seconds the address was last seen / advertised.
                          # DATA-GAP FIX (2026-06): the legacy NetAddress carried
                          # services + ip + port but NO timestamp, so the
                          # getnodeaddresses RPC had no real `time` to emit.
                          # Populated from the addr/addrv2 wire timestamp on
                          # receipt, from inject time for addpeeraddress, and from
                          # the connect/advertise time otherwise. Mirrors Core's
                          # CAddress::nTime which getnodeaddresses surfaces as the
                          # NUM_TIME `time` field (rpc/net.cpp:960).

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

proc networkIdToWire*(id: NetworkId): uint8 =
  ## BUG-1 FIX (W117): return the correct BIP-155 wire byte for a NetworkId.
  ## Nim enum ordinals (0-5) differ from BIP-155 wire IDs (1-6); this mapping
  ## corrects the off-by-one.  Previously `writeNetAddressV2` emitted
  ## `uint8(ord(id))` which sent 0 for IPv4 (wire must be 1), 1 for IPv6
  ## (wire must be 2), etc., making every addrv2 message unreadable by Core
  ## and other compliant implementations.
  case id
  of netIPv4:  Bip155IPv4    # 1
  of netIPv6:  Bip155IPv6    # 2
  of netTorV2: Bip155TorV2   # 3
  of netTorV3: Bip155TorV3   # 4
  of netI2P:   Bip155I2P     # 5
  of netCJDNS: Bip155CJDNS   # 6

proc wireToNetworkId*(b: uint8): Option[NetworkId] =
  ## BUG-1 FIX (W117) mirror: decode a BIP-155 wire ID byte (1-6) into the
  ## internal NetworkId enum.  Returns `none(NetworkId)` for unknown / future
  ## wire IDs so the caller can silent-skip the address entry per BIP-155
  ## §"Receiver behaviour" (skip unknown network IDs without aborting the
  ## addrv2 message).  Symmetric with `networkIdToWire`: every byte produced
  ## by the encoder round-trips through this decoder back to the same enum.
  case b
  of Bip155IPv4:   some(netIPv4)
  of Bip155IPv6:   some(netIPv6)
  of Bip155TorV2:  some(netTorV2)
  of Bip155TorV3:  some(netTorV3)
  of Bip155I2P:    some(netI2P)
  of Bip155CJDNS:  some(netCJDNS)
  else:            none(NetworkId)

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
  ## BUG-1 FIX (W117): use networkIdToWire() instead of ord() to get the
  ## correct BIP-155 wire byte (enum ordinals 0-5 ≠ wire IDs 1-6).
  w.writeUint8(networkIdToWire(addr2.networkId))

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
  ## Returns none for unknown / deprecated network IDs (silent-skip per BIP-155
  ## "Receiver behaviour": unknown entries must NOT abort the addrv2 message).
  ##
  ## BUG-1 FIX (W117): use `wireToNetworkId` instead of bare wire-byte literals
  ## so encode and decode share a single source of truth for the
  ## NetworkId <-> wire-byte mapping.  Previously the encoder used
  ## `uint8(ord(id))` (off-by-one) while the decoder used 1..6 literals; the
  ## existing round-trip test passed only because *both* sides were wrong in
  ## opposite directions and cancelled out.  After this fix, any byte
  ## produced by `writeNetAddressV2` decodes back to the same enum, and
  ## any byte from a BIP-155-compliant peer (incl. Core) is correctly
  ## interpreted on this end.
  let netIdByte = r.readUint8()
  let addrLen = r.readCompactSize()

  if addrLen > MaxAddrV2Size:
    raise newException(AddrV2Error, "address too long: " & $addrLen)

  let netIdOpt = wireToNetworkId(netIdByte)
  if netIdOpt.isNone:
    # Unknown wire ID (future network type) — consume bytes, skip entry.
    discard r.readBytes(int(addrLen))
    return none(NetAddressV2)

  case netIdOpt.get()
  of netIPv4:
    if addrLen != AddrIPv4Size:
      raise newException(AddrV2Error, "IPv4 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netIPv4)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrIPv4Size:
      addr2.ipv4[i] = bytes[i]
    return some(addr2)

  of netIPv6:
    if addrLen != AddrIPv6Size:
      raise newException(AddrV2Error, "IPv6 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netIPv6)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrIPv6Size:
      addr2.ipv6[i] = bytes[i]
    return some(addr2)

  of netTorV2:
    # Deprecated — silent-skip per BIP-155 (receivers SHOULD ignore TORv2).
    discard r.readBytes(int(addrLen))
    return none(NetAddressV2)

  of netTorV3:
    if addrLen != AddrTorV3Size:
      raise newException(AddrV2Error, "TorV3 address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netTorV3)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrTorV3Size:
      addr2.torv3[i] = bytes[i]
    return some(addr2)

  of netI2P:
    if addrLen != AddrI2PSize:
      raise newException(AddrV2Error, "I2P address with invalid length: " & $addrLen)
    var addr2 = NetAddressV2(networkId: netI2P)
    let bytes = r.readBytes(int(addrLen))
    for i in 0 ..< AddrI2PSize:
      addr2.i2p[i] = bytes[i]
    return some(addr2)

  of netCJDNS:
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
  ##
  ## BIP-155 `services` is a 64-bit bitfield, not a container length, and is
  ## serialized with `CompactSizeFormatter<false>` in Bitcoin Core
  ## (protocol.h:446 — `READWRITE(Using<CompactSizeFormatter<false>>(services_tmp))`).
  ## Pass `range_check=false` to readCompactSize so a peer announcing an
  ## experimental / future service bit at position >= 26 (value > 0x02000000)
  ## does not get rejected with "ReadCompactSize(): size too large" — that
  ## would tear down the whole message loop and disconnect the peer.
  ## Observed on mainnet (2026-05-27): every honest Satoshi peer eventually
  ## triggered this once they relayed any address with a high-bit service
  ## flag set, destroying the per-peer PRESYNC state on each disconnect and
  ## preventing from-genesis IBD from making progress past +782 headers.
  var ta: TimestampedAddrV2
  ta.timestamp = r.readUint32LE()
  ta.services = r.readCompactSize(range_check = false)

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
