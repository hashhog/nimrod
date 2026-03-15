## Network group computation for eclipse attack protection
## Computes /16 groups for IPv4 and /32 groups for IPv6
## Reference: Bitcoin Core netgroup.cpp GetGroup()

import std/[net, strutils, hashes]
import chronicles

const
  # Network types (compatible with Bitcoin Core)
  NetIPv4* = 1'u8
  NetIPv6* = 2'u8
  NetOnion* = 3'u8  # Tor .onion
  NetI2P* = 4'u8
  NetCJDNS* = 5'u8
  NetInternal* = 6'u8
  NetLocal* = 7'u8
  NetUnroutable* = 8'u8

type
  NetGroup* = object
    ## Network group identifier
    ## For IPv4: [NetIPv4, first_octet, second_octet] = /16 group
    ## For IPv6: [NetIPv6, first_4_bytes] = /32 group
    ## For other networks: [net_type, first_few_bytes]
    data*: seq[byte]

  IpAddr* = object
    ## IP address wrapper supporting both IPv4 and IPv6
    case isV6*: bool
    of false:
      v4*: array[4, byte]
    of true:
      v6*: array[16, byte]

proc `$`*(g: NetGroup): string =
  result = "NetGroup("
  for i, b in g.data:
    if i > 0: result.add(":")
    result.add(b.toHex(2))
  result.add(")")

proc `==`*(a, b: NetGroup): bool =
  a.data == b.data

proc hash*(g: NetGroup): Hash =
  hash(g.data)

proc parseIpAddr*(s: string): IpAddr =
  ## Parse an IP address string into IpAddr
  ## Supports IPv4 and IPv6 formats
  let normalized = s.strip()

  # Try IPv4 first
  let parts = normalized.split('.')
  if parts.len == 4:
    var isV4 = true
    var bytes: array[4, byte]
    for i, part in parts:
      try:
        let val = parseInt(part)
        if val < 0 or val > 255:
          isV4 = false
          break
        bytes[i] = byte(val)
      except ValueError:
        isV4 = false
        break
    if isV4:
      return IpAddr(isV6: false, v4: bytes)

  # Try IPv6
  # Handle formats like "::1", "::ffff:192.168.1.1", "2001:db8::1"
  try:
    # Strip brackets if present (e.g., "[::1]")
    var ipStr = normalized
    if ipStr.startsWith("[") and ipStr.contains("]"):
      let bracketEnd = ipStr.find(']')
      ipStr = ipStr[1 ..< bracketEnd]

    # Parse IPv6
    let ipv6Parts = ipStr.split("::")
    var bytes: array[16, byte]

    if ipv6Parts.len == 1:
      # No "::" - must have 8 groups
      let groups = ipStr.split(":")
      if groups.len == 8:
        for i, group in groups:
          let val = parseHexInt(group)
          bytes[i * 2] = byte((val shr 8) and 0xFF)
          bytes[i * 2 + 1] = byte(val and 0xFF)
        return IpAddr(isV6: true, v6: bytes)
    elif ipv6Parts.len == 2:
      # Has "::" - expand with zeros
      var leftGroups: seq[string]
      var rightGroups: seq[string]

      if ipv6Parts[0].len > 0:
        leftGroups = ipv6Parts[0].split(":")
      if ipv6Parts[1].len > 0:
        rightGroups = ipv6Parts[1].split(":")

      # Fill left side
      var pos = 0
      for group in leftGroups:
        if group.len > 0:
          let val = parseHexInt(group)
          bytes[pos] = byte((val shr 8) and 0xFF)
          bytes[pos + 1] = byte(val and 0xFF)
          pos += 2

      # Fill right side from end
      pos = 16 - rightGroups.len * 2
      for group in rightGroups:
        if group.len > 0:
          # Check for embedded IPv4 (::ffff:192.168.1.1)
          if group.contains('.'):
            let v4Parts = group.split('.')
            if v4Parts.len == 4:
              for i, part in v4Parts:
                bytes[12 + i] = byte(parseInt(part))
          else:
            let val = parseHexInt(group)
            bytes[pos] = byte((val shr 8) and 0xFF)
            bytes[pos + 1] = byte(val and 0xFF)
        pos += 2

      return IpAddr(isV6: true, v6: bytes)
  except ValueError, CatchableError:
    discard

  # Return unroutable placeholder
  result = IpAddr(isV6: false, v4: [0'u8, 0, 0, 0])

proc `$`*(ip: IpAddr): string =
  if ip.isV6:
    # Format as IPv6
    result = ""
    for i in 0 ..< 8:
      if i > 0: result.add(":")
      let val = (uint16(ip.v6[i * 2]) shl 8) or uint16(ip.v6[i * 2 + 1])
      result.add(val.toHex(4).toLowerAscii())
  else:
    result = $ip.v4[0] & "." & $ip.v4[1] & "." & $ip.v4[2] & "." & $ip.v4[3]

proc isIPv4Mapped*(ip: IpAddr): bool =
  ## Check if this is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
  if not ip.isV6:
    return false

  # Check for ::ffff: prefix
  for i in 0 ..< 10:
    if ip.v6[i] != 0:
      return false
  ip.v6[10] == 0xFF and ip.v6[11] == 0xFF

proc extractIPv4*(ip: IpAddr): array[4, byte] =
  ## Extract IPv4 address from IPv4-mapped IPv6
  if not ip.isV6:
    return ip.v4
  result[0] = ip.v6[12]
  result[1] = ip.v6[13]
  result[2] = ip.v6[14]
  result[3] = ip.v6[15]

proc isLocal*(ip: IpAddr): bool =
  ## Check if this is a local address
  if ip.isV6:
    if ip.isIPv4Mapped():
      let v4 = ip.extractIPv4()
      return v4[0] == 127 or v4[0] == 0
    # IPv6 loopback is ::1
    for i in 0 ..< 15:
      if ip.v6[i] != 0:
        return false
    return ip.v6[15] == 1
  else:
    # 127.0.0.0/8 or 0.0.0.0
    return ip.v4[0] == 127 or (ip.v4[0] == 0 and ip.v4[1] == 0 and
                               ip.v4[2] == 0 and ip.v4[3] == 0)

proc isRoutable*(ip: IpAddr): bool =
  ## Check if this IP is publicly routable
  ## Note: Private addresses (10.x, 192.168.x, 172.16-31.x) are considered
  ## "routable" for netgroup purposes - they just route within private networks.
  ## Only truly unroutable addresses (0.0.0.0, loopback) return false.
  if ip.isV6:
    if ip.isIPv4Mapped():
      let v4 = ip.extractIPv4()
      if v4[0] == 0: return false  # 0.0.0.0
      if v4[0] >= 224: return false  # Multicast and reserved
      # Private ranges are still "routable" for our purposes
      return true
    # IPv6 - loopback is not routable
    if ip.isLocal(): return false
    return true
  else:
    # IPv4
    if ip.v4[0] == 0: return false  # 0.0.0.0
    if ip.v4[0] >= 224: return false  # Multicast and reserved
    # 127.x.x.x is handled by isLocal()
    return true

proc isTor*(ip: IpAddr): bool =
  ## Check if this might be a Tor-encoded address
  ## Bitcoin Core uses special .onion encoding
  false  # Not implemented - would need onion address support

proc isI2P*(ip: IpAddr): bool =
  ## Check if this might be an I2P address
  false  # Not implemented

proc isCJDNS*(ip: IpAddr): bool =
  ## Check if this is a CJDNS address (fc00::/8)
  if ip.isV6:
    return ip.v6[0] == 0xFC
  false

proc getNetGroup*(ip: IpAddr): NetGroup =
  ## Get the network group for this IP address
  ## Reference: Bitcoin Core netgroup.cpp GetGroup()
  ##
  ## For IPv4: /16 group (first 2 octets)
  ## For IPv6: /32 group (first 4 bytes)
  ## For privacy networks (Tor, I2P): first 4 bits
  ## For localhost: all in same group
  ## For unroutable: all in same group

  if ip.isLocal():
    # All localhost addresses in same group
    return NetGroup(data: @[NetLocal])

  if not ip.isRoutable():
    # All unroutable in same group
    return NetGroup(data: @[NetUnroutable])

  if ip.isV6:
    if ip.isIPv4Mapped():
      # IPv4-mapped: use /16 group
      let v4 = ip.extractIPv4()
      return NetGroup(data: @[NetIPv4, v4[0], v4[1]])

    if ip.isCJDNS():
      # CJDNS: use first 12 bits (constant fc byte + 4 bits)
      # Skip the constant fc byte, use next byte
      return NetGroup(data: @[NetCJDNS, ip.v6[1]])

    # Regular IPv6: /32 group (first 4 bytes)
    return NetGroup(data: @[NetIPv6, ip.v6[0], ip.v6[1], ip.v6[2], ip.v6[3]])
  else:
    # IPv4: /16 group (first 2 octets)
    return NetGroup(data: @[NetIPv4, ip.v4[0], ip.v4[1]])

proc getNetGroup*(address: string): NetGroup =
  ## Get network group from address string
  ## Strips port if present
  var addrStr = address

  # Strip port if present
  if addrStr.contains(":"):
    # Check for IPv6 bracket notation [::1]:port
    let bracketIdx = addrStr.find('[')
    if bracketIdx >= 0:
      let closeBracket = addrStr.find(']')
      if closeBracket > bracketIdx:
        addrStr = addrStr[bracketIdx + 1 ..< closeBracket]
    else:
      # Count colons - IPv6 has multiple colons, IPv4:port has exactly one
      var colonCount = 0
      for c in addrStr:
        if c == ':':
          inc colonCount
      if colonCount == 1:
        # IPv4:port format - strip port
        let colonIdx = addrStr.find(':')
        if colonIdx > 0:
          addrStr = addrStr[0 ..< colonIdx]
      # else: IPv6 address with multiple colons - don't modify

  let ip = parseIpAddr(addrStr)
  return getNetGroup(ip)

proc getKeyedNetGroup*(ip: IpAddr, key: uint64): uint64 =
  ## Get a keyed (randomized) network group identifier
  ## Used for deterministic but unpredictable protection in eviction
  ## Reference: Bitcoin Core eviction.cpp CompareNetGroupKeyed
  let group = getNetGroup(ip)
  var h = key
  for b in group.data:
    h = h xor uint64(b)
    h = h * 0x5851F42D4C957F2D'u64  # FNV-style mixing
    h = h xor (h shr 47)
  result = h

proc sameNetGroup*(a, b: IpAddr): bool =
  ## Check if two IPs are in the same network group
  getNetGroup(a) == getNetGroup(b)

proc sameNetGroup*(a, b: string): bool =
  ## Check if two address strings are in the same network group
  getNetGroup(a) == getNetGroup(b)
