## Network group computation for eclipse attack protection
## Computes /16 groups for IPv4 and /32 groups for IPv6, or ASN-keyed groups
## when an asmap is loaded via NetGroupManager.
## Reference: Bitcoin Core netgroup.cpp GetGroup()

import std/[net, strutils, hashes]
import chronicles
import ./asmap

export asmap

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

      # BUG-G24 FIX: compute the right-side start position correctly.
      # An embedded IPv4 group (contains '.') occupies 4 bytes = 2 groups
      # in the 16-byte IPv6 layout, but counts as only 1 element in
      # rightGroups.  Without accounting for this, the position calculation
      # `16 - rightGroups.len * 2` underestimates the true byte footprint,
      # placing 0xffff at bytes[12-13] instead of bytes[10-11].
      # Fix: count each IPv4-containing element as 2 groups (4 bytes).
      # Reference: RFC 4291 §2.2, ::ffff:a.b.c.d → bytes[10-11]=0xFF, [12-15]=IPv4
      var effectiveGroupCount = 0
      for group in rightGroups:
        if group.contains('.'):
          effectiveGroupCount += 2  # IPv4 counts as 2 × 2-byte groups
        else:
          effectiveGroupCount += 1
      pos = 16 - effectiveGroupCount * 2

      for group in rightGroups:
        if group.len > 0:
          # Check for embedded IPv4 (e.g. ::ffff:192.168.1.1)
          if group.contains('.'):
            let v4Parts = group.split('.')
            if v4Parts.len == 4:
              for i, part in v4Parts:
                bytes[pos + i] = byte(parseInt(part))
            pos += 4  # advance by 4 bytes for the embedded IPv4
          else:
            let val = parseHexInt(group)
            bytes[pos] = byte((val shr 8) and 0xFF)
            bytes[pos + 1] = byte(val and 0xFF)
            pos += 2
        else:
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

proc isRFC1918*(v4: array[4, byte]): bool {.inline.} =
  ## RFC 1918 private IPv4 ranges:
  ##   10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
  ## Reference: Bitcoin Core CNetAddr::IsRFC1918()
  v4[0] == 10 or
  (v4[0] == 192 and v4[1] == 168) or
  (v4[0] == 172 and v4[1] >= 16 and v4[1] <= 31)

proc isRFC2544*(v4: array[4, byte]): bool {.inline.} =
  ## 198.18.0.0/15 — benchmarking (RFC 2544)
  v4[0] == 198 and (v4[1] == 18 or v4[1] == 19)

proc isRFC3927*(v4: array[4, byte]): bool {.inline.} =
  ## 169.254.0.0/16 — link-local (RFC 3927)
  v4[0] == 169 and v4[1] == 254

proc isRFC6598*(v4: array[4, byte]): bool {.inline.} =
  ## 100.64.0.0/10 — shared address space (RFC 6598)
  v4[0] == 100 and v4[1] >= 64 and v4[1] <= 127

proc isRFC5737*(v4: array[4, byte]): bool {.inline.} =
  ## Documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
  (v4[0] == 192 and v4[1] == 0 and v4[2] == 2) or
  (v4[0] == 198 and v4[1] == 51 and v4[2] == 100) or
  (v4[0] == 203 and v4[1] == 0 and v4[2] == 113)

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

proc isRoutable*(ip: IpAddr): bool =
  ## Check if this IP is publicly routable on the global internet.
  ## Reference: Bitcoin Core CNetAddr::IsRoutable()
  ## Rejects: RFC1918, RFC2544, RFC3927, RFC6598, RFC5737, loopback,
  ##          RFC4862 (IPv6 link-local), RFC4193 (IPv6 ULA), plus
  ##          unspecified (0.0.0.0 / ::).
  ##
  ## BUG-G22 FIX: CJDNS (fc00::/8) must be checked BEFORE the ULA
  ## (fc00::/7) rejection.  fc00::/8 is a strict subset of fc00::/7 so
  ## without this early return the ULA guard would reject all CJDNS
  ## addresses, collapsing every CJDNS peer into NetUnroutable.
  ## Reference: bitcoin-core/src/netaddress.cpp CNetAddr::IsRoutable()
  ## — Core treats NET_CJDNS as routable by keeping it out of the
  ## !IsRFC4193() rejection path via the m_net dispatch.
  if ip.isV6:
    # CJDNS (fc00::/8) is routable — check BEFORE the ULA (fc00::/7) guard.
    if ip.isCJDNS(): return true
    if ip.isIPv4Mapped():
      let v4 = ip.extractIPv4()
      if ip.isLocal(): return false             # 127.x.x.x / 0.0.0.0
      if v4[0] >= 224: return false             # multicast + reserved
      if v4.isRFC1918(): return false
      if v4.isRFC2544(): return false
      if v4.isRFC3927(): return false
      if v4.isRFC6598(): return false
      if v4.isRFC5737(): return false
      return true
    if ip.isLocal(): return false               # ::1
    # IPv6 link-local (fe80::/10) — RFC 4862
    if ip.v6[0] == 0xFE and (ip.v6[1] and 0xC0'u8) == 0x80'u8: return false
    # IPv6 ULA (fc00::/7) — RFC 4193 (fd00::/8 and remaining fc00::/7 that is NOT CJDNS)
    if (ip.v6[0] and 0xFE'u8) == 0xFC'u8: return false
    # Unspecified ::
    var allZero = true
    for b in ip.v6:
      if b != 0: allZero = false; break
    if allZero: return false
    return true
  else:
    # Direct IPv4 (non-mapped)
    if ip.v4[0] == 127 or ip.v4[0] == 0: return false
    if ip.v4[0] >= 224: return false            # multicast + reserved
    if ip.v4.isRFC1918(): return false
    if ip.v4.isRFC2544(): return false
    if ip.v4.isRFC3927(): return false
    if ip.v4.isRFC6598(): return false
    if ip.v4.isRFC5737(): return false
    return true

proc isRoutable*(ip: array[16, byte]): bool =
  ## isRoutable overload for the 16-byte IPv4-mapped format used by NetAddress.ip.
  ## Bytes 0-9 must be 0, bytes 10-11 must be 0xFF for an IPv4-mapped address.
  ## Reference: Bitcoin Core CNetAddr::IsRoutable()
  var isV4Mapped = true
  for i in 0..<10:
    if ip[i] != 0: isV4Mapped = false; break
  if isV4Mapped and (ip[10] != 0xFF or ip[11] != 0xFF):
    isV4Mapped = false
  if isV4Mapped:
    let v4: array[4, byte] = [ip[12], ip[13], ip[14], ip[15]]
    if v4[0] == 127 or v4[0] == 0: return false
    if v4[0] >= 224: return false
    if v4.isRFC1918(): return false
    if v4.isRFC2544(): return false
    if v4.isRFC3927(): return false
    if v4.isRFC6598(): return false
    if v4.isRFC5737(): return false
    return true
  else:
    # Native IPv6
    var allZero = true
    for b in ip:
      if b != 0: allZero = false; break
    if allZero: return false
    # loopback ::1
    var isLoopback = true
    for i in 0..<15:
      if ip[i] != 0: isLoopback = false; break
    if isLoopback and ip[15] == 1: return false
    # IPv6 link-local fe80::/10
    if ip[0] == 0xFE and (ip[1] and 0xC0'u8) == 0x80'u8: return false
    # IPv6 ULA fc00::/7
    if (ip[0] and 0xFE'u8) == 0xFC'u8: return false
    return true

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

# ---------------------------------------------------------------------------
# ASN-aware helpers (NetGroupManager integration)
# ---------------------------------------------------------------------------

proc ipAddrTo16Bytes(ip: IpAddr): array[16, byte] =
  ## Convert IpAddr to the 16-byte form expected by interpret().
  ## IPv4 addresses are returned as ::ffff:a.b.c.d (bytes 10-11 = 0xFF).
  if ip.isV6:
    result = ip.v6
  else:
    # Map to ::ffff:a.b.c.d
    result[10] = 0xFF
    result[11] = 0xFF
    result[12] = ip.v4[0]
    result[13] = ip.v4[1]
    result[14] = ip.v4[2]
    result[15] = ip.v4[3]

proc getMappedAS*(mgr: NetGroupManager, ip: IpAddr): uint32 =
  ## Return the ASN for `ip` using the loaded asmap (0 when not available).
  ## IPv4-mapped IPv6 addresses are correctly unwrapped before lookup.
  ## Reference: Bitcoin Core CConnman::GetMappedAS(), net.cpp:3800
  if not mgr.usingAsmap:
    return 0
  var lookupIp = ip
  # Unwrap IPv4-in-IPv6 (::ffff:a.b.c.d) to native IPv4 first
  if ip.isV6 and ip.isIPv4Mapped():
    let v4 = ip.extractIPv4()
    lookupIp = IpAddr(isV6: false, v4: v4)
  # Privacy networks (Tor, I2P) — no clearnet ASN, short-circuit to 0
  # (Core's GetMappedAS also returns 0 for these)
  # CJDNS is clearnet-routable and should go through Interpret
  mgr.getMappedAS(ipAddrTo16Bytes(lookupIp))

proc getNetGroupAsn*(mgr: NetGroupManager, ip: IpAddr): NetGroup =
  ## Return an ASN-keyed NetGroup when asmap is loaded, else fall back to
  ## the standard /16 (IPv4) or /32 (IPv6) group.
  ## Reference: Bitcoin Core NetGroupManager::GetGroup()
  if mgr.usingAsmap:
    let asn = getMappedAS(mgr, ip)
    if asn != 0:
      # Encode the 4-byte ASN big-endian as the group discriminator
      return NetGroup(data: @[
        byte((asn shr 24) and 0xFF),
        byte((asn shr 16) and 0xFF),
        byte((asn shr  8) and 0xFF),
        byte( asn         and 0xFF)
      ])
  # Fallback to /16 / /32 group
  getNetGroup(ip)
