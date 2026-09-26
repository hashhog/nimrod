## Self-address advertisement: the local address table (Bitcoin Core parity).
##
## A listening node must tell the network where it can be reached, or nobody
## ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
## only gossip source for OUR address is us. Core does this in three parts; the
## table (part 1) lives here, the per-peer choice and the send (parts 2 and 3)
## live in peermanager.nim because they need the peer set.
##
##  1. A table of local addresses (Core net.cpp mapLocalHost / AddLocal /
##     SeenLocal). Entries come from --externalip (score LocalManual) and from
##     discovery: an outbound peer's VERSION carries addr_recv, the address it
##     sees us at. Core only uses that per-peer (GetLocalAddrForPeer); we also
##     record it here so getnetworkinfo.localaddresses has something to show.
##     A discovered entry's score is the number of DISTINCT peer netgroups that
##     confirmed it, so one peer (or one /16) cannot talk us into advertising an
##     address; it needs MinDiscoveredLocalScore groups before it is used, and
##     it ages out after DiscoveredLocalAddrTTLSec without a fresh confirmation
##     so a changed public IP replaces the old one. Inbound peers only score an
##     entry that already exists (Core SeenLocal).
##  2. GetLocalAddrForPeer (net.cpp:240-268) — peermanager.localAddrForPeer.
##  3. MaybeSendAddr (net_processing.cpp:5445-5479) — peermanager.
##
## The RPC server runs on its own OS thread and reads this table for
## getnetworkinfo, so every access goes through `lock` and entries are plain
## value objects (no refs shared across threads; nimrod builds --mm:arc).

import std/[locks, tables, options, net, strutils, algorithm]
import ./netgroup

const
  # Local address scores (Core net.h enum LOCAL_NONE..LOCAL_MANUAL).
  LocalNone* = 0    ## unknown / discovered
  LocalIf* = 1      ## address a local interface listens on
  LocalBind* = 2    ## address explicitly bound to
  LocalMapped* = 3  ## address reported by PCP/NAT-PMP
  LocalManual* = 4  ## address explicitly specified (--externalip)

  AvgLocalAddressBroadcastIntervalSec* = 24 * 60 * 60
    ## Mean of the exponential delay between self-announcements to one peer
    ## (Core AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL, net_processing.cpp:158).
  LocalAddrCheckIntervalSec* = 60
    ## How often the peer-manager loop looks for peers whose announcement is
    ## due. Coarse is fine against a 24h mean; it also bounds how long after
    ## IBD ends the first (IBD-suppressed) announcement goes out.
  DiscoveredLocalAddrTTLSec* = 3 * 60 * 60
    ## A discovered (non-manual) entry not re-confirmed for this long is dropped.
  MinDiscoveredLocalScore* = 2
    ## Distinct peer netgroups that must confirm a discovered address before
    ## it is advertised to OTHER peers.
  MaxDiscoveredLocalAddrs* = 8
    ## Cap on discovered entries; the weakest is evicted to make room.
  MaxLocalAddrConfirmers* = 64
    ## Cap on the per-entry confirmer set (score ceiling for discovered).

type
  LocalAddress* = object
    ## One row of getnetworkinfo.localaddresses. `port` 0 means "our listen
    ## port" (a bare --externalip IP); peermanager resolves it.
    ip*: array[16, byte]   ## IPv4-mapped (::ffff:a.b.c.d) or native IPv6
    port*: uint16
    score*: int

  LocalAddrEntry = object
    ip: array[16, byte]
    port: uint16
    manual: bool
    baseScore: int            ## LocalManual for --externalip, else 0
    confirmers: seq[string]   ## distinct peer netgroups that confirmed it
    lastSeen: int64           ## unix seconds of the last confirmation

  LocalAddrTable* = object
    ## Core mapLocalHost. Keyed by IP only, like Core (map<CNetAddr, ...>).
    lock: Lock
    entries: Table[array[16, byte], LocalAddrEntry]

proc initLocalAddrTable*(t: var LocalAddrTable) =
  initLock(t.lock)
  t.entries = initTable[array[16, byte], LocalAddrEntry]()

# ---------------------------------------------------------------------------
# IP helpers

proc isIPv4Mapped16*(ip: array[16, byte]): bool =
  for i in 0 ..< 10:
    if ip[i] != 0: return false
  ip[10] == 0xFF and ip[11] == 0xFF

proc ip16FromString*(s: string): Option[array[16, byte]] =
  ## Parse an IPv4 / IPv6 literal (optionally bracketed) into the 16-byte
  ## IPv4-mapped / native-IPv6 form NetAddress uses. none() on a non-literal.
  var str = s.strip()
  if str.len >= 2 and str[0] == '[' and str[^1] == ']':
    str = str[1 ..< str.len - 1]
  let ip =
    try: parseIpAddress(str)
    except ValueError: return none(array[16, byte])
  var b: array[16, byte]
  case ip.family
  of IpAddressFamily.IPv4:
    b[10] = 0xFF
    b[11] = 0xFF
    for i in 0 ..< 4: b[12 + i] = ip.address_v4[i]
  of IpAddressFamily.IPv6:
    b = ip.address_v6
  some(b)

proc ip16ToString*(ip: array[16, byte]): string =
  ## Core CNetAddr::ToStringAddr: dotted quad for IPv4, RFC 5952 for IPv6.
  if isIPv4Mapped16(ip):
    return $ip[12] & "." & $ip[13] & "." & $ip[14] & "." & $ip[15]
  $IpAddress(family: IpAddressFamily.IPv6, address_v6: ip)

proc isRoutable16*(ip: array[16, byte]): bool =
  ## The node's canonical routable filter (netgroup.isRoutable, Core
  ## CNetAddr::IsRoutable) over the 16-byte form. Reused, not re-derived, so
  ## self-advertisement and addr gossip agree on what is routable.
  netgroup.isRoutable(ip)

# ---------------------------------------------------------------------------
# Table operations (all lock-protected)

proc score(e: LocalAddrEntry): int = e.baseScore + e.confirmers.len

proc usable(e: LocalAddrEntry): bool =
  ## May this entry be advertised to arbitrary peers?
  e.manual or e.confirmers.len >= MinDiscoveredLocalScore

proc expireLocked(t: var LocalAddrTable, now: int64) =
  var drop: seq[array[16, byte]]
  for k, e in t.entries:
    if not e.manual and now - e.lastSeen > DiscoveredLocalAddrTTLSec:
      drop.add(k)
  for k in drop: t.entries.del(k)

proc makeRoomLocked(t: var LocalAddrTable) =
  ## Evict the weakest (lowest score, then oldest) discovered entry when the
  ## discovered set is full.
  var n = 0
  var haveWorst = false
  var worstKey: array[16, byte]
  var worstScore = 0
  var worstSeen = 0'i64
  for k, e in t.entries:
    if e.manual: continue
    inc n
    if not haveWorst or e.score < worstScore or
       (e.score == worstScore and e.lastSeen < worstSeen):
      haveWorst = true
      worstKey = k
      worstScore = e.score
      worstSeen = e.lastSeen
  if n >= MaxDiscoveredLocalAddrs and haveWorst:
    t.entries.del(worstKey)

proc addManual*(t: var LocalAddrTable, ip: array[16, byte], port: uint16): bool =
  ## Record an operator-specified address (--externalip). port 0 = "our
  ## listen port". false for a non-routable address, which Core's AddLocal
  ## also refuses.
  if not isRoutable16(ip): return false
  withLock t.lock:
    var e = t.entries.getOrDefault(ip, LocalAddrEntry(ip: ip))
    e.manual = true
    e.baseScore = LocalManual
    e.port = port
    t.entries[ip] = e
  true

proc confirm*(t: var LocalAddrTable, ip: array[16, byte], port: uint16,
              group: string, create: bool, now: int64): bool =
  ## A peer in netgroup `group` sees us at `ip`. With create=false (inbound
  ## peers, Core SeenLocal) only an existing entry is scored; with create=true
  ## (outbound addr_recv discovery) a new entry is made with `port`.
  if not isRoutable16(ip): return false
  withLock t.lock:
    t.expireLocked(now)
    if ip notin t.entries:
      if not create:
        return false
      t.makeRoomLocked()
      t.entries[ip] = LocalAddrEntry(ip: ip, port: port)
    var e = t.entries[ip]
    if group notin e.confirmers and e.confirmers.len < MaxLocalAddrConfirmers:
      e.confirmers.add(group)
    e.lastSeen = now
    t.entries[ip] = e
  true

proc best*(t: var LocalAddrTable, peerIp: Option[array[16, byte]],
           now: int64): Option[LocalAddress] =
  ## Best usable local address for a peer (Core GetLocal): same address family
  ## as the peer first, then highest score, then most recently confirmed.
  withLock t.lock:
    t.expireLocked(now)
    let havePeer = peerIp.isSome
    let peerV4 = havePeer and isIPv4Mapped16(peerIp.get)
    proc reach(e: LocalAddrEntry): int =
      if havePeer and isIPv4Mapped16(e.ip) == peerV4: 1 else: 0
    var found = false
    var b: LocalAddrEntry
    for e in t.entries.values:
      if not e.usable: continue
      if not found or reach(e) > reach(b) or
         (reach(e) == reach(b) and (e.score > b.score or
           (e.score == b.score and e.lastSeen > b.lastSeen))):
        b = e
        found = true
    if found:
      result = some(LocalAddress(ip: b.ip, port: b.port, score: b.score))

proc scoreOf*(t: var LocalAddrTable, ip: array[16, byte]): int =
  ## Core GetnScore: the table score for `ip`, 0 when unknown.
  withLock t.lock:
    if ip in t.entries:
      result = t.entries[ip].score

proc list*(t: var LocalAddrTable, now: int64): seq[LocalAddress] =
  ## Every entry, highest score first (getnetworkinfo.localaddresses).
  withLock t.lock:
    t.expireLocked(now)
    for e in t.entries.values:
      result.add(LocalAddress(ip: e.ip, port: e.port, score: e.score))
  result.sort(proc(a, b: LocalAddress): int =
    if a.score != b.score: cmp(b.score, a.score)
    else: cmp(ip16ToString(a.ip), ip16ToString(b.ip)))

proc len*(t: var LocalAddrTable): int =
  withLock t.lock:
    result = t.entries.len

proc parseExternalIP*(v: string): Option[tuple[ip: array[16, byte], port: uint16]] =
  ## Parse an --externalip value: "<ip>", "<ip>:<port>" or "[<ipv6>]:<port>".
  ## Port 0 in the result means "use the listen port". none() when malformed.
  let s = v.strip()
  if s.len == 0: return none(tuple[ip: array[16, byte], port: uint16])
  let bare = ip16FromString(s)
  if bare.isSome:
    return some((ip: bare.get, port: 0'u16))
  var host, portStr: string
  if s[0] == '[':
    let close = s.find(']')
    if close < 0 or close + 1 >= s.len or s[close + 1] != ':':
      return none(tuple[ip: array[16, byte], port: uint16])
    host = s[1 ..< close]
    portStr = s[close + 2 .. ^1]
  else:
    let colon = s.rfind(':')
    if colon <= 0 or s.count(':') != 1:
      return none(tuple[ip: array[16, byte], port: uint16])
    host = s[0 ..< colon]
    portStr = s[colon + 1 .. ^1]
  let ip = ip16FromString(host)
  if ip.isNone: return none(tuple[ip: array[16, byte], port: uint16])
  let port =
    try: parseInt(portStr)
    except ValueError: -1
  if port <= 0 or port > 65535:
    return none(tuple[ip: array[16, byte], port: uint16])
  some((ip: ip.get, port: uint16(port)))
