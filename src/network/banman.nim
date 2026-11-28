## Ban manager for peer misbehavior tracking
## Implements persistent ban list with JSON storage (Bitcoin Core compatible)
## Reference: /home/max/hashhog/bitcoin/src/banman.cpp

import std/[tables, times, os, strutils, net]
import chronicles
import jsony

export chronicles

const
  DefaultBanDuration* = initDuration(hours = 24)
  BanListFileName* = "banlist.json"

type
  BanReason* = enum
    brManuallyAdded = "manually-added"
    brMisbehaving = "misbehaving"

  BanEntry* = object
    address*: string
    banCreated*: int64      # Unix timestamp when ban was created
    banUntil*: int64        # Unix timestamp when ban expires
    reason*: BanReason

  BanList* = object
    entries*: seq[BanEntry]

  BanManager* = ref object
    bannedPeers*: Table[string, BanEntry]
    dataDir*: string
    isDirty*: bool

proc newBanManager*(dataDir: string = "."): BanManager =
  BanManager(
    bannedPeers: initTable[string, BanEntry](),
    dataDir: dataDir,
    isDirty: false
  )

proc banListPath*(bm: BanManager): string =
  bm.dataDir / BanListFileName

proc isPortText(s: string): bool =
  s.len > 0 and s.allCharsInSet(Digits)

proc canonicalIp(ip: IpAddress): string =
  ## One text form per address, so the key compares like Core's CNetAddr
  ## (by bytes): lowercase, zero-compressed IPv6, and an IPv4-mapped IPv6
  ## address folded to dotted IPv4 (Core stores ::ffff:a.b.c.d as IPv4, and
  ## anchors.ipToString writes it that way too).
  if ip.family == IpAddressFamily.IPv6:
    var mapped = ip.address_v6[10] == 0xff'u8 and ip.address_v6[11] == 0xff'u8
    for i in 0 ..< 10:
      if ip.address_v6[i] != 0: mapped = false
    if mapped:
      let b = ip.address_v6
      return $b[12] & "." & $b[13] & "." & $b[14] & "." & $b[15]
  $ip

proc normalizeAddress*(address: string): string =
  ## Normalize address for consistent lookup: ban by IP, not IP:port.
  ##
  ## A port is stripped only from "[v6]:port" or a single-colon "host:port"
  ## (IPv4:port). A bare IPv6 literal -- which is exactly what inbound peers
  ## hand us as `$remoteAddr.address` -- is kept whole: cutting it at the
  ## last ':' turned "2001:db8::1" into the key "2001:db8:", so one ban hit
  ## every neighbour that differs only in the last group. Core's BanMan bans
  ## the exact CNetAddr (or an explicit subnet ban), never a derived range.
  ## A numeric IP is returned in canonical form (see canonicalIp), so the
  ## inbound, anchor (full eight-group) and setban spellings of one address
  ## share one key.
  # 1. A bare numeric IP (v4 or unbracketed v6).
  try:
    return canonicalIp(parseIpAddress(address))
  except ValueError:
    discard
  # 2. "[v6]" or "[v6]:port" -> the bracketed part.
  if address.len > 0 and address[0] == '[':
    let closeBracket = address.find(']')
    if closeBracket > 0:
      let rest = address[closeBracket + 1 .. ^1]
      if rest.len == 0 or (rest[0] == ':' and isPortText(rest[1 .. ^1])):
        let inner = address[1 ..< closeBracket]
        try:
          return canonicalIp(parseIpAddress(inner))
        except ValueError:
          return inner
    return address
  # 3. "host:port" with exactly one colon (IPv4:port). Anything with two or
  #    more colons is IPv6 text (e.g. a "2001:db8::/32" subnet) and is left
  #    alone rather than truncated.
  let colonIdx = address.rfind(':')
  if colonIdx > 0 and address.find(':') == colonIdx and
      isPortText(address[colonIdx + 1 .. ^1]):
    let host = address[0 ..< colonIdx]
    try:
      return canonicalIp(parseIpAddress(host))
    except ValueError:
      return host
  address

proc load*(bm: BanManager) =
  ## Load ban list from disk
  let path = bm.banListPath()
  if not fileExists(path):
    info "no ban list found, starting fresh", path = path
    return

  try:
    let content = readFile(path)
    let banList = content.fromJson(BanList)

    let now = getTime().toUnix()
    for entry in banList.entries:
      # Skip expired entries
      if entry.banUntil > now:
        # Re-key through normalizeAddress: a file written before keys were
        # canonical can hold e.g. "2001:DB8::1", which lookups never produce.
        var e = entry
        e.address = normalizeAddress(entry.address)
        if e.address in bm.bannedPeers and
            bm.bannedPeers[e.address].banUntil >= e.banUntil:
          continue
        bm.bannedPeers[e.address] = e

    info "loaded ban list", count = bm.bannedPeers.len, path = path
  except CatchableError as e:
    error "failed to load ban list", error = e.msg, path = path
  except Exception as e:
    # jsony can throw Exception
    error "failed to parse ban list", error = e.msg, path = path

proc save*(bm: BanManager) =
  ## Save ban list to disk
  if not bm.isDirty:
    return

  # Sweep expired entries before saving
  let now = getTime().toUnix()
  var toRemove: seq[string]
  for address, entry in bm.bannedPeers:
    if entry.banUntil <= now:
      toRemove.add(address)
  for address in toRemove:
    bm.bannedPeers.del(address)

  var banList: BanList
  for entry in bm.bannedPeers.values:
    banList.entries.add(entry)

  try:
    # Ensure data directory exists
    if not dirExists(bm.dataDir):
      createDir(bm.dataDir)

    let content = banList.toJson()
    writeFile(bm.banListPath(), content)
    bm.isDirty = false
    debug "saved ban list", count = banList.entries.len, path = bm.banListPath()
  except CatchableError as e:
    error "failed to save ban list", error = e.msg

proc isBanned*(bm: BanManager, address: string): bool =
  ## Check if an address is currently banned
  let normalizedAddr = normalizeAddress(address)
  if normalizedAddr notin bm.bannedPeers:
    return false

  let entry = bm.bannedPeers[normalizedAddr]
  let now = getTime().toUnix()

  if now >= entry.banUntil:
    # Ban expired, remove it
    bm.bannedPeers.del(normalizedAddr)
    bm.isDirty = true
    return false

  true

proc ban*(bm: BanManager, address: string, duration: Duration = DefaultBanDuration,
          reason: BanReason = brMisbehaving) =
  ## Ban an address for the specified duration
  let normalizedAddr = normalizeAddress(address)
  let now = getTime()
  let banUntil = now + duration

  let entry = BanEntry(
    address: normalizedAddr,
    banCreated: now.toUnix(),
    banUntil: banUntil.toUnix(),
    reason: reason
  )

  # Only update if this extends the ban
  if normalizedAddr in bm.bannedPeers:
    let existing = bm.bannedPeers[normalizedAddr]
    if existing.banUntil >= entry.banUntil:
      return  # Existing ban is longer

  bm.bannedPeers[normalizedAddr] = entry
  bm.isDirty = true

  info "peer banned", address = normalizedAddr, duration = $duration, reason = $reason

  # Save immediately (Bitcoin Core behavior)
  bm.save()

proc banAbsolute*(bm: BanManager, address: string, banUntil: int64,
                  reason: BanReason = brManuallyAdded) =
  ## Ban an address until a specific Unix timestamp
  let normalizedAddr = normalizeAddress(address)
  let now = getTime().toUnix()

  # Don't add bans that are already expired
  if banUntil <= now:
    return

  let entry = BanEntry(
    address: normalizedAddr,
    banCreated: now,
    banUntil: banUntil,
    reason: reason
  )

  # Only update if this extends the ban
  if normalizedAddr in bm.bannedPeers:
    let existing = bm.bannedPeers[normalizedAddr]
    if existing.banUntil >= entry.banUntil:
      return

  bm.bannedPeers[normalizedAddr] = entry
  bm.isDirty = true

  info "peer banned (absolute)", address = normalizedAddr, banUntil = banUntil, reason = $reason
  bm.save()

proc unban*(bm: BanManager, address: string): bool =
  ## Remove a ban on an address. Returns true if ban was removed.
  let normalizedAddr = normalizeAddress(address)
  if normalizedAddr notin bm.bannedPeers:
    return false

  bm.bannedPeers.del(normalizedAddr)
  bm.isDirty = true
  info "peer unbanned", address = normalizedAddr
  bm.save()
  true

proc clearBanned*(bm: BanManager) =
  ## Clear all bans
  if bm.bannedPeers.len == 0:
    return

  bm.bannedPeers.clear()
  bm.isDirty = true
  info "cleared all bans"
  bm.save()

proc sweepExpired*(bm: BanManager) =
  ## Remove expired bans from the list
  let now = getTime().toUnix()
  var toRemove: seq[string]

  for address, entry in bm.bannedPeers:
    if entry.banUntil <= now:
      toRemove.add(address)

  if toRemove.len > 0:
    for address in toRemove:
      bm.bannedPeers.del(address)
      debug "ban expired", address = address
    bm.isDirty = true
    bm.save()

proc listBanned*(bm: BanManager): seq[BanEntry] =
  ## Get list of all current bans (sweeps expired first)
  bm.sweepExpired()
  for entry in bm.bannedPeers.values:
    result.add(entry)

proc getBanTimeRemaining*(bm: BanManager, address: string): Duration =
  ## Get time remaining on a ban, or zeroDuration if not banned
  let normalizedAddr = normalizeAddress(address)
  if normalizedAddr notin bm.bannedPeers:
    return initDuration()

  let entry = bm.bannedPeers[normalizedAddr]
  let now = getTime().toUnix()

  if now >= entry.banUntil:
    return initDuration()

  initDuration(seconds = entry.banUntil - now)
