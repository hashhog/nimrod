## Ban manager for peer misbehavior tracking
## Implements persistent ban list with JSON storage (Bitcoin Core compatible)
## Reference: /home/max/hashhog/bitcoin/src/banman.cpp

import std/[tables, times, os, strutils]
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

proc normalizeAddress*(address: string): string =
  ## Normalize address for consistent lookup (strip port if present)
  ## Ban by IP, not IP:port
  let colonIdx = address.rfind(':')
  if colonIdx > 0:
    # Check if this might be IPv6
    let bracketIdx = address.find('[')
    if bracketIdx >= 0:
      # IPv6 format: [::1]:8333 - extract the IP portion
      let closeBracket = address.find(']')
      if closeBracket > bracketIdx:
        return address[bracketIdx + 1 ..< closeBracket]
      return address
    else:
      # IPv4 format: 192.168.1.1:8333
      return address[0 ..< colonIdx]
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
        bm.bannedPeers[entry.address] = entry

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
