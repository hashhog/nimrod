## Core-bucketed address manager (CAddrMan) for nimrod.
##
## Axis #2 (persistent bucketed addrman).  nimrod previously tracked
## peer addresses in two parallel flat seqs (knownAddresses +
## knownAddressesV2) where addKnownAddress just appended — no buckets, no
## per-manager salt, no anti-Sybil placement, and no peers.dat persistence.
## This module replaces that internal store with the full Bitcoin Core
## CAddrMan model (bitcoin-core/src/addrman.{cpp,h} + addrman_impl.h):
##
##  - NEW[1024][64] + TRIED[256][64] id-tables + mapInfo/mapAddr + a
##    per-manager 256-bit nKey salt.
##  - Deterministic placement keyed off nKey + netgroups: getNewBucket
##    (H(nKey, addrGroup, srcGroup) then H(nKey, srcGroup, ..) % 1024; a
##    source group reaches only NEW_BUCKETS_PER_SOURCE_GROUP=64 buckets,
##    anti-Sybil), getTriedBucket (TRIED_BUCKETS_PER_GROUP=8, % 256),
##    getBucketPosition (% BUCKET_SIZE=64).
##  - add (new-bucket placement + IsTerrible/refcount collision), good
##    (promote NEW->TRIED, tried-collision evicts the occupant back to its
##    NEW bucket), select (50/50 new/tried bias), attempt.
##  - Bounded ceiling 1024*64 + 256*64 = 81920 slots.
##  - Versioned, corrupt-safe, bounded peers.dat-equiv persistence that
##    round-trips the placement (re-bucketed from the persisted nKey).
##
## The PeerManager keeps its rich knownAddresses/knownAddressesV2 metadata
## seqs for getnodeaddresses / addr-sharing; THIS table is the placement +
## anti-Sybil + persistence engine wired under addKnownAddress.  Mirrors the
## rustoshi 361d81b retrofit (crates/network/src/peer_manager.rs).
##
## NOTE: the cheap hash here is impl-internal (single SHA-256 truncated to the
## low 8 bytes, little-endian).  peers.dat is a LOCAL file (never wire/RPC), so
## byte-identical Core bucket numbers are not required and not claimed; the
## golden test pins THIS impl's chosen hash.

import std/[tables, strutils, times, options, random, os]
import ./netgroup
import ../crypto/hashing

# ---------------------------------------------------------------------------
# Constants — exact Bitcoin Core addrman.h / addrman_impl.h values.
# ---------------------------------------------------------------------------
const
  AddrmanNewBucketCount*            = 1024  # 1 << 10 (ADDRMAN_NEW_BUCKET_COUNT)
  AddrmanTriedBucketCount*          = 256   # 1 << 8  (ADDRMAN_TRIED_BUCKET_COUNT)
  AddrmanBucketSize*                = 64    # 1 << 6  (ADDRMAN_BUCKET_SIZE)
  AddrmanNewBucketsPerSourceGroup*  = 64    # ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP
  AddrmanTriedBucketsPerGroup*      = 8     # ADDRMAN_TRIED_BUCKETS_PER_GROUP
  AddrmanNewBucketsPerAddress*      = 8     # ADDRMAN_NEW_BUCKETS_PER_ADDRESS
  AddrmanHorizonSecs*               = 30 * 24 * 60 * 60  # ADDRMAN_HORIZON (30 d)
  AddrmanRetries*                   = 3     # ADDRMAN_RETRIES
  AddrmanMaxFailures*               = 10    # ADDRMAN_MAX_FAILURES
  AddrmanMinFailSecs*               = 7 * 24 * 60 * 60   # ADDRMAN_MIN_FAIL (7 d)

  ## Hard slot ceiling: every id occupies at most one slot per table, and no
  ## table can grow past its fixed bucket geometry.  This is the bounded ceiling.
  AddrmanCeiling* = AddrmanNewBucketCount * AddrmanBucketSize +
                    AddrmanTriedBucketCount * AddrmanBucketSize  # 81920

  ## On-disk format version for the peers.dat-equiv.  Bumping invalidates older
  ## files (they load as an empty cold start, never a hard-down).
  AddrmanDatVersion* = 1'u32
  ## Filename for the bucketed addrman persistence (peers.dat-equiv).
  PeersDatabaseFilename* = "peers.dat"

  EmptySlot = -1'i64  # empty-slot sentinel (Core nid_type -1)

type
  NId* = int64  ## integer node id (Core nid_type).

  AddrManEntry* = object
    ## One address record held by the bucketed addrman.  Mirrors Core
    ## AddrInfo's bookkeeping fields (refcount, in_tried, attempt/success/seen
    ## times).
    ip*: array[16, byte]   ## 16-byte IPv4-mapped / native IPv6 address
    port*: uint16
    services*: uint64
    source*: array[16, byte]  ## where we first heard about it (for new-bucket grouping)
    timeUnix*: int64       ## last-seen unix timestamp (seconds)
    lastSuccessUnix*: int64  ## last-success unix timestamp (0 = never)
    lastTryUnix*: int64    ## last-try unix timestamp (0 = never)
    attempts*: uint32      ## consecutive connection attempts
    refCount*: uint32      ## how many new buckets reference this id (Core nRefCount)
    inTried*: bool         ## whether this id currently lives in the tried table

  AddrKey* = tuple[ip: array[16, byte], port: uint16]
    ## Stable address identity (Core CService key) for mapAddr.

  AddrManTable* = ref object
    ## Core-bucketed address manager: the NEW/TRIED tables + id maps + salt.
    nkey*: array[32, byte]   ## 256-bit per-manager salt (Core nKey); persisted; drives all placement
    vvNew: seq[array[AddrmanBucketSize, NId]]    ## NEW table  [bucket][pos] = id or -1
    vvTried: seq[array[AddrmanBucketSize, NId]]  ## TRIED table [bucket][pos] = id or -1
    mapInfo: Table[NId, AddrManEntry]            ## id -> entry (Core mapInfo)
    mapAddr: Table[AddrKey, NId]                 ## addr -> id (Core mapAddr)
    idCount: NId                                 ## next id to allocate (Core nIdCount)
    nNew*: int                                   ## ids in the new table (Core nNew)
    nTried*: int                                 ## ids in the tried table (Core nTried)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc nowUnix(): int64 {.inline.} =
  getTime().toUnix()

proc ipAddrOf(ip16: array[16, byte]): IpAddr =
  ## Recover an IpAddr from the 16-byte form (IPv4-mapped -> IPv4).
  var isV4Mapped = true
  for i in 0..<10:
    if ip16[i] != 0: isV4Mapped = false; break
  if isV4Mapped and (ip16[10] != 0xFF or ip16[11] != 0xFF):
    isV4Mapped = false
  if isV4Mapped:
    return IpAddr(isV6: false, v4: [ip16[12], ip16[13], ip16[14], ip16[15]])
  else:
    return IpAddr(isV6: true, v6: ip16)

proc groupBytes(ng: NetGroupManager, ip16: array[16, byte]): seq[byte] =
  ## NetGroupManager group bytes for an address (ASN-keyed when asmap loaded,
  ## else /16 or /32).  Reuses nimrod's Core-faithful netgroup engine.
  getNetGroupAsn(ng, ipAddrOf(ip16)).data

proc cheapHash(parts: varargs[seq[byte]]): uint64 =
  ## Cheap hash (Core HashWriter::GetCheapHash analogue): single SHA-256 of the
  ## concatenated parts, low 8 bytes interpreted little-endian.
  var buf: seq[byte] = @[]
  for p in parts:
    buf.add(p)
  let h = sha256(buf)
  result = 0'u64
  for i in 0..<8:
    result = result or (uint64(h[i]) shl (8 * i))

proc addrKey(ip16: array[16, byte], port: uint16): seq[byte] =
  ## Stable key bytes for an address (Core CService::GetKey analogue):
  ## 16-byte IPv6 representation + 2-byte big-endian port.
  result = newSeqOfCap[byte](18)
  for b in ip16: result.add(b)
  result.add(byte((port shr 8) and 0xFF))
  result.add(byte(port and 0xFF))

proc u64le(v: uint64): seq[byte] =
  result = newSeq[byte](8)
  for i in 0..<8: result[i] = byte((v shr (8 * i)) and 0xFF)

proc u32le(v: uint32): seq[byte] =
  result = newSeq[byte](4)
  for i in 0..<4: result[i] = byte((v shr (8 * i)) and 0xFF)

# ---------------------------------------------------------------------------
# IsTerrible (Core addrman.cpp:49-72)
# ---------------------------------------------------------------------------
proc isTerrible*(info: AddrManEntry, now: int64): bool =
  ## Should this entry be eviction-preferred?  Ports the five Core conditions.
  # never remove things tried in the last minute
  if info.lastTryUnix != 0 and (now - info.lastTryUnix) <= 60:
    return false
  # came in a flying DeLorean
  if info.timeUnix > now + 10 * 60:
    return true
  # not seen in recent history
  if (now - info.timeUnix) > AddrmanHorizonSecs:
    return true
  # tried N times and never a success
  if info.lastSuccessUnix == 0 and info.attempts >= uint32(AddrmanRetries):
    return true
  # N successive failures in the last week
  if info.lastSuccessUnix != 0 and
     (now - info.lastSuccessUnix) > AddrmanMinFailSecs and
     info.attempts >= uint32(AddrmanMaxFailures):
    return true
  false

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------
proc newAddrManTableWithKey*(nkey: array[32, byte]): AddrManTable =
  ## Create an empty table with a fixed salt (deterministic; for tests +
  ## persistence restore).
  result = AddrManTable(
    nkey: nkey,
    vvNew: newSeq[array[AddrmanBucketSize, NId]](AddrmanNewBucketCount),
    vvTried: newSeq[array[AddrmanBucketSize, NId]](AddrmanTriedBucketCount),
    mapInfo: initTable[NId, AddrManEntry](),
    mapAddr: initTable[AddrKey, NId](),
    idCount: 0,
    nNew: 0,
    nTried: 0,
  )
  for b in 0..<AddrmanNewBucketCount:
    for p in 0..<AddrmanBucketSize:
      result.vvNew[b][p] = EmptySlot
  for b in 0..<AddrmanTriedBucketCount:
    for p in 0..<AddrmanBucketSize:
      result.vvTried[b][p] = EmptySlot

proc newAddrManTable*(): AddrManTable =
  ## Create an empty table with a random salt.
  var nkey: array[32, byte]
  for i in 0..<32:
    nkey[i] = byte(rand(255))
  newAddrManTableWithKey(nkey)

# ---------------------------------------------------------------------------
# Placement — getNewBucket / getTriedBucket / getBucketPosition
# ---------------------------------------------------------------------------
proc getNewBucket(t: AddrManTable, addrGroup, srcGroup: seq[byte]): int =
  ## Core AddrInfo::GetNewBucket.
  let hash1 = cheapHash(@(t.nkey), addrGroup, srcGroup)
  let hash2 = cheapHash(@(t.nkey), srcGroup,
                        u64le(hash1 mod uint64(AddrmanNewBucketsPerSourceGroup)))
  int(hash2 mod uint64(AddrmanNewBucketCount))

proc getTriedBucket(t: AddrManTable, ip16: array[16, byte], port: uint16,
                    addrGroup: seq[byte]): int =
  ## Core AddrInfo::GetTriedBucket.
  let hash1 = cheapHash(@(t.nkey), addrKey(ip16, port))
  let hash2 = cheapHash(@(t.nkey), addrGroup,
                        u64le(hash1 mod uint64(AddrmanTriedBucketsPerGroup)))
  int(hash2 mod uint64(AddrmanTriedBucketCount))

proc getBucketPosition(t: AddrManTable, fNew: bool, bucket: int,
                       ip16: array[16, byte], port: uint16): int =
  ## Core AddrInfo::GetBucketPosition.
  let tag: seq[byte] = @[if fNew: byte('N') else: byte('K')]
  let hash1 = cheapHash(@(t.nkey), tag, u32le(uint32(bucket)), addrKey(ip16, port))
  int(hash1 mod uint64(AddrmanBucketSize))

# ---------------------------------------------------------------------------
# Internal id management — find / create / delete / clearNew
# ---------------------------------------------------------------------------
proc find(t: AddrManTable, ip16: array[16, byte], port: uint16): NId =
  ## Look up the id for an address (Core Find).  EmptySlot if absent.
  let k: AddrKey = (ip16, port)
  if t.mapAddr.hasKey(k): t.mapAddr[k] else: EmptySlot

proc create(t: AddrManTable, ip16: array[16, byte], port: uint16,
            source: array[16, byte], services: uint64, timeUnix: int64): NId =
  ## Allocate a fresh entry (Core Create).
  let id = t.idCount
  inc t.idCount
  t.mapInfo[id] = AddrManEntry(
    ip: ip16, port: port, services: services, source: source,
    timeUnix: timeUnix, lastSuccessUnix: 0, lastTryUnix: 0,
    attempts: 0, refCount: 0, inTried: false)
  t.mapAddr[(ip16, port)] = id
  id

proc deleteId(t: AddrManTable, id: NId) =
  ## Delete a refcount-0, non-tried id entirely (Core Delete).
  if t.mapInfo.hasKey(id):
    let info = t.mapInfo[id]
    if info.refCount == 0 and not info.inTried:
      t.mapAddr.del((info.ip, info.port))
      t.mapInfo.del(id)

proc clearNew(t: AddrManTable, bucket, pos: int) =
  ## Clear a new-table slot, decrementing the occupant refcount and deleting at
  ## 0 (Core ClearNew).
  let id = t.vvNew[bucket][pos]
  if id != EmptySlot:
    if t.mapInfo.hasKey(id):
      if t.mapInfo[id].refCount > 0:
        t.mapInfo[id].refCount -= 1
      let rc = t.mapInfo[id].refCount
      t.vvNew[bucket][pos] = EmptySlot
      if rc == 0:
        t.nNew = max(0, t.nNew - 1)
        t.deleteId(id)
    else:
      t.vvNew[bucket][pos] = EmptySlot

proc groupsOf(t: AddrManTable, info: AddrManEntry,
              ng: NetGroupManager): (seq[byte], seq[byte]) =
  (groupBytes(ng, info.ip), groupBytes(ng, info.source))

# ---------------------------------------------------------------------------
# add — Core Add_/AddSingle
# ---------------------------------------------------------------------------
proc add*(t: AddrManTable, ip16: array[16, byte], port: uint16,
          source: array[16, byte], services: uint64, timeUnix: int64,
          ng: NetGroupManager): bool =
  ## Place a heard-about address in the NEW table.  Returns true if a fresh
  ## slot insertion occurred.  Non-routable addrs and the bounded-ceiling guard
  ## cause a `false` return.
  if not isRoutable(ip16):
    return false
  let now = nowUnix()

  let existing = t.find(ip16, port)
  var id: NId
  if existing != EmptySlot:
    id = existing
    # Refresh existing (Core AddSingle update path).
    if t.mapInfo.hasKey(id):
      if timeUnix > t.mapInfo[id].timeUnix:
        t.mapInfo[id].timeUnix = timeUnix
      t.mapInfo[id].services = t.mapInfo[id].services or services
      if t.mapInfo[id].inTried:
        return false
      if t.mapInfo[id].refCount >= uint32(AddrmanNewBucketsPerAddress):
        return false
      # stochastic multiplicity gate: 2^refcount harder each time.
      if t.mapInfo[id].refCount > 0:
        let factor = 1'u32 shl t.mapInfo[id].refCount
        if uint32(rand(int(factor) - 1)) != 0'u32:
          return false
  else:
    # Bounded-ceiling guard: never allocate past the table capacity.
    if t.mapInfo.len >= AddrmanCeiling:
      return false
    id = t.create(ip16, port, source, services, timeUnix)

  # Compute the placement.
  let (addrGroup, srcGroup) = t.groupsOf(t.mapInfo[id], ng)
  let bucket = t.getNewBucket(addrGroup, srcGroup)
  let pos = t.getBucketPosition(true, bucket, ip16, port)

  let occupant = t.vvNew[bucket][pos]
  var insert = occupant == EmptySlot
  if occupant != id:
    if not insert:
      # Collision: overwrite iff occupant terrible, or occupant
      # multiply-referenced while the newcomer is fresh (Core rule).
      if t.mapInfo.hasKey(occupant):
        let o = t.mapInfo[occupant]
        let newRef = if t.mapInfo.hasKey(id): t.mapInfo[id].refCount else: 0'u32
        insert = o.isTerrible(now) or (o.refCount > 1 and newRef == 0)
      else:
        insert = true
    if insert:
      t.clearNew(bucket, pos)
      if t.mapInfo.hasKey(id):
        t.mapInfo[id].refCount += 1
      t.vvNew[bucket][pos] = id
      t.nNew += 1
    elif t.mapInfo.hasKey(id) and t.mapInfo[id].refCount == 0:
      # newly-created but not inserted -> drop it.
      t.deleteId(id)
  result = insert

# ---------------------------------------------------------------------------
# good — Core Good_/MakeTried
# ---------------------------------------------------------------------------
proc good*(t: AddrManTable, ip16: array[16, byte], port: uint16, now: int64,
           ng: NetGroupManager): bool =
  ## Promote an address from NEW to TRIED, evicting the existing tried occupant
  ## back to its NEW bucket on collision.
  let id = t.find(ip16, port)
  if id == EmptySlot:
    return false
  # Update try/success bookkeeping (Core Good_).
  if t.mapInfo.hasKey(id):
    t.mapInfo[id].lastSuccessUnix = now
    t.mapInfo[id].lastTryUnix = now
    t.mapInfo[id].attempts = 0
    if t.mapInfo[id].inTried:
      return false
    if t.mapInfo[id].refCount == 0:
      return false

  # Remove the id from ALL its new buckets (Core MakeTried loop).
  let (agNew, sgNew) = t.groupsOf(t.mapInfo[id], ng)
  let startB = t.getNewBucket(agNew, sgNew)
  for n in 0..<AddrmanNewBucketCount:
    let b = (startB + n) mod AddrmanNewBucketCount
    let p = t.getBucketPosition(true, b, ip16, port)
    if t.vvNew[b][p] == id:
      t.vvNew[b][p] = EmptySlot
      if t.mapInfo.hasKey(id):
        if t.mapInfo[id].refCount > 0:
          t.mapInfo[id].refCount -= 1
        if t.mapInfo[id].refCount == 0:
          break
  t.nNew = max(0, t.nNew - 1)
  if t.mapInfo.hasKey(id):
    t.mapInfo[id].refCount = 0

  # Compute the tried slot.
  let (agTried, _) = t.groupsOf(t.mapInfo[id], ng)
  let kBucket = t.getTriedBucket(ip16, port, agTried)
  let kPos = t.getBucketPosition(false, kBucket, ip16, port)

  # On collision evict the existing tried occupant back to NEW.
  let evict = t.vvTried[kBucket][kPos]
  if evict != EmptySlot:
    t.vvTried[kBucket][kPos] = EmptySlot
    t.nTried = max(0, t.nTried - 1)
    if t.mapInfo.hasKey(evict):
      t.mapInfo[evict].inTried = false
    # Recompute its new slot and place it back.
    let old = t.mapInfo[evict]
    let (oag, osg) = t.groupsOf(old, ng)
    let ob = t.getNewBucket(oag, osg)
    let op = t.getBucketPosition(true, ob, old.ip, old.port)
    t.clearNew(ob, op)
    if t.mapInfo.hasKey(evict):
      t.mapInfo[evict].refCount = 1
    t.vvNew[ob][op] = evict
    t.nNew += 1

  # Place the promoted id into tried.
  t.vvTried[kBucket][kPos] = id
  t.nTried += 1
  if t.mapInfo.hasKey(id):
    t.mapInfo[id].inTried = true
  result = true

# ---------------------------------------------------------------------------
# attempt — Core Attempt_
# ---------------------------------------------------------------------------
proc attempt*(t: AddrManTable, ip16: array[16, byte], port: uint16, now: int64) =
  ## Record a (possibly-failed) connection attempt.
  let k: AddrKey = (ip16, port)
  if t.mapAddr.hasKey(k):
    let id = t.mapAddr[k]
    if t.mapInfo.hasKey(id):
      t.mapInfo[id].lastTryUnix = now
      t.mapInfo[id].attempts += 1

# ---------------------------------------------------------------------------
# select — Core Select_ (simplified, bounded, liveness-safe)
# ---------------------------------------------------------------------------
proc select*(t: AddrManTable, newOnly: bool = false): Option[AddrKey] =
  ## 50/50 new-vs-tried when both are non-empty, then scan a random bucket from
  ## a random position and return the first occupant.  Bounded; returns an
  ## occupant whenever one exists.  (GetChance()*1.2^miss bias is a follow-up.)
  if t.mapInfo.len == 0:
    return none(AddrKey)
  if newOnly and t.nNew == 0:
    return none(AddrKey)
  if t.nNew + t.nTried == 0:
    return none(AddrKey)

  let searchTried =
    if newOnly or t.nTried == 0: false
    elif t.nNew == 0: true
    else: rand(1) == 1

  let bucketCount = if searchTried: AddrmanTriedBucketCount else: AddrmanNewBucketCount

  let startBucket = rand(bucketCount - 1)
  let initialPos = rand(AddrmanBucketSize - 1)
  for nb in 0..<bucketCount:
    let bucket = (startBucket + nb) mod bucketCount
    for i in 0..<AddrmanBucketSize:
      let pos = (initialPos + i) mod AddrmanBucketSize
      let id = if searchTried: t.vvTried[bucket][pos] else: t.vvNew[bucket][pos]
      if id != EmptySlot and t.mapInfo.hasKey(id):
        let info = t.mapInfo[id]
        return some((info.ip, info.port))
  none(AddrKey)

# ---------------------------------------------------------------------------
# Inspection helpers (tests + diagnostics)
# ---------------------------------------------------------------------------
proc newCount*(t: AddrManTable): int = t.nNew
proc triedCount*(t: AddrManTable): int = t.nTried
proc totalCount*(t: AddrManTable): int = t.mapInfo.len

# ---------------------------------------------------------------------------
# Per-network new/tried counts — backing for the getaddrmaninfo RPC.
# Mirrors Core AddrMan::Size(net, in_new) (addrman.cpp Size_ :1006-1026): a
# per-network split of the NEW and TRIED tables.  Core keys these by the
# address' GetNetClass() (netaddress.cpp).  nimrod's bucketed addrman stores
# every entry in the 16-byte IPv4-mapped / native-IPv6 form, so it can hold
# the three networks representable in 16 bytes: ipv4 (::ffff:a.b.c.d), cjdns
# (fc00::/8), and ipv6 (everything else routable).  Onion v3 (32-byte) and
# I2P (32-byte) do NOT fit this 16-byte store and are never placed here, so
# their counts are always 0 (the getaddrmaninfo handler still emits those
# keys at 0/0/0 to keep Core's fixed 6-key shape).
# ---------------------------------------------------------------------------
proc netClassName(ip16: array[16, byte]): string =
  ## Map a stored 16-byte addrman entry to its Core network-name string.
  ## GetNetClass parity for the networks a 16-byte address can encode.
  ## IPv4-mapped (::ffff:a.b.c.d) -> "ipv4"; fc00::/8 -> "cjdns"; otherwise
  ## native IPv6 -> "ipv6".  (Unroutable entries are never stored — add()
  ## gates on isRoutable — so no not_publicly_routable/internal mapping is
  ## needed; those are excluded from getaddrmaninfo by construction.)
  var isV4Mapped = true
  for i in 0..<10:
    if ip16[i] != 0: isV4Mapped = false; break
  if isV4Mapped and (ip16[10] != 0xFF or ip16[11] != 0xFF):
    isV4Mapped = false
  if isV4Mapped:
    return "ipv4"
  if ip16[0] == 0xFC'u8:   # CJDNS fc00::/8 (checked before the ULA range)
    return "cjdns"
  "ipv6"

proc networkCounts*(t: AddrManTable): Table[string, tuple[newCount, triedCount: int]] =
  ## Per-(network, table) counts for getaddrmaninfo.  Returns a map keyed by
  ## Core network name -> (new-table count, tried-table count).  Networks with
  ## no stored entries are simply absent from the map; the RPC handler
  ## pre-seeds the full Core key set at zero before merging this in.
  ##
  ## Iterates mapInfo (the id->entry store) once and bumps the matching
  ## (network, in_new|in_tried) counter, exactly mirroring Core's per-network
  ## Size(net, in_new) split.  O(n) over the addrman, pure read, no mutation.
  result = initTable[string, tuple[newCount, triedCount: int]]()
  for info in t.mapInfo.values:
    let name = netClassName(info.ip)
    var cur = result.getOrDefault(name, (0, 0))
    if info.inTried:
      cur.triedCount += 1
    else:
      cur.newCount += 1
    result[name] = cur

proc isInTried*(t: AddrManTable, ip16: array[16, byte], port: uint16): bool =
  let k: AddrKey = (ip16, port)
  t.mapAddr.hasKey(k) and t.mapInfo.hasKey(t.mapAddr[k]) and
    t.mapInfo[t.mapAddr[k]].inTried

proc newSlotOf*(t: AddrManTable, ip16: array[16, byte], port: uint16,
                ng: NetGroupManager): Option[(int, int)] =
  ## Recompute the (bucket, pos) an address currently occupies in NEW.  None if
  ## not in NEW.  Used by the determinism tests.
  let k: AddrKey = (ip16, port)
  if not t.mapAddr.hasKey(k): return none((int, int))
  let id = t.mapAddr[k]
  if not t.mapInfo.hasKey(id): return none((int, int))
  let info = t.mapInfo[id]
  if info.inTried: return none((int, int))
  let (ag, sg) = t.groupsOf(info, ng)
  let startB = t.getNewBucket(ag, sg)
  for n in 0..<AddrmanNewBucketCount:
    let b = (startB + n) mod AddrmanNewBucketCount
    let p = t.getBucketPosition(true, b, ip16, port)
    if t.vvNew[b][p] == id:
      return some((b, p))
  none((int, int))

proc triedSlotOf*(t: AddrManTable, ip16: array[16, byte], port: uint16,
                  ng: NetGroupManager): Option[(int, int)] =
  ## The (bucket, pos) an address occupies in TRIED.  None if not in TRIED.
  let k: AddrKey = (ip16, port)
  if not t.mapAddr.hasKey(k): return none((int, int))
  let id = t.mapAddr[k]
  if not t.mapInfo.hasKey(id): return none((int, int))
  let info = t.mapInfo[id]
  if not info.inTried: return none((int, int))
  let (ag, _) = t.groupsOf(info, ng)
  let kb = t.getTriedBucket(ip16, port, ag)
  let kp = t.getBucketPosition(false, kb, ip16, port)
  some((kb, kp))

# ---------------------------------------------------------------------------
# Persistence — versioned, corrupt-safe, bounded peers.dat-equiv
# ---------------------------------------------------------------------------
proc ip16ToStr(ip16: array[16, byte]): string =
  ## Encode the 16-byte address as 32 lowercase hex chars (port stored
  ## separately) — unambiguous and round-trips exactly.
  result = newStringOfCap(32)
  for b in ip16:
    result.add(toHex(int(b), 2).toLowerAscii())

proc strToIp16(s: string): Option[array[16, byte]] =
  if s.len != 32: return none(array[16, byte])
  var buf: array[16, byte]
  for i in 0..<16:
    try:
      buf[i] = byte(parseHexInt(s[2*i .. 2*i+1]))
    except ValueError:
      return none(array[16, byte])
  some(buf)

proc nkeyHex(t: AddrManTable): string =
  result = newStringOfCap(64)
  for b in t.nkey:
    result.add(toHex(int(b), 2).toLowerAscii())

proc hexDecode32(s: string): Option[array[32, byte]] =
  ## Decode a 64-char hex string into a 32-byte nkey.  None on bad input.
  if s.len != 64: return none(array[32, byte])
  var buf: array[32, byte]
  for i in 0..<32:
    try:
      buf[i] = byte(parseHexInt(s[2*i .. 2*i+1]))
    except ValueError:
      return none(array[32, byte])
  some(buf)

proc serialize*(t: AddrManTable): string =
  ## Serialize to a versioned, line-oriented text format.
  ##   line 0: "ADDRMAN <version> <nkey-hex>"
  ##   then one record per id:
  ##     "<n|t> <ip16hex> <port> <services> <source-ip16hex> <time> <last_success> <last_try> <attempts> <ref_count>"
  ## New records are re-placed via add() on load; tried records are re-promoted
  ## via good() so placement is recomputed deterministically from the same nkey.
  result = "ADDRMAN " & $AddrmanDatVersion & " " & t.nkeyHex() & "\n"
  for info in t.mapInfo.values:
    let tag = if info.inTried: "t" else: "n"
    result.add(tag & " " & ip16ToStr(info.ip) & " " & $info.port & " " &
               $info.services & " " & ip16ToStr(info.source) & " " &
               $info.timeUnix & " " & $info.lastSuccessUnix & " " &
               $info.lastTryUnix & " " & $info.attempts & " " &
               $info.refCount & "\n")

proc parse*(contents: string, ng: NetGroupManager): Option[AddrManTable] =
  ## Parse the serialized form.  Returns none on any structural problem so the
  ## caller can cold-start.  Bounded by AddrmanCeiling.
  let lines = contents.splitLines()
  if lines.len == 0: return none(AddrManTable)
  let hp = lines[0].splitWhitespace()
  if hp.len < 3 or hp[0] != "ADDRMAN": return none(AddrManTable)
  var version: uint32
  try:
    version = uint32(parseInt(hp[1]))
  except ValueError:
    return none(AddrManTable)
  if version != AddrmanDatVersion: return none(AddrManTable)
  let nkeyOpt = hexDecode32(hp[2])
  if nkeyOpt.isNone: return none(AddrManTable)
  let table = newAddrManTableWithKey(nkeyOpt.get())

  var triedAddrs: seq[AddrKey] = @[]
  for li in 1..<lines.len:
    let line = lines[li].strip()
    if line.len == 0: continue
    if table.mapInfo.len >= AddrmanCeiling: break
    let f = line.splitWhitespace()
    if f.len < 10: return none(AddrManTable)
    let ip16Opt = strToIp16(f[1])
    if ip16Opt.isNone: return none(AddrManTable)
    let srcOpt = strToIp16(f[4])
    if srcOpt.isNone: return none(AddrManTable)
    var port: uint16
    var services: uint64
    var timeUnix, lastSuccess, lastTry: int64
    var attempts: uint32
    try:
      port = uint16(parseInt(f[2]))
      services = uint64(parseBiggestUInt(f[3]))
      timeUnix = parseBiggestInt(f[5])
      lastSuccess = parseBiggestInt(f[6])
      lastTry = parseBiggestInt(f[7])
      attempts = uint32(parseInt(f[8]))
    except ValueError:
      return none(AddrManTable)
    let ip16 = ip16Opt.get()
    let src = srcOpt.get()
    # (Re)create via add() so the new-bucket placement is recomputed.
    discard table.add(ip16, port, src, services, timeUnix, ng)
    let k: AddrKey = (ip16, port)
    if table.mapAddr.hasKey(k):
      let id = table.mapAddr[k]
      if table.mapInfo.hasKey(id):
        table.mapInfo[id].lastSuccessUnix = lastSuccess
        table.mapInfo[id].lastTryUnix = lastTry
        table.mapInfo[id].attempts = attempts
    if f[0] == "t":
      triedAddrs.add((ip16, port))
  # Second pass: promote the tried records.
  let now = nowUnix()
  for (ip16, port) in triedAddrs:
    discard table.good(ip16, port, now, ng)
  some(table)

proc save*(t: AddrManTable, dataDir: string) =
  ## Atomic save to `<dataDir>/peers.dat` (temp + rename).  Best-effort;
  ## failures are swallowed, never fatal.
  let path = dataDir / PeersDatabaseFilename
  let tmp = path & ".tmp"
  try:
    createDir(dataDir)
    writeFile(tmp, t.serialize())
    moveFile(tmp, path)
  except CatchableError:
    try: removeFile(tmp)
    except CatchableError: discard

proc load*(dataDir: string, ng: NetGroupManager): AddrManTable =
  ## Load from `<dataDir>/peers.dat`, re-bucketing via add()/good() so placement
  ## is recomputed from the persisted nkey.  Corrupt / truncated / wrong-version
  ## / missing files yield a graceful empty cold start (never a crash).
  let path = dataDir / PeersDatabaseFilename
  var contents: string
  try:
    contents = readFile(path)
  except CatchableError:
    return newAddrManTable()
  let parsed = parse(contents, ng)
  if parsed.isSome: parsed.get() else: newAddrManTable()
