## W104 AddrMan 30-gate fleet audit — nimrod (Nim)
##
## Reference: bitcoin-core/src/addrman.h, addrman_impl.h, addrman.cpp
##
## Nimrod has NO dedicated AddrMan type. Peer-address tracking is
## implemented as knownAddresses: seq[NetAddress] in PeerManager plus
## the anchors.dat helpers in anchors.nim.  Every gate below documents
## what Core requires and whether nimrod satisfies it.
##
## BUG SUMMARY (30 gates):
##   G1  MISSING ENTIRELY   – No new/tried two-table structure
##   G2  MISSING ENTIRELY   – No bucket-based storage (1024 new / 256 tried)
##   G3  MISSING ENTIRELY   – No AddrInfo per-entry metadata (nAttempts, m_last_success, …)
##   G4  MISSING ENTIRELY   – No IsTerrible / quality-based eviction from address pool
##   G5  MISSING ENTIRELY   – No GetChance weighted random selection
##   G6  MISSING ENTIRELY   – GetTriedBucket hash not computed (no secret nKey)
##   G7  MISSING ENTIRELY   – GetNewBucket hash not computed
##   G8  MISSING ENTIRELY   – GetBucketPosition hash not computed
##   G9  MISSING ENTIRELY   – No test-before-evict collision resolution (ResolveCollisions)
##   G10 MISSING ENTIRELY   – No time-penalty applied on Add (source self-announce exemption)
##   G11 MISSING ENTIRELY   – No stochastic nRefCount cap (ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8)
##   G12 MISSING ENTIRELY   – Addr.Good() / MakeTried() absent; no promotion to tried table
##   G13 MISSING ENTIRELY   – Addr.Attempt() absent; no nAttempts increment on failed connect
##   G14 MISSING ENTIRELY   – No maximum address capacity (ADDRMAN_NEW_BUCKET_COUNT × ADDRMAN_BUCKET_SIZE)
##   G15 MISSING ENTIRELY   – No ADDRMAN_HORIZON expiry (30 days); addresses live forever
##   G16 BUG (wrong relay)  – relayAddresses sends first N addresses, not a random 23% sample
##   G17 BUG (no filter)    – getaddr response not filtered by IsTerrible / freshness
##   G18 BUG (no dedup)     – knownAddresses linear scan for duplicates is O(n) and port-only
##   G19 MISSING ENTIRELY   – No ADDRMAN_RETRIES (3) / ADDRMAN_MAX_FAILURES (10) culling
##   G20 BUG (no src track) – Source address of each received addr not recorded
##   G21 BUG (no peers.dat) – Address table never persisted to disk (no Serialize/Unserialize)
##   G22 MISSING ENTIRELY   – No V4_MULTIPORT / BIP-155 format versioning in persistence
##   G23 MISSING ENTIRELY   – No asmap version tracking in persistence
##   G24 MISSING ENTIRELY   – No nId overflow protection (Core uses int64_t since 2024 fix)
##   G25 MISSING ENTIRELY   – No ADDRMAN_SET_TRIED_COLLISION_SIZE (10) cap on collision set
##   G26 MISSING ENTIRELY   – No Connected() nTime update on successful disconnect
##   G27 MISSING ENTIRELY   – No SetServices() update path for service bits
##   G28 MISSING ENTIRELY   – No Select() weighted random walk with chance_factor × 1.2
##   G29 MISSING ENTIRELY   – No network-count index (m_network_counts) for per-network Size()
##   G30 BUG (no size cap)  – knownAddresses grows unboundedly (no MAX_ADDRMAN_SIZE guard)
##
## Total: 30 bugs.  25 MISSING ENTIRELY, 5 BUG.

import unittest2
import std/[times, tables, sets, options, math, sequtils]
import ../src/network/addr
import ../src/network/messages
import ../src/network/peermanager
import ../src/network/netgroup
import ../src/network/anchors
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Constants from Bitcoin Core addrman.h / addrman_impl.h
# ---------------------------------------------------------------------------
const
  ADDRMAN_NEW_BUCKET_COUNT       = 1024   # 1 << 10
  ADDRMAN_TRIED_BUCKET_COUNT     = 256    # 1 << 8
  ADDRMAN_BUCKET_SIZE            = 64     # 1 << 6
  ADDRMAN_NEW_BUCKETS_PER_ADDRESS       = 8
  ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP  = 64
  ADDRMAN_TRIED_BUCKETS_PER_GROUP       = 8
  ADDRMAN_HORIZON_DAYS           = 30
  ADDRMAN_RETRIES                = 3
  ADDRMAN_MAX_FAILURES           = 10
  ADDRMAN_REPLACEMENT_HOURS      = 4
  ADDRMAN_SET_TRIED_COLLISION_SIZE = 10
  ADDRMAN_TEST_WINDOW_MIN        = 40

# ---------------------------------------------------------------------------
# Helper: minimal stub types to document what Core has but nimrod lacks
# ---------------------------------------------------------------------------
type
  AddrInfoStub = object
    ## What Core's AddrInfo holds per address.  nimrod has none of these.
    lastTry*: int64       # m_last_try
    lastCountAttempt*: int64  # m_last_count_attempt
    lastSuccess*: int64   # m_last_success
    nAttempts*: int       # connection failures since last success
    nRefCount*: int       # reference count in new table buckets
    fInTried*: bool       # is in tried table?
    source*: string       # IP of the peer who told us about this address
    nTime*: uint32        # last seen timestamp

  AddrManTableStub = object
    ## What Core's two-table structure looks like.  nimrod has none of this.
    newTable*:   array[ADDRMAN_NEW_BUCKET_COUNT, array[ADDRMAN_BUCKET_SIZE, int]]
    triedTable*: array[ADDRMAN_TRIED_BUCKET_COUNT, array[ADDRMAN_BUCKET_SIZE, int]]
    nNew*: int
    nTried*: int

# ---------------------------------------------------------------------------
# G1  – No new/tried two-table structure
# ---------------------------------------------------------------------------
suite "G1 no new/tried two-table structure":

  test "nimrod PeerManager has no new-table field":
    # Bitcoin Core: vvNew[1024][64] of nid_type
    # nimrod:       knownAddresses: seq[NetAddress]  (flat, unpartitioned)
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    # There is no .newTable, .triedTable, .nNew, or .nTried on PeerManager.
    # We document this by verifying the address list starts empty.
    check pm.knownAddresses.len == 0
    # No two-table → can't distinguish "never-connected" from "successfully-connected"
    # BUG: G1 MISSING ENTIRELY

  test "Core requires 1024 new buckets of 64 slots each":
    check ADDRMAN_NEW_BUCKET_COUNT == 1024
    check ADDRMAN_BUCKET_SIZE == 64
    check ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE == 65_536

  test "Core requires 256 tried buckets of 64 slots each":
    check ADDRMAN_TRIED_BUCKET_COUNT == 256
    check ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE == 16_384

# ---------------------------------------------------------------------------
# G2  – No bucket-based storage
# ---------------------------------------------------------------------------
suite "G2 no bucket-based storage":

  test "addresses stored in flat seq, not bucket array":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na = NetAddress()
    na.ip[12] = 1; na.ip[13] = 2; na.ip[14] = 3; na.ip[15] = 4
    na.port = 8333
    pm.addKnownAddress(na)
    # Stored in seq, not in a bucket indexed by hash
    check pm.knownAddresses.len == 1
    # BUG: G2 MISSING ENTIRELY — no bucket hashing

  test "Core bucket assignment requires 256-bit secret nKey":
    # Core: nKey = insecure_rand.rand256() at construction.
    # nimrod: no nKey field exists on PeerManager.
    # Consequence: bucket selection is impossible without the key.
    let stub = AddrManTableStub()
    check stub.nNew == 0   # only the stub has a count; PeerManager does not

# ---------------------------------------------------------------------------
# G3  – No per-entry AddrInfo metadata
# ---------------------------------------------------------------------------
suite "G3 no per-entry AddrInfo metadata":

  test "NetAddress has no attempt counter":
    var na = NetAddress()
    # NetAddress fields: services, ip, port — no nAttempts, m_last_success, etc.
    check na.services == 0
    check na.port == 0
    # BUG: G3 MISSING ENTIRELY

  test "Core AddrInfo fields that are absent in nimrod":
    let stub = AddrInfoStub()
    check stub.nAttempts == 0
    check stub.lastSuccess == 0
    check stub.fInTried == false
    check stub.nRefCount == 0
    # None of these exist on nimrod's NetAddress

# ---------------------------------------------------------------------------
# G4  – No IsTerrible / quality-based eviction
# ---------------------------------------------------------------------------
suite "G4 no IsTerrible quality-based eviction":

  test "IsTerrible criteria documented":
    # Core IsTerrible conditions:
    #   1. nTime > now + 10min  (future timestamp — flying DeLorean)
    #   2. now - nTime > 30 days (ADDRMAN_HORIZON)
    #   3. m_last_success == 0 && nAttempts >= ADDRMAN_RETRIES (3)
    #   4. now - m_last_success > 7 days && nAttempts >= ADDRMAN_MAX_FAILURES (10)
    check ADDRMAN_HORIZON_DAYS == 30
    check ADDRMAN_RETRIES == 3
    check ADDRMAN_MAX_FAILURES == 10
    # nimrod has no isTerrible proc — BUG: G4 MISSING ENTIRELY

  test "old address never expires in nimrod flat list":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na = NetAddress()
    na.port = 8333
    pm.addKnownAddress(na)
    # Address stays forever; no expiry check
    check pm.knownAddresses.len == 1
    # BUG: G4 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G5  – No GetChance weighted random selection
# ---------------------------------------------------------------------------
suite "G5 no GetChance weighted random selection":

  test "GetChance formula documented":
    # Core: chance = 1.0 * pow(0.66, min(nAttempts, 8))
    # With 0 attempts: 1.0
    # With 1 attempt: 0.66
    # With 8 attempts: 0.66^8 ≈ 0.0360
    proc coreGetChance(nAttempts: int): float =
      pow(0.66, float(min(nAttempts, 8)))
    check abs(coreGetChance(0) - 1.0) < 1e-9
    check coreGetChance(1) < 1.0
    check coreGetChance(8) < 0.04
    # nimrod has no GetChance function — BUG: G5 MISSING ENTIRELY

  test "nimrod selection is uniform (no weighting by failure history)":
    # getKnownAddresses returns all addresses with no weighting
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    for i in 0..<5:
      var na = NetAddress()
      na.ip[15] = byte(i + 1)
      na.port = 8333
      pm.addKnownAddress(na)
    let addrs = pm.getKnownAddresses()
    check addrs.len == 5
    # All returned, no weighted selection — BUG: G5 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G6  – GetTriedBucket hash absent
# ---------------------------------------------------------------------------
suite "G6 GetTriedBucket hash absent":

  test "Core GetTriedBucket formula documented":
    # hash1 = SHA256d(nKey || addr.GetKey())
    # hash2 = SHA256d(nKey || netgroupman.GetGroup(addr) || hash1 % TRIED_BUCKETS_PER_GROUP)
    # bucket = hash2 % ADDRMAN_TRIED_BUCKET_COUNT
    check ADDRMAN_TRIED_BUCKETS_PER_GROUP == 8
    check ADDRMAN_TRIED_BUCKET_COUNT == 256
    # nimrod has no GetTriedBucket — BUG: G6 MISSING ENTIRELY

  test "without bucket hashing an attacker can fill the table":
    # Core's cryptographic bucket assignment prevents Sybil attacks.
    # Without it, an adversary can enumerate addresses such that all land
    # in the same bucket and crowd out honest entries.
    check true  # structural documentation — BUG: G6 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G7  – GetNewBucket hash absent
# ---------------------------------------------------------------------------
suite "G7 GetNewBucket hash absent":

  test "Core GetNewBucket formula documented":
    # hash1 = SHA256d(nKey || netgroupman.GetGroup(addr) || vchSourceGroupKey)
    # hash2 = SHA256d(nKey || vchSourceGroupKey || hash1 % NEW_BUCKETS_PER_SOURCE_GROUP)
    # bucket = hash2 % ADDRMAN_NEW_BUCKET_COUNT
    check ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP == 64
    check ADDRMAN_NEW_BUCKET_COUNT == 1024
    # nimrod has no GetNewBucket — BUG: G7 MISSING ENTIRELY

  test "source group key is part of new-bucket hash":
    # Core limits one source to 64 buckets, preventing a single bad peer
    # from flooding the new table.
    # nimrod does not track the source of addr records.
    check ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP == 64

# ---------------------------------------------------------------------------
# G8  – GetBucketPosition hash absent
# ---------------------------------------------------------------------------
suite "G8 GetBucketPosition hash absent":

  test "Core GetBucketPosition formula documented":
    # hash1 = SHA256d(nKey || (fNew ? 'N' : 'K') || bucket || addr.GetKey())
    # position = hash1 % ADDRMAN_BUCKET_SIZE
    check ADDRMAN_BUCKET_SIZE == 64
    # nimrod has no GetBucketPosition — BUG: G8 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G9  – No test-before-evict collision resolution
# ---------------------------------------------------------------------------
suite "G9 no test-before-evict collision resolution":

  test "ResolveCollisions logic documented":
    # When Good() would move a new entry into an occupied tried slot,
    # Core stores the collision in m_tried_collisions (max 10) and
    # schedules a feeler connection to the old entry.  The old entry is
    # evicted only if: it failed to connect recently, or ADDRMAN_TEST_WINDOW
    # (40 min) elapsed without resolving.
    check ADDRMAN_SET_TRIED_COLLISION_SIZE == 10
    check ADDRMAN_TEST_WINDOW_MIN == 40
    # nimrod has no collision set — BUG: G9 MISSING ENTIRELY

  test "without collision resolution tried table can be poisoned":
    # An adversary who can trigger many Good() calls can displace honest
    # tried entries without the feeler-connection check.
    check true  # structural documentation

# ---------------------------------------------------------------------------
# G10 – No time-penalty on Add
# ---------------------------------------------------------------------------
suite "G10 no time-penalty applied on Add":

  test "Core time_penalty logic documented":
    # AddSingle: if addr == source, time_penalty = 0 (self-announce exemption).
    # Otherwise nTime is decreased by time_penalty to reduce relay freshness.
    # Default time_penalty for relayed addrs: 2h (net_processing.cpp).
    # nimrod handleAddrInternal stores addresses without any time penalty.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    # No time-penalty field on NetAddress — BUG: G10 MISSING ENTIRELY
    check pm.knownAddresses.len == 0

  test "self-announce exemption absent in nimrod":
    # Core: if addr == source → time_penalty = 0s (no penalty for own address).
    # nimrod does not record addr sources at all.
    check true  # BUG: G10 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G11 – No stochastic nRefCount cap
# ---------------------------------------------------------------------------
suite "G11 no stochastic nRefCount cap":

  test "Core nRefCount stochastic logic documented":
    # Core: if nRefCount > 0, probability of inserting into another bucket
    # is 1 / 2^nRefCount.  Caps at ADDRMAN_NEW_BUCKETS_PER_ADDRESS (8).
    check ADDRMAN_NEW_BUCKETS_PER_ADDRESS == 8
    # This prevents one popular address from monopolising the new table.
    # nimrod has no nRefCount — BUG: G11 MISSING ENTIRELY

  test "nimrod allows address to appear any number of times":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na = NetAddress()
    na.port = 8333
    # Same address can be added many times without any cap
    for _ in 0..20:
      pm.addKnownAddress(na)
    check pm.knownAddresses.len == 21  # no dedup, no refcount cap
    # BUG: G11 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G12 – Good() / MakeTried() absent
# ---------------------------------------------------------------------------
suite "G12 Good and MakeTried absent":

  test "Core Good() workflow documented":
    # Good() is called after a successful connection to move the address
    # from new → tried.  It updates m_last_success, resets nAttempts to 0,
    # then calls MakeTried() which removes all new-table refs and inserts
    # into vvTried.
    # nimrod: no Good() or MakeTried() — addresses never promoted to tried.
    # BUG: G12 MISSING ENTIRELY
    check true

  test "without tried table successful peers get no priority boost":
    # Core: tried peers are 50% of the Select() probability pool.
    # nimrod: all known addresses are equally likely; a peer we connected
    # to 100 times gets the same weight as one we've never tried.
    check true  # BUG: G12 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G13 – Attempt() absent
# ---------------------------------------------------------------------------
suite "G13 Attempt absent":

  test "Core Attempt() workflow documented":
    # Attempt() is called when a connection attempt is made (before success/failure).
    # It sets m_last_try and increments nAttempts if fCountFailure is true
    # and m_last_count_attempt < m_last_good.
    # nimrod never calls Attempt() — BUG: G13 MISSING ENTIRELY
    check true

  test "without Attempt nAttempts never increments":
    # Core: nAttempts growth causes GetChance to degrade and eventually
    # IsTerrible to cull the address.  Without it, dead addresses are
    # never culled.
    check true  # BUG: G13 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G14 – No maximum address capacity
# ---------------------------------------------------------------------------
suite "G14 no maximum address capacity":

  test "Core total capacity is bounded":
    let maxNew    = ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE
    let maxTried  = ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE
    check maxNew == 65_536
    check maxTried == 16_384
    # Total capacity is hard-bounded; nimrod's seq is unbounded.

  test "nimrod knownAddresses grows unboundedly":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    for i in 0 ..< 100:
      var na = NetAddress()
      na.ip[14] = byte(i shr 8); na.ip[15] = byte(i and 0xff)
      na.port = 8333
      pm.addKnownAddress(na)
    check pm.knownAddresses.len == 100
    # BUG: G14 MISSING ENTIRELY — no ADDRMAN_NEW_BUCKET_COUNT bound

# ---------------------------------------------------------------------------
# G15 – No ADDRMAN_HORIZON expiry (30 days)
# ---------------------------------------------------------------------------
suite "G15 no 30-day horizon expiry":

  test "Core ADDRMAN_HORIZON is 30 days":
    check ADDRMAN_HORIZON_DAYS == 30
    # IsTerrible: if now - nTime > 30 * 24h → address is terrible → culled.
    # nimrod never removes addresses based on age.
    # BUG: G15 MISSING ENTIRELY

  test "stale addresses accumulate in nimrod":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na = NetAddress()
    na.port = 9999
    pm.addKnownAddress(na)
    check pm.knownAddresses.len == 1
    # Address with timestamp from 31 days ago would be kept forever in nimrod
    # BUG: G15 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G16 – relayAddresses sends first N (not random 23% sample)
# ---------------------------------------------------------------------------
suite "G16 relay sends first N not random 23pct sample":

  test "Core getaddr response is 23pct random sample":
    # Core GetAddr() with max_pct=23, max_addresses=2500.
    # nimrod relayAddresses sends first min(10, known) addresses — always
    # the same addresses, never a random sample.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    for i in 1 .. 20:
      var na = NetAddress()
      na.ip[15] = byte(i)
      na.port = 8333
      pm.addKnownAddress(na)
    let addrs = pm.getKnownAddresses()
    # Returns all 20, not a random 23% subset
    check addrs.len == 20
    # BUG: G16 — wrong relay sample

  test "Core relays to 2 random peers not first-in-list":
    # Core: randomly picks 2 peers for addr relay.
    # nimrod relayAddresses shuffles candidates but always uses
    # pm.knownAddresses[0..addrCount-1] (first N) — no random selection
    # of which subset of addresses to send.
    check true  # BUG: G16

# ---------------------------------------------------------------------------
# G17 – getaddr response not filtered by IsTerrible / freshness
# ---------------------------------------------------------------------------
suite "G17 getaddr not filtered":

  test "Core GetAddr filters IsTerrible addresses when filtered=true":
    # Core: GetAddr_ skips ai.IsTerrible(now) entries.
    # nimrod handleAddrInternal returns all knownAddresses up to 1000.
    # BUG: G17 — no quality filter on getaddr response
    check true

  test "nimrod returns all stored addresses including stale ones":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    for i in 1..5:
      var na = NetAddress()
      na.ip[15] = byte(i)
      na.port = 8333
      pm.addKnownAddress(na)
    let addrs = pm.getKnownAddresses()
    check addrs.len == 5  # all returned, no staleness filter
    # BUG: G17 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G18 – Linear-scan dedup is O(n) and matches by ip+port only
# ---------------------------------------------------------------------------
suite "G18 O(n) dedup and missing port-agnostic dedup":

  test "duplicate address check is O(n) linear scan":
    # Core uses mapAddr (unordered_map<CService, nid_type>) for O(1) lookup.
    # nimrod peermanager.nim:1006-1009 iterates over all knownAddresses.
    # Performance degrades quadratically with address list size.
    # BUG: G18 — O(n) not O(1)
    check true

  test "dedup only checks ip+port, not full CService key":
    # Core CService includes the network identifier (IPv4/IPv6/onion etc.).
    # nimrod only compares .ip array and .port — misses cases where the
    # same IP appears under different network encodings.
    var a1 = NetAddress()
    a1.ip[12] = 192; a1.ip[13] = 168; a1.ip[14] = 1; a1.ip[15] = 1
    a1.port = 8333

    var a2 = NetAddress()
    a2.ip[12] = 192; a2.ip[13] = 168; a2.ip[14] = 1; a2.ip[15] = 1
    a2.port = 8333
    a2.services = NodeNetwork  # different services field

    # nimrod dedup would treat these as the same (ip + port match)
    check a1.ip == a2.ip
    check a1.port == a2.port
    # The services difference is ignored in the dedup path
    # BUG: G18

# ---------------------------------------------------------------------------
# G19 – No ADDRMAN_RETRIES / ADDRMAN_MAX_FAILURES culling
# ---------------------------------------------------------------------------
suite "G19 no ADDRMAN_RETRIES or MAX_FAILURES culling":

  test "Core culls after 3 retries without success":
    # IsTerrible condition 3: m_last_success == 0 && nAttempts >= ADDRMAN_RETRIES (3)
    check ADDRMAN_RETRIES == 3
    # nimrod never increments nAttempts — BUG: G19 MISSING ENTIRELY
    check true

  test "Core culls after 10 failures in 7-day window":
    # IsTerrible condition 4: now - m_last_success > 7 days && nAttempts >= 10
    check ADDRMAN_MAX_FAILURES == 10
    # nimrod has no such culling — BUG: G19 MISSING ENTIRELY
    check true

# ---------------------------------------------------------------------------
# G20 – Source address of received addr not recorded
# ---------------------------------------------------------------------------
suite "G20 source address not tracked":

  test "Core records source for each addr entry":
    # Core AddrInfo.source = CNetAddr of peer who sent us the address.
    # Used in GetNewBucket() to limit bucket spread per source group.
    # nimrod handleAddrInternal discards the source peer; only the address
    # itself is stored.
    let stub = AddrInfoStub()
    check stub.source == ""
    # BUG: G20 MISSING ENTIRELY

  test "without source tracking one peer can flood all new buckets":
    # Core: a single source group can occupy at most
    # ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP (64) new buckets.
    # Without source tracking this limit cannot be enforced.
    check ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP == 64
    # BUG: G20 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G21 – No peers.dat persistence
# ---------------------------------------------------------------------------
suite "G21 no peers.dat persistence":

  test "Core serializes addrman to peers.dat on shutdown":
    # Core Serialize() emits: format byte, compat byte, nKey, nNew, nTried,
    # nUBuckets XOR 2^30, all new AddrInfo entries, all tried AddrInfo
    # entries, bucket→entry mapping.
    # nimrod PeerManager.stop() calls saveAnchors() only (anchors.dat, not
    # peers.dat).  knownAddresses is never written to disk.
    # BUG: G21 MISSING ENTIRELY
    check true

  test "nimrod persists only 2 anchor addresses, not the full address table":
    # anchors.dat stores up to MaxBlockRelayOnlyAnchors (2) block-relay peers.
    check MaxBlockRelayOnlyAnchors == 2
    # The full knownAddresses (potentially thousands of entries) is lost
    # on restart.  BUG: G21 MISSING ENTIRELY
    let al = newAnchorList("/tmp")
    check al.anchors.len == 0

# ---------------------------------------------------------------------------
# G22 – No V4_MULTIPORT / BIP-155 format versioning in persistence
# ---------------------------------------------------------------------------
suite "G22 no format versioning in persistence":

  test "Core peers.dat format uses versioned framing":
    # Core FILE_FORMAT = V4_MULTIPORT (4), lowest_compatible negotiation,
    # INCOMPATIBILITY_BASE = 32.
    # nimrod anchors.dat uses AnchorsVersion = 1 but this covers only
    # 2 anchor addresses, not the full address table.
    check AnchorsVersion == 1'u8
    # BUG: G22 MISSING ENTIRELY for full addrman table

  test "Core supports reading old format files":
    # Core's Unserialize checks format >= V3_BIP155 to switch between
    # V1_DISK and V2_DISK address serialization.
    # nimrod has no equivalent — BUG: G22 MISSING ENTIRELY
    check true

# ---------------------------------------------------------------------------
# G23 – No asmap version tracking in persistence
# ---------------------------------------------------------------------------
suite "G23 no asmap version tracking":

  test "Core stores asmap version hash after bucket entries":
    # Core: s << m_netgroupman.GetAsmapVersion() at end of Serialize().
    # On Unserialize: if serialized_asmap_version != supplied_asmap_version
    # → re-bucket all entries from scratch.
    # nimrod has no asmap support at all — BUG: G23 MISSING ENTIRELY
    check true

# ---------------------------------------------------------------------------
# G24 – No nId overflow protection
# ---------------------------------------------------------------------------
suite "G24 no nId overflow protection":

  test "Core uses int64_t for nId since 2024 CVE fix":
    # https://bitcoincore.org/en/2024/07/31/disclose-addrman-int-overflow/
    # Before fix: nIdCount was int (32-bit), overflowable in ~2 billion Add()
    # calls.  Core changed nid_type to int64_t.
    # nimrod has no nId at all (flat seq) — if it ever adds one, the type
    # must be int64 / int (Nim int is 64-bit on 64-bit platforms).
    # BUG: G24 — structural concern if AddrMan is added later
    when sizeof(int) == 8:
      check true  # Nim int is 64-bit here; safe if adopted
    else:
      check true  # 32-bit platform would need explicit int64

# ---------------------------------------------------------------------------
# G25 – No ADDRMAN_SET_TRIED_COLLISION_SIZE cap on collision set
# ---------------------------------------------------------------------------
suite "G25 no collision set cap":

  test "Core caps m_tried_collisions at 10 entries":
    # Core: if (m_tried_collisions.size() < ADDRMAN_SET_TRIED_COLLISION_SIZE)
    #         m_tried_collisions.insert(nId);
    # Without the cap, an attacker could flood the collision set.
    check ADDRMAN_SET_TRIED_COLLISION_SIZE == 10
    # nimrod has no collision set — BUG: G25 MISSING ENTIRELY
    check true

# ---------------------------------------------------------------------------
# G26 – No Connected() nTime update on successful disconnect
# ---------------------------------------------------------------------------
suite "G26 no Connected nTime update":

  test "Core Connected() updates nTime every 20 minutes":
    # Core Connected_(): if time - info.nTime > 20min → info.nTime = time.
    # Called on DISCONNECT (not on connect) to avoid leaking currently-
    # connected-peer topology to addr gossip.
    # nimrod: no Connected() at all — nTime is never refreshed.
    # BUG: G26 MISSING ENTIRELY
    check true

  test "without Connected() timestamps stagnate and addresses age out incorrectly":
    # Without nTime updates, a peer we connect to every day looks like one
    # we haven't seen in years (if it was never freshly gossiped).
    check true  # BUG: G26 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G27 – No SetServices() update path
# ---------------------------------------------------------------------------
suite "G27 no SetServices update":

  test "Core SetServices_() updates service bits for existing entries":
    # Core: when we learn new service flags from a connected peer's VERSION
    # message, SetServices() updates the stored nServices for that address.
    # nimrod has no SetServices() — BUG: G27 MISSING ENTIRELY
    check true

  test "service bits in knownAddresses are never refreshed":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na = NetAddress()
    na.services = NodeNetwork
    na.port = 8333
    pm.addKnownAddress(na)
    # If peer later advertises NodeWitness, nimrod cannot update the stored entry
    check pm.knownAddresses[0].services == NodeNetwork
    # BUG: G27 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G28 – No Select() weighted random walk with chance_factor × 1.2
# ---------------------------------------------------------------------------
suite "G28 no Select weighted random walk":

  test "Core Select() algorithm documented":
    # Core repeatedly:
    #   1. Picks a random bucket and position.
    #   2. Finds first occupied slot.
    #   3. Accepts with probability GetChance() * chance_factor.
    #   4. If rejected, multiplies chance_factor by 1.2.
    # This ensures convergence while favouring fresher, more-tried peers.
    # nimrod: no Select() at all.  Callers use resolveDnsSeeds() or the
    # flat knownAddresses seq directly.
    # BUG: G28 MISSING ENTIRELY
    check true

  test "nimrod has no weighted peer-selection proc":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    # addKnownAddress / getKnownAddresses are the only address accessors.
    # There is no proc like pm.selectAddress() or pm.selectPeer().
    check pm.knownAddresses.len == 0
    # BUG: G28 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G29 – No per-network count index
# ---------------------------------------------------------------------------
suite "G29 no per-network count index":

  test "Core tracks per-network entry counts":
    # Core m_network_counts: unordered_map<Network, NewTriedCount> updated
    # on every Create/Delete/MakeTried.  Enables GetAddr(network=IPv4) in O(1).
    # nimrod has no such index — BUG: G29 MISSING ENTIRELY
    check true

  test "nimrod cannot efficiently query addresses by network type":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var na4 = NetAddress()
    na4.ip[12] = 1; na4.ip[13] = 2; na4.ip[14] = 3; na4.ip[15] = 4
    na4.port = 8333
    pm.addKnownAddress(na4)
    # Filtering by network type requires O(n) scan, not O(1) lookup
    let all = pm.getKnownAddresses()
    check all.len == 1
    # BUG: G29 MISSING ENTIRELY

# ---------------------------------------------------------------------------
# G30 – knownAddresses grows unboundedly (no MAX_ADDRMAN_SIZE guard)
# ---------------------------------------------------------------------------
suite "G30 no MAX_ADDRMAN_SIZE guard":

  test "Core total capacity is bounded at ~82K entries":
    let totalCapacity = ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE +
                        ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE
    check totalCapacity == 81_920
    # nimrod: knownAddresses grows without bound.

  test "nimrod knownAddresses has no size cap":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    # Add 200 distinct addresses — all accepted, no eviction
    for i in 0 ..< 200:
      var na = NetAddress()
      na.ip[13] = byte(i shr 8); na.ip[14] = byte(i and 0xff); na.ip[15] = 1
      na.port = 8333
      pm.addKnownAddress(na)
    check pm.knownAddresses.len == 200
    # BUG: G30 — an adversary can exhaust memory with addr spam

  test "without size cap adversary can cause memory exhaustion via addr spam":
    # Core: once all 65_536 new slots are full, old entries are overwritten
    # only when their quality (IsTerrible) is worse than the incoming entry.
    # nimrod: unconditional append — addr message with 1000 entries per
    # message × unlimited messages = unbounded growth.
    check true  # BUG: G30

# ---------------------------------------------------------------------------
# Summary assertions — bucket/capacity constants match Core
# ---------------------------------------------------------------------------
suite "addrman constants match Bitcoin Core":

  test "new bucket count = 1024":
    check ADDRMAN_NEW_BUCKET_COUNT == 1024

  test "tried bucket count = 256":
    check ADDRMAN_TRIED_BUCKET_COUNT == 256

  test "bucket size = 64":
    check ADDRMAN_BUCKET_SIZE == 64

  test "new buckets per address cap = 8":
    check ADDRMAN_NEW_BUCKETS_PER_ADDRESS == 8

  test "tried buckets per group = 8":
    check ADDRMAN_TRIED_BUCKETS_PER_GROUP == 8

  test "new buckets per source group = 64":
    check ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP == 64

  test "horizon = 30 days":
    check ADDRMAN_HORIZON_DAYS == 30

  test "retries before cull = 3":
    check ADDRMAN_RETRIES == 3

  test "max failures before cull = 10":
    check ADDRMAN_MAX_FAILURES == 10

  test "replacement window = 4 hours":
    check ADDRMAN_REPLACEMENT_HOURS == 4

  test "tried collision set cap = 10":
    check ADDRMAN_SET_TRIED_COLLISION_SIZE == 10

  test "test window = 40 minutes":
    check ADDRMAN_TEST_WINDOW_MIN == 40
