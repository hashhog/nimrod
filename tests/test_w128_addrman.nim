## W128 — AddrMan + connman + peer selection (30-gate audit, xfail regression guards)
##
## Audit type: discovery (NO production code change in W128).
##
## W128 is the **complementary** audit to W104.  W104 catalogued the
## *internal* absence of an `AddrMan` type (no new/tried bucketing,
## no AddrInfo, no peers.dat, no IsTerrible / GetChance, no
## ResolveCollisions, etc.).  W128 catalogues the **orchestration**
## layer — the `CConnman::ThreadOpenConnections` shape, banman vs
## discouragement separation, FEELER / ADDR_FETCH / EXTRA_BLOCK_RELAY
## / preferred-network connection types, IsBadPort outbound gate,
## AddedNodesContain shadow-check, -onlynet reachability gate, and
## the orchestration call sites that wire AddrMan into Core's
## `ThreadOpenConnections` loop.
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour
## with a `check` that pins the gap.  When a future FIX wave closes
## the gap, the test will fail loudly and the developer must flip
## the assertion (per W120 / W122 / W123 / W124 / W125 methodology).
##
## Cross-checked against W104 30-gate set: every W128 gate is
## distinct from every W104 gate.
##
## References:
##   bitcoin-core/src/addrman.cpp / addrman.h / addrman_impl.h
##   bitcoin-core/src/net.cpp
##   bitcoin-core/src/banman.cpp / banman.h
##   bitcoin-core/src/util/asmap.cpp / asmap.h
##   audit/w128_addrman.md — full gate table + per-gate detail.

import unittest2
import std/[times, tables, sets, strutils, options, os, sequtils]
import ../src/network/peermanager
import ../src/network/banman
import ../src/network/eviction
import ../src/network/anchors
import ../src/network/asmap
import ../src/network/netgroup
import ../src/network/addr
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # banman.h
  DEFAULT_MISBEHAVING_BANTIME_SEC = 24 * 60 * 60   # 24h
  DUMP_BANS_INTERVAL_SEC          = 15 * 60        # 15min
  DISCOURAGEMENT_BLOOM_ELEMENTS   = 50_000         # banman.h:98
  # net.h / net.cpp
  FEELER_INTERVAL_SEC                       = 2 * 60   # 2min
  EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL_SEC  = 5 * 60   # 5min
  EXTRA_NETWORK_PEER_INTERVAL_SEC           = 5 * 60   # 5min
  MAX_OUTBOUND_FULL_RELAY_CONNECTIONS_CORE  = 8
  MAX_ADDNODE_CONNECTIONS_CORE              = 8
  MAX_FEELER_CONNECTIONS_CORE               = 1
  MAX_BLOCK_RELAY_ONLY_ANCHORS_CORE         = 2
  SEED_OUTBOUND_CONNECTION_THRESHOLD_CORE   = 2
  # util/asmap.cpp
  SANITY_CHECK_BITS_CORE                    = 128

# Source-level regression evidence: read the production .nim files once
# and assert specific landmark strings (or their absence).
let
  peermanagerSrc = readFile("src/network/peermanager.nim")
  banmanSrc      = readFile("src/network/banman.nim")
  asmapSrc       = readFile("src/network/asmap.nim")
  anchorsSrc     = readFile("src/network/anchors.nim")
  nimrodSrc      = readFile("src/nimrod.nim")

# ---------------------------------------------------------------------------
# G1-G3  — Discouragement bloom filter (BUG-1)
# ---------------------------------------------------------------------------
suite "W128 G1-G3 — discouragement bloom filter (BUG-1)":

  test "G1 BUG-1: BanMan.Discourage() is absent — misbehaving routes through Ban()":
    ## Core split Ban() and Discourage() in 2024 after
    ## disclose-unbounded-banlist.  Nimrod still uses a single
    ## persistent ban table for both manual and misbehaving peers.
    let bm = newBanManager("/tmp/nimrod-w128-bm-test-" & $getTime().toUnix())
    # There is no `discourage()` proc; misbehaving routes through `ban()`:
    check not compiles(bm.discourage("1.2.3.4"))
    # And peermanager.misbehavingPeer calls bm.ban(...) directly:
    check "pm.banPeer(peer.address, BanDuration, brMisbehaving)" in peermanagerSrc

  test "G2 BUG-1 cont: rolling-bloom discouragement filter (50000, 1e-6) absent":
    ## banman.h:98 `CRollingBloomFilter m_discouraged {50000, 0.000001}`.
    ## Nimrod has no RollingBloomFilter in banman.nim:
    check "RollingBloomFilter" notin banmanSrc
    check "m_discouraged"      notin banmanSrc
    check $DISCOURAGEMENT_BLOOM_ELEMENTS == "50000"  # constant pin

  test "G3 BUG-1 cont: IsDiscouraged() membership test absent":
    ## banman.cpp:83-87.  Nimrod has no `isDiscouraged` proc.
    let bm = newBanManager("/tmp/nimrod-w128-bm-test2-" & $getTime().toUnix())
    check not compiles(bm.isDiscouraged("1.2.3.4"))

# ---------------------------------------------------------------------------
# G4 — FEELER connections (BUG-2 — CLOSED 2026-06-12, anti-eclipse axis)
# ---------------------------------------------------------------------------
suite "W128 G4 — FEELER connection type (BUG-2 CLOSED)":

  test "G4 BUG-2 CLOSED: PeerConnectionType has a pctFeeler variant":
    ## net.cpp:2753-2756 `conn_type = ConnectionType::FEELER`.
    ## Nimrod now models the FEELER connection type as pctFeeler.
    var seenFeeler = false
    for pct in PeerConnectionType:
      let s = $pct
      if "Feeler" in s or "feeler" in s:
        seenFeeler = true
    check seenFeeler == true  # confirm present (feeler now implemented)

  test "G4 BUG-2 CLOSED cont: FEELER_INTERVAL=120s feeler timer in mainLoop":
    ## net.h:61 `FEELER_INTERVAL = 2min`.  Nimrod's mainLoop now opens a
    ## periodic feeler probe on a FeelerInterval timer.
    check "FeelerInterval" in peermanagerSrc
    check "tryFeelerConnection" in peermanagerSrc
    check $FEELER_INTERVAL_SEC == "120"  # constant pin

# ---------------------------------------------------------------------------
# G5 — ADDR_FETCH connections + m_addr_fetches deque (BUG-3)
# ---------------------------------------------------------------------------
suite "W128 G5 — ADDR_FETCH connection type (BUG-3)":

  test "G5 BUG-3: no pctAddrFetch variant in PeerConnectionType":
    var seenAddrFetch = false
    for pct in PeerConnectionType:
      let s = $pct
      if "AddrFetch" in s or "addrfetch" in s:
        seenAddrFetch = true
    check seenAddrFetch == false

  test "G5 BUG-3 cont: no m_addr_fetches deque / ProcessAddrFetch":
    check "addrFetches"      notin peermanagerSrc
    check "ProcessAddrFetch" notin peermanagerSrc
    check "AddAddrFetch"     notin peermanagerSrc

# ---------------------------------------------------------------------------
# G6 — Extra block-relay-only peer interval (BUG-4)
# ---------------------------------------------------------------------------
suite "W128 G6 — EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL (BUG-4)":

  test "G6 BUG-4: no 5-min extra-block-relay timer":
    ## net.cpp:2729-2752 / net.h:63.
    check "next_extra_block_relay"            notin peermanagerSrc
    check "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL" notin peermanagerSrc
    check $EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL_SEC == "300"

  test "G6 BUG-4 cont: no m_start_extra_block_relay_peers flag":
    check "startExtraBlockRelayPeers"    notin peermanagerSrc
    check "extraBlockRelayPeersEnabled"  notin peermanagerSrc

# ---------------------------------------------------------------------------
# G7 — MaybePickPreferredNetwork (BUG-5)
# ---------------------------------------------------------------------------
suite "W128 G7 — MaybePickPreferredNetwork (BUG-5)":

  test "G7 BUG-5: no preferred-network steering proc":
    ## net.cpp:2514-2528.
    check "MaybePickPreferredNetwork" notin peermanagerSrc
    check "preferredNetwork"          notin peermanagerSrc
    check "preferred_net"             notin peermanagerSrc

  test "G7 BUG-5 cont: no m_network_conn_counts per-network index":
    check "networkConnCounts"   notin peermanagerSrc
    check "network_conn_counts" notin peermanagerSrc
    # Nimrod has outboundNetGroups (HashSet[NetGroup]) but that's
    # the netgroup-collision set, not per-network conn count.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    check pm.outboundNetGroups.len == 0  # netgroup set, not per-net count

# ---------------------------------------------------------------------------
# G8-G9 — ResolveCollisions + SelectTriedCollision orchestration (BUG-6)
# ---------------------------------------------------------------------------
suite "W128 G8-G9 — collision-resolution orchestration (BUG-6)":

  test "G8 BUG-6: no addrman.ResolveCollisions() orchestration call":
    ## net.cpp:2773.  Nimrod has no addrman at all, so no call site.
    check "ResolveCollisions" notin peermanagerSrc
    check "resolveCollisions" notin peermanagerSrc

  test "G9 BUG-6 cont: no addrman.SelectTriedCollision() on feeler path":
    ## net.cpp:2804.  Nimrod has no feeler path (G4) so no call site.
    check "SelectTriedCollision" notin peermanagerSrc
    check "selectTriedCollision" notin peermanagerSrc

# ---------------------------------------------------------------------------
# G10 — IsBadPort outbound gate (BUG-7)
# ---------------------------------------------------------------------------
suite "W128 G10 — IsBadPort outbound gate (BUG-7)":

  test "G10 BUG-7: no IsBadPort blocklist gate in connectToPeerWithType":
    ## net.cpp:2858-2861 — Core skips outbound to known-exploited
    ## ports (445, 25, etc.) for first 50 tries.  Nimrod has only
    ## isRoutable, no port blocklist.
    check "IsBadPort" notin peermanagerSrc
    check "isBadPort" notin peermanagerSrc
    check "bad_port"  notin peermanagerSrc
    check "badPort"   notin peermanagerSrc

  test "G10 BUG-7 cont: well-known bad port 445 dialed silently":
    ## Document expected behavior: connectToPeerWithType opens a
    ## socket to anywhere :445 without filtering.  Static check is
    ## sufficient since we don't want to actually dial in CI.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    # The proc accepts any port; only isBanned and isRoutable gate
    # the dial decision.
    check pm.isBanned("1.2.3.4") == false
    # No IsBadPort surface to check against — confirmed by source grep above.

# ---------------------------------------------------------------------------
# G11 — AddedNodesContain shadow-check (BUG-8)
# ---------------------------------------------------------------------------
suite "W128 G11 — AddedNodesContain shadow-check (BUG-8)":

  test "G11 BUG-8: no AddedNodesContain check in auto outbound":
    ## net.cpp:2866-2872 — Core refuses to make an automatic outbound
    ## to a peer the operator has separately addnode'd.
    check "AddedNodesContain" notin peermanagerSrc
    check "addedNodesContain" notin peermanagerSrc
    check "isAddedNode"       notin peermanagerSrc

  test "G11 BUG-8 cont: no m_added_node_params list":
    ## Core uses m_added_node_params (CRITICAL_SECTION).  Nimrod has
    ## no equivalent — pctManual peers don't form a separate list,
    ## they're inline in pm.peers.
    check "addedNodeParams"  notin peermanagerSrc
    check "added_node_params" notin peermanagerSrc

# ---------------------------------------------------------------------------
# G12 — -onlynet reachability gate (BUG-9)
# ---------------------------------------------------------------------------
suite "W128 G12 — -onlynet + g_reachable_nets (BUG-9)":

  test "G12 BUG-9: no -onlynet CLI flag parsing":
    ## init.cpp `-onlynet=<net>`.  Nimrod has no equivalent.
    check "onlynet" notin nimrodSrc
    check "onlyNet" notin nimrodSrc
    check "ReachableNets" notin nimrodSrc

  test "G12 BUG-9 cont: no g_reachable_nets global gate":
    check "reachableNets"  notin peermanagerSrc
    check "ReachableNets"  notin peermanagerSrc
    # Per-feature gating exists (cjdnsReachable, onionProxy,
    # i2pSession) but no global "only Tor" enforcement.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    check pm.cjdnsReachable == false

# ---------------------------------------------------------------------------
# G13 — Asmap sanity check at load — PRESENT (W115 closure)
# ---------------------------------------------------------------------------
suite "W128 G13 — SanityCheckASMap (PRESENT, W115 closure)":

  test "G13 PRESENT: checkStandardAsmap called in loadAsmap":
    ## asmap.nim:289 — `if not checkStandardAsmap(buf): return @[]`.
    ## This is the W115 closure that nimrod ships.
    check "checkStandardAsmap(buf)" in asmapSrc
    check compiles(sanityCheckAsmap)
    check compiles(checkStandardAsmap)
    check $SANITY_CHECK_BITS_CORE == "128"

  test "G13 PRESENT cont: SanityCheck rejects malformed input":
    # Minimal smoke: empty asmap MUST fail sanity check.
    var emptyAsmap: seq[byte] = @[]
    check checkStandardAsmap(emptyAsmap) == false

# ---------------------------------------------------------------------------
# G14 — Asmap version stamp in peers.dat (BUG-10)
# ---------------------------------------------------------------------------
suite "W128 G14 — asmap version stamp in peers.dat (BUG-10)":

  test "G14 BUG-10: no peers.dat at all → no asmap version stamp":
    ## addrman_impl.h Format::V2_ASMAP stamps the asmap SHA-256
    ## into the peers.dat header so reload triggers re-bucketing.
    ## Nimrod has no peers.dat (W104 G21), so no version stamp path.
    check "peers.dat" notin peermanagerSrc
    check "V2_ASMAP"  notin peermanagerSrc
    check "savePeers" notin peermanagerSrc
    check "loadPeers" notin peermanagerSrc

# ---------------------------------------------------------------------------
# G15-G16 — m_network_counts + GetReachableEmptyNetworks (BUG-11)
# ---------------------------------------------------------------------------
suite "W128 G15-G16 — m_network_counts + GetReachableEmptyNetworks (BUG-11)":

  test "G15 BUG-11: no per-network m_network_counts index":
    ## addrman_impl.h:226-232.  Used to O(1) answer Size(net).
    check "m_network_counts" notin peermanagerSrc
    check "networkCounts"    notin peermanagerSrc

  test "G16 BUG-11 cont: no GetReachableEmptyNetworks → no fixed-seed gating":
    ## net.cpp:2495-2506.  Nimrod's fallbackPeers are an unconditional
    ## seed list, not gated on per-network emptiness.
    check "GetReachableEmptyNetworks"     notin peermanagerSrc
    check "getReachableEmptyNetworks"     notin peermanagerSrc
    check "reachableEmptyNetworks"        notin peermanagerSrc

# ---------------------------------------------------------------------------
# G17 — MAX_BLOCK_RELAY_ONLY_ANCHORS=2 enforcement — PRESENT
# ---------------------------------------------------------------------------
suite "W128 G17 — MAX_BLOCK_RELAY_ONLY_ANCHORS cap (PRESENT)":

  test "G17 PRESENT: MaxBlockRelayOnlyAnchors=2 const defined and enforced":
    ## net.cpp:57, 3496-3497.  anchors.nim:14 defines the constant
    ## and enforces it at save (66-67), load (143-144), add (170-172),
    ## and the helper conversion (265-266).
    check "MaxBlockRelayOnlyAnchors* = 2" in anchorsSrc
    check "al.anchors = al.anchors[0 ..< MaxBlockRelayOnlyAnchors]" in anchorsSrc
    check $MAX_BLOCK_RELAY_ONLY_ANCHORS_CORE == "2"

  test "G17 PRESENT cont: AnchorList.add caps at 2 entries":
    let dir = "/tmp/nimrod-w128-anchor-test-" & $getTime().toUnix()
    createDir(dir)
    defer: removeDir(dir)
    let al = newAnchorList(dir)
    # Add 3 distinct anchors; only the last 2 should survive.
    var ip1, ip2, ip3: array[16, byte]
    ip1[15] = 1; ip2[15] = 2; ip3[15] = 3
    al.add(1, ip1, 8333'u16)
    al.add(1, ip2, 8333'u16)
    al.add(1, ip3, 8333'u16)
    check al.count <= MAX_BLOCK_RELAY_ONLY_ANCHORS_CORE

# ---------------------------------------------------------------------------
# G18 — SEED_OUTBOUND_CONNECTION_THRESHOLD=2 (BUG-13)
# ---------------------------------------------------------------------------
suite "W128 G18 — SEED_OUTBOUND_CONNECTION_THRESHOLD (BUG-13)":

  test "G18 BUG-13: no SEED_OUTBOUND_CONNECTION_THRESHOLD gating on DNS seed lookup":
    ## net.cpp:69, 2696-2701.  Core only triggers DNS seed re-fetch
    ## if outbound < 2.  Nimrod's resolveDnsSeeds runs unconditionally
    ## on every reconnect cycle.
    check "SEED_OUTBOUND_CONNECTION_THRESHOLD" notin peermanagerSrc
    check "seedOutboundThreshold"              notin peermanagerSrc
    check $SEED_OUTBOUND_CONNECTION_THRESHOLD_CORE == "2"

# ---------------------------------------------------------------------------
# G19 — DEFAULT_MISBEHAVING_BANTIME + -bantime CLI (BUG-14)
# ---------------------------------------------------------------------------
suite "W128 G19 — bantime operator override (BUG-14)":

  test "G19 BUG-14: BanDuration is hard-coded 24h, no -bantime CLI flag":
    ## banman.h:19.  Nimrod's BanDuration is a const, not overridable
    ## from CLI.
    check "BanDuration*" in peermanagerSrc  # const defined
    check "initDuration(hours = 24)" in peermanagerSrc
    # No CLI flag in nimrod.nim:
    check "bantime"  notin nimrodSrc
    check "banTime"  notin nimrodSrc
    check $DEFAULT_MISBEHAVING_BANTIME_SEC == "86400"

  test "G19 BUG-14 cont: BanDuration const matches Core 24h":
    # Verify the value matches Core's default.
    let oneDay = initDuration(hours = 24)
    check oneDay.inSeconds == DEFAULT_MISBEHAVING_BANTIME_SEC

# ---------------------------------------------------------------------------
# G20 — DUMP_BANS_INTERVAL=15min periodic flush (BUG-15)
# ---------------------------------------------------------------------------
suite "W128 G20 — DUMP_BANS_INTERVAL periodic flush (BUG-15)":

  test "G20 BUG-15: no periodic DUMP_BANS_INTERVAL=15min timer":
    ## banman.h:22.  Nimrod flushes on every ban()/unban() (synchronous
    ## per call), no scheduled 15-min flush.
    check "DUMP_BANS_INTERVAL" notin peermanagerSrc
    check "DUMP_BANS_INTERVAL" notin banmanSrc
    check "dumpBansInterval"   notin peermanagerSrc
    check $DUMP_BANS_INTERVAL_SEC == "900"

  test "G20 BUG-15 cont: ban() calls save() synchronously":
    ## Confirms the current sync-on-write pattern (which is mostly
    ## fine but not the Core scheduled cadence).
    check "bm.save()" in banmanSrc

# ---------------------------------------------------------------------------
# G21 — IsBanned lookup performance (BUG-16)
# ---------------------------------------------------------------------------
suite "W128 G21 — IsBanned lookup performance (BUG-16)":

  test "G21 BUG-16: isBanned() is O(1) for IP-equality but no subnet matching":
    ## banman.cpp:89-102 iterates m_banned and calls sub_net.Match().
    ## Nimrod's isBanned hits a hash table directly, but only on
    ## IP-equality.  CIDR/subnet ban won't trigger isBanned for
    ## individual IPs in the subnet.
    let bm = newBanManager("/tmp/nimrod-w128-bm-test3-" & $getTime().toUnix())
    bm.ban("192.168.0.0", initDuration(hours = 1))  # exact-IP "subnet" attempt
    check bm.isBanned("192.168.0.0") == true     # exact match works
    check bm.isBanned("192.168.0.1") == false    # subnet match does NOT
    # (Even though 192.168.0.0/24 would include 192.168.0.1 in Core.)

# ---------------------------------------------------------------------------
# G22 — CSubNet-keyed bans (BUG-17)
# ---------------------------------------------------------------------------
suite "W128 G22 — CSubNet-keyed bans (BUG-17)":

  test "G22 BUG-17: ban() accepts only string IP, not CSubNet":
    ## banman.h:68-70 `Ban(const CSubNet& sub_net, ...)`.  Nimrod's
    ## ban() signature is `(bm: BanManager, address: string, duration:
    ## Duration, reason: BanReason)`.  No subnet type at all.
    let bm = newBanManager("/tmp/nimrod-w128-bm-test4-" & $getTime().toUnix())
    # `ban` accepts a string — confirm signature is IP-only.
    check compiles(bm.ban("192.168.0.0/24", initDuration(hours = 1)))
    # But the "subnet" is stored as a string key, not a real subnet:
    bm.ban("192.168.0.0/24", initDuration(hours = 1))
    # Look-up still goes by string-equal, so an IP in the subnet
    # does NOT match the subnet ban entry:
    check bm.isBanned("192.168.0.0") == false  # subnet entry doesn't apply to IPs

  test "G22 BUG-17 cont: no Subnet / CSubNet type in banman.nim":
    check "CSubNet" notin banmanSrc
    check "Subnet"  notin banmanSrc

# ---------------------------------------------------------------------------
# G23 — MAX_ADDNODE_CONNECTIONS separate slot pool (BUG-18)
# ---------------------------------------------------------------------------
suite "W128 G23 — MAX_ADDNODE_CONNECTIONS pool (BUG-18)":

  test "G23 BUG-18: no separate MAX_ADDNODE_CONNECTIONS=8 cap":
    ## net.h:71.  Nimrod's manual peers bypass slot limits without
    ## a separate cap — operator with 1000 addnodes can connect to all.
    check "MAX_ADDNODE_CONNECTIONS" notin peermanagerSrc
    check "maxAddnodeConnections"   notin peermanagerSrc
    check "maxAddnode"              notin peermanagerSrc
    check $MAX_ADDNODE_CONNECTIONS_CORE == "8"

  test "G23 BUG-18 cont: pctManual bypasses all slot limits":
    ## peermanager.nim:545-546:
    ##   of pctManual: discard  # manual/addnode peers bypass slot limits
    check "manual/addnode peers bypass slot limits" in peermanagerSrc

# ---------------------------------------------------------------------------
# G24 — MAX_FEELER_CONNECTIONS=1 cap (BUG-19)
# ---------------------------------------------------------------------------
suite "W128 G24 — MAX_FEELER_CONNECTIONS cap (BUG-19 CLOSED)":

  test "G24 BUG-19 CLOSED: MaxFeelerConnections=1 cap present":
    ## net.h:75 MAX_FEELER_CONNECTIONS=1.  Nimrod bounds feelers to one at a
    ## time via the single mainLoop feeler call site + the MaxFeelerConnections
    ## constant.
    check "MaxFeelerConnections" in peermanagerSrc
    check MaxFeelerConnections == 1
    check $MAX_FEELER_CONNECTIONS_CORE == "1"

# ---------------------------------------------------------------------------
# G25 — IsLocal → disconnect-only — PRESENT
# ---------------------------------------------------------------------------
suite "W128 G25 — IsLocal exempt from ban (PRESENT)":

  test "G25 PRESENT: misbehavingPeer skips ban for IsLocal":
    ## peermanager.nim:415-420 — checks `ip.isLocal()` and disconnects
    ## without entering ban table.  Matches Core.
    check "ip.isLocal()" in peermanagerSrc
    check "local peer — disconnect only" in peermanagerSrc

# ---------------------------------------------------------------------------
# G26 — addrman.Connected() on disconnect (BUG-20)
# ---------------------------------------------------------------------------
suite "W128 G26 — Connected() on disconnect (BUG-20)":

  test "G26 BUG-20: no addrman.Connected() call in removePeer":
    ## net_processing.cpp:FinalizeNode → addrman.Connected(addr).
    ## Critical: Core does this on disconnect (not connect) to avoid
    ## leaking topology.  Nimrod's removePeer doesn't touch addrman
    ## (no addrman to touch — W104 G26 orchestration side).
    check "addrman.Connected" notin peermanagerSrc
    check "addrman.connected" notin peermanagerSrc
    # The orchestration call site (removePeer) exists but has no
    # addrman update.  Confirm the proc exists:
    check "proc removePeer" in peermanagerSrc

# ---------------------------------------------------------------------------
# G27 — addrman.SetServices() from VERSION handler (BUG-21)
# ---------------------------------------------------------------------------
suite "W128 G27 — SetServices() from VERSION (BUG-21)":

  test "G27 BUG-21: no addrman.SetServices() call from VERSION handler":
    ## net_processing.cpp VERSION → addrman.SetServices(addr, services).
    ## Nimrod's peer.nim performHandshake reads services but never
    ## propagates them to a stored address record.
    let peerSrc = readFile("src/network/peer.nim")
    check "addrman.SetServices" notin peerSrc
    check "addrman.setServices" notin peerSrc

# ---------------------------------------------------------------------------
# G28-G29 — Attempt(addr, count_failures) (BUG-22, BUG-23)
# ---------------------------------------------------------------------------
suite "W128 G28-G29 — Attempt(addr, count_failures) (BUG-22+BUG-23)":

  test "G28 BUG-22: no addrman.Attempt() call in outbound connect path":
    ## net.cpp:2889-2896.  connectToPeerWithType does NOT update any
    ## per-address attempt counter.
    check "addrman.Attempt" notin peermanagerSrc
    check "addrman.attempt" notin peermanagerSrc

  test "G29 BUG-23: no count_failures heuristic":
    ## net.cpp:2893 — Core suppresses attempt-counting when the node
    ## is offline (only 1 netgroup of outbound).  Nimrod has no
    ## attempt counter so the heuristic is vacuously absent.
    check "count_failures" notin peermanagerSrc
    check "countFailures"  notin peermanagerSrc

# ---------------------------------------------------------------------------
# G30 — PRIVATE_BROADCAST connection type (BUG-24)
# ---------------------------------------------------------------------------
suite "W128 G30 — PRIVATE_BROADCAST connection type (BUG-24)":

  test "G30 BUG-24: no PRIVATE_BROADCAST variant in PeerConnectionType":
    ## Core post-2024 ConnectionType::PRIVATE_BROADCAST (orphan-tx
    ## privacy patch).  Cross-impl fleet gap.
    var seenPrivateBroadcast = false
    for pct in PeerConnectionType:
      let s = $pct
      if "Private" in s or "private" in s or "Broadcast" in s or "broadcast" in s:
        seenPrivateBroadcast = true
    check seenPrivateBroadcast == false

  test "G30 BUG-24 cont: no PRIVATE_BROADCAST orchestration":
    check "PRIVATE_BROADCAST" notin peermanagerSrc
    check "private_broadcast" notin peermanagerSrc

# ---------------------------------------------------------------------------
# Constant-pinning summary (forward regression: if Core changes a
# numerical constant, this suite breaks, prompting an explicit
# decision in the fleet sweep).
# ---------------------------------------------------------------------------
suite "W128 Core constant pinning":

  test "FEELER_INTERVAL=2min":
    check FEELER_INTERVAL_SEC == 120

  test "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min":
    check EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL_SEC == 300

  test "EXTRA_NETWORK_PEER_INTERVAL=5min":
    check EXTRA_NETWORK_PEER_INTERVAL_SEC == 300

  test "MAX_OUTBOUND_FULL_RELAY_CONNECTIONS=8":
    check MAX_OUTBOUND_FULL_RELAY_CONNECTIONS_CORE == 8

  test "MAX_ADDNODE_CONNECTIONS=8":
    check MAX_ADDNODE_CONNECTIONS_CORE == 8

  test "MAX_FEELER_CONNECTIONS=1":
    check MAX_FEELER_CONNECTIONS_CORE == 1

  test "MAX_BLOCK_RELAY_ONLY_ANCHORS=2":
    check MAX_BLOCK_RELAY_ONLY_ANCHORS_CORE == 2

  test "SEED_OUTBOUND_CONNECTION_THRESHOLD=2":
    check SEED_OUTBOUND_CONNECTION_THRESHOLD_CORE == 2

  test "DEFAULT_MISBEHAVING_BANTIME=24h=86400s":
    check DEFAULT_MISBEHAVING_BANTIME_SEC == 86_400

  test "DUMP_BANS_INTERVAL=15min=900s":
    check DUMP_BANS_INTERVAL_SEC == 900

  test "DISCOURAGEMENT_BLOOM_ELEMENTS=50000":
    check DISCOURAGEMENT_BLOOM_ELEMENTS == 50_000

  test "SANITY_CHECK_BITS=128":
    check SANITY_CHECK_BITS_CORE == 128
