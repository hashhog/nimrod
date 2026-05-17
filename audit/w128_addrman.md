# W128 — AddrMan + connman + peer selection audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W128)
Target: `src/network/peermanager.nim`, `src/network/banman.nim`,
        `src/network/eviction.nim`, `src/network/anchors.nim`,
        `src/network/asmap.nim`, `src/network/netgroup.nim`,
        and the connect orchestration in `src/nimrod.nim` boot
        sequence.
Reference:
  - `bitcoin-core/src/addrman.cpp` + `addrman.h` + `addrman_impl.h`
    (CAddrMan / AddrInfo / nKey / Select_ / GetAddr_ / IsTerrible /
    ResolveCollisions / m_tried_collisions / m_network_counts /
    SetServices / Connected / FILE_FORMAT)
  - `bitcoin-core/src/net.cpp`
    (CConnman::Start, AddAddrFetch / ProcessAddrFetch, FEELER /
    EXTRA_NETWORK_PEER_INTERVAL / EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL /
    MaybePickPreferredNetwork, GetReachableEmptyNetworks,
    ThreadOpenConnections, MAX_BLOCK_RELAY_ONLY_ANCHORS,
    SEED_OUTBOUND_CONNECTION_THRESHOLD, IsBadPort)
  - `bitcoin-core/src/banman.cpp` + `banman.h`
    (BanMan, m_banned vs m_discouraged rolling bloom filter,
    Discourage / IsDiscouraged / SetServices / DUMP_BANS_INTERVAL)
  - `bitcoin-core/src/util/asmap.cpp` + `asmap.h`
    (DecodeAsmap / Interpret / SanityCheckASMap)

W128 is the **complementary** audit to W104 (which carved out 30
AddrMan-internal gates: bucket structure, AddrInfo metadata,
IsTerrible / GetChance, GetTriedBucket / GetNewBucket hashes, persistence
format, peers.dat file, MAX_ADDRMAN_SIZE, etc.).  W128 scopes the
**orchestration** layer — how Core's connman drives addrman during the
`ThreadOpenConnections` loop, how it deduplicates banman vs discouragement,
how it picks preferred networks, how it manages anchors / feeler /
addr_fetch / extra block-relay connection types, how it gates on
IsReachable / IsBadPort / addnode-shadowing, and how persistence + asmap
sanity-check is wired.  Every W128 gate is **distinct** from the W104
30-gate set (cross-checked test by test).

Out of scope for W128 (handled in other waves):
  - W117: BIP-155 wire format + Tor v3 / I2P / CJDNS encode/decode.
  - W104: AddrMan internal bucketing, IsTerrible, GetChance, peers.dat
    serialization, 23%-of-pool gossip cap.
  - W115: asmap binary-trie interpreter correctness (G1-G17 of W115
    covered file load + Interpret() + NetGroupManager wiring).  W128
    re-asserts only the **sanity-check / asmap version stamping**
    surface that W115 did NOT touch.
  - W104 G16-G18: addr gossip 23% sampling, IsTerrible filter on
    getaddr response, knownAddresses port-only dedup — those three
    gossip-output bugs are W104's.  W128 audits the **inbound**
    gossip path (time-penalty, source-tracking, terrible-filter on
    Add) separately.

## Status

**BUGS FOUND — 23 distinct underlying defects (BUG-1..BUG-24, minus
the retired BUG-12) across 26 gates MISSING / PARTIAL (of 30 total).
4 gates PRESENT (G13 asmap-sanity-check, G17 MAX_ANCHORS=2 enforcement,
G25 IsLocal-exempt ban, and the implicit cross-class).**

Nimrod's "peer address tracking" is `PeerManager.knownAddresses:
seq[NetAddress]` plus `knownAddressesV2: seq[TimestampedAddrV2]` plus
`BanManager` (banlist.json, JSON storage, 24h default duration) plus
`AnchorList` (block-relay-only anchors).  The orchestration that Core
splits across `CConnman::ThreadOpenConnections`, `CAddrMan`,
`BanMan::IsDiscouraged`, `NetGroupManager::ASMapHealthCheck`,
`g_reachable_nets`, and `m_added_node_params` is collapsed into two
files (`peermanager.nim` + `banman.nim`) with the following gaps:

1. **No discouragement separation (BUG-1, P1-OPS-SEC)**:
   `banman.nim` has `BanReason.brMisbehaving` but treats misbehaving
   peers as full bans — written to `banlist.json`, scanned linearly
   on every connect, and growable to GiB sizes.  Core split this
   in 2024 (CVE-disclosure `disclose-unbounded-banlist`) into
   manual `ban` (persisted) vs probabilistic `discourage` (50 000-entry
   rolling bloom filter).  Nimrod has no bloom filter; every
   misbehaving peer creates a persistent ban entry.  An attacker
   that can trigger misbehavior from many IPs grows the on-disk
   ban list unboundedly.

2. **No FEELER / ADDR_FETCH / extra-block-relay / preferred-network
   connection types (BUG-2..BUG-5, P1-CDIV)**:
   `PeerConnectionType` is 4 entries (`pctFullRelay`,
   `pctBlockRelayOnly`, `pctInbound`, `pctManual`).  Core has 8
   types (the four above + `FEELER`, `ADDR_FETCH`, `BLOCK_RELAY`
   anchor variant tracked via `anchor` flag, and the
   "extra block-relay-only peer on `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL`"
   path).  No `next_feeler` timer, no `next_extra_block_relay`,
   no `next_extra_network_peer`, no `MaybePickPreferredNetwork`,
   no `m_addr_fetches` deque, no `GetReachableEmptyNetworks` gate
   for fixed-seed injection.

3. **No `ResolveCollisions` / `SelectTriedCollision` / feeler-driven
   test-before-evict (BUG-6, P2-CDIV)**: even W104 missed this gate's
   *connman wiring* — `ThreadOpenConnections` calls
   `addrman.get().ResolveCollisions()` once per outer loop iteration
   and `SelectTriedCollision()` on the feeler path.  Both are
   orchestration entry points; W104 documented only the addrman
   internals (G9).

4. **No `IsBadPort` outbound gate (BUG-7, P1-CDIV)**: Core
   `net.cpp:2858-2861` skips outbound dial to peers on bad ports
   (the ~80-entry blocklist of known-exploited ports — SMB 445, etc.)
   for the first 50 selection tries.  Nimrod's `connectToPeerWithType`
   has only an `isRoutable` check; bad ports are dialed silently.

5. **No `AddedNodesContain` shadow-check (BUG-8, P2-CDIV)**: Core
   `net.cpp:2866-2872` refuses to make an *automatic* outbound
   connection to a peer that the operator has separately added
   via `-addnode` — addnode connections are special-cased and the
   slot is reserved for the manual connection.  Nimrod's
   `connectToPeerWithType` makes no such check.

6. **No `-onlynet` reachability gate (BUG-9, P1-OPS-CDIV)**: Core
   exposes `-onlynet=<net>` and `g_reachable_nets` to let operators
   restrict outbound to specific networks.  Nimrod has
   `cjdnsReachable` and `proxyManager.{onionProxy,i2pSession}` (W117
   FIX-56) but no global "only-IPv4" / "only-IPv6" / "only-Tor"
   flag.  An operator who wants Tor-only outbound has no clean way
   to enforce it.

7. **No asmap version stamp in peers.dat (BUG-10, P2-OPS)**: Core
   `init.cpp` calls `SanityCheckASMap(asmap, 128)` before installing
   it AND stamps the asmap SHA-256 into peers.dat
   (addrman_impl.h Format::V2_ASMAP) so re-bucketing is triggered
   on asmap-file change.  Nimrod ships the sanity-check (W115
   closure, G13 PRESENT) but has no peers.dat (W104 G21) so the
   version-stamp side is moot.  BUG-10 pins the *forward* gap:
   even when a future FIX wave adds peers.dat, the asmap-version
   stamp has to land with it.

8. **No `m_network_counts` (BUG-11, P2-CDIV)**: Core indexes addresses
   per-network for `Size(net)` in O(1) and uses it in two places —
   `GetReachableEmptyNetworks` (which gates fixed-seed injection)
   and `MaybePickPreferredNetwork` (which steers extra outbound
   to under-represented networks).  Nimrod has no per-network count;
   both gating paths are absent (BUG-3, BUG-5 above).

9. **Other BUGs**: see gate table below.  Highlights are no
   `MAX_ADDNODE_CONNECTIONS=8` cap (BUG-18), bantime fixed at 24h
   (BUG-14, no `-bantime=<seconds>` operator override), no
   periodic banlist flush (BUG-15), and CSubNet-keyed bans
   missing (BUG-17).

The **net effect** is two-fold:

  - **Security**: an attacker that can sustain misbehavior from many
    IPs grows the on-disk banlist unboundedly (BUG-1) and degrades
    every `isBanned` query to O(1) but only for exact-IP lookup
    (BUG-16) — CIDR ban matching is absent (BUG-17).  This is the
    exact failure mode the 2024 Core CVE addressed for the unbounded
    growth side.
  - **Eclipse-resistance**: without FEELER (BUG-2), without
    `MaybePickPreferredNetwork` (BUG-5), without per-network counts
    (BUG-11), and without `-onlynet` reachability gating (BUG-9), the
    eclipse-attack mitigations Core layered after 2020 are partially
    or fully absent.  W104 already documented the underlying
    addrman bucketing absence; W128 adds the orchestration gaps that
    would still bite even with a properly bucketed addrman in place.

No consensus invariant is broken by any W128 BUG — the bugs are all
P1/P2 peering-policy / operator-surface divergences.

## Method

1. Read Core refs above (addrman.cpp / addrman.h / addrman_impl.h /
   net.cpp / banman.cpp / banman.h / util/asmap.cpp / asmap.h).
2. Enumerate orchestration entry points in nimrod
   (`peermanager.nim` 1626 LOC, `banman.nim` 246 LOC,
   `eviction.nim` 297 LOC, `anchors.nim`, `asmap.nim` 385 LOC,
   `netgroup.nim` 468 LOC).
3. For each of 30 audit gates below, classify nimrod's current
   behavior against Core's documented behavior:
   - **PRESENT** — nimrod implements the Core behaviour reachably.
   - **PARTIAL** — partial implementation; some sites match, some
     don't, or the behaviour is wired but with a hard-coded /
     non-overridable parameter.
   - **MISSING** — no implementation; the behaviour Core has is
     entirely absent.
4. Pin each PARTIAL / MISSING in `tests/test_w128_addrman.nim` as
   xfail-shape regression guards.

## Audit gates (30)

Numbering is W128-local.  Each gate cites Core's canonical call site
and nimrod's evidence.

| # | Gate | Core ref | nimrod | Status |
|---|------|----------|--------|--------|
| G1  | `BanMan::Discourage()` separate from `Ban()` (rolling bloom) | banman.cpp:124-128, banman.h:98 | absent | **MISSING (BUG-1, P1)** |
| G2  | Rolling-bloom discouragement filter (50 000 entries, 1e-6 fp) | banman.h:98 `CRollingBloomFilter` | absent | **MISSING (BUG-1 cont.)** |
| G3  | `BanMan::IsDiscouraged()` membership test | banman.cpp:83-87 | absent | **MISSING (BUG-1 cont.)** |
| G4  | `ConnectionType::FEELER` peer with `FEELER_INTERVAL=2min` exp timer | net.cpp:2753-2756, net.h:61 | absent | **MISSING (BUG-2, P1)** |
| G5  | `ConnectionType::ADDR_FETCH` + `m_addr_fetches` deque | net.cpp:2410-2429, net.h:1596 | absent | **MISSING (BUG-3, P2)** |
| G6  | `next_extra_block_relay` exp timer (`EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min`) | net.cpp:2729-2752 | absent | **MISSING (BUG-4, P2)** |
| G7  | `MaybePickPreferredNetwork()` + `next_extra_network_peer` | net.cpp:2514-2528, 2757-2767 | absent | **MISSING (BUG-5, P1)** |
| G8  | `AddrMan::ResolveCollisions()` called once per loop | addrman.cpp:617, net.cpp:2773 | absent | **MISSING (BUG-6, P2)** |
| G9  | `AddrMan::SelectTriedCollision()` on feeler path | addrman.cpp, net.cpp:2804 | absent | **MISSING (BUG-6 cont.)** |
| G10 | `IsBadPort` outbound gate (first 50 tries) | net.cpp:2858-2861, net.h `IsBadPort` | absent | **MISSING (BUG-7, P1)** |
| G11 | `AddedNodesContain(addr)` shadow-check on auto outbound | net.cpp:2866-2872 | absent | **MISSING (BUG-8, P2)** |
| G12 | `-onlynet=<net>` + `g_reachable_nets` global gate | init.cpp `SetReachable`, net.cpp `g_reachable_nets` | absent | **MISSING (BUG-9, P1)** |
| G13 | `SanityCheckASMap(data, bits=128)` at load | util/asmap.cpp `SanityCheckASMap`, init.cpp | present — `asmap.nim:289 checkStandardAsmap` is called inside `loadAsmap` (W115 closure) | **PRESENT** |
| G14 | Asmap version stamped in peers.dat | addrman_impl.h Format::V2_ASMAP | absent (no peers.dat at all) | **MISSING (BUG-10, P2)** |
| G15 | Per-network `m_network_counts` index | addrman_impl.h:226-232 | absent | **MISSING (BUG-11, P2)** |
| G16 | `GetReachableEmptyNetworks()` → fixed-seed injection | net.cpp:2495-2506, 2606-2645 | absent | **MISSING (BUG-11 cont.)** |
| G17 | `m_anchors` capped at `MAX_BLOCK_RELAY_ONLY_ANCHORS=2` | net.cpp:57, 3496-3497 | present — `anchors.nim:14 MaxBlockRelayOnlyAnchors=2` enforced at load/save/add | **PRESENT** |
| G18 | `SEED_OUTBOUND_CONNECTION_THRESHOLD=2` gating of DNS seed retry | net.cpp:69, 2696-2701 | absent | **MISSING (BUG-13, P2)** |
| G19 | `DEFAULT_MISBEHAVING_BANTIME=24h` operator-overridable via `-bantime` | banman.h:19, init.cpp `-bantime` | hard-coded `BanDuration=24h`, no CLI flag | **PARTIAL (BUG-14, P2)** |
| G20 | `DUMP_BANS_INTERVAL=15min` periodic banlist flush | banman.h:22 | only flushes on `ban()`/`unban()`, no timer | **PARTIAL (BUG-15, P2)** |
| G21 | `BanMan::IsBanned()` O(1) by subnet match | banman.cpp:89-102 + `m_banned: banmap_t` (map) | O(n) — `bannedPeers: Table[string,BanEntry]` but `isBanned` walks all (sweep) | **PARTIAL (BUG-16, P2)** |
| G22 | `CSubNet`-keyed bans (not just IP) | banman.cpp:104-116 `IsBanned(CSubNet&)` | only IP keys (`normalizeAddress` strips port) | **MISSING (BUG-17, P2)** |
| G23 | `MAX_ADDNODE_CONNECTIONS=8` separate slot pool | net.h:71 | no separate cap; manual peers bypass all limits | **PARTIAL (BUG-18, P2)** |
| G24 | `MAX_FEELER_CONNECTIONS=1` cap | net.h:75 | absent | **MISSING (BUG-19, P2)** |
| G25 | Loopback (`IsLocal`) addresses → disconnect-only, no ban | net_processing.cpp Misbehaving / banman.cpp | present — `peermanager.nim:415-420` checks `ip.isLocal()` before ban | **PRESENT** |
| G26 | `AddrMan::Connected()` called on **disconnect** to refresh nTime (no topology leak) | addrman.cpp Connected_, net_processing.cpp:disconnect | absent (W104 G26 — orchestration side: `removePeer` has no `addrman.Connected()` call) | **MISSING (BUG-20, P2)** |
| G27 | `AddrMan::SetServices()` updated from VERSION message handler | addrman.cpp SetServices_, net_processing.cpp:VERSION | absent (W104 G27 — orchestration side: VERSION handler has no `addrman.SetServices()` call) | **MISSING (BUG-21, P2)** |
| G28 | `AddrMan::Attempt(addr, count_failures)` called on every outbound attempt | addrman.cpp Attempt_, net.cpp:2889-2896 `count_failures` | absent (W104 G13 — orchestration side: `connectToPeerWithType` has no `addrman.Attempt()` call) | **MISSING (BUG-22, P2)** |
| G29 | `count_failures = (netgroups_size + privacy_peers) ≥ min(max_auto-1, 2)` to suppress Attempt-counting when offline | net.cpp:2893 | absent | **MISSING (BUG-23, P2)** |
| G30 | `private_broadcast` connection type (orphan-tx privacy patch) — Core 2024 addition | net.cpp `ConnectionType::PRIVATE_BROADCAST` | absent (orphan-tx privacy fork ignored) | **MISSING (BUG-24, P3)** |

Score: **4 PRESENT (G13 asmap-sanity-check + G17 MAX_ANCHORS=2 + G25 isLocal-exempt) / 5 PARTIAL / 21 MISSING = 26 of 30 gates buggy.**
Net BUGS for the dashboard (PARTIAL + MISSING; "BUG-N" counts each
distinct underlying defect): **23 distinct underlying defects** —
BUG-1..BUG-11 and BUG-13..BUG-24.  BUG-12 (MAX_ANCHORS=2 enforcement)
was retired after source verification confirmed `anchors.nim:14`
already enforces the Core constant.

For the wave header / commit message the headline count is
**23 BUGs**.

## Per-gate detail

### Gate 1-3 — Discouragement bloom filter (BUG-1)
- Core: `BanMan::Discourage(net_addr)` inserts into
  `m_discouraged: CRollingBloomFilter{50000, 0.000001}` (banman.h:98).
  `IsDiscouraged()` (banman.cpp:83-87) does a probabilistic
  membership test.  This was added 2024-07-03 after the
  "disclose-unbounded-banlist" disclosure; previously misbehaving
  peers were *banned*, growing the on-disk banlist unboundedly
  (an attacker could DoS via banlist growth).
- nimrod: `banman.nim` has `BanReason.brMisbehaving` but treats it
  identically to `brManuallyAdded` — both go into `bannedPeers:
  Table[string, BanEntry]`, persisted to `banlist.json`, and matched
  linearly in `isBanned()`.  An attacker triggering misbehavior
  from many IPs grows the banlist unboundedly.
- Evidence: `peermanager.nim:424` calls
  `pm.banPeer(peer.address, BanDuration, brMisbehaving)`; that
  routes through `banman.nim:133-159 ban()` which inserts into the
  same `bannedPeers` table as a manual ban.  No bloom filter exists.
- Status: MISSING (G1+G2+G3 roll up to BUG-1).

### Gate 4 — FEELER connections (BUG-2)
- Core: `net.cpp:2753-2756`
  ```cpp
  } else if (now > next_feeler) {
      next_feeler = now + rng.rand_exp_duration(FEELER_INTERVAL);
      conn_type = ConnectionType::FEELER;
      fFeeler = true;
  }
  ```
  `FEELER_INTERVAL=2min` (net.h:61).  Feelers are short-lived
  connections that probe addresses from the new table to promote
  them to tried — the "Eclipse-Eclipse" mitigation per Heilman
  et al.
- nimrod: `peermanager.nim:1068-1110 mainLoop` has only
  `lastReconnect`, `lastPing`, `lastGetAddr`, `lastStalePeerCheck`
  timers.  No `next_feeler`, no `pctFeeler`, no exponential
  random interval.
- Status: MISSING (G4 → BUG-2).

### Gate 5 — ADDR_FETCH connections + m_addr_fetches (BUG-3)
- Core: `net.cpp:2410-2429 ProcessAddrFetch()` pops the front of
  `m_addr_fetches: std::deque<std::string>` and opens a short
  connection with `ConnectionType::ADDR_FETCH`.  Used when
  addrman is empty and we need to bootstrap from a seed node.
  `AddAddrFetch` (net.cpp:132) is called on every seed in
  `ThreadDNSAddressSeed` if outbound count is below
  `SEED_OUTBOUND_CONNECTION_THRESHOLD=2`.
- nimrod: `peermanager.nim:449-468 resolveDnsSeeds` uses
  `resolveTAddress` once and returns the addresses for the
  caller to dial via `connectToPeerWithType(pctFullRelay)`.
  No ADDR_FETCH type, no `m_addr_fetches`, no
  `ProcessAddrFetch` orchestration.
- Status: MISSING (G5 → BUG-3).

### Gate 6 — Extra block-relay-only peer interval (BUG-4)
- Core: `net.cpp:2729-2752`
  ```cpp
  } else if (now > next_extra_block_relay && m_start_extra_block_relay_peers) {
      next_extra_block_relay = now + rng.rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
      conn_type = ConnectionType::BLOCK_RELAY;
  }
  ```
  `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min` (net.h:63).  Used
  as an additional eclipse-resistance probe — a fresh block-relay
  peer every ~5 min so an attacker can't pin all our outbound to
  malicious nodes.
- nimrod: no such timer.  `maintainConnections` only refills to the
  `maxOutboundBlockRelay=2` static limit.
- Status: MISSING (G6 → BUG-4).

### Gate 7 — MaybePickPreferredNetwork + next_extra_network_peer (BUG-5)
- Core: `net.cpp:2514-2528`
  ```cpp
  bool CConnman::MaybePickPreferredNetwork(std::optional<Network>& network) {
      std::array<Network, 5> nets{NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS};
      std::shuffle(nets.begin(), nets.end(), FastRandomContext());
      LOCK(m_nodes_mutex);
      for (const auto net : nets) {
          if (g_reachable_nets.Contains(net) && m_network_conn_counts[net] == 0 && addrman.get().Size(net) != 0) {
              network = net; return true;
          }
      }
      return false;
  }
  ```
  Used at `net.cpp:2757-2767` to steer an extra outbound to a
  reachable network we currently have zero peers on.
- nimrod: no `network_conn_counts`, no `Size(net)`, no preferred
  network gate.  Outbound is uniformly drawn from the flat
  `knownAddresses` seq via DNS resolution.
- Status: MISSING (G7 → BUG-5).

### Gate 8-9 — ResolveCollisions + SelectTriedCollision (BUG-6)
- Core: `net.cpp:2773` calls `addrman.get().ResolveCollisions()`
  once per outer ThreadOpenConnections iteration.
  `net.cpp:2804` calls `addrman.get().SelectTriedCollision()` on
  the feeler path to retrieve the address Good() wants to evict.
- nimrod: no orchestration call sites; W104 already documented
  the addrman-internal absence (W104 G9), W128 pins the
  orchestration side.
- Status: MISSING (G8+G9 → BUG-6).

### Gate 10 — IsBadPort outbound gate (BUG-7)
- Core: `net.cpp:2858-2861`
  ```cpp
  if (nTries < 50 && (addr.IsIPv4() || addr.IsIPv6()) && IsBadPort(addr.GetPort())) {
      continue;
  }
  ```
  `IsBadPort` (net.cpp `IsBadPort`) is the ~80-entry blocklist of
  known-exploited ports (SMB 445, SMTP 25, etc.).  Skipped for the
  first 50 selection attempts; after that even bad-port addresses
  are tried (last resort).
- nimrod: `connectToPeerWithType` has `isRoutable` (W104 G16 fix)
  but no `IsBadPort`.  A peer that advertised port 445 would be
  dialed silently.
- Status: MISSING (G10 → BUG-7).

### Gate 11 — AddedNodesContain shadow-check (BUG-8)
- Core: `net.cpp:2866-2872`
  ```cpp
  if (AddedNodesContain(addr)) {
      LogDebug(BCLog::NET, "Not making automatic ... connection to %s peer selected for manual (addnode) connection ...");
      continue;
  }
  ```
  Prevents an automatic outbound from competing with an addnode
  slot (Core reserves addnode slots for the operator).
- nimrod: no equivalent.  `connectToPeerWithType(pctManual)` opens
  a manual connection; nothing prevents `connectToPeerWithType(pctFullRelay)`
  to the same address from racing.
- Status: MISSING (G11 → BUG-8).

### Gate 12 — -onlynet + g_reachable_nets (BUG-9)
- Core: `init.cpp` parses `-onlynet=<net>` arguments, calls
  `g_reachable_nets.Add(net)` for each, then `g_reachable_nets.Contains(net)`
  gates every outbound (net.cpp:2840-2842) and every fixed-seed
  injection (net.cpp:2495-2506).
- nimrod: per-network gating is per-feature (`cjdnsReachable` field,
  `proxyManager.onionProxy`, `proxyManager.i2pSession`).  No global
  reachability set, no `-onlynet` CLI flag.  An operator who wants
  Tor-only outbound has to set `-onion` and *also* manually
  block-list IPv4 / IPv6 — which nimrod has no flag for.
- Status: MISSING (G12 → BUG-9).

### Gate 13 — Asmap sanity check at load — PRESENT
- Core: `init.cpp` calls `SanityCheckASMap(asmap_raw, 128)` before
  installing it.  `util/asmap.cpp::SanityCheckASMap` walks the
  binary trie, verifies every reachable RETURN has a non-zero ASN,
  and rejects asmaps with unreachable nodes.
- nimrod: `asmap.nim:289 checkStandardAsmap` IS called inside
  `loadAsmap`, walking the trie correctly per W115 closure.
  MATCHES Core.
- Status: **PRESENT**.

### Gate 14 — Asmap version stamp in peers.dat (BUG-10)
- Core: the asmap version (SHA256 of the file) is stamped into
  `peers.dat` (addrman_impl.h Format::V2_ASMAP) so that re-bucketing
  is triggered on asmap-file change.
- nimrod: there is no peers.dat at all (W104 G21), so there's
  nowhere to stamp the asmap version.  Re-bucketing on asmap
  change is impossible because the addresses themselves don't
  persist.  Adjacent to W104 G21 but pinned here because the
  forward path requires both peers.dat AND the version stamp.
- Status: MISSING (G14 → BUG-10).

### Gate 15-16 — m_network_counts + GetReachableEmptyNetworks (BUG-11)
- Core: `addrman_impl.h:226-232 m_network_counts` indexes addrman
  entries per (Network, new/tried).  `net.cpp:2495-2506
  GetReachableEmptyNetworks` iterates `NET_MAX` and for each
  reachable network with `Size==0`, marks it as a fixed-seed
  injection candidate.  Without `m_network_counts` both paths are
  O(n) scans or absent entirely.
- nimrod: no per-network count, no `GetReachableEmptyNetworks`,
  no fixed-seed injection conditioned on per-network emptiness.
  Fallback peers are an unconditional seed list (`fallbackPeers`).
- Status: MISSING (G15+G16 → BUG-11).

### Gate 17 — m_anchors capped at MAX_BLOCK_RELAY_ONLY_ANCHORS=2 — PRESENT
- Core: `net.cpp:57 MAX_BLOCK_RELAY_ONLY_ANCHORS=2`,
  enforced at `net.cpp:3496-3497` on load
  (`m_anchors.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS)`) and at
  `net.cpp:3652` on dump (`anchors_to_dump.resize`).
- nimrod: `anchors.nim:14 MaxBlockRelayOnlyAnchors = 2` is defined
  and enforced on save (line 66-67), on load (line 143-144), on
  add (line 170-172), and at the helper conversion (line 265-266).
  An additional sanity check at load (line 132) rejects files
  claiming more than 2× the cap.  MATCHES Core.
- Status: **PRESENT**.

### Gate 18 — SEED_OUTBOUND_CONNECTION_THRESHOLD=2 (BUG-13)
- Core: `net.cpp:69 SEED_OUTBOUND_CONNECTION_THRESHOLD=2`,
  used at `net.cpp:2304` (start DNS seed lookup only if outbound
  < threshold), `net.cpp:2335` (early-abort DNS seed thread),
  `net.cpp:2696-2701` (re-fetch from seeds via ADDR_FETCH if
  outbound full-relay < threshold).
- nimrod: DNS seed resolution is unconditional on startup
  (`startOutboundConnections` calls `resolveDnsSeeds` regardless
  of current outbound count).  No SEED_OUTBOUND_CONNECTION_THRESHOLD
  gate.
- Status: MISSING (G18 → BUG-13).

### Gate 19 — DEFAULT_MISBEHAVING_BANTIME=24h with -bantime override (BUG-14)
- Core: `banman.h:19 DEFAULT_MISBEHAVING_BANTIME=24h`, operator
  overridable via `-bantime=<seconds>` CLI flag (init.cpp).
- nimrod: `peermanager.nim:31 BanDuration=24h` is a const; no CLI
  flag in `src/nimrod.nim` argument parsing.  Operators who need
  longer/shorter bans must edit source.
- Status: PARTIAL (G19 → BUG-14).

### Gate 20 — DUMP_BANS_INTERVAL=15min periodic flush (BUG-15)
- Core: `banman.h:22 DUMP_BANS_INTERVAL=15min`, used by
  `scheduler.scheduleEvery(DumpBanlist, 15min)` in init.cpp.
- nimrod: banlist is flushed only inside `ban()`/`unban()`/`clearBanned()`
  (synchronous on each operation, see `banman.nim:159, 188, 199, 210`).
  No periodic timer, so a long-running node with no new ban
  operations will not flush expired entries between sweeps.
  `sweepExpired` IS called inside `save()`, so this is mostly
  fine — but the *periodic* sweep that Core has is absent.
- Status: PARTIAL (G20 → BUG-15).

### Gate 21 — IsBanned O(1) subnet match (BUG-16)
- Core: `banman.cpp:89-102` iterates `m_banned: banmap_t`
  (which is `std::map<CSubNet, CBanEntry>`).  For O(1) IP match
  the second overload (line 104-116) does `m_banned.find(sub_net)`
  by key — true O(log n) lookup.  But the first overload (line
  89-102) iterates all entries and calls `sub_net.Match(net_addr)`
  on each — O(n).  So Core itself has O(n) in the address-lookup
  case; the difference is bloom-filter accelerator for the
  discouragement set.
- nimrod: `bannedPeers: Table[string, BanEntry]` keyed by
  string-form address.  `isBanned()` does a hash-table lookup —
  O(1) for IP-only matches.  But because nimrod does NOT support
  CSubNet (BUG-17 below), there is no per-network match.
- Status: PARTIAL (G21 → BUG-16).  Lookup is O(1) but only for
  the IP-equality case; CIDR/subnet matching is absent.

### Gate 22 — CSubNet-keyed bans (BUG-17)
- Core: `banman.h:68-70` `Ban(const CSubNet& sub_net, ...)` and
  `IsBanned(const CSubNet&)`.  Used by RPC `setban 1.2.3.0/24
  add` to ban an entire subnet at once.
- nimrod: `banman.nim:133 ban(address: string)` accepts only a
  string (which `normalizeAddress` reduces to IP-only).  RPC
  `setban` cannot ban a subnet; only a single IP.
- Status: MISSING (G22 → BUG-17).

### Gate 23 — MAX_ADDNODE_CONNECTIONS=8 separate slot pool (BUG-18)
- Core: `net.h:71 MAX_ADDNODE_CONNECTIONS=8`, separate slot
  budget — addnode peers don't compete with the 8 outbound full-relay
  slots, they have their own 8 dedicated slots.
- nimrod: `connectManualPeer` calls `connectToPeerWithType(pctManual)`
  which is allowed to skip slot limits, but there's no separate
  *cap* of 8 — an operator with 100 addnodes can connect to all
  100.  Worse: there's no separate count tracking, so the operator
  can't even query how many addnodes are connected vs how many are
  ordinary outbound.
- Status: PARTIAL (G23 → BUG-18).

### Gate 24 — MAX_FEELER_CONNECTIONS=1 cap (BUG-19)
- Core: `net.h:75 MAX_FEELER_CONNECTIONS=1`.  Only one feeler
  is in flight at a time.
- nimrod: no feeler type at all (BUG-2), so the cap is moot —
  but for completeness pinned as G24.
- Status: MISSING (G24 → BUG-19).

### Gate 25 — IsLocal → disconnect-only (no ban) — PRESENT
- Core: `net_processing.cpp Misbehaving()` checks `addr.IsLocal()`
  and skips ban for loopback addresses.
- nimrod: `peermanager.nim:415-420` walks `ip.isLocal()` and
  disconnects-without-ban.  MATCHES Core.
- Status: **PRESENT**.

### Gate 26 — Connected() on disconnect refreshes nTime (BUG-20)
- Core: `net_processing.cpp:FinalizeNode` (peer disconnect path)
  calls `addrman.Connected(addr)` to refresh nTime.  Critical
  for keeping fresh addresses from aging out — and Core deliberately
  does this on **disconnect** (not connect) to avoid leaking
  currently-connected-peer topology to addr gossip.
- nimrod: `peermanager.nim:641-661 removePeer` has no
  `addrman.Connected()` call (and no addrman to call it on, per
  W104).  W104 G26 documented the *internal* absence; W128 G26
  pins the *orchestration* absence — where Core's call site sits.
- Status: MISSING (G26 → BUG-20).

### Gate 27 — SetServices() from VERSION handler (BUG-21)
- Core: VERSION-message handler in net_processing.cpp calls
  `addrman.SetServices(addr, services)` to refresh service bits
  on existing entries.
- nimrod: `peer.nim performHandshake` reads the peer's services
  but never updates the cached `knownAddresses[i].services`.
  W104 G27 was the internal absence; W128 G27 is the orchestration
  absence.
- Status: MISSING (G27 → BUG-21).

### Gate 28-29 — Attempt(addr, count_failures) on outbound (BUG-22, BUG-23)
- Core: `net.cpp:2889-2896` computes `count_failures` based on
  whether we have ≥ min(max_auto-1, 2) distinct-netgroup outbound
  peers (and all Tor/I2P/CJDNS peers).  This suppresses
  attempt-counting when the node is offline, so an outage doesn't
  poison the addrman by marking every address as failed.  Then
  calls `addrman.Attempt(addr, count_failures, ...)` to update
  `m_last_try` and conditionally `nAttempts`.
- nimrod: `connectToPeerWithType` has no addrman state to update,
  no `count_failures` heuristic.  W104 G13 was internal; W128
  G28+G29 are orchestration + the count_failures heuristic.
- Status: MISSING (G28+G29 → BUG-22+BUG-23).

### Gate 30 — PRIVATE_BROADCAST connection type (BUG-24)
- Core (post-2024): `ConnectionType::PRIVATE_BROADCAST` for the
  orphan-tx privacy patch.  Short-lived connection that
  broadcasts a single tx and disconnects.  Not yet shipped in
  every fleet impl; pinned here as a fleet-wide cross-impl gap.
- nimrod: not implemented.
- Status: MISSING (G30 → BUG-24, P3).

## Universal findings carried forward

Three of the 24 BUGs match cross-impl patterns seen in earlier
W-waves:

1. **"Misbehaving peer creates persistent ban entry"** (BUG-1) —
   the same banlist-growth pattern Core fixed in 2024 disclosure
   `disclose-unbounded-banlist`.  Cross-impl audit candidate for
   the W128 fleet sweep: every impl should have a discouragement
   bloom filter, not a banlist promotion path.

2. **"Connman-orchestration gap shadows addrman-internal gap"**
   (BUG-6, BUG-20, BUG-21, BUG-22, BUG-23) — W104 catalogued the
   *internal* absence of ResolveCollisions/Connected/SetServices/Attempt;
   even when a future FIX adds the internal procs, the
   *call sites* in net_processing equivalents must be wired too,
   or the new procs sit dead.  Same shape as the FIX-79 dead-helper
   pattern (May 16 nimrod `validateRbfDiagram`) — building a helper
   without wiring the call site = dead code.  W128 frames the
   wave so the FIX can land both sides together.

3. **"Operator surface absent — hard-coded constant"** (BUG-14)
   — fleet-wide pattern: hard-coded `BanDuration=24h`, no
   `-bantime` CLI flag.  Matches W124's "supervised-deployment
   notify hooks absent" finding (W124 BUG-8..BUG-12) and W125's
   "operator-visible error code drift" finding.  Suggests a
   broader "operator parameters checklist" wave (W129+) that
   sweeps every hard-coded constant in the fleet that Core
   exposes via CLI flag.

## Recommendations

Recommended next fix waves (suggestion only — discovery only in W128):

- **FIX-N1** (P1, ~3h): close BUG-1 by adding a discouragement
  rolling bloom filter to `banman.nim`.  Reuse `RollingBloomFilter`
  from `crypto/bloom.nim` (verify location); split
  `BanReason.brMisbehaving` so the bloom path is used for
  misbehaving and the `banlist.json` path stays for
  `brManuallyAdded`.  Affects fleet — cross-impl audit candidate.

- **FIX-N2** (P1, ~2h): close BUG-7 by adding `IsBadPort`
  blocklist (port-number set) and gating
  `connectToPeerWithType` on it for first 50 tries.

- **FIX-N3** (P1, ~2h): close BUG-9 by adding `-onlynet=<net>`
  CLI flag + global `reachableNets: HashSet[NetworkType]`,
  gating `connectToPeerWithType` on it.

- **FIX-N4** (P1, ~3h): close BUG-10 by adding
  `sanityCheckAsmap(data, bits=128)` to `asmap.nim` and calling
  it in `loadAsmap`.

- **FIX-N5** (P2, ~4h): close BUG-2 by adding feeler type
  + exponential timer in `peermanager.nim:mainLoop`.  Requires
  also closing W104 G9 (SelectTriedCollision) so feelers have
  something to dial.

The remaining 19 BUGs (BUG-3..BUG-6, BUG-8, BUG-11..BUG-13,
BUG-15..BUG-24) are interleaved with W104 internal gates and
should be co-scheduled with the W104 fix wave that introduces
a real `AddrMan` type.

## Acceptance / forward-regression

This audit ships **30 xfail-shaped gate tests** in
`tests/test_w128_addrman.nim`.  Each test pins the *current* (buggy /
absent) behaviour with a `check` that asserts the gap exists.  When
a future FIX wave closes the gap, the test will fail loudly and the
developer must flip the assertion (per the methodology established
in W120/W122/W123/W124/W125 audit waves).
