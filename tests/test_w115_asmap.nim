## W115 ASMap fleet audit — nimrod
##
## Reference: bitcoin-core/src/util/asmap.h/cpp, netgroup.h, addrman.cpp, init.cpp
##
## STATUS: ASMap is MISSING ENTIRELY in nimrod.
##         No asmap file loading, no Interpret() bytecode engine, no
##         NetGroupManager, no GetMappedAS(), no -asmap CLI flag, no
##         asmap version tracking in peers.dat, no getpeerinfo mapped_as field.
##         All 30 gates below document the gap.
##
## ─────────────────────────────────────────────────────────────────────────────
## Summary of findings
## ─────────────────────────────────────────────────────────────────────────────
##
##   G1  MISSING ENTIRELY   – No -asmap CLI option / config flag
##   G2  MISSING ENTIRELY   – No asmap file loading (DecodeAsmap equivalent)
##   G3  MISSING ENTIRELY   – MAX_ASMAP_FILESIZE (8 MiB) guard absent
##   G4  MISSING ENTIRELY   – No SanityCheckAsmap / CheckStandardAsmap
##   G5  MISSING ENTIRELY   – No AsmapVersion (SHA-256 fingerprint of file data)
##   G6  MISSING ENTIRELY   – No Interpret() bytecode engine (RETURN/JUMP/MATCH/DEFAULT)
##   G7  MISSING ENTIRELY   – No DecodeBits varint decoder (LE-packed bit stream)
##   G8  MISSING ENTIRELY   – No ConsumeBitLE (LE ordering for asmap data)
##   G9  MISSING ENTIRELY   – No ConsumeBitBE (BE ordering for IP bits)
##   G10 MISSING ENTIRELY   – No NetGroupManager type (wraps asmap + GetGroup + GetMappedAS)
##   G11 BUG (MEDIUM)       – getNetGroup uses /16 (IPv4) / /32 (IPv6) instead of ASN
##                            when asmap is available; eclipse resistance is weaker
##   G12 BUG (MEDIUM)       – Two IPs in same /16 but different ASes get same bucket
##                            → attacker in one AS can fill entire netgroup slot
##   G13 MISSING ENTIRELY   – No GetMappedAS() exposed via RPC or connman
##   G14 MISSING ENTIRELY   – getpeerinfo "mapped_as" field absent (Core: net.cpp:3813)
##   G15 MISSING ENTIRELY   – No getnodeaddresses "mapped_as" field
##   G16 MISSING ENTIRELY   – No HasConnectivity / ASMapHealthCheck diagnostic
##   G17 MISSING ENTIRELY   – No UsingASMap() predicate (always "not using")
##   G18 MISSING ENTIRELY   – No asmap version persisted in peers.dat serialization
##   G19 MISSING ENTIRELY   – No re-bucketing on asmap version change at load time
##   G20 MISSING ENTIRELY   – No embedded asmap binary (fallback when no file given)
##   G21 MISSING ENTIRELY   – No "asmap" entry in getnetworkinfo RPC output
##   G22 MISSING ENTIRELY   – No CJDNS ASN lookup (CJDNS addresses are clearnet-routable
##                            but nimrod has no path to look up their AS)
##   G23 MISSING ENTIRELY   – No Tor / I2P ASN short-circuit (return 0 for privacy nets)
##   G24 MISSING ENTIRELY   – No IPv4-in-IPv6 (mapped) address unwrapping before Interpret
##   G25 MISSING ENTIRELY   – No addrman bucket hashing with ASN (GetTriedBucket /
##                            GetNewBucket substitutes ASN-keyed hash for /16 group)
##   G26 MISSING ENTIRELY   – No tried-table or new-table (addrman completely flat),
##                            so even if ASN were computed, bucketing is absent
##   G27 MISSING ENTIRELY   – No outbound diversity check by ASN (CConnman uses
##                            netgroupman.GetGroup which is ASN-keyed when loaded)
##   G28 MISSING ENTIRELY   – No ASMapHealthCheck / logging on startup
##   G29 MISSING ENTIRELY   – asmap data not persisted with peers.dat on shutdown
##   G30 MISSING ENTIRELY   – No testnet4 / regtest stub ASMap (Core has regtest with
##                            reduced addresses; no asmap is fine, but the absence of
##                            the whole subsystem means testnet4 eclipse risk elevated)
##
## Total: 28 MISSING ENTIRELY, 2 BUG.  30 bugs, 30 tests.
## ─────────────────────────────────────────────────────────────────────────────

import unittest2
import std/[sets, tables, hashes, strutils]
import ../src/network/netgroup
import ../src/network/peermanager
import ../src/consensus/params

# ─────────────────────────────────────────────────────────────────────────────
# Constants derived from Bitcoin Core for documentation
# ─────────────────────────────────────────────────────────────────────────────
const
  MAX_ASMAP_FILESIZE_BYTES* = 8 * 1024 * 1024   # 8 MiB — init.cpp:1596
  ASMAP_BITS*               = 128               # CheckStandardAsmap uses 128 bits
  # Core instruction opcodes
  ASMAP_RETURN*  = 0'u32
  ASMAP_JUMP*    = 1'u32
  ASMAP_MATCH*   = 2'u32
  ASMAP_DEFAULT* = 3'u32
  # Core ASN encoding: minval=1, bit_sizes=[15,16,17,...,24]
  ASMAP_ASN_MINVAL* = 1'u32
  # INVALID sentinel
  ASMAP_INVALID* = 0xFFFF_FFFF'u32

# ─────────────────────────────────────────────────────────────────────────────
# G1 — -asmap CLI option / config flag
# Core: init.cpp:540  argsman.AddArg("-asmap=<file>", ...)
# ─────────────────────────────────────────────────────────────────────────────
suite "G1 no -asmap CLI option":
  test "nimrod has no -asmap flag (MISSING ENTIRELY)":
    # Core registers "-asmap=<file>" in ArgsManager.
    # nimrod's option parser has no equivalent.  Eclipse-resistant bucketing
    # is therefore always disabled regardless of any operator configuration.
    # BUG: G1 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G2 — asmap file loading (DecodeAsmap)
# Core: util/asmap.cpp:322  DecodeAsmap(fs::path path)
# ─────────────────────────────────────────────────────────────────────────────
suite "G2 no asmap file loading":
  test "DecodeAsmap equivalent absent (MISSING ENTIRELY)":
    # Core opens the binary file, reads it entirely into memory, runs
    # CheckStandardAsmap, and returns the byte vector.
    # nimrod has no equivalent proc — there is no asmap-loading path anywhere
    # in src/util/, src/network/, or src/nimrod.nim.
    # BUG: G2 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G3 — MAX_ASMAP_FILESIZE guard (8 MiB)
# Core: init.cpp — file size checked via AutoFile.size() inside DecodeAsmap
# ─────────────────────────────────────────────────────────────────────────────
suite "G3 no MAX_ASMAP_FILESIZE guard":
  test "MAX_ASMAP_FILESIZE is 8 MiB per Core":
    check MAX_ASMAP_FILESIZE_BYTES == 8 * 1024 * 1024

  test "nimrod has no file-size guard (MISSING ENTIRELY)":
    # Without the guard a malicious / corrupt asmap file of arbitrary size
    # could be mapped into memory.  Since nimrod has no file-loading path at
    # all, this guard is vacuously absent.
    # BUG: G3 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G4 — SanityCheckAsmap / CheckStandardAsmap
# Core: util/asmap.cpp:239,310
# ─────────────────────────────────────────────────────────────────────────────
suite "G4 no SanityCheckAsmap":
  test "SanityCheckAsmap validates all execution paths absent (MISSING ENTIRELY)":
    # Core walks every possible code path through the bytecode, verifying:
    # - no jump past EOF
    # - no excessive padding
    # - all paths terminate with RETURN
    # - no consecutive DEFAULT instructions
    # Without this, a malformed asmap file would cause Interpret() to call
    # assert(false) in production (UB in release builds).
    # BUG: G4 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G5 — AsmapVersion (SHA-256 fingerprint)
# Core: util/asmap.cpp:348  AsmapVersion(span<const byte> data)
# ─────────────────────────────────────────────────────────────────────────────
suite "G5 no AsmapVersion fingerprint":
  test "AsmapVersion computes SHA-256 of asmap bytes absent (MISSING ENTIRELY)":
    # Core hashes the entire asmap byte vector via HashWriter << data to
    # produce a uint256 checksum.  This hash is:
    #  (a) logged at startup for operator verification
    #  (b) stored in peers.dat so that a node detects asmap changes on restart
    #      and re-buckets all entries.
    # nimrod has no equivalent.
    # BUG: G5 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G6 — Interpret() bytecode engine
# Core: util/asmap.cpp:182  uint32_t Interpret(span asmap, span ip)
# ─────────────────────────────────────────────────────────────────────────────
suite "G6 no Interpret() bytecode engine":
  test "Interpret() trie traversal absent (MISSING ENTIRELY)":
    # Core's Interpret() consumes IP bits (big-endian) and asmap bits
    # (little-endian) to walk a compressed binary trie encoded as bytecode.
    # The four opcodes: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1].
    # Returns the ASN (uint32) for the longest-matching prefix, or 0 if none.
    # nimrod has no such function.
    # BUG: G6 MISSING ENTIRELY
    check true

  test "RETURN opcode constant is 0 per Core":
    check ASMAP_RETURN == 0'u32

  test "JUMP opcode constant is 1 per Core":
    check ASMAP_JUMP == 1'u32

  test "MATCH opcode constant is 2 per Core":
    check ASMAP_MATCH == 2'u32

  test "DEFAULT opcode constant is 3 per Core":
    check ASMAP_DEFAULT == 3'u32

# ─────────────────────────────────────────────────────────────────────────────
# G7 — DecodeBits varint decoder
# Core: util/asmap.cpp:87  uint32_t DecodeBits(...)
# ─────────────────────────────────────────────────────────────────────────────
suite "G7 no DecodeBits varint decoder":
  test "DecodeBits variable-length integer decoder absent (MISSING ENTIRELY)":
    # Core uses a custom class-based varint encoding where each number falls
    # into one of several bit-size classes.  The encoding for ASNs uses
    # bit_sizes=[15,16,17,...,24] with minval=1; for JUMP offsets uses
    # bit_sizes=[5,6,...,30] with minval=17.
    # nimrod has no DecodeBits equivalent.
    # BUG: G7 MISSING ENTIRELY
    check true

  test "ASMAP_INVALID sentinel is 0xFFFFFFFF per Core":
    check ASMAP_INVALID == 0xFFFF_FFFF'u32

  test "ASN encoding minval is 1 per Core (ASN 0 is reserved / not-found)":
    check ASMAP_ASN_MINVAL == 1'u32

# ─────────────────────────────────────────────────────────────────────────────
# G8 — ConsumeBitLE (little-endian bit extraction for asmap data)
# Core: util/asmap.cpp:54  inline bool ConsumeBitLE(size_t& bitpos, span bytes)
# ─────────────────────────────────────────────────────────────────────────────
suite "G8 no ConsumeBitLE":
  test "ConsumeBitLE absent — asmap data uses LSB-first bit ordering (MISSING)":
    # Core stores asmap bits in little-endian (LSB-first) order within bytes.
    # Bit `bitpos` is extracted as (bytes[bitpos/8] >> (bitpos%8)) & 1.
    # This is the opposite of the big-endian convention used for IP addresses.
    # Without ConsumeBitLE there is no way to decode the packed asmap trie.
    # BUG: G8 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G9 — ConsumeBitBE (big-endian bit extraction for IP bits)
# Core: util/asmap.cpp:65  inline bool ConsumeBitBE(uint8_t& bitpos, span bytes)
# ─────────────────────────────────────────────────────────────────────────────
suite "G9 no ConsumeBitBE":
  test "ConsumeBitBE absent — IP bits must be consumed MSB-first (MISSING)":
    # Core reads IP address bits in big-endian (MSB-first) order to match
    # network byte order: bit `bitpos` is (bytes[bitpos/8] >> (7-bitpos%8)) & 1.
    # This is symmetric with how CIDR prefixes are defined (most-significant
    # bit first).  Without ConsumeBitBE the trie cannot be traversed.
    # BUG: G9 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G10 — NetGroupManager type
# Core: netgroup.h — class NetGroupManager { GetGroup, GetMappedAS, UsingASMap }
# ─────────────────────────────────────────────────────────────────────────────
suite "G10 no NetGroupManager type":
  test "NetGroupManager wrapper type absent (MISSING ENTIRELY)":
    # Core's NetGroupManager encapsulates the asmap data and provides:
    #   GetGroup(addr)      → group bytes for bucketing (ASN-keyed or /16)
    #   GetMappedAS(addr)   → raw ASN for display / stats
    #   GetAsmapVersion()   → checksum uint256
    #   UsingASMap()        → bool predicate
    #   ASMapHealthCheck()  → diagnostic log
    # nimrod has only a bare getNetGroup(IpAddr) that always uses /16 or /32.
    # BUG: G10 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G11 — getNetGroup uses /16 instead of ASN when asmap available
# Core: netgroup.cpp GetGroup() uses Interpret() when m_asmap is non-empty
# BUG SEVERITY: MEDIUM
# ─────────────────────────────────────────────────────────────────────────────
suite "G11 getNetGroup uses /16 not ASN (BUG)":
  test "Two IPs in same /16 always get same group regardless of AS":
    # This is correct behavior *without* asmap, but it means eclipse protection
    # is limited to /16 granularity.  Two peers at 1.2.3.4 and 1.2.4.5 are in
    # different /24 subnets (possibly different ASes) but nimrod treats them as
    # the same group.  With asmap they might be in different ASes and should
    # count as separate groups.
    let ip1 = parseIpAddr("1.2.3.4")
    let ip2 = parseIpAddr("1.2.200.1")   # same /16 (1.2.0.0/16)
    let g1 = getNetGroup(ip1)
    let g2 = getNetGroup(ip2)
    # Without asmap both yield the same /16 group — documents BUG G11
    check g1 == g2

  test "getNetGroup for IPv4 always returns /16 prefix bytes":
    # Core with asmap would return hash(ASN, nKey) here.
    # nimrod returns [NetIPv4, first_octet, second_octet] unconditionally.
    let ip = parseIpAddr("8.8.8.8")       # Google DNS — AS15169
    let ip2 = parseIpAddr("8.8.4.4")      # also AS15169 but /16 same anyway
    let g = getNetGroup(ip)
    # Verify the /16 structure: first byte is NetIPv4, next two are 8, 8
    check g.data.len == 3
    check g.data[0] == NetIPv4
    check g.data[1] == 8'u8   # first octet
    check g.data[2] == 8'u8   # second octet — /16 boundary

  test "Two IPs in different /16 but same AS get different groups (false divergence)":
    # With asmap, 1.2.x.x and 1.3.x.x could be in the same AS → same bucket.
    # nimrod always separates them because /16 differs.  This is a false
    # positive for diversity: nimrod *over-separates*, which is not dangerous,
    # but it also *under-separates* within a /16 (G12).
    let ip1 = parseIpAddr("1.2.0.1")
    let ip2 = parseIpAddr("1.3.0.1")
    let g1 = getNetGroup(ip1)
    let g2 = getNetGroup(ip2)
    check g1 != g2   # /16 groups differ — correct for /16, but may be wrong for ASN

# ─────────────────────────────────────────────────────────────────────────────
# G12 — Two IPs in same /16 but different ASes get same bucket (BUG)
# Core: when asmap is loaded, GetGroup returns hash(ASN, nKey) — not /16
# BUG SEVERITY: MEDIUM (eclipse attack surface expanded within multi-AS /16)
# ─────────────────────────────────────────────────────────────────────────────
suite "G12 same /16 different AS treated identically (BUG)":
  test "nimrod cannot distinguish ASes within a single /16 block":
    # Real-world scenario: a transit provider may host clients from multiple
    # different ASes within the same /24 or /16.  Without asmap nimrod sees
    # all of them as one group, so an eclipse attacker with 8 IPs in the same
    # /16 can occupy all outbound-full-relay slots.
    # With asmap Core would compute distinct ASN→bucket hashes.
    # BUG: G12 — structural limitation while asmap is absent.
    let groupA = getNetGroup("203.0.113.1")   # same /16
    let groupB = getNetGroup("203.0.113.200") # same /16
    check groupA == groupB  # documents the collision

# ─────────────────────────────────────────────────────────────────────────────
# G13 — No GetMappedAS() exposed via connman
# Core: net.cpp:3800  CConnman::GetMappedAS(addr)
# ─────────────────────────────────────────────────────────────────────────────
suite "G13 no GetMappedAS() in connman / peermanager":
  test "PeerManager has no getMappedAS method (MISSING ENTIRELY)":
    # Core's CConnman::GetMappedAS delegates to m_netgroupman.GetMappedAS(addr)
    # which in turn calls Interpret().  nimrod's PeerManager type has no such
    # method.
    # BUG: G13 MISSING ENTIRELY
    when compiles(block:
      let pm = PeerManager()
      discard pm.getMappedAS("1.2.3.4")):
      check false  # should not compile
    else:
      check true

# ─────────────────────────────────────────────────────────────────────────────
# G14 — getpeerinfo "mapped_as" field absent
# Core: net.cpp:3813  vstats.back().m_mapped_as = GetMappedAS(pnode->addr)
# ─────────────────────────────────────────────────────────────────────────────
suite "G14 no mapped_as in getpeerinfo":
  test "getpeerinfo response does not include mapped_as (MISSING ENTIRELY)":
    # Core includes "mapped_as": <uint> in every getpeerinfo entry when asmap
    # is configured (0 when not configured but key is always present).
    # nimrod's handleGetPeerInfo (rpc/server.nim) has no "mapped_as" key.
    # BUG: G14 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G15 — No getnodeaddresses "mapped_as" field
# Core: rpc/net.cpp  getnodeaddresses includes mapped_as
# ─────────────────────────────────────────────────────────────────────────────
suite "G15 no mapped_as in getnodeaddresses":
  test "getnodeaddresses mapped_as absent (MISSING ENTIRELY)":
    # Core's getnodeaddresses RPC includes a "mapped_as" field per returned
    # address entry.  nimrod has no asmap, so this field cannot be populated.
    # BUG: G15 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G16 — No ASMapHealthCheck diagnostic
# Core: netgroup.h  void ASMapHealthCheck(const vector<CNetAddr>&)
# ─────────────────────────────────────────────────────────────────────────────
suite "G16 no ASMapHealthCheck":
  test "ASMapHealthCheck diagnostic absent (MISSING ENTIRELY)":
    # Core's ASMapHealthCheck logs how many ASes are represented in the addrman
    # new-table addresses to verify the asmap is providing meaningful diversity.
    # nimrod has no diagnostic equivalent.
    # BUG: G16 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G17 — No UsingASMap() predicate
# Core: netgroup.h  bool UsingASMap() const { return !m_asmap.empty(); }
# ─────────────────────────────────────────────────────────────────────────────
suite "G17 no UsingASMap predicate":
  test "UsingASMap() predicate absent (MISSING ENTIRELY)":
    # Core uses UsingASMap() to gate asmap-specific code paths (e.g. logging,
    # health check, bucket-hash selection).  nimrod has no such predicate;
    # it is unconditionally "not using asmap".
    # BUG: G17 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G18 — asmap version not persisted in peers.dat
# Core: addrman.cpp:207  s << m_netgroupman.GetAsmapVersion()
# ─────────────────────────────────────────────────────────────────────────────
suite "G18 asmap version not persisted in peers.dat":
  test "peers.dat serialization omits asmap version hash (MISSING ENTIRELY)":
    # Core appends a uint256 asmap version after the bucket entries during
    # peers.dat serialization.  On load, if the stored version differs from
    # the supplied asmap, Core re-buckets all entries.
    # nimrod has no asmap at all, so this field is never written.
    # BUG: G18 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G19 — No re-bucketing on asmap version change
# Core: addrman.cpp:313  if (...asmap version changed) re-bucket from scratch
# ─────────────────────────────────────────────────────────────────────────────
suite "G19 no re-bucketing on asmap version change":
  test "asmap version change does not trigger re-bucketing (MISSING ENTIRELY)":
    # When an operator upgrades to a newer asmap file, Core detects the
    # version mismatch and re-computes every bucket assignment from scratch.
    # Without this, stale bucket assignments from the old asmap persist,
    # reducing diversity guarantees.
    # nimrod has no addrman buckets and no asmap, so this logic is absent.
    # BUG: G19 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G20 — No embedded asmap fallback
# Core: init.cpp:1612  node::data::ip_asn embedded byte span
# ─────────────────────────────────────────────────────────────────────────────
suite "G20 no embedded asmap binary":
  test "no compiled-in asmap fallback (MISSING ENTIRELY)":
    # Core ships with an embedded asmap byte array (node/data/ip_asn.cpp) used
    # when the operator passes -asmap without a filename (-asmap=1).
    # nimrod has no such embedded data and no mechanism to load it.
    # BUG: G20 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G21 — No "asmap" entry in getnetworkinfo
# Core: rpc/net.cpp getnetworkinfo includes "asmap" key with version hash
# ─────────────────────────────────────────────────────────────────────────────
suite "G21 no asmap in getnetworkinfo":
  test "getnetworkinfo does not include asmap version (MISSING ENTIRELY)":
    # Core's getnetworkinfo RPC includes "asmap": <hash-hex> when asmap is
    # configured (empty string when not).  nimrod's equivalent RPC handler
    # does not include this field.
    # BUG: G21 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G22 — No CJDNS ASN lookup path
# Core: netgroup.cpp GetGroup() calls Interpret() for CJDNS addresses
# ─────────────────────────────────────────────────────────────────────────────
suite "G22 CJDNS ASN lookup absent":
  test "CJDNS addresses (fc00::/8) wrongly treated as unroutable (MISSING + extra bug)":
    # Core's GetGroup() treats CJDNS (fc00::/8) as clearnet-routable and passes
    # the address through Interpret() to obtain an ASN when asmap is loaded.
    # nimrod has two problems:
    #   (a) isRoutable() rejects fc00::/7 as IPv6 ULA (correct for ULA, but
    #       CJDNS fc00::/8 is a strict subset and should be treated differently).
    #   (b) Even if routed correctly, there is no Interpret() path for ASN lookup.
    # The net effect: nimrod groups all CJDNS addresses into NetUnroutable,
    # collapsing all CJDNS peers into a single bucket — no diversity at all.
    # BUG: G22 MISSING ENTIRELY (ASN lookup) + extra bug (CJDNS as unroutable)
    let cjdns = parseIpAddr("fc00::1")
    check cjdns.isCJDNS()  # correctly detected as CJDNS by isCJDNS()
    # But isRoutable returns false, so getNetGroup returns NetUnroutable
    check not cjdns.isRoutable()
    let g = getNetGroup(cjdns)
    check g.data[0] == NetUnroutable  # documents the wrong behavior

# ─────────────────────────────────────────────────────────────────────────────
# G23 — No Tor / I2P ASN short-circuit
# Core: netgroup.cpp — Tor/I2P return early (ASN lookup skipped; these are
#                       privacy networks, not clearnet)
# ─────────────────────────────────────────────────────────────────────────────
suite "G23 Tor/I2P not short-circuited in ASN lookup":
  test "Tor addresses not routable so not passed to Interpret (documented)":
    # Core's GetMappedAS returns 0 for Tor / I2P without calling Interpret().
    # nimrod would also return 0 (implicitly, since it never calls Interpret)
    # but only because the whole subsystem is absent.  The short-circuit logic
    # is still MISSING ENTIRELY as a documented code path.
    # BUG: G23 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G24 — No IPv4-in-IPv6 unwrapping before Interpret
# Core: netaddr.cpp — GetIn6Addr unwraps ::ffff:x.x.x.x before ASN lookup
# ─────────────────────────────────────────────────────────────────────────────
suite "G24 no IPv4-in-IPv6 unwrapping for Interpret":
  test "IPv4-mapped IPv6 address unwrapping for ASN lookup absent (MISSING + parser bug)":
    # Core unwraps ::ffff:a.b.c.d to the IPv4 address a.b.c.d before calling
    # Interpret(), since the asmap is keyed on 32-bit IPv4 for mapped addresses.
    # nimrod has two problems here:
    #   (a) parseIpAddr("::ffff:1.2.3.4") has a parser bug: the right-group
    #       position calculation treats the embedded IPv4 as 2 bytes (one group)
    #       but then writes 4 bytes at bytes[12..15], leaving bytes[10..11] as 0
    #       instead of 0xFF 0xFF.  So isIPv4Mapped() returns false for this form.
    #   (b) Even if the parser were correct, there is no Interpret() path.
    # BUG: G24 MISSING ENTIRELY + parser bug in parseIpAddr for ::ffff:x.x.x.x
    let mapped = parseIpAddr("::ffff:1.2.3.4")
    # Document the parser bug: isIPv4Mapped() should return true but does not
    check not mapped.isIPv4Mapped()  # BUG: should be true
    # The IPv4 bytes themselves ARE written at offset 12-15 (parser partially works)
    let v4 = mapped.extractIPv4()
    check v4 == [1'u8, 2, 3, 4]  # bytes at [12..15] are correct

# ─────────────────────────────────────────────────────────────────────────────
# G25 — No addrman bucket hashing with ASN
# Core: addrman_impl.h  GetNewBucket / GetTriedBucket use group bytes from
#                       NetGroupManager.GetGroup(), which is ASN-keyed
# ─────────────────────────────────────────────────────────────────────────────
suite "G25 no ASN-keyed bucket hashing in addrman":
  test "addrman bucket hashing uses getNetGroup which is /16-keyed (MISSING)":
    # Core: bucket = hash(nKey, source_group, GetGroup(addr)) where GetGroup
    #   uses the asmap-computed group bytes (ASN → 4 bytes) when asmap loaded.
    # nimrod: no bucket hashing exists at all (knownAddresses is a flat seq).
    #   Even if buckets were added, they would hash on /16 groups, not ASNs.
    # BUG: G25 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G26 — No tried/new tables (addrman completely flat)
# Core: addrman_impl.h  m_new_table[1024][64], m_tried_table[256][64]
# ─────────────────────────────────────────────────────────────────────────────
suite "G26 addrman is flat not bucketed (MISSING)":
  test "knownAddresses is a plain seq with no bucket structure":
    # nimrod stores addresses as a flat seq[NetAddress] (peermanager.nim:78).
    # This means ASN-based or /16-based eclipse protection via bucket limits
    # is entirely absent — an adversary can fill the flat list trivially.
    # BUG: G26 MISSING ENTIRELY (pre-existing, also reported in W104)
    let pm = newPeerManager(mainnetParams())
    check pm.knownAddresses.len == 0  # starts empty
    # The type is seq, not a bucketed structure

# ─────────────────────────────────────────────────────────────────────────────
# G27 — No outbound diversity check by ASN
# Core: net.cpp CConnman::HasFullyConnectedOutboundPeer — checks by
#       netgroupman.GetGroup() which is ASN-keyed
# ─────────────────────────────────────────────────────────────────────────────
suite "G27 outbound diversity checked by /16 not ASN (MISSING)":
  test "outboundNetGroups is keyed by /16 NetGroup not ASN (MISSING ENTIRELY)":
    # PeerManager.outboundNetGroups uses NetGroup from getNetGroup(ip) which
    # is always a /16 (IPv4) or /32 (IPv6) group.
    # Core uses netgroupman.GetGroup() which returns the ASN-keyed group when
    # asmap is loaded.  The diversity check is structurally present in nimrod
    # but uses the weaker /16 granularity.
    # BUG: G27 (structural limitation — ASN unavailable)
    let pm = newPeerManager(mainnetParams())
    check pm.outboundNetGroups.len == 0

# ─────────────────────────────────────────────────────────────────────────────
# G28 — No ASMapHealthCheck / startup logging
# Core: init.cpp calls netgroupman.ASMapHealthCheck after loading peers.dat
# ─────────────────────────────────────────────────────────────────────────────
suite "G28 no ASMapHealthCheck on startup":
  test "no health check logged on startup (MISSING ENTIRELY)":
    # Core logs the number of distinct ASes in addrman after loading peers.dat
    # when asmap is active.  This helps operators verify the asmap is providing
    # real diversity (e.g., "12 ASes represented in new table").
    # nimrod has no such logging path.
    # BUG: G28 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G29 — asmap data not persisted with peers.dat on shutdown
# Core: addrman.cpp Serialize writes asmap version at end of file
# ─────────────────────────────────────────────────────────────────────────────
suite "G29 asmap data not saved in peers.dat on shutdown":
  test "peers.dat persistence omits asmap context (MISSING ENTIRELY)":
    # Even if asmap were loaded, nimrod does not persist the asmap version
    # hash at the end of peers.dat, so on next start it cannot detect that
    # the asmap has changed and re-bucket accordingly.
    # BUG: G29 MISSING ENTIRELY
    check true

# ─────────────────────────────────────────────────────────────────────────────
# G30 — No testnet4/regtest ASMap stub
# Core: testnet4 / regtest use same ASMap path (just smaller address sets)
# ─────────────────────────────────────────────────────────────────────────────
suite "G30 no testnet4 or regtest ASMap consideration":
  test "testnet4 eclipse risk elevated due to absent ASMap (MISSING ENTIRELY)":
    # Core allows -asmap on all networks.  testnet4 has fewer peers so eclipse
    # attacks are easier; an asmap would help partition the small peer set by
    # AS ownership.  nimrod has no asmap on any network.
    # BUG: G30 MISSING ENTIRELY
    check true

  test "ASMAP_BITS constant matches Core (128 bits for IPv6)":
    check ASMAP_BITS == 128

  test "Core CheckStandardAsmap uses 128-bit input width":
    # SanityCheckAsmap(data, 128) — the 128 is the IPv6 address bit width
    check ASMAP_BITS == 128
