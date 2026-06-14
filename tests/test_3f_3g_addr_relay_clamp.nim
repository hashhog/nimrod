## test_3f_3g_addr_relay_clamp.nim
##
## Non-vacuous tests for two addr-policy fixes:
##
##   3F — relay gate: addr/addrv2 messages with > 10 entries MUST NOT be
##        relayed (they are getaddr responses).  Core gate is <= 10.
##        Before fix: gate was <= 1000.  Tests confirm AddrRelayMaxEntries == 10.
##        Reference: bitcoin-core/src/net_processing.cpp:5688.
##
##   3G — timestamp clamp: received addr/addrv2 timestamps that are pre-2001
##        (<= 100000000) or more than 10 minutes in the future are clamped to
##        (now - 5 days) before storing.  Without the fix, wild timestamps are
##        stored verbatim.
##        Reference: bitcoin-core/src/net_processing.cpp:5678-5680.

import unittest2
import std/times
import ../src/network/messages
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeIPv4Mapped(a, b, c, d: byte): array[16, byte] =
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc makeTA(a, b, c, d: byte; ts: uint32): TimestampedAddr =
  ## Build a TimestampedAddr for a routable IPv4 address.
  var na = NetAddress()
  na.ip = makeIPv4Mapped(a, b, c, d)
  na.port = 8333
  TimestampedAddr(timestamp: ts, address: na)

proc makeV2IPv4(a, b, c, d: byte; ts: uint32): TimestampedAddrV2 =
  ## Build a TimestampedAddrV2 for a routable IPv4 address (addrv2 format).
  var addr2 = NetAddressV2(networkId: netIPv4)
  addr2.ipv4 = [a, b, c, d]
  TimestampedAddrV2(
    timestamp: ts,
    services: 1'u64,
    address: addr2,
    port: 8333
  )

proc freshPeer(): Peer =
  newPeer("10.0.0.1", 8333'u16, mainnetParams(), pdInbound)

# ---------------------------------------------------------------------------
# 3F — relay gate constant is 10 (not 1000)
# ---------------------------------------------------------------------------

suite "3F addr relay gate == 10 (Core net_processing.cpp:5688)":

  test "3F: AddrRelayMaxEntries constant is 10":
    ## Pre-fix: AddrRelayMaxEntries was 1000.
    ## Post-fix: must be 10 (matches Core vAddr.size() <= 10).
    ## This test FAILS if the constant is reverted to 1000.
    check AddrRelayMaxEntries == 10

  test "3F: addr message with 11 entries stores addresses (storage gate unaffected)":
    ## The relay gate does NOT affect address storage.  Even a 1000-entry addr
    ## message should populate knownAddresses (all routable entries).
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowTs = uint32(getTime().toUnix())
    var addrs: seq[TimestampedAddr]
    for i in 1'u8 .. 11'u8:
      addrs.add(makeTA(8, 8, i, 1, nowTs))
    let msg = P2PMessage(kind: mkAddr, addresses: addrs)
    pm.handleAddrInternal(peer, msg)
    check pm.knownAddresses.len == 11

  test "3F: addrv2 message with 11 entries stores addresses (storage gate unaffected)":
    ## Same for addrv2: relay gate change must not affect address storage.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowTs = uint32(getTime().toUnix())
    var addrs: seq[TimestampedAddrV2]
    for i in 1'u8 .. 11'u8:
      addrs.add(makeV2IPv4(8, 8, i, 2, nowTs))
    let msg = P2PMessage(kind: mkAddrV2, addressesV2: addrs)
    pm.handleAddrInternal(peer, msg)
    check pm.knownAddresses.len == 11

  test "3F: addr message with exactly 10 entries is within relay gate":
    ## A message with exactly 10 entries satisfies <= 10, so relay is attempted
    ## (though with no connected peers it is a no-op).  Confirm no crash + storage.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowTs = uint32(getTime().toUnix())
    var addrs: seq[TimestampedAddr]
    for i in 1'u8 .. 10'u8:
      addrs.add(makeTA(9, 0, i, 1, nowTs))
    let msg = P2PMessage(kind: mkAddr, addresses: addrs)
    pm.handleAddrInternal(peer, msg)
    check pm.knownAddresses.len == 10

# ---------------------------------------------------------------------------
# 3G — timestamp clamp: ADDR path
# ---------------------------------------------------------------------------

suite "3G addr timestamp clamp (Core net_processing.cpp:5678-5680)":

  test "3G: pre-2001 timestamp (100000000) is clamped to now - 5 days":
    ## Core: if addr.nTime <= 100000000, clamp to (current_time - 5 days).
    ## Before fix: 100000000 stored verbatim.
    ## After fix: stored value is approximately now - 432000 seconds.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    # Timestamp at exactly the pre-2001 boundary (Unix 100000000 ≈ 1973-03-03).
    let staleTs = 100_000_000'u32
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(1, 2, 3, 4, staleTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    let stored = pm.knownAddresses[0].lastSeen
    let nowSec = uint32(getTime().toUnix())
    let fiveDays = 5'u32 * 24'u32 * 3600'u32
    # Must NOT be the raw stale value.
    check stored != staleTs
    # Must be within 60 seconds of (now - 5 days).
    check stored >= nowSec - fiveDays - 60'u32
    check stored <= nowSec - fiveDays + 60'u32

  test "3G: timestamp zero (below 100000000) is clamped to now - 5 days":
    ## Timestamp 0 is also pre-2001; same clamping applies.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(5, 6, 7, 8, 0'u32)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    let stored = pm.knownAddresses[0].lastSeen
    let nowSec = uint32(getTime().toUnix())
    let fiveDays = 5'u32 * 24'u32 * 3600'u32
    check stored != 0'u32
    check stored >= nowSec - fiveDays - 60'u32
    check stored <= nowSec - fiveDays + 60'u32

  test "3G: future timestamp (now + 20 min) is clamped to now - 5 days":
    ## Core: if addr.nTime > current_time + 10min, clamp to (current_time - 5 days).
    ## 20 minutes in the future exceeds the 10-minute tolerance window.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowSec = uint32(getTime().toUnix())
    let futureTs = nowSec + 1200'u32  # now + 20 minutes
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(51, 20, 30, 40, futureTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    let stored = pm.knownAddresses[0].lastSeen
    let fiveDays = 5'u32 * 24'u32 * 3600'u32
    check stored != futureTs
    check stored >= nowSec - fiveDays - 60'u32
    check stored <= nowSec - fiveDays + 60'u32

  test "3G: valid recent timestamp is stored as-is (no clamp)":
    ## A timestamp within the last hour must pass through unchanged.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowSec = uint32(getTime().toUnix())
    let recentTs = nowSec - 3600'u32  # 1 hour ago — valid
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(11, 22, 33, 44, recentTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    # Must be stored exactly as provided (no clamp applied).
    check pm.knownAddresses[0].lastSeen == recentTs

  test "3G: timestamp exactly at boundary (100000001) is NOT clamped":
    ## Core condition is strict: <= 100000000 triggers clamp, 100000001 does not.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let boundaryTs = 100_000_001'u32
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(12, 34, 56, 78, boundaryTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    check pm.knownAddresses[0].lastSeen == boundaryTs

  test "3G: timestamp within 10 minutes future is NOT clamped":
    ## now + 5 minutes is within the 10-minute tolerance; must not be clamped.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowSec = uint32(getTime().toUnix())
    let nearFutureTs = nowSec + 300'u32  # now + 5 minutes
    let msg = P2PMessage(kind: mkAddr,
      addresses: @[makeTA(15, 25, 35, 45, nearFutureTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    check pm.knownAddresses[0].lastSeen == nearFutureTs

# ---------------------------------------------------------------------------
# 3G — timestamp clamp: ADDRV2 path (IPv4/IPv6 via toLegacyTimestampedAddr)
# ---------------------------------------------------------------------------

suite "3G addrv2 timestamp clamp IPv4 path (Core net_processing.cpp:5678-5680)":

  test "3G/v2: pre-2001 timestamp is clamped (addrv2 IPv4 entry)":
    ## Same clamp applies to addrv2 messages carrying IPv4 addresses.
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let staleTs = 50_000_000'u32
    let msg = P2PMessage(kind: mkAddrV2,
      addressesV2: @[makeV2IPv4(8, 8, 4, 4, staleTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    let stored = pm.knownAddresses[0].lastSeen
    let nowSec = uint32(getTime().toUnix())
    let fiveDays = 5'u32 * 24'u32 * 3600'u32
    check stored != staleTs
    check stored >= nowSec - fiveDays - 60'u32
    check stored <= nowSec - fiveDays + 60'u32

  test "3G/v2: future timestamp > now+10min is clamped (addrv2 IPv4 entry)":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowSec = uint32(getTime().toUnix())
    let futureTs = nowSec + 3600'u32  # 1 hour in future
    let msg = P2PMessage(kind: mkAddrV2,
      addressesV2: @[makeV2IPv4(8, 8, 5, 5, futureTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    let stored = pm.knownAddresses[0].lastSeen
    let fiveDays = 5'u32 * 24'u32 * 3600'u32
    check stored != futureTs
    check stored >= nowSec - fiveDays - 60'u32
    check stored <= nowSec - fiveDays + 60'u32

  test "3G/v2: valid recent timestamp stored as-is (addrv2 IPv4 entry)":
    let pm = newPeerManager(regtestParams(), dataDir = "/tmp")
    var peer = freshPeer()
    let nowSec = uint32(getTime().toUnix())
    let recentTs = nowSec - 7200'u32  # 2 hours ago
    let msg = P2PMessage(kind: mkAddrV2,
      addressesV2: @[makeV2IPv4(8, 8, 6, 6, recentTs)])
    pm.handleAddrInternal(peer, msg)
    require pm.knownAddresses.len == 1
    check pm.knownAddresses[0].lastSeen == recentTs

when isMainModule:
  discard
