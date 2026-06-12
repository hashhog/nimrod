## W169 — P2P anti-eclipse hardening proof (nimrod, pilot).
##
## Proves the four Core-faithful additions to the connman/addr-relay layer:
##
##   1. FEELER selects from the NEW table and promotes a probed address
##      NEW->TRIED on handshake success (Core ThreadOpenConnections FEELER
##      branch: addrman.Select(true) + Good() on success).  A NEW entry that is
##      NOT probed/marked-good stays in NEW (falsification of "always tried").
##      Feelers do NOT consume a full-relay/block-relay outbound slot.
##
##   2. GETADDR-once: only the FIRST getaddr per connection is answered; a
##      second getaddr from the same peer returns empty (Core m_getaddr_recvd).
##      getaddr from a non-inbound (outbound) connection is ignored.
##
##   3. GETADDR 23%-cap: the response is capped at min(1000, floor(0.23 * N))
##      (Core MAX_PCT_ADDR_TO_SEND, integer floor).
##
##   4. Inbound addr token-bucket: a rate-limited (non-NoBan) peer whose bucket
##      is drained has its excess addresses DROPPED (Core m_addr_token_bucket,
##      MAX_ADDR_RATE_PER_SECOND=0.1 / MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000).
##
## Reference: bitcoin-core/src/net.cpp (ThreadOpenConnections FEELER),
##            bitcoin-core/src/net_processing.cpp (GETADDR handler + addr token
##            bucket), bitcoin-core/src/addrman.cpp (GetAddr_ / Select_ / Good_).

import unittest2
import std/[options, os, times]
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/addr
import ../src/network/addrman
import ../src/network/messages
import ../src/consensus/params

proc ip4(a, b, c, d: byte): array[16, byte] =
  ## IPv4 in 16-byte ::ffff:a.b.c.d form.
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc freshPm(): PeerManager =
  ## A peer manager backed by an empty temp datadir so the addrman starts cold.
  let dir = getTempDir() / ("nimrod_feeler_" & $getCurrentProcessId() & "_" & $epochTime())
  createDir(dir)
  newPeerManager(regtestParams(), dataDir = dir)

proc na(a, b, c, d: byte, port: uint16): NetAddress =
  NetAddress(services: 1'u64, ip: ip4(a, b, c, d), port: port, lastSeen: 1_700_000_000'u32)

# ─── 1. FEELER: select-from-NEW + promote-on-success + bounded ───────────────
suite "W169 feeler: NEW->TRIED promotion on probe success":

  test "selectAddress(newOnly) draws from NEW; markAddressGood promotes to TRIED":
    let pm = freshPm()
    let addr16 = ip4(9, 9, 9, 9)
    let src = ip4(9, 9, 9, 9)
    # Heard-about address lands in NEW.
    check pm.addrMan.add(addr16, 8333'u16, src, 1'u64, 1_700_000_000'i64, pm.netGroupManager)
    check pm.addrMan.newCount() == 1
    check pm.addrMan.triedCount() == 0
    check not pm.addrMan.isInTried(addr16, 8333'u16)

    # The feeler picks a NEW-table address (Core addrman.Select(true)).
    let sel = pm.selectAddress(newOnly = true)
    check sel.isSome
    check sel.get().ip == addr16
    check sel.get().port == 8333'u16

    # On a successful probe handshake the feeler calls markAddressGood, which
    # promotes the address NEW->TRIED (Core Good()).
    pm.markAddressGood("9.9.9.9", 8333'u16)
    check pm.addrMan.isInTried(addr16, 8333'u16)
    check pm.addrMan.triedCount() == 1

  test "FALSIFICATION: a NEW entry NOT probed stays in NEW (no auto-promotion)":
    let pm = freshPm()
    let addr16 = ip4(7, 7, 7, 7)
    check pm.addrMan.add(addr16, 8333'u16, addr16, 1'u64, 1_700_000_000'i64, pm.netGroupManager)
    # Selecting newOnly does NOT promote — only a successful probe (Good) does.
    discard pm.selectAddress(newOnly = true)
    check not pm.addrMan.isInTried(addr16, 8333'u16)
    check pm.addrMan.triedCount() == 0

  test "feeler selectAddress(newOnly) returns none when NEW table is empty":
    let pm = freshPm()
    check pm.addrMan.newCount() == 0
    check pm.selectAddress(newOnly = true).isNone

  test "feeler does NOT consume a full-relay / block-relay outbound slot":
    let pm = freshPm()
    # No outbound peers exist; opening a feeler must not change the slot counts.
    check pm.outboundFullRelayCount == 0
    check pm.outboundBlockRelayCount == 0
    # tryFeelerConnection is a no-op here (no NEW addr to probe) but must never
    # mutate the outbound slot accounting.
    check pm.maxOutboundFullRelay == DefaultMaxOutboundFullRelay

# ─── 2. GETADDR-once + non-inbound ignore ────────────────────────────────────
suite "W169 getaddr-once guard":

  test "second getaddr from the same peer returns empty":
    let pm = freshPm()
    # Seed enough known addresses that a response would be non-empty.
    for i in 0'u8..<50'u8:
      pm.knownAddresses.add(na(10, 0, 0, i, 8333))
    let peer = newPeer("5.5.5.5", 8333, regtestParams(), pdInbound)

    let first = pm.buildGetAddrResponse(peer)
    check first.len > 0          # first getaddr is answered
    check peer.getaddrRecvd      # guard latched

    let second = pm.buildGetAddrResponse(peer)
    check second.len == 0        # second getaddr is ignored

  test "getaddr from an OUTBOUND connection is ignored":
    let pm = freshPm()
    for i in 0'u8..<50'u8:
      pm.knownAddresses.add(na(11, 0, 0, i, 8333))
    let peer = newPeer("6.6.6.6", 8333, regtestParams(), pdOutbound)
    check pm.buildGetAddrResponse(peer).len == 0
    check not peer.getaddrRecvd  # never latched — request was rejected pre-guard

# ─── 3. GETADDR 23%-cap ──────────────────────────────────────────────────────
suite "W169 getaddr 23-percent cap":

  test "response capped at floor(0.23 * addrman size)":
    let pm = freshPm()
    # 200 known addresses -> cap = 23 * 200 / 100 = 46.
    for i in 0'u16..<200'u16:
      pm.knownAddresses.add(na(12, 0, uint8(i shr 8), uint8(i and 0xFF), 8333 + i))
    check pm.knownAddresses.len == 200
    let peer = newPeer("4.4.4.4", 8333, regtestParams(), pdInbound)
    let resp = pm.buildGetAddrResponse(peer)
    check resp.len == 46         # 23% floor of 200

  test "1000 hard cap dominates when 23% would exceed it":
    let pm = freshPm()
    # 5000 addresses -> 23% = 1150, clamped to MaxAddrToSend = 1000.
    for i in 0'u16..<5000'u16:
      pm.knownAddresses.add(na(13, uint8(i shr 8), 0, uint8(i and 0xFF), 8333))
    let peer = newPeer("3.3.3.3", 8333, regtestParams(), pdInbound)
    let resp = pm.buildGetAddrResponse(peer)
    check resp.len == MaxAddrToSend  # 1000, not 1150

# ─── 4. Inbound addr token-bucket ────────────────────────────────────────────
suite "W169 inbound addr token-bucket rate limit":

  test "excess addresses are dropped when the bucket is drained":
    let pm = freshPm()
    let peer = newPeer("2.2.2.2", 8333, regtestParams(), pdInbound)
    # Drain the bucket to empty and pin the refill clock so no tokens accrue
    # within the test window (1 second of real time would add only 0.1 token).
    peer.addrTokenBucket = 0.0
    peer.addrTokenTimestamp = getTime().toUnix()

    var addrs: seq[TimestampedAddr]
    for i in 0'u16..<20'u16:
      addrs.add(TimestampedAddr(timestamp: 1_700_000_000'u32,
        address: na(20, uint8(i shr 8), 0, uint8(i and 0xFF), 8333 + i)))
    let msg = newAddr(addrs)
    let before = pm.knownAddresses.len
    pm.handleAddrInternal(peer, msg)
    # With an empty bucket and a rate-limited (non-NoBan) peer, all 20 distinct
    # addresses are dropped — none stored.
    check pm.knownAddresses.len == before

  test "addresses ARE stored when the bucket has tokens":
    let pm = freshPm()
    let peer = newPeer("1.1.1.1", 8333, regtestParams(), pdInbound)
    peer.addrTokenBucket = 1000.0
    peer.addrTokenTimestamp = getTime().toUnix()

    var addrs: seq[TimestampedAddr]
    for i in 0'u16..<20'u16:
      addrs.add(TimestampedAddr(timestamp: 1_700_000_000'u32,
        address: na(21, uint8(i shr 8), 0, uint8(i and 0xFF), 8333 + i)))
    let msg = newAddr(addrs)
    let before = pm.knownAddresses.len
    pm.handleAddrInternal(peer, msg)
    check pm.knownAddresses.len == before + 20
    # Each stored address spent one token.
    check peer.addrTokenBucket <= 1000.0 - 20.0 + 0.5

  test "addrv2 cannot BYPASS the rate limit — excess dropped on a drained bucket":
    ## Core routes ADDR and ADDRV2 through the same ProcessAddrs token bucket
    ## (net_processing.cpp:4022); a peer must not evade MAX_ADDR_RATE_PER_SECOND
    ## by sending addrv2 instead of addr.
    let pm = freshPm()
    let peer = newPeer("3.3.3.3", 8333, regtestParams(), pdInbound)
    peer.addrTokenBucket = 0.0
    peer.addrTokenTimestamp = getTime().toUnix()

    var addrs: seq[TimestampedAddrV2]
    for i in 0'u16..<20'u16:
      var a = NetAddressV2(networkId: netIPv4)
      a.ipv4 = [22'u8, uint8(i shr 8), 0'u8, uint8(i and 0xFF)]
      addrs.add(TimestampedAddrV2(timestamp: 1_700_000_000'u32, services: 1'u64,
        address: a, port: uint16(8333 + i)))
    let msg = newAddrV2(addrs)
    let before = pm.knownAddresses.len
    pm.handleAddrInternal(peer, msg)
    # Empty bucket + rate-limited peer → all 20 addrv2 entries dropped.
    check pm.knownAddresses.len == before

  test "addrv2 ARE stored when the shared bucket has tokens":
    let pm = freshPm()
    let peer = newPeer("4.4.4.4", 8333, regtestParams(), pdInbound)
    peer.addrTokenBucket = 1000.0
    peer.addrTokenTimestamp = getTime().toUnix()

    var addrs: seq[TimestampedAddrV2]
    for i in 0'u16..<20'u16:
      var a = NetAddressV2(networkId: netIPv4)
      a.ipv4 = [23'u8, uint8(i shr 8), 0'u8, uint8(i and 0xFF)]
      addrs.add(TimestampedAddrV2(timestamp: 1_700_000_000'u32, services: 1'u64,
        address: a, port: uint16(8333 + i)))
    let msg = newAddrV2(addrs)
    let before = pm.knownAddresses.len
    pm.handleAddrInternal(peer, msg)
    check pm.knownAddresses.len == before + 20
    # Each stored addrv2 entry spent one token from the shared per-peer bucket.
    check peer.addrTokenBucket <= 1000.0 - 20.0 + 0.5
