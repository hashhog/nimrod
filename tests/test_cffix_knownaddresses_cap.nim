## test_cffix_knownaddresses_cap.nim
##
## cffix-nimrod-knownaddresses-cap
## (fingerprint nimrod:peermanager:knownAddresses-unbounded-linear-dedup)
##
## Before the fix:
##   - every new Peer started with a FULL 1000-token addr bucket
##     (peer.nim newPeer), so connect / send 1000 addrs / reconnect let one
##     host push 1000 addresses per connection, without limit;
##   - handleAddrInternal appended each accepted address to the flat
##     pm.knownAddresses / pm.knownAddressesV2 seqs after an O(n) linear
##     duplicate scan, and nothing ever trimmed those seqs.
##
## Core:
##   - Peer::m_addr_token_bucket starts at 1.0 (net_processing.cpp:380) and
##     gains MAX_ADDR_TO_SEND (1000) only when WE send that peer a getaddr,
##     which Core does once per connection (net_processing.cpp:3762-3767);
##   - accepted addresses go into AddrMan's fixed-size tables with hashed
##     lookup, so the store is bounded and a duplicate check is O(1).
##
## The `when declared(...)` guards keep this file compiling on master, where
## MaxKnownAddresses and noteGetAddrSent do not exist, so every test there
## fails on its assertion, by name.

import unittest2
import std/[sets, times]
import ../src/network/messages
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params

# The documented cap on each flat store.  On master there is no cap, so the
# fallback is the value the fix documents; the assertions then fail there.
const Cap =
  when declared(MaxKnownAddresses): MaxKnownAddresses
  else: 16384

proc ipv4Mapped(a, b, c, d: byte): array[16, byte] =
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc uniqueAddrs(batch, n: int): seq[TimestampedAddr] =
  ## n unique routable IPv4 addresses for batch `batch` (1.x.y.z with
  ## x = batch, so batches never overlap).
  let ts = uint32(getTime().toUnix())
  for i in 0 ..< n:
    var na = NetAddress()
    na.ip = ipv4Mapped(1'u8, byte(batch), byte(i shr 8), byte(i and 0xFF))
    na.port = 8333
    result.add(TimestampedAddr(timestamp: ts, address: na))

proc uniqueTorAddrs(batch, n: int): seq[TimestampedAddrV2] =
  let ts = uint32(getTime().toUnix())
  for i in 0 ..< n:
    var a = NetAddressV2(networkId: netTorV3)
    a.torv3[0] = byte(batch)
    a.torv3[1] = byte(i shr 8)
    a.torv3[2] = byte(i and 0xFF)
    a.torv3[31] = 0x5A
    result.add(TimestampedAddrV2(timestamp: ts, services: 1'u64,
                                 address: a, port: 8333))

proc freshInbound(i: int): Peer =
  newPeer("203.0.113." & $(i mod 250), uint16(40000 + i), mainnetParams(),
          pdInbound)

proc newPm(): PeerManager =
  newPeerManager(regtestParams(), dataDir = "/tmp")

proc noDuplicates(pm: PeerManager): bool =
  var seen = initHashSet[(array[16, byte], uint16)]()
  for na in pm.knownAddresses:
    if (na.ip, na.port) in seen: return false
    seen.incl((na.ip, na.port))
  true

suite "cffix knownAddresses cap (Core m_addr_token_bucket + bounded AddrMan)":

  test "a fresh inbound peer that was not sent getaddr starts with 1 addr token":
    ## Core net_processing.cpp:380 m_addr_token_bucket{1.0}.  master: 1000.
    let peer = freshInbound(1)
    check peer.addrTokenBucket == 1.0

  test "20 fresh peers x 1000 unsolicited addrs store one address each, under the cap":
    ## The item's repro.  master stores all 20,000.
    let pm = newPm()
    for p in 0 ..< 20:
      let peer = freshInbound(p)
      pm.handleAddrInternal(peer, newAddr(uniqueAddrs(p, 1000)))
    check pm.knownAddresses.len <= Cap
    # One token per fresh, unsolicited peer (no refill: first message).
    check pm.knownAddresses.len == 20

  test "the flat legacy store never exceeds MaxKnownAddresses, whatever the token supply":
    ## Bypass the rate limit (a peer with a huge bucket, like a NoBan peer) so
    ## the store cap alone is what bounds the seq.  master: 20,000.
    let pm = newPm()
    for p in 0 ..< 20:
      let peer = freshInbound(p)
      peer.addrTokenBucket = 1_000_000.0
      pm.handleAddrInternal(peer, newAddr(uniqueAddrs(p, 1000)))
    check pm.knownAddresses.len <= Cap
    check pm.knownAddresses.len == min(20_000, Cap)
    check pm.noDuplicates()

  test "the flat addrv2 (Tor/I2P/CJDNS) store never exceeds MaxKnownAddresses":
    let pm = newPm()
    for p in 0 ..< 20:
      let peer = freshInbound(p)
      peer.addrTokenBucket = 1_000_000.0
      pm.handleAddrInternal(peer, newAddrV2(uniqueTorAddrs(p, 1000)))
    check pm.knownAddressesV2.len <= Cap
    check pm.knownAddressesV2.len == min(20_000, Cap)

  test "a full store still deduplicates: a known address is not stored twice":
    let pm = newPm()
    for p in 0 ..< 20:
      let peer = freshInbound(p)
      peer.addrTokenBucket = 1_000_000.0
      pm.handleAddrInternal(peer, newAddr(uniqueAddrs(p, 1000)))
    let before = pm.knownAddresses.len
    # Re-send an address that is certainly still stored.
    let again = freshInbound(99)
    again.addrTokenBucket = 1_000_000.0
    let known = pm.knownAddresses[0]
    pm.handleAddrInternal(again, newAddr(@[TimestampedAddr(
      timestamp: uint32(getTime().toUnix()), address: known)]))
    check pm.knownAddresses.len == before
    check pm.noDuplicates()

  test "addrv2 duplicates of a Tor address are stored once":
    let pm = newPm()
    let peer = freshInbound(7)
    peer.addrTokenBucket = 1_000_000.0
    let batch = uniqueTorAddrs(3, 10)
    pm.handleAddrInternal(peer, newAddrV2(batch))
    pm.handleAddrInternal(peer, newAddrV2(batch))
    check pm.knownAddressesV2.len == 10

  test "sending getaddr adds MaxAddrToSend tokens, once per connection":
    ## Core net_processing.cpp:3762-3767: m_addr_token_bucket += MAX_ADDR_TO_SEND
    ## when we send the (one-time) getaddr.
    let pm = newPm()
    let peer = newPeer("198.51.100.7", 8333'u16, mainnetParams(), pdOutbound)
    when declared(noteGetAddrSent):
      pm.noteGetAddrSent(peer)
      pm.noteGetAddrSent(peer)   # the periodic re-send must not top up again
    check peer.addrTokenBucket == 1.0 + 1000.0
    # The solicited reply is processed in full.
    pm.handleAddrInternal(peer, newAddr(uniqueAddrs(5, 1000)))
    check pm.knownAddresses.len == 1000
