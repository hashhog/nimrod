## test_cffix_addr_relay_received.nim
##
## cffix-nimrod-addr-relay-received
## (fingerprint nimrod:peermanager:addr-relay-and-getaddr-serve-insertion-prefix-with-fresh-timestamps)
##
## Before the fix:
##   - relayAddresses sent knownAddresses[0..10) stamped with epochTime()
##     whenever an addr/addrv2 message of 1-10 entries arrived, whatever that
##     message held and even when none of its entries was accepted (rate
##     limited, unroutable, stale);
##   - buildGetAddrResponse answered with the same insertion-order prefix of
##     knownAddresses, every entry stamped "now";
##   - the legacy addr path stored non-routable addresses (10/8, 192.168/16...).
##
## Core:
##   - ProcessAddrs (net_processing.cpp:5625-5700) relays EACH received address
##     that passed the token bucket, is routable and is recent
##     (nTime > now - 10 min), in a message of <= 10 entries, via RelayAddress
##     (:2277) to up to 2 peers that can carry it (IsAddrCompatible), with the
##     address's own nTime;
##   - ProcessAddrs skips (neither stores nor relays) an address whose services
##     have neither NODE_NETWORK nor NODE_NETWORK_LIMITED (:5672-5673);
##   - GETADDR (:4815-4848) answers with GetAddresses: a random addrman sample
##     carrying each address's stored nTime, cached per network for
##     21 h + rand(6 h) (net.cpp:3702-3738);
##   - AddrMan::AddSingle drops a non-routable address, so it is never stored.
##
## The relays are read off real loopback sockets, so this file runs the same
## code path on master and on the fix.  The one field the fix adds
## (PeerManager.getAddrCache) is touched only under `when compiles(...)`.

import unittest2
import std/[os, sets, tables, times, options, strutils]
import chronos
import ../src/network/messages
import ../src/network/addr
import ../src/network/peermanager
import ../src/network/peer
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc ip4(a, b, c, d: byte): array[16, byte] =
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc freshPm(tag: string): (PeerManager, string) =
  let dir = getTempDir() / ("nimrod_cffix_addr_relay_" & tag & "_" &
    $getCurrentProcessId() & "_" & $epochTime())
  createDir(dir)
  (newPeerManager(regtestParams(), dataDir = dir), dir)

type Sink = object
  peer: Peer               # the PeerManager's view of the connection
  remote: StreamTransport  # the far end, where relayed bytes arrive
  inbox: ref seq[byte]     # bytes read off `remote` so far

var server {.threadvar.}: StreamServer

proc ensureServer() =
  if server.isNil:
    server = createStreamServer(initTAddress("127.0.0.1:0"), flags = {ReuseAddr})

proc pump(t: StreamTransport, inbox: ref seq[byte]) {.async.} =
  ## Copy everything that arrives on `t` into `inbox` until the socket closes.
  var buf = newSeq[byte](65536)
  try:
    while true:
      let n = await t.readOnce(addr buf[0], buf.len)
      if n == 0: break
      inbox[].add buf[0 ..< n]
  except CatchableError:
    discard

proc addSink(pm: PeerManager, host: string, wantsV2: bool): Sink =
  ## A ready peer in pm.peers backed by a real loopback TCP connection.
  ensureServer()
  let p = newPeer(host, 8333'u16, regtestParams(), pdOutbound)
  let acceptF = server.accept()
  p.transport = waitFor connect(server.localAddress())
  let remote = waitFor acceptF
  p.state = psReady
  p.wantsAddrV2 = wantsV2
  pm.peers[host & ":8333"] = p
  result = Sink(peer: p, remote: remote, inbox: new(seq[byte]))
  asyncSpawn pump(remote, result.inbox)

proc received(s: Sink): seq[P2PMessage] =
  ## Every complete P2P message sent to the sink since the last call.  Lets
  ## the spawned writers run until the socket has been quiet for 300 ms (at
  ## most 3 s), so a slow write under load is still seen.
  var quietMs = 0
  var waitedMs = 0
  var lastLen = s.inbox[].len
  while quietMs < 300 and waitedMs < 3000:
    waitFor sleepAsync(chronos.milliseconds(50))
    waitedMs += 50
    if s.inbox[].len != lastLen:
      lastLen = s.inbox[].len
      quietMs = 0
    else:
      quietMs += 50
  let data = s.inbox[]
  s.inbox[].setLen(0)
  var pos = 0
  while data.len - pos >= 24:
    var cmd = ""
    for i in 4 ..< 16:
      if data[pos + i] == 0: break
      cmd.add char(data[pos + i])
    let ln = int(data[pos + 16]) or (int(data[pos + 17]) shl 8) or
             (int(data[pos + 18]) shl 16) or (int(data[pos + 19]) shl 24)
    if data.len - pos - 24 < ln: break
    let payload = data[pos + 24 ..< pos + 24 + ln]
    result.add deserializePayload(cmd, payload)
    pos += 24 + ln

proc closeSink(s: Sink) =
  s.peer.transport.close()
  s.remote.close()

type Relayed = tuple[key: string, ts: uint32, kind: string]

proc keyOf(na: NetAddress): string =
  var s = ""
  for b in na.ip: s.add toHex(b)
  s & ":" & $na.port

proc keyOf(ta: TimestampedAddrV2): string =
  let legacy = toLegacyTimestampedAddr(ta)
  if legacy.isSome: return keyOf(legacy.get().address)
  $ta.address & ":" & $ta.port

proc relayedEntries(msgs: seq[P2PMessage]): seq[Relayed] =
  for m in msgs:
    case m.kind
    of mkAddr:
      for ta in m.addresses:
        result.add((keyOf(ta.address), ta.timestamp, "addr"))
    of mkAddrV2:
      for ta in m.addressesV2:
        result.add((keyOf(ta), ta.timestamp, "addrv2"))
    else: discard

proc seedA(pm: PeerManager, n: int, lastSeen: uint32) =
  ## A1..An straight into the store, all with an old lastSeen.
  for i in 1 .. n:
    pm.knownAddresses.add(NetAddress(services: 1'u64,
      ip: ip4(44, 0, 0, byte(i)), port: 8333, lastSeen: lastSeen))

proc sourcePeer(tokens: float64): Peer =
  result = newPeer("45.0.0.1", 8333'u16, regtestParams(), pdInbound)
  result.addrTokenBucket = tokens
  result.addrTokenTimestamp = getTime().toUnix()   # no refill in the window

proc addrOf(a, b, c, d: byte; ts: uint32): TimestampedAddr =
  TimestampedAddr(timestamp: ts,
    address: NetAddress(services: 1'u64, ip: ip4(a, b, c, d), port: 8333))

# ---------------------------------------------------------------------------

suite "cffix addr relay: relay what was received, not the stored prefix":

  test "a 1-entry addr relays the received address B only, with B's own timestamp":
    let (pm, dir) = freshPm("b")
    let old = uint32(getTime().toUnix()) - 3'u32 * 24'u32 * 3600'u32
    pm.seedA(20, old)
    let s1 = pm.addSink("46.0.0.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.0.2", wantsV2 = false)
    discard s1.received(); discard s2.received()   # drain: nothing before B
    let bTs = uint32(getTime().toUnix()) - 60'u32
    let b = addrOf(47, 1, 2, 3, bTs)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    let r1 = relayedEntries(s1.received())
    let r2 = relayedEntries(s2.received())
    # Both candidate peers get exactly {B} (Core relays a reachable address
    # to 2 peers), carrying B's wire nTime, never A1..A10 stamped now.
    checkpoint "B = " & keyOf(b.address) & " ts=" & $bTs
    checkpoint "relayed to s1: " & $r1
    checkpoint "relayed to s2: " & $r2
    check r1 == @[(keyOf(b.address), bTs, "addr")]
    check r2 == @[(keyOf(b.address), bTs, "addr")]
    s1.closeSink(); s2.closeSink(); removeDir(dir)

  test "an addr whose only entry is rate-limited relays nothing":
    let (pm, dir) = freshPm("rl")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.1.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.1.2", wantsV2 = false)
    let b = addrOf(47, 1, 2, 4, uint32(getTime().toUnix()) - 60'u32)
    pm.handleAddrInternal(sourcePeer(0.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(s1.received()).len == 0
    check relayedEntries(s2.received()).len == 0
    s1.closeSink(); s2.closeSink(); removeDir(dir)

  test "a legacy addr 10.0.0.1 is not stored and not relayed":
    let (pm, dir) = freshPm("nr")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.2.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.2.2", wantsV2 = false)
    let priv = addrOf(10, 0, 0, 1, uint32(getTime().toUnix()) - 60'u32)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[priv]))
    var stored = false
    for ka in pm.knownAddresses:
      if ka.ip == priv.address.ip: stored = true
    check not stored
    check relayedEntries(s1.received()).len == 0
    check relayedEntries(s2.received()).len == 0
    s1.closeSink(); s2.closeSink(); removeDir(dir)

  test "an address older than 10 minutes is stored but not relayed":
    let (pm, dir) = freshPm("old")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.3.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.3.2", wantsV2 = false)
    let b = addrOf(47, 1, 2, 5, uint32(getTime().toUnix()) - 3600'u32)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    var stored = false
    for ka in pm.knownAddresses:
      if ka.ip == b.address.ip: stored = true
    check stored
    check relayedEntries(s1.received()).len == 0
    check relayedEntries(s2.received()).len == 0
    s1.closeSink(); s2.closeSink(); removeDir(dir)

  test "an address advertising neither NODE_NETWORK nor NODE_NETWORK_LIMITED is not relayed":
    ## Core ProcessAddrs skips it before relay (net_processing.cpp:5672-5673).
    let (pm, dir) = freshPm("svc")
    let s1 = pm.addSink("46.0.7.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.7.2", wantsV2 = false)
    var b = addrOf(47, 1, 2, 7, uint32(getTime().toUnix()) - 60'u32)
    b.address.services = 8'u64          # NODE_WITNESS only
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(s1.received()).len == 0
    check relayedEntries(s2.received()).len == 0
    # Control: the same address with NODE_NETWORK_LIMITED is relayed.
    b.address.services = 1024'u64 or 8'u64
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(s1.received()).len == 1
    check relayedEntries(s2.received()).len == 1
    s1.closeSink(); s2.closeSink(); removeDir(dir)

  test "a received address is never relayed to a block-relay-only peer":
    ## Core RelayAddress picks only peers with m_addr_relay_enabled, which
    ## SetupAddressRelay never sets for a block-relay-only connection
    ## (net_processing.cpp:2309, SetupAddressRelay).  Relaying there would
    ## let whoever sent the address spot our hidden block-relay links.
    let (pm, dir) = freshPm("bro")
    let full = pm.addSink("46.0.8.1", wantsV2 = false)
    let bro = pm.addSink("46.0.8.2", wantsV2 = false)
    pm.extendedPeers["46.0.8.2:8333"] = ExtendedPeer(peer: bro.peer,
      connType: pctBlockRelayOnly, connectedTime: getTime())
    for k in 0 ..< 5:
      let b = addrOf(47, 4, 0, byte(k + 1), uint32(getTime().toUnix()) - 60'u32)
      pm.handleAddrInternal(sourcePeer(1000.0),
        P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(full.received()).len == 5   # control: relay works
    check relayedEntries(bro.received()).len == 0
    full.closeSink(); bro.closeSink(); removeDir(dir)

  test "an address received from a block-relay-only peer is not relayed":
    ## Core ProcessAddrs returns at once for a peer without addr relay
    ## (SetupAddressRelay is false for block-relay-only, net_processing.cpp:
    ## 5630), "to prevent providing adversaries with the additional
    ## information of addr traffic to infer the link".
    let (pm, dir) = freshPm("brosrc")
    let full = pm.addSink("46.0.10.1", wantsV2 = false)
    let src = sourcePeer(1000.0)
    pm.extendedPeers[src.address & ":" & $src.port] = ExtendedPeer(peer: src,
      connType: pctBlockRelayOnly, connectedTime: getTime())
    let b = addrOf(47, 5, 0, 1, uint32(getTime().toUnix()) - 60'u32)
    pm.handleAddrInternal(src, P2PMessage(kind: mkAddr, addresses: @[b]))
    var v = NetAddressV2(networkId: netIPv4)
    v.ipv4 = [47'u8, 5, 0, 2]
    pm.handleAddrInternal(src, P2PMessage(kind: mkAddrV2, addressesV2: @[
      TimestampedAddrV2(timestamp: uint32(getTime().toUnix()) - 60'u32,
                        services: 1'u64, address: v, port: 8333)]))
    check relayedEntries(full.received()).len == 0
    # Control: the same address from a full-relay source is relayed.
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(full.received()).len == 1
    full.closeSink(); removeDir(dir)

  test "a peer still handshaking gets no addr relay":
    ## Core relays only to peers with addr relay set up, which happens in the
    ## VERSION/VERACK handling; a peer mid-handshake is not a target.
    let (pm, dir) = freshPm("hs")
    let ready = pm.addSink("46.0.11.1", wantsV2 = false)
    let hs = pm.addSink("46.0.11.2", wantsV2 = false)
    hs.peer.state = psHandshaking
    let b = addrOf(47, 6, 0, 1, uint32(getTime().toUnix()) - 60'u32)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[b]))
    check relayedEntries(ready.received()).len == 1   # control
    check relayedEntries(hs.received()).len == 0
    ready.closeSink(); hs.closeSink(); removeDir(dir)

  test "an empty addr relays nothing":
    let (pm, dir) = freshPm("empty")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.9.1", wantsV2 = false)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: @[]))
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddrV2, addressesV2: @[]))
    check relayedEntries(s1.received()).len == 0
    s1.closeSink(); removeDir(dir)

  test "an 11-entry addr relays nothing":
    let (pm, dir) = freshPm("eleven")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.4.1", wantsV2 = false)
    let nowTs = uint32(getTime().toUnix()) - 60'u32
    var addrs: seq[TimestampedAddr]
    for i in 1'u8 .. 11'u8:
      addrs.add addrOf(47, 2, 0, i, nowTs)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddr, addresses: addrs))
    check relayedEntries(s1.received()).len == 0
    s1.closeSink(); removeDir(dir)

  test "a 1-entry addrv2 Tor v3 address goes only to the addrv2 peer, with its own timestamp":
    let (pm, dir) = freshPm("tor")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let v2 = pm.addSink("46.0.5.1", wantsV2 = true)
    let v1 = pm.addSink("46.0.5.2", wantsV2 = false)
    let tTs = uint32(getTime().toUnix()) - 30'u32
    var a = NetAddressV2(networkId: netTorV3)
    for i in 0 ..< 32: a.torv3[i] = byte(i + 1)
    let t = TimestampedAddrV2(timestamp: tTs, services: 1'u64, address: a,
                              port: 8333)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddrV2, addressesV2: @[t]))
    check relayedEntries(v2.received()) == @[(keyOf(t), tTs, "addrv2")]
    # A Tor v3 address cannot be written in a legacy addr message (Core
    # IsAddrCompatible), so the legacy peer gets nothing at all.
    check relayedEntries(v1.received()).len == 0
    v2.closeSink(); v1.closeSink(); removeDir(dir)

  test "a 1-entry addrv2 IPv4 address reaches a legacy peer as addr {B}":
    let (pm, dir) = freshPm("v2ip")
    pm.seedA(20, uint32(getTime().toUnix()) - 86400'u32)
    let s1 = pm.addSink("46.0.6.1", wantsV2 = false)
    let s2 = pm.addSink("46.0.6.2", wantsV2 = true)
    let bTs = uint32(getTime().toUnix()) - 45'u32
    var a = NetAddressV2(networkId: netIPv4)
    a.ipv4 = [47'u8, 3, 3, 3]
    let b = TimestampedAddrV2(timestamp: bTs, services: 1'u64, address: a,
                              port: 8333)
    pm.handleAddrInternal(sourcePeer(1000.0),
      P2PMessage(kind: mkAddrV2, addressesV2: @[b]))
    check relayedEntries(s1.received()) == @[(keyOf(b), bTs, "addr")]
    check relayedEntries(s2.received()) == @[(keyOf(b), bTs, "addrv2")]
    s1.closeSink(); s2.closeSink(); removeDir(dir)

suite "cffix getaddr: random sample with stored timestamps":

  test "getaddr reply carries each address's stored timestamp, not now":
    let (pm, dir) = freshPm("gats")
    let base = uint32(getTime().toUnix()) - 10'u32 * 86400'u32
    var want: Table[string, uint32]
    for i in 0 ..< 100:
      let na = NetAddress(services: 1'u64, ip: ip4(48, 0, byte(i shr 8), byte(i)),
                          port: 8333, lastSeen: base + uint32(i) * 60'u32)
      pm.knownAddresses.add(na)
      want[keyOf(na)] = na.lastSeen
    let resp = pm.buildGetAddrResponse(
      newPeer("49.0.0.1", 8333'u16, regtestParams(), pdInbound))
    check resp.len == 23   # floor(23% of 100)
    var mismatched = 0
    for ta in resp:
      if want.getOrDefault(keyOf(ta.address), 0'u32) != ta.timestamp:
        inc mismatched
    check mismatched == 0
    removeDir(dir)

  test "getaddr reply is a random sample, not the insertion-order prefix":
    let (pm, dir) = freshPm("gasample")
    var prefix: HashSet[string]
    for i in 0 ..< 1000:
      let na = NetAddress(services: 1'u64,
        ip: ip4(50, 0, byte(i shr 8), byte(i and 0xFF)), port: 8333,
        lastSeen: uint32(getTime().toUnix()) - 86400'u32)
      pm.knownAddresses.add(na)
      if i < 230: prefix.incl keyOf(na)
    # cap = 23% of 1000 = 230.
    let resp = pm.buildGetAddrResponse(
      newPeer("51.0.0.1", 8333'u16, regtestParams(), pdInbound))
    check resp.len == 230
    var outsidePrefix = 0
    for ta in resp:
      if keyOf(ta.address) notin prefix: inc outsidePrefix
    # A uniform sample of 230 of 1000 puts ~177 of its entries outside the
    # first 230 (sd ~6); the prefix answer puts none there.
    check outsidePrefix > 100
    removeDir(dir)

  test "getaddr replies are cached per network, then redrawn when the cache expires":
    ## Core CConnman::GetAddresses (net.cpp:3702-3738): one reply per network
    ## for 21 h + rand(6 h), so reconnecting cannot scrape the whole store.
    let (pm, dir) = freshPm("gacache")
    for i in 0 ..< 1000:
      pm.knownAddresses.add(NetAddress(services: 1'u64,
        ip: ip4(52, 0, byte(i shr 8), byte(i and 0xFF)), port: 8333,
        lastSeen: uint32(getTime().toUnix()) - 86400'u32))
    proc keys(r: seq[TimestampedAddr]): seq[string] =
      for ta in r: result.add keyOf(ta.address)
    let r1 = pm.buildGetAddrResponse(
      newPeer("53.0.0.1", 8333'u16, regtestParams(), pdInbound))
    let r2 = pm.buildGetAddrResponse(
      newPeer("53.0.0.2", 8333'u16, regtestParams(), pdInbound))
    check r1.len == 230
    check keys(r2) == keys(r1)          # same network, inside the lifetime
    # Expire the cache (master has no cache; there the reply never changes).
    when compiles(pm.getAddrCache):
      for k, v in pm.getAddrCache.mpairs: v.expiry = 0
    let r3 = pm.buildGetAddrResponse(
      newPeer("53.0.0.3", 8333'u16, regtestParams(), pdInbound))
    check r3.len == 230
    check keys(r3) != keys(r1)          # redrawn
    removeDir(dir)

  test "a getaddr reply drawn from a near-empty store does not stick once the store fills":
    ## nimrod's knownAddresses starts empty on every boot (Core's addrman is
    ## loaded from peers.dat first).  An early getaddr must not freeze an empty
    ## or tiny reply for the cache lifetime.
    let (pm, dir) = freshPm("gaboot")
    let r0 = pm.buildGetAddrResponse(
      newPeer("54.0.0.1", 8333'u16, regtestParams(), pdInbound))
    check r0.len == 0                   # empty store, empty reply
    for i in 0 ..< 10:
      pm.knownAddresses.add(NetAddress(services: 1'u64,
        ip: ip4(55, 0, 0, byte(i)), port: 8333,
        lastSeen: uint32(getTime().toUnix()) - 86400'u32))
    let r1 = pm.buildGetAddrResponse(
      newPeer("54.0.0.2", 8333'u16, regtestParams(), pdInbound))
    check r1.len == 2                   # floor(23% of 10)
    for i in 0 ..< 1000:
      pm.knownAddresses.add(NetAddress(services: 1'u64,
        ip: ip4(56, 0, byte(i shr 8), byte(i and 0xFF)), port: 8333,
        lastSeen: uint32(getTime().toUnix()) - 86400'u32))
    let r2 = pm.buildGetAddrResponse(
      newPeer("54.0.0.3", 8333'u16, regtestParams(), pdInbound))
    check r2.len == 232                 # floor(23% of 1010), freshly drawn
    removeDir(dir)
