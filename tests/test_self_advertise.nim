## test_self_advertise.nim
##
## Self-address advertisement (Bitcoin Core parity):
##   - routable filter + --externalip parsing       (net.cpp AddLocal)
##   - discovery from an outbound peer's addr_recv   (IsPeerAddrLocalGood/SeenLocal)
##   - addr / addrv2 contents incl. the LISTEN port  (MaybeSendAddr)
##   - the IBD gate, block-relay-only/feeler gate, the Poisson timer
##   - VERSION addr_from no longer carries the chain-default port
##
## Reference: bitcoin-core/src/net.cpp:240-268 (GetLocalAddrForPeer),
##            bitcoin-core/src/net_processing.cpp:5445-5479 (MaybeSendAddr).

import unittest2
import std/[options, os, times]
import ../src/network/messages
import ../src/network/peermanager
import ../src/network/peer
import ../src/primitives/serialize
import ../src/consensus/params

const ListenPort = 39777'u16

proc ip4(a, b, c, d: byte): array[16, byte] =
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

var tmpSeq = 0
proc freshPm(): PeerManager =
  inc tmpSeq
  let dir = getTempDir() / ("nimrod-selfadv-test-" & $getCurrentProcessId() &
                            "-" & $tmpSeq)
  createDir(dir)
  result = newPeerManager(regtestParams(), dataDir = dir)
  result.listenEnabled = true
  result.listenPort = ListenPort

proc cleanupPm(pm: PeerManager) =
  try: removeDir(pm.dataDir) except CatchableError: discard

proc readyPeer(address: string, dir: PeerDirection,
               seenUs: array[16, byte] = default(array[16, byte]),
               seenPort: uint16 = 0): Peer =
  result = newPeer(address, 8333'u16, regtestParams(), dir)
  result.state = psReady
  result.addrLocal = NetAddress(ip: seenUs, port: seenPort)

let now = getTime().toUnix()

suite "self-advertise: routable filter + --externalip parsing":
  test "private / loopback / documentation / unspecified are not routable":
    check not isRoutable16(ip4(10, 0, 0, 1))
    check not isRoutable16(ip4(192, 168, 1, 128))
    check not isRoutable16(ip4(172, 16, 0, 1))
    check not isRoutable16(ip4(127, 0, 0, 1))
    check not isRoutable16(ip4(100, 64, 0, 1))      # CGNAT RFC6598
    check not isRoutable16(ip4(203, 0, 113, 5))     # RFC5737
    check not isRoutable16(ip4(0, 0, 0, 0))
    check not isRoutable16(default(array[16, byte]))  # ::
    check isRoutable16(ip4(1, 2, 3, 4))
    check isRoutable16(ip4(76, 38, 7, 169))

  test "externalip parse: bare IP = port 0 (listen port), ip:port, [v6]:port":
    let a = parseExternalIP("1.2.3.4")
    check a.isSome and a.get.ip == ip4(1, 2, 3, 4) and a.get.port == 0
    let b = parseExternalIP("1.2.3.4:8337")
    check b.isSome and b.get.port == 8337
    let c = parseExternalIP("[2001:470::1]:8337")
    check c.isSome and c.get.port == 8337 and c.get.ip[0] == 0x20
    let d = parseExternalIP("2001:470::1")
    check d.isSome and d.get.port == 0
    check parseExternalIP("not-an-ip").isNone
    check parseExternalIP("1.2.3.4:0").isNone
    check parseExternalIP("1.2.3.4:70000").isNone
    check parseExternalIP("").isNone

  test "addExternalIP refuses non-routable, stores manual score 4":
    let pm = freshPm()
    check not pm.addExternalIP("192.168.1.128")
    check pm.addExternalIP("1.2.3.4")
    let rows = pm.localAddresses()
    check rows.len == 1
    check ip16ToString(rows[0].ip) == "1.2.3.4"
    check rows[0].port == ListenPort          # bare IP resolved to LISTEN port
    check rows[0].score == LocalManual
    cleanupPm(pm)

suite "self-advertise: discovery from addr_recv":
  test "outbound routable peer + routable addr_recv -> entry at LISTEN port":
    let pm = freshPm()
    let p = readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169), 51234)
    pm.noteVersionAddrRecv(p, now)
    let rows = pm.localAddresses()
    check rows.len == 1
    check ip16ToString(rows[0].ip) == "76.38.7.169"
    check rows[0].port == ListenPort          # NOT the peer-observed 51234
    check rows[0].score == 1
    cleanupPm(pm)

  test "score = distinct netgroups; same /16 twice counts once; needs 2 to be advertised":
    let pm = freshPm()
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169)), now)
    pm.noteVersionAddrRecv(readyPeer("8.8.4.4", pdOutbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses()[0].score == 1
    # a third peer that does not report anything useful: no addr known yet for it
    let q = readyPeer("9.9.9.9", pdOutbound)
    check pm.localAddrForPeer(q, now).isNone   # score 1 < MinDiscoveredLocalScore
    pm.noteVersionAddrRecv(readyPeer("1.1.1.1", pdOutbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses()[0].score == 2
    let chosen = pm.localAddrForPeer(q, now)
    check chosen.isSome
    check chosen.get.ip == ip4(76, 38, 7, 169) and chosen.get.port == ListenPort
    cleanupPm(pm)

  test "ignored: non-routable peer, non-routable addr_recv, --discover off, not listening":
    let pm = freshPm()
    pm.noteVersionAddrRecv(readyPeer("10.0.0.5", pdOutbound, ip4(76, 38, 7, 169)), now)
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(192, 168, 1, 128)), now)
    check pm.localAddresses().len == 0
    pm.discover = false
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses().len == 0
    pm.discover = true
    pm.listenEnabled = false
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses().len == 0
    cleanupPm(pm)

  test "inbound peers only score an existing entry (SeenLocal)":
    let pm = freshPm()
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdInbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses().len == 0
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169)), now)
    pm.noteVersionAddrRecv(readyPeer("1.1.1.1", pdInbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddresses()[0].score == 2
    cleanupPm(pm)

  test "discovered entries expire after 3h; manual entries do not":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169)), now)
    check pm.localAddrs.list(now).len == 2
    check pm.localAddrs.list(now + DiscoveredLocalAddrTTLSec + 1).len == 1
    cleanupPm(pm)

  test "discovered entries capped at 8":
    let pm = freshPm()
    for i in 0 ..< 20:
      pm.noteVersionAddrRecv(readyPeer("8.8.8.8", pdOutbound,
                                       ip4(76, 38, 7, byte(10 + i))), now + i)
    check pm.localAddresses().len == MaxDiscoveredLocalAddrs
    cleanupPm(pm)

suite "self-advertise: addr / addrv2 message contents":
  test "legacy addr: one entry, our IP, LISTEN port, advertised services, time now":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    let p = readyPeer("8.8.8.8", pdOutbound)
    let m = pm.prepareLocalAddrMsg(p, pctFullRelay, now)
    check m.isSome
    check m.get.kind == mkAddr
    # Round-trip through the wire codec: what a peer actually parses.
    let wire = deserializePayload("addr", serializePayload(m.get))
    check wire.addresses.len == 1
    let a = wire.addresses[0]
    check a.address.ip == ip4(1, 2, 3, 4)
    check a.address.port == ListenPort
    check a.address.services == advertisedServices()
    check a.timestamp == uint32(now)
    cleanupPm(pm)

  test "addrv2 when the peer sent sendaddrv2":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    let p = readyPeer("8.8.8.8", pdOutbound)
    p.wantsAddrV2 = true
    let m = pm.prepareLocalAddrMsg(p, pctFullRelay, now)
    check m.isSome and m.get.kind == mkAddrV2
    let wire = deserializePayload("addrv2", serializePayload(m.get))
    check wire.addressesV2.len == 1
    let a = wire.addressesV2[0]
    check a.address.networkId == netIPv4
    check a.address.ipv4 == [1'u8, 2, 3, 4]
    check a.port == ListenPort
    check a.services == advertisedServices()
    check a.timestamp == uint32(now)
    cleanupPm(pm)

  test "explicit --externalip port wins over listen port":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4:8337")
    let m = pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdOutbound), pctFullRelay, now)
    check m.isSome and m.get.addresses[0].address.port == 8337
    cleanupPm(pm)

  test "GetLocalAddrForPeer: nothing known -> peer's view; outbound keeps LISTEN port, inbound takes its port":
    let pm = freshPm()
    let o = readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169), 51234)
    let co = pm.localAddrForPeer(o, now)
    check co.isSome and co.get.ip == ip4(76, 38, 7, 169) and co.get.port == ListenPort
    let i = readyPeer("8.8.8.8", pdInbound, ip4(76, 38, 7, 169), 8337)
    let ci = pm.localAddrForPeer(i, now)
    check ci.isSome and ci.get.port == 8337
    cleanupPm(pm)

  test "GetLocalAddrForPeer: manual entry vs peer view uses the 1/2 coin":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    let o = readyPeer("8.8.8.8", pdOutbound, ip4(76, 38, 7, 169), 51234)
    var seenBits = -1
    let heads = pm.localAddrForPeer(o, now, proc(bits: int): bool =
      seenBits = bits
      true)
    check seenBits == 1                       # score 4 is not > LOCAL_MANUAL
    check heads.get.ip == ip4(76, 38, 7, 169)
    let tails = pm.localAddrForPeer(o, now, proc(bits: int): bool = false)
    check tails.get.ip == ip4(1, 2, 3, 4)
    cleanupPm(pm)

suite "self-advertise: gates and timer":
  test "IBD suppresses the send and leaves the first-send slot untouched":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    var ibd = true
    pm.isIbd = proc(): bool {.gcsafe, raises: [].} = ibd
    let p = readyPeer("8.8.8.8", pdOutbound)
    check pm.prepareLocalAddrMsg(p, pctFullRelay, now).isNone
    check p.nextLocalAddrSend == 0            # still "never sent"
    ibd = false
    check pm.prepareLocalAddrMsg(p, pctFullRelay, now + 60).isSome
    check p.nextLocalAddrSend > now + 60
    cleanupPm(pm)

  test "never to block-relay-only or feeler; not when not listening":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    check pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdOutbound), pctBlockRelayOnly, now).isNone
    check pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdOutbound), pctFeeler, now).isNone
    check pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdInbound), pctInbound, now).isSome
    check pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdOutbound), pctManual, now).isSome
    pm.listenEnabled = false
    check pm.prepareLocalAddrMsg(readyPeer("8.8.8.8", pdOutbound), pctFullRelay, now).isNone
    cleanupPm(pm)

  test "not re-sent before the Poisson deadline; re-sent after it":
    let pm = freshPm()
    check pm.addExternalIP("1.2.3.4")
    let p = readyPeer("8.8.8.8", pdOutbound)
    check pm.prepareLocalAddrMsg(p, pctFullRelay, now).isSome
    let deadline = p.nextLocalAddrSend
    check pm.prepareLocalAddrMsg(p, pctFullRelay, deadline - 1).isNone
    check pm.prepareLocalAddrMsg(p, pctFullRelay, deadline).isSome
    cleanupPm(pm)

  test "Poisson delay has a ~24h mean":
    var total = 0.0
    const N = 4000
    for _ in 0 ..< N:
      total += float(nextLocalAddrDelaySec())
    let mean = total / float(N)
    check mean > 0.85 * float(AvgLocalAddressBroadcastIntervalSec)
    check mean < 1.15 * float(AvgLocalAddressBroadcastIntervalSec)

  test "no usable address -> nothing sent (but the timer is armed)":
    let pm = freshPm()
    let p = readyPeer("8.8.8.8", pdOutbound)
    check pm.prepareLocalAddrMsg(p, pctFullRelay, now).isNone
    check p.nextLocalAddrSend != 0
    cleanupPm(pm)

suite "self-advertise: VERSION addr_from":
  test "sendVersion addr_from is empty (Core CService{}), not the chain-default port":
    # mainnet params: pre-fix addr_from.port was params.p2pPort = 8333 no
    # matter what --port was.  buildVersionMsg is what sendVersion sends.
    let p = newPeer("8.8.8.8", 8333'u16, mainnetParams(), pdOutbound)
    let v = p.buildVersionMsg(0).version
    check v.addrFrom.port == 0
    check v.addrFrom.ip == default(array[16, byte])
    check v.addrFrom.services == advertisedServices()
    let pm = freshPm()
    check pm.localVersion.addrFrom.port == 0
    cleanupPm(pm)
