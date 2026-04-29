## Tests for peer connection module
## Unit tests for peer creation, IPv4 mapping, and state management

import std/os
import unittest2
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params

suite "peer creation":
  test "newPeer creates peer with correct initial state":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params, pdOutbound)

    check peer.address == "127.0.0.1"
    check peer.port == 18444
    check peer.state == psDisconnected
    check peer.direction == pdOutbound
    check peer.networkMagic == params.magic
    check peer.handshakeComplete == false
    check peer.closing == false

  test "newPeer inbound direction":
    let params = regtestParams()
    let peer = newPeer("192.168.1.1", 8333, params, pdInbound)

    check peer.direction == pdInbound

  test "peer string representation":
    let params = mainnetParams()
    let peer = newPeer("10.0.0.1", 8333, params)

    check $peer == "10.0.0.1:8333"

suite "peer state":
  test "isConnected returns false when disconnected":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params)

    check peer.isConnected() == false

  test "isConnected returns false when transport is nil":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params)
    peer.state = psConnected

    check peer.isConnected() == false  # No transport

suite "IPv4 mapped addresses":
  test "ipv4ToMapped creates correct IPv6 format":
    let ipv4: array[4, byte] = [192'u8, 168, 1, 1]
    let mapped = ipv4ToMapped(ipv4)

    # First 10 bytes should be zero
    for i in 0 ..< 10:
      check mapped[i] == 0

    # Bytes 10-11 should be 0xFF
    check mapped[10] == 0xFF
    check mapped[11] == 0xFF

    # Last 4 bytes are the IPv4 address
    check mapped[12] == 192
    check mapped[13] == 168
    check mapped[14] == 1
    check mapped[15] == 1

  test "ipv4ToMapped localhost":
    let ipv4: array[4, byte] = [127'u8, 0, 0, 1]
    let mapped = ipv4ToMapped(ipv4)

    check mapped[12] == 127
    check mapped[13] == 0
    check mapped[14] == 0
    check mapped[15] == 1

  test "isIPv4Mapped detects mapped addresses":
    let mapped: array[16, byte] = [
      0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0xFF, 0xFF,
      192, 168, 1, 1
    ]
    check isIPv4Mapped(mapped) == true

  test "isIPv4Mapped rejects pure IPv6":
    let ipv6: array[16, byte] = [
      0x20'u8, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
      0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
    ]
    check isIPv4Mapped(ipv6) == false

  test "isIPv4Mapped rejects incorrect prefix":
    var badMapped: array[16, byte] = [
      0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0xFF, 0xFE,  # Wrong prefix
      192, 168, 1, 1
    ]
    check isIPv4Mapped(badMapped) == false

  test "extractIPv4 extracts address correctly":
    let mapped: array[16, byte] = [
      0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0xFF, 0xFF,
      10, 0, 0, 1
    ]
    let ipv4 = extractIPv4(mapped)

    check ipv4[0] == 10
    check ipv4[1] == 0
    check ipv4[2] == 0
    check ipv4[3] == 1

  test "ipv4ToMapped and extractIPv4 round-trip":
    let original: array[4, byte] = [172'u8, 16, 0, 100]
    let mapped = ipv4ToMapped(original)
    let extracted = extractIPv4(mapped)

    check extracted == original

suite "network magic":
  test "mainnet magic matches":
    let params = mainnetParams()
    let peer = newPeer("127.0.0.1", 8333, params)

    check peer.networkMagic == [0xF9'u8, 0xBE, 0xB4, 0xD9]

  test "testnet3 magic matches":
    let params = testnet3Params()
    let peer = newPeer("127.0.0.1", 18333, params)

    check peer.networkMagic == [0x0B'u8, 0x11, 0x09, 0x07]

  test "regtest magic matches":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params)

    check peer.networkMagic == [0xFA'u8, 0xBF, 0xB5, 0xDA]

suite "peer feature flags":
  test "initial feature flags are false":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params)

    check peer.sendHeaders == false
    check peer.wtxidRelay == false
    check peer.handshakeComplete == false

  test "feeFilterRate defaults to zero":
    let params = regtestParams()
    let peer = newPeer("127.0.0.1", 18444, params)

    check peer.feeFilterRate == 0

suite "NODE_BLOOM advertisement gate (BIP-35)":
  # Mirrors bitcoin-core/src/net_processing.cpp:4852-4863:
  #   if (!(peer.m_our_services & NODE_BLOOM) && !HasPermission(Mempool))
  #     drop + disconnect (unless NoBan).
  # We have no per-peer permission system, so the local advertisement
  # flag IS the gate.  Default (no env var) must be OFF, matching
  # DEFAULT_PEERBLOOMFILTERS = false in net_processing.h:44.
  test "default (env unset) is OFF":
    delEnv("NIMROD_PEER_BLOOM_FILTERS")
    check peerBloomFiltersEnabled() == false

  test "explicit '0' is OFF":
    putEnv("NIMROD_PEER_BLOOM_FILTERS", "0")
    check peerBloomFiltersEnabled() == false
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "'false' / 'no' / 'off' are OFF":
    for v in ["false", "no", "off", "garbage", ""]:
      putEnv("NIMROD_PEER_BLOOM_FILTERS", v)
      check peerBloomFiltersEnabled() == false
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "'1' / 'true' / 'yes' / 'on' are ON":
    for v in ["1", "true", "yes", "on", "TRUE", "On"]:
      putEnv("NIMROD_PEER_BLOOM_FILTERS", v)
      check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

when isMainModule:
  echo "Running peer tests..."
