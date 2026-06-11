## W168: advertised service-flags bitset for a full node.
##
## Regression for the service-flags campaign (2026-06-11): NODE_NETWORK_LIMITED
## must be advertised UNCONDITIONALLY by a full node (it was wrongly gated on
## prune mode), and NODE_P2P_V2 must be advertised because nimrod's inbound
## BIP-324 v2 responder runs default-on (honest, matching Core).
##
## Core full-node baseline (non-pruned, v2-transport-on) = 0xC09:
##   NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400) |
##   NODE_P2P_V2(0x800).
## Reference: bitcoin-core/src/init.cpp:863 and 987-990.

import std/os
import unittest2
import ../src/network/peer
import ../src/network/messages

suite "W168 advertised service flags":
  # advertisedServices() is env-driven only (compact-filters knob); ensure the
  # full-node baseline is computed with no optional knobs set.
  setup:
    delEnv("NIMROD_PEER_BLOCK_FILTERS")
    delEnv("NIMROD_BLOCK_FILTER_INDEX")
    delEnv("NIMROD_BIP324_V2_OUTBOUND")

  test "service constants have correct bit values":
    check NodeNetwork == 0x1'u64
    check NodeWitness == 0x8'u64
    check NodeNetworkLimited == 0x400'u64
    check NodeP2pV2 == 0x800'u64

  test "full-node baseline advertises exactly 0xC09":
    let svc = advertisedServices()
    check svc == 0xC09'u64

  test "NODE_NETWORK_LIMITED advertised UNCONDITIONALLY (not prune-gated)":
    # Prune state must NOT affect the advertised limited bit. Toggle the prune
    # advertise flag both ways and assert NODE_NETWORK_LIMITED stays set.
    setPruneModeAdvertise(false)
    check (advertisedServices() and NodeNetworkLimited) != 0
    setPruneModeAdvertise(true)
    check (advertisedServices() and NodeNetworkLimited) != 0
    # restore the default the rest of the suite expects
    setPruneModeAdvertise(false)

  test "NODE_NETWORK and NODE_WITNESS set for a full node":
    let svc = advertisedServices()
    check (svc and NodeNetwork) != 0
    check (svc and NodeWitness) != 0

  test "NODE_P2P_V2 advertised (inbound v2 responder is default-on)":
    check (advertisedServices() and NodeP2pV2) != 0

  test "NODE_BLOOM never advertised (no CBloomFilter impl)":
    check (advertisedServices() and NodeBloom) == 0
