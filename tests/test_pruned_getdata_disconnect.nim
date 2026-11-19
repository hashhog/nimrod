## fix-pruned-nodes-advertise-network: a pruned (NODE_NETWORK_LIMITED-only)
## node must advertise without NODE_NETWORK and must DISCONNECT a peer that
## getdata's a block deeper than 288 + 2 below the tip (Core
## net_processing.cpp:2383-2391), not answer notfound.
##
##   nim c -r tests/test_pruned_getdata_disconnect.nim

import unittest2
import ../src/network/peer
import ../src/network/messages

suite "pruned node services + deep getdata":
  teardown:
    setPruneModeAdvertise(false)
    setFullHistoryAdvertise(true)

  test "pruned: version services lack NODE_NETWORK, include NODE_NETWORK_LIMITED":
    setPruneModeAdvertise(true)
    check (advertisedServices() and NodeNetwork) == 0
    check (advertisedServices() and NodeNetworkLimited) != 0

  test "non-pruned: keeps NODE_NETWORK":
    setPruneModeAdvertise(false)
    check (advertisedServices() and NodeNetwork) != 0

  test "pruned: block deeper than 290 below tip => disconnect":
    when declared(shouldDisconnectForLimitedBlockRequest):
      check shouldDisconnectForLimitedBlockRequest(false, 1000'i32, 709'i32)
      check shouldDisconnectForLimitedBlockRequest(false, 1000'i32, 0'i32)
    else:
      check false  # base: handler answers notfound, never disconnects

  test "pruned: block within 290 of tip => no disconnect (Core boundary)":
    when declared(shouldDisconnectForLimitedBlockRequest):
      check not shouldDisconnectForLimitedBlockRequest(false, 1000'i32, 710'i32)
      check not shouldDisconnectForLimitedBlockRequest(false, 1000'i32, 999'i32)
    else:
      check false

  test "non-pruned: deep request never disconnects":
    when declared(shouldDisconnectForLimitedBlockRequest):
      check not shouldDisconnectForLimitedBlockRequest(true, 1000'i32, 1'i32)
    else:
      check false
