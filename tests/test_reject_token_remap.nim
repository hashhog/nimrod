## Reject-reason token parity — testmempoolaccept missing-inputs remap.
##
## Class 6 of the 2026-07-08 reason-code parity pass: Bitcoin Core remaps
## TX_MISSING_INPUTS to the bare token "missing-inputs" on the testmempoolaccept
## RPC path only (rpc/mempool.cpp:399-400), while every other reject reason is
## surfaced verbatim via state.GetRejectReason().  nimrod's internal mempool
## token for this case is "bad-txns-inputs-missingorspent[: <detail>]"; the RPC
## layer must translate it.  testAcceptRejectReason implements that translation.

import unittest2
import ../src/rpc/server

suite "testmempoolaccept reject-reason remap (class 6)":
  test "bad-txns-inputs-missingorspent -> missing-inputs":
    check testAcceptRejectReason("bad-txns-inputs-missingorspent") == "missing-inputs"

  test "bad-txns-inputs-missingorspent with detail suffix -> missing-inputs":
    check testAcceptRejectReason(
      "bad-txns-inputs-missingorspent: 00ff00ff") == "missing-inputs"
    check testAcceptRejectReason(
      "bad-txns-inputs-missingorspent: bad vout 3 for mempool parent") ==
      "missing-inputs"

  test "other bare tokens pass through unchanged":
    check testAcceptRejectReason("bad-txns-vin-empty") == "bad-txns-vin-empty"
    check testAcceptRejectReason("tx-size") == "tx-size"
    check testAcceptRejectReason("version") == "version"
    check testAcceptRejectReason("min relay fee not met") == "min relay fee not met"
    check testAcceptRejectReason("bad-txns-in-belowout") == "bad-txns-in-belowout"

when isMainModule:
  discard
