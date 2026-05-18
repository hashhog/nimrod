## W136 — BIP-130 sendheaders / BIP-133 feefilter / BIP-339 wtxidrelay
## audit (30 gates, xfail regression guards).
##
## Audit type: discovery (NO production code change in W136).
##
## W136 catalogues the gap between Bitcoin Core's net_processing.cpp
## `MaybeSendSendHeaders`, `MaybeSendFeefilter`, `FeeFilterRounder`,
## the SendMessages BIP-130 announce-revert logic, and BIP-339 wtxid-
## relay negotiation, vs. nimrod's parallel pipelines:
##
##   - `src/network/peer.nim`        — Peer fields + performHandshake +
##                                     pre-verack feature loop +
##                                     handleMessage post-handshake arms.
##   - `src/network/peermanager.nim` — `selectBlockAnnouncement` /
##                                     `broadcastBlock` / `broadcastTx`.
##   - `src/network/relay.nim`       — RelayManager (DEAD MODULE),
##                                     FeeFilterRounder,
##                                     `maybeSendFeefilter`, `setIBD`,
##                                     `setMempoolMinFeeRate`,
##                                     `getCurrentFeefilterValue`.
##   - `src/network/messages.nim`    — mkSendHeaders / mkWtxidRelay /
##                                     mkFeeFilter codec.
##   - `src/network/bip324.nim`      — short-ID table for v2 transport.
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour with
## a `check` that pins the gap.  When a future FIX wave closes the gap,
## the test will fail loudly and the developer must flip the assertion
## (per W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
## W134 methodology).
##
## References:
##   bitcoin-core/src/net_processing.cpp
##     - 179-183  (AVG_FEEFILTER_BROADCAST_INTERVAL / MAX_FEEFILTER_CHANGE_DELAY)
##     - 283-321  (Peer::m_wtxid_relay / m_fee_filter_sent / m_fee_filter_received)
##     - 405-412  (m_sent_sendheaders / m_prefers_headers)
##     - 740-741  (MaybeSendSendHeaders decl)
##     - 3710-3712 (post-VERSION emit WTXIDRELAY)
##     - 3896-3899 (SENDHEADERS receiver)
##     - 3919-3939 (WTXIDRELAY receiver; pre-VERACK only)
##     - 5035-5045 (FEEFILTER receiver; MoneyRange check)
##     - 5519-5538 (MaybeSendSendHeaders: chainwork gate)
##     - 5540-5580 (MaybeSendFeefilter: ForceRelay/BlockOnly/ignore exemptions)
##     - 5838-5925 (SendMessages BIP-130 announce-revert; MAX_BLOCKS_TO_ANNOUNCE)
##   bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
##     (FeeFilterRounder::round)
##   bitcoin-core/src/node/protocol_version.h (SENDHEADERS_VERSION/...)
##   audit/w136_relay_flags.md — full gate table + per-BUG detail.

import unittest2
import std/[options, strutils, os]
import ../src/network/[peer, peermanager, relay, messages]
import ../src/primitives/types
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # bitcoin-core/src/node/protocol_version.h
  CORE_SENDHEADERS_VERSION       = 70012'u32
  CORE_FEEFILTER_VERSION         = 70013'u32
  CORE_SHORT_IDS_BLOCKS_VERSION  = 70014'u32
  CORE_WTXID_RELAY_VERSION       = 70016'u32
  # bitcoin-core/src/net_processing.cpp:179-183
  CORE_AVG_FEEFILTER_BROADCAST_INTERVAL_SEC = 600   # 10 min
  CORE_MAX_FEEFILTER_CHANGE_DELAY_SEC       = 300   # 5 min
  # bitcoin-core/src/net_processing.h
  CORE_MAX_BLOCKS_TO_ANNOUNCE = 8
  # bitcoin-core/src/protocol.h (NetMsgType strings)
  CORE_MSG_SENDHEADERS = "sendheaders"
  CORE_MSG_FEEFILTER   = "feefilter"
  CORE_MSG_WTXIDRELAY  = "wtxidrelay"
  # bitcoin-core/src/policy/fees/block_policy_estimator.h:326-331
  CORE_MAX_FILTER_FEERATE = 1.0e7    # 10^7 sat/kvB
  CORE_FEE_FILTER_SPACING = 1.1      # 10% bucket spacing
  # bitcoin-core/src/consensus/amount.h
  CORE_MAX_MONEY = 2_100_000_000_000_000'i64  # 21,000,000 * 100,000,000

# Read production source files once for source-level pinning.
let
  peerSrc        = readFile("src/network/peer.nim")
  peerMgrSrc     = readFile("src/network/peermanager.nim")
  relaySrc       = readFile("src/network/relay.nim")
  messagesSrc    = readFile("src/network/messages.nim")
  bip324Src      = readFile("src/network/bip324.nim")
  nimrodSrc      = readFile("src/nimrod.nim")
  syncSrc        = readFile("src/network/sync.nim")

# ---------------------------------------------------------------------------
# G1 — RelayManager is a DEAD MODULE (BUG-1, P0-NET)
# ---------------------------------------------------------------------------
suite "W136 G1 — RelayManager DEAD MODULE / feefilter never sent (BUG-1)":

  test "G1 BUG-1: newRelayManager has NO production call site":
    ## `relay.nim` defines `newRelayManager*` (line 179) but no module in
    ## src/ ever invokes it.  Therefore `maybeSendFeefilter`,
    ## `sendFeefilterToAllPeers`, `setIBD`, `setMempoolMinFeeRate`,
    ## `getCurrentFeefilterValue` are all unreachable from the wire.
    ## Net result: nimrod NEVER sends a feefilter message.
    check "newRelayManager" notin nimrodSrc
    check "newRelayManager" notin peerMgrSrc
    check "newRelayManager" notin peerSrc
    check "newRelayManager" notin syncSrc
    # The proc definition IS in relay.nim:
    check "newRelayManager" in relaySrc
    # XFAIL: This passes today (dead module).  A fix wave that wires
    # RelayManager into peermanager.nim or nimrod.nim will flip the
    # first `notin` to `in` — flip the assertion in the same commit.

  test "G1 BUG-1 cont: setIBD has NO production call site":
    ## `relay.nim:setIBD` is defined but never called outside the
    ## relay.nim file itself.  RelayManager.isIBD is initialised to
    ## TRUE (line 185) and never transitions to FALSE in production.
    check "setIBD" in relaySrc          # defined here
    # No caller exists outside relay.nim:
    check ".setIBD(" notin nimrodSrc
    check ".setIBD(" notin syncSrc
    check ".setIBD(" notin peerMgrSrc

  test "G1 BUG-1 cont: setMempoolMinFeeRate has NO production call site":
    check "setMempoolMinFeeRate" in relaySrc
    check ".setMempoolMinFeeRate(" notin nimrodSrc
    check ".setMempoolMinFeeRate(" notin peerMgrSrc

  test "G1 BUG-1 cont: maybeSendFeefilter never invoked from wire path":
    ## The only call site for `maybeSendFeefilter` is inside
    ## `relay.nim:trickleLoop` (line 408), which is started from
    ## `RelayManager.start` — and `start` is never called from src/.
    check "maybeSendFeefilter" in relaySrc
    # No caller outside relay.nim:
    check "rm.maybeSendFeefilter" notin nimrodSrc
    check "rm.maybeSendFeefilter" notin peerMgrSrc

# ---------------------------------------------------------------------------
# G2 — sendSendHeaders fires unconditionally at handshake end (BUG-2, P0-NET)
# ---------------------------------------------------------------------------
suite "W136 G2 — sendSendHeaders unconditional (BUG-2)":

  test "G2 BUG-2: performHandshake calls sendSendHeaders without version/chainwork gate":
    ## Core `MaybeSendSendHeaders` (net_processing.cpp:5519-5538) gates on
    ## `!m_sent_sendheaders && GetCommonVersion() >= SENDHEADERS_VERSION
    ## && pindexBestKnownBlock != nullptr && nChainWork > MinChainWork`.
    ## nimrod sends unconditionally at the end of `performHandshake`.
    check "await peer.sendSendHeaders()" in peerSrc
    # No chain-work / sent-once guard anywhere near the call:
    check "m_sent_sendheaders" notin peerSrc
    check "sentSendHeaders" notin peerSrc
    check "MinimumChainWork" notin peerSrc
    check "pindexBestKnownBlock" notin peerSrc

  test "G2 BUG-2 cont: Peer object has NO m_sent_sendheaders field":
    ## Core net_processing.cpp:406 — `std::atomic<bool> m_sent_sendheaders{false}`.
    ## nimrod's Peer object should have a `sentSendHeaders` boolean once the
    ## fix lands (idempotency invariant).
    check "sentSendHeaders" notin peerSrc

  test "G2 BUG-2 cont: SENDHEADERS_VERSION constant not referenced":
    ## Core gate uses `SENDHEADERS_VERSION = 70012`.  nimrod's call
    ## site has no protocol-version check at all.
    check "SENDHEADERS_VERSION" notin peerSrc
    check "70012" notin peerSrc

# ---------------------------------------------------------------------------
# G3-G5 — MaybeSendFeefilter exemptions (BUG-3)
# ---------------------------------------------------------------------------
suite "W136 G3-G5 — MaybeSendFeefilter exemptions absent (BUG-3)":

  test "G3 BUG-3: maybeSendFeefilter doesn't check ForceRelay permission":
    ## Core net_processing.cpp:5545: `if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;`
    check "ForceRelay" notin relaySrc
    check "HasPermission" notin relaySrc

  test "G4 BUG-3: maybeSendFeefilter doesn't check block-relay-only connection":
    ## Core net_processing.cpp:5548: `if (pto.IsBlockOnlyConn()) return;`
    check "IsBlockOnlyConn" notin relaySrc
    check "isBlockOnlyConn" notin relaySrc
    check "pctBlockRelayOnly" notin relaySrc

  test "G5 BUG-3: maybeSendFeefilter doesn't check ignore_incoming_txs":
    ## Core net_processing.cpp:5542: `if (m_opts.ignore_incoming_txs) return;`
    check "ignore_incoming_txs" notin relaySrc
    check "ignoreIncomingTxs" notin relaySrc

# ---------------------------------------------------------------------------
# G6 — m_wtxid_relay_peers counter missing (BUG-4)
# ---------------------------------------------------------------------------
suite "W136 G6 — m_wtxid_relay_peers counter (BUG-4)":

  test "G6 BUG-4: no global wtxid_relay_peers counter":
    ## Core net_processing.cpp:837 — `std::atomic<int> m_wtxid_relay_peers{0}`.
    ## Decremented at line 1688 on peer disconnect; asserted == 0 at
    ## shutdown (line 1727).  nimrod has no equivalent counter.
    check "wtxidRelayPeers" notin peerMgrSrc
    check "wtxid_relay_peers" notin peerMgrSrc
    check "m_wtxid_relay_peers" notin peerMgrSrc

# ---------------------------------------------------------------------------
# G7 — FEEFILTER receiver doesn't validate MoneyRange (BUG-5)
# ---------------------------------------------------------------------------
suite "W136 G7 — FEEFILTER MoneyRange check absent (BUG-5)":

  test "G7 BUG-5: handleMessage mkFeeFilter arm has no MoneyRange check":
    ## Core net_processing.cpp:5038 — `if (MoneyRange(newFeeFilter))`.
    ## nimrod stores any uint64 value.
    let mkFeeFilterIdx = peerSrc.find("of mkFeeFilter:")
    check mkFeeFilterIdx > 0
    # Look at the body of the post-handshake handler (between line 1354+):
    let postHandshakeStart = peerSrc.find("peer.feeFilterRate = msg.feeRate", mkFeeFilterIdx)
    check postHandshakeStart > 0
    # The 50 chars BEFORE the assignment should have no MoneyRange / MaxMoney check:
    let preCtx = peerSrc[max(0, postHandshakeStart - 200) ..< postHandshakeStart]
    check "MoneyRange" notin preCtx
    check "MaxMoney" notin preCtx
    check "MAX_MONEY" notin preCtx

# ---------------------------------------------------------------------------
# G8 — MAX_BLOCKS_TO_ANNOUNCE = 8 revert-to-inv ceiling missing (BUG-6)
# ---------------------------------------------------------------------------
suite "W136 G8 — MAX_BLOCKS_TO_ANNOUNCE revert-to-inv (BUG-6)":

  test "G8 BUG-6: broadcastBlock has no announce-count ceiling":
    ## Core net_processing.cpp:5840 — `peer.m_blocks_for_headers_relay.size() >
    ## MAX_BLOCKS_TO_ANNOUNCE` flips back to `inv`-announcement.
    ## nimrod's `selectBlockAnnouncement` / `broadcastBlock` lacks this
    ## ceiling entirely.
    check "MAX_BLOCKS_TO_ANNOUNCE" notin peerMgrSrc
    check "blocksForHeadersRelay" notin peerMgrSrc
    check "fRevertToInv" notin peerMgrSrc

  test "G8 BUG-6 cont: selectBlockAnnouncement does not check announce count":
    ## The helper is a single-block decision based on `peerSendHeaders`.
    ## A queue of blocks-to-announce is not modeled at all.
    let selectIdx = peerMgrSrc.find("proc selectBlockAnnouncement*")
    check selectIdx > 0
    let endIdx = peerMgrSrc.find("proc broadcastBlock*", selectIdx)
    check endIdx > selectIdx
    let body = peerMgrSrc[selectIdx ..< endIdx]
    # No queue / count parameter:
    check "blocks_to_announce" notin body
    check "blocksToAnnounce" notin body
    check $CORE_MAX_BLOCKS_TO_ANNOUNCE notin body

# ---------------------------------------------------------------------------
# G9 — PeerHasHeader walk / pindexBestHeaderSent missing (BUG-7)
# ---------------------------------------------------------------------------
suite "W136 G9 — PeerHasHeader / bestHeaderSent (BUG-7)":

  test "G9 BUG-7: no PeerHasHeader equivalent in broadcastBlock":
    ## Core net_processing.cpp:5876 — `PeerHasHeader(&state, pindex)` skips
    ## headers the peer already knows.  nimrod re-announces unconditionally.
    check "PeerHasHeader" notin peerMgrSrc
    check "peerHasHeader" notin peerMgrSrc
    check "pindexBestHeaderSent" notin peerMgrSrc
    check "bestHeaderSent" notin peerMgrSrc

# ---------------------------------------------------------------------------
# G10 — peer.relay (version.relay flag) not gating outbound tx-inv (BUG-8)
# ---------------------------------------------------------------------------
suite "W136 G10 — peer.relay not honored for outbound tx-inv (BUG-8)":

  test "G10 BUG-8: broadcastTx does not gate on peer.relay":
    ## Core net_processing.cpp:5993 — `if (!tx_relay->m_relay_txs)
    ## tx_relay->m_tx_inventory_to_send.clear();`.  And the m_relays_txs
    ## flag from VERSION is checked separately at net_processing.cpp:3980,
    ## 5993.  nimrod's broadcastTx in peermanager.nim iterates all ready
    ## peers and emits inv regardless of peer.relay.
    let broadcastTxIdx = peerMgrSrc.find("proc broadcastTx*")
    check broadcastTxIdx > 0
    # Find the body up to the next proc:
    let nextProcIdx = peerMgrSrc.find("\nproc ", broadcastTxIdx + 1)
    let body = peerMgrSrc[broadcastTxIdx ..< nextProcIdx]
    # The body never reads peer.relay:
    check "peer.relay" notin body
    check "if not peer.relay" notin body

  test "G10 BUG-8 cont: relay.nim queueTxInv does not gate on peer.relay":
    ## Same divergence in the (dead-module) RelayManager.queueTxInv path.
    let queueTxInvIdx = relaySrc.find("proc queueTxInv*")
    check queueTxInvIdx > 0
    let nextProcIdx = relaySrc.find("\nproc ", queueTxInvIdx + 1)
    let body = relaySrc[queueTxInvIdx ..< nextProcIdx]
    check "state.peer.relay" notin body
    check "if not state.peer.relay" notin body

# ---------------------------------------------------------------------------
# G11 — FeeFilterRounder.round semantics drift (BUG-9)
# ---------------------------------------------------------------------------
suite "W136 G11 — FeeFilterRounder.round semantics (BUG-9)":

  test "G11 BUG-9: FeeFilterSpacing constant matches Core":
    ## Sanity: the bucket spacing constant matches.  This pin guards
    ## against accidental drift; the rounder logic itself (random
    ## sequence ordering) is documented in the audit.md.
    check FeeFilterSpacing == CORE_FEE_FILTER_SPACING
    check MaxFilterFeeRate == CORE_MAX_FILTER_FEERATE

  test "G11 BUG-9 cont: round uses Nim global rand(2), not FastRandomContext":
    ## Core uses `WITH_LOCK(m_insecure_rand_mutex, return insecure_rand.rand32()) % 3 != 0`.
    ## nimrod uses Nim's global `rand(2) != 0`.  Same uniform-on-{0,1,2}
    ## semantics, but byte-equivalent fuzz oracles diverge.
    check "rand(2) != 0" in relaySrc
    check "FastRandomContext" notin relaySrc
    check "rand32() %% 3" notin relaySrc

# ---------------------------------------------------------------------------
# G12 — randomize() called repeatedly (BUG-10)
# ---------------------------------------------------------------------------
suite "W136 G12 — randomize() reseed-per-call anti-pattern (BUG-10)":

  test "G12 BUG-10: relay.nim calls randomize() inside hot paths":
    ## Each of these is a fresh time-based reseed of Nim's global MT19937.
    ## Core threads a single FastRandomContext through the lifetime of
    ## the node and never reseeds.
    var calls = 0
    var idx = 0
    while idx < relaySrc.len:
      let f = relaySrc.find("randomize()", idx)
      if f < 0: break
      inc calls
      idx = f + 1
    check calls >= 3  # At least 3 reseed sites: rounder, poisson, hysteresis.

# ---------------------------------------------------------------------------
# G13 — AvgFeefilterBroadcastInterval clamped to 60s (BUG-11)
# ---------------------------------------------------------------------------
suite "W136 G13 — feefilter Poisson interval clamped to 60s (BUG-11)":

  test "G13 BUG-11: calculatePoissonDelay clamps to ≤ 60 seconds":
    ## relay.nim:197 — `clamp(delaySeconds, 0.1, 60.0)`.
    ## At mean = 600s (Core's AVG_FEEFILTER_BROADCAST_INTERVAL = 10min),
    ## every sample > 60s is capped at 60s ⇒ nimrod sends FEEFILTER
    ## at most every 60s, not every 10 minutes.
    check "clamp(delaySeconds, 0.1, 60.0)" in relaySrc
    # The interval constant IS 600s (matches Core's 10min):
    check AvgFeefilterBroadcastInterval == 600.0

# ---------------------------------------------------------------------------
# G14 — FeefilterHighThreshold 1.33 vs Core's 4/3 (BUG-12)
# ---------------------------------------------------------------------------
suite "W136 G14 — FeefilterHighThreshold rounding (BUG-12)":

  test "G14 BUG-12: FeefilterHighThreshold = 1.33 not 4/3":
    ## Core net_processing.cpp:5577 — `currentFilter > 4 * peer.m_fee_filter_sent / 3`.
    ## nimrod uses 1.33, which is < 4/3 (= 1.333̄).  At the boundary
    ## (e.g. currentFilter == sent * 4/3 exactly), Core triggers an
    ## early send; nimrod does NOT.
    check FeefilterHighThreshold == 1.33
    # The exact ratio is NOT used in the source:
    check "4.0 / 3.0" notin relaySrc
    check "4 / 3" notin relaySrc
    # Sanity: 1.33 < 4/3:
    check FeefilterHighThreshold < (4.0 / 3.0)

  test "G14 BUG-12 cont: FeefilterLowThreshold = 0.75 matches Core's 3/4":
    ## 3/4 = 0.75 exactly in floating-point, so the low side is fine.
    check FeefilterLowThreshold == 0.75
    check FeefilterLowThreshold == (3.0 / 4.0)

# ---------------------------------------------------------------------------
# G15 — Pre-verack feefilter accepted (BUG-13)
# ---------------------------------------------------------------------------
suite "W136 G15 — Pre-verack mkFeeFilter accepted (BUG-13)":

  test "G15 BUG-13: outbound pre-verack loop accepts mkFeeFilter":
    ## Core does NOT permit FEEFILTER pre-VERACK; the pre-verack switch
    ## in net_processing.cpp:3801-3940 only whitelists WTXIDRELAY,
    ## SENDADDRV2, SENDCMPCT, SENDTXRCNCL.  nimrod's outbound feature
    ## loop (peer.nim:1142-1144) accepts mkFeeFilter.
    # Find outbound waitForVerack loop:
    let outboundLoopStart = peerSrc.find("block waitForVerack:")
    check outboundLoopStart > 0
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    check inboundLoopStart > outboundLoopStart
    let outboundLoop = peerSrc[outboundLoopStart ..< inboundLoopStart]
    # Verify the pre-verack loop accepts mkFeeFilter:
    check "of mkFeeFilter:" in outboundLoop

  test "G15 BUG-13 cont: inbound pre-verack loop accepts mkFeeFilter":
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    check inboundLoopStart > 0
    # Take the body until next major proc-level dispatch:
    let endIdx = peerSrc.find("# Send feature negotiation", inboundLoopStart)
    check endIdx > inboundLoopStart
    let inboundLoop = peerSrc[inboundLoopStart ..< endIdx]
    check "of mkFeeFilter:" in inboundLoop

# ---------------------------------------------------------------------------
# G16 — Pre-verack sendheaders accepted (BUG-14)
# ---------------------------------------------------------------------------
suite "W136 G16 — Pre-verack mkSendHeaders accepted (BUG-14)":

  test "G16 BUG-14: outbound pre-verack loop accepts mkSendHeaders":
    let outboundLoopStart = peerSrc.find("block waitForVerack:")
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    let outboundLoop = peerSrc[outboundLoopStart ..< inboundLoopStart]
    check "of mkSendHeaders:" in outboundLoop

  test "G16 BUG-14 cont: inbound pre-verack loop accepts mkSendHeaders":
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    let endIdx = peerSrc.find("# Send feature negotiation", inboundLoopStart)
    let inboundLoop = peerSrc[inboundLoopStart ..< endIdx]
    check "of mkSendHeaders:" in inboundLoop

# ---------------------------------------------------------------------------
# G17 — WTXIDRELAY ordering vs SENDADDRV2 (BUG-15)
# ---------------------------------------------------------------------------
suite "W136 G17 — outbound handshake WTXIDRELAY/SENDADDRV2 order (BUG-15)":

  test "G17 BUG-15: nimrod sends SENDADDRV2 BEFORE WTXIDRELAY":
    ## Core net_processing.cpp:3710-3720 — WTXIDRELAY then SENDADDRV2.
    ## nimrod peer.nim:1110-1113 reversed.
    # Find the BIP155 block in performHandshake (outbound):
    let bip155Idx = peerSrc.find("BIP155: Send sendaddrv2 BEFORE verack")
    check bip155Idx > 0
    # The next two lines should be sendSendAddrV2 then sendWtxidRelay:
    let sendAddrV2Idx = peerSrc.find("sendSendAddrV2()", bip155Idx)
    let sendWtxidIdx = peerSrc.find("sendWtxidRelay()", bip155Idx)
    check sendAddrV2Idx > 0
    check sendWtxidIdx > 0
    # Reversed: sendaddrv2 first (smaller index) in nimrod.
    check sendAddrV2Idx < sendWtxidIdx

# ---------------------------------------------------------------------------
# G18 — validatePreHandshakeMessage permits FeeFilter/SendHeaders (BUG-16)
# ---------------------------------------------------------------------------
suite "W136 G18 — validatePreHandshakeMessage post-VERSION whitelist (BUG-16)":

  test "G18 BUG-16: isMessageAllowedDuringHandshake includes mkFeeFilter and mkSendHeaders":
    ## peer.nim:1771 — pre-VERACK whitelist includes mkFeeFilter and
    ## mkSendHeaders.  Core doesn't.
    let validateIdx = peerSrc.find("# Allowed: VERACK, and some negotiation messages")
    check validateIdx > 0
    let endIdx = peerSrc.find("proc validatePreHandshakeMessage*", validateIdx)
    check endIdx > validateIdx
    let body = peerSrc[validateIdx ..< endIdx]
    check "mkSendHeaders" in body
    check "mkFeeFilter" in body

  test "G18 BUG-16 cont: validatePreHandshakeMessage marAccept arm includes mkFeeFilter and mkSendHeaders":
    ## peer.nim:1816 — `of mkSendHeaders, mkSendCmpct, mkFeeFilter: marAccept`.
    check "of mkSendHeaders, mkSendCmpct, mkFeeFilter:" in peerSrc

# ---------------------------------------------------------------------------
# G19 — handleReceivedFeefilter dead helper (BUG-17)
# ---------------------------------------------------------------------------
suite "W136 G19 — handleReceivedFeefilter dead helper (BUG-17)":

  test "G19 BUG-17: handleReceivedFeefilter has no production call site":
    ## relay.nim:577-582 — defined but never used outside relay.nim and
    ## test files.  The real handler is at peer.nim:1354-1356.
    check "handleReceivedFeefilter" in relaySrc
    check "handleReceivedFeefilter" notin peerSrc
    check "handleReceivedFeefilter" notin peerMgrSrc
    check "handleReceivedFeefilter" notin nimrodSrc

# ---------------------------------------------------------------------------
# G20 — MinProtocolVersion = 70015 obviates SENDHEADERS/FEEFILTER gates (BUG-18)
# ---------------------------------------------------------------------------
suite "W136 G20 — MinProtocolVersion 70015 (BUG-18)":

  test "G20 BUG-18: MinProtocolVersion = 70015 (10x higher than Core's 31800)":
    ## peer.nim:25 — `MinProtocolVersion* = 70015'u32`.  Refuses any
    ## peer < 70015 in handshake.  Makes BIP-130/133 version gates
    ## de-facto trivially true, masking the absence of explicit gates
    ## in BUG-2/3/5.
    check MinProtocolVersion == 70015'u32
    # Core's MIN_PEER_PROTO_VERSION is 31800 (in version.h); we are
    # 2.2x more restrictive.  Witness was introduced at 70015 (BIP-141).
    check MinProtocolVersion > 31800'u32

# ---------------------------------------------------------------------------
# G21-G23 — Codec PRESENT (mkSendHeaders / mkWtxidRelay / mkFeeFilter)
# ---------------------------------------------------------------------------
suite "W136 G21-G23 — codec PRESENT (forward-regression sentinels)":

  test "G21 PRESENT: mkSendHeaders enum + commandToMessageKind + messageKindToCommand":
    check "mkSendHeaders" in messagesSrc
    check "\"sendheaders\": mkSendHeaders" in messagesSrc
    check "of mkSendHeaders: \"sendheaders\"" in messagesSrc

  test "G22 PRESENT: mkWtxidRelay enum + serialise + deserialise":
    check "mkWtxidRelay" in messagesSrc
    # No payload (empty body):
    check "of \"wtxidrelay\":" in messagesSrc
    check "of mkWtxidRelay" in messagesSrc

  test "G23 PRESENT: mkFeeFilter enum + uint64LE serialise/deserialise":
    check "mkFeeFilter" in messagesSrc
    check "w.writeUint64LE(msg.feeRate)" in messagesSrc
    check "feeRate: r.readUint64LE()" in messagesSrc
    # newFeeFilter constructor present:
    check "proc newFeeFilter*(feeRate: uint64)" in messagesSrc

# ---------------------------------------------------------------------------
# G24-G26 — BIP-324 short-ID table PRESENT
# ---------------------------------------------------------------------------
suite "W136 G24-G26 — bip324.nim short-ID table PRESENT":

  test "G24 PRESENT: sendheaders has a v2 short-ID":
    check "\"sendheaders\"" in bip324Src

  test "G25 PRESENT: wtxidrelay has a v2 short-ID":
    check "\"wtxidrelay\"" in bip324Src

  test "G26 PRESENT: feefilter has a v2 short-ID":
    check "\"feefilter\"" in bip324Src

# ---------------------------------------------------------------------------
# G27 — WTXIDRELAY post-VERACK is marDisconnect (PRESENT)
# ---------------------------------------------------------------------------
suite "W136 G27 — WTXIDRELAY post-VERACK is marDisconnect (PRESENT)":

  test "G27 PRESENT: WTXIDRELAY received after VERACK → marDisconnect":
    ## Core net_processing.cpp:3923-3925 — "Disconnect peers that send
    ## a wtxidrelay message after VERACK".  nimrod's
    ## validatePreHandshakeMessage at peer.nim:1808-1813 returns
    ## `marDisconnect` for mkWtxidRelay / mkSendAddrV2 after verackReceived.
    let arm = peerSrc.find("of mkWtxidRelay, mkSendAddrV2:")
    check arm > 0
    # Look ahead 200 chars:
    let ctx = peerSrc[arm ..< min(arm + 400, peerSrc.len)]
    check "marDisconnect" in ctx
    check "if peer.verackReceived" in ctx

# ---------------------------------------------------------------------------
# G28 — BIP-339 per-peer inv type switch (PRESENT)
# ---------------------------------------------------------------------------
suite "W136 G28 — BIP-339 per-peer inv type (PRESENT)":

  test "G28 PRESENT: queueTxInv switches invWtx vs invTx by peer.wtxidRelay":
    ## relay.nim:286-290 — wtxid-relay peers receive (invWtx, wtxidHash);
    ## legacy peers receive (invTx, effectiveTxid).
    check "if state.peer.wtxidRelay:" in relaySrc
    check "(invWtx, wtxidHash)" in relaySrc
    check "(invTx, effectiveTxid)" in relaySrc

  test "G28 PRESENT cont: broadcastTx in peermanager applies the same switch":
    ## peermanager.nim:927-930.
    check "if peer.wtxidRelay:" in peerMgrSrc
    check "(invWtx, wtxidHash)" in peerMgrSrc
    check "(invTx, txidHash)" in peerMgrSrc

# ---------------------------------------------------------------------------
# G29 — BIP-130 selectBlockAnnouncement emits headers when peer.sendHeaders (PRESENT)
# ---------------------------------------------------------------------------
suite "W136 G29 — BIP-130 selectBlockAnnouncement (PRESENT)":

  test "G29 PRESENT: selectBlockAnnouncement returns headers for sendHeaders peer":
    ## peermanager.nim:938-951.
    let header = BlockHeader(
      version: 1'i32,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 0'u32,
      bits: 0x1d00ffff'u32,
      nonce: 0'u32
    )
    let blockHash: array[32, byte] = default(array[32, byte])
    # peerSendHeaders=true → headers message:
    let msgHeaders = selectBlockAnnouncement(header, blockHash, true)
    check msgHeaders.kind == mkHeaders
    # peerSendHeaders=false → inv message:
    let msgInv = selectBlockAnnouncement(header, blockHash, false)
    check msgInv.kind == mkInv

# ---------------------------------------------------------------------------
# G30 — Pre-VERACK feature loop sets peer.wtxidRelay = true on mkWtxidRelay (PRESENT)
# ---------------------------------------------------------------------------
suite "W136 G30 — Pre-VERACK wtxidrelay sets flag (PRESENT)":

  test "G30 PRESENT: outbound pre-VERACK loop sets peer.wtxidRelay = true":
    let outboundLoopStart = peerSrc.find("block waitForVerack:")
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    let outboundLoop = peerSrc[outboundLoopStart ..< inboundLoopStart]
    check "of mkWtxidRelay:" in outboundLoop
    check "peer.wtxidRelay = true" in outboundLoop

  test "G30 PRESENT cont: inbound pre-VERACK loop sets peer.wtxidRelay = true":
    let inboundLoopStart = peerSrc.find("block waitForVerackInbound:")
    let endIdx = peerSrc.find("# Send feature negotiation", inboundLoopStart)
    let inboundLoop = peerSrc[inboundLoopStart ..< endIdx]
    check "of mkWtxidRelay:" in inboundLoop
    check "peer.wtxidRelay = true" in inboundLoop

# ---------------------------------------------------------------------------
# Sanity: protocol version constants
# ---------------------------------------------------------------------------
suite "W136 — protocol version constants pinned":

  test "ProtocolVersion in messages.nim is 70016 (BIP-339 negotiation enabled)":
    check ProtocolVersion == CORE_WTXID_RELAY_VERSION

  test "Core's SENDHEADERS / FEEFILTER / WTXIDRELAY message names":
    check messageKindToCommand(mkSendHeaders) == CORE_MSG_SENDHEADERS
    check messageKindToCommand(mkFeeFilter)   == CORE_MSG_FEEFILTER
    check messageKindToCommand(mkWtxidRelay)  == CORE_MSG_WTXIDRELAY
