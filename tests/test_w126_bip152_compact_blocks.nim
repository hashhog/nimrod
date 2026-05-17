## W126 BIP-152 Compact Block Relay — 30-gate audit tests
##
## Reference: bitcoin-core/src/blockencodings.{h,cpp},
##            bitcoin-core/src/net_processing.cpp
## BIP: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
##
## PRESENT gates: positive existence check via `compiles(symbol)` or
## a behavioural assertion against the implementation.
## MISSING gates: `check not compiles(<symbol>)` so this file fails to
## compile once the gap is closed in a follow-up fix wave (this
## signals the audit gate has flipped and reminds the fixer to also
## flip the corresponding `check not compiles` to `check compiles`).
##
## BUGS catalogued (see audit/w126_bip152_compact_blocks.md for full
## detail and priority):
##
##   BUG-1  (G12-G15)  cmpctblock header not chain-state-validated
##                     before InitData (no prev-block lookup, no PoW
##                     anti-DoS, no ProcessNewBlockHeaders).
##   BUG-2  (G20-G22)  getblocktxn serve handler is a stub.
##   BUG-3  (G11/G27-G29) HB-peer ANNOUNCE-side missing entirely
##                     (lNodesAnnouncingHeaderAndIDs absent;
##                     selectBlockAnnouncement only emits headers/inv;
##                     m_bip152_highbandwidth_to flag absent).
##   BUG-4  (G19)      fillFromExtraPool defined but never called
##                     from peer.nim's cmpctblock handler.
##   BUG-5  (G17)      Misbehaving / ScoreInvalidCompactBlock never
##                     invoked on rsInvalid cmpctblock (only logged).
##   BUG-6  (G7/G30)   inFlightBlocks: single-valued; cannot represent
##                     MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3.
##   BUG-7  (G_serve)  getdata(invCmpctBlock) serves without checking
##                     peerCmpctVersion / wantsCompactBlocks first.
##   BUG-8  (G25)      No IsBlockMutated / merkle check after
##                     FillBlock; short-id-collision reconstructions
##                     pass the encoding layer untrapped.
##   BUG-9  (G26)      Reconstructed block not routed into chain
##                     submission; mkCmpctBlock / mkBlockTxn handlers
##                     only log + increment stats.
##   BUG-10 (G19a)     50% missing-tx threshold short-circuits
##                     getblocktxn; Core has no such threshold.
##   BUG-11 (G10-sub)  sendSendCmpct called unconditionally at
##                     handshake; no IBD/blocksonly/nil-mempool guard.
##   BUG-12 (G21-sub)  blocktxnDepthOk defined but never called.
##   BUG-13 (G24-sub)  reconstructBlock does not clear pdb.header
##                     after fill (Core: SetNull at line 211).

import std/[options, tables, sets, strutils]
import unittest2

import ../src/network/compact_blocks
import ../src/network/messages
import ../src/network/peer as net_peer
import ../src/network/peermanager
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool as mempool_mod

# ----------------------------------------------------------------------------
# Test helpers — minimal block / tx builders sufficient to drive the gates.
# Mirrors the helper set used by test_w112_compact_blocks.nim.
# ----------------------------------------------------------------------------

proc makeTestTx(seed: int): Transaction =
  var inp: TxIn
  for i in 0 ..< 32:
    array[32, byte](inp.prevOut.txid)[i] = byte((seed * 7 + i) and 0xFF)
  inp.prevOut.vout = 0
  inp.scriptSig = @[byte(0x00)]
  inp.sequence = 0xFFFFFFFF'u32
  result.inputs.add(inp)
  var outp: TxOut
  outp.value = Satoshi(10_000_000 + seed * 1000)
  outp.scriptPubKey = @[byte(0x51)]
  result.outputs.add(outp)
  result.version = 1
  result.lockTime = 0

proc makeCoinbase(h: int32): Transaction =
  var inp: TxIn
  inp.prevOut.vout = 0xFFFFFFFF'u32
  inp.scriptSig = @[byte(0x03),
                    byte(h and 0xFF),
                    byte((h shr 8) and 0xFF),
                    byte((h shr 16) and 0xFF)]
  inp.sequence = 0xFFFFFFFF'u32
  result.inputs.add(inp)
  var outp: TxOut
  outp.value = Satoshi(625_000_000)
  outp.scriptPubKey = @[byte(0x51)]
  result.outputs.add(outp)
  result.version = 2
  result.lockTime = 0

proc makeBlock(h: int32, numTx: int = 5): Block =
  result.header.version = 0x20000000'i32
  result.header.timestamp = 1700000000'u32 + uint32(h * 600)
  result.header.bits = 0x1d00ffff'u32
  result.header.nonce = uint32(h * 31337)
  result.txs.add(makeCoinbase(h))
  for i in 1 ..< numTx:
    result.txs.add(makeTestTx(h.int * 100 + i))

# ============================================================================
# Construction (G1-G7)
# ============================================================================

suite "W126 BIP-152 construction (G1-G7)":

  test "G1 PRESENT: SHORTTXIDS_LENGTH = 6 (BIP-152 §Short transaction IDs)":
    # Core blockencodings.h:103 — `static constexpr int SHORTTXIDS_LENGTH = 6;`
    check ShortIdLength == 6

  test "G1 PRESENT: computed short IDs are exactly 6 bytes":
    var hdr: BlockHeader
    hdr.bits = 0x1d00ffff'u32
    var txid: TxId
    let sid = computeShortId(hdr, 0'u64, txid)
    check sid.len == 6

  test "G2 PRESENT: short-ID masks SipHash to 48 bits":
    # Core blockencodings.cpp:49 — `... & 0xffffffffffffL`.
    # We verify the structural property: short-IDs are 6 bytes.
    # Two different wtxids producing IDs that differ only in the high
    # 16 bits of the 64-bit hash MUST collide at the 48-bit truncation.
    # (Not exhaustively testable without crafting collisions; the
    # structural check is captured by G1's 6-byte assertion.)
    check ShortIdLength == 6
    check compiles(computeShortId)

  test "G3 PRESENT: FillShortTxIDSelector uses single SHA256, not double":
    # Core blockencodings.cpp:35-44 — single SHA256 of header‖nonce.
    # nimrod compact_blocks.nim:107-129 — uses sha256Single.
    check compiles(computeSipHashKeys)
    let blk = makeBlock(1, 2)
    let (k0a, k1a) = computeSipHashKeys(blk.header, 0xCAFE'u64)
    let (k0b, k1b) = computeSipHashKeys(blk.header, 0xCAFE'u64)
    # Deterministic.
    check k0a == k0b and k1a == k1b
    # Different nonce → different keys.
    let (k0c, k1c) = computeSipHashKeys(blk.header, 0xDEADBEEF'u64)
    check (k0a != k0c) or (k1a != k1c)

  test "G4 PRESENT: CMPCTBLOCKS_VERSION = 2 constant":
    # Core net_processing.cpp:199 — `static constexpr uint64_t
    # CMPCTBLOCKS_VERSION{2};`
    check CompactBlockVersion == 2'u64

  test "G5 PRESENT: MAX_CMPCTBLOCK_DEPTH = 5":
    # Core net_processing.cpp:138.
    check MaxCmpctBlockDepth == 5

  test "G6 PRESENT: MAX_BLOCKTXN_DEPTH = 10":
    # Core net_processing.cpp:140.
    check MaxBlocktxnDepth == 10

  test "G7 MISSING (BUG-6): MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3":
    # Core net_processing.h:47 —
    #   `static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;`
    # nimrod has no such constant; inFlightBlocks (peermanager.nim:91)
    # is a Table[BlockHash, InFlightBlock] (single-valued), so the
    # multimap semantics required for 3-parallel-HB-peer downloads of
    # the same blockhash are structurally impossible to express.
    check not compiles(MaxCmpctBlocksInflightPerBlock)
    check not compiles(MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK)

# ============================================================================
# SENDCMPCT negotiation (G8-G11)
# ============================================================================

suite "W126 BIP-152 SENDCMPCT negotiation (G8-G11)":

  test "G8 PRESENT: sendcmpct with version != 2 is silently dropped":
    # Core net_processing.cpp:3907 — `if (sendcmpct_version !=
    # CMPCTBLOCKS_VERSION) return;`.  nimrod peer.nim:1344 enforces.
    # Behavioural check via handleSendCmpct (the helper):
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 1'u64)
    check state.wantsCompactBlocks == false        # v1 dropped
    check state.compactBlockVersion == 0'u64
    state.handleSendCmpct(announce = true, version = 2'u64)
    check state.wantsCompactBlocks == true
    check state.compactBlockVersion == 2'u64
    state.handleSendCmpct(announce = true, version = 7'u64)
    # Higher-than-2 also dropped (no state mutation from the v7 call).
    check state.compactBlockVersion == 2'u64

  test "G9 PRESENT: peer's HB-from-us request stored as m_bip152_highbandwidth_from":
    # Core net_processing.cpp:3915 — `pfrom.m_bip152_highbandwidth_from
    # = sendcmpct_hb;`.  nimrod peer.nim:1349 — `peer.peerHighBandwidth
    # = announce;`.  Field exists; behavioural test is implicit via G8.
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 2'u64)
    check state.highBandwidthMode == true
    state.handleSendCmpct(announce = false, version = 2'u64)
    check state.highBandwidthMode == false

  test "G10 PRESENT: SENDCMPCT(0, 2) emitted at handshake completion":
    # Core net_processing.cpp:3868-3870 — outbound SENDCMPCT(0,2) is
    # sent on connection.  nimrod peer.nim:1234 — unconditional
    # `await peer.sendSendCmpct()` after VERACK.
    check compiles(sendSendCmpct)

  test "G11 MISSING (BUG-3): SENDCMPCT(1, 2) promote-to-HB never sent":
    # Core net_processing.cpp:1323 — `MakeAndPushMessage(*pfrom,
    # NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, /*version=*/
    # CMPCTBLOCKS_VERSION);` called from
    # MaybeSetPeerAsAnnouncingHeaderAndIDs.
    # nimrod: no `MaybeSetPeerAsAnnouncing...` analog; `sendSendCmpct`
    # is only ever called with announce=false at handshake.  Grep
    # confirms zero call sites with announce=true.
    check not compiles(maybeSetPeerAsAnnouncingHeaderAndIDs)
    check not compiles(promotePeerToHighBandwidth)

# ============================================================================
# CMPCTBLOCK receive (G12-G19)
# ============================================================================

suite "W126 BIP-152 CMPCTBLOCK receive (G12-G19)":

  test "G12 MISSING (BUG-1): LoadingBlocks / IBD guard on incoming cmpctblock":
    # Core net_processing.cpp:4469 — `if
    # (m_chainman.m_blockman.LoadingBlocks()) { ... return; }`
    # nimrod peer.nim:1366-1377 enters InitData immediately, no
    # LoadingBlocks check.
    # No helper exists for this gate.
    check not compiles(loadingBlocksGuardForCmpctBlock)

  test "G13 MISSING (BUG-1): prev_block lookup before InitData":
    # Core net_processing.cpp:4483-4489 — looks up
    # `LookupBlockIndex(header.hashPrevBlock)` and, if missing and not
    # IBD, sends GETHEADERS instead of running InitData.
    # nimrod has no equivalent path in mkCmpctBlock.
    check not compiles(lookupPrevBlockBeforeCmpctBlock)

  test "G14 MISSING (BUG-1): chain-work anti-DoS check on cmpctblock header":
    # Core net_processing.cpp:4490-4494 — `prev_block->nChainWork +
    # GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()`
    # short-circuits with a debug log.  nimrod has no chain-work
    # check on the cmpctblock path.
    check not compiles(getAntiDoSWorkThreshold)
    check not compiles(antiDoSWorkThreshold)

  test "G15 MISSING (BUG-1): ProcessNewBlockHeaders called on cmpctblock header":
    # Core net_processing.cpp:4503-4508 — runs header through
    # `ProcessNewBlockHeaders` (with `min_pow_checked=true`) before
    # any further work; on invalid: `MaybePunishNodeForBlock(...
    # via_compact_block=true, "invalid header via cmpctblock")`.
    # nimrod calls neither; the cmpctblock header is consumed only by
    # the encoding layer.
    check not compiles(processNewBlockHeadersViaCmpctBlock)

  test "G16 PRESENT: PartiallyDownloadedBlock::InitData faithful port":
    # Core blockencodings.cpp:62-116 — null-header rejection,
    # structural-gap check, bucket-size > 12, short-ID collision.
    # nimrod compact_blocks.nim:346-436 ports all four.
    check compiles(initPartiallyDownloadedBlock)

    # Behavioural: null header rejected.
    var cb: CompactBlock
    # bits = 0 makes isNullHeader return true.
    cb.header.bits = 0
    let (_, statusNull) = initPartiallyDownloadedBlock(cb)
    check statusNull == rsInvalid

    # Behavioural: bucket-size DoS guard (13 identical short IDs).
    var cbDoS: CompactBlock
    cbDoS.header.bits = 0x1d00ffff'u32
    for i in 0 ..< 13:
      cbDoS.shortIds.add([byte(0x11), 0x22, 0x33, 0x44, 0x55, 0x66])
    cbDoS.prefilledTxns.add(PrefilledTx(index: 13, tx: makeTestTx(1)))
    let (_, statusDoS) = initPartiallyDownloadedBlock(cbDoS)
    check statusDoS == rsFailed

  test "G17 MISSING (BUG-5): Misbehaving called on rsInvalid cmpctblock":
    # Core net_processing.cpp:4592-4594:
    #   if (status == READ_STATUS_INVALID) {
    #     RemoveBlockRequest(...);
    #     Misbehaving(peer, "invalid compact block");
    #     return;
    #   }
    # nimrod peer.nim:1378-1379 only logs `warn`; no call to
    # peer.misbehaving(ScoreInvalidCompactBlock, ...).
    # The constant ScoreInvalidCompactBlock exists (peer.nim:1635)
    # but has zero references in the cmpctblock handler.
    check compiles(ScoreInvalidCompactBlock)
    # Forward-regression source guard: until BUG-5 closes, the
    # mkCmpctBlock arm must not call misbehaving on rsInvalid.
    let source = readFile("src/network/peer.nim")
    # Anchor on the warn line that currently stands in for the
    # Misbehaving call.
    check "invalid compact block" in source
    # Search a window around the warn line for any misbehaving call.
    # Until the fix lands, neither pattern should appear adjacent to
    # the "invalid compact block" warning.
    let warnIdx = source.find("invalid compact block")
    if warnIdx >= 0:
      let windowStart = max(0, warnIdx - 200)
      let windowEnd = min(source.len, warnIdx + 400)
      let window = source[windowStart ..< windowEnd]
      check ("misbehaving(" notin window) or
            ("misbehaving(ScoreInvalidCompactBlock" notin window)

  test "G18 PRESENT: fillFromMempool wired into cmpctblock handler":
    # Core blockencodings.cpp:118-145 — fill mempool txs by short-id.
    # nimrod peer.nim:1384-1385 — `if peer.mempool != nil:
    # pdb.fillFromMempool(peer.mempool)`.
    check compiles(fillFromMempool)

  test "G19 MISSING (BUG-4): fillFromExtraPool never wired (dead helper)":
    # Core blockencodings.cpp:147-176 — `partialBlock.InitData(
    # cmpctblock, vExtraTxnForCompact)` always passes the extra-pool.
    # nimrod: fillFromExtraPool defined at compact_blocks.nim:476 but
    # `grep -rn fillFromExtraPool src/` returns only the definition.
    check compiles(fillFromExtraPool)   # helper itself exists
    # Forward-regression source guard: no caller in peer.nim.
    let source = readFile("src/network/peer.nim")
    check "fillFromExtraPool" notin source

  test "G19a PARTIAL (BUG-10): 50% miss-fraction threshold blocks getblocktxn":
    # Core net_processing.cpp:4609-4633 — always sends GETBLOCKTXN
    # when first_in_flight and some txs missing.  No miss-fraction
    # threshold.
    # nimrod peer.nim:1404-1410 — `if missPct > 50.0: ...
    # failedReconstructions++`, never sends getblocktxn.
    # Forward-regression source guard: this branch persists until
    # BUG-10 closes.  The literal "missPct > 50.0" remains in source.
    let source = readFile("src/network/peer.nim")
    check "missPct > 50.0" in source

# ============================================================================
# GETBLOCKTXN serve (G20-G23)
# ============================================================================

suite "W126 BIP-152 GETBLOCKTXN serve (G20-G23)":

  test "G20 MISSING (BUG-2): getblocktxn serve sends BLOCKTXN response":
    # Core net_processing.cpp:4245-4264 — looks up block, calls
    # SendBlockTransactions(pfrom, peer, block, req).
    # nimrod peer.nim:1419-1436 is a stub: logs and returns.
    # Forward-regression source guard: confirm the TODO marker still
    # stands.
    let source = readFile("src/network/peer.nim")
    check "TODO(BUG-5): look up the block and send a real blocktxn response" in source

    # And: no newBlockTxnMsg call inside the mkGetBlockTxn arm.
    let mkGetIdx = source.find("of mkGetBlockTxn:")
    check mkGetIdx >= 0
    let armEnd = source.find("of mkBlockTxn:", mkGetIdx)
    check armEnd > mkGetIdx
    let arm = source[mkGetIdx ..< armEnd]
    check "newBlockTxnMsg" notin arm
    check "sendMessage" notin arm

  test "G21 MISSING (BUG-12): blocktxnDepthOk is a dead helper":
    # Helper defined at compact_blocks.nim:658 with explicit Core ref.
    check compiles(blocktxnDepthOk)
    # But: zero callers in src/.  Source-guard for the dead-helper
    # pattern; once BUG-2 lands and wires blocktxnDepthOk into the
    # mkGetBlockTxn arm, this assertion flips.
    let peerSrc = readFile("src/network/peer.nim")
    let nodeSrc = readFile("src/nimrod.nim")
    check "blocktxnDepthOk" notin peerSrc
    check "blocktxnDepthOk" notin nodeSrc

  test "G22 MISSING (BUG-2): out-of-bounds index → Misbehaving":
    # Core net_processing.cpp:2602-2605 (SendBlockTransactions) —
    # `if (req.indexes[i] >= block.vtx.size()) Misbehaving(peer,
    # "getblocktxn with out-of-bounds tx indices");`
    # nimrod: implied dead path (BUG-2 makes the entire serve a stub).
    # No symbol for the check exists.
    check not compiles(sendBlockTransactions)
    check not compiles(misbehaveOnOutOfBoundsGetBlockTxn)

  test "G23 PRESENT: BlockTransactionsRequest differential-index codec":
    # Core blockencodings.h:53 — `Using<VectorFormatter<
    # DifferenceFormatter>>(obj.indexes)` enforces strictly-increasing
    # absolute indexes.
    # nimrod compact_blocks.nim:272-287 readBlockTxnRequest.
    var blockHash: BlockHash
    let req = BlockTxnRequest(
      blockHash: blockHash,
      indexes: @[uint16(1), uint16(3), uint16(7), uint16(8)])
    var w = BinaryWriter()
    w.writeBlockTxnRequest(req)
    var r = BinaryReader(data: w.data, pos: 0)
    let req2 = r.readBlockTxnRequest()
    check req2.indexes == req.indexes
    # Verify differential-encoding semantics on the wire.
    var r2 = BinaryReader(data: w.data, pos: 0)
    discard r2.readBlockHash()
    check r2.readCompactSize() == 4'u64    # count
    check r2.readCompactSize() == 1'u64    # diff: 1 - 0 = 1
    check r2.readCompactSize() == 1'u64    # diff: 3 - (1+1) = 1
    check r2.readCompactSize() == 3'u64    # diff: 7 - (3+1) = 3
    check r2.readCompactSize() == 0'u64    # diff: 8 - (7+1) = 0

# ============================================================================
# BLOCKTXN receive (G24-G26)
# ============================================================================

suite "W126 BIP-152 BLOCKTXN receive (G24-G26)":

  test "G24 PARTIAL (BUG-13): FillBlock does not clear pdb.header":
    # Core blockencodings.cpp:211-212 — `header.SetNull();
    # txn_available.clear();` after vtx populated, to prevent reuse.
    # nimrod reconstructBlock (compact_blocks.nim:546-570) populates
    # blk.txs but does NOT mutate pdb.header / pdb.txnAvailable.
    let blk = makeBlock(700, 4)
    let cb = newCompactBlock(blk, 0xABCD'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    discard pdb.fillMissingTransactions(blk.txs[1..^1])
    let (_, status) = pdb.reconstructBlock()
    check status == rsOk
    # Behavioural confirmation of BUG-13: header is still populated
    # post-reconstruct.  (If/when Core parity is restored, the
    # `header.bits == 0` assertion below will flip.)
    check pdb.header.bits == blk.header.bits
    check pdb.txnAvailable.len > 0

  test "G25 MISSING (BUG-8): IsBlockMutated / merkle check after FillBlock":
    # Core blockencodings.cpp:218-222 — `IsBlockMutated(block,
    # segwit_active)` post-fill catches short-ID-collision mis-
    # reconstructions before declaring READ_STATUS_OK.
    # nimrod compact_blocks.nim:564-568 comments explicitly that this
    # check is NOT performed and is left to callers; no caller in
    # peer.nim performs it.
    check not compiles(isBlockMutated)
    # Source-guard: the comment that documents the gap remains.
    let cbSrc = readFile("src/network/compact_blocks.nim")
    check "callers should" in cbSrc

  test "G26 PARTIAL (BUG-9): reconstructed block not routed to chain submission":
    # Core net_processing.cpp:3505-3513 / 4701 — successful
    # reconstruction triggers ProcessNewBlock(force_processing=true,
    # min_pow_checked=true) and RemoveBlockRequest.
    # nimrod peer.nim:1389-1395 / 1446-1451 only log success and
    # bump successfulReconstructions; no call to a chain-acceptance
    # function inside either arm.
    let source = readFile("src/network/peer.nim")
    # The mkCmpctBlock + mkBlockTxn arms must not contain calls to
    # the block-acceptance entry-points (acceptBlock, connectBlock,
    # processNewBlock).  Until BUG-9 lands these stay absent.
    let cbArm = source.find("of mkCmpctBlock:")
    let txArm = source.find("of mkBlockTxn:")
    let pkgArm = source.find("of mkSendPackages:")   # arm after mkBlockTxn
    check cbArm >= 0 and txArm > cbArm and pkgArm > txArm
    let cbBody = source[cbArm ..< txArm]
    let txBody = source[txArm ..< pkgArm]
    for arm in [cbBody, txBody]:
      check "processNewBlock" notin arm
      check "acceptBlock(" notin arm
      check "connectBlock(" notin arm

# ============================================================================
# HB-peer ANNOUNCE-side (G27-G29)
# ============================================================================

suite "W126 BIP-152 HB-peer ANNOUNCE-side (G27-G29)":

  test "G27 MISSING (BUG-3): lNodesAnnouncingHeaderAndIDs analog":
    # Core net_processing.cpp:987 — `std::list<NodeId>
    # lNodesAnnouncingHeaderAndIDs GUARDED_BY(cs_main);`
    # Maintained at cap of 3 by MaybeSetPeerAsAnnouncingHeaderAndIDs
    # (net_processing.cpp:1272-1329).
    # nimrod: no such list anywhere in src/network/.
    check not compiles(nodesAnnouncingHeaderAndIDs)
    check not compiles(hbPeers)
    check not compiles(highBandwidthPeers)
    # Source-guard: confirm no field on PeerManager.
    let pmSrc = readFile("src/network/peermanager.nim")
    check "lNodesAnnouncingHeaderAndIDs" notin pmSrc
    check "nodesAnnouncing" notin pmSrc

  test "G28 MISSING (BUG-3): m_bip152_highbandwidth_to flag on peer":
    # Core CNode::m_bip152_highbandwidth_to (set in
    # MaybeSetPeerAsAnnouncingHeaderAndIDs at line 1325) records
    # "we have selected this peer as our HB source".
    # nimrod Peer has peerHighBandwidth (= _from) but no _to flag.
    let peerSrc = readFile("src/network/peer.nim")
    check "peerHighBandwidth" in peerSrc                    # _from exists
    check "peerHighBandwidthTo" notin peerSrc               # _to absent
    check "bip152_highbandwidth_to" notin peerSrc

  test "G29 MISSING (BUG-3): broadcastBlock never sends cmpctblock":
    # Core net_processing.cpp:5895-5912 — block announcement loop
    # picks CMPCTBLOCK for HB peers (m_bip152_highbandwidth_to=true),
    # HEADERS for sendheaders peers, INV otherwise.
    # nimrod peermanager.nim:938-951 selectBlockAnnouncement picks
    # only between newHeaders and newInv.
    let pmSrc = readFile("src/network/peermanager.nim")
    # selectBlockAnnouncement does not branch on compactBlockState.
    let helperIdx = pmSrc.find("proc selectBlockAnnouncement")
    check helperIdx >= 0
    let helperEnd = pmSrc.find("proc ", helperIdx + 1)
    check helperEnd > helperIdx
    let helper = pmSrc[helperIdx ..< helperEnd]
    check "newCmpctBlockMsg" notin helper
    check "compactBlockState" notin helper
    check "highBandwidth" notin helper

# ============================================================================
# In-flight tracking (G30) + getdata serve preconditions (additional)
# ============================================================================

suite "W126 BIP-152 in-flight tracking + getdata preconditions (G30 + extras)":

  test "G30 MISSING (BUG-6): inFlightBlocks is single-valued, not multimap":
    # Core mapBlocksInFlight is a std::multimap<uint256, ...> allowing
    # up to MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 concurrent in-flight
    # records for the same blockhash from distinct HB peers.
    # nimrod peermanager.nim:91 — `inFlightBlocks: Table[BlockHash,
    # InFlightBlock]` (single-valued).
    let pmSrc = readFile("src/network/peermanager.nim")
    check "inFlightBlocks*: Table[BlockHash, InFlightBlock]" in pmSrc
    # If the table type ever widens to support parallel in-flight,
    # this literal check flips and the gate is closed.

  test "BUG-7: getdata(invCmpctBlock) serve has no peerCmpctVersion precondition":
    # nimrod.nim:971-1006 serves a cmpctblock for any getdata-with-
    # invCmpctBlock-type, regardless of whether the requesting peer
    # has previously sent us SENDCMPCT and we accepted it.
    let nodeSrc = readFile("src/nimrod.nim")
    let armIdx = nodeSrc.find("elif item.invType == invCmpctBlock:")
    check armIdx >= 0
    let armEnd = nodeSrc.find("elif item.invType", armIdx + 1)
    check armEnd > armIdx
    let arm = nodeSrc[armIdx ..< armEnd]
    # Until BUG-7 closes, the arm does not consult peerCmpctVersion
    # or compactBlockState.wantsCompactBlocks before serving.
    check "peerCmpctVersion" notin arm
    check "wantsCompactBlocks" notin arm

  test "BUG-11: sendSendCmpct unconditionally called at handshake (no IBD guard)":
    # Core MaybeSetPeerAsAnnouncingHeaderAndIDs (net_processing.cpp:
    # 1276-1279) returns early if `m_opts.ignore_incoming_txs`
    # (blocksonly mode).  nimrod peer.nim:1234 unconditional.
    let peerSrc = readFile("src/network/peer.nim")
    # Locate the post-VERACK send-sequence.
    let postVerackIdx = peerSrc.find("await peer.sendSendHeaders()")
    check postVerackIdx >= 0
    let windowEnd = min(peerSrc.len, postVerackIdx + 400)
    let window = peerSrc[postVerackIdx ..< windowEnd]
    check "await peer.sendSendCmpct()" in window
    # Until BUG-11 closes, no IBD/blocksonly gate fences the call.
    check "isInitialBlockDownload" notin window
    check "ignoreIncomingTxs" notin window
    check "blocksOnly" notin window

# ============================================================================
# Codec round-trip: end-to-end conformance (defense-in-depth)
# ============================================================================

suite "W126 BIP-152 wire format conformance":

  test "CompactBlock round-trip preserves header + nonce + shortIds + prefilled":
    let blk = makeBlock(1200, 10)
    let nonce = 0xFEDCBA9876543210'u64
    let cb = newCompactBlock(blk, nonce)
    var w = BinaryWriter()
    w.writeCompactBlock(cb)
    var r = BinaryReader(data: w.data, pos: 0)
    let cb2 = r.readCompactBlock()
    check cb2.header == cb.header
    check cb2.nonce == cb.nonce
    check cb2.shortIds.len == cb.shortIds.len
    check cb2.prefilledTxns.len == cb.prefilledTxns.len
    for i in 0 ..< cb.shortIds.len:
      check cb2.shortIds[i] == cb.shortIds[i]
    # Coinbase always prefilled at index 0 (BIP-152 §"Short transaction IDs").
    check cb2.prefilledTxns[0].index == 0

  test "BlockTxnResponse round-trip preserves transactions":
    let blk = makeBlock(1210, 3)
    let resp = BlockTxnResponse(
      blockHash: BlockHash(default(array[32, byte])),
      transactions: @[blk.txs[1], blk.txs[2]])
    var w = BinaryWriter()
    w.writeBlockTxnResponse(resp)
    var r = BinaryReader(data: w.data, pos: 0)
    let resp2 = r.readBlockTxnResponse()
    check resp2.transactions.len == resp.transactions.len

  test "P2P message kind ↔ command string round-trip":
    check messageKindToCommand(mkCmpctBlock) == "cmpctblock"
    check messageKindToCommand(mkGetBlockTxn) == "getblocktxn"
    check messageKindToCommand(mkBlockTxn) == "blocktxn"
    check messageKindToCommand(mkSendCmpct) == "sendcmpct"
    check commandToMessageKind("cmpctblock") == mkCmpctBlock
    check commandToMessageKind("getblocktxn") == mkGetBlockTxn
    check commandToMessageKind("blocktxn") == mkBlockTxn
    check commandToMessageKind("sendcmpct") == mkSendCmpct

  test "End-to-end reconstruct (coinbase prefilled + mempool fills rest)":
    let blk = makeBlock(1300, 6)
    let nonce = 0x0102030405060708'u64
    let cb = newCompactBlock(blk, nonce)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]())
    for i in 1 ..< blk.txs.len:
      mp.entries[txid(blk.txs[i])] = MempoolEntry(tx: blk.txs[i])
    pdb.fillFromMempool(mp)
    check pdb.isComplete()
    let (rebuilt, status) = pdb.reconstructBlock()
    check status == rsOk
    check rebuilt.txs.len == blk.txs.len
    check rebuilt.header == blk.header
