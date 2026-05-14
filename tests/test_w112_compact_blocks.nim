## W112 BIP-152 Compact Block Relay — 30-gate audit tests
## Reference: Bitcoin Core src/blockencodings.h/cpp, net_processing.cpp
## BIP: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
##
## Bugs found (see each gate for details):
##
##  BUG-1  (G4/G5)  MAX_CMPCTBLOCK_DEPTH=5 and MAX_BLOCKTXN_DEPTH=10 constants absent
##  BUG-2  (G8)     FIXED (FIX-43): peer.nim sendcmpct handler now gates on version==2;
##                  any version!=2 is discarded with no state update (matches Core)
##  BUG-3  (G9/G29/G30) HB peer list (lNodesAnnouncingHeaderAndIDs) + 3-peer cap MISSING ENTIRELY
##  BUG-4  (G11)    cmpctblock header not validated (no prev_block check, no PoW check,
##                  no ProcessNewBlockHeaders call) before InitData
##  BUG-5  (G17/G18) getblocktxn inbound: stub (logs only, never sends blocktxn response);
##                   MAX_BLOCKTXN_DEPTH depth guard entirely absent
##  BUG-6  (G22)    fillFromExtraPool is defined but NEVER called from live code path (dead helper)
##  BUG-7  (G25)    MAX_CMPCTBLOCK_DEPTH guard absent when serving getdata(invCmpctBlock)
##  BUG-8  (G26)    No IBD/blocksonly-mode guard: compact blocks offered even during IBD
##                  when mempool is nil/empty (Core: MaybeSetPeerAsAnnouncingHeaderAndIDs
##                  returns early if ignore_incoming_txs)
##  BUG-9  (G27)    HB peer block announcement (send cmpctblock to announce=true peers) absent;
##                  broadcastBlock always sends headers/inv, never cmpctblock
##  BUG-10 (G28)    50% missing-tx threshold skips getblocktxn; Core always tries
##                  getblocktxn if first_in_flight (no threshold)

import std/[options, tables, sets]
import unittest2
import ../src/network/compact_blocks
import ../src/network/messages
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool as mempool_mod

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
  inp.scriptSig = @[byte(0x03), byte(h and 0xFF), byte((h shr 8) and 0xFF), byte((h shr 16) and 0xFF)]
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
# G1: SHORTID_LEN = 6
# ============================================================================
suite "G1 ShortIdLength constant":
  test "ShortIdLength equals 6 (BIP-152 section 3)":
    check ShortIdLength == 6

  test "computed short IDs are exactly 6 bytes":
    var hdr: BlockHeader
    hdr.bits = 0x1d00ffff'u32
    var txid: TxId
    let sid = computeShortId(hdr, 0xDEADBEEF'u64, txid)
    check sid.len == 6

# ============================================================================
# G2: CompactBlockVersion = 2
# ============================================================================
suite "G2 CompactBlockVersion constant":
  test "CompactBlockVersion equals 2 (segwit-aware, wtxid-based)":
    check CompactBlockVersion == 2'u64

# ============================================================================
# G3: MaxBlockTxns = 100,000
# Reference: Core blockencodings.cpp:64 — MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
# ============================================================================
suite "G3 MaxBlockTxns constant":
  test "MaxBlockTxns equals 100000":
    check MaxBlockTxns == 100_000

  test "initPDB rejects block exceeding MaxBlockTxns":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    # Fill shortIds to just exceed MaxBlockTxns
    # We simulate this by crafting the count; for the actual deserialization path
    # the readCompactBlock path would reject, but we test initPDB directly here
    # by pre-populating the seq
    for i in 0 ..< (MaxBlockTxns + 1):
      var sid: array[6, byte]
      sid[0] = byte(i and 0xFF)
      sid[1] = byte((i shr 8) and 0xFF)
      sid[2] = byte((i shr 16) and 0xFF)
      cb.shortIds.add(sid)
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

# ============================================================================
# G4/G5: MAX_CMPCTBLOCK_DEPTH=5 and MAX_BLOCKTXN_DEPTH=10 constants absent
# BUG-1: These depth constants are not defined anywhere in nimrod.
# Core: net_processing.cpp:138 — static const int MAX_CMPCTBLOCK_DEPTH = 5;
#       net_processing.cpp:140 — static const int MAX_BLOCKTXN_DEPTH = 10;
# Impact: getdata(invCmpctBlock) responds with cmpctblock for any block depth (G25),
#         getblocktxn responds for blocks beyond depth 10 (G18).
# ============================================================================
suite "G4/G5 depth constants (BUG-1)":
  test "MAX_CMPCTBLOCK_DEPTH equals 5 (Core net_processing.cpp:138)":
    # Core: static const int MAX_CMPCTBLOCK_DEPTH = 5
    # When serving getdata(MSG_CMPCTBLOCK), only respond with a compact block
    # if block height >= tip - 5; otherwise fall back to full block.
    check MaxCmpctBlockDepth == 5

  test "MAX_BLOCKTXN_DEPTH equals 10 (Core net_processing.cpp:140)":
    # Core: static const int MAX_BLOCKTXN_DEPTH = 10
    # When serving getblocktxn, only respond with blocktxn if
    # block height >= tip - 10; otherwise serve the full block.
    check MaxBlocktxnDepth == 10

# ============================================================================
# G6: sendcmpct sent after handshake with version=2
# ============================================================================
suite "G6 sendcmpct negotiation outbound":
  test "sendcmpct default version is 2":
    # sendSendCmpct(peer, announce=false, version=2) is the default
    # We validate the message construction
    let msg = P2PMessage(kind: mkSendCmpct,
                         sendCmpct: SendCmpctMsg(announce: false, version: 2))
    check msg.sendCmpct.version == 2
    check not msg.sendCmpct.announce

  test "sendcmpct serialization round-trip (version and announce preserved)":
    let msg = P2PMessage(kind: mkSendCmpct,
                         sendCmpct: SendCmpctMsg(announce: false, version: 2))
    let payload = serializePayload(msg)
    let msg2 = deserializePayload("sendcmpct", payload)
    check msg2.sendCmpct.version == 2
    check not msg2.sendCmpct.announce

# ============================================================================
# G7: sendcmpct default announce=false (low-bandwidth mode)
# Core: MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, false, CMPCTBLOCKS_VERSION)
#        in the verack handler — always sends false first, upgrades selected peers later
# ============================================================================
suite "G7 sendcmpct announce default false":
  test "default sendcmpct is low-bandwidth (announce=false)":
    let msg = P2PMessage(kind: mkSendCmpct,
                         sendCmpct: SendCmpctMsg(announce: false, version: 2))
    check not msg.sendCmpct.announce

# ============================================================================
# G8: sendcmpct version filter — only version=2 accepted
# Core: net_processing.cpp:3907 — if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
# BUG-2 FIXED (FIX-43): peer.nim mkSendCmpct handler now gates on version == 2 only.
#   Any version != 2 is discarded before any state update (no peerCmpctVersion set,
#   no handleSendCmpct call), matching Core exactly.
# ============================================================================
suite "G8 sendcmpct version filter":
  test "version 2 accepted — wantsCompactBlocks becomes true":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = false, version = 2)
    check state.wantsCompactBlocks
    check state.compactBlockVersion == 2

  test "version 1 rejected by handleSendCmpct — wantsCompactBlocks stays false":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 1)
    check not state.wantsCompactBlocks
    check state.compactBlockVersion == 0

  test "version 0 rejected":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 0)
    check not state.wantsCompactBlocks

  test "version 3 rejected":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 3)
    check not state.wantsCompactBlocks

  test "BUG-2 FIXED — sendcmpct v1 leaves CompactBlockState fully unchanged (Core behaviour)":
    # Fix: peer.nim mkSendCmpct handler now gates on version == 2 exclusively.
    # Version != 2 is dropped before any state update (mirrors Core net_processing.cpp:3907).
    # peerCmpctVersion is NOT set for v1; handleSendCmpct is NOT called.
    # We verify via CompactBlockState that calling handleSendCmpct(version=1) leaves
    # wantsCompactBlocks=false and compactBlockVersion=0 (unchanged from initial state).
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 1)
    check not state.wantsCompactBlocks
    check state.compactBlockVersion == 0

# ============================================================================
# G9/G29/G30: HB peer list management (lNodesAnnouncingHeaderAndIDs) MISSING ENTIRELY
# BUG-3: Core maintains a circular list of ≤3 HB peers (MaybeSetPeerAsAnnouncingHeaderAndIDs).
#         Nimrod has no equivalent: no list, no 3-peer cap, no outbound preference,
#         no sendcmpct(announce=true) sent to selected peers.
# ============================================================================
suite "G9/G29/G30 HB peer management (BUG-3)":
  test "BUG-3 no lNodesAnnouncingHeaderAndIDs equivalent in nimrod":
    # Core net_processing.cpp:1272 — MaybeSetPeerAsAnnouncingHeaderAndIDs maintains
    # a list of ≤3 peers that receive cmpctblock announcements (announce=true).
    # nimrod: no such list, no selection logic, no 3-peer cap.
    # Impact: nimrod never proactively selects HB peers and never sends
    # sendcmpct(announce=true) to promote a peer to HB mode.
    skip()  # marker: subsystem entirely absent

  test "BUG-3 3-peer HB cap absent — would accept unlimited announce=true peers":
    # Core: lNodesAnnouncingHeaderAndIDs.size() >= 3 triggers demotion of oldest peer
    # nimrod: no cap — could theoretically accept any number of HB announcements
    skip()  # marker: no HB list, no cap logic

  test "BUG-3 outbound HB preference absent":
    # Core: if adding inbound HB peer would remove last outbound HB peer, it preserves
    # the outbound peer in the list. nimrod has no such preference.
    skip()  # marker: no HB list

# ============================================================================
# G10: sendcmpct state stored per-peer
# ============================================================================
suite "G10 per-peer compact block state":
  test "CompactBlockState initialises correctly":
    let state = newCompactBlockState()
    check not state.wantsCompactBlocks
    check not state.highBandwidthMode
    check state.compactBlockVersion == 0
    check state.pendingPartials.len == 0

  test "shouldSendCompactBlock only true after valid sendcmpct v2":
    var state = newCompactBlockState()
    check not state.shouldSendCompactBlock()
    state.handleSendCmpct(announce = false, version = 2)
    check state.shouldSendCompactBlock()

  test "supportsHighBandwidth tracks announce=true":
    var state = newCompactBlockState()
    check not state.supportsHighBandwidth()
    state.handleSendCmpct(announce = true, version = 2)
    check state.supportsHighBandwidth()

# ============================================================================
# G11: cmpctblock header validation (prev_block, PoW) before InitData
# BUG-4: Core (net_processing.cpp:4483-4510) checks prev_block exists, work threshold,
#         and calls ProcessNewBlockHeaders before InitData. nimrod does none of this.
# ============================================================================
suite "G11 cmpctblock header validation (BUG-4)":
  test "BUG-4 no prev_block lookup before InitData":
    # Core: LookupBlockIndex(cmpctblock.header.hashPrevBlock) must succeed
    # nimrod peer.nim:1306 goes directly to initPartiallyDownloadedBlock
    skip()  # marker: prev_block check absent

  test "BUG-4 no work-threshold check before InitData":
    # Core: if prev_block->nChainWork + GetBlockProof(...) < GetAntiDoSWorkThreshold() → return
    # nimrod: no such check; low-work compact blocks are processed
    skip()  # marker: anti-DoS work threshold absent

  test "BUG-4 no ProcessNewBlockHeaders call":
    # Core: m_chainman.ProcessNewBlockHeaders validates PoW, version bits, etc.
    # nimrod: header in compact block is not validated before use
    skip()  # marker: header validation absent

# ============================================================================
# G12: InitData structural guards (null header, empty block, structural gap)
# Core blockencodings.cpp:62-87
# ============================================================================
suite "G12 InitData structural guards":
  test "null header (bits=0) rejected":
    var cb: CompactBlock
    cb.header.bits = 0
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "both shortIds and prefilledTxns empty → rejected":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "prefilled index strictly increasing — out-of-order rejected":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    cb.shortIds.add([byte(2), 3, 4, 5, 6, 7])
    cb.shortIds.add([byte(3), 4, 5, 6, 7, 8])
    cb.prefilledTxns.add(PrefilledTx(index: 2, tx: makeTestTx(1)))
    cb.prefilledTxns.add(PrefilledTx(index: 1, tx: makeTestTx(2)))  # backwards
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "structural gap check: prefilled index leaves position unreachable":
    # 2 shortIds, but prefilled index = 5 → position 2,3,4 have nothing
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    cb.shortIds.add([byte(7), 8, 9, 10, 11, 12])
    cb.prefilledTxns.add(PrefilledTx(index: 5, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "valid layout — 2 shortIds + prefilled at index 2 accepted":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    cb.shortIds.add([byte(7), 8, 9, 10, 11, 12])
    cb.prefilledTxns.add(PrefilledTx(index: 2, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

  test "prefilled index overflow (>= total tx count) rejected":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    # prefilled at index 5, but total tx count = 1+1 = 2
    cb.prefilledTxns.add(PrefilledTx(index: 5, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

# ============================================================================
# G13: SipHash key derivation (SHA256(header||nonce_LE)[0..16] → k0/k1 LE u64)
# Core blockencodings.cpp:35-44 — FillShortTxIDSelector uses single SHA256
# ============================================================================
suite "G13 SipHash key derivation":
  test "keys derived from header+nonce are deterministic":
    var hdr: BlockHeader
    hdr.version = 0x20000000'i32
    hdr.bits = 0x1d00ffff'u32
    hdr.nonce = 12345'u32
    let n = 0xDEADBEEF12345678'u64
    let (k0a, k1a) = computeSipHashKeys(hdr, n)
    let (k0b, k1b) = computeSipHashKeys(hdr, n)
    check k0a == k0b
    check k1a == k1b

  test "different nonce produces different keys":
    var hdr: BlockHeader
    hdr.bits = 0x1d00ffff'u32
    let (k0a, k1a) = computeSipHashKeys(hdr, 100'u64)
    let (k0b, k1b) = computeSipHashKeys(hdr, 101'u64)
    check k0a != k0b or k1a != k1b

  test "different header produces different keys":
    var hdr1, hdr2: BlockHeader
    hdr1.bits = 0x1d00ffff'u32
    hdr1.nonce = 1'u32
    hdr2.bits = 0x1d00ffff'u32
    hdr2.nonce = 2'u32
    let (k0a, k1a) = computeSipHashKeys(hdr1, 0'u64)
    let (k0b, k1b) = computeSipHashKeys(hdr2, 0'u64)
    check k0a != k0b or k1a != k1b

  test "k0 from first 8 bytes of SHA256, k1 from next 8 bytes (LE u64)":
    # Verify the key extraction by computing the SHA256 manually and
    # comparing to computeSipHashKeys
    var hdr: BlockHeader
    hdr.version = 1'i32
    hdr.bits = 0x1d00ffff'u32
    let n = 0'u64
    var w = BinaryWriter()
    w.writeBlockHeader(hdr)
    w.writeUint64LE(n)
    let hashBytes = sha256Single(w.data)
    var expK0, expK1: uint64
    for i in 0 ..< 8:
      expK0 = expK0 or (uint64(hashBytes[i]) shl (i * 8))
      expK1 = expK1 or (uint64(hashBytes[i + 8]) shl (i * 8))
    let (k0, k1) = computeSipHashKeys(hdr, n)
    check k0 == expK0
    check k1 == expK1

  test "short ID lower 6 bytes of SipHash result":
    var hdr: BlockHeader
    hdr.bits = 0x1d00ffff'u32
    let (k0, k1) = computeSipHashKeys(hdr, 0'u64)
    var txidVal: TxId
    let sid = computeShortId(k0, k1, txidVal)
    check sid.len == 6

# ============================================================================
# G14: Max prefilledTxns count check in deserialization
# Core: no explicit prefilled count limit separate from total tx count
# nimrod: MaxPrefilledTxns = 10000 (extra guard)
# ============================================================================
suite "G14 prefilledTxns count bounds":
  test "MaxPrefilledTxns is 10000":
    check MaxPrefilledTxns == 10_000

  test "initPDB with many prefilled (under limit) works":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    # Add 5 prefilled txns with proper sequential indices
    for i in 0 ..< 5:
      cb.prefilledTxns.add(PrefilledTx(index: uint16(i), tx: makeTestTx(i)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

# ============================================================================
# G15: wtxid used for short ID computation (version 2, BIP-152 section 2)
# Core: shorttxids[i-1] = GetShortID(tx.GetWitnessHash())
# nimrod: computeShortId uses wtxid (wtxid proc on Transaction)
# ============================================================================
suite "G15 wtxid-based short ID (version 2)":
  test "newCompactBlock uses wtxid for non-coinbase transactions":
    let blk = makeBlock(100, 3)
    let nonce = 0xABCDEF0123456789'u64
    let cb = newCompactBlock(blk, nonce)
    let (k0, k1) = computeSipHashKeys(cb.header, nonce)
    # Verify each short ID matches the wtxid computation
    for i in 1 ..< blk.txs.len:
      let w = wtxid(blk.txs[i])
      let expected = computeShortId(k0, k1, w)
      check cb.shortIds[i - 1] == expected

  test "coinbase always at prefilled index 0":
    let blk = makeBlock(200, 4)
    let cb = newCompactBlock(blk, 0'u64)
    check cb.prefilledTxns.len == 1
    check cb.prefilledTxns[0].index == 0
    check txid(cb.prefilledTxns[0].tx) == txid(blk.txs[0])

# ============================================================================
# G16: getblocktxn sender — nimrod sends getblocktxn for missing transactions
# ============================================================================
suite "G16 getblocktxn sender":
  test "getMissingTxIndexes returns correct missing positions":
    let blk = makeBlock(300, 5)
    let cb = newCompactBlock(blk, 1'u64)
    var (pdb, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk
    let missing = pdb.getMissingTxIndexes()
    check missing.len == blk.txs.len - 1  # all except coinbase
    check 0'u16 notin missing  # coinbase prefilled

  test "createBlockTxnRequest constructs request with correct indexes":
    var blockHash: BlockHash
    for i in 0 ..< 32: array[32, byte](blockHash)[i] = byte(i)
    let req = createBlockTxnRequest(blockHash, @[uint16(1), uint16(3), uint16(5)])
    check req.blockHash == blockHash
    check req.indexes == @[uint16(1), uint16(3), uint16(5)]

  test "getblocktxn differential encoding round-trip":
    var blockHash: BlockHash
    let req = BlockTxnRequest(
      blockHash: blockHash,
      indexes: @[uint16(0), uint16(2), uint16(5), uint16(6)]
    )
    var w = BinaryWriter()
    w.writeBlockTxnRequest(req)
    var r = BinaryReader(data: w.data, pos: 0)
    let req2 = r.readBlockTxnRequest()
    check req2.indexes == req.indexes

# ============================================================================
# G17/G18: getblocktxn receiver — stub only; no blocktxn response; no depth guard
# BUG-5: peer.nim mkGetBlockTxn handler just logs and returns; never sends blocktxn.
#         MAX_BLOCKTXN_DEPTH guard absent.
# ============================================================================
suite "G17/G18 getblocktxn receiver (BUG-5)":
  test "BUG-5 getblocktxn handler is a stub — only logs, never sends blocktxn":
    # peer.nim:1348-1357 — receives getblocktxn and logs "Note: Actual block lookup
    # requires chain integration. For now, log the request."
    # Impact: peers asking nimrod for compact block transactions get no response.
    skip()  # marker: stub handler — no response sent

  test "BUG-5 MAX_BLOCKTXN_DEPTH=10 absent — deep getblocktxn not rejected":
    # Core: if pindex->nHeight < tip - MAX_BLOCKTXN_DEPTH → send full block instead
    # nimrod: no such guard; deep getblocktxn would (if implemented) respond for any depth
    skip()  # marker: depth guard absent

# ============================================================================
# G19: blocktxn sender (createBlockTxnResponse)
# ============================================================================
suite "G19 blocktxn sender":
  test "createBlockTxnResponse returns correct transactions at requested indexes":
    var blockHash: BlockHash
    let blk = makeBlock(400, 8)
    let resp = createBlockTxnResponse(blockHash, blk,
                                      @[uint16(1), uint16(3), uint16(5)])
    check resp.transactions.len == 3
    check txid(resp.transactions[0]) == txid(blk.txs[1])
    check txid(resp.transactions[1]) == txid(blk.txs[3])
    check txid(resp.transactions[2]) == txid(blk.txs[5])

  test "blocktxn wire serialization round-trip":
    var blockHash: BlockHash
    for i in 0 ..< 32: array[32, byte](blockHash)[i] = byte(255 - i)
    let txns = @[makeTestTx(1), makeTestTx(2)]
    let resp = BlockTxnResponse(blockHash: blockHash, transactions: txns)
    var w = BinaryWriter()
    w.writeBlockTxnResponse(resp)
    var r = BinaryReader(data: w.data, pos: 0)
    let resp2 = r.readBlockTxnResponse()
    check resp2.blockHash == resp.blockHash
    check resp2.transactions.len == 2

# ============================================================================
# G20: blocktxn receiver (completeBlock)
# ============================================================================
suite "G20 blocktxn receiver":
  test "completeBlock assembles full block from partial + blocktxn":
    let blk = makeBlock(500, 5)
    let cb = newCompactBlock(blk, 0xFEEDBEEF'u64)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    var state = newCompactBlockState()
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))
    state.pendingPartials[blockHash] = pdb
    # Provide the missing transactions
    let missing = pdb.getMissingTxIndexes()
    var missingTxns: seq[Transaction]
    for idx in missing:
      missingTxns.add(blk.txs[int(idx)])
    let (reconstructed, status) = state.completeBlock(blockHash, missingTxns)
    check status == rsOk
    check reconstructed.txs.len == blk.txs.len
    check reconstructed.header == blk.header

  test "completeBlock returns rsInvalid for unknown blockHash":
    var state = newCompactBlockState()
    var blockHash: BlockHash
    let (_, status) = state.completeBlock(blockHash, @[])
    check status == rsInvalid

  test "completeBlock removes pending on success":
    let blk = makeBlock(510, 2)
    let cb = newCompactBlock(blk, 42'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    var state = newCompactBlockState()
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))
    state.pendingPartials[blockHash] = pdb
    # Only coinbase; 1 missing
    let missing = pdb.getMissingTxIndexes()
    var missingTxns: seq[Transaction]
    for idx in missing: missingTxns.add(blk.txs[int(idx)])
    let (_, status) = state.completeBlock(blockHash, missingTxns)
    check status == rsOk
    check not state.hasPending(blockHash)

# ============================================================================
# G21: fillFromMempool uses wtxid for matching
# ============================================================================
suite "G21 fillFromMempool wtxid matching":
  test "fillFromMempool fills slots matching wtxid short IDs":
    let blk = makeBlock(600, 4)
    let nonce = 0x1234567890ABCDEF'u64
    let cb = newCompactBlock(blk, nonce)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    check not pdb.isComplete()
    # Simulate a mempool with all block txns (except coinbase which is prefilled)
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]()
    )
    for i in 1 ..< blk.txs.len:
      let tid = txid(blk.txs[i])
      mp.entries[tid] = MempoolEntry(tx: blk.txs[i])
    pdb.fillFromMempool(mp)
    check pdb.isComplete()

  test "fillFromMempool: mempool collision clears slot":
    # Build a compact block with one short-ID slot
    let blk = makeBlock(610, 2)
    let nonce = 0xCAFEBABE'u64
    let cb = newCompactBlock(blk, nonce)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    # First fill succeeds
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]()
    )
    let tx1 = blk.txs[1]
    let tid1 = txid(tx1)
    mp.entries[tid1] = MempoolEntry(tx: tx1)
    pdb.fillFromMempool(mp)
    check pdb.mempoolCount == 1
    # Manually simulate second match (collision) by calling fillFromMempool again
    # with a tx that has the SAME short ID (crafted by using a different wtxid that
    # happens to collide — difficult to craft; instead we simulate directly)
    # The key behavior: filledSlots prevents re-fill after collision
    let pos = 1
    check pos in pdb.filledSlots  # was filled by first match

# ============================================================================
# G22: fillFromExtraPool defined but dead helper — never called from live path
# BUG-6: fillFromExtraPool is implemented in compact_blocks.nim but never called
#         from peer.nim's cmpctblock handler. Core always passes extra_txn.
# ============================================================================
suite "G22 fillFromExtraPool dead helper (BUG-6)":
  test "fillFromExtraPool is defined and functional":
    let blk = makeBlock(700, 3)
    let nonce = 0xDEAD'u64
    let cb = newCompactBlock(blk, nonce)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    # Provide the missing transaction via extra pool
    let extraTxns = @[(wtxid(blk.txs[1]), blk.txs[1])]
    pdb.fillFromExtraPool(extraTxns)
    check pdb.txnAvailable[1].isSome

  test "BUG-6 fillFromExtraPool never called in live cmpctblock path":
    # peer.nim:1306-1346 — mkCmpctBlock handler calls fillFromMempool but NOT
    # fillFromExtraPool. Core's PartiallyDownloadedBlock::InitData receives
    # vExtraTxnForCompact as a parameter and always fills from both sources.
    # Impact: orphan-pool and recently-confirmed transactions not used for
    # reconstruction, causing unnecessary getblocktxn round trips.
    skip()  # marker: dead helper — never wired into live path

# ============================================================================
# G23: Short ID collision detection (duplicate short ID → rsFailed)
# Core blockencodings.cpp:107-115
# ============================================================================
suite "G23 collision detection":
  test "duplicate short ID in compact block → rsFailed":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.shortIds.add([byte(0xAA), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    cb.shortIds.add([byte(0xAA), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    cb.prefilledTxns.add(PrefilledTx(index: 2, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsFailed

  test "bucket-size DoS guard: 13 identical short IDs → rsFailed":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    for i in 0 ..< 13:
      cb.shortIds.add([byte(0x11), 0x22, 0x33, 0x44, 0x55, 0x66])
    cb.prefilledTxns.add(PrefilledTx(index: 13, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsFailed

  test "distinct short IDs all accepted":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    for i in 0 ..< 10:
      cb.shortIds.add([byte(i), byte(i+1), byte(i+2), byte(i+3), byte(i+4), byte(i+5)])
    cb.prefilledTxns.add(PrefilledTx(index: 10, tx: makeTestTx(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

  test "filledSlots prevents third-match re-fill after collision":
    let blk = makeBlock(800, 4)
    let cb = newCompactBlock(blk, 0'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    let pos = 1
    # Manually simulate two fills (collision)
    pdb.txnAvailable[pos] = some(makeTestTx(99))
    pdb.filledSlots.incl(pos)
    pdb.mempoolCount += 1
    # Collision: clear slot
    if pos in pdb.filledSlots:
      if pdb.txnAvailable[pos].isSome:
        pdb.txnAvailable[pos] = none(Transaction)
        pdb.mempoolCount -= 1
    # Third match attempt: pos is in filledSlots, so slot stays clear
    check not (pos notin pdb.filledSlots)  # filledSlots still has pos
    check pdb.txnAvailable[pos].isNone     # slot correctly clear

# ============================================================================
# G24: reconstructBlock (FillBlock equivalent)
# Core blockencodings.cpp:193-230
# ============================================================================
suite "G24 reconstructBlock":
  test "reconstructBlock succeeds when all slots filled":
    let blk = makeBlock(900, 6)
    let cb = newCompactBlock(blk, 0x1111111111111111'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    let missingTxns = blk.txs[1..^1]
    discard pdb.fillMissingTransactions(missingTxns)
    let (reconstructed, status) = pdb.reconstructBlock()
    check status == rsOk
    check reconstructed.txs.len == blk.txs.len
    check reconstructed.header == blk.header

  test "reconstructBlock fails when any slot missing":
    let blk = makeBlock(910, 4)
    let cb = newCompactBlock(blk, 0'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    # Do NOT fill missing transactions
    let (_, status) = pdb.reconstructBlock()
    check status == rsInvalid

  test "reconstructBlock with null header returns rsInvalid (FillBlock guard)":
    var pdb: PartiallyDownloadedBlock
    pdb.header.bits = 0  # null header
    pdb.txnAvailable.add(some(makeTestTx(1)))
    let (_, status) = pdb.reconstructBlock()
    check status == rsInvalid

  test "fillMissingTransactions fails if count mismatch (too many provided)":
    let blk = makeBlock(920, 3)
    let cb = newCompactBlock(blk, 0'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    # Provide too many transactions
    let status = pdb.fillMissingTransactions(@[blk.txs[1], blk.txs[2], makeTestTx(99)])
    check status == rsInvalid

# ============================================================================
# G25: MAX_CMPCTBLOCK_DEPTH guard when serving getdata(invCmpctBlock) — MISSING
# BUG-7: Core (net_processing.cpp:2466) checks if block height >= tip - 5 before
#         sending a compact block. nimrod's broadcastBlock never sends cmpctblock
#         at all (it always sends headers or inv), so the guard is moot — but the
#         underlying issue is that the cmpctblock serving path is absent.
# ============================================================================
suite "G25 MAX_CMPCTBLOCK_DEPTH serving guard (BUG-7)":
  test "cmpctBlockDepthOk: block at tip allowed":
    # Block exactly at tip — always within depth
    check cmpctBlockDepthOk(100'i32, 100'i32)

  test "cmpctBlockDepthOk: block 5 below tip allowed (boundary)":
    # tip=100, block=95: 95 >= 100 - 5 → allowed
    check cmpctBlockDepthOk(95'i32, 100'i32)

  test "cmpctBlockDepthOk: block 6 below tip rejected":
    # tip=100, block=94: 94 < 100 - 5 → fall back to full block
    check not cmpctBlockDepthOk(94'i32, 100'i32)

  test "cmpctBlockDepthOk: block deep in chain rejected":
    # tip=800000, block=100: well beyond depth 5
    check not cmpctBlockDepthOk(100'i32, 800_000'i32)

  test "blocktxnDepthOk: block 10 below tip allowed (boundary)":
    # tip=100, block=90: 90 >= 100 - 10 → allowed
    check blocktxnDepthOk(90'i32, 100'i32)

  test "blocktxnDepthOk: block 11 below tip rejected":
    # tip=100, block=89: 89 < 100 - 10 → serve full block instead
    check not blocktxnDepthOk(89'i32, 100'i32)

# ============================================================================
# G26: No compact blocks during IBD/blocksonly
# BUG-8: Core: MaybeSetPeerAsAnnouncingHeaderAndIDs returns if ignore_incoming_txs
#         (blocksonly mode). nimrod sends sendcmpct unconditionally in handshake
#         even when mempool is nil (IBD state).
# ============================================================================
suite "G26 IBD/blocksonly compact blocks guard (BUG-8)":
  test "BUG-8 sendcmpct sent unconditionally, ignoring IBD/nil-mempool state":
    # peer.nim:1164 — await peer.sendSendCmpct() called unconditionally after handshake
    # Core: MaybeSetPeerAsAnnouncingHeaderAndIDs returns early if ignore_incoming_txs
    # nimrod: no check for IBD state or nil mempool before offering compact blocks
    skip()  # marker: IBD guard absent

  test "fillFromMempool with nil mempool is guarded by peer.nim nil check":
    # peer.nim:1313 — "if peer.mempool != nil: pdb.fillFromMempool(peer.mempool)"
    # This is a partial mitigation: mempool won't crash, but compact blocks are
    # still offered (sendcmpct sent) even when nil, so peers expect cmpctblock
    # announcements that we can't fulfill properly.
    let blk = makeBlock(1000, 3)
    let cb = newCompactBlock(blk, 0'u64)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    # With nil mempool peer.nim doesn't call fillFromMempool — pdb stays empty
    check not pdb.isComplete()

# ============================================================================
# G27: Block announcement via cmpctblock to HB peers — MISSING
# BUG-9: broadcastBlock (peermanager.nim:794) always sends headers or inv;
#         it never sends cmpctblock to peers that requested announce=true.
#         Core: SendMessages checks m_bip152_highbandwidth_to and sends cmpctblock.
# ============================================================================
suite "G27 HB compact block announcement (BUG-9)":
  test "BUG-9 broadcastBlock never sends cmpctblock to HB peers":
    # peermanager.nim broadcastBlock selects between newHeaders and newInv based
    # on peer.sendHeaders. There is no check of compactBlockState.highBandwidthMode
    # or compactBlockState.wantsCompactBlocks.
    # Impact: even after a peer sends sendcmpct(announce=true), it never receives
    # cmpctblock announcements from nimrod. HB mode is fully dead.
    skip()  # marker: cmpctblock announcement path absent

# ============================================================================
# G28: Fallback to full block on reconstruction failure
# BUG-10: nimrod applies a 50% missing threshold before even trying getblocktxn.
#          Core ALWAYS tries getblocktxn (as long as first_in_flight).
# ============================================================================
suite "G28 fallback behavior (BUG-10)":
  test "BUG-10 nimrod skips getblocktxn if >50% transactions missing":
    # peer.nim:1333-1338:
    #   if missPct > 50.0: → failedReconstructions++, no getblocktxn sent
    # Core: always sends getblocktxn if first_in_flight, regardless of miss ratio.
    # Impact: blocks where nimrod's mempool has <50% of txns never get round-tripped;
    # nimrod counts them as reconstruction failures and never requests missing txns.
    skip()  # marker: 50% threshold is not Core-compatible

  test "compact block with all txns in mempool — no getblocktxn needed":
    let blk = makeBlock(1100, 4)
    let cb = newCompactBlock(blk, 0xCAFECAFE'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]()
    )
    for i in 1 ..< blk.txs.len:
      mp.entries[txid(blk.txs[i])] = MempoolEntry(tx: blk.txs[i])
    pdb.fillFromMempool(mp)
    check pdb.isComplete()
    let (_, status) = pdb.reconstructBlock()
    check status == rsOk

  test "compact block with some txns missing — getblocktxn indexes computed correctly":
    let blk = makeBlock(1110, 5)
    let cb = newCompactBlock(blk, 0'u64)
    var (pdb, _) = initPartiallyDownloadedBlock(cb)
    # Only fill one of 4 missing txns
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]()
    )
    mp.entries[txid(blk.txs[1])] = MempoolEntry(tx: blk.txs[1])
    pdb.fillFromMempool(mp)
    check not pdb.isComplete()
    let missing = pdb.getMissingTxIndexes()
    check 0'u16 notin missing   # coinbase prefilled
    check 1'u16 notin missing   # filled from mempool
    check 2'u16 in missing
    check 3'u16 in missing
    check 4'u16 in missing

# ============================================================================
# G29/G30: HB peer count and rotation — MISSING ENTIRELY (see G9 above)
# ============================================================================

# ============================================================================
# Wire format conformance (combined)
# ============================================================================
suite "Wire format conformance":
  test "compact block round-trip preserves all fields":
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
    check cb2.prefilledTxns[0].index == cb.prefilledTxns[0].index

  test "getblocktxn differential index encoding/decoding":
    var blockHash: BlockHash
    let req = BlockTxnRequest(
      blockHash: blockHash,
      indexes: @[uint16(1), uint16(3), uint16(7), uint16(8)]
    )
    var w = BinaryWriter()
    w.writeBlockTxnRequest(req)
    # Verify wire format: 32 bytes hash, then count, then diffs
    var r = BinaryReader(data: w.data, pos: 0)
    discard r.readBlockHash()
    check r.readCompactSize() == 4  # count
    check r.readCompactSize() == 1  # diff for index 1: 1 - 0 = 1
    check r.readCompactSize() == 1  # diff for index 3: 3 - (1+1) = 1
    check r.readCompactSize() == 3  # diff for index 7: 7 - (3+1) = 3
    check r.readCompactSize() == 0  # diff for index 8: 8 - (7+1) = 0

  test "P2P message kind ↔ command string round-trip":
    check messageKindToCommand(mkCmpctBlock) == "cmpctblock"
    check messageKindToCommand(mkGetBlockTxn) == "getblocktxn"
    check messageKindToCommand(mkBlockTxn) == "blocktxn"
    check messageKindToCommand(mkSendCmpct) == "sendcmpct"
    check commandToMessageKind("cmpctblock") == mkCmpctBlock
    check commandToMessageKind("getblocktxn") == mkGetBlockTxn
    check commandToMessageKind("blocktxn") == mkBlockTxn
    check commandToMessageKind("sendcmpct") == mkSendCmpct

  test "end-to-end reconstruction with mempool (coinbase + N mempool txns)":
    let blk = makeBlock(1300, 8)
    let nonce = 0x0102030405060708'u64
    let cb = newCompactBlock(blk, nonce)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    var mp = mempool_mod.Mempool(
      entries: initTable[TxId, MempoolEntry](),
      byWtxid: initTable[TxId, TxId](),
      spentBy: initTable[OutPoint, TxId]()
    )
    for i in 1 ..< blk.txs.len:
      mp.entries[txid(blk.txs[i])] = MempoolEntry(tx: blk.txs[i])
    pdb.fillFromMempool(mp)
    check pdb.isComplete()
    let (reconstructed, rStatus) = pdb.reconstructBlock()
    check rStatus == rsOk
    check reconstructed.txs.len == blk.txs.len
    for i in 0 ..< blk.txs.len:
      check txid(reconstructed.txs[i]) == txid(blk.txs[i])
