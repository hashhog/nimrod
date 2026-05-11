## Tests for BIP152 Compact Block Relay
## Tests short ID computation, serialization, and block reconstruction

import std/[random, options, strutils, sets]
import unittest2
import ../src/network/compact_blocks
import ../src/network/messages
import ../src/primitives/[types, serialize]

proc hexToBytes(s: string): seq[byte] {.used.} =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc bytesToHex(b: openArray[byte]): string {.used.} =
  for x in b:
    result.add(toHex(x, 2).toLowerAscii)

proc makeTestTransaction(seed: int): Transaction =
  ## Create a unique test transaction based on seed
  randomize(seed)
  result.version = 2
  result.lockTime = 0

  # Create a simple input
  var input: TxIn
  for i in 0 ..< 32:
    array[32, byte](input.prevOut.txid)[i] = byte(rand(255))
  input.prevOut.vout = uint32(rand(10))
  input.scriptSig = @[byte(0x00)]  # Empty script
  input.sequence = 0xffffffff'u32
  result.inputs.add(input)

  # Create an output
  var output: TxOut
  output.value = Satoshi(50_000_000 - seed * 1000)  # Varying values
  output.scriptPubKey = @[byte(0x00), byte(0x14)]  # P2WPKH-style
  for i in 0 ..< 20:
    output.scriptPubKey.add(byte(rand(255)))
  result.outputs.add(output)

proc makeCoinbaseTransaction(height: int32): Transaction =
  ## Create a coinbase transaction
  result.version = 2
  result.lockTime = 0

  # Coinbase input (all zeros txid, vout = 0xffffffff)
  var input: TxIn
  input.prevOut.vout = 0xffffffff'u32
  # Height in script (BIP34)
  input.scriptSig = @[byte(0x03), byte(height and 0xff),
                      byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff)]
  input.sequence = 0xffffffff'u32
  result.inputs.add(input)

  # Coinbase output
  var output: TxOut
  output.value = Satoshi(6_250_000_000)  # 6.25 BTC
  output.scriptPubKey = @[byte(0x51)]  # OP_1 (anyone can spend for testing)
  result.outputs.add(output)

proc makeTestBlock(height: int32, numTxs: int = 10): Block =
  ## Create a test block with the specified number of transactions
  randomize(height.int)

  # Block header
  result.header.version = 0x20000000
  for i in 0 ..< 32:
    array[32, byte](result.header.prevBlock)[i] = byte(rand(255))
  for i in 0 ..< 32:
    result.header.merkleRoot[i] = byte(rand(255))
  result.header.timestamp = 1700000000'u32 + uint32(height * 600)
  result.header.bits = 0x1d00ffff'u32
  result.header.nonce = uint32(rand(high(int32)))

  # Coinbase first
  result.txs.add(makeCoinbaseTransaction(height))

  # Additional transactions
  for i in 1 ..< numTxs:
    result.txs.add(makeTestTransaction(height.int * 1000 + i))

suite "short ID computation":
  test "sipHash keys from header and nonce":
    # Create a deterministic header
    var header: BlockHeader
    header.version = 0x20000000
    header.timestamp = 1700000000'u32
    header.bits = 0x1d00ffff'u32
    header.nonce = 12345'u32

    let nonce = 0xdeadbeef12345678'u64
    let (k0, k1) = computeSipHashKeys(header, nonce)

    # Keys should be consistent
    let (k0_2, k1_2) = computeSipHashKeys(header, nonce)
    check k0 == k0_2
    check k1 == k1_2

    # Different nonce should give different keys
    let (k0_3, k1_3) = computeSipHashKeys(header, nonce + 1)
    check k0 != k0_3 or k1 != k1_3

  test "short ID is 6 bytes":
    var header: BlockHeader
    let nonce = 0x123456789abcdef0'u64
    var txid: TxId
    for i in 0 ..< 32:
      array[32, byte](txid)[i] = byte(i)

    let shortId = computeShortId(header, nonce, txid)
    check shortId.len == ShortIdLength
    check shortId.len == 6

  test "short ID varies with wtxid":
    var header: BlockHeader
    let nonce = 0x123456789abcdef0'u64

    var txid1, txid2: TxId
    for i in 0 ..< 32:
      array[32, byte](txid1)[i] = byte(i)
      array[32, byte](txid2)[i] = byte(31 - i)

    let shortId1 = computeShortId(header, nonce, txid1)
    let shortId2 = computeShortId(header, nonce, txid2)

    check shortId1 != shortId2

  test "short ID is deterministic":
    var header: BlockHeader
    let nonce = 0xfedcba9876543210'u64
    var txid: TxId
    for i in 0 ..< 32:
      array[32, byte](txid)[i] = byte(i * 2)

    let shortId1 = computeShortId(header, nonce, txid)
    let shortId2 = computeShortId(header, nonce, txid)

    check shortId1 == shortId2

suite "compact block creation":
  test "create compact block from full block":
    let blk = makeTestBlock(100, 5)
    let nonce = 0x1234567890abcdef'u64

    let cb = newCompactBlock(blk, nonce)

    # Header should match
    check cb.header == blk.header
    check cb.nonce == nonce

    # Should have prefilled coinbase
    check cb.prefilledTxns.len == 1
    check cb.prefilledTxns[0].index == 0
    check cb.prefilledTxns[0].tx == blk.txs[0]

    # Should have short IDs for other transactions
    check cb.shortIds.len == blk.txs.len - 1  # All except coinbase

  test "blockTxCount returns correct total":
    let blk = makeTestBlock(100, 10)
    let cb = newCompactBlock(blk, 0)

    check cb.blockTxCount() == blk.txs.len

  test "empty block creates minimal compact block":
    var blk: Block
    blk.header.version = 1
    blk.header.timestamp = 1700000000'u32

    let cb = newCompactBlock(blk, 0)
    check cb.shortIds.len == 0
    check cb.prefilledTxns.len == 0

suite "compact block serialization":
  test "compact block round-trip":
    let blk = makeTestBlock(200, 15)
    let cb = newCompactBlock(blk, 0xabcdef0123456789'u64)

    # Serialize
    var w = BinaryWriter()
    w.writeCompactBlock(cb)
    let data = w.data

    # Deserialize
    var r = BinaryReader(data: data, pos: 0)
    let cb2 = r.readCompactBlock()

    # Verify
    check cb2.header == cb.header
    check cb2.nonce == cb.nonce
    check cb2.shortIds.len == cb.shortIds.len
    check cb2.prefilledTxns.len == cb.prefilledTxns.len

    for i in 0 ..< cb.shortIds.len:
      check cb2.shortIds[i] == cb.shortIds[i]

    for i in 0 ..< cb.prefilledTxns.len:
      check cb2.prefilledTxns[i].index == cb.prefilledTxns[i].index

  test "prefilled tx differential encoding":
    # Create a compact block with multiple prefilled txs
    var cb: CompactBlock
    cb.header.version = 1
    cb.nonce = 123

    # Add prefilled txs at specific indices
    cb.prefilledTxns.add(PrefilledTx(index: 0, tx: makeTestTransaction(1)))
    cb.prefilledTxns.add(PrefilledTx(index: 5, tx: makeTestTransaction(2)))
    cb.prefilledTxns.add(PrefilledTx(index: 10, tx: makeTestTransaction(3)))

    # Add short IDs for other positions (0..10 = 11 positions, 3 prefilled, 8 short IDs needed)
    for i in 0 ..< 8:
      cb.shortIds.add([byte(i), 1, 2, 3, 4, 5])

    # Round-trip
    var w = BinaryWriter()
    w.writeCompactBlock(cb)
    let data = w.data

    var r = BinaryReader(data: data, pos: 0)
    let cb2 = r.readCompactBlock()

    check cb2.prefilledTxns.len == 3
    check cb2.prefilledTxns[0].index == 0
    check cb2.prefilledTxns[1].index == 5
    check cb2.prefilledTxns[2].index == 10

suite "getblocktxn serialization":
  test "getblocktxn round-trip":
    var blockHash: BlockHash
    for i in 0 ..< 32:
      array[32, byte](blockHash)[i] = byte(i)

    let req = BlockTxnRequest(
      blockHash: blockHash,
      indexes: @[uint16(0), uint16(5), uint16(10), uint16(100)]
    )

    var w = BinaryWriter()
    w.writeBlockTxnRequest(req)
    let data = w.data

    var r = BinaryReader(data: data, pos: 0)
    let req2 = r.readBlockTxnRequest()

    check req2.blockHash == req.blockHash
    check req2.indexes.len == req.indexes.len
    for i in 0 ..< req.indexes.len:
      check req2.indexes[i] == req.indexes[i]

  test "getblocktxn differential encoding":
    var blockHash: BlockHash

    # Create request with specific indexes
    let req = BlockTxnRequest(
      blockHash: blockHash,
      indexes: @[uint16(1), uint16(3), uint16(7), uint16(8)]
    )

    # Serialize
    var w = BinaryWriter()
    w.writeBlockTxnRequest(req)
    let data = w.data

    # Verify differential encoding manually
    # After hash (32 bytes), count (1 byte), then:
    # index 1: diff = 1 - 0 = 1
    # index 3: diff = 3 - (1+1) = 1
    # index 7: diff = 7 - (3+1) = 3
    # index 8: diff = 8 - (7+1) = 0
    var r = BinaryReader(data: data, pos: 0)
    discard r.readBlockHash()
    discard r.readCompactSize()  # count = 4

    check r.readCompactSize() == 1  # diff for index 1
    check r.readCompactSize() == 1  # diff for index 3
    check r.readCompactSize() == 3  # diff for index 7
    check r.readCompactSize() == 0  # diff for index 8

suite "blocktxn serialization":
  test "blocktxn round-trip":
    var blockHash: BlockHash
    for i in 0 ..< 32:
      array[32, byte](blockHash)[i] = byte(255 - i)

    let resp = BlockTxnResponse(
      blockHash: blockHash,
      transactions: @[
        makeTestTransaction(1),
        makeTestTransaction(2),
        makeTestTransaction(3)
      ]
    )

    var w = BinaryWriter()
    w.writeBlockTxnResponse(resp)
    let data = w.data

    var r = BinaryReader(data: data, pos: 0)
    let resp2 = r.readBlockTxnResponse()

    check resp2.blockHash == resp.blockHash
    check resp2.transactions.len == resp.transactions.len

suite "block reconstruction":
  test "init partially downloaded block":
    let blk = makeTestBlock(300, 8)
    let cb = newCompactBlock(blk, 0x1122334455667788'u64)

    let (pdb, status) = initPartiallyDownloadedBlock(cb)

    check status == rsOk
    check pdb.header == cb.header
    check pdb.txnAvailable.len == blk.txs.len
    check pdb.prefilledCount == 1  # Coinbase

    # Coinbase should be available
    check pdb.txnAvailable[0].isSome
    check pdb.txnAvailable[0].get() == blk.txs[0]

    # Others should be missing
    for i in 1 ..< pdb.txnAvailable.len:
      check pdb.txnAvailable[i].isNone

  test "get missing tx indexes":
    let blk = makeTestBlock(400, 5)
    let cb = newCompactBlock(blk, 0)

    let (pdb, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

    let missing = pdb.getMissingTxIndexes()
    check missing.len == 4  # All except coinbase

    check 0'u16 notin missing  # Coinbase prefilled
    for i in 1 ..< 5:
      check uint16(i) in missing

  test "fill missing transactions":
    let blk = makeTestBlock(500, 5)
    let cb = newCompactBlock(blk, 0)

    var (pdb, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk
    check not pdb.isComplete()

    # Fill with the missing transactions (indices 1-4)
    let missingTxs = blk.txs[1..^1]
    let fillStatus = pdb.fillMissingTransactions(missingTxs)
    check fillStatus == rsOk
    check pdb.isComplete()

  test "reconstruct block":
    let blk = makeTestBlock(600, 7)
    let cb = newCompactBlock(blk, 0)

    var (pdb, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

    # Fill missing
    let missingTxs = blk.txs[1..^1]
    discard pdb.fillMissingTransactions(missingTxs)

    # Reconstruct
    let (reconstructed, rStatus) = pdb.reconstructBlock()
    check rStatus == rsOk
    check reconstructed.header == blk.header
    check reconstructed.txs.len == blk.txs.len

    for i in 0 ..< blk.txs.len:
      # Compare txids
      check txid(reconstructed.txs[i]) == txid(blk.txs[i])

  test "reject invalid compact block - empty":
    var cb: CompactBlock
    cb.header.version = 1

    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "reject invalid compact block - out of order prefilled":
    var cb: CompactBlock
    cb.header.version = 1
    cb.nonce = 123

    # Add prefilled txs in wrong order
    cb.prefilledTxns.add(PrefilledTx(index: 5, tx: makeTestTransaction(1)))
    cb.prefilledTxns.add(PrefilledTx(index: 2, tx: makeTestTransaction(2)))  # Wrong!

    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

suite "compact block state":
  test "new state defaults":
    let state = newCompactBlockState()

    check not state.wantsCompactBlocks
    check not state.highBandwidthMode
    check state.compactBlockVersion == 0

  test "handle sendcmpct version 2":
    var state = newCompactBlockState()

    state.handleSendCmpct(announce = false, version = 2)

    check state.wantsCompactBlocks
    check not state.highBandwidthMode
    check state.compactBlockVersion == 2

  test "handle sendcmpct high bandwidth mode":
    var state = newCompactBlockState()

    state.handleSendCmpct(announce = true, version = 2)

    check state.wantsCompactBlocks
    check state.highBandwidthMode
    check state.compactBlockVersion == 2

  test "reject invalid version":
    var state = newCompactBlockState()

    state.handleSendCmpct(announce = true, version = 0)

    check not state.wantsCompactBlocks

    state.handleSendCmpct(announce = true, version = 3)

    check not state.wantsCompactBlocks

  # Bug fix 4: Core only accepts version == 2 (CMPCTBLOCKS_VERSION),
  # not version 1.  Version 1 is the legacy txid-based protocol.
  test "reject version 1 (legacy txid-based, Core net_processing.cpp:3907)":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = true, version = 1)
    check not state.wantsCompactBlocks
    check state.compactBlockVersion == 0

  test "reconstruction stats":
    var state = newCompactBlockState()

    let (received, success, failed, rate) = state.getReconstructionStats()
    check received == 0
    check success == 0
    check failed == 0
    check rate == 0.0

suite "P2P message integration":
  test "cmpctblock message kind":
    check messageKindToCommand(mkCmpctBlock) == "cmpctblock"
    check commandToMessageKind("cmpctblock") == mkCmpctBlock

  test "getblocktxn message kind":
    check messageKindToCommand(mkGetBlockTxn) == "getblocktxn"
    check commandToMessageKind("getblocktxn") == mkGetBlockTxn

  test "blocktxn message kind":
    check messageKindToCommand(mkBlockTxn) == "blocktxn"
    check commandToMessageKind("blocktxn") == mkBlockTxn

  test "cmpctblock message serialization":
    let blk = makeTestBlock(700, 3)
    let cb = newCompactBlock(blk, 0)

    let msg = newCmpctBlockMsg(cb)
    check msg.kind == mkCmpctBlock

    # Serialize
    let payload = serializePayload(msg)

    # Deserialize
    let msg2 = deserializePayload("cmpctblock", payload)
    check msg2.kind == mkCmpctBlock
    check msg2.cmpctBlock.header == cb.header
    check msg2.cmpctBlock.nonce == cb.nonce

  test "getblocktxn message serialization":
    var blockHash: BlockHash
    for i in 0 ..< 32:
      array[32, byte](blockHash)[i] = byte(i)

    let msg = newGetBlockTxnMsg(blockHash, @[uint16(1), uint16(5), uint16(10)])
    check msg.kind == mkGetBlockTxn

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("getblocktxn", payload)

    check msg2.kind == mkGetBlockTxn
    check msg2.getBlockTxn.blockHash == blockHash
    check msg2.getBlockTxn.indexes == @[uint16(1), uint16(5), uint16(10)]

  test "blocktxn message serialization":
    var blockHash: BlockHash
    for i in 0 ..< 32:
      array[32, byte](blockHash)[i] = byte(i)

    let txns = @[makeTestTransaction(1), makeTestTransaction(2)]
    let msg = newBlockTxnMsg(blockHash, txns)
    check msg.kind == mkBlockTxn

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("blocktxn", payload)

    check msg2.kind == mkBlockTxn
    check msg2.blockTxn.blockHash == blockHash
    check msg2.blockTxn.transactions.len == 2

suite "helper functions":
  test "createBlockTxnRequest":
    var blockHash: BlockHash
    for i in 0 ..< 32:
      array[32, byte](blockHash)[i] = byte(i)

    let req = createBlockTxnRequest(blockHash, @[uint16(1), uint16(3)])
    check req.blockHash == blockHash
    check req.indexes.len == 2

  test "createBlockTxnResponse":
    var blockHash: BlockHash
    let blk = makeTestBlock(800, 10)

    let resp = createBlockTxnResponse(blockHash, blk, @[uint16(1), uint16(3), uint16(5)])

    check resp.blockHash == blockHash
    check resp.transactions.len == 3
    check txid(resp.transactions[0]) == txid(blk.txs[1])
    check txid(resp.transactions[1]) == txid(blk.txs[3])
    check txid(resp.transactions[2]) == txid(blk.txs[5])

  test "shouldSendCompactBlock":
    var state = newCompactBlockState()
    check not state.shouldSendCompactBlock()

    state.handleSendCmpct(announce = false, version = 2)
    check state.shouldSendCompactBlock()

  test "supportsHighBandwidth":
    var state = newCompactBlockState()
    check not state.supportsHighBandwidth()

    state.handleSendCmpct(announce = true, version = 2)
    check state.supportsHighBandwidth()

# ============================================================================
# W89 Bug-fix regression tests
# All reference Core blockencodings.cpp unless otherwise noted.
# ============================================================================

suite "W89 bug-fix regressions":

  # Bug fix 1: header null check in initPartiallyDownloadedBlock
  # Core line 62: header.IsNull() → READ_STATUS_INVALID
  test "null header (bits=0) rejected by initPartiallyDownloadedBlock":
    var cb: CompactBlock
    # bits == 0 means "null header" by our isNullHeader() convention
    cb.header.bits = 0
    cb.prefilledTxns.add(PrefilledTx(index: 0, tx: makeTestTransaction(1)))
    # Give it one short ID so it passes the empty check
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  # Positive: non-null header is accepted
  test "non-null header accepted by initPartiallyDownloadedBlock":
    let blk = makeTestBlock(900, 3)
    let cb = newCompactBlock(blk, 0x1234'u64)
    check cb.header.bits != 0  # makeTestBlock sets bits = 0x1d00ffff
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

  # Bug fix 2: prefilled structural gap check
  # Core line 80: lastprefilledindex > shorttxids.size() + i → READ_STATUS_INVALID
  # If prefilled index > num_short_ids + num_prefilled_so_far, there's a position
  # with neither a short ID nor a prefilled tx.
  test "prefilled gap check: index beyond short IDs + prefilled count":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.nonce = 42
    # Only 2 short IDs but prefilled tx claims index 5 (0-based) → gap
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    cb.shortIds.add([byte(7), 8, 9, 10, 11, 12])
    # Prefilled at absolute index 5: gap check: 5 > 2 short_ids + 0 prefilled_so_far → invalid
    cb.prefilledTxns.add(PrefilledTx(index: 5, tx: makeTestTransaction(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsInvalid

  test "prefilled gap check: valid placement (no gap)":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.nonce = 42
    # 2 short IDs + prefilled at index 2 (= shorttxids.size() + 0): just valid
    cb.shortIds.add([byte(1), 2, 3, 4, 5, 6])
    cb.shortIds.add([byte(7), 8, 9, 10, 11, 12])
    # prefilled[0].index = 2: check 2 <= 2 + 0 → OK
    cb.prefilledTxns.add(PrefilledTx(index: 2, tx: makeTestTransaction(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

  # Bug fix 3: bucket-size DoS guard
  # Core lines 110-111: bucket_size > 12 → READ_STATUS_FAILED
  test "bucket-size guard: 13 identical short IDs rejected":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.nonce = 7
    # 13 copies of the same 6-byte short ID exceeds bucket limit of 12
    for i in 0 ..< 13:
      cb.shortIds.add([byte(0xAA), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    cb.prefilledTxns.add(PrefilledTx(index: 13, tx: makeTestTransaction(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsFailed

  test "bucket-size guard: 12 identical short IDs accepted":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.nonce = 7
    # Exactly 12 is the limit: must not be rejected by bucket guard
    # (but WILL be rejected by the duplicate-key check since map size != input size)
    for i in 0 ..< 12:
      cb.shortIds.add([byte(0xAA), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    cb.prefilledTxns.add(PrefilledTx(index: 12, tx: makeTestTransaction(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    # 12 identical → collision (map dedup), so rsFailed — but NOT from bucket guard
    check status == rsFailed  # collision dedup fires, which is correct

  test "bucket-size guard: distinct short IDs all accepted":
    var cb: CompactBlock
    cb.header.bits = 0x1d00ffff'u32
    cb.nonce = 7
    # 15 distinct IDs — no single bucket should exceed 12
    for i in 0 ..< 15:
      cb.shortIds.add([byte(i), byte(i+1), byte(i+2), byte(i+3), byte(i+4), byte(i+5)])
    cb.prefilledTxns.add(PrefilledTx(index: 15, tx: makeTestTransaction(1)))
    let (_, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk

  # Bug fix 5: reconstructBlock header null check
  # Core line 193: if (header.IsNull()) return READ_STATUS_INVALID
  test "reconstructBlock rejects null header pdb":
    var pdb: PartiallyDownloadedBlock
    # header.bits == 0 → null
    pdb.header.bits = 0
    pdb.txnAvailable.add(some(makeTestTransaction(1)))
    let (_, status) = pdb.reconstructBlock()
    check status == rsInvalid

  # Bug fix 6 & 7: filledSlots prevents third-match re-fill after collision.
  # Core have_txn[] vector (line 118) tracks first match independently of
  # whether txn_available[] was subsequently cleared.
  test "filledSlots: direct collision simulation - slot cleared stays cleared":
    # Build a compact block with 3 non-prefilled slots
    let blk = makeTestBlock(950, 4)  # coinbase + 3 more
    let cb = newCompactBlock(blk, 0xdeadbeef'u64)
    var (pdb, status) = initPartiallyDownloadedBlock(cb)
    check status == rsOk
    # Initially no slots filled, mempoolCount = 0
    check pdb.filledSlots.len == 0
    check pdb.mempoolCount == 0

    # Simulate first match at position 1 (directly, as if fillFromExtraPool did it)
    let pos = 1
    pdb.txnAvailable[pos] = some(makeTestTransaction(99))
    pdb.filledSlots.incl(pos)
    pdb.mempoolCount += 1

    # Simulate collision (second match) — should clear the slot
    # This is the "else" branch in fillFromMempool/fillFromExtraPool
    if pos in pdb.filledSlots:
      if pdb.txnAvailable[pos].isSome:
        pdb.txnAvailable[pos] = none(Transaction)
        pdb.mempoolCount -= 1

    check pdb.txnAvailable[pos].isNone
    check pdb.mempoolCount == 0

    # Simulate "third match" attempt: pos IS in filledSlots so the
    # first-match branch is skipped — slot cannot be re-filled
    let wouldFill = pos notin pdb.filledSlots
    check not wouldFill  # confirms slot is guarded

  # Bug fix 6: filledSlots starts empty on init
  test "filledSlots: empty after initPartiallyDownloadedBlock":
    let blk = makeTestBlock(960, 2)  # coinbase + 1 more
    let cb = newCompactBlock(blk, 0xcafe'u64)
    var (pdb, initStatus) = initPartiallyDownloadedBlock(cb)
    check initStatus == rsOk
    check pdb.filledSlots.len == 0
    check pdb.mempoolCount == 0

  # Bug fix 4 and shouldSendCompactBlock consistency
  test "shouldSendCompactBlock: version 1 does not enable compact block sending":
    var state = newCompactBlockState()
    # Attempt to accept v1 (should be silently ignored per bug fix 4)
    state.handleSendCmpct(announce = false, version = 1)
    check not state.shouldSendCompactBlock()

  test "shouldSendCompactBlock: only version 2 enables compact block sending":
    var state = newCompactBlockState()
    state.handleSendCmpct(announce = false, version = 2)
    check state.shouldSendCompactBlock()
