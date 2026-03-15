## Tests for BIP152 Compact Block Relay
## Tests short ID computation, serialization, and block reconstruction

import std/[random, options, strutils]
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
