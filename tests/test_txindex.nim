## Tests for Transaction Index (txindex)

import std/[unittest, os, options, tempfiles]
import ../src/storage/indexes/txindex
import ../src/storage/indexes/base
import ../src/storage/db
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "TxIndex":
  var db: Database
  var idx: TxIndex
  var testDir: string

  setup:
    testDir = createTempDir("txindex_test_", "")
    db = openDatabase(testDir / "db")
    idx = newTxIndex(db, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "disabled index returns none":
    let disabledIdx = newTxIndex(db, enabled = false)
    var txidBytes: array[32, byte]
    txidBytes[0] = 1
    let txid = TxId(txidBytes)
    check disabledIdx.readTxPos(txid).isNone

  test "store and retrieve single tx position":
    var txidBytes: array[32, byte]
    for i in 0 ..< 32:
      txidBytes[i] = byte(i)
    let txid = TxId(txidBytes)

    let pos = DiskTxPos(
      fileNum: 5,
      blockDataPos: 12345,
      txOffset: 100
    )

    idx.writeTxs(@[(txid: txid, pos: pos)])

    let retrieved = idx.readTxPos(txid)
    check retrieved.isSome
    check retrieved.get().fileNum == 5
    check retrieved.get().blockDataPos == 12345
    check retrieved.get().txOffset == 100

  test "hasTx returns correct result":
    var txidBytes: array[32, byte]
    txidBytes[0] = 0xaa
    let txid = TxId(txidBytes)

    check idx.hasTx(txid) == false

    let pos = DiskTxPos(fileNum: 1, blockDataPos: 100, txOffset: 50)
    idx.writeTxs(@[(txid: txid, pos: pos)])

    check idx.hasTx(txid) == true

  test "batch write multiple transactions":
    var positions: seq[tuple[txid: TxId, pos: DiskTxPos]]
    for i in 0 ..< 10:
      var txidBytes: array[32, byte]
      txidBytes[0] = byte(i)
      let txid = TxId(txidBytes)
      let pos = DiskTxPos(
        fileNum: int32(i div 2),
        blockDataPos: int32(i * 1000),
        txOffset: int32(i * 10)
      )
      positions.add((txid: txid, pos: pos))

    idx.writeTxs(positions)

    # Verify all can be retrieved
    for (txid, expectedPos) in positions:
      let retrieved = idx.readTxPos(txid)
      check retrieved.isSome
      check retrieved.get().fileNum == expectedPos.fileNum
      check retrieved.get().blockDataPos == expectedPos.blockDataPos
      check retrieved.get().txOffset == expectedPos.txOffset

  test "non-existent tx returns none":
    var txidBytes: array[32, byte]
    txidBytes[0] = 0xff
    txidBytes[31] = 0xff
    let txid = TxId(txidBytes)

    check idx.readTxPos(txid).isNone

  test "DiskTxPos serialization round-trip":
    let original = DiskTxPos(
      fileNum: 12345,
      blockDataPos: -1,  # Test negative values
      txOffset: 999999
    )

    let serialized = serializeDiskTxPos(original)
    let deserialized = deserializeDiskTxPos(serialized)

    check deserialized.fileNum == original.fileNum
    check deserialized.blockDataPos == original.blockDataPos
    check deserialized.txOffset == original.txOffset

  test "customAppend indexes block transactions":
    # Create a simple block with one transaction
    var tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5000000000),
        scriptPubKey: @[0x76'u8, 0xa9, 0x14]  # P2PKH start
      )],
      lockTime: 0
    )

    var blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: default(array[32, byte]),
        timestamp: 1234567890,
        bits: 0x1d00ffff,
        nonce: 0
      ),
      txs: @[tx]
    )

    # Create block info for height 1 (not genesis)
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    let blockInfo = BlockInfo(
      hash: blockHash,
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true

    # Verify transaction was indexed
    let txHash = txid(tx)
    let pos = idx.readTxPos(txHash)
    check pos.isSome
    check pos.get().fileNum == 0
    check pos.get().blockDataPos == 100

  test "genesis block is skipped":
    var blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(version: 1)]
    )

    let blockInfo = BlockInfo(
      hash: BlockHash(default(array[32, byte])),
      prevHash: BlockHash(default(array[32, byte])),
      height: 0,  # Genesis
      data: some(blk),
      fileNum: 0,
      dataPos: 0
    )

    check idx.customAppend(blockInfo) == true
    # Genesis tx should NOT be indexed
    let txHash = txid(blk.txs[0])
    check idx.readTxPos(txHash).isNone

suite "TxIndex Key Construction":
  test "txIndexKey format":
    var txidBytes: array[32, byte]
    for i in 0 ..< 32:
      txidBytes[i] = byte(i)
    let txid = TxId(txidBytes)

    let key = txIndexKey(txid)
    check key.len == 33
    check key[0] == byte('t')
    for i in 0 ..< 32:
      check key[i + 1] == byte(i)

  test "compactSizeLen calculation":
    check compactSizeLen(0) == 1
    check compactSizeLen(252) == 1
    check compactSizeLen(253) == 3
    check compactSizeLen(0xFFFF) == 3
    check compactSizeLen(0x10000) == 5
    check compactSizeLen(0xFFFFFFFF'u64) == 5
    check compactSizeLen(0x100000000'u64) == 9
