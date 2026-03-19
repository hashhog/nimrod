## Tests for Block Filter Index (blockfilterindex)

import std/[unittest, os, options, tempfiles]
import ../src/storage/indexes/blockfilterindex
import ../src/storage/indexes/gcs
import ../src/storage/indexes/base
import ../src/storage/db
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "BlockFilterIndex":
  var db: Database
  var idx: BlockFilterIndex
  var testDir: string

  setup:
    testDir = createTempDir("blockfilter_test_", "")
    db = openDatabase(testDir / "db")
    idx = newBlockFilterIndex(db, testDir, bftBasic, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "disabled index returns none":
    let disabledIdx = newBlockFilterIndex(db, testDir, bftBasic, enabled = false)
    check disabledIdx.getFilterEntry(0).isNone

  test "FilterIndexEntry serialization":
    var entry = FilterIndexEntry(
      filterHash: default(array[32, byte]),
      filterHeader: default(array[32, byte]),
      fileNum: 5,
      filePos: 12345
    )
    for i in 0 ..< 32:
      entry.filterHash[i] = byte(i)
      entry.filterHeader[i] = byte(255 - i)

    let serialized = serializeFilterEntry(entry)
    let deserialized = deserializeFilterEntry(serialized)

    check deserialized.filterHash == entry.filterHash
    check deserialized.filterHeader == entry.filterHeader
    check deserialized.fileNum == entry.fileNum
    check deserialized.filePos == entry.filePos

  test "filter file path generation":
    check filterFileName(0) == "fltr00000.dat"
    check filterFileName(1) == "fltr00001.dat"
    check filterFileName(99999) == "fltr99999.dat"

  test "customAppend creates filter for block":
    # Create a block with some outputs
    var tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8, 0xa9, 0x14]),
        TxOut(value: Satoshi(1000000000), scriptPubKey: @[0x00'u8, 0x14])  # P2WPKH
      ],
      lockTime: 0
    )

    var blk = Block(
      header: BlockHeader(version: 1),
      txs: @[tx]
    )

    var hashBytes: array[32, byte]
    hashBytes[0] = 0xab
    let blockHash = BlockHash(hashBytes)

    let blockInfo = BlockInfo(
      hash: blockHash,
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true

    # Verify filter entry was created
    let entry = idx.getFilterEntry(1)
    check entry.isSome
    check entry.get().filterHash != default(array[32, byte])
    check entry.get().filterHeader != default(array[32, byte])

  test "filter header chaining":
    # Create two blocks and verify headers chain correctly
    var hashBytes1, hashBytes2: array[32, byte]
    hashBytes1[0] = 1
    hashBytes2[0] = 2

    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[1'u8, 2, 3])]
      )]
    )

    # First block
    let blockInfo1 = BlockInfo(
      hash: BlockHash(hashBytes1),
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 100
    )
    check idx.customAppend(blockInfo1) == true

    let entry1 = idx.getFilterEntry(1)
    check entry1.isSome

    # Second block
    let blockInfo2 = BlockInfo(
      hash: BlockHash(hashBytes2),
      prevHash: BlockHash(hashBytes1),
      height: 2,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 500
    )
    check idx.customAppend(blockInfo2) == true

    let entry2 = idx.getFilterEntry(2)
    check entry2.isSome

    # Headers should be different (chained)
    check entry1.get().filterHeader != entry2.get().filterHeader

  test "reorg copies to hash index":
    var hashBytes: array[32, byte]
    hashBytes[0] = 0xff

    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[5'u8, 6, 7])]
      )]
    )

    let blockInfo = BlockInfo(
      hash: BlockHash(hashBytes),
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true
    check idx.customRemove(blockInfo) == true

    # Should be accessible by hash after reorg
    let byHash = idx.getFilterEntryByHash(BlockHash(hashBytes))
    check byHash.isSome

suite "BlockFilterIndex Key Construction":
  test "filterHeightKey big-endian ordering":
    let key1 = filterHeightKey(0)
    let key2 = filterHeightKey(1)
    let key3 = filterHeightKey(256)

    check key1.len == 5
    check key2.len == 5
    check key3.len == 5

    check key1[0] == byte('f')
    check key2[0] == byte('f')
    check key3[0] == byte('f')

    # Big-endian: higher heights have lexicographically greater keys
    # Compare lexicographically using string comparison
    check cast[string](key1) < cast[string](key2)
    check cast[string](key2) < cast[string](key3)

  test "filterHashKey format":
    var hashBytes: array[32, byte]
    for i in 0 ..< 32:
      hashBytes[i] = byte(i)
    let blockHash = BlockHash(hashBytes)

    let key = filterHashKey(blockHash)
    check key.len == 33
    check key[0] == byte('g')
    for i in 0 ..< 32:
      check key[i + 1] == byte(i)
