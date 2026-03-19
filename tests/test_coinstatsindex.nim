## Tests for Coin Stats Index (coinstatsindex)

import std/[unittest, os, options, tempfiles]
import ../src/storage/indexes/coinstatsindex
import ../src/storage/indexes/base
import ../src/storage/db
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, muhash]
import ../src/consensus/params

suite "MuHash3072":
  test "empty muhash":
    var h = newMuHash3072()
    let result = h.finalize()
    check result != default(array[32, byte])

  test "insert single element":
    var h = newMuHash3072()
    h.insert(@[1'u8, 2, 3, 4, 5])
    let result = h.finalize()
    check result != default(array[32, byte])

  test "insert and remove cancels out":
    var h1 = newMuHash3072()
    var h2 = newMuHash3072()

    h1.insert(@[1'u8, 2, 3])
    h1.remove(@[1'u8, 2, 3])

    # After insert+remove, should be equivalent to empty
    # Note: Due to fraction representation, finalize needed
    let r1 = h1.finalize()
    let r2 = h2.finalize()
    check r1 == r2

  test "insert order independence":
    var h1 = newMuHash3072()
    var h2 = newMuHash3072()

    h1.insert(@[1'u8, 2, 3])
    h1.insert(@[4'u8, 5, 6])

    h2.insert(@[4'u8, 5, 6])
    h2.insert(@[1'u8, 2, 3])

    check h1.finalize() == h2.finalize()

  test "combine two muhashes":
    var h1 = newMuHash3072()
    var h2 = newMuHash3072()
    var combined = newMuHash3072()

    h1.insert(@[1'u8, 2, 3])
    h2.insert(@[4'u8, 5, 6])

    combined.insert(@[1'u8, 2, 3])
    combined.insert(@[4'u8, 5, 6])

    var merged = h1
    merged *= h2

    check merged.finalize() == combined.finalize()

  test "serialization round-trip":
    var h = newMuHash3072()
    h.insert(@[10'u8, 20, 30])
    h.insert(@[40'u8, 50, 60])

    let serialized = serializeMuHash(h)
    let deserialized = deserializeMuHash(serialized)

    check h.finalize() == deserialized.finalize()

suite "CoinStatsIndex":
  var db: Database
  var idx: CoinStatsIndex
  var testDir: string

  setup:
    testDir = createTempDir("coinstats_test_", "")
    db = openDatabase(testDir / "db")
    idx = newCoinStatsIndex(db, mainnetParams(), enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "disabled index returns none":
    let disabledIdx = newCoinStatsIndex(db, mainnetParams(), enabled = false)
    check disabledIdx.lookUpStats(0).isNone

  test "getBogoSize calculation":
    check getBogoSize(@[]) == 32 + 4 + 4 + 1 + 8 + 0 + 1
    check getBogoSize(@[1'u8, 2, 3]) == 32 + 4 + 4 + 1 + 8 + 3 + 1

  test "isUnspendable detection":
    check isUnspendable(@[]) == true  # Empty
    check isUnspendable(@[0x6a'u8]) == true  # OP_RETURN
    check isUnspendable(@[0x6a'u8, 0x04]) == true  # OP_RETURN with data
    check isUnspendable(@[0x76'u8, 0xa9]) == false  # P2PKH
    check isUnspendable(@[0x00'u8, 0x14]) == false  # P2WPKH

  test "genesis block handling":
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8])]
      )]
    )

    let blockInfo = BlockInfo(
      hash: BlockHash(default(array[32, byte])),
      prevHash: BlockHash(default(array[32, byte])),
      height: 0,  # Genesis
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 0
    )

    check idx.customAppend(blockInfo) == true

    # Genesis outputs are counted as unspendable
    check idx.totalUnspendablesGenesisBlock > 0

  test "process block with outputs":
    var prevHashBytes: array[32, byte]

    # Genesis first (required for state initialization)
    let genesis = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(version: 1)]
    )
    let genesisInfo = BlockInfo(
      hash: BlockHash(prevHashBytes),
      prevHash: BlockHash(default(array[32, byte])),
      height: 0,
      data: some(genesis),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 0
    )
    check idx.customAppend(genesisInfo) == true

    # Block with actual outputs
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xffffffff)],
        outputs: @[
          TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8, 0xa9]),
          TxOut(value: Satoshi(2500000000), scriptPubKey: @[0x00'u8, 0x14])
        ]
      )]
    )

    var hashBytes: array[32, byte]
    hashBytes[0] = 1
    let blockInfo = BlockInfo(
      hash: BlockHash(hashBytes),
      prevHash: BlockHash(prevHashBytes),
      height: 1,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true

    # Check stats
    let stats = idx.lookUpStats(1)
    check stats.isSome
    check stats.get().transactionOutputCount == 2
    check stats.get().totalAmount == 7500000000  # 5 + 2.5 BTC in sats

  test "OP_RETURN outputs are unspendable":
    var prevHashBytes: array[32, byte]

    # Genesis
    let genesis = Block(header: BlockHeader(version: 1), txs: @[Transaction(version: 1)])
    let genesisInfo = BlockInfo(
      hash: BlockHash(prevHashBytes),
      height: 0,
      data: some(genesis)
    )
    check idx.customAppend(genesisInfo) == true

    # Block with OP_RETURN output
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xffffffff)],
        outputs: @[
          TxOut(value: Satoshi(4900000000), scriptPubKey: @[0x76'u8, 0xa9]),
          TxOut(value: Satoshi(100000000), scriptPubKey: @[0x6a'u8, 0x04])  # OP_RETURN
        ]
      )]
    )

    var hashBytes: array[32, byte]
    hashBytes[0] = 1
    let blockInfo = BlockInfo(
      hash: BlockHash(hashBytes),
      prevHash: BlockHash(prevHashBytes),
      height: 1,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true

    # Only 1 output should be counted (not the OP_RETURN)
    check idx.transactionOutputCount == 1
    check idx.totalUnspendablesScripts == 100000000

suite "CoinStatsIndex Serialization":
  test "CoinStatsDbVal round-trip":
    var val = CoinStatsDbVal(
      transactionOutputCount: 12345,
      bogoSize: 67890,
      totalAmount: 1000000000,
      totalSubsidy: 500000000,
      totalUnspendablesGenesisBlock: 5000000000,
      totalUnspendablesBip30: 0,
      totalUnspendablesScripts: 100000,
      totalUnspendablesUnclaimedRewards: 50000
    )

    # Set block hash
    for i in 0 ..< 32:
      (array[32, byte](val.blockHash))[i] = byte(i)
      val.muhash[i] = byte(255 - i)

    let serialized = serializeCoinStatsVal(val)
    let deserialized = deserializeCoinStatsVal(serialized)

    check deserialized.transactionOutputCount == val.transactionOutputCount
    check deserialized.bogoSize == val.bogoSize
    check deserialized.totalAmount == val.totalAmount
    check deserialized.totalSubsidy == val.totalSubsidy
    check deserialized.muhash == val.muhash
