## Tests for Coin Stats Index (coinstatsindex)

import unittest2
import std/[os, options, tempfiles]
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
    var deserialized = deserializeMuHash(serialized)

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
    check getBogoSize(@[]) == 50'u64  # 32 + 4 + 4 + 1 + 8 + 0 + 1
    check getBogoSize(@[1'u8, 2, 3]) == 53'u64  # 32 + 4 + 4 + 1 + 8 + 3 + 1

  test "isUnspendable detection (Core CScript::IsUnspendable)":
    # Core's IsUnspendable:
    #   (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE)
    # Empty scripts are NOT unspendable (the size>0 guard).
    check isUnspendable(@[]) == false  # Empty -- Core: size()>0 guard
    check isUnspendable(@[0x6a'u8]) == true  # OP_RETURN
    check isUnspendable(@[0x6a'u8, 0x04]) == true  # OP_RETURN with data
    check isUnspendable(@[0x76'u8, 0xa9]) == false  # P2PKH
    check isUnspendable(@[0x00'u8, 0x14]) == false  # P2WPKH
    # Oversize: > MAX_SCRIPT_SIZE (10000 bytes).
    check isUnspendable(newSeq[byte](10001)) == true   # 10001 bytes
    check isUnspendable(newSeq[byte](10000)) == false  # exactly the limit

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
        inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xffffffff'u32)],
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
        inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xffffffff'u32)],
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

suite "CoinStatsIndex BIP30 duplicate-coinbase skip":
  ## Finding 4F/6H: coinstatsindex must skip the BIP30 duplicate-coinbase blocks
  ## at mainnet h=91722 and h=91812 (Bitcoin Core index/coinstatsindex.cpp:128-131).
  ## Their coinbase outputs became unspendable when the duplicates overwrote the
  ## earlier ones in the UTXO set; they must NOT be folded into muhash/totals.

  proc makeBip30Hash(displayHex: string): BlockHash =
    ## Convert a display-order hex string to an internal BlockHash.
    var h: array[32, byte]
    for i in 0..31:
      let hi = displayHex[i*2]; let lo = displayHex[i*2+1]
      let hiV = (if hi >= '0' and hi <= '9': ord(hi)-ord('0')
                 elif hi >= 'a' and hi <= 'f': ord(hi)-ord('a')+10
                 else: ord(hi)-ord('A')+10)
      let loV = (if lo >= '0' and lo <= '9': ord(lo)-ord('0')
                 elif lo >= 'a' and lo <= 'f': ord(lo)-ord('a')+10
                 else: ord(lo)-ord('A')+10)
      h[31 - i] = byte(hiV * 16 + loV)
    BlockHash(h)

  var db: Database
  var idx: CoinStatsIndex
  var testDir: string

  setup:
    testDir = createTempDir("coinstats_bip30_", "")
    db = openDatabase(testDir / "db")
    idx = newCoinStatsIndex(db, mainnetParams(), enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "BIP30 block at h=91722 skips coinbase, charges subsidy to unspendablesBip30":
    ## Non-vacuous: without the fix, customAppend folds the coinbase outputs
    ## into muhash/totalCoinbaseAmount/transactionOutputCount just like any
    ## other coinbase; with the fix all three remain zero and the subsidy
    ## appears in totalUnspendablesBip30.

    # Construct the BIP30-unspendable block hash for h=91722.
    let bip30Hash = makeBip30Hash(
      "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")

    # Genesis block first (customAppend requires prevHash chain continuity).
    let genesisHash = makeBip30Hash(
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    let genesis = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(version: 1)]
    )
    let genesisInfo = BlockInfo(
      hash: genesisHash,
      prevHash: BlockHash(default(array[32, byte])),
      height: 0,
      data: some(genesis),
      undoData: none(BlockUndo),
      fileNum: 0, dataPos: 0
    )
    check idx.customAppend(genesisInfo) == true

    # For simplicity seed idx.currentBlockHash to match our fake prevHash.
    # We can't replay 91721 blocks here; instead set the state we need:
    idx.currentBlockHash = makeBip30Hash(
      "0000000000004d3a4519983e1920a58c31ddb53b30c7c7afb95b29fffca4a04f")

    # Build a minimal block at h=91722 with the BIP30 hash.
    # The coinbase outputs a typical 5000000000 sat reward.
    let coinbaseTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                       vout: 0xFFFFFFFF'u32),
                     sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(5000000000'i64),
                       scriptPubKey: @[0x76'u8, 0xa9, 0x14] &
                                     newSeq[byte](20) & @[0x88'u8, 0xac])],
    )
    let bip30Blk = Block(
      header: BlockHeader(version: 1),
      txs: @[coinbaseTx]
    )
    let bip30PrevHash = makeBip30Hash(
      "0000000000004d3a4519983e1920a58c31ddb53b30c7c7afb95b29fffca4a04f")
    let bip30Info = BlockInfo(
      hash: bip30Hash,
      prevHash: bip30PrevHash,
      height: 91722'i32,
      data: some(bip30Blk),
      undoData: none(BlockUndo),
      fileNum: 0, dataPos: 0
    )

    check idx.customAppend(bip30Info) == true

    # The coinbase must NOT be in the UTXO set stats.
    check idx.transactionOutputCount == 0
    check idx.totalCoinbaseAmount == 0
    check idx.totalAmount == 0

    # The block subsidy must have been charged to totalUnspendablesBip30.
    let expectedSubsidy = int64(getBlockSubsidy(91722'i32, mainnetParams()))
    check idx.totalUnspendablesBip30 == expectedSubsidy
    check expectedSubsidy > 0

  test "non-BIP30 coinbase at h=91722 (wrong hash) IS processed normally":
    ## Sanity: a block at h=91722 with a DIFFERENT hash (not the BIP30 block)
    ## must still have its coinbase outputs folded in normally.
    ## Uses a fake hash that doesn't match either BIP30 entry.
    var fakeHash: array[32, byte]
    fakeHash[0] = 0xFF'u8  # completely different from either BIP30 hash
    let normalHash = BlockHash(fakeHash)

    # Seed prevHash.
    idx.currentBlockHash = BlockHash(default(array[32, byte]))

    let coinbaseTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                       vout: 0xFFFFFFFF'u32),
                     sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(5000000000'i64),
                       scriptPubKey: @[0x76'u8, 0xa9, 0x14] &
                                     newSeq[byte](20) & @[0x88'u8, 0xac])],
    )
    let blk = Block(header: BlockHeader(version: 1), txs: @[coinbaseTx])
    let info = BlockInfo(
      hash: normalHash,
      prevHash: BlockHash(default(array[32, byte])),
      height: 91722'i32,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0, dataPos: 0
    )
    # Seed currentBlockHash for prevHash continuity.
    idx.currentBlockHash = BlockHash(default(array[32, byte]))

    check idx.customAppend(info) == true

    # Non-BIP30: coinbase MUST be processed normally.
    check idx.transactionOutputCount == 1
    check idx.totalCoinbaseAmount == 5000000000'u64
    check idx.totalUnspendablesBip30 == 0

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
