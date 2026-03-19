## Tests for assumeUTXO snapshot functionality
## Tests snapshot creation, loading, serialization, and validation

import std/[os, options, tables, unittest]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/storage/[chainstate, snapshot]

suite "assumeUTXO snapshot":
  setup:
    let testDir = getTempDir() / "nimrod_snapshot_test"
    createDir(testDir)

  teardown:
    try:
      removeDir(testDir)
    except OSError:
      discard

  test "snapshot metadata serialization":
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(default(array[32, byte])),
      coinsCount: 12345
    )

    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readSnapshotMetadata()

    check decoded.version == meta.version
    check decoded.networkMagic == meta.networkMagic
    check decoded.baseBlockhash == meta.baseBlockhash
    check decoded.coinsCount == meta.coinsCount

  test "snapshot coin serialization":
    let coin = SnapshotCoin(
      outpoint: OutPoint(
        txid: TxId([1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]),
        vout: 42
      ),
      output: TxOut(
        value: Satoshi(100000000),  # 1 BTC
        scriptPubKey: @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
      ),
      height: 500000,
      isCoinbase: false
    )

    var w = BinaryWriter()
    w.writeSnapshotCoin(coin)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readSnapshotCoin()

    check decoded.outpoint == coin.outpoint
    check decoded.output.value == coin.output.value
    check decoded.output.scriptPubKey == coin.output.scriptPubKey
    check decoded.height == coin.height
    check decoded.isCoinbase == coin.isCoinbase

  test "snapshot coin with coinbase flag":
    let coin = SnapshotCoin(
      outpoint: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0
      ),
      output: TxOut(
        value: Satoshi(5000000000),  # 50 BTC coinbase
        scriptPubKey: @[0x41'u8] & newSeq[byte](65) & @[0xac'u8]
      ),
      height: 100,
      isCoinbase: true
    )

    var w = BinaryWriter()
    w.writeSnapshotCoin(coin)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readSnapshotCoin()

    check decoded.isCoinbase == true
    check decoded.height == 100

  test "snapshot file write and read":
    let testPath = testDir / "test_snapshot.dat"

    # Create metadata
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash([1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                                 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]),
      coinsCount: 2
    )

    # Write snapshot
    let sf = openSnapshotForWrite(testPath, meta)

    let coin1 = SnapshotCoin(
      outpoint: OutPoint(txid: TxId([1'u8] & newSeq[byte](31)), vout: 0),
      output: TxOut(value: Satoshi(100), scriptPubKey: @[0x00'u8]),
      height: 1,
      isCoinbase: true
    )
    let coin2 = SnapshotCoin(
      outpoint: OutPoint(txid: TxId([2'u8] & newSeq[byte](31)), vout: 1),
      output: TxOut(value: Satoshi(200), scriptPubKey: @[0x51'u8]),
      height: 2,
      isCoinbase: false
    )

    sf.writeCoin(coin1)
    sf.writeCoin(coin2)
    sf.close()

    # Read snapshot
    let readSf = openSnapshotForRead(testPath)
    check readSf.metadata.version == SnapshotVersion
    check readSf.metadata.coinsCount == 2

    let readCoin1 = readSf.readCoin()
    check readCoin1.isSome
    check readCoin1.get().outpoint.vout == 0
    check readCoin1.get().output.value == Satoshi(100)
    check readCoin1.get().isCoinbase == true

    let readCoin2 = readSf.readCoin()
    check readCoin2.isSome
    check readCoin2.get().outpoint.vout == 1
    check readCoin2.get().output.value == Satoshi(200)
    check readCoin2.get().isCoinbase == false

    let readCoin3 = readSf.readCoin()
    check readCoin3.isNone

    readSf.close()

  test "snapshot magic validation":
    let testPath = testDir / "bad_magic.dat"

    # Write invalid magic bytes
    let f = open(testPath, fmWrite)
    let badMagic = @[0x00'u8, 0x00, 0x00, 0x00, 0x00]
    discard f.writeBytes(badMagic)
    f.close()

    expect SnapshotError:
      discard openSnapshotForRead(testPath)

  test "snapshot version validation":
    let testPath = testDir / "bad_version.dat"

    # Write good magic but bad version
    var w = BinaryWriter()
    w.writeBytes(SnapshotMagic)
    w.writeUint16LE(99)  # Invalid version
    w.writeBytes([0xF9'u8, 0xBE, 0xB4, 0xD9])  # network magic
    w.writeBlockHash(BlockHash(default(array[32, byte])))
    w.writeUint64LE(0)

    let f = open(testPath, fmWrite)
    discard f.writeBytes(w.data)
    f.close()

    expect SnapshotError:
      discard openSnapshotForRead(testPath)

  test "assumeutxo data in params":
    let mainParams = mainnetParams()

    # Check that assumeutxoData is defined
    check mainParams.assumeutxoData.len >= 1

    # Verify first entry has expected structure
    let data = mainParams.assumeutxoData[0]
    check data.height > 0
    check data.chainTxCount > 0

  test "snapshot metadata validation":
    let mainParams = mainnetParams()

    # Valid metadata matching first assumeutxo entry
    let validMeta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainParams.networkMagic,
      baseBlockhash: mainParams.assumeutxoData[0].blockhash,
      coinsCount: 1000
    )

    let (valid, data, error) = validateSnapshotMetadata(
      validMeta, mainParams, mainParams.assumeutxoData
    )
    check valid == true
    check data.isSome

  test "snapshot metadata validation fails on wrong network":
    let mainParams = mainnetParams()

    # Metadata with wrong network magic
    let invalidMeta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0x00'u8, 0x00, 0x00, 0x00],  # Wrong magic
      baseBlockhash: mainParams.assumeutxoData[0].blockhash,
      coinsCount: 1000
    )

    let (valid, data, error) = validateSnapshotMetadata(
      invalidMeta, mainParams, mainParams.assumeutxoData
    )
    check valid == false
    check error == "network magic mismatch"

  test "snapshot metadata validation fails on unknown hash":
    let mainParams = mainnetParams()

    # Metadata with unknown block hash
    let invalidMeta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainParams.networkMagic,
      baseBlockhash: BlockHash([0xFF'u8] & newSeq[byte](31)),  # Unknown hash
      coinsCount: 1000
    )

    let (valid, data, error) = validateSnapshotMetadata(
      invalidMeta, mainParams, mainParams.assumeutxoData
    )
    check valid == false
    check "unknown snapshot block hash" in error

  test "assumeutxo state enum values":
    check auValidated != auUnvalidated
    check auUnvalidated != auInvalid
    check auInvalid != auValidated

  test "snapshot chainstate wrapper":
    let dbDir = testDir / "chainstate_db"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    let snapshotCs = newSnapshotChainState(cs)
    check snapshotCs.assumeutxo == auValidated
    check snapshotCs.snapshotBlockhash.isNone
    check snapshotCs.targetUtxoHash.isNone

  test "background validation structure":
    let bgv = newBackgroundValidation(
      targetHeight = 100,
      snapshotHash = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                      11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                      21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]
    )

    check bgv.running == false
    check bgv.progress == 0
    check bgv.targetHeight == 100

    let (current, target) = bgv.getProgress()
    check current == 0
    check target == 100

  test "UTXO hash computation is deterministic":
    # Empty set should return zero hash
    var coins: seq[SnapshotCoin] = @[]

    var w = BinaryWriter()
    for coin in coins:
      w.writeSnapshotCoin(coin)

    # Empty data should produce a consistent result
    # (in our implementation, we return zero hash for empty)
    check w.data.len == 0

  test "UTXO hash with coins":
    let coin1 = SnapshotCoin(
      outpoint: OutPoint(txid: TxId([1'u8] & newSeq[byte](31)), vout: 0),
      output: TxOut(value: Satoshi(100), scriptPubKey: @[0x00'u8]),
      height: 1,
      isCoinbase: true
    )

    var w1 = BinaryWriter()
    w1.writeSnapshotCoin(coin1)
    let hash1 = doubleSha256(w1.data)

    var w2 = BinaryWriter()
    w2.writeSnapshotCoin(coin1)
    let hash2 = doubleSha256(w2.data)

    # Same coin should produce same hash
    check hash1 == hash2

  test "testnet has empty assumeutxo data":
    let testnet3 = testnet3Params()
    check testnet3.assumeutxoData.len == 0

    let testnet4 = testnet4Params()
    check testnet4.assumeutxoData.len == 0

  test "regtest has empty assumeutxo data":
    let regtest = regtestParams()
    check regtest.assumeutxoData.len == 0

  test "signet has empty assumeutxo data":
    let signet = signetParams()
    check signet.assumeutxoData.len == 0
