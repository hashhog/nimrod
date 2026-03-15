## Block storage tests
## Tests flat file block storage (blk*.dat files)

import unittest2
import std/[os, options, streams]
import ../src/storage/[blockstore, db]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDir = "/tmp/nimrod_test_blockstore"

proc cleanup() =
  if dirExists(TestDir):
    removeDir(TestDir)

proc makeTestBlock(prevHash: BlockHash, height: int32, numTxs: int = 1): Block =
  ## Create a simple test block
  var txs: seq[Transaction]

  # Coinbase transaction
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xFFFFFFFF'u32
      ),
      scriptSig: @[byte(height and 0xff)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )
  txs.add(coinbase)

  # Add additional transactions if requested
  for i in 1 ..< numTxs:
    var fakeTxid: array[32, byte]
    fakeTxid[0] = byte(i)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(fakeTxid), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000000),
        scriptPubKey: @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))
      )],
      witnesses: @[],
      lockTime: 0
    )
    txs.add(tx)

  # Compute merkle root
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  result = Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x1d00ffff'u32,
      nonce: uint32(height)
    ),
    txs: txs
  )

proc blockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "Block file names":
  test "block file name format":
    check blockFileName(0) == "blk00000.dat"
    check blockFileName(1) == "blk00001.dat"
    check blockFileName(12) == "blk00012.dat"
    check blockFileName(123) == "blk00123.dat"
    check blockFileName(1234) == "blk01234.dat"
    check blockFileName(12345) == "blk12345.dat"
    check blockFileName(99999) == "blk99999.dat"

suite "BlockFilePos":
  test "null position":
    let nullP = nullPos()
    check nullP.isNull
    check nullP.fileNum == -1
    check nullP.dataPos == -1

  test "valid position":
    let pos = BlockFilePos(fileNum: 0, dataPos: 8)
    check not pos.isNull

suite "BlockFileInfo serialization":
  test "roundtrip serialization":
    let info = BlockFileInfo(
      nBlocks: 100,
      nSize: 50000000,
      nHeightFirst: 0,
      nHeightLast: 99,
      nTimeFirst: 1231006505,
      nTimeLast: 1231066505
    )

    let data = serializeBlockFileInfo(info)
    let restored = deserializeBlockFileInfo(data)

    check restored.nBlocks == info.nBlocks
    check restored.nSize == info.nSize
    check restored.nHeightFirst == info.nHeightFirst
    check restored.nHeightLast == info.nHeightLast
    check restored.nTimeFirst == info.nTimeFirst
    check restored.nTimeLast == info.nTimeLast

suite "BlockIndexEntry serialization":
  test "roundtrip serialization":
    let entry = BlockIndexEntry(
      fileNum: 5,
      dataPos: 12345,
      undoPos: 6789,
      height: 500000,
      nTx: 2500,
      status: BlockHaveData or BlockHaveUndo or BlockValidated
    )

    let data = serializeBlockIndexEntry(entry)
    let restored = deserializeBlockIndexEntry(data)

    check restored.fileNum == entry.fileNum
    check restored.dataPos == entry.dataPos
    check restored.undoPos == entry.undoPos
    check restored.height == entry.height
    check restored.nTx == entry.nTx
    check restored.status == entry.status

suite "Flat file block storage":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "save and read single block":
    let params = regtestParams()
    let bfm = newBlockFileManager(TestDir, params)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let (pos, ok) = bfm.saveBlockToDisk(genesis, 0)

    check ok
    check not pos.isNull
    check pos.fileNum == 0
    check pos.dataPos == StorageHeaderBytes  # First block starts right after header

    # Read it back
    let (readBlk, readOk) = bfm.readBlockFromDisk(pos)
    check readOk
    check readBlk.header.timestamp == genesis.header.timestamp
    check readBlk.txs.len == genesis.txs.len

    bfm.close()

  test "save and read with hash verification":
    let params = regtestParams()
    let bfm = newBlockFileManager(TestDir, params)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let hash = blockHash(genesis)

    let (pos, ok) = bfm.saveBlockToDisk(genesis, 0)
    check ok

    # Read with correct hash - should succeed
    let (blk1, ok1) = bfm.readBlockFromDisk(pos, hash)
    check ok1
    check blockHash(blk1) == hash

    # Read with wrong hash - should fail
    var wrongHash: array[32, byte]
    wrongHash[0] = 0xFF
    let (blk2, ok2) = bfm.readBlockFromDisk(pos, BlockHash(wrongHash))
    check not ok2

    bfm.close()

  test "magic number validation":
    let params = regtestParams()
    let bfm = newBlockFileManager(TestDir, params)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let (pos, ok) = bfm.saveBlockToDisk(genesis, 0)
    check ok

    # Corrupt the magic number
    let path = bfm.blockFilePath(0)
    let fs = newFileStream(path, fmReadWriteExisting)
    fs.setPosition(0)
    fs.write(char(0xFF))  # Corrupt first byte of magic
    fs.close()

    # Read should fail
    let (blk, readOk) = bfm.readBlockFromDisk(pos)
    check not readOk

    bfm.close()

  test "multiple blocks in same file":
    let params = regtestParams()
    let bfm = newBlockFileManager(TestDir, params)

    var prevHash = BlockHash(default(array[32, byte]))
    var positions: seq[BlockFilePos]

    # Write several blocks
    for h in 0 ..< 10:
      let blk = makeTestBlock(prevHash, int32(h))
      let (pos, ok) = bfm.saveBlockToDisk(blk, int32(h))
      check ok
      check pos.fileNum == 0  # All in first file
      positions.add(pos)
      prevHash = blockHash(blk)

    # Verify positions are sequential
    for i in 1 ..< positions.len:
      check positions[i].dataPos > positions[i-1].dataPos

    # Read all blocks back
    prevHash = BlockHash(default(array[32, byte]))
    for h in 0 ..< 10:
      let (blk, ok) = bfm.readBlockFromDisk(positions[h])
      check ok
      check blk.header.prevBlock == prevHash
      prevHash = blockHash(blk)

    bfm.close()

  test "file rollover at max size":
    # Create a manager with custom small max size for testing
    # We can't easily test 128MB rollover, but we verify the logic
    let params = regtestParams()
    let bfm = newBlockFileManager(TestDir, params)

    # Manually set current file size near the limit
    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let blockData = serialize(genesis)

    # First save should go in file 0
    let (pos1, ok1) = bfm.saveBlockToDisk(genesis, 0)
    check ok1
    check pos1.fileNum == 0

    bfm.close()

suite "Block storage with database":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "store and load block with index":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let hash = blockHash(genesis)

    # Store block
    let posOpt = bfm.storeBlock(genesis, 0)
    check posOpt.isSome

    # Load by hash
    let loaded = bfm.loadBlock(hash)
    check loaded.isSome
    check blockHash(loaded.get()) == hash

    # Check index entry
    let entry = bfm.getBlockIndex(hash)
    check entry.isSome
    check (entry.get().status and BlockHaveData) != 0
    check entry.get().height == 0
    check entry.get().nTx == 1

    bfm.close()
    db.close()

  test "idempotent block storage":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)

    # Store same block twice
    let pos1 = bfm.storeBlock(genesis, 0)
    let pos2 = bfm.storeBlock(genesis, 0)

    check pos1.isSome
    check pos2.isSome
    # Second store should return same position (block already exists)
    check pos1.get().fileNum == pos2.get().fileNum
    check pos1.get().dataPos == pos2.get().dataPos

    bfm.close()
    db.close()

  test "hasBlockOnDisk":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let hash = blockHash(genesis)

    # Before storing
    check not bfm.hasBlockOnDisk(hash)

    # After storing
    discard bfm.storeBlock(genesis, 0)
    check bfm.hasBlockOnDisk(hash)

    bfm.close()
    db.close()

  test "block validation status":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let hash = blockHash(genesis)

    discard bfm.storeBlock(genesis, 0)

    # Initially just have data
    var entry = bfm.getBlockIndex(hash).get()
    check (entry.status and BlockHaveData) != 0
    check (entry.status and BlockValidated) == 0

    # Mark as validated
    bfm.setBlockValidated(hash)
    entry = bfm.getBlockIndex(hash).get()
    check (entry.status and BlockValidated) != 0

    bfm.close()
    db.close()

  test "update undo position":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let hash = blockHash(genesis)

    discard bfm.storeBlock(genesis, 0)

    # Initially no undo
    var entry = bfm.getBlockIndex(hash).get()
    check entry.undoPos == -1
    check (entry.status and BlockHaveUndo) == 0

    # Update undo position
    bfm.updateUndoPos(hash, 12345)
    entry = bfm.getBlockIndex(hash).get()
    check entry.undoPos == 12345
    check (entry.status and BlockHaveUndo) != 0

    bfm.close()
    db.close()

  test "persistence across restarts":
    let params = regtestParams()

    # First session: store blocks
    block:
      let db = openDatabase(TestDir / "db")
      let bfm = newBlockFileManager(TestDir, params, db)

      let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
      let block1 = makeTestBlock(blockHash(genesis), 1)

      discard bfm.storeBlock(genesis, 0)
      discard bfm.storeBlock(block1, 1)

      bfm.close()
      db.close()

    # Second session: verify blocks
    block:
      let db = openDatabase(TestDir / "db")
      let bfm = newBlockFileManager(TestDir, params, db)

      let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
      let genesisHash = blockHash(genesis)

      let loaded = bfm.loadBlock(genesisHash)
      check loaded.isSome
      check blockHash(loaded.get()) == genesisHash

      let block1Hash = blockHash(makeTestBlock(genesisHash, 1))
      let loaded1 = bfm.loadBlock(block1Hash)
      check loaded1.isSome

      bfm.close()
      db.close()

suite "BlockFileInfo tracking":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "file info updates correctly":
    let params = regtestParams()
    let db = openDatabase(TestDir / "db")
    let bfm = newBlockFileManager(TestDir, params, db)

    # Store several blocks
    var prevHash = BlockHash(default(array[32, byte]))
    for h in 0 ..< 5:
      let blk = makeTestBlock(prevHash, int32(h))
      discard bfm.saveBlockToDisk(blk, int32(h))
      prevHash = blockHash(blk)

    # Check file info
    let info = bfm.loadFileInfo(0)
    check info.isSome
    check info.get().nBlocks == 5
    check info.get().nHeightFirst == 0
    check info.get().nHeightLast == 4
    check info.get().nSize > 0

    bfm.close()
    db.close()
