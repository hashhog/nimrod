## Tests for undo data storage and block disconnection
## Covers flat file storage, serialization, and chain reorganization

import unittest2
import std/[os, options, tables]
import ../src/storage/[db, chainstate, undo]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_undo_test"
const TestUndoPath = "/tmp/nimrod_undo_test/blocks"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(
  prevTxid: TxId,
  prevVout: uint32,
  value: int64,
  isCoinbase: bool = false,
  height: int32 = 0,
  extraNonce: array[4, byte] = default(array[4, byte])
): Transaction =
  ## Create a simple test transaction
  if isCoinbase:
    # Make coinbase unique by including height + extra nonce in scriptSig (BIP 34)
    let heightBytes = @[byte(height and 0xFF), byte((height shr 8) and 0xFF),
                        byte((height shr 16) and 0xFF), byte((height shr 24) and 0xFF)]
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[byte(0x08)] & heightBytes & @extraNonce,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )
  else:
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: prevTxid, vout: prevVout),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))
      )],
      witnesses: @[],
      lockTime: 0
    )

proc makeTestBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction], chainId: int32 = 0): Block =
  ## Create a test block with the given transactions
  ## chainId allows creating different blocks at the same height/prevHash
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  result = Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600) + uint32(chainId * 10),
      bits: 0x207fffff'u32,
      nonce: uint32(height) + uint32(chainId * 1000000)
    ),
    txs: txs
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32, chainId: int32 = 0): Block =
  ## Create a simple block with just a coinbase transaction
  ## chainId allows creating different blocks at the same height/prevHash
  var extraNonce: array[4, byte]
  let prevHashArr = array[32, byte](prevHash)
  for i in 0..3:
    extraNonce[i] = prevHashArr[i]
  # Add chainId to extraNonce to differentiate coinbase txids
  extraNonce[0] = extraNonce[0] xor byte(chainId and 0xFF)
  extraNonce[1] = extraNonce[1] xor byte((chainId shr 8) and 0xFF)
  let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true, height, extraNonce)
  makeTestBlock(prevHash, height, @[coinbase], chainId)

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "Undo data serialization":
  test "serialize and deserialize SpentOutput":
    let spent = SpentOutput(
      output: TxOut(
        value: Satoshi(100000000),
        scriptPubKey: @[byte(0x76), 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac]
      ),
      height: 50,
      isCoinbase: true
    )

    var w = BinaryWriter()
    w.serializeSpentOutput(spent)

    var r = BinaryReader(data: w.data, pos: 0)
    let deserialized = r.deserializeSpentOutput()

    check deserialized.height == 50
    check deserialized.isCoinbase == true
    check int64(deserialized.output.value) == 100000000
    check deserialized.output.scriptPubKey == spent.output.scriptPubKey

  test "serialize and deserialize TxUndo":
    var txUndo = TxUndo()
    txUndo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x00), 0x14]),
      height: 10,
      isCoinbase: false
    ))
    txUndo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(200000000), scriptPubKey: @[byte(0x76), 0xa9]),
      height: 20,
      isCoinbase: true
    ))

    var w = BinaryWriter()
    w.serializeTxUndo(txUndo)

    var r = BinaryReader(data: w.data, pos: 0)
    let deserialized = r.deserializeTxUndo()

    check deserialized.prevOutputs.len == 2
    check deserialized.prevOutputs[0].height == 10
    check deserialized.prevOutputs[0].isCoinbase == false
    check deserialized.prevOutputs[1].height == 20
    check deserialized.prevOutputs[1].isCoinbase == true

  test "serialize and deserialize BlockUndo":
    var blockUndo = BlockUndo()

    var tx1Undo = TxUndo()
    tx1Undo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x00)]),
      height: 10,
      isCoinbase: false
    ))
    blockUndo.txUndo.add(tx1Undo)

    var tx2Undo = TxUndo()
    tx2Undo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(200000000), scriptPubKey: @[byte(0x01)]),
      height: 20,
      isCoinbase: true
    ))
    tx2Undo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(300000000), scriptPubKey: @[byte(0x02)]),
      height: 30,
      isCoinbase: false
    ))
    blockUndo.txUndo.add(tx2Undo)

    let serialized = serializeBlockUndo(blockUndo)
    let deserialized = deserializeBlockUndo(serialized)

    check deserialized.txUndo.len == 2
    check deserialized.txUndo[0].prevOutputs.len == 1
    check deserialized.txUndo[1].prevOutputs.len == 2
    check deserialized.txUndo[1].prevOutputs[0].height == 20
    check deserialized.txUndo[1].prevOutputs[1].height == 30

suite "Undo flat file storage":
  setup:
    cleanupTestDb()
    createDir(TestUndoPath)

  teardown:
    cleanupTestDb()

  test "write and read block undo":
    let ufm = newUndoFileManager(TestUndoPath)
    let params = regtestParams()

    var blockUndo = BlockUndo()
    var txUndo = TxUndo()
    txUndo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x00), 0x14]),
      height: 10,
      isCoinbase: false
    ))
    blockUndo.txUndo.add(txUndo)

    # Create a fake prev block hash
    var prevHash: array[32, byte]
    prevHash[0] = 0xAA
    prevHash[31] = 0xBB

    let (pos, writeOk) = ufm.writeBlockUndo(blockUndo, BlockHash(prevHash), params)
    check writeOk
    check not pos.isNull
    check pos.fileNum == 0

    # Read it back
    let (readUndo, readOk) = ufm.readBlockUndo(pos, BlockHash(prevHash), params)
    check readOk
    check readUndo.txUndo.len == 1
    check readUndo.txUndo[0].prevOutputs.len == 1
    check readUndo.txUndo[0].prevOutputs[0].height == 10

    ufm.close()

  test "checksum verification fails on corruption":
    let ufm = newUndoFileManager(TestUndoPath)
    let params = regtestParams()

    var blockUndo = BlockUndo()
    var txUndo = TxUndo()
    txUndo.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x00)]),
      height: 10,
      isCoinbase: false
    ))
    blockUndo.txUndo.add(txUndo)

    var prevHash: array[32, byte]
    prevHash[0] = 0xCC

    let (pos, writeOk) = ufm.writeBlockUndo(blockUndo, BlockHash(prevHash), params)
    check writeOk

    # Try to read with wrong prev hash (should fail checksum)
    var wrongHash: array[32, byte]
    wrongHash[0] = 0xDD
    let (_, readOk) = ufm.readBlockUndo(pos, BlockHash(wrongHash), params)
    check not readOk  # Should fail due to checksum mismatch

    ufm.close()

  test "multiple blocks in same file":
    let ufm = newUndoFileManager(TestUndoPath)
    let params = regtestParams()

    # Write first block undo
    var blockUndo1 = BlockUndo()
    var txUndo1 = TxUndo()
    txUndo1.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x00)]),
      height: 10,
      isCoinbase: false
    ))
    blockUndo1.txUndo.add(txUndo1)

    var prevHash1: array[32, byte]
    prevHash1[0] = 0x11
    let (pos1, ok1) = ufm.writeBlockUndo(blockUndo1, BlockHash(prevHash1), params)
    check ok1

    # Write second block undo
    var blockUndo2 = BlockUndo()
    var txUndo2 = TxUndo()
    txUndo2.prevOutputs.add(SpentOutput(
      output: TxOut(value: Satoshi(200000000), scriptPubKey: @[byte(0x01)]),
      height: 20,
      isCoinbase: true
    ))
    blockUndo2.txUndo.add(txUndo2)

    var prevHash2: array[32, byte]
    prevHash2[0] = 0x22
    let (pos2, ok2) = ufm.writeBlockUndo(blockUndo2, BlockHash(prevHash2), params)
    check ok2

    # Both should be in same file
    check pos1.fileNum == pos2.fileNum
    check pos1.pos < pos2.pos

    # Read both back
    let (read1, readOk1) = ufm.readBlockUndo(pos1, BlockHash(prevHash1), params)
    check readOk1
    check read1.txUndo[0].prevOutputs[0].height == 10

    let (read2, readOk2) = ufm.readBlockUndo(pos2, BlockHash(prevHash2), params)
    check readOk2
    check read2.txUndo[0].prevOutputs[0].height == 20

    ufm.close()

suite "ChainState disconnect with flat file undo":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "connect and disconnect single block":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let coinbaseTxid = genesis.txs[0].txid()

    check cs.bestHeight == 0
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isSome

    # Connect block 1
    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    check cs.bestHeight == 1

    # Disconnect block 1 using flat file undo
    let disconnectRes = cs.disconnectBlock(block1)
    check disconnectRes.isOk
    check cs.bestHeight == 0

    # Block 1 coinbase should be gone
    check cs.getUtxo(OutPoint(txid: block1.txs[0].txid(), vout: 0)).isNone

    # Genesis coinbase should still exist
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isSome

    cs.close()

  test "disconnect block with spent UTXOs":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let coinbaseTxid = genesis.txs[0].txid()

    # Build chain to maturity (100 blocks)
    var prevHash = genesisHash
    for h in 1 ..< 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Spend genesis coinbase at height 100
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true, 100)
    let spendBlock = makeTestBlock(prevHash, 100, @[coinbase, spendTx])
    discard cs.connectBlock(spendBlock, 100)

    # Genesis UTXO should be spent
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isNone
    check cs.bestHeight == 100

    # Disconnect the spend block
    let disconnectRes = cs.disconnectBlock(spendBlock)
    check disconnectRes.isOk
    check cs.bestHeight == 99

    # Genesis UTXO should be restored
    let restoredUtxo = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check restoredUtxo.isSome
    check int64(restoredUtxo.get().output.value) == 5000000000
    check restoredUtxo.get().isCoinbase == true

    # Spend transaction outputs should be gone
    check cs.getUtxo(OutPoint(txid: spendTx.txid(), vout: 0)).isNone

    cs.close()

suite "Chain reorg with flat file undo":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "2-block reorg with flat file undo":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0, chainId = 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Connect chain A: blocks 1A, 2A (chainId = 1)
    let block1A = makeSimpleBlock(genesisHash, 1, chainId = 1)
    discard cs.connectBlock(block1A, 1)
    let block1AHash = getBlockHash(block1A)

    let block2A = makeSimpleBlock(block1AHash, 2, chainId = 1)
    discard cs.connectBlock(block2A, 2)

    check cs.bestHeight == 2

    let coinbase1A = block1A.txs[0].txid()
    let coinbase2A = block2A.txs[0].txid()

    check cs.getUtxo(OutPoint(txid: coinbase1A, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isSome

    # Create alternative chain B: blocks 1B, 2B, 3B (chainId = 2)
    let block1B = makeSimpleBlock(genesisHash, 1, chainId = 2)
    let block1BHash = getBlockHash(block1B)

    let block2B = makeSimpleBlock(block1BHash, 2, chainId = 2)
    let block2BHash = getBlockHash(block2B)

    let block3B = makeSimpleBlock(block2BHash, 3, chainId = 2)

    # Perform reorg
    let newChain = @[block1B, block2B, block3B]
    let reorgRes = cs.handleReorg(genesisHash, newChain)

    check reorgRes.isOk
    check cs.bestHeight == 3

    # Chain A UTXOs should be gone
    check cs.getUtxo(OutPoint(txid: coinbase1A, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isNone

    # Chain B UTXOs should exist
    let coinbase1B = block1B.txs[0].txid()
    let coinbase2B = block2B.txs[0].txid()
    let coinbase3B = block3B.txs[0].txid()

    check cs.getUtxo(OutPoint(txid: coinbase1B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase2B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase3B, vout: 0)).isSome

    cs.close()

  test "reorg with spent outputs":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0, chainId = 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let genesisCoinbase = genesis.txs[0].txid()

    # Build to maturity and spend genesis coinbase (chainId = 1 for this chain)
    var prevHash = genesisHash
    for h in 1 ..< 100:
      let blk = makeSimpleBlock(prevHash, int32(h), chainId = 1)
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Spend genesis at height 100
    let spendTx = makeTestTransaction(genesisCoinbase, 0, 4999000000, false)
    let cb100 = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true, 100)
    let block100 = makeTestBlock(prevHash, 100, @[cb100, spendTx], chainId = 1)
    discard cs.connectBlock(block100, 100)

    check cs.getUtxo(OutPoint(txid: genesisCoinbase, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: spendTx.txid(), vout: 0)).isSome

    # Create alternative chain from height 99 that doesn't spend genesis (chainId = 2)
    let altBlock100 = makeSimpleBlock(prevHash, 100, chainId = 2)
    let altBlock100Hash = getBlockHash(altBlock100)
    let altBlock101 = makeSimpleBlock(altBlock100Hash, 101, chainId = 2)

    # Reorg: fork at height 99
    let reorgRes = cs.handleReorg(prevHash, @[altBlock100, altBlock101])
    check reorgRes.isOk
    check cs.bestHeight == 101

    # Genesis coinbase should be restored (unspent in new chain)
    check cs.getUtxo(OutPoint(txid: genesisCoinbase, vout: 0)).isSome

    # The spend transaction output should not exist
    check cs.getUtxo(OutPoint(txid: spendTx.txid(), vout: 0)).isNone

    cs.close()

suite "FlatFilePos":
  test "isNull checks":
    check FlatFilePos(fileNum: -1, pos: 0).isNull
    check FlatFilePos(fileNum: 0, pos: -1).isNull
    check FlatFilePos(fileNum: -1, pos: -1).isNull
    check not FlatFilePos(fileNum: 0, pos: 0).isNull
    check not FlatFilePos(fileNum: 0, pos: 100).isNull
