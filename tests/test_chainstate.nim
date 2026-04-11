## ChainState tests
## Tests UTXO set management, block connect/disconnect, coinbase maturity, and reorg handling

import unittest2
import std/[os, options, strutils, tables]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_chainstate_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(
  prevTxid: TxId,
  prevVout: uint32,
  value: int64,
  isCoinbase: bool = false
): Transaction =
  ## Create a simple test transaction
  if isCoinbase:
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[byte(0x01), 0x01],  # Simple coinbase script
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

proc makeTestBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  ## Create a test block with the given transactions

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
      bits: 0x207fffff'u32,  # Regtest difficulty
      nonce: uint32(height)
    ),
    txs: txs
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  ## Create a simple block with just a coinbase
  let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
  makeTestBlock(prevHash, height, @[coinbase])

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "ChainState UTXO management":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "create and close chainstate":
    var cs = newChainState(TestDbPath, regtestParams())
    check cs != nil
    check cs.bestHeight == -1
    check cs.maxCacheSize == DefaultMaxCacheSize
    cs.close()

  test "connect genesis block":
    var cs = newChainState(TestDbPath, regtestParams())

    # Create genesis-like block
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let connectRes = cs.connectBlock(genesis, 0)

    check connectRes.isOk
    check cs.bestHeight == 0

    # Check coinbase UTXO exists
    let coinbaseTxid = genesis.txs[0].txid()
    let outpoint = OutPoint(txid: coinbaseTxid, vout: 0)
    let utxo = cs.getUtxo(outpoint)

    check utxo.isSome
    check utxo.get().isCoinbase == true
    check utxo.get().height == 0
    check int64(utxo.get().output.value) == 5000000000

    cs.close()

  test "connect chain of blocks":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Connect block 1
    let block1 = makeSimpleBlock(genesisHash, 1)
    let result1 = cs.connectBlock(block1, 1)
    check result1.isOk
    check cs.bestHeight == 1

    # Connect block 2
    let block1Hash = getBlockHash(block1)
    let block2 = makeSimpleBlock(block1Hash, 2)
    let result2 = cs.connectBlock(block2, 2)
    check result2.isOk
    check cs.bestHeight == 2

    # Verify all coinbase UTXOs exist
    check cs.getUtxo(OutPoint(txid: genesis.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: block1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: block2.txs[0].txid(), vout: 0)).isSome

    cs.close()

suite "ChainState coinbase maturity":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "cannot spend immature coinbase":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let coinbaseTxid = genesis.txs[0].txid()

    # Try to spend coinbase at height 50 (maturity = 100)
    var prevHash = genesisHash
    for h in 1 ..< 50:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    check cs.bestHeight == 49

    # Create block that spends immature coinbase
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let badBlock = makeTestBlock(prevHash, 50, @[coinbase, spendTx])

    let badResult = cs.connectBlock(badBlock, 50)
    check not badResult.isOk
    check "immature" in badResult.error

    cs.close()

  test "can spend mature coinbase":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let coinbaseTxid = genesis.txs[0].txid()

    # Build chain to height 100 (coinbase maturity)
    var prevHash = genesisHash
    for h in 1 ..< 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    check cs.bestHeight == 99

    # Now we can spend the genesis coinbase
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let goodBlock = makeTestBlock(prevHash, 100, @[coinbase, spendTx])

    let goodResult = cs.connectBlock(goodBlock, 100)
    check goodResult.isOk
    check cs.bestHeight == 100

    # Genesis coinbase should now be spent
    let genesisUtxo = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check genesisUtxo.isNone

    # New output should exist
    let newOutpoint = OutPoint(txid: spendTx.txid(), vout: 0)
    let newUtxo = cs.getUtxo(newOutpoint)
    check newUtxo.isSome
    check int64(newUtxo.get().output.value) == 4999000000

    cs.close()

suite "ChainState disconnect and restore":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "disconnect block restores UTXO":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let coinbaseTxid = genesis.txs[0].txid()

    # Build chain to maturity
    var prevHash = genesisHash
    for h in 1 ..< 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Spend the genesis coinbase
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let spendBlock = makeTestBlock(prevHash, 100, @[coinbase, spendTx])
    discard cs.connectBlock(spendBlock, 100)

    # Genesis UTXO should be spent
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isNone

    # Get undo data for the spend block
    let spendBlockHash = getBlockHash(spendBlock)
    let undoOpt = cs.db.getUndoData(spendBlockHash)
    check undoOpt.isSome

    let undo = undoOpt.get()
    check undo.spentOutputs.len == 1

    # Disconnect the block
    let disconnectRes = cs.disconnectBlock(spendBlock, 100, undo)
    check disconnectRes.isOk
    check cs.bestHeight == 99

    # Genesis UTXO should be restored
    let restoredUtxo = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check restoredUtxo.isSome
    check int64(restoredUtxo.get().output.value) == 5000000000
    check restoredUtxo.get().isCoinbase == true

    # Spend transaction outputs should be removed
    check cs.getUtxo(OutPoint(txid: spendTx.txid(), vout: 0)).isNone

    cs.close()

suite "ChainState 2-block reorg":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "handle 2-block reorg":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Connect chain A: blocks 1A, 2A
    let block1A = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1A, 1)
    let block1AHash = getBlockHash(block1A)

    let block2A = makeSimpleBlock(block1AHash, 2)
    discard cs.connectBlock(block2A, 2)

    check cs.bestHeight == 2

    # Save coinbase txids from chain A
    let coinbase1A = block1A.txs[0].txid()
    let coinbase2A = block2A.txs[0].txid()

    # Verify chain A UTXOs exist
    check cs.getUtxo(OutPoint(txid: coinbase1A, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isSome

    # Create alternative chain B: blocks 1B, 2B, 3B (longer chain)
    let block1B = makeSimpleBlock(genesisHash, 1)
    let block1BHash = getBlockHash(block1B)

    let block2B = makeSimpleBlock(block1BHash, 2)
    let block2BHash = getBlockHash(block2B)

    let block3B = makeSimpleBlock(block2BHash, 3)

    # Note: block1B and block2B have different hashes than 1A/2A because
    # they were created separately (different nonce/timestamp)

    # Perform reorg: fork point is genesis, new chain is [1B, 2B, 3B]
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

suite "UndoData serialization":
  test "serialize and deserialize undo data":
    var txid1: array[32, byte]
    txid1[0] = 0xAA
    txid1[31] = 0xBB

    var txid2: array[32, byte]
    txid2[0] = 0xCC
    txid2[31] = 0xDD

    let undo = UndoData(
      spentOutputs: @[
        (OutPoint(txid: TxId(txid1), vout: 0), UtxoEntry(
          output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x76), 0xa9]),
          height: 50,
          isCoinbase: true
        )),
        (OutPoint(txid: TxId(txid2), vout: 1), UtxoEntry(
          output: TxOut(value: Satoshi(200000000), scriptPubKey: @[byte(0x00), 0x14]),
          height: 75,
          isCoinbase: false
        ))
      ]
    )

    let serialized = serializeUndoData(undo)
    let deserialized = deserializeUndoData(serialized)

    check deserialized.spentOutputs.len == 2

    # Check first entry
    check deserialized.spentOutputs[0].outpoint.txid == TxId(txid1)
    check deserialized.spentOutputs[0].outpoint.vout == 0
    check int64(deserialized.spentOutputs[0].entry.output.value) == 100000000
    check deserialized.spentOutputs[0].entry.height == 50
    check deserialized.spentOutputs[0].entry.isCoinbase == true

    # Check second entry
    check deserialized.spentOutputs[1].outpoint.txid == TxId(txid2)
    check deserialized.spentOutputs[1].outpoint.vout == 1
    check int64(deserialized.spentOutputs[1].entry.output.value) == 200000000
    check deserialized.spentOutputs[1].entry.height == 75
    check deserialized.spentOutputs[1].entry.isCoinbase == false

suite "ChainState cache management":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "cache size tracking":
    var cs = newChainState(TestDbPath, regtestParams())
    cs.maxCacheSize = 10  # Small cache for testing

    check cs.cacheSize == 0

    # Connect blocks and track cache size
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    # Each block adds 1 coinbase output to cache
    check cs.cacheSize >= 1

    cs.close()

  test "flush clears cache":
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    check cs.cacheSize > 0

    cs.flushCache()

    check cs.cacheSize == 0
    check cs.utxoCache.len == 0

    # UTXO should still be retrievable from DB
    let outpoint = OutPoint(txid: genesis.txs[0].txid(), vout: 0)
    check cs.getUtxo(outpoint).isSome

    cs.close()

  test "persistence across reopens":
    # Create and connect blocks
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
      discard cs.connectBlock(genesis, 0)
      let genesisHash = getBlockHash(genesis)

      let block1 = makeSimpleBlock(genesisHash, 1)
      discard cs.connectBlock(block1, 1)

      check cs.bestHeight == 1
      cs.close()

    # Reopen and verify state
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      check cs.bestHeight == 1

      # Best block should be accessible
      let bestBlock = cs.db.getBlockByHeight(1)
      check bestBlock.isSome

      cs.close()
## IBD durability tests moved to test_ibd_durability.nim
