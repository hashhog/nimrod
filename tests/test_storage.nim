## Storage layer tests
## Tests RocksDB wrapper, chainstate, UTXO CRUD, and atomic batches

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_test_db"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

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
      scriptSig: @[byte(height and 0xff)],  # Simple height encoding
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),  # 50 BTC
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

suite "RocksDB wrapper":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "open and close database":
    let db = openDatabase(TestDbPath)
    check db != nil
    check dirExists(TestDbPath)
    db.close()

  test "put and get default column family":
    let db = openDatabase(TestDbPath)
    let key = @[byte(1), 2, 3]
    let value = @[byte(4), 5, 6, 7, 8]

    db.put(key, value)
    let retrieved = db.get(key)

    check retrieved.isSome
    check retrieved.get() == value
    db.close()

  test "put and get with column families":
    let db = openDatabase(TestDbPath)

    # Test each column family
    for cf in ColumnFamily:
      let key = @[byte(ord(cf)), 1, 2, 3]
      let value = @[byte(ord(cf)), 10, 20, 30]

      db.put(cf, key, value)
      let retrieved = db.get(cf, key)

      check retrieved.isSome
      check retrieved.get() == value

    db.close()

  test "delete key":
    let db = openDatabase(TestDbPath)
    let key = @[byte(1), 2, 3]
    let value = @[byte(4), 5, 6]

    db.put(key, value)
    check db.contains(key)

    db.delete(key)
    check not db.contains(key)
    check db.get(key).isNone

    db.close()

  test "write batch atomicity":
    let db = openDatabase(TestDbPath)
    let batch = db.newWriteBatch()

    # Add multiple operations to batch
    batch.put(@[byte(1)], @[byte(10)])
    batch.put(@[byte(2)], @[byte(20)])
    batch.put(@[byte(3)], @[byte(30)])

    # Not committed yet - should not be visible
    # (though in practice batch operations may be visible before commit)

    # Commit
    db.write(batch)

    # Now should be visible
    check db.get(@[byte(1)]).get() == @[byte(10)]
    check db.get(@[byte(2)]).get() == @[byte(20)]
    check db.get(@[byte(3)]).get() == @[byte(30)]

    batch.destroy()
    db.close()

  test "write batch with column families":
    let db = openDatabase(TestDbPath)
    let batch = db.newWriteBatch()

    batch.put(cfBlocks, @[byte(1)], @[byte(100)])
    batch.put(cfUtxo, @[byte(2)], @[byte(200)])
    batch.put(cfMeta, @[byte(3)], @[byte(255)])

    db.write(batch)

    check db.get(cfBlocks, @[byte(1)]).get() == @[byte(100)]
    check db.get(cfUtxo, @[byte(2)]).get() == @[byte(200)]
    check db.get(cfMeta, @[byte(3)]).get() == @[byte(255)]

    batch.destroy()
    db.close()

  test "key construction - block index key big endian":
    let key0 = blockIndexKey(0)
    check key0 == @[byte(0), 0, 0, 0]

    let key1 = blockIndexKey(1)
    check key1 == @[byte(0), 0, 0, 1]

    let key256 = blockIndexKey(256)
    check key256 == @[byte(0), 0, 1, 0]

    let keyBig = blockIndexKey(0x01020304)
    check keyBig == @[byte(1), 2, 3, 4]

  test "utxo key construction":
    var txid: array[32, byte]
    txid[0] = 0xAA
    txid[31] = 0xBB

    let key = utxoKey(txid, 0x12345678'u32)
    check key.len == 36
    check key[0] == 0xAA
    check key[31] == 0xBB
    check key[32] == 0x12
    check key[33] == 0x34
    check key[34] == 0x56
    check key[35] == 0x78

suite "ChainDb":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "open and close chain db":
    var cdb = openChainDb(TestDbPath)
    check cdb != nil
    check cdb.bestHeight == -1
    cdb.close()

  test "store and retrieve block":
    var cdb = openChainDb(TestDbPath)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    cdb.storeBlock(genesis)

    let headerBytes = serialize(genesis.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    let retrieved = cdb.getBlock(blockHash)
    check retrieved.isSome
    check retrieved.get().header.timestamp == genesis.header.timestamp
    check retrieved.get().txs.len == genesis.txs.len

    cdb.close()

  test "UTXO CRUD operations":
    var cdb = openChainDb(TestDbPath)

    var txid: array[32, byte]
    txid[0] = 0x42
    let outpoint = OutPoint(txid: TxId(txid), vout: 0)

    let entry = UtxoEntry(
      output: TxOut(
        value: Satoshi(100000000),
        scriptPubKey: @[byte(0x76), 0xa9]
      ),
      height: 100,
      isCoinbase: false
    )

    # Create
    cdb.putUtxo(outpoint, entry)

    # Read
    let retrieved = cdb.getUtxo(outpoint)
    check retrieved.isSome
    check int64(retrieved.get().output.value) == 100000000
    check retrieved.get().height == 100
    check retrieved.get().isCoinbase == false

    # Check exists
    check cdb.hasUtxo(outpoint)

    # Delete
    cdb.deleteUtxo(outpoint)
    check not cdb.hasUtxo(outpoint)
    check cdb.getUtxo(outpoint).isNone

    cdb.close()

  test "block index operations":
    var cdb = openChainDb(TestDbPath)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    let headerBytes = serialize(genesis.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    let idx = BlockIndex(
      hash: blockHash,
      height: 0,
      status: bsValidated,
      prevHash: genesis.header.prevBlock,
      header: genesis.header,
      totalWork: default(array[32, byte])
    )

    cdb.putBlockIndex(idx)

    # Retrieve by hash
    let byHash = cdb.getBlockIndex(blockHash)
    check byHash.isSome
    check byHash.get().height == 0
    check byHash.get().status == bsValidated

    # Retrieve hash by height
    let hashByHeight = cdb.getBlockHashByHeight(0)
    check hashByHeight.isSome
    check hashByHeight.get() == blockHash

    cdb.close()

  test "update best block":
    var cdb = openChainDb(TestDbPath)

    var blockHash: array[32, byte]
    blockHash[0] = 0xAB
    blockHash[31] = 0xCD

    cdb.updateBestBlock(BlockHash(blockHash), 42)

    check cdb.bestHeight == 42
    check array[32, byte](cdb.bestBlockHash)[0] == 0xAB
    check array[32, byte](cdb.bestBlockHash)[31] == 0xCD

    cdb.close()

    # Verify persistence
    var cdb2 = openChainDb(TestDbPath)
    check cdb2.bestHeight == 42
    check array[32, byte](cdb2.bestBlockHash)[0] == 0xAB
    cdb2.close()

  test "atomic applyBlock":
    var cdb = openChainDb(TestDbPath)

    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0, 2)
    cdb.applyBlock(genesis, 0)

    # Check block was stored
    let headerBytes = serialize(genesis.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))
    let retrieved = cdb.getBlock(blockHash)
    check retrieved.isSome

    # Check UTXOs were created for coinbase
    let coinbaseTxid = genesis.txs[0].txid()
    let coinbaseOutpoint = OutPoint(txid: coinbaseTxid, vout: 0)
    let coinbaseUtxo = cdb.getUtxo(coinbaseOutpoint)
    check coinbaseUtxo.isSome
    check coinbaseUtxo.get().isCoinbase == true
    check coinbaseUtxo.get().height == 0

    # Check best block was updated
    check cdb.bestHeight == 0
    check cdb.bestBlockHash == blockHash

    # Check block index
    let idx = cdb.getBlockIndex(blockHash)
    check idx.isSome
    check idx.get().status == bsValidated

    # Check tx index
    let txLoc = cdb.getTxIndex(coinbaseTxid)
    check txLoc.isSome
    check txLoc.get().blockHash == blockHash
    check txLoc.get().txIndex == 0

    cdb.close()

  test "chain of blocks":
    var cdb = openChainDb(TestDbPath)

    # Create and apply genesis
    let genesis = makeTestBlock(BlockHash(default(array[32, byte])), 0)
    cdb.applyBlock(genesis, 0)

    let genesisHeaderBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisHeaderBytes))

    # Create and apply block 1
    let block1 = makeTestBlock(genesisHash, 1)
    cdb.applyBlock(block1, 1)

    let block1HeaderBytes = serialize(block1.header)
    let block1Hash = BlockHash(doubleSha256(block1HeaderBytes))

    # Create and apply block 2
    let block2 = makeTestBlock(block1Hash, 2)
    cdb.applyBlock(block2, 2)

    # Verify chain state
    check cdb.bestHeight == 2

    # Verify all blocks accessible by height
    check cdb.getBlockHashByHeight(0).isSome
    check cdb.getBlockHashByHeight(1).isSome
    check cdb.getBlockHashByHeight(2).isSome
    check cdb.getBlockHashByHeight(3).isNone

    # Verify blocks accessible by hash
    check cdb.getBlock(genesisHash).isSome
    check cdb.getBlock(block1Hash).isSome

    cdb.close()
