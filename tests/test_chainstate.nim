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

proc makeSimpleBlock(prevHash: BlockHash, height: int32, extra: uint32 = 0): Block =
  ## Create a simple block with just a coinbase (height+extra in scriptSig for unique txid)
  ## Use 'extra' to distinguish alternative fork blocks at the same height
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff), byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let extraBytes = @[byte(extra and 0xff), byte((extra shr 8) and 0xff), byte((extra shr 16) and 0xff), byte((extra shr 24) and 0xff)]
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04)] & extraBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x51)]  # OP_1
    )],
    witnesses: @[],
    lockTime: 0
  )
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

suite "ChainState unspendable filter (CScript::IsUnspendable)":
  ## Regression for the dumptxoutset 2x-coin-count bug. Bitcoin Core's
  ## `AddCoins` (coins.cpp) skips outputs whose scriptPubKey is provably
  ## unspendable per `CScript::IsUnspendable()` (script.h:563): OP_RETURN-
  ## prefixed OR larger than MAX_SCRIPT_SIZE (10000 bytes). nimrod's
  ## chainstate must do the same so the UTXO set — and therefore
  ## dumptxoutset — matches Core byte-for-byte.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "OP_RETURN coinbase witness-commitment output not added to UTXO":
    # This mirrors what Core-mined regtest blocks at height >= 1 carry:
    # a spendable P2W* output PLUS a witness-commitment OP_RETURN output.
    # The OP_RETURN output must NOT enter the chainstate.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Build a coinbase that has TWO outputs: a P2W* spendable + an OP_RETURN.
    let heightBytes = @[byte(1), 0, 0, 0]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                          vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000),
              scriptPubKey: @[byte(0x00), 0x14] &
                @(array[20, byte](default(array[20, byte])))),
        # 0x6a = OP_RETURN, 0x24 = push 36 bytes (witness commitment header).
        TxOut(value: Satoshi(0),
              scriptPubKey: @[byte(0x6a), 0x24] & newSeq[byte](36))
      ],
      witnesses: @[],
      lockTime: 0
    )
    let blk = makeTestBlock(genesisHash, 1, @[coinbase])

    let r = cs.connectBlock(blk, 1)
    check r.isOk

    # The spendable output (vout=0) MUST be present.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 0)).isSome
    # The OP_RETURN witness-commitment output (vout=1) MUST NOT be present.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 1)).isNone

    cs.close()

  test "oversize scriptPubKey (> MAX_SCRIPT_SIZE) not added to UTXO":
    # MAX_SCRIPT_SIZE = 10000 bytes per Core script.h:40. Anything strictly
    # larger is provably unspendable and never enters the chainstate.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let heightBytes = @[byte(1), 0, 0, 0]
    # 10001 bytes — strictly above the limit. Core treats this as
    # IsUnspendable() == true.
    let oversized = newSeq[byte](10001)
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                          vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000),
              scriptPubKey: @[byte(0x51)]),  # OP_1 -- spendable
        TxOut(value: Satoshi(0), scriptPubKey: oversized)
      ],
      witnesses: @[],
      lockTime: 0
    )
    let blk = makeTestBlock(genesisHash, 1, @[coinbase])

    let r = cs.connectBlock(blk, 1)
    check r.isOk
    # Spendable vout=0 present, oversize vout=1 absent.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 1)).isNone

    cs.close()

suite "ChainState scrubunspendable (legacy datadir cleanup)":
  ## The write-time `isUnspendable` filter (commit 94b7755) only stops new
  ## OP_RETURN / oversize coins from entering the chainstate. Datadirs created
  ## BEFORE that fix still carry orphan entries. `scrubUnspendable` is the
  ## one-shot operator-invoked tool that walks cfUtxo and removes them.
  ## These tests synthesize a "pre-fix" chainstate by writing the orphans
  ## directly via `cs.db.putUtxo`, bypassing the new filter.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "scrubUnspendable removes OP_RETURN + oversize coins, keeps spendable":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect a real spendable coinbase via the normal path.
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let goodTxid = genesis.txs[0].txid()

    # Synthesize three "legacy" orphan entries by going around the filter
    # with direct db writes — this is exactly what a pre-fix nimrod build
    # would have left on disk.
    var op1Txid: array[32, byte]; op1Txid[0] = 0xAA
    let opReturnEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0),
                    scriptPubKey: @[byte(0x6a), 0x24] & newSeq[byte](36)),
      height: 1, isCoinbase: true)
    cs.db.putUtxo(OutPoint(txid: TxId(op1Txid), vout: 1), opReturnEntry)

    var op2Txid: array[32, byte]; op2Txid[0] = 0xBB
    let oversizeEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0), scriptPubKey: newSeq[byte](10001)),
      height: 2, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(op2Txid), vout: 0), oversizeEntry)

    var op3Txid: array[32, byte]; op3Txid[0] = 0xCC
    let opReturnEmptyPushEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a)]),
      height: 3, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(op3Txid), vout: 0), opReturnEmptyPushEntry)

    # Sanity: the legacy orphans are visible via the DB layer.
    check cs.db.getUtxo(OutPoint(txid: TxId(op1Txid), vout: 1)).isSome
    check cs.db.getUtxo(OutPoint(txid: TxId(op2Txid), vout: 0)).isSome
    check cs.db.getUtxo(OutPoint(txid: TxId(op3Txid), vout: 0)).isSome
    # Real spendable coinbase is in the cache (not yet flushed to disk).
    check cs.getUtxo(OutPoint(txid: goodTxid, vout: 0)).isSome

    let res = cs.scrubUnspendable()
    check res.removed == 3
    check res.bytesFreed > 0

    # All three orphans gone.
    check cs.db.getUtxo(OutPoint(txid: TxId(op1Txid), vout: 1)).isNone
    check cs.db.getUtxo(OutPoint(txid: TxId(op2Txid), vout: 0)).isNone
    check cs.db.getUtxo(OutPoint(txid: TxId(op3Txid), vout: 0)).isNone
    # Real coinbase UTXO is untouched.
    check cs.getUtxo(OutPoint(txid: goodTxid, vout: 0)).isSome

    cs.close()

  test "scrubUnspendable is idempotent (second call removes zero)":
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    # Plant one orphan and a real spendable entry written directly.
    var orphanTxid: array[32, byte]; orphanTxid[0] = 0xDD
    let orphan = UtxoEntry(
      output: TxOut(value: Satoshi(0),
                    scriptPubKey: @[byte(0x6a), 0x10] & newSeq[byte](16)),
      height: 1, isCoinbase: true)
    cs.db.putUtxo(OutPoint(txid: TxId(orphanTxid), vout: 0), orphan)

    var spendableTxid: array[32, byte]; spendableTxid[0] = 0xEE
    let spendable = UtxoEntry(
      output: TxOut(value: Satoshi(5000),
                    scriptPubKey: @[byte(0x00), 0x14] &
                      @(array[20, byte](default(array[20, byte])))),
      height: 2, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(spendableTxid), vout: 0), spendable)

    let first = cs.scrubUnspendable()
    check first.removed == 1
    check first.bytesFreed > 0

    let second = cs.scrubUnspendable()
    check second.removed == 0
    check second.bytesFreed == 0

    # Spendable entry survived both passes.
    check cs.db.getUtxo(OutPoint(txid: TxId(spendableTxid), vout: 0)).isSome
    # Orphan still gone.
    check cs.db.getUtxo(OutPoint(txid: TxId(orphanTxid), vout: 0)).isNone

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
    # Unique coinbase for block 100 (include height in scriptSig to avoid txid collision)
    let heightBytes100 = @[byte(100 and 0xff), byte((100 shr 8) and 0xff), byte(0), byte(0)]
    let coinbase = Transaction(version: 1, inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32), scriptSig: @[byte(0x04)] & heightBytes100, sequence: 0xFFFFFFFF'u32)], outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])], witnesses: @[], lockTime: 0)
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
    # Use extra=1 to ensure chain B coinbases have different txids than chain A
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 1)
    let block1BHash = getBlockHash(block1B)

    let block2B = makeSimpleBlock(block1BHash, 2, extra = 1)
    let block2BHash = getBlockHash(block2B)

    let block3B = makeSimpleBlock(block2BHash, 3, extra = 1)

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

# ============================================================================
# Side-branch acceptance tests (Pattern Y closure 2026-05-05)
#
# nimrod's pre-fix `handleSubmitBlock` side-branch arm computed a
# hypothetical newTotalWork and returned "inconclusive" but never persisted
# the side-branch block.  That made the corpus entry
# `regression/reorg-via-submitblock` fail in PARTIAL form (B1 OK but B2
# rejected with "rejected"): B1's parent (a base-chain block) was still in
# the active block_index, so B1 returned "inconclusive"; but because B1
# itself was never stored, B2 — whose parent IS B1 — fell into the
# "previous block truly unknown" path and was rejected outright.  The fix
# adds (a) `putBlockIndexHashOnly` to the storage layer and (b) two new
# behaviours in the side-branch arm: side-branch blocks are persisted with
# cumulative chain_work, and a strictly heavier side-branch triggers a
# reorg via the existing `handleReorg`.  Counterpart to Bitcoin Core's
# `BlockManager::AcceptBlock` (validation.cpp), which always writes a
# CBlockIndex regardless of which chain the block lives on.
# Reference fix in rustoshi: 68a422b.
# ============================================================================

suite "Side-branch block index persistence (Pattern Y storage layer)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "putBlockIndexHashOnly stores hash entry but preserves height->hash":
    # Build the database that submit_block's side-branch arm uses for
    # parent lookup.  Active chain: G -> A1.  Side-branch: B1 sharing
    # parent G.  After putBlockIndexHashOnly, both A1 and B1 should be
    # findable by hash, but the height=1 -> hash mapping must STILL point
    # at A1.  This is the exact invariant submit_block needs so that B2
    # (parent = B1) can find its parent in a future call.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let hashA1 = getBlockHash(blockA1)
    check cs.bestHeight == 1
    check cs.bestBlockHash == hashA1

    # Build a side-branch B1 sharing parent G.  Its hash differs from A1
    # because we set a different `extra` byte in the coinbase.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let hashB1 = getBlockHash(blockB1)
    check hashB1 != hashA1

    # Persist B1 via the side-branch helper (mirrors what handleSubmitBlock's
    # else-arm now does).
    cs.db.storeBlock(blockB1)
    let sideIdx = BlockIndex(
      hash: hashB1,
      height: 1,
      status: bsValidated,
      prevHash: blockB1.header.prevBlock,
      header: blockB1.header,
      totalWork: cs.totalWork,  # value doesn't matter for this test
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0
    )
    cs.db.putBlockIndexHashOnly(sideIdx)

    # B1 must be findable by hash (side-branch parent-lookup invariant).
    let b1IdxOpt = cs.db.getBlockIndex(hashB1)
    check b1IdxOpt.isSome
    check b1IdxOpt.get().hash == hashB1

    # A1 must STILL be findable by hash.
    let a1IdxOpt = cs.db.getBlockIndex(hashA1)
    check a1IdxOpt.isSome

    # Active chain ownership of height=1 must be unchanged: getBlockHashByHeight
    # still points at A1.  Pre-fix `putBlockIndex` (which we deliberately did
    # NOT call here) would have CLOBBERED this to point at B1.
    let activeAt1 = cs.db.getBlockHashByHeight(1)
    check activeAt1.isSome
    check activeAt1.get() == hashA1

    # B1's block body is also persisted (storeBlock).
    let b1BlockOpt = cs.db.getBlock(hashB1)
    check b1BlockOpt.isSome

    cs.close()

  test "side-branch chain B1->B2 — child can find parent in index":
    # The exact failure mode Pattern Y exhibited in nimrod: even when B1
    # is accepted as a side-branch and returns "inconclusive", the storage
    # invariant must hold so that a follow-up B2 (parent = B1) can look up
    # B1 via cs.db.getBlockIndex.  Pre-fix this lookup returned None.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let blockA2 = makeSimpleBlock(getBlockHash(blockA1), 2, extra = 0xAA)
    discard cs.connectBlock(blockA2, 2)
    check cs.bestHeight == 2

    # Side-branch B1 (parent = G), persisted as side-branch.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let hashB1 = getBlockHash(blockB1)
    cs.db.storeBlock(blockB1)
    let b1Idx = BlockIndex(
      hash: hashB1,
      height: 1,
      status: bsValidated,
      prevHash: blockB1.header.prevBlock,
      header: blockB1.header,
      totalWork: cs.totalWork,
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0
    )
    cs.db.putBlockIndexHashOnly(b1Idx)

    # Now build B2 (parent = B1).  Pre-fix cs.db.getBlockIndex(hashB1) was
    # None — exactly the symptom the corpus entry caught.
    let blockB2 = makeSimpleBlock(hashB1, 2, extra = 0xBB)
    let hashB2 = getBlockHash(blockB2)
    let parentLookup = cs.db.getBlockIndex(blockB2.header.prevBlock)
    check parentLookup.isSome  # would be None pre-fix
    check parentLookup.get().hash == hashB1
    check parentLookup.get().height == 1

    # And the active chain's tip is still A2.
    check cs.bestHeight == 2

    cs.close()

suite "Reorg via side-branch extension (Pattern Y end-to-end)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "heavier 3-block side-branch overtakes 2-block active chain":
    # Mirrors the full corpus scenario `regression/reorg-via-submitblock`:
    # active chain G->A1->A2 (h=2); submit B1, B2, B3 as a competing chain
    # rooted at G; expect tip to flip to B3 with the displaced A blocks
    # remaining findable in the block index.
    #
    # We exercise the same handleReorg call the new server.nim side-branch
    # arm performs once newTotalWork > cs.totalWork.  The block-index
    # plumbing (putBlockIndexHashOnly) is what makes the per-block parent
    # lookups inside that arm succeed in the first place — verified above.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let blockA2 = makeSimpleBlock(getBlockHash(blockA1), 2, extra = 0xAA)
    discard cs.connectBlock(blockA2, 2)
    let coinbaseA1 = blockA1.txs[0].txid()
    let coinbaseA2 = blockA2.txs[0].txid()
    check cs.bestHeight == 2

    # Build the heavier B-chain (3 blocks, all rooted at genesis).  Match
    # the persistence pattern submit_block's side-branch arm uses: store
    # each block + a hash-only block_index entry.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let blockB2 = makeSimpleBlock(getBlockHash(blockB1), 2, extra = 0xBB)
    let blockB3 = makeSimpleBlock(getBlockHash(blockB2), 3, extra = 0xBB)

    for blk in [blockB1, blockB2, blockB3]:
      let h = getBlockHash(blk)
      cs.db.storeBlock(blk)
      let idx = BlockIndex(
        hash: h,
        height: cs.bestHeight + 1,  # placeholder; only matters for replay
        status: bsValidated,
        prevHash: blk.header.prevBlock,
        header: blk.header,
        totalWork: cs.totalWork,
        undoPos: FlatFilePos(fileNum: -1, pos: -1),
        failureFlags: BLOCK_NO_FAILURE,
        sequenceId: 0
      )
      cs.db.putBlockIndexHashOnly(idx)

    # Reorg from active tip (A2) back to genesis, then connect B1->B2->B3.
    let newChain = @[blockB1, blockB2, blockB3]
    let reorgRes = cs.handleReorg(genesisHash, newChain)
    check reorgRes.isOk
    check cs.bestHeight == 3
    check cs.bestBlockHash == getBlockHash(blockB3)

    # Chain B coinbases are now in UTXO; chain A coinbases are gone.
    check cs.getUtxo(OutPoint(txid: blockB1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: blockB2.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: blockB3.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbaseA1, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbaseA2, vout: 0)).isNone

    # The displaced A-chain blocks are still findable in the block_index
    # (BlockManager::AcceptBlock parity — never deletes a known block).
    # connectBlock for A1/A2 wrote both hash-keyed and height-keyed entries;
    # the height-keyed one for h=1 has now been overwritten by B1 (correct,
    # height index follows active chain), but the hash-keyed entries
    # survive, so reconsiderblock / getblockheader can still find them.
    check cs.db.getBlockIndex(getBlockHash(blockA1)).isSome
    check cs.db.getBlockIndex(getBlockHash(blockA2)).isSome
    # And block bodies are still on disk.
    check cs.db.getBlock(getBlockHash(blockA1)).isSome
    check cs.db.getBlock(getBlockHash(blockA2)).isSome

    cs.close()

