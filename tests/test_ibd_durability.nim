## IBD Durability test
## Regression test for the post-reboot UTXO corruption bug:
## With WAL disabled during IBD, flushIBDBatch() must force memtables to SST
## files so that all column families (cfUtxo AND cfMeta) are durable.

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_ibd_durability_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(value: int64): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xFFFFFFFF'u32
      ),
      scriptSig: @[byte(0x01), 0x01],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeTestTransaction(5000000000)
  var txHashes: seq[array[32, byte]]
  txHashes.add(array[32, byte](coinbase.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: @[coinbase]
  )

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "ChainState IBD durability":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "IBD batch flush survives simulated crash":
    let targetHeight = int32(IbdBatchFlushInterval + 50)
    var expectedBestHeight: int32

    # Phase 1: Build chain in IBD mode, then close abruptly (no stopIBD)
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
      discard cs.connectBlock(genesis, 0)

      cs.startIBD()

      var prevHash = getBlockHash(genesis)
      for h in 1'i32 .. targetHeight:
        let blk = makeSimpleBlock(prevHash, h)
        let res = cs.connectBlockIBD(blk, h)
        check res.isOk
        prevHash = getBlockHash(blk)

      expectedBestHeight = cs.bestHeight
      check expectedBestHeight == targetHeight

      # Simulate crash: close the DB handle without graceful cleanup.
      # A real crash wouldn't run stopIBD or any destructors.
      cs.db.db.closeUnsafe()

    # Phase 2: Reopen and verify durability
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      # Height must be at least the last flush boundary (2000).
      # The 50 blocks after the flush boundary may be lost (they were in the
      # unflushed batch), but the flushed state must survive.
      check cs.bestHeight >= int32(IbdBatchFlushInterval)

      # Block index at the persisted height must be present
      let hashAtBest = cs.db.getBlockHashByHeight(cs.bestHeight)
      check hashAtBest.isSome

      cs.db.db.closeUnsafe()

  test "IBD batch flush keeps metadata and UTXOs consistent":
    let flushPoint = int32(IbdBatchFlushInterval)
    var lastCoinbaseTxid: TxId

    block:
      var cs = newChainState(TestDbPath, regtestParams())

      let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
      discard cs.connectBlock(genesis, 0)
      cs.startIBD()

      var prevHash = getBlockHash(genesis)
      for h in 1'i32 .. flushPoint:
        let blk = makeSimpleBlock(prevHash, h)
        let res = cs.connectBlockIBD(blk, h)
        check res.isOk
        prevHash = getBlockHash(blk)
        if h == flushPoint:
          lastCoinbaseTxid = blk.txs[0].txid()

      check cs.bestHeight == flushPoint
      cs.stopIBD()
      cs.db.db.closeUnsafe()

    # Reopen: height and UTXOs must agree
    block:
      var cs = newChainState(TestDbPath, regtestParams())
      check cs.bestHeight == flushPoint

      let utxo = cs.getUtxo(OutPoint(txid: lastCoinbaseTxid, vout: 0))
      check utxo.isSome
      check utxo.get().height == flushPoint

      cs.db.db.closeUnsafe()

  test "crash at block 3500 with flush_interval=2000 loses at most 2000 blocks":
    ## Process 5000 blocks with flush_interval=2000. Simulate a crash at
    ## block 3500 (midway between disk flushes at 2000 and 4000). On
    ## recovery, cfMeta must be within 2000 blocks of the crash height.
    const CrashHeight = 3500'i32
    const TotalBlocks = 5000'i32

    block:
      var cs = newChainState(TestDbPath, regtestParams())
      cs.ibdDiskFlushInterval = int(IbdBatchFlushInterval)  # 2000

      let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
      discard cs.connectBlock(genesis, 0)
      cs.startIBD()

      var prevHash = getBlockHash(genesis)
      for h in 1'i32 .. CrashHeight:
        let blk = makeSimpleBlock(prevHash, h)
        let res = cs.connectBlockIBD(blk, h)
        check res.isOk
        prevHash = getBlockHash(blk)

      check cs.bestHeight == CrashHeight

      # Simulate crash: abrupt close, no stopIBD, no graceful flush.
      cs.db.db.closeUnsafe()

    # Reopen and verify durability invariant
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      # The disk flush at block 2000 should have persisted. The batch write
      # at block 2000 also went to memtable but may or may not survive.
      # The key invariant: recovered height must be >= CrashHeight - flushInterval
      check cs.bestHeight >= CrashHeight - int32(IbdBatchFlushInterval)
      # And it cannot be higher than the crash point
      check cs.bestHeight <= CrashHeight

      # The block index at the recovered height must be present
      let hashAtBest = cs.db.getBlockHashByHeight(cs.bestHeight)
      check hashAtBest.isSome

      cs.db.db.closeUnsafe()
