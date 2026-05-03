## Regression test for the BIP-113 / Core ContextualCheckBlockHeader
## MTP enforcement (validation.cpp:4092):
##
##   if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
##       return state.Invalid(... "time-too-old" ...);
##
## Pre-fix nimrod's validateBlockHeader had:
##
##   if header.timestamp <= prevIndex.header.timestamp:
##     # This is a simplified check - full implementation would use MTP
##     discard  # Allow for now, full MTP check done in validateBlock
##
## ...and validateBlock did NOT add the missing MTP check. The fix puts
## the MTP check in validateBlock where the chain DB is in scope.

import unittest2
import std/[os, options]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/storage/chainstate

const TestDbPath = "/tmp/nimrod_mtp_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeCoinbaseTx(height: int32): Transaction =
  let heightBytes = @[
    byte(height and 0xff), byte((height shr 8) and 0xff),
    byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)
  ]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x51)]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlockWithTimestamp(prevHash: BlockHash, height: int32, timestamp: uint32): Block =
  let coinbase = makeCoinbaseTx(height)
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
      timestamp: timestamp,
      bits: 0x207fffff'u32,  # regtest difficulty
      nonce: uint32(height),
    ),
    txs: @[coinbase],
  )

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

suite "BIP-113 / MTP enforcement on block-header timestamp":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "block timestamp <= MTP is rejected by validateBlock":
    var cs = newChainState(TestDbPath, regtestParams())

    # Build a chain of 11 blocks with strictly increasing timestamps
    # 1000, 1100, 1200, ..., 2000. MTP of these 11 = sorted-median = 1500.
    var prevHash: BlockHash = BlockHash(default(array[32, byte]))
    var lastBlk: Block
    for h in 0'i32..10'i32:
      let ts = uint32(1000 + 100 * int(h))
      let blk = makeBlockWithTimestamp(prevHash, h, ts)
      let connRes = cs.connectBlock(blk, h)
      check connRes.isOk
      prevHash = getBlockHash(blk)
      lastBlk = blk

    # Resolve prevIndex for height=10
    let prevIdxOpt = cs.db.getBlockIndex(prevHash)
    check prevIdxOpt.isSome
    let prevIdx = prevIdxOpt.get()

    # Block at height=11 with timestamp = 1500 (== MTP). Must be REJECTED.
    let badBlk = makeBlockWithTimestamp(prevHash, 11, 1500'u32)
    let badRes = validateBlock(
      badBlk, prevIdx, cs.db, regtestParams(),
      checkScripts = false, checkPow = false)
    check (not badRes.isOk)
    check badRes.error == veBadTimestamp

    # Same prev, timestamp = 1499 (strictly less). Must be REJECTED.
    let badBlk2 = makeBlockWithTimestamp(prevHash, 11, 1499'u32)
    let badRes2 = validateBlock(
      badBlk2, prevIdx, cs.db, regtestParams(),
      checkScripts = false, checkPow = false)
    check (not badRes2.isOk)
    check badRes2.error == veBadTimestamp

    # Same prev, timestamp = 1501 (strictly greater than MTP). Must NOT be
    # rejected for timestamp reason. (The block may still fail other
    # checks like merkle/coinbase semantics, but it must NOT trip
    # veBadTimestamp.)
    let goodBlk = makeBlockWithTimestamp(prevHash, 11, 1501'u32)
    let goodRes = validateBlock(
      goodBlk, prevIdx, cs.db, regtestParams(),
      checkScripts = false, checkPow = false)
    if not goodRes.isOk:
      # Whatever error happens, it must NOT be the MTP gate.
      check goodRes.error != veBadTimestamp

    cs.close()
