## Retained-range body holes — QUEUES.md nimrod item 0 (2026-09-17).
##
## Live mainnet (22:52Z): getblock HAVE at 955000/960000/965000/966000 and
## at 967400, but -5 "Block not found" at 967000, with the node at tip 967473.
## That is not a retention floor. The block is on the active chain (tip is
## past it) and its body is unreadable.
##
## Cause: `connectBlockIBD` skips cfBlocks writes. P2P re-enters IBD whenever
## `headerTip - height > 10` (network/sync.nim), so a restart or header-sync
## stall that left the node 11+ blocks behind connected the catch-up window
## without storing bodies. `connectBlock` (the last 10, and every block once
## at tip) does store, which is why 966000 and 967400 can be present around
## a missing 967000.
##
## This file is the control:
##   nim c -r tests/test_retained_body_holes.nim
##
## It pins three things:
##   1. Genesis IBD still skips bodies (no silent 600 G backfill).
##   2. Catch-up IBD that extends an already-retained tip stores every body
##      so a stall cannot punch a hole.
##   3. `auditRetainedBodies` reports an interior miss between floor and tip
##      and does not treat a long unretained prefix as holes.

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_retained_body_holes"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(value: int64, height: int32): Transaction =
  Transaction(
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
      value: Satoshi(value),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] &
        @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeTestTransaction(50_0000_0000, height)
  var txHashes: seq[array[32, byte]]
  txHashes.add(array[32, byte](coinbase.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505'u32 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: @[coinbase]
  )

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

proc connectN(cs: var ChainState, prev: BlockHash, startH, endH: int32,
              ibd: bool): BlockHash =
  result = prev
  for h in startH .. endH:
    let blk = makeSimpleBlock(result, h)
    let res =
      if ibd: cs.connectBlockIBD(blk, h)
      else: cs.connectBlock(blk, h)
    check res.isOk
    result = getBlockHash(blk)

suite "retained-range body holes":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "genesis IBD does not store bodies (no silent archive backfill)":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    let genesisHash = getBlockHash(genesis)
    check cs.db.hasBlockBody(genesisHash)

    cs.startIBD()
    discard connectN(cs, genesisHash, 1, 8, ibd = true)
    cs.stopIBD()

    check cs.bestHeight == 8
    check cs.db.getBlockHashByHeight(8).isSome
    # Index is on the active chain...
    for h in 1'i32 .. 8'i32:
      let hashOpt = cs.db.getBlockHashByHeight(h)
      check hashOpt.isSome
      # ...but the IBD fast path must not have written the body. Writing
      # every IBD body is a ~600 G operator decision, not this fix.
      check not cs.db.hasBlockBody(hashOpt.get())
    cs.close()

  test "catch-up IBD extending a retained tip stores every body":
    ## The 967000 hole: node was at tip with bodies, fell 11+ behind,
    ## re-entered IBD, connected without writing cfBlocks.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var prev = getBlockHash(genesis)
    # Build a retained window with the post-IBD path (connectBlock).
    prev = connectN(cs, prev, 1, 5, ibd = false)
    for h in 1'i32 .. 5'i32:
      check cs.db.hasBlockBody(cs.db.getBlockHashByHeight(h).get())

    # Catch-up: more than 10 headers "ahead" is what trips startIBD on P2P.
    cs.startIBD()
    prev = connectN(cs, prev, 6, 18, ibd = true)
    cs.stopIBD()

    check cs.bestHeight == 18
    # Every height in the retained window, including the IBD catch-up
    # stretch, must be readable. This is the control that was red before
    # the connectBlockIBD retain path landed.
    for h in 1'i32 .. 18'i32:
      let hashOpt = cs.db.getBlockHashByHeight(h)
      check hashOpt.isSome
      check cs.db.hasBlockBody(hashOpt.get())
      check cs.db.getBlock(hashOpt.get()).isSome
    cs.close()

  test "audit finds an interior hole and ignores the unretained prefix":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var prev = getBlockHash(genesis)
    prev = connectN(cs, prev, 1, 12, ibd = false)

    # Punch a hole at height 8 (the 967000 shape: neighbours present).
    let holeHash = cs.db.getBlockHashByHeight(8).get()
    check cs.db.hasBlockBody(holeHash)
    cs.db.deleteBlockBody(holeHash)
    check not cs.db.hasBlockBody(holeHash)
    # Height index still resolves — getblockhash would succeed, getblock fails.
    check cs.db.getBlockHashByHeight(8).isSome
    check cs.db.getBlock(holeHash).isNone

    let audit = auditRetainedBodies(cs.db, cs.bestHeight, pruneHeight = -1,
                                    maxHoles = 16, unretainedGap = 1024)
    check audit.floor == 0
    check audit.tip == 12
    check audit.checked == 13
    check audit.holeCount == 1
    check audit.holes == @[8'i32]
    check not audit.truncated
    cs.close()

  test "audit with pruneHeight only scans the retained range":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var prev = getBlockHash(genesis)
    prev = connectN(cs, prev, 1, 10, ibd = false)
    # Delete height 2 (below prune floor) and height 7 (inside retained range).
    cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(2).get())
    cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(7).get())

    let audit = auditRetainedBodies(cs.db, cs.bestHeight, pruneHeight = 5,
                                    maxHoles = 16)
    check audit.floor == 5
    check audit.tip == 10
    check audit.checked == 6
    check audit.holes == @[7'i32]
    check audit.holeCount == 1
    cs.close()

  test "unretained prefix is a floor, not a bag of holes":
    ## Genesis body present, heights 1..5 missing, 6..10 present, 8 missing
    ## would be a hole — here we only have the prefix gap: 0 present,
    ## 1..5 missing, 6..10 present. With a small gap threshold the prefix
    ## is the floor and must not be reported as holes.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var prev = getBlockHash(genesis)
    prev = connectN(cs, prev, 1, 10, ibd = false)
    for h in 1'i32 .. 5'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())

    let audit = auditRetainedBodies(cs.db, cs.bestHeight, pruneHeight = -1,
                                    maxHoles = 16, unretainedGap = 3)
    check audit.floor == 6
    check audit.tip == 10
    check audit.checked == 5
    check audit.holeCount == 0
    check audit.holes.len == 0
    cs.close()

  test "negative control: a dense retained range audits clean":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    discard connectN(cs, getBlockHash(genesis), 1, 6, ibd = false)
    let audit = auditRetainedBodies(cs.db, cs.bestHeight)
    check audit.floor == 0
    check audit.holeCount == 0
    check audit.holes.len == 0
    check audit.checked == 7
    # Break the thing on purpose: the instrument must notice.
    cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(3).get())
    let broken = auditRetainedBodies(cs.db, cs.bestHeight)
    check broken.holeCount == 1
    check 3'i32 in broken.holes
    cs.close()
