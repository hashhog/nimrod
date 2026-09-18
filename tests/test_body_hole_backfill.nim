## Retained-range body-hole backfill — QUEUES.md nimrod item 0 (2026-09-18).
##
## Live mainnet after f6da7ed: getblockchaininfo is honest
## (pruneheight=967348, firstBody=952185, holes=1470, firstHole=952411)
## but the 1,470 connected-and-unreadable bodies are still missing.
## connectBlockIBD skipped cfBlocks; the node is long past those heights,
## so nothing self-heals. A peer getdata or a wallet rescan at exactly
## those heights fails — CHARTER-bar even though the gap is reported.
##
## This file is the control:
##   nim c -r tests/test_body_hole_backfill.nim
##
## Decision: on-demand enqueue when getblock/getdata hits a hole, plus a
## background repair planner that emits getdata for interior holes. Arrival
## of a behind-tip body (processBlock / getblockfrompeer) stores it. The
## unretained genesis prefix is NOT requested (no silent 600 G archive).
##
## Pins:
##   1. planBodyRepairs lists interior holes, not the unretained prefix.
##   2. enqueueBodyRepair queues a hole and refuses the prefix.
##   3. fillMissingBody stores a hole; a bad merkle is rejected.
##   4. processBlock of a behind-tip hole stores the body (was discarded).
##   5. getblock of a hole enqueues repair and still returns -5.
##   6. After fill, the hole is gone and pruneheight can walk down.
##   7. After repair completes, a scan from firstBody to tip is ZERO holes.
##   8. Negative control: punch a fresh hole; repair finds and fills it.
##   9. bodyRepairRemaining is the untruncated hole count, not the sample cap.

import unittest2
import std/[os, options, json, sets]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/network/[sync, messages]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/mining/fees

const TestDbPath = "/tmp/nimrod_body_hole_backfill"

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
    scriptSig: @[byte(height and 0xff), byte(0x01)],
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
  BlockHash(doubleSha256(serialize(blk.header)))

proc toHexLower(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc reverseHexLocal(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc displayHash(h: BlockHash): string =
  reverseHexLocal(toHexLower(array[32, byte](h)))

proc connectKeeping(cs: var ChainState, prev: BlockHash, startH, endH: int32,
                    bodies: var seq[Block]): BlockHash =
  result = prev
  for h in startH .. endH:
    let blk = makeSimpleBlock(result, h)
    check cs.connectBlock(blk, h).isOk
    bodies.add(blk)
    result = getBlockHash(blk)

proc rpcWithChainState(cs: ChainState): RpcServer =
  let params = regtestParams()
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)

proc rpcErr(rpc: RpcServer, methodName: string,
            params: JsonNode): tuple[code: int, msg: string] =
  try:
    discard rpc.handleMethod(methodName, params)
    (code: 0, msg: "(no error)")
  except RpcError as e:
    (code: e.code, msg: e.msg)

suite "retained-range body hole backfill":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "planBodyRepairs lists interior holes, not the unretained prefix":
    ## Live shape, scaled: prefix 1..5 missing, island 6..10, hole 11..13,
    ## suffix 14..20. Planner must emit 11,12,13 and not 1..5.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 20, bodies)
    for h in [1'i32, 2, 3, 4, 5, 11, 12, 13]:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())

    let planned = planBodyRepairs(cs.db, cs.bestHeight)
    var heights: seq[int32] = @[]
    for hash in planned:
      let idx = cs.db.getBlockIndex(hash)
      check idx.isSome
      heights.add(idx.get().height)
    check heights == @[11'i32, 12, 13]
    # Prefix must not be in the plan — that is the 600 G operator decision.
    for h in 1'i32 .. 5'i32:
      check cs.db.getBlockHashByHeight(h).get() notin planned
    cs.close()

  test "enqueueBodyRepair queues a hole and refuses the unretained prefix":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 10, bodies)
    # Interior hole first, while height 1 still has a body so
    # discoverFirstBody stays 0 (binary search is prefix-only).
    let holeHash = cs.db.getBlockHashByHeight(8).get()
    cs.db.deleteBlockBody(holeHash)
    check cs.enqueueBodyRepair(holeHash)
    check holeHash in cs.pendingBodyRepairs
    # Then a missing prefix: those heights are the floor, not repairs.
    for h in 1'i32 .. 5'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    let prefixHash = cs.db.getBlockHashByHeight(3).get()
    check not cs.enqueueBodyRepair(prefixHash)
    check prefixHash notin cs.pendingBodyRepairs
    # Already-have is not a repair.
    check not cs.enqueueBodyRepair(cs.db.getBlockHashByHeight(10).get())
    # Unknown hash is not a repair.
    check not cs.enqueueBodyRepair(BlockHash(default(array[32, byte])))
    cs.close()

  test "fillMissingBody stores a hole; bad merkle is rejected":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 8, bodies)
    let holeBlk = bodies[5] # height 5 (genesis is 0)
    let holeHash = getBlockHash(holeBlk)
    check holeBlk.header.nonce == 5'u32
    cs.db.deleteBlockBody(holeHash)
    check not cs.db.hasBlockBody(holeHash)

    let filled = cs.fillMissingBody(holeBlk)
    check filled.isOk
    check cs.db.hasBlockBody(holeHash)
    check cs.db.getBlock(holeHash).isSome
    # Idempotent.
    check cs.fillMissingBody(holeBlk).isOk

    # Punch again and feed a mutated body (same header, different tx).
    cs.db.deleteBlockBody(holeHash)
    var bad = holeBlk
    bad.txs[0].outputs[0].value = Satoshi(1)
    let rejected = cs.fillMissingBody(bad)
    check not rejected.isOk
    check not cs.db.hasBlockBody(holeHash)
    cs.close()

  test "fillMissingBody refuses the unretained prefix (no 600 G backfill)":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 10, bodies)
    for h in 1'i32 .. 5'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    let prefixBlk = bodies[2] # height 2
    let res = cs.fillMissingBody(prefixBlk)
    check not res.isOk
    check not cs.db.hasBlockBody(getBlockHash(prefixBlk))
    cs.close()

  test "processBlock of a behind-tip hole stores the body":
    ## Live getdata/getblockfrompeer arrival: the header is known, the
    ## height is on the active chain below the tip, the body is missing.
    ## Pre-fix, processBlock discarded anything behind chainTipHeight.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 12, bodies)
    let holeBlk = bodies[8]
    let holeHash = getBlockHash(holeBlk)
    cs.db.deleteBlockBody(holeHash)
    check not cs.db.hasBlockBody(holeHash)

    let params = regtestParams()
    let sm = newSyncManager(nil, cs.db, params, cs)
    check sm.chainTipHeight == 12
    let accepted = sm.processBlock(nil, holeBlk)
    check accepted
    check cs.db.hasBlockBody(holeHash)
    check holeHash notin cs.pendingBodyRepairs
    cs.close()

  test "processBlock of a mutated behind-tip body does not store":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 12, bodies)
    let holeBlk = bodies[8]
    let holeHash = getBlockHash(holeBlk)
    cs.db.deleteBlockBody(holeHash)
    var bad = holeBlk
    bad.txs[0].outputs[0].value = Satoshi(1)
    let sm = newSyncManager(nil, cs.db, params = regtestParams(),
        chainState = cs)
    check not sm.processBlock(nil, bad)
    check not cs.db.hasBlockBody(holeHash)
    cs.close()

  test "getblock of a hole enqueues repair and still returns -5":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 8, bodies)
    let holeHash = cs.db.getBlockHashByHeight(5).get()
    cs.db.deleteBlockBody(holeHash)
    let rpc = rpcWithChainState(cs)
    let err = rpcErr(rpc, "getblock", %*[displayHash(holeHash), 0])
    check err.code == -5
    check err.msg == "Block not found"
    check holeHash in cs.pendingBodyRepairs
    cs.close()

  test "getblock of a prefix-missing body does not enqueue genesis backfill":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 10, bodies)
    for h in 1'i32 .. 5'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    let prefixHash = cs.db.getBlockHashByHeight(3).get()
    let rpc = rpcWithChainState(cs)
    let err = rpcErr(rpc, "getblock", %*[displayHash(prefixHash), 0])
    check err.code == -5
    check prefixHash notin cs.pendingBodyRepairs
    cs.close()

  test "after fill, audit is clean and pruneheight walks down":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 12, bodies)
    let holeBlk = bodies[8]
    let holeHash = getBlockHash(holeBlk)
    cs.db.deleteBlockBody(holeHash)
    cs.historyFloorProbed = false
    check cs.discoverBodyFloor() == 9
    let before = auditRetainedBodies(cs.db, cs.bestHeight, pruneHeight = 0)
    check 8'i32 in before.holes
    check cs.fillMissingBody(holeBlk).isOk
    let after = auditRetainedBodies(cs.db, cs.bestHeight, pruneHeight = 0)
    check after.holeCount == 0
    cs.historyFloorProbed = false
    check cs.discoverBodyFloor() == 0
    cs.close()

  test "planRepairInventory emits getdata for queued holes only":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 12, bodies)
    for h in 1'i32 .. 4'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    let holeHash = cs.db.getBlockHashByHeight(8).get()
    cs.db.deleteBlockBody(holeHash)
    let n = cs.enqueueRetainedBodyRepairs()
    check n == 1
    check holeHash in cs.pendingBodyRepairs
    check cs.db.getBlockHashByHeight(2).get() notin cs.pendingBodyRepairs

    let sm = newSyncManager(nil, cs.db, regtestParams(), cs)
    let inv = sm.planRepairInventory()
    check inv.len == 1
    check inv[0].invType == invWitnessBlock
    check BlockHash(inv[0].hash) == holeHash
    # Second call while in-flight emits nothing.
    check sm.planRepairInventory().len == 0
    cs.close()

  test "negative control: a dense retained range plans zero repairs":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 6, bodies)
    check planBodyRepairs(cs.db, cs.bestHeight).len == 0
    check cs.enqueueRetainedBodyRepairs() == 0
    # Break it: the instrument must notice.
    cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(3).get())
    let broken = planBodyRepairs(cs.db, cs.bestHeight)
    check broken.len == 1
    check broken[0] == cs.db.getBlockHashByHeight(3).get()
    cs.close()

  test "after repair completes, firstBody-to-tip scan reports zero holes":
    ## CONTROL (QUEUES.md 2026-09-18 08:55Z (b)): after the repair
    ## drains, a scan from firstBody to tip must be empty. Logging
    ## "requesting count=16" is not completion.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 20, bodies)
    # Live shape: unretained prefix, an island, interior holes, suffix.
    # discoverFirstBody is a prefix binary search, so the holes must sit
    # above the first stored body (same as planBodyRepairs' own test).
    for h in [1'i32, 2, 3, 4, 5, 11, 12, 13]:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    cs.historyFloorProbed = false
    let firstBody = discoverFirstBody(cs.db, cs.bestHeight)
    check firstBody == 6
    let queued = cs.enqueueRetainedBodyRepairs()
    check queued == 3
    check cs.bodyRepairRemaining() == 3
    let rpc = rpcWithChainState(cs)
    let before = rpc.handleMethod("getblockchaininfo", %*[])
    check before["body_repair_remaining"].getInt() == 3
    check before["body_repair_filled"].getInt() == 0

    let sm = newSyncManager(nil, cs.db, regtestParams(), cs)
    for h in [11'i32, 12, 13]:
      check sm.processBlock(nil, bodies[h])
    check cs.bodyRepairRemaining() == 0
    check cs.bodyRepairFilled == 3
    let after = rpc.handleMethod("getblockchaininfo", %*[])
    check after["body_repair_remaining"].getInt() == 0
    check after["body_repair_filled"].getInt() == 3

    let scan = auditRetainedBodies(cs.db, cs.bestHeight,
        pruneHeight = firstBody, maxHoles = 10_000)
    check scan.floor == firstBody
    check scan.holeCount == 0
    check scan.holes.len == 0
    check not scan.truncated
    check countRetainedBodyHoles(cs.db, cs.bestHeight) == 0
    # Prefix below firstBody is still absent — not a repair.
    check not cs.db.hasBlockBody(cs.db.getBlockHashByHeight(3).get())
    cs.close()

  test "negative control: punch a fresh hole; repair finds and fills it":
    ## A backfill that silently stops at the first failure looks exactly
    ## like one that finished. Punching a hole into a just-repaired
    ## range must raise remaining, and filling it must clear the scan.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 12, bodies)
    for h in 1'i32 .. 4'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    cs.historyFloorProbed = false
    check cs.enqueueRetainedBodyRepairs() == 0
    check cs.bodyRepairRemaining() == 0
    check countRetainedBodyHoles(cs.db, cs.bestHeight) == 0

    let holeBlk = bodies[8]
    let holeHash = getBlockHash(holeBlk)
    cs.db.deleteBlockBody(holeHash)
    cs.historyFloorProbed = false
    check not cs.db.hasBlockBody(holeHash)
    # Queue was empty; a fresh hole is invisible until we plan again.
    check cs.bodyRepairRemaining() == 0
    check countRetainedBodyHoles(cs.db, cs.bestHeight) == 1
    let found = cs.enqueueRetainedBodyRepairs()
    check found == 1
    check holeHash in cs.pendingBodyRepairs
    check cs.bodyRepairRemaining() == 1
    let rpc = rpcWithChainState(cs)
    check rpc.handleMethod("getblockchaininfo", %*[])[
        "body_repair_remaining"].getInt() == 1

    let sm = newSyncManager(nil, cs.db, regtestParams(), cs)
    check sm.processBlock(nil, holeBlk)
    check cs.db.hasBlockBody(holeHash)
    check cs.bodyRepairRemaining() == 0
    check rpc.handleMethod("getblockchaininfo", %*[])[
        "body_repair_remaining"].getInt() == 0
    let firstBody = discoverFirstBody(cs.db, cs.bestHeight)
    let scan = auditRetainedBodies(cs.db, cs.bestHeight,
        pruneHeight = firstBody, maxHoles = 10_000)
    check scan.holeCount == 0
    check countRetainedBodyHoles(cs.db, cs.bestHeight) == 0
    cs.close()

  test "bodyRepairRemaining is the untruncated hole count, not the sample cap":
    ## Live audits log truncated=true because the sample list is capped
    ## at 64. Differencing that sample is comparing two ceilings.
    ## remaining / holeCount must be the real total.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    var bodies: seq[Block] = @[genesis]
    discard connectKeeping(cs, getBlockHash(genesis), 1, 90, bodies)
    for h in 11'i32 .. 90'i32:
      cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(h).get())
    cs.historyFloorProbed = false
    let audit = auditRetainedBodies(cs.db, cs.bestHeight)
    check audit.holeCount == 80
    check audit.truncated
    check audit.holes.len < 80
    let queued = cs.enqueueRetainedBodyRepairs()
    check queued == 80
    check cs.bodyRepairRemaining() == 80
    check cs.bodyRepairRemaining() == audit.holeCount
    check cs.bodyRepairRemaining() != audit.holes.len
    check countRetainedBodyHoles(cs.db, cs.bestHeight) == 80
    let rpc = rpcWithChainState(cs)
    let info = rpc.handleMethod("getblockchaininfo", %*[])
    check info["body_repair_remaining"].getInt() == 80
    cs.close()
