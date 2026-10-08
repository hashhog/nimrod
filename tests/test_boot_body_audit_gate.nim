## Boot must not hold RPC on the retained-range body scan.
##
## Live mainnet 2026-10-02: `block-serving services` at 02:00:06Z, then
## `retained-range bodies contiguous` after a walk of ~17.3k bodies
## (952185..tip), RPC up ~02:21Z. The 2026-09-27 boot spent 9.6 min in
## the same step. `stop_mainnet.sh` verifies `getblockcount` within
## 300s and reported failure while the node was healthy and still
## scanning. Bug class 1 (boot gating).
##
## Control:
##   nim c -r tests/test_boot_body_audit_gate.nim
##
## The scan (`auditRetainedBodies`) has to run after `startRpcThread`
## and the P2P listener, on the background audit thread — not inline
## in `startNode` before either exists.

import unittest2
import std/[os, strutils, sets, options, atomics]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

proc startNodeBody(src: string): string =
  const marker = "proc startNode*"
  let i = src.find(marker)
  doAssert i >= 0, "proc startNode* not found"
  let rest = src[i .. ^1]
  let nl = rest.find("\nproc ")
  if nl < 0: rest else: rest[0 ..< nl]

proc stripLineComments(s: string): string =
  ## Drop `#` comments so a comment that names the audit cannot
  ## satisfy the order check. Boot source has no `#` inside strings
  ## on the lines this test cares about.
  result = ""
  for line in s.splitLines:
    let hash = line.find('#')
    if hash >= 0:
      result.add(line[0 ..< hash])
    else:
      result.add(line)
    result.add('\n')

proc nimrodSrc(): string =
  let path = currentSourcePath().parentDir().parentDir() / "src" / "nimrod.nim"
  readFile(path)

suite "boot body-audit gate":
  test "retained-range scan starts after RPC and P2P, off the boot path":
    let code = stripLineComments(startNodeBody(nimrodSrc()))
    let deferAt = code.find("deferStartupBodyAudit(")
    let rpcAt = code.find("startRpcThread(")
    let p2pAt = code.find("startListeners(")
    let threadAt = code.find("retainedBodyAuditThreadMain")
    let auditAt = code.find("auditRetainedBodies(")
    check rpcAt >= 0
    check p2pAt >= 0
    # Flag goes up before the RPC thread exists, so getblockchaininfo
    # cannot start the linear walk on the RPC thread.
    check deferAt >= 0
    check deferAt < rpcAt
    # The walk itself is a thread proc invoked after the listener.
    check threadAt > rpcAt
    check threadAt > p2pAt
    # Not inline in startNode. A direct call here is the 10–20 min gate.
    check auditAt < 0

  test "sync loop drains staged repairs onto the main-thread queue":
    let path = currentSourcePath().parentDir().parentDir() / "src" / "network" / "sync.nim"
    let src = readFile(path)
    let i = src.find("proc syncLoop*")
    check i >= 0
    let rest = src[i .. ^1]
    let nl = rest.find("\nproc ")
    let body = if nl < 0: rest else: rest[0 ..< nl]
    check "drainStagedBodyRepairs(" in body

const TestDbPath = "/tmp/nimrod_boot_body_audit_gate"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(height: int32): Transaction =
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
      value: Satoshi(50_0000_0000),
      scriptPubKey: @[byte(0x51)]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeTestTransaction(height)
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

proc blockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc connectChain(cs: var ChainState, tip: int32): BlockHash =
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  check cs.connectBlock(genesis, 0).isOk
  result = blockHash(genesis)
  for h in 1'i32 .. tip:
    let blk = makeSimpleBlock(result, h)
    check cs.connectBlock(blk, h).isOk
    result = blockHash(blk)

suite "startup body audit does not walk on the caller":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "deferred floor is provisional and a hole is staged, not queued, until drain":
    ## Interior hole at height 8 of 0..12. The contiguous suffix is 9.
    ## discoverFirstBody is 0 (height 1 has a body). While the audit owns
    ## the walk, the RPC path must return 0 and must not cache it — caching
    ## the suffix here is the linear walk that held boot.
    var cs = newChainState(TestDbPath, regtestParams())
    discard connectChain(cs, 12)
    let holeHash = cs.db.getBlockHashByHeight(8).get()
    cs.db.deleteBlockBody(holeHash)
    let suffix = discoverBodyFloor(cs.db, cs.bestHeight)
    check suffix == 9
    check discoverFirstBody(cs.db, cs.bestHeight) == 0

    cs.deferStartupBodyAudit()
    let provisional = cs.discoverBodyFloor()
    check provisional == 0
    check provisional != suffix
    check not cs.historyFloorProbed

    cs.startupRetainedBodyAudit()
    check cs.historyFloorProbed
    check cs.discoverBodyFloor() == suffix
    # The audit thread must not write pendingBodyRepairs itself.
    check cs.bodyRepairRemaining() == 0
    check holeHash notin cs.pendingBodyRepairs
    check cs.drainStagedBodyRepairs() == 1
    check holeHash in cs.pendingBodyRepairs
    check cs.bodyRepairRemaining() == 1
    check cs.drainStagedBodyRepairs() == 0
    cs.close()

  test "contiguous range stages nothing and publishes floor 0":
    var cs = newChainState(TestDbPath, regtestParams())
    discard connectChain(cs, 6)
    cs.deferStartupBodyAudit()
    check cs.discoverBodyFloor() == 0
    check not cs.historyFloorProbed
    cs.startupRetainedBodyAudit()
    check cs.historyFloorProbed
    check cs.discoverBodyFloor() == 0
    check cs.drainStagedBodyRepairs() == 0
    check cs.bodyRepairRemaining() == 0
    cs.close()

suite "SIGTERM during the startup body audit":
  ## The audit thread reads cfBlocks for 10-20 min after a mainnet boot.
  ## The SIGTERM handler closes RocksDB; closing it under a thread that is
  ## still iterating is a use-after-close. The handler must stop the audit
  ## (or leave the DB open) first.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "a cancelled audit publishes nothing, stages nothing, and reports stopped":
    var cs = newChainState(TestDbPath, regtestParams())
    discard connectChain(cs, 12)
    cs.db.deleteBlockBody(cs.db.getBlockHashByHeight(8).get())
    cs.deferStartupBodyAudit()
    cs.markStartupBodyAuditRunning()
    check cs.bodyAuditRunning.load(moAcquire) == 1
    cs.bodyAuditCancel.store(true, moRelease)
    cs.startupRetainedBodyAudit()
    check cs.bodyAuditRunning.load(moAcquire) == 0
    check not cs.historyFloorProbed
    check cs.drainStagedBodyRepairs() == 0
    check cs.stopStartupBodyAudit(100)
    cs.close()

  test "stop waits for a running audit and gives up after its timeout":
    var cs = newChainState(TestDbPath, regtestParams())
    cs.markStartupBodyAuditRunning()
    check not cs.stopStartupBodyAudit(50)
    check cs.bodyAuditCancel.load(moAcquire)
    cs.bodyAuditRunning.store(0, moRelease)
    check cs.stopStartupBodyAudit(50)
    cs.close()

  test "the SIGTERM handler stops the audit before closing the database":
    # NI-4: the shutdown body moved out of the signal handler into
    # performShutdown (run on the main loop); the ordering pinned here is
    # unchanged.
    let src = stripLineComments(nimrodSrc())
    let i = src.find("proc performShutdown(")
    check i >= 0
    let body = src[i .. ^1]
    let stopAt = body.find("stopStartupBodyAudit(")
    let closeAt = body.find("cs.close()")
    check stopAt >= 0
    check closeAt > stopAt
    let markAt = src.find("markStartupBodyAuditRunning()")
    let threadAt = src.find("createThread(state.retainedBodyAuditThread")
    check markAt >= 0
    check markAt < threadAt
