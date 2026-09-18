## Honest pruned:true + pruneheight when historical bodies are missing.
##
## Live mainnet (2026-09-17T22:50Z): getblock on Core's real hash MISSES at
## 1 / 500000 / 900000 / 940000 and HAVEs from 960000, while
## getblockchaininfo reported pruned:false with no pruneheight. getblockhash
## answered height 1 because the height→hash index is dense — that is not
## the same as holding the body (receipt
## receipts/CORRECTION-historical-bodies-fleet-wide-2026-09-17.md).
##
## Core (rpc/blockchain.cpp): pruned is true whenever the node does not hold
## the full chain; pruneheight is the first height with complete data.
## getblockhash -8 is only for height < 0 or height > tip. An in-range
## height whose body we do not retain is -1 "Block not available (pruned
## data)" (same string Core's getblock uses for pruned bodies).
##
## rustoshi df9b23c4 / clearbit b554e02 already did this for a missing
## height-index prefix. nimrod's prefix is missing BODIES with the index
## still present — same honesty contract, different detector.
##
## This does not backfill genesis→floor. CONTROL:
##   nim c -r tests/test_pruned_history.nim

import unittest2
import std/[os, json, options]
import ../src/rpc/server
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/mempool/mempool
import ../src/mining/fees

var testDbSeq = 0

proc freshDbPath(): string =
  inc testDbSeq
  result = "/tmp/nimrod_pruned_history_" & $getCurrentProcessId() & "_" & $testDbSeq
  if dirExists(result):
    removeDir(result)

proc cleanupDb(path: string) =
  if dirExists(path):
    try:
      removeDir(path)
    except CatchableError, OSError:
      discard

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
  BlockHash(doubleSha256(serialize(blk.header)))

proc connectN(cs: var ChainState, prev: BlockHash, startH,
    endH: int32): BlockHash =
  result = prev
  for h in startH .. endH:
    let blk = makeSimpleBlock(result, h)
    check cs.connectBlock(blk, h).isOk
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

proc seedPrefixGap(cs: var ChainState, floor, tip: int32): BlockHash =
  ## Genesis body + contiguous bodies at floor..tip. Heights 1..floor-1 keep
  ## their height→hash index but have no body — the live mainnet shape
  ## (getblockhash(1) used to succeed, getblock(1) missed).
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  check cs.connectBlock(genesis, 0).isOk
  var prev = getBlockHash(genesis)
  prev = connectN(cs, prev, 1, tip)
  for h in 1'i32 .. (floor - 1):
    let hashOpt = cs.db.getBlockHashByHeight(h)
    check hashOpt.isSome
    cs.db.deleteBlockBody(hashOpt.get())
    check not cs.db.hasBlockBody(hashOpt.get())
  check cs.db.hasBlockBody(cs.db.getBlockHashByHeight(floor).get())
  check cs.db.hasBlockBody(cs.db.getBlockHashByHeight(tip).get())
  check cs.bestHeight == tip
  prev

suite "pruned history honesty":
  test "complete chain reports pruned false":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    discard connectN(cs, getBlockHash(genesis), 1, 5)
    let rpc = rpcWithChainState(cs)
    let info = rpc.handleMethod("getblockchaininfo", %*[])
    check info["pruned"].getBool() == false
    check not info.hasKey("pruneheight")
    check not info.hasKey("prune_target_size")

  test "prefix gap reports pruned true and pruneheight":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    # Bodies below the floor are absent; the height index is not.
    check cs.db.getBlockHashByHeight(5).isSome
    check not cs.db.hasBlockBody(cs.db.getBlockHashByHeight(5).get())
    let rpc = rpcWithChainState(cs)
    let info = rpc.handleMethod("getblockchaininfo", %*[])
    check info["pruned"].getBool() == true
    check info.hasKey("pruneheight")
    if info.hasKey("pruneheight"):
      check info["pruneheight"].getInt() == 10
    check not info.hasKey("prune_target_size")

  test "getblockhash below floor is -1 not -8":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcErr("getblockhash", %*[5])
    check r.code == -1
    check r.msg == "Block not available (pruned data)"
    check r.msg != "Block height out of range"

  test "getblockhash 1 below floor is -1 not -8":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcErr("getblockhash", %*[1])
    check r.code == -1
    check r.msg == "Block not available (pruned data)"

  test "getblockhash above tip is still -8":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcErr("getblockhash", %*[21])
    check r.code == -8
    check r.msg == "Block height out of range"

  test "getblockhash negative is still -8":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let r = rpc.rpcErr("getblockhash", %*[-1])
    check r.code == -8
    check r.msg == "Block height out of range"

  test "getblockhash 0 still returns genesis":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let h = rpc.handleMethod("getblockhash", %*[0])
    check h.kind == JString
    check h.getStr().len == 64

  test "getblockhash at floor returns the hash":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    let rpc = rpcWithChainState(cs)
    let h = rpc.handleMethod("getblockhash", %*[10])
    check h.kind == JString
    check h.getStr().len == 64
    let tip = rpc.handleMethod("getblockhash", %*[20])
    check tip.kind == JString
    check tip.getStr().len == 64

  test "discoverBodyFloor is 0 on a complete chain":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    check cs.connectBlock(genesis, 0).isOk
    discard connectN(cs, getBlockHash(genesis), 1, 8)
    check discoverBodyFloor(cs.db, cs.bestHeight) == 0
    check cs.discoverBodyFloor() == 0
    check not cs.holdsIncompleteHistory()

  test "discoverBodyFloor finds the first retained body":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    discard seedPrefixGap(cs, floor = 10, tip = 20)
    check discoverBodyFloor(cs.db, cs.bestHeight) == 10
    check cs.discoverBodyFloor() == 10
    check cs.holdsIncompleteHistory()
    check not heightHasBody(cs.db, 1)
    check not heightHasBody(cs.db, 9)
    check heightHasBody(cs.db, 10)
    check heightHasBody(cs.db, 20)
