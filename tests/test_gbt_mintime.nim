## getblocktemplate `mintime` / `curtime` vs Bitcoin Core v31.1.
##
## Core src/rpc/mining.cpp:997:
##   result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
## Core src/node/miner.cpp:36-47 (GetMinimumTime):
##   min_time = pindexPrev->GetMedianTimePast() + 1;
##   if ((pindexPrev->nHeight + 1) % difficulty_adjustment_interval == 0)
##     min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
## Core src/node/miner.cpp:49-53 (UpdateTime, called from CreateNewBlock and
## getblocktemplate): nTime = max(GetMinimumTime(...), now), and
## src/rpc/mining.cpp:1013 reports that as `curtime`.
##
## The template time fields are checked through handleMethod("getblocktemplate")
## on a real regtest ChainState.

import unittest2
import std/[os, json, times]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_gbt_mintime_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeCoinbaseTx(height: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04), byte(height and 0xff), byte((height shr 8) and 0xff),
                   byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc makeBlock(prevHash: BlockHash, height: int32, timestamp: uint32): Block =
  let coinbase = makeCoinbaseTx(height)
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
      timestamp: timestamp,
      bits: 0x207fffff'u32,
      nonce: uint32(height)),
    txs: @[coinbase])

proc buildChain(cs: var ChainState, times: seq[uint32]) =
  ## Connect blocks 0..times.len-1 with the given timestamps.
  var prevHash = BlockHash(default(array[32, byte]))
  for h, ts in times:
    let blk = makeBlock(prevHash, int32(h), ts)
    check cs.connectBlock(blk, int32(h)).isOk
    prevHash = BlockHash(doubleSha256(serialize(blk.header)))

proc gbt(cs: ChainState, params: ConsensusParams): JsonNode =
  let mp = newMempool(cs, params, fullRbf = false)
  let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                         peerManager = nil, feeEstimator = newFeeEstimator(),
                         params = params)
  rpc.handleMethod("getblocktemplate", %*[{"rules": ["segwit"]}])

suite "getblocktemplate mintime / curtime (Core GetMinimumTime)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "mintime is MTP(tip)+1, independent of the wall clock":
    # 12 blocks at 1700000000 + h (h = 0..11); tip MTP = median(1..11) = 1700000006.
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    var times: seq[uint32]
    for h in 0 .. 11: times.add(1700000000'u32 + uint32(h))
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["height"].getInt() == 12
    check t["mintime"].getBiggestInt() == 1700000007
    # curtime stays the (adjusted) clock: far above MTP+1 here.
    check t["curtime"].getBiggestInt() >= getTime().toUnix() - 5

  test "curtime is raised to mintime when the tip MTP is ahead of the clock":
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let base = uint32(getTime().toUnix() + 3600)
    var times: seq[uint32]
    for h in 0 .. 11: times.add(base + uint32(h))
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["mintime"].getBiggestInt() == int64(base) + 7
    check t["curtime"].getBiggestInt() == t["mintime"].getBiggestInt()

  test "BIP94: mintime is at least prev time - 600 on a retarget height":
    # Shrink the retarget interval so the template height (16) is a multiple of it.
    var params = regtestParams()
    params.difficultyAdjustmentInterval = 16
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    var times: seq[uint32]
    for h in 0 .. 14: times.add(1700000000'u32 + uint32(h))
    times.add(1700010000'u32)                 # tip (height 15) jumps ahead
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["height"].getInt() == 16
    # MTP(5..15) = 1700000010, so MTP+1 = 1700000011; prev time - MAX_TIMEWARP = 1700009400 wins.
    check t["mintime"].getBiggestInt() == 1700009400
    # Not a retarget height: plain MTP+1 even with a big jump at the tip.
    var params2 = regtestParams()
    params2.difficultyAdjustmentInterval = 2016
    check gbt(cs, params2)["mintime"].getBiggestInt() == 1700000011
