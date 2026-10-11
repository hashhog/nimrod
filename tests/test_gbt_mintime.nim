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

  # Core regtest: nPowTargetTimespan = 24*60*60, nPowTargetSpacing = 10*60
  # (kernel/chainparams.cpp:576-577), so DifficultyAdjustmentInterval() =
  # 86400 / 600 = 144 (consensus/params.h) and height 144 is a retarget height
  # for GetMinimumTime's BIP94 clamp (miner.cpp:36-47). Plain regtestParams().
  test "regtest params: retarget interval is 144 (86400 / 600), as in Core":
    let params = regtestParams()
    check params.powTargetTimespan == 86_400
    check params.powTargetSpacing == 600
    check params.difficultyAdjustmentInterval == 144

  test "regtest height 144: mintime is the tip time - 600 (BIP94 clamp)":
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    var times: seq[uint32]
    for h in 0 .. 142: times.add(1700000000'u32 + uint32(h))
    times.add(1700100000'u32)                 # tip 143 jumps ahead
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["height"].getInt() == 144
    # Core v31.1 on this chain: mintime 1700099400 (MTP+1 would be 1700000139).
    check t["mintime"].getBiggestInt() == 1700099400

  test "regtest height 144, tip 7000 s ahead of the clock: curtime is raised to tip - 600":
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let tip = uint32(getTime().toUnix() + 7000)
    var times: seq[uint32]
    for h in 0 .. 142: times.add(1700000000'u32 + uint32(h))
    times.add(tip)
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["height"].getInt() == 144
    check t["mintime"].getBiggestInt() == int64(tip) - 600
    check t["curtime"].getBiggestInt() == int64(tip) - 600

  test "regtest height 145 is not a retarget height: plain MTP + 1":
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    var times: seq[uint32]
    for h in 0 .. 143: times.add(1700000000'u32 + uint32(h))
    times.add(1700100000'u32)                 # tip 144 jumps ahead
    buildChain(cs, times)
    let t = gbt(cs, params)
    check t["height"].getInt() == 145
    # MTP(134..144) = 1700000139
    check t["mintime"].getBiggestInt() == 1700000140
