## NI-8: a long UTXO-set RPC must not hold the chain lock for the walk.
##
## dumptxoutset and sync/batch gettxoutsetinfo used to run the whole scan
## inside handleMethod's withChainLock (Core holds cs_main only to flush and
## open the cursor, then walks the snapshot unlocked). While that lock is
## held the main thread cannot connect a block, and shutdown cannot take the
## lock it acquires at the start of performShutdown.
##
## The walk is parked at race point "utxo.walk" (one coin). A correct node
## lets connectBlock finish while the walk is still parked, and the RPC
## answer is the snapshot from before that block.

import unittest2
import std/[options, os, json, strutils, atomics, times, monotimes]
import ../src/consensus/[params, validation]
import ../src/network/sync
import ../src/storage/[chainstate, snapshot]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

when not defined(nimrodRaceHooks):
  {.error: "compile with -d:nimrodRaceHooks".}

const ParkTimeoutMs = 2000
const ConnectBudgetMs = 400

proc hashOf(h: BlockHeader): BlockHash = BlockHash(doubleSha256(serialize(h)))

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc displayHex(a: array[32, byte]): string =
  var r: array[32, byte]
  for i in 0 ..< 32: r[i] = a[31 - i]
  hexOf(r)

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32): Block =
  let cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height),
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(50_0000_0000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
                        merkleRoot: merkleRoot(@[array[32, byte](cb.txid())]),
                        timestamp: ts, bits: 0x207fffff'u32, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb])

type
  ChainFix = object
    path: string
    params: ConsensusParams
    cs: ChainState
    rpc: RpcServer
    tip: BlockHeader
    height: int32

proc buildChain(path: string, n: int32): ChainFix =
  removeDir(path)
  var p = regtestParams()
  var cs = newChainState(path, p)
  doAssert cs.connectBlock(buildGenesisBlock(p), 0'i32).isOk
  var prev = p.genesisBlockHash
  var ts = 1_700_000_000'u32
  var last: BlockHeader
  for h in 1'i32 .. n:
    let b = mineBlock(prev, h, ts)
    doAssert cs.connectBlock(b, h).isOk, "connect " & $h
    prev = hashOf(b.header)
    last = b.header
    ts += 600
  let mp = newMempool(cs, p)
  let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                         peerManager = nil, feeEstimator = newFeeEstimator(),
                         params = p)
  ChainFix(path: path, params: p, cs: cs, rpc: rpc, tip: last, height: n)

var gParked: Atomic[bool]
var gRelease: Atomic[bool]
var gParkTimedOut: Atomic[bool]
var gParkedOnce: Atomic[bool]

proc waitFlag(f: var Atomic[bool], ms: int): bool =
  let deadline = epochTime() + ms.float / 1000.0
  while not f.load(moAcquire):
    if epochTime() > deadline: return false
    sleep(1)
  true

proc parkHook(point: string, hash: BlockHash) {.nimcall, gcsafe, raises: [].} =
  {.cast(gcsafe).}:
    if point != "utxo.walk": return
    # One coin only. Later coins must not each burn another ParkTimeoutMs
    # while the chain lock is still held.
    if gParkedOnce.exchange(true, moAcquireRelease):
      return
    gParked.store(true, moRelease)
    if not waitFlag(gRelease, ParkTimeoutMs):
      gParkTimedOut.store(true, moRelease)

proc resetPark() =
  gParked.store(false, moRelease)
  gRelease.store(false, moRelease)
  gParkTimedOut.store(false, moRelease)
  gParkedOnce.store(false, moRelease)
  raceHook = parkHook

type RpcJob = object
  rpc: RpcServer
  call: string
  params: string
  result: string
  err: string

var gWorker: Thread[void]
var gJob: Atomic[pointer]
var gJobDone: Atomic[bool]
var gWorkerQuit: Atomic[bool]

proc runJob(job: ptr RpcJob) =
  {.cast(gcsafe).}:
    try:
      job.result = $job.rpc.handleMethod(job.call, parseJson(job.params))
    except CatchableError as e:
      job.err = e.msg
    except Exception as e:
      job.err = "defect " & e.msg

proc workerLoop() {.thread.} =
  while not gWorkerQuit.load(moAcquire):
    let j = gJob.load(moAcquire)
    if j != nil:
      runJob(cast[ptr RpcJob](j))
      gJob.store(nil, moRelease)
      gJobDone.store(true, moRelease)
    else:
      sleep(1)

proc startJob(job: var RpcJob) =
  gJobDone.store(false, moRelease)
  gJob.store(addr job, moRelease)

proc finishJob() =
  doAssert waitFlag(gJobDone, 30_000), "RPC worker never finished"

createThread(gWorker, workerLoop)

proc connectWhileParked(cs: var ChainState, blk: Block, height: int32): tuple[ms: int64, ok: bool] =
  ## connectBlock while the walker is parked. Returns how long the connect
  ## waited and whether the walker had already left the RPC.
  doAssert waitFlag(gParked, 10_000), "walk never reached utxo.walk"
  let t0 = getMonoTime()
  let cr = cs.connectBlock(blk, height)
  let ms = inMilliseconds(getMonoTime() - t0)
  (ms, cr.isOk and not gJobDone.load(moAcquire) and not gParkTimedOut.load(moAcquire))

suite "NI-8 long UTXO RPC walks release the chain lock":

  test "dumptxoutset: block connects during the walk; dump is the pre-connect snapshot":
    var f = buildChain("/tmp/nimrod_ni8_dump", 5)
    defer:
      gRelease.store(true, moRelease)
      if not gJobDone.load(moAcquire): discard waitFlag(gJobDone, 10_000)
      raceHook = nil
      f.cs.close()
      removeDir(f.path)
    let preHeight = f.height
    let preHash = hashOf(f.tip)
    let expectPath = f.path & "/expect.dat"
    let expect = createSnapshot(f.cs, expectPath, f.params)
    let next = mineBlock(preHash, preHeight + 1, f.tip.timestamp + 600)
    resetPark()
    var job = RpcJob(rpc: f.rpc, call: "dumptxoutset",
                     params: $(%*[f.path & "/live.dat"]))
    startJob(job)
    let (ms, during) = connectWhileParked(f.cs, next, preHeight + 1)
    checkpoint "dumptxoutset connect-during-walk ms=" & $ms &
               " during=" & $during &
               " parkTimedOut=" & $gParkTimedOut.load() &
               " rpcDone=" & $gJobDone.load()
    check during
    check ms < ConnectBudgetMs
    gRelease.store(true, moRelease)
    finishJob()
    check job.err == ""
    let res = parseJson(job.result)
    check res["base_height"].getInt() == preHeight
    check res["base_hash"].getStr() == displayHex(array[32, byte](preHash))
    check res["coins_written"].getBiggestInt() == expect.coinsWritten.int64
    check res["txoutset_hash"].getStr() ==
           displayHex(expect.txoutsetHash)
    check f.cs.bestHeight == preHeight + 1
    check f.cs.bestBlockHash == hashOf(next.header)

  test "sync gettxoutsetinfo: block connects during the walk; stats are the pre-connect snapshot":
    var f = buildChain("/tmp/nimrod_ni8_info", 5)
    defer:
      gRelease.store(true, moRelease)
      if not gJobDone.load(moAcquire): discard waitFlag(gJobDone, 10_000)
      raceHook = nil
      f.cs.close()
      removeDir(f.path)
    let pre = f.cs.computeUtxoSetInfo(cshtHashSerialized)
    let preHeight = f.height
    let preHash = hashOf(f.tip)
    let next = mineBlock(preHash, preHeight + 1, f.tip.timestamp + 600)
    resetPark()
    var job = RpcJob(rpc: f.rpc, call: "gettxoutsetinfo", params: "[]")
    startJob(job)
    let (ms, during) = connectWhileParked(f.cs, next, preHeight + 1)
    checkpoint "gettxoutsetinfo connect-during-walk ms=" & $ms &
               " during=" & $during &
               " parkTimedOut=" & $gParkTimedOut.load() &
               " rpcDone=" & $gJobDone.load()
    check during
    check ms < ConnectBudgetMs
    gRelease.store(true, moRelease)
    finishJob()
    check job.err == ""
    let res = parseJson(job.result)
    check res["height"].getInt() == pre.height
    check res["bestblock"].getStr() == displayHex(array[32, byte](pre.bestBlock))
    check res["txouts"].getBiggestInt() == int64(pre.txOuts)
    check res["hash_serialized_3"].getStr() == displayHex(pre.hashSerialized)
    let wantBtc = pre.totalAmount.float64 / 100_000_000.0
    check abs(res["total_amount"].getFloat() - wantBtc) < 1e-8
    check f.cs.bestHeight == preHeight + 1
    check res["height"].getInt() == preHeight
    check res["bestblock"].getStr() == displayHex(array[32, byte](preHash))

gWorkerQuit.store(true, moRelease)
joinThread(gWorker)
