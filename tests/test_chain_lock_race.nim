## Chain lock (Core cs_main analogue): the RPC thread and the sync thread must
## never interleave inside a chainstate mutation, and an RPC read must never
## observe a half-applied block.
##
## nimrod runs the RPC server on its own OS thread (rpc/rpc_thread.nim) with
## direct access to the SAME ChainState / mempool the main (P2P + sync) thread
## mutates. Up to a0da75f nothing serialised them: submitblock connected
## blocks from the RPC thread while sync connected blocks on the main thread,
## and gettxout / getbestblockhash read the coin cache and the tip with no
## lock. Core holds cs_main across every chainstate mutation
## (ProcessNewBlock -> AcceptBlock / ActivateBestChain -> ConnectTip) and every
## coins-view read the RPC layer does (rpc/blockchain.cpp gettxout:
## LOCK(cs_main)), so neither outcome below is possible in Core.
##
## The interleaving is forced, not hoped for: chainstate.nim exposes named
## race points (compiled only with -d:nimrodRaceHooks) where a test parks one
## thread while the other runs. Each parked thread waits for the other side
## with a TIMEOUT, so with a correct lock (the other side blocks on it) the
## test does not deadlock: the parked thread times out, finishes, releases.
##
##   1. "connect.precommit": submitblock(X) on the RPC thread is parked after
##      validating and staging X but before its write; the sync thread then
##      connects a competitor Y at the SAME height spending the SAME coin.
##      Correct: exactly one of X / Y is connected, the coin is spent once,
##      the loser's coinbase is not in the UTXO set.
##   2. "connect.postcache": the sync thread connecting Y is parked after the
##      coin cache was updated but before the tip moved; the RPC thread asks
##      gettxout + getbestblockhash. Correct: the answer is all-before or
##      all-after Y, never a mix (Core: one LOCK(cs_main) for the whole call).

import unittest2
import std/[options, os, json, strutils, atomics, times, monotimes]
import ../src/network/sync
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

when not defined(nimrodRaceHooks):
  {.error: "compile with -d:nimrodRaceHooks".}

const EASY_BITS = 0x207fffff'u32
const BASE_TIME = 1_700_000_000'u32
const ParkTimeoutMs = 1500

proc hashOf(h: BlockHeader): BlockHash = BlockHash(doubleSha256(serialize(h)))

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc displayHex(a: array[32, byte]): string =
  var r: array[32, byte]
  for i in 0 ..< 32: r[i] = a[31 - i]
  hexOf(r)

proc makeCoinbaseTx(height: int32, tag: byte, nOut = 1): Transaction =
  var outs: seq[TxOut]
  for i in 0 ..< nOut:
    outs.add TxOut(value: Satoshi(5_000_000_000'i64 div nOut), scriptPubKey: @[byte(0x51)])
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: outs,
    witnesses: @[], lockTime: 0)

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32, tag: byte,
               extra: seq[Transaction] = @[], cbOuts = 1): Block =
  let cb = makeCoinbaseTx(height, tag, cbOuts)
  var txids = @[array[32, byte](cb.txid())]
  for t in extra: txids.add(array[32, byte](t.txid()))
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
                        merkleRoot: merkleRoot(txids), timestamp: ts,
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb] & extra)

proc spend(prev: OutPoint, value: int64, spkTag: byte): Transaction =
  # OP_TRUE prevout; distinct outputs so X's and Y's spends differ.
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51), spkTag])],
    witnesses: @[], lockTime: 0)

type
  Fixture = object
    path: string
    params: ConsensusParams
    cs: ChainState
    sm: SyncManager
    rpc: RpcServer
    coin: OutPoint          # block 1's coinbase, mature, spent by X and Y
    tip: BlockHeader        # block 3

proc buildFixture(path: string, cbOuts = 1): Fixture =
  removeDir(path)
  var p = regtestParams()
  p.coinbaseMaturity = 1
  var cs = newChainState(path, p)
  doAssert cs.connectBlock(buildGenesisBlock(p), 0'i32).isOk
  var prev = p.genesisBlockHash
  var ts = BASE_TIME
  var first: Block
  var last: BlockHeader
  for h in 1'i32 .. 3'i32:
    let b = mineBlock(prev, h, ts, 0x00, cbOuts = (if h == 1: cbOuts else: 1))
    doAssert cs.connectBlock(b, h).isOk
    if h == 1: first = b
    prev = hashOf(b.header)
    last = b.header
    ts += 600
  var csv = cs
  let sm = newSyncManager(nil, csv.db, p, csv)
  let mp = newMempool(cs, p)
  let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                         peerManager = nil, feeEstimator = newFeeEstimator(),
                         params = p)
  Fixture(path: path, params: p, cs: csv, sm: sm, rpc: rpc,
          coin: OutPoint(txid: first.txs[0].txid(), vout: 0'u32), tip: last)

# --- the parked-thread handshake -------------------------------------------

var gParkPoint: string            # set before any thread starts; read-only after
var gParkHash: BlockHash
var gParked: Atomic[bool]         # the hooked thread reached the point
var gOtherDone: Atomic[bool]      # the other thread finished its work
var gParkTimedOut: Atomic[bool]   # the hooked thread gave up waiting

proc waitFlag(f: var Atomic[bool], ms: int): bool =
  let deadline = epochTime() + ms.float / 1000.0
  while not f.load(moAcquire):
    if epochTime() > deadline: return false
    sleep(1)
  true

proc parkHook(point: string, hash: BlockHash) {.nimcall, gcsafe, raises: [].} =
  {.cast(gcsafe).}:
    if point != gParkPoint or hash != gParkHash: return
    gParked.store(true, moRelease)
    if not waitFlag(gOtherDone, ParkTimeoutMs):
      gParkTimedOut.store(true, moRelease)

proc resetPark(point: string, hash: BlockHash) =
  gParkPoint = point
  gParkHash = hash
  gParked.store(false); gOtherDone.store(false); gParkTimedOut.store(false)
  raceHook = parkHook

# --- the RPC-thread stand-in -------------------------------------------------
#
# ONE persistent worker thread plays the RPC thread for the whole module. It
# must outlive every allocation it makes: Nim's allocator gives each thread its
# own heap, and freeing (from the main thread) a block whose owning thread has
# already exited crashes in addToSharedFreeList. Production's RPC thread lives
# for the whole process, so this is a harness constraint, not a node bug. The
# WIP version of this file joined a per-test thread and SIGSEGV'd in teardown.

type RpcJob = object
  rpc: RpcServer
  calls: seq[tuple[m: string, params: string]]
  results: seq[string]
  waitParkFirst: bool     # wait until the main thread is parked before calling
  startGate: bool         # spin until gGo, so both threads start together
  releaseParkAfter: bool  # then tell the parked main thread it may continue

var gWorker: Thread[void]
var gJob: Atomic[pointer]
var gJobDone: Atomic[bool]
var gWorkerQuit: Atomic[bool]
var gReady: Atomic[bool]          # worker is spinning at the start gate
var gGo: Atomic[bool]             # open the start gate

proc runJob(job: ptr RpcJob) =
  {.cast(gcsafe).}:
    if job.waitParkFirst:
      discard waitFlag(gParked, 10_000)
    if job.startGate:
      gReady.store(true, moRelease)
      while not gGo.load(moAcquire): cpuRelax()
    for c in job.calls:
      var out1: string
      try:
        out1 = $job.rpc.handleMethod(c.m, parseJson(c.params))
      except CatchableError as e:
        out1 = "ERR " & e.msg
      except Exception as e:
        out1 = "DEFECT " & e.msg
      job.results.add(out1)
    if job.releaseParkAfter:
      gOtherDone.store(true, moRelease)

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
  doAssert waitFlag(gJobDone, 60_000), "RPC worker never finished its job"

createThread(gWorker, workerLoop)

suite "chain lock: RPC thread vs sync thread":

  test "submitblock(X) parked pre-commit while sync connects competitor Y — one winner":
    var f = buildFixture("/tmp/nimrod_chainlock_race_1")
    defer:
      raceHook = nil
      f.cs.close()
      removeDir(f.path)
    let tipHash = hashOf(f.tip)
    let x = mineBlock(tipHash, 4, f.tip.timestamp + 600, 0x01,
                      @[spend(f.coin, 4_999_000_000, 0x01)])
    let y = mineBlock(tipHash, 4, f.tip.timestamp + 601, 0x02,
                      @[spend(f.coin, 4_998_000_000, 0x02)])
    let xh = hashOf(x.header)
    let yh = hashOf(y.header)
    resetPark("connect.precommit", xh)

    let xparams = $(%*[hexOf(serialize(x))])
    var job = RpcJob(rpc: f.rpc)
    job.calls.add(("submitblock", xparams))
    startJob(job)                            # RPC thread: submitblock(X)
    check waitFlag(gParked, 10_000)          # X validated + staged, parked
    let yApplied = f.sm.applyBlock(y, 4'i32) # the sync thread's connect
    gOtherDone.store(true, moRelease)
    finishJob()
    raceHook = nil

    let onChain = f.cs.db.getBlockHashByHeight(4)
    let xCb = OutPoint(txid: x.txs[0].txid(), vout: 0'u32)
    let yCb = OutPoint(txid: y.txs[0].txid(), vout: 0'u32)
    let xSpendOut = OutPoint(txid: x.txs[1].txid(), vout: 0'u32)
    let ySpendOut = OutPoint(txid: y.txs[1].txid(), vout: 0'u32)
    checkpoint "submitblock(X) -> " & job.results[0] & "  applyBlock(Y) -> " &
               $yApplied & " (" & f.sm.lastApplyError & ")" &
               "  parkTimedOut=" & $gParkTimedOut.load()
    checkpoint "tip=" & $f.cs.bestHeight & " " & displayHex(array[32, byte](f.cs.bestBlockHash)) &
               "  X=" & displayHex(array[32, byte](xh)) & "  Y=" & displayHex(array[32, byte](yh)) &
               "  height4=" & (if onChain.isSome: displayHex(array[32, byte](onChain.get())) else: "none")
    checkpoint "coins: Xcb=" & $f.cs.getUtxo(xCb).isSome & " Ycb=" & $f.cs.getUtxo(yCb).isSome &
               " XspendOut=" & $f.cs.getUtxo(xSpendOut).isSome &
               " YspendOut=" & $f.cs.getUtxo(ySpendOut).isSome
    let xWon = job.results[0] == "null"
    # Exactly one block was connected at height 4.
    check xWon != yApplied
    check f.cs.bestHeight == 4
    check onChain.isSome and onChain.get() == f.cs.bestBlockHash
    let winner = f.cs.bestBlockHash
    check winner == xh or winner == yh
    # The coin was spent ONCE: only the winner's outputs exist.
    let winX = winner == xh
    check f.cs.getUtxo(xCb).isSome == winX
    check f.cs.getUtxo(xSpendOut).isSome == winX
    check f.cs.getUtxo(yCb).isSome == (not winX)
    check f.cs.getUtxo(ySpendOut).isSome == (not winX)
    # Same on disk, after a cold reopen.
    f.cs.close()
    var cs2 = newChainState(f.path, f.params)
    check cs2.bestBlockHash == winner
    check cs2.db.getUtxo(xCb).isSome == winX
    check cs2.db.getUtxo(yCb).isSome == (not winX)
    check cs2.db.getUtxo(ySpendOut).isSome == (not winX)
    check cs2.db.getUtxo(xSpendOut).isSome == winX
    f.cs = cs2

  test "gettxout during a sync connect parked after the cache update — no torn view":
    var f = buildFixture("/tmp/nimrod_chainlock_race_2")
    defer:
      raceHook = nil
      f.cs.close()
      removeDir(f.path)
    let tipHash = hashOf(f.tip)
    let y = mineBlock(tipHash, 4, f.tip.timestamp + 600, 0x02,
                      @[spend(f.coin, 4_998_000_000, 0x02)])
    let yh = hashOf(y.header)
    resetPark("connect.postcache", yh)
    let coinParams = $(%*[displayHex(array[32, byte](f.coin.txid)), 0, false])
    let ycbParams = $(%*[displayHex(array[32, byte](y.txs[0].txid())), 0, false])

    # The sync thread (this one) is the parked one here: applyBlock parks
    # inside the hook; the RPC worker waits for the park, runs the reads,
    # then releases it.
    var job = RpcJob(rpc: f.rpc, waitParkFirst: true, releaseParkAfter: true,
                     calls: @[("gettxout", coinParams), ("gettxout", ycbParams),
                              ("getbestblockhash", "[]"), ("getblockcount", "[]")])
    startJob(job)
    let yApplied = f.sm.applyBlock(y, 4'i32)
    finishJob()
    raceHook = nil

    let coinAns = parseJson(job.results[0])
    let ycbAns = parseJson(job.results[1])
    let best = parseJson(job.results[2]).getStr()
    let count = parseJson(job.results[3]).getInt()
    checkpoint "applyBlock(Y)=" & $yApplied & " parkTimedOut=" & $gParkTimedOut.load()
    checkpoint "gettxout(coin)=" & job.results[0]
    checkpoint "gettxout(Ycb)=" & job.results[1]
    checkpoint "getbestblockhash=" & best & " getblockcount=" & $count
    check yApplied
    let preTip = displayHex(array[32, byte](tipHash))
    let postTip = displayHex(array[32, byte](yh))
    # The reader saw ONE state: either entirely before Y or entirely after Y.
    if best == preTip:
      check count == 3
      check coinAns.kind == JObject                 # coin unspent before Y
      check ycbAns.kind == JNull                    # Y's coinbase not yet there
    else:
      check best == postTip
      check count == 4
      check coinAns.kind == JNull                   # spent by Y
      check ycbAns.kind == JObject
      if ycbAns.kind == JObject:
        check ycbAns["bestblock"].getStr() == postTip
        check ycbAns["confirmations"].getInt() == 1
    # Never a coin whose own reported confirmations are < 1.
    if ycbAns.kind == JObject:
      check ycbAns["confirmations"].getInt() >= 1

  test "UNINSTRUMENTED: concurrent submitblock(X) vs sync applyBlock(Y) — no double connect":
    # No race hooks: both threads are released from a start gate together and
    # the main thread's start is offset by a sweep of delays so the two
    # connects' critical windows overlap in some runs. X and Y each spend the
    # same 400 coins (one wide coinbase), which widens connectBlock's
    # check-to-commit window to the size of a real block's.
    raceHook = nil
    const Runs = 120
    const Coins = 400
    var doubles = 0
    var torn = 0
    var xWins = 0
    var yWins = 0
    var firstDouble = ""
    for run in 0 ..< Runs:
      let path = "/tmp/nimrod_chainlock_race_s" & $run
      var f = buildFixture(path, cbOuts = Coins)
      let tipHash = hashOf(f.tip)
      var xs, ys: Transaction
      xs = Transaction(version: 1, witnesses: @[], lockTime: 0)
      ys = Transaction(version: 1, witnesses: @[], lockTime: 0)
      for i in 0 ..< Coins:
        let op = OutPoint(txid: f.coin.txid, vout: uint32(i))
        xs.inputs.add TxIn(prevOut: op, scriptSig: @[], sequence: 0xFFFFFFFF'u32)
        ys.inputs.add TxIn(prevOut: op, scriptSig: @[], sequence: 0xFFFFFFFF'u32)
      xs.outputs = @[TxOut(value: Satoshi(4_000_000_000'i64), scriptPubKey: @[byte(0x51), 0x01])]
      ys.outputs = @[TxOut(value: Satoshi(3_900_000_000'i64), scriptPubKey: @[byte(0x51), 0x02])]
      let x = mineBlock(tipHash, 4, f.tip.timestamp + 600, 0x01, @[xs])
      let y = mineBlock(tipHash, 4, f.tip.timestamp + 601, 0x02, @[ys])
      let xh = hashOf(x.header)
      let yh = hashOf(y.header)
      var job = RpcJob(rpc: f.rpc, startGate: true)
      job.calls.add(("submitblock", $(%*[hexOf(serialize(x))])))
      gReady.store(false); gGo.store(false)
      startJob(job)
      doAssert waitFlag(gReady, 10_000)
      gGo.store(true, moRelease)
      # Sweep the relative phase: 0 .. 3.9 ms in 33 us steps.
      let spinUntil = getMonoTime() + initDuration(microseconds = (run mod 120) * 33)
      while getMonoTime() < spinUntil: cpuRelax()
      let yApplied = f.sm.applyBlock(y, 4'i32)
      finishJob()
      let xOk = job.results[0] == "null"
      let tip = f.cs.bestBlockHash
      if tip == xh: inc xWins
      elif tip == yh: inc yWins
      let xCb = OutPoint(txid: x.txs[0].txid(), vout: 0'u32)
      let yCb = OutPoint(txid: y.txs[0].txid(), vout: 0'u32)
      let bothCoinbases = f.cs.getUtxo(xCb).isSome and f.cs.getUtxo(yCb).isSome
      if xOk and yApplied:
        inc doubles
        if firstDouble.len == 0:
          firstDouble = "run " & $run & ": submitblock(X)=null AND applyBlock(Y)=true, tip=" &
                        (if tip == xh: "X" elif tip == yh: "Y" else: "?") &
                        " Xcb=" & $f.cs.getUtxo(xCb).isSome & " Ycb=" & $f.cs.getUtxo(yCb).isSome
      elif bothCoinbases:
        inc torn
      f.cs.close()
      removeDir(path)
    checkpoint "runs=" & $Runs & " doubleConnects=" & $doubles & " bothCoinbasesLive=" & $torn &
               " tipX=" & $xWins & " tipY=" & $yWins
    if firstDouble.len > 0: checkpoint "first double connect: " & firstDouble
    echo "STRESS runs=", Runs, " doubleConnects=", doubles, " bothCoinbasesLive=", torn,
         " tipX=", xWins, " tipY=", yWins
    check doubles == 0
    check torn == 0
    check xWins + yWins == Runs

gWorkerQuit.store(true, moRelease)
joinThread(gWorker)
