## NI-4 (fleet audit 2026-10-07): shutdown must not flush from inside an
## interrupted connect.
##
## Before the fix the SIGINT/SIGTERM handler ran the whole shutdown — UTXO
## cache flush, RocksDB close, quit — in signal context. A process-directed
## SIGTERM lands on the main thread wherever it is; inside connectBlock's
## cache-apply loop that flush wrote the block's spent coins back to disk
## (end-to-end reproducer: tools/repro_shutdown_flush.py; deployed 5215491
## CORRUPT 3/3, fix CLEAN 3/3). Core: the handler only signals
## (StartShutdown); WaitForShutdown -> Shutdown() runs on the main thread,
## which flushes once under cs_main, coins then best block.
##
## These tests pin the in-process halves:
##   * the handler only REQUESTS a shutdown: the process survives a SIGTERM
##     and shutdownRequested() turns true (on the old handler the runner
##     would quit(0) right here — the [OK] count, not the exit code, shows it);
##   * flushStateForShutdown writes every cached coin AND the tip marker in
##     one batch, so the marker on disk always describes the coins on disk;
##   * an RPC handler admitted after RPC stop answers "Shutting down" (-9)
##     instead of touching chain state (Core CRPCTable::execute).

import unittest2
import std/[os, json, options, posix]
import ../src/nimrod as nimrod_main
import ../src/primitives/types
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server as rpc_server
import ../src/util/fatal

const TestDb = "/tmp/nimrod_test_shutdown_flush"

suite "NI-4 shutdown runs on the main loop, not in the signal handler":

  test "SIGTERM only requests a shutdown; the process keeps running":
    setupSignalHandlers()
    defer:
      # Do not leak into the suites that run after this one in test_all:
      # the flag (connect loops stop between blocks while it is set), the
      # handlers, and the AbortNode action (tests keep it nil, util/fatal).
      clearShutdownRequestForTests()
      setAbortAction(nil)
      discard posix.signal(posix.SIGTERM, posix.SIG_DFL)
      discard posix.signal(posix.SIGINT, posix.SIG_DFL)
      discard posix.signal(posix.SIGHUP, posix.SIG_DFL)
    check not shutdownRequested()
    check posix.kill(posix.getpid(), posix.SIGTERM) == 0
    # A process-directed signal to ourselves is delivered before kill returns
    # when this thread does not block it; give other threads a moment anyway.
    var waited = 0
    while not shutdownRequested() and waited < 2000:
      sleep(10); waited += 10
    check shutdownRequested()
    # Still here: the handler did not run the shutdown (old handler: quit(0)).
    check true

  test "flushStateForShutdown: cached coins and the tip marker land together":
    removeDir(TestDb)
    defer: removeDir(TestDb)
    var cs = newChainState(TestDb, regtestParams())
    var txid: array[32, byte]
    txid[0] = 0x4e; txid[31] = 0x04
    let op = OutPoint(txid: TxId(txid), vout: 1)
    let entry = UtxoEntry(output: TxOut(value: Satoshi(5000), scriptPubKey: @[0x51'u8]),
                          height: 7, isCoinbase: false)
    cs.putUtxoCache(op, entry)          # in the cache only, not on disk
    check cs.db.getUtxo(op).isNone
    var tip: array[32, byte]
    tip[0] = 0xaa
    cs.bestBlockHash = BlockHash(tip)
    cs.bestHeight = 7
    cs.flushStateForShutdown()
    check cs.cacheSize == 0
    cs.close()
    var cs2 = newChainState(TestDb, regtestParams())
    defer: cs2.close()
    check cs2.db.getUtxo(op).isSome
    check cs2.db.getUtxo(op).get().output.value == Satoshi(5000)
    check cs2.bestBlockHash == BlockHash(tip)
    check cs2.bestHeight == 7

  test "RPC after stop answers Shutting down (-9) without running the handler":
    removeDir(TestDb)
    defer: removeDir(TestDb)
    let params = regtestParams()
    var cs = newChainState(TestDb, params)
    defer: cs.close()
    let mp = newMempool(cs, params, fullRbf = false)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    check rpc.handleMethod("getblockcount", %*[]).kind == JInt
    rpc.stop()
    var code = 0
    var msg = ""
    try:
      discard rpc.handleMethod("getblockcount", %*[])
    except RpcError as e:
      code = e.code
      msg = e.msg
    check code == -9
    check msg == "Shutting down"
