## Verbose mempool entries carry Core's cluster fields.
##
## For a CPFP pair Core reports descendantcount/descendantsize/fees.descendant
## over the tx plus its in-pool descendants, depends/spentby links between the
## in-pool parent and child, and chunkweight/fees.chunk per linearization
## chunk (parent + child form one chunk when the child pays for the parent).
## nimrod emitted per-tx values (descendantcount 1, chunkweight = own weight)
## and empty depends/spentby arrays.
##
## Reference: bitcoin-core/src/rpc/mempool.cpp entryToJSON.

import unittest2
import std/[options, tables, times, json, os, strutils]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/rpc/server

const TestDbPath = "/tmp/nimrod_mempool_cluster_fields_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc txidOf(b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  TxId(arr)

proc addEntry(mp: Mempool, id: TxId, prev: OutPoint, fee: int64, weight = 340) =
  let tx = Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)
  mp.entries[id] = MempoolEntry(
    tx: tx, txid: id, fee: Satoshi(fee), weight: weight, feeRate: 1.0,
    timeAdded: getTime(), height: 100, ancestorFee: Satoshi(fee),
    ancestorWeight: weight, ancestorCount: 1, ancestorSize: weight div 4)
  mp.spentBy[prev] = id

proc hex(id: TxId): string =
  var s = ""
  for i in countdown(31, 0):
    s.add(toHex(int(array[32, byte](id)[i]), 2))
  s.toLowerAscii

suite "mempool entry cluster fields":
  test "two-tx CPFP chain reports descendants, links and a shared chunk":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let parent = txidOf(0x01)
    let child = txidOf(0x02)
    var ext: array[32, byte]
    ext[0] = 0xEE
    mp.addEntry(parent, OutPoint(txid: TxId(ext), vout: 0), fee = 9)
    mp.addEntry(child, OutPoint(txid: parent, vout: 0), fee = 50000)

    let p = rpc.mempoolEntryJson(parent, mp.entries[parent])
    let c = rpc.mempoolEntryJson(child, mp.entries[child])

    check p["descendantcount"].getInt() == 2
    check p["descendantsize"].getInt() == 170
    check c["descendantcount"].getInt() == 1
    check c["descendantsize"].getInt() == 85
    check abs(p["fees"]["descendant"].getFloat() - 0.00050009) < 1e-12
    check abs(c["fees"]["descendant"].getFloat() - 0.0005) < 1e-12

    check p["chunkweight"].getInt() == 680
    check c["chunkweight"].getInt() == 680
    check abs(p["fees"]["chunk"].getFloat() - 0.00050009) < 1e-12
    check abs(c["fees"]["chunk"].getFloat() - 0.00050009) < 1e-12

    check p["depends"].len == 0
    check p["spentby"].len == 1
    check p["spentby"][0].getStr() == hex(child)
    check c["depends"].len == 1
    check c["depends"][0].getStr() == hex(parent)
    check c["spentby"].len == 0
    cs.close()
    cleanupTestDb()

  test "chunk stops at a better-paying parent: child stays its own chunk":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let parent = txidOf(0x11)
    let child = txidOf(0x12)
    var ext: array[32, byte]
    ext[0] = 0xEF
    mp.addEntry(parent, OutPoint(txid: TxId(ext), vout: 0), fee = 50000)
    mp.addEntry(child, OutPoint(txid: parent, vout: 0), fee = 100)
    let p = rpc.mempoolEntryJson(parent, mp.entries[parent])
    let c = rpc.mempoolEntryJson(child, mp.entries[child])
    check p["chunkweight"].getInt() == 340
    check c["chunkweight"].getInt() == 340
    check abs(p["fees"]["chunk"].getFloat() - 0.0005) < 1e-12
    check abs(c["fees"]["chunk"].getFloat() - 0.000001) < 1e-12
    check p["descendantcount"].getInt() == 2
    cs.close()
    cleanupTestDb()
