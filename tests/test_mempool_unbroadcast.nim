## Locally submitted txs are "unbroadcast" until a peer fetches them (Core
## m_unbroadcast_txids): getmempoolentry.unbroadcast and
## getmempoolinfo.unbroadcastcount reflect it; leaving the pool clears it.
import unittest2
import std/[options, tables, times, json, os, sets]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/rpc/server

const TestDbPath = "/tmp/nimrod_mempool_unbroadcast_test"

suite "mempool unbroadcast set":
  test "add, report, clear on getdata and on removal":
    if dirExists(TestDbPath):
      removeDir(TestDbPath)
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    var a, b, ext: array[32, byte]
    a[0] = 1
    b[0] = 2
    ext[0] = 0xEE
    for (id, v) in [(TxId(a), 0'u32), (TxId(b), 1'u32)]:
      let tx = Transaction(version: 2,
        inputs: @[TxIn(prevOut: OutPoint(txid: TxId(ext), vout: v),
                       scriptSig: @[], sequence: 0xfffffffd'u32)],
        outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      mp.entries[id] = MempoolEntry(tx: tx, txid: id, fee: Satoshi(100),
        weight: 340, timeAdded: getTime(), height: 1, ancestorFee: Satoshi(100),
        ancestorWeight: 340, ancestorCount: 1, ancestorSize: 85)
    mp.addUnbroadcast(TxId(a))
    mp.addUnbroadcast(TxId(a))  # a set, not a counter
    check rpc.mempoolEntryJson(TxId(a), mp.entries[TxId(a)])["unbroadcast"].getBool()
    check not rpc.mempoolEntryJson(TxId(b), mp.entries[TxId(b)])["unbroadcast"].getBool()
    check mp.unbroadcast.len == 1
    mp.removeUnbroadcast(TxId(a))  # a peer fetched it
    check mp.unbroadcast.len == 0
    mp.addUnbroadcast(TxId(b))
    mp.removeTransaction(TxId(b))  # left the pool
    check mp.unbroadcast.len == 0
    mp.addUnbroadcast(TxId(b))     # not in pool: ignored
    check mp.unbroadcast.len == 0
    cs.close()
    if dirExists(TestDbPath):
      removeDir(TestDbPath)
