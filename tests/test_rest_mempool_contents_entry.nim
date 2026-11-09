## `GET /rest/mempool/contents.json` serves Core's entryToJSON per entry.
##
## Core (src/rest.cpp rest_mempool) answers contents.json with
## MempoolToJSON(pool, verbose=true), which builds every value with the same
## entryToJSON getrawmempool true / getmempoolentry use (src/rpc/mempool.cpp).
## nimrod hand-rolled an eleven-field object instead: top-level fee,
## descendantfees and ancestorfees (Core has none of them; fees live in the
## "fees" sub-object), hardcoded descendantcount/ancestorcount 1, and no
## wtxid, chunkweight, fees, depends, spentby, bip125-replaceable or
## unbroadcast.  Core v31.1 regtest rows
## warden_invalidated_submit/rest/tip100-contents:<txid>.* caught it.

import unittest2
import std/[tables, times, json, os, strutils]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/rpc/[server, rest]

const TestDbPath = "/tmp/nimrod_rest_mempool_contents_entry_test"

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

suite "REST mempool/contents.json entry shape":
  test "contents.json entries equal getrawmempool true entries (Core entryToJSON)":
    cleanupTestDb()
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    var mp = newMempool(cs, params)
    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let restSrv = newRestServer(18444'u16, cs, mp, params)
    let parent = txidOf(0x01)
    let child = txidOf(0x02)
    var ext: array[32, byte]
    ext[0] = 0xEE
    mp.addEntry(parent, OutPoint(txid: TxId(ext), vout: 0), fee = 1_000_000)
    mp.addEntry(child, OutPoint(txid: parent, vout: 0), fee = 50_000)

    let resp = restSrv.handleRestMempoolContents()
    check resp.status == Http200
    let body = parseJson(resp.body)
    check body.kind == JObject
    check body.len == 2
    check body.hasKey(hex(parent))
    check body.hasKey(hex(child))

    for id in [parent, child]:
      let got = body[hex(id)]
      let want = rpc.mempoolEntryJson(id, mp.entries[id])
      # Same key set, same order, same values as the RPC entry object.
      var gotKeys, wantKeys: seq[string]
      for k, _ in got: gotKeys.add(k)
      for k, _ in want: wantKeys.add(k)
      check gotKeys == wantKeys
      check got == want

    let p = body[hex(parent)]
    # Fields Core does not emit at the top level of an entry.
    check not p.hasKey("fee")
    check not p.hasKey("descendantfees")
    check not p.hasKey("ancestorfees")
    # Fields Core emits that nimrod's REST entry lacked.
    for k in ["wtxid", "chunkweight", "fees", "depends", "spentby",
              "bip125-replaceable", "unbroadcast"]:
      check p.hasKey(k)
    # Real DAG walk, not a hardcoded 1.
    check p["descendantcount"].getInt() == 2
    check p["spentby"].len == 1
    check p["spentby"][0].getStr() == hex(child)
    check body[hex(child)]["depends"][0].getStr() == hex(parent)
    check abs(p["fees"]["base"].getFloat() - 0.01) < 1e-12
    cs.close()
    cleanupTestDb()
