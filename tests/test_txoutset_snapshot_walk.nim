## gettxoutsetinfo must not freeze the node (release gate 3a).
##
## Live mainnet 2026-10-01: the ~38 min walk ran synchronously on the RPC
## thread's chronos loop (one getblockcount waited 2,306 s), flushed the main
## thread's caches from that thread, and labelled the result with a height read
## at a different moment than its iterator's implicit snapshot.
##
## 1. `computeUtxoSetInfoAt` labels the result from the SAME snapshot it walks:
##    writes after the snapshot (a block connecting mid-walk) change neither
##    the count nor the label, and the fallback label (the live tip the old
##    code used) is ignored when the snapshot has one.
## 2. `runTxoWalk` keeps the caller's event loop live: a ticker on the same
##    loop keeps firing during the walk. CONTROL: the old inline walk on that
##    loop produces zero ticks.

import unittest2
import std/[os, options, times]
import chronos
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/rpc/server

const BaseDir = "/tmp/nimrod_txoutset_snapshot_walk"

proc coinKey(i: int): seq[byte] =
  var txid: array[32, byte]
  txid[0] = byte(i and 0xff)
  txid[1] = byte((i shr 8) and 0xff)
  txid[2] = byte((i shr 16) and 0xff)
  txid[31] = 0x5a
  utxoKey(txid, 0)

proc coinVal(i: int): seq[byte] =
  serializeUtxoEntry(UtxoEntry(
    output: TxOut(value: Satoshi(1000 + i), scriptPubKey: @[0x51'u8, byte(i and 0xff)]),
    height: 1, isCoinbase: false))

proc setTip(b: WriteBatch, h: int32, tag: byte) =
  var hash: array[32, byte]
  hash[0] = tag
  b.put(cfMeta, metaKey("bestblock"), @hash)
  var w = BinaryWriter()
  w.writeInt32LE(h)
  b.put(cfMeta, metaKey("height"), w.data)

proc addCoins(d: Database, lo, hi: int, h: int32, tag: byte) =
  let b = d.newWriteBatch()
  for i in lo ..< hi:
    b.put(cfUtxo, coinKey(i), coinVal(i))
  b.setTip(h, tag)
  d.write(b)

suite "gettxoutsetinfo snapshot walk":
  test "label and coins come from one snapshot":
    let dir = BaseDir & "_1"
    removeDir(dir)
    let d = openDatabase(dir)
    defer:
      d.close()
      removeDir(dir)
    d.addCoins(0, 10, 5, 0xaa)
    var view = openSnapshotView(d)
    # A block connects after the snapshot: new coins + new tip, one batch.
    d.addCoins(10, 15, 6, 0xbb)
    var fb: array[32, byte]
    fb[0] = 0xcc
    let info = computeUtxoSetInfoAt(view, cshtHashSerialized, 999, BlockHash(fb))
    closeSnapshotView(view)
    check info.txOuts == 10
    check info.height == 5
    check array[32, byte](info.bestBlock)[0] == 0xaa
    # Negative control: a new snapshot sees the block.
    var view2 = openSnapshotView(d)
    let info2 = computeUtxoSetInfoAt(view2, cshtHashSerialized, 999, BlockHash(fb))
    closeSnapshotView(view2)
    check info2.txOuts == 15
    check info2.height == 6
    check info2.hashSerialized != info.hashSerialized

  test "walk thread keeps the event loop live":
    let dir = BaseDir & "_2"
    removeDir(dir)
    let d = openDatabase(dir)
    defer:
      d.close()
      removeDir(dir)
    d.addCoins(0, 200_000, 1, 0xaa)
    var fb: array[32, byte]

    proc ticksDuring(inline: bool): Future[(int, float)] {.async.} =
      var ticks = 0
      var finished = false
      proc ticker() {.async.} =
        while not finished:
          await sleepAsync(1)
          inc ticks
      let t = ticker()
      let t0 = epochTime()
      if inline:
        var v = openSnapshotView(d)
        discard computeUtxoSetInfoAt(v, cshtMuHash, 0, BlockHash(fb))
        closeSnapshotView(v)
      else:
        discard await runTxoWalk(openSnapshotView(d), cshtMuHash, 0, BlockHash(fb))
      let dt = epochTime() - t0
      finished = true
      await t
      return (ticks, dt)

    let (ticks, dt) = waitFor ticksDuring(false)
    let (cTicks, cDt) = waitFor ticksDuring(true)
    echo "threaded walk: ", ticks, " ticks in ", dt, " s | inline (old): ",
         cTicks, " ticks in ", cDt, " s"
    check dt > 0.2            # the walk is long enough to measure
    check ticks.float >= dt * 100.0   # loop ticked at >= 100 Hz during it
    check cTicks <= 1         # CONTROL: the old inline walk froze the loop
