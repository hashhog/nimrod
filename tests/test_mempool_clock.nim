## The mempool clock (Core SetMockTime), `bytes` (GetTotalTxSize) and the
## unbroadcast set behind getmempoolinfo.
##
## `bytes` is the sum of entry vsizes -- 85 per 1-in/1-out P2SH(OP_TRUE) spend
## and 128 for the 2-input one, read from Bitcoin Core v31.1.0 (see
## test_mempool_usage.nim). The rolling minimum fee decays on the mempool
## clock, which setmocktime moves.
##
## Command:  nim c -r tests/test_mempool_clock.nim

import unittest2
import std/[os, sets, tables, tempfiles, times]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter

proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), 0]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc spend(prevs: openArray[OutPoint], value: int64): Transaction =
  var ins: seq[TxIn]
  for p in prevs:
    ins.add(TxIn(prevOut: p, scriptSig: @[byte(0x01), byte(OP_TRUE)],
                 sequence: 0xFFFFFFFD'u32))
  Transaction(version: 2, inputs: ins,
              outputs: @[TxOut(value: Satoshi(value), scriptPubKey: p2shTrue())],
              witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

type Fx = object
  dir: string
  cs: ChainState
  mp: Mempool
  crypto: CryptoEngine
  cb: seq[Transaction]
  tip: BlockHash

proc setup(maxSize = 5_000_000): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_mempool_usage_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = hashOf(blk)
  result.tip = prev
  result.mp = newMempool(result.cs, params, maxSize = maxSize, minFeeRate = 0.0)
  result.crypto = newCryptoEngine()

proc teardown(f: var Fx) =
  f.cs.close()
  removeDir(f.dir)

proc op(tx: Transaction, vout = 0'u32): OutPoint =
  OutPoint(txid: tx.txid(), vout: vout)

const Fee = 10_000'i64

suite "bytes is the sum of vsizes":
  test "85 per simple spend, 383 for the four-tx pool of test_mempool_usage":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let child = spend([a.op], 5_000_000_000 - 2 * Fee)
    let indep = spend([f.cb[2].op], 5_000_000_000 - Fee)
    let twoIn = spend([f.cb[3].op, f.cb[4].op], 10_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.totalTxSize == 85
    for t in [child, indep, twoIn]:
      check f.mp.acceptTransaction(t, f.crypto).isOk
    check f.mp.totalTxSize == 383
    f.teardown()

suite "unbroadcast set":
  test "a removed tx leaves the set":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    f.mp.unbroadcast.incl(a.txid())
    f.mp.removeTransaction(a.txid())
    check f.mp.unbroadcast.len == 0
    f.teardown()

suite "mempool mock clock":
  teardown:
    setMockTime(0)

  test "entries are stamped with mock time":
    var f = setup()
    setMockTime(1_700_000_000)
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.entries[a.txid()].timeAdded.toUnix() == 1_700_000_000
    f.teardown()

  test "the rolling floor halves after 12h at a full pool and not before":
    # 2500 keeps the pool above half full with one parent/child pair (2008).
    var f = setup(maxSize = 2_500)
    setMockTime(1_700_000_000)
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let child = spend([a.op], 5_000_000_000 - 2 * Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.acceptTransaction(child, f.crypto).isOk
    let poor = spend([f.cb[2].op], 5_000_000_000 - 1_000)
    check not f.mp.acceptTransaction(poor, f.crypto).isOk
    check f.mp.rollingMinimumFeeRate == 11_864.0
    # A block arms the decay (blockSinceLastRollingFeeBump).
    let blk = blockOf(f.tip, 111, @[coinbaseTx(111)])
    check f.cs.connectBlock(blk, 111).isOk
    # 10 s: Core only decays after lastRollingFeeUpdate + 10.
    setMockTime(1_700_000_010)
    check f.mp.getMinFee() == 11.864
    # One halflife later the floor is 11864 / 2 = 5932 sat/kvB.
    setMockTime(1_700_000_000 + 43_200 + 1)
    check abs(f.mp.getMinFee() - 5.932) < 0.001
    f.teardown()

  test "setMockTime(0) goes back to the wall clock":
    setMockTime(1_000)
    check mempoolUnixTime() == 1_000
    setMockTime(0)
    check mempoolUnixTime() > 1_700_000_000
