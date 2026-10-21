## getmempoolinfo `usage`/`bytes` and -maxmempool trimming, against Core v31.1.
##
## Core's `usage` is CTxMemPool::DynamicMemoryUsage(); `bytes` is the sum of
## entry vsizes (GetTotalTxSize). nimrod used to report the serialized length
## for both and compared that against -maxmempool, so it neither matched Core
## nor trimmed where Core does.
##
## Every expected number below was read from a Bitcoin Core v31.1.0 regtest node
## (sha256 986e63b3...6a08, the tools/core-regtest pin): P2SH(OP_TRUE) coinbases,
## 85-vbyte 1-in/1-out spends with scriptSig `01 51`, usage read from
## getmempoolinfo after each sendrawtransaction, then after one block that
## confirmed all four. The harness side is the `usage` rows of
## tools/core-regtest group warden_invalidated_submit.
##
## Command:  nim c -r tests/test_mempool_usage.nim

import unittest2
import std/[os, sets, tables, tempfiles]
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

suite "mempool usage follows Core DynamicMemoryUsage":
  test "one 1-in/1-out tx is 952 usage":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.currentSize == 952
    f.teardown()

  test "a child, a sibling and a 2-input tx step through 2008, 2976, 4040":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let child = spend([a.op], 5_000_000_000 - 2 * Fee)
    let indep = spend([f.cb[2].op], 5_000_000_000 - Fee)
    let twoIn = spend([f.cb[3].op, f.cb[4].op], 10_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.acceptTransaction(child, f.crypto).isOk
    check f.mp.currentSize == 2008          # cluster of 2: +136 over two singletons
    check f.mp.acceptTransaction(indep, f.crypto).isOk
    check f.mp.currentSize == 2976          # txns_randomized grows 2 -> 4 slots
    check f.mp.acceptTransaction(twoIn, f.crypto).isOk
    check f.mp.currentSize == 4040
    f.teardown()

  test "a block that confirms all of them leaves Core's 64 byte vector":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let child = spend([a.op], 5_000_000_000 - 2 * Fee)
    let indep = spend([f.cb[2].op], 5_000_000_000 - Fee)
    let twoIn = spend([f.cb[3].op, f.cb[4].op], 10_000_000_000 - Fee)
    for t in [a, child, indep, twoIn]:
      check f.mp.acceptTransaction(t, f.crypto).isOk
    let blk = blockOf(f.tip, 111, @[coinbaseTx(111), a, child, indep, twoIn])
    check f.cs.connectBlock(blk, 111).isOk
    check f.mp.entries.len == 0
    check f.mp.currentSize == 64            # txns_randomized keeps one slot
    f.teardown()

  test "a child that outbids its parent merges chunks and saves one node":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let rich = spend([a.op], 5_000_000_000 - Fee - 5_000_000)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.acceptTransaction(rich, f.crypto).isOk
    check f.mp.currentSize == 952 + 1056 - 64
    f.teardown()

suite "-maxmempool is compared against usage, not serialized bytes":
  test "a pool over budget trims its worst tx and bumps the rolling floor":
    # 2500 holds the parent/child pair (2008) but not a third tx (2976).
    var f = setup(maxSize = 2_500)
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    let child = spend([a.op], 5_000_000_000 - 2 * Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.acceptTransaction(child, f.crypto).isOk
    # 85 vbytes at 1000 sat: 11764 sat/kvB (integer division), plus the
    # 100 sat/kvB incremental relay fee Core adds in TrimToSize.
    let poor = spend([f.cb[2].op], 5_000_000_000 - 1_000)
    let res = f.mp.acceptTransaction(poor, f.crypto)
    check not res.isOk
    check res.error == "mempool full"
    check f.mp.entries.len == 2
    check f.mp.rollingMinimumFeeRate == 11_864.0
    f.teardown()

  test "the default budget does not trim a pool that fits":
    var f = setup()
    let a = spend([f.cb[1].op], 5_000_000_000 - Fee)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.rollingMinimumFeeRate == 0.0
    check f.mp.maxSize == 5_000_000
    f.teardown()
