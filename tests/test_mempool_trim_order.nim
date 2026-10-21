## When and what the mempool trims to -maxmempool, against Bitcoin Core.
##
## Core (validation.cpp) runs LimitMempoolSize -- Expire, then TrimToSize -- at
## the end of a single-tx accept (MemPoolAccept::Finalize, skipped for package
## members via m_package_submission) and ONCE after a whole package
## (AcceptPackage), after which every package tx that is gone, including one
## that was already in the pool, is reported "mempool full".  TrimToSize
## evicts TxGraph's worst chunk (txgraph.cpp GetWorstMainChunk): the lowest
## chunk feerate, then the larger equal-feerate prefix, then the chunk holding
## the greatest txid.  A chunk can be the low-fee tail of a chain only.
##
## Usage figures are the Core v31.1 numbers pinned in test_mempool_usage.nim:
## a 1-in/1-out spend is an 888-byte entry, a 2-input one 1064, a 3-input one
## 1240; txns_randomized costs 64/96/176 for 1/2/4 slots; a 2-tx cluster adds
## 136, minus 64 when the child outbids its parent (one chunk).
##
## Command:  nim c -r tests/test_mempool_trim_order.nim

import unittest2
import std/[os, tables, tempfiles]
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

proc setup(maxSize: int): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_mempool_trim_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = hashOf(blk)
  result.mp = newMempool(result.cs, params, maxSize = maxSize, minFeeRate = 0.0)
  result.crypto = newCryptoEngine()

proc teardown(f: var Fx) =
  f.cs.close()
  removeDir(f.dir)

proc op(tx: Transaction, vout = 0'u32): OutPoint =
  OutPoint(txid: tx.txid(), vout: vout)

proc txidGreater(a, b: TxId): bool =
  ## Core's fallback order: Txid operator<=>, a memcmp of the stored bytes.
  let x = array[32, byte](a)
  let y = array[32, byte](b)
  for i in 0 ..< 32:
    if x[i] != y[i]: return x[i] > y[i]
  false

const Coin = 5_000_000_000'i64

suite "a package is trimmed once, after every member is in (Core AcceptPackage)":
  test "a low-fee parent bumped by its child survives; the other tx is evicted":
    # X (3 inputs, ~60 sat/vB) alone: 1240 + 64.  X + parent = 2224 > 2100,
    # so trimming after the parent alone evicts the parent (1.2 sat/vB) and
    # the child then has no input.  Core inserts both, P+C is one chunk at
    # ~5900 sat/vB, X is the worst chunk; P+C left = 1848 + 176 = 2024.
    var f = setup(maxSize = 2_100)
    let x = spend([f.cb[1].op, f.cb[2].op, f.cb[3].op], 3 * Coin - 10_000)
    check f.mp.acceptTransaction(x, f.crypto).isOk
    let parent = spend([f.cb[4].op], Coin - 100)
    let child = spend([parent.op], Coin - 100 - 1_000_000)
    let res = f.mp.acceptPackage(@[parent, child], f.crypto)
    check res.valid
    check parent.txid() in f.mp.entries
    check child.txid() in f.mp.entries
    check x.txid() notin f.mp.entries
    check f.mp.currentSize == 2_024
    f.teardown()

  test "a member already in the pool that the final trim evicts is mempool full":
    # Pool: X (100k sat) + P (100 sat).  The package [P, C] adds C (1000 sat),
    # which outbids P, so P+C is one chunk below X and is the worst chunk.
    # Core evicts both and marks both mempool full -- P although it was in the
    # pool before the package.
    var f = setup(maxSize = 2_500)
    let x = spend([f.cb[1].op], Coin - 100_000)
    let parent = spend([f.cb[2].op], Coin - 100)
    let child = spend([parent.op], Coin - 100 - 1_000)
    check f.mp.acceptTransaction(x, f.crypto).isOk
    check f.mp.acceptTransaction(parent, f.crypto).isOk
    let res = f.mp.acceptPackage(@[parent, child], f.crypto)
    check not res.valid
    check res.error == "transaction failed"
    check res.txResults.len == 2
    check not res.txResults[0].allowed
    check res.txResults[0].error == "mempool full"
    check not res.txResults[1].allowed
    check res.txResults[1].error == "mempool full"
    check x.txid() in f.mp.entries
    check parent.txid() notin f.mp.entries
    check child.txid() notin f.mp.entries
    f.teardown()

  test "a package that fits is accepted and nothing is evicted":
    var f = setup(maxSize = 5_000_000)
    let parent = spend([f.cb[1].op], Coin - 100)
    let child = spend([parent.op], Coin - 100 - 1_000_000)
    let res = f.mp.acceptPackage(@[parent, child], f.crypto)
    check res.valid
    check f.mp.entries.len == 2
    check f.mp.rollingMinimumFeeRate == 0.0
    f.teardown()

suite "TrimToSize evicts the worst chunk, not a root plus its descendants":
  test "a high-fee parent keeps its place when only its low-fee child is worst":
    # H 235 sat/vB, its child L 1.2 sat/vB (two chunks in Core), Y 176 sat/vB.
    # H+L as one descendant set is 118 sat/vB < Y, but Core's worst chunk is L.
    var f = setup(maxSize = 2_500)
    let h = spend([f.cb[1].op], Coin - 20_000)
    let l = spend([h.op], Coin - 20_000 - 100)
    let y = spend([f.cb[2].op], Coin - 15_000)
    check f.mp.acceptTransaction(h, f.crypto).isOk
    check f.mp.acceptTransaction(l, f.crypto).isOk
    check f.mp.acceptTransaction(y, f.crypto).isOk
    check h.txid() in f.mp.entries
    check y.txid() in f.mp.entries
    check l.txid() notin f.mp.entries
    # L's chunk: 100 sat over 85 vB = 1176 sat/kvB, plus the 100 incremental.
    check f.mp.rollingMinimumFeeRate == 1_276.0
    f.teardown()

  test "equal-feerate chunks: the one holding the greater txid goes first":
    # A and B pay the same fee and have the same size; C (high fee) pushes the
    # pool over.  Core's chunk index orders the tie by the chunk's maximum txid
    # (fallback order) and evicts the last, i.e. the greater txid.
    var f = setup(maxSize = 2_500)
    let a = spend([f.cb[1].op], Coin - 5_000)
    let b = spend([f.cb[2].op], Coin - 5_000)
    let c = spend([f.cb[3].op], Coin - 50_000)
    check f.mp.acceptTransaction(a, f.crypto).isOk
    check f.mp.acceptTransaction(b, f.crypto).isOk
    check f.mp.acceptTransaction(c, f.crypto).isOk
    let loser = if txidGreater(a.txid(), b.txid()): a else: b
    let keeper = if txidGreater(a.txid(), b.txid()): b else: a
    check loser.txid() notin f.mp.entries
    check keeper.txid() in f.mp.entries
    check c.txid() in f.mp.entries
    f.teardown()

suite "an accept expires before it trims (Core LimitMempoolSize)":
  test "a single-tx accept drops a tx older than -mempoolexpiry":
    var f = setup(maxSize = 5_000_000)
    let t0 = 1_900_000_000'i64
    setMockTime(t0)
    let old = spend([f.cb[1].op], Coin - 10_000)
    check f.mp.acceptTransaction(old, f.crypto).isOk
    setMockTime(t0 + 337 * 3600)
    let fresh = spend([f.cb[2].op], Coin - 10_000)
    check f.mp.acceptTransaction(fresh, f.crypto).isOk
    check old.txid() notin f.mp.entries
    check fresh.txid() in f.mp.entries
    setMockTime(0)
    f.teardown()

  test "a package accept drops a tx older than -mempoolexpiry":
    var f = setup(maxSize = 5_000_000)
    let t0 = 1_900_000_000'i64
    setMockTime(t0)
    let old = spend([f.cb[1].op], Coin - 10_000)
    check f.mp.acceptTransaction(old, f.crypto).isOk
    setMockTime(t0 + 337 * 3600)
    let parent = spend([f.cb[2].op], Coin - 100)
    let child = spend([parent.op], Coin - 100 - 10_000)
    check f.mp.acceptPackage(@[parent, child], f.crypto).valid
    check old.txid() notin f.mp.entries
    check parent.txid() in f.mp.entries
    check child.txid() in f.mp.entries
    setMockTime(0)
    f.teardown()

  test "a tx younger than -mempoolexpiry stays":
    var f = setup(maxSize = 5_000_000)
    let t0 = 1_900_000_000'i64
    setMockTime(t0)
    let old = spend([f.cb[1].op], Coin - 10_000)
    check f.mp.acceptTransaction(old, f.crypto).isOk
    setMockTime(t0 + 335 * 3600)
    let fresh = spend([f.cb[2].op], Coin - 10_000)
    check f.mp.acceptTransaction(fresh, f.crypto).isOk
    check old.txid() in f.mp.entries
    setMockTime(0)
    f.teardown()
