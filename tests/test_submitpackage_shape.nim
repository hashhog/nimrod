## submitpackage / testmempoolaccept result shape against Bitcoin Core v31.1
## (rpc/mempool.cpp), as seen by tools/core-regtest groups `package` and
## `seed_submitpackage`:
##   - fees.effective-feerate is BTC/kvB (ValueFromAmount(GetFeePerK)), not sat/vB
##   - fees.effective-includes lists the wtxids behind that feerate
##   - submitpackage tx-results are keyed by wtxid and carry txid plus ONE of
##     other-wtxid / error / (vsize + fees) -- no `allowed`, no `wtxid`
##   - a member that passes on its own stays in the pool when a later member fails
##
## Command:  nim c -r tests/test_submitpackage_shape.nim

import unittest2
import std/[json, os, tables, tempfiles, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/mining/fees

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

proc spend(prev: OutPoint, value: int64): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[byte(0x01), byte(OP_TRUE)],
                   sequence: 0xFFFFFFFD'u32)],
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

type Fx = object
  dir: string
  rpc: RpcServer
  cb: seq[Transaction]

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_submitpackage_shape_", "")
  var cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  let mp = newMempool(cs, params)
  result.rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = params)

proc teardown(f: var Fx) =
  f.rpc.chainState.close()
  removeDir(f.dir)

proc op(tx: Transaction, vout = 0'u32): OutPoint =
  OutPoint(txid: tx.txid(), vout: vout)

proc hexBytes(data: openArray[byte]): string =
  for b in data: result.add(toHex(int(b), 2).toLowerAscii())

proc revHex(h: array[32, byte]): string =
  var r = h
  for i in 0 ..< 16: swap(r[i], r[31 - i])
  hexBytes(r)

proc hexOf(tx: Transaction): string = hexBytes(serialize(tx, true))
proc txidHex(tx: Transaction): string = revHex(array[32, byte](tx.txid()))
proc wtxidHex(tx: Transaction): string = revHex(array[32, byte](tx.wtxid()))

const Coin = 5_000_000_000'i64

suite "testmempoolaccept effective-feerate is BTC/kvB":
  test "single tx: fee 5000 sat, effective-feerate is GetFeePerK in BTC":
    var f = setup()
    let tx = spend(f.cb[1].op, Coin - 5_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(tx)]])
    check r[0]["allowed"].getBool()
    let vsize = r[0]["vsize"].getInt()
    let expected = float64(5_000 * 1000 div vsize) / 100_000_000.0
    check abs(r[0]["fees"]["effective-feerate"].getFloat() - expected) < 1e-12
    check r[0]["fees"]["effective-includes"][0].getStr() == wtxidHex(tx)
    f.teardown()

  test "package: each member is judged alone, effective-includes is itself":
    var f = setup()
    let a = spend(f.cb[1].op, Coin - 5_000)
    let b = spend(a.op, Coin - 5_000 - 6_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(a), hexOf(b)]])
    check r[0]["allowed"].getBool()
    check r[1]["allowed"].getBool()
    check r[1]["fees"]["effective-includes"].len == 1
    check r[1]["fees"]["effective-includes"][0].getStr() == wtxidHex(b)
    check r[1]["fees"]["effective-feerate"].getFloat() < 1.0   # BTC/kvB, not sat/vB
    check f.rpc.mempool.entries.len == 0                       # rolled back
    f.teardown()

  test "package: a below-relay parent stops the run (no CPFP in test accept)":
    var f = setup()
    let a = spend(f.cb[1].op, Coin - 1)
    let b = spend(a.op, Coin - 1 - 20_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(a), hexOf(b)]])
    check not r[0]["allowed"].getBool()
    check r[0]["reject-reason"].getStr() == "min relay fee not met"
    check not r[1].hasKey("allowed")
    check r[1]["txid"].getStr() == txidHex(b)
    f.teardown()

suite "submitpackage result shape (Core rpc/mempool.cpp)":
  test "CPFP: keyed by wtxid, package effective-feerate in BTC/kvB, includes both":
    var f = setup()
    let parent = spend(f.cb[1].op, Coin - 1)
    let child = spend(parent.op, Coin - 1 - 20_000)
    let r = f.rpc.handleMethod("submitpackage", %*[[hexOf(parent), hexOf(child)]])
    check r["package_msg"].getStr() == "success"
    for tx in [parent, child]:
      let e = r["tx-results"][wtxidHex(tx)]
      check e["txid"].getStr() == txidHex(tx)
      check not e.hasKey("allowed")
      check not e.hasKey("wtxid")
      check e.hasKey("vsize")
      check e["fees"]["effective-includes"].len == 2
      check e["fees"]["effective-includes"][0].getStr() == wtxidHex(parent)
      check e["fees"]["effective-includes"][1].getStr() == wtxidHex(child)
    let totalVsize = r["tx-results"][wtxidHex(parent)]["vsize"].getInt() +
                     r["tx-results"][wtxidHex(child)]["vsize"].getInt()
    let expected = float64((20_001 * 1000) div totalVsize) / 100_000_000.0
    check abs(r["tx-results"][wtxidHex(child)]["fees"]["effective-feerate"].getFloat() -
              expected) < 1e-12
    f.teardown()

  test "a missing-input child gets `error`; its parent stays, with its own feerate":
    var f = setup()
    let parent = spend(f.cb[1].op, Coin - 5_000)
    var ghost: array[32, byte]
    ghost[0] = 0x22
    var child = spend(parent.op, 1_000)
    child.inputs.add(TxIn(prevOut: OutPoint(txid: TxId(ghost), vout: 0),
                          scriptSig: @[byte(0x01), byte(OP_TRUE)],
                          sequence: 0xFFFFFFFD'u32))
    let r = f.rpc.handleMethod("submitpackage", %*[[hexOf(parent), hexOf(child)]])
    check r["package_msg"].getStr() == "transaction failed"
    let c = r["tx-results"][wtxidHex(child)]
    check c["error"].getStr() == "bad-txns-inputs-missingorspent"
    check not c.hasKey("vsize")
    check not c.hasKey("allowed")
    let p = r["tx-results"][wtxidHex(parent)]
    check p["fees"]["effective-includes"].len == 1
    check p["fees"]["effective-includes"][0].getStr() == wtxidHex(parent)
    check parent.txid() in f.rpc.mempool.entries
    f.teardown()
