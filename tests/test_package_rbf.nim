## Package RBF in submitpackage, against Bitcoin Core v31.1
## (validation.cpp MemPoolAccept::PackageRBFChecks, policy/rbf.cpp):
##   - a 1-parent-1-child package whose parent conflicts with the pool may
##     replace the conflicts on the package's combined fees
##   - the replaced txids come back in `replaced-transactions` (std::set order)
##   - rejects carry Core's package_msg: "package RBF failed: ..." /
##     "too-large-cluster", and leave the conflicts in the pool
##   - the post-replacement cluster is sized by sigop-adjusted weight
##     (core-regtest group package_rbf: `over` / `at-limit`)
##   - testmempoolaccept never evicts anything
##
## Command:  nim c -r tests/test_package_rbf.nim

import unittest2
import std/[json, os, tempfiles, algorithm, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/mining/fees

const
  RbfSeq = 0xFFFFFFFD'u32
  OutputSats = 1_000'i64
  Subsidy = 5_000_000_000'i64
  # secp256k1 generator, compressed (harness GENERATOR_COMPRESSED)
  Generator = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc bareMultisig(): seq[byte] =
  ## OP_1 <pubkey> OP_1 OP_CHECKMULTISIG: 20 legacy sigops (cost 80).
  var pk: seq[byte]
  for i in countup(0, Generator.len - 2, 2):
    pk.add byte(parseHexInt(Generator[i .. i + 1]))
  @[byte(0x51), 0x21] & pk & @[byte(0x51), 0xae]

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), 0]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(Subsidy), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

proc op(tx: Transaction, vout = 0'u32): OutPoint =
  OutPoint(txid: tx.txid(), vout: vout)

proc build(inputs: seq[OutPoint], inValue, fee: int64, extra: int,
           extraSpk: seq[byte], scriptSig = @[byte(0x01), byte(OP_TRUE)]): Transaction =
  ## Change output first (value = inValue - fee - extras), then `extra`
  ## 1,000-sat outputs to `extraSpk`.
  var ins: seq[TxIn]
  for p in inputs:
    ins.add TxIn(prevOut: p, scriptSig: scriptSig, sequence: RbfSeq)
  var outs = @[TxOut(value: Satoshi(inValue - fee - int64(extra) * OutputSats),
                     scriptPubKey: p2shTrue())]
  for _ in 0 ..< extra:
    outs.add TxOut(value: Satoshi(OutputSats), scriptPubKey: extraSpk)
  Transaction(version: 2, inputs: ins, outputs: outs, witnesses: @[], lockTime: 0)

proc changeOf(tx: Transaction): int64 = int64(tx.outputs[0].value)

type Fx = object
  dir: string
  rpc: RpcServer
  cb: seq[Transaction]

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_package_rbf_", "")
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

proc hexBytes(data: openArray[byte]): string =
  for b in data: result.add(toHex(int(b), 2).toLowerAscii())

proc revHex(h: array[32, byte]): string =
  var r = h
  for i in 0 ..< 16: swap(r[i], r[31 - i])
  hexBytes(r)

proc hexOf(tx: Transaction): string = hexBytes(serialize(tx, true))
proc idHex(tx: Transaction): string = revHex(array[32, byte](tx.txid()))

proc send(f: Fx, tx: Transaction) =
  let res = f.rpc.mempool.acceptTransaction(tx, f.rpc.crypto)
  doAssert res.isOk, "setup tx refused: " & res.error

proc submit(f: Fx, txs: seq[Transaction]): JsonNode =
  var arr = newJArray()
  for t in txs: arr.add(%hexOf(t))
  f.rpc.handleMethod("submitpackage", %*[arr])

proc inPool(f: Fx, tx: Transaction): bool = f.rpc.mempool.contains(tx.txid())

proc replacedOf(j: JsonNode): seq[string] =
  if j.hasKey("replaced-transactions"):
    for r in j["replaced-transactions"]: result.add r.getStr()

proc coreSetOrder(txs: seq[Transaction]): seq[string] =
  ## std::set<Txid> order: memcmp over the internal (little-endian) bytes.
  var ids: seq[array[32, byte]]
  for t in txs: ids.add array[32, byte](t.txid())
  ids.sort(proc(a, b: array[32, byte]): int =
    for i in 0 ..< 32:
      if a[i] != b[i]: return cmp(a[i], b[i])
    0)
  for i in ids: result.add revHex(i)

proc conflictPair(f: Fx, height: int): (Transaction, Transaction) =
  ## The harness scenario's O (wide, cheap, signals) and its descendant D.
  let o = build(@[op(f.cb[height])], Subsidy, 20_000, 600, p2shTrue())
  let d = build(@[op(o)], changeOf(o), 1_000, 0, p2shTrue())
  (o, d)

suite "package RBF (Core PackageRBFChecks)":
  test "at-limit: 1p1c replaces O and D; replaced-transactions in set order":
    # core-regtest package_rbf/at-limit: 126 + 126 bare multisig outputs,
    # 403,200 sigop-adjusted weight -- under the 404,000 cluster limit.
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(2)
    f.send(o); f.send(d)
    let p = build(@[op(f.cb[2])], Subsidy, 6_000, 126, bareMultisig())
    let c = build(@[op(p)], changeOf(p), 200_000, 126, bareMultisig())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() == "success"
    check replacedOf(j) == coreSetOrder(@[o, d])
    check f.inPool(p)
    check f.inPool(c)
    check not f.inPool(o)
    check not f.inPool(d)

  test "over: sigop-adjusted cluster over the limit is too-large-cluster, O and D stay":
    # package_rbf/over: 127 + 126 outputs, 404,800 adjusted weight (raw ~47k).
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(1)
    f.send(o); f.send(d)
    let p = build(@[op(f.cb[1])], Subsidy, 6_000, 127, bareMultisig())
    let c = build(@[op(p)], changeOf(p), 200_000, 126, bareMultisig())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() == "too-large-cluster"
    check replacedOf(j).len == 0
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p)
    check not f.inPool(c)

  test "package fees below the conflicts: insufficient anti-DoS fees, attributed to the child":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(3)
    f.send(o); f.send(d)
    let p = build(@[op(f.cb[3])], Subsidy, 6_000, 0, p2shTrue())
    let c = build(@[op(p)], changeOf(p), 10_000, 0, p2shTrue())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() ==
      "package RBF failed: insufficient anti-DoS fees, rejecting replacement " &
      idHex(c) & ", less fees than conflicting txs; 0.00016 < 0.00021"
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p)

  test "child feerate not above parent: package feerate is less than or equal to parent feerate":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(4)
    f.send(o); f.send(d)
    # P alone fails rule 3 (15,000 < 21,000); P+C pays 22,000 but C is the
    # lower-feerate half, so the package is not a chunk of its own.
    let p = build(@[op(f.cb[4])], Subsidy, 15_000, 0, p2shTrue())
    let c = build(@[op(p)], changeOf(p), 7_000, 1, p2shTrue())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr().startsWith(
      "package RBF failed: package feerate is less than or equal to parent feerate, package feerate ")
    check " BTC/kvB <= parent feerate is " in j["package_msg"].getStr()
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p)

  test "a parent with a mempool ancestor: new transaction cannot have mempool ancestors":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(5)
    let m = build(@[op(f.cb[6])], Subsidy, 5_000, 0, p2shTrue())
    f.send(o); f.send(d); f.send(m)
    let p = build(@[op(f.cb[5]), op(m)], Subsidy + changeOf(m), 6_000, 0, p2shTrue())
    let c = build(@[op(p)], changeOf(p), 200_000, 0, p2shTrue())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() ==
      "package RBF failed: new transaction cannot have mempool ancestors"
    check f.inPool(o)
    check f.inPool(d)
    check f.inPool(m)
    check not f.inPool(p)

  test "two parents and a child: package must be 1-parent-1-child":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(7)
    f.send(o); f.send(d)
    let p1 = build(@[op(f.cb[7])], Subsidy, 6_000, 0, p2shTrue())
    let p2 = build(@[op(f.cb[8])], Subsidy, 0, 0, p2shTrue())   # below min relay alone
    let c = build(@[op(p1), op(p2)], changeOf(p1) + changeOf(p2), 200_000, 0, p2shTrue())
    let j = f.submit(@[p1, p2, c])
    check j["package_msg"].getStr() ==
      "package RBF failed: package must be 1-parent-1-child"
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p1)
    check not f.inPool(p2)

  test "more fees but a worse chunk: package RBF does not improve feerate diagram":
    var f = setup()
    defer: f.teardown()
    # O: small and high-feerate (21,000 sat at ~100 vB).  P: ~10 kvB paying
    # 1,100 sat; C: small, 22,000.  The package outpays O but its single
    # chunk (~2.3 sat/vB) is far below O's.
    let o = build(@[op(f.cb[9])], Subsidy, 21_000, 0, p2shTrue())
    f.send(o)
    let p = build(@[op(f.cb[9])], Subsidy, 1_100, 300, p2shTrue())
    let c = build(@[op(p)], changeOf(p), 22_000, 0, p2shTrue())
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() ==
      "package RBF failed: insufficient feerate: does not improve feerate diagram"
    check f.inPool(o)
    check not f.inPool(p)
    check not f.inPool(c)

  test "a member failing after the package RBF checks puts O and D back":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(10)
    f.send(o); f.send(d)
    let p = build(@[op(f.cb[10])], Subsidy, 6_000, 0, p2shTrue())
    # C's scriptSig pushes OP_2 as the redeem script: P2SH hash mismatch, so
    # it fails only at the script checks, after the conflicts were staged.
    let c = build(@[op(p)], changeOf(p), 200_000, 0, p2shTrue(),
                  scriptSig = @[byte(0x01), byte(0x52)])
    let j = f.submit(@[p, c])
    check j["package_msg"].getStr() != "success"
    check replacedOf(j).len == 0
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p)
    check not f.inPool(c)

  test "testmempoolaccept of a replacing package leaves the conflicts in the pool":
    var f = setup()
    defer: f.teardown()
    let (o, d) = f.conflictPair(11)
    f.send(o); f.send(d)
    let p = build(@[op(f.cb[11])], Subsidy, 6_000, 0, p2shTrue())
    let c = build(@[op(p)], changeOf(p), 200_000, 0, p2shTrue())
    let j = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(p), hexOf(c)]])
    check j.kind == JArray
    check f.inPool(o)
    check f.inPool(d)
    check not f.inPool(p)
    check not f.inPool(c)
