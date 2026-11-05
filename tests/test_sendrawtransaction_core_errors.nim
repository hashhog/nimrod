## sendrawtransaction error messages and codes must match Core.
##
## Found by the Core regtest ratchet (nimrod operator group):
##   operator/sendrawtransaction/confirmed:message
##     core "Transaction outputs already in utxo set"
##   operator/sendrawtransaction/missing-inputs:message
##     core "bad-txns-inputs-missingorspent"
##   operator/sendrawtransaction/bad-maxfeerate:{code,message}
##     core -3 "Invalid amount" (AmountFromValue), nimrod -32602
##
## Core: node/transaction.cpp BroadcastTransaction (ALREADY_IN_UTXO_SET,
## MISSING_INPUTS -> RPC_TRANSACTION_ERROR with the bare reject token) and
## rpc/rawtransaction.cpp sendrawtransaction (ParseFeeRate -> AmountFromValue).

import unittest2
import std/[json, os, tempfiles, strutils]
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


template rpcErr(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error - call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

suite "sendrawtransaction matches Core errors":
  test "confirmed tx: -27 with Core's message":
    var f = setup()
    defer: f.teardown()
    let t = build(@[op(f.cb[1])], Subsidy, 20_000, 0, p2shTrue())
    var tip = BlockHash(default(array[32, byte]))
    for h in 0 .. 110:
      tip = BlockHash(doubleSha256(serialize(
        blockOf(tip, int32(h), @[f.cb[h]]).header)))
    let blk = blockOf(tip, 111, @[coinbaseTx(111), t])
    doAssert f.rpc.chainState.connectBlock(blk, 111).isOk
    let e = rpcErr(f.rpc.handleMethod("sendrawtransaction", %*[hexOf(t)]))
    check e.code == -27
    check e.msg == "Transaction outputs already in utxo set"

  test "missing inputs: -25 with the bare bad-txns-inputs-missingorspent":
    var f = setup()
    defer: f.teardown()
    let ghost = Transaction(version: 2,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 7),
                     scriptSig: @[byte(0x01), byte(OP_TRUE)], sequence: RbfSeq)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: p2shTrue())],
      witnesses: @[], lockTime: 0)
    let e = rpcErr(f.rpc.handleMethod("sendrawtransaction", %*[hexOf(ghost)]))
    check e.code == -25
    check e.msg == "bad-txns-inputs-missingorspent"

  test "non-numeric maxfeerate: -3 Invalid amount":
    var f = setup()
    defer: f.teardown()
    let t = build(@[op(f.cb[1])], Subsidy, 20_000, 0, p2shTrue())
    let e = rpcErr(f.rpc.handleMethod("sendrawtransaction", %*[hexOf(t), "x"]))
    check e.code == -3
    check e.msg == "Invalid amount"

  test "a valid tx is still accepted":
    var f = setup()
    defer: f.teardown()
    let t = build(@[op(f.cb[1])], Subsidy, 20_000, 0, p2shTrue())
    let r = f.rpc.handleMethod("sendrawtransaction", %*[hexOf(t), 0])
    check r.getStr() == idHex(t)
