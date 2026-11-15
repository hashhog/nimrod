## CheckFeeRate reject details against Bitcoin Core v31.1.
##
## Core's MemPoolAccept::CheckFeeRate (validation.cpp:699-712) rejects with
##   state.Invalid(TX_RECONSIDERABLE, "mempool min fee not met", "%d < %d")
##   state.Invalid(TX_RECONSIDERABLE, "min relay fee not met",   "%d < %d")
## where the numbers are the tx's modified fee and the floor's
## CFeeRate::GetFee(vsize) (rounded up, policy/feerate.cpp:20).
## state.ToString() is "<token>, <fee> < <required>"; testmempoolaccept puts it
## in reject-details (rpc/mempool.cpp:399-403) and sendrawtransaction in the
## error message.  Core v31.1 regtest row:
##   seed_submitpackage/valid-cpfp/accept:[0].reject-details
##   Core "min relay fee not met, 1 < 11", nimrod <missing>.
##
## Command:  nim c -r tests/test_min_relay_fee_reject_details.nim

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
  result.dir = createTempDir("nimrod_min_relay_fee_details_", "")
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

proc vsizeOf(tx: Transaction): int64 = int64((calculateWeight(tx) + 3) div 4)

proc requiredFee(perK, vsize: int64): int64 =
  ## CFeeRate::GetFee: EvaluateFeeUp, i.e. ceil(perK * vsize / 1000).
  (perK * vsize + 999) div 1000

suite "CheckFeeRate reject carries Core's '<fee> < <required>' details":
  test "testmempoolaccept package: below-relay parent has reject-details":
    var f = setup()
    let a = spend(f.cb[1].op, Coin - 1)
    let b = spend(a.op, Coin - 1 - 20_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(a), hexOf(b)]])
    check not r[0]["allowed"].getBool()
    check r[0]["reject-reason"].getStr() == "min relay fee not met"
    # Default -minrelaytxfee is 100 sat/kvB (policy/policy.h:70).
    check r[0].hasKey("reject-details")
    check r[0]{"reject-details"}.getStr() ==
      "min relay fee not met, 1 < " & $requiredFee(100, vsizeOf(a))
    f.teardown()

  test "testmempoolaccept single: below-relay tx has reject-details":
    var f = setup()
    let a = spend(f.cb[2].op, Coin - 3)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(a)]])
    check not r[0]["allowed"].getBool()
    check r[0]["reject-reason"].getStr() == "min relay fee not met"
    check r[0]{"reject-details"}.getStr() ==
      "min relay fee not met, 3 < " & $requiredFee(100, vsizeOf(a))
    f.teardown()

  test "acceptTransaction: rolling floor reject reads 'mempool min fee not met, <fee> < <required>'":
    var f = setup()
    # 5000 sat/kvB rolling floor, no block since the bump: GetMinFee() is the
    # raw value (txmempool.cpp:829).
    f.rpc.mempool.rollingMinimumFeeRate = 5000.0
    f.rpc.mempool.blockSinceLastRollingFeeBump = false
    let a = spend(f.cb[3].op, Coin - 100)
    let res = f.rpc.mempool.acceptTransaction(a, f.rpc.crypto)
    check not res.isOk
    check res.error == "mempool min fee not met, 100 < " & $requiredFee(5000, vsizeOf(a))
    f.teardown()

  test "control: a tx paying the floor is allowed":
    var f = setup()
    let a = spend(f.cb[4].op, Coin - 5_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(a)]])
    check r[0]["allowed"].getBool()
    check not r[0].hasKey("reject-details")
    f.teardown()
