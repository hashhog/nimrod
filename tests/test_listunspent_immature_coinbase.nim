## listunspent must NOT list immature coinbase outputs by default.
##
## BUG (Core v31.1 regtest differential, wallet group): after mining 101
## blocks to a wallet address Core's listunspent returns ONE coin (the
## height-1 coinbase, 101 confirmations) while nimrod returned 101 — the
## mature coin plus 100 immature coinbases flagged spendable:false/safe:false.
##
## Core:
##   - src/wallet/spend.cpp:357  AvailableCoins `continue`s past a coin when
##     `wallet.IsTxImmatureCoinBase(wtx) && !params.include_immature_coinbase`.
##   - src/wallet/spend.h:86     CoinFilterParams::include_immature_coinbase
##     defaults to false.
##   - src/wallet/rpc/coins.cpp:567,583-585  listunspent's query_options
##     accepts `include_immature_coinbase` (type-checked bool).
##   - src/wallet/rpc/coins.cpp:675  every listed coin reports spendable:true.
##   - src/wallet/wallet.cpp:3333-3351  a coinbase is immature while it has
##     fewer than COINBASE_MATURITY+1 (101) confirmations.
##
## Behaviour pins: exact counts, confirmations and flags, not error absence.

import unittest2
import std/[json, os, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/wallet
import ../src/crypto/address

let TestDbPath = getTempDir() / "nimrod_listunspent_immature_cb_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc fixedTxid(tag: int): TxId =
  var b: array[32, byte]
  b[0] = byte(tag and 0xff)
  b[1] = byte((tag shr 8) and 0xff)
  b[31] = 0xC5
  TxId(b)

const Tip = 101'i32

proc makeRpc(): RpcServer =
  ## Regtest wallet that has "mined" blocks 1..101 to its own address (one
  ## 50 BTC coinbase per block) and received one ordinary payment at the tip.
  cleanupTestDb()
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  result = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)
  var seed: array[64, byte]
  for i in 0 ..< 64:
    seed[i] = byte(i)
  var w = newWalletFromSeed(seed, params)
  w.addAccount(84, 0, 20)
  result.wallet = w
  let a1 = result.wallet.getNewAddressStr(P2WPKH)
  let spk = scriptPubKeyForAddress(decodeAddress(a1))
  for h in 1'i32 .. Tip:
    result.wallet.addUtxo(OutPoint(txid: fixedTxid(int(h)), vout: 0'u32),
                          TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: spk),
                          height = h, keyPath = "m/84'/1'/0'/0/0",
                          isInternal = false, isCoinbase = true)
  # One ordinary (non-coinbase) payment confirmed in the tip block.
  result.wallet.addUtxo(OutPoint(txid: fixedTxid(0x7777), vout: 1'u32),
                        TxOut(value: Satoshi(100_000_000'i64), scriptPubKey: spk),
                        height = Tip, keyPath = "m/84'/1'/0'/0/0",
                        isInternal = false, isCoinbase = false)
  result.chainState.bestHeight = Tip

proc teardown(rpc: RpcServer) =
  rpc.chainState.close()
  cleanupTestDb()

suite "listunspent immature coinbase (Core spend.cpp:357)":

  test "default listunspent skips the 100 immature coinbases":
    let rpc = makeRpc()
    let res = rpc.handleMethod("listunspent", %*[])
    check res.kind == JArray
    # height-1 coinbase (101 confs, mature) + the ordinary payment (1 conf)
    check res.len == 2
    var coinbaseConfs: seq[int] = @[]
    for e in res:
      check e["spendable"].getBool() == true
      check e["solvable"].getBool() == true
      check e["safe"].getBool() == true
      if e["amount"].getFloat() == 50.0:
        coinbaseConfs.add(e["confirmations"].getInt())
    check coinbaseConfs == @[101]
    rpc.teardown()

  test "minconf 101 lists exactly the one mature coinbase":
    let rpc = makeRpc()
    let res = rpc.handleMethod("listunspent", %*[101])
    check res.len == 1
    if res.len == 1:
      check res[0]["confirmations"].getInt() == 101
      check res[0]["spendable"].getBool() == true
      check res[0]["safe"].getBool() == true
    rpc.teardown()

  test "query_options.include_immature_coinbase=true lists them, spendable/safe true":
    let rpc = makeRpc()
    let res = rpc.handleMethod("listunspent",
      %*[1, 9999999, newJArray(), true, {"include_immature_coinbase": true}])
    check res.len == 102
    for e in res:
      check e["spendable"].getBool() == true
      check e["safe"].getBool() == true
    rpc.teardown()

  test "query_options.include_immature_coinbase=false is the default":
    let rpc = makeRpc()
    let res = rpc.handleMethod("listunspent",
      %*[1, 9999999, newJArray(), true, {"include_immature_coinbase": false}])
    check res.len == 2
    rpc.teardown()

  test "non-bool include_immature_coinbase is RPC_TYPE_ERROR (-3)":
    let rpc = makeRpc()
    var code = 0
    var msg = ""
    try:
      discard rpc.handleMethod("listunspent",
        %*[1, 9999999, newJArray(), true, {"include_immature_coinbase": "yes"}])
    except RpcError as e:
      code = e.code
      msg = e.msg
    check code == -3
    check "include_immature_coinbase" in msg
    rpc.teardown()

when isMainModule:
  discard
