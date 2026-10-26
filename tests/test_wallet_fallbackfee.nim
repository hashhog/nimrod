## Wallet spends with no fee estimate: -fallbackfee or an error, like Core.
##
## Reference: bitcoin-core/src/wallet/fees.cpp GetMinimumFeeRate and
## wallet/spend.cpp CreateTransactionInternal. With no estimate and
## -fallbackfee unset (Core's default is 0, which disables it) the spend
## fails with RPC_WALLET_INSUFFICIENT_FUNDS (-6):
##   "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or
##    enable -fallbackfee."
## With -fallbackfee=0.0002 (20 sat/vB, what Core's regtest tests pass) the
## spend goes through at that rate.
##
## Covers every wallet spend RPC that used to fall back to a hard-coded
## 10 sat/vB: sendtoaddress, send, fundrawtransaction, walletcreatefundedpsbt.
##
## Run:
##   nim c -r tests/test_wallet_fallbackfee.nim

import std/[json, options, os, strutils, tempfiles]
import unittest2

import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager]
import ../src/crypto/address

const
  Dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
  Disabled = "Fee estimation failed. Fallbackfee is disabled. " &
             "Wait a few blocks or enable -fallbackfee."

proc primeWalletWithUtxo(w: var Wallet, cs: var ChainState, value: Satoshi) =
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var txidBytes: array[32, byte]
  for i in 0 ..< 32: txidBytes[i] = byte((i + 7) and 0xff)
  let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
  let output = TxOut(value: value, scriptPubKey: spk)
  cs.putUtxoCache(op, UtxoEntry(output: output, height: 100, isCoinbase: false))
  w.addUtxo(op, output, height = 100, keyPath = key.path,
            isInternal = false, isCoinbase = false)

proc rawHexNoInputs(): string =
  let spk = scriptPubKeyForAddress(decodeAddress(Dest))
  let tx = Transaction(version: 2'i32, inputs: @[],
                       outputs: @[TxOut(value: Satoshi(10_000_000), scriptPubKey: spk)],
                       witnesses: @[], lockTime: 0'u32)
  var hex = ""
  for b in serialize(tx, includeWitness = false):
    hex.add(toHex(int(b), 2).toLowerAscii)
  hex

proc errOf(rpc: RpcServer, m: string, p: JsonNode): ref RpcError =
  try:
    discard rpc.handleMethod(m, p)
  except RpcError as e:
    return e
  nil

suite "wallet spends without a fee estimate (Core -fallbackfee)":
  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_fallbackfee_", "_regtest")
    cs = newChainState(tempDir, cparams)
    if cs.bestHeight < 0:
      let res = cs.connectBlock(buildGenesisBlock(cparams), 0)
      doAssert res.isOk, "Failed to connect genesis"
    let mp = newMempool(cs, cparams)
    rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = newFeeEstimator(), params = cparams)
    wm = newWalletManager(tempDir, cparams, cs)
    rpc.walletManager = wm
    discard rpc.handleMethod("createwallet", %*["fb"])
    var w = wm.getWallet("fb").get().wallet
    primeWalletWithUtxo(w, cs, Satoshi(100_000_000))

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  test "sendtoaddress without -fallbackfee fails like Core":
    let e = rpc.errOf("sendtoaddress", %*[Dest, 0.1])
    check e != nil
    if e != nil:
      check e.code == -6
      check e.msg == Disabled
    check rpc.mempool.count == 0

  test "sendtoaddress with -fallbackfee=0.0002 pays 20 sat/vB":
    rpc.fallbackFeeRate = 20.0
    let r = rpc.handleMethod("sendtoaddress", %*[Dest, 0.1])
    check r.kind == JString
    check r.getStr().len == 64
    check rpc.mempool.count == 1

  test "send without -fallbackfee fails like Core":
    let e = rpc.errOf("send", %*[{Dest: 0.1}])
    check e != nil
    if e != nil:
      check e.code == -6
      check e.msg == Disabled

  test "send with -fallbackfee succeeds":
    rpc.fallbackFeeRate = 20.0
    let r = rpc.handleMethod("send", %*[{Dest: 0.1}])
    check r.kind == JObject
    check r["complete"].getBool()

  test "fundrawtransaction without -fallbackfee fails like Core":
    let e = rpc.errOf("fundrawtransaction", %*[rawHexNoInputs()])
    check e != nil
    if e != nil:
      check e.code == -6
      check e.msg == Disabled

  test "fundrawtransaction with -fallbackfee succeeds":
    rpc.fallbackFeeRate = 20.0
    let r = rpc.handleMethod("fundrawtransaction", %*[rawHexNoInputs()])
    check r["fee"].getFloat() > 0.0

  test "walletcreatefundedpsbt without -fallbackfee fails like Core":
    let e = rpc.errOf("walletcreatefundedpsbt", %*[[], [{Dest: 0.1}]])
    check e != nil
    if e != nil:
      check e.code == -6
      check e.msg == Disabled

  test "walletcreatefundedpsbt with -fallbackfee succeeds":
    rpc.fallbackFeeRate = 20.0
    let r = rpc.handleMethod("walletcreatefundedpsbt", %*[[], [{Dest: 0.1}]])
    check r.hasKey("psbt")

  test "an explicit fee rate needs no -fallbackfee":
    let r = rpc.handleMethod("fundrawtransaction",
      %*[rawHexNoInputs(), {"fee_rate": 5}])
    check r["fee"].getFloat() > 0.0
