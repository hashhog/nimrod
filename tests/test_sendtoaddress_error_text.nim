## sendtoaddress error messages read like Core's.
##
## Core v31.1 regtest differential, wallet group (rows
## `wallet/error/insufficient:message` and `wallet/error/bad-address:message`):
##
##   sendtoaddress <own addr> 1000   Core: -6 "Insufficient funds"
##                                   nimrod: -6 "insufficient funds"
##   sendtoaddress notanaddress 1    Core: -5 "Invalid Bitcoin address: notanaddress"
##                                   nimrod: -5 "invalid address: base58 decode error: ..."
##
## Core:
##   - wallet/spend.cpp:1214-1234 CreateTransactionInternal: when SelectCoins
##     gives no specific error the spend fails with the general
##     "Insufficient funds" (also when the wallet has no coin at all).
##   - wallet/rpc/spend.cpp:187 SendMoney raises it as
##     RPC_WALLET_INSUFFICIENT_FUNDS (-6).
##   - rpc/rawtransaction_util.cpp:117-122 ParseOutputs: an undecodable
##     destination is RPC_INVALID_ADDRESS_OR_KEY (-5)
##     "Invalid Bitcoin address: " + the string the caller passed.
##
## Pins exact code AND exact message; a control shows a valid address gets
## past the address check.

import unittest2
import std/[json, os]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/wallet
import ../src/crypto/address

let TestDbPath = getTempDir() / "nimrod_sendtoaddress_error_text_test"

proc fixedTxid(tag: int): TxId =
  var b: array[32, byte]
  b[0] = byte(tag and 0xff)
  b[31] = 0x5E
  TxId(b)

proc makeRpc(fund: bool): (RpcServer, string) =
  ## Regtest wallet; with `fund` it holds one mature 1 BTC coin.
  if dirExists(TestDbPath):
    removeDir(TestDbPath)
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  var rpc = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)
  var seed: array[64, byte]
  for i in 0 ..< 64:
    seed[i] = byte(i + 7)
  var w = newWalletFromSeed(seed, params)
  w.addAccount(84, 0, 20)
  rpc.wallet = w
  rpc.fallbackFeeRate = 20.0
  let a1 = rpc.wallet.getNewAddressStr(P2WPKH)
  if fund:
    let spk = scriptPubKeyForAddress(decodeAddress(a1))
    rpc.wallet.addUtxo(OutPoint(txid: fixedTxid(1), vout: 0'u32),
                       TxOut(value: Satoshi(100_000_000'i64), scriptPubKey: spk),
                       height = 1, keyPath = "m/84'/1'/0'/0/0",
                       isInternal = false, isCoinbase = false)
  rpc.chainState.bestHeight = 10
  (rpc, a1)

proc teardown(rpc: RpcServer) =
  rpc.chainState.close()
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc rpcErr(rpc: RpcServer, params: JsonNode): (int, string) =
  try:
    discard rpc.handleMethod("sendtoaddress", params)
    (0, "")
  except RpcError as e:
    (e.code, e.msg)

suite "sendtoaddress error text (Core spend.cpp / rawtransaction_util.cpp)":

  test "underfunded send is -6 'Insufficient funds'":
    let (rpc, a1) = makeRpc(fund = true)
    let (code, msg) = rpc.rpcErr(%*[a1, 1000])
    check code == -6
    check msg == "Insufficient funds"
    rpc.teardown()

  test "send from a wallet with no coins is -6 'Insufficient funds'":
    let (rpc, a1) = makeRpc(fund = false)
    let (code, msg) = rpc.rpcErr(%*[a1, 1])
    check code == -6
    check msg == "Insufficient funds"
    rpc.teardown()

  test "undecodable address is -5 'Invalid Bitcoin address: <address>'":
    let (rpc, _) = makeRpc(fund = true)
    let (code, msg) = rpc.rpcErr(%*["notanaddress", 1])
    check code == -5
    check msg == "Invalid Bitcoin address: notanaddress"
    rpc.teardown()

  test "control: a valid regtest address gets past the address check":
    # Same call shape as the bad-address case, only the address differs:
    # it must reach coin selection (-6), so -5 above is the address check.
    let (rpc, a1) = makeRpc(fund = true)
    let (code, _) = rpc.rpcErr(%*[a1, 1000])
    check code != -5
    check code == -6
    rpc.teardown()
