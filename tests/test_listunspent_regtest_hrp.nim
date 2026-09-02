## listunspent / listtransactions must use the REGTEST bech32 HRP ("bcrt").
##
## BUG (nightly IMPORT arm, red every night since 2026-07-22):
##   `handleListUnspent` called
##     extractAddressFromScript(utxo.output.scriptPubKey, mainnet)
##   and omitted the third parameter, declared
##     regtest: bool = false                    (src/rpc/server.nim:3154-3155)
##   Because the default is false, every regtest segwit UTXO was rendered with
##   the shared testnet HRP "tb", while the very same key had been handed out
##   by `getnewaddress` as "bcrt1…" (wallet.nim:836-839 passes
##   `wallet.params.network == Regtest`). Same witness program, different HRP,
##   so the two strings never compare equal:
##     getnewaddress -> bcrt1q05fktjrqrr5ze7ntzukj0g0wrj5he0xm0l8srm
##     listunspent   -> tb1q05fktjrqrr5ze7ntzukj0g0wrj5he0xmdk7a5j
##   test-suite/import/nimrod_import.sh:291-293 filters listunspent by the
##   address getnewaddress returned, found nothing, and failed the arm.
##   `buildTxLegs` (backing listtransactions / gettransaction) had the same
##   omission on both its send and receive legs.
##
## Reference: bitcoin-core/src/kernel/chainparams.cpp:642 sets the regtest
## bech32_hrp to "bcrt" (mainnet "bc" :151, testnet/signet "tb" :264/:369/:510).
##
## These are behaviour pins, not error-absence pins: they assert the exact
## address string, amount and entry count the RPC must return.

import std/[unittest, json, os, strutils, tables]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/wallet
import ../src/crypto/address

const TestDbPath = "/tmp/nimrod_listunspent_hrp_test"

proc hexOf(b: seq[byte]): string =
  result = ""
  for x in b:
    result.add(toHex(x, 2).toLowerAscii())

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeRpc(): RpcServer =
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
  # Fixed BIP32 seed so the derived address is deterministic across runs.
  var seed: array[64, byte]
  for i in 0 ..< 64:
    seed[i] = byte(i)
  var w = newWalletFromSeed(seed, params)
  w.addAccount(84, 0, 20)        # BIP84 native segwit, the fleet default
  result.wallet = w

proc fixedTxid(tag: byte): TxId =
  var b: array[32, byte]
  for i in 0 ..< 32:
    b[i] = byte(int(tag) + i)
  TxId(b)

suite "regtest bech32 HRP in wallet RPC output":

  test "listunspent address == the address getnewaddress handed out (bcrt1…)":
    let rpc = makeRpc()

    # The address the wallet gives out. wallet.nim:836-839 already passes the
    # regtest flag, so this is "bcrt1…".
    let a1 = rpc.wallet.getNewAddressStr(P2WPKH)
    check a1.startsWith("bcrt1")

    # Fund that exact scriptPubKey. The bare test chainstate has no tip
    # (bestHeight == -1), so the UTXO is recorded unconfirmed (height 0) and
    # queried with minconf 0; the address-rendering path under test is the
    # same either way.
    let op = OutPoint(txid: fixedTxid(0xA0), vout: 0'u32)
    let spk = scriptPubKeyForAddress(decodeAddress(a1))
    rpc.wallet.addUtxo(op, TxOut(value: Satoshi(5_000_000_000'i64),
                                 scriptPubKey: spk),
                       height = 0'i32, keyPath = "m/84'/1'/0'/0/0",
                       isInternal = false, isCoinbase = false)

    let res = rpc.handleMethod("listunspent", %*[0])

    # Assert the ACTUAL returned values, not merely the absence of an error.
    check res.kind == JArray
    check res.len == 1
    let entry = res[0]
    check entry.hasKey("address")
    check entry["address"].getStr() == a1
    check entry["address"].getStr().startsWith("bcrt1")   # never "tb1"
    check entry["scriptPubKey"].getStr() == hexOf(spk)
    check entry["amount"].getFloat() == 50.0
    check entry["vout"].getInt() == 0

    rpc.chainState.close()
    cleanupTestDb()

  test "listtransactions receive leg address is bcrt1…, not tb1…":
    let rpc = makeRpc()
    let a1 = rpc.wallet.getNewAddressStr(P2WPKH)
    check a1.startsWith("bcrt1")
    let spk = scriptPubKeyForAddress(decodeAddress(a1))
    let txid = fixedTxid(0xB0)

    rpc.wallet.txHistory[txid] = WalletTxRecord(
      txid: txid,
      isCoinbase: false,
      credit: Satoshi(2_500_000_000'i64),
      debit: Satoshi(0),
      valueOut: Satoshi(2_500_000_000'i64),
      fromMe: false,
      height: 0'i32,
      time: 1_700_000_000'i64,
      details: @[WalletTxDetail(scriptPubKey: spk, isSend: false,
                                isMine: true,
                                amount: Satoshi(2_500_000_000'i64),
                                vout: 0'u32)])
    rpc.wallet.txOrder.add(txid)   # listtransactions walks txOrder

    let res = rpc.handleMethod("listtransactions", %*["*", 10])
    check res.kind == JArray
    check res.len == 1
    let leg = res[0]
    check leg.hasKey("address")
    check leg["address"].getStr() == a1
    check leg["address"].getStr().startsWith("bcrt1")     # never "tb1"
    check leg["category"].getStr() == "receive"
    check leg["amount"].getFloat() == 25.0

    rpc.chainState.close()
    cleanupTestDb()

when isMainModule:
  discard
