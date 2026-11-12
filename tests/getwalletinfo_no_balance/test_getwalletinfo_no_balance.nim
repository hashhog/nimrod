## getwalletinfo must not emit the legacy balance fields (wallet-cause-B).
##
## CONTROL: `nim c -r tests/getwalletinfo_no_balance/test_getwalletinfo_no_balance.nim`
##
## Core v31.1 wallet/rpc/wallet.cpp getwalletinfo returns walletname,
## walletversion, format, txcount, keypoolsize, ... and NO balance,
## unconfirmed_balance or immature_balance (those live in getbalances).

import unittest2
import std/[json, os]
import ../../src/rpc/server
import ../../src/mempool/mempool
import ../../src/storage/chainstate
import ../../src/consensus/params
import ../../src/mining/fees
import ../../src/wallet/[wallet, manager]
import ../../src/primitives/[types, serialize]

proc makeRpc(): RpcServer =
  let dbPath = "/tmp/nimrod_gwi_nobal_" & $getCurrentProcessId()
  if dirExists(dbPath):
    removeDir(dbPath)
  createDir(dbPath)
  let params = regtestParams()
  var cs = newChainState(dbPath, params)
  if cs.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    doAssert cs.connectBlock(genesis, 0).isOk
  let mp = newMempool(cs, params, fullRbf = false)
  result = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
    peerManager = nil, feeEstimator = newFeeEstimator(), params = params)
  result.walletManager = newWalletManager(dbPath, params, cs)

suite "getwalletinfo_no_balance":

  test "getwalletinfo has no balance fields":
    let rpc = makeRpc()
    discard rpc.handleMethod("createwallet", %*["w"])
    let info = rpc.handleMethod("getwalletinfo", %*[])
    for f in ["balance", "unconfirmed_balance", "immature_balance"]:
      check not info.hasKey(f)
    rpc.chainState.close()

  test "control: getwalletinfo keeps Core fields; getbalances still has balances":
    let rpc = makeRpc()
    discard rpc.handleMethod("createwallet", %*["w"])
    let info = rpc.handleMethod("getwalletinfo", %*[])
    for f in ["walletname", "walletversion", "format", "txcount",
              "keypoolsize", "private_keys_enabled", "avoid_reuse",
              "scanning", "descriptors", "external_signer", "blank",
              "flags", "lastprocessedblock"]:
      check info.hasKey(f)
    check rpc.handleMethod("getbalances", %*[]).hasKey("mine")
    rpc.chainState.close()
