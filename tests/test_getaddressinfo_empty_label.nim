## getaddressinfo lists the address-book label of a new address, even "".
##
## Core v31.1 regtest differential, wallet group (row
## `wallet/address/info:labels[0]`): after `getnewaddress` with no label,
## Core's getaddressinfo answers labels [""]; nimrod answered [].
##
## Core:
##   - wallet/rpc/addresses.cpp:51 getnewaddress: label = LabelFromValue(
##     params[0]), "" when omitted; wallet/wallet.cpp GetNewDestination then
##     calls SetAddressBook(dest, label, AddressPurpose::RECEIVE), so every
##     new receive address has an address-book entry.
##   - wallet/rpc/addresses.cpp:504-507 getaddressinfo: when the address has
##     an address-book entry, labels = [entry.GetLabel()], "" included.
##   - getrawchangeaddress does not touch the address book, so a change
##     address keeps labels [].
##
## Pins the exact labels arrays, the change-address control, and that an
## empty label survives a wallet snapshot reload.

import unittest2
import std/[json, os, tables]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/fees
import ../src/wallet/[wallet, wallet_persist]

let TestDbPath = getTempDir() / "nimrod_getaddressinfo_empty_label_test"

proc makeRpc(): RpcServer =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)
  createDir(TestDbPath)
  let params = regtestParams()
  let cs = newChainState(TestDbPath / "chain", params)
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
    seed[i] = byte(i + 3)
  var w = newWalletFromSeed(seed, params)
  w.addAccount(84, 0, 20)
  result.wallet = w

proc teardown(rpc: RpcServer) =
  rpc.chainState.close()
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc labelsOf(rpc: RpcServer, address: string): JsonNode =
  rpc.handleMethod("getaddressinfo", %*[address])["labels"]

suite "getaddressinfo labels of a new address (Core addresses.cpp:504-507)":

  test "getnewaddress with no label: labels is [\"\"]":
    let rpc = makeRpc()
    let a = rpc.handleMethod("getnewaddress", %*[]).getStr()
    check rpc.labelsOf(a) == %*[""]
    rpc.teardown()

  test "getnewaddress with label \"\": labels is [\"\"]":
    let rpc = makeRpc()
    let a = rpc.handleMethod("getnewaddress", %*[""]).getStr()
    check rpc.labelsOf(a) == %*[""]
    rpc.teardown()

  test "control: getnewaddress with a label: labels is [label]":
    let rpc = makeRpc()
    let a = rpc.handleMethod("getnewaddress", %*["rent"]).getStr()
    check rpc.labelsOf(a) == %*["rent"]
    rpc.teardown()

  test "control: a change address has no address-book entry: labels is []":
    let rpc = makeRpc()
    let c = rpc.handleMethod("getrawchangeaddress", %*[]).getStr()
    check rpc.labelsOf(c) == newJArray()
    rpc.teardown()

  test "an empty label survives a wallet snapshot reload":
    let rpc = makeRpc()
    let a = rpc.handleMethod("getnewaddress", %*[]).getStr()
    let snapPath = TestDbPath / "wallet.snap"
    check saveWalletSnapshot(rpc.wallet, snapPath)
    var seed: array[64, byte]
    for i in 0 ..< 64:
      seed[i] = byte(i + 3)
    var w2 = newWalletFromSeed(seed, regtestParams())
    w2.addAccount(84, 0, 20)
    discard loadWalletSnapshot(w2, snapPath)
    check a in w2.labels
    rpc.wallet = w2
    check rpc.labelsOf(a) == %*[""]
    rpc.teardown()
