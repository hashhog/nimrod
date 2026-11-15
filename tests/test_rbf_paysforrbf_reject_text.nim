## Single-transaction RBF reject text (Core PaysForRBF, policy/rbf.cpp:100-123).
##
## Core rejects a replacement that fails PaysForRBF with
##   state.Invalid(TX_RECONSIDERABLE, "insufficient fee", <err_string>)
## (validation.cpp:1013-1014), so the reason a client sees is
##   "insufficient fee, rejecting replacement <txid>, less fees than conflicting txs; <a> < <b>"
##   "insufficient fee, rejecting replacement <txid>, not enough additional fees to relay; <a> < <b>"
## with the replacement's txid and both amounts in FormatMoney (BTC, trailing
## zeros trimmed to two decimals).  The Core v31.1 regtest row
## package_rbf/over/submit:tx-results.<wtxid>.error is this string.

import unittest2
import std/[os, sets, tables, times, strutils]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_rbf_paysforrbf_text_test"

proc displayHex(id: TxId): string =
  ## Core uint256::ToString(): bytes reversed, lower-case hex.
  let a = array[32, byte](id)
  for i in countdown(31, 0):
    result.add(toHex(a[i], 2).toLowerAscii())

proc setupConflict(mp: var Mempool, outpoint: OutPoint, fee: int64): TxId =
  var arr: array[32, byte]
  arr[0] = 0x01
  let conflictTxid = TxId(arr)
  let conflictTx = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)
  mp.entries[conflictTxid] = MempoolEntry(
    tx: conflictTx, txid: conflictTxid, fee: Satoshi(fee),
    weight: 400, feeRate: 10.0, timeAdded: getTime(),
    height: 100, ancestorFee: Satoshi(fee), ancestorWeight: 400,
    ancestorCount: 1, ancestorSize: 100)
  mp.spentBy[outpoint] = conflictTxid
  conflictTxid

proc replacement(outpoint: OutPoint): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)

suite "single-tx RBF reject text matches Core PaysForRBF":
  setup:
    if dirExists(TestDbPath): removeDir(TestDbPath)
  teardown:
    if dirExists(TestDbPath): removeDir(TestDbPath)

  test "rule 3: names the replacement txid and prints amounts in BTC":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    var op: array[32, byte]
    op[0] = 0xAA
    let outpoint = OutPoint(txid: TxId(op), vout: 0)
    let conflictTxid = mp.setupConflict(outpoint, 21_000)
    let newTx = replacement(outpoint)
    let res = mp.checkRbfRules(newTx, Satoshi(6_000), 100, toHashSet([conflictTxid]))
    check not res.isOk
    # Core: "0.00006 < 0.00021" for 6000 vs 21000 sat (the regtest row's values).
    check res.error == "insufficient fee, rejecting replacement " &
      displayHex(newTx.txid()) & ", less fees than conflicting txs; 0.00006 < 0.00021"
    cs.close()

  test "rule 4: names the replacement txid and prints amounts in BTC":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    var op: array[32, byte]
    op[0] = 0xAB
    let outpoint = OutPoint(txid: TxId(op), vout: 0)
    let conflictTxid = mp.setupConflict(outpoint, 1_000)
    let newTx = replacement(outpoint)
    # Equal fees pass rule 3; 0 additional < 1 sat/vB * 100 vB fails rule 4.
    let res = mp.checkRbfRules(newTx, Satoshi(1_000), 100, toHashSet([conflictTxid]),
                               incrementalRelayFee = 1.0)
    check not res.isOk
    check res.error == "insufficient fee, rejecting replacement " &
      displayHex(newTx.txid()) & ", not enough additional fees to relay; 0.00 < 0.000001"
    cs.close()

  test "control: a replacement that pays enough is accepted":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    var op: array[32, byte]
    op[0] = 0xAC
    let outpoint = OutPoint(txid: TxId(op), vout: 0)
    let conflictTxid = mp.setupConflict(outpoint, 1_000)
    let newTx = replacement(outpoint)
    let res = mp.checkRbfRules(newTx, Satoshi(5_000), 100, toHashSet([conflictTxid]),
                               incrementalRelayFee = 1.0)
    check res.isOk
    cs.close()
