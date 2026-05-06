## signrawtransactionwithwallet + walletcreatefundedpsbt RPC dispatch tests
##
## Cat H wallet audit gap (2026-05-06): nimrod previously had no path from
## "have wallet UTXOs" to "broadcast tx" — both methods were missing from the
## handleMethod dispatch. These tests pin the dispatch + the happy / sad paths
## so a regression of the underlying PR (signrawtxwallet + walletcreatefundedpsbt)
## fails loud and immediate.
##
## Strategy: spin up a regtest RpcServer with a real WalletManager, seed the
## wallet with a synthetic UTXO whose scriptPubKey is owned by the wallet, then:
##   1. signrawtransactionwithwallet — build a raw P2WPKH-spending tx, sign it
##      via the new RPC, assert `complete=true` and the output hex contains a
##      witness stack.
##   2. walletcreatefundedpsbt — request a base64-PSBT funded automatically by
##      the wallet, assert (a) it round-trips through fromBase64, (b) `fee` is
##      positive, (c) the PSBT carries the wallet's UTXO as witness_utxo, and
##      (d) the case is reachable through handleMethod (not method-not-found).
##
## Run:
##   nim c -r tests/test_signrawtransactionwithwallet.nim

import std/[json, options, os, strutils, tables, tempfiles]
import unittest2

import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager, psbt]
import ../src/crypto/address

# Helper: build the payload-to-the-wallet UTXO that we'll spend.
# Returns (outpoint, output, scriptPubKey-hex)
proc primeWalletWithUtxo(w: var Wallet, value: Satoshi): tuple[
    op: OutPoint, output: TxOut, spkHex: string] =
  # Use the first external (receive) key on the BIP-84 account so the wallet
  # actually owns the script.
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)

  var txidBytes: array[32, byte]
  for i in 0 ..< 32: txidBytes[i] = byte(i + 1)
  let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
  let output = TxOut(value: value, scriptPubKey: spk)

  w.addUtxo(op, output, height = 100, keyPath = key.path,
            isInternal = false, isCoinbase = false)
  result = (op, output, "")
  # toHex without import — open-coded since helper is small
  for b in spk:
    result.spkHex.add(toHex(int(b), 2).toLowerAscii)

# Helper: hex-encode a byte sequence (mirrors server.toHex without importing
# private helpers).
proc hexEncode(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

# Helper: reverse hex (txid display ↔ internal byte order)
proc reverseHexT(s: string): string =
  result = ""
  var i = s.len - 2
  while i >= 0:
    result.add(s[i .. i+1])
    i -= 2

suite "signrawtransactionwithwallet + walletcreatefundedpsbt dispatch (Cat H)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_signrawwallet_", "_regtest")
    cs = newChainState(tempDir, cparams)
    if cs.bestHeight < 0:
      let genesis = buildGenesisBlock(cparams)
      let res = cs.connectBlock(genesis, 0)
      doAssert res.isOk, "Failed to connect genesis"

    let mp = newMempool(cs, cparams)
    let fe = newFeeEstimator()
    rpc = newRpcServer(
      port         = 18443'u16,
      chainState   = cs,
      mempool      = mp,
      peerManager  = nil,
      feeEstimator = fe,
      params       = cparams
    )
    wm = newWalletManager(tempDir, cparams, cs)
    rpc.walletManager = wm

    # Create wallet "tw" so getTargetWallet() resolves to it.
    var pCreate = newJArray()
    pCreate.add(%"tw")
    discard rpc.handleMethod("createwallet", pCreate)

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  test "signrawtransactionwithwallet is reachable via handleMethod (not method-not-found)":
    # Sanity: empty params will raise an RpcError, but it must NOT be
    # RpcMethodNotFound (-32601) — that's the regression guard.
    var caught: ref RpcError = nil
    try:
      discard rpc.handleMethod("signrawtransactionwithwallet", newJArray())
    except RpcError as e:
      caught = e
    check caught != nil
    check caught.code != RpcMethodNotFound
    check caught.code == RpcInvalidParams

  test "walletcreatefundedpsbt is reachable via handleMethod (not method-not-found)":
    var caught: ref RpcError = nil
    try:
      discard rpc.handleMethod("walletcreatefundedpsbt", newJArray())
    except RpcError as e:
      caught = e
    check caught != nil
    check caught.code != RpcMethodNotFound
    check caught.code == RpcInvalidParams

  test "signrawtransactionwithwallet signs a P2WPKH input from wallet UTXOs":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    let lw = wOpt.get()
    var w = lw.wallet

    # Seed the wallet with a 1.0-BTC P2WPKH UTXO it can sign.
    let primed = primeWalletWithUtxo(w, Satoshi(100_000_000))

    # Build an unsigned tx that spends the primed UTXO to the same address.
    let destSpk = primed.output.scriptPubKey
    let unsignedTx = Transaction(
      version: 2'i32,
      inputs: @[TxIn(prevOut: primed.op, scriptSig: @[],
                     sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(99_900_000), scriptPubKey: destSpk)],
      witnesses: @[@[]],
      lockTime: 0'u32
    )
    let unsignedHex = hexEncode(serialize(unsignedTx, includeWitness = false))

    var p = newJArray()
    p.add(%unsignedHex)
    let resp = rpc.handleMethod("signrawtransactionwithwallet", p)
    check resp.kind == JObject
    check resp.hasKey("hex")
    check resp.hasKey("complete")
    check resp["complete"].getBool() == true
    # No "errors" key on a fully-signed tx.
    check (not resp.hasKey("errors")) or resp["errors"].len == 0

    # Decode the returned hex and verify the witness stack now has 2 items
    # (signature + pubkey). This confirms BIP-143 P2WPKH signing fired, not
    # just a no-op pass-through.
    let signedHex = resp["hex"].getStr()
    var bytesOut = newSeq[byte](signedHex.len div 2)
    for i in 0 ..< bytesOut.len:
      bytesOut[i] = byte(parseHexInt(signedHex[i*2 .. i*2 + 1]))
    let signedTx = deserializeTransaction(bytesOut)
    check signedTx.witnesses.len == 1
    check signedTx.witnesses[0].len == 2  # [DER sig + sighash byte, pubkey]
    check signedTx.witnesses[0][1].len == 33  # compressed pubkey

  test "signrawtransactionwithwallet returns errors[] for unknown prevouts":
    # Build a tx referencing a UTXO the wallet has never seen. Expect
    # complete=false and an errors entry, no exception.
    var fakeTxidBytes: array[32, byte]
    for i in 0 ..< 32: fakeTxidBytes[i] = byte(0xff)
    let unsignedTx = Transaction(
      version: 2'i32,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(fakeTxidBytes), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x6a'u8])],
      witnesses: @[@[]],
      lockTime: 0'u32
    )
    let unsignedHex = hexEncode(serialize(unsignedTx, includeWitness = false))

    var p = newJArray()
    p.add(%unsignedHex)
    let resp = rpc.handleMethod("signrawtransactionwithwallet", p)
    check resp.kind == JObject
    check resp["complete"].getBool() == false
    check resp.hasKey("errors")
    check resp["errors"].len == 1
    check resp["errors"][0]["error"].getStr().contains("not found")

  test "walletcreatefundedpsbt auto-funds from wallet UTXOs and returns base64 PSBT":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    let lw = wOpt.get()
    var w = lw.wallet

    # Seed with enough to cover a 0.5-BTC payment + change + fee.
    let primed = primeWalletWithUtxo(w, Satoshi(100_000_000))
    discard primed  # silence unused

    # Use a fresh wallet address as the destination so we don't need an
    # external decode test vector here.
    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                       isChange = false)

    var inputs = newJArray()  # empty → auto-fund
    var outputs = newJArray()
    var outObj = newJObject()
    outObj[destAddr] = %0.5  # 0.5 BTC
    outputs.add(outObj)

    var p = newJArray()
    p.add(inputs)
    p.add(outputs)
    p.add(%0)  # locktime
    p.add(%*{"fee_rate": 1.0})  # 1 sat/vB

    let resp = rpc.handleMethod("walletcreatefundedpsbt", p)
    check resp.kind == JObject
    check resp.hasKey("psbt")
    check resp.hasKey("fee")
    check resp.hasKey("changepos")
    check resp["fee"].getFloat() > 0.0  # paid some fee

    # Round-trip the base64 PSBT through the deserializer to prove it's well-
    # formed. (createPsbt + updateInput must produce a valid PSBT.)
    let psbtBase64 = resp["psbt"].getStr()
    let psbtObj = fromBase64(psbtBase64)
    check psbtObj.tx.isSome
    let psbtTx = psbtObj.tx.get()
    # The funded tx must spend at least one input and have ≥1 output.
    check psbtTx.inputs.len >= 1
    check psbtTx.outputs.len >= 1
    # First input should carry a witnessUtxo (we populated it).
    check psbtObj.inputs[0].witnessUtxo.isSome

  test "walletcreatefundedpsbt with explicit inputs uses them as-is":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    let lw = wOpt.get()
    var w = lw.wallet

    let primed = primeWalletWithUtxo(w, Satoshi(100_000_000))

    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                       isChange = false)

    # Build inputs explicitly pointing at the primed UTXO.
    var inputs = newJArray()
    inputs.add(%*{
      "txid": reverseHexT(hexEncode(array[32, byte](primed.op.txid))),
      "vout": primed.op.vout
    })
    var outputs = newJArray()
    var outObj = newJObject()
    # Spend nearly all of it to leave room for the implied fee.
    outObj[destAddr] = %0.99
    outputs.add(outObj)

    var p = newJArray()
    p.add(inputs)
    p.add(outputs)

    let resp = rpc.handleMethod("walletcreatefundedpsbt", p)
    check resp.kind == JObject
    check resp.hasKey("psbt")
    let psbtObj = fromBase64(resp["psbt"].getStr())
    check psbtObj.tx.isSome
    let psbtTx = psbtObj.tx.get()
    check psbtTx.inputs.len == 1
    check psbtTx.inputs[0].prevOut.txid == primed.op.txid
    check psbtTx.inputs[0].prevOut.vout == primed.op.vout
    # changepos = -1 since we didn't auto-add change.
    check resp["changepos"].getInt() == -1
