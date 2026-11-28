## cffix-nimrod-send-lock-check: `send` must not sign from a locked wallet.
##
## Finding (fingerprint nimrod/rpc/send/missing-wallet-lock-check): handleSend
## had no isEncrypted/isLocked check (sendtoaddress has one), so it signed with
## the derived account keys -- which encryptWallet and lockWallet leave in
## memory -- accepted the tx to the mempool and returned complete:true.
##
## Core (bitcoin-core/src/wallet/rpc/spend.cpp):
##   send -> FundTransaction -> FinishTransaction, which runs
##   FillPSBT(sign=false) then FillPSBT(sign=true). A locked descriptor wallet
##   hands FillPSBT no private keys, so nothing is signed, FinalizeAndExtractPSBT
##   reports incomplete, and FinishTransaction returns
##   {"psbt": <base64>, "complete": false} without committing anything: no
##   mempool entry, no wallet spend. Funding errors (insufficient funds, fee)
##   still come first because funding runs before FinishTransaction.
##
## Run:
##   nim c -r tests/test_cffix_send_lock_check.nim

import std/[json, options, tables, tempfiles, os]
import unittest2

import ../src/primitives/types
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager, psbt]
import ../src/crypto/address

const
  Dest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
  Pass = "correct horse battery staple"

proc primeWalletWithUtxo(w: var Wallet, cs: var ChainState, value: Satoshi) =
  ## One confirmed P2WPKH coin, in both the chainstate (so the mempool accepts
  ## a spend of it) and the wallet.
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var txidBytes: array[32, byte]
  for i in 0 ..< 32: txidBytes[i] = byte((i * 3 + 11) and 0xff)
  let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
  let output = TxOut(value: value, scriptPubKey: spk)
  cs.putUtxoCache(op, UtxoEntry(output: output, height: 100, isCoinbase: false))
  w.addUtxo(op, output, height = 100, keyPath = key.path,
            isInternal = false, isCoinbase = false)

proc errOf(rpc: RpcServer, m: string, p: JsonNode): ref RpcError =
  try:
    discard rpc.handleMethod(m, p)
  except RpcError as e:
    return e
  nil

suite "cffix send lock check (Core spend.cpp FinishTransaction)":
  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var w: Wallet
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_cffix_send_lock_", "_regtest")
    cs = newChainState(tempDir, cparams)
    if cs.bestHeight < 0:
      let res = cs.connectBlock(buildGenesisBlock(cparams), 0)
      doAssert res.isOk, "Failed to connect genesis"
    let mp = newMempool(cs, cparams)
    rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = newFeeEstimator(), params = cparams)
    rpc.fallbackFeeRate = 20.0
    wm = newWalletManager(tempDir, cparams, cs)
    rpc.walletManager = wm
    discard rpc.handleMethod("createwallet", %*["lk"])
    w = wm.getWallet("lk").get().wallet
    primeWalletWithUtxo(w, cs, Satoshi(100_000_000))

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  proc checkUnsignedNotCommitted(r: JsonNode) =
    ## The Core shape for a send the wallet cannot sign.
    check r.kind == JObject
    check r.hasKey("complete")
    if r.hasKey("complete"):
      check r["complete"].getBool() == false
    check not r.hasKey("txid")
    check r.hasKey("psbt")
    if r.hasKey("psbt"):
      let p = fromBase64(r["psbt"].getStr())
      check p.tx.isSome
      if p.tx.isSome:
        let tx = p.tx.get()
        check tx.inputs.len == 1
        check p.inputs.len == 1
        # Unsigned: no signature anywhere, the prevout carried for a signer.
        for txin in tx.inputs:
          check txin.scriptSig.len == 0
        if p.inputs.len == 1:
          check p.inputs[0].witnessUtxo.isSome
          check p.inputs[0].partialSigs.len == 0
          check p.inputs[0].finalScriptWitness.len == 0
    # Nothing committed: no mempool entry, the coin is still the wallet's.
    check rpc.mempool.count == 0
    check w.utxos.len == 1

  test "send from a freshly encrypted wallet returns complete:false, no mempool tx":
    discard rpc.handleMethod("encryptwallet", %*[Pass])
    check w.isEncrypted and w.isLocked
    let r = rpc.handleMethod("send", %*[{Dest: 0.1}])
    checkUnsignedNotCommitted(r)

  test "send after walletpassphrase then walletlock returns complete:false, no mempool tx":
    # The amount leaves 3000 sat for the fee, inside the changeless window, so
    # funding needs no new change key. walletlock zeroes the master key and
    # deriving a fresh key from it never terminates (deriveChild retries every
    # index; a separate, pre-existing bug), so a send that needs change would
    # hang here on master and on head alike.
    discard rpc.handleMethod("encryptwallet", %*[Pass])
    discard rpc.handleMethod("walletpassphrase", %*[Pass, 600])
    discard rpc.handleMethod("walletlock", %*[])
    check w.isEncrypted and w.isLocked
    let r = rpc.handleMethod("send", %*[{Dest: 0.99997}])
    checkUnsignedNotCommitted(r)
    if r.hasKey("psbt"):
      let p = fromBase64(r["psbt"].getStr())
      if p.tx.isSome:
        check p.tx.get().outputs.len == 1   # changeless, as the comment says

  test "locked wallet: funding errors still come first (insufficient funds is -6)":
    discard rpc.handleMethod("encryptwallet", %*[Pass])
    let e = rpc.errOf("send", %*[{Dest: 1000}])
    check e != nil
    if e != nil:
      check e.code == -6
    check rpc.mempool.count == 0

  test "control: after walletpassphrase, send signs and broadcasts":
    discard rpc.handleMethod("encryptwallet", %*[Pass])
    discard rpc.handleMethod("walletpassphrase", %*[Pass, 600])
    check w.isEncrypted and not w.isLocked
    let r = rpc.handleMethod("send", %*[{Dest: 0.1}])
    check r.kind == JObject
    check r["complete"].getBool() == true
    check r.hasKey("txid")
    check r["txid"].getStr().len == 64
    check not r.hasKey("psbt")
    check rpc.mempool.count == 1

  test "control: an unencrypted wallet's send signs and broadcasts":
    let r = rpc.handleMethod("send", %*[{Dest: 0.1}])
    check r["complete"].getBool() == true
    check rpc.mempool.count == 1
