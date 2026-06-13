## walletprocesspsbt RPC dispatch + sign + finalize tests (Bitcoin Core v31.99
## src/wallet/rpc/spend.cpp::walletprocesspsbt).
##
## walletprocesspsbt is the Updater + Signer (+ Finalizer + Extractor) role:
## given a base64 PSBT it fills in the wallet's UTXO/script data, SIGNS every
## input the wallet holds a key for (reusing the SAME BIP-143 sighash + ECDSA
## engine as signrawtransactionwithwallet / walletcreatefundedpsbt), optionally
## finalizes, and returns { psbt, complete (, hex when complete) }.
##
## ⭐ The load-bearing assertion is (c): we do NOT merely check that a partial
## sig is non-empty — we decode the finalized network tx that walletprocesspsbt
## emits and run the input's scriptSig + witness back through the impl's OWN
## script verifier (script/interpreter.verifyScript) against the prevout's real
## scriptPubKey and BIP-143 sighash. If the signature is fabricated, malformed,
## or over the wrong sighash, verifyScript returns false and the test fails.
##
## Run:
##   nim c -r tests/test_walletprocesspsbt.nim

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
import ../src/script/interpreter

# Hex-encode a byte sequence (local helper; mirrors server's private toHex).
proc hexEncode(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

# Reverse hex (internal txid byte order -> display order).
proc reverseHexT(s: string): string =
  result = ""
  var i = s.len - 2
  while i >= 0:
    result.add(s[i .. i+1])
    i -= 2

# Decode a hex string to bytes.
proc hexDecode(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2 + 1]))

# Seed the wallet with a P2WPKH UTXO it owns. Returns (outpoint, output).
proc primeWalletWithUtxo(w: var Wallet, value: Satoshi, seedByte: byte): tuple[
    op: OutPoint, output: TxOut] =
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var txidBytes: array[32, byte]
  for i in 0 ..< 32: txidBytes[i] = byte((i + int(seedByte)) and 0xff)
  let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
  let output = TxOut(value: value, scriptPubKey: spk)
  w.addUtxo(op, output, height = 100, keyPath = key.path,
            isInternal = false, isCoinbase = false)
  result = (op, output)

suite "walletprocesspsbt: Updater + Signer + Finalizer (Core v31.99)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_walletprocesspsbt_", "_regtest")
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
    var pCreate = newJArray()
    pCreate.add(%"tw")
    discard rpc.handleMethod("createwallet", pCreate)

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  test "walletprocesspsbt is reachable via handleMethod (not method-not-found)":
    var caught: ref RpcError = nil
    try:
      discard rpc.handleMethod("walletprocesspsbt", newJArray())
    except RpcError as e:
      caught = e
    check caught != nil
    check caught.code != RpcMethodNotFound
    check caught.code == RpcInvalidParams

  test "walletprocesspsbt rejects a malformed base64 PSBT with -22":
    var caught: ref RpcError = nil
    var p = newJArray()
    p.add(%"not-a-valid-psbt")
    try:
      discard rpc.handleMethod("walletprocesspsbt", p)
    except RpcError as e:
      caught = e
    check caught != nil
    check caught.code == RpcDeserializationError  # -22, Core RPC_DESERIALIZATION_ERROR

  test "signs a single-wallet-input PSBT to completion; sig VERIFIES":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    var w = wOpt.get().wallet

    # Prime a 1.0-BTC P2WPKH UTXO the wallet owns.
    let primed = primeWalletWithUtxo(w, Satoshi(100_000_000), 1)
    let ownSpk = primed.output.scriptPubKey

    # ---- Creator/Updater: build a funded PSBT with this explicit input. ----
    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    var inputs = newJArray()
    inputs.add(%*{
      "txid": reverseHexT(hexEncode(array[32, byte](primed.op.txid))),
      "vout": primed.op.vout
    })
    var outputs = newJArray()
    var outObj = newJObject()
    outObj[destAddr] = %0.99  # leave room for the implied fee
    outputs.add(outObj)
    var pc = newJArray()
    pc.add(inputs)
    pc.add(outputs)
    let createResp = rpc.handleMethod("walletcreatefundedpsbt", pc)
    let unsignedPsbtB64 = createResp["psbt"].getStr()

    # ---- Signer + Finalizer: walletprocesspsbt (sign+finalize default). ----
    var pp = newJArray()
    pp.add(%unsignedPsbtB64)
    let resp = rpc.handleMethod("walletprocesspsbt", pp)
    check resp.kind == JObject
    check resp.hasKey("psbt")
    check resp.hasKey("complete")

    # (a) the returned psbt is valid base64 and round-trips.
    let outPsbtB64 = resp["psbt"].getStr()
    let roundTripped = fromBase64(outPsbtB64)
    check roundTripped.tx.isSome

    # (b) complete == true for a single-wallet-input PSBT.
    check resp["complete"].getBool() == true

    # Core emits the finalized network tx hex when complete.
    check resp.hasKey("hex")
    let finalTx = deserializeTransaction(hexDecode(resp["hex"].getStr()))
    check finalTx.inputs.len == 1
    # The single input must carry a 2-item witness [DER sig+hashbyte, pubkey].
    check finalTx.witnesses.len == 1
    check finalTx.witnesses[0].len == 2
    check finalTx.witnesses[0][1].len == 33  # compressed pubkey

    # ---- (c) ⭐ the produced signature VERIFIES through the impl's own
    # script verifier against the prevout scriptPubKey + BIP-143 sighash. ----
    let flags = {sfP2SH, sfWitness, sfWitnessPubkeyType, sfNullDummy,
                 sfDERSig, sfLowS, sfStrictEnc}
    let ok = verifyScript(
      scriptSig   = finalTx.inputs[0].scriptSig,   # empty for native P2WPKH
      scriptPubKey = ownSpk,
      tx          = finalTx,
      inputIndex  = 0,
      amount      = primed.output.value,
      flags       = flags,
      witness     = finalTx.witnesses[0]
    )
    check ok == true

    # Negative control: flip a byte of the signature and the SAME verifier
    # must reject it — proving the check is non-vacuous.
    var tampered = finalTx
    var badWit = tampered.witnesses[0]
    badWit[0][10] = badWit[0][10] xor 0xff'u8
    tampered.witnesses[0] = badWit
    let okTampered = verifyScript(
      scriptSig   = tampered.inputs[0].scriptSig,
      scriptPubKey = ownSpk,
      tx          = tampered,
      inputIndex  = 0,
      amount      = primed.output.value,
      flags       = flags,
      witness     = tampered.witnesses[0]
    )
    check okTampered == false

  test "sign=false updates UTXO data but adds no signature (no hex)":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    var w = wOpt.get().wallet
    let primed = primeWalletWithUtxo(w, Satoshi(100_000_000), 50)

    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    var inputs = newJArray()
    inputs.add(%*{
      "txid": reverseHexT(hexEncode(array[32, byte](primed.op.txid))),
      "vout": primed.op.vout
    })
    var outputs = newJArray()
    var outObj = newJObject()
    outObj[destAddr] = %0.99
    outputs.add(outObj)
    var pc = newJArray()
    pc.add(inputs)
    pc.add(outputs)
    let unsignedPsbtB64 = rpc.handleMethod("walletcreatefundedpsbt", pc)["psbt"].getStr()

    var pp = newJArray()
    pp.add(%unsignedPsbtB64)
    pp.add(%false)  # sign = false
    let resp = rpc.handleMethod("walletprocesspsbt", pp)
    # Not signed -> not complete -> no hex.
    check resp["complete"].getBool() == false
    check (not resp.hasKey("hex"))
    # But the input still round-trips and carries witness_utxo from the Updater.
    let rt = fromBase64(resp["psbt"].getStr())
    check rt.inputs.len == 1
    check rt.inputs[0].witnessUtxo.isSome
    # And it must carry NO partial signature (sign was disabled).
    check rt.inputs[0].partialSigs.len == 0
    check (not rt.inputs[0].isSigned())
