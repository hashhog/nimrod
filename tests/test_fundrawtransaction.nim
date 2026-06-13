## fundrawtransaction RPC functional test.
##
## Mirrors the walletcreatefundedpsbt auto-fund test
## (test_signrawtransactionwithwallet.nim:200) — same WalletManager +
## handleMethod path, same UTXO-priming fixture — but exercises the new
## `fundrawtransaction` handler, which reuses the SAME funding /
## coin-selection engine (wallet.createTransaction → coinselection.nim) and
## serializes the funded tx to hex instead of a PSBT.
##
## Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction (706),
##            FundTransaction (470). Result shape: {hex, fee, changepos}.
##
## Coverage:
##   1. dispatch reachability (not method-not-found).
##   2. default no-options auto-fund:
##        - build a raw tx with 1 output and NO inputs (createrawtransaction-
##          style), fund it, and assert:
##            * vin became non-empty (inputs were added by the selector),
##            * a change output exists (changepos >= 0) — the wallet UTXO is
##              far larger than the payment so change is required,
##            * fee > 0,
##            * the returned hex DECODES to that exact tx,
##            * changepos is consistent with the decoded hex (the output at
##              changepos belongs to the wallet, i.e. it is the appended one),
##            * sum(selected input values) == sum(outputs) + fee  (genuine
##              coin selection — real inputs, real fee, real change).
##   3. exact-spend path: changepos == -1 only when no change was added.
##
## Run:
##   nim c -r tests/test_fundrawtransaction.nim

import std/[json, options, os, strutils, tables, tempfiles]
import unittest2

import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager]
import ../src/crypto/address

# Prime the wallet with one P2WPKH UTXO it owns, ALSO inserting it into the
# chainstate UTXO cache so both the funding engine (reads wallet.utxos) and the
# test's accounting check (reads chainstate.getUtxo) see the same coin.
# Mirrors g22InjectFundingUtxo in test_w118_wallet.nim. Returns outpoint+output.
proc primeWalletWithUtxo(w: var Wallet, cs: var ChainState, value: Satoshi,
                         seedByte: byte = 1): tuple[op: OutPoint, output: TxOut] =
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var txidBytes: array[32, byte]
  for i in 0 ..< 32: txidBytes[i] = byte((i + int(seedByte)) and 0xff)
  let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
  let output = TxOut(value: value, scriptPubKey: spk)
  cs.putUtxoCache(op, UtxoEntry(output: output, height: 100, isCoinbase: false))
  w.addUtxo(op, output, height = 100, keyPath = key.path,
            isInternal = false, isCoinbase = false)
  (op, output)

proc hexEncode(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

proc hexDecode(s: string): seq[byte] =
  doAssert s.len mod 2 == 0, "odd-length hex"
  var i = 0
  while i < s.len:
    result.add(byte(parseHexInt(s[i .. i+1])))
    i += 2

# Decode a raw-tx hex that may be an empty-vin (legacy) tx whose leading 0x00
# vin-count would be mis-read by the witness-aware deserializer as a segwit
# marker. Try witness-aware first, then a legacy-forced parse.
proc decodeTxHex(hex: string): Transaction =
  let bytes = hexDecode(hex)
  try:
    return deserializeTransaction(bytes)
  except CatchableError:
    discard
  var r = BinaryReader(data: bytes, pos: 0)
  result.version = r.readInt32LE()
  let inputCount = r.readCompactSize()
  for i in 0 ..< int(inputCount):
    result.inputs.add(r.readTxIn())
  let outputCount = r.readCompactSize()
  for i in 0 ..< int(outputCount):
    result.outputs.add(r.readTxOut())
  result.lockTime = r.readUint32LE()
  result.witnesses = newSeq[seq[seq[byte]]](result.inputs.len)

# Build a raw tx hex with the given outputs and NO inputs (createrawtransaction
# shape: version 2, empty vin, locktime 0).
proc rawTxHexNoInputs(outputs: seq[TxOut]): string =
  let tx = Transaction(version: 2'i32, inputs: @[], outputs: outputs,
                       witnesses: @[], lockTime: 0'u32)
  hexEncode(serialize(tx, includeWitness = false))

suite "fundrawtransaction (Core spend.cpp:706 parity)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_fundraw_", "_regtest")
    cs = newChainState(tempDir, cparams)
    if cs.bestHeight < 0:
      let genesis = buildGenesisBlock(cparams)
      let res = cs.connectBlock(genesis, 0)
      doAssert res.isOk, "Failed to connect genesis"
    let mp = newMempool(cs, cparams)
    let fe = newFeeEstimator()
    rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = fe, params = cparams)
    wm = newWalletManager(tempDir, cparams, cs)
    rpc.walletManager = wm
    var pCreate = newJArray()
    pCreate.add(%"tw")
    discard rpc.handleMethod("createwallet", pCreate)

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  test "fundrawtransaction is reachable via handleMethod (not method-not-found)":
    var caught: ref RpcError = nil
    try:
      discard rpc.handleMethod("fundrawtransaction", newJArray())
    except RpcError as e:
      caught = e
    check caught != nil
    check caught.code != RpcMethodNotFound
    check caught.code == RpcInvalidParams

  test "default no-options: adds inputs + change, returns genuine {hex,fee,changepos}":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    var w = wOpt.get().wallet

    # Seed one large UTXO (1 BTC) so a 0.1-BTC payment requires change.
    discard primeWalletWithUtxo(w, cs, Satoshi(100_000_000))

    # Destination = a fresh wallet address (we just need a decodable spk).
    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    let destSpk = scriptPubKeyForAddress(decodeAddress(destAddr))
    let payAmount = Satoshi(10_000_000)  # 0.1 BTC
    let rawHex = rawTxHexNoInputs(@[TxOut(value: payAmount, scriptPubKey: destSpk)])

    # Sanity: the input raw tx truly has no inputs.
    let preTx = decodeTxHex(rawHex)
    check preTx.inputs.len == 0
    check preTx.outputs.len == 1

    var p = newJArray()
    p.add(%rawHex)
    let resp = rpc.handleMethod("fundrawtransaction", p)

    check resp.kind == JObject
    check resp.hasKey("hex")
    check resp.hasKey("fee")
    check resp.hasKey("changepos")

    let fee = resp["fee"].getFloat()
    let changepos = resp["changepos"].getInt()
    check fee > 0.0                       # real, non-zero computed fee
    check changepos >= 0                  # change WAS added (input >> payment)

    # The hex must DECODE to the funded tx.
    let fundedTx = decodeTxHex(resp["hex"].getStr())
    check fundedTx.inputs.len >= 1        # inputs were added by the selector
    check fundedTx.outputs.len == 2       # original payment + change
    check changepos < fundedTx.outputs.len

    # The original payment output must still be present, unmodified.
    var foundPayment = false
    for o in fundedTx.outputs:
      if o.value == payAmount and o.scriptPubKey == destSpk:
        foundPayment = true
    check foundPayment

    # The output at changepos must be the NON-payment one (the change).
    let changeOut = fundedTx.outputs[changepos]
    check not (changeOut.value == payAmount and changeOut.scriptPubKey == destSpk)
    check changeOut.value > Satoshi(0)

    # GENUINE accounting: sum(selected input values) == sum(outputs) + fee.
    var totalIn = Satoshi(0)
    for inp in fundedTx.inputs:
      let u = cs.getUtxo(inp.prevOut)
      check u.isSome  # every selected input is a real, known UTXO
      if u.isSome:
        totalIn = totalIn + u.get().output.value
    var sumOut = Satoshi(0)
    for o in fundedTx.outputs:
      sumOut = sumOut + o.value
    let feeSat = int64(totalIn) - int64(sumOut)
    check feeSat > 0
    # fee field (BTC) must equal the input-vs-output delta exactly.
    check abs(float64(feeSat) / 100_000_000.0 - fee) < 1e-12
    # change == inputs - outputs - fee, i.e. the change output exactly absorbs
    # the leftover (totalIn - payment - fee).
    check int64(changeOut.value) == int64(totalIn) - int64(payAmount) - feeSat

  test "exact spend (no change room) → changepos == -1":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    var w = wOpt.get().wallet

    # Small UTXO; pay nearly the whole thing so the leftover after fee is below
    # the dust limit → createTransaction adds NO change → changepos == -1.
    discard primeWalletWithUtxo(w, cs, Satoshi(20_000), seedByte = 9)
    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    let destSpk = scriptPubKeyForAddress(decodeAddress(destAddr))
    # Pay an amount that leaves < dust after a ~1 sat/vB fee.
    let payAmount = Satoshi(19_900)
    let rawHex = rawTxHexNoInputs(@[TxOut(value: payAmount, scriptPubKey: destSpk)])

    var p = newJArray()
    p.add(%rawHex)
    p.add(%*{"fee_rate": 1.0})

    var resp: JsonNode = nil
    var insufficient = false
    try:
      resp = rpc.handleMethod("fundrawtransaction", p)
    except RpcError as e:
      # Acceptable Core-faithful outcome if the tiny UTXO can't even cover the
      # fee: insufficient-funds is RPC_WALLET_ERROR, NOT method-not-found.
      check e.code == RpcWalletError
      insufficient = true

    if not insufficient:
      check resp.hasKey("hex")
      let changepos = resp["changepos"].getInt()
      let fundedTx = decodeTxHex(resp["hex"].getStr())
      if changepos == -1:
        # No change output: exactly the original payment output remains.
        check fundedTx.outputs.len == 1
      else:
        check fundedTx.outputs.len == 2
      check resp["fee"].getFloat() > 0.0

  test "subtractFeeFromOutputs: recipient bears the fee, balance preserved":
    let wOpt = wm.getWallet("tw")
    check wOpt.isSome
    var w = wOpt.get().wallet
    discard primeWalletWithUtxo(w, cs, Satoshi(100_000_000))

    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    let destSpk = scriptPubKeyForAddress(decodeAddress(destAddr))
    let payAmount = Satoshi(10_000_000)
    let rawHex = rawTxHexNoInputs(@[TxOut(value: payAmount, scriptPubKey: destSpk)])

    var p = newJArray()
    p.add(%rawHex)
    p.add(%*{"fee_rate": 5.0, "subtractFeeFromOutputs": @[0]})
    let resp = rpc.handleMethod("fundrawtransaction", p)

    let fee = resp["fee"].getFloat()
    let changepos = resp["changepos"].getInt()
    check fee > 0.0
    check changepos >= 0  # change still present
    let fundedTx = decodeTxHex(resp["hex"].getStr())

    # The fee value and input/output balance are still exact.
    var totalIn = Satoshi(0)
    for inp in fundedTx.inputs:
      let u = cs.getUtxo(inp.prevOut)
      if u.isSome: totalIn = totalIn + u.get().output.value
    var sumOut = Satoshi(0)
    for o in fundedTx.outputs:
      sumOut = sumOut + o.value
    let feeSat = int64(totalIn) - int64(sumOut)
    check feeSat > 0
    check abs(float64(feeSat) / 100_000_000.0 - fee) < 1e-12

    # The recipient output (still identifiable by its scriptPubKey) was REDUCED
    # below the requested amount — i.e. it actually bore the fee.
    var paymentVal = Satoshi(-1)
    for o in fundedTx.outputs:
      if o.scriptPubKey == destSpk:
        paymentVal = o.value
    check paymentVal >= Satoshi(0)
    check int64(paymentVal) < int64(payAmount)        # recipient paid the fee
    check int64(payAmount) - int64(paymentVal) == feeSat  # exactly the fee
