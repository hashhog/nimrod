## walletprocesspsbt must sign the wallet's own inputs over the wallet's own
## prevout data, not over UTXO data the PSBT author supplied (CVE-2020-14199
## class: an understated amount on a segwit v0 input lets an attacker collect
## two individually-valid signatures that together pay a huge fee).
##
## Core v31.1:
##   wallet/wallet.cpp CWallet::FillPSBT: "If we have no utxo, grab it from the
##     wallet" -- non_witness_utxo is filled from mapWallet when absent.
##   psbt.h PartiallySignedTransaction::Unserialize: for every input, a
##     non_witness_utxo whose hash is not the prevout txid throws "Non-witness
##     UTXO does not match outpoint hash", and one with no output at the
##     prevout index throws "Input specifies output index that does not
##     exist" (std::ios_base::failure; libstdc++ appends ": iostream error").
##     walletprocesspsbt (wallet/rpc/spend.cpp) turns a decode failure into
##     RPC_DESERIALIZATION_ERROR (-22) "TX decode failed <reason>".
##   psbt.cpp SignPSBTInput: the prevout comes from non_witness_utxo first.
##     When only witness_utxo is present `require_witness_sig = true`, and a
##     non-witness signature is then refused (PSBTError::INCOMPLETE: the
##     input stays unsigned). After a witness signature `witness_utxo = utxo`.
##
## Run:
##   nim c -r tests/test_cffix_psbt_trusted_prevout.nim

import std/[json, options, os, tables, tempfiles]
import unittest2

import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager, psbt]
import ../src/crypto/address

const
  TrueValue = 100_000_000'i64      # what the wallet's coin is really worth
  LowValue = 1_000_000'i64         # what the PSBT author claims it is worth

suite "cffix walletprocesspsbt: sign owned inputs over the wallet's prevout, verify non_witness_utxo":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_cffix_psbt_prevout_", "_regtest")
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
    rpc.fallbackFeeRate = 20.0
    var pCreate = newJArray()
    pCreate.add(%"tw")
    discard rpc.handleMethod("createwallet", pCreate)

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  proc wallet(): Wallet =
    let wOpt = wm.getWallet("tw")
    doAssert wOpt.isSome
    wOpt.get().wallet

  ## A wallet key of the given address type and its scriptPubKey.
  proc walletKey(kind: AddressType): (DerivedKey, seq[byte]) =
    var w = wallet()
    let a = w.getNewAddress(addrType = kind, accountIdx = -1,
                            isChange = false)
    let spk = scriptPubKeyForAddress(a)
    let k = w.findKeyForScript(spk)
    doAssert k.isSome, "wallet must own the key for " & $kind
    (k.get(), spk)

  ## A funding transaction paying `value` to `spk` at output 0 (tag makes the
  ## txid unique). It is never confirmed; the wallet learns it via addUtxo.
  proc fundingTx(spk: seq[byte], value: int64, tag: byte): Transaction =
    var prevHash: array[32, byte]
    prevHash[0] = tag
    prevHash[31] = 0xee
    Transaction(
      version: 2,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prevHash), vout: 0'u32),
                     scriptSig: @[0x51'u8], sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(value), scriptPubKey: spk)],
      witnesses: @[],
      lockTime: 0)

  ## The unsigned spend of `op`: one output of 0.5 BTC to a fixed script.
  proc spendTx(op: OutPoint): Transaction =
    Transaction(
      version: 2,
      inputs: @[TxIn(prevOut: op, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(50_000_000),
                       scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20))],
      witnesses: @[],
      lockTime: 0)

  proc ownCoin(fund: Transaction, key: DerivedKey) =
    var w = wallet()
    w.addUtxo(OutPoint(txid: fund.txid(), vout: 0'u32), fund.outputs[0],
              height = 100, keyPath = key.path,
              isInternal = false, isCoinbase = false)

  ## walletprocesspsbt psbt sign=<sign> "ALL" bip32derivs=true finalize=false
  proc process(p: Psbt, sign = true): Psbt =
    var pp = newJArray()
    pp.add(%p.toBase64())
    pp.add(%sign)
    pp.add(%"ALL")
    pp.add(%true)
    pp.add(%false)
    fromBase64(rpc.handleMethod("walletprocesspsbt", pp)["psbt"].getStr())

  proc processErr(p: Psbt, sign = true): ref RpcError =
    try:
      discard process(p, sign)
    except RpcError as e:
      return e
    nil

  const
    # Core throws std::ios_base::failure; on libstdc++ its what() ends in
    # ": iostream error" (Core answers e.g. "TX decode failed Invalid pubkey:
    # iostream error").
    HashMismatch = "TX decode failed Non-witness UTXO does not match outpoint hash: iostream error"
    IndexMissing = "TX decode failed Input specifies output index that does not exist: iostream error"

  proc checkDecodeRefused(e: ref RpcError, msg: string) =
    check e != nil
    if e != nil:
      check e.code == RpcDeserializationError  # -22, Core RPC_DESERIALIZATION_ERROR
      check e.msg == msg

  ## The DER signature (sighash byte included) the wallet key makes for
  ## input 0 of `tx` under BIP-143 with `value` as the spent amount.
  proc p2wpkhSig(tx: Transaction, key: DerivedKey, value: int64): seq[byte] =
    var scratch = tx
    scratch.witnesses = @[newSeq[seq[byte]]()]
    signInputP2WPKH(scratch, 0, key.extKey.key, key.extKey.publicKey,
                    Satoshi(value), 0x01'u32)
    doAssert scratch.witnesses[0].len == 2
    scratch.witnesses[0][0]

  proc onlySig(p: Psbt): seq[byte] =
    doAssert p.inputs[0].partialSigs.len == 1,
      "expected exactly one partial sig, got " & $p.inputs[0].partialSigs.len
    for _, sig in p.inputs[0].partialSigs:
      return sig

  test "owned P2WPKH input with an understated witness_utxo is signed over the wallet's true amount":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 1)
    ownCoin(fund, key)
    let tx = spendTx(OutPoint(txid: fund.txid(), vout: 0'u32))
    var p = createPsbt(tx)
    p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(LowValue),
                                         scriptPubKey: spk))
    let trueSig = p2wpkhSig(tx, key, TrueValue)
    let lowSig = p2wpkhSig(tx, key, LowValue)
    # Instrument check: the two amounts give different signatures, so the
    # comparison below can tell them apart.
    doAssert trueSig != lowSig
    let outP = process(p)
    let sig = onlySig(outP)
    check sig != lowSig
    check sig == trueSig
    # Core rewrites witness_utxo with the UTXO it signed over.
    check outP.inputs[0].witnessUtxo.isSome
    if outP.inputs[0].witnessUtxo.isSome:
      check int64(outP.inputs[0].witnessUtxo.get().value) == TrueValue

  test "owned P2WPKH input with an understated witness_utxo and sign=false comes back with the wallet's amount":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 2)
    ownCoin(fund, key)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(LowValue),
                                         scriptPubKey: spk))
    let outP = process(p, sign = false)
    check outP.inputs[0].partialSigs.len == 0
    check outP.inputs[0].witnessUtxo.isSome
    if outP.inputs[0].witnessUtxo.isSome:
      check int64(outP.inputs[0].witnessUtxo.get().value) == TrueValue

  test "non_witness_utxo whose txid does not match the prevout is refused":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 3)
    ownCoin(fund, key)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    # A different transaction (different txid) claiming the coin is small.
    let bogus = fundingTx(spk, LowValue, 4)
    doAssert bogus.txid() != fund.txid()
    p.inputs[0].nonWitnessUtxo = some(bogus)
    checkDecodeRefused(processErr(p), HashMismatch)

  test "non_witness_utxo whose txid does not match is refused with sign=false too":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 5)
    ownCoin(fund, key)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].nonWitnessUtxo = some(fundingTx(spk, LowValue, 6))
    checkDecodeRefused(processErr(p, sign = false), HashMismatch)

  test "non_witness_utxo with too few outputs for the prevout index is refused":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 7)
    ownCoin(fund, key)
    # The wallet coin sits at output 0; ask for output 3 of the right tx.
    var w = wallet()
    w.addUtxo(OutPoint(txid: fund.txid(), vout: 3'u32), fund.outputs[0],
              height = 100, keyPath = key.path,
              isInternal = false, isCoinbase = false)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 3'u32)))
    p.inputs[0].nonWitnessUtxo = some(fund)
    checkDecodeRefused(processErr(p), IndexMissing)

  test "foreign input with a mismatched non_witness_utxo is refused (Core checks every input)":
    let (_, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 8)
    # Not added to the wallet, and the script below is not the wallet's.
    let foreignSpk = @[0x00'u8, 0x14] & newSeq[byte](20)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].nonWitnessUtxo = some(fundingTx(foreignSpk, LowValue, 9))
    checkDecodeRefused(processErr(p), HashMismatch)

  test "finalized input with a mismatched non_witness_utxo is refused (Core checks while decoding)":
    let (_, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 17)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].finalScriptWitness = @[@[0x01'u8]]
    doAssert p.inputs[0].isSigned()
    p.inputs[0].nonWitnessUtxo = some(fundingTx(spk, LowValue, 18))
    checkDecodeRefused(processErr(p), HashMismatch)

  test "owned P2PKH key, coin unknown to the wallet: no legacy signature over witness_utxo-only data":
    # Legacy sighash does not commit to the amount or prove the script, so
    # Core requires a witness signature when it only has witness_utxo.
    let (_, spk) = walletKey(P2PKH)
    doAssert spk.len == 25 and spk[0] == 0x76
    let fund = fundingTx(spk, TrueValue, 10)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(LowValue),
                                         scriptPubKey: spk))
    let outP = process(p)
    check outP.inputs[0].partialSigs.len == 0

  test "control: correct non_witness_utxo is accepted and signed over its amount":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 11)
    ownCoin(fund, key)
    let tx = spendTx(OutPoint(txid: fund.txid(), vout: 0'u32))
    var p = createPsbt(tx)
    p.inputs[0].nonWitnessUtxo = some(fund)
    let outP = process(p)
    check onlySig(outP) == p2wpkhSig(tx, key, TrueValue)

  test "control: owned P2WPKH input with a truthful witness_utxo signs as before":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 12)
    ownCoin(fund, key)
    let tx = spendTx(OutPoint(txid: fund.txid(), vout: 0'u32))
    var p = createPsbt(tx)
    p.inputs[0].witnessUtxo = some(fund.outputs[0])
    check onlySig(process(p)) == p2wpkhSig(tx, key, TrueValue)

  test "control: owned P2WPKH key, coin unknown to the wallet, witness_utxo only: still signed (BIP-143 commits to it)":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 13)
    let tx = spendTx(OutPoint(txid: fund.txid(), vout: 0'u32))
    var p = createPsbt(tx)
    p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(LowValue),
                                         scriptPubKey: spk))
    check onlySig(process(p)) == p2wpkhSig(tx, key, LowValue)

  test "control: owned P2PKH coin in the wallet is signed":
    let (key, spk) = walletKey(P2PKH)
    let fund = fundingTx(spk, TrueValue, 14)
    ownCoin(fund, key)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    let outP = process(p)
    check outP.inputs[0].partialSigs.len == 1

  test "control: owned P2PKH key with a correct non_witness_utxo is signed":
    let (_, spk) = walletKey(P2PKH)
    let fund = fundingTx(spk, TrueValue, 15)
    var p = createPsbt(spendTx(OutPoint(txid: fund.txid(), vout: 0'u32)))
    p.inputs[0].nonWitnessUtxo = some(fund)
    let outP = process(p)
    check outP.inputs[0].partialSigs.len == 1

  test "owned P2WPKH input known only from the wallet's history is signed over the recorded amount, not witness_utxo's":
    # CWallet::FillPSBT backfills non_witness_utxo from mapWallet, which
    # holds wallet transactions whether or not their outputs are unspent.
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 16)
    var w = wallet()
    w.txHistory[fund.txid()] = WalletTxRecord(
      txid: fund.txid(), rawTx: serialize(fund, includeWitness = true))
    doAssert OutPoint(txid: fund.txid(), vout: 0'u32) notin w.utxos
    let tx = spendTx(OutPoint(txid: fund.txid(), vout: 0'u32))
    var p = createPsbt(tx)
    p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(LowValue),
                                         scriptPubKey: spk))
    let sig = onlySig(process(p))
    check sig != p2wpkhSig(tx, key, LowValue)
    check sig == p2wpkhSig(tx, key, TrueValue)

  test "owned P2PKH key, coin only in chainstate, no PSBT data: left unsigned (Core's walletprocesspsbt has no chainstate source)":
    let (_, spk) = walletKey(P2PKH)
    let fund = fundingTx(spk, TrueValue, 19)
    let op = OutPoint(txid: fund.txid(), vout: 0'u32)
    cs.db.putUtxo(op, UtxoEntry(output: fund.outputs[0], height: 1,
                                isCoinbase: false))
    doAssert cs.getUtxo(op).isSome
    doAssert op notin wallet().utxos
    let outP = process(createPsbt(spendTx(op)))
    check outP.inputs[0].partialSigs.len == 0

  test "control: owned P2WPKH key, coin only in chainstate, no PSBT data: signed over the chainstate amount":
    let (key, spk) = walletKey(P2WPKH)
    let fund = fundingTx(spk, TrueValue, 20)
    let op = OutPoint(txid: fund.txid(), vout: 0'u32)
    cs.db.putUtxo(op, UtxoEntry(output: fund.outputs[0], height: 1,
                                isCoinbase: false))
    let tx = spendTx(op)
    check onlySig(process(createPsbt(tx))) == p2wpkhSig(tx, key, TrueValue)
