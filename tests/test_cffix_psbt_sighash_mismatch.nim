## walletprocesspsbt must refuse a PSBT_IN_SIGHASH_TYPE that differs from the
## caller's sighashtype instead of signing with the PSBT author's choice.
##
## Core v31.1 src/psbt.cpp SignPSBTInput:
##   if (!sighash) sighash = utxo.scriptPubKey.IsPayToTaproot() ? SIGHASH_DEFAULT : SIGHASH_ALL;
##   if (input.sighash_type && input.sighash_type != sighash) return PSBTError::SIGHASH_MISMATCH;
## walletprocesspsbt throws JSONRPCPSBTError(SIGHASH_MISMATCH): code
## RPC_DESERIALIZATION_ERROR (-22, rpc/util.cpp RPCErrorFromPSBTError), message
## "Specified sighash value does not match value stored in PSBT"
## (common/messages.cpp PSBTErrorString).
##
## The check runs for every unfinalized input that has UTXO data, before any
## key lookup and whether or not `sign` is set (wallet/scriptpubkeyman.cpp
## DescriptorScriptPubKeyMan::FillPSBT calls SignPSBTInput for each one).
##
## Why it matters: with the old behaviour a counterparty who sets
## PSBT_IN_SIGHASH_TYPE=NONE on our input gets a SIGHASH_NONE signature from a
## default-args call, and can then rewrite every output.
##
## Run:
##   nim c -r tests/test_cffix_psbt_sighash_mismatch.nim

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

proc hexEncode(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

proc reverseHexT(s: string): string =
  var i = s.len - 2
  while i >= 0:
    result.add(s[i .. i+1])
    i -= 2

suite "cffix walletprocesspsbt: PSBT_IN_SIGHASH_TYPE vs caller sighashtype (Core SIGHASH_MISMATCH)":

  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_cffix_psbt_sighash_", "_regtest")
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

  ## A one-input PSBT spending a wallet-owned P2WPKH coin, with
  ## PSBT_IN_SIGHASH_TYPE set to `field` (none = field absent).
  ## foreignSpk: replace witness_utxo with this scriptPubKey. With
  ## keepWalletCoin=false the coin is also dropped from the wallet, so the
  ## input is someone else's; with true it stays a wallet coin whose
  ## witness_utxo misreports its scriptPubKey.
  proc makePsbt(seedByte: byte, field: Option[int32],
                foreignSpk: seq[byte] = @[],
                keepWalletCoin = false): string =
    let wOpt = wm.getWallet("tw")
    doAssert wOpt.isSome
    var w = wOpt.get().wallet
    let key = w.accounts[0].externalKeys[0]
    let spk = scriptPubKeyForAddress(key.address)
    doAssert spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14,
      "fixture must be P2WPKH"
    var txidBytes: array[32, byte]
    for i in 0 ..< 32: txidBytes[i] = byte((i + int(seedByte)) and 0xff)
    let op = OutPoint(txid: TxId(txidBytes), vout: 0'u32)
    w.addUtxo(op, TxOut(value: Satoshi(100_000_000), scriptPubKey: spk),
              height = 100, keyPath = key.path,
              isInternal = false, isCoinbase = false)
    let destAddr = w.getNewAddressStr(addrType = P2WPKH, accountIdx = -1,
                                      isChange = false)
    var inputs = newJArray()
    inputs.add(%*{"txid": reverseHexT(hexEncode(array[32, byte](op.txid))),
                  "vout": op.vout})
    var outputs = newJArray()
    var outObj = newJObject()
    outObj[destAddr] = %0.99
    outputs.add(outObj)
    var pc = newJArray()
    pc.add(inputs)
    pc.add(outputs)
    var p = fromBase64(rpc.handleMethod("walletcreatefundedpsbt", pc)["psbt"].getStr())
    doAssert p.inputs.len == 1
    p.inputs[0].sighashType = field
    if foreignSpk.len > 0:
      # Replace the UTXO data with an output the wallet holds no key for.
      p.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(100_000_000),
                                           scriptPubKey: foreignSpk))
      p.inputs[0].nonWitnessUtxo = none(Transaction)
      if not keepWalletCoin:
        w.utxos.del(op)
        doAssert op notin w.utxos
    p.toBase64()

  ## walletprocesspsbt "psbt" sign sighashtype(null = omitted) bip32derivs finalize=false
  proc process(b64: string, sign = true,
               sighash: JsonNode = newJNull()): JsonNode =
    var pp = newJArray()
    pp.add(%b64)
    pp.add(%sign)
    pp.add(sighash)
    pp.add(%true)
    pp.add(%false)
    rpc.handleMethod("walletprocesspsbt", pp)

  proc callErr(params: JsonNode): ref RpcError =
    try:
      discard rpc.handleMethod("walletprocesspsbt", params)
    except RpcError as e:
      return e
    nil

  proc onlySigHashByte(resp: JsonNode): int =
    let p = fromBase64(resp["psbt"].getStr())
    doAssert p.inputs[0].partialSigs.len == 1,
      "expected exactly one partial sig, got " & $p.inputs[0].partialSigs.len
    for _, sig in p.inputs[0].partialSigs:
      return int(sig[^1])

  proc checkMismatch(e: ref RpcError) =
    check e != nil
    if e != nil:
      check e.code == RpcDeserializationError  # -22, Core RPC_DESERIALIZATION_ERROR
      check "does not match" in e.msg
      check e.msg == "Specified sighash value does not match value stored in PSBT"

  test "PSBT_IN_SIGHASH_TYPE=NONE with default args is refused, not signed with NONE":
    let b64 = makePsbt(11, some(0x02'i32))
    var pp = newJArray()
    pp.add(%b64)                      # every other argument at its default
    let e = callErr(pp)
    if e == nil:
      # Show what master does instead: it signs with the author's NONE.
      let resp = rpc.handleMethod("walletprocesspsbt", pp)
      echo "  walletprocesspsbt succeeded: complete=", resp["complete"].getBool()
    checkMismatch(e)

  test "PSBT_IN_SIGHASH_TYPE=NONE with explicit sighashtype ALL is refused":
    let b64 = makePsbt(12, some(0x02'i32))
    var pp = newJArray()
    pp.add(%b64); pp.add(%true); pp.add(%"ALL")
    checkMismatch(callErr(pp))

  test "PSBT_IN_SIGHASH_TYPE=NONE|ANYONECANPAY with default args is refused":
    let b64 = makePsbt(13, some(0x82'i32))
    var pp = newJArray()
    pp.add(%b64)
    checkMismatch(callErr(pp))

  test "mismatch is refused with sign=false too (Core checks before signing)":
    let b64 = makePsbt(14, some(0x02'i32))
    var pp = newJArray()
    pp.add(%b64); pp.add(%false)
    checkMismatch(callErr(pp))

  test "explicit DEFAULT on a non-taproot input does not match a stored ALL":
    # Core: sighash = SIGHASH_DEFAULT (0) was given, so 1 != 0 -> mismatch.
    let b64 = makePsbt(15, some(0x01'i32))
    var pp = newJArray()
    pp.add(%b64); pp.add(%true); pp.add(%"DEFAULT")
    checkMismatch(callErr(pp))

  test "control: field absent, default args -> signs with SIGHASH_ALL (0x01)":
    let resp = process(makePsbt(21, none(int32)))
    check onlySigHashByte(resp) == 0x01

  test "control: field = ALL, default args -> signs with SIGHASH_ALL (0x01)":
    let resp = process(makePsbt(22, some(0x01'i32)))
    check onlySigHashByte(resp) == 0x01

  test "control: field = ALL, explicit ALL -> signs with SIGHASH_ALL (0x01)":
    let resp = process(makePsbt(23, some(0x01'i32)), sighash = %"ALL")
    check onlySigHashByte(resp) == 0x01

  test "control: field absent, explicit DEFAULT -> non-taproot signs with ALL (0x01)":
    let resp = process(makePsbt(24, none(int32)), sighash = %"DEFAULT")
    check onlySigHashByte(resp) == 0x01

  test "control: field = NONE, explicit NONE -> signs with SIGHASH_NONE (0x02)":
    let resp = process(makePsbt(25, some(0x02'i32)), sighash = %"NONE")
    check onlySigHashByte(resp) == 0x02

  test "control: field absent, explicit NONE -> signs with NONE and records the field":
    let resp = process(makePsbt(26, none(int32)), sighash = %"NONE")
    check onlySigHashByte(resp) == 0x02
    let p = fromBase64(resp["psbt"].getStr())
    check p.inputs[0].sighashType == some(0x02'i32)

  test "control: default args with finalize -> complete, field = ALL accepted":
    var pp = newJArray()
    pp.add(%makePsbt(27, some(0x01'i32)))
    let resp = rpc.handleMethod("walletprocesspsbt", pp)
    check resp["complete"].getBool() == true
    check resp.hasKey("hex")

  # A P2TR and a P2WPKH output whose keys the wallet does not hold.
  proc foreignP2tr(): seq[byte] =
    result = @[0x51'u8, 0x20]
    for i in 0 ..< 32: result.add(byte(0x40 + i))
  proc foreignP2wpkh(): seq[byte] =
    result = @[0x00'u8, 0x14]
    for i in 0 ..< 20: result.add(byte(0x90 + i))

  test "foreign P2WPKH input with stored NONE is refused although the wallet cannot sign it":
    # Core calls SignPSBTInput for every input with UTXO data, so the
    # mismatch fires before (and without) any key lookup.
    let b64 = makePsbt(31, some(0x02'i32), foreignP2wpkh())
    var pp = newJArray()
    pp.add(%b64)
    checkMismatch(callErr(pp))

  test "foreign P2TR input with stored ALL and default args is refused (taproot default is DEFAULT)":
    let b64 = makePsbt(32, some(0x01'i32), foreignP2tr())
    var pp = newJArray()
    pp.add(%b64)
    checkMismatch(callErr(pp))

  test "control: foreign P2TR input with stored DEFAULT (0x00) and default args is accepted":
    let b64 = makePsbt(33, some(0x00'i32), foreignP2tr())
    let resp = process(b64)
    check resp["complete"].getBool() == false
    let p = fromBase64(resp["psbt"].getStr())
    check p.inputs[0].partialSigs.len == 0

  test "control: foreign P2TR input with stored ALL and explicit ALL is accepted":
    let b64 = makePsbt(34, some(0x01'i32), foreignP2tr())
    let resp = process(b64, sighash = %"ALL")
    check resp["complete"].getBool() == false

  test "default and DEFAULT signs leave PSBT_IN_SIGHASH_TYPE unset (Core sets it only for non-ALL)":
    let r1 = process(makePsbt(41, none(int32)))
    check fromBase64(r1["psbt"].getStr()).inputs[0].sighashType.isNone
    let r2 = process(makePsbt(42, none(int32)), sighash = %"DEFAULT")
    check fromBase64(r2["psbt"].getStr()).inputs[0].sighashType.isNone

  test "a PSBT signed with DEFAULT can be processed again with DEFAULT":
    # Core: no field is written for DEFAULT/ALL, so the second call has
    # nothing to mismatch against and succeeds.
    let r1 = process(makePsbt(43, none(int32)), sighash = %"DEFAULT")
    var e: ref RpcError = nil
    try:
      discard process(r1["psbt"].getStr(), sighash = %"DEFAULT")
    except RpcError as err:
      e = err
    check e == nil

  # Core takes the prevout from the wallet's own transaction before the
  # PSBT's witness_utxo (CWallet::FillPSBT fills non_witness_utxo, which
  # SignPSBTInput prefers), so a witness_utxo that misreports a wallet
  # P2WPKH coin as P2TR does not change the default sighash (ALL).
  test "wallet coin with a P2TR-misreporting witness_utxo and stored DEFAULT (0x00) is refused":
    let b64 = makePsbt(51, some(0x00'i32), foreignP2tr(), keepWalletCoin = true)
    var pp = newJArray()
    pp.add(%b64)
    checkMismatch(callErr(pp))

  test "control: wallet coin with a P2TR-misreporting witness_utxo and stored ALL is accepted":
    let b64 = makePsbt(52, some(0x01'i32), foreignP2tr(), keepWalletCoin = true)
    var e: ref RpcError = nil
    try:
      discard process(b64)
    except RpcError as err:
      e = err
    check e == nil

