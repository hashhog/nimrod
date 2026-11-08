## Mempool script-check reject text parity with Bitcoin Core v31.1.
##
## Core's CheckInputScripts (validation.cpp:2119-2123) fails a mempool tx with
##   state.Invalid(TX_NOT_STANDARD,
##     strprintf("mempool-script-verify-flag-failed (%s)", ScriptErrorString(err)),
##     "input %i of %s (wtxid %s), spending %s:%i")        (validation.cpp:2021)
## whenever the flags in use include a STANDARD_NOT_MANDATORY bit (always true
## for PolicyScriptChecks, which runs STANDARD_SCRIPT_VERIFY_FLAGS), and with
## "block-script-verify-flag-failed (%s)" otherwise.  testmempoolaccept reports
## reject-reason = the token and reject-details = ToString() = "token, debug";
## submitpackage's tx-results error is ToString().
##
## The fixture spends a P2PK output with a DER-valid, low-S, SIGHASH_ALL
## signature (r=1, s=1) that does not verify: under NULLFAIL (a standard,
## non-mandatory flag) the failed CHECKSIG with a non-empty signature is
## SCRIPT_ERR_SIG_NULLFAIL -- the case tools/core-regtest seed_submitpackage
## invalid-sig-parent / invalid-sig-child exercise.
##
## Command:  nim c -r tests/test_mempool_script_verify_token.nim

import unittest2
import std/[json, os, tempfiles, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/mining/fees

const
  # secp256k1 generator G, compressed: a valid STRICTENC pubkey.
  GHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  Coin = 5_000_000_000'i64
  NullFailText = "Signature must be zero for failed CHECK(MULTI)SIG operation"

proc hexToSeq(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add(byte(parseHexInt(s[i .. i + 1])))

proc p2pkG(): seq[byte] =
  @[byte(0x21)] & hexToSeq(GHex) & @[byte(OP_CHECKSIG)]

proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc badSigScriptSig(): seq[byte] =
  # DER 30 06 02 01 01 02 01 01 + SIGHASH_ALL: strict-DER, low-S, defined
  # hashtype, does not verify against G.
  let sig = @[byte(0x30), 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
  @[byte(sig.len)] & sig

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), 0]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(Coin), scriptPubKey: p2pkG()),
               TxOut(value: Satoshi(Coin), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

type Fx = object
  dir: string
  rpc: RpcServer
  cb: seq[Transaction]

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_script_verify_token_", "")
  var cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  let mp = newMempool(cs, params)
  result.rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = params)

proc teardown(f: var Fx) =
  f.rpc.chainState.close()
  removeDir(f.dir)

proc op(tx: Transaction, vout = 0'u32): OutPoint =
  OutPoint(txid: tx.txid(), vout: vout)

proc hexBytes(data: openArray[byte]): string =
  for b in data: result.add(toHex(int(b), 2).toLowerAscii())

proc hexOf(tx: Transaction): string = hexBytes(serialize(tx, true))

proc badSpend(prev: OutPoint, value: int64, spk = p2shTrue()): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: prev, scriptSig: badSigScriptSig(),
                   sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: spk)],
    witnesses: @[], lockTime: 0)

proc trueSpend(prev: OutPoint, value: int64, spk = p2shTrue()): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[byte(0x01), byte(OP_TRUE)],
                   sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: spk)],
    witnesses: @[], lockTime: 0)

proc coreToken(): string =
  "mempool-script-verify-flag-failed (" & NullFailText & ")"

proc coreState(tx: Transaction, inputIdx: int): string =
  ## Core's state.ToString() for the failure: "<token>, <debug>".
  let prev = tx.inputs[inputIdx].prevOut
  coreToken() & ", input " & $inputIdx & " of " & $tx.txid() &
    " (wtxid " & $tx.wtxid() & "), spending " & $prev.txid & ":" & $prev.vout

suite "mempool script-check failure reads like Core's state string":
  test "mempool error is mempool-script-verify-flag-failed (<ScriptErrorString>), input N of ...":
    var f = setup()
    let tx = badSpend(f.cb[1].op(0), Coin - 10_000)
    let r = f.rpc.mempool.acceptTransaction(tx, f.rpc.crypto)
    check not r.isOk
    check r.error == coreState(tx, 0)
    f.teardown()

  test "testmempoolaccept single: reject-reason is the token, reject-details the state":
    var f = setup()
    let tx = badSpend(f.cb[1].op(0), Coin - 10_000)
    let r = f.rpc.handleMethod("testmempoolaccept", %*[[hexOf(tx)]])
    check not r[0]["allowed"].getBool()
    check r[0]["reject-reason"].getStr() == coreToken()
    check r[0].hasKey("reject-details")
    if r[0].hasKey("reject-details"):
      check r[0]["reject-details"].getStr() == coreState(tx, 0)
    f.teardown()

  test "testmempoolaccept package, invalid-sig child: accept[1] reason + details":
    var f = setup()
    let parent = trueSpend(f.cb[1].op(1), Coin - 10_000, p2pkG())
    let child = badSpend(parent.op(0), Coin - 20_000)
    let r = f.rpc.handleMethod("testmempoolaccept",
                               %*[[hexOf(parent), hexOf(child)]])
    check r[0]["allowed"].getBool()
    check not r[1]["allowed"].getBool()
    check r[1]["reject-reason"].getStr() == coreToken()
    check r[1].hasKey("reject-details")
    if r[1].hasKey("reject-details"):
      check r[1]["reject-details"].getStr() == coreState(child, 0)
    f.teardown()

  test "submitpackage, invalid-sig parent: tx-results error is the full state":
    var f = setup()
    let parent = badSpend(f.cb[1].op(0), Coin - 10_000)
    let child = trueSpend(parent.op(0), Coin - 20_000)
    let r = f.rpc.handleMethod("submitpackage", %*[[hexOf(parent), hexOf(child)]])
    let e = r["tx-results"][$parent.wtxid()]
    check e.hasKey("error")
    if e.hasKey("error"):
      check e["error"].getStr() == coreState(parent, 0)
    f.teardown()

when declared(coreScriptErrorString):
  suite "ScriptError -> Core ScriptErrorString (script/script_error.cpp)":
    test "texts match Core's ScriptErrorString":
      check coreScriptErrorString(seOk) == "No error"
      check coreScriptErrorString(seNullFail) == NullFailText
      check coreScriptErrorString(seVerify) ==
        "Script evaluated without error but finished with a false/empty top stack element"
      check coreScriptErrorString(seEqualVerify) == "Script failed an OP_EQUALVERIFY operation"
      check coreScriptErrorString(seNullDummy) == "Dummy CHECKMULTISIG argument must be zero"
      check coreScriptErrorString(seSigDer) == "Non-canonical DER signature"
      check coreScriptErrorString(seSigHighS) ==
        "Non-canonical signature: S value is unnecessarily high"
      check coreScriptErrorString(seCleanStack) == "Stack size must be exactly one after execution"
      check coreScriptErrorString(seDiscourageUpgradableNops) ==
        "NOPx reserved for soft-fork upgrades"
      check coreScriptErrorString(seWitnessPubkeyType) == "Using non-compressed keys in segwit"
      check coreScriptErrorString(seSchnorrSig) == "Invalid Schnorr signature"
    test "every ScriptError has a Core text":
      for e in ScriptError:
        check coreScriptErrorString(e).len > 0
else:
  suite "ScriptError -> Core ScriptErrorString (script/script_error.cpp)":
    test "coreScriptErrorString exists":
      check false

suite "testmempoolaccept split of a parenthesised token":
  test "mempool-script-verify-flag-failed (...), input ... splits after the ')'":
    let state = coreToken() & ", input 0 of aa (wtxid bb), spending cc:0"
    let (tok, det) = splitRejectState(state)
    check tok == coreToken()
    check det == state
  test "bare parenthesised token has no details":
    let (tok, det) = splitRejectState(coreToken())
    check tok == coreToken()
    check det == ""
