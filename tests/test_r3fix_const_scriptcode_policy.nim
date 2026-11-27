## r3fix-nimrod-const-scriptcode-policy: the mempool checks scripts with
## SCRIPT_VERIFY_CONST_SCRIPTCODE, and legacy CHECKSIG runs FindAndDelete
## before the signature/pubkey encoding checks, for an empty sig too.
##
## Core v31.1:
##   policy/policy.h:118-128  STANDARD_SCRIPT_VERIFY_FLAGS includes
##                            SCRIPT_VERIFY_CONST_SCRIPTCODE (policy only).
##   script/interpreter.cpp:474-476  OP_CODESEPARATOR in a BASE script is
##                            SCRIPT_ERR_OP_CODESEPARATOR, even unexecuted.
##   script/interpreter.cpp:326-336  EvalChecksigPreTapscript: in BASE,
##                            FindAndDelete(scriptCode, CScript() << vchSig)
##                            first (an empty sig is OP_0); found > 0 with the
##                            flag is SIG_FINDANDDELETE, BEFORE
##                            CheckSignatureEncoding / CheckPubKeyEncoding.
##
## Found by the R3 generating differential fuzzer, night 1 (seed 739943,
## hashhog#320), nimrod group G2. The mempool cases below fail on nimrod
## master: three are spends master ACCEPTS where Core refuses, the rest are
## refusals that name the wrong ScriptError. The interpreter cases pin that
## block-flag (consensus) outcomes do not move.
##
## Command:  nim c -r tests/test_r3fix_const_scriptcode_policy.nim

import unittest2
import std/[os, tempfiles, strutils]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/mining/fees

const
  # secp256k1 generator G, compressed: a valid STRICTENC pubkey.
  GHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  Coin = 100_000_000'i64
  CodesepText = "Using OP_CODESEPARATOR in non-witness script"
  FadText = "Signature is found in scriptCode"

proc hexToSeq(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add(byte(parseHexInt(s[i .. i + 1])))

proc push(d: seq[byte]): seq[byte] =
  doAssert d.len < 0x4c
  if d.len == 0: return @[0x00'u8]
  @[byte(d.len)] & d

proc p2sh(redeem: seq[byte]): seq[byte] =
  let h = hash160(redeem)
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc p2wsh(ws: seq[byte]): seq[byte] =
  let h = sha256(ws)
  @[byte(0x00), 0x20] & @h

let gPub = hexToSeq(GHex)

# A DER-valid low-S signature (r=1, s=1) with an UNDEFINED hashtype 0x00:
# STRICTENC's SIG_HASHTYPE in nimrod master's order.
let sigBadHashtype = @[byte(0x30), 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]
# Not DER at all: SIG_DER in nimrod master's order.
let sigNotDer = @[byte(0x01), 0x02, 0x01]

# Redeem / witness scripts, one coinbase output each (index = position).
let redeems = @[
  # 0: control, plain P2SH(OP_1)
  @[byte(OP_1)],
  # 1: hostile, P2SH(OP_CODESEPARATOR OP_1) -- nimrod master accepts
  @[byte(OP_CODESEPARATOR), OP_1],
  # 2: hostile, P2SH(OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF OP_1): unexecuted
  #    codeseparator -- nimrod master accepts
  @[byte(OP_0), OP_IF, OP_CODESEPARATOR, OP_ENDIF, OP_1],
  # 3: minimised night-1 case, P2SH(OP_CODESEPARATOR OP_WITHIN)
  @[byte(OP_CODESEPARATOR), OP_WITHIN],
  # 4: hostile, P2SH(OP_0 <G> CHECKSIG NOT) -- nimrod master accepts
  @[byte(OP_0)] & push(gPub) & @[byte(OP_CHECKSIG), OP_NOT],
  # 5: R5, P2SH(OP_0 OP_0 CHECKSIG NOT): master says PUBKEYTYPE
  @[byte(OP_0), OP_0, OP_CHECKSIG, OP_NOT],
  # 6: R8, P2SH(<sigBadHashtype> DROP <G> CHECKSIG NOT), scriptSig pushes the
  #    same sig: master says SIG_HASHTYPE
  push(sigBadHashtype) & @[byte(OP_DROP)] & push(gPub) & @[byte(OP_CHECKSIG), OP_NOT],
  # 7: R14, as 6 with a non-DER sig: master says SIG_DER
  push(sigNotDer) & @[byte(OP_DROP)] & push(gPub) & @[byte(OP_CHECKSIG), OP_NOT],
]
# 8: control, P2WSH(OP_CODESEPARATOR OP_1): CONST_SCRIPTCODE is BASE-only
let wsCodesep = @[byte(OP_CODESEPARATOR), OP_1]

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), 0]
  var outs: seq[TxOut]
  for r in redeems:
    outs.add TxOut(value: Satoshi(Coin), scriptPubKey: p2sh(r))
  outs.add TxOut(value: Satoshi(Coin), scriptPubKey: p2wsh(wsCodesep))
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: outs, witnesses: @[], lockTime: 0)

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
  result.dir = createTempDir("nimrod_r3fix_const_scriptcode_", "")
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

proc spend(f: Fx, vout: int, scriptSig: seq[byte],
           witness: seq[seq[byte]] = @[]): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: f.cb[1].txid(), vout: uint32(vout)),
                   scriptSig: scriptSig, sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(Coin - 10_000),
                     scriptPubKey: p2sh(@[byte(OP_1)]))],
    witnesses: (if witness.len > 0: @[witness] else: @[]), lockTime: 0)

proc p2shSpend(f: Fx, idx: int, extra: seq[byte] = @[]): Transaction =
  f.spend(idx, extra & push(redeems[idx]))

proc coreState(tx: Transaction, text: string): string =
  ## Core's state.ToString() for an input-0 policy script failure.
  let prev = tx.inputs[0].prevOut
  "mempool-script-verify-flag-failed (" & text & "), input 0 of " &
    $tx.txid() & " (wtxid " & $tx.wtxid() & "), spending " &
    $prev.txid & ":" & $prev.vout

proc accept(f: Fx, tx: Transaction): MempoolResult[TxId] =
  f.rpc.mempool.acceptTransaction(tx, f.rpc.crypto)

suite "r3fix const-scriptcode: mempool flags":
  test "standardScriptVerifyFlags includes sfConstScriptCode":
    check sfConstScriptCode in standardScriptVerifyFlags({sfP2SH, sfWitness})

suite "r3fix const-scriptcode: controls the mempool accepts":
  test "control: P2SH(OP_1) spend is accepted":
    var f = setup()
    let r = f.accept(f.p2shSpend(0))
    check r.isOk
    f.teardown()

  test "control: P2WSH(OP_CODESEPARATOR OP_1) spend is accepted (witness v0 is not BASE)":
    var f = setup()
    let tx = f.spend(redeems.len, @[], @[wsCodesep])
    let r = f.accept(tx)
    check r.isOk
    f.teardown()

suite "r3fix const-scriptcode: OP_CODESEPARATOR in a BASE script":
  test "P2SH(OP_CODESEPARATOR OP_1) is refused with OP_CODESEPARATOR":
    var f = setup()
    let tx = f.p2shSpend(1)
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, CodesepText)
    f.teardown()

  test "P2SH(OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF OP_1): unexecuted codeseparator is refused":
    var f = setup()
    let tx = f.p2shSpend(2)
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, CodesepText)
    f.teardown()

  test "minimised night-1 case P2SH(OP_CODESEPARATOR OP_WITHIN): OP_CODESEPARATOR, not INVALID_STACK_OPERATION":
    var f = setup()
    let tx = f.p2shSpend(3)
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, CodesepText)
    f.teardown()

suite "r3fix const-scriptcode: CHECKSIG FindAndDelete runs first":
  test "P2SH(OP_0 <G> CHECKSIG NOT): the empty sig's OP_0 is found -> SIG_FINDANDDELETE":
    var f = setup()
    let tx = f.p2shSpend(4)
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, FadText)
    f.teardown()

  test "R5 P2SH(OP_0 OP_0 CHECKSIG NOT): SIG_FINDANDDELETE, not PUBKEYTYPE":
    var f = setup()
    let tx = f.p2shSpend(5)
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, FadText)
    f.teardown()

  test "R8 sig with undefined hashtype found in scriptCode: SIG_FINDANDDELETE, not SIG_HASHTYPE":
    var f = setup()
    let tx = f.p2shSpend(6, push(sigBadHashtype))
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, FadText)
    f.teardown()

  test "R14 non-DER sig found in scriptCode: SIG_FINDANDDELETE, not SIG_DER":
    var f = setup()
    let tx = f.p2shSpend(7, push(sigNotDer))
    let r = f.accept(tx)
    check not r.isOk
    check r.error == coreState(tx, FadText)
    f.teardown()

# ---------------------------------------------------------------------------
# Consensus: block flags never carry CONST_SCRIPTCODE, and FindAndDelete
# still strips the sig from the legacy sighash's scriptCode.
# ---------------------------------------------------------------------------

proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32:
    result[i] = 0
  result[31] = b

proc derInt(v: openArray[byte]): seq[byte] =
  var b = @v
  while b.len > 1 and b[0] == 0 and (b[1] and 0x80) == 0:
    b.delete(0)
  if (b[0] and 0x80) != 0:
    b.insert(0'u8, 0)
  result = @[0x02'u8, byte(b.len)] & b

proc compactToDer(sig: Signature, hashType: byte): seq[byte] =
  var r, s: array[32, byte]
  copyMem(addr r[0], unsafeAddr sig[0], 32)
  copyMem(addr s[0], unsafeAddr sig[32], 32)
  let body = derInt(r) & derInt(s)
  result = @[0x30'u8, byte(body.len)] & body & @[hashType]

proc bareTx(): Transaction =
  Transaction(version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: default(TxId), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
    witnesses: @[], lockTime: 0)

proc selfSigCase(): tuple[spk, scriptSig: seq[byte], tx: Transaction] =
  ## scriptPubKey = <s> OP_DROP <k> OP_CHECKSIG, scriptSig = <s>.
  ## The legacy sighash covers the scriptCode with <s> FindAndDelete'd
  ## (OP_DROP <k> OP_CHECKSIG), so a sig made over that verifies only while
  ## FindAndDelete still strips <s> before the sighash (a sig over the
  ## unstripped script would have to contain itself).
  let k = derivePublicKey(mkPriv(0x21))
  let tail = @[byte(OP_DROP)] & push(@k) & @[byte(OP_CHECKSIG)]
  var tx = bareTx()
  # The legacy sighash blanks every scriptSig, so sign before setting it.
  let sighash = computeSighashLegacy(tx, 0, tail, 1'u32)
  let s = compactToDer(sign(mkPriv(0x21), sighash), 0x01)
  tx.inputs[0].scriptSig = push(s)
  (push(s) & tail, push(s), tx)

let blockFlags = getBlockScriptFlags(200, regtestParams())

suite "r3fix const-scriptcode: consensus (block flags) outcomes unchanged":
  test "block flags carry no CONST_SCRIPTCODE":
    check sfConstScriptCode notin blockFlags

  test "P2SH(OP_CODESEPARATOR OP_1) is consensus-valid":
    let r = redeems[1]
    let ss = push(r)
    var tx = bareTx()
    tx.inputs[0].scriptSig = ss
    check verifyScriptWithError(ss, p2sh(r), tx, 0, Satoshi(0), blockFlags) == seOk
    check verifyScript(ss, p2sh(r), tx, 0, Satoshi(0), blockFlags)

  test "OP_0 <G> CHECKSIG NOT is consensus-valid (empty sig, false, NOT)":
    let spk = redeems[4]
    var tx = bareTx()
    check verifyScriptWithError(@[], spk, tx, 0, Satoshi(0), blockFlags) == seOk
    check verifyScript(@[], spk, tx, 0, Satoshi(0), blockFlags)

  test "OP_0 OP_0 CHECKSIG NOT is consensus-valid":
    let spk = redeems[5]
    var tx = bareTx()
    check verifyScriptWithError(@[], spk, tx, 0, Satoshi(0), blockFlags) == seOk

  test "sig signed over the FindAndDelete-stripped scriptCode verifies under block flags":
    let c = selfSigCase()
    check verifyScriptWithError(c.scriptSig, c.spk, c.tx, 0, Satoshi(0), blockFlags) == seOk
    check verifyScript(c.scriptSig, c.spk, c.tx, 0, Satoshi(0), blockFlags)

  test "the same valid self-sig is SIG_FINDANDDELETE once CONST_SCRIPTCODE is set":
    let c = selfSigCase()
    check verifyScriptWithError(c.scriptSig, c.spk, c.tx, 0, Satoshi(0),
                                blockFlags + {sfConstScriptCode}) == seSigFindAndDelete
