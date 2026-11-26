## Witness v1 branch order and Pay-to-Anchor spends match Core v31.1
## (2026-11-24 Neon audit of nimrod, finding 5).
##
## Core VerifyWitnessProgram (interpreter.cpp:1947-1998):
##   v1 && 32-byte program && !is_p2sh   -> Taproot (succeeds at once when
##                                           SCRIPT_VERIFY_TAPROOT is off)
##   !is_p2sh && IsPayToAnchor            -> succeeds
##   anything else                        -> DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
##                                           under that flag, else succeeds
## nimrod's bool verifyScript (the mempool verdict) returned true for every
## non-32-byte v1 program, so a P2SH-wrapped P2A or P2SH-wrapped v1/20 spend
## passed nimrod's mempool where Core refuses it; its error twin let P2SH-P2A
## through as well; and a native v1/32 program with TAPROOT off fell into the
## DISCOURAGE branch.
##
## Core's Solver classifies OP_1 <4e73> as ANCHOR (solver.cpp), which
## AreInputsStandard allows; nimrod classified it WITNESS_UNKNOWN and its
## mempool refused every native P2A spend "witness program is undefined".

import unittest2
import std/[os, tempfiles, strutils]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter

const
  Coin = 5_000_000_000'i64
  P2ARedeem = @[0x51'u8, 0x02, 0x4e, 0x73]
  PolicyFlags = {sfP2SH, sfWitness, sfTaproot, sfDiscourageUpgradableWitnessProgram}

proc p2sh(redeem: seq[byte]): seq[byte] =
  @[0xa9'u8, 0x14] & @(hash160(redeem)) & @[0x87'u8]

proc v1Program(n: int): seq[byte] =
  result = @[0x51'u8, byte(n)]
  for i in 0 ..< n: result.add byte(i + 1)

proc spendTx(scriptSig: seq[byte]): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
                   scriptSig: scriptSig, sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
    witnesses: @[@[]], lockTime: 0)

proc both(scriptSig, spk: seq[byte], flags: set[ScriptFlags]):
    tuple[ok: bool, err: ScriptError] =
  let tx = spendTx(scriptSig)
  (ok: verifyScript(scriptSig, spk, tx, 0, Satoshi(1000), flags, @[]),
   err: verifyScriptWithError(scriptSig, spk, tx, 0, Satoshi(1000), flags, @[]))

suite "N5 witness v1 branch order (interpreter)":
  test "N5a: P2SH-wrapped P2A is DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
    let r = both(@[byte(P2ARedeem.len)] & P2ARedeem, p2sh(P2ARedeem), PolicyFlags)
    check r.ok == false
    check r.err == seDiscourageUpgradableWitnessProgram

  test "N5b: P2SH-wrapped v1/20 program is DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
    let redeem = v1Program(20)
    let r = both(@[byte(redeem.len)] & redeem, p2sh(redeem), PolicyFlags)
    check r.ok == false
    check r.err == seDiscourageUpgradableWitnessProgram

  test "N5i: native v1/20 program is DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM (sub-claim 1)":
    let r = both(@[], v1Program(20), PolicyFlags)
    check r.ok == false
    check r.err == seDiscourageUpgradableWitnessProgram

  test "N5c: native v1/32 with TAPROOT off succeeds even under DISCOURAGE":
    let r = both(@[], v1Program(32),
                 {sfP2SH, sfWitness, sfDiscourageUpgradableWitnessProgram})
    check r.ok == true
    check r.err == seOk

  test "N5d: control: native P2A succeeds under DISCOURAGE":
    let r = both(@[], P2ARedeem, PolicyFlags)
    check r.ok == true
    check r.err == seOk

  test "N5e: control: P2SH-wrapped P2A succeeds without DISCOURAGE (consensus flags)":
    let r = both(@[byte(P2ARedeem.len)] & P2ARedeem, p2sh(P2ARedeem),
                 {sfP2SH, sfWitness, sfTaproot})
    check r.ok == true
    check r.err == seOk

  test "N5f: control: native v1/32 with TAPROOT on and no witness fails":
    let r = both(@[], v1Program(32), PolicyFlags)
    check r.ok == false

# ---------------------------------------------------------------------------
# Mempool
# ---------------------------------------------------------------------------

proc coinbaseTx(height: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: @[0x01'u8, byte(height and 0xff), 0x01, 0],
                   sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(Coin div 2), scriptPubKey: P2ARedeem),
               TxOut(value: Satoshi(Coin div 2), scriptPubKey: p2sh(P2ARedeem))],
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
  cs: ChainState
  mp: Mempool
  cb: seq[Transaction]

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_neon_witness_v1_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  result.mp = newMempool(result.cs, params)

proc teardown(f: var Fx) =
  f.cs.close()
  removeDir(f.dir)

proc spendOut(f: Fx, h: int, vout: uint32, scriptSig: seq[byte]): Transaction =
  let p2shTrue = p2sh(@[0x51'u8])
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: f.cb[h].txid(), vout: vout),
                   scriptSig: scriptSig, sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(Coin div 2 - 50_000), scriptPubKey: p2shTrue)],
    witnesses: @[], lockTime: 0)

suite "N5 mempool: native P2A spends are standard, P2SH-P2A spends are not":
  test "N5g: a native P2A spend is accepted (Core: TxoutType::ANCHOR)":
    var f = setup()
    defer: f.teardown()
    let r = f.mp.acceptTransaction(f.spendOut(1, 0, @[]), newCryptoEngine())
    if not r.isOk: checkpoint r.error
    check r.isOk

  test "N5h: a P2SH-wrapped P2A spend is refused at the policy script check":
    var f = setup()
    defer: f.teardown()
    let tx = f.spendOut(2, 1, @[byte(P2ARedeem.len)] & P2ARedeem)
    let r = f.mp.acceptTransaction(tx, newCryptoEngine())
    check not r.isOk
    if not r.isOk:
      check r.error.startsWith("mempool-script-verify-flag-failed")
