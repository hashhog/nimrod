## Truncated OP_PUSHDATA1/2/4 in sigop counting (2026-11-24 Neon audit of
## nimrod, finding 3).
##
## Core v31.1 walks scripts with CScript::GetOp, which FAILS when a
## PUSHDATA1/2/4 lacks its length bytes or its payload:
##   - CScript::GetSigOpCount (script.cpp:159-181) stops counting (`break`);
##   - CScript::IsPushOnly (script.cpp) returns false;
##   - CScript::GetSigOpCount(scriptSig) for P2SH returns 0 (script.cpp:183-204).
## nimrod's countScriptSigops fell through on a truncated length and read the
## length bytes as opcodes, so `6a 4e ae ae ae` (OP_RETURN, PUSHDATA4 missing
## a length byte) counted 60 legacy sigops where Core counts 0. A coinbase
## with 334 such outputs is 80,160 sigop cost in nimrod (> 80,000,
## bad-blk-sigops) and 0 in Core: a valid block nimrod rejects. The P2SH /
## witness-P2SH helpers (isPushOnly, getLastPushData) had the same gap.

import std/options
import unittest2
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/storage/chainstate

const
  TruncOpReturn = @[0x6a'u8, 0x4e, 0xae, 0xae, 0xae]   # OP_RETURN PUSHDATA4(3 of 4 len bytes)
  PlainMultisig = @[0x6a'u8, 0xae, 0xae, 0xae]         # OP_RETURN + 3x CHECKMULTISIG (control)

proc coinbaseWith(spk: seq[byte], n: int): Transaction =
  var outs: seq[TxOut] = @[]
  for _ in 0 ..< n:
    outs.add(TxOut(value: Satoshi(0'i64), scriptPubKey: spk))
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x01), byte(0x00)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: outs, witnesses: @[], lockTime: 0)

proc mineRegtestBlock(coinbase: Transaction): Block =
  let mroot = merkleRoot(@[array[32, byte](coinbase.txid())])
  var hdr = BlockHeader(version: 4, prevBlock: BlockHash(default(array[32, byte])),
    merkleRoot: mroot, timestamp: 1_700_000_000'u32, bits: 0x207fffff'u32,
    nonce: 0'u32)
  while not hashMeetsTarget(BlockHash(doubleSha256(serialize(hdr))), hdr.bits):
    hdr.nonce = hdr.nonce + 1
  Block(header: hdr, txs: @[coinbase])

proc p2shSpk(): seq[byte] =
  result = @[0xa9'u8, 0x14]
  for _ in 0 ..< 20: result.add 0x00'u8
  result.add 0x87'u8

suite "N3 countScriptSigops stops at a truncated push like GetSigOpCount":
  test "N3a: OP_RETURN PUSHDATA4 with 3 length bytes counts 0 sigops":
    check countScriptSigops(TruncOpReturn) == 0
    check countScriptSigops(TruncOpReturn, accurate = true) == 0

  test "N3b: PUSHDATA2 with 1 length byte counts 0 sigops":
    check countScriptSigops(@[0x4d'u8, 0xac]) == 0

  test "N3c: PUSHDATA1 with no length byte stops; earlier sigops still count":
    check countScriptSigops(@[0xac'u8, 0x4c]) == 1
    check countScriptSigops(@[0xac'u8, 0x4d, 0xac]) == 1

  test "N3d: control: OP_RETURN followed by 3 bare CHECKMULTISIG counts 60":
    check countScriptSigops(PlainMultisig) == 60

  test "N3e: control: a complete PUSHDATA2 still skips its payload":
    check countScriptSigops(@[0x4d'u8, 0x02, 0x00, 0xac, 0xac, 0xac]) == 1

suite "N3 block level: 334 truncated-push outputs are not bad-blk-sigops":
  let params = regtestParams()

  test "N3f: coinbase with 334 x `6a 4e ae ae ae` passes checkBlock (Core: 0 sigops)":
    let blk = mineRegtestBlock(coinbaseWith(TruncOpReturn, 334))
    let res = checkBlock(blk, params)
    check res.isOk

  test "N3g: getLegacySigOpCount of that coinbase is 0":
    check getLegacySigOpCount(coinbaseWith(TruncOpReturn, 334)) == 0

  test "N3h: control: 334 x `6a ae ae ae` (no truncated push) is bad-blk-sigops":
    let blk = mineRegtestBlock(coinbaseWith(PlainMultisig, 334))
    let res = checkBlock(blk, params)
    check (not res.isOk)
    check res.error == veSigopExceeded

suite "N3 P2SH helpers treat a truncated scriptSig like GetOp failure":
  test "N3i: isPushOnly is false for a truncated push":
    check validation.isPushOnly(@[0x05'u8, 0xaa]) == false     # payload short
    check validation.isPushOnly(@[0x4c'u8]) == false           # no length byte
    check validation.isPushOnly(@[0x51'u8, 0x4d, 0x01]) == false

  test "N3j: control: isPushOnly is true for complete pushes":
    check validation.isPushOnly(@[0x00'u8, 0x51, 0x02, 0xaa, 0xbb, 0x4c, 0x00])

  test "N3k: P2SH sigops are 0 when the scriptSig ends in a truncated push":
    # scriptSig = <push redeem=[CHECKSIG]> PUSHDATA2(no length bytes)
    let scriptSig = @[0x01'u8, 0xac, 0x4d]
    let tx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
                     scriptSig: scriptSig, sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[0x51'u8])],
      witnesses: @[], lockTime: 0)
    let spk = p2shSpk()
    let lookup = proc(op: OutPoint): Option[UtxoEntry] =
      some(UtxoEntry(output: TxOut(value: Satoshi(1000), scriptPubKey: spk),
                     height: 1, isCoinbase: false))
    check getP2SHSigOpCount(tx, lookup) == 0

  test "N3l: control: the same scriptSig without the stray byte counts 1":
    let tx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
                     scriptSig: @[0x01'u8, 0xac], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[0x51'u8])],
      witnesses: @[], lockTime: 0)
    let spk = p2shSpk()
    let lookup = proc(op: OutPoint): Option[UtxoEntry] =
      some(UtxoEntry(output: TxOut(value: Satoshi(1000), scriptPubKey: spk),
                     height: 1, isCoinbase: false))
    check getP2SHSigOpCount(tx, lookup) == 1

  test "N3m: P2SH-P2WSH witness sigops are 0 when the scriptSig is not push-only":
    var program = @[0x00'u8, 0x20]
    for _ in 0 ..< 32: program.add 0x00'u8
    let scriptSig = @[byte(program.len)] & program & @[0x4c'u8]
    let witness = @[@[0xac'u8]]                       # witnessScript = CHECKSIG
    check countWitnessSigOpsForInput(scriptSig, p2shSpk(), witness) == 0
    let clean = @[byte(program.len)] & program
    check countWitnessSigOpsForInput(clean, p2shSpk(), witness) == 1
