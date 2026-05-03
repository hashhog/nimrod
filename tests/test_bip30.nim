## BIP-30 enforcement tests
## Verifies that checkBip30 uses the correct exception heights (91842, 91880)
## and enforces the duplicate-UTXO check at all other pre-BIP34 heights.
##
## Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().

import std/[options, tables]
import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]

# Helpers
proc makeOutPoint(txidByte: byte, vout: uint32): OutPoint =
  var txidArr: array[32, byte]
  txidArr[0] = txidByte
  OutPoint(txid: TxId(txidArr), vout: vout)

proc makeMinimalTx(): Transaction =
  ## Build a minimal coinbase-like transaction with one output.
  ## (txid will be derived from the serialized form)
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffff_ffff'u32),
      scriptSig: @[0x51'u8, 0x00'u8], # 2-byte coinbase scriptSig (min length)
      sequence: 0xffff_ffff'u32
    )],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[0x51'u8])],
    lockTime: 0
  )

suite "BIP-30 exception heights":

  test "height 91842 is exempt (no rejection even with duplicate UTXO)":
    let params = mainnetParams()
    # Pre-populate a 'have' set with the txid:vout from our test tx
    var haveSet: seq[OutPoint] = @[]
    let tx = makeMinimalTx()
    let txid = tx.txid()
    haveSet.add(OutPoint(txid: txid, vout: 0))

    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    let result = checkBip30(blk, 91842'i32, params, hasUtxo)
    check result.isOk  # Must be exempt

  test "height 91880 is exempt (no rejection even with duplicate UTXO)":
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let txid = tx.txid()
    var haveSet = @[OutPoint(txid: txid, vout: 0)]

    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    let result = checkBip30(blk, 91880'i32, params, hasUtxo)
    check result.isOk  # Must be exempt

  test "height 91843 enforces BIP-30 (duplicate UTXO must be rejected)":
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let txid = tx.txid()
    var haveSet = @[OutPoint(txid: txid, vout: 0)]

    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    let result = checkBip30(blk, 91843'i32, params, hasUtxo)
    check not result.isOk
    check result.error == veBip30DuplicateOutput

  test "height 100000 (pre-BIP34) enforces BIP-30 with duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let txid = tx.txid()
    var haveSet = @[OutPoint(txid: txid, vout: 0)]

    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    let result = checkBip30(blk, 100000'i32, params, hasUtxo)
    check not result.isOk
    check result.error == veBip30DuplicateOutput

  test "height 100000 passes BIP-30 when no duplicate UTXO exists":
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} = false

    let result = checkBip30(blk, 100000'i32, params, hasUtxo)
    check result.isOk

  test "old wrong exception heights (91722, 91812) are NOT exempt":
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let txid = tx.txid()
    var haveSet = @[OutPoint(txid: txid, vout: 0)]
    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    for wrongH in [91722'i32, 91812'i32]:
      let result = checkBip30(blk, wrongH, params, hasUtxo)
      check not result.isOk
      check result.error == veBip30DuplicateOutput

  test "post-BIP34 height (228000) skips BIP-30 check (inside BIP34-implies-BIP30 range)":
    # After bip34_height (227931) and before 1,983,702 BIP-30 is skipped.
    let params = mainnetParams()
    let tx = makeMinimalTx()
    let txid = tx.txid()
    var haveSet = @[OutPoint(txid: txid, vout: 0)]
    let blk = Block(txs: @[tx], header: BlockHeader())
    let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      for o in haveSet:
        if o.txid == op.txid and o.vout == op.vout: return true
      false

    let result = checkBip30(blk, 228000'i32, params, hasUtxo)
    check result.isOk  # BIP-34 active: skip BIP-30 check
