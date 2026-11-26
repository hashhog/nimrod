## Transaction wire codec parity with Core v31.1 primitives/transaction.h
## (2026-11-24 Neon audit of nimrod, finding 21).
##
##  (a) UnserializeTransaction reads `version | 00 | 00 | locktime` as a tx with
##      no inputs and no outputs: the vin is empty, the "flags" byte is 0, so it
##      reads neither vin/vout again nor witnesses. CheckTransaction then
##      rejects it bad-txns-vin-empty. nimrod threw "invalid segwit flag", so a
##      block carrying it failed to decode instead of failing with Core's reason.
##  (b) SerializeTransaction writes the 00 01 marker and witnesses only when
##      tx.HasWitness(): some input has a non-empty stack. nimrod wrote them
##      whenever `witnesses` had entries, so a legacy tx whose witnesses held
##      only empty stacks (the legacy-forced decoder, signrawtransaction*) came
##      out with a superfluous witness record that Core and nimrod's own reader
##      reject, and hashed to the wrong wtxid.

import unittest2
import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/crypto/hashing

proc legacyTx(nWitnessStacks: int): Transaction =
  result = Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 3),
                   scriptSig: @[0x51'u8], sequence: 0xFFFFFFFE'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
    lockTime: 7)
  result.witnesses = newSeq[seq[seq[byte]]](nWitnessStacks)

const ZeroInZeroOut = @[0x01'u8, 0, 0, 0,  0x00, 0x00,  0x05, 0, 0, 0]

suite "N21a 0-input/0-output transaction decodes like UnserializeTransaction":
  test "N21a1: `ver 00 00 locktime` decodes to no inputs, no outputs":
    var raised = ""
    var tx: Transaction
    try:
      tx = deserializeTransaction(ZeroInZeroOut)
    except CatchableError as e:
      raised = e.msg
    check raised == ""
    check tx.version == 1
    check tx.inputs.len == 0
    check tx.outputs.len == 0
    check tx.lockTime == 5'u32

  test "N21a2: a block carrying it decodes and checkBlock says bad-txns-vin-empty":
    let cb = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                       vout: 0xFFFFFFFF'u32),
                     scriptSig: @[0x01'u8, 0x01, 0x51], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[0x51'u8])],
      witnesses: @[], lockTime: 0)
    let empty = Transaction(version: 1, lockTime: 5)
    let mroot = merkleRoot(@[array[32, byte](cb.txid()), array[32, byte](empty.txid())])
    var hdr = BlockHeader(version: 4, prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: mroot, timestamp: 1_700_000_000'u32, bits: 0x207fffff'u32, nonce: 0)
    while not hashMeetsTarget(BlockHash(doubleSha256(serialize(hdr))), hdr.bits):
      hdr.nonce = hdr.nonce + 1
    # Wire bytes built by hand so the empty tx is exactly `01000000 00 00 05000000`.
    var raw = serialize(hdr) & @[0x02'u8] & serialize(cb, false) & ZeroInZeroOut
    var raised = ""
    var blk: Block
    try:
      blk = deserializeBlock(raw)
    except CatchableError as e:
      raised = e.msg
    check raised == ""
    if raised == "":
      check blk.txs.len == 2
      let res = checkBlock(blk, regtestParams())
      check (not res.isOk)
      if not res.isOk:
        check res.error == veVinEmpty

  test "N21a3: control: 00 02 (unknown optional data) still fails to decode":
    var raised = false
    try:
      discard deserializeTransaction(@[0x01'u8, 0, 0, 0, 0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0])
    except CatchableError:
      raised = true
    check raised

suite "N21b witness marker only when some input has a witness (HasWitness)":
  test "N21b1: empty witness stacks serialize exactly like the legacy form":
    let tx = legacyTx(1)
    check serialize(tx, true) == serialize(tx, false)

  test "N21b2: that serialization reads back (no superfluous witness record)":
    let tx = legacyTx(1)
    var raised = ""
    try:
      let back = deserializeTransaction(serialize(tx, true))
      check back.txid() == tx.txid()
    except CatchableError as e:
      raised = e.msg
    check raised == ""

  test "N21b3: wtxid of a tx without witness data equals its txid":
    let tx = legacyTx(1)
    check tx.wtxid() == tx.txid()

  test "N21b4: control: a non-empty witness still gets the marker":
    var tx = legacyTx(1)
    tx.witnesses[0] = @[@[0xAA'u8]]
    let s = serialize(tx, true)
    check s[4] == 0x00'u8
    check s[5] == 0x01'u8
    check tx.wtxid() != tx.txid()
