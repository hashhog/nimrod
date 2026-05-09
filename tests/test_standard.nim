## Tests for IsStandardTx (mempool/standard.nim)
## Mirrors Bitcoin Core IsStandardTx() acceptance/rejection cases.

import unittest2
import std/options
import ../src/mempool/standard
import ../src/primitives/[types, serialize]
import ../src/script/interpreter

# A reasonable scriptPubKey: P2PKH (always standard).
proc p2pkh(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] &
    @(default(array[20, byte])) &
    @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

proc p2wpkh(): seq[byte] =
  @[byte(OP_0), 0x14] & @(default(array[20, byte]))

proc p2tr(): seq[byte] =
  @[byte(OP_1), 0x20] & @(default(array[32, byte]))

proc opReturnPayload(payload: seq[byte]): seq[byte] =
  ## OP_RETURN <push payload>
  result.add(byte(OP_RETURN))
  if payload.len < 0x4c:
    result.add(byte(payload.len))
  else:
    # OP_PUSHDATA1
    result.add(0x4c'u8)
    result.add(byte(payload.len))
  for b in payload: result.add(b)

# Build a minimal "spending" transaction (1 input, 1 output) that *passes*
# every standardness check by default. Tests then mutate fields to trigger
# specific rejections.
proc baseTx(): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0
      ),
      scriptSig: @[byte(0x00)],  # OP_0 — push-only, well under 1650
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(100_000),
      scriptPubKey: p2pkh()
    )],
    witnesses: @[],
    lockTime: 0
  )

suite "IsStandardTx — version policy":
  test "version 1 accepted":
    var tx = baseTx()
    tx.version = 1
    let r = isStandardTx(tx)
    check r.ok
    check r.reason == ""

  test "version 2 accepted":
    let r = isStandardTx(baseTx())
    check r.ok

  test "version 3 accepted (TRUC)":
    var tx = baseTx()
    tx.version = 3
    let r = isStandardTx(tx)
    check r.ok

  test "version 0 rejected":
    var tx = baseTx()
    tx.version = 0
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "version"

  test "version 4 rejected":
    var tx = baseTx()
    tx.version = 4
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "version"

suite "IsStandardTx — input policy":
  test "scriptSig too large rejected":
    var tx = baseTx()
    # 1651 bytes of OP_0 — exceeds MaxStandardScriptSigSize (1650)
    tx.inputs[0].scriptSig = newSeq[byte](1651)
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "scriptsig-size"

  test "scriptSig at boundary accepted":
    var tx = baseTx()
    tx.inputs[0].scriptSig = newSeq[byte](1650)  # all 0x00 = OP_0 = push-only
    let r = isStandardTx(tx)
    check r.ok

  test "scriptSig with non-push opcode rejected":
    var tx = baseTx()
    tx.inputs[0].scriptSig = @[byte(OP_DUP)]  # OP_DUP is not push
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "scriptsig-not-pushonly"

suite "IsStandardTx — output script types":
  test "P2PKH accepted":
    let r = isStandardTx(baseTx())
    check r.ok

  test "P2WPKH accepted":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = p2wpkh()
    let r = isStandardTx(tx)
    check r.ok

  test "P2TR accepted":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = p2tr()
    let r = isStandardTx(tx)
    check r.ok

  test "garbage scriptPubKey rejected":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = @[byte(0xff), 0xff, 0xff]
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "scriptpubkey"

suite "IsStandardTx — OP_RETURN datacarrier":
  test "single small OP_RETURN accepted":
    var tx = baseTx()
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: opReturnPayload(@[byte(0x01), 0x02, 0x03])
    )
    let r = isStandardTx(tx)
    check r.ok

  test "two OP_RETURN outputs rejected (multi-op-return)":
    var tx = baseTx()
    tx.outputs = @[
      TxOut(value: Satoshi(0), scriptPubKey: opReturnPayload(@[byte(0x01)])),
      TxOut(value: Satoshi(0), scriptPubKey: opReturnPayload(@[byte(0x02)]))
    ]
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "multi-op-return"

  test "OP_RETURN above datacarrier budget rejected":
    var tx = baseTx()
    var opts = defaultIsStandardOptions()
    opts.maxDatacarrierBytes = some(40)
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: opReturnPayload(newSeq[byte](80))  # 80B + ~3B opcodes > 40
    )
    let r = isStandardTx(tx, opts)
    check not r.ok
    check r.reason == "datacarrier"

suite "IsStandardTx — dust outputs":
  test "above-dust output accepted":
    var tx = baseTx()
    tx.outputs[0].value = Satoshi(100_000)
    let r = isStandardTx(tx)
    check r.ok

  test "single dust output accepted (ephemeral allowance)":
    # P2PKH dust threshold is 546 sats — 1 sat is dust.
    var tx = baseTx()
    tx.outputs[0].value = Satoshi(1)
    let r = isStandardTx(tx)
    # A single dust output is allowed (MAX_DUST_OUTPUTS_PER_TX = 1).
    check r.ok

  test "two dust outputs rejected":
    var tx = baseTx()
    tx.outputs = @[
      TxOut(value: Satoshi(1), scriptPubKey: p2pkh()),
      TxOut(value: Satoshi(1), scriptPubKey: p2pkh())
    ]
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "dust"

suite "IsStandardTx — bare multisig":
  proc bareMultisig1of2(): seq[byte] =
    # OP_1 <33B pk1> <33B pk2> OP_2 OP_CHECKMULTISIG
    var script = newSeq[byte]()
    script.add(byte(OP_1))
    script.add(33'u8)
    for _ in 0 ..< 33: script.add(0x02'u8)
    script.add(33'u8)
    for _ in 0 ..< 33: script.add(0x03'u8)
    script.add(byte(OP_2))
    script.add(byte(OP_CHECKMULTISIG))
    script

  test "bare 1-of-2 multisig accepted by default":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = bareMultisig1of2()
    let r = isStandardTx(tx)
    check r.ok

  test "bare multisig rejected when permitBareMultisig=false":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = bareMultisig1of2()
    var opts = defaultIsStandardOptions()
    opts.permitBareMultisig = false
    let r = isStandardTx(tx, opts)
    check not r.ok
    check r.reason == "bare-multisig"

suite "IsStandardTx — weight cap":
  test "huge tx-size rejected":
    var tx = baseTx()
    # Pad scriptSig to push past 400_000 weight units. Each scriptSig byte
    # contributes 4 weight (legacy *3 + full *1). 100_001 bytes -> 400_004+ WU.
    # That also trips scriptsig-size first; instead pad multiple inputs.
    tx.inputs = @[]
    for i in 0 ..< 410:
      tx.inputs.add(TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: uint32(i)),
        scriptSig: newSeq[byte](1000),  # 1000 zero bytes — push-only, <1650
        sequence: 0xFFFFFFFF'u32
      ))
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "tx-size"

# ---------------------------------------------------------------------------
# W58-1 regression: malformed-push OP_RETURN must be nonstandard in the
# mempool path (isStandardTx → classifyStdTxout → isStandardOpReturn).
#
# W56 (bc1e2c8) fixed getScriptType() in src/rpc/server.nim (decodescript).
# This suite verifies the mempool classifier uses the same IsPushOnly logic
# and has always been correct — and locks it in as a regression test.
#
# Test vector: hex `6a09deadbeef`
#   0x6a = OP_RETURN
#   0x09 = direct push-9-bytes  (but only 4 bytes follow → truncated)
#   0xde 0xad 0xbe 0xef        (4 bytes, 5 short of the claimed 9)
#
# Bitcoin Core `decodescript 6a09deadbeef` → "type": "nonstandard"
# ---------------------------------------------------------------------------
suite "W58-1 regression — malformed-push OP_RETURN":
  proc malformedOpReturn(): seq[byte] =
    ## OP_RETURN + push-9-bytes opcode, but only 4 data bytes follow.
    @[byte(0x6a), 0x09, 0xde, 0xad, 0xbe, 0xef]

  proc validOpReturn32(): seq[byte] =
    ## OP_RETURN + well-formed push-32-bytes (the common case).
    result = @[byte(0x6a), 0x20]  # OP_RETURN, push-32
    for i in 0 ..< 32: result.add(byte(i))

  test "malformed-push OP_RETURN classified nonstandard by isStandardOpReturn":
    let ok = isStandardOpReturn(malformedOpReturn())
    check not ok

  test "valid 32-byte OP_RETURN classified standard by isStandardOpReturn":
    let ok = isStandardOpReturn(validOpReturn32())
    check ok

  test "malformed-push OP_RETURN classified stxNonStandard by classifyStdTxout":
    let kind = classifyStdTxout(malformedOpReturn())
    check kind == stxNonStandard

  test "valid 32-byte OP_RETURN classified stxNullData by classifyStdTxout":
    let kind = classifyStdTxout(validOpReturn32())
    check kind == stxNullData

  test "isStandardTx rejects tx with malformed-push OP_RETURN output":
    ## The mempool policy gate (acceptTransaction → isStandardTx) must reject
    ## a tx whose vout contains the malformed script, not accept it as nulldata.
    var tx = baseTx()
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: malformedOpReturn()
    )
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "scriptpubkey"

  test "isStandardTx accepts tx with valid OP_RETURN output":
    ## Positive control: a well-formed OP_RETURN must still be accepted.
    var tx = baseTx()
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: validOpReturn32()
    )
    let r = isStandardTx(tx)
    check r.ok
