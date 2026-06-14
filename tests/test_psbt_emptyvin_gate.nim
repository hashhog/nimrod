## Regression: un-gated witness-first decode silently DROPS outputs on an
## empty-vin tx (the leading 0x00 vin-count is mis-read as a segwit marker,
## the witness parse "succeeds" with trailing output bytes UNCONSUMED, and the
## legacy fallback never fires). Same bug class as nimrod converttopsbt
## (cc3be5d) — this guards the two remaining instances:
##   1. src/rpc/server.nim handleFundRawTransaction (full-consumption gate)
##   2. src/wallet/psbt.nim deserialize / fromBase64 global unsigned tx
##      (Core psbt.h: the global unsigned tx is TX_NO_WITNESS / legacy).
##
## Fixture: 0200000000010000000000000000066a040001020300000000
##   version 2 | 0 inputs | 1 output (value 0, scriptPubKey 6a0400010203 =
##   OP_RETURN push<00010203>) | locktime 0. A correct decode yields 0 inputs
##   + 1 output; the buggy witness-first decode yields 0/0.

import unittest2
import std/[strutils, options]
import ../src/primitives/[types, serialize]
import ../src/wallet/psbt

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc toHex(bytes: seq[byte]): string =
  for b in bytes:
    result.add(toHex(int(b), 2).toLowerAscii())

const
  EMPTY_VIN_TX_HEX = "0200000000010000000000000000066a040001020300000000"
  OP_RETURN_SPK_HEX = "6a0400010203"

suite "empty-vin witness-first decode gate (fundraw + psbt)":

  test "fixture: witness-first decode is the BUG (drops the output)":
    # Proves the test is non-vacuous: the un-gated witness-aware decoder
    # mis-reads the leading 0x00 as a segwit marker and loses the output,
    # and the result does NOT re-serialize back to the raw bytes.
    let raw = hexToBytes(EMPTY_VIN_TX_HEX)
    let buggy = deserializeTransaction(raw)
    check buggy.outputs.len == 0          # output silently dropped
    check serialize(buggy, includeWitness = true) != raw  # not fully consumed

  test "legacy-forced decoder preserves the OP_RETURN output":
    let raw = hexToBytes(EMPTY_VIN_TX_HEX)
    let tx = deserializeTransactionLegacyForced(raw)
    check tx.inputs.len == 0
    check tx.outputs.len == 1
    check tx.outputs[0].value == Satoshi(0)
    check toHex(tx.outputs[0].scriptPubKey) == OP_RETURN_SPK_HEX
    check tx.lockTime == 0'u32

  test "fundrawtransaction gate: witness decode rejected, legacy used":
    # Replicates handleFundRawTransaction's full-consumption gate exactly:
    # accept the witness-aware decode ONLY if it re-serializes to the raw
    # bytes; otherwise fall back to the legacy-forced decoder.
    let rawBytes = hexToBytes(EMPTY_VIN_TX_HEX)
    var rawTx: Transaction
    var decoded = false
    try:
      rawTx = deserializeTransaction(rawBytes)
      decoded = (serialize(rawTx, includeWitness = true) == rawBytes)
    except CatchableError:
      decoded = false
    check not decoded                     # witness path correctly rejected
    if not decoded:
      rawTx = deserializeTransactionLegacyForced(rawBytes)
    check rawTx.inputs.len == 0
    check rawTx.outputs.len == 1          # NOT 0/0
    check toHex(rawTx.outputs[0].scriptPubKey) == OP_RETURN_SPK_HEX

  test "psbt fromBase64: empty-vin unsigned tx round-trips, output preserved":
    # Build an unsigned tx with 0 inputs + 1 OP_RETURN output, wrap it in a
    # PSBT, encode to base64, and decode through fromBase64. Before the fix the
    # global-unsigned-tx witness-first decode dropped the output (0/0).
    var unsigned: Transaction
    unsigned.version = 2
    unsigned.outputs.add(TxOut(value: Satoshi(0),
                               scriptPubKey: hexToBytes(OP_RETURN_SPK_HEX)))
    unsigned.lockTime = 0

    let psbt = createPsbt(unsigned)
    let b64 = psbt.toBase64()
    let decoded = fromBase64(b64)

    check decoded.tx.isSome
    let dtx = decoded.tx.get()
    check dtx.inputs.len == 0
    check dtx.outputs.len == 1            # NOT dropped
    check dtx.outputs[0].value == Satoshi(0)
    check toHex(dtx.outputs[0].scriptPubKey) == OP_RETURN_SPK_HEX
    # And the PSBT itself tracks exactly one output map for that output.
    check decoded.outputs.len == 1
