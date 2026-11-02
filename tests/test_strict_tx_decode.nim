## decoderawtransaction / sendrawtransaction / testmempoolaccept must apply
## Core's DecodeTx rule: a hex tx decodes only if the parse consumes the WHOLE
## stream, and `iswitness` (decoderawtransaction) forces witness / no-witness.
##
## Found by the Core regtest ratchet (node_error rows, 2026-11-02):
##   operator/decoderawtransaction/trailing,
##   operator/decoderawtransaction/segwit-iswitness-false,
##   operator/sendrawtransaction/trailing,
##   operator/testmempoolaccept/trailing
## Core answered -22 "TX decode failed"; nimrod ignored the trailing byte and
## ignored `iswitness`, and returned a decoded tx.
##
## References: bitcoin-core/src/core_read.cpp DecodeTx,
##             bitcoin-core/src/rpc/rawtransaction.cpp decoderawtransaction,
##             bitcoin-core/src/rpc/mempool.cpp testmempoolaccept.

import unittest2
import std/[json, strutils]
import ../src/rpc/server
import ../src/primitives/[types, serialize]

const
  # 1-in/1-out segwit tx (P2WPKH spend, 1-byte-per-witness-item dummy sig).
  SegwitTx = "02000000000101" & "11".repeat(32) & "00000000" & "00" &
    "fdffffff01" & "f0ca052a01000000" & "16" & "0014" & "22".repeat(20) &
    "02" & "01" & "aa" & "01" & "bb" & "00000000"
  # Same shape, legacy (no witness).
  LegacyTx = "02000000" & "01" & "11".repeat(32) & "00000000" & "00" &
    "fdffffff01" & "f0ca052a01000000" & "16" & "0014" & "22".repeat(20) &
    "00000000"

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc srv(): RpcServer =
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

template rpcErr(body: untyped): tuple[code: int, msg: string] =
  var captured = (code: 0, msg: "(no error - call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

suite "strict transaction decode (Core DecodeTx)":
  test "decoderawtransaction accepts exact segwit and legacy hex":
    check srv().handleMethod("decoderawtransaction", %*[SegwitTx])["txid"].getStr().len == 64
    check srv().handleMethod("decoderawtransaction", %*[LegacyTx])["txid"].getStr().len == 64

  test "decoderawtransaction rejects trailing bytes with -22":
    for raw in [SegwitTx & "00", LegacyTx & "00"]:
      let e = rpcErr(srv().handleMethod("decoderawtransaction", %*[raw]))
      check e.code == -22
      check e.msg == "TX decode failed"

  test "decoderawtransaction iswitness=false rejects a segwit tx":
    let e = rpcErr(srv().handleMethod("decoderawtransaction", %*[SegwitTx, false]))
    check e.code == -22
    check e.msg == "TX decode failed"

  test "decoderawtransaction iswitness honoured for legacy / explicit true":
    check srv().handleMethod("decoderawtransaction", %*[LegacyTx, false])["vin"].len == 1
    check srv().handleMethod("decoderawtransaction", %*[LegacyTx, true])["vin"].len == 1
    check srv().handleMethod("decoderawtransaction", %*[SegwitTx, true])["vin"].len == 1

  test "sendrawtransaction rejects trailing bytes with -22":
    let e = rpcErr(srv().handleMethod("sendrawtransaction", %*[SegwitTx & "00"]))
    check e.code == -22
    check e.msg == "TX decode failed. Make sure the tx has at least one input."

  test "testmempoolaccept rejects trailing bytes with -22":
    let e = rpcErr(srv().handleMethod("testmempoolaccept", %*[[SegwitTx & "00"]]))
    check e.code == -22
    check e.msg.startsWith("TX decode failed: ")

  test "legacy decode keeps witnesses empty (no segwit marker on re-serialize)":
    # Regression guard: an empty-but-allocated witnesses seq made serialize()
    # emit 0001 marker bytes, corrupting gbt `data` and getrawtransaction hex.
    let raw = hexToBytes(LegacyTx)
    let tx = deserializeTransactionExact(raw)
    check tx.witnesses.len == 0
    check serialize(tx, includeWitness = true) == raw

  test "deserializeTransactionExact: segwit round-trips, trailing byte raises":
    let raw = hexToBytes(SegwitTx)
    check serialize(deserializeTransactionExact(raw), includeWitness = true) == raw
    expect SerializationError:
      discard deserializeTransactionExact(raw & @[0'u8])
