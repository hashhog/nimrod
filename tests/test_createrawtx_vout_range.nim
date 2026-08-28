## createrawtransaction — `vout` must be range-checked against int32
##
## THE DEFECT (regression pinned by this suite)
## --------------------------------------------
## `createrawtransaction`'s input parser only asked "is vout negative?".  It
## never asked "is vout too big?".  The value was then narrowed to the 32-bit
## `vout` field of the outpoint, so anything at or above 2^32 silently WRAPPED:
##
##     vout 4294967296 (2^32)   -->  outpoint index 0
##     vout 8589934592 (2^33)   -->  outpoint index 0
##
## Both were observed on the live mainnet node.  The RPC returned SUCCESS and a
## perfectly well-formed transaction hex — one that spends a COMPLETELY
## DIFFERENT outpoint from the one the caller asked for, and index 0 of a real
## txid is very likely a real, fundable output.  A caller that signs and
## broadcasts what it was handed spends the wrong coin, with no error and no
## log line anywhere.  Silent redirection of a spend is the worst shape a bug
## can take in this RPC.
##
## WHAT BITCOIN CORE DOES
## ----------------------
## Core reads the field with `find_value(o, "vout").getInt<int>()` —
## `int`, i.e. THIRTY-TWO bits (bitcoin-core/src/rpc/rawtransaction_util.cpp,
## AddInputs:38-45).  univalue's `getInt<Int>` (src/univalue/include/univalue.h)
## range-checks the parsed integer against the destination type and throws
## `std::runtime_error("JSON integer out of range")` when it does not fit; the
## RPC layer surfaces that as RPC_MISC_ERROR (-1).
##
## The ORDERING IS DELIBERATE AND IS UNIVALUE'S, NOT OURS: the range check
## lives inside the *conversion*, so it fires BEFORE the handler's own
## `if (nOutput < 0) throw ... "vout cannot be negative"` sign test ever runs.
## That is why -1 gets the vout-specific -8 message while 2147483648 — also
## "not a valid vout" in any human sense — gets the generic -1
## "JSON integer out of range" instead.  Matching Core here means matching that
## order, not just the two checks.
##
## The fix therefore adds, BEFORE the existing sign test:
##     if nOutput < low(int32) or nOutput > high(int32):
##       raise newRpcError(RpcMiscError, "JSON integer out of range")
##
## TEETH
## -----
## Cases 1-6 are all rejections, and a handler that rejected EVERY input would
## satisfy every one of them.  The two CONTROL cases exist to make that
## impossible: they drive the real handler to success and then DECODE the
## returned hex with the node's own deserializer, asserting the outpoint index
## that actually landed in the bytes.  In particular the int32-MAX control
## (2147483647) fails loudly if the new bound is off by one in the tight
## direction.
##
## References:
##   bitcoin-core/src/rpc/rawtransaction_util.cpp:38-45   AddInputs
##   bitcoin-core/src/univalue/include/univalue.h         getInt<Int>
##   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
##                                                        RPC_INVALID_PARAMETER = -8

import std/[unittest, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/rpc/server

const
  # Well-formed 64-hex txid; content is irrelevant, createrawtransaction never
  # looks it up (it builds an UNSIGNED tx and touches no chainstate).
  TestTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  Int32Max = 2147483647
  Int32MaxPlus1 = 2147483648'i64
  TwoPow32 = 4294967296'i64
  TwoPow33 = 8589934592'i64

proc minimalRpcServer(): RpcServer =
  ## createrawtransaction builds an unsigned transaction from its arguments
  ## alone — no chainstate, no mempool, no wallet — so a bare RpcServer is
  ## enough to drive the REAL handler (same rig as test_w135_parsehashv_neg8).
  RpcServer(port: 0, running: false, blockSubmissionPaused: false)

proc hexToBytesLocal(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc outputsObj(): JsonNode =
  ## A single OP_RETURN output. Deliberately data-only: it keeps the test
  ## independent of address encoding/network so a failure can only mean the
  ## input parser, never the output parser.
  %*{"data": "deadbeef"}

proc callCreateRaw(inputs: JsonNode): JsonNode =
  minimalRpcServer().handleMethod("createrawtransaction",
                                  %*[inputs, outputsObj()])

proc callCreateRawFull(params: JsonNode): JsonNode =
  minimalRpcServer().handleMethod("createrawtransaction", params)

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  ## Returns (0, "(no error)") when the call SUCCEEDS — so a test that expects
  ## a rejection fails loudly rather than silently passing on a success.
  var captured = (code: 0, msg: "(no error — call succeeded)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    captured = (code: -32603, msg: "unexpected exception: " & e.msg)
  captured

proc voutErr(v: int64): tuple[code: int, msg: string] =
  captureRpcError(callCreateRaw(%*[{"txid": TestTxid, "vout": v}]))

proc firstInputVout(txHex: string): uint32 =
  ## Decode with the node's own transaction deserializer and report the
  ## outpoint index that actually reached the wire bytes.
  let tx = deserializeTransaction(hexToBytesLocal(txHex))
  doAssert tx.inputs.len == 1, "expected exactly one input in the built tx"
  tx.inputs[0].prevOut.vout

suite "createrawtransaction vout range (int32) — REGRESSION":

  test "vout 4294967296 (2^32) -> -1 JSON integer out of range":
    ## PRE-FIX: returned a tx whose outpoint index was 0 (silent wrap).
    let r = voutErr(TwoPow32)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout 8589934592 (2^33) -> -1 JSON integer out of range":
    ## PRE-FIX: also wrapped to 0 — two different requests, one wrong spend.
    let r = voutErr(TwoPow33)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout 2147483648 (int32 MAX + 1) -> -1 JSON integer out of range":
    ## The exact boundary: one past what Core's getInt<int> can hold.
    let r = voutErr(Int32MaxPlus1)
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "vout -2147483649 (int32 MIN - 1) -> -1, range beats the sign test":
    ## Negative AND out of int32 range. Core's range check lives inside the
    ## conversion, so it wins over the "cannot be negative" message. This is
    ## the ordering assertion.
    let r = voutErr(-2147483649'i64)
    check r.code == -1
    check r.msg == "JSON integer out of range"

suite "createrawtransaction — neighbouring guards still report Core's codes":

  test "vout -1 -> -8 Invalid parameter, vout cannot be negative":
    ## In int32 range, so the range check passes and the sign test speaks.
    let r = voutErr(-1)
    check r.code == -8
    check r.msg == "Invalid parameter, vout cannot be negative"

  test "sequence 4294967296 -> -8 sequence number is out of range":
    let r = captureRpcError(callCreateRaw(
      %*[{"txid": TestTxid, "vout": 0, "sequence": TwoPow32}]))
    check r.code == -8
    check r.msg == "Invalid parameter, sequence number is out of range"

  test "locktime -1 -> -8 locktime out of range":
    let r = captureRpcError(callCreateRawFull(
      %*[[{"txid": TestTxid, "vout": 0}], outputsObj(), -1]))
    check r.code == -8
    check r.msg == "Invalid parameter, locktime out of range"

suite "createrawtransaction — CONTROLS (an over-tight bound must fail here)":

  test "vout 2147483647 (int32 MAX) is ACCEPTED and lands in the tx bytes":
    ## Mandatory teeth: proves the new upper bound is `> high(int32)`, not
    ## `>= high(int32)` or some smaller cap. Fails if the guard is over-tight.
    let hex = callCreateRaw(%*[{"txid": TestTxid, "vout": Int32Max}]).getStr()
    check hex.len > 0
    check firstInputVout(hex) == 2147483647'u32

  test "an ordinary vout 7 is ACCEPTED and lands in the tx bytes":
    ## Mandatory teeth: proves the handler still does its normal job, so the
    ## rejection tests above cannot be satisfied by a reject-everything stub.
    let hex = callCreateRaw(%*[{"txid": TestTxid, "vout": 7}]).getStr()
    check hex.len > 0
    check firstInputVout(hex) == 7'u32

## ============================================================================
## createrawtransaction — `replaceable=true` must REJECT contradicting sequences
## ============================================================================
##
## THE DEFECT
## ----------
## Nine of the ten nodes in this repo (nimrod included, before this suite)
## silently ACCEPT a request that contradicts itself:
##
##     createrawtransaction '[{"txid":…,"vout":0,"sequence":4294967295}]' \
##                          '{"data":"deadbeef"}' 0 true
##                                                  ^^^^ replaceable = true
##
## The caller has asked for two incompatible things: "make this replaceable"
## and "pin every input to SEQUENCE_FINAL", which is precisely the encoding
## that opts OUT of replacement.  nimrod resolved the conflict in favour of the
## explicit sequence, returned a well-formed hex, and said NOTHING.  The
## resulting transaction cannot be fee-bumped; the caller finds out only when
## it is stuck at a low feerate and `bumpfee` refuses it.  Core does not guess
## between two arguments that disagree — it refuses the request:
##
##     -8  Invalid parameter combination: Sequence number(s) contradict
##         replaceable option
##
## WHAT BITCOIN CORE DOES
## ----------------------
## bitcoin-core/src/rpc/rawtransaction_util.cpp, ConstructTransaction, at the
## very END — after AddInputs AND AddOutputs:
##
##     if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
##         !SignalsOptInRBF(CTransaction(rawTx))) {
##         throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter
##             combination: Sequence number(s) contradict replaceable option");
##     }
##
## bitcoin-core/src/util/rbf.cpp:
##
##     bool SignalsOptInRBF(const CTransaction &tx) {
##         for (const CTxIn &txin : tx.vin)
##             if (txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) return true;
##         return false;
##     }
##
## with MAX_BIP125_RBF_SEQUENCE = 0xfffffffd (bitcoin-core/src/util/rbf.h).
## So ALL THREE must hold to reject: rbf EXPLICITLY true, at least one input,
## and NO input signalling.
##
## THE ABSENT-vs-EXPLICIT ASYMMETRY (row 1 — the easy one to get wrong)
## --------------------------------------------------------------------
## An ABSENT `replaceable` still DEFAULTS to RBF when *choosing* the sequence
## (`AddInputs` uses `rbf.value_or(true)`), yet it does NOT arm this check,
## which is gated on `rbf.has_value()`.  That asymmetry is deliberate: a caller
## who never mentioned `replaceable` has asserted nothing, so an explicit
## `sequence` is simply their wish and there is nothing to contradict.  Only a
## caller who SAID `true` while ALSO pinning a non-signalling sequence has
## stated two incompatible things.  A check written against a bare `rbf` breaks
## row 1 — the plain `createrawtransaction inputs outputs` with a final
## sequence, which Core accepts.
##
## TEETH
## -----
## Four of the eight rows are ACCEPTS, and they are not padding: a check
## written as "explicit true ⇒ reject any explicit sequence" would still pass
## every REJECT row while breaking ordinary RBF usage.  Row 6 (mixed inputs:
## ONE signals, one does not) pins the "ANY input" semantics of
## SignalsOptInRBF against the tempting "ALL inputs" misreading; row 2 pins the
## boundary at `<=` 0xfffffffd rather than `<`.  Every ACCEPT row DECODES the
## returned hex with the node's own deserializer and asserts the sequence that
## actually reached the wire bytes — "no exception raised" alone would let a
## handler that quietly rewrote the sequence pass.
##
## Every row below was verified against a LIVE Bitcoin Core node.
##
## References:
##   bitcoin-core/src/rpc/rawtransaction_util.cpp  ConstructTransaction (tail)
##   bitcoin-core/src/util/rbf.cpp                 SignalsOptInRBF
##   bitcoin-core/src/util/rbf.h                   MAX_BIP125_RBF_SEQUENCE
##   bitcoin-core/src/rpc/protocol.h               RPC_INVALID_PARAMETER = -8

const
  SeqRbf         = 4294967293'i64  # 0xfffffffd  MAX_BIP125_RBF_SEQUENCE
  SeqNonFinal    = 4294967294'i64  # 0xfffffffe  MAX_SEQUENCE_NONFINAL
  SeqFinal       = 4294967295'i64  # 0xffffffff  SEQUENCE_FINAL
  ContradictMsg  =
    "Invalid parameter combination: Sequence number(s) contradict replaceable option"

proc inputSequences(txHex: string): seq[uint32] =
  ## Decode with the node's own transaction deserializer and report the
  ## sequences that actually reached the wire bytes.
  for txIn in deserializeTransaction(hexToBytesLocal(txHex)).inputs:
    result.add(txIn.sequence)

proc oneInput(sequence: int64 = -1): JsonNode =
  ## One well-formed input; `sequence` < 0 means "omit the key entirely", which
  ## is how row 8 exercises the defaulting path.
  if sequence < 0:
    %*[{"txid": TestTxid, "vout": 0}]
  else:
    %*[{"txid": TestTxid, "vout": 0, "sequence": sequence}]

proc callWithRbf(inputs: JsonNode, replaceable: bool): JsonNode =
  ## locktime must be passed positionally (0) to reach the 4th argument.
  callCreateRawFull(%*[inputs, outputsObj(), 0, replaceable])

suite "createrawtransaction — replaceable vs sequence contradiction (Core parity)":

  test "row 1: rbf ABSENT + sequence 0xffffffff -> ACCEPT (has_value() is false)":
    ## The asymmetry row. Absent still defaults to RBF for CHOOSING the
    ## sequence, but never arms the check. A check on a bare `rbf` fails here.
    let hex = callCreateRawFull(%*[oneInput(SeqFinal), outputsObj(), 0]).getStr()
    check inputSequences(hex) == @[0xffffffff'u32]
    # JSON null is Core's other spelling of "absent" (isNull() -> nullopt).
    let hexNull = callCreateRawFull(
      %*[oneInput(SeqFinal), outputsObj(), 0, newJNull()]).getStr()
    check inputSequences(hexNull) == @[0xffffffff'u32]
    # ...and with the argument omitted entirely (2-arg form).
    let hexShort = callCreateRawFull(%*[oneInput(SeqFinal), outputsObj()]).getStr()
    check inputSequences(hexShort) == @[0xffffffff'u32]

  test "row 2: rbf true + sequence 0xfffffffd -> ACCEPT (<= is inclusive)":
    ## Pins the boundary: MAX_BIP125_RBF_SEQUENCE itself SIGNALS. A `<`
    ## instead of `<=` in SignalsOptInRBF fails exactly here.
    let hex = callWithRbf(oneInput(SeqRbf), true).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "row 3: rbf true + sequence 0xfffffffe -> REJECT -8":
    ## One past the signalling boundary: nonfinal, but NOT replaceable.
    let r = captureRpcError(callWithRbf(oneInput(SeqNonFinal), true))
    check r.code == -8
    check r.msg == ContradictMsg

  test "row 4: rbf true + sequence 0xffffffff -> REJECT -8":
    ## SEQUENCE_FINAL — the flagship case, and what nine of ten nodes accept.
    let r = captureRpcError(callWithRbf(oneInput(SeqFinal), true))
    check r.code == -8
    check r.msg == ContradictMsg

  test "row 5: rbf true + NO inputs -> ACCEPT (vin.size() > 0 is false)":
    ## An empty vin cannot signal, yet Core does not reject: the guard demands
    ## at least one input. Decoded with the LEGACY-FORCED reader because a
    ## zero-input tx's `00` vin count is otherwise misread as a segwit marker.
    let hex = callWithRbf(newJArray(), true).getStr()
    let tx = deserializeTransactionLegacyForced(hexToBytesLocal(hex))
    check tx.inputs.len == 0
    check tx.outputs.len == 1

  test "row 6: rbf true + inputs (0xffffffff, 0) -> ACCEPT (ANY input signals)":
    ## SignalsOptInRBF is ANY, not ALL: one signalling input makes the whole
    ## transaction replaceable, so a mixed set is NOT a contradiction. A check
    ## that demands every input signal fails here — and would break the real
    ## multi-party use BIP-125 has this rule for.
    let inputs = %*[
      {"txid": TestTxid, "vout": 0, "sequence": SeqFinal},
      {"txid": TestTxid, "vout": 1, "sequence": 0}
    ]
    let hex = callWithRbf(inputs, true).getStr()
    check inputSequences(hex) == @[0xffffffff'u32, 0'u32]

  test "row 7: rbf FALSE + sequence 0xffffffff -> ACCEPT (rbf.value() is false)":
    ## Explicitly opting OUT and pinning a final sequence agree with each
    ## other; there is nothing to contradict.
    let hex = callWithRbf(oneInput(SeqFinal), false).getStr()
    check inputSequences(hex) == @[0xffffffff'u32]

  test "row 8: rbf true + NO explicit sequence -> ACCEPT (default IS 0xfffffffd)":
    ## The ordinary, overwhelmingly common RBF call. The default sequence
    ## picked by AddInputs already signals, so the tail check is satisfied.
    ## This is the row an over-eager "explicit true rejects" check breaks.
    let hex = callWithRbf(oneInput(), true).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

suite "createrawtransaction — contradiction check must not outrank earlier errors":

  test "an OUTPUT error still wins over the contradiction (Core's ordering)":
    ## Core runs the check AFTER AddOutputs, so a bad output is reported
    ## first even though the rbf/sequence pair also contradicts. Moving the
    ## check earlier (e.g. right after input parsing) flips this message.
    let r = captureRpcError(callCreateRawFull(
      %*[oneInput(SeqFinal), %*{"notanaddress": 1.0}, 0, true]))
    check r.code == -5
    check r.msg == "Invalid Bitcoin address: notanaddress"


## ============================================================================
## createrawtransaction — a PRESENT but NON-NUMERIC `sequence` is IGNORED
## ============================================================================
##
## THE DEFECT
## ----------
## nimrod answered -3 "Expected type number for sequence" to a call Bitcoin
## Core ACCEPTS.  A client that sends `"sequence": null` (trivially produced by
## any library that serialises an unset optional field) got a hard type error
## instead of a transaction.
##
## WHAT BITCOIN CORE DOES
## ----------------------
## AddInputs guards the ENTIRE read with a type test, and there is no `else`
## (bitcoin-core/src/rpc/rawtransaction_util.cpp:57-65):
##
##     const UniValue& sequenceObj = o.find_value("sequence");
##     if (sequenceObj.isNum()) {
##         int64_t seqNr64 = sequenceObj.getInt<int64_t>();
##         if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
##             throw JSONRPCError(RPC_INVALID_PARAMETER,
##                 "Invalid parameter, sequence number is out of range");
##         } else { nSequence = (uint32_t)seqNr64; }
##     }
##
## A string, bool, object, array or null never enters the branch, so the
## default computed a few lines above simply survives.
##
## THE ASSERTION IS ON THE EMITTED SEQUENCE, NOT ON MERE ACCEPTANCE
## ----------------------------------------------------------------
## This is a TWO-SIDED trap and "the call succeeded" does not distinguish the
## sides.  With `replaceable` absent, rbf.value_or(true) is TRUE, so the
## surviving default is MAX_BIP125_RBF_SEQUENCE (0xfffffffd) and the built
## transaction is REPLACEABLE.  An implementation that fell through to
## SEQUENCE_FINAL (0xffffffff) would also "accept" — while quietly handing back
## a NON-replaceable transaction.  rustoshi originally did exactly that.  Every
## row below therefore decodes the returned hex and asserts the sequence that
## actually reached the wire bytes.
##
## THE FLOAT ROW is the one a dynamically-typed implementation cannot express
## and Nim can.  univalue keeps the raw token and converts with
## std::from_chars, which stops at the '.' or the 'e' and leaves trailing
## characters, so the conversion FAILS.  Verified against the live Core node
## (2026-08-28): `sequence: 1.5` AND `sequence: 100.0` are both
## -1 "JSON integer out of range" — neither ignored nor accepted.
##
## Oracle rows below were captured from the live Core node on 2026-08-28:
##   sequence "nope" / true / false / null / {} / []   ACCEPT, emits 0xfffffffd
##   the same with replaceable=false                   ACCEPT, emits 0xffffffff
##   sequence 1.5 / 100.0                              REJECT -1
##   sequence 4294967296 / -1  (NUMERIC)               REJECT -8  (unchanged)

proc inputWithSeq(seqNode: JsonNode): JsonNode =
  ## One well-formed input whose `sequence` key carries an ARBITRARY JSON
  ## node, built explicitly rather than through `%*` so the non-numeric JSON
  ## types (object, array, null) reach the handler exactly as they arrive off
  ## the wire.
  let o = newJObject()
  o["txid"] = %TestTxid
  o["vout"] = %0
  o["sequence"] = seqNode
  result = newJArray()
  result.add(o)

suite "createrawtransaction — non-numeric sequence is ignored (Core parity)":

  test "string sequence is ignored; default RBF sequence reaches the bytes":
    let hex = callCreateRaw(inputWithSeq(%"nope")).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "bool true sequence is ignored; default RBF sequence reaches the bytes":
    let hex = callCreateRaw(inputWithSeq(%true)).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "bool false sequence is ignored; default RBF sequence reaches the bytes":
    let hex = callCreateRaw(inputWithSeq(%false)).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "null sequence is ignored; default RBF sequence reaches the bytes":
    ## An unset optional serialised as JSON null is the realistic client bug
    ## this row protects.
    let hex = callCreateRaw(inputWithSeq(newJNull())).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "object sequence is ignored; default RBF sequence reaches the bytes":
    let hex = callCreateRaw(inputWithSeq(newJObject())).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "array sequence is ignored; default RBF sequence reaches the bytes":
    let hex = callCreateRaw(inputWithSeq(newJArray())).getStr()
    check inputSequences(hex) == @[0xfffffffd'u32]

  test "ignored sequence leaves the REAL default in charge (rbf=false)":
    ## Proves the fall-through reaches the default COMPUTATION, not a
    ## hard-coded 0xfffffffd: with replaceable explicitly false and locktime 0,
    ## AddInputs picks SEQUENCE_FINAL.
    let hex = callCreateRawFull(
      %*[inputWithSeq(%"nope"), outputsObj(), 0, false]).getStr()
    check inputSequences(hex) == @[0xffffffff'u32]

  test "FLOAT sequence 1.5 -> -1 JSON integer out of range (isNum, but no int)":
    let r = captureRpcError(callCreateRaw(inputWithSeq(%1.5)))
    check r.code == -1
    check r.msg == "JSON integer out of range"

  test "FLOAT sequence 100.0 -> -1 (from_chars stops at the '.', integral or not)":
    ## Integral VALUE, non-integral TOKEN. Core rejects it just the same,
    ## because univalue converts the raw token, not the parsed double.
    let r = captureRpcError(callCreateRaw(inputWithSeq(%100.0)))
    check r.code == -1
    check r.msg == "JSON integer out of range"

suite "createrawtransaction — NUMERIC sequence rejections must be untouched":

  test "CONTROL: numeric sequence 4294967296 is still -8 out of range":
    ## Without this control the fix above is satisfiable by deleting the range
    ## check outright.
    let r = captureRpcError(callCreateRaw(
      %*[{"txid": TestTxid, "vout": 0, "sequence": TwoPow32}]))
    check r.code == -8
    check r.msg == "Invalid parameter, sequence number is out of range"

  test "CONTROL: numeric sequence -1 is still -8 out of range":
    let r = captureRpcError(callCreateRaw(
      %*[{"txid": TestTxid, "vout": 0, "sequence": -1}]))
    check r.code == -8
    check r.msg == "Invalid parameter, sequence number is out of range"

  test "CONTROL: an ordinary numeric sequence still reaches the tx bytes":
    ## Proves the numeric branch still ASSIGNS, so "ignore everything" is not
    ## a passing implementation.
    let hex = callCreateRaw(
      %*[{"txid": TestTxid, "vout": 0, "sequence": 12345}]).getStr()
    check inputSequences(hex) == @[12345'u32]
