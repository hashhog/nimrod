## Phase B `verifyscript` shim for nimrod.
##
## Drives nimrod's real consensus script interpreter
## (src/script/interpreter.nim::verifyScriptWithError) against the Phase B
## bounded reject-bar harness (tools/phaseb-vectors).
##
## It reconstructs the SAME crediting + spending transaction pair Core builds
## for its VerifyScript vectors
## (bitcoin-core/src/test/util/transaction_utils.cpp:
##  BuildCreditingTransaction / BuildSpendingTransaction) so that any
## signature-dependent rows compute an identical sighash, REUSING nimrod's own
## tx serialization + txid (primitives/serialize.nim) so the sighash matches
## byte-for-byte. Then it runs verifyScriptWithError with a flag set built by
## mapping all 22 Core flag tokens, and reports the accept/reject decision.
##
## Protocol (line-delimited JSON on stdin/stdout):
##   request:  {"op":"verifyscript",
##              "scriptSig_hex":"...","scriptPubKey_hex":"...",
##              "witness":["hex",...],"amount_sats":0,
##              "flags":["P2SH","WITNESS",...]}
##   response: {"result":true}                  (accept)
##             {"result":false,"reason":"..."}  (reject)
##             {"error":"..."}                  (could not evaluate)
##
## Lives inside the nimrod submodule (not the meta-repo) so the local
## `nim.cfg` (-d:useSystemSecp256k1, library linkage) and the nimble dep
## paths in config.nims apply when compiling.

import std/[json, strutils]
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/script/interpreter

proc hexDecode(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newException(ValueError, "odd hex length: " & $s.len)
  result = newSeqOfCap[byte](s.len div 2)
  var i = 0
  while i + 1 < s.len:
    result.add(byte(parseHexInt(s[i .. i+1])))
    i += 2

## Map Core flag tokens (interpreter.cpp:2168 ScriptFlagNamesToEnum) to
## nimrod's `ScriptFlags` enum set. Unknown token -> raise (shim emits
## {"error":...} so the driver skips rather than miscounts).
proc buildFlags(tokens: JsonNode): set[ScriptFlags] =
  result = {}
  for t in tokens:
    let name = t.getStr()
    case name
    of "P2SH": result.incl(sfP2SH)
    of "STRICTENC": result.incl(sfStrictEnc)
    of "DERSIG": result.incl(sfDERSig)
    of "LOW_S": result.incl(sfLowS)
    of "SIGPUSHONLY": result.incl(sfSigPushOnly)
    of "MINIMALDATA": result.incl(sfMinimalData)
    of "NULLDUMMY": result.incl(sfNullDummy)
    of "DISCOURAGE_UPGRADABLE_NOPS": result.incl(sfDiscourageUpgradableNops)
    of "CLEANSTACK": result.incl(sfCleanStack)
    of "MINIMALIF": result.incl(sfMinimalIf)
    of "NULLFAIL": result.incl(sfNullFail)
    of "CHECKLOCKTIMEVERIFY": result.incl(sfCheckLockTimeVerify)
    of "CHECKSEQUENCEVERIFY": result.incl(sfCheckSequenceVerify)
    of "WITNESS": result.incl(sfWitness)
    of "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
      result.incl(sfDiscourageUpgradableWitnessProgram)
    of "WITNESS_PUBKEYTYPE": result.incl(sfWitnessPubkeyType)
    of "CONST_SCRIPTCODE":
      # nimrod has no SCRIPT_VERIFY_CONST_SCRIPTCODE equivalent flag; it is
      # tracked here as a no-op (the const-scriptcode rule is not separately
      # enforced). Map to empty so the row still produces a decision rather
      # than being skipped; see triage notes.
      discard
    of "TAPROOT": result.incl(sfTaproot)
    of "DISCOURAGE_UPGRADABLE_PUBKEYTYPE":
      result.incl(sfDiscourageUpgradablePubkeyType)
    of "DISCOURAGE_OP_SUCCESS": result.incl(sfDiscourageOpSuccess)
    of "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
      result.incl(sfDiscourageUpgradableTaprootVersion)
    else:
      raise newException(ValueError, "unknown flag token: " & name)

## Replicate Core's BuildCreditingTransaction (transaction_utils.cpp:10):
## version=1, locktime=0, one input with a null prevout (zero hash, n=0xFFFFFFFF)
## and scriptSig `OP_0 OP_0` (0x00 0x00), sequence 0xFFFFFFFF; one output with
## the test scriptPubKey + amount. No witnesses, so txid uses legacy
## serialization and matches Core's CTransaction::GetHash.
proc buildCreditingTx(scriptPubKey: seq[byte], amount: int64): Transaction =
  var nullTxid: array[32, byte]  # all zeros
  result.version = 1
  result.lockTime = 0
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: TxId(nullTxid), vout: 0xFFFFFFFF'u32),
    scriptSig: @[0x00'u8, 0x00'u8],
    sequence: 0xFFFFFFFF'u32
  )]
  result.outputs = @[TxOut(
    value: Satoshi(amount),
    scriptPubKey: scriptPubKey
  )]
  result.witnesses = @[]

## Replicate Core's BuildSpendingTransaction (transaction_utils.cpp:26):
## version=1, locktime=0, one input spending credit vout 0 with the test
## scriptSig + witness, sequence 0xFFFFFFFF; one empty-script output, same
## amount. Witness is stored per-input (witnesses[0]); only set if non-empty
## so legacy-tx serialization is preserved for non-witness rows.
proc buildSpendingTx(scriptSig: seq[byte], witness: seq[seq[byte]],
                     credit: Transaction): Transaction =
  result.version = 1
  result.lockTime = 0
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: credit.txid(), vout: 0'u32),
    scriptSig: scriptSig,
    sequence: 0xFFFFFFFF'u32
  )]
  result.outputs = @[TxOut(
    value: credit.outputs[0].value,
    scriptPubKey: @[]
  )]
  if witness.len > 0:
    result.witnesses = @[witness]
  else:
    result.witnesses = @[]

proc jsonEscape(s: string): string =
  result = ""
  for c in s:
    case c
    of '\\': result.add("\\\\")
    of '"': result.add("\\\"")
    of '\n': result.add("\\n")
    of '\r': result.add("\\r")
    of '\t': result.add("\\t")
    else: result.add(c)

proc process(line: string): string =
  let req = parseJson(line)

  let ssig = hexDecode(req["scriptSig_hex"].getStr())
  let spk = hexDecode(req["scriptPubKey_hex"].getStr())
  let amount = if req.hasKey("amount_sats"): req["amount_sats"].getBiggestInt()
               else: 0'i64

  var witness: seq[seq[byte]] = @[]
  if req.hasKey("witness") and req["witness"].kind == JArray:
    for w in req["witness"]:
      witness.add(hexDecode(w.getStr()))

  let flags = buildFlags(req["flags"])

  let credit = buildCreditingTx(spk, amount)
  let spend = buildSpendingTx(ssig, witness, credit)

  # Single-input prevout context for BIP-143/BIP-341 sighash.
  let allAmounts = @[Satoshi(amount)]
  let allScriptPubKeys = @[spk]

  let err = verifyScriptWithError(
    ssig, spk, spend, 0, Satoshi(amount), flags, witness,
    allAmounts, allScriptPubKeys
  )

  if err == seOk:
    result = """{"result":true}"""
  else:
    result = """{"result":false,"reason":"""" & jsonEscape($err) & "\"}"

proc main() =
  var line: string
  while stdin.readLine(line):
    if line.strip().len == 0:
      continue
    var resp: string
    try:
      resp = process(line)
    except CatchableError as e:
      resp = """{"error":"""" & jsonEscape(e.msg) & "\"}"
    stdout.writeLine(resp)
    stdout.flushFile()

when isMainModule:
  main()
