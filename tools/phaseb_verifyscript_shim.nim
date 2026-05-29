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
## Second op `verifytx` (for tx_valid.json / tx_invalid.json): unlike
## `verifyscript` (which rebuilds Core's synthetic credit/spend pair),
## these vectors give a REAL serialized multi-input tx, so the sighash
## must be computed over THAT tx. Mirrors
## bitcoin-core/src/test/transaction_tests.cpp::CheckTxScripts: deserialize
## tx_hex with nimrod's OWN deserializer (parses the segwit marker/flag +
## per-input witnesses), build the prevout->(scriptPubKey, amount) map,
## then run verifyScriptWithError per input with the checker bound to THE
## REAL TX (input index + amount + all-prevouts) so the legacy/BIP-143/
## BIP-341 sighash commits to the actual surrounding transaction. The tx is
## valid iff ALL inputs pass; reject on the FIRST failing input (Core's loop
## is `i < vin.size() && tx_valid`).
##
##   request:  {"op":"verifytx",
##              "tx_hex":"...",
##              "prevouts":[{"txid":"<display-hex>","vout":N,
##                           "scriptPubKey_hex":"...","amount_sats":0},...],
##              "flags":["P2SH","WITNESS",...]}
##   response: {"valid":true}                   (all inputs verify)
##             {"valid":false,"reason":"..."}   (>=1 input failed)
##             {"error":"..."}                  (could not evaluate -> skip)
##
## Third op `checktx` (CheckTransaction-level, context-free structural
## validation): mirrors bitcoin-core/src/consensus/tx_check.cpp::
## CheckTransaction. These are the checks `verifytx` (per-input VerifyScript
## only) cannot catch — empty vin/vout, output value range and running
## total, duplicate inputs, oversize, coinbase scriptSig length, and a null
## prevout in a non-coinbase. We deserialize tx_hex and call nimrod's OWN
## `checkTransaction` (src/consensus/validation.nim:1620) so the harness
## exercises nimrod's consensus code, not a reimplementation in the shim.
## No UTXO/chain state is needed (params is passed but only the context-free
## gates G1..G9 run; mainnetParams() is a placeholder the proc never reads).
##
##   request:  {"op":"checktx","tx_hex":"..."}
##   response: {"valid":true}                   (structurally valid)
##             {"valid":false,"reason":"..."}   (CheckTransaction rejected)
##             {"error":"..."}                  (could not deserialize)
##
## Lives inside the nimrod submodule (not the meta-repo) so the local
## `nim.cfg` (-d:useSystemSecp256k1, library linkage) and the nimble dep
## paths in config.nims apply when compiling.

import std/[json, strutils, tables]
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/script/interpreter
import ../src/consensus/validation

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
      # Maps to nimrod's sfConstScriptCode (SCRIPT_VERIFY_CONST_SCRIPTCODE).
      # The enforcement (FindAndDelete found>0 => SCRIPT_ERR_SIG_FINDANDDELETE)
      # lives in interpreter.nim; this just passes the flag through so the rule
      # actually fires.
      result.incl(sfConstScriptCode)
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

proc processVerifyScript(req: JsonNode): string =
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

## Convert a DISPLAY-ORDER txid hex (as given in the tx_*.json prevouts) to
## the wire-order TxId that nimrod's deserializer stores in OutPoint.txid.
## readTxId reads the 32 prevout bytes verbatim (little-endian / wire order);
## the JSON hex is the big-endian display string, so we hex-decode then
## reverse to match. (`$TxId` reverses on the way out, the mirror of this.)
proc txidFromDisplayHex(s: string): TxId =
  let raw = hexDecode(s)
  if raw.len != 32:
    raise newException(ValueError, "prevout txid not 32 bytes: " & $raw.len)
  var arr: array[32, byte]
  for i in 0 ..< 32:
    arr[i] = raw[31 - i]
  TxId(arr)

## Mirror Core's transaction_tests.cpp::CheckTxScripts over a REAL tx.
## Deserialize tx_hex with nimrod's own deserializer (handles the segwit
## marker/flag + per-input witnesses), build the prevout map, then run
## verifyScriptWithError per input with the sighash computed over THE REAL
## TX. Valid iff ALL inputs pass; reject on the FIRST failing input.
proc processVerifyTx(req: JsonNode): string =
  let txBytes = hexDecode(req["tx_hex"].getStr())
  let tx = deserializeTransaction(txBytes)

  let flags = buildFlags(req["flags"])

  # Prevout map keyed by (wire-order txid, vout). Both spk + amount.
  var spkMap = initTable[(TxId, uint32), seq[byte]]()
  var amtMap = initTable[(TxId, uint32), int64]()
  for p in req["prevouts"]:
    let txid = txidFromDisplayHex(p["txid"].getStr())
    let vout = uint32(p["vout"].getBiggestInt())
    let spk = hexDecode(p["scriptPubKey_hex"].getStr())
    # amount defaults to 0 when absent (Core: contains(prevout) ? at : 0).
    let amt = if p.hasKey("amount_sats"): p["amount_sats"].getBiggestInt()
              else: 0'i64
    spkMap[(txid, vout)] = spk
    amtMap[(txid, vout)] = amt

  # Assemble per-input spent-script / spent-amount vectors in the tx's own
  # input order, so the BIP-143/BIP-341 all-prevouts commitment lines up
  # with input i. A prevout missing from the map => malformed row => error
  # (the driver skips it; never a fake pass).
  let n = tx.inputs.len
  var spentScripts = newSeq[seq[byte]](n)
  var spentAmounts = newSeq[Satoshi](n)
  for i in 0 ..< n:
    let key = (tx.inputs[i].prevOut.txid, tx.inputs[i].prevOut.vout)
    if not spkMap.hasKey(key):
      raise newException(ValueError,
        "no prevout scriptPubKey for input " & $i & " " &
        $tx.inputs[i].prevOut.txid & ":" & $tx.inputs[i].prevOut.vout)
    spentScripts[i] = spkMap[key]
    spentAmounts[i] = Satoshi(amtMap.getOrDefault(key, 0'i64))

  # Per-input VerifyScript over the real tx. Reject on first failure,
  # matching Core's `i < vin.size() && tx_valid` short-circuit.
  for i in 0 ..< n:
    let ssig = tx.inputs[i].scriptSig
    let spk = spentScripts[i]
    let amount = spentAmounts[i]
    let witness = if i < tx.witnesses.len: tx.witnesses[i]
                  else: @[]
    let err = verifyScriptWithError(
      ssig, spk, tx, i, amount, flags, witness,
      spentAmounts, spentScripts
    )
    if err != seOk:
      return """{"valid":false,"reason":"""" &
        jsonEscape("input " & $i & ": " & $err) & "\"}"

  result = """{"valid":true}"""

## CheckTransaction-level (context-free, structural) validation. Mirrors
## bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction by delegating
## to nimrod's OWN `checkTransaction` (src/consensus/validation.nim:1620),
## so a divergence here is a nimrod consensus bug, not a shim bug. No
## UTXO/chain state is needed — only the context-free gates G1..G9 run
## (vin/vout non-empty, oversize, output value range + running total,
## duplicate inputs, coinbase scriptSig length, non-coinbase null prevout).
## `params` is required by the signature but never read by those gates, so
## mainnetParams() is a placeholder.
proc processCheckTx(req: JsonNode): string =
  let txBytes = hexDecode(req["tx_hex"].getStr())
  let tx = deserializeTransaction(txBytes)
  let res = checkTransaction(tx, mainnetParams())
  if res.isOk:
    result = """{"valid":true}"""
  else:
    result = """{"valid":false,"reason":"""" &
      jsonEscape($res.error) & "\"}"

proc process(line: string): string =
  let req = parseJson(line)
  let op = if req.hasKey("op"): req["op"].getStr() else: "verifyscript"
  case op
  of "verifyscript": processVerifyScript(req)
  of "verifytx": processVerifyTx(req)
  of "checktx": processCheckTx(req)
  else: raise newException(ValueError, "unknown op: " & op)

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
