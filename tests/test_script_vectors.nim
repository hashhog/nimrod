## Test harness for Bitcoin Core's script_tests.json test vectors.
##
## Parses script assembly notation, constructs script bytecode, and
## verifies each test case against the nimrod script interpreter.
##
## Formats:
##   [scriptSig_asm, scriptPubKey_asm, flags, expected_result]              (4 fields)
##   [scriptSig_asm, scriptPubKey_asm, flags, expected_result, comment]     (5 fields)
##   [[witness...], amount, scriptSig_asm, scriptPubKey_asm, flags, result] (6+ fields, skipped)
##
## Single-element arrays are comments and are skipped.

import std/[json, strutils, sequtils, tables, os]
import ../src/primitives/types
import ../src/primitives/serialize  # txid computation for crediting/spending tx
import ../src/script/interpreter

const
  vectorPath = "/home/max/hashhog/bitcoin/src/test/data/script_tests.json"

# ---------------------------------------------------------------------------
# Opcode name -> byte value mapping
# ---------------------------------------------------------------------------

proc buildOpcodeMap(): Table[string, uint8] =
  result = initTable[string, uint8]()
  # Push values
  result["OP_0"] = OP_0; result["OP_FALSE"] = OP_FALSE
  result["OP_PUSHDATA1"] = OP_PUSHDATA1
  result["OP_PUSHDATA2"] = OP_PUSHDATA2
  result["OP_PUSHDATA4"] = OP_PUSHDATA4
  result["OP_1NEGATE"] = OP_1NEGATE; result["OP_RESERVED"] = OP_RESERVED
  result["OP_1"] = OP_1; result["OP_TRUE"] = OP_TRUE
  for i in 2..16:
    result["OP_" & $i] = uint8(0x50 + i)
  # Control
  result["OP_NOP"] = 0x61'u8; result["OP_VER"] = 0x62'u8
  result["OP_IF"] = 0x63'u8; result["OP_NOTIF"] = 0x64'u8
  result["OP_VERIF"] = 0x65'u8; result["OP_VERNOTIF"] = 0x66'u8
  result["OP_ELSE"] = 0x67'u8; result["OP_ENDIF"] = 0x68'u8
  result["OP_VERIFY"] = 0x69'u8; result["OP_RETURN"] = 0x6a'u8
  # Stack
  result["OP_TOALTSTACK"] = 0x6b'u8; result["OP_FROMALTSTACK"] = 0x6c'u8
  result["OP_2DROP"] = 0x6d'u8; result["OP_2DUP"] = 0x6e'u8
  result["OP_3DUP"] = 0x6f'u8; result["OP_2OVER"] = 0x70'u8
  result["OP_2ROT"] = 0x71'u8; result["OP_2SWAP"] = 0x72'u8
  result["OP_IFDUP"] = 0x73'u8; result["OP_DEPTH"] = 0x74'u8
  result["OP_DROP"] = 0x75'u8; result["OP_DUP"] = 0x76'u8
  result["OP_NIP"] = 0x77'u8; result["OP_OVER"] = 0x78'u8
  result["OP_PICK"] = 0x79'u8; result["OP_ROLL"] = 0x7a'u8
  result["OP_ROT"] = 0x7b'u8; result["OP_SWAP"] = 0x7c'u8
  result["OP_TUCK"] = 0x7d'u8
  # Splice (disabled)
  result["OP_CAT"] = 0x7e'u8; result["OP_SUBSTR"] = 0x7f'u8
  result["OP_LEFT"] = 0x80'u8; result["OP_RIGHT"] = 0x81'u8
  result["OP_SIZE"] = 0x82'u8
  # Bitwise (disabled)
  result["OP_INVERT"] = 0x83'u8; result["OP_AND"] = 0x84'u8
  result["OP_OR"] = 0x85'u8; result["OP_XOR"] = 0x86'u8
  # Comparison
  result["OP_EQUAL"] = 0x87'u8; result["OP_EQUALVERIFY"] = 0x88'u8
  result["OP_RESERVED1"] = 0x89'u8; result["OP_RESERVED2"] = 0x8a'u8
  # Arithmetic
  result["OP_1ADD"] = 0x8b'u8; result["OP_1SUB"] = 0x8c'u8
  result["OP_2MUL"] = 0x8d'u8; result["OP_2DIV"] = 0x8e'u8
  result["OP_NEGATE"] = 0x8f'u8; result["OP_ABS"] = 0x90'u8
  result["OP_NOT"] = 0x91'u8; result["OP_0NOTEQUAL"] = 0x92'u8
  result["OP_ADD"] = 0x93'u8; result["OP_SUB"] = 0x94'u8
  result["OP_MUL"] = 0x95'u8; result["OP_DIV"] = 0x96'u8
  result["OP_MOD"] = 0x97'u8; result["OP_LSHIFT"] = 0x98'u8
  result["OP_RSHIFT"] = 0x99'u8
  result["OP_BOOLAND"] = 0x9a'u8; result["OP_BOOLOR"] = 0x9b'u8
  result["OP_NUMEQUAL"] = 0x9c'u8; result["OP_NUMEQUALVERIFY"] = 0x9d'u8
  result["OP_NUMNOTEQUAL"] = 0x9e'u8
  result["OP_LESSTHAN"] = 0x9f'u8; result["OP_GREATERTHAN"] = 0xa0'u8
  result["OP_LESSTHANOREQUAL"] = 0xa1'u8; result["OP_GREATERTHANOREQUAL"] = 0xa2'u8
  result["OP_MIN"] = 0xa3'u8; result["OP_MAX"] = 0xa4'u8
  result["OP_WITHIN"] = 0xa5'u8
  # Crypto
  result["OP_RIPEMD160"] = 0xa6'u8; result["OP_SHA1"] = 0xa7'u8
  result["OP_SHA256"] = 0xa8'u8; result["OP_HASH160"] = 0xa9'u8
  result["OP_HASH256"] = 0xaa'u8
  result["OP_CODESEPARATOR"] = 0xab'u8
  result["OP_CHECKSIG"] = 0xac'u8; result["OP_CHECKSIGVERIFY"] = 0xad'u8
  result["OP_CHECKMULTISIG"] = 0xae'u8; result["OP_CHECKMULTISIGVERIFY"] = 0xaf'u8
  # Locktime
  result["OP_NOP1"] = 0xb0'u8
  result["OP_CHECKLOCKTIMEVERIFY"] = 0xb1'u8; result["OP_CLTV"] = 0xb1'u8; result["OP_NOP2"] = 0xb1'u8
  result["OP_CHECKSEQUENCEVERIFY"] = 0xb2'u8; result["OP_CSV"] = 0xb2'u8; result["OP_NOP3"] = 0xb2'u8
  result["OP_NOP4"] = 0xb3'u8; result["OP_NOP5"] = 0xb4'u8
  result["OP_NOP6"] = 0xb5'u8; result["OP_NOP7"] = 0xb6'u8
  result["OP_NOP8"] = 0xb7'u8; result["OP_NOP9"] = 0xb8'u8; result["OP_NOP10"] = 0xb9'u8
  result["OP_CHECKSIGADD"] = 0xba'u8
  result["OP_INVALIDOPCODE"] = 0xff'u8

  # Add bare aliases (without OP_ prefix)
  var bare: seq[(string, uint8)]
  for k, v in result:
    if k.startsWith("OP_"):
      bare.add((k[3..^1], v))
  for (k, v) in bare:
    result[k] = v

let opcodeMap = buildOpcodeMap()

# ---------------------------------------------------------------------------
# Script number encoding
# ---------------------------------------------------------------------------

proc encodeScriptNum(n: int64): seq[byte] =
  if n == 0:
    return @[]
  let negative = n < 0
  var absVal = if negative: uint64(-n) else: uint64(n)
  result = @[]
  while absVal > 0:
    result.add(byte(absVal and 0xff))
    absVal = absVal shr 8
  if (result[^1] and 0x80) != 0:
    result.add(if negative: 0x80'u8 else: 0x00'u8)
  elif negative:
    result[^1] = result[^1] or 0x80'u8

proc pushData(data: seq[byte]): seq[byte] =
  let length = data.len
  if length == 0:
    return @[0x00'u8]
  if length <= 75:
    result = @[byte(length)]
    result.add(data)
  elif length <= 255:
    result = @[0x4c'u8, byte(length)]
    result.add(data)
  elif length <= 65535:
    result = @[0x4d'u8, byte(length and 0xff), byte((length shr 8) and 0xff)]
    result.add(data)
  else:
    result = @[0x4e'u8, byte(length and 0xff), byte((length shr 8) and 0xff),
               byte((length shr 16) and 0xff), byte((length shr 24) and 0xff)]
    result.add(data)

# ---------------------------------------------------------------------------
# Script assembly parser
# ---------------------------------------------------------------------------

proc parseHex(s: string): seq[byte] =
  result = @[]
  var i = 0
  while i < s.len:
    result.add(byte(parseHexInt(s[i..i+1])))
    i += 2

proc parseScriptAsm(asmStr: string): seq[byte] =
  result = @[]
  let tokens = asmStr.splitWhitespace()
  var i = 0

  while i < tokens.len:
    let tok = tokens[i]

    # Quoted string
    if tok.len >= 2 and tok[0] == '\'' and tok[^1] == '\'':
      let text = tok[1..^2]
      var data: seq[byte]
      for c in text:
        data.add(byte(c))
      result.add(pushData(data))
      inc i
      continue

    # Hex literal
    if tok.startsWith("0x") or tok.startsWith("0X"):
      let hexStr = tok[2..^1]
      let data = parseHex(hexStr)

      # Check for push prefix pattern
      if data.len == 1 and i + 1 < tokens.len and
         (tokens[i+1].startsWith("0x") or tokens[i+1].startsWith("0X")):
        let opByte = data[0]
        if (opByte >= 1 and opByte <= 75) or opByte in [0x4c'u8, 0x4d'u8, 0x4e'u8]:
          let nextData = parseHex(tokens[i+1][2..^1])
          result.add(opByte)
          result.add(nextData)
          i += 2
          continue

      result.add(data)
      inc i
      continue

    # Opcode name lookup
    if tok in opcodeMap:
      result.add(opcodeMap[tok])
      inc i
      continue
    if ("OP_" & tok) in opcodeMap:
      result.add(opcodeMap["OP_" & tok])
      inc i
      continue

    # Bare "0"
    if tok == "0":
      result.add(0x00'u8)
      inc i
      continue

    # Decimal number
    try:
      let n = parseBiggestInt(tok)
      if n == -1:
        result.add(0x4f'u8)  # OP_1NEGATE
      elif n >= 1 and n <= 16:
        result.add(uint8(0x50 + n))
      else:
        let encoded = encodeScriptNum(int64(n))
        result.add(pushData(encoded))
      inc i
      continue
    except ValueError:
      discard

    raise newException(ValueError, "unknown token: " & tok)

# ---------------------------------------------------------------------------
# Flag parser
# ---------------------------------------------------------------------------

proc parseFlags(s: string): set[ScriptFlags] =
  result = {}
  if s.len == 0 or s == "NONE":
    return

  for f in s.split(","):
    let flag = f.strip()
    case flag
    of "P2SH": result.incl(sfP2SH)
    of "STRICTENC": result.incl(sfStrictEnc)
    of "DERSIG": result.incl(sfDERSig)
    of "LOW_S": result.incl(sfLowS)
    of "NULLDUMMY": result.incl(sfNullDummy)
    of "SIGPUSHONLY": result.incl(sfSigPushOnly)
    of "MINIMALDATA": result.incl(sfMinimalData)
    of "CLEANSTACK": result.incl(sfCleanStack)
    of "CHECKLOCKTIMEVERIFY": result.incl(sfCheckLockTimeVerify)
    of "CHECKSEQUENCEVERIFY": result.incl(sfCheckSequenceVerify)
    of "WITNESS": result.incl(sfWitness)
    of "WITNESS_PUBKEYTYPE": result.incl(sfWitnessPubkeyType)
    of "NULLFAIL": result.incl(sfNullFail)
    of "TAPROOT": result.incl(sfTaproot)
    of "MINIMALIF": result.incl(sfMinimalIf)
    of "DISCOURAGE_UPGRADABLE_NOPS": result.incl(sfDiscourageUpgradableNops)
    of "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
      result.incl(sfDiscourageUpgradableWitnessProgram)
    of "DISCOURAGE_OP_SUCCESS", "CONST_SCRIPTCODE",
       "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
      # May not have dedicated flags; skip
      discard
    else:
      discard

# ---------------------------------------------------------------------------
# Crediting and spending transactions (matches Bitcoin Core test approach)
# ---------------------------------------------------------------------------

proc makeCreditingTx(scriptPubKey: seq[byte], amount: Satoshi = Satoshi(0)): Transaction =
  ## Build the "crediting transaction" that funds the output being tested.
  ## Bitcoin Core: version 1, locktime 0, one input (null prevout,
  ## scriptSig = OP_0 OP_0, sequence 0xFFFFFFFF), one output
  ## (scriptPubKey = test's scriptPubKey, value = amount).
  var nullTxId: TxId
  result = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: nullTxId, vout: 0xFFFFFFFF'u32),
      scriptSig: @[0x00'u8, 0x00'u8],  # OP_0 OP_0
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: amount,
      scriptPubKey: scriptPubKey
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSpendingTx(creditTx: Transaction, scriptSig: seq[byte],
                     witness: seq[seq[byte]] = @[]): Transaction =
  ## Build the "spending transaction" that spends the crediting tx output.
  ## Bitcoin Core: version 1, locktime 0, one input (prevout = hash of
  ## crediting tx : 0, scriptSig = test's scriptSig, sequence 0xFFFFFFFF),
  ## one output (scriptPubKey = empty, value = creditTx output value).
  let creditTxId = txid(creditTx)
  result = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: creditTxId, vout: 0),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: creditTx.outputs[0].value,
      scriptPubKey: @[]
    )],
    witnesses: if witness.len > 0: @[witness] else: @[],
    lockTime: 0
  )

# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

proc main() =
  let data = readFile(vectorPath)
  let vectors = parseJson(data)

  var passed = 0
  var failed = 0
  var skipped = 0
  var parseErrors = 0
  var witnessTests = 0
  var i = 0

  for entry in vectors:
    inc i
    if entry.kind != JArray:
      inc skipped
      continue

    # Skip comments
    if entry.len <= 1:
      inc skipped
      continue

    var scriptSigAsm: string
    var scriptPubKeyAsm: string
    var flagsStr: string
    var expected: string
    var comment: string
    var witness: seq[seq[byte]]
    var amount: Satoshi = Satoshi(0)
    var isWitnessTest = false

    # Witness test vectors: first element is an array.
    # Format: [[witness_item1, witness_item2, ..., amount_btc], scriptSig, scriptPubKey, flags, expected]
    # The amount is the LAST element of the witness array (a number, not a hex string).
    if entry[0].kind == JArray:
      if entry.len < 5:
        inc skipped
        continue

      isWitnessTest = true
      inc witnessTests

      # Parse witness stack: all elements except the last (which is the amount)
      let witnessArr = entry[0]
      witness = @[]
      if witnessArr.len < 1:
        inc skipped
        continue

      # Last element of witness array is the amount in BTC
      let amountVal = witnessArr[witnessArr.len - 1]
      if amountVal.kind == JFloat:
        amount = Satoshi(int64(amountVal.getFloat() * 100_000_000.0 + 0.5))
      elif amountVal.kind == JInt:
        amount = Satoshi(amountVal.getBiggestInt() * 100_000_000)
      else:
        amount = Satoshi(0)

      # All elements before the last are witness stack items (hex strings)
      var hasTaprootPlaceholder = false
      for wi in 0 ..< witnessArr.len - 1:
        let hexStr = witnessArr[wi].getStr("")
        if hexStr.len == 0:
          witness.add(@[])
        elif hexStr.startsWith("#") or hexStr.contains("#SCRIPT#") or
             hexStr.contains("#CONTROLBLOCK#"):
          # Taproot test placeholders (#SCRIPT#, #CONTROLBLOCK#, etc.)
          hasTaprootPlaceholder = true
          break
        else:
          witness.add(parseHex(hexStr))

      if hasTaprootPlaceholder:
        inc skipped
        continue

      scriptSigAsm = entry[1].getStr("")
      scriptPubKeyAsm = entry[2].getStr("")

      # Skip vectors with #TAPROOTOUTPUT# placeholders in scriptPubKey
      if scriptPubKeyAsm.contains("#TAPROOTOUTPUT#"):
        inc skipped
        continue

      flagsStr = entry[3].getStr("")
      expected = entry[4].getStr("")
      comment = if entry.len >= 6: entry[5].getStr("") else: ""
    else:
      # Non-witness test
      if entry.len < 4:
        inc skipped
        continue

      scriptSigAsm = entry[0].getStr("")
      scriptPubKeyAsm = entry[1].getStr("")
      flagsStr = entry[2].getStr("")
      expected = entry[3].getStr("")
      comment = if entry.len >= 5: entry[4].getStr("") else: ""

    var scriptSig: seq[byte]
    try:
      scriptSig = parseScriptAsm(scriptSigAsm)
    except:
      inc parseErrors
      if parseErrors <= 20:
        stderr.writeLine("test " & $i & ": parse scriptSig error: " &
                        getCurrentExceptionMsg() & " (asmStr: " & scriptSigAsm & ")")
      continue

    var scriptPubKey: seq[byte]
    try:
      scriptPubKey = parseScriptAsm(scriptPubKeyAsm)
    except:
      inc parseErrors
      if parseErrors <= 20:
        stderr.writeLine("test " & $i & ": parse scriptPubKey error: " &
                        getCurrentExceptionMsg() & " (asmStr: " & scriptPubKeyAsm & ")")
      continue

    var flags = parseFlags(flagsStr)

    # Bitcoin Core: CLEANSTACK implies P2SH and WITNESS
    if sfCleanStack in flags:
      flags.incl(sfP2SH)
      flags.incl(sfWitness)

    # Build crediting and spending transactions (matches Bitcoin Core)
    let creditTx = makeCreditingTx(scriptPubKey, amount)
    let spendTx = makeSpendingTx(creditTx, scriptSig, witness)

    let err = verifyScriptWithError(scriptSig, scriptPubKey, spendTx, 0,
                                     amount = amount, flags = flags,
                                     witness = witness)

    let expectOk = expected == "OK"
    let gotOk = err == seOk

    if expectOk == gotOk:
      inc passed
    else:
      inc failed
      if failed <= 50:
        let witLabel = if isWitnessTest: " [WITNESS]" else: ""
        stderr.writeLine("FAIL test " & $i & ": expected=" & expected &
                        " got=" & $err &
                        " sigAsm=" & scriptSigAsm &
                        " pubkeyAsm=" & scriptPubKeyAsm &
                        " flags=" & flagsStr &
                        " comment=" & comment & witLabel)

  echo "script_tests.json results: " & $passed & " passed, " & $failed &
       " failed, " & $skipped & " skipped, " & $parseErrors & " parse errors" &
       " (" & $witnessTests & " witness tests included)"

  if failed > 0:
    stderr.writeLine("NOTE: " & $failed & " failures remain")

when isMainModule:
  main()
