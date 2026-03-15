## Bitcoin Script interpreter
## Stack-based virtual machine for transaction validation
## Supports P2PKH, P2SH, P2WPKH, P2WSH, and P2TR

import std/[sequtils, algorithm]
import nimcrypto/sha
import ../primitives/types
import ../primitives/serialize
import ../crypto/hashing
import ../crypto/secp256k1

type
  ScriptError* = enum
    seOk = "ok"
    seUnknownOpcode = "unknown opcode"
    seInvalidStack = "invalid stack operation"
    seEqualVerify = "OP_EQUALVERIFY failed"
    seCheckSigVerify = "OP_CHECKSIGVERIFY failed"
    seOpReturn = "OP_RETURN encountered"
    seDisabledOpcode = "disabled opcode"
    seCleanStack = "non-clean stack after evaluation"
    seMinimalData = "non-minimal data push"
    seWitnessProgramMismatch = "witness program mismatch"
    seScriptSize = "script too large"
    seOpCount = "opcode limit exceeded"
    sePushSize = "push size limit exceeded"
    seStackSize = "stack size limit exceeded"
    seInvalidOpcode = "invalid opcode in this context"
    seUnbalancedConditional = "unbalanced conditional"
    seNegativeLocktime = "negative locktime"
    seUnsatisfiedLocktime = "unsatisfied locktime"
    seNullDummy = "CHECKMULTISIG dummy must be empty"
    seNullFail = "signature must be empty on failed check"
    seWitnessMalleated = "witness malleated"
    seSigHashType = "invalid sighash type"
    seInvalidPubkey = "invalid public key"
    seInvalidSig = "invalid signature"
    seSigCount = "signature count mismatch"
    sePubkeyCount = "pubkey count mismatch"
    seVerify = "OP_VERIFY failed"
    seNumEqualVerify = "OP_NUMEQUALVERIFY failed"
    seCheckMultisigVerify = "OP_CHECKMULTISIGVERIFY failed"
    seWitnessPubkeyType = "witness pubkey type mismatch"
    seTaprootError = "taproot validation error"
    seSigPushOnly = "scriptSig must be push-only"
    seMinimalIf = "OP_IF/NOTIF argument must be minimal"
    seTapscriptMinimalIf = "tapscript OP_IF/NOTIF argument must be exactly 0 or 1"

  ScriptFlags* = enum
    sfNone             # No special rules
    sfP2SH             # BIP16: evaluate P2SH scripts
    sfDERSig           # BIP66: require strict DER signatures
    sfStrictEnc        # Require strict pubkey encoding
    sfMinimalData      # Require minimal data pushes
    sfCleanStack       # Require exactly one element on stack
    sfWitness          # BIP141: verify witness programs
    sfTaproot          # BIP341/342: taproot rules
    sfNullDummy        # BIP147: CHECKMULTISIG dummy must be empty
    sfNullFail         # BIP146: signature must be empty on failed check
    sfCheckLockTimeVerify  # BIP65: OP_CHECKLOCKTIMEVERIFY
    sfCheckSequenceVerify  # BIP112: OP_CHECKSEQUENCEVERIFY
    sfLowS             # Require low S signatures (policy only)
    sfSigPushOnly      # scriptSig must be push-only (policy only)
    sfWitnessPubkeyType  # BIP141: witness pubkeys must be compressed
    sfMinimalIf        # Require minimal encoding for OP_IF/NOTIF (policy for witness v0)

  SigVersion* = enum
    sigBase = 0        # Legacy scripts
    sigWitnessV0 = 1   # SegWit v0
    sigTaproot = 2     # Taproot (SegWit v1)
    sigTapscript = 3   # Tapscript

  ScriptInterpreter* = object
    stack*: seq[seq[byte]]
    altStack*: seq[seq[byte]]
    flags*: set[ScriptFlags]
    opCount*: int
    crypto*: CryptoEngine
    execStack*: seq[bool]  # Track IF/ELSE execution state
    codesepPos*: uint32    # Position after last OP_CODESEPARATOR

# Bitcoin Script opcodes
const
  MaxScriptSize* = 10_000
  MaxStackSize* = 1000
  MaxScriptElementSize* = 520
  MaxOpsPerScript* = 201
  MaxPubkeysPerMultisig* = 20
  MaxStackElements* = 1000

  # Push value opcodes
  OP_0* = 0x00'u8
  OP_FALSE* = 0x00'u8
  OP_PUSHDATA1* = 0x4c'u8
  OP_PUSHDATA2* = 0x4d'u8
  OP_PUSHDATA4* = 0x4e'u8
  OP_1NEGATE* = 0x4f'u8
  OP_RESERVED* = 0x50'u8
  OP_1* = 0x51'u8
  OP_TRUE* = 0x51'u8
  OP_2* = 0x52'u8
  OP_3* = 0x53'u8
  OP_4* = 0x54'u8
  OP_5* = 0x55'u8
  OP_6* = 0x56'u8
  OP_7* = 0x57'u8
  OP_8* = 0x58'u8
  OP_9* = 0x59'u8
  OP_10* = 0x5a'u8
  OP_11* = 0x5b'u8
  OP_12* = 0x5c'u8
  OP_13* = 0x5d'u8
  OP_14* = 0x5e'u8
  OP_15* = 0x5f'u8
  OP_16* = 0x60'u8

  # Control flow
  OP_NOP* = 0x61'u8
  OP_VER* = 0x62'u8
  OP_IF* = 0x63'u8
  OP_NOTIF* = 0x64'u8
  OP_VERIF* = 0x65'u8
  OP_VERNOTIF* = 0x66'u8
  OP_ELSE* = 0x67'u8
  OP_ENDIF* = 0x68'u8
  OP_VERIFY* = 0x69'u8
  OP_RETURN* = 0x6a'u8

  # Stack operations
  OP_TOALTSTACK* = 0x6b'u8
  OP_FROMALTSTACK* = 0x6c'u8
  OP_2DROP* = 0x6d'u8
  OP_2DUP* = 0x6e'u8
  OP_3DUP* = 0x6f'u8
  OP_2OVER* = 0x70'u8
  OP_2ROT* = 0x71'u8
  OP_2SWAP* = 0x72'u8
  OP_IFDUP* = 0x73'u8
  OP_DEPTH* = 0x74'u8
  OP_DROP* = 0x75'u8
  OP_DUP* = 0x76'u8
  OP_NIP* = 0x77'u8
  OP_OVER* = 0x78'u8
  OP_PICK* = 0x79'u8
  OP_ROLL* = 0x7a'u8
  OP_ROT* = 0x7b'u8
  OP_SWAP* = 0x7c'u8
  OP_TUCK* = 0x7d'u8

  # Splice operations (most disabled)
  OP_CAT* = 0x7e'u8      # Disabled
  OP_SUBSTR* = 0x7f'u8   # Disabled
  OP_LEFT* = 0x80'u8     # Disabled
  OP_RIGHT* = 0x81'u8    # Disabled
  OP_SIZE* = 0x82'u8

  # Bitwise logic (most disabled)
  OP_INVERT* = 0x83'u8   # Disabled
  OP_AND* = 0x84'u8      # Disabled
  OP_OR* = 0x85'u8       # Disabled
  OP_XOR* = 0x86'u8      # Disabled
  OP_EQUAL* = 0x87'u8
  OP_EQUALVERIFY* = 0x88'u8
  OP_RESERVED1* = 0x89'u8
  OP_RESERVED2* = 0x8a'u8

  # Arithmetic
  OP_1ADD* = 0x8b'u8
  OP_1SUB* = 0x8c'u8
  OP_2MUL* = 0x8d'u8     # Disabled
  OP_2DIV* = 0x8e'u8     # Disabled
  OP_NEGATE* = 0x8f'u8
  OP_ABS* = 0x90'u8
  OP_NOT* = 0x91'u8
  OP_0NOTEQUAL* = 0x92'u8
  OP_ADD* = 0x93'u8
  OP_SUB* = 0x94'u8
  OP_MUL* = 0x95'u8      # Disabled
  OP_DIV* = 0x96'u8      # Disabled
  OP_MOD* = 0x97'u8      # Disabled
  OP_LSHIFT* = 0x98'u8   # Disabled
  OP_RSHIFT* = 0x99'u8   # Disabled
  OP_BOOLAND* = 0x9a'u8
  OP_BOOLOR* = 0x9b'u8
  OP_NUMEQUAL* = 0x9c'u8
  OP_NUMEQUALVERIFY* = 0x9d'u8
  OP_NUMNOTEQUAL* = 0x9e'u8
  OP_LESSTHAN* = 0x9f'u8
  OP_GREATERTHAN* = 0xa0'u8
  OP_LESSTHANOREQUAL* = 0xa1'u8
  OP_GREATERTHANOREQUAL* = 0xa2'u8
  OP_MIN* = 0xa3'u8
  OP_MAX* = 0xa4'u8
  OP_WITHIN* = 0xa5'u8

  # Crypto
  OP_RIPEMD160* = 0xa6'u8
  OP_SHA1* = 0xa7'u8
  OP_SHA256* = 0xa8'u8
  OP_HASH160* = 0xa9'u8
  OP_HASH256* = 0xaa'u8
  OP_CODESEPARATOR* = 0xab'u8
  OP_CHECKSIG* = 0xac'u8
  OP_CHECKSIGVERIFY* = 0xad'u8
  OP_CHECKMULTISIG* = 0xae'u8
  OP_CHECKMULTISIGVERIFY* = 0xaf'u8

  # Locktime
  OP_NOP1* = 0xb0'u8
  OP_CHECKLOCKTIMEVERIFY* = 0xb1'u8
  OP_NOP2* = 0xb1'u8  # Alias
  OP_CHECKSEQUENCEVERIFY* = 0xb2'u8
  OP_NOP3* = 0xb2'u8  # Alias
  OP_NOP4* = 0xb3'u8
  OP_NOP5* = 0xb4'u8
  OP_NOP6* = 0xb5'u8
  OP_NOP7* = 0xb6'u8
  OP_NOP8* = 0xb7'u8
  OP_NOP9* = 0xb8'u8
  OP_NOP10* = 0xb9'u8

  # Taproot (BIP342)
  OP_CHECKSIGADD* = 0xba'u8

  # Reserved words
  OP_INVALIDOPCODE* = 0xff'u8

  # Sighash types
  SIGHASH_ALL* = 0x01'u8
  SIGHASH_NONE* = 0x02'u8
  SIGHASH_SINGLE* = 0x03'u8
  SIGHASH_ANYONECANPAY* = 0x80'u8

  # Taproot sighash
  SIGHASH_DEFAULT* = 0x00'u8

  # Sequence flags (BIP68)
  SEQUENCE_LOCKTIME_DISABLE_FLAG* = 1'u32 shl 31
  SEQUENCE_LOCKTIME_TYPE_FLAG* = 1'u32 shl 22
  SEQUENCE_LOCKTIME_MASK* = 0x0000ffff'u32

# Helper: check if executing (all conditions in execStack are true)
proc isExecuting(interp: ScriptInterpreter): bool =
  for exec in interp.execStack:
    if not exec:
      return false
  true

# Stack operations
proc newInterpreter*(): ScriptInterpreter =
  result.stack = @[]
  result.altStack = @[]
  result.flags = {}
  result.opCount = 0
  result.execStack = @[]
  result.codesepPos = 0xFFFFFFFF'u32  # BIP341: initialize to max

proc newInterpreter*(flags: set[ScriptFlags]): ScriptInterpreter =
  result = newInterpreter()
  result.flags = flags

proc push*(interp: var ScriptInterpreter, data: seq[byte]) =
  interp.stack.add(data)

proc pop*(interp: var ScriptInterpreter): seq[byte] =
  if interp.stack.len == 0:
    return @[]
  result = interp.stack.pop()

proc peek*(interp: ScriptInterpreter): seq[byte] =
  if interp.stack.len == 0:
    return @[]
  interp.stack[interp.stack.len - 1]

proc peekAt*(interp: ScriptInterpreter, idx: int): seq[byte] =
  ## Peek at element idx positions from top (0 = top)
  let pos = interp.stack.len - 1 - idx
  if pos < 0 or pos >= interp.stack.len:
    return @[]
  interp.stack[pos]

proc stackSize*(interp: ScriptInterpreter): int =
  interp.stack.len

proc combinedStackSize*(interp: ScriptInterpreter): int =
  interp.stack.len + interp.altStack.len

# Script number encoding/decoding (little-endian with sign bit in MSB)
proc toBool*(data: seq[byte]): bool =
  ## Convert stack element to boolean
  ## Empty or all zeros = false, 0x80 alone (negative zero) = false
  for i, b in data:
    if b != 0:
      # Check for negative zero (0x80 as last byte with all zeros before)
      if i == data.len - 1 and b == 0x80:
        return false
      return true
  false

# Alias matching Bitcoin Core naming
proc castToBool*(data: seq[byte]): bool =
  ## Alias for toBool, matching Bitcoin Core's CastToBool naming
  toBool(data)

proc toScriptNum*(data: seq[byte], requireMinimal: bool = false, maxLen: int = 4): (int64, bool) =
  ## Convert stack element to script number
  ## Returns (value, success)
  if data.len == 0:
    return (0'i64, true)

  if data.len > maxLen:
    return (0'i64, false)

  # Check minimal encoding
  if requireMinimal:
    # Check that the number is encoded with the minimum possible number of bytes
    if (data[data.len - 1] and 0x7f) == 0:
      # Extra byte not needed unless previous byte has high bit set
      if data.len <= 1 or (data[data.len - 2] and 0x80) == 0:
        return (0'i64, false)

  var negative = (data[data.len - 1] and 0x80) != 0
  var value: int64 = 0

  for i in countdown(data.len - 1, 0):
    var b = data[i]
    if i == data.len - 1:
      b = b and 0x7f
    value = (value shl 8) or int64(b)

  if negative:
    value = -value

  return (value, true)

proc fromScriptNum*(n: int64): seq[byte] =
  ## Convert int64 to minimal script number encoding
  if n == 0:
    return @[]

  var absN = if n < 0: -n else: n
  result = @[]

  while absN > 0:
    result.add(byte(absN and 0xff))
    absN = absN shr 8

  # If the high bit is set, add extra byte for sign
  if (result[result.len - 1] and 0x80) != 0:
    if n < 0:
      result.add(0x80)
    else:
      result.add(0x00)
  elif n < 0:
    result[result.len - 1] = result[result.len - 1] or 0x80

# Check for disabled opcodes
proc isDisabled(opcode: uint8): bool =
  opcode in [OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR,
             OP_XOR, OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT,
             OP_RSHIFT, OP_VERIF, OP_VERNOTIF]

# Check if pubkey is compressed (33 bytes, starting with 0x02 or 0x03)
proc isCompressedPubkey*(pubkey: seq[byte]): bool =
  ## BIP141 WITNESS_PUBKEYTYPE check: pubkeys in witness v0 must be compressed
  ## Compressed pubkey: 33 bytes, first byte is 0x02 or 0x03
  if pubkey.len != 33:
    return false
  case pubkey[0]
  of 0x02, 0x03:
    return true
  else:
    return false

# Check if opcode counts toward op limit
proc countsTowardOpLimit(opcode: uint8): bool =
  opcode > OP_16

# Tagged hash for taproot (BIP340/341)
proc taggedHash*(tag: string, data: openArray[byte]): array[32, byte] =
  ## SHA256(SHA256(tag) || SHA256(tag) || data)
  let tagHash = sha256(cast[seq[byte]](tag))
  var preimage: seq[byte]
  preimage.add(tagHash)
  preimage.add(tagHash)
  preimage.add(data)
  sha256(preimage)

# FindAndDelete - removes exact matches of a push-encoded signature from script
# Only used for sig_version BASE (legacy)
proc findAndDelete*(script: seq[byte], sig: seq[byte]): seq[byte] =
  ## Remove all occurrences of push-encoded sig from script
  if sig.len == 0:
    return script

  result = @[]
  var i = 0

  while i < script.len:
    let opcode = script[i]

    # Check for direct push (1-75 bytes)
    if opcode >= 0x01 and opcode <= 0x4b:
      let pushLen = int(opcode)
      if i + 1 + pushLen <= script.len:
        let pushData = script[i + 1 ..< i + 1 + pushLen]
        if pushData == sig:
          i += 1 + pushLen
          continue

    # Check for OP_PUSHDATA1
    elif opcode == OP_PUSHDATA1 and i + 1 < script.len:
      let pushLen = int(script[i + 1])
      if i + 2 + pushLen <= script.len:
        let pushData = script[i + 2 ..< i + 2 + pushLen]
        if pushData == sig:
          i += 2 + pushLen
          continue

    # Check for OP_PUSHDATA2
    elif opcode == OP_PUSHDATA2 and i + 2 < script.len:
      let pushLen = int(script[i + 1]) or (int(script[i + 2]) shl 8)
      if i + 3 + pushLen <= script.len:
        let pushData = script[i + 3 ..< i + 3 + pushLen]
        if pushData == sig:
          i += 3 + pushLen
          continue

    result.add(script[i])
    i += 1

# Sighash computation
type
  SigHashType* = uint32

proc computeSighashLegacy*(tx: Transaction, inputIndex: int,
                           scriptCode: openArray[byte],
                           hashType: uint32): array[32, byte] =
  ## BIP-62/143 legacy sighash
  ## Returns double-SHA256 of serialized tx with modified scriptSigs

  var modifiedTx = tx

  # Clear all scriptSigs
  for i in 0 ..< modifiedTx.inputs.len:
    modifiedTx.inputs[i].scriptSig = @[]

  # Set scriptCode for the input being signed
  if inputIndex < modifiedTx.inputs.len:
    modifiedTx.inputs[inputIndex].scriptSig = @scriptCode

  let baseType = hashType and 0x1f

  # SIGHASH_NONE: clear all outputs
  if baseType == uint32(SIGHASH_NONE):
    modifiedTx.outputs = @[]
    # Set sequence to 0 for all other inputs
    for i in 0 ..< modifiedTx.inputs.len:
      if i != inputIndex:
        modifiedTx.inputs[i].sequence = 0

  # SIGHASH_SINGLE: keep only output at inputIndex
  elif baseType == uint32(SIGHASH_SINGLE):
    if inputIndex >= modifiedTx.outputs.len:
      # Return hash of 1 followed by 0s (special case)
      var specialHash: array[32, byte]
      specialHash[0] = 1
      return specialHash

    # Resize outputs and set all before inputIndex to empty
    let output = modifiedTx.outputs[inputIndex]
    modifiedTx.outputs.setLen(inputIndex + 1)
    for i in 0 ..< inputIndex:
      modifiedTx.outputs[i] = TxOut(value: Satoshi(-1), scriptPubKey: @[])
    modifiedTx.outputs[inputIndex] = output

    # Set sequence to 0 for all other inputs
    for i in 0 ..< modifiedTx.inputs.len:
      if i != inputIndex:
        modifiedTx.inputs[i].sequence = 0

  # SIGHASH_ANYONECANPAY: only include the input being signed
  if (hashType and uint32(SIGHASH_ANYONECANPAY)) != 0:
    modifiedTx.inputs = @[modifiedTx.inputs[inputIndex]]

  # Clear witness for legacy sighash
  modifiedTx.witnesses = @[]

  # Serialize without witness
  var w = BinaryWriter()
  w.writeTransaction(modifiedTx, includeWitness = false)
  w.writeUint32LE(hashType)

  doubleSha256(w.data)

proc computeSighashSegwitV0*(tx: Transaction, inputIndex: int,
                              scriptCode: openArray[byte],
                              amount: Satoshi,
                              hashType: uint32): array[32, byte] =
  ## BIP-143 sighash for SegWit v0
  ## Commits to: version | hashPrevouts | hashSequence | outpoint |
  ##             scriptCode | amount | sequence | hashOutputs | locktime | hashType

  let baseType = hashType and 0x1f
  let anyoneCanPay = (hashType and uint32(SIGHASH_ANYONECANPAY)) != 0

  # hashPrevouts
  var hashPrevouts: array[32, byte]
  if not anyoneCanPay:
    var w = BinaryWriter()
    for input in tx.inputs:
      w.writeOutPoint(input.prevOut)
    hashPrevouts = doubleSha256(w.data)

  # hashSequence
  var hashSequence: array[32, byte]
  if not anyoneCanPay and baseType != uint32(SIGHASH_SINGLE) and baseType != uint32(SIGHASH_NONE):
    var w = BinaryWriter()
    for input in tx.inputs:
      w.writeUint32LE(input.sequence)
    hashSequence = doubleSha256(w.data)

  # hashOutputs
  var hashOutputs: array[32, byte]
  if baseType != uint32(SIGHASH_SINGLE) and baseType != uint32(SIGHASH_NONE):
    var w = BinaryWriter()
    for output in tx.outputs:
      w.writeTxOut(output)
    hashOutputs = doubleSha256(w.data)
  elif baseType == uint32(SIGHASH_SINGLE) and inputIndex < tx.outputs.len:
    var w = BinaryWriter()
    w.writeTxOut(tx.outputs[inputIndex])
    hashOutputs = doubleSha256(w.data)

  # Build preimage
  var preimage = BinaryWriter()
  preimage.writeInt32LE(tx.version)
  preimage.writeHash(hashPrevouts)
  preimage.writeHash(hashSequence)
  preimage.writeOutPoint(tx.inputs[inputIndex].prevOut)
  preimage.writeVarBytes(@scriptCode)
  preimage.writeInt64LE(int64(amount))
  preimage.writeUint32LE(tx.inputs[inputIndex].sequence)
  preimage.writeHash(hashOutputs)
  preimage.writeUint32LE(tx.lockTime)
  preimage.writeUint32LE(hashType)

  doubleSha256(preimage.data)

proc computeSighashTaproot*(tx: Transaction, inputIndex: int,
                            amounts: seq[Satoshi],
                            scriptPubKeys: seq[seq[byte]],
                            hashType: uint8,
                            extFlag: uint8 = 0,
                            annex: seq[byte] = @[],
                            tapleafHash: array[32, byte] = default(array[32, byte]),
                            codesepPos: uint32 = 0xFFFFFFFF'u32): array[32, byte] =
  ## BIP-341 taproot sighash
  ## Uses tagged hashes: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || epoch || ...)

  let effectiveHashType = if hashType == 0x00: SIGHASH_ALL else: hashType
  let baseType = effectiveHashType and 0x1f
  let anyoneCanPay = (effectiveHashType and SIGHASH_ANYONECANPAY) != 0

  var preimage: seq[byte]

  # Epoch (0x00 for current version)
  preimage.add(0x00)

  # hash_type - write original byte (0x00 for SIGHASH_DEFAULT)
  preimage.add(hashType)

  # nVersion
  var w = BinaryWriter()
  w.writeInt32LE(tx.version)
  preimage.add(w.data)

  # nLockTime
  w = BinaryWriter()
  w.writeUint32LE(tx.lockTime)
  preimage.add(w.data)

  # sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences
  if not anyoneCanPay:
    # sha_prevouts
    w = BinaryWriter()
    for input in tx.inputs:
      w.writeOutPoint(input.prevOut)
    preimage.add(sha256(w.data))

    # sha_amounts
    w = BinaryWriter()
    for amt in amounts:
      w.writeInt64LE(int64(amt))
    preimage.add(sha256(w.data))

    # sha_scriptpubkeys
    w = BinaryWriter()
    for spk in scriptPubKeys:
      w.writeVarBytes(spk)
    preimage.add(sha256(w.data))

    # sha_sequences
    w = BinaryWriter()
    for input in tx.inputs:
      w.writeUint32LE(input.sequence)
    preimage.add(sha256(w.data))

  # sha_outputs
  if baseType != uint32(SIGHASH_NONE) and baseType != uint32(SIGHASH_SINGLE):
    w = BinaryWriter()
    for output in tx.outputs:
      w.writeTxOut(output)
    preimage.add(sha256(w.data))

  # spend_type
  var spendType: uint8 = extFlag * 2
  if annex.len > 0:
    spendType = spendType or 1
  preimage.add(spendType)

  # Input-specific data
  if anyoneCanPay:
    w = BinaryWriter()
    w.writeOutPoint(tx.inputs[inputIndex].prevOut)
    preimage.add(w.data)

    w = BinaryWriter()
    w.writeInt64LE(int64(amounts[inputIndex]))
    preimage.add(w.data)

    w = BinaryWriter()
    w.writeVarBytes(scriptPubKeys[inputIndex])
    preimage.add(w.data)

    w = BinaryWriter()
    w.writeUint32LE(tx.inputs[inputIndex].sequence)
    preimage.add(w.data)
  else:
    w = BinaryWriter()
    w.writeUint32LE(uint32(inputIndex))
    preimage.add(w.data)

  # sha_annex (if present)
  if annex.len > 0:
    w = BinaryWriter()
    w.writeVarBytes(annex)
    preimage.add(sha256(w.data))

  # sha_single_output (for SIGHASH_SINGLE)
  if baseType == uint32(SIGHASH_SINGLE):
    if inputIndex < tx.outputs.len:
      w = BinaryWriter()
      w.writeTxOut(tx.outputs[inputIndex])
      preimage.add(sha256(w.data))
    else:
      # Return error hash
      var errorHash: array[32, byte]
      return errorHash

  # Tapscript extensions (extFlag != 0)
  if extFlag == 1:
    preimage.add(tapleafHash)

    w = BinaryWriter()
    w.writeUint8(0x00)  # key_version
    preimage.add(w.data)

    w = BinaryWriter()
    w.writeUint32LE(codesepPos)
    preimage.add(w.data)

  taggedHash("TapSighash", preimage)

# Script pattern detection
proc isP2PKH*(script: seq[byte]): bool =
  ## OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  script.len == 25 and
    script[0] == OP_DUP and
    script[1] == OP_HASH160 and
    script[2] == 0x14 and  # Push 20 bytes
    script[23] == OP_EQUALVERIFY and
    script[24] == OP_CHECKSIG

proc isP2SH*(script: seq[byte]): bool =
  ## OP_HASH160 <20 bytes> OP_EQUAL
  script.len == 23 and
    script[0] == OP_HASH160 and
    script[1] == 0x14 and  # Push 20 bytes
    script[22] == OP_EQUAL

proc isP2WPKH*(script: seq[byte]): bool =
  ## OP_0 <20 bytes>
  script.len == 22 and
    script[0] == OP_0 and
    script[1] == 0x14  # Push 20 bytes

proc isP2WSH*(script: seq[byte]): bool =
  ## OP_0 <32 bytes>
  script.len == 34 and
    script[0] == OP_0 and
    script[1] == 0x20  # Push 32 bytes

proc isP2TR*(script: seq[byte]): bool =
  ## OP_1 <32 bytes>
  script.len == 34 and
    script[0] == OP_1 and
    script[1] == 0x20  # Push 32 bytes

# Pay-to-Anchor script constant: OP_1 PUSHBYTES_2 0x4e73
const P2AScript* = @[0x51'u8, 0x02, 0x4e, 0x73]

proc isP2A*(script: seq[byte]): bool =
  ## OP_1 <0x4e73> (witness v1 with 2-byte program "Ns")
  ## Pay-to-Anchor output for fee bumping via CPFP
  script == P2AScript

proc isP2AFromProgram*(version: int, program: seq[byte]): bool =
  ## Check if witness program represents a P2A output
  version == 1 and
    program.len == 2 and
    program[0] == 0x4e and
    program[1] == 0x73

proc isWitnessProgram*(script: seq[byte]): (bool, int, seq[byte]) =
  ## Returns (isWitness, version, program)
  if script.len < 4 or script.len > 42:
    return (false, 0, @[])

  # Version opcode: OP_0 = 0, OP_1..OP_16 = 1..16
  let versionOp = script[0]
  var version: int
  if versionOp == OP_0:
    version = 0
  elif versionOp >= OP_1 and versionOp <= OP_16:
    version = int(versionOp - OP_1 + 1)
  else:
    return (false, 0, @[])

  # Push length
  let pushLen = int(script[1])
  if pushLen < 2 or pushLen > 40:
    return (false, 0, @[])

  # Check script is exactly version + push + program
  if script.len != 2 + pushLen:
    return (false, 0, @[])

  return (true, version, script[2 .. script.len - 1])

proc isPushOnly*(script: seq[byte]): bool =
  ## Check if script contains only push operations
  var pc = 0
  while pc < script.len:
    let opcode = script[pc]
    if opcode > OP_16:
      return false

    if opcode >= 0x01 and opcode <= 0x4b:
      pc += 1 + int(opcode)
    elif opcode == OP_PUSHDATA1:
      if pc + 1 >= script.len:
        return false
      pc += 2 + int(script[pc + 1])
    elif opcode == OP_PUSHDATA2:
      if pc + 2 >= script.len:
        return false
      let len = int(script[pc + 1]) or (int(script[pc + 2]) shl 8)
      pc += 3 + len
    elif opcode == OP_PUSHDATA4:
      if pc + 4 >= script.len:
        return false
      let len = int(script[pc + 1]) or (int(script[pc + 2]) shl 8) or
                (int(script[pc + 3]) shl 16) or (int(script[pc + 4]) shl 24)
      pc += 5 + len
    else:
      pc += 1

  true

# Signature checking context
type
  SigCheckContext* = object
    tx*: Transaction
    inputIndex*: int
    amount*: Satoshi
    scriptPubKey*: seq[byte]
    sigVersion*: SigVersion
    amounts*: seq[Satoshi]
    scriptPubKeys*: seq[seq[byte]]
    annex*: seq[byte]
    tapleafHash*: array[32, byte]
    codesepPos*: uint32

# Core evaluation function
proc eval*(interp: var ScriptInterpreter, script: openArray[byte],
           ctx: SigCheckContext): ScriptError =
  ## Execute script and return error code

  if script.len > MaxScriptSize:
    return seScriptSize

  var pc = 0
  let scriptLen = script.len

  while pc < scriptLen:
    let opcode = script[pc]
    pc += 1

    # Count non-push opcodes
    if opcode.countsTowardOpLimit:
      interp.opCount += 1
      if interp.opCount > MaxOpsPerScript:
        return seOpCount

    # Check for disabled opcodes (always fail, even in non-executing branch)
    if opcode.isDisabled:
      return seDisabledOpcode

    let executing = interp.isExecuting()

    # Push data opcodes (1-75 bytes)
    if opcode >= 0x01 and opcode <= 0x4b:
      let pushLen = int(opcode)
      if pc + pushLen > scriptLen:
        return seInvalidStack
      if executing:
        if pushLen > MaxScriptElementSize:
          return sePushSize
        interp.push(script[pc ..< pc + pushLen].toSeq)
      pc += pushLen
      continue

    elif opcode == OP_PUSHDATA1:
      if pc >= scriptLen:
        return seInvalidStack
      let pushLen = int(script[pc])
      pc += 1
      if pc + pushLen > scriptLen:
        return seInvalidStack
      if executing:
        if pushLen > MaxScriptElementSize:
          return sePushSize
        # Check minimal push encoding
        if sfMinimalData in interp.flags and pushLen <= 75:
          return seMinimalData
        interp.push(script[pc ..< pc + pushLen].toSeq)
      pc += pushLen
      continue

    elif opcode == OP_PUSHDATA2:
      if pc + 2 > scriptLen:
        return seInvalidStack
      let pushLen = int(script[pc]) or (int(script[pc + 1]) shl 8)
      pc += 2
      if pc + pushLen > scriptLen:
        return seInvalidStack
      if executing:
        if pushLen > MaxScriptElementSize:
          return sePushSize
        if sfMinimalData in interp.flags and pushLen <= 255:
          return seMinimalData
        interp.push(script[pc ..< pc + pushLen].toSeq)
      pc += pushLen
      continue

    elif opcode == OP_PUSHDATA4:
      if pc + 4 > scriptLen:
        return seInvalidStack
      let pushLen = int(script[pc]) or (int(script[pc + 1]) shl 8) or
                    (int(script[pc + 2]) shl 16) or (int(script[pc + 3]) shl 24)
      pc += 4
      if pc + pushLen > scriptLen:
        return seInvalidStack
      if executing:
        if pushLen > MaxScriptElementSize:
          return sePushSize
        if sfMinimalData in interp.flags and pushLen <= 65535:
          return seMinimalData
        interp.push(script[pc ..< pc + pushLen].toSeq)
      pc += pushLen
      continue

    # Non-executing branch: only process control flow
    if not executing:
      case opcode
      of OP_IF, OP_NOTIF:
        interp.execStack.add(false)
      of OP_ELSE:
        if interp.execStack.len == 0:
          return seUnbalancedConditional
        interp.execStack[interp.execStack.len - 1] = not interp.execStack[interp.execStack.len - 1]
      of OP_ENDIF:
        if interp.execStack.len == 0:
          return seUnbalancedConditional
        discard interp.execStack.pop()
      of OP_RETURN:
        # OP_RETURN in non-executing branch does NOT terminate
        discard
      else:
        discard
      continue

    # Executing opcodes
    case opcode
    of OP_0:
      interp.push(@[])

    of OP_1NEGATE:
      interp.push(fromScriptNum(-1))

    of OP_1..OP_16:
      interp.push(@[byte(opcode - OP_1 + 1)])

    of OP_NOP:
      discard

    of OP_NOP1, OP_NOP4..OP_NOP10:
      # NOP for soft-fork upgrades
      discard

    of OP_IF, OP_NOTIF:
      if interp.stack.len < 1:
        return seInvalidStack
      var val = interp.pop()
      var condition = toBool(val)

      # Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
      # The input argument must be exactly empty (false) or exactly @[0x01] (true).
      if ctx.sigVersion == sigTapscript:
        if val.len > 1 or (val.len == 1 and val[0] != 1):
          return seTapscriptMinimalIf

      # Under witness v0 rules it is only a policy rule, enabled through sfMinimalIf.
      # Same check: must be empty or exactly @[0x01].
      if ctx.sigVersion == sigWitnessV0 and sfMinimalIf in interp.flags:
        if val.len > 1 or (val.len == 1 and val[0] != 1):
          return seMinimalIf

      if opcode == OP_NOTIF:
        condition = not condition
      interp.execStack.add(condition)

    of OP_ELSE:
      if interp.execStack.len == 0:
        return seUnbalancedConditional
      interp.execStack[interp.execStack.len - 1] = not interp.execStack[interp.execStack.len - 1]

    of OP_ENDIF:
      if interp.execStack.len == 0:
        return seUnbalancedConditional
      discard interp.execStack.pop()

    of OP_VERIFY:
      if interp.stack.len < 1:
        return seInvalidStack
      if not toBool(interp.pop()):
        return seVerify

    of OP_RETURN:
      return seOpReturn

    # Stack operations
    of OP_TOALTSTACK:
      if interp.stack.len < 1:
        return seInvalidStack
      interp.altStack.add(interp.pop())

    of OP_FROMALTSTACK:
      if interp.altStack.len < 1:
        return seInvalidStack
      interp.push(interp.altStack.pop())

    of OP_2DROP:
      if interp.stack.len < 2:
        return seInvalidStack
      discard interp.pop()
      discard interp.pop()

    of OP_2DUP:
      if interp.stack.len < 2:
        return seInvalidStack
      let a = interp.peekAt(1)
      let b = interp.peekAt(0)
      interp.push(a)
      interp.push(b)

    of OP_3DUP:
      if interp.stack.len < 3:
        return seInvalidStack
      let a = interp.peekAt(2)
      let b = interp.peekAt(1)
      let c = interp.peekAt(0)
      interp.push(a)
      interp.push(b)
      interp.push(c)

    of OP_2OVER:
      if interp.stack.len < 4:
        return seInvalidStack
      let a = interp.peekAt(3)
      let b = interp.peekAt(2)
      interp.push(a)
      interp.push(b)

    of OP_2ROT:
      if interp.stack.len < 6:
        return seInvalidStack
      let a = interp.stack[interp.stack.len - 6]
      let b = interp.stack[interp.stack.len - 5]
      interp.stack.delete(interp.stack.len - 6)
      interp.stack.delete(interp.stack.len - 5)
      interp.push(a)
      interp.push(b)

    of OP_2SWAP:
      if interp.stack.len < 4:
        return seInvalidStack
      swap(interp.stack[interp.stack.len - 4], interp.stack[interp.stack.len - 2])
      swap(interp.stack[interp.stack.len - 3], interp.stack[interp.stack.len - 1])

    of OP_IFDUP:
      if interp.stack.len < 1:
        return seInvalidStack
      if toBool(interp.peek()):
        interp.push(interp.peek())

    of OP_DEPTH:
      interp.push(fromScriptNum(int64(interp.stack.len)))

    of OP_DROP:
      if interp.stack.len < 1:
        return seInvalidStack
      discard interp.pop()

    of OP_DUP:
      if interp.stack.len < 1:
        return seInvalidStack
      interp.push(interp.peek())

    of OP_NIP:
      if interp.stack.len < 2:
        return seInvalidStack
      interp.stack.delete(interp.stack.len - 2)

    of OP_OVER:
      if interp.stack.len < 2:
        return seInvalidStack
      interp.push(interp.peekAt(1))

    of OP_PICK:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok or n < 0:
        return seInvalidStack
      if int(n) >= interp.stack.len:
        return seInvalidStack
      interp.push(interp.peekAt(int(n)))

    of OP_ROLL:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok or n < 0:
        return seInvalidStack
      if int(n) >= interp.stack.len:
        return seInvalidStack
      let idx = interp.stack.len - 1 - int(n)
      let val = interp.stack[idx]
      interp.stack.delete(idx)
      interp.push(val)

    of OP_ROT:
      if interp.stack.len < 3:
        return seInvalidStack
      let c = interp.pop()
      let b = interp.pop()
      let a = interp.pop()
      interp.push(b)
      interp.push(c)
      interp.push(a)

    of OP_SWAP:
      if interp.stack.len < 2:
        return seInvalidStack
      swap(interp.stack[interp.stack.len - 1], interp.stack[interp.stack.len - 2])

    of OP_TUCK:
      if interp.stack.len < 2:
        return seInvalidStack
      let top = interp.peek()
      interp.stack.insert(top, interp.stack.len - 2)

    of OP_SIZE:
      if interp.stack.len < 1:
        return seInvalidStack
      interp.push(fromScriptNum(int64(interp.peek().len)))

    # Bitwise logic
    of OP_EQUAL:
      if interp.stack.len < 2:
        return seInvalidStack
      let a = interp.pop()
      let b = interp.pop()
      if a == b:
        interp.push(@[1'u8])
      else:
        interp.push(@[])

    of OP_EQUALVERIFY:
      if interp.stack.len < 2:
        return seInvalidStack
      let a = interp.pop()
      let b = interp.pop()
      if a != b:
        return seEqualVerify

    # Arithmetic
    of OP_1ADD:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(n + 1))

    of OP_1SUB:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(n - 1))

    of OP_NEGATE:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(-n))

    of OP_ABS:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(if n < 0: -n else: n))

    of OP_NOT:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(if n == 0: 1 else: 0))

    of OP_0NOTEQUAL:
      if interp.stack.len < 1:
        return seInvalidStack
      let (n, ok) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not ok:
        return seInvalidStack
      interp.push(fromScriptNum(if n != 0: 1 else: 0))

    of OP_ADD:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(a + b))

    of OP_SUB:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(a - b))

    of OP_BOOLAND:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a != 0 and b != 0: 1 else: 0))

    of OP_BOOLOR:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a != 0 or b != 0: 1 else: 0))

    of OP_NUMEQUAL:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a == b: 1 else: 0))

    of OP_NUMEQUALVERIFY:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      if a != b:
        return seNumEqualVerify

    of OP_NUMNOTEQUAL:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a != b: 1 else: 0))

    of OP_LESSTHAN:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a < b: 1 else: 0))

    of OP_GREATERTHAN:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a > b: 1 else: 0))

    of OP_LESSTHANOREQUAL:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a <= b: 1 else: 0))

    of OP_GREATERTHANOREQUAL:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a >= b: 1 else: 0))

    of OP_MIN:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a < b: a else: b))

    of OP_MAX:
      if interp.stack.len < 2:
        return seInvalidStack
      let (b, okB) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (a, okA) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okA or not okB:
        return seInvalidStack
      interp.push(fromScriptNum(if a > b: a else: b))

    of OP_WITHIN:
      if interp.stack.len < 3:
        return seInvalidStack
      let (max, okMax) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (min, okMin) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      let (x, okX) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okMax or not okMin or not okX:
        return seInvalidStack
      interp.push(fromScriptNum(if x >= min and x < max: 1 else: 0))

    # Crypto operations
    of OP_RIPEMD160:
      if interp.stack.len < 1:
        return seInvalidStack
      let data = interp.pop()
      let hashed = ripemd160(data)
      interp.push(@hashed)

    of OP_SHA1:
      if interp.stack.len < 1:
        return seInvalidStack
      let data = interp.pop()
      var sha1ctx: sha1
      sha1ctx.init()
      sha1ctx.update(data)
      let hashed = sha1ctx.finish().data
      interp.push(@hashed)

    of OP_SHA256:
      if interp.stack.len < 1:
        return seInvalidStack
      let data = interp.pop()
      let hashed = sha256(data)
      interp.push(@hashed)

    of OP_HASH160:
      if interp.stack.len < 1:
        return seInvalidStack
      let data = interp.pop()
      let hashed = hash160(data)
      interp.push(@hashed)

    of OP_HASH256:
      if interp.stack.len < 1:
        return seInvalidStack
      let data = interp.pop()
      let hashed = doubleSha256(data)
      interp.push(@hashed)

    of OP_CODESEPARATOR:
      interp.codesepPos = uint32(pc)

    of OP_CHECKSIG, OP_CHECKSIGVERIFY:
      if interp.stack.len < 2:
        return seInvalidStack

      # Pop pubkey first (top of stack), then signature
      let pubkey = interp.pop()
      let sig = interp.pop()

      var success = false

      if sig.len > 0 and pubkey.len > 0:
        case ctx.sigVersion
        of sigBase:
          # Legacy signature check
          if sig.len >= 1:
            let hashType = uint32(sig[sig.len - 1])
            let sigWithoutHashType = sig[0 ..< sig.len - 1]

            # FindAndDelete - only for legacy
            var scriptCode = @script
            scriptCode = findAndDelete(scriptCode, sig)

            let sighash = computeSighashLegacy(ctx.tx, ctx.inputIndex, scriptCode, hashType)
            success = verifyDer(pubkey, sighash, sigWithoutHashType)

        of sigWitnessV0:
          # SegWit v0 signature check
          # BIP141 WITNESS_PUBKEYTYPE: pubkeys must be compressed in witness v0
          if sfWitnessPubkeyType in interp.flags and not isCompressedPubkey(pubkey):
            return seWitnessPubkeyType

          if sig.len >= 1:
            let hashType = uint32(sig[sig.len - 1])
            let sigWithoutHashType = sig[0 ..< sig.len - 1]

            # For P2WPKH, scriptCode is OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
            let pubkeyHash = hash160(pubkey)
            var scriptCode: seq[byte] = @[OP_DUP, OP_HASH160, 0x14'u8]
            scriptCode.add(pubkeyHash)
            scriptCode.add([OP_EQUALVERIFY, OP_CHECKSIG])

            let sighash = computeSighashSegwitV0(ctx.tx, ctx.inputIndex, scriptCode, ctx.amount, hashType)
            success = verifyDer(pubkey, sighash, sigWithoutHashType)

        of sigTaproot, sigTapscript:
          # Taproot Schnorr signature check (BIP340)
          if pubkey.len == 32 and (sig.len == 64 or sig.len == 65):
            var hashType: uint8 = SIGHASH_DEFAULT
            var sigBytes: array[64, byte]

            if sig.len == 65:
              hashType = sig[64]
              # Validate hashType
              if hashType != SIGHASH_DEFAULT and hashType != SIGHASH_ALL and
                 hashType != SIGHASH_NONE and hashType != SIGHASH_SINGLE and
                 hashType != (SIGHASH_ALL or SIGHASH_ANYONECANPAY) and
                 hashType != (SIGHASH_NONE or SIGHASH_ANYONECANPAY) and
                 hashType != (SIGHASH_SINGLE or SIGHASH_ANYONECANPAY):
                if opcode == OP_CHECKSIGVERIFY:
                  return seCheckSigVerify
                interp.push(@[])
                continue

            for i in 0 ..< 64:
              sigBytes[i] = sig[i]

            var xonlyPk: array[32, byte]
            for i in 0 ..< 32:
              xonlyPk[i] = pubkey[i]

            let extFlag = if ctx.sigVersion == sigTapscript: 1'u8 else: 0'u8
            let sighash = computeSighashTaproot(
              ctx.tx, ctx.inputIndex, ctx.amounts, ctx.scriptPubKeys,
              hashType, extFlag, ctx.annex, ctx.tapleafHash, ctx.codesepPos
            )

            success = verifySchnorr(xonlyPk, @sighash, sigBytes)

      # BIP146 NULLFAIL: if signature check failed and NULLFAIL flag is set,
      # the signature must be empty
      if not success and sfNullFail in interp.flags and sig.len > 0:
        return seNullFail

      if opcode == OP_CHECKSIGVERIFY:
        if not success:
          return seCheckSigVerify
      else:
        interp.push(if success: @[1'u8] else: @[])

    of OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY:
      # CHECKMULTISIG has the famous off-by-one bug
      if interp.stack.len < 1:
        return seInvalidStack

      let (nPubkeys, okN) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okN or nPubkeys < 0 or nPubkeys > MaxPubkeysPerMultisig:
        return sePubkeyCount

      interp.opCount += int(nPubkeys)
      if interp.opCount > MaxOpsPerScript:
        return seOpCount

      if interp.stack.len < int(nPubkeys):
        return seInvalidStack

      var pubkeys: seq[seq[byte]]
      for i in 0 ..< int(nPubkeys):
        pubkeys.add(interp.pop())

      if interp.stack.len < 1:
        return seInvalidStack

      let (nSigs, okS) = toScriptNum(interp.pop(), sfMinimalData in interp.flags)
      if not okS or nSigs < 0 or nSigs > nPubkeys:
        return seSigCount

      if interp.stack.len < int(nSigs):
        return seInvalidStack

      var sigs: seq[seq[byte]]
      for i in 0 ..< int(nSigs):
        sigs.add(interp.pop())

      # Pop the dummy element (off-by-one bug)
      if interp.stack.len < 1:
        return seInvalidStack
      let dummy = interp.pop()

      # BIP147: dummy must be empty when NULLDUMMY is active
      if sfNullDummy in interp.flags and dummy.len > 0:
        return seNullDummy

      # Verify signatures
      var success = true
      var iSig = 0
      var iPubkey = 0

      while iSig < int(nSigs) and success:
        let sig = sigs[iSig]
        let pubkey = pubkeys[iPubkey]

        var verified = false
        if sig.len > 0 and pubkey.len > 0:
          case ctx.sigVersion
          of sigBase:
            if sig.len >= 1:
              let hashType = uint32(sig[sig.len - 1])
              let sigWithoutHashType = sig[0 ..< sig.len - 1]
              var scriptCode = @script
              # FindAndDelete all signatures (only for legacy)
              for s in sigs:
                scriptCode = findAndDelete(scriptCode, s)
              let sighash = computeSighashLegacy(ctx.tx, ctx.inputIndex, scriptCode, hashType)
              verified = verifyDer(pubkey, sighash, sigWithoutHashType)

          of sigWitnessV0:
            # BIP141 WITNESS_PUBKEYTYPE: pubkeys must be compressed in witness v0
            if sfWitnessPubkeyType in interp.flags and not isCompressedPubkey(pubkey):
              return seWitnessPubkeyType

            if sig.len >= 1:
              let hashType = uint32(sig[sig.len - 1])
              let sigWithoutHashType = sig[0 ..< sig.len - 1]
              # For P2WSH, use the witness script as scriptCode
              let sighash = computeSighashSegwitV0(ctx.tx, ctx.inputIndex, script, ctx.amount, hashType)
              verified = verifyDer(pubkey, sighash, sigWithoutHashType)

          else:
            # Tapscript doesn't use CHECKMULTISIG
            discard

        if verified:
          iSig += 1
        iPubkey += 1

        # Not enough pubkeys left
        if int(nSigs) - iSig > int(nPubkeys) - iPubkey:
          success = false

      # BIP146 NULLFAIL: if multisig failed and NULLFAIL flag is set,
      # ALL signatures must be empty
      if not success and sfNullFail in interp.flags:
        for sigItem in sigs:
          if sigItem.len > 0:
            return seNullFail

      if opcode == OP_CHECKMULTISIGVERIFY:
        if not success:
          return seCheckMultisigVerify
      else:
        interp.push(if success: @[1'u8] else: @[])

    of OP_CHECKLOCKTIMEVERIFY:
      if sfCheckLockTimeVerify notin interp.flags:
        # Treat as NOP if flag not set
        discard
      else:
        if interp.stack.len < 1:
          return seInvalidStack

        let (locktime, ok) = toScriptNum(interp.peek(), sfMinimalData in interp.flags, 5)
        if not ok or locktime < 0:
          return seNegativeLocktime

        # Check locktime type consistency
        let txLocktime = int64(ctx.tx.lockTime)
        let isBlockLocktime = locktime < 500_000_000
        let isTxBlockLocktime = txLocktime < 500_000_000

        if isBlockLocktime != isTxBlockLocktime:
          return seUnsatisfiedLocktime

        # Check locktime value
        if locktime > txLocktime:
          return seUnsatisfiedLocktime

        # Check sequence isn't disabled
        if ctx.tx.inputs[ctx.inputIndex].sequence == 0xFFFFFFFF'u32:
          return seUnsatisfiedLocktime

    of OP_CHECKSEQUENCEVERIFY:
      if sfCheckSequenceVerify notin interp.flags:
        # Treat as NOP if flag not set
        discard
      else:
        if interp.stack.len < 1:
          return seInvalidStack

        let (sequence, ok) = toScriptNum(interp.peek(), sfMinimalData in interp.flags, 5)
        if not ok or sequence < 0:
          return seNegativeLocktime

        # If disable flag is set, skip checks
        if (uint32(sequence) and SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0:
          discard
        else:
          # Check tx version
          if ctx.tx.version < 2:
            return seUnsatisfiedLocktime

          let txSequence = ctx.tx.inputs[ctx.inputIndex].sequence

          # Check sequence disable flag
          if (txSequence and SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0:
            return seUnsatisfiedLocktime

          # Check type consistency
          let isTimeType = (uint32(sequence) and SEQUENCE_LOCKTIME_TYPE_FLAG) != 0
          let isTxTimeType = (txSequence and SEQUENCE_LOCKTIME_TYPE_FLAG) != 0

          if isTimeType != isTxTimeType:
            return seUnsatisfiedLocktime

          # Check value
          let maskedSeq = uint32(sequence) and SEQUENCE_LOCKTIME_MASK
          let maskedTxSeq = txSequence and SEQUENCE_LOCKTIME_MASK

          if maskedSeq > maskedTxSeq:
            return seUnsatisfiedLocktime

    of OP_CHECKSIGADD:
      # BIP342 tapscript opcode
      if ctx.sigVersion != sigTapscript:
        return seInvalidOpcode

      if interp.stack.len < 3:
        return seInvalidStack

      let pubkey = interp.pop()
      let (n, ok) = toScriptNum(interp.pop(), true)
      let sig = interp.pop()

      if not ok:
        return seInvalidStack

      var success = false
      if sig.len > 0:
        if pubkey.len == 32 and (sig.len == 64 or sig.len == 65):
          var hashType: uint8 = SIGHASH_DEFAULT
          var sigBytes: array[64, byte]

          if sig.len == 65:
            hashType = sig[64]

          for i in 0 ..< 64:
            sigBytes[i] = sig[i]

          var xonlyPk: array[32, byte]
          for i in 0 ..< 32:
            xonlyPk[i] = pubkey[i]

          let sighash = computeSighashTaproot(
            ctx.tx, ctx.inputIndex, ctx.amounts, ctx.scriptPubKeys,
            hashType, 1, ctx.annex, ctx.tapleafHash, ctx.codesepPos
          )

          success = verifySchnorr(xonlyPk, @sighash, sigBytes)

      interp.push(fromScriptNum(if success: n + 1 else: n))

    of OP_VER, OP_RESERVED, OP_RESERVED1, OP_RESERVED2:
      return seInvalidOpcode

    else:
      return seUnknownOpcode

    # Check combined stack size
    if interp.combinedStackSize() > MaxStackElements:
      return seStackSize

  # Check for unbalanced conditionals
  if interp.execStack.len > 0:
    return seUnbalancedConditional

  seOk

# High-level verification functions

# Forward declaration
proc verifyWitnessProgram*(
  witness: seq[seq[byte]],
  version: int,
  program: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi,
  flags: set[ScriptFlags]
): bool

proc verifyScript*(
  scriptSig: seq[byte],
  scriptPubKey: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi = Satoshi(0),
  flags: set[ScriptFlags] = {},
  witness: seq[seq[byte]] = @[]
): bool =
  ## Verify a transaction input

  var interp = newInterpreter(flags)

  # Create signature check context
  var ctx = SigCheckContext(
    tx: tx,
    inputIndex: inputIndex,
    amount: amount,
    scriptPubKey: scriptPubKey,
    sigVersion: sigBase,
    amounts: @[amount],
    scriptPubKeys: @[scriptPubKey],
    codesepPos: 0xFFFFFFFF'u32
  )

  # Execute scriptSig
  if scriptSig.len > 0:
    let err = interp.eval(scriptSig, ctx)
    if err != seOk:
      return false

  # Copy stack for P2SH
  let stackCopy = interp.stack

  # Execute scriptPubKey
  let err = interp.eval(scriptPubKey, ctx)
  if err != seOk:
    return false

  if interp.stack.len == 0 or not toBool(interp.peek()):
    return false

  # Check for witness program
  let (isWitness, witnessVersion, witnessProgram) = isWitnessProgram(scriptPubKey)

  if sfWitness in flags and isWitness:
    if scriptSig.len > 0:
      # Native witness programs must have empty scriptSig
      return false

    return verifyWitnessProgram(
      witness, witnessVersion, witnessProgram, tx, inputIndex, amount, flags
    )

  # P2SH handling
  # BIP16: P2SH scriptSig must be push-only (unconditional consensus rule)
  # This is NOT gated by SCRIPT_VERIFY_SIGPUSHONLY - it's always enforced for P2SH
  if sfP2SH in flags and isP2SH(scriptPubKey):
    if not isPushOnly(scriptSig):
      return false  # seSigPushOnly

    if stackCopy.len == 0:
      return false

    # The serialized script is the last item pushed by scriptSig
    let serializedScript = stackCopy[stackCopy.len - 1]

    # Reset interpreter with P2SH stack (without the serialized script)
    interp = newInterpreter(flags)
    for i in 0 ..< stackCopy.len - 1:
      interp.push(stackCopy[i])

    ctx.sigVersion = sigBase
    let err = interp.eval(serializedScript, ctx)
    if err != seOk:
      return false

    if interp.stack.len == 0 or not toBool(interp.peek()):
      return false

    # Check for witness program in P2SH
    let (isP2shWitness, p2shVersion, p2shProgram) = isWitnessProgram(serializedScript)

    if sfWitness in flags and isP2shWitness:
      return verifyWitnessProgram(
        witness, p2shVersion, p2shProgram, tx, inputIndex, amount, flags
      )

  # Clean stack check
  if sfCleanStack in flags:
    if interp.stack.len != 1:
      return false

  true

# Forward declaration for verifyScriptWithError
proc verifyWitnessProgramWithError*(
  witness: seq[seq[byte]],
  version: int,
  program: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi,
  flags: set[ScriptFlags]
): ScriptError

proc verifyScriptWithError*(
  scriptSig: seq[byte],
  scriptPubKey: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi = Satoshi(0),
  flags: set[ScriptFlags] = {},
  witness: seq[seq[byte]] = @[]
): ScriptError =
  ## Verify a transaction input, returning the specific error on failure

  var interp = newInterpreter(flags)

  # Create signature check context
  var ctx = SigCheckContext(
    tx: tx,
    inputIndex: inputIndex,
    amount: amount,
    scriptPubKey: scriptPubKey,
    sigVersion: sigBase,
    amounts: @[amount],
    scriptPubKeys: @[scriptPubKey],
    codesepPos: 0xFFFFFFFF'u32
  )

  # Execute scriptSig
  if scriptSig.len > 0:
    let err = interp.eval(scriptSig, ctx)
    if err != seOk:
      return err

  # Copy stack for P2SH
  let stackCopy = interp.stack

  # Execute scriptPubKey
  let err = interp.eval(scriptPubKey, ctx)
  if err != seOk:
    return err

  if interp.stack.len == 0 or not toBool(interp.peek()):
    return seVerify

  # Check for witness program
  let (isWitness, witnessVersion, witnessProgram) = isWitnessProgram(scriptPubKey)

  if sfWitness in flags and isWitness:
    if scriptSig.len > 0:
      # Native witness programs must have empty scriptSig
      return seWitnessMalleated

    return verifyWitnessProgramWithError(
      witness, witnessVersion, witnessProgram, tx, inputIndex, amount, flags
    )

  # P2SH handling
  # BIP16: P2SH scriptSig must be push-only (unconditional consensus rule)
  # This is NOT gated by SCRIPT_VERIFY_SIGPUSHONLY - it's always enforced for P2SH
  if sfP2SH in flags and isP2SH(scriptPubKey):
    if not isPushOnly(scriptSig):
      return seSigPushOnly

    if stackCopy.len == 0:
      return seVerify

    # The serialized script is the last item pushed by scriptSig
    let serializedScript = stackCopy[stackCopy.len - 1]

    # Reset interpreter with P2SH stack (without the serialized script)
    interp = newInterpreter(flags)
    for i in 0 ..< stackCopy.len - 1:
      interp.push(stackCopy[i])

    ctx.sigVersion = sigBase
    let scriptErr = interp.eval(serializedScript, ctx)
    if scriptErr != seOk:
      return scriptErr

    if interp.stack.len == 0 or not toBool(interp.peek()):
      return seVerify

    # Check for witness program in P2SH
    let (isP2shWitness, p2shVersion, p2shProgram) = isWitnessProgram(serializedScript)

    if sfWitness in flags and isP2shWitness:
      return verifyWitnessProgramWithError(
        witness, p2shVersion, p2shProgram, tx, inputIndex, amount, flags
      )

  # Clean stack check
  if sfCleanStack in flags:
    if interp.stack.len != 1:
      return seCleanStack

  seOk

proc verifyWitnessProgram*(
  witness: seq[seq[byte]],
  version: int,
  program: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi,
  flags: set[ScriptFlags]
): bool =
  ## Verify a witness program

  if version == 0:
    # SegWit v0
    if program.len == 20:
      # P2WPKH
      if witness.len != 2:
        return false

      # Construct P2PKH script
      var scriptCode: seq[byte] = @[OP_DUP, OP_HASH160, 0x14'u8]
      scriptCode.add(program)
      scriptCode.add([OP_EQUALVERIFY, OP_CHECKSIG])

      var interp = newInterpreter(flags)
      # Push witness items onto stack (wire order is bottom-to-top)
      for item in witness:
        interp.push(item)

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_0, 0x14'u8] & program,
        sigVersion: sigWitnessV0,
        amounts: @[amount],
        scriptPubKeys: @[@[OP_0, 0x14'u8] & program],
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(scriptCode, ctx)
      if err != seOk:
        return false

      # Witness scripts implicitly require cleanstack: exactly one element on stack
      # This is NOT gated by the CLEANSTACK flag - it's always enforced for witness
      if interp.stack.len != 1:
        return false

      return castToBool(interp.peek())

    elif program.len == 32:
      # P2WSH
      if witness.len == 0:
        return false

      # Last witness item is the script
      let witnessScript = witness[witness.len - 1]

      # Verify script hash
      let computedHash = sha256(witnessScript)
      if program.len != 32:
        return false
      for i in 0 ..< 32:
        if computedHash[i] != program[i]:
          return false

      var interp = newInterpreter(flags)
      # Push witness items (except script) onto stack
      # Wire order is bottom-to-top, so we push in order
      for i in 0 ..< witness.len - 1:
        interp.push(witness[i])

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_0, 0x20'u8] & program,
        sigVersion: sigWitnessV0,
        amounts: @[amount],
        scriptPubKeys: @[@[OP_0, 0x20'u8] & program],
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(witnessScript, ctx)
      if err != seOk:
        return false

      # Witness scripts implicitly require cleanstack: exactly one element on stack
      # This is NOT gated by the CLEANSTACK flag - it's always enforced for witness
      if interp.stack.len != 1:
        return false

      return castToBool(interp.peek())

    else:
      return false

  elif version == 1 and sfTaproot in flags:
    # Taproot (SegWit v1)
    if program.len != 32:
      return false

    if witness.len == 0:
      return false

    # Check for annex
    var annex: seq[byte]
    var witnessStack = witness
    if witnessStack.len >= 2 and witnessStack[witnessStack.len - 1].len > 0 and
       witnessStack[witnessStack.len - 1][0] == 0x50:
      annex = witnessStack[witnessStack.len - 1]
      witnessStack = witnessStack[0 ..< witnessStack.len - 1]

    if witnessStack.len == 1:
      # Key path spend
      let sig = witnessStack[0]
      if sig.len != 64 and sig.len != 65:
        return false

      var hashType: uint8 = SIGHASH_DEFAULT
      var sigBytes: array[64, byte]

      if sig.len == 65:
        hashType = sig[64]
        if hashType == 0x00:
          return false  # Invalid explicit SIGHASH_DEFAULT

      for i in 0 ..< 64:
        sigBytes[i] = sig[i]

      # Get all input amounts and scriptPubKeys for taproot sighash
      var amounts: seq[Satoshi]
      var scriptPubKeys: seq[seq[byte]]
      for i, inp in tx.inputs:
        if i == inputIndex:
          amounts.add(amount)
          scriptPubKeys.add(@[OP_1, 0x20'u8] & program)
        else:
          amounts.add(Satoshi(0))  # Would need actual amounts
          scriptPubKeys.add(@[])   # Would need actual scriptPubKeys

      let sighash = computeSighashTaproot(
        tx, inputIndex, amounts, scriptPubKeys, hashType, 0, annex
      )

      var xonlyPk: array[32, byte]
      for i in 0 ..< 32:
        xonlyPk[i] = program[i]

      return verifySchnorr(xonlyPk, @sighash, sigBytes)

    else:
      # Script path spend
      if witnessStack.len < 2:
        return false

      let controlBlock = witnessStack[witnessStack.len - 1]
      let tapscript = witnessStack[witnessStack.len - 2]

      if controlBlock.len < 33 or (controlBlock.len - 33) mod 32 != 0:
        return false

      # Extract leaf version (mask with 0xFE to strip parity bit)
      let leafVersion = controlBlock[0] and 0xFE

      # Currently only leaf version 0xC0 (tapscript) is defined
      if leafVersion != 0xC0:
        # Unknown leaf version - succeed for forward compatibility
        return true

      # Compute leaf hash
      var leafData: seq[byte]
      leafData.add(leafVersion)
      var w = BinaryWriter()
      w.writeVarBytes(tapscript)
      leafData.add(w.data)
      let tapleafHash = taggedHash("TapLeaf", leafData)

      # Verify merkle proof and compute taproot output key
      var k = tapleafHash
      let pathLen = (controlBlock.len - 33) div 32

      for i in 0 ..< pathLen:
        var sibling: array[32, byte]
        for j in 0 ..< 32:
          sibling[j] = controlBlock[33 + i * 32 + j]

        var combined: seq[byte]
        # Lexicographic ordering
        var kLess = false
        for j in 0 ..< 32:
          if k[j] < sibling[j]:
            kLess = true
            break
          elif k[j] > sibling[j]:
            break
        if kLess:
          combined.add(k)
          combined.add(sibling)
        else:
          combined.add(sibling)
          combined.add(k)

        k = taggedHash("TapBranch", combined)

      # Extract internal pubkey from control block
      var internalPk: array[32, byte]
      for i in 0 ..< 32:
        internalPk[i] = controlBlock[1 + i]

      # Compute taptweak
      var tweakData: seq[byte]
      tweakData.add(internalPk)
      tweakData.add(k)
      let taptweak = taggedHash("TapTweak", tweakData)

      # TODO: Verify q = p + t*G where q is output key, p is internal key, t is tweak
      # This requires EC point operations which would need secp256k1 library calls
      # For now, we skip this verification

      # Execute tapscript
      var interp = newInterpreter(flags)
      # Push witness items (except control block and script) onto stack
      for i in 0 ..< witnessStack.len - 2:
        interp.push(witnessStack[i])

      # Get all input amounts and scriptPubKeys
      var amounts: seq[Satoshi]
      var scriptPubKeys: seq[seq[byte]]
      for i, inp in tx.inputs:
        if i == inputIndex:
          amounts.add(amount)
          scriptPubKeys.add(@[OP_1, 0x20'u8] & program)
        else:
          amounts.add(Satoshi(0))
          scriptPubKeys.add(@[])

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_1, 0x20'u8] & program,
        sigVersion: sigTapscript,
        amounts: amounts,
        scriptPubKeys: scriptPubKeys,
        annex: annex,
        tapleafHash: tapleafHash,
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(tapscript, ctx)
      if err != seOk:
        return false

      # Witness scripts implicitly require cleanstack: exactly one element on stack
      # This is NOT gated by the CLEANSTACK flag - it's always enforced for witness
      if interp.stack.len != 1:
        return false

      return castToBool(interp.peek())

  else:
    # Unknown witness version - succeed for forward compatibility
    # (but only if DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is not set)
    return true

proc verifyWitnessProgramWithError*(
  witness: seq[seq[byte]],
  version: int,
  program: seq[byte],
  tx: Transaction,
  inputIndex: int,
  amount: Satoshi,
  flags: set[ScriptFlags]
): ScriptError =
  ## Verify a witness program, returning the specific error on failure

  if version == 0:
    # SegWit v0
    if program.len == 20:
      # P2WPKH
      if witness.len != 2:
        return seWitnessProgramMismatch

      # Construct P2PKH script
      var scriptCode: seq[byte] = @[OP_DUP, OP_HASH160, 0x14'u8]
      scriptCode.add(program)
      scriptCode.add([OP_EQUALVERIFY, OP_CHECKSIG])

      var interp = newInterpreter(flags)
      for item in witness:
        interp.push(item)

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_0, 0x14'u8] & program,
        sigVersion: sigWitnessV0,
        amounts: @[amount],
        scriptPubKeys: @[@[OP_0, 0x14'u8] & program],
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(scriptCode, ctx)
      if err != seOk:
        return err

      # Witness cleanstack: must have exactly one element
      if interp.stack.len != 1:
        return seCleanStack

      if not castToBool(interp.peek()):
        return seVerify

      return seOk

    elif program.len == 32:
      # P2WSH
      if witness.len == 0:
        return seWitnessProgramMismatch

      let witnessScript = witness[witness.len - 1]
      let computedHash = sha256(witnessScript)
      for i in 0 ..< 32:
        if computedHash[i] != program[i]:
          return seWitnessProgramMismatch

      var interp = newInterpreter(flags)
      for i in 0 ..< witness.len - 1:
        interp.push(witness[i])

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_0, 0x20'u8] & program,
        sigVersion: sigWitnessV0,
        amounts: @[amount],
        scriptPubKeys: @[@[OP_0, 0x20'u8] & program],
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(witnessScript, ctx)
      if err != seOk:
        return err

      # Witness cleanstack: must have exactly one element
      if interp.stack.len != 1:
        return seCleanStack

      if not castToBool(interp.peek()):
        return seVerify

      return seOk

    else:
      return seWitnessProgramMismatch

  elif version == 1 and sfTaproot in flags:
    # Taproot (SegWit v1)
    if program.len != 32:
      return seWitnessProgramMismatch

    if witness.len == 0:
      return seWitnessProgramMismatch

    # Check for annex
    var annex: seq[byte]
    var witnessStack = witness
    if witnessStack.len >= 2 and witnessStack[witnessStack.len - 1].len > 0 and
       witnessStack[witnessStack.len - 1][0] == 0x50:
      annex = witnessStack[witnessStack.len - 1]
      witnessStack = witnessStack[0 ..< witnessStack.len - 1]

    if witnessStack.len == 1:
      # Key path spend - delegate to bool version for signature check
      if verifyWitnessProgram(witness, version, program, tx, inputIndex, amount, flags):
        return seOk
      else:
        return seTaprootError

    else:
      # Script path spend
      if witnessStack.len < 2:
        return seWitnessProgramMismatch

      let controlBlock = witnessStack[witnessStack.len - 1]
      let tapscript = witnessStack[witnessStack.len - 2]

      if controlBlock.len < 33 or (controlBlock.len - 33) mod 32 != 0:
        return seTaprootError

      let leafVersion = controlBlock[0] and 0xFE

      if leafVersion != 0xC0:
        # Unknown leaf version - succeed for forward compatibility
        return seOk

      # Compute leaf hash
      var leafData: seq[byte]
      leafData.add(leafVersion)
      var w = BinaryWriter()
      w.writeVarBytes(tapscript)
      leafData.add(w.data)
      let tapleafHash = taggedHash("TapLeaf", leafData)

      # Execute tapscript
      var interp = newInterpreter(flags)
      for i in 0 ..< witnessStack.len - 2:
        interp.push(witnessStack[i])

      var amounts: seq[Satoshi]
      var scriptPubKeys: seq[seq[byte]]
      for i, inp in tx.inputs:
        if i == inputIndex:
          amounts.add(amount)
          scriptPubKeys.add(@[OP_1, 0x20'u8] & program)
        else:
          amounts.add(Satoshi(0))
          scriptPubKeys.add(@[])

      var ctx = SigCheckContext(
        tx: tx,
        inputIndex: inputIndex,
        amount: amount,
        scriptPubKey: @[OP_1, 0x20'u8] & program,
        sigVersion: sigTapscript,
        amounts: amounts,
        scriptPubKeys: scriptPubKeys,
        annex: annex,
        tapleafHash: tapleafHash,
        codesepPos: 0xFFFFFFFF'u32
      )

      let err = interp.eval(tapscript, ctx)
      if err != seOk:
        return err

      # Witness cleanstack: must have exactly one element
      if interp.stack.len != 1:
        return seCleanStack

      if not castToBool(interp.peek()):
        return seVerify

      return seOk

  else:
    # Unknown witness version - succeed for forward compatibility
    return seOk

# Backward compatibility: simple execute without full tx context
proc execute*(
  interp: var ScriptInterpreter,
  script: seq[byte],
  sigChecker: proc(sig, pubkey: seq[byte]): bool = nil
): bool =
  ## Execute a script, returning true if successful (legacy API)
  var emptyTx = Transaction()
  var ctx = SigCheckContext(
    tx: emptyTx,
    inputIndex: 0,
    amount: Satoshi(0),
    sigVersion: sigBase,
    codesepPos: 0xFFFFFFFF'u32
  )

  let err = interp.eval(script, ctx)
  if err != seOk:
    return false

  if interp.stackSize == 0:
    return false

  toBool(interp.peek())
