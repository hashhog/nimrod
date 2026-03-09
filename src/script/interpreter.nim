## Bitcoin Script interpreter
## Stack-based virtual machine for transaction validation

import std/[deques]
import ../primitives/types
import ../crypto/hashing

type
  ScriptError* = object of CatchableError

  ScriptStack* = Deque[seq[byte]]

  ScriptInterpreter* = object
    stack*: ScriptStack
    altStack*: ScriptStack

# Bitcoin Script opcodes
const
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

  # Comparison
  OP_EQUAL* = 0x87'u8
  OP_EQUALVERIFY* = 0x88'u8

proc newInterpreter*(): ScriptInterpreter =
  result.stack = initDeque[seq[byte]]()
  result.altStack = initDeque[seq[byte]]()

proc push*(interp: var ScriptInterpreter, data: seq[byte]) =
  interp.stack.addLast(data)

proc pop*(interp: var ScriptInterpreter): seq[byte] =
  if interp.stack.len == 0:
    raise newException(ScriptError, "stack underflow")
  result = interp.stack.popLast()

proc peek*(interp: ScriptInterpreter): seq[byte] =
  if interp.stack.len == 0:
    raise newException(ScriptError, "stack empty")
  result = interp.stack[interp.stack.len - 1]

proc stackSize*(interp: ScriptInterpreter): int =
  interp.stack.len

proc toBool(data: seq[byte]): bool =
  for i, b in data:
    if b != 0:
      # Check for negative zero
      if i == data.len - 1 and b == 0x80:
        return false
      return true
  false

proc toInt(data: seq[byte]): int64 =
  if data.len == 0:
    return 0
  var negative = (data[data.len - 1] and 0x80) != 0
  result = 0
  for i in countdown(data.len - 1, 0):
    var b = data[i]
    if i == data.len - 1:
      b = b and 0x7f
    result = (result shl 8) or int64(b)
  if negative:
    result = -result

proc fromInt(n: int64): seq[byte] =
  if n == 0:
    return @[]
  var absN = if n < 0: -n else: n
  result = @[]
  while absN > 0:
    result.add(byte(absN and 0xff))
    absN = absN shr 8
  if (result[result.len - 1] and 0x80) != 0:
    if n < 0:
      result.add(0x80)
    else:
      result.add(0x00)
  elif n < 0:
    result[result.len - 1] = result[result.len - 1] or 0x80

proc execute*(
  interp: var ScriptInterpreter,
  script: seq[byte],
  sigChecker: proc(sig, pubkey: seq[byte]): bool = nil
): bool =
  ## Execute a script, returning true if successful
  let scriptData = script
  var pc = 0

  while pc < scriptData.len:
    let opcode = scriptData[pc]
    pc += 1

    # Push data opcodes (1-75 bytes)
    if opcode >= 0x01 and opcode <= 0x4b:
      let len = int(opcode)
      if pc + len > scriptData.len:
        raise newException(ScriptError, "script too short")
      interp.push(scriptData[pc ..< pc + len])
      pc += len

    elif opcode == OP_0:
      interp.push(@[])

    elif opcode >= OP_1 and opcode <= OP_16:
      interp.push(@[byte(opcode - OP_1 + 1)])

    elif opcode == OP_1NEGATE:
      interp.push(fromInt(-1))

    elif opcode == OP_PUSHDATA1:
      if pc >= scriptData.len:
        raise newException(ScriptError, "script too short")
      let len = int(scriptData[pc])
      pc += 1
      if pc + len > scriptData.len:
        raise newException(ScriptError, "script too short")
      interp.push(scriptData[pc ..< pc + len])
      pc += len

    elif opcode == OP_PUSHDATA2:
      if pc + 2 > scriptData.len:
        raise newException(ScriptError, "script too short")
      let len = int(scriptData[pc]) or (int(scriptData[pc + 1]) shl 8)
      pc += 2
      if pc + len > scriptData.len:
        raise newException(ScriptError, "script too short")
      interp.push(scriptData[pc ..< pc + len])
      pc += len

    elif opcode == OP_NOP:
      discard

    elif opcode == OP_VERIFY:
      if not toBool(interp.pop()):
        return false

    elif opcode == OP_RETURN:
      return false

    elif opcode == OP_DUP:
      let top = interp.peek()
      interp.push(top)

    elif opcode == OP_DROP:
      discard interp.pop()

    elif opcode == OP_SWAP:
      let a = interp.pop()
      let b = interp.pop()
      interp.push(a)
      interp.push(b)

    elif opcode == OP_EQUAL:
      let a = interp.pop()
      let b = interp.pop()
      if a == b:
        interp.push(@[1'u8])
      else:
        interp.push(@[])

    elif opcode == OP_EQUALVERIFY:
      let a = interp.pop()
      let b = interp.pop()
      if a != b:
        return false

    elif opcode == OP_HASH160:
      let data = interp.pop()
      let hashed = hash160(data)
      interp.push(@hashed)

    elif opcode == OP_HASH256:
      let data = interp.pop()
      let hashed = doubleSha256(data)
      interp.push(@hashed)

    elif opcode == OP_SHA256:
      let data = interp.pop()
      let hashed = sha256(data)
      interp.push(@hashed)

    elif opcode == OP_CHECKSIG:
      let pubkey = interp.pop()
      let sig = interp.pop()
      if sigChecker != nil and sigChecker(sig, pubkey):
        interp.push(@[1'u8])
      else:
        interp.push(@[])

    elif opcode == OP_CHECKSIGVERIFY:
      let pubkey = interp.pop()
      let sig = interp.pop()
      if sigChecker == nil or not sigChecker(sig, pubkey):
        return false

    else:
      # Unknown or unimplemented opcode
      raise newException(ScriptError, "unknown opcode: " & $opcode)

  # Script succeeds if stack is non-empty and top is true
  if interp.stackSize == 0:
    return false
  toBool(interp.peek())

proc verifyScript*(
  scriptSig: seq[byte],
  scriptPubKey: seq[byte],
  sigChecker: proc(sig, pubkey: seq[byte]): bool = nil
): bool =
  ## Verify a transaction input by running scriptSig then scriptPubKey
  var interp = newInterpreter()

  # First execute scriptSig
  if not interp.execute(scriptSig, sigChecker):
    return false

  # Then execute scriptPubKey with same stack
  interp.execute(scriptPubKey, sigChecker)
