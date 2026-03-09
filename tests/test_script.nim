## Tests for script interpreter

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/hashing

suite "script interpreter - basic operations":
  test "OP_TRUE":
    var interp = newInterpreter()
    let script = @[OP_TRUE]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 1

  test "OP_FALSE":
    var interp = newInterpreter()
    let script = @[OP_FALSE]
    let res = interp.execute(script)
    check res == false

  test "push data":
    var interp = newInterpreter()
    # Push 3 bytes: 0x01 0x02 0x03
    let script = @[0x03'u8, 0x01, 0x02, 0x03]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 1
    let top = interp.peek()
    check top == @[0x01'u8, 0x02, 0x03]

  test "OP_DUP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_DUP]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 2

  test "OP_EQUAL":
    var interp = newInterpreter()
    let script = @[OP_1, OP_1, OP_EQUAL]
    let res = interp.execute(script)
    check res == true

  test "OP_EQUAL fails":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_EQUAL]
    let res = interp.execute(script)
    check res == false

  test "OP_EQUALVERIFY success":
    var interp = newInterpreter()
    let script = @[OP_1, OP_1, OP_EQUALVERIFY, OP_TRUE]
    let res = interp.execute(script)
    check res == true

  test "OP_EQUALVERIFY fails":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_EQUALVERIFY]
    let res = interp.execute(script)
    check res == false

  test "OP_RETURN":
    var interp = newInterpreter()
    let script = @[OP_RETURN]
    let res = interp.execute(script)
    check res == false

  test "OP_SWAP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_SWAP]
    discard interp.execute(script)
    let top = interp.pop()
    check top == @[0x01'u8]

  test "OP_DROP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_DROP]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 1

  test "OP_HASH160":
    var interp = newInterpreter()
    # Push some data and hash it
    let script = @[0x03'u8, 0x01, 0x02, 0x03, OP_HASH160]
    let res = interp.execute(script)
    check res == true
    let hashed = interp.peek()
    check hashed.len == 20

suite "script interpreter - stack operations":
  test "OP_2DUP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_2DUP]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 4

  test "OP_3DUP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_3DUP]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 6

  test "OP_2DROP":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_2DROP]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 1

  test "OP_OVER":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_OVER]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 3
    check interp.peek() == @[0x01'u8]

  test "OP_ROT":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_ROT]
    discard interp.execute(script)
    # Stack: 2 3 1 (top)
    check interp.peek() == @[0x01'u8]

  test "OP_TOALTSTACK and OP_FROMALTSTACK":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_TOALTSTACK, OP_FROMALTSTACK]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 2
    check interp.peek() == @[0x02'u8]

  test "OP_DEPTH":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_DEPTH]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 4
    let (depth, ok) = toScriptNum(interp.peek())
    check ok == true
    check depth == 3

  test "OP_SIZE":
    var interp = newInterpreter()
    let script = @[0x05'u8, 0x01, 0x02, 0x03, 0x04, 0x05, OP_SIZE]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 2
    let (size, ok) = toScriptNum(interp.peek())
    check ok == true
    check size == 5

  test "OP_PICK":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_2, OP_PICK]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 4
    check interp.peek() == @[0x01'u8]

  test "OP_ROLL":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_3, OP_2, OP_ROLL]
    let res = interp.execute(script)
    check res == true
    check interp.stackSize == 3
    check interp.peek() == @[0x01'u8]

suite "script interpreter - arithmetic":
  test "OP_ADD":
    var interp = newInterpreter()
    let script = @[OP_2, OP_3, OP_ADD]
    let res = interp.execute(script)
    check res == true
    let (sum, ok) = toScriptNum(interp.peek())
    check ok == true
    check sum == 5

  test "OP_SUB":
    var interp = newInterpreter()
    let script = @[OP_5, OP_3, OP_SUB]
    let res = interp.execute(script)
    check res == true
    let (diff, ok) = toScriptNum(interp.peek())
    check ok == true
    check diff == 2

  test "OP_1ADD":
    var interp = newInterpreter()
    let script = @[OP_5, OP_1ADD]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 6

  test "OP_1SUB":
    var interp = newInterpreter()
    let script = @[OP_5, OP_1SUB]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 4

  test "OP_NEGATE":
    var interp = newInterpreter()
    let script = @[OP_5, OP_NEGATE]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == -5

  test "OP_ABS":
    var interp = newInterpreter()
    interp.push(fromScriptNum(-5))
    let script = @[OP_ABS]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 5

  test "OP_NOT":
    var interp = newInterpreter()
    let script = @[OP_0, OP_NOT]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_0NOTEQUAL":
    var interp = newInterpreter()
    let script = @[OP_5, OP_0NOTEQUAL]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_BOOLAND":
    var interp = newInterpreter()
    let script = @[OP_1, OP_2, OP_BOOLAND]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_BOOLOR":
    var interp = newInterpreter()
    let script = @[OP_0, OP_1, OP_BOOLOR]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_NUMEQUAL":
    var interp = newInterpreter()
    let script = @[OP_5, OP_5, OP_NUMEQUAL]
    let res = interp.execute(script)
    check res == true

  test "OP_NUMNOTEQUAL":
    var interp = newInterpreter()
    let script = @[OP_5, OP_6, OP_NUMNOTEQUAL]
    let res = interp.execute(script)
    check res == true

  test "OP_LESSTHAN":
    var interp = newInterpreter()
    let script = @[OP_3, OP_5, OP_LESSTHAN]
    let res = interp.execute(script)
    check res == true

  test "OP_GREATERTHAN":
    var interp = newInterpreter()
    let script = @[OP_5, OP_3, OP_GREATERTHAN]
    let res = interp.execute(script)
    check res == true

  test "OP_MIN":
    var interp = newInterpreter()
    let script = @[OP_5, OP_3, OP_MIN]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 3

  test "OP_MAX":
    var interp = newInterpreter()
    let script = @[OP_5, OP_3, OP_MAX]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 5

  test "OP_WITHIN":
    var interp = newInterpreter()
    # 3 WITHIN(2, 5) => true (2 <= 3 < 5)
    let script = @[OP_3, OP_2, OP_5, OP_WITHIN]
    let res = interp.execute(script)
    check res == true

suite "script interpreter - conditionals":
  test "OP_IF true branch":
    var interp = newInterpreter()
    let script = @[OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_IF false branch":
    var interp = newInterpreter()
    let script = @[OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 3

  test "OP_NOTIF":
    var interp = newInterpreter()
    let script = @[OP_0, OP_NOTIF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "nested IF":
    var interp = newInterpreter()
    let script = @[OP_1, OP_IF, OP_1, OP_IF, OP_5, OP_ENDIF, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 5

  test "OP_RETURN in non-executing branch does not fail":
    var interp = newInterpreter()
    let script = @[OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1]
    let res = interp.execute(script)
    check res == true

  test "unbalanced IF fails":
    var interp = newInterpreter()
    let script = @[OP_1, OP_IF, OP_2]
    let res = interp.execute(script)
    check res == false

  test "unbalanced ENDIF fails":
    var interp = newInterpreter()
    let script = @[OP_1, OP_ENDIF]
    let res = interp.execute(script)
    check res == false

suite "script interpreter - crypto":
  test "OP_SHA256":
    var interp = newInterpreter()
    let script = @[0x03'u8, 0x01, 0x02, 0x03, OP_SHA256]
    let res = interp.execute(script)
    check res == true
    let hashed = interp.peek()
    check hashed.len == 32

  test "OP_HASH256":
    var interp = newInterpreter()
    let script = @[0x03'u8, 0x01, 0x02, 0x03, OP_HASH256]
    let res = interp.execute(script)
    check res == true
    let hashed = interp.peek()
    check hashed.len == 32

  test "OP_RIPEMD160":
    var interp = newInterpreter()
    let script = @[0x03'u8, 0x01, 0x02, 0x03, OP_RIPEMD160]
    let res = interp.execute(script)
    check res == true
    let hashed = interp.peek()
    check hashed.len == 20

suite "script interpreter - script patterns":
  test "P2PKH script pattern detection":
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    var script: seq[byte] = @[OP_DUP, OP_HASH160, 0x14'u8]
    for i in 0 ..< 20:
      script.add(byte(i))
    script.add([OP_EQUALVERIFY, OP_CHECKSIG])
    check isP2PKH(script) == true

  test "P2SH script pattern detection":
    # OP_HASH160 <20 bytes> OP_EQUAL
    var script: seq[byte] = @[OP_HASH160, 0x14'u8]
    for i in 0 ..< 20:
      script.add(byte(i))
    script.add(OP_EQUAL)
    check isP2SH(script) == true

  test "P2WPKH script pattern detection":
    # OP_0 <20 bytes>
    var script: seq[byte] = @[OP_0, 0x14'u8]
    for i in 0 ..< 20:
      script.add(byte(i))
    check isP2WPKH(script) == true

  test "P2WSH script pattern detection":
    # OP_0 <32 bytes>
    var script: seq[byte] = @[OP_0, 0x20'u8]
    for i in 0 ..< 32:
      script.add(byte(i))
    check isP2WSH(script) == true

  test "P2TR script pattern detection":
    # OP_1 <32 bytes>
    var script: seq[byte] = @[OP_1, 0x20'u8]
    for i in 0 ..< 32:
      script.add(byte(i))
    check isP2TR(script) == true

  test "witness program detection v0":
    var script: seq[byte] = @[OP_0, 0x14'u8]
    for i in 0 ..< 20:
      script.add(byte(i))
    let (isWitness, version, program) = isWitnessProgram(script)
    check isWitness == true
    check version == 0
    check program.len == 20

  test "witness program detection v1":
    var script: seq[byte] = @[OP_1, 0x20'u8]
    for i in 0 ..< 32:
      script.add(byte(i))
    let (isWitness, version, program) = isWitnessProgram(script)
    check isWitness == true
    check version == 1
    check program.len == 32

suite "script interpreter - limits":
  test "script size limit":
    var interp = newInterpreter()
    # Create a script larger than 10,000 bytes
    var script: seq[byte] = @[]
    for i in 0 ..< 10001:
      script.add(OP_NOP)
    let res = interp.execute(script)
    check res == false

  test "opcode count limit":
    var interp = newInterpreter()
    # Create a script with more than 201 non-push opcodes
    var script: seq[byte] = @[OP_1]  # Start with something on stack
    for i in 0 ..< 202:
      script.add(OP_NOP)  # NOP counts as non-push
    let res = interp.execute(script)
    check res == false

  test "push size limit":
    var interp = newInterpreter({sfMinimalData})
    # Try to push more than 520 bytes (should fail with element size check)
    var script: seq[byte] = @[OP_PUSHDATA2, 0x09, 0x02]  # 521 bytes
    for i in 0 ..< 521:
      script.add(0x00)
    let res = interp.execute(script)
    check res == false

suite "script interpreter - boolean encoding":
  test "negative zero is false":
    check toBool(@[0x80'u8]) == false

  test "positive zero is false":
    check toBool(@[0x00'u8]) == false

  test "empty is false":
    check toBool(@[]) == false

  test "any non-zero is true":
    check toBool(@[0x01'u8]) == true
    check toBool(@[0x81'u8]) == true
    check toBool(@[0x00'u8, 0x01'u8]) == true

suite "script interpreter - number encoding":
  test "script number round trip":
    for n in [-1000'i64, -1, 0, 1, 127, 128, 255, 256, 1000]:
      let encoded = fromScriptNum(n)
      let (decoded, ok) = toScriptNum(encoded)
      check ok == true
      check decoded == n

  test "minimal encoding":
    # 0 should be empty
    let emptyBytes: seq[byte] = @[]
    check fromScriptNum(0) == emptyBytes
    # 1 should be single byte
    check fromScriptNum(1) == @[0x01'u8]
    # -1 should be 0x81
    check fromScriptNum(-1) == @[0x81'u8]
    # 127 should be single byte
    check fromScriptNum(127) == @[0x7f'u8]
    # 128 needs extra byte for sign
    check fromScriptNum(128) == @[0x80'u8, 0x00'u8]
    # -128 needs extra byte for sign
    check fromScriptNum(-128) == @[0x80'u8, 0x80'u8]

suite "script interpreter - disabled opcodes":
  test "OP_CAT disabled":
    var interp = newInterpreter()
    let script = @[OP_1, OP_1, OP_CAT]
    let res = interp.execute(script)
    check res == false

  test "OP_MUL disabled":
    var interp = newInterpreter()
    let script = @[OP_1, OP_1, OP_MUL]
    let res = interp.execute(script)
    check res == false

suite "script interpreter - tagged hash":
  test "tagged hash produces 32 bytes":
    let hash = taggedHash("TapLeaf", @[0x01'u8, 0x02, 0x03])
    check hash.len == 32

  test "tagged hash is deterministic":
    let hash1 = taggedHash("TapSighash", @[0x01'u8])
    let hash2 = taggedHash("TapSighash", @[0x01'u8])
    check hash1 == hash2

  test "different tags produce different hashes":
    let hash1 = taggedHash("TapLeaf", @[0x01'u8])
    let hash2 = taggedHash("TapBranch", @[0x01'u8])
    check hash1 != hash2

suite "script interpreter - push only":
  test "push only script":
    let script = @[OP_1, OP_2, 0x03'u8, 0x01, 0x02, 0x03]
    check isPushOnly(script) == true

  test "non-push only script":
    let script = @[OP_1, OP_DUP]
    check isPushOnly(script) == false

suite "script interpreter - P2PKH simulation":
  test "P2PKH script structure":
    # Simulated P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    # We'll just test the hash matching part without actual sig verification
    var interp = newInterpreter()
    interp.push(@[0x01'u8, 0x02, 0x03])  # Simulated pubkey

    let script = @[OP_DUP, OP_HASH160]
    discard interp.execute(script)

    check interp.stackSize == 2
    let hashed = interp.peek()
    check hashed.len == 20
