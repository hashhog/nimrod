## Tests for script interpreter

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

suite "script interpreter":
  test "OP_TRUE":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_TRUE])
    let result = interp.execute(script)
    check result == true
    check interp.stackSize == 1

  test "OP_FALSE":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_FALSE])
    let result = interp.execute(script)
    check result == false

  test "push data":
    var interp = newInterpreter()
    # Push 3 bytes: 0x01 0x02 0x03
    let script = ScriptBytes(@[0x03'u8, 0x01, 0x02, 0x03])
    let result = interp.execute(script)
    check result == true
    check interp.stackSize == 1
    let top = interp.peek()
    check top == @[0x01'u8, 0x02, 0x03]

  test "OP_DUP":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_DUP])
    let result = interp.execute(script)
    check result == true
    check interp.stackSize == 2

  test "OP_EQUAL":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_1, OP_EQUAL])
    let result = interp.execute(script)
    check result == true

  test "OP_EQUAL fails":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_2, OP_EQUAL])
    let result = interp.execute(script)
    check result == false

  test "OP_EQUALVERIFY success":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_1, OP_EQUALVERIFY, OP_TRUE])
    let result = interp.execute(script)
    check result == true

  test "OP_EQUALVERIFY fails":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_2, OP_EQUALVERIFY])
    let result = interp.execute(script)
    check result == false

  test "OP_RETURN":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_RETURN])
    let result = interp.execute(script)
    check result == false

  test "OP_SWAP":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_2, OP_SWAP])
    discard interp.execute(script)
    let top = interp.pop()
    check top == @[0x01'u8]

  test "OP_DROP":
    var interp = newInterpreter()
    let script = ScriptBytes(@[OP_1, OP_2, OP_DROP])
    let result = interp.execute(script)
    check result == true
    check interp.stackSize == 1

  test "OP_HASH160":
    var interp = newInterpreter()
    # Push some data and hash it
    let script = ScriptBytes(@[0x03'u8, 0x01, 0x02, 0x03, OP_HASH160])
    let result = interp.execute(script)
    check result == true
    let hashed = interp.peek()
    check hashed.len == 20

  test "P2PKH script pattern":
    # Simulated P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    # We'll just test the structure without actual sig verification
    var interp = newInterpreter()
    interp.push(@[0x01'u8, 0x02, 0x03])  # Simulated pubkey

    let script = ScriptBytes(@[OP_DUP, OP_HASH160])
    discard interp.execute(script)

    check interp.stackSize == 2
    let hashed = interp.peek()
    check hashed.len == 20

  test "verifyScript basic":
    let scriptSig = ScriptBytes(@[OP_1])
    let scriptPubKey = ScriptBytes(@[OP_1, OP_EQUAL])
    let result = verifyScript(scriptSig, scriptPubKey)
    check result == true
