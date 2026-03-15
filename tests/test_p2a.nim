## Tests for Pay-to-Anchor (P2A) script type

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

suite "pay-to-anchor":
  test "P2A script constant is correct":
    # OP_1 (0x51) PUSHBYTES_2 (0x02) 0x4e 0x73
    check P2AScript == @[0x51'u8, 0x02, 0x4e, 0x73]
    check P2AScript.len == 4

  test "isP2A detects valid P2A script":
    let script = @[0x51'u8, 0x02, 0x4e, 0x73]
    check isP2A(script) == true

  test "isP2A rejects wrong version opcode":
    # OP_2 instead of OP_1
    let script = @[0x52'u8, 0x02, 0x4e, 0x73]
    check isP2A(script) == false

  test "isP2A rejects wrong push length":
    # PUSHBYTES_3 instead of PUSHBYTES_2
    let script = @[0x51'u8, 0x03, 0x4e, 0x73, 0x00]
    check isP2A(script) == false

  test "isP2A rejects wrong program bytes":
    # Different 2-byte program
    let script = @[0x51'u8, 0x02, 0xff, 0xff]
    check isP2A(script) == false

  test "isP2A rejects too short script":
    let script = @[0x51'u8, 0x02, 0x4e]
    check isP2A(script) == false

  test "isP2A rejects too long script":
    let script = @[0x51'u8, 0x02, 0x4e, 0x73, 0x00]
    check isP2A(script) == false

  test "isP2A rejects P2TR script":
    # P2TR is OP_1 <32 bytes>, not P2A
    var script: seq[byte] = @[0x51'u8, 0x20]
    for i in 0 ..< 32:
      script.add(byte(i))
    check isP2A(script) == false

  test "isP2A rejects empty script":
    let script: seq[byte] = @[]
    check isP2A(script) == false

  test "isP2AFromProgram detects valid P2A witness program":
    let program = @[0x4e'u8, 0x73]
    check isP2AFromProgram(1, program) == true

  test "isP2AFromProgram rejects wrong version":
    let program = @[0x4e'u8, 0x73]
    check isP2AFromProgram(0, program) == false
    check isP2AFromProgram(2, program) == false

  test "isP2AFromProgram rejects wrong program bytes":
    let program = @[0xff'u8, 0xff]
    check isP2AFromProgram(1, program) == false

  test "isP2AFromProgram rejects wrong program length":
    let program = @[0x4e'u8]
    check isP2AFromProgram(1, program) == false
    let program3 = @[0x4e'u8, 0x73, 0x00]
    check isP2AFromProgram(1, program3) == false

  test "P2A is a witness program v1 with 2-byte program":
    let script = P2AScript
    let (isWitness, version, program) = isWitnessProgram(script)
    check isWitness == true
    check version == 1
    check program.len == 2
    check program[0] == 0x4e
    check program[1] == 0x73

  test "P2A witness program satisfies isP2AFromProgram":
    let script = P2AScript
    let (isWitness, version, program) = isWitnessProgram(script)
    check isWitness == true
    check isP2AFromProgram(version, program) == true

suite "anchor spending":
  test "P2A is anyone-can-spend with empty witness":
    # P2A outputs can be spent with an empty witness
    # This test verifies the script pattern is recognized correctly
    let script = P2AScript
    check isP2A(script) == true
    # The spending of P2A requires empty witness, which is handled
    # by the witness validation logic (no signature required)

  test "P2A constant matches expected bytes":
    # "Ns" = 0x4e 0x73 (ASCII for "Ns")
    check P2AScript[2] == 0x4e  # 'N'
    check P2AScript[3] == 0x73  # 's'
