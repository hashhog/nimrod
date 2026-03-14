## Tests for witness cleanstack enforcement
## Witness scripts implicitly require exactly one element on stack after execution
## This is NOT gated by the CLEANSTACK flag - it's always enforced for witness programs

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/hashing

suite "witness cleanstack - P2WPKH":
  test "P2WPKH with clean stack passes":
    # A valid P2WPKH execution should leave exactly one true element
    # We can't fully test this without real crypto, but we can verify the structure
    discard "Requires full signature verification - tested via Bitcoin Core test vectors"

  test "P2WPKH witness stack must have exactly 2 elements":
    # P2WPKH requires exactly 2 witness elements: <sig> <pubkey>
    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}

    # 20-byte program (P2WPKH)
    var program: seq[byte] = @[]
    for i in 0 ..< 20:
      program.add(byte(i))

    # Wrong witness stack size (1 element instead of 2)
    let witness1 = @[@[0x01'u8, 0x02]]
    let result1 = verifyWitnessProgram(witness1, 0, program, dummyTx, 0, Satoshi(1000), flags)
    check result1 == false

    # Wrong witness stack size (3 elements instead of 2)
    let witness3 = @[@[0x01'u8], @[0x02'u8], @[0x03'u8]]
    let result3 = verifyWitnessProgram(witness3, 0, program, dummyTx, 0, Satoshi(1000), flags)
    check result3 == false

suite "witness cleanstack - P2WSH":
  test "P2WSH with extra items on stack fails":
    # Create a witness script that leaves extra items on stack
    # Script: OP_1 OP_1 OP_1 (pushes 3 items, should fail cleanstack)
    let witnessScript = @[OP_1, OP_1, OP_1]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    let witness = @[witnessScript]  # Just the script, no other items

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == false  # Should fail - stack has 3 items, not 1

  test "P2WSH with empty stack fails":
    # Create a witness script that leaves empty stack
    # Script: OP_1 OP_DROP (pushes 1, drops it, leaves 0 items)
    let witnessScript = @[OP_1, OP_DROP]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    let witness = @[witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == false  # Should fail - stack is empty

  test "P2WSH with exactly one true element passes":
    # Create a witness script that leaves exactly one true element
    # Script: OP_1 (pushes 1, leaves 1 true item)
    let witnessScript = @[OP_1]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    let witness = @[witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == true  # Should pass - exactly one true item

  test "P2WSH with exactly one false element fails":
    # Create a witness script that leaves exactly one false element
    # Script: OP_0 (pushes 0, leaves 1 false item)
    let witnessScript = @[OP_0]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    let witness = @[witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == false  # Should fail - element is false

  test "P2WSH with two items where top is true fails cleanstack":
    # Create a witness script that leaves two items on stack
    # Script: OP_1 OP_1 (pushes 2 items, top is true but cleanstack fails)
    let witnessScript = @[OP_1, OP_1]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    let witness = @[witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == false  # Should fail - 2 items on stack

  test "P2WSH using witness stack items with clean result":
    # Witness stack: [item1, item2, script]
    # Script: OP_ADD OP_1 OP_EQUAL (adds two items, compares to 1)
    # Witness items 0x01 + 0x00 = 0x01, equals 1 => true
    let witnessScript = @[OP_ADD, OP_1, OP_EQUAL]
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    let flags = {sfWitness}
    # Witness: [0x01, 0x00, script] => stack starts as [0x01, 0x00]
    let witness = @[@[0x01'u8], @[], witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == true  # Should pass - 0x01 + 0x00 = 0x01 == 1

suite "witness cleanstack - not flag gated":
  test "cleanstack enforced without CLEANSTACK flag":
    # Verify that witness cleanstack is enforced even without sfCleanStack in flags
    # This is the key difference from legacy CLEANSTACK which IS flag-gated
    let witnessScript = @[OP_1, OP_1]  # Leaves 2 items
    let scriptHash = sha256(witnessScript)

    var dummyTx = Transaction()
    dummyTx.version = 2
    dummyTx.inputs = @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )]
    dummyTx.outputs = @[TxOut(value: Satoshi(1000), scriptPubKey: @[])]
    dummyTx.lockTime = 0

    # Note: sfCleanStack is NOT in flags
    let flags = {sfWitness}
    let witness = @[witnessScript]

    let res = verifyWitnessProgram(witness, 0, @scriptHash, dummyTx, 0, Satoshi(1000), flags)
    check res == false  # Should still fail - witness cleanstack is implicit

suite "witness cleanstack - castToBool":
  test "castToBool alias works correctly":
    check castToBool(@[]) == false
    check castToBool(@[0x00'u8]) == false
    check castToBool(@[0x80'u8]) == false  # negative zero
    check castToBool(@[0x01'u8]) == true
    check castToBool(@[0x81'u8]) == true
    check castToBool(@[0x00'u8, 0x01]) == true
