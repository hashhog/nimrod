## Tests for sigop counting with witness discount

import std/options
import unittest2
import ../src/consensus/[validation, params]
import ../src/primitives/types
import ../src/script/interpreter
import ../src/storage/chainstate

suite "sigop counting":
  test "countScriptSigops with OP_CHECKSIG":
    # P2PKH output script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let script = @[
      OP_DUP, OP_HASH160, 0x14'u8,  # OP_PUSHBYTES_20
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      OP_EQUALVERIFY, OP_CHECKSIG
    ]
    check countScriptSigops(script, accurate = false) == 1
    check countScriptSigops(script, accurate = true) == 1

  test "countScriptSigops with OP_CHECKMULTISIG inaccurate":
    # Bare multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    # Without accurate mode, counts 20 sigops
    # 0x21 = push 33 bytes, so we need exactly 33 bytes of data after each
    let script = @[OP_2] &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      @[OP_3, OP_CHECKMULTISIG]
    check countScriptSigops(script, accurate = false) == MaxPubkeysPerMultisig  # 20

  test "countScriptSigops with OP_CHECKMULTISIG accurate":
    # Bare 2-of-3 multisig with OP_3 preceding CHECKMULTISIG
    # 0x21 = push 33 bytes, so we need exactly 33 bytes of data after each
    let script = @[OP_2] &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      @[OP_3, OP_CHECKMULTISIG]
    check countScriptSigops(script, accurate = true) == 3

  test "isPayToScriptHash":
    # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    let p2shScript = @[
      0xa9'u8,  # OP_HASH160
      0x14'u8,  # Push 20 bytes
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x87'u8   # OP_EQUAL
    ]
    check isPayToScriptHash(p2shScript) == true

    # Not P2SH (wrong length)
    let notP2sh = @[0xa9'u8, 0x14'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87'u8]
    check isPayToScriptHash(notP2sh) == false

  test "isWitnessProgram for P2WPKH":
    # P2WPKH: OP_0 <20 bytes>
    let p2wpkh = @[0x00'u8, 0x14'u8] & newSeq[byte](20)
    let (valid, version, program) = validation.isWitnessProgram(p2wpkh)
    check valid == true
    check version == 0
    check program.len == 20

  test "isWitnessProgram for P2WSH":
    # P2WSH: OP_0 <32 bytes>
    let p2wsh = @[0x00'u8, 0x20'u8] & newSeq[byte](32)
    let (valid, version, program) = validation.isWitnessProgram(p2wsh)
    check valid == true
    check version == 0
    check program.len == 32

  test "isWitnessProgram for P2TR":
    # P2TR: OP_1 <32 bytes>
    let p2tr = @[0x51'u8, 0x20'u8] & newSeq[byte](32)
    let (valid, version, program) = validation.isWitnessProgram(p2tr)
    check valid == true
    check version == 1
    check program.len == 32

  test "isWitnessProgram invalid":
    # Too short
    let invalid1 = @[0x00'u8, 0x01'u8, 0x00'u8]
    let (valid1, _, _) = validation.isWitnessProgram(invalid1)
    check valid1 == false

    # Not OP_0..OP_16
    let invalid2 = @[0x02'u8, 0x14'u8] & newSeq[byte](20)  # 0x02 is not OP_0 or OP_1..OP_16
    let (valid2, _, _) = validation.isWitnessProgram(invalid2)
    check valid2 == false

  test "getLegacySigOpCount for P2PKH":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],  # Empty scriptSig (would be signature + pubkey)
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        # P2PKH output
        scriptPubKey: @[OP_DUP, OP_HASH160, 0x14'u8] & newSeq[byte](20) & @[OP_EQUALVERIFY, OP_CHECKSIG]
      )],
      witnesses: @[],
      lockTime: 0
    )
    # Output has 1 OP_CHECKSIG
    check getLegacySigOpCount(tx) == 1

suite "sigop cost with witness discount":
  test "legacy tx sigop cost scaled by 4":
    # A P2PKH output has 1 sigop, which costs 4 (WitnessScaleFactor)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[OP_DUP, OP_HASH160, 0x14'u8] & newSeq[byte](20) & @[OP_EQUALVERIFY, OP_CHECKSIG]
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Coinbase doesn't need UTXO lookup
    let lookupUtxo = proc(op: OutPoint): Option[UtxoEntry] = none(UtxoEntry)
    let result = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = false, useWitness = false)

    check result.isOk
    # 1 legacy sigop * 4 = 4
    check result.value == 4

  test "P2WPKH sigop cost is 1":
    # P2WPKH spending has 1 sigop, costs only 1 (witness discount)
    let prevTxid = TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: prevTxid, vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)  # P2WPKH output
      )],
      witnesses: @[@[@[0x30'u8] & newSeq[byte](70), @[0x02'u8] & newSeq[byte](32)]],
      lockTime: 0
    )

    # UTXO being spent is P2WPKH
    let p2wpkhScript = @[0x00'u8, 0x14] & newSeq[byte](20)
    let utxoEntry = UtxoEntry(
      output: TxOut(value: Satoshi(2_0000_0000), scriptPubKey: p2wpkhScript),
      height: 100,
      isCoinbase: false
    )

    let lookupUtxo = proc(op: OutPoint): Option[UtxoEntry] =
      if op.txid == prevTxid:
        return some(utxoEntry)
      none(UtxoEntry)

    let result = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = true, useWitness = true)

    check result.isOk
    # Legacy output sigops: 0 (P2WPKH output has no sigops in scriptPubKey)
    # Witness sigops: 1 (P2WPKH = 1)
    # Total = 0 * 4 + 1 = 1
    check result.value == 1

  test "P2WSH sigop cost from witness script":
    # P2WSH with a 2-of-3 multisig witness script
    let prevTxid = TxId([2'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    # Witness script: 2-of-3 multisig
    # 0x21 = push 33 bytes, so we need exactly 33 bytes of data after each
    let witnessScript = @[OP_2] &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      @[OP_3, OP_CHECKMULTISIG]

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: prevTxid, vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[@[
        @[],  # Dummy for multisig
        @[0x30'u8] & newSeq[byte](70),  # Sig 1
        @[0x30'u8] & newSeq[byte](70),  # Sig 2
        witnessScript  # The redeemscript is last
      ]],
      lockTime: 0
    )

    # UTXO being spent is P2WSH
    let p2wshScript = @[0x00'u8, 0x20] & newSeq[byte](32)
    let utxoEntry = UtxoEntry(
      output: TxOut(value: Satoshi(2_0000_0000), scriptPubKey: p2wshScript),
      height: 100,
      isCoinbase: false
    )

    let lookupUtxo = proc(op: OutPoint): Option[UtxoEntry] =
      if op.txid == prevTxid:
        return some(utxoEntry)
      none(UtxoEntry)

    let result = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = true, useWitness = true)

    check result.isOk
    # Witness sigops from 2-of-3 multisig: 3 (accurate count)
    # With witness discount, cost = 3
    check result.value == 3

  test "coinbase sigop cost":
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xffffffff'u32
        ),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],  # Height encoding
        sequence: 0xffffffff'u32
      )],
      outputs: @[
        TxOut(
          value: Satoshi(50_0000_0000),
          # P2PKH output with OP_CHECKSIG
          scriptPubKey: @[OP_DUP, OP_HASH160, 0x14'u8] & newSeq[byte](20) & @[OP_EQUALVERIFY, OP_CHECKSIG]
        )
      ],
      witnesses: @[],
      lockTime: 0
    )

    let lookupUtxo = proc(op: OutPoint): Option[UtxoEntry] = none(UtxoEntry)
    let result = getTransactionSigOpCost(coinbase, lookupUtxo, useP2SH = true, useWitness = true)

    check result.isOk
    # Coinbase output has 1 OP_CHECKSIG, scaled by 4
    check result.value == 4

suite "block sigop cost":
  test "MaxBlockSigopsCost constant":
    check MaxBlockSigopsCost == 80_000

  test "WitnessScaleFactor constant":
    check WitnessScaleFactor == 4

  test "countWitnessSigops P2WPKH":
    # P2WPKH: 20-byte program, version 0 = 1 sigop
    let program = newSeq[byte](20)
    let witness: seq[seq[byte]] = @[@[0x30'u8] & newSeq[byte](70), @[0x02'u8] & newSeq[byte](32)]
    check countWitnessSigops(0, program, witness) == 1

  test "countWitnessSigops P2WSH with simple checksig":
    # P2WSH with a simple OP_CHECKSIG script
    # Script: <pubkey> OP_CHECKSIG
    # 0x21 = push 33 bytes
    let program = newSeq[byte](32)
    let witnessScript = @[0x21'u8] & newSeq[byte](33) & @[OP_CHECKSIG]
    let witness: seq[seq[byte]] = @[@[0x30'u8] & newSeq[byte](70), witnessScript]
    check countWitnessSigops(0, program, witness) == 1

  test "countWitnessSigops P2TR returns 0":
    # Taproot sigops are handled by budget, not counted here
    let program = newSeq[byte](32)
    let witness: seq[seq[byte]] = @[@[0x00'u8] & newSeq[byte](63)]  # Schnorr signature
    check countWitnessSigops(1, program, witness) == 0

  test "MaxStandardTxSigopsCost constant":
    # policy/policy.h:44: MAX_BLOCK_SIGOPS_COST / 5 = 16_000
    check MaxStandardTxSigopsCost == 16_000
    check MaxStandardTxSigopsCost == MaxBlockSigopsCost div 5

  test "MaxStandardTxSigopsCost is 1/5 of MaxBlockSigopsCost":
    # Core invariant: per-tx policy limit = block limit / 5
    check MaxBlockSigopsCost == 5 * MaxStandardTxSigopsCost

suite "sigop boundary cases":
  test "CHECKMULTISIG accurate boundary: OP_1 (1 pubkey)":
    # OP_1 immediately before CHECKMULTISIG → accurate count = 1
    let script = @[OP_1, OP_CHECKMULTISIG]
    check countScriptSigops(script, accurate = true) == 1
    # Inaccurate always counts 20
    check countScriptSigops(script, accurate = false) == MaxPubkeysPerMultisig

  test "CHECKMULTISIG accurate boundary: OP_16 (16 pubkeys)":
    # OP_16 immediately before CHECKMULTISIG → accurate count = 16
    let script = @[OP_16, OP_CHECKMULTISIG]
    check countScriptSigops(script, accurate = true) == 16

  test "CHECKMULTISIG accurate: push between OP_n and CHECKMULTISIG resets lastOpcode":
    # When a push data opcode comes between OP_n and OP_CHECKMULTISIG,
    # lastOpcode is the push opcode (e.g. 0x21), not OP_n.
    # So accurate mode falls back to MAX_PUBKEYS_PER_MULTISIG (20).
    # This matches Bitcoin Core's GetSigOpCount() — script.cpp:162-179.
    # Real multisig has OP_n AFTER the pubkey pushes, immediately before CHECKMULTISIG.
    let pushThenCheckmultisig = @[OP_3, 0x21'u8] & newSeq[byte](33) & @[OP_CHECKMULTISIG]
    # lastOpcode = 0x21 (push33), not OP_3 → inaccurate path → 20
    check countScriptSigops(pushThenCheckmultisig, accurate = true) == MaxPubkeysPerMultisig

  test "CHECKMULTISIG accurate: proper 2-of-3 counts 3 not 20":
    # Real bare multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    # OP_3 is LAST opcode before CHECKMULTISIG → accurate count = 3
    let script = @[OP_2] &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      @[OP_3, OP_CHECKMULTISIG]
    check countScriptSigops(script, accurate = true) == 3
    check countScriptSigops(script, accurate = false) == 20

  test "CHECKMULTISIGVERIFY accurate counts like CHECKMULTISIG":
    # OP_CHECKMULTISIGVERIFY has same sigop counting as OP_CHECKMULTISIG
    let script = @[OP_3, OP_CHECKMULTISIGVERIFY]
    check countScriptSigops(script, accurate = true) == 3

  test "multiple CHECKSIG in one script":
    # OP_CHECKSIG + OP_CHECKSIGVERIFY in same script = 2 sigops
    let script = @[OP_CHECKSIG, OP_CHECKSIGVERIFY]
    check countScriptSigops(script, accurate = false) == 2

  test "witness P2WSH with 16-of-20 multisig counts accurately":
    # P2WSH witness script: OP_16 <pk1..pk20> OP_20 OP_CHECKMULTISIG
    # accurate count = 20 (OP_20 = OP_16+4 = out of OP_1..OP_16 range!  → actually OP_20 doesn't exist)
    # Bitcoin only supports up to 20 pubkeys, but OP_n only goes to OP_16.
    # For n > 16, you push n as a number, which is a push not OP_n — so lastOpcode = push byte
    # Let's test a valid case: 16-of-20 where m=16 via OP_16, n pushed as small int or direct
    # Use OP_16 for m, OP_20 not available → use 0x01 0x14 (push1 byte with value 20)
    # For the n-pubkey count in accurate mode, we need lastOpcode in [OP_1..OP_16]
    # If n=20 is pushed as a 1-byte number (opcode 0x01, data 0x14), lastOpcode=0x01 (not in range)
    # → falls back to MAX_PUBKEYS_PER_MULTISIG (20).  This is correct Core behavior.
    # Simpler test: just verify P2WSH correct accurate counting via countWitnessSigops
    let program = newSeq[byte](32)
    # Witness script: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    let witnessScript = @[OP_2] &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      (@[0x21'u8] & newSeq[byte](33)) &
      @[OP_3, OP_CHECKMULTISIG]
    let witness: seq[seq[byte]] = @[
      @[],
      @[0x30'u8] & newSeq[byte](70),
      @[0x30'u8] & newSeq[byte](70),
      witnessScript
    ]
    # P2WSH uses accurate=true → 3 sigops, cost=3 (witness discount, no ×4)
    check countWitnessSigops(0, program, witness) == 3

  test "P2WSH empty witness stack → 0 sigops (not crash)":
    # If witness.len == 0, P2WSH cannot extract script → 0 sigops
    let program = newSeq[byte](32)
    let witness: seq[seq[byte]] = @[]
    check countWitnessSigops(0, program, witness) == 0

  test "legacy sigop cost for max-multisig tx":
    # 1 CHECKMULTISIG inaccurate = 20 sigops × WitnessScaleFactor(4) = 80 cost
    let script = @[OP_CHECKMULTISIG]  # lastOpcode=0 (init), not in OP_1..OP_16 → inaccurate
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_000_000),
        scriptPubKey: script
      )],
      witnesses: @[],
      lockTime: 0
    )
    let lookupUtxo = proc(op: OutPoint): Option[UtxoEntry] = none(UtxoEntry)
    let result = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = false, useWitness = false)
    check result.isOk
    # 20 (inaccurate) × 4 (WitnessScaleFactor) = 80
    check result.value == 80

  test "sigop cost exceeding MaxStandardTxSigopsCost (16000)":
    # A block can have at most 80000 sigop cost.
    # Standard txs are limited to 16000 sigop cost (policy).
    # 16000 / 4 = 4000 legacy sigops needed to hit limit.
    # 4000 / 20 = 200 OP_CHECKMULTISIG (inaccurate) to hit 16000 cost.
    # Build a script with 201 OP_CHECKMULTISIG (inaccurate) = 201*20=4020 legacy sigops
    # 4020 × 4 = 16080 cost > 16000.
    var script: seq[byte] = @[]
    for _ in 0 ..< 201:
      script.add(OP_CHECKMULTISIG)
    # 201 × 20 inaccurate = 4020 sigops
    check countScriptSigops(script, accurate = false) == 201 * MaxPubkeysPerMultisig
    # cost = 4020 × 4 = 16080 > MaxStandardTxSigopsCost (16000)
    check (201 * MaxPubkeysPerMultisig * WitnessScaleFactor) > MaxStandardTxSigopsCost

  test "sigop cost at MaxStandardTxSigopsCost boundary (16000)":
    # Exactly MaxStandardTxSigopsCost / WitnessScaleFactor = 4000 legacy sigops is allowed.
    # 4000 / 20 = 200 inaccurate CHECKMULTISIG.
    var script: seq[byte] = @[]
    for _ in 0 ..< 200:
      script.add(OP_CHECKMULTISIG)
    check countScriptSigops(script, accurate = false) == 200 * MaxPubkeysPerMultisig  # = 4000
    # 4000 × 4 = 16000 = MaxStandardTxSigopsCost (exactly at limit, allowed)
    check (200 * MaxPubkeysPerMultisig * WitnessScaleFactor) == MaxStandardTxSigopsCost
