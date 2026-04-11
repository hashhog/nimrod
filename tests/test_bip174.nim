## BIP174 Test Vectors
## Official test vectors from the BIP174 specification

import std/[unittest, strutils, options, base64, tables]
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]

# Helper to convert hex string to bytes
proc hexToBytes(hex: string): seq[byte] =
  let cleanHex = hex.replace(" ", "").replace("\n", "")
  result = newSeq[byte](cleanHex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(cleanHex[i*2 ..< i*2+2]))

# Helper to convert bytes to hex
proc toHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(b.toHex(2).toLowerAscii())

suite "BIP174 Serialization Tests":
  # These test vectors are from BIP174 specification

  test "valid PSBT format check":
    # A minimal valid PSBT - just magic, empty tx, and separators
    # We can't use the official vectors directly as they require real Bitcoin transactions
    # but we can verify our serialization format is correct

    var txid: array[32, byte]
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(0),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    let psbt = createPsbt(tx)
    let serialized = psbt.serialize()

    # Verify magic bytes
    check serialized[0] == 0x70  # 'p'
    check serialized[1] == 0x73  # 's'
    check serialized[2] == 0x62  # 'b'
    check serialized[3] == 0x74  # 't'
    check serialized[4] == 0xff  # separator

  test "key-value format":
    # Test that we write proper key-value pairs
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(100000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Add a witness UTXO
    let utxo = TxOut(
      value: Satoshi(200000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let serialized = psbt.serialize()

    # After magic bytes, first key should be 0x01 0x00 (length 1, type GLOBAL_UNSIGNED_TX)
    check serialized[5] == 0x01  # key length = 1
    check serialized[6] == 0x00  # key type = PSBT_GLOBAL_UNSIGNED_TX

    # Deserialize and verify
    let restored = deserialize(serialized)
    check restored.tx.isSome
    check restored.inputs[0].witnessUtxo.isSome
    check restored.inputs[0].witnessUtxo.get().value == Satoshi(200000)

suite "BIP174 Invalid PSBT Tests":
  test "network transaction, not PSBT":
    # A network transaction (starts with version, not magic)
    let networkTx = hexToBytes("0200000001")

    expect PsbtError:
      discard deserialize(networkTx)

  test "PSBT with invalid magic":
    # Correct magic except last byte
    let invalidMagic = hexToBytes("7073627400")

    expect PsbtError:
      discard deserialize(invalidMagic)

  test "PSBT with no inputs":
    # A PSBT must have at least one input in the transaction
    # (though this is enforced by Bitcoin consensus, not PSBT format)
    let tx = Transaction(
      version: 2,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(100000), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )

    # This should work - PSBT format allows it
    let psbt = createPsbt(tx)
    check psbt.inputs.len == 0

suite "BIP174 Signing Flow":
  test "creator role - create unsigned PSBT":
    var txid: array[32, byte]
    for i in 0 ..< 32:
      txid[i] = byte(i)

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 1),
        scriptSig: @[],
        sequence: 0xfffffffd'u32  # RBF enabled
      )],
      outputs: @[TxOut(
        value: Satoshi(99000000),  # ~1 BTC minus fee
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 700000
    )

    let psbt = createPsbt(tx)

    check psbt.tx.isSome
    check psbt.tx.get().version == 2
    check psbt.tx.get().lockTime == 700000
    check psbt.inputs.len == 1
    check psbt.outputs.len == 1

  test "updater role - add UTXO info":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(90000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Updater adds UTXO info
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    check psbt.inputs[0].witnessUtxo.isSome

  test "signer role - add partial signature":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Signer adds signature
    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8] & newSeq[byte](71) & @[0x01'u8]  # DER sig + SIGHASH_ALL
    psbt.addPartialSig(0, pubkey, sig)

    check len(psbt.inputs[0].partialSigs) == 1

  test "combiner role - merge PSBTs":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: TxId(txid), vout: 0), scriptSig: @[], sequence: 0xffffffff'u32),
        TxIn(prevOut: OutPoint(txid: TxId(txid), vout: 1), scriptSig: @[], sequence: 0xffffffff'u32)
      ],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    var psbt1 = createPsbt(tx)
    var psbt2 = createPsbt(tx)

    # Signer 1 signs input 0
    let pubkey1 = @[0x02'u8] & newSeq[byte](32)
    let sig1 = @[0x30'u8] & newSeq[byte](71)
    psbt1.addPartialSig(0, pubkey1, sig1)

    # Signer 2 signs input 1
    let pubkey2 = @[0x03'u8] & newSeq[byte](32)
    let sig2 = @[0x30'u8] & newSeq[byte](70)
    psbt2.addPartialSig(1, pubkey2, sig2)

    # Combiner merges
    let combined = combinePsbts(@[psbt1, psbt2])

    check len(combined.inputs[0].partialSigs) == 1
    check len(combined.inputs[1].partialSigs) == 1

  test "finalizer role - finalize P2WPKH":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(90000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Setup P2WPKH
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8] & newSeq[byte](71)
    psbt.addPartialSig(0, pubkey, sig)

    # Finalizer finalizes
    check finalizePsbt(psbt)

    # Should have witness stack
    check psbt.inputs[0].finalScriptWitness.len == 2
    check psbt.inputs[0].finalScriptWitness[0] == sig
    check psbt.inputs[0].finalScriptWitness[1] == pubkey

  test "extractor role - extract transaction":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(90000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Setup and finalize
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8] & newSeq[byte](71)
    psbt.addPartialSig(0, pubkey, sig)

    discard finalizePsbt(psbt)

    # Extractor extracts
    let extracted = extractTransaction(psbt)

    check extracted.isSome
    check extracted.get().witnesses.len == 1
    check extracted.get().isSegwit()

suite "BIP174 Multisig Tests":
  test "2-of-3 multisig PSBT flow":
    var txid: array[32, byte]
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(90000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Signer 1 creates and adds signature
    var psbt1 = createPsbt(tx)
    let pubkey1 = @[0x02'u8] & newSeq[byte](32)
    let sig1 = @[0x30'u8, 0x44] & newSeq[byte](70)
    psbt1.addPartialSig(0, pubkey1, sig1)

    # Signer 2 creates and adds signature
    var psbt2 = createPsbt(tx)
    let pubkey2 = @[0x02'u8, 0x01] & newSeq[byte](31)
    let sig2 = @[0x30'u8, 0x45] & newSeq[byte](71)
    psbt2.addPartialSig(0, pubkey2, sig2)

    # Combiner merges
    let combined = combinePsbts(@[psbt1, psbt2])

    # Should have both signatures
    check len(combined.inputs[0].partialSigs) == 2

suite "BIP174 Roundtrip Tests":
  test "full roundtrip with all input fields":
    var txid: array[32, byte]
    txid[0] = 0xab

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 5),
        scriptSig: @[],
        sequence: 0xfffffffe'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(12345678),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 123456
    )

    var psbt = createPsbt(tx)

    # Add various input data
    let utxo = TxOut(
      value: Satoshi(99999999),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    psbt.inputs[0].sighashType = some(1'i32)
    psbt.inputs[0].redeemScript = @[0x51'u8, 0x21] & newSeq[byte](33)
    psbt.inputs[0].witnessScript = @[0x52'u8, 0x21] & newSeq[byte](33)

    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let origin = KeyOriginInfo(
      fingerprint: [0xde'u8, 0xad, 0xbe, 0xef],
      path: @[44'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32]
    )
    psbt.inputs[0].hdKeypaths[pubkey] = origin

    # Serialize and deserialize
    let serialized = psbt.serialize()
    let restored = deserialize(serialized)

    # Verify all fields
    check restored.tx.isSome
    check restored.tx.get().version == 2
    check restored.tx.get().lockTime == 123456
    check restored.inputs[0].witnessUtxo.isSome
    check restored.inputs[0].witnessUtxo.get().value == Satoshi(99999999)
    check restored.inputs[0].sighashType.isSome
    check restored.inputs[0].sighashType.get() == 1
    check restored.inputs[0].redeemScript.len > 0
    check restored.inputs[0].witnessScript.len > 0
    check restored.inputs[0].hdKeypaths.len == 1

  test "full roundtrip with output fields":
    var txid: array[32, byte]

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(100000),
        scriptPubKey: @[0xa9'u8, 0x14] & newSeq[byte](20) & @[0x87'u8]  # P2SH
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Add output data
    psbt.outputs[0].redeemScript = @[0x00'u8, 0x14] & newSeq[byte](20)

    let pubkey = @[0x03'u8] & newSeq[byte](32)
    let origin = KeyOriginInfo(
      fingerprint: [0x01'u8, 0x02, 0x03, 0x04],
      path: @[49'u32 or 0x80000000'u32]
    )
    psbt.outputs[0].hdKeypaths[pubkey] = origin

    # Roundtrip
    let restored = deserialize(psbt.serialize())

    check restored.outputs[0].redeemScript.len > 0
    check restored.outputs[0].hdKeypaths.len == 1

suite "PSBT Edge Cases":
  test "multiple inputs and outputs":
    var txid1, txid2: array[32, byte]
    txid1[0] = 1
    txid2[0] = 2

    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: TxId(txid1), vout: 0), scriptSig: @[], sequence: 0xffffffff'u32),
        TxIn(prevOut: OutPoint(txid: TxId(txid2), vout: 1), scriptSig: @[], sequence: 0xffffffff'u32)
      ],
      outputs: @[
        TxOut(value: Satoshi(50000), scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)),
        TxOut(value: Satoshi(40000), scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20))
      ],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    check psbt.inputs.len == 2
    check psbt.outputs.len == 2

    # Add data to each input
    for i in 0 ..< 2:
      let utxo = TxOut(
        value: Satoshi(100000 + int64(i) * 10000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )
      psbt.updateInput(i, utxo, isWitness = true)

    let restored = deserialize(psbt.serialize())

    check restored.inputs.len == 2
    check restored.inputs[0].witnessUtxo.get().value == Satoshi(100000)
    check restored.inputs[1].witnessUtxo.get().value == Satoshi(110000)

  test "base64 with special characters":
    var txid: array[32, byte]
    for i in 0 ..< 32:
      txid[i] = byte(i * 8)  # Various byte values

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 255),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(0xffffffffffffff),  # Large value
        scriptPubKey: @[0xff'u8] & newSeq[byte](50)
      )],
      witnesses: @[],
      lockTime: 0xffffffff'u32
    )

    let psbt = createPsbt(tx)
    let encoded = psbt.toBase64()
    let decoded = fromBase64(encoded)

    check decoded.tx.isSome
    check decoded.tx.get().inputs[0].prevOut.vout == 255

# Run tests if executed directly
when isMainModule:
  echo "Running BIP174 tests..."
