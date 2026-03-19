## Tests for PSBT (BIP174/370) implementation
## Partially Signed Bitcoin Transactions

import std/[unittest, strutils, tables, options, base64, sets]
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "PSBT Magic and Constants":
  test "magic bytes correct":
    check PSBT_MAGIC_BYTES == [0x70'u8, 0x73, 0x62, 0x74, 0xff]
    # "psbt" + 0xff
    check PSBT_MAGIC_BYTES[0] == byte(ord('p'))
    check PSBT_MAGIC_BYTES[1] == byte(ord('s'))
    check PSBT_MAGIC_BYTES[2] == byte(ord('b'))
    check PSBT_MAGIC_BYTES[3] == byte(ord('t'))
    check PSBT_MAGIC_BYTES[4] == 0xff'u8

  test "global key types":
    check PSBT_GLOBAL_UNSIGNED_TX == 0x00'u8
    check PSBT_GLOBAL_XPUB == 0x01'u8
    check PSBT_GLOBAL_VERSION == 0xFB'u8
    check PSBT_GLOBAL_PROPRIETARY == 0xFC'u8

  test "input key types":
    check PSBT_IN_NON_WITNESS_UTXO == 0x00'u8
    check PSBT_IN_WITNESS_UTXO == 0x01'u8
    check PSBT_IN_PARTIAL_SIG == 0x02'u8
    check PSBT_IN_SIGHASH == 0x03'u8
    check PSBT_IN_REDEEMSCRIPT == 0x04'u8
    check PSBT_IN_WITNESSSCRIPT == 0x05'u8
    check PSBT_IN_BIP32_DERIVATION == 0x06'u8
    check PSBT_IN_SCRIPTSIG == 0x07'u8
    check PSBT_IN_SCRIPTWITNESS == 0x08'u8

  test "taproot input key types":
    check PSBT_IN_TAP_KEY_SIG == 0x13'u8
    check PSBT_IN_TAP_SCRIPT_SIG == 0x14'u8
    check PSBT_IN_TAP_LEAF_SCRIPT == 0x15'u8
    check PSBT_IN_TAP_BIP32_DERIVATION == 0x16'u8
    check PSBT_IN_TAP_INTERNAL_KEY == 0x17'u8
    check PSBT_IN_TAP_MERKLE_ROOT == 0x18'u8

  test "output key types":
    check PSBT_OUT_REDEEMSCRIPT == 0x00'u8
    check PSBT_OUT_WITNESSSCRIPT == 0x01'u8
    check PSBT_OUT_BIP32_DERIVATION == 0x02'u8
    check PSBT_OUT_TAP_INTERNAL_KEY == 0x05'u8
    check PSBT_OUT_TAP_TREE == 0x06'u8
    check PSBT_OUT_TAP_BIP32_DERIVATION == 0x07'u8

suite "KeyOriginInfo":
  test "serialize and deserialize empty path":
    let origin = KeyOriginInfo(
      fingerprint: [0x01'u8, 0x02, 0x03, 0x04],
      path: @[]
    )

    var w = BinaryWriter()
    w.serializeKeyOrigin(origin)

    check w.data.len == 4  # Just fingerprint

    var r = BinaryReader(data: w.data, pos: 0)
    let deserialized = r.deserializeKeyOrigin(4)

    check deserialized.fingerprint == origin.fingerprint
    check deserialized.path.len == 0

  test "serialize and deserialize with path":
    let origin = KeyOriginInfo(
      fingerprint: [0xab'u8, 0xcd, 0xef, 0x12],
      path: @[44'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32, 0'u32, 0'u32]
    )

    var w = BinaryWriter()
    w.serializeKeyOrigin(origin)

    # 4 bytes fingerprint + 5 * 4 bytes indices = 24 bytes
    check w.data.len == 24

    var r = BinaryReader(data: w.data, pos: 0)
    let deserialized = r.deserializeKeyOrigin(24)

    check deserialized.fingerprint == origin.fingerprint
    check deserialized.path == origin.path

  test "equality":
    let a = KeyOriginInfo(fingerprint: [1'u8, 2, 3, 4], path: @[1'u32, 2, 3])
    let b = KeyOriginInfo(fingerprint: [1'u8, 2, 3, 4], path: @[1'u32, 2, 3])
    let c = KeyOriginInfo(fingerprint: [1'u8, 2, 3, 5], path: @[1'u32, 2, 3])

    check a == b
    check a != c

suite "PsbtInput":
  test "isNull on empty input":
    let input = PsbtInput()
    check input.isNull()

  test "isNull with witness utxo":
    var input = PsbtInput()
    input.witnessUtxo = some(TxOut(value: Satoshi(100000), scriptPubKey: @[0x00'u8, 0x14]))
    check not input.isNull()

  test "isSigned checks final fields":
    var input = PsbtInput()
    check not input.isSigned()

    input.finalScriptSig = @[0x01'u8, 0x02]
    check input.isSigned()

    input.finalScriptSig = @[]
    input.finalScriptWitness = @[@[0x01'u8], @[0x02'u8]]
    check input.isSigned()

  test "merge inputs":
    var a = PsbtInput()
    var b = PsbtInput()

    b.witnessUtxo = some(TxOut(value: Satoshi(50000), scriptPubKey: @[]))
    b.redeemScript = @[0x51'u8, 0x21]
    b.partialSigs[@[0x02'u8, 0x03, 0x04]] = @[0x30'u8, 0x44]

    a.merge(b)

    check a.witnessUtxo.isSome
    check a.witnessUtxo.get().value == Satoshi(50000)
    check a.redeemScript == @[0x51'u8, 0x21]
    check @[0x02'u8, 0x03, 0x04] in a.partialSigs

suite "PsbtOutput":
  test "isNull on empty output":
    let output = PsbtOutput()
    check output.isNull()

  test "isNull with redeem script":
    var output = PsbtOutput()
    output.redeemScript = @[0x51'u8]
    check not output.isNull()

  test "merge outputs":
    var a = PsbtOutput()
    var b = PsbtOutput()

    b.redeemScript = @[0x51'u8, 0x21]
    b.witnessScript = @[0x52'u8, 0x21]

    a.merge(b)

    check a.redeemScript == @[0x51'u8, 0x21]
    check a.witnessScript == @[0x52'u8, 0x21]

suite "PSBT Creation":
  test "create from simple transaction":
    var txid: array[32, byte]
    txid[0] = 0xab
    txid[31] = 0xcd

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

    let psbt = createPsbt(tx)

    check psbt.tx.isSome
    check psbt.inputs.len == 1
    check psbt.outputs.len == 1

  test "reject transaction with scriptSig":
    var txid: array[32, byte]

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[0x01'u8, 0x02],  # Non-empty
        sequence: 0xffffffff'u32
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    expect PsbtError:
      discard createPsbt(tx)

suite "PSBT Serialization":
  test "serialize and deserialize minimal PSBT":
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

    let original = createPsbt(tx)
    let serialized = original.serialize()

    # Check magic bytes
    check serialized[0..4] == @PSBT_MAGIC_BYTES

    # Deserialize
    let restored = deserialize(serialized)

    check restored.tx.isSome
    check restored.inputs.len == original.inputs.len
    check restored.outputs.len == original.outputs.len

  test "serialize with witness utxo":
    var txid: array[32, byte]

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 0
    )

    var psbt = createPsbt(tx)

    # Add witness UTXO
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let serialized = psbt.serialize()
    let restored = deserialize(serialized)

    check restored.inputs[0].witnessUtxo.isSome
    check restored.inputs[0].witnessUtxo.get().value == Satoshi(100000)

  test "serialize with partial signature":
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

    # Add partial signature (33-byte compressed pubkey)
    let pubkey = newSeq[byte](33)
    let sig = @[0x30'u8, 0x44] & newSeq[byte](70)
    psbt.addPartialSig(0, pubkey, sig)

    let serialized = psbt.serialize()
    let restored = deserialize(serialized)

    check restored.inputs[0].partialSigs.len == 1
    check pubkey in restored.inputs[0].partialSigs

  test "serialize with HD keypath":
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

    # Add HD keypath
    let pubkey = newSeq[byte](33)
    let origin = KeyOriginInfo(
      fingerprint: [0x01'u8, 0x02, 0x03, 0x04],
      path: @[84'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32]
    )
    psbt.inputs[0].hdKeypaths[pubkey] = origin

    let serialized = psbt.serialize()
    let restored = deserialize(serialized)

    check restored.inputs[0].hdKeypaths.len == 1
    check pubkey in restored.inputs[0].hdKeypaths
    check restored.inputs[0].hdKeypaths[pubkey].fingerprint == origin.fingerprint

suite "PSBT Base64":
  test "encode and decode base64":
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

    let original = createPsbt(tx)
    let encoded = original.toBase64()

    # Should start with cHNidP (base64 of "psbt")
    check encoded.startsWith("cHNi")

    let decoded = fromBase64(encoded)
    check decoded.tx.isSome

  test "reject invalid base64":
    expect PsbtError:
      discard fromBase64("not-valid-base64!!!")

suite "PSBT Combining":
  test "combine PSBTs with same transaction":
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

    var psbt1 = createPsbt(tx)
    var psbt2 = createPsbt(tx)

    # Add different signatures to each
    let pubkey1 = @[0x02'u8] & newSeq[byte](32)
    let pubkey2 = @[0x03'u8] & newSeq[byte](32)
    let sig1 = @[0x30'u8, 0x44] & newSeq[byte](70)
    let sig2 = @[0x30'u8, 0x45] & newSeq[byte](71)

    psbt1.addPartialSig(0, pubkey1, sig1)
    psbt2.addPartialSig(0, pubkey2, sig2)

    let combined = combinePsbts(@[psbt1, psbt2])

    check combined.inputs[0].partialSigs.len == 2
    check pubkey1 in combined.inputs[0].partialSigs
    check pubkey2 in combined.inputs[0].partialSigs

  test "reject combining different transactions":
    var txid1: array[32, byte]
    var txid2: array[32, byte]
    txid2[0] = 0x01  # Different

    let tx1 = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid1), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    let tx2 = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(txid2), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )

    let psbt1 = createPsbt(tx1)
    let psbt2 = createPsbt(tx2)

    expect PsbtError:
      discard combinePsbts(@[psbt1, psbt2])

suite "PSBT Finalization":
  test "finalize P2WPKH input":
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

    # Add witness UTXO (P2WPKH: OP_0 <20 bytes>)
    var pubkeyHash = newSeq[byte](20)
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & pubkeyHash
    )
    psbt.updateInput(0, utxo, isWitness = true)

    # Add partial signature
    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8, 0x44] & newSeq[byte](70)
    psbt.addPartialSig(0, pubkey, sig)

    # Finalize
    check finalizePsbt(psbt)
    check psbt.inputs[0].isSigned()
    check psbt.inputs[0].finalScriptWitness.len == 2

  test "extract finalized transaction":
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
    var pubkeyHash = newSeq[byte](20)
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & pubkeyHash
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8, 0x44] & newSeq[byte](70)
    psbt.addPartialSig(0, pubkey, sig)

    discard finalizePsbt(psbt)

    # Extract
    let extracted = extractTransaction(psbt)
    check extracted.isSome
    check extracted.get().witnesses.len == 1
    check extracted.get().witnesses[0].len == 2

suite "PSBT Analysis":
  test "analyze unsigned PSBT":
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

    let psbt = createPsbt(tx)
    let analysis = analyzePsbt(psbt)

    check analysis.inputCount == 1
    check analysis.outputCount == 1
    check not analysis.isComplete
    check analysis.nextRole == Updater

  test "analyze with UTXO":
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

    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let analysis = analyzePsbt(psbt)

    check analysis.inputs[0].hasUtxo
    check analysis.inputs[0].isSegwit
    check not analysis.inputs[0].isTaproot
    check analysis.nextRole == Signer

  test "analyze taproot input":
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

    # P2TR: OP_1 <32 bytes>
    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x51'u8, 0x20] & newSeq[byte](32)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let analysis = analyzePsbt(psbt)

    check analysis.inputs[0].isSegwit
    check analysis.inputs[0].isTaproot

  test "count unsigned inputs":
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

    var psbt = createPsbt(tx)

    check countUnsignedInputs(psbt) == 2

    # "Sign" one input
    psbt.inputs[0].finalScriptWitness = @[@[0x01'u8]]

    check countUnsignedInputs(psbt) == 1

  test "calculate fee":
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

    let utxo = TxOut(
      value: Satoshi(100000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )
    psbt.updateInput(0, utxo, isWitness = true)

    let analysis = analyzePsbt(psbt)

    check analysis.totalFee.isSome
    check analysis.totalFee.get() == Satoshi(10000)

suite "PSBT Roles":
  test "role names":
    check roleName(Creator) == "creator"
    check roleName(Updater) == "updater"
    check roleName(Signer) == "signer"
    check roleName(Combiner) == "combiner"
    check roleName(Finalizer) == "finalizer"
    check roleName(Extractor) == "extractor"

suite "PSBT Error Handling":
  test "reject empty data":
    expect PsbtError:
      discard deserialize(@[])

  test "reject invalid magic":
    expect PsbtError:
      discard deserialize(@[0x00'u8, 0x00, 0x00, 0x00, 0x00])

  test "reject missing separator":
    # Just magic bytes, no content
    expect PsbtError:
      discard deserialize(@PSBT_MAGIC_BYTES)

  test "reject PSBT without transaction":
    # Magic + separator (no tx)
    var data = @PSBT_MAGIC_BYTES
    data.add(PSBT_SEPARATOR)

    expect PsbtError:
      discard deserialize(data)

# Run tests if executed directly
when isMainModule:
  echo "Running PSBT tests..."
