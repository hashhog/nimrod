## Tests for legacy sighash computation
## Uses Bitcoin Core test vectors from sighash.json

import unittest2
import std/strutils
import ../src/script/sighash
import ../src/primitives/types
import ../src/primitives/serialize

# Helper to convert hex string to bytes
proc hexToBytes(hex: string): seq[byte] =
  if hex.len == 0:
    return @[]
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2+1]))

# Helper to convert bytes to hex string
proc bytesToHex(bytes: openArray[byte]): string =
  result = ""
  for b in bytes:
    result.add(b.toHex(2).toLowerAscii)

# Bitcoin Core sighash.json test vectors (subset)
# Format: [raw_transaction, script, input_index, hashType, expected_hash]
const testVectors = [
  ("907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229", "", 2, 1864164639'i32, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e"),
  ("a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5", "65", 0, -1391424484'i32, "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175"),
  ("6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8", "acab655151", 0, 479279909'i32, "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c"),
  ("73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000", "5163ac63635151ac", 1, 1190874345'i32, "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc"),
  ("e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000", "5300ac6a53ab6a", 1, -886562767'i32, "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798"),
  ("50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000", "6aac", 0, 946795545'i32, "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d"),
  # SIGHASH_SINGLE test case
  ("d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000", "535251536aac536a", 0, -1960128125'i32, "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a"),
  # SIGHASH_ANYONECANPAY tests
  ("c363a70c01ab174230bbe4afe0c3efa2d7f2feaf179431359adedccf30d1f69efe0c86ed390200000002ab51558648fe0231318b04000000000151662170000000000008ac5300006a63acac00000000", "", 0, 2146479410'i32, "191ab180b0d753763671717d051f138d4866b7cb0d1d4811472e64de595d2c70"),
  # More test vectors
  ("04bac8c5033460235919a9c63c42b2db884c7c8f2ed8fcd69ff683a0a2cccd9796346a04050200000003655351fcad3a2c5a7cbadeb4ec7acc9836c3f5c3e776e5c566220f7f965cf194f8ef98efb5e3530200000007526a006552526526a2f55ba5f69699ece76692552b399ba908301907c5763d28a15b08581b23179cb01eac03000000075363ab6a516351073942c2025aa98a05000000000765006aabac65abd7ffa6030000000004516a655200000000", "53ac6365ac526a", 1, 764174870'i32, "bf5fdc314ded2372a0ad078568d76c5064bf2affbde0764c335009e56634481b"),
  ("a93e93440250f97012d466a6cc24839f572def241c814fe6ae94442cf58ea33eb0fdd9bcc1030000000600636a0065acffffffff5dee3a6e7e5ad6310dea3e5b3ddda1a56bf8de7d3b75889fc024b5e233ec10f80300000007ac53635253ab53ffffffff0160468b04000000000800526a5300ac526a00000000", "ac00636a53", 1, 1773442520'i32, "5c9d3a2ce9365bb72cfabbaa4579c843bb8abf200944612cf8ae4b56a908bcbd"),
]

suite "legacy sighash - Bitcoin Core test vectors":
  for i, vec in testVectors:
    test "vector " & $i:
      let (rawTxHex, scriptHex, inputIndex, hashType, expectedHashHex) = vec

      # Parse transaction
      let txBytes = hexToBytes(rawTxHex)
      let tx = deserializeTransaction(txBytes)

      # Parse script
      let scriptCode = hexToBytes(scriptHex)

      # Compute sighash (no signature to FindAndDelete in these tests)
      let hash = computeLegacySighash(tx, inputIndex, scriptCode, cast[uint32](hashType))

      # Convert to hex for comparison (reversed because Bitcoin displays hashes in big-endian)
      var hashReversed: array[32, byte]
      for j in 0 ..< 32:
        hashReversed[j] = hash[31 - j]
      let computedHashHex = bytesToHex(hashReversed)

      check computedHashHex == expectedHashHex

suite "sighash - findAndDelete":
  test "empty signature returns original script":
    let script = @[0x51'u8, 0x52, 0x53]  # OP_1 OP_2 OP_3
    let emptySig: seq[byte] = @[]
    let deleteResult = findAndDelete(script, emptySig)
    check deleteResult == script

  test "removes single occurrence of short signature":
    # Script: OP_1 <push 3 bytes: AA BB CC> OP_2
    let script = @[0x51'u8, 0x03, 0xAA, 0xBB, 0xCC, 0x52]
    # Remove the signature AA BB CC
    let sig = @[0xAA'u8, 0xBB, 0xCC]
    let result = findAndDelete(script, sig)
    # Should remove the push-encoded signature: 03 AA BB CC
    check result == @[0x51'u8, 0x52]

  test "removes multiple occurrences":
    # Script: <push 2: AB CD> OP_1 <push 2: AB CD>
    let script = @[0x02'u8, 0xAB, 0xCD, 0x51, 0x02, 0xAB, 0xCD]
    let sig = @[0xAB'u8, 0xCD]
    let result = findAndDelete(script, sig)
    check result == @[0x51'u8]

  test "does not remove non-matching data":
    let script = @[0x51'u8, 0x03, 0xAA, 0xBB, 0xCC, 0x52]
    let sig = @[0xDD'u8, 0xEE, 0xFF]
    let result = findAndDelete(script, sig)
    check result == script

  test "handles PUSHDATA1 encoded signature":
    # Script with PUSHDATA1
    var script: seq[byte] = @[0x4c'u8, 0x50]  # PUSHDATA1, 80 bytes
    for i in 0 ..< 80:
      script.add(byte(i))
    script.add(0x51)  # OP_1

    # The signature is the 80 bytes
    var sig: seq[byte] = @[]
    for i in 0 ..< 80:
      sig.add(byte(i))

    let result = findAndDelete(script, sig)
    check result == @[0x51'u8]

suite "sighash - removeCodeSeparators":
  test "removes single OP_CODESEPARATOR":
    let script = @[0x51'u8, 0xab, 0x52]  # OP_1 OP_CODESEPARATOR OP_2
    let removeResult = removeCodeSeparators(script)
    check removeResult == @[0x51'u8, 0x52]

  test "removes multiple OP_CODESEPARATOR":
    let script = @[0xab'u8, 0x51, 0xab, 0x52, 0xab]
    let removeResult = removeCodeSeparators(script)
    check removeResult == @[0x51'u8, 0x52]

  test "preserves 0xab inside push data":
    # Script: <push 3 bytes: AB AB AB> (the bytes happen to be 0xAB but shouldn't be treated as opcodes)
    let script = @[0x03'u8, 0xab, 0xab, 0xab]
    let removeResult = removeCodeSeparators(script)
    check removeResult == script

  test "handles empty script":
    let emptyScript: seq[byte] = @[]
    let removeResult = removeCodeSeparators(emptyScript)
    check removeResult.len == 0

suite "sighash - getSubscriptAfterCodeSeparator":
  test "no codeseparator returns full script":
    let script = @[0x51'u8, 0x52, 0x53]
    let subResult = getSubscriptAfterCodeSeparator(script, 0xFFFFFFFF'u32)
    check subResult == script

  test "returns subscript after position":
    let script = @[0x51'u8, 0xab, 0x52, 0x53]  # OP_1 OP_CODESEP OP_2 OP_3
    # codesepPos is position AFTER the OP_CODESEPARATOR, i.e., position 2
    let subResult = getSubscriptAfterCodeSeparator(script, 2)
    check subResult == @[0x52'u8, 0x53]

  test "handles codesep at end":
    let script = @[0x51'u8, 0x52, 0xab]
    let subResult = getSubscriptAfterCodeSeparator(script, 3)
    check subResult.len == 0

suite "sighash - SIGHASH_SINGLE out of range":
  test "returns uint256(1) when input index >= output count":
    var tx = Transaction()
    tx.version = 1
    tx.lockTime = 0

    # Add 2 inputs
    tx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))
    tx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 1),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))

    # Add only 1 output
    tx.outputs.add(TxOut(value: Satoshi(100000), scriptPubKey: @[0x51'u8]))

    # SIGHASH_SINGLE for input 1, but only 1 output exists
    let hash = computeLegacySighash(tx, 1, @[], SIGHASH_SINGLE)

    # Should return uint256(1) = 0x01 followed by 31 zeros (little endian)
    var expectedHash: array[32, byte]
    expectedHash[0] = 1
    check hash == expectedHash

suite "sighash - complete signatureHash function":
  test "applies FindAndDelete to signature":
    var tx = Transaction()
    tx.version = 1
    tx.lockTime = 0
    tx.inputs.add(TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))
    tx.outputs.add(TxOut(value: Satoshi(100000), scriptPubKey: @[0x51'u8]))

    # scriptCode containing the signature we're checking
    let sig = @[0x30'u8, 0x44, 0x01]  # Fake DER signature start
    let scriptCode = @[0x51'u8, 0x03, 0x30, 0x44, 0x01, 0x52]  # Contains the sig

    let hashWithSig = signatureHash(tx, 0, scriptCode, sig, SIGHASH_ALL)

    # Without the signature in scriptCode
    let scriptCodeWithoutSig = @[0x51'u8, 0x52]
    let hashWithoutSig = computeLegacySighash(tx, 0, scriptCodeWithoutSig, SIGHASH_ALL)

    # They should match because signatureHash removes the sig
    check hashWithSig == hashWithoutSig
