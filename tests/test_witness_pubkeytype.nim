## Tests for SCRIPT_VERIFY_WITNESS_PUBKEYTYPE (BIP141)
##
## Witness v0 programs (P2WPKH, P2WSH) require compressed public keys.
## Uncompressed pubkeys (65 bytes, 0x04 prefix) must be rejected.
## Compressed pubkeys (33 bytes, 0x02 or 0x03 prefix) must be accepted.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/crypto/hashing
import ../src/consensus/validation
import ../src/consensus/params

suite "witness pubkeytype - compressed pubkey check":
  test "isCompressedPubkey accepts 0x02 prefix":
    var pubkey: seq[byte] = @[0x02'u8]
    for i in 0 ..< 32:
      pubkey.add(byte(i))
    check isCompressedPubkey(pubkey) == true

  test "isCompressedPubkey accepts 0x03 prefix":
    var pubkey: seq[byte] = @[0x03'u8]
    for i in 0 ..< 32:
      pubkey.add(byte(i))
    check isCompressedPubkey(pubkey) == true

  test "isCompressedPubkey rejects uncompressed 0x04 prefix":
    var pubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      pubkey.add(byte(i))
    check isCompressedPubkey(pubkey) == false

  test "isCompressedPubkey rejects wrong length":
    # Too short
    var short: seq[byte] = @[0x02'u8, 0x01, 0x02]
    check isCompressedPubkey(short) == false

    # Too long
    var long: seq[byte] = @[0x02'u8]
    for i in 0 ..< 34:
      long.add(byte(i))
    check isCompressedPubkey(long) == false

  test "isCompressedPubkey rejects invalid prefix":
    var pubkey: seq[byte] = @[0x05'u8]
    for i in 0 ..< 32:
      pubkey.add(byte(i))
    check isCompressedPubkey(pubkey) == false

  test "isCompressedPubkey rejects empty":
    check isCompressedPubkey(@[]) == false

suite "witness pubkeytype - P2WPKH with flag":
  test "P2WPKH with compressed pubkey passes":
    # Create compressed pubkey (33 bytes, 0x02 prefix)
    var compressedPubkey: seq[byte] = @[0x02'u8]
    for i in 0 ..< 32:
      compressedPubkey.add(byte(i))

    # Create P2WPKH witness program (hash160 of pubkey)
    let pubkeyHash = hash160(compressedPubkey)

    # Create P2WPKH scriptPubKey: OP_0 <20 bytes>
    var scriptPubKey: seq[byte] = @[OP_0, 0x14'u8]
    scriptPubKey.add(pubkeyHash)

    check isP2WPKH(scriptPubKey) == true

    # The pubkey is compressed, so it should pass the check
    check isCompressedPubkey(compressedPubkey) == true

  test "P2WPKH with uncompressed pubkey fails with sfWitnessPubkeyType":
    # Create uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressedPubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      uncompressedPubkey.add(byte(i))

    # The check should fail
    check isCompressedPubkey(uncompressedPubkey) == false

suite "witness pubkeytype - P2WSH CHECKSIG with flag":
  test "P2WSH CHECKSIG with uncompressed pubkey fails":
    # Test that CHECKSIG in witness v0 context with uncompressed pubkey
    # returns seWitnessPubkeyType error when flag is set
    var interp = newInterpreter({sfWitness, sfWitnessPubkeyType})

    # Create uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressedPubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      uncompressedPubkey.add(byte(i))

    # Push signature (empty for this test - we're testing pubkey validation)
    interp.push(@[0x30'u8, 0x01, 0x02, 0x01])  # dummy signature with sighash byte
    # Push uncompressed pubkey
    interp.push(uncompressedPubkey)

    let script = @[OP_CHECKSIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,  # Witness v0 context
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seWitnessPubkeyType

  test "P2WSH CHECKSIG with compressed pubkey passes validation":
    # Test that CHECKSIG in witness v0 context with compressed pubkey
    # does not return seWitnessPubkeyType error
    var interp = newInterpreter({sfWitness, sfWitnessPubkeyType, sfNullFail})

    # Create compressed pubkey (33 bytes, 0x02 prefix)
    var compressedPubkey: seq[byte] = @[0x02'u8]
    for i in 0 ..< 32:
      compressedPubkey.add(byte(i))

    # Push empty signature (to skip actual sig verification and test pubkey check only)
    interp.push(@[])  # empty signature
    # Push compressed pubkey
    interp.push(compressedPubkey)

    let script = @[OP_CHECKSIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    # Should NOT be seWitnessPubkeyType - compressed pubkey should pass
    check err != seWitnessPubkeyType
    # With empty sig and empty pubkey check, it should succeed (push false)
    check err == seOk

  test "P2WSH CHECKSIG without flag allows uncompressed pubkey":
    # Without sfWitnessPubkeyType flag, uncompressed pubkeys should be allowed
    var interp = newInterpreter({sfWitness})  # Note: no sfWitnessPubkeyType

    # Create uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressedPubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      uncompressedPubkey.add(byte(i))

    # Push empty signature
    interp.push(@[])
    # Push uncompressed pubkey
    interp.push(uncompressedPubkey)

    let script = @[OP_CHECKSIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    # Without the flag, should NOT fail with seWitnessPubkeyType
    check err != seWitnessPubkeyType

  test "legacy CHECKSIG allows uncompressed pubkey even with flag":
    # In legacy (sigBase) context, uncompressed pubkeys should always be allowed
    var interp = newInterpreter({sfWitnessPubkeyType})

    # Create uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressedPubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      uncompressedPubkey.add(byte(i))

    # Push empty signature
    interp.push(@[])
    # Push uncompressed pubkey
    interp.push(uncompressedPubkey)

    let script = @[OP_CHECKSIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,  # Legacy context
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    # Legacy context should NOT enforce witness pubkey type
    check err != seWitnessPubkeyType

suite "witness pubkeytype - P2WSH CHECKMULTISIG with flag":
  test "P2WSH CHECKMULTISIG with uncompressed pubkey fails":
    # Test that CHECKMULTISIG in witness v0 context with uncompressed pubkey
    # returns seWitnessPubkeyType error when flag is set
    var interp = newInterpreter({sfWitness, sfWitnessPubkeyType, sfNullDummy})

    # Create uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressedPubkey: seq[byte] = @[0x04'u8]
    for i in 0 ..< 64:
      uncompressedPubkey.add(byte(i))

    # Stack for 1-of-1 multisig: dummy, sig, nSigs, pubkey, nPubkeys
    interp.push(@[])  # dummy element (BIP147)
    interp.push(@[0x30'u8, 0x01, 0x02, 0x01])  # dummy signature with sighash byte
    interp.push(@[0x01'u8])  # nSigs = 1
    interp.push(uncompressedPubkey)  # uncompressed pubkey
    interp.push(@[0x01'u8])  # nPubkeys = 1

    let script = @[OP_CHECKMULTISIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seWitnessPubkeyType

  test "P2WSH CHECKMULTISIG with compressed pubkey passes validation":
    # Test that CHECKMULTISIG in witness v0 context with compressed pubkey
    # does not return seWitnessPubkeyType error
    var interp = newInterpreter({sfWitness, sfWitnessPubkeyType, sfNullDummy, sfNullFail})

    # Create compressed pubkey (33 bytes, 0x02 prefix)
    var compressedPubkey: seq[byte] = @[0x02'u8]
    for i in 0 ..< 32:
      compressedPubkey.add(byte(i))

    # Stack for 1-of-1 multisig with empty sig
    interp.push(@[])  # dummy element
    interp.push(@[])  # empty signature
    interp.push(@[0x01'u8])  # nSigs = 1
    interp.push(compressedPubkey)
    interp.push(@[0x01'u8])  # nPubkeys = 1

    let script = @[OP_CHECKMULTISIG]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    # Should NOT be seWitnessPubkeyType
    check err != seWitnessPubkeyType

suite "witness pubkeytype - block validation flags":
  test "getBlockScriptFlags includes sfWitnessPubkeyType at segwit height":
    # This test verifies that the validation module correctly enables
    # the sfWitnessPubkeyType flag at segwit activation height
    let mainnet = mainnetParams()

    # Before segwit
    let preSegwitFlags = getBlockScriptFlags(int32(mainnet.segwitHeight) - 1, mainnet)
    check sfWitnessPubkeyType notin preSegwitFlags

    # At segwit activation
    let segwitFlags = getBlockScriptFlags(int32(mainnet.segwitHeight), mainnet)
    check sfWitnessPubkeyType in segwitFlags
    check sfWitness in segwitFlags

  test "getBlockScriptFlags on regtest includes sfWitnessPubkeyType":
    let regtest = regtestParams()

    # On regtest, segwit is active from genesis (height 0)
    let flags = getBlockScriptFlags(0, regtest)
    check sfWitnessPubkeyType in flags
    check sfWitness in flags
