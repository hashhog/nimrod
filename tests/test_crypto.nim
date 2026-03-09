## Tests for cryptographic functions

import unittest2
import std/strutils
import ../src/crypto/hashing
import ../src/crypto/secp256k1

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc hexToArray32(hex: string): array[32, byte] =
  let bytes = hexToBytes(hex)
  for i in 0 ..< min(32, bytes.len):
    result[i] = bytes[i]

proc hexToArray64(hex: string): array[64, byte] =
  let bytes = hexToBytes(hex)
  for i in 0 ..< min(64, bytes.len):
    result[i] = bytes[i]

proc bytesToHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

proc strToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

suite "hashing":
  test "sha256 empty string":
    let hash = sha256(@[])
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    check bytesToHex(hash) == expected

  test "sha256 hello":
    let data = strToBytes("hello")
    let hash = sha256(data)
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    check bytesToHex(hash) == expected

  test "double sha256":
    let data = strToBytes("hello")
    let hash = doubleSha256(data)
    # SHA256(SHA256("hello"))
    let expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
    check bytesToHex(hash) == expected

  test "hash160":
    let data = strToBytes("hello")
    let hash = hash160(data)
    check hash.len == 20

  test "merkle root single":
    let hashes = @[sha256(strToBytes("tx1"))]
    let root = merkleRoot(hashes)
    check root == hashes[0]

  test "merkle root two":
    let tx1 = sha256(strToBytes("tx1"))
    let tx2 = sha256(strToBytes("tx2"))
    let root = merkleRoot(@[tx1, tx2])

    # Manual calculation
    var combined: array[64, byte]
    copyMem(addr combined[0], addr tx1[0], 32)
    copyMem(addr combined[32], addr tx2[0], 32)
    let expected = doubleSha256(combined)

    check root == expected

  test "merkle root odd count":
    let tx1 = sha256(strToBytes("tx1"))
    let tx2 = sha256(strToBytes("tx2"))
    let tx3 = sha256(strToBytes("tx3"))
    let root = merkleRoot(@[tx1, tx2, tx3])

    # With odd count, last hash is duplicated
    check root.len == 32

  test "sha256d empty string":
    # SHA-256d of empty input
    let hash = sha256d(@[])
    let expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    check bytesToHex(hash) == expected

  test "sha256d alias":
    # Verify doubleSha256 and sha256d are the same
    let data = strToBytes("hello")
    check sha256d(data) == doubleSha256(data)

  test "sha256Single":
    let data = strToBytes("hello")
    let hash = sha256Single(data)
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    check bytesToHex(hash) == expected

  test "hash160 of generator pubkey":
    # Uncompressed generator point G pubkey (33 bytes compressed)
    # This is the standard test vector: HASH160 of compressed generator pubkey
    let compressedG = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    let hash = hash160(compressedG)
    let expected = "751e76e8199196d454941c45d1b3a323f1433bd6"
    check bytesToHex(hash) == expected

when defined(useSystemSecp256k1):
  suite "secp256k1 ecdsa":
    setup:
      initSecp256k1()

    test "sign and verify roundtrip":
      let privateKey: PrivateKey = [
        0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
      ]

      let pubkey = derivePublicKey(privateKey)
      check pubkey.len == 33

      let msgHash = sha256d(strToBytes("test message"))
      let sig = sign(privateKey, msgHash)

      check verify(pubkey, msgHash, sig)

    test "verify fails with wrong message":
      let privateKey: PrivateKey = [
        0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
      ]

      let pubkey = derivePublicKey(privateKey)
      let msgHash = sha256d(strToBytes("test message"))
      let wrongHash = sha256d(strToBytes("wrong message"))
      let sig = sign(privateKey, msgHash)

      check not verify(pubkey, wrongHash, sig)

  suite "crypto engine":
    test "CryptoEngine lifecycle":
      var engine = newCryptoEngine()
      engine.close()

    test "CryptoEngine ecdsa verify":
      var engine = newCryptoEngine()
      defer: engine.close()

      let privateKey: PrivateKey = [
        0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
      ]

      initSecp256k1()
      let pubkey = derivePublicKey(privateKey)
      let msgHash = sha256d(strToBytes("test"))
      let sig = sign(privateKey, msgHash)

      check engine.verifyEcdsa(@sig, @pubkey, msgHash)
