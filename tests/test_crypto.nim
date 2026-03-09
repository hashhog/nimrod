## Tests for cryptographic functions

import unittest2
import std/strutils
import ../src/crypto/hashing

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc bytesToHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

suite "hashing":
  test "sha256 empty string":
    let hash = sha256(@[])
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    check bytesToHex(hash) == expected

  test "sha256 hello":
    let data = "hello".toOpenArrayByte(0, 4)
    let hash = sha256(data)
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    check bytesToHex(hash) == expected

  test "double sha256":
    let data = "hello".toOpenArrayByte(0, 4)
    let hash = doubleSha256(data)
    # SHA256(SHA256("hello"))
    let expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
    check bytesToHex(hash) == expected

  test "hash160":
    let data = "hello".toOpenArrayByte(0, 4)
    let hash = hash160(data)
    check hash.len == 20

  test "merkle root single":
    let hashes = @[sha256("tx1".toOpenArrayByte(0, 2))]
    let root = merkleRoot(hashes)
    check root == hashes[0]

  test "merkle root two":
    let tx1 = sha256("tx1".toOpenArrayByte(0, 2))
    let tx2 = sha256("tx2".toOpenArrayByte(0, 2))
    let root = merkleRoot(@[tx1, tx2])

    # Manual calculation
    var combined: array[64, byte]
    copyMem(addr combined[0], addr tx1[0], 32)
    copyMem(addr combined[32], addr tx2[0], 32)
    let expected = doubleSha256(combined)

    check root == expected

  test "merkle root odd count":
    let tx1 = sha256("tx1".toOpenArrayByte(0, 2))
    let tx2 = sha256("tx2".toOpenArrayByte(0, 2))
    let tx3 = sha256("tx3".toOpenArrayByte(0, 2))
    let root = merkleRoot(@[tx1, tx2, tx3])

    # With odd count, last hash is duplicated
    check root.len == 32
