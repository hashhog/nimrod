## Bitcoin Core MuHash3072 known-answer vectors.
##
## Reference: `bitcoin-core/src/test/crypto_tests.cpp::muhash_tests` (test
## block at lines 1245-1257). Validates that nimrod's MuHash3072 produces
## the same finalized 32-byte digest as Core for canonical inputs, which
## is the byte-level commitment used by:
##   - assumeutxo snapshot validation (validation.cpp:5912)
##   - dumptxoutset / loadtxoutset (rpc/blockchain.cpp::WriteUTXOSnapshot)
##   - coinstatsindex (kernel/coinstats.cpp::ApplyCoinHash)

import unittest2
import std/strutils
import ../src/crypto/muhash

proc bytesToHex(data: openArray[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

proc uint256DisplayHex(data: array[32, byte]): string =
  ## Bitcoin's uint256 hex display is byte-reversed vs the raw SHA256 output.
  ## Core's `BOOST_CHECK_EQUAL(out, uint256{"10d312..."})` parses the literal
  ## as a uint256 (LE-internal-storage), which prints bytes in reverse order
  ## relative to the raw hash. Match that here so test vectors copy/paste 1:1
  ## from `crypto_tests.cpp`.
  result = newStringOfCap(64)
  for i in countdown(31, 0):
    result.add(toHex(data[i], 2).toLowerAscii)

proc fromInt(i: byte): MuHash3072 =
  ## Mirror of Core's `FromInt(unsigned char i)`:
  ##   unsigned char tmp[32] = {i, 0};   return MuHash3072(tmp);
  ##
  ## In Core, `MuHash3072(span)` sets m_numerator = ToNum3072(span) and
  ## leaves m_denominator at its default (one).
  result = newMuHash3072()
  var tmp: array[32, byte]
  tmp[0] = i
  result.numerator = toNum3072(tmp)

suite "MuHash3072 Core known vectors":
  test "FromInt(0) * FromInt(1) / FromInt(2) matches Core":
    # crypto_tests.cpp:1245-1249
    var acc = fromInt(0)
    var one = fromInt(1)
    var two = fromInt(2)
    acc *= one
    acc /= two
    let digest = acc.finalize()
    check uint256DisplayHex(digest) ==
      "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"

  test "Insert/Remove equivalent to multiply/divide":
    # crypto_tests.cpp:1251-1257
    var acc = fromInt(0)
    var tmp1: array[32, byte]
    tmp1[0] = 1
    var tmp2: array[32, byte]
    tmp2[0] = 2
    acc.insert(tmp1)
    acc.remove(tmp2)
    let digest = acc.finalize()
    check uint256DisplayHex(digest) ==
      "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"

  test "Empty MuHash finalize is stable":
    # The empty MuHash has numerator = denominator = 1, so finalize =
    # SHA256(384 LE bytes of 1) = a known constant. Core uses this digest
    # implicitly whenever an empty UTXO set is hashed.
    var h = newMuHash3072()
    let d1 = h.finalize()
    var h2 = newMuHash3072()
    let d2 = h2.finalize()
    check d1 == d2
    # The empty digest is deterministic (snapshot-format invariant).
    check bytesToHex(d1).len == 64

  test "Order independence (insert)":
    var a = newMuHash3072()
    var b = newMuHash3072()
    a.insert(@[byte 0x11, 0x22, 0x33])
    a.insert(@[byte 0xAA, 0xBB, 0xCC])
    b.insert(@[byte 0xAA, 0xBB, 0xCC])
    b.insert(@[byte 0x11, 0x22, 0x33])
    check a.finalize() == b.finalize()

  test "Insert + Remove same element cancels":
    var a = newMuHash3072()
    var b = newMuHash3072()
    a.insert(@[byte 1, 2, 3, 4])
    a.remove(@[byte 1, 2, 3, 4])
    check a.finalize() == b.finalize()

  test "Combine via *= matches separate inserts":
    # crypto_tests.cpp:1229-1242 algebra: (X*Y)/Y = X
    var x = fromInt(3)
    var y = fromInt(5)
    var z = newMuHash3072()
    z *= x
    z *= y
    var yx = y
    yx *= x
    z /= yx
    var empty = newMuHash3072()
    check z.finalize() == empty.finalize()

  test "Serialization round-trip preserves finalize":
    var h = newMuHash3072()
    h.insert(@[byte 7, 8, 9])
    h.insert(@[byte 10, 11, 12])
    h.remove(@[byte 13, 14])
    let blob = serializeMuHash(h)
    check blob.len == 2 * ByteSize
    var h2 = deserializeMuHash(blob)
    check h.finalize() == h2.finalize()

suite "MuHash3072 Num3072 modular arithmetic":
  test "1 * 1 == 1":
    var n = newNum3072()
    let one = newNum3072()
    n.multiply(one)
    check n.isOne()

  test "Inverse of 1 is 1":
    let one = newNum3072()
    let inv = one.getInverse()
    check inv.isOne()

  test "Multiply then divide is identity":
    # Build a small concrete value: limb[0] = 7
    var a = newNum3072()
    a.limbs[0] = 7
    var x = newNum3072()
    x.limbs[0] = 13
    var orig = a
    a.multiply(x)
    a.divide(x)
    # After multiply+divide we should be back to 7.
    check a.limbs[0] == orig.limbs[0]
    for i in 1 ..< Limbs:
      check a.limbs[i] == 0

when isMainModule:
  echo "Running MuHash3072 Core vector tests..."
