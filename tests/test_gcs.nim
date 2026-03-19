## Tests for GCS (Golomb-Coded Set) filters (BIP 158)

import std/[unittest, sequtils, random]
import ../src/storage/indexes/gcs
import ../src/crypto/siphash
import ../src/primitives/types

suite "SipHash":
  test "basic siphash computation":
    # Test vector from SipHash reference
    let k0 = 0x0706050403020100'u64
    let k1 = 0x0f0e0d0c0b0a0908'u64
    let data = @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

    let hash = sipHash(k0, k1, data)
    # Result should be deterministic
    check hash != 0

  test "siphash with empty data":
    let hash = sipHash(0, 0, @[])
    check hash != 0  # Empty input still produces hash

  test "siphash different keys produce different hashes":
    let data = @[1'u8, 2, 3, 4]
    let h1 = sipHash(0, 0, data)
    let h2 = sipHash(1, 0, data)
    let h3 = sipHash(0, 1, data)
    check h1 != h2
    check h1 != h3
    check h2 != h3

  test "fastRange64 maps to range":
    # Test that fastRange64 maps uniformly to [0, n)
    let n = 1000'u64
    for i in 0 ..< 100:
      let hash = uint64(i * 12345)
      let mapped = fastRange64(hash, n)
      check mapped < n

suite "GCS BitWriter and BitReader":
  test "write and read single bits":
    var w = newBitWriter()
    w.writeBits(1, 1)
    w.writeBits(0, 1)
    w.writeBits(1, 1)
    w.writeBits(1, 1)

    var r = newBitReader(w.getData())
    check r.readBit() == 1
    check r.readBit() == 0
    check r.readBit() == 1
    check r.readBit() == 1

  test "write and read multiple bits":
    var w = newBitWriter()
    w.writeBits(0b10110, 5)
    w.writeBits(0b111, 3)

    var r = newBitReader(w.getData())
    check r.readBits(5) == 0b10110
    check r.readBits(3) == 0b111

  test "write and read across byte boundaries":
    var w = newBitWriter()
    w.writeBits(0xff, 8)   # Full byte
    w.writeBits(0x123, 12) # 12 bits crossing boundary

    var r = newBitReader(w.getData())
    check r.readBits(8) == 0xff
    check r.readBits(12) == 0x123

suite "Golomb-Rice coding":
  test "encode and decode small values":
    var w = newBitWriter()
    golombRiceEncode(w, BasicFilterP, 0)
    golombRiceEncode(w, BasicFilterP, 1)
    golombRiceEncode(w, BasicFilterP, 100)

    var r = newBitReader(w.getData())
    check golombRiceDecode(r, BasicFilterP) == 0
    check golombRiceDecode(r, BasicFilterP) == 1
    check golombRiceDecode(r, BasicFilterP) == 100

  test "encode and decode larger values":
    var w = newBitWriter()
    let values = @[1000'u64, 50000, 1000000, 10000000]
    for v in values:
      golombRiceEncode(w, BasicFilterP, v)

    var r = newBitReader(w.getData())
    for v in values:
      check golombRiceDecode(r, BasicFilterP) == v

  test "round-trip random values":
    randomize(42)
    var w = newBitWriter()
    var expected: seq[uint64]

    # Use reasonable values - with P=19, quotient should be small for efficiency
    # Values up to 2^25 are reasonable (quotient < 64)
    for _ in 0 ..< 50:
      let v = uint64(rand(1 shl 25))
      expected.add(v)
      golombRiceEncode(w, BasicFilterP, v)

    var r = newBitReader(w.getData())
    for v in expected:
      check golombRiceDecode(r, BasicFilterP) == v

suite "GCS Filter":
  test "empty filter":
    let params = GCSParams(sipHashK0: 0, sipHashK1: 0, p: BasicFilterP, m: BasicFilterM)
    let filter = newGCSFilter(params, newSeq[seq[byte]]())
    check filter.n == 0
    check filter.match(@[1'u8, 2, 3]) == false

  test "single element filter":
    let params = GCSParams(sipHashK0: 123, sipHashK1: 456, p: BasicFilterP, m: BasicFilterM)
    let elem = @[1'u8, 2, 3, 4, 5]
    let filter = newGCSFilter(params, @[elem])

    check filter.n == 1
    check filter.match(elem) == true
    check filter.match(@[9'u8, 8, 7]) == false  # Not in filter

  test "multiple elements filter":
    let params = GCSParams(sipHashK0: 0xdead, sipHashK1: 0xbeef, p: BasicFilterP, m: BasicFilterM)
    var elements: seq[seq[byte]]
    for i in 0 ..< 10:
      elements.add(@[byte(i), byte(i + 1), byte(i + 2)])

    let filter = newGCSFilter(params, elements)
    check filter.n == 10

    # All elements should match
    for elem in elements:
      check filter.match(elem) == true

  test "matchAny finds matches":
    let params = GCSParams(sipHashK0: 0x1234, sipHashK1: 0x5678, p: BasicFilterP, m: BasicFilterM)
    let elements = @[@[1'u8, 2, 3], @[4'u8, 5, 6], @[7'u8, 8, 9]]
    let filter = newGCSFilter(params, elements)

    # Query with one matching element
    check filter.matchAny(@[@[1'u8, 2, 3]]) == true
    check filter.matchAny(@[@[4'u8, 5, 6]]) == true

    # Query with multiple elements, one matching
    check filter.matchAny(@[@[99'u8], @[7'u8, 8, 9], @[88'u8]]) == true

    # Query with no matching elements (may have false positives, but unlikely)
    # This test is probabilistic - the vast majority should return false
    var falsePositives = 0
    for i in 100 ..< 200:
      if filter.matchAny(@[@[byte(i), byte(i + 50), byte(i + 100)]]):
        falsePositives += 1
    # With P=19, M=784931, FP rate is about 1/784931 per element
    check falsePositives < 10  # Should be very rare

  test "filter reconstruction from encoded data":
    let params = GCSParams(sipHashK0: 0xabcd, sipHashK1: 0xef01, p: BasicFilterP, m: BasicFilterM)
    let elements = @[@[10'u8, 20, 30], @[40'u8, 50, 60], @[70'u8, 80, 90]]
    let original = newGCSFilter(params, elements)

    # Reconstruct from encoded data
    let reconstructed = newGCSFilter(params, original.encoded)
    check reconstructed.n == original.n
    check reconstructed.f == original.f

    # Both should match the same elements
    for elem in elements:
      check reconstructed.match(elem) == true

suite "Block Filter (BIP 158)":
  test "basic filter params from block hash":
    var hashBytes: array[32, byte]
    for i in 0 ..< 32:
      hashBytes[i] = byte(i)
    let blockHash = BlockHash(hashBytes)

    let params = basicFilterParams(blockHash)
    check params.p == BasicFilterP
    check params.m == BasicFilterM
    # Keys should be derived from block hash
    check params.sipHashK0 != 0 or params.sipHashK1 != 0

  test "create block filter from elements":
    var hashBytes: array[32, byte]
    hashBytes[0] = 0xaa
    hashBytes[1] = 0xbb
    let blockHash = BlockHash(hashBytes)

    let scripts = @[@[0x76'u8, 0xa9], @[0x00'u8, 0x14], @[0xa9'u8, 0x14]]
    let filter = newBlockFilter(bftBasic, blockHash, scripts)

    check filter.filterType == bftBasic
    check filter.blockHash == blockHash
    check getN(filter) == 3

  test "filter hash and header computation":
    var hashBytes: array[32, byte]
    for i in 0 ..< 32:
      hashBytes[i] = byte(255 - i)
    let blockHash = BlockHash(hashBytes)

    let scripts = @[@[1'u8, 2, 3, 4, 5]]
    let filter = newBlockFilter(bftBasic, blockHash, scripts)

    let filterHash = getFilterHash(filter)
    check filterHash != default(array[32, byte])

    var prevHeader: array[32, byte]
    let header = computeFilterHeader(filter, prevHeader)
    check header != default(array[32, byte])
    check header != filterHash  # Header includes prev header

  test "isOpReturn detection":
    check isOpReturn(@[0x6a'u8, 0x00]) == true    # OP_RETURN
    check isOpReturn(@[0x6a'u8]) == true           # Just OP_RETURN
    check isOpReturn(@[0x76'u8, 0xa9]) == false   # P2PKH
    check isOpReturn(@[]) == false                 # Empty
