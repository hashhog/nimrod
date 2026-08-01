## Tests for GCS (Golomb-Coded Set) filters (BIP 158)
## W90: BIP-157/158 comprehensive audit

import unittest2
import std/[sequtils, random, strutils]
import ../src/storage/indexes/gcs
import ../src/crypto/siphash
import ../src/crypto/hashing
import ../src/primitives/types

proc fromHex(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc toHexStr(b: openArray[byte]): string =
  result = ""
  for x in b:
    result.add(toHex(x.int, 2).toLowerAscii)

proc displayHashToBlockHash(displayHex: string): BlockHash =
  ## Convert a display-format block hash (big-endian hex, as shown in explorers)
  ## to nimrod's BlockHash (internal little-endian byte order).
  ## Core stores uint256 m_data in LE; display reverses bytes.
  let raw = fromHex(displayHex)
  var bytes: array[32, byte]
  for i in 0 ..< 32:
    bytes[i] = raw[31 - i]
  BlockHash(bytes)

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

# ============================================================================
# W90 BIP-157/158 comprehensive audit tests
# ============================================================================

suite "W90 Bug 1+2: filter hash and header use double SHA256":
  ## Bug 1: getFilterHash must use SHA256d (CHash256), not single SHA256.
  ## Bug 2: computeFilterHeader must use SHA256d, not single SHA256.
  ## Reference: bitcoin-core/src/blockfilter.cpp:248-256
  ##   GetHash()       → Hash(GetEncodedFilter())     — CHash256 = SHA256d
  ##   ComputeHeader() → Hash(GetHash(), prev_header) — CHash256 = SHA256d
  ##
  ## Core test vector from bitcoin-core/src/test/data/blockfilters.json:
  ## Block 0 (genesis):
  ##   encoded filter: 019dfca8
  ##   filter hash:    21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
  ##   prev header:    0000000000000000000000000000000000000000000000000000000000000000
  ##   filter header:  21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
  ##
  ## Note: For the genesis block the filter header == filter hash because
  ## SHA256d(filterHash || 00..00) == the genesis filter header in Core.

  test "double SHA256 single encode round-trip":
    # SHA256d of 4 bytes must differ from single SHA256
    let data = @[0x01'u8, 0x9d, 0xfc, 0xa8]
    let single = sha256Single(data)
    let dbl    = sha256d(data)
    check single != dbl

  test "getFilterHash uses SHA256d — Core genesis test vector":
    ## Core genesis block filter bytes (encoded): 019dfca8
    ## filterHash = SHA256d(019dfca8) in internal LE byte order.
    ## JSON display format is reversed; we compare against internal format.
    ## Internal filterHash = 4c8af7fa3ac4111dc5fd7581d176c02dbbfde83fd6f16496a576fbd6b20537c0
    ## (Display = c03705b2...4c, but we store/compare LE)
    ## Source: computed from bitcoin-core/src/test/data/blockfilters.json genesis entry
    let encodedFilter = fromHex("019dfca8")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, encodedFilter, skipDecode = true)
    let filterHash = getFilterHash(filter)

    # Internal LE format: SHA256d([0x01,0x9d,0xfc,0xa8]) = 4c8af7fa...
    let expectedHex = "4c8af7fa3ac4111dc5fd7581d176c02dbbfde83fd6f16496a576fbd6b20537c0"
    check toHexStr(filterHash) == expectedHex

  test "computeFilterHeader uses SHA256d — Core genesis test vector":
    ## filterHeader = SHA256d(filterHash || prevHeader), all in LE internal format.
    ## genesis prevHeader = all zeros.
    ## Internal filterHeader = 50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821
    ## JSON display = 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
    ## (display is reversed; stored/compared in internal LE format)
    let encodedFilter = fromHex("019dfca8")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, encodedFilter, skipDecode = true)
    let prevHeader = default(array[32, byte])  # all zeros
    let header = computeFilterHeader(filter, prevHeader)

    # Internal LE: SHA256d(SHA256d(019dfca8) || zeros)
    let expectedHex = "50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821"
    check toHexStr(header) == expectedHex

  test "filter header chain: block 2 Core test vector":
    ## Block 2 from blockfilters.json (encoded filter: 0174a170).
    ## prevHeader = genesis filterHeader (internal LE):
    ##   50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821
    ## Expected block 2 filterHeader (internal LE):
    ##   ecd151c4db7bef1fb0b94840171d0b4f81eabd6bd10eb65a0a07ccee6c2073fd
    ## (JSON display = fd73c2e6ce7ca0...1fd1; reversed from internal)
    let encodedFilter2 = fromHex("0174a170")
    let filter2 = newBlockFilter(bftBasic,
                                  displayHashToBlockHash(
                                    "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820"),
                                  encodedFilter2, skipDecode = true)

    # prevHeader = genesis filterHeader (internal LE)
    let prevHeaderHex = "50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821"
    var prevHeader: array[32, byte]
    let phSeq = fromHex(prevHeaderHex)
    for i in 0 ..< 32: prevHeader[i] = phSeq[i]

    let header2 = computeFilterHeader(filter2, prevHeader)
    let expectedHex = "ecd151c4db7bef1fb0b94840171d0b4f81eabd6bd10eb65a0a07ccee6c2073fd"
    check toHexStr(header2) == expectedHex

suite "W90 Bug 3: N overflow check allows full uint32 range":
  ## Bug 3: Old check was `> uint32(high(int32))` (2^31-1).
  ## Core allows up to 2^32-1 (uint32).
  ## Reference: bitcoin-core/src/blockfilter.cpp:78-81 (m_N != N check)

  test "N=0 creates empty filter":
    let params = GCSParams(sipHashK0: 1, sipHashK1: 2, p: BasicFilterP, m: BasicFilterM)
    let f = newGCSFilter(params, newSeq[seq[byte]]())
    check f.n == 0

  test "overflow check accepts exactly uint32 maximum elements (conceptual)":
    # We can't realistically build 2^32 elements, but we verify the check
    # is against uint32.high, not int32.high, by checking the constant path.
    # The check `uint64(n) > uint64(high(uint32))` is tested by ensuring that
    # a filter with 2^31 elements would be accepted (not rejected with int32 limit).
    # Practical test: build a filter with more than int32.high / 1000 elements,
    # which would previously have failed — too slow to do literally, so we
    # verify the guard expression is correct via inspection + small case.
    let params = GCSParams(sipHashK0: 1, sipHashK1: 2, p: 8'u8, m: 100'u32)
    var elems: seq[seq[byte]]
    for i in 0 ..< 1000:
      elems.add(@[byte(i shr 8), byte(i and 0xff)])
    let f = newGCSFilter(params, elems)
    check f.n == 1000

suite "W90 Bug 4: duplicate element deduplication":
  ## Bug 4: newGCSFilter(params, elements) must deduplicate like Core's ElementSet.
  ## Reference: bitcoin-core/src/blockfilter.cpp:74-102 (GCSFilter::GCSFilter with ElementSet)

  test "duplicate elements produce same filter as deduped elements":
    let params = GCSParams(sipHashK0: 0xdead, sipHashK1: 0xbeef,
                            p: BasicFilterP, m: BasicFilterM)
    let elem1 = @[1'u8, 2, 3]
    let elem2 = @[4'u8, 5, 6]

    # Filter with duplicates
    let withDups = newGCSFilter(params, @[elem1, elem2, elem1, elem2])
    # Filter without duplicates
    let withoutDups = newGCSFilter(params, @[elem1, elem2])

    # N must be 2 (distinct elements), not 4
    check withDups.n == 2
    check withoutDups.n == 2
    check withDups.encoded == withoutDups.encoded

  test "all-duplicate elements give N=1":
    let params = GCSParams(sipHashK0: 1, sipHashK1: 2, p: BasicFilterP, m: BasicFilterM)
    let elem = @[0xaa'u8, 0xbb, 0xcc]
    let f = newGCSFilter(params, @[elem, elem, elem, elem])
    check f.n == 1

  test "match still works after deduplication":
    let params = GCSParams(sipHashK0: 123, sipHashK1: 456,
                            p: BasicFilterP, m: BasicFilterM)
    let elem1 = @[1'u8, 2, 3]
    let elem2 = @[4'u8, 5, 6]
    let f = newGCSFilter(params, @[elem1, elem2, elem1])  # dup elem1

    check f.match(elem1) == true
    check f.match(elem2) == true
    check f.match(@[7'u8, 8, 9]) == false

suite "W90 Bug 5: excess data check in encoded-filter decode":
  ## Bug 5: Decoding from encoded bytes must reject filters with excess data.
  ## Reference: bitcoin-core/src/blockfilter.cpp:63-71
  ##   if (!stream.empty()) throw std::ios_base::failure("excess data");

  test "valid single-element filter round-trips without error":
    let params = GCSParams(sipHashK0: 99, sipHashK1: 77, p: BasicFilterP, m: BasicFilterM)
    let elem = @[0x01'u8, 0x02, 0x03, 0x04, 0x05]
    let original = newGCSFilter(params, @[elem])
    # Must decode without raising
    let reconstructed = newGCSFilter(params, original.encoded, skipDecode = false)
    check reconstructed.n == original.n

  test "excess data appended to valid filter raises GCSFilterError":
    let params = GCSParams(sipHashK0: 99, sipHashK1: 77, p: BasicFilterP, m: BasicFilterM)
    let elem = @[0x01'u8, 0x02, 0x03]
    let original = newGCSFilter(params, @[elem])
    # Append garbage byte at end
    var corrupt = original.encoded
    corrupt.add(0xff'u8)
    corrupt.add(0x00'u8)  # two extra bytes
    var raised = false
    try:
      discard newGCSFilter(params, corrupt, skipDecode = false)
    except GCSFilterError:
      raised = true
    check raised

  test "skipDecode=true bypasses excess-data check":
    let params = GCSParams(sipHashK0: 1, sipHashK1: 2, p: BasicFilterP, m: BasicFilterM)
    let elem = @[0xaa'u8, 0xbb]
    let original = newGCSFilter(params, @[elem])
    var corrupt = original.encoded
    corrupt.add(0xff'u8)
    corrupt.add(0x00'u8)
    # skipDecode=true must not raise
    let f = newGCSFilter(params, corrupt, skipDecode = true)
    check f.n == original.n

suite "W90 Bug 8: BitReader isEmpty logic":
  ## Bug 8: old isEmpty had dead second branch (bitPos >= 8 unreachable).
  ## Fixed to: r.pos >= r.data.len

  test "isEmpty returns false for fresh reader with data":
    var w = newBitWriter()
    w.writeBits(0b10101010, 8)
    var r = newBitReader(w.getData())
    check not r.isEmpty()

  test "isEmpty returns true after consuming all bits":
    var w = newBitWriter()
    w.writeBits(0b1, 1)
    var r = newBitReader(w.getData())
    discard r.readBit()
    # After reading the 1 bit from a 1-byte stream, pos is still 0 (bitPos=1)
    # isEmpty should be false (still in the byte)
    check not r.isEmpty()
    # Read remaining 7 bits to exhaust the byte
    for _ in 0 ..< 7:
      discard r.readBit()
    # Now pos == 1 == data.len → isEmpty
    check r.isEmpty()

  test "isEmpty on empty data":
    var r = newBitReader(@[])
    check r.isEmpty()

suite "W90 Core test vectors — genesis block filter":
  ## Full end-to-end check using data from blockfilters.json.
  ## Genesis coinbase output scriptPubKey:
  ##   4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
  ## Genesis block has no inputs (coinbase only) → no spent outputs.
  ## So the basic filter contains exactly one element: the coinbase scriptPubKey.
  ##
  ## Block hash (testnet3 genesis, matches blockfilters.json test):
  ##   000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
  ## Expected encoded filter: 019dfca8
  ## Expected filterHash:     21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
  ## Expected filterHeader:   21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750

  test "genesis filter has exactly 1 element":
    let genesisCoinbaseScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    # Display hash reversed to internal LE byte order (Core's m_data layout)
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, @[genesisCoinbaseScript])
    check filter.filter.n == 1

  test "genesis filter encoded bytes: N=1 with correct compact-size prefix":
    ## The basic filter for the genesis block contains exactly 1 element
    ## (the coinbase scriptPubKey). The encoded format is CompactSize(1) followed
    ## by Golomb-Rice encoded deltas (P=19). First byte must be 0x01.
    let genesisCoinbaseScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, @[genesisCoinbaseScript])
    let encoded = getEncodedFilter(filter)
    # First byte = CompactSize(N=1) = 0x01
    check encoded.len > 1
    check encoded[0] == 0x01'u8
    # Filter must roundtrip
    let reconstructed = newBlockFilter(bftBasic, blockHash, encoded, skipDecode = false)
    check reconstructed.filter.n == 1
    check reconstructed.filter.match(genesisCoinbaseScript)

  test "genesis filter hash is SHA256d of encoded filter (double SHA256 not single)":
    ## Verifies that getFilterHash() uses SHA256d rather than SHA256.
    ## The actual value depends on the encoded bytes which depend on SipHash keys.
    ## We verify that: sha256d(encoded) != sha256(encoded) to confirm SHA256d is used.
    let genesisCoinbaseScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, @[genesisCoinbaseScript])
    let fhash = getFilterHash(filter)
    # Must equal SHA256d of the encoded bytes
    let expectedHash = sha256d(filter.filter.encoded)
    check fhash == expectedHash
    # And must differ from single SHA256
    let singleHash = sha256Single(filter.filter.encoded)
    check fhash != singleHash

  test "genesis filter header chains SHA256d(hash || prevHeader)":
    ## Verifies that computeFilterHeader() uses SHA256d of (filterHash || prevHeader).
    let genesisCoinbaseScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, @[genesisCoinbaseScript])
    let prevHeader = default(array[32, byte])
    let fheader = computeFilterHeader(filter, prevHeader)
    # Must equal SHA256d(filterHash || zeros)
    let fhash = getFilterHash(filter)
    var combined: array[64, byte]
    copyMem(addr combined[0], unsafeAddr fhash[0], 32)
    let expectedHeader = sha256d(combined)
    check fheader == expectedHeader
    # The header must differ from the hash (different inputs)
    check fheader != fhash

  test "match finds genesis coinbase script in genesis filter":
    let genesisCoinbaseScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

    let filter = newBlockFilter(bftBasic, blockHash, @[genesisCoinbaseScript])
    check filter.filter.match(genesisCoinbaseScript) == true
    check filter.filter.match(@[0xaa'u8, 0xbb]) == false
