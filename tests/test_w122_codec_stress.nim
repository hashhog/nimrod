## W122: BIP-158 GCS codec stress-vector audit (POST-FIX)
##
## Per haskoin W121 addendum BUG-16: Core's blockfilters.json doesn't exercise
## quotients >= 64.  This file stress-tests nimrod's Golomb-Rice codec across
## small, boundary (63/64/65), and large (100/200/1000) quotient values, plus
## the Core blockfilters.json byte-exact regression check (testnet3 genesis).
##
## History (see audit/w122_bip158_codec_stress.md):
##   - W122 audit FOUND P0-CDIV: nimrod's BitWriter/BitReader packed bits
##     **LSB-first within bytes** while Bitcoin Core (and every other BIP-158
##     impl) packs **MSB-first within bytes** per `BitStreamWriter` in
##     `bitcoin-core/src/streams.h:303-358`.  The codec round-tripped locally
##     but every non-trivial wire byte was different from Core's.
##   - FIX-83 (this wave) rewrote the codec MSB-first.  These tests now
##     assert byte-for-byte Core parity on every quotient regime, plus on
##     the Core blockfilters.json[0] (testnet3 genesis) fixture.
##
## Reference:
##   bitcoin-core/src/blockfilter.cpp  (GCSFilter ctor / GetEncodedFilter)
##   bitcoin-core/src/util/golombrice.h  (GolombRiceEncode / GolombRiceDecode)
##   bitcoin-core/src/streams.h  (BitStreamWriter::Write, BitStreamReader::Read)
##   bitcoin-core/src/test/data/blockfilters.json
##   BIP-158

import unittest2
import std/[strutils, os]
import ../src/storage/indexes/gcs
import ../src/primitives/types
import ../src/crypto/hashing
import ./blockfilters_vectors

proc fromHex(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc toHexStr(b: openArray[byte]): string =
  result = ""
  for x in b:
    result.add(toHex(x.int, 2).toLowerAscii)

proc displayHashToBlockHash(displayHex: string): BlockHash =
  let raw = fromHex(displayHex)
  var bytes: array[32, byte]
  for i in 0 ..< 32:
    bytes[i] = raw[31 - i]
  BlockHash(bytes)

# ============================================================================
# Self-consistent round-trip (regression — codec must stay internally consistent)
# ============================================================================

suite "W122 GR codec self-consistent round-trip across quotient regimes":
  ## These tests exercise the local writer/reader pair across the full
  ## stress range (haskoin BUG-16 region).  They must pass independently of
  ## bit order because the writer and reader use the same convention.

  test "round-trip q=0,1,5,63,64,65,100,200,1000 (zero remainder)":
    let p: uint8 = 19
    let qs = @[0'u64, 1, 5, 63, 64, 65, 100, 200, 1000]
    for q in qs:
      let x = q shl int(p)
      var w = newBitWriter()
      golombRiceEncode(w, p, x)
      var r = newBitReader(w.getData())
      check golombRiceDecode(r, p) == x

  test "round-trip mixed sequence with nonzero remainder":
    let p: uint8 = 19
    let qs = @[0'u64, 1, 5, 63, 64, 65, 100, 200, 1000]
    var w = newBitWriter()
    var expected: seq[uint64]
    for q in qs:
      let r_part = uint64(0xabcd) and ((1'u64 shl 19) - 1)
      let x = (q shl int(p)) or r_part
      expected.add(x)
      golombRiceEncode(w, p, x)
    var rd = newBitReader(w.getData())
    for x in expected:
      check golombRiceDecode(rd, p) == x

  test "encoded byte length matches ceil((q+1+P)/8) for x = q << P":
    let p: uint8 = 19
    for q in [0'u64, 1, 5, 63, 64, 65, 100, 200, 1000]:
      var w = newBitWriter()
      golombRiceEncode(w, p, q shl int(p))
      let bits = int(q) + 1 + int(p)
      let bytes = (bits + 7) div 8
      check w.getData().len == bytes

# ============================================================================
# Core blockfilters.json byte-exact regression (FIX-83 / W122 BUG-1 closure)
# ============================================================================
#
# Pre-FIX-83 these were `!=` xfail assertions documenting the LSB-first bug.
# Post-FIX-83 they assert byte-for-byte Core parity.  This is the regression
# battery W121 G10 flagged MISSING — it is now PRESENT and load-bearing.

suite "W122 FIX-83: nimrod GR codec matches Core MSB-first byte layout":
  ## Core's BitStreamWriter packs bits MSB-first within each byte (see
  ## bitcoin-core/src/streams.h:303-358 — "from the most significant bit
  ## position").  Post FIX-83, nimrod's BitWriter follows the same
  ## convention, so encoded filter bytes are byte-for-byte identical to
  ## Core's output.

  test "genesis filter byte equality matches Core (was xfail, now PASS)":
    ## Core's blockfilters.json entry [0] (testnet3 genesis):
    ##   Basic Filter: "019dfca8"
    ## Post-FIX-83, nimrod produces exactly the same bytes.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let encoded = getEncodedFilter(filter)
    check toHexStr(encoded) == "019dfca8"

  test "genesis filter hash equals Core's SHA256d(019dfca8)":
    ## SHA256d("019dfca8") = 4c8af7fa3ac4111dc5fd7581d176c02dbbfde83fd6f16496a576fbd6b20537c0
    ## (internal LE; display reverses bytes).  Equal post-FIX-83.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let nimFh = getFilterHash(filter)
    let coreFh = sha256d(fromHex("019dfca8"))
    let coreFhHex = "4c8af7fa3ac4111dc5fd7581d176c02dbbfde83fd6f16496a576fbd6b20537c0"
    check toHexStr(coreFh) == coreFhHex
    check toHexStr(nimFh) == coreFhHex

  test "GR-encoded q=1, r=0 (single bit 1 then 19 zeros) — Core MSB layout":
    ## Logical value: x = (1 << 19) = 524288
    ## MSB-first bit stream: 10 + 19 zeros = 21 bits => "10000000 00000000 00000"
    ## Padded to 3 bytes MSB-first: 0x80 0x00 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 1'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) == "800000"

  test "GR-encoded q=5, r=0 (five 1s then 0 then 19 zeros) — Core MSB layout":
    ## Bits MSB-first: 11111 0 followed by 19 zeros
    ##   byte0 = 11111000 = 0xf8;  byte1 = 0x00;  byte2 = 0x00;  byte3 = 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 5'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) == "f8000000"

  test "GR-encoded q=63 (boundary just below 64-bit run) — Core MSB layout":
    ## 63 ones + terminating 0 + 19 zeros = 83 bits = 11 bytes (3 pad bits)
    ## MSB-first: first 7 bytes 0xff (56 ones), 8th byte 0b11111110 = 0xfe
    ## (7 ones, then 0); then 0x00 0x00 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 63'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) == "fffffffffffffffe000000"

  test "GR-encoded q=65 (boundary just above 64-bit run — split unary write)":
    ## GolombRiceEncode loops writing up to 64 ones per pass.  q=65 forces
    ## a split: 64 ones in pass-1, then 1 one in pass-2, then 0 + remainder.
    ## MSB-first: 65 ones + 0 + 19 zeros = 85 bits = 11 bytes (3 pad bits)
    ##   8 bytes 0xff, then byte9 = 0b10000000 = 0x80, then 0x00 0x00 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 65'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) == "ffffffffffffffff800000"

  test "GR-encoded q=100 (well into haskoin BUG-16 stress regime)":
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 100'u64 shl 19)
    let encoded = w.getData()
    # Core MSB-first: 12 bytes 0xff (96 ones), then 0xf0 (4 ones + 0 + 3 zero
    # pad bits), then 0x00 0x00.  Total 15 bytes.
    check toHexStr(encoded) == "fffffffffffffffffffffffff00000"

# ============================================================================
# Downstream impact: P2P / REST / on-disk now Core-compatible
# ============================================================================

suite "W122 downstream Core-parity (FIX-83 closure)":
  ## These verify the fix propagates into the BIP-157 P2P serving path and
  ## the on-disk filter file format.  Post-FIX-83, every byte path is
  ## byte-for-byte Core-compatible.

  test "filter header chain matches Core at genesis (G7/G8 wire-compat)":
    ## Core's genesis filterHeader (internal LE):
    ##   50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821
    ## Post-FIX-83, nimrod produces exactly the same header.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let prevHeader = default(array[32, byte])
    let header = computeFilterHeader(filter, prevHeader)
    let coreHeaderHex =
      "50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821"
    check toHexStr(header) == coreHeaderHex

  test "cfilter wire payload (encoded bytes) is readable by Core peer":
    ## On the wire, after `filterType(1) || block_hash(32) || compactsize(len)`,
    ## the `filter_bytes` payload is exactly `getEncodedFilter(filter)`.
    ## Post-FIX-83, those bytes equal Core's expected payload.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let cfilterPayload = getEncodedFilter(filter)
    check toHexStr(cfilterPayload) == "019dfca8"

  test "cross-decode of Core bytes recovers the genesis element hash":
    ## A nimrod node reading Core-encoded bytes "019dfca8" via newGCSFilter
    ## now decodes the GR value as 769941 — the correct fastRange64 image
    ## of the genesis coinbase scriptPubKey under the testnet3 genesis
    ## siphash keys.  Pre-FIX-83 this either silently decoded garbage or
    ## raised excess-data; post-FIX-83 the decode is byte-correct.
    let coreBytes = fromHex("019dfca8")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let params = basicFilterParams(blockHash)
    var raised = false
    var matched = false
    try:
      let f = newGCSFilter(params, coreBytes, skipDecode = false)
      check f.n == 1
      # Match the actual genesis coinbase scriptPubKey: the same script
      # Core hashed when building "019dfca8".
      let genesisScript = fromHex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
        "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
      matched = f.match(genesisScript)
    except GCSFilterError:
      raised = true
    check not raised
    check matched

# ============================================================================
# Table-driven Core test vector replay (closes W121 G10 MISSING)
# ============================================================================

suite "W122 FIX-83: byte-exact replay of blockfilters.json vectors":
  ## Drives every vector in `coreBIP158TestVectors` through
  ## `verifyAgainstBIP158Vectors` so that any future regression
  ## (bit order, padding, encoding boundary, SHA256d swap) trips a
  ## concrete fail with the offending vector identifiable in the
  ## reported counts.

  test "every BIP-158 vector matches Core byte-for-byte":
    check coreBIP158TestVectors.len >= 2
    let res = verifyAgainstBIP158Vectors(coreBIP158TestVectors)
    check res.failed == 0
    check res.passed == coreBIP158TestVectors.len

# ============================================================================
# Source-level forward-regression guard (W122 BUG-1 anti-revert)
# ============================================================================

suite "W122 FIX-83: source-level regression guard — MSB-first wiring":
  ## Reads src/storage/indexes/gcs.nim and asserts that the MSB-first
  ## codec idioms are still present at the documented call sites.
  ##
  ## RATIONALE: the W122 bug is invisible in a self-consistent
  ## ecosystem.  A drive-by refactor that "simplifies" the BitWriter
  ## back to `byte(value shl bitPos)` would round-trip locally and
  ## escape the byte-exact regression unless someone re-ran the Core
  ## vector replay above.  This source-level guard fails immediately
  ## if the LSB-first idiom comes back, even before any test is run.
  ##
  ## Specifically asserts:
  ##   - the writer no longer uses `shl w.bitPos` (LSB-first shift)
  ##   - the writer uses the MSB-aligned form
  ##     `byte(... shl (8 - w.bitPos - toWrite))`
  ##   - the reader uses `(... shr (7 - r.bitPos))` (MSB-first read)
  ##   - the reader no longer uses `shr r.bitPos` (LSB-first read)

  test "gcs.nim writeBits uses MSB-first shift (not LSB-first)":
    # Path to source file relative to this test file location.
    let src = readFile(currentSourcePath().parentDir() /
                       "../src/storage/indexes/gcs.nim")
    # Pre-FIX-83 idiom was `byte(bitsToWrite shl w.bitPos)` — packing
    # bits at the low side of each byte.  Post-FIX-83 we use a
    # shiftFromTop variable equal to `8 - w.bitPos - toWrite`.
    check "shiftFromTop = 8 - w.bitPos - toWrite" in src
    check "byte(topBits shl shiftFromTop)" in src
    # The MSB-aligned extraction of payload bits is also distinctive.
    check "(value shr (remaining - toWrite))" in src
    # And the legacy LSB-first idiom (anywhere it could come back)
    # must not appear in the writer.
    check "bitsToWrite shl w.bitPos" notin src

  test "gcs.nim readBit uses MSB-first shift (not LSB-first)":
    let src = readFile(currentSourcePath().parentDir() /
                       "../src/storage/indexes/gcs.nim")
    # MSB-first decode idiom.
    check "shr (7 - r.bitPos)" in src
    # readBits assembles MSB-first: shift-left + or.
    check "result = (result shl 1) or r.readBit()" in src
    # Legacy LSB-first decode hallmark must not appear.
    check "r.data[r.pos] shr r.bitPos" notin src

  test "gcs.nim BitWriter bitPos comment says 'from MSB'":
    let src = readFile(currentSourcePath().parentDir() /
                       "../src/storage/indexes/gcs.nim")
    check "from MSB" in src
    check "MSB-first" in src
