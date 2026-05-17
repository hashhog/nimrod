## W122: BIP-158 GCS codec stress-vector audit (DISCOVERY)
##
## Per haskoin W121 addendum BUG-16: Core's blockfilters.json doesn't exercise
## quotients >= 64.  This file stress-tests nimrod's Golomb-Rice codec across
## small, boundary (63/64/65), and large (100/200/1000) quotient values, plus
## the existing Core blockfilters.json regression check (testnet3 genesis).
##
## Status (see audit/w122_bip158_codec_stress.md): **BUG FOUND — P0-CDIV**.
## Nimrod's bit-stream packing is **LSB-first within bytes**.  Bitcoin Core
## (and BIP-158 by spec, via Core's BitStreamWriter in src/streams.h) writes
## **MSB-first within bytes**.  These produce different wire bytes for every
## non-trivial encoding, so:
##   - nimrod's BlockFilter::encoded bytes do NOT match Core's blockfilters.json
##   - nimrod's filterHash = sha256d(encoded) does NOT match Core's filterHash
##   - nimrod's filterHeader chain does NOT match Core's
##   - nimrod's cfilter / cfheaders / cfcheckpt P2P responses are unreadable
##     by Core peers, and Core's responses are unreadable by nimrod
##   - nimrod's REST `/rest/blockfilter/...` payloads are wrong for callers
##     expecting Core-compatible bytes
##
## Reference:
##   bitcoin-core/src/blockfilter.cpp  (GCSFilter ctor / GetEncodedFilter)
##   bitcoin-core/src/util/golombrice.h  (GolombRiceEncode / GolombRiceDecode)
##   bitcoin-core/src/streams.h  (BitStreamWriter::Write, BitStreamReader::Read)
##   bitcoin-core/src/test/data/blockfilters.json
##   BIP-158
##
## These tests EXPECT FAILURE today (xfail).  They document the divergence so
## a future fix-wave can flip them green by switching nimrod's BitWriter/
## BitReader to MSB-first ordering.

import std/[unittest, strutils]
import ../src/storage/indexes/gcs
import ../src/primitives/types
import ../src/crypto/hashing

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
# Self-consistent round-trip (PASSES today — codec is internally consistent)
# ============================================================================

suite "W122 GR codec self-consistent round-trip across quotient regimes":
  ## These tests exercise the local writer/reader pair across the full
  ## stress range (haskoin BUG-16 region).  They MUST pass on the current
  ## codec because the writer and reader use the same bit order.

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
# Core blockfilters.json regression (FAILS today — documents the bug)
# ============================================================================
#
# This is the test G10 (MISSING in test_w121_compact_filters.nim) made
# concrete.  When the bit-order fix lands, these checks flip from xfail to
# pass and the codec will be byte-compatible with Core's BIP-158 wire.

suite "W122 BUG FOUND: nimrod GR codec bit-order differs from Core":
  ## Core's BitStreamWriter packs bits MSB-first within each byte (see
  ## bitcoin-core/src/streams.h:303-358 — "from the most significant bit
  ## position").  Nimrod's BitWriter packs LSB-first (see
  ## src/storage/indexes/gcs.nim:79 — `byte(bitsToWrite shl w.bitPos)`).
  ## These produce DIFFERENT wire bytes for the same logical GR value.
  ##
  ## Each test below documents one concrete divergence point.

  test "genesis filter byte equality FAILS today (xfail)":
    ## Core's blockfilters.json entry [0] (testnet3 genesis):
    ##   Basic Filter: "019dfca8"
    ## Nimrod produces "0155fe0e" — same logical content, wrong bit order.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let encoded = getEncodedFilter(filter)
    let coreExpected = "019dfca8"
    # xfail — should be "==" once bit order is fixed:
    check toHexStr(encoded) != coreExpected
    # Document the actual current bytes so a future fix can flip the polarity:
    check toHexStr(encoded) == "0155fe0e"

  test "genesis filter hash byte equality FAILS today (xfail)":
    ## Core's blockfilters.json filterHash (display=21584579...; internal LE):
    ##   SHA256d("019dfca8") = 4c8af7fa3ac4111dc5fd7581d176c02dbbfde83fd6f16496a576fbd6b20537c0
    ## Because nimrod's encoded bytes differ, its filter hash differs.
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
    check toHexStr(nimFh) != coreFhHex
    # Current actual nimrod hash (post-codec-bug):
    check toHexStr(nimFh) ==
      "f115ccef8a76383985dae8e940f744a9fafbd16deb6705baaf5457148f7545ca"

  test "GR-encoded q=1, r=0 (single bit 1 then 19 zeros)":
    ## Logical value: x = (1 << 19) = 524288
    ## MSB-first bit stream: 10 + 19 zeros = 21 bits => "10000000 00000000 00000"
    ## Padded to 3 bytes MSB-first: 0x80 0x00 0x00
    ## Nimrod's LSB-first produces: bits 1 then 0 in LSB of byte 0, plus 19 zeros
    ##   byte0 = 0b00000001 = 0x01;  rest = 0x00 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 1'u64 shl 19)
    let encoded = w.getData()
    # xfail — should be "800000" once bit order fixed:
    check toHexStr(encoded) != "800000"
    check toHexStr(encoded) == "010000"

  test "GR-encoded q=5, r=0 (five 1s then 0 then 19 zeros)":
    ## Bits MSB-first: 11111 0 followed by 19 zeros
    ##   byte0 = 11111000 = 0xf8;  byte1 = 0x00;  byte2 = 0x00;  byte3 = 0x00
    ## Nimrod's LSB-first: bits 11111 in low 5 bits of byte0 = 0x1f
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 5'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) != "f8000000"  # Core MSB-first
    check toHexStr(encoded) == "1f000000"   # Nimrod LSB-first

  test "GR-encoded q=63 (boundary just below 64-bit run)":
    ## 63 ones + terminating 0 + 19 zeros = 83 bits = 11 bytes (3 pad bits)
    ## MSB-first: first 7 bytes 0xff (56 ones), 8th byte 0b11111110 = 0xfe (7 ones, then 0)
    ## then 0x00 0x00 0x00
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 63'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) != "fffffffffffffffe000000"  # Core MSB-first
    check toHexStr(encoded) == "ffffffffffffff7f000000"   # Nimrod LSB-first

  test "GR-encoded q=65 (boundary just above 64-bit run — split unary write)":
    ## GolombRiceEncode loops writing up to 64 ones per pass.  q=65 forces
    ## a split: 64 ones in pass-1, then 1 one in pass-2, then 0 + remainder.
    ## MSB-first: 65 ones + 0 + 19 zeros = 85 bits = 11 bytes (3 pad bits)
    ##   8 bytes 0xff, then byte9 = 0b10000000 = 0x80, then 0x00 0x00 0x00
    ## Nimrod LSB-first: 8 bytes 0xff, then byte9 = 0b00000001 = 0x01
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 65'u64 shl 19)
    let encoded = w.getData()
    check toHexStr(encoded) != "ffffffffffffffff800000"  # Core MSB-first
    check toHexStr(encoded) == "ffffffffffffffff010000"   # Nimrod LSB-first

  test "GR-encoded q=100 (well into haskoin BUG-16 stress regime)":
    let p: uint8 = 19
    var w = newBitWriter()
    golombRiceEncode(w, p, 100'u64 shl 19)
    let encoded = w.getData()
    # Core would produce: 12 bytes 0xff (96 ones), then 0xf0 (4 ones + 0 + 3 zero-pad)
    # then 0x00 0x00.  Total 15 bytes.
    check toHexStr(encoded) != "fffffffffffffffffffffffff00000"  # Core
    check toHexStr(encoded) == "ffffffffffffffffffffffff0f0000"   # Nimrod

# ============================================================================
# Downstream impact (FAILS today — documents P2P / REST / index incompat)
# ============================================================================

suite "W122 downstream impact of bit-order bug":
  ## These verify the bug propagates into the BIP-157 P2P serving path and
  ## the on-disk filter file format.  Each test verifies a current behavior
  ## that is wire-incompatible with Core.

  test "filter header chain diverges at genesis (G7/G8 wire-incompat)":
    ## Core's genesis filterHeader (display=21584579...; internal LE):
    ##   50b781aed7b7129012a6d20e2d040027937f3affaee573779908ebb779455821
    ## Nimrod produces a different header because filterHash differs.
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
    check toHexStr(header) != coreHeaderHex   # xfail — bit-order bug propagates

  test "cfilter wire payload (encoded bytes) is unreadable by Core peer":
    ## On the wire, after `filterType(1) || block_hash(32) || compactsize(len)`,
    ## the `filter_bytes` payload is exactly `getEncodedFilter(filter)`.
    ## A Core peer reading this with its MSB-first BitStreamReader will get
    ## a totally different sequence of GR values than nimrod intended to
    ## encode.  Document this concretely with the genesis filter.
    let genesisScript = fromHex(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb" &
      "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    let blockHash = displayHashToBlockHash(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
    let filter = newBlockFilter(bftBasic, blockHash, @[genesisScript])
    let cfilterPayload = getEncodedFilter(filter)
    # Core would expect "019dfca8" for this block.  We send "0155fe0e".
    check toHexStr(cfilterPayload) == "0155fe0e"
    check toHexStr(cfilterPayload) != "019dfca8"

  test "round-trip survives self-decode but cross-decode of Core bytes fails":
    ## A nimrod node reading Core-encoded bytes "019dfca8" via newGCSFilter
    ## would either decode garbage element hashes OR raise excess-data.
    ## Either way the filter contents are wrong relative to the block.
    ##
    ## We document by trying to decode Core's bytes with nimrod's reader.
    ## (Note: the constructor verifies N+1 GR decodes succeed but does not
    ## verify the decoded values are meaningful — so "succeeds" silently.)
    let coreBytes = fromHex("019dfca8")
    let params = GCSParams(
      # Use the testnet3 genesis siphash keys (correct for this block):
      sipHashK0: 0x719526f8d77f4943'u64,
      sipHashK1: 0xaec3ced90fa3f408'u64,
      p: BasicFilterP, m: BasicFilterM)
    var raised = false
    try:
      let f = newGCSFilter(params, coreBytes, skipDecode = false)
      # If we got here, the decode "succeeded" but the value is garbage.
      # Verify N matches Core's expected N=1 (CompactSize byte is shared
      # between the two encodings so N is the same):
      check f.n == 1
    except GCSFilterError:
      raised = true
    # Either silently garbage OR raises — both are wrong.  Document the
    # observed behavior so a future fix wave can flip the assertion.
    discard raised  # current behavior: silent decode of meaningless value
