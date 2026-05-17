## Byte-exact BIP-158 regression vectors — closes W121 G10 MISSING.
##
## These vectors are transcribed from bitcoin-core's
## `src/test/data/blockfilters.json` (the canonical BIP-158 fixture set).
## Each entry pins both the encoded basic filter bytes and the chained
## filter header at one of Core's reference heights on testnet3.
##
## The vectors are used by:
##   - `test_w122_codec_stress.nim` (post-FIX-83 byte-equality assertions)
##   - `test_gcs.nim` (W90 SHA256d genesis vector)
##   - `verifyAgainstBIP158Vectors` (proc below) — minimal byte-exact
##     replay driver against `newBlockFilter`/`getEncodedFilter`/
##     `computeFilterHeader`, suitable for table-driven regression.
##
## NOTE: this module exists in `tests/` because it is regression test
## infrastructure, not production-fronted runtime data.  Importing it
## from production code is intentionally awkward (relative `..` path).
##
## Closes W121 G10:
##   "BIP-158 Core test-vector regression battery MISSING".
## Closes W122 BUG-1 (audit `75aea2e`) downstream.
##
## Reference: bitcoin-core/src/test/data/blockfilters.json
## Reference: BIP-158
## Reference: audit/w122_bip158_codec_stress.md (post-FIX-83)

import std/[strutils]
import ../src/storage/indexes/gcs
import ../src/primitives/types

type
  ## One BIP-158 reference vector.  Hex strings are LE-internal where
  ## applicable (block hash / filterHash / filterHeader display order is
  ## big-endian in the JSON; we keep the display form here and convert
  ## at the comparison site).
  BIP158TestVector* = object
    height*: int
    ## display-order (big-endian) block hash, as in JSON
    blockHashDisplay*: string
    ## Encoded basic filter bytes (lowercase hex).
    basicFilterHex*: string
    ## display-order (big-endian) filter header chained on the parent's
    ## header.  prevHeader is the previous vector's `filterHeaderDisplay`
    ## (or all-zeros for genesis).
    filterHeaderDisplay*: string
    ## display-order (big-endian) previous filter header used to compute
    ## this vector's header.
    prevHeaderDisplay*: string

const
  ## BIP-158 reference vectors transcribed byte-for-byte from
  ## bitcoin-core's `src/test/data/blockfilters.json`.  Each row pins the
  ## encoded basic-filter bytes AND the chained filter header against a
  ## declared prev-header (NOT necessarily the previous row — the JSON
  ## samples non-contiguous heights, so each vector carries its own
  ## prev_header taken from the chain).
  coreBIP158TestVectors*: seq[BIP158TestVector] = @[
    # blockfilters.json[1]: genesis (height 0)
    BIP158TestVector(
      height: 0,
      blockHashDisplay:
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
      basicFilterHex: "019dfca8",
      filterHeaderDisplay:
        "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750",
      prevHeaderDisplay:
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    # blockfilters.json[2]: height 2 (prev header = chain's block-1 header)
    BIP158TestVector(
      height: 2,
      blockHashDisplay:
        "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820",
      basicFilterHex: "0174a170",
      filterHeaderDisplay:
        "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0",
      prevHeaderDisplay:
        "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1",
    ),
    # blockfilters.json[3]: height 3 (prev header = height-2 filter header)
    BIP158TestVector(
      height: 3,
      blockHashDisplay:
        "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10",
      basicFilterHex: "016cf7a0",
      filterHeaderDisplay:
        "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a",
      prevHeaderDisplay:
        "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0",
    ),
  ]

proc fromHexBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc displayHashTo32*(displayHex: string): array[32, byte] =
  let raw = fromHexBytes(displayHex)
  for i in 0 ..< 32:
    result[i] = raw[31 - i]

proc displayHashToBlockHash*(displayHex: string): BlockHash =
  BlockHash(displayHashTo32(displayHex))

proc toHexLow*(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(toHex(x.int, 2).toLowerAscii)

proc verifyAgainstBIP158Vectors*(
  vectors: openArray[BIP158TestVector]
): tuple[passed: int, failed: int] =
  ## Replay every vector through `newBlockFilter` (skipDecode=true so we
  ## parse the encoded bytes back into a filter shell whose
  ## `computeFilterHeader` chains onto the JSON-declared parent).
  ## Returns (passed, failed) for the caller to assert against.
  ##
  ## Each vector exercises:
  ##   - `newBlockFilter(bftBasic, hash, encoded, skipDecode=true)`
  ##   - `getFilterHash(filter)` = SHA256d(encoded)
  ##   - `computeFilterHeader(filter, prevHeader)`
  ##     = SHA256d(filterHash || prevHeader)
  ##
  ## A vector "passes" when:
  ##   - `getEncodedFilter` returns exactly the JSON-declared bytes
  ##   - `computeFilterHeader` returns the JSON-declared chained header
  ##     (display-reversed for the comparison)
  for v in vectors:
    let encoded = fromHexBytes(v.basicFilterHex)
    let blockHash = displayHashToBlockHash(v.blockHashDisplay)
    let filter = newBlockFilter(bftBasic, blockHash, encoded, skipDecode = true)
    let outEncoded = getEncodedFilter(filter)
    let prevHeader = displayHashTo32(v.prevHeaderDisplay)
    let header = computeFilterHeader(filter, prevHeader)

    # Filter bytes must round-trip exactly.
    if toHexLow(outEncoded) != v.basicFilterHex:
      inc result.failed
      continue
    # Filter header must match (after display-order reversal).
    let displayHeader = block:
      var rev: array[32, byte]
      for i in 0 ..< 32:
        rev[i] = header[31 - i]
      toHexLow(rev)
    if displayHeader != v.filterHeaderDisplay:
      inc result.failed
      continue
    inc result.passed
