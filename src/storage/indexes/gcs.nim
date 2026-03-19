## Golomb-Coded Set (GCS) implementation for BIP 158 compact block filters
##
## GCS is a probabilistic data structure for set membership testing
## with configurable false positive rate (1/M). Elements are hashed
## to a range [0, N*M), sorted, and deltas are Golomb-Rice encoded.
##
## BIP 158 "Basic" filter parameters:
##   P = 19 (Golomb-Rice coding parameter)
##   M = 784931 (inverse false positive rate)
##
## Reference: Bitcoin Core /src/blockfilter.cpp
## Reference: BIP 158 https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

import std/[algorithm, sets, hashes]
import ../../primitives/[types, serialize]
import ../../crypto/siphash
import ../../crypto/hashing

type
  GCSFilterError* = object of CatchableError

  ## GCS filter parameters
  GCSParams* = object
    sipHashK0*: uint64    ## SipHash key part 1 (from block hash)
    sipHashK1*: uint64    ## SipHash key part 2 (from block hash)
    p*: uint8             ## Golomb-Rice coding parameter
    m*: uint32            ## Inverse false positive rate

  ## A Golomb-coded set filter
  GCSFilter* = object
    params*: GCSParams
    n*: uint32            ## Number of elements
    f*: uint64            ## Range of element hashes (N * M)
    encoded*: seq[byte]   ## Encoded filter data

  ## Bit writer for Golomb-Rice encoding
  BitWriter* = object
    data*: seq[byte]
    bitPos: int           ## Bits written to current byte (0-7)

  ## Bit reader for Golomb-Rice decoding
  BitReader* = object
    data: seq[byte]
    pos: int              ## Current byte position
    bitPos: int           ## Current bit within byte (0-7)

# BIP 158 "Basic" filter constants
const
  BasicFilterP* = 19'u8
  BasicFilterM* = 784931'u32

# ============================================================================
# Bit writer for Golomb-Rice encoding
# ============================================================================

proc newBitWriter*(): BitWriter =
  result.data = @[]
  result.bitPos = 0

proc writeBits*(w: var BitWriter, value: uint64, bits: int) =
  ## Write `bits` bits of `value` to the stream
  var remaining = bits
  var val = value

  while remaining > 0:
    # Start new byte if needed
    if w.bitPos == 0:
      w.data.add(0)

    # How many bits can we write to current byte?
    let available = 8 - w.bitPos
    let toWrite = min(remaining, available)

    # Extract bits to write (from low end of val)
    let mask = (1'u64 shl toWrite) - 1
    let bitsToWrite = val and mask

    # Write to current byte (pack from low bits)
    w.data[^1] = w.data[^1] or byte(bitsToWrite shl w.bitPos)

    # Update state
    w.bitPos = (w.bitPos + toWrite) mod 8
    if w.bitPos == 0 and remaining > toWrite:
      discard  # Will start new byte on next iteration
    val = val shr toWrite
    remaining -= toWrite

proc flush*(w: var BitWriter) =
  ## Flush any remaining partial byte (already handled by writeBits)
  discard

proc getData*(w: BitWriter): seq[byte] =
  w.data

# ============================================================================
# Bit reader for Golomb-Rice decoding
# ============================================================================

proc newBitReader*(data: seq[byte]): BitReader =
  result.data = data
  result.pos = 0
  result.bitPos = 0

proc readBit*(r: var BitReader): uint64 =
  ## Read a single bit
  if r.pos >= r.data.len:
    raise newException(GCSFilterError, "unexpected end of filter data")

  let bit = (r.data[r.pos] shr r.bitPos) and 1
  r.bitPos += 1
  if r.bitPos == 8:
    r.bitPos = 0
    r.pos += 1
  uint64(bit)

proc readBits*(r: var BitReader, bits: int): uint64 =
  ## Read `bits` bits from the stream
  result = 0
  for i in 0 ..< bits:
    result = result or (r.readBit() shl i)

proc isEmpty*(r: BitReader): bool =
  r.pos >= r.data.len or (r.pos == r.data.len - 1 and r.bitPos >= 8)

# ============================================================================
# Golomb-Rice encoding/decoding
# ============================================================================

proc golombRiceEncode*(w: var BitWriter, p: uint8, x: uint64) =
  ## Encode a value using Golomb-Rice coding
  ## Write quotient as unary (q 1's followed by 0), then remainder in P bits
  let q = x shr p      ## Quotient
  let r = x and ((1'u64 shl p) - 1)  ## Remainder (bottom P bits)

  # Write quotient in unary: q ones followed by a zero
  var remaining = q
  while remaining > 0:
    let nbits = min(remaining, 64).int
    w.writeBits(not 0'u64, nbits)  # Write `nbits` ones
    remaining -= uint64(nbits)
  w.writeBits(0, 1)  # Terminating zero

  # Write remainder in P bits
  w.writeBits(r, int(p))

proc golombRiceDecode*(r: var BitReader, p: uint8): uint64 =
  ## Decode a Golomb-Rice encoded value
  ## Read unary quotient, then P-bit remainder
  var q: uint64 = 0

  # Read unary: count ones until we hit a zero
  while r.readBit() == 1:
    q += 1

  # Read remainder
  let remainder = r.readBits(int(p))

  result = (q shl p) + remainder

# ============================================================================
# GCS filter construction
# ============================================================================

proc hashToRange*(params: GCSParams, element: openArray[byte], f: uint64): uint64 =
  ## Hash an element to range [0, F) where F = N * M
  let hash = sipHash(params.sipHashK0, params.sipHashK1, element)
  fastRange64(hash, f)

proc buildHashedSet*(params: GCSParams, elements: seq[seq[byte]], f: uint64): seq[uint64] =
  ## Hash all elements and return sorted list of hashes
  result = newSeqOfCap[uint64](elements.len)
  for elem in elements:
    result.add(hashToRange(params, elem, f))
  result.sort()

proc newGCSFilter*(params: GCSParams): GCSFilter =
  ## Create an empty filter
  result.params = params
  result.n = 0
  result.f = 0
  result.encoded = @[]

proc newGCSFilter*(params: GCSParams, elements: seq[seq[byte]]): GCSFilter =
  ## Build a GCS filter from a set of elements
  result.params = params
  result.n = uint32(elements.len)
  if result.n > uint32(high(int32)):
    raise newException(GCSFilterError, "N must be < 2^31")
  result.f = uint64(result.n) * uint64(params.m)

  if elements.len == 0:
    # Empty filter: just N=0
    var w = BinaryWriter()
    w.writeCompactSize(0)
    result.encoded = w.data
    return

  # Build sorted hash set
  let hashedSet = buildHashedSet(params, elements, result.f)

  # Encode: CompactSize(N) followed by Golomb-Rice encoded deltas
  var w = BinaryWriter()
  w.writeCompactSize(uint64(result.n))

  var bitWriter = newBitWriter()
  var lastValue: uint64 = 0
  for value in hashedSet:
    let delta = value - lastValue
    golombRiceEncode(bitWriter, params.p, delta)
    lastValue = value
  bitWriter.flush()

  # Combine CompactSize and bit data
  result.encoded = w.data
  result.encoded.add(bitWriter.getData())

proc newGCSFilter*(params: GCSParams, encodedFilter: seq[byte], skipDecode: bool = false): GCSFilter =
  ## Reconstruct a filter from encoded data
  result.params = params
  result.encoded = encodedFilter

  if encodedFilter.len == 0:
    result.n = 0
    result.f = 0
    return

  # Read N from CompactSize prefix
  var r = BinaryReader(data: encodedFilter, pos: 0)
  let n = r.readCompactSize()
  if n > uint64(high(uint32)):
    raise newException(GCSFilterError, "N must be < 2^32")
  result.n = uint32(n)
  result.f = uint64(result.n) * uint64(params.m)

  if skipDecode:
    return

  # Verify we can decode exactly N elements
  if result.n == 0:
    return

  var bitData = encodedFilter[r.pos .. ^1]
  var bitReader = newBitReader(bitData)
  for i in 0 ..< result.n:
    discard golombRiceDecode(bitReader, params.p)

# ============================================================================
# GCS filter matching
# ============================================================================

proc matchInternal(filter: GCSFilter, sortedHashes: seq[uint64]): bool =
  ## Check if any of the sorted hashes match the filter
  if filter.n == 0 or sortedHashes.len == 0:
    return false

  # Read N and get bit data
  var r = BinaryReader(data: filter.encoded, pos: 0)
  let n = r.readCompactSize()
  if n != uint64(filter.n):
    return false

  var bitData = filter.encoded[r.pos .. ^1]
  var bitReader = newBitReader(bitData)

  var value: uint64 = 0
  var hashIdx = 0

  for i in 0 ..< filter.n:
    let delta = golombRiceDecode(bitReader, filter.params.p)
    value += delta

    # Linear search through sorted query hashes
    while hashIdx < sortedHashes.len:
      if sortedHashes[hashIdx] == value:
        return true
      elif sortedHashes[hashIdx] > value:
        break
      hashIdx += 1

  false

proc match*(filter: GCSFilter, element: openArray[byte]): bool =
  ## Check if a single element may be in the filter
  ## Returns true if element matches (may be false positive)
  if filter.n == 0:
    return false

  let hash = hashToRange(filter.params, element, filter.f)
  filter.matchInternal(@[hash])

proc matchAny*(filter: GCSFilter, elements: seq[seq[byte]]): bool =
  ## Check if any of the elements may be in the filter
  ## More efficient than checking each element individually
  if filter.n == 0 or elements.len == 0:
    return false

  let hashes = buildHashedSet(filter.params, elements, filter.f)
  filter.matchInternal(hashes)

# ============================================================================
# Block filter (BIP 158)
# ============================================================================

type
  BlockFilterType* = enum
    bftBasic = 0    ## Basic filter (all scriptPubKeys)
    bftInvalid = 255

  BlockFilter* = object
    filterType*: BlockFilterType
    blockHash*: BlockHash
    filter*: GCSFilter

proc basicFilterParams*(blockHash: BlockHash): GCSParams =
  ## Get BIP 158 "Basic" filter parameters for a block
  ## SipHash keys are derived from block hash
  let hashBytes = array[32, byte](blockHash)
  var k0, k1: uint64
  for i in 0 ..< 8:
    k0 = k0 or (uint64(hashBytes[i]) shl (i * 8))
    k1 = k1 or (uint64(hashBytes[8 + i]) shl (i * 8))

  GCSParams(
    sipHashK0: k0,
    sipHashK1: k1,
    p: BasicFilterP,
    m: BasicFilterM
  )

proc getFilterHash*(filter: BlockFilter): array[32, byte] =
  ## Compute filter hash (SHA256 of encoded filter)
  sha256Single(filter.filter.encoded)

proc computeFilterHeader*(filter: BlockFilter, prevHeader: array[32, byte]): array[32, byte] =
  ## Compute filter header: SHA256(filterHash || prevHeader)
  ## This creates a chain of filter commitments
  let filterHash = getFilterHash(filter)
  var combined: array[64, byte]
  copyMem(addr combined[0], unsafeAddr filterHash[0], 32)
  copyMem(addr combined[32], unsafeAddr prevHeader[0], 32)
  sha256Single(combined)

proc newBlockFilter*(filterType: BlockFilterType, blockHash: BlockHash,
                     elements: seq[seq[byte]]): BlockFilter =
  ## Create a new block filter from elements
  case filterType
  of bftBasic:
    let params = basicFilterParams(blockHash)
    result.filterType = filterType
    result.blockHash = blockHash
    result.filter = newGCSFilter(params, elements)
  of bftInvalid:
    raise newException(GCSFilterError, "invalid filter type")

proc newBlockFilter*(filterType: BlockFilterType, blockHash: BlockHash,
                     encodedFilter: seq[byte], skipDecode: bool = false): BlockFilter =
  ## Reconstruct a block filter from encoded data
  case filterType
  of bftBasic:
    let params = basicFilterParams(blockHash)
    result.filterType = filterType
    result.blockHash = blockHash
    result.filter = newGCSFilter(params, encodedFilter, skipDecode)
  of bftInvalid:
    raise newException(GCSFilterError, "invalid filter type")

proc getEncodedFilter*(filter: BlockFilter): seq[byte] =
  filter.filter.encoded

proc getN*(filter: BlockFilter): uint32 =
  filter.filter.n

# ============================================================================
# Basic filter element extraction (BIP 158)
# ============================================================================

proc isOpReturn*(script: openArray[byte]): bool =
  ## Check if script starts with OP_RETURN
  script.len > 0 and script[0] == 0x6a

# Spent output type for filter element extraction
type SpentOutput* = object
  output*: TxOut
  height*: int32
  isCoinbase*: bool

proc extractBasicFilterElements*(
  blk: Block,
  undoData: seq[SpentOutput]
): seq[seq[byte]] =
  ## Extract elements for a BIP 158 "Basic" filter
  ## Includes:
  ##   - All output scriptPubKeys (except empty and OP_RETURN)
  ##   - All spent output scriptPubKeys from undo data
  var elements: HashSet[seq[byte]]

  # Add output scriptPubKeys
  for tx in blk.txs:
    for output in tx.outputs:
      let script = output.scriptPubKey
      # Skip empty and OP_RETURN scripts
      if script.len > 0 and not isOpReturn(script):
        elements.incl(script)

  # Add spent output scriptPubKeys from undo data
  for spent in undoData:
    let script = spent.output.scriptPubKey
    if script.len > 0:
      elements.incl(script)

  # Convert to seq
  for elem in elements:
    result.add(elem)
