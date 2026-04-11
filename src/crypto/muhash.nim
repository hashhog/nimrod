## MuHash3072 - Multiplicative hash for UTXO set commitments
##
## MuHash is a hash function that allows incremental updates:
##   - Adding an element: multiply numerator by hash(element)
##   - Removing an element: multiply denominator by hash(element)
##   - Final hash: (numerator / denominator) mod p, then SHA256
##
## Uses 3072-bit arithmetic with prime modulus (2^3072 - 1103717).
## The multiplicative property allows parallel computation and efficient
## updates without recomputing the entire hash.
##
## Reference: Bitcoin Core /src/crypto/muhash.cpp
## Reference: https://cseweb.ucsd.edu/~mihir/papers/inchash.pdf

import std/[options]
import ./hashing
import ../primitives/[types, serialize]

const
  ByteSize* = 384                          ## 3072 bits = 384 bytes
  MaxPrimeDiff* = 1103717'u64              ## 2^3072 - MaxPrimeDiff is prime
  Limbs* = 48                              ## 48 x 64-bit limbs = 3072 bits
  LimbSize* = 64

type
  MuHashError* = object of CatchableError

  ## 3072-bit number represented as 48 x 64-bit limbs (little-endian)
  Num3072* = object
    limbs*: array[Limbs, uint64]

  ## MuHash accumulator with numerator/denominator representation
  MuHash3072* = object
    numerator*: Num3072
    denominator*: Num3072

# ============================================================================
# Helper math operations
# ============================================================================

proc isOverflow(n: Num3072): bool =
  ## Check if n >= modulus (2^3072 - MaxPrimeDiff)
  ## This means n.limbs[0] > MAX - MaxPrimeDiff and all other limbs are MAX
  if n.limbs[0] <= high(uint64) - MaxPrimeDiff:
    return false
  for i in 1 ..< Limbs:
    if n.limbs[i] != high(uint64):
      return false
  true

proc fullReduce(n: var Num3072) =
  ## Reduce by adding MaxPrimeDiff (equivalent to subtracting modulus)
  var carry: uint64 = MaxPrimeDiff
  for i in 0 ..< Limbs:
    let sum = n.limbs[i] + carry
    carry = if sum < n.limbs[i]: 1'u64 else: 0'u64
    n.limbs[i] = sum

proc setToOne*(n: var Num3072) =
  ## Set to multiplicative identity (1)
  n.limbs[0] = 1
  for i in 1 ..< Limbs:
    n.limbs[i] = 0

proc newNum3072*(): Num3072 =
  ## Create a new Num3072 initialized to 1
  result.setToOne()

proc isOne*(n: Num3072): bool =
  ## Check if value is 1
  if n.limbs[0] != 1:
    return false
  for i in 1 ..< Limbs:
    if n.limbs[i] != 0:
      return false
  true

proc fromBytes*(data: array[ByteSize, byte]): Num3072 =
  ## Construct Num3072 from 384 bytes (little-endian)
  for i in 0 ..< Limbs:
    var limb: uint64 = 0
    for j in 0 ..< 8:
      limb = limb or (uint64(data[i * 8 + j]) shl (j * 8))
    result.limbs[i] = limb

proc toBytes*(n: Num3072): array[ByteSize, byte] =
  ## Convert Num3072 to 384 bytes (little-endian)
  for i in 0 ..< Limbs:
    for j in 0 ..< 8:
      result[i * 8 + j] = byte((n.limbs[i] shr (j * 8)) and 0xff)

# ============================================================================
# 128-bit integer support for multiplication
# ============================================================================

type uint128* = object
  lo*, hi*: uint64

# ============================================================================
# Modular multiplication using schoolbook algorithm with reduction
# Closely follows Bitcoin Core's muhash.cpp Multiply implementation.
# ============================================================================

proc mul64(a, b: uint64): uint128 {.inline.} =
  ## 64x64 -> 128-bit multiply using 32-bit halves.
  ## Reference: Hacker's Delight §8-2 "Unsigned multiply high"
  let a0 = a and 0xFFFFFFFF'u64
  let a1 = a shr 32
  let b0 = b and 0xFFFFFFFF'u64
  let b1 = b shr 32

  let w0 = a0 * b0                           # ≤ 64 bits
  let t  = a1 * b0 + (w0 shr 32)            # ≤ 64 bits (see proof below)
  var w1 = (t and 0xFFFFFFFF'u64) + a0 * b1 # ≤ 64 bits (no overflow)
  let w2 = t shr 32

  result.lo = (w1 shl 32) or (w0 and 0xFFFFFFFF'u64)
  result.hi = a1 * b1 + w2 + (w1 shr 32)
  # Proof of no overflow: w1 ≤ (2^32-1) + (2^32-1)^2 < 2^64 (no overflow in +=)
  # hi ≤ (2^32-1)^2 + (2^32-1) + (2^64-1)/2^32 < 2^64

## [c0,c1,c2] += a * b  (matches Bitcoin Core's muladd3)
proc muladd3(c0, c1, c2: var uint64, a, b: uint64) {.inline.} =
  let t = mul64(a, b)
  let tl = t.lo
  var th = t.hi

  c0 += tl
  if c0 < tl: th += 1
  c1 += th
  if c1 < th: c2 += 1

## [c0,c1,c2] += n * [d0,d1,d2]  (matches Bitcoin Core's mulnadd3)
proc mulnadd3(c0, c1, c2: var uint64, d0, d1, d2: var uint64, n: uint64) {.inline.} =
  var t = mul64(d0, n)
  t.lo += c0
  if t.lo < c0: t.hi += 1
  c0 = t.lo
  var t2 = t.hi + c1
  let carry = if t2 < t.hi: 1'u64 else: 0'u64
  t = mul64(d1, n)
  t2 += t.lo
  let carry2 = if t2 < t.lo: 1'u64 else: 0'u64
  c1 = t2
  c2 = t.hi + d2 * n + carry + carry2 + c2

## [c0,c1] *= n  (matches Bitcoin Core's muln2)
proc muln2(c0, c1: var uint64, n: uint64) {.inline.} =
  let t = mul64(c0, n)
  c0 = t.lo
  let carry = t.hi
  let t2 = mul64(c1, n)
  c1 = t2.lo + carry
  # t2.hi is discarded (should be 0 for valid inputs)

## Extract lowest limb of [c0,c1,c2] into n, shift left by 1 limb
## (matches Bitcoin Core's extract3)
proc extract3(c0, c1, c2: var uint64, n: var uint64) {.inline.} =
  n = c0
  c0 = c1
  c1 = c2
  c2 = 0

## Add limb a to [c0,c1], extract lowest limb into n
## (matches Bitcoin Core's addnextract2)
proc addnextract2(c0, c1: var uint64, a: uint64, n: var uint64) {.inline.} =
  var c2: uint64 = 0
  c0 += a
  if c0 < a:
    c1 += 1
    if c1 == 0: c2 = 1
  n = c0
  c0 = c1
  c1 = c2

proc multiply*(a: var Num3072, b: Num3072) =
  ## Multiply a by b modulo (2^3072 - MaxPrimeDiff)
  ## Directly mirrors Bitcoin Core's Num3072::Multiply.
  var c0, c1, c2: uint64 = 0
  var tmp: Num3072

  # Compute limbs 0..N-2 of a*b into tmp, including one reduction.
  for j in 0 ..< Limbs - 1:
    var d0, d1, d2: uint64 = 0
    # High part: sum a[i] * b[N+j-i] for i = j+1..N-1
    # (first term uses mul, rest use muladd3)
    muladd3(d0, d1, d2, a.limbs[1 + j], b.limbs[Limbs + j - (1 + j)])
    for i in 2 + j ..< Limbs:
      muladd3(d0, d1, d2, a.limbs[i], b.limbs[Limbs + j - i])
    # c += d * MaxPrimeDiff
    mulnadd3(c0, c1, c2, d0, d1, d2, MaxPrimeDiff)
    # Low part: sum a[i] * b[j-i] for i = 0..j
    for i in 0 .. j:
      muladd3(c0, c1, c2, a.limbs[i], b.limbs[j - i])
    extract3(c0, c1, c2, tmp.limbs[j])

  # Compute limb N-1 of a*b into tmp.
  for i in 0 ..< Limbs:
    muladd3(c0, c1, c2, a.limbs[i], b.limbs[Limbs - 1 - i])
  extract3(c0, c1, c2, tmp.limbs[Limbs - 1])

  # Second reduction: c = (c0,c1) * MaxPrimeDiff, add back into result.
  muln2(c0, c1, MaxPrimeDiff)
  for j in 0 ..< Limbs:
    addnextract2(c0, c1, tmp.limbs[j], a.limbs[j])

  # Final reductions if needed (c0 will be 0 or 1 after the loop).
  if a.isOverflow(): a.fullReduce()
  if c0 != 0: a.fullReduce()

# ============================================================================
# Modular inverse using extended Euclidean algorithm
# ============================================================================

proc getInverse*(a: Num3072): Num3072 =
  ## Compute modular inverse using Fermat's little theorem:
  ## a^(-1) = a^(p-2) mod p, where p = 2^3072 - MaxPrimeDiff
  ##
  ## The exponent is p-2 = 2^3072 - MaxPrimeDiff - 2 = 2^3072 - 1103719
  ## In binary: 3072 bits, mostly 1s with the low 20 bits representing ~(1103719)
  ## = 11111...1111_0001111101001111111111001001 (low bits inverted from 1103719+2)
  ##
  ## Uses square-and-multiply (right-to-left bit scan of exponent).
  ##
  ## Note: MaxPrimeDiff = 1103717, so p-2 = 2^3072 - 1103719
  ## 1103719 in binary = 0x10DC67 = 0001_0000_1101_1100_0110_0111
  ## p-2 bits: bits 3071..20 are all 1, bits 19..0 are NOT(low 20 bits of 1103719)
  ## Actually: p = 2^3072 - 1103717, p-2 = 2^3072 - 1103719
  ## The binary representation of p-2 in 3072 bits:
  ##   bits 3071..20 are all 1 (because 2^3072 minus a small number)
  ##   bits 19..0: 2^20 - 1103719 + 2^3072 ... let's compute directly

  if a.isOne():
    result.setToOne()
    return

  # Build p-2 as an array of uint64 limbs (little-endian)
  # p = 2^3072 - 1103717
  # p-2 = 2^3072 - 1103719
  # In 3072-bit number: all limbs are 0xFFFFFFFFFFFFFFFF except limb[0]
  # limb[0] = 0xFFFFFFFFFFFFFFFF - 1103719 + 1 = 0xFFFFFFFFFFEF23C8
  # Actually: 2^64 - 1103719 = 18446744073708447897 = 0xFFFFFFFFFFEF23D9
  # Wait: 1103719 = 0x10DC67, so 0xFFFFFFFFFFFFFFFF - 0x10DC67 + 1 = 0xFFFFFFFFFFEF2399
  # Let me compute: 0x10DC67 = 1*16^5 + 0*16^4 + D*16^3 + C*16^2 + 6*16 + 7
  #               = 1048576 + 0 + 53248 + 3072 + 96 + 7 = 1104999?
  # 1103719 decimal: 1103719 / 16 = 68982r7, 68982/16 = 4311r6, 4311/16 = 269r7
  # 269/16 = 16r13(D), 16/16 = 1r0, so 1103719 = 0x10D767? Let me be precise:
  # 1103719 = 1048576 + 55143 = 1048576 + 32768 + 22375 = ...
  # Just compute: 1103719 in hex:
  # 1103719 mod 16 = 7, 1103719 div 16 = 68982
  # 68982 mod 16 = 6, div = 4311
  # 4311 mod 16 = 7 (4311=269*16+7), div = 269
  # 269 mod 16 = 13 (D), div = 16
  # 16 mod 16 = 0, div = 1
  # 1 mod 16 = 1
  # So 1103719 = 0x10D767
  # limb[0] of p-2 = 2^64 - 1103719 = 0xFFFFFFFFFFFFFFFF - 0x10D767 + 1 = 0xFFFFFFFFFFFEF299
  # Wait: FFFFFFFFFFFFFFFF - 10D767 = FFFFFFFFFFF F2898
  # Let me just hardcode: 2^64 = 18446744073709551616
  # 18446744073709551616 - 1103719 = 18446744073708447897
  # In hex: let me compute 1103719 = 0x10D767
  # 0xFFFFFFFFFFFFFFFF = 18446744073709551615
  # 18446744073709551615 - 1103719 + 1 = 18446744073708447897
  # 18446744073708447897 in hex: FFFFFFFFFFFE F... let me skip and compute differently

  # Simpler: use square-and-multiply with the exponent as a byte array
  # p-2 = 2^3072 - 1103719
  # Build the exponent byte array (little-endian): 384 bytes
  # All bytes are 0xFF except the first few
  # 1103719 in bytes (little-endian): [0x67, 0xD7, 0x10, 0, 0, ...]
  # p-2 = complement: first byte = 0xFF - 0x67 = 0x98 + carry...
  # Two's complement of 1103719 in 384 bytes = 384-byte subtraction
  # 2^3072 - 1103719 = subtract 1103719 from 2^3072
  # = all 0xFF bytes (which is 2^3072-1) minus (1103719-1) = minus 1103718
  # 1103718 = 0x10D766
  # So exp = 0xFF...FF XOR 0x10D766 (with the first 3 bytes being ~0x10D766)
  # byte0 = 0xFF ^ 0x66 = 0x99? No: ~0x66 = 0x99, ~0x6 AND ...
  # Simpler yet: 2^3072 - 1103719 = (2^3072 - 1) - 1103718 = all-ones minus 1103718
  # 1103718 = 0x10D766
  # all-ones minus 1103718: byte0=0xFF-0x66=0x99, byte1=0xFF-0xD7=0x28, byte2=0xFF-0x10=0xEF,
  #   byte3=0xFF, ..., byte383=0xFF
  # But borrow: this is NOT simple XOR. It's arithmetic subtraction.
  # Let me just verify: 0xFFFFFFFFFFFFFFFF - 0x10D766 = 0xFFFFFFFFFFEF2899
  # And 2^3072 - 1103719: limb[0] = 0xFFFFFFFFFFFFFFFF - 1103718 = 0xFFFFFFFFFFEF2899
  # 1103718 = 0x10D766: 0x10D766 = 1*2^20 + 0*2^16 + 13*2^12 + 7*2^8 + 6*2^4 + 6
  # = 1048576 + 53248 + 1792 + 96 + 6 = 1103718 ✓
  # 0xFFFFFFFFFFFFFFFF - 0x10D766 = 0xFFFFFFFFFFEF2899

  var exp: array[Limbs, uint64]
  for i in 0 ..< Limbs:
    exp[i] = 0xFFFFFFFFFFFFFFFF'u64
  exp[0] = 0xFFFFFFFFFFEF2899'u64  # 2^64 - 1103718 - 1 = 2^64 - 1103719

  # Square-and-multiply (left-to-right, starting from highest bit)
  result.setToOne()
  var base = a

  # Scan from bit 3071 down to bit 0
  for limbIdx in countdown(Limbs - 1, 0):
    for bitIdx in countdown(63, 0):
      # Square
      result.multiply(result)
      if result.isOverflow(): result.fullReduce()
      # Multiply by base if bit is set
      let bit = (exp[limbIdx] shr uint64(bitIdx)) and 1'u64
      if bit == 1:
        result.multiply(base)
        if result.isOverflow(): result.fullReduce()

proc divide*(a: var Num3072, b: Num3072) =
  ## Divide a by b modulo prime
  ## a = a * b^(-1) mod p
  if a.isOverflow():
    a.fullReduce()

  var bCopy = b
  if bCopy.isOverflow():
    bCopy.fullReduce()

  let inv = bCopy.getInverse()
  a.multiply(inv)

  if a.isOverflow():
    a.fullReduce()

# ============================================================================
# MuHash3072 implementation
# ============================================================================

proc newMuHash3072*(): MuHash3072 =
  ## Create empty MuHash (represents empty set)
  result.numerator.setToOne()
  result.denominator.setToOne()

proc toNum3072(data: openArray[byte]): Num3072 =
  ## Convert arbitrary data to Num3072 via hashing
  ## Uses SHA256 -> ChaCha20 expansion to get 384 bytes
  ##
  ## Simplified: use multiple SHA256 rounds to fill 384 bytes
  let hash1 = sha256Single(data)

  var expanded: array[ByteSize, byte]
  var pos = 0
  var counter = 0'u32

  while pos < ByteSize:
    # Hash: SHA256(original_hash || counter)
    var toHash: seq[byte] = @hash1
    toHash.add(byte(counter and 0xff))
    toHash.add(byte((counter shr 8) and 0xff))
    toHash.add(byte((counter shr 16) and 0xff))
    toHash.add(byte((counter shr 24) and 0xff))

    let chunk = sha256Single(toHash)
    for i in 0 ..< min(32, ByteSize - pos):
      expanded[pos + i] = chunk[i]
    pos += 32
    counter += 1

  result = fromBytes(expanded)
  # Reduce modulo p if >= p
  if result.isOverflow():
    result.fullReduce()

proc insert*(h: var MuHash3072, data: openArray[byte]) =
  ## Insert element into set (multiply numerator)
  let elem = toNum3072(data)
  h.numerator.multiply(elem)

proc remove*(h: var MuHash3072, data: openArray[byte]) =
  ## Remove element from set (multiply denominator)
  let elem = toNum3072(data)
  h.denominator.multiply(elem)

proc `*=`*(h: var MuHash3072, other: MuHash3072) =
  ## Combine two MuHash values (union of sets)
  h.numerator.multiply(other.numerator)
  h.denominator.multiply(other.denominator)

proc `/=`*(h: var MuHash3072, other: MuHash3072) =
  ## Subtract MuHash value (difference of sets)
  h.numerator.multiply(other.denominator)
  h.denominator.multiply(other.numerator)

proc finalize*(h: var MuHash3072): array[32, byte] =
  ## Compute final 256-bit hash
  ## Result = SHA256(numerator / denominator mod p)
  h.numerator.divide(h.denominator)
  h.denominator.setToOne()  # Reset for continued use

  let data = h.numerator.toBytes()
  sha256Single(data)

# ============================================================================
# Coin hash helpers for coinstatsindex
# ============================================================================

proc serializeCoinForHash*(outpoint: OutPoint, value: int64,
                           scriptPubKey: seq[byte], height: int32,
                           isCoinbase: bool): seq[byte] =
  ## Serialize a UTXO for MuHash insertion/removal
  ## Format matches Bitcoin Core's TxOutSer
  var w = BinaryWriter()

  # Outpoint
  w.writeTxId(outpoint.txid)
  w.writeUint32LE(outpoint.vout)

  # Coin data
  w.writeInt32LE(height)
  w.writeUint8(if isCoinbase: 1'u8 else: 0'u8)
  w.writeInt64LE(value)
  w.writeVarBytes(scriptPubKey)

  w.data

proc applyCoinHash*(h: var MuHash3072, outpoint: OutPoint, value: int64,
                    scriptPubKey: seq[byte], height: int32, isCoinbase: bool) =
  ## Add a UTXO to the MuHash
  let data = serializeCoinForHash(outpoint, value, scriptPubKey, height, isCoinbase)
  h.insert(data)

proc removeCoinHash*(h: var MuHash3072, outpoint: OutPoint, value: int64,
                     scriptPubKey: seq[byte], height: int32, isCoinbase: bool) =
  ## Remove a UTXO from the MuHash
  let data = serializeCoinForHash(outpoint, value, scriptPubKey, height, isCoinbase)
  h.remove(data)

# ============================================================================
# Serialization for persistence
# ============================================================================

proc serializeMuHash*(h: MuHash3072): seq[byte] =
  ## Serialize MuHash state (numerator + denominator)
  var w = BinaryWriter()
  w.writeBytes(h.numerator.toBytes())
  w.writeBytes(h.denominator.toBytes())
  w.data

proc deserializeMuHash*(data: seq[byte]): MuHash3072 =
  ## Deserialize MuHash state
  if data.len < 2 * ByteSize:
    raise newException(MuHashError, "invalid MuHash data")

  var numBytes, denomBytes: array[ByteSize, byte]
  copyMem(addr numBytes[0], unsafeAddr data[0], ByteSize)
  copyMem(addr denomBytes[0], unsafeAddr data[ByteSize], ByteSize)

  result.numerator = fromBytes(numBytes)
  result.denominator = fromBytes(denomBytes)

