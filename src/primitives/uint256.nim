## UInt256 - 256-bit unsigned integer for Bitcoin target arithmetic
## Implements multiplication, division, and comparison needed for difficulty adjustment

type
  UInt256* = object
    ## 256-bit unsigned integer stored as 4 x 64-bit limbs in little-endian order
    ## limbs[0] is the least significant limb
    limbs*: array[4, uint64]

# Constructors

proc initUInt256*(): UInt256 =
  ## Zero-initialize a UInt256
  result

proc initUInt256*(val: uint64): UInt256 =
  ## Create UInt256 from a single uint64 value
  result.limbs[0] = val

proc initUInt256*(bytes: array[32, byte]): UInt256 =
  ## Create UInt256 from 32-byte array (little-endian)
  ## bytes[0] is least significant byte
  for i in 0..3:
    var limb: uint64 = 0
    for j in 0..7:
      limb = limb or (uint64(bytes[i * 8 + j]) shl (j * 8))
    result.limbs[i] = limb

proc toBytes*(n: UInt256): array[32, byte] =
  ## Convert UInt256 to 32-byte array (little-endian)
  for i in 0..3:
    for j in 0..7:
      result[i * 8 + j] = byte((n.limbs[i] shr (j * 8)) and 0xff)

# Comparison operators

proc `==`*(a, b: UInt256): bool =
  a.limbs == b.limbs

proc `<`*(a, b: UInt256): bool =
  ## Compare two UInt256 values
  for i in countdown(3, 0):
    if a.limbs[i] < b.limbs[i]:
      return true
    elif a.limbs[i] > b.limbs[i]:
      return false
  false  # Equal

proc `<=`*(a, b: UInt256): bool =
  a < b or a == b

proc `>`*(a, b: UInt256): bool =
  not (a <= b)

proc `>=`*(a, b: UInt256): bool =
  not (a < b)

proc isZero*(n: UInt256): bool =
  n.limbs[0] == 0 and n.limbs[1] == 0 and n.limbs[2] == 0 and n.limbs[3] == 0

# Arithmetic operations

proc `+`*(a, b: UInt256): UInt256 =
  ## Add two UInt256 values (with overflow wrapping)
  var carry: uint64 = 0
  for i in 0..3:
    let sum = a.limbs[i] + b.limbs[i] + carry
    if sum < a.limbs[i] or (sum == a.limbs[i] and (b.limbs[i] > 0 or carry > 0)):
      carry = 1
    else:
      carry = 0
    result.limbs[i] = sum

proc `-`*(a, b: UInt256): UInt256 =
  ## Subtract two UInt256 values (with underflow wrapping)
  var borrow: uint64 = 0
  for i in 0..3:
    let diff = a.limbs[i] - b.limbs[i] - borrow
    if a.limbs[i] < b.limbs[i] + borrow:
      borrow = 1
    else:
      borrow = 0
    result.limbs[i] = diff

proc `*`*(a: UInt256, b: uint64): UInt256 =
  ## Multiply UInt256 by uint64
  var carry: uint64 = 0
  for i in 0..3:
    # Use 128-bit multiplication via two 64-bit multiplies
    let al = a.limbs[i] and 0xffffffff'u64
    let ah = a.limbs[i] shr 32
    let bl = b and 0xffffffff'u64
    let bh = b shr 32

    # Multiply parts
    let ll = al * bl
    let lh = al * bh
    let hl = ah * bl
    let hh = ah * bh

    # Combine with carry
    let mid = lh + hl
    let midCarry = if mid < lh: 1'u64 shl 32 else: 0'u64

    let low = ll + (mid shl 32)
    let lowCarry = if low < ll: 1'u64 else: 0'u64

    let high = hh + (mid shr 32) + midCarry + lowCarry

    let sum = low + carry
    let sumCarry = if sum < low: 1'u64 else: 0'u64

    result.limbs[i] = sum
    carry = high + sumCarry

proc `div`*(a: UInt256, b: uint64): UInt256 =
  ## Divide UInt256 by uint64
  if b == 0:
    # Division by zero - return max value (or could raise)
    for i in 0..3:
      result.limbs[i] = high(uint64)
    return

  var remainder: uint64 = 0
  for i in countdown(3, 0):
    # Process each 64-bit limb
    # We need to compute (remainder * 2^64 + a.limbs[i]) / b
    # Since this can overflow, we handle it carefully

    # If remainder is 0, division is straightforward
    if remainder == 0:
      result.limbs[i] = a.limbs[i] div b
      remainder = a.limbs[i] mod b
    else:
      # Need to handle (remainder * 2^64 + limb) / b
      # Use binary long division for correctness
      let limb = a.limbs[i]
      var q: uint64 = 0
      var r: uint64 = remainder

      for j in countdown(63, 0):
        # Shift r left by 1 and bring in next bit of limb
        let bit = (limb shr j) and 1
        let newR = (r shl 1) or bit

        # Check for overflow in the shift
        if r >= (1'u64 shl 63):
          # r would overflow when shifted - this means newR >= b for sure
          q = q or (1'u64 shl j)
          r = newR - b
        elif newR >= b:
          q = q or (1'u64 shl j)
          r = newR - b
        else:
          r = newR

      result.limbs[i] = q
      remainder = r

proc `mod`*(a: UInt256, b: uint64): uint64 =
  ## Modulo UInt256 by uint64
  if b == 0:
    return 0

  var remainder: uint64 = 0
  for i in countdown(3, 0):
    if remainder == 0:
      remainder = a.limbs[i] mod b
    else:
      # Same binary long division as above, but we only need remainder
      let limb = a.limbs[i]
      var r = remainder

      for j in countdown(63, 0):
        let bit = (limb shr j) and 1
        let newR = (r shl 1) or bit

        if r >= (1'u64 shl 63):
          r = newR - b
        elif newR >= b:
          r = newR - b
        else:
          r = newR

      remainder = r

  remainder

proc `shl`*(a: UInt256, bits: int): UInt256 =
  ## Left shift UInt256 by bits (0-255)
  if bits <= 0:
    return a
  if bits >= 256:
    return initUInt256()

  let limbShift = bits div 64
  let bitShift = bits mod 64

  if bitShift == 0:
    for i in countdown(3, limbShift):
      result.limbs[i] = a.limbs[i - limbShift]
  else:
    for i in countdown(3, 0):
      let srcIdx = i - limbShift
      if srcIdx >= 0:
        result.limbs[i] = a.limbs[srcIdx] shl bitShift
        if srcIdx > 0:
          result.limbs[i] = result.limbs[i] or (a.limbs[srcIdx - 1] shr (64 - bitShift))

proc `shr`*(a: UInt256, bits: int): UInt256 =
  ## Right shift UInt256 by bits (0-255)
  if bits <= 0:
    return a
  if bits >= 256:
    return initUInt256()

  let limbShift = bits div 64
  let bitShift = bits mod 64

  if bitShift == 0:
    for i in 0..(3 - limbShift):
      result.limbs[i] = a.limbs[i + limbShift]
  else:
    for i in 0..3:
      let srcIdx = i + limbShift
      if srcIdx <= 3:
        result.limbs[i] = a.limbs[srcIdx] shr bitShift
        if srcIdx < 3:
          result.limbs[i] = result.limbs[i] or (a.limbs[srcIdx + 1] shl (64 - bitShift))

# Compact target conversion (Bitcoin nBits format)

proc setCompact*(bits: uint32): UInt256 =
  ## Convert compact target representation (nBits) to UInt256
  ## Returns (target, isNegative, isOverflow)
  let exponent = int((bits shr 24) and 0xff)
  let mantissa = bits and 0x007fffff

  # Check for negative (MSB of mantissa set)
  if (bits and 0x00800000) != 0:
    return initUInt256()  # Negative targets are invalid

  if exponent == 0:
    return initUInt256()

  if mantissa == 0:
    return initUInt256()

  # Target = mantissa * 2^(8*(exponent-3))
  result = initUInt256(uint64(mantissa))

  if exponent <= 3:
    # Right shift
    let shift = (3 - exponent) * 8
    result = result shr shift
  else:
    # Left shift
    let shift = (exponent - 3) * 8
    result = result shl shift

proc getCompact*(target: UInt256): uint32 =
  ## Convert UInt256 target to compact representation (nBits)

  # Find the highest non-zero byte
  var size = 32
  let bytes = target.toBytes()

  while size > 0 and bytes[size - 1] == 0:
    dec size

  if size == 0:
    return 0

  var mantissa: uint32
  if size <= 3:
    mantissa = uint32(bytes[0])
    if size > 1:
      mantissa = mantissa or (uint32(bytes[1]) shl 8)
    if size > 2:
      mantissa = mantissa or (uint32(bytes[2]) shl 16)
    mantissa = mantissa shl (8 * (3 - size))
  else:
    mantissa = uint32(bytes[size - 3])
    mantissa = mantissa or (uint32(bytes[size - 2]) shl 8)
    mantissa = mantissa or (uint32(bytes[size - 1]) shl 16)

  # If MSB is set, we need to add a zero byte
  if (mantissa and 0x00800000) != 0:
    mantissa = mantissa shr 8
    inc size

  (uint32(size) shl 24) or mantissa

# String representation for debugging

proc toHexByte(b: byte): string =
  const hexChars = "0123456789abcdef"
  result = newString(2)
  result[0] = hexChars[int(b shr 4)]
  result[1] = hexChars[int(b and 0xf)]

proc `$`*(n: UInt256): string =
  ## Convert to hex string for debugging
  let bytes = n.toBytes()
  result = "0x"
  for i in countdown(31, 0):
    result.add(toHexByte(bytes[i]))
