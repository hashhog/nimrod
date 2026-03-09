## Bech32 and Bech32m encoding for segwit addresses
## Implements BIP-173 (Bech32) and BIP-350 (Bech32m)

import std/strutils

const
  Bech32Charset* = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  BECH32_CONST* = 1'u32
  BECH32M_CONST* = 0x2bc830a3'u32

type
  Bech32Encoding* = enum
    bech32Classic  # BIP-173, witness v0
    bech32m        # BIP-350, witness v1+

  Bech32Error* = object of CatchableError

# Reverse lookup table for decoding
const Bech32Map: array[128, int8] = block:
  var result: array[128, int8]
  for i in 0 ..< 128:
    result[i] = -1
  for i, c in Bech32Charset:
    result[ord(c)] = int8(i)
    # Also map uppercase
    if c >= 'a' and c <= 'z':
      result[ord(c) - ord('a') + ord('A')] = int8(i)
  result

proc bech32Polymod*(values: openArray[int]): uint32 =
  ## Compute Bech32 checksum polymod
  const GEN = [0x3b6a57b2'u32, 0x26508e6d'u32, 0x1ea119fa'u32, 0x3d4233dd'u32, 0x2a1462b3'u32]
  var chk: uint32 = 1
  for v in values:
    let top = chk shr 25
    chk = ((chk and 0x1ffffff) shl 5) xor uint32(v)
    for i in 0 ..< 5:
      if ((top shr i) and 1) != 0:
        chk = chk xor GEN[i]
  result = chk

proc hrpExpand(hrp: string): seq[int] =
  ## Expand human-readable part for checksum computation
  result = newSeq[int](hrp.len * 2 + 1)
  for i, c in hrp:
    result[i] = ord(c) shr 5
  result[hrp.len] = 0
  for i, c in hrp:
    result[hrp.len + 1 + i] = ord(c) and 31

proc bech32CreateChecksum(hrp: string, data: seq[int], enc: Bech32Encoding): seq[int] =
  ## Create 6-character checksum
  let constant = if enc == bech32Classic: BECH32_CONST else: BECH32M_CONST
  var values = hrpExpand(hrp)
  values.add(data)
  for _ in 0 ..< 6:
    values.add(0)
  let polymod = bech32Polymod(values) xor constant
  result = newSeq[int](6)
  for i in 0 ..< 6:
    result[i] = int((polymod shr (5 * (5 - i))) and 31)

proc bech32VerifyChecksum(hrp: string, data: seq[int]): Bech32Encoding =
  ## Verify checksum and return encoding type
  var values = hrpExpand(hrp)
  values.add(data)
  let polymod = bech32Polymod(values)
  if polymod == BECH32_CONST:
    return bech32Classic
  elif polymod == BECH32M_CONST:
    return bech32m
  else:
    raise newException(Bech32Error, "invalid bech32 checksum")

proc bech32Encode*(hrp: string, data: seq[int], enc: Bech32Encoding): string =
  ## Encode HRP and 5-bit data values to Bech32/Bech32m string
  let checksum = bech32CreateChecksum(hrp, data, enc)
  var combined = data
  combined.add(checksum)

  result = hrp & "1"
  for d in combined:
    result.add(Bech32Charset[d])

proc bech32Decode*(s: string): tuple[hrp: string, data: seq[int], enc: Bech32Encoding] =
  ## Decode Bech32/Bech32m string to HRP and 5-bit data values
  ## Returns data WITHOUT checksum
  if s.len < 8:
    raise newException(Bech32Error, "bech32 string too short")

  # Check for mixed case
  var hasLower, hasUpper = false
  for c in s:
    if c >= 'a' and c <= 'z': hasLower = true
    if c >= 'A' and c <= 'Z': hasUpper = true
  if hasLower and hasUpper:
    raise newException(Bech32Error, "bech32 string has mixed case")

  # Convert to lowercase for processing
  let lower = s.toLowerAscii()

  # Find separator
  var sepPos = -1
  for i in countdown(lower.len - 1, 0):
    if lower[i] == '1':
      sepPos = i
      break

  if sepPos < 1 or sepPos + 7 > lower.len:
    raise newException(Bech32Error, "invalid bech32 separator position")

  result.hrp = lower[0 ..< sepPos]

  # Validate HRP characters
  for c in result.hrp:
    if ord(c) < 33 or ord(c) > 126:
      raise newException(Bech32Error, "invalid bech32 HRP character")

  # Decode data part
  result.data = newSeq[int](lower.len - sepPos - 1)
  for i in (sepPos + 1) ..< lower.len:
    let c = lower[i]
    if ord(c) >= 128 or Bech32Map[ord(c)] < 0:
      raise newException(Bech32Error, "invalid bech32 data character: " & c)
    result.data[i - sepPos - 1] = Bech32Map[ord(c)]

  # Verify checksum and determine encoding
  result.enc = bech32VerifyChecksum(result.hrp, result.data)

  # Remove checksum from data
  result.data = result.data[0 ..< result.data.len - 6]

proc convertBits*(data: openArray[int], fromBits, toBits: int, pad: bool): seq[int] =
  ## Convert between bit groups (e.g., 8-bit to 5-bit)
  var acc = 0
  var bits = 0
  let maxv = (1 shl toBits) - 1
  let maxAcc = (1 shl (fromBits + toBits - 1)) - 1

  result = @[]
  for value in data:
    if value < 0 or value >= (1 shl fromBits):
      raise newException(Bech32Error, "invalid value for bit conversion")
    acc = ((acc shl fromBits) or value) and maxAcc
    bits += fromBits
    while bits >= toBits:
      bits -= toBits
      result.add((acc shr bits) and maxv)

  if pad:
    if bits > 0:
      result.add((acc shl (toBits - bits)) and maxv)
  elif bits >= fromBits:
    raise newException(Bech32Error, "non-zero padding bits")
  elif ((acc shl (toBits - bits)) and maxv) != 0:
    raise newException(Bech32Error, "non-zero padding bits")
