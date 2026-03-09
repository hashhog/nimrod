## Base58 and Base58Check encoding for Bitcoin addresses
## Used for legacy P2PKH and P2SH addresses

import ../crypto/hashing

const Base58Alphabet* = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Reverse lookup table for decoding
const Base58Map: array[256, int8] = block:
  var result: array[256, int8]
  for i in 0 ..< 256:
    result[i] = -1
  for i, c in Base58Alphabet:
    result[ord(c)] = int8(i)
  result

type Base58Error* = object of CatchableError

proc base58Encode*(data: openArray[byte]): string =
  ## Encode bytes to Base58 string
  ## Preserves leading zero bytes as '1' characters
  if data.len == 0:
    return ""

  # Count leading zeros
  var zeros = 0
  for b in data:
    if b == 0:
      inc zeros
    else:
      break

  # Allocate enough space for base58 encoding (log(256)/log(58) ≈ 1.37)
  let size = (data.len) * 138 div 100 + 1
  var b58 = newSeq[int](size)
  var length = 0

  # Process the bytes
  for i in 0 ..< data.len:
    var carry = int(data[i])
    var j = 0
    # Apply "b58 = b58 * 256 + carry"
    while j < length or carry != 0:
      if j < length:
        carry += 256 * b58[j]
      b58[j] = carry mod 58
      carry = carry div 58
      inc j
    length = j

  # Skip leading zeros in b58 (they're at the end because it's reversed)
  # and reverse the array
  result = newString(zeros + length)
  for i in 0 ..< zeros:
    result[i] = '1'
  for i in 0 ..< length:
    result[zeros + i] = Base58Alphabet[b58[length - 1 - i]]

proc base58Decode*(s: string): seq[byte] =
  ## Decode Base58 string to bytes
  ## Returns empty seq on invalid input
  if s.len == 0:
    return @[]

  # Count leading '1's (representing zero bytes)
  var zeros = 0
  for c in s:
    if c == '1':
      inc zeros
    else:
      break

  # Allocate enough space for decoding (log(58)/log(256) ≈ 0.73)
  let size = s.len * 733 div 1000 + 1
  var b256 = newSeq[int](size)
  var length = 0

  # Process the characters
  for i in 0 ..< s.len:
    let c = ord(s[i])
    if c >= 256 or Base58Map[c] < 0:
      raise newException(Base58Error, "invalid base58 character: " & s[i])

    var carry = int(Base58Map[c])
    var j = 0
    # Apply "b256 = b256 * 58 + carry"
    while j < length or carry != 0:
      if j < length:
        carry += 58 * b256[j]
      b256[j] = carry mod 256
      carry = carry div 256
      inc j
    length = j

  # Build result (reverse the array)
  result = newSeq[byte](zeros + length)
  for i in 0 ..< zeros:
    result[i] = 0
  for i in 0 ..< length:
    result[zeros + i] = byte(b256[length - 1 - i])

proc base58CheckEncode*(payload: openArray[byte]): string =
  ## Encode with Base58Check (appends 4-byte double-SHA256 checksum)
  var data = newSeq[byte](payload.len + 4)
  for i, b in payload:
    data[i] = b

  # Compute checksum (first 4 bytes of double SHA256)
  let checksum = doubleSha256(payload)
  data[payload.len] = checksum[0]
  data[payload.len + 1] = checksum[1]
  data[payload.len + 2] = checksum[2]
  data[payload.len + 3] = checksum[3]

  base58Encode(data)

proc base58CheckDecode*(s: string): seq[byte] =
  ## Decode Base58Check string, verifying checksum
  ## Returns payload (without checksum) or raises on invalid checksum
  let data = base58Decode(s)
  if data.len < 4:
    raise newException(Base58Error, "base58check data too short")

  let payload = data[0 ..< data.len - 4]
  let givenChecksum = data[data.len - 4 .. data.len - 1]

  # Verify checksum
  let computed = doubleSha256(payload)
  if givenChecksum[0] != computed[0] or
     givenChecksum[1] != computed[1] or
     givenChecksum[2] != computed[2] or
     givenChecksum[3] != computed[3]:
    raise newException(Base58Error, "invalid base58check checksum")

  result = payload
