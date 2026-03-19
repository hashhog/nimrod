## ChaCha20-Poly1305 AEAD cipher for BIP-324
##
## Implements RFC 8439 AEAD_CHACHA20_POLY1305 and the forward-secure
## variants FSChaCha20 and FSChaCha20Poly1305 used in BIP-324.
##
## Reference: Bitcoin Core crypto/chacha20poly1305.cpp

import std/endians

const
  ChaCha20BlockSize* = 64
  ChaCha20KeySize* = 32
  ChaCha20NonceSize* = 12
  Poly1305KeySize* = 32
  Poly1305TagSize* = 16
  AEADExpansion* = Poly1305TagSize

type
  ChaCha20State = array[16, uint32]

  ChaCha20* = object
    ## ChaCha20 stream cipher (RFC 8439)
    state: ChaCha20State
    keystream: array[ChaCha20BlockSize, byte]
    position: int  # Position within current block

  Poly1305* = object
    ## Poly1305 MAC (RFC 8439)
    r: array[5, uint32]  # Key r (clamped)
    h: array[5, uint32]  # Accumulator
    pad: array[4, uint32]  # Key s
    buffer: array[16, byte]
    bufferLen: int

  AEADChaCha20Poly1305* = object
    ## AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)
    chacha20: ChaCha20

  FSChaCha20* = object
    ## Forward-secure ChaCha20 for BIP-324 length encryption
    ## Rekeys every rekeyInterval messages
    chacha20: ChaCha20
    rekeyInterval: uint32
    packetCounter: uint32
    rekeyCounter: uint64

  FSChaCha20Poly1305* = object
    ## Forward-secure ChaCha20-Poly1305 AEAD for BIP-324
    ## Rekeys every rekeyInterval messages
    aead: AEADChaCha20Poly1305
    rekeyInterval: uint32
    packetCounter: uint32
    rekeyCounter: uint64

# ==========================================================================
# ChaCha20 implementation
# ==========================================================================

proc rotl32(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

proc quarterRound(a, b, c, d: var uint32) {.inline.} =
  a = a + b; d = d xor a; d = rotl32(d, 16)
  c = c + d; b = b xor c; b = rotl32(b, 12)
  a = a + b; d = d xor a; d = rotl32(d, 8)
  c = c + d; b = b xor c; b = rotl32(b, 7)

proc chachaBlock(state: var ChaCha20State, output: var array[64, byte]) =
  ## Generate one 64-byte block of keystream
  var working = state

  # 20 rounds (10 double-rounds)
  for _ in 0..<10:
    # Column rounds
    quarterRound(working[0], working[4], working[8], working[12])
    quarterRound(working[1], working[5], working[9], working[13])
    quarterRound(working[2], working[6], working[10], working[14])
    quarterRound(working[3], working[7], working[11], working[15])
    # Diagonal rounds
    quarterRound(working[0], working[5], working[10], working[15])
    quarterRound(working[1], working[6], working[11], working[12])
    quarterRound(working[2], working[7], working[8], working[13])
    quarterRound(working[3], working[4], working[9], working[14])

  # Add working state to original state and serialize
  for i in 0..<16:
    let word = working[i] + state[i]
    littleEndian32(addr output[i * 4], unsafeAddr word)

  # Increment counter
  state[12] += 1
  if state[12] == 0:
    state[13] += 1

proc initChaCha20*(key: openArray[byte]): ChaCha20 =
  ## Initialize ChaCha20 with a 32-byte key
  assert key.len == ChaCha20KeySize

  # Constants "expand 32-byte k"
  result.state[0] = 0x61707865'u32
  result.state[1] = 0x3320646e'u32
  result.state[2] = 0x79622d32'u32
  result.state[3] = 0x6b206574'u32

  # Key
  for i in 0..<8:
    var word: uint32
    littleEndian32(addr word, unsafeAddr key[i * 4])
    result.state[4 + i] = word

  # Counter and nonce (initialized to zero)
  result.state[12] = 0
  result.state[13] = 0
  result.state[14] = 0
  result.state[15] = 0

  result.position = ChaCha20BlockSize  # Force block generation on first use

proc setKey*(c: var ChaCha20, key: openArray[byte]) =
  ## Set a new key
  assert key.len == ChaCha20KeySize
  for i in 0..<8:
    var word: uint32
    littleEndian32(addr word, unsafeAddr key[i * 4])
    c.state[4 + i] = word

proc seek*(c: var ChaCha20, nonce: array[12, byte], counter: uint32) =
  ## Seek to a specific position (nonce + block counter)
  c.state[12] = counter

  var word: uint32
  littleEndian32(addr word, unsafeAddr nonce[0])
  c.state[13] = word
  littleEndian32(addr word, unsafeAddr nonce[4])
  c.state[14] = word
  littleEndian32(addr word, unsafeAddr nonce[8])
  c.state[15] = word

  c.position = ChaCha20BlockSize  # Force block generation

proc seek96*(c: var ChaCha20, packetCounter: uint32, rekeyCounter: uint64) =
  ## Seek using BIP-324 style nonce (packet counter + rekey counter)
  ## Nonce = packetCounter (4 bytes LE) || rekeyCounter (8 bytes LE)
  var nonce: array[12, byte]
  littleEndian32(addr nonce[0], unsafeAddr packetCounter)
  littleEndian64(addr nonce[4], unsafeAddr rekeyCounter)
  c.seek(nonce, 0)

proc keystream*(c: var ChaCha20, output: var openArray[byte]) =
  ## Generate keystream bytes
  var pos = 0
  while pos < output.len:
    if c.position >= ChaCha20BlockSize:
      chachaBlock(c.state, c.keystream)
      c.position = 0

    let available = min(ChaCha20BlockSize - c.position, output.len - pos)
    for i in 0..<available:
      output[pos + i] = c.keystream[c.position + i]
    pos += available
    c.position += available

proc crypt*(c: var ChaCha20, input: openArray[byte], output: var openArray[byte]) =
  ## Encrypt or decrypt data (XOR with keystream)
  assert input.len == output.len
  var pos = 0
  while pos < input.len:
    if c.position >= ChaCha20BlockSize:
      chachaBlock(c.state, c.keystream)
      c.position = 0

    let available = min(ChaCha20BlockSize - c.position, input.len - pos)
    for i in 0..<available:
      output[pos + i] = input[pos + i] xor c.keystream[c.position + i]
    pos += available
    c.position += available

# ==========================================================================
# Poly1305 implementation
# ==========================================================================

proc clamp(r: var array[16, byte]) =
  ## Clamp r per RFC 8439
  r[3] = r[3] and 0x0f
  r[7] = r[7] and 0x0f
  r[11] = r[11] and 0x0f
  r[15] = r[15] and 0x0f
  r[4] = r[4] and 0xfc
  r[8] = r[8] and 0xfc
  r[12] = r[12] and 0xfc

proc initPoly1305*(key: openArray[byte]): Poly1305 =
  ## Initialize Poly1305 with a 32-byte one-time key
  assert key.len == Poly1305KeySize

  # r = first 16 bytes (clamped)
  var r: array[16, byte]
  for i in 0..<16:
    r[i] = key[i]
  clamp(r)

  # Load r as 5 26-bit limbs
  result.r[0] = (uint32(r[0]) or (uint32(r[1]) shl 8) or (uint32(r[2]) shl 16) or (uint32(r[3]) shl 24)) and 0x3ffffff
  result.r[1] = ((uint32(r[3]) shr 2) or (uint32(r[4]) shl 6) or (uint32(r[5]) shl 14) or (uint32(r[6]) shl 22)) and 0x3ffffff
  result.r[2] = ((uint32(r[6]) shr 4) or (uint32(r[7]) shl 4) or (uint32(r[8]) shl 12) or (uint32(r[9]) shl 20)) and 0x3ffffff
  result.r[3] = ((uint32(r[9]) shr 6) or (uint32(r[10]) shl 2) or (uint32(r[11]) shl 10) or (uint32(r[12]) shl 18)) and 0x3ffffff
  result.r[4] = ((uint32(r[12]) shr 8) or (uint32(r[13]) shl 0) or (uint32(r[14]) shl 8) or (uint32(r[15]) shl 16)) and 0x3ffffff

  # s = last 16 bytes
  var word: uint32
  littleEndian32(addr word, unsafeAddr key[16])
  result.pad[0] = word
  littleEndian32(addr word, unsafeAddr key[20])
  result.pad[1] = word
  littleEndian32(addr word, unsafeAddr key[24])
  result.pad[2] = word
  littleEndian32(addr word, unsafeAddr key[28])
  result.pad[3] = word

  # Initialize accumulator
  for i in 0..<5:
    result.h[i] = 0

  result.bufferLen = 0

proc processBlock(p: var Poly1305, data: openArray[byte], hibit: uint32) =
  ## Process a 16-byte block
  # Load block as 5 26-bit limbs
  var h0 = p.h[0] + ((uint32(data[0]) or (uint32(data[1]) shl 8) or (uint32(data[2]) shl 16) or (uint32(data[3]) shl 24)) and 0x3ffffff)
  var h1 = p.h[1] + (((uint32(data[3]) shr 2) or (uint32(data[4]) shl 6) or (uint32(data[5]) shl 14) or (uint32(data[6]) shl 22)) and 0x3ffffff)
  var h2 = p.h[2] + (((uint32(data[6]) shr 4) or (uint32(data[7]) shl 4) or (uint32(data[8]) shl 12) or (uint32(data[9]) shl 20)) and 0x3ffffff)
  var h3 = p.h[3] + (((uint32(data[9]) shr 6) or (uint32(data[10]) shl 2) or (uint32(data[11]) shl 10) or (uint32(data[12]) shl 18)) and 0x3ffffff)
  var h4 = p.h[4] + (((uint32(data[12]) shr 8) or (uint32(data[13]) shl 0) or (uint32(data[14]) shl 8) or (uint32(data[15]) shl 16)) and 0x3ffffff) + (hibit shl 24)

  # Multiply by r
  let r0 = p.r[0]
  let r1 = p.r[1]
  let r2 = p.r[2]
  let r3 = p.r[3]
  let r4 = p.r[4]

  let s1 = r1 * 5
  let s2 = r2 * 5
  let s3 = r3 * 5
  let s4 = r4 * 5

  var d0 = uint64(h0) * uint64(r0) + uint64(h1) * uint64(s4) + uint64(h2) * uint64(s3) + uint64(h3) * uint64(s2) + uint64(h4) * uint64(s1)
  var d1 = uint64(h0) * uint64(r1) + uint64(h1) * uint64(r0) + uint64(h2) * uint64(s4) + uint64(h3) * uint64(s3) + uint64(h4) * uint64(s2)
  var d2 = uint64(h0) * uint64(r2) + uint64(h1) * uint64(r1) + uint64(h2) * uint64(r0) + uint64(h3) * uint64(s4) + uint64(h4) * uint64(s3)
  var d3 = uint64(h0) * uint64(r3) + uint64(h1) * uint64(r2) + uint64(h2) * uint64(r1) + uint64(h3) * uint64(r0) + uint64(h4) * uint64(s4)
  var d4 = uint64(h0) * uint64(r4) + uint64(h1) * uint64(r3) + uint64(h2) * uint64(r2) + uint64(h3) * uint64(r1) + uint64(h4) * uint64(r0)

  # Partial reduction mod 2^130 - 5
  var c = d0 shr 26; h0 = uint32(d0) and 0x3ffffff
  d1 += c; c = d1 shr 26; h1 = uint32(d1) and 0x3ffffff
  d2 += c; c = d2 shr 26; h2 = uint32(d2) and 0x3ffffff
  d3 += c; c = d3 shr 26; h3 = uint32(d3) and 0x3ffffff
  d4 += c; c = d4 shr 26; h4 = uint32(d4) and 0x3ffffff
  h0 += uint32(c) * 5; c = uint64(h0 shr 26); h0 = h0 and 0x3ffffff
  h1 += uint32(c)

  p.h[0] = h0
  p.h[1] = h1
  p.h[2] = h2
  p.h[3] = h3
  p.h[4] = h4

proc update*(p: var Poly1305, data: openArray[byte]) =
  ## Update with additional data
  var pos = 0

  # Process buffered data first
  if p.bufferLen > 0:
    let need = min(16 - p.bufferLen, data.len)
    for i in 0..<need:
      p.buffer[p.bufferLen + i] = data[i]
    p.bufferLen += need
    pos = need

    if p.bufferLen == 16:
      p.processBlock(p.buffer, 1)
      p.bufferLen = 0

  # Process full blocks
  while pos + 16 <= data.len:
    var blk: array[16, byte]
    for i in 0..<16:
      blk[i] = data[pos + i]
    p.processBlock(blk, 1)
    pos += 16

  # Buffer remaining data
  while pos < data.len:
    p.buffer[p.bufferLen] = data[pos]
    inc p.bufferLen
    inc pos

proc finalize*(p: var Poly1305, tag: var array[16, byte]) =
  ## Finalize and output the 16-byte tag
  # Process final block if any
  if p.bufferLen > 0:
    var final: array[16, byte]
    for i in 0..<p.bufferLen:
      final[i] = p.buffer[i]
    final[p.bufferLen] = 0x01
    for i in (p.bufferLen + 1)..<16:
      final[i] = 0
    p.processBlock(final, 0)

  # Full carry chain
  var h0 = p.h[0]
  var h1 = p.h[1]
  var h2 = p.h[2]
  var h3 = p.h[3]
  var h4 = p.h[4]

  var c = h1 shr 26; h1 = h1 and 0x3ffffff
  h2 += c; c = h2 shr 26; h2 = h2 and 0x3ffffff
  h3 += c; c = h3 shr 26; h3 = h3 and 0x3ffffff
  h4 += c; c = h4 shr 26; h4 = h4 and 0x3ffffff
  h0 += c * 5; c = h0 shr 26; h0 = h0 and 0x3ffffff
  h1 += c

  # Compute h + -p
  var g0 = h0 + 5; c = g0 shr 26; g0 = g0 and 0x3ffffff
  var g1 = h1 + c; c = g1 shr 26; g1 = g1 and 0x3ffffff
  var g2 = h2 + c; c = g2 shr 26; g2 = g2 and 0x3ffffff
  var g3 = h3 + c; c = g3 shr 26; g3 = g3 and 0x3ffffff
  var g4 = h4 + c - (1'u32 shl 26)

  # Select h if h < p, else h - p
  let mask = (g4 shr 31) - 1
  g0 = g0 and mask
  g1 = g1 and mask
  g2 = g2 and mask
  g3 = g3 and mask
  g4 = g4 and mask
  let notMask = not mask
  h0 = (h0 and notMask) or g0
  h1 = (h1 and notMask) or g1
  h2 = (h2 and notMask) or g2
  h3 = (h3 and notMask) or g3
  h4 = (h4 and notMask) or g4

  # Compute h + pad
  var f0 = uint64(h0 or (h1 shl 26)) + uint64(p.pad[0])
  var f1 = uint64((h1 shr 6) or (h2 shl 20)) + uint64(p.pad[1])
  var f2 = uint64((h2 shr 12) or (h3 shl 14)) + uint64(p.pad[2])
  var f3 = uint64((h3 shr 18) or (h4 shl 8)) + uint64(p.pad[3])

  f1 += f0 shr 32
  f2 += f1 shr 32
  f3 += f2 shr 32

  let h0out = uint32(f0)
  let h1out = uint32(f1)
  let h2out = uint32(f2)
  let h3out = uint32(f3)

  littleEndian32(addr tag[0], unsafeAddr h0out)
  littleEndian32(addr tag[4], unsafeAddr h1out)
  littleEndian32(addr tag[8], unsafeAddr h2out)
  littleEndian32(addr tag[12], unsafeAddr h3out)

# ==========================================================================
# AEAD_CHACHA20_POLY1305 (RFC 8439)
# ==========================================================================

proc initAEADChaCha20Poly1305*(key: openArray[byte]): AEADChaCha20Poly1305 =
  ## Initialize AEAD with a 32-byte key
  result.chacha20 = initChaCha20(key)

proc setKey*(a: var AEADChaCha20Poly1305, key: openArray[byte]) =
  ## Set a new key
  a.chacha20.setKey(key)

proc computeTag(a: var AEADChaCha20Poly1305, nonce: array[12, byte],
                aad: openArray[byte], ciphertext: openArray[byte],
                tag: var array[16, byte]) =
  ## Compute Poly1305 tag
  # Get Poly1305 key from block 0
  a.chacha20.seek(nonce, 0)
  var poly1305Key: array[64, byte]
  a.chacha20.keystream(poly1305Key)

  var poly = initPoly1305(poly1305Key[0..<32])

  # Process AAD with padding
  poly.update(aad)
  let aadPadding = (16 - (aad.len mod 16)) mod 16
  if aadPadding > 0:
    var padding: array[16, byte]
    poly.update(padding[0..<aadPadding])

  # Process ciphertext with padding
  poly.update(ciphertext)
  let ctPadding = (16 - (ciphertext.len mod 16)) mod 16
  if ctPadding > 0:
    var padding: array[16, byte]
    poly.update(padding[0..<ctPadding])

  # Process lengths
  var lengths: array[16, byte]
  var aadLen = uint64(aad.len)
  var ctLen = uint64(ciphertext.len)
  littleEndian64(addr lengths[0], addr aadLen)
  littleEndian64(addr lengths[8], addr ctLen)
  poly.update(lengths)

  poly.finalize(tag)

proc encrypt*(a: var AEADChaCha20Poly1305, nonce: array[12, byte],
              plain: openArray[byte], aad: openArray[byte],
              cipher: var openArray[byte]) =
  ## Encrypt plaintext and produce ciphertext + tag
  ## cipher must be plain.len + 16 bytes
  assert cipher.len == plain.len + AEADExpansion

  # Encrypt starting at block 1
  a.chacha20.seek(nonce, 1)
  var ciphertext = newSeq[byte](plain.len)
  a.chacha20.crypt(plain, ciphertext)

  # Copy ciphertext to output
  for i in 0..<ciphertext.len:
    cipher[i] = ciphertext[i]

  # Compute and append tag
  var tag: array[16, byte]
  a.computeTag(nonce, aad, ciphertext, tag)
  for i in 0..<16:
    cipher[plain.len + i] = tag[i]

proc decrypt*(a: var AEADChaCha20Poly1305, nonce: array[12, byte],
              cipher: openArray[byte], aad: openArray[byte],
              plain: var openArray[byte]): bool =
  ## Decrypt ciphertext and verify tag
  ## Returns false if authentication fails
  assert plain.len + AEADExpansion == cipher.len

  let ciphertextLen = cipher.len - 16

  # Verify tag
  var expectedTag: array[16, byte]
  a.computeTag(nonce, aad, cipher[0..<ciphertextLen], expectedTag)

  # Constant-time comparison
  var diff: byte = 0
  for i in 0..<16:
    diff = diff or (cipher[ciphertextLen + i] xor expectedTag[i])

  if diff != 0:
    return false

  # Decrypt starting at block 1
  a.chacha20.seek(nonce, 1)
  a.chacha20.crypt(cipher[0..<ciphertextLen], plain)

  return true

proc keystream*(a: var AEADChaCha20Poly1305, nonce: array[12, byte],
                output: var openArray[byte]) =
  ## Generate keystream (starting at block 1, skipping Poly1305 key block)
  a.chacha20.seek(nonce, 1)
  a.chacha20.keystream(output)

# ==========================================================================
# FSChaCha20 (Forward-Secure ChaCha20)
# ==========================================================================

proc initFSChaCha20*(key: openArray[byte], rekeyInterval: uint32): FSChaCha20 =
  ## Initialize forward-secure ChaCha20
  result.chacha20 = initChaCha20(key)
  result.rekeyInterval = rekeyInterval
  result.packetCounter = 0
  result.rekeyCounter = 0

proc nextPacket(f: var FSChaCha20) =
  ## Advance to next packet, rekeying if needed
  inc f.packetCounter
  if f.packetCounter == f.rekeyInterval:
    # Generate new key from keystream
    var nonce: array[12, byte]
    littleEndian32(addr nonce[0], unsafeAddr f.rekeyInterval)  # 0xFFFFFFFF trick from Core
    var counter = 0xFFFFFFFF'u32
    littleEndian32(addr nonce[0], addr counter)
    littleEndian64(addr nonce[4], addr f.rekeyCounter)

    f.chacha20.seek(nonce, 0)
    var newKey: array[64, byte]
    f.chacha20.keystream(newKey)

    f.chacha20.setKey(newKey[0..<32])
    f.packetCounter = 0
    inc f.rekeyCounter

proc crypt*(f: var FSChaCha20, input: openArray[byte], output: var openArray[byte]) =
  ## Encrypt/decrypt with forward secrecy
  f.chacha20.seek96(f.packetCounter, f.rekeyCounter)
  f.chacha20.crypt(input, output)
  f.nextPacket()

# ==========================================================================
# FSChaCha20Poly1305 (Forward-Secure AEAD)
# ==========================================================================

proc initFSChaCha20Poly1305*(key: openArray[byte], rekeyInterval: uint32): FSChaCha20Poly1305 =
  ## Initialize forward-secure AEAD
  result.aead = initAEADChaCha20Poly1305(key)
  result.rekeyInterval = rekeyInterval
  result.packetCounter = 0
  result.rekeyCounter = 0

proc nextPacket(f: var FSChaCha20Poly1305) =
  ## Advance to next packet, rekeying if needed
  inc f.packetCounter
  if f.packetCounter == f.rekeyInterval:
    # Generate new key from keystream
    var nonce: array[12, byte]
    var counter = 0xFFFFFFFF'u32
    littleEndian32(addr nonce[0], addr counter)
    littleEndian64(addr nonce[4], addr f.rekeyCounter)

    var newKey: array[64, byte]
    f.aead.keystream(nonce, newKey)

    f.aead.setKey(newKey[0..<32])
    f.packetCounter = 0
    inc f.rekeyCounter

proc encrypt*(f: var FSChaCha20Poly1305, header: byte, contents: openArray[byte],
              aad: openArray[byte], output: var openArray[byte]) =
  ## Encrypt header + contents with AAD
  ## Output must be 1 + contents.len + 16 bytes
  assert output.len == 1 + contents.len + AEADExpansion

  var nonce: array[12, byte]
  littleEndian32(addr nonce[0], addr f.packetCounter)
  littleEndian64(addr nonce[4], addr f.rekeyCounter)

  # Combine header + contents for encryption
  var plain = newSeq[byte](1 + contents.len)
  plain[0] = header
  for i, b in contents:
    plain[1 + i] = b

  f.aead.encrypt(nonce, plain, aad, output)
  f.nextPacket()

proc decrypt*(f: var FSChaCha20Poly1305, cipher: openArray[byte],
              aad: openArray[byte]): tuple[header: byte, contents: seq[byte], ok: bool] =
  ## Decrypt and return header + contents
  ## Returns (0, @[], false) on authentication failure
  if cipher.len < 1 + AEADExpansion:
    return (0'u8, @[], false)

  var nonce: array[12, byte]
  littleEndian32(addr nonce[0], addr f.packetCounter)
  littleEndian64(addr nonce[4], addr f.rekeyCounter)

  var plain = newSeq[byte](cipher.len - AEADExpansion)
  if not f.aead.decrypt(nonce, cipher, aad, plain):
    return (0'u8, @[], false)

  f.nextPacket()

  let header = plain[0]
  var contents = newSeq[byte](plain.len - 1)
  for i in 0..<contents.len:
    contents[i] = plain[1 + i]

  return (header, contents, true)
