## SipHash-2-4 implementation for compact block filters (BIP 158)
## Used to hash scriptPubKeys into range [0, N*M) for GCS encoding
##
## Reference: https://131002.net/siphash/
## Reference: Bitcoin Core /src/crypto/siphash.cpp

type
  SipHasher* = object
    ## SipHash-2-4 state with 128-bit key
    v0, v1, v2, v3: uint64
    tmp: uint64
    count: int

const
  C0 = 0x736f6d6570736575'u64
  C1 = 0x646f72616e646f6d'u64
  C2 = 0x6c7967656e657261'u64
  C3 = 0x7465646279746573'u64

proc rotl(x: uint64, b: int): uint64 {.inline.} =
  (x shl b) or (x shr (64 - b))

proc sipRound(v0, v1, v2, v3: var uint64) {.inline.} =
  v0 += v1
  v1 = rotl(v1, 13)
  v1 = v1 xor v0
  v0 = rotl(v0, 32)

  v2 += v3
  v3 = rotl(v3, 16)
  v3 = v3 xor v2

  v0 += v3
  v3 = rotl(v3, 21)
  v3 = v3 xor v0

  v2 += v1
  v1 = rotl(v1, 17)
  v1 = v1 xor v2
  v2 = rotl(v2, 32)

proc newSipHasher*(k0, k1: uint64): SipHasher =
  ## Create a new SipHasher with 128-bit key (k0, k1)
  result.v0 = C0 xor k0
  result.v1 = C1 xor k1
  result.v2 = C2 xor k0
  result.v3 = C3 xor k1
  result.tmp = 0
  result.count = 0

proc writeWord(h: var SipHasher, data: uint64) =
  ## Process a single 64-bit word
  h.v3 = h.v3 xor data
  sipRound(h.v0, h.v1, h.v2, h.v3)
  sipRound(h.v0, h.v1, h.v2, h.v3)
  h.v0 = h.v0 xor data

proc write*(h: var SipHasher, data: uint64) =
  ## Write a 64-bit integer (little-endian)
  h.writeWord(data)
  h.count += 8

proc write*(h: var SipHasher, data: openArray[byte]) =
  ## Write arbitrary bytes
  var pos = 0
  let len = data.len

  # If we have leftover bytes from previous write, try to complete a word
  let inTmp = h.count and 7
  if inTmp > 0:
    let needed = 8 - inTmp
    if len >= needed:
      # Complete the word
      for i in 0 ..< needed:
        h.tmp = h.tmp or (uint64(data[i]) shl ((inTmp + i) * 8))
      h.writeWord(h.tmp)
      h.tmp = 0
      pos = needed
      h.count += needed
    else:
      # Not enough to complete, just accumulate
      for i in 0 ..< len:
        h.tmp = h.tmp or (uint64(data[i]) shl ((inTmp + i) * 8))
      h.count += len
      return

  # Process full 8-byte words
  while pos + 8 <= len:
    var word: uint64 = 0
    for i in 0 ..< 8:
      word = word or (uint64(data[pos + i]) shl (i * 8))
    h.writeWord(word)
    pos += 8
    h.count += 8

  # Accumulate remaining bytes
  for i in pos ..< len:
    h.tmp = h.tmp or (uint64(data[i]) shl ((i - pos) * 8))
    h.count += 1

proc finalize*(h: var SipHasher): uint64 =
  ## Finalize and return the 64-bit hash
  # Add length byte and any remaining data
  let inTmp = h.count and 7
  var finalWord = h.tmp or (uint64(h.count and 0xff) shl 56)
  h.writeWord(finalWord)

  # Two more rounds (finalization)
  h.v2 = h.v2 xor 0xff
  sipRound(h.v0, h.v1, h.v2, h.v3)
  sipRound(h.v0, h.v1, h.v2, h.v3)
  sipRound(h.v0, h.v1, h.v2, h.v3)
  sipRound(h.v0, h.v1, h.v2, h.v3)

  result = h.v0 xor h.v1 xor h.v2 xor h.v3

proc sipHash*(k0, k1: uint64, data: openArray[byte]): uint64 =
  ## Convenience function: compute SipHash-2-4 in one call
  var h = newSipHasher(k0, k1)
  h.write(data)
  h.finalize()

proc sipHash*(k0, k1: uint64, data: uint64): uint64 =
  ## Hash a single 64-bit value
  var h = newSipHasher(k0, k1)
  h.write(data)
  h.finalize()

# ============================================================================
# FastRange64 - map hash to range [0, n)
# ============================================================================

proc fastRange64*(hash: uint64, n: uint64): uint64 =
  ## Map a 64-bit hash to range [0, n) using multiplication
  ## This is more efficient than modulo and has good distribution
  ## Reference: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  ##
  ## Computes (hash * n) >> 64, which maps uniformly to [0, n)
  when defined(gcc) or defined(clang):
    # Use 128-bit multiply when available
    {.emit: """
    unsigned __int128 full = (unsigned __int128)`hash` * (unsigned __int128)`n`;
    `result` = (uint64_t)(full >> 64);
    """.}
  else:
    # Fallback: split into 32-bit parts
    let lo1 = hash and 0xFFFFFFFF'u64
    let hi1 = hash shr 32
    let lo2 = n and 0xFFFFFFFF'u64
    let hi2 = n shr 32

    # Partial products
    let a = lo1 * lo2
    let b = lo1 * hi2
    let c = hi1 * lo2
    let d = hi1 * hi2

    # Add partial products with carry
    let carry = ((a shr 32) + (b and 0xFFFFFFFF) + (c and 0xFFFFFFFF)) shr 32
    result = d + (b shr 32) + (c shr 32) + carry
