## ASMap (Autonomous System Map) interpreter
## Provides a compressed binary-trie mapping from IP address prefixes to ASNs.
##
## Reference: bitcoin-core/src/util/asmap.h/cpp
## Closes W115 G1-G17 (core interpreter + file loading + NetGroupManager).
##
## Encoding summary:
##   - asmap data: LSB-first bit ordering within bytes (little-endian)
##   - IP address: MSB-first bit ordering (big-endian / network byte order)
##   - 4 instructions: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
##   - Variable-length integers for ASNs, jump offsets, and match patterns

import std/[os, strutils]
import chronicles
import ../crypto/hashing

export hashing

const
  MaxAsmapFileSize* = 8_388_608  ## 8 MiB — bitcoin-core/src/init.cpp
  AsmapInvalid* = 0xFFFFFFFF'u32  ## Sentinel for decode errors

# ---------------------------------------------------------------------------
# Internal helpers — bit extraction
# ---------------------------------------------------------------------------

proc consumeBitLE(bitpos: var uint32, data: openArray[byte]): bool {.inline.} =
  ## Extract the next bit from `data` using LSB-first (little-endian) ordering.
  ## This is used for the asmap bytecode stream.
  ## Core: ConsumeBitLE in asmap.cpp
  let b = bitpos
  inc bitpos
  ((data[b shr 3] shr (b and 7)) and 1'u8) != 0

proc consumeBitBE(bitpos: var uint8, data: openArray[byte]): bool {.inline.} =
  ## Extract the next bit from `data` using MSB-first (big-endian) ordering.
  ## This is used for IP address bytes (network byte order).
  ## Core: ConsumeBitBE in asmap.cpp
  let b = bitpos
  inc bitpos
  ((data[b shr 3] shr (7 - (b and 7))) and 1'u8) != 0

# ---------------------------------------------------------------------------
# Variable-length integer decoder
# ---------------------------------------------------------------------------

proc decodeBits(bitpos: var uint32, data: openArray[byte],
                minval: uint32, bitSizes: openArray[uint8]): uint32 =
  ## Generic variable-length integer decoder used by ASN, JUMP, and MATCH.
  ##
  ## Encoding scheme (example minval=100, bitSizes=[4,2,2,3]):
  ##   [100..115]: [0] + 4-bit big-endian (x-100)
  ##   [116..119]: [1,0] + 2-bit big-endian (x-116)
  ##   [120..123]: [1,1,0] + 2-bit big-endian (x-120)
  ##   [124..131]: [1,1,1] + 3-bit big-endian (x-124)
  ##
  ## Reference: bitcoin-core/src/util/asmap.cpp:87 DecodeBits()
  let endBit = uint32(data.len) * 8
  var val = minval
  for i, bs in bitSizes:
    # Read continuation bit unless this is the last class
    let bit: bool =
      if i + 1 < bitSizes.len:
        if bitpos >= endBit: return AsmapInvalid
        consumeBitLE(bitpos, data)
      else:
        false
    if bit:
      # Not this class — add size of this class and try next
      val += (1'u32 shl bs)
    else:
      # Decode position within this class (big-endian within the class)
      for b in 0 ..< int(bs):
        if bitpos >= endBit: return AsmapInvalid
        let ipBit = consumeBitLE(bitpos, data)
        if ipBit:
          val += (1'u32 shl (int(bs) - 1 - b))
      return val
  AsmapInvalid  # Ran out of classes

# Encoding tables — must match Bitcoin Core exactly
const
  # Instruction type: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
  TypeBitSizes:  array[3, uint8] = [0'u8, 0'u8, 1'u8]
  # ASN: minval=1, values from 1 to ~16.7M
  AsnBitSizes:   array[10, uint8] = [15'u8, 16, 17, 18, 19, 20, 21, 22, 23, 24]
  # MATCH argument: values in [2, 511]; highest set bit = match length
  MatchBitSizes: array[8, uint8]  = [1'u8, 2, 3, 4, 5, 6, 7, 8]
  # JUMP offset: minimum 17; can be large
  JumpBitSizes:  array[26, uint8] = [5'u8, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                                     27, 28, 29, 30]

proc decodeType(bitpos: var uint32, data: openArray[byte]): uint32 =
  decodeBits(bitpos, data, 0, TypeBitSizes)

proc decodeAsn(bitpos: var uint32, data: openArray[byte]): uint32 =
  decodeBits(bitpos, data, 1, AsnBitSizes)

proc decodeMatch(bitpos: var uint32, data: openArray[byte]): uint32 =
  decodeBits(bitpos, data, 2, MatchBitSizes)

proc decodeJump(bitpos: var uint32, data: openArray[byte]): uint32 =
  decodeBits(bitpos, data, 17, JumpBitSizes)

# ---------------------------------------------------------------------------
# Instruction constants
# ---------------------------------------------------------------------------

const
  InstructionReturn*  = 0'u32   ## [0]
  InstructionJump*    = 1'u32   ## [1,0]
  InstructionMatch*   = 2'u32   ## [1,1,0]
  InstructionDefault* = 3'u32   ## [1,1,1]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc interpret*(asmap: openArray[byte], ip: array[16, byte]): uint32 =
  ## Execute the ASMap bytecode to find the ASN for `ip`.
  ##
  ## `asmap` encodes a binary trie (LSB-first within bytes).
  ## `ip` is a 16-byte IPv6 address (big-endian; IPv4 must be in
  ##   ::ffff:a.b.c.d mapped form, occupying bytes 12-15).
  ##
  ## Returns the matched ASN (>0), or 0 if no match / error.
  ## Reference: bitcoin-core/src/util/asmap.cpp:182 Interpret()
  if asmap.len == 0:
    return 0

  var pos: uint32 = 0
  let endPos = uint32(asmap.len) * 8
  var ipBit: uint8 = 0
  let ipBitsEnd = uint8(ip.len * 8)  # 128 for IPv6
  var defaultAsn: uint32 = 0

  while pos < endPos:
    let opcode = decodeType(pos, asmap)

    if opcode == InstructionReturn:
      let asn = decodeAsn(pos, asmap)
      if asn == AsmapInvalid: break
      return asn

    elif opcode == InstructionJump:
      let jump = decodeJump(pos, asmap)
      if jump == AsmapInvalid: break
      if ipBit == ipBitsEnd: break
      if uint64(jump) >= uint64(endPos - pos): break
      if consumeBitBE(ipBit, ip):
        pos += jump   # bit=1: skip to right subtree
      # bit=0: fall through to left subtree

    elif opcode == InstructionMatch:
      let match = decodeMatch(pos, asmap)
      if match == AsmapInvalid: break
      # matchlen = position of highest set bit - 1
      # bit_width(match) = floor(log2(match)) + 1
      var matchlen: int = 0
      var tmp = match shr 1
      while tmp != 0:
        inc matchlen
        tmp = tmp shr 1
      if int(ipBitsEnd - ipBit) < matchlen: break
      var mismatch = false
      for b in 0 ..< matchlen:
        if consumeBitBE(ipBit, ip) != (((match shr (matchlen - 1 - b)) and 1) != 0):
          mismatch = true
          break
      if mismatch:
        return defaultAsn   # pattern mismatch — use current default

    elif opcode == InstructionDefault:
      let asn = decodeAsn(pos, asmap)
      if asn == AsmapInvalid: break
      defaultAsn = asn

    else:
      break   # Instruction straddles EOF

  # Reached EOF without RETURN or aborted — should not happen on sane asmap
  0

proc sanityCheckAsmap*(asmap: openArray[byte], bits: int): bool =
  ## Validate asmap structure by simulating all possible execution paths.
  ## `bits` is the number of IP address bits (128 for IPv6, 32 for IPv4).
  ## Returns true iff the bytecode is well-formed.
  ## Reference: bitcoin-core/src/util/asmap.cpp:239 SanityCheckAsmap()
  var pos: uint32 = 0
  let endPos = uint32(asmap.len) * 8
  var jumps: seq[tuple[offset: uint32, bitsLeft: int]]  # pending jump targets
  var prevOpcode: uint32 = InstructionJump  # matches Core's initial prevopcode
  var hadIncompleteMatch = false
  var bitsLeft = bits

  while pos != endPos:
    # No jump target should fall inside the previous instruction
    if jumps.len > 0 and pos >= jumps[^1].offset:
      return false

    let opcode = decodeType(pos, asmap)

    if opcode == InstructionReturn:
      if prevOpcode == InstructionDefault: return false
      let asn = decodeAsn(pos, asmap)
      if asn == AsmapInvalid: return false
      if jumps.len == 0:
        # Must be at EOF with at most 7 zero-padding bits
        if endPos - pos > 7: return false
        while pos != endPos:
          if consumeBitLE(pos, asmap): return false
        return true
      else:
        # Must land exactly at the queued jump target
        if pos != jumps[^1].offset: return false
        bitsLeft = jumps[^1].bitsLeft
        jumps.setLen(jumps.len - 1)
        prevOpcode = InstructionJump

    elif opcode == InstructionJump:
      let jump = decodeJump(pos, asmap)
      if jump == AsmapInvalid: return false
      if int64(jump) > int64(endPos - pos): return false
      if bitsLeft == 0: return false
      dec bitsLeft
      let target = pos + jump
      if jumps.len > 0 and target >= jumps[^1].offset: return false
      jumps.add((target, bitsLeft))
      prevOpcode = InstructionJump

    elif opcode == InstructionMatch:
      let match = decodeMatch(pos, asmap)
      if match == AsmapInvalid: return false
      var matchlen: int = 0
      var tmp = match shr 1
      while tmp != 0:
        inc matchlen
        tmp = tmp shr 1
      if prevOpcode != InstructionMatch: hadIncompleteMatch = false
      if matchlen < 8 and hadIncompleteMatch: return false
      hadIncompleteMatch = (matchlen < 8)
      if bitsLeft < matchlen: return false
      bitsLeft -= matchlen
      prevOpcode = InstructionMatch

    elif opcode == InstructionDefault:
      if prevOpcode == InstructionDefault: return false
      let asn = decodeAsn(pos, asmap)
      if asn == AsmapInvalid: return false
      prevOpcode = InstructionDefault

    else:
      return false

  false  # Reached EOF without RETURN instruction

proc checkStandardAsmap*(data: openArray[byte]): bool =
  ## Validate asmap data for standard (128-bit IPv6) use.
  ## Reference: bitcoin-core/src/util/asmap.cpp:310 CheckStandardAsmap()
  sanityCheckAsmap(data, 128)

proc loadAsmap*(path: string): seq[byte] =
  ## Load an asmap binary file from `path`, enforce the 8 MiB size limit,
  ## and run CheckStandardAsmap.  Returns the data on success, empty on failure.
  ## Reference: bitcoin-core/src/util/asmap.cpp:322 DecodeAsmap()
  if not fileExists(path):
    warn "asmap file not found", path = path
    return @[]

  let size = getFileSize(path)
  if size <= 0:
    warn "asmap file is empty", path = path
    return @[]
  if size > MaxAsmapFileSize:
    warn "asmap file exceeds 8 MiB limit",
         path = path, size = size, limit = MaxAsmapFileSize
    return @[]

  try:
    let f = open(path, fmRead)
    defer: f.close()
    var buf = newSeq[byte](size)
    let n = f.readBytes(buf, 0, buf.len)
    if n != buf.len:
      warn "asmap file short read", path = path, expected = buf.len, got = n
      return @[]

    if not checkStandardAsmap(buf):
      warn "asmap sanity check failed", path = path
      return @[]

    info "loaded asmap file",
         path = path, size = n
    buf
  except IOError as e:
    warn "failed to read asmap file", path = path, error = e.msg
    @[]

proc asmapVersion*(data: openArray[byte]): array[32, byte] =
  ## Compute a SHA-256 fingerprint of the asmap data for version tracking.
  ## Reference: bitcoin-core/src/util/asmap.cpp:348 AsmapVersion()
  if data.len == 0:
    return default(array[32, byte])
  sha256(data)

# ---------------------------------------------------------------------------
# NetGroupManager
# ---------------------------------------------------------------------------

type
  NetGroupManager* = ref object
    ## Manages asmap data and provides ASN-aware network grouping.
    ## Core: netgroup.h class NetGroupManager
    asmapData*: seq[byte]   ## Empty when not using asmap (fallback to /16 or /32)
    version*: array[32, byte]  ## SHA-256 fingerprint of asmapData

proc newNetGroupManager*(asmapData: seq[byte] = @[]): NetGroupManager =
  ## Create a NetGroupManager with optional asmap data.
  ## Pass an empty seq to disable asmap (fallback to /16 / /32 grouping).
  let ver = if asmapData.len > 0: asmapVersion(asmapData) else: default(array[32, byte])
  NetGroupManager(asmapData: asmapData, version: ver)

proc usingAsmap*(mgr: NetGroupManager): bool =
  ## Returns true if an asmap file is loaded.
  ## Core: NetGroupManager::UsingASMap()
  mgr.asmapData.len > 0

proc getMappedAS*(mgr: NetGroupManager, ip: array[16, byte]): uint32 =
  ## Interpret the asmap to find the ASN for `ip`.
  ## Returns 0 when asmap is not loaded or the IP is not in any mapped prefix.
  ## `ip` must be a 16-byte array; IPv4 addresses should be passed as
  ## ::ffff:a.b.c.d (bytes 0-9 = 0, bytes 10-11 = 0xFF, bytes 12-15 = IPv4).
  ## Core: NetGroupManager::GetMappedAS()
  if mgr.asmapData.len == 0:
    return 0
  interpret(mgr.asmapData, ip)

proc getAsmapVersion*(mgr: NetGroupManager): array[32, byte] =
  ## Return the SHA-256 fingerprint of the loaded asmap data.
  mgr.version

proc getAsmapVersionHex*(mgr: NetGroupManager): string =
  ## Return the version fingerprint as a lowercase hex string (64 chars).
  ## Returns empty string when asmap is not loaded.
  if not mgr.usingAsmap:
    return ""
  var s = newStringOfCap(64)
  for b in mgr.version:
    s.add toHex(b.int, 2).toLowerAscii
  s
