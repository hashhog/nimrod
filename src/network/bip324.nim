## BIP-324 v2 Encrypted Transport Protocol
##
## Implements the encrypted P2P transport layer for Bitcoin:
## - ElligatorSwift key exchange (via libsecp256k1)
## - HKDF-SHA256 key derivation
## - FSChaCha20 for length encryption
## - FSChaCha20Poly1305 AEAD for payload encryption
## - Short message ID encoding
##
## Reference: BIP-324, Bitcoin Core bip324.cpp

import std/[endians, random, tables, strutils]
import ../crypto/[secp256k1, hkdf, chacha20poly1305]
import ../consensus/params

export secp256k1.EllSwiftPubKey
# Re-export AEADExpansion so callers in peer.nim can size v2 packets via
# `import ./bip324` alone.
export chacha20poly1305.AEADExpansion

const
  # BIP-324 constants
  SessionIdLen* = 32
  GarbageTerminatorLen* = 16
  RekeyInterval* = 224'u32
  LengthLen* = 3
  HeaderLen* = 1
  MaxGarbageLen* = 4095

  # Total overhead: 3 (length) + 1 (header) + 16 (tag) = 20 bytes
  BIP324Expansion* = LengthLen + HeaderLen + AEADExpansion

  # Bit flag in header byte indicating a decoy message
  IgnoreBit* = 0x80'u8

  # Size of ElligatorSwift public key
  EllSwiftPubKeySize* = 64

  # V1 prefix length to check for fallback
  V1PrefixLen* = 16

type
  BIP324Cipher* = object
    ## BIP-324 packet cipher for encrypted P2P transport
    sendLCipher: FSChaCha20          # Length encryption (send)
    recvLCipher: FSChaCha20          # Length encryption (recv)
    sendPCipher: FSChaCha20Poly1305  # Payload AEAD (send)
    recvPCipher: FSChaCha20Poly1305  # Payload AEAD (recv)

    privateKey: PrivateKey
    ourPubKey: EllSwiftPubKey
    sessionId: array[SessionIdLen, byte]
    sendGarbageTerminator: array[GarbageTerminatorLen, byte]
    recvGarbageTerminator: array[GarbageTerminatorLen, byte]

    initialized: bool

  BIP324Error* = object of CatchableError

# Short message type IDs (BIP-324 table — canonical, IDs 0x01..0x1c)
# Maps 12-byte ASCII command strings to single-byte IDs.
#
# This table mirrors Bitcoin Core's `V2_MESSAGE_IDS` (net.cpp:919-954) and
# clearbit's `V2_MESSAGE_IDS` (v2_transport.zig:133-163).  Index 0 is the
# long-form indicator (0x00 + 12-byte cmd-name).  Indices 0x1d..0x20 are
# explicitly reserved by BIP-324 ("for future use") and MUST NOT be used
# for application messages on the wire — `version`, `verack`, `getaddr`,
# `wtxidrelay`, `sendaddrv2`, `sendheaders` are all sent via the long
# (12-byte) form.
#
# Pre-fix bug: `version` was mapped to 0x00 here, which made
# `encodeV2Message("version", payload)` emit `[0x00, payload...]` with NO
# 12-byte command-name field — a malformed long-form frame.  Strict
# decoders (e.g. haskoin) read `payload[0..11]` as the command name,
# rejected the connection with "Unknown short message ID", and the
# nimrod→haskoin pair was `no-conn` in the BIP-324 interop matrix
# (wave-bip324-interop-rerun-2026-04-29/MATRIX.md).
const shortMsgTypes* = {
  "addr":          0x01'u8,
  "block":         0x02'u8,
  "blocktxn":      0x03'u8,
  "cmpctblock":    0x04'u8,
  "feefilter":     0x05'u8,
  "filteradd":     0x06'u8,
  "filterclear":   0x07'u8,
  "filterload":    0x08'u8,
  "getblocks":     0x09'u8,
  "getblocktxn":   0x0a'u8,
  "getdata":       0x0b'u8,
  "getheaders":    0x0c'u8,
  "headers":       0x0d'u8,
  "inv":           0x0e'u8,
  "mempool":       0x0f'u8,
  "merkleblock":   0x10'u8,
  "notfound":      0x11'u8,
  "ping":          0x12'u8,
  "pong":          0x13'u8,
  "sendcmpct":     0x14'u8,
  "tx":            0x15'u8,
  "getcfilters":   0x16'u8,
  "cfilter":       0x17'u8,
  "getcfheaders":  0x18'u8,
  "cfheaders":     0x19'u8,
  "getcfcheckpt":  0x1a'u8,
  "cfcheckpt":     0x1b'u8,
  "addrv2":        0x1c'u8,
  # 0x1d..0x20 reserved by BIP-324; do NOT add encoder mappings.
  # `version`, `verack`, `getaddr`, `wtxidrelay`, `sendaddrv2`,
  # `sendheaders` are encoded via the long (12-byte) form.
}.toTable

# De-facto extended decoder mapping for short IDs that several hashhog
# impls (blockbrew, beamchain, ouroboros) emit on the wire even though
# BIP-324 marks 0x1d-0x22 as "reserved for future use".  We accept these
# on input only — the nimrod encoder always uses the canonical long form
# for these messages so outbound traffic stays spec-compliant for strict
# v2 peers (e.g. haskoin pre-extended-decoder).  Mirrors haskoin's
# `v2ExtendedDecodeIds` (Network.hs:5527-5535).
const extendedDecodeIds* = {
  0x1d'u8: "wtxidrelay",
  0x1e'u8: "sendaddrv2",
  0x1f'u8: "sendheaders",
  0x20'u8: "version",
  0x21'u8: "verack",
  0x22'u8: "getaddr",
}.toTable

# Reverse mapping for decoding (canonical 0x01..0x1c only).
let shortMsgTypesReverse* = block:
  var m = initTable[byte, string]()
  for k, v in shortMsgTypes:
    m[v] = k
  m

proc newBIP324Cipher*(): BIP324Cipher =
  ## Create a new BIP-324 cipher with a randomly generated private key
  randomize()

  # Generate random private key
  for i in 0..<32:
    result.privateKey[i] = byte(rand(255))

  # Create ElligatorSwift public key
  result.ourPubKey = ellswiftCreate(result.privateKey)
  result.initialized = false

proc newBIP324CipherWithKey*(privateKey: PrivateKey): BIP324Cipher =
  ## Create a BIP-324 cipher with a specific private key (for testing)
  result.privateKey = privateKey
  result.ourPubKey = ellswiftCreate(result.privateKey)
  result.initialized = false

proc getOurPubKey*(c: BIP324Cipher): EllSwiftPubKey =
  ## Get our ElligatorSwift-encoded public key (64 bytes)
  c.ourPubKey

proc isInitialized*(c: BIP324Cipher): bool =
  ## Check if the cipher is ready for encryption/decryption
  c.initialized

proc getSessionId*(c: BIP324Cipher): array[SessionIdLen, byte] =
  ## Get the session ID (only valid after initialization)
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")
  c.sessionId

proc getSendGarbageTerminator*(c: BIP324Cipher): array[GarbageTerminatorLen, byte] =
  ## Get the garbage terminator to send
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")
  c.sendGarbageTerminator

proc getRecvGarbageTerminator*(c: BIP324Cipher): array[GarbageTerminatorLen, byte] =
  ## Get the expected garbage terminator to receive
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")
  c.recvGarbageTerminator

proc initialize*(c: var BIP324Cipher, theirPubKey: EllSwiftPubKey,
                 initiator: bool, magic: array[4, byte]) =
  ## Initialize the cipher after receiving the peer's public key
  ##
  ## theirPubKey: The peer's 64-byte ElligatorSwift public key
  ## initiator: true if we initiated the connection (sent first)
  ## magic: Network magic bytes for key derivation salt

  # Compute ECDH shared secret using BIP-324 hash function
  let ecdhSecret = computeBIP324ECDHSecret(
    c.privateKey, c.ourPubKey, theirPubKey, initiator
  )

  # Build salt: "bitcoin_v2_shared_secret" + magic bytes.  Building via
  # an explicit char append is necessary because `cast[string]` on a
  # fixed-size byte array reinterprets the array's stack memory as a
  # Nim string header (length prefix + ptr), reading garbage that
  # crashes the HKDF call when the bytes happen to look like a non-nil
  # but invalid string ptr.
  var salt = "bitcoin_v2_shared_secret"
  salt.add(char(magic[0]))
  salt.add(char(magic[1]))
  salt.add(char(magic[2]))
  salt.add(char(magic[3]))

  # Initialize HKDF with the shared secret
  let hkdf = newHkdfSha256L32(ecdhSecret, salt)

  # Derive encryption keys
  let initiatorLKey = hkdf.expand32("initiator_L")
  let initiatorPKey = hkdf.expand32("initiator_P")
  let responderLKey = hkdf.expand32("responder_L")
  let responderPKey = hkdf.expand32("responder_P")

  # Assign keys based on role
  if initiator:
    c.sendLCipher = initFSChaCha20(initiatorLKey, RekeyInterval)
    c.sendPCipher = initFSChaCha20Poly1305(initiatorPKey, RekeyInterval)
    c.recvLCipher = initFSChaCha20(responderLKey, RekeyInterval)
    c.recvPCipher = initFSChaCha20Poly1305(responderPKey, RekeyInterval)
  else:
    c.sendLCipher = initFSChaCha20(responderLKey, RekeyInterval)
    c.sendPCipher = initFSChaCha20Poly1305(responderPKey, RekeyInterval)
    c.recvLCipher = initFSChaCha20(initiatorLKey, RekeyInterval)
    c.recvPCipher = initFSChaCha20Poly1305(initiatorPKey, RekeyInterval)

  # Derive garbage terminators
  let garbageKey = hkdf.expand32("garbage_terminators")
  if initiator:
    for i in 0..<GarbageTerminatorLen:
      c.sendGarbageTerminator[i] = garbageKey[i]
      c.recvGarbageTerminator[i] = garbageKey[GarbageTerminatorLen + i]
  else:
    for i in 0..<GarbageTerminatorLen:
      c.recvGarbageTerminator[i] = garbageKey[i]
      c.sendGarbageTerminator[i] = garbageKey[GarbageTerminatorLen + i]

  # Derive session ID
  let sessionKey = hkdf.expand32("session_id")
  for i in 0..<SessionIdLen:
    c.sessionId[i] = sessionKey[i]

  c.initialized = true

proc encrypt*(c: var BIP324Cipher, contents: openArray[byte],
              aad: openArray[byte] = [], ignore: bool = false): seq[byte] =
  ## Encrypt a message packet
  ##
  ## contents: The message content (message type ID + payload)
  ## aad: Additional authenticated data (typically garbage during handshake)
  ## ignore: Set true for decoy messages
  ##
  ## Returns: encrypted_length (3) || encrypted_payload+tag
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")

  result = newSeq[byte](LengthLen + contents.len + HeaderLen + AEADExpansion)

  # Encrypt length (3 bytes, little-endian)
  var lenBytes: array[3, byte]
  lenBytes[0] = byte(contents.len and 0xFF)
  lenBytes[1] = byte((contents.len shr 8) and 0xFF)
  lenBytes[2] = byte((contents.len shr 16) and 0xFF)

  var encryptedLen: array[3, byte]
  c.sendLCipher.crypt(lenBytes, encryptedLen)
  result[0] = encryptedLen[0]
  result[1] = encryptedLen[1]
  result[2] = encryptedLen[2]

  # Set header byte (ignore flag)
  let header: byte = if ignore: IgnoreBit else: 0

  # Encrypt payload: header || contents with AEAD
  var output = newSeq[byte](1 + contents.len + AEADExpansion)
  c.sendPCipher.encrypt(header, contents, aad, output)

  for i in 0..<output.len:
    result[LengthLen + i] = output[i]

proc decryptLength*(c: var BIP324Cipher, encryptedLen: openArray[byte]): uint32 =
  ## Decrypt the 3-byte length field from an encrypted packet
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")

  if encryptedLen.len != LengthLen:
    raise newException(BIP324Error, "invalid length field size")

  var lenBytes: array[3, byte]
  c.recvLCipher.crypt(encryptedLen, lenBytes)

  result = uint32(lenBytes[0]) or
           (uint32(lenBytes[1]) shl 8) or
           (uint32(lenBytes[2]) shl 16)

proc decrypt*(c: var BIP324Cipher, encryptedPayload: openArray[byte],
              aad: openArray[byte] = []): tuple[contents: seq[byte], ignore: bool] =
  ## Decrypt the payload portion of an encrypted packet
  ## (length should already be decrypted separately)
  ##
  ## Returns (contents, ignore_flag) or raises on auth failure
  if not c.initialized:
    raise newException(BIP324Error, "cipher not initialized")

  let (header, contents, ok) = c.recvPCipher.decrypt(encryptedPayload, aad)
  if not ok:
    raise newException(BIP324Error, "decryption failed - authentication error")

  let ignore = (header and IgnoreBit) == IgnoreBit
  result = (contents, ignore)

# ==========================================================================
# Message encoding/decoding helpers
# ==========================================================================

proc encodeV2Message*(command: string, payload: openArray[byte]): seq[byte] {.gcsafe.} =
  ## Encode a message for v2 transport.
  ## Returns: `message_type_id (1 byte) || payload`
  ##  OR     `0x00 || command (12 bytes) || payload` for unknown commands.
  ##
  ## See `decodeV2Message` for the gcsafe rationale.
  {.gcsafe.}:
    if command in shortMsgTypes:
      let id = shortMsgTypes[command]
      result = newSeq[byte](1 + payload.len)
      result[0] = id
      for i, b in payload:
        result[1 + i] = b
      return

  # Long-form encoding: 0x00 + 12-byte command + payload
  result = newSeq[byte](1 + 12 + payload.len)
  result[0] = 0x00
  for i in 0..<min(command.len, 12):
    result[1 + i] = byte(command[i])
  for i in 0..<payload.len:
    result[13 + i] = payload[i]

proc decodeV2Message*(content: openArray[byte]):
    tuple[command: string, payload: seq[byte]] {.gcsafe.} =
  ## Decode a message from v2 transport.
  ## Returns (command_string, payload).
  ##
  ## `{.gcsafe.}`: the module-level `shortMsgTypesReverse` table is
  ## initialised once at module load and never mutated, so reads are
  ## safe across threads.  We tell the compiler explicitly because
  ## global `let` Tables otherwise propagate gcsafety taint.
  if content.len == 0:
    raise newException(BIP324Error, "empty message content")

  let firstByte = content[0]

  if firstByte == 0x00:
    # Long-form encoding
    if content.len < 13:
      raise newException(BIP324Error, "short message content")

    # Find null terminator in command
    var cmdEnd = 0
    for i in 1..<13:
      if content[i] == 0:
        break
      cmdEnd = i

    var command = ""
    for i in 1..cmdEnd:
      command.add(char(content[i]))

    var payload = newSeq[byte](content.len - 13)
    for i in 0..<payload.len:
      payload[i] = content[13 + i]

    return (command, payload)

  # Short-form encoding
  {.gcsafe.}:
    if firstByte in shortMsgTypesReverse:
      let command = shortMsgTypesReverse[firstByte]
      var payload = newSeq[byte](content.len - 1)
      for i in 0..<payload.len:
        payload[i] = content[1 + i]
      return (command, payload)

    # De-facto extended IDs (0x1d..0x22) — accept on input for cross-impl
    # interop with blockbrew/beamchain/ouroboros which emit these instead
    # of the canonical long form for `version` etc.  See
    # `extendedDecodeIds` doc-comment above.
    if firstByte in extendedDecodeIds:
      let command = extendedDecodeIds[firstByte]
      var payload = newSeq[byte](content.len - 1)
      for i in 0..<payload.len:
        payload[i] = content[1 + i]
      return (command, payload)

  raise newException(BIP324Error, "unknown message type ID: 0x" & $firstByte.toHex(2))

# ==========================================================================
# Garbage generation and V1 detection
# ==========================================================================

proc generateGarbage*(): seq[byte] =
  ## Generate random garbage data of random length (0 to MaxGarbageLen)
  randomize()
  let length = rand(MaxGarbageLen)
  result = newSeq[byte](length)
  for i in 0..<length:
    result[i] = byte(rand(255))

proc checkV1Magic*(data: openArray[byte], magic: uint32): bool =
  ## Check if the first bytes look like a v1 protocol message
  ## Returns true if data starts with: magic + "version\x00\x00\x00\x00\x00"
  if data.len < V1PrefixLen:
    return false

  # Build expected v1 prefix
  var expectedPrefix: array[V1PrefixLen, byte]
  littleEndian32(addr expectedPrefix[0], unsafeAddr magic)

  # "version" + 5 null bytes
  let versionCmd = "version"
  for i in 0..<versionCmd.len:
    expectedPrefix[4 + i] = byte(versionCmd[i])
  # Remaining bytes are already 0

  for i in 0..<V1PrefixLen:
    if data[i] != expectedPrefix[i]:
      return false

  return true

proc checkV1MagicBytes*(data: openArray[byte], magic: array[4, byte]): bool =
  ## Check if the first bytes look like a v1 protocol message (array version)
  var magicU32: uint32
  littleEndian32(addr magicU32, unsafeAddr magic[0])
  checkV1Magic(data, magicU32)

# ==========================================================================
# Hex utilities
# ==========================================================================

proc toHex(b: byte, len: int): string =
  const hexChars = "0123456789abcdef"
  result = newString(len)
  for i in countdown(len - 1, 0):
    result[len - 1 - i] = hexChars[(b.int shr (i * 4)) and 0xF]
