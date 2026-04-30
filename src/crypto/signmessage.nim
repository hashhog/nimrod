## Bitcoin signed message format (signmessage / verifymessage)
##
## Reference: bitcoin-core/src/common/signmessage.cpp
##
## Signing flow (CKey::SignCompact + EncodeBase64):
##   1. Build hash input: compactSize(24) || "Bitcoin Signed Message:\n" ||
##      compactSize(len(msg)) || msg
##   2. Hash with double SHA-256.
##   3. ECDSA sign recoverable -> 64-byte (r,s) + recid.
##   4. Header byte = 27 + recid + (4 if compressed else 0).
##   5. Result is 65 bytes: header || r || s, base64 encoded.
##
## Verify flow (DecodeBase64 + CPubKey::RecoverCompact + PKHash):
##   1. Decode 65-byte signature.
##   2. recid = (header - 27) & 3, compressed = (header - 27) & 4 != 0.
##   3. Recover pubkey from sig+msgHash; serialize compressed/uncompressed
##      according to header flag.
##   4. Compare hash160(serializedPubkey) to address.pubkeyHash.

import std/[base64]
import ./hashing
import ./secp256k1
import ../primitives/serialize

const MessageMagic* = "Bitcoin Signed Message:\n"

proc messageHash*(message: string): array[32, byte] =
  ## Compute the double-SHA-256 hash that Bitcoin Core's `MessageHash`
  ## computes. The serialization is:
  ##   compactSize(24) || MessageMagic || compactSize(len(message)) || message
  var w = BinaryWriter()
  w.writeCompactSize(uint64(MessageMagic.len))
  for c in MessageMagic:
    w.writeUint8(uint8(c))
  w.writeCompactSize(uint64(message.len))
  for c in message:
    w.writeUint8(uint8(c))
  doubleSha256(w.data)

proc signMessage*(privateKey: PrivateKey, message: string,
                  compressed: bool = true): string =
  ## Sign `message` with `privateKey` and return base64-encoded compact
  ## signature, matching Bitcoin Core's `signmessage` output format.
  let h = messageHash(message)
  let (sig, recid) = signCompactRecoverable(privateKey, h)

  var raw = newSeq[byte](65)
  raw[0] = uint8(27 + recid + (if compressed: 4 else: 0))
  for i in 0 ..< 64:
    raw[i + 1] = sig[i]

  var rawStr = newString(65)
  for i in 0 ..< 65:
    rawStr[i] = char(raw[i])
  result = encode(rawStr)

type
  MessageVerifyResult* = enum
    mvrOk
    mvrInvalidAddress           ## Address could not be parsed
    mvrAddressNoKey             ## Address is not P2PKH
    mvrMalformedSignature       ## Base64 decode failed or wrong length
    mvrPubkeyNotRecovered       ## libsecp256k1 recover failed
    mvrNotSigned                ## Pubkey hash mismatch

proc verifyMessageRaw*(pubkeyHash: array[20, byte], signatureBase64: string,
                       message: string): MessageVerifyResult =
  ## Verify a base64 message signature against a 20-byte P2PKH hash.
  ## Caller is responsible for ensuring the address is P2PKH.
  var sigBytesStr: string
  try:
    sigBytesStr = decode(signatureBase64)
  except CatchableError:
    return mvrMalformedSignature

  if sigBytesStr.len != 65:
    return mvrMalformedSignature

  let header = uint8(sigBytesStr[0])
  if header < 27 or header > 27 + 4 + 3:
    return mvrMalformedSignature
  let recid = int((header - 27) and 3)
  let compressed = ((header - 27) and 4) != 0

  var sig64: array[64, byte]
  for i in 0 ..< 64:
    sig64[i] = byte(sigBytesStr[i + 1])

  let h = messageHash(message)
  let recovered = recoverCompactPubkey(h, sig64, recid, compressed)
  if recovered.len == 0:
    return mvrPubkeyNotRecovered

  let computedHash = hash160(recovered)
  if computedHash == pubkeyHash:
    mvrOk
  else:
    mvrNotSigned
