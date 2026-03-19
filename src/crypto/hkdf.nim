## HKDF-SHA256 key derivation (RFC 5869)
## Fixed output length of 32 bytes (L=32) matching Bitcoin Core's implementation

import nimcrypto/[sha2, hmac]

const
  HkdfOutputLen* = 32  # Fixed output length (L=32)

type
  HkdfSha256L32* = object
    ## HKDF-SHA256 with fixed output length of 32 bytes
    ## Matches Bitcoin Core's CHKDF_HMAC_SHA256_L32
    prk: array[32, byte]  # Pseudo-random key

proc newHkdfSha256L32*(ikm: openArray[byte], salt: string): HkdfSha256L32 =
  ## Initialize HKDF with input key material and salt
  ## Performs the HKDF-Extract step: PRK = HMAC-SHA256(salt, IKM)
  var ctx: HMAC[sha256]
  ctx.init(salt)
  ctx.update(ikm)
  var digest = ctx.finish()
  copyMem(addr result.prk[0], addr digest.data[0], 32)

proc expand32*(self: HkdfSha256L32, info: string, output: var array[32, byte]) =
  ## HKDF-Expand to produce exactly 32 bytes
  ## OKM = HMAC-SHA256(PRK, info || 0x01)
  ## Since L=32 and hash output is 32 bytes, we only need one round with counter 0x01
  var ctx: HMAC[sha256]
  ctx.init(self.prk)
  ctx.update(info)
  ctx.update([0x01'u8])
  var digest = ctx.finish()
  copyMem(addr output[0], addr digest.data[0], 32)

proc expand32*(self: HkdfSha256L32, info: string): array[32, byte] =
  ## Convenience overload that returns the result
  self.expand32(info, result)

# Direct function interface for simple use cases
proc hkdfExpand*(ikm: openArray[byte], salt: string, info: string): array[32, byte] =
  ## One-shot HKDF-SHA256 with L=32
  let hkdf = newHkdfSha256L32(ikm, salt)
  result = hkdf.expand32(info)
