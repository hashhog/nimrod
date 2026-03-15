## Wallet encryption module
## AES-256-CBC encryption for private keys
## Key derivation using SHA-512 iterations (Bitcoin Core compatible)
##
## Reference: Bitcoin Core /src/wallet/crypter.cpp

import std/[sysrand, options]
import nimcrypto/[sha2, hmac, rijndael, bcmode]

type
  CrypterError* = object of CatchableError

  ## Encryption key material
  KeyingMaterial* = seq[byte]

  ## Crypter with key and IV
  WalletCrypter* = ref object
    key*: array[32, byte]       ## AES-256 key (32 bytes)
    iv*: array[16, byte]        ## IV (16 bytes, AES block size)
    keySet*: bool

const
  ## Key and IV sizes (matching Bitcoin Core WALLET_CRYPTO_* constants)
  WalletCryptoKeySize* = 32
  WalletCryptoIvSize* = 16
  WalletCryptoSaltSize* = 8

  ## Default number of SHA-512 iterations for key derivation
  DefaultKeyDerivationRounds* = 25000

proc newWalletCrypter*(): WalletCrypter =
  ## Create a new wallet crypter (key not set)
  WalletCrypter(keySet: false)

proc bytesToKeySha512Aes*(salt: openArray[byte], passphrase: string,
                           rounds: int): tuple[key: array[32, byte], iv: array[16, byte]] =
  ## Derive encryption key and IV from passphrase using iterated SHA-512
  ## This mimics OpenSSL's EVP_BytesToKey with AES-256-CBC and SHA-512
  ##
  ## Reference: Bitcoin Core CCrypter::BytesToKeySHA512AES
  if rounds < 1:
    raise newException(CrypterError, "rounds must be >= 1")

  # Initial hash: passphrase + salt
  var ctx: sha512
  ctx.init()
  ctx.update(cast[ptr byte](unsafeAddr passphrase[0]), uint(passphrase.len))
  if salt.len > 0:
    ctx.update(unsafeAddr salt[0], uint(salt.len))

  var buf: array[64, byte]
  discard ctx.finish(buf)

  # Iterate
  for i in 0 ..< rounds - 1:
    ctx.init()
    ctx.update(addr buf[0], 64)
    discard ctx.finish(buf)

  # First 32 bytes = key, next 16 bytes = IV
  copyMem(addr result.key[0], addr buf[0], 32)
  copyMem(addr result.iv[0], addr buf[32], 16)

  # Clear intermediate data
  for i in 0 ..< buf.len:
    buf[i] = 0

proc setKeyFromPassphrase*(crypter: WalletCrypter, passphrase: string,
                            salt: openArray[byte], rounds: int = DefaultKeyDerivationRounds): bool =
  ## Set encryption key from passphrase
  ## Returns false if parameters are invalid
  if salt.len != WalletCryptoSaltSize:
    return false
  if rounds < 1:
    return false

  let (key, iv) = bytesToKeySha512Aes(salt, passphrase, rounds)
  crypter.key = key
  crypter.iv = iv
  crypter.keySet = true
  true

proc setKey*(crypter: WalletCrypter, key: array[32, byte], iv: array[16, byte]): bool =
  ## Set encryption key and IV directly
  crypter.key = key
  crypter.iv = iv
  crypter.keySet = true
  true

proc encrypt*(crypter: WalletCrypter, plaintext: openArray[byte]): seq[byte] =
  ## Encrypt data using AES-256-CBC with PKCS7 padding
  ## Returns ciphertext
  if not crypter.keySet:
    raise newException(CrypterError, "encryption key not set")

  if plaintext.len == 0:
    return @[]

  # Calculate padded length (PKCS7 padding to AES block size)
  let blockSize = 16
  let paddedLen = ((plaintext.len div blockSize) + 1) * blockSize

  # Create padded plaintext
  var padded = newSeq[byte](paddedLen)
  copyMem(addr padded[0], unsafeAddr plaintext[0], plaintext.len)

  # PKCS7 padding: pad with bytes equal to the number of padding bytes
  let padValue = byte(paddedLen - plaintext.len)
  for i in plaintext.len ..< paddedLen:
    padded[i] = padValue

  # Encrypt using AES-256-CBC
  var ctx: CBC[aes256]
  ctx.init(crypter.key, crypter.iv)

  result = newSeq[byte](paddedLen)
  ctx.encrypt(padded, result)
  ctx.clear()

proc decrypt*(crypter: WalletCrypter, ciphertext: openArray[byte]): seq[byte] =
  ## Decrypt data using AES-256-CBC with PKCS7 padding removal
  ## Returns plaintext
  if not crypter.keySet:
    raise newException(CrypterError, "encryption key not set")

  if ciphertext.len == 0:
    return @[]

  if ciphertext.len mod 16 != 0:
    raise newException(CrypterError, "ciphertext length must be multiple of 16")

  # Decrypt using AES-256-CBC
  var ctx: CBC[aes256]
  ctx.init(crypter.key, crypter.iv)

  var decrypted = newSeq[byte](ciphertext.len)
  ctx.decrypt(ciphertext, decrypted)
  ctx.clear()

  # Remove PKCS7 padding
  if decrypted.len == 0:
    return decrypted

  let padValue = decrypted[^1]
  if padValue == 0 or int(padValue) > decrypted.len or int(padValue) > 16:
    raise newException(CrypterError, "invalid padding")

  # Verify padding bytes
  for i in decrypted.len - int(padValue) ..< decrypted.len:
    if decrypted[i] != padValue:
      raise newException(CrypterError, "invalid padding")

  result = decrypted[0 ..< decrypted.len - int(padValue)]

proc generateSalt*(): array[8, byte] =
  ## Generate a random salt for key derivation
  if not urandom(result):
    raise newException(CrypterError, "failed to generate random salt")

proc generateIv*(): array[16, byte] =
  ## Generate a random IV for encryption
  if not urandom(result):
    raise newException(CrypterError, "failed to generate random IV")

proc encryptSecret*(masterKey: array[32, byte], plaintext: openArray[byte],
                     iv: array[32, byte]): seq[byte] =
  ## Encrypt a secret (e.g., private key) using master key
  ## Uses first 16 bytes of IV for AES-CBC
  ## Reference: Bitcoin Core EncryptSecret
  var crypter = newWalletCrypter()
  var shortIv: array[16, byte]
  copyMem(addr shortIv[0], unsafeAddr iv[0], 16)
  discard crypter.setKey(masterKey, shortIv)
  crypter.encrypt(plaintext)

proc decryptSecret*(masterKey: array[32, byte], ciphertext: openArray[byte],
                     iv: array[32, byte]): seq[byte] =
  ## Decrypt a secret using master key
  ## Uses first 16 bytes of IV for AES-CBC
  ## Reference: Bitcoin Core DecryptSecret
  var crypter = newWalletCrypter()
  var shortIv: array[16, byte]
  copyMem(addr shortIv[0], unsafeAddr iv[0], 16)
  discard crypter.setKey(masterKey, shortIv)
  crypter.decrypt(ciphertext)

proc clearKey*(crypter: WalletCrypter) =
  ## Clear the encryption key from memory
  for i in 0 ..< crypter.key.len:
    crypter.key[i] = 0
  for i in 0 ..< crypter.iv.len:
    crypter.iv[i] = 0
  crypter.keySet = false
