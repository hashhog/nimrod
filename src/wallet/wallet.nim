## Basic wallet functionality
## Key management, address generation, and transaction signing

import std/[tables, options, strutils]
import ../primitives/types
import ../crypto/[hashing, secp256k1]

type
  WalletError* = object of CatchableError

  AddressType* = enum
    P2PKH     # Pay to public key hash (legacy)
    P2SH      # Pay to script hash
    P2WPKH    # Pay to witness public key hash (native segwit)
    P2WSH     # Pay to witness script hash

  WalletKey* = object
    privateKey*: PrivateKey
    publicKey*: PublicKey
    addressType*: AddressType
    label*: string

  Wallet* = ref object
    keys*: Table[string, WalletKey]  # address -> key
    defaultAddressType*: AddressType

# Base58 alphabet
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

proc base58Encode*(data: openArray[byte]): string =
  ## Encode bytes as base58
  if data.len == 0:
    return ""

  # Count leading zeros
  var zeros = 0
  for b in data:
    if b == 0:
      zeros += 1
    else:
      break

  # Convert to big integer and encode
  var num: seq[byte] = @data
  var encoded: seq[char]

  while num.len > 0:
    var carry = 0
    var newNum: seq[byte]
    for b in num:
      carry = carry * 256 + int(b)
      if newNum.len > 0 or carry >= 58:
        newNum.add(byte(carry div 58))
      carry = carry mod 58
    encoded.add(BASE58_ALPHABET[carry])
    num = newNum

  # Add leading 1s for zeros
  for i in 0 ..< zeros:
    encoded.add('1')

  # Reverse
  result = ""
  for i in countdown(encoded.len - 1, 0):
    result.add(encoded[i])

proc base58Decode*(s: string): seq[byte] =
  ## Decode base58 string
  if s.len == 0:
    return @[]

  # Count leading 1s
  var zeros = 0
  for c in s:
    if c == '1':
      zeros += 1
    else:
      break

  # Convert from base58
  var num: seq[int]
  for c in s:
    let idx = BASE58_ALPHABET.find(c)
    if idx < 0:
      raise newException(WalletError, "invalid base58 character")

    var carry = idx
    for i in 0 ..< num.len:
      carry = carry + num[i] * 58
      num[i] = carry and 0xff
      carry = carry shr 8

    while carry > 0:
      num.add(carry and 0xff)
      carry = carry shr 8

  # Add leading zeros
  result = newSeq[byte](zeros)
  for i in countdown(num.len - 1, 0):
    result.add(byte(num[i]))

proc base58CheckEncode*(version: byte, payload: openArray[byte]): string =
  ## Encode with version byte and checksum
  var data: seq[byte] = @[version]
  data.add(@payload)
  let checksum = doubleSha256(data)[0..3]
  data.add(checksum)
  base58Encode(data)

proc base58CheckDecode*(s: string): tuple[version: byte, payload: seq[byte]] =
  ## Decode base58check
  let data = base58Decode(s)
  if data.len < 5:
    raise newException(WalletError, "invalid base58check data")

  let payload = data[0 ..< data.len - 4]
  let checksum = data[data.len - 4 .. ^1]
  let expectedChecksum = doubleSha256(payload)[0..3]

  if checksum != @expectedChecksum:
    raise newException(WalletError, "invalid checksum")

  (payload[0], payload[1 .. ^1])

proc pubkeyToP2PKHAddress*(pubkey: PublicKey, mainnet: bool = true): string =
  ## Convert public key to P2PKH address
  let pubkeyHash = hash160(pubkey)
  let version = if mainnet: 0x00'u8 else: 0x6f'u8
  base58CheckEncode(version, pubkeyHash)

proc pubkeyToP2WPKHAddress*(pubkey: PublicKey, mainnet: bool = true): string =
  ## Convert public key to native segwit address (bech32)
  # Simplified - just return hex for now, proper bech32 encoding needed
  let pubkeyHash = hash160(pubkey)
  let hrp = if mainnet: "bc" else: "tb"
  hrp & "1q" & toHex(pubkeyHash).toLowerAscii  # Not proper bech32!

proc newWallet*(): Wallet =
  Wallet(
    keys: initTable[string, WalletKey](),
    defaultAddressType: P2PKH
  )

proc generateKey*(wallet: Wallet, label: string = ""): string =
  ## Generate a new key and return its address
  # Generate random private key
  var privateKey: PrivateKey
  # In real implementation, use cryptographically secure random
  for i in 0 ..< 32:
    privateKey[i] = byte(i * 7 + 13)  # Placeholder - use proper RNG!

  let publicKey = derivePublicKey(privateKey)
  let address = pubkeyToP2PKHAddress(publicKey, true)

  wallet.keys[address] = WalletKey(
    privateKey: privateKey,
    publicKey: publicKey,
    addressType: wallet.defaultAddressType,
    label: label
  )

  address

proc importPrivateKey*(wallet: Wallet, wif: string, label: string = ""): string =
  ## Import a WIF-encoded private key
  let (version, payload) = base58CheckDecode(wif)

  var privateKey: PrivateKey
  if payload.len == 32:
    copyMem(addr privateKey[0], addr payload[0], 32)
  elif payload.len == 33 and payload[32] == 0x01:
    copyMem(addr privateKey[0], addr payload[0], 32)
  else:
    raise newException(WalletError, "invalid WIF format")

  let publicKey = derivePublicKey(privateKey)
  let mainnet = version == 0x80
  let address = pubkeyToP2PKHAddress(publicKey, mainnet)

  wallet.keys[address] = WalletKey(
    privateKey: privateKey,
    publicKey: publicKey,
    addressType: P2PKH,
    label: label
  )

  address

proc exportPrivateKey*(wallet: Wallet, address: string): string =
  ## Export private key as WIF
  if address notin wallet.keys:
    raise newException(WalletError, "address not found")

  let key = wallet.keys[address]
  var payload: seq[byte] = @key.privateKey
  payload.add(0x01)  # Compressed
  base58CheckEncode(0x80, payload)

proc getAddresses*(wallet: Wallet): seq[string] =
  for address in wallet.keys.keys:
    result.add(address)

proc signMessage*(wallet: Wallet, address: string, message: openArray[byte]): Signature =
  ## Sign a message with the key for an address
  if address notin wallet.keys:
    raise newException(WalletError, "address not found")

  let key = wallet.keys[address]
  let messageHash = doubleSha256(message)
  sign(key.privateKey, messageHash)

proc createScriptPubKey*(address: string): ScriptBytes =
  ## Create a scriptPubKey for an address
  let (version, payload) = base58CheckDecode(address)

  if version == 0x00 or version == 0x6f:  # P2PKH
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    var script: seq[byte] = @[0x76'u8, 0xa9, 0x14]
    script.add(payload)
    script.add(@[0x88'u8, 0xac])
    ScriptBytes(script)
  elif version == 0x05 or version == 0xc4:  # P2SH
    # OP_HASH160 <20 bytes> OP_EQUAL
    var script: seq[byte] = @[0xa9'u8, 0x14]
    script.add(payload)
    script.add(0x87)
    ScriptBytes(script)
  else:
    raise newException(WalletError, "unsupported address type")

proc toHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2))
