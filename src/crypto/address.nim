## Bitcoin address encoding and decoding
## Supports P2PKH, P2SH (Base58Check) and P2WPKH, P2WSH, P2TR (Bech32/Bech32m)

import std/strutils
import base58, bech32

# Network prefixes for Base58Check
const
  MainnetP2PKH* = 0x00'u8
  MainnetP2SH* = 0x05'u8
  TestnetP2PKH* = 0x6F'u8
  TestnetP2SH* = 0xC4'u8

  # Human-readable parts for Bech32
  MainnetHRP* = "bc"
  TestnetHRP* = "tb"

type
  AddressType* = enum
    P2PKH    # Pay to Public Key Hash (legacy)
    P2SH     # Pay to Script Hash (legacy)
    P2WPKH   # Pay to Witness Public Key Hash (segwit v0)
    P2WSH    # Pay to Witness Script Hash (segwit v0)
    P2TR     # Pay to Taproot (segwit v1)

  Address* = object
    case kind*: AddressType
    of P2PKH:
      pubkeyHash*: array[20, byte]
    of P2SH:
      scriptHash*: array[20, byte]
    of P2WPKH:
      wpkh*: array[20, byte]
    of P2WSH:
      wsh*: array[32, byte]
    of P2TR:
      taprootKey*: array[32, byte]

  AddressError* = object of CatchableError

proc encodeAddress*(a: Address, mainnet: bool = true): string =
  ## Encode address to string representation
  case a.kind
  of P2PKH:
    let prefix = if mainnet: MainnetP2PKH else: TestnetP2PKH
    var payload = newSeq[byte](21)
    payload[0] = prefix
    for i, b in a.pubkeyHash:
      payload[i + 1] = b
    result = base58CheckEncode(payload)

  of P2SH:
    let prefix = if mainnet: MainnetP2SH else: TestnetP2SH
    var payload = newSeq[byte](21)
    payload[0] = prefix
    for i, b in a.scriptHash:
      payload[i + 1] = b
    result = base58CheckEncode(payload)

  of P2WPKH:
    let hrp = if mainnet: MainnetHRP else: TestnetHRP
    # Witness version 0 + 20 bytes of data
    var data5bit = @[0]  # witness version
    var data8bit = newSeq[int](a.wpkh.len)
    for i, b in a.wpkh:
      data8bit[i] = int(b)
    data5bit.add(convertBits(data8bit, 8, 5, true))
    result = bech32Encode(hrp, data5bit, bech32Classic)

  of P2WSH:
    let hrp = if mainnet: MainnetHRP else: TestnetHRP
    # Witness version 0 + 32 bytes of data
    var data5bit = @[0]  # witness version
    var data8bit = newSeq[int](a.wsh.len)
    for i, b in a.wsh:
      data8bit[i] = int(b)
    data5bit.add(convertBits(data8bit, 8, 5, true))
    result = bech32Encode(hrp, data5bit, bech32Classic)

  of P2TR:
    let hrp = if mainnet: MainnetHRP else: TestnetHRP
    # Witness version 1 + 32 bytes of data
    var data5bit = @[1]  # witness version
    var data8bit = newSeq[int](a.taprootKey.len)
    for i, b in a.taprootKey:
      data8bit[i] = int(b)
    data5bit.add(convertBits(data8bit, 8, 5, true))
    result = bech32Encode(hrp, data5bit, bech32m)

proc decodeAddress*(s: string): Address =
  ## Decode address string to Address object
  ## Raises AddressError on invalid input

  # Try Bech32/Bech32m first (starts with bc1 or tb1)
  let lower = s.toLowerAscii()
  if lower.startsWith("bc1") or lower.startsWith("tb1"):
    try:
      let (_, data, enc) = bech32Decode(s)

      if data.len < 1:
        raise newException(AddressError, "empty witness program")

      let witnessVersion = data[0]
      let programData = convertBits(data[1 .. ^1], 5, 8, false)

      # Validate witness version vs encoding
      if witnessVersion == 0:
        if enc != bech32Classic:
          raise newException(AddressError, "witness v0 must use bech32, not bech32m")
      else:
        if enc != bech32m:
          raise newException(AddressError, "witness v1+ must use bech32m, not bech32")

      # Determine address type from witness version and program length
      case witnessVersion
      of 0:
        if programData.len == 20:
          result = Address(kind: P2WPKH)
          for i, v in programData:
            result.wpkh[i] = byte(v)
        elif programData.len == 32:
          result = Address(kind: P2WSH)
          for i, v in programData:
            result.wsh[i] = byte(v)
        else:
          raise newException(AddressError, "invalid witness v0 program length: " & $programData.len)

      of 1:
        if programData.len == 32:
          result = Address(kind: P2TR)
          for i, v in programData:
            result.taprootKey[i] = byte(v)
        else:
          raise newException(AddressError, "invalid witness v1 program length: " & $programData.len)

      else:
        raise newException(AddressError, "unsupported witness version: " & $witnessVersion)

    except Bech32Error as e:
      raise newException(AddressError, "bech32 decode error: " & e.msg)

  else:
    # Try Base58Check (legacy addresses)
    try:
      let payload = base58CheckDecode(s)
      if payload.len < 1:
        raise newException(AddressError, "empty base58check payload")

      let version = payload[0]
      let data = payload[1 .. ^1]

      case version
      of MainnetP2PKH, TestnetP2PKH:
        if data.len != 20:
          raise newException(AddressError, "invalid P2PKH hash length: " & $data.len)
        result = Address(kind: P2PKH)
        for i, v in data:
          result.pubkeyHash[i] = v

      of MainnetP2SH, TestnetP2SH:
        if data.len != 20:
          raise newException(AddressError, "invalid P2SH hash length: " & $data.len)
        result = Address(kind: P2SH)
        for i, v in data:
          result.scriptHash[i] = v

      else:
        raise newException(AddressError, "unknown address version: " & $version)

    except Base58Error as e:
      raise newException(AddressError, "base58 decode error: " & e.msg)

proc scriptPubKeyForAddress*(a: Address): seq[byte] =
  ## Generate scriptPubKey for the given address
  case a.kind
  of P2PKH:
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    result = @[0x76'u8, 0xa9, 0x14]  # OP_DUP OP_HASH160 PUSH20
    for b in a.pubkeyHash:
      result.add(b)
    result.add(0x88)  # OP_EQUALVERIFY
    result.add(0xac)  # OP_CHECKSIG

  of P2SH:
    # OP_HASH160 <20 bytes> OP_EQUAL
    result = @[0xa9'u8, 0x14]  # OP_HASH160 PUSH20
    for b in a.scriptHash:
      result.add(b)
    result.add(0x87)  # OP_EQUAL

  of P2WPKH:
    # OP_0 <20 bytes>
    result = @[0x00'u8, 0x14]  # OP_0 PUSH20
    for b in a.wpkh:
      result.add(b)

  of P2WSH:
    # OP_0 <32 bytes>
    result = @[0x00'u8, 0x20]  # OP_0 PUSH32
    for b in a.wsh:
      result.add(b)

  of P2TR:
    # OP_1 <32 bytes>
    result = @[0x51'u8, 0x20]  # OP_1 PUSH32
    for b in a.taprootKey:
      result.add(b)

proc isMainnet*(s: string): bool =
  ## Check if address string is mainnet
  let lower = s.toLowerAscii()
  if lower.startsWith("bc1"):
    return true
  if lower.startsWith("tb1"):
    return false
  # Base58Check - decode and check version
  try:
    let payload = base58CheckDecode(s)
    if payload.len > 0:
      return payload[0] == MainnetP2PKH or payload[0] == MainnetP2SH
  except Base58Error:
    discard
  return false
