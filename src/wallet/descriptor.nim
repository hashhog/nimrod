## Output Descriptors (BIP380-386)
## A language for describing sets of output scripts
## Used for wallet import/export and watch-only wallets
##
## Reference: Bitcoin Core script/descriptor.cpp

import std/[strutils, options, algorithm]
import ../crypto/[hashing, secp256k1, address, base58]
import ./wallet

export address.AddressType, address.Address

type
  DescriptorError* = object of CatchableError

  ## Derivation type for ranged descriptors
  DeriveType* = enum
    NonRanged       ## No derivation (single key)
    UnhardenedRanged  ## Wildcard derivation /* (unhardened)
    HardenedRanged    ## Hardened wildcard derivation /*' or /*h

  ## Parse context for descriptor validation
  ParseContext* = enum
    ContextTop      ## Top-level context
    ContextP2SH     ## Inside sh()
    ContextP2WPKH   ## Inside wpkh()
    ContextP2WSH    ## Inside wsh()
    ContextP2TR     ## Inside tr()

  ## Key origin information (fingerprint + derivation path)
  KeyOrigin* = object
    fingerprint*: array[4, byte]
    path*: seq[uint32]

  ## Types of key providers
  KeyProviderKind* = enum
    KPConstHex      ## Constant hex public key
    KPConstWIF      ## Constant WIF private key
    KPBIP32         ## BIP32 extended key with derivation

  ## Key provider - describes how to get a public key
  KeyProvider* = ref object
    exprIndex*: uint32    ## Index of this key expression
    origin*: Option[KeyOrigin]  ## Optional origin info [fingerprint/path]
    apostrophe*: bool     ## Use ' notation (vs h)
    case kind*: KeyProviderKind
    of KPConstHex:
      pubkey*: PublicKey
      xonly*: bool        ## 32-byte x-only pubkey
    of KPConstWIF:
      privateKey*: PrivateKey
      constPubkey*: PublicKey
    of KPBIP32:
      extPubKey*: ExtendedKey
      derivePath*: seq[uint32]
      deriveType*: DeriveType

  ## Descriptor node types
  DescriptorKind* = enum
    DKPk            ## pk(KEY)
    DKPkh           ## pkh(KEY)
    DKWpkh          ## wpkh(KEY)
    DKSh            ## sh(SCRIPT)
    DKWsh           ## wsh(SCRIPT)
    DKTr            ## tr(KEY) or tr(KEY,TREE)
    DKRawTr         ## rawtr(KEY)
    DKMulti         ## multi(K,KEY,...)
    DKSortedMulti   ## sortedmulti(K,KEY,...)
    DKMultiA        ## multi_a(K,KEY,...) - tapscript
    DKSortedMultiA  ## sortedmulti_a(K,KEY,...) - tapscript
    DKAddr          ## addr(ADDR)
    DKRaw           ## raw(HEX)
    DKCombo         ## combo(KEY)
    DKMiniscript    ## miniscript expression

  ## Taproot tree node
  TrTreeNode* = ref object
    case isLeaf*: bool
    of true:
      leafScript*: DescriptorNode
    of false:
      left*: TrTreeNode
      right*: TrTreeNode

  ## Main descriptor node
  DescriptorNode* = ref object
    case kind*: DescriptorKind
    of DKPk, DKPkh, DKWpkh, DKCombo, DKRawTr:
      key*: KeyProvider
    of DKSh, DKWsh:
      sub*: DescriptorNode
    of DKTr:
      internalKey*: KeyProvider
      tree*: Option[TrTreeNode]
      depths*: seq[int]  ## Depth of each script in tree
      scripts*: seq[DescriptorNode]  ## Flattened script leaves
    of DKMulti, DKSortedMulti, DKMultiA, DKSortedMultiA:
      threshold*: int
      keys*: seq[KeyProvider]
    of DKAddr:
      address*: Address
    of DKRaw:
      rawScript*: seq[byte]
    of DKMiniscript:
      discard  ## Not implemented yet

  ## Parsed descriptor
  Descriptor* = ref object
    node*: DescriptorNode
    checksum*: string    ## 8-character BCH checksum

  ## Result of expanding a descriptor at a position
  ExpandedDescriptor* = object
    scripts*: seq[seq[byte]]   ## Generated scriptPubKeys
    pubkeys*: seq[PublicKey]   ## Public keys used
    addresses*: seq[Address]   ## Addresses generated

# =============================================================================
# Descriptor Checksum (8-character BCH code)
# Reference: Bitcoin Core script/descriptor.cpp DescriptorChecksum
# =============================================================================

const
  ## Input charset for descriptor checksum - maps characters to their positions
  ## Characters are grouped in sets of 32
  InputCharset = "0123456789()[],'/*abcdefgh@:$%{}" &
                 "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" &
                 "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

  ## Output charset for checksum (Bech32 charset)
  ChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

proc descriptorPolymod(c: uint64, val: int): uint64 =
  ## BCH code polynomial modular computation
  ## Generator polynomial: x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}
  let c0 = (c shr 35).byte
  result = ((c and 0x7ffffffff'u64) shl 5) xor uint64(val)
  if (c0 and 1) != 0: result = result xor 0xf5dee51989'u64
  if (c0 and 2) != 0: result = result xor 0xa9fdca3312'u64
  if (c0 and 4) != 0: result = result xor 0x1bab10e32d'u64
  if (c0 and 8) != 0: result = result xor 0x3706b1677a'u64
  if (c0 and 16) != 0: result = result xor 0x644d626ffd'u64

proc computeDescriptorChecksum*(descriptor: string): string =
  ## Compute 8-character BCH checksum for a descriptor
  ## Returns empty string if descriptor contains invalid characters
  var c = 1'u64
  var cls = 0
  var clsCount = 0

  for ch in descriptor:
    let pos = InputCharset.find(ch)
    if pos < 0:
      return ""  # Invalid character

    # Emit symbol for position within 32-group
    c = descriptorPolymod(c, pos and 31)

    # For each 3-character group, emit extra symbol
    cls = cls * 3 + (pos shr 5)
    inc clsCount
    if clsCount == 3:
      c = descriptorPolymod(c, cls)
      cls = 0
      clsCount = 0

  # Emit remaining group if any
  if clsCount > 0:
    c = descriptorPolymod(c, cls)

  # Shift 8 more times with zero
  for _ in 0 ..< 8:
    c = descriptorPolymod(c, 0)

  # XOR with 1 to prevent trailing zeros
  c = c xor 1

  # Convert to checksum characters
  result = newString(8)
  for i in 0 ..< 8:
    result[i] = ChecksumCharset[int((c shr (5 * (7 - i))) and 31)]

proc verifyDescriptorChecksum*(descriptor: string): tuple[valid: bool, payload: string] =
  ## Verify descriptor checksum and return payload without checksum
  let hashPos = descriptor.rfind('#')
  if hashPos < 0:
    # No checksum present
    return (false, descriptor)

  let payload = descriptor[0 ..< hashPos]
  let givenChecksum = descriptor[hashPos + 1 .. ^1]

  if givenChecksum.len != 8:
    return (false, payload)

  let computed = computeDescriptorChecksum(payload)
  if computed == "" or computed != givenChecksum:
    return (false, payload)

  (true, payload)

proc addDescriptorChecksum*(descriptor: string): string =
  ## Add checksum to a descriptor
  let checksum = computeDescriptorChecksum(descriptor)
  if checksum == "":
    raise newException(DescriptorError, "invalid characters in descriptor")
  descriptor & "#" & checksum

# =============================================================================
# Key Path Parsing
# =============================================================================

proc parseKeyPathNum(s: string): tuple[index: uint32, hardened: bool] =
  ## Parse a single key path component (e.g., "44", "0'", "0h")
  var str = s
  var hardened = false

  if str.endsWith("'") or str.endsWith("h") or str.endsWith("H"):
    hardened = true
    str = str[0 ..< str.len - 1]

  let index = try:
    parseUInt(str).uint32
  except ValueError:
    raise newException(DescriptorError, "invalid key path component: " & s)

  if index > 0x7FFFFFFF'u32:
    raise newException(DescriptorError, "key path value out of range: " & s)

  (index, hardened)

proc parseKeyPath*(path: string): tuple[path: seq[uint32], apostrophe: bool] =
  ## Parse a derivation path string (e.g., "44'/0'/0'")
  ## Returns path components and whether apostrophe notation was used
  if path.len == 0:
    return (@[], true)

  var components: seq[uint32]
  var apostrophe = true

  let parts = path.split('/')
  for part in parts:
    if part.len == 0:
      continue

    let (index, hardened) = parseKeyPathNum(part)
    if hardened:
      if part.endsWith("h") or part.endsWith("H"):
        apostrophe = false
      components.add(index or 0x80000000'u32)
    else:
      components.add(index)

  (components, apostrophe)

proc pathToString*(path: seq[uint32], apostrophe: bool = true): string =
  ## Convert path components to string
  var parts: seq[string]
  for idx in path:
    let isHardened = (idx and 0x80000000'u32) != 0
    let val = idx and 0x7FFFFFFF'u32
    if isHardened:
      parts.add($val & (if apostrophe: "'" else: "h"))
    else:
      parts.add($val)
  parts.join("/")

# =============================================================================
# Extended Key Parsing
# =============================================================================

proc decodeExtendedKey*(s: string): tuple[key: ExtendedKey, isPrivate: bool, mainnet: bool] =
  ## Decode xpub/xprv/tpub/tprv from Base58Check
  let data = base58CheckDecode(s)
  if data.len != 78:
    raise newException(DescriptorError, "invalid extended key length")

  # Parse version bytes
  let version = (uint32(data[0]) shl 24) or (uint32(data[1]) shl 16) or
                (uint32(data[2]) shl 8) or uint32(data[3])

  var isPrivate: bool
  var mainnet: bool

  case version
  of 0x0488ADE4'u32:  # xprv
    isPrivate = true
    mainnet = true
  of 0x0488B21E'u32:  # xpub
    isPrivate = false
    mainnet = true
  of 0x04358394'u32:  # tprv
    isPrivate = true
    mainnet = false
  of 0x043587CF'u32:  # tpub
    isPrivate = false
    mainnet = false
  else:
    raise newException(DescriptorError, "unknown extended key version")

  var key: ExtendedKey
  key.depth = data[4]
  copyMem(addr key.parentFingerprint[0], addr data[5], 4)
  key.childIndex = (uint32(data[9]) shl 24) or (uint32(data[10]) shl 16) or
                   (uint32(data[11]) shl 8) or uint32(data[12])
  copyMem(addr key.chainCode[0], addr data[13], 32)
  key.isPrivate = isPrivate

  if isPrivate:
    # Private key: 0x00 + 32 bytes
    if data[45] != 0:
      raise newException(DescriptorError, "invalid private key encoding")
    copyMem(addr key.key[0], addr data[46], 32)
    key.publicKey = derivePublicKey(key.key)
  else:
    # Public key: 33 bytes
    copyMem(addr key.publicKey[0], addr data[45], 33)

  (key, isPrivate, mainnet)

# =============================================================================
# WIF Decoding
# =============================================================================

proc decodeWIF*(s: string): tuple[key: PrivateKey, compressed: bool, mainnet: bool] =
  ## Decode WIF private key
  let data = base58CheckDecode(s)

  var mainnet: bool
  var compressed: bool

  case data.len
  of 33:
    # Uncompressed
    compressed = false
    case data[0]
    of 0x80: mainnet = true
    of 0xEF: mainnet = false
    else:
      raise newException(DescriptorError, "invalid WIF version")
  of 34:
    # Compressed
    compressed = true
    if data[33] != 0x01:
      raise newException(DescriptorError, "invalid WIF compression flag")
    case data[0]
    of 0x80: mainnet = true
    of 0xEF: mainnet = false
    else:
      raise newException(DescriptorError, "invalid WIF version")
  else:
    raise newException(DescriptorError, "invalid WIF length")

  var key: PrivateKey
  copyMem(addr key[0], addr data[1], 32)
  (key, compressed, mainnet)

# =============================================================================
# Hex Parsing
# =============================================================================

proc parseHexBytes*(s: string): seq[byte] =
  ## Parse hex string to bytes
  if s.len mod 2 != 0:
    raise newException(DescriptorError, "odd hex string length")

  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 ..< i*2+2]))

proc toHex*(data: openArray[byte]): string =
  ## Convert bytes to hex string
  result = newString(data.len * 2)
  const hexChars = "0123456789abcdef"
  for i, b in data:
    result[i*2] = hexChars[int(b shr 4)]
    result[i*2+1] = hexChars[int(b and 0x0f)]

# =============================================================================
# Key Provider Operations
# =============================================================================

proc isRange*(kp: KeyProvider): bool =
  ## Check if key provider is ranged
  if kp.kind == KPBIP32:
    return kp.deriveType != NonRanged
  false

proc getPubKey*(kp: KeyProvider, pos: int = 0): PublicKey =
  ## Get public key at position (for ranged descriptors)
  case kp.kind
  of KPConstHex:
    result = kp.pubkey
  of KPConstWIF:
    result = kp.constPubkey
  of KPBIP32:
    var key = kp.extPubKey
    # Derive through the path
    for idx in kp.derivePath:
      key = deriveChild(key, idx)
    # Apply range derivation
    case kp.deriveType
    of NonRanged:
      discard
    of UnhardenedRanged:
      key = deriveChild(key, uint32(pos))
    of HardenedRanged:
      key = deriveChild(key, uint32(pos) or 0x80000000'u32)
    result = key.publicKey

proc getXonlyPubKey*(kp: KeyProvider, pos: int = 0): array[32, byte] =
  ## Get x-only public key (for Taproot)
  let pk = kp.getPubKey(pos)
  copyMem(addr result[0], addr pk[1], 32)

proc keyProviderToString*(kp: KeyProvider): string =
  ## Convert key provider to string representation
  result = ""

  # Origin info
  if kp.origin.isSome:
    let origin = kp.origin.get
    result.add("[")
    result.add(toHex(origin.fingerprint))
    if origin.path.len > 0:
      result.add("/")
      result.add(pathToString(origin.path, kp.apostrophe))
    result.add("]")

  case kp.kind
  of KPConstHex:
    if kp.xonly:
      var xonly: array[32, byte]
      copyMem(addr xonly[0], addr kp.pubkey[1], 32)
      result.add(toHex(xonly))
    else:
      result.add(toHex(kp.pubkey))
  of KPConstWIF:
    # For string representation, show public key
    result.add(toHex(kp.constPubkey))
  of KPBIP32:
    result.add(serializeExtendedKey(kp.extPubKey, true))  # Always xpub in toString
    if kp.derivePath.len > 0:
      result.add("/")
      result.add(pathToString(kp.derivePath, kp.apostrophe))
    case kp.deriveType
    of NonRanged:
      discard
    of UnhardenedRanged:
      result.add("/*")
    of HardenedRanged:
      if kp.apostrophe:
        result.add("/*'")
      else:
        result.add("/*h")

# =============================================================================
# Descriptor Node Operations
# =============================================================================

proc isRange*(node: DescriptorNode): bool =
  ## Check if descriptor is ranged
  case node.kind
  of DKPk, DKPkh, DKWpkh, DKCombo, DKRawTr:
    return node.key.isRange()
  of DKSh, DKWsh:
    return node.sub.isRange()
  of DKTr:
    if node.internalKey.isRange():
      return true
    for script in node.scripts:
      if script.isRange():
        return true
    return false
  of DKMulti, DKSortedMulti, DKMultiA, DKSortedMultiA:
    for key in node.keys:
      if key.isRange():
        return true
    return false
  of DKAddr, DKRaw:
    return false
  of DKMiniscript:
    return false

proc isSolvable*(node: DescriptorNode): bool =
  ## Check if descriptor is solvable (can generate signing info)
  case node.kind
  of DKPk, DKPkh, DKWpkh, DKCombo, DKMulti, DKSortedMulti,
     DKTr, DKRawTr, DKMultiA, DKSortedMultiA, DKMiniscript:
    return true
  of DKSh, DKWsh:
    return node.sub.isSolvable()
  of DKAddr, DKRaw:
    return false

# =============================================================================
# Script Generation
# =============================================================================

proc makeMultisigScript(threshold: int, pubkeys: seq[PublicKey], sorted: bool): seq[byte] =
  ## Generate a multisig script
  var keys = pubkeys
  if sorted:
    keys.sort(proc(a, b: PublicKey): int =
      for i in 0 ..< 33:
        if a[i] < b[i]: return -1
        if a[i] > b[i]: return 1
      return 0
    )

  # OP_n <pubkey1> <pubkey2> ... <pubkeyn> OP_m OP_CHECKMULTISIG
  if threshold < 1 or threshold > 16:
    raise newException(DescriptorError, "invalid multisig threshold")
  if keys.len < 1 or keys.len > 16:
    raise newException(DescriptorError, "invalid multisig key count")
  if threshold > keys.len:
    raise newException(DescriptorError, "threshold exceeds key count")

  # OP_1 to OP_16 are 0x51 to 0x60
  result.add(byte(0x50 + threshold))
  for pk in keys:
    result.add(byte(pk.len))
    result.add(@pk)
  result.add(byte(0x50 + keys.len))
  result.add(0xAE)  # OP_CHECKMULTISIG

proc makeMultisigAScript(threshold: int, pubkeys: seq[PublicKey], sorted: bool): seq[byte] =
  ## Generate a tapscript multisig using OP_CHECKSIGADD
  var keys = pubkeys
  if sorted:
    keys.sort(proc(a, b: PublicKey): int =
      for i in 0 ..< 33:
        if a[i] < b[i]: return -1
        if a[i] > b[i]: return 1
      return 0
    )

  # <pubkey1> OP_CHECKSIG <pubkey2> OP_CHECKSIGADD ... OP_n OP_NUMEQUAL
  if keys.len == 0:
    raise newException(DescriptorError, "empty multisig keys")

  # First key
  var xonly: array[32, byte]
  copyMem(addr xonly[0], addr keys[0][1], 32)
  result.add(0x20)  # Push 32 bytes
  result.add(@xonly)
  result.add(0xAC)  # OP_CHECKSIG

  # Remaining keys
  for i in 1 ..< keys.len:
    copyMem(addr xonly[0], addr keys[i][1], 32)
    result.add(0x20)
    result.add(@xonly)
    result.add(0xBA)  # OP_CHECKSIGADD

  # Threshold comparison
  if threshold <= 16:
    result.add(byte(0x50 + threshold))  # OP_n
  else:
    # Push number as bytes
    var n = threshold
    var numBytes: seq[byte]
    while n > 0:
      numBytes.add(byte(n and 0xFF))
      n = n shr 8
    if numBytes.len > 0 and (numBytes[^1] and 0x80) != 0:
      numBytes.add(0)
    result.add(byte(numBytes.len))
    result.add(numBytes)
  result.add(0x9C)  # OP_NUMEQUAL

proc expandNode*(node: DescriptorNode, pos: int = 0): ExpandedDescriptor =
  ## Expand descriptor node at position to scripts and addresses
  case node.kind
  of DKPk:
    let pk = node.key.getPubKey(pos)
    # pk(KEY) = <pubkey> OP_CHECKSIG
    var script: seq[byte]
    script.add(byte(pk.len))
    script.add(@pk)
    script.add(0xAC)  # OP_CHECKSIG
    result.scripts.add(script)
    result.pubkeys.add(pk)

  of DKPkh:
    let pk = node.key.getPubKey(pos)
    let pkh = hash160(pk)
    # pkh(KEY) = OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    var script = @[0x76'u8, 0xA9, 0x14]
    script.add(@pkh)
    script.add(0x88)  # OP_EQUALVERIFY
    script.add(0xAC)  # OP_CHECKSIG
    result.scripts.add(script)
    result.pubkeys.add(pk)
    result.addresses.add(Address(kind: P2PKH, pubkeyHash: pkh))

  of DKWpkh:
    let pk = node.key.getPubKey(pos)
    let pkh = hash160(pk)
    # wpkh(KEY) = OP_0 <20 bytes>
    var script = @[0x00'u8, 0x14]
    script.add(@pkh)
    result.scripts.add(script)
    result.pubkeys.add(pk)
    result.addresses.add(Address(kind: P2WPKH, wpkh: pkh))

  of DKSh:
    let subExpanded = expandNode(node.sub, pos)
    if subExpanded.scripts.len != 1:
      raise newException(DescriptorError, "sh() requires single script")
    let redeemScript = subExpanded.scripts[0]
    let scriptHash = hash160(redeemScript)
    # sh(SCRIPT) = OP_HASH160 <20 bytes> OP_EQUAL
    var script = @[0xA9'u8, 0x14]
    script.add(@scriptHash)
    script.add(0x87)  # OP_EQUAL
    result.scripts.add(script)
    result.pubkeys = subExpanded.pubkeys
    result.addresses.add(Address(kind: P2SH, scriptHash: scriptHash))

  of DKWsh:
    let subExpanded = expandNode(node.sub, pos)
    if subExpanded.scripts.len != 1:
      raise newException(DescriptorError, "wsh() requires single script")
    let witnessScript = subExpanded.scripts[0]
    let scriptHash = sha256Single(witnessScript)
    # wsh(SCRIPT) = OP_0 <32 bytes>
    var script = @[0x00'u8, 0x20]
    script.add(@scriptHash)
    result.scripts.add(script)
    result.pubkeys = subExpanded.pubkeys
    result.addresses.add(Address(kind: P2WSH, wsh: scriptHash))

  of DKTr:
    let xonly = node.internalKey.getXonlyPubKey(pos)
    # For now, simple key-path only (no script tree)
    # tr(KEY) = OP_1 <32 bytes>
    # TODO: Implement taproot tree building with merkle root tweak
    var script = @[0x51'u8, 0x20]
    script.add(@xonly)
    result.scripts.add(script)
    result.addresses.add(Address(kind: P2TR, taprootKey: xonly))

  of DKRawTr:
    let xonly = node.key.getXonlyPubKey(pos)
    var script = @[0x51'u8, 0x20]
    script.add(@xonly)
    result.scripts.add(script)
    result.addresses.add(Address(kind: P2TR, taprootKey: xonly))

  of DKMulti, DKSortedMulti:
    var pubkeys: seq[PublicKey]
    for key in node.keys:
      pubkeys.add(key.getPubKey(pos))
    let sorted = node.kind == DKSortedMulti
    let script = makeMultisigScript(node.threshold, pubkeys, sorted)
    result.scripts.add(script)
    result.pubkeys = pubkeys

  of DKMultiA, DKSortedMultiA:
    var pubkeys: seq[PublicKey]
    for key in node.keys:
      pubkeys.add(key.getPubKey(pos))
    let sorted = node.kind == DKSortedMultiA
    let script = makeMultisigAScript(node.threshold, pubkeys, sorted)
    result.scripts.add(script)
    result.pubkeys = pubkeys

  of DKAddr:
    result.scripts.add(scriptPubKeyForAddress(node.address))
    result.addresses.add(node.address)

  of DKRaw:
    result.scripts.add(node.rawScript)

  of DKCombo:
    # combo(KEY) generates P2PK + P2PKH + P2WPKH + P2SH-P2WPKH (if compressed)
    let pk = node.key.getPubKey(pos)
    let pkh = hash160(pk)
    result.pubkeys.add(pk)

    # P2PK
    var p2pk: seq[byte]
    p2pk.add(byte(pk.len))
    p2pk.add(@pk)
    p2pk.add(0xAC)
    result.scripts.add(p2pk)

    # P2PKH
    var p2pkh = @[0x76'u8, 0xA9, 0x14]
    p2pkh.add(@pkh)
    p2pkh.add([0x88'u8, 0xAC])
    result.scripts.add(p2pkh)
    result.addresses.add(Address(kind: P2PKH, pubkeyHash: pkh))

    # If compressed, also P2WPKH and P2SH-P2WPKH
    if pk[0] == 0x02 or pk[0] == 0x03:
      # P2WPKH
      var p2wpkh = @[0x00'u8, 0x14]
      p2wpkh.add(@pkh)
      result.scripts.add(p2wpkh)
      result.addresses.add(Address(kind: P2WPKH, wpkh: pkh))

      # P2SH-P2WPKH
      var redeemScript = @[0x00'u8, 0x14]
      redeemScript.add(@pkh)
      let scriptHash = hash160(redeemScript)
      var p2sh = @[0xA9'u8, 0x14]
      p2sh.add(@scriptHash)
      p2sh.add(0x87)
      result.scripts.add(p2sh)
      result.addresses.add(Address(kind: P2SH, scriptHash: scriptHash))

  of DKMiniscript:
    raise newException(DescriptorError, "miniscript not implemented")

# =============================================================================
# Descriptor Parsing
# =============================================================================

proc skipWhitespace(s: string, pos: var int) =
  while pos < s.len and s[pos] in {' ', '\t', '\n', '\r'}:
    inc pos

proc expectChar(s: string, pos: var int, c: char) =
  if pos >= s.len or s[pos] != c:
    raise newException(DescriptorError, "expected '" & c & "' at position " & $pos)
  inc pos

proc parseUntil(s: string, pos: var int, delims: set[char]): string =
  let start = pos
  while pos < s.len and s[pos] notin delims:
    inc pos
  s[start ..< pos]

proc parseFunctionName(s: string, pos: var int): string =
  let start = pos
  while pos < s.len and s[pos] in {'a'..'z', 'A'..'Z', '_', '0'..'9'}:
    inc pos
  s[start ..< pos]

proc newKeyProviderConstHex(pubkey: PublicKey, xonly: bool, origin: Option[KeyOrigin],
                             apostrophe: bool, exprIndex: uint32): KeyProvider =
  result = KeyProvider(kind: KPConstHex, pubkey: pubkey, xonly: xonly,
                       origin: origin, apostrophe: apostrophe, exprIndex: exprIndex)

proc newKeyProviderConstWIF(privateKey: PrivateKey, constPubkey: PublicKey,
                             origin: Option[KeyOrigin], apostrophe: bool,
                             exprIndex: uint32): KeyProvider =
  result = KeyProvider(kind: KPConstWIF, privateKey: privateKey, constPubkey: constPubkey,
                       origin: origin, apostrophe: apostrophe, exprIndex: exprIndex)

proc newKeyProviderBIP32(extPubKey: ExtendedKey, derivePath: seq[uint32],
                          deriveType: DeriveType, origin: Option[KeyOrigin],
                          apostrophe: bool, exprIndex: uint32): KeyProvider =
  result = KeyProvider(kind: KPBIP32, extPubKey: extPubKey, derivePath: derivePath,
                       deriveType: deriveType, origin: origin, apostrophe: apostrophe,
                       exprIndex: exprIndex)

proc parseKeyProvider(s: string, pos: var int, ctx: ParseContext): KeyProvider =
  ## Parse a key expression
  var origin: Option[KeyOrigin] = none(KeyOrigin)
  var apostrophe = true

  skipWhitespace(s, pos)

  # Check for origin info [fingerprint/path]
  if pos < s.len and s[pos] == '[':
    inc pos
    let originStr = parseUntil(s, pos, {']'})
    expectChar(s, pos, ']')

    let parts = originStr.split('/', 1)
    if parts.len == 0 or parts[0].len != 8:
      raise newException(DescriptorError, "invalid fingerprint in origin")

    var originInfo: KeyOrigin
    let fpBytes = parseHexBytes(parts[0])
    copyMem(addr originInfo.fingerprint[0], addr fpBytes[0], 4)

    if parts.len > 1:
      let (path, apos) = parseKeyPath(parts[1])
      originInfo.path = path
      apostrophe = apos

    origin = some(originInfo)

  skipWhitespace(s, pos)

  # Parse the key itself
  let keyStr = parseUntil(s, pos, {',', ')', '/', '#', ' ', '\t'})

  # Check for derivation path after the key
  var derivePath: seq[uint32] = @[]
  var deriveType = NonRanged

  if pos < s.len and s[pos] == '/':
    inc pos
    var pathStr = parseUntil(s, pos, {',', ')', '#'})

    # Check for wildcard at end
    if pathStr.endsWith("/*'") or pathStr.endsWith("/*h"):
      deriveType = HardenedRanged
      apostrophe = pathStr.endsWith("/*'")
      pathStr = pathStr[0 ..< pathStr.len - 3]
    elif pathStr.endsWith("/*"):
      deriveType = UnhardenedRanged
      pathStr = pathStr[0 ..< pathStr.len - 2]

    if pathStr.len > 0:
      let (path, apos) = parseKeyPath(pathStr)
      derivePath = path
      apostrophe = apos

  # Determine key type and construct appropriate KeyProvider
  if keyStr.startsWith("xpub") or keyStr.startsWith("xprv") or
     keyStr.startsWith("tpub") or keyStr.startsWith("tprv"):
    # BIP32 extended key
    let (extKey, isPrivate, mainnet) = decodeExtendedKey(keyStr)
    result = newKeyProviderBIP32(extKey, derivePath, deriveType, origin, apostrophe, 0)

  elif keyStr.len == 66 or keyStr.len == 130:
    # Hex public key (33 or 65 bytes)
    let keyBytes = parseHexBytes(keyStr)
    if keyBytes.len == 33:
      var pubkey: PublicKey
      copyMem(addr pubkey[0], addr keyBytes[0], 33)
      result = newKeyProviderConstHex(pubkey, false, origin, apostrophe, 0)
    elif keyBytes.len == 65:
      raise newException(DescriptorError, "uncompressed public keys not supported in descriptors")
    else:
      raise newException(DescriptorError, "invalid public key length")

  elif keyStr.len == 64 and ctx == ContextP2TR:
    # 32-byte x-only public key (Taproot)
    let keyBytes = parseHexBytes(keyStr)
    var pubkey: PublicKey
    # Convert to compressed format (assume even parity)
    pubkey[0] = 0x02
    copyMem(addr pubkey[1], addr keyBytes[0], 32)
    result = newKeyProviderConstHex(pubkey, true, origin, apostrophe, 0)

  elif keyStr.len >= 51 and keyStr.len <= 52:
    # WIF private key
    let (privKey, compressed, mainnet) = decodeWIF(keyStr)
    if not compressed and ctx in {ContextP2WPKH, ContextP2WSH, ContextP2TR}:
      raise newException(DescriptorError, "uncompressed keys not allowed in witness context")
    let pubkey = derivePublicKey(privKey)
    result = newKeyProviderConstWIF(privKey, pubkey, origin, apostrophe, 0)

  else:
    raise newException(DescriptorError, "invalid key expression: " & keyStr)

proc parseDescriptorNode(s: string, pos: var int, ctx: ParseContext): DescriptorNode

proc newDescriptorNodePk(key: KeyProvider): DescriptorNode =
  result = DescriptorNode(kind: DKPk, key: key)

proc newDescriptorNodePkh(key: KeyProvider): DescriptorNode =
  result = DescriptorNode(kind: DKPkh, key: key)

proc newDescriptorNodeWpkh(key: KeyProvider): DescriptorNode =
  result = DescriptorNode(kind: DKWpkh, key: key)

proc newDescriptorNodeSh(sub: DescriptorNode): DescriptorNode =
  result = DescriptorNode(kind: DKSh, sub: sub)

proc newDescriptorNodeWsh(sub: DescriptorNode): DescriptorNode =
  result = DescriptorNode(kind: DKWsh, sub: sub)

proc newDescriptorNodeTr(internalKey: KeyProvider, tree: Option[TrTreeNode],
                          depths: seq[int], scripts: seq[DescriptorNode]): DescriptorNode =
  result = DescriptorNode(kind: DKTr, internalKey: internalKey, tree: tree,
                          depths: depths, scripts: scripts)

proc newDescriptorNodeRawTr(key: KeyProvider): DescriptorNode =
  result = DescriptorNode(kind: DKRawTr, key: key)

proc newDescriptorNodeMulti(threshold: int, keys: seq[KeyProvider]): DescriptorNode =
  result = DescriptorNode(kind: DKMulti, threshold: threshold, keys: keys)

proc newDescriptorNodeSortedMulti(threshold: int, keys: seq[KeyProvider]): DescriptorNode =
  result = DescriptorNode(kind: DKSortedMulti, threshold: threshold, keys: keys)

proc newDescriptorNodeMultiA(threshold: int, keys: seq[KeyProvider]): DescriptorNode =
  result = DescriptorNode(kind: DKMultiA, threshold: threshold, keys: keys)

proc newDescriptorNodeSortedMultiA(threshold: int, keys: seq[KeyProvider]): DescriptorNode =
  result = DescriptorNode(kind: DKSortedMultiA, threshold: threshold, keys: keys)

proc newDescriptorNodeAddr(address: Address): DescriptorNode =
  result = DescriptorNode(kind: DKAddr, address: address)

proc newDescriptorNodeRaw(rawScript: seq[byte]): DescriptorNode =
  result = DescriptorNode(kind: DKRaw, rawScript: rawScript)

proc newDescriptorNodeCombo(key: KeyProvider): DescriptorNode =
  result = DescriptorNode(kind: DKCombo, key: key)

proc parseDescriptorNode(s: string, pos: var int, ctx: ParseContext): DescriptorNode =
  ## Parse a descriptor node
  skipWhitespace(s, pos)

  let funcName = parseFunctionName(s, pos)
  skipWhitespace(s, pos)
  expectChar(s, pos, '(')

  case funcName.toLowerAscii()
  of "pk":
    let key = parseKeyProvider(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodePk(key)

  of "pkh":
    if ctx == ContextP2TR:
      raise newException(DescriptorError, "pkh() not allowed in tr() context")
    let key = parseKeyProvider(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodePkh(key)

  of "wpkh":
    if ctx notin {ContextTop, ContextP2SH}:
      raise newException(DescriptorError, "wpkh() only allowed at top level or in sh()")
    let key = parseKeyProvider(s, pos, ContextP2WPKH)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodeWpkh(key)

  of "sh":
    if ctx != ContextTop:
      raise newException(DescriptorError, "sh() only allowed at top level")
    let sub = parseDescriptorNode(s, pos, ContextP2SH)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodeSh(sub)

  of "wsh":
    if ctx notin {ContextTop, ContextP2SH}:
      raise newException(DescriptorError, "wsh() only allowed at top level or in sh()")
    let sub = parseDescriptorNode(s, pos, ContextP2WSH)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodeWsh(sub)

  of "tr":
    if ctx != ContextTop:
      raise newException(DescriptorError, "tr() only allowed at top level")
    let internalKey = parseKeyProvider(s, pos, ContextP2TR)

    skipWhitespace(s, pos)
    # Check for script tree
    if pos < s.len and s[pos] == ',':
      inc pos
      # TODO: Parse taproot script tree
      # For now, skip to closing paren
      var depth = 1
      while pos < s.len and depth > 0:
        if s[pos] == '(':
          inc depth
        elif s[pos] == ')':
          dec depth
          if depth > 0:
            inc pos
        else:
          inc pos
    else:
      expectChar(s, pos, ')')
    result = newDescriptorNodeTr(internalKey, none(TrTreeNode), @[], @[])

  of "rawtr":
    if ctx != ContextTop:
      raise newException(DescriptorError, "rawtr() only allowed at top level")
    let key = parseKeyProvider(s, pos, ContextP2TR)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodeRawTr(key)

  of "multi", "sortedmulti":
    if ctx notin {ContextTop, ContextP2SH, ContextP2WSH}:
      raise newException(DescriptorError, "multi() not allowed in this context")

    # Parse threshold
    skipWhitespace(s, pos)
    let threshStr = parseUntil(s, pos, {','})
    let threshold = parseInt(threshStr.strip())
    var keys: seq[KeyProvider] = @[]

    # Parse keys
    while pos < s.len and s[pos] == ',':
      inc pos
      let key = parseKeyProvider(s, pos, ctx)
      keys.add(key)
      skipWhitespace(s, pos)

    expectChar(s, pos, ')')

    if funcName == "multi":
      result = newDescriptorNodeMulti(threshold, keys)
    else:
      result = newDescriptorNodeSortedMulti(threshold, keys)

  of "multi_a", "sortedmulti_a":
    if ctx != ContextP2TR:
      raise newException(DescriptorError, "multi_a() only allowed in tr() context")

    skipWhitespace(s, pos)
    let threshStr = parseUntil(s, pos, {','})
    let threshold = parseInt(threshStr.strip())
    var keys: seq[KeyProvider] = @[]

    while pos < s.len and s[pos] == ',':
      inc pos
      let key = parseKeyProvider(s, pos, ContextP2TR)
      keys.add(key)
      skipWhitespace(s, pos)

    expectChar(s, pos, ')')

    if funcName == "multi_a":
      result = newDescriptorNodeMultiA(threshold, keys)
    else:
      result = newDescriptorNodeSortedMultiA(threshold, keys)

  of "addr":
    if ctx != ContextTop:
      raise newException(DescriptorError, "addr() only allowed at top level")
    skipWhitespace(s, pos)
    let addrStr = parseUntil(s, pos, {')'})
    let address = decodeAddress(addrStr.strip())
    expectChar(s, pos, ')')
    result = newDescriptorNodeAddr(address)

  of "raw":
    if ctx != ContextTop:
      raise newException(DescriptorError, "raw() only allowed at top level")
    skipWhitespace(s, pos)
    let hexStr = parseUntil(s, pos, {')'})
    let rawScript = parseHexBytes(hexStr.strip())
    expectChar(s, pos, ')')
    result = newDescriptorNodeRaw(rawScript)

  of "combo":
    if ctx != ContextTop:
      raise newException(DescriptorError, "combo() only allowed at top level")
    let key = parseKeyProvider(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = newDescriptorNodeCombo(key)

  else:
    raise newException(DescriptorError, "unknown descriptor function: " & funcName)

proc parseDescriptor*(descriptor: string, requireChecksum: bool = false): Descriptor =
  ## Parse a descriptor string
  new(result)

  var payload = descriptor
  var givenChecksum = ""

  # Check for checksum
  let hashPos = descriptor.rfind('#')
  if hashPos >= 0:
    payload = descriptor[0 ..< hashPos]
    givenChecksum = descriptor[hashPos + 1 .. ^1]

    if givenChecksum.len != 8:
      raise newException(DescriptorError, "invalid checksum length")

    let computed = computeDescriptorChecksum(payload)
    if computed != givenChecksum:
      raise newException(DescriptorError, "checksum mismatch: expected " & computed & ", got " & givenChecksum)

    result.checksum = givenChecksum
  elif requireChecksum:
    raise newException(DescriptorError, "checksum required but not present")
  else:
    result.checksum = computeDescriptorChecksum(payload)

  var pos = 0
  result.node = parseDescriptorNode(payload, pos, ContextTop)

  skipWhitespace(payload, pos)
  if pos < payload.len:
    raise newException(DescriptorError, "unexpected characters after descriptor")

# =============================================================================
# Descriptor String Generation
# =============================================================================

proc nodeToString(node: DescriptorNode): string =
  ## Convert descriptor node to string (without checksum)
  case node.kind
  of DKPk:
    result = "pk(" & keyProviderToString(node.key) & ")"
  of DKPkh:
    result = "pkh(" & keyProviderToString(node.key) & ")"
  of DKWpkh:
    result = "wpkh(" & keyProviderToString(node.key) & ")"
  of DKSh:
    result = "sh(" & nodeToString(node.sub) & ")"
  of DKWsh:
    result = "wsh(" & nodeToString(node.sub) & ")"
  of DKTr:
    result = "tr(" & keyProviderToString(node.internalKey)
    # TODO: Add tree scripts
    result.add(")")
  of DKRawTr:
    result = "rawtr(" & keyProviderToString(node.key) & ")"
  of DKMulti:
    result = "multi(" & $node.threshold
    for key in node.keys:
      result.add("," & keyProviderToString(key))
    result.add(")")
  of DKSortedMulti:
    result = "sortedmulti(" & $node.threshold
    for key in node.keys:
      result.add("," & keyProviderToString(key))
    result.add(")")
  of DKMultiA:
    result = "multi_a(" & $node.threshold
    for key in node.keys:
      result.add("," & keyProviderToString(key))
    result.add(")")
  of DKSortedMultiA:
    result = "sortedmulti_a(" & $node.threshold
    for key in node.keys:
      result.add("," & keyProviderToString(key))
    result.add(")")
  of DKAddr:
    result = "addr(" & encodeAddress(node.address, true) & ")"
  of DKRaw:
    result = "raw(" & toHex(node.rawScript) & ")"
  of DKCombo:
    result = "combo(" & keyProviderToString(node.key) & ")"
  of DKMiniscript:
    result = "miniscript(...)"

proc toString*(desc: Descriptor, includeChecksum: bool = true): string =
  ## Convert descriptor to string representation
  result = nodeToString(desc.node)
  if includeChecksum:
    result = addDescriptorChecksum(result)

# =============================================================================
# Address Derivation
# =============================================================================

proc deriveAddresses*(desc: Descriptor, start: int = 0, count: int = 1,
                      mainnet: bool = true): seq[string] =
  ## Derive addresses from a descriptor
  ## For ranged descriptors, derives addresses at positions [start, start+count)
  result = @[]

  if desc.node.isRange():
    for i in start ..< start + count:
      let expanded = expandNode(desc.node, i)
      for addr in expanded.addresses:
        result.add(encodeAddress(addr, mainnet))
  else:
    # Non-ranged descriptor - derive only at position 0
    let expanded = expandNode(desc.node, 0)
    for addr in expanded.addresses:
      result.add(encodeAddress(addr, mainnet))

proc deriveScripts*(desc: Descriptor, start: int = 0, count: int = 1): seq[seq[byte]] =
  ## Derive scriptPubKeys from a descriptor
  result = @[]

  if desc.node.isRange():
    for i in start ..< start + count:
      let expanded = expandNode(desc.node, i)
      result.add(expanded.scripts)
  else:
    let expanded = expandNode(desc.node, 0)
    result = expanded.scripts

# =============================================================================
# Descriptor Info
# =============================================================================

type
  DescriptorInfo* = object
    descriptor*: string       ## Canonical descriptor with checksum
    checksum*: string         ## Just the checksum
    isRange*: bool            ## Whether descriptor is ranged
    isSolvable*: bool         ## Whether descriptor provides solvability
    hasPrivateKeys*: bool     ## Whether descriptor contains private keys

proc hasPrivateKeys(node: DescriptorNode): bool =
  case node.kind
  of DKPk, DKPkh, DKWpkh, DKCombo, DKRawTr:
    return node.key.kind == KPConstWIF or
           (node.key.kind == KPBIP32 and node.key.extPubKey.isPrivate)
  of DKSh, DKWsh:
    return hasPrivateKeys(node.sub)
  of DKTr:
    if node.internalKey.kind == KPConstWIF:
      return true
    if node.internalKey.kind == KPBIP32 and node.internalKey.extPubKey.isPrivate:
      return true
    for script in node.scripts:
      if hasPrivateKeys(script):
        return true
    return false
  of DKMulti, DKSortedMulti, DKMultiA, DKSortedMultiA:
    for key in node.keys:
      if key.kind == KPConstWIF:
        return true
      if key.kind == KPBIP32 and key.extPubKey.isPrivate:
        return true
    return false
  of DKAddr, DKRaw, DKMiniscript:
    return false

proc getDescriptorInfo*(descriptor: string): DescriptorInfo =
  ## Get information about a descriptor
  let desc = parseDescriptor(descriptor)

  result.checksum = desc.checksum
  result.descriptor = toString(desc)
  result.isRange = desc.node.isRange()
  result.isSolvable = desc.node.isSolvable()
  result.hasPrivateKeys = hasPrivateKeys(desc.node)
