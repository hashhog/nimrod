## PSBT (BIP174/370) - Partially Signed Bitcoin Transactions
## Standard format for unsigned/partially-signed transactions
## Enables multi-party signing workflows (hardware wallets, multisig, etc.)
##
## Reference: Bitcoin Core psbt.h/psbt.cpp

import std/[tables, options, sets, strutils, base64, algorithm, hashes, sequtils]
import ../primitives/[types, serialize]
import ../crypto/hashing

export types

type
  PsbtError* = object of CatchableError

# =============================================================================
# PSBT Constants
# =============================================================================

const
  # Magic bytes: "psbt" + 0xff separator
  PSBT_MAGIC_BYTES*: array[5, byte] = [0x70'u8, 0x73, 0x62, 0x74, 0xff]

  # Separator byte between maps
  PSBT_SEPARATOR*: byte = 0x00

  # Maximum file size (100 MB)
  MAX_FILE_SIZE_PSBT* = 100_000_000

  # Highest supported version
  PSBT_HIGHEST_VERSION*: uint32 = 0

# Global key types
const
  PSBT_GLOBAL_UNSIGNED_TX*: uint8 = 0x00
  PSBT_GLOBAL_XPUB*: uint8 = 0x01
  PSBT_GLOBAL_VERSION*: uint8 = 0xFB
  PSBT_GLOBAL_PROPRIETARY*: uint8 = 0xFC

# Input key types
const
  PSBT_IN_NON_WITNESS_UTXO*: uint8 = 0x00
  PSBT_IN_WITNESS_UTXO*: uint8 = 0x01
  PSBT_IN_PARTIAL_SIG*: uint8 = 0x02
  PSBT_IN_SIGHASH*: uint8 = 0x03
  PSBT_IN_REDEEMSCRIPT*: uint8 = 0x04
  PSBT_IN_WITNESSSCRIPT*: uint8 = 0x05
  PSBT_IN_BIP32_DERIVATION*: uint8 = 0x06
  PSBT_IN_SCRIPTSIG*: uint8 = 0x07
  PSBT_IN_SCRIPTWITNESS*: uint8 = 0x08
  PSBT_IN_RIPEMD160*: uint8 = 0x0A
  PSBT_IN_SHA256*: uint8 = 0x0B
  PSBT_IN_HASH160*: uint8 = 0x0C
  PSBT_IN_HASH256*: uint8 = 0x0D
  # Taproot
  PSBT_IN_TAP_KEY_SIG*: uint8 = 0x13
  PSBT_IN_TAP_SCRIPT_SIG*: uint8 = 0x14
  PSBT_IN_TAP_LEAF_SCRIPT*: uint8 = 0x15
  PSBT_IN_TAP_BIP32_DERIVATION*: uint8 = 0x16
  PSBT_IN_TAP_INTERNAL_KEY*: uint8 = 0x17
  PSBT_IN_TAP_MERKLE_ROOT*: uint8 = 0x18
  # MuSig2
  PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS*: uint8 = 0x1A
  PSBT_IN_MUSIG2_PUB_NONCE*: uint8 = 0x1B
  PSBT_IN_MUSIG2_PARTIAL_SIG*: uint8 = 0x1C
  PSBT_IN_PROPRIETARY*: uint8 = 0xFC

# Output key types
const
  PSBT_OUT_REDEEMSCRIPT*: uint8 = 0x00
  PSBT_OUT_WITNESSSCRIPT*: uint8 = 0x01
  PSBT_OUT_BIP32_DERIVATION*: uint8 = 0x02
  PSBT_OUT_TAP_INTERNAL_KEY*: uint8 = 0x05
  PSBT_OUT_TAP_TREE*: uint8 = 0x06
  PSBT_OUT_TAP_BIP32_DERIVATION*: uint8 = 0x07
  PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS*: uint8 = 0x08
  PSBT_OUT_PROPRIETARY*: uint8 = 0xFC

# =============================================================================
# PSBT Types
# =============================================================================

type
  # Key origin info for HD derivation paths
  KeyOriginInfo* = object
    fingerprint*: array[4, byte]  ## First 4 bytes of master key hash
    path*: seq[uint32]            ## Derivation path indices

  # Proprietary key-value pair
  PsbtProprietary* = object
    identifier*: seq[byte]
    subtype*: uint64
    key*: seq[byte]
    value*: seq[byte]

  # Per-input PSBT data
  PsbtInput* = object
    # UTXO information
    nonWitnessUtxo*: Option[Transaction]  ## Full previous tx (non-segwit)
    witnessUtxo*: Option[TxOut]           ## Output being spent (segwit)

    # Scripts
    redeemScript*: seq[byte]              ## P2SH redeem script
    witnessScript*: seq[byte]             ## P2WSH witness script
    finalScriptSig*: seq[byte]            ## Completed scriptSig
    finalScriptWitness*: seq[seq[byte]]   ## Completed witness stack

    # Signatures and keys
    partialSigs*: Table[seq[byte], seq[byte]]  ## pubkey -> signature
    sighashType*: Option[int32]
    hdKeypaths*: Table[seq[byte], KeyOriginInfo]  ## pubkey -> derivation

    # Hash preimages
    ripemd160Preimages*: Table[array[20, byte], seq[byte]]
    sha256Preimages*: Table[array[32, byte], seq[byte]]
    hash160Preimages*: Table[array[20, byte], seq[byte]]
    hash256Preimages*: Table[array[32, byte], seq[byte]]

    # Taproot fields
    tapKeySig*: seq[byte]  ## 64-65 byte key path signature
    tapScriptSigs*: Table[(array[32, byte], array[32, byte]), seq[byte]]  ## (xonly, leaf_hash) -> sig
    tapScripts*: Table[(seq[byte], int), HashSet[seq[byte]]]  ## (script, leaf_ver) -> control_blocks
    tapBip32Paths*: Table[array[32, byte], (HashSet[array[32, byte]], KeyOriginInfo)]  ## xonly -> (leaf_hashes, origin)
    tapInternalKey*: array[32, byte]
    tapMerkleRoot*: array[32, byte]

    # Unknown and proprietary
    unknown*: Table[seq[byte], seq[byte]]
    proprietary*: seq[PsbtProprietary]

  # Per-output PSBT data
  PsbtOutput* = object
    redeemScript*: seq[byte]
    witnessScript*: seq[byte]
    hdKeypaths*: Table[seq[byte], KeyOriginInfo]

    # Taproot fields
    tapInternalKey*: array[32, byte]
    tapTree*: seq[(uint8, uint8, seq[byte])]  ## (depth, leaf_ver, script)
    tapBip32Paths*: Table[array[32, byte], (HashSet[array[32, byte]], KeyOriginInfo)]

    # Unknown and proprietary
    unknown*: Table[seq[byte], seq[byte]]
    proprietary*: seq[PsbtProprietary]

  # Main PSBT structure
  Psbt* = object
    tx*: Option[Transaction]  ## Unsigned transaction
    xpubs*: Table[KeyOriginInfo, HashSet[seq[byte]]]  ## origin -> xpubs
    inputs*: seq[PsbtInput]
    outputs*: seq[PsbtOutput]
    version*: Option[uint32]
    unknown*: Table[seq[byte], seq[byte]]
    proprietary*: seq[PsbtProprietary]

  # PSBT workflow roles
  PsbtRole* = enum
    Creator
    Updater
    Signer
    Combiner
    Finalizer
    Extractor

# =============================================================================
# KeyOriginInfo helpers
# =============================================================================

proc `==`*(a, b: KeyOriginInfo): bool =
  a.fingerprint == b.fingerprint and a.path == b.path

proc hash*(k: KeyOriginInfo): Hash =
  var h: Hash = 0
  h = h !& hash(k.fingerprint)
  for idx in k.path:
    h = h !& hash(idx)
  !$h

proc serializeKeyOrigin*(w: var BinaryWriter, origin: KeyOriginInfo) =
  ## Serialize KeyOriginInfo (fingerprint + path indices)
  w.writeBytes(origin.fingerprint)
  for idx in origin.path:
    w.writeUint32LE(idx)

proc deserializeKeyOrigin*(r: var BinaryReader, length: int): KeyOriginInfo =
  ## Deserialize KeyOriginInfo from length bytes
  if length mod 4 != 0 or length == 0:
    raise newException(PsbtError, "invalid length for HD key path")

  if r.pos + 4 > r.data.len:
    raise newException(PsbtError, "unexpected end of data reading fingerprint")
  copyMem(addr result.fingerprint[0], addr r.data[r.pos], 4)
  r.pos += 4

  let numIndices = (length - 4) div 4
  for i in 0 ..< numIndices:
    result.path.add(r.readUint32LE())

# =============================================================================
# PsbtInput helpers
# =============================================================================

proc isNull*(input: PsbtInput): bool =
  input.nonWitnessUtxo.isNone and
  input.witnessUtxo.isNone and
  input.partialSigs.len == 0 and
  input.finalScriptSig.len == 0 and
  input.finalScriptWitness.len == 0

proc isSigned*(input: PsbtInput): bool =
  ## Check if input is already signed (has final fields)
  input.finalScriptSig.len > 0 or input.finalScriptWitness.len > 0

proc merge*(a: var PsbtInput, b: PsbtInput) =
  ## Merge another input into this one
  if a.nonWitnessUtxo.isNone and b.nonWitnessUtxo.isSome:
    a.nonWitnessUtxo = b.nonWitnessUtxo
  if a.witnessUtxo.isNone and b.witnessUtxo.isSome:
    a.witnessUtxo = b.witnessUtxo
  if a.redeemScript.len == 0:
    a.redeemScript = b.redeemScript
  if a.witnessScript.len == 0:
    a.witnessScript = b.witnessScript
  if a.finalScriptSig.len == 0:
    a.finalScriptSig = b.finalScriptSig
  if a.finalScriptWitness.len == 0:
    a.finalScriptWitness = b.finalScriptWitness
  if a.sighashType.isNone:
    a.sighashType = b.sighashType

  # Merge partial sigs
  for key, sig in b.partialSigs:
    if key notin a.partialSigs:
      a.partialSigs[key] = sig

  # Merge HD keypaths
  for key, origin in b.hdKeypaths:
    if key notin a.hdKeypaths:
      a.hdKeypaths[key] = origin

  # Merge preimages
  for hash, preimage in b.ripemd160Preimages:
    if hash notin a.ripemd160Preimages:
      a.ripemd160Preimages[hash] = preimage
  for hash, preimage in b.sha256Preimages:
    if hash notin a.sha256Preimages:
      a.sha256Preimages[hash] = preimage
  for hash, preimage in b.hash160Preimages:
    if hash notin a.hash160Preimages:
      a.hash160Preimages[hash] = preimage
  for hash, preimage in b.hash256Preimages:
    if hash notin a.hash256Preimages:
      a.hash256Preimages[hash] = preimage

  # Merge taproot
  if a.tapKeySig.len == 0:
    a.tapKeySig = b.tapKeySig
  for key, sig in b.tapScriptSigs:
    if key notin a.tapScriptSigs:
      a.tapScriptSigs[key] = sig
  if a.tapInternalKey == default(array[32, byte]):
    a.tapInternalKey = b.tapInternalKey
  if a.tapMerkleRoot == default(array[32, byte]):
    a.tapMerkleRoot = b.tapMerkleRoot

  # Merge unknown
  for key, val in b.unknown:
    if key notin a.unknown:
      a.unknown[key] = val

# =============================================================================
# PsbtOutput helpers
# =============================================================================

proc isNull*(output: PsbtOutput): bool =
  output.redeemScript.len == 0 and
  output.witnessScript.len == 0 and
  output.hdKeypaths.len == 0

proc merge*(a: var PsbtOutput, b: PsbtOutput) =
  ## Merge another output into this one
  if a.redeemScript.len == 0:
    a.redeemScript = b.redeemScript
  if a.witnessScript.len == 0:
    a.witnessScript = b.witnessScript

  for key, origin in b.hdKeypaths:
    if key notin a.hdKeypaths:
      a.hdKeypaths[key] = origin

  if a.tapInternalKey == default(array[32, byte]):
    a.tapInternalKey = b.tapInternalKey
  if a.tapTree.len == 0:
    a.tapTree = b.tapTree

  for key, val in b.unknown:
    if key notin a.unknown:
      a.unknown[key] = val

# =============================================================================
# PSBT Serialization
# =============================================================================

proc writeKeyValue(w: var BinaryWriter, key: openArray[byte], value: openArray[byte]) =
  ## Write a key-value pair in PSBT format
  w.writeCompactSize(uint64(key.len))
  w.writeBytes(key)
  w.writeCompactSize(uint64(value.len))
  w.writeBytes(value)

proc serializePsbtInput*(w: var BinaryWriter, input: PsbtInput) =
  ## Serialize a PSBTInput
  # Non-witness UTXO
  if input.nonWitnessUtxo.isSome:
    let txData = input.nonWitnessUtxo.get().serialize(includeWitness = false)
    w.writeKeyValue([PSBT_IN_NON_WITNESS_UTXO], txData)

  # Witness UTXO
  if input.witnessUtxo.isSome:
    var valW = BinaryWriter()
    valW.writeTxOut(input.witnessUtxo.get())
    w.writeKeyValue([PSBT_IN_WITNESS_UTXO], valW.data)

  # Only write signature data if not finalized
  if input.finalScriptSig.len == 0 and input.finalScriptWitness.len == 0:
    # Partial signatures
    for pubkey, sig in input.partialSigs:
      var key = @[PSBT_IN_PARTIAL_SIG]
      key.add(pubkey)
      w.writeKeyValue(key, sig)

    # Sighash type
    if input.sighashType.isSome:
      var valW = BinaryWriter()
      valW.writeInt32LE(input.sighashType.get())
      w.writeKeyValue([PSBT_IN_SIGHASH], valW.data)

    # Redeem script
    if input.redeemScript.len > 0:
      w.writeKeyValue([PSBT_IN_REDEEMSCRIPT], input.redeemScript)

    # Witness script
    if input.witnessScript.len > 0:
      w.writeKeyValue([PSBT_IN_WITNESSSCRIPT], input.witnessScript)

    # HD keypaths
    for pubkey, origin in input.hdKeypaths:
      var key = @[PSBT_IN_BIP32_DERIVATION]
      key.add(pubkey)
      var valW = BinaryWriter()
      valW.serializeKeyOrigin(origin)
      w.writeKeyValue(key, valW.data)

    # Preimages
    for hash, preimage in input.ripemd160Preimages:
      var key = @[PSBT_IN_RIPEMD160]
      key.add(@hash)
      w.writeKeyValue(key, preimage)

    for hash, preimage in input.sha256Preimages:
      var key = @[PSBT_IN_SHA256]
      key.add(@hash)
      w.writeKeyValue(key, preimage)

    for hash, preimage in input.hash160Preimages:
      var key = @[PSBT_IN_HASH160]
      key.add(@hash)
      w.writeKeyValue(key, preimage)

    for hash, preimage in input.hash256Preimages:
      var key = @[PSBT_IN_HASH256]
      key.add(@hash)
      w.writeKeyValue(key, preimage)

    # Taproot key sig
    if input.tapKeySig.len > 0:
      w.writeKeyValue([PSBT_IN_TAP_KEY_SIG], input.tapKeySig)

    # Taproot script sigs
    for keyPair, sig in input.tapScriptSigs:
      let (xonly, leafHash) = keyPair
      var key = @[PSBT_IN_TAP_SCRIPT_SIG]
      key.add(@xonly)
      key.add(@leafHash)
      w.writeKeyValue(key, sig)

    # Taproot leaf scripts
    for leafKey, controlBlocks in input.tapScripts:
      let (script, leafVer) = leafKey
      for cb in controlBlocks:
        var key = @[PSBT_IN_TAP_LEAF_SCRIPT]
        key.add(cb)
        var value = script
        value.add(byte(leafVer))
        w.writeKeyValue(key, value)

    # Taproot BIP32 paths
    for xonly, pathData in input.tapBip32Paths:
      let (leafHashes, origin) = pathData
      var key = @[PSBT_IN_TAP_BIP32_DERIVATION]
      key.add(@xonly)
      var valW = BinaryWriter()
      valW.writeCompactSize(uint64(leafHashes.len))
      for lh in leafHashes:
        valW.writeBytes(lh)
      valW.serializeKeyOrigin(origin)
      w.writeKeyValue(key, valW.data)

    # Taproot internal key
    if input.tapInternalKey != default(array[32, byte]):
      w.writeKeyValue([PSBT_IN_TAP_INTERNAL_KEY], @(input.tapInternalKey))

    # Taproot merkle root
    if input.tapMerkleRoot != default(array[32, byte]):
      w.writeKeyValue([PSBT_IN_TAP_MERKLE_ROOT], @(input.tapMerkleRoot))

  # Final scriptSig
  if input.finalScriptSig.len > 0:
    w.writeKeyValue([PSBT_IN_SCRIPTSIG], input.finalScriptSig)

  # Final scriptWitness
  if input.finalScriptWitness.len > 0:
    var valW = BinaryWriter()
    valW.writeWitness(input.finalScriptWitness)
    w.writeKeyValue([PSBT_IN_SCRIPTWITNESS], valW.data)

  # Proprietary
  for prop in input.proprietary:
    w.writeKeyValue(prop.key, prop.value)

  # Unknown
  for key, value in input.unknown:
    w.writeKeyValue(key, value)

  # Separator
  w.writeUint8(PSBT_SEPARATOR)

proc serializePsbtOutput*(w: var BinaryWriter, output: PsbtOutput) =
  ## Serialize a PSBTOutput
  # Redeem script
  if output.redeemScript.len > 0:
    w.writeKeyValue([PSBT_OUT_REDEEMSCRIPT], output.redeemScript)

  # Witness script
  if output.witnessScript.len > 0:
    w.writeKeyValue([PSBT_OUT_WITNESSSCRIPT], output.witnessScript)

  # HD keypaths
  for pubkey, origin in output.hdKeypaths:
    var key = @[PSBT_OUT_BIP32_DERIVATION]
    key.add(pubkey)
    var valW = BinaryWriter()
    valW.serializeKeyOrigin(origin)
    w.writeKeyValue(key, valW.data)

  # Taproot internal key
  if output.tapInternalKey != default(array[32, byte]):
    w.writeKeyValue([PSBT_OUT_TAP_INTERNAL_KEY], @(output.tapInternalKey))

  # Taproot tree
  if output.tapTree.len > 0:
    var valW = BinaryWriter()
    for (depth, leafVer, script) in output.tapTree:
      valW.writeUint8(depth)
      valW.writeUint8(leafVer)
      valW.writeVarBytes(script)
    w.writeKeyValue([PSBT_OUT_TAP_TREE], valW.data)

  # Taproot BIP32 paths
  for xonly, pathData in output.tapBip32Paths:
    let (leafHashes, origin) = pathData
    var key = @[PSBT_OUT_TAP_BIP32_DERIVATION]
    key.add(@xonly)
    var valW = BinaryWriter()
    valW.writeCompactSize(uint64(leafHashes.len))
    for lh in leafHashes:
      valW.writeBytes(lh)
    valW.serializeKeyOrigin(origin)
    w.writeKeyValue(key, valW.data)

  # Proprietary
  for prop in output.proprietary:
    w.writeKeyValue(prop.key, prop.value)

  # Unknown
  for key, value in output.unknown:
    w.writeKeyValue(key, value)

  # Separator
  w.writeUint8(PSBT_SEPARATOR)

proc serialize*(psbt: Psbt): seq[byte] =
  ## Serialize PSBT to binary format
  var w = BinaryWriter()

  # Magic bytes
  w.writeBytes(PSBT_MAGIC_BYTES)

  # Global unsigned tx (required)
  if psbt.tx.isNone:
    raise newException(PsbtError, "PSBT must have unsigned transaction")
  let txData = psbt.tx.get().serialize(includeWitness = false)
  w.writeKeyValue([PSBT_GLOBAL_UNSIGNED_TX], txData)

  # Global xpubs
  for origin, xpubSet in psbt.xpubs:
    for xpub in xpubSet:
      var key = @[PSBT_GLOBAL_XPUB]
      key.add(xpub)
      var valW = BinaryWriter()
      # First write the length, then the origin
      let originLen = 4 + origin.path.len * 4
      valW.writeCompactSize(uint64(originLen))
      valW.serializeKeyOrigin(origin)
      w.writeKeyValue(key, valW.data)

  # Version (only if > 0)
  if psbt.version.isSome and psbt.version.get() > 0:
    var valW = BinaryWriter()
    valW.writeUint32LE(psbt.version.get())
    w.writeKeyValue([PSBT_GLOBAL_VERSION], valW.data)

  # Proprietary
  for prop in psbt.proprietary:
    w.writeKeyValue(prop.key, prop.value)

  # Unknown
  for key, value in psbt.unknown:
    w.writeKeyValue(key, value)

  # Global separator
  w.writeUint8(PSBT_SEPARATOR)

  # Inputs
  for input in psbt.inputs:
    w.serializePsbtInput(input)

  # Outputs
  for output in psbt.outputs:
    w.serializePsbtOutput(output)

  result = w.data

# =============================================================================
# PSBT Deserialization
# =============================================================================

proc readKeyValue(r: var BinaryReader): (seq[byte], seq[byte]) =
  ## Read a key-value pair. Returns empty key on separator.
  let keyLen = r.readCompactSize()
  if keyLen == 0:
    return (@[], @[])  # Separator

  let key = r.readBytes(int(keyLen))
  let valueLen = r.readCompactSize()
  let value = r.readBytes(int(valueLen))
  (key, value)

proc deserializePsbtInput*(r: var BinaryReader): PsbtInput =
  ## Deserialize a PSBTInput
  var keysSeen: HashSet[seq[byte]]

  while r.remaining > 0:
    let (key, value) = r.readKeyValue()
    if key.len == 0:
      break  # Separator found

    # Check for duplicate keys
    if key in keysSeen:
      raise newException(PsbtError, "duplicate key in input")
    keysSeen.incl(key)

    # Parse key type
    var keyR = BinaryReader(data: key, pos: 0)
    let keyType = keyR.readCompactSize()

    case keyType
    of PSBT_IN_NON_WITNESS_UTXO:
      if key.len != 1:
        raise newException(PsbtError, "non-witness utxo key must be 1 byte")
      result.nonWitnessUtxo = some(deserializeTransaction(value))

    of PSBT_IN_WITNESS_UTXO:
      if key.len != 1:
        raise newException(PsbtError, "witness utxo key must be 1 byte")
      var valR = BinaryReader(data: value, pos: 0)
      result.witnessUtxo = some(valR.readTxOut())

    of PSBT_IN_PARTIAL_SIG:
      # Key is type + pubkey
      if key.len != 34 and key.len != 66:
        raise newException(PsbtError, "invalid partial sig key size")
      let pubkey = key[1 ..< key.len]
      result.partialSigs[pubkey] = value

    of PSBT_IN_SIGHASH:
      if key.len != 1:
        raise newException(PsbtError, "sighash key must be 1 byte")
      var valR = BinaryReader(data: value, pos: 0)
      result.sighashType = some(valR.readInt32LE())

    of PSBT_IN_REDEEMSCRIPT:
      if key.len != 1:
        raise newException(PsbtError, "redeem script key must be 1 byte")
      result.redeemScript = value

    of PSBT_IN_WITNESSSCRIPT:
      if key.len != 1:
        raise newException(PsbtError, "witness script key must be 1 byte")
      result.witnessScript = value

    of PSBT_IN_BIP32_DERIVATION:
      # Key is type + pubkey
      if key.len != 34 and key.len != 66:
        raise newException(PsbtError, "invalid BIP32 derivation key size")
      let pubkey = key[1 ..< key.len]
      var valR = BinaryReader(data: value, pos: 0)
      let origin = valR.deserializeKeyOrigin(value.len)
      result.hdKeypaths[pubkey] = origin

    of PSBT_IN_SCRIPTSIG:
      if key.len != 1:
        raise newException(PsbtError, "scriptsig key must be 1 byte")
      result.finalScriptSig = value

    of PSBT_IN_SCRIPTWITNESS:
      if key.len != 1:
        raise newException(PsbtError, "scriptwitness key must be 1 byte")
      var valR = BinaryReader(data: value, pos: 0)
      result.finalScriptWitness = valR.readWitness()

    of PSBT_IN_RIPEMD160:
      if key.len != 21:
        raise newException(PsbtError, "ripemd160 key must be 21 bytes")
      var hash: array[20, byte]
      copyMem(addr hash[0], addr key[1], 20)
      result.ripemd160Preimages[hash] = value

    of PSBT_IN_SHA256:
      if key.len != 33:
        raise newException(PsbtError, "sha256 key must be 33 bytes")
      var hash: array[32, byte]
      copyMem(addr hash[0], addr key[1], 32)
      result.sha256Preimages[hash] = value

    of PSBT_IN_HASH160:
      if key.len != 21:
        raise newException(PsbtError, "hash160 key must be 21 bytes")
      var hash: array[20, byte]
      copyMem(addr hash[0], addr key[1], 20)
      result.hash160Preimages[hash] = value

    of PSBT_IN_HASH256:
      if key.len != 33:
        raise newException(PsbtError, "hash256 key must be 33 bytes")
      var hash: array[32, byte]
      copyMem(addr hash[0], addr key[1], 32)
      result.hash256Preimages[hash] = value

    of PSBT_IN_TAP_KEY_SIG:
      if key.len != 1:
        raise newException(PsbtError, "tap key sig key must be 1 byte")
      if value.len < 64 or value.len > 65:
        raise newException(PsbtError, "tap key sig must be 64-65 bytes")
      result.tapKeySig = value

    of PSBT_IN_TAP_SCRIPT_SIG:
      if key.len != 65:
        raise newException(PsbtError, "tap script sig key must be 65 bytes")
      var xonly: array[32, byte]
      var leafHash: array[32, byte]
      copyMem(addr xonly[0], addr key[1], 32)
      copyMem(addr leafHash[0], addr key[33], 32)
      if value.len < 64 or value.len > 65:
        raise newException(PsbtError, "tap script sig must be 64-65 bytes")
      result.tapScriptSigs[(xonly, leafHash)] = value

    of PSBT_IN_TAP_LEAF_SCRIPT:
      if key.len < 34 or (key.len - 2) mod 32 != 0:
        raise newException(PsbtError, "invalid tap leaf script key")
      if value.len < 1:
        raise newException(PsbtError, "tap leaf script value must be at least 1 byte")
      let controlBlock = key[1 ..< key.len]
      let leafVer = int(value[value.len - 1])
      let script = value[0 ..< value.len - 1]
      let leafKey = (script, leafVer)
      if leafKey notin result.tapScripts:
        result.tapScripts[leafKey] = initHashSet[seq[byte]]()
      result.tapScripts[leafKey].incl(controlBlock)

    of PSBT_IN_TAP_BIP32_DERIVATION:
      if key.len != 33:
        raise newException(PsbtError, "tap bip32 derivation key must be 33 bytes")
      var xonly: array[32, byte]
      copyMem(addr xonly[0], addr key[1], 32)

      var valR = BinaryReader(data: value, pos: 0)
      let numHashes = int(valR.readCompactSize())
      var leafHashes = initHashSet[array[32, byte]]()
      for i in 0 ..< numHashes:
        leafHashes.incl(valR.readHash())
      let origin = valR.deserializeKeyOrigin(value.len - valR.pos)
      result.tapBip32Paths[xonly] = (leafHashes, origin)

    of PSBT_IN_TAP_INTERNAL_KEY:
      if key.len != 1:
        raise newException(PsbtError, "tap internal key key must be 1 byte")
      if value.len != 32:
        raise newException(PsbtError, "tap internal key must be 32 bytes")
      copyMem(addr result.tapInternalKey[0], addr value[0], 32)

    of PSBT_IN_TAP_MERKLE_ROOT:
      if key.len != 1:
        raise newException(PsbtError, "tap merkle root key must be 1 byte")
      if value.len != 32:
        raise newException(PsbtError, "tap merkle root must be 32 bytes")
      copyMem(addr result.tapMerkleRoot[0], addr value[0], 32)

    of PSBT_IN_PROPRIETARY:
      var prop = PsbtProprietary(key: key, value: value)
      # Parse identifier and subtype from remaining key data
      if keyR.remaining > 0:
        prop.identifier = keyR.readVarBytes()
        if keyR.remaining > 0:
          prop.subtype = keyR.readCompactSize()
      result.proprietary.add(prop)

    else:
      # Unknown key type
      result.unknown[key] = value

proc deserializePsbtOutput*(r: var BinaryReader): PsbtOutput =
  ## Deserialize a PSBTOutput
  var keysSeen: HashSet[seq[byte]]

  while r.remaining > 0:
    let (key, value) = r.readKeyValue()
    if key.len == 0:
      break  # Separator found

    if key in keysSeen:
      raise newException(PsbtError, "duplicate key in output")
    keysSeen.incl(key)

    var keyR = BinaryReader(data: key, pos: 0)
    let keyType = keyR.readCompactSize()

    case keyType
    of PSBT_OUT_REDEEMSCRIPT:
      if key.len != 1:
        raise newException(PsbtError, "redeem script key must be 1 byte")
      result.redeemScript = value

    of PSBT_OUT_WITNESSSCRIPT:
      if key.len != 1:
        raise newException(PsbtError, "witness script key must be 1 byte")
      result.witnessScript = value

    of PSBT_OUT_BIP32_DERIVATION:
      if key.len != 34 and key.len != 66:
        raise newException(PsbtError, "invalid BIP32 derivation key size")
      let pubkey = key[1 ..< key.len]
      var valR = BinaryReader(data: value, pos: 0)
      let origin = valR.deserializeKeyOrigin(value.len)
      result.hdKeypaths[pubkey] = origin

    of PSBT_OUT_TAP_INTERNAL_KEY:
      if key.len != 1:
        raise newException(PsbtError, "tap internal key key must be 1 byte")
      if value.len != 32:
        raise newException(PsbtError, "tap internal key must be 32 bytes")
      copyMem(addr result.tapInternalKey[0], addr value[0], 32)

    of PSBT_OUT_TAP_TREE:
      if key.len != 1:
        raise newException(PsbtError, "tap tree key must be 1 byte")
      var valR = BinaryReader(data: value, pos: 0)
      while valR.remaining > 0:
        let depth = valR.readUint8()
        let leafVer = valR.readUint8()
        let script = valR.readVarBytes()
        result.tapTree.add((depth, leafVer, script))

    of PSBT_OUT_TAP_BIP32_DERIVATION:
      if key.len != 33:
        raise newException(PsbtError, "tap bip32 derivation key must be 33 bytes")
      var xonly: array[32, byte]
      copyMem(addr xonly[0], addr key[1], 32)

      var valR = BinaryReader(data: value, pos: 0)
      let numHashes = int(valR.readCompactSize())
      var leafHashes = initHashSet[array[32, byte]]()
      for i in 0 ..< numHashes:
        leafHashes.incl(valR.readHash())
      let origin = valR.deserializeKeyOrigin(value.len - valR.pos)
      result.tapBip32Paths[xonly] = (leafHashes, origin)

    of PSBT_OUT_PROPRIETARY:
      var prop = PsbtProprietary(key: key, value: value)
      if keyR.remaining > 0:
        prop.identifier = keyR.readVarBytes()
        if keyR.remaining > 0:
          prop.subtype = keyR.readCompactSize()
      result.proprietary.add(prop)

    else:
      result.unknown[key] = value

proc deserialize*(data: openArray[byte]): Psbt =
  ## Deserialize PSBT from binary
  if data.len < 5:
    raise newException(PsbtError, "PSBT too short")

  var r = BinaryReader(data: @data, pos: 0)

  # Check magic bytes
  for i in 0 ..< 5:
    if r.readUint8() != PSBT_MAGIC_BYTES[i]:
      raise newException(PsbtError, "invalid PSBT magic bytes")

  var keysSeen: HashSet[seq[byte]]

  # Read global map
  while r.remaining > 0:
    let (key, value) = r.readKeyValue()
    if key.len == 0:
      break  # Separator found

    if key in keysSeen:
      raise newException(PsbtError, "duplicate key in global map")
    keysSeen.incl(key)

    var keyR = BinaryReader(data: key, pos: 0)
    let keyType = keyR.readCompactSize()

    case keyType
    of PSBT_GLOBAL_UNSIGNED_TX:
      if key.len != 1:
        raise newException(PsbtError, "unsigned tx key must be 1 byte")
      let tx = deserializeTransaction(value)
      # Verify scriptSigs and witnesses are empty
      for txin in tx.inputs:
        if txin.scriptSig.len > 0:
          raise newException(PsbtError, "unsigned tx has non-empty scriptSig")
      if tx.witnesses.len > 0:
        for w in tx.witnesses:
          if w.len > 0:
            raise newException(PsbtError, "unsigned tx has non-empty witness")
      result.tx = some(tx)

    of PSBT_GLOBAL_XPUB:
      if key.len != 79:  # 1 + 78 bytes for BIP32 extended key
        raise newException(PsbtError, "invalid global xpub key size")
      let xpub = key[1 ..< key.len]

      var valR = BinaryReader(data: value, pos: 0)
      let originLen = int(valR.readCompactSize())
      let origin = valR.deserializeKeyOrigin(originLen)

      if origin notin result.xpubs:
        result.xpubs[origin] = initHashSet[seq[byte]]()
      result.xpubs[origin].incl(xpub)

    of PSBT_GLOBAL_VERSION:
      if key.len != 1:
        raise newException(PsbtError, "version key must be 1 byte")
      var valR = BinaryReader(data: value, pos: 0)
      let ver = valR.readUint32LE()
      if ver > PSBT_HIGHEST_VERSION:
        raise newException(PsbtError, "unsupported PSBT version: " & $ver)
      result.version = some(ver)

    of PSBT_GLOBAL_PROPRIETARY:
      var prop = PsbtProprietary(key: key, value: value)
      if keyR.remaining > 0:
        prop.identifier = keyR.readVarBytes()
        if keyR.remaining > 0:
          prop.subtype = keyR.readCompactSize()
      result.proprietary.add(prop)

    else:
      result.unknown[key] = value

  # Must have unsigned tx
  if result.tx.isNone:
    raise newException(PsbtError, "no unsigned transaction in PSBT")

  # Read inputs
  let numInputs = result.tx.get().inputs.len
  for i in 0 ..< numInputs:
    if r.remaining == 0:
      raise newException(PsbtError, "not enough input maps")
    result.inputs.add(r.deserializePsbtInput())

  # Read outputs
  let numOutputs = result.tx.get().outputs.len
  for i in 0 ..< numOutputs:
    if r.remaining == 0:
      raise newException(PsbtError, "not enough output maps")
    result.outputs.add(r.deserializePsbtOutput())

# =============================================================================
# Base64 encoding/decoding
# =============================================================================

proc toBase64*(psbt: Psbt): string =
  ## Encode PSBT as base64 string
  encode(psbt.serialize())

proc fromBase64*(data: string): Psbt =
  ## Decode PSBT from base64 string
  try:
    let decoded = decode(data)
    var bytes = newSeq[byte](decoded.len)
    for i in 0 ..< decoded.len:
      bytes[i] = byte(decoded[i])
    result = deserialize(bytes)
  except ValueError as e:
    raise newException(PsbtError, "invalid base64: " & e.msg)

# =============================================================================
# PSBT Role Functions
# =============================================================================

proc createPsbt*(tx: Transaction): Psbt =
  ## Creator: Create a new PSBT from an unsigned transaction
  ## The transaction should have empty scriptSigs and witnesses
  for txin in tx.inputs:
    if txin.scriptSig.len > 0:
      raise newException(PsbtError, "transaction must have empty scriptSigs")

  result.tx = some(tx)
  result.inputs = newSeq[PsbtInput](tx.inputs.len)
  result.outputs = newSeq[PsbtOutput](tx.outputs.len)

proc addInput*(psbt: var Psbt, txin: TxIn, input: PsbtInput) =
  ## Add an input to the PSBT
  if psbt.tx.isNone:
    raise newException(PsbtError, "PSBT has no transaction")

  var tx = psbt.tx.get()
  tx.inputs.add(txin)
  psbt.tx = some(tx)
  psbt.inputs.add(input)

proc addOutput*(psbt: var Psbt, txout: TxOut, output: PsbtOutput) =
  ## Add an output to the PSBT
  if psbt.tx.isNone:
    raise newException(PsbtError, "PSBT has no transaction")

  var tx = psbt.tx.get()
  tx.outputs.add(txout)
  psbt.tx = some(tx)
  psbt.outputs.add(output)

proc updateInput*(psbt: var Psbt, index: int, utxo: TxOut, isWitness: bool = true) =
  ## Updater: Add UTXO information to an input
  if index >= psbt.inputs.len:
    raise newException(PsbtError, "input index out of range")

  if isWitness:
    psbt.inputs[index].witnessUtxo = some(utxo)
  else:
    # For non-witness, we need the full previous transaction
    # This is a simplified version - full implementation would need the tx
    raise newException(PsbtError, "non-witness UTXO update requires full transaction")

proc updateInputWithTx*(psbt: var Psbt, index: int, prevTx: Transaction) =
  ## Updater: Add full previous transaction for non-witness input
  if index >= psbt.inputs.len:
    raise newException(PsbtError, "input index out of range")
  psbt.inputs[index].nonWitnessUtxo = some(prevTx)

proc addPartialSig*(psbt: var Psbt, inputIndex: int, pubkey: seq[byte], sig: seq[byte]) =
  ## Signer: Add a partial signature to an input
  if inputIndex >= psbt.inputs.len:
    raise newException(PsbtError, "input index out of range")
  psbt.inputs[inputIndex].partialSigs[pubkey] = sig

proc combinePsbts*(psbts: seq[Psbt]): Psbt =
  ## Combiner: Merge multiple PSBTs with the same underlying transaction
  if psbts.len == 0:
    raise newException(PsbtError, "no PSBTs to combine")

  result = psbts[0]

  for i in 1 ..< psbts.len:
    let other = psbts[i]

    # Verify same transaction
    if result.tx.isNone or other.tx.isNone:
      raise newException(PsbtError, "PSBT missing transaction")

    let txA = result.tx.get()
    let txB = other.tx.get()

    if txA.txid() != txB.txid():
      raise newException(PsbtError, "cannot combine PSBTs with different transactions")

    # Merge inputs
    for j in 0 ..< result.inputs.len:
      result.inputs[j].merge(other.inputs[j])

    # Merge outputs
    for j in 0 ..< result.outputs.len:
      result.outputs[j].merge(other.outputs[j])

    # Merge xpubs
    for origin, xpubs in other.xpubs:
      if origin notin result.xpubs:
        result.xpubs[origin] = initHashSet[seq[byte]]()
      for xpub in xpubs:
        result.xpubs[origin].incl(xpub)

    # Merge unknown
    for key, value in other.unknown:
      if key notin result.unknown:
        result.unknown[key] = value

proc finalizePsbtInput*(input: var PsbtInput): bool =
  ## Finalizer: Finalize an input by combining partial signatures
  ## Returns true if finalization was successful

  # Skip if already finalized
  if input.isSigned():
    return true

  # Check if we have the UTXO
  if input.witnessUtxo.isNone and input.nonWitnessUtxo.isNone:
    return false

  # Get the scriptPubKey
  var spk: seq[byte]
  if input.witnessUtxo.isSome:
    spk = input.witnessUtxo.get().scriptPubKey
  else:
    # Would need to look up from nonWitnessUtxo using the outpoint
    return false

  # Determine script type and finalize accordingly
  # P2WPKH: OP_0 <20 bytes>
  if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
    # Need exactly one partial signature
    if input.partialSigs.len != 1:
      return false

    for pubkey, sig in input.partialSigs:
      input.finalScriptWitness = @[sig, pubkey]
      return true

  # P2WSH: OP_0 <32 bytes>
  elif spk.len == 34 and spk[0] == 0x00 and spk[1] == 0x20:
    # Need witness script
    if input.witnessScript.len == 0:
      return false

    # For multisig, collect signatures in order
    # This is simplified - full implementation needs proper ordering
    var witness: seq[seq[byte]]
    witness.add(@[])  # Empty element for CHECKMULTISIG bug
    for pubkey, sig in input.partialSigs:
      witness.add(sig)
    witness.add(input.witnessScript)
    input.finalScriptWitness = witness
    return true

  # P2TR: OP_1 <32 bytes>
  elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
    # Key path spend
    if input.tapKeySig.len > 0:
      input.finalScriptWitness = @[input.tapKeySig]
      return true

    # Script path would need tap leaf script
    return false

  # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  elif spk.len == 25 and spk[0] == 0x76 and spk[1] == 0xa9:
    if input.partialSigs.len != 1:
      return false

    for pubkey, sig in input.partialSigs:
      # Build scriptSig: <sig> <pubkey>
      var scriptSig: seq[byte]
      scriptSig.add(byte(sig.len))
      scriptSig.add(sig)
      scriptSig.add(byte(pubkey.len))
      scriptSig.add(pubkey)
      input.finalScriptSig = scriptSig
      return true

  # P2SH: OP_HASH160 <20> OP_EQUAL
  elif spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14:
    # Check for P2SH-P2WPKH
    if input.redeemScript.len == 22 and input.redeemScript[0] == 0x00:
      if input.partialSigs.len != 1:
        return false

      for pubkey, sig in input.partialSigs:
        # Final scriptSig is just the redeem script push
        var scriptSig: seq[byte]
        scriptSig.add(byte(input.redeemScript.len))
        scriptSig.add(input.redeemScript)
        input.finalScriptSig = scriptSig
        input.finalScriptWitness = @[sig, pubkey]
        return true

    return false

  false

proc finalizePsbt*(psbt: var Psbt): bool =
  ## Finalizer: Finalize all inputs
  ## Returns true if all inputs were finalized
  result = true
  for i in 0 ..< psbt.inputs.len:
    if not finalizePsbtInput(psbt.inputs[i]):
      result = false

proc extractTransaction*(psbt: Psbt): Option[Transaction] =
  ## Extractor: Extract the final signed transaction
  ## Returns None if not all inputs are finalized
  if psbt.tx.isNone:
    return none(Transaction)

  var tx = psbt.tx.get()

  # Check all inputs are finalized and fill in data
  for i in 0 ..< psbt.inputs.len:
    let input = psbt.inputs[i]
    if not input.isSigned():
      return none(Transaction)

    tx.inputs[i].scriptSig = input.finalScriptSig

  # Set up witnesses
  tx.witnesses = newSeq[seq[seq[byte]]](tx.inputs.len)
  for i in 0 ..< psbt.inputs.len:
    tx.witnesses[i] = psbt.inputs[i].finalScriptWitness

  some(tx)

# =============================================================================
# PSBT Analysis
# =============================================================================

type
  PsbtInputAnalysis* = object
    hasUtxo*: bool
    isSegwit*: bool
    isTaproot*: bool
    hasPartialSigs*: bool
    sigCount*: int
    isFinal*: bool
    missingKeys*: seq[seq[byte]]

  PsbtAnalysis* = object
    version*: uint32
    inputCount*: int
    outputCount*: int
    inputs*: seq[PsbtInputAnalysis]
    totalFee*: Option[Satoshi]
    isComplete*: bool
    nextRole*: PsbtRole

proc analyzeInput*(input: PsbtInput): PsbtInputAnalysis =
  ## Analyze a single PSBT input
  result.hasUtxo = input.witnessUtxo.isSome or input.nonWitnessUtxo.isSome
  result.isFinal = input.isSigned()
  result.hasPartialSigs = input.partialSigs.len > 0 or input.tapKeySig.len > 0
  result.sigCount = input.partialSigs.len + input.tapScriptSigs.len
  if input.tapKeySig.len > 0:
    result.sigCount += 1

  # Determine if segwit/taproot
  if input.witnessUtxo.isSome:
    let spk = input.witnessUtxo.get().scriptPubKey
    result.isSegwit = spk.len >= 2 and (spk[0] == 0x00 or spk[0] == 0x51)
    result.isTaproot = spk.len == 34 and spk[0] == 0x51

proc analyzePsbt*(psbt: Psbt): PsbtAnalysis =
  ## Analyze a PSBT to determine its current state
  result.version = psbt.version.get(0)

  if psbt.tx.isSome:
    result.inputCount = psbt.tx.get().inputs.len
    result.outputCount = psbt.tx.get().outputs.len

  result.isComplete = true
  for i in 0 ..< psbt.inputs.len:
    let analysis = analyzeInput(psbt.inputs[i])
    result.inputs.add(analysis)
    if not analysis.isFinal:
      result.isComplete = false

  # Calculate fee if we have all UTXOs
  var totalIn = Satoshi(0)
  var totalOut = Satoshi(0)
  var hasAllUtxos = true

  for input in psbt.inputs:
    if input.witnessUtxo.isSome:
      totalIn = totalIn + input.witnessUtxo.get().value
    elif input.nonWitnessUtxo.isSome:
      # Would need outpoint to get value
      hasAllUtxos = false
    else:
      hasAllUtxos = false

  if psbt.tx.isSome:
    for output in psbt.tx.get().outputs:
      totalOut = totalOut + output.value

  if hasAllUtxos and int64(totalIn) >= int64(totalOut):
    result.totalFee = some(totalIn - totalOut)

  # Determine next role
  if result.isComplete:
    result.nextRole = Extractor
  elif result.inputs.anyIt(it.hasPartialSigs and not it.isFinal):
    result.nextRole = Finalizer
  elif result.inputs.allIt(it.hasUtxo):
    result.nextRole = Signer
  else:
    result.nextRole = Updater

proc countUnsignedInputs*(psbt: Psbt): int =
  ## Count inputs that are not yet signed
  for input in psbt.inputs:
    if not input.isSigned():
      inc result

proc getInputUtxo*(psbt: Psbt, index: int): Option[TxOut] =
  ## Get the UTXO for a specific input
  if index >= psbt.inputs.len:
    return none(TxOut)

  let input = psbt.inputs[index]
  if input.witnessUtxo.isSome:
    return input.witnessUtxo

  if input.nonWitnessUtxo.isSome and psbt.tx.isSome:
    let prevTx = input.nonWitnessUtxo.get()
    let outpoint = psbt.tx.get().inputs[index].prevOut
    if int(outpoint.vout) < prevTx.outputs.len:
      return some(prevTx.outputs[outpoint.vout])

  none(TxOut)

# =============================================================================
# PSBT Helpers
# =============================================================================

proc isNull*(psbt: Psbt): bool =
  psbt.tx.isNone

proc getVersion*(psbt: Psbt): uint32 =
  psbt.version.get(0)

proc roleName*(role: PsbtRole): string =
  case role
  of Creator: "creator"
  of Updater: "updater"
  of Signer: "signer"
  of Combiner: "combiner"
  of Finalizer: "finalizer"
  of Extractor: "extractor"

proc `$`*(psbt: Psbt): string =
  ## String representation for debugging
  result = "PSBT("
  if psbt.tx.isSome:
    result.add("tx=" & $psbt.tx.get().txid())
  result.add(", inputs=" & $psbt.inputs.len)
  result.add(", outputs=" & $psbt.outputs.len)
  if psbt.version.isSome:
    result.add(", version=" & $psbt.version.get())
  result.add(")")
