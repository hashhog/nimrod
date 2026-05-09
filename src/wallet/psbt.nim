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

proc proprietaryKey*(typeByte: uint8, identifier: openArray[byte],
                     subtype: uint64, keydata: openArray[byte] = []): seq[byte] =
  ## Build the canonical BIP-174 proprietary key blob:
  ##   <typeByte> <CompactSize id-len> <id> <CompactSize subtype> <keydata>
  ## Used when the caller fills `identifier`/`subtype` on a PsbtProprietary
  ## but leaves `key` empty.
  var w = BinaryWriter()
  w.writeUint8(typeByte)
  w.writeCompactSize(uint64(identifier.len))
  w.writeBytes(identifier)
  w.writeCompactSize(subtype)
  if keydata.len > 0:
    w.writeBytes(keydata)
  result = w.data

proc encodeProprietary*(prop: PsbtProprietary, typeByte: uint8): seq[byte] =
  ## Pick the on-wire key for a proprietary record. Prefer `prop.key` when
  ## the caller supplied it (round-trip from a parsed PSBT); otherwise build
  ## the canonical key from (typeByte, identifier, subtype).
  if prop.key.len > 0:
    prop.key
  else:
    proprietaryKey(typeByte, prop.identifier, prop.subtype)

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

# ---------------------------------------------------------------------------
# Canonical-emit helpers (W47)
# ---------------------------------------------------------------------------
# nimrod stores `partialSigs` and `hdKeypaths` in `Table[seq[byte], …]`.
# Nim's `Table` iteration order is hash-bucket order — neither insertion
# order nor lex order — so naive `for k, v in tbl:` produces non-canonical
# bytes that break `combinepsbt` idempotence (T2) and per-fixture
# byte-identity (T3). Mirror the fleet sort-on-emit decision:
#   - partial_sigs: sort by HASH160(pubkey) (blockbrew W45 / beamchain W46-2)
#   - bip32_derivation: sort by raw pubkey (Core's `Sort()` in psbt.cpp)
# Reference: `bitcoin-core/src/psbt.h` — Core uses `std::map` (lex sorted)
# for both fields, so any iteration order that matches Core's per-key
# canonicalization works. We follow the per-impl convention for parity.

proc sortedPartialSigs(t: Table[seq[byte], seq[byte]]):
    seq[(seq[byte], seq[byte])] =
  ## Return (pubkey, sig) pairs sorted by HASH160(pubkey). Order chosen for
  ## fleet parity (blockbrew W45). Returns empty seq if table is empty.
  result = newSeqOfCap[(seq[byte], seq[byte])](t.len)
  for k, v in t:
    result.add((k, v))
  result.sort(proc(a, b: (seq[byte], seq[byte])): int =
    let ha = hash160(a[0])
    let hb = hash160(b[0])
    for i in 0 ..< 20:
      if ha[i] != hb[i]:
        return cmp(ha[i], hb[i])
    return 0)

proc sortedHdKeypaths(t: Table[seq[byte], KeyOriginInfo]):
    seq[(seq[byte], KeyOriginInfo)] =
  ## Return (pubkey, origin) pairs sorted by raw pubkey bytes. Mirrors Core's
  ## `std::map<CPubKey, ...>` ordering in psbt.h.
  result = newSeqOfCap[(seq[byte], KeyOriginInfo)](t.len)
  for k, v in t:
    result.add((k, v))
  result.sort(proc(a, b: (seq[byte], KeyOriginInfo)): int =
    let la = a[0].len
    let lb = b[0].len
    let n = min(la, lb)
    for i in 0 ..< n:
      if a[0][i] != b[0][i]:
        return cmp(a[0][i], b[0][i])
    cmp(la, lb))

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

  # Only write signature data if not finalized.
  # W47 encoder gate: mirrors `bitcoin-core/src/psbt.h:313` — once
  # final_script_sig / final_script_witness is set, producer-only fields
  # MUST NOT be emitted. (This file already had the gate; W47 retains it
  # and pairs it with a cleared-on-finalize step in finalizePsbtInput so
  # the in-memory shape stays honest for downstream callers.)
  if input.finalScriptSig.len == 0 and input.finalScriptWitness.len == 0:
    # Partial signatures — sorted by HASH160(pubkey) for canonical emit (W47).
    for (pubkey, sig) in sortedPartialSigs(input.partialSigs):
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

    # HD keypaths — sorted by raw pubkey for canonical emit (W47).
    for (pubkey, origin) in sortedHdKeypaths(input.hdKeypaths):
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
    w.writeKeyValue(encodeProprietary(prop, PSBT_IN_PROPRIETARY), prop.value)

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

  # HD keypaths — sorted by raw pubkey for canonical emit (W47).
  for (pubkey, origin) in sortedHdKeypaths(output.hdKeypaths):
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
    w.writeKeyValue(encodeProprietary(prop, PSBT_OUT_PROPRIETARY), prop.value)

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
  # BIP-174: value is the raw key origin bytes (4-byte fingerprint + N*4 path
  # indices). The outer key/value length comes from writeKeyValue itself; an
  # extra CompactSize prefix here would not match Core's decodepsbt. Mirror
  # the input/output BIP32_DERIVATION pattern (lines 347-352, 449-454).
  for origin, xpubSet in psbt.xpubs:
    for xpub in xpubSet:
      var key = @[PSBT_GLOBAL_XPUB]
      key.add(xpub)
      var valW = BinaryWriter()
      valW.serializeKeyOrigin(origin)
      w.writeKeyValue(key, valW.data)

  # Version (only if > 0)
  if psbt.version.isSome and psbt.version.get() > 0:
    var valW = BinaryWriter()
    valW.writeUint32LE(psbt.version.get())
    w.writeKeyValue([PSBT_GLOBAL_VERSION], valW.data)

  # Proprietary
  for prop in psbt.proprietary:
    w.writeKeyValue(encodeProprietary(prop, PSBT_GLOBAL_PROPRIETARY), prop.value)

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

      # BIP-174: value is the raw key origin (fingerprint + path), no
      # CompactSize prefix. Length is the value size itself.
      var valR = BinaryReader(data: value, pos: 0)
      let origin = valR.deserializeKeyOrigin(value.len)

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

# =============================================================================
# Multisig finalize helpers (W47, mirrors rustoshi W46 / beamchain W46-2 /
# haskoin W46. Closes W42-A diagnostic gap: nimrod was at 1/5 on
# `tools/psbt-multi-input-test.sh` because the finalizer only handled
# single-sig P2WPKH / P2SH-P2WPKH, with the P2WSH branch unconditionally
# concatenating Table-iteration-order signatures (non-canonical AND broken
# for M-of-N where M < N). Reference for layout decisions:
# `bitcoin-core/src/script/sign.cpp::ProduceSignature` and BIP-11.)
# =============================================================================

proc pushToScriptSig*(script: var seq[byte], data: openArray[byte]) =
  ## Append a length-prefixed push using the minimal Bitcoin script
  ## encoding (1-byte length for <=75B, OP_PUSHDATA1 for 76..255,
  ## OP_PUSHDATA2 for 256..65535). Mirrors `CScript::operator<<` in
  ## `bitcoin-core/src/script/script.h`. Used by the legacy P2SH-multisig
  ## finalizer to push signatures + the redeem script into final scriptSig;
  ## also handy for the P2SH-P2WSH outer scriptSig (1 push of redeem).
  let n = data.len
  if n == 0:
    script.add(0x00'u8)            # OP_0 / empty push
  elif n <= 75:
    script.add(byte(n))
    for b in data: script.add(b)
  elif n <= 255:
    script.add(0x4c'u8)            # OP_PUSHDATA1
    script.add(byte(n))
    for b in data: script.add(b)
  elif n <= 65535:
    script.add(0x4d'u8)            # OP_PUSHDATA2
    script.add(byte(n and 0xff))
    script.add(byte((n shr 8) and 0xff))
    for b in data: script.add(b)
  else:
    script.add(0x4e'u8)            # OP_PUSHDATA4
    script.add(byte(n and 0xff))
    script.add(byte((n shr 8) and 0xff))
    script.add(byte((n shr 16) and 0xff))
    script.add(byte((n shr 24) and 0xff))
    for b in data: script.add(b)

proc parseMultisigScript*(script: openArray[byte]):
    Option[(int, seq[seq[byte]])] =
  ## Parse a `<M> <pk1> ... <pkN> <N> OP_CHECKMULTISIG` script and return
  ## (M, pubkeys-in-script-order). Returns none on shape mismatch.
  ## Mirrors `bitcoin-core/src/script/solver.cpp::MatchMultisig`.
  if script.len < 4: return none((int, seq[seq[byte]]))
  if script[script.len - 1] != 0xae'u8:  # OP_CHECKMULTISIG
    return none((int, seq[seq[byte]]))
  let mOp = script[0]
  if mOp < 0x51'u8 or mOp > 0x60'u8:     # OP_1 .. OP_16
    return none((int, seq[seq[byte]]))
  let m = int(mOp - 0x50'u8)
  let nOp = script[script.len - 2]
  if nOp < 0x51'u8 or nOp > 0x60'u8:
    return none((int, seq[seq[byte]]))
  let n = int(nOp - 0x50'u8)
  if m == 0 or m > n or n > 20:
    return none((int, seq[seq[byte]]))

  var keys: seq[seq[byte]]
  var i = 1
  let endIdx = script.len - 2
  while i < endIdx:
    let pushLen = int(script[i])
    if pushLen != 33 and pushLen != 65:
      return none((int, seq[seq[byte]]))
    inc i
    if i + pushLen > endIdx:
      return none((int, seq[seq[byte]]))
    var pk = newSeq[byte](pushLen)
    for j in 0 ..< pushLen:
      pk[j] = script[i + j]
    keys.add(pk)
    i += pushLen
  if keys.len != n:
    return none((int, seq[seq[byte]]))
  some((m, keys))

proc collectMultisigSigsInScriptOrder(
    partialSigs: Table[seq[byte], seq[byte]],
    keys: seq[seq[byte]], m: int): Option[seq[seq[byte]]] =
  ## Walk `keys` in script-pubkey order and pick partialSigs[pk] for each
  ## key we hold a signature for, stopping at M. Returns none if fewer than
  ## M signatures are available. Critical for CHECKMULTISIG: signatures
  ## MUST be in script-order, NOT insertion order, NOT sorted by pubkey.
  ## Reference: `bitcoin-core/src/script/sign.cpp::SignStep` (TX_MULTISIG
  ## branch) + the W46 closure in rustoshi/beamchain/haskoin.
  var sigs: seq[seq[byte]]
  for pk in keys:
    if pk in partialSigs:
      sigs.add(partialSigs[pk])
      if sigs.len == m:
        break
  if sigs.len < m:
    return none(seq[seq[byte]])
  some(sigs)

proc clearProducerFields(input: var PsbtInput) =
  ## BIP-174 finalizer-role contract: once final_script_sig /
  ## final_script_witness is set, producer-only fields SHOULD be cleared
  ## from the in-memory map. Mirrors lunarblock W41 / ouroboros W43 /
  ## beamchain W46-2 / rustoshi W46. The encoder's `if !finalized` gate
  ## already guards the on-wire bytes; clearing keeps callers honest.
  ##
  ## CRITICAL (W43-1 regression-avoidance): callers MUST set
  ## `finalScriptSig` / `finalScriptWitness` BEFORE invoking this. Clearing
  ## first leaves the input half-finalized if a later step throws.
  ##
  ## We deliberately KEEP `nonWitnessUtxo` / `witnessUtxo` because the
  ## extractor still needs them for amount-bounded signing checks.
  input.partialSigs.clear()
  input.sighashType = none(int32)
  input.redeemScript.setLen(0)
  input.witnessScript.setLen(0)
  input.hdKeypaths.clear()
  input.tapKeySig.setLen(0)
  input.tapInternalKey = default(array[32, byte])

proc finalizePsbtInput*(input: var PsbtInput;
                        spkOverride: openArray[byte] = []): bool =
  ## Finalizer: Finalize an input by combining partial signatures.
  ## Returns true on success, false if data missing or script type
  ## unsupported. Handles:
  ##   - P2WPKH (single-sig)
  ##   - Native P2WSH (multisig + single-CHECKSIG)
  ##   - P2TR key-path
  ##   - P2PKH (single-sig)
  ##   - P2SH-P2WPKH (single-sig)
  ##   - P2SH-P2WSH (multisig + single-CHECKSIG)
  ##   - Legacy P2SH-multisig
  ##
  ## W47: multisig + P2SH-P2WSH branches added to close W42-A
  ## diagnostic. See `parseMultisigScript`/`clearProducerFields` for
  ## design notes.
  ##
  ## `spkOverride`: when the caller already knows the prevout's
  ## scriptPubKey (e.g. dispatch from `finalizePsbt` which can resolve
  ## `nonWitnessUtxo[outpoint.vout]`), pass it here. Used to support
  ## legacy P2SH inputs that ONLY ship `nonWitnessUtxo` (per BIP-174).

  # Skip if already finalized
  if input.isSigned():
    return true

  # Get the scriptPubKey
  var spk: seq[byte]
  if spkOverride.len > 0:
    spk = @spkOverride
  elif input.witnessUtxo.isSome:
    spk = input.witnessUtxo.get().scriptPubKey
  elif input.nonWitnessUtxo.isNone:
    return false
  else:
    # No outpoint context here. Caller must dispatch via `finalizePsbt`
    # for non-witness inputs.
    return false

  # Determine script type and finalize accordingly
  # P2WPKH: OP_0 <20 bytes>
  if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
    # Need exactly one partial signature
    if input.partialSigs.len != 1:
      return false

    for pubkey, sig in input.partialSigs:
      input.finalScriptWitness = @[sig, pubkey]
      clearProducerFields(input)
      return true

  # P2WSH: OP_0 <32 bytes>
  elif spk.len == 34 and spk[0] == 0x00 and spk[1] == 0x20:
    # Need witness script
    if input.witnessScript.len == 0:
      return false

    # W31: refuse to emit a witness referencing a witnessScript that does
    # not commit to spk[2..33]. Without this an attacker who supplied a
    # forged PSBT_IN_WITNESSSCRIPT would extract a "valid"-looking final
    # tx the network rejects, after we've already laundered partialSigs
    # against an attacker-chosen sighash.
    if not verifyP2WSHCommitment(input.witnessScript, spk):
      return false

    # W47: prefer canonical multisig assembly. If the witnessScript parses
    # as M-of-N CHECKMULTISIG, build `[OP_0_byte, sig1, ..., sigM,
    # witness_script]` with sigs in script-pubkey order. Fall back to the
    # single-CHECKSIG layout `[sig, witness_script]` otherwise.
    let parsed = parseMultisigScript(input.witnessScript)
    if parsed.isSome:
      let (m, keys) = parsed.get()
      let sigsOpt = collectMultisigSigsInScriptOrder(input.partialSigs, keys, m)
      if sigsOpt.isNone:
        return false
      var witness: seq[seq[byte]] = newSeqOfCap[seq[byte]](m + 2)
      witness.add(@[])  # CHECKMULTISIG bug-compat empty pad
      for sig in sigsOpt.get():
        witness.add(sig)
      witness.add(input.witnessScript)
      input.finalScriptWitness = witness
      clearProducerFields(input)
      return true
    else:
      # Single-CHECKSIG-style witness script (or non-canonical shape).
      if input.partialSigs.len != 1:
        return false
      for pubkey, sig in input.partialSigs:
        input.finalScriptWitness = @[sig, input.witnessScript]
        clearProducerFields(input)
        return true

  # P2TR: OP_1 <32 bytes>
  elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
    # Key path spend
    if input.tapKeySig.len > 0:
      input.finalScriptWitness = @[input.tapKeySig]
      clearProducerFields(input)
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
      pushToScriptSig(scriptSig, sig)
      pushToScriptSig(scriptSig, pubkey)
      input.finalScriptSig = scriptSig
      clearProducerFields(input)
      return true

  # P2SH: OP_HASH160 <20> OP_EQUAL
  elif spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14:
    # W31: redeemScript must hash to the prevout's script-hash, otherwise a
    # forged PSBT_IN_REDEEMSCRIPT would be embedded into the final scriptSig
    # and the wallet's already-collected partialSigs were produced under an
    # attacker-chosen sighash. Refuse to finalize.
    if input.redeemScript.len == 0:
      return false
    if not verifyP2SHCommitment(input.redeemScript, spk):
      return false

    # P2SH-P2WPKH: redeemScript = OP_0 <20-byte pubkey hash>
    if input.redeemScript.len == 22 and input.redeemScript[0] == 0x00 and
       input.redeemScript[1] == 0x14:
      if input.partialSigs.len != 1:
        return false

      for pubkey, sig in input.partialSigs:
        # Final scriptSig is a single push of the redeem script
        var scriptSig: seq[byte]
        pushToScriptSig(scriptSig, input.redeemScript)
        input.finalScriptSig = scriptSig
        input.finalScriptWitness = @[sig, pubkey]
        clearProducerFields(input)
        return true

    # P2SH-P2WSH: redeemScript = OP_0 <32-byte sha256(witnessScript)>
    if input.redeemScript.len == 34 and input.redeemScript[0] == 0x00 and
       input.redeemScript[1] == 0x20:
      if input.witnessScript.len == 0:
        return false
      # Verify the redeemScript commits to the witnessScript.
      if not verifyP2WSHCommitment(input.witnessScript, input.redeemScript):
        return false

      # Inner witness assembly: same as native P2WSH.
      let parsed = parseMultisigScript(input.witnessScript)
      var witness: seq[seq[byte]]
      if parsed.isSome:
        let (m, keys) = parsed.get()
        let sigsOpt = collectMultisigSigsInScriptOrder(input.partialSigs, keys, m)
        if sigsOpt.isNone:
          return false
        witness = newSeqOfCap[seq[byte]](m + 2)
        witness.add(@[])  # CHECKMULTISIG empty pad
        for sig in sigsOpt.get():
          witness.add(sig)
        witness.add(input.witnessScript)
      else:
        if input.partialSigs.len != 1:
          return false
        for pubkey, sig in input.partialSigs:
          witness = @[sig, input.witnessScript]
          break

      # Outer scriptSig: a single push of the redeemScript.
      var scriptSig: seq[byte]
      pushToScriptSig(scriptSig, input.redeemScript)
      input.finalScriptSig = scriptSig
      input.finalScriptWitness = witness
      clearProducerFields(input)
      return true

    # Legacy P2SH-multisig: redeemScript parses as M-of-N CHECKMULTISIG.
    # Layout: `OP_0 <sig1> ... <sigM> <push(redeemScript)>`. OP_0 is the
    # CHECKMULTISIG empty-pad bug-compat byte. Sigs MUST be in script-
    # pubkey order. Reference: BIP-11 / Core sign.cpp::ProduceSignature.
    let parsed = parseMultisigScript(input.redeemScript)
    if parsed.isSome:
      let (m, keys) = parsed.get()
      let sigsOpt = collectMultisigSigsInScriptOrder(input.partialSigs, keys, m)
      if sigsOpt.isNone:
        return false
      var scriptSig: seq[byte]
      scriptSig.add(0x00'u8)  # OP_0 / empty pad
      for sig in sigsOpt.get():
        pushToScriptSig(scriptSig, sig)
      pushToScriptSig(scriptSig, input.redeemScript)
      input.finalScriptSig = scriptSig
      clearProducerFields(input)
      return true

    return false

  false

proc finalizePsbt*(psbt: var Psbt): bool =
  ## Finalizer: Finalize all inputs.
  ## Returns true if all inputs were finalized.
  ##
  ## W47: resolves prevout scriptPubKey from `nonWitnessUtxo` using the
  ## outpoint (`tx.inputs[i].prevOut.vout`) for legacy / pre-segwit inputs
  ## that don't carry `witnessUtxo`. This is required for the canonical
  ## Core 2-in PSBT fixture (`tools/psbt-multi-input-fixture.json`) where
  ## input 0 is legacy P2SH-multisig + non-witness UTXO only.
  result = true
  for i in 0 ..< psbt.inputs.len:
    var spkOverride: seq[byte]
    if psbt.inputs[i].witnessUtxo.isNone and
       psbt.inputs[i].nonWitnessUtxo.isSome and
       psbt.tx.isSome:
      let prevTx = psbt.inputs[i].nonWitnessUtxo.get()
      let vout = int(psbt.tx.get().inputs[i].prevOut.vout)
      if vout < prevTx.outputs.len:
        spkOverride = prevTx.outputs[vout].scriptPubKey
    if not finalizePsbtInput(psbt.inputs[i], spkOverride):
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

# =============================================================================
# W48: Core-correct analyzepsbt classifier
#
# Mirrors `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT` and
# `bitcoin-core/src/rpc/rawtransaction.cpp::analyzepsbt`.
#
# The legacy `analyzePsbt` above keeps a coarser "any partial sig means
# finalizer" heuristic (callers depend on its `PsbtAnalysis` shape). The
# helpers below — used by the analyzepsbt RPC handler — implement Core's
# precise per-input classification:
#
#   1. final_script_sig or final_script_witness present  -> extractor
#   2. has UTXO + enough partial_sigs (M of N for multisig) -> finalizer
#   3. has UTXO                                          -> signer
#   4. else                                              -> updater
#
# PSBT-level `next` is the MIN per-input role under Core's order:
#   creator < updater < signer < finalizer < extractor   (`psbt.cpp:91-95`).
#
# Reference: hotbuns W47-5 (`b6ccf2a`) `analyzePSBTCore`.
# Reference: camlcoin W41 (`2a22a0e`) `psbt_next_role`.
# =============================================================================

type
  AnalyzedInput* = object
    hasUtxo*: bool
    isFinal*: bool
    nextRole*: string                 ## one of {extractor, finalizer, signer, updater}
    missingSignatures*: seq[seq[byte]]  ## hex-pubkeys whose partial sig is absent (multisig signer-state only)

  AnalyzedPsbt* = object
    inputs*: seq[AnalyzedInput]
    nextRole*: string                 ## min over per-input roles (Core ordering)

proc requiredSigCount*(input: PsbtInput): Option[int] =
  ## Compute the minimum number of partial signatures required to finalize
  ## an input. Mirrors Core's `SignPSBTInput` dummy-sign attempt in
  ## `src/node/psbt.cpp::AnalyzePSBT` — for next-role analysis, only the
  ## missing-sigs count matters.
  ##
  ## - Multisig (P2SH / P2WSH / P2SH-P2WSH): M from the redeem/witness script.
  ## - Taproot key-path: 1 (the schnorr sig).
  ## - Single-sig (P2PKH / P2WPKH / P2SH-P2WPKH): 1.
  ## - No utxo / no script: none (caller treats as "cannot classify").
  if input.witnessScript.len > 0:
    let parsed = parseMultisigScript(input.witnessScript)
    if parsed.isSome:
      return some(parsed.get()[0])
    return some(1)  ## Non-multisig P2WSH: single-sig finalize.
  if input.redeemScript.len > 0:
    let parsed = parseMultisigScript(input.redeemScript)
    if parsed.isSome:
      return some(parsed.get()[0])
    return some(1)  ## Bare P2SH non-multisig (e.g. P2SH-P2WPKH wrapper).
  if input.tapInternalKey != default(array[32, byte]):
    return some(1)
  if input.witnessUtxo.isSome or input.nonWitnessUtxo.isSome:
    return some(1)  ## Plain P2PKH/P2WPKH single-sig.
  none(int)

proc isInputReadyToFinalize*(input: PsbtInput): bool =
  ## Is this input ready for the finalizer step?
  ##
  ## Mirrors Core's "dummy-sign succeeds" branch in `AnalyzePSBT`: when a
  ## non-finalized input has every signature it needs (M-of-N for multisig;
  ## 1 for single-sig; tap_key_sig for taproot), the next role is FINALIZER,
  ## not SIGNER.
  if input.isSigned():
    return false
  if input.tapKeySig.len > 0:
    return true
  let nSigs = input.partialSigs.len
  if nSigs == 0:
    return false
  let needed = requiredSigCount(input)
  if needed.isNone:
    ## Cannot classify; mirror hotbuns/camlcoin fallback — don't regress
    ## single-sig inputs by demanding a script we don't have.
    return nSigs >= 1
  nSigs >= needed.get()

proc inputNextRoleCore*(input: PsbtInput): string =
  ## Per-input next role (Core-shape strings).
  ## Mirrors `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT` branching.
  if input.isSigned():
    return "extractor"
  let hasUtxo = input.witnessUtxo.isSome or input.nonWitnessUtxo.isSome
  if not hasUtxo:
    return "updater"
  if isInputReadyToFinalize(input):
    return "finalizer"
  "signer"

proc roleRank(role: string): int =
  ## Core ordering: creator < updater < signer < finalizer < extractor.
  case role
  of "creator": 0
  of "updater": 1
  of "signer": 2
  of "finalizer": 3
  of "extractor": 4
  else: 4

proc analyzePsbtCore*(psbt: Psbt): AnalyzedPsbt =
  ## Compute the Core-shape `analyzepsbt` result.
  ##
  ## Per-input `next` is computed via `inputNextRoleCore`. PSBT-level
  ## `next` is the minimum per-input role under Core's ordering. For
  ## multisig signer-state inputs, `missingSignatures` lists pubkeys
  ## whose partial sig is absent (informational; harness only checks
  ## the top-level `.next`).
  result.nextRole = "extractor"
  for inp in psbt.inputs:
    var ai: AnalyzedInput
    ai.hasUtxo = inp.witnessUtxo.isSome or inp.nonWitnessUtxo.isSome
    ai.isFinal = inp.isSigned()
    ai.nextRole = inputNextRoleCore(inp)

    if ai.nextRole == "signer":
      ## Best-effort missing-pubkey list for multisig signer-state inputs.
      let script =
        if inp.witnessScript.len > 0: inp.witnessScript
        elif inp.redeemScript.len > 0: inp.redeemScript
        else: @[]
      if script.len > 0:
        let parsed = parseMultisigScript(script)
        if parsed.isSome:
          let (_, keys) = parsed.get()
          for pk in keys:
            if pk notin inp.partialSigs:
              ai.missingSignatures.add(pk)

    if roleRank(ai.nextRole) < roleRank(result.nextRole):
      result.nextRole = ai.nextRole
    result.inputs.add(ai)

  if psbt.inputs.len == 0:
    result.nextRole = "creator"

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
