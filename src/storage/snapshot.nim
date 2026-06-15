## assumeUTXO snapshot support — Bitcoin Core byte-compatible
##
## Implements the same on-disk snapshot format as Bitcoin Core
## (`bitcoin-core/src/node/utxo_snapshot.{h,cpp}` +
## `bitcoin-core/src/rpc/blockchain.cpp::WriteUTXOSnapshot`).
##
## File layout:
##   header:
##     5  bytes   magic   = "utxo\xff"
##     2  bytes   version = uint16 LE (= 2)
##     4  bytes   network magic (e.g. mainnet 0xf9 0xbe 0xb4 0xd9)
##     32 bytes   base block hash (raw bytes — Core writes uint256 internally)
##     8  bytes   coins_count = uint64 LE
##   body: groups by txid, each group is
##     32 bytes   txid (raw, internal byte order)
##     compactsize  coins_per_txid (n entries)
##     for each entry:
##         compactsize    vout
##         VARINT         code = (height * 2) | coinbase     (Bitcoin VARINT, NOT compactsize)
##         VARINT         CompressAmount(value)
##         ScriptCompression  scriptPubKey  (special-case 0..5, else VARINT(size+6) + raw bytes)
##
## Bitcoin VARINT differs from CompactSize: 7 data bits per byte, MSB=continuation.
## See `bitcoin-core/src/serialize.h::WriteVarInt`.
##
## Per-coin helpers replicate `Coin::Serialize`, `AmountCompression`,
## `ScriptCompression`, `CompressAmount`, `CompressScript`
## (`bitcoin-core/src/coins.h`, `bitcoin-core/src/compressor.{h,cpp}`).

import std/[options, tables, os, algorithm, posix]
import chronos
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../crypto/muhash
import ../crypto/secp256k1 as snapshot_secp
import ../consensus/params
import ./db
import ./chainstate

export chainstate

type
  SnapshotError* = object of CatchableError

  ## Snapshot validation state — tracks whether a snapshot chainstate has
  ## been fully validated by the background chain.
  Assumeutxo* = enum
    auValidated    ## Fully validated from genesis (or background validation done)
    auUnvalidated  ## Loaded from snapshot, background validation pending
    auInvalid      ## Snapshot validation failed (hash mismatch)

  ## Metadata at the head of every snapshot file. Fields match
  ## `bitcoin-core/src/node/utxo_snapshot.h::SnapshotMetadata`.
  SnapshotMetadata* = object
    version*: uint16
    networkMagic*: array[4, byte]
    baseBlockhash*: BlockHash
    coinsCount*: uint64

  ## A single coin in the snapshot — the per-coin equivalent of
  ## (COutPoint, Coin) from Bitcoin Core.
  SnapshotCoin* = object
    outpoint*: OutPoint
    output*: TxOut
    height*: int32
    isCoinbase*: bool

  ## Open snapshot file (read or write). Per-coin reads are streaming
  ## so we don't have to load the entire UTXO set into memory.
  SnapshotFile* = ref object
    path*: string
    metadata*: SnapshotMetadata
    file*: File
    coinsRead*: uint64
    coinsWritten*: uint64
    # Read-side streaming state for the txid-grouped layout.
    pendingTxid*: TxId
    pendingRemaining*: uint64

  ## Role of a chainstate in the dual-chainstate (assumeUTXO) model.
  ## Mirrors Bitcoin Core's `ChainstateRole` (validation.h): the genesis-rooted
  ## chainstate that re-validates the snapshot is the BACKGROUND chainstate; the
  ## snapshot-rooted chainstate the node serves from is the SNAPSHOT chainstate.
  ## A node with no active snapshot has a single chainstate with role `csrNormal`.
  ChainstateRole* = enum
    csrNormal       ## Single fully-validated chainstate (no snapshot active).
    csrSnapshot     ## Snapshot-rooted active chainstate (Core's m_from_snapshot).
    csrBackground   ## Genesis-rooted background chainstate re-validating a snapshot.

  SnapshotChainState* = ref object
    chainState*: ChainState
    assumeutxo*: Assumeutxo
    snapshotBlockhash*: Option[BlockHash]
    targetUtxoHash*: Option[array[32, byte]]
    role*: ChainstateRole   ## csrSnapshot once a snapshot is loaded into it.

  BackgroundValidation* = ref object
    running*: bool
    progress*: int32
    targetHeight*: int32
    snapshotHash*: array[32, byte]

  ## A live snapshot activation: the snapshot (active) chainstate, the SECOND
  ## background chainstate with its OWN separate coins store, and the driver
  ## that re-connects genesis->base into that store and re-derives the UTXO hash.
  ##
  ## Mirrors the triple Core threads through `ActivateSnapshot`(validation.cpp:5588)
  ## / `AddChainstate`(:6170): the unvalidated snapshot chainstate, the validated
  ## background chainstate targeting the snapshot base, and the work that
  ## independently recomputes the snapshot's HASH_SERIALIZED.
  SnapshotActivation* = ref object
    snapshot*: SnapshotChainState        ## Active, Unvalidated snapshot chainstate.
    background*: ChainState              ## Background chainstate — SEPARATE store.
    bgValidation*: BackgroundValidation  ## Drives the genesis->base re-connect.
    baseHeight*: int32                   ## Snapshot base height (= au_data.height).
    assumedHash*: array[32, byte]        ## au_data.hash_serialized to match against.
    bgDbPath*: string                    ## On-disk dir of the bg coins store.

  SnapshotValidationResult* = enum
    svrNotReady
    svrValid
    svrInvalid

const
  ## Magic bytes — see Bitcoin Core SNAPSHOT_MAGIC_BYTES.
  SnapshotMagic*: array[5, byte] = [byte('u'), byte('t'), byte('x'), byte('o'), 0xFF'u8]
  ## On-disk format version (Bitcoin Core SnapshotMetadata::VERSION).
  SnapshotVersion*: uint16 = 2
  ## ScriptCompression special-case prefix count, see compressor.h.
  ScriptSpecialScripts*: uint64 = 6

# ============================================================================
# Bitcoin VARINT (NOT CompactSize) — see bitcoin-core/src/serialize.h
# ============================================================================

## writeVarInt and readVarInt are defined in ../primitives/serialize.nim
## (imported via the `serialize` module above) and available here without
## redeclaration.  They were previously duplicated in this file; the
## canonical versions in serialize.nim are now used by both snapshot and
## undo serialization paths.

# ============================================================================
# Amount compression — bitcoin-core/src/compressor.cpp
# ============================================================================

proc compressAmount*(n: uint64): uint64 =
  ## Identical to Core CompressAmount.
  if n == 0:
    return 0
  var v = n
  var e = 0
  while (v mod 10) == 0 and e < 9:
    v = v div 10
    inc e
  if e < 9:
    let d = int(v mod 10)
    doAssert d >= 1 and d <= 9
    v = v div 10
    return 1 + (v * 9 + uint64(d - 1)) * 10 + uint64(e)
  else:
    return 1 + (v - 1) * 10 + 9

proc decompressAmount*(x: uint64): uint64 =
  ## Identical to Core DecompressAmount.
  if x == 0:
    return 0
  var rem = x - 1
  let e = int(rem mod 10)
  rem = rem div 10
  var n: uint64 = 0
  if e < 9:
    let d = int(rem mod 9) + 1
    rem = rem div 9
    n = rem * 10 + uint64(d)
  else:
    n = rem + 1
  for _ in 0 ..< e:
    n *= 10
  n

# ============================================================================
# Script compression — see compressor.{h,cpp}
# ============================================================================
#
# Special cases (1-byte tag + payload):
#   0x00  P2PKH:  OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG  -> 21 bytes
#   0x01  P2SH:   OP_HASH160 <20> OP_EQUAL                            -> 21 bytes
#   0x02  Compressed P2PK (pubkey starts with 0x02)                   -> 33 bytes
#   0x03  Compressed P2PK (pubkey starts with 0x03)                   -> 33 bytes
#   0x04  Uncompressed P2PK, even Y                                   -> 33 bytes
#   0x05  Uncompressed P2PK, odd Y                                    -> 33 bytes
# Otherwise:
#   VARINT(script.len + 6) followed by raw script bytes.
#
# Encoder: recognizes P2PKH, P2SH, compressed P2PK (tags 0x00..0x03), and
# uncompressed P2PK (tags 0x04/0x05). For uncompressed P2PK the encoder
# validates via a secp256k1 round-trip (build compressed form, call
# decompressPubkey to confirm the point is on the curve), then emits
# tag 0x04|(Y_lsb) + X[32] — matching Bitcoin Core compressor.cpp:71-82.
# Invalid uncompressed pubkeys fall through to the generic encoding.
# Decoder: handles all 6 special cases. Tags 0x04/0x05 invoke libsecp256k1 to
# recover the full y-coordinate via secp256k1_ec_pubkey_parse +
# secp256k1_ec_pubkey_serialize(SECP256K1_EC_UNCOMPRESSED) — matches Bitcoin
# Core's `compressor.cpp::DecompressScript` for nSize 0x04/0x05.

const
  OpDup = 0x76'u8
  OpHash160 = 0xA9'u8
  OpEqualverify = 0x88'u8
  OpEqual = 0x87'u8
  OpChecksig = 0xAC'u8

proc tryCompressScript(script: openArray[byte], outBytes: var seq[byte]): bool =
  ## Attempts to encode a script using one of the special cases.
  ## Returns true and fills `outBytes` (1-byte tag + 20/32 byte payload) if so.
  # P2PKH: OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  if script.len == 25 and script[0] == OpDup and script[1] == OpHash160 and
     script[2] == 0x14'u8 and script[23] == OpEqualverify and script[24] == OpChecksig:
    outBytes = newSeq[byte](21)
    outBytes[0] = 0x00'u8
    for i in 0 ..< 20: outBytes[1 + i] = script[3 + i]
    return true
  # P2SH: OP_HASH160 0x14 <20 bytes> OP_EQUAL
  if script.len == 23 and script[0] == OpHash160 and script[1] == 0x14'u8 and
     script[22] == OpEqual:
    outBytes = newSeq[byte](21)
    outBytes[0] = 0x01'u8
    for i in 0 ..< 20: outBytes[1 + i] = script[2 + i]
    return true
  # Compressed P2PK: 0x21 <33 byte pubkey starting 0x02|0x03> OP_CHECKSIG
  if script.len == 35 and script[0] == 0x21'u8 and script[34] == OpChecksig and
     (script[1] == 0x02'u8 or script[1] == 0x03'u8):
    outBytes = newSeq[byte](33)
    outBytes[0] = script[1]
    for i in 0 ..< 32: outBytes[1 + i] = script[2 + i]
    return true
  # Uncompressed P2PK: 0x41 <0x04 || X[32] || Y[32]> OP_CHECKSIG (67 bytes).
  # Bitcoin Core compressor.cpp:46-52 + 76-82 — IsToPubKey accepts this form,
  # validates via CPubKey::IsFullyValid(), then encodes as tag 0x04|(Y_lsb) + X[32].
  # Layout: script[0]=0x41(push 65), script[1]=0x04, script[2..33]=X, script[34..65]=Y,
  #         script[66]=OP_CHECKSIG. Y-parity = LSB of script[65] (last byte of Y).
  if script.len == 67 and script[0] == 0x41'u8 and script[1] == 0x04'u8 and
     script[66] == OpChecksig:
    # Validate pubkey via libsecp256k1: build compressed form (0x02|Y_lsb || X),
    # attempt parse (secp256k1_ec_pubkey_parse accepts compressed/uncompressed).
    # If decompressPubkey on the compressed form succeeds, the curve point is valid.
    # This mirrors CPubKey::IsFullyValid() in Bitcoin Core.
    let yLsb = script[65] and 0x01'u8
    var compressedKey = newSeq[byte](33)
    compressedKey[0] = 0x02'u8 or yLsb
    for i in 0 ..< 32: compressedKey[1 + i] = script[2 + i]
    let decompressed = snapshot_secp.decompressPubkey(compressedKey)
    if decompressed.len == 65:
      # Valid pubkey — encode as tag 0x04|(Y_lsb) + X[32] (33 bytes).
      outBytes = newSeq[byte](33)
      outBytes[0] = 0x04'u8 or yLsb
      for i in 0 ..< 32: outBytes[1 + i] = script[2 + i]
      return true
    # Invalid curve point — fall through to generic encoding.
  return false

proc writeCompressedScript*(w: var BinaryWriter, script: openArray[byte]) =
  ## Serialize `script` using ScriptCompression (Core's TxOutCompression path).
  var compressed: seq[byte]
  if tryCompressScript(script, compressed):
    # Special case: tag is in compressed[0], it's already the encoded length-tag.
    # Bitcoin Core writes the tag as the VARINT itself (since 0x00..0x05 < 0xFD).
    w.writeBytes(compressed)
    return
  # Generic case: VARINT(size + 6) then raw script bytes.
  w.writeVarInt(uint64(script.len) + ScriptSpecialScripts)
  w.writeBytes(script)

proc decompressSpecialScript(tag: uint64, payload: openArray[byte]): seq[byte] =
  ## Inverse of `tryCompressScript`. Handles all 6 special cases.
  case tag
  of 0x00:
    doAssert payload.len == 20
    result = newSeq[byte](25)
    result[0] = OpDup; result[1] = OpHash160; result[2] = 0x14'u8
    for i in 0 ..< 20: result[3 + i] = payload[i]
    result[23] = OpEqualverify; result[24] = OpChecksig
  of 0x01:
    doAssert payload.len == 20
    result = newSeq[byte](23)
    result[0] = OpHash160; result[1] = 0x14'u8
    for i in 0 ..< 20: result[2 + i] = payload[i]
    result[22] = OpEqual
  of 0x02, 0x03:
    doAssert payload.len == 32
    result = newSeq[byte](35)
    result[0] = 0x21'u8
    result[1] = byte(tag)
    for i in 0 ..< 32: result[2 + i] = payload[i]
    result[34] = OpChecksig
  of 0x04, 0x05:
    # Uncompressed P2PK. Recover the y-coordinate via libsecp256k1 and emit
    # `0x41 <65-byte pubkey> OP_CHECKSIG` (67 bytes), matching Bitcoin Core's
    # `compressor.cpp::DecompressScript` for nSize 0x04/0x05:
    #   build 33-byte compressed pubkey: (0x02 | (tag - 0x02)) || x[32]
    #   pubkey_parse, pubkey_serialize(UNCOMPRESSED) -> 65 bytes
    #   wrap as raw P2PK script.
    doAssert payload.len == 32
    var compressed = newSeq[byte](33)
    compressed[0] = 0x02'u8 or byte(tag - 0x02)
    for i in 0 ..< 32: compressed[1 + i] = payload[i]
    let uncompressed = snapshot_secp.decompressPubkey(compressed)
    if uncompressed.len != 65:
      # Core returns false from DecompressScript here; we propagate as an
      # error so the snapshot load aborts loudly rather than silently
      # corrupting the UTXO set.
      raise newException(SnapshotError,
        "ScriptCompression: invalid x-coordinate for uncompressed P2PK (tag " & $tag & ")")
    result = newSeq[byte](67)
    result[0] = 0x41'u8  # push 65 bytes
    for i in 0 ..< 65: result[1 + i] = uncompressed[i]
    result[66] = OpChecksig
  else:
    raise newException(SnapshotError, "unknown ScriptCompression tag: " & $tag)

proc specialScriptSize(tag: uint64): int =
  case tag
  of 0x00, 0x01: 20
  of 0x02, 0x03, 0x04, 0x05: 32
  else: 0

proc readCompressedScript*(r: var BinaryReader): seq[byte] =
  ## Inverse of writeCompressedScript.
  let tag = r.readVarInt()
  if tag < ScriptSpecialScripts:
    let payloadLen = specialScriptSize(tag)
    if payloadLen == 0:
      raise newException(SnapshotError, "invalid ScriptCompression special tag")
    let payload = r.readBytes(payloadLen)
    return decompressSpecialScript(tag, payload)
  let scriptLen = tag - ScriptSpecialScripts
  if scriptLen > 16505'u64:  # MAX_SCRIPT_SIZE-ish guard, see compressor.h
    raise newException(SnapshotError, "ScriptCompression: script too long: " & $scriptLen)
  return r.readBytes(int(scriptLen))

# ============================================================================
# Per-coin (in-tx) serialization — see Coin::Serialize / TxOutCompression
# ============================================================================

proc writeCoinBody*(w: var BinaryWriter, coin: SnapshotCoin) =
  ## Serialize a single coin in Core's per-coin layout, NOT including the
  ## outer txid (handled by the txid-grouping layer). Layout:
  ##   compactsize(vout) | VARINT(code) | VARINT(CompressAmount(value)) | scriptPubKey
  w.writeCompactSize(uint64(coin.outpoint.vout))
  let code = uint64(coin.height) * 2'u64 + (if coin.isCoinbase: 1'u64 else: 0'u64)
  w.writeVarInt(code)
  w.writeVarInt(compressAmount(uint64(int64(coin.output.value))))
  w.writeCompressedScript(coin.output.scriptPubKey)

proc readCoinBody*(r: var BinaryReader, txid: TxId): SnapshotCoin =
  ## Inverse of writeCoinBody — the outer txid is fed in by the caller.
  result.outpoint.txid = txid
  result.outpoint.vout = uint32(r.readCompactSize())
  let code = r.readVarInt()
  result.height = int32(code shr 1)
  result.isCoinbase = (code and 1'u64) == 1
  let compressedAmount = r.readVarInt()
  result.output.value = Satoshi(int64(decompressAmount(compressedAmount)))
  result.output.scriptPubKey = r.readCompressedScript()

# ============================================================================
# Snapshot metadata serialization
# ============================================================================

proc writeSnapshotMetadata*(w: var BinaryWriter, meta: SnapshotMetadata) =
  ## Serialize the file header. Magic (5) | version (2 LE) | netmagic (4) |
  ## base blockhash (32 raw) | coinsCount (8 LE).
  w.writeBytes(SnapshotMagic)
  w.writeUint16LE(meta.version)
  w.writeBytes(meta.networkMagic)
  w.writeBlockHash(meta.baseBlockhash)
  w.writeUint64LE(meta.coinsCount)

proc readSnapshotMetadata*(r: var BinaryReader): SnapshotMetadata =
  let magic = r.readBytes(5)
  for i in 0 ..< 5:
    if magic[i] != SnapshotMagic[i]:
      raise newException(SnapshotError, "invalid snapshot magic bytes")
  result.version = r.readUint16LE()
  if result.version != SnapshotVersion:
    raise newException(SnapshotError, "unsupported snapshot version: " & $result.version)
  for i in 0 .. 3:
    result.networkMagic[i] = r.readUint8()
  result.baseBlockhash = r.readBlockHash()
  result.coinsCount = r.readUint64LE()

# ============================================================================
# Snapshot file I/O
# ============================================================================

proc openSnapshotForWrite*(path: string, meta: SnapshotMetadata): SnapshotFile =
  result = SnapshotFile(path: path, metadata: meta, coinsWritten: 0)
  result.file = open(path, fmWrite)
  var w = BinaryWriter()
  w.writeSnapshotMetadata(meta)
  discard result.file.writeBytes(w.data, 0, w.data.len)

proc syncSnapshotFile*(sf: SnapshotFile) =
  ## Flush the user-space buffer and fsync the underlying file descriptor
  ## so the snapshot bytes are durable on disk before any subsequent
  ## atomic-rename. Mirrors Bitcoin Core's `Fdatasync` / `fclose` flush
  ## in rpc/blockchain.cpp::dumptxoutset before the temppath → path rename.
  if sf.file != nil:
    sf.file.flushFile()
    let fh = sf.file.getOsFileHandle()
    discard posix.fsync(cint(fh))

proc writeTxidGroup*(sf: SnapshotFile, txid: TxId, coins: seq[SnapshotCoin]) =
  ## Write one txid-group: txid | compactsize(coins.len) | per-coin bodies.
  ## Mirrors the lambda in WriteUTXOSnapshot (rpc/blockchain.cpp:3303).
  doAssert coins.len > 0
  var w = BinaryWriter()
  w.writeTxId(txid)
  w.writeCompactSize(uint64(coins.len))
  for c in coins:
    w.writeCoinBody(c)
  discard sf.file.writeBytes(w.data, 0, w.data.len)
  sf.coinsWritten += uint64(coins.len)

proc openSnapshotForRead*(path: string): SnapshotFile =
  if not fileExists(path):
    raise newException(SnapshotError, "snapshot file not found: " & path)
  result = SnapshotFile(path: path, coinsRead: 0)
  result.file = open(path, fmRead)
  # Header is fixed-size: 5 + 2 + 4 + 32 + 8 = 51 bytes.
  var headerBytes = newSeq[byte](51)
  let n = result.file.readBytes(headerBytes, 0, 51)
  if n != 51:
    result.file.close()
    raise newException(SnapshotError, "truncated snapshot header")
  var r = BinaryReader(data: headerBytes, pos: 0)
  result.metadata = r.readSnapshotMetadata()
  result.pendingRemaining = 0

proc readBytesExact(f: File, n: int): seq[byte] =
  result = newSeq[byte](n)
  if n == 0: return
  let got = f.readBytes(result, 0, n)
  if got != n:
    raise newException(SnapshotError, "truncated snapshot body")

proc readCompactSizeStream(f: File): uint64 =
  ## Read CompactSize directly from the file stream — needed because per-coin
  ## payloads are variable size and we don't pre-buffer the body.
  let first = readBytesExact(f, 1)[0]
  if first < 0xFD:
    return uint64(first)
  elif first == 0xFD:
    let b = readBytesExact(f, 2)
    return uint64(b[0]) or (uint64(b[1]) shl 8)
  elif first == 0xFE:
    let b = readBytesExact(f, 4)
    return uint64(b[0]) or (uint64(b[1]) shl 8) or
           (uint64(b[2]) shl 16) or (uint64(b[3]) shl 24)
  else:
    let b = readBytesExact(f, 8)
    var v: uint64 = 0
    for i in 0 .. 7:
      v = v or (uint64(b[i]) shl (i * 8))
    return v

proc readVarIntStream(f: File): uint64 =
  var n: uint64 = 0
  while true:
    let ch = readBytesExact(f, 1)[0]
    if n > (high(uint64) shr 7):
      raise newException(SnapshotError, "VARINT overflow")
    n = (n shl 7) or uint64(ch and 0x7F)
    if (ch and 0x80) != 0:
      if n == high(uint64):
        raise newException(SnapshotError, "VARINT overflow")
      inc n
    else:
      return n

proc readScriptStream(f: File): seq[byte] =
  let tag = readVarIntStream(f)
  if tag < ScriptSpecialScripts:
    let payloadLen = specialScriptSize(tag)
    if payloadLen == 0:
      raise newException(SnapshotError, "invalid ScriptCompression special tag")
    let payload = readBytesExact(f, payloadLen)
    return decompressSpecialScript(tag, payload)
  let scriptLen = tag - ScriptSpecialScripts
  if scriptLen > 16505'u64:
    raise newException(SnapshotError, "ScriptCompression: script too long")
  return readBytesExact(f, int(scriptLen))

proc readCoinStream(sf: SnapshotFile, txid: TxId): SnapshotCoin =
  ## Stream-read one (vout, code, amount, script) tuple after the txid header.
  result.outpoint.txid = txid
  result.outpoint.vout = uint32(readCompactSizeStream(sf.file))
  let code = readVarIntStream(sf.file)
  result.height = int32(code shr 1)
  result.isCoinbase = (code and 1'u64) == 1
  let compressedAmount = readVarIntStream(sf.file)
  result.output.value = Satoshi(int64(decompressAmount(compressedAmount)))
  result.output.scriptPubKey = readScriptStream(sf.file)

proc readCoin*(sf: SnapshotFile): Option[SnapshotCoin] =
  ## Read the next coin. None when all `coinsCount` entries have been returned.
  if sf.coinsRead >= sf.metadata.coinsCount:
    return none(SnapshotCoin)
  if sf.pendingRemaining == 0:
    # Start a fresh txid group: read txid + compactsize(count).
    let txidBytes = readBytesExact(sf.file, 32)
    var txid: array[32, byte]
    for i in 0 ..< 32: txid[i] = txidBytes[i]
    sf.pendingTxid = TxId(txid)
    sf.pendingRemaining = readCompactSizeStream(sf.file)
    if sf.pendingRemaining == 0:
      raise newException(SnapshotError, "snapshot txid group with zero coins")
    # B4: coins_per_txid > coins_left group overcount detection
    # (bitcoin-core/src/validation.cpp:5804-5806).
    # Reject if a single txid group claims more coins than remain in the header count.
    let coinsLeft = sf.metadata.coinsCount - sf.coinsRead
    if sf.pendingRemaining > coinsLeft:
      raise newException(SnapshotError,
        "Mismatch in coins count in snapshot metadata and actual snapshot data")
  let coin = sf.readCoinStream(sf.pendingTxid)
  dec sf.pendingRemaining
  inc sf.coinsRead
  some(coin)

proc close*(sf: SnapshotFile) =
  if sf.file != nil:
    sf.file.close()
    sf.file = nil

# ============================================================================
# Snapshot creation (dumptxoutset)
# ============================================================================

proc createSnapshot*(
    cs: ChainState,
    path: string,
    params: ConsensusParams
): tuple[coinsWritten: uint64, baseHash: BlockHash, baseHeight: int32, txoutsetHash: array[32, byte]] =
  ## Create a UTXO snapshot from the current chainstate UTXO cache.
  ## Mirrors the layout of `WriteUTXOSnapshot` in rpc/blockchain.cpp.
  ##
  ## Atomic write protocol: bytes go to "<path>.incomplete", we fsync the
  ## fd, then rename to <path>. Mirrors Bitcoin Core's
  ## `temppath = path + ".incomplete"` flow in
  ## rpc/blockchain.cpp::dumptxoutset so that an operator copying mid-dump
  ## never sees a torn file, and a SIGKILL during dump leaves only the
  ## .incomplete artifact (cleaned up here on any error path).
  ##
  ## NOTE: a production-grade implementation would iterate the on-disk
  ## leveldb-equivalent (rocksdb cfUtxo) using a cursor; nimrod's db.nim
  ## doesn't expose iteration FFI yet, so we currently dump the in-memory
  ## utxoCache. This still produces a Core-byte-compatible file for any
  ## coins that *are* in the cache, which is sufficient for round-trip tests.
  ##
  ## Genesis coinbase is intentionally excluded: Bitcoin Core treats the
  ## genesis block's coinbase output as un-spendable and never adds it to
  ## the UTXO set (see bitcoin-core/src/validation.cpp:2337-2343 — Core
  ## special-cases the genesis block to skip ConnectBlock entirely). nimrod
  ## DOES connect the genesis block via connectBlock(genesis, 0), so the
  ## coin lives in our cache; we filter it out here to match Core's dump.

  # Compute the genesis coinbase txid (= merkle root of the single-tx genesis
  # block). We compare against this to identify the unspendable genesis coin.
  let genesisBlk = buildGenesisBlock(params)
  let genesisCoinbaseTxid = genesisBlk.txs[0].txid()

  var coins: seq[SnapshotCoin] = @[]
  for op, entry in cs.utxoCache:
    # Skip the genesis coinbase output — Core never has this in its UTXO set.
    if entry.height == 0 and entry.isCoinbase and
       op.txid == genesisCoinbaseTxid:
      continue
    # Defensive: skip provably unspendable outputs at dump time too. The
    # AddCoins-equivalent path (connectBlock / connectBlockIBD / applyBlock)
    # already filters these, but legacy datadirs created before that fix may
    # have OP_RETURN or oversize coins persisted. Belt-and-suspenders so we
    # always produce Core-byte-compatible dumps regardless of chainstate
    # provenance.
    if isUnspendable(entry.output.scriptPubKey):
      continue
    coins.add(SnapshotCoin(
      outpoint: op,
      output: entry.output,
      height: entry.height,
      isCoinbase: entry.isCoinbase
    ))

  # Group by txid (Core relies on leveldb sort order; we sort explicitly).
  coins.sort do (a, b: SnapshotCoin) -> int:
    let aT = array[32, byte](a.outpoint.txid)
    let bT = array[32, byte](b.outpoint.txid)
    for i in 0 ..< 32:
      if aT[i] != bT[i]:
        return int(aT[i]) - int(bT[i])
    return int(a.outpoint.vout) - int(b.outpoint.vout)

  let coinsCount = uint64(coins.len)

  let meta = SnapshotMetadata(
    version: SnapshotVersion,
    networkMagic: params.networkMagic,
    baseBlockhash: cs.bestBlockHash,
    coinsCount: coinsCount
  )

  # Atomic-write protocol (see proc doc above): write to <path>.incomplete,
  # fsync, rename. On any error in this block we best-effort delete the
  # temp file before re-raising.
  let tmpPath = path & ".incomplete"
  let sf = openSnapshotForWrite(tmpPath, meta)
  var renamed = false
  defer:
    sf.close()
    if not renamed and fileExists(tmpPath):
      try: removeFile(tmpPath) except CatchableError: discard

  # Walk by txid groups, writing the snapshot file AND streaming each coin's
  # canonical `TxOutSer` bytes through a `HashWriter` (SHA256d) for the
  # `hash_serialized` commitment.
  #
  # Per `bitcoin-core/src/kernel/coinstats.cpp:161-163` and
  # `bitcoin-core/src/validation.cpp:5901-5915`, the assumeutxo strict gate
  # uses `CoinStatsHashType::HASH_SERIALIZED`, which is `HashWriter` over
  # canonical-order `TxOutSer` bytes. MuHash3072 is the
  # `gettxoutsetinfo hash_type=muhash` path and is NOT what `loadtxoutset`
  # compares against `AssumeutxoData::hash_serialized`. The byte stream fed
  # to either hash function is identical (both use `TxOutSer`), only the
  # outer hash differs.
  var hw = initHashWriter()
  var i = 0
  while i < coins.len:
    var j = i + 1
    while j < coins.len and coins[j].outpoint.txid == coins[i].outpoint.txid:
      inc j
    var group = newSeq[SnapshotCoin](j - i)
    for k in 0 ..< (j - i):
      group[k] = coins[i + k]
    sf.writeTxidGroup(group[0].outpoint.txid, group)
    for c in group:
      let coinBytes = serializeCoinForHash(
        c.outpoint, int64(c.output.value), c.output.scriptPubKey,
        c.height, c.isCoinbase
      )
      hw.update(coinBytes)
    i = j

  # Durability: flush user-space buffer + fsync the underlying fd before
  # the atomic rename. Without this, a power loss between rename and
  # flush could leave <path> visible with zero-length or torn contents.
  sf.syncSnapshotFile()
  sf.close()

  # Atomic rename: tmp -> final. After this point the snapshot file is
  # visible to any concurrent reader; up until now an observer would only
  # see the .incomplete temp.
  moveFile(tmpPath, path)
  renamed = true

  let txoutsetHash = if coins.len > 0: hw.finalizeHash()
                     else: default(array[32, byte])

  result = (coinsWritten: coinsCount,
            baseHash: cs.bestBlockHash,
            baseHeight: cs.bestHeight,
            txoutsetHash: txoutsetHash)

# ============================================================================
# Snapshot loading (loadtxoutset)
# ============================================================================

proc validateSnapshotMetadata*(
    meta: SnapshotMetadata,
    params: ConsensusParams,
    assumeutxoData: seq[AssumeutxoData]
): tuple[valid: bool, data: Option[AssumeutxoData], error: string] =
  ## Core-strict whitelist check (bitcoin-core/src/validation.cpp:5775-5780).
  ## The snapshot's base blockhash must match one of the hardcoded
  ## assumeutxo entries; otherwise the load is refused with the exact
  ## Core-format error message.
  if meta.networkMagic != params.networkMagic:
    return (false, none(AssumeutxoData), "network magic mismatch")
  for d in assumeutxoData:
    if d.blockhash == meta.baseBlockhash:
      return (true, some(d), "")
  # Blockhash not in the assumeutxo whitelist. Core reports the snapshot's
  # block height; we don't have that locally for an unknown blockhash, so we
  # report 0 to signal "not recognized". The error format matches Core
  # verbatim so downstream tooling can pattern-match it.
  return (false, none(AssumeutxoData),
          "Assumeutxo height in snapshot metadata not recognized (0) - " &
          "refusing to load snapshot")

## Chunk size for the per-coin WriteBatch (Phase 2 of FIX-D). Matches
## ouroboros's `_CHUNK_SIZE = 10_000` so the cross-impl crash-recovery
## semantics are identical. 10K coins per batch keeps the RocksDB
## WriteBatch memory bounded (~1–2 MB) and cuts the per-coin overhead
## while still bounding how much progress is lost on a mid-load crash.
const SnapshotLoadChunkSize* = 10_000

proc loadSnapshot*(
    path: string,
    targetCs: var ChainState,
    params: ConsensusParams,
    assumeutxoData: seq[AssumeutxoData]
): tuple[success: bool, coinsLoaded: uint64, error: string] =
  ## Load a Core-format UTXO snapshot into `targetCs`.
  ##
  ## Atomicity (FIX-D, chainstate atomicity family 2026-05-26 — analog of
  ## ouroboros commit `2b76e0e`):
  ##
  ##   Phase 1 (begin):  write the SNAPSHOT_LOAD_IN_PROGRESS marker via
  ##                     `writeSynced` (WAL + fsync) BEFORE any per-coin
  ##                     write. After this returns, a crash is recoverable —
  ##                     next-boot `recoverFromSnapshotCrash` (wired into
  ##                     `openChainDb`) detects the marker, wipes the partial
  ##                     UTXO CF, and resets the tip to the genesis sentinel.
  ##                     The operator must then re-run `loadtxoutset`.
  ##   Phase 2 (chunks): apply up to `SnapshotLoadChunkSize` coins per
  ##                     RocksDB WriteBatch. RocksDB applies the WriteBatch
  ##                     atomically across CFs, so per-chunk writes are
  ##                     all-or-nothing. The marker stays set across chunks.
  ##   Phase 3 (commit): a SINGLE atomic + synced WriteBatch fuses tip
  ##                     update + marker delete. Pre-FIX-D the tip write and
  ##                     the per-coin writes were independent — a SIGKILL
  ##                     could leave a mix of partial-snapshot UTXOs with
  ##                     the old tip pointer still on disk. Post-FIX-D the
  ##                     three states (no-load-started, load-in-progress,
  ##                     load-committed) are crash-distinguishable.
  ##
  ## Pre-FIX-D the loader did per-coin direct `putUtxo` (one put per coin,
  ## no batching, no marker) followed by a separate `updateBestBlock`. See
  ## `CORE-PARITY-AUDIT/_chainstate-atomicity-family-2026-05-26.md` for the
  ## full family context.
  var sf: SnapshotFile
  try:
    sf = openSnapshotForRead(path)
  except SnapshotError as e:
    return (false, 0'u64, e.msg)
  except IOError as e:
    return (false, 0'u64, "failed to open snapshot: " & e.msg)

  defer: sf.close()

  let validation = validateSnapshotMetadata(sf.metadata, params, assumeutxoData)
  if not validation.valid:
    return (false, 0'u64, validation.error)
  let assumeData = validation.data.get()

  # B8: Work-exceeds-active-chainstate pre-check
  # (bitcoin-core/src/validation.cpp:5787-5788, PopulateAndValidateSnapshot).
  # Reject if the active chain is already at or past the snapshot height — in
  # that case the snapshot's work cannot exceed the active tip's work, so
  # loading it would corrupt the state. We approximate with height since
  # AssumeutxoData does not store chainwork.
  if targetCs.bestHeight > 0 and targetCs.bestHeight >= assumeData.height:
    return (false, 0'u64, "Work does not exceed active chainstate")

  let baseHeight = assumeData.height

  # ----------------------------------------------------------
  # FIX-D Phase 1 — write the SNAPSHOT_LOAD_IN_PROGRESS marker
  # BEFORE any per-coin write. The marker is written via the synced
  # write-options path so it survives a power loss even when WAL is
  # globally disabled for IBD throughput. After this point, a crash
  # mid-load is recoverable: next-boot `recoverFromSnapshotCrash`
  # clears the partial chainstate.
  # ----------------------------------------------------------
  targetCs.db.writeSnapshotLoadMarker(sf.metadata.baseBlockhash, baseHeight)

  var coinsLoaded: uint64 = 0
  # Stream every loaded coin's canonical `TxOutSer` bytes through a
  # `HashWriter` (SHA256d) so we can verify the snapshot's `hash_serialized`
  # commitment (`validation.cpp:5901-5915`, `coinstats.cpp:161-163`).
  # This is the `CoinStatsHashType::HASH_SERIALIZED` branch — NOT MuHash3072.
  # We must NOT mark the chain tip valid until the digest matches au_data.
  var hw = initHashWriter()

  # Phase 2 — chunked per-coin writes. We collect up to SnapshotLoadChunkSize
  # coins per WriteBatch (matches ouroboros). The cache mirror (`putUtxoCache`)
  # is updated in-step so in-process readers see the loaded coins immediately.
  var chunkBatch = targetCs.db.db.newWriteBatch()
  var chunkCount = 0
  defer: chunkBatch.destroy()

  # Inline-as-template to dodge the capture-`var ChainState` restriction on
  # nested closures.
  template flushChunk() =
    if chunkCount > 0:
      targetCs.db.db.write(chunkBatch)
      chunkBatch.destroy()
      chunkBatch = targetCs.db.db.newWriteBatch()
      chunkCount = 0

  # Wrap the streaming loop: SnapshotError from readCoin (including B4
  # group-overcount) surfaces as a structured failure rather than an exception.
  # Crucially, if we bail out here we do NOT delete the marker — next-boot
  # `recoverFromSnapshotCrash` will detect it and clear the partial state.
  try:
    while true:
      let coinOpt = sf.readCoin()
      if coinOpt.isNone:
        break
      let coin = coinOpt.get()

      # B1: coin.nHeight > base_height guard
      # (bitcoin-core/src/validation.cpp:5814).
      if coin.height > baseHeight:
        return (false, coinsLoaded,
                "Bad snapshot data after deserializing " & $coinsLoaded & " coins")

      # B3: vout == UINT32_MAX coinstats overflow guard
      # (bitcoin-core/src/validation.cpp:5815-5816 — avoids integer wrap-around
      # in coinstats.cpp::ApplyHash which uses outpoint.n + 1).
      if coin.outpoint.vout >= 0xFFFFFFFF'u32:
        return (false, coinsLoaded,
                "Bad snapshot data after deserializing " & $coinsLoaded & " coins")

      # B2: per-coin MoneyRange check
      # (bitcoin-core/src/validation.cpp:5820-5822).
      let coinValue = int64(coin.output.value)
      if coinValue < 0 or coinValue > int64(MaxMoney):
        return (false, coinsLoaded,
                "Bad snapshot data after deserializing " & $coinsLoaded &
                " coins - bad tx out value")

      let entry = UtxoEntry(
        output: coin.output,
        height: coin.height,
        isCoinbase: coin.isCoinbase
      )
      targetCs.putUtxoCache(coin.outpoint, entry)
      let utxoK = utxoKey(array[32, byte](coin.outpoint.txid),
                          coin.outpoint.vout)
      chunkBatch.put(cfUtxo, utxoK, serializeUtxoEntry(entry))
      inc chunkCount
      if chunkCount >= SnapshotLoadChunkSize:
        flushChunk()
      let coinBytes = serializeCoinForHash(
        coin.outpoint, int64(coin.output.value), coin.output.scriptPubKey,
        coin.height, coin.isCoinbase
      )
      hw.update(coinBytes)
      inc coinsLoaded
  except SnapshotError as e:
    return (false, coinsLoaded, e.msg)

  if coinsLoaded != sf.metadata.coinsCount:
    return (false, coinsLoaded,
            "coin count mismatch: expected " & $sf.metadata.coinsCount &
            ", got " & $coinsLoaded)

  # Flush tail residue (<SnapshotLoadChunkSize coins remaining).
  flushChunk()

  # B5: Trailing-bytes exhaustion check
  # (bitcoin-core/src/validation.cpp:5872-5882).
  # After all declared coins have been consumed, attempt to read one more byte.
  # If the read SUCCEEDS (returns data), the file has extra garbage bytes — reject.
  # If it raises an exception / returns 0 (EOF), we're exactly out of data — accept.
  var trailingBuf = newSeq[byte](1)
  let trailingGot = sf.file.readBytes(trailingBuf, 0, 1)
  if trailingGot > 0:
    return (false, coinsLoaded,
            "Bad snapshot - coins left over after deserializing " & $coinsLoaded & " coins")

  # Strict assumeutxo content-hash check, matching Bitcoin Core verbatim
  # (`bitcoin-core/src/validation.cpp:5912-5914`):
  #
  #   if (AssumeutxoHash{maybe_stats->hashSerialized} != au_data.hash_serialized) {
  #       return util::Error{Untranslated(strprintf("Bad snapshot content hash: expected %s, got %s",
  #           au_data.hash_serialized.ToString(), maybe_stats->hashSerialized.ToString()))};
  #   }
  #
  # `maybe_stats->hashSerialized` is computed via
  # `CoinStatsHashType::HASH_SERIALIZED` (`coinstats.cpp:161-163`), which is
  # `HashWriter::GetHash()` (= SHA256d) over the canonical-order TxOutSer
  # byte stream. Both sides are uint256 in Core; their `ToString()` is the
  # byte-reversed hex display. We replicate that display so error messages
  # copy/paste 1:1 against Core's RPC output and assumeutxoData literals.
  let computedHash = hw.finalizeHash()
  if computedHash != assumeData.hashSerialized:
    proc dispHex(b: array[32, byte]): string =
      const hexDigits = "0123456789abcdef"
      result = newStringOfCap(64)
      for k in countdown(31, 0):
        result.add(hexDigits[int(b[k] shr 4)])
        result.add(hexDigits[int(b[k] and 0x0F)])
    return (false, coinsLoaded,
            "Bad snapshot content hash: expected " &
            dispHex(assumeData.hashSerialized) & ", got " &
            dispHex(computedHash))

  # ----------------------------------------------------------
  # FIX-D Phase 3 — final atomic commit batch. ONE WriteBatch fuses:
  #   - cfMeta bestblock pointer
  #   - cfMeta height pointer
  #   - delete of SNAPSHOT_LOAD_IN_PROGRESS marker
  # written via `writeSynced` (WAL + fsync). Either all three land or
  # none do, so a crash here cannot leave the tip pointing at the
  # snapshot with the marker still set (which would trigger an
  # unwanted recovery on next open) — nor leave the marker deleted
  # with the tip not yet updated (which would silently "lose" the
  # just-loaded snapshot on next open).
  # ----------------------------------------------------------
  targetCs.bestBlockHash = sf.metadata.baseBlockhash
  targetCs.bestHeight = assumeData.height
  targetCs.db.bestBlockHash = sf.metadata.baseBlockhash
  targetCs.db.bestHeight = assumeData.height
  let commitBatch = targetCs.db.db.newWriteBatch()
  defer: commitBatch.destroy()
  commitBatch.put(cfMeta, metaKey("bestblock"),
                  @(array[32, byte](sf.metadata.baseBlockhash)))
  var hw2 = BinaryWriter()
  hw2.writeInt32LE(assumeData.height)
  commitBatch.put(cfMeta, metaKey("height"), hw2.data)
  commitBatch.delete(cfMeta, metaKey(SnapshotLoadMarkerKey))
  targetCs.db.db.writeSynced(commitBatch)
  return (true, coinsLoaded, "")

# ============================================================================
# Dual-chainstate management (snapshot vs background validation chain)
# ============================================================================

proc newSnapshotChainState*(cs: ChainState): SnapshotChainState =
  SnapshotChainState(
    chainState: cs,
    assumeutxo: auValidated,
    snapshotBlockhash: none(BlockHash),
    targetUtxoHash: none(array[32, byte]),
    role: csrNormal
  )

proc activateSnapshot*(
    snapshotCs: SnapshotChainState,
    snapshotPath: string,
    params: ConsensusParams,
    assumeutxoData: seq[AssumeutxoData]
): tuple[success: bool, error: string] =
  # B7: Double-activation guard
  # (bitcoin-core/src/validation.cpp:5600-5601).
  # "Can't activate a snapshot-based chainstate more than once."
  if snapshotCs.assumeutxo == auUnvalidated:
    return (false, "Can't activate a snapshot-based chainstate more than once")

  let res = loadSnapshot(
    snapshotPath, snapshotCs.chainState, params, assumeutxoData
  )
  if not res.success:
    return (false, res.error)
  for d in assumeutxoData:
    if d.blockhash == snapshotCs.chainState.bestBlockHash:
      snapshotCs.assumeutxo = auUnvalidated
      snapshotCs.snapshotBlockhash = some(d.blockhash)
      snapshotCs.targetUtxoHash = some(d.hashSerialized)
      snapshotCs.role = csrSnapshot
      return (true, "")
  return (false, "snapshot hash not found in assumeutxo data")

# ============================================================================
# UTXO set hash helpers (debug / dumptxoutset response)
# ============================================================================

proc computeUtxoSetHashFromCoins*(coins: seq[SnapshotCoin]): array[32, byte] =
  ## Compute Core's `hash_serialized` over a list of coins using `HashWriter`
  ## (= SHA256d) over the concatenation of canonical `TxOutSer` bytes.
  ##
  ## This matches:
  ##   - `bitcoin-core/src/kernel/coinstats.cpp::ApplyCoinHash(HashWriter&, ...)`
  ##     (per-coin TxOutSer bytes piped through a single CSHA256 context)
  ##   - `bitcoin-core/src/kernel/coinstats.cpp::ComputeUTXOStats` with
  ##     `CoinStatsHashType::HASH_SERIALIZED`
  ##   - the `hashSerialized` commitment stored in `AssumeutxoData` and
  ##     checked by `loadtxoutset` (`validation.cpp:5901-5915`)
  ##
  ## Order-DEPENDENT: SHA256d is not a multiset hash, so callers must feed
  ## coins in canonical UTXO-cursor order (txid asc, vout asc) for the digest
  ## to match Core's `ComputeUTXOStats`. `gettxoutsetinfo hash_type=muhash`
  ## uses a different (order-independent) code path — see
  ## `src/crypto/muhash.nim`.
  if coins.len == 0:
    return default(array[32, byte])
  var hw = initHashWriter()
  for c in coins:
    let coinBytes = serializeCoinForHash(
      c.outpoint, int64(c.output.value), c.output.scriptPubKey,
      c.height, c.isCoinbase
    )
    hw.update(coinBytes)
  hw.finalizeHash()

proc validateSnapshot*(
    snapshotCs: SnapshotChainState,
    backgroundCs: var ChainState
): SnapshotValidationResult =
  ## REAL background validation (Core's `MaybeValidateSnapshot`,
  ## validation.cpp:5967): once the BACKGROUND chainstate has re-connected
  ## every block genesis->base into its OWN coins store, recompute the
  ## HASH_SERIALIZED of *that store's* UTXO set and compare it to the
  ## assumeUTXO commitment (`au_data.hash_serialized`). MATCH -> snapshot
  ## VALIDATED + background retired; MISMATCH -> snapshot INVALID (never
  ## silently accepted — Core calls `handle_invalid_snapshot` / `AbortNode`).
  ##
  ## This deliberately recomputes the hash from `backgroundCs` rather than
  ## trusting the load-time digest: the load-time gate authenticates the
  ## *file*; this is the trustless re-derivation by independent re-connection
  ## that catches a snapshot whose committed hash passes the load gate but is
  ## inconsistent with the genesis->base replay.
  ##
  ## Uses `computeUtxoSetInfo(.., cshtHashSerialized)` — the SAME
  ## `serializeCoinForHash` + `HashWriter` (SHA256d) kernel the load-time gate
  ## streams (`loadSnapshot` above), so the two hashes are byte-comparable.
  if snapshotCs.assumeutxo != auUnvalidated:
    return svrNotReady
  if snapshotCs.snapshotBlockhash.isNone or snapshotCs.targetUtxoHash.isNone:
    return svrNotReady
  # The background chainstate must have reached the snapshot base height.
  let targetHash = snapshotCs.snapshotBlockhash.get()
  if backgroundCs.bestBlockHash != targetHash:
    return svrNotReady

  # Recompute HASH_SERIALIZED over the BACKGROUND store's own coins.
  let info = computeUtxoSetInfo(backgroundCs, cshtHashSerialized)
  let recomputed = info.hashSerialized
  let assumed = snapshotCs.targetUtxoHash.get()

  if recomputed == assumed:
    # MATCH — Core: unvalidated_cs.m_assumeutxo = VALIDATED + retire bg.
    snapshotCs.assumeutxo = auValidated
    return svrValid
  else:
    # MISMATCH — Core: handle_invalid_snapshot() marks the snapshot INVALID
    # and AbortNode()s; we never flip it to validated.
    snapshotCs.assumeutxo = auInvalid
    return svrInvalid

# ============================================================================
# Background validation (async — preserved from prior interface)
# ============================================================================

proc newBackgroundValidation*(targetHeight: int32,
                              snapshotHash: array[32, byte]): BackgroundValidation =
  BackgroundValidation(
    running: false,
    progress: 0,
    targetHeight: targetHeight,
    snapshotHash: snapshotHash
  )

proc runBackgroundValidation*(
    bgv: BackgroundValidation,
    backgroundCs: var ChainState,
    snapshotCs: SnapshotChainState,
    getNextBlock: proc(height: int32): Option[Block] {.gcsafe, raises: [].},
    params: ConsensusParams
) {.async.} =
  bgv.running = true
  bgv.progress = backgroundCs.bestHeight + 1
  while bgv.running and bgv.progress <= bgv.targetHeight:
    let blockOpt = getNextBlock(bgv.progress)
    if blockOpt.isNone:
      await sleepAsync(100.milliseconds)
      continue
    let r = backgroundCs.connectBlock(blockOpt.get(), bgv.progress)
    if not r.isOk:
      bgv.running = false
      snapshotCs.assumeutxo = auInvalid
      return
    inc bgv.progress
    if bgv.progress > bgv.targetHeight:
      # Reached the base: recompute HASH_SERIALIZED over the bg store and
      # compare to the commitment (validateSnapshot flips Validated/Invalid).
      discard validateSnapshot(snapshotCs, backgroundCs)
      bgv.running = false
      return
    await sleepAsync(0.milliseconds)
  bgv.running = false

# ============================================================================
# Dual-chainstate snapshot activation (Core ActivateSnapshot / AddChainstate)
# ============================================================================

proc makeBackgroundChainState*(bgDbPath: string,
                               params: ConsensusParams): ChainState =
  ## Construct the SECOND (background) chainstate for snapshot validation:
  ## a genesis-rooted chainstate with its OWN `ChainDb` at a DISTINCT on-disk
  ## directory (NOT the active snapshot store) and a fresh, EMPTY UTXO set at
  ## height 0.
  ##
  ## This is Core's `AddChainstate` demotion (validation.cpp:6170): the
  ## genesis-validated chainstate keeps its own coins DB and is re-purposed as
  ## the background validator that re-derives the snapshot's UTXO hash from
  ## genesis. A brand-new store has no persisted tip, so `newChainState` seeds
  ## it at the zero (genesis-sentinel) tip with zero coins — exactly the state
  ## Core's background chainstate replays forward from.
  ##
  ## The tip height is seeded to -1 (PRE-genesis) so the re-connection driver
  ## starts at height 0 and connects the GENESIS block first — connectBlock
  ## special-cases height 0 (no UTXO mutation, sets bestBlockHash = genesisHash,
  ## validation.cpp:2337-2343), which the height-1 block needs as its prevBlock.
  result = newChainState(bgDbPath, params)
  # newChainState reads cdb.bestBlockHash/Height from disk; a fresh dir has
  # none, so the hash is already the zero sentinel (= genesis prevBlock).
  result.bestBlockHash = BlockHash(default(array[32, byte]))
  result.bestHeight = -1'i32
  result.db.bestBlockHash = BlockHash(default(array[32, byte]))
  result.db.bestHeight = -1'i32

proc activateSnapshotWithBackground*(
    snapshotCs: SnapshotChainState,
    bgDbPath: string,
    assumedHash: array[32, byte],
    baseHeight: int32
): SnapshotActivation =
  ## Wire up a real dual-chainstate validation for an already-loaded snapshot
  ## chainstate (`snapshotCs`, produced by `activateSnapshot`/`loadSnapshot`,
  ## carrying `assumeutxo = auUnvalidated`).
  ##
  ## Builds the SECOND background chainstate at `bgDbPath` with its OWN separate
  ## coins store (via `makeBackgroundChainState`) and a `BackgroundValidation`
  ## context targeting `baseHeight`. The activation itself performs NO block
  ## connection — exactly like Core's `ActivateSnapshot`, which returns after
  ## demoting the prior chainstate and lets the validation queue do the work.
  ##
  ## Aliasing guarantee: the background store is a distinct `ChainState`/`ChainDb`
  ## rooted at a different directory; a write to one store is invisible in the
  ## other (proven by the dual-chainstate spec). A caller that aliases the two
  ## stores (same db path) is a programming error — `runSnapshotValidation`
  ## refuses it.
  snapshotCs.assumeutxo = auUnvalidated
  snapshotCs.role = csrSnapshot
  let background = makeBackgroundChainState(bgDbPath, snapshotCs.chainState.params)
  let bgv = newBackgroundValidation(baseHeight, assumedHash)
  SnapshotActivation(
    snapshot: snapshotCs,
    background: background,
    bgValidation: bgv,
    baseHeight: baseHeight,
    assumedHash: assumedHash,
    bgDbPath: bgDbPath
  )

proc runSnapshotValidation*(
    activation: SnapshotActivation,
    getNextBlock: proc(height: int32): Option[Block] {.gcsafe, raises: [].}
): tuple[validated: bool, error: string] =
  ## Synchronously drive the background validation to its terminal state
  ## (Core's `MaybeValidateSnapshot` reached at the base) and report the verdict.
  ##
  ## Returns `(true, "")` when the background chainstate's independently
  ## re-computed UTXO hash MATCHED the assumed hash — the snapshot flips to
  ## `auValidated` and the background chainstate is logically retired.
  ##
  ## Returns `(false, <error>)` when the genesis->base re-connect completed but
  ## the recomputed hash MISMATCHED (snapshot -> `auInvalid`, error carries
  ## "mismatch"), or a block failed to connect, or no block was available at a
  ## required height. The snapshot is NEVER silently accepted on a mismatch
  ## (Core `handle_invalid_snapshot` / `AbortNode`).
  ##
  ## Aliasing guard: refuse to run if the background store IS the snapshot store
  ## (same `ChainDb` ref) — that would be a tautological hash-of-self, not an
  ## independent re-derivation. `ChainDb` is a `ref object`, so `==` compares
  ## reference identity.
  if activation.background.db == activation.snapshot.chainState.db:
    return (false, "background store aliases the snapshot store — refusing")

  # Bound the loop: if `getNextBlock` returns none for a required height we must
  # not spin forever. Track stall iterations and fail closed.
  # `connectBlock` takes `var ChainState`; bind the ref field to a local var so
  # the mutation flows back through the shared ref (ChainState is a ref object).
  var bg = activation.background
  var stalls = 0
  const MaxStalls = 4
  activation.bgValidation.running = true
  activation.bgValidation.progress = bg.bestHeight + 1
  while activation.bgValidation.running and
        activation.bgValidation.progress <= activation.bgValidation.targetHeight:
    let blockOpt = getNextBlock(activation.bgValidation.progress)
    if blockOpt.isNone:
      inc stalls
      if stalls > MaxStalls:
        activation.bgValidation.running = false
        activation.snapshot.assumeutxo = auInvalid
        return (false, "background validation stalled: missing block at height " &
                $activation.bgValidation.progress)
      continue
    stalls = 0
    let r = bg.connectBlock(blockOpt.get(), activation.bgValidation.progress)
    if not r.isOk:
      activation.bgValidation.running = false
      activation.snapshot.assumeutxo = auInvalid
      return (false, "background connect failed at height " &
              $activation.bgValidation.progress & ": " & r.error)
    inc activation.bgValidation.progress
    if activation.bgValidation.progress > activation.bgValidation.targetHeight:
      let verdict = validateSnapshot(activation.snapshot, bg)
      activation.bgValidation.running = false
      case verdict
      of svrValid:
        return (true, "")
      of svrInvalid:
        return (false, "snapshot UTXO hash mismatch: background re-derivation " &
                "did not match the assumeutxo commitment")
      of svrNotReady:
        activation.snapshot.assumeutxo = auInvalid
        return (false, "snapshot validation did not reach a terminal state")
  activation.bgValidation.running = false
  activation.snapshot.assumeutxo = auInvalid
  return (false, "background validation did not reach the snapshot base")

proc stopBackgroundValidation*(bgv: BackgroundValidation) =
  bgv.running = false

proc getProgress*(bgv: BackgroundValidation): tuple[current: int32, target: int32] =
  (bgv.progress, bgv.targetHeight)
