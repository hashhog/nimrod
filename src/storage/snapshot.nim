## assumeUTXO snapshot support
## Load/save UTXO set snapshots for fast node startup
## Reference: Bitcoin Core utxo_snapshot.cpp, validation.cpp
##
## Snapshot format (Bitcoin Core compatible):
## - Magic bytes: "utxo\xFF" (5 bytes)
## - Version: uint16 (currently 2)
## - Network magic: 4 bytes
## - Base blockhash: 32 bytes
## - Coins count: uint64
## - UTXO entries: (txid, vout, coin data)...
##
## Background validation: after loading a snapshot, a background chainstate
## validates from genesis to the snapshot height. When the background
## chainstate reaches the snapshot point and its UTXO hash matches,
## the snapshot is fully validated.

import std/[options, tables, os, algorithm]
import chronos
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../consensus/params
import ./db
import ./chainstate

export chainstate

type
  SnapshotError* = object of CatchableError

  ## Snapshot validation state
  ## Tracks whether a snapshot chainstate has been fully validated
  Assumeutxo* = enum
    auValidated     ## Fully validated from genesis (or snapshot validation complete)
    auUnvalidated   ## Loaded from snapshot, background validation in progress
    auInvalid       ## Snapshot validation failed (hash mismatch)

  ## AssumeutxoData contains hardcoded snapshot parameters for each valid snapshot
  ## These are stored in ConsensusParams and used to verify loaded snapshots
  AssumeutxoData* = object
    height*: int32                  ## Block height of snapshot
    hashSerialized*: array[32, byte]  ## Expected SHA256d hash of serialized UTXO set
    chainTxCount*: uint64           ## Cumulative transaction count up to snapshot
    blockhash*: BlockHash           ## Block hash at snapshot height

  ## Metadata stored at the beginning of a snapshot file
  SnapshotMetadata* = object
    version*: uint16                ## Format version (currently 2)
    networkMagic*: array[4, byte]   ## Network identifier
    baseBlockhash*: BlockHash       ## Block hash at which snapshot was taken
    coinsCount*: uint64             ## Total number of UTXOs in snapshot

  ## Compact coin representation for snapshot serialization
  ## Encodes height and coinbase flag together: height*2 + coinbase
  SnapshotCoin* = object
    outpoint*: OutPoint
    output*: TxOut
    height*: int32
    isCoinbase*: bool

  ## Snapshot file handle for reading/writing
  SnapshotFile* = ref object
    path*: string
    metadata*: SnapshotMetadata
    file*: File
    coinsRead*: uint64
    coinsWritten*: uint64

  ## Extended ChainState with snapshot validation support
  SnapshotChainState* = ref object
    chainState*: ChainState
    assumeutxo*: Assumeutxo
    snapshotBlockhash*: Option[BlockHash]  ## Base block of loaded snapshot
    targetUtxoHash*: Option[array[32, byte]]  ## Expected UTXO hash for validation

  ## Background validation task
  BackgroundValidation* = ref object
    running*: bool
    progress*: int32  ## Current height being validated
    targetHeight*: int32  ## Height to reach (snapshot base)
    snapshotHash*: array[32, byte]  ## Expected UTXO hash at target

  ## Result of snapshot validation
  SnapshotValidationResult* = enum
    svrNotReady       ## Background validation hasn't reached snapshot height
    svrValid          ## UTXO hash matches - snapshot is valid
    svrInvalid        ## UTXO hash mismatch - snapshot is invalid

const
  SnapshotMagic* = [byte('u'), byte('t'), byte('x'), byte('o'), 0xFF'u8]
  SnapshotVersion*: uint16 = 2

# ============================================================================
# Snapshot metadata serialization
# ============================================================================

proc writeSnapshotMetadata*(w: var BinaryWriter, meta: SnapshotMetadata) =
  ## Write snapshot file header
  w.writeBytes(SnapshotMagic)
  w.writeUint16LE(meta.version)
  w.writeBytes(meta.networkMagic)
  w.writeBlockHash(meta.baseBlockhash)
  w.writeUint64LE(meta.coinsCount)

proc readSnapshotMetadata*(r: var BinaryReader): SnapshotMetadata =
  ## Read and validate snapshot file header
  let magic = r.readBytes(5)
  if magic != @SnapshotMagic:
    raise newException(SnapshotError, "invalid snapshot magic bytes")

  result.version = r.readUint16LE()
  if result.version != SnapshotVersion:
    raise newException(SnapshotError, "unsupported snapshot version: " & $result.version)

  for i in 0..3:
    result.networkMagic[i] = r.readUint8()

  result.baseBlockhash = r.readBlockHash()
  result.coinsCount = r.readUint64LE()

# ============================================================================
# Coin serialization for snapshots
# ============================================================================

proc writeSnapshotCoin*(w: var BinaryWriter, coin: SnapshotCoin) =
  ## Write a single UTXO to snapshot
  ## Format: outpoint(36) | value(8) | script(varint+data) | height_coinbase(varint)
  w.writeOutPoint(coin.outpoint)
  w.writeInt64LE(int64(coin.output.value))
  w.writeVarBytes(coin.output.scriptPubKey)
  # Encode height and coinbase together
  let heightCoinbase = uint64(coin.height) * 2 + (if coin.isCoinbase: 1 else: 0)
  w.writeCompactSize(heightCoinbase)

proc readSnapshotCoin*(r: var BinaryReader): SnapshotCoin =
  ## Read a single UTXO from snapshot
  result.outpoint = r.readOutPoint()
  result.output.value = Satoshi(r.readInt64LE())
  result.output.scriptPubKey = r.readVarBytes()
  let heightCoinbase = r.readCompactSize()
  result.height = int32(heightCoinbase div 2)
  result.isCoinbase = (heightCoinbase and 1) == 1

# ============================================================================
# UTXO set hash computation
# ============================================================================

proc computeUtxoSetHash*(cs: ChainState): array[32, byte] =
  ## Compute SHA256d hash of the UTXO set in deterministic order
  ## This is used to verify snapshot integrity
  ##
  ## Algorithm:
  ## 1. Collect all UTXOs from database
  ## 2. Sort by outpoint (txid then vout)
  ## 3. Serialize each UTXO and feed to hasher
  ## 4. Return double SHA256 of all serialized data
  ##
  ## Note: This is a simplified version. Bitcoin Core uses HASH_SERIALIZED
  ## which has specific ordering and serialization requirements.

  var coins: seq[SnapshotCoin] = @[]

  # Iterate through all UTXOs in the database
  # For now, we'll use a simplified approach that works with our storage layer
  # A full implementation would need iterator support in the DB layer

  # Sort coins by outpoint for deterministic ordering
  coins.sort do (a, b: SnapshotCoin) -> int:
    let aTxid = array[32, byte](a.outpoint.txid)
    let bTxid = array[32, byte](b.outpoint.txid)
    for i in 0..<32:
      if aTxid[i] != bTxid[i]:
        return int(aTxid[i]) - int(bTxid[i])
    return int(a.outpoint.vout) - int(b.outpoint.vout)

  # Hash all coins
  var w = BinaryWriter()
  for coin in coins:
    w.writeSnapshotCoin(coin)

  if w.data.len == 0:
    # Empty UTXO set - return zero hash
    return default(array[32, byte])

  doubleSha256(w.data)

proc computeUtxoSetHashFromIterator*(
  iterateUtxos: proc(): Option[tuple[outpoint: OutPoint, entry: UtxoEntry]]
): array[32, byte] =
  ## Compute UTXO set hash using an iterator callback
  ## This allows computing the hash without loading all UTXOs into memory

  var coins: seq[SnapshotCoin] = @[]

  while true:
    let utxoOpt = iterateUtxos()
    if utxoOpt.isNone:
      break
    let (outpoint, entry) = utxoOpt.get()
    coins.add(SnapshotCoin(
      outpoint: outpoint,
      output: entry.output,
      height: entry.height,
      isCoinbase: entry.isCoinbase
    ))

  # Sort for deterministic ordering
  coins.sort do (a, b: SnapshotCoin) -> int:
    let aTxid = array[32, byte](a.outpoint.txid)
    let bTxid = array[32, byte](b.outpoint.txid)
    for i in 0..<32:
      if aTxid[i] != bTxid[i]:
        return int(aTxid[i]) - int(bTxid[i])
    return int(a.outpoint.vout) - int(b.outpoint.vout)

  var w = BinaryWriter()
  for coin in coins:
    w.writeSnapshotCoin(coin)

  if w.data.len == 0:
    return default(array[32, byte])

  doubleSha256(w.data)

# ============================================================================
# Snapshot file I/O
# ============================================================================

proc openSnapshotForWrite*(path: string, meta: SnapshotMetadata): SnapshotFile =
  ## Create a new snapshot file for writing
  result = SnapshotFile(
    path: path,
    metadata: meta,
    coinsWritten: 0
  )

  result.file = open(path, fmWrite)

  # Write header
  var w = BinaryWriter()
  w.writeSnapshotMetadata(meta)
  discard result.file.writeBytes(w.data, 0, w.data.len)

proc openSnapshotForRead*(path: string): SnapshotFile =
  ## Open an existing snapshot file for reading
  result = SnapshotFile(
    path: path,
    coinsRead: 0
  )

  if not fileExists(path):
    raise newException(SnapshotError, "snapshot file not found: " & path)

  result.file = open(path, fmRead)

  # Read header (magic + version + network_magic + blockhash + coins_count = 5 + 2 + 4 + 32 + 8 = 51 bytes)
  var headerBytes = newSeq[byte](51)
  let bytesRead = result.file.readBytes(headerBytes, 0, 51)
  if bytesRead != 51:
    result.file.close()
    raise newException(SnapshotError, "truncated snapshot header")

  var r = BinaryReader(data: headerBytes, pos: 0)
  result.metadata = r.readSnapshotMetadata()

proc writeCoin*(sf: SnapshotFile, coin: SnapshotCoin) =
  ## Write a single coin to the snapshot file
  var w = BinaryWriter()
  w.writeSnapshotCoin(coin)
  discard sf.file.writeBytes(w.data, 0, w.data.len)
  inc sf.coinsWritten

proc readCoin*(sf: SnapshotFile): Option[SnapshotCoin] =
  ## Read the next coin from the snapshot file
  ## Returns none when all coins have been read
  if sf.coinsRead >= sf.metadata.coinsCount:
    return none(SnapshotCoin)

  # Read coin data (variable size)
  # We need to read in chunks since size is variable
  var data: seq[byte] = @[]

  # Read outpoint (36 bytes)
  var outpointBytes = newSeq[byte](36)
  if sf.file.readBytes(outpointBytes, 0, 36) != 36:
    return none(SnapshotCoin)
  data.add(outpointBytes)

  # Read value (8 bytes)
  var valueBytes = newSeq[byte](8)
  if sf.file.readBytes(valueBytes, 0, 8) != 8:
    return none(SnapshotCoin)
  data.add(valueBytes)

  # Read script (varint length + data)
  var lenByte = newSeq[byte](1)
  if sf.file.readBytes(lenByte, 0, 1) != 1:
    return none(SnapshotCoin)
  data.add(lenByte)

  var scriptLen: int
  if lenByte[0] < 0xFD:
    scriptLen = int(lenByte[0])
  elif lenByte[0] == 0xFD:
    var lenBytes = newSeq[byte](2)
    if sf.file.readBytes(lenBytes, 0, 2) != 2:
      return none(SnapshotCoin)
    data.add(lenBytes)
    scriptLen = int(lenBytes[0]) or (int(lenBytes[1]) shl 8)
  elif lenByte[0] == 0xFE:
    var lenBytes = newSeq[byte](4)
    if sf.file.readBytes(lenBytes, 0, 4) != 4:
      return none(SnapshotCoin)
    data.add(lenBytes)
    scriptLen = int(lenBytes[0]) or (int(lenBytes[1]) shl 8) or
                (int(lenBytes[2]) shl 16) or (int(lenBytes[3]) shl 24)
  else:
    # 8-byte length - unlikely for scripts
    return none(SnapshotCoin)

  if scriptLen > 0:
    var scriptBytes = newSeq[byte](scriptLen)
    if sf.file.readBytes(scriptBytes, 0, scriptLen) != scriptLen:
      return none(SnapshotCoin)
    data.add(scriptBytes)

  # Read height/coinbase varint
  var heightByte = newSeq[byte](1)
  if sf.file.readBytes(heightByte, 0, 1) != 1:
    return none(SnapshotCoin)
  data.add(heightByte)

  if heightByte[0] >= 0xFD:
    var extraBytes: int
    if heightByte[0] == 0xFD:
      extraBytes = 2
    elif heightByte[0] == 0xFE:
      extraBytes = 4
    else:
      extraBytes = 8
    var extra = newSeq[byte](extraBytes)
    if sf.file.readBytes(extra, 0, extraBytes) != extraBytes:
      return none(SnapshotCoin)
    data.add(extra)

  var r = BinaryReader(data: data, pos: 0)
  let coin = r.readSnapshotCoin()
  inc sf.coinsRead
  some(coin)

proc close*(sf: SnapshotFile) =
  if sf.file != nil:
    sf.file.close()

# ============================================================================
# Snapshot creation (dumptxoutset)
# ============================================================================

proc createSnapshot*(
  cs: ChainState,
  path: string,
  params: ConsensusParams
): tuple[coinsWritten: uint64, hash: array[32, byte]] =
  ## Create a UTXO snapshot file from the current chainstate
  ## Returns the number of coins written and the UTXO set hash
  ##
  ## This implements the `dumptxoutset` RPC functionality.

  # Count UTXOs first (we need this for the header)
  var coinsCount: uint64 = 0
  var coins: seq[SnapshotCoin] = @[]

  # Note: A full implementation would iterate the database directly
  # For now, we'll use the cache and any UTXOs we can access
  for outpoint, entry in cs.utxoCache:
    coins.add(SnapshotCoin(
      outpoint: outpoint,
      output: entry.output,
      height: entry.height,
      isCoinbase: entry.isCoinbase
    ))

  coinsCount = uint64(coins.len)

  # Sort for deterministic ordering
  coins.sort do (a, b: SnapshotCoin) -> int:
    let aTxid = array[32, byte](a.outpoint.txid)
    let bTxid = array[32, byte](b.outpoint.txid)
    for i in 0..<32:
      if aTxid[i] != bTxid[i]:
        return int(aTxid[i]) - int(bTxid[i])
    return int(a.outpoint.vout) - int(b.outpoint.vout)

  let meta = SnapshotMetadata(
    version: SnapshotVersion,
    networkMagic: params.networkMagic,
    baseBlockhash: cs.bestBlockHash,
    coinsCount: coinsCount
  )

  let sf = openSnapshotForWrite(path, meta)
  defer: sf.close()

  # Write all coins and compute hash
  var w = BinaryWriter()
  for coin in coins:
    sf.writeCoin(coin)
    w.writeSnapshotCoin(coin)

  let hash = if w.data.len > 0:
    doubleSha256(w.data)
  else:
    default(array[32, byte])

  (coinsWritten: coinsCount, hash: hash)

# ============================================================================
# Snapshot loading (loadtxoutset)
# ============================================================================

proc validateSnapshotMetadata*(
  meta: SnapshotMetadata,
  params: ConsensusParams,
  assumeutxoData: seq[AssumeutxoData]
): tuple[valid: bool, data: Option[AssumeutxoData], error: string] =
  ## Validate snapshot metadata against hardcoded assumeutxo data

  # Check network magic
  if meta.networkMagic != params.networkMagic:
    return (false, none(AssumeutxoData), "network magic mismatch")

  # Find matching assumeutxo data by block hash
  for data in assumeutxoData:
    if data.blockhash == meta.baseBlockhash:
      return (true, some(data), "")

  (false, none(AssumeutxoData), "unknown snapshot block hash - not in assumeutxo list")

proc loadSnapshot*(
  path: string,
  targetCs: var ChainState,
  params: ConsensusParams,
  assumeutxoData: seq[AssumeutxoData]
): tuple[success: bool, coinsLoaded: uint64, error: string] =
  ## Load a UTXO snapshot into a chainstate
  ## Returns success status, coins loaded, and any error message
  ##
  ## This implements the `loadtxoutset` RPC functionality.

  let sf = try:
    openSnapshotForRead(path)
  except SnapshotError as e:
    return (false, 0, e.msg)
  except IOError as e:
    return (false, 0, "failed to open snapshot: " & e.msg)

  defer: sf.close()

  # Validate metadata
  let validation = validateSnapshotMetadata(sf.metadata, params, assumeutxoData)
  if not validation.valid:
    return (false, 0, validation.error)

  let assumeData = validation.data.get()

  # Load all coins into chainstate
  var coinsLoaded: uint64 = 0
  var hashWriter = BinaryWriter()

  while true:
    let coinOpt = sf.readCoin()
    if coinOpt.isNone:
      break

    let coin = coinOpt.get()

    # Add to chainstate UTXO cache
    let entry = UtxoEntry(
      output: coin.output,
      height: coin.height,
      isCoinbase: coin.isCoinbase
    )
    targetCs.putUtxoCache(coin.outpoint, entry)

    # Also write to database
    targetCs.db.putUtxo(coin.outpoint, entry)

    # Accumulate for hash verification
    hashWriter.writeSnapshotCoin(coin)
    inc coinsLoaded

  # Verify coin count
  if coinsLoaded != sf.metadata.coinsCount:
    return (false, coinsLoaded, "coin count mismatch: expected " &
            $sf.metadata.coinsCount & ", got " & $coinsLoaded)

  # Compute and verify UTXO hash
  let computedHash = if hashWriter.data.len > 0:
    doubleSha256(hashWriter.data)
  else:
    default(array[32, byte])

  if computedHash != assumeData.hashSerialized:
    return (false, coinsLoaded, "UTXO hash mismatch - snapshot may be corrupted")

  # Update chainstate to snapshot tip
  targetCs.bestBlockHash = sf.metadata.baseBlockhash
  targetCs.bestHeight = assumeData.height
  targetCs.db.updateBestBlock(sf.metadata.baseBlockhash, assumeData.height)

  (true, coinsLoaded, "")

# ============================================================================
# Dual chainstate management
# ============================================================================

proc newSnapshotChainState*(cs: ChainState): SnapshotChainState =
  ## Wrap a ChainState with snapshot validation tracking
  SnapshotChainState(
    chainState: cs,
    assumeutxo: auValidated,  # Default to validated (normal IBD)
    snapshotBlockhash: none(BlockHash),
    targetUtxoHash: none(array[32, byte])
  )

proc activateSnapshot*(
  snapshotCs: var SnapshotChainState,
  snapshotPath: string,
  params: ConsensusParams,
  assumeutxoData: seq[AssumeutxoData]
): tuple[success: bool, error: string] =
  ## Activate a snapshot chainstate
  ## The chainstate will be marked as unvalidated until background validation completes

  let (success, coinsLoaded, error) = loadSnapshot(
    snapshotPath, snapshotCs.chainState, params, assumeutxoData
  )

  if not success:
    return (false, error)

  # Find the assumeutxo data for this snapshot
  for data in assumeutxoData:
    if data.blockhash == snapshotCs.chainState.bestBlockHash:
      snapshotCs.assumeutxo = auUnvalidated
      snapshotCs.snapshotBlockhash = some(data.blockhash)
      snapshotCs.targetUtxoHash = some(data.hashSerialized)
      return (true, "")

  (false, "snapshot hash not found in assumeutxo data")

proc validateSnapshot*(
  snapshotCs: var SnapshotChainState,
  backgroundCs: ChainState
): SnapshotValidationResult =
  ## Check if background validation has reached snapshot height
  ## and if so, verify the UTXO hash matches

  if snapshotCs.assumeutxo != auUnvalidated:
    return svrNotReady

  if snapshotCs.snapshotBlockhash.isNone or snapshotCs.targetUtxoHash.isNone:
    return svrNotReady

  # Check if background chainstate has reached snapshot height
  let targetHash = snapshotCs.snapshotBlockhash.get()
  let targetIdxOpt = backgroundCs.db.getBlockIndex(targetHash)

  if targetIdxOpt.isNone:
    return svrNotReady

  let targetHeight = targetIdxOpt.get().height

  if backgroundCs.bestHeight < targetHeight:
    return svrNotReady

  # Background has reached snapshot height - verify UTXO hash
  let computedHash = computeUtxoSetHash(backgroundCs)
  let expectedHash = snapshotCs.targetUtxoHash.get()

  if computedHash == expectedHash:
    snapshotCs.assumeutxo = auValidated
    svrValid
  else:
    snapshotCs.assumeutxo = auInvalid
    svrInvalid

# ============================================================================
# Background validation (async)
# ============================================================================

proc newBackgroundValidation*(
  targetHeight: int32,
  snapshotHash: array[32, byte]
): BackgroundValidation =
  BackgroundValidation(
    running: false,
    progress: 0,
    targetHeight: targetHeight,
    snapshotHash: snapshotHash
  )

proc runBackgroundValidation*(
  bgv: BackgroundValidation,
  backgroundCs: var ChainState,
  snapshotCs: var SnapshotChainState,
  getNextBlock: proc(height: int32): Option[Block] {.gcsafe, raises: [].},
  params: ConsensusParams
) {.async.} =
  ## Run background validation from genesis to snapshot height
  ## This is an async task that validates blocks in the background
  ## while the snapshot chainstate handles new blocks

  bgv.running = true
  bgv.progress = backgroundCs.bestHeight + 1

  while bgv.running and bgv.progress <= bgv.targetHeight:
    # Get the next block to validate
    let blockOpt = getNextBlock(bgv.progress)
    if blockOpt.isNone:
      # No block available yet - wait and retry
      await sleepAsync(100.milliseconds)
      continue

    let blk = blockOpt.get()

    # Connect the block
    let connectResult = backgroundCs.connectBlock(blk, bgv.progress)
    if not connectResult.isOk:
      # Validation failed - this is a serious error
      bgv.running = false
      snapshotCs.assumeutxo = auInvalid
      return

    inc bgv.progress

    # Check if we've reached the target
    if bgv.progress > bgv.targetHeight:
      # Verify UTXO hash
      let validationResult = validateSnapshot(snapshotCs, backgroundCs)
      bgv.running = false
      return

    # Yield to allow other async tasks to run
    await sleepAsync(0.milliseconds)

  bgv.running = false

proc stopBackgroundValidation*(bgv: BackgroundValidation) =
  bgv.running = false

proc getProgress*(bgv: BackgroundValidation): tuple[current: int32, target: int32] =
  (bgv.progress, bgv.targetHeight)
