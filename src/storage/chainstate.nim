## Chainstate management
## UTXO set manager with block connect/disconnect, in-memory cache, and reorg support
## Uses RocksDB column families for data separation
## Undo data stored in flat files (rev*.dat) for efficient reorg handling

import std/[options, tables, os]
import ./db
import ./undo
import ../primitives/[types, serialize]
import ../crypto/hashing
import ../crypto/muhash
import ../consensus/params
import ../consensus/assumevalid
import chronicles

export db.ColumnFamily
export undo.BlockUndo, undo.TxUndo, undo.SpentOutput, undo.FlatFilePos

# Re-export the RocksDB shared block-cache budget so RPC callers (getchainstates'
# coins_db_cache_bytes) can report the genuine on-disk coins-DB cache size without
# importing storage/db directly. openChainDb -> openDatabase uses defaultDbConfig,
# whose blockCacheSize IS this constant (src/storage/db.nim:18,229), so this is the
# real cache budget the chainstate's coins data is served from.
export db.BlockCacheSize

const
  CoinsTipCacheBytes* = 450 * 1024 * 1024
    ## Configured in-memory coins (UTXO) cache byte budget — the documented
    ## dbcache split for the coins-tip cache (mirrors src/storage/utxo_cache.nim
    ## DefaultDbCacheSize = 450 MiB). NOTE: the live `ChainState` coins cache
    ## actually flushes by ENTRY COUNT (`maxCacheSize`, default
    ## DefaultMaxCacheSize=50000), not bytes, so no byte budget is tracked on the
    ## hot path. This constant is the genuine configured byte budget reported as
    ## Core's m_coinstip_cache_size_bytes (getchainstates' coins_tip_cache_bytes).

type
  ChainStateError* = object of CatchableError

  BlockStatus* = enum
    bsHeaderOnly    ## Only header stored
    bsDataStored    ## Full block data stored
    bsValidated     ## Block fully validated
    bsInvalid       ## Block validation failed

  ## Block failure flags for invalidateblock/reconsiderblock
  ## These are stored separately from BlockStatus to allow combinations
  BlockFailureFlags* = distinct uint8

const
  BLOCK_FAILED_VALID* = BlockFailureFlags(32)    ## Block failed validation (invalidateblock)
  BLOCK_FAILED_CHILD* = BlockFailureFlags(64)    ## Descendant of a failed block
  BLOCK_NO_FAILURE* = BlockFailureFlags(0)       ## No failure flags set

proc `or`*(a, b: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `and`*(a, b: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `not`*(a: BlockFailureFlags): BlockFailureFlags {.borrow.}
proc `==`*(a, b: BlockFailureFlags): bool {.borrow.}
proc `!=`*(a, b: BlockFailureFlags): bool = not (a == b)

proc hasFlag*(flags: BlockFailureFlags, flag: BlockFailureFlags): bool =
  (uint8(flags) and uint8(flag)) != 0

proc setFlag*(flags: var BlockFailureFlags, flag: BlockFailureFlags) =
  flags = BlockFailureFlags(uint8(flags) or uint8(flag))

proc clearFlag*(flags: var BlockFailureFlags, flag: BlockFailureFlags) =
  flags = BlockFailureFlags(uint8(flags) and (not uint8(flag)))

proc isFailed*(flags: BlockFailureFlags): bool =
  ## Check if block has the BLOCK_FAILED_VALID flag set.
  ## Reference: Bitcoin Core v25+ uses only BLOCK_FAILED_VALID for candidate
  ## filtering (validation.cpp:3139, chain.h — BLOCK_FAILED_CHILD is unused).
  ## BUG-02 fix: only BLOCK_FAILED_VALID constitutes a failure for chain selection.
  flags.hasFlag(BLOCK_FAILED_VALID)

type
  BlockIndex* = object
    hash*: BlockHash
    height*: int32
    status*: BlockStatus
    prevHash*: BlockHash
    header*: BlockHeader
    totalWork*: array[32, byte]  ## Cumulative chain work
    undoPos*: FlatFilePos        ## Position of undo data in rev*.dat files
    failureFlags*: BlockFailureFlags  ## Failure flags for invalidateblock/reconsiderblock
    sequenceId*: int32           ## For preciousblock: lower = more precious
    nTx*: int32                  ## Number of transactions in this block (0 = unknown)

  UtxoEntry* = object
    output*: TxOut
    height*: int32
    isCoinbase*: bool

  ## UndoData stores spent outputs for block disconnect
  UndoData* = object
    spentOutputs*: seq[tuple[outpoint: OutPoint, entry: UtxoEntry]]

  ## ChainDb provides raw database access
  ChainDb* = ref object
    db*: Database
    bestBlockHash*: BlockHash
    bestHeight*: int32
    # IBD unflushed block-index shadow.
    #
    # During IBD `connectBlockIBD` defers ALL writes (block-index rows
    # included) into a single RocksDB WriteBatch and only flushes every
    # IbdBatchFlushInterval (2000) blocks. Until that flush, RocksDB does
    # NOT contain the just-connected blocks' index rows, so the raw reads
    # `getBlockIndex` / `getBlockHashByHeight` return stale data for the
    # whole unflushed window.
    #
    # That staleness silently mis-feeds EVERY contextual consensus check
    # that walks recent blocks through a `ChainDb`:
    #   - getMtpForHeight (BIP-113 finality cutoff in validateBlock, and
    #     the time-too-old gate in contextualCheckBlockHeader) — produced
    #     "bad-txns-nonfinal" on valid mainnet block 950149.
    #   - the bad-diffbits getAncestor walk in contextualCheckBlockHeader
    #     (493bcd1 patched only the immediate parent header, not the
    #     deeper retarget ancestor walk).
    #
    # These two maps shadow the unflushed window so the raw `ChainDb`
    # readers (used by validation, mempool, mining, RPC) transparently see
    # in-flight IBD blocks. They are the single source of truth for the
    # unflushed window: `connectBlockIBD` populates them, `flushIBDBatch`
    # clears them once the rows are durable in RocksDB.
    ibdIndexByHash*: Table[BlockHash, BlockIndex]
    ibdIndexByHeight*: Table[int32, BlockHash]

  ## ChainState wraps ChainDb with cache management and consensus params
  ChainState* = ref object
    db*: ChainDb
    bestBlockHash*: BlockHash
    bestHeight*: int32
    totalWork*: array[32, byte]
    params*: ConsensusParams
    utxoCache*: Table[OutPoint, UtxoEntry]
    cacheSize*: int
    maxCacheSize*: int  ## Flush at 50000
    undoMgr*: UndoFileManager  ## Manages flat file undo storage
    # IBD batching state
    ibdBatch*: WriteBatch        ## Persistent write batch for IBD
    ibdBatchBlocks*: int         ## Blocks accumulated in current batch
    ibdMode*: bool               ## True during initial block download
    # Pending UTXO deletes tracked during IBD (cache key -> true)
    ibdDeletedUtxos*: Table[string, bool]
    # Disk flush state — tracks blocks since last forced memtable→SST flush.
    # Separate from ibdBatchBlocks so that stopIBD/startIBD oscillations
    # (from P2P sync and RPC feeder running concurrently) don't trigger
    # expensive column-family flushes on every state transition.
    ibdBlocksSinceLastDiskFlush*: int
    ibdDiskFlushInterval*: int   ## Configurable via --ibd-flush-interval (default 2000)
    # NOTE: the IBD unflushed block-index shadow now lives on `ChainDb`
    # (`ibdIndexByHash` / `ibdIndexByHeight`). It used to be a height-only
    # `ibdHeightToHash` map here, but that could not cover hash -> index
    # lookups (getMtpForHeight's getBlockIndex walk, the diffbits
    # getAncestor retarget walk). Moving it down to ChainDb makes the raw
    # `getBlockIndex` / `getBlockHashByHeight` readers shadow-aware for
    # EVERY caller (validation, mempool, mining, RPC) — one source of truth.
    # Multi-block reorg atomicity: while a single-batch reorg is in progress
    # (handleReorg), reads from getUtxo must be filtered against UTXOs that
    # have been *staged* into the in-flight WriteBatch but not yet written
    # to disk. Without this filter, a getUtxo cache-miss would fall through
    # to RocksDB and return a stale (old-chain) UTXO that the staged batch
    # has marked for deletion. See `handleReorg` (Pattern D — single-batch
    # disconnect+reconnect, CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md).
    # nil outside of handleReorg.
    reorgDeletedUtxos*: TableRef[string, bool]
    # Optional disconnect hook fired after a successful block disconnect
    # (legacy `disconnectBlock` and Pattern-D `handleReorg`). Wired by the
    # daemon (src/nimrod.nim) when --blockfilterindex is enabled, so the
    # BIP-157 BlockFilterIndex's customRemove fires symmetrically with the
    # connect-side `addBlock` hook in network/sync.nim + rpc/server.nim.
    # nil when the index is disabled (or in tests that do not exercise the
    # filter index). Indirected through a callback so chainstate.nim does
    # not have to import storage/indexes/blockfilterindex (which would
    # create a circular dep through indexes/base via undo-shim).
    # Reference: bitcoin-core/src/index/base.cpp::BaseIndex::BlockDisconnected.
    disconnectHook*: proc(blockHash: BlockHash, prevHash: BlockHash,
                          height: int32) {.raises: [].}
    # Optional per-block script-verification hook fired by `handleReorg` while
    # connecting each promoted side-branch block, BEFORE that block's UTXO
    # mutation is staged. Closes the reorg false-accept (chain-split class):
    # the inline connect loop in `handleReorg` mutated the UTXO set
    # (spend/create/index/advance-tip) but ran NO per-input script
    # verification, so an invalid-script block sitting on a higher-work
    # side-branch could be promoted onto the active chain with forged
    # signatures unchecked. Bitcoin Core re-runs full script verification on
    # every reorg-connected block via ConnectTip -> ConnectBlock
    # (validation.cpp), and rustoshi (reorganize -> connect_block_with_
    # sequence_locks) + blockbrew (ReorgTo -> ConnectBlock) do the same.
    #
    # The hook receives the candidate block and its height and returns ok()
    # when every input script verifies (or scripts are legitimately skipped
    # under assume-valid), or an error string on the first script failure —
    # which aborts the reorg and rolls the in-memory + on-disk state back to
    # the pre-reorg chain (RocksDB WriteBatch is never committed).
    #
    # Indirected through a callback so chainstate.nim does NOT import
    # consensus/validation (which imports storage/chainstate — a cycle).
    # Wired by the layer that owns both the ChainState and a CryptoEngine
    # (src/rpc/server.nim, the only handleReorg caller). When nil (tests, or
    # before wiring) the loop behaves as before — but the production reorg
    # path MUST wire it so promoted blocks are script-verified.
    #
    # Returns (ok: true) when every input script verifies, or
    # (ok: false, err: <reason>) on the first failure. A plain tuple is used
    # instead of ChainStateResult[void] because this field is declared inside
    # the ChainState object body, before the generic `case` ChainStateResult
    # type is fully defined in the same `type` section (Nim rejects the
    # forward reference to a generic variant type as a proc return type here).
    reorgVerifyHook*: proc(blk: Block, height: int32): tuple[ok: bool, err: string]
                          {.gcsafe, raises: [].}

  ## Result type for chainstate operations
  ChainStateResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

# Result constructors
proc ok*[T](val: T): ChainStateResult[T] =
  ChainStateResult[T](isOk: true, value: val)

proc ok*(): ChainStateResult[void] =
  ChainStateResult[void](isOk: true)

proc err*(T: typedesc, msg: string): ChainStateResult[T] =
  ChainStateResult[T](isOk: false, error: msg)

proc err*(msg: string): ChainStateResult[void] =
  ChainStateResult[void](isOk: false, error: msg)

# Key helpers

proc outpointKey(txid: TxId, vout: uint32): string =
  ## Cache key for outpoints
  result = newString(36)
  let txidArr = array[32, byte](txid)
  for i in 0..<32:
    result[i] = char(txidArr[i])
  result[32] = char((vout shr 24) and 0xff)
  result[33] = char((vout shr 16) and 0xff)
  result[34] = char((vout shr 8) and 0xff)
  result[35] = char(vout and 0xff)

proc outpointKey(op: OutPoint): string =
  outpointKey(op.txid, op.vout)

# Serialization for BlockIndex

proc serializeBlockIndex*(idx: BlockIndex): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(idx.hash)
  w.writeInt32LE(idx.height)
  w.writeUint8(uint8(ord(idx.status)))
  w.writeBlockHash(idx.prevHash)
  w.writeBlockHeader(idx.header)
  w.writeBytes(idx.totalWork)
  # Serialize undo file position
  w.writeInt32LE(idx.undoPos.fileNum)
  w.writeInt32LE(idx.undoPos.pos)
  # Serialize failure flags and sequence ID (new in phase 51)
  w.writeUint8(uint8(idx.failureFlags))
  w.writeInt32LE(idx.sequenceId)
  # Serialize nTx (W57: transaction count per block for getblockheader RPC)
  w.writeInt32LE(idx.nTx)
  w.data

proc deserializeBlockIndex*(data: seq[byte]): BlockIndex =
  var r = BinaryReader(data: data, pos: 0)
  result.hash = r.readBlockHash()
  result.height = r.readInt32LE()
  result.status = BlockStatus(r.readUint8())
  result.prevHash = r.readBlockHash()
  result.header = r.readBlockHeader()
  result.totalWork = r.readHash()
  # Deserialize undo file position (with backward compatibility)
  if r.remaining() >= 8:
    result.undoPos.fileNum = r.readInt32LE()
    result.undoPos.pos = r.readInt32LE()
  else:
    # Legacy format without undo position
    result.undoPos = FlatFilePos(fileNum: -1, pos: -1)
  # Deserialize failure flags and sequence ID (with backward compatibility)
  if r.remaining() >= 5:
    result.failureFlags = BlockFailureFlags(r.readUint8())
    result.sequenceId = r.readInt32LE()
  else:
    result.failureFlags = BLOCK_NO_FAILURE
    result.sequenceId = 0
  # Deserialize nTx (W57, backward compatible — 0 if not present in old data)
  if r.remaining() >= 4:
    result.nTx = r.readInt32LE()
  else:
    result.nTx = 0

# Serialization for UtxoEntry

proc serializeUtxoEntry*(entry: UtxoEntry): seq[byte] =
  ## Exported so the snapshot loader can stage per-coin writes directly into
  ## its WriteBatch (FIX-D, chainstate atomicity family 2026-05-26) without
  ## taking the per-coin `putUtxo` round-trip.
  var w = BinaryWriter()
  w.writeTxOut(entry.output)
  w.writeInt32LE(entry.height)
  w.writeUint8(if entry.isCoinbase: 1 else: 0)
  w.data

proc deserializeUtxoEntry*(data: seq[byte]): UtxoEntry =
  var r = BinaryReader(data: data, pos: 0)
  result.output = r.readTxOut()
  result.height = r.readInt32LE()
  result.isCoinbase = r.readUint8() != 0

# Serialization for UndoData

proc serializeUndoData*(undo: UndoData): seq[byte] =
  var w = BinaryWriter()
  w.writeCompactSize(uint64(undo.spentOutputs.len))
  for (outpoint, entry) in undo.spentOutputs:
    w.writeOutPoint(outpoint)
    let entryBytes = serializeUtxoEntry(entry)
    w.writeCompactSize(uint64(entryBytes.len))
    w.writeBytes(entryBytes)
  w.data

proc deserializeUndoData*(data: seq[byte]): UndoData =
  var r = BinaryReader(data: data, pos: 0)
  let count = r.readCompactSize()
  for i in 0 ..< int(count):
    let outpoint = r.readOutPoint()
    let entryLen = r.readCompactSize()
    let entryBytes = r.readBytes(int(entryLen))
    let entry = deserializeUtxoEntry(entryBytes)
    result.spentOutputs.add((outpoint, entry))

# TxIndex entry: block hash + position in block

type TxLocation* = object
  blockHash*: BlockHash
  txIndex*: uint32  ## Index within block

proc serializeTxLocation(loc: TxLocation): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(loc.blockHash)
  w.writeUint32LE(loc.txIndex)
  w.data

proc deserializeTxLocation(data: seq[byte]): TxLocation =
  var r = BinaryReader(data: data, pos: 0)
  result.blockHash = r.readBlockHash()
  result.txIndex = r.readUint32LE()

# ChainDb operations (low-level database access)

# Forward declaration — definition lives further down with the rest of the
# snapshot-load atomicity helpers (FIX-D). Declared here so `openChainDb` can
# call it during DB open.
proc recoverFromSnapshotCrash*(cdb: ChainDb): bool

proc openChainDb*(path: string): ChainDb =
  ## Open the chain database
  result = ChainDb(
    db: openDatabase(path),
    bestBlockHash: BlockHash(default(array[32, byte])),
    bestHeight: -1,
    ibdIndexByHash: initTable[BlockHash, BlockIndex](),
    ibdIndexByHeight: initTable[int32, BlockHash]()
  )

  # FIX-D (chainstate atomicity family 2026-05-26): if the previous process
  # crashed mid-`loadtxoutset`, the SNAPSHOT_LOAD_IN_PROGRESS marker is still
  # set in cfMeta. Clear the partial chainstate + reset tip BEFORE we read the
  # tip pointer below — otherwise we'd publish the stale tip pointer to
  # consensus code that would then read inconsistent UTXOs.
  #
  # Wrapped in try/except + {.cast(gcsafe).} so the recovery code's
  # chronicles-log + RocksDB iterator exception surface (Exception-typed,
  # and the iter pulls from globals that the strict-gcsafe checker can't
  # see across) does not widen the exception/gcsafe footprint of
  # openChainDb / newChainState — which is called from the
  # chronos-`{.async.}` daemon entry point.
  {.cast(gcsafe).}:
    try:
      discard result.recoverFromSnapshotCrash()
    except CatchableError as e:
      warn "recoverFromSnapshotCrash failed; daemon will continue with on-disk tip",
           err = e.msg
    except Exception as e:
      warn "recoverFromSnapshotCrash hit unexpected Exception; daemon continuing",
           err = e.msg

  # Load best block from meta
  let bestHashData = result.db.get(cfMeta, metaKey("bestblock"))
  if bestHashData.isSome:
    var hash: array[32, byte]
    copyMem(addr hash[0], addr bestHashData.get()[0], 32)
    result.bestBlockHash = BlockHash(hash)

  let heightData = result.db.get(cfMeta, metaKey("height"))
  if heightData.isSome:
    var r = BinaryReader(data: heightData.get(), pos: 0)
    result.bestHeight = r.readInt32LE()

proc close*(cdb: var ChainDb) =
  cdb.db.close()

# Block storage (ChainDb)

proc storeBlock*(cdb: ChainDb, blk: Block) =
  ## Store full block data
  let headerBytes = serialize(blk.header)
  let hash = doubleSha256(headerBytes)

  cdb.db.put(cfBlocks, blockKey(hash), serialize(blk))

proc getBlock*(cdb: ChainDb, hash: BlockHash): Option[Block] =
  ## Retrieve block by hash
  let data = cdb.db.get(cfBlocks, blockKey(array[32, byte](hash)))
  if data.isSome:
    return some(deserializeBlock(data.get()))
  none(Block)

# Block index operations (ChainDb)

proc putBlockIndex*(cdb: ChainDb, idx: BlockIndex) =
  ## Store block index entry (by hash)
  cdb.db.put(cfBlockIndex, blockKey(array[32, byte](idx.hash)), serializeBlockIndex(idx))
  # Also store height -> hash mapping
  cdb.db.put(cfBlockIndex, blockIndexKey(idx.height), @(array[32, byte](idx.hash)))

proc putBlockIndexHashOnly*(cdb: ChainDb, idx: BlockIndex) =
  ## Store a block index entry by hash WITHOUT touching the height -> hash
  ## mapping. Used for side-branch blocks where the active chain already
  ## owns the height -> hash slot. Mirrors Bitcoin Core's
  ## `BlockManager::AcceptBlock` (validation.cpp), which always writes the
  ## CBlockIndex regardless of which chain the block lives on but never
  ## mutates the active chain's height index until ActivateBestChain.
  cdb.db.put(cfBlockIndex, blockKey(array[32, byte](idx.hash)), serializeBlockIndex(idx))

proc getBlockIndex*(cdb: ChainDb, hash: BlockHash): Option[BlockIndex] =
  ## Get block index by hash.
  ##
  ## Consults the IBD unflushed shadow FIRST: during IBD `connectBlockIBD`
  ## defers index rows into a write batch that is not visible to a plain
  ## RocksDB read until the periodic flush. Without this, every contextual
  ## consensus check that walks recent blocks (getMtpForHeight finality
  ## cutoff, the diffbits getAncestor retarget walk) would read stale data
  ## for the whole unflushed window. See the `ibdIndexByHash` field comment.
  if cdb.ibdIndexByHash.len > 0:
    let shadow = cdb.ibdIndexByHash.getOrDefault(hash, BlockIndex(height: -1))
    if shadow.height >= 0:
      return some(shadow)
  let data = cdb.db.get(cfBlockIndex, blockKey(array[32, byte](hash)))
  if data.isSome:
    return some(deserializeBlockIndex(data.get()))
  none(BlockIndex)

proc getBlockHashByHeight*(cdb: ChainDb, height: int32): Option[BlockHash] =
  ## Get block hash at given height.
  ##
  ## Consults the IBD unflushed shadow FIRST (see `getBlockIndex` above and
  ## the `ibdIndexByHeight` field comment): mid-IBD the height -> hash rows
  ## for the unflushed window live only in the in-memory shadow, not yet in
  ## RocksDB. getMtpForHeight walks this proc for the previous 11 blocks; a
  ## stale miss there silently truncated the MTP window and rejected valid
  ## blocks with "bad-txns-nonfinal".
  if cdb.ibdIndexByHeight.len > 0 and height in cdb.ibdIndexByHeight:
    return some(cdb.ibdIndexByHeight[height])
  let data = cdb.db.get(cfBlockIndex, blockIndexKey(height))
  if data.isSome and data.get().len >= 32:
    var hash: array[32, byte]
    copyMem(addr hash[0], addr data.get()[0], 32)
    return some(BlockHash(hash))
  none(BlockHash)

proc getBlockByHeight*(cdb: ChainDb, height: int32): Option[Block] =
  ## Get block at height
  let hashOpt = cdb.getBlockHashByHeight(height)
  if hashOpt.isSome:
    return cdb.getBlock(hashOpt.get())
  none(Block)

proc getBlockHashByHeight*(cs: ChainState, height: int32): Option[BlockHash] =
  ## Get block hash at given height.
  ##
  ## Delegates to the raw `ChainDb` reader, which now consults the IBD
  ## unflushed shadow itself — so the unflushed window is covered uniformly
  ## for every caller (validation/mempool/mining/RPC) instead of only this
  ## ChainState-typed path. During IBD blocks are batched and only written
  ## to RocksDB every 2000 blocks; the shadow ensures getblockhash is never
  ## "out of range" for heights that are already connected.
  cs.db.getBlockHashByHeight(height)

# UTXO operations (ChainDb - low level)

proc putUtxo*(cdb: ChainDb, outpoint: OutPoint, entry: UtxoEntry) =
  ## Add or update UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.put(cfUtxo, key, serializeUtxoEntry(entry))

proc getUtxo*(cdb: ChainDb, outpoint: OutPoint): Option[UtxoEntry] =
  ## Get UTXO entry directly from database (no caching at this layer;
  ## ChainState.utxoCache provides bounded caching above).
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  let data = cdb.db.get(cfUtxo, key)
  if data.isSome:
    return some(deserializeUtxoEntry(data.get()))
  none(UtxoEntry)

proc deleteUtxo*(cdb: ChainDb, outpoint: OutPoint) =
  ## Remove UTXO
  let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
  cdb.db.delete(cfUtxo, key)

proc hasUtxo*(cdb: ChainDb, outpoint: OutPoint): bool =
  cdb.getUtxo(outpoint).isSome

# TX index operations (ChainDb)

proc putTxIndex*(cdb: ChainDb, txid: TxId, location: TxLocation) =
  ## Index a transaction
  cdb.db.put(cfTxIndex, txIndexKey(array[32, byte](txid)), serializeTxLocation(location))

proc getTxIndex*(cdb: ChainDb, txid: TxId): Option[TxLocation] =
  ## Look up transaction location
  let data = cdb.db.get(cfTxIndex, txIndexKey(array[32, byte](txid)))
  if data.isSome:
    return some(deserializeTxLocation(data.get()))
  none(TxLocation)

# Undo data operations (ChainDb)

proc undoKey(hash: BlockHash): seq[byte] =
  ## Key for undo data: "undo:" prefix + block hash
  result = @[byte('u'), byte('n'), byte('d'), byte('o'), byte(':')]
  result.add(@(array[32, byte](hash)))

proc putUndoData*(cdb: ChainDb, blockHash: BlockHash, undo: UndoData) =
  ## Store undo data for a block
  cdb.db.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))

proc getUndoData*(cdb: ChainDb, blockHash: BlockHash): Option[UndoData] =
  ## Get undo data for a block
  let data = cdb.db.get(cfMeta, undoKey(blockHash))
  if data.isSome:
    return some(deserializeUndoData(data.get()))
  none(UndoData)

proc deleteUndoData*(cdb: ChainDb, blockHash: BlockHash) =
  ## Remove undo data for a block
  cdb.db.delete(cfMeta, undoKey(blockHash))

proc getBlockUndoFromFile*(cs: ChainState, blockIdx: BlockIndex,
                           prevHash: BlockHash): Option[BlockUndo] =
  ## Read BlockUndo from the flat file rev*.dat using the block index undoPos.
  ## Returns none if undoPos is invalid, undoMgr is nil, or the read fails.
  ## Exported so that RPC handlers can compute per-tx fees without needing
  ## to import undo.nim directly.
  if blockIdx.undoPos.fileNum < 0 or blockIdx.undoPos.pos < 0:
    return none(BlockUndo)
  if cs.undoMgr == nil:
    return none(BlockUndo)
  let (bu, ok) = cs.undoMgr.readBlockUndo(blockIdx.undoPos, prevHash, cs.params)
  if ok: some(bu) else: none(BlockUndo)

# Chain state updates (ChainDb)

proc updateBestBlock*(cdb: ChainDb, hash: BlockHash, height: int32) =
  ## Update best block pointer
  cdb.bestBlockHash = hash
  cdb.bestHeight = height

  cdb.db.put(cfMeta, metaKey("bestblock"), @(array[32, byte](hash)))

  var w = BinaryWriter()
  w.writeInt32LE(height)
  cdb.db.put(cfMeta, metaKey("height"), w.data)

# ============================================================================
# Snapshot-load atomicity marker (analog of ouroboros FIX-D, 2026-05-26).
# ============================================================================
#
# `loadSnapshot` (the `loadtxoutset` RPC handler in `snapshot.nim`) historically
# wrote per-coin UTXOs directly via `putUtxo` and then called `updateBestBlock`
# as a separate step. A SIGKILL between those two steps left RocksDB with a mix
# of new-snapshot UTXOs and the old chain tip pointer — a half-loaded state
# that subsequent block validation would happily mistake for a healthy chain.
#
# To close this gap we follow ouroboros's three-phase FIX-D protocol:
#
#   Phase 1 (begin): write the `SNAPSHOT_LOAD_IN_PROGRESS` marker via
#     `writeSynced` (WAL + fsync) BEFORE any per-coin write. After this
#     completes, a crash leaves the marker on disk and `recoverFromSnapshotCrash`
#     on next open detects + clears the partial state.
#   Phase 2 (chunks): apply N coins per RocksDB WriteBatch (single batch is
#     atomic across all CFs; we still keep WAL on for the chunked writes so
#     the per-chunk write is durable, matching ouroboros's chunk semantics).
#   Phase 3 (commit): a single WriteBatch fuses tip update + marker delete,
#     written via `writeSynced` so either all three (bestblock, height, marker
#     deletion) land or none do.
#
# The marker key lives in `cfMeta` under a fixed name. Value is
# `[32-byte base_blockhash][4-byte base_height LE]` (36 bytes), matching the
# ouroboros payload so future cross-impl tooling can read it byte-identically.
#
# Reference: ouroboros commit 2b76e0e + family doc
# `CORE-PARITY-AUDIT/_chainstate-atomicity-family-2026-05-26.md`.

const SnapshotLoadMarkerKey* = "snapshot_load_in_progress"
  ## cfMeta key name for the SNAPSHOT_LOAD_IN_PROGRESS marker. Public so
  ## tests and tooling can probe it.

proc writeSnapshotLoadMarker*(cdb: ChainDb,
                               baseBlockhash: BlockHash,
                               baseHeight: int32) =
  ## Phase 1 — write the SNAPSHOT_LOAD_IN_PROGRESS marker to cfMeta. Caller
  ## should invoke this BEFORE any per-coin UTXO write so a crash mid-load can
  ## be detected on next open. We persist via the synced sibling
  ## (`writeSynced` on a single-entry batch) so the marker survives a crash
  ## even if the daemon previously called `disableWAL` for IBD throughput.
  var value = newSeq[byte](36)
  let h = array[32, byte](baseBlockhash)
  for i in 0 ..< 32:
    value[i] = h[i]
  let height = cast[uint32](baseHeight)
  value[32] = byte(height and 0xff)
  value[33] = byte((height shr 8) and 0xff)
  value[34] = byte((height shr 16) and 0xff)
  value[35] = byte((height shr 24) and 0xff)

  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()
  batch.put(cfMeta, metaKey(SnapshotLoadMarkerKey), value)
  cdb.db.writeSynced(batch)

proc getSnapshotLoadMarker*(cdb: ChainDb):
    Option[tuple[baseBlockhash: BlockHash, baseHeight: int32]] =
  ## Read the SNAPSHOT_LOAD_IN_PROGRESS marker if present. Returns the
  ## `(baseBlockhash, baseHeight)` of the in-progress load, or `none` if no
  ## load is in progress.
  let data = cdb.db.get(cfMeta, metaKey(SnapshotLoadMarkerKey))
  if data.isNone:
    return none(tuple[baseBlockhash: BlockHash, baseHeight: int32])
  let bytes = data.get()
  if bytes.len != 36:
    # Defensive: corrupt marker. Treat as present so the recovery path clears
    # the chainstate — better to lose a not-yet-committed snapshot than to
    # silently keep a half-loaded one.
    return some((baseBlockhash: BlockHash(default(array[32, byte])),
                 baseHeight: 0'i32))
  var hash: array[32, byte]
  for i in 0 ..< 32:
    hash[i] = bytes[i]
  let height = int32(
    uint32(bytes[32]) or
    (uint32(bytes[33]) shl 8) or
    (uint32(bytes[34]) shl 16) or
    (uint32(bytes[35]) shl 24)
  )
  some((baseBlockhash: BlockHash(hash), baseHeight: height))

proc hasSnapshotLoadMarker*(cdb: ChainDb): bool =
  ## Convenience predicate — tests + operator diagnostics.
  cdb.db.contains(cfMeta, metaKey(SnapshotLoadMarkerKey))

proc clearUtxoColumnFamily*(cdb: ChainDb) =
  ## Iterate every key in `cfUtxo` and delete it in a single WriteBatch. Used
  ## by `recoverFromSnapshotCrash` to reset the chainstate after detecting a
  ## crashed `loadtxoutset` — partial per-coin chunks have half-overwritten the
  ## UTXO set and there is no per-block undo trail to replay back to the prior
  ## tip, so the only safe recovery is to wipe the UTXO CF and force the
  ## operator to re-run `loadtxoutset`. Mirrors ouroboros's `clear_chainstate`.
  var keysToDelete: seq[seq[byte]] = @[]
  for (key, _) in cdb.db.iterCf(cfUtxo):
    keysToDelete.add(key)
  if keysToDelete.len == 0:
    return
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()
  for k in keysToDelete:
    batch.delete(cfUtxo, k)
  cdb.db.writeSynced(batch)

proc recoverFromSnapshotCrash*(cdb: ChainDb): bool =
  ## Called during `openChainDb`. If a SNAPSHOT_LOAD_IN_PROGRESS marker is
  ## present, the previous process crashed mid-`loadtxoutset` and the UTXO CF
  ## contains a mix of partial-snapshot + partial-old coins that cannot be
  ## safely repaired. We:
  ##   1. wipe the UTXO column family,
  ##   2. reset the on-disk tip pointer to all-zeros / height 0 (genesis
  ##      sentinel — distinguishable from any real tip),
  ##   3. delete the marker.
  ## The operator must re-run `loadtxoutset` from the source file to restore
  ## the chainstate. Returns `true` if a recovery was performed, `false`
  ## otherwise. Mirrors ouroboros's `recover_from_crash` (snapshot branch).
  let markerOpt = cdb.getSnapshotLoadMarker()
  if markerOpt.isNone:
    return false

  let marker = markerOpt.get()
  warn "SNAPSHOT_LOAD_IN_PROGRESS marker found — crash detected during loadtxoutset; clearing chainstate",
       baseHeight = marker.baseHeight

  cdb.clearUtxoColumnFamily()

  # Reset best-block to all-zeros / height 0 so callers see a clean slate
  # and don't try to validate blocks above a missing UTXO set. Fuse the
  # reset + marker-delete into one atomic, synced WriteBatch — either both
  # land or neither does, so a second crash here cannot leave the daemon in
  # a state where the marker is gone but the tip still points at the snapshot.
  let zeroHash = BlockHash(default(array[32, byte]))
  cdb.bestBlockHash = zeroHash
  cdb.bestHeight = 0
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](zeroHash)))
  var w = BinaryWriter()
  w.writeInt32LE(0)
  batch.put(cfMeta, metaKey("height"), w.data)
  batch.delete(cfMeta, metaKey(SnapshotLoadMarkerKey))
  cdb.db.writeSynced(batch)

  warn "Snapshot-load crash recovery complete — chainstate cleared; tip reset to genesis-sentinel; re-run loadtxoutset to restore"
  true

# ============================================================================
# ChainState - High-level UTXO set manager with cache and reorg support
# ============================================================================

const
  DefaultMaxCacheSize* = 50000
  ## Maximum memory budget for UTXO cache (2 GiB — increased for faster IBD)
  MaxCacheBytes* = 2_147_483_648
  ## Eviction target: evict down to half the max (~225 MiB)
  EvictTargetBytes* = MaxCacheBytes div 2
  ## IBD batch flush interval: write batch to memtable every N blocks
  IbdBatchFlushInterval* = 2000
  ## Estimated bytes per cache entry (OutPoint key ~60 bytes + UtxoEntry ~80 bytes + Table overhead ~32 bytes)
  EstimatedEntryBytes* = 172

proc newChainState*(dbPath: string, params: ConsensusParams): ChainState =
  ## Create a new ChainState with given path and consensus params
  let cdb = openChainDb(dbPath)
  result = ChainState(
    db: cdb,
    bestBlockHash: cdb.bestBlockHash,
    bestHeight: cdb.bestHeight,
    totalWork: default(array[32, byte]),
    params: params,
    utxoCache: initTable[OutPoint, UtxoEntry](),
    cacheSize: 0,
    maxCacheSize: DefaultMaxCacheSize,
    undoMgr: newUndoFileManager(dbPath / "blocks"),
    ibdBatch: nil,
    ibdBatchBlocks: 0,
    ibdMode: false,
    ibdDeletedUtxos: initTable[string, bool](),
    ibdBlocksSinceLastDiskFlush: 0,
    ibdDiskFlushInterval: IbdBatchFlushInterval,  # default: flush to disk every 2000 blocks
    reorgDeletedUtxos: nil,
    disconnectHook: nil
  )

  # Load total work from DB if available
  let workData = cdb.db.get(cfMeta, metaKey("totalwork"))
  if workData.isSome and workData.get().len >= 32:
    copyMem(addr result.totalWork[0], addr workData.get()[0], 32)

proc close*(cs: var ChainState) =
  cs.undoMgr.close()
  cs.db.close()

# UTXO operations (ChainState - with cache management)

proc getUtxo*(cs: ChainState, op: OutPoint): Option[UtxoEntry] =
  ## Get UTXO entry, checking cache first
  ## During IBD, also checks deletion tracking
  ## During a single-batch reorg, also checks reorg-tentative-delete tracking
  ## so cache-misses don't fall through to RocksDB and return UTXOs that the
  ## in-flight batch has already marked for deletion.
  let ck = outpointKey(op)

  # During IBD, check if this UTXO was deleted in the current unflushed batch
  if cs.ibdMode:
    if ck in cs.ibdDeletedUtxos:
      return none(UtxoEntry)

  # During a multi-block reorg, the WriteBatch is held open across N+M blocks
  # and not flushed to disk until the end. UTXOs that the batch has staged
  # for deletion (created by disconnected old-chain blocks, or spent by
  # connected new-chain blocks) must not be returned from RocksDB.
  if cs.reorgDeletedUtxos != nil:
    if ck in cs.reorgDeletedUtxos[]:
      return none(UtxoEntry)

  # Check local cache first
  if op in cs.utxoCache:
    return some(cs.utxoCache[op])

  # Fall back to database
  cs.db.getUtxo(op)

proc putUtxoCache*(cs: var ChainState, op: OutPoint, entry: UtxoEntry) =
  ## Add UTXO to cache (doesn't write to DB until flush)
  if op notin cs.utxoCache:
    inc cs.cacheSize
  cs.utxoCache[op] = entry

proc deleteUtxoCache*(cs: var ChainState, op: OutPoint) =
  ## Mark UTXO as deleted in cache
  if op in cs.utxoCache:
    cs.utxoCache.del(op)
    dec cs.cacheSize

proc flushCache*(cs: var ChainState) =
  ## Flush cached UTXOs to database
  for op, entry in cs.utxoCache:
    cs.db.putUtxo(op, entry)
  cs.utxoCache.clear()
  cs.cacheSize = 0

  # Also save total work
  cs.db.db.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

proc shouldFlush*(cs: ChainState): bool =
  cs.cacheSize >= cs.maxCacheSize

# Work calculation helpers

proc addWork(total: var array[32, byte], work: array[32, byte]) =
  ## Add work to total (256-bit addition, little-endian)
  var carry: uint32 = 0
  for i in 0 ..< 32:
    let sum = uint32(total[i]) + uint32(work[i]) + carry
    total[i] = byte(sum and 0xff)
    carry = sum shr 8

proc calculateBlockWork(bits: uint32): array[32, byte] =
  ## Calculate work from difficulty target
  ## Work = 2^256 / (target + 1)
  ## For simplicity, we approximate: work ≈ 2^(256-log2(target))
  ## A more accurate implementation would use big integer division
  let target = compactToTarget(bits)

  # Find the highest non-zero byte to estimate difficulty
  var highestBit = 0
  for i in countdown(31, 0):
    if target[i] != 0:
      highestBit = i * 8
      var b = target[i]
      while b != 0:
        inc highestBit
        b = b shr 1
      break

  # Work is approximately 2^(256 - highestBit)
  # For simplicity, set one bit at position (256 - highestBit)
  result = default(array[32, byte])
  if highestBit > 0 and highestBit < 256:
    let workBit = 256 - highestBit
    let bytePos = workBit div 8
    let bitPos = workBit mod 8
    if bytePos < 32:
      result[bytePos] = byte(1 shl bitPos)
  else:
    # Minimum work
    result[0] = 1

# Generate undo data before connecting a block

proc generateUndoData*(cs: ChainState, blk: Block, height: int32 = -1): UndoData =
  ## Generate undo data for a block (record all spent outputs).
  ## Legacy format - kept for backward compatibility.
  ##
  ## ``height`` is the height of the block being connected.  It is used as
  ## the per-coin ``height`` for any intra-block output spent later in the
  ## same block (those outputs would otherwise live at the current block's
  ## height in Bitcoin Core's view — they are not yet flushed to chainstate).
  ## If callers pass -1 (legacy default) we fall back to ``cs.bestHeight + 1``
  ## which is the height of the block currently being connected in all the
  ## existing call sites.
  ##
  ## W93 Gate (Core val:2600 / coins.cpp AddCoins): Bitcoin Core's view is
  ## mutated incrementally — `UpdateCoins` is called immediately after each
  ## transaction's input checks, so a later tx in the same block can spend
  ## an output created by an earlier tx in the same block.  nimrod calls
  ## `generateUndoData` BEFORE any state mutation, so `cs.getUtxo()` cannot
  ## see same-block outputs.  We must therefore track intra-block outputs
  ## locally and consult them first, otherwise the undo entry is silently
  ## dropped and disconnectBlock fails with the vin-count gate
  ## (chainstate.nim:1470 — Bitcoin Core val:2229-2232).
  let coinHeight = if height >= 0: height else: cs.bestHeight + 1
  var intra = initTable[string, UtxoEntry]()
  for txIdx, tx in blk.txs:
    # Skip coinbase inputs (nothing spent)
    if txIdx == 0:
      # Add coinbase outputs to intra-block index so a later tx in the
      # same block could spend them (CSV-style; matches Core's AddCoins
      # order).  Skip provably unspendable outputs to mirror AddCoins.
      let cbTxid = tx.txid()
      for vout, output in tx.outputs:
        if isUnspendable(output.scriptPubKey):
          continue
        let key = $array[32, byte](cbTxid) & ":" & $vout
        intra[key] = UtxoEntry(
          output: output, height: coinHeight,
          isCoinbase: true
        )
      continue

    for input in tx.inputs:
      let intraKey = $array[32, byte](input.prevOut.txid) & ":" & $input.prevOut.vout
      if intraKey in intra:
        result.spentOutputs.add((input.prevOut, intra[intraKey]))
        intra.del(intraKey)
        continue
      let utxoOpt = cs.getUtxo(input.prevOut)
      if utxoOpt.isSome:
        result.spentOutputs.add((input.prevOut, utxoOpt.get()))

    # After spending, add this tx's outputs to the intra-block index.
    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      if isUnspendable(output.scriptPubKey):
        continue
      let key = $array[32, byte](thisTxid) & ":" & $vout
      intra[key] = UtxoEntry(
        output: output, height: coinHeight,
        isCoinbase: false
      )

proc generateBlockUndo*(cs: ChainState, blk: Block, height: int32 = -1): BlockUndo =
  ## Generate BlockUndo data for flat file storage.
  ## One TxUndo per non-coinbase transaction, each containing all spent outputs.
  ##
  ## ``height`` is the height of the block being connected (same semantics as
  ## ``generateUndoData``).
  ##
  ## W93 Gate (Core val:2600 / coins.cpp AddCoins): same intra-block tracking
  ## as `generateUndoData` — see comment there.  Without this, a block with
  ## an intra-block tx chain (tx[2] spends tx[1]'s output) writes a TxUndo
  ## with fewer prevOutputs than tx.inputs, and disconnectBlock fails the
  ## vin-count gate (chainstate.nim:1470 — Bitcoin Core val:2229-2232).
  let coinHeight = if height >= 0: height else: cs.bestHeight + 1
  var intra = initTable[string, UtxoEntry]()
  for txIdx, tx in blk.txs:
    if txIdx == 0:
      # Index coinbase outputs as intra-block candidates.
      let cbTxid = tx.txid()
      for vout, output in tx.outputs:
        if isUnspendable(output.scriptPubKey):
          continue
        let key = $array[32, byte](cbTxid) & ":" & $vout
        intra[key] = UtxoEntry(
          output: output, height: coinHeight,
          isCoinbase: true
        )
      continue

    var txUndo = TxUndo()
    for input in tx.inputs:
      let intraKey = $array[32, byte](input.prevOut.txid) & ":" & $input.prevOut.vout
      if intraKey in intra:
        let entry = intra[intraKey]
        txUndo.prevOutputs.add(SpentOutput(
          output: entry.output,
          height: entry.height,
          isCoinbase: entry.isCoinbase
        ))
        intra.del(intraKey)
        continue
      let utxoOpt = cs.getUtxo(input.prevOut)
      if utxoOpt.isSome:
        let entry = utxoOpt.get()
        txUndo.prevOutputs.add(SpentOutput(
          output: entry.output,
          height: entry.height,
          isCoinbase: entry.isCoinbase
        ))
    result.txUndo.add(txUndo)

    # After this tx, add its outputs to intra-block index for any later tx.
    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      if isUnspendable(output.scriptPubKey):
        continue
      let key = $array[32, byte](thisTxid) & ":" & $vout
      intra[key] = UtxoEntry(
        output: output, height: coinHeight,
        isCoinbase: false
      )

# Connect a block to the chain

proc buildAssumeValidContext(cs: ChainState, blockHash: BlockHash,
                              height: int32): AssumeValidContext =
  ## Build an AssumeValidContext from ChainState for a block being connected.
  ## The best-header is approximated by the current chain tip (cs.totalWork).
  ## During IBD the chain tip IS the best-validated block, which is a safe
  ## lower bound for the chainwork check.
  result = AssumeValidContext(
    blockHash: blockHash,
    blockHeight: height,
    assumeValidHeight: cs.params.assumeValidHeight,
    # Best header: use chain tip height and accumulated work.
    # This is conservative — if anything, it under-counts chainwork.
    bestHeaderHeight: cs.bestHeight,
    bestHeaderChainWork: cs.totalWork
  )
  result.activeHashAtBlockHeight = cs.db.getBlockHashByHeight(height)
  if cs.params.assumeValidHeight > 0:
    result.activeHashAtAssumeValidHeight =
      cs.db.getBlockHashByHeight(cs.params.assumeValidHeight)

proc connectBlock*(cs: var ChainState, blk: Block, height: int32): ChainStateResult[void] =
  ## Connect a block: spend inputs, create outputs, update state
  ## Returns error if any input is missing or immature coinbase
  ## Undo data is written to flat files (rev*.dat) for efficient reorg handling

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # W93 Gate (Core val:2333): the view's best block must match the candidate
  # block's parent before mutation.  Bitcoin Core enforces this via
  # `assert(hashPrevBlock == view.GetBestBlock())` (validation.cpp:2333).
  # Without this guard, calling connectBlock with a non-extending block —
  # e.g. via a stale RPC call, an internal scheduler bug, or a future
  # callsite that forgets the parent check — would silently corrupt the
  # UTXO set.  Genesis (height==0) bypasses because cs.bestBlockHash is
  # zero-initialised before genesis is applied.
  if height > 0 and cs.bestBlockHash != blk.header.prevBlock:
    return err("connectBlock precondition violated: cs.bestBlockHash " &
               $cs.bestBlockHash & " != block.prevBlock " &
               $blk.header.prevBlock & " (height " & $height & ")")

  # Generate undo data before making changes (both formats for compatibility).
  # Pass `height` so intra-block-spent outputs get the correct creation height
  # in their SpentOutput entries (matches Core's UpdateCoins per-tx AddCoins).
  let undo = cs.generateUndoData(blk, height)
  let blockUndo = cs.generateBlockUndo(blk, height)

  # Write undo data to flat file
  var undoPos = FlatFilePos(fileNum: -1, pos: -1)
  if blk.txs.len > 1:  # Only write undo if there are non-coinbase transactions
    let (pos, ok) = cs.undoMgr.writeBlockUndo(blockUndo, blk.header.prevBlock, cs.params)
    if not ok:
      return err("failed to write undo data for block " & $blockHash)
    undoPos = pos

  # Create a write batch for atomic updates
  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()

  # Store full block data
  batch.put(cfBlocks, blockKey(array[32, byte](blockHash)), serialize(blk))

  # Genesis block: skip transaction connection.
  #
  # Bitcoin Core special-cases the genesis block at the top of `ConnectBlock`
  # (`bitcoin-core/src/validation.cpp:2337-2343`) and returns early without
  # touching the UTXO set:
  #
  #     if (block.GetHash() == m_chainman.GetParams()
  #             .GetConsensus().hashGenesisBlock) {
  #         if (!fJustCheck)
  #             view.SetBestBlock(pindex->GetBlockHash());
  #         return true;
  #     }
  #
  # Consequently the genesis coinbase output is unspendable and never
  # enters Core's chainstate. Without this guard, `connectBlock(genesis, 0)`
  # would write the genesis coinbase to `cfUtxo` and `gettxoutsetinfo` /
  # `dumptxoutset` would diverge from Core by one coin (W12 + W14).
  #
  # We still write the block index entry, totalWork, best-block pointer,
  # and full-block storage below — that bookkeeping is what `connectBlock`
  # needs to set up the chain tip, equivalent to the post-skip codepath in
  # Core's `ConnectTip` (`view.SetBestBlock` + the pindex flag updates).
  if height == 0:
    discard
  else:
    # Process each transaction
    for txIdx, tx in blk.txs:
      let txId = tx.txid()

      # Spend inputs (skip coinbase which has no inputs to spend)
      if txIdx > 0:
        for input in tx.inputs:
          let utxoOpt = cs.getUtxo(input.prevOut)
          if utxoOpt.isNone:
            return err("missing input: " & $input.prevOut.txid)

          let entry = utxoOpt.get()

          # Check coinbase maturity
          if entry.isCoinbase:
            let age = height - entry.height
            if age < int32(cs.params.coinbaseMaturity):
              # Use ancestor-check assumevalid semantics (Bitcoin Core v28.0).
              # The maturity bypass only applies when the block is on the
              # assumed-valid chain (ancestor check) — NOT a plain height check.
              let avCtx = buildAssumeValidContext(cs, blockHash, height)
              let skipReason = shouldSkipScripts(avCtx, cs.params)
              if skipReason == ssrSkip:
                warn "immature coinbase below assume-valid (allowing)",
                     height = height, coinbaseHeight = entry.height,
                     age = age, prevTxid = $input.prevOut.txid,
                     prevVout = input.prevOut.vout
              else:
                return err("immature coinbase spend at height " & $height &
                          ", coinbase height " & $entry.height &
                          ", age " & $age & " < " & $cs.params.coinbaseMaturity)

          # Delete from DB and cache
          let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
          batch.delete(cfUtxo, key)
          cs.deleteUtxoCache(input.prevOut)

      # Create outputs
      for voutIdx, output in tx.outputs:
        # Skip provably unspendable outputs (OP_RETURN, oversized scripts).
        # Mirrors `AddCoins` in bitcoin-core/src/coins.cpp which calls
        # `IsUnspendable()` (script.h:563) and never adds them to the UTXO
        # set. Without this filter, dumptxoutset emits 2x the coin count
        # for any chain whose coinbases carry the segwit witness-commitment
        # OP_RETURN output.
        if isUnspendable(output.scriptPubKey):
          continue
        let entry = UtxoEntry(
          output: output,
          height: height,
          isCoinbase: txIdx == 0
        )
        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
        batch.put(cfUtxo, key, serializeUtxoEntry(entry))
        cs.putUtxoCache(outpoint, entry)

      # Index transaction
      let loc = TxLocation(blockHash: blockHash, txIndex: uint32(txIdx))
      batch.put(cfTxIndex, txIndexKey(array[32, byte](txId)), serializeTxLocation(loc))

  # Calculate and add work
  let blockWork = calculateBlockWork(blk.header.bits)
  addWork(cs.totalWork, blockWork)

  # Create block index entry with undo position
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: cs.totalWork,
    undoPos: undoPos,
    nTx: int32(blk.txs.len)
  )
  batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  batch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Store undo data (legacy RocksDB format for backward compatibility)
  batch.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))

  # Update best block
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(height)
  batch.put(cfMeta, metaKey("height"), w.data)
  batch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

  # Commit atomically
  cs.db.db.write(batch)

  # Update in-memory state
  cs.bestBlockHash = blockHash
  cs.bestHeight = height
  cs.db.bestBlockHash = blockHash
  cs.db.bestHeight = height

  # Flush cache if needed
  if cs.shouldFlush():
    cs.flushCache()

  ok()

proc startIBD*(cs: var ChainState) =
  ## Enter IBD mode: enable write batching for performance
  cs.ibdMode = true
  cs.ibdBatch = cs.db.db.newWriteBatch()
  cs.ibdBatchBlocks = 0
  cs.ibdDeletedUtxos = initTable[string, bool]()
  # Increase cache size during IBD to reduce DB lookups
  cs.maxCacheSize = 200_000
  # Disable WAL for faster writes (data is durable via periodic batch flushes)
  cs.db.db.disableWAL()

proc evictCleanEntries*(cs: var ChainState) =
  ## Evict clean (already flushed) entries from the UTXO cache when memory
  ## exceeds MaxCacheBytes. Evicts down to EvictTargetBytes.
  ## During IBD the cache grows unbounded because flushIBDBatch writes entries
  ## to RocksDB but never removes them from memory. This bounds RSS.
  let cacheBytes = cs.cacheSize * EstimatedEntryBytes
  if cacheBytes <= MaxCacheBytes:
    return

  var toRemove: seq[OutPoint] = @[]
  var currentBytes = cacheBytes

  for op, entry in cs.utxoCache:
    if currentBytes <= EvictTargetBytes:
      break
    toRemove.add(op)
    currentBytes -= EstimatedEntryBytes

  for op in toRemove:
    cs.utxoCache.del(op)
    dec cs.cacheSize

proc flushIBDBatch*(cs: var ChainState) =
  ## Flush the accumulated IBD write batch to RocksDB as ONE atomically
  ## crash-durable operation.
  ##
  ## The batch carries the chain-tip pointer (`cfMeta` bestblock/height/
  ## totalwork), every staged UTXO mutation (`cfUtxo`), AND the block-index
  ## rows (`cfBlockIndex`, accumulated by `connectBlockIBD`). RocksDB applies a
  ## multi-column-family WriteBatch atomically across CFs, so the tip and the
  ## UTXO set move together — exactly the invariant Bitcoin Core's
  ## CCoinsViewDB::BatchWrite preserves with its DB_BEST_BLOCK batch.
  ##
  ## DURABILITY: the write goes through `writeSynced` (WAL on + fsync). During
  ## IBD the primary write path has its WAL disabled (`startIBD` → `disableWAL`)
  ## for throughput, so a plain `write` here would land only in the volatile
  ## memtable; durability would then hinge on `flushAllColumnFamilies`, whose
  ## per-CF `rocksdb_flush_cf` calls are NOT mutually atomic. A SIGKILL after
  ## the UTXO CF flushed but before the meta CF flushed would leave the
  ## on-disk tip pointer inconsistent with the on-disk UTXO set — silent
  ## chainstate corruption surviving the restart. `writeSynced` fsyncs the
  ## whole multi-CF batch as a unit, so a crash either loses the entire
  ## checkpoint (chainstate stays consistent at the previous flush; IBD just
  ## redownloads) or keeps all of it. There is no partial-checkpoint window.
  if cs.ibdBatch != nil and cs.ibdBatchBlocks > 0:
    # Write best block pointer into the batch so it's atomic
    cs.ibdBatch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](cs.bestBlockHash)))
    var w = BinaryWriter()
    w.writeInt32LE(cs.bestHeight)
    cs.ibdBatch.put(cfMeta, metaKey("height"), w.data)
    cs.ibdBatch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

    # Also flush cached UTXOs into the batch
    for op, entry in cs.utxoCache:
      let key = utxoKey(array[32, byte](op.txid), op.vout)
      cs.ibdBatch.put(cfUtxo, key, serializeUtxoEntry(entry))

    # Commit the entire batch atomically AND crash-durably (WAL + fsync).
    # See the proc docstring: a plain `write` is only memtable-durable while
    # IBD has the WAL disabled, which opens a tip-vs-UTXO desync window.
    cs.db.db.writeSynced(cs.ibdBatch)

    # Reset batch
    cs.ibdBatch.clear()
    cs.ibdBatchBlocks = 0
    cs.ibdDeletedUtxos.clear()
    # The batch is now durably committed to RocksDB (the `writeSynced` above
    # fsyncs the WAL), so the block-index rows are visible to plain reads.
    # Clear the unflushed shadow — clearing AFTER the write guarantees no
    # window where a read finds neither shadow nor DB.
    cs.db.ibdIndexByHash.clear()
    cs.db.ibdIndexByHeight.clear()

    # Update ChainDb in-memory state
    cs.db.bestBlockHash = cs.bestBlockHash
    cs.db.bestHeight = cs.bestHeight

    # Clear the entire UTXO cache after flush — all entries are now persisted
    # to RocksDB. Keeping them around wastes memory during IBD since the
    # working set moves forward (subsequent blocks rarely reference old UTXOs).
    # This bounds RSS to O(batch_interval * block_size) instead of O(chain_size).
    let evictedEntries = cs.cacheSize
    cs.utxoCache.clear()
    cs.cacheSize = 0
    info "flushed IBD batch", height = cs.bestHeight, evicted = evictedEntries,
         batchBlocks = IbdBatchFlushInterval

proc flushToDiskIfNeeded*(cs: var ChainState, force: bool = false) =
  ## Force all memtables to SST files if enough blocks have accumulated
  ## since the last disk flush, or unconditionally if force=true.
  ## WAL is disabled during IBD, so memtable data is volatile. This call
  ## is the ONLY mechanism that makes chainstate durable during IBD.
  if force or cs.ibdBlocksSinceLastDiskFlush >= cs.ibdDiskFlushInterval:
    cs.db.db.flushAllColumnFamilies()
    info "flushed memtables to SST", height = cs.bestHeight,
         blocksSinceFlush = cs.ibdBlocksSinceLastDiskFlush
    cs.ibdBlocksSinceLastDiskFlush = 0

proc stopIBD*(cs: var ChainState) =
  ## Exit IBD mode: flush remaining batch and switch to per-block writes
  if cs.ibdBatch != nil:
    cs.flushIBDBatch()
    # Force memtables to SST so all data is durable before leaving IBD
    cs.flushToDiskIfNeeded(force = true)
    cs.ibdBatch.destroy()
    cs.ibdBatch = nil
  cs.ibdMode = false
  cs.maxCacheSize = DefaultMaxCacheSize
  # Re-enable WAL for normal operation
  cs.db.db.enableWAL()

proc scrubUnspendable*(cs: var ChainState):
    tuple[removed: uint64, bytesFreed: uint64] =
  ## One-shot operator-invoked scrub: walk the entire UTXO column family,
  ## delete every entry whose scriptPubKey is provably unspendable per
  ## `CScript::IsUnspendable()` (OP_RETURN-prefixed OR > MAX_SCRIPT_SIZE).
  ##
  ## Closes the legacy datadir gap left by the byte-identity fix
  ## (94b7755): existing chainstates created BEFORE that commit still carry
  ## orphan OP_RETURN coins from segwit-coinbase witness commitments. The
  ## write-time filter only stops new writes — it can't remove stale rows.
  ##
  ## Idempotent: a second call removes 0 rows. Safe to run with the cache
  ## non-empty; we also drop in-cache unspendable entries so the user can
  ## scrub mid-IBD if desired (though "operator-invoked, not on startup"
  ## remains the canonical use case).
  ##
  ## Returns (removed_count, bytes_freed) where bytes_freed sums
  ## (key_len + value_len) for every deleted entry (an estimate of LSM
  ## payload reclaimed once compaction sweeps the tombstones).
  result.removed = 0
  result.bytesFreed = 0

  # Phase 1: drop unspendable rows from the in-memory cache so we don't
  # re-flush them and so a same-process gettxoutsetinfo sees the truth.
  var cacheKeysToDrop: seq[OutPoint] = @[]
  for op, entry in cs.utxoCache:
    if isUnspendable(entry.output.scriptPubKey):
      cacheKeysToDrop.add(op)
  for op in cacheKeysToDrop:
    cs.utxoCache.del(op)
    if cs.cacheSize > 0:
      dec cs.cacheSize

  # Phase 2: stream the on-disk UTXO column family. Collect candidate keys
  # first (we can't safely delete during iteration on every backend), then
  # delete them in a single write batch.
  var keysToDelete: seq[seq[byte]] = @[]
  var bytesFreed: uint64 = 0
  for (key, value) in cs.db.db.iterCf(cfUtxo):
    # Defensive: skip malformed entries rather than crash mid-scrub.
    var entry: UtxoEntry
    try:
      entry = deserializeUtxoEntry(value)
    except CatchableError:
      continue
    if isUnspendable(entry.output.scriptPubKey):
      keysToDelete.add(key)
      bytesFreed += uint64(key.len + value.len)

  if keysToDelete.len == 0:
    info "scrubunspendable: no orphan entries found"
    return (0'u64, 0'u64)

  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()
  for k in keysToDelete:
    batch.delete(cfUtxo, k)
  cs.db.db.write(batch)

  result.removed = uint64(keysToDelete.len)
  result.bytesFreed = bytesFreed
  info "scrubunspendable: removed entries",
       removed = result.removed, bytesFreed = result.bytesFreed

# ============================================================================
# gettxoutsetinfo — UTXO set walk + Core-byte-parity statistics
# ============================================================================
#
# Mirrors `bitcoin-core/src/kernel/coinstats.cpp::ComputeUTXOStats`. The
# canonical iteration order is "raw txid bytes ascending, then vout
# ascending"; nimrod's UTXO key is `txid(32) || vout(4 BE)` which sorts
# lexicographically the same way RocksDB walks `cfUtxo`, so a forward
# cursor walk yields Core's exact ordering.
#
# Per-tx grouping: Core's `ApplyHash` rebuilds a `std::map<uint32_t, Coin>`
# keyed on vout for each txid. Since vout-asc cursor order == numeric-asc
# map order for our 4-BE encoding, we can stream every (outpoint, coin)
# pair through a single `HashWriter` (SHA256d) directly without
# rebuffering by txid — the resulting digest is byte-identical to Core's
# `hash_serialized_3`.
#
# Hash type:
#   * `hash_serialized_3` — `HashWriter` (SHA256d) over canonical TxOutSer.
#     This is the historical `gettxoutsetinfo` default.
#   * `hash_serialized_2` — emitted as an alias to `hash_serialized_3` for
#     compatibility with the cross-impl diff-test harness, which checks
#     `_2` first before falling back to `_3` / `hash_serialized`.
#   * `muhash` — `MuHash3072`. Order-independent, computed via the same
#     TxOutSer byte stream (`bitcoin-core/src/kernel/coinstats.cpp:58-63`).
#   * `none` — skip the hash, just return counts/totals.
#
# WARNING: same as Core's coinstats.cpp comment — the byte stream fed
# through these hashes is exactly `serializeCoinForHash` (= TxOutSer).
# Changing that layout invalidates assumeutxo commitments and snapshot
# round-trip tests.

type
  CoinStatsHashType* = enum
    cshtNone
    cshtHashSerialized   ## SHA256d HashWriter (Core's hash_serialized_3)
    cshtMuHash           ## MuHash3072 (gettxoutsetinfo hash_type=muhash)

  UtxoSetInfo* = object
    height*: int32
    bestBlock*: BlockHash
    transactions*: uint64    ## distinct txids with at least one UTXO
    txOuts*: uint64          ## total number of UTXOs
    bogosize*: uint64        ## Core's database-independent size estimate
    totalAmount*: int64      ## sum of all UTXO values (satoshi)
    diskSize*: uint64        ## estimated on-disk size of the chainstate UTXO
                             ## data (sum of raw key+value bytes for every
                             ## cfUtxo entry). Mirrors Core's `disk_size`
                             ## (`view->EstimateSize()`); impl-specific, NOT
                             ## byte-comparable across nodes.
    hashType*: CoinStatsHashType
    hashSerialized*: array[32, byte]  ## populated when hashType != cshtNone

proc bogoSizeFor(scriptPubKeyLen: int): uint64 =
  ## Mirrors `bitcoin-core/src/kernel/coinstats.cpp::GetBogoSize`:
  ##   32 (txid) + 4 (vout) + 4 (height|coinbase) + 8 (amount) +
  ##   2 (scriptPubKey len) + scriptPubKey.size().
  uint64(32 + 4 + 4 + 8 + 2 + scriptPubKeyLen)

iterator iterateUtxos*(cs: var ChainState): tuple[outpoint: OutPoint,
                                                   entry: UtxoEntry] =
  ## Forward cursor walk of the authoritative UTXO set, yielding each
  ## logical (outpoint, coin) pair. Used by `scantxoutset` and any other
  ## consumer that needs to scan the whole set without recomputing stats.
  ##
  ## Same pre-walk flush + unspendable-coin filter + key decode as
  ## `computeUtxoSetInfo` (see that proc for the rationale on each step);
  ## factored out here so the RPC layer doesn't reach into the raw
  ## `cs.db.db` cursor directly.
  if cs.ibdMode:
    cs.flushIBDBatch()
  else:
    cs.flushCache()

  for (key, value) in cs.db.db.iterCf(cfUtxo):
    if key.len != 36:
      continue
    var entry: UtxoEntry
    try:
      entry = deserializeUtxoEntry(value)
    except CatchableError:
      continue

    if isUnspendable(entry.output.scriptPubKey):
      continue

    var txidBytes: array[32, byte]
    copyMem(addr txidBytes[0], unsafeAddr key[0], 32)
    let vout = (uint32(key[32]) shl 24) or
               (uint32(key[33]) shl 16) or
               (uint32(key[34]) shl 8)  or
                uint32(key[35])
    yield (OutPoint(txid: TxId(txidBytes), vout: vout), entry)

proc computeUtxoSetInfo*(cs: var ChainState,
                         hashType: CoinStatsHashType): UtxoSetInfo =
  ## Walk the entire UTXO set and return Core-parity stats.
  ##
  ## Order: forward `cfUtxo` cursor (raw txid bytes asc, then vout asc).
  ## This matches `ComputeUTXOStats` (`coinstats.cpp:111-146`).
  ##
  ## Pre-walk: flush in-memory state to disk so the cursor sees the
  ## authoritative UTXO set. In IBD mode this drains the pending
  ## WriteBatch and the deletion-tracking table; in steady-state it
  ## flushes the read cache (a no-op if all entries are already on disk).
  ## Without this, freshly-connected blocks would either be missed
  ## (entries only in cache) or double-counted (entries pending in
  ## ibdDeletedUtxos that still exist on disk).
  if cs.ibdMode:
    cs.flushIBDBatch()
  else:
    cs.flushCache()

  result.height = cs.bestHeight
  result.bestBlock = cs.bestBlockHash
  result.hashType = hashType

  var hw = initHashWriter()
  var muh = newMuHash3072()

  # NOTE: W12 (efdc4bf) had a walk-time genesis-coinbase filter here as a
  # workaround for nimrod adding the genesis coinbase to cfUtxo via
  # `connectBlock(genesis, 0)`. W14 fixes that at the writer
  # (chainstate.nim:626 — height==0 skips per-tx UTXO mutation, matching
  # `validation.cpp:2337-2343`), so the filter is no longer needed.
  # `createSnapshot` keeps its dump-time filter as belt-and-suspenders
  # for legacy datadirs created before W14.

  # Track distinct-tx count by detecting txid transitions in cursor order.
  var sawAny = false
  var prevTxidBytes: array[32, byte]

  for (key, value) in cs.db.db.iterCf(cfUtxo):
    if key.len != 36:
      # Defensive: skip malformed entries rather than abort the walk.
      continue
    var entry: UtxoEntry
    try:
      entry = deserializeUtxoEntry(value)
    except CatchableError:
      continue

    # Skip provably unspendable entries that may persist on legacy
    # datadirs (pre-94b7755 chainstates carry orphan OP_RETURN coins
    # from segwit witness-commitment outputs). Core's `AddCoins` filters
    # these at write time so its UTXO walk never sees them; we mirror
    # that by filtering at read time too. `scrubUnspendable` is the
    # idempotent operator tool for permanent removal.
    if isUnspendable(entry.output.scriptPubKey):
      continue

    # Reconstruct the outpoint from the 36-byte key (txid(32) || vout(4 BE)).
    var txidBytes: array[32, byte]
    copyMem(addr txidBytes[0], unsafeAddr key[0], 32)

    let vout = (uint32(key[32]) shl 24) or
               (uint32(key[33]) shl 16) or
               (uint32(key[34]) shl 8)  or
                uint32(key[35])
    let outpoint = OutPoint(txid: TxId(txidBytes), vout: vout)

    # Distinct-tx count: increment whenever the leading 32 bytes change.
    if not sawAny or txidBytes != prevTxidBytes:
      inc result.transactions
      prevTxidBytes = txidBytes
      sawAny = true

    inc result.txOuts
    result.bogosize += bogoSizeFor(entry.output.scriptPubKey.len)
    result.totalAmount += int64(entry.output.value)
    # Estimated on-disk chainstate size: the raw key + value bytes for this
    # cfUtxo entry, as they sit in the column family. This is a deterministic
    # proxy for Core's `view->EstimateSize()` (RocksDB has no leveldb-style
    # range estimate bound here). Impl-specific by design — the differential
    # test only asserts disk_size is PRESENT + integer-typed, never byte-equal.
    result.diskSize += uint64(key.len + value.len)

    if hashType != cshtNone:
      let coinBytes = serializeCoinForHash(
        outpoint, int64(entry.output.value), entry.output.scriptPubKey,
        entry.height, entry.isCoinbase)
      case hashType
      of cshtHashSerialized:
        hw.update(coinBytes)
      of cshtMuHash:
        muh.insert(coinBytes)
      of cshtNone: discard

  case hashType
  of cshtHashSerialized:
    if result.txOuts > 0:
      result.hashSerialized = hw.finalizeHash()
    else:
      result.hashSerialized = default(array[32, byte])
  of cshtMuHash:
    result.hashSerialized = muh.finalize()
  of cshtNone: discard

proc connectBlockIBD*(cs: var ChainState, blk: Block, height: int32): ChainStateResult[void] =
  ## Fast-path block connection for IBD
  ## Skips: undo data, tx index, full block storage, per-block RocksDB flush
  ## Accumulates UTXO changes in memory + write batch, flushes every IbdBatchFlushInterval blocks

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # W93 Gate (Core val:2333): same precondition as connectBlock above.  IBD
  # callsites have always relied on the SyncManager to enforce this, but
  # defense-in-depth keeps the chainstate self-consistent if anyone wires
  # a new caller without the parent check.  Genesis (height==0) bypasses.
  if height > 0 and cs.bestBlockHash != blk.header.prevBlock:
    return err("connectBlockIBD precondition violated: cs.bestBlockHash " &
               $cs.bestBlockHash & " != block.prevBlock " &
               $blk.header.prevBlock & " (height " & $height & ")")

  # Process each transaction - UTXO updates only
  for txIdx, tx in blk.txs:
    let txId = tx.txid()

    # Spend inputs (skip coinbase)
    if txIdx > 0:
      for input in tx.inputs:
        let utxoOpt = cs.getUtxo(input.prevOut)
        if utxoOpt.isNone:
          # Also check ibdDeletedUtxos - if already deleted, it's a double-spend
          return err("missing input: " & $input.prevOut.txid)

        let entry = utxoOpt.get()

        # Check coinbase maturity
        if entry.isCoinbase:
          let age = height - entry.height
          if age < int32(cs.params.coinbaseMaturity):
            # Use ancestor-check assumevalid semantics (Bitcoin Core v28.0).
            # Only bypass maturity enforcement when the block is on the
            # assumed-valid chain (ancestor check) — NOT a plain height check.
            let avCtx = buildAssumeValidContext(cs, blockHash, height)
            let skipReason = shouldSkipScripts(avCtx, cs.params)
            if skipReason == ssrSkip:
              warn "immature coinbase below assume-valid (allowing)",
                   height = height, coinbaseHeight = entry.height,
                   age = age, prevTxid = $input.prevOut.txid,
                   prevVout = input.prevOut.vout
            else:
              return err("immature coinbase spend at height " & $height &
                        ", coinbase height " & $entry.height &
                        ", age " & $age & " < " & $cs.params.coinbaseMaturity)

        # Delete from batch and cache
        let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
        cs.ibdBatch.delete(cfUtxo, key)
        cs.deleteUtxoCache(input.prevOut)
        # Track deletion so we don't serve stale data from DB
        cs.ibdDeletedUtxos[outpointKey(input.prevOut)] = true

    # Create outputs - add to cache (will be flushed in batch)
    for voutIdx, output in tx.outputs:
      # Skip provably unspendable outputs — see connectBlock comment above.
      if isUnspendable(output.scriptPubKey):
        continue
      let entry = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: txIdx == 0
      )
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      cs.putUtxoCache(outpoint, entry)
      # Remove from deleted tracking if re-created
      let ck = outpointKey(outpoint)
      if ck in cs.ibdDeletedUtxos:
        cs.ibdDeletedUtxos.del(ck)

  # Calculate and add work
  let blockWork = calculateBlockWork(blk.header.bits)
  addWork(cs.totalWork, blockWork)

  # Store block index entry (lightweight - needed for chain tracking)
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: cs.totalWork,
    undoPos: FlatFilePos(fileNum: -1, pos: -1),
    nTx: int32(blk.txs.len)
  )
  cs.ibdBatch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  cs.ibdBatch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Track the row in the ChainDb unflushed shadow so that the raw readers
  # `getBlockIndex` (by hash) AND `getBlockHashByHeight` (by height) serve
  # this block before the write batch is flushed to RocksDB (every 2000
  # blocks). This is what makes the contextual consensus checks correct
  # mid-IBD: getMtpForHeight walks the previous 11 blocks via these readers
  # (BIP-113 finality cutoff + the time-too-old gate), and the bad-diffbits
  # getAncestor retarget walk uses getBlockIndex. Cleared by flushIBDBatch
  # once the rows are durable. See the `ChainDb.ibdIndexByHash` comment.
  cs.db.ibdIndexByHash[blockHash] = idx
  cs.db.ibdIndexByHeight[height] = blockHash

  # Update in-memory state
  cs.bestBlockHash = blockHash
  cs.bestHeight = height

  cs.ibdBatchBlocks += 1
  cs.ibdBlocksSinceLastDiskFlush += 1

  # Flush batch every N blocks (write batch → memtable, fast)
  if cs.ibdBatchBlocks >= IbdBatchFlushInterval:
    cs.flushIBDBatch()

  # Periodically force memtables to SST (memtable → disk, slower but durable)
  cs.flushToDiskIfNeeded()

  ok()

proc getUtxoIBD*(cs: ChainState, op: OutPoint): Option[UtxoEntry] =
  ## Get UTXO during IBD - checks deletions tracking
  # Check if deleted in current batch
  let ck = outpointKey(op)
  if ck in cs.ibdDeletedUtxos:
    return none(UtxoEntry)

  # Check local cache first
  if op in cs.utxoCache:
    return some(cs.utxoCache[op])

  # Fall back to database
  cs.db.getUtxo(op)

# Disconnect a block from the chain

proc isBip30UnspendableForDisconnect(height: int32, blockHash: BlockHash): bool =
  ## Return true iff this block's coinbase outputs are considered unspendable
  ## for the purpose of DisconnectBlock — i.e. the two original BIP-30
  ## violating mainnet blocks whose duplicate coinbases were overwritten.
  ##
  ## Reference: Bitcoin Core validation.cpp:2201-2202 (DisconnectBlock).
  ##   h=91722  hash=00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e
  ##   h=91812  hash=00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f
  ##
  ## Duplicated here (not imported from validation.nim) to avoid a circular
  ## dependency: chainstate <- validation <- chainstate.
  const bip30Unspend1Hash = block:
    var h: array[32, byte]
    let hex = "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
    for i in 0..31:
      let hi = hex[i*2]; let lo = hex[i*2+1]
      let hiV = (if hi >= '0' and hi <= '9': ord(hi)-ord('0') elif hi >= 'a' and hi <= 'f': ord(hi)-ord('a')+10 else: ord(hi)-ord('A')+10)
      let loV = (if lo >= '0' and lo <= '9': ord(lo)-ord('0') elif lo >= 'a' and lo <= 'f': ord(lo)-ord('a')+10 else: ord(lo)-ord('A')+10)
      h[31 - i] = byte(hiV * 16 + loV)
    h
  const bip30Unspend2Hash = block:
    var h: array[32, byte]
    let hex = "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
    for i in 0..31:
      let hi = hex[i*2]; let lo = hex[i*2+1]
      let hiV = (if hi >= '0' and hi <= '9': ord(hi)-ord('0') elif hi >= 'a' and hi <= 'f': ord(hi)-ord('a')+10 else: ord(hi)-ord('A')+10)
      let loV = (if lo >= '0' and lo <= '9': ord(lo)-ord('0') elif lo >= 'a' and lo <= 'f': ord(lo)-ord('a')+10 else: ord(lo)-ord('A')+10)
      h[31 - i] = byte(hiV * 16 + loV)
    h
  (height == 91722'i32 and array[32, byte](blockHash) == bip30Unspend1Hash) or
  (height == 91812'i32 and array[32, byte](blockHash) == bip30Unspend2Hash)

proc disconnectBlock*(cs: var ChainState, blk: Block, height: int32, undo: UndoData,
                      fClean: ptr bool = nil): ChainStateResult[void] =
  ## Disconnect a block: restore spent outputs, remove created outputs.
  ## Requires undo data to restore spent UTXOs.
  ##
  ## Gates mirroring Bitcoin Core validation.cpp DisconnectBlock:
  ##  Gate 1: Skip IsUnspendable outputs — they were never stored (validation.cpp:2214).
  ##  Gate 2: fEnforceBIP30 — relax output-mismatch for h=91722/91812 coinbases (val:2201-2202).
  ##  Gate 3: Restore inputs in reverse vin order (validation.cpp:2233).
  ##  Gate 4: SetBestBlock unconditionally (validation.cpp:2245).
  ##
  ## `fClean` (optional out-param, default nil → behavior unchanged): when
  ## non-nil, this tracks Bitcoin Core's `DISCONNECT_UNCLEAN` signal
  ## (validation.cpp:2185-2244). Core sets `fClean = false` (non-fatal, the
  ## disconnect still proceeds and the function still returns success/ok) on
  ## two conditions, both of which nimrod previously collapsed silently into
  ## "ok" because the writer is purely key-driven:
  ##   (a) SpendCoin output-side identity mismatch (validation.cpp:2218-2226):
  ##       the coin being removed for a created output is absent, or does not
  ##       match the block's output by the 4-field coin identity
  ##       (value + scriptPubKey + height + isCoinbase). BIP-30-unspendable
  ##       coinbases (h=91722/91812 with the matching hash) are EXEMPT.
  ##   (b) ApplyTxInUndo HaveCoin overwrite (validation.cpp:2153): the spent
  ##       input being restored is already present (unspent) in the view, so
  ##       the restore overwrites a live coin.
  ## This makes the real DisconnectBlock surface the same tri-valued
  ## ok/unclean distinction Core's caller (DisconnectTip) observes, without
  ## altering the default (nil) call path used everywhere in production.

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Gate 2: BIP-30 unspendable exception for the two historical duplicate-coinbase
  # blocks (h=91722, h=91812).  Their coinbase outputs were overwritten by later
  # duplicates, so the SpendCoin check would fail; suppress it here.
  # Reference: validation.cpp:2201-2202, 2209-2221.
  let fEnforceBip30 = not isBip30UnspendableForDisconnect(height, blockHash)

  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()

  # Process transactions in reverse order (validation.cpp:2205)
  for txIdx in countdown(blk.txs.len - 1, 0):
    let tx = blk.txs[txIdx]
    let txId = tx.txid()
    let isCoinbase = (txIdx == 0)
    # is_bip30_exception: coinbase of an unspendable block — mismatch is tolerated.
    let isBip30Exception = isCoinbase and not fEnforceBip30

    # Gate 1: Remove created outputs, skipping IsUnspendable ones.
    # Unspendable outputs (OP_RETURN or >MAX_SCRIPT_SIZE) were never written to
    # the UTXO set on connect, so deleting them here is a harmless no-op on RocksDB,
    # but skipping them is the correct behavior matching Core (validation.cpp:2214).
    for voutIdx in 0 ..< tx.outputs.len:
      if isUnspendable(tx.outputs[voutIdx].scriptPubKey):
        continue  # Gate 1: never stored, never remove
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      # Gate 2: For the BIP-30 unspendable coinbases, the UTXO was overwritten;
      # skip the delete to avoid an inconsistency marker (equivalent to Core's
      # fClean=false path that still proceeds).
      if not isBip30Exception:
        # DISCONNECT_UNCLEAN (a): Core SpendCoin output-identity check
        # (validation.cpp:2218-2226). When fClean tracking is requested, verify
        # the coin we are about to remove is present AND matches the block's
        # output by the 4-field coin identity (value + scriptPubKey + height +
        # isCoinbase). Absent or mismatched => non-fatal unclean. The delete
        # still proceeds (key-driven), matching Core.
        if fClean != nil:
          let present = cs.getUtxo(outpoint)
          if present.isNone:
            fClean[] = false
          else:
            let cur = present.get()
            if cur.output.value != tx.outputs[voutIdx].value or
               cur.output.scriptPubKey != tx.outputs[voutIdx].scriptPubKey or
               cur.height != height or cur.isCoinbase != isCoinbase:
              fClean[] = false
        batch.delete(cfUtxo, key)
        cs.deleteUtxoCache(outpoint)

    # Remove tx index entry
    batch.delete(cfTxIndex, txIndexKey(array[32, byte](txId)))

  # Restore spent outputs from undo data — mirrors `ApplyTxInUndo`
  # (validation.cpp:2149-2175).
  #
  # Gate 3: Core restores inputs in reverse vin order within each tx
  # (validation.cpp:2233: for j = vin.size(); j > 0; --j).  The UndoData
  # flat list is already ordered per-tx forward, so we restore per-outpoint
  # by key — order is irrelevant for KV correctness.
  #
  # Gate 5 (ApplyTxInUndo: HaveCoin overwrite check, val:2153):
  #   If the outpoint we're about to restore is already in the UTXO set
  #   (alive), the restore is an "overwrite" — Core sets fClean=false but
  #   still proceeds (it's a non-fatal inconsistency).  We don't track an
  #   fClean flag, but we MUST still proceed with the put — the in-memory
  #   batch.put will overwrite the existing entry, matching Core's
  #   `view.AddCoin(out, std::move(undo), !fClean)` with possible_overwrite=true.
  #
  # Gate 6 (ApplyTxInUndo: missing-metadata sibling recovery, val:2155-2166):
  #   In legacy undo records, only the LAST spend of a transaction's outputs
  #   carried height/coinbase metadata.  When restoring an earlier-spent
  #   sibling, undo.nHeight == 0 and we recover the metadata from any other
  #   unspent output of the same tx (AccessByTxid).  Newer undo records
  #   always carry per-output metadata so this path is dormant on
  #   chains synced with modern code, but is required for correctness on
  #   legacy datadirs and crash-recovery from old undo files.
  for (outpoint, entry) in undo.spentOutputs:
    var restoreEntry = entry

    # DISCONNECT_UNCLEAN (b): ApplyTxInUndo HaveCoin overwrite check
    # (validation.cpp:2153). If the outpoint we are about to restore is already
    # present (unspent) in the view, the restore overwrites a live coin —
    # Core's `view.AddCoin(out, std::move(undo), !fClean)` with fClean=false.
    # Non-fatal: the put below proceeds and still overwrites.
    if fClean != nil:
      if cs.getUtxo(outpoint).isSome:
        fClean[] = false

    # Gate 6: missing-metadata sibling recovery.
    if restoreEntry.height == 0 and not restoreEntry.isCoinbase:
      # Look up any other output of the same tx that is still unspent and
      # copy its (height, isCoinbase) metadata into this restore entry.
      # Walk vout indices forward as Core does (AccessByTxid in coins.cpp).
      var foundMeta = false
      const MaxOutputsToProbe = 65535  # MAX_OUTPUTS_PER_BLOCK bound
      var probeVout: uint32 = 0
      while probeVout < uint32(MaxOutputsToProbe):
        if probeVout == outpoint.vout:
          inc probeVout
          continue
        let probeOp = OutPoint(txid: outpoint.txid, vout: probeVout)
        let alt = cs.getUtxo(probeOp)
        if alt.isSome:
          restoreEntry.height = alt.get().height
          restoreEntry.isCoinbase = alt.get().isCoinbase
          foundMeta = true
          break
        # If we've passed the rough limit and found nothing, stop.
        # Real coinbases are at vout=0; spends rarely exceed a few hundred outputs.
        if probeVout > 2000'u32 and not foundMeta:
          break
        inc probeVout
      if not foundMeta:
        # No sibling found — Core returns DISCONNECT_FAILED here
        # (validation.cpp:2164).  This indicates corrupted/orphan undo data.
        return err("DisconnectBlock: missing metadata for outpoint " &
                   $outpoint & " and no unspent sibling found in same tx " &
                   "(legacy undo record corruption)")

    let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
    batch.put(cfUtxo, key, serializeUtxoEntry(restoreEntry))
    cs.putUtxoCache(outpoint, restoreEntry)

  # Remove undo data for this block
  batch.delete(cfMeta, undoKey(blockHash))

  # Remove block index height mapping
  batch.delete(cfBlockIndex, blockIndexKey(height))

  # Keep the IBD unflushed shadow consistent: if this block is still in the
  # unflushed window (rare — disconnect during IBD is not a normal path, but
  # defense-in-depth), drop it so the contextual checks never see a block
  # that has been disconnected. The hash row is left as an orphan index
  # entry, mirroring Core which retains the CBlockIndex on disconnect.
  if cs.db.ibdIndexByHeight.getOrDefault(height, BlockHash(default(array[32, byte]))) == blockHash:
    cs.db.ibdIndexByHeight.del(height)
  cs.db.ibdIndexByHash.del(blockHash)

  # Subtract work (reverse the work addition)
  let blockWork = calculateBlockWork(blk.header.bits)
  var newTotalWork = cs.totalWork
  # Subtract: newTotal = total - blockWork
  var borrow: int32 = 0
  for i in 0 ..< 32:
    let diff = int32(newTotalWork[i]) - int32(blockWork[i]) - borrow
    if diff < 0:
      newTotalWork[i] = byte((diff + 256) and 0xff)
      borrow = 1
    else:
      newTotalWork[i] = byte(diff)
      borrow = 0
  cs.totalWork = newTotalWork

  # Gate 4: SetBestBlock unconditionally — Core always calls
  # view.SetBestBlock(pindex->pprev->GetBlockHash()) (validation.cpp:2245).
  # The old guard `if newBestHeight >= 0` was wrong: it skipped the update
  # when disconnecting block 0 (which should not happen in practice but is
  # still incorrect semantics).  We always update.
  let newBestHeight = height - 1
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blk.header.prevBlock)))
  var w = BinaryWriter()
  w.writeInt32LE(newBestHeight)
  batch.put(cfMeta, metaKey("height"), w.data)
  batch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

  cs.bestBlockHash = blk.header.prevBlock
  cs.bestHeight = newBestHeight
  cs.db.bestBlockHash = blk.header.prevBlock
  cs.db.bestHeight = newBestHeight

  cs.db.db.write(batch)

  # Fire the disconnect hook (BIP-157 filter-index rollback).  Runs AFTER
  # the chainstate batch commits so the filter index never observes a
  # state the chainstate has not yet committed.  Hook errors are swallowed
  # by the index implementation (see blockfilterindex.removeBlock) so a
  # failed filter rollback does not corrupt the chainstate disconnect.
  if cs.disconnectHook != nil:
    cs.disconnectHook(blockHash, blk.header.prevBlock, height)

  ok()

proc disconnectBlock*(cs: var ChainState, blk: Block): ChainStateResult[void] =
  ## Disconnect a block by reading undo data from flat files
  ## This is the preferred method for disconnection as it reads from rev*.dat

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Get block index to find undo position
  let idxOpt = cs.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return err("block index not found for " & $blockHash)

  let idx = idxOpt.get()
  let height = idx.height

  # Try to read undo from flat files first
  if not idx.undoPos.isNull:
    let (blockUndo, ok) = cs.undoMgr.readBlockUndo(idx.undoPos, blk.header.prevBlock, cs.params)
    if ok:
      # Gate: blockUndo.txUndo.len + 1 must equal blk.txs.len (one TxUndo per
      # non-coinbase tx).  Mismatch means the undo data is inconsistent with the
      # block body — fail hard rather than silently restoring wrong inputs.
      # Reference: Bitcoin Core validation.cpp:2190-2193.
      #
      # Note: must be UNCONDITIONAL — an early `blk.txs.len > 1` guard would
      # let a coinbase-only block with a non-empty txUndo (corruption) slip
      # through and silently restore phantom UTXOs.  Core's check fires for
      # every block, including 1-tx coinbase-only blocks where vtxundo must be
      # empty.
      if blockUndo.txUndo.len + 1 != blk.txs.len:
        return err("DisconnectBlock: block/undo tx count mismatch: block has " &
                   $blk.txs.len & " txs but undo has " & $blockUndo.txUndo.len &
                   " entries (expected " & $(blk.txs.len - 1) & ")")

      # Convert BlockUndo to UndoData format for the existing disconnection logic.
      # Each TxUndo's prevOutputs are in forward vin order; the per-tx index
      # aligns spent[j] with vin[j] for outpoint reconstruction.
      var undo = UndoData()
      for txIdx in 1 ..< blk.txs.len:  # Skip coinbase
        let tx = blk.txs[txIdx]
        let txUndo = blockUndo.txUndo[txIdx - 1]
        # Gate: per-tx vin count must equal txUndo.prevOutputs count.
        # Reference: validation.cpp:2229-2232.
        if txUndo.prevOutputs.len != tx.inputs.len:
          return err("DisconnectBlock: tx " & $txIdx &
                     " vin count (" & $tx.inputs.len &
                     ") != undo prevout count (" & $txUndo.prevOutputs.len & ")")
        for i, spent in txUndo.prevOutputs:
          let outpoint = tx.inputs[i].prevOut
          let entry = UtxoEntry(
            output: spent.output,
            height: spent.height,
            isCoinbase: spent.isCoinbase
          )
          undo.spentOutputs.add((outpoint, entry))
      return cs.disconnectBlock(blk, height, undo)

  # Fall back to RocksDB undo data
  let undoOpt = cs.db.getUndoData(blockHash)
  if undoOpt.isNone:
    return err("undo data not found for " & $blockHash)

  cs.disconnectBlock(blk, height, undoOpt.get())

# Handle a reorg

const
  ## Maximum reorg depth that nimrod will attempt to apply atomically.
  ## Mirrors Bitcoin Core's MAX_REORG_LENGTH (validation.cpp) — Core
  ## refuses to invalidate beyond this depth via `invalidateblock`. We
  ## use the same limit as a guard rail on `handleReorg`'s single batch:
  ## a 100-deep reorg with full undo data and bodies for both chains
  ## fits comfortably in a RocksDB WriteBatch on commodity hardware,
  ## while ruling out runaway batches that would exhaust memory or
  ## block the writer thread for seconds.
  MAX_REORG_DEPTH* = 100

proc handleReorg*(cs: var ChainState, forkPoint: BlockHash, newChain: seq[Block],
                  disconnectedTxs: var seq[Transaction]): ChainStateResult[void] =
  ## Handle a chain reorganization atomically.
  ##
  ## Pattern D (single-batch disconnect+reconnect): every UTXO mutation,
  ## block-index update, undo deletion, txindex revert, txindex (re)insert,
  ## bestblock/height/totalwork pointer update, and block-body store for
  ## the entire N-block disconnect + M-block connect runs inside ONE
  ## RocksDB WriteBatch. The batch is committed exactly once at the end
  ## via `cs.db.db.write(batch)`.
  ##
  ## Crash semantics: a crash at any point before `db.write` returns
  ## leaves the on-disk chainstate fully on the OLD (pre-reorg) chain —
  ## RocksDB guarantees the WriteBatch either fully applies or not at
  ## all. A crash AFTER `db.write` returns leaves the on-disk chainstate
  ## fully on the NEW chain. There is no partial-reorg disk state.
  ##
  ## In-memory state (bestBlockHash / bestHeight / totalWork / utxoCache)
  ## is mutated tentatively as each block is staged onto the batch. On
  ## any error before commit, the snapshot taken at entry is restored —
  ## no torn state escapes this proc.
  ##
  ## Disconnect depth is capped at MAX_REORG_DEPTH (100) to bound the
  ## batch size and protect the writer thread.
  ##
  ## forkPoint: the last common ancestor block hash
  ## newChain: blocks to connect, in order from forkPoint+1 to new tip
  ##
  ## disconnectedTxs (out): every non-coinbase transaction found in the
  ## disconnected blocks, in the order Core uses for `MaybeUpdateMempoolForReorg`
  ## (oldest-first per block, fork+1 → old tip).  Caller is responsible for
  ## re-feeding these to the mempool via `mempool.blockDisconnected`.
  ## Mirrors camlcoin `lib/sync.ml:2295-2363` (`disconnected_txs` ref) and
  ## bitcoin-core `validation.cpp::DisconnectTip` →
  ## `disconnectpool.addForBlock` → `MaybeUpdateMempoolForReorg`
  ## (Pattern B closure for nimrod, see
  ## CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md).
  ## Pattern D closure: see
  ## CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md.

  disconnectedTxs.setLen(0)

  # Guard against re-entrant or nested reorg attempts. The single shared
  # WriteBatch + reorgDeletedUtxos override only handles one reorg at a time.
  if cs.reorgDeletedUtxos != nil:
    return err("handleReorg called while another reorg is already in progress")

  # First, walk back from current tip to fork point, collecting blocks
  # and undo data we'll need. This pass does NOT mutate any state.
  var currentHash = cs.bestBlockHash
  var currentHeight = cs.bestHeight
  var disconnectedBlocks: seq[(Block, UndoData, int32)] = @[]

  while currentHash != forkPoint and currentHeight >= 0:
    # Cap the disconnect depth so the single batch never grows unbounded.
    if disconnectedBlocks.len >= MAX_REORG_DEPTH:
      return err("reorg depth exceeds MAX_REORG_DEPTH=" & $MAX_REORG_DEPTH &
                 " (refused to apply, current tip " & $cs.bestBlockHash &
                 " forkPoint " & $forkPoint & ")")

    # Get the block to disconnect
    let blkOpt = cs.db.getBlock(currentHash)
    if blkOpt.isNone:
      return err("cannot find block to disconnect: " & $currentHash)

    let blk = blkOpt.get()

    # Get undo data
    let undoOpt = cs.db.getUndoData(currentHash)
    if undoOpt.isNone:
      return err("missing undo data for block: " & $currentHash)

    disconnectedBlocks.add((blk, undoOpt.get(), currentHeight))

    # Move to previous block
    currentHash = blk.header.prevBlock
    dec currentHeight

  if currentHash != forkPoint:
    return err("failed to reach fork point: walked back to height " &
               $currentHeight & " hash " & $currentHash)

  # ---- Snapshot in-memory state for rollback on staging error ----
  let savedBestHash = cs.bestBlockHash
  let savedBestHeight = cs.bestHeight
  let savedTotalWork = cs.totalWork
  # Table assignment in Nim copies the table contents, giving us an
  # independent snapshot we can restore on error.
  let savedCache = cs.utxoCache
  let savedCacheSize = cs.cacheSize

  # ---- Open the single WriteBatch for the entire reorg ----
  let batch = cs.db.db.newWriteBatch()
  defer: batch.destroy()

  # Tentative-delete tracking so getUtxo() doesn't fall through to RocksDB
  # and return UTXOs that the in-flight batch has marked for deletion.
  cs.reorgDeletedUtxos = newTable[string, bool]()

  template rollbackInMemory() =
    cs.bestBlockHash = savedBestHash
    cs.bestHeight = savedBestHeight
    cs.totalWork = savedTotalWork
    cs.utxoCache = savedCache
    cs.cacheSize = savedCacheSize
    cs.db.bestBlockHash = savedBestHash
    cs.db.bestHeight = savedBestHeight
    cs.reorgDeletedUtxos = nil
    disconnectedTxs.setLen(0)

  # ---- Stage all disconnects onto the shared batch ----
  # Capture per-disconnect hash/prevHash/height tuples so the index
  # disconnect hook (BIP-157 filter-index rollback) can fire AFTER the
  # single batch commits.  Order is tip→fork (the natural disconnect
  # order); the hook receives them in the same order so the filter
  # index unwinds prevFilterHeader symmetrically.
  var disconnectedForHook: seq[(BlockHash, BlockHash, int32)] = @[]
  var height = cs.bestHeight
  for (blk, undo, blkHeight) in disconnectedBlocks:
    if blkHeight != height:
      rollbackInMemory()
      return err("internal: disconnect height mismatch (expected " &
                 $height & ", got " & $blkHeight & ")")

    # Collect non-coinbase txs for caller-side mempool refill (Pattern B).
    for txIdx, tx in blk.txs:
      if txIdx > 0:
        disconnectedTxs.add(tx)

    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))
    disconnectedForHook.add((blockHash, blk.header.prevBlock, blkHeight))

    # Process transactions in reverse: remove created outputs, drop tx index.
    # Gate: skip IsUnspendable outputs — they were never added to the UTXO set
    # (validation.cpp:2214) so attempting to delete them is a no-op that also
    # pollutes the reorgDeletedUtxos tracking set.
    for txIdx in countdown(blk.txs.len - 1, 0):
      let tx = blk.txs[txIdx]
      let txId = tx.txid()
      for voutIdx in 0 ..< tx.outputs.len:
        if isUnspendable(tx.outputs[voutIdx].scriptPubKey):
          continue  # never stored, never remove (validation.cpp:2214)
        let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
        batch.delete(cfUtxo, key)
        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        cs.deleteUtxoCache(outpoint)
        # Mark as tentatively deleted so a later in-batch read doesn't
        # surface this UTXO from RocksDB.
        cs.reorgDeletedUtxos[][outpointKey(outpoint)] = true
      batch.delete(cfTxIndex, txIndexKey(array[32, byte](txId)))

    # Restore spent outputs from undo data.
    for (outpoint, entry) in undo.spentOutputs:
      let key = utxoKey(array[32, byte](outpoint.txid), outpoint.vout)
      batch.put(cfUtxo, key, serializeUtxoEntry(entry))
      cs.putUtxoCache(outpoint, entry)
      # If we previously marked this outpoint for tentative delete in an
      # earlier disconnect (unlikely in a clean reorg, but possible if
      # an old-chain block both spent and re-created the same outpoint),
      # the put here supersedes that delete — clear the tentative flag.
      cs.reorgDeletedUtxos[].del(outpointKey(outpoint))

    # Drop legacy RocksDB undo data for this block.
    batch.delete(cfMeta, undoKey(blockHash))

    # Remove block index height mapping (the height slot will be reclaimed
    # by the new chain's connect step).
    batch.delete(cfBlockIndex, blockIndexKey(blkHeight))

    # Subtract this block's work from the running total. Mirrors the
    # arithmetic in the legacy disconnectBlock proc.
    let blockWork = calculateBlockWork(blk.header.bits)
    var newTotalWork = cs.totalWork
    var borrow: int32 = 0
    for i in 0 ..< 32:
      let diff = int32(newTotalWork[i]) - int32(blockWork[i]) - borrow
      if diff < 0:
        newTotalWork[i] = byte((diff + 256) and 0xff)
        borrow = 1
      else:
        newTotalWork[i] = byte(diff)
        borrow = 0
    cs.totalWork = newTotalWork

    # Tentatively roll the tip pointer back one slot.
    cs.bestBlockHash = blk.header.prevBlock
    cs.bestHeight = blkHeight - 1
    cs.db.bestBlockHash = blk.header.prevBlock
    cs.db.bestHeight = blkHeight - 1

    dec height

  if cs.bestBlockHash != forkPoint:
    rollbackInMemory()
    return err("failed to reach fork point after staging disconnects")

  # ---- Stage all connects onto the same batch ----
  var newHeight = cs.bestHeight + 1
  for blk in newChain:
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    # Generate undo data BEFORE mutating UTXO state.
    let undo = cs.generateUndoData(blk)
    let blockUndo = cs.generateBlockUndo(blk)

    # ---- Script verification on the promoted side-branch block ----
    # Bitcoin Core re-runs full per-input script verification on EVERY block
    # connected during a reorg (ConnectTip -> ConnectBlock, validation.cpp),
    # using the UTXO view rebuilt to the fork point plus the already-connected
    # earlier side-branch blocks. nimrod's main-chain path runs the same check
    # via acceptBlock -> verifyScripts; the reorg path previously inlined the
    # UTXO mutation WITHOUT this check, so a higher-work side-branch block with
    # forged signatures could be promoted onto the active chain unverified
    # (chain-split-class false-accept). We close that here by invoking the
    # injected verify hook against the live UTXO view at this exact point:
    #   * all earlier `newChain` blocks have already been staged into
    #     cs.utxoCache + cs.reorgDeletedUtxos (this loop processes them in
    #     order, fork+1 -> tip), and
    #   * THIS block's inputs are not yet spent,
    # which is precisely the view Core's ConnectBlock sees. Intra-block spends
    # within `blk` are resolved by verifyScripts' own intra-block UTXO tracking,
    # so cs.getUtxo (which honours reorgDeletedUtxos / cache / DB) is the
    # correct source.
    #
    # The skip gate is computed HERE (not in the hook) and mirrors the
    # main-chain assume-valid logic — `acceptBlock` skips verifyScripts when
    # shouldSkipScripts == ssrSkip; the per-input coinbase-maturity bypass
    # below uses the identical computation. Keeping the gate in chainstate.nim
    # (where buildAssumeValidContext / shouldSkipScripts are already in scope)
    # means we never OVER-flag a block the main path would have skipped, and
    # the hook stays a pure "verify scripts for this block" callback (so
    # server.nim's wiring needs no assume-valid plumbing).
    #
    # On the first script failure the reorg is aborted: rollbackInMemory()
    # restores the pre-reorg in-memory state, the WriteBatch is never
    # committed (defer destroy), and the original tip is left intact.
    if cs.reorgVerifyHook != nil:
      let avCtxV = buildAssumeValidContext(cs, blockHash, newHeight)
      if shouldSkipScripts(avCtxV, cs.params) != ssrSkip:
        let verifyRes = cs.reorgVerifyHook(blk, newHeight)
        if not verifyRes.ok:
          rollbackInMemory()
          return err("reorg connect rejected block " & $blockHash &
                     " at height " & $newHeight & ": " & verifyRes.err)

    # Write undo to flat file (rev*.dat). This is durable independent of
    # the RocksDB batch, but committing it early is fine: on a mid-reorg
    # crash, the rev*.dat entries become unreferenced (nothing in the
    # block index points to them) and are inert until reclaimed.
    var undoPos = FlatFilePos(fileNum: -1, pos: -1)
    if blk.txs.len > 1:
      let (pos, ok) = cs.undoMgr.writeBlockUndo(blockUndo, blk.header.prevBlock, cs.params)
      if not ok:
        rollbackInMemory()
        return err("failed to write undo data for block " & $blockHash)
      undoPos = pos

    # Store full block data.
    batch.put(cfBlocks, blockKey(array[32, byte](blockHash)), serialize(blk))

    # Process each transaction.
    for txIdx, tx in blk.txs:
      let txId = tx.txid()

      # Spend inputs (skip coinbase).
      if txIdx > 0:
        for input in tx.inputs:
          let utxoOpt = cs.getUtxo(input.prevOut)
          if utxoOpt.isNone:
            rollbackInMemory()
            return err("missing input during connect at height " & $newHeight &
                       ": " & $input.prevOut.txid)

          let entry = utxoOpt.get()

          # Coinbase maturity check (matches connectBlock).
          if entry.isCoinbase:
            let age = newHeight - entry.height
            if age < int32(cs.params.coinbaseMaturity):
              let avCtx = buildAssumeValidContext(cs, blockHash, newHeight)
              let skipReason = shouldSkipScripts(avCtx, cs.params)
              if skipReason == ssrSkip:
                warn "immature coinbase below assume-valid (allowing in reorg)",
                     height = newHeight, coinbaseHeight = entry.height,
                     age = age, prevTxid = $input.prevOut.txid,
                     prevVout = input.prevOut.vout
              else:
                rollbackInMemory()
                return err("immature coinbase spend during reorg at height " &
                           $newHeight & ", coinbase height " & $entry.height &
                           ", age " & $age & " < " & $cs.params.coinbaseMaturity)

          let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
          batch.delete(cfUtxo, key)
          cs.deleteUtxoCache(input.prevOut)
          cs.reorgDeletedUtxos[][outpointKey(input.prevOut)] = true

      # Create outputs.
      for voutIdx, output in tx.outputs:
        if isUnspendable(output.scriptPubKey):
          continue
        let entry = UtxoEntry(
          output: output,
          height: newHeight,
          isCoinbase: txIdx == 0
        )
        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
        batch.put(cfUtxo, key, serializeUtxoEntry(entry))
        cs.putUtxoCache(outpoint, entry)
        # A connect creates a fresh UTXO; clear any earlier tentative-delete.
        cs.reorgDeletedUtxos[].del(outpointKey(outpoint))

      # Index transaction.
      let loc = TxLocation(blockHash: blockHash, txIndex: uint32(txIdx))
      batch.put(cfTxIndex, txIndexKey(array[32, byte](txId)), serializeTxLocation(loc))

    # Add this block's work to the running total.
    let blockWork = calculateBlockWork(blk.header.bits)
    addWork(cs.totalWork, blockWork)

    # Block index entry (with undo position) + height -> hash mapping.
    let idx = BlockIndex(
      hash: blockHash,
      height: newHeight,
      status: bsValidated,
      prevHash: blk.header.prevBlock,
      header: blk.header,
      totalWork: cs.totalWork,
      undoPos: undoPos,
      nTx: int32(blk.txs.len)
    )
    batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
    batch.put(cfBlockIndex, blockIndexKey(newHeight), @(array[32, byte](blockHash)))

    # Legacy RocksDB undo (kept for backward compatibility with disconnectBlock paths).
    batch.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))

    # Tentatively advance the tip pointer.
    cs.bestBlockHash = blockHash
    cs.bestHeight = newHeight
    cs.db.bestBlockHash = blockHash
    cs.db.bestHeight = newHeight

    inc newHeight

  # Final tip pointers and totalwork live in cfMeta — write them ONCE,
  # last, after all per-block writes are staged. On commit, RocksDB
  # applies the whole batch atomically.
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](cs.bestBlockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(cs.bestHeight)
  batch.put(cfMeta, metaKey("height"), w.data)
  batch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

  # ---- Single atomic commit ----
  cs.db.db.write(batch)

  # Clear the tentative-delete override; from here on getUtxo can read
  # straight from RocksDB and see the post-reorg state.
  cs.reorgDeletedUtxos = nil

  # Fire the disconnect hook for every disconnected block, in tip→fork
  # order (same order they were staged onto the batch).  Used by the
  # BIP-157 BlockFilterIndex to roll back its filter-header chain
  # symmetrically with chainstate.  Mirrors Bitcoin Core's per-block
  # BaseIndex::BlockDisconnected fan-out from validation.cpp::DisconnectTip.
  # Runs AFTER the chainstate batch commits — the index never observes
  # a state the chainstate has not yet committed.
  if cs.disconnectHook != nil:
    for (bh, ph, h) in disconnectedForHook:
      cs.disconnectHook(bh, ph, h)

  # Flush cache if it grew above threshold during the reorg.
  if cs.shouldFlush():
    cs.flushCache()

  ok()

proc handleReorg*(cs: var ChainState, forkPoint: BlockHash,
                  newChain: seq[Block]): ChainStateResult[void] =
  ## Backwards-compatible thin wrapper that drops the disconnected-tx list.
  ## New code paths that need mempool refill on reorg should call the
  ## three-arg overload above and feed the result to
  ## `mempool.blockDisconnected`.
  var disconnectedTxs: seq[Transaction] = @[]
  cs.handleReorg(forkPoint, newChain, disconnectedTxs)

# ============================================================================
# Legacy compatibility functions (operate on ChainDb directly)
# ============================================================================

proc applyBlock*(cdb: ChainDb, blk: Block, height: int32) =
  ## Atomically apply a block: spend inputs, create outputs, update index
  ## Legacy function - use ChainState.connectBlock for new code
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # W93 Gate (Core val:2333): precondition that the existing best block hash
  # matches the candidate's parent.  Defensive check — sync.nim's outer loop
  # already enforces this, but applyBlock is exposed for legacy callers and
  # silently corrupting the DB on a wrong-parent block would be much worse
  # than a logged warning.  Skip for genesis (height==0) where bestBlockHash
  # is the all-zero default.
  if height > 0 and cdb.bestBlockHash != blk.header.prevBlock:
    warn "applyBlock precondition violated, skipping",
         expectedPrev = $cdb.bestBlockHash, gotPrev = $blk.header.prevBlock,
         height = height
    return

  # Store full block data
  batch.put(cfBlocks, blockKey(array[32, byte](blockHash)), serialize(blk))

  # Genesis block: skip transaction connection — see `connectBlock` (above)
  # for the full rationale and Bitcoin Core reference
  # (`validation.cpp:2337-2343`). Without this guard, the legacy applyBlock
  # path (still used from network/sync.nim:1162) would write the genesis
  # coinbase into cfUtxo and re-introduce the W12/W14 divergence.
  if height == 0:
    discard
  else:
    # Process each transaction
    for txIdx, tx in blk.txs:
      let txId = tx.txid()

      # Spend inputs (skip coinbase which has no inputs to spend)
      if txIdx > 0:
        for input in tx.inputs:
          let key = utxoKey(array[32, byte](input.prevOut.txid), input.prevOut.vout)
          batch.delete(cfUtxo, key)
          discard  # Cache removed — ChainState layer handles caching

      # Create outputs
      for voutIdx, output in tx.outputs:
        # Skip provably unspendable outputs (OP_RETURN, oversized scripts) —
        # mirrors AddCoins in bitcoin-core/src/coins.cpp.
        if isUnspendable(output.scriptPubKey):
          continue
        let entry = UtxoEntry(
          output: output,
          height: height,
          isCoinbase: txIdx == 0
        )
        let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
        batch.put(cfUtxo, key, serializeUtxoEntry(entry))

        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        discard  # Cache removed — ChainState layer handles caching

      # Index transaction
      let loc = TxLocation(blockHash: blockHash, txIndex: uint32(txIdx))
      batch.put(cfTxIndex, txIndexKey(array[32, byte](txId)), serializeTxLocation(loc))

  # W93: derive totalWork from the parent index instead of writing default(0).
  # Storing zero work on every applyBlock-path block index entry would corrupt
  # any future chain-selection logic that ranks by totalWork.  Falls back to a
  # genesis sentinel (all-zero) only for height==0.
  var totalWork: array[32, byte] = default(array[32, byte])
  if height > 0:
    let prevIdxOpt = cdb.getBlockIndex(blk.header.prevBlock)
    if prevIdxOpt.isSome:
      totalWork = prevIdxOpt.get().totalWork
  let blockWork = calculateBlockWork(blk.header.bits)
  addWork(totalWork, blockWork)

  # Create block index entry
  let idx = BlockIndex(
    hash: blockHash,
    height: height,
    status: bsValidated,
    prevHash: blk.header.prevBlock,
    header: blk.header,
    totalWork: totalWork,
    nTx: int32(blk.txs.len)
  )
  batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))
  batch.put(cfBlockIndex, blockIndexKey(height), @(array[32, byte](blockHash)))

  # Update best block
  batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](blockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(height)
  batch.put(cfMeta, metaKey("height"), w.data)
  # W93: persist totalWork in cfMeta for crash-recovery consistency.
  batch.put(cfMeta, metaKey("totalwork"), @totalWork)

  # Commit atomically
  cdb.db.write(batch)

  # Update in-memory state
  cdb.bestBlockHash = blockHash
  cdb.bestHeight = height

proc disconnectBlock*(cdb: ChainDb, blk: Block, height: int32) =
  ## Atomically disconnect a block: restore spent outputs, remove created outputs
  ## Legacy function - use ChainState.disconnectBlock for new code
  let batch = cdb.db.newWriteBatch()
  defer: batch.destroy()

  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Process transactions in reverse order (validation.cpp:2205)
  for txIdx in countdown(blk.txs.len - 1, 0):
    let tx = blk.txs[txIdx]
    let txId = tx.txid()

    # Remove created outputs.
    # Gate: skip IsUnspendable outputs — they were never stored
    # (validation.cpp:2214 + Core's CCoinsViewCache::AddCoin in coins.cpp:91
    # which short-circuits for IsUnspendable scripts).
    for voutIdx in 0 ..< tx.outputs.len:
      if isUnspendable(tx.outputs[voutIdx].scriptPubKey):
        continue
      let key = utxoKey(array[32, byte](txId), uint32(voutIdx))
      batch.delete(cfUtxo, key)
      let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
      discard  # Cache removed

    # Remove tx index entry
    batch.delete(cfTxIndex, txIndexKey(array[32, byte](txId)))

    # Note: Restoring spent inputs requires having the previous UTXO data
    # which would typically be stored in an undo file. For now we skip this.

  # Remove block index height mapping
  batch.delete(cfBlockIndex, blockIndexKey(height))

  # Keep the IBD unflushed shadow consistent (defense-in-depth — see the
  # ChainState-level disconnectBlock for rationale).
  if cdb.ibdIndexByHeight.getOrDefault(height, BlockHash(default(array[32, byte]))) == blockHash:
    cdb.ibdIndexByHeight.del(height)
  cdb.ibdIndexByHash.del(blockHash)

  # Update best block to previous
  let newBestHeight = height - 1
  if newBestHeight >= 0:
    let prevHashOpt = cdb.getBlockHashByHeight(newBestHeight)
    if prevHashOpt.isSome:
      batch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](prevHashOpt.get())))
      var w = BinaryWriter()
      w.writeInt32LE(newBestHeight)
      batch.put(cfMeta, metaKey("height"), w.data)

      cdb.bestBlockHash = prevHashOpt.get()
      cdb.bestHeight = newBestHeight

  cdb.db.write(batch)
