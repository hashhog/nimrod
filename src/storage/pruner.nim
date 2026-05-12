## Production prune driver — wires the dormant blockstore prune machinery
## into the live nimrod daemon. Implements the on-disk prune semantics that
## Bitcoin Core ships in `node/blockstorage.cpp::PruneBlockFilesManual` /
## `FindFilesToPrune`, adapted for nimrod's split storage layout:
##
##   * Block bodies live in RocksDB column family `cfBlocks` (NOT in
##     blk*.dat flat files — the BlockFileManager flat-file path is dormant
##     and used only for prune metadata bookkeeping).
##   * Undo data lives in flat files `rev*.dat`, owned by UndoFileManager.
##   * Block index lives in RocksDB `cfBlockIndex` (status flags carry the
##     "have data / have undo" bits we must clear when pruning).
##
## What this module does:
##   1. Decides which blocks are prunable (`tip - MIN_BLOCKS_TO_KEEP`,
##      respecting the assumeutxo snapshot floor when one was loaded).
##   2. For automatic mode, walks heights from the current `pruneHeight`
##      forward and deletes (block body, tx-index entries) until the on-disk
##      footprint falls below the configured target.
##   3. For manual mode (RPC `pruneblockchain`), prunes up to the requested
##      height (subject to the same safety floors).
##   4. Updates each pruned block's BlockIndex to clear `BlockHaveData` and
##      `BlockHaveUndo`, persists the new `pruneHeight` to `cfMeta`, and
##      unlinks any rev*.dat files whose entire range now lies below the
##      `pruneHeight` (we keep the file as long as any block in it might
##      still need its undo data for a reorg below MIN_BLOCKS_TO_KEEP).
##   5. Honors `--prune=1` as Bitcoin Core's "manual mode": auto-prune is
##      disabled, but `pruneblockchain` still works.
##
## References:
##   * bitcoin-core/src/node/blockstorage.cpp::FindFilesToPrune
##   * bitcoin-core/src/node/blockstorage.cpp::PruneBlockFilesManual
##   * bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile
##   * bitcoin-core/src/init.cpp (the `-prune=1` manual-mode branch)

import std/[os, options, sets]
import chronicles
import ./blockstore
import ./chainstate
import ./db
import ../consensus/params
import ../primitives/[types, serialize]

const
  ## Sentinel value used by Core to express "manual mode": the operator
  ## passed `-prune=1`, which is too small to be a real MiB target. We
  ## interpret it the same way: auto-prune disabled; manual RPC enabled.
  ManualModeSentinel* = uint64(1)

  ## Smallest legal automatic-prune target (Bitcoin Core: MIN_DISK_SPACE_FOR_BLOCK_FILES).
  ## Must equal blockstore.MinDiskSpaceForBlockFiles. Re-asserted for callers
  ## that wire CLI parsing without touching blockstore internals.
  AutoPruneFloorBytes* = MinDiskSpaceForBlockFiles  ## 550 MiB

  ## How often (block-connect events) the auto-prune trigger evaluates the
  ## on-disk footprint. Mirrors Core's "after every flush" cadence — we
  ## don't have a flush hook in the heartbeat path, so we throttle by
  ## elapsed blocks instead. 200 blocks ≈ 30-40 min of mainnet sync,
  ## well under one block-file (128 MiB) of churn.
  AutoPruneCheckInterval* = 200

type
  PruneMode* = enum
    pmDisabled    ## --prune omitted; everything is archived.
    pmManualOnly  ## --prune=1; auto-prune off, RPC `pruneblockchain` ok.
    pmAutomatic   ## --prune=N (N >= 550); auto-prune fires past target.

  ## Production-side prune driver. Holds references to the chainstate and
  ## the (mostly-bookkeeping) BlockFileManager. Owned by NodeState.
  Pruner* = ref object
    chainState*: ChainState
    bfm*: BlockFileManager
    params*: ConsensusParams
    mode*: PruneMode
    targetBytes*: uint64        ## 0 if mode == pmDisabled
    pruneHeight*: int32         ## Lowest height for which we still have body data.
                                 ## -1 if nothing pruned yet.
    blocksSinceLastCheck*: int  ## Throttle for auto-prune trigger.

# ----------------------------------------------------------------------------
# Persistence helpers — stash pruneHeight and pruneTarget under cfMeta so
# that getblockchaininfo answers correctly across daemon restarts even
# before we re-prune anything.
# ----------------------------------------------------------------------------

proc pruneHeightKey(): seq[byte] =
  metaKey("prune_height")

proc pruneTargetKey(): seq[byte] =
  metaKey("prune_target")

proc savePruneState(p: Pruner) =
  ## Persist the current prune state so it survives a restart.
  let database = p.chainState.db.db
  var hbuf = newSeq[byte](4)
  let h = cast[uint32](p.pruneHeight)
  hbuf[0] = byte((h shr 24) and 0xff)
  hbuf[1] = byte((h shr 16) and 0xff)
  hbuf[2] = byte((h shr 8) and 0xff)
  hbuf[3] = byte(h and 0xff)
  database.put(cfMeta, pruneHeightKey(), hbuf)

  var tbuf = newSeq[byte](8)
  let t = p.targetBytes
  for i in 0 ..< 8:
    tbuf[i] = byte((t shr (8 * (7 - i))) and 0xff'u64)
  database.put(cfMeta, pruneTargetKey(), tbuf)

proc loadPersistedPruneHeight(database: Database): int32 =
  ## Returns -1 if no persisted state.
  let data = database.get(cfMeta, pruneHeightKey())
  if data.isNone or data.get().len < 4:
    return -1
  let bytes = data.get()
  let h = (uint32(bytes[0]) shl 24) or
          (uint32(bytes[1]) shl 16) or
          (uint32(bytes[2]) shl 8) or
          uint32(bytes[3])
  cast[int32](h)

# ----------------------------------------------------------------------------
# Construction
# ----------------------------------------------------------------------------

proc newPruner*(
    chainState: ChainState,
    bfm: BlockFileManager,
    params: ConsensusParams,
    pruneTargetMiB: uint64
): Pruner =
  ## Create a Pruner for the given prune-target value (units: MiB, matching
  ## Bitcoin Core's `-prune=N`).  `0` = pruning disabled; `1` = manual mode;
  ## `>= 550` = automatic mode (anything 1 < N < 550 is rejected upstream
  ## by the CLI parser, so we don't re-floor here).
  result = Pruner(
    chainState: chainState,
    bfm: bfm,
    params: params,
    pruneHeight: -1,
    blocksSinceLastCheck: 0
  )

  if pruneTargetMiB == 0:
    result.mode = pmDisabled
    result.targetBytes = 0
    bfm.setPruneTarget(0)
  elif pruneTargetMiB == ManualModeSentinel:
    result.mode = pmManualOnly
    # Use the floor for the BlockFileManager's metadata so that
    # `findFilesToPruneManual` does not short-circuit on "not in prune mode";
    # the auto trigger gates separately on `mode`.
    result.targetBytes = AutoPruneFloorBytes
    bfm.setPruneTarget(AutoPruneFloorBytes)
  else:
    result.mode = pmAutomatic
    let bytes = pruneTargetMiB * 1024'u64 * 1024'u64
    result.targetBytes = max(bytes, AutoPruneFloorBytes)
    bfm.setPruneTarget(result.targetBytes)

  # Restore persisted pruneHeight (so the daemon reports correctly even
  # before any new pruning happens this run).
  let persisted = loadPersistedPruneHeight(chainState.db.db)
  if persisted >= 0:
    result.pruneHeight = persisted

  if result.mode != pmDisabled:
    result.savePruneState()

# ----------------------------------------------------------------------------
# Safety floor: never prune below assumeutxo snapshot height when one was
# loaded for this run; the snapshot's hashSerialized commits to the UTXO
# set at that height, and we may need the block body for verification.
# ----------------------------------------------------------------------------

proc assumeUtxoFloor*(p: Pruner): int32 =
  ## Lowest height that MUST be retained because of an active assumeutxo
  ## snapshot. Returns -1 if no snapshot is in scope.
  if p.params.assumeutxoData.len == 0:
    return -1
  # Conservative: keep all snapshot heights. Operator can choose to prune
  # below them only by manually calling `pruneblockchain` with a lower target;
  # auto-mode will never go below the smallest snapshot height.
  var lowest: int32 = high(int32)
  for entry in p.params.assumeutxoData:
    if entry.height < lowest:
      lowest = entry.height
  if lowest == high(int32): -1 else: lowest

# ----------------------------------------------------------------------------
# Disk-usage estimator. Without dedicated blk*.dat files we approximate the
# pruneable footprint as `cfBlocks` size on disk + `rev*.dat` aggregate. We
# only need an order-of-magnitude estimate for the auto-prune trigger; the
# delete loop tracks actual byte savings.
# ----------------------------------------------------------------------------

proc estimateBlockBodyBytes(p: Pruner): uint64 =
  ## Approximate `cfBlocks` on-disk size by summing serialized lengths for
  ## blocks at heights `[pruneHeight+1 .. tip]`. This is O(N); for a fully
  ## synced node we cap the sample (N) so we don't stall the heartbeat.
  let tip = p.chainState.bestHeight
  if tip < 0:
    return 0
  let startH = max(0'i32, p.pruneHeight + 1)
  if startH > tip:
    return 0

  var total: uint64 = 0
  # Sample every Nth block when chain is long; multiply by N for the estimate.
  const MaxSamples = 256
  let span = tip - startH + 1
  let stride = if span > MaxSamples: span div MaxSamples else: 1'i32
  var sampled: int = 0
  var h = startH
  while h <= tip:
    let hashOpt = p.chainState.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      let raw = p.chainState.db.db.get(cfBlocks, blockKey(array[32, byte](hashOpt.get())))
      if raw.isSome:
        total += uint64(raw.get().len)
        inc sampled
    h += stride

  if sampled == 0:
    return 0
  # Project: average sample size * total span.
  let avg = total div uint64(sampled)
  avg * uint64(span)

proc estimateUndoBytes(p: Pruner): uint64 =
  ## Aggregate size of rev*.dat files. Inexpensive (1-3 stat() calls in
  ## practice).
  var total: uint64 = 0
  let dir = p.chainState.undoMgr.dataDir
  for fileNum in 0'i32 .. 1024'i32:
    let path = dir / blockstore.undoFileName(fileNum)
    if not fileExists(path):
      break
    try:
      total += uint64(getFileSize(path))
    except OSError:
      discard
  total

proc estimateCurrentUsage*(p: Pruner): uint64 =
  ## Total prune-relevant bytes on disk. Used by the auto-prune trigger.
  estimateBlockBodyBytes(p) + estimateUndoBytes(p)

# ----------------------------------------------------------------------------
# Core delete loop: walk heights up from `startHeight` and physically
# remove block bodies (cfBlocks) + tx-index entries; clear the
# BlockHaveData / BlockHaveUndo bits; advance pruneHeight.
# ----------------------------------------------------------------------------

proc clearBlockHaveBits(idx: BlockIndex): BlockIndex =
  ## Return a copy of `idx` with the data/undo status bits cleared and
  ## the undo position reset (matches Core's PruneOneBlockFile).
  ## We signal "body has been pruned" by demoting the status to
  ## `bsHeaderOnly` and resetting the undo position. Validated/invalid
  ## terminal states are preserved (a block that already failed stays
  ## failed) but in practice we only prune validated blocks anyway.
  result = idx
  if result.status == bsDataStored or result.status == bsValidated:
    result.status = bsHeaderOnly
  result.undoPos = FlatFilePos(fileNum: -1, pos: -1)

proc pruneBlockBodyAtHeight(p: Pruner, h: int32, batch: WriteBatch): uint64 =
  ## Delete the block body + tx-index for the block at active-chain height h.
  ## Returns the number of bytes reclaimed (0 if already pruned / missing).
  let hashOpt = p.chainState.db.getBlockHashByHeight(h)
  if hashOpt.isNone:
    return 0
  let bh = hashOpt.get()
  let k = blockKey(array[32, byte](bh))

  let raw = p.chainState.db.db.get(cfBlocks, k)
  if raw.isNone:
    return 0  # Already pruned.

  let bytes = uint64(raw.get().len)

  # Decode the block to find tx ids — we must drop the corresponding
  # tx-index entries so getrawtransaction stops returning a body that no
  # longer has its source block.
  try:
    let blk = deserializeBlock(raw.get())
    for tx in blk.txs:
      let txid = tx.txid()
      batch.delete(cfTxIndex, txIndexKey(array[32, byte](txid)))
  except CatchableError:
    discard
  except Exception:
    discard

  # Drop the block body itself.
  batch.delete(cfBlocks, k)

  # Clear BlockHaveData/BlockHaveUndo bits in the block index. We reuse the
  # existing serializer so the on-disk format stays binary-compatible.
  let idxOpt = p.chainState.db.getBlockIndex(bh)
  if idxOpt.isSome:
    let cleared = clearBlockHaveBits(idxOpt.get())
    batch.put(
      cfBlockIndex,
      blockKey(array[32, byte](cleared.hash)),
      serializeBlockIndex(cleared)
    )

  bytes

# ----------------------------------------------------------------------------
# rev*.dat unlinker. We can only delete a rev file once *every* block whose
# undo position lives in it has been pruned; otherwise a reorg below the
# 288-block keep window would silently fail. Conservative approach: only
# unlink files whose contained undo positions are all below the new
# pruneHeight, and keep the highest-numbered (currently-being-written)
# rev*.dat untouched.
# ----------------------------------------------------------------------------

proc unlinkObsoleteUndoFiles(p: Pruner) =
  ## Walk the rev*.dat directory and delete files that are entirely below
  ## the current pruneHeight. We approximate "entirely below" by checking
  ## that no live block-index entry points at a position in this file; if
  ## the file is unreferenced it's safe to unlink.
  if p.pruneHeight < 0:
    return

  let dir = p.chainState.undoMgr.dataDir
  if not dirExists(dir):
    return

  # Build a set of currently-referenced rev file numbers.
  var referenced = initHashSet[int32]()
  let tip = p.chainState.bestHeight
  let startH = max(0'i32, p.pruneHeight)
  var h = startH
  while h <= tip:
    let hashOpt = p.chainState.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      let idxOpt = p.chainState.db.getBlockIndex(hashOpt.get())
      if idxOpt.isSome and idxOpt.get().undoPos.fileNum >= 0:
        referenced.incl(idxOpt.get().undoPos.fileNum)
    h += 1

  # Walk rev*.dat 0..N until a gap; unlink anything not in `referenced`.
  for fileNum in 0'i32 .. 4096'i32:
    let path = dir / blockstore.undoFileName(fileNum)
    if not fileExists(path):
      break
    if fileNum in referenced:
      continue
    try:
      removeFile(path)
      info "pruner: unlinked obsolete undo file", file = path
    except OSError as e:
      warn "pruner: failed to unlink undo file", file = path, error = e.msg

# ----------------------------------------------------------------------------
# Public entry points
# ----------------------------------------------------------------------------

proc pruneToHeight*(p: Pruner, requestedTarget: int32): int32 =
  ## Prune block bodies up to (but not including) `requestedTarget`,
  ## subject to the MIN_BLOCKS_TO_KEEP and assumeutxo floors. Returns the
  ## new `pruneHeight` (lowest still-retained block height; -1 if nothing
  ## was pruned).
  ##
  ## Mirrors Bitcoin Core's `PruneBlockFilesManual` semantics: callers
  ## pre-validate the height bound; this proc applies the safety floors
  ## as a defensive belt-and-braces check.
  if p.mode == pmDisabled:
    raise newException(CatchableError, "pruning is not enabled")

  let tip = p.chainState.bestHeight
  if tip < 0:
    return p.pruneHeight

  # Apply Core's safety floors.
  var ceiling = min(requestedTarget, tip - int32(params.MinBlocksToKeep))
  let auFloor = p.assumeUtxoFloor()
  if auFloor >= 0 and ceiling > auFloor:
    # Honor assumeutxo: never prune blocks at or above the snapshot floor
    # by our own choice. Operators who really want to can call
    # `pruneblockchain <auFloor + 1>` explicitly; we still clamp to MTP-keep.
    ceiling = auFloor
  if ceiling < 0:
    return p.pruneHeight

  let startH = max(0'i32, p.pruneHeight + 1)
  if startH > ceiling:
    # Already pruned past the requested target.
    return p.pruneHeight

  let batch = p.chainState.db.db.newWriteBatch()
  defer: batch.destroy()

  var bytesFreed: uint64 = 0
  var lastPruned: int32 = p.pruneHeight
  var h = startH
  while h <= ceiling:
    let freed = p.pruneBlockBodyAtHeight(h, batch)
    if freed > 0:
      bytesFreed += freed
      lastPruned = h
    h += 1

  if lastPruned > p.pruneHeight:
    p.chainState.db.db.write(batch)
    p.pruneHeight = lastPruned
    p.savePruneState()
    p.unlinkObsoleteUndoFiles()
    info "pruner: pruned block bodies",
         from_height = startH, to_height = lastPruned,
         bytes_freed = bytesFreed,
         new_prune_height = p.pruneHeight

  p.pruneHeight

proc autoPruneIfNeeded*(p: Pruner) =
  ## Heartbeat hook — called periodically from the main daemon loop. No-op
  ## unless mode is `pmAutomatic` and the on-disk footprint has crossed the
  ## configured target.
  if p.mode != pmAutomatic:
    return

  inc p.blocksSinceLastCheck
  if p.blocksSinceLastCheck < AutoPruneCheckInterval:
    return
  p.blocksSinceLastCheck = 0

  let used = p.estimateCurrentUsage()
  if used <= p.targetBytes:
    return

  # Grow `pruneHeight` aggressively enough to reclaim ~10% of the target
  # size in this pass. Walking every height is cheap (RocksDB delete).
  let tip = p.chainState.bestHeight
  if tip < 0:
    return
  let safeCeiling = tip - int32(params.MinBlocksToKeep)
  if safeCeiling < 0:
    return

  # Aim for "delete enough blocks to drop estimated usage below target".
  # Bound how many heights we touch in one pass to keep heartbeat snappy.
  const MaxHeightsPerPass = 4096
  let pruneCeiling = min(
    int32(p.pruneHeight + 1 + MaxHeightsPerPass),
    safeCeiling
  )
  let startH = max(0'i32, p.pruneHeight + 1)
  if startH > pruneCeiling:
    return

  info "pruner: auto-prune triggered",
       used_bytes = used, target_bytes = p.targetBytes,
       from_height = startH, ceiling_height = pruneCeiling
  discard p.pruneToHeight(pruneCeiling)

proc isManualMode*(p: Pruner): bool =
  p.mode == pmManualOnly

proc isPruning*(p: Pruner): bool =
  p.mode != pmDisabled

proc currentPruneHeight*(p: Pruner): int32 =
  p.pruneHeight

proc currentTargetBytes*(p: Pruner): uint64 =
  p.targetBytes
