## Multi-layer UTXO cache with dirty/fresh tracking
## Implements Bitcoin Core's CCoinsView hierarchy pattern:
##   CoinsViewDB -> CoinsViewCache -> CoinsViewCache (stacked)
##
## Key optimizations:
## - FRESH flag: coins created and spent before flush never touch disk
## - Dirty tracking: only modified entries written during flush
## - Memory-aware: auto-flush when cache exceeds dbcache limit (default 450 MiB)
##
## Reference: /home/max/hashhog/bitcoin/src/coins.cpp, coins.h

import std/[options, tables, hashes]
import ./db
import ../primitives/[types, serialize]

export types.OutPoint, types.TxOut, types.Satoshi, types.TxId

const
  DefaultDbCacheSize* = 450 * 1024 * 1024  # 450 MiB
  CoinDbPrefix* = byte('C')  # RocksDB key prefix for coins

type
  ## A UTXO entry stored in the cache/database
  Coin* = object
    txOut*: TxOut           ## The unspent transaction output
    height*: int32          ## Block height where this output was created
    isCoinbase*: bool       ## Whether this is from a coinbase transaction

  ## Cache entry with dirty/fresh flags for flush optimization
  ## Valid states (per Bitcoin Core):
  ## - unspent, FRESH, DIRTY: new coin created in cache
  ## - unspent, not FRESH, DIRTY: coin modified (e.g. during reorg)
  ## - unspent, not FRESH, not DIRTY: clean coin fetched from backing store
  ## - spent, not FRESH, DIRTY: spent coin, spentness needs flushing
  CoinEntry* = object
    coin*: Coin
    dirty*: bool            ## Modified since last flush
    fresh*: bool            ## Not in backing store (created in this cache)

  ## Statistics for cache performance monitoring
  CacheStats* = object
    hits*: int64            ## Cache hits
    misses*: int64          ## Cache misses (fell through to backing store)
    dirtyCount*: int        ## Number of dirty entries
    flushCount*: int        ## Number of flushes performed

  ## Abstract base for UTXO views
  ## Uses Nim's method dispatch for polymorphism
  CoinsView* = ref object of RootObj
    stats*: CacheStats

  ## Database-backed view (reads/writes to RocksDB)
  CoinsViewDB* = ref object of CoinsView
    db*: Database
    bestBlockHash*: array[32, byte]

  ## In-memory cache layer with dirty/fresh tracking
  CoinsViewCache* = ref object of CoinsView
    base*: CoinsView                      ## Backing view (DB or another cache)
    cache*: Table[OutPoint, CoinEntry]    ## In-memory cache
    cachedMemoryUsage*: int               ## Estimated memory usage in bytes
    maxCacheSize*: int                    ## Flush threshold in bytes
    bestBlockHash*: array[32, byte]       ## Current best block

# =============================================================================
# Coin serialization
# =============================================================================

proc serializeCoin*(coin: Coin): seq[byte] =
  ## Serialize coin for RocksDB storage
  ## Format: VARINT((coinbase ? 1 : 0) | (height << 1)) || TxOut
  var w = BinaryWriter()
  let code = uint32(coin.height) * 2 + (if coin.isCoinbase: 1 else: 0)
  w.writeCompactSize(uint64(code))
  w.writeTxOut(coin.txOut)
  w.data

proc deserializeCoin*(data: seq[byte]): Coin =
  ## Deserialize coin from RocksDB storage
  var r = BinaryReader(data: data, pos: 0)
  let code = r.readCompactSize()
  result.height = cast[int32](code shr 1)
  result.isCoinbase = (code and 1) != 0
  result.txOut = r.readTxOut()

proc isSpent*(coin: Coin): bool =
  ## A coin is spent if its scriptPubKey is empty and value is 0
  coin.txOut.scriptPubKey.len == 0 and int64(coin.txOut.value) == 0

proc clear*(coin: var Coin) =
  ## Mark coin as spent by clearing its output
  coin.txOut.scriptPubKey = @[]
  coin.txOut.value = Satoshi(0)

proc dynamicMemoryUsage*(coin: Coin): int =
  ## Estimate dynamic memory usage of a coin
  coin.txOut.scriptPubKey.len

# =============================================================================
# OutPoint key encoding
# =============================================================================

proc hash*(op: OutPoint): Hash =
  ## Hash function for OutPoint (for Table use)
  var h: Hash = 0
  let txidBytes = array[32, byte](op.txid)
  for b in txidBytes:
    h = h !& Hash(b)
  h = h !& Hash(op.vout)
  !$h

proc coinDbKey*(outpoint: OutPoint): seq[byte] =
  ## RocksDB key: 'C' || txid (32 bytes) || vout (varint)
  var w = BinaryWriter()
  w.writeUint8(CoinDbPrefix)
  w.writeBytes(array[32, byte](outpoint.txid))
  w.writeCompactSize(uint64(outpoint.vout))
  w.data

# =============================================================================
# CoinsView base methods (virtual)
# =============================================================================

method getCoin*(view: CoinsView, outpoint: OutPoint): Option[Coin] {.base.} =
  ## Retrieve a coin, potentially caching the result
  none(Coin)

method haveCoin*(view: CoinsView, outpoint: OutPoint): bool {.base.} =
  ## Check if coin exists
  view.getCoin(outpoint).isSome

method getBestBlock*(view: CoinsView): array[32, byte] {.base.} =
  ## Get the best block hash for this view
  default(array[32, byte])

method flush*(view: CoinsView): bool {.base.} =
  ## Flush changes to backing store
  true

method estimateSize*(view: CoinsView): int {.base.} =
  ## Estimate storage size in bytes
  0

# =============================================================================
# CoinsViewDB implementation
# =============================================================================

proc newCoinsViewDB*(db: Database): CoinsViewDB =
  ## Create a database-backed coins view
  result = CoinsViewDB(
    db: db,
    bestBlockHash: default(array[32, byte]),
    stats: CacheStats()
  )

  # Load best block from metadata
  let data = db.get(cfUtxo, @[byte('B')])  # 'B' for best block
  if data.isSome and data.get().len >= 32:
    copyMem(addr result.bestBlockHash[0], addr data.get()[0], 32)

method getCoin*(view: CoinsViewDB, outpoint: OutPoint): Option[Coin] =
  ## Read coin from RocksDB
  let key = coinDbKey(outpoint)
  let data = view.db.get(cfUtxo, key)

  if data.isSome:
    inc view.stats.hits
    let coin = deserializeCoin(data.get())
    if not coin.isSpent:
      return some(coin)
  else:
    inc view.stats.misses

  none(Coin)

method haveCoin*(view: CoinsViewDB, outpoint: OutPoint): bool =
  ## Check if coin exists in DB
  let key = coinDbKey(outpoint)
  view.db.contains(cfUtxo, key)

method getBestBlock*(view: CoinsViewDB): array[32, byte] =
  view.bestBlockHash

proc setBestBlock*(view: CoinsViewDB, hash: array[32, byte]) =
  ## Update best block in database
  view.bestBlockHash = hash
  view.db.put(cfUtxo, @[byte('B')], @hash)

proc putCoin*(view: CoinsViewDB, outpoint: OutPoint, coin: Coin) =
  ## Write coin to database
  let key = coinDbKey(outpoint)
  if coin.isSpent:
    view.db.delete(cfUtxo, key)
  else:
    view.db.put(cfUtxo, key, serializeCoin(coin))

proc deleteCoin*(view: CoinsViewDB, outpoint: OutPoint) =
  ## Delete coin from database
  let key = coinDbKey(outpoint)
  view.db.delete(cfUtxo, key)

method estimateSize*(view: CoinsViewDB): int =
  ## Estimate database size (placeholder - would need RocksDB stats)
  0

# =============================================================================
# CoinsViewCache implementation
# =============================================================================

proc newCoinsViewCache*(base: CoinsView, maxCacheSize: int = DefaultDbCacheSize): CoinsViewCache =
  ## Create a cache layer on top of another view
  result = CoinsViewCache(
    base: base,
    cache: initTable[OutPoint, CoinEntry](),
    cachedMemoryUsage: 0,
    maxCacheSize: maxCacheSize,
    bestBlockHash: default(array[32, byte]),
    stats: CacheStats()
  )

proc dynamicMemoryUsage*(view: CoinsViewCache): int =
  ## Total estimated memory usage
  # Base overhead per entry (OutPoint + flags + pointers)
  const entryOverhead = 36 + 8 + 16  # ~60 bytes
  view.cache.len * entryOverhead + view.cachedMemoryUsage

proc cacheSize*(view: CoinsViewCache): int =
  ## Number of entries in cache
  view.cache.len

proc dirtyCount*(view: CoinsViewCache): int =
  ## Count of dirty entries
  view.stats.dirtyCount

proc shouldFlush*(view: CoinsViewCache): bool =
  ## Check if cache should be flushed
  view.dynamicMemoryUsage() >= view.maxCacheSize

method getCoin*(view: CoinsViewCache, outpoint: OutPoint): Option[Coin] =
  ## Get coin, checking cache first then falling through to base
  if outpoint in view.cache:
    let entry = view.cache[outpoint]
    if not entry.coin.isSpent:
      inc view.stats.hits
      return some(entry.coin)
    else:
      # Spent in cache
      return none(Coin)

  # Cache miss - fetch from base
  inc view.stats.misses
  let baseCoin = view.base.getCoin(outpoint)

  if baseCoin.isSome:
    # Cache the result (not dirty, not fresh - it's from backing store)
    view.cache[outpoint] = CoinEntry(
      coin: baseCoin.get(),
      dirty: false,
      fresh: false
    )
    view.cachedMemoryUsage += baseCoin.get().dynamicMemoryUsage()
    return baseCoin

  none(Coin)

proc haveCoinInCache*(view: CoinsViewCache, outpoint: OutPoint): bool =
  ## Check if coin is in cache (without accessing backing store)
  if outpoint in view.cache:
    return not view.cache[outpoint].coin.isSpent
  false

method haveCoin*(view: CoinsViewCache, outpoint: OutPoint): bool =
  ## Check if coin exists (cache first, then base)
  if outpoint in view.cache:
    return not view.cache[outpoint].coin.isSpent
  view.base.haveCoin(outpoint)

method getBestBlock*(view: CoinsViewCache): array[32, byte] =
  ## Get best block (from cache or base)
  if view.bestBlockHash != default(array[32, byte]):
    return view.bestBlockHash
  view.base.getBestBlock()

proc setBestBlock*(view: CoinsViewCache, hash: array[32, byte]) =
  ## Set best block in cache (flushed later)
  view.bestBlockHash = hash

proc addCoin*(view: CoinsViewCache, outpoint: OutPoint, coin: Coin, possibleOverwrite: bool = false) =
  ## Add a coin to the cache
  ## possibleOverwrite should be true if an unspent version may exist (e.g. duplicate txids pre-BIP34)
  assert not coin.isSpent, "Cannot add a spent coin"

  var fresh = false

  if outpoint in view.cache:
    let existing = view.cache[outpoint]

    if not possibleOverwrite and not existing.coin.isSpent:
      raise newException(ValueError, "Attempted to overwrite unspent coin")

    # If re-adding a spent coin that was dirty, we can't mark it fresh
    # (its spentness may not have been flushed to parent)
    fresh = not existing.dirty

    # Update memory tracking
    view.cachedMemoryUsage -= existing.coin.dynamicMemoryUsage()
    if existing.dirty:
      dec view.stats.dirtyCount
  else:
    # New entry - it's fresh (not in backing store)
    fresh = true

  view.cache[outpoint] = CoinEntry(
    coin: coin,
    dirty: true,
    fresh: fresh
  )
  inc view.stats.dirtyCount
  view.cachedMemoryUsage += coin.dynamicMemoryUsage()

proc spendCoin*(view: CoinsViewCache, outpoint: OutPoint, moveout: var Option[Coin]): bool =
  ## Spend a coin, optionally moving its data out
  ## Returns true if coin was found and spent
  var entry: CoinEntry

  if outpoint in view.cache:
    entry = view.cache[outpoint]
    if entry.coin.isSpent:
      return false

    if entry.dirty:
      dec view.stats.dirtyCount
    view.cachedMemoryUsage -= entry.coin.dynamicMemoryUsage()

    moveout = some(entry.coin)

    # FRESH optimization: if fresh and spent, we can delete entirely
    # (coin was created and spent without touching disk)
    if entry.fresh:
      view.cache.del(outpoint)
      return true

    # Otherwise mark as spent and dirty
    var spentEntry = entry
    spentEntry.coin.clear()
    spentEntry.dirty = true
    spentEntry.fresh = false
    view.cache[outpoint] = spentEntry
    inc view.stats.dirtyCount
    return true

  # Not in cache - try to fetch from base
  let baseCoin = view.base.getCoin(outpoint)
  if baseCoin.isNone:
    return false

  moveout = baseCoin

  # Mark as spent in cache (dirty, not fresh)
  var spentCoin = baseCoin.get()
  spentCoin.clear()
  view.cache[outpoint] = CoinEntry(
    coin: spentCoin,
    dirty: true,
    fresh: false
  )
  inc view.stats.dirtyCount
  true

proc spendCoin*(view: CoinsViewCache, outpoint: OutPoint): bool =
  ## Spend a coin without retrieving its data
  var moveout: Option[Coin]
  view.spendCoin(outpoint, moveout)

proc uncache*(view: CoinsViewCache, outpoint: OutPoint) =
  ## Remove non-dirty entry from cache
  if outpoint in view.cache:
    let entry = view.cache[outpoint]
    if not entry.dirty:
      view.cachedMemoryUsage -= entry.coin.dynamicMemoryUsage()
      view.cache.del(outpoint)

method flush*(view: CoinsViewCache): bool =
  ## Flush all dirty entries to backing store
  ## Returns true on success
  inc view.stats.flushCount

  if view.base of CoinsViewDB:
    let dbView = CoinsViewDB(view.base)
    let batch = dbView.db.newWriteBatch()
    defer: batch.destroy()

    var toDelete: seq[OutPoint] = @[]

    for outpoint, entry in view.cache:
      if not entry.dirty:
        continue

      let key = coinDbKey(outpoint)

      if entry.coin.isSpent:
        # FRESH + spent = never existed in DB, skip delete
        if entry.fresh:
          toDelete.add(outpoint)
        else:
          batch.delete(cfUtxo, key)
          toDelete.add(outpoint)
      else:
        batch.put(cfUtxo, key, serializeCoin(entry.coin))

    # Update best block
    if view.bestBlockHash != default(array[32, byte]):
      batch.put(cfUtxo, @[byte('B')], @(view.bestBlockHash))
      dbView.bestBlockHash = view.bestBlockHash

    dbView.db.write(batch)

    # Clean up spent entries from cache
    for op in toDelete:
      view.cache.del(op)

    # Clear dirty flags on remaining entries
    for outpoint in view.cache.keys:
      var entry = view.cache[outpoint]
      entry.dirty = false
      entry.fresh = false
      view.cache[outpoint] = entry

    view.stats.dirtyCount = 0
    return true

  elif view.base of CoinsViewCache:
    # Flush to parent cache
    let parentCache = CoinsViewCache(view.base)

    for outpoint, entry in view.cache:
      if not entry.dirty:
        continue

      if entry.coin.isSpent:
        if entry.fresh:
          # Never existed in parent, skip
          discard
        else:
          # Mark spent in parent
          discard parentCache.spendCoin(outpoint)
      else:
        # Add/update in parent
        if outpoint in parentCache.cache:
          parentCache.addCoin(outpoint, entry.coin, possibleOverwrite = true)
        else:
          parentCache.addCoin(outpoint, entry.coin, possibleOverwrite = entry.fresh)

    # Update best block in parent
    if view.bestBlockHash != default(array[32, byte]):
      parentCache.setBestBlock(view.bestBlockHash)

    # Clear this cache after flush
    view.cache.clear()
    view.cachedMemoryUsage = 0
    view.stats.dirtyCount = 0
    return true

  false

proc sync*(view: CoinsViewCache): bool =
  ## Flush to backing store but keep cache contents (for non-destructive sync)
  ## Clears dirty flags but retains cached coins
  if view.base of CoinsViewDB:
    let dbView = CoinsViewDB(view.base)
    let batch = dbView.db.newWriteBatch()
    defer: batch.destroy()

    var spentEntries: seq[OutPoint] = @[]

    for outpoint, entry in view.cache:
      if not entry.dirty:
        continue

      let key = coinDbKey(outpoint)

      if entry.coin.isSpent:
        if not entry.fresh:
          batch.delete(cfUtxo, key)
        spentEntries.add(outpoint)
      else:
        batch.put(cfUtxo, key, serializeCoin(entry.coin))

    # Update best block
    if view.bestBlockHash != default(array[32, byte]):
      batch.put(cfUtxo, @[byte('B')], @(view.bestBlockHash))
      dbView.bestBlockHash = view.bestBlockHash

    dbView.db.write(batch)

    # Remove spent entries, clear flags on others
    for op in spentEntries:
      view.cache.del(op)

    for outpoint in view.cache.keys:
      var entry = view.cache[outpoint]
      entry.dirty = false
      entry.fresh = false
      view.cache[outpoint] = entry

    view.stats.dirtyCount = 0
    return true

  false

proc reset*(view: CoinsViewCache) =
  ## Discard all cached changes without flushing
  view.cache.clear()
  view.cachedMemoryUsage = 0
  view.stats.dirtyCount = 0
  view.bestBlockHash = default(array[32, byte])

method estimateSize*(view: CoinsViewCache): int =
  view.dynamicMemoryUsage()

# =============================================================================
# Utility functions
# =============================================================================

proc addCoins*(view: CoinsViewCache, tx: types.Transaction, height: int32) =
  ## Add all outputs from a transaction to the cache
  let isCoinbase = tx.inputs.len > 0 and
                   tx.inputs[0].prevOut.vout == 0xFFFFFFFF'u32 and
                   array[32, byte](tx.inputs[0].prevOut.txid) == default(array[32, byte])
  let txid = tx.txid()

  for vout, output in tx.outputs:
    # Skip unspendable outputs
    if output.scriptPubKey.len > 0 and output.scriptPubKey[0] == 0x6a:  # OP_RETURN
      continue

    let outpoint = OutPoint(txid: txid, vout: uint32(vout))
    let coin = Coin(
      txOut: output,
      height: height,
      isCoinbase: isCoinbase
    )
    # Coinbase can always overwrite (pre-BIP34 duplicate txids)
    view.addCoin(outpoint, coin, possibleOverwrite = isCoinbase)

proc haveInputs*(view: CoinsViewCache, tx: types.Transaction): bool =
  ## Check if all inputs of a transaction are available
  # Skip coinbase (has no real inputs)
  if tx.inputs.len > 0 and
     tx.inputs[0].prevOut.vout == 0xFFFFFFFF'u32 and
     array[32, byte](tx.inputs[0].prevOut.txid) == default(array[32, byte]):
    return true

  for input in tx.inputs:
    if not view.haveCoin(input.prevOut):
      return false
  true
