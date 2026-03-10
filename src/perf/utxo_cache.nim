## High-performance UTXO cache with open-addressing hash map
## Optimized for fast lookups during IBD and block validation
##
## Design:
## - Open-addressing with linear probing for cache-friendly access
## - 36-byte key (32-byte txid + 4-byte vout) hashed to 64-bit
## - Configurable load factor threshold (default 0.7)
## - Automatic resizing when load factor exceeded

import std/[options, hashes]
import ../primitives/types
import ../storage/chainstate

export UtxoEntry, OutPoint

type
  CacheState* = enum
    csEmpty = 0
    csOccupied = 1
    csDeleted = 2

  UtxoCacheEntry* = object
    state*: CacheState
    key*: OutPoint
    value*: UtxoEntry

  UtxoCache* = object
    ## Open-addressing hash map for UTXO entries
    ## Optimized for hot UTXO lookups during validation
    buckets*: seq[UtxoCacheEntry]
    count*: int
    capacity*: int
    deletedCount*: int
    loadFactorThreshold*: float64
    stats*: UtxoCacheStats

  UtxoCacheStats* = object
    ## Statistics for cache performance analysis
    hits*: int64
    misses*: int64
    insertions*: int64
    deletions*: int64
    probeCount*: int64  # Total probe steps (for measuring clustering)
    resizeCount*: int

const
  DefaultCapacity* = 65536  # 64K entries initial
  DefaultLoadFactor* = 0.7
  MinCapacity* = 1024

proc hash(op: OutPoint): Hash {.inline.} =
  ## Hash an OutPoint for the hash table
  ## Uses FNV-1a style combining for speed
  {.push overflowChecks: off.}
  var h: Hash = 0
  let txidBytes = array[32, byte](op.txid)

  # Hash txid bytes
  for b in txidBytes:
    h = h xor Hash(b)
    h = h * 0x01000193  # FNV prime

  # Hash vout
  h = h xor Hash(op.vout)
  h = h * 0x01000193
  h = h xor Hash(op.vout shr 8)
  h = h * 0x01000193
  h = h xor Hash(op.vout shr 16)
  h = h * 0x01000193
  h = h xor Hash(op.vout shr 24)
  {.pop.}

  result = h

proc nextPowerOfTwo(n: int): int =
  ## Round up to next power of two
  var x = n - 1
  x = x or (x shr 1)
  x = x or (x shr 2)
  x = x or (x shr 4)
  x = x or (x shr 8)
  x = x or (x shr 16)
  x = x or (x shr 32)
  x + 1

proc newUtxoCache*(capacity: int = DefaultCapacity, loadFactor: float64 = DefaultLoadFactor): UtxoCache =
  ## Create a new UTXO cache with given initial capacity
  let actualCapacity = max(MinCapacity, nextPowerOfTwo(capacity))
  result.capacity = actualCapacity
  result.buckets = newSeq[UtxoCacheEntry](actualCapacity)
  result.count = 0
  result.deletedCount = 0
  result.loadFactorThreshold = loadFactor
  result.stats = UtxoCacheStats()

proc loadFactor*(cache: UtxoCache): float64 =
  ## Current load factor (occupied + deleted / capacity)
  float64(cache.count + cache.deletedCount) / float64(cache.capacity)

proc effectiveLoadFactor*(cache: UtxoCache): float64 =
  ## Effective load factor (occupied only / capacity)
  float64(cache.count) / float64(cache.capacity)

proc findSlot(cache: UtxoCache, key: OutPoint): tuple[idx: int, found: bool] =
  ## Find the slot for a key using linear probing
  ## Returns (index, found) where found indicates if key exists
  let h = hash(key)
  let mask = cache.capacity - 1  # Capacity is power of 2
  var idx = h and mask
  var firstDeleted = -1

  for probe in 0 ..< cache.capacity:
    let entry = cache.buckets[idx]

    case entry.state
    of csEmpty:
      # Key not found, return insertion point
      if firstDeleted >= 0:
        return (firstDeleted, false)
      return (idx, false)

    of csDeleted:
      # Track first deleted slot for potential insertion
      if firstDeleted < 0:
        firstDeleted = idx

    of csOccupied:
      if entry.key == key:
        return (idx, true)

    idx = (idx + 1) and mask

  # Table full (shouldn't happen with proper load factor management)
  if firstDeleted >= 0:
    return (firstDeleted, false)
  return (-1, false)

proc resize(cache: var UtxoCache, newCapacity: int) =
  ## Resize the cache to new capacity
  let actualCapacity = nextPowerOfTwo(newCapacity)
  var oldBuckets = cache.buckets

  cache.buckets = newSeq[UtxoCacheEntry](actualCapacity)
  cache.capacity = actualCapacity
  cache.count = 0
  cache.deletedCount = 0
  cache.stats.resizeCount += 1

  # Reinsert all occupied entries
  for entry in oldBuckets:
    if entry.state == csOccupied:
      let (idx, _) = cache.findSlot(entry.key)
      cache.buckets[idx] = UtxoCacheEntry(
        state: csOccupied,
        key: entry.key,
        value: entry.value
      )
      cache.count += 1

proc maybeResize(cache: var UtxoCache) =
  ## Resize if load factor exceeded
  if cache.loadFactor() > cache.loadFactorThreshold:
    cache.resize(cache.capacity * 2)

proc get*(cache: var UtxoCache, key: OutPoint): Option[UtxoEntry] =
  ## Look up a UTXO entry by OutPoint
  ## O(1) average case with linear probing
  let (idx, found) = cache.findSlot(key)

  if found:
    cache.stats.hits += 1
    return some(cache.buckets[idx].value)
  else:
    cache.stats.misses += 1
    return none(UtxoEntry)

proc get*(cache: UtxoCache, key: OutPoint): Option[UtxoEntry] =
  ## Look up a UTXO entry (const version, no stats update)
  let (idx, found) = cache.findSlot(key)
  if found:
    return some(cache.buckets[idx].value)
  none(UtxoEntry)

proc contains*(cache: UtxoCache, key: OutPoint): bool =
  ## Check if key exists in cache
  let (_, found) = cache.findSlot(key)
  found

proc put*(cache: var UtxoCache, key: OutPoint, val: UtxoEntry) =
  ## Insert or update a UTXO entry
  cache.maybeResize()

  let (idx, found) = cache.findSlot(key)

  if idx < 0:
    # Table full even after resize (shouldn't happen)
    cache.resize(cache.capacity * 2)
    cache.put(key, val)
    return

  if not found:
    # Check if we're replacing a deleted slot
    if cache.buckets[idx].state == csDeleted:
      cache.deletedCount -= 1
    cache.count += 1
    cache.stats.insertions += 1

  cache.buckets[idx] = UtxoCacheEntry(
    state: csOccupied,
    key: key,
    value: val
  )

proc delete*(cache: var UtxoCache, key: OutPoint): bool =
  ## Delete a UTXO entry
  ## Returns true if entry was found and deleted
  let (idx, found) = cache.findSlot(key)

  if found:
    cache.buckets[idx].state = csDeleted
    cache.count -= 1
    cache.deletedCount += 1
    cache.stats.deletions += 1
    return true

  false

proc clear*(cache: var UtxoCache) =
  ## Clear all entries from the cache
  for i in 0 ..< cache.capacity:
    cache.buckets[i] = UtxoCacheEntry()
  cache.count = 0
  cache.deletedCount = 0

proc len*(cache: UtxoCache): int =
  ## Number of entries in cache
  cache.count

proc hitRate*(cache: UtxoCache): float64 =
  ## Cache hit rate as a ratio
  let total = cache.stats.hits + cache.stats.misses
  if total > 0:
    float64(cache.stats.hits) / float64(total)
  else:
    0.0

proc avgProbeLength*(cache: UtxoCache): float64 =
  ## Average probe length (requires probing stats)
  let lookups = cache.stats.hits + cache.stats.misses
  if lookups > 0:
    float64(cache.stats.probeCount) / float64(lookups)
  else:
    0.0

# Batch operations for efficiency

proc putBatch*(cache: var UtxoCache, entries: openArray[(OutPoint, UtxoEntry)]) =
  ## Insert multiple entries efficiently
  # Pre-resize if needed
  let neededCapacity = int(float64(cache.count + entries.len) / cache.loadFactorThreshold) + 1
  if neededCapacity > cache.capacity:
    cache.resize(neededCapacity * 2)

  for (key, val) in entries:
    cache.put(key, val)

proc deleteBatch*(cache: var UtxoCache, keys: openArray[OutPoint]): int =
  ## Delete multiple entries, returns count deleted
  for key in keys:
    if cache.delete(key):
      result += 1

# Iterator support

iterator pairs*(cache: UtxoCache): (OutPoint, UtxoEntry) =
  ## Iterate over all cache entries
  for entry in cache.buckets:
    if entry.state == csOccupied:
      yield (entry.key, entry.value)

iterator keys*(cache: UtxoCache): OutPoint =
  ## Iterate over all keys
  for entry in cache.buckets:
    if entry.state == csOccupied:
      yield entry.key

iterator values*(cache: UtxoCache): UtxoEntry =
  ## Iterate over all values
  for entry in cache.buckets:
    if entry.state == csOccupied:
      yield entry.value

# Memory estimation

proc estimatedMemoryBytes*(cache: UtxoCache): int =
  ## Estimate memory usage in bytes
  ## Entry: ~100 bytes (OutPoint 36 + UtxoEntry ~60 + overhead)
  const entrySize = 128  # Conservative estimate with alignment
  cache.capacity * entrySize

proc estimatedMemoryMB*(cache: UtxoCache): float64 =
  float64(cache.estimatedMemoryBytes()) / (1024 * 1024)

# Compact to reclaim deleted slots

proc compact*(cache: var UtxoCache) =
  ## Rebuild the cache to reclaim deleted slots
  ## Call this periodically during IBD if deletedCount is high
  if cache.deletedCount > cache.count div 4:  # >25% deleted
    cache.resize(cache.capacity)
