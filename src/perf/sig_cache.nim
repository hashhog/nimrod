## Signature verification cache - caches successful script verifications
## to avoid redundant work during block connection and mempool acceptance.
##
## Fix W105 G7+G8+G10:
##   G7: key uses wtxid (witness transaction ID) not txid; witness-malleated
##       variants of the same txid now correctly produce distinct cache keys.
##   G8: 32-byte nonce sampled from OS CSPRNG at SigCache construction time;
##       key = SHA256(nonce || wtxid || inputIndex_le32 || flags_le32) so
##       cache entries are not predictable from public transaction data.
##   G10: Lock protects all table accesses; safe for concurrent lookup/insert
##        from parallel script-verification tasks if the parallel path is
##        re-enabled, and from concurrent mempool + block-connect execution.
##
## Reference: bitcoin-core/src/script/sigcache.h
##   SignatureCache::ComputeEntry — salted SHA256 over sig material + nonce
##   ValidationCache ctor — nonce = GetRandHash()
##   SignatureCache::Get — std::shared_lock<std::shared_mutex>
##   SignatureCache::Set — std::unique_lock<std::shared_mutex>

import std/[tables, hashes, locks, sysrand]
import ../crypto/hashing

type
  ## Internal key: first 8 bytes of SHA256(nonce||wtxid||inputIndex||flags).
  ## Using a uint64 keeps the Table hot-path cheap while preserving collision
  ## resistance from the 256-bit hash.
  SigCacheKey* = uint64

  SigCache* = ref object
    nonce*: array[32, byte]       ## CSPRNG nonce; set once at construction
    entries: Table[SigCacheKey, bool]
    maxEntries: int
    lock: Lock                    ## Protects all accesses to `entries`

## Derive the internal cache key from (nonce, wtxid, inputIndex, flags).
proc computeKey*(cache: SigCache, wtxid: array[32, byte],
                 inputIndex: uint32, flags: uint32): SigCacheKey =
  ## key = SHA256(nonce[32] || wtxid[32] || inputIndex_le32[4] || flags_le32[4])
  ## Take the first 8 bytes of the resulting 32-byte hash as the uint64 key.
  var buf: array[72, byte]
  # nonce
  for i in 0 ..< 32:
    buf[i] = cache.nonce[i]
  # wtxid
  for i in 0 ..< 32:
    buf[32 + i] = wtxid[i]
  # inputIndex little-endian 4 bytes
  buf[64] = byte(inputIndex and 0xFF'u32)
  buf[65] = byte((inputIndex shr 8) and 0xFF'u32)
  buf[66] = byte((inputIndex shr 16) and 0xFF'u32)
  buf[67] = byte((inputIndex shr 24) and 0xFF'u32)
  # flags little-endian 4 bytes
  buf[68] = byte(flags and 0xFF'u32)
  buf[69] = byte((flags shr 8) and 0xFF'u32)
  buf[70] = byte((flags shr 16) and 0xFF'u32)
  buf[71] = byte((flags shr 24) and 0xFF'u32)
  let digest = sha256Single(buf)
  # Pack first 8 bytes as little-endian uint64
  result = uint64(digest[0]) or
           (uint64(digest[1]) shl 8) or
           (uint64(digest[2]) shl 16) or
           (uint64(digest[3]) shl 24) or
           (uint64(digest[4]) shl 32) or
           (uint64(digest[5]) shl 40) or
           (uint64(digest[6]) shl 48) or
           (uint64(digest[7]) shl 56)

proc newSigCache*(maxEntries: int = 50_000): SigCache =
  var c = SigCache(
    entries: initTable[SigCacheKey, bool](),
    maxEntries: maxEntries
  )
  initLock(c.lock)
  # Initialize nonce from OS CSPRNG (/dev/urandom on Linux)
  if not urandom(c.nonce):
    raise newException(IOError,
      "SigCache: system entropy unavailable; cannot initialize nonce")
  result = c

proc lookup*(cache: SigCache, wtxid: array[32, byte],
             inputIndex: uint32, flags: uint32): bool =
  ## Thread-safe lookup; returns true iff (wtxid, inputIndex, flags) is cached.
  let key = cache.computeKey(wtxid, inputIndex, flags)
  withLock cache.lock:
    result = cache.entries.hasKey(key)

proc insert*(cache: SigCache, wtxid: array[32, byte],
             inputIndex: uint32, flags: uint32) =
  ## Thread-safe insert. Evicts one entry (first found) when at capacity.
  let key = cache.computeKey(wtxid, inputIndex, flags)
  withLock cache.lock:
    if cache.entries.hasKey(key):
      return
    if cache.entries.len >= cache.maxEntries:
      # Simple eviction: remove first entry found in iteration order
      for k in cache.entries.keys:
        cache.entries.del(k)
        break
    cache.entries[key] = true

proc clear*(cache: SigCache) =
  withLock cache.lock:
    cache.entries.clear()

proc len*(cache: SigCache): int =
  withLock cache.lock:
    result = cache.entries.len
