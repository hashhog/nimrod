## Signature verification cache - caches successful script verifications
## to avoid redundant work during block connection and mempool acceptance.
##
## Fix W160 BUG-11:
##   Cache key now folds in (sighash || pubkey || sig) per Bitcoin Core's
##   ComputeEntryECDSA / ComputeEntrySchnorr (sigcache.cpp:39-50). The previous
##   key — SHA256(nonce || wtxid || inputIndex || flags) — was insufficient for
##   the tapscript-multisig case where a single input runs multiple OP_CHECKSIG
##   ops with different (sighash, sig, pubkey) tuples: the first successful
##   verify cached `(wtxid, inputIdx, flags) -> true`, and every subsequent
##   verify call for the same input short-circuited regardless of which
##   sig/pubkey was being checked. With the new key, distinct (sighash, sig,
##   pubkey) tuples map to distinct cache slots, matching Core's per-sig
##   caching semantics.
##
## Fix W105 G7+G8+G10 (preserved):
##   G8: 32-byte nonce sampled from OS CSPRNG at SigCache construction time;
##       key = SHA256(nonce || sighash || pubkey || sig) so cache entries are
##       not predictable from public transaction data.
##   G10: Lock protects all table accesses; safe for concurrent lookup/insert
##        from parallel script-verification tasks if the parallel path is
##        re-enabled, and from concurrent mempool + block-connect execution.
##
## Reference: bitcoin-core/src/script/sigcache.cpp:39-50
##   ComputeEntryECDSA(entry, sighash, sig, pubkey)
##   ComputeEntrySchnorr(entry, sighash, sig, pubkey)

import std/[tables, hashes, locks, sysrand]
import ../crypto/hashing

type
  ## Internal key: first 8 bytes of SHA256(nonce || sighash || pubkey || sig).
  ## Using a uint64 keeps the Table hot-path cheap while preserving collision
  ## resistance from the underlying 256-bit hash.
  SigCacheKey* = uint64

  SigCache* = ref object
    nonce*: array[32, byte]       ## CSPRNG nonce; set once at construction
    entries: Table[SigCacheKey, bool]
    maxEntries: int
    lock: Lock                    ## Protects all accesses to `entries`

## Derive the internal cache key from (nonce, sighash, pubkey, sig).
## Mirrors Core's ComputeEntryECDSA/ComputeEntrySchnorr which fold the
## sighash, signature bytes, and pubkey bytes into the cache key so two
## different (sighash, sig, pubkey) tuples for the same transaction input
## map to distinct cache slots — closes the tapscript-multisig short-circuit
## documented in W160 BUG-11.
proc computeKey*(cache: SigCache, sighash: array[32, byte],
                 pubkey: openArray[byte], sig: openArray[byte]): SigCacheKey =
  ## key = SHA256(nonce[32] || sighash[32] || pubkey[..] || sig[..])
  ## Take the first 8 bytes of the resulting 32-byte hash as the uint64 key.
  var buf = newSeq[byte](64 + pubkey.len + sig.len)
  for i in 0 ..< 32:
    buf[i] = cache.nonce[i]
  for i in 0 ..< 32:
    buf[32 + i] = sighash[i]
  for i in 0 ..< pubkey.len:
    buf[64 + i] = pubkey[i]
  for i in 0 ..< sig.len:
    buf[64 + pubkey.len + i] = sig[i]
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

proc lookup*(cache: SigCache, sighash: array[32, byte],
             pubkey: openArray[byte], sig: openArray[byte]): bool =
  ## Thread-safe lookup; returns true iff (sighash, pubkey, sig) is cached.
  let key = cache.computeKey(sighash, pubkey, sig)
  withLock cache.lock:
    result = cache.entries.hasKey(key)

proc insert*(cache: SigCache, sighash: array[32, byte],
             pubkey: openArray[byte], sig: openArray[byte]) =
  ## Thread-safe insert. Evicts one entry (first found) when at capacity.
  let key = cache.computeKey(sighash, pubkey, sig)
  withLock cache.lock:
    if cache.entries.hasKey(key):
      return
    if cache.entries.len >= cache.maxEntries:
      # Simple eviction: remove first entry found in iteration order
      for k in cache.entries.keys:
        cache.entries.del(k)
        break
    cache.entries[key] = true

## Backward-compatible (wtxid, inputIndex, flags) API used by older tests and
## tooling. The underlying key derivation is identical to the new
## (sighash, pubkey, sig) API — we just stuff the legacy fields into the
## sighash/pubkey/sig slots so distinct (wtxid, inputIdx, flags) tuples still
## map to distinct slots. New production code MUST use the canonical
## (sighash, pubkey, sig) overloads above — they are what closes W160 BUG-11.
proc encodeLegacyKey(wtxid: array[32, byte], inputIndex: uint32,
                     flags: uint32): tuple[sighash: array[32, byte],
                                            pubkey: array[4, byte],
                                            sig: array[4, byte]] =
  result.sighash = wtxid
  result.pubkey = [byte(inputIndex and 0xFF'u32),
                   byte((inputIndex shr 8) and 0xFF'u32),
                   byte((inputIndex shr 16) and 0xFF'u32),
                   byte((inputIndex shr 24) and 0xFF'u32)]
  result.sig = [byte(flags and 0xFF'u32),
                byte((flags shr 8) and 0xFF'u32),
                byte((flags shr 16) and 0xFF'u32),
                byte((flags shr 24) and 0xFF'u32)]

proc computeKey*(cache: SigCache, wtxid: array[32, byte],
                 inputIndex: uint32, flags: uint32): SigCacheKey =
  let parts = encodeLegacyKey(wtxid, inputIndex, flags)
  cache.computeKey(parts.sighash, parts.pubkey, parts.sig)

proc lookup*(cache: SigCache, wtxid: array[32, byte],
             inputIndex: uint32, flags: uint32): bool =
  let parts = encodeLegacyKey(wtxid, inputIndex, flags)
  cache.lookup(parts.sighash, parts.pubkey, parts.sig)

proc insert*(cache: SigCache, wtxid: array[32, byte],
             inputIndex: uint32, flags: uint32) =
  let parts = encodeLegacyKey(wtxid, inputIndex, flags)
  cache.insert(parts.sighash, parts.pubkey, parts.sig)

proc clear*(cache: SigCache) =
  withLock cache.lock:
    cache.entries.clear()

proc len*(cache: SigCache): int =
  withLock cache.lock:
    result = cache.entries.len

## Process-wide sigcache, shared by every CHECKSIG / CHECKSIGADD evaluation
## across all transactions in the mempool and block-validation hot paths.
## Mirrors Bitcoin Core's static `signatureCache` / `g_sig_cache` (init.cpp).
var globalSigCache* = newSigCache(50_000)
