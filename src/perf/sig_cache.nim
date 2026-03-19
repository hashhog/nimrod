## Signature verification cache - caches successful script verifications
## to avoid redundant work during block connection and mempool acceptance.

import std/[tables, hashes]

type
  SigCacheKey* = object
    txid*: array[32, byte]
    inputIndex*: uint32
    flags*: uint32

  SigCache* = ref object
    entries: Table[SigCacheKey, bool]
    maxEntries: int

proc hash*(k: SigCacheKey): Hash =
  var h: Hash = 0
  h = h !& hash(k.txid)
  h = h !& hash(k.inputIndex)
  h = h !& hash(k.flags)
  result = !$h

proc newSigCache*(maxEntries: int = 50_000): SigCache =
  SigCache(entries: initTable[SigCacheKey, bool](), maxEntries: maxEntries)

proc lookup*(cache: SigCache, txid: array[32, byte], inputIndex: uint32, flags: uint32): bool =
  let key = SigCacheKey(txid: txid, inputIndex: inputIndex, flags: flags)
  cache.entries.hasKey(key)

proc insert*(cache: SigCache, txid: array[32, byte], inputIndex: uint32, flags: uint32) =
  let key = SigCacheKey(txid: txid, inputIndex: inputIndex, flags: flags)
  if cache.entries.hasKey(key):
    return
  if cache.entries.len >= cache.maxEntries:
    # Random eviction: remove first entry found
    for k in cache.entries.keys:
      cache.entries.del(k)
      break
  cache.entries[key] = true

proc clear*(cache: SigCache) =
  cache.entries.clear()

proc len*(cache: SigCache): int =
  cache.entries.len
