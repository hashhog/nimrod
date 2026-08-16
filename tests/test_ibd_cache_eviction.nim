## IBD UTXO-cache eviction regression test.
##
## The bug this pins (2026-08-15, mainnet genesis rig): `evictCleanEntries` is
## the ONLY bound on the UTXO cache during IBD, and it decides via
## `cacheSize * EstimatedEntryBytes <= maxCacheBytes`. `EstimatedEntryBytes`
## was 172 while the measured marginal cost is 336
## (tests/measure_utxo_entry_bytes.nim), so the computed size stayed under the
## ceiling forever: the rig reached 38.5M entries / 37 GiB RSS against a
## configured --dbcache=8192 with cacheAfter == cacheBefore on ALL 14 flushes.
## Eviction had never fired once, and the rig OOM-killed a neighbouring node
## twice before anyone noticed.
##
## There was no test asserting that eviction ever actually happens — the whole
## failure mode was a bound that silently never triggered. These tests assert
## the trigger itself, not just the arithmetic.

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbBase = "/tmp/nimrod_ibd_cache_eviction_test"

proc dbPath(n: int): string = TestDbBase & "_" & $n

proc cleanupTestDbs() =
  for n in 1 .. 4:
    if dirExists(dbPath(n)):
      removeDir(dbPath(n))

proc putEntries(cs: var ChainState, count: int, startIdx: int = 0) =
  ## Populate the cache directly — this exercises the eviction bound without
  ## needing real blocks.
  for i in startIdx ..< startIdx + count:
    var raw: array[32, byte]
    raw[0] = byte(i and 0xff)
    raw[1] = byte((i shr 8) and 0xff)
    raw[2] = byte((i shr 16) and 0xff)
    raw[3] = byte((i shr 24) and 0xff)
    cs.putUtxoCache(
      OutPoint(txid: TxId(raw), vout: uint32(i and 0x3)),
      UtxoEntry(
        output: TxOut(value: Satoshi(i + 1), scriptPubKey: newSeq[byte](22)),
        height: int32(i mod 100_000),
        isCoinbase: false))

suite "IBD UTXO cache eviction":
  setup:
    cleanupTestDbs()

  teardown:
    cleanupTestDbs()

  test "EstimatedEntryBytes reflects the measured marginal cost":
    # Guards against silently reverting to a hand-guessed value. The measured
    # figure is 336 B/entry (tests/measure_utxo_entry_bytes.nim, Nim 2.2.8 /
    # Linux amd64). A LOWER value re-arms the unbounded-growth bug, so the
    # floor is the assertion that matters.
    check EstimatedEntryBytes >= 336

  test "eviction FIRES once the cache exceeds its byte ceiling":
    var cs = newChainState(dbPath(1), regtestParams())
    cs.startIBD()
    # Small explicit ceiling so the test stays fast: 4 MiB.
    cs.maxCacheBytes = 4 * 1024 * 1024
    let ceilingEntries = cs.maxCacheBytes div EstimatedEntryBytes

    # Fill to 2x the ceiling.
    putEntries(cs, ceilingEntries * 2)
    check cs.cacheSize == ceilingEntries * 2

    cs.evictCleanEntries()

    # It must actually have evicted — the exact bug was a no-op here.
    check cs.cacheSize < ceilingEntries * 2
    # And it must land at/below the half-ceiling target.
    let targetEntries = (cs.maxCacheBytes div 2) div EstimatedEntryBytes
    check cs.cacheSize <= targetEntries + 1
    cs.db.db.closeUnsafe()

  test "eviction is a NO-OP while under the ceiling":
    var cs = newChainState(dbPath(2), regtestParams())
    cs.startIBD()
    cs.maxCacheBytes = 4 * 1024 * 1024
    let ceilingEntries = cs.maxCacheBytes div EstimatedEntryBytes

    putEntries(cs, ceilingEntries div 2)
    let before = cs.cacheSize
    cs.evictCleanEntries()
    check cs.cacheSize == before   # nothing evicted; hot set stays resident
    cs.db.db.closeUnsafe()

  test "--dbcache budget actually bounds the cache (setDbCache path)":
    var cs = newChainState(dbPath(3), regtestParams())
    # 8 MiB budget, the same path --dbcache=<MiB> takes on the real node.
    cs.setDbCache(8)
    cs.startIBD()
    # setDbCache floors maxCacheBytes at MaxCacheBytes (2 GiB) by design, so
    # pin the ceiling explicitly to keep the test small while still driving
    # the derived entry target.
    cs.maxCacheBytes = 8 * 1024 * 1024
    let ceilingEntries = cs.maxCacheBytes div EstimatedEntryBytes

    # Simulate repeated IBD flush intervals: grow, flush-evict, repeat. The
    # cache must NEVER exceed the ceiling across iterations — the live failure
    # was monotonic growth across 14 consecutive flushes.
    var idx = 0
    for round in 1 .. 5:
      putEntries(cs, ceilingEntries, idx)
      idx += ceilingEntries
      cs.evictCleanEntries()
      check cs.cacheSize <= ceilingEntries
    cs.db.db.closeUnsafe()
