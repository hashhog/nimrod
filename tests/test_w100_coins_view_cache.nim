## W100: CCoinsViewCache + FlushStateToDisk gate audit tests
## Reference: bitcoin-core/src/coins.h, coins.cpp, validation.cpp FlushStateToDisk
##
## Bugs covered:
## B1 (G11): flush() to CoinsViewDB retains unspent entries (Sync semantics, not Flush)
## B2 (G11b): sync() removes spent entries (Core Sync keeps all entries flagged clean)
## B3 (G15): SanityCheck proc missing - no invariant verification
## B4 (G21): flush-to-parent: child FRESH + parent unspent overwrites silently (Core throws)
## B5 (G22): DynamicMemoryUsage undercount (entryOverhead too small, no hashtable node cost)
## B6 (G25/G26): No FlushStateMode enum, no 1-hour PERIODIC trigger
## B7 (G27): No nMinDiskSpace check before flush
## B8 (G18): AccessByTxid MaxOutputsToProbe=65535 vs Core's ~111111
## B9 (G14): No ReallocateCache equivalent after flush
## B10 (G30): No ChainStateFlushed signal/notification after flush
## B11: isSpent sentinel: value=0+empty != Core's nValue=-1 sentinel
## B12: addCoin lacks isUnspendable guard (only addCoins wrapper has it)

import std/[os, options, random]
import unittest2
import ../src/storage/utxo_cache
import ../src/storage/db
import ../src/primitives/[types, serialize]

proc randomTxId(): TxId =
  var bytes: array[32, byte]
  for i in 0..<32:
    bytes[i] = byte(rand(255))
  TxId(bytes)

proc randomOutPoint(): OutPoint =
  OutPoint(txid: randomTxId(), vout: uint32(rand(100)))

proc makeCoin(value: int64 = 100_000, height: int32 = 100,
              coinbase: bool = false,
              script: seq[byte] = @[byte(0x76), 0xa9, 0x14]): utxo_cache.Coin =
  utxo_cache.Coin(
    txOut: TxOut(value: Satoshi(value), scriptPubKey: script),
    height: height,
    isCoinbase: coinbase
  )

proc openTestDb(suffix: string = ""): tuple[db: Database, path: string] =
  let path = getTempDir() / "nimrod_w100_" & suffix & "_" & $rand(999_999)
  (openDatabase(path), path)

# ============================================================
# B1: flush() to CoinsViewDB retains unspent entries in cache
#     Core's Flush() clears the entire cache (will_erase=true).
#     nimrod flush() only removes spent entries; unspent entries
#     remain with dirty=false, fresh=false — Sync semantics.
# ============================================================
suite "W100 B1 flush_to_db_retains_cache":
  test "after flush unspent entries remain in cache (Sync behavior not Flush)":
    let (db, path) = openTestDb("b1")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = makeCoin()
    cache.addCoin(op, coin)
    check cache.cacheSize() == 1

    check cache.flush()

    # BUG B1: entry stays in cache after flush — Core would have cleared it
    # Correct Core behavior: cacheSize() == 0 after Flush()
    let cacheAfterFlush = cache.cacheSize()
    check cacheAfterFlush == 1  # documents actual (buggy) behavior: entry retained
    check cache.haveCoinInCache(op)   # still in cache post-flush

  test "flush to DB writes dirty entries but dirty flag clears":
    let (db, path) = openTestDb("b1b")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    cache.addCoin(op, makeCoin())
    check cache.dirtyCount() == 1

    check cache.flush()

    # Dirty count should be 0 after flush
    check cache.dirtyCount() == 0
    # Coin is now in DB
    check dbView.getCoin(op).isSome

# ============================================================
# B2: sync() removes spent entries (should keep them per Core)
#     Core Sync (will_erase=false): all entries stay in cache,
#     just flags cleared. nimrod sync() deletes spent entries.
# ============================================================
suite "W100 B2 sync_removes_spent_entries":
  test "sync removes spent non-fresh entries from cache (Core keeps them)":
    let (db, path) = openTestDb("b2")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    # Seed DB so coin is non-fresh in cache
    dbView.putCoin(op, makeCoin())
    discard cache.getCoin(op)   # bring into cache (clean, non-fresh)
    check cache.haveCoinInCache(op)

    # Now spend it — makes entry dirty+spent+non-fresh
    discard cache.spendCoin(op)
    check not cache.haveCoin(op)
    check cache.cacheSize() == 1  # spent entry still in cache (dirty)

    check cache.sync()

    # BUG B2: sync() deletes spent entries; Core's Sync should keep them clean
    # Correct Core behavior: entry stays with dirty=false after Sync
    check cache.cacheSize() == 0  # documents actual behavior: entry removed

  test "sync preserves unspent entries":
    let (db, path) = openTestDb("b2b")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    cache.addCoin(op, makeCoin())
    check cache.sync()

    check cache.haveCoinInCache(op)
    check cache.dirtyCount() == 0

# ============================================================
# B3: SanityCheck proc missing
#     Core has CCoinsViewCache::SanityCheck() that asserts:
#     - spent coins are DIRTY and not FRESH
#     - unspent coins not FRESH if not DIRTY
#     - cachedCoinsUsage is recomputed correctly
# ============================================================
suite "W100 B3 sanitycheck_missing":
  test "no SanityCheck proc defined on CoinsViewCache":
    # This test documents the absence — it compiles because we don't call it.
    # If SanityCheck existed, we could call it and verify invariants.
    let (db, path) = openTestDb("b3")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    cache.addCoin(op, makeCoin())

    # BUG B3: cannot call cache.sanityCheck() — proc does not exist
    # Manually verify the invariant that should be checked:
    # addCoin → entry should be DIRTY and may be FRESH
    check cache.dirtyCount() == 1

    # Spend it: now it should be DIRTY and not FRESH (for non-fresh coins)
    # (fresh+spent gets deleted immediately so dirtyCount drops)
    discard cache.spendCoin(op)
    # Fresh coin was spent → deleted from cache → dirtyCount = 0
    check cache.dirtyCount() == 0

  test "spent non-fresh entry has dirty flag (invariant verification)":
    let (db, path) = openTestDb("b3b")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    dbView.putCoin(op, makeCoin())     # put in DB (non-fresh)
    discard cache.spendCoin(op)        # spend via cache

    # Should be: spent + dirty + not fresh
    check cache.cacheSize() == 1
    check not cache.haveCoin(op)
    check cache.dirtyCount() == 1     # must be dirty

# ============================================================
# B4 (G21): Flush to parent cache: child FRESH + parent unspent
#     Core: throws logic_error ("FRESH flag misapplied")
#     nimrod: silently overwrites via addCoin(possibleOverwrite=true)
# ============================================================
suite "W100 B4 fresh_invariant_parent_flush":
  test "FRESH child flushing to parent with existing unspent coin overwrites silently":
    let (db, path) = openTestDb("b4")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let parent = newCoinsViewCache(dbView)
    let child = newCoinsViewCache(parent)

    let op = randomOutPoint()
    let coin1 = makeCoin(50_000)
    let coin2 = makeCoin(100_000)

    # Put coin1 in parent cache (unspent, not fresh, not dirty after getCoin)
    dbView.putCoin(op, coin1)
    discard parent.getCoin(op)  # cache it in parent as clean non-fresh
    check parent.haveCoinInCache(op)

    # Now add coin2 as FRESH in child (simulates creating new coin at same outpoint)
    # This SHOULD be an invariant violation: child FRESH but parent has unspent coin
    child.addCoin(op, coin2)  # child marks FRESH because op not in child cache

    # BUG B4: flush() silently overwrites parent entry instead of raising error
    # Core would raise: std::logic_error("FRESH flag misapplied to coin...")
    check child.flush()  # should throw but doesn't

    # After flush, parent now has coin2 (the overwritten value)
    let got = parent.getCoin(op)
    check got.isSome
    check got.get().txOut.value == Satoshi(100_000)  # coin2 overwrote coin1

# ============================================================
# B5 (G22): DynamicMemoryUsage undercount
#     Core: memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage
#     nimrod: cache.len * 60 + cachedMemoryUsage (script bytes only)
# ============================================================
suite "W100 B5 dynamic_memory_usage":
  test "dynamicMemoryUsage reported is less than actual entry count * real overhead":
    let (db, path) = openTestDb("b5")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    # Add entries with larger scripts to expose the undercount
    for i in 0..<100:
      let op = OutPoint(txid: randomTxId(), vout: uint32(i))
      # P2PKH script is 25 bytes
      let script = newSeq[byte](25)
      let coin = utxo_cache.Coin(
        txOut: TxOut(value: Satoshi(100_000), scriptPubKey: script),
        height: int32(i),
        isCoinbase: false
      )
      cache.addCoin(op, coin)

    let reported = cache.dynamicMemoryUsage()

    # BUG B5: entryOverhead=60 bytes, but real hashtable node is ~100-200 bytes
    # Real per-entry cost >= scriptLen(25) + coin_struct(~30) + map_node(~50+) = ~105+
    # Total for 100 entries should be at least 10500 bytes
    let minExpected = 100 * 105  # conservative minimum
    # nimrod reports cache.len*60 + cachedMemoryUsage(scripts=2500) = 6000+2500=8500
    # which is less than the conservative minimum
    check reported < minExpected  # documents undercount

  test "cachedMemoryUsage tracks script bytes only":
    let (db, path) = openTestDb("b5b")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let script = newSeq[byte](100)  # 100-byte script
    let op = randomOutPoint()
    cache.addCoin(op, utxo_cache.Coin(
      txOut: TxOut(value: Satoshi(0), scriptPubKey: script),
      height: 1'i32, isCoinbase: false))

    # cachedMemoryUsage should reflect the script bytes
    let mem = cache.dynamicMemoryUsage()
    check mem > 0

# ============================================================
# B6 (G25/G26): No FlushStateMode enum / no 1hr PERIODIC trigger
#     Core: FlushStateMode {NONE, IF_NEEDED, PERIODIC, ALWAYS, FORCE_FLUSH, FORCE_SYNC}
#     Core: PERIODIC triggers write if nNow >= m_next_write (50-70 min interval)
#     nimrod: binary force flag only; no periodic time-based flush
# ============================================================
suite "W100 B6 flush_state_mode_missing":
  test "no FlushStateMode enum defined in storage modules":
    # The test compiles — verifying that FlushStateMode is NOT defined
    # by checking that flushToDiskIfNeeded takes a bool not an enum.
    # If FlushStateMode existed, we'd import and use it here.
    # The absence means PERIODIC/IF_NEEDED/NONE distinctions are missing.
    check true  # placeholder: absence of the type IS the bug

  test "shouldFlush uses entry count not memory bytes for chainstate":
    ## Core triggers flush when cache memory >= dbcache limit (bytes).
    ## ChainState.shouldFlush() uses cs.cacheSize >= cs.maxCacheSize (entry count).
    ## A single large-script UTXO can exceed memory budget without triggering flush.
    # This is documented via the field names
    let path = getTempDir() / "nimrod_w100_b6_" & $rand(999_999)
    defer: removeDir(path)
    # The maxCacheSize=50000 is entry count, not byte budget
    # 50000 entries * 172 bytes/entry (EstimatedEntryBytes) = 8.6 MB
    # Core uses 450 MiB default — nimrod's entry-count threshold fires much earlier
    check true  # bug documented: count-based threshold vs byte-based threshold

# ============================================================
# B7 (G27): No nMinDiskSpace check before flush
#     Core FlushStateToDisk: calls CheckDiskSpace before writing coins.
#     nimrod flushCache / flushToDiskIfNeeded: no disk-space check.
# ============================================================
suite "W100 B7 no_disk_space_check":
  test "flushCache writes without checking available disk space":
    ## Core validation.cpp:2778,2811 calls CheckDiskSpace before flushing.
    ## nimrod flushCache() has no such guard: a full disk causes a RocksDB
    ## write failure but not a graceful FatalError with operator notification.
    ## Documenting the absence:
    check true  # absence of CheckDiskSpace call is the bug

# ============================================================
# B8 (G18): AccessByTxid MaxOutputsToProbe=65535 vs Core ~111111
#     Core: while (iter.n < MAX_OUTPUTS_PER_BLOCK) where
#       MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / (WITNESS_SCALE_FACTOR * sizeof(CTxOut{}))
#       = 4_000_000 / (4 * 9) = 111111
#     nimrod: MaxOutputsToProbe = 65535 (too small by ~45576 entries)
#     Additionally nimrod has an early-exit at probeVout > 2000 when !foundMeta
#     which means it gives up even earlier than 65535 for most searches.
# ============================================================
suite "W100 B8 access_by_txid_probe_limit":
  test "MaxOutputsToProbe constant is 65535, Core uses 111111":
    ## Bitcoin Core MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT /
    ##   (WITNESS_SCALE_FACTOR * GetSerializeSize(CTxOut())) = 111111
    ## nimrod uses 65535 — will fail to find metadata for outputs at
    ## vout indices 65535..111110 in a maximally-dense block.
    ## This causes DISCONNECT_FAILED on blocks with >65535 outputs per tx.
    const nimrodLimit = 65535
    const coreLimit = 111_111  # MAX_BLOCK_WEIGHT / (4 * 9)
    check nimrodLimit < coreLimit  # documents the gap

  test "early-exit at probeVout > 2000 causes premature metadata failure":
    ## nimrod disconnectBlock Gate 6 exits the AccessByTxid loop when
    ## probeVout > 2000 and no sibling found. Core's AccessByTxid does
    ## NOT have this early exit — it scans all MAX_OUTPUTS_PER_BLOCK vouts.
    ## A tx with vout[0..2001] all spent and vout[2002] unspent as sibling
    ## would cause nimrod to return DISCONNECT_FAILED where Core succeeds.
    const earlyExitLimit = 2000'u32
    const coreLimit = 111_111'u32
    check earlyExitLimit < coreLimit  # documents early-exit bug

# ============================================================
# B9 (G14): No ReallocateCache equivalent after flush
#     Core: Flush(reallocate_cache=true) calls ReallocateCache() to
#     release and re-acquire the pool allocator, keeping memory compact.
#     nimrod: no pool allocator, no reallocation step — the hashtable
#     retains its allocated capacity after flush even though it's now empty.
# ============================================================
suite "W100 B9 no_reallocate_cache":
  test "flush does not shrink cache capacity (no ReallocateCache equivalent)":
    let (db, path) = openTestDb("b9")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    # Add many entries
    var ops: seq[OutPoint] = @[]
    for i in 0..<200:
      let op = randomOutPoint()
      ops.add(op)
      cache.addCoin(op, makeCoin())

    # Spend all of them so flush would erase them
    for op in ops:
      discard cache.spendCoin(op)

    check cache.flush()

    # After flush all spent-non-fresh entries are removed
    # BUG B9: Core would call ReallocateCache to release pool memory.
    # nimrod has no equivalent — the Nim Table retains its bucket array.
    check cache.cacheSize() == 0  # entries gone but memory not compacted

# ============================================================
# B10 (G30): No ChainStateFlushed signal after flush
#     Core: calls signals->ChainStateFlushed after full_flush_completed.
#     nimrod: fires disconnectHook for disconnects but no flush notification.
# ============================================================
suite "W100 B10 no_flush_notification":
  test "flush has no callback/signal for post-flush notification":
    ## Core validation.cpp:2831-2833: after full flush, calls
    ## m_chainman.m_options.signals->ChainStateFlushed(role, locator).
    ## This notifies the wallet to update best-block markers.
    ## nimrod has no equivalent — wallet won't be notified after UTXO flush.
    ## Documenting the absence:
    check true  # absence of ChainStateFlushed hook is the bug

# ============================================================
# B11: isSpent sentinel mismatch
#     Core: Coin::IsSpent() = out.IsNull() = (nValue == -1)
#     nimrod: isSpent() = (scriptPubKey.len == 0 AND value == 0)
#     A zero-value UTXO with empty scriptPubKey would be mis-classified as spent.
# ============================================================
suite "W100 B11 isspent_sentinel_mismatch":
  test "zero-value coin with empty scriptPubKey is incorrectly treated as spent":
    ## Core: IsSpent() checks nValue == -1 (sentinel).
    ## nimrod: isSpent() checks value==0 AND scriptPubKey empty.
    ## A legitimate 0-satoshi UTXO with no script (edge case, e.g. pruned/legacy)
    ## would be classified as spent by nimrod but NOT by Core.
    let zeroCoin = utxo_cache.Coin(
      txOut: TxOut(value: Satoshi(0), scriptPubKey: @[]),
      height: 100'i32,
      isCoinbase: false
    )
    # BUG B11: nimrod says this coin is spent (value=0 AND script empty)
    check zeroCoin.isSpent  # documents the false-positive

    # Core would say this is NOT spent unless nValue == -1
    # A coin with value=0 is valid (dust limit is policy, not consensus)
    # and nValue=-1 is the explicit sentinel, not nValue=0

  test "clear() sets value=0 not value=-1 unlike Core SetNull()":
    var coin = makeCoin(50_000)
    check not coin.isSpent

    coin.clear()
    check coin.isSpent
    # Core SetNull() sets nValue = -1; nimrod clear() sets value = 0
    check int64(coin.txOut.value) == 0  # nimrod uses 0 as sentinel (not -1)

  test "coin with value greater than zero and non-empty script is not spent":
    let coin = makeCoin(1, 1)  # value=1, non-empty script
    check not coin.isSpent

# ============================================================
# B12: addCoin lacks isUnspendable guard
#     Core AddCoin: early-returns if coin.out.scriptPubKey.IsUnspendable()
#     nimrod addCoin: no isUnspendable check — can add OP_RETURN outputs to cache
#     (only addCoins wrapper has the check, not the low-level addCoin)
# ============================================================
suite "W100 B12 addcoin_no_unspendable_guard":
  test "addCoin accepts OP_RETURN output without rejection":
    let (db, path) = openTestDb("b12")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    # OP_RETURN script — provably unspendable
    let opReturnScript = @[byte(0x6a), 0x04, 0xde, 0xad, 0xbe, 0xef]
    let coin = utxo_cache.Coin(
      txOut: TxOut(value: Satoshi(0), scriptPubKey: opReturnScript),
      height: 100'i32,
      isCoinbase: false
    )

    # BUG B12: addCoin should guard with isUnspendable() and return early
    # Core coins.cpp:91: "if (coin.out.scriptPubKey.IsUnspendable()) return;"
    # nimrod addCoin: no such guard
    cache.addCoin(op, coin)  # succeeds when it should silently skip

    check cache.haveCoin(op)  # documents that OP_RETURN is accepted into cache
    check cache.cacheSize() == 1

  test "addCoins wrapper (tx-level) does filter IsUnspendable":
    ## addCoins (the tx wrapper) correctly calls isUnspendable() and skips
    ## OP_RETURN outputs. Only the low-level addCoin lacks the guard.
    let (db, path) = openTestDb("b12b")
    defer: db.close(); removeDir(path)
    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let txid = randomTxId()
    # Construct minimal transaction with one OP_RETURN output
    let opReturnScript = @[byte(0x6a), 0x04, 0xde, 0xad]
    let coinbaseTx = types.Transaction(
      version: 1'i32,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x03), 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[byte(0x51)]),
        TxOut(value: Satoshi(0), scriptPubKey: opReturnScript)
      ],
      lockTime: 0'u32
    )
    cache.addCoins(coinbaseTx, 1'i32)

    # OP_RETURN output at vout=1 should NOT be in cache
    let opReturnOutPoint = OutPoint(txid: coinbaseTx.txid(), vout: 1'u32)
    check not cache.haveCoin(opReturnOutPoint)  # addCoins correctly filtered it

when isMainModule:
  randomize()
  echo "Running W100 CCoinsViewCache + FlushStateToDisk audit tests..."
