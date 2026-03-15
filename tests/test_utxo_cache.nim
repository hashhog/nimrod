## Tests for multi-layer UTXO cache
## Covers CoinsViewDB, CoinsViewCache, dirty/fresh flags, and flush behavior

import std/[os, options, random]
import unittest2
import ../src/storage/utxo_cache
import ../src/storage/db
import ../src/primitives/types
import ../src/primitives/serialize

# Re-export Coin type from utxo_cache
type MyCoin = utxo_cache.Coin

proc randomTxId(): TxId =
  var bytes: array[32, byte]
  for i in 0..<32:
    bytes[i] = byte(rand(255))
  TxId(bytes)

proc randomOutPoint(): OutPoint =
  OutPoint(txid: randomTxId(), vout: uint32(rand(10)))

proc testCoin(value: int64 = 100000, height: int32 = 100, coinbase: bool = false): utxo_cache.Coin =
  utxo_cache.Coin(
    txOut: TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x76), 0xa9, 0x14]),
    height: height,
    isCoinbase: coinbase
  )

proc createTestDb(name: string): Database =
  let path = getTempDir() / "nimrod_test_" & name & "_" & $rand(999999)
  openDatabase(path)

proc cleanupTestDb(db: Database, path: string) =
  db.close()
  removeDir(path)

suite "utxo_cache":
  test "coin serialization roundtrip":
    let coin = testCoin(50000, 500, true)
    let data = serializeCoin(coin)
    let decoded = deserializeCoin(data)

    check decoded.txOut.value == coin.txOut.value
    check decoded.height == coin.height
    check decoded.isCoinbase == coin.isCoinbase
    check decoded.txOut.scriptPubKey == coin.txOut.scriptPubKey

  test "coin isSpent and clear":
    var coin = testCoin()
    check not coin.isSpent

    coin.clear()
    check coin.isSpent
    check coin.txOut.scriptPubKey.len == 0
    check int64(coin.txOut.value) == 0

  test "outpoint key encoding":
    let op = OutPoint(txid: randomTxId(), vout: 42)
    let key = coinDbKey(op)

    # Key should start with 'C' prefix
    check key[0] == byte('C')
    # Followed by 32-byte txid
    check key.len >= 34  # 1 + 32 + varint(vout)

suite "coins_view":
  test "CoinsViewDB basic operations":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let view = newCoinsViewDB(db)
    let op = randomOutPoint()
    let coin = testCoin()

    # Initially empty
    check view.getCoin(op).isNone
    check not view.haveCoin(op)

    # Put coin
    view.putCoin(op, coin)
    check view.haveCoin(op)

    let retrieved = view.getCoin(op)
    check retrieved.isSome
    check retrieved.get().height == coin.height
    check retrieved.get().txOut.value == coin.txOut.value

    # Delete coin
    view.deleteCoin(op)
    check not view.haveCoin(op)

  test "CoinsViewDB best block":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let view = newCoinsViewDB(db)

    var hash: array[32, byte]
    for i in 0..<32:
      hash[i] = byte(i)

    view.setBestBlock(hash)
    check view.getBestBlock() == hash

  test "CoinsViewCache get falls through to base":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Put in DB directly
    dbView.putCoin(op, coin)

    # Cache should find it via fallthrough
    check cache.haveCoin(op)
    let retrieved = cache.getCoin(op)
    check retrieved.isSome
    check retrieved.get().height == coin.height

    # Should now be cached
    check cache.haveCoinInCache(op)

  test "CoinsViewCache addCoin creates fresh entry":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Add to cache (should be dirty and fresh)
    cache.addCoin(op, coin)

    check cache.haveCoin(op)
    check cache.haveCoinInCache(op)
    check cache.dirtyCount() == 1

  test "CoinsViewCache spendCoin fresh optimization":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Add to cache (fresh)
    cache.addCoin(op, coin)
    check cache.cacheSize() == 1

    # Spend it - should be completely removed (FRESH optimization)
    var spentCoin: Option[utxo_cache.Coin]
    check cache.spendCoin(op, spentCoin)
    check spentCoin.isSome
    check spentCoin.get().height == coin.height

    # Entry should be gone entirely (fresh coins don't need to be flushed)
    check cache.cacheSize() == 0
    check not cache.haveCoin(op)

  test "CoinsViewCache spendCoin non-fresh marks dirty":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Put directly in DB (not fresh in cache)
    dbView.putCoin(op, coin)

    # Spend via cache (will fetch from DB first)
    var spentCoin: Option[utxo_cache.Coin]
    check cache.spendCoin(op, spentCoin)
    check spentCoin.isSome

    # Entry should still exist (dirty, spent, not fresh - needs flush)
    check cache.cacheSize() == 1
    check not cache.haveCoin(op)  # Spent, so not "have"

suite "flush":
  test "flush writes dirty entries to DB":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op1 = randomOutPoint()
    let op2 = randomOutPoint()
    let coin1 = testCoin(10000, 100)
    let coin2 = testCoin(20000, 200)

    # Add coins to cache
    cache.addCoin(op1, coin1)
    cache.addCoin(op2, coin2)

    # Before flush, not in DB
    check dbView.getCoin(op1).isNone
    check dbView.getCoin(op2).isNone

    # Flush
    check cache.flush()

    # After flush, should be in DB
    let db1 = dbView.getCoin(op1)
    let db2 = dbView.getCoin(op2)
    check db1.isSome
    check db2.isSome
    check db1.get().txOut.value == coin1.txOut.value
    check db2.get().txOut.value == coin2.txOut.value

  test "flush fresh+spent never touches DB":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Add and immediately spend
    cache.addCoin(op, coin)
    discard cache.spendCoin(op)

    # Flush - entry should be gone from cache (fresh optimization)
    # and never written to DB
    check cache.flush()

    # Verify not in DB
    check dbView.getCoin(op).isNone

  test "flush spent non-fresh deletes from DB":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    # Put in DB first
    dbView.putCoin(op, coin)
    check dbView.haveCoin(op)

    # Spend via cache
    discard cache.spendCoin(op)

    # Flush should delete from DB
    check cache.flush()

    # Verify deleted from DB
    check not dbView.haveCoin(op)

  test "flush updates best block":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    var hash: array[32, byte]
    for i in 0..<32:
      hash[i] = byte(i + 10)

    cache.setBestBlock(hash)
    check cache.flush()

    check dbView.getBestBlock() == hash

  test "sync preserves cache contents":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    cache.addCoin(op, coin)
    check cache.sync()

    # Should still be in cache
    check cache.haveCoinInCache(op)
    check cache.dirtyCount() == 0  # But no longer dirty

  test "reset discards changes":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op = randomOutPoint()
    let coin = testCoin()

    cache.addCoin(op, coin)
    cache.reset()

    check cache.cacheSize() == 0
    check not cache.haveCoin(op)

  test "stacked cache flushes to parent":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache1 = newCoinsViewCache(dbView)
    let cache2 = newCoinsViewCache(cache1)

    let op = randomOutPoint()
    let coin = testCoin()

    # Add to top cache
    cache2.addCoin(op, coin)
    check cache2.haveCoin(op)
    check not cache1.haveCoinInCache(op)

    # Flush cache2 -> cache1
    check cache2.flush()
    check cache1.haveCoinInCache(op)

    # Flush cache1 -> DB
    check cache1.flush()
    check dbView.haveCoin(op)

  test "memory tracking":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView, maxCacheSize = 1024)  # 1KB limit

    let initialMem = cache.dynamicMemoryUsage()

    # Add coins until we should flush
    for i in 0..<100:
      let op = randomOutPoint()
      let coin = testCoin()
      cache.addCoin(op, coin)

      if cache.shouldFlush():
        break

    # Memory should have increased
    check cache.dynamicMemoryUsage() > initialMem

  test "uncache removes non-dirty entries":
    let path = getTempDir() / "nimrod_test_db_" & $rand(999999)
    let db = openDatabase(path)
    defer:
      db.close()
      removeDir(path)

    let dbView = newCoinsViewDB(db)
    let cache = newCoinsViewCache(dbView)

    let op1 = randomOutPoint()
    let op2 = randomOutPoint()
    let coin = testCoin()

    # Put op1 in DB (will be non-dirty when cached)
    dbView.putCoin(op1, coin)

    # Add op2 to cache (will be dirty)
    cache.addCoin(op2, coin)

    # Fetch op1 to cache it
    discard cache.getCoin(op1)

    check cache.haveCoinInCache(op1)
    check cache.haveCoinInCache(op2)

    # Uncache op1 (non-dirty) - should work
    cache.uncache(op1)
    check not cache.haveCoinInCache(op1)

    # Uncache op2 (dirty) - should not remove
    cache.uncache(op2)
    check cache.haveCoinInCache(op2)

when isMainModule:
  randomize()
  echo "Running utxo_cache tests..."
