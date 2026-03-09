## RocksDB wrapper for persistent storage
## Uses nimcrypto's rocksdb bindings

import std/[os, options]
import rocksdb

type
  RocksDbError* = object of CatchableError

  Database* = ref object
    db: RocksDbReadWriteRef
    path: string

  WriteBatch* = ref object
    batch: rocksdb.WriteBatchRef

proc openDatabase*(path: string): Database =
  ## Open or create a RocksDB database
  createDir(path)
  let res = openRocksDb(path)
  if res.isErr:
    raise newException(RocksDbError, "failed to open database: " & $res.error)
  result = Database(db: res.value, path: path)

proc close*(db: Database) =
  if db.db != nil:
    db.db.close()

proc get*(db: Database, key: openArray[byte]): Option[seq[byte]] =
  let res = db.db.get(key)
  if res.isOk:
    if res.value.len > 0:
      return some(res.value)
  none(seq[byte])

proc put*(db: Database, key, value: openArray[byte]) =
  let res = db.db.put(key, value)
  if res.isErr:
    raise newException(RocksDbError, "put failed: " & $res.error)

proc delete*(db: Database, key: openArray[byte]) =
  let res = db.db.delete(key)
  if res.isErr:
    raise newException(RocksDbError, "delete failed: " & $res.error)

proc contains*(db: Database, key: openArray[byte]): bool =
  db.get(key).isSome

proc newWriteBatch*(db: Database): WriteBatch =
  WriteBatch(batch: db.db.openWriteBatch())

proc put*(batch: WriteBatch, key, value: openArray[byte]) =
  batch.batch.put(key, value)

proc delete*(batch: WriteBatch, key: openArray[byte]) =
  batch.batch.delete(key)

proc write*(db: Database, batch: WriteBatch) =
  let res = db.db.write(batch.batch)
  if res.isErr:
    raise newException(RocksDbError, "batch write failed: " & $res.error)

proc clear*(batch: WriteBatch) =
  batch.batch.clear()

# Key prefixes for different data types
const
  PREFIX_BLOCK* = byte(0x01)
  PREFIX_BLOCK_INDEX* = byte(0x02)
  PREFIX_TX* = byte(0x03)
  PREFIX_UTXO* = byte(0x04)
  PREFIX_META* = byte(0x05)

proc blockKey*(hash: array[32, byte]): seq[byte] =
  result = @[PREFIX_BLOCK]
  result.add(hash)

proc blockIndexKey*(height: int): seq[byte] =
  result = @[PREFIX_BLOCK_INDEX]
  let h = uint32(height)
  result.add(byte((h shr 24) and 0xff))
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))

proc txKey*(txid: array[32, byte]): seq[byte] =
  result = @[PREFIX_TX]
  result.add(txid)

proc utxoKey*(txid: array[32, byte], vout: uint32): seq[byte] =
  result = @[PREFIX_UTXO]
  result.add(txid)
  result.add(byte((vout shr 24) and 0xff))
  result.add(byte((vout shr 16) and 0xff))
  result.add(byte((vout shr 8) and 0xff))
  result.add(byte(vout and 0xff))

proc metaKey*(name: string): seq[byte] =
  result = @[PREFIX_META]
  for c in name:
    result.add(byte(c))
