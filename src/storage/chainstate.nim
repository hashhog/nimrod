## Chainstate management
## Tracks UTXO set and blockchain state

import std/[options, tables]
import ./rocksdb
import ../primitives/[types, serialize]
import ../crypto/hashing

type
  ChainStateError* = object of CatchableError

  Utxo* = object
    value*: Satoshi
    scriptPubKey*: seq[byte]
    height*: int
    coinbase*: bool

  ChainState* = ref object
    db*: Database
    bestBlockHash*: BlockHash
    bestHeight*: int
    utxoCache*: Table[string, Utxo]  # In-memory cache

proc utxoCacheKey(txid: TxId, vout: uint32): string =
  result = ""
  for b in array[32, byte](txid):
    result.add(char(b))
  result.add(char((vout shr 24) and 0xff))
  result.add(char((vout shr 16) and 0xff))
  result.add(char((vout shr 8) and 0xff))
  result.add(char(vout and 0xff))

proc serializeUtxo(utxo: Utxo): seq[byte] =
  var w = BinaryWriter()
  w.writeInt64LE(int64(utxo.value))
  w.writeVarBytes(utxo.scriptPubKey)
  w.writeInt32LE(int32(utxo.height))
  w.writeUint8(if utxo.coinbase: 1 else: 0)
  w.data

proc deserializeUtxo(data: seq[byte]): Utxo =
  var r = BinaryReader(data: data, pos: 0)
  result.value = Satoshi(r.readInt64LE())
  result.scriptPubKey = r.readVarBytes()
  result.height = int(r.readInt32LE())
  result.coinbase = r.readUint8() != 0

proc openChainState*(path: string): ChainState =
  result = ChainState(
    db: openDatabase(path),
    bestBlockHash: BlockHash(default(array[32, byte])),
    bestHeight: -1,
    utxoCache: initTable[string, Utxo]()
  )

  # Load best block from db
  let bestHashData = result.db.get(metaKey("bestblock"))
  if bestHashData.isSome:
    var hash: array[32, byte]
    copyMem(addr hash[0], addr bestHashData.get()[0], 32)
    result.bestBlockHash = BlockHash(hash)

  let heightData = result.db.get(metaKey("height"))
  if heightData.isSome:
    var r = BinaryReader(data: heightData.get(), pos: 0)
    result.bestHeight = int(r.readInt32LE())

proc close*(cs: ChainState) =
  cs.db.close()

proc getUtxo*(cs: ChainState, txid: TxId, vout: uint32): Option[Utxo] =
  let cacheKey = utxoCacheKey(txid, vout)

  # Check cache first
  if cacheKey in cs.utxoCache:
    return some(cs.utxoCache[cacheKey])

  # Check database
  let key = utxoKey(array[32, byte](txid), vout)
  let data = cs.db.get(key)
  if data.isSome:
    let utxo = deserializeUtxo(data.get())
    cs.utxoCache[cacheKey] = utxo
    return some(utxo)

  none(Utxo)

proc addUtxo*(cs: ChainState, txid: TxId, vout: uint32, utxo: Utxo) =
  let cacheKey = utxoCacheKey(txid, vout)
  cs.utxoCache[cacheKey] = utxo

  let key = utxoKey(array[32, byte](txid), vout)
  cs.db.put(key, serializeUtxo(utxo))

proc removeUtxo*(cs: ChainState, txid: TxId, vout: uint32) =
  let cacheKey = utxoCacheKey(txid, vout)
  cs.utxoCache.del(cacheKey)

  let key = utxoKey(array[32, byte](txid), vout)
  cs.db.delete(key)

proc hasUtxo*(cs: ChainState, txid: TxId, vout: uint32): bool =
  cs.getUtxo(txid, vout).isSome

proc updateBestBlock*(cs: ChainState, hash: BlockHash, height: int) =
  cs.bestBlockHash = hash
  cs.bestHeight = height

  cs.db.put(metaKey("bestblock"), @(array[32, byte](hash)))

  var w = BinaryWriter()
  w.writeInt32LE(int32(height))
  cs.db.put(metaKey("height"), w.data)

proc storeBlock*(cs: ChainState, blk: Block, height: int) =
  let headerBytes = serialize(blk.header)
  let hash = doubleSha256(headerBytes)

  # Store block data
  cs.db.put(blockKey(hash), serialize(blk))

  # Store height -> hash index
  cs.db.put(blockIndexKey(height), @hash)

proc getBlockByHeight*(cs: ChainState, height: int): Option[Block] =
  let hashData = cs.db.get(blockIndexKey(height))
  if hashData.isNone:
    return none(Block)

  var hash: array[32, byte]
  copyMem(addr hash[0], addr hashData.get()[0], 32)

  let blockData = cs.db.get(blockKey(hash))
  if blockData.isNone:
    return none(Block)

  some(deserializeBlock(blockData.get()))

proc getBlockByHash*(cs: ChainState, hash: BlockHash): Option[Block] =
  let blockData = cs.db.get(blockKey(array[32, byte](hash)))
  if blockData.isNone:
    return none(Block)

  some(deserializeBlock(blockData.get()))
