## SQLite-based Wallet Storage
## Persistent storage for wallet data (keys, UTXOs, transactions)
## Uses Nim's db_sqlite module for SQLite3 bindings

import std/[os, strutils, options, json, times]
import ../primitives/types
import ../crypto/address

type
  WalletDbError* = object of CatchableError

  WalletDb* = ref object
    path*: string
    db*: pointer  # SQLite3 handle
    isOpen*: bool

  ## Stored key information
  StoredKey* = object
    path*: string
    privateKey*: array[32, byte]
    publicKey*: array[33, byte]
    chainCode*: array[32, byte]
    address*: string
    addressType*: AddressType
    isInternal*: bool
    accountIndex*: int
    keyIndex*: int

  ## Stored UTXO
  StoredUtxo* = object
    txid*: array[32, byte]
    vout*: uint32
    value*: int64
    scriptPubKey*: seq[byte]
    height*: int32
    keyPath*: string
    isInternal*: bool
    spentInTxid*: Option[array[32, byte]]  # Set when spent

  ## Wallet metadata
  WalletMeta* = object
    version*: int
    createdAt*: int64
    lastScanHeight*: int32
    network*: string
    encryptedSeed*: seq[byte]  # Encrypted master seed

# SQLite FFI bindings
{.push importc, cdecl.}

type
  Sqlite3 = distinct pointer
  Sqlite3Stmt = distinct pointer

const
  SQLITE_OK = 0
  SQLITE_ERROR = 1
  SQLITE_ROW = 100
  SQLITE_DONE = 101
  SQLITE_INTEGER = 1
  SQLITE_BLOB = 4
  SQLITE_TEXT = 3

proc sqlite3_open(filename: cstring, ppDb: ptr Sqlite3): cint
proc sqlite3_close(db: Sqlite3): cint
proc sqlite3_exec(db: Sqlite3, sql: cstring, callback: pointer, arg: pointer, errmsg: ptr cstring): cint
proc sqlite3_prepare_v2(db: Sqlite3, sql: cstring, nByte: cint, ppStmt: ptr Sqlite3Stmt, pzTail: ptr cstring): cint
proc sqlite3_step(stmt: Sqlite3Stmt): cint
proc sqlite3_finalize(stmt: Sqlite3Stmt): cint
proc sqlite3_reset(stmt: Sqlite3Stmt): cint
proc sqlite3_bind_int(stmt: Sqlite3Stmt, idx: cint, value: cint): cint
proc sqlite3_bind_int64(stmt: Sqlite3Stmt, idx: cint, value: int64): cint
proc sqlite3_bind_text(stmt: Sqlite3Stmt, idx: cint, text: cstring, n: cint, destructor: pointer): cint
proc sqlite3_bind_blob(stmt: Sqlite3Stmt, idx: cint, data: pointer, n: cint, destructor: pointer): cint
proc sqlite3_column_int(stmt: Sqlite3Stmt, iCol: cint): cint
proc sqlite3_column_int64(stmt: Sqlite3Stmt, iCol: cint): int64
proc sqlite3_column_text(stmt: Sqlite3Stmt, iCol: cint): cstring
proc sqlite3_column_blob(stmt: Sqlite3Stmt, iCol: cint): pointer
proc sqlite3_column_bytes(stmt: Sqlite3Stmt, iCol: cint): cint
proc sqlite3_column_type(stmt: Sqlite3Stmt, iCol: cint): cint
proc sqlite3_errmsg(db: Sqlite3): cstring
proc sqlite3_last_insert_rowid(db: Sqlite3): int64

{.pop.}

# Helper to convert SQLITE_TRANSIENT
let SQLITE_TRANSIENT = cast[pointer](-1)

proc checkError(db: Sqlite3, rc: cint, msg: string) =
  if rc != SQLITE_OK and rc != SQLITE_ROW and rc != SQLITE_DONE:
    let errmsg = $sqlite3_errmsg(db)
    raise newException(WalletDbError, msg & ": " & errmsg)

proc newWalletDb*(path: string): WalletDb =
  ## Create a new wallet database connection
  result = WalletDb(path: path, isOpen: false)

proc open*(wdb: var WalletDb) =
  ## Open the database and create tables if needed
  if wdb.isOpen:
    return

  let dir = wdb.path.parentDir()
  if dir != "" and not dirExists(dir):
    createDir(dir)

  var db: Sqlite3
  let rc = sqlite3_open(wdb.path.cstring, addr db)
  if rc != SQLITE_OK:
    raise newException(WalletDbError, "failed to open wallet database")

  wdb.db = cast[pointer](db)
  wdb.isOpen = true

  # Create tables
  let createTables = """
    CREATE TABLE IF NOT EXISTS wallet_meta (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_scan_height INTEGER NOT NULL DEFAULT 0,
      network TEXT NOT NULL,
      encrypted_seed BLOB
    );

    CREATE TABLE IF NOT EXISTS keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      path TEXT UNIQUE NOT NULL,
      private_key BLOB NOT NULL,
      public_key BLOB NOT NULL,
      chain_code BLOB NOT NULL,
      address TEXT NOT NULL,
      address_type INTEGER NOT NULL,
      is_internal INTEGER NOT NULL,
      account_index INTEGER NOT NULL,
      key_index INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS utxos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      txid BLOB NOT NULL,
      vout INTEGER NOT NULL,
      value INTEGER NOT NULL,
      script_pubkey BLOB NOT NULL,
      height INTEGER NOT NULL,
      key_path TEXT NOT NULL,
      is_internal INTEGER NOT NULL,
      spent_in_txid BLOB,
      UNIQUE(txid, vout)
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      txid BLOB UNIQUE NOT NULL,
      raw_tx BLOB NOT NULL,
      height INTEGER,
      block_hash BLOB,
      timestamp INTEGER NOT NULL,
      fee INTEGER,
      is_sent INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      purpose INTEGER NOT NULL,
      coin_type INTEGER NOT NULL,
      account_index INTEGER NOT NULL,
      next_external INTEGER NOT NULL DEFAULT 0,
      next_internal INTEGER NOT NULL DEFAULT 0,
      gap INTEGER NOT NULL DEFAULT 20,
      UNIQUE(purpose, coin_type, account_index)
    );

    CREATE INDEX IF NOT EXISTS idx_keys_address ON keys(address);
    CREATE INDEX IF NOT EXISTS idx_utxos_key_path ON utxos(key_path);
    CREATE INDEX IF NOT EXISTS idx_utxos_spent ON utxos(spent_in_txid);
  """

  var errmsg: cstring
  let execRc = sqlite3_exec(Sqlite3(wdb.db), createTables.cstring, nil, nil, addr errmsg)
  if execRc != SQLITE_OK:
    let msg = if errmsg != nil: $errmsg else: "unknown error"
    raise newException(WalletDbError, "failed to create tables: " & msg)

proc close*(wdb: var WalletDb) =
  ## Close the database connection
  if wdb.isOpen:
    discard sqlite3_close(Sqlite3(wdb.db))
    wdb.isOpen = false

proc initMeta*(wdb: WalletDb, network: string, encryptedSeed: seq[byte]) =
  ## Initialize wallet metadata (call once when creating new wallet)
  if not wdb.isOpen:
    raise newException(WalletDbError, "database not open")

  let db = Sqlite3(wdb.db)
  let sql = """
    INSERT OR REPLACE INTO wallet_meta (id, version, created_at, last_scan_height, network, encrypted_seed)
    VALUES (1, 1, ?, 0, ?, ?)
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  checkError(db, rc, "prepare meta insert")

  rc = sqlite3_bind_int64(stmt, 1, getTime().toUnix())
  checkError(db, rc, "bind created_at")

  rc = sqlite3_bind_text(stmt, 2, network.cstring, -1, SQLITE_TRANSIENT)
  checkError(db, rc, "bind network")

  if encryptedSeed.len > 0:
    rc = sqlite3_bind_blob(stmt, 3, addr encryptedSeed[0], cint(encryptedSeed.len), SQLITE_TRANSIENT)
  else:
    rc = sqlite3_bind_blob(stmt, 3, nil, 0, nil)
  checkError(db, rc, "bind encrypted_seed")

  rc = sqlite3_step(stmt)
  if rc != SQLITE_DONE:
    checkError(db, rc, "step meta insert")

  discard sqlite3_finalize(stmt)

proc getMeta*(wdb: WalletDb): Option[WalletMeta] =
  ## Get wallet metadata
  if not wdb.isOpen:
    return none(WalletMeta)

  let db = Sqlite3(wdb.db)
  let sql = "SELECT version, created_at, last_scan_height, network, encrypted_seed FROM wallet_meta WHERE id = 1"

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return none(WalletMeta)

  rc = sqlite3_step(stmt)
  if rc != SQLITE_ROW:
    discard sqlite3_finalize(stmt)
    return none(WalletMeta)

  var meta: WalletMeta
  meta.version = sqlite3_column_int(stmt, 0)
  meta.createdAt = sqlite3_column_int64(stmt, 1)
  meta.lastScanHeight = int32(sqlite3_column_int(stmt, 2))
  meta.network = $sqlite3_column_text(stmt, 3)

  let seedLen = sqlite3_column_bytes(stmt, 4)
  if seedLen > 0:
    let seedPtr = sqlite3_column_blob(stmt, 4)
    meta.encryptedSeed = newSeq[byte](seedLen)
    copyMem(addr meta.encryptedSeed[0], seedPtr, seedLen)

  discard sqlite3_finalize(stmt)
  some(meta)

proc updateScanHeight*(wdb: WalletDb, height: int32) =
  ## Update the last scanned block height
  if not wdb.isOpen:
    return

  let db = Sqlite3(wdb.db)
  let sql = "UPDATE wallet_meta SET last_scan_height = ? WHERE id = 1"

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  checkError(db, rc, "prepare scan height update")

  rc = sqlite3_bind_int(stmt, 1, cint(height))
  checkError(db, rc, "bind height")

  discard sqlite3_step(stmt)
  discard sqlite3_finalize(stmt)

proc saveKey*(wdb: WalletDb, key: StoredKey) =
  ## Save a derived key to the database
  if not wdb.isOpen:
    raise newException(WalletDbError, "database not open")

  let db = Sqlite3(wdb.db)
  let sql = """
    INSERT OR REPLACE INTO keys
    (path, private_key, public_key, chain_code, address, address_type, is_internal, account_index, key_index)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  checkError(db, rc, "prepare key insert")

  rc = sqlite3_bind_text(stmt, 1, key.path.cstring, -1, SQLITE_TRANSIENT)
  checkError(db, rc, "bind path")

  rc = sqlite3_bind_blob(stmt, 2, addr key.privateKey[0], 32, SQLITE_TRANSIENT)
  checkError(db, rc, "bind private_key")

  rc = sqlite3_bind_blob(stmt, 3, addr key.publicKey[0], 33, SQLITE_TRANSIENT)
  checkError(db, rc, "bind public_key")

  rc = sqlite3_bind_blob(stmt, 4, addr key.chainCode[0], 32, SQLITE_TRANSIENT)
  checkError(db, rc, "bind chain_code")

  rc = sqlite3_bind_text(stmt, 5, key.address.cstring, -1, SQLITE_TRANSIENT)
  checkError(db, rc, "bind address")

  rc = sqlite3_bind_int(stmt, 6, cint(ord(key.addressType)))
  checkError(db, rc, "bind address_type")

  rc = sqlite3_bind_int(stmt, 7, cint(if key.isInternal: 1 else: 0))
  checkError(db, rc, "bind is_internal")

  rc = sqlite3_bind_int(stmt, 8, cint(key.accountIndex))
  checkError(db, rc, "bind account_index")

  rc = sqlite3_bind_int(stmt, 9, cint(key.keyIndex))
  checkError(db, rc, "bind key_index")

  rc = sqlite3_step(stmt)
  if rc != SQLITE_DONE:
    checkError(db, rc, "step key insert")

  discard sqlite3_finalize(stmt)

proc getKeyByAddress*(wdb: WalletDb, address: string): Option[StoredKey] =
  ## Get a key by its address
  if not wdb.isOpen:
    return none(StoredKey)

  let db = Sqlite3(wdb.db)
  let sql = """
    SELECT path, private_key, public_key, chain_code, address, address_type, is_internal, account_index, key_index
    FROM keys WHERE address = ?
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return none(StoredKey)

  rc = sqlite3_bind_text(stmt, 1, address.cstring, -1, SQLITE_TRANSIENT)
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return none(StoredKey)

  rc = sqlite3_step(stmt)
  if rc != SQLITE_ROW:
    discard sqlite3_finalize(stmt)
    return none(StoredKey)

  var key: StoredKey
  key.path = $sqlite3_column_text(stmt, 0)

  let privPtr = sqlite3_column_blob(stmt, 1)
  if privPtr != nil:
    copyMem(addr key.privateKey[0], privPtr, 32)

  let pubPtr = sqlite3_column_blob(stmt, 2)
  if pubPtr != nil:
    copyMem(addr key.publicKey[0], pubPtr, 33)

  let chainPtr = sqlite3_column_blob(stmt, 3)
  if chainPtr != nil:
    copyMem(addr key.chainCode[0], chainPtr, 32)

  key.address = $sqlite3_column_text(stmt, 4)
  key.addressType = AddressType(sqlite3_column_int(stmt, 5))
  key.isInternal = sqlite3_column_int(stmt, 6) != 0
  key.accountIndex = sqlite3_column_int(stmt, 7)
  key.keyIndex = sqlite3_column_int(stmt, 8)

  discard sqlite3_finalize(stmt)
  some(key)

proc saveUtxo*(wdb: WalletDb, utxo: StoredUtxo) =
  ## Save a UTXO to the database
  if not wdb.isOpen:
    raise newException(WalletDbError, "database not open")

  let db = Sqlite3(wdb.db)
  let sql = """
    INSERT OR REPLACE INTO utxos
    (txid, vout, value, script_pubkey, height, key_path, is_internal, spent_in_txid)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  checkError(db, rc, "prepare utxo insert")

  rc = sqlite3_bind_blob(stmt, 1, addr utxo.txid[0], 32, SQLITE_TRANSIENT)
  checkError(db, rc, "bind txid")

  rc = sqlite3_bind_int(stmt, 2, cint(utxo.vout))
  checkError(db, rc, "bind vout")

  rc = sqlite3_bind_int64(stmt, 3, utxo.value)
  checkError(db, rc, "bind value")

  if utxo.scriptPubKey.len > 0:
    rc = sqlite3_bind_blob(stmt, 4, addr utxo.scriptPubKey[0], cint(utxo.scriptPubKey.len), SQLITE_TRANSIENT)
  else:
    rc = sqlite3_bind_blob(stmt, 4, nil, 0, nil)
  checkError(db, rc, "bind script_pubkey")

  rc = sqlite3_bind_int(stmt, 5, cint(utxo.height))
  checkError(db, rc, "bind height")

  rc = sqlite3_bind_text(stmt, 6, utxo.keyPath.cstring, -1, SQLITE_TRANSIENT)
  checkError(db, rc, "bind key_path")

  rc = sqlite3_bind_int(stmt, 7, cint(if utxo.isInternal: 1 else: 0))
  checkError(db, rc, "bind is_internal")

  if utxo.spentInTxid.isSome:
    let spent = utxo.spentInTxid.get()
    rc = sqlite3_bind_blob(stmt, 8, addr spent[0], 32, SQLITE_TRANSIENT)
  else:
    rc = sqlite3_bind_blob(stmt, 8, nil, 0, nil)
  checkError(db, rc, "bind spent_in_txid")

  rc = sqlite3_step(stmt)
  if rc != SQLITE_DONE:
    checkError(db, rc, "step utxo insert")

  discard sqlite3_finalize(stmt)

proc markUtxoSpent*(wdb: WalletDb, txid: array[32, byte], vout: uint32, spentInTxid: array[32, byte]) =
  ## Mark a UTXO as spent
  if not wdb.isOpen:
    return

  let db = Sqlite3(wdb.db)
  let sql = "UPDATE utxos SET spent_in_txid = ? WHERE txid = ? AND vout = ?"

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return

  rc = sqlite3_bind_blob(stmt, 1, addr spentInTxid[0], 32, SQLITE_TRANSIENT)
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_blob(stmt, 2, addr txid[0], 32, SQLITE_TRANSIENT)
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 3, cint(vout))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  discard sqlite3_step(stmt)
  discard sqlite3_finalize(stmt)

proc getUnspentUtxos*(wdb: WalletDb): seq[StoredUtxo] =
  ## Get all unspent UTXOs
  result = @[]

  if not wdb.isOpen:
    return

  let db = Sqlite3(wdb.db)
  let sql = """
    SELECT txid, vout, value, script_pubkey, height, key_path, is_internal
    FROM utxos WHERE spent_in_txid IS NULL
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return

  while true:
    rc = sqlite3_step(stmt)
    if rc != SQLITE_ROW:
      break

    var utxo: StoredUtxo

    let txidPtr = sqlite3_column_blob(stmt, 0)
    if txidPtr != nil:
      copyMem(addr utxo.txid[0], txidPtr, 32)

    utxo.vout = uint32(sqlite3_column_int(stmt, 1))
    utxo.value = sqlite3_column_int64(stmt, 2)

    let spkLen = sqlite3_column_bytes(stmt, 3)
    if spkLen > 0:
      let spkPtr = sqlite3_column_blob(stmt, 3)
      utxo.scriptPubKey = newSeq[byte](spkLen)
      copyMem(addr utxo.scriptPubKey[0], spkPtr, spkLen)

    utxo.height = int32(sqlite3_column_int(stmt, 4))
    utxo.keyPath = $sqlite3_column_text(stmt, 5)
    utxo.isInternal = sqlite3_column_int(stmt, 6) != 0

    result.add(utxo)

  discard sqlite3_finalize(stmt)

proc saveAccount*(wdb: WalletDb, purpose, coinType, accountIndex: uint32,
                   nextExternal, nextInternal, gap: int) =
  ## Save account state
  if not wdb.isOpen:
    return

  let db = Sqlite3(wdb.db)
  let sql = """
    INSERT OR REPLACE INTO accounts
    (purpose, coin_type, account_index, next_external, next_internal, gap)
    VALUES (?, ?, ?, ?, ?, ?)
  """

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return

  rc = sqlite3_bind_int(stmt, 1, cint(purpose))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 2, cint(coinType))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 3, cint(accountIndex))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 4, cint(nextExternal))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 5, cint(nextInternal))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  rc = sqlite3_bind_int(stmt, 6, cint(gap))
  if rc != SQLITE_OK:
    discard sqlite3_finalize(stmt)
    return

  discard sqlite3_step(stmt)
  discard sqlite3_finalize(stmt)

proc getTotalBalance*(wdb: WalletDb): int64 =
  ## Get total unspent balance
  if not wdb.isOpen:
    return 0

  let db = Sqlite3(wdb.db)
  let sql = "SELECT COALESCE(SUM(value), 0) FROM utxos WHERE spent_in_txid IS NULL"

  var stmt: Sqlite3Stmt
  var rc = sqlite3_prepare_v2(db, sql.cstring, -1, addr stmt, nil)
  if rc != SQLITE_OK:
    return 0

  rc = sqlite3_step(stmt)
  if rc != SQLITE_ROW:
    discard sqlite3_finalize(stmt)
    return 0

  result = sqlite3_column_int64(stmt, 0)
  discard sqlite3_finalize(stmt)
