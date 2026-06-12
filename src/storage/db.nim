## RocksDB wrapper for persistent storage
## Uses FFI bindings via importc with column family support
##
## Performance tuning for IBD:
## - 512MB block cache for hot data
## - 64MB write buffer with 4 max buffers
## - 10-bit bloom filters on UTXO column family
## - LZ4 compression for UTXO, Snappy for blocks

import std/[os, options, cpuinfo]

export options

const LibRocksDb* = "librocksdb.so"

# Performance tuning constants
const
  BlockCacheSize* = 512 * 1024 * 1024'u64       # 512 MiB shared block cache
  WriteBufferSize* = 64 * 1024 * 1024'u64       # 64 MiB write buffer
  MaxWriteBufferNumber* = 3                      # 3 write buffers max
  BloomFilterBits* = 10                          # 10-bit bloom filter
  MaxOpenFiles* = 256                            # Limit file descriptors
  MaxBackgroundJobs* = 4                         # Background compaction jobs

type
  RocksDbError* = object of CatchableError

  # Opaque pointer types for RocksDB C API
  RocksDbPtr* = pointer
  RocksDbOptionsPtr* = pointer
  RocksDbWriteOptionsPtr* = pointer
  RocksDbReadOptionsPtr* = pointer
  RocksDbColumnFamilyHandle* = pointer
  RocksDbWriteBatchPtr* = pointer
  RocksDbIteratorPtr* = pointer
  RocksDbBlockBasedOptionsPtr* = pointer
  RocksDbCachePtr* = pointer
  RocksDbFilterPolicyPtr* = pointer

  CompressionType* = enum
    ctNone = 0
    ctSnappy = 1
    ctZlib = 2
    ctBz2 = 3
    ctLz4 = 4
    ctLz4hc = 5
    ctXpress = 6
    ctZstd = 7

# RocksDB C API bindings
{.push importc, dynlib: LibRocksDb.}
# Options
proc rocksdb_options_create*(): RocksDbOptionsPtr
proc rocksdb_options_destroy*(opts: RocksDbOptionsPtr)
proc rocksdb_options_set_create_if_missing*(opts: RocksDbOptionsPtr, v: uint8)
proc rocksdb_options_set_create_missing_column_families*(opts: RocksDbOptionsPtr, v: uint8)
proc rocksdb_options_set_prefix_extractor*(opts: RocksDbOptionsPtr, extractor: pointer)
proc rocksdb_options_increase_parallelism*(opts: RocksDbOptionsPtr, total_threads: cint)
proc rocksdb_options_optimize_level_style_compaction*(opts: RocksDbOptionsPtr, memtable_budget: uint64)
proc rocksdb_options_set_compression*(opts: RocksDbOptionsPtr, compression: cint)
proc rocksdb_options_set_write_buffer_size*(opts: RocksDbOptionsPtr, size: csize_t)
proc rocksdb_options_set_max_write_buffer_number*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_min_write_buffer_number_to_merge*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_max_background_jobs*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_level0_file_num_compaction_trigger*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_level0_slowdown_writes_trigger*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_level0_stop_writes_trigger*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_target_file_size_base*(opts: RocksDbOptionsPtr, size: uint64)
proc rocksdb_options_set_max_bytes_for_level_base*(opts: RocksDbOptionsPtr, size: uint64)
proc rocksdb_options_set_max_open_files*(opts: RocksDbOptionsPtr, num: cint)
proc rocksdb_options_set_allow_mmap_reads*(opts: RocksDbOptionsPtr, v: uint8)
proc rocksdb_options_set_block_based_table_factory*(opts: RocksDbOptionsPtr, tableOpts: RocksDbBlockBasedOptionsPtr)

# Block-based table options
proc rocksdb_block_based_options_create*(): RocksDbBlockBasedOptionsPtr
proc rocksdb_block_based_options_destroy*(opts: RocksDbBlockBasedOptionsPtr)
proc rocksdb_block_based_options_set_block_cache*(opts: RocksDbBlockBasedOptionsPtr, cache: RocksDbCachePtr)
proc rocksdb_block_based_options_set_filter_policy*(opts: RocksDbBlockBasedOptionsPtr, policy: RocksDbFilterPolicyPtr)
proc rocksdb_block_based_options_set_cache_index_and_filter_blocks*(opts: RocksDbBlockBasedOptionsPtr, v: uint8)
proc rocksdb_block_based_options_set_pin_l0_filter_and_index_blocks_in_cache*(opts: RocksDbBlockBasedOptionsPtr, v: uint8)

# Cache
proc rocksdb_cache_create_lru*(capacity: csize_t): RocksDbCachePtr
proc rocksdb_cache_destroy*(cache: RocksDbCachePtr)

# Bloom filter
proc rocksdb_filterpolicy_create_bloom*(bits_per_key: cint): RocksDbFilterPolicyPtr
proc rocksdb_filterpolicy_create_bloom_full*(bits_per_key: cint): RocksDbFilterPolicyPtr
proc rocksdb_filterpolicy_destroy*(policy: RocksDbFilterPolicyPtr)

# Read/Write options
proc rocksdb_writeoptions_create*(): RocksDbWriteOptionsPtr
proc rocksdb_writeoptions_destroy*(opts: RocksDbWriteOptionsPtr)
proc rocksdb_writeoptions_set_sync*(opts: RocksDbWriteOptionsPtr, v: uint8)
proc rocksdb_writeoptions_disable_WAL*(opts: RocksDbWriteOptionsPtr, v: cint)
proc rocksdb_readoptions_create*(): RocksDbReadOptionsPtr
proc rocksdb_readoptions_destroy*(opts: RocksDbReadOptionsPtr)
proc rocksdb_readoptions_set_verify_checksums*(opts: RocksDbReadOptionsPtr, v: uint8)
proc rocksdb_readoptions_set_fill_cache*(opts: RocksDbReadOptionsPtr, v: uint8)

# Database operations
proc rocksdb_open*(opts: RocksDbOptionsPtr, name: cstring, errptr: ptr cstring): RocksDbPtr
proc rocksdb_open_column_families*(opts: RocksDbOptionsPtr, name: cstring,
    num_column_families: cint, column_family_names: ptr cstring,
    column_family_options: ptr RocksDbOptionsPtr,
    column_family_handles: ptr RocksDbColumnFamilyHandle,
    errptr: ptr cstring): RocksDbPtr
proc rocksdb_close*(db: RocksDbPtr)
proc rocksdb_cancel_all_background_work*(db: RocksDbPtr, wait: uint8)

# Basic CRUD
proc rocksdb_put*(db: RocksDbPtr, writeOpts: RocksDbWriteOptionsPtr,
    key: cstring, keylen: csize_t, val: cstring, vallen: csize_t, errptr: ptr cstring)
proc rocksdb_get*(db: RocksDbPtr, readOpts: RocksDbReadOptionsPtr,
    key: cstring, keylen: csize_t, vallen: ptr csize_t, errptr: ptr cstring): cstring
proc rocksdb_delete*(db: RocksDbPtr, writeOpts: RocksDbWriteOptionsPtr,
    key: cstring, keylen: csize_t, errptr: ptr cstring)

# Column family CRUD
proc rocksdb_put_cf*(db: RocksDbPtr, writeOpts: RocksDbWriteOptionsPtr,
    cf: RocksDbColumnFamilyHandle, key: cstring, keylen: csize_t,
    val: cstring, vallen: csize_t, errptr: ptr cstring)
proc rocksdb_get_cf*(db: RocksDbPtr, readOpts: RocksDbReadOptionsPtr,
    cf: RocksDbColumnFamilyHandle, key: cstring, keylen: csize_t,
    vallen: ptr csize_t, errptr: ptr cstring): cstring
proc rocksdb_delete_cf*(db: RocksDbPtr, writeOpts: RocksDbWriteOptionsPtr,
    cf: RocksDbColumnFamilyHandle, key: cstring, keylen: csize_t, errptr: ptr cstring)

# Column family management
proc rocksdb_create_column_family*(db: RocksDbPtr, opts: RocksDbOptionsPtr,
    name: cstring, errptr: ptr cstring): RocksDbColumnFamilyHandle
proc rocksdb_drop_column_family*(db: RocksDbPtr, cf: RocksDbColumnFamilyHandle, errptr: ptr cstring)
proc rocksdb_column_family_handle_destroy*(cf: RocksDbColumnFamilyHandle)
proc rocksdb_list_column_families*(opts: RocksDbOptionsPtr, name: cstring,
    lencf: ptr csize_t, errptr: ptr cstring): ptr cstring
proc rocksdb_list_column_families_destroy*(list: ptr cstring, len: csize_t)

# Write batch
proc rocksdb_writebatch_create*(): RocksDbWriteBatchPtr
proc rocksdb_writebatch_destroy*(batch: RocksDbWriteBatchPtr)
proc rocksdb_writebatch_clear*(batch: RocksDbWriteBatchPtr)
proc rocksdb_writebatch_put*(batch: RocksDbWriteBatchPtr,
    key: cstring, keylen: csize_t, val: cstring, vallen: csize_t)
proc rocksdb_writebatch_put_cf*(batch: RocksDbWriteBatchPtr,
    cf: RocksDbColumnFamilyHandle, key: cstring, keylen: csize_t,
    val: cstring, vallen: csize_t)
proc rocksdb_writebatch_delete*(batch: RocksDbWriteBatchPtr,
    key: cstring, keylen: csize_t)
proc rocksdb_writebatch_delete_cf*(batch: RocksDbWriteBatchPtr,
    cf: RocksDbColumnFamilyHandle, key: cstring, keylen: csize_t)
proc rocksdb_write*(db: RocksDbPtr, writeOpts: RocksDbWriteOptionsPtr,
    batch: RocksDbWriteBatchPtr, errptr: ptr cstring)

# Flush options (force memtable -> SST)
proc rocksdb_flushoptions_create*(): pointer
proc rocksdb_flushoptions_destroy*(opts: pointer)
proc rocksdb_flushoptions_set_wait*(opts: pointer, v: uint8)
proc rocksdb_flush_cf*(db: RocksDbPtr, flushOpts: pointer,
    cf: RocksDbColumnFamilyHandle, errptr: ptr cstring)

# Iterator API (used by chainstate scrub + future cursor-driven snapshot)
proc rocksdb_create_iterator_cf*(db: RocksDbPtr, readOpts: RocksDbReadOptionsPtr,
    cf: RocksDbColumnFamilyHandle): RocksDbIteratorPtr
proc rocksdb_iter_destroy*(it: RocksDbIteratorPtr)
proc rocksdb_iter_seek_to_first*(it: RocksDbIteratorPtr)
proc rocksdb_iter_seek_to_last*(it: RocksDbIteratorPtr)
proc rocksdb_iter_next*(it: RocksDbIteratorPtr)
proc rocksdb_iter_valid*(it: RocksDbIteratorPtr): uint8
proc rocksdb_iter_key*(it: RocksDbIteratorPtr, klen: ptr csize_t): cstring
proc rocksdb_iter_value*(it: RocksDbIteratorPtr, vlen: ptr csize_t): cstring
proc rocksdb_iter_get_error*(it: RocksDbIteratorPtr, errptr: ptr cstring)

# Memory management
proc rocksdb_free*(p: pointer)
{.pop.}

type
  ColumnFamily* = enum
    cfDefault = "default"
    cfBlocks = "blocks"           # Full block data
    cfBlockIndex = "block_index"  # Height -> hash mapping
    cfUtxo = "utxo"               # UTXO set
    cfTxIndex = "tx_index"        # TxID -> block location
    cfMeta = "meta"               # Chain metadata
    cfCoinStats = "coin_stats"    # coinstatsindex: per-height MuHash + counts
                                  # (dedicated CF so its B/H/M/s/h keys never
                                  # collide with blockfilterindex's keys, which
                                  # also live in cfMeta). create_missing_column_
                                  # families=1 makes this auto-create on upgrade.
    cfTxoSpender = "txo_spender"  # txospenderindex: spent-outpoint -> spending
                                  # tx record + the base-index B/H best-block
                                  # keys. Dedicated CF for the same key-collision
                                  # reason as cfCoinStats; auto-creates on upgrade
                                  # via create_missing_column_families=1.

  Database* = ref object
    db: RocksDbPtr
    path: string
    cfHandles: array[ColumnFamily, RocksDbColumnFamilyHandle]
    dbOpts: RocksDbOptionsPtr
    writeOpts: RocksDbWriteOptionsPtr
    syncWriteOpts: RocksDbWriteOptionsPtr
      ## A SECOND write-options handle with WAL enabled + sync=1, used by
      ## `writeSynced`. The primary `writeOpts` may have its WAL disabled mid-
      ## IBD for speed (`disableWAL`); `syncWriteOpts` is never mutated, so the
      ## periodic IBD chainstate checkpoint can be made atomically crash-
      ## durable even while WAL is globally off. See `writeSynced`.
    readOpts: RocksDbReadOptionsPtr
    blockCache: RocksDbCachePtr
    bloomFilter: RocksDbFilterPolicyPtr
    cfTableOpts: array[ColumnFamily, RocksDbBlockBasedOptionsPtr]

  WriteBatch* = ref object
    batch: RocksDbWriteBatchPtr
    db: Database

  DatabaseConfig* = object
    ## Configuration for database performance tuning
    blockCacheSize*: uint64
    writeBufferSize*: uint64
    maxWriteBuffers*: int
    bloomFilterBits*: int
    useCompression*: bool
    syncWrites*: bool

proc defaultDbConfig*(): DatabaseConfig =
  ## Default performance-tuned configuration
  DatabaseConfig(
    blockCacheSize: BlockCacheSize,
    writeBufferSize: WriteBufferSize,
    maxWriteBuffers: MaxWriteBufferNumber,
    bloomFilterBits: BloomFilterBits,
    useCompression: false,
    syncWrites: false
  )

proc checkError(err: cstring) =
  if err != nil:
    let msg = $err
    rocksdb_free(err)
    raise newException(RocksDbError, msg)

proc cfNames(): array[ColumnFamily, string] =
  for cf in ColumnFamily:
    result[cf] = $cf

proc createCfOptions(config: DatabaseConfig, cf: ColumnFamily,
                      blockCache: RocksDbCachePtr,
                      bloomFilter: RocksDbFilterPolicyPtr): tuple[opts: RocksDbOptionsPtr, tableOpts: RocksDbBlockBasedOptionsPtr] =
  ## Create optimized options for each column family
  result.opts = rocksdb_options_create()
  rocksdb_options_set_create_if_missing(result.opts, 1)
  rocksdb_options_set_create_missing_column_families(result.opts, 1)

  # Set parallelism based on CPU count
  let threads = min(countProcessors(), 8)
  rocksdb_options_increase_parallelism(result.opts, cint(threads))
  rocksdb_options_set_max_background_jobs(result.opts, cint(MaxBackgroundJobs))

  # Write buffer configuration
  rocksdb_options_set_write_buffer_size(result.opts, csize_t(config.writeBufferSize))
  rocksdb_options_set_max_write_buffer_number(result.opts, cint(config.maxWriteBuffers))
  rocksdb_options_set_min_write_buffer_number_to_merge(result.opts, 2)

  # Level style compaction triggers
  rocksdb_options_set_level0_file_num_compaction_trigger(result.opts, 4)
  rocksdb_options_set_level0_slowdown_writes_trigger(result.opts, 20)
  rocksdb_options_set_level0_stop_writes_trigger(result.opts, 36)

  # Target file sizes
  rocksdb_options_set_target_file_size_base(result.opts, 64 * 1024 * 1024)  # 64MB
  rocksdb_options_set_max_bytes_for_level_base(result.opts, 256 * 1024 * 1024)  # 256MB

  # Per-CF compression settings
  case cf
  of cfUtxo:
    # LZ4 for UTXO - fast compression for frequent access
    if config.useCompression:
      rocksdb_options_set_compression(result.opts, cint(ord(ctLz4)))
  of cfBlocks:
    # LZ4 for blocks - fast compression
    if config.useCompression:
      rocksdb_options_set_compression(result.opts, cint(ord(ctLz4)))
  else:
    # LZ4 for other CFs
    if config.useCompression:
      rocksdb_options_set_compression(result.opts, cint(ord(ctLz4)))

  # Block-based table options with bloom filter and cache
  result.tableOpts = rocksdb_block_based_options_create()

  # Set block cache (shared across CFs)
  if blockCache != nil:
    rocksdb_block_based_options_set_block_cache(result.tableOpts, blockCache)

  # Bloom filter for UTXO lookups (critical for performance)
  if cf == cfUtxo and bloomFilter != nil:
    rocksdb_block_based_options_set_filter_policy(result.tableOpts, bloomFilter)
    rocksdb_block_based_options_set_cache_index_and_filter_blocks(result.tableOpts, 1)
    rocksdb_block_based_options_set_pin_l0_filter_and_index_blocks_in_cache(result.tableOpts, 1)

  rocksdb_options_set_block_based_table_factory(result.opts, result.tableOpts)

proc openDatabase*(path: string, config: DatabaseConfig = defaultDbConfig()): Database =
  ## Open or create a RocksDB database with column families
  ## Uses performance-tuned settings for IBD
  createDir(path)

  result = Database(path: path)

  # Create shared block cache (512MB default)
  result.blockCache = rocksdb_cache_create_lru(csize_t(config.blockCacheSize))

  # Create bloom filter policy (10-bit default)
  result.bloomFilter = rocksdb_filterpolicy_create_bloom_full(cint(config.bloomFilterBits))

  # Create base options
  result.dbOpts = rocksdb_options_create()
  rocksdb_options_set_create_if_missing(result.dbOpts, 1)
  rocksdb_options_set_create_missing_column_families(result.dbOpts, 1)

  let threads = min(countProcessors(), 4)
  rocksdb_options_increase_parallelism(result.dbOpts, cint(threads))
  rocksdb_options_optimize_level_style_compaction(result.dbOpts, config.writeBufferSize)
  rocksdb_options_set_max_open_files(result.dbOpts, cint(MaxOpenFiles))
  rocksdb_options_set_allow_mmap_reads(result.dbOpts, 0)  # Disable mmap to prevent RSS inflation

  # Write options
  result.writeOpts = rocksdb_writeoptions_create()
  if not config.syncWrites:
    rocksdb_writeoptions_set_sync(result.writeOpts, 0)
    rocksdb_writeoptions_disable_WAL(result.writeOpts, 0)  # Keep WAL for durability

  # Dedicated sync write options — WAL enabled + sync=1, never mutated. Used by
  # `writeSynced` so the IBD chainstate checkpoint (`flushIBDBatch`) is written
  # as ONE atomically-durable multi-CF operation even when the primary
  # `writeOpts` has had its WAL disabled for IBD throughput. Without this the
  # only durability mechanism during IBD was a per-column-family memtable flush
  # (`flushAllColumnFamilies`) whose `rocksdb_flush_cf` calls are NOT mutually
  # atomic: a crash after the UTXO CF flushed but before the meta (chain-tip)
  # CF flushed would leave the on-disk tip pointer inconsistent with the
  # on-disk UTXO set. Mirrors Bitcoin Core's CCoinsViewDB::BatchWrite, whose
  # final batch (carrying DB_BEST_BLOCK) is written synchronously.
  result.syncWriteOpts = rocksdb_writeoptions_create()
  rocksdb_writeoptions_set_sync(result.syncWriteOpts, 1)
  rocksdb_writeoptions_disable_WAL(result.syncWriteOpts, 0)

  # Read options
  result.readOpts = rocksdb_readoptions_create()
  rocksdb_readoptions_set_verify_checksums(result.readOpts, 0)  # Skip checksums for speed
  rocksdb_readoptions_set_fill_cache(result.readOpts, 1)

  var err: cstring = nil

  # Prepare column family names and per-CF options
  let cfNamesList = cfNames()
  var
    cfNamePtrs: array[ColumnFamily, cstring]
    cfOpts: array[ColumnFamily, RocksDbOptionsPtr]
    cfTableOpts: array[ColumnFamily, RocksDbBlockBasedOptionsPtr]

  for cf in ColumnFamily:
    cfNamePtrs[cf] = cstring(cfNamesList[cf])
    let (opts, tableOpts) = createCfOptions(config, cf, result.blockCache, result.bloomFilter)
    cfOpts[cf] = opts
    cfTableOpts[cf] = tableOpts

  # Store all table opts references for cleanup
  result.cfTableOpts = cfTableOpts

  # Open with column families
  result.db = rocksdb_open_column_families(
    result.dbOpts,
    cstring(path),
    cint(ord(high(ColumnFamily)) + 1),
    addr cfNamePtrs[low(ColumnFamily)],
    addr cfOpts[low(ColumnFamily)],
    addr result.cfHandles[low(ColumnFamily)],
    addr err
  )
  checkError(err)

  # Cleanup per-CF options (DB owns them now)
  for cf in ColumnFamily:
    if cfOpts[cf] != result.dbOpts:
      rocksdb_options_destroy(cfOpts[cf])

proc closeUnsafe*(db: Database) =
  ## Close only the RocksDB handle without destroying options/cache/filter.
  ## Used in crash-simulation tests where we want to abandon the DB abruptly.
  if db != nil and db.db != nil:
    rocksdb_cancel_all_background_work(db.db, 1)
    for cf in ColumnFamily:
      if db.cfHandles[cf] != nil:
        rocksdb_column_family_handle_destroy(db.cfHandles[cf])
        db.cfHandles[cf] = nil
    rocksdb_close(db.db)
    db.db = nil

proc close*(db: Database) =
  if db == nil:
    return

  # Step 1: Cancel all background compaction/flush work and wait for completion.
  # Background threads hold references to column families; destroying CF handles
  # while compaction is running triggers the ColumnFamilySet 'last_ref' assertion.
  if db.db != nil:
    rocksdb_cancel_all_background_work(db.db, 1)  # wait=1: block until done

  # Step 2: Destroy column family handles (must happen before rocksdb_close)
  for cf in ColumnFamily:
    if db.cfHandles[cf] != nil:
      rocksdb_column_family_handle_destroy(db.cfHandles[cf])
      db.cfHandles[cf] = nil

  # Step 3: Close the database (must happen before destroying options/cache/filter)
  if db.db != nil:
    rocksdb_close(db.db)
    db.db = nil

  # Step 4: Destroy options and shared resources (after DB is closed)
  if db.readOpts != nil:
    rocksdb_readoptions_destroy(db.readOpts)
    db.readOpts = nil
  if db.writeOpts != nil:
    rocksdb_writeoptions_destroy(db.writeOpts)
    db.writeOpts = nil
  if db.syncWriteOpts != nil:
    rocksdb_writeoptions_destroy(db.syncWriteOpts)
    db.syncWriteOpts = nil
  if db.dbOpts != nil:
    rocksdb_options_destroy(db.dbOpts)
    db.dbOpts = nil
  for cf in ColumnFamily:
    if db.cfTableOpts[cf] != nil:
      rocksdb_block_based_options_destroy(db.cfTableOpts[cf])
      db.cfTableOpts[cf] = nil
  if db.blockCache != nil:
    rocksdb_cache_destroy(db.blockCache)
    db.blockCache = nil
  # Note: bloomFilter is owned by cfTableOpts after set_filter_policy; do NOT destroy separately

proc get*(db: Database, cf: ColumnFamily, key: openArray[byte]): Option[seq[byte]] =
  var
    err: cstring = nil
    vallen: csize_t

  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  let data = rocksdb_get_cf(
    db.db, db.readOpts, db.cfHandles[cf],
    keyPtr, csize_t(key.len),
    addr vallen, addr err
  )
  checkError(err)

  if data != nil and vallen > 0:
    var res = newSeq[byte](vallen)
    copyMem(addr res[0], data, vallen)
    rocksdb_free(data)
    return some(res)
  elif data != nil:
    rocksdb_free(data)

  none(seq[byte])

proc get*(db: Database, key: openArray[byte]): Option[seq[byte]] =
  ## Get from default column family
  db.get(cfDefault, key)

proc put*(db: Database, cf: ColumnFamily, key, value: openArray[byte]) =
  var err: cstring = nil
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  let valPtr = if value.len > 0: cast[cstring](unsafeAddr value[0]) else: cast[cstring](nil)
  rocksdb_put_cf(
    db.db, db.writeOpts, db.cfHandles[cf],
    keyPtr, csize_t(key.len),
    valPtr, csize_t(value.len),
    addr err
  )
  checkError(err)

proc put*(db: Database, key, value: openArray[byte]) =
  ## Put to default column family
  db.put(cfDefault, key, value)

proc delete*(db: Database, cf: ColumnFamily, key: openArray[byte]) =
  var err: cstring = nil
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  rocksdb_delete_cf(
    db.db, db.writeOpts, db.cfHandles[cf],
    keyPtr, csize_t(key.len),
    addr err
  )
  checkError(err)

proc delete*(db: Database, key: openArray[byte]) =
  ## Delete from default column family
  db.delete(cfDefault, key)

proc contains*(db: Database, cf: ColumnFamily, key: openArray[byte]): bool =
  db.get(cf, key).isSome

proc contains*(db: Database, key: openArray[byte]): bool =
  db.contains(cfDefault, key)

# Write batch operations

proc newWriteBatch*(db: Database): WriteBatch =
  WriteBatch(batch: rocksdb_writebatch_create(), db: db)

proc put*(batch: WriteBatch, cf: ColumnFamily, key, value: openArray[byte]) =
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  let valPtr = if value.len > 0: cast[cstring](unsafeAddr value[0]) else: cast[cstring](nil)
  rocksdb_writebatch_put_cf(
    batch.batch, batch.db.cfHandles[cf],
    keyPtr, csize_t(key.len),
    valPtr, csize_t(value.len)
  )

proc put*(batch: WriteBatch, key, value: openArray[byte]) =
  ## Put to default column family
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  let valPtr = if value.len > 0: cast[cstring](unsafeAddr value[0]) else: cast[cstring](nil)
  rocksdb_writebatch_put(
    batch.batch,
    keyPtr, csize_t(key.len),
    valPtr, csize_t(value.len)
  )

proc delete*(batch: WriteBatch, cf: ColumnFamily, key: openArray[byte]) =
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  rocksdb_writebatch_delete_cf(
    batch.batch, batch.db.cfHandles[cf],
    keyPtr, csize_t(key.len)
  )

proc delete*(batch: WriteBatch, key: openArray[byte]) =
  ## Delete from default column family
  let keyPtr = if key.len > 0: cast[cstring](unsafeAddr key[0]) else: cast[cstring](nil)
  rocksdb_writebatch_delete(
    batch.batch,
    keyPtr, csize_t(key.len)
  )

proc write*(db: Database, batch: WriteBatch) =
  var err: cstring = nil
  rocksdb_write(db.db, db.writeOpts, batch.batch, addr err)
  checkError(err)

proc writeSynced*(db: Database, batch: WriteBatch) =
  ## Apply `batch` atomically AND crash-durably: WAL enabled + fsync, via the
  ## dedicated `syncWriteOpts` handle, regardless of whether the primary
  ## `writeOpts` currently has its WAL disabled for IBD throughput.
  ##
  ## RocksDB applies a multi-column-family WriteBatch atomically across all
  ## CFs; with sync=1 the WAL record is fsync'd before return, so the whole
  ## batch survives a crash as a unit. This is the durability primitive the
  ## periodic IBD chainstate checkpoint needs so the chain-tip pointer and the
  ## UTXO-set mutations can never be persisted out of step with each other.
  var err: cstring = nil
  rocksdb_write(db.db, db.syncWriteOpts, batch.batch, addr err)
  checkError(err)

proc clear*(batch: WriteBatch) =
  rocksdb_writebatch_clear(batch.batch)

proc destroy*(batch: WriteBatch) =
  if batch.batch != nil:
    rocksdb_writebatch_destroy(batch.batch)

proc disableWAL*(db: Database) =
  ## Disable Write-Ahead Log for faster writes during IBD
  ## Data is still durable via periodic flushes
  if db.writeOpts != nil:
    rocksdb_writeoptions_disable_WAL(db.writeOpts, 1)

proc enableWAL*(db: Database) =
  ## Re-enable Write-Ahead Log after IBD
  if db.writeOpts != nil:
    rocksdb_writeoptions_disable_WAL(db.writeOpts, 0)

proc flushAllColumnFamilies*(db: Database) =
  ## Force all column-family memtables to SST files on disk.
  ## Must be called after IBD batch writes (where WAL is disabled) to
  ## ensure durability — without this, a crash loses all memtable data.
  let flushOpts = rocksdb_flushoptions_create()
  rocksdb_flushoptions_set_wait(flushOpts, 1)  # block until flush completes
  defer: rocksdb_flushoptions_destroy(flushOpts)

  for cf in ColumnFamily:
    if db.cfHandles[cf] != nil:
      var err: cstring = nil
      rocksdb_flush_cf(db.db, flushOpts, db.cfHandles[cf], addr err)
      checkError(err)

# ============================================================================
# Iteration helpers — used by scrubunspendable to walk an entire CF.
# ============================================================================

iterator iterCf*(db: Database, cf: ColumnFamily): tuple[key: seq[byte], value: seq[byte]] =
  ## Iterate over every (key, value) pair in `cf`. Yields a copy of each
  ## entry so the caller may mutate the database while iterating (e.g. to
  ## delete the just-yielded key). Internally this snapshots the iterator
  ## by copying both buffers up front, then advances before yielding.
  let it = rocksdb_create_iterator_cf(db.db, db.readOpts, db.cfHandles[cf])
  if it == nil:
    raise newException(RocksDbError, "failed to create iterator for cf " & $cf)
  try:
    rocksdb_iter_seek_to_first(it)
    while rocksdb_iter_valid(it) != 0:
      var klen: csize_t = 0
      var vlen: csize_t = 0
      let kPtr = rocksdb_iter_key(it, addr klen)
      let vPtr = rocksdb_iter_value(it, addr vlen)
      var key = newSeq[byte](klen)
      var val = newSeq[byte](vlen)
      if klen > 0:
        copyMem(addr key[0], kPtr, klen)
      if vlen > 0:
        copyMem(addr val[0], vPtr, vlen)
      # NOTE: we do NOT free kPtr/vPtr — RocksDB owns those buffers and
      # invalidates them on the next iter_next/destroy.
      yield (key, val)
      rocksdb_iter_next(it)
    var err: cstring = nil
    rocksdb_iter_get_error(it, addr err)
    checkError(err)
  finally:
    rocksdb_iter_destroy(it)

# Key construction helpers (big-endian for ordered iteration)

proc blockKey*(hash: array[32, byte]): seq[byte] =
  ## Key for block data: just the hash
  @hash

proc blockIndexKey*(height: int32): seq[byte] =
  ## Key for height->hash mapping: big-endian height for ordered iteration
  let h = cast[uint32](height)
  result = newSeq[byte](4)
  result[0] = byte((h shr 24) and 0xff)
  result[1] = byte((h shr 16) and 0xff)
  result[2] = byte((h shr 8) and 0xff)
  result[3] = byte(h and 0xff)

proc utxoKey*(txid: array[32, byte], vout: uint32): seq[byte] =
  ## UTXO key: txid(32) || vout(4 BE)
  result = newSeq[byte](36)
  copyMem(addr result[0], unsafeAddr txid[0], 32)
  result[32] = byte((vout shr 24) and 0xff)
  result[33] = byte((vout shr 16) and 0xff)
  result[34] = byte((vout shr 8) and 0xff)
  result[35] = byte(vout and 0xff)

proc txIndexKey*(txid: array[32, byte]): seq[byte] =
  ## Key for tx index: just the txid
  @txid

proc metaKey*(name: string): seq[byte] =
  ## Key for metadata
  result = newSeq[byte](name.len)
  for i, c in name:
    result[i] = byte(c)
