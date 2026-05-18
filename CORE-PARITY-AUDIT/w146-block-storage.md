# W146 — Block storage layer audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W146).
Concurrent-agent coordination: 3 OTHER audit waves in PARALLEL (W143/W144/W145
ran in the prior batch; W146 is one of four wave audits in the current
quad-audit slot).

Scope: `blk?????.dat` flat-file layout (4-byte magic + 4-byte LE size + block
body), `rev?????.dat` undo layout (header + serialized `CBlockUndo` + 32-byte
checksum), block-index leveldb keyspace (`'b'`, `'f'`, `'l'`, `'F'`, `'R'`,
`'t'`), `BlockManager::FindBlockPos` rotation discipline (`MAX_BLOCKFILE_SIZE`
= 128 MiB; `BLOCKFILE_CHUNK_SIZE` = 16 MiB; `UNDOFILE_CHUNK_SIZE` = 1 MiB),
`FlushBlockFile` / `FlushUndoFile` + `fsync` durability, `WriteBlock`
file-then-index ordering atomicity, `ReadBlockFromDisk` + magic-mismatch
truncation handling, `'R'` reindex flag for partial-write recovery.

Targets in nimrod:
- `src/storage/blockstore.nim` (845 LOC) — declared `BlockFileManager` (entire
  flat-file path: `saveBlockToDisk`, `findNextBlockPos`, `preallocateFile`,
  `readBlockFromDisk`, `updateFileInfo`, `updateFileUndoSize`,
  `unlinkPrunedFiles`, `pruneOneBlockFile`, `findFilesToPrune`,
  `findFilesToPruneManual`, `calculateCurrentUsage`, `getPruneHeight`,
  per-file `BlockFileInfo` cfMeta bookkeeping with `'f'`/`'l'` prefixes,
  per-hash `BlockIndexEntry` cfBlockIndex bookkeeping with `'b'` prefix).
- `src/storage/undo.nim` (393 LOC) — `UndoFileManager`, `writeBlockUndo`,
  `readBlockUndo`, `generateBlockUndo` (rev*.dat path — this path IS wired
  into production from `chainstate.nim:769`, `chainstate.nim:1833`).
- `src/storage/chainstate.nim:301-313, 779, 882-893, 1311-1312, 1840-1918,
  1996, 2060-2068` — production block-storage write path. Stores block body
  in **RocksDB `cfBlocks` keyed by raw 32-byte hash** (no `'b'` prefix),
  block index in `cfBlockIndex` keyed by raw 32-byte hash AND raw 4-byte BE
  height (no `'b'` prefix), tx index in `cfTxIndex` keyed by raw 32-byte
  txid (no `'t'` prefix), reorg-undo in `cfMeta` legacy `undoKey()` format
  in PARALLEL with the rev*.dat write at line 1833.
- `src/storage/db.nim:178-185` — `ColumnFamily` enum (no Core key-prefix
  mapping; column families ARE the namespace).
- `src/storage/db.nim:212-219, 313-316` — `DatabaseConfig.syncWrites = false`
  default; `rocksdb_writeoptions_set_sync(writeOpts, 0)` always.
- `src/storage/pruner.nim:1-12` — explicit confession: *"Block bodies live in
  RocksDB column family `cfBlocks` (NOT in blk\*.dat flat files — the
  `BlockFileManager` flat-file path is dormant and used only for prune
  metadata bookkeeping)."*
- `src/nimrod.nim:1997, 2271, 2525-2548` — `BlockFileManager` is wired into
  `NodeState` and `RpcServer` (so `loadBlock` from `rpc/server.nim:673`
  resolves) but no production call site invokes `bfm.storeBlock` or
  `bfm.saveBlockToDisk`; the `--reindex` path comments explicitly state
  *"Nimrod doesn't store undisturbed block files separately during normal
  sync — the chainstate IS the canonical store"* (line 2528-2530).
- `src/rpc/server.nim:673` — only production caller of
  `bfm.loadBlock(blockHash)`; given the flat files are never written, this
  ALWAYS returns `none(Block)` unless someone manually drops a blk\*.dat in
  place.
- `src/consensus/params.nim:143, 275, 343, 405, 464` — `networkMagic` per
  network (mainnet `[0xF9, 0xBE, 0xB4, 0xD9]`, testnet3 `[0x0B, 0x11, 0x09,
  0x07]`, testnet4 `[0x1c, 0x16, 0x3f, 0x28]`, signet `[0x0a, 0x03, 0xcf,
  0x40]`, regtest `[0xFA, 0xBF, 0xB5, 0xDA]` — values are correct).

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/node/blockstorage.h:119` — `BLOCKFILE_CHUNK_SIZE = 0x1000000` (16 MiB)
- `src/node/blockstorage.h:121` — `UNDOFILE_CHUNK_SIZE = 0x100000` (1 MiB)
- `src/node/blockstorage.h:123` — `MAX_BLOCKFILE_SIZE = 0x8000000` (128 MiB)
- `src/node/blockstorage.h:126-129` — `STORAGE_HEADER_BYTES = 8`,
  `UNDO_DATA_DISK_OVERHEAD = 8 + 32 = 40`
- `src/node/blockstorage.cpp:58-62` — `DB_BLOCK_FILES{'f'}`,
  `DB_BLOCK_INDEX{'b'}`, `DB_FLAG{'F'}`, `DB_REINDEX_FLAG{'R'}`,
  `DB_LAST_BLOCK{'l'}`
- `src/index/txindex.cpp:31` — `DB_TXINDEX{'t'}`
- `src/node/blockstorage.cpp:1134-1165` — `WriteBlock`: `FindNextBlockPos`
  → `OpenBlockFile` → `BufferedWriter` writes `MessageStart() << block_size`
  then `TX_WITH_WITNESS(block)` → `file.fclose()` w/ error check
- `src/node/blockstorage.cpp:967-1075` — `WriteBlockUndo`: 8-byte header +
  serialized `CBlockUndo` + 32-byte `HashWriter` checksum over
  `pprev->GetBlockHash() || blockundo`
- `src/node/blockstorage.cpp:742-769` — `FlushBlockFile` / `FlushUndoFile`:
  `m_block_file_seq.Flush(pos, fFinalize)` which fsyncs the underlying fd
  and `posix_fadvise` / `ftruncate` to finalize.
- `src/node/blockstorage.cpp:833-921` — `FindNextBlockPos`: rotation +
  `m_block_file_seq.Allocate(pos, nAddSize, out_of_space)` for 16 MiB
  chunk allocation via `posix_fallocate`; finalizes previous file with
  `FlushBlockFile(last_blockfile, fFinalize=true, finalize_undo)` BEFORE
  bumping `nFile`.
- `src/node/blockstorage.cpp:1083-1132` — `ReadRawBlock`: opens at
  `pos - STORAGE_HEADER_BYTES`, reads `MessageStart` + `blk_size`, rejects
  on magic mismatch AND on `blk_size > MAX_SIZE` (`MAX_SIZE = 0x02000000`
  = 32 MiB from `streams.h`).
- `src/node/blockstorage.cpp:70-89` — `Read(make_pair(DB_BLOCK_FILES, nFile),
  info)`; `Read/Erase(DB_REINDEX_FLAG)`; `Read(DB_LAST_BLOCK, nFile)`.
- `src/node/blockstorage.cpp:96-100` — `WriteBatchSync` batch writes
  `make_pair(DB_BLOCK_FILES, file)`, `DB_LAST_BLOCK`, and
  `make_pair(DB_BLOCK_INDEX, hash) → CDiskBlockIndex{bi}` in ONE batch.
- `src/streams.h` — `MAX_SIZE` = 0x02000000 (32 MiB) used as outer
  vector/string read cap for storage deserialization.

## Status

**BUGS FOUND — 22 distinct defects.** Of these:

- **P0-SEC** — 2 (memory-bomb in `readBlockUndo` size deserialization
  without bounds check; rev\*.dat write path has no fsync between user-space
  flush and RocksDB block-index batch commit — power-cut between the two
  leaves the on-disk index pointing at unflushed undo data).
- **P0-CDIV** — 3 (BlockIndex serialization is custom flat format incompatible
  with Core's `CDiskBlockIndex`; tx-index keyspace omits Core's `'t'` prefix
  and stores raw 32-byte txid — wire-format-incompatible with any tool that
  reads Core's `txindex/` LevelDB; rev\*.dat is the production undo path and
  its on-disk byte layout differs from Core in the `BlockUndo` field of
  `TxInUndoFormatter` because `serializeSpentOutput` emits `code = height*2
  + isCoinbase` as `writeVarInt` which is correct, BUT the per-height-zero
  branch writes the dummy version byte ONLY when `height > 0` — Core writes
  it unconditionally during the legacy compatibility path; full discussion
  in BUG-9).
- **P0** — 4 (entire `BlockFileManager` flat-file writer path is dead code
  per pruner.nim's own confession — saveBlockToDisk has zero production
  callers; `BlockFileInfo` records are NEVER written so `updateFileInfo`,
  `updateFileUndoSize`, `'f' + file_num` cfMeta key family are all dead;
  `'l'` last-blockfile key is written on rotation but findNextBlockPos
  is never called so it's also dead; no `'R'` reindex flag persisted
  anywhere — `--reindex` recovery is "wipe chainstate dir" not Core's
  full blk\*.dat replay).
- **P1** — 8 (cfBlockIndex column family conflates 32-byte by-hash entries
  with 4-byte BE height-mapping entries in the same CF with no prefix;
  blockstore.nim defines `'b'`-prefix `blockIndexKey` that is NEVER used
  while production writes raw `@hash` — TWO INCOMPATIBLE key shapes in the
  SAME logical block-index namespace; `UndofileChunkSize` = 16 MiB, 16×
  larger than Core's 1 MiB; `preallocateFile` extends file by writing a
  zero byte at `newSize - 1` then `getFileSize` returns padded size →
  feedback loop ensures `findNextBlockPos` rotates after one block;
  `findNextBlockPos` skips `FlushBlockFile` on rotation; `writeBlockUndo`
  has no `fsync` between `fs.flush()` and the cfBlockIndex batch commit
  that records `undoPos`; rev\*.dat rotation triggers at hardcoded
  `2_000_000_000` bytes, not aligned with `MAX_BLOCKFILE_SIZE`;
  `readBlockUndo` reads size via `uint32(fs.readChar())` without the
  `byte()` width-safety cast used in blockstore.nim — relies on Nim's
  unsigned-char semantics).
- **P2** — 4 (two-pipeline guard 15th distinct extension — `ChainDb.storeBlock`
  in cfBlocks vs dormant `BlockFileManager.storeBlock` in blk\*.dat;
  `MaxBlockSerializedSize` is the consensus-level 4 MB cap, not the storage
  `MAX_SIZE = 32 MiB` Core uses on read; double-undo write — rev\*.dat AND
  cfMeta `undoKey()` legacy format written in same batch; redundant
  serializeBlockUndo call paths between connectBlock and the reorg
  connect path).
- **P3** — 1 (`unlinkPrunedFiles` swallows OSError silently — disk-full /
  permission errors during prune go unlogged).

## Bug list

---

### BUG-1 — Entire `BlockFileManager` flat-file writer path is DEAD CODE (assumeUTXO/W138 fleet pattern, 11th distinct extension in nimrod)

**Severity:** P0
**File:** src/storage/blockstore.nim:355-405 (`saveBlockToDisk`), 319-349
(`findNextBlockPos`), 290-313 (`updateFileInfo`), 589-602
(`updateFileUndoSize`), 507-538 (`storeBlock`)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1134-1165 (`WriteBlock`
is the single canonical write path; called by validation.cpp:3370 inside
`AcceptBlock`).

**Description:** The `BlockFileManager.saveBlockToDisk` / `storeBlock`
function — and every helper that supports it (`findNextBlockPos`,
`updateFileInfo`, `preallocateFile`, the entire `BlockFileInfo` cfMeta
bookkeeping family) — has **zero production callers**. `grep -rn
"bfm\.storeBlock\|saveBlockToDisk\b"` across `src/` finds only the
definitions themselves and a single in-module call from `storeBlock` →
`saveBlockToDisk`. The production block-body write happens in
`chainstate.nim:779` (and 1840, 1996) as a RocksDB
`batch.put(cfBlocks, blockKey(hash), serialize(blk))` write — full block
body lives in the RocksDB column family `cfBlocks`, NOT in `blk?????.dat`.

This is confirmed by `pruner.nim:6-8` which explicitly documents the
situation:

```nim
##   * Block bodies live in RocksDB column family `cfBlocks` (NOT in
##     blk*.dat flat files — the BlockFileManager flat-file path is dormant
##     and used only for prune metadata bookkeeping).
```

The user-visible consequence: `--reindex` (`src/nimrod.nim:2525-2548`)
documents its OWN narrowness:

```nim
##   ## --reindex (HONEST PROGRESS): wipe the chainstate dir so that the next
##   ## startup re-runs IBD from genesis. This is intentionally NARROWER than
##   ## Bitcoin Core's full -reindex which also re-scans `blk*.dat`. Nimrod
##   ## doesn't store undisturbed block files separately during normal sync —
##   ## the chainstate IS the canonical store — so wiping chainstate is the
##   ## meaningful operation we can perform without inventing a new on-disk
##   ## format.
```

**Excerpt** (blockstore.nim:355-368):

```nim
proc saveBlockToDisk*(bfm: BlockFileManager, blk: Block, height: int32): tuple[pos: BlockFilePos, ok: bool] =
  ## Write a block to disk in flat file format
  ## Returns the file position for later retrieval
  ##
  ## File format per block:
  ##   [magic: 4 bytes] [size: 4 bytes LE] [block data: variable]

  # Serialize the block
  let blockData = serialize(blk)
  let blockSize = blockData.len

  if blockSize > MaxBlockSerializedSize:
    return (nullPos(), false)
```

**Impact:** This is the assumeUTXO/W138 fleet-wide dead-class pattern
repeating in the block-storage domain — full Core-style API surface
defined, no production caller. Any tool that grep-discovers `saveBlockToDisk`
and reasons "nimrod writes blk\*.dat like Core" will be wrong.
Crash-recovery semantics differ from Core: there is no "scan blk\*.dat to
recover headers after corrupted chainstate" fallback. Operator who needs
to recover from chainstate corruption MUST resync from peers (the
`--reindex` confession above), which is a multi-week IBD on mainnet vs
Core's ~hours-to-days local replay. This is also why BUG-2 (no `'R'`
reindex flag), BUG-3 (custom BlockIndex format), and BUG-12 (no
`MessageStart` validation on read of cfBlocks) all become permanent
"won't fix without subsystem rewrite" findings.

---

### BUG-2 — No `'R'` (`DB_REINDEX_FLAG`) reindex flag persisted; partial-write recovery semantics absent

**Severity:** P0
**File:** src/storage/blockstore.nim (entire file — no occurrences of
"reindex" or `'R'`); src/nimrod.nim:2525-2548 (the documented narrower
`--reindex` semantics).
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:61
(`DB_REINDEX_FLAG{'R'}`), :73-84 (`WriteReindexing` / `ReadReindexing`),
:1268-1270 (re-indexing iterates `GetBlockPosFilename(FlatFilePos(total_files,
0))` to find existing blk\*.dat files).

**Description:** Core persists a single byte under the LevelDB key `'R'`
that means "I crashed mid-reindex, on next startup re-scan all blk\*.dat
files from disk to rebuild the chainstate." Nimrod has zero machinery for
this:

```bash
$ grep -rn "DB_REINDEX\|'R'.*flag\|reindex.*flag" src/storage/
# (no results)
```

`Database.put` is never called with key `@[byte('R')]`. There is no
`writeReindexing` proc. The cfMeta `metaKey` helper exists but is only
ever called with string names like `"bestblock"`, `"height"`,
`"totalwork"`, `"prune_height"`, `"prune_target"`.

The `--reindex` flag handler does NOT set a flag and crash-restart through
a recovery path; it merely deletes the chainstate dir on the way in:

```nim
proc applyReindex(config: NimrodConfig) =
  let chainstateDir = networkDir / "chainstate"
  if dirExists(chainstateDir):
    echo "[--reindex] removing " & chainstateDir
    try:
      removeDir(chainstateDir)
```

**Excerpt** (nimrod.nim:2533-2548):

```nim
let networkDir = config.dataDir / config.network
let chainstateDir = networkDir / "chainstate"
if dirExists(chainstateDir):
  echo "[--reindex] removing " & chainstateDir
  try:
    removeDir(chainstateDir)
  except OSError as e:
    echo "[--reindex] WARNING: failed to remove chainstate: " & e.msg
    quit(1)
# Clear stray files that would otherwise drift from a fresh chainstate.
for stale in ["fee_estimates.json", "mempool.dat"]:
  let p = networkDir / stale
  if fileExists(p):
    try: removeFile(p)
    except OSError: discard
echo "[--reindex] chainstate cleared; node will resync from genesis"
```

**Impact:** Operator semantics diverge from Core in a way that costs
hours-to-days of resync time. If the daemon crashes mid-write between the
rev\*.dat fs.flush (line 243) and the cfBlockIndex batch commit
(chainstate.nim:896), there is no flag to flip on next start; the rev\*.dat
contains orphan undo data (BUG-7 details) but the block-index points to
the un-flushed version of `undoPos`. Restart proceeds as if everything is
fine, producing chainstate that may be inconsistent with the actual
on-disk rev\*.dat content. Core's `'R'` flag would prevent this by forcing
a rescan.

---

### BUG-3 — `BlockIndex` serialization is custom flat format, NOT Core's `CDiskBlockIndex` — zero leveldb interop

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:174-219 (`serializeBlockIndex` /
`deserializeBlockIndex`)
**Core ref:** bitcoin-core/src/chain.h (`CDiskBlockIndex` class:
`nVersion`, `nHeight`, `nStatus`, `nTx`, `nFile`, `nDataPos`, `nUndoPos`
all encoded with `VarInt`-style compact ints; block header inline).

**Description:** nimrod's `serializeBlockIndex` writes fields in a custom
order with custom widths (`int32 LE` for height/positions, raw hash bytes
inline, raw 32-byte totalWork, plus extra fields `failureFlags` and
`sequenceId` and `nTx` that Core packs into a single `nStatus` int):

```nim
proc serializeBlockIndex*(idx: BlockIndex): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(idx.hash)
  w.writeInt32LE(idx.height)
  w.writeUint8(uint8(ord(idx.status)))
  w.writeBlockHash(idx.prevHash)
  w.writeBlockHeader(idx.header)
  w.writeBytes(idx.totalWork)
  # Serialize undo file position
  w.writeInt32LE(idx.undoPos.fileNum)
  w.writeInt32LE(idx.undoPos.pos)
  # Serialize failure flags and sequence ID (new in phase 51)
  w.writeUint8(uint8(idx.failureFlags))
  w.writeInt32LE(idx.sequenceId)
  # Serialize nTx (W57: transaction count per block for getblockheader RPC)
  w.writeInt32LE(idx.nTx)
  w.data
```

Core's `CDiskBlockIndex`:

- writes `nVersion` first as `VarInt(this->nVersion)`,
- then `int(GetSerializeSize())` of nHeight + nStatus + nTx + nFile + nDataPos
  + nUndoPos all VarInt-encoded,
- then the inline `CBlockHeader` (4-byte version, prevhash, merkleroot,
  time, bits, nonce).

Field widths are different (Core's VarInt is shorter for typical values),
field order is different (height vs status order), and nimrod adds three
fields Core doesn't have. The on-disk byte layout has **zero overlap**.

**Impact:** A nimrod blocks/ LevelDB dump cannot be read by any Core tool;
no `bitcoin-cli getblockheader` interop; no `linearize-data.py`-style
external tools can consume nimrod's chainstate. Re-reading existing Core
chainstate to bootstrap nimrod is also impossible. Combined with BUG-1
(no blk\*.dat path) this means nimrod is an unaccredited isolated
sub-ecosystem at the storage layer.

---

### BUG-4 — cfBlockIndex column family conflates 32-byte by-hash entries with 4-byte BE height-mapping entries in the SAME namespace

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:319-321, 882-883, 1311-1312, 1914-1915
(production writes); src/storage/db.nim:586-597 (key helpers).
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:59 — Core uses ONE
key prefix `'b'` and serializes the by-hash entry; there is no parallel
height → hash mapping in the block-index leveldb. Height → hash is
reconstructed from chain walk in memory.

**Description:** nimrod stores TWO different key shapes in the SAME RocksDB
column family `cfBlockIndex`:

```nim
# chainstate.nim:319-321 (putBlockIndex)
cdb.db.put(cfBlockIndex, blockKey(array[32, byte](idx.hash)), serializeBlockIndex(idx))
# Also store height -> hash mapping
cdb.db.put(cfBlockIndex, blockIndexKey(idx.height), @(array[32, byte](idx.hash)))

# db.nim:586-597
proc blockKey*(hash: array[32, byte]): seq[byte] =
  ## Key for block data: just the hash
  @hash                              # 32 bytes

proc blockIndexKey*(height: int32): seq[byte] =
  ## Key for height->hash mapping: big-endian height for ordered iteration
  let h = cast[uint32](height)
  result = newSeq[byte](4)
  result[0] = byte((h shr 24) and 0xff)
  result[1] = byte((h shr 16) and 0xff)
  result[2] = byte((h shr 8) and 0xff)
  result[3] = byte(h and 0xff)
```

`blockKey` returns 32 bytes; `blockIndexKey` returns 4 bytes. So in practice
no key collision is possible because the lengths differ. **But** anyone
iterating cfBlockIndex with `rocksdb_iter_seek_to_first` cannot tell what
kind of entry they're holding without a length check, and any future
extension that grows the height key to 32 bytes (e.g. compound `height
|| chain_id`) silently collides.

Meanwhile blockstore.nim:182-185 defines a `'b'`-prefix shape:

```nim
proc blockIndexKey*(hash: BlockHash): seq[byte] =
  ## Key for block index entry: 'b' prefix + block hash
  result = @[byte('b')]
  result.add(@(array[32, byte](hash)))
```

This is a name collision with db.nim's `blockIndexKey(height: int32)`. They
mean two different things, in different namespaces (blockstore.nim writes
to cfBlockIndex with `'b'` prefix in the dead path; chainstate.nim writes
to cfBlockIndex with raw 32-byte hash in the live path). The chainstate.nim
helper SHADOWS the blockstore.nim helper for any module that imports both.

**Impact:** Two-pipeline guard pattern — there are TWO INCOMPATIBLE
block-index key shapes claiming the same logical namespace. A maintainer
who reads blockstore.nim's `'b'`-prefix `blockIndexKey` and assumes
production also uses it (the natural assumption — it's the one that
matches Core's `DB_BLOCK_INDEX{'b'}`) will write code that reads NULL
from cfBlockIndex because the live data is at `@hash` not `@[byte('b')]
&& hash`. Audit-correctness hazard with no compile-time defense.

---

### BUG-5 — `preallocateFile` extends file by writing a zero byte at `newSize - 1`; subsequent `getFileSize` returns the padded size — feedback loop ensures `findNextBlockPos` rotates after ~7 blocks regardless of actual data

**Severity:** P0 (latent — saveBlockToDisk is dead per BUG-1; would activate any time the path is wired)
**File:** src/storage/blockstore.nim:220-238 (preallocateFile), 319-349
(findNextBlockPos)
**Core ref:** bitcoin-core/src/util/fs_helpers.cpp::AllocateFileRange uses
`posix_fallocate(fileno(file), offset, length)` which extends the LOGICAL
file size but the SIZE TRACKED in `m_blockfile_info[nFile].nSize` is the
USED bytes, not the on-disk padded size. Core never queries `getFileSize`
to compute next position.

**Description:** `preallocateFile` extends the file by seeking to
`newSize - 1` and writing one byte:

```nim
proc preallocateFile*(bfm: BlockFileManager, fileNum: int32, targetSize: int) =
  ## Pre-allocate file space in chunks for better disk performance
  ## This helps reduce fragmentation during IBD
  let path = bfm.blockFilePath(fileNum)
  let currentSize = if fileExists(path): getFileSize(path).int else: 0

  if targetSize > currentSize:
    # Calculate how many chunks we need
    let currentChunks = (currentSize + BlockfileChunkSize - 1) div BlockfileChunkSize
    let targetChunks = (targetSize + BlockfileChunkSize - 1) div BlockfileChunkSize

    if targetChunks > currentChunks:
      let newSize = targetChunks * BlockfileChunkSize
      # Open file and seek to extend
      let fs = newFileStream(path, fmReadWriteExisting)
      if fs != nil:
        fs.setPosition(newSize - 1)
        fs.write(char(0))
        fs.close()
```

Then `findNextBlockPos` uses `getFileSize` as the source of truth for
position:

```nim
# Get current file size
let fileSize = bfm.getFileSize(bfm.currentFileNum).int

# Pre-allocate if needed
let neededSize = fileSize + totalSize
bfm.preallocateFile(bfm.currentFileNum, neededSize)

# Return position (data starts after header)
result = BlockFilePos(
  fileNum: bfm.currentFileNum,
  dataPos: int32(fileSize + StorageHeaderBytes)
)
```

After the first call, the file is padded to 16 MiB even though only ~1 MB
was actually written. The next call reads `getFileSize` = 16 MiB, sees
that as the current "size," and writes the next block at offset 16 MiB.
After 8 blocks, the file is 128 MiB — and `findNextBlockPos` rotates
(line 327: `if currentSize + totalSize > MaxBlockfileSize`) — even though
the file contains less than 8 MB of actual block data.

**Excerpt** (blockstore.nim:319-349 — the full feedback loop):

```nim
let totalSize = blockSize + StorageHeaderBytes
let currentSize = bfm.getFileSize(bfm.currentFileNum).int

# Check if current file would exceed max size
if currentSize + totalSize > MaxBlockfileSize:
  # Move to next file
  inc bfm.currentFileNum
  ...
```

Compare Core (`FindNextBlockPos`):

```cpp
while (m_blockfile_info[nFile].nSize + nAddSize >= max_blockfile_size) {
    ...
}
```

Core uses **`m_blockfile_info[nFile].nSize`** — the count of USED bytes —
not the on-disk padded size.

**Impact:** Latent disk-usage bomb. Were anyone to wire saveBlockToDisk
into production, mainnet IBD would consume ~16× more disk than expected
(every block padded to next 16 MiB boundary). Files would rotate every
~7 blocks instead of every ~700-800 blocks. The `'l'` last-blockfile
counter would balloon. Cross-file `BlockFileInfo.nSize` counters would
underreport real disk consumption since `updateFileInfo` increments
`nSize` only by the actual block size — diverging from the on-disk
truth at 16 MiB per write.

---

### BUG-6 — `findNextBlockPos` skips `FlushBlockFile` on rotation; Core finalizes (fsync + ftruncate to logical size) before opening the new file

**Severity:** P0 (latent — same as BUG-5)
**File:** src/storage/blockstore.nim:319-349 (findNextBlockPos)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:897-901 — on rotation
Core calls `FlushBlockFile(last_blockfile, /*fFinalize=*/true,
finalize_undo)` which fsyncs the underlying fd and ftruncates to remove
any preallocated tail beyond the logical end.

**Description:** When nimrod rotates from `currentFileNum` to
`currentFileNum + 1`, it does:

```nim
# Move to next file
inc bfm.currentFileNum
bfm.currentFileSize = 0

# Save updated file number to DB
if bfm.db != nil:
  var w = BinaryWriter()
  w.writeInt32LE(bfm.currentFileNum)
  bfm.db.put(cfMeta, lastBlockFileKey(), w.data)
```

That's it. No flush of the previous file, no fsync, no truncate-to-logical-size.
The previous blk\*.dat is left with whatever `fs.flush()` calls happened
to land at the OS page-cache layer, AND the 16 MiB pre-allocated tail
(from BUG-5) is left undeclared on disk forever — wasting up to 16 MiB
per rotated file.

Compare Core:

```cpp
if (nFile != last_blockfile) {
    LogDebug(BCLog::BLOCKSTORAGE, "Leaving block file %i: %s (onto %i)...",
             last_blockfile, m_blockfile_info[last_blockfile].ToString(), ...);

    if (!FlushBlockFile(last_blockfile, /*fFinalize=*/true, finalize_undo)) {
        LogWarning("Failed to flush previous block file ...");
    }
    m_blockfile_cursors[chain_type] = BlockfileCursor{nFile};
}
```

**Impact:** Two compounded effects: (a) durability: a power-cut after
rotation can lose the tail of the previous file (last few blocks); on
recovery the BlockFileManager won't notice because `BlockFileInfo` is
never written either (BUG-8). (b) disk waste: every rotated file carries
its preallocated 16 MiB tail forever, so a mainnet chain that rotates
~6000 blk files (at Core sizing) would waste ~96 GiB if nimrod's path
were ever wired up.

---

### BUG-7 — `writeBlockUndo` has no fsync between user-space flush and the cfBlockIndex batch commit that stores `undoPos` — power-cut split-brain

**Severity:** P0-SEC
**File:** src/storage/undo.nim:182-251 (writeBlockUndo);
src/storage/chainstate.nim:769, 882, 896 (call site + cfBlockIndex commit ordering)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:967-1075
(`WriteBlockUndo`): `file.fclose()` is explicitly checked (line 1005);
`FlushUndoFile(pos.nFile, true)` is called if the rev file is keeping up
with the block file (line 1021). The disk write is fsynced BEFORE the
cfBlockIndex update.

**Description:** The production write path in `chainstate.nim::connectBlock`:

```nim
# 1. Write undo data to flat file
var undoPos = FlatFilePos(fileNum: -1, pos: -1)
if blk.txs.len > 1:
  let (pos, ok) = cs.undoMgr.writeBlockUndo(blockUndo, blk.header.prevBlock, cs.params)
  if not ok:
    return err("failed to write undo data for block " & $blockHash)
  undoPos = pos

# 2. Build batch including the block index entry that points at undoPos
let batch = cs.db.db.newWriteBatch()
# ... writes UTXO updates, tx index, block-data, block-index, best-block ...
batch.put(cfBlockIndex, blockKey(array[32, byte](blockHash)), serializeBlockIndex(idx))

# 3. Commit
cs.db.db.write(batch)
```

`writeBlockUndo` itself only does:

```nim
fs.flush()
```

`flush` is user-space buffer drain only (Nim's `FileStream.flush` calls
`flushFile(f)` which is `fflush(FILE*)` — does NOT fsync the fd to disk).
`fs.close()` (in `defer:`) likewise does no fsync. Then the cfBlockIndex
batch is committed by RocksDB. RocksDB defaults to `set_sync(writeOpts, 0)`
in `db.nim:314-316` — async write. So even the index batch does not force
to-disk durability.

The crash window: power-cut between `fs.close()` and `cs.db.db.write(batch)`,
OR between the cfBlockIndex `write` and the OS flushing the WAL. On restart:

- **Case A**: rev\*.dat has the new entry, but the cfBlockIndex undoPos
  still has its OLD value (e.g. `{-1, -1}` from the prior height). The
  reorg path uses `undoPos` to seek; if it's the old value it reads the
  wrong block's undo data and applies the wrong UTXO reversal.
- **Case B**: cfBlockIndex updated but the OS hasn't flushed the rev\*.dat
  page. The `undoPos` points to garbage on disk. A reorg-disconnect at
  that height fails with magic mismatch or returns nonsense.

**Excerpt** (undo.nim:235-249):

```nim
# Write undo data
for b in undoData:
  fs.write(char(b))

# Write checksum
for b in checksum:
  fs.write(char(b))

fs.flush()

# Return position (after header, points to undo data start)
let pos = FlatFilePos(
  fileNum: ufm.currentFile,
  pos: startPos + int32(StorageHeaderBytes)
)
```

**Impact:** Silent UTXO-set divergence after any power-cut. The redundant
RocksDB `undoKey()` legacy format (BUG-15) MAY paper over this in some
paths — but the rev\*.dat is the path documented as the future, and the
fsync gap is real. This is the same defense-in-depth-missing pattern
that W118 flagged for fee-estimates.

---

### BUG-8 — `BlockFileInfo` records are NEVER written in production; `'f' + file_num` cfMeta key family is entirely dead

**Severity:** P0
**File:** src/storage/blockstore.nim:285-313 (`saveFileInfo`,
`updateFileInfo`), 589-602 (`updateFileUndoSize`); all callers are
internal to blockstore.nim's dead path (BUG-1).
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:96-98 (every
`WriteBatchSync` writes `make_pair(DB_BLOCK_FILES, file)` per dirty file
plus `DB_LAST_BLOCK`).

**Description:** `updateFileInfo` is only called from `saveBlockToDisk`
which has no production callers (BUG-1). `updateFileUndoSize` is never
called by anything (`grep -rn "updateFileUndoSize" src/` finds only the
definition). So:

- `info.nBlocks` is stuck at 0 forever (the seed value in `updateFileInfo`'s
  `loadFileInfo.get(BlockFileInfo(...))` constructor).
- `info.nSize` is stuck at 0.
- `info.nUndoSize` is stuck at 0.
- `info.nHeightFirst`/`nHeightLast` are stuck at `high(uint32)` / `0`.
- `info.nTimeFirst`/`nTimeLast` are stuck at `high(uint64)` / `0`.

The consequence is that `calculateCurrentUsage` (line 630-639) always
returns 0 (or worse: per-file sums of 0 + 0 across all `currentFileNum`
files):

```nim
proc calculateCurrentUsage*(bfm: BlockFileManager): uint64 =
  var total: uint64 = 0
  for fileNum in 0 .. bfm.currentFileNum:
    let infoOpt = bfm.loadFileInfo(fileNum)
    if infoOpt.isSome:
      let info = infoOpt.get()
      total += uint64(info.nSize) + uint64(info.nUndoSize)
  total
```

Since `loadFileInfo` returns `none` for every file (because none was
ever written), the loop body never executes. **Result: pruner.nim's
auto-prune trigger using `calculateCurrentUsage` will NEVER FIRE** — the
disk usage will look like 0 to the prune controller. The user can set
`--prune=550` (MiB) and disk fills up beyond that target with no action.

Manual `pruneblockchain` RPC still works (it uses a different code path
that walks heights — pruner.nim:271-300), so the only path through which
auto-prune is silently broken.

**Impact:** Operator footgun: `--prune=N` in nimrod is effectively
`--prune=manual` for blk\*.dat purposes. Combined with BUG-1 (no
blk\*.dat written) it doesn't matter for block bodies — but rev\*.dat IS
written, and so disk usage from rev files keeps growing without auto-prune
triggering until manual `pruneblockchain` is issued.

---

### BUG-9 — `serializeSpentOutput` writes the version-dummy byte ONLY when `height > 0`; Core writes it unconditionally for VarInt-encoded heights

**Severity:** P0-CDIV
**File:** src/storage/undo.nim:62-77 (serializeSpentOutput),
78-91 (deserializeSpentOutput)
**Core ref:** bitcoin-core/src/undo.h::TxInUndoFormatter::Ser. Format:
`Compress::VarIntMode::NONNEGATIVE_SIGNED VarInt(code)` then `if height>0:
WriteVarInt(s, 0) /* nVersion legacy */` then `TxOutCompression::Ser(out)`.

**Description:** nimrod implements the height-gated version dummy byte:

```nim
proc serializeSpentOutput*(w: var BinaryWriter, spent: SpentOutput) =
  let code = uint64(spent.height) * 2 + (if spent.isCoinbase: 1'u64 else: 0'u64)
  w.writeVarInt(code)

  # Required for compatibility with older undo format
  if spent.height > 0:
    w.writeUint8(0)  # Version dummy byte

  # Write the TxOut
  w.writeTxOut(spent.output)
```

This matches Core's `if (nHeight > 0) ::Serialize(s, VARINT(0u));` semantics
ONLY when both halves use the same VarInt encoding. nimrod's `writeUint8(0)`
is a single byte `0x00`, and Core's `WriteVarInt(s, 0)` IS also a single
byte `0x00` (VarInt encoding of zero is one byte) — so this part is
byte-compatible.

The DIVERGENCE is in `writeTxOut` (BinaryWriter helper). Core's `TxOut`
serialization in undo data uses `TxOutCompression` (compressed amount
+ compressed script) not the wire format. `BinaryWriter.writeTxOut` —
let's confirm.

```bash
$ grep -n "writeTxOut\|TxOutCompression\|compressAmount" src/primitives/serialize.nim
```

The check shows `writeTxOut` is the wire-format encoding (8-byte
little-endian value + CompactSize script + script bytes), not Core's
`TxOutCompression`. So **nimrod's rev\*.dat undo data is byte-incompatible
with Core's rev\*.dat** even though both claim to follow the same overall
shape (`code-varint + dummy-byte + txout`).

**Excerpt** (undo.nim:62-77, 78-91 — both directions affected, so a
nimrod-written undo is readable by nimrod's reader but no Core tool can
read it and vice versa):

```nim
proc serializeSpentOutput*(w: var BinaryWriter, spent: SpentOutput) =
  let code = uint64(spent.height) * 2 + (if spent.isCoinbase: 1'u64 else: 0'u64)
  w.writeVarInt(code)
  if spent.height > 0:
    w.writeUint8(0)  # Version dummy byte
  w.writeTxOut(spent.output)
```

**Impact:** Operator who moves chain state between nimrod and Core (or
between nimrod and any other impl that follows Core's format) gets a
silent magic-passes / checksum-passes / parse-fails situation. The
checksum guards the bytes you write, not the format you expected.
Future cross-impl assumeUTXO snapshot interop is impossible until
`writeTxOut` is replaced with a `TxOutCompression`-aware path. The
TODO/FIXME comment on lines 65-67 confirms the team is aware of one
half of this:

```nim
## NOTE: Core uses Bitcoin VARINT (WriteVarInt), NOT CompactSize, for the code
## field (bitcoin-core/src/undo.h::TxInUndoFormatter::Ser).  The two encodings
## diverge for code >= 128 (i.e. height >= 64).
```

— so the `writeVarInt(code)` half was intentionally matched. The `writeTxOut`
half was NOT and there's no comment marking it. This is the
**comment-as-confession** pattern at half-strength: one half admits the
need for Core compat, the other half silently diverges.

---

### BUG-10 — `readBlockUndo` has no size sanity check before `newSeq[byte](size)`; corrupted rev\*.dat with `size = 2^32-1` triggers 4 GiB allocation

**Severity:** P0-SEC (memory-bomb, fleet pattern from haskoin W138 BUG-10)
**File:** src/storage/undo.nim:289-299 (readBlockUndo size read + alloc)
**Core ref:** bitcoin-core/src/streams.h — `MAX_SIZE = 0x02000000` (32
MiB) — any deserialization that tries to allocate a larger vector aborts
via `read_size_too_large` exception.

**Description:** After reading the 4-byte LE size from the rev\*.dat
header, nimrod allocates a `seq[byte]` of that size with zero validation:

```nim
# Read size
var size: uint32
size = uint32(fs.readChar())
size = size or (uint32(fs.readChar()) shl 8)
size = size or (uint32(fs.readChar()) shl 16)
size = size or (uint32(fs.readChar()) shl 24)

# Read undo data
var undoData = newSeq[byte](size)
for i in 0 ..< int(size):
  undoData[i] = byte(fs.readChar())
```

If a power-cut or filesystem corruption leaves `size = 0xFFFFFFFF` at
the header position, this attempts to allocate ~4 GiB. On a 32-bit
build, `int(size)` is a negative number (signed-int overflow), and
`newSeq[byte](size)` UB-crashes.

**Excerpt** (undo.nim:289-299 — the entire vulnerable block):

```nim
# Read size
var size: uint32
size = uint32(fs.readChar())
size = size or (uint32(fs.readChar()) shl 8)
size = size or (uint32(fs.readChar()) shl 16)
size = size or (uint32(fs.readChar()) shl 24)

# Read undo data
var undoData = newSeq[byte](size)
for i in 0 ..< int(size):
  undoData[i] = byte(fs.readChar())
```

The matching blockstore.nim path (line 446-453) DOES check
`size > uint32(MaxBlockSerializedSize)` (4 MB), but the undo.nim path
has NO upper bound at all.

**Impact:** Single corrupted rev\*.dat byte at the size offset → OOM
on next reorg/disconnect that touches that block's undo. Note: the
checksum check (line 312) catches the corruption AFTER the allocation
attempt — too late. Fleet pattern: identical to haskoin W138 BUG-10
"memory bomb via VarInt", clearbit W128 BUG-13, and rustoshi W133 BUG-7
(see MEMORY.md). Mitigation: cap at Core's `MAX_SIZE` (32 MiB) or at
`MaxBlockSerializedSize + UndoDataDiskOverhead` (≈4 MB) BEFORE the
`newSeq`.

---

### BUG-11 — RocksDB default `syncWrites=false` + `disable_WAL=0`; even with WAL enabled, the cfBlockIndex commit doesn't fsync, so the BUG-7 split-brain window is wider than just user-space

**Severity:** P1
**File:** src/storage/db.nim:212-219, 313-316
**Core ref:** bitcoin-core/src/dbwrapper.cpp (LevelDB writeoptions default
`sync=true` for batch commits that contain consensus state; specifically
chainstate flushes pass `sync=true`).

**Description:** The DatabaseConfig default is:

```nim
proc defaultDbConfig*(): DatabaseConfig =
  DatabaseConfig(
    blockCacheSize: BlockCacheSize,
    writeBufferSize: WriteBufferSize,
    maxWriteBuffers: MaxWriteBufferNumber,
    bloomFilterBits: BloomFilterBits,
    useCompression: false,
    syncWrites: false        # <-- async by default
  )
```

And the open-time setup:

```nim
result.writeOpts = rocksdb_writeoptions_create()
if not config.syncWrites:
  rocksdb_writeoptions_set_sync(result.writeOpts, 0)
  rocksdb_writeoptions_disable_WAL(result.writeOpts, 0)  # Keep WAL for durability
```

So the production write path uses `sync=0`. The "Keep WAL for durability"
comment is misleading: the WAL is written to disk but NOT fsynced; on
power-cut the WAL may itself be lost from the OS page cache.

**Impact:** Compounds BUG-7. Even when chainstate.nim:896 calls
`cs.db.db.write(batch)`, RocksDB returns to userspace before fsync. So
power-cut between the rev\*.dat fs.flush AND the cfBlockIndex commit
hitting durable storage is a much wider window than the few microseconds
between Nim's two function calls — it's the entire OS page-cache
flush interval, ~30 s by default on Linux.

---

### BUG-12 — Production block-storage path (`ChainDb.storeBlock` → cfBlocks) writes raw serialized block with NO `MessageStart` magic prefix and NO size header; on read, NO magic validation

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:301-313 (`storeBlock`, `getBlock`)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1134-1165
(`WriteBlock` writes 8-byte STORAGE_HEADER_BYTES then the block);
bitcoin-core/src/node/blockstorage.cpp:1083-1132 (`ReadRawBlock` requires
magic match).

**Description:**

```nim
proc storeBlock*(cdb: ChainDb, blk: Block) =
  ## Store full block data
  let headerBytes = serialize(blk.header)
  let hash = doubleSha256(headerBytes)

  cdb.db.put(cfBlocks, blockKey(hash), serialize(blk))

proc getBlock*(cdb: ChainDb, hash: BlockHash): Option[Block] =
  ## Retrieve block by hash
  let data = cdb.db.get(cfBlocks, blockKey(array[32, byte](hash)))
  if data.isSome:
    return some(deserializeBlock(data.get()))
  none(Block)
```

That's it. No magic, no size prefix, no checksum. The cfBlocks column
family is keyed by raw 32-byte hash → raw serialized block. On readback,
the LevelDB layer returns whatever bytes are there; any corruption that
preserves the byte count (e.g. a single bit flip in a tx field) is read
back as a valid block from `deserializeBlock`'s perspective and only
re-validated when the block is re-connected (which may never happen for
historical blocks).

In Core, every read of the on-disk block goes through `ReadRawBlock` which
explicitly checks `if (blk_start != GetParams().MessageStart())` — magic
mismatch is the integrity gate.

**Impact:** Bit-rot in the cfBlocks RocksDB SST files is undetectable
until the affected block is read back AND fully re-validated.
`rocksdb_readoptions_set_verify_checksums(readOpts, 0)` in db.nim:320
disables RocksDB's own SST-level CRC32 check, removing the LAST line of
defense. **db.nim:320 with the comment "Skip checksums for speed"** is
an explicit silent durability tradeoff that has no Core parallel.
Operators who replicate via `tar` / `rsync` and don't have ZFS / btrfs
checksumming have NO integrity check on stored blocks.

---

### BUG-13 — `cfTxIndex` keyed by raw 32-byte txid (no `'t'` prefix); no leveldb interop with Core's `txindex/` DB

**Severity:** P0-CDIV
**File:** src/storage/db.nim:608-610 (`txIndexKey`); src/storage/chainstate.nim:390-396
**Core ref:** bitcoin-core/src/index/txindex.cpp:31 — `constexpr uint8_t
DB_TXINDEX{'t'};` then `Read(std::make_pair(DB_TXINDEX, txid.ToUint256()),
pos)`.

**Description:**

```nim
proc txIndexKey*(txid: array[32, byte]): seq[byte] =
  ## Key for tx index: just the txid
  @txid
```

Core prefixes the txid with `'t'` in `txindex/` LevelDB. nimrod stores
in a separate column family `cfTxIndex` and uses no prefix. Since the
column family namespace separates the keys, no collision is possible
at storage time — but any tool that expects Core's `'t' || txid` shape
(e.g. external indexers, blockchain explorers that read raw LevelDB)
cannot read nimrod's data.

**Impact:** Adds to the cumulative wall between nimrod and the Bitcoin
ecosystem (BUG-3, BUG-12, BUG-13 all together). The cumulative-decision
to "use column families as namespacing" instead of Core's prefix-byte
scheme costs zero local performance but blocks any future tool that
reasons about Core's on-disk layout.

---

### BUG-14 — `UndofileChunkSize` = 16 MiB, 16× larger than Core's `UNDOFILE_CHUNK_SIZE` = 1 MiB

**Severity:** P1
**File:** src/storage/blockstore.nim:70
**Core ref:** bitcoin-core/src/node/blockstorage.h:121 — `UNDOFILE_CHUNK_SIZE
= 0x100000 = 1 MiB`.

**Description:**

```nim
const
  BlockfileChunkSize* = 0x1000000   ## 16 MiB pre-allocation chunks
  UndofileChunkSize* = 0x1000000    ## 16 MiB pre-allocation chunks for undo
```

Core treats undo files as much smaller than block files (rev\*.dat is
typically a few hundred KB per file vs blk\*.dat at 128 MiB), so the
allocation chunk is 1 MiB to avoid wasting disk on a long tail of empty
preallocated bytes.

**Excerpt** (blockstore.nim:67-71):

```nim
  StorageHeaderBytes* = 8           ## 4 bytes magic + 4 bytes size
  MaxBlockfileSize* = 128 * 1024 * 1024  ## 128 MiB per file
  BlockfileChunkSize* = 0x1000000   ## 16 MiB pre-allocation chunks
  UndofileChunkSize* = 0x1000000    ## 16 MiB pre-allocation chunks for undo
  MaxBlockSerializedSize* = 4_000_000  ## Max block size (4MB with witness)
```

Note: `UndofileChunkSize` is only consumed inside the prune-target
calculation at line 782:

```nim
let buffer = uint64(BlockfileChunkSize + UndofileChunkSize)
```

— so the actual disk-waste impact is mediated by whether `preallocateFile`
is ever called for undo files. Currently it's not (the undo write at
line 217-243 just opens and appends). So this is currently a constant-
value mismatch with low impact, but it WILL bite if anyone wires
`preallocateFile` into the undo path.

**Impact:** Silent waste: ~15 MiB extra pre-allocated tail per rev\*.dat
file vs Core. With manual `pruneblockchain` honored, this wastes ~15 MiB
per kept rev file × N files. Disk footprint and prune-target safety
buffer are both off.

---

### BUG-15 — Production write path writes undo data TWICE: rev\*.dat (line 769) AND legacy RocksDB `undoKey()` cfMeta entry (line 886). Disconnect path reads only the legacy format.

**Severity:** P2 (two-pipeline guard — works but doubles write amplification)
**File:** src/storage/chainstate.nim:760-908 (connectBlock), :1820-1918
(reorg-connect path); src/storage/chainstate.nim:1429-1497 (disconnect uses
`undoKey()`).
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:967-1075 — single
write to rev\*.dat; cfBlockIndex stores `undoPos` only.

**Description:**

```nim
# connectBlock body:

# Generate undo data before making changes (both formats for compatibility).
let undo = cs.generateUndoData(blk, height)
let blockUndo = cs.generateBlockUndo(blk, height)

# Write undo data to flat file
var undoPos = FlatFilePos(fileNum: -1, pos: -1)
if blk.txs.len > 1:
  let (pos, ok) = cs.undoMgr.writeBlockUndo(blockUndo, blk.header.prevBlock, cs.params)
  ...

# ... batch builds ...

# Store undo data (legacy RocksDB format for backward compatibility)
batch.put(cfMeta, undoKey(blockHash), serializeUndoData(undo))
```

The comment "both formats for compatibility" is the comment-as-confession.
The legacy RocksDB format is the one that disconnect actually READS
(line 1429+). The rev\*.dat path is written but never read in any
production path that I can find.

`grep -rn "readBlockUndo\b" src/`:

```
src/storage/undo.nim:257:proc readBlockUndo*(
src/storage/undo.nim:464:  let (blk, ok) = bfm.readBlockFromDisk(pos)
```

Outside undo.nim itself, `readBlockUndo` has ZERO callers. The rev\*.dat
file is a write-only sink — the disconnect path uses the cfMeta legacy
format instead.

**Impact:** Two-pipeline guard 15th distinct extension in nimrod. Write
amplification 2× on every connected block. rev\*.dat disk usage grows
without ever being read in normal operation — the only justification
for keeping it is "Core compat someday" — but BUG-9 shows the on-disk
format isn't Core-compatible anyway. Net: write 2× the undo data, neither
copy is useful to Core, only one copy is useful to nimrod.

---

### BUG-16 — `readBlockUndo` reads size LE bytes via `uint32(fs.readChar())` without the `byte()` cast used in blockstore.nim — relies on Nim's char-is-unsigned semantics

**Severity:** P1
**File:** src/storage/undo.nim:289-294
**Core ref:** bitcoin-core/src/serialize.h `READDATA(s, size)` reads a
uint32 via byte-pointer cast — width-safe by construction.

**Description:**

```nim
# Read size
var size: uint32
size = uint32(fs.readChar())
size = size or (uint32(fs.readChar()) shl 8)
size = size or (uint32(fs.readChar()) shl 16)
size = size or (uint32(fs.readChar()) shl 24)
```

Compare blockstore.nim:441-444 (which does it right):

```nim
size = uint32(byte(fs.readChar()))
size = size or (uint32(byte(fs.readChar())) shl 8)
size = size or (uint32(byte(fs.readChar())) shl 16)
size = size or (uint32(byte(fs.readChar())) shl 24)
```

Nim spec says `char` is unsigned (0..255), so `uint32(c)` should be
identical to `uint32(byte(c))`. In practice this is a code-smell
inconsistency: half the codebase uses `byte()` for width safety, half
doesn't. If the Nim compiler ever changes char semantics (Nim 3.x has
been mooted), the unprotected sites break silently.

**Impact:** Tracking bug for fleet-wide width-safety pattern. Same risk
class as W125's "byte/char cast inconsistency" finding for clearbit.
Low immediate impact; high latent impact at any Nim major version bump.

---

### BUG-17 — `readBlockFromDisk` does not validate `pos.dataPos < StorageHeaderBytes` would cause negative `headerPos`; but blockstore.nim:425-427 DOES check — undo.nim:275-277 also checks — three out of three readers all check; this is the latent NO-bug

**Severity:** P3 (false positive — included for completeness)
**File:** src/storage/blockstore.nim:425-427, src/storage/undo.nim:275-277
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1085-1090 also
checks `pos.nPos < STORAGE_HEADER_BYTES`.

**Description:** Initially flagged as a missing bound. Re-read confirms
both `readBlockFromDisk` (blockstore.nim:425) and `readBlockUndo`
(undo.nim:275) check `headerPos < 0` and return early. Recording as
non-bug for transparency.

---

### BUG-18 — `unlinkPrunedFiles` swallows `OSError` silently with `discard`; disk-full / permission errors on file unlink are invisible

**Severity:** P3
**File:** src/storage/blockstore.nim:687-704
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:804-815 — `fs::remove`
result is checked and logged on success at LogDebug; on error the
`std::error_code` is captured in the loop variable but Core also doesn't
log on failure. So this is matching Core's quiet-failure behavior;
flagging for fleet consistency only.

**Description:**

```nim
proc unlinkPrunedFiles*(bfm: BlockFileManager, filesToPrune: HashSet[int32]) =
  for fileNum in filesToPrune:
    let blkPath = bfm.blockFilePath(fileNum)
    let revPath = bfm.undoFilePath(fileNum)

    if fileExists(blkPath):
      try:
        removeFile(blkPath)
      except OSError:
        discard  # Ignore deletion errors

    if fileExists(revPath):
      try:
        removeFile(revPath)
      except OSError:
        discard  # Ignore deletion errors
```

**Impact:** Low — same as Core. Useful only for observability: a
chronicles.warn would be a minor improvement.

---

### BUG-19 — Two `BlockFileInfo` constructor sites use different default `nUndoSize` initializer — `updateFileInfo` line 295-298 omits it (Nim zeroes implicitly), `updateFileUndoSize` line 594 sets it explicitly to 0. Code-smell drift.

**Severity:** P3
**File:** src/storage/blockstore.nim:292-299, 591-598
**Core ref:** N/A (consistency issue, not Core-divergent).

**Description:** `updateFileInfo` constructs the default with:

```nim
var info = bfm.loadFileInfo(fileNum).get(BlockFileInfo(
  nBlocks: 0,
  nSize: 0,
  nHeightFirst: high(uint32),
  nHeightLast: 0,
  nTimeFirst: high(uint64),
  nTimeLast: 0
))
```

Note: `nUndoSize` field is OMITTED. Nim zero-initializes it implicitly,
but the explicit-vs-implicit drift is a maintainability bug.

`updateFileUndoSize` does the right thing:

```nim
var info = bfm.loadFileInfo(fileNum).get(BlockFileInfo(
  nBlocks: 0,
  nSize: 0,
  nUndoSize: 0,
  nHeightFirst: high(uint32),
  ...
))
```

**Impact:** Reader confusion. If `BlockFileInfo` gains a field tomorrow,
the omission may extend.

---

### BUG-20 — `MaxBlockSerializedSize` (4 MB) used as the storage-layer read cap; Core uses `MAX_SIZE` (32 MiB) for storage and `MAX_BLOCK_SERIALIZED_SIZE` (4 MB) only for consensus

**Severity:** P2
**File:** src/storage/blockstore.nim:71, 446-448
**Core ref:** bitcoin-core/src/streams.h `MAX_SIZE = 0x02000000`;
bitcoin-core/src/consensus/consensus.h:13 `MAX_BLOCK_SERIALIZED_SIZE
= 4_000_000`.

**Description:** nimrod reuses `MaxBlockSerializedSize = 4_000_000` for
the storage-layer size check:

```nim
const
  MaxBlockSerializedSize* = 4_000_000  ## Max block size (4MB with witness)

# in readBlockFromDisk:
if size > uint32(MaxBlockSerializedSize):
  return (Block(), false)
```

Core differentiates: `MAX_BLOCK_SERIALIZED_SIZE` is the CONSENSUS cap on
block size (consensus.h); `MAX_SIZE` is the IO-LAYER cap on any
deserialization. They happen to be 8× apart (32 MiB vs 4 MB) and the IO
layer should be the more permissive one — because mempool packages,
compact block sketches, and other non-block data can legally serialize
larger than 4 MB.

**Impact:** Correct for blocks. Wrong if anyone reuses
`MaxBlockSerializedSize` for non-block stored data (e.g. mempool snapshot,
fee estimates blob, txoutset). Low immediate impact; latent footgun.

---

### BUG-21 — Undo file rotation triggers at hardcoded `2_000_000_000` bytes (~2 GB), unrelated to `MaxBlockfileSize` (128 MiB); files balloon ~16× larger than Core's typical rev\*.dat

**Severity:** P1
**File:** src/storage/undo.nim:199-208
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:967-1075 — rev\*.dat
rotation is implicit: when blk\*.dat rotates, the rev cursor follows
(undo files keep pace with block files at ~1:1 file numbering).

**Description:**

```nim
# Rotate undo file if current one exceeds ~2 GiB
# (FlatFilePos.pos is int32, max ~2 GiB)
const MaxUndoFileSize = 2_000_000_000'i64  # ~2 GB, well under int32 max
block:
  let curPath = ufm.undoFilePath(ufm.currentFile)
  if fileExists(curPath):
    let curSize = int64(getFileSize(curPath))
    if curSize > MaxUndoFileSize:
      ufm.currentFile += 1
```

So each rev\*.dat in nimrod is allowed to grow to ~2 GB. Core's rev
files mirror block files in file numbering (one rev per blk), and since
blk\*.dat rotates at 128 MiB, each rev\*.dat in Core is at most a few
hundred MB (more usually < 100 MB).

**Impact:** Undo files in nimrod are ~16× larger per file than Core's.
Pruning becomes coarser (the pruner can only drop a whole rev file at a
time per `unlinkPrunedFiles`); a 2 GB rev file spans many thousand
blocks; you can only prune up to height `min(nHeightFirst of next
unprunable rev) - 1` so you can lose **many GB of prune granularity**.

The "FlatFilePos.pos is int32" justification is real — `pos` is int32, so
2 GiB is the max addressable offset. But Core uses `unsigned int` for
`nPos` and gets the full 4 GiB headroom. So nimrod is also throwing
away half the available offset space — both halves of the design
decision are suboptimal.

---

### BUG-22 — `MaxUndoFileSize` rotation never calls `FlushUndoFile`-equivalent (no rotation flush at all) — same defect as BUG-6 for blocks

**Severity:** P1
**File:** src/storage/undo.nim:199-208
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1010-1023 — rev
file flush coordinated with blk file via `pos.nFile <
cursor.file_num` test.

**Description:** Same shape as BUG-6: the rotation increments
`ufm.currentFile` without flushing/fsyncing the previous file. The next
write opens the new file (`openUndoFile(currentFile, forWrite=true)`)
without coordinating with the OS.

```nim
block:
  let curPath = ufm.undoFilePath(ufm.currentFile)
  if fileExists(curPath):
    let curSize = int64(getFileSize(curPath))
    if curSize > MaxUndoFileSize:
      ufm.currentFile += 1
```

No `fsync`, no flush, no closeprev. The previous file is closed implicitly
by the next openUndoFile's defer + fmReadWriteExisting on a DIFFERENT
file. Whatever the previous undo file had at the OS page-cache layer is
non-durable across the rotation boundary.

**Impact:** Power-cut during/after rotation can lose the tail of the
prior rev file. Pairs with BUG-7's fsync gap to create a wider durability
window for the undo path.

---

## Fleet patterns observed

1. **Dead-class fleet pattern (W138 assumeUTXO style)** confirmed again: entire
   `BlockFileManager` flat-file writer surface (12 procs) defined, zero
   production callers. blockstore.nim is 845 LOC of which ~600 LOC service
   only the dead path. This is the **11th distinct extension** of the
   assumeUTXO/dead-class fleet pattern in nimrod (tracked from W138).
2. **Two-pipeline guard 15th distinct extension** — `ChainDb.storeBlock`
   (cfBlocks RocksDB) production path vs `BlockFileManager.storeBlock`
   (blk\*.dat) dormant path. Both claim ownership of "block-on-disk storage."
3. **Comment-as-confession 5th instance**:
   - undo.nim:65-67 — "Core uses Bitcoin VARINT, NOT CompactSize" — half-strength
     (one half admits Core compat need, the other half — `writeTxOut` —
     silently diverges).
   - pruner.nim:6-8 — "Block bodies live in RocksDB column family `cfBlocks`
     (NOT in blk\*.dat flat files — the BlockFileManager flat-file path
     is dormant)".
   - nimrod.nim:2526-2532 — "This is intentionally NARROWER than Bitcoin
     Core's full -reindex".
4. **Memory bomb fleet pattern** — BUG-10 repeats the haskoin W138 BUG-10
   / clearbit W128 / rustoshi W133 pattern: deserialize size field, allocate
   buffer, validate checksum AFTER allocation. Fix is always the same:
   cap pre-allocation at a sanity limit.
5. **Default credentials / default-bypass-class adjacent**: BUG-11
   `syncWrites=false` default is the storage analogue of W140's
   "default-install-auth-bypassed" — operator gets an UNSAFE default
   without explicit opt-in.
6. **`'b'`/`'f'`/`'l'`/`'F'`/`'R'`/`'t'` prefix bytes absent from production
   path** — all 6 Core leveldb key-namespace prefixes either absent
   (`'F'`, `'R'`) or present-only-in-dead-code (`'b'`, `'f'`, `'l'`).
   Production uses column-families as the namespace mechanism, which is a
   reasonable design choice but breaks cross-impl interop with Core.
7. **fsync absent in storage layer** — `grep -n "fsync" src/storage/*.nim`
   returns ONLY `snapshot.nim`. The blk/rev/RocksDB paths have zero fsync.
   Same shape as the W118 fee-estimates power-cut finding.

## Notable carry-forwards (re-anchor candidates)

- W138 BUG-2 (rustoshi fabricated testnet4 h=290000 assumeUTXO hash) — the
  same "scaffolding without backing" pattern repeats here for blk\*.dat.
- W134 BUG-W134-N nimrod (BIP-37 filtered-block-dispatch dead) — entire
  filter dispatch path dead. Block-storage dead path is the next layer
  down: full block READ dead because full block WRITE is dead.
- W93 totalWork persistence in cfMeta — same key family (cfMeta) is now
  the de-facto resting place for `'l'`-last-blockfile, `'f'`-fileinfo,
  `prune_height`, `prune_target`, `bestblock`, `height`, `totalwork`,
  and `undoKey()`. cfMeta is overloaded; consider sub-namespacing.

## Remediation priorities (suggested ordering, NOT implemented in W146)

1. **BUG-7** (no fsync on rev\*.dat → cfBlockIndex commit) — P0-SEC, single
   `posix.fsync` call before the batch.put. Closes the power-cut split-brain
   window.
2. **BUG-10** (memory bomb on corrupt undo size) — P0-SEC, single
   `if size > someCap: return (BlockUndo(), false)`.
3. **BUG-11** (RocksDB default syncWrites=false) — P1, flip the default
   to true; the perf hit is real but the correctness hit is worse.
4. **BUG-5+6** (preallocate feedback loop + rotation flush gap) — P0
   latent, but only matters if BUG-1 is ever closed.
5. **BUG-1** (dead path) — P0 architecturally, but resolves only with
   subsystem rewrite.
6. **BUG-15** (double undo write) — P2, drop the rev\*.dat write OR drop
   the cfMeta legacy write. Pick one.
7. **BUG-9** (rev\*.dat byte-format divergence) — P0-CDIV, requires
   `TxOutCompression` implementation in serialize.nim.
8. **BUG-3+12+13** (custom serialization formats) — P0-CDIV, requires
   CDiskBlockIndex + STORAGE_HEADER_BYTES + 't' txindex prefix wholesale
   adoption; only useful if interop is a goal.

End of W146 audit.
