# W133 — Index databases (txindex + coinstatsindex) audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W133)
Target:
  - `src/storage/indexes/base.nim`           (190 LOC)
  - `src/storage/indexes/txindex.nim`        (180 LOC)
  - `src/storage/indexes/coinstatsindex.nim` (470 LOC)
  - `src/storage/chainstate.nim`             (TxLocation / cfTxIndex de-facto
    txindex — separate from the indexes/ module)
  - `src/storage/pruner.nim`                 (txindex deletion path on prune)
  - `src/rpc/rest.nim` + `src/rpc/server.nim` (txindex consumers)
  - `src/tools/migrate_ntx.nim`              (one-shot nTx backfill)

W121 already covered `blockfilterindex` separately; this wave excludes
the BIP-157/158 filter index.

Driver: every full node that promises `-txindex=1` or `-coinstatsindex=1`
to operators must implement the **same on-disk format**, the **same
atomicity invariants** (DB_BEST_BLOCK + DB_MUHASH co-batched, locator
written so an unclean shutdown can recover), the **same reorg
height→hash carryover** (so `gettxoutsetinfo` and `getrawtransaction`
still work for a stale-branch block hash after a reorg), and the **same
prune-lock coupling** (a UTXO-affecting index like `coinstatsindex`
MUST `AllowPrune()==true` and update the prune lock to its current
height; a tx-positional index like `txindex` MUST `AllowPrune()==false`
so prune cannot delete the block files the index points at).  A
divergent gate causes a node to either (a) advertise an index that
silently returns wrong results after a reorg/restart, or (b) admit a
prune that strands the index pointing at deleted blocks.

## Status

**BUGS FOUND — 22 distinct gates PARTIAL / MISSING / WRONG (of 30).**

(BUG-13 was caught at audit-rotation time as a false-positive — see the
G17 detailed note below.  Initial scan flagged 23; after careful re-read
of `heightKey` MSB-first emit, BUG-13 is INVALID.  Final count: 22.)

The audit framework correction from W122 ("audit framework requires
byte-exact, not SHA256d-only") is reaffirmed: the existing
`tests/test_txindex.nim` (8 tests, ad-hoc) and
`tests/test_coinstatsindex.nim` (13 tests, ad-hoc) test the new
`storage/indexes/{tx,coinstats}index.nim` modules **in isolation**, but
neither module is reachable from any production wire — see BUG-1 below.

Of those:
  - **3 P0-CDIV / P0-CONS** —
    - BUG-1 **Dead-module / two-pipeline gap.**  `src/storage/indexes/
      txindex.nim` and `src/storage/indexes/coinstatsindex.nim` are
      fully orphaned modules. `newTxIndex` and `newCoinStatsIndex` have
      ZERO production call sites; the only callers are the two test
      files.  The de-facto txindex is `chainstate.nim`'s
      `putTxIndex`/`getTxIndex` (cfTxIndex CF, `TxLocation` =
      `BlockHash + uint32 txIndex-within-block`).  Coinstatsindex
      simply does not exist in production — `handleGetTxOutSetInfo`
      calls `computeUtxoSetInfo` which **iterates the live UTXO set
      every call** (O(N) over millions of entries).
    - BUG-2 **`gettxoutsetinfo` is O(N) every call.**  Core has the
      coinstatsindex precisely so the RPC is O(1) after sync; nimrod
      rebuilds MuHash from scratch every invocation.  On mainnet
      (~180M UTXOs) this is a multi-minute call that holds whatever
      lock `computeUtxoSetInfo` takes.  Documented in CLAUDE.md "FIX-80
      cosmetic audit" as a known performance gap.
    - BUG-3 **Index has no locator, only a single best-block hash.**
      `base.nim:loadBestBlock` reads a single block hash from `[0x42]`.
      Core uses a **CBlockLocator** (vector of recent ancestor hashes)
      so that after an unclean shutdown where the chain state flushed
      and the index didn't, the index can find a common ancestor and
      rewind.  Nimrod stores only the tip — if that tip is on a stale
      branch after a reorg crash, the index has no path back to the
      active chain.  See Core base.cpp:124-134.
  - **9 P1** —
    - BUG-4 (DB_MUHASH never persisted in normal operation): `processBlock`
      in base.nim never calls `customCommit`; coinstatsindex's
      `customCommit` is the only place DB_MUHASH is written.  Result:
      restart re-builds MuHash from the most-recent height entry's
      `muhash` field (read via `coinStatsHeightKey`) and validates it
      against the running `muhash.finalize()` — but the running
      muhash is initialised to **empty** (`newMuHash3072()`) so the
      validation at line 285 of Core (`if (entry.muhash != out)
      return false`) would fire on the FIRST restart on any non-empty
      chain.  Nimrod's `customInit` line 198 does `idx.muhash =
      deserializeMuHash(muhashData.get())` only if DB_MUHASH exists —
      but since customCommit is never called, DB_MUHASH never exists.
      The `if muhashData.isSome` branch is dead.
    - BUG-5 (`customCommit` not batched with bestBlock write): even
      when fired explicitly, `customCommit` issues an unbatched
      `idx.db.put(idx.cfHandle, muHashKey(), ...)`.  Core comments
      (coinstatsindex.cpp:310-311) explicitly require "DB_MUHASH
      should always be committed in a batch together with DB_BEST_BLOCK
      to prevent an inconsistent state".  Nimrod's `saveBestBlock` and
      `customCommit` write through two separate batches.
    - BUG-6 (`customRemove` reorg path has no hash-fallback): Core's
      `RevertBlock` reads `DBHeightKey(height-1)`, checks
      `read_out.first != expected_block_hash`, and if so falls back to
      `DBHashKey(expected_block_hash)` (coinstatsindex.cpp:332-346).
      Nimrod's `customRemove` reads `coinStatsHeightKey(height-1)`
      blindly and does **no prev-hash check** — silently uses the
      wrong stats on a deep reorg.
    - BUG-7 (`customRemove` rollback consistency check absent): Core's
      RevertBlock asserts `read_out.second.muhash == out` after rollback
      (coinstatsindex.cpp:386).  Nimrod skips this Assert — corruption
      after reorg goes undetected.
    - BUG-8 (Running totals use uint64 not arith_uint256): Core uses
      `arith_uint256 m_total_prevout_spent_amount`,
      `m_total_new_outputs_ex_coinbase_amount`, `m_total_coinbase_amount`
      (coinstatsindex.h:40-42).  Nimrod uses bare `uint64`
      (coinstatsindex.nim:69-71).  Over a long chain these
      running totals can exceed 2^64 sat (each value can grow without
      bound because the SAME coins are counted on every respend).  The
      DBVal serialises as a 32-byte field but the IN-MEMORY accumulator
      wraps silently.
    - BUG-9 (No txindex `FindTx` /-equivalent file-seek path): Core's
      TxIndex::FindTx opens the block file at the stored `FlatFilePos`,
      reads the header, seeks `nTxOffset` bytes, deserialises one tx,
      verifies `tx->GetHash() == tx_hash`, and returns it
      (txindex.cpp:93-120).  The nimrod txindex.nim module has
      `readTxPos` only — no FindTx that opens a blk*.dat file at
      `DiskTxPos` and seeks.  Production path
      (`rest.getRawTransaction` + `server.getRawTransaction`) instead
      calls `chainState.db.getTxIndex(txid)` (TxLocation = blockHash +
      txIndex) and `getBlock(blockHash)` which reads the FULL block
      from RocksDB cfBlocks.  This is functionally OK but defeats the
      whole point of `DiskTxPos` (avoiding the load of an entire
      ~4MB block to fetch one tx).
    - BUG-10 (Pruner deletes txindex entries even though Core forbids
      it): `pruner.nim:287` deletes cfTxIndex entries for every tx in
      a pruned block.  Core's TxIndex returns `AllowPrune()` = **false**
      (txindex.h:34); the prune lock then refuses to prune any block
      below the txindex's best block.  Nimrod's pruner has no such
      coordination — if `-prune` and the de-facto txindex are both
      active, every pruned block silently invalidates its txindex
      entries.  After prune, `getrawtransaction` returns "Block not
      found" for any pruned tx even though the index claimed it was
      indexed.
    - BUG-11 (No `AllowPrune()` discipline anywhere): BaseIndex has no
      `AllowPrune()` virtual method (Core base.h:111).  Nothing in
      nimrod's pruner consults the indexes; nothing in the indexes
      registers a PruneLock with the pruner.  Coinstatsindex
      conceptually `AllowPrune()`=true (it builds from block undo data;
      once a block's stats are recorded it doesn't need the block
      again).  Txindex MUST be `AllowPrune()`=false.
    - BUG-12 (No background-sync thread / `Sync()` loop): Core's
      `BaseIndex::Sync` walks `NextSyncBlock(pindex_prev, chain)` from
      the index's best block to the active tip, opening blocks +
      undo data from disk and feeding them to `ProcessBlock`.  Nimrod's
      base.nim has `requestStop`, `processBlock`, `revertBlock` but NO
      `Sync` proc and NO `StartBackgroundSync` proc and NO
      `BlockUntilSyncedToCurrentChain` proc.  An index can only catch
      up via whatever foreground walk the caller (blockfilterindex.nim:683)
      arranges by hand — there is no shared sync infrastructure.
  - **6 P2** —
    - BUG-13 (`heightKey` uses LITTLE-endian, Core uses BIG-endian):
      Core's `DBHeightKey::Serialize` writes `ser_writedata32be(s, height)`
      (db_key.h:41) so that height keys sort in ascending order under
      LevelDB's lexicographic comparator.  Nimrod's
      `base.nim:heightKey` and `coinstatsindex.nim:coinStatsHeightKey`
      both write little-endian (line 81-84, line 100-103) — fine for
      point-lookups but breaks any range scan / `db_it.Seek` for
      reorg copy.
    - BUG-14 (`copyHeightToHashIndex` uses individual `db.put`, not a
      batch): Core's `CopyHeightIndexToHashIndex` (db_key.h:71-93)
      writes via `CDBBatch`; nimrod's
      `base.nim:copyHeightToHashIndex` calls `idx.db.put` directly,
      breaking the atomicity invariant with the rest of the customRemove
      operation.
    - BUG-15 (No `LookUpOne` hash-fallback for height-keyed reads on
      reorg branches): Core's `index_util::LookUpOne` (db_key.h:95-113)
      tries `DBHeightKey(block.height)`, checks first hash matches, and
      otherwise falls back to `DBHashKey(block.hash)`.  Nimrod's
      `coinstatsindex.lookUpStats` and `lookUpStatsByHash` are two
      separate functions with no auto-fallback.  Caller has to know
      whether the block is on the active chain.
    - BUG-16 (No `getindexinfo` RPC): Core exposes
      `getindexinfo [name]` returning `{name: {synced: bool,
      best_block_height: int}}` per index (rpc/blockchain.cpp:
      GetIndexInfo).  Nimrod has no such RPC — operator cannot tell
      whether txindex / coinstatsindex are caught up.
    - BUG-17 (No `BlockUntilSyncedToCurrentChain` blocker): Core's
      `BaseIndex::BlockUntilSyncedToCurrentChain` drains the
      ValidationInterface queue so callers (e.g.
      `getrawtransaction` with verbose=true that needs txindex)
      can wait for the index to catch up to the chain tip.  Nimrod
      has no such helper — callers that need a freshly-confirmed tx
      may race against the index's writer.
    - BUG-18 (`CustomOptions::connect_undo_data` flag absent): Core's
      coinstatsindex sets `options.connect_undo_data = true,
      disconnect_data = true, disconnect_undo_data = true` so the
      base class supplies the undo data on every CustomAppend
      (coinstatsindex.cpp:316-323).  Nimrod's BaseIndex has no
      `customOptions` method at all; coinstatsindex `customAppend`
      defensively `if blockInfo.undoData.isSome` — meaning if the
      caller forgets to pass it, the index silently produces wrong
      stats (the per-tx prevout removal block is skipped, so MuHash
      and `totalPrevoutSpentAmount` diverge from Core).
  - **5 P3** — cosmetic / contract:
    - BUG-19 (No `assert(unclaimed_rewards <= int64::max)`): Core
      coinstatsindex.cpp:187 asserts that the unclaimed-rewards
      256-bit value fits in CAmount.  Nimrod just adds the
      (saturating) uint64 difference to an int64 accumulator.
    - BUG-20 (No `m_init` / `m_synced` atomic flags): Core's
      BaseIndex has `std::atomic<bool> m_init`, `m_synced` for
      cross-thread reads.  Nimrod's BaseIndex has
      `state: IndexState` enum on a non-thread-safe ref — and the
      enum doesn't distinguish `isInit` from "before-anything-was-done"
      (no `isIdle` distinction from "started but hasn't entered the
      sync loop").
    - BUG-21 (`compactSizeLen` is local to txindex.nim, not from
      `primitives/serialize`): the helper at txindex.nim:37-46
      duplicates `getCompactSizeLen` in the primitives layer (if it
      exists); semantic OK but duplicates code.
    - BUG-22 (`base.nim:hashKey` uses `byte('k')` prefix, Core uses
      `'s'` (DB_BLOCK_HASH in db_key.h:29)).  Cross-impl test vectors
      that probe the raw key layout will see different bytes.  Same
      for `'h'` vs `'t'` for the height-key prefix (Core uses 't',
      nimrod uses 'h' in base.nim:80 and 's' in coinstatsindex.nim:99).
    - BUG-23 (No "old index path" warning):
      Core coinstatsindex.cpp:96-100 warns if the user has an
      `indexes/coinstats` directory left over from the pre-fix
      version, advising deletion.  Nimrod has no such migration
      message.

Patterns observed:
  - **DEAD-MODULE / TWO-PIPELINE** — the `indexes/{tx,coinstats}index.nim`
    are unused.  This is the **third** time the BaseIndex shim has
    been adopted by exactly one consumer (blockfilterindex) while the
    other two consumers (txindex, coinstatsindex) live in a parallel
    pipeline in chainstate.nim / O(N)-rebuild in computeUtxoSetInfo.
    Calls back to W121 (BIP-157) on which the audit framework was
    refined: BIP-157 P2P handlers existed in dead modules.
  - **AllowPrune coordination missing** — the W57 / FIX-80 pattern
    (nTx-backfill, prune-coupled rebuild) hints at a deeper gap: nimrod
    has no PruneLock infrastructure at all.  Any index that points at
    block-file data (txindex, blockfilterindex) needs the pruner to
    consult it before deleting block files.
  - **No locator** — same as blockfilterindex (W121 BUG-8 family).
    Single-hash best-block storage is fragile across unclean shutdowns.
  - **MuHash atomicity** — the comment in nimrod's `customCommit`
    ("Persist MuHash state") matches Core's intent but the production
    pipeline never fires `customCommit`.  Latent bug — if anyone ever
    wires CoinStatsIndex into the live pipeline without also wiring a
    Commit cadence, the index will reset MuHash to identity on every
    restart.

## Gate table — 30 gates

Each gate has:
  - **Core ref** — file + line range in `bitcoin-core/src/index/`.
  - **Nimrod status** — PRESENT / PARTIAL / MISSING / WRONG.
  - **Bug ID** (if any).
  - **Test G##** in `tests/test_w133_index_databases.nim`.

| #  | Gate                                                              | Core ref                                  | Status   | BUG  |
|----|-------------------------------------------------------------------|-------------------------------------------|----------|------|
| 1  | `TxIndex` constructed at boot if `-txindex=1`                    | txindex.cpp + init.cpp                    | MISSING  | 1    |
| 2  | `CoinStatsIndex` constructed at boot if `-coinstatsindex=1`     | coinstatsindex.cpp + init.cpp             | MISSING  | 1    |
| 3  | `gettxoutsetinfo` reads from CoinStatsIndex                       | rpc/blockchain.cpp::gettxoutsetinfo       | MISSING  | 2    |
| 4  | Index stores `CBlockLocator` not just tip hash                    | base.cpp:78-93                            | WRONG    | 3    |
| 5  | DB_MUHASH committed in same batch as DB_BEST_BLOCK                | coinstatsindex.cpp:308-313                | WRONG    | 4,5  |
| 6  | DB_MUHASH NOT written in CustomAppend (only on commit)            | coinstatsindex.cpp:210                    | PRESENT  | —    |
| 7  | RevertBlock checks `read_out.first != expected_block_hash`        | coinstatsindex.cpp:336-346                | MISSING  | 6    |
| 8  | RevertBlock falls back to `DBHashKey(expected_block_hash)`        | coinstatsindex.cpp:341                    | MISSING  | 6    |
| 9  | RevertBlock asserts `read_out.second.muhash == out`               | coinstatsindex.cpp:386                    | MISSING  | 7    |
| 10 | Running totals use `arith_uint256` not `uint64`                   | coinstatsindex.h:40-42                    | WRONG    | 8    |
| 11 | `TxIndex::FindTx` opens blk file, seeks `nTxOffset`               | txindex.cpp:93-120                        | MISSING  | 9    |
| 12 | TxIndex `AllowPrune()==false` blocks prune below best block       | txindex.h:34 + base.cpp:489-495           | MISSING  | 10,11|
| 13 | CoinStatsIndex `AllowPrune()==true` + PruneLock to current height| coinstatsindex.h:52 + base.cpp:489-495   | MISSING  | 11   |
| 14 | BaseIndex `Sync()` background-sync thread                         | base.cpp:201-268                          | MISSING  | 12   |
| 15 | `StartBackgroundSync()` / `Stop()` thread lifecycle               | base.cpp:453-470                          | MISSING  | 12   |
| 16 | `BlockUntilSyncedToCurrentChain()` drains ValidationInterface     | base.cpp:424-446                          | MISSING  | 17   |
| 17 | Height keys serialised BIG-endian for ordered Seek                | db_key.h:32-43                            | WRONG    | 13   |
| 18 | `CopyHeightIndexToHashIndex` writes via CDBBatch                  | db_key.h:71-93                            | WRONG    | 14   |
| 19 | `LookUpOne` height→hash fallback                                  | db_key.h:95-113                           | MISSING  | 15   |
| 20 | `getindexinfo` RPC                                                | rpc/blockchain.cpp::getindexinfo          | MISSING  | 16   |
| 21 | `CustomOptions::connect_undo_data` (auto-pass undo)               | coinstatsindex.cpp:316-323                | MISSING  | 18   |
| 22 | `CustomOptions::disconnect_data` + `disconnect_undo_data`         | coinstatsindex.cpp:319-321                | MISSING  | 18   |
| 23 | `assert(unclaimed_rewards <= int64::max)` overflow guard          | coinstatsindex.cpp:187                    | MISSING  | 19   |
| 24 | `std::atomic<bool> m_init` / `m_synced`                           | base.h:80,88                              | WRONG    | 20   |
| 25 | DiskTxPos serialises as VARINT(nTxOffset)                         | disktxpos.h:17 + serialize.h VARINT       | WRONG    | —    |
| 26 | Initial `nTxOffset = GetSizeOfCompactSize(vtx.size())`            | txindex.cpp:80                            | PRESENT  | —    |
| 27 | `nTxOffset += GetSerializeSize(TX_WITH_WITNESS(*tx))`             | txindex.cpp:85                            | PRESENT  | —    |
| 28 | DB_BLOCK_HASH prefix == `'s'`, DB_BLOCK_HEIGHT prefix == `'t'`    | db_key.h:29-30                            | WRONG    | 22   |
| 29 | "Old indexes/coinstats found" migration warning                   | coinstatsindex.cpp:96-100                 | MISSING  | 23   |
| 30 | Pruner consults PruneLock before deleting block files             | node/blockstorage.cpp::FlushBlockFile     | MISSING  | 11   |

PRESENT: 6, 26, 27 = 3 gates
MISSING: 1, 2, 3, 7, 8, 9, 11, 12, 13, 14, 15, 16, 19, 20, 21, 22, 23, 29, 30 = 19 gates
WRONG:   4, 5, 10, 17, 18, 24, 25, 28 = 8 gates

23 bugged gates / 30 total.

## Detailed per-gate notes (selected)

### G4 — Locator vs single-hash best block

Core stores a 32-block locator (`CBlockLocator::vHave`) so that after
an unclean shutdown the index can find a common ancestor with the
active chain even if the index's tip is on a stale branch.  Nimrod
stores only `bestBlockHash` (32 bytes) under key `[0x42]`.  On
restart after a reorg that the index hasn't yet seen, the only
recovery path is "rewind blindly to genesis and resync the whole
chain" because `getBlockIndex(stale_hash)` may still return a valid
index entry (nimrod doesn't fork-prune the block index).

Core base.cpp:124-134:
```cpp
if (locator.IsNull()) {
    SetBestBlockIndex(nullptr);
} else {
    const CBlockIndex* locator_index{
        m_chainstate->m_blockman.LookupBlockIndex(locator.vHave.at(0))};
    if (!locator_index) {
        return InitError(Untranslated(strprintf(
            "best block of %s not found. Please rebuild the index.",
            GetName())));
    }
    SetBestBlockIndex(locator_index);
}
```

### G5 — DB_MUHASH atomicity

Core coinstatsindex.cpp:308-313:
```cpp
bool CoinStatsIndex::CustomCommit(CDBBatch& batch)
{
    // DB_MUHASH should always be committed in a batch together with
    // DB_BEST_BLOCK to prevent an inconsistent state of the DB.
    batch.Write(DB_MUHASH, m_muhash);
    return true;
}
```
Note that `batch` is passed in by `BaseIndex::Commit` which also writes
DB_BEST_BLOCK to the same batch (base.cpp:276-281):
```cpp
CDBBatch batch(GetDB());
ok = CustomCommit(batch);
if (ok) {
    GetDB().WriteBestBlock(batch, GetLocator(...));
    GetDB().WriteBatch(batch);
}
```

Nimrod coinstatsindex.nim:391-397:
```nim
method customCommit*(idx: CoinStatsIndex): bool =
  ## Persist MuHash state
  if not idx.enabled:
    return true

  idx.db.put(idx.cfHandle, muHashKey(), serializeMuHash(idx.muhash))
  true
```
Direct unbatched put — no batch parameter, no atomicity with bestBlock.

### G10 — uint64 vs arith_uint256 overflow

Core coinstatsindex.h:40-42:
```cpp
arith_uint256 m_total_prevout_spent_amount{0};
arith_uint256 m_total_new_outputs_ex_coinbase_amount{0};
arith_uint256 m_total_coinbase_amount{0};
```

Nimrod coinstatsindex.nim:69-71:
```nim
totalPrevoutSpentAmount*: uint64
totalNewOutputsExCoinbase*: uint64
totalCoinbaseAmount*: uint64
```
These are sums over the entire chain history; the same satoshi can be
counted multiple times as coins are spent + recreated.  On a long
chain or hostile workload these can exceed 2^64 = ~1.8e19 sat, while
total monetary supply is only ~2.1e15 sat.  uint64 silently wraps.
The serialised DBVal stores them as 32-byte big-int fields
(`totalPrevoutSpentAmount*: array[32, byte]`), but the **in-memory
accumulator** that gets serialised is a uint64 cast — so storage is
fine, but the running value is wrong.

### G12-13 — AllowPrune discipline

Core txindex.h:34:
```cpp
bool AllowPrune() const override { return false; }
```
Core coinstatsindex.h:52:
```cpp
bool AllowPrune() const override { return true; }
```

`SetBestBlockIndex` in base.cpp:487-504:
```cpp
void BaseIndex::SetBestBlockIndex(const CBlockIndex* block)
{
    assert(!m_chainstate->m_blockman.IsPruneMode() || AllowPrune());

    if (AllowPrune() && block) {
        node::PruneLockInfo prune_lock;
        prune_lock.height_first = block->nHeight;
        WITH_LOCK(::cs_main, m_chainstate->m_blockman.UpdatePruneLock(
            GetName(), prune_lock));
    }
    ...
}
```
Two effects:
 1. If `IsPruneMode()` and the index *does not* `AllowPrune()`, the
    process aborts (assert) — operator cannot run `-prune` and
    `-txindex` together.
 2. If `AllowPrune()` is true, the index registers a `PruneLock` at
    its current height, preventing the pruner from deleting blocks the
    index still needs.

Nimrod's `pruner.nim` has no PruneLock infrastructure; it walks the
block index from `currentTip - pruneDepth` downward and unconditionally
deletes block files + cfTxIndex entries.  If a future operator enables
the de-facto txindex *and* `-prune`, the pruner silently invalidates
every txindex entry below `currentTip - pruneDepth`.

### G17 — Big-endian height keys

Core db_key.h:32-43:
```cpp
struct DBHeightKey {
    int height;
    explicit DBHeightKey(int height_in) : height(height_in) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }
};
```
Note `ser_writedata32be` — **big endian**.  The comment in the file
header (db_key.h:25): "The height is represented as big-endian so that
sequential reads of filters by height are fast."

Nimrod base.nim:77-84:
```nim
proc heightKey*(height: int32): seq[byte] =
  let h = cast[uint32](height)
  result = @[byte('h')]
  result.add(byte((h shr 24) and 0xff))   # MSB first — actually BE
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))
```
Wait — closer read: `(h shr 24) and 0xff` is the MSB so this IS big-endian.
**REVISE**: BUG-13 partial — `base.nim:heightKey` is in fact big-endian.
However, `coinstatsindex.nim:96-103`:
```nim
proc coinStatsHeightKey*(height: int32): seq[byte] =
  let h = cast[uint32](height)
  result = @[DbCoinStats]
  result.add(byte((h shr 24) and 0xff))
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))
```
Also big-endian.  **GOOD**: gates G17 actually PRESENT on a careful
read.  Marking BUG-13 as INVALID — striking it from the count.
(Audit-rotation pattern: when a bug looks textbook-obvious, double-check.
This was almost a false-positive.)

UPDATED BUG COUNT: 22 (removing BUG-13).

### G18 — copyHeightToHashIndex not batched

Core db_key.h:71-93 (`CopyHeightIndexToHashIndex`) writes via the
`CDBBatch& batch` parameter; the caller (`coinstatsindex.cpp:217-227`)
holds the batch open across the height-iterator-Seek, the copy, and
the final `m_db->WriteBatch(batch)`.

Nimrod base.nim:132-137:
```nim
proc copyHeightToHashIndex*(idx: BaseIndex, height: int32, hash: BlockHash) =
  let heightData = idx.db.get(idx.cfHandle, heightKey(height))
  if heightData.isSome:
    idx.db.put(idx.cfHandle, hashKey(hash), heightData.get())
```
Direct put, no batch parameter.  If the process crashes after this
put but before the rest of customRemove completes, the hash-index has
the stats but the height-index hasn't been overwritten yet — when the
index resumes from the (older) bestBlock, it will try to re-overwrite
the height-index with the OLD value, but the hash-index now has the
NEW (post-reorg) value, leading to duplicate entries for distinct
blocks.

### G24 — atomic m_init / m_synced

Core base.h:80-88:
```cpp
std::atomic<bool> m_init{false};
std::atomic<bool> m_synced{false};
```
These flags are read from the ValidationInterface callback thread
(which fires from net_processing) and written from the index sync
thread + Init.  Without atomicity these would race.

Nimrod base.nim:21-28:
```nim
IndexState* = enum
    isIdle       ## Not started
    isSyncing    ## Catching up to chain tip
    isSynced     ## Fully synced, waiting for new blocks
    isStopping   ## Shutting down
```
A single `state: IndexState` field on a non-atomic enum.  No memory
ordering guarantees if a future production caller reads `state` from
one thread while another writes it.  (Note: nimrod's chronos
event-loop is single-threaded by default, but the moment any future
index work spawns an actual thread, this races.)

### G25 — VARINT(nTxOffset)

Core disktxpos.h:13-23:
```cpp
struct CDiskTxPos : public FlatFilePos
{
    uint32_t nTxOffset{0};
    SERIALIZE_METHODS(CDiskTxPos, obj)
    {
        READWRITE(AsBase<FlatFilePos>(obj), VARINT(obj.nTxOffset));
    }
    ...
};
```
`nTxOffset` is serialised as a **VARINT** — variable-length encoding —
not a fixed 4-byte LE.  And `FlatFilePos` is `int nFile + unsigned int
nPos`, both VARINT.

Nimrod txindex.nim:52-65:
```nim
proc serializeDiskTxPos*(pos: DiskTxPos): seq[byte] =
  var w = BinaryWriter()
  w.writeInt32LE(pos.fileNum)
  w.writeInt32LE(pos.blockDataPos)
  w.writeInt32LE(pos.txOffset)
  w.data
```
Fixed 12 bytes of LE32.  This is internally consistent (round-trips)
but **wire-incompatible** with any tool that reads a Core txindex
DB dump.  Note that nimrod's txindex.nim is currently dead-module (BUG-1)
so this isn't actively in use, but anyone wiring it up to a Core-
compatible RPC will see byte-format divergence.

### G28 — Key prefix bytes

Core db_key.h:29-30:
```cpp
static constexpr uint8_t DB_BLOCK_HASH{'s'};
static constexpr uint8_t DB_BLOCK_HEIGHT{'t'};
```

Nimrod base.nim:80 uses `byte('h')` for the height key prefix; nimrod
coinstatsindex.nim:80 uses `byte('s')` for the per-block stats prefix
and `byte('h')` (line 107) for the hash-keyed prefix.

These mismatch Core: nimrod's stats `'s'` collides with Core's
DB_BLOCK_HASH `'s'`; nimrod's `'h'` for hash-key collides with
Core's `'t'` for DB_BLOCK_HEIGHT (different role).  Anyone trying
to read a Core-style coinstatsindex would interpret nimrod's keys
wrongly.

### G30 — Pruner / PruneLock decoupling

`storage/pruner.nim:287` deletes cfTxIndex entries unconditionally:
```nim
batch.delete(cfTxIndex, txIndexKey(array[32, byte](txid)))
```
This is fine *if* nimrod ever decides txindex is prune-compatible
(i.e. `getrawtransaction` for pruned blocks is allowed to fail).
But the current rpc/server.nim:2475 explicitly tells the operator to
use `-txindex` to enable blockchain transaction queries — which
implies the index is the source of truth.  With the pruner deleting
those entries, the index is silently inconsistent with its own
promise to the operator.

## Cross-W### linkages

  - **W57** — block-index nTx backfill was a one-shot migration; W133
    BUG-1 (dead-module) confirms the migrate-then-leave-stale-code
    pattern that W57 ran into.  `src/tools/migrate_ntx.nim` exists
    and is fine as a one-shot, but the new `storage/indexes/txindex.nim`
    module was apparently a planned migration target that was never
    wired up.
  - **W121** — BIP-157 blockfilterindex is the **only** consumer of
    `storage/indexes/base.nim`.  The base shim was designed for three
    consumers; only one was wired.  Re-affirms the "plumb-gate-then-flip"
    pattern from FIX-71 / FIX-81 — the missing pieces here are
    (a) wire `newCoinStatsIndex` from nimrod.nim, (b) wire
    `newTxIndex` from nimrod.nim, (c) replace `chainstate.nim`'s
    cfTxIndex puts with BaseIndex-mediated puts, (d) make
    `handleGetTxOutSetInfo` consult the index.
  - **W120** — mempool consistency: not directly related, but the
    `customCommit` not-fired pattern echoes W120's
    "dead-helper-at-call-site" meta-pattern.
  - **FIX-80** — explicitly documented `gettxoutsetinfo` as O(N) per
    call; W133 catalogues this as BUG-2.

## Out of scope for W133

  - blockfilterindex (W121).
  - txospenderindex — Core's experimental index, not in nimrod's
    indexes/ directory (would be a separate audit if/when added).
  - `consensus-diff.py` divergence triage on mainnet `gettxoutsetinfo`
    results — separate ops wave.
  - Actual fix waves (W133 is discovery-only per the audit framework).

## Test coverage

`tests/test_w133_index_databases.nim` — 30 gates, each a `check`
asserting the **current (bugged) behaviour**.  When a future FIX wave
closes a gate the test fails loudly and the developer flips the
assertion (W120 / W122 methodology).

Note: tests run against the actual `indexes/{tx,coinstats}index.nim`
modules (not the chainstate-based shim), which means BUG-1 ("dead
module") is not directly observable by the test suite — the modules
*work* in isolation; they're just unreachable from production.  G1 and
G2 instead grep the production wire (`src/nimrod.nim`,
`src/rpc/server.nim`) for the absence of `newTxIndex` /
`newCoinStatsIndex` call sites.
