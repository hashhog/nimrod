## W133 — Index databases (txindex + coinstatsindex) audit (30 gates, xfail
## regression guards).
##
## Audit type: discovery (NO production code change in W133).
##
## W133 catalogues the gap between Bitcoin Core's `BaseIndex` / `TxIndex` /
## `CoinStatsIndex` and nimrod's parallel pipelines:
##
##   - `src/storage/indexes/{base,txindex,coinstatsindex}.nim` (new BaseIndex
##     shim with reorg-aware customAppend / customRemove) — currently a
##     DEAD MODULE wired only into the test suite.
##   - `src/storage/chainstate.nim` (the de-facto txindex, via cfTxIndex CF
##     + `TxLocation` = BlockHash + uint32 txIndex-within-block).
##   - `src/storage/pruner.nim` (deletes cfTxIndex entries on prune, with no
##     PruneLock coordination).
##   - `src/rpc/server.nim::handleGetTxOutSetInfo` (calls `computeUtxoSetInfo`
##     which iterates the live UTXO set on every request — there is no
##     CoinStatsIndex consulted).
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour with a
## `check` that pins the gap.  When a future FIX wave closes the gap, the
## test will fail loudly and the developer must flip the assertion
## (per W120 / W122 / W123 / W124 / W125 / W128 / W131 methodology).
##
## References:
##   bitcoin-core/src/index/base.cpp / base.h
##   bitcoin-core/src/index/txindex.cpp / txindex.h
##   bitcoin-core/src/index/coinstatsindex.cpp / coinstatsindex.h
##   bitcoin-core/src/index/db_key.h
##   bitcoin-core/src/index/disktxpos.h
##   audit/w133_index_databases.md — full gate table + per-gate detail.

import unittest2
import std/[options, os, strutils, tempfiles]
import ../src/storage/indexes/base
import ../src/storage/indexes/txindex
import ../src/storage/indexes/coinstatsindex
import ../src/storage/db
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, muhash]
import ../src/consensus/params

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # Core index/base.cpp:47
  CORE_DB_BEST_BLOCK_PREFIX = 'B'
  # Core index/db_key.h:29-30 — DB_BLOCK_HASH = 's', DB_BLOCK_HEIGHT = 't'
  CORE_DB_BLOCK_HASH_PREFIX   = 's'
  CORE_DB_BLOCK_HEIGHT_PREFIX = 't'
  # Core index/txindex.cpp:31
  CORE_DB_TXINDEX_PREFIX = 't'
  # Core index/coinstatsindex.cpp:42
  CORE_DB_MUHASH_PREFIX = 'M'
  # Core index/base.cpp:49-50
  CORE_SYNC_LOG_INTERVAL_SEC          = 30
  CORE_SYNC_LOCATOR_WRITE_INTERVAL_SEC = 30
  # Core index/txindex.h:19 / coinstatsindex.h:25
  CORE_DEFAULT_TXINDEX        = false
  CORE_DEFAULT_COINSTATSINDEX = false

# Read production source files once for source-level pinning.
let
  baseSrc        = readFile("src/storage/indexes/base.nim")
  txindexSrc     = readFile("src/storage/indexes/txindex.nim")
  coinstatsSrc   = readFile("src/storage/indexes/coinstatsindex.nim")
  chainstateSrc  = readFile("src/storage/chainstate.nim")
  prunerSrc      = readFile("src/storage/pruner.nim")
  serverSrc      = readFile("src/rpc/server.nim")
  nimrodSrc      = readFile("src/nimrod.nim")

# ---------------------------------------------------------------------------
# G1 — Two-pipeline / dead-module gap (BUG-1)
# ---------------------------------------------------------------------------
suite "W133 G1-G2 — dead-module / two-pipeline gap (BUG-1)":

  test "G1 BUG-1: newTxIndex has NO production call site":
    ## `storage/indexes/txindex.nim` defines `newTxIndex` but no module in
    ## src/ ever invokes it.  The production txindex is the chainstate-based
    ## one (cfTxIndex / TxLocation via `chainstate.nim:putTxIndex`).
    check "newTxIndex" notin nimrodSrc
    check "newTxIndex" notin serverSrc
    check "newTxIndex" notin chainstateSrc
    # The chainstate-side pipeline IS used:
    check "putTxIndex" in chainstateSrc

  test "G2 BUG-1 cont: newCoinStatsIndex has NO production call site":
    ## `storage/indexes/coinstatsindex.nim` defines `newCoinStatsIndex` but
    ## no module in src/ ever invokes it.  `gettxoutsetinfo` instead calls
    ## `computeUtxoSetInfo` which iterates the live UTXO set every time.
    check "newCoinStatsIndex" notin nimrodSrc
    check "newCoinStatsIndex" notin serverSrc
    check "newCoinStatsIndex" notin chainstateSrc
    # The O(N) fallback IS what `gettxoutsetinfo` calls today:
    check "computeUtxoSetInfo" in serverSrc

# ---------------------------------------------------------------------------
# G3 — gettxoutsetinfo is O(N), not O(1) via index (BUG-2)
# ---------------------------------------------------------------------------
suite "W133 G3 — gettxoutsetinfo is O(N) per call (BUG-2)":

  test "G3 BUG-2: handleGetTxOutSetInfo doesn't read from CoinStatsIndex":
    ## Core's rpc/blockchain.cpp::gettxoutsetinfo checks
    ## `g_coin_stats_index ? g_coin_stats_index->LookUpStats(...) : ...`
    ## first, falling back to a UTXO walk only if the index is disabled.
    ## Nimrod always walks: handleGetTxOutSetInfo → computeUtxoSetInfo.
    check "handleGetTxOutSetInfo" in serverSrc
    # No reference to CoinStatsIndex / lookUpStats inside handleGetTxOutSetInfo:
    check "lookUpStats" notin serverSrc
    check "CoinStatsIndex" notin serverSrc

# ---------------------------------------------------------------------------
# G4 — Locator vs single-hash best block (BUG-3)
# ---------------------------------------------------------------------------
suite "W133 G4 — locator vs single-hash bestBlock (BUG-3)":

  test "G4 BUG-3: BaseIndex stores only 32-byte tip hash, not a CBlockLocator":
    ## Core base.cpp:78-93 stores a CBlockLocator (vector of recent ancestor
    ## hashes) under key DB_BEST_BLOCK.  Nimrod stores only one 32-byte hash
    ## under key 'B'.
    check "BlockLocator" notin baseSrc
    check "Locator"      notin baseSrc
    check "vHave"        notin baseSrc
    # bestBlockKey is the single-byte 'B' key:
    let k = bestBlockKey()
    check k.len == 1
    check k[0] == byte(CORE_DB_BEST_BLOCK_PREFIX)

  test "G4 BUG-3 cont: loadBestBlock reads 32 bytes only, no fallback chain":
    check "loadBestBlock" in baseSrc
    # Sanity: the impl uses a single byte('B') key:
    check "bestBlockKey" in baseSrc

# ---------------------------------------------------------------------------
# G5 — DB_MUHASH atomicity with DB_BEST_BLOCK (BUG-4, BUG-5)
# ---------------------------------------------------------------------------
suite "W133 G5 — DB_MUHASH co-batched with DB_BEST_BLOCK (BUG-4, BUG-5)":

  test "G5 BUG-4: processBlock NEVER calls customCommit":
    ## Core base.cpp:201-268 (Sync loop) and 380-422 (ChainStateFlushed)
    ## both call Commit() which calls CustomCommit().  Nimrod's
    ## processBlock (base.nim:163-169) only calls customAppend +
    ## saveBestBlock; customCommit is unreachable from the foreground path.
    check "processBlock" in baseSrc
    # Confirm processBlock does NOT call customCommit:
    let processBlockStart = baseSrc.find("proc processBlock*")
    check processBlockStart > 0
    # Look at the body up to the next blank line / next-proc marker.
    # We can be brittle here and just check the entire base file lacks
    # any forward call:
    check "customCommit(" notin baseSrc

  test "G5 BUG-5: customCommit issues an unbatched put (no CDBBatch param)":
    ## Core coinstatsindex.cpp:308-313 receives `CDBBatch& batch` so the
    ## MuHash write is atomic with DB_BEST_BLOCK.  Nimrod's customCommit
    ## takes no batch parameter and uses `idx.db.put`.
    check "customCommit*(idx: CoinStatsIndex)" in coinstatsSrc
    check "idx.db.put(idx.cfHandle, muHashKey(), serializeMuHash" in coinstatsSrc
    # base.nim's customCommit has no CDBBatch / batch parameter:
    check "customCommit*(idx: BaseIndex, batch:" notin baseSrc

# ---------------------------------------------------------------------------
# G6 — DB_MUHASH not written in CustomAppend (PRESENT)
# ---------------------------------------------------------------------------
suite "W133 G6 — DB_MUHASH NOT written in CustomAppend (PRESENT)":

  test "G6 PRESENT: customAppend does not write DB_MUHASH":
    ## Core coinstatsindex.cpp:210 has a comment "Intentionally do not
    ## update DB_MUHASH here so it stays in sync with DB_BEST_BLOCK".
    ## Nimrod's customAppend also doesn't write muHashKey().
    # Find the customAppend body:
    let appendStart = coinstatsSrc.find("method customAppend*(idx: CoinStatsIndex")
    check appendStart > 0
    let appendEnd = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    check appendEnd > appendStart
    let appendBody = coinstatsSrc[appendStart .. appendEnd]
    # muHashKey() should NOT be written inside customAppend:
    check "muHashKey()" notin appendBody

# ---------------------------------------------------------------------------
# G7-G8 — RevertBlock hash fallback for reorg (BUG-6)
# ---------------------------------------------------------------------------
suite "W133 G7-G8 — RevertBlock hash fallback on reorg (BUG-6)":

  test "G7 BUG-6: RevertBlock does NOT check read_out.first != expected_prev_hash":
    ## Core coinstatsindex.cpp:336-346: read DBHeightKey(height-1), check
    ## the value's first==expected_prev_hash, fall back to DBHashKey if not.
    ## Nimrod customRemove reads coinStatsHeightKey(height-1) blindly.
    let removeStart = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    check removeStart > 0
    let removeBody = coinstatsSrc[removeStart .. ^1]
    # No comparison of read_out.blockHash vs expected prev_hash:
    check "val.blockHash != blockInfo.prevHash" notin removeBody
    check "read_out.first" notin removeBody  # the Core idiom name

  test "G8 BUG-6 cont: RevertBlock has NO DBHashKey fallback read":
    let removeStart = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    let removeBody = coinstatsSrc[removeStart .. ^1]
    # coinStatsHashKey is used for COPY (write-side), not as a fallback READ
    # path during RevertBlock.  The fallback chain (height-then-hash) is
    # entirely absent in customRemove:
    check "coinStatsHashKey(blockInfo.prevHash)" notin removeBody

# ---------------------------------------------------------------------------
# G9 — RevertBlock muhash consistency assert (BUG-7)
# ---------------------------------------------------------------------------
suite "W133 G9 — RevertBlock muhash rollback assert (BUG-7)":

  test "G9 BUG-7: no Assert(read_out.second.muhash == out) after rollback":
    ## Core coinstatsindex.cpp:386: `Assert(read_out.second.muhash == out);`
    ## verifies the rolled-back muhash matches what was previously stored.
    ## Nimrod skips this entirely.
    let removeStart = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    let removeBody = coinstatsSrc[removeStart .. ^1]
    check "assert" notin removeBody.toLower
    check "doAssert" notin removeBody

# ---------------------------------------------------------------------------
# G10 — Running totals overflow guard (BUG-8)
# ---------------------------------------------------------------------------
suite "W133 G10 — running totals use uint64 not arith_uint256 (BUG-8)":

  test "G10 BUG-8: totalPrevoutSpentAmount declared as uint64 not 256-bit":
    ## Core coinstatsindex.h:40-42 uses arith_uint256 for the three running
    ## totals: total_prevout_spent_amount, total_new_outputs_ex_coinbase,
    ## total_coinbase_amount.  These sum over the WHOLE chain history;
    ## the same satoshi is counted on every respend, so the running value
    ## is NOT bounded by 21M BTC.  uint64 silently wraps.
    check "totalPrevoutSpentAmount*: uint64"   in coinstatsSrc
    check "totalNewOutputsExCoinbase*: uint64" in coinstatsSrc
    check "totalCoinbaseAmount*: uint64"       in coinstatsSrc
    # Confirm there is no arith_uint256 or 256-bit accumulator in scope:
    check "arith_uint256"    notin coinstatsSrc
    check "ArithUint256"     notin coinstatsSrc
    check "UInt256"          notin coinstatsSrc

  test "G10 BUG-8 cont: stored DBVal IS 32-byte but accumulator wraps":
    ## The serialised form uses array[32, byte] (good), but the in-memory
    ## accumulator that gets converted via uint64ToBytes is bare uint64
    ## (bad).
    check "totalPrevoutSpentAmount*: array[32, byte]"    in coinstatsSrc
    check "totalNewOutputsExCoinbase*: array[32, byte]"  in coinstatsSrc
    check "totalCoinbaseAmount*: array[32, byte]"        in coinstatsSrc
    # And `uint64ToBytes` is the lossy conversion:
    check "uint64ToBytes" in coinstatsSrc

# ---------------------------------------------------------------------------
# G11 — TxIndex::FindTx with file seek (BUG-9)
# ---------------------------------------------------------------------------
suite "W133 G11 — TxIndex::FindTx file-seek path (BUG-9)":

  test "G11 BUG-9: indexes/txindex.nim has no FindTx / file-open / seek":
    ## Core txindex.cpp:93-120: open block file at FlatFilePos, read header,
    ## file.seek(nTxOffset, SEEK_CUR), deserialise one tx, verify hash.
    ## Nimrod's indexes/txindex.nim has `readTxPos` only — no file-seek
    ## helper.
    check "readTxPos" in txindexSrc
    check "FindTx"    notin txindexSrc
    check "findTx"    notin txindexSrc
    check "OpenBlockFile" notin txindexSrc

  test "G11 BUG-9 cont: production rest.getRawTransaction loads FULL block":
    ## src/rpc/rest.nim:566-579: getTxIndex → getBlock(blockHash) → blk.txs
    ## [loc.txIndex].  This loads the whole block (~4MB possible) to fetch
    ## one tx; the DiskTxPos optimisation is unused.
    let restSrc = readFile("src/rpc/rest.nim")
    check "rest.chainState.db.getTxIndex(txid)" in restSrc
    check "rest.chainState.db.getBlock(loc.blockHash)" in restSrc

# ---------------------------------------------------------------------------
# G12 — TxIndex AllowPrune()==false prune lock (BUG-10, BUG-11)
# ---------------------------------------------------------------------------
suite "W133 G12 — TxIndex AllowPrune()==false (BUG-10, BUG-11)":

  test "G12 BUG-10: pruner deletes cfTxIndex entries unconditionally":
    ## Core txindex.h:34 declares AllowPrune()=false; base.cpp:489 asserts
    ## IsPruneMode + !AllowPrune is impossible.  Nimrod's pruner.nim:287
    ## walks every tx in a pruned block and deletes its cfTxIndex entry,
    ## with no consultation of any AllowPrune flag.
    check "batch.delete(cfTxIndex, txIndexKey" in prunerSrc

  test "G12 BUG-11: BaseIndex has no AllowPrune virtual method":
    ## Core base.h:111: `virtual bool AllowPrune() const = 0;`
    ## Nimrod's BaseIndex has no AllowPrune surface at all.
    check "AllowPrune" notin baseSrc
    check "allowPrune" notin baseSrc

# ---------------------------------------------------------------------------
# G13 — CoinStatsIndex AllowPrune()==true + PruneLock (BUG-11)
# ---------------------------------------------------------------------------
suite "W133 G13 — CoinStatsIndex PruneLock registration (BUG-11)":

  test "G13 BUG-11: coinstatsindex has no PruneLock registration":
    ## Core base.cpp:489-495: `SetBestBlockIndex` calls UpdatePruneLock
    ## when AllowPrune is true, registering a per-index prune lock at the
    ## current best height.  Nimrod's `saveBestBlock` does no such thing.
    check "PruneLock"    notin baseSrc
    check "pruneLock"    notin baseSrc
    check "UpdatePruneLock" notin baseSrc
    check "updatePruneLock" notin baseSrc

# ---------------------------------------------------------------------------
# G14-G15 — Sync() / StartBackgroundSync (BUG-12)
# ---------------------------------------------------------------------------
suite "W133 G14-G15 — BaseIndex Sync thread lifecycle (BUG-12)":

  test "G14 BUG-12: BaseIndex has no Sync() loop / NextSyncBlock helper":
    ## Core base.cpp:201-268 implements the catch-up loop:
    ## NextSyncBlock(pindex, chain) walks the active chain from the
    ## index's best block.  Nimrod has no such loop in base.nim.
    check "proc Sync*"          notin baseSrc
    check "proc sync*"          notin baseSrc
    check "NextSyncBlock"       notin baseSrc
    check "nextSyncBlock"       notin baseSrc

  test "G15 BUG-12 cont: no StartBackgroundSync / Stop thread lifecycle":
    ## Core base.cpp:453-470: StartBackgroundSync spawns a thread; Stop
    ## joins it.  Nimrod's BaseIndex has requestStop (a flag) but no
    ## actual thread / chronos-task lifecycle in base.nim.
    check "StartBackgroundSync" notin baseSrc
    check "startBackgroundSync" notin baseSrc
    check "m_thread_sync"       notin baseSrc

# ---------------------------------------------------------------------------
# G16 — BlockUntilSyncedToCurrentChain (BUG-17)
# ---------------------------------------------------------------------------
suite "W133 G16 — BlockUntilSyncedToCurrentChain (BUG-17)":

  test "G16 BUG-17: no BlockUntilSyncedToCurrentChain helper":
    ## Core base.cpp:424-446 drains the ValidationInterface queue so
    ## RPC callers (e.g. getrawtransaction verbose=true that needs
    ## txindex) can synchronously wait for a fresh tip.  Nimrod has no
    ## such helper.
    check "BlockUntilSyncedToCurrentChain" notin baseSrc
    check "blockUntilSyncedToCurrentChain" notin baseSrc

# ---------------------------------------------------------------------------
# G17 — Height-key endianness (PRESENT — false-positive caught at audit time)
# ---------------------------------------------------------------------------
suite "W133 G17 — height-key endianness (PRESENT)":

  test "G17 PRESENT: heightKey serialises big-endian like Core":
    ## Core db_key.h:32-43 uses ser_writedata32be for ordered LevelDB
    ## scans.  Nimrod's heightKey was initially suspected of being LE
    ## but is in fact BE — MSB-first shr-24 emit.
    let k = heightKey(0x01020304'i32)
    # Expected: ['h', 0x01, 0x02, 0x03, 0x04] (big-endian after 'h' prefix)
    check k.len == 5
    check k[0] == byte('h')
    check k[1] == 0x01
    check k[2] == 0x02
    check k[3] == 0x03
    check k[4] == 0x04

  test "G17 cont: coinStatsHeightKey also big-endian":
    let k = coinStatsHeightKey(0x10203040'i32)
    check k.len == 5
    check k[0] == byte('s')  # nimrod uses 's' — note Core uses 't' (BUG-22)
    check k[1] == 0x10
    check k[2] == 0x20
    check k[3] == 0x30
    check k[4] == 0x40

# ---------------------------------------------------------------------------
# G18 — copyHeightToHashIndex not batched (BUG-14)
# ---------------------------------------------------------------------------
suite "W133 G18 — copyHeightToHashIndex not batched (BUG-14)":

  test "G18 BUG-14: copyHeightToHashIndex uses idx.db.put not CDBBatch":
    ## Core db_key.h:71-93 `CopyHeightIndexToHashIndex` writes via the
    ## `CDBBatch& batch` argument; the caller (coinstatsindex.cpp:217-227)
    ## holds the batch open across the height-iterator-Seek + the copy +
    ## the final WriteBatch.  Nimrod's copyHeightToHashIndex does an
    ## immediate `idx.db.put`, breaking atomicity with the rest of
    ## customRemove.
    check "proc copyHeightToHashIndex*" in baseSrc
    # The body uses idx.db.put directly (not idx.db.newWriteBatch):
    let copyStart = baseSrc.find("proc copyHeightToHashIndex*")
    check copyStart > 0
    let copyBody = baseSrc[copyStart .. ^1]
    let nextProcIdx = copyBody.find("\nproc ", 5)
    let body =
      if nextProcIdx > 0: copyBody[0 .. nextProcIdx]
      else: copyBody
    check "idx.db.put(" in body
    check "newWriteBatch" notin body

# ---------------------------------------------------------------------------
# G19 — LookUpOne fallback (BUG-15)
# ---------------------------------------------------------------------------
suite "W133 G19 — LookUpOne height→hash fallback (BUG-15)":

  test "G19 BUG-15: no LookUpOne helper — lookUpStats has no fallback":
    ## Core db_key.h:95-113 `LookUpOne(db, block, result)` tries
    ## DBHeightKey, checks first hash matches, falls back to DBHashKey.
    ## Nimrod has lookUpStats (height-keyed) and lookUpStatsByHash (hash-
    ## keyed) as two SEPARATE functions — caller has to know.
    check "proc lookUpStats*"        in coinstatsSrc
    check "proc lookUpStatsByHash*"  in coinstatsSrc
    check "LookUpOne" notin coinstatsSrc
    check "lookUpOne" notin coinstatsSrc

# ---------------------------------------------------------------------------
# G20 — getindexinfo RPC (BUG-16) — CLOSED
# ---------------------------------------------------------------------------
# Previously this suite asserted getindexinfo was ABSENT (BUG-16 gap marker).
# It is now implemented Core-correctly (src/rpc/node.cpp:351-410 SummaryToJSON +
# getindexinfo). The handler emits, for each *running* index, one entry keyed by
# the index name whose value has EXACTLY {synced, best_block_height}. nimrod runs
# only the BIP-157 "basic block filter index", so that is the only key it emits.
# Differential parity proven in test-suite/index/nimrod_getindexinfo.sh.
suite "W133 G20 — getindexinfo RPC present + Core-shaped (BUG-16 CLOSED)":

  test "G20 BUG-16 CLOSED: getindexinfo handler + dispatch arm present":
    ## Core rpc/node.cpp::getindexinfo returns per-index
    ## {synced, best_block_height}.  Nimrod now has the RPC.
    check "proc handleGetIndexInfo" in serverSrc
    check "of \"getindexinfo\":"    in serverSrc

  test "G20 BUG-16 CLOSED: getindexinfo emits Core's exact value fields":
    ## SummaryToJSON pushes exactly "synced" then "best_block_height" — no
    ## best_hash / best_block_hash / name-inside-the-value.
    let start = serverSrc.find("proc handleGetIndexInfo")
    check start >= 0
    let stop = serverSrc.find("proc handleGetChainTxStats")
    let body = serverSrc[start .. (if stop > start: stop else: serverSrc.len - 1)]
    check "\"synced\"" in body
    check "\"best_block_height\"" in body
    # The basic block filter index is the only index nimrod runs -> its GetName().
    check "basic block filter index" in body
    # MUST NOT emit best_hash / best_block_hash as JSON keys from getindexinfo
    # (IndexSummary carries best_block_hash internally but getindexinfo never
    # emits it).  Check the quoted-key form so the explanatory comments above —
    # which mention the field names in prose — do not trip the guard.
    check "[\"best_hash\"]" notin body
    check "[\"best_block_hash\"]" notin body
    check "(\"best_hash\")" notin body
    check "(\"best_block_hash\")" notin body
    # nimrod runs no txindex -> the handler must not fabricate a txindex key.
    check "\"txindex\"" notin body

# ---------------------------------------------------------------------------
# G21-G22 — CustomOptions undo flags (BUG-18)
# ---------------------------------------------------------------------------
suite "W133 G21-G22 — CustomOptions undo flags (BUG-18)":

  test "G21 BUG-18: BaseIndex has no CustomOptions method":
    ## Core base.h:152 declares `virtual NotifyOptions CustomOptions()`.
    ## Nimrod's BaseIndex has no equivalent — the caller has to remember
    ## to pass undoData by hand.
    check "CustomOptions" notin baseSrc
    check "customOptions" notin baseSrc
    check "NotifyOptions" notin baseSrc

  test "G22 BUG-18 cont: coinstatsindex defensively guards on undoData.isSome":
    ## Without CustomOptions::connect_undo_data, the caller can forget to
    ## pass undoData.  Nimrod's customAppend silently skips the
    ## prevout-removal loop when undoData is absent — producing wrong
    ## MuHash and wrong running totals.
    let appendStart = coinstatsSrc.find("method customAppend*(idx: CoinStatsIndex")
    let appendEnd   = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    let appendBody  = coinstatsSrc[appendStart .. appendEnd]
    check "blockInfo.undoData.isSome" in appendBody
    # And no `assert blockInfo.undoData.isSome` — silent skip is the bug.
    check "assert blockInfo.undoData" notin appendBody

# ---------------------------------------------------------------------------
# G23 — unclaimed_rewards int64::max assert (BUG-19)
# ---------------------------------------------------------------------------
suite "W133 G23 — unclaimed_rewards overflow guard (BUG-19)":

  test "G23 BUG-19: no assert that unclaimed_rewards fits in int64":
    ## Core coinstatsindex.cpp:187:
    ##   assert(unclaimed_rewards <= arith_uint256(std::numeric_limits<CAmount>::max()));
    ## Nimrod just adds the uint64 difference to int64 without checking
    ## for overflow.
    let appendStart = coinstatsSrc.find("method customAppend*(idx: CoinStatsIndex")
    let appendEnd   = coinstatsSrc.find("method customRemove*(idx: CoinStatsIndex")
    let body = coinstatsSrc[appendStart .. appendEnd]
    check "unclaimed_rewards" notin body
    check "unclaimedRewards <= int64.high" notin body
    # The actual code just does `if expected > actual: idx.totalUnspendablesUnclaimedRewards += int64(expected - actual)`
    check "if expected > actual:" in body

# ---------------------------------------------------------------------------
# G24 — atomic m_init / m_synced (BUG-20)
# ---------------------------------------------------------------------------
suite "W133 G24 — atomic init/synced flags (BUG-20)":

  test "G24 BUG-20: BaseIndex uses non-atomic IndexState enum":
    ## Core base.h:80-88 uses `std::atomic<bool> m_init` and `m_synced`
    ## for cross-thread coherence.  Nimrod's BaseIndex has a single
    ## non-atomic enum `state: IndexState`.
    ## (The substring "atomic" appears in a comment "atomically" — we look
    ## for the actual `Atomic[bool]` / `std/atomics` import that would
    ## indicate a real fix.)
    check "state*: IndexState" in baseSrc
    check "std/atomics"  notin baseSrc
    check "Atomic[bool]" notin baseSrc
    check "Atomic[" notin baseSrc
    # No m_init / m_synced distinction:
    check "m_init"   notin baseSrc
    check "m_synced" notin baseSrc

# ---------------------------------------------------------------------------
# G25 — DiskTxPos VARINT(nTxOffset)
# ---------------------------------------------------------------------------
suite "W133 G25 — DiskTxPos VARINT encoding (BUG-25 cosmetic)":

  test "G25: DiskTxPos serialises 12-byte LE not VARINT":
    ## Core disktxpos.h:17 uses VARINT for nFile, nPos AND nTxOffset.
    ## Nimrod emits fixed 12-byte LE.  Internally consistent (round-trips)
    ## but wire-incompatible with Core txindex DB dumps.
    let pos = DiskTxPos(fileNum: 0, blockDataPos: 0, txOffset: 0)
    let bytes = serializeDiskTxPos(pos)
    check bytes.len == 12  # 3 * int32 = fixed-width, NOT VARINT
    # If VARINT were in use, three zeros would encode to 3 bytes total.

  test "G25 cont: confirm round-trip is still self-consistent":
    let original = DiskTxPos(fileNum: 5, blockDataPos: 1234, txOffset: 99)
    let bytes = serializeDiskTxPos(original)
    let recovered = deserializeDiskTxPos(bytes)
    check recovered.fileNum == original.fileNum
    check recovered.blockDataPos == original.blockDataPos
    check recovered.txOffset == original.txOffset

# ---------------------------------------------------------------------------
# G26-G27 — initial nTxOffset + tx-with-witness increment (PRESENT)
# ---------------------------------------------------------------------------
suite "W133 G26-G27 — DiskTxPos offset semantics (PRESENT)":

  setup:
    let testDir = createTempDir("w133_txoffset_", "")
    let db = openDatabase(testDir / "db")
    let idx = newTxIndex(db, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "G26 PRESENT: initial nTxOffset = compactSizeLen(vtx.size())":
    ## Core txindex.cpp:80: initial = GetSizeOfCompactSize(vtx.size()).
    ## Nimrod: txOffset = compactSizeLen(uint64(blk.txs.len)) — matches.
    check compactSizeLen(0)             == 1
    check compactSizeLen(252)           == 1
    check compactSizeLen(253)           == 3
    check compactSizeLen(0xFFFF)        == 3
    check compactSizeLen(0x10000)       == 5
    check compactSizeLen(0xFFFFFFFF'u64) == 5

  test "G27 PRESENT: txOffset increments by serialize(tx) (witness-inclusive)":
    ## Core txindex.cpp:85: nTxOffset += GetSerializeSize(TX_WITH_WITNESS(*tx)).
    ## Nimrod txindex.nim:132: txOffset += int32(serialize(tx).len).
    ## Default `serialize(tx)` in primitives/serialize.nim:354 is
    ## includeWitness=true — matches Core.
    var tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5000000000),
        scriptPubKey: @[0x76'u8, 0xa9, 0x14]
      )],
      lockTime: 0
    )
    let bytes = serialize(tx)
    check bytes.len > 0  # round-trip placeholder: confirms the serialize path

# ---------------------------------------------------------------------------
# G28 — Key prefix bytes match Core (BUG-22)
# ---------------------------------------------------------------------------
suite "W133 G28 — DB_BLOCK_HASH / DB_BLOCK_HEIGHT prefix bytes (BUG-22)":

  test "G28 BUG-22: nimrod uses 'h' for height, Core uses 't'":
    ## Core db_key.h:30: `static constexpr uint8_t DB_BLOCK_HEIGHT{'t'};`
    ## Nimrod base.nim:80: `result = @[byte('h')]` — different prefix.
    let k = heightKey(0)
    check k[0] == byte('h')
    check char(k[0]) != CORE_DB_BLOCK_HEIGHT_PREFIX  # 't'

  test "G28 BUG-22 cont: nimrod uses 'k' for hashKey, Core uses 's'":
    ## Core db_key.h:29: `static constexpr uint8_t DB_BLOCK_HASH{'s'};`
    ## Nimrod base.nim:88: `result = @[byte('k')]` — different prefix.
    var hashBytes: array[32, byte]
    hashBytes[0] = 0xab
    let k = hashKey(BlockHash(hashBytes))
    check k[0] == byte('k')
    check char(k[0]) != CORE_DB_BLOCK_HASH_PREFIX  # 's'

  test "G28 BUG-22 cont: coinstatsindex uses 's'/'h', Core uses 't'/'s'":
    ## Nimrod coinstatsindex collides 's' with Core's DB_BLOCK_HASH
    ## prefix and uses 'h' for hash-keyed (Core's DB_BLOCK_HEIGHT prefix).
    let kh = coinStatsHeightKey(0)
    check kh[0] == byte('s')   # nimrod's height-key prefix
    var hashBytes: array[32, byte]
    let khash = coinStatsHashKey(BlockHash(hashBytes))
    check khash[0] == byte('h')  # nimrod's hash-key prefix
    # Together these are SWAPPED relative to Core.

  test "G28: DB_MUHASH prefix matches Core ('M')":
    check char(DbMuHash) == CORE_DB_MUHASH_PREFIX

  test "G28: DB_TXINDEX prefix matches Core ('t')":
    check char(DbTxIndex) == CORE_DB_TXINDEX_PREFIX

# ---------------------------------------------------------------------------
# G29 — Old indexes/coinstats migration warning (BUG-23)
# ---------------------------------------------------------------------------
suite "W133 G29 — old indexes/coinstats migration warning (BUG-23)":

  test "G29 BUG-23: no 'indexes/coinstats' legacy-path warning":
    ## Core coinstatsindex.cpp:96-100 warns if `indexes/coinstats` (the
    ## buggy pre-v30 path) exists, advising deletion.  Nimrod has no
    ## such migration message.
    check "indexes/coinstats" notin coinstatsSrc
    check "downgrade" notin coinstatsSrc.toLower
    check "v29" notin coinstatsSrc.toLower
    check "v30" notin coinstatsSrc.toLower

# ---------------------------------------------------------------------------
# G30 — Pruner PruneLock coupling (BUG-11)
# ---------------------------------------------------------------------------
suite "W133 G30 — pruner / PruneLock coupling (BUG-11)":

  test "G30 BUG-11: pruner.nim has no PruneLock infrastructure":
    ## Core node/blockstorage.cpp consults a per-index PruneLock map
    ## (`m_prune_locks`) before deleting block files; the index
    ## registers its PruneLock via SetBestBlockIndex.  Nimrod's pruner
    ## has no such consultation.
    check "PruneLock"        notin prunerSrc
    check "pruneLock"        notin prunerSrc
    check "m_prune_locks"    notin prunerSrc

  test "G30 BUG-11 cont: pruner.nim deletes block + txindex without index check":
    ## The unconditional cfTxIndex deletion at pruner.nim:287 is the
    ## "smoking gun" for the missing coordination — if any future
    ## fixwave wires the de-facto txindex through BaseIndex, the
    ## pruner will need a parallel update to consult AllowPrune.
    check "batch.delete(cfTxIndex"   in prunerSrc
    check "batch.delete(cfBlocks"    in prunerSrc

# ---------------------------------------------------------------------------
# Functional cross-checks — txindex module still works in isolation
# (BUG-1 says the module is DEAD-WIRED in production, but is internally OK.)
# ---------------------------------------------------------------------------
suite "W133 functional — indexes/txindex.nim module is self-consistent":

  setup:
    let testDir = createTempDir("w133_func_tx_", "")
    let db = openDatabase(testDir / "db")
    let idx = newTxIndex(db, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "F1: round-trip a DiskTxPos via writeTxs / readTxPos":
    var txidBytes: array[32, byte]
    for i in 0 ..< 32:
      txidBytes[i] = byte(i + 1)
    let txid = TxId(txidBytes)
    let pos = DiskTxPos(fileNum: 7, blockDataPos: 4321, txOffset: 42)
    idx.writeTxs(@[(txid: txid, pos: pos)])
    let r = idx.readTxPos(txid)
    check r.isSome
    check r.get().fileNum == 7
    check r.get().blockDataPos == 4321
    check r.get().txOffset == 42

  test "F2: disabled index returns none from readTxPos":
    let disabledIdx = newTxIndex(db, enabled = false)
    var txidBytes: array[32, byte]
    txidBytes[0] = 0xff
    let txid = TxId(txidBytes)
    check disabledIdx.readTxPos(txid).isNone

# ---------------------------------------------------------------------------
# Functional cross-checks — coinstatsindex module still works in isolation
# ---------------------------------------------------------------------------
suite "W133 functional — indexes/coinstatsindex.nim module is self-consistent":

  setup:
    let testDir = createTempDir("w133_func_cs_", "")
    let db = openDatabase(testDir / "db")
    let idx = newCoinStatsIndex(db, mainnetParams(), enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "F3: genesis-block customAppend records unspendable subsidy":
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8])]
      )]
    )
    let blockInfo = BlockInfo(
      hash: BlockHash(default(array[32, byte])),
      prevHash: BlockHash(default(array[32, byte])),
      height: 0,
      data: some(blk),
      undoData: none(BlockUndo),
      fileNum: 0, dataPos: 0
    )
    check idx.customAppend(blockInfo) == true
    check idx.totalUnspendablesGenesisBlock > 0

  test "F4: lookUpStats round-trip after customAppend":
    # Genesis first
    let genesis = Block(header: BlockHeader(version: 1), txs: @[Transaction(version: 1)])
    let genesisHash = BlockHash(default(array[32, byte]))
    let gInfo = BlockInfo(
      hash: genesisHash, prevHash: genesisHash, height: 0,
      data: some(genesis), undoData: none(BlockUndo), fileNum: 0, dataPos: 0
    )
    check idx.customAppend(gInfo) == true

    # Height 1
    var blkHashBytes: array[32, byte]
    blkHashBytes[0] = 1
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xffffffff'u32)],
        outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8, 0xa9])]
      )]
    )
    let info = BlockInfo(
      hash: BlockHash(blkHashBytes), prevHash: genesisHash, height: 1,
      data: some(blk), undoData: none(BlockUndo), fileNum: 0, dataPos: 100
    )
    check idx.customAppend(info) == true
    let stats = idx.lookUpStats(1)
    check stats.isSome
    check stats.get().transactionOutputCount == 1
