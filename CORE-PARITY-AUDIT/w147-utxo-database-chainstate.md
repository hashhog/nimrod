# W147 — UTXO database / chainstate audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W147).
Concurrent-agent coordination: 3 OTHER audit waves (W146/W148/W149) running in
parallel sub-agents.

Scope: CCoinsView interface + CCoinsViewCache (DIRTY/FRESH flags, Flush vs Sync,
SpendCoin / AccessCoin / AddCoin semantics) + CCoinsViewDB (LevelDB 'C'+outpoint
key, Coin compression via VARINT(code) + TxOutCompression, obfuscate_key XOR,
DB_HEAD_BLOCKS two-phase commit) + FlushStateToDisk triggers (dbcache,
PERIODIC, IF_NEEDED, ALWAYS) + obfuscate_key.

Targets in nimrod:
- `src/storage/utxo_cache.nim` (559 LOC) — full CCoinsView hierarchy
  reimplementation: `CoinsView` / `CoinsViewDB` / `CoinsViewCache` with
  `CoinEntry { coin, dirty, fresh }` flags. **DEAD MODULE — imported only
  by tests** (`tests/test_utxo_cache.nim`, `tests/test_w100_coins_view_cache.nim`,
  `tests/test_perf.nim`); never imported by any `src/` file.
- `src/storage/chainstate.nim` (2126 LOC) — production UTXO path:
  `ChainDb` (raw RocksDB CRUD lines 274-447) + `ChainState`
  (cache + reorg/IBD lines 449-2126). Cache layer is a flat
  `Table[OutPoint, UtxoEntry]` with **NO dirty/fresh flags**.
- `src/storage/db.nim` (616 LOC) — RocksDB C-API wrapper with 6 CFs
  (`cfDefault`, `cfBlocks`, `cfBlockIndex`, `cfUtxo`, `cfTxIndex`, `cfMeta`).
- `src/storage/snapshot.nim` (918 LOC) — Core-compatible `compressAmount` /
  `compressScript` / `writeCompressedScript` / `decompressSpecialScript`
  exists but used **only** by snapshot dump/load (assumeUTXO), never by
  chainstate.
- `src/storage/undo.nim` (393 LOC) — flat-file undo (`rev*.dat`).
- `src/nimrod.nim:1672-1776` — XOR `xorDeobfuscate` helper for Core blk*.dat
  obfuscation **on import only** (not for nimrod's own DB).

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/coins.h:34-90` — `Coin` (CTxOut + fCoinBase:1 + nHeight:31), with
  `Serialize` writing `VARINT((nHeight << 1) | fCoinBase)` then
  `Using<TxOutCompression>(out)`. `CTxOut::IsNull() = (nValue == -1)`.
- `src/coins.h:109-260` — `CCoinsCacheEntry` with DIRTY/FRESH doubly-linked
  list, `SetDirty`/`SetFresh`/`SetClean`, sentinel pattern.
- `src/coins.cpp:89-130` — `CCoinsViewCache::AddCoin` (FRESH only when
  `!possible_overwrite` AND entry is spent and not dirty).
- `src/coins.cpp:153-175` — `CCoinsViewCache::SpendCoin` (FRESH delete-path
  optimization; otherwise SetDirty + Coin::Clear).
- `src/coins.cpp:208-300` — `CCoinsViewCache::BatchWrite` parent-cache merge
  (FRESH-flag misapplied → throw; FRESH-in-grandparent-erase optimization).
- `src/coins.cpp:279-300` — `Flush(reallocate_cache=true)` vs `Sync()`:
  Flush clears cacheCoins, Sync keeps but clears flagged status.
- `src/txdb.cpp:23-27` — `DB_COIN='C'`, `DB_BEST_BLOCK='B'`, `DB_HEAD_BLOCKS='H'`,
  legacy `DB_COINS='c'`.
- `src/txdb.cpp:42-51` — `CoinEntry::SERIALIZE_METHODS` = `key=DB_COIN`,
  `outpoint.hash` (32 bytes raw), `VARINT(outpoint.n)`. **VARINT not CompactSize.**
- `src/txdb.cpp:100-164` — `CCoinsViewDB::BatchWrite` two-phase commit:
  (1) erase DB_BEST_BLOCK + write DB_HEAD_BLOCKS=[hashBlock,old_tip];
  (2) write coin batches; (3) erase DB_HEAD_BLOCKS + write DB_BEST_BLOCK.
- `src/compressor.cpp` — `CompressAmount` (mantissa+exponent), `CompressScript`
  (P2PKH/P2SH/compressed-P2PK 1-byte tag).
- `src/dbwrapper.h:188-192` — `m_obfuscation`, `OBFUSCATION_KEY="\0obfuscate_key"`
  (14 bytes, null-prefixed).
- `src/dbwrapper.cpp:253-262` — autogenerates random 8-byte XOR key on first open
  of an obfuscate-enabled DB.
- `src/validation.cpp` — `FlushStateMode { NONE, IF_NEEDED, PERIODIC, ALWAYS }`,
  `FlushStateToDisk` triggers (dbcache exceed, 1-hour PERIODIC, 24-hour DATABASE).

## Status

**BUGS FOUND — 21 distinct defects.** Of these:

- **P0-CDIV** — 6 (chainstate DB byte format diverges from Core — VARINT vs
  CompactSize for height-code AND vout-key; coin serialization omits
  TxOutCompression so coins are stored uncompressed; obfuscate_key absent —
  nimrod chainstate cannot be opened by Core and vice-versa; CCoinsViewCache
  module is dead — only `Table[OutPoint, UtxoEntry]` without DIRTY/FRESH in
  production path → cache cannot model "spent and dirty" so a memory-only
  cache can never flush spentness to disk; `addCoin` line 311 marks a new
  outpoint as `fresh=true` unconditionally even when `possibleOverwrite=true`
  for coinbase BIP-30 cases — diverges from Core which keeps fresh=false on
  the overwrite path; legacy `ChainDb.disconnectBlock` (line 2078) NEVER
  restores spent inputs but is reachable via signature export — UTXO
  resurrection bug class).
- **P0-SEC** — 1 (no DB_HEAD_BLOCKS two-phase commit; a crash between
  `bestblock` write and the coin-batch durability fence leaves the
  chainstate in a state where the recovery code cannot detect the
  inconsistency — Core's `old_heads[0] != hashBlock` assert fires; nimrod
  silently boots with corrupt UTXO set).
- **P0** — 0.
- **P1** — 7 (sentinel mismatch: nimrod `isSpent = (value==0 AND script.len==0)`
  vs Core `nValue == -1` — wrong-sentinel UTXOs slip through cache layers
  semantically; `dynamicMemoryUsage` undercount in CCoinsViewCache
  (entryOverhead=60 vs realistic ~140 with hashtable node + pointer overhead);
  `shouldFlush` uses entry-count threshold not byte-budget (Core's dbcache
  is 450 MiB); FRESH-misapplied parent-cache check missing — Core throws
  logic_error, nimrod silently overwrites; legacy `cdb.disconnectBlock`
  dead-code parallel to `cs.disconnectBlock`; no `Cursor()` API on CoinsView
  (nimrod uses ad-hoc `iterCf` on the cfUtxo CF — works, but cross-impl
  consumers expect the cursor interface); no `AccessCoin` / `coinEmpty`
  sentinel (callers must check `Option[Coin]` instead of receiving a null Coin).
- **P2** — 5 (no `Reset` / `ReallocateCache` after Flush — memory not
  reclaimed; no `Uncache` operator-tool RPC equivalent; no `SanityCheck`
  invariant check on cache linked-list; no `HaveCoinInCache` optimization
  used in production (cache fall-through misses opportunity); compressor
  module is unused-but-not-deleted dead module relative to chainstate path).
- **P3** — 2 (no separation between cache+DB views in production — `ChainState`
  IS the cache and IS the DB wrapper; comment-as-confession: chainstate.nim
  references "FRESH optimization" but production has no FRESH flag).

## Bug list

---

### BUG-1 — Coin VARINT field written as CompactSize → chainstate DB byte-format diverges from Core for any height >= 64

**Severity:** P0-CDIV
**File:** src/storage/utxo_cache.nim:73-74
**Core ref:** bitcoin-core/src/coins.h:66-67 (`uint32_t code = nHeight * uint32_t{2} + fCoinBase; ::Serialize(s, VARINT(code));`)

**Description:** `serializeCoin` writes the `(height<<1 | isCoinbase)` code
using `writeCompactSize`, but Core uses Bitcoin's WriteVarInt (NOT the
wire-protocol CompactSize). The two encodings differ for any `code >= 128`,
which means **every coin at height >= 64** is stored with one byte less
than Core. The file's own header comment claims "VARINT(code)" but the
implementation calls `writeCompactSize`. Nimrod even has a fully working
`writeVarInt` in `src/primitives/serialize.nim:153` — it's just not
called from this path.

**Excerpt:**
```nim
proc serializeCoin*(coin: Coin): seq[byte] =
  ## Serialize coin for RocksDB storage
  ## Format: VARINT((coinbase ? 1 : 0) | (height << 1)) || TxOut
  var w = BinaryWriter()
  let code = uint32(coin.height) * 2 + (if coin.isCoinbase: 1 else: 0)
  w.writeCompactSize(uint64(code))     # WRONG: should be writeVarInt
  w.writeTxOut(coin.txOut)
  w.data
```

For reference, `serialize.nim:148-151` itself documents the divergence:
```
#   CompactSize(128) = [0x80]           (1 byte)
#   WriteVarInt(128) = [0x80, 0x00]     (2 bytes)
```

**Impact:** nimrod's UTXO storage byte-format is byte-incompatible with
Core for any post-genesis coin (any height >= 64 = block ~64 onward).
A cross-impl chainstate clone — copying nimrod's chainstate into a Core
node's `chainstate/` directory — would fail to deserialize. This also
affects the dead `utxo_cache.nim` module (so even if it were wired up it
would have the same bug). Same code copy-pasted into a future "make it
Core-compatible" sprint silently breaks regardless.

---

### BUG-2 — Coin TxOut written uncompressed (no TxOutCompression) → chainstate is ~30% larger than Core and byte-incompatible

**Severity:** P0-CDIV
**File:** src/storage/utxo_cache.nim:75 (and src/storage/chainstate.nim:222-227)
**Core ref:** bitcoin-core/src/coins.h:64-69 (`::Serialize(s, Using<TxOutCompression>(out));`)

**Description:** Core's `Coin::Serialize` wraps the `CTxOut` in
`TxOutCompression` — which calls `CompressAmount` on the value and
`CompressScript` on the scriptPubKey (mapping P2PKH/P2SH/compressed-P2PK
into a 1-byte tag + 20/32 byte payload). nimrod's `serializeCoin` calls
plain `writeTxOut` (`int64 value + varbytes script`). Similarly, the
production `serializeUtxoEntry` in `chainstate.nim:222-227` also calls
raw `writeTxOut`. nimrod has `compressAmount` and `writeCompressedScript`
in `src/storage/snapshot.nim:119-220` but they are wired ONLY for
assumeUTXO snapshot dump/load, not for the chainstate DB.

**Excerpt (production path, chainstate.nim:222-227):**
```nim
proc serializeUtxoEntry(entry: UtxoEntry): seq[byte] =
  var w = BinaryWriter()
  w.writeTxOut(entry.output)        # raw 8-byte LE value + varbytes script
  w.writeInt32LE(entry.height)      # raw 4-byte int32 — Core uses VARINT
  w.writeUint8(if entry.isCoinbase: 1 else: 0)  # separate byte — Core packs in code
  w.data
```

**Impact:** Two-fold. (a) **Storage bloat:** every coin uses an extra
2-30 bytes vs Core (script-type compression saves ~30 bytes per P2PKH
output). For ~120M UTXOs that's ~3 GB of extra disk. (b) **Byte
incompatibility:** identical to BUG-1 — nimrod's chainstate cannot be
loaded by Core (or any Core-compatible impl) and vice versa. Compounds:
nimrod has TWO separate UTXO entry formats (one in dead `utxo_cache.nim`,
one in production `chainstate.nim`) — both diverge from Core, but
ALSO differ from each other on the height/isCoinbase encoding (utxo_cache
uses VARINT-style code-packing, chainstate writes int32 + byte separately).

---

### BUG-3 — chainstate DB has no obfuscate_key XOR layer → leveldb files contain raw scriptPubKey bytes flagged as virus signatures

**Severity:** P0-CDIV
**File:** src/storage/utxo_cache.nim (no obfuscate_key handling); src/storage/db.nim (no obfuscation hook)
**Core ref:** bitcoin-core/src/dbwrapper.h:188-192 (`m_obfuscation`, `OBFUSCATION_KEY="\0obfuscate_key", 14`); bitcoin-core/src/dbwrapper.cpp:253-262 (auto-generates 8-byte XOR key on first open).

**Description:** Core stores an 8-byte random XOR key at the well-known
key `'\0' + "obfuscate_key"` (14 bytes, null-prefixed to avoid collisions
with any user key). ALL values in the chainstate DB are XOR'd against
this key (looped to value length) on read and write. nimrod's chainstate
DB does **not** read, write, or apply this key. The codebase DOES have an
XOR helper (`src/nimrod.nim:1672 xorDeobfuscate`) — but only for parsing
Bitcoin Core's `blk*.dat` files during import, not for nimrod's own DB.

**Excerpt (nimrod.nim:1672-1676 — proof the primitive exists but is unwired
for chainstate):**
```nim
proc xorDeobfuscate(data: var openArray[byte], fileOffset: int64, key: array[8, byte]) =
  if key == default(array[8, byte]):
    return
  for i in 0 ..< data.len:
    data[i] = data[i] xor key[int((fileOffset + int64(i)) mod 8)]
```

**Impact:** Three issues. (a) **Cross-impl incompatibility hardening:**
even if BUG-1+BUG-2 were fixed, nimrod's leveldb/rocksdb files would
still be unreadable by Core (Core expects XOR'd values, finds raw bytes,
deserialization fails). (b) **Anti-virus false positives:** the original
reason Core added obfuscation — raw scriptPubKey bytes can trigger AV
heuristics that flag the chainstate as malware. nimrod ships unprotected.
(c) **No mitigation path:** since there's no `obfuscate_key` row,
upgrading to compatibility later requires a full chainstate rewrite, not
just toggling a flag. Two-pipeline guard 14th distinct extension (since
W76): impl HAS the primitive (XOR loop) but it's wired for the WRONG
input source (blk*.dat import) instead of the chainstate DB.

---

### BUG-4 — CCoinsViewCache module is dead — imported only by tests, never wired into the production chainstate path

**Severity:** P0-CDIV
**File:** src/storage/utxo_cache.nim (entire 559-line file)
**Core ref:** bitcoin-core/src/coins.h:147-340 (`CCoinsViewCache` is THE
chainstate cache layer; Core's validation, mempool, RPC, wallet all hold
references to a `CCoinsViewCache&`).

**Description:** `utxo_cache.nim` defines the full Core-style CCoinsView
class hierarchy: `CoinsView` (base) / `CoinsViewDB` (RocksDB backend) /
`CoinsViewCache` (with DIRTY + FRESH flag tracking, Flush/Sync split,
parent-cache stacking, Uncache, etc.). It implements every behavior
W147 is asking about: dirty/fresh, FRESH delete-without-flush
optimization, possible_overwrite path, sync vs flush, etc. But:

```
$ grep -rn "import.*utxo_cache" nimrod/src/ nimrod/tests/
nimrod/tests/test_utxo_cache.nim:6:import ../src/storage/utxo_cache
nimrod/tests/test_perf.nim:5:import ../src/perf/[bench, utxo_cache]
nimrod/tests/test_w100_coins_view_cache.nim:20:import ../src/storage/utxo_cache
nimrod/tests/test_all.nim:60:import ./test_utxo_cache
```

ZERO `src/` files import it. The production `ChainState` (chainstate.nim)
uses a flat `Table[OutPoint, UtxoEntry]` with no dirty/fresh tracking.

**Impact:** Massive surface area defect: 559 lines of well-engineered
Core-shape cache code is never executed in production. Production
chainstate has **no FRESH-flag optimization** (UTXOs created and spent
within the same block touch RocksDB unnecessarily — Core skips this disk
trip). Production also has **no dirty tracking** so a flush writes every
single cached entry every time (vs Core which only writes the
dirty subset). Two-pipeline guard 9th-of-9 storage subsystem flavor:
prior W138 audit catalogued the same pattern in nimrod (BackgroundValidator
defined zero callers). Fleet pattern (W138 BUG-8/W141 BUG-1 etc) crystallized
in W147 too. Companion to "well-engineered-helper-never-wired" pattern.

---

### BUG-5 — `addCoin` marks new-outpoint entries `fresh=true` unconditionally even when `possibleOverwrite=true` → fresh-flag misapplied for BIP-30 coinbase overwrite path

**Severity:** P0-CDIV
**File:** src/storage/utxo_cache.nim:288-319
**Core ref:** bitcoin-core/src/coins.cpp:89-114 (Core's `AddCoin`: `fresh = false` is the default; only set true when `!possible_overwrite` AND the existing-but-spent entry is not dirty).

**Description:** Core's `AddCoin` declares `bool fresh = false;` then enters
the `if (!possible_overwrite)` branch where it MAY set fresh=true based on
the existing entry's DIRTY flag. If `possible_overwrite == true`, the code
skips the entire branch and `fresh` stays false — even when the entry is
newly inserted (no existing entry). nimrod's `addCoin` instead does:

```nim
if outpoint in view.cache:
  ...
  fresh = not existing.dirty           # OK for non-overwrite case
else:
  # New entry - it's fresh (not in backing store)
  fresh = true                          # WRONG when possibleOverwrite=true
```

The branch on line 310-311 unconditionally sets `fresh = true` for any
brand-new entry — even when the caller passed `possibleOverwrite=true`.

**Impact:** In Core, the BIP-30 path (`AddCoins` in coins.cpp:142-150
passes `fCoinbase` as the `check_for_overwrite` flag, which becomes
`possible_overwrite`) deliberately marks coinbases NON-fresh because they
might overwrite an existing-but-spent entry in a re-org. nimrod's
`addCoins` wrapper at line 545 (`view.addCoin(outpoint, coin, possibleOverwrite = isCoinbase)`)
sets possibleOverwrite=true for coinbases — but addCoin then marks them
FRESH because the cache slot is empty. If that same coinbase outpoint is
later spent before the cache flushes (theoretically impossible for
coinbase maturity but exercised in tests / reorg paths), the FRESH-spent
delete-without-flush optimization runs, and the spentness is never
flushed to RocksDB. **UTXO resurrection bug class.** Only "dormant" because
the module is dead (BUG-4).

---

### BUG-6 — Legacy `ChainDb.disconnectBlock` does not restore spent inputs (it's a forward-only delete) — UTXO resurrection if called from any path

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:2078-2126
**Core ref:** bitcoin-core/src/validation.cpp:2149-2245 (`DisconnectBlock`
must call `ApplyTxInUndo` to restore every spent UTXO).

**Description:** A SECOND `disconnectBlock` overload exists on `ChainDb`
(not `ChainState`) at line 2078 with the comment "Legacy function - use
ChainState.disconnectBlock for new code". It deletes the block's created
outputs, deletes its tx-index entries, but EXPLICITLY does not restore
spent inputs:

```nim
# Note: Restoring spent inputs requires having the previous UTXO data
# which would typically be stored in an undo file. For now we skip this.
```

This is exported (`disconnectBlock*`) and reachable from any caller that
holds a `ChainDb`. No active production caller invokes it today (grep
confirms), but the function signature is public.

**Impact:** Three-pipeline guard (three `disconnectBlock` overloads at
chainstate.nim:1382 / 1543 / 2078): the third one is silently broken in a
way that LOSES the entire UTXO restoration step. If a future RPC handler
or test harness wires `ChainDb.disconnectBlock` instead of
`ChainState.disconnectBlock`, every input spent by the disconnected
block becomes a "missing UTXO" on the next reorg — chain splits guaranteed.
"Comment-as-confession" 5th instance flagged this wave: the comment
literally says "For now we skip this", with no removal or guard. Cosmetic
fix: delete the dead overload; structural fix: route any
`disconnectBlock(cdb: ChainDb, ...)` call to throw immediately.

---

### BUG-7 — No DB_HEAD_BLOCKS two-phase commit marker → post-crash recovery can boot on a torn chainstate without detecting the corruption

**Severity:** P0-SEC
**File:** src/storage/chainstate.nim:889-896, 947-959; src/storage/utxo_cache.nim:411-413
**Core ref:** bitcoin-core/src/txdb.cpp:100-164 (`CCoinsViewDB::BatchWrite`
two-phase: erase DB_BEST_BLOCK + write DB_HEAD_BLOCKS=[new, old]; write
coins; erase DB_HEAD_BLOCKS + write DB_BEST_BLOCK).

**Description:** Core uses a two-phase commit pattern on every BatchWrite
specifically to detect torn chainstate from mid-flush crashes:

1. Before the coin writes: erase `'B'` (DB_BEST_BLOCK), write
   `'H'` (DB_HEAD_BLOCKS) = the vector `[hashBlock, old_tip]`. This is
   the "we're transitioning" marker.
2. Write the coin batch (potentially huge).
3. After the coins land: erase `'H'`, write `'B'` = `hashBlock`.
   This is the "consistent again" marker.

On startup, if `DB_BEST_BLOCK` is null and `DB_HEAD_BLOCKS` has 2 entries,
Core knows it crashed mid-flush, fires the `LogError("inconsistent state, …
reindex-chainstate")` warning, and asserts `old_heads[0] == hashBlock`.

nimrod does NEITHER. It writes a `bestblock` key directly inside the same
write batch as the coins (chainstate.nim:889). RocksDB write-batches are
atomic at the batch level, but the IBD code path writes the bestblock,
height, totalwork BEFORE the cached UTXOs into the batch
(chainstate.nim:947-956) — so within a single block-connect batch the
ordering is "header pointers first, then UTXOs". If we crash inside the
memtable flush at exactly the wrong moment with WAL disabled (`disableWAL`
is called in `startIBD` line 919), the on-disk state can have the new
bestblock pointer but missing UTXO updates — and there's no `DB_HEAD_BLOCKS`
marker to flag the inconsistency. The startup path just reads `bestblock`
and trusts it.

**Excerpt (chainstate.nim:945-959, IBD flush — note bestblock written
BEFORE the UTXOs into the batch):**
```nim
if cs.ibdBatch != nil and cs.ibdBatchBlocks > 0:
  cs.ibdBatch.put(cfMeta, metaKey("bestblock"), @(array[32, byte](cs.bestBlockHash)))
  var w = BinaryWriter()
  w.writeInt32LE(cs.bestHeight)
  cs.ibdBatch.put(cfMeta, metaKey("height"), w.data)
  cs.ibdBatch.put(cfMeta, metaKey("totalwork"), @(cs.totalWork))

  # Also flush cached UTXOs into the batch  <-- ordered AFTER bestblock
  for op, entry in cs.utxoCache:
    let key = utxoKey(array[32, byte](op.txid), op.vout)
    cs.ibdBatch.put(cfUtxo, key, serializeUtxoEntry(entry))

  cs.db.db.write(cs.ibdBatch)
```

**Impact:** During IBD (WAL disabled), a crash between memtable creation
and SST flush can leave the chainstate in a torn state where bestblock
points past the actual UTXO set. On restart, nimrod boots, gets to the
"too-high" bestblock, accepts the next block, attempts to spend UTXOs
that don't exist, returns "missing input", **bans peers**, and silently
loses the chain. Worse, the user has no `getchainstates`-style RPC to
detect this; the only sign is "stuck at tip" alarms. This is exactly
why Core's HEAD_BLOCKS marker fires `LogError` plus the assert at
txdb.cpp:115. Compounds: `nimrod.cli` does not yet expose
`reindex-chainstate` recovery; the only mitigation is a full reindex.

---

### BUG-8 — `isSpent` sentinel mismatch: `(value==0 AND script.len==0)` vs Core's `nValue == -1`

**Severity:** P1
**File:** src/storage/utxo_cache.nim:86-93
**Core ref:** bitcoin-core/src/primitives/transaction.h:154-162 (`CTxOut::SetNull() { nValue = -1; … }; IsNull() { return nValue == -1; }`); bitcoin-core/src/coins.h:83-85 (`Coin::IsSpent() { return out.IsNull(); }`).

**Description:** Core's spent sentinel is the special value `nValue == -1`.
This is unambiguous: any UTXO with value >= 0 is unspent; only the
explicit SetNull (nValue = -1) marks "this Coin slot is empty". nimrod's
`isSpent` uses two-field equality: `scriptPubKey.len == 0 AND value == 0`.
This is wrong on two axes: (a) a legitimately-zero-value coin with an
empty witness commitment script would be misclassified spent. (b) The
SetNull path in nimrod (`clear`) sets `value = 0` and `scriptPubKey = @[]`
— but anywhere a `Coin` ends up half-initialised, it satisfies the
"spent" predicate. Core uses a SINGLE sentinel value that cannot collide
with any legal UTXO.

**Excerpt:**
```nim
proc isSpent*(coin: Coin): bool =
  coin.txOut.scriptPubKey.len == 0 and int64(coin.txOut.value) == 0

proc clear*(coin: var Coin) =
  coin.txOut.scriptPubKey = @[]
  coin.txOut.value = Satoshi(0)
```

**Impact:** Dormant due to BUG-4 (module dead) but if the cache is ever
wired up, a default-constructed Coin (Satoshi(0), @[]) is "spent",
meaning `FetchCoin` returning a fresh coin with an empty script (legal in
Core for 0-value witness commits) treats it as gone. The bug surface is
small in practice — Core's IsUnspendable would normally filter these —
but the semantic mismatch is the kind of thing that misfires in fuzzing.

---

### BUG-9 — `dynamicMemoryUsage` undercounts cache entry overhead (60 vs ~140 bytes/entry) → cache exceeds 450MB dbcache budget silently

**Severity:** P1
**File:** src/storage/utxo_cache.nim:221-226
**Core ref:** bitcoin-core/src/core_memusage.h (proper memusage accounting per CCoinsMap entry).

**Description:** nimrod uses a hardcoded constant:
```nim
const entryOverhead = 36 + 8 + 16  # ~60 bytes
view.cache.len * entryOverhead + view.cachedMemoryUsage
```

Per entry: OutPoint key (36 bytes) + flags (8) + 16 byte "pointer" guess.
A Nim `Table[OutPoint, CoinEntry]` actually uses ~96 bytes per slot at
50% load (HashSlot + Key + Value + 2 padding + hash word), plus Nim ref
overhead, plus the OutPoint hash function allocates a Hash. Real usage is
closer to 140-160 bytes. Combined with `view.cachedMemoryUsage` (which only
counts `scriptPubKey.len` per coin — not the TxOut.value 8 bytes, not the
height int32, not the isCoinbase bool, not the Nim seq overhead), the
total is undercounted by ~2x.

**Impact:** `shouldFlush` (line 235) compares `dynamicMemoryUsage() >= maxCacheSize`
(default 450 MiB). With 2x undercount, the actual RSS at the trigger
moment is ~900 MiB. On a constrained VM this can OOM before the flush
fires. Companion to W141 fleet-wide memory-accounting fleet bug. (Dormant
in production since BUG-4 means the module isn't running.)

---

### BUG-10 — Cache flush logic in production has no FRESH-fast-path → UTXOs created+spent in same block always touch disk

**Severity:** P1
**File:** src/storage/chainstate.nim:539-544 (flushCache), src/storage/chainstate.nim:829-861 (connectBlock spend+create)
**Core ref:** bitcoin-core/src/coins.cpp:153-175 (FRESH-flag delete-from-cache without touching parent).

**Description:** Production `flushCache` just writes every cached entry
unconditionally:
```nim
proc flushCache*(cs: var ChainState) =
  for op, entry in cs.utxoCache:
    cs.db.putUtxo(op, entry)
  cs.utxoCache.clear()
  cs.cacheSize = 0
```

Spends go directly to RocksDB via `batch.delete(cfUtxo, key)` in
`connectBlock` (line 840). There's no in-cache "spent" marker — the
deleteUtxoCache simply removes the entry. This means:

(a) A UTXO created in block N and spent in block N (same-block spend) is
    `putUtxoCache` then immediately deleted from cache AND a `batch.delete`
    is emitted on the same key it was about to insert. Core's FRESH flag
    detects this and skips BOTH operations (the entry never touches disk).
    Nimrod always emits the delete (and may also emit the put, depending
    on whether the put was already inside the same writeBatch).
(b) Aggregate over a 100k-block IBD, this is millions of unnecessary
    disk writes.

**Impact:** Wasted IBD IO. Not a consensus bug — the post-flush state is
identical to Core's — but the throughput delta is significant. Pairs with
BUG-4: the well-engineered FRESH-aware cache module exists, just unwired.

---

### BUG-11 — `shouldFlush` uses entry-count (50000) not Core's byte-budget (dbcache 450 MiB)

**Severity:** P1
**File:** src/storage/chainstate.nim:549-550, line 454
**Core ref:** bitcoin-core/src/validation.cpp::FlushStateToDisk (compares CCoinsViewCache::DynamicMemoryUsage() vs `nCoinCacheUsage`).

**Description:** Production trigger:
```nim
const DefaultMaxCacheSize* = 50000      # entry count, not bytes
proc shouldFlush*(cs: ChainState): bool = cs.cacheSize >= cs.maxCacheSize
```

Core compares total bytes (`CCoinsViewCache::DynamicMemoryUsage()`) against
the user-tunable `-dbcache` setting (default 450 MiB). A 50000-entry
threshold can be reached in <50 average blocks (1000 outputs each),
forcing extremely frequent flushes during IBD, OR can be MISSED for
hundreds of blocks if outputs are sparse. Nimrod does have a separate
`MaxCacheBytes = 2 GiB` (line 456) with `evictCleanEntries` eviction,
but that's an OOM guard — not a "should we flush now" decision. The two
metrics are not aligned.

**Impact:** Suboptimal IBD performance. Same as BUG-10: not a consensus
bug, but Core's heuristic was selected for a reason — too-frequent flushes
hurt SST compaction, too-rare flushes risk OOM. Nimrod's chosen
50000-entry constant has no documented tuning history.

---

### BUG-12 — No `Sync()` vs `Flush()` split → operator cannot drain dirty entries without invalidating the cache

**Severity:** P1
**File:** src/storage/utxo_cache.nim:383, 466 (both methods exist but conflate)
**Core ref:** bitcoin-core/src/coins.cpp:279-300 (`Flush(reallocate_cache=true)` clears cacheCoins; `Sync` keeps but clears flags).

**Description:** Core distinguishes:
- `Flush(true)`: drain all dirty entries, clear cacheCoins, optionally
  reallocate the underlying memory pool. Used at shutdown and after a
  reorg.
- `Sync()`: drain all dirty entries to disk but KEEP the cache contents
  (with flags cleared). Used during periodic flushes — keeps hot data warm.

nimrod's `flush` empties the cache (line 459 `view.cache.clear()`); the
sync proc (line 466) writes to disk and DOES retain non-spent entries —
which matches Core's Sync. But there's no `Flush(reallocate=true)`
behavior — `flush` simply clears without reallocating. The naming
inversion is confusing: nimrod's `flush` looks like Core's "Reset" and
nimrod's `sync` looks like Core's "Sync" but is named differently from
the corresponding Core method. Comment-as-confession: the doc at line 467
says "non-destructive sync (clears dirty flags but retains cached coins)"
which is exactly Core's Sync — so `flush` is left as half-Reset.

**Impact:** Dormant (BUG-4). If wired up, a caller invoking "flush" would
lose all warm cache contents; subsequent reads would all be cold-fetched
from RocksDB. Production `flushCache` (chainstate.nim:539) has the same
flavor.

---

### BUG-13 — FRESH-misapplied throw missing in `addCoin` parent-cache flush path → silent overwrite of unspent parent coin

**Severity:** P1
**File:** src/storage/utxo_cache.nim:449-452
**Core ref:** bitcoin-core/src/coins.cpp:240-246 (`throw std::logic_error("FRESH flag misapplied to coin that exists in parent cache");`).

**Description:** Core's BatchWrite explicitly throws when a child cache
flushes a FRESH-marked coin that ALSO exists unspent in the parent —
that's a calling-code bug (FRESH means "doesn't exist upstream", so
parent-unspent is contradictory). nimrod's `flush` to a parent cache
just calls `addCoin(outpoint, entry.coin, possibleOverwrite = entry.fresh)`
which inside `addCoin` (line 298) raises a NimError if the existing entry
is unspent AND possibleOverwrite is false. But when the entry IS fresh,
possibleOverwrite=true, the unspent-overwrite check at line 298 SKIPS,
and the coin is silently overwritten without any consistency-check.

**Excerpt (utxo_cache.nim:449-452):**
```nim
# Add/update in parent
if outpoint in parentCache.cache:
  parentCache.addCoin(outpoint, entry.coin, possibleOverwrite = true)
else:
  parentCache.addCoin(outpoint, entry.coin, possibleOverwrite = entry.fresh)
```

Note line 450 ALWAYS sets `possibleOverwrite=true` when the outpoint exists
in the parent — so a FRESH child overwriting an unspent parent silently
succeeds. Core throws.

**Impact:** Cache-stacking bugs become silent. Dormant in production
(BUG-4). When wired up, a stacked CCoinsViewCache (mempool sits on a
chainstate cache, which sits on the DB) loses a layer of defense
against "the calling code put FRESH where it shouldn't have".

---

### BUG-14 — No `Cursor()` API on the CoinsView base — cross-impl tools cannot iterate the UTXO set through the abstract layer

**Severity:** P1
**File:** src/storage/utxo_cache.nim:120-142 (base methods); no Cursor
**Core ref:** bitcoin-core/src/coins.h:230 (`virtual std::unique_ptr<CCoinsViewCursor> Cursor() const;`); bitcoin-core/src/txdb.cpp:194-244 (`CCoinsViewDBCursor` implementation).

**Description:** Core's CCoinsView declares `Cursor()` as part of its
public interface. CCoinsViewDB returns a leveldb-iterator wrapper; tools
like `dumptxoutset` and `gettxoutsetinfo` iterate through this cursor.
nimrod has NO Cursor method on `CoinsView`. The production path
(chainstate.nim:1044, 1162) uses an ad-hoc `cs.db.db.iterCf(cfUtxo)`
iterator at the raw RocksDB layer — fine for in-process use, but it
means external tools can't drive a chainstate walk through the abstract
view (because the abstract view doesn't expose iteration).

**Impact:** Limits future composability — a wallet rescan or analytics
script written against `CoinsView` cannot iterate. Dormant in production
(BUG-4). For chainstate.nim it's not a bug per se, just a
parametric-API gap: a future cross-impl `gettxoutsetinfo` consumer
that targets `CoinsView` instead of `Database` would silently fail.

---

### BUG-15 — No `AccessCoin` / `coinEmpty` sentinel — callers must allocate Option[Coin] on every lookup

**Severity:** P1
**File:** src/storage/utxo_cache.nim:239 (only `getCoin` returns `Option[Coin]`)
**Core ref:** bitcoin-core/src/coins.cpp:179-186 (`const Coin& AccessCoin` returns a reference to a static `coinEmpty` sentinel).

**Description:** Core has two accessors:
- `GetCoin(outpoint, coin)` — fills a Coin by value, returns bool.
- `AccessCoin(outpoint)` — returns `const Coin&` to a cached entry (or a
  static `coinEmpty` if missing). Used hot inside script-verify where
  allocation is forbidden.

nimrod only has `getCoin` returning `Option[Coin]`. Every UTXO lookup in
the hot path allocates a `none(Coin)` or `some(coin)` — a Nim Option
is a small wrapper but still copy-constructs the Coin payload (TxOut +
height + bool). At 800k blocks × ~3000 inputs/block average, that's 2.4B
unnecessary copies. Core's reference-based AccessCoin avoids every one
of them.

**Impact:** IBD throughput hit. Compounds with BUG-9 / BUG-11 — IBD perf
loses on three fronts: cache sizing wrong, fresh-fast-path absent,
per-lookup allocations.

---

### BUG-16 — `connectBlock` and `connectBlockIBD` two-pipeline guard on the SAME UTXO mutation logic — every fix has to land twice

**Severity:** P1
**File:** src/storage/chainstate.nim:739-908 (connectBlock); 1222-1332 (connectBlockIBD); 1620-1956 (handleReorg connect inline)
**Core ref:** bitcoin-core/src/validation.cpp:2330+ (single `ConnectBlock`).

**Description:** nimrod has THREE separate connect-block code paths:
(a) `connectBlock` — full path with undo data + tx index + block storage
    + per-block batch commit + cache flush.
(b) `connectBlockIBD` — fast IBD path: skips undo file, skips tx index,
    skips full-block storage, accumulates 2000-block batches.
(c) inlined inside `handleReorg` (lines 1817-1926) — third copy of the
    spend-inputs/create-outputs/maturity-check logic, this time staging
    onto a shared reorg batch.

Each has its own subtly-different version of the same intra-block-tracking
logic. Core has ONE `ConnectBlock` shared across IBD and reorg (Core
distinguishes via the `fJustCheck` flag, not by code path).

**Impact:** Every consensus-relevant fix to the UTXO mutation logic must
be applied three times. W12 OP_RETURN-genesis fix had to be applied in
connectBlock first, then connectBlockIBD; the handleReorg path was
fixed later. Latent risk: a future fix that lands in two paths but not
the third causes connect-vs-reorg state divergence. The chainstate.nim
file is 2126 lines partly because of this triplication.

---

### BUG-17 — No `Reset()` / `ReallocateCache` after Flush — Nim Table memory never compacts after batch evictions

**Severity:** P2
**File:** src/storage/utxo_cache.nim:511-516 (`reset` exists but doesn't reallocate)
**Core ref:** bitcoin-core/src/coins.cpp:341-349 (`ReallocateCache` destroys and reconstructs the underlying `CCoinsMap` to release memory pool capacity back to the allocator).

**Description:** Core's `Flush(reallocate_cache=true)` calls
`ReallocateCache` which **destroys** the unordered_map and reconstructs
it — releasing the memory-pool capacity back to the OS. nimrod's `reset`
just calls `view.cache.clear()` which empties entries but keeps the
Table's internal slot capacity allocated. Repeated Flush cycles never
shrink the cache backing store.

**Impact:** RSS doesn't trend down after large reorgs / IBD-to-tip
transition. Cosmetic during IBD (the cache will refill), but post-IBD
the steady-state memory is permanently elevated. Same dormancy as BUG-4.

---

### BUG-18 — No `Uncache()` operator RPC — cannot evict known-cold UTXOs

**Severity:** P2
**File:** src/storage/utxo_cache.nim:375-381 (proc exists, no caller); no RPC
**Core ref:** bitcoin-core/src/coins.cpp:310-322 (`Uncache` per-outpoint eviction); used by `gettxoutsetinfo` and mempool acceptance to drop coins that were only-just-fetched-for-validation.

**Description:** nimrod's `uncache` is defined in `utxo_cache.nim:375` but
has no callers in src/ (dormant module pattern, see BUG-4). Core uses
Uncache as a memory-pressure release valve: after validating a tx, drop
the coins it fetched from the cache (they're unlikely to be re-read soon).
Production chainstate has no equivalent.

**Impact:** Cache grows monotonically until shouldFlush fires. Less
adaptive than Core. Minor.

---

### BUG-19 — No SanityCheck invariant — silent cache-state divergence

**Severity:** P2
**File:** src/storage/utxo_cache.nim (no SanityCheck)
**Core ref:** bitcoin-core/src/coins.cpp:351-381 (`SanityCheck` verifies dirty_count == count_dirty == count_linked, and recomputed_usage == cachedCoinsUsage).

**Description:** Core's `SanityCheck` walks the entire cache and verifies
the linked-list of flagged entries matches the actual DIRTY/FRESH state
of each entry — runs under `-checklevel` and in unit tests. nimrod has
NO equivalent. The production cache (BUG-4 dormant module aside) doesn't
even HAVE the linked list, so the invariant is moot.

**Impact:** Hidden corruption from a future cache-flag-mutation bug
would never be caught at runtime. Cosmetic for now.

---

### BUG-20 — Compressor module dead in chainstate path — `snapshot.nim:compressAmount/compressScript` exists but is wired only for assumeUTXO dump/load

**Severity:** P2
**File:** src/storage/snapshot.nim:119, 183, 211 (compress functions defined and used by snapshot only)
**Core ref:** bitcoin-core/src/compressor.h, compressor.cpp (shared between chainstate write and assumeutxo).

**Description:** Same module is supposed to back BOTH the on-disk coin
serialization and the assumeUTXO dump/load. In Core, `Coin::Serialize`
calls `Using<TxOutCompression>(out)` which is the same compressor used
in `dumptxoutset`. nimrod splits them: snapshot uses the proper compressor,
chainstate uses `writeTxOut` raw. Three-pipeline guard candidate (dead
chainstate compressor pipeline; live snapshot pipeline; raw production
pipeline — three encodings for the same conceptual UTXO).

**Impact:** Storage bloat (see BUG-2) and dump/load consistency only
works because snapshot.nim re-implements the rule. A future refactor
that "consolidates the UTXO format" must touch both call sites.

---

### BUG-21 — Production `ChainState` is its own cache AND DB wrapper — no `CCoinsView`-style separation, blocks future composability

**Severity:** P3
**File:** src/storage/chainstate.nim:87-95 (ChainState fields: `db: ChainDb`, `utxoCache: Table[OutPoint, UtxoEntry]`); 449-491 (`newChainState` is the only constructor)
**Core ref:** bitcoin-core/src/coins.h:147-330 (CCoinsView interface is independent of any storage; CCoinsViewDB / CCoinsViewCache / CCoinsViewMemPool stack via `SetBackend`).

**Description:** Core's design factors the DB-backend (CCoinsViewDB), the
in-memory cache (CCoinsViewCache), and the mempool-overlay
(CCoinsViewMemPool) into independent classes that stack via `base*`
pointers. nimrod's production path collapses all three into the single
`ChainState` ref: it owns the RocksDB connection, the cache, the IBD
state, the reorg state, the disconnect hook, the undo manager — 17
fields total. This is the opposite of the layered CCoinsView pattern.

**Impact:** Hard to write a mempool overlay or a snapshot-rewind cache
without changing ChainState's shape. The `utxo_cache.nim` module is what
the layered design WOULD look like — it just isn't used (BUG-4).
Comment-as-confession 5th instance flagged this wave: chainstate.nim:2094
refers to "Core's CCoinsViewCache::AddCoin" as the authoritative
reference for an in-place delete operation, even though nimrod's
production cache has no AddCoin / Spend / FRESH-flag concept of its own.

---

## Fleet-pattern smells (W147)

1. **Dead module pattern (BUG-4, BUG-17 through BUG-21):** 559-line
   `utxo_cache.nim` defines the full Core-shape `CCoinsView` hierarchy
   with dirty/fresh tracking, parent-cache stacking, Flush/Sync split —
   imported only by tests. Production uses a flat
   `Table[OutPoint, UtxoEntry]` with none of the cache-layer semantics.
   This is the same fleet-wide W138 BUG-4 / W141 BUG-1 pattern: an
   architecturally-correct module sits next to production code that
   does not use it.

2. **Two-pipeline guard (BUG-16):** `connectBlock` / `connectBlockIBD`
   / `handleReorg`-inline implement THREE copies of the same UTXO
   mutation logic. Companion to fleet W143/W125/W101 multi-pipeline
   patterns. Three copies means three audit footprints for every
   future consensus fix.

3. **Comment-as-confession (BUG-6, BUG-21):** `chainstate.nim:2108`
   literally reads "For now we skip this" (the missing restore-spent-inputs
   step in legacy `ChainDb.disconnectBlock`). chainstate.nim:2094 references
   "Core's CCoinsViewCache::AddCoin" even though nimrod's production cache
   has no AddCoin / FRESH concept. 5th distinct comment-as-confession
   instance this audit; W141 also flagged comment-as-confession in nimrod
   for getzmqnotifications.

4. **Carry-forward re-anchor (BUG-1, BUG-2):** the VARINT-vs-CompactSize
   bug AND the missing-TxOutCompression bug both predate the chainstate
   v1 format that nimrod has been shipping. The original architectural
   decision to call the encoding "VARINT" but implement CompactSize is
   the kind of thing W124 (clearbit), W125, and W139 (lunarblock)
   surfaced — wave-N audit catches a wave-1 architectural choice.

5. **Wrong-input-source primitive wiring (BUG-3):** nimrod HAS the
   8-byte XOR machinery (used for parsing Core's blk*.dat during
   import) but does not apply it to its own chainstate DB. Same "this
   impl already exports the primitive, just never calls it" pattern
   flagged in W140 BUG-5 (haskoin `constantTimeEq`), W141 (rustoshi
   zmq.rs), and others fleet-wide.

6. **Two-phase commit absent (BUG-7):** Core's DB_HEAD_BLOCKS /
   DB_BEST_BLOCK two-marker dance protects against torn-state IBD
   crashes. nimrod writes both into a single batch with WAL disabled
   during IBD — and silently boots on torn state. Same risk-class as
   W125 / W138 / W141 default-config-yet-no-defense audits.

7. **Fleet-wide UTXO serialization byte-incompat (BUG-1, BUG-2, BUG-3):**
   nimrod chainstate cannot be opened by Bitcoin Core; can be expected
   to be flagged FLEET-WIDE in W147 across all 10 impls. Cross-impl
   chainstate-clone tooling cannot ever be implemented as long as 10
   impls each ship a custom byte format.
