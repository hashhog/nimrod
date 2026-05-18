# W138 — assumeUTXO snapshots audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W138).
Concurrent waves: 3 OTHER discovery waves running in parallel; this wave
takes the **assumeUTXO snapshot** axis distinct from W137 PSBT, W136
relay flags, W135 standardness, W134 BIP-37 bloom.

Target:
  - `src/storage/snapshot.nim`           (918 LOC) — magic/version/metadata,
    SnapshotFile read/write, ScriptCompression + AmountCompression + Coin
    body codec, `openSnapshotForRead`, `readCoin` (streaming),
    `createSnapshot` (dumptxoutset core), `loadSnapshot` (loadtxoutset
    core), `validateSnapshotMetadata` + B1..B8 strictness gates,
    `SnapshotChainState` + `activateSnapshot`, `BackgroundValidation`
    async loop, `validateSnapshot`.
  - `src/consensus/params.nim`           (`AssumeutxoData`; per-network
    `assumeutxoData` seq; mainnetParams entries at 840000 / 880000 /
    910000 / 935000; testnet3/testnet4/regtest/signet all empty).
  - `src/rpc/server.nim` snapshot RPCs:
    - `handleDumpTxOutSet`     (dumptxoutset, lines 4840-5038)
    - `handleLoadTxOutSet`     (loadtxoutset, lines 5040-5088 — refused at
      RPC, only the CLI `--load-snapshot=<path>` path is wired)
    - `resolveRollbackTargetHeight` (lines 4810-4838, helper used by
      dumptxoutset rollback)
    - dispatch arms `dumptxoutset` / `loadtxoutset` / `gettxoutsetinfo`
      (lines 8268-8273).
  - `src/storage/pruner.nim`              (`assumeUtxoFloor`, lines 174-186 —
    auto-prune floor derived from `params.assumeutxoData`).
  - `src/storage/chainstate.nim`          (`ChainState` ref object, lines 88-133
    — no `m_from_snapshot_blockhash`, no `m_target_blockhash`, no
    `m_assumeutxo` enum on the chainstate; only the standalone
    `SnapshotChainState` wrapper in snapshot.nim).
  - `src/nimrod.nim`                      (lines 1967-1988 — startup-only
    --load-snapshot path; refuses if `bestHeight > 0`).

Reference (Bitcoin Core, commit pinned by `bitcoin-core/` submodule):
  - `src/node/utxo_snapshot.{h,cpp}`     — `SnapshotMetadata` Serialize/
    Unserialize, `SNAPSHOT_MAGIC_BYTES`, `SNAPSHOT_CHAINSTATE_SUFFIX`,
    `SNAPSHOT_BLOCKHASH_FILENAME`, `WriteSnapshotBaseBlockhash`,
    `ReadSnapshotBaseBlockhash`, `FindAssumeutxoChainstateDir`.
  - `src/validation.cpp:5588-6080`       — `ChainstateManager::ActivateSnapshot`,
    `PopulateAndValidateSnapshot`, `MaybeValidateSnapshot`,
    `MaybeRebalanceCaches`, `AddChainstate`, `LoadAssumeutxoChainstate`,
    `InvalidateCoinsDBOnDisk`, `DeleteChainstate`,
    `ValidatedSnapshotCleanup`.
  - `src/validation.h`                    — `Chainstate::m_from_snapshot_blockhash`,
    `m_target_blockhash`, `m_target_utxohash`, `m_assumeutxo` enum
    (`VALIDATED` / `UNVALIDATED` / `INVALID`), `m_cached_snapshot_base`.
  - `src/rpc/blockchain.cpp:3068-3520`    — `dumptxoutset` (PrepareUTXOSnapshot
    + WriteUTXOSnapshot + temppath/.incomplete/fifo handling +
    TemporaryRollback + NetworkDisable RAII + pruned-mode pre-check),
    `loadtxoutset` (NODE_NETWORK→NODE_NETWORK_LIMITED service flag flip),
    `getchainstates`.
  - `src/kernel/chainparams.{h,cpp}`      — `AssumeutxoData` struct,
    `m_assumeutxo_data` per-network table, `AssumeutxoForBlockhash`,
    `AssumeutxoForHeight`, `GetAvailableSnapshotHeights`. Mainnet has
    4 entries, testnet3 2, testnet4 2, signet 2, regtest 3.
  - `src/kernel/coinstats.{h,cpp}`        — `CoinStatsHashType::HASH_SERIALIZED`
    branch (= HashWriter SHA256d over TxOutSer bytes); `ApplyCoinHash`;
    `ComputeUTXOStats`.

BIPs: none (assumeUTXO is a Bitcoin Core feature, not standardized).

W138 is the **first** wave to audit nimrod's assumeUTXO snapshot codec +
load/dump RPCs + two-chainstate manager end-to-end against Core. Prior
waves established the file format (B1..B8 strictness gates in
`snapshot.nim`) and the CLI `--load-snapshot` path; this wave sweeps the
remaining Core-parity surface (dual-chainstate manager, on-disk
chainstate-dir suffix, background validation, RPC field shapes,
chainparams whitelist).

## Status

**BUGS FOUND — 18 distinct defects across 18 gates MISSING / PARTIAL /
WRONG (of 30). 12 gates PRESENT (Core-aligned).**

Of those:
  - **3 P0-CDIV / P0-CONS** — consensus / network divergence risk
    (testnet4 / signet / regtest assumeutxoData seqs are EMPTY where
    Core has 2 / 2 / 3 entries — loading a legitimate Core snapshot on
    those networks REJECTS with "not recognized"; B7 double-activation
    guard uses wrong polarity — refuses second activation of a
    successfully-validated chainstate instead of refusing while the
    first is still UNVALIDATED — Core line 5600 says the opposite; no
    second chainstate / background-validation chain exists at all — the
    snapshot tip replaces the active chain, so a later hash mismatch
    cannot trigger fatal rollback per Core MaybeValidateSnapshot
    handle_invalid_snapshot at validation.cpp:5987-6017).
  - **6 P1** — Core-parity / divergence-from-spec bugs (no
    `m_from_snapshot_blockhash` / `m_target_blockhash` / `m_assumeutxo`
    on the live `ChainState` — only on the standalone
    `SnapshotChainState` wrapper that is never instantiated in the
    production startup path; no `chainstate_snapshot` data dir suffix
    or `base_blockhash` marker file written on snapshot load — Core
    persists the snapshot-tip blockhash to `SNAPSHOT_BLOCKHASH_FILENAME`
    so restart re-detects it; no headers-chain ancestor check before
    accepting a base_blockhash — Core line 5622 refuses if
    `m_best_header->GetAncestor(snapshot_start_block->nHeight) !=
    snapshot_start_block`; no mempool-empty precondition — Core line
    5627; B8 work-exceeds check uses `height` not `chainwork` —
    AssumeutxoData has no chainwork field so a low-difficulty fork
    above the active tip would bypass; assumeUtxoFloor uses LOWEST
    height across ALL hardcoded entries — Core ties prune floor to
    the specific activated snapshot's base height, not a stale
    historical entry — over-conservative when no snapshot is loaded).
  - **6 P2** — RPC / interface gaps (no `getchainstates` RPC
    dispatch arm — Core exposes the dual-chainstate view + `validated`
    bool; loadtxoutset RPC always refused — only CLI startup path works;
    NODE_NETWORK → NODE_NETWORK_LIMITED service flag flip on
    snapshot-load is missing — Core blockchain.cpp:3432-3435;
    `chainTxCount` from AssumeutxoData is NOT written into the snapshot
    base block's `BlockIndex.nTx` — Core line 5949; no `nchaintx` /
    `txoutset_hash` in loadtxoutset response — Core dumptxoutset has
    these but loadtxoutset's documented response does not; result of
    `--load-snapshot=<path>` does not record provenance — restart
    cannot tell whether the chainstate is snapshot-derived).
  - **3 P3** — cosmetic / contract (BackgroundValidation `progress`
    monotonicity not asserted; SnapshotError messages partly diverge
    from Core verbatim — e.g. "snapshot file not found" vs "Couldn't
    open file %s for reading"; `MaxScriptSize` guard hardcoded to
    16505 not Core's `MAX_SCRIPT_SIZE = 10000` — Core's compressor.h
    actually allows scripts up to `0x10000 + 6` via nSize encoding so
    nimrod's bound is too tight; `SnapshotChainState.assumeutxo`
    initialized to `auValidated` is structurally wrong — a fresh
    snapshot chainstate should start `auUnvalidated`).

## Gates / matrix

Order: each gate covers a distinct slice of Core's assumeUTXO contract.

| # | Gate | Status | Severity | Notes |
|---|------|--------|----------|-------|
| G1 | `SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff}` | PRESENT | — | `snapshot.nim:99` matches Core `utxo_snapshot.h:28`. |
| G2 | Metadata `version = 2` LE uint16 | PRESENT | — | `snapshot.nim:101` matches Core `utxo_snapshot.h:39`. |
| G3 | Network magic byte-compare | PRESENT | — | `validateSnapshotMetadata` (`snapshot.nim:634`) checks `meta.networkMagic != params.networkMagic`. Core `utxo_snapshot.h:91-101` raises on mismatch and decodes peer network. |
| G4 | Base blockhash + coins_count fields | PRESENT | — | `snapshot.nim:54-58` and `writeSnapshotMetadata` (`:319-326`) byte-for-byte. |
| G5 | Txid-grouped body layout | PRESENT | — | `writeTxidGroup` (`snapshot.nim:362`) + `readCoin` streaming state (`pendingTxid`, `pendingRemaining`) mirrors Core's `write_coins_to_file` lambda at `rpc/blockchain.cpp:3303-3311`. |
| G6 | Per-coin codec (VARINT(code), VARINT(CompressAmount), ScriptCompression) | PRESENT | — | `writeCoinBody` / `readCoinBody` at `snapshot.nim:294-313`; matches Core `Coin::Serialize` (`coins.h`) + `compressor.cpp`. |
| G7 | `coins_per_txid > coins_left` → "Mismatch in coins count" | PRESENT | — | `readCoin` at `snapshot.nim:470-473` (B4 guard). |
| G8 | `coin.nHeight > base_height` → "Bad snapshot data" | PRESENT | — | `loadSnapshot` at `snapshot.nim:700-702` (B1 guard, matches Core `validation.cpp:5814`). |
| G9 | `outpoint.n >= UINT32_MAX` → coinstats wrap guard | PRESENT | — | `snapshot.nim:707-709` (B3 guard, matches Core `:5815-5816`). |
| G10 | `MoneyRange(coin.value)` per-coin check | PRESENT | — | `snapshot.nim:713-717` (B2 guard, matches Core `:5820-5822`). |
| G11 | Trailing-bytes check after coins_left==0 | PRESENT | — | `snapshot.nim:745-749` (B5 guard, matches Core `:5872-5882`). |
| G12 | Base block IS in headers chain | **MISSING (BUG-1)** | **P1** | Core line 5611-5614 requires `m_blockman.LookupBlockIndex(base_blockhash)`. nimrod's `loadSnapshot` and `activateSnapshot` only walk the hardcoded `assumeutxoData` whitelist; if the local node's header sync has not yet reached the snapshot base height, Core REFUSES with "must appear in the headers chain", nimrod silently accepts and pins `targetCs.bestHeight = assumeData.height` without a header chain. |
| G13 | Base block NOT `BLOCK_FAILED_VALID` | **MISSING (BUG-2)** | **P1** | Core line 5617-5620. nimrod has no analog; the `assumeutxoData` whitelist is consulted but no per-block status check is done. If the operator had marked the block invalid before loading, nimrod would still accept. |
| G14 | Forked-headers chain check (`m_best_header GetAncestor`) | **MISSING (BUG-3)** | **P1** | Core line 5622-5624. nimrod has no headers-chain comparator at snapshot-load time; loading a snapshot when a competing more-work headers chain exists silently picks the snapshot's chain — Core refuses. |
| G15 | Mempool MUST be empty before snapshot activation | **MISSING (BUG-4)** | **P1** | Core line 5626-5629. nimrod's `loadSnapshot` and `activateSnapshot` do not consult `state.mempool`. CLI startup path runs before mempool is populated so the practical hit is small, but the RPC path (currently always refused but documented as "the intended path") would not enforce. |
| G16 | Double-activation guard (`CurrentChainstate().m_from_snapshot_blockhash`) | **PARTIAL (BUG-5)** | **P0-CDIV** | nimrod has the wrapper-level guard in `activateSnapshot` (`snapshot.nim:803-805`) but the polarity is INVERTED — Core's check fires when `CurrentChainstate().m_from_snapshot_blockhash` is set (i.e. ANY prior snapshot already active, regardless of whether validated); nimrod's check fires only when `snapshotCs.assumeutxo == auUnvalidated`. After background validation completes (`validateSnapshot` flips to `auValidated`, `snapshot.nim:870`), a second `activateSnapshot` call would proceed where Core would refuse. The error message string matches Core verbatim ("Can't activate a snapshot-based chainstate more than once") but the trigger condition diverges. |
| G17 | Work-exceeds-active pre-check (PopulateAndValidate) | **PARTIAL (BUG-6)** | **P1** | `loadSnapshot` at `snapshot.nim:677-678` (B8 guard) compares HEIGHT not chainwork: `if targetCs.bestHeight > 0 and targetCs.bestHeight >= assumeData.height`. Core line 5787-5788 uses `CBlockIndexWorkComparator()(ActiveTip(), snapshot_start_block)` which compares `nChainWork`. AssumeutxoData has no chainwork field in nimrod (`params.nim:26-30`) — there's no way to do the real comparison. On regtest / signet / testnet4 a low-difficulty fork above the snapshot height could bypass; on mainnet practically safe because the snapshots are checkpointed. |
| G18 | Work-exceeds-active post-check (ActivateSnapshot final) | **MISSING (BUG-7)** | **P1** | Core line 5706 (`if (!CBlockIndexWorkComparator()(ActiveTip(), snapshot_chainstate->m_chain.Tip()))`). nimrod has no analog after the per-coin streaming load — once `loadSnapshot` succeeds, the chain tip is unconditionally pinned to the snapshot base. |
| G19 | assumeutxo whitelist (per-network) | **PARTIAL / P0-CDIV (BUG-8)** | **P0-CDIV** | Mainnet entries match Core verbatim (`params.nim:227-268` mirrors `kernel/chainparams.cpp:158-183`). BUT **testnet4 (line 397), regtest (line 508), signet (line 457) all have `assumeutxoData = @[]`** where Core has 2 (testnet4 90000+120000), 3 (regtest 110+200+299), 2 (signet 160000+290000) entries respectively. Consequence: a legitimate snapshot file generated by Core on any test network will fail `validateSnapshotMetadata` with the "Assumeutxo height in snapshot metadata not recognized (0)" error and refuse to load. Also testnet3 missing assumeutxoData but Core also has none there — that one is OK. |
| G20 | hash_serialized strict gate (HashWriter SHA256d) | PRESENT | — | `loadSnapshot` at `snapshot.nim:766-776` matches Core verbatim. The byte-reversed-hex display in the error message is preserved 1:1. |
| G21 | `m_chain_tx_count` written to snapshot-base BlockIndex.nTx | **MISSING (BUG-9)** | **P2** | Core line 5949: `index->m_chain_tx_count = au_data.m_chain_tx_count;`. nimrod `loadSnapshot` updates `bestBlockHash` + `bestHeight` (`snapshot.nim:778-780`) but does NOT call into `db.updateBlockIndex` to set `nTx` on the snapshot-base BlockIndex. Downstream RPCs like `getchainstats` / `getblockheader` (the latter has `nTx` since W57) would report 0 for the snapshot base block until normal block sync catches up. |
| G22 | `BLOCK_OPT_WITNESS` flag set on snapshot chain (post-segwit) | **MISSING (BUG-10)** | **P2** | Core line 5935-5936: the loop walks every snapshot-chain block from height 1 to snapshot.Height() and ORs `BLOCK_OPT_WITNESS` into `index->nStatus` when `DeploymentActiveAt(...SEGWIT)`. nimrod has no such loop — `BlockStatus` is a single enum value not a bitmask (`chainstate.nim:178` writes it as one `uint8`). This means `Chainstate::NeedsRedownload()` (which Core uses to refuse a snapshot that doesn't have witness commitments) would re-prompt for `-reindex` on every startup of a snapshot-loaded chain. |
| G23 | Two-chainstate manager (HistoricalChainstate vs Active) | **MISSING (BUG-11)** | **P0-CDIV** | Core lines 5717-5727: `AddChainstate` pushes a new `Chainstate` onto `m_chainstates`, the previous one becomes the "historical" / background-validation chain. `ChainstateManager` exposes `HistoricalChainstate()`, `ActiveChainstate()`, `CurrentChainstate()`. nimrod has a SINGLE `ChainState* = ref object` (`chainstate.nim:88`); the snapshot path mutates this in-place. Consequence: there is NO background chain to validate the snapshot against — when `MaybeValidateSnapshot` should fire (Core val.cpp:5987-6077), nimrod cannot detect a bad snapshot at all. The `SnapshotChainState` + `BackgroundValidation` types in `snapshot.nim:80-91` are scaffolding for the dual-chainstate model but are never wired into the production startup path (`nimrod.nim:1976` constructs neither — it calls `loadSnapshot(...)` directly on the single live ChainState). |
| G24 | `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` marker | **MISSING (BUG-12)** | **P1** | Core `utxo_snapshot.h:113`. `WriteSnapshotBaseBlockhash` (`utxo_snapshot.cpp:22-46`) writes the raw 32-byte snapshot-tip hash into `<chainstate_dir>/base_blockhash` so that `LoadAssumeutxoChainstate` on subsequent boot can rediscover and resume. nimrod writes nothing of the sort — after `--load-snapshot` returns, the only on-disk marker is the chainstate's `bestBlockHash` field, which doesn't distinguish "this is a snapshot tip" from "this is a genuine sync tip". Restart cannot tell whether to keep treating the chainstate as snapshot-derived. |
| G25 | `_snapshot` directory suffix (`SNAPSHOT_CHAINSTATE_SUFFIX`) | **MISSING (BUG-13)** | **P1** | Core `utxo_snapshot.h:128`. The leveldb dir of the snapshot chainstate gets a `_snapshot` suffix so `FindAssumeutxoChainstateDir` can locate it. nimrod uses one chainstate dir per network with no suffix variant; the snapshot data is merged into the same RocksDB column families as a normally-synced chain. Consequence: if a snapshot load fails partway, there's no easy way to wipe just the snapshot data — `cleanup_bad_snapshot` (Core val.cpp:5677-5694) would have to wipe the whole chainstate. nimrod's `loadSnapshot` returns `(false, coinsLoaded, error)` but partial state (already-loaded coins) is left in the live UTXO cache. |
| G26 | `MaybeValidateSnapshot` triggered when background chain reaches target | **PARTIAL (BUG-14)** | **P1** | `validateSnapshot` (`snapshot.nim:852-871`) is a stub. The comment at line 856 admits: "intentionally does NOT compute a UTXO hash from `backgroundCs` since that requires a UTXO iterator we don't yet expose". Core line 6036-6066 calls `ComputeUTXOStats(...HASH_SERIALIZED, &validated_coins_db, ...)` and compares against `au_data.hash_serialized`. nimrod skips the actual hash compare and unconditionally flips `auValidated` once `backgroundCs.bestHeight >= targetIdxOpt.get().height`. A bad snapshot whose hash differs from the assumeutxo entry would NEVER be detected after-the-fact. |
| G27 | `InvalidateCoinsDBOnDisk` rename to `_INVALID` | **MISSING (BUG-15)** | **P1** | Core val.cpp:6201-6231: when `MaybeValidateSnapshot` detects a bad snapshot, the snapshot chainstate dir is renamed to `<dir>_INVALID` for forensics, and the user is notified via `fatalError`. nimrod has no analog — `validateSnapshot` returns `svrInvalid` (`snapshot.nim:863`) but no rename, no fatal error, no forensic dir. |
| G28 | `ValidatedSnapshotCleanup` rename to `_todelete` | **MISSING (BUG-16)** | **P2** | Core val.cpp:6280-6345: after successful validation, the background chainstate dir is renamed to `<dir>_todelete`, the snapshot chainstate dir is renamed to the canonical chainstate dir, and the `_todelete` dir is wiped. nimrod has no analog. Without G23 there's no second chainstate to clean up, but if/when the dual model lands this gap reopens. |
| G29 | `dumptxoutset` RPC: TemporaryRollback + NetworkDisable + pruned check + fifo + temppath | **PARTIAL (BUG-17)** | **P2** | nimrod has these in scope (`server.nim:4840-5038` — pruned-mode pre-check at :4922, NetworkDisable via `blockSubmissionPaused` at :4936-4941, TemporaryRollback via `disconnectBlock` loop at :4978-4987, .incomplete + atomic rename at `snapshot.nim:563-611`). What's missing: (i) fifo handling — Core `is_fifo(path_info)` (`rpc/blockchain.cpp:3137`) writes directly to the fifo and skips the rename; nimrod's `createSnapshot` unconditionally goes through `.incomplete`; (ii) `nchaintx` field is emitted ONLY when the dump base matches a hardcoded assumeutxo entry (`server.nim:5023-5028`); Core emits `nchaintx = tip->m_chain_tx_count` ALWAYS (`rpc/blockchain.cpp:3346`); (iii) `cursor`-based dump iterates over a LEVELDB SNAPSHOT (`rpc/blockchain.cpp:3248`) so concurrent UTXO writes during the dump don't tear; nimrod iterates `cs.utxoCache` directly which is mutable. |
| G30 | `loadtxoutset` RPC + NODE_NETWORK→NODE_NETWORK_LIMITED + `getchainstates` | **MISSING (BUG-18)** | **P2** | (a) `loadtxoutset` RPC is intentionally disabled in nimrod (`server.nim:5040-5088`) — only the CLI `--load-snapshot=<path>` path works; Core supports both. The CLI gate at `nimrod.nim:1971-1973` ALSO refuses if `bestHeight > 0` which is stricter than Core's mempool-empty + work-comparator gates and silently no-ops without an error. (b) Service-flag flip is missing — Core `rpc/blockchain.cpp:3432-3435` strips `NODE_NETWORK` and adds `NODE_NETWORK_LIMITED` after snapshot activation because the snapshot-loaded node cannot serve historical blocks below the snapshot base; nimrod does neither. (c) `getchainstates` RPC is not in the dispatch table (`server.nim:8234-8275`) so `getchainstates` returns "method not found". Operators have NO way to query "am I on a snapshot chain?" once `--load-snapshot` returns. |

## Bug catalogue

Severity legend: **P0-CDIV** = consensus / network divergence;
**P0-CONS** = consensus rule violation; **P1** = Core-parity / spec
divergence; **P2** = RPC / interface; **P3** = cosmetic / contract.

---

### BUG-1 (G12, P1) — Base block header chain-membership check missing

`loadSnapshot` only checks the hardcoded `assumeutxoData` whitelist
(`snapshot.nim:636-638`). Core additionally requires
`m_blockman.LookupBlockIndex(base_blockhash)` to return a non-null,
non-failed block index — i.e. the local node MUST have already
header-synced up to or past the snapshot base before accepting the
snapshot (`validation.cpp:5611-5615`).

Impact: an operator running `--load-snapshot=<path>` on a near-empty
chainstate gets `bestHeight = assumeData.height` pinned (`snapshot.nim:779`)
WITHOUT any header-chain validation. The snapshot tip is detached from
the local header chain entirely.

---

### BUG-2 (G13, P1) — `BLOCK_FAILED_VALID` not checked on snapshot base

Core `validation.cpp:5617-5620` rejects snapshot loads whose base block
is part of an invalid chain. nimrod has no such guard. `BlockStatus` /
`BlockFailureFlags` fields exist in `chainstate.nim` (lines 178+208) but
`loadSnapshot` does not consult them.

---

### BUG-3 (G14, P1) — Forked headers-chain check missing

Core `validation.cpp:5622-5624` rejects snapshot loads if the local
header chain has a MORE-WORK fork that does NOT pass through the
snapshot base. nimrod's snapshot path doesn't compare against any
`m_best_header` analog — partly because nimrod's HeadersSync state is
not surfaced via `ChainState`.

---

### BUG-4 (G15, P1) — Mempool-empty precondition missing

Core `validation.cpp:5626-5629` refuses snapshot activation while
`CurrentChainstate().GetMempool()->size() > 0`. nimrod's `loadSnapshot`
ignores the mempool. The CLI path (`nimrod.nim:1976`) runs before
mempool init so this gate would not catch a real bug there, but the
intended (currently-disabled) `loadtxoutset` RPC would silently accept.

---

### BUG-5 (G16, P0-CDIV) — Double-activation guard polarity inverted

`activateSnapshot` (`snapshot.nim:803-805`):
```nim
if snapshotCs.assumeutxo == auUnvalidated:
  return (false, "Can't activate a snapshot-based chainstate more than once")
```

Core `validation.cpp:5600`:
```cpp
if (this->CurrentChainstate().m_from_snapshot_blockhash) {
  return util::Error{Untranslated("Can't activate a snapshot-based chainstate more than once")};
}
```

Core's predicate is "any snapshot chainstate ever activated, regardless
of whether it's been validated yet". nimrod's predicate is "snapshot
currently in UNVALIDATED state". After background validation flips the
state to `auValidated` (`snapshot.nim:870`), a second `activateSnapshot`
call would PROCEED in nimrod — Core would refuse. The string is
correct, the trigger is wrong.

---

### BUG-6 (G17, P1) — Height used instead of chainwork for "work-exceeds-active"

`loadSnapshot` at `snapshot.nim:676-678`:
```nim
# AssumeutxoData does not store chainwork.
if targetCs.bestHeight > 0 and targetCs.bestHeight >= assumeData.height:
  return (false, 0'u64, "Work does not exceed active chainstate")
```

Core uses `CBlockIndexWorkComparator()` on `nChainWork` (a 256-bit
cumulative work integer), not height. On any network where difficulty
changes (i.e. all of them except regtest no-retarget), height and
chainwork can diverge — e.g. a stale low-difficulty fork at height
N+10 has less work than a normal chain at height N. nimrod's
`AssumeutxoData` struct (`params.nim:26-30`) does not even carry a
chainwork field — to fix this gate, the struct needs a 32-byte
`chainWork` column and chainparams.cpp's `m_chain_tx_count` line
would need an additional manual chainwork populate.

---

### BUG-7 (G18, P1) — Post-load work-exceeds check missing

Core `validation.cpp:5706` does a SECOND work-exceeds check after the
heavy per-coin streaming load. nimrod's `loadSnapshot` returns
`(true, coinsLoaded, "")` immediately after `targetCs.db.updateBestBlock`
without re-checking active-vs-snapshot work.

---

### BUG-8 (G19, P0-CDIV) — testnet4 / signet / regtest assumeutxoData seqs are EMPTY

`params.nim:397` (testnet4): `result.assumeutxoData = @[]`
`params.nim:457` (signet):   `result.assumeutxoData = @[]`
`params.nim:508` (regtest):  `result.assumeutxoData = @[]`

Bitcoin Core has (kernel/chainparams.cpp):
  - testnet4: 2 entries (heights 90000, 120000)
  - signet:   2 entries (heights 160000, 290000)
  - regtest:  3 entries (heights 110, 200, 299) — used by Core's
    functional test suite (`feature_assumeutxo.py`,
    `tool_bitcoin_chainstate.py`, fuzz target `utxo_snapshot.cpp`)

Consequence: A legitimate Core-produced snapshot for any of these
networks is **rejected** by nimrod's `validateSnapshotMetadata` at
`snapshot.nim:636-645` with the error "Assumeutxo height in snapshot
metadata not recognized (0) - refusing to load snapshot". This blocks
fast-sync on test networks AND prevents nimrod from running Core's
own `feature_assumeutxo.py` against a regtest fixture (which needs
heights 110, 200, 299 in the whitelist). Mainnet entries match Core
verbatim — only the test networks are gapped.

---

### BUG-9 (G21, P2) — `chainTxCount` not written to BlockIndex on load

Core `validation.cpp:5949`:
```cpp
index->m_chain_tx_count = au_data.m_chain_tx_count;
```

nimrod `loadSnapshot` at `:778-780` updates only `bestBlockHash` +
`bestHeight`. `BlockIndex.nTx` (the W57-added cumulative tx count) is
not populated for the snapshot base. Consequence: `getblockheader`
returns `nTx = 0` for the snapshot base block until normal block sync
catches up; `getchaintxstats` is wrong for any window crossing the
snapshot base; `verificationprogress` (Core's `GuessVerificationProgress`,
which uses `m_chain_tx_count`) returns incorrect values until backfill.

---

### BUG-10 (G22, P2) — `BLOCK_OPT_WITNESS` flag not set on activated chain

Core `validation.cpp:5930-5945` walks every block from height 1 to
`snapshot_chainstate.m_chain.Height()` and sets `BLOCK_OPT_WITNESS` on
each `index->nStatus` when `DeploymentActiveAt(...SEGWIT)`. Purpose:
prevent `Chainstate::NeedsRedownload()` from asking for `-reindex` on
the next startup. nimrod has no such loop — `BlockStatus` is a single
enum (`primitives/types.nim`, single byte at `chainstate.nim:178`), so
the bitwise OR is structurally impossible. If nimrod ever lands a
`NeedsRedownload`-equivalent check, snapshot-loaded chains will
self-corrupt.

---

### BUG-11 (G23, P0-CDIV) — No two-chainstate manager / no background validation chain

This is the largest gap. Core's `ChainstateManager` owns
`m_chainstates: std::vector<std::unique_ptr<Chainstate>>` where during
snapshot mode there are TWO chainstates: the historical / background
validation chainstate (validates from genesis) and the snapshot /
active chainstate (built from the snapshot). `MaybeValidateSnapshot`
fires when the historical chain reaches the snapshot base block and
computes the UTXO hash of the historical chainstate's coinsdb,
comparing against the hardcoded `au_data.hash_serialized`. If they
disagree, `handle_invalid_snapshot` (`validation.cpp:5987-6017`)
triggers a `fatalError` and the snapshot dir is renamed `_INVALID`.

nimrod has a SINGLE `ChainState* = ref object` (`chainstate.nim:88-133`).
The snapshot path mutates this in-place. There is NO background
chainstate. The `SnapshotChainState` and `BackgroundValidation` types
in `snapshot.nim:80-91` exist as forward-looking scaffolding but are
never instantiated in the production startup path — `nimrod.nim:1976`
calls `loadSnapshot(...)` directly on the single live ChainState.
`BackgroundValidation.runBackgroundValidation` (`snapshot.nim:886-912`)
is dead code with no call site (verifiable via `grep -rn
"runBackgroundValidation" src/` = 0 matches outside the file itself).

Consequence: a bad snapshot CANNOT be detected after-the-fact in nimrod.
Once `--load-snapshot` returns, the tip is pinned. If the hash was
correct at activation time but tampered later (via filesystem swap), or
if the assumeutxoData entry itself is wrong, nimrod will happily build
on top.

---

### BUG-12 (G24, P1) — `base_blockhash` marker file not written

Core writes `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` into the
snapshot chainstate dir (`utxo_snapshot.cpp:22-46`). On restart,
`LoadAssumeutxoChainstate` (`validation.cpp:6151-6168`) re-reads this
file to rediscover the snapshot tip and reconstruct the dual-chainstate
view.

nimrod writes nothing of the sort. After `--load-snapshot=<path>` runs,
the only on-disk evidence of snapshot provenance is the chainstate's
`bestBlockHash` field — which is indistinguishable from a normally-synced
chainstate. Restart silently picks up the chainstate as if it had been
fully validated, and Core's "snapshot needs background validation"
state machine is unreachable.

---

### BUG-13 (G25, P1) — `_snapshot` directory suffix missing

Core's snapshot chainstate's leveldb dir is named
`chainstate<SNAPSHOT_CHAINSTATE_SUFFIX>` = `chainstate_snapshot`
(`utxo_snapshot.h:128`). `FindAssumeutxoChainstateDir` keys off this
suffix. nimrod has one RocksDB dir per network with no suffix variant
— the snapshot's loaded coins are merged into the same column
families as a normal sync.

Consequence: (a) impossible to atomically wipe just the snapshot
without wiping the whole chainstate; (b) `cleanup_bad_snapshot`-style
recovery (Core `validation.cpp:5677-5694`) cannot work without
filesystem-level isolation; (c) `ValidatedSnapshotCleanup`'s rename
dance (BUG-16) needs this suffix to operate.

---

### BUG-14 (G26, P1) — `validateSnapshot` is a stub (hash compare absent)

`snapshot.nim:852-871`:
```nim
proc validateSnapshot*(...): SnapshotValidationResult =
  ## Stub-level "did the background chain reach the snapshot?" check. This
  ## intentionally does NOT compute a UTXO hash from `backgroundCs` since
  ## that requires a UTXO iterator we don't yet expose.
  ...
  # Without a UTXO iterator we cannot byte-verify here. Mark validated.
  snapshotCs.assumeutxo = auValidated
  return svrValid
```

The comment is the bug confession. Core `validation.cpp:6036-6066`
runs `ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...)` on
the background chainstate's coinsdb and compares against
`au_data.hash_serialized`. Mismatch triggers fatalError. nimrod skips
the actual hash compare. Even if BUG-11 (two-chainstate manager) were
fixed, this stub means bad snapshots would still be undetected.

Required wiring: a UTXO cursor over RocksDB's `cfUtxo` column family
piped through a `HashWriter` (which already exists at
`crypto/hashing.nim`), comparing against
`SnapshotChainState.targetUtxoHash`.

---

### BUG-15 (G27, P1) — Bad-snapshot recovery (`_INVALID` rename + fatalError) missing

Core `validation.cpp:6201-6231` (`InvalidateCoinsDBOnDisk`): renames
the snapshot chainstate dir to `<dir>_INVALID` for forensics, raises a
`fatalError` (which propagates through GUI notifications, stops the
node, instructs the operator). nimrod's `validateSnapshot` returns
`svrInvalid` (`snapshot.nim:863`) — there is no rename, no fatal-error
plumbing, no operator notification.

Consequence: a bad snapshot is silently mis-validated and the daemon
keeps running on the corrupted UTXO set. Combined with BUG-14 this is
"no detection, no recovery".

---

### BUG-16 (G28, P2) — `ValidatedSnapshotCleanup` rename dance missing

Core `validation.cpp:6280-6345`: after the background chain validates
the snapshot, the background chainstate dir is renamed to `_todelete`,
the snapshot dir is renamed to the canonical `chainstate` dir, and
`_todelete` is wiped. nimrod has no analog. Without the dual
chainstate (BUG-11) this is moot, but landing the dual model without
the cleanup leaves dead leveldb dirs forever.

---

### BUG-17 (G29, P2) — `dumptxoutset` partial: fifo / `nchaintx` always / cursor-snapshot

(a) **FIFO handling**: Core `rpc/blockchain.cpp:3137` checks
`fs::is_fifo(path_info)` and writes directly to the fifo, skipping the
.incomplete temp + rename. nimrod's `createSnapshot` always uses
`.incomplete` (`snapshot.nim:563`). Piping `dumptxoutset` to a named
pipe blocks indefinitely waiting for an atomic rename that can never
happen on a fifo.

(b) **`nchaintx` field conditional**: nimrod emits `nchaintx` ONLY
when the dump base matches a hardcoded assumeutxoData entry
(`server.nim:5023-5028`). Core emits `nchaintx = tip->m_chain_tx_count`
ALWAYS (`rpc/blockchain.cpp:3346`). Operators using `dumptxoutset` at
a non-assumeutxo height (e.g. operator at height 750_000 dumping for
internal use) get a response that's missing a field Core always
emits.

(c) **Cursor-based snapshot semantics**: Core's `pcursor` is a
leveldb cursor that iterates over a LEVELDB SNAPSHOT
(`rpc/blockchain.cpp:3248`) — concurrent UTXO writes during the dump
don't tear. nimrod iterates `cs.utxoCache` directly (`snapshot.nim:522`)
which is a mutable `Table[OutPoint, UtxoEntry]`. The NetworkDisable
gate (`server.nim:4937`) reduces but does not eliminate the race
because internal flushes / reorg paths can still mutate the cache
while `createSnapshot` is walking it.

---

### BUG-18 (G30, P2) — `loadtxoutset` RPC disabled + service flag + `getchainstates`

(a) `loadtxoutset` RPC unconditionally throws RpcInternalError
(`server.nim:5080-5088`) — the wired path is CLI startup-only. Core
supports both, and `loadtxoutset` is documented as the primary entry
point. Side effect: cross-impl smoke tests that POST `loadtxoutset` to
the RPC see a hard refusal (cross-referenced in the comment at
`server.nim:5063` to a 2026-05-05 cross-impl audit).

(b) Service-flag flip missing: Core `rpc/blockchain.cpp:3432-3435`:
```cpp
node.connman->RemoveLocalServices(NODE_NETWORK);
node.connman->AddLocalServices(NODE_NETWORK_LIMITED);
```
This is because a snapshot-loaded node cannot serve blocks below the
snapshot base. nimrod's PeerManager exposes service-flag mutation
(`network/peer.nim` advertises NODE_NETWORK by default) but the
startup-snapshot path (`nimrod.nim:1976-1988`) never calls it.

(c) `getchainstates` RPC missing. The dispatch table at
`server.nim:8234-8275` has no `of "getchainstates":` arm. Operators
cannot ask "is this a snapshot chain?" / "what's the background
validation progress?". This is BIP-ungate-able (just an RPC) but it's
how Core's dual-chainstate state is observable.

---

### Additional notes (P3 — cosmetic / contract)

- **`SnapshotChainState.assumeutxo` initialized to `auValidated`** at
  `snapshot.nim:790` is structurally wrong. A fresh snapshot
  chainstate should start `auUnvalidated`. Today this doesn't trip
  anything because BUG-11 means `SnapshotChainState` is never
  instantiated, but if/when the dual model lands this default will
  bypass G16.
- **MAX_SCRIPT_SIZE guard** at `snapshot.nim:286` / `:439` uses
  `16505`. Core's `compressor.h` allows up to
  `0x10000 + 6` (= 65542) via the nSize encoding. 16505 is too tight
  — a legitimate non-standard script of size 17000 (within Core's
  consensus limit of 10000 but Core's compressor's WIDER bound of
  ~65540 used during decompression) would be rejected on load.
- **`SnapshotError` messages partly diverge from Core verbatim**:
  e.g. "snapshot file not found: %s" vs Core's "Couldn't open file
  %s for reading." (`rpc/blockchain.cpp:3413-3415`). Downstream
  tooling pattern-matches Core's verbatim strings.
- **`BackgroundValidation.progress` not asserted monotonic**: the
  async loop at `snapshot.nim:886-912` does `inc bgv.progress` without
  validating that `bgv.progress <= bgv.targetHeight + 1` after every
  step. A bug in `getNextBlock` returning the wrong height would
  silently advance past the target.

## Universal patterns

This wave was a single-impl audit so cross-impl patterns are noted for
the audit framework but no fleet-sweep is implied.

1. **"Wrapper-scaffolding without call site"** (`SnapshotChainState`,
   `BackgroundValidation` in `snapshot.nim`). Pattern shape: a type
   exists for a Core-feature, exposes the right API surface, but
   `grep -rn newSnapshotChainState src/` outside the file = 0 matches.
   The TYPE is correct, the PLUMBING is missing. Same pattern as
   nimrod's RelayManager dead module in W136 (cross-reference
   `audit/w136_relay_flags.md` BUG-1 / G1).
2. **"P0-CDIV hiding behind audit framework assumption"** (BUG-8 / G19
   testnet4 / signet / regtest empty assumeutxoData). Pattern shape:
   a per-network table populated for ONE network (mainnet) and empty
   for OTHERS, where Core has entries for all 4 / 5. The mainnet entry
   makes the code path look "implemented" but it's not exercised on
   any test network. Audit framework should always check ALL networks'
   per-feature data tables, not just mainnet. Same pattern surfaced
   in W122 BIP-158 stress audit for nimrod's filter-format-version
   bump.
3. **"Audit framework requires reading the CONFESS comments"** —
   BUG-14 was a one-line confession at `snapshot.nim:856`: "this
   intentionally does NOT compute a UTXO hash... requires a UTXO
   iterator we don't yet expose". Same pattern as W122 blockbrew's
   "test-comment-as-confession" finding. When a comment explains why
   a check is missing, that comment IS the audit finding — flag it
   verbatim with the line number.
4. **"Polarity-inverted guard"** (BUG-5 / G16). Pattern: error string
   matches Core verbatim, but the boolean predicate is wrong. Audit
   framework should never trust string-match as proof of correctness
   — diff the PREDICATE, not the MESSAGE. Same pattern as FIX-80
   clearbit's IBD latch (string was right, the comparator was the bug).

## Out of scope for W138

Items NOT audited (deferred to future waves):

- **Bench / performance** of streaming load — Core uses `FlushSnapshotToDisk`
  every 120000 coins (`validation.cpp:5840-5856`); nimrod does not
  batch-flush during load.
- **`scrubunspendable` RPC** (`server.nim:8274-8275`) — related to
  snapshot data hygiene but a separate scope.
- **MuHash3072** UTXO commitment path (`crypto/muhash.nim`) — that
  serves `gettxoutsetinfo hash_type=muhash`, NOT assumeutxo, per the
  comments at `snapshot.nim:577-582`.
- **Cross-impl parity** with the other 9 nodes — single-impl audit.
- **Snapshot rate-limit / interruption** during background validation
  (Core `SnapshotUTXOHashBreakpoint` at `validation.cpp:5749-5752`) —
  noted but not audited.

## Cross-references

- Prior parity work: `CORE-PARITY-AUDIT/_snapshot-cli-rpc-parity-audit-2026-05-05.md`
  (cross-impl loadtxoutset RPC vs CLI behaviour, cited at
  `server.nim:5071`).
- Audit-as-suite pattern: `audit/w120_mempool_rbf.md`,
  `audit/w122_bip158_codec_stress.md`,
  `audit/w136_relay_flags.md`, `audit/w137_psbt.md`.
- Test suite: `tests/test_w138_assumeutxo.nim` (this commit).
