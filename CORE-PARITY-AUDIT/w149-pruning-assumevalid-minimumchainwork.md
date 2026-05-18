# W149 — Pruning + AssumeValid + MinimumChainWork (nimrod)

**Wave:** W149 — `FindFilesToPrune`, `FindFilesToPruneManual`, `PruneOneBlockFile`,
`UnlinkPrunedFiles`, `m_have_pruned`, `MIN_BLOCKS_TO_KEEP=288`,
`pruneblockchain` RPC; `BLOCK_ASSUMED_VALID` / `fScriptChecks`
script-skip gate, `defaultAssumeValid` per network;
`nMinimumChainWork` / `UpdateIBDStatus` / `MinimumConnectedChainWork`,
`-prune=N` (`0`/`1`/`>=550`) argument parsing.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/node/blockstorage.cpp:292-319` — `FindFilesToPruneManual`
  (assert `IsPruneMode()` + `nManualPruneHeight > 0`, walks via
  `Chainstate::GetPruneRange`, prunes any blk*.dat whose `nHeightLast` is
  at or below `last_block_can_prune` AND whose `nHeightFirst` is at or
  above `min_block_to_prune`).
- `bitcoin-core/src/node/blockstorage.cpp:321-410` — `FindFilesToPrune`
  (target = `max(MIN_DISK_SPACE_FOR_BLOCK_FILES, GetPruneTarget() / num_chainstates)`,
  halves the target while a background chainstate is validating an
  assumeUTXO snapshot, accounts for IBD remaining-blocks buffer).
- `bitcoin-core/src/validation.cpp:6347-6373` — `Chainstate::GetPruneRange`
  (snapshot semantics: when this is a snapshot chain that has not yet been
  fully validated, `prune_start = SnapshotBase()->nHeight + 1` — that is,
  blocks AT or BELOW the snapshot base are kept; blocks ABOVE the snapshot
  base are pruneable. The opposite of nimrod's `assumeUtxoFloor`).
- `bitcoin-core/src/validation.h:79` — `MIN_BLOCKS_TO_KEEP = 288`.
- `bitcoin-core/src/init.cpp` — `-prune=N` argument: `0` disables, `1` is
  manual-only sentinel (`IsPruneMode() == true`, auto-prune off), `>=550`
  enables auto-prune to the byte budget.
- `bitcoin-core/src/validation.cpp:2345-2383` — `BLOCK_ASSUMED_VALID`
  propagation + `fScriptChecks` skip gate in `ConnectBlock`. The 6-condition
  ancestor check (assumevalid hash set; in index; block is ancestor of
  assumevalid; block is ancestor of best_header; best_header chainwork
  ≥ MinimumChainWork; best_header at least `TWO_WEEKS_IN_SECONDS` of
  equivalent work past block via `GetBlockProofEquivalentTime`).
- `bitcoin-core/src/chain.cpp:136-151` — `GetBlockProofEquivalentTime`
  (CHAINWORK-difference / GetBlockProof(tip) * params.nPowTargetSpacing).
- `bitcoin-core/src/kernel/chainparams.cpp` — `consensus.defaultAssumeValid`
  per network. Signet ships a `defaultAssumeValid` hash at height ~293,175;
  hash AND height are both encoded into Core's `BLOCK_ASSUMED_VALID`
  propagation via the in-index `LookupBlockIndex(defaultAssumeValid)`.
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd` latched
  to false when `IsTipRecent(MinimumChainWork(), max_tip_age)`).
- `bitcoin-core/src/net_processing.cpp` — `MinimumConnectedChainWork`
  governs outbound-peer eviction of low-work chains.

## Files audited

- `src/storage/pruner.nim` — production prune driver
  (`PruneMode`/`pmDisabled`/`pmManualOnly`/`pmAutomatic`, `pruneToHeight`,
  `autoPruneIfNeeded`, `assumeUtxoFloor`, `estimateCurrentUsage`,
  `pruneBlockBodyAtHeight`, `unlinkObsoleteUndoFiles`, `clearBlockHaveBits`).
- `src/storage/blockstore.nim` — `BlockFileManager`, `MIN_BLOCKS_TO_KEEP`,
  `findFilesToPruneManual`, `findFilesToPrune`, `pruneOneBlockFile`,
  flat-file metadata bookkeeping (`blk*.dat` / `rev*.dat`).
- `src/storage/chainstate.nim:719-737, 822-836, 1255-1270, 1857-1872` —
  `buildAssumeValidContext`, three `shouldSkipScripts` call sites inside
  `connectBlock` / `connectBlockIBD` / reorg connect loop (all three only
  USE the gate to bypass coinbase maturity; the script-skip semantics live
  upstream in caller code).
- `src/consensus/assumevalid.nim` — 6-condition ancestor-check engine
  (`ScriptSkipReason`, `AssumeValidContext`, `shouldSkipScripts`,
  `TwoWeeksInBlocks = 2016`).
- `src/consensus/chain.nim:111-163` — `CheckpointState`
  (`isAssumeValidBlock`, `shouldSkipScriptVerification`,
  `meetsMinimumWork`, `verifyMinimumWork`) — a second, parallel assumevalid
  + min-chain-work engine that coexists with `assumevalid.nim`.
- `src/consensus/params.nim` — per-network `assumeValidBlockHash`,
  `assumeValidHeight`, `minimumChainWork`, `MinBlocksToKeep = 288`,
  `assumeutxoData`.
- `src/consensus/validation.nim:767-826, 1265-1283, 1911-1991` —
  `validateBlockHeader` / `validateBlock` / `acceptBlock` with
  `minPowChecked` plumbing.
- `src/network/sync.nim:412-435, 800-940, 1080-1148, 1660-1719` —
  PRESYNC / `minPowChecked` plumbing, `computeMinimumRequiredWork`,
  the two non-RPC assumevalid call sites (`applyBlock` IBD path and
  `processReceivedBlocks` parallel-download path).
- `src/nimrod.nim:165-218, 393-396, 530-547, 602-606, 940-958,
  1888-1898, 1993-2015, 2363-2370, 2522-2548` — CLI plumbing for
  `--prune`, `--reindex`, the version-handshake `NODE_NETWORK_LIMITED`
  latch, `applyReindex`, the heartbeat auto-prune trigger,
  `BIP-159 peerblockfilters` cross-check.
- `src/rpc/server.nim:305-372, 3742-3757, 4530-4537, 4753-4804` —
  `getblockchaininfo` pruning fields, `pruneblockchain` RPC handler,
  `submitblock` skipScripts gate.

---

## Gate matrix (33 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` arg parsing | G1: `0` disabled, `1` manual sentinel, `>=550` auto, `2..549` rejected | PASS (`nimrod.nim:530-547`) |
| 1 | … | G2: `pmManualOnly` mode honored by `pruneblockchain` RPC and skipped by auto trigger | PASS (`pruner.nim:421-422, 458-459`) |
| 1 | … | G3: `-prune=N` toggles `NODE_NETWORK_LIMITED` advertisement | PASS (`nimrod.nim:1898`, `peer.nim:580`) |
| 1 | … | G4: `-prune=N` toggles `m_have_pruned` analog persisted to disk | **BUG-1 (P1)** no `m_have_pruned` analog. nimrod persists `pruneHeight` (`pruner.nim:91-106`) but never sets a "have ever pruned" boolean that survives restart, so RPC `getblockchaininfo.pruned` is `false` whenever `--prune` is dropped from CLI even if the on-disk store was previously pruned. |
| 2 | `pruneblockchain` RPC | G5: rejects when not in prune mode | PASS (`server.nim:4775-4777`) |
| 2 | … | G6: rejects negative height | PASS (`server.nim:4785-4786`) |
| 2 | … | G7: timestamp-mode (height ≥ 1e9) → resolve to block | **BUG-2 (P2)** Core's `pruneblockchain` accepts a unix timestamp and calls `GetBlockHashByTime`; nimrod hard-rejects with an "unsupported" error (`server.nim:4791-4793`). Loses Bitcoin-Core API parity for monitoring scripts. |
| 2 | … | G8: caps requested height at tip − MIN_BLOCKS_TO_KEEP via internal clamp | PASS via `pruner.nim:377` |
| 3 | `FindFilesToPrune` semantics | G9: target derived from `-prune=N` in MiB, floored at 550 MiB | PASS (`pruner.nim:152-156`) |
| 3 | … | G10: target halved during background-chainstate validation of assumeUTXO snapshot | **BUG-3 (P1)** Core divides target by `num_chainstates` (`blockstorage.cpp:336`) — nimrod has no background-chainstate concept at all (see W138 dead-class) so the divider is moot, but the calculation also never halves regardless. Operators loading an assumeUTXO snapshot get a 2× higher effective target than Core. |
| 3 | … | G11: IBD remaining-blocks buffer added to nBuffer | **BUG-4 (P2)** Core inflates nBuffer by `average_block_size × remaining_blocks` during IBD (`blockstorage.cpp:363-368`) so it does not over-prune blocks that are about to be re-fetched. nimrod's `autoPruneIfNeeded` (`pruner.nim:417-456`) has no equivalent — a node that just exited IBD and immediately re-entered (e.g. peer churn after restart) will over-aggressively prune. |
| 4 | `Chainstate::GetPruneRange` snapshot floor | G12: snapshot present → `prune_start = SnapshotBase().nHeight + 1` (keep blocks BELOW snapshot) | **BUG-5 (P0-CDIV)** `pruner.nim:174-186` (`assumeUtxoFloor`) inverts the semantics. nimrod refuses to prune blocks at OR ABOVE the snapshot base; Core refuses to prune blocks AT OR BELOW the snapshot base (because the background chainstate needs them to historically validate the snapshot). With nimrod's logic, after loading an assumeUTXO snapshot at h=840000, auto-prune CAN delete h=839999 (still needed if background validation ever wires) but CANNOT delete h=840001..tip (which Core readily prunes). Cross-cite: comment at `pruner.nim:179-181` confidently asserts the wrong direction. |
| 4 | … | G13: snapshot floor lifts after `Assumeutxo::VALIDATED` | **BUG-6 (P1)** Core releases the prune floor once background validation completes (`validation.cpp:6354`); nimrod's `assumeUtxoFloor` is computed from `params.assumeutxoData` (a CONFIG list, not runtime state) so the floor is FOREVER pinned to the LOWEST hardcoded snapshot height (`pruner.nim:182-186`). Mainnet `params.assumeutxoData` has FOUR entries; the floor latches to 840000 permanently regardless of whether the operator actually loaded any of them. |
| 5 | Auto-prune heartbeat trigger | G14: cadence ≈ "after every flush" (Core) | **BUG-7 (P1)** nimrod calls `autoPruneIfNeeded` from a 10-second heartbeat (`nimrod.nim:2366-2370, 2381`). The field `blocksSinceLastCheck` (`pruner.nim:77`) is named "blocks" but is incremented per HEARTBEAT (`pruner.nim:424`), so `AutoPruneCheckInterval = 200` resolves to 200 × 10s = ~33 min real-time. On a mainnet node receiving 1 block / 10 min (~6 blocks per check window) the trigger fires at ~3% the block cadence of Core (which checks after EACH block flush). Comment at `pruner.nim:56-59` claims "200 blocks ≈ 30-40 min of mainnet sync" — the unit is wrong (heartbeats, not blocks); it just HAPPENS to land at the same ballpark because mainnet blocks ≈ 10 min ≈ 60 heartbeats. On a fast regtest or testnet4 (10× faster blocks) the trigger lags 10×. |
| 5 | … | G15: lock/serial discipline (single-writer to chainstate during prune) | PARTIAL — `pruneToHeight` opens a write-batch and commits in one atomic shot; no explicit lock vs. ConnectBlock, so a heartbeat-driven prune racing a P2P-driven block-connect can interleave (the batch is atomic at RocksDB level, but pruneHeight is updated outside the chainstate write-batch — see G19 below). |
| 6 | `BLOCK_HAVE_DATA` / `m_have_pruned` semantics | G16: per-block `BLOCK_HAVE_DATA` bit cleared on prune | PARTIAL — `clearBlockHaveBits` (`pruner.nim:253-263`) demotes status FROM `bsDataStored`/`bsValidated` TO `bsHeaderOnly`. That is a one-bit ladder for nimrod (BlockStatus = 4 ordered states); Core uses a bitmask where HAVE_DATA is independent of validity. **BUG-8 (P1)** consequence: a `bsValidated` block that is pruned LOSES its validation status — on a subsequent restart it shows as `bsHeaderOnly` indistinguishable from a header we never had the body for. Core preserves `BLOCK_VALID_SCRIPTS` even after pruning the body. |
| 6 | … | G17: per-block `BLOCK_HAVE_UNDO` bit cleared on prune | PARTIAL via the same status demotion (no independent HAVE_UNDO bit; `undoPos` is reset to `(-1, -1)`). |
| 6 | … | G18: `m_have_pruned` global cleared/set | **BUG-1 cross-cite** — absent entirely. |
| 7 | `unlinkObsoleteUndoFiles` correctness | G19: walks active-chain only (`getBlockHashByHeight` is active-chain) | **BUG-9 (P0)** `pruner.nim:330-341` builds the `referenced` set by walking `getBlockHashByHeight(h)` for `h ∈ [pruneHeight, tip]`. Side-branch blocks accepted via Pattern Y (`submitblock` RPC against a non-extending header — `rpc/server.nim:3805-3820`) have undo positions in rev*.dat files but are NOT on the active chain. Their `undoPos.fileNum` will not appear in `referenced`, so `unlinkObsoleteUndoFiles` happily deletes a rev file that still holds undo data needed for a future reorg ONTO that side branch. Same shape as W148 BUG-9 (skip-list missing) on the disconnect-side; here it is the symmetric deletion-side leak. |
| 7 | … | G20: keep highest-numbered rev*.dat (currently-being-written) | **BUG-10 (P2)** doc comment at `pruner.nim:314-316` says "keep the highest-numbered rev*.dat untouched". The code does not implement that guard — the for-loop at `pruner.nim:344-354` iterates `0 .. 4096` and unlinks any unreferenced file including the latest. If a reorg disconnects mid-loop, the in-flight write to the latest rev*.dat could land on a just-unlinked file inode. Documented-but-not-implemented. |
| 7 | … | G21: bounded walk (Core: while file_num <= prune_file) | PARTIAL — hardcoded `0 .. 4096` upper bound (`pruner.nim:344`) instead of `bfm.currentFileNum`. Cheap; correctness-OK but wasteful. |
| 8 | AssumeValid 6-condition ancestor check | G22: assumevalid hash set (non-zero) | PASS (`assumevalid.nim:110`) |
| 8 | … | G23: assumevalid hash in local block index | PARTIAL — implemented as "have active-chain hash at assumeValidHeight" (`assumevalid.nim:115-118`). Core's check is `LookupBlockIndex(defaultAssumeValid) != nullptr` (header-chain index, NOT active chain). The comment at `assumevalid.nim:66-71` acknowledges the divergence and claims to use the header chain via `activeHashAtBlockHeight`, but the callers in `chainstate.nim:719-737` pass `cs.db.getBlockHashByHeight(...)` which IS active-chain. Header-chain vs active-chain divergence: during IBD with split header sync the active chain reaches `assumeValidHeight` long after headers do, so the script-skip gate never fires. |
| 8 | … | G24: ancestor check via `assumeValidIndex.GetAncestor(pindex->nHeight) == pindex` | DIVERGE — implemented via 2-component equality (block at height matches AND assumevalid at its height matches; `assumevalid.nim:120-144`). Equivalent only under strict active-chain semantics — see G23. |
| 8 | … | G25: best-header at least 2 weeks past block via `GetBlockProofEquivalentTime` (CHAINWORK-based) | **BUG-11 (P1)** `assumevalid.nim:160` uses height-difference (`bestHeaderHeight - blockHeight >= TwoWeeksInBlocks=2016`). Core uses `GetBlockProofEquivalentTime` (`chain.cpp:136-151`) which is CHAINWORK / GetBlockProof(tip) * params.nPowTargetSpacing. On testnet (min-difficulty blocks) and testnet4 (BIP-94 timewarp regions) chainwork advances at ~1/1000 the rate of height, so the 2-week guard would refuse to skip scripts even when 100k+ height of headers have arrived. nimrod silently skips. The comment at `assumevalid.nim:30-32` acknowledges "we approximate with block-count distance" — documented divergence from Core. |
| 9 | Per-network defaultAssumeValid | G26: mainnet hash + height both set | PASS (`params.nim:204-206`) |
| 9 | … | G27: testnet3 + testnet4 both set | PASS |
| 9 | … | G28: signet `defaultAssumeValid` set | **BUG-12 (P0)** `params.nim:451-453` sets `assumeValidBlockHash` for signet but NEVER sets `assumeValidHeight` (left at the default int32 zero). Condition 2 of `shouldSkipScripts` (`assumevalid.nim:113-118`) looks up `getBlockHashByHeight(0)` which returns the GENESIS hash, not the signet assumevalid hash → returns `ssrNotAncestorOfAssumeValid` for every signet block. Signet operators sync with FULL script verification, ~10-50× slower than Core. The same fix pattern as the testnet4 entry (`params.nim:391-393`) was simply skipped on signet. |
| 9 | … | G29: regtest `assumeValidBlockHash` = zero (always verify) | PASS (`params.nim:505`) — `ssrAssumeValidUnset` fires correctly. |
| 9 | … | G30: `-assumevalid=0` / `-assumevalid=<hash>` CLI override | **BUG-13 (P1)** Core's `-assumevalid` accepts both `0` (turn off entirely) and a hex hash (replace shipped value). nimrod has NO CLI flag for assumevalid at all (`nimrod.nim:380-450`); a dead comment in `network/sync.nim:1670` even references "`--noassumevalid` operators" — the flag does not exist. Operators wanting full-script verification must rebuild the binary. |
| 10 | MinimumChainWork | G31: per-network `nMinimumChainWork` non-zero (mainnet/testnet3/testnet4/signet) | PASS (`params.nim:200, 323, 387, 448`). |
| 10 | … | G32: `-minimumchainwork` CLI override | **BUG-14 (P1)** Core ships `-minimumchainwork=<hex>` as an operator override (init.cpp). nimrod has no CLI knob; the value is compile-time. |
| 10 | … | G33: `IsInitialBlockDownload` gate uses MinimumChainWork + tip-recent | **BUG-15 (P0-CDIV)** RPC `getblockchaininfo.initialblockdownload` is hardcoded to `bestHeight < 100` (`rpc/server.nim:345`). Has NOTHING to do with MinimumChainWork or tip-recent. On regtest a node at h=150 returns `initialblockdownload=false` even with zero peer connections. On mainnet during a deep reorg or a stalled sync at h=900000 it returns false even when the active tip is months stale. |

---

## BUG-1 (P1) — No `m_have_pruned` global persisted across restarts

**Severity:** P1. Bitcoin Core `BlockManager::m_have_pruned` is a boolean
loaded from `BlockTreeDB` (`blockstorage.cpp:578`) that latches once any
block has ever been pruned on this datadir. `getblockchaininfo.pruned`
is `m_have_pruned`, NOT a function of the CURRENT `-prune` flag. Once
true, the value stays true forever; operators dropping `-prune` from the
CLI still see `pruned=true` reflecting the on-disk state.

nimrod has no equivalent. `getblockchaininfo` decides `pruned`
purely from runtime `rpc.pruner != nil and rpc.pruner.isPruning`
(`rpc/server.nim:319`). Drop `--prune` on the next startup and a node
with 800k pruned blocks reports `pruned=false`. Wallet code that
queries `pruned` before doing a rescan (Core convention) silently
attempts to read absent blocks.

**File:** `src/storage/pruner.nim:84-118` (state persistence),
`src/rpc/server.nim:315-327` (getblockchaininfo dispatch).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:578` (`ReadFlag("prunedblockfiles", m_have_pruned)`).

**Impact:** Wallet/RPC consumers can't tell if the on-disk store has
ever been pruned. `gettxoutproof`, `getrawtransaction`, `wallet
rescanblockchain` all use this signal.

---

## BUG-2 (P2) — `pruneblockchain` RPC rejects unix-timestamp argument

**Severity:** P2. Bitcoin Core's `pruneblockchain` accepts a value
≥ 1_000_000_000 as a unix timestamp and resolves it to a block via
`GetBlockHashByTime`. nimrod hard-rejects with `"Could not find block
with at least the specified timestamp"` (`server.nim:4791-4793`) — the
error string matches Core's "no such block" path but the rejection
fires UNCONDITIONALLY, even when a block with that timestamp exists.

**File:** `src/rpc/server.nim:4791-4793`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp` (`pruneblockchain`).

**Impact:** Monitoring scripts that pass a unix timestamp (e.g.
`pruneblockchain $(date -d '7 days ago' +%s)`) fail. Operator must
compute the height client-side.

---

## BUG-3 (P1) — Auto-prune target NOT halved during background-chainstate snapshot validation

**Severity:** P1. Bitcoin Core's `FindFilesToPrune`
(`blockstorage.cpp:335-337`) computes:
```cpp
const int num_chainstates{chainman.HistoricalChainstate() ? 2 : 1};
const auto target = std::max(MIN_DISK_SPACE_FOR_BLOCK_FILES, GetPruneTarget() / num_chainstates);
```
so a node loading an assumeUTXO snapshot keeps a 2× lower aggressive
target while the background chainstate is replaying history.

nimrod has no `HistoricalChainstate` concept (cross-cite W138 fleet
dead-class finding) and no halving. The `Pruner.targetBytes` field is
fixed at construction (`pruner.nim:142-157`) and never adjusted.
Operators loading an assumeUTXO snapshot on a `-prune=550` node
get the FULL 550 MiB budget for both the active and the background
chainstate, blowing through Core's 275 MiB-per-chainstate floor.

**File:** `src/storage/pruner.nim:142-157`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:335-337`

**Impact:** Disk-budget overshoot during assumeUTXO validation, plus
the underlying "no background chainstate" gap (W138).

---

## BUG-4 (P2) — IBD remaining-blocks buffer absent from auto-prune calc

**Severity:** P2. Core inflates `nBuffer` by
`average_block_size × remaining_blocks` during IBD
(`blockstorage.cpp:363-368`) so a node mid-IBD does not over-prune
blocks that will soon be re-fetched. nimrod's `autoPruneIfNeeded`
(`pruner.nim:417-456`) computes the buffer purely from a static
`AutoPruneFloorBytes`. After IBD-restart with a ~100k block gap to
catch up, the auto-prune trigger can fire aggressively on the
just-stored window.

**File:** `src/storage/pruner.nim:417-456`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:363-368`

**Impact:** Over-pruning during IBD churn → re-download of blocks that
were just deleted → wasted bandwidth.

---

## BUG-5 (P0-CDIV) — `assumeUtxoFloor` INVERTS Core's snapshot semantics

**Severity:** P0-CDIV. This is the central pruning-snapshot bug.

**Core (`validation.cpp:6354-6360`):**
```cpp
if (m_from_snapshot_blockhash && m_assumeutxo != Assumeutxo::VALIDATED) {
    // Only prune blocks _after_ the snapshot if this is a snapshot chain
    // that has not been fully validated yet. The earlier blocks need to be
    // kept to validate the snapshot
    prune_start = Assert(SnapshotBase())->nHeight + 1;
}
```
Core: blocks BELOW the snapshot height are KEPT (needed for background
validation); blocks ABOVE the snapshot height are PRUNEABLE.

**nimrod (`pruner.nim:376-383`):**
```nim
var ceiling = min(requestedTarget, tip - int32(params.MinBlocksToKeep))
let auFloor = p.assumeUtxoFloor()
if auFloor >= 0 and ceiling > auFloor:
  ceiling = auFloor
```
nimrod: blocks AT or ABOVE the snapshot height are KEPT; blocks BELOW
are pruneable. **Exactly inverted.**

**File:** `src/storage/pruner.nim:174-186` (`assumeUtxoFloor` —
returns lowest snapshot height) and `pruner.nim:376-383` (apply as
ceiling).

**Core ref:** `bitcoin-core/src/validation.cpp:6347-6373`
(`Chainstate::GetPruneRange`).

**Impact:**
- A nimrod node that loaded a snapshot at h=840000 and is now at
  h=850000 with `--prune=550`: nimrod refuses to prune anything past
  h=840000. The 10000 blocks of post-snapshot data accumulate
  unbounded, defeating the prune target.
- A nimrod node WITHOUT a loaded snapshot but with hardcoded snapshot
  metadata in `params.assumeutxoData` (mainnet ships FOUR entries):
  prune ceiling latches to h=840000 (the lowest), so all blocks past
  840000 are protected from pruning. As of late 2025 / 2026, that
  protects 100,000+ blocks of mainnet history forever.
- The comment-as-confession at `pruner.nim:179-181` ("Honor
  assumeutxo: never prune blocks at or above the snapshot floor by
  our own choice") inverts the actual reason for the floor: Core's
  reason is "we need the OLDER blocks to validate the snapshot", not
  "we need the NEWER blocks". Doc and code agree with each other and
  both disagree with Core.

This is the same pattern-class as fleet W128 banman / W144
script_flag_exceptions: a guard correctly identified but anchored in
the wrong direction.

---

## BUG-6 (P1) — Snapshot floor latches from CONFIG list, not runtime snapshot state

**Severity:** P1. Core's `m_assumeutxo` field tracks the runtime
status of the assumeUTXO subsystem (`Assumeutxo::VALIDATED` /
`PARTIAL` / `EMPTY`); `GetPruneRange` consults it. Once background
validation completes, the prune-start floor is released.

nimrod's `assumeUtxoFloor` (`pruner.nim:174-186`) reads
`p.params.assumeutxoData` — a CONFIG list hardcoded in
`params.nim:227-268`. There is no runtime "I have actually loaded a
snapshot, and it is in validation phase X" state. The floor is
latched to the LOWEST hardcoded snapshot height in the params (mainnet
= 840000) FOREVER, regardless of whether the operator ever loaded a
snapshot or not.

**File:** `src/storage/pruner.nim:174-186`

**Core ref:** `bitcoin-core/src/validation.cpp:6354`

**Impact:** A mainnet node that NEVER loaded any assumeUTXO snapshot
still gets the snapshot prune floor applied. Combined with BUG-5's
inverted direction, the result is: a default `--prune=550` mainnet
node refuses to prune anything past height 840000, defeating the
prune target the moment the chain crosses that height.

---

## BUG-7 (P1) — `blocksSinceLastCheck` counts heartbeats, not blocks

**Severity:** P1 (correctness of cadence). The field
`blocksSinceLastCheck` (`pruner.nim:77`) and constant
`AutoPruneCheckInterval = 200` (`pruner.nim:55-59`) read like a
per-block counter. The actual call-site
(`nimrod.nim:2366-2370`) is a 10-second heartbeat, and the increment
(`pruner.nim:424`) fires once per heartbeat regardless of block rate.

Result: `200 × 10s = 33 min` real-time cadence on any network.
Core checks after EACH block-file flush — i.e. roughly per block on
mainnet, dozens per second on regtest.

- **Mainnet** (~10 min/block): nimrod fires 1 check / ~3 blocks.
  Roughly compatible with Core by accident.
- **Testnet4 / signet** (irregular block timing, min-difficulty
  runs): nimrod still fires 1 check / 33 min even when 1000 blocks
  arrive in that window. Auto-prune lags badly.
- **Regtest**: a block-mining test that produces 200 blocks in a
  second never triggers the prune check.

The doc comment at `pruner.nim:56-59` claims "200 blocks ≈ 30-40 min
of mainnet sync, well under one block-file (128 MiB) of churn" —
the math is right but the UNIT is wrong; on a network where blocks
arrive faster than one per heartbeat, the constraint inverts.

**File:** `src/storage/pruner.nim:54-59, 77, 417-427`
(constant + field + increment); `src/nimrod.nim:2363-2381`
(heartbeat call site).

**Core ref:** `bitcoin-core/src/validation.cpp` (auto-prune triggers
on each `FlushStateToDisk` call).

**Impact:** Disk-budget enforcement uncoupled from actual sync rate.
Doc and code disagree on the unit (blocks vs heartbeats), guaranteeing
operator surprise.

---

## BUG-8 (P1) — Pruning destroys `bsValidated` status (no separate HAVE_DATA bit)

**Severity:** P1 (cross-cite W148 BUG-9 fleet pattern). Core's
`BlockStatus` separates the validity ladder (`BLOCK_VALID_*`) from the
storage bits (`BLOCK_HAVE_DATA`, `BLOCK_HAVE_UNDO`). Pruning clears
the storage bits but PRESERVES `BLOCK_VALID_SCRIPTS`. A pruned block
is still known-to-be-validated; the body is just gone.

nimrod's `BlockStatus` is a 4-state ordered enum
(`chainstate.nim:22-26`): `bsHeaderOnly`, `bsDataStored`, `bsValidated`,
`bsInvalid`. `clearBlockHaveBits` demotes FROM `bsDataStored` /
`bsValidated` TO `bsHeaderOnly` (`pruner.nim:253-263`). On a
subsequent restart, the block index entry shows `bsHeaderOnly` — the
node forgets it ever validated the block.

**File:** `src/storage/pruner.nim:253-263`

**Core ref:** `bitcoin-core/src/chain.h:42-86` (BLOCK_VALID_* vs
HAVE_* bits).

**Impact:**
- On reorg evaluation post-prune, the candidate-tip selection
  (`FindMostWorkChain` analog) cannot filter on
  `BLOCK_VALID_CHAIN`/`SCRIPTS` because the bit is no longer set.
- If a pruned block becomes a reorg target, it must be re-downloaded
  AND re-validated — Core would re-download but skip validation.
- Indistinguishable from "never had body" on restart, complicating
  diagnostic / repair tooling.

---

## BUG-9 (P0) — `unlinkObsoleteUndoFiles` walks active-chain only; side-branch undo files deleted

**Severity:** P0 (reorg-failure primitive). `unlinkObsoleteUndoFiles`
(`pruner.nim:318-354`) builds a `referenced: HashSet[int32]` of
rev*.dat file numbers by walking `getBlockHashByHeight(h)` for
`h ∈ [pruneHeight, tip]`. That helper is ACTIVE-CHAIN ONLY
(`db.nim:590-597` — single height→hash mapping, not multi-tip).

Side-branch blocks accepted via Pattern Y (`rpc/server.nim:3805-3820`,
`submitblock` on a non-extending header) DO get a `BlockIndex` entry
with `undoPos.fileNum >= 0` pointing at a rev*.dat. They are not on
the active chain, so their file numbers never enter `referenced`.
`unlinkObsoleteUndoFiles` happily deletes the rev*.dat — and the next
reorg that targets that side branch fails at the `DisconnectBlock`
stage with "missing undo data".

**File:** `src/storage/pruner.nim:318-354`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:804-832`
(`UnlinkPrunedFiles` — Core enumerates files by file number, not by
walking the active chain).

**Impact:** Silent data loss for side-branch undo data. Manifests
only on a deep reorg that crosses a prune boundary. Same shape as
W148 BUG-9 (active-chain-only walk in `recalculateBestTipLocked`).

---

## BUG-10 (P2) — Doc says "keep highest-numbered rev*.dat", code does not

**Severity:** P2. The module-level comment at `pruner.nim:314-316`
states: "keep the highest-numbered (currently-being-written) rev*.dat
untouched". The implementation at `pruner.nim:344-354` iterates
`0 .. 4096` and unlinks any file not in `referenced` — including the
highest-numbered one if it happens to be missing live referents
(e.g. during a stretch where new connects write to it but none have
been flushed-and-indexed yet).

**File:** `src/storage/pruner.nim:344-354`

**Impact:** Race condition between in-flight rev*.dat writes by
`UndoFileManager.writeBlockUndo` and the unlinker. Race window is
narrow (heartbeat-cadence, not per-block) so production occurrences
will be rare but undiagnosable.

---

## BUG-11 (P1) — 2-week guard uses HEIGHT distance, not `GetBlockProofEquivalentTime` (chainwork-based)

**Severity:** P1. Core's `BLOCK_ASSUMED_VALID` 6th condition
(`validation.cpp:2364`) uses
`GetBlockProofEquivalentTime(*m_best_header, *pindex, *m_best_header, params.GetConsensus())`
— a CHAINWORK-difference scaled by `params.nPowTargetSpacing` and the
tip's `GetBlockProof`. The metric is the equivalent NUMBER OF SECONDS
of mainnet-equivalent work past the candidate block.

nimrod's `shouldSkipScripts` (`assumevalid.nim:160`) uses
`bestHeaderHeight - blockHeight >= TwoWeeksInBlocks=2016` — a raw
height distance. The doc comment at `assumevalid.nim:30-32`
acknowledges "we approximate".

Divergence cases:
- **Testnet3 / testnet4 min-difficulty runs**: a 2016-height
  difference can carry only a tiny fraction of "2 weeks of mainnet
  work" because nBits sits at `0x1d00ffff`. nimrod skips scripts when
  Core would not.
- **BIP-94 timewarp regions on testnet4**: same direction.
- **Mainnet difficulty drops**: when the next-period difficulty
  drops significantly (e.g. after a halving + price crash), 2016
  blocks carries less work than at average difficulty; nimrod will
  skip when Core won't.
- **Mainnet difficulty rises**: 2016 blocks carries MORE work than 2
  weeks-equivalent; nimrod still skips at the height boundary; Core
  may skip earlier (chainwork crossed the threshold first).

**File:** `src/consensus/assumevalid.nim:25-32, 155-161`

**Core ref:** `bitcoin-core/src/chain.cpp:136-151`,
`bitcoin-core/src/validation.cpp:2364`.

**Impact:** Cross-impl test-vector divergence on testnet; possible
chain-split signal if a malicious peer can craft a chain that lands
exactly inside the gap between nimrod's height-metric and Core's
chainwork-metric.

---

## BUG-12 (P0) — Signet `assumeValidHeight` left at zero; assumevalid silently disabled

**Severity:** P0 (operational performance, not consensus). Every
network except signet sets BOTH `assumeValidBlockHash` AND
`assumeValidHeight`:
- Mainnet: `assumeValidHeight = 944_000` (`params.nim:186`)
- Testnet3: `assumeValidHeight = 123_613` (`params.nim:329`)
- Testnet4: `assumeValidHeight = 4_842_348` (`params.nim:393`)

Signet (`params.nim:402-460`) sets `assumeValidBlockHash` at line
451-453 but NEVER sets `assumeValidHeight`. The field defaults to
the int32 zero from `result` initialization.

Effect on `shouldSkipScripts`:
1. Condition 1 (`isZeroHash(params.assumeValidBlockHash)`) passes (hash
   is non-zero).
2. Condition 2 looks up
   `getBlockHashByHeight(params.assumeValidHeight=0)` which returns
   the GENESIS hash. `activeHashAtAssumeValidHeight = some(<genesis>)`.
3. Condition 3 then checks `activeHashAtAssumeValidHeight.get() !=
   params.assumeValidBlockHash` — `<genesis>` ≠
   `00000008414aab61...`, so returns `ssrNotAncestorOfAssumeValid`.

Every signet block trips condition 3 → full script verification.
Signet IBD ≈ 10-50× slower than Core.

**File:** `src/consensus/params.nim:402-460`

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp` (signet
`consensus.defaultAssumeValid` is paired with a height — Core derives
the height from the in-index lookup of the hash, but nimrod's gate is
height-comparison-first).

**Impact:** Signet operators sync 10-50× slower than Core. The
mistake is mechanical — the same one-line copy-paste fix used in
testnet4 was simply omitted. Free win.

---

## BUG-13 (P1) — No `-assumevalid=0` / `-assumevalid=<hash>` CLI override; dead comment references it

**Severity:** P1. Bitcoin Core ships
`-assumevalid=<hex_block_hash>` as an operator override:
- `0` → turn off assumevalid entirely (full script verification)
- `<hex>` → replace the shipped hash with the operator-supplied one
- Default (flag absent) → use `defaultAssumeValid` from chainparams.

nimrod has NO CLI flag for assumevalid (`nimrod.nim:380-450` exhaustively
lists supported flags; absent). The doc comment at
`src/network/sync.nim:1670` literally references
"`--noassumevalid` operators get full script verification on this
path" — but `--noassumevalid` does not exist. The comment is a confession
of an intended-but-never-shipped feature.

**File:** `src/nimrod.nim:380-450, 458-700` (CLI parse); dead
reference at `src/network/sync.nim:1670`.

**Core ref:** `bitcoin-core/src/init.cpp` (`-assumevalid` arg).

**Impact:**
- Operators wanting full script verification (auditors, fork
  contestants) must rebuild the binary.
- Comment-as-confession pattern: documented behavior diverges from
  shipped behavior.

---

## BUG-14 (P1) — No `-minimumchainwork=<hex>` CLI override

**Severity:** P1. Bitcoin Core's `-minimumchainwork=<hex>` arg lets
operators raise the minimum-chainwork bar for header acceptance —
useful for forensics, fork-contestant operation, and rapidly
deploying anti-DoS bumps without a binary release.

nimrod's `params.minimumChainWork` is compile-time
(`params.nim:200, 323, 387, 448, 504`). No CLI override; no config
file knob.

**File:** `src/consensus/params.nim:200, 323, 387, 448, 504`
(per-network values); `src/nimrod.nim:380-450` (CLI omits the
flag).

**Core ref:** `bitcoin-core/src/init.cpp` (`-minimumchainwork`).

**Impact:** Operator agility gap. During an active chain-split or
RBF-bypass campaign, the only way to raise the chainwork floor is a
rebuild + restart.

---

## BUG-15 (P0-CDIV) — `getblockchaininfo.initialblockdownload` hardcoded `bestHeight < 100`

**Severity:** P0-CDIV (RPC contract divergence). Bitcoin Core's
`IsInitialBlockDownload` (`validation.cpp:1940-1984`) is a latched
boolean that flips false when ALL of these become true:
1. `m_chain.Tip()->nChainWork >= MinimumChainWork()`
2. `IsTipRecent(MinimumChainWork(), max_tip_age)` (tip within
   max_tip_age seconds of wall-clock now)
3. Tip is not on a known-invalid chain

Once `m_cached_is_ibd.store(false)`, it stays false.

nimrod's `getblockchaininfo` (`rpc/server.nim:345`):
```nim
"initialblockdownload": rpc.chainState.bestHeight < 100,
```
A static threshold of 100 has nothing to do with chainwork or
recency.

Failure modes:
- **Regtest mining test that runs 100 blocks**: `initialblockdownload`
  flips false at h=100 regardless of any network state. Mempool
  acceptance policies that gate on `IsInitialBlockDownload()` flip
  with it.
- **Mainnet startup**: a fresh node hits h=100 within 30 seconds of
  syncing the first headers; `initialblockdownload` reports false
  even though the node has 0 of mainnet's ~900k blocks.
- **Mainnet stalled at h=900000 due to wallet bug**: reports `false`
  (correct), but if user wipes chainstate without removing the wallet
  the node falls back to h=99 → reports true → matches Core (by
  accident).

**File:** `src/rpc/server.nim:345`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1984` and
3283-3291.

**Impact:**
- Wallet code (Core convention) skips rescan when IBD is true;
  nimrod's hardcoded gate breaks this contract.
- ZMQ `rawblock` consumers (Core convention) skip historical blocks
  during IBD; nimrod fires them at h≥100 even for genesis-replay.
- Cross-impl consensus-monitor tests that gate on
  `initialblockdownload` produce false negatives.

Same pattern-shape as W148 BUG-13 (blockbrew IBD-exit `==` instead
of `>=`); fleet-wide gap: implementations diverge from Core's
chainwork-and-recency model.

---

## BUG-16 (P1) — `--reindex` does not delete blk*.dat / rev*.dat alongside chainstate

**Severity:** P1 (reindex+prune race). Bitcoin Core's `-reindex`
ALSO re-scans `blk*.dat` files (re-reads block bodies from flat
files into the chainstate); nimrod's `applyReindex`
(`nimrod.nim:2525-2548`) removes only the chainstate dir. The doc
comment at lines 2526-2532 admits the divergence ("intentionally
NARROWER than Bitcoin Core's full -reindex which also re-scans
blk*.dat").

Combined with prune mode: a node that ran `--prune=10000` and
pruned to height 799000, then runs `--reindex`, will:
1. Wipe chainstate (including `pruneHeight` metadata).
2. Re-start with `pruner.pruneHeight = -1` (loaded from missing
   key).
3. Re-sync from genesis from peers — but blocks 0..798999 cannot be
   served from any peer that ran a normal archive. The
   `NODE_NETWORK_LIMITED` advertisement still claims to serve only
   the last 288, so other prune nodes won't serve.
4. The rev*.dat files left on disk are now ORPHANED. They cannot
   be reconciled with the fresh block-index (no entries point at
   them) and the next `unlinkObsoleteUndoFiles` deletes them all
   (correct in this case, but silently).

**File:** `src/nimrod.nim:2525-2548`

**Core ref:** Core's `-reindex` flow in
`bitcoin-core/src/init.cpp` and `node/blockstorage.cpp`.

**Impact:**
- After `--reindex` on a previously-pruned node, IBD-from-peers may
  fail because no peer serves the deleted historical range.
- Operator surprise: doc warns this is narrower than Core but the
  failure mode (stuck IBD post-reindex) is not signposted.

---

## BUG-17 (P1) — `validateBlock` always defaults `minPowChecked=true` (no fallback for direct-peer paths)

**Severity:** P1 (defense-in-depth). The `validateBlockHeader` proc
correctly threads `minPowChecked` (`validation.nim:767-805`) and the
PRESYNC path in `sync.nim:929-934` plumbs it through. But the
`validateBlock` -> `validateBlockHeader` call (`validation.nim:1272`)
passes only 4 of the 5 parameters, defaulting `minPowChecked=true`:

```nim
let headerResult = validateBlockHeader(blk.header, prevIndex, params, checkPow)
```

That is correct for the post-PRESYNC blocks reaching `acceptBlock`,
but a future call-site that wires `validateBlock` directly (e.g.
RPC `verifyblock`, or a refactor of `submitblock` skipping the
header pre-check) will silently bypass the
`veInsufficientChainWork` gate.

**File:** `src/consensus/validation.nim:1272`

**Core ref:** `bitcoin-core/src/validation.cpp:4229` (the gate that
`min_pow_checked=false` triggers).

**Impact:** Defense-in-depth gap. Not exploitable today; a future
callsite refactor could re-introduce the W97-class peer-anti-DoS
hole.

---

## BUG-18 (P1) — Parallel assumevalid engine in `consensus/chain.nim` (CheckpointState) coexists with `consensus/assumevalid.nim`

**Severity:** P1 (two-pipeline guard, 16th distinct W76+ extension).
`src/consensus/chain.nim:111-163` defines `isAssumeValidBlock` and
`shouldSkipScriptVerification` — a simpler 2-condition assumevalid
check (block IS the assumevalid hash OR is an ancestor) plus a
`meetsMinimumWork` helper. This is parallel-and-dormant relative to
the production `src/consensus/assumevalid.nim:99-164`
(6-condition).

Search for production callers of `chain.nim`'s functions:
```
$ grep -rn 'shouldSkipScriptVerification\|isAssumeValidBlock\|CheckpointState' src/ | grep -v 'consensus/chain.nim'
```
returns zero hits outside the module. The entire `CheckpointState`
machinery is dead — but the 2-condition `shouldSkipScriptVerification`
encodes a STRICTER-than-Core check (just "ancestor", missing the
4 anti-fake-chain safety guards). If anyone wires it in lieu of
`assumevalid.nim`'s `shouldSkipScripts`, the script-skip becomes a
DoS primitive.

**File:** `src/consensus/chain.nim:15-180`

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383` (single
6-condition engine).

**Impact:** "Two-pipeline guard" fleet pattern — the WEAKER engine
sits primed for accidental reuse. Cross-cite W148 BUG-3 (two
pipelines).

---

## BUG-19 (P1) — `buildAssumeValidContext` passes `cs.db.getBlockHashByHeight` (active-chain) for assumevalid lookup

**Severity:** P1 (covered by G23 PARTIAL). `chainstate.nim:719-737`
fills `activeHashAtAssumeValidHeight` from `cs.db.getBlockHashByHeight(cs.params.assumeValidHeight)`.
That database accessor returns ACTIVE-CHAIN hashes only. During
IBD when the header chain has reached h=944_000 but the active
chain is at h=500_000, the lookup returns `None` → condition 2 of
`shouldSkipScripts` fires `ssrHashNotInIndex` → scripts are
NOT skipped → defeats the entire purpose of assumevalid during IBD.

The `applyBlock` path (`sync.nim:1080-1108`) and
`processReceivedBlocks` (`sync.nim:1660-1719`) correctly use
`sm.headerChain.getHashByHeight(...)` (header-chain index), so the
IBD-via-sync paths work. The `connectBlock` / `connectBlockIBD` /
reorg paths in chainstate.nim use the wrong source.

In practice, `connectBlock`'s only use of the gate is to bypass
COINBASE_MATURITY when scripts are being skipped
(`chainstate.nim:822-836`) — so the active-chain lookup causes
overly-conservative maturity enforcement during IBD reorgs. Not a
script-skip issue in the production path because the script-skip
gate is computed UPSTREAM by callers (RPC + sync.nim).

The duplication is a foot-gun: two implementations of the same
context-builder, one (sync.nim) using the right source, the other
(chainstate.nim) using the wrong source.

**File:** `src/storage/chainstate.nim:719-737`

**Core ref:** `bitcoin-core/src/validation.cpp:2350-2360`
(`assumeValidIndex.GetAncestor(...)` walks header-index pindex
pointers).

**Impact:** Coinbase-maturity over-enforcement during IBD reorgs.
Functional bug only on testnet/regtest reorgs ≥ 100 blocks deep
crossing an IBD window.

---

## BUG-20 (P1) — `submitblock` RPC uses height-only assumevalid gate (bypasses 6-condition check)

**Severity:** P1 (RPC-side bypass of the ancestor-check guard).
At `src/rpc/server.nim:3742-3743`:

```nim
let skipScripts = cs.params.assumeValidHeight > 0 and
                  height <= cs.params.assumeValidHeight
```

This is a plain HEIGHT comparison — NOT a call to the 6-condition
`shouldSkipScripts` engine. Conditions 4 (best-header ancestor),
5 (min chain work), 6 (2-week guard) are all skipped. An operator
who submits a block with `submitblock` that is on a fork below
`assumeValidHeight` will get scripts skipped — even though that
fork is NOT on the active assumevalid chain.

The IBD paths (`sync.nim:1080-1108, 1660-1719`) correctly call
`shouldSkipScripts`. Only the RPC submitblock path uses the
shortcut.

**File:** `src/rpc/server.nim:3742-3743`

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383`
(single gate, no path-dependent shortcut).

**Impact:** A side-branch block submitted via RPC below
`assumeValidHeight` will have scripts skipped. If the fork chain is
attacker-controlled, this is a script-validation bypass at the RPC
boundary. The fact that 3 of 4 acceptance paths use the strong
gate and 1 uses a weak one is a textbook two-pipeline divergence.

---

## BUG-21 (P1) — IBD-fast-path activation gated by `assumeValidHeight - 1000` (off-by-arbitrary)

**Severity:** P1 (cadence). At `src/rpc/server.nim:3756-3757`:

```nim
let useIBD = cs.params.assumeValidHeight > 0 and
             height < cs.params.assumeValidHeight - 1000
```

The IBD fast-path triggers when more than 1000 blocks below the
shipped `assumeValidHeight`. Core's IBD-vs-normal gate is rooted in
`IsInitialBlockDownload()` (chainwork + recency), not a fixed delta
below assumevalid.

- Operators who unset assumevalid via a (non-existent) CLI flag would
  get the IBD path NEVER fire on submitblock.
- After Bitcoin Core ships a newer `defaultAssumeValid` but nimrod
  has not pulled the bump, the IBD-fast-path window shrinks as the
  active chain catches up.
- The constant `1000` has no Core counterpart.

**File:** `src/rpc/server.nim:3756-3757`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1984`.

**Impact:** RPC submitblock latency variance.

---

## BUG-22 (P2) — `pruneHeight` field comment says "lowest still-retained" but field stores "highest pruned"

**Severity:** P2 (documentation drift). `pruner.nim:75-76`:
```nim
pruneHeight*: int32         ## Lowest height for which we still have body data.
                             ## -1 if nothing pruned yet.
```

Actual semantics: `pruner.nim:402-407` assigns `lastPruned` (highest
height pruned in the loop) to `pruneHeight`. The next prune starts
at `pruneHeight + 1` (line 387, 449). So `pruneHeight` is the
HIGHEST pruned height; the lowest retained height is
`pruneHeight + 1`.

The fix (`pruneHeight = lastPruned`) is correct relative to use
in `pruneToHeight`'s startH calculation; the COMMENT is wrong.
RPC `getblockchaininfo.pruneheight` returns this field
(`rpc/server.nim:354`); Core's `pruneheight` is "lowest still-retained
height" (`bitcoin-core/src/rpc/blockchain.cpp` `getblockchaininfo`).
Off-by-one in the RPC value relative to Core.

**File:** `src/storage/pruner.nim:75-76, 405-407, 463-465`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp` `getblockchaininfo`
"pruneheight" field doc: "lowest-height complete block stored".

**Impact:** Wallet rescan code or block-explorer indexer that pages
"from pruneheight to tip" reads off-by-one: nimrod's value is the
lowest height that has been DELETED, not the lowest that exists.

---

## Fleet-pattern smells

- **Two-pipeline guard, 16th distinct extension**: `consensus/chain.nim`
  defines a parallel-and-weaker assumevalid engine
  (`CheckpointState`/`shouldSkipScriptVerification`) that coexists
  with the production 6-condition engine in `consensus/assumevalid.nim`
  (BUG-18). The two-engine pattern continues to surface in nearly
  every nimrod audit.
- **Comment-as-confession (6th in nimrod, 7th-8th fleet-wide this
  quad)**:
  - `pruner.nim:179-181` confidently asserts the inverted snapshot
    semantic ("never prune blocks at or above the snapshot floor by
    our own choice"). Doc and code agree; both disagree with Core
    (BUG-5).
  - `src/network/sync.nim:1670` references "`--noassumevalid`
    operators" — the flag does not exist (BUG-13).
  - `pruner.nim:56-59` documents `200 blocks ≈ 30-40 min`, but
    the counter is per-heartbeat not per-block (BUG-7).
- **Plumb-gate-then-flip (W141 nimrod had this 2× in one wave; W149
  fleet pattern shows it once)**: `minPowChecked` is correctly
  plumbed through `validateBlockHeader` (`validation.nim:767-805`)
  and PRESYNC (`sync.nim:929-934`), then `validateBlock` defaults
  the parameter to `true` (BUG-17), defeating the gate on any
  caller that takes the `validateBlock` entrypoint.
- **Snapshot-config vs runtime drift**: `assumeUtxoFloor` reads a
  CONFIG list, not runtime snapshot state (BUG-6). Similar shape to
  W138's "ChainstateManager defined but never wired" — production
  ignores the runtime concept entirely.
- **Active-chain-only walk in storage-side helper**:
  `unlinkObsoleteUndoFiles` uses `getBlockHashByHeight` ignoring
  side-branch indexes (BUG-9). Same shape as W148 BUG-9
  (blockbrew `recalculateBestTipLocked` walks active chain only).
- **One-of-N callers diverges (RPC vs sync)**: `submitblock` uses a
  height-only assumevalid gate (BUG-20) while the two sync.nim
  call-sites use the proper 6-condition engine. Three call-sites
  total, one diverges.
- **Default-int32 zero as deferred config**: signet's
  `assumeValidHeight` defaults to zero (BUG-12) — the field exists
  but was simply forgotten in the network init proc. Same pattern
  shape as W138 BlockfileChunkSize defaulted to zero.
- **30-of-33 NOT fired**: this audit has 22 BUGs across 33 gates;
  the implementation is mostly Core-shaped with bugs clustered in
  (a) snapshot semantics (inverted floor + dead config-vs-runtime),
  (b) assumevalid signet gap, (c) RPC contract drift
  (`initialblockdownload`, `pruneblockchain` timestamp arg, side-branch
  unlink), (d) operator-knob absence (`-assumevalid`,
  `-minimumchainwork`).

---

## Summary

22 BUGs across 33 sub-gates / 9 behaviours. Severity totals:

- **P0-CDIV** (consensus-divergent, mainnet/signet operational): 2 —
  BUG-5 (inverted snapshot prune floor), BUG-15 (`initialblockdownload`
  hardcoded `<100`).
- **P0**: 2 — BUG-9 (side-branch rev*.dat unlink), BUG-12 (signet
  assumeValidHeight=0).
- **P1**: 14 — BUG-1, BUG-3, BUG-6, BUG-7, BUG-8, BUG-11, BUG-13,
  BUG-14, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21.
- **P2**: 4 — BUG-2, BUG-4, BUG-10, BUG-22.

Highest-leverage fixes (1-line / 1-config each):

1. **BUG-12** — Set `result.assumeValidHeight = 293_175` in
   `signetParams()` (`params.nim:451-453` region). One-line; closes
   10-50× signet IBD speed gap.
2. **BUG-15** — Replace `bestHeight < 100` with the proper IBD
   gate (chainwork ≥ minimumChainWork AND tip recent). One-call into
   existing helpers.
3. **BUG-5** — Flip the comparison direction in `assumeUtxoFloor`
   usage (`pruner.nim:376-383`): use the snapshot height as a
   `prune_start` lower bound (Core semantics), not as a `prune_end`
   upper bound. Also gate on actual snapshot-load state instead of
   `params.assumeutxoData` non-emptiness (BUG-6 same change).
4. **BUG-20** — Replace the height shortcut in `submitblock`
   (`server.nim:3742-3743`) with a call to `shouldSkipScripts(...)`,
   matching the two sync.nim call-sites. Closes the RPC-side
   bypass.
5. **BUG-7** — Either rename the counter to `heartbeatsSinceLastCheck`
   and pick a sensible heartbeat-cadence-aware interval, OR move
   the increment into a block-connect hook so the unit matches the
   name.
6. **BUG-9** — Use the `BlockIndex` directly-stored `undoPos`
   information from a full sweep of all `bsValidated`/`bsDataStored`
   entries in `cfBlockIndex`, not just active-chain heights — matches
   Core's file-number-based walk in `UnlinkPrunedFiles`.
