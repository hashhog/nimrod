# W148 — Headers-first sync + chain selection + reorg audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W148).
Concurrent-agent coordination: 3 OTHER audit waves running in parallel sub-agents
(IBD & storage theme — quad-wave, 4-of-4).

Scope:
1. ProcessNewBlockHeaders contract (validate header chain — PoW + MTP + version
   — BEFORE downloading full blocks; updates `m_block_index` map + extends
   `m_best_header`; headers advance independently of full validation).
2. CChain (`m_chain`) tip with random-access `[height]`, `Genesis()`, `Tip()`,
   `FindFork(other_chain)`, iterator support for ancestor traversal.
3. ActivateBestChain loop (while `m_best_header` has more chainwork than
   `m_chain.Tip()` AND `BLOCK_VALID_SCRIPTS` exists on the path → DisconnectTip
   + ConnectTip until tips converge; releases `cs_main` between iterations).
4. MAX reorg depth refusal semantics (operator override).
5. ConnectTip — apply block forward → ConnectBlock + CCoinsViewCache mutation +
   `BLOCK_VALID_SCRIPTS` flag set; on failure, mark `BLOCK_FAILED_VALID`.
6. DisconnectTip — reverse mutation using `rev*.dat` undo data; rewinds
   `CCoinsViewCache`; failure = halt + alert (FatalError).
7. CBlockIndex validity bitfield: `BLOCK_VALID_HEADER` →
   `BLOCK_VALID_TREE` → `BLOCK_VALID_TRANSACTIONS` → `BLOCK_VALID_CHAIN` →
   `BLOCK_VALID_SCRIPTS`. Used by `FindMostWorkChain` for tip selection.
8. `m_chain_tx_count` + `m_chain_work` per-block cumulative counters maintained
   at header-acceptance time.

Targets in nimrod:
- `src/network/sync.nim` — `SyncManager` (lines 49-96, header tip vs chain tip
  separation), `validateHeader` (412-461), `handleHeaders` (lines ~768-982,
  the main header-message handler), `processHeaders` (1452-1494, legacy linear
  appender), `applyBlock` (1056-), `processBlock` (1236-), `handleBlock`
  (1772-), `BlockDownloader` (1500+), `processReceivedBlocks` (1643-1771).
- `src/network/headerssync.nim` — anti-DoS PRESYNC/REDOWNLOAD pipeline (532
  LOC). Linear-only — no fork handling.
- `src/storage/chainstate.nim` — `BlockStatus` enum (22-26), `BlockIndex`
  (60-70), `connectBlock` (739-908), `connectBlockIBD` (1222+), `disconnectBlock`
  three overloads (1382, 1543, 1605), `handleReorg` (1620-1959), `MAX_REORG_DEPTH=100`
  (1618).
- `src/consensus/chain.nim` — `CheckpointState` (15-22), `setBlockFailureFlags`
  (330-371), `resetBlockFailureFlags` (373-430), `invalidateBlock` (432-492),
  `reconsiderBlock` (494-516), `preciousBlock` (518-559).
- `src/consensus/validation.nim` — `acceptBlock` (1911-, unified check-only
  pipeline, `fRequested`/`activeTipHeight` parameters defined but never passed
  by any caller — see BUG-7), `veTooFarAhead` (61) error code never raised in
  practice.
- `src/rpc/server.nim` — `handleSubmitBlock` (3691+), side-branch acceptance
  (3805-3935), `findLocatorFork` (in src/nimrod.nim:736).

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/validation.cpp:4186-4239` `AcceptBlockHeader` (per-header validation +
  `m_block_index` insert + `m_best_header` advance).
- `src/validation.cpp:4242-4270` `ProcessNewBlockHeaders` (locked wrapper).
- `src/validation.cpp:2929-2992` `DisconnectTip`.
- `src/validation.cpp:3005-3110` `ConnectTip`.
- `src/validation.cpp:3114-3171` `FindMostWorkChain` (set-based candidate
  scan, skips failed/missing-data chains).
- `src/validation.cpp:3191-3320` `ActivateBestChainStep`.
- `src/validation.cpp:3323-3488` `ActivateBestChain` (main loop, releases
  `cs_main` between iterations, `LimitValidationInterfaceQueue` callback drain).
- `src/chain.h:42-86` `BlockStatus` enum — 5 distinct `BLOCK_VALID_*` levels
  + `BLOCK_HAVE_DATA`/`BLOCK_HAVE_UNDO` separately.
- `src/chain.h:93-200` `CBlockIndex`: `nChainWork`, `nTx`, `m_chain_tx_count`,
  `nSequenceId`, `pskip` (O(log n) ancestor walk).
- `src/node/blockstorage.cpp:174-192` `CBlockIndexWorkComparator` —
  (`nChainWork`, `nSequenceId`, pointer-addr) ordering tuple.
- `src/validation.cpp:3699-3711` `SetBlockFailureFlags` / `ResetBlockFailureFlags`.
- `src/net_processing.cpp::ProcessHeadersMessage` (around lines ~3500 in
  recent Core) — main P2P entry, contains `nUnconnectingHeaders` accounting,
  Misbehaving on invalid header, and the actual `ProcessNewBlockHeaders` call.

## Status

**BUGS FOUND — 22 distinct defects.** Of these:

- **P0-CONSENSUS** — 2 (side-branch acceptance via submitblock RPC persists
  the block to disk with `status = bsValidated` after running ONLY
  `checkBlock` — no contextual validation, no BIP-30, no script verify, no
  coinbase-value gate; reorg path then promotes that side-branch to active
  chain via `connectBlock` which itself does no consensus checks (cross-cite
  W145 BUG-2). A miner who can produce a valid-PoW side-branch with greater
  work but malformed contextual content gets to overwrite the active chain.
  BUG-1 covers RPC submitblock; BUG-2 covers the parallel `handleReorg`
  connect-side missing contextual validation.).
- **P0-CDIV** — 6 (entire P2P-driven reorg path is missing — `handleReorg`
  has NO caller in `sync.nim`; HeaderChain is structurally linear so headers
  cannot fork; "rolled back to common ancestor" path in `syncLoop` decrements
  counters without disconnecting blocks from chainstate; `fTooFarAhead` DoS
  guard never fires because no caller passes `fRequested`/`activeTipHeight`;
  `BlockStatus` enum has 4 flat states vs Core's 5-level validity ladder
  + 3 orthogonal HAVE/FAILED flags; `m_chain_tx_count` per-block does not
  exist on `BlockIndex` — only on assumeutxo whitelist).
- **P0-SEC** — 1 (`handleReorg` accepts caller-supplied `newChain: seq[Block]`
  without verifying the seq's internal hash chain — if RPC submitblock or
  any future caller constructs `newChainBlocks` from disk lookups where one
  hop is corrupted, the connect loop silently spends UTXOs against a
  non-canonical chain).
- **P0** — 1 (header chain rebuilt from scratch on every startup
  `# TODO: Load header chain from database / For now, start fresh and re-sync
  headers`, sync.nim:524-528 — every restart redownloads full header chain).
- **P1** — 6 (MAX_REORG_DEPTH=100 vs Core's "no limit, operator-bounded";
  `validateHeader` does NOT enforce `prev block invalid` (Core
  `BLOCK_INVALID_PREV` / "bad-prevblk"); `connectBlock` failure path does NOT
  mark block `BLOCK_FAILED_VALID`; `disconnectBlock` failure path does NOT
  halt the daemon (Core `FatalError`); `validateHeader` allows accepting
  headers up to 2h in the future at parse time but doesn't store the
  rejection on retry — peer that times-out their clock skews loses the
  header forever; tip selection compares only on `chainwork` — no
  `sequenceId` tiebreak.).
- **P2** — 4 (`processHeaders` legacy path silently `continue`s on
  validation failure without any peer punishment; no `BLOCK_OPT_WITNESS`
  flag — re-acceptance from a non-witness peer would silently strip
  witness data; `findLocatorFork` doesn't verify `prevBlock` linkage,
  trusts the locator order; `disconnectBlock` keeps undo file entries
  in flat files even after a successful disconnect — wasted disk).
- **P3** — 2 (cosmetic: `BlockStatus = bsValidated` is set BEFORE
  `verifyScripts` actually runs in side-branch case — semantics of
  `bsValidated` differ between connect and side-store paths; comment
  at `chain.nim:286` references `validation.cpp:3699-3711` but the
  setBlockFailureFlags impl walks the FULL `cfBlockIndex` rocksdb scan
  per call — quadratic with chain length).

## Bug list

---

### BUG-1 — `submitblock` RPC stores side-branch blocks with `status = bsValidated` after running ONLY context-free `checkBlock`, then promotes them to active chain via `connectBlock` which also runs zero consensus checks

**Severity:** P0-CONSENSUS
**File:** src/rpc/server.nim:3805-3935 (side-branch persistence + reorg trigger),
src/storage/chainstate.nim:739-908 (connectBlock — no validateBlock call),
src/storage/chainstate.nim:1817-1898 (handleReorg connect-side — no acceptBlock
call).
**Core ref:** bitcoin-core/src/validation.cpp:3005-3110 `ConnectTip` calls
`ConnectBlock(block, pindexNew, view, *this)` which itself runs
`CheckBlock` + `ContextualCheckBlock` + sigops + script verify + BIP-30
+ coinbase-value gate INSIDE ConnectBlock. The full pipeline runs on every
candidate block before the UTXO view is mutated; bitcoin-core/src/validation.cpp:4308
also calls `AcceptBlockHeader` (which runs `ContextualCheckBlockHeader`)
even for side-branch blocks before storage.

**Description:** nimrod's submitblock side-branch path (rpc/server.nim:3805+)
runs only `checkBlock` (context-free PoW/merkle/tx-sanity at line 3701) and
then directly persists the side-branch block to disk with `status = bsValidated`
at line 3866-3879. There is NO `validateBlock` (BIP-34, BIP-68, coinbase value,
MTP, witness commitment, weight, sigops). There is NO BIP-30 check. There is
NO script verification.

Worse: when the side-branch later has greater work and triggers a reorg via
`handleReorg`, the connect-side loop (chainstate.nim:1817-1898) only runs
`connectBlock`-internal checks (missing-input + coinbase maturity) — NOT
`acceptBlock`. So a malicious miner who can construct a higher-work
side-branch with malformed block content gets to overwrite the active chain.

**Excerpt** (src/rpc/server.nim:3805-3880):
```nim
else:
  # prevhash does not match current tip — this is a side-branch block.
  # ... no validateBlock, no BIP-30, no script verify ...
  let prevIdxOpt = cs.db.getBlockIndex(prevHash)
  if prevIdxOpt.isNone:
    return %"rejected"
  let prevIdx = prevIdxOpt.get()
  # ... compute newTotalWork ...
  cs.db.storeBlock(blk)
  let sideIdx = BlockIndex(
    hash: blockHash, height: newHeight,
    status: bsValidated,            # <-- bypasses every contextual gate
    prevHash: blk.header.prevBlock, header: blk.header,
    totalWork: newTotalWork,
    undoPos: FlatFilePos(fileNum: -1, pos: -1),
    failureFlags: BLOCK_NO_FAILURE,
    sequenceId: 0,
    nTx: int32(blk.txs.len)
  )
  cs.db.putBlockIndexHashOnly(sideIdx)
```

And the reorg connect side (src/storage/chainstate.nim:1817-1898):
```nim
# ---- Stage all connects onto the same batch ----
var newHeight = cs.bestHeight + 1
for blk in newChain:
  # Generate undo data BEFORE mutating UTXO state.
  let undo = cs.generateUndoData(blk)        # <-- no acceptBlock first
  # ... batch.put(cfBlocks, ...), spend inputs, create outputs ...
  # Only consensus check: coinbase maturity.
```

**Impact:** Inflation attack on the active chain via a `submitblock` payload
crafted to win a reorg. Same fleet pattern as W143 BUG-2 / W145 BUG-2-3
(connectBlock variants lack contextual checks). On a private-rebroadcast
network attack (miner colludes with relay), the attacker can produce a
chain segment with 2× subsidy, oversized weight, bad MTP, or wrong BIP-34
height that wins by greater work and is silently accepted.

---

### BUG-2 — `handleReorg` connect-side loop runs ZERO contextual consensus checks (no `validateBlock`, no `acceptBlock`)

**Severity:** P0-CONSENSUS
**File:** src/storage/chainstate.nim:1817-1898
**Core ref:** bitcoin-core/src/validation.cpp:3005-3110 `ConnectTip` →
`ConnectBlock` (validation.cpp:2354+) runs the full
CheckBlock+ContextualCheckBlock+CheckInputs pipeline inside the connect-tip
loop on every iteration.

**Description:** Distinct from BUG-1: BUG-1 covers the side-branch
persistence path; BUG-2 covers `handleReorg` itself. Even if BUG-1 were
fixed by making side-branch persistence run full validation, `handleReorg`
would STILL connect the new chain without validation because the connect-side
loop only enforces `getUtxo missing` (1850) and `coinbase maturity` (1858).
No subsidy check, no MoneyRange, no duplicate inputs (CVE-2018-17144), no
sigop cost, no weight, no witness commitment, no MTP. This means **any**
caller of `handleReorg` (now: only RPC submitblock side-branch path; later:
P2P side-branch reorg if BUG-3 is fixed) inherits the missing-validation hole.

**Excerpt** (src/storage/chainstate.nim:1842-1894):
```nim
for txIdx, tx in blk.txs:
  let txId = tx.txid()
  if txIdx > 0:
    for input in tx.inputs:
      let utxoOpt = cs.getUtxo(input.prevOut)
      if utxoOpt.isNone:
        rollbackInMemory()
        return err("missing input during connect at height " & ...)
      let entry = utxoOpt.get()
      if entry.isCoinbase:
        let age = newHeight - entry.height
        if age < int32(cs.params.coinbaseMaturity):
          # ... maturity check ...
      # delete from UTXO + cache
  for voutIdx, output in tx.outputs:
    if isUnspendable(output.scriptPubKey): continue
    # ... add outputs ...
# That's the ENTIRE consensus surface for a reorg connect.
```

**Impact:** Two-pipeline guard — the side-branch persistence path AND the
reorg connect-side path BOTH must run full validation independently.
Pattern fleet-flagged in W145 BUG-2/3 (`connectBlock` and `connectBlockIBD`
each lack contextual checks).

---

### BUG-3 — P2P-driven reorg is COMPLETELY MISSING: `handleReorg` has zero callers in `sync.nim`; HeaderChain is structurally linear so headers cannot fork

**Severity:** P0-CDIV
**File:** src/network/sync.nim:34-40 (HeaderChain type), 898-962 (handleHeaders
linear-append loop), 1056-1221 (applyBlock — requires tip-extending block).
The single `handleReorg` caller is in src/rpc/server.nim:3926 (submitblock RPC).
**Core ref:** bitcoin-core/src/validation.cpp:3323-3488 `ActivateBestChain` is
the chain-selection loop called from `ProcessNewBlock` (4433), `LoadChainTip`,
and the P2P "block" message handler. It iterates `FindMostWorkChain` →
disconnect-to-fork-point → connect-forward until tips converge. Core does
this for EVERY block delivery, P2P or RPC.

**Description:** nimrod's P2P pipeline (sync.nim) never calls `handleReorg`.
The applyBlock proc (1056) hard-codes a chain-extending precondition at
line 1066:
```nim
let expectedPrev = if height == 1: sm.params.genesisBlockHash
                   else: sm.chainTip
if blk.header.prevBlock != expectedPrev:
  warn "block does not connect", height = height, ...
  return false
```
Side-branch blocks arriving from peers are silently dropped. The header
chain itself is a flat `seq[BlockHeader]` (HeaderChain at sync.nim:34-40)
with `tip`, `tipHeight`, `byHash[BlockHash, int]` — no `prev` pointers
because the structure is implicitly linear. There is no `m_block_index` map
that supports multiple competing chains.

The only "reorg" branch in `syncLoop` (1346-1373) decrements `chainTipHeight`
and `chainTip` counters when the header chain disagrees with the chain tip,
but does NOT actually `disconnectBlock` from chainstate — it just
re-assigns pointers, leaving the chainstate UTXO set frozen on the old
chain. This is BUG-4 (separate finding).

**Excerpt** (src/network/sync.nim:34-40):
```nim
HeaderChain* = object
  headers*: seq[BlockHeader]
  hashes*: seq[BlockHash]        ## Index -> hash mapping
  byHash*: Table[BlockHash, int]  ## Hash -> index mapping
  tip*: BlockHash
  tipHeight*: int32
  totalWork*: array[32, byte]  ## Cumulative work of the chain
```

**Impact:** nimrod will never follow a P2P-driven chain reorg, even for
trivial 1-block reorgs that Bitcoin Core handles routinely. A natural-fork
near the tip (latency-driven, very common) leaves nimrod stuck on the
losing branch until restart or until the operator manually intervenes via
`submitblock`. Long-lived chain split below the operator's view.
Note: handleReorg DOES work via RPC — so the function exists; it's the P2P
plumbing that's missing.

---

### BUG-4 — "Rolled back to common ancestor" path in `syncLoop` rewinds counters WITHOUT disconnecting blocks from chainstate, leaving the UTXO set frozen on the stale fork

**Severity:** P0-CDIV
**File:** src/network/sync.nim:1346-1373
**Core ref:** bitcoin-core/src/validation.cpp:2929-2992 `DisconnectTip` —
EVERY chain-tip rewind goes through `DisconnectBlock(block, pindexDelete, view)`
+ `view.Flush()` which mutates `CCoinsViewCache`.

**Description:** When the header chain has been re-synced from a peer and
disagrees with the persisted `chainTip` at the same height, syncLoop
decides "the stored chain tip may be on a stale fork" and rewinds
`sm.chainTipHeight` + `sm.chainTip` in a while loop. It also updates
`sm.chainState.bestHeight` and `sm.chainState.bestBlockHash` in-place — but
DOES NOT call `disconnectBlock` for each rewound height. The on-disk UTXO
set retains the stale-fork UTXOs, and the chainstate's `totalWork` pointer
remains pinned to the stale fork's cumulative work.

**Excerpt** (src/network/sync.nim:1348-1373):
```nim
block chainTipCheck:
  let headerHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
  if headerHashOpt.isSome and headerHashOpt.get() != sm.chainTip:
    # Chain tip mismatch - roll back to common ancestor
    while sm.chainTipHeight > 0:
      let hashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
      if hashOpt.isSome and hashOpt.get() == sm.chainTip:
        break
      ...
      sm.chainTipHeight -= 1                    # <-- pointer move only
      let prevHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
      if prevHashOpt.isSome:
        sm.chainTip = prevHashOpt.get()
      else:
        break
    info "rolled back to common ancestor", height = ...
    if sm.chainState != nil:
      sm.chainState.bestHeight = sm.chainTipHeight       # <-- pointer move only
      sm.chainState.bestBlockHash = sm.chainTip           # <-- pointer move only
```

**Impact:** UTXO set divergence. Subsequent `getUtxo` lookups return UTXOs
that belong to the discarded chain, so `verifyScripts` will accept a
double-spend (the stale-chain UTXO is still there). Same in-flight bytes
arriving as block bodies will then ConnectBlock against a corrupted UTXO
view, producing a permanent fork that never realigns to the network. Pairs
with BUG-3: the "rollback" code path attempts to recover from a reorg the
node never detected.

---

### BUG-5 — Header chain rebuilt from scratch on every startup (`# TODO: Load header chain from database`)

**Severity:** P0
**File:** src/network/sync.nim:511-528
**Core ref:** bitcoin-core/src/validation.cpp::LoadBlockIndex loads the
full block index (including all known headers) from `blocks/index/` on
startup so `m_best_header` is restored without re-downloading.

**Description:** The SyncManager constructor at sync.nim:511-528 loads
the chain-tip from `chainDb` (chain tip = persisted active chain) but
explicitly notes:
```nim
# TODO: Load header chain from database
# For now, start fresh and re-sync headers
let genesis = buildGenesisBlock(params)
let genesisHash = params.genesisBlockHash
result.headerChain = initHeaderChain(genesis.header, genesisHash)
```
After every restart, nimrod redownloads the entire header chain from
peers. At mainnet h=870_000 that's ~70 MB of headers + a full PRESYNC
round-trip = several minutes of cold-start overhead.

**Impact:** Cold-start delay; node operationally fragile on restart loops.
Combined with BUG-3 (no P2P reorg), an attacker that manages to deliver
a low-work fork after restart and before honest peers connect can deceive
the node into accepting a stale chain as the header tip. Also wastes peer
bandwidth fleet-wide on every nimrod node restart.

---

### BUG-6 — `BlockStatus` enum has 4 flat states (bsHeaderOnly/bsDataStored/bsValidated/bsInvalid) vs Core's 5-level validity ladder + orthogonal HAVE/FAILED flags

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:22-26 (BlockStatus), 30-50
(BlockFailureFlags as separate distinct uint8).
**Core ref:** bitcoin-core/src/chain.h:42-86 `enum BlockStatus`:
`BLOCK_VALID_RESERVED` → `BLOCK_VALID_TREE` → `BLOCK_VALID_TRANSACTIONS`
→ `BLOCK_VALID_CHAIN` → `BLOCK_VALID_SCRIPTS` as nested levels
(MASK=5 lower bits); plus orthogonal `BLOCK_HAVE_DATA`,
`BLOCK_HAVE_UNDO`, `BLOCK_FAILED_VALID`, `BLOCK_FAILED_CHILD`,
`BLOCK_OPT_WITNESS`, `BLOCK_STATUS_RESERVED`.

**Description:** nimrod's BlockStatus is:
```nim
BlockStatus* = enum
  bsHeaderOnly    ## Only header stored
  bsDataStored    ## Full block data stored
  bsValidated     ## Block fully validated
  bsInvalid       ## Block validation failed
```
This collapses Core's five distinct validity levels into a single
"validated/not validated" bit. Specifically `BLOCK_VALID_TRANSACTIONS`
(only "structural-tx check passed, no double-spend or script check yet")
vs `BLOCK_VALID_CHAIN` (UTXO + BIP-30 passed) vs `BLOCK_VALID_SCRIPTS`
(scripts fully verified). nimrod cannot represent "this block is on a
header-only side-branch we've structurally checked but haven't
downloaded yet" — that information is needed by `FindMostWorkChain`
to filter candidates that have full data.

The `BLOCK_HAVE_DATA` vs `BLOCK_HAVE_UNDO` separation also doesn't exist
— nimrod stores `undoPos` as part of BlockIndex; if it's a sentinel
`(-1, -1)` it means "no undo on disk" but is conflated with "headers-only"
in the validity bit.

**Excerpt** (src/storage/chainstate.nim:22-26):
```nim
BlockStatus* = enum
  bsHeaderOnly    ## Only header stored
  bsDataStored    ## Full block data stored
  bsValidated     ## Block fully validated
  bsInvalid       ## Block validation failed
```

**Impact:** Cannot distinguish header-only candidates from full-data
candidates during tip selection; cannot represent a block whose UTXO has
been validated but whose scripts haven't (assumevalid optimization in
Core relies on this). The side-branch persistence path (BUG-1) writes
`bsValidated` after only context-free `checkBlock` — semantically wrong
but the enum offers no finer-grained state to set instead.

---

### BUG-7 — `acceptBlock`'s `fRequested`/`activeTipHeight` parameters are NEVER passed by any caller — the `fTooFarAhead` DoS guard is dead code

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:1911-1948 (acceptBlock signature
declares `activeTipHeight: int32 = -1, fRequested: bool = true`); all three
callsites at src/rpc/server.nim:3747, src/network/sync.nim:1127,
src/network/sync.nim:1704 OMIT both parameters → defaults kick in →
guard is bypassed.
**Core ref:** bitcoin-core/src/validation.cpp:4325-4336 `fTooFarAhead`
guard fires when unrequested block height > `m_chain.Tip().nHeight + MIN_BLOCKS_TO_KEEP`
(288). This prevents a hostile peer from burning the validator's CPU
by sending deep-future blocks during IBD or normal operation.

**Description:** Every caller relies on the defaults (`fRequested=true`,
`activeTipHeight=-1`). The guard's wire-level effect:
```nim
if not fRequested and activeTipHeight >= 0:
  let blkHeight = prevIndex.height + 1
  if blkHeight > activeTipHeight + int32(MinBlocksToKeep):
    return voidErr(veTooFarAhead)
```
`fRequested=true` short-circuits the conjunction at the `and` → guard never
fires. Even if it did, `activeTipHeight=-1` would short-circuit. The
documentation comment (validation.nim:1943) says "fRequested == true means
the block was explicitly requested (IBD, submitblock)" but offers no path
for relay-fed unsolicited blocks to set false. The error code `veTooFarAhead`
(validation.nim:61) is defined but never raised in production.

**Excerpt** (src/network/sync.nim:1127-1131 — typical caller):
```nim
let acceptResultApply = acceptBlock(blk, prevIdxApply, dbForApply, sm.params,
                                    skipScripts = skipScripts,
                                    checkPow = false,
                                    getUtxo = utxoForApply,
                                    crypto = cryptoApply)
# No activeTipHeight, no fRequested — defaults to (true, -1) → guard off
```

**Impact:** Hostile peer can deliver MAX_FUTURE_BLOCK_TIME-bounded
"future" blocks at arbitrary heights, forcing the validator to run the
entire CheckBlock + validateBlock + BIP-30 + verifyScripts pipeline on
each one. Core skips them with `return state.Invalid(.., "too-far-ahead")`
(no body). Pre-W138 fleet pattern: defined-but-unwired DoS guards.

---

### BUG-8 — `handleReorg` accepts caller-supplied `newChain: seq[Block]` without validating its INTERNAL hash linkage

**Severity:** P0-SEC
**File:** src/storage/chainstate.nim:1620-1959
**Core ref:** bitcoin-core/src/validation.cpp:3191-3320 `ActivateBestChainStep`
walks `pindexConnect = pindex` then `pindexConnect = pindexConnect->pprev`
within `m_block_index`, so every connect-link is a verified-by-construction
parent pointer. There is no "trust the caller's list."

**Description:** `handleReorg(cs, forkPoint, newChain, disconnectedTxs)`
takes a flat `seq[Block]` parameter for the new chain. The connect-side
loop (1817-1898) iterates this seq without ever checking that
`newChain[i+1].header.prevBlock == newChain[i].hash`. The caller in
rpc/server.nim:3896-3923 constructs `newChainBlocks` by walking
`blk.header.prevBlock` backwards through `cs.db.getBlock()` lookups —
which is correct AS LONG AS the database is intact. If the database is
corrupted, or if a future caller builds `newChainBlocks` from anywhere
else, the loop silently spends UTXOs against a broken hash chain.

**Excerpt** (src/storage/chainstate.nim:1819-1822):
```nim
# ---- Stage all connects onto the same batch ----
var newHeight = cs.bestHeight + 1
for blk in newChain:
  let headerBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(headerBytes))
  # No: assert(blk.header.prevBlock == prevHashOfPriorBlockInSeq)
```

**Impact:** Caller-driven UTXO corruption. The submitblock RPC caller is
the only one today, and it walks via `cs.db.getBlock(walkHash)` so is safe
in practice — but the absence of the invariant guard means a single
caller-construction bug elsewhere would silently corrupt the chainstate.

---

### BUG-9 — MAX_REORG_DEPTH = 100 is hardcoded — Core does NOT enforce a hard-coded reorg limit

**Severity:** P1
**File:** src/storage/chainstate.nim:1609-1618 (constant), 1673-1678 (enforcement).
**Core ref:** Bitcoin Core has no `MAX_REORG_DEPTH` constant. The validation
guard is per-operator (`-assumevalid=0` to override deep history). The W148
brief mentions "288"; the actual Core source has no such limit.

**Description:** nimrod hardcodes MAX_REORG_DEPTH=100 and refuses to apply
any reorg deeper than that. The reason given in the comment (1610-1617)
is "fits comfortably in a RocksDB WriteBatch" — an implementation concern,
not a consensus rule. Refusing a longer-but-still-valid reorg with greater
PoW work is a chain-split risk: nimrod would stay on a chain that the rest
of the network has abandoned.

**Excerpt** (src/storage/chainstate.nim:1609-1678):
```nim
const
  ## Maximum reorg depth that nimrod will attempt to apply atomically.
  ## Mirrors Bitcoin Core's MAX_REORG_LENGTH (validation.cpp) — Core
  ## refuses to invalidate beyond this depth via `invalidateblock`. We
  ## use the same limit as a guard rail on `handleReorg`'s single batch:
  MAX_REORG_DEPTH* = 100
# Comment is incorrect: Core has NO such constant.

# ...
while currentHash != forkPoint and currentHeight >= 0:
  if disconnectedBlocks.len >= MAX_REORG_DEPTH:
    return err("reorg depth exceeds MAX_REORG_DEPTH=" & $MAX_REORG_DEPTH & ...)
```

**Impact:** Comment-as-confession (says "Mirrors Bitcoin Core's MAX_REORG_LENGTH"
which doesn't exist in Core). A real-network event that reorgs more than
100 blocks would isolate nimrod from the rest of the fleet permanently
until the operator manually intervenes. Combined with BUG-3 (no P2P reorg
at all), this is academic in current state, but becomes load-bearing if
BUG-3 is fixed.

---

### BUG-10 — `validateHeader` does NOT enforce `BLOCK_INVALID_PREV` ("bad-prevblk") — a header descending from a marked-invalid ancestor is accepted

**Severity:** P1
**File:** src/network/sync.nim:412-461 (validateHeader)
**Core ref:** bitcoin-core/src/validation.cpp:4220-4222 inside
`AcceptBlockHeader`:
```cpp
if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
    LogDebug(BCLog::VALIDATION, "header %s has prev block invalid: %s\n", ...);
    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
}
```

**Description:** `validateHeader` (sync.nim:412-461) checks: too-little-chainwork,
PoW, linkage to prev, MTP, future-time, difficulty retarget. It does NOT
look up the prev block in the `failureFlags` field of the BlockIndex.
A peer that has discovered we've marked block N invalid via `invalidateblock`
RPC can resend headers descending from N — they pass all our gates because
we never check the prev's failure flags. Core rejects with `bad-prevblk`
immediately at `AcceptBlockHeader`.

**Excerpt** (src/network/sync.nim:412-461 — validateHeader full body):
```nim
proc validateHeader*(header: BlockHeader, hc: HeaderChain, height: int32,
                     params: ConsensusParams,
                     minPowChecked: bool = true): tuple[valid: bool, error: string] =
  if not minPowChecked: ...
  if not validateHeaderPoW(header): ...
  if height > 0:
    if height - 1 >= int32(hc.hashes.len): ...
    let prevHash = hc.hashes[height - 1]
    if not validateHeaderChainLinkByHash(header, prevHash): ...
    if not validateHeaderMTP(header, hc, height): ...
  # ... future-time + retarget ...
  # NO: BlockIndex prev.failureFlags lookup
  (true, "")
```

**Impact:** Wasted resources processing headers descending from a
marked-invalid block. The peer is not punished for the second-and-subsequent
attempts.

---

### BUG-11 — `connectBlock` failure path does NOT mark the block `BLOCK_FAILED_VALID` — repeated retries against the same bad block are possible

**Severity:** P1
**File:** src/storage/chainstate.nim:739-908 (connectBlock returns err but
does not update BlockIndex.failureFlags); src/network/sync.nim:1190-1191
(caller warns but does not mark).
**Core ref:** bitcoin-core/src/validation.cpp:3097-3105 inside `ConnectTip`:
```cpp
if (!rv) {
    if (state.IsInvalid()) InvalidBlockFound(pindexNew, state);
    LogError("%s: ConnectBlock %s failed, %s\n", __func__, pindexNew->GetBlockHash().ToString(), state.ToString());
    return false;
}
```
`InvalidBlockFound` sets `BLOCK_FAILED_VALID` on the offending block and
marks the cached invalid tip pointer.

**Description:** nimrod's `connectBlock` returns `err("...")` on script
failure / missing input but never touches `BlockIndex.failureFlags` for the
candidate block. Subsequent reorg attempts at the same height (via
submitblock or a future P2P reorg path) re-attempt the same bad block,
wasting CPU and never converging.

**Excerpt** (src/storage/chainstate.nim:813-815):
```nim
let utxoOpt = cs.getUtxo(input.prevOut)
if utxoOpt.isNone:
  return err("missing input: " & $input.prevOut.txid)
# No: idx.failureFlags.setFlag(BLOCK_FAILED_VALID); cs.db.putBlockIndex(idx)
```

**Impact:** Cannot poison-pill known-bad blocks. Combined with BUG-8 (no
caller-side hash-chain check), a corrupted side-branch can be retried
indefinitely.

---

### BUG-12 — `disconnectBlock` failure path does NOT halt the daemon — Core treats this as `FatalError`

**Severity:** P1
**File:** src/storage/chainstate.nim:1543-1605 (`disconnectBlock` overload
that reads undo from flat files — returns `err()` on undo-missing /
corruption but does NOT raise nor terminate).
**Core ref:** bitcoin-core/src/validation.cpp:3208-3214 inside
`ActivateBestChainStep`:
```cpp
if (!DisconnectTip(state, &disconnectpool)) {
    MaybeUpdateMempoolForReorg(disconnectpool, false);
    FatalError(m_chainman.GetNotifications(), state, _("Failed to disconnect block."));
    return false;
}
```
`FatalError` triggers a coordinated shutdown — Core considers an undo
failure a "we cannot continue with consistent state" event.

**Description:** nimrod's disconnect failure path returns a string error
that propagates to handleReorg, which calls `rollbackInMemory()` and returns
`err()`. The caller (`handleSubmitBlock`) treats this as "inconclusive" and
the daemon keeps running with a chainstate that may be partially mutated
(actually the in-memory rollback restores prior pointers, but the rev*.dat
flat file undo position is non-transactional — if the undo file write
succeeded but the batch commit failed, the rev*.dat file now contains
orphan undo data referencing nothing).

**Excerpt** (src/storage/chainstate.nim:1599-1605):
```nim
# Fall back to RocksDB undo data
let undoOpt = cs.db.getUndoData(blockHash)
if undoOpt.isNone:
  return err("undo data not found for " & $blockHash)
cs.disconnectBlock(blk, height, undoOpt.get())
# No: FatalError / shutdown.
```

**Impact:** Silent persistence corruption potential. Operator unaware that
chainstate is in a degraded state.

---

### BUG-13 — Tip selection compares only on `chainwork` — no `sequenceId` tiebreak — equal-work side-branches are indistinguishable

**Severity:** P1
**File:** src/rpc/server.nim:3884 (`compareWork256(newTotalWork, cs.totalWork) <= 0`),
src/consensus/chain.nim:539 (preciousBlock uses chainwork comparison).
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:174-192
`CBlockIndexWorkComparator::operator()` — ordering tuple is
(`nChainWork`, `-nSequenceId`, pointer-addr). On equal work, the block
seen FIRST (lower `nSequenceId`) wins — provides first-seen tiebreaking,
critical for selfish-mining resistance.

**Description:** nimrod's chain-selection comparisons use only
`compareWork256(a, b)` (consensus/chain.nim:137-145) — a pure
chainwork comparison. On a natural equal-work fork (two miners racing
near-simultaneously to find a block at the same height), nimrod compares
the work, finds it equal, and chooses based on **arrival order** — but
"arrival order" is implicit in the call stack and is NOT recorded on the
BlockIndex. The `sequenceId` field exists (chainstate.nim:69) but is only
modified by `preciousBlock` RPC (chain.nim:556) — it is NEVER auto-assigned
on AcceptBlock.

**Excerpt** (src/rpc/server.nim:3881-3885):
```nim
# Block is on a fork with same or less work — accepted as side-branch
# per BIP-22 ("inconclusive": accepted but not yet known to be on best
# chain).
if compareWork256(newTotalWork, cs.totalWork) <= 0:
  return %"inconclusive"
```

**Impact:** First-seen rule violation. Two competing equal-work blocks
delivered to nimrod will produce non-deterministic tip selection across
restarts. Selfish-mining defense weakens (Core's first-seen rule penalizes
withheld blocks).

---

### BUG-14 — `m_chain_tx_count` per-block does not exist on `BlockIndex` (only `nTx`); cumulative tx count cannot be computed without a full ancestor walk

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:60-70 (BlockIndex), src/consensus/params.nim:29
(chainTxCount exists only as a per-network assumeutxo snapshot field).
**Core ref:** bitcoin-core/src/chain.h:125-130 `CBlockIndex::m_chain_tx_count` —
populated at BLOCK_VALID_TRANSACTIONS time; used by RPC `getblockchaininfo`,
`getblockheader`, IBD verification progress, and `GuessVerificationProgress`.

**Description:** nimrod's `BlockIndex` stores `nTx: int32` (per-block tx count)
but no cumulative `m_chain_tx_count`. The only place a cumulative count
exists is the assumeutxo snapshot table entries (params.nim:233, 243, ...)
where it's used to bootstrap from a UTXO snapshot. For ordinary block
acceptance, there is no per-block cumulative counter — meaning RPC
`getblockchaininfo.txCount` would have to walk all ancestors to compute it
(O(height) per call).

**Excerpt** (src/storage/chainstate.nim:60-70):
```nim
BlockIndex* = object
  hash*: BlockHash
  height*: int32
  status*: BlockStatus
  prevHash*: BlockHash
  header*: BlockHeader
  totalWork*: array[32, byte]  ## Cumulative chain work  (✓ cumulative)
  undoPos*: FlatFilePos
  failureFlags*: BlockFailureFlags
  sequenceId*: int32
  nTx*: int32                  ## Number of transactions in this block (NOT cumulative)
```

**Impact:** Cannot represent the Core-style cumulative tx counter that
RPC callers and IBD progress estimation rely on. Approximate
`txCount`/`getchaintxstats` semantics diverge from Core. Fleet pattern:
nimrod tracks `totalWork` cumulatively but not `chainTxCount`.

---

### BUG-15 — `processHeaders` legacy interface silently `continue`s on validation failure with NO peer punishment

**Severity:** P2
**File:** src/network/sync.nim:1452-1494
**Core ref:** bitcoin-core/src/net_processing.cpp::ProcessHeadersMessage —
on `AcceptBlockHeader` failure, Misbehaving the peer with score 100 +
disconnect.

**Description:** `processHeaders` (legacy) catches every validation failure
with `continue` and never reports back to the peer manager. The newer
`handleHeaders` (1452+) does Misbehaving correctly, but anything that calls
the legacy interface (currently: an external `BlockSync` type wrapper, see
sync.nim:1452 `BlockSync` parameter) loses the punishment signal.

**Excerpt** (src/network/sync.nim:1465-1473):
```nim
# Basic validation
if expectedHeight > 0:
  let prevHashOpt = sync.headerChain.getHashByHeight(expectedHeight - 1)
  if prevHashOpt.isNone or header.prevBlock != prevHashOpt.get():
    continue                       # <-- silent skip
let (valid, _) = validateHeader(header, sync.headerChain, expectedHeight, sync.params)
if not valid:
  continue                         # <-- silent skip, no Misbehaving
```

**Impact:** DoS surface — peer that spams invalid headers via the legacy
path is not banned. Same fleet pattern: dual-path framework (legacy
processHeaders + new handleHeaders) with divergent enforcement.

---

### BUG-16 — No `BLOCK_OPT_WITNESS` flag — re-acceptance from a non-witness peer would silently strip witness data

**Severity:** P2
**File:** src/storage/chainstate.nim:60-70 (BlockIndex), 22-26 (BlockStatus).
**Core ref:** bitcoin-core/src/chain.h:82 `BLOCK_OPT_WITNESS = 128` — set
when block data was received with a witness-enforcing client; used to
detect a witness-stripped relay re-encode of a known block.

**Description:** nimrod has no per-BlockIndex flag for "the block on disk
was received with witness." If a non-witness peer (NODE_WITNESS=0) re-delivers
a known block and the storage layer accepts it, the previously-witness-bearing
block on disk could be overwritten with a witness-stripped re-encode (depending
on `storeBlock` semantics). Core's `BLOCK_OPT_WITNESS` flag is the wire-level
guard against this.

**Excerpt** (src/storage/chainstate.nim:60-70 — BlockIndex has no witness flag).

**Impact:** Theoretical witness data loss on re-delivery. Low practical
likelihood (the active chain's blocks have witness data from the initial
delivery), but the absence of the flag means there's no detection mechanism
if it ever does happen.

---

### BUG-17 — `findLocatorFork` doesn't verify `prevBlock` linkage — trusts the locator order

**Severity:** P2
**File:** src/nimrod.nim:736-764
**Core ref:** bitcoin-core/src/validation.cpp:120 `FindForkInGlobalIndex`
walks the locator and returns the first hash present in `m_block_index` on
the active chain (validated by `Contains(pindex)`). The locator is
attacker-controlled; trust comes from the lookup verifying it's on our chain.

**Description:** nimrod's `findLocatorFork` does verify on-chain membership
(by re-looking-up `getHashByHeight(height) == hash`) — good. But there is
NO verification that the locator is in valid descending-height order; a
malformed locator that puts a tip-height hash AFTER a low-height hash
would still cause the loop to return the first match without rejecting the
malformed shape. This is a peer-fuzzing concern more than a consensus
bug.

**Excerpt** (src/nimrod.nim:746-755):
```nim
for h in locatorHashes:
  let bh = BlockHash(h)
  if state.syncManager != nil:
    let heightOpt = state.syncManager.headerChain.getHeight(bh)
    if heightOpt.isSome:
      let onChainOpt = state.syncManager.headerChain.getHashByHeight(heightOpt.get())
      if onChainOpt.isSome and onChainOpt.get() == bh:
        return heightOpt.get()
  # No: assert locatorHashes[i].height > locatorHashes[i+1].height
```

**Impact:** Fuzzer / static-analyzer surface. Limited DoS potential
because the lookup is bounded by the locator length (~33 hashes max).

---

### BUG-18 — `disconnectBlock` keeps undo file entries in flat files even after successful disconnect — wasted disk

**Severity:** P2
**File:** src/storage/chainstate.nim:1382-1541 (disconnectBlock writes the
delete to cfMeta:undoKey but does NOT free the rev*.dat flat-file entries
referenced via `undoPos`).
**Core ref:** bitcoin-core/src/validation.cpp:2929-2992 `DisconnectTip`
also doesn't immediately free flat-file undo entries (Core writes new
undo data sequentially and prunes by file), but the `FlushStateToDisk`
periodic cleanup eventually compacts. nimrod has no equivalent pruner.

**Description:** After a successful disconnect, the legacy RocksDB undo
entry is deleted (chainstate.nim:1494) but the rev*.dat flat-file slot
remains permanently allocated. Repeated reorgs accumulate dead undo
records. The `pruner.nim` module handles block-file pruning by height
but does NOT touch dead undo records below the prune horizon.

**Impact:** Storage bloat proportional to reorg frequency. On testnet4 with
frequent reorgs (testnet timewarp), this can grow tens of GB over months.

---

### BUG-19 — `validateHeader` rejects future-timestamped headers at parse time, but the rejection state is NOT persisted — peer that times-out their clock skews loses the header forever

**Severity:** P1
**File:** src/network/sync.nim:451-454 (validateHeader future-time check
uses `getTime().toUnix().uint32` — local clock, not adjusted-time as
Core does).
**Core ref:** bitcoin-core/src/validation.cpp:4115-4118
`ContextualCheckBlockHeader` uses `GetAdjustedTime()` (peer-time-median
adjusted) and stores the header as "soft-rejected" so retries after our
clock catches up still accept the header.

**Description:** Two issues compounded:
1. Local clock vs adjusted-time. Core uses `GetAdjustedTime()` (median of
   peer-reported times within ±70min) to compute the "now" boundary;
   nimrod uses raw local time, so a node with a fast clock will permanently
   reject otherwise-valid headers from honest peers.
2. The rejection is returned-and-forgotten. nimrod doesn't store the
   rejected-but-not-banned state; a retry at the same height that includes
   the header again will be silently ignored (sync.nim:904 `hasHeader(hash)`
   returns true only AFTER a successful add; rejected headers aren't recorded).

**Excerpt** (src/network/sync.nim:451-454):
```nim
# Check timestamp not too far in future
let now = getTime().toUnix().uint32
if header.timestamp > now + uint32(MaxFutureBlockTime):
  return (false, "timestamp too far in future")
```

**Impact:** Honest-peer disconnection on clock-skew. Operator with
fast-skew clock isolates themselves.

---

### BUG-20 — Side-branch persistence path sets `status = bsValidated` BEFORE verifyScripts has actually run (cosmetic)

**Severity:** P3
**File:** src/rpc/server.nim:3866-3879
**Core ref:** bitcoin-core/src/chain.h:42-86 — Core sets
`BLOCK_VALID_TREE` after header validation, `BLOCK_VALID_TRANSACTIONS`
after CheckBlock, `BLOCK_VALID_CHAIN` after CheckInputs without scripts,
`BLOCK_VALID_SCRIPTS` ONLY after script verification.

**Description:** Cosmetic but observable: the side-branch block, which has
only had `checkBlock` run (not validateBlock, BIP-30, verifyScripts), is
written to disk with `status = bsValidated`. If the block is later promoted
to the active chain via reorg, the `connectBlock` path doesn't re-run
verifyScripts (because the side-branch persistence already happened) — so
the script verification is silently skipped for that path. (Cross-cite
BUG-1 for the consensus impact; BUG-20 is the cosmetic enum misuse.)

**Excerpt** (src/rpc/server.nim:3866-3879):
```nim
cs.db.storeBlock(blk)
let sideIdx = BlockIndex(
  hash: blockHash, height: newHeight,
  status: bsValidated,            # <-- premature; only checkBlock has run
  ...
)
cs.db.putBlockIndexHashOnly(sideIdx)
```

**Impact:** Misleading observability via `getblockheader` RPC (the field
suggests full validation when only context-free checks ran). Combined with
BUG-1's consensus issue, this is a "comment-as-confession" candidate.

---

### BUG-21 — `setBlockFailureFlags` does an O(N) RocksDB scan of the FULL block-index column on every call — quadratic with chain length

**Severity:** P3
**File:** src/consensus/chain.nim:330-371
**Core ref:** bitcoin-core/src/validation.cpp:3699-3711 `SetBlockFailureFlags`
walks the in-memory `m_block_index` map (O(N) but cached, not disk I/O).

**Description:** nimrod stores BlockIndex entries in RocksDB column family
`cfBlockIndex` and iterates them on every `setBlockFailureFlags` call to
find descendants. At mainnet h=870_000 that's 870k disk reads per
invalidateBlock. Core's in-memory map keeps the cost constant per access.

**Excerpt** (src/consensus/chain.nim:350-364):
```nim
for (key, value) in chaindb.iterCf(cs.db.db, chaindb.cfBlockIndex):
  if key.len != 32:
    continue  # Skip height->hash mapping entries (4-byte keys)
  if value.len == 0:
    continue
  let candidate = deserializeBlockIndex(value)
  ...
  let ancestorOpt = cs.getAncestorAtHeight(candidate, invalidBlock.height)
```

**Impact:** Operational concern: invalidateblock RPC takes minutes on a
fully-synced node. Same problem in `resetBlockFailureFlags` (chain.nim:373-430).

---

### BUG-22 — `MAX_REORG_DEPTH` comment claims to "mirror Bitcoin Core's MAX_REORG_LENGTH" — Core has no such constant

**Severity:** P3
**File:** src/storage/chainstate.nim:1610-1617
**Core ref:** bitcoin-core/src/validation.cpp — `git grep MAX_REORG`
returns no constant; Core enforces reorg limits only via the per-operator
assumevalid override at deep history (e.g., `assumevalid` block hash).

**Description:** Comment-as-confession candidate. The comment says:
```
## Mirrors Bitcoin Core's MAX_REORG_LENGTH (validation.cpp) — Core
## refuses to invalidate beyond this depth via `invalidateblock`.
```
But Core's source contains no `MAX_REORG_LENGTH` constant. The
restriction is purely an implementation concern (RocksDB WriteBatch size),
not a consensus rule. Pairs with BUG-9 (the actual divergence impact).

**Excerpt** (src/storage/chainstate.nim:1610-1617):
```nim
const
  ## Maximum reorg depth that nimrod will attempt to apply atomically.
  ## Mirrors Bitcoin Core's MAX_REORG_LENGTH (validation.cpp) — Core
  ## refuses to invalidate beyond this depth via `invalidateblock`. We
  ## use the same limit as a guard rail on `handleReorg`'s single batch:
  MAX_REORG_DEPTH* = 100
```

**Impact:** Documentation-truth-divergence. Future engineers searching
Core source for `MAX_REORG_LENGTH` find nothing and may "fix" the wrong
side of the discrepancy.

---

## Fleet patterns identified

- **Dead-DoS-guard fleet pattern (5th distinct extension)** — BUG-7
  (`fTooFarAhead` param plumbed end-to-end but never passed by any of three
  callers; default values short-circuit the guard). Cross-cite W141 BUG-24
  (nimrod zmq.nim never imported), W126 banman two-channel split, W128
  inv-relay buckets. nimrod-specific: parameters declared with defaults that
  make the guard a no-op. **Fix is 3 lines**: pass `activeTipHeight = sm.chainState.bestHeight`
  and `fRequested = (peer == nil or hash in dl.pendingRequests)` at each callsite.

- **Two-pipeline guard (15th distinct extension fleet-wide)** — BUG-1+BUG-2
  pair. Side-branch persistence runs `checkBlock` only, and reorg connect-side
  runs `connectBlock` only. The "full pipeline" (`checkBlock` → `validateBlock`
  → `checkBip30` → `verifyScripts`) exists as `acceptBlock` and runs on the
  happy path, but neither side-branch persistence nor reorg connect uses it.
  Cross-cite W141 ouroboros (audit framing).

- **Comment-as-confession (5th instance this campaign)** — BUG-22 (MAX_REORG_DEPTH
  comment lies about Core having MAX_REORG_LENGTH). Compare W141 rustoshi
  zmq.rs comment-as-confession, W138 haskoin Consensus.hs:4917-4919 "In a
  full implementation, we would compute MuHash3072 here. For now, mark as
  validated", and the 4 earlier instances ledgered in MEMORY.md.

- **TODO-as-feature (1st instance documented here)** — BUG-5 (`# TODO: Load
  header chain from database / For now, start fresh and re-sync headers`
  at sync.nim:524-528). Operational cost is paid silently on every restart.

- **Defined-but-never-set field** — BUG-13 (`sequenceId` on BlockIndex
  exists, is serialized, but is only modified by `preciousBlock` RPC).
  BUG-16 (`BLOCK_OPT_WITNESS` flag absent entirely).

- **Pointer-only state rollback** — BUG-4 (syncLoop "rolled back to common
  ancestor" path decrements counters without disconnecting blocks). Echoes
  W148 in spirit: state pointers and durable state diverge.

- **Plumb-gate-then-flip (2nd instance this campaign — see also W141 BUG-24
  + BUG-26 nimrod)** — BUG-7 (acceptBlock declares `fRequested`/`activeTipHeight`
  parameters; all callers omit them so they default to the bypass values).
  Same shape as W141.

- **Linear-only-where-tree-needed** — BUG-3 (HeaderChain is a flat seq).
  Cross-cite W138 dead-module class.

## Cross-cite

- W143 BUG-2: IBD reindex calls `connectBlockIBD` without `validateBlock` —
  same root cause as BUG-1/BUG-2 (validation-bypassed persistence paths).
- W145 BUG-2/3: `connectBlock` and `connectBlockIBD` lack contextual checks —
  direct dependency of BUG-2.
- W144 audits the script-verify side; BUG-1 makes that audit's findings
  relevant in a fresh context (side-branch reorg).

## Priority next-fix wave candidates

1. **BUG-7 dead-DoS-guard fix** (3 lines) — pass `fRequested` + `activeTipHeight`
   at three callsites. Closes a defined-but-disabled DoS guard.
2. **BUG-4 pointer-only rollback** (rewrite syncLoop:1346-1373 to call
   `disconnectBlock` per height). High-impact P0-CDIV.
3. **BUG-1 + BUG-2 paired** (wire `acceptBlock` into side-branch persistence
   AND handleReorg connect-side). Closes the consensus hole.
4. **BUG-3 P2P-driven reorg** (long, structural — design `handleReorg` callsite
   in `processBlock` / `applyBlock` for side-branch-extending blocks). Most
   impactful but multi-wave.
5. **BUG-11 mark BLOCK_FAILED_VALID on connect failure** (3 lines in
   chainstate.nim:739-908; sync.nim:1191).
6. **BUG-9 + BUG-22 paired** (remove or operator-override the 100-block reorg
   limit; correct the misleading comment).
