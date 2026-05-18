# W153 — Mempool eviction + tx-removed signals + min-relay fee (nimrod)

**Wave:** W153 — `TrimToSize` / `LimitMempoolSize` (size-limit eviction),
`Expire` (336h aging), `GetMinFee` / `trackPackageRemoved`
(rolling-min-fee + decay), `removeRecursive` / `RemoveStaged` /
`removeUnchecked` / `removeConflicts` (cascade APIs),
`removeForBlock` / `removeForReorg` / `MaybeUpdateMempoolForReorg`
(block / reorg integration), `ClearPrioritisation` /
`PrioritiseTransaction` / `m_unbroadcast_txids`, the
`MemPoolRemovalReason` enum + signal fan-out
(`TransactionRemovedFromMempool`,
`MempoolTransactionsRemovedForBlock`,
`MempoolTransactionsRemovedForReorg`); ZMQ `pubhashtx` / `pubrawtx` /
`pubsequence` per-tx publish on accept/remove; REST
`/rest/mempool/{info,contents}.json`; tunables
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
`DEFAULT_MIN_RELAY_TX_FEE=100 sat/kvB`,
`DEFAULT_INCREMENTAL_RELAY_FEE=100 sat/kvB`,
`ROLLING_FEE_HALFLIFE=12h`; RPCs
`getmempoolinfo`, `getrawmempool`, `getmempoolentry`,
`getmempoolancestors`, `getmempooldescendants`, `savemempool` /
`dumpmempool` / `importmempool`, `loadmempool` (deprecated),
`prioritisetransaction`.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/kernel/mempool_options.h:19,23,40-44` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300`,
  `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336`,
  `max_size_bytes = 300 * 1'000'000`,
  `expiry = 336h`,
  `incremental_relay_feerate = DEFAULT_INCREMENTAL_RELAY_FEE`,
  `min_relay_feerate = DEFAULT_MIN_RELAY_TX_FEE`.
- `bitcoin-core/src/policy/policy.h:48,70` —
  `DEFAULT_INCREMENTAL_RELAY_FEE = 100` sat/kvB,
  `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
  (`static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE)`
  in `node/mempool_args.cpp:69`).
- `bitcoin-core/src/txmempool.h:212` —
  `ROLLING_FEE_HALFLIFE = 60*60*12` (12h); accelerated `/2` when
  `DynamicMemoryUsage() < sizelimit/2`, `/4` when `< sizelimit/4`.
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` —
  `enum class MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK,
  CONFLICT, REPLACED }`. Passed to every `removeUnchecked` site and
  forwarded into the `TransactionRemovedFromMempool` signal.
- `bitcoin-core/src/txmempool.cpp:360-395` —
  `removeForReorg(chain, check_final_and_mature)`: after re-admit, walk
  the whole mempool and drop entries that became non-final / coinbase-
  immature at the new tip; per-tx `removeRecursive(REORG)` so
  descendants follow.
- `bitcoin-core/src/txmempool.cpp:386-405` —
  `removeRecursive(tx, reason)`: CalculateDescendants → RemoveStaged.
  Every remove is **recursive** so dependents never dangle.
- `bitcoin-core/src/txmempool.cpp:405-432` —
  `removeForBlock(vtx, nBlockHeight)`: for each block tx → `removeUnchecked(BLOCK)`
  + `removeConflicts(tx)` + `ClearPrioritisation(tx)`. The conflicts
  path calls `removeRecursive(CONFLICT)` — descendants of conflicts
  go too. Emits `MempoolTransactionsRemovedForBlock` to the validation
  signals fan-out.
- `bitcoin-core/src/txmempool.cpp:383-403` — `removeConflicts(tx)`:
  walks `mapNextTx[input.prevout]` and calls `removeRecursive(CONFLICT)`
  on each. Recursive.
- `bitcoin-core/src/txmempool.cpp:778-782` — `DynamicMemoryUsage()`:
  multi-index overhead estimate +
  `memusage::DynamicUsage(mapNextTx, mapDeltas, txns_randomized)` +
  `m_txgraph->GetMainMemoryUsage()` + `cachedInnerUsage`. This is the
  value compared against `sizelimit` in `TrimToSize`, NOT raw
  serialized bytes.
- `bitcoin-core/src/txmempool.cpp:811-827` — `Expire(now)`: drops every
  entry whose `nTime < now - expiry`, then `RemoveStaged(EXPIRY)` on
  the full descendant closure.
- `bitcoin-core/src/txmempool.cpp:829-851` — `GetMinFee(sizelimit)`:
  `(blockSinceLastRollingFeeBump==false || rollingMinimumFeeRate==0)
  → return raw`; else decay by `pow(2, elapsed/halflife)` with
  pool-fullness-accelerated halflife; if floor < `incremental/2` →
  zero. Returns `max(CFeeRate(rollingMinimumFeeRate),
  incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved(rate)`:
  if `rate > rollingMinimumFeeRate` → bump and clear
  `blockSinceLastRollingFeeBump`.
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize(sizelimit,
  pvNoSpendsRemaining)`: loops while `DynamicMemoryUsage() > sizelimit`,
  picks the worst chunk via `m_txgraph->GetWorstMainChunk()`,
  `removed += incremental_relay_feerate`, `trackPackageRemoved(removed)`,
  `removeUnchecked(SIZELIMIT)` on every member of the staged set.
- `bitcoin-core/src/txmempool.cpp:630-665` —
  `PrioritiseTransaction(hash, nFeeDelta)`: store delta in `mapDeltas`,
  walk all descendants via TxGraph and bump their `m_modified_fee` so
  package selection sees the priority.
- `bitcoin-core/src/txmempool.cpp:667-678` — `ClearPrioritisation(hash)`:
  erase from `mapDeltas` (called from `removeForBlock` so the delta
  doesn't survive past confirmation).
- `bitcoin-core/src/validation.cpp:294-385` —
  `MaybeUpdateMempoolForReorg(disconnectpool, fAddToMempool)`: builds
  pred `filter_final_and_mature` from `m_chain.Tip()`, calls
  `disconnectpool.addUnchecked` to re-admit (when true), then runs
  `m_mempool->removeForReorg(m_chain, filter_final_and_mature)` so
  txs that became invalid at the new tip are dropped (and their
  descendants too). Crucially: the predicate uses the NEW tip's
  CSV / CLTV / coinbase-maturity context.
- `bitcoin-core/src/rpc/mempool.cpp:1067-1096` — `getmempoolinfo`
  result:
  - `"mempoolminfee" : ValueFromAmount(max(GetMinFee(),
     min_relay_feerate).GetFeePerK())` — BTC/kvB
  - `"minrelaytxfee" : ValueFromAmount(min_relay_feerate.GetFeePerK())`
  - `"incrementalrelayfee" : ValueFromAmount(incremental_relay_feerate.GetFeePerK())`
  - `"unbroadcastcount" : pool.GetUnbroadcastTxs().size()`
  - `"fullrbf" : true` (Core 28+; nimrod still configurable).
- `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction` — three
  positional args (`txid`, deprecated `priority_delta`, `fee_delta`);
  rejects deltas that would push `nModifiedFee` outside `MoneyRange`;
  calls `pool.PrioritiseTransaction` which fans out to TxGraph and
  triggers a re-sort.
- `bitcoin-core/src/node/mempool_persist.cpp` — `DumpMempool` /
  `LoadMempool` write/read `mempool.dat` with format version, XOR key,
  per-tx `nTime + nFeeDelta`, `mapDeltas`, and the `unbroadcast` set
  (which Core actually uses post-load to retry broadcast).
- `bitcoin-core/src/validationinterface.h` —
  `TransactionRemovedFromMempool(tx, reason, sequence)` and
  `MempoolTransactionsRemovedForBlock(removed_txs, nBlockHeight)`
  fan out to:
  (a) fee-estimator (`removeTx`/`processBlock`),
  (b) ZMQ (`pubhashtx`/`pubrawtx`/`pubsequence` REMOVED label `R`),
  (c) wallet (txid invalidation), (d) any other validation-interface
  subscriber.

## Files audited

- `src/mempool/mempool.nim` (2336 lines) — `Mempool` ref-object,
  `MempoolEntry`, `AtmpArgs`, `acceptTransactionWithArgs`,
  `acceptTransaction`, `removeTransaction`, `removeForBlock`,
  `blockDisconnected` (reorg refill), `expire`,
  `evictLowestFee`, `trackPackageRemoved`, `getMinFee`, fields
  `maxSize`, `currentSize`, `minFeeRate`,
  `rollingMinimumFeeRate`, `blockSinceLastRollingFeeBump`,
  `lastRollingFeeUpdate`, `incrementalRelayFeeRate`, `expiryHours`,
  `feeEstimator`.
- `src/mempool/persist.nim` (297 lines) — `dumpMempool`, `loadMempool`,
  obfuscation key handling, format-version (`MempoolDumpVersion` v2 XOR
  + `MempoolDumpVersionNoXor` v1), `nFeeDelta` field read-and-discard,
  empty `mapDeltas` + `unbroadcast` set written.
- `src/mempool/standard.nim` — `StdDustRelayTxFee = 3000`,
  `getDustThreshold`.
- `src/rpc/server.nim:1198-1223` — `handleGetMempoolInfo` (BUG-1).
- `src/rpc/server.nim:1283-1378` — `handleGetRawMempool`,
  `handleGetMempoolEntry`, `mempoolEntryJson`,
  `handleGetMempoolAncestors`, `handleGetMempoolDescendants`.
- `src/rpc/server.nim:1380-1420` — `handleDumpMempool`, `handleLoadMempool`.
- `src/rpc/server.nim:3787-3801, 3946-3964` — `submitblock` happy-path
  and reorg-path mempool integration (`removeForBlock`, `blockDisconnected`).
- `src/rpc/rest.nim:771-782, 784-820` — `handleRestMempoolInfo`,
  `handleRestMempoolContents` (REST mirror; duplicate of BUG-1).
- `src/rpc/zmq.nim` (579 lines) — `ZmqNotificationInterface`,
  `notifyTransaction`, `notifyRawTransaction`,
  `notifyTransactionAcceptance`, `notifyTransactionRemoval`,
  `notifyMempoolAccept`, `notifyMempoolRemove`,
  `notifyBlockConnected`, `notifyBlockDisconnected`. **All 9 mempool/tx
  notify procs are exported but NEVER called outside zmq.nim itself.**
- `src/network/sync.nim:1056-1221` — `applyBlock` (the P2P-driven
  block-application path; does NOT call `mempool.removeForBlock`).
- `src/storage/chainstate.nim:1640-1700` — `handleReorg` (returns
  `disconnectedTxs` but does not invoke any mempool hook).
- `src/nimrod.nim:2017-2025, 2360-2362` — mempool construction (with
  ALL defaults, no operator knobs) and the once-per-10s `expire()`
  heartbeat.
- `src/mining/fees.nim:186-203` — `removeTransaction` (the
  fee-estimator hook nimrod calls from every mempool removal,
  irrespective of reason — Core does the same so this is parity).

---

## Gate matrix (36 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `mempoolminfee` JSON divisor | G1: `/ 100_000.0` (sat/vbyte → BTC/kB) | **BUG-1 (P0-CDIV)** — uses `/ 100_000_000.0` instead. Reported as W141 BUG-8, **5+ weeks open, 4 audits without closure** (W141 / W150 / W151 / W152 / now W153) |
| 1 | … | G2: same divisor in REST `/rest/mempool/info.json` | **BUG-1 cross-cite** — REST handler duplicates the bug at `rest.nim:773` |
| 2 | DEFAULT_MIN_RELAY_TX_FEE | G3: default `mp.minFeeRate` matches Core's 100 sat/kvB (= 0.1 sat/vbyte) | **BUG-2 (P0-CDIV)** — `DefaultMinFeeRate = 1.0` sat/vbyte (`mempool.nim:97`) = 1000 sat/kvB = **10× Core's 100 sat/kvB**. Same shape as the W120 BUG-1 incremental-fee 10× bug that FIX-69 fixed for `DefaultIncrementalRelayFee`, but `DefaultMinFeeRate` was missed. **"Asymmetric fix" pattern.** |
| 3 | DEFAULT_INCREMENTAL_RELAY_FEE | G4: matches 100 sat/kvB | PASS (`mempool.nim:102 DefaultIncrementalRelayFeeSatKvB = 100.0`, post-FIX-69) |
| 4 | DEFAULT_MAX_MEMPOOL_SIZE_MB | G5: 300 MB default | PASS (`mempool.nim:96 DefaultMaxMempoolSize = 300_000_000`) |
| 4 | … | G6: `-maxmempool` operator knob plumbed to `newMempool` | **BUG-3 (P1)** — `nimrod.nim:2019 state.mempool = newMempool(state.chainState, params)` uses ALL defaults; no `config.maxMempool` / `config.mempoolExpiry` / `config.minRelayTxFee` / `config.incrementalRelayFee` plumbing exists |
| 4 | … | G7: `TrimToSize` size comparator uses `DynamicMemoryUsage()` not raw serialized bytes | **BUG-4 (P1)** — `mempool.nim:1329` and `:2304` test `mp.currentSize + txSize > mp.maxSize` where `currentSize` is the sum of `serialize(tx).len`. Core's `DynamicMemoryUsage` includes multi-index overhead + TxGraph + cachedInnerUsage (typically 3-5× raw size). Result: nimrod allows roughly 3-5× more txs than Core before eviction triggers |
| 5 | DEFAULT_MEMPOOL_EXPIRY_HOURS | G8: 336h (14 days) default | PASS (`mempool.nim:103 DefaultMempoolExpiryHours = 336`) |
| 5 | … | G9: `expire()` invoked from main heartbeat | PASS (`nimrod.nim:2361 state.mempool.expire()`, every 10s) |
| 5 | … | G10: descendant closure dropped with expiring root | PASS (`mempool.nim:1718-1729` collects descendants via `calculateDescendants` then `removeTransaction`) |
| 6 | ROLLING_FEE_HALFLIFE | G11: 12h base halflife | PASS (`mempool.nim:101 RollingFeeHalflife = 60 * 60 * 12`) |
| 6 | … | G12: accelerated `/2` and `/4` based on pool fullness | PASS (`mempool.nim:1569-1572`) |
| 6 | … | G13: `trackPackageRemoved` adds `incremental_relay_feerate` to removed feerate before bumping | PASS (`mempool.nim:1683 mp.trackPackageRemoved(removedRateSatKvB + mp.incrementalRelayFeeRate)`) |
| 6 | … | G14: `blockSinceLastRollingFeeBump` reset on `removeForBlock` | PASS (`mempool.nim:1470`) |
| 6 | … | G15: floor cleared to 0 when `< incremental/2` | PASS (`mempool.nim:1579-1581`) |
| 7 | `MemPoolRemovalReason` enum | G16: enum defined with EXPIRY / SIZELIMIT / REORG / BLOCK / CONFLICT / REPLACED | **BUG-5 (P1)** — there is no `MemPoolRemovalReason` enum at all in nimrod. `removeTransaction` takes no reason parameter; the per-call-site reason is implicit. Downstream (ZMQ, fee-estimator, RPC) cannot distinguish |
| 7 | … | G17: reason forwarded into a `TransactionRemovedFromMempool` signal | **BUG-5 cross-cite** — no signal exists; subscribers (ZMQ, fee-estimator) hardcode their own fan-out logic |
| 8 | `removeForBlock` cascade | G18: `removeConflicts(tx)` walks descendants via `removeRecursive(CONFLICT)` | **BUG-6 (P0-CDIV)** — `removeForBlock` (`mempool.nim:1438-1466`) removes only the direct conflict, NOT its descendants. If block tx-A conflicts with mempool tx-B, and mempool tx-C depends on tx-B, then tx-C is left **dangling** — its `spentBy` reference points at a now-deleted parent, breaking ancestor walks, RBF conflict detection, and fee-rate accounting. Core's `removeRecursive(CONFLICT)` walks the descendant closure |
| 8 | … | G19: emit `MempoolTransactionsRemovedForBlock(vtx_removed, height)` after the staged batch | **BUG-7 (P1)** — no batched signal; the only post-block fan-out is `feeEstimator.processBlock` called from `rpc/server.nim:3793-3797` (server-side, not mempool-side; fragile because only the `submitblock` path triggers it — the P2P `applyBlock` path doesn't even call `removeForBlock`, see BUG-8) |
| 8 | … | G20: `ClearPrioritisation(txid)` invoked per block tx | **BUG-8 cross-cite** — no `mapDeltas` infrastructure exists; nimrod has no `prioritisetransaction` RPC (BUG-15), so the ClearPrioritisation hook would also be a no-op today |
| 9 | P2P block-apply integration | G21: `sync.nim::applyBlock` calls `mempool.removeForBlock(blk)` after successful connect | **BUG-9 (P0-CDIV)** — `applyBlock` at `network/sync.nim:1056-1221` is the **canonical IBD + post-IBD inv-driven** block-application path. It connects the block (line 1186-1189), populates BIP-157 filter index (1196-1202), updates `chainTip` (1207), but **never touches `rpc.mempool`**. Only the `submitblock` RPC (`server.nim:3790`) and the regtest `generatetoaddress` (`mining.nim:106, 318`) call `removeForBlock`. Net effect: in normal P2P operation, transactions confirmed in incoming blocks **stay in the mempool forever** (until they expire at 14d). |
| 9 | … | G22: reorg path emits `MempoolTransactionsRemovedForReorg` | **BUG-9 cross-cite** — `storage/chainstate.nim::handleReorg` returns `disconnectedTxs` to caller and `rpc/server.nim:3946-3964` calls `mp.blockDisconnected(disconnectedTxs, crypto)` + `mp.removeForBlock(connected)`. This is wired ONLY in the `submitblock` reorg branch. P2P-driven reorgs (the normal case) execute via `network/sync.nim` / `storage/chainstate.nim` and miss this fan-out entirely |
| 10 | `removeForReorg` post-refill filter | G23: after disconnect-pool refill, walk mempool and drop txs that became non-final / coinbase-immature at the new tip | **BUG-10 (P0-CDIV)** — `mempool.nim::blockDisconnected` (1485-1501) re-feeds each disconnected non-coinbase tx through `acceptTransaction`. Once admitted, it stays. Core's `removeForReorg(chain, filter_final_and_mature)` runs AFTER refill and removes any tx — including pre-existing mempool entries unrelated to the reorg — that fail `CheckFinalTx(tip+1)` / `CheckSequenceLocksAtTip` / coinbase-maturity at the new tip. nimrod has no equivalent filter |
| 11 | ZMQ tx/block fan-out | G24: `pubhashtx` published on every mempool accept | **BUG-11 (P0-DEAD)** — `notifyTransaction`, `notifyRawTransaction`, `notifyMempoolAccept`, `notifyMempoolRemove`, `notifyTransactionAcceptance`, `notifyTransactionRemoval`, `notifyBlockConnected`, `notifyBlockDisconnected` (all exported) have **ZERO callers** outside `zmq.nim`. The ZMQ subsystem is fully defined (constructor, initialize, shutdown, notifier types, all 9 publish helpers) but **never wired into the mempool/chain accept/remove path**. `RpcServer.zmq` field at `server.nim:51` exists but is never initialized. `getzmqnotifications` RPC at `server.nim:3338` always returns `[]` |
| 11 | … | G25: `pubsequence` REMOVED label `R` on eviction | **BUG-11 cross-cite** — `notifyTransactionRemoval` formats the REMOVED sequence packet correctly (`zmq.nim:507-524`), but is never called. Subscribers (electrs / fulcrum / mempool.space / nbxplorer) never see removal events |
| 11 | … | G26: `pubrawblock` / `pubhashblock` on connect | **BUG-11 cross-cite** — `notifyBlock` / `notifyRawBlock` defined; not called by `submitblock` (`server.nim:3787-3803`) or `applyBlock` (`sync.nim`) |
| 12 | `bypassLimits` plumb-then-flip | G27: reorg refill (`blockDisconnected`) sets `bypassLimits=true` so old txs not rejected for new min-fee floor | **BUG-12 (P1)** — `mempool.nim:1499` calls `mp.acceptTransaction(tx, crypto)` (no AtmpArgs override) → defaults apply (`bypassLimits=false`). The field exists, is documented (`mempool.nim:40-42 "used for reorg replay; skip min-fee + TRUC limits"`), is honored downstream (`mempool.nim:1150, 1168, 1340`), but no production caller ever sets it to `true`. **Carry-forward of W150 BUG-7 "plumb-gate-then-don't-flip"** — 7th distinct nimrod instance per W152 tracking |
| 13 | `prioritisetransaction` RPC | G28: RPC dispatch table contains `prioritisetransaction` | **BUG-13 (P1)** — there is no `prioritisetransaction` case in `server.nim` dispatch (`rpc/server.nim:8278+`). `mempool.nim:1130-1131` admits: `"// nimrod has no PrioritiseTransaction, so modified == base"` (comment-as-confession, 8th nimrod instance). Operators cannot bump per-tx priority for block-template selection or to ensure a stuck tx confirms |
| 13 | … | G29: `mapDeltas` field on Mempool | NOT IMPLEMENTED (cross-cite BUG-13) |
| 13 | … | G30: `nFeeDelta` persisted in mempool.dat | **BUG-13 cross-cite** — `persist.nim:107` writes `0i64` and `:224` reads-and-discards. Dump-and-restore strips any prioritisation deltas |
| 14 | Unbroadcast set | G31: `m_unbroadcast_txids` tracked by mempool | **BUG-14 (P1)** — no such set exists. `server.nim:1215 "unbroadcastcount": 0` is hardcoded; `server.nim:1280 obj["unbroadcast"] = %false` is hardcoded per entry. `persist.nim:111` writes `0` count and `:251-253` reads-and-discards. Operators cannot tell which mempool entries haven't yet been broadcast; rebroadcast logic that Core uses (`mempool.cpp:692-720`) is fully absent |
| 15 | `getmempoolinfo` shape | G32: emits `permitbaremultisig` / `maxdatacarriersize` / `limitclustercount` / `limitclustersize` / `limitancestorcount` / `limitancestorsize` / `limitdescendantcount` / `limitdescendantsize` | **BUG-15 (P1)** — none of the 8 newer Core fields are emitted (`server.nim:1205-1223`). Cross-impl divergence; tooling that branches on those fields (mempool monitors, fee bumpers) gets stale answers |
| 15 | … | G33: `mempoolminfee` is `max(GetMinFee(), min_relay_feerate)` | **BUG-16 (P1)** — nimrod returns raw `mp.minFeeRate` (line 1200, after the divisor bug). Core: `max(GetMinFee(), min_relay_feerate)`. Should reflect the rolling floor too |
| 16 | RPC `incrementalrelayfee` accuracy | G34: returns `incremental_relay_feerate` from mempool options | **BUG-17 (P1)** — hardcoded literal `0.00001` (BTC/kB) at `server.nim:1214` instead of reading `rpc.mempool.incrementalRelayFeeRate`. The value happens to match `0.00001 BTC/kB = 10 sat/kvB` which is **10× too small** vs Core's 100 sat/kvB; or interpreted as `0.00001 BTC/kvB = 0.01 sat/vB = 10 sat/kvB`, still 10× too small. Either way: wrong, hardcoded, divergent from actual mempool config |
| 17 | `removeUnchecked` reason fan-out | G35: subscribers receive different reason codes for size-limit vs expiry vs replaced | **BUG-18 (P1)** — `removeTransaction` (`mempool.nim:1385-1435`) has no reason parameter; fee-estimator hook on line 1414-1415 fires for ALL removals indiscriminately. Core deliberately threads the reason so e.g. SIZELIMIT removals don't pollute the "tx took too long to confirm" estimator signal even though current Core implementation actually does `removeTx` unconditionally (parity-OK for fee-estimator), but the **ZMQ sequence labels** `A`/`R` need the reason to populate the 1-byte label correctly |

---

## BUG-1 (P0-CDIV / W141 carry-forward, 4 audits without closure) — `mempoolminfee` divisor 1000× too large

**Severity:** P0-CDIV. **5+ weeks open, 4 prior audits acknowledged
without closure (W141 / W150 / W151 / W152 / now W153).**

Bitcoin Core's `getmempoolinfo` returns
`mempoolminfee` in **BTC/kvB**. `nimrod`'s `handleGetMempoolInfo` at
`src/rpc/server.nim:1198-1212` converts `mp.minFeeRate` (which is in
**sat/vbyte**) using `/ 100_000_000.0` — i.e. it treats the value as
satoshis and converts to BTC, ignoring the per-vbyte-vs-per-kvbyte
factor of 1000.

```nim
proc handleGetMempoolInfo*(rpc: RpcServer): JsonNode =
  let minFee = rpc.mempool.minFeeRate / 100000000.0  # WRONG: should be / 100000.0
  ...
  %*{
    ...
    "mempoolminfee": minFee,        # 1000× too small
    "minrelaytxfee": minFee,        # 1000× too small
    "incrementalrelayfee": 0.00001, # hardcoded; see BUG-17
    ...
  }
```

Correct conversion: `sat/vbyte → BTC/kvB` is `sat_per_vbyte / 100_000`
(because `sat_per_vbyte × 1_000_vbytes_per_kvbyte / 100_000_000_sats_per_BTC
= sat_per_vbyte / 100_000`). With the default `minFeeRate = 1.0` sat/vbyte,
nimrod currently emits `mempoolminfee = 0.00000001` BTC/kvB instead of
Core's `0.00001` BTC/kvB — **1000× too small.** (After fixing BUG-2 to
the correct default of 0.1 sat/vbyte = 100 sat/kvB, the correct emit
becomes `0.000001` BTC/kvB; the divisor bug remains independent.)

The same bug is **duplicated in REST** at
`src/rpc/rest.nim:771-782 handleRestMempoolInfo` with the same
`/ 100_000_000.0` divisor.

**File:** `src/rpc/server.nim:1200` (RPC) and `src/rpc/rest.nim:773`
(REST mirror).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo` —
`ret.pushKV("mempoolminfee", ValueFromAmount(std::max(pool.GetMinFee(),
pool.m_opts.min_relay_feerate).GetFeePerK()))` where `GetFeePerK`
returns sat/kvB and `ValueFromAmount` divides by `COIN = 100_000_000`
to produce BTC/kvB.

**Impact:** any Core-compatible tool that consumes `getmempoolinfo`
to compute a min-fee floor sees a value 1000× too small. Wallets,
fee bumpers, mempool monitors, mining pool integrations all
underestimate the floor by 1000×. **Trivial fix** (single-character
edit per call site: `/ 100000000.0` → `/ 100000.0`), open across 4
prior audits without closure.

---

## BUG-2 (P0-CDIV) — `DefaultMinFeeRate = 1.0` sat/vB is 10× Core's `DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB`

**Severity:** P0-CDIV. ("Asymmetric fix" pattern — FIX-69 fixed
the incremental relay fee from 1.0 → 0.1 sat/vB but missed
`DefaultMinFeeRate` which has the identical 10× shape.)

Bitcoin Core's `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
(`policy/policy.h:70`) = **0.1 sat/vbyte**. nimrod's
`DefaultMinFeeRate = 1.0` sat/vbyte (`mempool.nim:97`) = 1000 sat/kvB.

This is the **default min-relay** floor: a tx whose fee rate is below
this is rejected with `"mempool min fee not met"` (`mempool.nim:1153-1156`).
With nimrod's default, any tx paying 0.1 sat/vbyte to 0.99 sat/vbyte
— which Core accepts — is rejected by nimrod.

Cross-cite W120 BUG-1: `DefaultIncrementalRelayFee` was originally
also `1.0` sat/vB and was fixed to `0.1` sat/vB via FIX-69
(`mempool.nim:128-132`). The fix comment at line 132 says "FIX-69:
was 1.0 sat/vB (10x Core). See W120 BUG-1." — but the **identical
10× bug in `DefaultMinFeeRate`** at line 97 was missed by the same
fix.

```nim
DefaultMaxMempoolSize* = 300_000_000  ## 300 MB
DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum  # <-- 10× Core
MaxStandardTxWeight* = 400_000        ## 400K weight units max per tx
```

**File:** `src/mempool/mempool.nim:97`.

**Core ref:** `bitcoin-core/src/policy/policy.h:70`
`DEFAULT_MIN_RELAY_TX_FEE{100}` sat/kvB =
`bitcoin-core/src/node/mempool_args.cpp:69`
`static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE)`
— Core asserts these two defaults are equal; in nimrod they
differ by 10× after the partial FIX-69.

**Impact:** any transaction paying between Core's floor (0.1 sat/vB)
and nimrod's floor (1.0 sat/vB) is rejected by nimrod but accepted
by every other Bitcoin Core-compatible node. During fee market
quiet periods, nimrod refuses to relay traffic the rest of the
network is happily relaying. Cross-impl divergence; degraded relay
participation; CPFP fee bumps for stuck txs at < 1 sat/vB silently
fail.

---

## BUG-3 (P1) — Mempool operator knobs not plumbed from config

**Severity:** P1 ("wiring-look-but-no-wire" fleet pattern).

Bitcoin Core exposes `-maxmempool=<MB>`, `-mempoolexpiry=<hours>`,
`-minrelaytxfee=<sat/kvB>`, `-incrementalrelayfee=<sat/kvB>`,
`-mempoolfullrbf=<bool>` as documented operator knobs. `newMempool`
in `mempool.nim:192-225` takes all these as named parameters with
sensible defaults — but `nimrod.nim:2019` constructs:

```nim
state.mempool = newMempool(state.chainState, params)
```

— all positional defaults, no operator overrides. A grep for
`config.maxMempool`, `config.mempoolExpiry`, `config.minRelay`,
`config.incrementalRelay` returns zero hits across `src/`. Operators
who tune Core's mempool via `bitcoin.conf` get those values silently
ignored when porting to nimrod.

**File:** `src/nimrod.nim:2019`, the `NimrodConfig` struct
(no mempool fields), and the absent `cmd/parse_config` plumbing.

**Core ref:** `bitcoin-core/src/init.cpp` — every mempool default
above is registered as an `ArgsManager` flag in `SetupServerArgs`.

**Impact:** operator parity gap. A node operator running
`-maxmempool=500` on Core gets a 500 MB mempool; on nimrod the
config field is silently ignored and the mempool runs with the
hardcoded 300 MB default. Same for the other knobs.

---

## BUG-4 (P1) — `TrimToSize` gate uses raw serialized bytes, not `DynamicMemoryUsage`

**Severity:** P1. Bitcoin Core's `TrimToSize(sizelimit)` and
`GetMinFee(sizelimit)` compare against `DynamicMemoryUsage()`
(`txmempool.cpp:778-782`), which includes the multi-index overhead
(estimated `9 * sizeof(void*)` per entry), `mapNextTx`, `mapDeltas`,
`txns_randomized`, the cluster-mempool TxGraph, and `cachedInnerUsage`.
For a typical entry this is 3-5× the raw serialized size.

nimrod's `mp.currentSize` (`mempool.nim:67-68`) is the running sum of
`serialize(tx).len` per entry (`mempool.nim:1362, 1405`). The size
comparator at `mempool.nim:1329` and `:2304`:

```nim
while mp.currentSize + txSize > mp.maxSize:
  mp.evictLowestFee()
```

A 300 MB nimrod mempool therefore admits roughly 1 GB worth of Core-
DynamicMemoryUsage txs before evicting. The rolling-fee decay
multiplier at `mempool.nim:1569-1572` also reads `currentSize` vs
`maxSize`, so the `÷2` / `÷4` halflife acceleration thresholds fire
later than Core's.

**File:** `src/mempool/mempool.nim:67, 1329, 1362, 1405, 1569-1572,
2304`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:778-782, 829-851,
861-911`.

**Impact:** real memory ceiling on a nimrod node is 3-5× the
configured `-maxmempool`. Long-running nodes can run the host OOM
killer well before `evictLowestFee` triggers. The rolling-fee floor
decays slower than Core because the half-full / quarter-full
thresholds are gated on the under-counted size.

---

## BUG-5 (P1) — `MemPoolRemovalReason` enum absent; removals are reason-free

**Severity:** P1.

Bitcoin Core threads `MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG,
BLOCK, CONFLICT, REPLACED }` through every removal site, forwards it
into the `TransactionRemovedFromMempool` signal, and lets subscribers
branch on it (e.g., the wallet treats `REPLACED` differently from
`BLOCK`).

nimrod's `removeTransaction` (`mempool.nim:1385-1435`) takes no reason
parameter. Call sites:
- `mempool.nim:1330` (TrimToSize-equivalent) → no reason
- `mempool.nim:1411` (RBF replacement) → no reason
- `mempool.nim:1465` (removeForBlock-confirm + removeForBlock-conflict) → no reason
- `mempool.nim:1729` (expire) → no reason
- `rpc/server.nim:2983` (sendrawtransaction maxfeerate exceeded) → no reason
- `rpc/server.nim:1435` (mempool persist tests) → no reason

Every caller is silently a different reason; the call sites encode the
reason via control flow only. Downstream subscribers (ZMQ — BUG-11
notes it's dead but the format includes a 1-byte sequence label that
should differ by reason; fee-estimator; future wallet wiring) cannot
distinguish.

**File:** `src/mempool/mempool.nim:1385` (signature has no `reason`
param); all 6 call sites.

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20`.

**Impact:** subscriber-side parity gap; ZMQ `pubsequence` removal
label is hardcoded to `R` even though Core distinguishes by reason
in some downstream uses; fee-estimator cannot future-proof for the
day Core adds reason branching back into its `removeTx` hook.

---

## BUG-6 (P0-CDIV) — `removeForBlock` does not cascade conflict descendants

**Severity:** P0-CDIV.

Bitcoin Core's `removeForBlock` → `removeConflicts(tx)` →
`removeRecursive(it->second, MemPoolRemovalReason::CONFLICT)` — the
**recursive** form walks the descendant closure of every conflict so
that a tx-C dependent on a now-conflicted tx-B is removed too. This is
required because tx-C's input outpoint references a UTXO that no
longer exists (it was destroyed by tx-B which was destroyed by the
block tx).

nimrod's `removeForBlock` (`mempool.nim:1438-1466`):

```nim
for tx in blk.txs:
  let txid = tx.txid()
  if txid in mp.entries:
    toRemove.add(txid)
  for input in tx.inputs:
    if input.prevOut in mp.spentBy:
      let conflictTxid = mp.spentBy[input.prevOut]
      if conflictTxid notin toRemove:
        toRemove.add(conflictTxid)   # <-- only the direct conflict
                                     #     descendants of conflict are NOT removed
for txid in toRemove:
  mp.removeTransaction(txid)         # <-- removeTransaction does NOT cascade descendants either
```

`removeTransaction` (`mempool.nim:1385-1435`) only cascades to
**ephemeral-dust parents** (line 1417-1435), not to **conflict
descendants**. Cross-check: there is no `calculateDescendants(txid)`
call in either `removeForBlock` or `removeTransaction`.

**Failure mode:** block tx-A spends outpoint X. mempool tx-B also
spends X (so tx-B is a conflict). mempool tx-C spends an output of
tx-B. After `removeForBlock`:
- tx-A is confirmed
- tx-B is removed (direct conflict)
- **tx-C remains in the mempool** with `spentBy[tx-B's output] = tx-C`,
  but tx-B's output no longer exists in any view. The mempool's
  ancestor walks for tx-C return a stale answer; RBF conflict
  detection against tx-C fails ("can't find ancestor"); block-template
  selection picks tx-C and the resulting block fails consensus
  ("inputs-missingorspent" at next `generateblock`/mining)

**File:** `src/mempool/mempool.nim:1438-1466` (no
`calculateDescendants` call); `src/mempool/mempool.nim:1385-1435`
(`removeTransaction` cascades only ephemeral-dust parents).

**Core ref:**
`bitcoin-core/src/txmempool.cpp:383-403::removeConflicts`,
`bitcoin-core/src/txmempool.cpp:386-405::removeRecursive`.

**Impact:** dangling descendants in mempool after every block
containing a conflict; ancestor-walk corruption; mining picks
descendants whose inputs are gone, producing invalid blocks; RBF
conflict detection (`findConflicts`) returns false-negative on
cascading reorganisations. **Production reliability bug** triggered
whenever a block contains an RBF-replaced tx where the replaced tx
has CPFP children.

---

## BUG-7 (P1) — No `MempoolTransactionsRemovedForBlock` batched signal

**Severity:** P1.

Core emits `MempoolTransactionsRemovedForBlock(vtx_removed, nBlockHeight)`
at the end of `removeForBlock` (`txmempool.cpp:425-428`). Subscribers:
- fee-estimator `MempoolTransactionsRemovedForBlock` →
  `processBlock(txs_removed_for_block, nBlockHeight)` — the canonical
  signal that drives the bucket-grid confirmation matrix
- wallet (invalidate tx-spending UTXOs)
- ZMQ batched publish

nimrod's `removeForBlock` (`mempool.nim:1438-1470`) emits no signal.
The only per-block fee-estimator update happens at `rpc/server.nim:3793-3797`
(submitblock happy-path) where the caller loops over `blk.txs` and
calls `feeEstimator.processBlock(height, confirmedTxids)`. This means:
1. Only the submitblock RPC path updates the fee estimator (BUG-9
   covers the P2P-applyBlock-doesn't-touch-mempool issue),
2. The list passed includes ALL block txs, not just the ones that
   were in mempool — `processBlock` then has to do its own per-txid
   lookup,
3. No reorg-specific signal exists.

**File:** `src/mempool/mempool.nim:1438-1470` (no signal emit).

**Core ref:**
`bitcoin-core/src/validationinterface.h::MempoolTransactionsRemovedForBlock`,
`bitcoin-core/src/policy/fees/block_policy_estimator.cpp::MempoolTransactionsRemovedForBlock`.

**Impact:** fee-estimator parity gap when the block-application path
isn't `submitblock`; ZMQ batching impossible; future wallet wiring
would need a hand-rolled fan-out.

---

## BUG-8 (P1) — No `prioritisetransaction` infrastructure (`mapDeltas`, `ClearPrioritisation`)

**Severity:** P1 (cross-cite BUG-13 for the user-facing RPC piece).

Core's `mapDeltas: std::map<Txid, CAmount>` lets operators bump or
penalize per-tx priority via `prioritisetransaction` RPC.
`PrioritiseTransaction` updates the delta and propagates to all
descendants via TxGraph so package selection sees the modified fee.
`ClearPrioritisation(hash)` runs from `removeForBlock` (per
`txmempool.cpp:420`) so the delta doesn't survive past confirmation
and re-confirm in a reorg.

nimrod has none of this:
- no `mapDeltas` field on `Mempool` (`mempool.nim:63-93`)
- no `MempoolEntry.feeDelta` field (`mempool.nim:19-31`)
- comment-as-confession at `mempool.nim:1130-1131`:
  `"// m_base_fees plus PrioritiseTransaction deltas (Core
  validation.cpp:930). // nimrod has no PrioritiseTransaction, so
  modified == base"` (8th nimrod instance of comment-as-confession)
- `persist.nim:107` writes `0i64` for nFeeDelta;
  `persist.nim:224` reads-and-discards
- `persist.nim:109, 285` writes `compactsize(0)` for mapDeltas;
  `persist.nim:245-248` reads-and-discards

`removeForBlock` correctly does NOT call `ClearPrioritisation` because
the operation is a no-op on nimrod.

**File:** `src/mempool/mempool.nim:19-31, 63-93, 1130-1131`;
`src/mempool/persist.nim:105-107, 224, 245-248`.

**Core ref:**
`bitcoin-core/src/txmempool.cpp:630-665::PrioritiseTransaction`,
`bitcoin-core/src/txmempool.cpp:667-678::ClearPrioritisation`.

**Impact:** operators cannot bump a stuck tx; cannot penalize a
spam-like high-priority tx without RBF; cross-impl divergence with
every other hashhog impl.

---

## BUG-9 (P0-CDIV) — P2P block-apply path (`sync.nim::applyBlock`) does NOT call `mempool.removeForBlock`

**Severity:** P0-CDIV. **Single biggest behavioural divergence in this
audit.**

`network/sync.nim::applyBlock` (lines 1056-1221) is the canonical
block-application path for **both** IBD (`drainBlockBuffer` loop at
1223-1234) **and** post-IBD inv-driven block arrivals (`processBlock`
at 1236-1293). The function:
1. Validates the block (`checkBlock` + `acceptBlock` consensus pipeline)
2. Connects via `chainState.connectBlock` / `connectBlockIBD`
3. Populates BIP-157 filter index
4. Updates `chainTip`, `chainTipHeight`
5. **Never touches `rpc.mempool`**.

The only call sites that DO touch the mempool on a connected block:
- `rpc/server.nim:3790 mp.removeForBlock(blk)` — submitblock RPC happy path
- `rpc/server.nim:3952 mp.removeForBlock(connected)` — submitblock RPC reorg path
- `rpc/mining.nim:106, 318 mempool.removeForBlock(blk)` — regtest
  `generateblock` / `generatetoaddress`

So in **normal P2P-driven operation** (the actual production path on
mainnet/testnet4 nodes), confirmed transactions stay in the mempool
**forever** — until `expire()` evicts them at the 14-day hard limit
(`mempool.nim:1704-1729`). Symptoms:
- `getrawmempool` keeps growing as P2P blocks confirm transactions
  that were already in the mempool
- `getmempoolinfo.size` and `.bytes` diverge upward from reality
- `TrimToSize` evicts on size-limit grounds, but the floor is bumped
  by `trackPackageRemoved` of LEGITIMATE high-fee evictions — not
  by removing the just-confirmed txs that should never have counted
- rolling-min-fee decay never gets `blockSinceLastRollingFeeBump =
  true` (it's set only at `mempool.nim:1470` in `removeForBlock`)
  → the floor stays at the most-recently-evicted feerate forever
  (effectively bricking the mempool against future low-fee txs)
- fee estimator misses every IBD/P2P block (`processBlock` only fires
  from `rpc/server.nim:3793`/`:3954`)

**File:** `src/network/sync.nim:1056-1221` — the gap (no
`mempool.removeForBlock` call); cross-cite `src/storage/chainstate.nim`
which exposes `bestBlockHash`/`bestHeight` mutation but no
mempool-side notification primitive.

**Core ref:**
`bitcoin-core/src/validation.cpp:3247-3270::ConnectTip` →
`m_mempool->removeForBlock(blockConnecting.vtx, height)` is called
unconditionally in the connect path. Core's chainstate is the one
holding the mempool reference, so no path can skip it.

**Impact:** mainnet/testnet4 nimrod nodes have **permanently broken
mempool eviction** after IBD, plus broken rolling-fee decay, plus
broken fee estimator post-IBD. Practical effect: `getrawmempool` is
unreliable for monitoring, fee estimation diverges from Core, and
the rolling-fee floor never drops once bumped. **Production-blocking**
for any operator depending on mempool/fee-estimator RPCs.

---

## BUG-10 (P0-CDIV) — No `removeForReorg` post-refill filter

**Severity:** P0-CDIV.

Core's `MaybeUpdateMempoolForReorg(disconnectpool, fAddToMempool)`:
1. Re-admits disconnected non-coinbase txs (`disconnectpool.addUnchecked`),
2. Then runs `m_mempool->removeForReorg(m_chain, filter_final_and_mature)`
   over the entire mempool to drop **any** entry (re-admitted or
   pre-existing) that fails `CheckFinalTxAtTip` / `CheckSequenceLocksAtTip`
   / coinbase-maturity at the NEW tip,
3. Per-removal `removeRecursive(REORG)` so descendants follow.

The predicate uses CSV/CLTV/MTP context at the new tip — these
constraints CHANGE on reorg (different MTP, different tip height,
different ancestor for sequence-lock evaluation). A tx that was
final at the old tip can be non-final at the new tip, and vice versa.
Pre-existing mempool txs (not disconnected) can also become
non-final after a reorg shortens the active chain.

nimrod's `blockDisconnected` (`mempool.nim:1485-1501`) re-feeds each
disconnected non-coinbase tx through `acceptTransaction`, which DOES
run the per-tx validity checks at the new tip — but only for the
disconnected txs. Pre-existing mempool entries are not re-validated:

```nim
proc blockDisconnected*(mp: Mempool, txs: seq[Transaction],
                        crypto: CryptoEngine): int =
  for tx in txs:
    let txid = tx.txid()
    if txid in mp.entries:
      continue                              # <-- already in mempool
    let res = mp.acceptTransaction(tx, crypto)   # <-- only disconnected
    if res.isOk:
      inc result
```

There is no companion `removeForReorg(chainstate, predicate)` walk.

**File:** `src/mempool/mempool.nim:1485-1501` (only re-admit, no
post-refill filter); no equivalent of Core's `removeForReorg`
exists in `src/mempool/`.

**Core ref:**
`bitcoin-core/src/txmempool.cpp:360-395::removeForReorg`,
`bitcoin-core/src/validation.cpp:294-385::MaybeUpdateMempoolForReorg`.

**Impact:** after a reorg, the mempool can contain non-final txs
(invalid wrt new MTP/tip-height for CLTV/CSV), or txs that spend
coinbase outputs whose maturity now doesn't reach 100. Block-template
selection picks one of these, mining produces an invalid block,
peers ban us. **Reorg correctness bug.**

---

## BUG-11 (P0-DEAD) — Entire ZMQ subsystem is dead code

**Severity:** P0-DEAD.

`src/rpc/zmq.nim` (579 lines) defines the full `ZmqNotificationInterface`
with:
- `newZmqNotificationInterface`, `initialize`, `shutdown`,
  `getActiveNotifiers`
- Block notifiers: `notifyBlock`, `notifyRawBlock`,
  `notifyBlockConnect`, `notifyBlockDisconnect`
- Tx notifiers: `notifyTransaction`, `notifyRawTransaction`,
  `notifyTransactionAcceptance`, `notifyTransactionRemoval`
- Combined helpers: `notifyTip`, `notifyBlockConnected`,
  `notifyBlockDisconnected`, `notifyMempoolAccept`,
  `notifyMempoolRemove`

`RpcServer` declares the field `zmq*: ZmqNotificationInterface` at
`src/rpc/server.nim:51`. `handleGetZmqNotifications` at
`server.nim:3338-3351` reads it. **Nothing else uses it.**

A grep for every notifyXxxx proc returns ZERO callers outside zmq.nim
itself. The field is never set; the procs are never invoked. `RpcServer`
constructor (`rpc/server.nim::newRpcServer`) does not initialize the
field, so it stays `nil`, `getzmqnotifications` always returns `[]`,
and no subscriber ever sees any event.

The notify routines are FULLY WIRED INTO ZMQ correctly (verified at
`zmq.nim:464-524`): they format the right packet bodies
(`MSG_HASHTX` + reversed txid; `MSG_RAWTX` + serialized witness tx;
`MSG_SEQUENCE` + 41-byte body with label `A` or `R` + 8-byte LE
sequence). The infrastructure works perfectly in isolation — it is
just never called.

This is a textbook **dead-data plumbing** finding: the surface area
exists, the format is correct, the lifecycle methods exist
(`initialize`, `shutdown`), but the **callers are missing**.

**File:** `src/rpc/zmq.nim:464-579` (all notify procs); `src/rpc/server.nim:51`
(field), `:3338-3351` (the one caller, RPC-only); `src/mempool/mempool.nim`,
`src/network/sync.nim`, `src/storage/chainstate.nim`, `src/rpc/server.nim`
(submitblock path) — all four locations that SHOULD call notify routines
do not.

**Core ref:** `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`
hooks into validation interface; fans every tx accept/remove and
every block connect/disconnect into the configured publishers.

**Impact:**
- Operators configuring `-zmqpubhashtx=tcp://*:28332` etc. get
  a quiet socket; `getzmqnotifications` returns `[]` so monitoring
  detects no subscriptions
- Electrs / fulcrum / mempool.space / nbxplorer / any tooling that
  uses ZMQ for low-latency tx-acceptance + block notification cannot
  function against a nimrod node
- The `RpcServer.zmq` field is dead-storage cross-cite to BUG-1
  W141 etc.

---

## BUG-12 (P1 / W150 BUG-7 carry-forward) — `bypassLimits` field defined and honored, never set true

**Severity:** P1. **7th distinct nimrod instance of
"plumb-gate-then-don't-flip"** (W150 BUG-7 was the first; W151 / W152
catalogued more).

`AtmpArgs.bypassLimits` (`mempool.nim:40-42`):

```nim
bypassLimits*: bool            ## Core ATMPArgs::m_bypass_limits — used for
                               ## reorg replay; skip min-fee + TRUC limits.
```

Honored at three gates inside `acceptTransactionWithArgs`:
- `mempool.nim:1150` — min-fee gate skipped
- `mempool.nim:1168` — TRUC checks skipped
- `mempool.nim:1340` — post-eviction "mempool full" check skipped

But **no production caller sets it to `true`**. Grep for `bypassLimits:
true` / `bypassLimits = true` returns zero hits.

Most critical missing caller: `mempool.nim:1485-1501::blockDisconnected`
re-admits disconnected non-coinbase txs by calling
`mp.acceptTransaction(tx, crypto)` — defaults apply, so the min-fee
gate fires. If the rolling-fee floor has risen since these txs were
admitted (which is likely if they came from a disconnected high-fee
block era), the re-admit fails and Core-equivalent txs are silently
dropped. Core specifically sets `bypass_limits=true` for reorg refill
exactly to avoid this drop.

**File:** `src/mempool/mempool.nim:40-42` (field), `:1150, 1168, 1340`
(honored gates), `:1499` (the missing caller —
`mp.acceptTransaction(tx, crypto)` should be `mp.acceptTransactionWithArgs(tx, crypto, AtmpArgs(bypassLimits: true, allowReplacement: true))`).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
sets `bypass_limits=true` on the per-tx ATMPArgs for disconnect-pool
refill.

**Impact:** reorg refill drops more txs than Core; the disconnected
txs that paid below the post-reorg rolling-fee floor are silently
lost; mempool state diverges from Core after every reorg of depth >0.

---

## BUG-13 (P1) — `prioritisetransaction` RPC absent

**Severity:** P1 (cross-cite BUG-8 for the underlying
`mapDeltas`/`ClearPrioritisation` infrastructure).

Core exposes `prioritisetransaction` (3 positional args: `txid`,
deprecated `priority_delta`, `fee_delta`). nimrod's RPC dispatch table
at `src/rpc/server.nim:8278+` has no case for it. A caller invoking
`prioritisetransaction` over JSON-RPC receives "Method not found".

The mempool entries' `modifiedFee` field (returned by
`mempoolEntryJson` at `server.nim:1265` as `"modified"`) is always
equal to `base` (line 1130-1131 comment-as-confession).

**File:** `src/rpc/server.nim` (no `handlePrioritiseTransaction`
proc; no `"prioritisetransaction"` dispatch case).

**Core ref:**
`bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`.

**Impact:** operators cannot bump a stuck tx, cannot penalize a spam
tx without RBF; mining-pool tooling that uses prioritisetransaction
to schedule pool's-own-payout txs cannot integrate; cross-impl
divergence.

---

## BUG-14 (P1) — Unbroadcast set absent; rebroadcast logic missing

**Severity:** P1.

Core's `m_unbroadcast_txids` (set inside `CTxMemPool`) tracks
transactions that haven't had a confirmed peer-side broadcast yet,
so the rebroadcast scheduler (`net_processing.cpp:rebroadcast_timer`)
periodically re-broadcasts them. Persisted in mempool.dat so a
restart-then-resume node retries unfinished broadcasts.

nimrod has no such set:
- `Mempool` struct has no `unbroadcastTxs` field (`mempool.nim:63-93`)
- `server.nim:1215 "unbroadcastcount": 0` is hardcoded zero
- `server.nim:1280 obj["unbroadcast"] = %false` is hardcoded false
- `persist.nim:111` writes `compactsize(0)` for the unbroadcast count;
  `persist.nim:251-253` reads-and-discards
- there is no rebroadcast scheduler in `src/network/`

Operators cannot tell which mempool entries are at risk of being
silently lost (peer dropped immediately after accept), and the
canonical Core rebroadcast hook never fires.

**File:** `src/mempool/mempool.nim:63-93` (struct);
`src/rpc/server.nim:1215, 1280` (hardcoded values);
`src/mempool/persist.nim:111, 251-253` (write-zero / read-discard).

**Core ref:** `bitcoin-core/src/txmempool.cpp:784-790::RemoveUnbroadcastTx`,
`bitcoin-core/src/net_processing.cpp::CheckForStaleTipAndEvictPeers`
(the rebroadcast loop).

**Impact:** txs whose first announcement gets the announcing peer
disconnected are silently dropped from the relay graph; operators
see no diagnostic via `getmempoolinfo.unbroadcastcount` because the
field is hardcoded.

---

## BUG-15 (P1) — `getmempoolinfo` missing 8 Core fields

**Severity:** P1.

Core's `getmempoolinfo` (post v25) returns:
- `loaded`, `size`, `bytes`, `usage`, `total_fee`, `maxmempool`
- `mempoolminfee`, `minrelaytxfee`, `incrementalrelayfee`
- `unbroadcastcount`, `fullrbf`
- **`permitbaremultisig`** (operator -permitbaremultisig)
- **`maxdatacarriersize`** (operator -datacarriersize)
- **`limitclustercount`** (operator -limitclustercount)
- **`limitclustersize`** (operator -limitclustersize)
- **`limitancestorcount`** (operator -limitancestorcount)
- **`limitancestorsize`** (operator -limitancestorsize)
- **`limitdescendantcount`** (operator -limitdescendantcount)
- **`limitdescendantsize`** (operator -limitdescendantsize)

nimrod's `handleGetMempoolInfo` (`server.nim:1199-1223`) returns only
the first 11 fields. The 8 bolded fields above are absent. Tooling
that branches on those fields (mempool monitors, batch-submission
planners) gets stale answers.

**File:** `src/rpc/server.nim:1205-1223`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
`MempoolInfoToJSON` at lines around 1067-1096.

**Impact:** monitoring divergence; some clients reject the JSON shape
as "missing required key" depending on strictness.

---

## BUG-16 (P1) — `mempoolminfee` returns raw `minFeeRate`, not `max(GetMinFee(), minRelayFee)`

**Severity:** P1.

Core's `mempoolminfee` = `max(pool.GetMinFee(),
pool.m_opts.min_relay_feerate).GetFeePerK()` — it explicitly takes
the maximum of the **dynamic** rolling floor (decaying after a block,
bumped after size-limit eviction) and the **static** min-relay floor.
This is the value the operator should use to decide "will my tx be
accepted right now".

nimrod's `handleGetMempoolInfo` (`server.nim:1200`) returns
`rpc.mempool.minFeeRate / 100_000_000.0` — the raw static floor,
ignoring `mp.rollingMinimumFeeRate`. After an eviction storm bumps
the rolling floor to e.g. 50 sat/vB, Core reports `mempoolminfee = 50
sat/vB` and external tooling stops trying to submit; nimrod still
reports `1 sat/vB` and tooling submits and gets rejected.

**File:** `src/rpc/server.nim:1200`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
line that calls `pool.GetMinFee()` first.

**Impact:** wallets and fee bumpers receive an unrealistic floor;
batch-submission planners hammer the node with txs that get rejected
under the rolling floor.

---

## BUG-17 (P1) — `incrementalrelayfee` is a hardcoded literal

**Severity:** P1.

`src/rpc/server.nim:1214 "incrementalrelayfee": 0.00001` is a
hardcoded BTC/kB literal. It does not read `rpc.mempool.incrementalRelayFeeRate`
(which IS the correct source per `mempool.nim:87, 102, 1683`).

Numeric check:
- nimrod's runtime `mp.incrementalRelayFeeRate = 100.0` sat/kvB
  → correct emit = `100 / 100_000_000 = 0.000001` BTC/kB
- hardcoded value `0.00001` BTC/kB → 10× too high

Or if the intended unit was BTC/kvB (which is what Core emits):
- `0.00001 BTC/kvB = 10 sat/kvB` — 10× too small
- correct emit = `100 / 100_000_000 = 0.000001 BTC/kvB`

Either way, the hardcoded value diverges from the actual mempool
configuration; and like BUG-1, the divisor relationship is wrong.
Plus, the value cannot follow operator `-incrementalrelayfee`
overrides (if BUG-3 is fixed).

**File:** `src/rpc/server.nim:1214`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
`ret.pushKV("incrementalrelayfee", ValueFromAmount(pool.m_opts.incremental_relay_feerate.GetFeePerK()))`.

**Impact:** RBF-rule-4 fee calculations done client-side from
`getmempoolinfo.incrementalrelayfee` over- or under-pay by 10× for
the same reasons as BUG-1.

---

## BUG-18 (P1) — `removeTransaction` fee-estimator hook fires unconditionally

**Severity:** P1.

`mempool.nim:1413-1415`:

```nim
# BUG-12 fix (W114 FIX-47): notify fee estimator of eviction/removal.
if mp.feeEstimator != nil:
  mp.feeEstimator.removeTransaction(txid)
```

This fires for ALL removal reasons (BLOCK / CONFLICT / REPLACED /
EXPIRY / SIZELIMIT / REORG). Core's current implementation actually
does the same (`block_policy_estimator.cpp::TransactionRemovedFromMempool`
calls `removeTx(tx->GetHash())` ignoring the reason — so parity is
OK in 2026). BUT: the policy reason is that `BLOCK` removals MUST
also fire `processBlock` (which `fees.nim::processBlock` does
separately), and Core's design preserves the reason in case future
refactors want it back.

The carry-forward concern: when Core eventually re-introduces
reason-branching, nimrod's no-reason `removeTransaction` API will
break parity silently. The plumb-gate-then-don't-have-the-info shape
is fragile by design.

**File:** `src/mempool/mempool.nim:1413-1415`.

**Core ref:**
`bitcoin-core/src/policy/fees/block_policy_estimator.cpp::TransactionRemovedFromMempool`
(currently `/*unused*/ reason`).

**Impact:** currently parity-OK; future-fragile.

---

## BUG-19 (P1) — `feeEstimator.processBlock` only called from `submitblock` and reorg-via-submitblock paths

**Severity:** P1 (downstream of BUG-9 but documented separately because
the fix is independent: even if `removeForBlock` were called from
`sync.nim::applyBlock`, the fee-estimator hook also needs wiring).

Call sites for `feeEstimator.processBlock(height, confirmedTxids)`:
- `rpc/server.nim:3793-3797` — submitblock happy path
- `rpc/server.nim:3954-3961` — submitblock reorg path

Neither fires from `network/sync.nim::applyBlock` (the canonical P2P
block path) or `mempool.nim::removeForBlock` (the right architectural
home for the call). Cross-cite BUG-9: the P2P-driven block path
doesn't call `removeForBlock` either, so the fee-estimator gets no
updates from production P2P operation.

**File:** `src/rpc/server.nim:3793-3797, 3954-3961` (the only call
sites); `src/network/sync.nim:1056-1221` (the missing call site).

**Core ref:**
`bitcoin-core/src/policy/fees/block_policy_estimator.cpp::MempoolTransactionsRemovedForBlock`
fires from the chainstate's `BlockConnected` validation signal.

**Impact:** post-IBD fee estimation never updates from the chain;
fee-estimate RPCs (`estimatesmartfee`, `estimaterawfee`) return
either the initial fallback or stale values from the brief regtest
testing window.

---

## BUG-20 (P1) — `incrementalRelayFeeRate / 1000.0` conversion in bumpfee path is correct but the field unit is documented inconsistently

**Severity:** P1 (documentation / type-tightness gap).

`src/rpc/server.nim:6957-6959`:

```nim
let minRelayFeeSatVb = rpc.mempool.minFeeRate
let incrementalRelayFeeSatVb =
  rpc.mempool.incrementalRelayFeeRate / 1000.0  # sat/kvB → sat/vB
```

The conversion `/1000.0` is correct (sat/kvB → sat/vB). BUT:
- `mp.minFeeRate` is documented as sat/vbyte (`mempool.nim:69`)
  and used directly in sat/vB context here — correct.
- `mp.incrementalRelayFeeRate` is documented as sat/kvB
  (`mempool.nim:87`) and converted here — correct.

These two fee fields have DIFFERENT UNITS on the same struct. Every
caller has to remember which is which. Type-aliasing as `SatPerVByte`
vs `SatPerKVByte` would prevent the entire class of bugs that
includes BUG-1, BUG-2, BUG-17.

**File:** `src/mempool/mempool.nim:69, 87` (heterogeneous units);
`src/rpc/server.nim:6957-6959, 1200, 1214` (call sites that must
remember).

**Core ref:** `bitcoin-core/src/policy/feerate.h::CFeeRate` is one
value type used everywhere — sat/kvB exclusively, with explicit
`GetFee(size_t bytes)` accessors that take vbytes and return sats.

**Impact:** every fee bug in this audit (BUG-1, BUG-2, BUG-17) is
downstream of this type-tightness gap.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-1, BUG-2, BUG-6, BUG-9, BUG-10, BUG-12 cross-class)
- **P0-DEAD:** 1 (BUG-11)
- **P1:** 13 (BUG-3, BUG-4, BUG-5, BUG-7, BUG-8, BUG-13, BUG-14,
  BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20)

(BUG-12 is technically a P1 plumb-gate carry-forward but the reorg-
divergence shape is P0-CDIV-class; counted as P1 above to keep the
severity bar consistent with W150's classification.)

**Total: 20 bugs, 7 P0-class.**

**Fleet patterns confirmed:**
- **"dead-data plumbing"** (BUG-11 ZMQ subsystem, BUG-13 prioritisation,
  BUG-14 unbroadcast set, BUG-17 hardcoded literal) — 4 instances this
  wave; nimrod cumulative across W141+W150+W151+W152+W153 now ~12
- **"wiring-look-but-no-wire"** (BUG-3 operator knobs, BUG-9
  applyBlock → removeForBlock, BUG-19 fee-estimator processBlock)
- **"plumb-gate-then-don't-flip"** (BUG-12 bypassLimits) — 7th nimrod
  instance; W150 BUG-7 was the first
- **"comment-as-confession"** (BUG-8 line 1130-1131 "nimrod has no
  PrioritiseTransaction, so modified == base") — 8th nimrod instance
- **"asymmetric fix"** (BUG-2 DefaultMinFeeRate missed by FIX-69
  while DefaultIncrementalRelayFee was caught — NEW PATTERN this wave;
  the partial fix is itself a bug)
- **"4-audit carry-forward without closure"** (BUG-1 mempoolminfee
  divisor — W141 / W150 / W151 / W152 / W153)
- **"two-pipeline guard 19th distinct extension"** (BUG-9
  applyBlock and submitblock are two block-application pipelines and
  only one calls `removeForBlock`; cross-cite with BUG-19 the same
  shape for fee-estimator hook)
- **"hardcoded literal where field exists"** (BUG-17
  `"incrementalrelayfee": 0.00001` instead of reading the field)
- **"heterogeneous units on same struct"** (BUG-20 minFeeRate vs
  incrementalRelayFeeRate sat/vB vs sat/kvB)

**Top three findings:**

1. **BUG-9 (P0-CDIV)** — `network/sync.nim::applyBlock` (the canonical
   P2P block-apply path) does NOT call `mempool.removeForBlock`.
   In normal P2P operation on mainnet/testnet4, confirmed transactions
   stay in the mempool forever (until 14-day expiry). `getrawmempool`
   diverges upward from reality; rolling-fee decay never gets the
   `blockSinceLastRollingFeeBump = true` signal (so the floor stays
   bumped forever); fee-estimator misses every block (BUG-19 cross-cite);
   `TrimToSize` evictions bump the floor for the WRONG reasons.
   **Production-blocking** for any operator depending on mempool/
   fee-estimator RPCs.

2. **BUG-11 (P0-DEAD)** — Entire ZMQ subsystem is fully implemented
   (579 lines, all formats correct) but the 9 mempool/block notify
   procs are never called from anywhere. `RpcServer.zmq` field never
   initialized. Operators get a quiet socket; electrs / fulcrum /
   mempool.space cannot integrate.

3. **BUG-1 (P0-CDIV / 4-audit carry-forward)** — `mempoolminfee`
   divisor `/ 100_000_000.0` instead of `/ 100_000.0` — **1000× too
   small**. Single-character edit per call site, two sites
   (`server.nim:1200` + `rest.nim:773`). **5+ weeks open across W141
   / W150 / W151 / W152 / W153.**

Notable adjacent finding: **BUG-2 (P0-CDIV)** — DefaultMinFeeRate is
10× Core's default; FIX-69 fixed the sibling DefaultIncrementalRelayFee
but missed this one. Fixing BUG-2 + BUG-1 together would close the
fee-rate parity gap that has plagued nimrod across the last 5 audits.
