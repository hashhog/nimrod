## W154 — CreateNewBlock + BlockAssembler + block template construction (nimrod)

**Wave:** W154 — `BlockAssembler`, `CreateNewBlock`, `resetBlock`, `addChunks`,
`TestChunkBlockLimits`, `TestChunkTransactions`, `AddToBlock`, `ClampOptions`,
`ApplyArgsManOptions`, `UpdateTime`, `GetMinimumTime`,
`GenerateCoinbaseCommitment`, `RegenerateCommitments`, `BlockMerkleRoot`,
`BlockWitnessMerkleRoot`, `IncrementExtraNonce` (legacy), per-network
constants `DEFAULT_BLOCK_MAX_WEIGHT = 4_000_000`,
`DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`,
`MINIMUM_BLOCK_RESERVED_WEIGHT = 2000`, `MAX_CONSECUTIVE_FAILURES = 1000`,
`BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000`, `MAX_BLOCK_SIGOPS_COST = 80_000`,
`MAX_BLOCK_WEIGHT = 4_000_000`, `WITNESS_SCALE_FACTOR = 4`,
`DEFAULT_BLOCK_MIN_TX_FEE` (1 sat/vB), `MAX_TIMEWARP = 600`,
`generatetoaddress`/`generatetodescriptor`/`generateblock` RPCs,
`getblocktemplate` GBT BIP-22 + BIP-23, `submitblock`.

**Scope:** discovery only — NO production code change in W154.
Concurrent-agent coordination: this is one of the W154 quad-audit sub-agents.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.h:42-57` — `CBlockTemplate { CBlock block; vTxFees;
  vTxSigOpsCost; m_package_feerates; m_coinbase_tx }`. Per-tx fee and sigops
  arrays are surfaced to the miner caller for `getblocktemplate`.
- `bitcoin-core/src/node/miner.h:60-123` — `BlockAssembler` class:
  `nBlockMaxWeight{DEFAULT_BLOCK_MAX_WEIGHT}`, `blockMinFeeRate{DEFAULT_BLOCK_MIN_TX_FEE}`,
  `test_block_validity{true}`, `print_modified_fee`,
  private `resetBlock`, `AddToBlock`, `addChunks`, `TestChunkBlockLimits`,
  `TestChunkTransactions`.
- `bitcoin-core/src/policy/policy.h:25-34` —
  `DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT}`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT{8000}`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT{2000}`,
  `DEFAULT_BLOCK_MIN_TX_FEE` (1 sat/vB / 1000 sat/kvB).
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT = 4_000_000`,
  `WITNESS_SCALE_FACTOR = 4`, `MAX_BLOCK_SIGOPS_COST = 80_000`,
  `MAX_TIMEWARP = 600`, `COINBASE_MATURITY = 100`.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`:
  block_reserved_weight clamped to `[MINIMUM_BLOCK_RESERVED_WEIGHT (2000),
  MAX_BLOCK_WEIGHT (4_000_000)]`; coinbase_output_max_additional_sigops clamped
  to `[0, MAX_BLOCK_SIGOPS_COST (80_000)]`; nBlockMaxWeight clamped to
  `[block_reserved_weight, MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`: nBlockWeight starts
  at `m_options.block_reserved_weight`; nBlockSigOpsCost starts at
  `m_options.coinbase_output_max_additional_sigops`; nBlockTx/nFees=0.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  - dummy coinbase tx pushed first (line 133).
  - `pblock->nVersion = ComputeBlockVersion(pindexPrev, GetConsensus())` (line 140)
    — uses versionbitscache to compute signaling bits.
  - regtest-only override `-blockversion=N` (line 143-145).
  - `m_lock_time_cutoff = pindexPrev->GetMedianTimePast()` (line 148).
  - mempool block-building lock acquired across the entire chunk-selection
    window (line 151-154) — `StartBlockBuilding`/`StopBlockBuilding` bookends.
  - coinbase scriptSig built via `CScript() << nHeight` (line 186) and, if
    `include_dummy_extranonce`, with an `OP_0` (line 187-193) to guarantee
    scriptSig.size() ≥ 2 for `nHeight <= 16`.
  - coinbase nLockTime = `nHeight - 1` (line 196) — anti-fee-sniping.
  - coinbase nSequence = `MAX_SEQUENCE_NONFINAL` (line 171) so the nLockTime
    is enforced.
  - `m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev)` (line 200) —
    inserts OP_RETURN 0xaa21a9ed witness-commitment output and witness reserved
    value into coinbase.
  - `UpdateTime(pblock, ...)` (line 219) — picks `max(GetMinimumTime, NodeClock::now())`.
  - `pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, ...)` (line 220).
  - **TestBlockValidity called at end** (line 223-227) — the assembler validates
    its own output via the canonical consensus pipeline before returning.
- `bitcoin-core/src/node/miner.cpp:239-260` — `TestChunkBlockLimits` is the
  ONLY place weight/sigops are enforced; uses `>=` (strict) on both.
- `bitcoin-core/src/node/miner.cpp:262-277` — `AddToBlock` accumulates fees,
  weights, sigops, vTxFees, vTxSigOpsCost in lock-step.
- `bitcoin-core/src/node/miner.cpp:279-334` — `addChunks` loop:
  - `chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions)` —
    pops the next CL-graph chunk (which may contain multiple txs, in
    topological order).
  - skip-condition: `chunk_feerate_vsize << blockMinFeeRate.GetFeePerVSize()` —
    everything else has lower feerate, return (no continue).
  - on `SkipBuilderChunk` failure: `nConsecutiveFailed++`; abort if
    `> MAX_CONSECUTIVE_FAILURES (1000)` AND
    `nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA (4000) > nBlockMaxWeight`.
  - on success: include ALL txs in the chunk together via `AddToBlock` for
    each tx — atomic; child + parents added together.
- `bitcoin-core/src/node/miner.cpp:36-65` — `GetMinimumTime` /
  `UpdateTime`:
  ```cpp
  int64_t GetMinimumTime(...) {
      int64_t min_time = pindexPrev->GetMedianTimePast() + 1;
      const int height = pindexPrev->nHeight + 1;
      if (height % difficulty_adjustment_interval == 0) {
          min_time = std::max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
      }
      return min_time;
  }
  ```
  i.e. **BIP-94 anti-timewarp accounting on every network, on diff-adjustment
  blocks**. `UpdateTime` then picks `max(GetMinimumTime, NodeClock::now())` and,
  on testnet/regtest with `fPowAllowMinDifficultyBlocks`, recomputes
  `pblock->nBits = GetNextWorkRequired(...)`.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`: erases
  the existing witness-commitment output, re-runs `GenerateCoinbaseCommitment`,
  re-computes `hashMerkleRoot` via `BlockMerkleRoot(block)`. Used when the
  block's txs change after `CreateNewBlock` returned (e.g., for testing/proposal).
- `bitcoin-core/src/validation.cpp:3997-4019` — `GenerateCoinbaseCommitment`:
  - returns no-op if `GetWitnessCommitmentIndex(block) != NO_WITNESS_COMMITMENT`
    (already has a commitment).
  - witnessroot = `BlockWitnessMerkleRoot(block)`;
  - commitment = `SHA256d(witnessroot || ret(32 zeros))`;
  - scriptPubKey = `OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commit>` (38 bytes).
  - **also calls `UpdateUncommittedBlockStructures`** which writes 32-zero
    witness reserved value into coinbase scriptWitness[0].
- `bitcoin-core/src/consensus/merkle.cpp:46-63` — `ComputeMerkleRoot` detects
  CVE-2012-2459 mutation via the `mutated` out-param flagged whenever an
  inner-hash adjacent pair was duplicated (odd row).
- `bitcoin-core/src/rpc/mining.cpp::generateBlocks` — the regtest `generateblock`
  / `generatetoaddress` RPCs route the mined block through
  `ProcessNewBlock` (the canonical consensus pipeline used for inbound P2P
  blocks), which calls `CheckBlock → AcceptBlock (ContextualCheckBlock) →
  ConnectBlock`. **NEVER calls a "fast path" that skips validation.**

**Files audited**
- `src/mining/blocktemplate.nim` (574 LOC) — `BlockTemplate`,
  `encodeBip34Height`, `computeWitnessCommitment`, `createWitnessCommitmentOutput`,
  `createCoinbaseTx`, `estimateTxSigops`, `calculateTxWeight`,
  `clampBlockOptions`, `buildBlockTemplate`, `updateTimestamp`,
  `updateTimestampSimple`, `updateExtraNonce`, `mine`, `toBlock`.
- `src/rpc/mining.nim` (320 LOC) — `mineBlock`, `generateBlocks`,
  `generateToAddress`, `generateToDescriptor`, `generateBlockWithTxs`,
  per-call `RegtestBits = 0x207fffff` and `DefaultMaxTries = 1_000_000`.
- `src/mining/fees.nim` (396 LOC) — `FeeEstimator` (out-of-scope for W154
  except where mining-side mempoolminfee echoes the W141 BUG-8 divisor regression).
- `src/rpc/server.nim:3576-3668` — `handleGetBlockTemplate` GBT response with
  `coinbasevalue`, `sigoplimit`, `sizelimit=4_000_000`, `weightlimit`, `mintime`,
  `default_witness_commitment`, `rules`, `vbavailable`, `vbrequired`.
- `src/rpc/server.nim:3681-3970` — `handleSubmitBlock` (the GOOD pipeline:
  `checkBlock → acceptBlock → connectBlock`).
- `src/rpc/server.nim:3974-4160` — `handleGenerateToAddress`,
  `handleGenerateToDescriptor`, `handleGenerateBlock`.
- `src/rpc/server.nim:4425-4460` — `handleGetMiningInfo` (`blockmintxfee` is
  hardcoded to `0.00001000` — see BUG-21).
- `src/consensus/params.nim:88-93, 162, 291, 358, 419, 476` —
  `MaxBlockWeight = 4_000_000`, `WitnessScaleFactor = 4`,
  `MaxBlockSigopsCost = 80_000`, `MaxStandardTxSigopsCost = 16_000` and the
  per-network `maxBlockWeight = 4_000_000` (all five networks identical to
  Core).
- `src/consensus/validation.nim:210-219` — `getBlockSubsidy`; 1260-1451
  `validateBlock`; 1808-1855 `checkBlock`; 1808+ `acceptBlock`.
- `src/storage/chainstate.nim:739-908` — `connectBlock` (the SHORTCUT that the
  miner uses — does NOT call `checkBlock`/`validateBlock`/`acceptBlock`).
- `src/mempool/mempool.nim:1504-1527` — `getTransactionsByFeeRate` (the
  per-entry ancestor-feerate sort, see BUG-3 below).

---

## Gate matrix (33 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT = 4_000_000 | G1: constant defined | PASS (`params.nim:88`) |
| 1 | … | G2: per-network field set to 4_000_000 (mainnet/testnet3/testnet4/regtest/signet) | PASS (`params.nim:162/291/358/419/476`) |
| 2 | WITNESS_SCALE_FACTOR = 4 | G3: constant defined and used in weight calc | PASS (`params.nim:93`, `validation.nim:1346`, `blocktemplate.nim:276`) |
| 3 | DEFAULT_BLOCK_MAX_WEIGHT (default cap, ops-tunable) | G4: separate from MAX_BLOCK_WEIGHT, operator-tunable | **BUG-1 (P1)** — no `DEFAULT_BLOCK_MAX_WEIGHT` constant; `clampBlockOptions` consumes `params.maxBlockWeight` (the **consensus** cap) directly. There is no `-blockmaxweight` operator knob, no way to mine smaller blocks for testing. Core's `DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT}` is conceptually distinct (policy vs consensus). |
| 4 | DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 | G5: constant defined | PASS (`blocktemplate.nim:16 CoinbaseReservedWeight = 8_000`) |
| 4 | … | G6: MINIMUM_BLOCK_RESERVED_WEIGHT = 2000 enforced | PASS (`blocktemplate.nim:19, 283`) |
| 4 | … | G7: `-blockreservedweight` operator knob | **BUG-2 (P1)** — no such flag; `CoinbaseReservedWeight` is a `const` not a runtime option. `clampBlockOptions` accepts `reservedWeight: int` from the caller but no caller threads it from CLI args. |
| 5 | addPackageTxs / addChunks: ancestor-cluster ordering | G8: child + parents added atomically (topological) | **BUG-3 (P0-CONS)** — `getTransactionsByFeeRate` (`mempool.nim:1504-1527`) sorts INDIVIDUAL entries by `ancestorFee/ancestorWeight`. A child with high ancestor-feerate is enumerated BEFORE its parent (the parent's individual feerate is lower). The selection loop accepts the child while its parent may be skipped or appear later — producing a block with child-before-parent OR child-without-parent, both of which violate consensus (Core CheckTransaction rejects `bad-txns-inputs-missingorspent`). Core uses `GetBlockBuilderChunk` which pops the entire CL-graph chunk in topological order; nimrod has no chunk concept. |
| 5 | … | G9: greedy-by-package, not greedy-by-individual | **BUG-3 cross-cite** — see G8. The skip-on-weight-fail loop continues to the next individual entry, never reverting an already-accepted child to maintain topological order. |
| 6 | MAX_CONSECUTIVE_FAILURES + BLOCK_FULL_ENOUGH_WEIGHT_DELTA | G10: 1000 / 4000 constants present and used | PASS (`blocktemplate.nim:23, 27, 356-358, 366-368, 374-376`) |
| 7 | TestChunkBlockLimits uses `>=` not `>` | G11: weight gate is `>=` | PASS (`blocktemplate.nim:353` matches `miner.cpp:241`) |
| 7 | … | G12: sigops gate is `>=` | PASS (`blocktemplate.nim:364`) |
| 8 | GenerateCoinbaseCommitment / 0xaa21a9ed OP_RETURN | G13: prefix bytes `0x6a 0x24 0xaa 0x21 0xa9 0xed` | PASS (`blocktemplate.nim:12, 144`) |
| 8 | … | G14: only emit OP_RETURN when there are segwit txs | **BUG-4 (P1)** — `createCoinbaseTx` (`blocktemplate.nim:178-195`) sets `hasWitnessCommitment` to TRUE only when the commitment is non-zero. Core unconditionally generates the commitment whenever the chain is past segwit activation (`validation.cpp:3997-4019` is called regardless of whether any non-coinbase tx carries a witness). On a chain-tip past segwit-active, a block with no segwit txs in nimrod has NO witness commitment in the coinbase, but Core would still emit one. A miner that re-submits a nimrod-built template via Core's `submitblock` (legitimate cross-impl flow) gets rejected with `bad-witness-merkle-match`. |
| 8 | … | G15: coinbase witness stack: exactly one element of 32 zero bytes (consensus) | PASS (`blocktemplate.nim:199-206`) — written only when commitment emitted; cross-cite BUG-4 for the asymmetry. |
| 9 | BlockMerkleRoot / BlockWitnessMerkleRoot | G16: txid merkle root recomputed before return | PASS (`blocktemplate.nim:432-436`) |
| 9 | … | G17: CVE-2012-2459 mutation detection during merkle build | **BUG-5 (P0-CDIV)** — `hashing.computeMerkleRoot` does NOT surface a mutation flag (cross-cite W143 BUG and W142 BUG-1). The miner therefore cannot detect that its own merkle tree was inadvertently built with a duplicate-leaf-pair (e.g., from a malformed mempool entry). Core's `ComputeMerkleRoot` returns a `mutated` bool out-param. |
| 10 | mintime = parent MTP + 1 | G18: `updateTimestamp` enforces `prevBlockMtp + 1` floor | PARTIAL (`blocktemplate.nim:506-509`) — enforced only when caller passes `prevBlockMtp > 0`; default arg is `0` (line 491). `mineBlock` does NOT call `updateTimestamp`; instead it sets `tmpl.header.timestamp = uint32(getTime().toUnix())` (`rpc/mining.nim:43`), bypassing the MTP+1 floor entirely. `generateBlockWithTxs` does the same (`rpc/mining.nim:278`). On regtest where wall-clock has drifted < prevMTP+1, the mined block will fail consensus on its OWN `checkBlock → contextualCheckBlockHeader` IF the consensus path ever runs — but see BUG-9 below; it doesn't. |
| 10 | … | G19: BIP-94 MAX_TIMEWARP = 600 on diff-adjustment blocks (every network, per Core post-#28676) | **BUG-6 (P0-CDIV)** — `updateTimestamp` knows nothing about BIP-94. Core's `GetMinimumTime` raises the floor to `max(prevMTP+1, pindexPrev->GetBlockTime() - MAX_TIMEWARP)` on diff-adjustment-height blocks **on every network**, not just BIP-94 networks. A nimrod-mined block on mainnet at height `% 2016 == 0` whose timestamp is `pindexPrev->GetBlockTime() - 1000` (1000s before parent) passes `getTime().toUnix() >= prevMTP+1` but a Core node receiving it will reject with `time-timewarp-attack` once Core enables BIP-94 on mainnet (which it does post-v29). Carry-forward shape of `nimrod` not enforcing BIP-94 on non-testnet4 networks at mining time. |
| 10 | … | G20: nVersion = ComputeBlockVersion(pindexPrev, params) | PASS in `buildBlockTemplate` (`blocktemplate.nim:459-467`); **BUG-7 (P0-CDIV)** in `generateBlockWithTxs` (`rpc/mining.nim:275`) — hardcoded `0x20000000`, ignores BIP-9 STARTED/LOCKED_IN signaling bits. Two-pipeline guard (**19th distinct extension**, first for miner template construction): the GBT path and the regtest `generateblock` path derive nVersion differently. A regtest test that exercises BIP-9 deployments will see GBT signal a bit while `generateblock` does NOT. |
| 11 | coinbase scriptSig 2..100 bytes | G21: encodeBip34Height 1..16 → 1-byte OP_n + dummy_extranonce → ≥ 2 bytes | PASS (`blocktemplate.nim:90-110, 171-175`); the 8-byte extra-nonce padding guarantees scriptSig.len ≥ 9 even at height 1. |
| 11 | … | G22: coinbase scriptSig ≤ 100 bytes | PASS (`validation.nim:325-326` enforces); `createCoinbaseTx` produces ~14 bytes (height 1-3 byte + 8 extra-nonce + … = ≤ 13). |
| 12 | BIP-34 coinbase-height encoding | G23: matches `CScript() << nHeight` byte-exact | **BUG-8 (P1)** — `encodeBip34Height` (`blocktemplate.nim:90-110`) does NOT emit `OP_0` (0x00 byte) for `height == 0`; instead returns `@[0x00'u8]`. Core's `CScript() << int64_t(0)` emits `OP_0` (one byte 0x00). They happen to produce the same byte but for opposite reasons (nimrod returns a single 0x00 byte tagged as "OP_0 for zero"; Core invokes the `int64_t` overload that goes through `CScriptNum::serialize(0)` → empty array → push as `OP_0`). The output happens to match. **Actual divergence:** when `height > 0xffff_ff7f` (32-bit unsigned with bit-31 set in the high byte), nimrod's `if (data[^1] and 0x80) != 0` appends `0x00`, matching Core. But for `height < 0`, nimrod returns `@[0x00'u8]` (the `OP_0` branch); Core's `int64_t(-h)` emits a sign-bit-set CScriptNum. Caller guarantees `height >= 0`, so the divergence is latent. **Real bug:** `encodeBip34Height` is **also** used in `validateCoinbase` (`validation.nim:340`) — so the miner and the validator share the same encoder but a different consumer (e.g., a peer-built block with `CScript() << 0` followed by anything) would be validated correctly only if encoder is byte-exact. Mark P1 because the latent divergence is not currently triggered. |
| 13 | GBT reserved weight + sigops | G24: `weightlimit` and `sigoplimit` emitted as consensus caps | PASS (`server.nim:3656-3658`) |
| 13 | … | G25: `weightlimit` emits `params.maxBlockWeight` (consensus cap) NOT `nBlockMaxWeight` (operator-tunable policy cap) | **BUG-9 (P1)** — `server.nim:3658` emits `rpc.params.maxBlockWeight` (always 4_000_000). When BUG-2's `-blockmaxweight` is wired (likely future fix), the GBT response will still report consensus cap, misleading external miners (cgminer, S9 fw, mining proxies) that read `weightlimit` for their internal sanity checks. Core emits the **template's** nBlockMaxWeight. |
| 13 | … | G26: `sizelimit` matches reality (4_000_000 means pre-segwit equivalent) | **BUG-10 (P2)** — `server.nim:3657` hardcodes `4000000`. Core hardcodes `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` here as a BIP-22 "size limit" — this is the **post-segwit** serialized-with-witness cap. Cosmetic, but if `params.maxBlockWeight` is ever overridden the GBT consumer sees a constant. |
| 14 | mining path → ProcessNewBlock-equivalent consensus pipeline | G27: `generatetoaddress` routes mined block through `checkBlock → validateBlock → checkBip30 → verifyScripts → connectBlock` (the `acceptBlock` pipeline) | **BUG-11 (P0-CONS)** — `mineBlock` (`rpc/mining.nim:75-108`) calls `chainState.connectBlock(blk, height)` DIRECTLY (line 101). `connectBlock` (`chainstate.nim:739-908`) is a state-mutation primitive that only checks coinbase maturity on input spending; it does NOT call `checkBlock` (PoW + merkle + tx sanity), does NOT call `validateBlock` (weight + sigops + BIP-34 + coinbase value + IsFinalTx + witness commitment), does NOT call `checkBip30` (CVE-2012-1909 dup-coinbase), does NOT call `verifyScripts`. **This is the same fleet-wide pattern called out in W143 BUG-3 (`--reindex` paths bypass `acceptBlock`) and W145 BUG-1 (`--reindex` skips entire consensus pipeline).** The miner pipeline is now the THIRD ENTRY POINT in nimrod that bypasses consensus (after IBD-reindex paths in `nimrod.nim:1611+, 1780+`). A miner that produces an overweight block, a block whose merkle root is wrong, a block whose coinbase value exceeds subsidy+fees, or a block with a duplicate witness commitment will have that block ACCEPTED into its own chainstate. The block then fails when relayed to peers ("bad-blk-length", "bad-txns-merkle", "bad-cb-amount") — the local node is now stuck on a forked tip until a manual `invalidateblock`. Three-pipeline drift (NEW finding for nimrod). |
| 14 | … | G28: same for `generateblock` (`generateBlockWithTxs`) | **BUG-11 cross-cite** — `rpc/mining.nim:313` calls `chainState.connectBlock(blk, height)` directly; identical bypass. |
| 14 | … | G29: same for `submitblock` (BIP-22) | PASS — `handleSubmitBlock` (`server.nim:3681-3793`) correctly routes through `checkBlock + acceptBlock + connectBlock`. **The asymmetry is the bug.** Submission via P2P or BIP-22 RPC is validated; local block generation is NOT. |
| 15 | coinbase int64 overflow (carry-forward from W143 BUG-2 / W145 BUG-5) | G30: subsidy + fees and coinbase output sum bounded before `>` comparison | **BUG-12 (P0-SEC, CARRY-FORWARD)** — W143 BUG-2 (coinbase int64 wrap in `validateBlock`) and W145 BUG-5 (coinbase int64 accumulator wraps before `>` compare) BOTH apply to the miner-side `createCoinbaseTx` (`blocktemplate.nim:189`): `subsidy + fees` is a `Satoshi + Satoshi` borrow on int64 (`{.borrow.}` operator, no overflow trap). On a (hypothetical, miner-controlled) `totalFees > 2_100_000_000_000_000`, the addition wraps to negative; the wrap then propagates into the coinbase output value. The `validateBlock` consensus path (BUG-11) is **bypassed** by the miner, so the wrap is not caught locally. Carry-forward severity is **strictly worse here than in validation**: the miner CONSTRUCTS the broken coinbase rather than validating one. Cross-cite W145 BUG-1 — fee summing in mempool `selectTransactionsForBlock` uses raw `Satoshi + Satoshi`. |
| 16 | mempoolminfee divisor for block-template `blockmintxfee` (carry-forward W141 BUG-8 / W153 BUG-1) | G31: `getmininginfo.blockmintxfee` is correct sat/vB conversion | **BUG-13 (P1, CARRY-FORWARD)** — `server.nim:4449` hardcodes `0.00001000`. W141 BUG-8 / W153 BUG-1 flagged that nimrod's mempool `getmempoolinfo.mempoolminfee` divisor is 1000× too low; the miner-side echo is `getmininginfo.blockmintxfee`, which Core derives from `m_options.blockMinFeeRate.GetFeePerVSize()`. The hardcoded `0.00001000` is correct AS A VALUE (1000 sat/kvB = 0.00001000 BTC/kB) but the value is hardcoded — it does not reflect the actual `blockMinFeeRate` in the template. Any future `-blockmintxfee=N` flag (BUG-2 sibling) will be ignored here. Same pattern as the mempoolminfee divisor regression that has been open since W138. |
| 17 | bypassLimits gate (carry-forward W150 BUG-7) | G32: block-template path doesn't construct a tx-acceptance path with `bypassLimits` plumbed but not flipped | N/A — block-template path does not call mempool acceptTransaction; orthogonal to W150 BUG-7. But the analogous shape **does** appear in the mining path: `mineBlock` accepts an `if params.powNoRetargeting:` regtest flag (line 38) that flips the target to RegtestBits — fine. There is, however, NO `bypassLimits`-like skip-script gate on the assemble path. PASS-by-not-applicable. |
| 18 | `m_last_block_weight` / `m_last_block_num_txs` | G33: surfaced (Core: `BlockAssembler::m_last_block_weight`, static inline `std::optional`) | **BUG-14 (P2)** — nimrod exposes `tmpl.totalWeight` per template but does NOT cache the assembler-static `last_block_weight`. `getmininginfo` (`server.nim:4444`) emits `currentblockweight = 0`. The field is meant to surface the LAST built template's weight so external miners can graph their template-fill rates; nimrod always reports 0. Same gap as the no-knob `-blockmaxweight`. |

---

## BUG-1 (P1) — `DEFAULT_BLOCK_MAX_WEIGHT` is conflated with consensus `MAX_BLOCK_WEIGHT`; no `-blockmaxweight` operator knob

**Severity:** P1. Bitcoin Core distinguishes the consensus cap
(`MAX_BLOCK_WEIGHT = 4_000_000`, `consensus/consensus.h`) from the default
miner template cap (`DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT}`,
`policy/policy.h:25`). The operator can override the latter with
`-blockmaxweight=N` (`ApplyArgsManOptions`, `miner.cpp:101`). Smaller blocks
than 4M WU are useful for: testing on regtest, mining shorter blocks for
low-bandwidth uplinks, throughput experiments.

nimrod's `clampBlockOptions` (`blocktemplate.nim:278-285`) takes
`params.maxBlockWeight` (the consensus cap) directly. There is no
`-blockmaxweight` CLI flag, no per-template override knob, no way to mine
smaller blocks for testing.

**File:** `src/mining/blocktemplate.nim:278-285`,
`src/rpc/server.nim:3585-3590` (caller passes no override).

**Core ref:** `bitcoin-core/src/policy/policy.h:25-27`,
`bitcoin-core/src/node/miner.cpp:101`.

**Impact:** regtest test ergonomics; no operator knob; future regression
that bumps `params.maxBlockWeight` (network-level config drift) silently
changes mining behaviour without operator intervention.

---

## BUG-2 (P1) — No `-blockreservedweight` operator knob

**Severity:** P1. `CoinbaseReservedWeight = 8_000` (`blocktemplate.nim:16`)
is a `const`. `clampBlockOptions` accepts `reservedWeight: int` from the
caller, but the only caller (`buildBlockTemplate:325`) passes
`CoinbaseReservedWeight` (the const), and there is no CLI flag to override.
Core exposes `-blockreservedweight` (`miner.cpp:106-108`) and a separate
`options.block_reserved_weight` field that the assembler reads from
`m_options`.

Operators who want to reserve more space for a fancy coinbase scriptPubKey
(e.g., a multisig with many keys, a witness scriptPubKey with extra data, a
custom OP_RETURN witness commitment for L2 protocols) have no way to do so;
the hard-coded 8000 WU caps the coinbase at ~2KB serialized.

**File:** `src/mining/blocktemplate.nim:16, 19, 325`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:106-108, 113-114`.

**Impact:** no operator knob; L2 protocol miners (rollup commit blocks,
sidechain pegouts) cannot reserve extra coinbase space.

---

## BUG-3 (P0-CONS) — `getTransactionsByFeeRate` sorts INDIVIDUAL entries by ancestor-feerate, producing child-before-parent or child-without-parent blocks

**Severity:** P0-CONS. Bitcoin Core's `addChunks` (`miner.cpp:279-334`) pops
ENTIRE CL-graph chunks from the mempool via
`m_mempool->GetBlockBuilderChunk(selected_transactions)`. A chunk contains
multiple txs in topological order; either ALL txs in the chunk are added
together (via `AddToBlock` for each in order) or NONE are
(`SkipBuilderChunk`). This guarantees that every block respects topological
ordering (child appears after parent) and includes either both parent +
child or neither — the consensus rule `bad-txns-inputs-missingorspent`
cannot be violated by a Core-built template.

nimrod's `getTransactionsByFeeRate` (`mempool.nim:1504-1527`) does the wrong
thing in three independent ways:

1. **Per-entry sort, not per-cluster.** `entries: seq[MempoolEntry]` is
   built from `mp.entries.values` (one entry per tx, not per cluster). The
   sort key is `entry.ancestorFee / (entry.ancestorWeight / 4.0)`. A child
   with a tiny individual fee but huge ancestor-feerate (CPFP situation)
   appears EARLY in the sorted seq; its parent (lower ancestor-feerate)
   appears LATER.

2. **Greedy weight-fit selection.** The selection loop
   (`mempool.nim:1523-1527`) accepts entries in sort order as long as
   `totalWeight + entry.weight <= maxWeight`. There is NO topological
   check — if the child fits, it's included. The parent may later be
   included (if it also fits) OR skipped (if `maxWeight` is exhausted) OR
   rejected by `nConsecutiveFailed` in the caller.

3. **No chunk-skip-together semantics.** The caller
   (`blocktemplate.nim:342-386`) processes each entry independently. If a
   weight/sigops/finality check skips an entry, the loop just moves to the
   next entry — even if that next entry depends on the skipped one.

**Failure mode (regtest reproduction)**

```text
1. submit tx A (parent, fee 1 sat/vB, weight 200)
2. submit tx B (child spending A.vout[0], fee 1000 sat/vB on its own,
   ancestor-feerate ((1000 * 50 vB) + (1 * 50 vB)) / (50 + 50) =
   500.5 sat/vB; A's ancestor-feerate is unchanged at 1 sat/vB)
3. getblocktemplate
4. expected: A then B in the template (Core: chunk {A, B} popped together,
   AddToBlock(A) then AddToBlock(B))
5. observed: B in slot 1, A may or may not appear in slot 2 — depending on
   weight-fit order
   - if A appears later, the template has B before A → consensus failure on
     submit: "bad-txns-inputs-missingorspent" (B.vin[0] references A.txid
     but A is not yet in the UTXO set as of B's position in the block)
   - if A does NOT appear (maxWeight exhausted, nConsecutiveFailed abort
     after B+everything-else-with-higher-individual-feerate-than-A),
     B is included without A → same "bad-txns-inputs-missingorspent"
```

The miner's `connectBlock` shortcut (BUG-11) means the local node accepts
its own broken block (no consensus check). The block then fails when
relayed; the node is stuck on a fork.

**File:** `src/mempool/mempool.nim:1504-1527`;
`src/mining/blocktemplate.nim:333-386` (selection loop is per-entry not
per-chunk).

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334` (`addChunks` /
`GetBlockBuilderChunk`); `bitcoin-core/src/txmempool.cpp::CTxMemPool::GetBlockBuilderChunk`
(chunk-graph traversal in topological order).

**Excerpt (nimrod, per-entry sort)**
```nim
entries.sort(proc(a, b: MempoolEntry): int =
  let aRate = float64(int64(a.ancestorFee)) / (float64(a.ancestorWeight) / 4.0)
  let bRate = float64(int64(b.ancestorFee)) / (float64(b.ancestorWeight) / 4.0)
  if aRate > bRate: -1 elif aRate < bRate: 1 else: 0
)
# Select transactions up to maxWeight
var totalWeight = 0
for entry in entries:
  if totalWeight + entry.weight <= maxWeight:
    result.add(entry)
    totalWeight += entry.weight
```

The selection loop does **not** look at `entry.tx.inputs[*].prevOut.txid` to
verify topological order against already-accepted entries.

**Impact:**
- Local consensus error: the miner's own chainstate may accept a block that
  Core's `submitblock` would reject.
- Relayed-block reject: the block fails P2P propagation with
  `bad-txns-inputs-missingorspent`; the local node sees a chain fork once
  honest peers extend the canonical chain past the rejected block.
- Cross-impl divergence in mempool-package mining (W151 RBF + W137 PSBT v2
  package mining are both predicated on topological correctness).

---

## BUG-4 (P1) — Witness commitment skipped when no segwit txs (Core emits unconditionally post-segwit-active)

**Severity:** P1. Bitcoin Core's `ChainstateManager::GenerateCoinbaseCommitment`
(`validation.cpp:3997-4019`) generates the witness commitment unconditionally
whenever it's called from `BlockAssembler::CreateNewBlock` (`miner.cpp:200`).
Core's `GetWitnessCommitmentIndex` returns `NO_WITNESS_COMMITMENT` for a
freshly-built coinbase; the unconditional generation path then runs.

The post-segwit-active block thus always carries a witness commitment in the
coinbase, even on blocks containing zero segwit non-coinbase txs.

nimrod's `createCoinbaseTx` (`blocktemplate.nim:178-195`) decides whether to
emit the OP_RETURN witness commitment based on a `hasWitnessCommitment` bool
that scans the 32-byte commitment for any non-zero byte. The caller
(`buildBlockTemplate:389-403`) sets `witnessCommitment = default(array)`
unless `hasSegwit == true`. So a block whose only segwit-aware tx is the
coinbase itself (no segwit non-coinbase txs) gets NO witness commitment.

**Failure mode:**

1. Mainnet height 500,000 (post-segwit-active).
2. Mempool is empty (or contains only non-segwit txs).
3. nimrod builds an empty block: `txList = []`, `hasSegwit = false`.
4. Coinbase has **no witness commitment**.
5. A Core peer receives the block via P2P. Core's `CheckWitnessMalleation`
   (validation.cpp:3870-3916) is called with `expect_witness_commitment =
   IsSegWitEnabled(...)`. Result: `bad-witness-nonce-size` / no-witness-commitment
   reject because Core expects the coinbase to carry one.

A Core node would reject the block; the nimrod miner produces an unrelayable
block that gets accepted into its own chainstate (cross-cite BUG-11).

**File:** `src/mining/blocktemplate.nim:178-195, 389-411`.

**Core ref:** `bitcoin-core/src/validation.cpp:3997-4019`
(`GenerateCoinbaseCommitment` unconditional);
`bitcoin-core/src/validation.cpp::IsWitnessEnabled` segwit-active gate.

**Excerpt (nimrod, conditional emission)**
```nim
# Check if we have a non-zero witness commitment
var hasWitnessCommitment = false
for b in witnessCommitment:
  if b != 0:
    hasWitnessCommitment = true
    break
# … later …
if hasWitnessCommitment:
  outputs.add(createWitnessCommitmentOutput(witnessCommitment))
```

The `hasWitnessCommitment` test is a workaround for "no segwit txs" — but
that's the wrong gate. The gate should be "is segwit active at this
height", which is `height >= params.segwitHeight` and is independent of
mempool content.

**Impact:** post-segwit-active blocks with no segwit non-coinbase txs are
unrelayable across Core peers; on a quiet mainnet hour with no segwit txs
(unusual but possible during congestion-free periods) the miner produces a
block that the entire Core-running network rejects.

---

## BUG-5 (P0-CDIV) — CVE-2012-2459 mutation flag not surfaced from `computeMerkleRoot`

**Severity:** P0-CDIV. Bitcoin Core's `ComputeMerkleRoot`
(`consensus/merkle.cpp:46-63`) returns the merkle root AND sets an out-param
`bool& mutated` flag when the input vector contains an odd-leaf duplication
pattern (CVE-2012-2459). The miner's `BlockMerkleRoot`/`BlockWitnessMerkleRoot`
wrappers propagate this; `IsBlockMutated` checks the flag and refuses to
build/accept mutated blocks.

nimrod's `hashing.computeMerkleRoot` (called from `blocktemplate.nim:436`)
does NOT surface a mutation flag. The miner can therefore unknowingly
produce a mutated merkle tree (e.g., if the mempool selection picks a
duplicate-txid set due to a stale entry). The mutated block would propagate
and be accepted by old peers but rejected by modern peers — chain-split
candidate identical in shape to W143 BUG and W142 BUG-1 (the same gap on
the validation side).

**File:** `src/mining/blocktemplate.nim:431-436` (merkle build),
`src/crypto/hashing.nim` (no mutation flag exported).

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63`
(mutation-detecting merkle root); `bitcoin-core/src/validation.cpp:4027-4056`
(`IsBlockMutated`).

**Impact:** miner-side counterpart of W143 BUG `CVE-2012-2459 mutated-flag
plumbing`. Same chain-split shape. **6+ impls confirm CVE-2012-2459
mutation detection missing fleet-wide** (per memory MEMORY.md May 18
quad-audit aggregate); this is the nimrod-miner-side instance.

---

## BUG-6 (P0-CDIV) — `updateTimestamp` ignores BIP-94 `MAX_TIMEWARP` on diff-adjustment blocks (every network)

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`miner.cpp:36-47`) raises the floor to
`max(prevMTP+1, pindexPrev->GetBlockTime() - MAX_TIMEWARP)` on
`height % difficulty_adjustment_interval == 0` blocks **on every network**.
The comment is explicit: "Account for BIP94 timewarp rule on all networks.
This makes future activation safer." Core enforces this in the miner even
where the consensus rule (`ContextualCheckBlockHeader`) only enforces it
on `enforceBIP94 == true` networks (testnet4, regtest with the flag).

nimrod's `updateTimestamp` (`blocktemplate.nim:489-517`) computes:

```nim
let minTime = if prevBlockMtp > 0: prevBlockMtp + 1 else: 0'u32
let newTime = max(minTime, now)
tmpl.header.timestamp = newTime
```

No `pindexPrev->GetBlockTime() - MAX_TIMEWARP` floor; no per-height check.
On testnet4 (where BIP-94 IS consensus-enforced via `enforceBIP94 = true`),
a nimrod-mined diff-adjustment block whose timestamp is `< parent.timestamp
- 600` is INVALID and **the validation path will reject the block the miner
just built**. On mainnet, the same shape produces a block that Core (when
BIP-94 ships on mainnet) will reject as `time-timewarp-attack`.

Worse: `mineBlock` (`rpc/mining.nim:43`) doesn't call `updateTimestamp` at
all; it sets `tmpl.header.timestamp = uint32(getTime().toUnix())` directly.
The `prevMTP+1` floor is silently dropped. Same in `generateBlockWithTxs`
(`rpc/mining.nim:278, 303`).

**File:** `src/mining/blocktemplate.nim:489-517` (updateTimestamp has no
BIP-94); `src/rpc/mining.nim:43, 278, 303` (mineBlock paths skip
updateTimestamp entirely).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` (`GetMinimumTime`),
`bitcoin-core/src/node/miner.cpp:49-65` (`UpdateTime`).

**Impact:**
- testnet4 mining on a diff-adjustment height: the miner builds an invalid
  block (`time-timewarp-attack`). BUG-11 lets the block into the local
  chainstate; the relay fails; the node is stuck.
- mainnet post-BIP-94-activation: same shape.
- The wall-clock-only path in `mineBlock` skips the `prevMTP+1` floor
  unconditionally; on regtest with a fast-forwarded mock time before the
  block is mined, the timestamp can be < `prevMTP+1`, producing a block
  `validateBlockHeader` would reject as `veBadTimestamp`.

---

## BUG-7 (P0-CDIV) — `generateBlockWithTxs` hardcodes nVersion = 0x20000000 (two-pipeline guard, 19th distinct extension)

**Severity:** P0-CDIV. `buildBlockTemplate` (`blocktemplate.nim:459-467`)
correctly computes `blockVersion = computeBlockVersion(deployments,
prevHash, getBlockIndexFn, getMtpFn, vbCaches)` via the BIP-9
versionbitscache — emits the top 3 bits as `001` plus any STARTED /
LOCKED_IN deployment bits.

`generateBlockWithTxs` (`rpc/mining.nim:275`) hardcodes:

```nim
var header = BlockHeader(
  version: 0x20000000,
  prevBlock: chainState.bestBlockHash,
  …
)
```

`0x20000000` is the BIP-9 top-bits alone — NO deployment bits. A regtest
test that exercises a BIP-9 deployment (e.g., a TestSequenceLock script
that gates on CSV signaling) will see GBT (`buildBlockTemplate`) signal a
bit while `generateblock` (`generateBlockWithTxs`) does NOT. The block is
otherwise identical, so the test exercises a different code path on each
miner entry-point.

**Fleet pattern:** this is the **19th distinct two-pipeline-guard finding**
in nimrod tracking (per MEMORY.md aggregate W76+; previous nimrod
two-pipeline finding was W143 `--reindex` paths). First time the
two-pipeline split is in MINER block-version derivation.

**File:** `src/rpc/mining.nim:275`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:140` (single source of nVersion
via `ComputeBlockVersion`).

**Impact:**
- Regtest BIP-9 deployment tests give different results depending on which
  RPC mined the block (GBT vs generateblock).
- A signet network configured with custom BIP-9 deployments would have
  miner-built blocks fail signet-block-solution if the missing bit is in the
  challenge.

---

## BUG-8 (P1) — `encodeBip34Height` height==0 latent divergence; height<0 returns OP_0 instead of CScriptNum-of-negative

**Severity:** P1. The encoder at `blocktemplate.nim:90-110` has two
divergences from Core's `CScript() << int64_t(nHeight)` that are latent
(not triggered today, but break under future use):

1. `height == 0`: nimrod returns `@[0x00'u8]` (literal byte 0x00, which
   happens to be OP_0). Core's `CScript()::operator<<(int64_t)` for 0 calls
   `push_int64(0)` which goes through `CScriptNum::serialize(0)` → empty
   array → emitted as `OP_0` (the opcode 0x00). The OUTPUT byte string
   matches by coincidence, but the SEMANTIC route differs. Caller
   `createCoinbaseTx` adds 8 zero extranonce bytes regardless, so the final
   scriptSig is `[0x00, 0x00 * 8] = 9 bytes`, which exceeds the 2-byte
   minimum.

2. `height < 0`: nimrod returns `@[0x00'u8]` (treats negative as zero). Core's
   `int64_t(-h)` for `h<0` would go through the `push_int64` path with a
   sign-bit-set CScriptNum encoding. Caller guarantees `height >= 0`
   (`createCoinbaseTx:154` declares `height: int32`; the wrapper
   `chainState.bestHeight + 1` is `int32 + 1` so genesis case is `0`), so
   this is latent.

The real risk is the BIP-34 round-trip: `validateCoinbase` (`validation.nim:340`)
calls `encodeBip34Height(height)` to build the expected prefix. If a peer
sends a block where coinbase scriptSig starts with `CScript() << 17 = [0x01,
0x11]` (push 1-byte 0x11), nimrod's `encodeBip34Height(17)` returns
`[0x01, 0x11]` — matches. If a peer sends `CScript() << 128 = [0x02, 0x80,
0x00]` (push 2-byte 0x80 0x00 with sign-extension), nimrod's
`encodeBip34Height(128)` returns `[0x02, 0x80, 0x00]` — matches. Spot-check
passes for the heights tested.

The latent risk is on the encoder reuse pattern: if a future caller (e.g.,
a wallet building a coinbase locally for testing) passes a signed
`int32(-1)`, the encoder silently returns `@[0x00'u8]` instead of a CScriptNum
encoding of `-1`. The validator-side `validateCoinbase` then uses the same
broken encoder and they agree on a wrong value.

**File:** `src/mining/blocktemplate.nim:90-110`.

**Core ref:** `bitcoin-core/src/script/script.h:433-448`
(`CScript::push_int64`), `script/script.h::CScriptNum::serialize`.

**Impact:** latent. Catalogued because the encoder is shared with the
validator path; an asymmetric fix on one side would silently diverge.

---

## BUG-9 (P1) — GBT `weightlimit` reports consensus cap not template cap

**Severity:** P1. Bitcoin Core's `getblocktemplate` `weightlimit` field
emits `template->nBlockMaxWeight` (the **policy** cap that drove block
construction; usually equal to consensus `MAX_BLOCK_WEIGHT` but can be
lower under `-blockmaxweight=N`). External miners (cgminer, mining proxies,
Stratum-V2 templates) sanity-check this against their own constructed
extranonce-rolled coinbase weight; if `weightlimit` reports the consensus
cap while the real template was clamped lower, the miner can build a
template that's correct for them but oversized for nimrod.

nimrod's `handleGetBlockTemplate` (`server.nim:3658`) emits
`rpc.params.maxBlockWeight` — the consensus cap, always 4_000_000. If BUG-1
is fixed (adding `-blockmaxweight`), this field will still report consensus
cap until separately fixed.

**File:** `src/rpc/server.nim:3658`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` ("weightlimit"
emission uses `pblocktemplate->block.GetTotalWeight()` … or the policy max,
depending on whether the template was clamped).

**Impact:** future operator override of `-blockmaxweight` won't be visible
in GBT response; mining tooling sees stale consensus cap.

---

## BUG-10 (P2) — GBT `sizelimit` hardcoded as 4_000_000 instead of `MAX_BLOCK_SERIALIZED_SIZE` constant

**Severity:** P2. `server.nim:3657` emits `"sizelimit": 4000000`. This is
the correct **post-segwit** serialized-with-witness cap, but it's hardcoded
as a literal integer. There is no `MaxBlockSerializedSize` constant in
`consensus/params.nim`. If the consensus rule ever ships at a different
size (`MAX_BLOCK_SERIALIZED_SIZE` is currently `4_000_000` in
`bitcoin-core/src/consensus/consensus.h:24` but is conceptually distinct
from `MAX_BLOCK_WEIGHT`), nimrod's GBT response will not track.

**File:** `src/rpc/server.nim:3657`.

**Impact:** cosmetic; constant magnet for stale-literal regression.

---

## BUG-11 (P0-CONS) — `generatetoaddress` / `generateblock` / `generatetodescriptor` BYPASS consensus pipeline (third nimrod entry point, three-pipeline drift)

**Severity:** P0-CONS. Bitcoin Core's `generateBlocks` (`rpc/mining.cpp`)
routes the mined block through `ProcessNewBlock`, which runs `CheckBlock →
AcceptBlockHeader → AcceptBlock (ContextualCheckBlock) → ConnectBlock`.
There is no "miner fast path" that skips validation.

nimrod's `mineBlock` (`rpc/mining.nim:75-108`), `generateBlocks` (line 75-108),
`generateToAddress` (line 110-133), `generateToDescriptor` (line 135-161),
and `generateBlockWithTxs` (line 163-321) ALL call
`chainState.connectBlock(blk, height)` DIRECTLY (lines 101, 313).

`connectBlock` (`chainstate.nim:739-908`) is the state-mutation primitive
that ONLY does:
- bestBlockHash-extends-tip precondition (line 755-758),
- per-input coinbase-maturity check (line 820-836),
- UTXO mutation (delete spent, add created),
- undo data write,
- best-block pointer update.

It does NOT call:
- `checkBlock` (PoW, merkle root, tx sanity, coinbase scriptSig length,
  `CheckTransaction` for non-coinbase, witness commitment context-free check)
- `validateBlock` (weight ≤ maxBlockWeight, sigops ≤ 80_000, BIP-34 coinbase
  height encoding, MTP timestamp lower bound, BIP-94 timewarp, BIP-66/65/34
  version, coinbase output ≤ subsidy + fees, MoneyRange, IsFinalTx per tx,
  witness commitment context-aware check)
- `checkBip30` (CVE-2012-1909 duplicate-coinbase check at BIP-30 grandfather
  heights 91842, 91880)
- `verifyScripts` (per-input script execution)

**The miner is therefore the THIRD ENTRY POINT in nimrod that bypasses
consensus.** Per MEMORY.md W143 BUG-3, the IBD `--reindex` paths
(`nimrod.nim:1611+, 1780+`) are the first two; per W145 BUG-1 the same
paths bypass subsidy/MoneyRange. **Three-pipeline drift (NEW finding for
nimrod)** — this is the first nimrod 3-pipeline gap; previous waves
reported 2-pipeline.

**Failure modes:**

1. **Overweight block accepted locally, rejected by peers.** A miner that
   accidentally selects too many txs (e.g., BUG-3 above produces a child
   without parent → block still respects weight cap but is structurally
   invalid; or a future bug in `selectTransactionsForBlock` produces a 5MB
   block) sees the block accepted into chainstate (no
   `weight ≤ maxBlockWeight` check). Peers reject with `bad-blk-length`;
   node is stuck on the forked tip.

2. **Invalid coinbase value accepted locally.** A future bug or hostile
   `coinbaseScript` (e.g., a 21M-BTC OP_RETURN output) produces a block
   with coinbase value > subsidy + fees. `validateBlock:1440` would
   reject with `veBadAmount` ("bad-cb-amount"); `connectBlock` does not run
   it. Block accepted locally, rejected on relay.

3. **Mutated merkle (CVE-2012-2459) accepted locally.** Cross-cite BUG-5;
   the miner builds, the validator never runs.

4. **CVE-2018-17144 (duplicate inputs in same tx) accepted locally.** A
   manually-crafted `coinbase` or any tx via `generateBlockWithTxs` with
   duplicate `(txid, vout)` in its inputs is accepted by `connectBlock`
   (which only does per-input lookup; doesn't dedupe). `validateBlock` /
   `checkTransaction` would reject; bypassed.

5. **BIP-34 height-encoding violation accepted locally.** Coinbase
   scriptSig that doesn't start with `encodeBip34Height(height)` would be
   rejected by `validateCoinbase`; not called.

**Cross-cite W143 BUG-3** (IBD reindex bypass) and **W145 BUG-1**
(reindex CVE-2018-17144 + MoneyRange + subsidy bypass). The miner path is
strictly worse than the reindex path: reindex processes ATTACKER-supplied
blocks (untrusted, third-party); the miner produces SELF-CONSTRUCTED blocks
that the operator believes are valid. The expectation of correctness is
higher.

**File:** `src/rpc/mining.nim:75-108, 110-133, 135-161, 163-321` (every
mining entry point);
`src/storage/chainstate.nim:739-908` (`connectBlock` as the only validation).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateBlocks`,
`bitcoin-core/src/validation.cpp::ProcessNewBlock`.

**Excerpt (nimrod, direct connect)**
```nim
# rpc/mining.nim:75
proc generateBlocks*(
  chainState: var ChainState,
  ...
): seq[BlockHash] =
  for i in 0 ..< nblocks:
    let blockOpt = mineBlock(chainState, mempool, params, coinbaseScript, maxTries)
    if blockOpt.isNone:
      break
    let blk = blockOpt.get()
    ...
    let height = chainState.bestHeight + 1
    let connectResult = chainState.connectBlock(blk, height)   # <-- BYPASSES ACCEPTBLOCK
    if not connectResult.isOk:
      break
```

Compare `handleSubmitBlock` (`server.nim:3681-3793`) which correctly routes
`checkBlock → acceptBlock(skipScripts, checkPow=false, getUtxo) →
connectBlock`. The asymmetry IS the bug.

**Impact:** the local node can be forked off the canonical chain by its
OWN block-generation RPC. Operators who use `generatetoaddress` for
testing on private testnets will see local-chain divergence from the
relayed-block-validation pipeline. **Three-pipeline drift extends the
two-pipeline guard pattern, first nimrod instance.**

---

## BUG-12 (P0-SEC, CARRY-FORWARD W143 BUG-2 / W145 BUG-5) — Coinbase int64 overflow in `createCoinbaseTx`; subsidy + fees uses raw `Satoshi` borrow

**Severity:** P0-SEC. Cross-cite W143 BUG-2 ("coinbase output overflow in
`validateBlock`") and W145 BUG-5 ("coinbase int64 accumulator wraps before
> compare"). Same shape on the miner construction side:

`createCoinbaseTx` (`blocktemplate.nim:185-191`) builds the coinbase output as:

```nim
outputs.add(TxOut(
  value: subsidy + fees,
  scriptPubKey: scriptPubKey
))
```

`subsidy` is `Satoshi` (int64 distinct type with `+` borrow). `fees` is
`Satoshi` (accumulated from `entry.fee` in `buildBlockTemplate:383`
via `totalFees = totalFees + entry.fee`). The `{.borrow.}` operator inherits
Nim's int64 semantics: wraparound on overflow, no trap.

With `subsidy = 5_000_000_000` (50 BTC at height 0) and `fees` accumulated
from arbitrary mempool entries (no MoneyRange check on the sum, per W145
audit), the addition can wrap if `fees > int64.max - subsidy`. The wrapped
negative value becomes the coinbase `value`, which:
- in `validateBlock:1440`, the comparison `coinbaseValue > int64(subsidy) +
  totalFees` is between two int64 values; both can wrap; the comparison can
  be false even though the actual sum is overflowed.
- in `connectBlock` (which is what the miner actually runs, per BUG-11),
  there IS no validation; the wrapped value goes straight into the UTXO set.

The mempool admission path does cap individual fees via fee-rate checks,
but the SUM has no cap. An adversary submitting 80_000 sigops worth of
"high fee" txs (one near the per-tx max) can push the sum near `int64.max`.

**File:** `src/mining/blocktemplate.nim:185-191, 383, 426`;
`src/mempool/mempool.nim:1504-1527` (entry.fee sum has no overflow guard).

**Core ref:** `bitcoin-core/src/validation.cpp:2543-2547`
(`bad-txns-accumulated-fee-outofrange`); `bitcoin-core/src/node/miner.cpp:178`
(`block_reward = nFees + GetBlockSubsidy(...)`).

**Impact:** miner can be tricked into building an overflow-coinbase block.
Local acceptance via BUG-11; relayed rejection. Companion to W143 BUG-2 /
W145 BUG-5; the bug crosses validator AND miner sides — fix must touch both.

---

## BUG-13 (P1, CARRY-FORWARD W141 BUG-8 / W153 BUG-1) — `getmininginfo.blockmintxfee` hardcoded; will not echo any future `-blockmintxfee` operator knob

**Severity:** P1. W141 BUG-8 / W153 BUG-1 (open 5+ weeks across 5 audits)
flagged that nimrod's mempool `getmempoolinfo.mempoolminfee` divisor is
1000× too low. The miner-side echo is `getmininginfo.blockmintxfee`,
which Core derives from `BlockAssembler::m_options.blockMinFeeRate.GetFeePerVSize()`.

nimrod's `handleGetMiningInfo` (`server.nim:4449`) hardcodes:

```nim
resp["blockmintxfee"] = %0.00001000
```

Two issues:
1. **Hardcoded value:** any future `-blockmintxfee=N` flag (the obvious
   next-step paired with BUG-1's `-blockmaxweight`) will be ignored here.
2. **No mempool-side derivation:** Core's value comes from the assembler's
   actual `blockMinFeeRate`, NOT from a CLI default. The mempool minimum
   admission floor (`mp.minFeeRate`) is independent. Reporting a fixed
   `0.00001000` while the mempool floor is rolling (after eviction events)
   gives external miners misleading information for fee estimation.

The W141 / W153 mempool divisor regression has the same shape: a hardcoded
or wrongly-converted unit makes external tooling read a 1000× wrong value.

**File:** `src/rpc/server.nim:4449`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getmininginfo` (emits
`blockMinFeeRate.GetFeePerVSize()`).

**Impact:** stale literal; downstream mining tooling reads a constant
instead of the actual mining-floor. Composes with W141 / W153 mempool-side
divisor regression for cumulative misreport.

---

## BUG-14 (P2) — `m_last_block_weight` / `m_last_block_num_txs` not surfaced

**Severity:** P2. Bitcoin Core surfaces `BlockAssembler::m_last_block_weight`
and `m_last_block_num_txs` as static `std::optional` fields
(`miner.h:96-99`). External miners read these via the `getmininginfo` RPC
fields `currentblockweight` and `currentblocktx`. nimrod's
`handleGetMiningInfo` (`server.nim:4443-4445`) hardcodes:

```nim
resp["currentblocksize"]   = %0
resp["currentblockweight"] = %0
resp["currentblocktx"]     = %0
```

Always 0. External miners that graph their template-fill rate over time
see a flat zero line. Cosmetic / observability gap.

**File:** `src/rpc/server.nim:4443-4445`.

**Core ref:** `bitcoin-core/src/node/miner.h:96-99`.

**Impact:** observability; no operator can tell from RPC alone how full
the last mined template was.

---

## BUG-15 (P1) — `mineBlock` ignores `updateTimestamp`; bypasses both MTP+1 floor and BIP-94 floor

**Severity:** P1 (specific shape of BUG-6, separately catalogued because
it's an entry-point gap not a primitive gap). `mineBlock`
(`rpc/mining.nim:42-43`) sets:

```nim
# Update timestamp
tmpl.header.timestamp = uint32(getTime().toUnix())
```

This is wall-clock unconditional. It does NOT call `updateTimestamp`,
which is the only place the `prevBlockMtp + 1` floor is enforced (and even
that does so only when caller passes `prevBlockMtp > 0`; the default arg
is 0 — see BUG-6).

Failure mode: regtest test that fast-forwards mock-time (or any environment
where wall-clock has drifted backwards) produces a block whose timestamp
is < `prevBlock.MTP + 1`. The block is locally accepted (BUG-11) but
rejected by any peer running `validateBlockHeader` → `veBadTimestamp`.

**File:** `src/rpc/mining.nim:42-43, 277-278, 302-303`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:219` (`UpdateTime` always
called in `CreateNewBlock`).

**Impact:** wall-clock-only timestamps in mineBlock; local node forks off
canonical chain when wall-clock < prevMTP+1.

---

## BUG-16 (P1) — `RegtestBits` (0x207fffff) constant duplicated between `mining.nim` and `params.nim`; mining override bypasses chain `getNextWorkRequired`

**Severity:** P1. `rpc/mining.nim:20` defines `RegtestBits = 0x207fffff'u32`.
`params.nim:472` sets `result.genesisBits = 0x207fffff'u32` for regtest.
Two constants, same value.

`mineBlock` (`rpc/mining.nim:38-40`):

```nim
if params.powNoRetargeting:
  tmpl.header.bits = RegtestBits
  tmpl.target = computeTarget(RegtestBits)
```

This OVERRIDES whatever `buildBlockTemplate` computed via the chain's
`getNextWorkRequired`. On regtest, `params.powNoRetargeting = true`, so
this fires always. The override means regtest test cases that **want** to
exercise `getNextWorkRequired`'s code path (e.g., a test that sets up a
custom regtest with `powNoRetargeting=false`) see the miner ignore the
chain rule. Also: `generateBlockWithTxs` does the same (line 270-271) but
in a DIFFERENT shape — sets `bits = RegtestBits` only if `powNoRetargeting`,
otherwise uses `params.genesisBits` (also 0x207fffff at regtest config).
Either way, both paths bypass `getNextWorkRequired`.

Core relies on `UpdateTime` calling `pblock->nBits =
GetNextWorkRequired(pindexPrev, pblock, consensusParams)`
(`miner.cpp:220`) — the single source of truth for nBits even on regtest.

**File:** `src/rpc/mining.nim:20, 38-40, 270-271`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:220`.

**Impact:** duplicate constant; bypass of chain rule on regtest; test
coverage gap.

---

## BUG-17 (P1) — `mine` (in `blocktemplate.nim:560`) does not update timestamp on nonce-exhaustion; CPU mining can loop forever past a wrap

**Severity:** P1. Bitcoin Core's standard mining loop (and every external
miner) updates `pblock->nTime` whenever the nonce space is exhausted
without finding a valid hash. nimrod's `mine` (`blocktemplate.nim:560-568`)
iterates the nonce space:

```nim
proc mine*(tmpl: var BlockTemplate, maxIterations: uint32 = 0xffffffff'u32): bool =
  for nonce in 0'u32 ..< maxIterations:
    tmpl.header.nonce = nonce
    let headerBytes = serialize(tmpl.header)
    let hash = doubleSha256(headerBytes)
    if hashMeetsTarget(hash, tmpl.target):
      return true
  false
```

No timestamp update on `nonce` exhaustion. Real mainnet difficulty makes
this unreachable for `maxIterations = 0xffffffff` — the entire nonce space
exhausts in ~4 seconds at modern hashrate, but mainnet would not find a
solution within it. Returning `false` is correct as long as the caller
re-invokes `mine` after refreshing `tmpl.header.timestamp` — but no caller
does (`handleGetBlockTemplate` returns the template to an external miner;
the regtest `generateBlocks` uses `mineBlock` not `mine`, and `mineBlock`
does have a timestamp refresh on wrap, line 70-71).

Cosmetic / unused in practice; flagged because the proc IS exported (`mine*`)
and a future external caller (Nim-based CPU miner script) would loop
forever on mainnet.

**File:** `src/mining/blocktemplate.nim:560-568`.

**Core ref:** Core's mining loop (older versions; modern Core delegates to
external miners and only does CPU mining in tests).

**Impact:** dead-code / unused export hazard; future caller risk.

---

## BUG-18 (P1) — `RegenerateCommitments`-equivalent absent; no helper to re-derive coinbase commitment + merkle root after external tx mutation

**Severity:** P1. Bitcoin Core's `RegenerateCommitments`
(`miner.cpp:67-77`) is a public helper used by tests and proposal-mode
miners to (a) erase the existing witness-commitment output, (b) re-run
`GenerateCoinbaseCommitment`, (c) recompute `hashMerkleRoot`. nimrod has
no equivalent. `updateExtraNonce` (`blocktemplate.nim:524-549`)
recomputes the merkle root but does NOT re-derive the witness commitment.

A consumer that wants to mutate the template's transactions (e.g., a
test harness that swaps a tx in/out of the template before submitting via
BIP-22 proposal mode) has no clean API. The only option is to call
`buildBlockTemplate` from scratch, which throws away the assembler's work.

**File:** `src/mining/blocktemplate.nim` (no `regenerateCommitments` proc).

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77`.

**Impact:** missing API; test ergonomics. BIP-22 proposal flow can't be
tested cleanly without rebuilding the template.

---

## BUG-19 (P2) — `clampBlockOptions` silently clamps reservedWeight above maxWeight

**Severity:** P2. `clampBlockOptions` (`blocktemplate.nim:278-285`):

```nim
let clampedReserved = max(MinimumBlockReservedWeight, min(reservedWeight, MaxBlockWeight))
let clampedMax = max(clampedReserved, min(maxWeight, MaxBlockWeight))
```

If caller passes `reservedWeight = 10_000` and `maxWeight = 5_000`, the
result is `(10_000, 10_000)` — `maxWeight` is silently bumped UP to match
`reservedWeight`. Core's `ClampOptions` documents this as intentional
("block_reserved_weight can safely exceed -blockmaxweight, but the rest of
the block template will be empty"). nimrod's implementation matches Core
behaviour. **No bug here per se; flagged to confirm parity** — the
inline comment at `blocktemplate.nim:281-282` correctly describes the
behaviour.

P2 instead of PASS because the operator-visible message is silent — there
is no log line if reservedWeight ends up exceeding maxWeight. Core also
doesn't log, but Core has the `-blockmaxweight` knob to surface the
behaviour through CLI defaults; nimrod has neither (cross-cite BUG-1).

**File:** `src/mining/blocktemplate.nim:278-285`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:79-88`.

**Impact:** cosmetic; logged for parity-trace.

---

## BUG-20 (P1) — `estimateTxSigops` undercounts (P2SH heuristic, BIP-141 witness-sigops absent)

**Severity:** P1. The miner's per-tx sigops estimator
(`blocktemplate.nim:234-270`) is a heuristic on output script shapes:

```nim
# P2SH: assume 1 sigop (conservative)
elif script.len == 23 and script[0] == 0xa9:  # OP_HASH160
  sigops += 1
```

The comment says "conservative" but a P2SH redeem-script can contain up
to `MAX_BLOCK_SIGOPS_COST / 4 = 20_000` legacy sigops post-execution
(witness-discounted to 5000 cost per tx). A real `GetTransactionSigOpCost`
(`validation.nim:1346`) accounts for legacy + P2SH + witness sigops scaled
by `WitnessScaleFactor`. The miner's heuristic massively undercounts P2SH,
P2WSH, and Taproot script-path-spend sigops.

Consequence: a block selected by `selectTransactionsForBlock` may pass the
miner's per-tx `estimateTxSigops` sum check (`blocktemplate.nim:364`) yet
exceed `MaxBlockSigopsCost` when computed correctly. The miner constructs
an overweight-sigops block; `validateBlock` rejects with `veSigopExceeded`
("bad-blk-sigops"); per BUG-11 this is only seen on relay.

**File:** `src/mining/blocktemplate.nim:234-270`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:143-162`
(`GetTransactionSigOpCost`).

**Impact:** miner builds blocks with hidden sigops violations; relay
rejection; chain stall (per BUG-11 path).

---

## BUG-21 (P1) — `coinbasevalue` GBT field has no MoneyRange clamp; can be reported as wrapped negative

**Severity:** P1. `server.nim:3651`:

```nim
"coinbasevalue": int64(tmpl.totalFees) + int64(getBlockSubsidy(int32(tmpl.height), rpc.params)),
```

`tmpl.totalFees` is `Satoshi` (int64 distinct). `getBlockSubsidy` returns
`Satoshi`. The `int64(...) + int64(...)` works on raw int64s, but there is
NO MoneyRange clamp — if `tmpl.totalFees` is overflow-wrapped (cross-cite
BUG-12), the JSON response contains a negative number. External miners
that parse this as a CFeeAmount panic.

**File:** `src/rpc/server.nim:3651`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
"coinbasevalue" emission uses `pblocktemplate->m_coinbase_tx.block_reward_remaining`
which is bounded.

**Impact:** RPC JSON contract can emit negative satoshi; downstream
tooling panics or silently propagates the wrap.

---

## BUG-22 (P1) — `handleGenerateToAddress` updates fee estimator with EMPTY confirmed-txids list

**Severity:** P1. `server.nim:4017-4021`:

```nim
# Update fee estimator for each block
if rpc.feeEstimator != nil:
  for i, hash in hashes:
    let height = rpc.chainState.bestHeight - int32(hashes.len - 1 - i)
    # Get confirmed txids (simplified - just mark block processed)
    rpc.feeEstimator.processBlock(height, @[])
```

`processBlock(height, @[])` decays the bucket stats but records ZERO
confirmations. Mining blocks normally DO confirm txs (drawn from mempool).
The fee estimator's "block N just landed with these txids" event is
dropped on the floor for regtest mining; downstream `estimatesmartfee`
output is rotten by N decay passes per block without any confirmation
counter increment.

The comment "simplified - just mark block processed" is **comment-as-confession**
(**8th distinct nimrod instance** per MEMORY.md aggregate; previous nimrod
confession was W143 inline comment). The handler builds the mined block,
knows the txs that were included (would need to call
`mempool.removeForBlock` introspectively or read `tmpl.transactions` and
filter), but skips that work.

**File:** `src/rpc/server.nim:4017-4021`.

**Core ref:** `bitcoin-core/src/policy/fees.cpp::CBlockPolicyEstimator::processBlock`
called with full confirmed-tx list.

**Impact:** fee estimator decays correctly but never records confirmations
on regtest mining; estimatesmartfee output unusable after regtest mining
session.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CONS:** 2 (BUG-3 child-before-parent in template, BUG-11 miner
  bypasses consensus pipeline — same fleet-wide pattern as W143 BUG-3 +
  W145 BUG-1 for IBD-reindex; this is the THIRD nimrod entry point that
  bypasses, i.e. **three-pipeline drift**, first nimrod instance).
- **P0-CDIV:** 4 (BUG-5 CVE-2012-2459 mutation flag absent, BUG-6 BIP-94
  not enforced at mining time on diff-adjustment blocks across all
  networks, BUG-7 generateBlockWithTxs hardcoded nVersion two-pipeline
  guard, BUG-4 unconditional witness commitment missing).
- **P0-SEC:** 1 (BUG-12 coinbase int64 overflow in `createCoinbaseTx`;
  carry-forward W143 BUG-2 / W145 BUG-5).
- **P1:** 12 (BUG-1, BUG-2, BUG-8, BUG-9, BUG-13, BUG-15, BUG-16, BUG-17,
  BUG-18, BUG-20, BUG-21, BUG-22).
- **P2:** 3 (BUG-10, BUG-14, BUG-19).

**Fleet patterns confirmed:**
- **"Three-pipeline drift"** (BUG-11) — NEW for nimrod. The IBD-reindex
  paths (W143 BUG-3), the IBD-reindex CVE-2018-17144 path (W145 BUG-1),
  and now the miner block-generation path all bypass `acceptBlock`. First
  nimrod 3-pipeline finding; extends previous 2-pipeline tracking.
- **"Two-pipeline guard, 19th distinct extension"** (BUG-7) — first time
  the split is in miner block-version derivation. GBT path uses
  `computeBlockVersion`; regtest `generateBlock` path hardcodes 0x20000000.
- **"Comment-as-confession, 8th nimrod instance"** (BUG-22) — server.nim
  comment "simplified - just mark block processed" admits the fee-estimator
  hook is incomplete.
- **"Carry-forward int64 overflow"** (BUG-12) — W143 BUG-2 + W145 BUG-5
  both apply to the miner-construction side, not just the validator side;
  same `Satoshi + Satoshi` borrow without overflow trap; the miner side is
  STRICTLY WORSE because the miner CONSTRUCTS the overflow rather than
  validating one.
- **"Carry-forward mempoolminfee divisor regression"** (BUG-13) — W141
  BUG-8 / W153 BUG-1 open since W138 (5+ weeks across 5 audits). Mining
  side's `getmininginfo.blockmintxfee` is hardcoded, will not echo any
  future `-blockmintxfee` operator knob.
- **"Asymmetric pipeline drift between regtest mining RPCs and BIP-22
  submitblock"** (BUG-11) — `submitblock` routes through `acceptBlock`
  correctly; `generatetoaddress`/`generateblock` bypass it. The asymmetry
  is the bug.
- **"Dead-data plumbing"** (BUG-14 `m_last_block_weight` absent, BUG-18
  RegenerateCommitments absent, BUG-2 `-blockreservedweight` knob absent)
  — three primitives Core exposes that nimrod's miner doesn't.
- **"Hardcoded constant where Core has operator knob"** (BUG-1
  `-blockmaxweight`, BUG-2 `-blockreservedweight`, BUG-13
  `-blockmintxfee`).
- **"Bypass of canonical pipeline by entry point added later"** (BUG-11)
  — `generatetoaddress` postdates `submitblock`; the canonical pipeline
  exists, the new entry didn't wire to it.

**Top three findings:**

1. **BUG-11 (P0-CONS three-pipeline drift)** — every regtest mining RPC
   (`generatetoaddress`, `generateblock`, `generatetodescriptor`,
   `generateBlockWithTxs`) routes its mined block through
   `chainState.connectBlock` DIRECTLY, bypassing the full consensus
   pipeline (`checkBlock`, `validateBlock`, `checkBip30`, `verifyScripts`).
   This is the THIRD nimrod entry point that bypasses (after W143 BUG-3
   and W145 BUG-1 for IBD-reindex); first nimrod three-pipeline drift.
   The miner can produce blocks that the local node accepts but the
   relay-validation pipeline (and any Core peer) rejects — chain stalls
   on a fork until manual `invalidateblock`. **Bundle fix:** add a single
   helper `acceptAndConnectMinedBlock` in `chainstate.nim` that runs
   `checkBlock + acceptBlock + connectBlock` together and have all four
   mining entry points call it. ~10 LOC. Fixes BUG-11 + indirectly closes
   BUG-3 (child-before-parent block is rejected at `bad-txns-inputs-
   missingorspent`), BUG-4 (missing witness commitment is rejected at
   `bad-witness-merkle-match`), BUG-5 (mutated merkle is rejected via the
   `IsBlockMutated` step in `checkBlock` if that is also fixed), BUG-6
   (timewarp is rejected at `time-timewarp-attack`), BUG-7 (wrong nVersion
   is rejected at `bad-version` per `contextualCheckBlockHeader`), BUG-12
   (overflow coinbase is rejected at `veBadAmount`).

2. **BUG-3 (P0-CONS child-before-parent in template)** —
   `getTransactionsByFeeRate` sorts INDIVIDUAL mempool entries by
   ancestor-feerate then accepts them one-by-one without topological
   guard. A CPFP child (high ancestor-feerate, low individual feerate) is
   enumerated before its parent (low ancestor-feerate) and accepted while
   the parent might be skipped. Result: block with child-before-parent or
   child-without-parent — both violate consensus. Core uses
   `GetBlockBuilderChunk` which pops entire CL-graph chunks in topological
   order. **Cross-fleet pattern:** the chunk-graph mempool selection is
   the same shape as the W129 "fleet-wide coin selection effective_value"
   issue but on the mempool side. **Fix:** add a `getBlockBuilderChunk`
   helper to mempool.nim that returns clusters in topological order; have
   the miner consume those, not the sorted-entries seq. Larger fix
   (~50 LOC mempool + ~30 LOC miner).

3. **BUG-12 + BUG-6 cluster (carry-forward P0-SEC overflow + P0-CDIV
   BIP-94)** — `createCoinbaseTx` builds the coinbase value as raw
   `Satoshi + Satoshi` borrow with no MoneyRange clamp; combined with BUG-11
   means an overflow-wrapped value goes straight to the UTXO set. Concurrent
   with BUG-6: the miner's timestamp logic doesn't account for BIP-94
   MAX_TIMEWARP on diff-adjustment heights across all networks (Core enforces
   this at mining time on every network for forward-compat with future
   mainnet BIP-94 activation). Both have the carry-forward shape (W143 +
   W145 already flagged the validator-side counterparts); this audit
   extends the finding to the miner-construction side. Fix BUG-11 first
   (this catches the overflow when ConnectBlock rejects); then add explicit
   MoneyRange clamps in `createCoinbaseTx` and `selectTransactionsForBlock`,
   then port `GetMinimumTime`'s BIP-94 floor into `updateTimestamp`.
