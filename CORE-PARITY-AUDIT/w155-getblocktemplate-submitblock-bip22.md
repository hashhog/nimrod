## W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (nimrod)

**Wave:** W155 — `getblocktemplate`, `submitblock`, `submitheader`,
`prioritisetransaction`, `getprioritisedtransactions`, `getmininginfo`,
BIP-22 / BIP-23 `template_request` (mode, capabilities, rules, longpollid,
data), template fields (version, rules[], vbavailable, vbrequired,
previousblockhash, transactions[], coinbaseaux, coinbasevalue, longpollid,
target, mintime, mutable[], noncerange, sigoplimit, sizelimit, weightlimit,
curtime, bits, height, signet_challenge, default_witness_commitment),
per-tx (data, txid, hash, depends, fee, sigops, weight),
`BIP22ValidationResult` string set, `UpdateUncommittedBlockStructures`,
proposal mode, longpoll wait-on-tip-change-or-mempool-update, signet rules
gate, GBT IBD/no-peers refusal.

**Scope:** discovery only — NO production code change in W155.
Concurrent-agent coordination: this is one of the W155 quad-audit sub-agents.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:587-603` — `BIP22ValidationResult(state)`:
  IsValid → null; IsError → JSONRPCError; IsInvalid + non-empty reason →
  `reason`; IsInvalid + empty → `"rejected"`. The canonical BIP-22 return
  shape for submitblock.
- `bitcoin-core/src/rpc/mining.cpp:606-613` — `gbt_rule_value(name, optional)`:
  prefixes rule name with `!` when NOT optional (per BIP-9). Determines
  whether a rule appears as `"!segwit"`, `"!signet"`, `"taproot"` etc. in
  the GBT rules[].
- `bitcoin-core/src/rpc/mining.cpp:615-1034` — full `getblocktemplate`
  pipeline:
  - `params[0]` is `template_request` OBJECT with `mode`, `capabilities`,
    `rules`, `longpollid`, `data` (proposal).
  - `mode == "proposal"` → DecodeHexBlk + TestBlockValidity + return
    `"duplicate"` / `"duplicate-invalid"` / `"duplicate-inconclusive"` /
    BIP22ValidationResult. Never returns a template in proposal mode.
  - `rules` MUST contain `"segwit"` else throws `RPC_INVALID_PARAMETER`.
    On signet chains `rules` MUST also contain `"signet"`.
  - `!miner.isTestChain()` branch: throws `RPC_CLIENT_NOT_CONNECTED`
    when peer count == 0, and `RPC_CLIENT_IN_INITIAL_DOWNLOAD` when in IBD.
  - longpoll wait loop (line 783-845): hashWatchedChain from `longpollid`
    (first 64 hex chars = tip hash, rest = `nTransactionsUpdatedLast`);
    wait up to 60s on first check then 10s intervals; release `cs_main`
    while waiting; break on tip change OR
    `mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP`.
  - static `pindexPrev`/`time_start`/`block_template` reused across calls
    (5-second cooldown for mempool-update rebuild; tip change forces
    rebuild immediately) — line 859-884.
  - `UpdateTime` (line 889) before serialising → `mintime` / `curtime` are
    BIP-94 timewarp aware via `GetMinimumTime` (miner.cpp:36-47).
  - `aMutable` is `["time", "transactions", "prevblock"]` (line 942-945).
  - `aCaps` is `["proposal"]` (line 895).
  - `vbavailable` walks `gbtstatus.signalling` + `gbtstatus.locked_in`
    via `gbt_rule_value` so `name` may be `!name` (non-optional rule). Also
    iterates `gbtstatus.active` to append final `aRules`.
  - per-tx entry (line 911-935): `data`, `txid` (display BE), `hash`
    (wtxid display BE), `depends` (array of 1-based template indices
    derived from `setTxIndex`), `fee`, `sigops` (divided by
    WITNESS_SCALE_FACTOR when `fPreSegWit`), `weight`.
  - `coinbasevalue = block.vtx[0]->vout[0].nValue` (line 1001) — reads
    THE COINBASE OUTPUT, not (subsidy + fees).
  - `longpollid = tip.GetHex() + ToString(nTransactionsUpdatedLast)` (line
    1002) — hex tip hash concatenated with the integer counter.
  - `noncerange = "00000000ffffffff"` (line 1006) — 8 hex bytes (LE), not 4.
  - `sigoplimit` / `sizelimit` divided by `WITNESS_SCALE_FACTOR` when
    `fPreSegWit` (line 1009-1014).
  - `weightlimit` ONLY emitted when `!fPreSegWit` (line 1017-1019).
  - `bits = strprintf("%08x", block.nBits)` — big-endian hex (line 1021).
  - `signet_challenge` emitted only on signet chains (line 1024-1026).
  - `default_witness_commitment` emitted ONLY when
    `coinbase.required_outputs.size() > 0` — i.e., only when the assembler
    placed a witness-commitment output. NOT unconditional.
- `bitcoin-core/src/rpc/mining.cpp:1038-1106` — `submitblock`:
  - **TWO arguments accepted**: `hexdata` (required) and `dummy` (BIP-22
    compatibility, ignored).
  - `chainman.UpdateUncommittedBlockStructures(block, pindex)` (line 1088)
    — for any block whose prev exists, repopulates witness reserved value
    + commitment in coinbase scriptWitness BEFORE ProcessNewBlock. This
    lets a miner submit a stripped-witness block and have it auto-fixed
    by the receiving node.
  - `submitblock_StateCatcher` validation-interface RAII: catches the
    `BlockChecked` callback ONLY for `block.GetHash()`.
  - Returns `"duplicate"` when `!new_block && accepted`.
  - Returns `"inconclusive"` when state-catcher never fired (e.g., block
    accepted but parked on a side-branch).
  - Otherwise `BIP22ValidationResult(state)`.
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`:
  refuses if prev unknown; calls `ProcessNewBlockHeaders` and surfaces
  `RPC_VERIFY_ERROR` on rejection.
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`:
  fields are `blocks`, `currentblockweight` (optional, only when
  `BlockAssembler::m_last_block_weight.has_value()`), `currentblocktx`
  (optional, same gate), `bits` (`%08x` BE hex), `difficulty`, `target`
  (display BE), `networkhashps`, `pooledtx`, `blockmintxfee` (BTC/kvB),
  `chain`, `signet_challenge` (only on signet), `next` object with
  `height`/`bits`/`difficulty`/`target`, `warnings` (ARRAY by default,
  STRING only with `-deprecatedrpc=warnings`). **No `currentblocksize`** —
  Core removed this field.
- `bitcoin-core/src/rpc/mining.cpp:502-545` — `prioritisetransaction`:
  3 args (`txid`, `dummy=0`, `fee_delta`); throws if `dummy != 0`;
  refuses when `require_standard && tx has dust output`; calls
  `mempool.PrioritiseTransaction(txid, fee_delta)`. Returns `true`.
- `bitcoin-core/src/rpc/mining.cpp:547-583` — `getprioritisedtransactions`:
  enumerates `mempool.GetPrioritisedTransactions()` returning a map of
  `{txid: {fee_delta, in_mempool, modified_fee?}}`.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`: `min_time =
  prevMTP + 1`; at diff-adjustment-interval heights also raises floor to
  `max(min_time, prevBlockTime - MAX_TIMEWARP)` — BIP-94 timewarp on every
  network.
- `bitcoin-core/src/validation.cpp::UpdateUncommittedBlockStructures` —
  inserts 32-zero witness reserved value into coinbase scriptWitness[0]
  before ProcessNewBlock when prev is known.

**Files audited**
- `src/rpc/server.nim:3576-3668` — `handleGetBlockTemplate` (GBT response
  shape, vbavailable, rules, default_witness_commitment, noncerange,
  sigoplimit, sizelimit, weightlimit, coinbasevalue, mintime, curtime,
  bits).
- `src/rpc/server.nim:3670-3679` — `bip22ChainError` (chainstate string
  → BIP-22 token map; substring-matching).
- `src/rpc/server.nim:3681-3970` — `handleSubmitBlock` (block-decode,
  checkBlock, acceptBlock, connectBlock; side-branch reorg path).
- `src/rpc/server.nim:4407-4460` — `handleGetMiningInfo` (fields, bits
  encoding, target, networkhashps, pooledtx, currentblocksize, warnings).
- `src/rpc/server.nim:4540-4542` — `help` table mining section (only 3
  RPCs listed).
- `src/rpc/server.nim:8333-8338` — RPC dispatch table mining section
  (only 3 mining RPCs wired).
- `src/consensus/validation.nim:108-169` — `bip22String` (ValidationError
  → BIP-22 token map; case-statement).
- `src/mining/blocktemplate.nim:287-487` — `buildBlockTemplate` (the
  upstream of GBT; templates have `header`, `transactions`, `totalFees`,
  `totalWeight`, `totalSigops`, `height`, `target`).
- `src/mining/blocktemplate.nim:112-138` — `computeWitnessCommitment`
  (used by GBT `default_witness_commitment` field).
- `src/rpc/mining.nim:1-321` — regtest mining RPCs (generate*,
  generatetoaddress, generatetodescriptor, generateblock — relevant
  insofar as they may bypass the BIP-22 submitblock pipeline; see W154
  BUG-11).
- `src/consensus/params.nim:88-95, 144-188, 280-291, 344-358, 406-419,
  465-476` — per-network `defaultPort`, `maxBlockWeight`,
  `subsidyHalvingInterval`, `powAllowMinDifficultyBlocks`. No
  `signet_challenge`, no `signetBlocks` field.

---

## Gate matrix (30 sub-gates / 18 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GBT `mode` argument | G1: `mode == "template"` (default) | PASS by accident — `params[0]` parsed only as `JObject` then `discard` (`server.nim:3582-3583`). No mode dispatch. |
| 1 | … | G2: `mode == "proposal"` runs `TestBlockValidity` | **BUG-1 (P0-CDIV)** — `mode` field IGNORED. Any caller passing `{"mode":"proposal","data":"<hex>"}` gets a regular template back instead of a proposal-acceptance test. Core returns `"duplicate"` / `BIP22ValidationResult(...)` strings; nimrod returns a template object. BIP-23 proposal mode is **completely non-functional**. |
| 2 | GBT `rules` validation | G3: `rules` MUST contain `"segwit"` else `RPC_INVALID_PARAMETER` | **BUG-2 (P0-CDIV)** — `rules` field IGNORED. nimrod returns a segwit-aware template regardless of client capability declaration. Pre-segwit-aware miners (theoretical edge case) would parse `default_witness_commitment` as junk. Core's strict gate exists precisely to refuse non-segwit miners templates with witness commitments they cannot understand. |
| 2 | … | G4: signet chain MUST receive `rules: ["segwit","signet"]` else throw | **BUG-3 (P1)** — no signet handling whatsoever in `handleGetBlockTemplate`. The `signet_challenge` and `signet` rule are silently omitted from the template even on a signet chain (`params.network == Signet` is recognized in `getmininginfo`'s `chainName` but never in GBT). Signet miners cannot ever build a valid block from the nimrod template — they need the challenge script to populate the signet block solution. |
| 3 | GBT IBD / no-peers gate | G5: refuse with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` when in IBD | **BUG-4 (P0-CDIV)** — handler runs unconditionally. A miner that pulls a GBT during IBD gets a template whose `previousblockhash` is the partially-synced tip, `coinbasevalue` is wrong (subsidy at a partial height), and `target` is stale. The miner builds and submits, the block is buried by a reorg as soon as IBD catches up. Core throws and the miner reacts. |
| 3 | … | G6: refuse with `RPC_CLIENT_NOT_CONNECTED` when no peers | **BUG-4 cross-cite** — no peer-count check. Same downstream effect: orphan blocks built against a stale tip. |
| 4 | GBT `longpollid` field | G7: present in response shape | **BUG-5 (P0-CDIV)** — `longpollid` is **NOT EMITTED** at all in the response object (`server.nim:3642-3668`). The entire BIP-22 long-polling protocol is dead — clients have nothing to send in subsequent requests. Even external miners that long-poll on tip change cannot do so. |
| 4 | … | G8: longpollid wait-loop accepts `lpval` and waits for tip change OR mempool update | **BUG-5 cross-cite** — no wait loop at all; handler returns immediately every time. |
| 4 | … | G9: `lpval` format = `<64hex tipHash><uint64 nTxUpdated>` | **BUG-5 cross-cite** — no parser; the parameter is ignored. |
| 5 | GBT `vbavailable` from versionbits | G10: walks `getDeployments(network)` STARTED + LOCKED_IN | PASS (`server.nim:3622-3637`) — this was fixed in an earlier wave (BUG-2 fix annotation). |
| 5 | … | G11: rule names prefixed `!` when non-optional (BIP-9) | **BUG-6 (P1)** — nimrod `vbavailableObj[dep.name] = %dep.bit` (line 3637) emits raw `dep.name`. Core's `gbt_rule_value(name, info.gbt_optional_rule)` prefixes with `!` when the rule is non-optional. Result: a Core miner expecting `"!taproot"` in vbavailable would see `"taproot"` from nimrod and infer "this is an optional rule, I can omit signaling" — leading the miner to leave a versionbit unset that the soft-fork demands be set. Two-pipeline guard repeat: the `rulesArr` for active rules HARDCODES the `!` for segwit but not for vbavailable. |
| 6 | GBT per-tx `depends` array | G12: array of 1-based template indices of in-template parent txs | **BUG-7 (P0-CDIV)** — `depends` is **NOT EMITTED** at all per-tx (`server.nim:3600-3607`). External miners that respect topological ordering (most do; e.g., cgminer asserts it for fork-safety) cannot know which mempool ancestors must travel together with which descendants. A miner that fairly randomly drops txs from the template (e.g., for max-bytes-uplink) may drop a parent and leave a child, producing a block with `bad-txns-inputs-missingorspent` on submit. Cross-cite W154 BUG-3 (child-before-parent in the assembler itself — the miner-side `depends` gap and the assembler-side ordering gap COMPOUND). |
| 7 | GBT per-tx `fee` + `sigops` + `weight` | G13: all three emitted as JSON NUMBERs | PASS (`server.nim:3604-3606`) — `int64(entry.fee)`, `estimateTxSigops(tx)`, `validation.calculateTransactionWeight(tx)` — three NUMBERs. |
| 7 | … | G14: `sigops` divided by WITNESS_SCALE_FACTOR when `fPreSegWit` | **BUG-8 (P2)** — nimrod emits raw sigops cost regardless of segwit activation height. Latent on practical chains (segwit active everywhere by now) but a pre-segwit-replay (e.g., regtest with segwit disabled) sees 4x-inflated sigops in the template. |
| 8 | GBT `coinbasevalue` field | G15: JSON NUMBER (not string), in satoshis | PASS (`server.nim:3651`) — int64 emitted; jsony serializes as JSON NUMBER. |
| 8 | … | G16: VALUE = block.vtx[0].vout[0].nValue (the actual coinbase output) NOT recomputed (subsidy + fees) | **BUG-9 (P1)** — nimrod RECOMPUTES `int64(tmpl.totalFees) + int64(getBlockSubsidy(int32(tmpl.height), rpc.params))`. Core reads the assembled coinbase output value. Latent divergence: if `createCoinbaseTx` cap-cleared the value or the assembler had a fee-bug, nimrod's `coinbasevalue` claims more than the coinbase actually pays out. The miner that builds against this template overpays themselves (the value they put in the coinbase is the claimed `coinbasevalue`, but the assembler placed less). Compounds with the W143 BUG-2 / W145 BUG-5 / W154 BUG-12 int64 wrap carry-forward (if `totalFees` wrapped negative, `coinbasevalue` is wrong by the same wrap). |
| 9 | GBT `noncerange` | G17: 8-hex `"00000000ffffffff"` (4 bytes start || 4 bytes end) | PASS (`server.nim:3655`). |
| 10 | GBT `sigoplimit` + `sizelimit` | G18: BOTH emitted with consensus values | PASS-with-cosmetic-bug (`server.nim:3656-3657`). `sigoplimit = MaxBlockSigopsCost (80_000)` correct; `sizelimit = 4000000` correct value but **hardcoded** (cross-cite W154 BUG-10). |
| 10 | … | G19: divided by WITNESS_SCALE_FACTOR when `fPreSegWit` | **BUG-10 (P2)** — never divided; same shape as G14. |
| 11 | GBT `weightlimit` | G20: emitted only when post-segwit (Core omits when `fPreSegWit`) | **BUG-11 (P2)** — emitted unconditionally (`server.nim:3658`). Latent. |
| 12 | GBT `mintime` field | G21: respects MTP + 1 (BIP-113 floor) | **BUG-12 (P1)** — `server.nim:3653` emits `tmpl.header.timestamp` which is `getTime().toUnix()` from `buildBlockTemplate:473`, NOT the MTP+1 floor. Core's `mintime = GetMinimumTime(pindexPrev, ...)` (`miner.cpp:36`). A miner with skewed clock can pass a GBT-supplied `mintime` to its hardware as the lower bound, mine a block with `nTime < prevMTP+1`, and have it rejected with `time-too-old` on submit. |
| 12 | … | G22: BIP-94 timewarp accounting at diff-adjustment heights (Core does this **on every network** post-v29) | **BUG-13 (P0-CDIV, carry-forward W154 BUG-6)** — `mintime` is `tmpl.header.timestamp` regardless of `height % difficulty_adjustment_interval`. A nimrod-mined mainnet block at height % 2016 == 0 with `nTime = prevBlockTime - 1000` (i.e., 1000s earlier than parent) passes locally but gets `time-timewarp-attack` from a post-v29 Core peer. Carry-forward shape; mining-side equivalent of the validation-side gap. |
| 13 | GBT `curtime` field | G23: emitted as JSON NUMBER, current Unix time | PASS (`server.nim:3659`) — same as `tmpl.header.timestamp` (which is `getTime().toUnix()`). |
| 13 | … | G24: bounded by `UpdateTime` (max(GetMinimumTime, NodeClock::now())) | **BUG-14 (P1, carry-forward W154 BUG-6)** — `curtime` is plain `getTime().toUnix()` with no MTP+1 / BIP-94 floor. Miner that reads `curtime` and sets `nTime = curtime` may build a sub-MTP block. |
| 14 | GBT `bits` hex encoding | G25: 8-char `%08x` BE hex (e.g., `"1d00ffff"`) | **BUG-15 (P0-CDIV)** — `server.nim:3660-3665` emits **LITTLE-ENDIAN** bytes (low byte first). Core emits **BIG-ENDIAN** hex via `strprintf("%08x", block.nBits)`. The OTHER nimrod handlers (`handleGetBlock`, `handleGetBlockHeader`, `handleGetMiningInfo`) correctly emit BE — see `server.nim:619-625`, `4425-4430`. Direct two-pipeline divergence within the same RPC server: `getblocktemplate` returns `"ffff001d"`, `getmininginfo` and `getblock` return `"1d00ffff"`, for the same block. External miners that round-trip nimrod `getblocktemplate.bits` into their own block header construction get a different difficulty target than `getmininginfo` says is in effect. **20th distinct two-pipeline-guard extension**. |
| 15 | GBT `mutable` array | G26: `["time", "transactions", "prevblock"]` exact match | PASS (`server.nim:3654`). |
| 15 | … | G27: `capabilities` array | PASS — emitted as `["proposal"]` (`server.nim:3643`) matching Core. |
| 16 | GBT `default_witness_commitment` field | G28: emitted ONLY when assembler placed a witness commitment (i.e., post-segwit AND any segwit tx OR Core's unconditional path) | **BUG-16 (P0-CDIV)** — `server.nim:3667` emits `default_witness_commitment` **UNCONDITIONALLY**, including on pre-segwit chains, regardless of whether any tx in the template is segwit. The value is computed by `computeWitnessCommitment(tmpl.transactions)`, which on a coinbase-only template returns `doubleSha256` of an all-zero buffer — a fixed garbage value. A pre-segwit-active miner that obeys the `default_witness_commitment` and inserts it into the coinbase finds the block rejected with `bad-witness-merkle-match`. Cross-cite W154 BUG-4 (assembler-side: nimrod only emits the OP_RETURN commitment when at least one segwit tx is present, opposite asymmetry). The two BUGs compound: a coinbase-only post-segwit block has NO commitment in the assembled coinbase (W154 BUG-4) but the GBT response advertises a default commitment (W155 BUG-16). |
| 17 | submitblock `dummy` (2nd arg) | G29: accepted and ignored per BIP-22 | PASS (`server.nim:3688-3689`) — only checks `params.len < 1`; ignores any subsequent params. |
| 17 | … | G30: returns BIP22ValidationResult string (`"rejected"`, `"high-hash"`, `"bad-txnmrklroot"`, `"bad-witness-merkle-match"`, `"bad-cb-amount"`, etc.) | PASS (`validation.nim:108-169`) — full bip22String mapping. |
| 18 | submitblock side-branch processing | G31: side-branch block validated by full `acceptBlock` pipeline before persistence | **BUG-17 (P0-CONS)** — `server.nim:3866-3879` STORES a side-branch block (`cs.db.storeBlock(blk)` + `putBlockIndexHashOnly(sideIdx)`) with `status: bsValidated` after only `checkBlock` (which only checks PoW + merkle structure + tx sanity). It does **NOT** call `acceptBlock` on the side-branch path; `acceptBlock` is only called when `prevHash == cs.bestBlockHash` (line 3747). The side-branch path skips BIP-30 dup-coinbase, BIP-34 height encoding, BIP-65/66 contextual checks, witness commitment match, MTP+1 timestamp, coinbase value, sigops cost, weight limit, IsFinalTx — every contextual + connect-time check. Block is marked `bsValidated` (line 3870) AFTER bypassing 9+ consensus gates. On a later reorg (line 3884-3923), `handleReorg` → `connectBlock` may then accept the never-validated side-branch block onto the active chain. **Same shape as W143 BUG-3 / W145 BUG-1 / W154 BUG-11** — nimrod's FIFTH distinct entry point that bypasses the full consensus pipeline (after `--reindex`, `mineBlock`, `generateBlockWithTxs`, and `connectBlockIBD` shortcut). |
| 18 | … | G32: side-branch block's PoW-work claim cross-checked via parent's claimed work | PARTIAL — `newTotalWork = prevIdx.totalWork + blockWork` (line 3851-3857) is computed, but no validation that the PoW satisfies the chain's required `nBits` for that height (`getNextWorkRequired`). A side-branch block can claim arbitrary work without proving it. |
| 19 | submitblock `UpdateUncommittedBlockStructures` | G33: re-populate witness reserved value + commitment into coinbase scriptWitness BEFORE consensus pipeline runs | **BUG-18 (P1)** — no equivalent of Core's `UpdateUncommittedBlockStructures(block, pindex)` call (`mining.cpp:1086-1089`). A miner that submits a stripped-witness block (legitimate ASIC-uplink optimization) cannot have it auto-fixed by nimrod's `submitblock`; the block is rejected with `bad-witness-merkle-match` on the first `checkBlock`. Core silently repairs and validates. |
| 20 | submitheader RPC | G34: present in dispatch | **BUG-19 (P1)** — `submitheader` RPC is **absent** from nimrod (`server.nim:8333-8338` mining section has only `getmininginfo`, `getblocktemplate`, `submitblock`). Block-only-relay nodes and SPV bridge software that uses `submitheader` to seed the headers chain cannot interoperate. Returns `"method not found"`. |
| 21 | prioritisetransaction RPC | G35: present in dispatch | **BUG-20 (P0-CDIV)** — `prioritisetransaction` is **absent** from nimrod. Mempool comment at `mempool.nim:1130-1131` literally says `"nimrod has no PrioritiseTransaction, so modified == base"`. Operators that depend on `prioritisetransaction` for fee-bumping stuck transactions, or for sealing-in CPFP child preferences, have no facility. Core supports it; nimrod returns `"method not found"`. **Comment-as-confession 8th instance** for nimrod (the mempool comment literally documents the absence). |
| 21 | … | G36: `getprioritisedtransactions` RPC present | **BUG-20 cross-cite** — absent. |
| 22 | getmininginfo `currentblocksize` field | G37: NOT emitted (Core removed it) | **BUG-21 (P2)** — `server.nim:4443` emits `currentblocksize = 0`. Core removed this field; emitting it is a wire-shape drift. Cosmetic. |
| 22 | … | G38: `currentblockweight` / `currentblocktx` OPTIONAL — only emitted when assembler has built at least one block | **BUG-22 (P2, carry-forward W154 BUG-14)** — emitted unconditionally as `0` regardless of whether any block has been assembled. Core omits via `if (m_last_block_weight) obj.pushKV(...)`. A monitoring tool that uses `currentblockweight > 0` as a proxy for "this node has built a template" gets a false negative on nimrod. |
| 22 | … | G39: `warnings` emitted as ARRAY by default (STRING only with `-deprecatedrpc=warnings`) | **BUG-23 (P2)** — `server.nim:4459` emits `warnings = ""` (empty STRING). Core post-v29 emits `warnings = []` (empty ARRAY) by default. JSON-schema-strict clients reject the STRING form. |
| 23 | bip22ChainError substring matching | G40: maps connectBlock error strings to BIP-22 tokens | **BUG-24 (P1)** — `server.nim:3670-3679` uses `if "..." in errMsg` substring matching. Three branches: `"missing input"`/`"missing or spent"` → `bad-txns-inputs-missingorspent`; `"immature coinbase"` → `bad-txns-premature-spend-of-coinbase`; `"duplicate"` → `bad-txns-duplicate` (which is not a real BIP-22 token; Core uses `bad-txns-inputs-missingorspent` for in-block dup-txid and `bad-txns-BIP30` for cross-block; `bad-txns-duplicate` does not appear in Core's reject-reason set). Free-form English strings vs Core's strict reject-token set. Wire-string parity slippage — same shape as the lunarblock W145 9-token sweep. |

---

## BUG-1 (P0-CDIV) — GBT `mode == "proposal"` is silently ignored; BIP-23 proposal mode non-functional

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate` (`mining.cpp:717-752`)
parses `template_request.mode`. When the value is `"proposal"`, Core:

1. Requires `template_request.data` (else `RPC_TYPE_ERROR`).
2. Calls `DecodeHexBlk` to deserialize the proposed block.
3. Looks up the block hash in the block index.
   - If found and valid → returns `"duplicate"` STRING.
   - If found and `BLOCK_FAILED_VALID` → returns `"duplicate-invalid"`.
   - Otherwise found → `"duplicate-inconclusive"`.
4. If not found, calls `TestBlockValidity(chainstate, block,
   /*check_pow=*/false, /*check_merkle_root=*/true)` and returns
   `BIP22ValidationResult(state)`.

In short, BIP-23 proposal mode is a complete validity check of a candidate
block WITHOUT requiring valid PoW. Miners use it as a pre-flight sanity
check before spending hash power.

nimrod's `handleGetBlockTemplate` (`server.nim:3582-3583`) treats
`params[0]` as an opaque JObject and `discard`s it. There is no `mode`
dispatch, no `data` parser, no `TestBlockValidity` equivalent. A caller
passing `{"mode":"proposal","data":"<hex>"}` receives a normal template
object back, with no relationship to their submitted block. This violates
BIP-23 cleanly.

**File:** `src/rpc/server.nim:3581-3583`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:717-752`.

**Impact:** mining-pool software that pre-flight-checks blocks via
`mode=proposal` (most do; it's BIP-23 standard) silently treats nimrod's
template-response as a successful proposal acceptance and may submit an
invalid block via `submitblock` next, wasting hash power. Cross-fleet
divergence; observable from any miner that issues a BIP-23 conformant
GBT call.

---

## BUG-2 (P0-CDIV) — GBT `rules` field validation absent; pre-segwit-aware clients silently get segwit templates

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate` (`mining.cpp:754-857`)
enforces that the client's `rules` array contains `"segwit"`:

```cpp
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set ...");
}
```

This is a strict gate. A miner that does not declare segwit capability
gets `RPC_INVALID_PARAMETER` rather than a template they cannot understand.

nimrod ignores `rules` entirely. A caller passing
`{"rules":["nonexistent"]}` gets the same segwit-aware template as a
caller passing `{"rules":["segwit","taproot","signet"]}`. The
`default_witness_commitment` field is unconditionally populated (cross-cite
BUG-16) and the miner is expected to insert it — but a non-segwit-aware
miner doesn't know what to do with it.

**File:** `src/rpc/server.nim:3581-3583` (params not parsed).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-857`.

**Impact:** practical: vanishingly small in 2026 (every active miner
supports segwit). Theoretical: nimrod cannot serve as a drop-in replacement
for Core in pre-segwit-replay or regtest-without-segwit testing scenarios.
Architectural: the missing gate is a class of BIP-23 conformance bug.

---

## BUG-3 (P1) — GBT signet handling absent; `signet_challenge` and `signet` rule never emitted

**Severity:** P1. Bitcoin Core's GBT (`mining.cpp:849-852, 962, 1024-1026`):

- Enforces `rules.contains("signet")` on signet chains.
- Pushes `"!signet"` into the `rules` array.
- Emits `signet_challenge = HexStr(consensusParams.signet_challenge)` so
  the miner knows the script their block's signet-witness must satisfy.

nimrod's `handleGetBlockTemplate` has zero references to signet. The
`ConsensusParams` struct (`params.nim:30-90`) has no `signetChallenge`
field. Signet miners against a nimrod node cannot construct a valid block
(the signet block-solution rule requires the per-network challenge).

**File:** `src/rpc/server.nim:3576-3668` (no signet branch);
`src/consensus/params.nim:30-90` (no field).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-852, 962, 1024-1026`.

**Impact:** nimrod cannot run as a signet mining node. The chain is
`Signet` capable per `params.nim:399, 4438`, but mining is structurally
broken.

---

## BUG-4 (P0-CDIV) — GBT does not refuse during IBD or when no peers are connected

**Severity:** P0-CDIV. Bitcoin Core's GBT (`mining.cpp:766-775`) throws
two distinct errors before constructing a template:

```cpp
if (!miner.isTestChain()) {
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, ...);
    }
    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, ...);
    }
}
```

These exist because building a template against a stale chain tip
(during IBD, when the local "tip" is not the network tip) or with no
peers (when there's no chain to actually submit to) produces blocks that
will be orphaned the moment IBD completes or peers reconnect. Mining
against such a template wastes the miner's hash power.

nimrod's `handleGetBlockTemplate` (`server.nim:3577-3668`) runs
unconditionally. A miner pulling a template during IBD gets a template
whose `previousblockhash`, `coinbasevalue` (subsidy at partial height),
`bits`, and `height` are all wrong relative to the network.

**File:** `src/rpc/server.nim:3577-3590` (no IBD/peer gate).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Impact:** observable cross-impl divergence. Most production-grade
miners catch the IBD error and back off; against nimrod they receive
templates and waste hash power on orphan blocks until they manually
detect the IBD condition via other RPCs.

---

## BUG-5 (P0-CDIV) — `longpollid` is absent from GBT response; BIP-22 long-polling protocol dead

**Severity:** P0-CDIV. Bitcoin Core's GBT (`mining.cpp:1002`) emits:

```cpp
result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

And on subsequent GBT calls with `longpollid` set in the request
(`mining.cpp:783-845`), the handler enters a wait loop that releases
`cs_main`, waits up to 60s on first iteration then 10s thereafter, and
breaks when either:
- The tip hash changes, OR
- `mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP`.

This is the BIP-22 long-polling protocol. Miners use it to avoid busy-loop
polling for template updates.

nimrod's GBT response (`server.nim:3642-3668`) emits no `longpollid`
field at all. The wait-loop in the handler does not exist. The static
template cache (Core: `static CBlockIndex* pindexPrev; static
unique_ptr<BlockTemplate> block_template;`) does not exist; every GBT
call builds a fresh template from scratch.

**File:** `src/rpc/server.nim:3576-3668`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:783-845, 1002`.

**Impact:** miners that long-poll on tip changes (the standard mode for
modern pool software like Stratum-v2 gateway → upstream GBT bridge,
ckpool, cgminer) cannot use nimrod as their GBT source. The wire shape
is missing, and even if a client guesses a longpollid the wait-loop
returns immediately with a fresh template. Compounds the busy-loop
cost: every miner polls every block-interval, against nimrod they must
poll on a fixed timer (typically 1Hz) which is 600× more traffic than
long-poll-on-tip-change.

---

## BUG-6 (P1) — `vbavailable` rule names not `!`-prefixed for non-optional rules

**Severity:** P1. Bitcoin Core's `gbt_rule_value(name, gbt_optional_rule)`
(`mining.cpp:606-613`) prefixes the rule name with `!` when it is not
optional. The `vbavailable` map is populated via:

```cpp
for (const auto& [name, info] : gbtstatus.signalling) {
    vbavailable.pushKV(gbt_rule_value(name, info.gbt_optional_rule), info.bit);
    ...
}
```

So clients see entries like `{"!segwit": 1, "taproot": 2}` — the `!`
signals "non-optional" per BIP-9 / BIP-22 conventions.

nimrod emits raw `dep.name` (`server.nim:3637`):

```nim
vbavailableObj[dep.name] = %dep.bit
```

A Core-compatible miner that sees `"taproot"` (no `!` prefix) assumes
the rule is optional, may omit the signaling bit, and miss the
soft-fork's signaling-mandatory window. Two-pipeline guard repeat:
the `rulesArr` for active rules does emit `"!segwit"` (line 3618), but
vbavailable does NOT use the same convention.

**File:** `src/rpc/server.nim:3637`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:606-613, 968-983`.

**Impact:** miners that auto-derive their `nVersion` signaling bits
from `vbavailable` may under-signal a non-optional soft-fork. On a
hypothetical future soft-fork that ships as `gbt_optional_rule = false`,
nimrod-served templates would silently drop the mandatory signaling
bit. Latent until next soft-fork; once active, would produce
"`bad-version`"-class rejection chains.

---

## BUG-7 (P0-CDIV) — per-tx `depends` array not emitted in GBT

**Severity:** P0-CDIV. Bitcoin Core's per-tx GBT entry (`mining.cpp:917-923`):

```cpp
UniValue deps(UniValue::VARR);
for (const CTxIn &in : tx.vin) {
    if (setTxIndex.contains(in.prevout.hash))
        deps.push_back(setTxIndex[in.prevout.hash]);
}
entry.pushKV("depends", std::move(deps));
```

Where `setTxIndex` maps txid → 0-based template index built by the
enumeration loop (`mining.cpp:898, 906`). This tells the miner which
transactions in the template are in-template parents of which others.
Miners that thin the template (e.g., to fit a smaller -blockmaxweight
ceiling) MUST drop a parent + all its descendants together; otherwise
the resulting block has `bad-txns-inputs-missingorspent`.

nimrod's GBT per-tx entry (`server.nim:3600-3607`):

```nim
txs.add(%*{
    "data": toHex(serialize(tx)),
    "txid": reverseHex(toHex(array[32, byte](txid))),
    "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
    "fee": fee,
    "sigops": estimateTxSigops(tx),
    "weight": validation.calculateTransactionWeight(tx)
})
```

No `depends`. Miners cannot detect in-template parents.

**File:** `src/rpc/server.nim:3592-3607`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:917-923`.

**Impact:** any miner that performs template-thinning (most do, to
control bandwidth or to obey -blockmaxweight) may drop a parent tx and
leave a child, building a block that fails on submit with
`bad-txns-inputs-missingorspent`. Combined with W154 BUG-3
(child-before-parent in the assembler), this is two compounding gaps:
the assembler may serve a non-topological ordering AND the GBT response
hides the dependency relationships.

---

## BUG-9 (P1) — `coinbasevalue` recomputed instead of read from assembled coinbase

**Severity:** P1. Bitcoin Core's GBT emits:

```cpp
result.pushKV("coinbasevalue", block.vtx[0]->vout[0].nValue);
```

Reading directly from the ASSEMBLED COINBASE. If the assembler placed
a smaller value (e.g., bug, fee burn, miner-configured donation), the
miner sees the actual value paid out.

nimrod recomputes:

```nim
"coinbasevalue": int64(tmpl.totalFees) + int64(getBlockSubsidy(int32(tmpl.height), rpc.params)),
```

This is the THEORETICAL maximum, not what the assembler actually placed
in the coinbase output. If `buildBlockTemplate` had a fee-accounting bug
or the int64 fee accumulator wrapped (W145 BUG-5 / W154 BUG-12
carry-forward), nimrod's `coinbasevalue` claims more than the coinbase
pays out. A miner that obeys `coinbasevalue` and inserts that value
into their coinbase output overpays themselves (block becomes
`bad-cb-amount` invalid).

**File:** `src/rpc/server.nim:3651`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1001`.

**Impact:** silent fee-accounting drift between assembler-side reality
and GBT-side claim. Compounds with the int64 wrap carry-forward
(W143/W145/W154); on a hypothetical wrap, `coinbasevalue` is wrong by
the wrap delta. Cross-impl divergence: external miners that compare
nimrod's `coinbasevalue` against Core's see different values for the
same template.

---

## BUG-12 (P1) + BUG-13 (P0-CDIV) — `mintime` not MTP+1 floor; BIP-94 timewarp absent

**Severity:** BUG-12 P1 (BIP-113 MTP+1 missing); BUG-13 P0-CDIV (BIP-94
absence on mainnet).

Bitcoin Core's `GetMinimumTime` (`miner.cpp:36-47`):

```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
const int height{pindexPrev->nHeight + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```

Used in the GBT response (`mining.cpp:1004`):

```cpp
result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
```

Two consensus floors:
1. BIP-113 MTP + 1 (every block).
2. BIP-94 timewarp: at diff-adjustment-interval heights (every 2016
   blocks on mainnet), `nTime >= prevBlockTime - MAX_TIMEWARP (600s)`.
   Bitcoin Core enforces BIP-94 on EVERY NETWORK after v29 (testnet4
   landed it first; mainnet activation post-v29).

nimrod's `handleGetBlockTemplate` emits:

```nim
"mintime": tmpl.header.timestamp,
```

Where `tmpl.header.timestamp = uint32(getTime().toUnix())` — wall clock,
no MTP+1, no BIP-94. A miner that obeys `mintime` and sets `nTime =
mintime` may build a block that fails consensus on both BIP-113
("time-too-old") and, post-v29, BIP-94 ("time-timewarp-attack").

Carry-forward from W154 BUG-6 (mining-time BIP-94 absence). The
validation side actually DOES check `time-timewarp-attack`
(`validation.nim:159, veTimeWarpAttack`) — so a nimrod-mined block
fails nimrod's own validator on diff-adjustment heights. The GBT side
mints templates whose `mintime` does not respect what the validator
will accept. Intra-node split (mining vs validation pipelines).

**File:** `src/rpc/server.nim:3653`;
`src/mining/blocktemplate.nim:469-476` (`buildBlockTemplate` sets
timestamp to wall-clock).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47, 219`;
`bitcoin-core/src/rpc/mining.cpp:1004`.

**Impact:** miners that obey GBT `mintime` mine `time-too-old` blocks
on the first block of a new diff-adjustment interval that follows a
local clock-skew. Compounds with BUG-14 (`curtime` same gap).

---

## BUG-15 (P0-CDIV) — GBT `bits` hex is LITTLE-ENDIAN; Core emits BIG-ENDIAN

**Severity:** P0-CDIV. Bitcoin Core emits:

```cpp
result.pushKV("bits", strprintf("%08x", block.nBits));
```

`%08x` formats a 32-bit unsigned integer as 8 hex digits, MOST-SIGNIFICANT
NIBBLE FIRST. For `nBits = 0x1d00ffff`, the emitted string is
`"1d00ffff"`.

nimrod (`server.nim:3660-3665`):

```nim
"bits": toHex(cast[array[4, byte]]([
    byte(tmpl.header.bits and 0xff),       # low byte first
    byte((tmpl.header.bits shr 8) and 0xff),
    byte((tmpl.header.bits shr 16) and 0xff),
    byte((tmpl.header.bits shr 24) and 0xff) # high byte last
])),
```

For `nBits = 0x1d00ffff`, nimrod emits `"ffff001d"`.

The other nimrod handlers emit BE correctly:
- `handleGetMiningInfo` (`server.nim:4425-4430`): high byte first.
- `handleGetBlock` (`server.nim:619-625`): high byte first.
- `handleGetBlockHeader` (`server.nim:774-780`): high byte first.

So nimrod has TWO bits-hex pipelines diverging by 4-byte byte-order
within the same RPC server. A miner that compares `getblocktemplate.bits`
against `getmininginfo.bits` for the same tip sees different strings.
A miner that reconstructs the block header from `bits` ends up with a
totally different difficulty target (the byte-reversed `nBits` is not
even a valid compact target on any expected chain — e.g., `0xffff001d`
parses as exponent 0xff, which is out of range).

**20th distinct two-pipeline-guard extension** (first for byte-order
within a single RPC server).

**File:** `src/rpc/server.nim:3660-3665`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1021`.

**Impact:** every external mining tool that reads `getblocktemplate.bits`
into block-header construction sees byte-reversed nBits. The resulting
block target is wildly different. Local nimrod-only mining scripts that
read `tmpl.header.bits` (uint32) skip the hex round-trip and work fine,
masking the bug on internal regtest. Cross-impl divergence; observable
on any GBT call against a nimrod node.

---

## BUG-16 (P0-CDIV) — `default_witness_commitment` emitted unconditionally even on pre-segwit chains / coinbase-only templates

**Severity:** P0-CDIV. Bitcoin Core (`mining.cpp:1028-1031`):

```cpp
if (auto coinbase{block_template->getCoinbaseTx()}; coinbase.required_outputs.size() > 0) {
    CHECK_NONFATAL(coinbase.required_outputs.size() == 1);
    result.pushKV("default_witness_commitment", HexStr(coinbase.required_outputs[0].scriptPubKey));
}
```

The field is emitted ONLY when the assembler placed a witness-commitment
output (i.e., post-segwit, with at least one segwit tx — or per
`GenerateCoinbaseCommitment` semantics, unconditionally on post-segwit
chains).

nimrod (`server.nim:3667`):

```nim
"default_witness_commitment": toHex(@[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed] & @(computeWitnessCommitment(tmpl.transactions)))
```

Unconditional. On a coinbase-only template (no segwit txs), the
`computeWitnessCommitment` call (`blocktemplate.nim:112-138`) hashes
`witnessMerkleRoot || 0x00*32`. With only the coinbase wtxid (all-zero),
`witnessMerkleRoot = SHA256d(all-zero || all-zero)` which is a fixed
garbage value. nimrod emits an OP_RETURN containing this garbage hash
as the "default" commitment.

A miner that obeys `default_witness_commitment` and inserts it into the
coinbase finds the block rejected with `bad-witness-merkle-match`
because the coinbase commitment must match
`SHA256d(BlockWitnessMerkleRoot(block) || witnessReservedValue)` and the
constructed block has no segwit transactions, so the commitment must be
that-of-an-all-zero block.

Compounding W154 BUG-4 (assembler-side: nimrod's `createCoinbaseTx` only
emits the OP_RETURN when at least one segwit tx is present — OPPOSITE
asymmetry): the assembler may produce a block WITHOUT a witness
commitment, but the GBT response advertises a DEFAULT commitment. A
miner following the GBT instructions ends up with two coinbase outputs
that don't agree.

**File:** `src/rpc/server.nim:3667`;
`src/mining/blocktemplate.nim:178-195` (assembler asymmetry).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1028-1031`;
`bitcoin-core/src/validation.cpp::GenerateCoinbaseCommitment`.

**Impact:** cross-impl divergence on any GBT call; the
`default_witness_commitment` field returned by nimrod for a coinbase-only
template (e.g., a freshly-cleared mempool) is a fixed garbage value that
miners cannot use. Compounds W154 BUG-4: assembler-side absence + GBT
advertising creates a guaranteed-invalid block-construction recipe.

---

## BUG-17 (P0-CONS) — submitblock side-branch path skips `acceptBlock`; persists unvalidated blocks as `bsValidated`

**Severity:** P0-CONS. nimrod's `handleSubmitBlock` (`server.nim:3705-3878`)
splits on `prevHash == cs.bestBlockHash`:

- **Same as tip** (line 3710-3803): calls `checkBlock` → `acceptBlock`
  (the full pipeline) → `connectBlock`. CORRECT.
- **Side-branch** (line 3805-3879): calls `checkBlock` only, then stores
  the block via `cs.db.storeBlock(blk)` + creates a `BlockIndex` with
  `status: bsValidated` (line 3870), and persists via
  `cs.db.putBlockIndexHashOnly(sideIdx)`.

The side-branch path SKIPS:
- `acceptBlock` (BIP-30, BIP-34, BIP-65, BIP-66, BIP-113 contextual)
- `checkBip30` (duplicate-coinbase)
- `validateBlock` (weight, sigops cost, BIP-34 coinbase height,
  coinbase value, IsFinalTx, witness commitment match)
- `verifyScripts`
- `getNextWorkRequired` (the side-branch's nBits is not validated
  against the chain's required difficulty for that height)

The block is then marked `bsValidated` (line 3870) — a FALSE claim of
validity. On a later reorg (line 3884-3923), `handleReorg` traverses
`newChainBlocks` and calls `connectBlock` for each. `connectBlock`
(`chainstate.nim:739-908`, per W154 BUG-11) is a state-mutation
primitive that does NOT re-validate consensus rules. The never-validated
side-branch block reaches the active chain.

**This is the same shape as W143 BUG-3 / W145 BUG-1 / W154 BUG-11**:
nimrod has multiple consensus-bypass entry points. After this audit,
the count is:

1. `--reindex` path (W143 BUG-3) — bypasses entire `acceptBlock`.
2. `mineBlock` regtest path (W154 BUG-11) — calls `connectBlock` direct.
3. `generateBlockWithTxs` (W154 BUG-11) — same.
4. `connectBlockIBD` fast path (`server.nim:3772-3775`) — IBD shortcut.
5. **NEW W155: submitblock side-branch path** — stores unvalidated.

**Five distinct consensus-bypass entry points** — a class of finding
explicitly called out as the "N-pipeline drift" universal pattern in
the May 18 quad-audit grand-pattern catalogue.

**File:** `src/rpc/server.nim:3866-3879` (side-branch persistence).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1083-1095` — Core ALWAYS
calls `chainman.ProcessNewBlock(blockptr, /*force_processing=*/true,
/*min_pow_checked=*/true, /*new_block=*/&new_block)` regardless of
whether the block extends the active chain or a side-branch.
`ProcessNewBlock` always routes through `CheckBlock` → `AcceptBlock`
(which includes `ContextualCheckBlock`) before any persistence.

**Impact:**

- A peer submitting a side-branch block with a valid PoW but an
  invalid coinbase amount (`bad-cb-amount`), an invalid BIP-30
  duplicate, an oversized weight, a non-final tx, or any other
  contextual-rule violation has the block persisted as `bsValidated`.
- On a future reorg that promotes that side-branch to the active
  chain (peer broadcasts a deeper side-branch tip), the never-validated
  block is accepted onto the active chain via `handleReorg` →
  `connectBlock`.
- The nimrod node now disagrees with Core on chain state: Core rejected
  the side-branch on submission, nimrod accepted it without validation
  and may now connect it on reorg.
- Chain-split candidate on adversarial side-branch submissions.

---

## BUG-19 (P1) + BUG-20 (P0-CDIV) — `submitheader`, `prioritisetransaction`, `getprioritisedtransactions` RPCs absent

**Severity:** BUG-19 P1 (submitheader); BUG-20 P0-CDIV
(prioritisetransaction).

nimrod's RPC dispatch (`server.nim:8332-8338`) for the mining section
contains ONLY:

```nim
of "getmininginfo":
    rpc.handleGetMiningInfo()
of "getblocktemplate":
    rpc.handleGetBlockTemplate(params)
of "submitblock":
    rpc.handleSubmitBlock(params)
```

Three RPCs. Bitcoin Core's mining section (`mining.cpp:1148-1167`)
registers SEVEN:
- `getnetworkhashps` (nimrod has separate handler at line 8466)
- `getmininginfo`
- `prioritisetransaction` — **ABSENT in nimrod**
- `getprioritisedtransactions` — **ABSENT in nimrod**
- `getblocktemplate`
- `submitblock`
- `submitheader` — **ABSENT in nimrod**

`prioritisetransaction` is critical for production miners: it lets
operators force-bump-in stuck transactions (e.g., low-fee txs that have
been mempool-pinned), and lets pool operators sponsor specific txids
into the next block. nimrod's mempool literally has a comment
acknowledging the absence:

```nim
# m_base_fees plus PrioritiseTransaction deltas (Core validation.cpp:930).
# nimrod has no PrioritiseTransaction, so modified == base — but expose the
```

(`mempool.nim:1130-1131`) — **comment-as-confession, 8th instance** for
nimrod.

`submitheader` is used by block-only-relay nodes and SPV bridges to
seed the headers chain without sending a full block. Its absence makes
nimrod incompatible as a header-only relay backend.

**File:** `src/rpc/server.nim:8332-8338` (no entries).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-545, 547-583,
1108-1146, 1148-1167`.

**Impact:** any operational workflow that requires
`prioritisetransaction` (most mining pools have this in their fee-bump
toolkit; many wallet UX flows include it for stuck-tx recovery) cannot
use nimrod. `submitheader` absence affects block-relay-only network
topology participants. Both return `"method not found"` from nimrod's
RPC.

---

## Fleet-pattern cross-cites (this wave)

This audit triggered the following fleet patterns called out in the
May 18 grand catalogue:

- **N-pipeline drift** (5th distinct nimrod entry point for
  consensus-bypass) — BUG-17. Now 5 distinct entry points in nimrod
  alone: `--reindex`, `mineBlock`, `generateBlockWithTxs`,
  `connectBlockIBD`, **submitblock side-branch persistence**. Three
  consensus-pipelines / two-pipeline drift universal pattern, 4th
  consecutive wave finding for nimrod (W143, W145, W154, W155).
- **Two-pipeline guard 20th distinct extension** — BUG-15. First
  byte-order-within-single-RPC-server divergence (GBT vs getmininginfo
  emit `bits` in opposite byte order).
- **Comment-as-confession 8th instance** — BUG-20.
  `mempool.nim:1130-1131` literally says "nimrod has no
  PrioritiseTransaction".
- **Carry-forward fleet pattern** — BUG-9, BUG-12, BUG-13, BUG-14
  carry-forward W141 BUG-8 (mempoolminfee divisor), W143 BUG-2 (int64
  coinbase wrap), W145 BUG-5 (int64 fee accumulator wrap), W154 BUG-6
  (BIP-94 timewarp absent at mining time).
- **Plumb-gate-then-flip 7th instance** (cross-cite W154 BUG-13):
  `vbavailable` flag-walk is implemented (G10 PASS) but the
  `!`-prefixing helper is not used (G11 BUG-6) — the gate is plumbed
  but a critical formatting step is missed.
- **Dead-data plumbing** — BUG-3. `ConsensusParams.network = Signet`
  is set per `params.nim:399, 4438` (recognized in `getmininginfo`)
  but no `signetChallenge` field exists at all, so `signet_challenge`
  cannot be emitted in GBT (data not plumbed end-to-end).
- **Wire-string parity slippage** — BUG-24.
  `bip22ChainError` substring-matches free-form English instead of
  using Core's reject-token set; emits non-Core token
  `"bad-txns-duplicate"`.
- **20th distinct two-pipeline-guard extension** — see BUG-15.

---

## Summary

Bug count: **24** (G1..G40 sub-gates; 16 PASS, 24 distinct BUG
verdicts).

By severity:
- **P0-CONS**: 1 (BUG-17 submitblock side-branch persistence skips
  acceptBlock; persists as bsValidated)
- **P0-CDIV**: 9 (BUG-1 mode=proposal ignored, BUG-2 rules ignored,
  BUG-4 IBD/no-peers gate absent, BUG-5 longpollid absent, BUG-7
  depends absent, BUG-13 BIP-94 timewarp absent at mining,
  BUG-15 bits LE not BE, BUG-16 default_witness_commitment unconditional,
  BUG-20 prioritisetransaction RPC absent)
- **P1**: 9 (BUG-3 signet, BUG-6 vbavailable ! prefix, BUG-8 sigops
  not /4 pre-segwit, BUG-9 coinbasevalue recomputed, BUG-12 mintime
  MTP+1 absent, BUG-14 curtime BIP-113 floor absent, BUG-18
  UpdateUncommittedBlockStructures absent, BUG-19 submitheader absent,
  BUG-24 chainerror substring match emits non-Core token)
- **P2**: 5 (BUG-10 sizelimit not /4 pre-segwit, BUG-11 weightlimit
  unconditional, BUG-21 currentblocksize legacy field, BUG-22
  currentblockweight not optional, BUG-23 warnings is STRING not
  ARRAY)

Top findings:
1. **BUG-17 (P0-CONS) submitblock side-branch persistence** —
   5th distinct nimrod consensus-bypass entry point. Side-branch blocks
   are stored with `status: bsValidated` after only `checkBlock`,
   skipping `acceptBlock`/`validateBlock`/`checkBip30`/`verifyScripts`.
   On future reorg, these never-validated blocks reach the active chain.
   Chain-split candidate.
2. **BUG-15 (P0-CDIV) GBT `bits` byte-order divergence** — `bits`
   emitted little-endian in GBT response vs big-endian in
   `getmininginfo`/`getblock`/`getblockheader`. 20th distinct
   two-pipeline-guard extension; intra-RPC-server byte-order split. Any
   external miner round-tripping nimrod GBT into block-header
   construction gets a wildly different difficulty target.
3. **BUG-5 (P0-CDIV) `longpollid` absent** — the entire BIP-22
   long-polling protocol is dead. Miners cannot wait-on-tip-change;
   must busy-poll every block-interval at ~600× the traffic of long-poll.
   Compounds with BUG-1 (mode=proposal absent) — both pillars of BIP-22
   protocol conformance are missing.
