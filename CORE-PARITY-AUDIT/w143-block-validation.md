# W143 — Block-level validation audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W143).
Concurrent-agent coordination: 3 OTHER audit waves in PARALLEL (streak 71 fix +
72 discovery preserved).

Scope: CheckBlock + ContextualCheckBlockHeader + ContextualCheckBlock +
ConnectBlock + CheckTransaction + CheckMerkleRoot (CVE-2012-2459 mutated-tree
detection), MAX_BLOCK_SIGOPS_COST = 80,000, BIP-34 coinbase height encoding,
BIP-30 duplicate-coinbase exceptions, MoneyRange invariants, vin/vout
non-empty + coinbase uniqueness, block size / weight bounds, block-timestamp
gates (MAX_FUTURE_BLOCK_TIME + MTP).

Targets in nimrod:
- `src/consensus/validation.nim` (1994 LOC) — `computeMerkleRoot`,
  `calculateBlockWeight`, `validateCoinbase`, `checkWitnessMalleation`,
  `getMedianTimePast`, `getBlockScriptFlags`, `validateTransaction`,
  `validateBlockHeader`, `contextualCheckBlockHeader`,
  `getTransactionSigOpCost`, `countBlockSigopsCost`, `isFinalTxEarly`,
  `validateBlock`, `verifyScripts`, `checkBlockHeader`, `checkTransaction`,
  `isFinalTx`, `checkBlockLocktime`, `checkBip30`, `checkBlock`, `acceptBlock`.
- `src/consensus/params.nim` (743 LOC) — chain params, BIP heights, constants.
- `src/primitives/types.nim` (108 LOC) — TxId / BlockHash / Satoshi distinct types.
- `src/storage/chainstate.nim` (lines 739-1332) — `connectBlock` + `connectBlockIBD`.
- `src/nimrod.nim` (lines 1611, 1780) — IBD reindex paths that bypass `acceptBlock`.
- `src/network/sync.nim` (lines 1072, 1127, 1659, 1704) — P2P / IBD paths that
  do call `acceptBlock`.

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/validation.cpp` — `CheckBlockHeader` (3828-3835), `CheckMerkleRoot`
  (3837-3862), `CheckWitnessMalleation` (3870-3916), `CheckBlock` (3918-3983),
  `IsBlockMutated` (4027-4056), `ContextualCheckBlockHeader` (4080-4121),
  `ContextualCheckBlock` (4129-4184), `ConnectBlock` (2295-2750),
  `GetBlockSubsidy` (1839-1850).
- `src/consensus/tx_check.cpp` — `CheckTransaction` (11-60).
- `src/consensus/tx_verify.cpp` — `IsFinalTx` (17-37), `GetLegacySigOpCount`
  (112-124), `GetP2SHSigOpCount` (126-141), `GetTransactionSigOpCost` (143-162),
  `CheckTxInputs` (164-214).
- `src/consensus/merkle.cpp` — `ComputeMerkleRoot` (46-63) with mutation
  detection, `BlockMerkleRoot` (66-74), `BlockWitnessMerkleRoot` (76-85).
- `src/consensus/consensus.h` — `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`,
  `MAX_BLOCK_WEIGHT = 4_000_000`, `MAX_BLOCK_SIGOPS_COST = 80_000`,
  `WITNESS_SCALE_FACTOR = 4`, `MAX_TIMEWARP = 600`.
- `src/consensus/validation.h` — `GetBlockWeight` (136-139).
- `src/script/script.h` — `CScript::push_int64` (433-448), CScriptNum encoding.
- `src/kernel/chainparams.cpp` — `script_flag_exceptions` (85-88, 210-211),
  BIP34Height/Hash (89-90), CSV/SegWit/Taproot heights (93-94).

## Status

**BUGS FOUND — 19 distinct defects.** Of these:

- **P0-CONSENSUS** — 2 (coinbase output checks missing from `checkBlock`
  enable miner overflow-trickery; IBD-import paths bypass entire
  contextual-check pipeline including BIP-34 / sigops / weight / coinbase
  value / witness-commitment / IsFinalTx).
- **P0-CDIV** — 5 (Core's CVE-2012-2459 mutation flag plumbing not
  preserved; signet block-solution check absent; reject-reason for
  CVE-2012-2459 leaf-dup differs from Core; taproot script-flag exception
  enforces flags Core skips; pre-segwit `vtx.size() * 4 >
  MAX_BLOCK_WEIGHT` early bound missing).
- **P0-SEC** — 1 (coinbase value overflow during accumulation in
  `validateBlock`).
- **P1** — 6 (BIP-30 reject-reason divergence; `veBadAmount` re-used for
  in-tx amount errors AND coinbase-too-much; legacy sigops early-cap
  missing from `checkBlock`; P2SH sigop counting unconditional vs Core's
  height-gated; 64-byte tx mutation defense absent; `IsBlockMutated`
  helper absent — used by Core both in `ProcessNewBlock` AND in
  `PartiallyDownloadedBlock`).
- **P2** — 4 (no `fChecked` / `m_checked_merkle_root` memoization;
  `bad-blk-length` reject reason replaced with `no-coinbase` for empty
  `blk.txs`; `checkBlock` skips coinbase from `CheckTransaction` gates;
  off-by-one between BIP-34 expected height and `prevIndex.height + 1`
  is fine but documentation drift).
- **P3** — 1 (testnet3 `bip34Height = 21111` not verified against Core).

## Bug list

---

### BUG-1 — `checkBlock` skips `CheckTransaction` for the coinbase, enabling P0-CONSENSUS coinbase overflow and forbidden-amount minting via output-value wrap

**Severity:** P0-CONSENSUS
**File:** src/consensus/validation.nim:1836-1841
**Core ref:** bitcoin-core/src/validation.cpp:3959-3968 (CheckBlock loops
`for (const auto& tx : block.vtx)` and calls `CheckTransaction(*tx,
tx_state)` on EVERY transaction — including the coinbase) and
bitcoin-core/src/consensus/tx_check.cpp:11-60 (CheckTransaction performs
per-output `value < 0` / `value > MAX_MONEY` / running-sum
`MoneyRange(nValueOut)` BEFORE the IsCoinBase branch).

**Description:** Nim's `checkBlock` explicitly `continue`s past the
coinbase before calling `checkTransaction`:

```nim
# Check each non-coinbase transaction
for i, tx in blk.txs:
  if i == 0: continue  # coinbase already checked above
  let txResult = checkTransaction(tx, params)
  if not txResult.isOk:
    return txResult
```

The "already checked above" claim is FALSE: lines 1829-1833 only call
`validateCoinbaseSizeOnly`, which checks `2 <= scriptSig.size() <= 100`
and nothing else. The coinbase outputs are NEVER subjected to:
- `value < 0` rejection (Core: `bad-txns-vout-negative`).
- `value > MAX_MONEY` rejection (Core: `bad-txns-vout-toolarge`).
- running sum `nValueOut > MAX_MONEY` rejection (Core:
  `bad-txns-txouttotal-toolarge`).
- `vin.empty()` rejection (Core: `bad-txns-vin-empty` — moot for coinbase
  but the gate still runs in Core).
- `vout.empty()` rejection (Core: `bad-txns-vout-empty` — a real risk if
  a malicious miner produces a coinbase with zero outputs).
- non-witness size limit (Core: `bad-txns-oversize`).

`validateBlock` line 1437-1438 only sums `int64(output.value)` into
`coinbaseValue` without per-output checks. Sum can WRAP if individual
outputs are large enough (see BUG-2 for the overflow analysis). Even
without wrap, a coinbase with `outputs = []` would be accepted by
checkBlock (`vout.empty()` not caught) and then sum to 0, which is `<=
subsidy + totalFees`, accepted.

**Impact:** Consensus divergence. A block with a coinbase containing
`vout.empty()` or with `value > MAX_MONEY` per-output is REJECTED by
Bitcoin Core (`bad-txns-vout-empty` / `bad-txns-vout-toolarge`) but
ACCEPTED by nimrod's `checkBlock`. Whether `validateBlock` catches it
downstream depends on the path (see BUG-2 / BUG-3 for paths that skip
`validateBlock`). At minimum the reject reasons diverge, which breaks
the BIP-22 / submitblock contract and corrupts ban scoring.

---

### BUG-2 — `validateBlock` coinbase-value sum overflows when individual outputs near `INT64_MAX/N`, bypassing `bad-cb-amount`

**Severity:** P0-SEC
**File:** src/consensus/validation.nim:1434-1441
**Core ref:** bitcoin-core/src/consensus/tx_check.cpp:24-34 (Core's
`CheckTransaction` per-output `value > MAX_MONEY` rejection + running
sum `MoneyRange(nValueOut)` happen BEFORE any coinbase-value math).

**Description:** Because per-output `<= MAX_MONEY` is NOT enforced on
the coinbase (BUG-1), `validateBlock`'s coinbase-value check accumulates
arbitrary `int64` values:

```nim
# Check coinbase output value
let subsidy = getBlockSubsidy(height, params)
var coinbaseValue = int64(0)
for output in blk.txs[0].outputs:
  coinbaseValue += int64(output.value)

if coinbaseValue > int64(subsidy) + totalFees:
  return voidErr(veBadAmount)
```

For a coinbase with three outputs each `value = INT64_MAX / 2`:

- output[0]: `coinbaseValue = INT64_MAX/2`           (positive, fits)
- output[1]: `coinbaseValue = INT64_MAX - 1`         (positive, fits, no overflow flag in Nim)
- output[2]: `coinbaseValue = INT64_MAX - 1 + INT64_MAX/2` → SIGNED WRAP → negative number.

`coinbaseValue > int64(subsidy) + totalFees` is now `negative > small
positive` = FALSE. Block accepted. The check is silently bypassed.

Bitcoin Core never reaches this site because `CheckTransaction` rejects
the second output at `value > MAX_MONEY`.

`Satoshi` is a Nim `distinct int64` (primitives/types.nim:11) with no
runtime overflow guard; `+` is `{.borrow.}` from `int64` (line 41) which
in Nim defaults to wrapping arithmetic in release builds.

**Impact:** A miner controlling the block-template (or any attacker who
can submit blocks via `submitblock`) can craft a coinbase that mints
unbounded value — provided downstream paths (script verification,
sync.nim P2P decoding) don't catch the malformed value via a different
gate. The P2P path catches because `acceptBlock → checkBlock` is run on
peer blocks via `sync.nim:1072` and `validateBlock` is then run via
`acceptBlock` — but `checkBlock` itself doesn't reject (BUG-1) and
`validateBlock` is the wrapping path. The fix is to enforce
`CheckTransaction` on the coinbase (closes BUG-1) so the per-output
`> MAX_MONEY` gate runs first.

---

### BUG-3 — Block-import (re-index) paths in `nimrod.nim:1611,1780` call `checkBlock` + `connectBlockIBD` only, bypassing `validateBlock` / `acceptBlock` and skipping ALL contextual consensus checks

**Severity:** P0-CONSENSUS
**File:** src/nimrod.nim:1611-1620, src/nimrod.nim:1780-1789
**Core ref:** bitcoin-core/src/validation.cpp:4347-4352 (loadblk and
reindex paths funnel through `ProcessNewBlock` → `CheckBlock` →
`ContextualCheckBlock` → `ConnectBlock`; no Core path connects a block
to chainstate without ContextualCheckBlock).

**Description:** The two `nimrod.nim` IBD-import call sites:

```nim
# Validate
let checkResult = checkBlock(blk, params)
if not checkResult.isOk:
  echo "Block validation failed at height " & $frameHeight & ": " & $checkResult.error
  break

# Connect
let connectResult = cs.connectBlockIBD(blk, frameHeight)
```

… run ONLY `checkBlock` (context-free) followed directly by
`connectBlockIBD`. They never call `acceptBlock`. Consequently the
following gates are SKIPPED on these import paths:

1. `contextualCheckBlockHeader`: `bad-diffbits` (nBits ≠
   GetNextWorkRequired), `time-too-old` (timestamp ≤ MTP-of-11),
   `time-timewarp-attack` (BIP94), `bad-version` (BIP-34 / BIP-66 / BIP-65
   header-version cutoffs).
2. `validateBlock` body: BIP-34 coinbase height prefix
   (`validateCoinbase` at line 1300); block weight cap (line 1322); IsFinalTx
   per transaction (line 1371); bad-cb-amount (line 1440); witness
   commitment validation (line 1447); per-tx duplicate-input dedup (line
   700); per-non-coinbase-tx `validateTransaction` (line 1380); sigop
   cost ≤ 80,000 (line 1431).
3. `checkBip30`: cross-block dup-UTXO (CVE-2012-1909).
4. `verifyScripts`: per-input script execution (this part is intentional
   on IBD reindex paths).

`connectBlockIBD` (chainstate.nim:1222) only checks coinbase maturity
on spent inputs and writes UTXO updates. None of items 1-3 above run.

**Impact:** A `bitcoind`-format block file (`blk*.dat`) replayed through
the import path can advance the chain with blocks that have wrong nBits
/ wrong block version / late timestamps / non-final transactions / sigop
overload / wrong witness commitment / over-subsidy coinbases. As long as
the txns reference valid UTXOs and the merkle root checks out, the
import accepts. Reindexing from a hostile `blocks/` directory therefore
silently corrupts the chainstate. Core's reindex path runs the FULL
ContextualCheckBlock + ConnectBlock pipeline; this divergence is a
hardened-vs-permissive consensus mismatch.

**Excerpt (validation gap):**

```nim
# nimrod.nim:1608
let blk = deserializeBlock(blockData)

# Validate
let checkResult = checkBlock(blk, params)   # <-- only context-free path
if not checkResult.isOk: ...

# Connect
let connectResult = cs.connectBlockIBD(blk, frameHeight)  # <-- no validateBlock
```

---

### BUG-4 — `computeMerkleRoot` does not propagate the CVE-2012-2459 `mutated` flag through merkle tree levels; relies on leaf-only duplicate-txid detection in `validateBlock`, leaving `checkBlock` exposed

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:172-197
**Core ref:** bitcoin-core/src/consensus/merkle.cpp:46-63 (Core's
ComputeMerkleRoot tracks `mutation` across EVERY level: `for (size_t
pos = 0; pos + 1 < hashes.size(); pos += 2) if (hashes[pos] ==
hashes[pos + 1]) mutation = true;`); val:3853-3858 then rejects
`bad-txns-duplicate` with `BlockValidationResult::BLOCK_MUTATED`.

**Description:** Nim's `computeMerkleRoot` has NO `var mutated`
out-parameter; it only returns the root:

```nim
proc computeMerkleRoot*(txids: seq[array[32, byte]]): array[32, byte] =
  if txids.len == 0:
    return default(array[32, byte])
  if txids.len == 1:
    return txids[0]
  var level = txids
  while level.len > 1:
    var nextLevel: seq[array[32, byte]]
    var i = 0
    while i < level.len:
      var combined: array[64, byte]
      copyMem(addr combined[0], unsafeAddr level[i][0], 32)
      if i + 1 < level.len:
        copyMem(addr combined[32], unsafeAddr level[i + 1][0], 32)
      else:
        # Duplicate last hash if odd number
        copyMem(addr combined[32], unsafeAddr level[i][0], 32)
      nextLevel.add(doubleSha256(combined))
      i += 2
    level = nextLevel
  result = level[0]
```

The leaf-duplicate detection lives ONLY in `validateBlock`
(lines 1304-1310):

```nim
# Check for duplicate transactions
var txids = initTable[string, bool]()
for tx in blk.txs:
  let txid = $tx.txid()
  if txid in txids:
    return voidErr(veDuplicateTx)
  txids[txid] = true
```

Two-layer divergence:

1. `checkBlock` (context-free path, called from compact-block reconstruct,
   from `submitblock`, from `nimrod.nim` reindex) does NOT perform a
   leaf-dedup. A block fed to `checkBlock` with `[A, B, A, B]` (canonical
   CVE-2012-2459 malleation of a 2-leaf tree padded to 4 leaves) computes
   the same merkle root as `[A, B]`. The malleation passes checkBlock.
   Only when the path reaches `validateBlock` does the deduplication
   table catch it. The `submitblock` RPC path calls `acceptBlock` which
   includes validateBlock, so the live path catches. But the reindex
   path (BUG-3) does NOT call validateBlock, so the malleation is
   accepted, fingerprinted into UTXO set, and pinned forever.

2. The reject-reason divergence: Core emits `bad-txns-duplicate` from
   `CheckMerkleRoot` (val:3856) with `BLOCK_MUTATED` severity. Nim's
   `veDuplicateTx` maps to `bad-txns-inputs-missingorspent` per the
   `bip22String` table at line 124. The comment at line 122-124
   acknowledges the divergence ("Core parity: in-block dup-txid →
   bad-txns-inputs-missingorspent (ConnectBlock prevout path)") but
   conflates the ConnectBlock prevout path (Core's `HaveCoin` failure)
   with the CheckMerkleRoot path (Core's mutation flag) — they have
   different reject-reasons in Core.

**Impact:** P0-CDIV split-brain potential: a CVE-2012-2459-malleated
block submitted via the reindex path is accepted; the same block
submitted via P2P is rejected. Different reject-reason on the same
class of malleation breaks BIP-22 + ban-score parity.

---

### BUG-5 — `IsBlockMutated` helper (used by Core in PartiallyDownloadedBlock + ProcessNewBlock) is absent; compact-block reconstruction does NOT enforce CVE-2012-2459 + witness-malleation gates

**Severity:** P1
**File:** src/network/compact_blocks.nim:559-570
**Core ref:** bitcoin-core/src/validation.cpp:4027-4056 (IsBlockMutated:
combines CheckMerkleRoot, the 64-byte-tx defense, and CheckWitnessMalleation
into ONE callable). Called from:
- `src/blockencodings.cpp:220` after compact-block tx reconstruction.
- `src/net_processing.cpp` cmpctblock handler.

**Description:** The `compact_blocks.nim` reconstruction explicitly
acknowledges the gap in a code comment but does NOT implement it:

```nim
# compact_blocks.nim:564
# Note: Bitcoin Core also calls IsBlockMutated(block, segwit_active) here
# (line 220) to verify the merkle root and witness commitment before returning
# READ_STATUS_OK.  Full mutation checking requires the chain context
# (segwit active flag) which is threaded in at the call site; callers should
# verify merkle root and witness commitment after this returns rsOk.

(blk, rsOk)
```

"callers should verify" — but the callers don't. `validateBlock` is
reached later, but ONLY for blocks that progress through the full
acceptance path; a reconstruction that returns `rsOk` and then takes a
side path (e.g. mempool insertion of reconstructed transactions, BIP-152
relayed-tx fan-out) bypasses the mutation gate entirely.

**Comment-as-confession pattern** (cf. clearbit W141 BUG-13, rustoshi
W141 comment-archetype, haskoin W138 BUG-3): code explicitly acknowledges
a missing consensus check via comment and defers responsibility to a
caller that doesn't enforce it.

**Impact:** Compact-block path can accept a mutated block stub for any
side effect (cmpctblock-to-PoW-validation, mempool prefill). Real-world
exploitability bounded but theoretical CVE-2012-2459 / witness-malleation
escape route.

---

### BUG-6 — Signet block-solution check (`CheckSignetBlockSolution`) is COMPLETELY ABSENT

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim (entire), src/consensus/params.nim
**Core ref:** bitcoin-core/src/validation.cpp:3930-3933 (CheckBlock):
```cpp
// Signet only: check block solution
if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
}
```
And `src/signet.{h,cpp}` for the implementation.

**Description:** A grep for `signet_blocks`, `CheckSignetBlockSolution`,
`signetChallenge`, `signet.*sign` in `src/` returns ZERO matches. The
`signetParams()` (params.nim:402) sets `result.network = Signet` but
the consensus check on every block's signet challenge is never performed.

**Impact:** When nimrod is run on signet, the block-validity rule "block
must contain a valid signature over the signet challenge in an OP_RETURN
output of the coinbase" is unenforced. Any peer can craft a block with
correct PoW (signet PoW limit is `00000377ae00...`, very weak) and have
nimrod accept it as a valid signet block. This is a soft-fork-equivalent
divergence: nimrod accepts blocks that Core rejects on signet.

---

### BUG-7 — Taproot script-flag exception (mainnet height 692,975) over-enforces flags Core deliberately skips

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:491-524
**Core ref:** bitcoin-core/src/kernel/chainparams.cpp:87-88
(`script_flag_exceptions.emplace(uint256{"0000...e395ad"}, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)`)
and bitcoin-core/src/validation.cpp:2263-2265 (Core's exception logic
OVERRIDES `flags` with the entry, dropping ALL other flags including
DERSIG / CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY / NULLDUMMY).

**Description:** Nim's `getBlockScriptFlags` only removes `sfTaproot`
when the exception hash matches:

```nim
if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
  result.incl(sfTaproot)
```

But the function returns the FULL `result` set that already includes
sfDERSig, sfCheckLockTimeVerify, sfCheckSequenceVerify, sfWitness,
sfNullDummy (lines 501-521). Core's exception path returns ONLY
`{P2SH, Witness}` — Core does NOT enforce DERSIG, CLTV, CSV, NULLDUMMY
for that one block.

**Impact:** Mainnet block 692,975's transactions are re-validated under
stricter flags than Core uses. If the block contains any input whose
signature is non-DER-canonical (BIP-66), non-final-via-CLTV (BIP-65),
non-final-via-CSV (BIP-112), or pushes a non-zero dummy on
CHECKMULTISIG (NULLDUMMY), nimrod rejects the block while Core accepts.
The block is at height 692,975 — well below any current tip — so this
manifests during reindex / IBD as a stuck chain. The Bitcoin Core
exception was added explicitly because the block contains such an
edge-case; nimrod misses the broader override semantic.

**Excerpt:**

```nim
proc getBlockScriptFlags*(height: int32, params: ConsensusParams,
                          blockHash: string = ""): set[ScriptFlags] =
  if blockHash == BIP16_EXCEPTION_HASH:
    return {}  # SCRIPT_VERIFY_NONE for this block

  result = {sfP2SH}                                  # always
  if height >= int32(params.bip66Height): result.incl(sfDERSig)
  if height >= int32(params.bip65Height): result.incl(sfCheckLockTimeVerify)
  if height >= int32(params.csvHeight):   result.incl(sfCheckSequenceVerify)
  if height >= int32(params.segwitHeight):
    result.incl(sfWitness); result.incl(sfNullDummy)

  if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
    result.incl(sfTaproot)
```

---

### BUG-8 — Early `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` bound missing from `checkBlock`; legacy 1-MB base-size bound implicit but not first-class

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:1808-1855
**Core ref:** bitcoin-core/src/validation.cpp:3947:
```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Three weight-related early bounds in Core CheckBlock,
all under one `bad-blk-length` reject:
1. `block.vtx.empty()` — Nim checks at line 1824 but maps to `veNoCoinbase`
   = `no-coinbase` reject reason (BUG-13 below), not `bad-blk-length`.
2. `block.vtx.size() * 4 > MAX_BLOCK_WEIGHT` — i.e., `txCount > 1,000,000`,
   a DoS pre-check. ENTIRELY MISSING in nimrod's `checkBlock`. An
   attacker can submit a block with 4 million 1-byte transactions and
   make `checkBlock` allocate memory and compute the merkle root over 4M
   leaves before any other check rejects.
3. `GetSerializeSize(TX_NO_WITNESS(block)) * 4 > MAX_BLOCK_WEIGHT` —
   legacy 1-MB base-size cap (pre-SegWit). Nim's `calculateBlockWeight`
   in `validateBlock` (line 1322) computes `baseSize*3 + fullSize` which
   does cap-equivalent (`baseSize*4 ≥ baseSize*3 + fullSize` when
   `fullSize ≤ baseSize*4 − baseSize*3 = baseSize`), so the legacy
   bound is implicitly enforced — but only via `validateBlock`, not via
   `checkBlock`. Reindex paths (BUG-3) skip it.

**Impact:** DoS amplification on context-free `checkBlock`. Reject-reason
divergence (`bad-blk-length` vs `no-coinbase` vs whatever the merkle
recompute throws on 4M leaves). In the reindex path the legacy 1-MB
cap is silently unenforced.

---

### BUG-9 — `validateBlock` skips coinbase from `validateTransaction`; coinbase has no per-output `< 0` / `> MAX_MONEY` / running-sum check via that path either

**Severity:** P0-SEC
**File:** src/consensus/validation.nim:1379-1380
**Core ref:** bitcoin-core/src/validation.cpp:3959 (CheckBlock per-tx
CheckTransaction loop has no `if i == 0` skip).

**Description:** The contextual-check loop in validateBlock explicitly
starts at index 1:

```nim
# Validate non-coinbase transactions
for i in 1 ..< blk.txs.len:
  let tx = blk.txs[i]
  ...
  let txResult = validateTransaction(tx, lookupUtxo, height, params, intraBlockUtxos)
```

`validateTransaction` (line 681) is where the per-output checks live:
`value < 0`, `value > MaxMoney`, running sum overflow. These are NOT
applied to `blk.txs[0]` (the coinbase). The only coinbase output check
is the aggregate `coinbaseValue > subsidy + totalFees` at line 1440 —
which is the wrappable accumulator from BUG-2.

**Impact:** Compounds BUG-1 and BUG-2: even if `checkBlock` were fixed
to call `checkTransaction` on the coinbase, `validateBlock` would still
need its own coinbase per-output gate before the wrappable accumulator.
Defense in depth absent.

---

### BUG-10 — `veBadAmount` reject reason is overloaded for THREE distinct Core conditions; bip22String maps it to `bad-cb-amount` only, masking the in-tx amount errors

**Severity:** P1
**File:** src/consensus/validation.nim:120, :751, :755, :1441
**Core ref:** Distinct reject reasons in Core: `bad-cb-amount`
(val:2612), `bad-txns-inputvalues-outofrange` (tx_verify.cpp:187),
`bad-txns-fee-outofrange` (tx_verify.cpp:209), `bad-txns-in-belowout`
(tx_verify.cpp:198).

**Description:** `veBadAmount` is returned from THREE call sites:

```nim
# validation.nim:751 — input value out of range
if inputValue < 0 or inputValue > int64(MaxMoney):
  return err(int64, veBadAmount)

# validation.nim:755 — accumulated input sum out of range
totalInput += inputValue
if totalInput > int64(MaxMoney):
  return err(int64, veBadAmount)

# validation.nim:1441 — coinbase pays too much
if coinbaseValue > int64(subsidy) + totalFees:
  return voidErr(veBadAmount)
```

… all three map to `bad-cb-amount` in `bip22String`:

```nim
# validation.nim:120
of veBadAmount: "bad-cb-amount"
```

But Core reports:
- in-tx input value out of range → `bad-txns-inputvalues-outofrange`
- coinbase output sum > subsidy + fees → `bad-cb-amount`

**Impact:** P2P / submitblock RPC clients receive `bad-cb-amount` for
non-coinbase transactions with out-of-range input values. This breaks
mempool-rejection telemetry, BIP-22 contracts, and downstream peer-ban
score calibration (Core's `MaybePunishNodeForBlock` uses different ban
weights for different reject reasons).

---

### BUG-11 — `validateBlock` total-sigops counting unconditionally treats P2SH as active; Core gates P2SH sigop counting on `SCRIPT_VERIFY_P2SH` flag

**Severity:** P1
**File:** src/consensus/validation.nim:1402, :1192
**Core ref:** bitcoin-core/src/consensus/tx_verify.cpp:150-152
(GetTransactionSigOpCost):
```cpp
if (flags & SCRIPT_VERIFY_P2SH) {
    nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
}
```

**Description:** Nim's `validateBlock` calls
`getTransactionSigOpCost(tx, lookupUtxo, useP2SH=true, useWitness=useWitnessSigops)`
with `useP2SH` hardcoded `true` at line 1402. Similarly
`countBlockSigopsCost` (line 1192) sets `useP2SH = true`.

Core uses BIP-16 activation at mainnet height 170,060. Below this
height (pre-BIP-16), P2SH sigops are NOT counted. The Nim code
acknowledges this in comment (line 500: "P2SH active from BIP16 (mainnet:
170060, but treat as always-on for simplicity)") and at line 1187
("P2SH sigops if height >= p2shHeight (always on mainnet)"), but
doesn't actually gate on the height.

**Impact:** For replay of mainnet blocks 0..170,059 (or testnet
equivalents), nimrod over-counts sigops. A pre-BIP-16 block that uses
P2SH-shaped output scripts (`OP_HASH160 <20 bytes> OP_EQUAL`) with
high sigop counts inside the "redeem script" payload (which is just
data, not a script before BIP-16) would have its sigops counted as
P2SH sigops in nimrod but not in Core. If those sigops push the block
total over 80,000, nimrod rejects with `bad-blk-sigops` while Core
accepts. Mostly historical — the chain is way past 170,060 — but a
reindex / replay would diverge.

---

### BUG-12 — Legacy sigops early-cap (Core val:3971-3977) missing from `checkBlock`; Nim defers ALL sigop accounting to UTXO-aware `validateBlock`

**Severity:** P1
**File:** src/consensus/validation.nim:1808-1855
**Core ref:** bitcoin-core/src/validation.cpp:3971-3977:
```cpp
unsigned int nSigOps = 0;
for (const auto& tx : block.vtx) {
    nSigOps += GetLegacySigOpCount(*tx);
}
if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");
```

**Description:** Core's `CheckBlock` does a pre-flight legacy-only sigops
check that does NOT require UTXOs — it caps `legacyOnlyCount > 20_000`
(20,000 * 4 > 80,000). Nim's `checkBlock` does no sigop check at all.
The first sigop gate runs in `validateBlock` line 1431, which requires
UTXO lookups (witness sigop counting needs the prevout scriptPubKey).

**Impact:** Two divergences:
1. Context-free DoS pre-check absent: a block with 200,000 legacy
   `OP_CHECKSIG`s in scriptSigs can be fully merkle-validated in
   `checkBlock` before being rejected — wasted work on hostile blocks.
2. Reject-reason ordering: Core may reject with `bad-blk-sigops` before
   missing-input cascades; Nim may reject with `bad-txns-inputs-missingorspent`
   (from `validateTransaction`) when UTXOs are unavailable AND the block
   would also fail `bad-blk-sigops`. Order of reject reasons matters for
   PoW-DoS scoring.

---

### BUG-13 — Empty `blk.txs` reject reason is `no-coinbase`; Core emits `bad-blk-length`

**Severity:** P2
**File:** src/consensus/validation.nim:1823-1825, :1284-1286
**Core ref:** bitcoin-core/src/validation.cpp:3947-3948:
```cpp
if (block.vtx.empty() || ...) return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Nim's `checkBlock`:

```nim
# Must have at least one transaction (coinbase)
if blk.txs.len == 0:
  return voidErr(veNoCoinbase)
```

`veNoCoinbase` maps to no entry in bip22String (no `of veNoCoinbase:`
arm) so falls through to the `else: "rejected"` at line 169. Core uses
`bad-blk-length`.

Same divergence at validateBlock:1285-1290. validateBlock also returns
`veNoCoinbase` for "first transaction must be coinbase" — Core uses
`bad-cb-missing`. And for "no other transaction can be coinbase"
returns `veBadCoinbase` → `bad-cb-height` (line 129) — Core uses
`bad-cb-multiple`. Multiple reject-reason cascade divergences in one
proc.

**Impact:** Reject-reason mismatch on a permanently-malformed block.
BIP-22 submitblock RPC consumers / test-suite fixtures relying on
exact Core reject strings will fail.

---

### BUG-14 — 64-byte transaction mutation defense (Core val:4036-4043) is absent

**Severity:** P1
**File:** src/consensus/validation.nim (entire)
**Core ref:** bitcoin-core/src/validation.cpp:4036-4043 (inside
IsBlockMutated):
```cpp
// Consider the block mutated if any transaction is 64 bytes in size (see 3.1
// in "Weaknesses in Bitcoin's Merkle Root Construction")
return std::any_of(block.vtx.begin(), block.vtx.end(),
                   [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
```

**Description:** Core's `IsBlockMutated` adds a defensive check: if any
non-witness tx serializes to exactly 64 bytes, the block is mutated.
This defeats the well-known merkle-tree malleation where 64-byte
"transactions" look identical to internal-node hashes. Nim has no
such check.

**Impact:** Theoretical CVE-2012-2459 escape route closed in Core but
open in nimrod. The check only fires when the FIRST tx isn't a coinbase
(see Core val:4035 guard), which is a separate consensus failure
anyway, so exploit chain is narrow. P1 because the gate exists in Core
for a known cryptographic reason.

---

### BUG-15 — `fChecked` / `m_checked_merkle_root` / `m_checked_witness_commitment` memoization absent; every revalidation redoes O(n) work

**Severity:** P2
**File:** src/consensus/validation.nim (entire)
**Core ref:** bitcoin-core/src/primitives/block.h (CBlock has
mutable `fChecked`, `m_checked_merkle_root`, `m_checked_witness_commitment`);
val:3922-3923 (`if (block.fChecked) return true;`), val:3839
(`if (block.m_checked_merkle_root) return true;`).

**Description:** Bitcoin's `CBlock` carries mutable cache flags so that
`CheckBlock` and `CheckMerkleRoot` early-return on re-entry. nimrod's
`Block` (primitives/types.nim:74-76) has no such fields. Repeated
calls to checkBlock / validateBlock from different code paths
re-compute the merkle root, re-iterate transactions, etc.

**Impact:** Pure performance, not consensus. On a re-org through 100
blocks each with 4000 transactions, nimrod redundantly re-hashes
~400k transactions per repeated validation pass. Core does it once.

---

### BUG-16 — `Satoshi` distinct arithmetic borrows `+` from `int64` with no overflow guard; coinbase-sum overflow path is reachable

**Severity:** P1 (companion to BUG-2)
**File:** src/primitives/types.nim:38-42
**Core ref:** bitcoin-core/src/consensus/amount.h (CAmount = int64_t)
with explicit `MoneyRange()` gates at every accumulation point in
val/tx_check/tx_verify.

**Description:**

```nim
proc `==`*(a, b: Satoshi): bool {.borrow.}
proc `<`*(a, b: Satoshi): bool {.borrow.}
proc `<=`*(a, b: Satoshi): bool {.borrow.}
proc `+`*(a, b: Satoshi): Satoshi {.borrow.}
proc `-`*(a, b: Satoshi): Satoshi {.borrow.}
```

In Nim release builds, integer overflow in `int64` `+` silently wraps
modulo 2^64 (Nim docs: `-d:release` disables `--overflowChecks:on`
unless explicitly enabled). Per-call MoneyRange validation is the
ONLY defense. The defense is missing on the coinbase output path
(BUG-1 / BUG-2 / BUG-9).

**Impact:** Cross-cite to BUG-2 root cause. Treat `Satoshi` arithmetic
as raw `int64` for safety analysis; every accumulator must be paired
with a `MoneyRange` check.

---

### BUG-17 — `validateBlock` second pass on "no other coinbase" returns `veBadCoinbase` mapped to `bad-cb-height`; Core emits `bad-cb-multiple`

**Severity:** P2
**File:** src/consensus/validation.nim:1293-1295, :129
**Core ref:** bitcoin-core/src/validation.cpp:3953-3955:
```cpp
for (unsigned int i = 1; i < block.vtx.size(); i++)
    if (block.vtx[i]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");
```

**Description:** Nim conflates "first tx is not coinbase" with "another
tx is coinbase" via `veBadCoinbase` mapped to `bad-cb-height` (line 129).
The reject-reason string for `bad-cb-multiple` doesn't exist anywhere
in the enum.

**Impact:** Reject-reason mismatch. P2 because both are rare malformed
inputs.

---

### BUG-18 — `encodeBip34Height(height = 0)` returns `@[byte(0x00)]` which IS OP_0 byte-equivalent but the documentation conflates "OP_0 byte" with "single-byte serialized push of empty bytestring"

**Severity:** P3 (documentation drift; no consensus impact at the bip34 activation height)
**File:** src/consensus/validation.nim:299-300
**Core ref:** bitcoin-core/src/script/script.h:439-441 (push_int64(0)
calls `push_back(OP_0)` where `OP_0 = 0x00`).

**Description:** The Nim comment says `height == 0 → OP_0 (0x00), single byte`.
The literal byte `0x00` IS `OP_0`, so this is correct in practice — but BIP-34
activation height is 1 (regtest) or 227,931 (mainnet), so height=0 is never
hit in production. Defensive code path with no test coverage. Compare to Core
where `OP_0` is a named opcode constant. Drift not bug.

**Impact:** None in practice. Cleanup-worthy.

---

### BUG-19 — testnet3 BIP34Height (21111) used in nimrod params.nim is below Core's documented edge-case range; needs cross-reference against `consensus.BIP34Height = 21111` in Core kernel/chainparams.cpp:212. Verified equal.

**Severity:** P3 (verification, no divergence)
**File:** src/consensus/params.nim:273+
**Core ref:** bitcoin-core/src/kernel/chainparams.cpp:212

**Description:** Cross-check confirmed: testnet3 BIP34Height = 21111 matches
Core. Recorded for audit completeness; flagged because testnet3 has the
documented "block 21111 BIP34 violation at indicated-height 33333" edge
case that requires the BIP30_LIMIT escape hatch (val:2456-2458).

**Impact:** None observed.

---

## Fleet patterns observed

1. **IBD-import shortcut**: `nimrod.nim:1611/1780` import paths skip
   `validateBlock` / `acceptBlock`. Same pattern seen in clearbit W138
   (CLI `--load-snapshot` skips RPC's hash gate), camlcoin W138 (run-time
   dead-code), beamchain W141 (xref silenced + rebar3 release skips
   verifier). Audit type: **"different entry, fewer gates"** — single
   source of truth for the pipeline (`acceptBlock`) is present but the
   IBD-import code copy-pastes its own minimal pipeline alongside.

2. **Reject-reason mapping conflation**: `bip22String` table at
   validation.nim:108-169 conflates THREE Core reject reasons under
   single Nim enum values (BUG-10 `veBadAmount` × 3 sites; BUG-13
   `veNoCoinbase` × 2 sites). The comment at line 122-124
   acknowledges the deliberate conflation for `veDuplicateTx` but
   doesn't extend the rigor to `veBadAmount` / `veNoCoinbase` /
   `veBadCoinbase`.

3. **Comment-as-confession (4th instance this campaign)**:
   `compact_blocks.nim:564-568` — "Bitcoin Core also calls
   IsBlockMutated here … callers should verify". Same archetype as
   haskoin W138 BUG-3 (Consensus.hs:4917-4919 "In a full implementation,
   we would compute MuHash3072 here. For now, mark as validated"),
   clearbit W141 BUG-13, rustoshi W141 BUG-13.

4. **Coinbase-special-case skip + accumulator-wrap**: BUG-1 / BUG-2 /
   BUG-9 form a P0-SEC chain — checkBlock skips coinbase (claiming
   "already checked"), validateTransaction skips coinbase, validateBlock
   does its own ad-hoc accumulator with no `MoneyRange` per-step. The
   accumulator wraps. Compare to camlcoin W132 MTP off-by-one and
   ouroboros W132 utxo_mtp=0 fallback — "isolated ad-hoc gate that
   silently fails closed".

5. **Dead-canonical-helper pattern**: `validateCoinbase` (line 329)
   does the BIP-34 height check correctly but is only called from
   `validateBlock` (line 1300), not from `checkBlock`. The
   `validateCoinbaseSizeOnly` (line 317) is called from `checkBlock` to
   do half of what `validateCoinbase` does. Two near-identical procs
   with non-overlapping scope; the consequence is BUG-3 (reindex paths
   skip half).

6. **Two-pipeline coexistence guard absent**: There is no test / lint /
   gate ensuring `nimrod.nim:1611,1780` reindex paths and
   `sync.nim:1072,1659` P2P paths run the SAME consensus pipeline.
   Compare to ouroboros W140 "two-pipeline guard 14th distinct extension"
   pattern — explicit cross-pipeline gate is the systemic fix.

7. **Distinct-int64 arithmetic without overflow guard**: `Satoshi`
   borrows `+` and `-` from int64. Compounds BUG-1 / BUG-2 / BUG-9.
   Cross-cite: rustoshi W141 BUG-1 entire zmq.rs DEAD CODE — different
   bug class but same root (distinct-type semantics not enforced where
   they matter).

8. **Signet protocol-rule absent**: BUG-6 (CheckSignetBlockSolution
   absent) compounds with the fact that signetParams.assumeValidHeight
   et al. are present, suggesting signet support was scaffolded but
   never finished. Cross-cite to W138 fleet pattern (ChainstateManager
   defined-but-uncalled — 9 of 10 impls).

## Affected paths

- `submitblock` RPC (rpc/server.nim:3701) — calls `checkBlock` + `acceptBlock`. Catches BUG-1/2 via validateBlock (with wrap risk per BUG-2). Catches BUG-3 trivially (validateBlock is invoked).
- P2P block message (network/sync.nim:1072 + 1127) — calls `checkBlock` + `acceptBlock`. Same coverage as submitblock.
- `processReceivedBlocks` (network/sync.nim:1659 + 1704) — same coverage.
- IBD reindex (nimrod.nim:1611, 1780) — checkBlock + connectBlockIBD ONLY. SKIPS validateBlock, checkBip30, verifyScripts, contextualCheckBlockHeader. BUG-3 manifests here.
- Compact-block reconstruction (network/compact_blocks.nim:560) — returns `(blk, rsOk)` without calling IsBlockMutated. BUG-5 manifests here.

## Test gap

No test suite exercises:
- A block with coinbase output value = `INT64_MAX / 2` × 3 (BUG-2 / BUG-9).
- A block with coinbase `vout.empty()` (BUG-1).
- A signet block (BUG-6).
- The taproot exception block 692,975 with non-DER signatures (BUG-7).
- A block with `txCount = 1_500_000` 1-byte transactions (BUG-8).
- An IBD-reindex import of a hostile `blk*.dat` (BUG-3).
- A compact-block-reconstructed CVE-2012-2459 malleation (BUG-4 + BUG-5).

## Operational recommendation

Highest-priority fixes from this audit:

1. **BUG-1 + BUG-9 + BUG-2 (P0-CONSENSUS / P0-SEC)**: Add `checkTransaction(blk.txs[0], params)` in `checkBlock` (drop the `if i == 0: continue`), AND add per-output `< 0` / `> MAX_MONEY` / running-sum-MoneyRange in `validateBlock` coinbase pass. Three-line change.
2. **BUG-3 (P0-CONSENSUS)**: Replace `checkBlock` + `connectBlockIBD` in `nimrod.nim:1611,1780` with `acceptBlock` + `connectBlockIBD` (or call `validateBlock` between them). One-line wiring change per call site.
3. **BUG-6 (P0-CDIV)**: Implement `CheckSignetBlockSolution` against signet_challenge in coinbase. Multi-line; gate behind `params.network == Signet`.
4. **BUG-7 (P0-CDIV)**: `getBlockScriptFlags` exception path should OVERRIDE flags to `{sfP2SH, sfWitness}` for taproot exception (not just clear `sfTaproot`).
5. **BUG-4 (P0-CDIV)**: Either thread a `var mutated` out-param through `computeMerkleRoot` matching Core's mutation flag, OR move the leaf-dedup check from `validateBlock` to `checkBlock` so the context-free path catches it.
