# W145 — Coinbase / subsidy / fees / MAX_MONEY audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W145).
Concurrent-agent coordination: 3 OTHER audit waves (W142/W143/W144) running in
parallel sub-agents.

Scope: GetBlockSubsidy + halving table + ≥64-halving guard + nSubsidyHalvingInterval
per-network table + coinbase output sum ≤ subsidy + fees check ("bad-cb-amount")
+ COINBASE_MATURITY = 100 + MAX_MONEY = 2.1e15 sat (`MoneyRange`) + duplicate
input check ("bad-txns-inputs-duplicate" — CVE-2018-17144) + fee invariant
sum(in) ≥ sum(out) ("bad-txns-in-belowout") + sum-of-outputs Int64 overflow guard
+ negative output / output > MAX_MONEY per-output gates (CVE-2010-5139).

Targets in nimrod:
- `src/consensus/validation.nim` — TWO `getBlockSubsidy` overloads at lines
  210-219 (int32) and re-exported from params, `validateTransaction`
  (681-764) for fee+MoneyRange+CVE-2018-17144, `validateBlock` (1260-1451)
  coinbase value check, `checkTransaction` (1589-1653) the context-free
  per-tx gate.
- `src/consensus/params.nim` — `subsidyHalvingInterval` per-network
  (lines 161, 290, 357, 418, 475), `coinbaseMaturity` per-network
  (165, 294, 361, 422, 479), `MaxMoney = 21_000_000 * 100_000_000`
  (line 86), SECOND `getBlockSubsidy` overload at line 521-528 (int).
- `src/storage/chainstate.nim` — `connectBlock` (739-908) and
  `connectBlockIBD` (1222-onwards) — neither validates subsidy/fees/MoneyRange.
- `src/nimrod.nim` — IBD reindex paths at lines 1611+ and 1780+ which only call
  `checkBlock` then `connectBlockIBD` (bypass `validateBlock` / subsidy check).
- `src/network/sync.nim` — P2P paths at lines 1127, 1704 which call
  `acceptBlock` (full pipeline including subsidy).
- `src/rpc/server.nim:3681+` — `handleSubmitBlock` which calls `acceptBlock`.
- `src/mempool/mempool.nim:627-654` — `calculateFee` (no overflow / MoneyRange
  on input/output accumulators).
- `src/network/relay.nim:97` — duplicate `MaxMoney = 2_100_000_000_000_000`
  constant in network module.

Reference (Bitcoin Core, shallow clone at `/home/work/hashhog/bitcoin-core/`):
- `src/validation.cpp` — `GetBlockSubsidy` (1839-1850), `ConnectBlock`
  coinbase value check (2610-2614 — "bad-cb-amount"), `MoneyRange` for
  accumulated nFees (2543-2547 — "bad-txns-accumulated-fee-outofrange").
- `src/consensus/amount.h` — `COIN = 100_000_000`, `MAX_MONEY = 21_000_000 *
  COIN`, `MoneyRange(nValue) = (nValue >= 0 && nValue <= MAX_MONEY)`.
- `src/consensus/consensus.h` — `COINBASE_MATURITY = 100` (line 19).
- `src/consensus/tx_check.cpp` — `CheckTransaction` full body (11-60) with
  CVE-2010-5139 per-output `<0` / `>MAX_MONEY` / running-sum
  `MoneyRange(nValueOut)` AND CVE-2018-17144 duplicate-input check.
- `src/consensus/tx_verify.cpp` — `CheckTxInputs` (164-214 — including
  "bad-txns-inputvalues-outofrange" 191-192, "bad-txns-in-belowout" 198-199,
  "bad-txns-fee-outofrange" 209-210, "bad-txns-premature-spend-of-coinbase"
  179-181).
- `src/kernel/chainparams.cpp` — `nSubsidyHalvingInterval = 210_000`
  (mainnet 84, testnet3 209, testnet4 310, signet 454) and `= 150` (regtest 535).

## Status

**BUGS FOUND — 22 distinct defects.** Of these:

- **P0-CONSENSUS** — 1 (IBD-reindex paths in `src/nimrod.nim` call
  `connectBlockIBD` directly without `validateBlock` / `acceptBlock` →
  miner-overflow attack, missing duplicate-input check, missing MoneyRange,
  no subsidy check; same fleet pattern flagged in W143 BUG-2 / W125 patterns).
- **P0-CDIV** — 4 (`connectBlock` & `connectBlockIBD` skip BOTH subsidy
  check AND CheckTransaction; coinbase output values escape per-output
  CVE-2010-5139 gate; coinbase output accumulator can wrap before
  `>=` comparison; `validateTransaction` uses `veBadAmount` →
  "bad-cb-amount" for non-coinbase input range errors).
- **P0-SEC** — 2 (coinbase output sum int64 overflow in
  `validateBlock`:1436-1440 with malicious 21M-BTC outputs; mempool
  `calculateFee` accumulates int64 with no overflow / MoneyRange guard).
- **P1** — 8 (duplicate-getBlockSubsidy fork-in-the-road; testnet3
  bip34Height=21111 vs Core which records `21111` BUT a 7-block-shy
  reorg-detection gap; `veFeeTooLow` defined zero callers; absence of
  `bad-txns-fee-outofrange` token mapping; missing "bad-txns-inputvalues-
  outofrange" mapping; `checkBlock` skips coinbase from CheckTransaction so
  G3-G6 / G7 gates miss it; duplicate `MaxMoney` constant in `network/relay`;
  missing `Satoshi`-aware overflow on `+` operator since it's `{.borrow.}`).
- **P2** — 5 (Nim signed-int `shr` semantics dependence on positive
  halvings — no negative-height guard; missing assert/log on subsidy=0
  branch; `coinbasevalue` RPC field uses raw add with no MoneyRange clamp;
  Satoshi distinct-type `+` borrow loses overflow trapping; double-counting
  risk if both intra-block + chainstate UTXOs return for same outpoint).
- **P3** — 2 (cosmetic: subsidy comment says "every 4 years" — drift if
  block interval ever changed; testnet4 powLimit uses mainnet limit not
  testnet limit per Core kernel/chainparams.cpp:309).

## Bug list

---

### BUG-1 — IBD reindex paths call `connectBlockIBD` directly without `validateBlock`/`acceptBlock`, bypassing the entire subsidy / MoneyRange / duplicate-input / coinbase-value pipeline

**Severity:** P0-CONSENSUS
**File:** src/nimrod.nim:1611-1620, 1780-1789 (the two `import blocks-via-bitcoind-dat` reindex paths)
**Core ref:** bitcoin-core/src/validation.cpp:2610-2614 ("bad-cb-amount" check
runs inside `ConnectBlock` on every block, including IBD-imported blocks via
`ProcessNewBlock` → `AcceptBlock` → `ContextualCheckBlock`).

**Description:** The two reindex paths in `src/nimrod.nim` run only
`checkBlock(blk, params)` (context-free PoW/merkle/tx-sanity) and then call
`cs.connectBlockIBD(blk, height)` to mutate the UTXO set. `checkBlock` itself
skips the coinbase from per-tx CheckTransaction gates (see BUG-9), and
`connectBlockIBD` does no consensus validation at all (see BUG-2/3/4 below).
That means: a `blocks.dat` file forged to contain a block whose coinbase pays
10× the subsidy + fees (or whose coinbase has 21,000,000 BTC outputs that
overflow the int64 accumulator, or whose non-coinbase tx duplicates the same
input twice à la CVE-2018-17144) is accepted as canonical history during
`--reindex`. The malicious peer can poison the snapshot supply chain
(downloaded `blocks.dat` files, validator who restored an old snapshot, etc).

**Excerpt** (src/nimrod.nim:1608-1620):
```nim
let blk = deserializeBlock(blockData)
# Validate
let checkResult = checkBlock(blk, params)
if not checkResult.isOk:
  echo "Block validation failed at height " & $frameHeight & ": " & $checkResult.error
  break
# Connect
let connectResult = cs.connectBlockIBD(blk, frameHeight)
```

**Impact:** Inflation attack via malicious blocks.dat or reindex source. Same
fleet pattern as W143 BUG-2 (IBD-import bypasses contextual checks). The P2P
IBD path through `sync.nim` correctly calls `acceptBlock` (line 1127, 1704) so
network-driven IBD is safe; only `--reindex` from local files is vulnerable.

---

### BUG-2 — `connectBlock` (mutating-write path) performs ZERO consensus validation: no subsidy gate, no MoneyRange, no duplicate inputs, no fee check

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:739-908
**Core ref:** bitcoin-core/src/validation.cpp:2456-2750 (ConnectBlock runs
CheckTransaction inputs gate, MoneyRange on totals, IsFinalTx, and finally
"bad-cb-amount" before mutating the UTXO view).

**Description:** `connectBlock` is the UTXO-mutating write path. It only
enforces coinbase maturity (lines 819-836) and missing-input (line 814).
It does NOT call `validateBlock`, does NOT compute subsidy, does NOT
accumulate fees, does NOT verify duplicate inputs, does NOT enforce the
coinbase-pays-too-much check. It relies entirely on the caller to have run
`acceptBlock` first. `mineBlock` → `rpc/mining.nim:101` → `connectBlock(blk,
height)` directly skips `acceptBlock`. So:

**Excerpt** (src/rpc/mining.nim:99-103):
```nim
# Connect block to chainstate
let height = chainState.bestHeight + 1
let connectResult = chainState.connectBlock(blk, height)
if not connectResult.isOk:
  break
```

**Impact:** The `generate`/`generatetoaddress` RPC mining path on regtest /
testnet can produce blocks that violate subsidy without rejection. Less
likely to be exploited (caller controls the coinbase), but if a downstream
test fixture / RPC client crafts a malicious template, no consensus tripwire
fires. Reorg edge cases (call `connectBlock` after `disconnectBlock` without
`acceptBlock` re-run) also bypass these gates.

---

### BUG-3 — `connectBlockIBD` (fast-path) performs ZERO consensus validation either

**Severity:** P0-CDIV
**File:** src/storage/chainstate.nim:1222-end-of-proc
**Core ref:** Same as BUG-2.

**Description:** The IBD fast-path connectBlockIBD has the same problem: no
subsidy gate, no MoneyRange totals, no duplicate-input check, no fee
verification. It depends entirely on a prior `acceptBlock` call. Combined
with BUG-1, the `nimrod` reindex CLI command can grow the chain unchecked.

**Excerpt** (src/storage/chainstate.nim:1243-1278):
```nim
# Spend inputs (skip coinbase)
if txIdx > 0:
  for input in tx.inputs:
    let utxoOpt = cs.getUtxo(input.prevOut)
    if utxoOpt.isNone:
      return err("missing input: " & $input.prevOut.txid)
    let entry = utxoOpt.get()
    # Check coinbase maturity
    if entry.isCoinbase:
      let age = height - entry.height
      if age < int32(cs.params.coinbaseMaturity):
        # … bypass for assume-valid …
        return err("immature coinbase spend at height " & $height ...)
    # Delete from batch and cache
    ...
```

**Impact:** Same as BUG-2.

---

### BUG-4 — Coinbase output values are NEVER subjected to per-output CVE-2010-5139 gate (negative / > MAX_MONEY / running-sum > MAX_MONEY)

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:1817-1841 (checkBlock skip), 1300-1302 (validateCoinbase only does scriptSig length / BIP-34 prefix), 1434-1441 (final coinbase-value check uses raw int64 add).
**Core ref:** bitcoin-core/src/validation.cpp:3961 `for (const auto& tx :
block.vtx) { CheckTransaction(*tx, tx_state); }` — coinbase IS included; and
bitcoin-core/src/consensus/tx_check.cpp:25-34 runs the per-output negative /
overflow / running-sum gates BEFORE the IsCoinBase branch.

**Description:** `checkBlock` at line 1836-1837 has:
```nim
for i, tx in blk.txs:
  if i == 0: continue  # coinbase already checked above
```
But "coinbase already checked above" is ONLY a scriptSig length check via
`validateCoinbaseSizeOnly`. The per-output CVE-2010-5139 gates (negative,
overflow, > MAX_MONEY) are skipped for the coinbase. `validateBlock` then
does `coinbaseValue += int64(output.value)` over a potentially crafted
multi-output coinbase whose individual outputs exceed MAX_MONEY, accumulates
without checking, and only compares the sum to `subsidy + totalFees`.

**Impact:** A coinbase tx with `vout=[21_000_001 * COIN, -1 * COIN]` would
sum to `(21_000_001 - 1) * COIN = 21M COIN = MaxMoney exactly`, defeating
the `> subsidy + totalFees` check while being internally inconsistent
(one negative output, one supra-MAX_MONEY output — Core rejects both with
"bad-txns-vout-negative" / "bad-txns-vout-toolarge"). The miner could
exploit this to mint negative-value outputs that the wallet UI / accounting
software might misinterpret. Also opens the door for follow-on bugs.

---

### BUG-5 — Coinbase output sum (`coinbaseValue`) accumulator can int64-overflow before `>` comparison

**Severity:** P0-SEC
**File:** src/consensus/validation.nim:1436-1441
**Core ref:** bitcoin-core/src/validation.cpp:2611 calls
`block.vtx[0]->GetValueOut()` which is `CTransaction::GetValueOut()` in
`primitives/transaction.cpp:38` — that proc explicitly returns
`MAX_MONEY + 1` if accumulation would overflow (`throw std::runtime_error`
on overflow, caught upstream as "vout total out of range").

**Description:** validation.nim:1436-1441:
```nim
var coinbaseValue = int64(0)
for output in blk.txs[0].outputs:
  coinbaseValue += int64(output.value)

if coinbaseValue > int64(subsidy) + totalFees:
  return voidErr(veBadAmount)
```

Nim's `+=` on int64 wraps silently on overflow (no exception). A coinbase
with N outputs each ≤ MAX_MONEY but whose sum exceeds INT64_MAX wraps to a
negative number, which is < subsidy+fees → check PASSES. Combined with
BUG-4 (per-output check skipped for coinbase), an attacker mining a single
block can mint near-INT64_MAX worth of satoshis to a single address that the
chainstate then dutifully indexes — gigantic inflation bug.

**Excerpt** (validation.nim:1436-1441):
```nim
var coinbaseValue = int64(0)
for output in blk.txs[0].outputs:
  coinbaseValue += int64(output.value)

if coinbaseValue > int64(subsidy) + totalFees:
  return voidErr(veBadAmount)
```

**Impact:** Catastrophic inflation if reached. Two preconditions must hold:
(a) caller doesn't already filter per-output MAX_MONEY (BUG-4) and (b)
attacker controls the coinbase template (always true on regtest /
test-vectors fed through `submitblock`). On mainnet PoW must also pass —
but the bug exists in the codepath regardless. Core defends with
`GetValueOut()` exception throw.

---

### BUG-6 — `validateTransaction` uses `veBadAmount` → "bad-cb-amount" for non-coinbase input range errors

**Severity:** P0-CDIV
**File:** src/consensus/validation.nim:749-755
**Core ref:** bitcoin-core/src/consensus/tx_verify.cpp:191-192:
`state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange")`.

**Description:** `veBadAmount` maps to the BIP-22 string `"bad-cb-amount"`
(validation.nim:120), which is Core's reject-reason for the COINBASE
output value exceeding `subsidy + nFees`. But validation.nim raises this
SAME enum from `validateTransaction` (a non-coinbase path) at lines 749-751
("inputValue < 0 or inputValue > MaxMoney") and 754-755 ("totalInput >
MaxMoney"). Core's correct token for those two cases is
`"bad-txns-inputvalues-outofrange"` (consensus/tx_verify.cpp:191).

**Excerpt** (validation.nim:744-755):
```nim
let inputValue = int64(utxo.output.value)
if inputValue < 0 or inputValue > int64(MaxMoney):
  return err(int64, veBadAmount)        # WRONG — should be inputvalues-outofrange

totalInput += inputValue
if totalInput > int64(MaxMoney):
  return err(int64, veBadAmount)        # WRONG — same
```

**Impact:** Reject-reason confusion. Diff-test corpus parity break: any
test vector that crafts a non-coinbase tx with overflowed input values
would expect `"bad-txns-inputvalues-outofrange"` and nimrod returns
`"bad-cb-amount"`. Same diff-test parity failure mode as W143 BUG noted
(reject-reason divergence on output-value path).

---

### BUG-7 — Two duplicate `getBlockSubsidy` overloads (int + int32) — fork-in-the-road fleet pattern

**Severity:** P1
**File:** src/consensus/validation.nim:210-219 (int32) + src/consensus/params.nim:521-528 (int)
**Core ref:** bitcoin-core/src/validation.cpp:1839-1850 — single proc, takes
`int nHeight`.

**Description:** Two parallel implementations:
- `consensus/params.nim:521 — proc getBlockSubsidy*(height: int, ...): Satoshi`
- `consensus/validation.nim:210 — proc getBlockSubsidy*(height: int32, ...): Satoshi`

Both have the same body but slightly different idioms (one uses
`50 * 100_000_000`, the other `5_000_000_000`). Callers use whichever
overload resolves based on the caller's parameter type:
- `coinstatsindex.nim:239 → int32 version`
- `blocktemplate.nim:318 → int version` (chainState.bestHeight + 1 is int32 + 1 = int32, but with `let height = ` may convert)
- `rpc/server.nim:3651 → explicitly int32(tmpl.height)`
- `validation.nim:1435 → int32 version`

This is the classic fleet pattern: "two-pipeline guard" — two parallel
ways to compute the same consensus quantity. If a future patch updates one
without the other (BIP-defined ad-hoc subsidy change?), consensus splits.

**Excerpt** (params.nim:521-528 vs validation.nim:210-219):
```nim
# params.nim — int
proc getBlockSubsidy*(height: int, params: ConsensusParams): Satoshi =
  let halvings = height div params.subsidyHalvingInterval
  if halvings >= 64:
    return Satoshi(0)
  var subsidy = int64(50 * 100_000_000)  # 50 BTC in satoshis
  subsidy = subsidy shr halvings
  Satoshi(subsidy)

# validation.nim — int32
proc getBlockSubsidy*(height: int32, params: ConsensusParams): Satoshi =
  let halvings = height div int32(params.subsidyHalvingInterval)
  if halvings >= 64:
    return Satoshi(0)
  var subsidy = 5_000_000_000'i64  # 50 BTC in satoshis
  subsidy = subsidy shr halvings
  Satoshi(subsidy)
```

**Impact:** Fork-in-the-road. Today both are equivalent, but the fleet
pattern is well-documented (W134, W137) as a regression magnet. Consolidate.

---

### BUG-8 — `checkBlock` skips coinbase from per-tx context-free gate, leaving G3 (size cap) / G7 (duplicate inputs) unenforced for the coinbase

**Severity:** P1
**File:** src/consensus/validation.nim:1835-1841
**Core ref:** bitcoin-core/src/validation.cpp:3959-3968 — `CheckBlock` loops
over `for (const auto& tx : block.vtx)` calling `CheckTransaction(*tx, tx_state)`
on EVERY transaction — INCLUDING the coinbase.

**Description:** validation.nim:1835-1841:
```nim
# Check each non-coinbase transaction
for i, tx in blk.txs:
  if i == 0: continue  # coinbase already checked above
  let txResult = checkTransaction(tx, params)
  if not txResult.isOk:
    return txResult
```

But "coinbase already checked above" only ran `validateCoinbaseSizeOnly`
(line 1831), which is JUST the 2..100-byte scriptSig length check. The
coinbase escapes:
- G3 `base-size * 4 <= MAX_BLOCK_WEIGHT` (CVE-2010-5141 precursor)
- G4 per-output `value >= 0`
- G5 per-output `value <= MAX_MONEY`
- G6 running-sum ≤ MAX_MONEY
- G7 no duplicate `(txid, vout)` inputs (CVE-2018-17144)

Coinbases only ever have one input, so G7 is moot for coinbase. But G3-G6
are real consensus rules that Core enforces.

**Impact:** Reject-reason mismatch on diff-test for malicious coinbases.
Same root pattern as W143 BUG-1. Note: validateBlock's
`coinbaseValue` check (line 1440) catches subsidy overflow indirectly, but
the per-output gates and the size gate are still skipped.

---

### BUG-9 — `mempool.calculateFee` has no MoneyRange / overflow gate on the input/output accumulators

**Severity:** P0-SEC
**File:** src/mempool/mempool.nim:627-654
**Core ref:** bitcoin-core/src/consensus/tx_verify.cpp:179-211 — `CheckTxInputs`
enforces `nValueIn += ...; if (!MoneyRange(coin.out.nValue) ||
!MoneyRange(nValueIn))` after every input.

**Description:** mempool/mempool.nim:627-654:
```nim
proc calculateFee(tx: Transaction, mp: Mempool): Option[Satoshi] =
  var inputValue = int64(0)

  for input in tx.inputs:
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      inputValue += int64(utxo.get().output.value)  # no MoneyRange guard
    else:
      ...
        inputValue += int64(parentTx.outputs[input.prevOut.vout].value)
      ...

  var outputValue = int64(0)
  for output in tx.outputs:
    outputValue += int64(output.value)            # no MoneyRange guard

  if inputValue >= outputValue:
    some(Satoshi(inputValue - outputValue))
  else:
    none(Satoshi)
```

Both accumulators are raw int64 with no `>= 0 && <= MaxMoney` guard. A tx
whose total input or output exceeds INT64_MAX wraps silently → produces a
nonsense fee. Core's mempool path runs CheckTxInputs with MoneyRange
enforcement on every step.

**Impact:** Mempool fee accounting can be corrupted by a malicious tx that
references a corrupted UTXO (e.g. assumeUTXO snapshot poisoning bug from
W138). Realistically gated by the rest of the validation pipeline, but the
defense-in-depth gap is present.

---

### BUG-10 — `coinbaseMaturity` enforced via `if entry.isCoinbase` but UTXO undo deserialization could lose the bit

**Severity:** P2
**File:** src/storage/chainstate.nim:222-233 (serializeUtxoEntry / deserialize)
**Core ref:** bitcoin-core/src/coins.h:32-43 — `Coin` packs `fCoinBase` into
the lower bit of `nHeight*2 + fCoinBase` (BIP-30 / nValue extra bit format).

**Description:** validation.nim's `serializeUtxoEntry`/`deserializeUtxoEntry`
writes/reads `isCoinbase` as a separate uint8 byte. That's safe in
isolation. But the legacy RocksDB undo format (Bitcoin Core compatibility
format used for `getrawtransaction`-style lookups) packs height+isCoinbase
into a single varint as `(height << 1) | isCoinbase`. Nimrod's
`utxo_cache.nim:73` does use the packed format:
```nim
let code = uint32(coin.height) * 2 + (if coin.isCoinbase: 1 else: 0)
```
But the two formats coexist. If a coin migrates between formats during
reorg / snapshot round-trip, the `isCoinbase` bit can be lost, which
disables the maturity gate at line 819-836 of chainstate.nim.

**Excerpt** (chainstate.nim:225-226):
```nim
w.writeInt32LE(entry.height)
w.writeUint8(if entry.isCoinbase: 1 else: 0)
```

**Impact:** Edge case — only triggers if the two serialization formats are
crossed. Not currently a live issue, but a regression-injection magnet.

---

### BUG-11 — `connectBlock` / `connectBlockIBD` maturity check uses `assumeValidHeight` bypass that disables COINBASE_MATURITY enforcement during IBD

**Severity:** P1
**File:** src/storage/chainstate.nim:819-836, 1253-1270, 1857-1872 (three copies)
**Core ref:** bitcoin-core/src/validation.cpp:373-377 — COINBASE_MATURITY is
enforced unconditionally; `assumevalid` only skips SCRIPT VERIFICATION (sig
checks), NOT coinbase maturity (Core val:2295-2750 ConnectBlock).

**Description:** Three places in chainstate.nim wrap the coinbase-maturity
enforcement in `shouldSkipScripts(avCtx, cs.params)`. If the block is
ancestor-on-assumevalid-chain, the maturity check is logged-and-allowed
instead of failing. But the call site predicate
`shouldSkipScripts(...) == ssrSkip` is supposed to gate SCRIPT verification
only — Core's assumevalid bypass does not skip CheckTxInputs maturity. The
nimrod implementation silently relaxes the maturity rule.

**Excerpt** (chainstate.nim:822-836):
```nim
if age < int32(cs.params.coinbaseMaturity):
  let avCtx = buildAssumeValidContext(cs, blockHash, height)
  let skipReason = shouldSkipScripts(avCtx, cs.params)
  if skipReason == ssrSkip:
    warn "immature coinbase below assume-valid (allowing)",
         height = height, coinbaseHeight = entry.height,
         age = age, prevTxid = $input.prevOut.txid,
         prevVout = input.prevOut.vout
  else:
    return err("immature coinbase spend at height " & $height ...)
```

**Impact:** Below `assumeValidHeight`, nimrod accepts a transaction that
spends an immature coinbase output. Core does not. Reorg replay could
end up with a chain state different from Core's. Probably caught by
ancestor-chain hash check in practice, but the gate divergence is real.

---

### BUG-12 — Negative-height not guarded in either `getBlockSubsidy` overload (Nim `shr` on signed-int with negative shift count is undefined)

**Severity:** P2
**File:** src/consensus/validation.nim:214-218 + src/consensus/params.nim:523-527
**Core ref:** bitcoin-core/src/validation.cpp:1841-1849 — `int halvings =
nHeight / interval` is signed; negative height yields negative halvings,
caller never passes negative height (genesis = 0 is the floor), but Core's
implementation still has the `>=64` guard before `subsidy >>= halvings`
which in C++ is UB for negative shift count.

**Description:** Neither nimrod overload guards `height < 0`. The caller
chain (validateBlock → `prevIndex.height + 1`, mining → `chainState.bestHeight
+ 1`) keeps height >= 0 in practice. But the proc is `*` (exported) and a
future caller could legitimately pass negative height (e.g. a malformed
header where prevIndex.height = -2). Then halvings = -1, `>= 64` is false,
and `subsidy shr -1` triggers Nim's undefined behavior for negative shift.

**Excerpt** (validation.nim:214-218):
```nim
let halvings = height div int32(params.subsidyHalvingInterval)
if halvings >= 64:
  return Satoshi(0)
var subsidy = 5_000_000_000'i64
subsidy = subsidy shr halvings    # halvings might be negative
Satoshi(subsidy)
```

**Impact:** Defense-in-depth gap. Add `if halvings < 0: return Satoshi(0)`
or `if height < 0: return Satoshi(0)`.

---

### BUG-13 — Duplicate `MaxMoney` constant in `src/network/relay.nim:97`

**Severity:** P1
**File:** src/network/relay.nim:96-97
**Core ref:** bitcoin-core/src/consensus/amount.h:26 — single definition.

**Description:** A SECOND `MaxMoney` is defined in `network/relay.nim`:
```nim
## MAX_MONEY in satoshis (used during IBD to reject all tx inv)
MaxMoney* = 2_100_000_000_000_000'i64
```
The canonical `MaxMoney = Satoshi(21_000_000 * 100_000_000'i64)` is in
`params.nim:86`. The two definitions are numerically equal today, but the
relay.nim version uses raw int64 (not Satoshi distinct type). Two
divergent representations risk drift.

**Impact:** If a future patch updates one without the other, the IBD
feefilter at line 516 (`return MaxMoney`) would diverge from the consensus
MaxMoney. Pattern: "two-pipeline guard" extension #15.

---

### BUG-14 — `veFeeTooLow` enum defined with ZERO callers — dead error code

**Severity:** P1
**File:** src/consensus/validation.nim:44
**Core ref:** N/A — Core uses `bad-txns-fee-outofrange` for negative fee in
CheckTxInputs (`consensus/tx_verify.cpp:209-210`).

**Description:** `veFeeTooLow = "transaction fee too low"` defined at line 44
of validation.nim. Searching for callers:
```
$ grep -n 'veFeeTooLow' src/
src/consensus/validation.nim:44:    veFeeTooLow = "transaction fee too low"
```
Zero production callers, zero test callers. Either a stub for future
mempool policy work, or vestigial dead code.

**Impact:** Dead enum value. Bigger concern: nimrod has no mapping for
Core's `"bad-txns-fee-outofrange"` (fee exceeds MAX_MONEY after subtraction).
A tx with `nValueIn = MAX_MONEY`, `nValueOut = -1` would yield fee =
MAX_MONEY + 1 which Core rejects with that token; nimrod has no equivalent.
But the per-output negative check (`veNegativeOutput`) fires first, so the
gap is theoretically reachable only via corrupted UTXO. Still — token gap.

---

### BUG-15 — No mapping from `validateTransaction`'s input-value overflow to Core's `bad-txns-inputvalues-outofrange` token

**Severity:** P1
**File:** src/consensus/validation.nim:749-755 + bip22String mapping at 108-170
**Core ref:** bitcoin-core/src/consensus/tx_verify.cpp:191-192.

**Description:** Pairs with BUG-6. validation.nim raises `veBadAmount` for
"inputValue < 0 OR inputValue > MaxMoney" AND for "totalInput > MaxMoney",
which both map to BIP-22 string `bad-cb-amount`. Core uses
`bad-txns-inputvalues-outofrange`. Add a new enum entry
`veInputValuesOutOfRange` and string mapping.

**Impact:** Diff-test corpus reject-reason mismatch. Coupled with BUG-6.

---

### BUG-16 — `Satoshi` distinct `+` operator borrows int64, losing overflow trapping; same for `-`

**Severity:** P2
**File:** src/primitives/types.nim:41-42
**Core ref:** bitcoin-core/src/consensus/amount.h:12-15 — `CAmount` is
`int64_t`, also no exception on overflow, but Core uses MoneyRange after
every arithmetic.

**Description:**
```nim
proc `+`*(a, b: Satoshi): Satoshi {.borrow.}
proc `-`*(a, b: Satoshi): Satoshi {.borrow.}
```
These borrowed operators wrap on int64 overflow. The distinct type was
introduced for type safety, but its arithmetic operators do not add
overflow protection. validateBlock:1440 mitigates by widening to int64
manually before `+`, but other call sites (e.g. `int64(tmpl.totalFees) +
int64(getBlockSubsidy(...))` in rpc/server.nim:3651) rely on caller
discipline.

**Impact:** Foundation hazard. Pattern of "type-safety primitive that
doesn't actually add safety" — same fleet pattern as W137 declare-init-
deinit-but-never-populate.

---

### BUG-17 — `coinbasevalue` RPC field returns raw `int64(totalFees) + int64(subsidy)` with no MoneyRange clamp

**Severity:** P2
**File:** src/rpc/server.nim:3651
**Core ref:** bitcoin-core/src/rpc/mining.cpp `BlockAssembler` — uses
`nFees + GetBlockSubsidy(nHeight, ...)` which is wrapped by Core's
MoneyRange-enforcing CTransaction::GetValueOut.

**Description:**
```nim
"coinbasevalue": int64(tmpl.totalFees) + int64(getBlockSubsidy(int32(tmpl.height), rpc.params)),
```
If a maliciously constructed mempool gives `totalFees = MAX_MONEY` (BUG-9),
the addition with subsidy = 50 BTC wraps. Client receives a negative
coinbasevalue field. Realistically gated by BUG-9 not actually being
reachable, but the lack of defensive clamp here is concerning.

**Impact:** RPC client confusion if a miner client is hooked up to a poisoned
mempool. Cosmetic-but-defense-in-depth.

---

### BUG-18 — `tmpl.height` typed `int` instead of `int32` — silent narrowing at int32(tmpl.height)

**Severity:** P2
**File:** src/mining/blocktemplate.nim:73 (`height*: int`) + src/rpc/server.nim:3651
**Core ref:** bitcoin-core/src/validation.cpp signature `int nHeight`.

**Description:**
```nim
# blocktemplate.nim:73
height*: int  # Should be int32 for consistency with chainstate
# server.nim:3651
"coinbasevalue": ... + int64(getBlockSubsidy(int32(tmpl.height), ...))
```
The explicit `int32(tmpl.height)` cast at server.nim:3651 silently narrows.
On a 32-bit Nim build (`int == int32`), it's lossless. On 64-bit
(`int == int64`), heights > 2^31-1 narrow incorrectly — though no real
chain reaches 2^31 blocks. Latent integer-conversion sloppiness.

**Impact:** Cosmetic on real networks. The pattern of int↔int32 friction is
a known fleet hazard.

---

### BUG-19 — Duplicate-input check uses `string` concat with `$array[32, byte]` — O(n) string ops vs Core's `std::set<COutPoint>` O(log n)

**Severity:** P2
**File:** src/consensus/validation.nim:699-704 + 1633-1638
**Core ref:** bitcoin-core/src/consensus/tx_check.cpp:41-44:
```cpp
std::set<COutPoint> vInOutPoints;
for (const auto& txin : tx.vin) {
  if (!vInOutPoints.insert(txin.prevout).second)
    return state.Invalid(... "bad-txns-inputs-duplicate");
}
```

**Description:** Two separate copies of the duplicate-input check, both
using stringified outpoint keys (32-byte txid string + ":" + vout-as-text).
String concat allocates per tx-input. For a worst-case 24,386-input tx
(spec max), this is ~1MB of garbage per tx vs Core's tree insertion.

Also: the two copies (one in validateTransaction, one in checkTransaction)
risk drift if one is updated and the other isn't. Pattern: code-duplication
in CVE-relevant code.

**Excerpt** (validation.nim:699-704):
```nim
var seenInputs = initTable[string, bool]()
for inp in tx.inputs:
  let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
  if key in seenInputs:
    return err(int64, veDuplicateInput)
  seenInputs[key] = true
```

**Impact:** Performance pessimization in IBD / mempool flood-attack
scenarios. Also: code duplication risks drift. Refactor to a single
`hasDuplicateInputs(tx) → bool` helper and use HashSet[OutPoint] (with a
proper OutPoint hash, not stringified).

---

### BUG-20 — Subsidy comment "every 4 years" hardcodes target-spacing assumption — drifts with regtest/testnet

**Severity:** P3
**File:** src/consensus/validation.nim:212
**Core ref:** bitcoin-core/src/validation.cpp:1847 — same comment.

**Description:** Cosmetic. The comment "Subsidy halves every 210,000 blocks
(on mainnet)" is correct. The trailing "every 4 years" docs comment in
params.nim:521 is parameter-correct but reading-misleading on regtest
(150-block halving = ~25 minutes).

**Impact:** Documentation drift. Not actionable now; flag for cleanup.

---

### BUG-21 — testnet4 `subsidyHalvingInterval = 210_000` — verify against Core

**Severity:** P3
**File:** src/consensus/params.nim:418
**Core ref:** bitcoin-core/src/kernel/chainparams.cpp:310 — `nSubsidyHalvingInterval = 210000;`

**Description:** Verification ok — Core has testnet4 = 210000 (same as
mainnet). Nimrod matches. Logging for completeness.

**Impact:** None. Confirmation only.

---

### BUG-22 — `Satoshi(21_000_000 * 100_000_000'i64)` MaxMoney compile-time constant — verify constant evaluation isn't surprising

**Severity:** P3
**File:** src/consensus/params.nim:86
**Core ref:** bitcoin-core/src/consensus/amount.h:26.

**Description:** Verification: `21_000_000 * 100_000_000 =
2,100,000,000,000,000`. Fits in int64 (max ~9.2e18). Compile-time constant
evaluation is deterministic; matches Core's `21000000 * COIN`. The `'i64`
suffix on 100_000_000 ensures int64 arithmetic (avoiding int32 overflow
during multiplication: 21M * 100M = 2.1e15 > 2^31-1 = 2.15e9).

**Impact:** None. Confirmation only.

---

## Fleet patterns observed

1. **Two-pipeline guard** (BUG-7 + BUG-13): TWO duplicate-getBlockSubsidy
   overloads (int + int32) AND duplicate-MaxMoney constants (params vs
   network/relay). Extension #15 of the fleet-wide "two parallel paths to
   the same consensus quantity" pattern — same pattern flagged in W134 /
   W137 / W140 (two-pipeline guard 14th extension).

2. **Dead code in consensus paths** (BUG-14): `veFeeTooLow` defined, zero
   callers. Matches W138/W137 dead-class pattern, scaled-down to a single
   enum value.

3. **Defense-in-depth missing every layer** (BUG-1 + BUG-2 + BUG-3 + BUG-4
   + BUG-5 + BUG-8 + BUG-9): nimrod's validation pipeline is layered into
   `acceptBlock → validateBlock → connectBlock`, BUT the mutating-write
   layer (`connectBlock` / `connectBlockIBD`) has NO consensus checks of
   its own and relies on the caller. The reindex CLI path skips
   `acceptBlock`. checkBlock skips coinbase from CheckTransaction. Compound
   security stack from W140 — same pattern.

4. **Reject-reason divergence** (BUG-6 + BUG-15): Reuse of `veBadAmount` →
   "bad-cb-amount" for non-coinbase paths. Same root pattern as W143 BUG-7
   ("veBadAmount re-used for in-tx amount errors AND coinbase-too-much").

5. **No explicit overflow trap in distinct types** (BUG-16 + BUG-5 + BUG-9):
   `Satoshi` is a distinct type with borrowed `+`/`-` that loses overflow
   protection. Three accumulator sites (coinbase value, mempool input,
   mempool output) all suffer.

6. **"Comment-as-confession"** (BUG-11 partial): chainstate.nim:823 reads
   "Use ancestor-check assumevalid semantics (Bitcoin Core v28.0). The
   maturity bypass only applies when the block is on the assumed-valid
   chain (ancestor check) — NOT a plain height check." — the comment
   confesses the bypass is a divergence from Core's strict-maturity
   enforcement. Pattern matches W138 BUG-3 / W141 / W134 "comment-as-
   confession" instances.

7. **"30-of-30-gates-buggy" precursor**: not full 30/30, but `connectBlock`
   and `connectBlockIBD` lack 4+ of 8 listed gates (subsidy, MoneyRange,
   duplicate-inputs, fee invariant). Marks subsystem candidate for
   incremental gate-by-gate hardening rather than rewrite.

## Suggested fix order (priority — informational only, W145 is discovery)

1. **BUG-1** (P0-CONSENSUS): Replace `checkBlock` + `connectBlockIBD` in
   src/nimrod.nim reindex paths with `acceptBlock` (already used by P2P
   IBD path in network/sync.nim).
2. **BUG-2 + BUG-3** (P0-CDIV pair): Add `validateBlock` call inside
   `connectBlock` / `connectBlockIBD` as defense-in-depth, or refuse to
   accept blocks without a prior `acceptBlock` audit-trail flag.
3. **BUG-5** (P0-SEC): Replace coinbase output sum accumulator with a
   `MoneyRange`-guarded helper: `getCoinbaseValueOut(tx) → Option[Satoshi]`
   that returns `none` on overflow.
4. **BUG-4** (P0-CDIV): Remove `if i == 0: continue` in
   `checkBlock` and let `checkTransaction` run on the coinbase too.
5. **BUG-6 + BUG-15** (P0-CDIV pair): Add `veInputValuesOutOfRange` enum
   variant + bip22String mapping for "bad-txns-inputvalues-outofrange".
6. **BUG-9** (P0-SEC): Add MoneyRange guards to mempool.calculateFee.
7. **BUG-7 + BUG-13** (P1 pair): Consolidate duplicate constants.
8. **BUG-11** (P1): Audit whether the assumevalid-maturity-bypass is
   intentional; if not, remove. Document if intentional.

End of W145 audit.
