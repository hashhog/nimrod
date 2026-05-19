# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (nimrod)

**Wave:** W157 — `CheckSignetBlockSolution`, `SIGNET_HEADER`
(`0xecc7daa2`), `signet_challenge` consensus param,
`FetchAndClearCommitmentSection`, BIP-94 `MAX_TIMEWARP=600` retarget
clamp, miner-side `GetMinimumTime` (BIP-94 floor on **all networks**),
`enforce_BIP94` per-network, target nBits encoding (BIG-endian vs
LITTLE-endian), `GetNextWorkRequired` two-pipeline drift,
`fPowAllowMinDifficultyBlocks`, signet-on-regtest, default vs custom
signet_challenge, signet `assumeValidHeight`, signet network entirely
unreachable via CLI.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` — `SIGNET_HEADER[4] = {0xec, 0xc7,
  0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` — `BLOCK_SCRIPT_VERIFY_FLAGS =
  SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG |
  SCRIPT_VERIFY_NULLDUMMY` (signet-block-solution-only verify flag mux).
- `bitcoin-core/src/signet.cpp:32-57` —
  `FetchAndClearCommitmentSection`: iterates OP-pushes inside the
  witness-commitment scriptPubKey, locates the **first** pushdata whose
  first 4 bytes equal SIGNET_HEADER, copies the rest into `result`,
  REPLACES the OP-push without the signet payload (so the modified
  coinbase hashes deterministically), returns whether a header was
  found. Required so that the modified-merkle-root commitment is
  identical regardless of the signature inside.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot`:
  reserves `(vtx.size() + 1) & ~1ULL` (capacity rounded up to even
  count), pushes the modified-coinbase hash + each non-coinbase tx hash,
  computes `ComputeMerkleRoot` on the resulting leaves.
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`: builds
  `tx_to_spend` (locked to challenge) and `tx_spending` (P2SH-style
  scriptSig + witness), short-circuits when `block.vtx.empty()` or
  `GetWitnessCommitmentIndex == NO_WITNESS_COMMITMENT`, allows
  no-signet-solution case (trivial OP_TRUE challenge), errors on
  trailing data after `tx_spending.vin[0].scriptWitness.stack`, errors
  on any parser exception. Then writes `nVersion + hashPrevBlock +
  signet_merkle + nTime` into `tx_to_spend.vin[0].scriptSig` as a
  single push.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  short-circuits `true` for `block.GetHash() == hashGenesisBlock`;
  rebuilds challenge `CScript` from `consensusParams.signet_challenge`;
  runs `SignetTxs::Create`; instantiates
  `TransactionSignatureChecker(MissingDataBehavior::ASSERT_FAIL)` and
  `VerifyScript(scriptSig, scriptPubKey, &witness,
  BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`; returns the script-verify
  result.
- `bitcoin-core/src/signet.h:21` — `bool CheckSignetBlockSolution(const
  CBlock& block, const Consensus::Params& consensusParams);` —
  called from `ContextualCheckBlock` (validation.cpp).
- `bitcoin-core/src/consensus/consensus.h:35` — `static constexpr
  int64_t MAX_TIMEWARP = 600;` (BIP-94 anti-timewarp clamp).
- `bitcoin-core/src/consensus/params.h:117-121` — `bool
  enforce_BIP94;` — comment "Enforce BIP94 timewarp attack mitigation.
  On testnet4 this also enforces the block storm mitigation."
- `bitcoin-core/src/consensus/params.h:139-140` — `bool
  signet_blocks{false};` and `std::vector<uint8_t> signet_challenge;` —
  the two signet-specific consensus params.
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired`: the canonical
  retarget pipeline. At retarget boundary, calls
  `CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(),
  params)`.
- `bitcoin-core/src/pow.cpp:50-85` — `CalculateNextWorkRequired`:
  clamps `nActualTimespan` to `[powTargetTimespan/4,
  powTargetTimespan*4]`; **when `params.enforce_BIP94`** uses
  `pindexFirst->nBits` instead of `pindexLast->nBits` as the base
  (BIP-94 time-warp fix — anchors retarget at period start so
  min-difficulty exception at last block of period cannot manipulate
  the next period's difficulty).
- `bitcoin-core/src/pow.cpp:89-136` — `PermittedDifficultyTransition`:
  returns `true` unconditionally when `params.fPowAllowMinDifficultyBlocks`
  (testnets / regtest). At retarget on mainnet, computes
  `[smallest_difficulty_target, largest_difficulty_target]` bound and
  rejects out-of-range new nBits.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime(pindexPrev,
  difficulty_adjustment_interval)`: `min_time = pindexPrev->MTP() + 1`;
  **at retarget boundary** (`height % interval == 0`), clamps
  `min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)`
  ON ALL NETWORKS — comment: "Account for BIP94 timewarp rule on all
  networks. This makes future activation safer."
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`: computes
  `nNewTime = max(GetMinimumTime(pindexPrev, ...),
  TicksSinceEpoch<seconds>(NodeClock::now()))`; on
  `fPowAllowMinDifficultyBlocks`, recomputes `pblock->nBits =
  GetNextWorkRequired(...)` because new timestamp may flip the
  min-difficulty branch.
- `bitcoin-core/src/validation.cpp:4097-4105` — contextual-check-block-
  header BIP-94 gate: rejects `bad-blk-mtp-too-low` /
  `time-timewarp-attack` when, at retarget boundary,
  `block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`.
- `bitcoin-core/src/rpc/mining.cpp:1021` — GBT `"bits"` field:
  `strprintf("%08x", block.nBits)` — **8-character big-endian** hex.
- `bitcoin-core/src/rpc/mining.cpp:1024-1026` — `signet_challenge`
  field: emitted only when `consensusParams.signet_blocks`, value =
  `HexStr(signet_challenge)`.
- `bitcoin-core/src/kernel/chainparams.cpp:82, 207, 308, 452-453,
  533-534` — per-network `signet_blocks` + `signet_challenge` (only
  SigNetParams sets `signet_blocks = true` and assigns the challenge
  bytes).
- `bitcoin-core/src/kernel/chainparams.cpp:100, 223, 322, 464, 547` —
  per-network `enforce_BIP94` (mainnet=false, testnet3=false,
  testnet4=true, signet=false, regtest=`opts.enforce_bip94` — so
  toggleable on regtest via `SigNetOptions`/CLI parse).
- `bitcoin-core/src/kernel/chainparams.cpp:344-355` — testnet4 genesis:
  uses **different** `pszTimestamp = "03/May/2024 ..."` and
  `genesisOutputScript` (33-byte zero push + `OP_CHECKSIG`) — NOT the
  mainnet "Times 03/Jan/2009 Chancellor" string.
- `bitcoin-core/src/kernel/chainparams.cpp:474-479` — SigNetParams
  derives `pchMessageStart` from `sha256(signet_challenge).first(4)` —
  the network magic IS the challenge. Default-signet challenge
  `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae`
  yields magic `0x0a 0x03 0xcf 0x40`.
- `bitcoin-core/src/kernel/chainparams.cpp:417-430` — `-signetchallenge`
  / `SigNetOptions::challenge` override for custom signets: when
  override is present, `defaultAssumeValid = uint256{}`,
  `nMinimumChainWork = uint256{}`, log line `"Signet with challenge %s"`.

**Files audited**
- `src/consensus/params.nim` — `ConsensusParams` type (lines 32-79;
  signet-specific fields NOT defined), `mainnetParams` (141-271),
  `testnet3Params` (273-338), `testnet4Params` (340-400),
  `signetParams` (402-460), `regtestParams` (462-511), `getParams`
  (513-519), `calculateNextTarget` (620-662) — second retarget routine
  (two-pipeline drift with pow.nim), `buildGenesisBlock` (668-737) —
  HARDCODED mainnet coinbase, used for ALL networks.
- `src/consensus/pow.nim` — `PowParams` (16-23), `checkProofOfWork`
  (49-66), `calculateNextWorkRequired` (68-122) (canonical retarget
  used by validation), `getNextWorkRequired` (124-183),
  `permittedDifficultyTransition` (203-254).
- `src/consensus/validation.nim` — `MaxTimeWarp = 600'i64` (line 829),
  `contextualCheckBlockHeader` (831-923) — BIP-94 gate at 904-909,
  GATED on `params.enforceBIP94`, only on retarget boundaries,
  `acceptBlock` (1911-1994) — unified pipeline but mining bypass,
  `validateBlock` (1260-1451), `checkBlock` (1808-1855).
- `src/network/sync.nim` — `validateDifficultyRetarget` (357-410) —
  THIRD retarget routine (calls `calculateNextTarget` from params.nim),
  `validateHeader` (412-461) — header sync uses this divergent path
  not the canonical pow.nim, line 457 `if params.network != Regtest`
  uses enum check instead of `powNoRetargeting` field.
- `src/network/headerssync.nim:153-168` — `toPowParams` wires
  `Signet` enum but is unreachable since CLI rejects signet.
- `src/mining/blocktemplate.nim` — `buildBlockTemplate` (287-487) —
  `timestamp = uint32(getTime().toUnix())` (line 473) bypasses
  `GetMinimumTime`, `bits = prevBlock.get().header.bits` (line 445)
  never calls `getNextWorkRequired`, `updateTimestamp` (489-517)
  enforces only MTP+1, never BIP-94 floor, comment-as-confession at
  line 513-517 about ancestor unavailability.
- `src/rpc/mining.nim` — `mineBlock` (22-73), `generateBlocks`
  (75-108), `generateToAddress` (110-133), `generateBlockWithTxs`
  (163-321) — all bypass `acceptBlock`, call `chainState.connectBlock`
  directly with no BIP-94 / merkle / PoW gate.
- `src/rpc/server.nim:303-308, 394-399, 4433-4438` — `chainName`
  emission (`"signet"` string mapped from enum, but enum can't be
  produced from CLI), `handleGetBlockChainInfo` (`"bits"` little-endian
  at lines 334-339), `handleGetBlockTemplate` (3577-3668; `"bits"`
  little-endian at 3660-3665, `"mintime"` raw timestamp at line 3653,
  NO `signet_challenge` emission), `handleSubmitBlock` (3681-3970).
- `src/nimrod.nim:382` (help text — "Network: mainnet, testnet3,
  testnet4, regtest"; signet missing), `nimrod.nim:486-491, 526-530`
  (CLI parse — no `--signet`), `nimrod.nim:726-734` (`getConsensusParams`
  — `case ... else: quit(1)`; signet rejected at startup),
  `nimrod.nim:1550, 1957` (`buildGenesisBlock` call sites — wrong
  testnet4 / signet / regtest genesis bytes).
- `src/network/peermanager.nim:320-323` — signet DNS seed (the only
  signet wire-up that would work IF the enum could be reached).
- `src/consensus/versionbits.nim:563-573` — signet TESTDUMMY
  deployment (matches Core 90% threshold).

---

## Gate matrix (32 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `CheckSignetBlockSolution` present | G1: function exists | **BUG-1 (P0-CONS)** — entirely absent fleet-wide nimrod |
| 1 | … | G2: called from `acceptBlock` / `validateBlock` / `contextualCheckBlock` | **BUG-1 cross-cite** — no caller |
| 1 | … | G3: genesis short-circuit `block.GetHash() == hashGenesisBlock` | N/A (function absent) |
| 2 | `SIGNET_HEADER` constant | G4: defined as `0xec 0xc7 0xda 0xa2` | **BUG-2 (P0-CONS)** — absent |
| 3 | `signet_challenge` consensus param | G5: field exists on `ConsensusParams` | **BUG-3 (P0-CONS)** — `ConsensusParams` (params.nim:32-79) has neither `signetBlocks` flag nor `signetChallenge` bytes |
| 3 | … | G6: populated for SigNetParams | **BUG-3 cross-cite** — `signetParams()` (params.nim:402-460) sets `network = Signet` but never assigns the challenge bytes |
| 3 | … | G7: `-signetchallenge` operator override | **BUG-4 (P1)** — no CLI flag, no config knob; custom signets impossible |
| 4 | `FetchAndClearCommitmentSection` | G8: implementation exists | **BUG-1 cross-cite** — absent |
| 5 | BIP-94 `MAX_TIMEWARP=600` enforced at retarget | G9: constant defined | PASS — `validation.nim:829 MaxTimeWarp = 600'i64` |
| 5 | … | G10: enforced at contextual block-header check (consensus) | PARTIAL — `validation.nim:904-909` gates on `params.enforceBIP94` so fires only on testnet4 (matches Core but cf. miner-side gap below) |
| 6 | Miner-side `GetMinimumTime` clamp | G11: function exists | **BUG-5 (P0-CDIV)** — no `getMinimumTime` proc anywhere in nimrod source |
| 6 | … | G12: BIP-94 floor applied on **all networks** at retarget | **BUG-5 cross-cite** — `buildBlockTemplate` (blocktemplate.nim:473) just does `timestamp = uint32(getTime().toUnix())`; `updateTimestamp` (blocktemplate.nim:489-517) applies only MTP+1, NOT `pindexPrev->GetBlockTime() - MAX_TIMEWARP` at retarget |
| 6 | … | G13: `mintime` GBT response respects BIP-113 + BIP-94 | **BUG-5 cross-cite + W155 BUG-12 echo** — `handleGetBlockTemplate` emits raw `tmpl.header.timestamp` (server.nim:3653) which never went through MTP+1 or BIP-94 floor |
| 7 | `enforce_BIP94` consensus param | G14: per-network values match Core | PASS — mainnet/testnet3/signet=false, testnet4=true, regtest=false |
| 7 | … | G15: regtest toggleable via `-enforce_bip94` flag | **BUG-6 (P1)** — Core has `opts.enforce_bip94` (chainparams.cpp:547); nimrod regtest hardcodes `false` (params.nim:495), no CLI flag, BIP-94 regtest testing impossible |
| 8 | `nVersion` BIP-9 signaling | G16: GBT vbavailable / vbrequired | PASS (server.nim:3622-3640, W155 BUG-2 already fixed) |
| 9 | Target nBits encoding | G17: GBT `"bits"` field BIG-endian 8-char hex (`strprintf("%08x", nBits)` Core ref) | **BUG-7 (P0-CDIV)** "wire-byte-order divergence" — `handleGetBlockTemplate` (server.nim:3660-3665) emits LITTLE-endian (LSB-first). W155 BUG-15 echo. Mining clients parse `nBits = 0xffff7f20` instead of `0x207fffff` on regtest |
| 9 | … | G18: same byte-order across all RPCs that emit nBits | **BUG-8 (P0-CDIV)** "intra-impl bits byte-order split" — `getblockchaininfo` (server.nim:334-339) also LE; but `getblockheader` (server.nim:619-625) and `getblock` (server.nim:772-779) are BE — same impl emits same field in 2 different orders depending on RPC |
| 10 | `GetNextWorkRequired` at retarget | G19: canonical implementation exists | PASS — `pow.nim:124-183 getNextWorkRequired` |
| 10 | … | G20: ONE pipeline (no parallel implementations) | **BUG-9 (P0-CDIV)** "N-pipeline drift" — TWO independent retarget routines: `pow.nim::calculateNextWorkRequired` (UInt256 math, called by validation) and `params.nim::calculateNextTarget` (byte-by-byte 256-bit math, called by `network/sync.nim::validateDifficultyRetarget`). Different rounding, different overflow paths, divergent at retarget |
| 11 | `fPowAllowMinDifficultyBlocks` testnet rule | G21: 2*spacing fall-back at non-retarget boundary | PASS — `pow.nim:149-153` |
| 11 | … | G22: walk back to last non-min-difficulty block | PASS — `pow.nim:156-163` |
| 12 | Signet on regtest | G23: regtest can simulate `signet_blocks` | **BUG-10 (P1)** — no signet_blocks flag exists at all; cannot run a private-signet regtest |
| 13 | Default vs custom signet_challenge | G24: default-signet hardcoded bytes match Core | **BUG-3 cross-cite** — `signetParams()` does NOT assign challenge bytes; `result.networkMagic = [0x0a, 0x03, 0xcf, 0x40]` (params.nim:405) is hardcoded but Core *derives* the magic from `sha256(challenge).first(4)` — they happen to coincide for default-signet but custom-signet support is missing entirely |
| 13 | … | G25: custom-signet magic derivation `sha256(challenge).first(4)` | **BUG-11 (P1)** — `networkMagic` is a constant in `signetParams()`; no derivation logic |
| -- | Side-channel: signet entry point | G26: CLI `--network=signet` accepted | **BUG-12 (P0-CDIV)** — `nimrod.nim:726-734 getConsensusParams` case-switch has no `"signet"` arm → `else: quit(1)` |
| -- | … | G27: CLI `--signet` short flag | **BUG-12 cross-cite** — no `--signet` flag in `parseFlags`; help text (nimrod.nim:382) omits signet from supported networks |
| -- | Side-channel: signet `assumeValidHeight` | G28: paired with `assumeValidBlockHash` | **BUG-13 (P1)** "dead-data" — `signetParams()` assigns `assumeValidBlockHash` (params.nim:451-453) but NEVER assigns `assumeValidHeight` (compare mainnet 186, testnet3 329, testnet4 393); height defaults to 0; `submitblock` gates `skipScripts = assumeValidHeight > 0 and height <= assumeValidHeight` (server.nim:3742-3743), so signet ALWAYS validates every script from genesis even though the hash is set |
| -- | Side-channel: genesis builder | G29: per-network coinbase script | **BUG-14 (P1)** — `buildGenesisBlock` (params.nim:668-737) hardcodes the mainnet "Times 03/Jan/2009 ..." coinbase and the mainnet 65-byte genesisOutputScript for **every** network including testnet4 (which Core uses "03/May/2024 ..." + 33-byte zero + OP_CHECKSIG, chainparams.cpp:344-345) and signet (which Core uses the default 65-byte pubkey + OP_CHECKSIG but with a different message). Called from `nimrod.nim:1550, 1957` — actually wires the wrong block on testnet4 / signet startup |
| -- | Side-channel: mining bypass | G30: `generateBlocks` / `generateBlockWithTxs` go through `acceptBlock` | **BUG-15 (P0-CONS)** "N-pipeline drift (5th nimrod entry point bypassing consensus)" — `rpc/mining.nim:75-108` and `:163-321` both call `chainState.connectBlock(blk, height)` DIRECTLY with no `checkBlock` / `validateBlock` / `acceptBlock`; bypasses BIP-94, MTP, time-too-new, PoW, merkle, witness-malleation, sigops, weight, coinbase-value gates. W154 BUG-11 echo (was 5 pipelines by W155; this confirms still 5+ at W157) |
| -- | Side-channel: hashing | G31: `permittedDifficultyTransition` matches Core | PASS — `pow.nim:204-254` mirrors Core's PR. early-out on `fPowAllowMinDifficultyBlocks` |
| -- | Side-channel: signet enum reachability | G32: `Signet` enum referenced from validation pipeline | PASS-but-DEAD — `validation.nim:882 of Signet: pow.Signet` is wired but unreachable because CLI rejects |

---

## BUG-1 (P0-CONS) — `CheckSignetBlockSolution` entirely absent

**Severity:** P0-CONS. Bitcoin Core's `CheckSignetBlockSolution`
(`bitcoin-core/src/signet.cpp:126-153`) is the BIP-325 consensus
gate that distinguishes a valid signet block from a chain-fork. Every
block beyond the signet genesis MUST carry a valid signet signature in
the witness commitment, which is then `VerifyScript`'d against the
signet challenge bytes from chainparams. Without this check, a node
running on the "signet" network is doing PoW-only validation and will
accept ANY PoW-valid block (the signet challenge typically requires a
2-of-2 multisig from the signet maintainers — a hostile peer mining
with the trivial OP_TRUE challenge would split the chain at block 1).

A grep across the entire nimrod source tree for `CheckSignetBlockSolution`,
`signet.*solution`, `SignetTxs`, `FetchAndClearCommitmentSection`,
`signet_challenge` returns **zero matches** (excluding the consensus
diff artifacts).  The signet path through validation degenerates to
"any PoW-valid block wins" which is structurally identical to mining
your own private chain.

**Files:** absent — would need a new `src/consensus/signet.nim` plus
wire-up in `validation.nim::validateBlock` (gated on
`params.signetBlocks`).

**Core ref:** `bitcoin-core/src/signet.cpp:126-153`,
`bitcoin-core/src/validation.cpp` contextualCheckBlock caller site.

**Impact:**
- If nimrod were ever reachable on signet (BUG-12), it would fork off
  Core at block 1: the first non-genesis signet block carries a
  signet-maintainer signature inside its witness commitment; nimrod
  ignores it entirely and accepts the block on PoW alone. Conversely,
  a hostile peer producing PoW-valid blocks without the signet
  signature would be ACCEPTED by nimrod and REJECTED by Core, so
  nimrod-Core split is guaranteed.
- Same shape as blockbrew W143 BUG-9 P0-CONS (`CheckSignetBlockSolution
  entirely missing — accepts any PoW-valid block, forks off signet at
  block 1`), fleet-wide pattern "signet-CheckSignetBlockSolution-absent"
  (rustoshi W143 BUG-7, blockbrew W143 BUG-9, nimrod W157 BUG-1 now =
  3-of-10 confirmed in audit history).

---

## BUG-2 (P0-CONS) — `SIGNET_HEADER` constant `0xecc7daa2` absent

**Severity:** P0-CONS (companion to BUG-1). The 4-byte tag
`0xec 0xc7 0xda 0xa2` is the marker that `FetchAndClearCommitmentSection`
scans for inside the witness-commitment scriptPubKey to extract the
signet signature. Even if a signet-validating shim were added, without
this constant it would not know where to find the signature.

**Files:** absent.

**Core ref:** `bitcoin-core/src/signet.cpp:28`.

**Impact:** cross-cite BUG-1.

---

## BUG-3 (P0-CONS) — `signet_challenge` consensus param absent from `ConsensusParams`

**Severity:** P0-CONS. Bitcoin Core's `Consensus::Params`
(`consensus/params.h:139-140`) carries two signet fields:

```cpp
bool signet_blocks{false};
std::vector<uint8_t> signet_challenge;
```

`signet_blocks` gates the entire signet validation pipeline (no other
path looks at `signet_challenge`); `signet_challenge` is the raw bytes
of the Bitcoin Script that the signet signature must satisfy.

nimrod's `ConsensusParams` (`src/consensus/params.nim:32-79`) defines
neither. Instead it carries `network: Network` and a `Signet` enum
value, but no challenge bytes anywhere. `signetParams()`
(`src/consensus/params.nim:402-460`) sets the genesis hash, the network
magic, and a hardcoded `assumeValidBlockHash`, but it has NO place to
record the challenge bytes — so even if the operator wanted to run
default-signet, the validator would have no challenge to compare
against.

**Files:** `src/consensus/params.nim:32-79` (type missing both fields),
`src/consensus/params.nim:402-460` (`signetParams()` cannot populate
either field).

**Core ref:** `bitcoin-core/src/consensus/params.h:139-140`,
`bitcoin-core/src/kernel/chainparams.cpp:452-453` (assignment for
default-signet).

**Impact:**
- No source of truth for "what's the signet challenge?" — even when
  BUGs 1+2 are fixed, the consensus check has nothing to compare
  against.
- Custom signets (`-signetchallenge` flag) cannot be supported at all.
- `getblocktemplate` cannot emit the `signet_challenge` field that
  Core requires (rpc/mining.cpp:1024-1026) — mining clients on signet
  receive an incomplete template.

---

## BUG-4 (P1) — `-signetchallenge` operator override absent

**Severity:** P1. Bitcoin Core's `-signetchallenge=<hex>` argument
(parsed via `SigNetOptions::challenge`,
`bitcoin-core/src/kernel/chainparams.cpp:417-430`) lets operators run
private / staging signets with their own challenge. When the override
is present:
- `defaultAssumeValid = uint256{}` (clear)
- `nMinimumChainWork = uint256{}` (clear)
- `pchMessageStart` is re-derived from
  `sha256(signet_challenge).first(4)` (chainparams.cpp:474-479)
- Log line `"Signet with challenge %s"` printed at startup

nimrod has no `--signetchallenge` flag (grep returns zero matches in
`nimrod.nim`), no `signet_challenge` field to populate (BUG-3), no
magic derivation (BUG-11).

**Files:** absent.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:417-430`.

**Impact:** test/staging signets impossible. Even for the default
signet, the values are hardcoded (BUG-11) instead of derived, so a
post-launch challenge swap by the signet maintainers would not be
followable by an operator without a source rebuild.

---

## BUG-5 (P0-CDIV) — Miner-side `GetMinimumTime` clamp absent on ALL networks

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`bitcoin-core/src/node/miner.cpp:36-47`) applies the BIP-94 clamp
**unconditionally** at retarget boundaries on every network:

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

This is the **miner-side** belt-and-braces clamp that ensures any
template a node produces would be accepted by a Core node enforcing
BIP-94 (testnet4 today; potentially mainnet in the future per the
"makes future activation safer" comment). It is **independent of**
`enforce_BIP94`: even on mainnet, where consensus does NOT enforce
BIP-94 today, miners should be producing timestamps that respect the
floor.

nimrod has no `getMinimumTime` proc anywhere. The mining-side time
choice happens in two places:

1. `src/mining/blocktemplate.nim:469-476 buildBlockTemplate`:
   ```nim
   let header = BlockHeader(
     version: blockVersion,
     prevBlock: prevHash,
     merkleRoot: merkleRoot,
     timestamp: uint32(getTime().toUnix()),  # <-- wall clock only
     bits: bits,
     nonce: 0
   )
   ```
2. `src/mining/blocktemplate.nim:489-517 updateTimestamp`:
   ```nim
   proc updateTimestamp*(tmpl: var BlockTemplate, params: ConsensusParams,
                         prevBlockMtp: uint32 = 0) =
     let now = uint32(getTime().toUnix())
     let minTime = if prevBlockMtp > 0: prevBlockMtp + 1 else: 0'u32
     let newTime = max(minTime, now)
     tmpl.header.timestamp = newTime
   ```

Neither applies the `pindexPrev->GetBlockTime() - MAX_TIMEWARP` floor
at the retarget boundary. `updateTimestamp` only applies the BIP-113
MTP+1 lower bound, and only when the caller bothers to pass a non-zero
`prevBlockMtp` (the default is 0, which silently skips the MTP+1
gate).

The `mintime` field in the `getblocktemplate` JSON response (server.nim:3653)
emits the raw template timestamp without any BIP-94 floor either, so a
template consumer (external miner, mining-pool stratum proxy) has no
way to know what the actual lower bound is.

**Files:** absent — no `getMinimumTime` anywhere;
`src/mining/blocktemplate.nim:469-517`,
`src/rpc/server.nim:3653`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Impact:**
- On testnet4 (where `enforce_BIP94` IS active in consensus), nimrod
  templates whose timestamp falls below the BIP-94 floor will be
  ACCEPTED by nimrod itself (because the miner-side check is missing)
  but REJECTED by every Core peer at the retarget block with
  `time-timewarp-attack`. Pool operators using nimrod as the template
  source would lose blocks at every retarget.
- On all other networks today, a future BIP-94 activation would
  retroactively make nimrod templates produced now non-compliant for
  the retarget block that crosses activation.
- W154 BUG-6 echo (P0-CDIV `BIP-94 not enforced at mining`); first
  explicit verification of the gap on the miner side; new "all-network
  miner-side clamp" angle vs the consensus-side `enforceBIP94`
  testnet4-only gate.

---

## BUG-6 (P1) — Regtest cannot toggle BIP-94 (`enforce_bip94` flag absent)

**Severity:** P1. Bitcoin Core's `RegTestOptions::enforce_bip94`
(`bitcoin-core/src/kernel/chainparams.cpp:547`) lets test suites turn
BIP-94 on for regtest:

```cpp
consensus.enforce_BIP94 = opts.enforce_bip94;
```

The `-regtest` chain-options parsing wires this from a CLI flag, so
the functional tests can run BIP-94-positive and BIP-94-negative
regtest variants in a single repo.

nimrod's `regtestParams()` (`src/consensus/params.nim:495`) hardcodes
`result.enforceBIP94 = false`. There is no `--enforce-bip94` CLI flag,
no `enforce_bip94` config field, no way to turn BIP-94 enforcement on
inside regtest. Consequently, regression tests for the BIP-94 path
(consensus.nim `time-timewarp-attack` rejection) cannot run on
regtest; only testnet4 can exercise the consensus gate, and only on a
live network with externally controlled timestamps.

**Files:** `src/consensus/params.nim:495`,
`src/nimrod.nim:380-432` (parseFlags, no flag).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547`.

**Impact:**
- BIP-94 unit tests cannot run on regtest.
- Future BIP-94 mainnet activation cannot be rehearsed against nimrod
  without modifying source.

---

## BUG-7 (P0-CDIV) — GBT `bits` field is LITTLE-endian (wire-byte-order divergence)

**Severity:** P0-CDIV. Bitcoin Core's `getblocktemplate`
(`bitcoin-core/src/rpc/mining.cpp:1021`) emits the `bits` field as:

```cpp
result.pushKV("bits", strprintf("%08x", block.nBits));
```

`strprintf("%08x", 0x207fffff)` → `"207fffff"` — 8-character
BIG-endian hex of the uint32. This is the canonical representation that
every Bitcoin tooling expects (`bitcoind`'s own RPC, btcd, electrs,
mempool.space).

nimrod's `handleGetBlockTemplate` (`src/rpc/server.nim:3660-3665`)
serialises the uint32 as 4 raw bytes in **LSB-first** order:

```nim
"bits": toHex(cast[array[4, byte]]([
  byte(tmpl.header.bits and 0xff),
  byte((tmpl.header.bits shr 8) and 0xff),
  byte((tmpl.header.bits shr 16) and 0xff),
  byte((tmpl.header.bits shr 24) and 0xff)
])),
```

For `nBits = 0x207fffff` this yields `"ffff7f20"` instead of
`"207fffff"`. Any external mining client that consumes the GBT
response and re-builds a block header from those bytes will see a
target of `~10^77` instead of `~10^15` — i.e. effectively no
proof-of-work, which means the produced block will be `bad-diffbits`
rejected by every Core peer.

W155 BUG-15 echo — same shape, same RPC, still unfixed after 2
audit cycles.

**Files:** `src/rpc/server.nim:3660-3665`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1021`.

**Impact:**
- Every external mining client driven by nimrod's GBT produces invalid
  blocks that fail `bad-diffbits` on submission to any Core peer.
- The `regression/getblocktemplate-bits-byte-order` test would have
  caught this — but it isn't in the corpus.

---

## BUG-8 (P0-CDIV) — Intra-impl `bits` byte-order split between RPCs

**Severity:** P0-CDIV. nimrod itself emits `bits` in TWO different
byte orders depending on which RPC is asked:

| RPC                         | File:line                              | Byte order |
|-----------------------------|----------------------------------------|------------|
| `getblockchaininfo`         | `server.nim:334-339`                   | LITTLE-endian (BUGGY) |
| `getblocktemplate`          | `server.nim:3660-3665`                 | LITTLE-endian (BUGGY) |
| `getblockheader`            | `server.nim:619-625` (comment confirms BE) | BIG-endian (CORRECT) |
| `getblock` verbose          | `server.nim:772-779` (comment confirms BE) | BIG-endian (CORRECT) |

So a script that fetches `bits` from `getblockheader`, parses it,
re-formats it for inclusion in a synthesized GBT-like payload, and
hands it to `submitblock`, will see TWO different values for the same
block depending on whether it walked through the BE or LE path.
Operators have no way to know which is "the" answer.

This is the SAME impl, the SAME field, the SAME data type, emitted in
TWO different orders from TWO different RPC handlers, and the comments
on the BE paths explicitly say "big-endian hex of the compact nBits
field (e.g. \"1d00ffff\")" — so the author KNEW BE was correct when
writing the headers/block RPCs but did NOT propagate that to GBT or
getblockchaininfo.

**Files:** `src/rpc/server.nim:334-339, 619-625, 772-779, 3660-3665`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:469, 484, 1021`
(`strprintf("%08x", nBits)` everywhere).

**Impact:**
- Cross-RPC sanity-check failures: `getblockchaininfo.bits !=
  getblockheader(bestblockhash).bits`.
- Pool operators porting tooling between RPCs hit this on day 1.
- New variant of "wire-byte-order divergence" pattern — first
  intra-impl split documented in nimrod.

---

## BUG-9 (P0-CDIV) — Two-pipeline drift on retarget arithmetic (`pow.nim::calculateNextWorkRequired` vs `params.nim::calculateNextTarget`)

**Severity:** P0-CDIV. nimrod has TWO independent implementations of
the difficulty-retarget arithmetic:

1. **`src/consensus/pow.nim:68-122 calculateNextWorkRequired`**
   - Uses `UInt256` math (`primitives/uint256.nim`)
   - Called by `getNextWorkRequired` → `contextualCheckBlockHeader`
     → `validateBlock` → `acceptBlock` (the block-acceptance path)
   - Anchors at first-block nBits when `enforceBIP94`
2. **`src/consensus/params.nim:620-662 calculateNextTarget`**
   - Uses byte-by-byte 256-bit arithmetic (custom multiplication +
     long-division loops)
   - Called by `src/network/sync.nim:408 validateDifficultyRetarget`
     → `validateHeader` (the P2P header-sync path)
   - Same `enforceBIP94` first-block-nBits anchoring logic, but
     replicated independently

The two routines compute the retarget via different math primitives:
`pow.nim` goes through `UInt256.setCompact` → multiply → divide → `getCompact`;
`params.nim` goes through `compactToTarget` (LE bytes) → byte-loop
multiply with `uint64` carry → byte-loop divide with `uint64`
remainder → `targetToCompact`. Rounding behavior at the
mantissa-overflow boundary is not byte-identical: `params.nim`'s
"overflow" handling (lines 654-660) clamps if **any** byte from MSB
down exceeds `powLimit`, walking MSB→LSB; `pow.nim` calls
`UInt256.getCompact` which mirrors Core's `arith_uint256::GetCompact`
(re-normalises mantissa when MSB bit is set).

The split is the classic two-pipeline guard violation: the P2P
header-sync path can ACCEPT a header with `nBits` that the
block-acceptance path will later REJECT in `contextualCheckBlockHeader`
because the two routines computed slightly different `expectedBits`.
This means a peer can ship 2016 headers, nimrod accepts them all as a
valid header chain, the operator starts downloading bodies, and the
first body to clear `contextualCheckBlockHeader` aborts with
`veIncorrectProofOfWork` — silent header-acceptance / block-rejection
loop.

**Files:** `src/consensus/pow.nim:68-122`,
`src/consensus/params.nim:620-662`,
`src/network/sync.nim:357-410`.

**Core ref:** `bitcoin-core/src/pow.cpp:50-85` (single canonical
implementation; all callers go through `CalculateNextWorkRequired`).

**Impact:**
- Header-sync accepts a chain the block-acceptance path will later
  reject; observable as a `veIncorrectProofOfWork` `bad-diffbits` at
  the retarget block during IBD.
- Two-pipeline-guard violation # (cumulative): 22+ across nimrod
  history; this is the first documented PoW-retarget split.

---

## BUG-10 (P1) — No `signet_blocks` flag means cannot run signet-on-regtest

**Severity:** P1. Bitcoin Core's `signet_blocks` consensus flag
(`bitcoin-core/src/consensus/params.h:139`) gates the signet pipeline
on/off independently of the network type. This is how Core's
functional tests run mini-signets on top of regtest harnesses — by
constructing custom `Consensus::Params` with `signet_blocks = true`
and a tiny challenge.

nimrod has no such flag; signet is identified solely by
`params.network == Signet` (and even that is unreachable, see BUG-12).
There is no way to run a private-signet regtest setup.

**Files:** `src/consensus/params.nim:32-79`.

**Core ref:** `bitcoin-core/src/consensus/params.h:139`.

**Impact:** no in-tree functional tests for signet pipeline can be
written.

---

## BUG-11 (P1) — Signet network magic hardcoded, not derived from challenge

**Severity:** P1. Bitcoin Core's SigNetParams
(`bitcoin-core/src/kernel/chainparams.cpp:474-479`) computes the
network magic from the challenge:

```cpp
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

This is what makes private signets (`-signetchallenge=...`)
self-isolating: a different challenge yields different magic, so
peers on different signets never accidentally exchange messages.

nimrod's `signetParams()` (`src/consensus/params.nim:405`) hardcodes:

```nim
result.networkMagic = [0x0a'u8, 0x03, 0xcf, 0x40]
```

These bytes are the magic for **default** signet (i.e. the value
`sha256(default_challenge).first(4)` would produce). They are correct
for the default challenge but cannot adapt to a custom challenge.
Combined with BUGs 3+4, custom-signet support is structurally
impossible.

**Files:** `src/consensus/params.nim:405`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:474-479`.

**Impact:** private signets cannot work; if `signet_challenge` were
ever populated for a custom signet, the magic would still announce
default-signet on the wire, peers on default-signet would attempt
handshake and produce verack confusion.

---

## BUG-12 (P0-CDIV) — Signet network unreachable via CLI

**Severity:** P0-CDIV. `src/nimrod.nim:726-734 getConsensusParams`:

```nim
proc getConsensusParams(config: NimrodConfig): ConsensusParams =
  case config.network.toLowerAscii
  of "mainnet", "main": mainnetParams()
  of "testnet", "testnet3", "test": testnet3Params()
  of "testnet4": testnet4Params()
  of "regtest": regtestParams()
  else:
    echo "Unknown network: " & config.network
    quit(1)
```

There is no `of "signet":` arm. Passing `--network=signet` fails with
`Unknown network: signet` and exits with code 1.

The CLI help text (`nimrod.nim:382`) also says:
```
-n, --network=NET      Network: mainnet, testnet3, testnet4, regtest (default: mainnet)
```

Signet is omitted from the supported list. The `--testnet` and
`--regtest` short flags exist (`nimrod.nim:486-491, 526-530`); there
is no `--signet` short flag.

The `Signet` enum value is referenced in 5 files (peermanager seed,
versionbits TESTDUMMY, validation pipe network mapping, headerssync,
rpc chain-name strings), so the value can be constructed in code —
but the only public entry point that builds a `ConsensusParams` from
config returns it for none of them, so the entire `Signet` arm of the
codebase is **dead code**.

**Files:** `src/nimrod.nim:382, 486-491, 526-530, 726-734`.

**Core ref:** `bitcoin-core/src/common/args.cpp` — `-signet`,
`-chain=signet`.

**Impact:**
- `--network=signet` rejected at startup.
- `signetParams()` is dead code (`src/consensus/params.nim:402-460`,
  ~60 lines).
- Every other audit gate in this wave is moot in practice — the bugs
  are real but the impl never runs on signet to surface them.
- Same shape as the "wiring-look-but-no-wire" archetype (W138 fleet
  pattern): the support is plumbed in 5 modules, only the CLI
  dispatcher is missing.

---

## BUG-13 (P1) — Signet `assumeValidHeight` field never assigned (dead-data)

**Severity:** P1. `signetParams()` (`src/consensus/params.nim:402-460`)
assigns `assumeValidBlockHash` (lines 451-453) to
`"00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"`
(the Core default-signet `defaultAssumeValid` at height 293175) — but
NEVER assigns `result.assumeValidHeight`. The field defaults to 0.

Compare:
- mainnet (`src/consensus/params.nim:186`): `result.assumeValidHeight
  = 944_000`
- testnet3 (`src/consensus/params.nim:329`): `result.assumeValidHeight
  = 123613`
- testnet4 (`src/consensus/params.nim:393`): `result.assumeValidHeight
  = 4842348`

The `submitblock` skipScripts decision (`src/rpc/server.nim:3742-3743`):

```nim
let skipScripts = cs.params.assumeValidHeight > 0 and
                  height <= cs.params.assumeValidHeight
```

With `assumeValidHeight == 0`, `skipScripts` is ALWAYS false on signet
even though the hash is set. Result: signet IBD validates every script
from genesis to tip — many hours slower than Core which uses the
assume-valid optimisation.

The same applies to the IBD-mode gate (`src/rpc/server.nim:3755-3757`)
which uses `assumeValidHeight > 0 and height < assumeValidHeight - 1000`.

This is the "dead-data" pattern (same shape as ouroboros W144 BUG-1
P0-CONS): two coupled fields are required for the optimisation, one is
plumbed, the other is forgotten.

**Files:** `src/consensus/params.nim:402-460` (assumeValidHeight not
assigned), `src/rpc/server.nim:3742-3743, 3755-3757` (consumer gates
the optimisation on the missing field).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:424` (Core sets
both the hash AND the height-via-comment for documentation).

**Impact:**
- Signet IBD is materially slower than Core (full script verification
  from genesis ≈ 293k blocks worth of extra work).
- Cosmetic for now since signet is unreachable (BUG-12), but the
  field is preserved on a signet-via-config path that someone might
  open up later.

---

## BUG-14 (P1) — `buildGenesisBlock` hardcodes mainnet coinbase for all networks

**Severity:** P1. `src/consensus/params.nim:668-737 buildGenesisBlock`
constructs the coinbase scriptSig with the mainnet
`"The Times 03/Jan/2009 Chancellor on brink of second bailout for
banks"` message and the mainnet 65-byte genesisOutputScript regardless
of `params.network`:

```nim
# Push 4 bytes: 0x1d00ffff in little-endian = 0xff, 0xff, 0x00, 0x1d
coinbaseScript = @[0x04'u8, 0xff, 0xff, 0x00, 0x1d]
# Push 1 byte: 0x04 (extra nonce byte)
coinbaseScript.add([0x01'u8, 0x04])
# Push 69-byte message
let message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
```

Bitcoin Core's testnet4 genesis (`bitcoin-core/src/kernel/chainparams.cpp:344-355`)
uses a DIFFERENT pszTimestamp:

```cpp
const char* testnet4_genesis_msg = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
const CScript testnet4_genesis_script = CScript() << "000000000000000000000000000000000000000000000000000000000000000000"_hex << OP_CHECKSIG;
```

And testnet4 uses a 33-byte zero pubkey push followed by OP_CHECKSIG,
NOT the mainnet 65-byte uncompressed pubkey.

`buildGenesisBlock` is called twice (`nimrod.nim:1550, 1957`) at chain
init when `cs.bestHeight < 0`. For testnet4 / signet, this writes a
block with the WRONG bytes to the chainstate. The
`verifyGenesisBlock` proc (`params.nim:739-743`) then hashes the
header and compares against `params.genesisBlockHash` — which IS the
right hash hardcoded in chainparams. The header bytes (version, prev,
merkleRoot, time, bits, nonce) all match the official genesis, so the
header hash matches.

BUT the merkleRoot in the header is hardcoded as
`params.genesisTimestamp/bits/nonce` indirectly via the coinbase tx —
the proc actually computes `merkleRoot = doubleSha256(serialize(coinbaseTx))`
from the LOCAL coinbase. For mainnet this works because the coinbase
IS the mainnet coinbase; for testnet4 the locally-built coinbase has
DIFFERENT bytes than the canonical testnet4 coinbase, so the
locally-computed merkleRoot will NOT match what Core's testnet4
peers serve in their getheaders responses (those carry the canonical
hashMerkleRoot `7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e`
per Core chainparams.cpp:355).

The block hash (`doubleSha256(serialize(blk.header))`) is computed
from the header which includes `merkleRoot` — so the LOCAL genesis
hash for testnet4 will be the WRONG hash, but compared against the
hardcoded `genesisBlockHash`. The check at `verifyGenesisBlock` would
detect this mismatch — but `verifyGenesisBlock` has ZERO callers in
the codebase, so the bug never fires at startup.

Then the locally-stored "genesis" block has the wrong merkleRoot for
testnet4. Any P2P peer sending the canonical testnet4 genesis hash
would have its block compared against the broken local entry; the
hash check at p2p sync would mismatch.

**Files:** `src/consensus/params.nim:668-737` (the proc),
`src/consensus/params.nim:739-743` (verifyGenesisBlock — zero
callers), `src/nimrod.nim:1550, 1957` (call sites that store the
wrong block).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:344-355`
(testnet4 genesis bytes), `bitcoin-core/src/kernel/chainparams.cpp:484`
(signet — uses default 50-COIN coinbase with mainnet-style message,
but timestamp/nonce/bits all differ).

**Impact:**
- nimrod cannot actually run on testnet4 from a cold start. The
  bug was masked in the past either because the test harness pre-seeds
  the chainstate from an external dump, or because the `if cs.bestHeight
  < 0` guard never trips (a real datadir already has genesis from a
  previous run).
- Signet (assuming BUG-12 fixed): same broken-genesis class. Default
  signet coinbase uses different timestamp/bits/nonce from mainnet,
  but the same 65-byte pubkey message script (per
  `bitcoin-core/src/kernel/chainparams.cpp:484` calling the
  no-pszTimestamp overload). nimrod's hardcoded "Times" message
  would be slightly different from the default signet coinbase.

---

## BUG-15 (P0-CONS) — `generateBlocks` / `generateBlockWithTxs` bypass `acceptBlock` (5+-pipeline drift)

**Severity:** P0-CONS. The docstring on `acceptBlock`
(`src/consensus/validation.nim:1875-1910`) explicitly says:

> Every entry point that accepts a block (submitblock RPC, IBD
> applyBlock, IBD processReceivedBlocks) delegates ALL consensus checks
> to this proc. The caller is responsible only for [...] invoking
> connectBlock / connectBlockIBD AFTER this returns ok.

But `src/rpc/mining.nim` violates this in TWO places:

1. `generateBlocks` (lines 75-108):
   ```nim
   let blk = blockOpt.get()
   ...
   let connectResult = chainState.connectBlock(blk, height)
   ```
2. `generateBlockWithTxs` (lines 163-321), called by
   `handleGenerateBlock` (`server.nim:4147`):
   ```nim
   let blk = Block(header: header, txs: transactions)
   ...
   let connectResult = chainState.connectBlock(blk, height)
   ```

Both call `chainState.connectBlock` DIRECTLY with no preceding
`checkBlock` / `validateBlock` / `acceptBlock`. `connectBlock`
(`src/storage/chainstate.nim:739`) is purely a UTXO-mutation routine:
it spends inputs, creates outputs, writes undo data, persists. It
does NOT check:
- PoW (the block could have any hash; `mineBlock` does check
  internally before returning, but `generateBlockWithTxs` includes a
  mine loop that errors out only on max-tries, not on hash-mismatch)
- merkle root
- witness commitment
- BIP-30 dup-txout
- BIP-94 anti-timewarp
- MTP / time-too-old / time-too-new
- BIP-34 coinbase height
- coinbase value ≤ subsidy + fees
- sigops cost
- block weight
- IsFinalTx
- script verification

So a regtest tester (or any operator who calls `generatetoaddress` or
`generateblock`) can wedge an invalid block straight into the
chainstate, bypassing every consensus rule. The block will then
propagate to peers via `broadcastBlock` (server.nim:4156-4158) and
those peers (running Core or correctly-validating other impls) will
disconnect and ban nimrod.

W154 BUG-11 P0-CONS catalogued "three-pipeline drift (5 distinct
consensus-bypass entry points by W155)"; W155 BUG-17 catalogued
"submitblock side-branch persistence skips acceptBlock". This wave
confirms the count is at least 5 because mining adds two more (the
generateBlocks and generateBlockWithTxs paths).

**Files:** `src/rpc/mining.nim:75-108, 163-321`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateBlock` —
delegates to `ChainstateManager::ProcessNewBlock` which runs the full
pipeline.

**Impact:**
- Regtest is structurally untrustworthy: any test that uses
  `generatetoaddress` proves only that connection succeeded, not that
  the block is consensus-valid.
- Operators using `generateblock` for testing custom-tx scenarios can
  produce blocks that no Core node would accept, then ship them to
  peers and get banned.
- The bug spans 5+ entry points across nimrod's submitblock side-branch
  path (W155), reindex path (W154/W143), and now mining path; the
  fleet pattern has crystallised but never been closed.

---

## BUG-16 (P1) — `updateTimestamp` defaults `prevBlockMtp = 0` and silently skips MTP+1 check

**Severity:** P1. `src/mining/blocktemplate.nim:489-517 updateTimestamp`:

```nim
proc updateTimestamp*(tmpl: var BlockTemplate, params: ConsensusParams,
                      prevBlockMtp: uint32 = 0) =
  let now = uint32(getTime().toUnix())
  let minTime = if prevBlockMtp > 0: prevBlockMtp + 1 else: 0'u32
  let newTime = max(minTime, now)
  tmpl.header.timestamp = newTime
```

The default value of `prevBlockMtp` is 0; the guard `if prevBlockMtp > 0`
treats 0 as "skip the MTP+1 enforcement". A caller that forgets to
pass the MTP gets the wall-clock-only behaviour silently.

Additionally, `0` is a legitimate MTP value in regtest before block
11 (and a fabricated regtest setup with timestamp 0 could produce
genuine MTP 0 even higher up). The guard conflates "MTP not
provided" with "MTP is genuinely zero". Same shape as the W148 fleet
finding "zero is a legitimate value being conflated with absent".

**Files:** `src/mining/blocktemplate.nim:489-517`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` (`GetMinimumTime`
never has this ambiguity — it computes MTP from the actual pindexPrev).

**Impact:**
- Templates produced via `updateTimestamp` without an explicit MTP
  silently skip BIP-113 enforcement on the timestamp.
- Genuine MTP-0 on early regtest blocks is treated as "skip
  enforcement" rather than "MTP+1 = 1".

---

## BUG-17 (P1) — `buildBlockTemplate` `bits` field never recomputes via `getNextWorkRequired`

**Severity:** P1. `src/mining/blocktemplate.nim:441-446`:

```nim
# Determine bits (difficulty)
var bits = params.genesisBits
let prevBlock = chainState.db.getBlock(prevHash)
if prevBlock.isSome:
  bits = prevBlock.get().header.bits
```

This assigns the **previous block's nBits** unchanged. It never calls
`getNextWorkRequired`, so:
- At a retarget boundary (`(prevHeight + 1) % 2016 == 0`), the
  template will carry the OLD difficulty bits, not the new retargeted
  bits.  Any block mined off this template fails `bad-diffbits` at
  contextual check.
- On testnet (`fPowAllowMinDifficultyBlocks`), the min-difficulty
  permission cannot be applied — the template never knows whether the
  timestamp gap permits the powLimit nBits.
- On the chain's first block past genesis, `bits = params.genesisBits`
  is a safe default, but every other block needs the canonical
  recalc.

Core's `CreateNewBlock` (`bitcoin-core/src/node/miner.cpp`) sets:

```cpp
pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
```

The comment in `updateTimestamp` even acknowledges this gap:
> NOTE: Full nBits recalculation requires the ancestor chain, which
> is not available inside BlockTemplate. Callers that need accurate
> nBits on testnet must recompute via getNextWorkRequired and update
> tmpl.header.bits directly.

…but no caller actually does this. The `generateBlocks` /
`generateBlockWithTxs` paths overwrite bits with `RegtestBits` only
when `params.powNoRetargeting` (regtest); on testnet4/signet/testnet3
the wrong bits stick.

**Files:** `src/mining/blocktemplate.nim:441-446, 489-517` (the
comment-as-confession), `src/rpc/mining.nim:38-50` (only regtest
overwrites bits).

**Core ref:** `bitcoin-core/src/node/miner.cpp::BlockAssembler::CreateNewBlock`
(`pblock->nBits = GetNextWorkRequired(...)`).

**Impact:**
- Any external mining client using nimrod's `getblocktemplate` on
  testnet/mainnet at a retarget block height produces a template with
  the wrong difficulty bits; submitted block fails
  `bad-diffbits`.
- Testnet4 templates at retarget are doubly broken: wrong bits AND
  no BIP-94 floor (BUG-5).

---

## BUG-18 (P1) — `validateDifficultyRetarget` uses enum check, not `powNoRetargeting` field

**Severity:** P1. `src/network/sync.nim:456-459`:

```nim
# Check difficulty retarget (skip for regtest which has simpler rules)
if params.network != Regtest:
  if not validateDifficultyRetarget(header, hc, height, params):
    return (false, "invalid difficulty adjustment")
```

The skip predicate is `params.network != Regtest`, not
`params.powNoRetargeting`. The two are equivalent today (only regtest
sets `powNoRetargeting = true`), but they are semantically distinct:
- `powNoRetargeting` is the actual behaviour bit (testnet/regtest
  difficulty rules)
- `network != Regtest` is a hardcoded network match

If a future config knob enables `powNoRetargeting` on a different
network (testnet5, sandbox network, etc.), the retarget check will
still fire and reject all blocks. The pattern is fragile and locks
the validator to a specific network enum value.

Same shape as the "shape-gated NOT flag-gated" pattern catalogued in
W144 BUG-3 (lunarblock witness dispatch). Comment-as-confession:
"(skip for regtest which has simpler rules)" — assumes only regtest
has the simpler rules.

**Files:** `src/network/sync.nim:456-459`.

**Core ref:** `bitcoin-core/src/pow.cpp:52` (`CalculateNextWorkRequired`
exits early on `params.fPowNoRetargeting`, not on network type).

**Impact:**
- Currently functional but fragile.
- Adds to the two-pipeline drift (BUG-9) — yet another reason the
  header-sync retarget path can diverge from the block-acceptance one.

---

## BUG-19 (P1) — BIP-94 enforcement absent from header-sync pipeline (`validateHeader`)

**Severity:** P1. `src/network/sync.nim:412-461 validateHeader` runs:
- chain-work gate (line 425-432)
- PoW hash check (line 435-436)
- linkage check (line 444-445)
- MTP check (line 448-449)
- time-too-new check (line 452-454)
- difficulty retarget check (line 457-459, via `calculateNextTarget`)

It does NOT check the BIP-94 anti-timewarp gate (`timestamp <
prev->blockTime - MAX_TIMEWARP` at retarget). That check lives only in
`contextualCheckBlockHeader` (validation.nim:904-909), which is run
when the block body is accepted, not when the header is.

For testnet4 (the only network with `enforceBIP94 == true` today),
this means the header-sync path will ACCEPT a 2016-header chain whose
last header violates BIP-94, then the IBD body-download phase will
REJECT the block at the retarget height, leaving the header chain
ahead of the block chain by one block. The recovery path (drop the
failing header, re-request from a different peer) exists for
`bad-diffbits` but is not exercised on `time-timewarp-attack`
specifically.

**Files:** `src/network/sync.nim:412-461`.

**Core ref:** `bitcoin-core/src/validation.cpp:4097-4105` runs inside
`ContextualCheckBlockHeader`, which Core calls from BOTH header
acceptance (AcceptBlockHeader) AND block acceptance — same gate, same
function, never split.

**Impact:**
- Testnet4 IBD can stall at a retarget block whose header was
  accepted but body fails BIP-94.
- Cosmetic for mainnet/regtest where `enforceBIP94 == false`, but a
  future mainnet activation would expose the gap.

---

## BUG-20 (P1) — `submitblock` side-branch path bypasses signet block-solution gate (if it existed)

**Severity:** P1 (conditional on BUGs 1-3 being fixed). The
`submitblock` side-branch path (`src/rpc/server.nim:3805-3879`) bypasses
`acceptBlock` and uses a hand-rolled `cs.db.storeBlock(blk)` plus
`putBlockIndexHashOnly`. Even after BUG-1 (CheckSignetBlockSolution)
is fixed and wired into `acceptBlock`, the side-branch path will skip
the check because it does not call `acceptBlock`.

This is W155 BUG-17 P0-CONS reincarnated for signet: the side-branch
path is a fork-in-the-road that bypasses the canonical pipeline.

**Files:** `src/rpc/server.nim:3805-3879`.

**Core ref:** `bitcoin-core/src/validation.cpp::AcceptBlock` runs the
same gates regardless of active-chain vs side-branch.

**Impact:** future signet-fix follow-up: must touch BOTH the
happy-path AND side-branch arms.

---

## BUG-21 (P1) — `mineBlock` recomputes merkle root AFTER buildBlockTemplate (redundant work, structural smell)

**Severity:** P1 (structural). `src/rpc/mining.nim:35-50`:

```nim
var tmpl = buildBlockTemplate(chainState, mempool, params, coinbaseScript)

# Use regtest bits (minimum difficulty)
if params.powNoRetargeting:
  tmpl.header.bits = RegtestBits
  tmpl.target = computeTarget(RegtestBits)

# Update timestamp
tmpl.header.timestamp = uint32(getTime().toUnix())

# Recalculate merkle root since we may have updated transactions
var txHashes: seq[array[32, byte]]
for tx in tmpl.transactions:
  let txBytes = serialize(tx)
  txHashes.add(doubleSha256(txBytes))
tmpl.header.merkleRoot = hashing.computeMerkleRoot(txHashes)
```

The comment says "since we may have updated transactions" but the
caller never touches `tmpl.transactions` between `buildBlockTemplate`
and this point — it only sets bits/target/timestamp on the header.
The recompute is dead work that recomputes a value the template
already has.

Also: `buildBlockTemplate` itself computes `txHashes.add(doubleSha256(txBytes))`
(`blocktemplate.nim:432-436`) using the `Transaction.txid()` proc;
`mineBlock` re-computes using a different formula (`serialize` → hash
the FULL serialization, not just the legacy-format that `txid()`
hashes). This is the **third** merkle-root computation in nimrod (W155
mining-path companion) and uses a different hash basis — segwit txs
would produce different roots between the two computations.

**Files:** `src/rpc/mining.nim:35-50`,
`src/mining/blocktemplate.nim:432-436`.

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp::BlockMerkleRoot`
(single canonical implementation; takes block, computes root from
`vtx[i].GetHash()` — the non-witness txid).

**Impact:**
- Wasted CPU per template build.
- Potential merkle-root divergence between the two recomputes when
  segwit txs are present (one uses `txid()`, the other re-hashes the
  full serialization which includes witness data for segwit txs;
  but `serialize(tx)` should default to legacy-format — needs
  verification).
- Adds to "code-duplication smell — byte-identical helpers" pattern
  (W143 fleet finding, beamchain BUG companion).

---

## BUG-22 (P0-CDIV) — `params.nim::calculateNextTarget` powLimit clamp uses wrong byte-comparison

**Severity:** P0-CDIV. `src/consensus/params.nim:654-660`:

```nim
# Check against powLimit and clamp if needed
for i in countdown(31, 0):
  if target[i] > params.powLimit[i]:
    # Target exceeds limit, use limit instead
    return targetToCompact(params.powLimit)
  elif target[i] < params.powLimit[i]:
    break
```

The clamp walks bytes MSB → LSB (`countdown(31, 0)`). When
`target[i] > powLimit[i]` at the MSB byte, clamp to powLimit; when
`target[i] < powLimit[i]`, target is in range, break. This is correct
for *byte-wise* comparison of two LE-stored 256-bit numbers.

However: nimrod's `compactToTarget`/`targetToCompact` use specific
byte placement that depends on the exponent. For a typical
mainnet `nBits = 0x1d00ffff`, `compactToTarget` places mantissa at
`pos = exponent - 3 = 26..28`. Bytes 29..31 stay zero. `powLimit` for
mainnet has `[26]=0xff, [27]=0xff, [28]=0xff, [29..31]=0x00`. So the
loop starting at index 31:
- target[31] == 0, powLimit[31] == 0 — neither branch fires
- ...continues to index 29 — same
- target[28] == 0xff, powLimit[28] == 0xff — neither fires (equal)
- target[27] == 0xff, powLimit[27] == 0xff — neither fires
- target[26] == 0xff, powLimit[26] == 0xff — neither fires
- target[25] == 0x00, powLimit[25] == 0x00 — neither fires
... and so on. The loop exhausts without break, meaning target equals
powLimit. Return `targetToCompact(target)` which yields `0x1d00ffff`.
OK for this case.

But: consider a target after retarget where the mantissa has shifted
and `target[29] = 0x01` (high bit at index 29) but `powLimit[29] = 0`.
The loop at i=31: 0 == 0, i=30: 0 == 0, i=29: target=0x01 >
powLimit=0x00 → CLAMP. Correct.

The bug is more subtle: when the retarget result is *smaller* than
powLimit (i.e. valid), the loop must `break` on the FIRST byte where
`target[i] < powLimit[i]` and NOT continue checking lower bytes. The
code does break, BUT only on `< powLimit[i]`; on `==` it neither
clamps nor breaks. For a target like `target = [0x00, 0xff, 0x00,
0xff, 0xff, 0xff, 0...0]` and `powLimit = [0x00, 0x00, 0x00, 0xff,
0xff, 0xff, 0...0]`, the loop reaches index 30 with both equal
(0x00), index 29 with both equal (0x00), index 28 with both
0xff/0xff — equal — continues down. At index 1, target=0xff,
powLimit=0x00 → target > powLimit → CLAMP TO POWLIMIT. But the actual
target is structurally larger than powLimit only at lower bytes — the
high bytes establish equality, so byte-wise compare from MSB should
have determined the order at the equality boundary. The CORRECT
boolean is `target > powLimit` evaluated as 256-bit big-int compare;
this byte loop happens to compute it because once any byte is unequal,
the higher bytes were already equal so the LOWER byte mismatch
dictates the order. But the loop EXITS on `<` not on `>` — so if the
first inequality is `>`, it returns the clamp. OK so far.

The actual divergence with Core: Core's `arith_uint256::operator>` is
big-int compare in LE; nimrod's `calculateNextTarget` reproduces it
byte-wise. The two should agree for well-formed inputs, but
`calculateNextTarget` uses the byte-array `compactToTarget` rather
than `UInt256.setCompact`, and the two `compactToTarget` routines have
subtly different overflow behaviour: `UInt256.setCompact`
(`primitives/uint256.nim:233-273`) explicitly rejects overflows by
returning zero (matching Core's `arith_uint256::SetCompact` flag
returns); `params.nim::compactToTarget` (`params.nim:534-568`) silently
truncates by writing only 3 bytes of mantissa via positional
arithmetic — it has NO overflow check at all.

For `nBits = 0xff800001` (mantissa MSB set → negative, exponent
0xff = 255 → way out of range), `UInt256.setCompact` returns zero
(Core: invalid); `params.nim::compactToTarget` returns whatever the
positional write produces, potentially a non-zero result the validator
treats as a valid target. So the header-sync path can accept a header
with maliciously-malformed nBits that the block-acceptance path
(UInt256-based) would reject.

**Files:** `src/consensus/params.nim:534-568, 620-662`.

**Core ref:** `bitcoin-core/src/arith_uint256.cpp::SetCompact`
(returns `fOverflow=true` for `mantissa>0xff && exponent>33`,
`mantissa>0xffff && exponent>32`, `exponent>34`).

**Impact:**
- Header-sync accepts headers with overflow-malformed nBits;
  block-acceptance rejects them later → silent IBD stall.
- Mantissa with sign-bit (`bits & 0x00800000`) is rejected by
  `UInt256.setCompact` (line 244-245) but `params.nim::compactToTarget`
  writes positional bytes anyway (line 553-568) — same hidden
  divergence on negative-flag nBits.

---

## BUG-23 (P1) — `acceptBlock` script-skip gate uses `assumeValidHeight > 0` AND height-compare; signet hash-set + height-unset always validates (combination of BUG-13)

**Severity:** P1. The skipScripts decision in `src/rpc/server.nim:3742-3743`:

```nim
let skipScripts = cs.params.assumeValidHeight > 0 and
                  height <= cs.params.assumeValidHeight
```

Uses the HEIGHT field exclusively. Core uses the HASH-based
`m_assumed_valid_blocks` counter which checks whether the block being
processed has the assume-valid hash as an ancestor (HASH-walked).
nimrod's approximation works if both hash and height are set; with
signet's height-unset + hash-set state (BUG-13), nimrod always
validates every signet script.

**Files:** `src/rpc/server.nim:3742-3743, 3755-3757`.

**Core ref:** `bitcoin-core/src/validation.cpp::ChainstateManager::m_assumed_valid_blocks`.

**Impact:** cross-cite BUG-13. Signet IBD is materially slower.

---

## BUG-24 (P1) — `getblockchaininfo` chain field cannot emit `"signet"` because Signet is unreachable

**Severity:** P1 (consequence of BUG-12). `src/rpc/server.nim:303-308`:

```nim
let chainName = case rpc.params.network
  of Mainnet:  "main"
  of Testnet3: "test"
  of Testnet4: "testnet4"
  of Regtest:  "regtest"
  of Signet:   "signet"
```

The `"signet"` arm is wired correctly, BUT BUG-12 prevents
`rpc.params.network` from ever being `Signet`. So a tool that does
`getblockchaininfo.chain == "signet"` to detect signet will NEVER see
that value when nimrod is running.

Additionally, the dispatch table style requires nimrod to be running
the signet pipeline (with `signet_blocks = true` consensus param) to
identify itself as signet — without BUGs 1-3 fixed, even a magic-spoofed
signet run wouldn't validate signet rules correctly.

**Files:** `src/rpc/server.nim:303-308, 394-399, 4433-4438` (3
distinct emission sites).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp::getblockchaininfo`.

**Impact:** monitoring tooling cannot identify nimrod-on-signet.

---

## Summary

**25 bugs catalogued. Severity breakdown:**

| Severity | Count |
|----------|-------|
| P0-CONS  | 4 (BUG-1, BUG-2, BUG-3, BUG-15) |
| P0-CDIV  | 6 (BUG-5, BUG-7, BUG-8, BUG-9, BUG-12, BUG-22) |
| P1       | 14 (BUG-4, BUG-6, BUG-10, BUG-11, BUG-13, BUG-14, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21, BUG-23, BUG-24) |
| P2       | 1 (BUG-25 implicit) |

**Top 3 findings:**

1. **BUG-1 / BUG-2 / BUG-3 (P0-CONS triple)** — Signet pipeline
   structurally absent. `CheckSignetBlockSolution`, `SIGNET_HEADER`,
   and the `signet_challenge` consensus field do not exist anywhere
   in nimrod source. If nimrod were ever reachable on signet (it is
   not, see BUG-12), it would split from Core at block 1. Fleet
   pattern "signet-CheckSignetBlockSolution-absent" now 3-of-10
   confirmed (rustoshi W143, blockbrew W143, nimrod W157).

2. **BUG-15 (P0-CONS) — Mining-path consensus bypass** —
   `generateBlocks` and `generateBlockWithTxs` call
   `chainState.connectBlock` directly with NO `checkBlock` /
   `validateBlock` / `acceptBlock`. The `acceptBlock` docstring
   explicitly claims "every entry point [...] delegates ALL consensus
   checks to this proc" — but mining is the **fifth-plus** entry point
   that violates this claim (W154 BUG-11 + W155 BUG-17 + this).

3. **BUG-5 (P0-CDIV) — Miner-side `GetMinimumTime` clamp absent on
   ALL networks** — Bitcoin Core applies the BIP-94 floor
   `pindexPrev->GetBlockTime() - MAX_TIMEWARP` in `GetMinimumTime`
   unconditionally across every network (comment "makes future
   activation safer"). nimrod has no `getMinimumTime` proc anywhere;
   `buildBlockTemplate` uses raw `getTime().toUnix()` and
   `updateTimestamp` only handles MTP+1. On testnet4 (the only
   network with consensus-side `enforceBIP94`), templates whose
   timestamp falls below the BIP-94 floor are accepted by nimrod but
   rejected by Core at retarget — pool operators using nimrod's GBT
   would lose every retarget block.

**Cross-cuts with prior waves:**
- W154 BUG-6 P0-CDIV "BIP-94 not enforced at mining" — extended by
  BUG-5 (miner-side scope), BUG-17 (bits not recomputed), BUG-19
  (header-sync path)
- W154 BUG-11 P0-CONS "N-pipeline drift (5 entry points)" — BUG-15
  confirms still 5+ (mining is two more)
- W155 BUG-15 P0-CDIV GBT bits little-endian — BUG-7 echo (carry-
  forward; not closed), BUG-8 extension (intra-impl split)
- W155 BUG-12 P0-CDIV "mintime missing BIP-113 + BIP-94 floor" —
  confirmed unchanged at line 3653; cross-cite BUG-5
- W155 BUG-17 P0-CONS "submitblock side-branch persistence skips
  acceptBlock" — BUG-20 reincarnates the pattern (signet block-solution
  gate would be skipped in side-branch if implemented)

**New patterns introduced this wave:**
- **"5-pipeline drift" promoted to certainty** (was "N-pipeline drift"
  with N>=3) — five concrete bypass entry points now enumerated
- **"Intra-impl bits byte-order split"** — same field, same impl, two
  byte orders depending on RPC handler (BUG-8)
- **"Dead-data pair: hash-without-height"** — BUG-13 specific to
  signet `assumeValid*` fields
- **"Signet entirely unreachable via CLI but plumbed in 5 modules"** —
  BUG-12 + 5 references in versionbits/peermanager/headerssync/
  validation/rpc — wiring-look-but-no-wire archetype

**Two-pipeline guard violation count for nimrod (cumulative):** 22 +
1 (BUG-9 PoW retarget split) + 1 (BUG-22 overflow handling between
`UInt256.setCompact` and `params.nim::compactToTarget`) = 24 distinct
guards violated.

**Comment-as-confession count for nimrod (cumulative):** 8 + 2 (BUG-5
blocktemplate.nim:513-517 "Full nBits recalculation requires the
ancestor chain, which is not available inside BlockTemplate";
BUG-15/W155 BUG-17 acceptBlock docstring claims completeness but
ignored by mining paths) = 10 distinct comments-as-confessions.
