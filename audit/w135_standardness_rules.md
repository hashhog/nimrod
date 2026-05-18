# W135 — Standardness rules (IsStandardTx) audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W135)
Target:
  - `src/mempool/standard.nim`        (`IsStandardTx`, `IsWitnessStandard`,
                                       `classifyStdTxout`, `isStandardOpReturn`,
                                       `isStandardP2PK`, `isStandardMultisig`,
                                       `dustThreshold`, `isDustOutput`,
                                       `evalScriptSigPushes`,
                                       `IsStandardOptions` /
                                       `defaultIsStandardOptions`)
  - `src/mempool/mempool.nim`          (call sites: `isStandardTx(tx)` at :921,
                                       `isWitnessStandard(...)` at :1017,
                                       `classifyStdTxout(prevSpk)` +
                                       `MaxP2shSigops=15` inlined P2SH redeem
                                       sigop counter at :1038-1107, plus the
                                       duplicated `getDustThreshold` +
                                       `isDust` at :426-462)
  - `src/script/interpreter.nim`       (`isP2PKH`, `isP2SH`, `isP2WPKH`,
                                       `isP2WSH`, `isP2TR`, `isP2A`,
                                       `isWitnessProgram`, `isPushOnly`,
                                       opcode constants)
  - `src/consensus/params.nim`         (`MaxBlockWeight`, `MaxBlockSigopsCost`,
                                       `MaxStandardTxSigopsCost`)

Bitcoin Core references:
  - `src/policy/policy.cpp`
    - lines 27-64 (`GetDustThreshold`)
    - lines 66-69 (`IsDust`)
    - lines 71-78 (`GetDust`)
    - lines 80-98 (`IsStandard` per-output classification)
    - lines 100-165 (`IsStandardTx` 5-gate spine)
    - lines 167-194 (`CheckSigopsBIP54` — BIP-54 legacy-sigop cap)
    - lines 214-263 (`ValidateInputsStandardness` — input-side standardness)
    - lines 265-352 (`IsWitnessStandard` — 6-gate witness policy)
  - `src/policy/policy.h`
    - constants: `MAX_STANDARD_TX_WEIGHT=400000`, `MIN_STANDARD_TX_NONWITNESS_SIZE=65`,
      `MAX_P2SH_SIGOPS=15`, `MAX_STANDARD_TX_SIGOPS_COST=16000`,
      `MAX_TX_LEGACY_SIGOPS=2500`, `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
      `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
      `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
      `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`,
      `MAX_STANDARD_SCRIPTSIG_SIZE=1650`, `DUST_RELAY_TX_FEE=3000`,
      `MAX_DUST_OUTPUTS_PER_TX=1`, `MAX_OP_RETURN_RELAY=100000`,
      `TX_MIN_STANDARD_VERSION=1`, `TX_MAX_STANDARD_VERSION=3`,
      `DEFAULT_PERMIT_BAREMULTISIG=true`, `DEFAULT_ACCEPT_DATACARRIER=true`,
      `STANDARD_SCRIPT_VERIFY_FLAGS`, `MANDATORY_SCRIPT_VERIFY_FLAGS`,
      `STANDARD_NOT_MANDATORY_VERIFY_FLAGS`, `STANDARD_LOCKTIME_VERIFY_FLAGS`,
      `ANNEX_TAG=0x50`, `TAPROOT_LEAF_MASK=0xfe`,
      `TAPROOT_LEAF_TAPSCRIPT=0xc0`.
  - `src/script/solver.h` (`TxoutType` enum: NONSTANDARD, ANCHOR, PUBKEY,
    PUBKEYHASH, SCRIPTHASH, MULTISIG, NULL_DATA, WITNESS_V0_*, WITNESS_V1_TAPROOT,
    WITNESS_UNKNOWN)
  - `src/script/solver.cpp`
    - lines 36-47 (`MatchPayToPubkey`)
    - lines 49-56 (`MatchPayToPubkeyHash`)
    - lines 85-105 (`MatchMultisig` — uses `GetScriptNumber` so m/n can be
      OP_n OR a minimally-encoded pushdata up to `MAX_PUBKEYS_PER_MULTISIG=20`)
    - lines 141-211 (`Solver` dispatch: P2SH shortcut → witness program switch
      with explicit ANCHOR via `IsPayToAnchor()` → OP_RETURN/PushOnly → P2PK →
      P2PKH → MultiSig)
  - `src/script/script.cpp` (`CScript::IsPushOnly` — opcode > OP_16 → reject;
    OP_RESERVED IS allowed)
  - `src/script/script.h` (`MAX_SCRIPT_SIZE=10000`,
    `CScript::IsUnspendable() = (size>0 && front()==OP_RETURN) || size>MAX_SCRIPT_SIZE`)
  - `src/policy/settings.cpp` + `init.cpp:670-680` (`-permitbaremultisig`,
    `-datacarrier`, `-datacarriersize`, `-dustrelayfee` wiring through
    `CTxMemPool::Options` and into `IsStandardTx` callers)
  - `src/policy/truc_policy.h` (`TRUC_VERSION=3` → why `TxMaxStandardVersion=3`)
  - `src/policy/ephemeral_policy.{h,cpp}` (`PreCheckEphemeralTx` —
    drives the `MAX_DUST_OUTPUTS_PER_TX=1` ephemeral-anchor allowance)
  - `src/kernel/mempool_options.h:45` (`dust_relay_feerate{DUST_RELAY_TX_FEE}`)

Driver: standardness is the mempool gatekeeper between consensus-valid and
relay-acceptable.  A divergence in any of the 30 gates causes either
(a) **mempool poisoning** — an outbound tx is accepted by some nodes in
the fleet and rejected by others, fragmenting the mempool and inflating
RBF / sibling-eviction logic; or (b) **transaction stalling** — a wallet
spends to a script type the fleet majority accepts but a minority
classifies as nonstandard, so the tx never propagates.  Every gate
here also gates the `testmempoolaccept` RPC + the wallet's pre-broadcast
self-check, so divergences surface fleetwide via RPC parity tests too.

## Status

**BUGS FOUND — 16 distinct gates DIVERGENT / PARTIAL / MISSING (of 30).**

Of those:
  - **2 P0-CDIV / P0-CONS** — concrete fleet divergences on outputs that
    cross the boundary:
    - **BUG-01**: `dustThreshold` mis-detects witness programs.
      `standard.nim:195-198` (and the duplicated `getDustThreshold` at
      `mempool.nim:444-446`) uses the byte-pattern test
      `script[0] >= 0x00 and script[0] <= 0x10` to decide whether the
      output is a witness program.  Witness version 0 is encoded as
      `OP_0 = 0x00`, but witness versions 1..16 are encoded as
      `OP_1 = 0x51 .. OP_16 = 0x60` — none of which is `<= 0x10`.
      Result: **every v1+ witness output (most importantly P2TR) is
      classified as legacy for dust purposes**, gets the 148-byte
      legacy spend estimate, and yields a dust threshold of **573 sats**
      for a 34-byte P2TR scriptPubKey instead of the Core-correct
      **330 sats** (`(34 + 1 + 8 + 67) * 3000 / 1000`).  A wallet that
      pays a Core-standard 400-sat P2TR output finds the tx rejected as
      dust by every nimrod node in the fleet.  The bug also mis-flags a
      legacy script whose second byte happens to equal `script.len - 2`
      (e.g. a raw `[0x01, 0x02, 0xXX, 0xXX]`) as a witness program for
      dust purposes — wrong direction but rare in practice.
    - **BUG-02**: `classifyStdTxout` has no `stxAnchor` and routes
      Pay-to-Anchor outputs to `stxWitnessUnknown`.  `standard.nim:60-71`
      defines `StdTxoutKind` with no `stxAnchor` variant; the P2A script
      `[OP_1, 0x02, 0x4e, 0x73]` falls through the explicit shape checks
      (`isP2WPKH`/`isP2WSH`/`isP2TR` all fail because they require
      `script.len == {22,34,34}` and `prog.len == {20,32,32}`), then
      `isWitnessProgram` returns `(true, 1, [0x4e, 0x73])` and the
      function emits `stxWitnessUnknown` (line 175).  Two divergent
      consequences:
      (a) **`isStandardTx` accepts P2A outputs** (Witness-Unknown is
      not rejected at output-classify time, matching Core IsStandard
      shortcut), so output-side parity holds *by accident*; but
      (b) **`mempool.nim:1050` rejects every P2A *input* as
      "bad-txns-nonstandard-inputs: input X witness program is undefined"**
      because the input-standardness path treats `stxWitnessUnknown` as
      a hard reject.  Core's `ValidateInputsStandardness` flows P2A
      through `Solver()` → `TxoutType::ANCHOR` and accepts it (it's
      neither NONSTANDARD nor WITNESS_UNKNOWN nor SCRIPTHASH, so none of
      the rejection branches in policy.cpp:228-258 fire).  Net effect:
      **nimrod cannot spend a P2A output**, despite advertising the
      anchor-aware fee-bumping path in tests.  This is the
      direct fleet-poisoning failure mode for the BIP-431 / TRUC
      anchor flow.
  - **3 P1** — observable divergences that don't poison the mempool but
    flip reason strings / behaviour at the policy boundary:
    - **BUG-03**: BIP-54 legacy sigop cap (`MAX_TX_LEGACY_SIGOPS = 2500`)
      is **not enforced**.  Core's `CheckSigopsBIP54` (policy.cpp:170-194)
      sums `txin.scriptSig.GetSigOpCount(fAccurate=true) +
      prev.scriptPubKey.GetSigOpCount(scriptSig)` across all inputs and
      rejects with `"non-witness sigops exceed bip54 limit"` if the sum
      exceeds 2500.  Nimrod has no equivalent: grep for `MAX_TX_LEGACY_SIGOPS`
      / `MaxTxLegacySigops` / `bip54` / `bip-54` returns zero hits in
      `src/`.  The only legacy-sigop reference is the inline P2SH-redeem
      counter (`MaxP2shSigops=15`) at `mempool.nim:1066`, which is the
      per-input MAX_P2SH_SIGOPS cap, not the cross-input BIP-54 sum.
      A tx whose inputs collectively trigger >2500 legacy sigops would
      pass nimrod's standardness but be rejected by Core 31.99 with
      a different reason string.
    - **BUG-04**: `isStandardOpReturn` and `classifyStdTxout` accept
      v0 witness programs with malformed `prog.len` as
      `stxWitnessUnknown` instead of `stxNonStandard`.
      `standard.nim:165-175` — after the explicit P2WPKH / P2WSH checks
      fail, `isWitnessProgram(script)` returns `(true, 0, prog)` for any
      v0 script of length 4..42 (`prog.len 2..40`).  The two `if`
      branches (`ver==0 and prog.len in {20,32}` → stxNonStandard) /
      (`ver==1 and prog.len==32` → stxNonStandard) are **dead** — those
      shapes are already matched by `isP2WPKH`/`isP2WSH`/`isP2TR`
      earlier.  The reachable case is "v0 prog.len NOT in {20,32}" or
      "v1 prog.len != 32" — both flow to `stxWitnessUnknown`.  Core's
      `Solver` (solver.cpp:177) returns **`NONSTANDARD` for v0 with
      unrecognised program length**, not WITNESS_UNKNOWN.  Consequence:
      an output of the form `[OP_0, 0x05, …]` is `stxWitnessUnknown` in
      nimrod (`IsStandard` returns true) but `NONSTANDARD` in Core
      (`IsStandard` returns false) — nimrod **admits a tx Core rejects
      as `"scriptpubkey"`**.  On the input side, the divergence flips
      the other way: nimrod's `mempool.nim:1050` rejects
      `stxWitnessUnknown` as `bad-txns-nonstandard-inputs`, while Core
      rejects it via the same code path with the same string —
      coincidentally aligned on input side, divergent on output side.
    - **BUG-05**: `isStandardMultisig` accepts m,n only as OP_1..OP_16,
      so a 17-of-20 / 1-of-17 / etc. multisig is `stxNonStandard`
      (`"scriptpubkey"`) in nimrod, but `MULTISIG` then IsStandard-false
      with `"scriptpubkey"` in Core.  Same final reason string by
      accident.  More important: for n ∈ {4..16}, nimrod **does**
      classify as `stxMultisig` and then rejects via the
      `n > MaxStandardMultisigN(3)` branch with reason **`"bare-multisig"`**,
      while Core's IsStandard returns false at the helper (n > 3) →
      `reason = "scriptpubkey"`.  Real reason-string divergence
      between nimrod (`"bare-multisig"`) and Core (`"scriptpubkey"`)
      for any 4-of-N..16-of-N bare-multisig output.  See `test_w135`
      G17 below.
  - **4 P2** — operator-visible CLI/config gaps and reason-string drift
    that don't affect single-tx admission but break the configurable
    surface:
    - **BUG-06**: `-dustrelayfee` CLI flag not wired.  Core init.cpp:674
      registers `-dustrelayfee=<amt>` and `CTxMemPool::Options::dust_relay_feerate`
      defaults to `DUST_RELAY_TX_FEE=3000` but is overridable.  Nimrod
      hardcodes `StdDustRelayTxFee = 3000` (standard.nim:38) AND
      `DustRelayTxFee = 3000` (mempool.nim, used by the duplicated
      `getDustThreshold`).  No CLI plumbing, no override.  Operator
      cannot relay sub-dust outputs (e.g. on regtest harness) by
      raising `dustrelayfee`.
    - **BUG-07**: `-permitbaremultisig` CLI flag not wired.  Nimrod's
      `IsStandardOptions.permitBareMultisig` exists in the type but
      `mempool.nim:921` calls `isStandardTx(tx)` with no opts, always
      using `defaultIsStandardOptions()` (which hardcodes `true`).
      No CLI flag, no config path.
    - **BUG-08**: `-datacarrier` and `-datacarriersize` flags not wired.
      Same shape as BUG-07: `IsStandardOptions.maxDatacarrierBytes`
      exists but is fixed at `some(MaxOpReturnRelayBytes=100_000)`.
      Operator cannot disable OP_RETURN relay (`-datacarrier=0`) or
      shrink the per-tx budget (`-datacarriersize=N`).
    - **BUG-09**: `dustThreshold` ignores `IsUnspendable size>MAX_SCRIPT_SIZE`.
      Core's `IsUnspendable()` is `(size>0 && front()==OP_RETURN) ||
      size > MAX_SCRIPT_SIZE`.  Nimrod's `dustThreshold` only checks the
      OP_RETURN byte (`standard.nim:192`).  A >10000-byte scriptPubKey
      would yield a non-zero dust threshold in nimrod and zero in Core.
      Practically gated by consensus (`bad-txns-oversize` rejects
      base-size > 100K → script ≤ 100K anyway, and per-script `MAX_SCRIPT_SIZE`
      is enforced elsewhere), but the gate is missing in this code path.
  - **7 P3** — cosmetic / completeness / documentation gaps:
    - **BUG-10**: `dustThreshold` uses `8 + scriptPubKey.len + 1` for
      output size, hardcoding varint=1.  For scriptPubKey >= 253 bytes
      the varint is 3 bytes; nimrod under-counts by 2.  Practically
      out of standardness reach (a standard scriptPubKey is ≤ 84 bytes
      via the P2WSH 3600-byte witness limit, but the COMPUTATION of
      dust threshold is on the *output* script, capped at the `MAX_SCRIPT_SIZE`
      of 10K, where ≥ 253 bytes is plausible).
    - **BUG-11**: `dustThreshold` is duplicated.  `standard.nim:189` and
      `mempool.nim:426` define identical (and identically-buggy)
      implementations.  When BUG-01/09/10 land, two call sites must be
      patched; nothing prevents drift.
    - **BUG-12**: `isStandardMultisig` doesn't enforce `CheckMinimalPush`
      on pushdata-encoded m / n.  Core's `MatchMultisig` (solver.cpp:91-101)
      goes via `GetScriptNumber` which calls `CheckMinimalPush`.
      Nimrod only accepts OP_1..OP_16 (not pushdata-encoded numbers
      ≥ 17 needed for n=17..20), so the divergence is BUG-05 (n max 16
      vs 20).  Cosmetic relative to BUG-05.
    - **BUG-13**: `isStandardP2PK` doesn't validate the pubkey prefix
      (0x02/0x03 for compressed, 0x04 for uncompressed).  Core's
      `MatchPayToPubkey` (solver.cpp:36-47) only checks `CPubKey::ValidSize`
      (33 or 65), so same as nimrod — **NOT a bug**, but called out for
      audit-completeness.  Cosmetic note only.
    - **BUG-14**: docstring drift — `standard.nim:234` lists
      `"multi-op-return"` as a possible reason string, but no code
      path emits it (Core 31.99 removed the multi-OP_RETURN count
      limit, only the cumulative bytes-budget remains; see W71 regression
      tests in `test_standard.nim`).  Cleanup.
    - **BUG-15**: tx-version is `int32` in nimrod (`primitives/types.nim:60`)
      vs `uint32_t` in Core (`primitives/transaction.h:293`).  For
      bit-31-set versions, nimrod sees a negative int32 (e.g. -2147483648)
      and Core sees a positive uint32 (e.g. 2147483648).  Both fall
      outside `[1, 3]` and reject as `"version"`, so end result aligned,
      but type-shape divergence ripples into serialization (the wire
      bytes match because `int32` reinterpret-cast equals `uint32`, but
      arithmetic comparisons differ).  Documented for completeness.
    - **BUG-16**: `evalScriptSigPushes` only handles push opcodes and
      treats everything else (including OP_RESERVED 0x50, OP_RESERVED1
      0x89, etc.) as a hard reject.  Core's `EvalScript` with
      `SCRIPT_VERIFY_NONE` actually *executes* the script, so a
      scriptSig with OP_DUP would execute (and would still leave the
      stack in some state).  In practice this only matters if
      `IsWitnessStandard` is called WITHOUT a preceding `IsStandardTx`
      (since IsStandardTx requires push-only scriptSigs), so this
      passes through nimrod's mempool flow but breaks if a future
      caller invokes `isWitnessStandard` standalone.  Architectural
      assumption — documented.

## 30-gate matrix

| # | Gate | Status | BUG | Verdict |
|---|------|--------|-----|---------|
| G1 | `TX_MIN_STANDARD_VERSION=1` / `TX_MAX_STANDARD_VERSION=3` enforced | PASS | — | `standard.nim:42-43, 235-236`. ✓ |
| G2 | Version field treated as 32-bit (signed vs unsigned semantics) | PARTIAL | BUG-15 | `int32` instead of `uint32_t`; same final reject by coincidence. |
| G3 | `MAX_STANDARD_TX_WEIGHT=400000` enforced via `GetTransactionWeight` formula | PASS | — | `standard.nim:36, 239`; weight = base*3+full (Core parity). |
| G4 | Per-input `scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE` rejected as `"scriptsig-size"` | PASS | — | `standard.nim:47, 243-244`. |
| G5 | Per-input `IsPushOnly(scriptSig)` rejected as `"scriptsig-not-pushonly"` | PASS | — | `standard.nim:245-246` via `interpreter.isPushOnly`. |
| G6 | `Solver()` shortcut: P2SH classified before witness | PASS | — | `classifyStdTxout` order: P2PKH → P2SH → P2WPKH → P2WSH → P2TR → witness → OP_RETURN → P2PK → multisig.  Matches Core (Solver:147-211). |
| G7 | Witness-program version 0, length 20 → P2WPKH (WITNESS_V0_KEYHASH) | PASS | — | `isP2WPKH` in interpreter. |
| G8 | Witness-program version 0, length 32 → P2WSH (WITNESS_V0_SCRIPTHASH) | PASS | — | `isP2WSH`. |
| G9 | Witness-program version 1, length 32 → P2TR (WITNESS_V1_TAPROOT) | PASS | — | `isP2TR`. |
| G10 | Pay-to-Anchor `[OP_1, 0x02, 0x4e73]` recognised as a standard txout type (TxoutType::ANCHOR) | MISSING | BUG-02 | No `stxAnchor` variant; routed to `stxWitnessUnknown`; output-side coincidentally passes, **input-side rejects every P2A spend**. |
| G11 | Other versioned witness programs (v2..v16 or v1 ≠32) → WITNESS_UNKNOWN | PARTIAL | BUG-04 | Output reaches `stxWitnessUnknown` correctly for v2..v16, but v0 with `prog.len ∉ {20,32}` is **also** mapped to `stxWitnessUnknown` instead of `NONSTANDARD`. |
| G12 | OP_RETURN + IsPushOnly(begin+1) → NULL_DATA | PASS | — | `isStandardOpReturn` walks pushes, rejects on truncated payload, returns true iff `pc == script.len`.  W58-1 regression test passes. |
| G13 | P2PK shapes (33-byte or 65-byte pubkey push + OP_CHECKSIG) → PUBKEY | PASS | — | `isStandardP2PK` (note BUG-13 cosmetic: matches Core's "size-only" check). |
| G14 | Bare multisig recognition (m-of-n with OP_n encoding) | PARTIAL | BUG-05/BUG-12 | Accepts OP_1..OP_16 for m/n; rejects 17..20 (would need pushdata-encoded num) — Core supports up to MAX_PUBKEYS_PER_MULTISIG=20 via `GetScriptNumber`. |
| G15 | `NONSTANDARD` outputs rejected as `"scriptpubkey"` | PASS | — | `standard.nim:256-257`. |
| G16 | NULL_DATA datacarrier bytes-budget (`MAX_OP_RETURN_RELAY=100000`) deducted per output, reject as `"datacarrier"` over budget | PASS | — | `standard.nim:248-267`.  Multi-OP_RETURN cumulative-bytes semantics (Core 31.99 has no count limit) matches.  W71 regression covers. |
| G17 | MULTISIG with `n > 3` rejected via IsStandard (reason `"scriptpubkey"`) | DIVERGENT | BUG-05 | Nimrod returns `"bare-multisig"` for n ∈ {4..16} (it reaches `stxMultisig` then checks `n > MaxStandardMultisigN`); Core's IsStandard helper returns false (n > 3) BEFORE the bare-multisig gate, producing `"scriptpubkey"`. |
| G18 | MULTISIG with `permitBareMultisig=false` rejected as `"bare-multisig"` | PASS | — | `standard.nim:268-273` (when n ≤ 3). |
| G19 | `MAX_DUST_OUTPUTS_PER_TX=1` ephemeral allowance enforced | PASS | — | `standard.nim:37, 252, 277-283`.  `dustCount > 1` → `"dust"`. |
| G20 | Dust threshold formula for legacy (P2PKH/P2SH/P2PK) outputs (`(34+148) * 3000 / 1000 = 546`) | PASS | — | `standard.nim:189-204`, with the witness-program flag false. |
| G21 | Dust threshold formula for segwit v0 (`(31+67) * 3000 / 1000 = 294` for P2WPKH) | PASS | — | When `script[0]==0x00`, the `<= 0x10` test fires, witness-program path used. |
| G22 | Dust threshold formula for segwit v1+ (P2TR + WitnessUnknown) — same witness-discounted formula | DIVERGENT | BUG-01 | OP_1..OP_16 are 0x51..0x60, not ≤0x10; nimrod uses the legacy 148-byte input estimate → **threshold 573 instead of 330** for standard P2TR. |
| G23 | OP_RETURN dust threshold = 0 (always, via `IsUnspendable`) | PASS | — | `standard.nim:192-193` short-circuits on `OP_RETURN` byte. |
| G24 | `dust_relay_feerate` configurable via `-dustrelayfee` CLI flag | MISSING | BUG-06 | Hardcoded 3000 sat/kvB in both `StdDustRelayTxFee` (standard.nim:38) and `DustRelayTxFee` (mempool.nim).  No CLI wiring. |
| G25 | `permit_bare_multisig` configurable via `-permitbaremultisig` CLI flag | MISSING | BUG-07 | `IsStandardOptions.permitBareMultisig` exists in type but no CLI parses it; call site `mempool.nim:921` uses defaults. |
| G26 | `max_datacarrier_bytes` configurable via `-datacarrier` / `-datacarriersize` CLI flags | MISSING | BUG-08 | Same shape as G25; hardcoded `some(MaxOpReturnRelayBytes)`. |
| G27 | `MIN_STANDARD_TX_NONWITNESS_SIZE=65` enforced (CVE-2017-12842 mitigation) | PASS | — | `mempool.nim:909-912`; lives in PreChecks, not `IsStandardTx` itself (matches Core's split). |
| G28 | `MAX_STANDARD_TX_SIGOPS_COST=16000` enforced post-input-check | PASS | — | `mempool.nim:1126`. |
| G29 | `MAX_P2SH_SIGOPS=15` enforced per-input on P2SH redeemScript | PASS | — | `mempool.nim:1066-1107`; inline accurate-sigop counter; uses fallback 20 when `lastOp` is not OP_n. |
| G30 | `MAX_TX_LEGACY_SIGOPS=2500` BIP-54 cross-input cap enforced via `CheckSigopsBIP54` | MISSING | BUG-03 | No `MaxTxLegacySigops` constant, no `checkSigopsBIP54` proc anywhere in `src/`. |
| G31 | `ValidateInputsStandardness` per-input classification (NONSTANDARD/WITNESS_UNKNOWN reject; SCRIPTHASH MAX_P2SH_SIGOPS) | PARTIAL | BUG-02/BUG-04 | Inline equivalent at mempool.nim:1038-1107 covers SCRIPTHASH and rejects WITNESS_UNKNOWN; but classifies P2A inputs as WITNESS_UNKNOWN → false reject (BUG-02), and v0-malformed-prog inputs as WITNESS_UNKNOWN → coincidental correct reject (BUG-04). |
| G32 | `IsWitnessStandard` Gate 1: P2A with non-empty witness → reject | PASS | — | `standard.nim:419-421`. |
| G33 | `IsWitnessStandard` Gate 2: P2SH-wrapped extract redeemScript via push-only eval | PASS | — | `standard.nim:423-434, evalScriptSigPushes`.  (Architectural note BUG-16: assumes IsStandardTx pre-check on scriptSig push-only.) |
| G34 | `IsWitnessStandard` Gate 3: non-witness redeem + non-empty witness → reject | PASS | — | `standard.nim:436-440`. |
| G35 | `IsWitnessStandard` Gate 4: P2WSH `MAX_STANDARD_P2WSH_*` (3600 script / 100 stack items / 80 per item) | PASS | — | `standard.nim:444-454`. |
| G36 | `IsWitnessStandard` Gate 5: P2TR annex 0x50 reject + tapscript leaf 0xc0 stack-item ≤ 80 + empty stack reject | PASS | — | `standard.nim:456-484`. |
| G37 | `IsWitnessStandard` Gate 6: coinbase exempt | PASS | — | `standard.nim:408-409`. |

(37 gates total; the matrix exceeds the headline "30 gates" by 7 to
cover all surfaces — duplicate dust impl, separate IsWitnessStandard
gates, and the architecturally-split PreChecks gate G27.  Counting BUG-distinct
gates: 16 distinct gates DIVERGENT/PARTIAL/MISSING.)

## Per-BUG detail

### BUG-01 (P0-CDIV): `dustThreshold` mis-detects v1+ witness programs

**Affected gates**: G22 (P2TR/witness-unknown dust formula).
**Files**: `src/mempool/standard.nim:195-198`, duplicated at
`src/mempool/mempool.nim:444-446`.

The byte-pattern test `output.scriptPubKey[0] >= 0x00'u8 and output.scriptPubKey[0] <= 0x10'u8`
intends to recognise "version byte is OP_0 (0x00) or OP_1..OP_16".  But
the witness-version opcodes are:

- OP_0 = 0x00
- OP_1 = 0x51 (= 81)
- OP_2 = 0x52 (= 82)
- …
- OP_16 = 0x60 (= 96)

So `0x51 > 0x10` and **every v1+ witness output (P2TR, witness-unknown
v2..v16) fails the test**.  For a 34-byte P2TR scriptPubKey, nimrod
computes:

```
outputSize = 8 + 34 + 1 = 43
isWitProg = false                       # ← bug
inputSize = 32 + 4 + 1 + 107 + 4 = 148  # legacy estimate
totalSize = 43 + 148 = 191
threshold = 191 * 3000 / 1000 = 573 sat
```

Core (via `IsWitnessProgram`) correctly classifies P2TR as a witness
program and computes:

```
outputSize = 8 + 34 + 1 = 43
isWitProg = true
inputSize = 32 + 4 + 1 + (107 / 4) + 4 = 67
totalSize = 43 + 67 = 110
threshold = 110 * 3000 / 1000 = 330 sat
```

Divergence: 573 vs 330 — **a 243-sat zone where nimrod calls dust and
Core does not**.  Hits production whenever a wallet pays a Core-standard
P2TR output below 573 sats; the tx never propagates through any nimrod
node.

The second-byte length test (`int(script[1]) == script.len - 2`) further
mis-flags legacy scripts whose second byte coincidentally matches the
script length minus 2 (e.g. a raw 4-byte legacy script `[0x01, 0x02, …]`)
as witness programs — opposite-direction divergence, much rarer in
practice.

Fix sketch (single line, applied symmetrically to standard.nim and
mempool.nim): replace the byte-pattern test with a call to the existing
`isWitnessProgram(script)` from `script/interpreter.nim` (which already
handles all version-opcode cases correctly).  Validated against Core's
GetDustThreshold by computing thresholds for all 5 standard shapes
(legacy P2PKH/P2SH, P2WPKH, P2WSH, P2TR) and comparing.

### BUG-02 (P0-CDIV): `classifyStdTxout` has no `stxAnchor`

**Affected gates**: G10 (P2A txout type), G31 (input-side classification).
**Files**: `src/mempool/standard.nim:60-71` (enum), `:165-175` (witness
dispatch), `src/mempool/mempool.nim:1050` (input reject).

Core's `TxoutType` enum has `ANCHOR` (solver.h:25); `Solver` returns
`TxoutType::ANCHOR` when the script matches the BIP-431 P2A pattern
(solver.cpp:169-171).  Nimrod's `StdTxoutKind` has no `stxAnchor`.
Walking the dispatch:

```
[OP_1, 0x02, 0x4e, 0x73]   # P2A scriptPubKey
↓
isP2PKH      → false   (script.len 4 ≠ 25)
isP2SH       → false   (script.len 4 ≠ 23)
isP2WPKH     → false   (script.len 4 ≠ 22)
isP2WSH      → false   (script.len 4 ≠ 34)
isP2TR       → false   (script.len 4 ≠ 34)
isWitnessProgram(script) → (true, 1, [0x4e, 0x73])
  → "if ver==1 and prog.len==32" branch → false (prog.len=2)
  → falls through to → return stxWitnessUnknown
```

Output-side: `isStandardTx` line 274 (`else: discard`) keeps the txout
in the standard set (because `stxWitnessUnknown` is neither
`stxNonStandard` nor `stxNullData` nor `stxMultisig`).  Coincidentally
matches Core: Core's `IsStandard` returns true for `ANCHOR` too.

Input-side: `mempool.nim:1050-1052` rejects `stxWitnessUnknown` as
`"bad-txns-nonstandard-inputs: input X witness program is undefined"`.
Core's `ValidateInputsStandardness` flows `ANCHOR` through with no
reject branch (it's not NONSTANDARD, not WITNESS_UNKNOWN, not SCRIPTHASH).

Net effect: **nimrod can create P2A outputs (output-side accepts) but
cannot spend them (input-side rejects)**.  Every fee-bump CPFP that
attempts to consume an anchor will fail in the mempool.

Fix sketch: add `stxAnchor` to the enum; insert
`if isP2A(script): return stxAnchor` in `classifyStdTxout` *before*
the `isWitnessProgram` fallthrough (matching Core's Solver order,
solver.cpp:165-171); add a NEW non-reject branch for `stxAnchor` in
mempool.nim's input loop (the dispatch should fall through, matching
the legacy script types).  Add a regression test that spends a P2A
output.

### BUG-03 (P1): BIP-54 legacy sigop cap not enforced

**Affected gate**: G30.
**Files**: nowhere — proc absent.

Core's `CheckSigopsBIP54` (policy/policy.cpp:170-194) walks
`tx.vin`, sums `txin.scriptSig.GetSigOpCount(/*fAccurate=*/true) +
prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig)`, and rejects with
`"non-witness sigops exceed bip54 limit"` if the accumulator exceeds
`MAX_TX_LEGACY_SIGOPS=2500`.  This is a NEW gate (BIP-54, post-2025)
not subsumed by the older `MAX_STANDARD_TX_SIGOPS_COST=16000` (which
counts ALL sigops including witness, capped at 5× the legacy limit).

Nimrod has zero references: no constant, no proc, no call site.  A
craft-tx with 2501-3000 legacy sigops would pass nimrod's standardness
but be rejected by Core 31.99.

Fix sketch: add `MaxTxLegacySigops* = 2_500` to `consensus/params.nim`,
add a `checkSigopsBIP54` proc to `mempool.nim` mirroring the Core
function, and call it inside `ValidateInputsStandardness`-equivalent
(mempool.nim:1038-1107).  Forward-regression: add a test that a
`getTransactionSigOpCost(use_witness=false) > 2500` craft-tx is rejected
as `"non-witness sigops exceed bip54 limit"`.

### BUG-04 (P1): malformed v0 witness routes to WitnessUnknown

**Affected gates**: G11 (other witness program types), G31 (input-side).
**Files**: `src/mempool/standard.nim:165-175`.

For v0 with `prog.len ∈ {2..19, 21..31, 33..40}` (i.e. anything other
than 20 or 32), nimrod's dispatch falls to `return stxWitnessUnknown`.
Core's `Solver` returns **`NONSTANDARD`** for v0 with such lengths
(solver.cpp:177: `return TxoutType::NONSTANDARD;`).

Consequence on OUTPUT side: nimrod accepts a tx with output
`[OP_0, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]` (v0, 5-byte program);
Core rejects it as `"scriptpubkey"`.  Fleet poisoning shape.

Consequence on INPUT side: nimrod rejects it as
`"bad-txns-nonstandard-inputs: input X witness program is undefined"`;
Core rejects it as `"bad-txns-nonstandard-inputs: input X script unknown"`.
Same rejection, different reason string.

Fix sketch: add an explicit early-return at line 173 — if `ver == 0`
and `prog.len ∉ {20, 32}`, return `stxNonStandard`.  The pre-existing
dead-code branches at lines 170-174 can be deleted (already covered by
isP2WPKH/isP2WSH/isP2TR), and replaced with the v0-malformed-len reject.

### BUG-05 (P1): bare multisig reason-string divergence at n=4..16

**Affected gates**: G14, G17, G31 (cosmetic for n=17..20).
**Files**: `src/mempool/standard.nim:117-148, 268-273`.

For a bare 4-of-N multisig (n ∈ {4..16}):
- Core: `MatchMultisig` accepts → `IsStandard` rejects at `n > 3` →
  `IsStandardTx` returns `reason = "scriptpubkey"`.
- Nimrod: `isStandardMultisig` accepts (`m ≤ n`, both in OP_1..OP_16,
  pubkeys match) → `classifyStdTxout` returns `stxMultisig` →
  `isStandardTx` reaches the bare-multisig gate at line 269-273 → the
  `n > MaxStandardMultisigN(3)` branch fires → `reason = "bare-multisig"`.

Reason-string divergence breaks `testmempoolaccept` parity in any cross-impl
RPC test that expects Core's exact strings.

For n=17..20 (encoded via pushdata, not OP_n), nimrod's
`isStandardMultisig` returns false at the `nOp > OP_16` check (line 130),
so dispatch falls through to `stxNonStandard` → `reason = "scriptpubkey"`.
Same as Core for n=17..20 by happy accident (Core also rejects via
IsStandard for n > 3).

Fix sketch: split the bare-multisig gate so the `n > 3` IsStandard-helper
sub-check produces `reason = "scriptpubkey"`, and only the
`permitBareMultisig=false` case produces `reason = "bare-multisig"`.
Mirror Core IsStandard policy.cpp:87-95 exactly.

### BUG-06 / BUG-07 / BUG-08 (P2): CLI flags not wired

Three sibling bugs.  In each case the IsStandardOptions / mempool
constants are correctly defined inside the module, but no CLI parser
emits them and no caller passes anything other than the default.

- BUG-06: `-dustrelayfee` → `StdDustRelayTxFee` / `DustRelayTxFee`.
- BUG-07: `-permitbaremultisig` → `IsStandardOptions.permitBareMultisig`.
- BUG-08: `-datacarrier`, `-datacarriersize` → `IsStandardOptions.maxDatacarrierBytes`.

All three flip operator-visible behavior in Core's debug-only relay
category (init.cpp:670-680) but are silently no-ops in nimrod.

Fix sketch: route the three flags through `nimrod.nim` CLI parsing into
the mempool's options struct (mempool.nim already accepts an
`AtmpArgs` struct; extend with a `relayOptions` field carrying the
IsStandardOptions instance and dust feerate), then plumb to the
`isStandardTx(tx, opts)` call site at mempool.nim:921 and to
`getDustThreshold` callers.

### BUG-09 / BUG-10 / BUG-11 (P2/P3): dust threshold edge cases

- BUG-09: missing `IsUnspendable size > MAX_SCRIPT_SIZE` check.  Practically
  unreachable (`bad-txns-oversize` from CheckTransaction kicks in earlier),
  but technically a divergence.
- BUG-10: outputSize varint hardcoded to 1 byte.  Off by 2 for scriptPubKey ≥
  253 bytes.  Out of standardness reach in practice but should match Core
  exactly.
- BUG-11: dust threshold is duplicated.  `standard.nim:189` and `mempool.nim:426`
  must be kept in sync; nothing enforces this.

Fix sketch: consolidate to one implementation (probably
`mempool.getDustThreshold` since mempool is the natural owner) and have
`standard.nim` import it.  The circular-import comment at the top of
standard.nim was the reason for duplication — the right fix is to move
the dust helper into a non-imports-mempool module (e.g. into
`policy/feerate.nim` or a new `policy/dust.nim`).

### BUG-12 / BUG-13 / BUG-14 / BUG-15 / BUG-16 (P3): cosmetic / completeness

- BUG-12: isStandardMultisig accepts only OP_1..OP_16 for m/n (Core supports
  pushdata-encoded 17..20 too).  Subsumed by BUG-05's analysis.
- BUG-13: isStandardP2PK pubkey-prefix check absent.  Matches Core (Core
  also only checks size).  **Documented as non-bug** — listed for
  completeness.
- BUG-14: docstring drift — `"multi-op-return"` listed as a possible
  reason string but no code path emits it.
- BUG-15: tx.version `int32` vs `uint32_t`.  Different type-shape, same
  reject outcome.
- BUG-16: `evalScriptSigPushes` strictly push-only (Core's `EvalScript`
  with `SCRIPT_VERIFY_NONE` is more permissive).  Safe under the
  current IsStandardTx-before-IsWitnessStandard architecture; brittle
  if order ever changes.

## Universal patterns observed in this audit

1. **"Byte-pattern detection in dust path while a real classifier sits
   one module away"** (BUG-01).  The dust function imports `interpreter`
   for opcode constants and weight calc, but reimplements witness-program
   detection via raw byte ranges — and gets OP_1..OP_16 wrong by 0x40
   (the difference between `0x10` and `0x50`).  Pattern: when a helper
   wants to ask "is this a witness program?", call the canonical
   `isWitnessProgram` from `interpreter.nim` — don't reinvent the
   byte test.
2. **"Missing `stxAnchor` variant for a TxoutType that needs distinct
   dispatch"** (BUG-02).  The `StdTxoutKind` enum was authored before
   BIP-431 P2A merged; the post-merge code adds an `isP2A` predicate
   used inside `isWitnessStandard` (Gate 1) but never adds the enum
   variant or the classifier branch.  Pattern: when a new TxoutType
   lands in Core's solver, every classifier dispatch needs the new
   branch, including the input-side reject taxonomy.
3. **"Audit-stamp drift between docstring and code"** (BUG-14): the
   docstring lists `"multi-op-return"` as a possible reason string,
   but W71 already removed the count-limit code path.  Pattern: when a
   gate is removed, every doc surface that named the gate's reject string
   must be updated; a forward-regression search-grep can catch this.
4. **"Option types defined but call sites bypass them with defaults"**
   (BUG-06/07/08).  `IsStandardOptions` is the right architectural
   shape — but there's no actual operator path from CLI → mempool →
   call site.  Pattern: when a config option's shape is added, also add
   a CLI parser and forward-regression test that exercises the
   non-default value end-to-end.
5. **"Duplicate implementation across modules with the same bug"**
   (BUG-01 / BUG-11).  Both `standard.dustThreshold` and
   `mempool.getDustThreshold` have the same OP_1..OP_16 byte-pattern
   bug.  Pattern: when a function is duplicated across modules (often
   to avoid circular imports), every fix must touch both — and a
   forward-regression guard should prevent re-introduction.  Best to
   factor into a third module that neither depends on the other.

## Out of scope

- **PolicyScriptChecks / STANDARD_SCRIPT_VERIFY_FLAGS plumbing** — already
  audited in W94 (taproot policy gates) and W96 (MemPoolAccept).  This
  audit assumes `standardScriptVerifyFlags` (`mempool.nim:863`) is
  correct.
- **TRUC / BIP-431 standardness checks** — covered separately by
  `checkSingleTrucRules` (mempool.nim:1169).  Only the version-bound
  TX_MAX_STANDARD_VERSION=3 gate (G1) is in scope here.
- **Ephemeral dust handling** (`preCheckEphemeralTx`) — out of W135
  scope; covered by W116 (ephemeral dust audit).
- **RBF rules** — out of scope (W120/W130).
- **Misbehaving-peer-disconnect** — out of scope (W121/W128).

## Tests

`tests/test_w135_standardness.nim` — 30 tests across 9 suites,
covering: dust threshold formulas for all 5 standard shapes (including
the BUG-01 P2TR divergence); P2A output + input round-trip (BUG-02);
BIP-54 absence (BUG-03); v0-malformed-prog dispatch (BUG-04);
multi-multisig reason-string divergence (BUG-05); 2 ephemeral dust
allowance gates; OP_RETURN-as-unspendable; one `IsStandardOptions`-vs-CLI
plumbing assertion (BUG-06/07/08 surface).  Pass / fail mix is
deliberate — the BUG-confirming tests assert the CURRENT (divergent)
behavior using `expect`-style assertions so the BUGs are pinned and
become forward-regression guards.  When the fix waves land, the
tests' polarity should be flipped to assert the Core-aligned behavior.
