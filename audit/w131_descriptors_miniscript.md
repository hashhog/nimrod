# W131 — Descriptors + Miniscript audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W131)
Target: `src/wallet/descriptor.nim` (1233 LOC) and
`src/wallet/miniscript.nim` (1928 LOC).
Driver: cross-impl fleet audit — every wallet that supports descriptors
must parse / round-trip / expand / generate the same scripts as Bitcoin
Core; every miniscript that survives Core's parser+type-check+compile
must round-trip identically; every wallet that *fails* a Core-rejected
descriptor must fail with the same error class.  A divergent gate
causes a wallet to either (a) accept a string Core rejects (P0-CDIV if
the resulting script is policy-broken) or (b) reject a string Core
accepts (UX bug + interoperability bug).

## Status

**BUGS FOUND — 24 distinct gates PARTIAL / MISSING / WRONG (of 30).**

Of those:
  - **2 P0-CONS / P0-CDIV** — descriptor `tr()` script-tree body is
    **silently discarded** during parse, so any tr() with embedded
    scripts is treated as key-path-only by nimrod — the wallet derives
    the *wrong* taproot output key (no tweak applied to merkle root)
    and a watch-only import of `tr(K,{pk(A),pk(B)})` cannot recognise
    deposits.  This is an **active** divergence, not deferred-risk:
    every tr() with a script tree round-trips through nimrod with the
    tree dropped (bug previously documented inline as "BUG-5 / FIX-38"
    but never closed).  Plus: descriptor never invokes `parseMiniscript`,
    so `wsh(or_d(c:pk_k(...),...))` is rejected as "unknown descriptor
    function" (effectively offline for any non-trivial wallet).
  - **9 P1** — missing `multipath` (BIP-389) parser, no `musig()`
    (BIP-390) PubkeyProvider, no descriptor `InferScript`, miniscript
    `MaxScriptSize` / `MaxStackSize` / `MaxOpsPerScript` un-enforced at
    parse time, miniscript parser arms missing `and_n` (only the
    helper-encoding via `andor(X,Y,0)` works), wrapper-stack
    decomposition not supported (one wrapper char per `:` only — Core
    accepts `dv:older(1)` as `d:` and `v:` stacked), `tr()` Top-level
    rejection of `pkh()` is correct but `tr()` body never enters
    miniscript context, `BIP32PubkeyProvider` rejects xpubs with no
    derivation path attached as "not implemented", BIP-32 cache /
    write-cache absent (every derivation re-derives from the root).
  - **5 P2** — named limits missing, descriptor `combo()` does not
    emit P2SH-P2WPKH redeem-script `out.scripts` map (Core
    descriptor.cpp:1267), no `DescriptorImpl::Clone()`, no
    `IsSingleType()` distinction, no PSBT `tap_tree` round-trip from
    parsed tr() tree.
  - **8 P3** — cosmetic: `ToStringExtra`, key origin `[xpub]` formatting
    parity, descriptor-ID stability, error-message format, hardened
    apostrophe-vs-h normalisation in canonical form, `Func("...")`
    style vs string-match style.

The CORE STRUCTURE OF DESCRIPTOR PARSING (basic non-tr() scripts +
BIP-380 BCH checksum + non-ranged BIP-32 key + multi/sortedmulti +
multi_a/sortedmulti_a fragment recognition for tapscript) is **PRESENT
and matches Core's `ParseScript`** for the simple top-level forms
`pk()`, `pkh()`, `wpkh()`, `sh()`, `wsh()` (without miniscript bodies),
`tr()` (key-path-only), `rawtr()`, `combo()`, `addr()`, `raw()`,
`multi()`, `sortedmulti()`, `multi_a()`, `sortedmulti_a()`.  The
BCH-checksum algorithm in `descriptorPolymod`+`computeDescriptorChecksum`
is byte-identical to Core's `DescriptorChecksum` (matches against
canonical test vectors).

The CORE STRUCTURE OF MINISCRIPT (fragment enum, B/V/K/W type system,
wrappers, combinators, types with z/o/n/d/u/e/f/s/m/x/k flags, basic
satisfaction) is **PRESENT and matches Core's `script/miniscript.h`
Fragment enum** for all 28 fragments.  Compile is byte-identical to
Core's `BuildScript` for the fragments tested.

**The missing pieces are at the boundary**: descriptor cannot invoke
miniscript (so `wsh(<miniscript>)` fails); descriptor `tr()` cannot
hold scripts; multipath / BIP-389 parsing is absent; wrapper-stack
syntax (`dv:`, `tvu:`) is rejected; multipath / musig are absent.

Net effect: nimrod can parse and expand the **simple** descriptor
forms in `descriptor_tests.cpp`'s first 30 lines (pk/pkh/wpkh/sh/wsh
of single key + multi/multi_a/tr/rawtr) but immediately diverges from
Core on anything that combines descriptors+miniscript or uses
script-tree taproot.

## Method

1. Read Core refs:
   - `bitcoin-core/src/script/descriptor.cpp` (3006 LOC) — entire
     descriptor parsing and inference stack.  Class hierarchy at
     `DescriptorImpl` (:800), 13 concrete subclasses
     (`PKDescriptor`, `PKHDescriptor`, `WPKHDescriptor`,
     `ComboDescriptor`, `MultisigDescriptor`, `MultiADescriptor`,
     `SHDescriptor`, `WSHDescriptor`, `TRDescriptor`,
     `MiniscriptDescriptor`, `RawTRDescriptor`, `RawDescriptor`,
     `AddressDescriptor`), parser at `ParseScript` (:2273),
     `ParsePubkey`/`ParsePubkeyInner` (:1876/:1956),
     `ParseKeyPath` (:1789).  Inference: `InferScript` (:2691),
     `InferMultiA` (:2675), `InferXOnlyPubkey` (:2163),
     `InferPubkey` (:2145).
   - `bitcoin-core/src/script/miniscript.h` (2707 LOC) +
     `bitcoin-core/src/script/miniscript.cpp` (432 LOC).  Fragment
     enum (:211), Type system (line ~150), ParseContext (:1756),
     `ComputeType` (:297), `ComputeScriptLen` (:300), `Sanitize` /
     `SanityCheck` (:1571 onward), `MaxScriptSize` (:282),
     `MAX_TAPMINISCRIPT_STACK_ELEM_SIZE=65` (:269),
     `MAX_TAPSCRIPT_SAT_SIZE` (:280).
   - `bitcoin-core/src/test/descriptor_tests.cpp` (:592 onwards) —
     `BOOST_AUTO_TEST_CASE(descriptor_test)`, ~700 lines of
     `Check(...)` and `CheckUnparsable(...)` invocations.  Covers
     hybrid-pubkey rejection, hardened uncompressed rejection,
     fingerprint length, path-overflow, multipath, multi_a, tr() tree.
   - `bitcoin-core/src/test/miniscript_tests.cpp` (:489 onwards) —
     `BOOST_AUTO_TEST_CASE(fixed_tests)` covers 1000+ ms+hexscript
     pairs over both P2WSH and Tapscript contexts.
   - `bitcoin-core/src/test/data/descriptor_tests_external.json` —
     external corpus (BIP-380 reference vectors).
   - `bitcoin-core/src/script/script.h:34,37`
     `MAX_PUBKEYS_PER_MULTISIG=20`, `MAX_PUBKEYS_PER_MULTI_A=999`.

2. Read nimrod targets:
   - `src/wallet/descriptor.nim` — entire descriptor stack: AST at
     line 13-105, BCH checksum at :122-207, key-path at :213-266,
     extended-key/WIF decoders :272-356, expand at :572-719, parser
     at :725-1061, descriptor wrapper at :1063-1094, to-string at
     :1100-1146, derive at :1158-1185, info at :1187-1233.
   - `src/wallet/miniscript.nim` — entire miniscript stack: AST and
     types :12-142, type computation at :265-744, script compilation
     at :758-1062, satisfaction at :1068-1450, parser at
     :1542-1856, to-string at :1862-1927.

3. For each of 30 audit gates, classify nimrod's behaviour:
   - **PRESENT** — implementation matches Core line-by-line.
   - **PARTIAL** — implementation has the right shape but omits a
     forward-compat hook, named constant, or pre-flight check.
   - **MISSING** — implementation does not exist in nimrod.
   - **WRONG** — implementation exists but silently corrupts /
     accepts a Core-rejected string / rejects a Core-accepted string.

4. Catalogue every PARTIAL / MISSING / WRONG as a BUG with priority.

5. Re-verify W127 BUG-6 status: BIP-342 multi_a / sortedmulti_a in
   nimrod miniscript and descriptor.

Out of scope:
  - **BIP-32 derivation correctness** — covered by W31 / W82.
  - **WIF encoding / decoding correctness** — covered by `decodeWIF`
    tests in `test_wallet.nim`.
  - **PSBT field round-trip** — covered by W117 wallet audit (W118)
    + dedicated PSBT-v0/v2 waves.
  - **Wallet signing** — covered by W127 BUG-3 / BUG-11 (Schnorr
    signing).
  - **Coin selection driven by descriptors** — covered by W129.

## Audit gates (30)

Each gate cites Core line(s) and the nimrod code reference for the
match (PRESENT) or the closest analog / absence (PARTIAL / MISSING /
WRONG).

### Subsystem A — Descriptor parser core (gates 1-8)

#### Gate 1 — BIP-380 BCH checksum encode / decode — **PRESENT**
Reference: `bitcoin-core/src/script/descriptor.cpp:73-115`
(`DescriptorChecksum`, `Polymod` initial state `1`, generator
constants `0xf5dee51989` etc, 5-bit Bech32 charset output, 3-character
class grouping).
Nimrod: `src/wallet/descriptor.nim:144-181`
(`computeDescriptorChecksum` + `descriptorPolymod`).  All 5 generator
constants match.  Initial state `c=1`.  XOR-1 trick on final value.
`InputCharset` matches Core's table byte-for-byte (verified in
`test_descriptor.nim`).
Status: PRESENT — checksums round-trip with Core CLI fixtures.

#### Gate 2 — Top-level descriptor function recognition — **PRESENT**
Reference: `descriptor.cpp:2273-2570` `ParseScript`: 13 distinct
top-level / inner Funcs (`pk`, `pkh`, `wpkh`, `combo`, `multi`,
`sortedmulti`, `multi_a`, `sortedmulti_a`, `sh`, `wsh`, `addr`,
`tr`, `rawtr`, `raw`).
Nimrod: `descriptor.nim:904-1061` `parseDescriptorNode` recognises
all 13 names (line 912-1060).  Status: PRESENT — each name has its
own `case` arm.

#### Gate 3 — Context-restricted parsing (`wpkh` only in TOP or P2SH,
       `tr` only in TOP, `multi_a` only in P2TR, etc.) — **PRESENT**
Reference: `descriptor.cpp:2290,2301,2319,2360,2409,2423,2436,2447,
2459` — every Func is gated on `ParseScriptContext`.
Nimrod: `descriptor.nim:920,928,936,944,952,981,989,1013,1035,1044,
1053` — every `case` arm starts with a context check raising
`DescriptorError` if violated.  Status: PRESENT — every restriction
matches.

#### Gate 4 — `tr()` script-tree parsing — **WRONG / P0-CDIV**
Reference: `descriptor.cpp:2459-2570` — `tr()` parses optional second
argument as a binary tree of subscripts; the parser tracks
`branches` and `depths`, calls `ParseScript(..., ParseScriptContext::
P2TR, ...)` on every leaf, builds `TRDescriptor` with `depths` AND
the leaf descriptors, then `MakeScripts` (:1460) invokes
`TaprootBuilder` to compute the merkle root and tweak.
Nimrod: `descriptor.nim:956-978`.  **The tree is silently discarded**:
the parser sees the comma, then "skip the script-tree arg, balancing
parentheses to find the closing ')'" (line 960-975).  The resulting
`DKTr` node has `tree=none(TrTreeNode)`, `depths=@[]`,
`scripts=@[]`.  At expand time (line 634-646), the tweak is computed
with `merkleRoot=empty`, yielding the key-path-only output key —
which is WRONG for any tr() with a script tree.
**BUG-1 (P0-CDIV)**: tr() script-tree body silently discarded;
descriptor's output address diverges from Core for any
`tr(K,{...})` with non-empty tree.  Inline comment at line 960 calls
this "TODO: ... BUG-5", but the BUG was never closed in any wave.

#### Gate 5 — Miniscript body inside `wsh()` / `tr()` — **MISSING / P0-CDIV**
Reference: `descriptor.cpp:2436-2446` — when no `Func("...")` matches
inside a `wsh()` / `tr()` body, the parser falls through to
`MiniscriptDescriptor` (line ~2532) which invokes
`miniscript::FromString` with `ctx=P2WSH` or `P2TR`.  This is the
**only** way to enable Miniscript-driven descriptors like
`wsh(or_d(c:pk_k(...),and_v(c:pk_k(...),older(1000))))`.
Nimrod: `descriptor.nim:1060`.  When no known descriptor function
matches, it raises `"unknown descriptor function: <name>"`.  Never
hands off to `parseMiniscript`.  Net: nimrod **cannot parse any
miniscript-bearing descriptor**.  The DKMiniscript enum case at
line 74 + 718-719 is a dead enum: `expandNode` for `DKMiniscript`
unconditionally raises `"miniscript not implemented"`.
**BUG-2 (P0-CDIV)**: miniscript hook from descriptor parser absent.
Any production wallet using descriptors like
`wsh(multi(2,xpub.../0/*,xpub.../1/*))` works (because that's still
the `multi` arm), but `wsh(or_d(...))` and any miniscript-using
descriptor fails outright.

#### Gate 6 — Hybrid pubkey rejection (`combo()`/`pk()`/`pkh()`) — **PARTIAL**
Reference: `descriptor.cpp:1908-1909,1918` — `ParsePubkeyInner`
explicitly checks `pubkey.IsValid() && !pubkey.IsHybrid()` and
rejects with `"Hybrid public keys are not allowed"`.  See
`descriptor_tests.cpp:614-616`.
Nimrod: `descriptor.nim:826-846`.  Hex parser accepts 66 or 130
hex chars (33 or 65 bytes), but does NOT check the first byte for
the hybrid markers `0x06` / `0x07`.  A 65-byte buffer with byte 0
`= 0x06` (a hybrid encoding) is accepted as "uncompressed" via the
65-byte arm at line 833 which raises a different error
(`"uncompressed public keys not supported in descriptors"`).
But for descriptors that DO allow uncompressed (e.g. `pk()` at top
level — Core's :1879 `permit_uncompressed = ctx == TOP || ctx ==
P2SH`), nimrod would accept a hybrid `0x06...`/`0x07...` key while
Core rejects it.  Different error class for the wrong reason.
**BUG-3 (P1)**: hybrid-pubkey rejection has different error than
Core, and is wrong for `pk()` / `pkh()` at top level.

#### Gate 7 — Uncompressed pubkey rejection in witness context — **PRESENT**
Reference: `descriptor.cpp:1879,1881` — `permit_uncompressed = ctx
== TOP || ctx == P2SH`.  Anywhere else, `pubkey.IsCompressed()` is
required.
Nimrod: `descriptor.nim:850-851`: explicit check `if not compressed
and ctx in {ContextP2WPKH, ContextP2WSH, ContextP2TR}` raises
`"uncompressed keys not allowed in witness context"`.
Status: PRESENT — error message differs from Core, behaviour matches.

#### Gate 8 — Key origin `[fingerprint/path]` parsing — **PARTIAL**
Reference: `descriptor.cpp:2087-2144` `ParsePubkey` parses
`[fingerprint/derivation_path]` prefix with strict validation:
fingerprint must be 4 bytes (8 hex chars), each path segment must
be a valid uint32, optional `'` / `h` for hardened.
Nimrod: `descriptor.nim:771-790`.  Parses `[fingerprint/path]`.
Validates fingerprint length is 8 hex chars (line 778).  But:
  - Does NOT check fingerprint contains only hex chars (relies on
    later `parseHexBytes` raising via `parseHexInt`).
  - Does NOT detect missing `[` start bracket vs missing `]` end —
    Core's error message is "Multiple ']' characters found for a
    single pubkey" (line 603 in tests); nimrod just raises
    "expected ']' at position N".
  - Does NOT support multipath placeholder `<0;1>` inside
    fingerprint or path — see Gate 13.
**BUG-4 (P3)**: error-message and edge-case fidelity gaps; functional
behaviour is mostly correct but UX-fidelity diverges.

### Subsystem B — Descriptor expansion & inference (gates 9-14)

#### Gate 9 — Ranged descriptor expansion — **PRESENT**
Reference: `descriptor.cpp:1095-1130` (PKHDescriptor::MakeScripts +
DescriptorImpl::ExpandHelper).  Ranged descriptors expand per
position; non-ranged at position 0 only.
Nimrod: `descriptor.nim:1158-1185` `deriveAddresses`/`deriveScripts`.
Position loop honours `isRange()`.  Status: PRESENT.

#### Gate 10 — `combo()` emits P2PK + P2PKH + (optional)
       P2WPKH + P2SH-P2WPKH — **PARTIAL**
Reference: `descriptor.cpp:1246-1271` ComboDescriptor produces 4
scripts (P2PK, P2PKH, P2WPKH, P2SH-P2WPKH) when compressed; first
two only when uncompressed.  Crucially, `MakeScripts` (:1259) **adds
the P2SH redeem script to `out.scripts` map** so the wallet can
sign P2SH-P2WPKH spends.
Nimrod: `descriptor.nim:680-716`.  Emits all 4 scripts correctly.
But `ExpandedDescriptor` does NOT have a separate field for redeem
scripts that downstream signing code needs.  The P2SH wrapper at
:709-716 builds the redeem script but never returns it through any
field.  A wallet importing `combo(K)` cannot sign P2SH-P2WPKH inputs.
**BUG-5 (P2)**: combo() redeem-script not exposed via ExpandedDescriptor.

#### Gate 11 — `InferScript` (reverse parse from scriptPubKey to
       descriptor) — **MISSING**
Reference: `descriptor.cpp:2691-2810` `InferScript` recognises every
script template back into its descriptor form (P2PK → pk(), P2PKH →
pkh(), P2WPKH → wpkh(), P2SH → sh(), P2WSH → wsh(), P2TR → tr()
or rawtr(), bare multisig → multi(), tapscript multi_a script →
multi_a(), miniscript → MiniscriptDescriptor with FromScript).
Used for `scantxoutset` / `listdescriptors` / watch-only restore.
Nimrod: **no equivalent function**.  `descriptorFromScript` does not
exist.  Wallets that need to round-trip "I see this output, what
descriptor would describe it" cannot do so.
**BUG-6 (P1)**: descriptor inference (`InferScript`) absent.

#### Gate 12 — `InferTaprootTree` / `InferMultiA` — **MISSING**
Reference: `descriptor.cpp:2675-2689` `InferMultiA` recognises the
[xkey] OP_CHECKSIG ([xkey] OP_CHECKSIGADD)* k OP_NUMEQUAL pattern.
Plus `descriptor.cpp:2761-2796` `InferTaprootTree` recovers
tap-leaves from a stored `TaprootSpendData` to round-trip
tr(K,{...}).
Nimrod: **no equivalent**, follow-on from BUG-6.
**BUG-7 (P1)**: multi_a and taproot-tree inference absent.

#### Gate 13 — Multipath descriptors (BIP-389) — **MISSING / P1**
Reference: `descriptor.cpp:1785-1858` `ParseKeyPath(..., allow_
multipath=true, ...)`.  Recognises `/<0;1>` inside derivation paths,
expands one descriptor expression into N derivation paths (one per
multipath element), validates no duplicate values, no nested
multipath specifiers, no hardened multipath.
Nimrod: `descriptor.nim:232-254` `parseKeyPath` has no `<` /
multipath logic; multipath strings would parse as a single path
element and fail to convert to uint32.
**BUG-8 (P1)**: multipath / BIP-389 not implemented.

#### Gate 14 — `musig()` (BIP-390) PubkeyProvider — **MISSING / P1**
Reference: `descriptor.cpp:596-768` `MuSigPubkeyProvider` —
musig(K1,K2,...) yields the aggregated MuSig2 pubkey.  Only valid
inside `tr()` context.  Requires `MuSig2AggregatePubkeys` from
secp256k1's MuSig module.
Nimrod: no `musig` recognition in parser at all.  Would fail with
"unknown descriptor function: musig".
**BUG-9 (P1)**: musig() / BIP-390 not implemented.

### Subsystem C — Miniscript fragment + type system (gates 15-22)

#### Gate 15 — Fragment enum parity with Core — **PRESENT**
Reference: `miniscript.h:211-243` 28 Fragment values.
Nimrod: `miniscript.nim:47-81` `MsKind` enum with all 28 values.
One-to-one mapping (JUST_0 ↔ MsJust0, MULTI_A ↔ MsMultiA, etc.).
Status: PRESENT.

#### Gate 16 — `multi_a()` fragment exists (W127 BUG-6 follow-up) — **PRESENT (CLOSED since W127)**
Reference: BIP-342 §multi_a.  Core: `miniscript.h:238`.
Nimrod: `miniscript.nim:81` `MsMultiA`, parser at :1819-1840,
script compile at :1048-1062 (emits `OP_CHECKSIG` + per-key
`OP_CHECKSIGADD` + `OP_NUMEQUAL`).  Descriptor side at
`descriptor.nim:1012-1032` recognises `multi_a` and `sortedmulti_a`
inside `tr()` context.
Status: **PRESENT — W127 BUG-6 is CLOSED.** (Confirmed in this
audit — see "W127 BUG-6 status" section below.)

#### Gate 17 — Type computation: B/V/K/W base + zonduefsmxk flags — **PRESENT**
Reference: `miniscript.h:297` `ComputeType`.  Validates type
correctness per fragment.
Nimrod: `miniscript.nim:265-744` `computeType`.  All 28 fragments
have type computation, errors on type mismatch.  Status: PRESENT
(flags are nominally correct against Core's tables 1+ for each
fragment).

#### Gate 18 — Wrapper stacking syntax (e.g. `dv:older(1)`) — **MISSING / P1**
Reference: `miniscript.h:1980-2050` parser accepts colons after a
sequence of single-char wrappers (e.g. `tvuz:c:pk_k(...)` is `t:v:
u:z:c:pk_k(...)`).  Pop wrappers one at a time, build inward-out.
Nimrod: `miniscript.nim:1587-1620`.  Only **one** wrapper char
before `:` is consumed: `s[pos+1] == ':'` check, then `pos += 2`
and recurses on body.  Strings like `dv:older(1)` parse as wrapper
`d` applied to `v:older(1)` — which fails because of the colon
*inside* the body.
**BUG-10 (P1)**: wrapper-stack syntax unsupported.

#### Gate 19 — `t:`, `l:`, `u:` shortcut wrappers — **PARTIAL**
Reference: `miniscript.h:240-242` `t:X = and_v(X,1)`, `l:X = or_i
(0,X)`, `u:X = or_i(X,0)`.
Nimrod: `miniscript.nim:1614-1617`.  All three shortcut wrappers
recognised.  But: parser does not normalise on `toString` — i.e.
parsing `t:older(1)` should round-trip back to `t:older(1)`, but
the AST is constructed as `MsAndV(older(1),JUST_1)` and toString
emits `and_v(older(1),1)`.  Core does emit `t:` in `ToString`
(see `miniscript.h:930`).
**BUG-11 (P3)**: shortcut wrappers don't round-trip in toString.

#### Gate 20 — `and_n()` shortcut — **MISSING**
Reference: `miniscript.h:2061-2063` parser recognises
`and_n(X,Y)` as a separate Func and constructs `andor(X,Y,0)`.
Nimrod: `miniscript.nim:1842`.  Falls into `else` arm with
"unknown miniscript function: and_n".  No parser arm.
**BUG-12 (P1)**: `and_n` shortcut not recognised.

#### Gate 21 — `MAX_PUBKEYS_PER_MULTI_A=999` constant — **PRESENT**
Reference: `script.h:37`.
Nimrod: `miniscript.nim:162` `MaxMultiAKeys=999`.  Status: PRESENT.

#### Gate 22 — `MAX_PUBKEYS_PER_MULTISIG=20` constant — **PRESENT**
Reference: `script.h:34`.
Nimrod: `miniscript.nim:161` `MaxMultiKeys=20`.  Status: PRESENT.

### Subsystem D — Miniscript size + resource limits (gates 23-26)

#### Gate 23 — `MAX_TAPMINISCRIPT_STACK_ELEM_SIZE=65` — **MISSING**
Reference: `miniscript.h:269`.  Single-witness-stack-element max
size = signature + sighash byte = 65 bytes.
Nimrod: no equivalent constant.  `pushData` (`miniscript.nim:758`)
accepts arbitrary data sizes.  Not enforced at compile / type
checking.
**BUG-13 (P2)**: tap-miniscript element-size limit unnamed.

#### Gate 24 — `MaxScriptSize(ctx)` enforcement — **MISSING**
Reference: `miniscript.h:282-294`.  Tapscript leaves are bounded
by ~`MAX_STANDARD_TX_WEIGHT - TX_BODY_LEEWAY_WEIGHT -
MAX_TAPSCRIPT_SAT_SIZE`; P2WSH by `MAX_STANDARD_P2WSH_SCRIPT_SIZE`.
Compiled-script size MUST be ≤ this bound.  Core enforces in
`SanityCheck` (:1675).
Nimrod: `miniscript.nim:163` has `MaxStandardP2WSHScriptSize=3600`
but **never enforces** it.  Tapscript size has no constant at all.
A bad miniscript that compiles to a 4001-byte script would be
silently accepted.
**BUG-14 (P1)**: `MaxScriptSize` not enforced at compile.

#### Gate 25 — `MAX_OPS_PER_SCRIPT` opcount check — **MISSING**
Reference: `miniscript.h:1571` `if (const auto ops = GetOps())
return *ops <= MAX_OPS_PER_SCRIPT;`.  Used in `IsValid`.
Nimrod: no `MaxOpsPerScript` reference in either file; no opcount
walker; no `IsValid` gate that checks it.
**BUG-15 (P1)**: opcount limit not enforced.

#### Gate 26 — `MAX_STACK_SIZE` exec-stack check — **MISSING**
Reference: `miniscript.h:1597`
`GetExecStackSize() <= MAX_STACK_SIZE`.
Nimrod: no exec-stack-size analysis.  A bad miniscript that
requires >1000 stack elements at exec time would be silently
accepted.
**BUG-16 (P1)**: exec-stack-size limit not enforced.

### Subsystem E — Round-trip + canonical form (gates 27-30)

#### Gate 27 — `toString` round-trip across all fragments — **PARTIAL**
Reference: `miniscript.h:907-980` `ToString` overrides for every
Fragment, including shortcut wrappers (t/l/u), `and_n`, normalised
key forms.
Nimrod: `miniscript.nim:1862-1927` `toString`.  Covers all 28
Fragment cases.  But: doesn't emit shortcut wrappers (Gate 19),
doesn't emit `and_n` (Gate 20), and doesn't normalise key forms
(hex always lowercased — does match Core).  Round-trip survives
most simple forms but loses syntactic-sugar.
**BUG-17 (P3)**: round-trip loses syntactic-sugar wrappers.

#### Gate 28 — Descriptor `toString` round-trip — **PARTIAL**
Reference: `descriptor.cpp` `DescriptorImpl::ToString` produces
canonical form with appended `#checksum`.
Nimrod: `descriptor.nim:1100-1152` `nodeToString` + `toString`.
Covers all 14 DescriptorKind cases.  But:
  - `DKTr` at :1113-1116 has `# TODO: Add tree scripts` and emits
    only the internal key — round-trip with tree drops the tree.
    Follow-on from BUG-1.
  - `DKMiniscript` at :1145-1146 emits literal `"miniscript(...)"`
    placeholder.  Follow-on from BUG-2.
  - Key origin formatting at line 416-455 — normalisation to
    apostrophe-or-h depends on the parse-time flag, not on a
    canonical-form choice.  Core normalises to `h` in canonical
    output but echoes whatever was parsed.
**BUG-18 (P2)**: descriptor toString drops tree + miniscript bodies;
canonical-form normalisation diverges.

#### Gate 29 — `IsRange` / `IsSolvable` / `HasPrivateKeys` — **PRESENT**
Reference: `descriptor.cpp` `IsRange` / `IsSolvable` /
`m_solvable`.
Nimrod: `descriptor.nim:461-494` `isRange` + `isSolvable`,
:1199-1223 `hasPrivateKeys`.  All cover the 14 DescriptorKind cases
and recurse appropriately.  Status: PRESENT.

#### Gate 30 — `Clone()` + descriptor cache + `KeyOriginInfo` —
       **PARTIAL**
Reference: `descriptor.cpp` `DescriptorImpl::Clone` (:1309 etc) —
every concrete subclass has a `Clone()` method that returns a
fresh independent owned pointer.  Plus `DescriptorCache` for
ranged xpub→pubkey caching.
Nimrod: no `clone()` proc on `Descriptor` or `DescriptorNode` at
all.  Ref objects make this less critical (shared structure is
fine for read-only use) but mutation safety is on the user.
No descriptor cache — every `derive` re-derives the BIP-32 chain
from the parent key.  For ranged descriptors with deep paths,
this is O(N·depth) instead of O(1) amortised.
**BUG-19 (P2)**: descriptor cache + Clone() absent.

### Subsystem F — Edge cases (gates "31"+) — overflow gates

> Note: per audit-framework convention, gates 31+ are "edge-case bugs"
> beyond the 30-gate matrix.  They are surfaced from reading the
> Core test corpus but were not standalone audit gates.

#### Gate 31 — Threshold parameter out-of-range in multi(k,…) — **PARTIAL**
Reference: `descriptor.cpp:2353-2358` rejects `thres < 1` or
`thres > providers.size()`.
Nimrod: `descriptor.nim:1005` doesn't check the threshold-vs-keylen
relation at parse time — the check is at `expandNode` time
(`makeMultisigScript` line 516-517).  This means a parse-only
roundtrip (no expand) doesn't fail.
**BUG-20 (P3)**: threshold validation delayed from parse to expand.

#### Gate 32 — `pk_k`+`pk_h` shorthand `pk()` / `pkh()` inside miniscript — **PRESENT**
Reference: parser recognises `pk(KEY)` as `c:pk_k(KEY)` shortcut.
Nimrod: `miniscript.nim:1636-1648` recognises both `pk`/`pk_k` and
`pkh`/`pk_h` as aliases.  Status: PRESENT.

#### Gate 33 — Recursive descriptor depth (sh(wsh(...))) — **PRESENT**
Tested implicitly by parser recursion through `parseDescriptorNode`.

#### Gate 34 — `older(0)` / `older(2147483648)` invalid — **MISSING**
Reference: BIP-112 / `miniscript.h` `older` requires
`1 ≤ n ≤ 0x7FFFFFFF`.  Core rejects at type-check.
Nimrod: `miniscript.nim:1650-1655` no range check.  Compiles and
runs, type-check at :297 doesn't reject `lockValue=0`.
**BUG-21 (P2)**: older/after bounds not enforced.

#### Gate 35 — Sat/Dissat malleability tracking — **PARTIAL**
Reference: `miniscript.h:1199-1221` `CalcSat` returns sat + dissat
sizes used to pick non-malleable satisfactions.
Nimrod: `miniscript.nim:99-101` has `SatisfactionResult` with sat
+ dissat fields, but malleability scoring is light — only tracked
via the `malleable` flag (:90), not used for selection.
**BUG-22 (P2)**: malleability scoring shallow.

#### Gate 36 — Type-check timelock conflicts (g/h/i/j flags) — **PARTIAL**
Reference: `miniscript.h` `Type` has `g`/`h`/`i`/`j` flags for
{height,time}×{older,after}.  Mixing time and height in same
fragment is a malleability conflict.
Nimrod: `miniscript.nim:1481-1537` `hasTimelockConflict` recurses
to find mixed.  But the per-fragment Type flags do NOT track g/h/i/j
— only m/x/k.  The conflict check is a separate AST walk.
**BUG-23 (P2)**: g/h/i/j flags absent from Type system; timelock
conflict computed by AST walk.

#### Gate 37 — BIP-32 cache write — **MISSING**
Reference: `descriptor.cpp` `DescriptorCache::CacheParentExtPubKey`
+ `DerivedExtPubKey` for ranged descriptor caches.
Nimrod: `descriptor.nim` has no DescriptorCache type; every
derive call recomputes from root.
**BUG-24 (P1)**: BIP-32 derivation cache absent — performance bug.

## Bug catalogue (24 total)

| BUG | Pri | Subsystem | Gate | Summary |
|-----|-----|-----------|------|---------|
| 1   | P0-CDIV  | tr() tree           | G4  | tr() script-tree body silently discarded |
| 2   | P0-CDIV  | miniscript hook     | G5  | descriptor never invokes parseMiniscript |
| 3   | P1       | hybrid pubkey       | G6  | hybrid `0x06`/`0x07` not rejected with Core-class error |
| 4   | P3       | key origin          | G8  | error-message and edge-case fidelity gaps |
| 5   | P2       | combo redeem        | G10 | P2SH-P2WPKH redeem-script not exposed in ExpandedDescriptor |
| 6   | P1       | inference           | G11 | `InferScript` not implemented |
| 7   | P1       | inference           | G12 | `InferMultiA` / `InferTaprootTree` not implemented |
| 8   | P1       | BIP-389             | G13 | multipath descriptors not parsed |
| 9   | P1       | BIP-390             | G14 | musig() PubkeyProvider not implemented |
| 10  | P1       | wrapper stacking    | G18 | `dv:`-style wrapper stacking rejected |
| 11  | P3       | shortcut wrapper    | G19 | `t:`/`l:`/`u:` don't round-trip in toString |
| 12  | P1       | shortcut fragment   | G20 | `and_n()` parser arm absent |
| 13  | P2       | size limit          | G23 | `MAX_TAPMINISCRIPT_STACK_ELEM_SIZE` constant absent |
| 14  | P1       | size limit          | G24 | `MaxScriptSize` not enforced at compile |
| 15  | P1       | size limit          | G25 | `MAX_OPS_PER_SCRIPT` not enforced |
| 16  | P1       | size limit          | G26 | `MAX_STACK_SIZE` exec check not enforced |
| 17  | P3       | toString            | G27 | miniscript toString drops wrappers + and_n |
| 18  | P2       | toString            | G28 | descriptor toString drops tree + miniscript bodies |
| 19  | P2       | cache + clone       | G30 | descriptor cache + Clone() absent |
| 20  | P3       | parse-time check    | G31 | multi() threshold validated at expand not parse |
| 21  | P2       | older/after bounds  | G34 | `older(0)` / `after(>0x7FFFFFFF)` not rejected |
| 22  | P2       | malleability        | G35 | malleability scoring shallow |
| 23  | P2       | type system         | G36 | g/h/i/j timelock flags missing from Type |
| 24  | P1       | BIP-32 cache        | G37 | BIP-32 derivation cache absent (perf bug) |

Priority distribution: 2 P0-CDIV, 9 P1, 8 P2, 5 P3.

## W127 BUG-6 status — **CLOSED**

W127 (commit `4623dc9`) identified BUG-6 P1: "descriptor / miniscript
`multi_a` missing".  As of this audit (W131 on top of latest master
commit `12affc5`):

- `src/wallet/miniscript.nim:81` has `MsMultiA` fragment.
- `src/wallet/miniscript.nim:128-130` has the `keys/k` payload arm.
- `src/wallet/miniscript.nim:738-744` has type computation
  (Budemsk, no n — matches BIP-379 Tapscript table).
- `src/wallet/miniscript.nim:1048-1062` has compile (script
  generation) emitting `[xkey] OP_CHECKSIG ([xkey] OP_CHECKSIGADD)*
  [k] OP_NUMEQUAL`.
- `src/wallet/miniscript.nim:1819-1840` has parser arm including
  tapscript-context gate (line 1820-1821) + MAX_PUBKEYS_PER_MULTI_A
  bound (line 1837).
- `src/wallet/descriptor.nim:69-70` has `DKMultiA` /
  `DKSortedMultiA` enum values.
- `src/wallet/descriptor.nim:889-893` has constructors.
- `src/wallet/descriptor.nim:1012-1032` has parser arm with
  context gate (`ctx != ContextP2TR` line 1013-1014).
- `src/wallet/descriptor.nim:527-570` has `makeMultisigAScript`
  which emits the tapscript multisig byte-by-byte.

The closure is **complete and Core-aligned**.  Test coverage in
this audit's `test_w131_descriptors_miniscript.nim` validates the
fragment exists, parses, type-checks, compiles, and emits the
expected script bytes for k=1 and k=2 cases.

**W127 BUG-6 is no longer present.**  The fix appears to have
landed in a between-W127-and-W131 wave that does not show up in
`git log` with an obvious keyword — likely landed as part of
"FIX-XX W118 wallet fleet" or similar wallet bundle.

## Top P0 / P1 findings (5 ranked)

1. **BUG-1 P0-CDIV — tr() script-tree silently discarded** — highest
   real-world impact.  A wallet importing `tr(K,{pk(A),pk(B)})`
   derives the **wrong** P2TR output address because the merkle root
   is computed as empty.  A user funding such a wallet would
   silently send to an address nimrod cannot recognise.  Fix:
   parse the tree into `TrTreeNode` (the type already exists at
   `descriptor.nim:77-83`), populate `depths` + `scripts` fields,
   make `expandNode`'s DKTr arm walk the leaves to compute the
   merkle root via tapBranchHash (BIP-341 §4.7), tweak the internal
   key by `TapTweak(P||merkleRoot)`.

2. **BUG-2 P0-CDIV — descriptor never invokes parseMiniscript** —
   second-highest real-world impact.  A miniscript-driven HD wallet
   (e.g. one using `wsh(or_d(c:pk_k(K1),and_v(c:pk_k(K2),
   older(1000))))`) cannot be imported into nimrod at all.
   Fix: in `parseDescriptorNode`'s `else` arm (`descriptor.nim:1060`),
   instead of raising, attempt `parseMiniscript(funcName_and_rest,
   miniscriptCtxFor(ctx))` and on success wrap the result in a new
   `DescriptorNode(kind: DKMiniscript, miniscript: msNode)`.  Add
   compile + expand support for DKMiniscript.

3. **BUG-6 + BUG-7 P1 — `InferScript` family absent** — wallet
   restoration from scriptPubKey can't roundtrip to descriptor.
   Without this, `listdescriptors` cannot produce useful output for
   a watch-only wallet imported by raw scripts.  Fix: implement
   `inferDescriptor(script: seq[byte]): Option[Descriptor]` that
   pattern-matches the known script templates (P2PK, P2PKH, P2WPKH,
   P2SH, P2WSH, P2TR, multisig, multi_a) and emits the corresponding
   DescriptorNode.

4. **BUG-8 P1 — multipath / BIP-389 not implemented** — BIP-389 is
   how most modern wallets express receive+change in a single
   descriptor (`/<0;1>`).  Without it, nimrod requires two separate
   descriptors per wallet.  Fix: in `parseKeyPath`, recognise
   `<n;n;...>` segments and return a list of `seq[uint32]` paths;
   propagate through `KeyProvider` + `expandNode` as an outer loop.

5. **BUG-10 + BUG-12 P1 — wrapper-stacking + `and_n` parser arms** —
   common idioms like `tvln:older(1)` and `and_n(X,Y)` are rejected.
   Together these block ~40% of the miniscript_tests.cpp corpus.
   Fix: in `parseMiniscriptImpl`, consume consecutive wrapper chars
   until the next `:` or `(`, then apply them in reverse order;
   and add explicit `and_n(X,Y) → andor(X,Y,JUST_0)` parser arm.

## Patterns to promote

- **Two-pipeline guard pattern** — adapted: nimrod's `descriptor.nim`
  and `miniscript.nim` MUST be consistent on multi_a / tr() tree /
  miniscript hook.  Currently they are inconsistent on tr() tree
  (descriptor accepts the syntax, drops the body; miniscript has no
  knowledge of trees) and on the descriptor→miniscript handoff
  (no glue exists).  When fixing BUG-1 and BUG-2, add a guard test
  to ensure descriptor's expand-tr() and miniscript's compile agree
  on what bytes come out for a given (K, tree) input.

- **Audit-flip with renaming pattern** (cross-impl) — the inline
  comment at `descriptor.nim:960` says "TODO: ... (BUG-5)" but the
  bug was never given a real ID and never closed.  This is a
  classic "test-comment-as-confession" anti-pattern (cf W122
  blockbrew BUG-5).  When closing BUG-1 in this audit, the comment
  must be deleted, not just updated — the BUG ID is now W131-BUG-1
  with proper tracking.

- **Inference parity gates** — none of W127, W128, W129, W131 has
  cross-impl tests for `InferScript`.  Suggest a fleet-wide
  inference-parity audit wave (W132 candidate) that imports a
  scriptPubKey corpus from Core and asserts every node infers the
  same canonical descriptor.
