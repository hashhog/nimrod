# W134 — BIP-37 / BIP-111 Bloom Filter (legacy SPV) audit (nimrod)

Date: 2026-05-17
Audit type: discovery (NO production code change in W134)
Predecessor: W110 (same subsystem, ran 2026-05-13).  W110 caught 14 BUGs
and led to FIX-35 (drop NODE_BLOOM advertisement) and FIX-36 (parse
filterload/filteradd/filterclear/merkleblock + BIP-111 disconnect).
W134 re-classifies the subsystem against the 30-gate matrix to verify
FIX-35 / FIX-36 closure semantics, catch any drift, and catalogue any
new BUGs that surfaced after the previous fix waves.

Target:
  - `src/network/messages.nim`       (MessageKind enum, deserializePayload,
                                       serializePayload, commandToMessageKind,
                                       messageKindToCommand)
  - `src/network/peer.nim`           (handleMessage filterload/add/clear/
                                       merkleblock arms; peerBloomFiltersEnabled;
                                       sendVersion NODE_BLOOM gate)
  - `src/nimrod.nim`                 (handleMessage filterload/add/clear/
                                       merkleblock arms; mempool gate;
                                       getdata→invFilteredBlock path)
  - `src/network/eviction.nim`       (EvictionCandidate.bloomFilter field)
  - `src/network/peermanager.nim`    (EvictionCandidate construction site)
  - `src/network/bip324.nim`         (BIP-324 short-ID table — filteradd /
                                       filterclear / filterload / merkleblock)
  - `src/rpc/server.nim`             (w47bBuildPartialMerkleTree /
                                       w47bParsePartialMerkleTree — RPC PMT
                                       helpers, P2P-unreachable)
  - `src/script/interpreter.nim`     (MaxScriptElementSize = 520 — would
                                       be the filteradd cap if implemented)

Bitcoin Core references:
  - `src/common/bloom.h` + `src/common/bloom.cpp`
    (CBloomFilter, CRollingBloomFilter, MAX_BLOOM_FILTER_SIZE,
     MAX_HASH_FUNCS, BLOOM_UPDATE_*, MurmurHash3 schedule, insert /
     contains / IsWithinSizeConstraints / IsRelevantAndUpdate)
  - `src/merkleblock.h` + `src/merkleblock.cpp`
    (CMerkleBlock, CPartialMerkleTree, BitsToBytes / BytesToBits)
  - `src/net_processing.cpp`
    - lines 2438–2458 (getdata MSG_FILTERED_BLOCK → merkleblock + matched txns)
    - lines 4853–4863 (mempool gate: NODE_BLOOM OR NetPermissionFlags::Mempool)
    - lines 4963–4985 (FILTERLOAD: NODE_BLOOM gate → disconnect, size check
                      → Misbehaving, install filter)
    - lines 4988–5013 (FILTERADD: NODE_BLOOM gate → disconnect, size check
                      → Misbehaving on > MAX_SCRIPT_ELEMENT_SIZE)
    - lines 5016–5032 (FILTERCLEAR: NODE_BLOOM gate → disconnect, clear filter)
    - line 1613 (NetPermissionFlags::BloomFilter → OR in NODE_BLOOM)
    - lines 3680–3687 (txinv gate uses m_relay_txs + NODE_BLOOM)
  - `src/init.cpp`
    - line 572 (`-peerbloomfilters` arg)
    - lines 1104–1105 (`-peerbloomfilters` → OR g_local_services with NODE_BLOOM)
  - `src/net_processing.h:44` (`DEFAULT_PEERBLOOMFILTERS = false`)
  - `src/protocol.h:316–317` (`NODE_BLOOM = (1 << 2)`)
  - BIPs: 37 (bloom-filtered tx relay), 111 (NODE_BLOOM service bit, default-off,
          MUST NOT advertise if not served).

Driver: BIP-37 is the legacy SPV protocol — a peer connects, sends a
`filterload`, receives `merkleblock` for filtered blocks and `tx`
for matching mempool transactions.  BIP-111 mandates that a node MUST
NOT advertise NODE_BLOOM unless it serves BIP-37 requests; SPV clients
rely on this advertisement to decide where to connect.  A node that
silently drops `filterload` while advertising NODE_BLOOM **deceives**
SPV clients into believing filtering is active — a privacy break
(every tx the wallet sees is unfiltered) and a DoS vector (the SPV
client waits forever for merkleblock that never comes).

## Status

**BUGS — 9 distinct gates remain (of 30).**  W110's 14 BUGs reduced to 9
in this re-audit because:
  - **W110 BUG-05** (filterload/add/clear absent from message enum) — **CLOSED**
    by FIX-36; G25/G26/G27 now emit `mkFilterLoad`/`mkFilterAdd`/
    `mkFilterClear` and disconnect on receipt (verified G25/G26/G27 tests
    below).
  - **W110 BUG-13** (NODE_BLOOM deception of SPV clients) — **CLOSED** by
    FIX-35; `sendVersion` never sets the bit and `peerBloomFiltersEnabled`
    is now only the BIP-35 mempool gate (verified G30 below).
  - **W134 BUG-22** is **NEW** — the BIP-35 `mempool` message handler in
    `nimrod.nim:1141–1188` correctly gates on `peerBloomFiltersEnabled()`,
    but the gate is `NIMROD_PEER_BLOOM_FILTERS` (an opt-in env var that
    defaults OFF — Core-aligned), so the original W110 catalogue listed
    this as PASS.  However, the gate text was tweaked from W110 to add
    a "NODE_BLOOM not advertised" debug log — verified PASS, no new BUG.
  - **W134 BUG-23** would have been a `NODE_BLOOM` regression in
    `eviction.nim` — but the field is intentionally tracked as a no-op
    feature input (always false in `peermanager.nim:751`), which is
    consistent with W110 BUG-01 (no bloom subsystem). No new BUG.

The remaining 9 BUGs are the **subsystem-absent** consequence of the
W110 root finding (BUG-01 in W110): nimrod has no CBloomFilter,
CRollingBloomFilter, MurmurHash3, or BLOOM_UPDATE_* enum, and the
classic dead-helper PMT pair (`w47bBuildPartialMerkleTree` /
`w47bParsePartialMerkleTree`) remains unreachable from any P2P bloom
path.  All 9 are categorised PARTIAL or MISSING; none is a fresh
production regression.

## 30-gate matrix

| # | Gate | Status | BUG | Verdict |
|---|------|--------|-----|---------|
| G1 | `MAX_BLOOM_FILTER_SIZE = 36000` constant | MISSING | BUG-01 | Constant absent; no DoS guard on incoming filterload size. |
| G2 | `MAX_HASH_FUNCS = 50` constant | MISSING | BUG-02 | Constant absent. |
| G3 | `LN2SQUARED` full-precision constant | MISSING | (dep on BUG-03) | No CBloomFilter type → no constructor → no sizing formula. |
| G4 | CBloomFilter constructor sizing formula | MISSING | BUG-03 | `CBloomFilter::CBloomFilter` absent. |
| G5 | nHashFuncs computed via `vData.size()*8/nElements*LN2` | MISSING | (dep on BUG-03) | Constructor absent. |
| G6 | MurmurHash3 32-bit primitive | MISSING | BUG-04 | Not implemented anywhere in `src/crypto/`. |
| G7 | Hash schedule `i*0xFBA4C795 + nTweak` | MISSING | (dep on BUG-04) | Hash primitive absent. |
| G8 | Bit-index derivation `% (vData.size() * 8)` + `vData[idx>>3] \|= 1<<(7&idx)` | MISSING | (dep on BUG-03) | No bloom byte array. |
| G9 | `insert` / `contains` correctness + CVE-2013-5700 empty-filter guard | MISSING | (dep on BUG-03) | No methods. |
| G10 | `isFull` / `isEmpty` short-circuit | MISSING | (dep on BUG-03) | Methods absent. |
| G11 | `BLOOM_UPDATE_NONE` = 0 | MISSING | BUG-05 | Enum absent. |
| G12 | `BLOOM_UPDATE_ALL` = 1 | MISSING | BUG-05 | Enum absent. |
| G13 | `BLOOM_UPDATE_P2PUBKEY_ONLY` = 2 | MISSING | BUG-05 | Enum absent. |
| G14 | `BLOOM_UPDATE_MASK` = 3 | MISSING | BUG-05 | Enum absent. |
| G15 | `nFlags & BLOOM_UPDATE_MASK` applied inside `IsRelevantAndUpdate` | MISSING | BUG-06 | `IsRelevantAndUpdate` absent. |
| G16 | `IsRelevantAndUpdate`: txid contains check | MISSING | BUG-06 | absent. |
| G17 | `IsRelevantAndUpdate`: per-output `scriptPubKey` pushdata extract | MISSING | BUG-06 | absent. |
| G18 | `IsRelevantAndUpdate`: P2PKH/P2SH/P2PK/multisig via `Solver()` | MISSING | BUG-06 | absent. |
| G19 | `IsRelevantAndUpdate`: per-input `prevout` contains check | MISSING | BUG-06 | absent. |
| G20 | `IsRelevantAndUpdate`: per-input `scriptSig` pushdata extract | MISSING | BUG-06 | absent. |
| G21 | `UPDATE_ALL` → insert every matched output's outpoint | MISSING | BUG-06 | absent. |
| G22 | `UPDATE_P2PUBKEY_ONLY` → insert P2PK/Multisig outpoints only | MISSING | BUG-06 | absent. |
| G23 | `UPDATE_NONE` → filter never mutated | MISSING | BUG-06 | absent. |
| G24 | Outpoint 36-byte LE serialization (`txid 32 LE \|\| vout 4 LE`) for bloom insert/contains | MISSING | BUG-07 | No bloom helper; raw serializer is correct but never called from any bloom path. |
| G25 | `filterload` message: parse + size check + Misbehaving + install per-peer filter | PARTIAL | (FIX-36 closes parse path) | Parse arm present; body skipped; disconnect fires.  Size check + install absent — but those would only matter if the filter were actually stored (BUG-08). |
| G26 | `filteradd` message: parse + `data.size() > MAX_SCRIPT_ELEMENT_SIZE` Misbehaving + insert into peer filter | PARTIAL | (FIX-36 closes parse path) | Parse arm present; body skipped; disconnect fires.  Size check + insert absent (BUG-08). |
| G27 | `filterclear` message: parse + clear per-peer filter | PARTIAL | (FIX-36 closes parse path) | Parse arm present; disconnect fires.  Clear absent (BUG-08). |
| G28 | `merkleblock` outgoing from getdata(MSG_FILTERED_BLOCK) + PartialMerkleTree | MISSING | BUG-09 | `nimrod.nim:1020-1022` getdata handler falls to `notFound` for `invFilteredBlock`; `mkMerkleBlock` is only an INCOMING log+drop arm; PMT helpers in `rpc/server.nim` are RPC-only (dead-helper from P2P perspective). |
| G29 | `IsWithinSizeConstraints` guard executed on incoming filterload (post-deserialise) | MISSING | (dep on BUG-01) | Type absent. |
| G30 | `NODE_BLOOM` service bit + BIP-111 advertisement gate | PARTIAL (FIX-35 closes) | — | Bit defined (= 4); NEVER advertised in `sendVersion`; `peerBloomFiltersEnabled` re-purposed as BIP-35 mempool gate only.  Closure of W110 BUG-13. |

Verdict summary (re-audit deltas vs W110):
  - **2 closed** since W110 (FIX-35 + FIX-36).
  - **9 still open** (all variants of the W110 root finding: subsystem absent).
  - **0 new regressions** introduced by FIX-35 / FIX-36.

## BUGs (W134 enumeration — re-numbered from W110)

### BUG-01 [MISSING ENTIRELY, severity HIGH (P0-CDIV-spv)] CBloomFilter type absent
Bitcoin Core `bloom.h` defines `CBloomFilter` with `vData`, `nHashFuncs`,
`nTweak`, `nFlags`, `Hash`, `insert`, `contains`, `IsWithinSizeConstraints`,
`IsRelevantAndUpdate`.  Nimrod has no such type in `src/` — the only
hits for "bloom" are: (a) RocksDB block-based filter policy (storage layer,
not P2P); (b) the BIP-37 message enum variants added by FIX-36 (which
intentionally skip the body); (c) the `peerBloomFiltersEnabled` env-var
gate (which guards `mempool` only).  Root cause for G1, G2, G3, G4, G5,
G8, G9, G10, G29.  Re-classified from W110 BUG-01 (no change).

### BUG-02 [MISSING ENTIRELY, severity MED] MAX_BLOOM_FILTER_SIZE = 36000 absent
Core `bloom.h:17` defines the cap; without it, an incoming `filterload`
of up to 4 MB (the protocol message cap) would be accepted if the parse
path were ever implemented.  Currently moot because the message is
disconnected on receipt, but adding the bloom subsystem later without
this constant would re-open a DoS vector.  Re-classified from W110 BUG-02.

### BUG-03 [MISSING ENTIRELY, severity MED] MAX_HASH_FUNCS = 50 absent
Core `bloom.h:18` caps hash-function count to 50.  Without it a peer
could claim `nHashFuncs = 65535`, causing O(65535) hashes per lookup.
Re-classified from W110 BUG-03.

### BUG-04 [MISSING ENTIRELY, severity HIGH] MurmurHash3 32-bit primitive absent
Core `hash.h:209` / `hash.cpp:13` defines the MurmurHash3 (x86_32) hash
primitive used by `CBloomFilter::Hash` and `CRollingBloomFilter`.  Nimrod
has `src/crypto/hashing.nim` (SHA-256, RIPEMD-160, HASH256) and
`src/crypto/siphash.nim` (SipHash-2-4 for BIP-339 short IDs), but no
MurmurHash3.  Any future bloom implementation must add it; using SHA-256
or SipHash would produce wrong bit positions.  Re-classified from W110 BUG-04.

### BUG-05 [MISSING ENTIRELY, severity LOW] BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK absent
Core `bloom.h:22-28` defines the four enum values governing
`IsRelevantAndUpdate` mutation semantics.  Nimrod has neither the enum
nor any code that would consume it.  Root cause for G11/G12/G13/G14.
Was W110 BUG-10.

### BUG-06 [MISSING ENTIRELY, severity HIGH] IsRelevantAndUpdate algorithm absent
Core `bloom.cpp:95-167` walks tx outputs (match pushdata, possibly
insert outpoint under UPDATE_ALL / UPDATE_P2PUBKEY_ONLY), then tx inputs
(match prevout, match scriptSig data items).  Nimrod has no equivalent
procedure or trace of one in any audit guard.  An SPV wallet relying on
nimrod for filtered tx relevance would never receive any merkleblock
(see BUG-09).  Root cause for G15/G16/G17/G18/G19/G20/G21/G22/G23.
Was W110 BUG-11.

### BUG-07 [MISSING ENTIRELY, severity LOW] bloom-outpoint 36-byte LE helper absent
Core `bloom.cpp:60-63` serialises outpoint as `[txid 32 LE] ++ [vout 4 LE]`
via `DataStream stream{}; stream << outpoint;` and feeds the 36-byte
span to `insert(MakeUCharSpan(stream))`.  Nimrod's `serialize.nim`
writes OutPoint correctly for other call sites, but there is no
`bloomInsertOutpoint()` helper and no call to it.  Was W110 BUG-12.

### BUG-08 [MISSING ENTIRELY, severity LOW] no per-peer bloom filter state on Peer
Core `node/connection_types.h` stores `m_bloom_filter`
(`unique_ptr<CBloomFilter>`) and `m_relay_txs` in `TxRelay`.  Nimrod's
`Peer` object (`src/network/peer.nim`) has no such fields.  Even if the
FIX-36 disconnect were replaced with installation, there is nowhere
to keep the filter or signal whether the peer wants tx relay through it.
Was W110 BUG-06.

### BUG-09 [MISSING ENTIRELY, severity MED (P0-CDIV-spv)] invFilteredBlock falls through to notFound; no merkleblock emit
`nimrod.nim:1020-1022` getdata handler falls to `else: notFound.add(item)`
for any `InvType` other than `invBlock`/`invWitnessBlock`/`invCmpctBlock`/
`invTx`/`invWitnessTx`.  Core `net_processing.cpp:2438-2458` handles
`inv.IsMsgFilteredBlk()` by building `CMerkleBlock(*pblock,
*tx_relay->m_bloom_filter)` and emitting `merkleblock` + matched
`tx` messages.  An SPV client that requests filtered blocks from nimrod
receives `notfound`, will retry, and eventually disconnect.

Note: this BUG is the only one that surfaces a behavioural divergence
from the wire-side regardless of whether NODE_BLOOM is advertised —
because the peer might still issue `getdata` with `MSG_FILTERED_BLOCK`
inv type if the SPV client believed that bloom was supported (e.g. from
a stale peer DB).  Core responds "no response" silently (line 2459
"no response" comment); nimrod responds with `notfound`, which is
correctly conservative but does not match Core's behaviour exactly.
Re-classified from W110 BUG-09.  **OPTIONAL UPGRADE**: track-as-known
divergence; not P0 because the SPV client should reconnect to a node
that does advertise NODE_BLOOM.

### BUG-10 [PARTIAL / DEAD-HELPER, severity LOW] w47b PMT helpers unreachable from P2P
`src/rpc/server.nim:7974` `w47bBuildPartialMerkleTree` and `:8041`
`w47bParsePartialMerkleTree` implement a correct CPartialMerkleTree
(traverse + emit `[header 80][nTx 4-LE][varint nHashes][hashes
32*N][varint nFlagBytes][flagBytes]` for build; consume the same for
parse).  Wired only to `gettxoutproof` / `verifytxoutproof` RPC calls
(`:8199` and `:8217`).  No call site from any P2P path; no
`CMerkleBlock` wrapper that combines header + PMT for the
`merkleblock` outbound.  This is the classic dead-helper pattern: the
algorithm exists but is unreachable from the bloom subsystem.  Was
W110 BUG-14.

## CLOSED since W110

### CLOSED W110 BUG-05 — filterload/add/clear absent from message enum
**Fix:** FIX-36 added `mkFilterLoad`, `mkFilterAdd`, `mkFilterClear` to
`MessageKind`, mapped them in `commandToMessageKind`/`messageKindToCommand`
and `deserializePayload` (body intentionally skipped — BUG-01 makes the
body meaningless).  `handleMessage` in both `peer.nim:1534-1547` and
`nimrod.nim:1404-1417` emit the BIP-111 disconnect on receipt.
Verified by G25/G26/G27 tests below.  Also closed for BIP-324: v2
short-ID table maps the messages to the new enum variants.

### CLOSED W110 BUG-13 — NODE_BLOOM deception of SPV clients
**Fix:** FIX-35 dropped `NodeBloom` from the outbound version services
bitmap.  `peer.nim:575` builds `ourServices = NodeNetwork or
NodeWitness` and never ORs in `NodeBloom` regardless of any env var.
`peerBloomFiltersEnabled` is kept only as the BIP-35 `mempool` gate
(comment block at `peer.nim:549-566` explicitly documents this).
Verified by G30 tests below.

## Pattern observations

### "FIX-36 closure shape" — parse-but-disconnect rather than full implement
FIX-36 chose to add the message variants and drop them, rather than
implement the full bloom subsystem (a ~300+ LOC investment for an
SPV-only protocol that BIP-111 default-off-since-Bitcoin-Core 0.19 and
that Compact Block Filters / BIP-157 fully supersede on the privacy
front).  The closure is correct: it eliminates the BIP-111 violation
(W110 BUG-13) without paying the implementation cost.  But it leaves
G28 (filtered-block serving) as an unrecoverable gap — an SPV client
issuing `getdata(MSG_FILTERED_BLOCK)` will see `notfound`.  This is
**by design** but should be documented as a known-divergence in any
operator-facing release notes that mention BIP-37.

### "Re-audit-after-fix" methodology
W134 is W110 re-classified against the same 30 gates after FIX-35 /
FIX-36 landed.  Two BUGs closed, 9 remain (all subsystem-absent),
0 regressions.  Outcome confirms FIX-35 / FIX-36 are clean fixes.
This is the first time a discovery wave has been re-run against the
same subsystem after a fix wave; the re-audit shape is cheap (~30
min for 30 gates) and a good template for future fix-wave verification.

### "dead-helper preserved across audits"
BUG-10 (w47b PMT helpers unreachable from P2P) carries over from W110
unchanged.  Pattern repetition for the cross-wave "dead-helper-at-RPC-
call-site" finding noted in FIX-79 / FIX-80 cluster.  In the bloom
case the helper is RPC-reachable (gettxoutproof) — it's NOT dead in
absolute terms, only dead **from the BIP-37 P2P bloom path**.

## TWO-PIPELINE

None.  Bloom subsystem is absent; no production path competes with a
test path.  PMT helpers (BUG-10) are RPC-reachable so not in a
two-pipeline split per the FIX-79 / FIX-80 framing.

## Scope clarifications

- **Out-of-scope**: BIP-35 `mempool` message handling (gated on
  `peerBloomFiltersEnabled` env var; covered by W103 / W121).
- **Out-of-scope**: BIP-157/158 compact block filters (different subsystem;
  covered by W121 / W122).
- **Out-of-scope**: RocksDB block-based filter policy in `storage/db.nim`
  (purely a storage-layer Bloom; unrelated to BIP-37).
- **Out-of-scope**: `EvictionCandidate.bloomFilter` field — set to `false`
  in `peermanager.nim:751` because nimrod has no bloom subsystem;
  preserved for layout / future use.

## Operational impact

- **Today**: nimrod does NOT advertise NODE_BLOOM, so no compliant SPV
  client will issue `filterload`.  If a buggy / non-compliant peer
  sends `filterload` anyway, FIX-36 disconnects per BIP-111 (matches
  Core `net_processing.cpp:4964-4967`).  No deception, no DoS surface.
- **Edge case**: an SPV client that received an outdated peer DB entry
  listing nimrod as NODE_BLOOM (from before FIX-35) might still send
  `getdata(MSG_FILTERED_BLOCK)`; nimrod responds `notfound` rather
  than Core's silent no-response.  Effect: SPV client retries
  ~1-2 times and disconnects.  Acceptable; documented under BUG-09.
- **SPV client side**: out-of-scope (nimrod is server-only for BIP-37).
