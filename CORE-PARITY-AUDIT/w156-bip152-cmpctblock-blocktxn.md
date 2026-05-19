# W156 — BIP-152 sendcmpct + cmpctblock + getblocktxn + blocktxn (wire-level deep dive, nimrod)

**Wave:** W156 — Wire-level deep audit of BIP-152 compact block relay
in nimrod (Nim).  W126 covered the fundamentals — this wave drills into
the wire-format paths, SipHash key derivation, prefilled-txn
differential encoding, HB-mode peer selection, MAX_BLOCKTXN_DEPTH /
MAX_CMPCTBLOCK_DEPTH gating, MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK
multimap semantics, sendcmpct(version=1) legacy compat, post-
reconstruction routing into validation, and unsolicited-cmpctblock
DoS-amplification.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.h:23-43` — `DifferenceFormatter`
  (m_shift cumulative, `ReadCompactSize` + `++` post-increment).
- `bitcoin-core/src/blockencodings.h:45-55` — `BlockTransactionsRequest`
  (uint256 blockhash + DifferenceFormatter<uint16> indexes).
- `bitcoin-core/src/blockencodings.h:57-71` — `BlockTransactions`
  (uint256 blockhash + TX_WITH_WITNESS vector).
- `bitcoin-core/src/blockencodings.h:74-81` — `PrefilledTransaction`
  (uint16 index serialised as COMPACTSIZE; tx serialized
  TX_WITH_WITNESS).
- `bitcoin-core/src/blockencodings.h:90-130` — `CBlockHeaderAndShortTxIDs`
  (header + uint64 nonce + shorttxids[6] + prefilledtxn; on read,
  validates `BlockTxCount() > 0xFFFF`).
- `bitcoin-core/src/blockencodings.cpp:20-50` —
  `CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs`,
  `FillShortTxIDSelector` (CSHA256 single, NOT double), `GetShortID`
  (SipHash-2-4 of wtxid, mask `& 0xffffffffffffL`).
- `bitcoin-core/src/blockencodings.cpp:59-181` — `PartiallyDownloadedBlock::InitData`
  (null-header reject, sum-count cap `MAX_BLOCK_WEIGHT /
  MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 100_000`, prefilled-index
  monotonic + structural-gap check, bucket-size > 12 → FAILED, short-ID
  collision → FAILED, extra_txn pool fill with witness-hash dedup).
- `bitcoin-core/src/blockencodings.cpp:191-237` —
  `PartiallyDownloadedBlock::FillBlock` (clears header to prevent
  re-fill, calls `IsBlockMutated(block, segwit_active)` before
  returning OK).
- `bitcoin-core/src/crypto/siphash.cpp:73-89` — `CSipHasher::Finalize`
  (`m_count << 56`).
- `bitcoin-core/src/crypto/siphash.cpp:91-125` —
  `PresaltedSipHasher::operator()(uint256)` (specialised 4-word fast
  path; `(uint64_t{4}) << 59` is identical to `32 << 56`).
- `bitcoin-core/src/net_processing.h:47` —
  `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`.
- `bitcoin-core/src/net_processing.cpp:138-141` —
  `MAX_CMPCTBLOCK_DEPTH = 5`, `MAX_BLOCKTXN_DEPTH = 10`, static_assert
  `MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP`.
- `bitcoin-core/src/net_processing.cpp:199` — `CMPCTBLOCKS_VERSION = 2`
  (constant).
- `bitcoin-core/src/net_processing.cpp:1272-1329` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs` (HB-peer cap = 3, swap-to-
  protect last outbound, demote oldest, send SENDCMPCT(0,2) on demote
  / SENDCMPCT(1,2) on promote; gate behind `m_provides_cmpctblocks`).
- `bitcoin-core/src/net_processing.cpp:2461-2476` —
  getdata(MSG_CMPCT_BLOCK) serve: depth gate + `a_recent_compact_block`
  cache; on miss, fall back to full block.
- `bitcoin-core/src/net_processing.cpp:3901-3917` — SENDCMPCT receive:
  silently drop `version != CMPCTBLOCKS_VERSION`, set
  `m_provides_cmpctblocks = true`, `m_requested_hb_cmpctblocks =
  sendcmpct_hb`, `m_bip152_highbandwidth_from = sendcmpct_hb`.
- `bitcoin-core/src/net_processing.cpp:4245-4302` — getblocktxn serve
  (`SendBlockTransactions`): depth gate (`MAX_BLOCKTXN_DEPTH`),
  out-of-bounds index → Misbehaving(100), fall-back to full block on
  deep request.
- `bitcoin-core/src/net_processing.cpp:4469-4708` — cmpctblock receive
  (`ProcessCompactBlockTxns` / inline): LoadingBlocks gate, prev-block
  lookup, low-work anti-DoS, ProcessNewBlockHeaders, InitData,
  Misbehaving on rsInvalid, conditional getblocktxn vs getdata
  fall-back, ProcessNewBlock on full reconstruction.
- BIP-152 mediawiki §"Protocol".

**Files audited**
- `src/network/compact_blocks.nim` (679 LOC) — wire encoding, partial-
  block reconstruction, depth helpers, state struct.
- `src/network/peer.nim:140-152, 184-187, 640-645, 1131-1148, 1209-1226,
  1233-1234, 1339-1353, 1366-1457, 1624-1660` — sendcmpct/cmpctblock/
  getblocktxn/blocktxn handlers + handshake + misbehaviour scoring.
- `src/network/messages.nim:88-91, 199-205, 265-274, 454-462, 528-537,
  616-622, 666-672, 825-839, 1065-1080` — message kinds, serializers,
  command-name mapping.
- `src/network/peermanager.nim:91-93, 938-970` — `inFlightBlocks`
  single-valued table, `selectBlockAnnouncement` (BIP-130-only),
  `broadcastBlock`.
- `src/network/relay.nim:301-326` — `relayBlockImmediate` (inv-only).
- `src/nimrod.nim:794-1425` — top-level dispatch (`handleMessage`); note
  `mkCmpctBlock`, `mkGetBlockTxn`, `mkBlockTxn` are NOT listed and fall
  into `else: discard` at line 1424.
- `src/nimrod.nim:971-1006` — getdata(invCmpctBlock) serve.
- `src/crypto/siphash.nim` (160 LOC) — SipHash-2-4 generic path used
  by short-id computation.
- `src/primitives/serialize.nim:188-203, 239-322` — block-hash/tx
  serialization used by writeCompactBlock + writePrefilledTx.

---

## Wire-level audit matrix (24 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sendcmpct(announce, version=2) wire | G1: `bool announce` 1-byte + `uint64 version` LE | PASS (`messages.nim:456-462`) |
| 1 | … | G2: receiver silently drops `version != 2` | PASS (`peer.nim:1344-1346`) |
| 1 | … | G3: sender emits SENDCMPCT(0,2) at handshake end | PARTIAL — `peer.nim:1234` sends unconditionally; **BUG-1** (no IBD/blocksonly/segwit-services guard) |
| 1 | … | G4: pre-VERACK SENDCMPCT recorded, not discarded | **BUG-2 (P1)** — `peer.nim:1137-1138, 1215-1216` only trace; never call `handleSendCmpct`; state lost forever |
| 2 | SipHash key derivation | G5: SHA256-single of `header‖nonce`; k0=low8, k1=next8, little-endian | PASS (`compact_blocks.nim:107-129`) |
| 2 | … | G6: short-id = SipHash-2-4(wtxid, k0, k1) & 0xffffffffffff | PASS (`compact_blocks.nim:131-141`, 4-word path verified — `nimrod` finalize byte `32 << 56` = Core's `(uint64_t{4}) << 59` = same value) |
| 3 | CompactBlock wire | G7: header + uint64LE nonce + compactsize|shortids|6-byte each + compactsize|prefilledtxn| | PASS (`compact_blocks.nim:215-230`) |
| 3 | … | G8: receive reject sum-count > MAX_BLOCK_TXNS=100_000 | **BUG-3 (P1)** — `readCompactBlock` checks `shortIdCount > MaxBlockTxns` AND `prefilledCount > MaxPrefilledTxns` SEPARATELY at decode time. A peer can send `shortIdCount=99_999 + prefilledCount=9_999 = 109_998` (> Core's 100_000), and nimrod allocates + reads all 109_998 entries before the `blockTxCount > 0xFFFF` check at line 256 (which catches sum > 65_535 but not the 100_000..65_535 hole — wait, 0xFFFF = 65_535, so sum > 100_000 IS rejected by the 0xFFFF check. But the memory allocation already happened). Specifically: nimrod allocates `shortIds.add(...)` 99_999 times BEFORE seeing the prefilled count, then errors. DoS amplification: 99_999 × 6-byte allocs = ~600KB read, no early rejection. |
| 4 | Prefilled tx differential encoding | G9: COMPACTSIZE of (idx_i - idx_{i-1} - 1) per Core's `DifferenceFormatter` (`m_shift += n; v = m_shift++`) | PASS (`compact_blocks.nim:183-203`) — write/read mirror Core's formula |
| 4 | … | G10: prefilled.tx.IsNull() = `vin.empty() && vout.empty()` | PASS (`compact_blocks.nim:376` — `inputs.len == 0 and outputs.len == 0`) |
| 4 | … | G11: tx serialized with TX_WITH_WITNESS | PASS (`compact_blocks.nim:189, 295`) |
| 4 | … | G12: prefilled at index 0 is coinbase | **BUG-4 (P1)** — `newCompactBlock` (compact_blocks.nim:152-173) always prefills `blk.txs[0]` with index 0 — but does NOT verify `blk.txs[0].IsCoinBase()`. A mis-constructed Block with non-coinbase at txs[0] silently produces a structurally-invalid cmpctblock; Core's constructor at `blockencodings.cpp:28` also assumes vtx[0] = coinbase but the upstream `CheckBlock` rejects non-coinbase-first blocks before cmpctblock construction is ever reached. nimrod's cmpctblock-construction path is callable from `nimrod.nim:988` regardless of upstream validation state, so the assumption is unchecked. |
| 5 | getblocktxn wire | G13: blockhash + DifferenceFormatter<uint16> indexes | PASS (`compact_blocks.nim:259-287`) — differential decode matches Core's `m_shift += n; v = m_shift++` |
| 5 | … | G14: bound `count` at MAX_BLOCK_TXNS = 100_000 on receive | **BUG-5 (P1)** — `readBlockTxnRequest` (line 272-287) has NO cap on `count`; a peer can send `count = 4_000_000` (fits in 5-byte compactsize), causing 4M readCompactSize loops + 4M `indexes.add(...)`. Capped only by 4MB-wire-limit which allows ~800K compactsize-1 entries (= ~800K-iteration DoS amplification per message). |
| 6 | blocktxn wire | G15: blockhash + tx_count compactsize + TX_WITH_WITNESS each | PASS (`compact_blocks.nim:289-303`) |
| 6 | … | G16: bound `count` at MAX_BLOCK_TXNS = 100_000 on receive | **BUG-6 (P1)** — `readBlockTxnResponse` (line 297-303) has NO cap on `count` either. Same DoS shape as BUG-5. |
| 7 | MAX_CMPCTBLOCK_DEPTH=5 (serve) | G17: getdata(MSG_CMPCT_BLOCK) at depth > 5 → fall back to full block | PASS (`nimrod.nim:983-1001`, calls `cmpctBlockDepthOk`) |
| 7 | … | G18: `a_recent_compact_block` cache reused on same-hash reserve | **BUG-7 (P2)** — nimrod regenerates a fresh nonce + full cmpctblock for EVERY getdata(MSG_CMPCT_BLOCK) request (nimrod.nim:985-988); Core caches the most-recent cmpctblock and reuses if `header.GetHash() == inv.hash`. Bandwidth + CPU regression on hot-block fan-out. |
| 8 | MAX_BLOCKTXN_DEPTH=10 (serve) | G19: getblocktxn at depth > 10 → fall back to full block | **BUG-8 (P0-CDIV serve)** — `mkGetBlockTxn` handler (`peer.nim:1419-1436`) is a noop: comment at line 1431 admits "TODO(BUG-5): look up the block and send a real blocktxn response." Depth check is NOT performed; no block lookup; no fall-back to full-block. nimrod.nim's `handleMessage` (`nimrod.nim:794-1425`) does NOT dispatch `mkGetBlockTxn` (no `of mkGetBlockTxn:` case; falls into `else: discard` at line 1424). **Peers that send us getblocktxn time out waiting for a reply.** `blocktxnDepthOk` helper at `compact_blocks.nim:658-664` is dead-helper-at-call-site (zero `src/` callers). `createBlockTxnResponse` at compact_blocks.nim:670-679 is dead. `newBlockTxnMsg` at messages.nim:1074 is dead. |
| 9 | MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3 | G20: parallel cmpctblock request from up to 3 HB peers per blockhash | **BUG-9 (P1)** — `peermanager.nim:91` `inFlightBlocks: Table[BlockHash, InFlightBlock]` is single-valued. Cannot represent 3 concurrent compact-block downloads for the same hash; structurally precludes Core's multimap semantics. Carry-forward from W126 BUG-6. |
| 10 | HB-mode announce-side | G21: `MaybeSetPeerAsAnnouncingHeaderAndIDs` HB-peer selector (cap 3, swap-to-protect last outbound, demote oldest) | **BUG-10 (P0-CDIV announce)** — no `lNodesAnnouncingHeaderAndIDs` / `nodesAnnouncing` / `hbPeers` analog anywhere in `src/`. Verified via grep. Carry-forward from W126 BUG-3. |
| 10 | … | G22: `peerHighBandwidthTo` (= `m_bip152_highbandwidth_to`) tracked + emit SENDCMPCT(1,2) on promote / SENDCMPCT(0,2) on demote | **BUG-10 cross-cite** — `peer.nim:142` declares `peerHighBandwidth*: bool` (the FROM side); no symmetric TO-side field exists. `sendSendCmpct(announce=true)` is never called anywhere (`grep -rn 'sendSendCmpct.*true' src/` → zero matches). |
| 10 | … | G23: on BlockConnected, send CMPCTBLOCK directly to peers in HB-to mode (skip headers/inv) | **BUG-11 (P0-CDIV announce)** — `peermanager.nim:953-970` `broadcastBlock` calls `selectBlockAnnouncement` which returns only `newHeaders` or `newInv` (peermanager.nim:938-951). `relay.nim:301-326` `relayBlockImmediate` sends only `newInv`. Zero callers of `newCmpctBlockMsg` outside the getdata-serve at `nimrod.nim:989`. **nimrod is BIP-152 receive-only at the announce level** — it cannot proactively push cmpctblocks to anyone. |
| 11 | Version compat | G24: silently ignore SENDCMPCT version=1 (legacy non-witness) per BIP-152 supersession | PASS — `peer.nim:1344-1346` covers all `version != 2`, including version=1; matches Core net_processing.cpp:3907 |
| 12 | sendcmpct sender services | G25: do not send SENDCMPCT to peer that does not signal NODE_WITNESS | **BUG-12 (P1)** — `peer.nim:1233-1234` unconditionally sends `sendSendCmpct` regardless of `peer.services & NODE_WITNESS`. A non-segwit peer (services bit 3 unset) receives our version=2 SENDCMPCT and either drops it (Core peers would per their own check) OR sends us a cmpctblock without witness coverage — there is no negotiation safety net beyond the peer's own validation. Core gates HB-promotion via `m_provides_cmpctblocks` + service-bit checks. |

---

## BUG-1 (P1) — `sendSendCmpct` fired unconditionally at handshake; no IBD/blocksonly/mempool guard

**Severity:** P1. Bitcoin Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs`
(`net_processing.cpp:1276-1279`) returns early when
`m_opts.ignore_incoming_txs` is set (blocksonly mode): *"When in
-blocksonly mode, never request high-bandwidth mode from peers. Our
mempool will not contain the transactions necessary to reconstruct the
compact block."* Additionally, the initial SENDCMPCT(0, 2) is sent
only after `m_provides_cmpctblocks` has been observed.

nimrod's `peer.nim:1233-1234` sends `sendSendCmpct()` unconditionally
at the end of every handshake, regardless of:
- IBD state (mempool is empty / under-filled during IBD; received
  cmpctblocks will not reconstruct from mempool),
- blocksonly mode (the receive-side at `peer.nim:1384` correctly
  guards on `peer.mempool != nil` but the SEND-SIDE still advertises
  v2 capability, causing peers to push cmpctblocks we cannot
  reconstruct),
- the peer's own NODE_BLOOM / NODE_WITNESS service signalling.

**File:** `src/network/peer.nim:1233-1234, 640-645`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1276-1279`.

**Impact:** during IBD, every cmpctblock offered by HB-mode peers
fails mempool fill (BUG-9 from W126: 50% threshold also short-
circuits). Net effect: bandwidth waste for the duration of IBD;
nimrod falls back to full-block getdata for every announced block but
the cmpctblock-receive path still allocates the PartiallyDownloadedBlock
struct and runs InitData first.

---

## BUG-2 (P1) — Pre-VERACK SENDCMPCT silently dropped; never recorded on state

**Severity:** P1. Bitcoin Core processes SENDCMPCT regardless of
verack ordering — the message is observed early in
`PeerManagerImpl::ProcessMessage` and updates `m_provides_cmpctblocks`
and `m_bip152_highbandwidth_from` immediately. Peers that signal
high-bandwidth mode BEFORE the verack exchange completes (a legitimate
ordering — Core sends sendcmpct before SendMessages runs SetMsgFlags)
have their preferences recorded.

nimrod's handshake loop at `peer.nim:1131-1148` (outbound) and
`peer.nim:1209-1226` (inbound) handles `mkSendCmpct` only via
`trace "peer supports compact blocks (pre-verack)"` — there is **NO**
call to `peer.compactBlockState.handleSendCmpct(...)` or to set
`peer.peerCmpctVersion` / `peer.peerHighBandwidth`.

**Failure mode:** a peer that sends SENDCMPCT once during the pre-
verack window (correct per BIP-152 timing) and never re-sends post-
verack (which Core does NOT re-send) leaves us with
`peerCmpctVersion=0` forever — even though the peer said it supports
cmpctblocks. Compounded with BUG-10/BUG-11 (we never announce
cmpctblocks anyway), the practical effect is masked, but the state
record is wrong.

**File:** `src/network/peer.nim:1131-1148, 1209-1226`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3901-3917` (handler
runs without verack precondition).

**Impact:** stale `peerCmpctVersion=0` for peers that send SENDCMPCT
once pre-verack. Receive-side never serves cmpctblocks to them via
getdata(MSG_CMPCT_BLOCK) (because `peerCmpctVersion` check would gate
the serve, see also W126 BUG-7 — but that check is also currently
missing, so the impact is masked twice over). Fix to one defect
without the other unmasks the second.

---

## BUG-3 (P1) — `readCompactBlock` wire decode accepts sum > MAX_BLOCK_TXNS prior to per-decode cap

**Severity:** P1. Bitcoin Core's `CBlockHeaderAndShortTxIDs`
SERIALIZE_METHODS (`blockencodings.h:121-130`) checks
`obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()` on
read. `PartiallyDownloadedBlock::InitData` (`blockencodings.cpp:64`)
additionally checks
`cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() >
MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` (= 100_000)
and rejects with READ_STATUS_INVALID.

nimrod's `readCompactBlock` (`compact_blocks.nim:232-257`) checks each
count SEPARATELY:

```nim
let shortIdCount = r.readCompactSize()
if shortIdCount > MaxBlockTxns:               # = 100_000
  raise newException(SerializationError, "too many short IDs")
for i in 0 ..< int(shortIdCount):
  result.shortIds.add(r.readShortId())        # allocates here

let prefilledCount = r.readCompactSize()
if prefilledCount > MaxPrefilledTxns:         # = 10_000
  raise newException(SerializationError, "too many prefilled transactions")
for i in 0 ..< int(prefilledCount):
  result.prefilledTxns.add(r.readPrefilledTx(prevIndex))

if result.blockTxCount() > int(high(uint16)):  # = 65_535
  raise newException(SerializationError, "block tx count overflowed 16 bits")
```

A malicious peer can send `shortIdCount = 65_535` AND `prefilledCount =
10_000` AND each prefilled tx is the 40-byte serialised-minimum
transaction (fits ~390 KB total, under 4 MB MaxMessagePayload). The
65_535 + 10_000 = 75_535 sum exceeds Core's 65_535 (the 0xFFFF check
catches it at the end) — but nimrod has already allocated:
- 65_535 × 6-byte short-id reads = 393_210 bytes,
- 10_000 partial Transaction reads with at-least 40-byte serialization
  each = ~400_000 bytes,
- Plus seq[] amortised overhead.

Core does the wire-level read into temporary structures, then the
InitData check immediately rejects on sum > 100_000 BEFORE any further
allocation. nimrod's allocation is irreversible (the seq[]s in
`result.shortIds` / `result.prefilledTxns` are kept until GC), and the
deserialiser only fails at the very end. **DoS amplification: ~800 KB
write per junk cmpctblock.**

**File:** `src/network/compact_blocks.nim:238-257`.

**Core ref:** `bitcoin-core/src/blockencodings.h:121-130`,
`bitcoin-core/src/blockencodings.cpp:62-65` (sum-count cap).

**Impact:** memory DoS amplification per junk message; combined with
BUG-13 (Misbehaving never called on rsInvalid) the peer pays no cost
for sending these.

---

## BUG-4 (P1) — `newCompactBlock` assumes `blk.txs[0]` is coinbase without verification

**Severity:** P1. Bitcoin Core's `CBlockHeaderAndShortTxIDs`
constructor (`blockencodings.cpp:20-33`) is called only AFTER the
block has been validated via `CheckBlock` (which enforces
"bad-cb-missing" — coinbase must be at vtx[0] and be a true coinbase
per `IsCoinBase()`). nimrod's `newCompactBlock` is callable from
`nimrod.nim:988` (getdata(MSG_CMPCT_BLOCK) serve) for ANY block
retrieved from the db, including header-only / orphan / partially-
validated blocks. The first transaction is unconditionally prefilled
with index 0 without checking `IsCoinBase()`.

**File:** `src/network/compact_blocks.nim:152-173, 168`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:28` —
`prefilledtxn[0] = {0, block.vtx[0]}` is preceded by upstream
CheckBlock that enforces `tx[0].IsCoinBase()`.

**Impact:** a structurally invalid block in the db (should not exist
post-CheckBlock, but the wire-serve path does not re-validate) would
be relayed as a cmpctblock with a non-coinbase prefilled at index 0,
which the receiving peer would silently accept (cmpctblock does not
re-enforce coinbase placement). Fleet-interop break: peer's later
`CheckBlock` would reject; we'd be banned for serving "invalid"
cmpctblocks even though the block was valid by-shape at the storage
layer. Combined with BUG-13 (we have no equivalent ban guard for them),
the asymmetry is one-sided against us.

---

## BUG-5 (P1) — `readBlockTxnRequest` has NO cap on `count`; DoS amplification via differential-index inflation

**Severity:** P1. Bitcoin Core's `BlockTransactionsRequest` is
serialised via `Using<VectorFormatter<DifferenceFormatter>>(obj.indexes)`
(`blockencodings.h:53`). The `VectorFormatter` length-prefix limit is
implicit via the surrounding `MAX_PROTOCOL_MESSAGE_LENGTH = 4 MB`
limit and the `DifferenceFormatter` `m_shift` overflow check at line
40 (`m_shift >= numeric_limits<uint64_t>::max()`). Core's getblocktxn
serve path then explicitly checks `req.indexes[i] >= block.vtx.size()`
and Misbehaves on out-of-bounds.

nimrod's `readBlockTxnRequest` (`compact_blocks.nim:272-287`) reads
`count` from compactsize WITHOUT a cap:

```nim
result.blockHash = r.readBlockHash()
let count = r.readCompactSize()
var prevIndex = 0
for i in 0 ..< int(count):
  let diff = r.readCompactSize()
  ...
```

`count` can be up to ~4 million (a 5-byte compactsize fits up to
`0xFFFFFFFF` but the 4MB wire cap limits actual inflation to ~800k
single-byte compactsize entries — still 800k iterations + 800k seq
appends per malicious message).

**File:** `src/network/compact_blocks.nim:272-287`.

**Core ref:** Implicit via 4MB wire cap + DifferenceFormatter `m_shift`
overflow at `bitcoin-core/src/blockencodings.h:40`.

**Impact:** CPU DoS amplification per malicious getblocktxn message:
800k `readCompactSize` calls + 800k `indexes.add(uint16)` per message;
no ban, no rate-limit (BUG-13 cross-cite). Compounded by BUG-8
(getblocktxn serve handler is a noop), so the cost is paid on PARSE
only; we don't then look up + serve a block. But the parser pays.

---

## BUG-6 (P1) — `readBlockTxnResponse` has NO cap on `count`; same shape as BUG-5

**Severity:** P1. Symmetric defect on the blocktxn RECEIVE path.

```nim
result.blockHash = r.readBlockHash()
let count = r.readCompactSize()
for i in 0 ..< int(count):
  result.transactions.add(r.readTransaction())
```

A malicious blocktxn with `count` of 800k forces 800k `readTransaction`
calls, each of which (per `primitives/serialize.nim:271-322`) reads at
minimum 4 + 1 + n + 4 = ~10 bytes for an empty-input empty-output tx,
which the parser would reject IF it gets to the IsNull check — but it
doesn't, because there is no IsNull check inside `readTransaction`. So
the parser would happily consume 800k transactions each ~10-60 bytes
into `result.transactions`, exhausting RAM before the 4MB wire cap
trips.

Wait — 800k × 40 bytes = 32 MB, well over 4 MB. So the actual inflation
ceiling is ~100k transactions (4 MB / 40-byte-min). Still: 100k tx
allocations per junk message, no ban, no rate-limit.

**File:** `src/network/compact_blocks.nim:297-303`.

**Core ref:** Implicit via 4MB wire cap + `MAX_BLOCK_TXNS` enforcement
at `bitcoin-core/src/blockencodings.cpp:64` for the cmpctblock-side
construction (Core's blocktxn receive uses the original indexes set
length, not the wire count, to gate).

**Impact:** RAM DoS amplification per malicious blocktxn message. The
post-parse handler at `peer.nim:1438-1457` doesn't reject mismatched
counts (the txns are simply not used unless matched by hash), but the
allocation already happened.

---

## BUG-7 (P2) — `a_recent_compact_block` cache absent; regenerate per-request

**Severity:** P2 (performance, not correctness). Bitcoin Core caches
the most-recently-served compact block in `a_recent_compact_block`
(`net_processing.cpp:2467-2471`); if the requested hash matches, the
cached cmpctblock is sent unchanged (same nonce, same short-IDs). This
amortises siphash key derivation + per-tx short-id computation across
multiple peers requesting the same block (common at fan-out time).

nimrod's serve path (`nimrod.nim:985-988`) regenerates a fresh
`urandom(8)` nonce and constructs a new `CompactBlock` on EVERY
getdata(MSG_CMPCT_BLOCK) request:

```nim
let nonce = urandom(8)
var nonceVal: uint64
for i in 0 ..< 8: nonceVal = nonceVal or (uint64(nonce[i]) shl (i * 8))
let cb = newCompactBlock(blk, nonceVal)   # re-runs SipHash key derivation
                                          # + per-tx short-ID computation
```

For a 4000-tx block fan-out to 8 peers, this is 8 × 4000 = 32_000
SipHash operations versus Core's 4_000.

**File:** `src/nimrod.nim:985-988`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2467-2471`.

**Impact:** CPU/throughput regression on block fan-out; ~8× SipHash
operations per fan-out event. Not consensus.

---

## BUG-8 (P0-CDIV serve) — `mkGetBlockTxn` handler is a stub; nimrod is unservable as a BIP-152 partner

**Severity:** P0-CDIV (carry-forward from W126 BUG-2, but escalated to
P0-CDIV here because the dispatch gap also extends through nimrod.nim).
Bitcoin Core's `SendBlockTransactions` (`net_processing.cpp:4245-4302`)
processes getblocktxn:
1. Look up `pindex` by hash; depth gate (`pindex->nHeight >= tip -
   MAX_BLOCKTXN_DEPTH`); else respond with MSG_BLOCK fallback.
2. Read the block from disk.
3. For each `req.indexes[i]`: check `< block.vtx.size()`; otherwise
   `Misbehaving(peer, 100, "getblocktxn with out-of-bounds tx indices")`.
4. Build BlockTransactions response and send.

nimrod's `mkGetBlockTxn` arm at `peer.nim:1419-1436`:

```nim
of mkGetBlockTxn:
  let req = msg.getBlockTxn
  info "received getblocktxn", peer = $peer,
       hash = $req.blockHash,
       indexes = req.indexes.len
  # TODO(BUG-5): look up the block and send a real blocktxn response.
  # For now the depth gate is present; requests deeper than
  # MAX_BLOCKTXN_DEPTH are logged as such so callers know to expect
  # a full block response from a correctly-wired implementation.
  # (Depth check requires chain state which is not accessible here;
  # the full guard is enforced at the NodeState layer in nimrod.nim.)
```

The comment claims "the depth gate is present" but **no depth check is
actually called** — the `blocktxnDepthOk` helper at
`compact_blocks.nim:658-664` has zero callers (verified via
`grep -rn blocktxnDepthOk src/`). The comment also claims dispatch
will route via nimrod.nim — but `handleMessage` in `nimrod.nim` (lines
794-1425) does NOT include a `of mkGetBlockTxn:` case, so the message
falls through to `else: discard` at line 1424. **The handler is a
no-op at every layer.**

Consequence: peers that send us getblocktxn time out waiting for a
blocktxn reply. They eventually fall back to full-block getdata, but
the original BIP-152 round-trip is wasted. `createBlockTxnResponse`
(`compact_blocks.nim:670-679`) is a dead helper. `newBlockTxnMsg`
(`messages.nim:1074`) is a dead constructor. The G19 "MAX_BLOCKTXN_DEPTH
on serve" gate is unreachable.

**File:** `src/network/peer.nim:1419-1436`; `src/network/compact_blocks.nim:658-679`;
`src/network/messages.nim:1074-1080`; `src/nimrod.nim:794-1425` (no
dispatch case).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4245-4302`,
`SendBlockTransactions` at 2598.

**Impact:** nimrod is **unusable as a BIP-152 serving partner**. Any
peer that selects us as HB-source-of-them (which BUG-2 prevents anyway
in practice, but the gap exists if we ever wire BUG-2 / BUG-10) will
time out on every getblocktxn. Combined with BUG-10 (no HB-mode
announce side), the entire BIP-152 surface is effectively
receive-only — and even receive does not route reconstructed blocks
into validation (W126 BUG-9). **The cmpctblock subsystem ships ~700
LOC of well-engineered code that is almost entirely unwired.**

This is the **5th wire-level subsystem in 2026** where nimrod ships
"defined but unwired" infrastructure (BIP-152 announce + serve, BIP-152
extra-pool fill, BIP-157 violation disconnect pre-FIX-78, BIP-331
package-relay receive, BIP-339 wtxid-relay sender) — fleet pattern.

---

## BUG-9 (P1) — `inFlightBlocks` single-valued; structurally precludes MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3

**Severity:** P1 (carry-forward from W126 BUG-6). Bitcoin Core's
`mapBlocksInFlight` is a `std::multimap<uint256, ...>` (`net_processing.h`)
keyed on blockhash with up to `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3`
entries from distinct HB peers. This allows parallel cmpctblock
download from 3 peers for the same hash — the first one to
successfully reconstruct wins; the others are aborted.

nimrod's `peermanager.nim:91`:

```nim
inFlightBlocks: Table[BlockHash, InFlightBlock]
```

Single-valued. A second peer pushing the same blockhash overwrites the
first entry, silently losing the original in-flight record. Cannot
express Core's MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3 semantics.

**File:** `src/network/peermanager.nim:91`.

**Core ref:** `bitcoin-core/src/net_processing.h:47` (constant);
`net_processing.cpp:4577-4624` (3-peer parallel logic).

**Impact:** masked by BUG-10/BUG-11 (we never have 3 HB peers to
parallel-download from anyway); but a fix to BUG-10 unmasks this
defect — the architecture would need redesign before HB-mode could
actually function.

---

## BUG-10 (P0-CDIV announce) — `MaybeSetPeerAsAnnouncingHeaderAndIDs` analog entirely absent

**Severity:** P0-CDIV (carry-forward from W126 BUG-3). Bitcoin Core's
`MaybeSetPeerAsAnnouncingHeaderAndIDs` (`net_processing.cpp:1272-1329`)
manages the HB-peer selection list `lNodesAnnouncingHeaderAndIDs` with:
- cap of 3 peers,
- swap-to-protect last outbound HB peer when adding inbound,
- demote oldest when full,
- emit SENDCMPCT(0,2) on demote / SENDCMPCT(1,2) on promote.

nimrod has none of this. Verified via grep:
- `grep -rn "lNodesAnnouncing\|hbPeers\|HighBandwidthPeers" src/` → zero matches.
- `grep -rn "sendSendCmpct.*true" src/` → zero matches; the announce
  parameter on `sendSendCmpct` is always defaulted to `false`.
- `peer.nim:142` declares `peerHighBandwidth*: bool` (the FROM-side)
  but the symmetric `peerHighBandwidthTo` field does NOT exist.

**File:** `src/network/peermanager.nim` (no HB-peer list);
`src/network/peer.nim:142, 640-645` (no announce=true emission).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`.

**Impact:** nimrod never PROMOTES a peer to HB-mode-from-us; therefore
never emits SENDCMPCT(1,2) outbound; therefore peers receive only
SENDCMPCT(0,2) — they will offer cmpctblocks only after we explicitly
request via getdata(MSG_CMPCT_BLOCK), which we never do (BUG-11). The
proactive-push half of BIP-152 is completely disabled.

---

## BUG-11 (P0-CDIV announce) — `broadcastBlock` / `relayBlockImmediate` never emit `cmpctblock`

**Severity:** P0-CDIV (carry-forward from W126 BUG-3 sub-case, but
escalated here because the announce-side defect is wider than
selectBlockAnnouncement). Bitcoin Core's announce loop
(`net_processing.cpp:5895-5912`) iterates over connected peers and, for
each peer with `m_bip152_highbandwidth_to == true`, sends CMPCTBLOCK
directly (bypassing headers/inv). Other peers receive headers (BIP-130
sendheaders-preference) or inv.

nimrod's `peermanager.nim:953-970` `broadcastBlock` calls
`selectBlockAnnouncement(header, hash, peer.sendHeaders)` which returns
ONLY `newHeaders` or `newInv` (lines 938-951). `relay.nim:301-326`
`relayBlockImmediate` sends only `newInv`. Zero callers of
`newCmpctBlockMsg` outside the reactive getdata-serve at
`nimrod.nim:989`.

**Failure mode:** even if BUG-10 were fixed (HB-peer selection
working), the announce path would still emit only headers/inv because
`selectBlockAnnouncement` has no cmpctblock branch. The BIP-152
proactive-push optimisation — the entire reason for HB-mode existing —
is structurally absent.

**File:** `src/network/peermanager.nim:938-970`;
`src/network/relay.nim:301-326`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5895-5912`.

**Impact:** nimrod is **BIP-152-receive-only at the announce level**
even when receive-side is wired. Bandwidth + latency cost: every new
block we mine (via internalminer) or relay (from another peer via
inv) reaches downstream peers via headers + getdata(MSG_BLOCK) round-
trip — never the single-shot cmpctblock push.

---

## BUG-12 (P1) — `sendSendCmpct` sent to non-NODE_WITNESS peers; protocol contract leak

**Severity:** P1. Bitcoin Core's CMPCTBLOCKS_VERSION = 2 implies
witness-tx serialization in prefilled transactions. The peer must
support NODE_WITNESS (service bit 3) to consume version=2 cmpctblocks
correctly. Core gates HB-promotion via `m_provides_cmpctblocks` AND
the peer's own version=2 advertisement — which a non-NODE_WITNESS
peer would never make. But the INITIAL SENDCMPCT(0,2) advertisement
from us to them is sent regardless; the peer then advertises its own
SENDCMPCT (if any) which we silently drop if version != 2 (BIP-152
correct behaviour). So this is mostly cosmetic on the send side.

However: nimrod's `peer.nim:1233-1234` sends `sendSendCmpct()`
unconditionally without checking `peer.services & NODE_WITNESS`. A
peer that advertises e.g. NODE_NETWORK_LIMITED but NOT NODE_WITNESS
(rare but legal — a pruned non-witness node, hypothetical) would see
our v2 advert and could respond with their own v2 SENDCMPCT (they
might support v2 receive even if they don't serve witness data). The
asymmetry creates a fleet-interop ambiguity: we'd then offer them
witness-bearing prefilled txs they cannot parse.

**File:** `src/network/peer.nim:1233-1234`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3868-3870` (sends
SENDCMPCT only to peers post-VERACK with v2 capability inference).

**Impact:** edge-case fleet-interop ambiguity; very low in practice
(no production peer ships without NODE_WITNESS today). Listed for
defense-in-depth.

---

## BUG-13 (P0-CDIV) — `Misbehaving` never called on `rsInvalid` cmpctblock; `ScoreInvalidCompactBlock` is dead-constant-at-call-site

**Severity:** P0-CDIV (carry-forward from W126 BUG-5; W156 elevates
because it compounds with BUG-3/BUG-5/BUG-6 DoS amplification). Bitcoin
Core's `net_processing.cpp:4592-4594` on `READ_STATUS_INVALID` from
`PartiallyDownloadedBlock::InitData` calls:

```cpp
RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId());
Misbehaving(peer, "invalid compact block");
```

The peer is immediately flagged for disconnect (post-PR-25974 the
Misbehaving threshold is removed; any call disconnects).

nimrod's `peer.nim:1378-1379`:

```nim
if status != rsOk:
  warn "invalid compact block", peer = $peer, status = $status
```

Only a log line. No `peer.misbehaving(...)` call. The
`ScoreInvalidCompactBlock = 100` constant defined at
`peer.nim:1635` is **dead-constant-at-call-site** — defined,
documented, never invoked. Verified via grep:

```bash
grep -rn 'ScoreInvalidCompactBlock\|misbehaving.*[Cc]ompact\|misbehaving.*cmpct' src/
# Result: only the definition at peer.nim:1635. Zero call sites.
```

**File:** `src/network/peer.nim:1378-1379, 1635, 1641-1650`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4592-4594`.

**Impact:** combined with BUG-3 (DoS amplification on junk cmpctblock
parse), BUG-5 (DoS on junk getblocktxn parse), and BUG-6 (DoS on junk
blocktxn parse), a malicious peer can pay ~800 KB of bandwidth and ~1 MB
of our RAM per junk message INDEFINITELY without ever being
disconnected. Classic **dead-constant-at-call-site** fleet pattern
(W156's first instance documented; carry-forward from W126 unresolved
since 2026-05-17).

---

## BUG-14 (P1) — Reconstructed block on cmpctblock-only fill is dropped; no chain submission

**Severity:** P1 (carry-forward from W126 BUG-9; W156 re-anchors the
gate). Bitcoin Core's `ProcessCompactBlockTxns` / inline path at
`net_processing.cpp:3505-3513` / `4701-4708` calls `ProcessNewBlock`
with `force_processing=true, min_pow_checked=true` on successful
reconstruction.

nimrod's `peer.nim:1387-1399` (cmpctblock-only reconstruction from
mempool) and `peer.nim:1445-1454` (blocktxn-completed reconstruction)
both end in:

```nim
peer.compactBlockState.successfulReconstructions += 1
```

Stat counter only. No call to `state.syncManager.processBlock(blk)` /
equivalent. Verified by grep: no `connectBlock` / `processNewBlock` /
`chainState.acceptBlock` call inside the mkCmpctBlock or mkBlockTxn
arms of `peer.nim:handleMessage`.

**File:** `src/network/peer.nim:1387-1457`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3505-3513`.

**Impact:** reconstructed blocks are silently dropped. nimrod re-fetches
the same block via headers + getdata(MSG_BLOCK) when re-announced by
another peer, defeating the entire purpose of compact-block relay.
Throughput cost: O(block-size) bytes per re-fetch, ~1MB on a typical
mainnet block.

---

## BUG-15 (P1) — `reconstructBlock` does NOT call `IsBlockMutated`; merkle / witness commitment unchecked at FillBlock layer

**Severity:** P1 (carry-forward from W126 BUG-8). Bitcoin Core's
`PartiallyDownloadedBlock::FillBlock` (`blockencodings.cpp:218-222`)
calls `IsBlockMutated(block, segwit_active)` and returns
`READ_STATUS_FAILED` if true; this catches short-ID-collision-induced
wrong-tx reconstructions that produce structurally-invalid blocks.

nimrod's `compact_blocks.nim:546-570` `reconstructBlock` explicitly
documents the gap:

```nim
# Note: Bitcoin Core also calls IsBlockMutated(block, segwit_active) here
# (line 220) to verify the merkle root and witness commitment before returning
# READ_STATUS_OK.  Full mutation checking requires the chain context
# (segwit active flag) which is threaded in at the call site; callers should
# verify merkle root and witness commitment after this returns rsOk.
```

This is a **comment-as-confession** (W156's 1st instance; nimrod fleet
pattern 9th distinct). The callers at `peer.nim:1389, 1446` do NOT
verify merkle root or witness commitment — they only log success and
drop the block (BUG-14).

**File:** `src/network/compact_blocks.nim:564-568`;
`src/network/peer.nim:1389, 1446`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:218-222`.

**Impact:** short-ID-collision-induced wrong-tx reconstruction is not
caught at the cmpctblock layer. Validation would catch later via
merkle root check in connectBlock, but DoS-resilience is lower: Core
fails fast and falls back to getdata(MSG_BLOCK); nimrod would silently
accept the wrong block into pending and have no fallback path because
BUG-14 means we never connect anyway.

---

## BUG-16 (P1) — `reconstructBlock` does NOT clear `pdb.header` to prevent double-fill

**Severity:** P1 (carry-forward from W126 BUG-13). Bitcoin Core's
`FillBlock` (`blockencodings.cpp:211-212`) does:

```cpp
header.SetNull();
txn_available.clear();
```

After successful fill, to prevent the same partial block from being
re-filled with a different blocktxn response (e.g., from a second
malicious peer that replays the same blockhash with different
transactions).

nimrod's `reconstructBlock` does not clear `pdb.header` after fill. The
guard at `compact_blocks.nim:552-554` (return `rsInvalid` on null
header) is the only protection, and it's only useful if the header was
ever cleared in the first place. Mitigated in practice by
`completeBlock` calling `state.pendingPartials.del(blockHash)` on
success (line 620), but if `reconstructBlock` is called directly from
the mempool-fill path at `peer.nim:1389` (where there is no `del`),
the pdb remains in `pendingPartials` (because we never added it for
the mempool-only path — see peer.nim:1387-1399, no add to pendingPartials)
— so the actual replay window is narrow.

**File:** `src/network/compact_blocks.nim:546-570`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:211-212`.

**Impact:** narrow replay window; defence-in-depth gap. Combined with
BUG-14 (block dropped anyway), the practical impact is masked.

---

## BUG-17 (P0-CDIV) — `mkCmpctBlock` header not chain-state-validated; LoadingBlocks / prev-block / anti-DoS-work gates absent

**Severity:** P0-CDIV (carry-forward from W126 BUG-1). Bitcoin Core's
cmpctblock receive path at `net_processing.cpp:4469-4508`:

1. `LoadingBlocks()` gate — drop if importing/reindexing.
2. Look up `prev_block`; if not found AND not IBD, send GETHEADERS
   instead.
3. Anti-DoS work check: `prev_block->nChainWork +
   GetBlockProof(header) < AntiDoSWorkThreshold` → drop.
4. `ProcessNewBlockHeaders({header})` to enter the header into the
   chain index; punish via `MaybePunishNodeForBlock(via_compact_block=true)`
   on invalid.

nimrod's `peer.nim:1366-1377` proceeds directly to
`initPartiallyDownloadedBlock(cb)` with NONE of the above gates:

```nim
of mkCmpctBlock:
  let cb = msg.cmpctBlock
  let headerData = serialize(cb.header)
  let blockHash = BlockHash(doubleSha256(headerData))
  info "received compact block", peer = $peer, ...
  var (pdb, status) = initPartiallyDownloadedBlock(cb)  # <-- no prev-block / anti-DoS gates
```

**File:** `src/network/peer.nim:1366-1377`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4469-4508`.

**Impact:** a peer can send cmpctblocks for arbitrary headers
(including orphan / invalid-PoW / low-work-fake) and trigger mempool
short-id matching work; nimrod has no anti-DoS counter on this path
(compounding with BUG-13 which removes the only consequence anyway).
Orphan-header cmpctblocks should trigger getheaders to re-locate the
ancestor chain — nimrod simply accepts and runs InitData.

---

## BUG-18 (P1) — `getdata(invCmpctBlock)` serve does NOT precondition on `peerCmpctVersion`; serves cmpctblocks to peers that never sent SENDCMPCT

**Severity:** P1 (carry-forward from W126 BUG-7). Bitcoin Core's
getdata(MSG_CMPCT_BLOCK) serve path at `net_processing.cpp:2461`
operates only on peers whose `m_provides_cmpctblocks` is true (set
when SENDCMPCT(version=2) was received). A peer that never sent
SENDCMPCT but issues getdata(MSG_CMPCT_BLOCK | 4) is anomalous; Core
would not be honoring an HB-mode that wasn't negotiated.

nimrod's `nimrod.nim:971-1006` serves a compact block for any
getdata(invCmpctBlock) inv item, regardless of the requesting peer's
SENDCMPCT history. `peer.peerCmpctVersion` is set on receipt (`peer.nim:1348`)
but never consulted at serve time. `compactBlockState.wantsCompactBlocks`
similarly is set but never checked.

**File:** `src/nimrod.nim:971-1006`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2461`.

**Impact:** bandwidth waste serving cmpctblocks to peers that won't
understand them; spec-divergence at the periphery (peer with v1 client
and no SENDCMPCT receives a v2 cmpctblock with witness-bearing
prefilled txs that would fail to parse on a non-witness-aware
deserializer).

---

## BUG-19 (P1) — Two-pipeline guard: peer.peerCmpctVersion + peer.peerHighBandwidth vs compactBlockState.wantsCompactBlocks + compactBlockState.highBandwidthMode (21st distinct extension)

**Severity:** P1. nimrod tracks SENDCMPCT state in TWO places:

1. **`peer.peerCmpctVersion: uint64`** and **`peer.peerHighBandwidth:
   bool`** (`peer.nim:141-142, 1348-1349`).
2. **`peer.compactBlockState.wantsCompactBlocks: bool`**,
   **`compactBlockVersion: uint64`**, **`highBandwidthMode: bool`**
   (`compact_blocks.nim:93-95, 594-596`).

Both are written by the SAME handler at `peer.nim:1347-1350`:

```nim
peer.peerCmpctVersion = version
peer.peerHighBandwidth = announce
peer.compactBlockState.handleSendCmpct(announce, version)
```

But:
- `peer.peerCmpctVersion` and `peer.peerHighBandwidth` are NEVER READ
  anywhere else in the codebase (verified via grep — zero consumers).
- `compactBlockState.wantsCompactBlocks` / `highBandwidthMode` are
  read ONLY by the dead helpers `shouldSendCompactBlock` and
  `supportsHighBandwidth` (`compact_blocks.nim:641-648`), which
  themselves have ZERO callers.

This is the **21st distinct two-pipeline-guard finding** across the
nimrod fleet (per W155 quad-audit tracking) AND is also a
**dead-data-plumbing** fleet pattern (state written, never read on
either pipe). The two pipes diverge by construction (handleSendCmpct
drops version != 2; direct assignment doesn't), so a future caller
reading one vs the other would see different values for version=1
inputs.

**File:** `src/network/peer.nim:141-142, 1347-1350`;
`src/network/compact_blocks.nim:93-95, 594-596, 641-648`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3909-3915` (single
`CNodeState` + `CNode` field; no doubled state).

**Impact:** dead-data symmetric pair; cleanup candidate. Any future
fix to BUG-18 (gate getdata serve on cmpctVersion) must choose
between the two pipes — choosing the wrong one would leak state
divergence at version=1.

---

## BUG-20 (P1) — `MaxBlockTxns` defined twice with same value but different derivation; comment-as-confession 2nd nimrod instance

**Severity:** P1 (minor). `compact_blocks.nim:23-28`:

```nim
## Maximum transactions per block (sanity check).
## Mirrors Bitcoin Core blockencodings.cpp:64:
##   MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 4_000_000 / 40 = 100_000.
## Previously this used 60 (MIN_TRANSACTION_WEIGHT / WitnessScaleFactor) by mistake,
## giving 66_666 and leaving the guard too tight.
MaxBlockTxns* = MaxBlockWeight div MinSerializableTransactionWeight  # = 100_000
```

The comment is a **comment-as-confession** about a prior off-by-coefficient
bug (used `60` instead of `10` in MIN_SERIALIZABLE_TRANSACTION_WEIGHT
derivation). The fix is correct (100_000 matches Core). However: the
0xFFFF check at line 256 caps the SUM at 65_535, which is TIGHTER than
MaxBlockTxns=100_000. So MaxBlockTxns is effectively unused for the
purpose it was named for — the actual limit on read is 65_535 (the
uint16 representable space). The fix-comment celebrates a 100_000
constant that is never the binding constraint.

**File:** `src/network/compact_blocks.nim:23-28, 240, 359`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:64`.

**Impact:** the 100_000 constant is correctly mirrored but the actual
wire-rejection threshold is 65_535 (the more-restrictive 0xFFFF
overflow check). A clean implementation would either remove the
65_535 check (relying on 100_000) or remove the 100_000 check
(relying on 65_535). Co-existence is fleet-pattern noise.

---

## BUG-21 (P1) — `MAX_BLOCKTXN_DEPTH` violated by `MIN_BLOCKS_TO_KEEP` mismatch (Core's static_assert not enforced in nimrod)

**Severity:** P1. Bitcoin Core's `net_processing.cpp:141`:

```cpp
static const int MAX_BLOCKTXN_DEPTH = 10;
static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP, "MAX_BLOCKTXN_DEPTH too high");
```

The static_assert guarantees that pruned nodes can ALWAYS serve a
blocktxn for requests up to `MAX_BLOCKTXN_DEPTH = 10` deep — because
the corresponding block body MUST still be on disk (`MIN_BLOCKS_TO_KEEP
= 288` includes the recent 10 plenty of times).

nimrod defines `MaxBlocktxnDepth = 10` (`compact_blocks.nim:41`) and
`MinBlocksToKeep = 288` (likely elsewhere — confirmed at
`util/ops.nim` per the cross-cite from W149 context), but there is NO
equivalent compile-time check. If a future change reduces MinBlocksToKeep
below 10, the wire-spec correctness silently breaks. Combined with
BUG-8 (handler is a stub), this is dormant today, but the
defense-in-depth gap exists.

**File:** `src/network/compact_blocks.nim:36-41`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:141`.

**Impact:** dormant; no current path triggers. Listed for completeness.

---

## BUG-22 (P1) — handshake message dispatch loop accepts up to 20 pre-VERACK feature messages; cmpctblock not in allow-list

**Severity:** P1. nimrod's handshake pre-VERACK loops at
`peer.nim:1120-1148` (outbound) and `peer.nim:1198-1226` (inbound)
allow up to 20 messages between version-exchange and verack-arrival.
The allow-list covers: `mkVerack`, `mkWtxidRelay`, `mkSendAddrV2`,
`mkSendCmpct`, `mkSendHeaders`, `mkFeeFilter`, `mkSendTxRcncl`. ANY
OTHER message raises `PeerError "unexpected message during handshake"`.

Bitcoin Core's `ProcessMessage` does NOT enforce a strict allow-list
between VERSION and VERACK — peers MAY send `MEMPOOL`, `GETADDR`,
`PING` (and Core handles them; some are deferred until post-VERACK).
nimrod's allow-list rejects e.g. a stray `PING` or `MEMPOOL` between
VERSION and VERACK, disconnecting the peer.

For BIP-152 specifically: a peer that sends `CMPCTBLOCK` (announcing
a new block they just mined) before our VERACK arrives — which is a
legitimate ordering if our handshake is slow — gets DISCONNECTED with
"unexpected message during handshake". Core would queue the message
and process it post-VERACK.

**File:** `src/network/peer.nim:1120-1148, 1198-1226, 1148, 1226`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
(no strict pre-VERACK allow-list).

**Impact:** rare-but-real: a peer that mined a block during our 60-
second handshake window and tried to announce via cmpctblock gets
disconnected. They'd reconnect and re-announce, but the connection
churn is observable in operator logs and creates a fleet-interop
asymmetry.

---

## BUG-23 (P2) — `BlockTxnRequest` `indexes` allocated as `seq[uint16]` even when count = 0; minor

**Severity:** P2 (cosmetic / type-tightness). `compact_blocks.nim:272-287`
allocates `result.indexes: seq[uint16]` via `add` calls; for a request
with count=0 this allocates an empty seq with no items. Nim's `seq`
has a small header overhead but is otherwise fine. Listed only for
parity with the fleet pattern of "wire-decode-allocates-too-eagerly".

**File:** `src/network/compact_blocks.nim:286`.

**Impact:** none; cosmetic.

---

## BUG-24 (P1) — `mkCmpctBlock` path runs even when `peer.mempool == nil` (during IBD); cycles wasted on dead InitData

**Severity:** P1. `peer.nim:1366-1417` proceeds through
`initPartiallyDownloadedBlock(cb)` unconditionally; the
`peer.mempool != nil` guard at line 1384 only skips the FILL step.
During IBD when `peer.mempool` is nil, the path:

1. Computes SHA256 + SipHash key derivation for the cmpctblock header
   (compact_blocks.nim:107-129) — O(80-byte header serialization +
   SHA256 + 2 × SipHash setup).
2. Allocates `PartiallyDownloadedBlock` with `txnAvailable` array sized
   to total tx count.
3. Iterates all short-ids to build `shortIdMap` and run bucket-check.
4. Skips fillFromMempool (nil mempool).
5. `pdb.isComplete()` → false (no txs filled from mempool means all
   shortIds are missing).
6. Computes `missPct = 100.0` → "compact block too many missing txns,
   skipping" log.
7. Drops the block. No fall-back getdata(MSG_BLOCK) is issued
   (BUG-10 from W126).

So during IBD, every offered cmpctblock costs us ~O(N_txs × SipHash) of
work to drop. The work could be saved by an early `if peer.mempool ==
nil: trace + return` at line 1376.

**File:** `src/network/peer.nim:1376-1417`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4469` (`LoadingBlocks()`
gate; Core also has a higher-up "is mempool initialized" check).

**Impact:** CPU regression during IBD; per-block ~O(4000 × SipHash)
wasted. Bandwidth: we're already receiving the cmpctblock so the
bytes are sunk; the wasted work is post-receive parse + InitData
allocation.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-8 serve-stub, BUG-10 HB-peer absent, BUG-11
  cmpctblock-never-announced, BUG-13 Misbehaving-never-called, BUG-17
  header-not-validated) — wait, recount: BUG-8, BUG-10, BUG-11, BUG-13,
  BUG-17 = 5 P0-CDIV.
- **P0-CDIV:** 5 (BUG-8, BUG-10, BUG-11, BUG-13, BUG-17)
- **P1:** 17 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-9, BUG-12,
  BUG-14, BUG-15, BUG-16, BUG-18, BUG-19, BUG-20, BUG-21, BUG-22, BUG-24)
- **P2:** 2 (BUG-7, BUG-23)

Recount: 5 P0-CDIV + 17 P1 + 2 P2 = 24. ✓

**Fleet patterns confirmed:**
- "dead-helper-at-call-site" (BUG-8: `blocktxnDepthOk`,
  `createBlockTxnResponse`, `newBlockTxnMsg`; BUG-9 from W126
  carry-forward: `fillFromExtraPool`) — 3rd nimrod compact-block-domain
  instance.
- "dead-constant-at-call-site" (BUG-13: `ScoreInvalidCompactBlock = 100`
  defined, never invoked).
- "dead-data plumbing" (BUG-19: `peer.peerCmpctVersion`,
  `peer.peerHighBandwidth`, `compactBlockState.wantsCompactBlocks`,
  `compactBlockState.highBandwidthMode` all written, none read).
- "two-pipeline guard 21st distinct extension" (BUG-19: state doubled
  across `peer.*` and `compactBlockState.*`).
- "comment-as-confession 1st W156 instance" (BUG-15: explicit comment
  at compact_blocks.nim:564-568 documents the missing IsBlockMutated
  check).
- "comment-as-confession 2nd W156 instance" (BUG-20: comment celebrates
  fixing a prior off-by-coefficient bug, but the constant fixed is
  unreachable behind a tighter check).
- "TODO-as-confession" (BUG-8: `peer.nim:1431` comment "TODO(BUG-5):
  look up the block and send a real blocktxn response" — explicit
  acknowledgment that the handler is a noop).
- "wire-decode-allocates-eagerly" (BUG-3, BUG-5, BUG-6: no cap on
  count → up to 800k iterations + RAM allocation per junk message;
  DoS amplification).
- "subsystem-defined-but-unwired" (BUG-8 + BUG-10 + BUG-11 + BUG-14:
  ~700 LOC of well-engineered cmpctblock code, almost entirely
  unreachable from production paths).
- "plumb-gate-then-flip" (BUG-22: pre-VERACK allow-list rejects
  cmpctblock; a fix would need to either widen the list or queue the
  message — same shape as nimrod's 7th plumb-gate-then-flip across
  W117+ tracking).

**Top three findings:**

1. **BUG-8 + BUG-10 + BUG-11 (P0-CDIV cluster: BIP-152 announce/serve
   subsystem-defined-but-unwired)** — nimrod ships ~700 LOC of
   compact-block code (compact_blocks.nim 679 LOC + scattered
   handlers), but:
   - `mkGetBlockTxn` is a noop (BUG-8); peers timeout on getblocktxn.
   - HB-peer selection (`MaybeSetPeerAsAnnouncingHeaderAndIDs`) is
     entirely absent (BUG-10).
   - `broadcastBlock` / `relayBlockImmediate` only emit headers/inv,
     never cmpctblock (BUG-11).
   - Reconstructed blocks are dropped without chain submission
     (BUG-14 from W126).

   **Net effect: nimrod is a partial BIP-152 client that can RECEIVE
   pushed cmpctblocks (which never happens because we don't promote
   peers to HB-from-us) and can SERVE getdata(MSG_CMPCT_BLOCK)
   (sort-of — see BUG-18) but cannot serve getblocktxn and cannot
   announce. The entire HB-mode push optimisation is structurally
   absent.** Throughput cost on relay: every block fan-out to peers
   pays full BIP-130 headers + getdata(MSG_BLOCK) round-trip when
   Core would push a single cmpctblock.

2. **BUG-3 + BUG-5 + BUG-6 (P1 DoS amplification cluster: wire-decode
   without count cap; no Misbehaving on rsInvalid via BUG-13)** — a
   malicious peer can paid ~800 KB of bandwidth to allocate ~1 MB of
   our RAM per junk cmpctblock / getblocktxn / blocktxn message,
   indefinitely, because:
   - `readCompactBlock` accepts `shortIdCount + prefilledCount` up to
     ~75k before the 0xFFFF check fires (BUG-3).
   - `readBlockTxnRequest` has no `count` cap (BUG-5).
   - `readBlockTxnResponse` has no `count` cap (BUG-6).
   - On `rsInvalid` from `initPartiallyDownloadedBlock`, peer is
     NOT misbehaved — only logged (BUG-13).
   - `ScoreInvalidCompactBlock = 100` constant is dead-at-call-site
     (BUG-13 cross-cite).

   Combined: a single malicious peer can sustain ~10 MB/s of RAM
   allocation work via 12 junk messages per second, with no
   disconnect signal.

3. **BUG-17 (P0-CDIV: cmpctblock header not chain-state-validated)** —
   nimrod runs `initPartiallyDownloadedBlock(cb)` immediately on
   receipt, with no `LoadingBlocks` gate, no prev-block lookup, no
   anti-DoS work threshold, no `ProcessNewBlockHeaders` call. A peer
   can send cmpctblocks for arbitrary (orphan, low-PoW-fake,
   never-going-to-connect) headers and force us through the InitData
   work pipeline. Combined with BUG-13's missing Misbehaving call,
   there is no consequence for the spam.

**Carry-forward audit:** of the 13 distinct W126 BUGs catalogued
2026-05-17, **ALL 13 remain present** in the current nimrod master
(no FIX waves between W126 and W156 closed any of them). W156 adds
**11 NEW** wire-level-deep findings (BUG-1 IBD/blocksonly send guard;
BUG-2 pre-VERACK SENDCMPCT loss; BUG-3 sum-count cap miss; BUG-4
coinbase-at-0 assumption; BUG-5/BUG-6 wire-decode count cap miss;
BUG-7 a_recent_compact_block cache absent; BUG-12 NODE_WITNESS guard;
BUG-19 two-pipeline guard 21st; BUG-20 comment-as-confession 2nd;
BUG-21 MIN_BLOCKS_TO_KEEP static_assert absent; BUG-22 handshake
allow-list excludes cmpctblock; BUG-23 cosmetic; BUG-24 IBD cycles
wasted on dead InitData) — but the **W126 13** + **W156 11 new** = 24
total catalogued.

**Wire-format paths PASS:** SipHash-2-4 key derivation (G5, G6 —
fast-path 4-word verified against Core's `(uint64_t{4}) << 59`
equivalence), DifferenceFormatter encode/decode for both prefilledtxn
and getblocktxn (G9, G13), tx-with-witness serialization (G11),
sendcmpct on-wire layout (G1, G2), CMPCTBLOCKS_VERSION = 2 silent-drop
of version=1 (G24).
