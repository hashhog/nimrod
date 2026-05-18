# W141 — ZMQ + REST + Notification scripts audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W141).
Concurrent-agent coordination: 3 OTHER audit waves in PARALLEL (streak
71 fix + 68 discovery preserved).

Target:
  - `src/rpc/zmq.nim`               (579 LOC) — ZMQ publisher (hashblock /
    hashtx / rawblock / rawtx / sequence) + FFI bindings + helpers.
    Defined but **NOT IMPORTED ANYWHERE** in nimrod (see G29 / BUG-22).
  - `src/rpc/rest.nim`              (1373 LOC) — HTTP/HTTPS REST listener,
    request parser, routing, per-endpoint handlers, BIP-78 POST PayJoin,
    BIP-157 cfilter/cfheader endpoints.
  - `src/nimrod.nim`                (CLI / wiring) — `--rest`, `--restport`,
    `--rpc-tls-cert`, `--rpc-tls-key`. No ZMQ CLI surface, no
    `-blocknotify` / `-walletnotify` / `-alertnotify`.

Reference (Bitcoin Core):
  - `src/zmq/zmqnotificationinterface.{h,cpp}` — top-level orchestrator
    (Create, Initialize, Shutdown, UpdatedBlockTip, BlockConnected /
    BlockDisconnected, TransactionAddedToMempool /
    TransactionRemovedFromMempool, GetActiveNotifiers).
  - `src/zmq/zmqpublishnotifier.{h,cpp}` — per-topic publisher
    (Initialize/Shutdown, SendZmqMessage 3-part [topic][body][seq],
    NotifyBlock / NotifyTransaction / NotifyBlockConnect /
    NotifyBlockDisconnect / NotifyTransactionAcceptance /
    NotifyTransactionRemoval, IsZMQAddressIPV6 → ZMQ_IPV6 socket option).
  - `src/zmq/zmqabstractnotifier.{h,cpp}` — base class, DEFAULT_ZMQ_SNDHWM.
  - `src/rest.cpp` + `src/rest.h` — full REST surface
    (/rest/tx, /rest/block, /rest/block/notxdetails, /rest/blockpart,
     /rest/blockfilter, /rest/blockfilterheaders, /rest/chaininfo,
     /rest/mempool/{info,contents}, /rest/headers, /rest/getutxos,
     /rest/deploymentinfo, /rest/blockhashbyheight, /rest/spenttxouts).
  - `src/init.cpp` — `-blocknotify` wiring (line 2009), `-rest` (line ?).
  - `src/node/kernel_notifications.cpp` — `-alertnotify` wiring
    (AlertNotify, line 30).
  - `src/wallet/wallet.cpp` — `-walletnotify` wiring (m_notify_tx_changed_script).
  - `src/common/system.cpp` — `runCommand` (the worker that ::system()s
    the user-provided shell command); `ShellEscape`.

BIPs: none (BIP-157 cfilter REST endpoints are covered structurally
by W121; this wave focuses on cross-cutting transport/notify surface).

W141 is the **first** wave to audit nimrod's ZMQ publisher and the
notification-script CLI surface end-to-end against Core, and to
re-sweep the REST endpoint set against Core's `uri_prefixes[]` table
in `src/rest.cpp:1141-1159`.

## Status

**BUGS FOUND — 26 distinct defects across 23 gates (MISSING / PARTIAL /
WRONG) of 30. 7 gates PRESENT (Core-aligned).**

Subsystem breakdown:

- **ZMQ publisher** (G1–G11): 6 BUGS — IPV6 socket option not set on
  TCP IPv6 addresses; module exists but is NEVER instantiated by the
  node (no import, no wiring in `nimrod.nim`); `getActiveNotifiers`
  returns tuple rather than const ref to notifier object; no
  per-notifier failure → erase semantics (Core's
  `TryForEachAndRemoveFailed`); IPC `unix://` → `ipc://` rewrite
  missing; UTF-8/ASCII body validation absent.
- **REST endpoint set** (G12–G22): 11 BUGS — 4 endpoints entirely
  missing (`/rest/chaininfo`, `/rest/deploymentinfo`,
  `/rest/blockpart`, `/rest/spenttxouts`); `getutxos` binary format
  drops CompactSize prefix on bitmap AND on the outs vector — wire
  format INCOMPATIBLE with Core; `mempool/info.json` returns
  `mempoolminfee` / `minrelaytxfee` 1000× too small (sat/vbyte ÷ 1e8
  instead of × 1000 / 1e8); `mempool/contents.json` synthesizes
  ancestor/descendant counts as `1` rather than walking the DAG, and
  emits sat-denominated `descendantfees` / `ancestorfees` against
  Core's BTC; block JSON missing `versionHex`, `mediantime`,
  `difficulty`, `chainwork`, `nTx` (legacy) — divergent shape;
  `headers/` route only accepts deprecated 2-segment form (no
  `?count=N` for new 1-segment); coinbase detection per-input rather
  than per-tx; `parseDataFormat` lowercases suffix while Core matches
  case-sensitively; query-string parsing in `blockfilterheaders/`
  reimplemented per-handler rather than shared.
- **REST listener** (G23–G27): 4 BUGS — bind hardcoded to 127.0.0.1
  with no `--restbind` / `--rpcallowip` analog; no warmup-check
  (`RPCIsInWarmup` / `CheckWarmup`) on any endpoint; HTTPS path
  swallows handshake errors at debug level but the listener's
  user-facing log only mentions "HTTPS" success — no error log on
  per-connection TLS handshake failure; `formatHttpResponse` always
  adds `Access-Control-Allow-Origin: *` (CORS wildcard) which Core's
  httpserver does NOT add by default (operator-toggle on Core).
- **Notification scripts** (G28–G30): 5 BUGS — `-blocknotify` not
  implemented; `-walletnotify` not implemented; `-alertnotify` not
  implemented; no equivalent of Core's `runCommand` (sandbox/shell
  wrapper) anywhere in `src/`; no `ShellEscape` helper means any
  future implementation MUST audit-vet shell-injection BEFORE landing
  (preventative finding — universal pattern).

Of the 26:

  - **3 P0-CDIV / P0-WIRE** — consensus-adjacent / wire-format
    divergence (BUG-7 `getutxos` bitmap+outs missing CompactSize
    prefix = wire-incompatible response that decoders will mis-parse;
    BUG-1 ZMQ_IPV6 socket option not set = bind-failure on dual-stack
    hosts for `tcp://[::1]:N` addresses; BUG-24 module not wired =
    notifications NEVER fire — silent operational gap).
  - **10 P1** — interop / shape (mempoolminfee 1000× too small;
    descendant/ancestor counts synthesized = misreporting;
    blockJSON missing versionHex/mediantime/difficulty/chainwork;
    headers route missing new 1-segment form; coinbase per-input
    check; CORS wildcard auto-added; warmup-check absent;
    REST bind hardcoded; getActiveNotifiers tuple return; BUG-26
    RPC plumbed but field always nil).
  - **8 P2** — endpoint absence (`/rest/chaininfo`,
    `/rest/deploymentinfo`, `/rest/blockpart`, `/rest/spenttxouts`,
    `/rest/headers` new form, `-blocknotify`, `-walletnotify`,
    `-alertnotify`).
  - **5 P3** — cosmetic / contract (UTF-8/ASCII body validation
    absent on ZMQ; `ipc://`-prefix `unix://` rewrite missing;
    `TryForEachAndRemoveFailed` semantic absent;
    `Access-Control-Allow-Origin` cosmetic divergence;
    `parseDataFormat` toLowerAscii vs Core case-match).

## Gates / matrix

Order: each gate covers a distinct slice of Core's transport contract.

| #   | Subsystem | Gate                                                                                 | Verdict           |
|-----|-----------|--------------------------------------------------------------------------------------|-------------------|
| G1  | ZMQ       | ZMQ_IPV6 socket option set based on IPv6 in `tcp://[::]:N`                           | **BUG-1**  (P0-WIRE) |
| G2  | ZMQ       | 3-part multipart wire `[topic][body][LE32 seq]`                                      | PRESENT           |
| G3  | ZMQ       | Per-notifier sequence number, increments only on success                             | PRESENT           |
| G4  | ZMQ       | Socket reuse across notifiers sharing an address                                     | PRESENT           |
| G5  | ZMQ       | `DEFAULT_ZMQ_SNDHWM = 1000`, ZMQ_SNDHWM set per-notifier                             | PRESENT           |
| G6  | ZMQ       | ZMQ_TCP_KEEPALIVE = 1                                                                | PRESENT           |
| G7  | ZMQ       | ZMQ_LINGER = 0 on shutdown                                                           | PRESENT           |
| G8  | ZMQ       | Hash byte order reversed for wire (display-BE → internal-LE)                         | PRESENT           |
| G9  | ZMQ       | sequence body shape: 32-byte hash + 1-byte label (+8-byte LE mempool seq for A/R)    | PRESENT           |
| G10 | ZMQ       | `unix://...` → `ipc://...` prefix rewrite (Core zmqnotificationinterface.cpp:62-64)  | **BUG-2**  (P3)   |
| G11 | ZMQ       | `TryForEachAndRemoveFailed` semantic (drop failed notifier rather than retry)        | **BUG-3**  (P3)   |
| G12 | REST      | `/rest/chaininfo` endpoint                                                           | **BUG-4**  (P2)   |
| G13 | REST      | `/rest/deploymentinfo[/<blockhash>]` endpoint                                        | **BUG-5**  (P2)   |
| G14 | REST      | `/rest/blockpart/<hash>?offset=&size=` endpoint                                      | **BUG-6**  (P2)   |
| G15 | REST      | `/rest/getutxos` binary format: `<active_height><active_hash><bitmap><outs>` with CompactSize | **BUG-7**  (P0-WIRE) |
| G16 | REST      | `/rest/mempool/info.json` `mempoolminfee` / `minrelaytxfee` BTC/kvB                  | **BUG-8**  (P1)   |
| G17 | REST      | `/rest/mempool/contents.json` `verbose=true/false` + `mempool_sequence=true/false`   | **BUG-9**  (P1)   |
| G18 | REST      | `/rest/mempool/contents.json` walked-DAG ancestor/descendant counts and fees-in-BTC  | **BUG-10** (P1) + **BUG-11** (P1) |
| G19 | REST      | `/rest/block/<hash>.json`: `versionHex`, `mediantime`, `difficulty`, `chainwork`     | **BUG-12** (P1)   |
| G20 | REST      | `/rest/headers/<hash>.<ext>?count=N` 1-segment + query-param form (Core 28+)         | **BUG-13** (P2)   |
| G21 | REST      | `/rest/spenttxouts/<blockhash>.<ext>` endpoint                                       | **BUG-14** (P2)   |
| G22 | REST      | `parseDataFormat` suffix case-sensitivity (Core: case-sensitive; nimrod: lowercases) | **BUG-15** (P3)   |
| G23 | REST      | Listener: bind respects `-rpcbind`/`-rpcallowip` (Core httpserver)                   | **BUG-16** (P1)   |
| G24 | REST      | `CheckWarmup` on every endpoint (Core rest.cpp:171)                                  | **BUG-17** (P1)   |
| G25 | REST      | `Access-Control-Allow-Origin: *` auto-added (Core: NOT auto-added)                   | **BUG-18** (P3)   |
| G26 | REST      | Coinbase tx detection per-tx (vin.size()==1 AND prevout.IsNull()), not per-input     | **BUG-19** (P1)   |
| G27 | REST      | Pruned-block / `BLOCK_HAVE_DATA` reporting on `/rest/block` (Core rest.cpp:418-423)  | **BUG-20** (P2)   |
| G28 | NOTIFY    | `-blocknotify=<cmd>` shell command on best-block change (Core init.cpp:2009-2019)    | **BUG-21** (P2)   |
| G29 | NOTIFY    | `-walletnotify=<cmd>` / `-alertnotify=<cmd>` shell command surface                   | **BUG-22** (P2) + **BUG-23** (P2) |
| G30 | NOTIFY    | ZMQ module wired into the node: `import ./rpc/zmq` + `notifyTip` call in connectTip  | **BUG-24** (P0-WIRE) + **BUG-25** (P1) + **BUG-26** (P3) |

## Bug detail

### BUG-1 (P0-WIRE) — ZMQ_IPV6 socket option not set
**Surface**: `src/rpc/zmq.nim:201-240` (`initialize` proc on
`ZmqNotifier`).

**Symptom**: A `tcp://[::1]:28332` address (IPv6) fails to bind on
systems where libzmq defaults to IPv4-only. Core inspects the address
via `IsZMQAddressIPV6` (zmqpublishnotifier.cpp:82-93) and sets
`ZMQ_IPV6 = 1` on the socket via `zmq_setsockopt` BEFORE calling
`zmq_bind`. Nimrod declares the `ZMQ_IPV6 = 42.cint` constant but
**never calls `zmq_setsockopt(ZMQ_IPV6, ...)`** — `initialize()` sets
only `ZMQ_SNDHWM` and `ZMQ_TCP_KEEPALIVE` before binding.

**Wire impact**: TCP/IPv6 publisher fails to start (silent on
OpenBSD per Core's own comment) or binds to wrong stack.

**Fix sketch**: Add a `proc isZmqAddressIpv6(address: string): bool`
mirroring Core, then before `zmq_bind` add:

```nim
var ipv6Enable: cint = (if isZmqAddressIpv6(notifier.address): 1 else: 0)
if zmq_setsockopt(notifier.socket, ZMQ_IPV6, addr ipv6Enable,
                  csize_t(sizeof(cint))) != 0:
  error "ZMQ: failed to set ZMQ_IPV6"
  discard zmq_close(notifier.socket)
  return false
```

### BUG-2 (P3) — `unix://` → `ipc://` prefix rewrite missing
**Surface**: `src/rpc/zmq.nim` (no rewrite); Core
`zmqnotificationinterface.cpp:62-64`.

**Symptom**: Core accepts `-zmqpubhashblock=unix:///tmp/x.sock` and
silently rewrites the `unix://` prefix to `ipc://` (libzmq's spelling).
Nimrod passes the literal string straight through to `zmq_bind`, which
will fail to recognise `unix://`. Operators following Core docs (or
Bitcoin wiki) hit "failed to bind" with a misleading address.

**Fix sketch**: At config parse time (when nimrod adds CLI surface),
strip-and-replace the `unix://` prefix before storing the address.

### BUG-3 (P3) — `TryForEachAndRemoveFailed` semantic absent
**Surface**: `src/rpc/zmq.nim:397-579` (`notifyBlock`,
`notifyRawBlock`, `notifyTransaction`, etc.); Core
`zmqnotificationinterface.cpp:133-149`.

**Symptom**: When a single notifier fails (e.g. socket closed by
subscriber, downstream is unreachable), Core's
`TryForEachAndRemoveFailed` **erases** that notifier from the live
list so subsequent calls don't repeatedly attempt the dead socket.
Nimrod's per-call loop only `warn`s on failure and leaves the dead
notifier in `zmq.notifiers`. Subsequent block / tx events log a
warning every time.

**Fix sketch**: Track failure-count or follow Core's
"remove-on-false-return" pattern; gate behind a `--zmqstrict` flag if
operators want hard-fail vs soft-degrade.

### BUG-4 (P2) — `/rest/chaininfo` endpoint missing
**Surface**: `src/rpc/rest.nim:1105-1147` (`handleRestRequest` route
table); Core `rest.cpp:716-738` (`rest_chaininfo`) +
`rest.cpp:1151` (`uri_prefixes[] {"/rest/chaininfo", ...}`).

**Symptom**: `curl 127.0.0.1:48346/rest/chaininfo.json` returns 404.
Light-client tooling and `bitcoin-cli`-replacement scripts that
expect this endpoint break.

**Fix sketch**: Add `if cleanPath.startsWith("chaininfo"): return
rest.handleRestChainInfo(cleanPath[9 .. ^1])`, implement
`handleRestChainInfo` to return the same shape as nimrod's RPC
`getblockchaininfo`.

### BUG-5 (P2) — `/rest/deploymentinfo` endpoint missing
**Surface**: `src/rpc/rest.nim:1105-1147`; Core `rest.cpp:743-780`.

**Symptom**: BIP-9 / BIP-341 deployment progress unobservable via REST.
Forces operators to fall back to JSON-RPC `getdeploymentinfo`.

### BUG-6 (P2) — `/rest/blockpart` endpoint missing
**Surface**: `src/rpc/rest.nim:1105-1147`; Core
`rest.cpp:481-498` (`rest_block_part`).

**Symptom**: Cannot request a byte-range of a block over REST.
Bandwidth-constrained clients that pull only the witness portion or
the tail of a block (e.g. for cfilter audit) cannot do so without
fetching the whole block via `/rest/block/<hash>.bin`.

### BUG-7 (P0-WIRE) — `/rest/getutxos` binary format drops CompactSize on bitmap and outs
**Surface**: `src/rpc/rest.nim:686-747` (`handleRestGetUtxos` binary
and hex branches); Core `rest.cpp:1038-1054`.

**Symptom**: Core's binary response is
`DataStream << active_height << active_hash << bitmap << outs;` where
`bitmap` is `std::vector<unsigned char>` (CompactSize-prefixed) and
`outs` is `std::vector<CCoin>` (CompactSize-prefixed). Each `CCoin`
serializes as `<nTxVerDummy:4><nHeight:4><CTxOut>`, where CTxOut is
`<value:8><scriptPubKey:CompactSize+bytes>`.

Nimrod writes:
1. `chainHeight` (4 bytes LE) — OK.
2. `chainTipHash` (32 bytes) — OK.
3. `bitmap` bytes — **NO CompactSize prefix** (BUG).
4. UTXO entries inline — **NO CompactSize count prefix** (BUG).

A `bitcoinlib` / `python-bitcoinlib` decoder that calls
`vector::Unserialize` will read the first byte of the bitmap as the
CompactSize length of the bitmap vector. If the operator is requesting
2 UTXOs (bitmap is 1 byte), the first bitmap byte happens to be small
(e.g. `0x03`) and the next 3 bytes get consumed as bitmap. The decoder
then fails or silently mis-aligns.

This is **wire-incompatible** with Core BIP-64.

**Fix sketch**:

```nim
# bitmap
let bmLen = bitmap.len
if bmLen < 0xFD: data.add(byte(bmLen))
else: data.add(byte(0xFD)); data.add(byte(bmLen and 0xff))
                            data.add(byte((bmLen shr 8) and 0xff))
data.add(bitmap)
# outs vector count
let outsCount = utxos.len
if outsCount < 0xFD: data.add(byte(outsCount))
else: data.add(byte(0xFD)); data.add(byte(outsCount and 0xff))
                            data.add(byte((outsCount shr 8) and 0xff))
# then each CCoin entry as today
```

### BUG-8 (P1) — `mempoolminfee` / `minrelaytxfee` 1000× too small
**Surface**: `src/rpc/rest.nim:771-782` (`handleRestMempoolInfo`).

**Symptom**: Code reads `let minFee = rest.mempool.minFeeRate /
100000000.0` and reports as both `mempoolminfee` and `minrelaytxfee`.

`mempool.minFeeRate` is **sat/vbyte** (per
`src/mempool/mempool.nim:69` comment). Core's field is BTC/kvB
(per `rest.cpp` via `MempoolInfoToJSON` → `GetFeePerK().GetFeePerK()`).

Correct conversion: `sat/vB × 1000 = sat/kvB; sat/kvB / 1e8 = BTC/kvB`,
i.e. divide sat/vB by 1e5, NOT by 1e8.

A 1 sat/vB minrelay reported as `0.00000001` BTC/kvB instead of the
correct `0.00001` — 1000× smaller. Wallet fee bumpers reading this
endpoint would attempt to send transactions below relay floor, which
the node then rejects.

**Fix sketch**:

```nim
let minFeeBtcPerKvb = rest.mempool.minFeeRate / 100000.0  # sat/vB → BTC/kvB
```

Note: comment in source says `# sat/vbyte to BTC/kB` which is itself
misleading — Bitcoin Core uses BTC/kvB (kilo-virtual-byte), and the
factor 1e8 maps to /vbyte not /kvB. The comment is an audit-finding
of its own.

### BUG-9 (P1) — `mempool/contents.json` ignores `verbose` and `mempool_sequence`
**Surface**: `src/rpc/rest.nim:784-802` (`handleRestMempoolContents`);
Core `rest.cpp:799-823`.

**Symptom**: Core requires `?verbose=true|false` and
`?mempool_sequence=true|false` query params and **errors** with 400
on any other string. It also rejects `verbose=true` combined with
`mempool_sequence=true` (line 820-822). Nimrod ignores both, always
emits the verbose object form. Tooling that requests `verbose=false`
expecting a flat txid array (Core's terse form) gets a verbose object.

### BUG-10 (P1) — synthesized ancestor/descendant counts (always 1)
**Surface**: `src/rpc/rest.nim:795-801`.

**Symptom**: Every entry reports `descendantcount: 1, ancestorcount: 1,
descendantsize: <self>, ancestorsize: <self>`. Real ancestor /
descendant cluster shape (Core walks `CTxMemPoolEntry::GetAncestors()`
/ `GetDescendants()` via the mempool DAG) is not computed.

Wallet fee bumpers and BIP-125 RBF clients that read this endpoint to
estimate package size cannot — they see flat singletons.

### BUG-11 (P1) — `descendantfees` / `ancestorfees` in sat not BTC
**Surface**: `src/rpc/rest.nim:797, 800`.

**Symptom**: Nimrod emits `descendantfees: int64(entry.fee)` (sat)
where Core emits BTC (`fees.base`, `fees.modified`, `fees.ancestor`,
`fees.descendant` are all `ValueFromAmount` = BTC float). A consumer
that expects BTC sees fees 1e8× too large, treats every tx as a fee
giant.

### BUG-12 (P1) — `/rest/block/<hash>.json` missing fields
**Surface**: `src/rpc/rest.nim:356-381` (block JSON build); Core
`src/rpc/blockchain.cpp:154-205` (`blockheaderToJSON` + `blockToJSON`).

**Symptom**: Missing: `versionHex` (4-byte hex form of nVersion),
`mediantime` (GetMedianTimePast), `difficulty` (GetDifficulty),
`chainwork` (hex), `nTx` is present but at outer-block level only,
`strippedsize`, `weight` (block), `size` (block). Some are minor; the
critical absences are `versionHex`, `mediantime` (BIP-113 anchor),
`chainwork` (light-client validation anchor), and `difficulty`.

### BUG-13 (P2) — `/rest/headers/` only supports deprecated 2-segment form
**Surface**: `src/rpc/rest.nim:394-482` (`handleRestHeaders`); Core
`rest.cpp:179-274`.

**Symptom**: Core 28+ supports
`/rest/headers/<hash>.<ext>?count=N` (1-segment + query param).
Nimrod only supports `/rest/headers/<count>/<hash>.<ext>` (2-segment).
Clients written against the newer form 400 on nimrod.

### BUG-14 (P2) — `/rest/spenttxouts/<blockhash>` endpoint missing
**Surface**: `src/rpc/rest.nim:1105-1147`; Core
`rest.cpp:313-381` (`rest_spent_txouts`).

**Symptom**: Per-block spent-prevout enumeration unavailable.
Block-explorer / mempool-archive tooling that uses this to
reconstruct prevout values cannot.

### BUG-15 (P3) — `parseDataFormat` lowercases suffix (Core is case-sensitive)
**Surface**: `src/rpc/rest.nim:205-222`.

**Symptom**: Nimrod accepts `.JSON`, `.Hex`, `.BIN` and treats them as
the lowercase equivalents (line 215 `toLowerAscii`). Core compares the
suffix byte-for-byte against `{"bin", "hex", "json"}` — case-mismatches
return UNDEF → 404. Cosmetic divergence; clients written to Core's
strictness will accept nimrod's response but the reverse
(client-written-for-nimrod) breaks against Core.

### BUG-16 (P1) — REST listener bind hardcoded
**Surface**: `src/rpc/rest.nim:1352` (`initTAddress("127.0.0.1",
Port(rest.port))`).

**Symptom**: Cannot bind on `0.0.0.0` (LAN exposure) or specific
interface. Operators wanting a private LAN REST endpoint cannot.
Core uses `-rpcbind=<addr>` (multi-valued) and `-rpcallowip=<subnet>`
to govern this. Nimrod has neither.

### BUG-17 (P1) — no warmup-check on REST endpoints
**Surface**: every `handleRest*` proc in `src/rpc/rest.nim`; Core
`rest.cpp:171-177` (`CheckWarmup`).

**Symptom**: Core returns `HTTP_SERVICE_UNAVAILABLE` (503) with
"Service temporarily unavailable: <message>" during init/loading
phase. Nimrod silently serves partial data from an uninitialised
chainstate / mempool. Clients that race the node startup see
malformed responses.

### BUG-18 (P3) — `Access-Control-Allow-Origin: *` always set
**Surface**: `src/rpc/rest.nim:1153-1158` (`formatHttpResponse`).

**Symptom**: Nimrod hardcodes the CORS wildcard. Core's httpserver
does NOT emit CORS headers by default (operators must use a reverse
proxy for browser-side CORS). Cosmetic divergence with security
implications — browser-side scripts CAN cross-origin call nimrod's
REST, can NOT cross-origin call Core's.

### BUG-19 (P1) — coinbase detection per-input not per-tx
**Surface**: `src/rpc/rest.nim:321-325`.

**Symptom**: Loop iterates inputs and marks each NULL-prevout input
as `coinbase`. A standard coinbase has exactly 1 input + that input's
prevout is null. Core's `IsCoinBase()` (primitives/transaction.h)
requires both. Nimrod's loop misclassifies any tx whose first input
happens to be NULL-prevout (consensus-invalid txes, but a
defense-in-depth bug — and the format consumers downstream might
interpret a 2-input tx with one coinbase-like input as part-coinbase,
which Core never emits).

### BUG-20 (P2) — pruned-block reporting absent
**Surface**: `src/rpc/rest.nim:283-287`; Core `rest.cpp:418-423`.

**Symptom**: Core checks `pblockindex->nStatus & BLOCK_HAVE_DATA`,
and on miss distinguishes "pruned" vs "not fully downloaded".
Nimrod just returns 404 "not found" indiscriminately.

### BUG-21 (P2) — `-blocknotify=<cmd>` not implemented
**Surface**: no `src/nimrod.nim` CLI surface; Core
`init.cpp:2009-2019`.

**Symptom**: External notification scripts (a common ops tool;
e.g. spend-track, real-time push to webhook) cannot be wired.

**Universal pattern (preventative)**: Core's implementation
`std::thread t(runCommand, command); t.detach();` runs the user
command via `::system()` after a single `ReplaceAll(command, "%s",
block.GetBlockHash().GetHex())`. Block hashes are hex-only ASCII so
no escaping is strictly needed BUT if nimrod ever implements this,
the implementation MUST:
  1. Use `osproc.execProcess` / `startProcess` with an arg-list, NOT
     `osproc.execCmd` or `os.execShellCmd` — shell-injection vector.
  2. If a shell IS used (operator convenience), require explicit
     opt-in (`--blocknotify-shell`).
  3. Treat the substitution token (`%s`) as the ENTIRE block-hash
     argument; reject any `%s` literal in the substituted value
     (defense-in-depth against quine-style injection — block hash is
     hex so safe, but the pattern is universal).

### BUG-22 (P2) — `-walletnotify=<cmd>` not implemented
Same pattern as BUG-21, in the wallet path. Core source:
`wallet/wallet.cpp:1162`.

### BUG-23 (P2) — `-alertnotify=<cmd>` not implemented
Same pattern as BUG-21, kernel-side. Core source:
`node/kernel_notifications.cpp:30-46`. Note Core's AlertNotify uses
`SanitizeString` AND wraps in single quotes BEFORE shell-substituting
— a real shell-injection hardening. Any nimrod implementation MUST
mirror this (it's the universal shell-injection pattern).

### BUG-24 (P0-WIRE) — ZMQ module never instantiated by node
**Surface**: `src/nimrod.nim` (entire file) — no `import ./rpc/zmq`,
no `ZmqNotificationInterface` field on `NodeState`, no call to
`initialize` / `shutdown`, no `notifyTip` / `notifyBlockConnected` /
`notifyMempoolAccept` hooks in connect/disconnect tip code paths or
mempool-accept code paths.

**Symptom**: A complete ZMQ implementation (`src/rpc/zmq.nim`, 579
LOC) lives in the source tree and is **fully unused at runtime**.
Tests import it (tests/test_zmq.nim, tests/test_notification.nim)
but production never does. Operators who set `-zmqpubhashblock=...`
on the command line see no notifications because (a) the CLI doesn't
recognise the flag and (b) even if it did, no event hook fires
`notifyBlock`.

This is the universal **"plumb-gate-then-flip cross-wave activation"**
pattern from FIX-81 / FIX-82 (per recent memory entries) — a module
plumbed but never wired. Closing this requires:
  1. Add `--zmqpubhashblock=ADDR`, `--zmqpubhashtx=ADDR`,
     `--zmqpubrawblock=ADDR`, `--zmqpubrawtx=ADDR`,
     `--zmqpubsequence=ADDR` plus `*hwm` variants to `nimrod.nim`.
  2. Add `ZmqNotificationInterface` field on `NodeState`.
  3. Initialise on startup, after chainstate is ready, before P2P.
  4. Call `notifyTip(blockHash, isIBD)` at every connect-tip site
     (search for `bestHeight = newHeight` / `tip = newTip`).
  5. Call `notifyMempoolAccept(tx, mempoolSeq)` at every accept-to-
     mempool call site.
  6. Call `notifyBlockDisconnected(blk, hash)` at every disconnect.
  7. Shutdown on graceful exit.

### BUG-25 (P1) — `getActiveNotifiers` returns tuple, not const-ref to notifier
**Surface**: `src/rpc/zmq.nim:382-391`; Core
`zmqnotificationinterface.cpp:35-42`.

**Symptom**: Cosmetic API difference; once BUG-24 is closed and a
`getzmqnotifications` RPC is added, the RPC handler must build the
same JSON shape Core emits (array of `{type, address, hwm}`). Current
tuple form is fine for the shape, but Core's
`std::list<const CZMQAbstractNotifier*>` exposes the notifier object
itself; tooling that wants per-notifier state (last-sequence,
last-error) cannot reach it.

### BUG-26 (P1) — `getzmqnotifications` RPC plumbed but `rpc.zmq` field never assigned
**Surface**: `src/rpc/server.nim:51` (`zmq*: ZmqNotificationInterface`
field declared), `:3338-3351` (`handleGetZmqNotifications` returns
JSON array), `:8329-8330` (dispatch). `:105-130` (`newRpcServer`
constructor — no `zmq:` parameter, no field assignment).

**Symptom**: An RPC client calling `getzmqnotifications` always
gets back `[]` — empty array — because `rpc.zmq` is always `nil` at
runtime. This is the SAME "plumb-gate-then-flip" cross-wave pattern
as the recent compact-filter activation chain
(FIX-71→FIX-81/FIX-82). The handler is wired but the data source is
not.

**Fix sketch (paired with BUG-24)**:
  1. Add `zmq: ZmqNotificationInterface = nil` parameter to
     `newRpcServer`.
  2. In `nimrod.nim` startup, construct the `ZmqNotificationInterface`
     from CLI flags, initialise it, and pass it to `newRpcServer`.
  3. The RPC handler then reflects the live notifiers automatically
     (no change needed at the handler).

**Audit framing correction**: The original draft mis-framed this as
"RPC absent" — actually the RPC IS plumbed. The real gap is the
field-population gap, identical in shape to BUG-24. This is a
**meta-pattern observation**: this audit found TWO plumb-gate-then-
flip-style activation chains (BUG-24: module exists, no wiring;
BUG-26: handler exists, field never assigned). Both close together
in a future fix wave.

## Universal patterns surfaced

This wave brings **TWO** universal patterns to the project audit
ledger:

1. **Shell-injection vector class** (BUG-21 / 22 / 23). Any
   notification-script implementation in any of the 10 impls MUST
   use an arg-list / `startProcess` form, NOT a shell-string form,
   unless the operator opts in via an explicit flag. The Bitcoin
   Core `-alertnotify` (kernel_notifications.cpp:30-46) and
   `-walletnotify` (wallet/wallet.cpp:1162) and `-blocknotify`
   (init.cpp:2009-2019) all use `::system()` with prior
   SanitizeString + single-quote wrapping. Hex-only block-hash
   substitution is safe, but `-walletnotify` substitutes `%w`
   (wallet name) and arbitrary wallet names are operator-supplied
   strings — these MUST be shell-escaped. **Universal advisory**:
   each impl that adds notification-script support gets a dedicated
   audit gate for shell-injection vetting.

2. **"Module exists but is not wired at runtime"** (BUG-24).
   nimrod's `src/rpc/zmq.nim` joins the previously-documented
   cross-wave activation gap pattern (FIX-71 plumb-gate-FALSE →
   FIX-81 / FIX-82 wire-and-flip). This audit identifies the gap;
   a future fix wave closes it.

## Test plan

`tests/test_w141_zmq_rest_notify.nim` pins each gate. Methodology
(per W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
W134 / W135 / W136 / W137 audits):

- Each test asserts the CURRENT (buggy or absent) behaviour with a
  `check` that locks the gap.
- When a future FIX wave closes the gap, the test fails loudly and
  the developer must flip the assertion.
- No production code is changed in W141.

The test file is self-contained and source-pinned where ZMQ/REST/
notify behaviour is too FFI-or-network heavy to exercise directly.
30 gates, ~50 `check` assertions.

## Out of scope (for W141)

- Implementing BUG-24 (full ZMQ wire-up) — separate fix wave,
  multi-site touchpoint, requires CLI flag, NodeState field, and
  hooks in chain.connectTip / mempool.accept / mempool.remove.
- Implementing BUG-21 / 22 / 23 (notification-script support) —
  separate fix wave, requires CLI flag, run-as-detached-thread
  primitive, and shell-injection vetting.
- Implementing BUG-7 (getutxos wire-format) — straightforward, but
  a single-impl fix wave to keep the scope clean and to allow a
  cross-impl wire-format audit to follow.
- Implementing BUG-4 / 5 / 6 / 14 (missing REST endpoints) — fan-out
  effort; better as a dedicated REST-completeness wave.
- HTTPS / TLS handshake hardening — covered by FIX-64 / W119.

## Concurrent-agent coordination

3 OTHER audit waves in PARALLEL with W141 (per the launch brief).
This audit touches:
- `src/rpc/zmq.nim` — read-only (no other wave should be writing).
- `src/rpc/rest.nim` — read-only.
- `src/nimrod.nim` — read-only.
- `audit/w141_zmq_rest_notify.md` — NEW (this file).
- `tests/test_w141_zmq_rest_notify.nim` — NEW.

No cross-wave file overlap expected.
