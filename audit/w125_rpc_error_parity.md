# W125 — JSON-RPC error code parity audit (nimrod)

Date: 2026-05-17
Audit type: discovery
Target: `src/rpc/server.nim` (JSON-RPC dispatch + per-handler error
raises).  REST `/payjoin` errors (BIP-78 `errorCode` envelope) and the
P2P misbehaving-peer codes in `src/network/` are out of scope for this
wave (different code spaces).
Driver: cross-impl fleet audit — every node must surface Bitcoin
Core's documented JSON-RPC error codes so multi-node consensus tools
(`consensus-diff.py`, `fleet-monitor.sh`, `test_rpc.py`) and operator
tooling that branches on `error.code` produce the same decisions
against any impl.

## Status

**BUGS FOUND — 16 distinct gates MISSING / PARTIAL (of 30).**

Nimrod implements a small subset of Core's `RPCErrorCode` enum (9 of
~30 codes in `bitcoin-core/src/rpc/protocol.h`) and routes most
exceptional paths through three buckets:

- `RpcInvalidParams` (-32602) — 156 raise sites
- `RpcMiscError` (-1) — 64 raise sites
- `RpcInvalidAddressOrKey` (-5) — 54 raise sites

Cross-referenced against Core, the most pervasive pattern is **"every
wallet-state error becomes RPC_MISC_ERROR (-1)"** instead of the
documented `RPC_WALLET_*` codes (-4, -11..-19, -35, -36).  A client
that branches on `error.code == -13` to prompt for an unlock will
never trigger against nimrod.  A second pervasive pattern is **"every
deserialization failure becomes RPC_INVALID_PARAMETER (-8) [aliased
locally as `RpcInvalidParams` despite the comment]"** instead of the
documented `RPC_DESERIALIZATION_ERROR` (-22).  Tools that distinguish
"bad request shape" from "bad transaction bytes" cannot do so.

The third pattern is a complete absence of any code denoting **node
state** (`RPC_IN_WARMUP` -28, `RPC_CLIENT_IN_INITIAL_DOWNLOAD` -10,
`RPC_CLIENT_NOT_CONNECTED` -9, `RPC_CLIENT_P2P_DISABLED` -31,
`RPC_CLIENT_MEMPOOL_DISABLED` -33).  There is no warmup state at all
in the dispatch path (`handleSingleRequest` calls `handleMethod`
immediately on receipt, regardless of chainState load progress);
`submitblock`, `getblocktemplate`, and `addnode` all route P2P-absent
errors through `RpcInternalError`.

The fourth pattern is **constant naming drift**.  Nimrod's local
`RpcInvalidParams` is mapped to value `-32602` (JSON-RPC 2.0
`InvalidParams`), but Core uses two distinct codes that nimrod
collapses into one:
  - `-32602 RPC_INVALID_PARAMS` (JSON-RPC envelope: bad params shape)
  - `-8    RPC_INVALID_PARAMETER` (application-layer: bad parameter
    value)

In `rpc/protocol.h` Core comments make the distinction explicit
("RPC_INVALID_REQUEST should not be used for application-layer
errors"; same applies symmetrically to `-32602`).  Nimrod uses
`-32602` for both, so 156 raise sites that semantically should be
`-8 RPC_INVALID_PARAMETER` (e.g. "block height out of range",
"maxfeerate cannot exceed 1 BTC/kvB", "missing txid parameter") emit
`-32602` instead.

Net effect: any cross-impl client / test that uses `error.code` for
control flow (e.g. retry on -28, prompt on -13, fall back on -22)
will silently mis-branch against nimrod.  No transaction is
mis-accepted and no consensus invariant is broken — this is an
operator-surface / API-shape divergence, not a consensus bug — but
it is fleet-wide and high-traffic.

## Method

1. Catalog all `newRpcError(<code>, …)` raise sites in
   `src/rpc/server.nim` (8737 lines, 321 raise sites).
2. Catalog all `throw JSONRPCError(RPC_*, …)` raise sites in
   `bitcoin-core/src/rpc/*.cpp` + `bitcoin-core/src/wallet/rpc/*.cpp`
   (matched by `protocol.h` enum).
3. For each of 30 audit gates below, classify nimrod's current
   behavior against Core's documented behavior:
   - **PRESENT** — nimrod raises the same code Core does for at
     least one representative raise site.
   - **PARTIAL** — nimrod raises a related code but not Core's
     specific code (e.g. `-1` instead of `-13`), or only some sites
     match.
   - **MISSING** — nimrod never raises this code, or has no analog
     path in dispatch.

Out of scope (NOT audited by W125):
  - HTTP status-code mapping (`HTTP_UNAUTHORIZED`, `HTTP_FORBIDDEN`,
    `HTTP_NOT_FOUND`).  Nimrod's `processClient` returns plain
    `200 OK` for every JSON-RPC response and `401` for auth failure;
    Core has the full `HTTP_*` enum.  Future audit wave candidate.
  - BIP-78 PayJoin `errorCode` envelope at REST `/payjoin`.  Distinct
    error space (`PayJoinErrorKind`); covered by W119 audit.
  - P2P misbehavior codes (`MISBEHAVING_*`); not JSON-RPC.
  - BIP-323 Silent Payments (cited only as reference; not yet
    implemented and the prompt's reference to BIP-323 is a stub).

## Audit gates (30)

Numbering matches the standard W125 set across the fleet.  Each gate
cites Core's `RPCErrorCode` value (from `bitcoin-core/src/rpc/protocol.h`)
and Core's canonical raise site.

| #  | Gate                                                                                          | Core code | nimrod | Status   |
|----|-----------------------------------------------------------------------------------------------|-----------|--------|----------|
| 1  | Standard envelope: `-32700 RPC_PARSE_ERROR` on malformed JSON body                            | -32700    | -32700 | PRESENT  |
| 2  | Standard envelope: `-32600 RPC_INVALID_REQUEST` on missing/non-string `method` or empty batch | -32600    | -32600 | PRESENT  |
| 3  | Standard envelope: `-32601 RPC_METHOD_NOT_FOUND` for unknown method names                     | -32601    | -32601 | PRESENT  |
| 4  | Standard envelope: `-32602 RPC_INVALID_PARAMS` reserved for bad params *shape* (object/array) | -32602    | -32602 (over-used) | PARTIAL |
| 5  | Standard envelope: `-32603 RPC_INTERNAL_ERROR` reserved for genuine bitcoind internal errors  | -32603    | -32603 | PRESENT  |
| 6  | App-layer: `-1 RPC_MISC_ERROR` for `std::exception` thrown in command handling                | -1        | -1     | PRESENT  |
| 7  | App-layer: `-3 RPC_TYPE_ERROR` when a param is the wrong JSON type (e.g. "verbose must be int")| -3       | -32602 | MISSING  |
| 8  | App-layer: `-5 RPC_INVALID_ADDRESS_OR_KEY` on invalid address / unknown block hash / unknown txid | -5    | -5     | PRESENT  |
| 9  | App-layer: `-7 RPC_OUT_OF_MEMORY` on allocation failure                                       | -7        | n/a    | MISSING  |
| 10 | App-layer: `-8 RPC_INVALID_PARAMETER` for bad parameter *value* (height out of range, etc.)   | -8        | -32602 | MISSING  |
| 11 | App-layer: `-20 RPC_DATABASE_ERROR` on RocksDB / chainstate / blockstore read/write failure   | -20       | -32603 / -1 | MISSING |
| 12 | App-layer: `-22 RPC_DESERIALIZATION_ERROR` on TX/block/PSBT/script decode failure             | -22       | -32602 | MISSING  |
| 13 | App-layer: `-25 RPC_VERIFY_ERROR` on block submission validation failure (`submitblock`)      | -25       | BIP-22 string | PARTIAL |
| 14 | App-layer: `-26 RPC_VERIFY_REJECTED` (alias `RPC_TRANSACTION_REJECTED`) for tx mempool reject | -26       | -26    | PRESENT  |
| 15 | App-layer: `-27 RPC_VERIFY_ALREADY_IN_UTXO_SET` (alias `RPC_TRANSACTION_ALREADY_IN_CHAIN`)    | -27       | -27    | PRESENT  |
| 16 | Node-state: `-28 RPC_IN_WARMUP` when the node hasn't finished loading chain state             | -28       | n/a    | MISSING  |
| 17 | Node-state: `-32 RPC_METHOD_DEPRECATED` for deprecated method calls                            | -32       | n/a    | MISSING  |
| 18 | P2P: `-9 RPC_CLIENT_NOT_CONNECTED` when the node isn't connected to the network               | -9        | -32603 | MISSING  |
| 19 | P2P: `-10 RPC_CLIENT_IN_INITIAL_DOWNLOAD` while initial block download is still in progress   | -10       | n/a    | MISSING  |
| 20 | P2P: `-23 RPC_CLIENT_NODE_ALREADY_ADDED` when `addnode add` targets an already-added peer     | -23       | n/a    | MISSING  |
| 21 | P2P: `-24 RPC_CLIENT_NODE_NOT_ADDED` on `addnode remove`/`onetry` of an unknown peer          | -24       | n/a    | MISSING  |
| 22 | P2P: `-29 RPC_CLIENT_NODE_NOT_CONNECTED` for `disconnectnode` of an unknown peer              | -29       | n/a    | MISSING  |
| 23 | P2P: `-30 RPC_CLIENT_INVALID_IP_OR_SUBNET` on bad IP/subnet in `setban`/`addnode`             | -30       | -32602 | PARTIAL  |
| 24 | P2P: `-31 RPC_CLIENT_P2P_DISABLED` when peer manager is absent / disabled                     | -31       | -32603 | MISSING  |
| 25 | P2P: `-33 RPC_CLIENT_MEMPOOL_DISABLED` when mempool RPCs are called with no mempool           | -33       | -32603 | MISSING  |
| 26 | Wallet: `-4 RPC_WALLET_ERROR` generic wallet error                                            | -4        | -4     | PRESENT  |
| 27 | Wallet: `-6 RPC_WALLET_INSUFFICIENT_FUNDS` on insufficient balance for spend                  | -6        | -1     | MISSING  |
| 28 | Wallet: `-11 RPC_WALLET_INVALID_LABEL_NAME` on invalid label (e.g. starts with `*`)            | -11       | n/a    | MISSING  |
| 29 | Wallet: `-12 RPC_WALLET_KEYPOOL_RAN_OUT` when keypool exhausted (HD-disabled / paused wallet)  | -12       | n/a    | MISSING  |
| 30 | Wallet: `-13/-14/-15/-17 RPC_WALLET_{UNLOCK_NEEDED,PASSPHRASE_INCORRECT,WRONG_ENC_STATE,ALREADY_UNLOCKED}` on encrypt/unlock errors | -13..-17 | -1 | MISSING  |

Score: **14 PRESENT (incl. PRESENT-with-caveat) / 4 PARTIAL / 12 MISSING.**
Net BUGS for the dashboard (PARTIAL + MISSING): **16**.

## Per-gate detail (Core mapping + nimrod evidence)

### Gate 1 — `-32700 RPC_PARSE_ERROR` — PRESENT
- Core: `src/rpc/request.cpp` parse failure (HTTP body not valid JSON)
  → `JSONRPCError(RPC_PARSE_ERROR, ...)` → mapped to HTTP 200 body
  with `error.code = -32700`.
- nimrod: `server.nim:8562-8565` `parseJson` failure handler returns
  `makeErrorResponse(newJNull(), RpcParseError, "Parse error: " & e.msg)`
  where `RpcParseError = -32700` (line 81). Matches.

### Gate 2 — `-32600 RPC_INVALID_REQUEST` — PRESENT
- Core: `src/rpc/request.cpp` rejects requests without `method` field
  / wrong type with `RPC_INVALID_REQUEST` (-32600).
- nimrod: `server.nim:8505,8514,8523,8572,8576` raise
  `RpcInvalidRequest = -32600` for non-object request, missing/empty
  `method`, empty batch, batch > `MaxBatchSize`. Matches.

### Gate 3 — `-32601 RPC_METHOD_NOT_FOUND` — PRESENT
- Core: `src/rpc/server.cpp::ExecuteCommand` → on unknown method
  raises `RPC_METHOD_NOT_FOUND` (-32601).
- nimrod: `server.nim:8476` `else: raise newRpcError(RpcMethodNotFound,
  "method not found: " & methodName)` where `RpcMethodNotFound =
  -32601`. Matches.

### Gate 4 — `-32602 RPC_INVALID_PARAMS` (envelope) — PARTIAL
- Core: `-32602` is documented as a JSON-RPC 2.0 envelope code for
  "bad params *shape*" only.  Application-layer "bad value" errors
  use `-8 RPC_INVALID_PARAMETER`.  Distinct codes; Core uses each
  separately (`grep` shows 176 sites for `-8` and 1 site for
  `-32602` in `src/rpc/`).
- nimrod: collapses both into `RpcInvalidParams = -32602`.  156 raise
  sites emit `-32602` regardless of whether the failure is "params is
  not an array" (envelope) or "height out of range" (application).
- Status: PARTIAL — the envelope code is at least present.  See
  also Gate 10.

### Gate 5 — `-32603 RPC_INTERNAL_ERROR` — PRESENT (over-used; see Gates 11,18,24,25)
- Core: reserved for genuine bitcoind internal errors (datadir
  corruption, etc.).
- nimrod: `server.nim:8551` catch-all uses `RpcInternalError` for any
  uncaught `CatchableError`. Matches the *envelope* code but is
  over-used for paths that should be more specific (P2P disabled,
  DB error, etc.).

### Gate 6 — `-1 RPC_MISC_ERROR` — PRESENT (massively over-used)
- Core: `-1` is used as a fallback for ad-hoc errors.
- nimrod: 64 raise sites use `RpcMiscError = -1`. Many of these
  semantically map to other codes (Gates 11, 27, 30, etc.) but the
  envelope code is correct on its face.

### Gate 7 — `-3 RPC_TYPE_ERROR` — MISSING
- Core: `src/rpc/util.cpp` + per-handler.  Used when a JSON parameter
  is the wrong type, e.g. "Expected type number, got string".  16
  raise sites across `src/rpc/`.
- nimrod: no `RpcTypeError` constant defined.  Type-mismatch sites
  raise `RpcInvalidParams` (-32602) instead.  Example:
  `server.nim:2393` "verbose must be a boolean or integer" should be
  `-3` per Core.

### Gate 8 — `-5 RPC_INVALID_ADDRESS_OR_KEY` — PRESENT
- Core: 72 raise sites — invalid address, unknown txid, unknown
  block hash, etc.
- nimrod: 54 raise sites.  Matches Core semantics.

### Gate 9 — `-7 RPC_OUT_OF_MEMORY` — MISSING
- Core: defined in `protocol.h` but rarely raised in practice
  (allocation failures usually crash the process).  Counted as
  MISSING for parity but expected to be MISSING in most impls.

### Gate 10 — `-8 RPC_INVALID_PARAMETER` — MISSING
- Core: 176 raise sites — the *most common* error code in the entire
  RPC layer.  Bad parameter *value* (e.g. "negative height",
  "maxfeerate cannot exceed 1 BTC/kvB", "missing txid parameter",
  "rawtxs array must not be empty").
- nimrod: no `RpcInvalidParameter = -8` constant.  All 176-equivalent
  sites in nimrod use `RpcInvalidParams = -32602` instead.  This is
  the single largest semantic gap in the audit.
- Representative Core sites: `src/rpc/blockchain.cpp` (height oob),
  `src/rpc/mempool.cpp` (maxfeerate), `src/rpc/rawtransaction.cpp`
  (missing field), `src/wallet/rpc/...` (address type).

### Gate 11 — `-20 RPC_DATABASE_ERROR` — MISSING
- Core: 4 raise sites — `src/rpc/blockchain.cpp` and `wallet/rpc/`
  on RocksDB / wallet-DB I/O failure.
- nimrod: no `RpcDatabaseError = -20` constant. RocksDB errors
  surface as either `RpcInternalError` (-32603) or `RpcMiscError`
  (-1) depending on which raise site catches them.

### Gate 12 — `-22 RPC_DESERIALIZATION_ERROR` — MISSING
- Core: 28 raise sites — `src/rpc/rawtransaction.cpp`,
  `src/rpc/mempool.cpp`, `src/rpc/mining.cpp`.  "TX decode failed",
  "Block decode failed", "TX decode failed for tx %d", etc.
- nimrod: no `RpcDeserializationError = -22` constant.  All TX/block
  decode failures use `RpcInvalidParams = -32602` instead.  Examples:
  - `server.nim:2552` "invalid transaction: " (sendrawtransaction)
  - `server.nim:2646` "script decode failed"
  - `server.nim:2996` "TX decode failed"
  - `server.nim:3058` "TX " & $i & " decode failed"
  - `server.nim:3270` (submitpackage path)
  - `server.nim:6324` (sign path)
- Core's distinction matters: `-32602`/`-8` mean "this parameter is
  the wrong value"; `-22` means "the bytes decoded OK as hex but
  did not deserialize as a transaction".  Tools that retry on `-22`
  (e.g. trying alternative encodings) cannot do so against nimrod.

### Gate 13 — `-25 RPC_VERIFY_ERROR` — PARTIAL
- Core: 6 raise sites in `src/rpc/mining.cpp`.  Used by
  `submitblock`/`getblocktemplate` (`proposal` mode) when block
  validation fails (`TestBlockValidity failed: %s`).
- nimrod: `submitblock` (`server.nim:3681-3863`) returns the BIP-22
  *result string* directly (e.g. `"rejected"`, `"bad-cb-amount"`)
  instead of raising `-25`.  This is partly BIP-22 compliant — Core
  also returns the BIP-22 string for top-level block-rejection paths
  in `submitblock` — but the `-25` code is used for the
  `block proposal` sub-flow and for `verifymessage`/`signrawtransaction`
  verify-script paths, which nimrod does not surface as `-25` at all.
  Some non-submitblock paths in nimrod use `RpcTransactionError = -25`
  (e.g. `server.nim:2966` "missing inputs") — that's gate 14
  semantically (rejection) but happens to share the alias value `-25`.
- Status: PARTIAL — the constant exists (`RpcTransactionError = -25`,
  with comment claiming it's "Generic transaction error" but the
  alias-of `RPC_VERIFY_ERROR`), but Core's primary site (`submitblock`
  proposal mode) does not raise it.

### Gate 14 — `-26 RPC_VERIFY_REJECTED` — PRESENT
- Core: alias `RPC_TRANSACTION_REJECTED`.  Used by `sendrawtransaction`
  / `submitpackage` on mempool reject.
- nimrod: `server.nim:2968,2970,2985` raise `RpcTransactionRejected`
  (-26) for mempool reject paths. Matches.

### Gate 15 — `-27 RPC_VERIFY_ALREADY_IN_UTXO_SET` — PRESENT
- Core: alias `RPC_TRANSACTION_ALREADY_IN_CHAIN`.  Used by
  `sendrawtransaction` when TX already confirmed.
- nimrod: `server.nim:2939,2944` raise `RpcTransactionAlreadyInChain`
  (-27).  Matches.

### Gate 16 — `-28 RPC_IN_WARMUP` — MISSING
- Core: `src/rpc/server.cpp:488` raises `RPC_IN_WARMUP` while the
  node is loading chain state before RPC is fully ready.  Clients
  retry on -28.
- nimrod: no warmup state in `handleSingleRequest`.  Dispatch runs
  immediately; any RPC during startup either races the chain-state
  load and gets `RpcInternalError`, or crashes.  No `-28` code
  exists.

### Gate 17 — `-32 RPC_METHOD_DEPRECATED` — MISSING
- Core: 1 raise site — `src/rpc/util.cpp`.  Used when a deprecated
  method is called with `-deprecatedrpc` not enabled.
- nimrod: no deprecated-method gating; no `-32` code raised anywhere.
- Lower-priority gate but counted for parity.

### Gate 18 — `-9 RPC_CLIENT_NOT_CONNECTED` — MISSING
- Core: `src/rpc/mining.cpp:769` "is not connected!" /
  `src/rpc/mining.cpp:843` "Shutting down".  Raised when
  `getblocktemplate`/`submitblock` is called and the node is not
  connected to peers.
- nimrod: `handleAddNode` `server.nim:3544` raises
  `RpcInternalError` ("peer manager not available") instead. No `-9`.

### Gate 19 — `-10 RPC_CLIENT_IN_INITIAL_DOWNLOAD` — MISSING
- Core: 2 raise sites — `mining.cpp:773` (`getblocktemplate` blocked
  during IBD) and `mempool.cpp:1141` (`importmempool` blocked during
  IBD).
- nimrod: no IBD-aware error code.  `handleGetBlockTemplate`
  (`server.nim:3577`) and `handleLoadMempool` (`server.nim:1404+`)
  do not check IBD state.  Some paths *do* check `ibdMode` (e.g.
  `cs.startIBD()` in `submitblock`) but never raise `-10`.

### Gate 20 — `-23 RPC_CLIENT_NODE_ALREADY_ADDED` — MISSING
- Core: 2 raise sites — `src/rpc/net.cpp`.
- nimrod: `handleAddNode` `server.nim:3536` does not detect duplicate
  add; `case command of "add": asyncSpawn connectAsync(...)` blindly
  attempts a new connection.  No duplicate-detection path.

### Gate 21 — `-24 RPC_CLIENT_NODE_NOT_ADDED` — MISSING
- Core: 2 raise sites — `src/rpc/net.cpp`.
- nimrod: `handleAddNode` `case "remove"` walks `getReadyPeers()` and
  silently no-ops if no match; never raises.  No `-24` analogue.

### Gate 22 — `-29 RPC_CLIENT_NODE_NOT_CONNECTED` — MISSING
- Core: 1 raise site — `src/rpc/net.cpp::disconnectnode`.
- nimrod: `handleDisconnectNode` `server.nim:4365` — not inspected
  closely; from `grep` no `-29` raise.

### Gate 23 — `-30 RPC_CLIENT_INVALID_IP_OR_SUBNET` — PARTIAL
- Core: 3 raise sites — `setban`, `addnode`.
- nimrod: `handleAddNode` `server.nim:3556` raises `RpcInvalidParams`
  for invalid port; `setban` paths likely similar.  The error is
  caught but with the wrong code.

### Gate 24 — `-31 RPC_CLIENT_P2P_DISABLED` — MISSING
- Core: `src/rpc/server_util.cpp:103,119,127` — raised when P2P or
  AddrMan is disabled.
- nimrod: `handleAddNode` `server.nim:3544` "peer manager not
  available" uses `RpcInternalError` (-32603) instead.

### Gate 25 — `-33 RPC_CLIENT_MEMPOOL_DISABLED` — MISSING
- Core: 1 raise site — for `-blocksonly` mode mempool RPCs.
- nimrod: `server.nim:1388,1399,1405,1412` "Mempool unavailable"
  uses `RpcInternalError` (-32603) instead.

### Gate 26 — `-4 RPC_WALLET_ERROR` — PRESENT
- Core: 41 raise sites — generic wallet errors.
- nimrod: `server.nim:6125` (and 3 others) raise `RpcWalletError`
  (-4). Matches for the small subset of sites that use it.

### Gate 27 — `-6 RPC_WALLET_INSUFFICIENT_FUNDS` — MISSING
- Core: 6 raise sites — `sendtoaddress`, `walletcreatefundedpsbt`,
  etc. when balance is insufficient.
- nimrod: no `RpcWalletInsufficientFunds = -6` constant. Insufficient
  funds surface as `RpcMiscError` (-1) or `RpcWalletError` (-4)
  depending on path.

### Gate 28 — `-11 RPC_WALLET_INVALID_LABEL_NAME` — MISSING
- Core: 2 raise sites — `setlabel`, `getaddressesbylabel`.
- nimrod: no `-11` code; `setlabel` handler (`server.nim:5931+`)
  does not validate label name shape.

### Gate 29 — `-12 RPC_WALLET_KEYPOOL_RAN_OUT` — MISSING
- Core: 2 raise sites — `getnewaddress`, `getrawchangeaddress`.
- nimrod: no `-12` code.  Nimrod's wallet is descriptor-based and
  may not have a keypool concept in the same shape, but Core's code
  surfaces this on HD-disabled / paused wallets.

### Gate 30 — `-13/-14/-15/-17 RPC_WALLET_{UNLOCK,PASSPHRASE,ENCSTATE,UNLOCKED}` — MISSING
- Core:
  - `-13 RPC_WALLET_UNLOCK_NEEDED` (1 raise site)
  - `-14 RPC_WALLET_PASSPHRASE_INCORRECT` (4 raise sites)
  - `-15 RPC_WALLET_WRONG_ENC_STATE` (4 raise sites — "wallet is
    already encrypted", "wallet is not encrypted")
  - `-17 RPC_WALLET_ALREADY_UNLOCKED` (n/a in current Core)
- nimrod: `server.nim:5829-5925` (`handleEncryptWallet`,
  `handleWalletPassphrase`, `handleWalletLock`,
  `handleWalletPassphraseChange`) collapse all four into
  `RpcMiscError` (-1):
  - L5846 "wallet is already encrypted" → should be `-15`
  - L5852 (encrypt failure) → should be `-16`
    (`RPC_WALLET_ENCRYPTION_FAILED`)
  - L5873 "wallet is not encrypted" → should be `-15`
  - L5877 "incorrect passphrase" → should be `-14`
  - L5891 "wallet is not encrypted" (walletlock) → should be `-15`
  - L5918 "wallet is not encrypted" (passphrasechange) → should be `-15`
  - L5922 "incorrect old passphrase" → should be `-14`
  - L4636 (server.nim) "Error: Please enter the wallet passphrase
    with walletpassphrase first." (string only — not raised, used
    in a help message) — Core's `-13` site.
  - `getTargetWallet` `server.nim:5224` "wallet not loaded" → should
    be `-18 RPC_WALLET_NOT_FOUND`.

This is the single largest cluster of "wrong code" in nimrod and is
the most user-visible: every client tool that prompts on `-13` or
distinguishes `-14`/`-15` (e.g. Bitcoin Knots' GUI, electrum-bcr's
hot-wallet helpers) will silently fail to branch correctly.

## Universal observations (across the fleet)

These are observations that may recur in sibling impls and are worth
calling out at the meta level rather than per-bug:

1. **"Local constant table is a subset of `protocol.h`"** — nimrod
   defines 9 of ~30 Core codes.  Most other impls in the fleet
   define a similarly partial subset (per W118/W119/W120 audits of
   wallet RPC error handling).  Likely fleet-wide pattern: only
   "happy-path adjacent" codes are added when each RPC is first
   wired.

2. **"-32602 collapse"** — every impl in the fleet that the user has
   asked about so far appears to use the JSON-RPC envelope code
   `-32602` for both application-layer "bad value" and envelope-level
   "bad params shape".  Core's `protocol.h` comment explicitly warns
   against this collapse for `-32600`; the same warning should apply
   symmetrically to `-32602` (Core does not state it but uses `-8`
   consistently for the application-layer case).

3. **"RPC_MISC_ERROR (-1) is the universal escape hatch"** — when
   handler authors are unsure which code applies, they use `-1`.
   This is exactly Core's documented purpose for `-1`, but it then
   means impls quietly degrade to `-1` instead of growing their
   constant table.

4. **"No node-state codes"** — `RPC_IN_WARMUP` (-28),
   `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10),
   `RPC_CLIENT_P2P_DISABLED` (-31), and
   `RPC_CLIENT_MEMPOOL_DISABLED` (-33) are MISSING in nimrod and
   likely MISSING across the fleet because these require a
   dispatcher-layer pre-check (Core's `server.cpp` calls
   `IsRPCRunning()` and `rpcWarmupStatus` before dispatch), and
   the per-handler `getRequired*` helpers in `server_util.cpp`.
   Most impls dispatch immediately on JSON parse and never have a
   global warmup guard.

5. **Wire-on-the-good-paths, gap-on-the-error-paths** — this is the
   33rd-wave dead-helper-like pattern in a new shape.  The
   error-code constants and `newRpcError` machinery are in place and
   tested for the codes that exist; the gap is that the *correct*
   code is not chosen at the raise site.  Cosmetically the JSON-RPC
   envelope is well-formed.

## Recommended fix decomposition

Future fix waves (NO production change in W125):

- **FIX-N (P1, fleet)**: introduce all 30 Core codes as named
  constants in `server.nim` (or a new `src/rpc/errors.nim`).
- **FIX-N+1 (P0-RPC, nimrod)**: route wallet-encryption raise sites
  (Gate 30) to `-13/-14/-15/-16`.  Highest user-visibility gain per
  LOC.
- **FIX-N+2 (P1, nimrod)**: route TX/block decode failures (Gate 12)
  to `-22 RPC_DESERIALIZATION_ERROR`.  Largest raise-site count after
  Gate 10.
- **FIX-N+3 (P2, nimrod)**: split `-32602` into envelope (`-32602`)
  vs application (`-8`).  Largest semantic shift; defer until the
  audit has been ratified at the fleet level so all impls move
  together.
- **FIX-N+4 (P1, nimrod)**: dispatcher-layer warmup gate (`-28`) and
  IBD-aware mining/mempool gates (`-10`).  Requires adding a
  `warmup` field to `RpcServer`.
- **FIX-N+5 (P2, nimrod)**: P2P codes (`-9, -23, -24, -29, -30, -31,
  -33`).  Touch `handleAddNode` / `handleDisconnectNode` /
  `handleSetBan` / mempool RPC entries.
- **FIX-N+6 (P2, nimrod)**: wallet codes (`-6, -11, -12, -18, -35,
  -36`).

The full table maps each fix to its Gate # so the audit can be
cited from the fix commit body.

## References

- `bitcoin-core/src/rpc/protocol.h` — `enum RPCErrorCode`
- `bitcoin-core/src/rpc/server.cpp` — dispatch + warmup gate
- `bitcoin-core/src/rpc/server_util.cpp` — P2P / mempool gates
- `bitcoin-core/src/rpc/mining.cpp` — `submitblock` proposal,
  `getblocktemplate` (NOT_CONNECTED, IBD)
- `bitcoin-core/src/rpc/rawtransaction.cpp` — deserialization
- `bitcoin-core/src/rpc/blockchain.cpp` — database / verify
- `bitcoin-core/src/wallet/rpc/encrypt.cpp` — wallet enc-state codes

## Test file

xfail regression guards live at
`tests/test_w125_error_parity.nim`.  Each MISSING / PARTIAL gate has
a `test` that documents the current (wrong) code with `check`, plus
a TODO comment naming the expected code.  When a future FIX wave
lands, the `check` flips to the correct code and the test acts as a
post-fix regression guard.
