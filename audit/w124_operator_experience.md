# W124 — Operator-experience audit (nimrod)

Date: 2026-05-17
Audit type: discovery
Target: `src/nimrod.nim`, `src/util/ops.nim`, `src/rpc/server.nim`, and the
operator-shaped configuration / lifecycle surface.
Reference: `bitcoin-core/src/init.cpp`, `bitcoin-core/src/init/common.cpp`,
`bitcoin-core/src/logging.{cpp,h}` (shutdown lives inside `src/init.cpp` —
`Interrupt()` / `Shutdown()` / `g_shutdown` since the standalone
`shutdown.{cpp,h}` file was folded into `init.cpp` in modern Core).

## Status

**6 BUGS FOUND — 1 P0-CORRECTNESS, 2 P1-OPS, 3 P2-OPS.**

The lifecycle skeleton is well-engineered (clean SIGINT/SIGTERM/SIGHUP path
in `setupSignalHandlers`, two-fork `daemonize`, PID file + idempotent
cleanup, ready-FD systemd-style supervision, mempool.dat + fee_estimates.json
on shutdown).  The bugs cluster around three failure modes:

1. **RPC `stop` is a no-op** (P0): the handler returns a polite string
   `"nimrod server stopping"` but never sets `globalNodeState.running = false`
   and never raises SIGTERM at itself.  `nimrod stop` claims success and the
   node keeps running until an operator kill.  Caught by xfail test G2.
2. **Datadir lock missing** (P1): two simultaneous `nimrod start` runs on
   the same datadir silently race on RocksDB + the cookie file + the PID
   file (the second `writePidFile` simply overwrites the first).  Core's
   `LockDirectory` + `.lock` sentinel is absent.
3. **Notify hooks absent** (P2): `-blocknotify`, `-startupnotify`,
   `-shutdownnotify`, `-walletnotify`, `-alertnotify` — five Core operator
   hooks — are unimplemented.  Supervised deployments (systemd, k8s,
   monitoring sidecars) often depend on at least `-blocknotify` for tip
   propagation.

In addition, the `getrpcinfo` RPC is a stub (returns empty
`active_commands` and empty `logpath`), the user-agent + getnetworkinfo
`"version"` fields are hard-coded integers that drift from
`NimrodVersion`, and there is no debug-log rotation / shrink path.

The **W57 `bin/migrate_ntx` tool** (FIX-80 finding) is operator-friendly
in the small but ships **no `--help`**, **no dry-run**, **no idempotence
marker** (re-running scans the entire cfTxIndex again), and **no
node-running guard** (rocksdb FFI will fail noisily, but the tool does
not check for `.cookie` / `nimrod.pid` first to give a cleaner error).
Same shape applies to `bin/patch_ntx`.

## 30 audit gates

Classification:
- **PRESENT** — feature wired end-to-end and reachable from the operator surface.
- **PARTIAL** — implementation present but gappy: undocumented, dead-code
  reachable, hard-coded value, or missing one of (CLI flag / config-file
  key / RPC surface / shutdown cleanup).
- **MISSING** — no implementation; the operator-visible behaviour Core has
  is absent.

Gates are grouped: **G1-G10 lifecycle + shutdown**, **G11-G20 logging + debug**,
**G21-G30 datadir, supervision, ops UX**.

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G1 | SIGINT/SIGTERM graceful shutdown | **PRESENT** | `setupSignalHandlers` (`src/nimrod.nim:1433-1510`); flushes IBD, UTXO cache, REST, RPC, mempool.dat, fee_estimates.json, peers, db; matches Core `Interrupt()` + `Shutdown()` shape. |
| G2 | RPC `stop` actually shuts the node down | **MISSING (BUG-1, P0)** | `src/rpc/server.nim:8457-8459` returns `"nimrod server stopping"` and **never** flips `globalNodeState.running` or signals SIGTERM.  `nimrod stop` lies about success.  See `tests/test_w124_operator.nim` `G2 BUG-1`. |
| G3 | SIGHUP reopens debug log | **PRESENT** | `sigHupHandler` → `reopenLog` (`src/util/ops.nim:152-168`); uses POSIX `open/dup2/close` only (signal-safe-ish); path tracked via `gLogPath`. |
| G4 | `--daemon` two-fork detach | **PRESENT** | `daemonize` in `src/util/ops.nim:33-96`; correct two-fork + `setsid` + umask reset + stdio dup2; mirrors Core `daemon()` wrapper. |
| G5 | PID file write + cleanup | **PRESENT** | `writePidFile` (`src/util/ops.nim:102-112`); cleaned in signal handler (line 1447) and `finally` of `main()` (line 2648).  Idempotent. |
| G6 | `--pid=<path>` override | **PRESENT** | Wired via CLI (`src/nimrod.nim:576-577`) and config-file (`src/nimrod.nim:306-307`); defaults to `<datadir>/nimrod.pid`. |
| G7 | `--ready-fd=<N>` systemd-style notify | **PARTIAL** | `signalReadyFd` (`src/util/ops.nim:223-233`) fires before main loop; **no support for `sd_notify`'s `NOTIFY_SOCKET`** environment-variable protocol (Core via systemd unit doesn't have it either, but the gap is operator-visible vs every other Bitcoin impl that uses libsystemd).  PARTIAL, not MISSING — the FD path covers most supervisors. |
| G8 | Datadir lock (`.lock` sentinel) | **MISSING (BUG-2, P1)** | No `flock`/`LockDirectory` on `<datadir>/<network>/`; two `nimrod start` on the same datadir race RocksDB + cookie file + PID file.  Second `writePidFile` silently clobbers the first.  Core does `LockDirectory(args.GetDataDirNet(), ".lock")`. |
| G9 | `--reindex` chainstate wipe | **PRESENT** | `applyReindex` (`src/nimrod.nim:2525-2548`); HONEST PROGRESS comment makes the limit explicit (does not re-scan `blk*.dat`, drops chainstate to trigger fresh IBD).  Clears stray `mempool.dat` + `fee_estimates.json`. |
| G10 | `mempool.dat` persistence on shutdown | **PRESENT** | `dumpMempool` in `sigHandler` (`src/nimrod.nim:1488-1492`) + `loadMempool` on startup (line 2023-2037).  Core-compatible format (per W120 BUG-4 + persist module). |
| G11 | `-debuglogfile=<file>` | **PRESENT** | CLI (`src/nimrod.nim:590-591`) + config (line 316-317); falls back to `<datadir>/<network>/debug.log` under `--daemon`; redirected via `redirectLogToFile` (`src/util/ops.nim:129-150`). |
| G12 | `--debug=<cat,cat>` topic filter | **PRESENT** | `parseDebugCategories` + `applyDebugCategories` (`src/util/ops.nim:189-217`); 27 known categories; `all`/`1` enables everything; `0`/`none` disables. |
| G13 | `-debugexclude=<cat>` | **MISSING (BUG-3, P2)** | Core's `-debugexclude` ("include all except X") has no equivalent in `parseDebugCategories`.  Operator can only opt-in to categories, not opt-out of one. |
| G14 | `--printtoconsole` | **PRESENT** | CLI + config (`src/nimrod.nim:585-589`, 314-315); used by `operationalSetup` to suppress the daemon log-file redirect. |
| G15 | `-logtimestamps` / `-logthreadnames` / `-logsourcelocations` / `-logips` | **MISSING (BUG-4, P2)** | None of these four Core flags exist.  Chronicles formats timestamps by default but operator cannot toggle them (or thread name, source location, IP-address inclusion in net logs) the way Core operators do.  Diagnostic-only — not a correctness bug, but a parity gap. |
| G16 | `-loglevel=<level>|<category>:<level>` | **PARTIAL** | `--loglevel=info|debug|...` exists as a global level (`config.logLevel`).  Per-category levels (`net:debug`) — Core's syntax — are not supported. |
| G17 | Log rotation / `-shrinkdebugfile` | **MISSING (BUG-5, P2)** | No `MaxLogSize` enforcement, no shrink-at-startup behaviour, no internal rotator.  Operators must use external `logrotate` + SIGHUP (which IS wired via G3 — so this is mitigatable externally, but the in-process Core behaviour is absent). |
| G18 | `getrpcinfo` RPC | **PARTIAL (BUG-6, P2)** | `handleGetRPCInfo` (`src/rpc/server.nim:8227-8229`) returns `{"active_commands": [], "logpath": ""}` — a stub.  Two of the three useful fields (`active_commands`, `logpath`) are hard-coded empty.  Operator-visible degradation of debugging tooling. |
| G19 | `uptime` RPC | **PRESENT** | `handleUptime` (`src/rpc/server.nim:4400`) dispatched at `:8460`.  Returns seconds since RPC server started. |
| G20 | `logging` RPC (toggle categories at runtime) | **MISSING (BUG-7, P2)** | No `logging` method dispatched in `handleMethod`.  Operator cannot enable/disable a debug category against a running node — must restart with new `--debug=...`. |
| G21 | `--datadir` override | **PRESENT** | `src/nimrod.nim:474-475` (CLI) + config-file key.  `getHomeDir() / ".nimrod"` default. |
| G22 | `--conf=<path>` override | **PRESENT** | `loadConfigFile` (line 235-358); CLI `--conf=` at line 578-579. |
| G23 | RPC cookie file (`.cookie`) | **PRESENT** | `generateCookieFile` (`src/nimrod.nim:1512-1528`); mode 0o600; format `__cookie__:<hex>` matches Core; removed on SIGINT/SIGTERM. |
| G24 | `--blocknotify=<cmd>` external hook | **MISSING (BUG-8, P2)** | Core's `-blocknotify=<cmd>` (executes a shell command on each new tip — `%s` substituted for block hash) has no equivalent.  Mining pool / monitoring deployments rely on this. |
| G25 | `--walletnotify=<cmd>` external hook | **MISSING (BUG-9, P2)** | Same shape as G24 but for wallet tx events.  Affects wallet-using operators. |
| G26 | `--alertnotify=<cmd>` external hook | **MISSING (BUG-10, P2)** | Core's `-alertnotify=<cmd>` (fires on warnings like "51% attack detected"). |
| G27 | `--startupnotify=<cmd>` external hook | **MISSING (BUG-11, P2)** | Core's `-startupnotify=<cmd>` after `AppInitMain` returns. |
| G28 | `--shutdownnotify=<cmd>` external hook | **MISSING (BUG-12, P2)** | Core's `-shutdownnotify=<cmd>` fired from `Interrupt()` before `Shutdown()`. |
| G29 | `getnetworkinfo` `version` / `subversion` consistency | **PARTIAL (BUG-13, P2)** | Both fields are hard-coded literals (`210000` integer + `/nimrod:0.1.0/` string in `src/rpc/server.nim:3418-3419`); `NimrodVersion` const (`src/nimrod.nim:21`) is `"0.1.0"`.  Three sources of truth, no cross-reference — a `NimrodVersion` bump won't update the network handshake.  Already drifted: the integer is `210000` (Bitcoin Core encoding) but unrelated to the string version. |
| G30 | `bin/migrate_ntx` operator UX (W57 backfill) | **PARTIAL (BUG-14, P2)** | Tool runs, but: no `--help`, no `--dry-run`, no node-running guard (RocksDB lock failure is the operator's only signal), no idempotence marker (re-runs re-scan the entire `cfTxIndex` — at fleet scale that's ~5-10 minutes wasted), no progress percentage (only absolute count).  `bin/patch_ntx` has the same shape. |

## Universal findings carried forward

Three of the bugs match cross-impl patterns seen in earlier W-waves:

1. **"RPC lies about its action"** — G2 BUG-1 (`stop` returns success
   without acting) mirrors W120 BUG-3 (`bip125-replaceable` lies about
   ancestor-walking) and the broader cross-impl pattern "RPC lies about
   X" that hit 5 of 10 impls in W120.  Same fix shape: handler must
   modify global state, not just respond.

2. **"Dead-helper at call site"** — G18 BUG-6 (`getrpcinfo` returns a
   stub with empty `active_commands` even though the RPC server keeps
   a per-connection map internally that COULD be exposed).  Continues
   the 33-wave dead-helper streak — see W121 W120 W119.

3. **"Comment-as-confession"** — G2 BUG-1 has the literal in-source
   comment `# Return success - actual shutdown handled by caller`
   (`src/rpc/server.nim:8458`).  No caller acts on it.  The 11th
   confession-comment observed across the fleet — see W120 BUG-5
   (blockbrew `getmempoolinfo` FullRBF:true comment).

## Bug summary (severity-sorted)

| # | Severity | Gate | One-line |
|---|----------|------|---------|
| BUG-1 | P0-CORRECTNESS | G2 | `stop` RPC handler is a no-op — node keeps running after `nimrod stop` claims success. |
| BUG-2 | P1-OPS | G8 | No datadir lock — two `nimrod start` on same datadir race RocksDB + cookie + PID. |
| BUG-3 | P2-OPS | G13 | `-debugexclude=<cat>` (opt-out from `--debug=1`) absent. |
| BUG-4 | P2-OPS | G15 | `-logtimestamps` / `-logthreadnames` / `-logsourcelocations` / `-logips` absent (4 flags). |
| BUG-5 | P2-OPS | G17 | No in-process log rotation / `-shrinkdebugfile` (external `logrotate` + SIGHUP works). |
| BUG-6 | P2-OPS | G18 | `getrpcinfo` stub: `active_commands` and `logpath` always empty. |
| BUG-7 | P2-OPS | G20 | `logging` RPC absent — operator cannot toggle categories live. |
| BUG-8 | P2-OPS | G24 | `--blocknotify=<cmd>` absent. |
| BUG-9 | P2-OPS | G25 | `--walletnotify=<cmd>` absent. |
| BUG-10 | P2-OPS | G26 | `--alertnotify=<cmd>` absent. |
| BUG-11 | P2-OPS | G27 | `--startupnotify=<cmd>` absent. |
| BUG-12 | P2-OPS | G28 | `--shutdownnotify=<cmd>` absent. |
| BUG-13 | P2-OPS | G29 | `getnetworkinfo` version/subversion hard-coded, drift from `NimrodVersion`. |
| BUG-14 | P2-OPS | G30 | `bin/migrate_ntx` + `bin/patch_ntx`: no `--help`, no `--dry-run`, no idempotence, no node-running guard. |

(Count: 14 bugs across 30 gates.  P0=1, P1=1, P2=12.  10 gates PRESENT,
5 PARTIAL, 15 MISSING.)

## Tests

`tests/test_w124_operator.nim` lifts these into 30 audit-flip / xfail
assertions, one per gate.  Pattern matches W121 / W122:

- PRESENT gates: positive `check compiles(...)` or behavioural assertion.
- PARTIAL gates: assert the present part; xfail-mark the missing piece.
- MISSING gates: `check not compiles(<symbol>)` so the test FILE fails
  to compile once the gap is closed.  Each closure of a MISSING gate
  must update this test to `compiles(...)` in the corresponding FIX
  wave.

The G2 BUG-1 test is **behavioural** rather than compile-time: it
checks that the `"stop"` handler returns the empty-action stub and that
no public proc exists to wire it to `globalNodeState.running`.

Pre-existing nimble-test breakage: `tests/test_blockstore.nim` fails to
compile due to the `MinBlocksToKeep` namespace conflict between
`storage/blockstore.MinBlocksToKeep` and `consensus/params.MinBlocksToKeep`
(both are `int literal(288)`).  This blocks `nimble test` system-wide;
**it is a pre-existing failure** (per FIX-83/87 notes) and not caused by
this audit.  The W124 test file compiles in isolation (verified).

## Suggested fix shapes (out-of-scope for this audit)

- **BUG-1 (P0):** in `handleStop`, set `globalNodeState.running = false`
  and raise SIGTERM at self (or call `posix.kill(getpid(), SIGTERM)`) so
  the existing graceful path runs.  Either approach matches Core
  `rpc/server.cpp::stop` shape.

- **BUG-2 (P1):** add `lockDataDir(networkDir)` invocation in
  `operationalSetup` BEFORE `writePidFile`.  Use `posix.open(O_CREAT|O_EXCL)`
  on `<networkDir>/.lock` containing the PID; `O_EXCL` failure raises a
  clear "another nimrod is running, pid=<n>" error.  Mirrors Core
  `LockDirectory(args.GetDataDirNet(), ".lock")` in `init.cpp:1163-1165`.

- **BUG-3..BUG-7 (P2 log/debug):** add four CLI flags + parseDebugCategories
  extension for excludes; wire a per-category log level setter; add
  shrinkdebugfile-at-startup; wire `logging` RPC method to
  `chronicles/topics_registry.setTopicState`.

- **BUG-8..BUG-12 (P2 notify hooks):** add `runHook(cmd, substitution)`
  helper using `osproc.startProcess`; wire five call-sites (block-connected
  hook on chainstate, mempool wallet-tx hook, peerman alert hook, end of
  `operationalSetup`, top of `sigHandler`).  All five share the same
  shape.

- **BUG-13 (P2 versioning):** expose `NimrodVersion` (and a derived
  integer) from a single source; have `handleGetNetworkInfo` read both.

- **BUG-14 (P2 W57 tool UX):** add a `--help` arg, a `--dry-run` flag
  (skip the `cdb.db.write(batch)`), and a node-running guard that
  errors cleanly when a `.lock` / `.cookie` is present.

## Verification (smoke)

`tests/test_w124_operator.nim` compiles in isolation; G2 BUG-1
behavioural test asserts the stub return string and the absence of a
`triggerShutdown` proc.  No production code modified by this audit.

## References

- `bitcoin-core/src/init.cpp` — `Interrupt()` (line 268), `Shutdown()`
  (line 288), `CreatePidFile` (line 183), `LockDirectory` invocation
  (line 1163-1165), `-shutdownnotify` / `-startupnotify` / `-blocknotify`
  declarations (line 529-530, 498).
- `bitcoin-core/src/init/common.cpp` — `AddLoggingArgs` (line 27) for
  the full `-log*` flag inventory.
- `bitcoin-core/src/logging.h` — `LogInstance().m_reopen_file` (line 186)
  for SIGHUP reopen; `MaxLogSize` for shrinkdebugfile.
- `src/nimrod.nim:1433-1510` — `setupSignalHandlers` (the well-engineered
  half of nimrod's operator surface).
- `src/util/ops.nim` — daemonize / pidfile / log-reopen helpers.
- `src/rpc/server.nim:8457-8459` — the BUG-1 confession.
