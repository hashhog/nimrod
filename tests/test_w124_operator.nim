## W124 — Operator-experience audit (nimrod)
##
## 30 gates classifying nimrod's operator-shaped configuration / lifecycle
## surface (CLI flags, signal handling, shutdown, daemonization, PID file,
## debug log, datadir lock, notify hooks, RPC ops surface, W57 backfill
## tool UX).
##
## Reference: bitcoin-core/src/init.cpp (Interrupt / Shutdown / CreatePidFile
##            / LockDirectory / notify hooks / cookie auth)
##            bitcoin-core/src/init/common.cpp (AddLoggingArgs — 11 log/debug
##            flags)
##            bitcoin-core/src/logging.{cpp,h} (m_reopen_file SIGHUP, log
##            level + category management)
##            audit/w124_operator_experience.md
##
## PRESENT gates: positive existence check via `compiles(symbol)`, behaviour
##                assertion, or source-level regression read of a known wire.
## PARTIAL gates: assert the PRESENT part, then xfail-mark the missing piece.
## MISSING gates: `check not compiles(<symbol>)` so this file FAILS TO
##                COMPILE once the gap is closed in a follow-up fix wave.
##                Each closure of a MISSING gate must flip the corresponding
##                assertion to `compiles(...)`.

import std/[unittest, os, strutils, sets, tempfiles, posix]

import ../src/nimrod as nimrod_main
import ../src/util/ops
import ../src/rpc/server as rpc_server

# ============================================================================
# G1-G10: lifecycle + shutdown
# ============================================================================

suite "W124 lifecycle + shutdown (G1-G10)":

  test "G1 PRESENT: setupSignalHandlers wired (SIGINT/SIGTERM/SIGHUP)":
    ## src/nimrod.nim:1433-1510 — sigHandler covers SIGINT/SIGTERM, sigHupHandler
    ## covers SIGHUP. Mirrors Core init.cpp `Interrupt()` + `Shutdown()` shape.
    check compiles(setupSignalHandlers)
    let src = readFile("src/nimrod.nim")
    check "signal(SIGINT, sigHandler)" in src
    check "signal(SIGTERM, sigHandler)" in src
    check "signal(SIGHUP, sigHupHandler)" in src

  test "G2 BUG-1 (P0): RPC `stop` is a no-op confession":
    ## src/rpc/server.nim:8457-8459 — the handler returns a polite string
    ## and the inline comment confesses "actual shutdown handled by caller"
    ## but NO caller of `handleMethod` acts on the return value to flip
    ## `globalNodeState.running`.  `nimrod stop` claims success and the
    ## node keeps running.  The 11th confession-comment observed across
    ## the fleet (cf. W120 BUG-5 blockbrew getmempoolinfo).
    let src = readFile("src/rpc/server.nim")
    # Find the `stop` handler and assert the confession is still there:
    check "of \"stop\":" in src
    check "# Return success - actual shutdown handled by caller" in src
    check "nimrod server stopping" in src
    # The fix would add a `triggerShutdown` proc OR set
    # globalNodeState.running = false inside the handler.  Neither exists:
    check not compiles(rpc_server.triggerShutdown)
    # Source-level: handler body must NOT touch globalNodeState today.
    # Walk the lines near 8457 and confirm globalNodeState is not flipped.
    let lines = src.splitLines()
    var sawStop = false
    var sawNoOp = false
    for i, line in lines:
      if "of \"stop\":" in line:
        sawStop = true
        # Inspect the next 3 lines for the no-op pattern.
        for j in 1 .. 3:
          if i + j < lines.len:
            let body = lines[i + j]
            if "nimrod server stopping" in body:
              sawNoOp = true
            check "globalNodeState.running = false" notin body
            check "kill(getpid()" notin body
    check sawStop
    check sawNoOp

  test "G3 PRESENT: SIGHUP reopens debug log":
    ## src/util/ops.nim:152-168 — reopenLog uses POSIX open/dup2/close only
    ## (signal-safe-ish). Wired via sigHupHandler at src/nimrod.nim:1437-1440.
    check compiles(reopenLog)
    check compiles(redirectLogToFile)
    check compiles(currentLogPath)
    let src = readFile("src/nimrod.nim")
    check "sigHupHandler" in src
    check "reopenLog()" in src

  test "G4 PRESENT: --daemon two-fork detach":
    ## src/util/ops.nim:33-96 — correct two-fork + setsid + umask + stdio
    ## dup2.  Mirrors Core util/system.cpp `daemon()` wrapper.
    check compiles(daemonize)
    let src = readFile("src/util/ops.nim")
    # Two forks
    check src.count("fork()") >= 2
    check "setsid()" in src
    check "umask" in src.toLowerAscii()

  test "G5 PRESENT: PID file write + idempotent cleanup":
    ## src/util/ops.nim:102-123 — writePidFile + removePidFile.
    check compiles(writePidFile)
    check compiles(removePidFile)
    # Behaviour: write then remove leaves no file.
    let tmp = createTempDir("nimrod_w124_pid_", "")
    let p = tmp / "nimrod.pid"
    writePidFile(p)
    check fileExists(p)
    let content = readFile(p).strip()
    check content == $getpid()
    removePidFile()
    check (not fileExists(p))
    # Idempotent: second call is a no-op.
    removePidFile()
    removeDir(tmp)

  test "G6 PRESENT: --pid=<path> CLI + config override":
    ## src/nimrod.nim:576-577 (CLI) + 306-307 (config).  Default
    ## <datadir>/nimrod.pid (line 2577-2578).
    let src = readFile("src/nimrod.nim")
    check "of \"pid\":" in src
    check "config.pidFile = value" in src
    check "config.pidFile = p.val" in src
    check "config.dataDir / \"nimrod.pid\"" in src

  test "G7 PARTIAL: --ready-fd FD-based supervision but no NOTIFY_SOCKET":
    ## signalReadyFd exists (covers `--ready-fd=N`) but Core/libsystemd's
    ## env-var protocol `NOTIFY_SOCKET=/run/systemd/notify` + `READY=1\n` /
    ## `STATUS=...` / `MAINPID=$$` is absent.  Operator using a stock
    ## systemd Type=notify unit will NOT see ready signals.
    check compiles(signalReadyFd)
    # PARTIAL: NOTIFY_SOCKET path absent — no proc named anything close.
    check not compiles(sdNotify)
    check not compiles(notifyReady)
    let src = readFile("src/util/ops.nim")
    check "NOTIFY_SOCKET" notin src

  test "G8 BUG-2 (P1): datadir lock (.lock) absent":
    ## Core init.cpp:1163-1165 calls
    ## `LockDirectory(args.GetDataDirNet(), ".lock")` and fails AppInit
    ## with a clear "another bitcoind is running" error.  Nimrod has no
    ## equivalent: two `nimrod start` on the same datadir race RocksDB +
    ## .cookie + nimrod.pid (the second writePidFile silently clobbers
    ## the first).
    check not compiles(lockDataDir)
    check not compiles(lockDirectory)
    let src = readFile("src/util/ops.nim")
    # Sanity: no flock / fcntl path here, and no .lock sentinel.
    check "flock" notin src.toLowerAscii()
    check "LockDirectory" notin src
    let nimSrc = readFile("src/nimrod.nim")
    check "lockDataDir(" notin nimSrc
    check "\".lock\"" notin nimSrc

  test "G9 PRESENT: --reindex chainstate wipe":
    ## src/nimrod.nim:2525-2548 — applyReindex; HONEST PROGRESS comment
    ## (doesn't re-scan blk*.dat — drops chainstate so next start triggers
    ## fresh IBD).  Clears stray mempool.dat + fee_estimates.json.
    let src = readFile("src/nimrod.nim")
    check "proc applyReindex" in src
    check "fee_estimates.json" in src
    check "mempool.dat" in src

  test "G10 PRESENT: mempool.dat persistence on shutdown":
    ## sigHandler dumps mempool (src/nimrod.nim:1488-1492); startNode
    ## restores it (line 2023-2037).  Core-byte-compatible format.
    let src = readFile("src/nimrod.nim")
    check "dumpMempool(" in src
    check "loadMempool(" in src
    check "CurrentMempoolDumpFile" in src

# ============================================================================
# G11-G20: logging + debug surface
# ============================================================================

suite "W124 logging + debug (G11-G20)":

  test "G11 PRESENT: --debuglogfile=<path>":
    let src = readFile("src/nimrod.nim")
    check "of \"debuglogfile\":" in src
    check compiles(redirectLogToFile)

  test "G12 PRESENT: --debug=<cat,cat> topic filter":
    check compiles(parseDebugCategories)
    check compiles(applyDebugCategories)
    # Behaviour: comma-separated multi-cat parses to set.
    let s = parseDebugCategories("net,p2p,rpc")
    check s.len == 3
    check "net" in s and "p2p" in s and "rpc" in s
    # `0`/`none` disables, `1`/`all` enables everything.
    check parseDebugCategories("0").len == 0
    check parseDebugCategories("all") == toHashSet(["all"])
    # 27 known categories declared (Core parity for the common subset).
    check KnownDebugCategories.len >= 25

  test "G13 BUG-3 (P2): -debugexclude=<cat> absent":
    ## Core's "include all except X" syntax is missing.
    ## `parseDebugCategories` only handles whole-categories, not excludes.
    let src = readFile("src/util/ops.nim")
    check "debugexclude" notin src.toLowerAscii()
    check "-debugexclude" notin src
    check not compiles(parseDebugExcludes)

  test "G14 PRESENT: --printtoconsole":
    let src = readFile("src/nimrod.nim")
    check "of \"printtoconsole\":" in src
    check "config.printToConsole" in src

  test "G15 BUG-4 (P2): -logtimestamps / -logthreadnames / -logsourcelocations / -logips absent":
    ## Four Core operator flags from src/init/common.cpp:34-39.  Diagnostic
    ## parity gap — not correctness, but four operator-visible toggles
    ## that every Bitcoin Core deployment expects.
    let opsSrc = readFile("src/util/ops.nim")
    let nimSrc = readFile("src/nimrod.nim")
    for flag in ["logtimestamps", "logthreadnames",
                 "logsourcelocations", "logips"]:
      check flag notin opsSrc.toLowerAscii()
      check flag notin nimSrc.toLowerAscii()
    check not compiles(setLogTimestamps)
    check not compiles(setLogThreadNames)

  test "G16 PARTIAL: --loglevel=<level> but no per-category level":
    ## --loglevel=info exists (config.logLevel).  Per-category
    ## (`net:debug`) — Core's syntax — is unsupported.
    let nimSrc = readFile("src/nimrod.nim")
    check "config.logLevel" in nimSrc
    check "of \"loglevel\"" in nimSrc.toLowerAscii() or
          "of \"loglevel\", \"l\":" in nimSrc
    # Per-category level not parsed — check no `:` splitter in
    # parseDebugCategories or anywhere accepting `cat:level`.
    let opsSrc = readFile("src/util/ops.nim")
    check "category_specific" notin opsSrc.toLowerAscii()
    check "perCategoryLevel" notin opsSrc

  test "G17 BUG-5 (P2): no in-process log rotation / -shrinkdebugfile":
    ## SIGHUP-reopen (G3) covers external logrotate, but Core's
    ## ShrinkDebugFile / MaxLogSize internal path is absent.
    let opsSrc = readFile("src/util/ops.nim")
    check "MaxLogSize" notin opsSrc
    check "ShrinkDebugFile" notin opsSrc
    check "shrinkdebugfile" notin opsSrc.toLowerAscii()
    check not compiles(shrinkDebugFile)
    check not compiles(rotateLog)

  test "G18 BUG-6 (P2): getrpcinfo is a stub":
    ## src/rpc/server.nim:8227-8229 — handleGetRPCInfo returns
    ## {"active_commands": [], "logpath": ""}.  Both are hard-coded empty.
    let src = readFile("src/rpc/server.nim")
    let stubLine = "%*{\"active_commands\": [], \"logpath\": \"\"}"
    check stubLine in src

  test "G19 PRESENT: uptime RPC":
    let src = readFile("src/rpc/server.nim")
    check "of \"uptime\":" in src
    check "handleUptime" in src

  test "G20 BUG-7 (P2): logging RPC absent (no runtime category toggle)":
    ## No method `logging` dispatched in handleMethod.  Operator must
    ## restart with new --debug=... to change topic state.
    let src = readFile("src/rpc/server.nim")
    check "of \"logging\":" notin src
    check "handleLogging" notin src

# ============================================================================
# G21-G30: datadir, supervision, ops UX
# ============================================================================

suite "W124 datadir + supervision + ops UX (G21-G30)":

  test "G21 PRESENT: --datadir override":
    let src = readFile("src/nimrod.nim")
    check "of \"datadir\", \"d\":" in src
    check "config.dataDir = value" in src
    check "config.dataDir = p.val" in src
    check "getHomeDir() / \".nimrod\"" in src

  test "G22 PRESENT: --conf=<path> + config-file loading":
    let src = readFile("src/nimrod.nim")
    check "of \"conf\":" in src
    check "loadConfigFile" in src
    check "config.confFile" in src

  test "G23 PRESENT: RPC cookie file (.cookie) Core-byte-compatible":
    ## generateCookieFile produces __cookie__:<32-byte-hex> with mode 0o600.
    let src = readFile("src/nimrod.nim")
    check "proc generateCookieFile" in src
    check "__cookie__:" in src
    check "fpUserRead, fpUserWrite" in src
    # Removed on shutdown.
    check "removeFile(cookiePath)" in src

  test "G24 BUG-8 (P2): --blocknotify=<cmd> external hook absent":
    let nimSrc = readFile("src/nimrod.nim")
    check "blocknotify" notin nimSrc.toLowerAscii()
    check not compiles(runBlockNotify)

  test "G25 BUG-9 (P2): --walletnotify=<cmd> external hook absent":
    let nimSrc = readFile("src/nimrod.nim")
    let walletSrcs = readFile("src/wallet/wallet.nim")
    check "walletnotify" notin nimSrc.toLowerAscii()
    check "walletnotify" notin walletSrcs.toLowerAscii()
    check not compiles(runWalletNotify)

  test "G26 BUG-10 (P2): --alertnotify=<cmd> external hook absent":
    let nimSrc = readFile("src/nimrod.nim")
    check "alertnotify" notin nimSrc.toLowerAscii()
    check not compiles(runAlertNotify)

  test "G27 BUG-11 (P2): --startupnotify=<cmd> external hook absent":
    let nimSrc = readFile("src/nimrod.nim")
    check "startupnotify" notin nimSrc.toLowerAscii()
    check not compiles(runStartupNotify)

  test "G28 BUG-12 (P2): --shutdownnotify=<cmd> external hook absent":
    let nimSrc = readFile("src/nimrod.nim")
    check "shutdownnotify" notin nimSrc.toLowerAscii()
    check not compiles(runShutdownNotify)

  test "G29 BUG-13 (P2): getnetworkinfo version drift":
    ## Three sources of truth:
    ##   src/nimrod.nim:24               NimrodVersion = "1.0.0"
    ##   src/network/messages.nim:22     UserAgent = "/nimrod:1.0.0/"
    ##   src/rpc/server.nim:5274-5275    "version": 210000, "subversion": "/nimrod:1.0.0/"
    ## No cross-reference: bumping NimrodVersion will NOT update the handshake.
    let rpcSrc = readFile("src/rpc/server.nim")
    check "\"version\": 210000" in rpcSrc
    check "\"subversion\": \"/nimrod:1.0.0/\"" in rpcSrc
    # The drift: nothing in handleGetNetworkInfo references NimrodVersion.
    check "NimrodVersion" notin rpcSrc

  test "G30 BUG-14 (P2): bin/migrate_ntx + bin/patch_ntx — operator UX gaps":
    ## W57 backfill tool. Per FIX-80 finding, it works but lacks --help,
    ## --dry-run, idempotence marker, and a node-running guard.
    let migrateSrc = readFile("src/tools/migrate_ntx.nim")
    let patchSrc = readFile("src/tools/patch_ntx.nim")

    # No --help / -h flag handling.
    check "--help" notin migrateSrc
    check "-h\"" notin migrateSrc

    # No --dry-run support — every run writes.
    check "--dry-run" notin migrateSrc
    check "dryRun" notin migrateSrc

    # No node-running guard (looks for .cookie / .lock / .pid first).
    check ".cookie" notin migrateSrc
    check ".lock" notin migrateSrc
    check "nimrod.pid" notin migrateSrc

    # No idempotence marker (a sentinel key in cfBlockIndex saying
    # "this backfill already ran at <timestamp>" would let re-runs short-circuit).
    check "BACKFILL_DONE" notin migrateSrc
    check "migrate_ntx_done" notin migrateSrc

    # patch_ntx shares the same shape gaps.
    check "--help" notin patchSrc
    check "--dry-run" notin patchSrc
    check ".cookie" notin patchSrc

when isMainModule:
  echo "W124 operator-experience audit — 30 gates"
