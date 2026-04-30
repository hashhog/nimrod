## Operational helpers: daemonization, PID file, log reopen on SIGHUP,
## debug-topic mapping, ready-fd notification.
##
## References:
##   bitcoin-core/src/init.cpp           — AppInit / startup / -daemon path
##   bitcoin-core/src/util/system.cpp    — daemon() wrapper, fork/setsid
##   bitcoin-core/src/init/common.cpp    — g_pidfile_path

import std/[os, posix, strutils, sets, locks]
import chronicles
import chronicles/topics_registry as cr

# ---------------------------------------------------------------------------
# State shared with the SIGHUP signal handler. The handler runs in
# async-signal context, so we keep state minimal and re-derive paths on use.
# ---------------------------------------------------------------------------

var
  gLogPath {.global.}: string = ""
  gLogReopenLock {.global.}: Lock
  gLogReopenLockInit {.global.}: bool = false
  gPidPath {.global.}: string = ""

proc ensureLogReopenLockInit() =
  if not gLogReopenLockInit:
    initLock(gLogReopenLock)
    gLogReopenLockInit = true

# ---------------------------------------------------------------------------
# Daemonization
# ---------------------------------------------------------------------------

proc daemonize*(stdoutPath = "", stderrPath = "") {.discardable.} =
  ## Detach from the controlling terminal in the spirit of Bitcoin Core's
  ## `daemon()` wrapper (`src/util/system.cpp`).  Forks twice, calls setsid
  ## between, redirects stdin to /dev/null and stdout/stderr to the supplied
  ## paths (or /dev/null if blank).
  ##
  ## Caller responsibilities: invoke BEFORE opening any long-lived FDs (the
  ## RocksDB chainstate, the RPC listener, the P2P socket).  After this
  ## returns, the parent process has exited.
  let pid1 = fork()
  if pid1 < 0:
    raise newException(OSError, "fork() failed: " & $strerror(errno))
  if pid1 > 0:
    # Parent of first fork — exit so the child becomes orphaned and is
    # adopted by init/PID 1.
    quit(0)

  # First child: become a session leader.
  if setsid() < 0:
    raise newException(OSError, "setsid() failed: " & $strerror(errno))

  # Second fork ensures we are NOT a session leader and therefore can never
  # acquire a controlling terminal again.
  let pid2 = fork()
  if pid2 < 0:
    raise newException(OSError, "second fork() failed: " & $strerror(errno))
  if pid2 > 0:
    quit(0)

  # Reset umask so the PID file / chainstate dirs get sane perms.
  discard umask(Mode(0o022))

  # Redirect stdio. If a path is supplied we open it append-mode; else
  # /dev/null. We keep fds 0/1/2 on their conventional numbers.
  let devNull = open("/dev/null", O_RDWR)
  if devNull >= 0:
    discard dup2(devNull, 0)
    if devNull > 2:
      discard close(devNull)

  proc reopenStream(path: string, fd: cint) =
    if path.len == 0:
      let dn = open("/dev/null", O_WRONLY)
      if dn >= 0:
        discard dup2(dn, fd)
        if dn != fd:
          discard close(dn)
      return
    let f = open(cstring(path),
                 O_WRONLY or O_CREAT or O_APPEND,
                 Mode(0o644))
    if f < 0:
      # Best-effort: fall back to /dev/null rather than dying silently.
      let dn = open("/dev/null", O_WRONLY)
      if dn >= 0:
        discard dup2(dn, fd)
        if dn != fd: discard close(dn)
      return
    discard dup2(f, fd)
    if f != fd:
      discard close(f)

  reopenStream(stdoutPath, 1)
  reopenStream(stderrPath, 2)

# ---------------------------------------------------------------------------
# PID file
# ---------------------------------------------------------------------------

proc writePidFile*(path: string) =
  ## Write our PID to `path`. Creates parent dirs as needed. Mirrors
  ## Bitcoin Core's `CreatePidFile` (init/common.cpp `g_pidfile_path`).
  if path.len == 0:
    return
  let parent = parentDir(path)
  if parent.len > 0 and not dirExists(parent):
    createDir(parent)
  let pid = getpid()
  writeFile(path, $pid & "\n")
  gPidPath = path

proc removePidFile*() =
  ## Delete the PID file we wrote at startup. Safe to call multiple times.
  if gPidPath.len == 0:
    return
  try:
    if fileExists(gPidPath):
      removeFile(gPidPath)
  except OSError:
    discard
  gPidPath = ""

# ---------------------------------------------------------------------------
# Log file routing + SIGHUP reopen
# ---------------------------------------------------------------------------

proc redirectLogToFile*(path: string) =
  ## Append-redirect stdout AND stderr to `path`. Used when the user passes
  ## `--debuglogfile=...` or implicitly after `--daemon` without
  ## `--printtoconsole`.  Tracks `path` for SIGHUP reopen.
  if path.len == 0:
    return
  let parent = parentDir(path)
  if parent.len > 0 and not dirExists(parent):
    createDir(parent)
  let f = open(cstring(path),
               O_WRONLY or O_CREAT or O_APPEND,
               Mode(0o644))
  if f < 0:
    raise newException(IOError,
      "failed to open log file '" & path & "': " & $strerror(errno))
  discard dup2(f, 1)
  discard dup2(f, 2)
  if f != 1 and f != 2:
    discard close(f)
  ensureLogReopenLockInit()
  withLock gLogReopenLock:
    gLogPath = path

proc reopenLog*() =
  ## Reopen the configured log file in-place, replacing FDs 1 and 2.
  ## Called from the SIGHUP handler — must be async-signal-safe-ish, so we
  ## avoid Nim allocator paths and only use POSIX open/dup2/close.
  ensureLogReopenLockInit()
  var path: cstring
  withLock gLogReopenLock:
    if gLogPath.len == 0:
      return
    path = cstring(gLogPath)
    let f = open(path, O_WRONLY or O_CREAT or O_APPEND, Mode(0o644))
    if f < 0:
      return
    discard dup2(f, 1)
    discard dup2(f, 2)
    if f != 1 and f != 2:
      discard close(f)

proc currentLogPath*(): string =
  ## Returns the path most recently passed to redirectLogToFile, or empty.
  ensureLogReopenLockInit()
  withLock gLogReopenLock:
    result = gLogPath

# ---------------------------------------------------------------------------
# Debug-topic mapping (`--debug=net,p2p,...`)
# ---------------------------------------------------------------------------

const KnownDebugCategories* = [
  "net", "p2p", "tor", "mempool", "http", "bench", "zmq",
  "db", "rpc", "addrman", "selectcoins", "reindex", "cmpctblock",
  "rand", "prune", "proxy", "mempoolrej", "libevent", "coindb",
  "qt", "leveldb", "validation", "i2p", "ipc",
  # nimrod-specific
  "sync", "peer", "wallet", "fees", "consensus"
]

proc parseDebugCategories*(spec: string): HashSet[string] =
  ## Split a `--debug=cat1,cat2` string into a set. `--debug=1` and
  ## `--debug=all` enable everything. `--debug=0` / blank disables.
  result = initHashSet[string]()
  if spec.len == 0:
    return
  for raw in spec.split(','):
    let cat = raw.strip().toLowerAscii()
    if cat.len == 0: continue
    if cat == "0" or cat == "none":
      result.clear()
      return
    if cat == "1" or cat == "all":
      result.incl("all")
      return
    result.incl(cat)

proc applyDebugCategories*(cats: HashSet[string]) =
  ## Lower the active log level to debug and enable each requested topic
  ## via chronicles' runtime topic registry.
  if cats.len == 0:
    return
  cr.setLogLevel(LogLevel.DEBUG)
  if "all" in cats:
    # Nothing further to enable: lowering the log level is sufficient because
    # un-tagged (Normal) topics are gated only by the active log level.
    return
  for cat in cats:
    discard cr.setTopicState(cat, cr.TopicState.Enabled, LogLevel.DEBUG)

# ---------------------------------------------------------------------------
# Ready-FD notification (systemd `READY=1` style, but FD-based)
# ---------------------------------------------------------------------------

proc signalReadyFd*(fd: int) =
  ## Write a single `\n` to `fd`. Lets a supervisor process block on a
  ## pipe until the node is up.  Best-effort.
  if fd < 0:
    return
  try:
    let buf = "\n"
    discard posix.write(cint(fd), unsafeAddr buf[0], 1)
    discard close(cint(fd))
  except OSError, IOError:
    discard
