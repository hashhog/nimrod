## shutdown.nim — the shutdown-request flag (Core node/interrupt + ShutdownRequested).
##
## Set from the SIGINT/SIGTERM handler (async-signal-safe: one atomic store);
## read by the main loop's shutdown watcher and by long main-thread loops that
## connect many blocks in one synchronous section, which stop between blocks
## so the shutdown is served promptly (Core ActivateBestChain:
## `if (m_chainman.m_interrupt) break;` between ActivateBestChainStep calls).

import std/atomics

var shutdownFlag: Atomic[bool]

proc requestShutdown*() {.inline.} =
  shutdownFlag.store(true, moRelease)

proc shutdownRequested*(): bool {.inline.} =
  shutdownFlag.load(moAcquire)
