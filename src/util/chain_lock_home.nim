## chain_lock_home.nim — the main thread's side of the chain lock (cs_main).
##
## See storage/chain_lock.nim for the design. This module holds the chronos
## half: the eventfd a foreign thread fires before it blocks on the lock, and
## the main-loop task that hands the lock over at a callback boundary. Kept
## out of storage/ so the chainstate layer does not depend on chronos.

import chronos
import chronos/threadsync
import chronicles
from ../storage/chainstate import ChainState
import ../storage/chain_lock

const DefaultHandoffTickMs* = 50
  ## The hand-over task also wakes on this tick, so a lost eventfd edge costs
  ## a foreign thread at most this long.

type
  ChainLockHome* = ref object
    cs: ChainState
    sig: ThreadSignalPtr
    tickMs: int
    stopped*: bool

proc chainLockWakeFire(arg: pointer) {.nimcall, gcsafe, raises: [].} =
  ## Called by a foreign thread about to block on the chain lock: an eventfd
  ## write that wakes the main loop if it is idle in epoll.
  if arg == nil: return
  discard cast[ThreadSignalPtr](arg).fireSync()

proc handoffLoop(h: ChainLockHome) {.async.} =
  ## Runs on the main loop. Each wake is a callback boundary: no synchronous
  ## main-thread section is in progress, so handing the lock over here never
  ## exposes intermediate state.
  while not h.stopped:
    try:
      if h.sig != nil:
        discard await h.sig.wait().withTimeout(chronos.milliseconds(h.tickMs))
      else:
        await sleepAsync(chronos.milliseconds(h.tickMs))
    except CatchableError:
      discard
    discard h.cs.chainLock.yieldToWaiters()

proc installChainLockHome*(cs: ChainState,
                           tickMs: int = DefaultHandoffTickMs): ChainLockHome =
  ## Make the calling thread (the one running the chronos main loop) the
  ## chain lock's home and start the hand-over task on its loop. Call before
  ## creating any thread that touches chain state.
  result = ChainLockHome(cs: cs, tickMs: tickMs)
  cs.chainLock.becomeHome()
  let sigRes = ThreadSignalPtr.new()
  if sigRes.isErr:
    warn "chain lock: no cross-thread wake-up; foreign threads wait up to one tick",
         tickMs = tickMs, error = sigRes.error
  else:
    result.sig = sigRes.get()
    cs.chainLock.setWake(chainLockWakeFire, cast[pointer](result.sig))
  asyncSpawn handoffLoop(result)

proc stop*(h: ChainLockHome) =
  h.stopped = true
