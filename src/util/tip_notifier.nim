## tip_notifier.nim — wake-on-tip-advance primitive for the wait-family RPCs.
##
## Bitcoin Core registers a `WaitTipChanged` condition (kernel
## `KernelNotifications::blockTip`) that is signalled on every active-chain tip
## update. The `waitfornewblock` / `waitforblock` / `waitforblockheight` RPCs
## (`rpc/blockchain.cpp` lines 290-470) block on it with a deadline, re-checking
## their predicate (new tip / hash match / height >=) after each wake and
## returning the current tip `{hash, height}` on match OR timeout.
##
## `TipNotifier` is the nimrod analogue. It mirrors the proven ouroboros pilot
## (`src/ouroboros/tip_notifier.py`): a monotonic generation counter plus a wake
## mechanism, lost-wakeup-safe.
##
## Concurrency in nimrod
## ---------------------
## Unlike ouroboros (single asyncio loop), nimrod runs the RPC server on its OWN
## OS thread (`src/rpc/rpc_thread.nim`) with a thread-local chronos dispatcher,
## while block connect / reorg run on the main thread. So `notify()` is fired
## from a DIFFERENT thread than the one a waiter `await`s on. A thread-local
## `chronos.AsyncEvent` cannot bridge that gap, so this primitive uses:
##
##   * an `Atomic[int64]` generation counter — the single source of truth for
##     "did the tip move since I snapshotted". Bumped on every tip advance,
##     read by waiters. Atomic loads/stores are safe from any thread.
##   * a `ThreadSignalPtr` (chronos cross-thread eventfd) — fired from the
##     connect/reorg thread, `await`ed on the RPC thread. This is the prompt
##     wake-up so a waiter does not have to busy-poll. `fireSync` is callable
##     from any thread; `wait()` returns a `Future` on the awaiting thread.
##
## The eventfd is single-consumer (one `fire` releases one `wait`). To support
## multiple concurrent waiters correctly, each waiter races `signal.wait()`
## against a short bounded `sleepAsync` cap (`PollCapMs`). Whichever fires first,
## the waiter then re-reads the AUTHORITATIVE database tip and re-checks its
## predicate. Correctness therefore NEVER depends on a `fire` reaching a
## specific waiter — the generation counter + bounded re-poll guarantees every
## waiter observes the tip move within `PollCapMs`, and the eventfd just makes
## the common (single-waiter) case wake in well under a millisecond.
##
## Lost-wakeup safety (the classic race): a waiter snapshots `generation()`,
## checks its predicate against the real DB tip, and only THEN awaits. A
## `notify()` that races in after the predicate check but before the await bumps
## the counter, so the waiter's next snapshot differs and it re-checks
## immediately instead of sleeping. No wake is ever lost.
##
## The shared state is `allocShared`-backed (a raw `ptr`, not a GC ref) so that
## ARC reference counting never runs across threads on it.

import std/atomics
import chronos
import chronos/threadsync

type
  TipNotifierObj = object
    generation: Atomic[int64]
    signal: ThreadSignalPtr

  TipNotifier* = ptr TipNotifierObj
    ## Cross-thread wake-on-tip-advance handle. Created once at boot
    ## (`newTipNotifier`), shared by the chainstate (notify side, main thread)
    ## and the RPC server (wait side, RPC thread). Never freed for the lifetime
    ## of the process.

const
  PollCapMs* = 50
    ## Upper bound (ms) a waiter sleeps between re-checks even if no eventfd
    ## fire reaches it. Bounds the wake latency for the multi-waiter /
    ## coalesced-notify case; 50ms keeps event-wake comfortably sub-second
    ## while adding negligible CPU.

proc newTipNotifier*(): TipNotifier =
  ## Allocate a process-lifetime tip notifier. Returns `nil` if the underlying
  ## cross-thread signal could not be created (caller treats nil as "no
  ## notifier" and the wait RPCs degrade to returning the current tip).
  let sigRes = ThreadSignalPtr.new()
  if sigRes.isErr:
    return nil
  result = cast[TipNotifier](allocShared0(sizeof(TipNotifierObj)))
  result.generation.store(0, moRelaxed)
  result.signal = sigRes.get()

proc monotonicMs*(): int64 =
  ## Current steady-clock time in milliseconds. Exposed so callers in modules
  ## that import `std/times` (whose `milliseconds` clashes with chronos's
  ## `timer.milliseconds`) can do plain integer deadline math without the
  ## ambiguity. Backed by the same monotonic source chronos uses.
  Moment.now().epochNanoSeconds div 1_000_000

proc generation*(n: TipNotifier): int64 =
  ## Current tip-change generation (bumped on every `notify`). Waiters snapshot
  ## this BEFORE checking their predicate so a notify that races in between the
  ## check and the await is observed (no lost wakeup).
  if n == nil: return 0
  n.generation.load(moAcquire)

proc notify*(n: TipNotifier) {.gcsafe, raises: [].} =
  ## Signal that the active-chain tip advanced. Bumps the generation counter
  ## (release ordering, so a waiter that observes the new generation also
  ## observes the new tip the chainstate wrote before calling this) and fires
  ## the cross-thread eventfd to wake any RPC-thread waiter promptly.
  ##
  ## Safe to call from ANY thread (the connect/reorg chokepoints run on the
  ## main thread; submitblock/generate run on the RPC thread). Best-effort: a
  ## signal-fire fault must never stall block connection, so errors are
  ## swallowed — the bounded re-poll in `waitTipChanged` still guarantees the
  ## waiter sees the generation bump.
  if n == nil: return
  discard n.generation.fetchAdd(1, moRelease)
  try:
    discard n.signal.fireSync()
  except CatchableError:
    discard
  except Exception:
    discard

proc waitTipChanged*(n: TipNotifier, lastGen: int64,
                     timeoutMs: int): Future[bool] {.async.} =
  ## Await the next tip change after `lastGen`, or until `timeoutMs` elapses.
  ##
  ## `timeoutMs == 0` waits indefinitely (Core's "no timeout"). Returns `true`
  ## if a tip change (generation bump) was observed within the deadline, `false`
  ## on timeout. EITHER way the caller MUST re-read the authoritative DB tip and
  ## re-evaluate its predicate — this primitive only provides a prompt wake-up,
  ## never the tip value itself.
  if n == nil:
    return false

  # Fast path: a notify already raced in since the caller's snapshot.
  if n.generation.load(moAcquire) != lastGen:
    return true

  # Absolute deadline for the bounded-timeout case. Unused when timeoutMs == 0
  # (wait indefinitely), so a default Moment is fine there.
  let deadline =
    if timeoutMs > 0: Moment.now() + timeoutMs.milliseconds
    else: Moment.now()

  while true:
    # Re-check the generation each iteration so a notify coalesced with another
    # waiter's eventfd consumption is never missed.
    if n.generation.load(moAcquire) != lastGen:
      return true

    # Bound each wait slice to PollCapMs (and to the remaining deadline). The
    # eventfd `wait()` makes the common single-waiter case wake in well under a
    # millisecond; the PollCapMs cap is the safety net for the multi-waiter /
    # coalesced-notify case where a different waiter consumed the one eventfd
    # token, so this waiter must re-check the generation on its own.
    var sliceMs = PollCapMs
    if timeoutMs > 0:
      let remaining = deadline - Moment.now()
      if remaining <= ZeroDuration:
        return false
      let remMs = int(remaining.milliseconds)
      if remMs < sliceMs:
        sliceMs = remMs
      if sliceMs <= 0:
        sliceMs = 1

    # withTimeout awaits the cross-thread eventfd up to `sliceMs`, returning
    # true if it fired (cancelling nothing) or false on the slice timeout
    # (cancelling the pending wait — which only removes the read registration,
    # it does not consume an eventfd token). Either way we loop and re-read the
    # authoritative generation, so correctness never depends on a fire reaching
    # THIS waiter.
    let sigFut = n.signal.wait()
    try:
      discard await withTimeout(sigFut, sliceMs.milliseconds)
    except CancelledError:
      if not sigFut.finished:
        await sigFut.cancelAndWait()
      raise
    # Fully reap the wait before the next iteration registers a fresh one on
    # the same eventfd (withTimeout only schedules the cancel on a slice
    # timeout; it does not await it).
    if not sigFut.finished:
      await sigFut.cancelAndWait()
