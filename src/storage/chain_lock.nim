## chain_lock.nim — nimrod's cs_main.
##
## ONE recursive lock serialises every chainstate mutation (connect,
## disconnect, reorg, IBD batch flush, UTXO-cache flush, invalidate /
## reconsider, snapshot load), every mempool mutation, and every read of chain
## / coin / mempool state made from a thread other than the main thread.
## Bitcoin Core does the same with `cs_main` (validation.cpp: ProcessNewBlock
## -> AcceptBlock / ActivateBestChain -> ConnectTip all run under it;
## rpc/blockchain.cpp gettxout takes LOCK(cs_main) for the whole call).
##
## Why it exists: nimrod runs the JSON-RPC server, the REST server, the wallet
## rescan and the retained-body audit on their own OS threads with direct
## access to the SAME ChainState / Mempool the main thread (P2P + sync)
## mutates. Up to a0da75f nothing serialised them: submitblock connected a
## block on the RPC thread while sync connected a competitor on the main
## thread, and both committed at the same height (tests/test_chain_lock_race).
##
## THE HOME THREAD
## ---------------
## The main thread runs a chronos event loop: P2P message handlers, the sync
## loop, relay timers and the mempool all read chain state from many async
## procs, between many `await`s. Locking every one of those reads by hand is
## an audit nobody would finish and a rule the next edit would break. So the
## main thread is the lock's HOME: in the running node it acquires the lock
## once at startup (`becomeHome`) and holds it at all times, except when it
## hands it over.
##
## A foreign thread (RPC, REST, wallet rescan, body audit) that wants the lock
## registers as a waiter and wakes the home thread (`wakeFn`, wired by
## src/nimrod.nim to a chronos ThreadSignalPtr). The home thread's yield task
## runs as an ordinary chronos callback — i.e. BETWEEN callbacks, never inside
## a synchronous section — and calls `yieldToWaiters`, which releases the
## lock until every registered waiter has had it, then takes it back. So:
##
##   * every main-thread read and write is covered with no per-call-site
##     locking, and new main-thread code is covered automatically;
##   * a foreign thread observes chain state only at main-thread callback
##     boundaries — exactly the states other main-thread async tasks already
##     observe across an `await`;
##   * a foreign thread's wait is bounded by the main thread's longest
##     SYNCHRONOUS section (one block connect, one message handler), never by
##     network latency: an `await` on the network is a callback boundary, and
##     the yield task gets to run there. The lock is therefore never held
##     ACROSS network I/O in the sense that matters — no waiter ever waits for
##     a peer.
##
## Outside the running node (unit tests, CLI import) there is no home thread
## and the lock is an ordinary recursive mutex.
##
## LOCK ORDER (acquire left to right only; never acquire a lock to the left
## while holding one to the right):
##
##   ChainLock  ->  WalletManager.walletsLock  ->  ChainState.bodyRepairStageLock
##              ->  verify-pool queue lock      ->  RocksDB / allocator internals
##
## The mempool and the fee estimator have no lock of their own: they are
## covered by ChainLock (Core takes mempool.cs after cs_main; nimrod folds it
## in). The tip notifier is lock-free (atomics + eventfd). Nothing that holds
## walletsLock calls into ChainState.
##
## RULES
##   * Never hold the lock across an `await`. `withChainLock` bodies must be
##     synchronous. (The home thread's base hold is the one sanctioned
##     exception, and it is released at every callback boundary on demand.)
##   * Never block the home thread on a foreign thread that may be waiting for
##     the lock (shutdown waits are bounded and say so).
##   * A long foreign operation (wallet rescan, filter scan) calls
##     `yieldHeld` between units of work so the main thread is not stalled.

import std/[locks, atomics, monotimes, times]
from std/posix import sched_yield

type
  ChainLock* = object
    m: Lock
    owner: Atomic[int]      ## getThreadId() of the holder; 0 = free
    depth: int              ## recursion depth; touched only by the holder
    waiters: Atomic[int]    ## foreign threads registered to acquire
    home: Atomic[int]       ## thread that holds the lock by default (0 = none)
    wakeFn: proc(arg: pointer) {.nimcall, gcsafe, raises: [].}
    wakeArg: pointer
    handoffs: Atomic[int64] ## yields that let at least one waiter in (stats)
    homeBlocked: Atomic[bool] ## home thread is blocked re-taking the lock

const YieldSpinBudget = initDuration(milliseconds = 50)
  ## How long the home thread keeps the lock released while waiters keep
  ## arriving, before it takes the lock back regardless (anti-starvation for
  ## the main thread under an RPC flood).

proc initChainLock*(cl: var ChainLock) =
  initLock(cl.m)
  cl.owner.store(0)
  cl.depth = 0
  cl.waiters.store(0)
  cl.home.store(0)
  cl.wakeFn = nil
  cl.wakeArg = nil

proc heldByMe*(cl: var ChainLock): bool {.inline.} =
  cl.owner.load(moAcquire) == getThreadId()

proc depthHeld*(cl: var ChainLock): int {.inline.} =
  ## Recursion depth if the calling thread holds the lock, else 0.
  if cl.heldByMe: cl.depth else: 0

proc waiterCount*(cl: var ChainLock): int {.inline.} =
  cl.waiters.load(moAcquire)

proc handoffCount*(cl: var ChainLock): int64 {.inline.} =
  cl.handoffs.load(moRelaxed)

proc isHomeThread*(cl: var ChainLock): bool {.inline.} =
  cl.home.load(moAcquire) == getThreadId()

proc takeOwnership(cl: var ChainLock, depth: int) {.inline.} =
  cl.owner.store(getThreadId(), moRelease)
  cl.depth = depth

proc acquireChain*(cl: var ChainLock) {.gcsafe, raises: [].} =
  ## Recursive acquire. A thread that is not the holder registers as a waiter
  ## and wakes the home thread before blocking, so a home thread idle in its
  ## event loop hands the lock over within one callback.
  if cl.heldByMe:
    inc cl.depth
    return
  if not cl.m.tryAcquire():
    discard cl.waiters.fetchAdd(1, moAcquireRelease)
    let fn = cl.wakeFn
    if fn != nil:
      fn(cl.wakeArg)
    cl.m.acquire()
    discard cl.waiters.fetchSub(1, moAcquireRelease)
  cl.takeOwnership(1)

proc releaseChain*(cl: var ChainLock) {.gcsafe, raises: [].} =
  doAssert cl.heldByMe, "ChainLock released by a thread that does not hold it"
  dec cl.depth
  if cl.depth == 0:
    cl.owner.store(0, moRelease)
    cl.m.release()

template withChainLock*(cl: var ChainLock, body: untyped) =
  ## Hold the chain lock (recursively) for `body`. `body` must be synchronous:
  ## never `await` inside it.
  acquireChain(cl)
  try:
    body
  finally:
    releaseChain(cl)

proc letWaitersThrough(cl: var ChainLock, savedDepth: int) {.gcsafe, raises: [].} =
  ## Fully release (the caller holds at `savedDepth`), keep it released while
  ## registered waiters take their turn (bounded by YieldSpinBudget), then take
  ## it back at the same depth.
  cl.depth = 0
  cl.owner.store(0, moRelease)
  cl.m.release()
  let deadline = getMonoTime() + YieldSpinBudget
  while cl.waiters.load(moAcquire) > 0 and getMonoTime() < deadline:
    discard sched_yield()
  cl.homeBlocked.store(true, moRelease)
  cl.m.acquire()
  cl.homeBlocked.store(false, moRelease)
  cl.takeOwnership(savedDepth)
  discard cl.handoffs.fetchAdd(1, moRelaxed)

proc yieldToWaiters*(cl: var ChainLock): bool {.gcsafe, raises: [].} =
  ## Home thread only, at its BASE hold (depth 1 — i.e. not inside any
  ## withChainLock section). Returns true when it let at least one waiter in.
  ## A no-op at a deeper depth: the caller is inside a critical section and a
  ## foreign thread must not see its intermediate state.
  if cl.waiters.load(moAcquire) == 0:
    return false
  if not cl.heldByMe or cl.depth != 1:
    return false
  cl.letWaitersThrough(1)
  true

proc yieldForShutdown*(cl: var ChainLock): bool {.gcsafe, raises: [].} =
  ## Shutdown only: the caller is waiting (bounded) for a background thread to
  ## exit, and that thread may be blocked acquiring the lock. Let waiters
  ## through at ANY depth. Not for normal operation — at depth > 1 the caller
  ## is inside a critical section.
  if cl.waiters.load(moAcquire) == 0 or not cl.heldByMe:
    return false
  cl.letWaitersThrough(cl.depth)
  true

proc yieldHeld*(cl: var ChainLock): bool {.gcsafe, raises: [].} =
  ## For a long operation that holds the lock at depth 1 and has reached a
  ## point where its own state is consistent (between blocks of a rescan): let
  ## whoever is waiting run, then continue. Callers up the stack must not rely
  ## on chain state being unchanged across this call (Core's rescan runs
  ## without cs_main between blocks for the same reason).
  ##
  ## On the home thread this is `yieldToWaiters`. On a foreign thread the home
  ## thread is usually the one waiting: it is blocked re-taking the lock after
  ## handing it over, so release, let it in (bounded wait), and re-acquire as
  ## an ordinary waiter (which wakes it to hand the lock back at its next
  ## callback boundary).
  if cl.isHomeThread:
    return cl.yieldToWaiters()
  if not cl.heldByMe or cl.depth != 1:
    return false
  if not cl.homeBlocked.load(moAcquire) and cl.waiters.load(moAcquire) == 0:
    return false
  cl.depth = 0
  cl.owner.store(0, moRelease)
  cl.m.release()
  # Do not barge straight back in: wait until someone else has taken it.
  let deadline = getMonoTime() + initDuration(milliseconds = 10)
  while cl.owner.load(moAcquire) == 0 and getMonoTime() < deadline:
    discard sched_yield()
  cl.acquireChain()
  true

proc setWake*(cl: var ChainLock, fn: proc(arg: pointer) {.nimcall, gcsafe, raises: [].},
              arg: pointer) =
  ## Wire the home thread's wake-up. Call before any foreign thread starts.
  cl.wakeArg = arg
  cl.wakeFn = fn

proc becomeHome*(cl: var ChainLock) =
  ## Called once by the main thread before it starts any thread that touches
  ## chain state. From here on the calling thread holds the lock at depth 1
  ## (its base hold) and hands it over in `yieldToWaiters`.
  acquireChain(cl)
  cl.home.store(getThreadId(), moRelease)
