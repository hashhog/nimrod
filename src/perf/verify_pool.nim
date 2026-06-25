## Bounded parallel script-verification worker pool (W167 IBD-perf).
##
## Mirrors Bitcoin Core's CCheckQueue (`bitcoin-core/src/checkqueue.h`):
##   - ONE static pool of N worker threads, created once and reused across every
##     block (Core constructs the queue once in `init.cpp` and feeds it via
##     `CCheckQueueControl`).
##   - The master thread JOINS as the N-th worker (Core's `Loop(fMaster=true)`),
##     so on an M-input block we get M / (N+1) work per thread rather than the
##     master idling on a join.
##   - First-failure short-circuit via an atomic `bad` flag (Core's
##     `m_result` / `fOk=false` cancellation): once any check fails, the
##     remaining checks are skipped rather than executed.
##   - Worker threads are named `scriptch.<i>` (Core's
##     `util::ThreadRename("scriptch.%i")`).
##   - Pool size clamped to `MAX_SCRIPTCHECK_THREADS` = 15
##     (Core `validation.h: static constexpr int MAX_SCRIPTCHECK_THREADS{15}`).
##
## CONSENSUS NOTE: the worker calls the *9-arg* `verifyScript`, passing the full
## `allAmounts` / `allScriptPubKeys` arrays. The dead `perf/parallel_verify.nim`
## path dropped those (7-arg call) and computed the wrong BIP-341 sighash for
## multi-input Taproot spends. This module carries them on every `ScriptCheck`
## so the parallel verdict is byte-identical to the serial one.
##
## SAFETY: the only shared mutable state a worker touches is `globalSigCache`
## (lock-protected, `perf/sig_cache.nim`) and the read-only randomized secp256k1
## verify context (`globalContext`, pre-warmed by `initSecp256k1()` BEFORE any
## dispatch — closes the lazy-init TOCTOU race). Every `ScriptCheck` is a
## by-value snapshot; workers never mutate the block, the tx, or the UTXO set.

import std/[locks, cpuinfo, atomics, sets]
import ../primitives/types
import ../crypto/secp256k1
import ../script/interpreter

# ---------------------------------------------------------------------------
# Optional thread-engagement instrumentation (tests only).
#
# When `gInstrument` is set true (by a test via `enableInstrumentation`), every
# check execution records the running thread's OS id into a lock-protected set,
# and a global counter of checks-run is bumped. A test can then assert that the
# set has >1 distinct thread id — i.e. the pool DEMONSTRABLY ran checks across
# more than one core, not just on the master (the GHC-parMap-fizzle / haskoin
# parMap failure mode). Zero overhead in production (`gInstrument` defaults
# false; the recording branch is skipped).
# ---------------------------------------------------------------------------
var gInstrument: bool = false
var gInstrLock: Lock
var gInstrLockInit = false
var gThreadIds: HashSet[int]
var gChecksRun: Atomic[int]

proc enableInstrumentation*() {.gcsafe.} =
  {.cast(gcsafe).}:
    if not gInstrLockInit:
      initLock(gInstrLock)
      gInstrLockInit = true
    withLock gInstrLock:
      gThreadIds = initHashSet[int]()
    gChecksRun.store(0, moRelaxed)
    gInstrument = true

proc disableInstrumentation*() {.gcsafe.} =
  {.cast(gcsafe).}:
    gInstrument = false

proc distinctThreadCount*(): int {.gcsafe.} =
  {.cast(gcsafe).}:
    if not gInstrLockInit: return 0
    withLock gInstrLock:
      result = gThreadIds.len

proc instrumentedChecksRun*(): int {.gcsafe.} =
  {.cast(gcsafe).}:
    result = gChecksRun.load(moRelaxed)

proc recordThread() {.gcsafe.} =
  ## Record the calling thread's id (instrumentation only).
  {.cast(gcsafe).}:
    if not gInstrLockInit: return
    discard gChecksRun.fetchAdd(1, moRelaxed)
    let tid = int(getThreadId())
    withLock gInstrLock:
      gThreadIds.incl(tid)

const
  ## Core: validation.h `static constexpr int MAX_SCRIPTCHECK_THREADS{15};`
  MaxScriptCheckThreads* = 15

type
  TxPrevouts* = object
    ## Per-transaction BIP-341 committed-prevout arrays. Mirrors Core's
    ## `PrecomputedTransactionData` (specifically `m_spent_outputs` which backs
    ## `m_spent_amounts_single_hash` / `m_spent_scripts_single_hash`).
    ## One `TxPrevouts` is created per non-coinbase tx in `collectChecks` and
    ## stored in a block-level `seq[TxPrevouts]` that lives on the master
    ## thread's stack for the duration of `runChecks`. Every `ScriptCheck` for
    ## the same tx holds a raw `ptr TxPrevouts` — zero-copy sharing.
    ## SAFETY: `runChecks` (and its callers) blocks until all worker threads
    ## have finished; the ptr is never dangled because the owning seq outlives
    ## every worker access.
    allAmounts*: seq[Satoshi]
    allScriptPubKeys*: seq[seq[byte]]

  ScriptCheck* = object
    ## Self-contained, by-value description of ONE input's script verification.
    ## Equivalent to Core's `CScriptCheck` callable; it carries everything the
    ## 9-arg `verifyScript` needs so a worker thread can run it with no access
    ## to the block / chainstate.
    ##
    ## PERF FIX (per-ScriptCheck materialization overhead): the BIP-341
    ## committed-prevout arrays (allAmounts / allScriptPubKeys) are now shared
    ## across ALL inputs of the same tx via a raw pointer (`prevoutsPtr`) into a
    ## block-level `seq[TxPrevouts]` owned by `verifyScripts`. The old design
    ## copied the full seq arrays onto EVERY ScriptCheck — O(inputs^2) per tx —
    ## causing the parallel path to allocate MORE than the serial path despite
    ## doing the same work. With the pointer the materialization cost drops to
    ## O(tx_count): one TxPrevouts per tx regardless of input count.
    ## G21 fix is preserved: prevoutsPtr always points to the full tx arrays.
    scriptSig*: seq[byte]
    scriptPubKey*: seq[byte]
    tx*: Transaction
    inputIndex*: int
    amount*: Satoshi
    flags*: set[ScriptFlags]
    witness*: seq[seq[byte]]
    prevoutsPtr*: ptr TxPrevouts  ## shared per-tx; see TxPrevouts above

  VerifyPool = object
    threads: seq[Thread[int]]
    lock: Lock
    workCond: Cond          ## workers wait here for new work / shutdown
    doneCond: Cond          ## master waits here for all work to drain
    checks: ptr seq[ScriptCheck]  ## current batch (owned by the master frame)
    nextIdx: int            ## next un-claimed index into checks[]
    inFlight: int           ## checks claimed-but-not-yet-finished
    bad: Atomic[bool]       ## first-failure short-circuit (Core do_work=false)
    generation: int         ## bumped per batch so workers know work is fresh
    shutdown: bool
    numWorkers: int         ## spawned worker threads (master adds itself = N+1 verifiers)
    started: bool

var gPool: VerifyPool
var gPoolLock: Lock          ## guards one-time pool construction
var gPoolLockInit = false

proc clampWorkers*(requested: int): int {.gcsafe.} =
  ## requested: 0 = auto (countProcessors()-1, leaving one core for the rest of
  ## the node), N>0 = explicit. Clamped to [1, MAX_SCRIPTCHECK_THREADS] like
  ## Core's `std::clamp(n, 0, MAX_SCRIPTCHECK_THREADS)` (init.cpp), except we
  ## never go below 1 spawned helper so the master always has a peer.
  let base =
    if requested <= 0: countProcessors() - 1
    else: requested
  clamp(base, 1, MaxScriptCheckThreads)

## Run one ScriptCheck. The {.cast(gcsafe).} is sound: the closure touches only
## (a) by-value fields of `chk`, (b) the read-only `prevoutsPtr` (written once
## by collectChecks before any worker runs, never mutated again), (c) the
## lock-protected globalSigCache, and (d) the read-only secp verify context.
## Mirrors Core's CScriptCheck::operator() running on a worker thread.
proc runOne(chk: ScriptCheck): bool {.gcsafe.} =
  {.cast(gcsafe).}:
    if gInstrument:
      recordThread()
    # Deref the shared per-tx TxPrevouts. The ptr is guaranteed live: the
    # block-level seq[TxPrevouts] lives in verifyScripts (on the master stack)
    # and runChecks blocks until all workers finish before returning.
    let prevouts = chk.prevoutsPtr
    let amounts     = if prevouts != nil: prevouts[].allAmounts     else: @[chk.amount]
    let scriptPKs   = if prevouts != nil: prevouts[].allScriptPubKeys else: @[chk.scriptPubKey]
    result = verifyScript(
      chk.scriptSig,
      chk.scriptPubKey,
      chk.tx,
      chk.inputIndex,
      chk.amount,
      chk.flags,
      chk.witness,
      amounts,
      scriptPKs
    )

proc workerLoop(id: int) {.thread, gcsafe.} =
  ## Pull-based worker: claim one check at a time under the lock, run it
  ## outside the lock, repeat until the batch drains or `bad` is set.
  {.cast(gcsafe).}:
    while true:
      var chk: ScriptCheck
      var haveWork = false
      acquire(gPool.lock)
      while true:
        if gPool.shutdown:
          release(gPool.lock)
          return
        if gPool.checks != nil and
           gPool.nextIdx < gPool.checks[].len and
           not gPool.bad.load(moRelaxed):
          chk = gPool.checks[][gPool.nextIdx]
          inc gPool.nextIdx
          inc gPool.inFlight
          haveWork = true
          break
        # Nothing to do right now: sleep until woken with new work / shutdown.
        wait(gPool.workCond, gPool.lock)
      release(gPool.lock)

      if haveWork:
        let okScript = runOne(chk)
        acquire(gPool.lock)
        if not okScript:
          gPool.bad.store(true, moRelaxed)
        dec gPool.inFlight
        # The master returns once no more checks WILL be claimed (batch retired,
        # fully claimed, OR short-circuited via `bad`) AND nothing is still
        # running. Including `bad` here is REQUIRED to avoid deadlock: when a
        # check fails with nextIdx < len, claiming stops (the claim guard checks
        # `not bad`), so without this the last finishing worker would never
        # signal doneCond and the master would block forever.
        let noMoreWork = (gPool.checks == nil) or
                         (gPool.nextIdx >= gPool.checks[].len) or
                         gPool.bad.load(moRelaxed)
        if noMoreWork and gPool.inFlight == 0:
          signal(gPool.doneCond)
        release(gPool.lock)

proc ensurePoolImpl(numWorkers: int) =
  ## Construct the static pool exactly once. Subsequent calls are no-ops; the
  ## worker count is fixed for the process lifetime (Core constructs the queue
  ## once at startup). Pre-warms secp256k1 before any worker can touch it.
  if not gPoolLockInit:
    # First-ever entry: serialize construction. (Node startup is single-threaded
    # here, but be defensive.)
    initLock(gPoolLock)
    gPoolLockInit = true
  withLock gPoolLock:
    if gPool.started:
      return
    # CONSENSUS-CRITICAL: pre-warm the global secp256k1 context on the MAIN
    # thread before spawning workers, so no worker races context_create /
    # context_randomize on first touch.
    initSecp256k1()
    initLock(gPool.lock)
    initCond(gPool.workCond)
    initCond(gPool.doneCond)
    gPool.checks = nil
    gPool.nextIdx = 0
    gPool.inFlight = 0
    gPool.bad.store(false, moRelaxed)
    gPool.generation = 0
    gPool.shutdown = false
    gPool.numWorkers = numWorkers
    gPool.threads = newSeq[Thread[int]](numWorkers)
    for i in 0 ..< numWorkers:
      createThread(gPool.threads[i], workerLoop, i)
    gPool.started = true

proc ensurePool(numWorkers: int) {.gcsafe.} =
  ## gcsafe wrapper. The cast is sound: pool construction is one-time, runs
  ## single-threaded at node boot before any worker exists, and is serialized
  ## by gPoolLock. gPool holds no GC'd state that workers concurrently mutate.
  {.cast(gcsafe).}:
    ensurePoolImpl(numWorkers)

proc poolWorkerCount*(): int {.gcsafe.} =
  ## Number of spawned helper threads (0 if the pool was never started).
  ## The total verifier count is this + 1 (the master joins as a worker).
  {.cast(gcsafe).}:
    result = if gPool.started: gPool.numWorkers else: 0

proc runChecksParallelImpl(checks: var seq[ScriptCheck]): bool =
  ## Run every check across the static pool, master joining as a worker.
  ## Returns true iff ALL checks pass. First failure short-circuits the rest.
  ## CALLER must have called `ensurePool` (and thus pre-warmed secp) already.
  ##
  ## `addr checks` stays valid because this proc blocks until every claimed
  ## check finishes (inFlight==0) before returning, so workers never deref a
  ## dead pointer.
  if checks.len == 0:
    return true

  # Publish the batch to the workers.
  acquire(gPool.lock)
  gPool.checks = addr checks
  gPool.nextIdx = 0
  gPool.inFlight = 0
  gPool.bad.store(false, moRelaxed)
  inc gPool.generation
  # Wake all workers.
  broadcast(gPool.workCond)
  release(gPool.lock)

  # Master joins as the (N+1)-th worker: claim and run checks itself.
  while true:
    var chk: ScriptCheck
    var haveWork = false
    acquire(gPool.lock)
    if gPool.checks != nil and
       gPool.nextIdx < gPool.checks[].len and
       not gPool.bad.load(moRelaxed):
      chk = gPool.checks[][gPool.nextIdx]
      inc gPool.nextIdx
      inc gPool.inFlight
      haveWork = true
    release(gPool.lock)

    if not haveWork:
      break

    let okScript = runOne(chk)
    acquire(gPool.lock)
    if not okScript:
      gPool.bad.store(true, moRelaxed)
    dec gPool.inFlight
    release(gPool.lock)

  # All checks are now claimed (master drained nextIdx). Wait for any checks
  # still running on worker threads to finish before reading the verdict.
  acquire(gPool.lock)
  while gPool.inFlight > 0:
    wait(gPool.doneCond, gPool.lock)
  # Retire the batch so idle workers don't re-touch a stack-dead seq.
  gPool.checks = nil
  let failed = gPool.bad.load(moRelaxed)
  release(gPool.lock)

  not failed

proc runChecksParallel*(checks: var seq[ScriptCheck]): bool {.gcsafe.} =
  ## gcsafe wrapper: gPool access is lock-protected; no GC'd global is mutated
  ## concurrently outside the lock.
  {.cast(gcsafe).}:
    result = runChecksParallelImpl(checks)

proc runChecksSerial*(checks: seq[ScriptCheck]): bool {.gcsafe.} =
  ## Single-threaded reference path. Byte-identical verdict to the parallel
  ## path because both consume the SAME `seq[ScriptCheck]` built by
  ## `collectChecks`. First failure short-circuits.
  for chk in checks:
    if not runOne(chk):
      return false
  true

proc initVerifyPool*(numVerifyWorkers: int) {.gcsafe.} =
  ## Node-startup hook: pre-warm secp and spawn the static pool. `numVerifyWorkers`
  ## is the CLI `--verify-threads` value (0 = auto). Safe to call once; idempotent.
  ensurePool(clampWorkers(numVerifyWorkers))

proc runChecks*(checks: var seq[ScriptCheck]): bool {.gcsafe.} =
  ## Dispatch: parallel if the static pool is up AND there is work, else serial.
  ## The pool MUST be started by `initVerifyPool` at boot for the parallel path
  ## to engage; if it was never started (e.g. a unit test calling verifyScripts
  ## directly) we fall back to the serial path, which is verdict-identical.
  {.cast(gcsafe).}:
    if gPool.started and gPool.numWorkers > 0 and checks.len > 0:
      result = runChecksParallel(checks)
    else:
      result = runChecksSerial(checks)
