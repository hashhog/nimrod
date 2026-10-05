## Bounded parallel script-verification worker pool (CCheckQueue-shaped).
##
## Mirrors Bitcoin Core's CCheckQueue (`bitcoin-core/src/checkqueue.h`):
##   - ONE static pool of extra worker threads, created once at boot and reused
##     across every block (Core constructs the queue once in ChainstateManager
##     with batch_size=128 and feeds it via CCheckQueueControl).
##   - The master thread JOINS as the N-th worker (Core's `Loop(fMaster=true)`).
##   - First-failure short-circuit of *unclaimed* work (Core's `m_result` /
##     `do_work=false`). Already-claimed lower-index checks still finish so the
##     reported failure is the lowest index — worker count cannot change the
##     accept/reject decision or the reject reason.
##   - `-par` mapping matches `chainstatemanager_args.cpp`: 0 = auto, 1 = serial
##     (zero extra workers), extra workers clamped to MAX_SCRIPTCHECK_THREADS=15.
##
## CONSENSUS NOTE: the worker calls the *9-arg* `verifyScriptWithError`, passing
## the full `allAmounts` / `allScriptPubKeys` arrays. The dead
## `perf/parallel_verify.nim` path dropped those (7-arg call) and computed the
## wrong BIP-341 sighash for multi-input Taproot spends.
##
## SAFETY: the only shared mutable state a worker touches is `globalSigCache`
## (lock-protected, `perf/sig_cache.nim`) and the read-only randomized secp256k1
## verify context (`globalContext`, pre-warmed by `initSecp256k1()` BEFORE any
## dispatch). Every `ScriptCheck` is a by-value snapshot; workers never mutate
## the block, the tx, or the UTXO set. Per-worker claimed buffers are bounded
## by ScriptCheckBatchSize (128), matching Core — not O(inputs) and not
## O(threads × inputs).

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
  ## Core: chainstatemanager_args.h `DEFAULT_SCRIPTCHECK_THREADS{0}` (auto).
  DefaultScriptCheckThreads* = 0
  ## Core: CCheckQueue constructed with batch_size=128 (validation.cpp).
  ScriptCheckBatchSize* = 128

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
    ## 9-arg `verifyScriptWithError` needs so a worker thread can run it with
    ## no access to the block / chainstate.
    ##
    ## The BIP-341 committed-prevout arrays (allAmounts / allScriptPubKeys) are
    ## shared across ALL inputs of the same tx via a raw pointer (`prevoutsPtr`)
    ## into a block-level `seq[TxPrevouts]` owned by `verifyScripts`.
    scriptSig*: seq[byte]
    scriptPubKey*: seq[byte]
    tx*: Transaction
    inputIndex*: int
    amount*: Satoshi
    flags*: set[ScriptFlags]
    witness*: seq[seq[byte]]
    prevoutsPtr*: ptr TxPrevouts ## shared per-tx; see TxPrevouts above

  ScriptCheckResult* = object
    ## Verdict of a batch of script checks. `ok` is true iff every check
    ## returned seOk. On failure, `err` / `failIndex` identify the LOWEST
    ## index that failed, so 1 worker and N workers report the same reason
    ## even when several checks would fail.
    ##
    ## Gate 6 — THREE outcomes, not two: `internal` is set when any check did
    ## not produce a script result at all (it raised: OOM, an FFI / secp
    ## context fault, an interpreter bug). That is NOT a script failure and
    ## must never become one: `ok` is false (nothing was proven valid) but the
    ## caller re-runs / halts instead of rejecting the block. `internal`
    ## dominates any script failure seen in the same run.
    ok*: bool
    err*: ScriptError
    failIndex*: int
    internal*: bool
    internalMsg*: string

  ScriptCheckInternalError* = object of CatchableError
    ## Raised by the legacy bool `runChecks*` wrappers when a run was
    ## internal: a bool cannot carry the third outcome, and `false` would be
    ## a script-failure verdict.

  VerifyPool = object
    threads: seq[Thread[pointer]]
    lock: Lock
    workCond: Cond               ## workers wait here for new work / shutdown
    doneCond: Cond               ## master waits here for all work to drain
    checks: ptr seq[ScriptCheck] ## current batch (owned by the master frame)
    nextIdx: int                 ## next un-claimed index into checks[]
    inFlight: int                ## checks claimed-but-not-yet-finished
    bad: Atomic[bool]            ## first-failure short-circuit of unclaimed work
    failIndex: Atomic[int]       ## lowest failing index, -1 if none
    failErr: ScriptError         ## ScriptError at failIndex (written under lock)
    internal: bool               ## a check raised (written under lock)
    internalMsg: string          ## first internal error message (under lock)
    shutdown: bool
    numWorkers: int              ## spawned worker threads (master adds itself)
    started: bool

proc resolveScriptCheckThreads*(par: int): int {.gcsafe.} =
  ## TOTAL verifier threads including the master. Matches Core
  ## `chainstatemanager_args.cpp`:
  ##   script_threads = par
  ##   if par <= 0: script_threads += ncores     # 0 = auto; -n = leave n free
  ##   extra = clamp(script_threads - 1, 0, MAX_SCRIPTCHECK_THREADS)
  ##   total = extra + 1                         # master always counts
  ## So `-par=1` is serial (zero extra workers); `-par=4` is 3 helpers + master.
  var scriptThreads = par
  if scriptThreads <= 0:
    scriptThreads += countProcessors()
  let extra = clamp(scriptThreads - 1, 0, MaxScriptCheckThreads)
  extra + 1

proc clampWorkers*(requested: int): int {.gcsafe.} =
  ## Extra helper threads spawned besides the master (0 = serial).
  ## `requested` is the raw `-par` / `--verify-threads` value.
  resolveScriptCheckThreads(requested) - 1

## Run one ScriptCheck. The {.cast(gcsafe).} is sound: the closure touches only
## (a) by-value fields of `chk`, (b) the read-only `prevoutsPtr` (written once
## by collectChecks before any worker runs, never mutated again), (c) the
## lock-protected globalSigCache, and (d) the read-only secp verify context.
## Mirrors Core's CScriptCheck::operator() running on a worker thread.
# Gate-6 fault injection (tests only; nil in production). When the hook
# returns true for a check, that check dies with a resource-exhaustion
# exception instead of producing a script result — the shape of an OOM, an
# FFI fault or an interpreter bug inside one script check.
var scriptCheckFaultHook*: proc(inputIndex: int): bool {.gcsafe, raises: [].}

proc runOne(chk: ScriptCheck): ScriptError {.gcsafe.} =
  {.cast(gcsafe).}:
    if gInstrument:
      recordThread()
    let fh = scriptCheckFaultHook
    if fh != nil and fh(chk.inputIndex):
      raise newException(ResourceExhaustedError,
        "injected script-check internal error (input " & $chk.inputIndex & ")")
    # Deref the shared per-tx TxPrevouts. The ptr is guaranteed live: the
    # block-level seq[TxPrevouts] lives in verifyScripts (on the master stack)
    # and runChecks blocks until all workers finish before returning.
    let prevouts = chk.prevoutsPtr
    let amounts = if prevouts != nil: prevouts[].allAmounts else: @[chk.amount]
    let scriptPKs = if prevouts != nil: prevouts[].allScriptPubKeys else: @[
        chk.scriptPubKey]
    result = verifyScriptWithError(
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

proc runOneSafe(chk: ScriptCheck): tuple[err: ScriptError, internal: bool,
                                         msg: string] {.gcsafe.} =
  ## runOne with the third outcome made explicit. A check that raises —
  ## including a Defect from an interpreter bug, and on a WORKER thread, where
  ## an escaping exception used to kill the process mid-batch — is recorded as
  ## internal. It is never turned into a ScriptError.
  try:
    result = (err: runOne(chk), internal: false, msg: "")
  except Exception as e:
    result = (err: seOk, internal: true,
              msg: "input " & $chk.inputIndex & ": " & $e.name & ": " & e.msg)

proc recordFailure(q: ptr VerifyPool, idx: int, err: ScriptError) {.inline.} =
  ## Lowest-index failure wins so the reported reason is independent of which
  ## worker finished first. Called with q.lock held.
  let cur = q.failIndex.load(moRelaxed)
  if cur < 0 or idx < cur:
    q.failIndex.store(idx, moRelaxed)
    q.failErr = err
  q.bad.store(true, moRelaxed)

proc claimBatch(q: ptr VerifyPool): tuple[start, n: int] {.inline.} =
  ## Claim up to ScriptCheckBatchSize unclaimed checks. Called with q.lock held.
  ## Returns n=0 when there is nothing to claim (drained, short-circuited, or
  ## no batch published).
  result.start = 0
  result.n = 0
  if q.checks != nil and
     q.nextIdx < q.checks[].len and
     not q.bad.load(moRelaxed):
    let remaining = q.checks[].len - q.nextIdx
    result.n = max(1, min(ScriptCheckBatchSize, remaining))
    result.start = q.nextIdx
    q.nextIdx += result.n
    q.inFlight += result.n

proc runClaimed(q: ptr VerifyPool, start, n: int) {.gcsafe.} =
  ## Execute a claimed [start, start+n) slice in place (no per-worker copy of
  ## the work vector). Skip remaining higher indices once a lower-or-equal
  ## failure is known.
  var localFailIdx = -1
  var localFailErr = seOk
  var localInternal = false
  var localInternalMsg = ""
  for i in 0 ..< n:
    let idx = start + i
    let known = q.failIndex.load(moRelaxed)
    if q.bad.load(moRelaxed) and known >= 0 and idx > known:
      break
    let r = runOneSafe(q.checks[][idx])
    if r.internal:
      # No result for this check: stop, short-circuit the rest of the run
      # (its outcome is internal whatever else fails), report it.
      localInternal = true
      localInternalMsg = r.msg
      break
    if r.err != seOk:
      localFailIdx = idx
      localFailErr = r.err
      # Indices in a claimed slice increase, so this is the lowest in-slice
      # failure. Stop the rest of the slice; lower indices were already
      # claimed by someone else (or already ran in this slice).
      break
  acquire(q.lock)
  if localFailIdx >= 0:
    recordFailure(q, localFailIdx, localFailErr)
  if localInternal:
    if not q.internal:
      q.internal = true
      q.internalMsg = localInternalMsg
    q.bad.store(true, moRelaxed)
  q.inFlight -= n
  let noMoreWork = (q.checks == nil) or
                   (q.nextIdx >= q.checks[].len) or
                   q.bad.load(moRelaxed)
  if noMoreWork and q.inFlight == 0:
    signal(q.doneCond)
  release(q.lock)

proc workerLoop(p: pointer) {.thread, gcsafe.} =
  ## Pull-based worker: claim a bounded batch under the lock, run it outside
  ## the lock, repeat until shutdown. Mirrors CCheckQueue::Loop(fMaster=false).
  let q = cast[ptr VerifyPool](p)
  {.cast(gcsafe).}:
    while true:
      var start = 0
      var n = 0
      acquire(q.lock)
      while true:
        if q.shutdown:
          release(q.lock)
          return
        let claimed = claimBatch(q)
        if claimed.n > 0:
          start = claimed.start
          n = claimed.n
          break
        wait(q.workCond, q.lock)
      release(q.lock)
      runClaimed(q, start, n)

proc startPool(q: var VerifyPool, numWorkers: int) =
  ## Spawn `numWorkers` helper threads against `q`. Caller owns `q` for as
  ## long as the threads run (join before `q` goes out of scope).
  initSecp256k1()
  initLock(q.lock)
  initCond(q.workCond)
  initCond(q.doneCond)
  q.checks = nil
  q.nextIdx = 0
  q.inFlight = 0
  q.failIndex.store(-1, moRelaxed)
  q.failErr = seOk
  q.internal = false
  q.internalMsg = ""
  q.bad.store(false, moRelaxed)
  q.shutdown = false
  q.numWorkers = numWorkers
  q.threads = newSeq[Thread[pointer]](numWorkers)
  q.started = true
  for i in 0 ..< numWorkers:
    createThread(q.threads[i], workerLoop, cast[pointer](addr q))

proc shutdownPool(q: var VerifyPool) =
  if not q.started:
    return
  acquire(q.lock)
  q.shutdown = true
  broadcast(q.workCond)
  release(q.lock)
  for i in 0 ..< q.threads.len:
    joinThread(q.threads[i])
  deinitCond(q.workCond)
  deinitCond(q.doneCond)
  deinitLock(q.lock)
  q.started = false
  q.numWorkers = 0
  q.threads = @[]

proc completeOn(q: ptr VerifyPool, checks: var seq[
    ScriptCheck]): ScriptCheckResult {.gcsafe.} =
  ## Run every check across `q`, master joining as a worker. Returns the
  ## lowest-index failure if any check fails. CALLER must have started `q`.
  ##
  ## `addr checks` stays valid because this proc blocks until every claimed
  ## check finishes (inFlight==0) before returning.
  if checks.len == 0:
    return ScriptCheckResult(ok: true, err: seOk, failIndex: -1)

  acquire(q.lock)
  q.checks = addr checks
  q.nextIdx = 0
  q.inFlight = 0
  q.bad.store(false, moRelaxed)
  q.failIndex.store(-1, moRelaxed)
  q.failErr = seOk
  q.internal = false
  q.internalMsg = ""
  broadcast(q.workCond)
  release(q.lock)

  # Master joins as the (N+1)-th worker.
  while true:
    acquire(q.lock)
    let claimed = claimBatch(q)
    release(q.lock)
    if claimed.n == 0:
      break
    runClaimed(q, claimed.start, claimed.n)

  acquire(q.lock)
  while q.inFlight > 0:
    wait(q.doneCond, q.lock)
  q.checks = nil
  let fi = q.failIndex.load(moRelaxed)
  let err = q.failErr
  let internal = q.internal
  let internalMsg = q.internalMsg
  release(q.lock)

  if internal:
    ScriptCheckResult(ok: false, err: seOk, failIndex: -1, internal: true,
                      internalMsg: internalMsg)
  elif fi >= 0:
    ScriptCheckResult(ok: false, err: err, failIndex: fi)
  else:
    ScriptCheckResult(ok: true, err: seOk, failIndex: -1)

var gPool: VerifyPool
var gPoolLock: Lock
var gPoolLockInit = false

proc ensurePoolImpl(numWorkers: int) =
  ## Construct the static process pool exactly once. Subsequent calls are
  ## no-ops; the worker count is fixed for the process lifetime.
  if not gPoolLockInit:
    initLock(gPoolLock)
    gPoolLockInit = true
  withLock gPoolLock:
    if gPool.started:
      return
    if numWorkers <= 0:
      return
    startPool(gPool, numWorkers)

proc ensurePool(numWorkers: int) {.gcsafe.} =
  {.cast(gcsafe).}:
    ensurePoolImpl(numWorkers)

proc poolWorkerCount*(): int {.gcsafe.} =
  ## Number of spawned helper threads (0 if the pool was never started, which
  ## is the `-par=1` serial path). Total verifier count is this + 1 when the
  ## pool is up, or 1 when it is not.
  {.cast(gcsafe).}:
    result = if gPool.started: gPool.numWorkers else: 0

proc runChecksSerialDetailed*(checks: openArray[
    ScriptCheck]): ScriptCheckResult {.gcsafe.} =
  ## Single-threaded reference path. First failure in index order is the
  ## reported reason — identical to the parallel lowest-index rule because
  ## claiming is sequential from 0.
  for i, chk in checks:
    let r = runOneSafe(chk)
    if r.internal:
      return ScriptCheckResult(ok: false, err: seOk, failIndex: -1,
                               internal: true, internalMsg: r.msg)
    if r.err != seOk:
      return ScriptCheckResult(ok: false, err: r.err, failIndex: i)
  ScriptCheckResult(ok: true, err: seOk, failIndex: -1)

proc boolOrRaise(r: ScriptCheckResult): bool =
  if r.internal:
    raise newException(ScriptCheckInternalError,
                       "script check internal error: " & r.internalMsg)
  r.ok

proc runChecksSerial*(checks: seq[ScriptCheck]): bool {.gcsafe.} =
  boolOrRaise(runChecksSerialDetailed(checks))

proc runChecksParallel*(checks: var seq[ScriptCheck]): bool {.gcsafe.} =
  ## gcsafe wrapper around the process-global pool. Caller must have started
  ## the pool via initVerifyPool (extra workers > 0).
  {.cast(gcsafe).}:
    result = boolOrRaise(completeOn(addr gPool, checks))

proc initVerifyPool*(numVerifyWorkers: int) {.gcsafe.} =
  ## Node-startup hook: pre-warm secp and spawn the static pool when `-par`
  ## resolves to extra workers. `numVerifyWorkers` is the raw CLI `-par` /
  ## `--verify-threads` value (0 = auto, 1 = serial). Idempotent. `-par=1`
  ## leaves the pool unstarted so `runChecks` takes the serial path, matching
  ## Core's `CCheckQueue::HasThreads() == false`.
  let extra = clampWorkers(numVerifyWorkers)
  if extra > 0:
    ensurePool(extra)
  else:
    # Still pre-warm secp on the main thread so a later serial verify does
    # not race a lazy context_create.
    initSecp256k1()

proc runChecksDetailed*(checks: var seq[ScriptCheck]): ScriptCheckResult {.gcsafe.} =
  ## Dispatch: parallel if the static pool is up AND there is work, else serial.
  ## The pool MUST be started by `initVerifyPool` at boot for the parallel path
  ## to engage; if it was never started (`-par=1`, or a unit test calling
  ## verifyScripts directly) we fall back to the serial path, which is
  ## verdict-identical.
  {.cast(gcsafe).}:
    if gPool.started and gPool.numWorkers > 0 and checks.len > 0:
      result = completeOn(addr gPool, checks)
    else:
      result = runChecksSerialDetailed(checks)

proc runChecks*(checks: var seq[ScriptCheck]): bool {.gcsafe.} =
  ## Legacy bool form. An internal run RAISES ScriptCheckInternalError — it is
  ## never reported as `false` (which every caller reads as a script failure).
  boolOrRaise(runChecksDetailed(checks))

proc runChecksWithN*(nTotal: int, checks: var seq[
    ScriptCheck]): ScriptCheckResult {.gcsafe.} =
  ## Test/control path: run `checks` with exactly `nTotal` verifier threads
  ## (1 = serial; N = N-1 helpers + master). Does NOT touch the process-global
  ## pool, so 1-vs-2-vs-4-vs-8 can be measured in one process. Extra workers
  ## are capped at MaxScriptCheckThreads so a typo cannot spawn hundreds of
  ## Nim threads.
  let n = max(1, min(nTotal, MaxScriptCheckThreads + 1))
  if n == 1 or checks.len == 0:
    return runChecksSerialDetailed(checks)
  {.cast(gcsafe).}:
    var q: VerifyPool
    startPool(q, n - 1)
    result = completeOn(addr q, checks)
    shutdownPool(q)
