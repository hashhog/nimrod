## Chain lock hand-over (storage/chain_lock.nim + util/chain_lock_home.nim).
##
## In the running node the main thread holds the chain lock by default and
## hands it to foreign threads (RPC, REST, rescan, audit) only at chronos
## callback boundaries. These tests drive the exact production pieces —
## ChainState.chainLock, installChainLockHome, the hand-over task — on a real
## chronos loop with a real second OS thread, and check:
##
##   1. a foreign thread gets the lock promptly while the home loop is idle
##      (the eventfd wake works, not just the fallback tick);
##   2. a synchronous main-thread section is NEVER interleaved with a foreign
##      holder — with a control showing the same instrument DOES see the
##      interleaving when the main thread does not hold the lock (the
##      pre-fix state of every main-thread read);
##   3. a long foreign hold that calls yieldHeld between units lets the main
##      loop run; without yieldHeld it does not (control).
##
## The foreign threads here allocate nothing on the Nim heap that outlives
## them (ints and atomics only), so joining them is safe.

import unittest2
import std/[os, atomics, monotimes, times]
import chronos
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/util/chain_lock_home

proc freshChainState(path: string): ChainState =
  removeDir(path)
  newChainState(path, regtestParams())

# --- shared between the main thread and the foreign thread -----------------
var gCs: ptr ChainLock
var gStop: Atomic[bool]
var gA, gB: Atomic[int]            # updated by the main thread's sync section
var gObserved: Atomic[int]         # foreign observations of (gA, gB)
var gTorn: Atomic[int]             # observations with gA != gB
var gAcquiredNs: Atomic[int64]     # foreign acquire latency
var gUnitsDone: Atomic[int]
var gUseYield: Atomic[bool]
var gForeignHolding: Atomic[bool]
var gWorkerDone: Atomic[bool]

proc acquireOnce(arg: int) {.thread.} =
  let t0 = getMonoTime()
  acquireChain(gCs[])
  gAcquiredNs.store((getMonoTime() - t0).inNanoseconds)
  releaseChain(gCs[])

proc observer(arg: int) {.thread.} =
  # Repeatedly take the lock and look at the pair the main thread updates.
  while not gStop.load(moAcquire):
    acquireChain(gCs[])
    let a = gA.load(moRelaxed)
    let b = gB.load(moRelaxed)
    releaseChain(gCs[])
    discard gObserved.fetchAdd(1)
    if a != b: discard gTorn.fetchAdd(1)
    sleep(0)

proc unlockedObserver(arg: int) {.thread.} =
  # Control: same observation with no lock at all.
  while not gStop.load(moAcquire):
    let a = gA.load(moRelaxed)
    cpuRelax()
    let b = gB.load(moRelaxed)
    discard gObserved.fetchAdd(1)
    if a != b: discard gTorn.fetchAdd(1)

proc longForeignHold(arg: int) {.thread.} =
  # A rescan-like operation: 100 units of ~1 ms under one hold.
  acquireChain(gCs[])
  gForeignHolding.store(true)
  for i in 0 ..< 100:
    let until = getMonoTime() + initDuration(milliseconds = 1)
    while getMonoTime() < until: cpuRelax()
    discard gUnitsDone.fetchAdd(1)
    if gUseYield.load(): discard gCs[].yieldHeld()
  gForeignHolding.store(false)
  releaseChain(gCs[])
  gWorkerDone.store(true, moRelease)

proc mainSyncSection(ms: int) =
  ## A synchronous main-thread section (one callback, no await) that keeps an
  ## invariant (gA == gB) broken for most of its duration.
  let until = getMonoTime() + initDuration(milliseconds = ms)
  while getMonoTime() < until:
    discard gA.fetchAdd(1)
    let spin = getMonoTime() + initDuration(microseconds = 20)
    while getMonoTime() < spin: cpuRelax()
    discard gB.fetchAdd(1)

proc resetGlobals() =
  gStop.store(false); gA.store(0); gB.store(0); gObserved.store(0)
  gTorn.store(0); gAcquiredNs.store(-1); gUnitsDone.store(0)
  gForeignHolding.store(false); gWorkerDone.store(false)

suite "chain lock hand-over (home thread)":

  test "foreign acquire is served promptly while the home loop idles (eventfd wake)":
    resetGlobals()
    var cs = freshChainState("/tmp/nimrod_chainlock_handoff_1")
    defer:
      cs.close(); removeDir("/tmp/nimrod_chainlock_handoff_1")
    # Tick of 2 s: a prompt hand-over can only come from the wake path.
    let home = installChainLockHome(cs, tickMs = 2000)
    gCs = addr cs.chainLock
    check cs.chainLock.isHomeThread
    check cs.chainLock.depthHeld == 1
    var th: Thread[int]
    createThread(th, acquireOnce, 0)
    let deadline = getMonoTime() + initDuration(milliseconds = 1500)
    while gAcquiredNs.load() < 0 and getMonoTime() < deadline:
      waitFor sleepAsync(chronos.milliseconds(1))
    joinThread(th)
    home.stop()
    let ns = gAcquiredNs.load()
    checkpoint "foreign acquire latency = " & $(ns div 1000) & " us"
    echo "HANDOFF idle-loop acquire latency us=", ns div 1000
    check ns >= 0
    check ns < 200_000_000  # far below the 2 s tick: the wake path served it
    check cs.chainLock.depthHeld == 1   # home hold restored

  test "a synchronous main-thread section is never interleaved with a foreign holder":
    resetGlobals()
    var cs = freshChainState("/tmp/nimrod_chainlock_handoff_2")
    defer:
      cs.close(); removeDir("/tmp/nimrod_chainlock_handoff_2")
    let home = installChainLockHome(cs, tickMs = 5)
    gCs = addr cs.chainLock
    var th: Thread[int]
    createThread(th, observer, 0)
    # Interleave: three 150 ms synchronous sections separated by event-loop
    # turns (where the hand-over task runs).
    for i in 0 ..< 3:
      mainSyncSection(150)
      waitFor sleepAsync(chronos.milliseconds(30))
    gStop.store(true, moRelease)
    # Let a blocked observer through so it can see gStop.
    for i in 0 ..< 20:
      waitFor sleepAsync(chronos.milliseconds(5))
    joinThread(th)
    home.stop()
    checkpoint "observed=" & $gObserved.load() & " torn=" & $gTorn.load()
    echo "HANDOFF locked observer: observed=", gObserved.load(), " torn=", gTorn.load()
    check gObserved.load() > 0      # the foreign thread did get the lock
    check gTorn.load() == 0         # ... but never inside a sync section

  test "CONTROL: without the lock the same instrument sees torn state":
    # Proves the observer above can see a torn pair when nothing serialises
    # it — i.e. the 0 above is the lock's doing, not a blind instrument.
    resetGlobals()
    var th: Thread[int]
    createThread(th, unlockedObserver, 0)
    sleep(5)
    mainSyncSection(150)
    gStop.store(true, moRelease)
    joinThread(th)
    checkpoint "observed=" & $gObserved.load() & " torn=" & $gTorn.load()
    echo "HANDOFF unlocked control: observed=", gObserved.load(), " torn=", gTorn.load()
    check gTorn.load() > 0

  test "a long foreign hold with yieldHeld lets the main loop run; without it, not":
    for useYield in [true, false]:
      resetGlobals()
      gUseYield.store(useYield)
      let path = "/tmp/nimrod_chainlock_handoff_3_" & $useYield
      var cs = freshChainState(path)
      let home = installChainLockHome(cs, tickMs = 5)
      gCs = addr cs.chainLock
      var ticks = 0
      var ticksDuringHold = 0
      var th: Thread[int]
      createThread(th, longForeignHold, 0)
      let deadline = getMonoTime() + initDuration(seconds = 10)
      # Keep the loop (and so the hand-over task) running until the worker has
      # RELEASED: joining it while this thread holds the lock would deadlock
      # (the rule in storage/chain_lock.nim).
      while not gWorkerDone.load(moAcquire) and getMonoTime() < deadline:
        waitFor sleepAsync(chronos.milliseconds(1))   # a main-loop "tick"
        inc ticks
        if gForeignHolding.load() and gUnitsDone.load() in 1 .. 98:
          inc ticksDuringHold
      joinThread(th)
      home.stop()
      cs.close(); removeDir(path)
      checkpoint "yieldHeld=" & $useYield & " units=" & $gUnitsDone.load() &
                 " ticks=" & $ticks & " ticksDuringHold=" & $ticksDuringHold
      echo "HANDOFF long foreign hold yieldHeld=", useYield, " ticksDuringHold=", ticksDuringHold
      check gUnitsDone.load() == 100
      if useYield:
        check ticksDuringHold >= 10
      else:
        check ticksDuringHold <= 1
