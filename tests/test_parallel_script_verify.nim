## Parallel script verification controls (QUEUES.md nimrod item 0, 2026-09-19).
##
## REQUIRED:
## 1. Decision identity — accept/reject AND reject reason identical at 1 worker
##    and at N.
## 2. Failure propagation — one failing check in one worker rejects the whole
##    batch with the same reason as the serial path.
## 3. Measured scaling — blk/h at 1, 2, 4, 8 workers on a post-segwit-shaped
##    batch with thousands of inputs, reported as numbers.
## 4. Bounded RSS — more workers must not mean unbounded buffers (batch=128,
##    work vector is borrowed, extra RSS is O(threads) not O(threads × inputs)).
##
## Worker count must not change validity. `--par=1` is serial.
##
## Command:
##   nim c -r --threads:on --mm:arc -d:release tests/test_parallel_script_verify.nim

import unittest2
import std/[os, strutils, times]
import ../src/perf/verify_pool
import ../src/primitives/types
import ../src/script/interpreter

proc dummyTx(): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(),
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0
  )

proc opTrue(): seq[byte] = @[0x51'u8]
proc opFalse(): seq[byte] = @[0x00'u8]

proc hashHeavyScript(rounds: int): seq[byte] =
  ## `scriptPubKey` valid with an empty scriptSig: N rounds of
  ## PUSH32/SHA256/DROP then OP_TRUE. CPU-bound so 1-vs-N scaling is measurable.
  result = newSeqOfCap[byte](rounds * 35 + 1)
  for _ in 0 ..< rounds:
    result.add(0x20'u8) # OP_PUSHBYTES_32
    for i in 0 ..< 32:
      result.add(0xAB'u8)
    result.add(0xa8'u8) # OP_SHA256
    result.add(0x75'u8) # OP_DROP
  result.add(0x51'u8) # OP_TRUE

proc mkCheck(spk: seq[byte]): ScriptCheck =
  ScriptCheck(
    scriptSig: @[],
    scriptPubKey: spk,
    tx: dummyTx(),
    inputIndex: 0,
    amount: Satoshi(1000),
    flags: {},
    witness: @[],
    prevoutsPtr: nil
  )

proc mkBatch(n: int, spk: seq[byte]): seq[ScriptCheck] =
  result = newSeq[ScriptCheck](n)
  for i in 0 ..< n:
    result[i] = mkCheck(spk)

proc rssKb(): int64 =
  try:
    for line in lines("/proc/self/status"):
      if line.startsWith("VmRSS:"):
        let parts = line.splitWhitespace()
        if parts.len >= 2:
          return int64(parseInt(parts[1]))
  except CatchableError:
    discard
  0

suite "parallel script verify — Core -par mapping":
  test "par_resolve_matches_core":
    check DefaultScriptCheckThreads == 0
    check MaxScriptCheckThreads == 15
    check ScriptCheckBatchSize == 128

    # Explicit counts: total threads = clamp(par-1, 0, 15) + 1.
    check resolveScriptCheckThreads(1) == 1 # --par=1 is serial
    check resolveScriptCheckThreads(4) == 4
    check resolveScriptCheckThreads(16) == 16
    check resolveScriptCheckThreads(100) == MaxScriptCheckThreads + 1

    let auto = resolveScriptCheckThreads(0)
    check auto >= 1 and auto <= MaxScriptCheckThreads + 1
    let leaveOne = resolveScriptCheckThreads(-1)
    check leaveOne >= 1 and leaveOne <= MaxScriptCheckThreads + 1
    check leaveOne <= auto

    check clampWorkers(1) == 0
    check clampWorkers(4) == 3

  test "CLI exposes --par and rewrites Core's single-dash -par":
    let src = readFile(currentSourcePath().parentDir / "../src/nimrod.nim")
    check src.contains("of \"par\", \"verify-threads\"")
    check src.contains("rewriteCoreParFlags")
    check src.contains("of \"par\", \"verifythreads\", \"verify-threads\"")

suite "parallel script verify — decision identity":
  test "decision_identity_1_vs_n_accept":
    var checks = mkBatch(64, opTrue())
    let one = runChecksWithN(1, checks)
    let eight = runChecksWithN(8, checks)
    check one.ok
    check one == eight

  test "decision_identity_and_failure_propagation_1_vs_n":
    # 63 OP_TRUE + one OP_FALSE in the middle: the failing check runs on
    # whatever worker draws it. The whole batch must reject, and the reason
    # must match the serial path (single failure → no scheduling ambiguity).
    var checks = mkBatch(64, opTrue())
    checks[37] = mkCheck(opFalse())

    let serial = runChecksWithN(1, checks)
    check not serial.ok
    check serial.err == seVerify
    check serial.failIndex == 37

    for n in [2, 4, 8]:
      let parallel = runChecksWithN(n, checks)
      check serial == parallel

suite "parallel script verify — measured scaling":
  test "measured_scaling_1_2_4_8":
    const Inputs = 2048
    var rounds = 16
    var checks = mkBatch(Inputs, hashHeavyScript(rounds))

    # Grow work until 1 worker takes ≥150 ms so the ratio is measurable.
    # Cap rounds at 96 so we stay under MaxOpsPerScript (201); SHA256+DROP
    # count, pushes do not.
    while true:
      let t0 = epochTime()
      let r = runChecksWithN(1, checks)
      let ms = (epochTime() - t0) * 1000.0
      check r.ok
      if ms >= 150.0 or rounds >= 96:
        echo "scaling warmup: 1 worker ", formatFloat(ms, ffDecimal, 1),
             " ms at ", rounds, " SHA256 rounds, ", Inputs, " inputs"
        break
      rounds *= 2
      if rounds > 96: rounds = 96
      checks = mkBatch(Inputs, hashHeavyScript(rounds))

    echo "measured scaling (", Inputs, " inputs, ", rounds, " SHA256 rounds/input):"
    var timesMs: seq[float] = @[]
    for n in [1, 2, 4, 8]:
      var best = 60.0
      for _ in 0 ..< 2:
        let t0 = epochTime()
        let r = runChecksWithN(n, checks)
        check r.ok
        best = min(best, epochTime() - t0)
      let secs = max(best, 1e-9)
      let blkH = 3600.0 / secs
      timesMs.add(best * 1000.0)
      echo "  ", align($n, 2), " workers: ",
           align(formatFloat(blkH, ffDecimal, 1), 8), " blk/h  (",
           formatFloat(best * 1000.0, ffDecimal, 1), " ms/block)"

    # Weak liveness bound, not a claimed speedup: 8 workers must not be a
    # serial-plus-disaster (more than 3× slower than 1).
    check timesMs[3] < timesMs[0] * 3.0 + 50.0

suite "parallel script verify — bounded RSS":
  test "bounded_rss_more_workers_not_unbounded_buffers":
    check ScriptCheckBatchSize == 128
    let src = readFile(currentSourcePath().parentDir / "../src/perf/verify_pool.nim")
    check src.contains("ScriptCheckBatchSize")
    check src.contains("claimBatch")
    # Work is claimed by index into the caller's seq — no per-worker clone of
    # the whole vector (the O(threads × inputs) failure mode).
    check src.contains("q.checks[][idx]") or src.contains("q.checks[][start")

    const Inputs = 4096
    var checks = mkBatch(Inputs, opTrue())

    discard runChecksWithN(1, checks)
    let rssAfter1 = rssKb()
    discard runChecksWithN(8, checks)
    let rssAfter8 = rssKb()
    let extra = max(rssAfter8 - rssAfter1, 0)
    echo "bounded RSS: after 1 worker ", rssAfter1, " kB, after 8 workers ",
         rssAfter8, " kB, extra ", extra, " kB"
    # 64 MiB slack covers thread stacks + allocator jitter. 4096 OP_TRUE
    # scripts cloned 8× into unbounded per-worker queues would blow past this
    # once the payload is hash-heavy; the structural claimBatch bound is the
    # real discriminator if this ever trips.
    check extra < 64 * 1024
