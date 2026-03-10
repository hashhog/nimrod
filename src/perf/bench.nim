## Performance benchmarking utilities
## Provides timing macros and statistics for profiling critical paths

import std/[times, stats, strformat, monotimes, strutils]

export stats, monotimes

type
  BenchResult* = object
    ## Result of a benchmark run
    name*: string
    iterations*: int
    meanUs*: float64
    stdDevUs*: float64
    minUs*: float64
    maxUs*: float64
    totalMs*: float64

  BenchmarkSuite* = object
    ## Collection of benchmark results
    results*: seq[BenchResult]
    startTime*: MonoTime

proc newBenchmarkSuite*(): BenchmarkSuite =
  ## Create a new benchmark suite
  BenchmarkSuite(
    results: @[],
    startTime: getMonoTime()
  )

proc add*(suite: var BenchmarkSuite, result: BenchResult) =
  suite.results.add(result)

proc report*(suite: BenchmarkSuite): string =
  ## Generate a report of all benchmark results
  result = "Benchmark Results:\n"
  result &= "-".repeat(70) & "\n"
  result &= "Name                           Mean (us)    StdDev     Min        Max\n"
  result &= "-".repeat(70) & "\n"
  for r in suite.results:
    result &= &"{r.name:<30} {r.meanUs:>10.1f} {r.stdDevUs:>10.1f} {r.minUs:>10.1f} {r.maxUs:>10.1f}\n"
  let elapsed = (getMonoTime() - suite.startTime).inMilliseconds
  result &= "-".repeat(70) & "\n"
  result &= &"Total suite time: {elapsed}ms\n"

template benchmark*(benchName: string, benchIterations: int, body: untyped): BenchResult =
  ## Benchmark a block of code
  ## Returns timing statistics in microseconds
  var timings: RunningStat
  var minTime = float64.high
  var maxTime = 0.0'f64

  # Warmup runs
  for _ in 0 ..< min(benchIterations div 10, 10):
    body

  # Timed runs
  for i in 0 ..< benchIterations:
    let start = getMonoTime()
    body
    let elapsed = float64((getMonoTime() - start).inMicroseconds)
    timings.push(elapsed)
    if elapsed < minTime:
      minTime = elapsed
    if elapsed > maxTime:
      maxTime = elapsed

  echo benchName & ": mean=" & $timings.mean & "us std=" & $timings.standardDeviation & "us (n=" & $benchIterations & ")"

  BenchResult(
    name: benchName,
    iterations: benchIterations,
    meanUs: timings.mean,
    stdDevUs: timings.standardDeviation,
    minUs: minTime,
    maxUs: maxTime,
    totalMs: float64(benchIterations) * timings.mean / 1000.0
  )

template benchmarkMs*(benchName: string, benchIterations: int, body: untyped): BenchResult =
  ## Benchmark a block of code, reporting in milliseconds
  ## Better for longer-running operations
  var timings: RunningStat
  var minTime = float64.high
  var maxTime = 0.0'f64

  for i in 0 ..< benchIterations:
    let start = getMonoTime()
    body
    let elapsed = float64((getMonoTime() - start).inMilliseconds)
    timings.push(elapsed)
    if elapsed < minTime:
      minTime = elapsed
    if elapsed > maxTime:
      maxTime = elapsed

  echo benchName & ": mean=" & $timings.mean & "ms std=" & $timings.standardDeviation & "ms (n=" & $benchIterations & ")"

  BenchResult(
    name: benchName,
    iterations: benchIterations,
    meanUs: timings.mean * 1000.0,  # Store as us for consistency
    stdDevUs: timings.standardDeviation * 1000.0,
    minUs: minTime * 1000.0,
    maxUs: maxTime * 1000.0,
    totalMs: float64(benchIterations) * timings.mean
  )

template timeIt*(benchName: string, body: untyped): untyped =
  ## Simple one-shot timing for debugging
  let start = getMonoTime()
  body
  let elapsed = (getMonoTime() - start).inMicroseconds
  echo benchName & ": " & $elapsed & "us (" & $(float64(elapsed)/1000.0) & "ms)"

template assertPerf*(benchName: string, maxUs: float64, benchIterations: int, body: untyped) =
  ## Assert that code runs within performance budget
  ## Useful for regression testing
  var totalUs = 0.0'f64

  for i in 0 ..< benchIterations:
    let start = getMonoTime()
    body
    totalUs += float64((getMonoTime() - start).inMicroseconds)

  let meanUs = totalUs / float64(benchIterations)
  if meanUs > maxUs:
    raise newException(AssertionDefect,
      "Performance assertion failed for " & benchName & ": " & $meanUs & "us > " & $maxUs & "us limit")
  echo "[PASS] " & benchName & ": " & $meanUs & "us <= " & $maxUs & "us"

# Throughput measurement

type
  ThroughputMeter* = object
    ## Measures operations per second
    name*: string
    startTime*: MonoTime
    count*: int64

proc start*(meter: var ThroughputMeter, name: string) =
  meter.name = name
  meter.startTime = getMonoTime()
  meter.count = 0

proc record*(meter: var ThroughputMeter, n: int = 1) =
  meter.count += n

proc opsPerSec*(meter: ThroughputMeter): float64 =
  let elapsedSec = float64((getMonoTime() - meter.startTime).inMicroseconds) / 1_000_000.0
  if elapsedSec > 0:
    float64(meter.count) / elapsedSec
  else:
    0.0

proc report*(meter: ThroughputMeter): string =
  let ops = meter.opsPerSec()
  &"{meter.name}: {ops:.0f} ops/sec ({meter.count} total)"

# Memory measurement helpers

proc getMemoryUsageMB*(): float64 =
  ## Get approximate memory usage in MB (Linux only)
  ## Returns -1 on non-Linux or if unable to read
  try:
    let status = readFile("/proc/self/status")
    for line in status.splitLines:
      if line.startsWith("VmRSS:"):
        let parts = line.split()
        if parts.len >= 2:
          return parseFloat(parts[1]) / 1024.0  # kB to MB
  except:
    discard
  return -1.0

template withMemoryReport*(name: string, body: untyped) =
  ## Report memory usage before and after a block
  let memBefore = getMemoryUsageMB()
  body
  let memAfter = getMemoryUsageMB()
  if memBefore >= 0 and memAfter >= 0:
    echo &"{name}: {memAfter - memBefore:.1f}MB delta (now {memAfter:.1f}MB)"
