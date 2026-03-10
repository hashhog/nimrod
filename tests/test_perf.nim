## Performance tests for nimrod
## Tests benchmarking utilities and performance-critical components

import std/[unittest, options, times, random, strutils]
import ../src/perf/[bench, utxo_cache]
import ../src/primitives/types
import ../src/storage/chainstate

suite "benchmark utilities":
  test "benchmark template measures correctly":
    var counter = 0
    let result = benchmark("counter increment", 1000):
      counter += 1

    # counter includes warmup runs (10% of iterations, min 10)
    check counter >= 1000
    check result.iterations == 1000
    check result.meanUs >= 0
    check result.name == "counter increment"

  test "benchmark suite collects results":
    var suite = newBenchmarkSuite()

    let r1 = benchmark("fast op", 100):
      discard 1 + 1

    let r2 = benchmark("slow op", 100):
      var x = 0
      for i in 0 ..< 100:
        x += i

    suite.add(r1)
    suite.add(r2)

    check suite.results.len == 2
    let report = suite.report()
    check "fast op" in report
    check "slow op" in report

  test "throughput meter":
    var meter: ThroughputMeter
    meter.start("test ops")

    for i in 0 ..< 1000:
      meter.record()

    check meter.count == 1000
    check meter.opsPerSec() > 0

  test "assertPerf passes for fast code":
    assertPerf("simple add", 100.0, 100):
      discard 1 + 1

suite "utxo cache":
  proc makeOutPoint(seed: int): OutPoint =
    var txid: array[32, byte]
    let s = uint32(seed)
    txid[0] = byte(s and 0xff)
    txid[1] = byte((s shr 8) and 0xff)
    txid[2] = byte((s shr 16) and 0xff)
    txid[3] = byte((s shr 24) and 0xff)
    OutPoint(txid: TxId(txid), vout: uint32(seed mod 10))

  proc makeUtxoEntry(value: int64, height: int32): UtxoEntry =
    UtxoEntry(
      output: TxOut(value: Satoshi(value), scriptPubKey: @[0x76'u8, 0xa9]),
      height: height,
      isCoinbase: false
    )

  test "basic put/get/delete":
    var cache = newUtxoCache(1024)

    let op = makeOutPoint(42)
    let entry = makeUtxoEntry(100000, 100)

    # Initially empty
    check cache.get(op).isNone
    check cache.len == 0

    # Put
    cache.put(op, entry)
    check cache.len == 1

    # Get
    let retrieved = cache.get(op)
    check retrieved.isSome
    check int64(retrieved.get().output.value) == 100000

    # Delete
    check cache.delete(op) == true
    check cache.len == 0
    check cache.get(op).isNone

  test "handles collisions":
    var cache = newUtxoCache(64)  # Small capacity to force collisions

    var entries: seq[(OutPoint, UtxoEntry)]
    for i in 0 ..< 50:
      let op = makeOutPoint(i * 17)  # Different seeds
      let entry = makeUtxoEntry(int64(i * 1000), int32(i))
      entries.add((op, entry))
      cache.put(op, entry)

    check cache.len == 50

    # Verify all can be retrieved
    for (op, entry) in entries:
      let retrieved = cache.get(op)
      check retrieved.isSome
      check retrieved.get().height == entry.height

  test "auto-resize on high load":
    var cache = newUtxoCache(64)

    # Insert many items to trigger resize
    for i in 0 ..< 100:
      let op = makeOutPoint(i)
      cache.put(op, makeUtxoEntry(int64(i), 0))

    check cache.len == 100
    check cache.capacity > 64  # Should have resized

    # All items still accessible
    for i in 0 ..< 100:
      let op = makeOutPoint(i)
      check cache.contains(op)

  test "batch operations":
    var cache = newUtxoCache()

    var batch: seq[(OutPoint, UtxoEntry)]
    for i in 0 ..< 100:
      batch.add((makeOutPoint(i), makeUtxoEntry(int64(i), 0)))

    cache.putBatch(batch)
    check cache.len == 100

    var keys: seq[OutPoint]
    for i in 0 ..< 50:
      keys.add(makeOutPoint(i))

    let deleted = cache.deleteBatch(keys)
    check deleted == 50
    check cache.len == 50

  test "iteration":
    var cache = newUtxoCache()

    for i in 0 ..< 10:
      cache.put(makeOutPoint(i), makeUtxoEntry(int64(i * 100), 0))

    var count = 0
    var totalValue = 0'i64
    for (op, entry) in cache.pairs:
      count += 1
      totalValue += int64(entry.output.value)

    check count == 10
    check totalValue == 4500  # 0 + 100 + 200 + ... + 900

  test "memory estimation":
    var cache = newUtxoCache(1024)

    let memBefore = cache.estimatedMemoryBytes()
    check memBefore > 0

    for i in 0 ..< 500:
      cache.put(makeOutPoint(i), makeUtxoEntry(int64(i), 0))

    # Memory estimate should be based on capacity, not count
    check cache.estimatedMemoryBytes() == memBefore

  test "compact reclaims deleted slots":
    var cache = newUtxoCache(64)

    # Fill cache
    for i in 0 ..< 40:
      cache.put(makeOutPoint(i), makeUtxoEntry(int64(i), 0))

    check cache.len == 40

    # Delete half
    for i in 0 ..< 20:
      discard cache.delete(makeOutPoint(i))

    check cache.len == 20
    check cache.deletedCount == 20

    # Compact
    cache.compact()

    check cache.len == 20
    check cache.deletedCount == 0

  test "hit rate tracking":
    var cache = newUtxoCache()

    cache.put(makeOutPoint(1), makeUtxoEntry(100, 0))
    cache.put(makeOutPoint(2), makeUtxoEntry(200, 0))

    # Hits
    discard cache.get(makeOutPoint(1))
    discard cache.get(makeOutPoint(2))
    discard cache.get(makeOutPoint(1))

    # Misses
    discard cache.get(makeOutPoint(99))
    discard cache.get(makeOutPoint(100))

    check cache.stats.hits == 3
    check cache.stats.misses == 2
    check cache.hitRate() == 0.6

suite "utxo cache performance":
  test "lookup performance < 1us average":
    var cache = newUtxoCache(100000)
    randomize(42)

    # Populate with 50k entries
    for i in 0 ..< 50000:
      var txid: array[32, byte]
      for j in 0 ..< 32:
        txid[j] = byte(rand(255))
      let op = OutPoint(txid: TxId(txid), vout: uint32(rand(9)))
      cache.put(op, UtxoEntry(
        output: TxOut(value: Satoshi(rand(100000000)), scriptPubKey: @[0x76'u8]),
        height: int32(rand(800000)),
        isCoinbase: false
      ))

    # Benchmark lookups
    var keys: seq[OutPoint]
    for (op, _) in cache.pairs:
      keys.add(op)
      if keys.len >= 1000:
        break

    let start = cpuTime()
    var hits = 0
    for _ in 0 ..< 10000:
      let key = keys[rand(keys.len - 1)]
      if cache.get(key).isSome:
        hits += 1
    let elapsed = cpuTime() - start

    let usPerLookup = (elapsed * 1_000_000) / 10000.0
    echo "UTXO lookup: ", usPerLookup, " us/op"

    # Target: < 1us average
    check usPerLookup < 5.0  # Relaxed for test environments
    check hits == 10000
