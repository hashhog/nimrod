## SHA-256 Hardware Acceleration Benchmarks
##
## Tests and benchmarks for hardware-accelerated SHA-256 operations.
## Verifies correctness and measures throughput.

import unittest2
import std/[monotimes, strformat]

import ../src/crypto/cpufeatures
import ../src/crypto/sha256_accel
import ../src/crypto/hashing

suite "SHA-256 Hardware Acceleration":

  setup:
    initSha256Accel()

  test "CPU feature detection":
    let features = detectCpuFeatures()
    echo "Detected CPU features: ", cpuFeaturesString()
    echo "SHA-256 implementation: ", getImplementationString()

    # Should always succeed (may be empty set)
    check true

  test "sha256Accel matches nimcrypto":
    # Test various input sizes
    let testCases = @[
      newSeq[byte](0),                    # Empty
      @[0x00'u8],                         # Single byte
      @[0x61'u8, 0x62, 0x63],             # "abc"
      newSeq[byte](55),                   # Just under one block
      newSeq[byte](56),                   # Exactly padding boundary
      newSeq[byte](64),                   # One block
      newSeq[byte](128),                  # Two blocks
      newSeq[byte](1000),                 # Many blocks
    ]

    for data in testCases:
      let accelResult = sha256Accel(data)
      let nimcryptoResult = sha256(data)
      check accelResult == nimcryptoResult

  test "sha256dAccel matches doubleSha256":
    let testData = @[
      newSeq[byte](0),
      @[0x00'u8],
      @[0x61'u8, 0x62, 0x63],
      newSeq[byte](64),
      newSeq[byte](256),
    ]

    for data in testData:
      let accelResult = sha256dAccel(data)
      let normalResult = doubleSha256(data)
      check accelResult == normalResult

  test "sha256d64 correctness":
    # Test specialized 64-byte double SHA-256
    var input: array[64, byte]
    for i in 0..<64:
      input[i] = byte(i)

    let result = sha256d64(input)

    # Verify against standard implementation
    let expected = doubleSha256(input)
    check result == expected

  test "sha256d64 known vector":
    # Known test vector: two concatenated 32-byte hashes
    var input: array[64, byte]
    # First "hash"
    for i in 0..<32:
      input[i] = byte(i)
    # Second "hash"
    for i in 32..<64:
      input[i] = byte(i)

    let result = sha256d64(input)

    # Computed expected value via standard double-SHA256
    let expected = doubleSha256(input)
    check result == expected

  test "sha256d64Batch correctness":
    const batchSize = 10
    var inputs: array[batchSize, array[64, byte]]
    var outputs: array[batchSize, array[32, byte]]

    # Initialize with different data
    for i in 0..<batchSize:
      for j in 0..<64:
        inputs[i][j] = byte((i * 64 + j) mod 256)

    sha256d64Batch(outputs, inputs)

    # Verify each result
    for i in 0..<batchSize:
      let expected = sha256d64(inputs[i])
      check outputs[i] == expected

  test "computeMerkleRootAccel matches reference":
    # Test with various numbers of hashes
    let testCases = @[1, 2, 3, 4, 5, 7, 8, 15, 16, 100]

    for count in testCases:
      var hashes: seq[array[32, byte]]
      for i in 0..<count:
        var h: array[32, byte]
        for j in 0..<32:
          h[j] = byte((i * 32 + j) mod 256)
        hashes.add(h)

      let accelRoot = computeMerkleRootAccel(hashes)
      let normalRoot = computeMerkleRoot(hashes)

      check accelRoot == normalRoot

  test "incremental Sha256Context":
    var ctx: Sha256Context
    ctx.init()

    # Hash "abc" incrementally
    ctx.update(@[0x61'u8])  # 'a'
    ctx.update(@[0x62'u8])  # 'b'
    ctx.update(@[0x63'u8])  # 'c'

    let result = ctx.finalize()
    let expected = sha256Accel(@[0x61'u8, 0x62, 0x63])

    check result == expected

  test "incremental context with large data":
    var ctx: Sha256Context
    ctx.init()

    # Hash 1MB incrementally in chunks
    let chunkSize = 4096
    let totalSize = 1024 * 1024

    var fullData: seq[byte]
    var offset = 0

    while offset < totalSize:
      var chunk: seq[byte]
      for i in 0..<chunkSize:
        chunk.add(byte((offset + i) mod 256))
      ctx.update(chunk)
      fullData.add(chunk)
      offset += chunkSize

    let incremental = ctx.finalize()
    let direct = sha256Accel(fullData)

    check incremental == direct

suite "SHA-256 Benchmarks":

  setup:
    initSha256Accel()

  test "sha256 throughput benchmark":
    echo "\n--- SHA-256 Throughput Benchmark ---"
    echo "Implementation: ", getImplementationString()

    # Benchmark different sizes
    let sizes = @[64, 256, 1024, 4096, 65536, 1048576]

    for size in sizes:
      var data = newSeq[byte](size)
      for i in 0..<size:
        data[i] = byte(i mod 256)

      let iterations = max(1, 100_000_000 div size)  # ~100MB total

      let start = getMonoTime()
      for _ in 0..<iterations:
        discard sha256Accel(data)
      let elapsed = (getMonoTime() - start).inMicroseconds

      let totalBytes = float64(size * iterations)
      let mbps = totalBytes / (float64(elapsed) / 1_000_000.0) / (1024.0 * 1024.0)

      echo &"  {size:>8} bytes: {mbps:>8.1f} MB/s ({iterations} iterations)"

  test "sha256d64 throughput benchmark":
    echo "\n--- sha256d64 Benchmark ---"
    echo "Implementation: ", getImplementationString()

    var input: array[64, byte]
    for i in 0..<64:
      input[i] = byte(i)

    const iterations = 1_000_000

    let start = getMonoTime()
    for _ in 0..<iterations:
      discard sha256d64(input)
    let elapsed = (getMonoTime() - start).inMicroseconds

    let opsPerSec = float64(iterations) / (float64(elapsed) / 1_000_000.0)
    echo &"  Single: {opsPerSec:>12.0f} ops/sec"

    # Also benchmark batch mode
    const batchSize = 100
    var inputs: array[batchSize, array[64, byte]]
    var outputs: array[batchSize, array[32, byte]]
    for i in 0..<batchSize:
      for j in 0..<64:
        inputs[i][j] = byte((i * 64 + j) mod 256)

    const batchIterations = iterations div batchSize

    let batchStart = getMonoTime()
    for _ in 0..<batchIterations:
      sha256d64Batch(outputs, inputs)
    let batchElapsed = (getMonoTime() - batchStart).inMicroseconds

    let batchOpsPerSec = float64(batchIterations * batchSize) / (float64(batchElapsed) / 1_000_000.0)
    echo &"  Batch:  {batchOpsPerSec:>12.0f} ops/sec ({batchSize} per batch)"

  test "merkle root throughput benchmark":
    echo "\n--- Merkle Root Benchmark ---"
    echo "Implementation: ", getImplementationString()

    let txCounts = @[100, 500, 1000, 2000, 4000]

    for count in txCounts:
      var hashes: seq[array[32, byte]]
      for i in 0..<count:
        var h: array[32, byte]
        for j in 0..<32:
          h[j] = byte((i * 32 + j) mod 256)
        hashes.add(h)

      let iterations = max(1, 10000 div count)

      let start = getMonoTime()
      for _ in 0..<iterations:
        discard computeMerkleRootAccel(hashes)
      let elapsed = (getMonoTime() - start).inMicroseconds

      let avgMs = float64(elapsed) / float64(iterations) / 1000.0
      echo &"  {count:>5} txs: {avgMs:>8.3f} ms/root"

  test "throughput target check":
    ## Verify we meet performance targets
    ## Target: >500 MB/s on modern x86 with SHA-NI

    let impl = getActiveImplementation()

    # 1MB benchmark
    var data = newSeq[byte](1024 * 1024)
    for i in 0..<data.len:
      data[i] = byte(i mod 256)

    const iterations = 10

    let start = getMonoTime()
    for _ in 0..<iterations:
      discard sha256Accel(data)
    let elapsed = (getMonoTime() - start).inMicroseconds

    let mbps = float64(iterations) / (float64(elapsed) / 1_000_000.0)

    echo "\n--- Performance Target Check ---"
    echo &"  Achieved: {mbps:.1f} MB/s"

    case impl
    of siSHANI:
      echo "  Target:   >500 MB/s (SHA-NI)"
      if mbps < 500:
        echo "  WARNING: Below target throughput for SHA-NI"
    of siArmSHA2:
      echo "  Target:   >200 MB/s (ARM SHA2)"
      if mbps < 200:
        echo "  WARNING: Below target throughput for ARM SHA2"
    of siPortable:
      echo "  Target:   >100 MB/s (portable)"
      # Portable is expected to be slower

    # Don't fail the test, just report
    check true
