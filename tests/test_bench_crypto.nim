## Crypto Benchmarks
##
## Combined benchmarks for all hardware-accelerated crypto operations.
## Run with: nimble test -- bench_crypto

import unittest2
import std/[monotimes, strformat]

import ../src/crypto/cpufeatures
import ../src/crypto/sha256_accel

when defined(useSystemSecp256k1):
  import ../src/crypto/secp256k1

suite "Crypto Benchmark Suite":

  setup:
    initSha256Accel()

  test "CPU features report":
    echo "\n=========================================="
    echo "         Hardware Crypto Report"
    echo "=========================================="
    echo ""
    echo "CPU Features: ", cpuFeaturesString()
    echo "SHA-256:      ", getImplementationString()

    when defined(amd64) or defined(i386):
      let features = detectCpuFeatures()
      echo ""
      echo "x86 Feature Details:"
      echo "  SSE3:   ", cfSSE3 in features
      echo "  SSSE3:  ", cfSSSE3 in features
      echo "  SSE4.1: ", cfSSE41 in features
      echo "  SSE4.2: ", cfSSE42 in features
      echo "  AVX:    ", cfAVX in features
      echo "  AVX2:   ", cfAVX2 in features
      echo "  SHA-NI: ", cfSHANI in features

    when defined(arm64) or defined(aarch64):
      let features = detectCpuFeatures()
      echo ""
      echo "ARM Feature Details:"
      echo "  NEON:   ", cfNEON in features
      echo "  SHA2:   ", cfSHANI in features

    echo ""

  test "SHA-256 benchmark summary":
    echo "--- SHA-256 Performance ---"

    # Quick benchmark: 1MB hashing
    var data = newSeq[byte](1024 * 1024)
    for i in 0..<data.len:
      data[i] = byte(i mod 256)

    # Single-threaded throughput
    let iterations = 50
    let start = getMonoTime()
    for _ in 0..<iterations:
      discard sha256Accel(data)
    let elapsed = (getMonoTime() - start).inMicroseconds

    let mbps = float64(iterations) / (float64(elapsed) / 1_000_000.0)
    echo &"  Throughput:    {mbps:>8.1f} MB/s (1MB blocks)"

    # sha256d64 ops/sec
    var input64: array[64, byte]
    for i in 0..<64:
      input64[i] = byte(i)

    const ops = 500_000
    let d64Start = getMonoTime()
    for _ in 0..<ops:
      discard sha256d64(input64)
    let d64Elapsed = (getMonoTime() - d64Start).inMicroseconds

    let d64OpsPerSec = float64(ops) / (float64(d64Elapsed) / 1_000_000.0)
    echo &"  sha256d64:     {d64OpsPerSec:>8.0f} ops/sec"

    # Merkle root benchmark (1000 tx block)
    var hashes: seq[array[32, byte]]
    for i in 0..<1000:
      var h: array[32, byte]
      for j in 0..<32:
        h[j] = byte((i * 32 + j) mod 256)
      hashes.add(h)

    let merkleIterations = 1000
    let merkleStart = getMonoTime()
    for _ in 0..<merkleIterations:
      discard computeMerkleRootAccel(hashes)
    let merkleElapsed = (getMonoTime() - merkleStart).inMicroseconds

    let merkleMs = float64(merkleElapsed) / float64(merkleIterations) / 1000.0
    echo &"  Merkle (1000): {merkleMs:>8.3f} ms/root"

    echo ""

  when defined(useSystemSecp256k1):
    test "secp256k1 benchmark summary":
      echo "--- secp256k1 Performance ---"

      # Generate test key pair
      let privkey: PrivateKey = [
        0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
      ]

      let msgHash: array[32, byte] = [
        0xaa'u8, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
      ]

      initSecp256k1()
      let pubkey = derivePublicKey(privkey)
      let signature = sign(privkey, msgHash)

      # ECDSA verify benchmark
      const verifyIterations = 10_000
      let verifyStart = getMonoTime()
      for _ in 0..<verifyIterations:
        discard verify(pubkey, msgHash, signature)
      let verifyElapsed = (getMonoTime() - verifyStart).inMicroseconds

      let verifyOpsPerSec = float64(verifyIterations) / (float64(verifyElapsed) / 1_000_000.0)
      echo &"  ECDSA verify:  {verifyOpsPerSec:>8.0f} ops/sec"

      # Sign benchmark
      const signIterations = 5_000
      let signStart = getMonoTime()
      for _ in 0..<signIterations:
        discard sign(privkey, msgHash)
      let signElapsed = (getMonoTime() - signStart).inMicroseconds

      let signOpsPerSec = float64(signIterations) / (float64(signElapsed) / 1_000_000.0)
      echo &"  ECDSA sign:    {signOpsPerSec:>8.0f} ops/sec"

      echo ""

  test "block validation estimate":
    echo "--- Block Validation Estimates ---"

    # Simulate block validation workload
    # Typical block: 2000 txs, 4000 inputs

    let txCount = 2000
    let inputCount = 4000

    # Time merkle root computation
    var hashes: seq[array[32, byte]]
    for i in 0..<txCount:
      var h: array[32, byte]
      for j in 0..<32:
        h[j] = byte((i * 32 + j) mod 256)
      hashes.add(h)

    let merkleStart = getMonoTime()
    discard computeMerkleRootAccel(hashes)
    let merkleUs = (getMonoTime() - merkleStart).inMicroseconds

    echo &"  Merkle root ({txCount} txs):      {merkleUs:>6} us"

    # Estimate signature verification time
    when defined(useSystemSecp256k1):
      let privkey: PrivateKey = [
        0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
      ]
      let msgHash: array[32, byte] = [
        0xaa'u8, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
      ]

      initSecp256k1()
      let pubkey = derivePublicKey(privkey)
      let signature = sign(privkey, msgHash)

      # Benchmark single verify to estimate
      const sampleVerify = 100
      let verifyStart = getMonoTime()
      for _ in 0..<sampleVerify:
        discard verify(pubkey, msgHash, signature)
      let verifyUs = (getMonoTime() - verifyStart).inMicroseconds

      let perVerifyUs = float64(verifyUs) / float64(sampleVerify)
      let estSigTimeMs = float64(inputCount) * perVerifyUs / 1000.0

      echo &"  Sig verify ({inputCount} inputs):   {estSigTimeMs:>6.1f} ms (estimated)"
      echo &"  Total block estimate:       {float64(merkleUs) / 1000.0 + estSigTimeMs:>6.1f} ms"

    echo ""
    echo "Note: Actual block validation also includes:"
    echo "  - Script execution"
    echo "  - UTXO lookups"
    echo "  - Consensus rule checks"
    echo "  - I/O operations"
    echo ""
