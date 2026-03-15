## Tests for BIP9 Version Bits State Machine

import std/[tables, options]
import unittest2
import ../src/consensus/versionbits
import ../src/consensus/params
import ../src/primitives/types
import ../src/storage/chainstate

# Test utilities - create mock blockchain data

proc makeBlockHash(height: int): BlockHash =
  ## Create a deterministic block hash from height
  var hash: array[32, byte]
  let h = uint32(height)
  hash[0] = byte(h and 0xff)
  hash[1] = byte((h shr 8) and 0xff)
  hash[2] = byte((h shr 16) and 0xff)
  hash[3] = byte((h shr 24) and 0xff)
  BlockHash(hash)

type
  MockChain = ref object
    blocks: Table[BlockHash, BlockIndex]
    byHeight: Table[int32, BlockHash]

proc newMockChain(): MockChain =
  MockChain(
    blocks: initTable[BlockHash, BlockIndex](),
    byHeight: initTable[int32, BlockHash]()
  )

proc addBlock(chain: MockChain, height: int32, version: int32, timestamp: uint32) =
  let hash = makeBlockHash(height)
  let prevHash = if height > 0: makeBlockHash(height - 1) else: BlockHash(default(array[32, byte]))

  var header = BlockHeader()
  header.version = version
  header.timestamp = timestamp
  header.prevBlock = prevHash

  let idx = BlockIndex(
    hash: hash,
    height: height,
    status: bsValidated,
    prevHash: prevHash,
    header: header,
    totalWork: default(array[32, byte])
  )

  chain.blocks[hash] = idx
  chain.byHeight[height] = hash

proc getBlockIndex(chain: MockChain): proc(h: BlockHash): Option[BlockIndex] =
  proc lookup(h: BlockHash): Option[BlockIndex] =
    if h in chain.blocks:
      some(chain.blocks[h])
    else:
      none(BlockIndex)
  lookup

proc getMtp(chain: MockChain): proc(h: BlockHash): int64 =
  ## Simple MTP: just return the block's timestamp
  ## In a real implementation, this would compute median of 11 blocks
  proc lookup(h: BlockHash): int64 =
    if h in chain.blocks:
      int64(chain.blocks[h].header.timestamp)
    else:
      0'i64
  lookup

suite "BIP9 Version Bits":

  test "version bits top bits detection":
    check isVersionBitsSignaling(0x20000000'i32) == true
    check isVersionBitsSignaling(0x20000001'i32) == true
    check isVersionBitsSignaling(0x3FFFFFFF'i32) == true
    check isVersionBitsSignaling(0x00000001'i32) == false  # Old version 1
    check isVersionBitsSignaling(0x00000002'i32) == false  # Old version 2
    check isVersionBitsSignaling(0x40000000'i32) == false  # Wrong top bits
    check isVersionBitsSignaling(0x60000000'i32) == false  # Wrong top bits

  test "deployment bit signaling":
    # Bit 2 (Taproot)
    check signalsBit(0x20000004'i32, 2) == true
    check signalsBit(0x20000000'i32, 2) == false
    check signalsBit(0x00000004'i32, 2) == false  # Missing BIP9 top bits

    # Bit 28 (TESTDUMMY)
    check signalsBit(0x30000000'i32, 28) == true
    check signalsBit(0x20000000'i32, 28) == false

  test "deployment mask":
    check deploymentMask(0) == 0x00000001'u32
    check deploymentMask(1) == 0x00000002'u32
    check deploymentMask(2) == 0x00000004'u32
    check deploymentMask(28) == 0x10000000'u32

  test "state names":
    check stateName(tsDefined) == "defined"
    check stateName(tsStarted) == "started"
    check stateName(tsLockedIn) == "locked_in"
    check stateName(tsActive) == "active"
    check stateName(tsFailed) == "failed"

  test "always active deployment":
    let chain = newMockChain()
    chain.addBlock(0, 1, 1000000)
    chain.addBlock(1, 1, 1000600)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: AlwaysActive,
      timeout: 0,
      minActivationHeight: 0,
      period: 2016,
      threshold: 1815
    )

    var cache = initTable[BlockHash, ThresholdState]()
    let state = getStateFor(
      deployment,
      makeBlockHash(1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsActive

  test "never active deployment":
    let chain = newMockChain()
    chain.addBlock(0, 1, 1000000)
    chain.addBlock(1, 1, 1000600)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: NeverActive,
      timeout: 0,
      minActivationHeight: 0,
      period: 2016,
      threshold: 1815
    )

    var cache = initTable[BlockHash, ThresholdState]()
    let state = getStateFor(
      deployment,
      makeBlockHash(1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsFailed

  test "defined state before start time":
    let chain = newMockChain()
    # Create blocks with timestamps before start time
    for i in 0 ..< 100:
      chain.addBlock(int32(i), 0x20000004'i32, uint32(1000000 + i * 600))

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: 2000000,  # Start time in future
      timeout: 3000000,
      minActivationHeight: 0,
      period: 144,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()
    let state = getStateFor(
      deployment,
      makeBlockHash(99),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsDefined

  test "started state after start time":
    let chain = newMockChain()
    # Create blocks with timestamps after start time but not enough signaling
    let startTime = 1000000'i64
    for i in 0 ..< 200:
      let ts = uint32(startTime + 100 + int64(i) * 600)  # All after start time
      # Only some blocks signal
      let version = if i mod 3 == 0: 0x20000004'i32 else: 0x20000000'i32
      chain.addBlock(int32(i), version, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,  # Far future timeout
      minActivationHeight: 0,
      period: 144,
      threshold: 108  # 75%
    )

    var cache = initTable[BlockHash, ThresholdState]()
    # Check state at end of first period
    let state = getStateFor(
      deployment,
      makeBlockHash(143),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    # Should be STARTED because MTP >= startTime but not enough signaling
    check state == tsStarted

  test "locked_in after threshold reached":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    # First period: all blocks signal (to get to STARTED then LOCKED_IN)
    for i in 0 ..< period * 2:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      # All blocks signal the bit
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108  # 75%
    )

    var cache = initTable[BlockHash, ThresholdState]()
    # Check state at end of second period
    let state = getStateFor(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsLockedIn

  test "active after locked_in period":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    # Three periods: all signaling to get through STARTED -> LOCKED_IN -> ACTIVE
    for i in 0 ..< period * 3:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()
    # Check state at end of third period
    let state = getStateFor(
      deployment,
      makeBlockHash(period * 3 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsActive

  test "failed state after timeout":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let timeout = 1100000'i64  # Timeout soon after start
    let period = 144

    # Create first period with timestamps before start (DEFINED)
    for i in 0 ..< period:
      let ts = uint32(500000 + int64(i) * 600)  # Before start time
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    # Create second period past start but before timeout (STARTED)
    for i in period ..< period * 2:
      let ts = uint32(startTime + 100 + int64(i - period) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    # Create third period past timeout (should transition to FAILED)
    for i in period * 2 ..< period * 3:
      let ts = uint32(timeout + 1000 + int64(i - period * 2) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: timeout,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()
    let state = getStateFor(
      deployment,
      makeBlockHash(period * 3 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state == tsFailed

  test "min activation height delays active state":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144
    let minActivationHeight = period * 5  # Require 5 periods before activation

    # Three periods of signaling
    for i in 0 ..< period * 4:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: minActivationHeight,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()
    # After 3 periods, should still be LOCKED_IN due to min height
    let state3 = getStateFor(
      deployment,
      makeBlockHash(period * 3 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state3 == tsLockedIn

    # Add more blocks until past min activation height
    for i in period * 4 ..< period * 6:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    # Now should be ACTIVE
    let state6 = getStateFor(
      deployment,
      makeBlockHash(period * 6 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check state6 == tsActive

  test "signaling statistics":
    let chain = newMockChain()
    let period = 144

    # Create partial period - first 30 blocks signal, rest don't
    for i in 0 ..< 50:
      let version = if i < 30: 0x20000004'i32 else: 0x20000000'i32
      chain.addBlock(int32(i), version, uint32(1000000 + i * 600))

    # Debug: check block versions are set correctly
    let blk0 = chain.blocks[makeBlockHash(0)]
    let blk29 = chain.blocks[makeBlockHash(29)]
    let blk30 = chain.blocks[makeBlockHash(30)]
    let blk49 = chain.blocks[makeBlockHash(49)]

    check signalsBit(blk0.header.version, 2) == true
    check signalsBit(blk29.header.version, 2) == true
    check signalsBit(blk30.header.version, 2) == false
    check signalsBit(blk49.header.version, 2) == false

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: 500000,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    let stats = getStateStatistics(
      deployment,
      chain.blocks[makeBlockHash(49)],
      chain.getBlockIndex()
    )

    check stats.period == period
    check stats.threshold == 108
    check stats.elapsed == 50
    check stats.count == 30  # First 30 signal
    # Can we reach threshold? Need 108, have 30, 94 blocks left -> possible
    check stats.possible == true

  test "compute block version":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    # Create one period past start time
    for i in 0 ..< period:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    let deployments = @[
      BIP9Deployment(
        name: "test1",
        bit: 1,
        startTime: startTime,
        timeout: 9000000,
        minActivationHeight: 0,
        period: period,
        threshold: 108
      ),
      BIP9Deployment(
        name: "test2",
        bit: 2,
        startTime: startTime,
        timeout: 9000000,
        minActivationHeight: 0,
        period: period,
        threshold: 108
      )
    ]

    var caches = newSeq[Table[BlockHash, ThresholdState]]()

    let version = computeBlockVersion(
      deployments,
      makeBlockHash(period - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      caches
    )

    # Should have BIP9 top bits plus both deployment bits
    check (version and VersionBitsTopMask) == VersionBitsTopBits
    check (version and int32(deploymentMask(1))) != 0  # Bit 1 set
    check (version and int32(deploymentMask(2))) != 0  # Bit 2 set

  test "cache correctness":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    for i in 0 ..< period * 3:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()

    # Query multiple times - should be consistent
    let state1 = getStateFor(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )

    let state2 = getStateFor(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )

    check state1 == state2
    check cache.len > 0  # Cache should be populated

  test "state since height":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    # First period (0-143): timestamps before start -> DEFINED
    # MTP at 143 will be based on these timestamps
    for i in 0 ..< period:
      let ts = uint32(500000 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    # Second period (144-287): timestamps AFTER start
    # MTP at 287 will use these timestamps, which are past startTime
    # So state transitions to STARTED at the end of this period
    for i in period ..< period * 2:
      let ts = uint32(startTime + 100 + int64(i - period) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    # Third period (288-431): still STARTED (not enough signaling for LOCKED_IN)
    for i in period * 2 ..< period * 3:
      let ts = uint32(startTime + 100 + int64(i - period) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()

    # Verify MTP semantics:
    # State at hash(143) computes state for block 144 - uses MTP at 143 (still < startTime)
    # State at hash(287) computes state for block 288 - uses MTP at 287 (past startTime)
    let stateAt143 = getStateFor(
      deployment,
      makeBlockHash(143),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check stateAt143 == tsDefined  # MTP at 143 < startTime

    let stateAt287 = getStateFor(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )
    check stateAt287 == tsStarted  # MTP at 287 >= startTime

    # The sinceHeight should tell us when STARTED began
    # Since STARTED begins at period 2 (block 288), sinceHeight = 288
    let sinceHeight = getStateSinceHeight(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    )

    # STARTED state began at height 288 (first block of third period)
    check sinceHeight == period * 2

  test "taproot deployment parameters":
    let mainnetTaproot = taprootDeployment(Mainnet)
    check mainnetTaproot.bit == 2
    check mainnetTaproot.period == 2016
    check mainnetTaproot.threshold == 1815  # 90%
    check mainnetTaproot.minActivationHeight == 709632

    let testnetTaproot = taprootDeployment(Testnet4)
    check testnetTaproot.startTime == AlwaysActive

    let regtestTaproot = taprootDeployment(Regtest)
    check regtestTaproot.startTime == AlwaysActive
    check regtestTaproot.period == 144

  test "version bits cache management":
    let cache = newVersionBitsCache()
    check cache.stateCaches.len == 0

    # Add to cache directly
    cache.getDeploymentCache(0)[makeBlockHash(0)] = tsStarted
    check cache.stateCaches.len == 1
    check makeBlockHash(0) in cache.stateCaches[0]
    check cache.stateCaches[0][makeBlockHash(0)] == tsStarted

    cache.clear()
    check cache.stateCaches.len == 0

  test "is deployment active helper":
    let chain = newMockChain()
    let startTime = 1000000'i64
    let period = 144

    # Three periods of full signaling -> ACTIVE
    for i in 0 ..< period * 3:
      let ts = uint32(startTime + 100 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let deployment = BIP9Deployment(
      name: "test",
      bit: 2,
      startTime: startTime,
      timeout: 9000000,
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )

    var cache = initTable[BlockHash, ThresholdState]()

    # End of period 2 - should be LOCKED_IN, not active yet
    check isDeploymentActive(
      deployment,
      makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    ) == false

    # End of period 3 - should be ACTIVE
    check isDeploymentActive(
      deployment,
      makeBlockHash(period * 3 - 1),
      chain.getBlockIndex(),
      chain.getMtp(),
      cache
    ) == true

when isMainModule:
  # Run all tests
  discard
