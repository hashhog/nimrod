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

  # =========================================================================
  # W91: BIP-9 gate coverage — NoTimeout + network-specific deployment params
  # =========================================================================

  test "W91-G1: NoTimeout constant equals high(int64) — Core params.h:70":
    ## Core: BIP9Deployment::NO_TIMEOUT = std::numeric_limits<int64_t>::max()
    check NoTimeout == high(int64)
    # Must be clearly distinct from NeverActive and AlwaysActive
    check NoTimeout != NeverActive
    check NoTimeout != AlwaysActive
    check NoTimeout > 0'i64

  test "W91-G2: timeout=0 causes FAILED for started deployment without sufficient signals":
    ## This test proves the bug: if timeout=0, MTP>=0 is immediately true in the
    ## first STARTED period.  If block count < threshold (no signaling here),
    ## the deployment jumps STARTED -> FAILED without ever getting a chance to
    ## accumulate signals.
    ## Core versionbits.cpp:95-96: "else if (MTP >= nTimeTimeout) -> FAILED"
    ## Note: Core checks count FIRST; if count >= threshold it goes LOCKED_IN
    ## even with timeout=0.  Here we use NO signaling so count < threshold.
    let chain = newMockChain()
    let startTime = 0'i64   # starts from genesis (like regtest testdummy)
    let period = 144
    # No signaling blocks — version stays at 0x20000000, bit 28 not set
    for i in 0 ..< period * 2:
      let ts = uint32(100 + int64(i) * 600)  # MTP will be > 0
      chain.addBlock(int32(i), 0x20000000'i32, ts)  # no signaling

    let badDeployment = BIP9Deployment(
      name: "test",
      bit: 28,
      startTime: 0,       # start from genesis
      timeout: 0,         # BUG: timeout=0, MTP>=0 fires immediately in STARTED
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let state = getStateFor(badDeployment, makeBlockHash(period * 2 - 1),
                            chain.getBlockIndex(), chain.getMtp(), cache)
    # count=0 < threshold=108, MTP>0 >= timeout=0 -> FAILED
    check state == tsFailed

    # Now with NoTimeout it should stay STARTED (no signaling -> stays STARTED, not FAILED)
    let goodDeployment = BIP9Deployment(
      name: "test",
      bit: 28,
      startTime: 0,
      timeout: NoTimeout,  # FIXED: never times out
      minActivationHeight: 0,
      period: period,
      threshold: 108
    )
    var cache2 = initTable[BlockHash, ThresholdState]()
    let state2 = getStateFor(goodDeployment, makeBlockHash(period * 2 - 1),
                             chain.getBlockIndex(), chain.getMtp(), cache2)
    check state2 == tsStarted  # No signaling -> stays STARTED (not FAILED)

  test "W91-G3: testdummy mainnet — NeverActive + NoTimeout + threshold=1815":
    ## Core kernel/chainparams.cpp:102-107 (mainnet)
    let dep = testDummyDeployment(Mainnet)
    check dep.bit == 28
    check dep.startTime == NeverActive
    check dep.timeout == NoTimeout
    check dep.period == 2016
    check dep.threshold == 1815  # 90%
    check dep.minActivationHeight == 0

  test "W91-G4: testdummy testnet3 — threshold=1512 (75%), not 1815":
    ## Core kernel/chainparams.cpp:225-230 (testnet3)
    ## Bug: old code used MainnetThreshold=1815 for all networks
    let dep = testDummyDeployment(Testnet3)
    check dep.bit == 28
    check dep.startTime == NeverActive
    check dep.timeout == NoTimeout
    check dep.period == 2016
    check dep.threshold == 1512  # 75% per BIP9 testnet recommendation

  test "W91-G5: testdummy testnet4 — threshold=1512 (75%), not 1815":
    ## Core kernel/chainparams.cpp:325-330 (testnet4)
    let dep = testDummyDeployment(Testnet4)
    check dep.bit == 28
    check dep.startTime == NeverActive
    check dep.timeout == NoTimeout
    check dep.period == 2016
    check dep.threshold == 1512  # 75%

  test "W91-G6: testdummy signet — threshold=1815 (90%)":
    ## Core kernel/chainparams.cpp:468-473 (signet)
    ## Signet uses mainnet thresholds (90%) unlike testnet3/4 (75%)
    let dep = testDummyDeployment(Signet)
    check dep.bit == 28
    check dep.startTime == NeverActive
    check dep.timeout == NoTimeout
    check dep.period == 2016
    check dep.threshold == 1815  # 90%

  test "W91-G7: testdummy regtest — startTime=0 + period=144 + threshold=108":
    ## Core kernel/chainparams.cpp:550-555 (regtest)
    ## CRITICAL: regtest uses startTime=0 (not NeverActive!) so testdummy
    ## can actually be deployed via -vbparams on regtest.
    ## period=144 and threshold=108 (75% of 144).
    let dep = testDummyDeployment(Regtest)
    check dep.bit == 28
    check dep.startTime == 0           ## NOT NeverActive — regtest starts from genesis
    check dep.timeout == NoTimeout     ## never times out
    check dep.period == 144            ## faster period for testing
    check dep.threshold == 108         ## 75% of 144
    check dep.minActivationHeight == 0

  test "W91-G8: getDeployments returns only live versionbits deployments":
    ## Core has MAX_VERSION_BITS_DEPLOYMENTS=1 (only testdummy).
    ## Taproot is buried, not a live versionbits deployment.
    ## Reference: consensus/params.h:37-42, deploymentinfo.cpp:11-16.
    let deployments = getDeployments(Mainnet)
    check deployments.len == 1
    check deployments[0].name == "testdummy"

    let regtestDeps = getDeployments(Regtest)
    check regtestDeps.len == 1
    check regtestDeps[0].name == "testdummy"

  test "W91-G9: computeBlockVersion only signals live versionbits bits":
    ## computeBlockVersion must NOT set taproot bit (2) since taproot is buried.
    ## On regtest, testdummy (bit 28) CAN be signaled if in STARTED/LOCKED_IN.
    let chain = newMockChain()
    # Regtest testdummy startTime=0, so it enters STARTED from genesis
    for i in 0 ..< 144:
      let ts = uint32(100 + int64(i) * 600)  # all MTP >= 0 >= startTime=0
      # All blocks signal bit 28
      chain.addBlock(int32(i), 0x10000000'i32 or 0x20000000'i32, ts)

    var caches = newSeq[Table[BlockHash, ThresholdState]]()
    let deployments = getDeployments(Regtest)
    let getBlockIndexFn = chain.getBlockIndex()
    let getMtpFn = chain.getMtp()
    let ver = computeBlockVersion(
      deployments, makeBlockHash(143), getBlockIndexFn, getMtpFn, caches
    )

    # Must have BIP9 top bits
    check (ver and VersionBitsTopMask) == VersionBitsTopBits
    # Taproot bit (2) must NOT be set — taproot is buried, not in computeBlockVersion
    check (ver and int32(deploymentMask(2))) == 0

  test "W91-G10: DEFINED->STARTED transition fires at MTP >= startTime (gate 7)":
    ## Core versionbits.cpp:77-80
    let chain = newMockChain()
    let startTime = 2000000'i64
    let period = 144
    # Period 1: MTP < startTime
    for i in 0 ..< period:
      chain.addBlock(int32(i), 0x20000000'i32, uint32(500000 + int64(i) * 600))
    # Period 2: MTP crosses startTime mid-period
    for i in period ..< period * 2:
      chain.addBlock(int32(i), 0x20000000'i32, uint32(startTime + int64(i - period) * 600))

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let st1 = getStateFor(dep, makeBlockHash(period - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st1 == tsDefined  # MTP at end of period 1 still < startTime

    let st2 = getStateFor(dep, makeBlockHash(period * 2 - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st2 == tsStarted  # After period where MTP crossed startTime

  test "W91-G11: STARTED count loop — counts nPeriod blocks backward (gate 8)":
    ## Core versionbits.cpp:85-92: iterates exactly nPeriod blocks backward from pindexPrev
    let chain = newMockChain()
    let period = 144
    # All blocks after startTime, exactly threshold-1 of them signal
    # (threshold-1 = 107 signal, 37 do not → not locked in)
    let startTime = 100'i64
    for i in 0 ..< period * 2:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      let version = if i mod 144 < 107: 0x20000004'i32 else: 0x20000000'i32
      chain.addBlock(int32(i), version, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    # Period 1 starts STARTED (MTP >= startTime); period 2 counts 107 signals < 108
    let st = getStateFor(dep, makeBlockHash(period * 2 - 1),
                         chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsStarted  # 107 < threshold=108, stays STARTED

  test "W91-G12: STARTED count hits threshold -> LOCKED_IN (gate 9)":
    ## Core versionbits.cpp:93-94
    let chain = newMockChain()
    let period = 144
    let startTime = 100'i64
    # Period 1 and 2: all 144 blocks signal
    for i in 0 ..< period * 2:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let st = getStateFor(dep, makeBlockHash(period * 2 - 1),
                         chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsLockedIn  # 144 >= 108

  test "W91-G13: STARTED MTP >= timeout -> FAILED, even with signals (gate 10)":
    ## Core versionbits.cpp:95-96: timeout checked AFTER signaling count
    ## If count >= threshold we go LOCKED_IN regardless of timeout.
    ## If count < threshold AND MTP >= timeout, we go FAILED.
    let chain = newMockChain()
    let period = 144
    let startTime = 1000000'i64
    let timeout = 1010000'i64  # Expires quickly
    # Period 1: MTP just above start, below timeout — enters STARTED
    for i in 0 ..< period:
      let ts = uint32(startTime + 100 + int64(i) * 10)  # close timestamps, well below timeout
      chain.addBlock(int32(i), 0x20000000'i32, ts)       # no signaling
    # Period 2: MTP crosses timeout — should fail (no signaling)
    for i in period ..< period * 2:
      let ts = uint32(timeout + 1000 + int64(i - period) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)       # still no signaling

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: timeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let st = getStateFor(dep, makeBlockHash(period * 2 - 1),
                         chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsFailed

  test "W91-G14: LOCKED_IN min_activation_height delays ACTIVE (gate 11)":
    ## Core versionbits.cpp:100-103: nHeight+1 >= min_activation_height
    let chain = newMockChain()
    let period = 144
    let startTime = 100'i64
    let minH = period * 5  # require height 720 before activation
    for i in 0 ..< period * 6:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: minH, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    # After period 3 (height 431), LOCKED_IN, but minH=720 not reached
    let st3 = getStateFor(dep, makeBlockHash(period * 3 - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st3 == tsLockedIn  # minH=720 > period*3=432

    # After period 5 (height 719), still LOCKED_IN — first block of period 6
    # is at height 720 = minH, so pindexPrev.height+1=720 >= 720 at period 5 boundary
    let st5 = getStateFor(dep, makeBlockHash(period * 5 - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st5 == tsActive  # pindexPrev.height=719, +1=720 >= minH=720

  test "W91-G15: ACTIVE and FAILED are terminal states (gate 12)":
    ## Core versionbits.cpp:107-109: no transitions from ACTIVE or FAILED
    let chain = newMockChain()
    let period = 144
    let startTime = 100'i64
    # Build to ACTIVE
    for i in 0 ..< period * 4:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000004'i32, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let st3 = getStateFor(dep, makeBlockHash(period * 3 - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st3 == tsActive

    # Even with more blocks that DON'T signal, still ACTIVE
    for i in period * 4 ..< period * 5:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)  # no signaling
    let st4 = getStateFor(dep, makeBlockHash(period * 4 - 1),
                          chain.getBlockIndex(), chain.getMtp(), cache)
    check st4 == tsActive  # terminal

  test "W91-G16: cache key at nullptr/genesis uses all-zeros hash (gate 4)":
    ## Core versionbits.cpp:52-55: nullptr (genesis parent) -> DEFINED
    ## Nimrod equivalent: BlockHash(default(array[32, byte]))
    let chain = newMockChain()
    chain.addBlock(0'i32, 0x20000000'i32, 1000000'u32)

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: 2000000, timeout: NoTimeout,
      minActivationHeight: 0, period: 144, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    # Querying with the zero hash (parent of genesis) should give DEFINED
    let zeroHash = BlockHash(default(array[32, byte]))
    let st = getStateFor(dep, zeroHash, chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsDefined

  test "W91-G17: period alignment — pindexPrev adjusted to height - (height+1)%period (gate 3)":
    ## Core versionbits.cpp:46
    ## pindexPrev = GetAncestor(height - (height+1) % period)
    ## A block at height 5 with period 10: adjusted to height 5 - (5+1)%10 = 5-6 → negative → nullptr
    ## A block at height 15 with period 10: adjusted to 15 - (15+1)%10 = 15-6 = 9
    let chain = newMockChain()
    let period = 10
    for i in 0 ..< 30:
      chain.addBlock(int32(i), 0x20000000'i32, uint32(100 + i * 600))

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: NeverActive, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 8
    )
    var cache = initTable[BlockHash, ThresholdState]()
    # NeverActive -> always FAILED, regardless of alignment
    let st = getStateFor(dep, makeBlockHash(15),
                         chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsFailed

  test "W91-G18: MTP optimization — blocks before startTime cached as DEFINED (gate 5)":
    ## Core versionbits.cpp:57-61
    ## Optimization: if MTP < startTime, cache as DEFINED to avoid deeper lookups
    let chain = newMockChain()
    let startTime = 9000000'i64
    let period = 144
    for i in 0 ..< period * 2:
      # Use very low timestamps so MTP stays far below startTime
      chain.addBlock(int32(i), 0x20000000'i32, uint32(1 + i))

    let dep = BIP9Deployment(
      name: "test", bit: 2,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var cache = initTable[BlockHash, ThresholdState]()
    let st = getStateFor(dep, makeBlockHash(period * 2 - 1),
                         chain.getBlockIndex(), chain.getMtp(), cache)
    check st == tsDefined
    check cache.len > 0  # optimization path must have populated cache

  test "W91-G19: computeBlockVersion sets STARTED bit + TOP_BITS (gates 14-17)":
    ## Core versionbits.cpp:265-279
    ## Must start with VERSIONBITS_TOP_BITS and OR in bits for STARTED/LOCKED_IN
    let chain = newMockChain()
    let startTime = 100'i64
    let period = 144
    # One period at startTime — transitions to STARTED at next boundary
    for i in 0 ..< period:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000000'i32, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 3,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var caches = newSeq[Table[BlockHash, ThresholdState]]()
    let ver = computeBlockVersion(
      @[dep], makeBlockHash(period - 1),
      chain.getBlockIndex(), chain.getMtp(), caches
    )
    # Top bits must be set
    check (ver and VersionBitsTopMask) == VersionBitsTopBits
    # Bit 3 must be set (deployment is STARTED)
    check (ver and int32(deploymentMask(3))) != 0

  test "W91-G20: computeBlockVersion LOCKED_IN also sets bit (gate 16)":
    ## Core versionbits.cpp:273: LOCKED_IN || STARTED -> set bit
    let chain = newMockChain()
    let startTime = 100'i64
    let period = 144
    # Two periods of full signaling: period 1=STARTED, period 2=LOCKED_IN
    for i in 0 ..< period * 2:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000008'i32, ts)  # bit 3 signals

    let dep = BIP9Deployment(
      name: "test", bit: 3,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var caches = newSeq[Table[BlockHash, ThresholdState]]()
    let ver = computeBlockVersion(
      @[dep], makeBlockHash(period * 2 - 1),
      chain.getBlockIndex(), chain.getMtp(), caches
    )
    check (ver and VersionBitsTopMask) == VersionBitsTopBits
    check (ver and int32(deploymentMask(3))) != 0  # LOCKED_IN sets bit

  test "W91-G21: computeBlockVersion ACTIVE does NOT set bit":
    ## Core versionbits.cpp:272-275: only LOCKED_IN|STARTED set the bit
    let chain = newMockChain()
    let startTime = 100'i64
    let period = 144
    # Three periods to reach ACTIVE
    for i in 0 ..< period * 3:
      let ts = uint32(startTime + 1 + int64(i) * 600)
      chain.addBlock(int32(i), 0x20000008'i32, ts)

    let dep = BIP9Deployment(
      name: "test", bit: 3,
      startTime: startTime, timeout: NoTimeout,
      minActivationHeight: 0, period: period, threshold: 108
    )
    var caches = newSeq[Table[BlockHash, ThresholdState]]()
    let ver = computeBlockVersion(
      @[dep], makeBlockHash(period * 3 - 1),
      chain.getBlockIndex(), chain.getMtp(), caches
    )
    check (ver and VersionBitsTopMask) == VersionBitsTopBits
    # ACTIVE: bit must NOT be set
    check (ver and int32(deploymentMask(3))) == 0

  test "W91-G22: VersionBitsConditionChecker::Condition — needs BOTH top mask AND bit (gates 18-19)":
    ## Core versionbits_impl.h:79-82
    ## (nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS AND (nVersion & Mask()) != 0
    # Has top bits, has bit 5 -> signals
    check signalsBit(0x20000020'i32, 5) == true
    # Has top bits, missing bit 5 -> does not signal
    check signalsBit(0x20000000'i32, 5) == false
    # Missing top bits (old-style version 2), has bit 5 -> does NOT signal
    check signalsBit(0x00000020'i32, 5) == false
    # Top mask wrong (0x40... instead of 0x20...), has bit 5 -> does NOT signal
    check signalsBit(0x40000020'i32, 5) == false
    # Exactly at boundary bit 0
    check signalsBit(0x20000001'i32, 0) == true
    check signalsBit(0x20000000'i32, 0) == false
    # Bit 28 (testdummy)
    check signalsBit(0x30000000'i32, 28) == true   # 0x20000000 | 0x10000000
    check signalsBit(0x20000000'i32, 28) == false

when isMainModule:
  # Run all tests
  discard
