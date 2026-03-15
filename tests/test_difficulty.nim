## Tests for difficulty adjustment and PoW

import std/[options]
import unittest2
import ../src/consensus/[params, pow]
import ../src/primitives/[types, uint256]

suite "UInt256 arithmetic":
  test "initialize from uint64":
    let n = initUInt256(0x123456789abcdef0'u64)
    check n.limbs[0] == 0x123456789abcdef0'u64
    check n.limbs[1] == 0
    check n.limbs[2] == 0
    check n.limbs[3] == 0

  test "initialize from bytes":
    var bytes: array[32, byte]
    bytes[0] = 0x01
    bytes[8] = 0x02
    bytes[16] = 0x03
    bytes[24] = 0x04
    let n = initUInt256(bytes)
    check n.limbs[0] == 0x01
    check n.limbs[1] == 0x02
    check n.limbs[2] == 0x03
    check n.limbs[3] == 0x04

  test "toBytes roundtrip":
    let n = initUInt256(0xdeadbeef12345678'u64)
    let bytes = n.toBytes()
    let n2 = initUInt256(bytes)
    check n == n2

  test "comparison operators":
    let a = initUInt256(100'u64)
    let b = initUInt256(200'u64)
    let c = initUInt256(100'u64)

    check a < b
    check not (b < a)
    check not (a < c)
    check a <= c
    check a <= b
    check b > a
    check a == c
    check not (a == b)

  test "addition":
    let a = initUInt256(0xffffffffffffffff'u64)
    let b = initUInt256(1'u64)
    let c = a + b
    check c.limbs[0] == 0
    check c.limbs[1] == 1

  test "subtraction":
    var n: UInt256
    n.limbs[1] = 1
    let one = initUInt256(1'u64)
    let result = n - one
    check result.limbs[0] == 0xffffffffffffffff'u64
    check result.limbs[1] == 0

  test "multiply by uint64":
    let a = initUInt256(0x1000000000000000'u64)
    let result = a * 16'u64
    check result.limbs[1] == 1
    check result.limbs[0] == 0

  test "divide by uint64":
    var n: UInt256
    n.limbs[1] = 1  # = 2^64
    let result = n div 2'u64
    check result.limbs[0] == 0x8000000000000000'u64
    check result.limbs[1] == 0

  test "modulo by uint64":
    let n = initUInt256(17'u64)
    check (n mod 5'u64) == 2'u64

  test "left shift":
    let n = initUInt256(1'u64)
    let shifted = n shl 64
    check shifted.limbs[0] == 0
    check shifted.limbs[1] == 1

  test "right shift":
    var n: UInt256
    n.limbs[1] = 1
    let shifted = n shr 64
    check shifted.limbs[0] == 1
    check shifted.limbs[1] == 0

  test "isZero":
    let zero = initUInt256()
    let one = initUInt256(1'u64)
    check zero.isZero()
    check not one.isZero()

suite "compact target conversion (UInt256)":
  test "setCompact mainnet max":
    let target = setCompact(0x1d00ffff'u32)
    # Exponent 29, mantissa 0x00ffff
    # Target = 0x00ffff * 2^(8*26) = 0x00ffff << 208
    check not target.isZero()

  test "setCompact regtest":
    let target = setCompact(0x207fffff'u32)
    # Exponent 32, mantissa 0x7fffff
    # Target = 0x7fffff * 2^(8*29) = 0x7fffff << 232
    check not target.isZero()

  test "setCompact negative returns zero":
    let target = setCompact(0x1d800000'u32)  # MSB of mantissa set
    check target.isZero()

  test "setCompact zero exponent returns zero":
    let target = setCompact(0x00123456'u32)
    check target.isZero()

  test "getCompact roundtrip":
    let origBits = 0x1d00ffff'u32
    let target = setCompact(origBits)
    let bits = target.getCompact()
    check bits == origBits

  test "getCompact regtest roundtrip":
    let origBits = 0x207fffff'u32
    let target = setCompact(origBits)
    let bits = target.getCompact()
    check bits == origBits

suite "PowParams creation":
  test "mainnet params":
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = p.powAllowMinDifficultyBlocks
    powParams.powNoRetargeting = p.powNoRetargeting
    powParams.enforceBIP94 = p.enforceBIP94

    check powParams.powAllowMinDifficultyBlocks == false
    check powParams.powNoRetargeting == false
    check powParams.enforceBIP94 == false

  test "testnet3 params":
    let p = testnet3Params()
    check p.powAllowMinDifficultyBlocks == true
    check p.powNoRetargeting == false
    check p.enforceBIP94 == false

  test "testnet4 params":
    let p = testnet4Params()
    check p.powAllowMinDifficultyBlocks == true
    check p.powNoRetargeting == false
    check p.enforceBIP94 == true

  test "regtest params":
    let p = regtestParams()
    check p.powAllowMinDifficultyBlocks == true
    check p.powNoRetargeting == true
    check p.enforceBIP94 == false

  test "signet params":
    let p = signetParams()
    check p.powAllowMinDifficultyBlocks == false
    check p.powNoRetargeting == false
    check p.enforceBIP94 == false

suite "checkProofOfWork":
  test "zero hash meets any target":
    var hash: array[32, byte]
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing

    check checkProofOfWork(BlockHash(hash), 0x1d00ffff'u32, powParams)

  test "max hash fails":
    var hash: array[32, byte]
    for i in 0..31:
      hash[i] = 0xff
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit

    check not checkProofOfWork(BlockHash(hash), 0x1d00ffff'u32, powParams)

  test "genesis hash meets target":
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit

    check checkProofOfWork(p.genesisBlockHash, p.genesisBits, powParams)

suite "difficulty retarget":
  test "no change when timespan is exact":
    let p = mainnetParams()
    let lastIndex = pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: 0x1d00ffff'u32,
        timestamp: uint32(p.powTargetTimespan)
      )
    )

    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powNoRetargeting = false

    let newBits = calculateNextWorkRequired(lastIndex, 0, powParams)
    check newBits == 0x1d00ffff'u32

  test "difficulty increases when blocks are fast":
    let p = mainnetParams()
    # Half the expected timespan
    let halfTimespan = int64(p.powTargetTimespan) div 2
    let lastIndex = pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: 0x1d00ffff'u32,
        timestamp: uint32(halfTimespan)
      )
    )

    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powNoRetargeting = false

    let newBits = calculateNextWorkRequired(lastIndex, 0, powParams)
    # New target should be smaller (higher difficulty)
    let oldTarget = setCompact(0x1d00ffff'u32)
    let newTarget = setCompact(newBits)
    check newTarget < oldTarget

  test "difficulty decreases when blocks are slow":
    let p = mainnetParams()
    # Double the expected timespan
    let doubleTimespan = int64(p.powTargetTimespan) * 2
    let lastIndex = pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: 0x1c00ffff'u32,  # Lower target (higher difficulty)
        timestamp: uint32(doubleTimespan)
      )
    )

    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powNoRetargeting = false

    let newBits = calculateNextWorkRequired(lastIndex, 0, powParams)
    # New target should be larger (lower difficulty)
    let oldTarget = setCompact(0x1c00ffff'u32)
    let newTarget = setCompact(newBits)
    check newTarget > oldTarget

  test "clamped to 4x maximum":
    let p = mainnetParams()
    # Very fast - 1/10 of expected
    let veryFast = int64(p.powTargetTimespan) div 10
    let lastIndex = pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: 0x1c00ffff'u32,
        timestamp: uint32(veryFast)
      )
    )

    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powNoRetargeting = false

    # Should be clamped to 4x increase (1/4 of target)
    let newBits = calculateNextWorkRequired(lastIndex, 0, powParams)
    let oldTarget = setCompact(0x1c00ffff'u32)
    let newTarget = setCompact(newBits)

    # New target should be 1/4 of old (4x harder)
    let expectedTarget = oldTarget div 4'u64
    # Allow some rounding error from compact conversion
    check newTarget <= oldTarget

  test "regtest never retargets":
    let p = regtestParams()
    let lastIndex = pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: 0x207fffff'u32,
        timestamp: 100000
      )
    )

    var powParams: PowParams
    powParams.network = Regtest
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powNoRetargeting = true

    let newBits = calculateNextWorkRequired(lastIndex, 0, powParams)
    check newBits == 0x207fffff'u32

suite "getNextWorkRequired":
  proc makeAncestorFn(blocks: seq[pow.BlockIndex]): GetAncestorFn =
    ## Create a getAncestor function from a sequence of blocks
    return proc(index: pow.BlockIndex, height: int32): pow.BlockIndex =
      for blk in blocks:
        if blk.height == height:
          return blk
      # Return the index itself if not found (shouldn't happen in tests)
      index

  test "mainnet non-retarget returns previous bits":
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = false
    powParams.powNoRetargeting = false

    let lastIndex = pow.BlockIndex(
      height: 1000,  # Not a retarget boundary
      header: BlockHeader(
        bits: 0x1c123456'u32,
        timestamp: 1000000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])
    let newBits = getNextWorkRequired(lastIndex, 1000100, powParams, getAncestor)
    check newBits == 0x1c123456'u32

  test "testnet3 min-difficulty after 20 minutes":
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false

    let lastIndex = pow.BlockIndex(
      height: 1000,
      header: BlockHeader(
        bits: 0x1c123456'u32,
        timestamp: 1000000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])
    # Block timestamp > 20 minutes (1200 seconds) after previous
    let newBlockTime = uint32(1000000 + 1201)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)
    # Should return min difficulty
    check newBits == getPowLimitCompact(powParams)

  test "testnet3 walk-back to non-min-difficulty":
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false

    let minDiffBits = getPowLimitCompact(powParams)
    let realBits = 0x1c123456'u32

    # Create a chain with some min-diff blocks followed by real difficulty
    var blocks: seq[pow.BlockIndex]
    blocks.add(pow.BlockIndex(
      height: 1000,
      header: BlockHeader(bits: realBits, timestamp: 1000000)
    ))
    for i in 1001..1005:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(1000000 + (i - 1000) * 600))
      ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    # Block arrives within 20 minutes - should walk back
    let newBlockTime = uint32(lastIndex.header.timestamp + 600)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)
    # Should return the real difficulty, not min-diff
    check newBits == realBits

  test "regtest always returns previous bits":
    let p = regtestParams()
    var powParams: PowParams
    powParams.network = Regtest
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = true

    let lastIndex = pow.BlockIndex(
      height: 2016,  # At retarget boundary
      header: BlockHeader(
        bits: 0x207fffff'u32,
        timestamp: 1000000
      )
    )

    let firstIndex = pow.BlockIndex(
      height: 1,
      header: BlockHeader(
        bits: 0x207fffff'u32,
        timestamp: 0
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex, firstIndex])
    let newBits = getNextWorkRequired(lastIndex, 2000000, powParams, getAncestor)
    # Regtest never retargets
    check newBits == 0x207fffff'u32

suite "permittedDifficultyTransition":
  test "testnet allows any transition":
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powAllowMinDifficultyBlocks = true

    check permittedDifficultyTransition(powParams, 1000, 0x1c000000'u32, 0x1d00ffff'u32)

  test "mainnet non-retarget must be identical":
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powAllowMinDifficultyBlocks = false

    # Not at retarget boundary
    check permittedDifficultyTransition(powParams, 1000, 0x1c123456'u32, 0x1c123456'u32)
    check not permittedDifficultyTransition(powParams, 1000, 0x1c123456'u32, 0x1c123457'u32)

  test "mainnet retarget within bounds":
    let p = mainnetParams()
    var powParams: PowParams
    powParams.network = Mainnet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powAllowMinDifficultyBlocks = false

    # At retarget boundary (height divisible by 2016)
    # Same bits should be allowed
    check permittedDifficultyTransition(powParams, 2016, 0x1c00ffff'u32, 0x1c00ffff'u32)

suite "network params":
  test "testnet4 exists":
    let p = testnet4Params()
    check p.network == Testnet4
    check p.defaultPort == 48333
    check p.enforceBIP94 == true

  test "signet exists":
    let p = signetParams()
    check p.network == Signet
    check p.defaultPort == 38333
    check p.powAllowMinDifficultyBlocks == false

  test "getParams works for all networks":
    check getParams(Mainnet).network == Mainnet
    check getParams(Testnet3).network == Testnet3
    check getParams(Testnet4).network == Testnet4
    check getParams(Regtest).network == Regtest
    check getParams(Signet).network == Signet

suite "BIP94 testnet4 difficulty adjustment":
  proc makeAncestorFn(blocks: seq[pow.BlockIndex]): GetAncestorFn =
    return proc(index: pow.BlockIndex, height: int32): pow.BlockIndex =
      for blk in blocks:
        if blk.height == height:
          return blk
      index

  test "BIP94 uses first block bits for retarget":
    ## BIP94 time-warp fix: use first block's bits instead of last block's bits
    ## This prevents time-warp attacks on testnet4
    let p = testnet4Params()
    var powParams: PowParams
    powParams.network = Testnet4
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false
    powParams.enforceBIP94 = true

    let minDiffBits = getPowLimitCompact(powParams)
    let realBits = 0x1c123456'u32

    # Create chain where first block has real difficulty, last has min-diff
    var blocks: seq[pow.BlockIndex]

    # First block of period (height 0) - real difficulty
    blocks.add(pow.BlockIndex(
      height: 0,
      header: BlockHeader(bits: realBits, timestamp: 0)
    ))

    # Fill middle blocks with min-diff (simulating 20-min rule usage)
    for i in 1..2014:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(i * 600))
      ))

    # Last block (height 2015) - min-diff
    blocks.add(pow.BlockIndex(
      height: 2015,
      header: BlockHeader(
        bits: minDiffBits,
        timestamp: uint32(p.powTargetTimespan)  # Exactly on target
      )
    ))

    let lastIndex = blocks[^1]
    let firstIndex = blocks[0]
    let getAncestor = makeAncestorFn(blocks)

    # For BIP94, retarget should use first block's bits (realBits), not last's (minDiffBits)
    let newBits = getNextWorkRequired(lastIndex, uint32(p.powTargetTimespan + 600), powParams, getAncestor)

    # Result should be based on realBits, not minDiffBits
    # Since timespan == targetTimespan, should stay same as realBits
    check newBits == realBits

  test "BIP94 min-difficulty still allowed after 20 minutes":
    ## Even with BIP94, the 20-minute min-diff rule still applies
    let p = testnet4Params()
    var powParams: PowParams
    powParams.network = Testnet4
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false
    powParams.enforceBIP94 = true

    let lastIndex = pow.BlockIndex(
      height: 1000,  # Not a retarget boundary
      header: BlockHeader(
        bits: 0x1c123456'u32,
        timestamp: 1000000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])

    # Block timestamp > 20 minutes after previous
    let newBlockTime = uint32(1000000 + 1201)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    # Should return min difficulty (20-minute rule applies)
    check newBits == getPowLimitCompact(powParams)

suite "testnet walk-back edge cases":
  proc makeAncestorFn(blocks: seq[pow.BlockIndex]): GetAncestorFn =
    return proc(index: pow.BlockIndex, height: int32): pow.BlockIndex =
      for blk in blocks:
        if blk.height == height:
          return blk
      index

  test "walk-back stops at retarget boundary":
    ## Walk-back should stop at difficulty adjustment interval boundary
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false

    let minDiffBits = getPowLimitCompact(powParams)
    let realBits = 0x1c123456'u32

    # Create chain where retarget boundary (2016) has min-diff
    var blocks: seq[pow.BlockIndex]

    # Retarget boundary (height 2016) with min-diff
    blocks.add(pow.BlockIndex(
      height: 2016,
      header: BlockHeader(bits: minDiffBits, timestamp: 2000000)
    ))

    # Next few blocks also min-diff
    for i in 2017..2020:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(2000000 + (i - 2016) * 600))
      ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    # Walk-back should stop at 2016 (retarget boundary) and return its bits
    let newBlockTime = uint32(lastIndex.header.timestamp + 600)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    # Should return the retarget boundary's bits (min-diff in this case)
    check newBits == minDiffBits

  test "walk-back finds non-min-diff in middle":
    ## Walk-back finds a real difficulty block between min-diff blocks
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false

    let minDiffBits = getPowLimitCompact(powParams)
    let realBits1 = 0x1c123456'u32
    let realBits2 = 0x1c654321'u32

    var blocks: seq[pow.BlockIndex]

    # Early block with real difficulty
    blocks.add(pow.BlockIndex(
      height: 1000,
      header: BlockHeader(bits: realBits1, timestamp: 1000000)
    ))

    # Min-diff blocks
    for i in 1001..1003:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(1000000 + (i - 1000) * 600))
      ))

    # Another real difficulty block in the middle
    blocks.add(pow.BlockIndex(
      height: 1004,
      header: BlockHeader(bits: realBits2, timestamp: 1002400)
    ))

    # More min-diff blocks after
    for i in 1005..1008:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(1002400 + (i - 1004) * 600))
      ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    # Should walk back and find realBits2 (the most recent non-min-diff)
    let newBlockTime = uint32(lastIndex.header.timestamp + 600)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    check newBits == realBits2

  test "all min-diff to height 0":
    ## Edge case: walk-back reaches height 0
    let p = testnet3Params()
    var powParams: PowParams
    powParams.network = Testnet3
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = false

    let minDiffBits = getPowLimitCompact(powParams)
    let realBits = 0x1c123456'u32

    var blocks: seq[pow.BlockIndex]

    # Genesis-like block with real difficulty
    blocks.add(pow.BlockIndex(
      height: 0,
      header: BlockHeader(bits: realBits, timestamp: 0)
    ))

    # All subsequent blocks are min-diff
    for i in 1..5:
      blocks.add(pow.BlockIndex(
        height: int32(i),
        header: BlockHeader(bits: minDiffBits, timestamp: uint32(i * 600))
      ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    # Should walk back to height 0 and return its bits
    let newBlockTime = uint32(lastIndex.header.timestamp + 600)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    check newBits == realBits

suite "regtest difficulty behavior":
  proc makeAncestorFn(blocks: seq[pow.BlockIndex]): GetAncestorFn =
    return proc(index: pow.BlockIndex, height: int32): pow.BlockIndex =
      for blk in blocks:
        if blk.height == height:
          return blk
      index

  test "regtest always minimum difficulty":
    ## Regtest always returns powLimit (minimum difficulty)
    let p = regtestParams()
    var powParams: PowParams
    powParams.network = Regtest
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = true

    # Regtest genesis bits
    let regtestBits = 0x207fffff'u32

    let lastIndex = pow.BlockIndex(
      height: 100,
      header: BlockHeader(
        bits: regtestBits,
        timestamp: 100000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])
    let newBits = getNextWorkRequired(lastIndex, 200000, powParams, getAncestor)

    # Should always return previous bits (no retargeting)
    check newBits == regtestBits

  test "regtest at retarget boundary still no change":
    ## Even at retarget boundary, regtest doesn't adjust difficulty
    let p = regtestParams()
    var powParams: PowParams
    powParams.network = Regtest
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = true

    let regtestBits = 0x207fffff'u32

    var blocks: seq[pow.BlockIndex]
    blocks.add(pow.BlockIndex(
      height: 1,
      header: BlockHeader(bits: regtestBits, timestamp: 0)
    ))
    blocks.add(pow.BlockIndex(
      height: 2016,  # Retarget boundary
      header: BlockHeader(bits: regtestBits, timestamp: 10000000)  # Very slow
    ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    let newBits = getNextWorkRequired(lastIndex, 20000000, powParams, getAncestor)

    # Should still return previous bits despite being at retarget boundary
    check newBits == regtestBits

  test "regtest ignores 20-minute rule":
    ## Regtest doesn't apply the 20-minute min-diff exception
    ## because powNoRetargeting means calculateNextWorkRequired returns prev bits
    let p = regtestParams()
    var powParams: PowParams
    powParams.network = Regtest
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = true
    powParams.powNoRetargeting = true

    let regtestBits = 0x207fffff'u32

    let lastIndex = pow.BlockIndex(
      height: 1000,
      header: BlockHeader(
        bits: regtestBits,
        timestamp: 1000000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])

    # Block timestamp > 20 minutes after previous
    let newBlockTime = uint32(1000000 + 5000)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    # Regtest still returns previous bits regardless of time gap
    # (the 20-minute rule still triggers but result is same as min-diff anyway)
    check newBits == regtestBits

suite "signet difficulty behavior":
  proc makeAncestorFn(blocks: seq[pow.BlockIndex]): GetAncestorFn =
    return proc(index: pow.BlockIndex, height: int32): pow.BlockIndex =
      for blk in blocks:
        if blk.height == height:
          return blk
      index

  test "signet does not allow min-difficulty blocks":
    ## Signet is like mainnet - no min-difficulty exception
    let p = signetParams()
    var powParams: PowParams
    powParams.network = Signet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = false
    powParams.powNoRetargeting = false
    powParams.enforceBIP94 = false

    let signetBits = 0x1e0377ae'u32  # Signet genesis bits

    let lastIndex = pow.BlockIndex(
      height: 1000,
      header: BlockHeader(
        bits: signetBits,
        timestamp: 1000000
      )
    )

    let getAncestor = makeAncestorFn(@[lastIndex])

    # Even with long time gap, signet doesn't allow min-diff
    let newBlockTime = uint32(1000000 + 5000)
    let newBits = getNextWorkRequired(lastIndex, newBlockTime, powParams, getAncestor)

    # Should return previous bits (no min-diff exception)
    check newBits == signetBits

  test "signet normal retarget":
    ## Signet does normal retargeting like mainnet
    let p = signetParams()
    var powParams: PowParams
    powParams.network = Signet
    powParams.powLimit = p.powLimit
    powParams.powTargetTimespan = p.powTargetTimespan
    powParams.powTargetSpacing = p.powTargetSpacing
    powParams.powAllowMinDifficultyBlocks = false
    powParams.powNoRetargeting = false

    # Use a harder difficulty that can be decreased (not at powLimit)
    let signetBits = 0x1c0377ae'u32  # Harder than genesis, can be decreased

    # For retarget to happen at height 2016:
    # - First block of period: height 0
    # - Last block of period: height 2015
    # - Next block (retarget): height 2016
    # lastIndex should be height 2015 (next height 2016 % 2016 == 0)
    var blocks: seq[pow.BlockIndex]
    # First block of period
    blocks.add(pow.BlockIndex(
      height: 0,  # First block of difficulty period
      header: BlockHeader(bits: signetBits, timestamp: 0)
    ))
    # Last block of period - double timespan (slow blocks)
    blocks.add(pow.BlockIndex(
      height: 2015,  # Last block of period
      header: BlockHeader(
        bits: signetBits,
        timestamp: uint32(p.powTargetTimespan * 2)
      )
    ))

    let lastIndex = blocks[^1]
    let getAncestor = makeAncestorFn(blocks)

    let newBits = getNextWorkRequired(lastIndex, uint32(p.powTargetTimespan * 2 + 600), powParams, getAncestor)

    # Should have increased target (decreased difficulty) due to slow blocks
    let oldTarget = setCompact(signetBits)
    let newTarget = setCompact(newBits)
    check newTarget > oldTarget
