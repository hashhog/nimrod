## Tests for checkpoint verification
##
## Tests cover:
## - Checkpoint hash verification at known heights
## - Fork rejection below the last checkpoint
## - Minimum chain work validation
## - AssumeValid optimization
## - Network-specific checkpoint data

import std/[options, strutils, tables]
import unittest2
import ../src/consensus/[params, chain, validation]
import ../src/primitives/types

proc hexToBytes32(hex: string): array[32, byte] =
  assert hex.len == 64
  for i in 0..31:
    let h = hex[i*2 ..< i*2 + 2]
    result[31 - i] = byte(parseHexInt(h))

suite "checkpoint state initialization":
  test "mainnet checkpoint state":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Should have multiple checkpoints
    check params.checkpoints.len > 0
    check state.checkpointMap.len == params.checkpoints.len

    # Last checkpoint should be the highest
    check state.lastCheckpointHeight > 0

    # Minimum chain work should be non-zero
    var isZero = true
    for b in state.minimumChainWork:
      if b != 0:
        isZero = false
        break
    check not isZero

  test "testnet3 checkpoint state":
    let params = testnet3Params()
    let state = initCheckpointState(params)

    # Testnet3 should have at least one checkpoint
    check params.checkpoints.len >= 1

    # Minimum chain work should be set
    var isZero = true
    for b in state.minimumChainWork:
      if b != 0:
        isZero = false
        break
    check not isZero

  test "testnet4 checkpoint state":
    let params = testnet4Params()
    let state = initCheckpointState(params)

    # Testnet4 is new, may have no historical checkpoints
    check params.checkpoints.len >= 0

    # But should have minimum chain work
    var isZero = true
    for b in state.minimumChainWork:
      if b != 0:
        isZero = false
        break
    check not isZero

  test "signet checkpoint state":
    let params = signetParams()
    let state = initCheckpointState(params)

    # Signet should have minimum chain work
    var isZero = true
    for b in state.minimumChainWork:
      if b != 0:
        isZero = false
        break
    check not isZero

  test "regtest has no checkpoints":
    let params = regtestParams()
    let state = initCheckpointState(params)

    # Regtest should have no checkpoints
    check params.checkpoints.len == 0
    check state.lastCheckpointHeight == 0

    # Minimum chain work should be zero
    var isZero = true
    for b in state.minimumChainWork:
      if b != 0:
        isZero = false
        break
    check isZero

suite "checkpoint hash verification":
  test "verify checkpoint at correct height":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Pick a known checkpoint (block 11111)
    let height = 11111'u32
    let expectedHash = BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
    ))

    # Verify it passes
    let result = state.verifyCheckpoint(height, expectedHash)
    check result.isOk

  test "reject wrong hash at checkpoint height":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Use a checkpoint height but wrong hash
    let height = 11111'u32
    let wrongHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ))

    let result = state.verifyCheckpoint(height, wrongHash)
    check not result.isOk
    check result.error == ceCheckpointMismatch

  test "non-checkpoint height always passes":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Use a height that's not a checkpoint
    let height = 12345'u32  # Not a checkpoint
    let anyHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000042"
    ))

    # Should pass since it's not a checkpoint height
    check not state.isCheckpointHeight(height)
    let result = state.verifyCheckpoint(height, anyHash)
    check result.isOk

  test "getCheckpointHash returns expected value":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Check a known checkpoint
    let hashOpt = state.getCheckpointHash(11111'u32)
    check hashOpt.isSome
    check hashOpt.get() == BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
    ))

    # Check a non-checkpoint height
    let noneOpt = state.getCheckpointHash(12345'u32)
    check noneOpt.isNone

suite "fork rejection":
  test "cannot fork below last checkpoint":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Try to fork at height 100 (below all checkpoints)
    check not state.canForkAt(100)

    let result = state.verifyForkPoint(100)
    check not result.isOk
    check result.error == ceForkBelowCheckpoint

  test "can fork above last checkpoint":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Fork point above last checkpoint should be allowed
    let highHeight = state.lastCheckpointHeight + 1000
    check state.canForkAt(highHeight)

    let result = state.verifyForkPoint(highHeight)
    check result.isOk

  test "regtest allows any fork":
    let params = regtestParams()
    let state = initCheckpointState(params)

    # Regtest has no checkpoints, so any fork is allowed
    check state.canForkAt(0)
    check state.canForkAt(1)
    check state.canForkAt(1000)

    let result = state.verifyForkPoint(0)
    check result.isOk

suite "minimum chain work":
  test "mainnet minimum work is non-trivial":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Zero work should not meet requirement
    let zeroWork: array[32, byte] = default(array[32, byte])
    check not state.meetsMinimumWork(zeroWork)

    let result = state.verifyMinimumWork(zeroWork)
    check not result.isOk
    check result.error == ceInsufficientWork

  test "mainnet accepts sufficient work":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Use the minimum chain work itself (should pass exactly)
    let result = state.verifyMinimumWork(state.minimumChainWork)
    check result.isOk

  test "mainnet accepts more than minimum work":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Create work that's higher than minimum (set all bytes to 0xff)
    var highWork: array[32, byte]
    for i in 0..31:
      highWork[i] = 0xff

    check state.meetsMinimumWork(highWork)
    let result = state.verifyMinimumWork(highWork)
    check result.isOk

  test "regtest has no minimum work":
    let params = regtestParams()
    let state = initCheckpointState(params)

    # Even zero work should pass for regtest
    let zeroWork: array[32, byte] = default(array[32, byte])
    check state.meetsMinimumWork(zeroWork)

    let result = state.verifyMinimumWork(zeroWork)
    check result.isOk

suite "assume valid":
  test "mainnet has assume valid block":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Should have non-zero assume-valid hash
    let zeroHash = BlockHash(default(array[32, byte]))
    check state.assumeValidHash != zeroHash

  test "isAssumeValidBlock matches exact hash":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # The exact assume-valid hash should match
    check state.isAssumeValidBlock(state.assumeValidHash)

    # A different hash should not match
    let differentHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ))
    check not state.isAssumeValidBlock(differentHash)

  test "regtest has no assume valid":
    let params = regtestParams()
    let state = initCheckpointState(params)

    let zeroHash = BlockHash(default(array[32, byte]))
    check state.assumeValidHash == zeroHash

    # Any hash should return false
    let anyHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000042"
    ))
    check not state.isAssumeValidBlock(anyHash)

  test "script verification skip logic":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Should skip for assume-valid block itself
    check state.shouldSkipScriptVerification(state.assumeValidHash, false)

    # Should skip for ancestor of assume-valid
    let ancestorHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ))
    check state.shouldSkipScriptVerification(ancestorHash, isAncestorOfAssumeValid = true)

    # Should NOT skip for non-ancestor
    check not state.shouldSkipScriptVerification(ancestorHash, isAncestorOfAssumeValid = false)

suite "header checkpoint validation":
  test "validates checkpoint at correct height":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    let height = 11111'u32
    let correctHash = BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
    ))

    # Should pass with correct hash (not a fork, just normal chain extension)
    let result = state.validateHeaderCheckpoint(height, correctHash)
    check result.isOk

  test "rejects wrong checkpoint hash":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    let height = 11111'u32
    let wrongHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ))

    let result = state.validateHeaderCheckpoint(height, wrongHash)
    check not result.isOk
    check result.error == ceCheckpointMismatch

  test "rejects fork below checkpoint":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Try to add a header from a fork that branches off at height 100
    # (which is below all checkpoints)
    let forkHeight = 100'u32
    let anyHash = BlockHash(hexToBytes32(
      "0000000000000000000000000000000000000000000000000000000000000042"
    ))

    # This is a fork from the main chain at height 100
    let result = state.validateHeaderCheckpoint(forkHeight + 1, anyHash,
                                                  isForkFromMainChain = true,
                                                  forkPointHeight = forkHeight)
    check not result.isOk
    check result.error == ceForkBelowCheckpoint

suite "checkpoint utilities":
  test "getCheckpointsSorted returns sorted list":
    let params = mainnetParams()
    let sorted = getCheckpointsSorted(params)

    # Check that heights are in ascending order
    for i in 1 ..< sorted.len:
      check sorted[i].height > sorted[i-1].height

  test "findLastCheckpointBelow":
    let params = mainnetParams()
    let state = initCheckpointState(params)

    # Find checkpoint below height 50000
    let found = state.findLastCheckpointBelow(50000)
    check found.isSome
    # Should find block 33333 (the highest checkpoint <= 50000)
    check found.get().height == 33333

    # Find checkpoint below height 10000 (below first checkpoint)
    let notFound = state.findLastCheckpointBelow(10000)
    # There's no checkpoint at or below 10000 except genesis...
    # Actually 11111 > 10000, so should return none or genesis
    # Our implementation should return none since 11111 is the first checkpoint
    check notFound.isNone

suite "256-bit work comparison":
  test "compareWork256 zero vs zero":
    let a: array[32, byte] = default(array[32, byte])
    let b: array[32, byte] = default(array[32, byte])
    check compareWork256(a, b) == 0

  test "compareWork256 zero vs nonzero":
    let a: array[32, byte] = default(array[32, byte])
    var b: array[32, byte]
    b[0] = 1
    check compareWork256(a, b) == -1
    check compareWork256(b, a) == 1

  test "compareWork256 different MSB":
    var a: array[32, byte]
    var b: array[32, byte]
    a[31] = 1
    b[31] = 2
    check compareWork256(a, b) == -1
    check compareWork256(b, a) == 1

  test "isZeroWork":
    let zero: array[32, byte] = default(array[32, byte])
    check isZeroWork(zero)

    var nonzero: array[32, byte]
    nonzero[15] = 1
    check not isZeroWork(nonzero)

suite "network checkpoint data":
  test "mainnet has multiple checkpoints":
    let params = mainnetParams()
    # Should have at least 5 well-known checkpoints
    check params.checkpoints.len >= 5

  test "mainnet checkpoint heights are increasing":
    let params = mainnetParams()
    for i in 1 ..< params.checkpoints.len:
      check params.checkpoints[i].height > params.checkpoints[i-1].height

  test "mainnet checkpoints match expected values":
    let params = mainnetParams()

    # Verify a few well-known checkpoints
    # Block 11111
    check params.checkpoints[0].height == 11111
    check params.checkpoints[0].hash == BlockHash(hexToBytes32(
      "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
    ))

    # Block 33333
    check params.checkpoints[1].height == 33333
    check params.checkpoints[1].hash == BlockHash(hexToBytes32(
      "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"
    ))

  test "testnet3 has checkpoint":
    let params = testnet3Params()
    check params.checkpoints.len >= 1

    # Block 546 is a well-known testnet checkpoint
    check params.checkpoints[0].height == 546

  test "testnet4 checkpoint values from Bitcoin Core":
    let params = testnet4Params()

    # Verify minimum chain work matches Bitcoin Core
    let expectedWork = hexToBytes32(
      "0000000000000000000000000000000000000000000009a0fe15d0177d086304"
    )
    check params.minimumChainWork == expectedWork

  test "signet checkpoint values from Bitcoin Core":
    let params = signetParams()

    # Verify minimum chain work matches Bitcoin Core
    let expectedWork = hexToBytes32(
      "00000000000000000000000000000000000000000000000000000b463ea0a4b8"
    )
    check params.minimumChainWork == expectedWork

suite "validation error types":
  test "checkpoint validation errors exist":
    # Ensure the validation error types are defined
    check veCheckpointMismatch.ord > 0
    check veForkBelowCheckpoint.ord > 0
    check veInsufficientChainWork.ord > 0

  test "checkpoint errors have descriptive messages":
    check $veCheckpointMismatch == "block hash does not match checkpoint"
    check $veForkBelowCheckpoint == "cannot fork before the last checkpoint"
    check $veInsufficientChainWork == "chain does not meet minimum work requirement"
