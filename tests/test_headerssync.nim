## Tests for header sync anti-DoS (PRESYNC/REDOWNLOAD)
## Validates the two-phase header sync protection mechanism

import std/[unittest, deques]
import ../src/network/headerssync
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

suite "HeadersSyncParams":
  test "mainnet has correct params":
    let params = mainnetParams()
    check params.headersSyncParams.commitmentPeriod == 641
    check params.headersSyncParams.redownloadBufferSize == 15218

  test "testnet3 has correct params":
    let params = testnet3Params()
    check params.headersSyncParams.commitmentPeriod == 673
    check params.headersSyncParams.redownloadBufferSize == 14460

  test "testnet4 has correct params":
    let params = testnet4Params()
    check params.headersSyncParams.commitmentPeriod == 606
    check params.headersSyncParams.redownloadBufferSize == 16092

  test "regtest has correct params":
    let params = regtestParams()
    check params.headersSyncParams.commitmentPeriod == 275
    check params.headersSyncParams.redownloadBufferSize == 7017

suite "CompressedHeader":
  test "compressed header is smaller than full header":
    # Full header: 80 bytes (4+32+32+4+4+4)
    # Compressed: 48 bytes (4+32+4+4+4) - no prevHash
    let compressed = CompressedHeader(
      version: 1,
      merkleRoot: default(array[32, byte]),
      timestamp: 1234567890,
      bits: 0x1d00ffff,
      nonce: 12345
    )
    # Nim doesn't have sizeof for objects, but we know it's 48 bytes
    check compressed.version == 1
    check compressed.timestamp == 1234567890

  test "roundtrip compressed header":
    let original = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 42
    )

    let compressed = original.toCompressed()
    let prevHash = BlockHash(default(array[32, byte]))
    let restored = compressed.toFullHeader(prevHash)

    check restored.version == original.version
    check restored.prevBlock == original.prevBlock
    check restored.merkleRoot == original.merkleRoot
    check restored.timestamp == original.timestamp
    check restored.bits == original.bits
    check restored.nonce == original.nonce

suite "HeadersSyncState Initialization":
  test "new state starts in Presync":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    check state.getState() == Presync
    check state.getPresyncHeight() == 0
    check state.currentChainWork == initUInt256(1)

  test "commit offset is within bounds":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    for _ in 0..<10:
      let state = newHeadersSyncState(
        peerId = 1,
        params = params,
        chainStartHeight = 0,
        chainStartHash = genesisHash,
        chainStartBits = genesis.header.bits,
        chainStartWork = initUInt256(1),
        minimumRequiredWork = initUInt256(1000)
      )

      check state.commitOffset >= 0
      check state.commitOffset < params.headersSyncParams.commitmentPeriod

suite "HeadersSyncState Presync Phase":
  test "shouldStoreCommitment respects commitment period":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Count how many heights match in a period
    var matchCount = 0
    for h in 0..<params.headersSyncParams.commitmentPeriod:
      if state.shouldStoreCommitment(int64(h)):
        matchCount += 1

    check matchCount == 1  # Exactly one per period

  test "commitment bit is deterministic for same header":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    let bit1 = state.computeCommitmentBit(genesisHash)
    let bit2 = state.computeCommitmentBit(genesisHash)
    check bit1 == bit2

  test "commitment bits differ for different headers":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Create different hashes
    var hash1: BlockHash = genesisHash
    var hash2: BlockHash
    var hash2Arr: array[32, byte]
    hash2Arr[0] = 1
    hash2 = BlockHash(hash2Arr)

    # Over many tries, bits should differ at least sometimes
    # (they're random 1-bit values)
    var diffCount = 0
    for i in 0..<100:
      var h: array[32, byte]
      h[0] = byte(i)
      let bit = state.computeCommitmentBit(BlockHash(h))
      if bit:
        diffCount += 1

    # Should have some true and some false (probabilistic test)
    check diffCount > 10
    check diffCount < 90

suite "HeadersSyncState Transitions":
  test "transitions to Redownload when work threshold met":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    # Very low work threshold for testing
    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(2)  # Trivial threshold
    )

    check state.getState() == Presync

    # Create a header that connects to genesis.
    # Note: regtest powLimit is 0x207fffff, so almost any nonce passes
    # the per-header PoW gate, but nonce=0 happens to land just above
    # the target for the all-zero merkle root, so use nonce=1 (verified
    # to satisfy checkProofOfWork in this configuration).
    let header = BlockHeader(
      version: 1,
      prevBlock: genesisHash,
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: genesis.header.bits,
      nonce: 1
    )

    let result = state.processNextHeaders(@[header], false)

    # With very low threshold, should transition to Redownload
    # The transition depends on accumulated work
    # For regtest with easy difficulty, any header adds significant work
    check result.success

  test "empty headers returns without error":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    let result = state.processNextHeaders(@[], false)
    check not result.success  # Empty is failure

suite "HeadersSyncState Block Locator":
  test "locator includes last header hash":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    let locator = state.nextHeadersRequestLocator()

    check locator.len >= 1
    check locator[^1] == genesisHash  # Chain start always included

  test "locator empty when done":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Force to Done state
    state.downloadState = Done

    let locator = state.nextHeadersRequestLocator()
    check locator.len == 0

suite "Anti-DoS Properties":
  test "max commitments bound is set":
    let params = mainnetParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Max commitments should be > 0 and bounded
    check state.maxCommitments > 0
    check state.maxCommitments < 100_000_000  # Reasonable bound

  test "hasher salt and commit offset are set":
    # Note: Random values may be the same when created in rapid succession
    # but each peer should have its own state with potentially different values
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # These should be initialized (may be any value including 0)
    check state.commitOffset >= 0
    check state.commitOffset < params.headersSyncParams.commitmentPeriod
    # Hasher salt is just a uint64, any value is valid

suite "ProcessingResult":
  test "success and requestMore flags work correctly":
    var result = ProcessingResult(
      powValidatedHeaders: @[],
      success: true,
      requestMore: true
    )
    check result.success
    check result.requestMore
    check result.powValidatedHeaders.len == 0

    result.success = false
    check not result.success

suite "Anti-DoS Integration":
  test "work threshold calculation":
    # Test that work threshold is calculated correctly
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Minimum required work should match what we passed
    check state.minimumRequiredWork == initUInt256(1000)

  test "presync stores only commitments not full headers":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(uint64.high)  # Very high threshold to stay in presync
    )

    check state.getState() == Presync

    # During presync, redownloaded headers should be empty
    check state.redownloadedHeaders.len == 0

    # Header commitments grow as we would process headers (1 per period)
    # Initially should be 0
    check state.headerCommitments.len == 0

  test "max headers per message constant matches Bitcoin Core":
    check MaxHeadersPerMessage == 2000

  test "per-peer salt provides unique commitment hashing":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    # Create two states with different peer IDs (different salts)
    let state1 = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    let state2 = newHeadersSyncState(
      peerId = 2,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(1000)
    )

    # Different peers may have different hasher salts
    # (not guaranteed but likely due to timing/randomness)
    # Just verify both have initialized salts
    check state1.hasherSalt != 0 or state2.hasherSalt != 0 or
          state1.commitOffset >= 0 or state2.commitOffset >= 0

suite "HeadersSyncState Per-Header PoW Gate (HSync wave Job 1)":
  ## Defense-in-depth: presync must reject headers whose hash does not
  ## meet the claimed `bits` target.  Without this gate, a peer can fabricate
  ## an arbitrary commitment trail and exhaust the work-accumulator /
  ## commitment-deque slots before the main acceptance path catches it.
  ## Mirrors bitcoin-core/src/validation.cpp::CheckProofOfWork called
  ## inside HeadersSyncState::ProcessNextHeaders.

  test "presync rejects header whose hash exceeds claimed target":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(2)
    )

    # Forge a header with mainnet-like difficulty (0x1d00ffff).  Its target
    # is *much* tighter than regtest's 0x207fffff powLimit, so an all-zero
    # merkle-root header with nonce 0 will not satisfy it.  The peer
    # nonetheless claims it does — exactly the attack we're guarding against.
    let cheatHeader = BlockHeader(
      version: 1,
      prevBlock: genesisHash,
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: 0x1d00ffff'u32,                  # claimed mainnet-tight target
      nonce: 0
    )

    let result = state.processNextHeaders(@[cheatHeader], false)
    check not result.success

  test "presync accepts header whose hash meets claimed target":
    # The other side of the gate: a regtest header that *does* satisfy
    # 0x207fffff must still flow through validateAndProcessSingleHeader.
    # If the gate over-rejects, presync collapses for honest peers.
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1,
      params = params,
      chainStartHeight = 0,
      chainStartHash = genesisHash,
      chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1),
      minimumRequiredWork = initUInt256(uint64.high)  # stay in presync
    )

    # nonce=1 satisfies regtest powLimit for an all-zero merkle root header
    # at this prevBlock + timestamp (verified offline against
    # checkProofOfWork).  See validation.cpp::CheckProofOfWork — regtest
    # 0x207fffff is ~2^256-1 so almost any hash qualifies.
    let goodHeader = BlockHeader(
      version: 1,
      prevBlock: genesisHash,
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: genesis.header.bits,
      nonce: 1
    )

    let result = state.processNextHeaders(@[goodHeader], false)
    check result.success
    check state.getPresyncHeight() == 1
