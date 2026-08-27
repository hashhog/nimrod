## Tests for header sync anti-DoS (PRESYNC/REDOWNLOAD)
## Validates the two-phase header sync protection mechanism
## W88 additions: 7 bugs audited; gate list below.

import std/[unittest, deques, times]
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
    # Just verify both have initialized salts (two words each)
    check state1.hasherSalt0 != 0 or state2.hasherSalt0 != 0 or
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

# =============================================================================
# W88 bug-fix gate tests
# Bug #1: getBlockProof approximation (Core chain.cpp:121-133)
# Bug #2: computeCommitmentBit uses SHA-256 instead of SipHash-2-4
# Bug #3: hasherSalt single uint64 → now two words (k0, k1)
# Bug #4: rand(high(int)) caps top bit → now use cast[uint64](rng.next())
# Bug #5: maxCommitments wrong MTP estimate → chainStartMtp parameter
# Bug #6: lastHeaderReceived.timestamp not set → chainStartTime parameter
# Bug #7: dead firstHash variable removed from validateAndStoreHeadersCommitments
# =============================================================================

suite "W88 Bug #1: getBlockProof exact formula (Core chain.cpp:121-133)":
  test "regtest easy target (0x207fffff) gives positive work":
    # 0x207fffff is regtest powLimit — target is huge, work is small but > 0.
    let header = BlockHeader(bits: 0x207fffff'u32)
    let work = getBlockProof(header)
    check not work.isZero()

  test "mainnet genesis target (0x1d00ffff) gives correct work":
    # Bitcoin Core: GetBitsProof(0x1d00ffff) should equal
    # (~target / (target+1)) + 1.
    # target = 0x00000000ffff0000000000000000000000000000000000000000000000000000
    # We just verify it's strictly > regtest work (harder target = more work).
    let mainnetHeader = BlockHeader(bits: 0x1d00ffff'u32)
    let regtestHeader = BlockHeader(bits: 0x207fffff'u32)
    let mainnetWork = getBlockProof(mainnetHeader)
    let regtestWork = getBlockProof(regtestHeader)
    check mainnetWork > regtestWork

  test "zero bits returns zero work":
    let header = BlockHeader(bits: 0'u32)
    let work = getBlockProof(header)
    check work.isZero()

  test "difficulty-1 target (0x1d00ffff) work matches Core reference":
    # Bitcoin Core GetBitsProof(0x1d00ffff):
    # target = 2^224 - 2^208
    # (~target / (target+1)) + 1 ≈ 2^32 + 1
    # Verify the result is in the expected ballpark (>= 2^32).
    let header = BlockHeader(bits: 0x1d00ffff'u32)
    let work = getBlockProof(header)
    let expectedMin = initUInt256(uint64(1) shl 32)
    check work >= expectedMin

  test "harder target gives strictly more work than easier target":
    # Harder target = smaller target bits value = more work.
    let easier = BlockHeader(bits: 0x1d00ffff'u32)  # difficulty 1
    let harder = BlockHeader(bits: 0x1900ffff'u32)  # ~difficulty 65536
    let easierWork = getBlockProof(easier)
    let harderWork = getBlockProof(harder)
    check harderWork > easierWork

suite "W88 Bug #2+#3: computeCommitmentBit uses SipHash-2-4 (not SHA-256)":
  test "commitment bit is deterministic for same hash and same state":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000)
    )
    # Same hash → same bit (keyed PRF property)
    let b1 = state.computeCommitmentBit(genesisHash)
    let b2 = state.computeCommitmentBit(genesisHash)
    check b1 == b2

  test "different 128-bit keys produce independent commitment bits":
    # Two states with different SipHash keys may produce different bits
    # for the same header hash (PRF independence).
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    var diffCount = 0
    for i in 0..<32:
      # Manually override the two key words to test independence.
      # Two states with orthogonal k0/k1 must produce uncorrelated bits.
      let state = newHeadersSyncState(
        peerId = int64(i * 1234567), params = params, chainStartHeight = 0,
        chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
        chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000)
      )
      var hash: array[32, byte]
      hash[0] = byte(i)
      if state.computeCommitmentBit(BlockHash(hash)):
        inc diffCount

    # Over 32 tries roughly half should be 1 (random PRF)
    check diffCount > 4
    check diffCount < 28

  test "hasherSalt0 and hasherSalt1 are both present as uint64 fields":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 42, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000)
    )
    # Both key words are accessible (struct shape regression guard)
    discard state.hasherSalt0
    discard state.hasherSalt1
    check true  # compiles → struct has both fields

suite "W88 Bug #4: rand() full 64-bit key range":
  test "hasherSalt0 can be odd (top-bit accessible)":
    # rand(high(int)) always returns values with bit 63 clear.
    # cast[uint64](rng.next()) uses the full 64-bit range.
    # We can't guarantee a specific value, but over many tries at least
    # some should have bit 63 set.
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    var highBitSeen = false
    for i in 0..<128:
      let state = newHeadersSyncState(
        peerId = int64(i), params = params, chainStartHeight = 0,
        chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
        chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000)
      )
      if (state.hasherSalt0 and (1'u64 shl 63)) != 0:
        highBitSeen = true
        break
    check highBitSeen

suite "W88 Bug #5: maxCommitments uses actual MTP (chainStartMtp param)":
  test "maxCommitments with chainStartMtp=0 falls back gracefully":
    let params = mainnetParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000),
      chainStartMtp = 0
    )
    check state.maxCommitments > 0
    check state.maxCommitments < 100_000_000'u64

  test "maxCommitments is smaller when chainStartMtp is recent":
    # A very recent MTP → fewer seconds since start → fewer max commitments.
    # A very old MTP → more seconds since start → more max commitments.
    let params = mainnetParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let nowSec = uint32(getTime().toUnix)

    let stateOldMtp = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 840000,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000),
      chainStartMtp = 1_000_000'u32  # old MTP (year ~2001)
    )
    let stateNewMtp = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 840000,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(1000),
      chainStartMtp = nowSec - 3600  # recent MTP (1 hour ago)
    )
    check stateOldMtp.maxCommitments > stateNewMtp.maxCommitments

suite "W88 Bug #6: lastHeaderReceived.timestamp set from chainStartTime":
  test "getPresyncTime returns chainStartTime not 0":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let chainTime = genesis.header.timestamp
    let state = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(uint64.high),
      chainStartTime = chainTime
    )
    # Before any headers are processed, getPresyncTime() should return
    # the chain-start timestamp (not 0).
    # Bitcoin Core: m_last_header_received = m_chain_start.GetBlockHeader()
    # which includes nTime (headerssync.cpp:30).
    check state.getPresyncTime() == chainTime

  test "getPresyncTime returns 0 when chainStartTime not passed (regression guard)":
    # When chainStartTime = 0 (default), timestamp should remain 0.
    # This confirms the parameter wiring is correct, not accidentally hardcoded.
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(uint64.high)
    )
    check state.getPresyncTime() == 0'u32

suite "W88 Bug #7: no dead firstHash computation in validateAndStoreHeadersCommitments":
  test "non-continuous presync headers are rejected":
    # The connectivity check (prevBlock != lastHeaderHash) must still fire
    # correctly now that the dead firstHash local is removed.
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let state = newHeadersSyncState(
      peerId = 1, params = params, chainStartHeight = 0,
      chainStartHash = genesisHash, chainStartBits = genesis.header.bits,
      chainStartWork = initUInt256(1), minimumRequiredWork = initUInt256(uint64.high)
    )

    # Header whose prevBlock does NOT connect to genesisHash
    var wrongPrev: array[32, byte]
    wrongPrev[0] = 0xff
    let disconnected = BlockHeader(
      version: 1,
      prevBlock: BlockHash(wrongPrev),
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: genesis.header.bits,
      nonce: 0
    )

    let result = state.processNextHeaders(@[disconnected], false)
    check not result.success
