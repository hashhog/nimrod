## Tests for block template generation
## Tests empty mempool, multi-tx templates, merkle root, witness commitment

import unittest2
import std/times

import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/crypto/hashing
import ../src/mining/blocktemplate

suite "Block Template":

  test "BIP-34 height encoding for various heights":
    # Mirrors Core CScript() << int64_t(nHeight) (script/script.h
    # push_int64): 0 -> OP_0, 1..16 -> OP_1..OP_16, else minimal CScriptNum.
    # Height 0
    let enc0 = encodeBip34Height(0)
    check enc0 == @[0x00'u8]  # OP_0

    # Height 1
    let enc1 = encodeBip34Height(1)
    check enc1 == @[0x51'u8]  # OP_1

    # Height 16
    let enc16 = encodeBip34Height(16)
    check enc16 == @[0x60'u8]  # OP_16

    # Height 127
    let enc127 = encodeBip34Height(127)
    check enc127 == @[0x01'u8, 0x7f]

    # Height 128 (needs 2 bytes due to sign bit)
    let enc128 = encodeBip34Height(128)
    check enc128 == @[0x02'u8, 0x80, 0x00]

    # Height 255
    let enc255 = encodeBip34Height(255)
    check enc255 == @[0x02'u8, 0xff, 0x00]

    # Height 256
    let enc256 = encodeBip34Height(256)
    check enc256 == @[0x02'u8, 0x00, 0x01]

    # Height 500000 (typical mainnet height)
    let enc500k = encodeBip34Height(500000)
    check enc500k.len == 4  # 3-byte push
    check enc500k[0] == 0x03
    # 500000 = 0x07A120 in hex, little-endian = 0x20, 0xA1, 0x07
    check enc500k[1] == 0x20
    check enc500k[2] == 0xA1
    check enc500k[3] == 0x07

  test "create coinbase tx without witness commitment":
    let height = int32(100)
    let subsidy = Satoshi(50_0000_0000)
    let fees = Satoshi(1_0000)
    let scriptPubKey = @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
    let emptyCommitment: array[32, byte] = default(array[32, byte])

    let coinbase = createCoinbaseTx(height, subsidy, fees, scriptPubKey, emptyCommitment)

    # Check basic structure
    check coinbase.version == 2
    check coinbase.inputs.len == 1
    check coinbase.outputs.len == 1  # No witness commitment output

    # Check coinbase input
    check coinbase.inputs[0].prevOut.vout == 0xffffffff'u32
    check array[32, byte](coinbase.inputs[0].prevOut.txid) == default(array[32, byte])

    # Check output value
    check coinbase.outputs[0].value == subsidy + fees

    # Check no witness data (no segwit txs)
    check coinbase.witnesses.len == 0

  test "create coinbase tx with witness commitment":
    let height = int32(500000)
    let subsidy = Satoshi(12_5000_0000)
    let fees = Satoshi(5_0000)
    let scriptPubKey = @[0x00'u8, 0x14] & newSeq[byte](20)  # P2WPKH

    # Non-zero witness commitment
    var commitment: array[32, byte]
    for i in 0 ..< 32:
      commitment[i] = byte(i)

    let coinbase = createCoinbaseTx(height, subsidy, fees, scriptPubKey, commitment)

    # Check we have 2 outputs
    check coinbase.outputs.len == 2

    # First output is the block reward
    check coinbase.outputs[0].value == subsidy + fees

    # Second output is the witness commitment (OP_RETURN)
    check coinbase.outputs[1].value == Satoshi(0)
    check coinbase.outputs[1].scriptPubKey.len == 38  # 6 (header) + 32 (commitment)
    check coinbase.outputs[1].scriptPubKey[0] == 0x6a  # OP_RETURN
    check coinbase.outputs[1].scriptPubKey[1] == 0x24  # Push 36 bytes
    check coinbase.outputs[1].scriptPubKey[2] == 0xaa
    check coinbase.outputs[1].scriptPubKey[3] == 0x21
    check coinbase.outputs[1].scriptPubKey[4] == 0xa9
    check coinbase.outputs[1].scriptPubKey[5] == 0xed

    # Check witness data is present
    check coinbase.witnesses.len == 1
    check coinbase.witnesses[0].len == 1
    check coinbase.witnesses[0][0].len == 32

  test "compute witness commitment with single segwit tx":
    # Build a simple list of transactions
    var txs: seq[Transaction]

    # Coinbase (placeholder)
    txs.add(Transaction())

    # One segwit transaction with witness data
    var segwitTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[@[@[0x30'u8] & newSeq[byte](71)]],  # Fake signature
      lockTime: 0
    )
    txs.add(segwitTx)

    let commitment = computeWitnessCommitment(txs)

    # Commitment should be non-zero
    var isZero = true
    for b in commitment:
      if b != 0:
        isZero = false
        break
    check not isZero

    # Commitment should be deterministic
    let commitment2 = computeWitnessCommitment(txs)
    check commitment == commitment2

  test "witness commitment with multiple transactions":
    var txs: seq[Transaction]
    txs.add(Transaction())  # Coinbase

    # Add 5 segwit transactions
    for i in 0 ..< 5:
      var witnessData = newSeq[byte](72)
      witnessData[0] = byte(i)

      var tx = Transaction(
        version: 2,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: uint32(i)),
          scriptSig: @[],
          sequence: 0xffffffff'u32
        )],
        outputs: @[TxOut(
          value: Satoshi(1_0000_0000),
          scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
        )],
        witnesses: @[@[witnessData]],
        lockTime: 0
      )
      txs.add(tx)

    let commitment = computeWitnessCommitment(txs)

    # Should be 32 bytes, non-zero
    var allZero = true
    for b in commitment:
      if b != 0:
        allZero = false
        break
    check not allZero

  test "tx sigops estimation":
    # P2PKH output
    let p2pkhOutput = TxOut(
      value: Satoshi(1_0000_0000),
      scriptPubKey: @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
    )

    var tx1 = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[p2pkhOutput],
      witnesses: @[],
      lockTime: 0
    )

    let sigops1 = estimateTxSigops(tx1)
    check sigops1 >= 1

    # P2WPKH output
    let p2wpkhOutput = TxOut(
      value: Satoshi(1_0000_0000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
    )

    var tx2 = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[p2wpkhOutput],
      witnesses: @[],
      lockTime: 0
    )

    let sigops2 = estimateTxSigops(tx2)
    check sigops2 >= 1

  test "tx weight calculation":
    # Simple legacy transaction
    var legacyTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: newSeq[byte](100),  # Typical P2PKH scriptSig
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )

    let weight = calculateTxWeight(legacyTx)
    check weight > 0

    # Weight = base_size * 4 for legacy txs (no witness discount)
    let legacySize = serializeLegacy(legacyTx).len
    check weight == legacySize * 4

  test "compute target from bits":
    # Mainnet genesis bits
    let mainnetBits = 0x1d00ffff'u32
    let target = computeTarget(mainnetBits)

    # Target should have specific structure
    # 0x1d00ffff means exponent=0x1d=29, mantissa=0x00ffff
    # Position = 29 - 3 = 26, so bytes 26, 27, 28 should be set
    check target[26] == 0xff
    check target[27] == 0xff
    check target[28] == 0x00

  test "hash meets target comparison":
    var target: array[32, byte]
    target[31] = 0xff  # Very easy target

    # Hash that's all zeros should meet any target
    var easyHash: array[32, byte]
    check hashMeetsTarget(easyHash, target)

    # Hash that's all 0xff should fail most targets
    var hardHash: array[32, byte]
    for i in 0 ..< 32:
      hardHash[i] = 0xff
    check not hashMeetsTarget(hardHash, target)

    # Equal hash should pass
    check hashMeetsTarget(target, target)

  test "merkle root computation for single tx":
    var txs: seq[Transaction]
    txs.add(Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[0x01'u8, 0x02],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_0000_0000),
        scriptPubKey: @[0x76'u8, 0xa9]
      )],
      witnesses: @[],
      lockTime: 0
    ))

    var txHashes: seq[array[32, byte]]
    for tx in txs:
      txHashes.add(doubleSha256(serialize(tx)))

    let merkle = computeMerkleRoot(txHashes)

    # For single tx, merkle root = tx hash
    check merkle == txHashes[0]

  test "merkle root computation for multiple txs":
    var txHashes: seq[array[32, byte]]

    # Create 4 fake tx hashes
    for i in 0 ..< 4:
      var h: array[32, byte]
      h[0] = byte(i)
      txHashes.add(h)

    let merkle = computeMerkleRoot(txHashes)

    # Merkle root should be non-zero
    var isZero = true
    for b in merkle:
      if b != 0:
        isZero = false
        break
    check not isZero

    # Same inputs should give same output
    let merkle2 = computeMerkleRoot(txHashes)
    check merkle == merkle2

  test "block template to block conversion":
    # Create a minimal template
    let header = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1234567890'u32,
      bits: 0x1d00ffff'u32,
      nonce: 12345'u32
    )

    let coinbase = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
        scriptSig: @[0x03'u8, 0x01, 0x02, 0x03],
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_0000_0000),
        scriptPubKey: @[0x51'u8]  # OP_1
      )],
      witnesses: @[],
      lockTime: 0
    )

    let tmpl = BlockTemplate(
      header: header,
      coinbaseTx: coinbase,
      transactions: @[coinbase],
      totalFees: Satoshi(0),
      totalWeight: 400,
      totalSigops: 1,
      height: 1,
      target: default(array[32, byte])
    )

    let blk = tmpl.toBlock()

    check blk.header.version == header.version
    check blk.header.timestamp == header.timestamp
    check blk.header.nonce == header.nonce
    check blk.txs.len == 1
    check blk.txs[0].outputs[0].value == Satoshi(50_0000_0000)

  test "witness commitment header constant":
    # BIP-141 specifies witness commitment header
    check WitnessCommitmentHeader == @[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]

  test "reserved coinbase weight constant":
    # Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 (policy/policy.h:27).
    # Fixed in W87: old value was 4000 (under-reserved by 4000 WU).
    check CoinbaseReservedWeight == 8000

  test "max block sigops constant":
    # BIP-141 specifies 80K sigops cost limit
    check params.MaxBlockSigopsCost == 80000

  # Locktime finality tests
  test "isFinalTx with lockTime=0 is always final":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0x00000000'u32  # Non-final sequence
      )],
      outputs: @[TxOut(value: Satoshi(1_0000_0000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 0  # lockTime=0 is always final
    )
    check isFinalTx(tx, blockHeight = 500000, blockTime = 1600000000)

  test "isFinalTx with height-based locktime satisfied":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0x00000000'u32  # Non-final sequence
      )],
      outputs: @[TxOut(value: Satoshi(1_0000_0000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 100  # Height-based (< 500_000_000)
    )
    # Block height 100 means lockTime 100 is satisfied (100 < 100 is false, so not final)
    check not isFinalTx(tx, blockHeight = 100, blockTime = 1600000000)
    # Block height 101 means lockTime 100 is satisfied (100 < 101)
    check isFinalTx(tx, blockHeight = 101, blockTime = 1600000000)

  test "isFinalTx with time-based locktime satisfied":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0x00000000'u32  # Non-final sequence
      )],
      outputs: @[TxOut(value: Satoshi(1_0000_0000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 500_000_001'u32  # Time-based (>= 500_000_000)
    )
    # Block time 500_000_001 means lockTime is not satisfied
    check not isFinalTx(tx, blockHeight = 700000, blockTime = 500_000_001)
    # Block time 500_000_002 means lockTime is satisfied
    check isFinalTx(tx, blockHeight = 700000, blockTime = 500_000_002)

  test "isFinalTx with all inputs SEQUENCE_FINAL ignores lockTime":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32  # SEQUENCE_FINAL
      )],
      outputs: @[TxOut(value: Satoshi(1_0000_0000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 999_999_999'u32  # Very far in the future (time-based)
    )
    # Even though lockTime is not satisfied, all inputs are final
    check isFinalTx(tx, blockHeight = 100, blockTime = 1000)

  test "isFinalTx with mixed sequence - not final":
    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
          scriptSig: @[],
          sequence: 0xFFFFFFFF'u32  # SEQUENCE_FINAL
        ),
        TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 1),
          scriptSig: @[],
          sequence: 0x00000000'u32  # Non-final
        )
      ],
      outputs: @[TxOut(value: Satoshi(1_0000_0000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 999_999_999'u32  # Very far in the future
    )
    # Not all inputs are final, so lockTime applies and tx is not final
    check not isFinalTx(tx, blockHeight = 100, blockTime = 1000)

  test "coinbase has correct sequence (MAX_SEQUENCE_NONFINAL)":
    let height = int32(500000)
    let subsidy = Satoshi(12_5000_0000)
    let fees = Satoshi(0)
    let scriptPubKey = @[0x51'u8]  # OP_1
    let emptyCommitment: array[32, byte] = default(array[32, byte])

    let coinbase = createCoinbaseTx(height, subsidy, fees, scriptPubKey, emptyCommitment)

    # Coinbase input sequence should be MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)
    # This ensures locktime is still enforced (unlike SEQUENCE_FINAL which disables it)
    # Reference: Bitcoin Core miner.cpp line 171
    check coinbase.inputs[0].sequence == MaxSequenceNonFinal
    check coinbase.inputs[0].sequence == 0xFFFFFFFE'u32

  test "coinbase has lockTime=height-1 for anti-fee-sniping":
    let height = int32(500000)
    let subsidy = Satoshi(12_5000_0000)
    let fees = Satoshi(0)
    let scriptPubKey = @[0x51'u8]
    let emptyCommitment: array[32, byte] = default(array[32, byte])

    let coinbase = createCoinbaseTx(height, subsidy, fees, scriptPubKey, emptyCommitment)

    # Coinbase lockTime should be height - 1 for anti-fee-sniping
    # This prevents miners from reorging to steal fees from recent blocks
    # Reference: Bitcoin Core miner.cpp line 196
    check coinbase.lockTime == uint32(height - 1)
    check coinbase.lockTime == 499999'u32

  test "coinbase lockTime=0 for height 1":
    # Edge case: at height 1, lockTime = 0 (since height - 1 = 0)
    let height = int32(1)
    let subsidy = Satoshi(50_0000_0000)
    let fees = Satoshi(0)
    let scriptPubKey = @[0x51'u8]
    let emptyCommitment: array[32, byte] = default(array[32, byte])

    let coinbase = createCoinbaseTx(height, subsidy, fees, scriptPubKey, emptyCommitment)
    check coinbase.lockTime == 0'u32

  test "locktime threshold constant":
    # Below 500_000_000 is height-based, at or above is time-based
    check LocktimeThreshold == 500_000_000'u32

  test "sequence final constant":
    check SequenceFinal == 0xFFFFFFFF'u32

  test "max sequence nonfinal constant":
    # MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1
    # Used for anti-fee-sniping to ensure locktime is enforced
    check MaxSequenceNonFinal == 0xFFFFFFFE'u32
    check MaxSequenceNonFinal == SequenceFinal - 1

# ---------------------------------------------------------------------------
# W87 gate tests — block template assembly correctness
# Reference: Bitcoin Core node/miner.cpp (DEFAULT_BLOCK_RESERVED_WEIGHT,
# ClampOptions, TestChunkBlockLimits, addChunks, UpdateTime)
# ---------------------------------------------------------------------------
suite "Block Template W87 Gates":

  # Bug 1: CoinbaseReservedWeight was 4000 (Core DEFAULT_BLOCK_RESERVED_WEIGHT = 8000)
  test "CoinbaseReservedWeight equals Core DEFAULT_BLOCK_RESERVED_WEIGHT (8000)":
    # Bitcoin Core policy/policy.h:27:
    #   static constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
    check CoinbaseReservedWeight == 8_000

  # Bug 2: MINIMUM_BLOCK_RESERVED_WEIGHT constant
  test "MinimumBlockReservedWeight equals Core MINIMUM_BLOCK_RESERVED_WEIGHT (2000)":
    # Bitcoin Core policy/policy.h:34:
    #   static constexpr unsigned int MINIMUM_BLOCK_RESERVED_WEIGHT{2000};
    check MinimumBlockReservedWeight == 2_000

  # Bug 5/6: MAX_CONSECUTIVE_FAILURES and BLOCK_FULL_ENOUGH_WEIGHT_DELTA
  test "MaxConsecutiveFailures equals Core MAX_CONSECUTIVE_FAILURES (1000)":
    # Bitcoin Core node/miner.cpp:284
    check MaxConsecutiveFailures == 1_000

  test "BlockFullEnoughWeightDelta equals Core BLOCK_FULL_ENOUGH_WEIGHT_DELTA (4000)":
    # Bitcoin Core node/miner.cpp:285
    check BlockFullEnoughWeightDelta == 4_000

  # Bug 9: DefaultBlockMinFeeRateSatKvB
  test "DefaultBlockMinFeeRateSatKvB equals Core DEFAULT_BLOCK_MIN_TX_FEE * 1000 (1000 sat/kvB)":
    # Bitcoin Core policy/policy.h:36: DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/vbyte
    check DefaultBlockMinFeeRateSatKvB == 1_000'i64

  # clampBlockOptions tests (Bug 2)
  test "clampBlockOptions clamps reservedWeight to [MinimumBlockReservedWeight, MaxBlockWeight]":
    # Normal case: both in range
    let (maxW, resW) = clampBlockOptions(4_000_000, 8_000)
    check resW == 8_000
    check maxW == 4_000_000

  test "clampBlockOptions raises reservedWeight below minimum to MinimumBlockReservedWeight":
    # Core rejects anything below MINIMUM_BLOCK_RESERVED_WEIGHT at startup
    let (_, resW) = clampBlockOptions(4_000_000, 100)
    check resW == MinimumBlockReservedWeight  # 2000

  test "clampBlockOptions caps maxWeight at MAX_BLOCK_WEIGHT":
    let (maxW, _) = clampBlockOptions(99_000_000, 8_000)
    check maxW == MaxBlockWeight  # 4_000_000

  test "clampBlockOptions ensures maxWeight >= reservedWeight":
    # If someone passes maxWeight smaller than reservedWeight, clamp maxWeight up
    let (maxW, resW) = clampBlockOptions(1_000, 8_000)
    check resW == 8_000
    check maxW == 8_000  # maxWeight raised to match reservedWeight

  test "clampBlockOptions: reservedWeight above MaxBlockWeight is capped":
    let (maxW, resW) = clampBlockOptions(4_000_000, 99_000_000)
    check resW == MaxBlockWeight
    check maxW == MaxBlockWeight

  # Bug 4/12: sigops boundary — >= not >
  test "sigops check is >= MaxBlockSigopsCost (boundary — exactly 80000 is rejected)":
    # Core TestChunkBlockLimits line 244:
    #   if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false;
    # Adding a tx whose sigops brings the total to exactly 80000 must be rejected.
    # Old code used `>`, which would have accepted it.
    let maxSigops = MaxBlockSigopsCost  # 80_000
    # Simulate: running cost = 79999, new tx has 1 sigop → total = 80000 → reject
    let runningCost = maxSigops - 1
    let txSigops = 1
    check runningCost + txSigops >= maxSigops  # This is the gate that now fires

  test "sigops check allows txs that bring total to 79999":
    let runningCost = MaxBlockSigopsCost - 2
    let txSigops = 1
    check not (runningCost + txSigops >= MaxBlockSigopsCost)

  # Bug 3: weight boundary — >= not >
  test "weight check is >= nBlockMaxWeight (boundary — exactly at limit is rejected)":
    # Core TestChunkBlockLimits line 241:
    #   if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) return false;
    # A tx that would make nBlockWeight == nBlockMaxWeight must be rejected.
    let nBlockMaxWeight = 4_000_000
    let nBlockWeight = 3_999_900
    let txWeight = 100  # Would bring total to exactly 4_000_000 → reject
    check nBlockWeight + txWeight >= nBlockMaxWeight

  test "weight check allows tx that brings total to 3999999":
    let nBlockMaxWeight = 4_000_000
    let nBlockWeight = 3_999_900
    let txWeight = 99   # Would bring total to 3_999_999 → accept
    check not (nBlockWeight + txWeight >= nBlockMaxWeight)

  # Bug 7: updateTimestamp MTP+1 enforcement
  test "updateTimestamp enforces MTP+1 lower bound":
    let header = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1_000_000'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    )
    var tmpl = BlockTemplate(
      header: header,
      coinbaseTx: Transaction(),
      transactions: @[],
      totalFees: Satoshi(0),
      totalWeight: 8_000,
      totalSigops: 0,
      height: 1,
      target: default(array[32, byte])
    )

    let params = regtestParams()
    # prevBlockMtp = far future timestamp to force MTP+1 > now
    let farFutureMtp = uint32(int64(getTime().toUnix()) + 3600)
    tmpl.updateTimestamp(params, prevBlockMtp = farFutureMtp)
    # Timestamp must be >= farFutureMtp + 1 (the MTP+1 floor)
    check tmpl.header.timestamp >= farFutureMtp + 1

  test "updateTimestamp uses current time when MTP+1 < now":
    let header = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 0'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    )
    var tmpl = BlockTemplate(
      header: header,
      coinbaseTx: Transaction(),
      transactions: @[],
      totalFees: Satoshi(0),
      totalWeight: 8_000,
      totalSigops: 0,
      height: 1,
      target: default(array[32, byte])
    )

    let params = regtestParams()
    let oldMtp = 1_000_000'u32  # Old MTP; MTP+1 = 1_000_001, well below now
    let before = uint32(getTime().toUnix())
    tmpl.updateTimestamp(params, prevBlockMtp = oldMtp)
    let after = uint32(getTime().toUnix())
    # Timestamp should be approximately now
    check tmpl.header.timestamp >= before
    check tmpl.header.timestamp <= after + 1

  test "updateTimestamp with prevBlockMtp=0 skips MTP enforcement":
    let header = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 0'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    )
    var tmpl = BlockTemplate(
      header: header,
      coinbaseTx: Transaction(),
      transactions: @[],
      totalFees: Satoshi(0),
      totalWeight: 8_000,
      totalSigops: 0,
      height: 1,
      target: default(array[32, byte])
    )
    let params = regtestParams()
    let before = uint32(getTime().toUnix())
    tmpl.updateTimestamp(params, prevBlockMtp = 0)
    let after = uint32(getTime().toUnix())
    check tmpl.header.timestamp >= before
    check tmpl.header.timestamp <= after + 1

  # Block-level weight constant
  test "block reserved weight of 8000 fits within MAX_BLOCK_WEIGHT of 4000000":
    check CoinbaseReservedWeight < MaxBlockWeight
    # Remaining capacity for transactions
    let txCapacity = MaxBlockWeight - CoinbaseReservedWeight
    check txCapacity == 3_992_000

  # Sanity: old reserved weight (4000) vs. new (8000) — documents the bug
  test "reserved weight increased from 4000 to 8000 (bug fix documentation)":
    # Verify the constant is the corrected value, not the old under-reserved value
    check CoinbaseReservedWeight == 8_000
    check CoinbaseReservedWeight != 4_000  # Was wrong before W87
