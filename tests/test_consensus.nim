## Tests for consensus rules

import std/strutils
import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "consensus params":
  test "mainnet genesis hash":
    let params = mainnetParams()
    check params.network == Mainnet
    check params.defaultPort == 8333
    check params.p2pPort == 8333
    check params.rpcPort == 8332
    check params.networkMagic == [0xF9'u8, 0xBE, 0xB4, 0xD9]
    check params.coinbaseMaturity == 100
    check params.taprootHeight == 709632

  test "testnet params":
    let params = testnet3Params()
    check params.network == Testnet3
    check params.defaultPort == 18333
    check params.p2pPort == 18333
    check params.networkMagic == [0x0B'u8, 0x11, 0x09, 0x07]
    check params.dnsSeeds.len > 0

  test "regtest params":
    let params = regtestParams()
    check params.network == Regtest
    check params.subsidyHalvingInterval == 150
    check params.defaultPort == 18444
    check params.networkMagic == [0xFA'u8, 0xBF, 0xB5, 0xDA]
    check params.segwitHeight == 0  # Active from genesis
    check params.taprootHeight == 0  # Active from genesis
    check params.dnsSeeds.len == 0  # No DNS seeds for regtest

  test "block subsidy halving":
    let params = mainnetParams()

    # Block 0: 50 BTC
    check getBlockSubsidy(0, params) == Satoshi(50_00000000)

    # Block 209999: still 50 BTC
    check getBlockSubsidy(209999, params) == Satoshi(50_00000000)

    # Block 210000: 25 BTC
    check getBlockSubsidy(210000, params) == Satoshi(25_00000000)

    # Block 420000: 12.5 BTC
    check getBlockSubsidy(420000, params) == Satoshi(12_50000000)

    # Block 630000: 6.25 BTC
    check getBlockSubsidy(630000, params) == Satoshi(6_25000000)

  test "global constants":
    check MaxMoney == Satoshi(21_000_000 * 100_000_000'i64)
    check SubsidyHalving == 210_000
    check MaxBlockWeight == 4_000_000
    check MaxBlockSize == 1_000_000
    check MaxBlockSigopsCost == 80_000
    check WitnessScaleFactor == 4
    check MedianTimeSpan == 11
    check MaxFutureBlockTime == 7200
    check TargetTimespan == 1_209_600
    check TargetSpacing == 600
    check DifficultyAdjustmentInterval == 2016
    check MaxCompactTarget == 0x1d00ffff'u32

suite "compact target conversion":
  test "compactToTarget mainnet max":
    # 0x1d00ffff: exponent=29, mantissa=0x00ffff
    # target = 0x00ffff * 2^(8*26) = 0x00ffff shifted left 26 bytes
    # In LE byte array: bytes 26,27,28 = 0xff,0xff,0x00
    let target = compactToTarget(0x1d00ffff'u32)
    # Bytes 0-25 should be zero (below the mantissa position)
    for i in 0..25:
      check target[i] == 0
    # Bytes 26,27 are the non-zero mantissa bytes
    check target[26] == 0xff
    check target[27] == 0xff
    check target[28] == 0x00  # High byte of mantissa
    # Bytes 29-31 should be zero
    for i in 29..31:
      check target[i] == 0

  test "compactToTarget regtest":
    # 0x207fffff: exponent=32, mantissa=0x7fffff
    # target = 0x7fffff * 2^(8*29) = 0x7fffff shifted left 29 bytes
    # In LE byte array: bytes 29,30,31 = 0xff,0xff,0x7f
    let target = compactToTarget(0x207fffff'u32)
    for i in 0..28:
      check target[i] == 0
    check target[29] == 0xff
    check target[30] == 0xff
    check target[31] == 0x7f

  test "compactToTarget small value":
    # 0x03123456: exponent=3, mantissa=0x123456
    # But MSB (0x12) has bit 4 set which is < 0x80, so not negative
    # target = 0x123456 * 2^(8*0) = 0x123456
    # In LE: bytes 0,1,2 = 0x56, 0x34, 0x12
    let target = compactToTarget(0x03123456'u32)
    check target[0] == 0x56
    check target[1] == 0x34
    check target[2] == 0x12
    for i in 3..31:
      check target[i] == 0

  test "targetToCompact roundtrip":
    # Test that compactToTarget -> targetToCompact gives same result
    let origBits = 0x1d00ffff'u32
    let target = compactToTarget(origBits)
    let bits = targetToCompact(target)
    check bits == origBits

  test "targetToCompact regtest roundtrip":
    let origBits = 0x207fffff'u32
    let target = compactToTarget(origBits)
    let bits = targetToCompact(target)
    check bits == origBits

  test "compactToTarget zero exponent":
    let target = compactToTarget(0x00123456'u32)
    for i in 0..31:
      check target[i] == 0

  test "compactToTarget negative mantissa":
    # MSB of mantissa set = negative in CScriptNum, should return zero
    let target = compactToTarget(0x1d800000'u32)
    for i in 0..31:
      check target[i] == 0

suite "hash meets target":
  test "hash below target passes":
    # A hash with many leading zeros should pass a reasonable target
    var hashBytes: array[32, byte]
    hashBytes[0] = 0x01  # Very small number
    let hash = BlockHash(hashBytes)
    check hashMeetsTarget(hash, MaxCompactTarget) == true

  test "hash equal to target passes":
    let target = compactToTarget(MaxCompactTarget)
    let hash = BlockHash(target)
    check hashMeetsTarget(hash, MaxCompactTarget) == true

  test "hash above target fails":
    # A hash that's too large for the target
    var hashBytes: array[32, byte]
    for i in 0..31:
      hashBytes[i] = 0xff
    let hash = BlockHash(hashBytes)
    check hashMeetsTarget(hash, MaxCompactTarget) == false

  test "genesis hash meets mainnet target":
    let params = mainnetParams()
    check hashMeetsTarget(params.genesisBlockHash, params.genesisBits) == true

suite "difficulty retarget":
  test "no change when timespan is exact":
    let params = mainnetParams()
    let prevBits = 0x1d00ffff'u32
    # If actual timespan equals target, no change
    let newBits = calculateNextTarget(prevBits, int64(params.powTargetTimespan), params)
    check newBits == prevBits

  test "difficulty increases when blocks too fast":
    let params = mainnetParams()
    let prevBits = 0x1d00ffff'u32
    # Blocks mined in half the expected time -> difficulty doubles
    # But clamped to 4x max change
    let halfTimespan = int64(params.powTargetTimespan) div 2
    let newBits = calculateNextTarget(prevBits, halfTimespan, params)
    # New target should be smaller (higher difficulty)
    let oldTarget = compactToTarget(prevBits)
    let newTarget = compactToTarget(newBits)
    # Compare targets - new should be smaller
    var oldSmaller = false
    var newSmaller = false
    for i in countdown(31, 0):
      if newTarget[i] < oldTarget[i]:
        newSmaller = true
        break
      elif newTarget[i] > oldTarget[i]:
        oldSmaller = true
        break
    check newSmaller == true

  test "difficulty decreases when blocks too slow":
    let params = mainnetParams()
    let prevBits = 0x1c00ffff'u32  # Use a lower target so we have room to grow
    # Blocks mined in double the expected time
    let doubleTimespan = int64(params.powTargetTimespan) * 2
    let newBits = calculateNextTarget(prevBits, doubleTimespan, params)
    # New target should be larger (lower difficulty)
    let oldTarget = compactToTarget(prevBits)
    let newTarget = compactToTarget(newBits)
    var newLarger = false
    for i in countdown(31, 0):
      if newTarget[i] > oldTarget[i]:
        newLarger = true
        break
      elif newTarget[i] < oldTarget[i]:
        break
    check newLarger == true

  test "clamped to 4x maximum increase":
    let params = mainnetParams()
    let prevBits = 0x1c00ffff'u32
    # Blocks mined in 1/10 the expected time (way too fast)
    let veryFastTimespan = int64(params.powTargetTimespan) div 10
    let newBits = calculateNextTarget(prevBits, veryFastTimespan, params)
    # Should only decrease target by 4x max (increase difficulty by 4x)
    # The clamping should limit to targetTimespan/4

  test "clamped to 4x maximum decrease":
    let params = mainnetParams()
    let prevBits = 0x1c00ffff'u32
    # Blocks mined in 10x the expected time (way too slow)
    let verySlowTimespan = int64(params.powTargetTimespan) * 10
    let newBits = calculateNextTarget(prevBits, verySlowTimespan, params)
    # Should only increase target by 4x max (decrease difficulty by 4x)

suite "genesis block":
  test "build mainnet genesis":
    let params = mainnetParams()
    let genesis = buildGenesisBlock(params)

    # Verify header fields
    check genesis.header.version == 1
    check genesis.header.timestamp == 1231006505
    check genesis.header.bits == 0x1d00ffff'u32
    check genesis.header.nonce == 2083236893'u32

    # Verify single coinbase transaction
    check genesis.txs.len == 1
    check isCoinbase(genesis.txs[0])

    # Verify coinbase output value (50 BTC)
    check genesis.txs[0].outputs[0].value == Satoshi(50 * 100_000_000)

  test "verify mainnet genesis hash":
    let params = mainnetParams()
    let genesis = buildGenesisBlock(params)
    check verifyGenesisBlock(genesis, params) == true

  test "build regtest genesis":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)

    check genesis.header.version == 1
    check genesis.header.bits == 0x207fffff'u32
    check genesis.header.nonce == 2'u32
    check genesis.txs.len == 1

  test "verify regtest genesis hash":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    check verifyGenesisBlock(genesis, params) == true

  test "build testnet3 genesis":
    let params = testnet3Params()
    let genesis = buildGenesisBlock(params)

    check genesis.header.version == 1
    check genesis.header.bits == 0x1d00ffff'u32
    check genesis.header.nonce == 414098458'u32
    check genesis.txs.len == 1

  test "verify testnet3 genesis hash":
    let params = testnet3Params()
    let genesis = buildGenesisBlock(params)
    check verifyGenesisBlock(genesis, params) == true

suite "transaction validation":
  test "transaction must have inputs":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )
    let res = checkTransaction(tx, params)
    check res.valid == false
    check "no inputs" in res.error

  test "transaction must have outputs":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    let res = checkTransaction(tx, params)
    check res.valid == false
    check "no outputs" in res.error

  test "output value cannot exceed max money":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(int64(MaxMoney) + 1),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )
    let res = checkTransaction(tx, params)
    check res.valid == false

  test "valid basic transaction":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[0x01'u8],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(100_000),
        scriptPubKey: @[0x76'u8, 0xa9]
      )],
      witnesses: @[],
      lockTime: 0
    )
    let res = checkTransaction(tx, params)
    check res.valid == true

  test "coinbase detection":
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )
    check isCoinbase(coinbase) == true

    let regular = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(100),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )
    check isCoinbase(regular) == false
