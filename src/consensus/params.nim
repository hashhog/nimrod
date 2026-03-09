## Bitcoin consensus parameters
## Network-specific constants for mainnet, testnet, regtest

import ../primitives/types
import std/strutils

type
  Network* = enum
    Mainnet
    Testnet3
    Regtest

  ConsensusParams* = object
    network*: Network
    networkMagic*: array[4, byte]
    defaultPort*: uint16
    dnsSeeds*: seq[string]
    genesisBlockHash*: BlockHash
    genesisPrevHash*: BlockHash
    genesisTimestamp*: uint32
    genesisBits*: uint32
    genesisNonce*: uint32
    genesisVersion*: int32
    subsidyHalvingInterval*: int
    maxBlockWeight*: int
    maxBlockSize*: int
    maxBlockSigopsCost*: int
    coinbaseMaturity*: int
    bip34Height*: int
    bip65Height*: int
    bip66Height*: int
    segwitHeight*: int
    taprootHeight*: int
    powLimit*: array[32, byte]
    powTargetTimespan*: int
    powTargetSpacing*: int
    difficultyAdjustmentInterval*: int
    minRelayTxFee*: Satoshi
    dustLimit*: Satoshi
    # Legacy aliases
    p2pPort*: uint16
    rpcPort*: uint16

# Global consensus constants
const
  MaxMoney* = Satoshi(21_000_000 * 100_000_000'i64)
  SubsidyHalving* = 210_000
  MaxBlockWeight* = 4_000_000
  MaxBlockSize* = 1_000_000
  MaxBlockSigopsCost* = 80_000
  WitnessScaleFactor* = 4
  MedianTimeSpan* = 11
  MaxFutureBlockTime* = 7200  # 2 hours in seconds
  TargetTimespan* = 1_209_600  # 14 days in seconds
  TargetSpacing* = 600         # 10 minutes in seconds
  DifficultyAdjustmentInterval* = 2016
  MaxCompactTarget* = 0x1d00ffff'u32

proc hexToBytes32(hex: string): array[32, byte] =
  assert hex.len == 64
  for i in 0..31:
    let h = hex[i*2 ..< i*2 + 2]
    result[31 - i] = byte(parseHexInt(h))

proc mainnetParams*(): ConsensusParams =
  result.network = Mainnet
  result.networkMagic = [0xF9'u8, 0xBE, 0xB4, 0xD9]
  result.defaultPort = 8333
  result.dnsSeeds = @[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl"
  ]
  result.genesisBlockHash = BlockHash(hexToBytes32(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1231006505
  result.genesisBits = 0x1d00ffff'u32
  result.genesisNonce = 2083236893'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210_000
  result.maxBlockWeight = 4_000_000
  result.maxBlockSize = 1_000_000
  result.maxBlockSigopsCost = 80_000
  result.coinbaseMaturity = 100
  result.bip34Height = 227931
  result.bip65Height = 388381
  result.bip66Height = 363725
  result.segwitHeight = 481824
  result.taprootHeight = 709632
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600  # 14 days
  result.powTargetSpacing = 600  # 10 minutes
  result.difficultyAdjustmentInterval = 2016
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Legacy aliases
  result.p2pPort = 8333
  result.rpcPort = 8332

proc testnet3Params*(): ConsensusParams =
  result.network = Testnet3
  result.networkMagic = [0x0B'u8, 0x11, 0x09, 0x07]
  result.defaultPort = 18333
  result.dnsSeeds = @[
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "testnet-seed.bluematt.me"
  ]
  result.genesisBlockHash = BlockHash(hexToBytes32(
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1296688602
  result.genesisBits = 0x1d00ffff'u32
  result.genesisNonce = 414098458'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210_000
  result.maxBlockWeight = 4_000_000
  result.maxBlockSize = 1_000_000
  result.maxBlockSigopsCost = 80_000
  result.coinbaseMaturity = 100
  result.bip34Height = 21111
  result.bip65Height = 581885
  result.bip66Height = 330776
  result.segwitHeight = 834624
  result.taprootHeight = 0  # Active from genesis on testnet3
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Legacy aliases
  result.p2pPort = 18333
  result.rpcPort = 18332

proc regtestParams*(): ConsensusParams =
  result.network = Regtest
  result.networkMagic = [0xFA'u8, 0xBF, 0xB5, 0xDA]
  result.defaultPort = 18444
  result.dnsSeeds = @[]  # No DNS seeds for regtest
  result.genesisBlockHash = BlockHash(hexToBytes32(
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1296688602
  result.genesisBits = 0x207fffff'u32
  result.genesisNonce = 2'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 150
  result.maxBlockWeight = 4_000_000
  result.maxBlockSize = 1_000_000
  result.maxBlockSigopsCost = 80_000
  result.coinbaseMaturity = 100
  result.bip34Height = 500
  result.bip65Height = 1351
  result.bip66Height = 1251
  result.segwitHeight = 0  # Active from genesis
  result.taprootHeight = 0  # Active from genesis
  result.powLimit = hexToBytes32(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Legacy aliases
  result.p2pPort = 18444
  result.rpcPort = 18443

proc getParams*(network: Network): ConsensusParams =
  case network
  of Mainnet: mainnetParams()
  of Testnet3: testnet3Params()
  of Regtest: regtestParams()

proc getBlockSubsidy*(height: int, params: ConsensusParams): Satoshi =
  ## Calculate block subsidy at given height
  let halvings = height div params.subsidyHalvingInterval
  if halvings >= 64:
    return Satoshi(0)
  var subsidy = int64(50 * 100_000_000)  # 50 BTC in satoshis
  subsidy = subsidy shr halvings
  Satoshi(subsidy)

# Compact target (nBits) conversion functions
# Format: 1 byte exponent, 3 bytes mantissa (big-endian in the compact form)
# Target = mantissa * 2^(8*(exponent-3))

proc compactToTarget*(bits: uint32): array[32, byte] =
  ## Convert compact target representation (nBits) to 256-bit target
  ## Compact format: [exponent: 8 bits][mantissa: 24 bits]
  ## Exponent indicates the size in bytes of the target value
  ## Result is stored in little-endian byte order
  let exponent = int((bits shr 24) and 0xff)
  let mantissa = bits and 0x007fffff

  # Handle negative bit (MSB of mantissa is sign in CScriptNum)
  if (bits and 0x00800000) != 0:
    # Negative target - return zero
    return default(array[32, byte])

  if exponent == 0:
    return default(array[32, byte])

  # Place mantissa at the right position
  # The mantissa represents bytes at positions [exponent-3, exponent-1]
  # stored big-endian in the compact representation
  if exponent <= 3:
    # Target fits in the mantissa, right-shift
    let shift = (3 - exponent) * 8
    let val = mantissa shr shift
    result[0] = byte(val and 0xff)
    result[1] = byte((val shr 8) and 0xff)
    result[2] = byte((val shr 16) and 0xff)
  else:
    # Place the 3-byte mantissa at the right position
    let pos = exponent - 3
    if pos < 32:
      result[pos] = byte(mantissa and 0xff)
    if pos + 1 < 32:
      result[pos + 1] = byte((mantissa shr 8) and 0xff)
    if pos + 2 < 32:
      result[pos + 2] = byte((mantissa shr 16) and 0xff)

proc targetToCompact*(target: array[32, byte]): uint32 =
  ## Convert 256-bit target to compact representation (nBits)
  ## Finds the highest non-zero byte to determine exponent
  ## Returns compact target with proper mantissa and exponent

  # Find highest non-zero byte
  var size = 32
  while size > 0 and target[size - 1] == 0:
    dec size

  if size == 0:
    return 0

  var mantissa: uint32
  if size <= 3:
    mantissa = uint32(target[0])
    if size > 1:
      mantissa = mantissa or (uint32(target[1]) shl 8)
    if size > 2:
      mantissa = mantissa or (uint32(target[2]) shl 16)
    mantissa = mantissa shl (8 * (3 - size))
  else:
    mantissa = uint32(target[size - 3])
    mantissa = mantissa or (uint32(target[size - 2]) shl 8)
    mantissa = mantissa or (uint32(target[size - 1]) shl 16)

  # If MSB of mantissa is set, we need to increase exponent and shift
  # because MSB is treated as sign bit in CScriptNum
  if (mantissa and 0x00800000) != 0:
    mantissa = mantissa shr 8
    inc size

  result = (uint32(size) shl 24) or mantissa

proc hashMeetsTarget*(hash: BlockHash, bits: uint32): bool =
  ## Check if block hash meets the difficulty target
  ## Hash is treated as 256-bit LE unsigned integer
  ## Returns true if hash <= target
  let target = compactToTarget(bits)
  let hashBytes = array[32, byte](hash)

  # Compare as little-endian 256-bit integers (compare from MSB = highest index)
  for i in countdown(31, 0):
    if hashBytes[i] < target[i]:
      return true
    elif hashBytes[i] > target[i]:
      return false
  # Equal
  return true

proc calculateNextTarget*(prevTarget: uint32, actualTimespan: int64,
                          params: ConsensusParams): uint32 =
  ## Calculate next difficulty target based on actual time to mine previous period
  ## Clamps ratio to [targetTimespan/4, targetTimespan*4]
  ## newTarget = oldTarget * clampedTimespan / targetTimespan

  # Clamp the actual timespan
  var clampedTimespan = actualTimespan
  let minTimespan = int64(params.powTargetTimespan) div 4
  let maxTimespan = int64(params.powTargetTimespan) * 4

  if clampedTimespan < minTimespan:
    clampedTimespan = minTimespan
  elif clampedTimespan > maxTimespan:
    clampedTimespan = maxTimespan

  # Convert current target to 256-bit
  var target = compactToTarget(prevTarget)

  # Multiply target by clampedTimespan (shift and add for 256-bit)
  # Using simple multiplication with overflow handling
  var carry: uint64 = 0
  for i in 0..31:
    let product = uint64(target[i]) * uint64(clampedTimespan) + carry
    target[i] = byte(product and 0xff)
    carry = product shr 8

  # Divide by targetTimespan
  var remainder: uint64 = 0
  for i in countdown(31, 0):
    let dividend = (remainder shl 8) or uint64(target[i])
    target[i] = byte(dividend div uint64(params.powTargetTimespan))
    remainder = dividend mod uint64(params.powTargetTimespan)

  # Check against powLimit and clamp if needed
  for i in countdown(31, 0):
    if target[i] > params.powLimit[i]:
      # Target exceeds limit, use limit instead
      return targetToCompact(params.powLimit)
    elif target[i] < params.powLimit[i]:
      break

  targetToCompact(target)

# Genesis block construction
import ../crypto/hashing
import ../primitives/serialize

proc buildGenesisBlock*(params: ConsensusParams): Block =
  ## Build the genesis block for the given network
  ## Mainnet: version=1, timestamp=1231006505, bits=0x1d00ffff, nonce=2083236893
  ## Coinbase: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

  # Build coinbase scriptSig
  # All networks use the same coinbase script as mainnet:
  # 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73
  # This is: push 4 bytes (0xffff001d = 0x1d00ffff in LE), push 1 byte (0x04), push 69-byte message
  var coinbaseScript: seq[byte]

  # Push 4 bytes: 0x1d00ffff in little-endian = 0xff, 0xff, 0x00, 0x1d
  coinbaseScript = @[0x04'u8, 0xff, 0xff, 0x00, 0x1d]
  # Push 1 byte: 0x04 (extra nonce byte)
  coinbaseScript.add([0x01'u8, 0x04])
  # Push 69-byte message
  let message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  coinbaseScript.add(byte(message.len))
  for c in message:
    coinbaseScript.add(byte(c))

  # Build coinbase output script (pubkey to satoshi's pubkey, OP_CHECKSIG)
  # Mainnet genesis: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f OP_CHECKSIG
  let genesisOutputScript = @[
    0x41'u8,  # Push 65 bytes
    0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 0xb7,
    0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde,
    0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, 0x12,
    0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d,
    0x5f,
    0xac  # OP_CHECKSIG
  ]

  # Build coinbase transaction
  let coinbaseTx = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xffffffff'u32
      ),
      scriptSig: coinbaseScript,
      sequence: 0xffffffff'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(50 * 100_000_000),  # 50 BTC
      scriptPubKey: genesisOutputScript
    )],
    witnesses: @[],
    lockTime: 0
  )

  # Compute merkle root (single tx = tx hash)
  let txBytes = serialize(coinbaseTx)
  let txHash = doubleSha256(txBytes)

  # Build block header
  let header = BlockHeader(
    version: params.genesisVersion,
    prevBlock: params.genesisPrevHash,
    merkleRoot: txHash,
    timestamp: params.genesisTimestamp,
    bits: params.genesisBits,
    nonce: params.genesisNonce
  )

  result = Block(
    header: header,
    txs: @[coinbaseTx]
  )

proc verifyGenesisBlock*(blk: Block, params: ConsensusParams): bool =
  ## Verify that the given block matches the expected genesis block
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))
  hash == params.genesisBlockHash
