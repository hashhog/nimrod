## Bitcoin consensus parameters
## Network-specific constants for mainnet, testnet, regtest

import ../primitives/types

type
  Network* = enum
    Mainnet
    Testnet3
    Regtest

  ConsensusParams* = object
    network*: Network
    genesisHash*: BlockHash
    genesisPrevHash*: BlockHash
    genesisTimestamp*: uint32
    genesisBits*: uint32
    genesisNonce*: uint32
    genesisVersion*: int32
    subsidyHalvingInterval*: int
    maxBlockWeight*: int
    maxBlockSize*: int
    targetSpacing*: int  # seconds between blocks
    targetTimespan*: int  # seconds for difficulty adjustment
    powLimit*: array[32, byte]
    bip34Height*: int
    bip65Height*: int
    bip66Height*: int
    segwitHeight*: int
    minRelayTxFee*: Satoshi
    dustLimit*: Satoshi
    p2pPort*: uint16
    rpcPort*: uint16
    magic*: array[4, byte]

proc hexToBytes32(hex: string): array[32, byte] =
  assert hex.len == 64
  for i in 0..31:
    let h = hex[i*2 ..< i*2 + 2]
    result[31 - i] = byte(parseHexInt(h))

import std/strutils

proc mainnetParams*(): ConsensusParams =
  result.network = Mainnet
  result.genesisHash = BlockHash(hexToBytes32(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1231006505
  result.genesisBits = 0x1d00ffff'u32
  result.genesisNonce = 2083236893'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210000
  result.maxBlockWeight = 4000000
  result.maxBlockSize = 1000000
  result.targetSpacing = 600  # 10 minutes
  result.targetTimespan = 14 * 24 * 60 * 60  # 2 weeks
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.bip34Height = 227931
  result.bip65Height = 388381
  result.bip66Height = 363725
  result.segwitHeight = 481824
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  result.p2pPort = 8333
  result.rpcPort = 8332
  result.magic = [0xf9'u8, 0xbe, 0xb4, 0xd9]

proc testnet3Params*(): ConsensusParams =
  result.network = Testnet3
  result.genesisHash = BlockHash(hexToBytes32(
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1296688602
  result.genesisBits = 0x1d00ffff'u32
  result.genesisNonce = 414098458'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210000
  result.maxBlockWeight = 4000000
  result.maxBlockSize = 1000000
  result.targetSpacing = 600
  result.targetTimespan = 14 * 24 * 60 * 60
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.bip34Height = 21111
  result.bip65Height = 581885
  result.bip66Height = 330776
  result.segwitHeight = 834624
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  result.p2pPort = 18333
  result.rpcPort = 18332
  result.magic = [0x0b'u8, 0x11, 0x09, 0x07]

proc regtestParams*(): ConsensusParams =
  result.network = Regtest
  result.genesisHash = BlockHash(hexToBytes32(
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1296688602
  result.genesisBits = 0x207fffff'u32
  result.genesisNonce = 2'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 150
  result.maxBlockWeight = 4000000
  result.maxBlockSize = 1000000
  result.targetSpacing = 600
  result.targetTimespan = 14 * 24 * 60 * 60
  result.powLimit = hexToBytes32(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.bip34Height = 500
  result.bip65Height = 1351
  result.bip66Height = 1251
  result.segwitHeight = 0
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  result.p2pPort = 18444
  result.rpcPort = 18443
  result.magic = [0xfa'u8, 0xbf, 0xb5, 0xda]

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
