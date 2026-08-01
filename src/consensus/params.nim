## Bitcoin consensus parameters
## Network-specific constants for mainnet, testnet, regtest

import ../primitives/types
import std/[strutils, os, json]

type
  Network* = enum
    Mainnet
    Testnet3
    Testnet4
    Regtest
    Signet

  HeadersSyncParams* = object
    ## Configuration for headers sync memory usage (anti-DoS)
    ## Used to bound memory during PRESYNC/REDOWNLOAD header sync
    commitmentPeriod*: int      ## Distance in blocks between commitments
    redownloadBufferSize*: int  ## Min headers to accumulate before feeding to chain

  ## Checkpoint entry: height -> expected block hash
  Checkpoint* = tuple[height: uint32, hash: BlockHash]

  ## assumeUTXO data: hardcoded snapshot parameters for fast sync
  ## Reference: Bitcoin Core chainparams.cpp, validation.cpp
  AssumeutxoData* = object
    height*: int32                    ## Block height of snapshot
    hashSerialized*: array[32, byte]  ## SHA256d hash of serialized UTXO set
    chainTxCount*: uint64             ## Cumulative transaction count
    blockhash*: BlockHash             ## Block hash at snapshot height

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
    bip34Hash*: array[32, byte]   ## Block hash at BIP34 activation height; all-zeros if not set.
                                   ## Bitcoin Core consensus/params.h BIP34Hash.
                                   ## Used to verify we are on the canonical chain before
                                   ## allowing BIP34 to suppress BIP30 UTXO duplicate checks.
    bip65Height*: int
    bip66Height*: int
    csvHeight*: int      # BIP68/112/113 (CSV) activation height
    segwitHeight*: int
    taprootHeight*: int
    powLimit*: array[32, byte]
    powTargetTimespan*: int
    powTargetSpacing*: int
    difficultyAdjustmentInterval*: int
    # PoW adjustment rules
    powAllowMinDifficultyBlocks*: bool  # Allow min-difficulty blocks (testnet/regtest)
    powNoRetargeting*: bool             # Never retarget (regtest)
    enforceBIP94*: bool                 # Testnet4 time-warp fix
    minRelayTxFee*: Satoshi
    dustLimit*: Satoshi
    # Header sync anti-DoS params
    headersSyncParams*: HeadersSyncParams
    # Checkpoint verification (anti-DoS and fork protection)
    minimumChainWork*: array[32, byte]  # Minimum cumulative PoW required
    assumeValidBlockHash*: BlockHash    # Skip script verification before this block
    assumeValidHeight*: int32           # Height of the assume-valid block
    checkpoints*: seq[Checkpoint]       # Known block hashes at specific heights
    # assumeUTXO snapshot data
    assumeutxoData*: seq[AssumeutxoData]  # Valid snapshot parameters
    # Legacy aliases
    p2pPort*: uint16
    rpcPort*: uint16

# Alias for networkMagic for convenience
template magic*(p: ConsensusParams): array[4, byte] = p.networkMagic

# Global consensus constants
const
  MaxMoney* = Satoshi(21_000_000 * 100_000_000'i64)
  SubsidyHalving* = 210_000
  MaxBlockWeight* = 4_000_000
  MaxBlockSize* = 1_000_000
  MaxBlockSigopsCost* = 80_000
  ## Policy limit per-tx: MAX_BLOCK_SIGOPS_COST / 5 (policy/policy.h:44 in Core)
  MaxStandardTxSigopsCost* = MaxBlockSigopsCost div 5  # = 16_000
  WitnessScaleFactor* = 4
  MedianTimeSpan* = 11
  MaxFutureBlockTime* = 7200  # 2 hours in seconds
  TargetTimespan* = 1_209_600  # 14 days in seconds
  TargetSpacing* = 600         # 10 minutes in seconds
  DifficultyAdjustmentInterval* = 2016
  MaxCompactTarget* = 0x1d00ffff'u32

  ## Minimum transaction weight (consensus/consensus.h:23).
  ## 60 is the lower bound for the size of a valid serialized CTransaction;
  ## multiplied by WitnessScaleFactor. Used for per-tx sanity checks and
  ## in merkleblock to bound the maximum number of transactions per block.
  MinTransactionWeight* = WitnessScaleFactor * 60  # = 240

  ## Minimum serializable transaction weight (consensus/consensus.h:24).
  ## 10 is the lower bound for the serialized CTransaction size (version +
  ## 0-input varint + 0-output varint + locktime = 10 bytes); multiplied by
  ## WitnessScaleFactor.  Used in compact block relay to bound the sanity
  ## check on the number of short-IDs (blockencodings.cpp:64).
  MinSerializableTransactionWeight* = WitnessScaleFactor * 10  # = 40

  ## Default sigops-to-bytes ratio used in fee-rate calculations
  ## (policy/policy.h:50). GetVirtualTransactionSize uses this to convert
  ## sigop cost to virtual bytes: vsize = ceil(max(weight, sigops*20) / 4).
  DefaultBytesPerSigop* = 20

  ## Minimum blocks to keep on disk for block-relay pruning and the
  ## fTooFarAhead guard in AcceptBlock.
  ## Reference: bitcoin-core/src/validation.h:79 — MIN_BLOCKS_TO_KEEP.
  ## A block whose height exceeds ActiveChainHeight + MIN_BLOCKS_TO_KEEP is
  ## silently deferred (not validated) to prevent CPU-DoS from hostile peers
  ## sending deep-future blocks during IBD.
  MinBlocksToKeep* = 288

  # BIP68 sequence lock constants
  # Note: These are also defined in script/interpreter.nim for OP_CHECKSEQUENCEVERIFY
  # Using SequenceLock prefix to avoid name collision
  SequenceLockDisableFlag* = 1'u32 shl 31   # Bit 31: disable relative timelock
  SequenceLockTypeFlag* = 1'u32 shl 22      # Bit 22: 0=height-based, 1=time-based
  SequenceLockMask* = 0x0000ffff'u32        # Lower 16 bits: lock value
  SequenceLockGranularity* = 9              # Time-based locks are in 512-second increments (2^9)

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
  # Bitcoin Core kernel/chainparams.cpp:90: consensus.BIP34Hash
  # Block hash at height 227931 — used to verify canonical chain before
  # suppressing BIP30 checks (validation.cpp:2462).
  result.bip34Hash = hexToBytes32(
    "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
  )
  result.bip65Height = 388381
  result.bip66Height = 363725
  result.csvHeight = 419328    # BIP68/112/113 activation
  result.segwitHeight = 481824
  result.taprootHeight = 709632
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600  # 14 days
  result.powTargetSpacing = 600  # 10 minutes
  result.difficultyAdjustmentInterval = 2016
  # Skip script verification below this height during IBD.
  # MUST equal the height of assumeValidBlockHash below (938343). The faithful
  # gate (assumevalid.nim shouldSkipScripts, condition 3) compares the
  # active-chain hash AT assumeValidHeight against assumeValidBlockHash, so a
  # mismatched pair (previously 944000 vs a hash at 938343) can NEVER satisfy
  # condition 3 — the skip would never fire and every historical block would be
  # fully re-verified (fail-safe, but a silent perf/faithfulness bug). Keep the
  # two consistent, matching Bitcoin Core's m_assumed_valid_hash convention
  # (the hash IS the block at this height).
  result.assumeValidHeight = 938_343
  # PoW rules: mainnet does normal retargeting
  result.powAllowMinDifficultyBlocks = false
  result.powNoRetargeting = false
  result.enforceBIP94 = false
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Header sync anti-DoS params (from Bitcoin Core headerssync-params.py)
  result.headersSyncParams = HeadersSyncParams(
    commitmentPeriod: 641,
    redownloadBufferSize: 15218  # ~23.7 commitments
  )
  # Checkpoint verification (from Bitcoin Core chainparams.cpp)
  # nMinimumChainWork: minimum cumulative PoW to accept as valid chain
  result.minimumChainWork = hexToBytes32(
    "0000000000000000000000000000000000000001128750f82f4c366153a3a030"
  )
  # defaultAssumeValid: block hash up to which scripts are assumed valid
  result.assumeValidBlockHash = BlockHash(hexToBytes32(
    "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"  # 938343
  ))
  # Well-known mainnet checkpoints (height -> hash)
  # These prevent long-range attacks by rejecting forks below these heights
  result.checkpoints = @[
    (11111'u32, BlockHash(hexToBytes32("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"))),
    (33333'u32, BlockHash(hexToBytes32("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"))),
    (74000'u32, BlockHash(hexToBytes32("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"))),
    (105000'u32, BlockHash(hexToBytes32("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"))),
    (134444'u32, BlockHash(hexToBytes32("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"))),
    (168000'u32, BlockHash(hexToBytes32("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"))),
    (193000'u32, BlockHash(hexToBytes32("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"))),
    (210000'u32, BlockHash(hexToBytes32("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"))),
    (216116'u32, BlockHash(hexToBytes32("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"))),
    (225430'u32, BlockHash(hexToBytes32("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"))),
    (250000'u32, BlockHash(hexToBytes32("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"))),
    (279000'u32, BlockHash(hexToBytes32("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"))),
    (295000'u32, BlockHash(hexToBytes32("00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")))
  ]
  # assumeUTXO snapshot data — first four entries verbatim from Bitcoin Core
  # bitcoin-core/src/kernel/chainparams.cpp::CMainParams::m_assumeutxo_data
  # (commit pinned by the bitcoin-core/ submodule). The 944183 and 481823
  # entries are nimrod's own snapshot-campaign additions (not in Core).
  result.assumeutxoData = @[
    AssumeutxoData(
      height: 840000'i32,
      hashSerialized: hexToBytes32(
        "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
      ),
      chainTxCount: 991032194'u64,
      blockhash: BlockHash(hexToBytes32(
        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
      ))
    ),
    AssumeutxoData(
      height: 880000'i32,
      hashSerialized: hexToBytes32(
        "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
      ),
      chainTxCount: 1145604538'u64,
      blockhash: BlockHash(hexToBytes32(
        "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
      ))
    ),
    AssumeutxoData(
      height: 910000'i32,
      hashSerialized: hexToBytes32(
        "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
      ),
      chainTxCount: 1226586151'u64,
      blockhash: BlockHash(hexToBytes32(
        "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
      ))
    ),
    AssumeutxoData(
      height: 935000'i32,
      hashSerialized: hexToBytes32(
        "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
      ),
      chainTxCount: 1305397408'u64,
      blockhash: BlockHash(hexToBytes32(
        "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
      ))
    ),
    AssumeutxoData(
      height: 944183'i32,
      hashSerialized: hexToBytes32(
        "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
      ),
      chainTxCount: 1334000000'u64,
      blockhash: BlockHash(hexToBytes32(
        "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
      ))
    ),
    AssumeutxoData(
      # Track-B WINDOWED replay: last pre-segwit block (segwit activates 481824).
      # hashSerialized + chainTxCount from the boundary-snapshot result JSON
      # (Core dumptxoutset rollback=481823). blockhash = the 481823 header hash.
      height: 481823'i32,
      hashSerialized: hexToBytes32(
        "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4"
      ),
      chainTxCount: 249036369'u64,
      blockhash: BlockHash(hexToBytes32(
        "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80"
      ))
    )
  ]
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
  # Bitcoin Core kernel/chainparams.cpp:213: consensus.BIP34Hash (testnet3)
  result.bip34Hash = hexToBytes32(
    "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
  )
  result.bip65Height = 581885
  result.bip66Height = 330776
  result.csvHeight = 770112    # BIP68/112/113 activation on testnet3
  result.segwitHeight = 834624
  result.taprootHeight = 0  # Active from genesis on testnet3
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  # PoW rules: testnet3 allows min-difficulty blocks
  result.powAllowMinDifficultyBlocks = true
  result.powNoRetargeting = false
  result.enforceBIP94 = false
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Header sync anti-DoS params (from Bitcoin Core headerssync-params.py)
  result.headersSyncParams = HeadersSyncParams(
    commitmentPeriod: 673,
    redownloadBufferSize: 14460  # ~21.5 commitments
  )
  # Checkpoint verification (from Bitcoin Core chainparams.cpp)
  result.minimumChainWork = hexToBytes32(
    "0000000000000000000000000000000000000000000017dde1c649f3708d14b6"
  )
  result.assumeValidBlockHash = BlockHash(hexToBytes32(
    "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"  # 4842348
  ))
  result.assumeValidHeight = 4842348
  # Testnet3 checkpoints
  result.checkpoints = @[
    (546'u32, BlockHash(hexToBytes32("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")))
  ]
  # No assumeUTXO snapshots defined for testnet3
  result.assumeutxoData = @[]
  # Legacy aliases
  result.p2pPort = 18333
  result.rpcPort = 18332

proc testnet4Params*(): ConsensusParams =
  ## Testnet4 parameters (BIP94)
  result.network = Testnet4
  result.networkMagic = [0x1c'u8, 0x16, 0x3f, 0x28]  # 0x1c163f28
  result.defaultPort = 48333
  result.dnsSeeds = @[
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz"
  ]
  result.genesisBlockHash = BlockHash(hexToBytes32(
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1714777860
  result.genesisBits = 0x1d00ffff'u32
  result.genesisNonce = 393743547'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210_000
  result.maxBlockWeight = 4_000_000
  result.maxBlockSize = 1_000_000
  result.maxBlockSigopsCost = 80_000
  result.coinbaseMaturity = 100
  # All soft forks active from genesis on testnet4
  result.bip34Height = 1
  result.bip65Height = 1
  result.bip66Height = 1
  result.csvHeight = 1
  result.segwitHeight = 1
  result.taprootHeight = 1
  result.powLimit = hexToBytes32(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  # PoW rules: testnet4 allows min-difficulty + BIP94 time-warp fix
  result.powAllowMinDifficultyBlocks = true
  result.powNoRetargeting = false
  result.enforceBIP94 = true
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Header sync anti-DoS params (from Bitcoin Core headerssync-params.py)
  result.headersSyncParams = HeadersSyncParams(
    commitmentPeriod: 606,
    redownloadBufferSize: 16092  # ~26.6 commitments
  )
  # Checkpoint verification (from Bitcoin Core chainparams.cpp)
  result.minimumChainWork = hexToBytes32(
    "0000000000000000000000000000000000000000000009a0fe15d0177d086304"
  )
  result.assumeValidBlockHash = BlockHash(hexToBytes32(
    "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"  # 123613
  ))
  result.assumeValidHeight = 123613
  # Testnet4 has no historical checkpoints (fresh network)
  result.checkpoints = @[]
  # No assumeUTXO snapshots defined for testnet4 yet
  result.assumeutxoData = @[]
  # Legacy aliases
  result.p2pPort = 48333
  result.rpcPort = 48332

proc signetParams*(): ConsensusParams =
  ## Signet parameters (BIP325)
  result.network = Signet
  result.networkMagic = [0x0a'u8, 0x03, 0xcf, 0x40]  # 0x0a03cf40
  result.defaultPort = 38333
  result.dnsSeeds = @[
    "seed.signet.bitcoin.sprovoost.nl"
  ]
  result.genesisBlockHash = BlockHash(hexToBytes32(
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
  ))
  result.genesisPrevHash = BlockHash(default(array[32, byte]))
  result.genesisTimestamp = 1598918400
  result.genesisBits = 0x1e0377ae'u32
  result.genesisNonce = 52613770'u32
  result.genesisVersion = 1
  result.subsidyHalvingInterval = 210_000
  result.maxBlockWeight = 4_000_000
  result.maxBlockSize = 1_000_000
  result.maxBlockSigopsCost = 80_000
  result.coinbaseMaturity = 100
  # All soft forks active from genesis on signet
  result.bip34Height = 1
  result.bip65Height = 1
  result.bip66Height = 1
  result.csvHeight = 1
  result.segwitHeight = 1
  result.taprootHeight = 1
  result.powLimit = hexToBytes32(
    "00000377ae000000000000000000000000000000000000000000000000000000"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  # PoW rules: signet does NOT allow min-difficulty blocks (PoW is controlled)
  result.powAllowMinDifficultyBlocks = false
  result.powNoRetargeting = false
  result.enforceBIP94 = false
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Header sync anti-DoS params (from Bitcoin Core headerssync-params.py)
  result.headersSyncParams = HeadersSyncParams(
    commitmentPeriod: 620,
    redownloadBufferSize: 15724  # ~25.4 commitments
  )
  # Checkpoint verification (from Bitcoin Core chainparams.cpp)
  result.minimumChainWork = hexToBytes32(
    "00000000000000000000000000000000000000000000000000000b463ea0a4b8"
  )
  result.assumeValidBlockHash = BlockHash(hexToBytes32(
    "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"  # 293175
  ))
  # Signet has no historical checkpoints
  result.checkpoints = @[]
  # No assumeUTXO snapshots defined for signet
  result.assumeutxoData = @[]
  # Legacy aliases
  result.p2pPort = 38333
  result.rpcPort = 38332

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
  result.bip34Height = 1  # Bitcoin Core kernel/chainparams.cpp:536: consensus.BIP34Height = 1
  result.bip65Height = 1    # Bitcoin Core kernel/chainparams.cpp:538: consensus.BIP65Height = 1
  result.bip66Height = 1    # Bitcoin Core kernel/chainparams.cpp:539: consensus.BIP66Height = 1
  result.csvHeight = 1      # Bitcoin Core kernel/chainparams.cpp:540: consensus.CSVHeight = 1
  result.segwitHeight = 0    # Active from genesis
  result.taprootHeight = 0   # Active from genesis
  result.powLimit = hexToBytes32(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  result.powTargetTimespan = 1_209_600
  result.powTargetSpacing = 600
  result.difficultyAdjustmentInterval = 2016
  # PoW rules: regtest never retargets, always allows min-difficulty
  result.powAllowMinDifficultyBlocks = true
  result.powNoRetargeting = true
  result.enforceBIP94 = false
  result.minRelayTxFee = Satoshi(1000)
  result.dustLimit = Satoshi(546)
  # Header sync anti-DoS params (smaller for regtest)
  result.headersSyncParams = HeadersSyncParams(
    commitmentPeriod: 275,
    redownloadBufferSize: 7017  # ~25.5 commitments
  )
  # Checkpoint verification: regtest has no checkpoints (private testing network)
  result.minimumChainWork = default(array[32, byte])  # No minimum work requirement
  result.assumeValidBlockHash = BlockHash(default(array[32, byte]))  # No assume-valid
  result.checkpoints = @[]  # No checkpoints for regtest
  # assumeUTXO snapshot data — Core-parity regtest entries, verbatim from
  # bitcoin-core/src/kernel/chainparams.cpp::CRegTestParams::m_assumeutxo_data.
  # REGTEST ONLY — never widen mainnet/testnet4 tables with these. Unblocks
  # tools/boot-smoke.sh (the height-299 fixture matches feature_assumeutxo.py's
  # entry) and any unit/fuzz tooling built against the 110/200 entries.
  result.assumeutxoData = @[
    AssumeutxoData(
      # For use by unit tests
      height: 110'i32,
      hashSerialized: hexToBytes32(
        "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"
      ),
      chainTxCount: 111'u64,
      blockhash: BlockHash(hexToBytes32(
        "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"
      ))
    ),
    AssumeutxoData(
      # For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
      height: 200'i32,
      hashSerialized: hexToBytes32(
        "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
      ),
      chainTxCount: 201'u64,
      blockhash: BlockHash(hexToBytes32(
        "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
      ))
    ),
    AssumeutxoData(
      # For use by test/functional/feature_assumeutxo.py and
      # test/functional/tool_bitcoin_chainstate.py
      height: 299'i32,
      hashSerialized: hexToBytes32(
        "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"
      ),
      chainTxCount: 334'u64,
      blockhash: BlockHash(hexToBytes32(
        "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"
      ))
    )
  ]
  # Legacy aliases
  result.p2pPort = 18444
  result.rpcPort = 18443

proc getParams*(network: Network): ConsensusParams =
  case network
  of Mainnet: mainnetParams()
  of Testnet3: testnet3Params()
  of Testnet4: testnet4Params()
  of Regtest: regtestParams()
  of Signet: signetParams()

const CampaignAssumeutxoEnvVar = "HASHHOG_CAMPAIGN_ASSUMEUTXO"

proc campaignAssumeutxoFatal(path, msg: string) {.noreturn.} =
  ## A malformed/colliding campaign file is a startup-fatal condition
  ## (campaign data may never silently be dropped or override a production
  ## entry). Mirrors the existing `echo ...; quit(1)` config-error pattern
  ## used elsewhere in nimrod's startup path (see getConsensusParams).
  echo "[CAMPAIGN-ASSUMEUTXO] " & path & ": " & msg
  quit(1)

proc loadCampaignAssumeutxo*(params: var ConsensusParams) =
  ## `HASHHOG_CAMPAIGN_ASSUMEUTXO=<abs-path.json>` — read ONCE at startup,
  ## after network-params selection. When set, parses the file and appends
  ## its entries to the *running network's* assumeutxo allowlist
  ## (`params.assumeutxoData`), which every lookup site in nimrod reads from
  ## (RPC loadtxoutset/dumptxoutset, the `--load-snapshot` CLI path, and the
  ## prune floor) — so merging here is a single chokepoint covering all of
  ## them. Unset/empty => bit-identical to today: the only code executed is
  ## a single `getEnv` call returning "".
  ##
  ## Fixture format (tools/campaign-assumeutxo/*.json), hex in Core DISPLAY
  ## order exactly like the hardcoded tables above — converted with the same
  ## `hexToBytes32` used for every other entry in this file:
  ##   [ { "height": N, "blockhash": "...", "hash_serialized": "...",
  ##       "m_chain_tx_count": N, ...optional extra keys ignored } ]
  ##
  ## On collision with a built-in (or already-loaded) entry, by height OR
  ## blockhash: refuses to start. Campaign data may never override a
  ## production hash. See receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md.
  let path = getEnv(CampaignAssumeutxoEnvVar, "")
  if path.len == 0:
    return

  let raw =
    try:
      readFile(path)
    except IOError as e:
      campaignAssumeutxoFatal(path, "failed to read: " & e.msg)
  let root =
    try:
      parseJson(raw)
    except CatchableError as e:
      campaignAssumeutxoFatal(path, "failed to parse JSON: " & e.msg)

  if root.kind != JArray:
    campaignAssumeutxoFatal(path, "expected a top-level JSON array")

  var loaded: seq[AssumeutxoData] = @[]
  var heights: seq[string] = @[]

  for entry in root.elems:
    if entry.kind != JObject:
      campaignAssumeutxoFatal(path, "each entry must be a JSON object")

    for key in ["height", "blockhash", "hash_serialized", "m_chain_tx_count"]:
      if not entry.hasKey(key):
        campaignAssumeutxoFatal(path, "entry missing required key \"" & key & "\"")

    let heightNode = entry["height"]
    if heightNode.kind != JInt or heightNode.getBiggestInt() <= 0:
      campaignAssumeutxoFatal(path, "\"height\" must be a positive integer")
    let height = int32(heightNode.getBiggestInt())

    let blockhashHex = entry["blockhash"].getStr("")
    if blockhashHex.len != 64 or not blockhashHex.allCharsInSet(HexDigits):
      campaignAssumeutxoFatal(path,
        "\"blockhash\" at height " & $height & " must be 64 hex characters")

    let hashSerializedHex = entry["hash_serialized"].getStr("")
    if hashSerializedHex.len != 64 or not hashSerializedHex.allCharsInSet(HexDigits):
      campaignAssumeutxoFatal(path,
        "\"hash_serialized\" at height " & $height & " must be 64 hex characters")

    let chainTxCountNode = entry["m_chain_tx_count"]
    if chainTxCountNode.kind != JInt or chainTxCountNode.getBiggestInt() < 0:
      campaignAssumeutxoFatal(path,
        "\"m_chain_tx_count\" at height " & $height & " must be a non-negative integer")
    let chainTxCount = uint64(chainTxCountNode.getBiggestInt())

    let data = AssumeutxoData(
      height: height,
      hashSerialized: hexToBytes32(hashSerializedHex),
      chainTxCount: chainTxCount,
      blockhash: BlockHash(hexToBytes32(blockhashHex))
    )

    # Collision refusal: never let campaign data override/duplicate a
    # built-in entry, or a different entry already merged from this same
    # campaign file, by height OR blockhash.
    for existing in params.assumeutxoData:
      if existing.height == data.height or existing.blockhash == data.blockhash:
        campaignAssumeutxoFatal(path,
          "entry at height " & $height &
          " collides with a built-in assumeutxo entry — refusing to start")
    for existing in loaded:
      if existing.height == data.height or existing.blockhash == data.blockhash:
        campaignAssumeutxoFatal(path,
          "duplicate entry at height " & $height & " within campaign file")

    loaded.add(data)
    heights.add($height)

  params.assumeutxoData.add(loaded)

  # Loud, greppable startup banner (tools/fleet-monitor.sh alerts if this
  # ever appears in a production log — the flag must only be used for the
  # M2 boundary campaign, never on a launcher-started production node).
  echo "[CAMPAIGN-ASSUMEUTXO] loaded " & $loaded.len & " entries from " &
    path & " heights=[" & heights.join(", ") & "]"

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
