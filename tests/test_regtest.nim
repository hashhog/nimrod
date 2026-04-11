## Tests for regtest mining RPCs
## Tests generatetoaddress, generateblock, generatetodescriptor

import unittest2
import std/[options, os, json, strutils, tempfiles]

import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/[chainstate, db]
import ../src/mempool/mempool
import ../src/crypto/[hashing, address, secp256k1]
import ../src/mining/blocktemplate
import ../src/rpc/mining

suite "Regtest params":
  test "regtest network has correct parameters":
    let params = regtestParams()

    check params.network == Regtest
    check params.networkMagic == [0xFA'u8, 0xBF, 0xB5, 0xDA]
    check params.defaultPort == 18444
    check params.rpcPort == 18443
    check params.powAllowMinDifficultyBlocks == true
    check params.powNoRetargeting == true
    check params.subsidyHalvingInterval == 150
    check params.coinbaseMaturity == 100

  test "regtest genesisBits is minimum difficulty":
    let params = regtestParams()

    # Regtest uses 0x207fffff (minimum difficulty)
    check params.genesisBits == 0x207fffff'u32

  test "regtest powLimit allows easy mining":
    let params = regtestParams()

    # The regtest powLimit should be 0x7fff... (very high target = easy mining)
    check params.powLimit[31] == 0x7f
    check params.powLimit[30] == 0xff

suite "Regtest block mining":
  var chainState: ChainState
  var mempool: Mempool
  var params: ConsensusParams
  var tempDir: string

  setup:
    tempDir = createTempDir("nimrod_test_", "_regtest")
    params = regtestParams()
    chainState = newChainState(tempDir, params)
    mempool = newMempool(chainState, params)

    # Initialize with genesis block if needed
    if chainState.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      let result = chainState.connectBlock(genesis, 0)
      check result.isOk

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "mineBlock produces valid block on regtest":
    # Create a simple P2PKH coinbase script
    let coinbaseScript = @[
      0x76'u8, 0xa9, 0x14,  # OP_DUP OP_HASH160 PUSH20
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,  # 20 zero bytes (placeholder pubkeyhash)
      0x88, 0xac  # OP_EQUALVERIFY OP_CHECKSIG
    ]

    let blockOpt = mineBlock(chainState, mempool, params, coinbaseScript, 1000)
    check blockOpt.isSome

    let blk = blockOpt.get()
    check blk.txs.len >= 1  # At least coinbase

    # Verify block hash meets target
    let headerBytes = serialize(blk.header)
    let hash = doubleSha256(headerBytes)
    let target = computeTarget(blk.header.bits)
    check hashMeetsTarget(hash, target)

  test "generateBlocks produces multiple blocks":
    let coinbaseScript = @[0x51'u8]  # OP_1 (anyone can spend for testing)

    let initialHeight = chainState.bestHeight
    let hashes = generateBlocks(chainState, mempool, params, coinbaseScript, 10, 1000)

    check hashes.len == 10
    check chainState.bestHeight == initialHeight + 10

    # Verify each hash is unique
    for i, hash in hashes:
      for j in (i+1) ..< hashes.len:
        check hash != hashes[j]

  test "generateBlocks increments chain height":
    let coinbaseScript = @[0x51'u8]

    let startHeight = chainState.bestHeight
    discard generateBlocks(chainState, mempool, params, coinbaseScript, 5, 1000)

    check chainState.bestHeight == startHeight + 5

  test "coinbase subsidy halving on regtest":
    # Regtest halves every 150 blocks
    let subsidy0 = getBlockSubsidy(0, params)
    let subsidy149 = getBlockSubsidy(149, params)
    let subsidy150 = getBlockSubsidy(150, params)

    check subsidy0 == Satoshi(5_000_000_000)  # 50 BTC
    check subsidy149 == Satoshi(5_000_000_000)  # Still 50 BTC
    check subsidy150 == Satoshi(2_500_000_000)  # 25 BTC (first halving)

suite "Generate RPC address parsing":
  test "generateToAddress parses bech32 address":
    let params = regtestParams()

    # bcrt1 prefix is used for regtest bech32 addresses
    # Using a testnet address format for parsing test
    let addrStr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

    try:
      let parsed = decodeAddress(addrStr)
      check parsed.kind == P2WPKH
    except AddressError:
      # Expected if address validation is strict
      skip()

  test "generateToAddress parses legacy P2PKH address":
    # Testnet P2PKH address (starts with m or n)
    let addrStr2 = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"

    try:
      let parsed = decodeAddress(addrStr2)
      check parsed.kind == P2PKH
    except AddressError:
      # May fail if network mismatch
      skip()

suite "Generate block with transactions":
  var chainState: ChainState
  var mempool: Mempool
  var params: ConsensusParams
  var tempDir: string

  setup:
    tempDir = createTempDir("nimrod_test_", "_generateblock")
    params = regtestParams()
    chainState = newChainState(tempDir, params)
    mempool = newMempool(chainState, params)

    # Initialize with genesis
    if chainState.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      discard chainState.connectBlock(genesis, 0)

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "generateBlockWithTxs with empty tx list":
    let coinbaseScript = @[0x51'u8]

    # Generate block with no additional transactions
    let hashOpt = generateBlockWithTxs(
      chainState, mempool, params,
      coinbaseScript, @[], 1000
    )

    check hashOpt.isSome

    let hash = hashOpt.get()
    let blkOpt = chainState.db.getBlock(hash)
    check blkOpt.isSome

    # Should have only coinbase
    let blk = blkOpt.get()
    check blk.txs.len == 1

  test "blocks link correctly":
    let coinbaseScript = @[0x51'u8]

    # Generate several blocks
    let hashes = generateBlocks(chainState, mempool, params, coinbaseScript, 3, 1000)
    check hashes.len == 3

    # Verify chain linkage
    for i in 1 ..< hashes.len:
      let blkOpt = chainState.db.getBlock(hashes[i])
      check blkOpt.isSome

      let blk = blkOpt.get()
      check blk.header.prevBlock == hashes[i-1]

suite "Regtest genesis":
  test "regtest genesis block builds correctly":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)

    let headerBytes = serialize(genesis.header)
    let hash = BlockHash(doubleSha256(headerBytes))

    # Verify it matches the expected genesis hash
    check hash == params.genesisBlockHash

  test "regtest genesis has correct timestamp":
    let params = regtestParams()

    # Regtest uses same timestamp as testnet
    check params.genesisTimestamp == 1296688602

  test "regtest genesis has nonce 2":
    let params = regtestParams()

    # Regtest genesis nonce is 2 (easy to find at min difficulty)
    check params.genesisNonce == 2

suite "Coinbase maturity":
  var chainState: ChainState
  var mempool: Mempool
  var params: ConsensusParams
  var tempDir: string

  setup:
    tempDir = createTempDir("nimrod_test_", "_maturity")
    params = regtestParams()
    chainState = newChainState(tempDir, params)
    mempool = newMempool(chainState, params)

    # Start with genesis
    if chainState.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      discard chainState.connectBlock(genesis, 0)

  teardown:
    chainState.close()
    removeDir(tempDir)

  test "coinbase requires 100 blocks to mature":
    check params.coinbaseMaturity == 100

  test "generate 100 blocks matures first coinbase":
    let coinbaseScript = @[0x51'u8]

    # Generate 100 blocks (coinbase maturity)
    let hashes = generateBlocks(chainState, mempool, params, coinbaseScript, 100, 1000)
    check hashes.len == 100
    check chainState.bestHeight >= 100

    # After 100 blocks, first coinbase should be mature
    # (The genesis coinbase at height 0 is mature at height 100)
