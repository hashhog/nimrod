## Deep-reorg Core-parity regression — the 288-block reorg cap Class-A divergence.
##
## Bitcoin Core (validation.cpp ActivateBestChainStep) has NO reorg-depth
## cap: it walks back to the fork point unbounded and follows the most-work
## valid chain to ANY depth. MIN_BLOCKS_TO_KEEP (288) is a PRUNING floor,
## not a consensus reorg bound.
##
## nimrod historically enforced MAX_REORG_DEPTH=288 UNCONDITIONALLY in
## handleReorg, so an archive node (undo data always present) would
## gratuitously refuse a >288 reorg to a higher-work chain and strand
## itself on the lower-work minority chain — a consensus split.
##
## Fix: gate the cap on cs.pruningEnabled. Archive (default) reorgs to any
## depth (Core parity); a pruned node keeps the cap (it may lack undo data
## for a too-deep reorg -> controlled abort mirroring Core's FatalError).

import unittest2
import std/[os, options, tables]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_deep_reorg_archive_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc makeSpendableScript(): seq[byte] =
  @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))

proc makeSimpleBlock(prevHash: BlockHash, height: int32, chainId: int32 = 0): Block =
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let chainBytes = @[byte(chainId and 0xff), byte((chainId shr 8) and 0xff),
                     byte((chainId shr 16) and 0xff), byte((chainId shr 24) and 0xff)]
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04)] & chainBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      # Pay well under the smallest subsidy in the tested height range
      # (regtest halves every 150 blocks: 2.5 BTC at h150). Paying less
      # than the subsidy is always valid; this keeps the reorg's coinbase
      # amount check (bad-cb-amount) happy across all 290+ blocks.
      value: Satoshi(1000000),
      scriptPubKey: makeSpendableScript()
    )]
  )
  let txHashes = @[array[32, byte](coinbase.txid())]
  let header = BlockHeader(
    version: 1,
    prevBlock: prevHash,
    merkleRoot: merkleRoot(txHashes),
    timestamp: 1231006505 + uint32(height * 600) + uint32(chainId * 10),
    bits: 0x207fffff'u32,
    nonce: uint32(height) + uint32(chainId * 1000000)
  )
  Block(header: header, txs: @[coinbase])

# Depth of chain A that must be disconnected to reach the fork point.
# Must exceed MAX_REORG_DEPTH (288) to exercise the gate.
const DeepDepth = 290'i32

suite "Deep reorg — Core-parity unbounded archive reorg (288-cap gate)":

  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "archive node reorgs PAST the 288-block cap to the higher-work chain":
    var cs = newChainState(TestDbPath, regtestParams())
    check cs.pruningEnabled == false  # archive is the default

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Chain A: DeepDepth blocks off genesis (this is the active tip).
    var prev = genesisHash
    for h in 1'i32 .. DeepDepth:
      let blk = makeSimpleBlock(prev, h, chainId = 1)
      discard cs.connectBlock(blk, h)
      prev = getBlockHash(blk)
    check cs.bestHeight == DeepDepth

    # Chain B: DeepDepth+1 blocks off genesis (higher work -> Core reorgs).
    var chainB: seq[Block] = @[]
    prev = genesisHash
    for h in 1'i32 .. (DeepDepth + 1):
      let blk = makeSimpleBlock(prev, h, chainId = 2)
      chainB.add(blk)
      prev = getBlockHash(blk)

    # Disconnect depth == DeepDepth (290) > MAX_REORG_DEPTH (288).
    let res = cs.handleReorg(genesisHash, chainB)
    check res.isOk                              # reorg SUCCEEDS (Core parity)
    check cs.bestHeight == DeepDepth + 1
    check cs.bestBlockHash == getBlockHash(chainB[^1])  # tip == chain-B tip
    cs.close()

  test "pruned node still REFUSES a reorg deeper than the retained window":
    var cs = newChainState(TestDbPath, regtestParams())
    cs.pruningEnabled = true  # emulate --prune=N: keep the safety cap

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    var prev = genesisHash
    for h in 1'i32 .. DeepDepth:
      let blk = makeSimpleBlock(prev, h, chainId = 1)
      discard cs.connectBlock(blk, h)
      prev = getBlockHash(blk)

    var chainB: seq[Block] = @[]
    prev = genesisHash
    for h in 1'i32 .. (DeepDepth + 1):
      let blk = makeSimpleBlock(prev, h, chainId = 2)
      chainB.add(blk)
      prev = getBlockHash(blk)

    let res = cs.handleReorg(genesisHash, chainB)
    check (not res.isOk)                        # pruned: controlled refusal
    check cs.bestHeight == DeepDepth            # stayed on original chain
    cs.close()
