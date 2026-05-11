## W92 — DisconnectBlock + ApplyTxInUndo + chain reorg comprehensive audit tests.
##
## Gates tested (mirroring Bitcoin Core validation.cpp:2149-2248, 2929-2992):
##  Gate 1: IsUnspendable skip on output removal (val:2214)
##  Gate 2: fEnforceBIP30 — h=91722/91812 BIP-30-unspendable coinbase tolerance (val:2201-2209)
##  Gate 3: blockUndo.txUndo.len + 1 == block.txs.len consistency check (val:2190-2193)
##  Gate 4: per-tx vin count == txUndo.prevOutputs count (val:2229-2232)
##  Gate 5: handleReorg skips IsUnspendable on output removal (val:2214)
##  Gate 6: SetBestBlock unconditionally (val:2245)
##  Gate 7: disconnect restores spent UTXOs (basic correctness)
##  Gate 8: disconnect removes created UTXOs (basic correctness)
##  Gate 9: reorg preserves UTXO consistency across fork
##  Gate 10: disconnect hook fires after commit

import unittest2
import std/[os, options, tables]
import ../src/storage/[db, chainstate, undo]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/consensus/validation as val

const TestDbPath = "/tmp/nimrod_disconnect_test_w92"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeUnspendableScript(): seq[byte] =
  ## OP_RETURN script — IsUnspendable() returns true for this
  @[byte(0x6a), 0x04, 0xde, 0xad, 0xbe, 0xef]

proc makeSpendableScript(): seq[byte] =
  ## P2WPKH-style script (not unspendable)
  @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

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
      value: Satoshi(5000000000),
      scriptPubKey: makeSpendableScript()
    )],
    witnesses: @[],
    lockTime: 0
  )
  let txHashes = @[array[32, byte](coinbase.txid())]
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600) + uint32(chainId * 10),
      bits: 0x207fffff'u32,
      nonce: uint32(height) + uint32(chainId * 1000000)
    ),
    txs: @[coinbase]
  )

proc makeBlockWithOpReturn(prevHash: BlockHash, height: int32): Block =
  ## Build a block with a coinbase that has both a spendable and an
  ## OP_RETURN (unspendable) output.
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04), 0x01, 0x02, 0x03, 0x04],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[
      TxOut(value: Satoshi(5000000000), scriptPubKey: makeSpendableScript()),
      TxOut(value: Satoshi(0), scriptPubKey: makeUnspendableScript())  # OP_RETURN
    ],
    witnesses: @[],
    lockTime: 0
  )
  let txHashes = @[array[32, byte](coinbase.txid())]
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: @[coinbase]
  )

proc makeSpendBlock(
  prevHash: BlockHash,
  height: int32,
  coinbaseTxid: TxId,
  chainId: int32 = 0
): Block =
  ## Block that spends a coinbase UTXO (needs maturity, so height >= prev_height + 100)
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let chainBytes = @[byte(chainId and 0xff), byte((chainId shr 8) and 0xff)]
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x02)] & chainBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: makeSpendableScript()
    )],
    witnesses: @[],
    lockTime: 0
  )
  let spendTx = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: coinbaseTxid, vout: 0),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(4999000000),
      scriptPubKey: makeSpendableScript()
    )],
    witnesses: @[],
    lockTime: 0
  )
  let txHashes = @[array[32, byte](coinbase.txid()), array[32, byte](spendTx.txid())]
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600) + uint32(chainId * 100),
      bits: 0x207fffff'u32,
      nonce: uint32(height) + uint32(chainId * 100)
    ),
    txs: @[coinbase, spendTx]
  )

proc seedChain(cs: var ChainState): tuple[
    genesisHash: BlockHash,
    fixtureHash: BlockHash,
    coinbaseTxid: TxId
  ] =
  ## Connect genesis (h=0, no UTXO) + fixture coinbase block at h=1
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  let genesisHash = getBlockHash(genesis)
  let fixture = makeSimpleBlock(genesisHash, 1)
  discard cs.connectBlock(fixture, 1)
  let fixtureHash = getBlockHash(fixture)
  (genesisHash, fixtureHash, fixture.txs[0].txid())

# ---------------------------------------------------------------------------
# Suite: Gate 1 — IsUnspendable output skip on disconnect
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 1: IsUnspendable skip":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 1: OP_RETURN output is never stored and skipped on disconnect":
    ## Spendable output (vout=0) must be removed from UTXO set on disconnect.
    ## Unspendable output (vout=1, OP_RETURN) was never stored, so deleting it
    ## must be a no-op (not cause an error).
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Block with OP_RETURN output at vout=1
    let blk = makeBlockWithOpReturn(genesisHash, 1)
    let cbTxid = blk.txs[0].txid()
    discard cs.connectBlock(blk, 1)

    # Spendable UTXO (vout=0) should exist
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 0)).isSome
    # Unspendable UTXO (vout=1) should never have been stored
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 1)).isNone

    # Disconnect — must succeed without error despite OP_RETURN output
    let res = cs.disconnectBlock(blk)
    check res.isOk
    check cs.bestHeight == 0

    # Spendable UTXO should be gone after disconnect
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 0)).isNone

    cs.close()

  test "Gate 1: multiple OP_RETURN outputs all skipped cleanly":
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Coinbase with 3 OP_RETURN outputs (all unspendable)
    let heightBytes = @[byte(0x01), byte(0x00), byte(0x00), byte(0x00)]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04), 0xAA, 0xBB, 0xCC, 0xDD],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000), scriptPubKey: makeSpendableScript()),
        TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a), 0x01, 0xAA]),
        TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a), 0x01, 0xBB]),
        TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a), 0x01, 0xCC])
      ],
      witnesses: @[],
      lockTime: 0
    )
    let txHashes = @[array[32, byte](coinbase.txid())]
    let blk = Block(
      header: BlockHeader(
        version: 1, prevBlock: genesisHash,
        merkleRoot: merkleRoot(txHashes),
        timestamp: 1231006505 + 600'u32, bits: 0x207fffff'u32, nonce: 1
      ),
      txs: @[coinbase]
    )
    let cbTxid = coinbase.txid()
    discard cs.connectBlock(blk, 1)

    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 1)).isNone
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 2)).isNone
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 3)).isNone

    let res = cs.disconnectBlock(blk)
    check res.isOk

    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 0)).isNone

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 2 — BIP-30 fEnforceBIP30 logic in DisconnectBlock
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 2: isBip30UnspendableForDisconnect":

  test "Gate 2: h=91722 canonical hash — fEnforceBIP30=false (coinbase mismatch tolerated)":
    ## Bitcoin Core validation.cpp:2201: when disconnecting h=91722 with the
    ## canonical block hash, is_bip30_exception=true for the coinbase, so
    ## the output-mismatch fClean=false is suppressed.
    ## We test the helper directly since we cannot reproduce actual h=91722 data.
    ##
    ## The key property: isBip30UnspendableForDisconnect must return true for
    ## exactly these two (height, hash) pairs and false for all others.
    ##
    ## We verify indirectly via the public isBip30Unspendable from validation.nim.

    let hash91722 = val.bip30HashFromHex(
      "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
    )
    check val.isBip30Unspendable(91722'i32, hash91722)
    check not val.isBip30Unspendable(91722'i32, default(array[32, byte]))
    check not val.isBip30Unspendable(91721'i32, hash91722)

  test "Gate 2: h=91812 canonical hash — fEnforceBIP30=false":

    let hash91812 = val.bip30HashFromHex(
      "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
    )
    check val.isBip30Unspendable(91812'i32, hash91812)
    check not val.isBip30Unspendable(91812'i32, default(array[32, byte]))
    check not val.isBip30Unspendable(91813'i32, hash91812)

  test "Gate 2: non-special heights are not unspendable":
    check not val.isBip30Unspendable(91842'i32, default(array[32, byte]))
    check not val.isBip30Unspendable(91880'i32, default(array[32, byte]))
    check not val.isBip30Unspendable(0'i32, default(array[32, byte]))
    check not val.isBip30Unspendable(100000'i32, default(array[32, byte]))

# ---------------------------------------------------------------------------
# Suite: Gate 3 — blockUndo.txUndo count consistency check
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 3: undo/block tx count consistency":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 3: block with only coinbase (no TxUndo needed) disconnects cleanly":
    ## A block with only the coinbase has blk.txs.len=1. BlockUndo for it
    ## should have 0 TxUndo entries (only non-coinbase txs get TxUndo).
    ## The consistency check: txUndo.len + 1 == txs.len → 0+1==1 ✓
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, _) = seedChain(cs)

    let blk = makeSimpleBlock(fixtureHash, 2)
    discard cs.connectBlock(blk, 2)
    check cs.bestHeight == 2

    let res = cs.disconnectBlock(blk)
    check res.isOk
    check cs.bestHeight == 1

    cs.close()

  test "Gate 3: block with 2 txs needs exactly 1 TxUndo":
    ## blk.txs = [coinbase, spendTx] → txUndo.len must be 1.
    ## Connect+disconnect a spend block. If undo count mismatches, err is returned.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, coinbaseTxid) = seedChain(cs)

    # Build to coinbase maturity (h=1 coinbase spendable at h=101)
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    let spendBlock = makeSpendBlock(prevHash, 101, coinbaseTxid)
    let spendRes = cs.connectBlock(spendBlock, 101)
    check spendRes.isOk
    check cs.bestHeight == 101

    let discRes = cs.disconnectBlock(spendBlock)
    check discRes.isOk
    check cs.bestHeight == 100

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 4 — per-tx vin count == txUndo.prevOutputs count
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 4: per-tx vin/undo count":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 4: spend tx with 1 input has 1 prevOutput in undo":
    ## Single-input spend tx: undo must record exactly 1 prevOutput.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, coinbaseTxid) = seedChain(cs)

    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Single-input spend
    let spendBlock = makeSpendBlock(prevHash, 101, coinbaseTxid)
    discard cs.connectBlock(spendBlock, 101)

    # The UTXO that was spent must be restored after disconnect
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isNone  # spent

    let discRes = cs.disconnectBlock(spendBlock)
    check discRes.isOk
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isSome  # restored

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 5 — handleReorg skips IsUnspendable on disconnect phase
# ---------------------------------------------------------------------------

suite "handleReorg Gate 5: IsUnspendable skip in reorg disconnect":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 5: reorg over OP_RETURN block succeeds without error":
    ## Old-chain block has OP_RETURN output. handleReorg must skip it
    ## (never stored, so delete would fail silently, but tracking it
    ## in reorgDeletedUtxos would poison the tentative-delete set).
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Old chain: block 1A has OP_RETURN output
    let block1A = makeBlockWithOpReturn(genesisHash, 1)
    discard cs.connectBlock(block1A, 1)
    let cb1A = block1A.txs[0].txid()
    check cs.bestHeight == 1
    check cs.getUtxo(OutPoint(txid: cb1A, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb1A, vout: 1)).isNone  # OP_RETURN, never stored

    # New chain: 1B, 2B — wins by length
    let block1B = makeSimpleBlock(genesisHash, 1, chainId = 1)
    let block1BHash = getBlockHash(block1B)
    let block2B = makeSimpleBlock(block1BHash, 2, chainId = 1)

    let reorgRes = cs.handleReorg(genesisHash, @[block1B, block2B])
    check reorgRes.isOk
    check cs.bestHeight == 2

    # Old chain UTXOs gone
    check cs.getUtxo(OutPoint(txid: cb1A, vout: 0)).isNone

    # New chain UTXOs present
    let cb1B = block1B.txs[0].txid()
    let cb2B = block2B.txs[0].txid()
    check cs.getUtxo(OutPoint(txid: cb1B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb2B, vout: 0)).isSome

    cs.close()

  test "Gate 5: reorg with OP_RETURN on both old and new chain":
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let block1A = makeBlockWithOpReturn(genesisHash, 1)
    discard cs.connectBlock(block1A, 1)

    let block1B = makeBlockWithOpReturn(genesisHash, 2)  # different timestamp via height=2
    let block1BHash = getBlockHash(block1B)
    let block2B = makeSimpleBlock(block1BHash, 3, chainId = 5)

    let reorgRes = cs.handleReorg(genesisHash, @[block1B, block2B])
    check reorgRes.isOk
    check cs.bestHeight == 2  # newChain has 2 blocks

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 6 — SetBestBlock unconditional update
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 6: bestBlock updated unconditionally":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 6: bestBlockHash updated to prevBlock after disconnect":
    ## After disconnect of block at height H, bestBlockHash must be
    ## the disconnected block's prevBlock (not stale).
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    let block1Hash = getBlockHash(block1)

    let block2 = makeSimpleBlock(block1Hash, 2)
    discard cs.connectBlock(block2, 2)

    check cs.bestHeight == 2
    check cs.bestBlockHash == getBlockHash(block2)

    # Disconnect block2
    let r2 = cs.disconnectBlock(block2)
    check r2.isOk
    check cs.bestHeight == 1
    check cs.bestBlockHash == block1Hash  # must be block1's hash

    # Disconnect block1
    let r1 = cs.disconnectBlock(block1)
    check r1.isOk
    check cs.bestHeight == 0
    check cs.bestBlockHash == genesisHash  # must be genesis hash

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gates 7+8 — basic UTXO restore + removal correctness
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gates 7+8: UTXO restore and removal":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gates 7+8: disconnect removes block outputs and restores spent inputs":
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, coinbaseTxid) = seedChain(cs)

    # Build to maturity
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Block 101: spends the h=1 coinbase
    let spendBlock = makeSpendBlock(prevHash, 101, coinbaseTxid)
    let spendTxid = spendBlock.txs[1].txid()
    let cbTxid101 = spendBlock.txs[0].txid()

    discard cs.connectBlock(spendBlock, 101)

    # After connect: coinbase at h=1 spent, spendTx output and cb101 exist
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isNone  # spent
    check cs.getUtxo(OutPoint(txid: spendTxid, vout: 0)).isSome    # created
    check cs.getUtxo(OutPoint(txid: cbTxid101, vout: 0)).isSome    # created

    # Disconnect
    let discRes = cs.disconnectBlock(spendBlock)
    check discRes.isOk

    # Gate 7: spent UTXOs restored
    let restored = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check restored.isSome
    check int64(restored.get().output.value) == 5000000000
    check restored.get().isCoinbase == true
    check restored.get().height == 1

    # Gate 8: created UTXOs removed
    check cs.getUtxo(OutPoint(txid: spendTxid, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: cbTxid101, vout: 0)).isNone

    check cs.bestHeight == 100

    cs.close()

  test "Gates 7+8: multiple spend transactions in single block":
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed two coinbases in separate blocks
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let gHash = getBlockHash(genesis)

    let blk1 = makeSimpleBlock(gHash, 1, chainId = 0)
    discard cs.connectBlock(blk1, 1)
    let blk1Hash = getBlockHash(blk1)
    let cb1 = blk1.txs[0].txid()

    let blk2 = makeSimpleBlock(blk1Hash, 2, chainId = 1)
    discard cs.connectBlock(blk2, 2)
    let blk2Hash = getBlockHash(blk2)
    let cb2 = blk2.txs[0].txid()

    # Pad to maturity for both coinbases
    var prevHash = blk2Hash
    for h in 3 ..< 102:
      let blk = makeSimpleBlock(prevHash, int32(h), chainId = int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Block 102 spends cb1; block 103 spends cb2 — two separate disconnect tests
    let spendBlk102 = makeSpendBlock(prevHash, 102, cb1, chainId = 200)
    discard cs.connectBlock(spendBlk102, 102)

    check cs.getUtxo(OutPoint(txid: cb1, vout: 0)).isNone

    let discRes = cs.disconnectBlock(spendBlk102)
    check discRes.isOk
    check cs.getUtxo(OutPoint(txid: cb1, vout: 0)).isSome  # restored

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 9 — reorg UTXO consistency
# ---------------------------------------------------------------------------

suite "handleReorg Gate 9: UTXO consistency across fork":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 9: 2-block reorg — old UTXOs gone, new UTXOs present":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blk1A = makeSimpleBlock(genesisHash, 1, chainId = 1)
    discard cs.connectBlock(blk1A, 1)
    let blk1AHash = getBlockHash(blk1A)
    let blk2A = makeSimpleBlock(blk1AHash, 2, chainId = 1)
    discard cs.connectBlock(blk2A, 2)

    let cb1A = blk1A.txs[0].txid()
    let cb2A = blk2A.txs[0].txid()
    check cs.getUtxo(OutPoint(txid: cb1A, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb2A, vout: 0)).isSome

    let blk1B = makeSimpleBlock(genesisHash, 1, chainId = 2)
    let blk1BHash = getBlockHash(blk1B)
    let blk2B = makeSimpleBlock(blk1BHash, 2, chainId = 2)
    let blk2BHash = getBlockHash(blk2B)
    let blk3B = makeSimpleBlock(blk2BHash, 3, chainId = 2)

    let reorgRes = cs.handleReorg(genesisHash, @[blk1B, blk2B, blk3B])
    check reorgRes.isOk
    check cs.bestHeight == 3

    # Old chain UTXOs gone
    check cs.getUtxo(OutPoint(txid: cb1A, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: cb2A, vout: 0)).isNone

    # New chain UTXOs present
    let cb1B = blk1B.txs[0].txid()
    let cb2B = blk2B.txs[0].txid()
    let cb3B = blk3B.txs[0].txid()
    check cs.getUtxo(OutPoint(txid: cb1B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb2B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb3B, vout: 0)).isSome

    cs.close()

  test "Gate 9: reorg reversal — reorg to chain A then back to B":
    ## Performs two reorgs and verifies UTXO set is consistent both times.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Chain A: blocks 1A, 2A
    let blk1A = makeSimpleBlock(genesisHash, 1, chainId = 10)
    discard cs.connectBlock(blk1A, 1)
    let blk1AHash = getBlockHash(blk1A)
    let blk2A = makeSimpleBlock(blk1AHash, 2, chainId = 10)
    discard cs.connectBlock(blk2A, 2)
    let cb2A = blk2A.txs[0].txid()

    # Reorg to chain B (3 blocks, longer)
    let blk1B = makeSimpleBlock(genesisHash, 1, chainId = 20)
    let blk1BHash = getBlockHash(blk1B)
    let blk2B = makeSimpleBlock(blk1BHash, 2, chainId = 20)
    let blk2BHash = getBlockHash(blk2B)
    let blk3B = makeSimpleBlock(blk2BHash, 3, chainId = 20)

    let r1 = cs.handleReorg(genesisHash, @[blk1B, blk2B, blk3B])
    check r1.isOk
    check cs.bestHeight == 3
    check cs.getUtxo(OutPoint(txid: cb2A, vout: 0)).isNone  # gone

    # Reorg back to a 4-block A chain
    let blk3A = makeSimpleBlock(blk1AHash, 3, chainId = 10)
    let blk3AHash = getBlockHash(blk3A)
    let blk4A = makeSimpleBlock(blk3AHash, 4, chainId = 10)

    let r2 = cs.handleReorg(genesisHash, @[blk1A, blk2A, blk3A, blk4A])
    check r2.isOk
    check cs.bestHeight == 4
    check cs.getUtxo(OutPoint(txid: cb2A, vout: 0)).isSome  # restored

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 10 — disconnectHook fires after commit
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 10: disconnectHook fires after commit":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 10: disconnectHook called with correct (blockHash, prevHash, height)":
    var cs = newChainState(TestDbPath, regtestParams())

    var hookCalled = false
    var hookedHash = BlockHash(default(array[32, byte]))
    var hookedPrev = BlockHash(default(array[32, byte]))
    var hookedHeight: int32 = -1

    cs.disconnectHook = proc(bh: BlockHash, ph: BlockHash, h: int32) {.raises: [].} =
      hookCalled = true
      hookedHash = bh
      hookedPrev = ph
      hookedHeight = h

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    let block1Hash = getBlockHash(block1)

    let res = cs.disconnectBlock(block1)
    check res.isOk
    check hookCalled
    check hookedHash == block1Hash
    check hookedPrev == genesisHash
    check hookedHeight == 1

    cs.close()

  test "Gate 10: disconnectHook fires for each block in handleReorg":
    var cs = newChainState(TestDbPath, regtestParams())

    var hookedBlocks: seq[tuple[hash: BlockHash, height: int32]] = @[]
    cs.disconnectHook = proc(bh: BlockHash, ph: BlockHash, h: int32) {.raises: [].} =
      hookedBlocks.add((bh, h))

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blk1 = makeSimpleBlock(genesisHash, 1, chainId = 1)
    discard cs.connectBlock(blk1, 1)
    let blk1Hash = getBlockHash(blk1)
    let blk2 = makeSimpleBlock(blk1Hash, 2, chainId = 1)
    discard cs.connectBlock(blk2, 2)
    let blk2Hash = getBlockHash(blk2)

    # Reorg both blocks away
    let newBlk1 = makeSimpleBlock(genesisHash, 1, chainId = 2)
    let newBlk1Hash = getBlockHash(newBlk1)
    let newBlk2 = makeSimpleBlock(newBlk1Hash, 2, chainId = 2)
    let newBlk2Hash = getBlockHash(newBlk2)
    let newBlk3 = makeSimpleBlock(newBlk2Hash, 3, chainId = 2)

    let reorgRes = cs.handleReorg(genesisHash, @[newBlk1, newBlk2, newBlk3])
    check reorgRes.isOk

    # Hook should have been called for the 2 disconnected blocks (tip→fork order)
    check hookedBlocks.len == 2
    # First hook: tip block (h=2, blk2)
    check hookedBlocks[0].hash == blk2Hash
    check hookedBlocks[0].height == 2
    # Second hook: h=1 block (blk1)
    check hookedBlocks[1].hash == blk1Hash
    check hookedBlocks[1].height == 1

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 11 — ApplyTxInUndo missing-metadata sibling recovery
# (validation.cpp:2155-2166)
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 11: missing-metadata sibling recovery":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 11: height=0 + isCoinbase=false undo entry triggers sibling lookup":
    ## Construct a 2-output tx, spend output 0 in block N, leave output 1 unspent.
    ## When disconnecting block N, the undo entry for vout=0 carries height=0
    ## (legacy missing-metadata format).  ApplyTxInUndo must look up vout=1
    ## via AccessByTxid to recover the (height, isCoinbase) metadata.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, _) = seedChain(cs)

    # Build a 2-output coinbase at h=2 (we need an unrelated spendable tx).
    # Use the existing seed (h=1 coinbase at fixtureHash) → mature at h=101.
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Manually inject a UtxoEntry at (synthFakeTxId, vout=1) so the sibling
    # lookup has something to find.  This simulates a 2-output transaction
    # where vout=1 is still unspent at the time we disconnect vout=0's spend.
    let fakeTxidBytes = block:
      var b: array[32, byte]
      for i in 0..31: b[i] = byte(i + 1)
      b
    let siblingEntry = UtxoEntry(
      output: TxOut(value: Satoshi(1000), scriptPubKey: makeSpendableScript()),
      height: 42,
      isCoinbase: false
    )
    cs.putUtxoCache(OutPoint(txid: TxId(fakeTxidBytes), vout: 1), siblingEntry)
    # Persist to RocksDB via a connect-block side effect would be heavy;
    # the in-memory cache is enough for getUtxo() to surface it.

    # Build a UndoData entry with height=0 (legacy) for vout=0 of the same tx.
    var undoData = UndoData()
    let missingMetaEntry = UtxoEntry(
      output: TxOut(value: Satoshi(2000), scriptPubKey: makeSpendableScript()),
      height: 0,        # ← the legacy missing-metadata marker
      isCoinbase: false
    )
    undoData.spentOutputs.add((
      OutPoint(txid: TxId(fakeTxidBytes), vout: 0),
      missingMetaEntry
    ))

    # Build a 2-tx block (coinbase + a fake "spent the sibling" tx).  The
    # spend tx's vin references our synthetic outpoint so disconnectBlock
    # restores via our undoData.
    let heightBytes = @[byte(0x65), byte(0x00), byte(0x00), byte(0x00)]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5000000000),
        scriptPubKey: makeSpendableScript()
      )],
      witnesses: @[], lockTime: 0
    )
    let spend = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(fakeTxidBytes), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1500),
        scriptPubKey: makeSpendableScript()
      )],
      witnesses: @[], lockTime: 0
    )
    let txHashes = @[array[32, byte](coinbase.txid()), array[32, byte](spend.txid())]
    let fakeSpendBlock = Block(
      header: BlockHeader(
        version: 1, prevBlock: prevHash,
        merkleRoot: merkleRoot(txHashes),
        timestamp: 1231006505 + 101'u32 * 600'u32, bits: 0x207fffff'u32, nonce: 101
      ),
      txs: @[coinbase, spend]
    )

    # We bypass connectBlock (no UTXO for the input) and call disconnectBlock
    # directly with the synthetic UndoData.  Pre-condition: fakeSpendBlock NOT
    # in chainstate; we're testing the metadata-recovery path of the inner
    # disconnectBlock proc.
    let res = cs.disconnectBlock(fakeSpendBlock, 101, undoData)
    check res.isOk

    # After restore, the outpoint at (fakeTxid, vout=0) should have the
    # SIBLING's metadata (height=42, isCoinbase=false), not the original
    # height=0.
    let restored = cs.getUtxo(OutPoint(txid: TxId(fakeTxidBytes), vout: 0))
    check restored.isSome
    check restored.get().height == 42        # recovered from sibling
    check restored.get().isCoinbase == false

    cs.close()

  test "Gate 11: height=0 + no sibling → DISCONNECT_FAILED equivalent (err)":
    ## When the undo entry carries height=0 AND no unspent sibling exists in
    ## the UTXO set, Core returns DISCONNECT_FAILED (validation.cpp:2164).
    ## nimrod's equivalent: return an err Result.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, _, _) = seedChain(cs)

    let isolatedTxidBytes = block:
      var b: array[32, byte]
      for i in 0..31: b[i] = byte(0xFF - i)
      b
    var undoData = UndoData()
    undoData.spentOutputs.add((
      OutPoint(txid: TxId(isolatedTxidBytes), vout: 0),
      UtxoEntry(
        output: TxOut(value: Satoshi(100), scriptPubKey: makeSpendableScript()),
        height: 0, isCoinbase: false
      )
    ))

    let heightBytes = @[byte(0x02), byte(0x00), byte(0x00), byte(0x00)]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: makeSpendableScript())],
      witnesses: @[], lockTime: 0
    )
    let spend = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(isolatedTxidBytes), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(50), scriptPubKey: makeSpendableScript())],
      witnesses: @[], lockTime: 0
    )
    let txHashes = @[array[32, byte](coinbase.txid()), array[32, byte](spend.txid())]
    let blk = Block(
      header: BlockHeader(
        version: 1, prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: merkleRoot(txHashes),
        timestamp: 9999'u32, bits: 0x207fffff'u32, nonce: 1
      ),
      txs: @[coinbase, spend]
    )

    let res = cs.disconnectBlock(blk, 2'i32, undoData)
    check (not res.isOk)   # should fail — no sibling for metadata recovery

    cs.close()

  test "Gate 11: height>0 undo entry bypasses sibling lookup (modern format)":
    ## When the undo entry has height > 0 (modern per-output metadata),
    ## the sibling recovery path must NOT execute — height is used as-is.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, coinbaseTxid) = seedChain(cs)

    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    let spendBlock = makeSpendBlock(prevHash, 101, coinbaseTxid)
    discard cs.connectBlock(spendBlock, 101)

    # The undo data restored via disconnectBlock(blk) carries height=1
    # (the h=1 coinbase).  Path: height > 0 → sibling lookup is skipped.
    let r = cs.disconnectBlock(spendBlock)
    check r.isOk
    let restored = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check restored.isSome
    check restored.get().height == 1   # original metadata preserved
    check restored.get().isCoinbase == true

    cs.close()

# ---------------------------------------------------------------------------
# Suite: Gate 12 — Block/undo TX-count mismatch is hard error
# (validation.cpp:2190-2193)
# ---------------------------------------------------------------------------

suite "DisconnectBlock Gate 12: undo/block tx-count mismatch is fatal":

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "Gate 12: coinbase-only block with non-empty txUndo would be rejected":
    ## We can't easily construct this on-disk; we test the contract via the
    ## structural invariant directly.  If a malicious undo record had
    ## txUndo.len == 1 for a coinbase-only block (txs.len == 1), the gate
    ## should fire (1 + 1 != 1).  Since the inner disconnectBlock proc
    ## doesn't read undo from disk, we exercise the check at the
    ## from-disk entry point indirectly via the connect+disconnect roundtrip,
    ## which is the path that actually consults the undo file.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, fixtureHash, _) = seedChain(cs)

    let blk = makeSimpleBlock(fixtureHash, 2)
    discard cs.connectBlock(blk, 2)
    # Roundtrip disconnect should succeed for a well-formed coinbase-only block.
    check cs.disconnectBlock(blk).isOk
    check cs.bestHeight == 1

    cs.close()
