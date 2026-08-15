## adoptAppliedBlock — marker-lag repair regression test
##
## Scenario (observed live 2026-08-15, mainnet genesis rig at 838704/838705):
## with the WAL disabled during IBD, a SIGKILL can land after a block's UTXO
## mutations became durable but before the tip-pointer meta write did. On
## restart the chain tip points at the parent while the UTXO set is one block
## AHEAD; replaying that block rejects "missing input" (its spends are already
## deleted) — indistinguishable from corruption without a probe.
##
## adoptAppliedBlock probes for POSITIVE EVIDENCE — the block's own outputs
## present in the UTXO set (an outpoint is unique to its creating block, so
## false positives are impossible) — and on evidence performs the connect
## bookkeeping WITHOUT re-applying UTXO mutations. Core analogue:
## ReplayBlocks' tolerant roll-forward (validation.cpp::RollforwardBlock).
## Fleet precedent: blockbrew AdoptAppliedBlock (e7d0afe).

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbBase = "/tmp/nimrod_adopt_applied_test"

proc dbPath(n: int): string = TestDbBase & "_" & $n

proc cleanupTestDbs() =
  for n in 1 .. 4:
    if dirExists(dbPath(n)):
      removeDir(dbPath(n))

proc makeTestCoinbase(value: int64): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xFFFFFFFF'u32
      ),
      scriptSig: @[byte(0x01), 0x01],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32,
                     coinbaseValue: int64 = 5000000000): Block =
  let coinbase = makeTestCoinbase(coinbaseValue)
  var txHashes: seq[array[32, byte]]
  txHashes.add(array[32, byte](coinbase.txid()))
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

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "adoptAppliedBlock marker-lag repair":
  setup:
    cleanupTestDbs()

  teardown:
    cleanupTestDbs()

  test "adopts an already-applied block on positive evidence":
    var cs = newChainState(dbPath(1), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    let blk1 = makeSimpleBlock(genesisHash, 1)
    check cs.connectBlockIBD(blk1, 1).isOk
    check cs.bestHeight == 1

    # Simulate the torn state: the UTXO mutations of blk1 are applied (they
    # sit in the cache/batch) but the recorded tip is rewound to the parent —
    # exactly what a restart after the mid-flush SIGKILL observes.
    cs.bestHeight = 0
    cs.bestBlockHash = genesisHash

    # A plain re-connect must fail: blk1's coinbase output already exists,
    # and for a spend-carrying block its inputs would already be deleted.
    # (Here the observable effect is the adoption probe finding the output.)
    let res = cs.adoptAppliedBlock(blk1, 1)
    check res.isOk
    check cs.bestHeight == 1
    check cs.bestBlockHash == getBlockHash(blk1)

    # The block-index row must be visible to the raw readers (unflushed
    # shadow), exactly as after a genuine connectBlockIBD.
    let idx = cs.db.getBlockIndex(getBlockHash(blk1))
    check idx.isSome
    check idx.get().height == 1
    cs.db.db.closeUnsafe()

  test "refuses adoption with no evidence (genuinely un-applied block)":
    var cs = newChainState(dbPath(2), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    # Different coinbase value ⇒ different txid ⇒ none of this block's
    # outputs exist in the UTXO set. The probe MUST come back negative —
    # this is what keeps genuine corruption on the loud reject path.
    let phantom = makeSimpleBlock(genesisHash, 1, coinbaseValue = 5000000001)
    let res = cs.adoptAppliedBlock(phantom, 1)
    check (not res.isOk)
    check cs.bestHeight == 0
    check cs.bestBlockHash == genesisHash
    cs.db.db.closeUnsafe()

  test "refuses adoption that does not extend the tip":
    var cs = newChainState(dbPath(3), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    cs.startIBD()
    # Wrong height (tip is 0, block claims height 5).
    let stray = makeSimpleBlock(getBlockHash(genesis), 5)
    check (not cs.adoptAppliedBlock(stray, 5).isOk)
    cs.db.db.closeUnsafe()

  test "refuses adoption outside IBD mode":
    var cs = newChainState(dbPath(4), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    # No startIBD: ibdBatch is nil; adoption must refuse rather than crash.
    let blk1 = makeSimpleBlock(getBlockHash(genesis), 1)
    check (not cs.adoptAppliedBlock(blk1, 1).isOk)
    cs.db.db.closeUnsafe()
