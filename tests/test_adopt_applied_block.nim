## adoptAppliedBlock — marker-lag repair regression test
##
## Scenario (observed live 2026-08-15, mainnet genesis rig at 838704/838705):
## with the WAL disabled during IBD, a SIGKILL can land after some of a
## block's UTXO mutations became durable but before the tip-pointer meta
## write did. On restart the chain tip points at the parent while the UTXO
## set holds a PREFIX (possibly all) of the block's mutations; replaying the
## block rejects "missing input" (its spends are already deleted) —
## indistinguishable from corruption without a probe.
##
## adoptAppliedBlock probes for POSITIVE EVIDENCE against the RAW DB — the
## block's own outputs durable (an outpoint is unique to its creating block,
## so false positives are impossible; the cached view is NOT consulted since
## it can carry residue of this session's own failed attempts) — and on
## evidence performs a TOLERANT ROLL-FORWARD: idempotent deletes +
## deterministic overwrite puts converge partial, full, or poisoned states
## to the exact post-block state, committed atomically at once. Core
## analogue: ReplayBlocks (validation.cpp::RollforwardBlock). Fleet
## precedent: blockbrew AdoptAppliedBlock (e7d0afe).
##
## Also covers the enabling fix: connectBlockIBD is now two-pass (validate
## ALL inputs before mutating), so a failed connect leaves NO residue in the
## cache / write batch / deleted-tracking.

import unittest2
import std/[os, options, tables]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbBase = "/tmp/nimrod_adopt_applied_test"

proc dbPath(n: int): string = TestDbBase & "_" & $n

proc cleanupTestDbs() =
  for n in 1 .. 6:
    if dirExists(dbPath(n)):
      removeDir(dbPath(n))

proc makeTestCoinbase(value: int64, numOutputs: int = 1): Transaction =
  var outs: seq[TxOut]
  for i in 0 ..< numOutputs:
    outs.add(TxOut(
      value: Satoshi(value + int64(i)),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    ))
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
    outputs: outs,
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32,
                     coinbaseValue: int64 = 5000000000,
                     numOutputs: int = 1): Block =
  let coinbase = makeTestCoinbase(coinbaseValue, numOutputs)
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

  test "adopts a fully-applied durable block on raw-DB evidence":
    var cs = newChainState(dbPath(1), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    let blk1 = makeSimpleBlock(genesisHash, 1)
    check cs.connectBlockIBD(blk1, 1).isOk
    # Make the mutations DURABLE (the real scenario: the block's writes hit
    # the DB, the tip pointer didn't). The probe reads the raw DB only.
    cs.flushIBDBatch()
    check cs.bestHeight == 1

    # Simulate the torn state: rewind the recorded tip to the parent.
    cs.bestHeight = 0
    cs.bestBlockHash = genesisHash

    let res = cs.adoptAppliedBlock(blk1, 1)
    check res.isOk
    check cs.bestHeight == 1
    check cs.bestBlockHash == getBlockHash(blk1)

    # The block-index row must be visible to the raw readers.
    let idx = cs.db.getBlockIndex(getBlockHash(blk1))
    check idx.isSome
    check idx.get().height == 1
    cs.db.db.closeUnsafe()

  test "converges a PARTIALLY-applied durable block (tolerant roll-forward)":
    var cs = newChainState(dbPath(2), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    # Two-output coinbase: after flush, delete output 1 from the raw DB to
    # simulate a partial prefix (only output 0 durable) — the live rig's
    # exact disease (1718/18516 outputs durable).
    let blk1 = makeSimpleBlock(genesisHash, 1, numOutputs = 2)
    check cs.connectBlockIBD(blk1, 1).isOk
    cs.flushIBDBatch()
    let cbTxid = blk1.txs[0].txid()
    let op0 = OutPoint(txid: cbTxid, vout: 0'u32)
    let op1 = OutPoint(txid: cbTxid, vout: 1'u32)
    cs.db.deleteUtxo(op1)
    # Clear the cached copy so reads reflect the damaged durable state.
    cs.deleteUtxoCache(op1)
    check cs.db.getUtxo(op0).isSome
    check cs.db.getUtxo(op1).isNone

    # Torn state: tip rewound, durable set partial.
    cs.bestHeight = 0
    cs.bestBlockHash = genesisHash

    let res = cs.adoptAppliedBlock(blk1, 1)
    check res.isOk
    check cs.bestHeight == 1
    # Roll-forward flushed immediately: BOTH outputs must now be durable.
    check cs.db.getUtxo(op0).isSome
    check cs.db.getUtxo(op1).isSome
    cs.db.db.closeUnsafe()

  test "refuses adoption with no durable evidence (genuinely un-applied block)":
    var cs = newChainState(dbPath(3), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    # Different coinbase value ⇒ different txid ⇒ none of this block's
    # outputs exist anywhere. The probe MUST come back negative — this is
    # what keeps genuine corruption on the loud reject path.
    let phantom = makeSimpleBlock(genesisHash, 1, coinbaseValue = 5000000001)
    let res = cs.adoptAppliedBlock(phantom, 1)
    check (not res.isOk)
    check cs.bestHeight == 0
    check cs.bestBlockHash == genesisHash
    cs.db.db.closeUnsafe()

  test "cache residue alone is NOT evidence (raw-DB gate)":
    var cs = newChainState(dbPath(4), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    let blk1 = makeSimpleBlock(genesisHash, 1)
    # Plant the block's output in the CACHE only (what a failed partial
    # attempt used to leave behind) — never flushed, so not durable. The
    # old cs.getUtxo probe accepted this; the raw-DB probe must not.
    let cbTxid = blk1.txs[0].txid()
    cs.putUtxoCache(OutPoint(txid: cbTxid, vout: 0'u32),
                    UtxoEntry(output: blk1.txs[0].outputs[0], height: 1,
                              isCoinbase: true))
    let res = cs.adoptAppliedBlock(blk1, 1)
    check (not res.isOk)
    check cs.bestHeight == 0
    cs.db.db.closeUnsafe()

  test "refuses adoption that does not extend the tip":
    var cs = newChainState(dbPath(5), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    cs.startIBD()
    # Wrong height (tip is 0, block claims height 5).
    let stray = makeSimpleBlock(getBlockHash(genesis), 5)
    check (not cs.adoptAppliedBlock(stray, 5).isOk)
    cs.db.db.closeUnsafe()

  test "failed connectBlockIBD leaves no residue (two-pass)":
    var cs = newChainState(dbPath(6), regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    cs.startIBD()
    # A block whose second tx spends a nonexistent outpoint: the connect
    # must fail WITHOUT creating the coinbase output, without deleting the
    # phantom input, and without marking anything in ibdDeletedUtxos.
    let coinbase = makeTestCoinbase(5000000000)
    var phantomTxid: array[32, byte]
    phantomTxid[0] = 0xde
    phantomTxid[1] = 0xad
    let spender = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: TxId(phantomTxid), vout: 0'u32),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(1000),
                       scriptPubKey: @[byte(0x51)])],
      witnesses: @[], lockTime: 0)
    var txHashes: seq[array[32, byte]]
    txHashes.add(array[32, byte](coinbase.txid()))
    txHashes.add(array[32, byte](spender.txid()))
    let badBlk = Block(
      header: BlockHeader(
        version: 1, prevBlock: genesisHash, merkleRoot: merkleRoot(txHashes),
        timestamp: 1231007105, bits: 0x207fffff'u32, nonce: 1),
      txs: @[coinbase, spender])

    let res = cs.connectBlockIBD(badBlk, 1)
    check (not res.isOk)
    # No residue: coinbase output NOT created, nothing marked deleted, tip
    # unchanged. (Before the two-pass rework the coinbase output WAS created
    # and later flushes committed it durably — the poison generator.)
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 0'u32)).isNone
    check cs.ibdDeletedUtxos.len == 0
    check cs.bestHeight == 0
    cs.db.db.closeUnsafe()
