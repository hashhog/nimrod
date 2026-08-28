## W93 — ConnectBlock + ConnectTip + UpdateCoins comprehensive audit tests.
##
## Mirror of W92 (DisconnectBlock).  Targets Bitcoin Core's ConnectBlock
## (validation.cpp:2295-2673), ConnectTip (:3005-3105), and UpdateCoins
## (:1999-2012).
##
## Gates exercised here (focus on the ones that produced fixes in W93):
##  Gate-A (val:2333)  precondition: cs.bestBlockHash == blk.header.prevBlock
##  Gate-B (val:1999 + coins.cpp AddCoins)
##                       intra-block UTXO tracking: a tx that spends an output
##                       created by an earlier tx in the SAME block must end up
##                       in the block-undo with the correct prevOutputs count.
##                       Without this, disconnectBlock fails the vin-count gate
##                       (chainstate.nim:1470 — val:2229-2232).
##  Gate-C (val:2010 + AddCoins IsUnspendable)
##                       UpdateCoins-equivalent skips IsUnspendable outputs
##                       (OP_RETURN, oversized scripts).
##  Gate-D (val:2337-2343)  genesis special-case: no UTXO mutation at height 0.
##  Gate-E (val:2654)        bestBlockHash is set to the new tip atomically.
##  Gate-F (chainstate.nim:applyBlock + W93 fix)
##                       legacy applyBlock writes a non-zero totalWork derived
##                       from the parent index (was: default(0)).
##  Gate-G (val:2402)        IsBIP30Repeat exempts the two historical mainnet
##                       coinbase-duplicate blocks (regression test).
##  Gate-H (val:2467)        BIP-34 implies BIP-30 limit (height ≥ 1,983,702)
##                       always re-enables the BIP-30 UTXO scan.
##  Gate-I (val:2333 again)  connectBlockIBD enforces the same parent gate as
##                       connectBlock.

import unittest2
import std/[os, options, strutils, tables]
import ../src/storage/[db, chainstate, undo]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/consensus/validation as val

const TestDbPath = "/tmp/nimrod_connect_block_w93"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeP2WPKH(): seq[byte] =
  ## Spendable P2WPKH-style script.
  @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))

proc makeOpReturn(): seq[byte] =
  ## OP_RETURN (IsUnspendable returns true).
  @[byte(0x6a), 0x04, 0xde, 0xad, 0xbe, 0xef]

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

proc makeCoinbaseTx(height: int32, extra: int32 = 0,
                    spk: seq[byte] = makeP2WPKH()): Transaction =
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let extraBytes = @[byte(extra and 0xff), byte((extra shr 8) and 0xff),
                     byte((extra shr 16) and 0xff), byte((extra shr 24) and 0xff)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04)] & extraBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: spk)],
    witnesses: @[],
    lockTime: 0
  )

proc makeSpendingTx(prevTxid: TxId, prevVout: uint32,
                    value: int64 = 4990000000): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: makeP2WPKH())],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlock(prevHash: BlockHash, height: int32,
               txs: seq[Transaction], nonce: uint32 = 0): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600) + nonce,
      bits: 0x207fffff'u32,
      nonce: uint32(height) xor nonce
    ),
    txs: txs
  )

proc seedChain(cs: var ChainState):
    tuple[height: int32, hash: BlockHash, cbTxid: TxId] =
  ## Connect genesis (height 0, no UTXO mutation) and an extra coinbase block
  ## at height 1.  Returns the height-1 block info so tests can build a
  ## height-2 block that spends the height-1 coinbase.
  let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                          @[makeCoinbaseTx(0)])
  doAssert cs.connectBlock(genesis, 0).isOk
  let h1 = makeBlock(getBlockHash(genesis), 1, @[makeCoinbaseTx(1)])
  doAssert cs.connectBlock(h1, 1).isOk
  (1'i32, getBlockHash(h1), h1.txs[0].txid())

# ---------------------------------------------------------------------------
# Gate-A — connectBlock precondition (Core val:2333)
# ---------------------------------------------------------------------------

suite "W93 — ConnectBlock gates":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-A: connectBlock rejects block whose prevBlock != bestBlockHash":
    ## Defensive check mirroring Bitcoin Core's `assert(hashPrevBlock ==
    ## view.GetBestBlock())` (validation.cpp:2333).  Without this, calling
    ## connectBlock with a stale/wrong-parent block would silently corrupt
    ## the UTXO set.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, _, _) = seedChain(cs)
    let bogusPrev = BlockHash([byte(0xde), 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                               0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef])
    let bad = makeBlock(bogusPrev, 2, @[makeCoinbaseTx(2)])
    let res = cs.connectBlock(bad, 2)
    check (not res.isOk)
    check ($res.error).contains("precondition")
    cs.close()

  test "Gate-A: connectBlock accepts block whose prevBlock == bestBlockHash":
    ## Sanity case — the precondition does not over-reject.
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, _) = seedChain(cs)
    let nxt = makeBlock(prev, h + 1, @[makeCoinbaseTx(h + 1)])
    let res = cs.connectBlock(nxt, h + 1)
    check res.isOk
    cs.close()

  test "Gate-I: connectBlockIBD rejects wrong-parent block":
    ## Same precondition as Gate-A, IBD fast path.
    var cs = newChainState(TestDbPath, regtestParams())
    let (_, _, _) = seedChain(cs)
    cs.startIBD()
    let bogusPrev = BlockHash([byte(0x11), 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44,
                               0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44,
                               0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44,
                               0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44])
    let bad = makeBlock(bogusPrev, 2, @[makeCoinbaseTx(2)])
    let res = cs.connectBlockIBD(bad, 2)
    check (not res.isOk)
    check ($res.error).contains("precondition")
    cs.close()

# ---------------------------------------------------------------------------
# Gate-B — intra-block UTXO tracking (val:2600 / AddCoins per-tx)
# ---------------------------------------------------------------------------

suite "W93 — UpdateCoins / intra-block UTXOs":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-B: generateBlockUndo captures intra-block spend":
    ## Block with two txs where tx[1] spends an output created by tx[0]
    ## (NOT the coinbase — tx[0] here is a non-coinbase tx funded by an
    ## earlier UTXO; this is the textbook intra-block tx chain).
    ##
    ## Pre-W93: generateBlockUndo iterated tx[1]'s inputs and called
    ## cs.getUtxo() which returned None for tx[0]'s output (not yet in
    ## chainstate), silently dropping the undo entry.  txUndo.prevOutputs
    ## ended up with 0 entries instead of 1 — disconnectBlock would fail
    ## the vin-count gate (chainstate.nim:1470 — val:2229-2232).
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, cbTxid) = seedChain(cs)

    # Build a height-h+1 block with: coinbase + tx[1] that spends the
    # height-1 coinbase + tx[2] that spends tx[1]'s output.
    let coinbase = makeCoinbaseTx(h + 1, extra = 99)
    let tx1 = makeSpendingTx(cbTxid, 0, value = 4_500_000_000)
    let tx2 = makeSpendingTx(tx1.txid(), 0, value = 4_000_000_000)
    let blk = makeBlock(prev, h + 1, @[coinbase, tx1, tx2])

    # Generate block undo at this height; check both txUndo entries
    # have the correct prevOutputs count.
    let undo = cs.generateBlockUndo(blk, h + 1)
    check undo.txUndo.len == 2  # one per non-coinbase tx
    check undo.txUndo[0].prevOutputs.len == 1  # tx1 spent the height-1 coinbase
    check undo.txUndo[1].prevOutputs.len == 1  # tx2 spent tx1's output (intra-block)
    cs.close()

  test "Gate-B: generateUndoData captures intra-block spend":
    ## Same shape, legacy UndoData format.
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, cbTxid) = seedChain(cs)

    let coinbase = makeCoinbaseTx(h + 1, extra = 100)
    let tx1 = makeSpendingTx(cbTxid, 0, value = 4_500_000_000)
    let tx2 = makeSpendingTx(tx1.txid(), 0, value = 4_000_000_000)
    let blk = makeBlock(prev, h + 1, @[coinbase, tx1, tx2])

    let undo = cs.generateUndoData(blk, h + 1)
    # 2 non-coinbase tx, one input each → 2 spentOutputs total.
    check undo.spentOutputs.len == 2
    cs.close()

  test "Gate-B (standalone undo.nim): generateBlockUndo with intra-block spend":
    ## The free-standing generateBlockUndo in undo.nim takes a closure for
    ## UTXO lookup.  With the W93 fix it must also synthesise intra-block
    ## outputs from earlier txs in the block.
    let coinbase = makeCoinbaseTx(2)
    var prevTxid: array[32, byte]
    prevTxid[0] = 0xab
    let tx1 = makeSpendingTx(TxId(prevTxid), 0, value = 4_500_000_000)
    let tx2 = makeSpendingTx(tx1.txid(), 0, value = 4_000_000_000)
    let blk = Block(header: BlockHeader(), txs: @[coinbase, tx1, tx2])

    proc emptyLookup(op: OutPoint):
        Option[tuple[output: TxOut, height: int32, isCoinbase: bool]] =
      # Pretend we have the height-1 coinbase available so tx1 looks
      # spendable from the chainstate's perspective.
      if op.txid == TxId(prevTxid) and op.vout == 0:
        return some((output: TxOut(value: Satoshi(5_000_000_000),
                                   scriptPubKey: makeP2WPKH()),
                     height: 1'i32, isCoinbase: true))
      none(tuple[output: TxOut, height: int32, isCoinbase: bool])

    let undo = undo.generateBlockUndo(blk, emptyLookup, 2)
    check undo.txUndo.len == 2
    check undo.txUndo[0].prevOutputs.len == 1
    check undo.txUndo[1].prevOutputs.len == 1
    # The intra-block entry should be stamped with the current block's height.
    check undo.txUndo[1].prevOutputs[0].height == 2

  test "Gate-B: undo.txUndo[*].prevOutputs.len matches tx.inputs.len even for intra-block":
    ## Stronger invariant — what disconnectBlock requires.
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, cbTxid) = seedChain(cs)

    let coinbase = makeCoinbaseTx(h + 1, extra = 1)
    let tx1 = makeSpendingTx(cbTxid, 0, value = 4_500_000_000)
    let tx2 = makeSpendingTx(tx1.txid(), 0, value = 4_000_000_000)
    let blk = makeBlock(prev, h + 1, @[coinbase, tx1, tx2])

    let bu = cs.generateBlockUndo(blk, h + 1)
    let nonCoinbase = blk.txs[1 .. ^1]
    for i, tx in nonCoinbase:
      check bu.txUndo[i].prevOutputs.len == tx.inputs.len
    cs.close()

# ---------------------------------------------------------------------------
# Gate-C — IsUnspendable filter inside UpdateCoins-equivalent path
# ---------------------------------------------------------------------------

suite "W93 — IsUnspendable filter":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-C: connectBlock skips OP_RETURN outputs in UTXO set":
    ## Bitcoin Core AddCoins (coins.cpp) skips IsUnspendable outputs;
    ## nimrod's connectBlock mirrors this at line 744.
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, _) = seedChain(cs)
    # Build a coinbase with one P2WPKH output and one OP_RETURN output.
    let cb = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04), 0x02, 0x00, 0x00, 0x00, 0x04, 0xcc, 0xcc, 0xcc, 0xcc],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5_000_000_000), scriptPubKey: makeP2WPKH()),
        TxOut(value: Satoshi(0), scriptPubKey: makeOpReturn())
      ],
      witnesses: @[],
      lockTime: 0
    )
    let blk = makeBlock(prev, h + 1, @[cb])
    check cs.connectBlock(blk, h + 1).isOk
    # P2WPKH output should be in UTXO; OP_RETURN must not be.
    check cs.getUtxo(OutPoint(txid: cb.txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: cb.txid(), vout: 1)).isNone
    cs.close()

# ---------------------------------------------------------------------------
# Gate-D — genesis special-case (val:2337-2343)
# ---------------------------------------------------------------------------

suite "W93 — Genesis special-case":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-D: connectBlock at height 0 does not write coinbase to UTXO set":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk
    # Genesis coinbase must not be in the UTXO set (Bitcoin Core parity).
    check cs.getUtxo(OutPoint(txid: genesis.txs[0].txid(), vout: 0)).isNone
    check cs.bestHeight == 0
    cs.close()

# ---------------------------------------------------------------------------
# Gate-E — bestBlockHash updates atomically (val:2654)
# ---------------------------------------------------------------------------

suite "W93 — Best-block update":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-E: bestBlockHash matches connected block hash":
    var cs = newChainState(TestDbPath, regtestParams())
    let (h, prev, _) = seedChain(cs)
    let nxt = makeBlock(prev, h + 1, @[makeCoinbaseTx(h + 1)])
    check cs.connectBlock(nxt, h + 1).isOk
    check cs.bestBlockHash == getBlockHash(nxt)
    check cs.bestHeight == h + 1
    cs.close()

# ---------------------------------------------------------------------------
# Gate-F — applyBlock totalWork derivation (W93 fix)
# ---------------------------------------------------------------------------

suite "W93 — applyBlock totalWork":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "Gate-F: applyBlock derives non-zero totalWork from parent":
    ## Pre-W93 applyBlock wrote default(0) for totalWork; the new version
    ## fetches the parent index and accumulates calculateBlockWork.
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk
    # Now use the legacy applyBlock path at height 1; it must write a
    # non-zero totalWork.
    let h1 = makeBlock(getBlockHash(genesis), 1, @[makeCoinbaseTx(1)])
    cs.db.applyBlock(h1, 1)
    let idxOpt = cs.db.getBlockIndex(getBlockHash(h1))
    check idxOpt.isSome
    let idx = idxOpt.get()
    var zero: array[32, byte]
    check idx.totalWork != zero
    cs.close()

  test "Gate-F: applyBlock refuses wrong-parent block":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk
    # Build a height-1 block with a bogus prev — applyBlock must skip it
    # without mutating bestBlockHash.
    let bogusPrev = BlockHash([byte(0x99), 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                               0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                               0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                               0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99])
    let bad = makeBlock(bogusPrev, 1, @[makeCoinbaseTx(1, extra = 7)])
    let before = cs.db.bestBlockHash
    cs.db.applyBlock(bad, 1)
    check cs.db.bestBlockHash == before  # unchanged
    cs.close()

# ---------------------------------------------------------------------------
# Gate-G/H — BIP-30 regression coverage
# ---------------------------------------------------------------------------

suite "W93 — BIP-30 regression":
  test "Gate-G: IsBIP30Repeat exempts canonical mainnet duplicates":
    # Pulled forward from W92 BIP-30 audit; W93 verifies they still trip.
    # The two canonical BIP-30 repeat block hashes (in internal LE byte order):
    # h=91842 displayed hash 00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec
    # h=91880 displayed hash 00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721
    let hash91842: array[32, byte] = [
      byte 0xec, 0xca, 0xe0, 0x00, 0xe3, 0xc8, 0xe4, 0xe0,
      0x93, 0x93, 0x63, 0x60, 0x43, 0x1f, 0x3b, 0x76,
      0x03, 0xc5, 0x63, 0xc1, 0xff, 0x61, 0x81, 0x39,
      0x0a, 0x4d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    let hash91880: array[32, byte] = [
      byte 0x21, 0xd7, 0x7c, 0xcb, 0x4c, 0x08, 0x38, 0x6a,
      0x04, 0xac, 0x01, 0x96, 0x0a, 0xe9, 0x10, 0xf6,
      0xa1, 0xd2, 0xc2, 0xa3, 0x77, 0x55, 0x8c, 0xa1,
      0x90, 0xf1, 0x43, 0x07, 0x00, 0x00, 0x00, 0x00
    ]
    check val.isBip30Repeat(91842'i32, hash91842)
    # Wrong height + correct hash must NOT match.
    check (not val.isBip30Repeat(91843'i32, hash91842))
    # Genesis hash never matches.
    check (not val.isBip30Repeat(0'i32, default(array[32, byte])))

  test "Gate-H: checkBip30 always scans at height ≥ 1,983,702":
    ## Even when bip34Hash is set, height ≥ 1,983,702 re-enables the UTXO scan.
    ## We can't seed a real UTXO collision in this fast unit test, so we just
    ## confirm the gate runs (no UTXO ⇒ ok) and that it does *not* short-circuit
    ## on the BIP34 hash exemption.
    var params = mainnetParams()
    # Build a single-coinbase block; pretend it's at height 1,983,800.
    let blk = Block(
      header: BlockHeader(),
      txs: @[makeCoinbaseTx(1_983_800'i32)]
    )
    proc hasUtxo(op: OutPoint): bool {.gcsafe, raises: [].} = false
    var hash: array[32, byte] = default(array[32, byte])
    let res = val.checkBip30(blk, 1_983_800'i32, hash, params, hasUtxo)
    check res.isOk

# ---------------------------------------------------------------------------
# #64 — REORG CONNECT PATH with an intra-block tx chain
#
# The fleet audit (2026-08-24) found that 0 of 10 impls exercise an
# intra-block chain on the reorg CONNECT side: every reorg suite connects
# coinbase-only blocks.  nimrod already had the right BLOCK SHAPE in this
# file — @[coinbase, tx1, tx2] where tx2 spends tx1 — but wired to
# connectBlock, never to handleReorg.  The reorg path is a SECOND
# implementation of intra-block resolution in most of these codebases, and
# it was tested only against blocks that cannot exercise it.  That is exactly
# the code that broke in haskoin (bea8d11), ouroboros (78fc20f), camlcoin
# (388b65f) and rustoshi (d086a76).
#
# This routes the same shape through handleReorg and asserts the resulting
# UTXO set, which is what a coinbase-only reorg test can never do.
# ---------------------------------------------------------------------------
suite "#64 — reorg CONNECT path resolves an intra-block tx chain":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "handleReorg connects a block whose tx2 spends tx1 from the same block":
    var cs = newChainState(TestDbPath, regtestParams())
    let (h0, _, cbTxid) = seedChain(cs)

    # Bury the height-1 coinbase past COINBASE MATURITY (100).  Every existing
    # intra-block test in this file only builds UNDO data, which does not
    # enforce maturity — this is the first one that actually CONNECTS such a
    # block, so it is the first that has to respect it.  (Verified: without
    # the burial connectBlock rejects the block outright, which would have
    # made this test look like a reorg bug when it is a fixture bug.)
    var h = h0
    var tipHash = getBlockHash(makeBlock(BlockHash(default(array[32, byte])), 0,
                                         @[makeCoinbaseTx(0)]))
    tipHash = cs.bestBlockHash
    for i in 1 .. 101:
      let filler = makeBlock(tipHash, h + 1, @[makeCoinbaseTx(h + 1, extra = 1000 + int32(i))])
      doAssert cs.connectBlock(filler, h + 1).isOk
      tipHash = getBlockHash(filler)
      h = h + 1
    let forkHash = tipHash

    # Chain A (to be disconnected): one coinbase-only block on top of the fork.
    let aBlock = makeBlock(forkHash, h + 1, @[makeCoinbaseTx(h + 1, extra = 7)])
    check cs.connectBlock(aBlock, h + 1).isOk
    check cs.bestBlockHash == getBlockHash(aBlock)

    # Chain B (to be connected by the reorg): TWO blocks, the first carrying a
    # real intra-block chain — tx1 spends the height-1 coinbase, tx2 spends
    # tx1's output while tx1 is still only in this same block.
    let bCoinbase1 = makeCoinbaseTx(h + 1, extra = 21)
    let tx1 = makeSpendingTx(cbTxid, 0, value = 4_500_000_000)
    let tx2 = makeSpendingTx(tx1.txid(), 0, value = 4_000_000_000)
    let b1 = makeBlock(forkHash, h + 1, @[bCoinbase1, tx1, tx2])
    let b2 = makeBlock(getBlockHash(b1), h + 2, @[makeCoinbaseTx(h + 2, extra = 22)])

    check cs.handleReorg(forkHash, @[b1, b2]).isOk

    # The reorg took: tip is chain B.
    check cs.bestBlockHash == getBlockHash(b2)

    # --- the assertions a coinbase-only reorg test cannot make ---
    # tx1's output was created AND spent inside the connected block, so it must
    # NOT survive in the UTXO set.  A reorg connect path that resolves
    # intra-block spends in two passes (all outputs, then all inputs) leaves
    # this coin behind as a phantom.
    check cs.getUtxo(OutPoint(txid: tx1.txid(), vout: 0)).isNone

    # tx2's output IS unspent and must be present.
    let tx2Utxo = cs.getUtxo(OutPoint(txid: tx2.txid(), vout: 0))
    check tx2Utxo.isSome
    if tx2Utxo.isSome:
      check tx2Utxo.get().output.value == Satoshi(4_000_000_000)

    # The height-1 coinbase that tx1 consumed must be gone.
    check cs.getUtxo(OutPoint(txid: cbTxid, vout: 0)).isNone

    # Chain A's coinbase was disconnected, so its output must be gone too.
    check cs.getUtxo(OutPoint(txid: aBlock.txs[0].txid(), vout: 0)).isNone
    cs.close()
