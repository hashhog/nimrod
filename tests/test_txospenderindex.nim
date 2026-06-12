## txospenderindex tests — spent-outpoint -> spending-tx index + the
## gettxspendingprevout RPC data path.
##
## Proves (per the AXIS-#3 design + the rustoshi reorg lesson):
##   1. CONNECT writes A:0 -> B (spendingtxid, blockhash, full tx).
##   2. The index is REORG-SAFE through nimrod's single unified chainstate
##      `disconnectHook` — the SAME hook coinstatsindex / blockfilterindex use —
##      which fires per disconnected block on BOTH:
##        (a) the LIVE reorg path (handleReorg, heavier branch orphans B), AND
##        (b) the invalidateblock path (disconnectBlock).
##      On disconnect the keys are RE-DERIVED from the disconnected block's OWN
##      inputs and ERASED (Core CustomRemove(BuildSpenderPositions)).
##   3. After a live reorg whose new branch spends the SAME outpoint A:0 with a
##      DIFFERENT tx B2, the index resolves A:0 -> B2 (disconnect-BEFORE-connect).
##   4. Falsification: a fresh / disabled index does NOT answer.
##
## The hook installed here is a byte-for-byte copy of the production wiring in
## src/nimrod.nim (the txospender clause of state.chainState.disconnectHook), so
## this exercises the real reorg fan-out, not a test stub.

import unittest2
import std/[os, options]
import ../src/storage/[db, chainstate]
import ../src/storage/indexes/txospenderindex
import ../src/storage/undo as chainundo
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/consensus/chain  # invalidateBlock

const TestDbPath = "/tmp/nimrod_txospender_test"

proc cleanup() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Minimal block / tx builders (mirror tests/test_chainstate.nim helpers).
# ---------------------------------------------------------------------------

proc mkCoinbase(tag: byte): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x01), tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc mkSpend(prevTxid: TxId, prevVout: uint32, outTag: byte): Transaction =
  ## A non-coinbase tx spending (prevTxid:prevVout). outTag distinguishes the
  ## txid of two different spenders of the same outpoint.
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(4_999_000_000),
                     scriptPubKey: @[byte(0x00), 0x14, outTag])],
    witnesses: @[],
    lockTime: 0)

proc mkBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1, prevBlock: prevHash, merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505'u32 + uint32(height * 600),
      bits: 0x207fffff'u32, nonce: uint32(height)),
    txs: txs)

proc blkHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

# ---------------------------------------------------------------------------
# Production-equivalent disconnect hook (copied from src/nimrod.nim's
# txospender clause). Installed on a real ChainState so handleReorg /
# invalidateBlock / disconnectBlock all drive the index erase through it.
# ---------------------------------------------------------------------------

proc installTxoHook(cs: var ChainState, idx: TxoSpenderIndex) =
  let txoIdx = idx
  let csForHook = cs
  cs.disconnectHook = proc(blockHash: BlockHash, prevHash: BlockHash,
                           height: int32) {.raises: [].} =
    if txoIdx != nil:
      try:
        let blkOpt = csForHook.db.getBlock(blockHash)
        if blkOpt.isSome:
          discard txoIdx.removeBlock(blkOpt.get(), blockHash, prevHash, height)
      except CatchableError:
        discard
      except Exception:
        discard


suite "txospenderindex — index logic":
  setup:
    cleanup()
  teardown:
    cleanup()

  test "connect records A:0 -> B; disabled/fresh index does NOT answer (falsification)":
    let database = openDatabase(TestDbPath)
    defer: database.close()

    # Falsification arm: a DISABLED index must never answer.
    let off = newTxoSpenderIndex(database, enabled = false)
    var arb: array[32, byte]
    arb[0] = 7'u8
    let txA0 = OutPoint(txid: TxId(arb), vout: 0)
    check off.findSpender(txA0).isNone

    let idx = newTxoSpenderIndex(database, enabled = true)
    # Fresh enabled index, nothing connected yet: must NOT answer.
    check idx.findSpender(txA0).isNone

    # Build A (coinbase at h1) and B (spends A:0 at h2).
    let g = BlockHash(default(array[32, byte]))
    let cbA = mkCoinbase(0xA1)
    let blk1 = mkBlock(g, 1, @[cbA])
    let h1 = blkHash(blk1)
    let txAid = cbA.txid()

    let cbB = mkCoinbase(0xB0)        # block 2 coinbase
    let txB = mkSpend(txAid, 0, 0xBB) # B spends A:0
    let blk2 = mkBlock(h1, 2, @[cbB, txB])
    let h2 = blkHash(blk2)

    check idx.addBlock(blk1, h1, 1, chainundo.BlockUndo()) == true
    check idx.addBlock(blk2, h2, 2, chainundo.BlockUndo()) == true

    # A:0 now resolves to B, confirmed in block h2, with the full tx.
    let rec = idx.findSpender(OutPoint(txid: txAid, vout: 0))
    check rec.isSome
    check rec.get().spendingTxid == txB.txid()
    check rec.get().blockHash == h2
    check deserializeTransaction(rec.get().spendingTx).txid() == txB.txid()

    # The coinbase null prevout is NEVER indexed.
    check idx.findSpender(OutPoint(txid: TxId(default(array[32, byte])),
                                   vout: 0xFFFFFFFF'u32)).isNone

  test "removeBlock erases A:0 and rolls best height back (CustomRemove parity)":
    let database = openDatabase(TestDbPath)
    defer: database.close()
    let idx = newTxoSpenderIndex(database, enabled = true)

    let g = BlockHash(default(array[32, byte]))
    let cbA = mkCoinbase(0xA1)
    let blk1 = mkBlock(g, 1, @[cbA]); let h1 = blkHash(blk1)
    let txAid = cbA.txid()
    let txB = mkSpend(txAid, 0, 0xBB)
    let blk2 = mkBlock(h1, 2, @[mkCoinbase(0xB0), txB]); let h2 = blkHash(blk2)

    check idx.addBlock(blk1, h1, 1, chainundo.BlockUndo()) == true
    check idx.addBlock(blk2, h2, 2, chainundo.BlockUndo()) == true
    check idx.bestHeight == 2
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isSome

    # Disconnect h2: re-derive keys from blk2's inputs and erase them.
    check idx.removeBlock(blk2, h2, blk2.header.prevBlock, 2) == true
    check idx.bestHeight == 1
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isNone


proc mkGenesis(): Block =
  ## Regtest genesis-shaped block at height 0 (coinbase only, OP_1 output).
  mkBlock(BlockHash(default(array[32, byte])), 0, @[mkCoinbase(0x00)])

suite "txospenderindex — reorg-safety through the real chainstate disconnectHook":
  setup:
    cleanup()
  teardown:
    cleanup()

  test "LIVE reorg (heavier branch via handleReorg) erases A:0 through the production hook":
    # End-to-end through the REAL chainstate + the production disconnectHook:
    #   - mine a coinbase at h1 and mature it (h2..h101 coinbase-only),
    #   - at h102 connect tx A spending the matured h1 coinbase,
    #   - at h103 connect tx B spending A:0  (A is non-coinbase -> no maturity),
    #   - index every connected block via addBlock (mirrors the daemon),
    #   - then a LIVE REORG: a heavier branch off h102 (no B) orphans h103,
    #     firing the production disconnectHook -> index ERASES A:0.
    var cs = newChainState(TestDbPath, regtestParams())
    let idx = newTxoSpenderIndex(cs.db.db, enabled = true)
    installTxoHook(cs, idx)
    defer: cs.close()

    let g = mkGenesis(); let gHash = blkHash(g)
    check cs.connectBlock(g, 0).isOk
    check idx.addBlock(g, gHash, 0, chainundo.BlockUndo()) == true

    # h1: the coinbase whose output A will spend.
    let cb1 = mkCoinbase(0xA1)
    let blk1 = mkBlock(gHash, 1, @[cb1]); let h1 = blkHash(blk1)
    check cs.connectBlock(blk1, 1).isOk
    check idx.addBlock(blk1, h1, 1, chainundo.BlockUndo()) == true
    let cb1id = cb1.txid()

    # h2..h101: mature cb1 (coinbaseMaturity = 100).
    var prev = h1
    for hgt in 2'i32 .. 101'i32:
      let blk = mkBlock(prev, hgt, @[mkCoinbase(byte(hgt and 0xff))])
      let hh = blkHash(blk)
      check cs.connectBlock(blk, hgt).isOk
      check idx.addBlock(blk, hh, hgt, chainundo.BlockUndo()) == true
      prev = hh
    let h101 = prev

    # h102: tx A spends the now-matured h1 coinbase (cb1:0).
    let txA = mkSpend(cb1id, 0, 0xAA)
    let blkA = mkBlock(h101, 102, @[mkCoinbase(0xD2), txA]); let hA = blkHash(blkA)
    check cs.connectBlock(blkA, 102).isOk
    check idx.addBlock(blkA, hA, 102, chainundo.BlockUndo()) == true
    let txAid = txA.txid()

    # h103: tx B spends A:0 (A is NON-coinbase -> no maturity gate).
    let txB = mkSpend(txAid, 0, 0xBB)
    let blkB = mkBlock(hA, 103, @[mkCoinbase(0xD3), txB]); let hB = blkHash(blkB)
    check cs.connectBlock(blkB, 103).isOk
    check idx.addBlock(blkB, hB, 103, chainundo.BlockUndo()) == true
    check cs.bestHeight == 103

    # A:0 resolves to B, confirmed in hB.
    let pre = idx.findSpender(OutPoint(txid: txAid, vout: 0))
    check pre.isSome
    check pre.get().spendingTxid == txB.txid()
    check pre.get().blockHash == hB

    # --- LIVE REORG: heavier branch off h102 (hA) that does NOT contain B.
    #     h103' -> h104' outweighs the single-block tip h103, so handleReorg
    #     DISCONNECTS h103 (firing the production disconnectHook -> erase A:0)
    #     BEFORE connecting the new branch. This is the live reorg path
    #     (handleReorg), NOT invalidateblock. ---
    let blk3p = mkBlock(hA, 103, @[mkCoinbase(0xE3)]); let h3p = blkHash(blk3p)
    let blk4p = mkBlock(h3p, 104, @[mkCoinbase(0xE4)])
    let reorgRes = cs.handleReorg(hA, @[blk3p, blk4p])
    check reorgRes.isOk
    check cs.bestHeight == 104

    # The production disconnectHook fired for the orphaned h103 body whose input
    # re-derives A:0 -> the index ERASED it. (rustoshi-lesson: live-reorg path.)
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isNone

  test "invalidateblock erases A:0 through the production hook":
    # Same chain shape; this time disconnect via invalidateBlock (the
    # disconnectBlock path), proving the SAME unified hook fires on the OTHER
    # disconnect path too.
    var cs = newChainState(TestDbPath, regtestParams())
    let idx = newTxoSpenderIndex(cs.db.db, enabled = true)
    installTxoHook(cs, idx)
    defer: cs.close()

    let g = mkGenesis(); let gHash = blkHash(g)
    check cs.connectBlock(g, 0).isOk
    discard idx.addBlock(g, gHash, 0, chainundo.BlockUndo())

    let cb1 = mkCoinbase(0xA1)
    let blk1 = mkBlock(gHash, 1, @[cb1]); let h1 = blkHash(blk1)
    check cs.connectBlock(blk1, 1).isOk
    discard idx.addBlock(blk1, h1, 1, chainundo.BlockUndo())
    let cb1id = cb1.txid()

    var prev = h1
    for hgt in 2'i32 .. 101'i32:
      let blk = mkBlock(prev, hgt, @[mkCoinbase(byte(hgt and 0xff))])
      let hh = blkHash(blk)
      check cs.connectBlock(blk, hgt).isOk
      discard idx.addBlock(blk, hh, hgt, chainundo.BlockUndo())
      prev = hh

    let txA = mkSpend(cb1id, 0, 0xAA)
    let blkA = mkBlock(prev, 102, @[mkCoinbase(0xD2), txA]); let hA = blkHash(blkA)
    check cs.connectBlock(blkA, 102).isOk
    discard idx.addBlock(blkA, hA, 102, chainundo.BlockUndo())
    let txAid = txA.txid()

    let txB = mkSpend(txAid, 0, 0xBB)
    let blkB = mkBlock(hA, 103, @[mkCoinbase(0xD3), txB]); let hB = blkHash(blkB)
    check cs.connectBlock(blkB, 103).isOk
    discard idx.addBlock(blkB, hB, 103, chainundo.BlockUndo())
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isSome

    # invalidateblock(hB): disconnects h103 (disconnectBlock -> production hook).
    let invRes = cs.invalidateBlock(hB)
    check invRes.isOk
    check cs.bestHeight == 102
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isNone

  test "live reorg re-spends the SAME outpoint with a different tx (disconnect-before-connect)":
    # The strongest reorg-safety case: branch X spends A:0 with B; the heavier
    # branch Y spends the SAME A:0 with a DIFFERENT tx B2. After the reorg the
    # index must resolve A:0 -> B2 (not the orphaned B). Driven purely through
    # the index connect/disconnect calls in handleReorg tip->fork order.
    let database = openDatabase(TestDbPath)
    defer: database.close()
    let idx = newTxoSpenderIndex(database, enabled = true)

    let g = BlockHash(default(array[32, byte]))
    let cbA = mkCoinbase(0xA1)
    let blkA = mkBlock(g, 1, @[cbA]); let hA = blkHash(blkA)
    let txAid = cbA.txid()
    check idx.addBlock(blkA, hA, 1, chainundo.BlockUndo()) == true

    # Branch X tip: B spends A:0.
    let txB = mkSpend(txAid, 0, 0xB1)
    let blkB = mkBlock(hA, 2, @[mkCoinbase(0xB0), txB]); let hB = blkHash(blkB)
    check idx.addBlock(blkB, hB, 2, chainundo.BlockUndo()) == true
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).get().spendingTxid == txB.txid()

    # Reorg: disconnect X tip (tip->fork order), then connect heavier branch Y
    # whose tip B2 spends the SAME A:0.
    check idx.removeBlock(blkB, hB, hA, 2) == true        # disconnect BEFORE connect
    check idx.findSpender(OutPoint(txid: txAid, vout: 0)).isNone  # erased

    let txB2 = mkSpend(txAid, 0, 0xB2)                    # different spender of A:0
    let blkB2 = mkBlock(hA, 2, @[mkCoinbase(0xC0), txB2]); let hB2 = blkHash(blkB2)
    let blkY3 = mkBlock(hB2, 3, @[mkCoinbase(0xC3)]); let hY3 = blkHash(blkY3)
    check idx.addBlock(blkB2, hB2, 2, chainundo.BlockUndo()) == true
    check idx.addBlock(blkY3, hY3, 3, chainundo.BlockUndo()) == true

    let rec = idx.findSpender(OutPoint(txid: txAid, vout: 0))
    check rec.isSome
    check rec.get().spendingTxid == txB2.txid()  # the NEW branch's spender
    check rec.get().spendingTxid != txB.txid()   # NOT the orphaned one
    check rec.get().blockHash == hB2
