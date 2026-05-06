## Orphan tx pool tests
##
## Covers the standalone orphan pool (`src/mempool/orphan.nim`):
##   1. addOrphan respects MaxOrphanTransactions cap
##   2. addOrphan respects MaxOrphanTxSize cap (per-tx)
##   3. addOrphan respects MaxOrphansPerPeer cap (per-peer)
##   4. takeChildrenOf returns orphans whose inputs reference a parent txid
##   5. removeForBlock evicts orphans included or invalidated by a block
##   6. removeForPeer drops every orphan announced by a given peer
##   7. expireOld drops orphans older than the expire window
##
## These tests use synthetic transactions (no chainstate, no signatures);
## the orphan pool is a pure in-memory data structure.

import unittest2
import std/[os]
import ../src/mempool/orphan
import ../src/primitives/[types, serialize]

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

proc makeTxId(seed: byte): TxId =
  ## Deterministic TxId for testing.  Uses the seed byte across all 32 bytes
  ## so the resulting hashes don't collide for distinct seeds.
  var arr: array[32, byte]
  for i in 0 ..< 32:
    arr[i] = seed
  TxId(arr)

proc makeTx(seed: byte, parentTxids: seq[TxId] = @[],
            extraOutputBytes: int = 0): Transaction =
  ## Build a synthetic Transaction whose txid is deterministic in `seed`
  ## (modulo the BTC double-sha256 — the actual txid is computed by
  ## serializing).  Each input references one of `parentTxids` (or a
  ## made-up parent if none given).  `extraOutputBytes` lets us blow up
  ## the serialized size to test the per-tx size cap.
  var inputs: seq[TxIn]
  if parentTxids.len == 0:
    inputs = @[TxIn(
      prevOut: OutPoint(txid: makeTxId(0xAA'u8 xor seed), vout: 0),
      scriptSig: @[byte(seed)],
      sequence: 0xFFFFFFFF'u32
    )]
  else:
    for parent in parentTxids:
      inputs.add(TxIn(
        prevOut: OutPoint(txid: parent, vout: 0),
        scriptSig: @[byte(seed)],
        sequence: 0xFFFFFFFF'u32
      ))
  var script: seq[byte] = @[byte(0x6a)]  # OP_RETURN
  if extraOutputBytes > 0:
    # Pad with zero bytes to force the serialized tx to exceed a chosen
    # threshold — the per-tx size cap test relies on this knob.
    var padding = newSeq[byte](extraOutputBytes)
    script.add(padding)
  Transaction(
    version: 1,
    inputs: inputs,
    outputs: @[TxOut(
      value: Satoshi(0),
      scriptPubKey: script
    )],
    witnesses: @[],
    lockTime: 0
  )

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

suite "OrphanPool — basic admit / lookup":

  test "empty pool reports zero":
    let pool = newOrphanPool()
    check pool.count == 0

  test "addOrphan accepts a small tx and reports it":
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let tx = makeTx(0x01'u8)
    check pool.addOrphan(tx, peer) == true
    check pool.count == 1
    check pool.contains(tx.txid()) == true
    check pool.countForPeer(peer) == 1

  test "addOrphan dedupes (already present)":
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let tx = makeTx(0x02'u8)
    check pool.addOrphan(tx, peer) == true
    # Second add with the same txid is a no-op.
    check pool.addOrphan(tx, peer) == false
    check pool.count == 1

suite "OrphanPool — bounds":

  test "MaxOrphanTransactions cap evicts oldest on overflow":
    # Tiny pool to make the cap easy to hit; test directly verifies that
    # entry #(N+1) evicts the oldest entry.
    let pool = newOrphanPool(maxOrphans = 3, maxPerPeer = 100,
                             maxTxSize = MaxOrphanTxSize)
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let tx1 = makeTx(0x10'u8)
    let tx2 = makeTx(0x11'u8)
    let tx3 = makeTx(0x12'u8)
    let tx4 = makeTx(0x13'u8)
    check pool.addOrphan(tx1, peer) == true
    # Force a real wallclock gap so addedAt timestamps differ enough
    # that "oldest" is unambiguous on coarse-grained CI clocks.
    sleep(2)
    check pool.addOrphan(tx2, peer) == true
    sleep(2)
    check pool.addOrphan(tx3, peer) == true
    sleep(2)
    check pool.count == 3
    # Pool is full.  Adding a 4th must evict the oldest (tx1).
    check pool.addOrphan(tx4, peer) == true
    check pool.count == 3
    check pool.contains(tx1.txid()) == false   # evicted
    check pool.contains(tx4.txid()) == true    # admitted

  test "MaxOrphanTxSize cap rejects oversized tx":
    # Build a tx whose serialized size comfortably exceeds 1 KB so we can
    # set maxTxSize = 512 and prove the gate fires.
    let pool = newOrphanPool(maxOrphans = 100, maxPerPeer = 100,
                             maxTxSize = 512)
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let big = makeTx(0x20'u8, extraOutputBytes = 2048)
    check pool.addOrphan(big, peer) == false
    check pool.count == 0
    # And a small tx still fits.
    let small = makeTx(0x21'u8)
    check pool.addOrphan(small, peer) == true
    check pool.count == 1

  test "MaxOrphansPerPeer cap evicts that peer's oldest":
    # Per-peer cap = 2.  Peer A fills 2 slots, then announces a 3rd:
    # peer A's oldest must be evicted (not peer B's).
    let pool = newOrphanPool(maxOrphans = 100, maxPerPeer = 2,
                             maxTxSize = MaxOrphanTxSize)
    let peerA: OrphanPeerId = ("10.0.0.1", 8333'u16)
    let peerB: OrphanPeerId = ("10.0.0.2", 8333'u16)
    let txB = makeTx(0x30'u8)
    let txA1 = makeTx(0x31'u8)
    let txA2 = makeTx(0x32'u8)
    let txA3 = makeTx(0x33'u8)
    check pool.addOrphan(txB, peerB) == true
    sleep(2)
    check pool.addOrphan(txA1, peerA) == true
    sleep(2)
    check pool.addOrphan(txA2, peerA) == true
    sleep(2)
    check pool.countForPeer(peerA) == 2
    check pool.countForPeer(peerB) == 1
    # Peer A is at its cap; the 3rd add must evict A's oldest (txA1) and
    # MUST NOT touch peer B's entry.
    check pool.addOrphan(txA3, peerA) == true
    check pool.countForPeer(peerA) == 2
    check pool.countForPeer(peerB) == 1
    check pool.contains(txA1.txid()) == false   # peer A's oldest evicted
    check pool.contains(txA2.txid()) == true
    check pool.contains(txA3.txid()) == true
    check pool.contains(txB.txid()) == true     # peer B untouched

suite "OrphanPool — resolution":

  test "takeChildrenOf returns and removes orphans of a parent":
    # Two children spend outputs of the same parent tx; takeChildrenOf
    # must return both and clear them from the pool.
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let parentTxid = makeTxId(0x40'u8)
    let child1 = makeTx(0x41'u8, parentTxids = @[parentTxid])
    let child2 = makeTx(0x42'u8, parentTxids = @[parentTxid])
    let unrelated = makeTx(0x43'u8)  # different parent, not affected
    check pool.addOrphan(child1, peer) == true
    check pool.addOrphan(child2, peer) == true
    check pool.addOrphan(unrelated, peer) == true
    check pool.count == 3
    let popped = pool.takeChildrenOf(parentTxid)
    check popped.len == 2
    # Both children must be gone, unrelated must remain.
    check pool.contains(child1.txid()) == false
    check pool.contains(child2.txid()) == false
    check pool.contains(unrelated.txid()) == true
    check pool.count == 1

  test "takeChildrenOf returns empty when no children":
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    let tx = makeTx(0x50'u8)
    check pool.addOrphan(tx, peer) == true
    let popped = pool.takeChildrenOf(makeTxId(0xFF'u8))
    check popped.len == 0
    check pool.count == 1   # unrelated entry untouched

suite "OrphanPool — block / peer / expiry housekeeping":

  test "removeForBlock drops confirmed and conflicting orphans":
    # Build:
    #   - parentA has one output, spent by orphanChild
    #   - orphanConflict double-spends the same outpoint as orphanChild
    #     (from parentA, vout 0)
    #   - orphanConfirmed has the SAME txid as a tx in the new block
    #   - unrelatedOrphan has nothing to do with the block
    # After removeForBlock(blk where blk has [parentA, orphanConfirmed]):
    #   - orphanChild removed (parentA's output now spent)
    #   - orphanConflict removed (double-spend with confirmed parentA's
    #     coinbase-style spent input — see below)
    #   - orphanConfirmed removed (confirmed by txid)
    #   - unrelatedOrphan retained
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)

    # Tx that will appear in the block; its inputs will become "spent"
    # outpoints in the block.
    let blockTxA = makeTx(0x60'u8)
    let blockTxAId = blockTxA.txid()
    # Orphan that double-spends one of blockTxA's inputs.
    let orphanConflict = Transaction(
      version: 1,
      inputs: blockTxA.inputs,   # exact same prevOut → double-spend
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a)])],
      witnesses: @[],
      lockTime: 7
    )
    # Orphan that has the same txid as a block tx.  We can synthesize this
    # by re-using blockTxA itself (txid matches).  Add as orphan first.
    let orphanConfirmed = blockTxA
    # Unrelated orphan whose inputs don't appear in the block.
    let unrelated = makeTx(0x61'u8)

    check pool.addOrphan(orphanConflict, peer) == true
    check pool.addOrphan(unrelated, peer) == true
    check pool.count == 2
    # orphanConfirmed has the same txid as blockTxA — re-add via a peer.
    check pool.addOrphan(orphanConfirmed, peer) == true
    check pool.count == 3

    # Block contains blockTxA (and a coinbase, but coinbase prevOut is
    # the all-zero txid; if any orphan referenced that as a parent it
    # would be evicted too — we don't, so that's fine).
    let blk = Block(
      header: BlockHeader(),
      txs: @[blockTxA]
    )
    let removed = pool.removeForBlock(blk)
    check removed >= 2
    check pool.contains(orphanConflict.txid()) == false
    check pool.contains(blockTxAId) == false   # orphanConfirmed gone
    check pool.contains(unrelated.txid()) == true

  test "removeForPeer drops every orphan announced by a peer":
    let pool = newOrphanPool()
    let peerA: OrphanPeerId = ("10.0.0.1", 8333'u16)
    let peerB: OrphanPeerId = ("10.0.0.2", 8333'u16)
    check pool.addOrphan(makeTx(0x70'u8), peerA) == true
    check pool.addOrphan(makeTx(0x71'u8), peerA) == true
    check pool.addOrphan(makeTx(0x72'u8), peerB) == true
    check pool.count == 3
    let removed = pool.removeForPeer(peerA)
    check removed == 2
    check pool.count == 1
    check pool.countForPeer(peerA) == 0
    check pool.countForPeer(peerB) == 1

  test "expireOld drops orphans older than threshold":
    # We can't fast-forward wall-clock time inside the pool, so use a
    # very short expire window (-1 second drops everything).
    let pool = newOrphanPool()
    let peer: OrphanPeerId = ("1.2.3.4", 8333'u16)
    check pool.addOrphan(makeTx(0x80'u8), peer) == true
    check pool.addOrphan(makeTx(0x81'u8), peer) == true
    check pool.count == 2
    # `expireSeconds = -1` means "anything added at or before now+1s" →
    # all current entries.  Pass `-1` as the threshold and verify both
    # entries get reaped.  (A future-dated cutoff catches every entry
    # added before that future moment, i.e. every existing entry.)
    let dropped = pool.expireOld(expireSeconds = -1)
    check dropped == 2
    check pool.count == 0
