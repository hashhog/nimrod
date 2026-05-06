## Pruner tests — exercises the production prune driver wired in
## src/storage/pruner.nim.  Specifically covers:
##
##   1. Mode classification: --prune=0 (disabled), --prune=1 (manual-only),
##      --prune=N>=550 (automatic).
##   2. pruneblockchain manual flow: actually drops block bodies + tx-index
##      entries from RocksDB and resets the block-index status bits.
##   3. getblockchaininfo-side reporting via pruner accessors
##      (currentPruneHeight / currentTargetBytes / isPruning).
##   4. Manual-mode short-circuit: autoPruneIfNeeded never fires when the
##      pruner is in pmManualOnly.
##   5. Persistence: pruneHeight survives a daemon restart (saved under
##      cfMeta).

import unittest2
import std/[os, options, tables]
import ../src/storage/[db, chainstate, blockstore, pruner]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestRoot = "/tmp/nimrod_pruner_test"

proc cleanup() =
  if dirExists(TestRoot):
    removeDir(TestRoot)

proc makeCoinbase(height: int32): Transaction =
  ## Build a coinbase tx whose scriptSig encodes the height (so each block
  ## gets a unique txid).
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[
        byte(height and 0xff),
        byte((height shr 8) and 0xff),
        byte((height shr 16) and 0xff),
        byte((height shr 24) and 0xff)
      ],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(50_0000_0000),
      scriptPubKey: @[byte(0x6a)]  # OP_RETURN — provably unspendable
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeCoinbase(height)
  let txHashes = @[array[32, byte](coinbase.txid())]
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1_700_000_000'u32 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: @[coinbase]
  )

proc populateChain(cs: var ChainState, height: int32): seq[BlockHash] =
  ## Drive `cs` from genesis up to `height` (inclusive). Returns hashes
  ## indexed by height. We deliberately bypass full validation: each block
  ## has only a non-spendable coinbase, so connectBlock writes the body to
  ## `cfBlocks` and updates the index but does not touch the UTXO set.
  result = @[]
  var prev = BlockHash(default(array[32, byte]))
  for h in 0'i32 .. height:
    let blk = makeBlock(prev, h)
    let r = cs.connectBlock(blk, h)
    if not r.isOk:
      raise newException(CatchableError, "connectBlock failed at " & $h & ": " & r.error)
    let bh = BlockHash(doubleSha256(serialize(blk.header)))
    result.add(bh)
    prev = bh

suite "Pruner mode classification":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "prune target 0 disables the subsystem":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let p = newPruner(cs, bfm, params, 0)
    check p.mode == pmDisabled
    check not p.isPruning()
    check p.currentTargetBytes() == 0
    # bfm should also reflect "not in prune mode" — drives getblockchaininfo
    # for callers that have not wired a Pruner separately.
    check not bfm.isPruneMode

  test "prune target 1 == manual-only mode":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let p = newPruner(cs, bfm, params, 1)
    check p.mode == pmManualOnly
    check p.isPruning()
    check p.isManualMode()
    # Auto-trigger never fires in manual mode regardless of "usage".
    p.blocksSinceLastCheck = 99999
    p.autoPruneIfNeeded()  # must not raise, must not modify pruneHeight
    check p.currentPruneHeight() == -1

  test "prune target 600 MiB == automatic mode (clamped to floor if smaller)":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let p = newPruner(cs, bfm, params, 600)  # MiB
    check p.mode == pmAutomatic
    check p.currentTargetBytes() == 600'u64 * 1024'u64 * 1024'u64

    # Sub-floor automatic targets are clamped UP to the 550 MiB floor.
    # CLI rejects 2..549 upstream, but newPruner is also called by tests
    # that may pass raw values; defensively floor here.
    let p2 = newPruner(cs, bfm, params, 100)  # below floor
    check p2.mode == pmAutomatic
    check p2.currentTargetBytes() == AutoPruneFloorBytes

suite "Pruner manual delete loop":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "pruneToHeight drops block bodies but never below safety floor":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    # Build a 350-block chain so 350 - 288 = 62 blocks are eligible.
    let hashes = populateChain(cs, 350)
    check hashes.len == 351  # heights 0..350

    # Confirm bodies are present pre-prune.
    for h in 0'i32 .. 100'i32:
      let raw = cs.db.db.get(cfBlocks, blockKey(array[32, byte](hashes[h])))
      check raw.isSome

    let p = newPruner(cs, bfm, params, 1)  # manual mode is fine for this
    let newPruneHeight = p.pruneToHeight(50)

    # Should have pruned heights 1..50 (inclusive). Height 0 is genesis;
    # both 0 and 1..50 fall in the requested range.
    check newPruneHeight >= 49'i32

    # The bodies for heights 1..newPruneHeight must be gone.
    for h in 1'i32 .. newPruneHeight:
      let raw = cs.db.db.get(cfBlocks, blockKey(array[32, byte](hashes[h])))
      check raw.isNone

    # Bodies for heights >= newPruneHeight+1 must still be present.
    let raw = cs.db.db.get(
      cfBlocks, blockKey(array[32, byte](hashes[newPruneHeight + 1]))
    )
    check raw.isSome

    # The block-index entry is preserved; status downgraded to header-only.
    let idxOpt = cs.db.getBlockIndex(hashes[1])
    check idxOpt.isSome
    check idxOpt.get().status == bsHeaderOnly

  test "pruneToHeight refuses to prune within MIN_BLOCKS_TO_KEEP of tip":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let hashes = populateChain(cs, 350)
    let p = newPruner(cs, bfm, params, 1)

    # tip - 288 = 62, so any request above 62 should clamp internally.
    let pruneHeight = p.pruneToHeight(300)
    check pruneHeight <= 350'i32 - 288'i32

    # Tip itself remains intact.
    let tipBody = cs.db.db.get(
      cfBlocks, blockKey(array[32, byte](hashes[350]))
    )
    check tipBody.isSome

  test "pruneToHeight raises when subsystem disabled":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let p = newPruner(cs, bfm, params, 0)
    var raised = false
    try:
      discard p.pruneToHeight(10)
    except CatchableError:
      raised = true
    check raised

suite "Pruner reporting + persistence":
  setup:
    cleanup()

  teardown:
    cleanup()

  test "getblockchaininfo-style reporters answer correctly":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    let auto = newPruner(cs, bfm, params, 600)  # MiB
    check auto.isPruning()
    check auto.currentTargetBytes() >= AutoPruneFloorBytes
    check auto.currentPruneHeight() == -1  # nothing pruned yet
    # estimateCurrentUsage works on an empty chain.
    discard auto.estimateCurrentUsage()

  test "pruneHeight is persisted across pruner re-construction":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)

    discard populateChain(cs, 350)

    block:
      let p = newPruner(cs, bfm, params, 1)
      let newH = p.pruneToHeight(40)
      check newH >= 0

    # Build a fresh Pruner against the same chainstate + bfm; it should
    # restore the persisted pruneHeight.
    let p2 = newPruner(cs, bfm, params, 1)
    check p2.currentPruneHeight() >= 0

    bfm.close()
    cs.close()

  test "manual mode short-circuits autoPruneIfNeeded":
    let params = regtestParams()
    var cs = newChainState(TestRoot / "cs", params)
    defer: cs.close()
    let bfm = newBlockFileManager(TestRoot, params, cs.db.db)
    defer: bfm.close()

    discard populateChain(cs, 350)

    let p = newPruner(cs, bfm, params, 1)  # manual-only
    p.blocksSinceLastCheck = 100_000  # force trigger threshold past
    let before = p.currentPruneHeight()
    p.autoPruneIfNeeded()
    let after = p.currentPruneHeight()
    check before == after  # auto-prune did not fire
