## W164 — IBD applyBlock must validate difficulty against the REAL parent
## header (the "bad-diffbits" mainnet block 950147 incident).
##
## Incident (mainnet, 2026-05-20): after the W163 header-chain-reload fix
## (d665405) finally let nimrod's IBD reach the first block past its
## persisted tip (block 950147, parent 950146), block validation failed:
##
##   WRN block failed consensus checks (IBD applyBlock) height=950147
##       error="incorrect proof of work (bad-diffbits)"
##
## Block 950147 is a VALID mainnet block (bitcoin-core / beamchain /
## blockbrew / haskoin all accepted it). It is NOT a difficulty-retarget
## boundary, so per Core `pow.cpp::GetNextWorkRequired` its nBits MUST be
## byte-identical to its parent 950146's nBits — the non-retarget branch
## `return pindexLast->nBits` returns the parent's bits unchanged.
##
## Root cause — sync.nim `applyBlock` built the `prevIndex` it hands to
## `acceptBlock` as a SENTINEL carrying only {hash, height}; the `header`
## field was left zero-initialised. `acceptBlock -> validateBlock ->
## contextualCheckBlockHeader` (Gate 1, "bad-diffbits") computes the
## expected nBits via `getNextWorkRequired`, which for a non-retarget
## block returns `prevIndex.header.bits` — i.e. 0. So EVERY block's real
## nBits (e.g. 0x17020f79 for 950146/950147) was compared against 0 and
## rejected. Latent since the contextual difficulty check landed
## (c90f70c); only reachable once d665405 let IBD advance past the
## persisted tip — surfacing on the very first block applied.
##
## Fix — `applyBlock` now populates `prevIndex.header` from the in-memory
## header chain (which is synced ahead of block download AND reloaded from
## the block index on restart), falling back to the persisted block index.
##
## This suite exercises the real `applyBlock` path. It uses regtest-style
## params with `powAllowMinDifficultyBlocks=false` + `powNoRetargeting=false`
## so the non-retarget difficulty branch enforces `nBits == parent.nBits`
## exactly as on mainnet — while keeping the easy regtest `powLimit` so the
## blocks are mineable in a unit test.
##
## Bitcoin Core reference: pow.cpp::GetNextWorkRequired (non-retarget branch
## returns pindexLast->nBits) + validation.cpp::ContextualCheckBlockHeader
## (bad-diffbits gate compares block.nBits to GetNextWorkRequired).

import unittest2
import std/[options, os]
import ../src/network/sync
import ../src/consensus/[params, validation, chain]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Params: regtest difficulty (easy, mineable) but with MAINNET-style PoW
# rules so the non-retarget "bad-diffbits" equality check is live.
# ---------------------------------------------------------------------------
proc diffbitsParams(): ConsensusParams =
  result = regtestParams()
  # Mainnet semantics for the non-retarget branch of getNextWorkRequired:
  #   powAllowMinDifficultyBlocks=false -> the branch returns parent.bits
  #     (no min-difficulty walk-back), so contextualCheckBlockHeader Gate 1
  #     enforces `block.nBits == parent.nBits` exactly.
  #   powNoRetargeting=false -> calculateNextWorkRequired is not short-
  #     circuited (irrelevant for the non-retarget heights used here, but
  #     keeps the params honest).
  result.powAllowMinDifficultyBlocks = false
  result.powNoRetargeting = false

# ---------------------------------------------------------------------------
# Block construction at the easy regtest target (with REAL mined PoW, since
# applyBlock -> checkBlock verifies proof of work).
# ---------------------------------------------------------------------------

# Regtest powLimit target; compact 0x207fffff. A child that wants a nBits
# DIFFERENT from its parent but still trivially mineable uses EASY_BITS_ALT:
# 0x207ffffe is a slightly smaller mantissa -> still an astronomically large
# target (PoW passes for any nonce) but != 0x207fffff, so it isolates the
# "bad-diffbits" rejection from a PoW-fail rejection.
const EASY_BITS     = 0x207fffff'u32
const EASY_BITS_ALT = 0x207ffffe'u32

proc makeCoinbaseTx(height: int32): Transaction =
  ## Coinbase with canonical BIP-34 height encoding, padded to >= 2 bytes.
  let scriptSig = encodeBip34Height(height) & @[byte(0x00)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5_000_000_000'i64),
      scriptPubKey: @[byte(0x51)]   # OP_TRUE
    )],
    witnesses: @[],
    lockTime: 0
  )

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32,
               bits: uint32 = EASY_BITS): Block =
  ## Build a structurally-valid block and mine a nonce that satisfies `bits`.
  let coinbase = makeCoinbaseTx(height)
  var hdr = BlockHeader(
    version: 4,
    prevBlock: prevHash,
    merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
    timestamp: ts,
    bits: bits,
    nonce: 0
  )
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[coinbase])

# ---------------------------------------------------------------------------
# A populated ChainDb: the CANONICAL genesis + `count` mined blocks, all
# connected via connectBlock.  Returns the ChainState and the block list
# (index 0 = genesis).  Mirrors a real datadir at the moment of a clean
# shutdown — every block index row is flushed to RocksDB.
#
# The genesis MUST be the canonical block (buildGenesisBlock), not a freshly
# mined one: loadHeaderChainFromDb anchors the reload at params.genesisBlockHash
# and the height-1 header must link onto it.
# ---------------------------------------------------------------------------
proc buildDatadir(path: string, p: ConsensusParams,
                  count: int): tuple[cs: ChainState, blks: seq[Block]] =
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  let res0 = cs.connectBlock(genesis, 0'i32)
  doAssert res0.isOk, "buildDatadir connect genesis: " & $res0.error
  var blks: seq[Block] = @[genesis]
  var prevHash = p.genesisBlockHash
  var ts = 1_700_000_000'u32
  for h in 1'i32 .. int32(count):
    let blk = mineBlock(prevHash, h, ts)
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "buildDatadir connect h=" & $h & ": " & $res.error
    prevHash = hashOf(blk.header)
    blks.add(blk)
    ts += 600
  result = (cs, blks)

# ===========================================================================
suite "W164: applyBlock validates difficulty against the real parent header":

  test "non-retarget block with nBits == parent.nBits is ACCEPTED":
    ## THE 950147 bug. Pre-fix `applyBlock` passed a zeroed-header prevIndex,
    ## so getNextWorkRequired returned 0 and the block's real nBits != 0 was
    ## rejected "bad-diffbits". A valid non-retarget block MUST be accepted.
    let p = diffbitsParams()
    let path = "/tmp/nimrod_w164_accept"
    let (cs, blks) = buildDatadir(path, p, 5)   # genesis + blocks 1..5
    defer:
      var c = cs
      c.close()
      removeDir(path)

    # Drive applyBlock through a SyncManager whose header chain is synced
    # ahead of the block tip (the normal IBD invariant: headers first).
    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    check sm.chainTipHeight == 5

    # Block 6: non-retarget, same nBits as its parent (block 5). Mainnet
    # block 950147 relative to 950146 is exactly this shape.
    let tip = blks[5]
    let blk6 = mineBlock(hashOf(tip.header), 6, tip.header.timestamp + 600,
                         bits = EASY_BITS)   # == parent's bits

    # The header chain must know block 6 (processBlock places it before
    # applyBlock runs); seed it the way processHeaders would.
    check sm.processHeaders(@[blk6.header]) == 1
    check sm.headerChain.tipHeight == 6

    # Pre-fix: false with "bad-diffbits". Post-fix: accepted.
    check sm.applyBlock(blk6, 6)
    check sm.chainTipHeight == 6
    check sm.chainTip == hashOf(blk6.header)

  test "non-retarget block with WRONG nBits is REJECTED (bad-diffbits)":
    ## The fix must not over-correct: a genuinely wrong nBits on a
    ## non-retarget block must still be rejected. EASY_BITS_ALT is a valid
    ## (mineable) target so PoW passes — isolating the bad-diffbits gate.
    let p = diffbitsParams()
    let path = "/tmp/nimrod_w164_reject"
    let (cs, blks) = buildDatadir(path, p, 5)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let tip = blks[5]

    # Block 6 with nBits DIFFERENT from parent (parent uses EASY_BITS).
    let badBlk6 = mineBlock(hashOf(tip.header), 6, tip.header.timestamp + 600,
                            bits = EASY_BITS_ALT)   # != parent's bits
    check badBlk6.header.bits != tip.header.bits

    # W168: header admission now runs the bad-diffbits gate too (Core
    # validation.cpp:4088 inside AcceptBlockHeader), so this header no longer
    # even reaches the header chain.  Before W168 the header path skipped the
    # difficulty check entirely on regtest (`if params.network != Regtest`) and
    # this returned 1 — the body path was the only thing rejecting it.
    check sm.processHeaders(@[badBlk6.header]) == 0
    check sm.headerChain.tipHeight == 5

    # The BODY path must still reject it independently (defence in depth: the
    # W164 fix is about applyBlock's prevIndex, and that must keep working even
    # though the header never got in).  Chain tip must not advance.
    check (not sm.applyBlock(badBlk6, 6))
    check sm.chainTipHeight == 5
    check sm.chainTip == hashOf(tip.header)

  test "first block past a RELOADED header chain validates difficulty (exact 950147 scenario)":
    ## End-to-end reproduction: build a datadir, drop it, then bring up a
    ## fresh SyncManager (which calls loadHeaderChainFromDb to rebuild the
    ## header chain from the block index — the W163 reload). Then apply the
    ## first block past the reloaded tip. This is precisely what happened on
    ## mainnet: restart at persisted tip 950146, then apply 950147.
    let p = diffbitsParams()
    let path = "/tmp/nimrod_w164_reload"

    # Phase 1: build the datadir to height 8, capture the next-block inputs,
    # then close it (clean shutdown — block index fully flushed).
    var nextBlk: Block
    var reloadTipHash: BlockHash
    block:
      let (cs, blks) = buildDatadir(path, p, 8)
      let tip = blks[8]
      reloadTipHash = hashOf(tip.header)
      nextBlk = mineBlock(reloadTipHash, 9, tip.header.timestamp + 600,
                          bits = EASY_BITS)   # non-retarget: == parent's bits
      var c = cs
      c.close()

    # Phase 2: reopen the datadir cold. newSyncManager reloads the header
    # chain from the persisted block index (loadHeaderChainFromDb).
    var cs2 = newChainState(path, p)
    defer:
      var c = cs2
      c.close()
      removeDir(path)
    var cs2v = cs2
    let sm = newSyncManager(nil, cs2v.db, p, cs2v)

    # The reload restored the chain to its persisted tip (height 8) — and,
    # critically, every reloaded BlockIndex carries its real `header`.
    check sm.headerChain.tipHeight == 8
    check sm.headerChain.tip == reloadTipHash
    check sm.chainTipHeight == 8
    # The reloaded parent header has the REAL nBits (not zero) — the data
    # the difficulty check depends on survived the reload.
    check sm.headerChain.getHeaderByHeight(8).get().bits == EASY_BITS

    # Catch-up: header 9 arrives, then the block body is applied. Pre-fix
    # this is exactly where mainnet failed "bad-diffbits" on block 950147.
    check sm.processHeaders(@[nextBlk.header]) == 1
    check sm.applyBlock(nextBlk, 9)
    check sm.chainTipHeight == 9
    check sm.chainTip == hashOf(nextBlk.header)

  test "consecutive blocks apply with prev index still in the unflushed IBD batch":
    ## Regression guard for the chosen fix source. `connectBlockIBD` batches
    ## the parent's block-index row and only flushes to RocksDB every
    ## IbdBatchFlushInterval blocks — so a plain `getBlockIndex` on the
    ## just-connected parent would be STALE mid-IBD and re-introduce
    ## "bad-diffbits". The fix reads the parent header from the in-memory
    ## header chain, which is always current. Apply a run of blocks (with
    ## the header tip far enough ahead to select the IBD fast path) and
    ## confirm the difficulty check passes for every one.
    let p = diffbitsParams()
    let path = "/tmp/nimrod_w164_ibdbatch"
    let (cs, blks) = buildDatadir(path, p, 3)   # genesis + 1..3
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)

    # Pre-mine 30 non-retarget blocks (4..33), all nBits == parent's.
    var chain: seq[Block]
    var prevHdr = blks[3].header
    var ts = blks[3].header.timestamp
    for h in 4'i32 .. 33'i32:
      ts += 600
      let b = mineBlock(hashOf(prevHdr), h, ts, bits = EASY_BITS)
      chain.add(b)
      prevHdr = b.header

    # Sync ALL 30 headers first (header tip = 33). With blocksRemaining > 10
    # applyBlock selects connectBlockIBD, which batches the index rows.
    var headers: seq[BlockHeader]
    for b in chain: headers.add(b.header)
    check sm.processHeaders(headers) == 30
    check sm.headerChain.tipHeight == 33

    # Apply every block. For blocks whose parent's index row has not been
    # flushed yet, the difficulty check still passes because the parent
    # header is sourced from the (current) in-memory header chain.
    for i, b in chain:
      let h = int32(4 + i)
      check sm.applyBlock(b, h)
      check sm.chainTipHeight == h
    check sm.chainTipHeight == 33
    check sm.chainTip == hashOf(chain[^1].header)
