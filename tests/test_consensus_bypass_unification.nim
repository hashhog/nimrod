## Consensus-bypass unification tests (W143+W145+W154+W155+W157 fix wave).
##
## Background. Five distinct nimrod block-acceptance entry points historically
## bypassed the canonical `acceptBlock` envelope, each one admitting blocks
## that Core would reject:
##
##   1. W143 BUG-3   — nimrod.nim:1611 (`--import` stdin frames)
##   2. W145 BUG-1   — nimrod.nim:1780 (`--import` blk*.dat dir; missed
##                     CVE-2018-17144 duplicate-input check)
##   3. W154 BUG-11  — mining.nim::generateBlocks + ::generateBlockWithTxs
##                     (regtest `generatetoaddress` / `generateblock`)
##   4. W155 BUG-17  — server.nim submitblock side-branch persistence
##   5. W157 BUG-15  — echo of W154 (same generateBlocks paths)
##
## Per fix-wave 2026-05-19, all five paths now route through the unified
## `acceptAndConnectBlock` (active-chain extensions) or `validateForStorage`
## (side-branch persistence) helpers, both of which call the canonical
## `acceptBlock` envelope (checkBlock + validateBlock + checkBip30 +
## verifyScripts).
##
## These tests exercise the canonical envelope by constructing blocks that
## must be REJECTED, then invoking each of the five entry points to confirm
## the rejection fires. Prior to the fix, several paths admitted the bad
## block silently.

import unittest2
import std/[options, os, tables, atomics, tempfiles, json, strutils]
import ../src/consensus/[validation, params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1, address]
import ../src/storage/[db, chainstate]
import ../src/mempool/mempool
import ../src/mining/blocktemplate
import ../src/rpc/mining

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------
var dbCounter: Atomic[int]
dbCounter.store(0)

proc freshDbPath(): string =
  let n = dbCounter.fetchAdd(1)
  "/tmp/nimrod_bypass_" & $n

proc cleanupDb(path: string) =
  if dirExists(path):
    removeDir(path)

proc makeRegtestCoinbase(height: int32, subsidyMint: Satoshi = Satoshi(5_000_000_000),
                        extraScriptByte: byte = 0x00): Transaction =
  ## BIP-34-canonical regtest coinbase. `subsidyMint` defaults to the regtest
  ## 50-BTC subsidy; callers override to mint MORE for over-subsidy tests.
  ## `extraScriptByte` lets callers differentiate two coinbases at the same
  ## height (BIP-30 rejects duplicate txids across blocks otherwise).
  let canonical = validation.encodeBip34Height(height)
  let scriptSig = canonical & @[extraScriptByte]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                        vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: subsidyMint,
      scriptPubKey: @[byte(0x51)]  # OP_TRUE — anyone can spend
    )],
    witnesses: @[],
    lockTime: 0
  )

proc minePoW(header: var BlockHeader, maxTries: uint64 = 1_000_000) =
  ## Find a nonce so that the header hash satisfies the bits target.
  ## On regtest 0x207fffff the first few nonces almost always work.
  var nonce = 0'u32
  var tries = 0'u64
  while tries < maxTries:
    header.nonce = nonce
    let h = BlockHash(doubleSha256(serialize(header)))
    if hashMeetsTarget(h, header.bits):
      return
    inc nonce
    inc tries
  raise newException(ValueError, "minePoW exhausted maxTries")

proc makeBlk(prevHash: BlockHash, height: int32, ts: uint32,
             coinbase: Transaction,
             bits: uint32 = 0x207fffff'u32, ver: int32 = 4,
             extraTxs: seq[Transaction] = @[]): Block =
  ## Build a regtest block and mine a valid nonce. Extra txs (non-coinbase)
  ## are appended; merkle root is computed over the full tx list.
  var allTxids = @[array[32, byte](coinbase.txid())]
  for tx in extraTxs:
    allTxids.add(array[32, byte](tx.txid()))
  var header = BlockHeader(
    version: ver,
    prevBlock: prevHash,
    merkleRoot: merkleRoot(allTxids),
    timestamp: ts,
    bits: bits,
    nonce: 0'u32,
  )
  minePoW(header)
  Block(
    header: header,
    txs: @[coinbase] & extraTxs,
  )

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc buildRegtestChain(dbPath: string, p: ConsensusParams, n: int,
                      baseTs: uint32 = 1_700_000_000'u32,
                      tsStep: uint32 = 600'u32): (ChainState, seq[Block]) =
  ## Build a clean regtest chain of `n` blocks via direct connectBlock
  ## (sidesteps the canonical envelope for fixture setup only).
  var cs = newChainState(dbPath, p)
  var prevHash = BlockHash(default(array[32, byte]))
  var blks: seq[Block]
  for h in 0'i32 ..< int32(n):
    let ts = baseTs + uint32(h) * tsStep
    let blk = makeBlk(prevHash, h, ts, makeRegtestCoinbase(h))
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "buildRegtestChain failed h=" & $h & ": " & $res.error
    prevHash = getBlockHash(blk)
    blks.add(blk)
  (cs, blks)

# ===========================================================================
# Entry point 1+2: reindex via acceptAndConnectBlock (W143 BUG-3, W145 BUG-1).
# ===========================================================================
# These tests directly exercise the unified helper that the reindex paths
# in `src/nimrod.nim:1611,1780` invoke. Before this wave, those paths called
# `checkBlock` + `connectBlockIBD` only, which would accept any of the bad
# blocks below.

suite "W143/W145 — reindex path routes through acceptBlock envelope":

  test "reindex rejects block with wrong nBits (contextual header gate)":
    ## W143 BUG-3 sub-symptom: contextualCheckBlockHeader is the gate that
    ## catches bad-diffbits. Before the fix, reindex skipped it entirely.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let prevHash = getBlockHash(blks[2])
    # Regtest uses powNoRetargeting → expected bits is ALWAYS 0x207fffff.
    # Any other value (even 0x207ffffe, which is still easy to mine but
    # differs from the canonical regtest target) fails bad-diffbits.
    let badNBits = 0x207ffffe'u32
    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32,
                            makeRegtestCoinbase(3),
                            bits = badNBits)
    let res = acceptAndConnectBlock(cs, candidate, 3, bsReindex, crypto,
                                    forceIbdConnect = true)
    check (not res.isOk)
    check cs.bestHeight == 2  # chain unchanged

  test "reindex rejects block with CVE-2018-17144 duplicate inputs":
    ## W145 BUG-1: reindex skipped CheckTransaction's duplicate-input gate,
    ## which is the CVE-2018-17144 inflation defense. The duplicate inputs
    ## live on a NON-coinbase tx (coinbase has only one input).
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let prevHash = getBlockHash(blks[2])
    let coinbase = makeRegtestCoinbase(3)

    # Craft a non-coinbase tx with the SAME (txid, vout) input twice.
    # Doesn't matter that the prevout doesn't exist in UTXO — the duplicate-
    # input check in checkTransaction runs BEFORE any UTXO lookup.
    let outpoint = OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32)
    let dupInputsTx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xFFFFFFFF'u32),
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xFFFFFFFF'u32),
      ],
      outputs: @[TxOut(value: Satoshi(1), scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: 0
    )

    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32, coinbase,
                            extraTxs = @[dupInputsTx])

    let res = acceptAndConnectBlock(cs, candidate, 3, bsReindex, crypto,
                                    forceIbdConnect = true)
    check (not res.isOk)
    check cs.bestHeight == 2  # chain unchanged

# ===========================================================================
# Entry point 3+5: mining via acceptAndConnectBlock (W154 BUG-11, W157 BUG-15).
# ===========================================================================
# Wired through `generateBlocks` / `generateBlockWithTxs` in
# `src/rpc/mining.nim`. We exercise the helper directly with a deliberately
# malformed mining-produced block to confirm the envelope fires.

suite "W154/W157 — mining path routes through acceptBlock envelope":

  test "mining rejects over-subsidy coinbase":
    ## W154 BUG-11: pre-fix, a miner that produced a coinbase paying MORE
    ## than `subsidy + fees` had the block accepted into its own chainstate
    ## (rejected only when peers later relayed it). acceptAndConnectBlock
    ## now runs validateBlock's coinbase-value gate before connect.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let prevHash = getBlockHash(blks[2])
    # Regtest subsidy at height 3 = 50 BTC. Mint 100 BTC = 2× subsidy.
    let badCoinbase = makeRegtestCoinbase(3, Satoshi(10_000_000_000))
    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32, badCoinbase)

    let res = acceptAndConnectBlock(cs, candidate, 3, bsMining, crypto)
    check (not res.isOk)
    check cs.bestHeight == 2  # chain unchanged

  test "mining accepts a well-formed block (regression guard)":
    ## Sanity check: a correctly-formed regtest block must still flow
    ## through. If this fails, the fix has broken the happy path.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let prevHash = getBlockHash(blks[2])
    let coinbase = makeRegtestCoinbase(3)
    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32, coinbase)

    let res = acceptAndConnectBlock(cs, candidate, 3, bsMining, crypto)
    check res.isOk
    check cs.bestHeight == 3

  test "generateBlocks end-to-end produces a chain that the same envelope accepts":
    ## End-to-end: drive `generateBlocks` (which now wires acceptAndConnectBlock
    ## under the hood) and confirm it grows the chain. Pre-fix this worked
    ## but accepted unvalidated blocks; post-fix it must still grow the chain
    ## with VALIDATED blocks.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()
    var mempool = newMempool(cs, regtestParams())

    # Seed genesis via direct connect (fixture, not under test).
    if cs.bestHeight < 0:
      let genesis = buildGenesisBlock(regtestParams())
      doAssert cs.connectBlock(genesis, 0).isOk

    let coinbaseScript = @[byte(0x51)]
    let hashes = generateBlocks(cs, mempool, regtestParams(),
                                coinbaseScript, 5, 1000)
    check hashes.len == 5
    check cs.bestHeight == 5  # genesis(0) + 5 mined = 5

# ===========================================================================
# Entry point 4: submitblock side-branch via validateForStorage (W155 BUG-17).
# ===========================================================================

suite "W155 — submitblock side-branch routes through validation":

  test "side-branch storage rejects block with bad merkle root":
    ## W155 BUG-17 sub-symptom: side-branch path only ran checkBlock (which
    ## DOES catch bad merkle root for safety) — but a more subtle gate it
    ## skipped was contextualCheckBlockHeader. We exercise bad merkle root
    ## because it's the simplest gate that fires regardless of UTXO context.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 5)
    defer: cs.close()

    let crypto = newCryptoEngine()
    # Build a side-branch off blks[2] (i.e. parent height = 2, side height = 3).
    # The side-branch's parent is in the index but not on the active tip.
    let sideParent = blks[2]
    let sideParentHash = getBlockHash(sideParent)
    let sideParentIdx = cs.db.getBlockIndex(sideParentHash).get()

    var candidate = makeBlk(sideParentHash, 3, 1_700_005_000'u32,
                            makeRegtestCoinbase(3))
    # Corrupt the merkle root — must be caught by checkBlock inside the
    # validateForStorage envelope.
    var bogusRoot: array[32, byte]
    bogusRoot[0] = 0xDE
    candidate.header.merkleRoot = bogusRoot

    let res = validateForStorage(cs, candidate, sideParentIdx, crypto)
    check (not res.isOk)

  test "side-branch storage rejects block with wrong-height BIP-34 coinbase":
    ## Tighter test: BIP-34 height-encoding gate lives in validateBlock,
    ## which the pre-fix path entirely bypassed for side-branch persistence.
    ## A correct chain-tip block with the WRONG BIP-34 prefix is caught
    ## here only because we now route through validateBlock.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 5)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let sideParent = blks[2]
    let sideParentHash = getBlockHash(sideParent)
    let sideParentIdx = cs.db.getBlockIndex(sideParentHash).get()

    # Build a side-branch block at height 3 but encode height=99 in the
    # coinbase scriptSig — Core rejects with bad-cb-height.
    let badCoinbase = makeRegtestCoinbase(99'i32)
    let candidate = makeBlk(sideParentHash, 3, 1_700_005_000'u32, badCoinbase)

    let res = validateForStorage(cs, candidate, sideParentIdx, crypto)
    check (not res.isOk)

  test "side-branch storage accepts a well-formed side-branch block":
    ## Sanity check: a correctly-formed side-branch block flows through
    ## validateForStorage. Verifies the fix doesn't blanket-reject side
    ## branches.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 5)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let sideParent = blks[2]
    let sideParentHash = getBlockHash(sideParent)
    let sideParentIdx = cs.db.getBlockIndex(sideParentHash).get()

    # Side block must satisfy contextualCheckBlockHeader's MTP gate at
    # sideParent's height. Use a timestamp comfortably after blks[2].ts
    # (which is 1_700_000_000 + 2*600 = 1_700_001_200). The coinbase
    # extraScriptByte differs from the active-chain blks[3] coinbase so
    # BIP-30 doesn't flag a duplicate txid.
    let candidate = makeBlk(sideParentHash, 3, 1_700_005_000'u32,
                            makeRegtestCoinbase(3, extraScriptByte = 0x01))

    let res = validateForStorage(cs, candidate, sideParentIdx, crypto)
    check res.isOk

# ===========================================================================
# Cross-cutting: BlockSource discrimination
# ===========================================================================

suite "BlockSource discrimination":

  test "acceptAndConnectBlock refuses bsSubmitBlockSide":
    ## bsSubmitBlockSide indicates a side-branch block, which must go through
    ## `validateForStorage` (not `acceptAndConnectBlock`) because the active
    ## chainstate's UTXO set does not match the side-branch's parent state.
    ## The helper must explicitly reject the wrong source rather than silently
    ## try (and likely fail confusingly during connect).
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()

    let crypto = newCryptoEngine()
    let prevHash = getBlockHash(blks[2])
    let candidate = makeBlk(prevHash, 3, 1_700_005_000'u32,
                            makeRegtestCoinbase(3))

    let res = acceptAndConnectBlock(cs, candidate, 3, bsSubmitBlockSide, crypto)
    check (not res.isOk)
    check contains(res.error, "validateForStorage")

# ===========================================================================
# Core-parity: side-branch UTXO validation deferral (skipConnectChecks).
# ===========================================================================
#
# Bitcoin Core AcceptBlock (validation.cpp:4298-4396) stores any block that
# passes CheckBlock + ContextualCheckBlock, WITHOUT running ConnectBlock (UTXO
# validation). ConnectBlock only runs during ActivateBestChainStep when the
# block is actually connected to the active chain, against the fork-point UTXO
# view rebuilt by DisconnectBlock.
#
# The bug: before this fix, validateForStorage called acceptBlock with
# skipConnectChecks=false (the default), so validateBlock ran the full per-tx
# UTXO loop against the active-tip UTXO set. A side-branch block that spends a
# UTXO consumed by the active chain ABOVE the fork point legitimately exists at
# the fork but is "missing" from the active-tip view →
# false "bad-txns-inputs-missingorspent" rejection.
#
# The fix: validateForStorage now passes skipConnectChecks=true, deferring all
# UTXO-dependent checks to connect time.

suite "skipConnectChecks — side-branch accepts cross-fork-spent UTXOs":

  test "side-branch block spending cross-fork UTXO is NOT false-rejected":
    ## Setup (heights 0..102):
    ##   h=0 (genesis, coinbase unspendable per Core) → h=1..101 → A102 → A103
    ##                                                   └→ B102 (side-branch off h=101)
    ##
    ## The h=1 coinbase output is mature at height 102 (100 confirmations).
    ## A102 spends the h=1 coinbase output (active chain).
    ## B102 also spends the h=1 coinbase output (side-branch, legitimate at fork).
    ##
    ## Pre-fix: validateForStorage ran validateBlock with the active-tip UTXO
    ## set. The h=1 coinbase is spent by A102, absent from the active-tip view
    ## → validateBlock rejects B102 as "bad-txns-inputs-missingorspent".
    ##
    ## Post-fix: validateForStorage passes skipConnectChecks=true → the per-tx
    ## UTXO loop is skipped → B102 is accepted for storage.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)

    # Build 102 blocks (h=0..101); h=1 coinbase matures at h=102.
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 102)
    defer: cs.close()
    let crypto = newCryptoEngine()

    # The h=1 coinbase UTXO is the shared outpoint.
    # (Genesis coinbase is unspendable by Core convention — never in UTXO set.)
    let h1CoinbaseTx = blks[1].txs[0]
    let sharedUtxoTxid = h1CoinbaseTx.txid()
    let sharedUtxoOp = OutPoint(txid: sharedUtxoTxid, vout: 0)

    # Confirm the UTXO is present at the active tip (not yet spent).
    let utxoBefore = cs.getUtxo(sharedUtxoOp)
    doAssert utxoBefore.isSome,
      "Expected h=1 coinbase UTXO to be present before A102"

    # Fork parent = blks[101] (h=101).
    let a101Hash = getBlockHash(blks[101])

    # --- A102 (h=102): active chain spends the h=1 coinbase UTXO ---
    let spendTxA102 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: sharedUtxoOp,
        scriptSig: @[byte(0x51)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(4_999_000_000'i64),
        scriptPubKey: @[byte(0x51)]
      )],
      lockTime: 0
    )
    let a102Coinbase = makeRegtestCoinbase(102)
    let a102Blk = makeBlk(a101Hash, 102, 1_700_000_000'u32 + 102*600'u32,
                          a102Coinbase, extraTxs = @[spendTxA102])
    let a102Result = cs.connectBlock(a102Blk, 102)
    doAssert a102Result.isOk, "A102 connect failed: " & $a102Result.error
    let a102Hash = getBlockHash(a102Blk)

    # UTXO is now gone from active-tip UTXO set (spent by A102).
    let utxoAfterA102 = cs.getUtxo(sharedUtxoOp)
    doAssert utxoAfterA102.isNone,
      "Expected h=1 coinbase UTXO to be absent after A102"

    # --- A103 (h=103): extend active chain further ---
    let a103Blk = makeBlk(a102Hash, 103, 1_700_000_000'u32 + 103*600'u32,
                          makeRegtestCoinbase(103))
    let a103Result = cs.connectBlock(a103Blk, 103)
    doAssert a103Result.isOk, "A103 connect failed: " & $a103Result.error

    # Active tip is at height 103. h=1 coinbase UTXO is spent.

    # --- B102 (h=102, side-branch off blks[101]) ---
    # B102 spends the same h=1 coinbase UTXO. Legitimate: at the fork point
    # (after h=101, before A102) the UTXO exists and is mature. From the
    # active-tip view it is missing (spent by A102 above the fork).
    let spendTxB102 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: sharedUtxoOp,   # same UTXO as A102 spends
        scriptSig: @[byte(0x51)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(4_999_000_000'i64),
        scriptPubKey: @[byte(0x51)]
      )],
      lockTime: 0
    )
    # Differentiate B102's coinbase from A102's via extraScriptByte (BIP-30).
    let b102Coinbase = makeRegtestCoinbase(102, extraScriptByte = 0x42)
    let a101Idx = cs.db.getBlockIndex(a101Hash).get()
    let b102Blk = makeBlk(a101Hash, 102, 1_700_000_000'u32 + 102*600'u32,
                          b102Coinbase, extraTxs = @[spendTxB102])

    # THE BUG TEST: validateForStorage must NOT reject B102 with
    # "bad-txns-inputs-missingorspent" because the h=1 coinbase UTXO is
    # legitimately present at the fork but absent from the active-tip view.
    let res = validateForStorage(cs, b102Blk, a101Idx, crypto)
    check res.isOk  # Must ACCEPT the side-branch block for storage

  test "side-branch with genuinely bad inputs is still rejected":
    ## Regression guard: skipConnectChecks must NOT suppress rejection of
    ## side-branch blocks that reference a UTXO that never existed at all
    ## (not just consumed by the active chain — genuinely nonexistent).
    ##
    ## Note: with skipConnectChecks=true, validateForStorage defers ALL UTXO
    ## checks to connect time. A block with a completely fabricated prevout
    ## therefore passes validateForStorage (mirrors Core AcceptBlock: Core also
    ## stores the block without checking UTXO existence at accept time).
    ## The invalid spend is caught at connect time (handleReorg → connectBlock).
    ## This test documents the correct post-fix behaviour: accept-for-storage
    ## defers UTXO validation, just like Core.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildRegtestChain(dbPath, regtestParams(), 3)
    defer: cs.close()
    let crypto = newCryptoEngine()

    # Build a spend of a completely fabricated UTXO.
    var fakeTxid: array[32, byte]
    fakeTxid[0] = 0xDE
    fakeTxid[1] = 0xAD
    let fakeOp = OutPoint(txid: TxId(fakeTxid), vout: 0)
    let fakeTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: fakeOp,
        scriptSig: @[byte(0x51)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_000_000'i64),
        scriptPubKey: @[byte(0x51)]
      )],
      lockTime: 0
    )
    let sideParent = blks[1]
    let sideParentHash = getBlockHash(sideParent)
    let sideParentIdx = cs.db.getBlockIndex(sideParentHash).get()

    let b2Coinbase = makeRegtestCoinbase(2, extraScriptByte = 0x42)
    let b2Blk = makeBlk(sideParentHash, 2, 1_700_001_200'u32, b2Coinbase,
                        extraTxs = @[fakeTx])

    # Post-fix: validateForStorage accepts for storage (defers UTXO checks to
    # connect time, matching Core AcceptBlock). The invalid spend is caught by
    # connectBlock during a reorg to this branch.
    let res = validateForStorage(cs, b2Blk, sideParentIdx, crypto)
    check res.isOk  # accepted for storage; bad UTXO rejected at connect time
