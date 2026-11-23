## cffix-nimrod-reorg-bip68-mtp — BIP-68 time locks on a reorg-connected block
## must measure the coin's MTP on the branch being connected, not the active
## chain's height index.
##
## Core: CalculateSequenceLocks (consensus/tx_verify.cpp) takes
##   nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
## where `block` is the CBlockIndex of the block being connected, so the
## ancestor is on that block's own chain.
##
## Pre-fix nimrod: reorgConnectChecks resolved nCoinTime with
## getMtpForHeight(db, h), which walks getBlockHashByHeight.  During
## handleReorg the new branch's height rows exist only in the uncommitted
## WriteBatch, so the committed height index is still the OLD chain: a coin
## created at F+2 or above got its MTP window from old-chain blocks, and above
## the old tip the window was empty (MTP 0).
##
## Fixture (regtest, CSV active from height 1), fork point F = 2:
##   common   h0..h2         stored WITH height rows (putBlockIndex)
##   old      h3..h5         stored WITH height rows — the committed active chain
##   new      h3'..h7'       stored hash-only (putBlockIndexHashOnly) — exactly
##                           what handleReorg's DB looks like before commit
## The block under test is connected on top of the new branch and is handed
## straight to reorgConnectChecks, the per-block hook handleReorg fires.
##
## Every timestamp is header-valid (strictly above its parent's MTP) on its
## own chain.  nimrod's median is sorted[len div 2], same as Core.

import unittest2
import std/[os, options]
import ../src/consensus/[validation, params]
import ../src/primitives/types
import ../src/storage/chainstate

const TestDbPath = "/tmp/nimrod_cffix_reorg_bip68_mtp_test"
const ForkHeight = 2'i32

proc cleanupDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc tagHash(tag: int, h: int32): BlockHash =
  var a: array[32, byte]
  a[0] = byte(tag)
  a[1] = byte(h)
  a[2] = 0xb6          # keep clear of the all-zero null hash
  BlockHash(a)

proc mkIdx(tag: int, h: int32, prev: BlockHash, ts: uint32): BlockIndex =
  BlockIndex(
    hash: tagHash(tag, h),
    height: h,
    header: BlockHeader(version: 4, prevBlock: prev,
                        merkleRoot: default(array[32, byte]),
                        timestamp: ts, bits: 0x207fffff'u32, nonce: uint32(h)),
    status: bsValidated,
    totalWork: default(array[32, byte]))

const CommonTag = 1
const OldTag = 2
const NewTag = 3

type Fixture = object
  newTip: BlockIndex       ## highest stored new-branch block (parent of the block under test)
  newByHeight: seq[BlockIndex]

proc buildFixture(cs: ChainState, common, old, new: openArray[uint32]): Fixture =
  ## common -> heights 0..F (height rows), old -> F+1.. (height rows),
  ## new -> F+1'.. (hash-only).  Returns the new branch.
  doAssert common.len == int(ForkHeight) + 1
  var prev = BlockHash(default(array[32, byte]))
  var forkIdx: BlockIndex
  for i, ts in common:
    let idx = mkIdx(CommonTag, int32(i), prev, ts)
    cs.db.putBlockIndex(idx)
    prev = idx.hash
    forkIdx = idx
  prev = forkIdx.hash
  for i, ts in old:
    let idx = mkIdx(OldTag, ForkHeight + 1 + int32(i), prev, ts)
    cs.db.putBlockIndex(idx)
    prev = idx.hash
  result.newByHeight = @[]
  prev = forkIdx.hash
  for i, ts in new:
    let idx = mkIdx(NewTag, ForkHeight + 1 + int32(i), prev, ts)
    cs.db.putBlockIndexHashOnly(idx)
    prev = idx.hash
    result.newByHeight.add idx
  result.newTip = result.newByHeight[^1]

proc mkCoinOutpoint(): OutPoint =
  var a: array[32, byte]
  a[0] = 0xc0
  a[31] = 0x1d
  OutPoint(txid: TxId(a), vout: 0)

let coinOutpoint = mkCoinOutpoint()

proc coinbaseTx(h: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xffffffff'u32),
                   scriptSig: @[0x01'u8, byte(h), 0x00], sequence: 0xffffffff'u32)],
    outputs: @[TxOut(value: Satoshi(50 * 100_000_000), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0)

proc spendTx(lockUnits: uint32): Transaction =
  ## v2 tx with one time-type relative lock of `lockUnits` * 512 s on coin C.
  Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: coinOutpoint, scriptSig: @[],
                   sequence: SequenceLockTypeFlag or lockUnits)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0)

proc runConnect(cs: ChainState, fx: Fixture, coinHeight: int32,
                lockUnits: uint32): ValidationResult[void] =
  ## Connect the block at newTip.height+1 (parent = new-branch tip) holding a
  ## spend of coin C, created at `coinHeight`, through reorgConnectChecks.
  let height = fx.newTip.height + 1
  let blk = Block(
    header: BlockHeader(version: 4, prevBlock: fx.newTip.hash,
                        merkleRoot: default(array[32, byte]),
                        timestamp: fx.newTip.header.timestamp + 1,
                        bits: 0x207fffff'u32, nonce: 7),
    txs: @[coinbaseTx(height), spendTx(lockUnits)])
  let coin = UtxoEntry(output: TxOut(value: Satoshi(100_000), scriptPubKey: @[0x51'u8]),
                       height: coinHeight, isCoinbase: false)
  let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
    if op == coinOutpoint: some(coin) else: none(UtxoEntry)
  reorgConnectChecks(blk, height, lookup, cs.db, regtestParams())

# Fork-point timestamps shared by every case: MTP(h2) = 2000.
const Common = [1000'u32, 2000, 5000]

suite "cffix-nimrod-reorg-bip68-mtp: reorg BIP-68 coin MTP comes from the connecting branch":

  setup: cleanupDb()
  teardown: cleanupDb()

  test "invalid on the new branch is rejected bad-txns-nonfinal (old-chain MTP would accept)":
    ## Coin C at F+3' (h5); spender in F+5' (h7), parent F+4' (h6).
    ##   coin MTP must be MTP(F+2') = median{1000,2000,5000,6000,7000} = 5000
    ##   old-chain MTP(F+2)        = median{1000,2000,5000,2001,2002} = 2001
    ##   block MTP = MTP(F+4')     = median{1000,2000,5000,6000..9000} = 6000
    ## L = 4 (2048 s): new 5000+2047 = 7047 >= 6000 -> NON-FINAL (Core);
    ##                 old 2001+2047 = 4048 <  6000 -> final (pre-fix nimrod).
    var cs = newChainState(TestDbPath, regtestParams())
    let fx = buildFixture(cs, Common, [2001'u32, 2002, 2003],
                          [6000'u32, 7000, 8000, 9000])
    check getMtpForBlockIndex(cs.db, fx.newByHeight[1]) == 5000'u32   # new F+2'
    check getMtpForHeight(cs.db, ForkHeight + 2) == 2001'u32           # old F+2
    check getMtpForBlockIndex(cs.db, fx.newTip) == 6000'u32            # block MTP
    let res = runConnect(cs, fx, ForkHeight + 3, 4)
    check not res.isOk
    if not res.isOk:
      check res.error == veSequenceLockNotSatisfied
      check bip22String(res.error) == "bad-txns-nonfinal"
    cs.close()

  test "valid on the new branch is accepted (old-chain MTP would reject)":
    ## Mirror: old branch higher than new at the coin's window.
    ##   coin MTP must be MTP(F+2') = median{1000,2000,5000,2001,3000} = 2001
    ##   old-chain MTP(F+2)        = median{1000,2000,5000,2500,3000} = 2500
    ##   block MTP = MTP(F+4')     = median{1000,2000,5000,2001,3000,3000,5001} = 3000
    ## L = 1 (512 s): new 2001+511 = 2512 < 3000 -> final (Core accepts);
    ##                old 2500+511 = 3011 >= 3000 -> NON-FINAL (pre-fix nimrod
    ##                rejects the heavier valid branch).
    var cs = newChainState(TestDbPath, regtestParams())
    let fx = buildFixture(cs, Common, [2500'u32, 3000, 3000],
                          [2001'u32, 3000, 3000, 5001])
    check getMtpForBlockIndex(cs.db, fx.newByHeight[1]) == 2001'u32
    check getMtpForHeight(cs.db, ForkHeight + 2) == 2500'u32
    check getMtpForBlockIndex(cs.db, fx.newTip) == 3000'u32
    let res = runConnect(cs, fx, ForkHeight + 3, 1)
    check res.isOk
    if not res.isOk:
      checkpoint "rejected with " & $res.error
    cs.close()

  test "coin above the old tip: empty old-chain window must not read as MTP 0":
    ## Coin C at F+5' (h7) — above the old tip (h5), so the committed height
    ## index has no row at the coin's parent height h6 and getMtpForHeight
    ## returns 0.  Spender in F+6' (h8), parent F+5' (h7).
    ##   coin MTP must be MTP(F+4') = median{1000,2000,5000,6000..9000} = 6000
    ##   block MTP = MTP(F+5')      = median{1000,2000,5000,6000..10000} = 7000
    ## L = 4: new 6000+2047 = 8047 >= 7000 -> NON-FINAL (Core);
    ##        empty window 0+2047 < 7000 -> final (pre-fix nimrod).
    var cs = newChainState(TestDbPath, regtestParams())
    let fx = buildFixture(cs, Common, [2001'u32, 2002, 2003],
                          [6000'u32, 7000, 8000, 9000, 10000])
    check getMtpForHeight(cs.db, ForkHeight + 4) == 0'u32   # the empty window
    check getMtpForBlockIndex(cs.db, fx.newByHeight[3]) == 6000'u32
    check getMtpForBlockIndex(cs.db, fx.newTip) == 7000'u32
    let res = runConnect(cs, fx, ForkHeight + 5, 4)
    check not res.isOk
    if not res.isOk:
      check bip22String(res.error) == "bad-txns-nonfinal"
    cs.close()

  test "coin below the fork resolves through the shared ancestry (both chains agree)":
    ## Control: coin C at h1 (common).  coin MTP = MTP(h0) = 1000 on either
    ## chain; block MTP = 6000.  L = 9 (4608 s): 1000+4607 = 5607 < 6000 ->
    ## final; L = 10 (5120 s): 6119 >= 6000 -> non-final.  The boundary pins
    ## the exact coin MTP the fix resolves for a coin below the fork.
    var cs = newChainState(TestDbPath, regtestParams())
    let fx = buildFixture(cs, Common, [2001'u32, 2002, 2003],
                          [6000'u32, 7000, 8000, 9000])
    check runConnect(cs, fx, 1, 9).isOk
    let res = runConnect(cs, fx, 1, 10)
    check not res.isOk
    if not res.isOk:
      check bip22String(res.error) == "bad-txns-nonfinal"
    cs.close()

  test "getAncestorIndex follows the branch above the fork and the index below it":
    when declared(getAncestorIndex):
      var cs = newChainState(TestDbPath, regtestParams())
      let fx = buildFixture(cs, Common, [2001'u32, 2002, 2003],
                            [6000'u32, 7000, 8000, 9000])
      # Above the fork: the new-branch block, not the old row at that height.
      let a4 = getAncestorIndex(cs.db, fx.newTip, ForkHeight + 2)
      check a4.isSome and a4.get().hash == fx.newByHeight[1].hash
      # At / below the fork: the shared block.
      let a2 = getAncestorIndex(cs.db, fx.newTip, ForkHeight)
      check a2.isSome and a2.get().hash == tagHash(CommonTag, ForkHeight)
      let a0 = getAncestorIndex(cs.db, fx.newTip, 0)
      check a0.isSome and a0.get().hash == tagHash(CommonTag, 0)
      # Self, and out of range.
      check getAncestorIndex(cs.db, fx.newTip, fx.newTip.height).get().hash == fx.newTip.hash
      check getAncestorIndex(cs.db, fx.newTip, fx.newTip.height + 1).isNone
      check getAncestorIndex(cs.db, fx.newTip, -1).isNone
      cs.close()
    else:
      fail()   # master: the branch-ancestor resolver does not exist

  test "missing branch ancestor fails closed as a local read error, not a verdict":
    ## Break the new branch's parent link (F+2' stored, F+1' missing): the coin
    ## MTP cannot be resolved, so the result must be the local utxo-read-error
    ## token — never "final" off a guessed window and never a block verdict.
    var cs = newChainState(TestDbPath, regtestParams())
    var prev = BlockHash(default(array[32, byte]))
    for i, ts in Common:
      let idx = mkIdx(CommonTag, int32(i), prev, ts)
      cs.db.putBlockIndex(idx)
      prev = idx.hash
    for i, ts in [2001'u32, 2002, 2003]:
      let idx = mkIdx(OldTag, ForkHeight + 1 + int32(i), prev, ts)
      cs.db.putBlockIndex(idx)
      prev = idx.hash
    var nb: seq[BlockIndex]
    prev = tagHash(NewTag, ForkHeight + 1)       # F+1' never stored
    for i, ts in [7000'u32, 8000, 9000]:
      let idx = mkIdx(NewTag, ForkHeight + 2 + int32(i), prev, ts)
      cs.db.putBlockIndexHashOnly(idx)
      prev = idx.hash
      nb.add idx
    let fx = Fixture(newTip: nb[^1], newByHeight: nb)
    let res = runConnect(cs, fx, ForkHeight + 2, 4)   # coin parent = F+1' (missing)
    check not res.isOk
    if not res.isOk:
      check res.error == veUtxoReadError
    cs.close()
