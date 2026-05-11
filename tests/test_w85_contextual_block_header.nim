## W85 — Comprehensive tests for MedianTimePast + ContextualCheckBlockHeader
##
## Covers all gates in contextualCheckBlockHeader (validation.cpp:4080-4121):
##   Gate 1: bad-diffbits — nBits != GetNextWorkRequired          (line 4088)
##   Gate 2: time-too-old — timestamp <= MTP of prev 11 blocks    (line 4092)
##   Gate 3: time-timewarp-attack — BIP94 anti-timewarp           (line 4097)
##   Gate 4: bad-version — obsolete nVersion after BIP34/66/65    (line 4113)
##
## Also covers:
##   time-too-new overflow fix in validateBlockHeader
##   bip22String mappings for all new error codes
##
## Reference: bitcoin-core/src/validation.cpp:4080-4121
##            bitcoin-core/src/chain.h:230-246 (GetMedianTimePast)
##            bitcoin-core/src/consensus/consensus.h:35 (MAX_TIMEWARP=600)

import unittest2
import std/[os, options, times, atomics]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/storage/chainstate

var dbCounter: Atomic[int]
dbCounter.store(0)

proc freshDbPath(): string =
  let n = dbCounter.fetchAdd(1)
  "/tmp/nimrod_w85_" & $n

proc cleanupDb(path: string) =
  if dirExists(path):
    removeDir(path)

proc makeCoinbaseTx(height: int32): Transaction =
  let heightBytes = @[
    byte(height and 0xff), byte((height shr 8) and 0xff),
    byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)
  ]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x51)]  # OP_1
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlockV(prevHash: BlockHash, height: int32, ts: uint32,
                bits: uint32 = 0x207fffff'u32,
                version: int32 = 4): Block =
  let coinbase = makeCoinbaseTx(height)
  Block(
    header: BlockHeader(
      version: version,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
      timestamp: ts,
      bits: bits,
      nonce: uint32(height),
    ),
    txs: @[coinbase],
  )

proc makeBlk(prevHash: BlockHash, height: int32, ts: uint32,
             bits: uint32 = 0x207fffff'u32): Block =
  makeBlockV(prevHash, height, ts, bits, version=4)

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc buildChainN(dbPath: string, p: ConsensusParams, n: int,
                 baseTs: uint32, tsStep: uint32,
                 bits: uint32): (ChainState, seq[Block]) =
  ## Build a fresh chainstate with n blocks and return it open.
  var cs = newChainState(dbPath, p)
  var prevHash = BlockHash(default(array[32, byte]))
  var blks: seq[Block]
  for h in 0'i32 ..< int32(n):
    let ts = baseTs + uint32(h) * tsStep
    let blk = makeBlk(prevHash, h, ts, bits)
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "buildChainN failed h=" & $h & ": " & $res.error
    prevHash = getBlockHash(blk)
    blks.add(blk)
  (cs, blks)

# ============================================================================
# Suite 1: Gate 2 — time-too-old (MTP)
# ============================================================================

suite "W85 Gate 2: time-too-old (MTP enforcement)":

  test "block timestamp == MTP is rejected (time-too-old)":
    ## MTP of 11 blocks ts 1000..2000 step 100 = sorted[5] = 1500.
    ## A candidate block with ts=1500 must be REJECTED.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 11, 1000'u32, 100'u32, 0x207fffff'u32)
    defer: cs.close()

    let prevHash = getBlockHash(blks[10])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlk(prevHash, 11, 1500'u32)
    let res = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veBadTimestamp

  test "block timestamp < MTP is rejected (time-too-old)":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 11, 1000'u32, 100'u32, 0x207fffff'u32)
    defer: cs.close()

    let prevHash = getBlockHash(blks[10])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlk(prevHash, 11, 1400'u32)
    let res = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veBadTimestamp

  test "block timestamp == MTP+1 passes MTP gate":
    ## ts=1501 is strictly > MTP=1500. Must NOT produce veBadTimestamp.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var (cs, blks) = buildChainN(dbPath, regtestParams(), 11, 1000'u32, 100'u32, 0x207fffff'u32)
    defer: cs.close()

    let prevHash = getBlockHash(blks[10])
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let goodBlk = makeBlk(prevHash, 11, 1501'u32)
    let res = validateBlock(goodBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veBadTimestamp

  test "MTP uses up to 11 predecessors, not just direct parent":
    ## Chain: ts 1000..1009, then block 10 at ts=5000.
    ## MTP of 11 = sorted[5] = 1005 (parent ts=5000 is irrelevant for the gate).
    ## ts=1000: rejected. ts=4000: passes MTP (> 1005, less than parent 5000 ok).
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    var prevHash = BlockHash(default(array[32, byte]))
    var blks: seq[Block]
    for h in 0'i32..9'i32:
      let blk = makeBlk(prevHash, h, uint32(1000 + h), 0x207fffff'u32)
      check cs.connectBlock(blk, h).isOk
      prevHash = getBlockHash(blk)
      blks.add(blk)
    let blk10 = makeBlk(prevHash, 10, 5000'u32, 0x207fffff'u32)
    check cs.connectBlock(blk10, 10).isOk
    prevHash = getBlockHash(blk10)
    blks.add(blk10)

    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # ts=1000: MTP is 1005 → rejected
    let badBlk = makeBlk(prevHash, 11, 1000'u32)
    let badRes = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                               checkScripts=false, checkPow=false)
    check (not badRes.isOk)
    check badRes.error == veBadTimestamp

    # ts=4000 > MTP=1005: passes MTP gate
    let goodBlk = makeBlk(prevHash, 11, 4000'u32)
    let goodRes = validateBlock(goodBlk, prevIdx, cs.db, regtestParams(),
                                checkScripts=false, checkPow=false)
    if not goodRes.isOk:
      check goodRes.error != veBadTimestamp

  test "chain shorter than 11: MTP uses all available blocks":
    ## 3 blocks ts=100,200,300. MTP=sorted[1]=200. ts=200 rejected, ts=201 passes.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    var prevHash = BlockHash(default(array[32, byte]))
    var blks: seq[Block]
    for h in 0'i32..2'i32:
      let blk = makeBlk(prevHash, h, uint32(100 + 100*h))
      check cs.connectBlock(blk, h).isOk
      prevHash = getBlockHash(blk)
      blks.add(blk)

    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlk(prevHash, 3, 200'u32)
    let badRes = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                               checkScripts=false, checkPow=false)
    check (not badRes.isOk)
    check badRes.error == veBadTimestamp

    let goodBlk = makeBlk(prevHash, 3, 201'u32)
    let goodRes = validateBlock(goodBlk, prevIdx, cs.db, regtestParams(),
                                checkScripts=false, checkPow=false)
    if not goodRes.isOk:
      check goodRes.error != veBadTimestamp

# ============================================================================
# Suite 2: Gate 3 — time-timewarp-attack (BIP94)
# ============================================================================

suite "W85 Gate 3: time-timewarp-attack (BIP94)":

  test "BIP94: diff-adjustment block with ts < prevTs-600 is rejected":
    ## At height N (retarget), enforceBIP94 requires:
    ##   block.ts >= prevBlock.ts - MAX_TIMEWARP (600)
    ## i.e. block.ts < prevBlock.ts - 600 is rejected.
    ##
    ## Setup: 4 blocks with ts 100, 200, 300, 2_000_000.
    ## MTP of these 4 = sorted[2] = 300.
    ## prevTs = 2_000_000.  Attack ts = prevTs - 601 = 1_999_399.
    ## 1_999_399 > MTP (300) → MTP gate passes.
    ## 1_999_399 < prevTs - 600 (1_999_400) → timewarp gate fires!
    ##
    ## Custom params: regtest-like but enforceBIP94=true, diffAdjInterval=4
    ## and powNoRetargeting=true so diffbits gate trivially passes.

    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)

    var p = regtestParams()
    p.enforceBIP94 = true
    p.difficultyAdjustmentInterval = 4

    var cs = newChainState(dbPath, p)
    defer: cs.close()

    let bits = 0x207fffff'u32
    # Use timestamps: h=0→100, h=1→200, h=2→300, h=3→2000000
    let timestamps = [100u32, 200, 300, 2000000]
    var prevHash = BlockHash(default(array[32, byte]))
    var blks: seq[Block]
    for h in 0'i32..3'i32:
      let blk = makeBlk(prevHash, h, timestamps[h], bits)
      check cs.connectBlock(blk, h).isOk
      prevHash = getBlockHash(blk)
      blks.add(blk)

    let prevIdx = cs.db.getBlockIndex(prevHash).get()
    let prevTs = prevIdx.header.timestamp  # = 2_000_000

    # Height 4 = retarget boundary (4 mod 4 == 0).
    # attackTs = prevTs - 601 = 1_999_399. This is > MTP (300), < prevTs-600.
    let attackTs = uint32(int(prevTs) - 601)
    let badBlk = makeBlk(prevHash, 4, attackTs, bits)
    let res = validateBlock(badBlk, prevIdx, cs.db, p, checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veTimeWarpAttack

  test "BIP94: ts exactly at prevTs-600 is NOT rejected (boundary)":
    ## Core condition: ts < prevTs - 600 → reject.
    ## ts == prevTs - 600 is NOT < prevTs - 600 → accepted by timewarp gate.
    ## Same chain setup as previous test for consistent MTP.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)

    var p = regtestParams()
    p.enforceBIP94 = true
    p.difficultyAdjustmentInterval = 4

    var cs = newChainState(dbPath, p)
    defer: cs.close()

    let bits = 0x207fffff'u32
    let timestamps = [100u32, 200, 300, 2000000]
    var prevHash = BlockHash(default(array[32, byte]))
    var blks: seq[Block]
    for h in 0'i32..3'i32:
      let blk = makeBlk(prevHash, h, timestamps[h], bits)
      check cs.connectBlock(blk, h).isOk
      prevHash = getBlockHash(blk)
      blks.add(blk)

    let prevIdx = cs.db.getBlockIndex(prevHash).get()
    let prevTs = prevIdx.header.timestamp  # = 2_000_000

    # ts = prevTs - 600 = 1_999_400: NOT < prevTs-600 → timewarp gate passes
    let borderTs = uint32(int(prevTs) - 600)
    let borderBlk = makeBlk(prevHash, 4, borderTs, bits)
    let borderRes = validateBlock(borderBlk, prevIdx, cs.db, p, checkScripts=false, checkPow=false)
    if not borderRes.isOk:
      check borderRes.error != veTimeWarpAttack

  test "BIP94 timewarp only fires at retarget boundaries":
    ## At height NOT a multiple of 2016 (or custom diffAdjInterval), the gate
    ## must NOT fire regardless of timestamp.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)

    var p = regtestParams()
    p.enforceBIP94 = true
    p.difficultyAdjustmentInterval = 4

    var cs = newChainState(dbPath, p)
    defer: cs.close()

    let bits = 0x207fffff'u32
    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32, bits)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()
    let prevTs = prevIdx.header.timestamp

    # height=1 is NOT 1 mod 4 == 0, so timewarp doesn't apply
    let oldTs = uint32(int(prevTs) - 10000)  # way before prevTs - 600
    let blk1 = makeBlk(prevHash, 1, oldTs, bits)
    let res = validateBlock(blk1, prevIdx, cs.db, p, checkScripts=false, checkPow=false)
    # May fail MTP (oldTs <= MTP) but not timewarp
    if not res.isOk:
      check res.error != veTimeWarpAttack

  test "mainnet (enforceBIP94=false) ignores timewarp entirely":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 2000000'u32)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let blk1 = makeBlk(prevHash, 1, 2000001'u32)
    let res = validateBlock(blk1, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veTimeWarpAttack

# ============================================================================
# Suite 3: Gate 4 — bad-version
# ============================================================================

suite "W85 Gate 4: bad-version (obsolete nVersion rejection)":

  test "nVersion=1 rejected after BIP34 activation":
    ## testnet4 has BIP34 at height 1. Block at h>=1 with nVersion=1 must fail.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, testnet4Params())
    defer: cs.close()

    let blk0 = makeBlockV(BlockHash(default(array[32, byte])), 0, 1000000'u32,
                          0x1d00ffff'u32, version=4)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlockV(prevHash, 1, 1000601'u32, 0x1d00ffff'u32, version=1)
    let res = validateBlock(badBlk, prevIdx, cs.db, testnet4Params(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veBadBlockVersion

  test "nVersion=2 rejected after BIP66 activation":
    ## BIP66 at height 1. nVersion=2 (< 3) must fail.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, testnet4Params())
    defer: cs.close()

    let blk0 = makeBlockV(BlockHash(default(array[32, byte])), 0, 1000000'u32,
                          0x1d00ffff'u32, version=4)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlockV(prevHash, 1, 1000601'u32, 0x1d00ffff'u32, version=2)
    let res = validateBlock(badBlk, prevIdx, cs.db, testnet4Params(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veBadBlockVersion

  test "nVersion=3 rejected after BIP65 activation":
    ## BIP65 at height 1. nVersion=3 (< 4) must fail.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, testnet4Params())
    defer: cs.close()

    let blk0 = makeBlockV(BlockHash(default(array[32, byte])), 0, 1000000'u32,
                          0x1d00ffff'u32, version=4)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlockV(prevHash, 1, 1000601'u32, 0x1d00ffff'u32, version=3)
    let res = validateBlock(badBlk, prevIdx, cs.db, testnet4Params(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veBadBlockVersion

  test "nVersion=4 accepted after all three BIPs active":
    ## nVersion=4 is valid (meets >=4, >=3, >=2).
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, testnet4Params())
    defer: cs.close()

    let blk0 = makeBlockV(BlockHash(default(array[32, byte])), 0, 1000000'u32,
                          0x1d00ffff'u32, version=4)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let goodBlk = makeBlockV(prevHash, 1, 1000601'u32, 0x1d00ffff'u32, version=4)
    let res = validateBlock(goodBlk, prevIdx, cs.db, testnet4Params(),
                            checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veBadBlockVersion

  test "nVersion=1 accepted before BIP34 activation on mainnet":
    ## mainnet bip34Height=227931. At height 1, BIP34 not yet active.
    ## nVersion=1 must NOT produce veBadBlockVersion.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var p = mainnetParams()
    var cs = newChainState(dbPath, p)
    defer: cs.close()

    let blk0 = makeBlockV(BlockHash(default(array[32, byte])), 0, 1231006505'u32,
                          0x1d00ffff'u32, version=1)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # height=1 < bip34Height=227931 → nVersion=1 acceptable
    let goodBlk = makeBlockV(prevHash, 1, 1231007105'u32,
                             0x1d00ffff'u32, version=1)
    let res = validateBlock(goodBlk, prevIdx, cs.db, p, checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veBadBlockVersion

# ============================================================================
# Suite 4: Gate 1 — bad-diffbits (nBits check)
# ============================================================================

suite "W85 Gate 1: bad-diffbits (nBits must match GetNextWorkRequired)":

  test "wrong nBits on non-retarget block is rejected":
    ## On regtest (powNoRetargeting=true), all blocks keep the genesis bits.
    ## A block with different nBits must fail with veIncorrectProofOfWork.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    let correctBits = 0x207fffff'u32
    let wrongBits   = 0x207ffffe'u32  # one step harder

    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32, correctBits)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let badBlk = makeBlk(prevHash, 1, 1001000'u32, wrongBits)
    let res = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veIncorrectProofOfWork

  test "correct nBits on non-retarget block passes diffbits gate":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    let bits = 0x207fffff'u32
    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32, bits)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let goodBlk = makeBlk(prevHash, 1, 1001000'u32, bits)
    let res = validateBlock(goodBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veIncorrectProofOfWork

  test "min-difficulty block with wrong bits is rejected on testnet4 (normal gap)":
    ## On testnet4, a block with ts gap <= 2*targetSpacing must keep prev bits.
    ## A different nBits must fail.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, testnet4Params())
    defer: cs.close()

    let normalBits = 0x1d00ffff'u32
    let wrongBits  = 0x1d00fffe'u32

    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32, normalBits)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    # Normal gap (600s), wrong bits
    let badBlk = makeBlk(prevHash, 1, 1000600'u32, wrongBits)
    let res = validateBlock(badBlk, prevIdx, cs.db, testnet4Params(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veIncorrectProofOfWork

# ============================================================================
# Suite 5: time-too-new overflow fix
# ============================================================================

suite "W85 time-too-new overflow fix (validateBlockHeader)":

  test "timestamp slightly under MAX_FUTURE_BLOCK_TIME accepted":
    ## A block with timestamp = now + 7199s must NOT be rejected.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let nearFuture = uint32(getTime().toUnix()) + 7199'u32
    let goodBlk = makeBlk(prevHash, 1, nearFuture)
    let res = validateBlock(goodBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    if not res.isOk:
      check res.error != veTimeTooNew

  test "timestamp > MAX_FUTURE_BLOCK_TIME is rejected":
    ## A block with timestamp = now + 7201s must fail with veTimeTooNew.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var cs = newChainState(dbPath, regtestParams())
    defer: cs.close()

    let blk0 = makeBlk(BlockHash(default(array[32, byte])), 0, 1000000'u32)
    check cs.connectBlock(blk0, 0).isOk
    let prevHash = getBlockHash(blk0)
    let prevIdx = cs.db.getBlockIndex(prevHash).get()

    let farFuture = uint32(getTime().toUnix()) + 7201'u32
    let badBlk = makeBlk(prevHash, 1, farFuture)
    let res = validateBlock(badBlk, prevIdx, cs.db, regtestParams(),
                            checkScripts=false, checkPow=false)
    check (not res.isOk)
    check res.error == veTimeTooNew

# ============================================================================
# Suite 6: bip22String mappings
# ============================================================================

suite "W85 bip22String mappings":

  test "veIncorrectProofOfWork -> bad-diffbits":
    check bip22String(veIncorrectProofOfWork) == "bad-diffbits"

  test "veTimeWarpAttack -> time-timewarp-attack":
    check bip22String(veTimeWarpAttack) == "time-timewarp-attack"

  test "veTimeTooNew -> time-too-new":
    check bip22String(veTimeTooNew) == "time-too-new"

  test "veBadBlockVersion -> bad-version":
    check bip22String(veBadBlockVersion) == "bad-version"

  test "veBadTimestamp -> time-too-old (regression)":
    check bip22String(veBadTimestamp) == "time-too-old"

# ============================================================================
# Suite 7: getMedianTimePast correctness
# ============================================================================

suite "W85 getMedianTimePast correctness":

  test "11 blocks: median is sorted[5] = 600":
    ## Core: pbegin[(pend-pbegin)/2]. For 11 elements index 5.
    let headers = block:
      var h: seq[BlockHeader]
      for ts in [100u32, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100]:
        h.add(BlockHeader(version:1, timestamp: ts, bits:0))
      h
    check getMedianTimePast(headers) == 600'u32

  test "11 blocks reversed: same median":
    let headers = block:
      var h: seq[BlockHeader]
      for ts in [1100u32, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 100]:
        h.add(BlockHeader(version:1, timestamp: ts, bits:0))
      h
    check getMedianTimePast(headers) == 600'u32

  test "1 block: median is that block":
    let headers = @[BlockHeader(version:1, timestamp:42'u32, bits:0)]
    check getMedianTimePast(headers) == 42'u32

  test "empty: median is 0":
    let headers: seq[BlockHeader] = @[]
    check getMedianTimePast(headers) == 0'u32

  test "3 blocks: median is sorted[1]":
    let headers = block:
      var h: seq[BlockHeader]
      for ts in [300u32, 100, 200]:
        h.add(BlockHeader(version:1, timestamp: ts, bits:0))
      h
    check getMedianTimePast(headers) == 200'u32
