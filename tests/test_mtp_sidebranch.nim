## Regression test: MTP for block-header validation must use hash-linked
## parent walk (getMtpForBlockIndex), not the active-chain height->hash
## index (getMtpForHeight).
##
## Bitcoin Core's GetMedianTimePast (chain.h:233-245) walks pindex->pprev —
## the block's own parent pointers — regardless of which chain the block is
## on.  contextualCheckBlockHeader (validation.cpp:4092) and the BIP-113
## nLockTimeCutoff (validation.cpp:4140-4142) both derive MTP this way.
##
## Pre-fix nimrod: getMtpForHeight(utxos, prevIndex.height) was used, which
## indexes the HEIGHT->HASH map.  That map is last-writer-wins per height
## (accept_header / process_redownload_headers write it unconditionally), so
## for a side-branch block the height slot may point to a DIFFERENT block
## than the actual ancestor, giving wrong MTP.
##
## This test demonstrates the divergence using `putBlockIndexHashOnly` to
## build a chain that is stored BY HASH ONLY (no height entries).  Then:
##   getMtpForHeight  → returns 0 (height index is empty for these hashes)
##   getMtpForBlockIndex → returns the correct median of the stored timestamps
##
## The EFFECTIVE gate: contextualCheckBlockHeader with a block timestamp that
## is <= the real MTP (should be rejected, veBadTimestamp) but > 0 (would be
## accepted under the broken getMtpForHeight path that returns 0).

import unittest2
import std/[os, options]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/storage/chainstate

const TestDbPath = "/tmp/nimrod_mtp_sidebranch_test"

proc cleanupDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc zeroHash(): BlockHash = BlockHash(default(array[32, byte]))

proc fakeHash(n: int): BlockHash =
  var a: array[32, byte]
  a[0] = byte(n)
  a[1] = byte(n shr 8)
  BlockHash(a)

proc makeBlockIndex(h: int32, prevH: BlockHash, ts: uint32): BlockIndex =
  let header = BlockHeader(
    version: 1,
    prevBlock: prevH,
    merkleRoot: default(array[32, byte]),
    timestamp: ts,
    bits: 0x207fffff'u32,
    nonce: uint32(h)
  )
  BlockIndex(
    hash: fakeHash(int(h) + 100),  # deterministic unique hash
    height: h,
    header: header,
    status: bsValidated,
    totalWork: default(array[32, byte])
  )

# ---------------------------------------------------------------------------
# Unit tests for getMtpForBlockIndex
# ---------------------------------------------------------------------------

suite "getMtpForBlockIndex — hash-linked MTP walk":

  setup: cleanupDb()
  teardown: cleanupDb()

  test "11-block chain: correct median from hash links, getMtpForHeight returns 0":
    ## Build a chain of 11 blocks stored BY HASH ONLY (no height->hash index).
    ## Timestamps: 1000, 1100, ..., 2000. Sorted median of 11 = 1500.
    var cs = newChainState(TestDbPath, regtestParams())

    var prevH = zeroHash()
    var tip: BlockIndex
    for i in 0 ..< 11:
      let ts = uint32(1000 + 100 * i)
      let idx = makeBlockIndex(int32(i), prevH, ts)
      cs.db.putBlockIndexHashOnly(idx)
      prevH = idx.hash
      tip = idx

    # getMtpForHeight should return 0 (height->hash index is empty for i 0..10)
    let mtpByHeight = getMtpForHeight(cs.db, tip.height)
    check mtpByHeight == 0'u32

    # getMtpForBlockIndex should return 1500 (the correct median of 1000..2000)
    let mtpByHash = getMtpForBlockIndex(cs.db, tip)
    check mtpByHash == 1500'u32

    cs.close()

  test "fewer than 11 blocks: partial chain median is correct":
    var cs = newChainState(TestDbPath, regtestParams())

    # 3 blocks with timestamps 100, 200, 300 → sorted median = 200
    var prevH = zeroHash()
    var tip: BlockIndex
    for i in 0 ..< 3:
      let idx = makeBlockIndex(int32(i), prevH, uint32(100 * (i + 1)))
      cs.db.putBlockIndexHashOnly(idx)
      prevH = idx.hash
      tip = idx

    let mtp = getMtpForBlockIndex(cs.db, tip)
    check mtp == 200'u32

    cs.close()

  test "genesis block (no parent): MTP is genesis timestamp":
    ## Genesis has prevBlock = zero hash, which won't be in the DB.
    ## getMtpForBlockIndex should collect just the genesis header and return its ts.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeBlockIndex(0, zeroHash(), 1296688602'u32)
    cs.db.putBlockIndexHashOnly(genesis)

    let mtp = getMtpForBlockIndex(cs.db, genesis)
    check mtp == 1296688602'u32

    cs.close()

# ---------------------------------------------------------------------------
# EFFECTIVE gate: contextualCheckBlockHeader uses getMtpForBlockIndex
# ---------------------------------------------------------------------------

suite "contextualCheckBlockHeader uses hash-linked MTP for time-too-old":

  setup: cleanupDb()
  teardown: cleanupDb()

  test "side-branch block rejected for time-too-old using hash-linked MTP":
    ## Chain stored by hash only (simulates side-branch, no height->hash index).
    ## 11 ancestors with timestamps 1000..2000; real MTP = 1500.
    ##
    ## Block under test has timestamp = 1400:
    ##   Pre-fix: getMtpForHeight returns 0 → 1400 > 0 → ACCEPTED (wrong)
    ##   Post-fix: getMtpForBlockIndex returns 1500 → 1400 <= 1500 → REJECTED ✓
    var cs = newChainState(TestDbPath, regtestParams())

    var prevH = zeroHash()
    var prevIdx: BlockIndex
    for i in 0 ..< 11:
      let ts = uint32(1000 + 100 * i)
      let idx = makeBlockIndex(int32(i), prevH, ts)
      cs.db.putBlockIndexHashOnly(idx)
      prevH = idx.hash
      prevIdx = idx

    # prevIdx is the 11th block (height=10, timestamp=2000).
    # The new block (height=11) has timestamp=1400 which is <= MTP=1500.
    let badHeader = BlockHeader(
      version: 4,
      prevBlock: prevIdx.hash,
      merkleRoot: default(array[32, byte]),
      timestamp: 1400'u32,
      bits: 0x207fffff'u32,
      nonce: 0'u32
    )
    let result = contextualCheckBlockHeader(badHeader, prevIdx, cs.db, regtestParams())
    check (not result.isOk)
    check result.error == veBadTimestamp

    cs.close()

  test "side-branch block accepted when timestamp strictly exceeds hash-linked MTP":
    ## Same setup, but timestamp = 1501 (> MTP=1500) — should NOT be rejected
    ## for veBadTimestamp (may fail other checks, but not time-too-old).
    var cs = newChainState(TestDbPath, regtestParams())

    var prevH = zeroHash()
    var prevIdx: BlockIndex
    for i in 0 ..< 11:
      let ts = uint32(1000 + 100 * i)
      let idx = makeBlockIndex(int32(i), prevH, ts)
      cs.db.putBlockIndexHashOnly(idx)
      prevH = idx.hash
      prevIdx = idx

    let goodHeader = BlockHeader(
      version: 4,
      prevBlock: prevIdx.hash,
      merkleRoot: default(array[32, byte]),
      timestamp: 1501'u32,
      bits: 0x207fffff'u32,
      nonce: 0'u32
    )
    let result = contextualCheckBlockHeader(goodHeader, prevIdx, cs.db, regtestParams())
    if not result.isOk:
      check result.error != veBadTimestamp  # any other error is acceptable here

    cs.close()
