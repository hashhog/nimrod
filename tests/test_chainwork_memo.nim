## computeChainwork memo (gate 3a: getblockchaininfo held the RPC thread).
##
## Live 2026-10-03: getblockchaininfo walked every block index row from the tip
## to genesis on each call — 12.7 s on mainnet, and a getblockcount sent 1 s
## later waited 11.7 s behind it (single-threaded RPC dispatch). The memo
## records the work of walked tips and of every 2016th height, and a later walk
## stops at the first recorded ancestor.
##
## Equivalence: with the memo cleared, computeChainwork is the old full walk.
## Every memo-assisted answer must equal that cold answer — on the active
## chain, across a side branch, and after the tip moves.
##
## Instrument check: the memo must actually be consulted. With genesis's index
## row deleted, a cold walk stops short (a different, partial number); a
## memo-assisted walk still returns the full work. If the memo were dead code
## the two would be equal and the check fails.
##
## CONTROL: nim c -r tests/test_chainwork_memo.nim

import unittest2
import std/[os]
import ../src/storage/[db, chainstate]
import ../src/storage/undo as undoModule
import ../src/consensus/[params, chain]
import ../src/primitives/types
import ../src/rpc/server

const TestDbPath = "/data/nvme1/hashhog-phaseb/review-logs/nimrod_chainwork_memo_test"

proc synthHash(branch: int, height: int32): BlockHash =
  var a: array[32, byte]
  a[0] = byte(branch + 1)
  a[1] = byte(height and 0xff)
  a[2] = byte((height shr 8) and 0xff)
  a[3] = byte((height shr 16) and 0xff)
  a[31] = 0x5a
  BlockHash(a)

proc bitsAt(height: int32): uint32 =
  ## A few distinct difficulties so the per-epoch proof actually varies.
  const table = [0x1d00ffff'u32, 0x1c7fff00'u32, 0x1b0404cb'u32, 0x1a05db8b'u32]
  table[(height div 2016) mod 4]

proc putIdx(cs: ChainState, hash, prev: BlockHash, height: int32, bits: uint32) =
  var hdr: BlockHeader
  hdr.prevBlock = prev
  hdr.bits = bits
  let idx = BlockIndex(
    hash: hash, height: height, status: bsValidated, prevHash: prev,
    header: hdr, totalWork: default(array[32, byte]),
    undoPos: undoModule.FlatFilePos(fileNum: -1, pos: -1),
    failureFlags: BLOCK_NO_FAILURE, sequenceId: 0, nTx: 1)
  cs.db.putBlockIndexHashOnly(idx)

proc cold(cs: ChainState, h: BlockHash, height: int32): array[32, byte] =
  resetChainworkMemo()
  result = computeChainwork(cs.db, h, height)
  resetChainworkMemo()

suite "computeChainwork memo":
  if dirExists(TestDbPath): removeDir(TestDbPath)
  var cs = newChainState(TestDbPath, testnet4Params())

  const N = 5000'i32
  const Fork = 4500'i32
  const SideLen = 600'i32
  var main: seq[BlockHash]
  for h in 0'i32 ..< N:
    let hash = synthHash(0, h)
    let prev = if h == 0: BlockHash(default(array[32, byte])) else: main[h - 1]
    cs.putIdx(hash, prev, h, bitsAt(h))
    main.add hash
  var side: seq[BlockHash]
  for i in 0'i32 ..< SideLen:
    let h = Fork + 1 + i
    let hash = synthHash(1, h)
    let prev = if i == 0: main[Fork] else: side[i - 1]
    cs.putIdx(hash, prev, h, bitsAt(h) xor 0x00000100'u32)
    side.add hash

  test "memo-assisted answers equal the cold full walk":
    let tip = N - 1
    let coldTip = cs.cold(main[tip], tip)
    resetChainworkMemo()
    check computeChainwork(cs.db, main[tip], tip) == coldTip   # populates
    check computeChainwork(cs.db, main[tip], tip) == coldTip   # memo hit
    for h in [0'i32, 1, 100, 2015, 2016, 2017, 4031, 4032, 4500, 4998]:
      let want = cs.cold(main[h], h)
      discard computeChainwork(cs.db, main[tip], tip)          # repopulate
      check computeChainwork(cs.db, main[h], h) == want
    let sideTip = Fork + SideLen
    let wantSide = cs.cold(side[^1], sideTip)
    discard computeChainwork(cs.db, main[tip], tip)
    check computeChainwork(cs.db, side[^1], sideTip) == wantSide
    check wantSide != coldTip

  test "tip advance: one new block on a memoized tip":
    let newH = N
    let newHash = synthHash(0, newH)
    cs.putIdx(newHash, main[^1], newH, bitsAt(newH))
    let want = cs.cold(newHash, newH)
    discard computeChainwork(cs.db, main[^1], N - 1)
    check computeChainwork(cs.db, newHash, newH) == want
    main.add newHash

  test "instrument: the memo is consulted (genesis row removed)":
    let tip = int32(main.len - 1)
    let full = cs.cold(main[tip], tip)
    discard computeChainwork(cs.db, main[tip], tip)            # memoize
    cs.db.db.delete(cfBlockIndex, blockKey(array[32, byte](main[0])))
    # A new block on top: the walk must stop at the memoized tip and
    # never needs genesis.
    let nh = tip + 1
    let nhash = synthHash(0, nh)
    cs.putIdx(nhash, main[tip], nh, bitsAt(nh))
    let viaMemo = computeChainwork(cs.db, nhash, nh)
    let coldPartial = cs.cold(nhash, nh)
    check viaMemo != coldPartial   # memo used: full work, not a partial sum
    check viaMemo != full          # one more block of work than the old tip
    # A partial walk must not be memoized: restore genesis, ask again.
    discard computeChainwork(cs.db, nhash, nh)                 # partial, memo empty
    cs.putIdx(main[0], BlockHash(default(array[32, byte])), 0, bitsAt(0))
    check computeChainwork(cs.db, nhash, nh) == viaMemo

  cs.close()
  removeDir(TestDbPath)
