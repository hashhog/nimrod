## KB-181: invalidateblock / reconsiderblock activate the most-work valid chain.
##
## Core's invalidateblock and reconsiderblock RPCs both end in
## ActivateBestChain (rpc/blockchain.cpp InvalidateBlock / ReconsiderBlock).
## That loop picks the best candidate by CBlockIndexWorkComparator (most work,
## then lowest nSequenceId, i.e. first received), connects toward it one block
## at a time, marks the first block that fails ConnectBlock invalid, and keeps
## the valid prefix it already connected. nimrod's invalidateblock activated
## nothing, and its reconsiderblock only took a strictly heavier branch as a
## whole, so the core-regtest failed_reorg group disagreed with Core:
##
##   B  side branch 3'-4'-5'' with 5'' invalid, invalidateblock 4a:
##      Core connects 3'-4', fails 5'', ends on 4' (height 9 in the harness);
##      nimrod stayed on 3a (8), and still did after a restart.
##   C  invalidateblock 4a with an equal-work side branch: Core moves to 4';
##      reconsiderblock 4a: 4a was received first, so Core returns to it.
##   E  as C with a restart in between: a restart resets the sequence ids and
##      the loaded tip's chain wins ties (SEQ_ID_BEST_CHAIN_FROM_DISK), so Core
##      stays on 4'.
##
## Every block here is built the way the harness builds them
## (tools/core-regtest/harness/scenarios/failed_reorg.py): OP_TRUE coinbases,
## and a bad block's coinbase claims 51 BTC against a 50 BTC subsidy, so it
## fails bad-cb-amount at connect time only. The adversarial cases at the end
## check that the new activation never connects past an invalid block, never
## takes a branch with less work, and skips a candidate it cannot connect.

import unittest2
import std/[options, os, json, strutils]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
from ../src/network/sync import validateHeaderPoW

const EASY_BITS = 0x207fffff'u32
const BASE_TIME = 1_700_000_000'u32
const COIN = 100_000_000'i64

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc displayHex(h: BlockHash): string =
  let a = array[32, byte](h)
  var r: array[32, byte]
  for i in 0 ..< 32: r[i] = a[31 - i]
  hexOf(r)

proc mkBlock(prev: BlockHash, height: int32, tag: byte, bad = false,
             offset = 0'u32): Block =
  ## Same shape as the harness: time BASE_TIME + height (+1 on side blocks),
  ## a tag byte in the coinbase so siblings differ, 51 BTC when `bad`.
  let value = if bad: 51 * COIN else: 50 * COIN
  let cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x02), 0xF7, tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)
  var hdr = BlockHeader(version: 0x20000000'i32, prevBlock: prev,
                        merkleRoot: merkleRoot(@[array[32, byte](cb.txid())]),
                        timestamp: BASE_TIME + uint32(height) + offset,
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb])

type Node = object
  path: string
  params: ConsensusParams
  cs: ChainState
  rpc: RpcServer

proc attach(n: var Node) =
  n.rpc = newRpcServer(port = 18443'u16, chainState = n.cs,
                       mempool = newMempool(n.cs, n.params),
                       peerManager = nil, feeEstimator = newFeeEstimator(),
                       params = n.params)

proc openNode(name: string): Node =
  result.path = getTempDir() / ("nimrod_kb181_" & name)
  removeDir(result.path)
  result.params = regtestParams()
  result.cs = newChainState(result.path, result.params)
  doAssert result.cs.connectBlock(buildGenesisBlock(result.params), 0'i32).isOk
  result.attach()

proc restart(n: var Node) =
  ## Same datadir, fresh process state: what the harness's restart does.
  n.cs.close()
  n.cs = newChainState(n.path, n.params)
  n.attach()

proc shut(n: var Node) =
  n.cs.close()
  removeDir(n.path)

proc submit(n: Node, b: Block): JsonNode =
  n.rpc.handleMethod("submitblock", %*[hexOf(serialize(b))])

proc invalidate(n: Node, h: BlockHash) =
  discard n.rpc.handleMethod("invalidateblock", %*[displayHex(h)])

proc reconsider(n: Node, h: BlockHash) =
  discard n.rpc.handleMethod("reconsiderblock", %*[displayHex(h)])

proc tip(n: Node): BlockHash = n.cs.bestBlockHash

proc height(n: Node): int =
  n.rpc.handleMethod("getblockcount", %*[]).getInt()

proc failedOnDisk(n: Node, h: BlockHash): bool =
  let idx = n.cs.db.getBlockIndex(h)
  idx.isSome and idx.get().failureFlags.isFailed()

proc mainChain(n: Node, upTo: int32, tagBase: byte): seq[Block] =
  ## Blocks 1..upTo on genesis, each submitted and connected.
  var prev = n.params.genesisBlockHash
  for h in 1'i32 .. upTo:
    let b = mkBlock(prev, h, tagBase + byte(h))
    doAssert n.submit(b).kind == JNull, "main block " & $h & " not connected"
    result.add(b)
    prev = hashOf(b)

suite "KB-181 failed_reorg: invalidateblock / reconsiderblock activate the best chain":

  test "B: invalidateblock connects the valid prefix of a side branch whose tip is invalid":
    var n = openNode("b")
    defer: n.shut()
    # G-1-2-3a-4a-5a, and 3'-4'-5'' off 2 (5'' pays 51 BTC), submitted while
    # 5a is the tip, so nothing on the side branch has been connected.
    let m = n.mainChain(5, 0x30)
    let s3 = mkBlock(hashOf(m[1]), 3, 0x43, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0x44, offset = 1)
    let s5bad = mkBlock(hashOf(s4), 5, 0x45, bad = true, offset = 1)
    for b in [s3, s4, s5bad]:
      discard n.submit(b)
    check n.tip == hashOf(m[4])

    n.invalidate(hashOf(m[3]))
    # Core: 5'' is the most-work candidate, fails bad-cb-amount, and 4' (more
    # work than 3a) is kept.
    check n.tip == hashOf(s4)
    check n.height == 4
    check n.failedOnDisk(hashOf(s5bad))
    check not n.failedOnDisk(hashOf(s4))
    check not n.failedOnDisk(hashOf(s3))

  test "B: the activated side branch and the failed block survive a restart":
    var n = openNode("b_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x30)
    let s3 = mkBlock(hashOf(m[1]), 3, 0x43, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0x44, offset = 1)
    let s5bad = mkBlock(hashOf(s4), 5, 0x45, bad = true, offset = 1)
    for b in [s3, s4, s5bad]:
      discard n.submit(b)
    n.invalidate(hashOf(m[3]))
    n.restart()
    check n.tip == hashOf(s4)
    check n.height == 4
    # The invalid block stays failed across the restart and is never
    # reconnected, whether resubmitted or offered by a reconsider of 4a.
    check n.failedOnDisk(hashOf(s5bad))
    check n.submit(s5bad).getStr() == "duplicate-invalid"
    check n.tip == hashOf(s4)

  test "C: reconsiderblock returns to the first-received block on an equal-work tie":
    var n = openNode("c")
    defer: n.shut()
    let m = n.mainChain(4, 0x50)
    let s3 = mkBlock(hashOf(m[1]), 3, 0x63, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0x64, offset = 1)
    for b in [s3, s4]:
      discard n.submit(b)
    check n.tip == hashOf(m[3])

    n.invalidate(hashOf(m[3]))
    check n.tip == hashOf(s4)          # Core: 4' has more work than 3a
    check n.height == 4

    n.reconsider(hashOf(m[3]))
    check n.tip == hashOf(m[3])        # Core: equal work, 4a received first
    check n.height == 4

  test "D: reconsiderblock stays on a heavier side branch":
    var n = openNode("d")
    defer: n.shut()
    let m = n.mainChain(4, 0x70)
    n.invalidate(hashOf(m[3]))
    check n.tip == hashOf(m[2])
    let s3 = mkBlock(hashOf(m[1]), 3, 0x83, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0x84, offset = 1)
    let s5 = mkBlock(hashOf(s4), 5, 0x85, offset = 1)
    for b in [s3, s4, s5]:
      discard n.submit(b)
    check n.tip == hashOf(s5)
    n.reconsider(hashOf(m[3]))
    check n.tip == hashOf(s5)
    check n.height == 5

  test "E: after a restart the loaded tip wins the tie and reconsiderblock keeps it":
    var n = openNode("e")
    defer: n.shut()
    let m = n.mainChain(4, 0x90)
    let s3 = mkBlock(hashOf(m[1]), 3, 0xA3, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0xA4, offset = 1)
    for b in [s3, s4]:
      discard n.submit(b)
    n.invalidate(hashOf(m[3]))
    check n.tip == hashOf(s4)
    n.restart()
    check n.tip == hashOf(s4)
    n.reconsider(hashOf(m[3]))
    check n.tip == hashOf(s4)          # Core: SEQ_ID_BEST_CHAIN_FROM_DISK
    check not n.failedOnDisk(hashOf(m[3]))
    n.restart()
    check n.tip == hashOf(s4)
    check n.height == 4

suite "KB-181 adversarial: activation never connects past an invalid block":

  test "an invalid block in the middle of a heavier side branch stops it; the tip stays valid":
    var n = openNode("mid_bad")
    defer: n.shut()
    let m = n.mainChain(4, 0x10)
    # 3'' is invalid (51 BTC); 4'' and 5'' on top of it carry more work.
    let s3bad = mkBlock(hashOf(m[1]), 3, 0xB3, bad = true, offset = 1)
    let s4 = mkBlock(hashOf(s3bad), 4, 0xB4, offset = 1)
    let s5 = mkBlock(hashOf(s4), 5, 0xB5, offset = 1)
    for b in [s3bad, s4, s5]:
      discard n.submit(b)
    check n.tip == hashOf(m[3])
    n.invalidate(hashOf(m[3]))
    check n.tip == hashOf(m[2])
    check n.height == 3
    check n.failedOnDisk(hashOf(s3bad))
    check n.failedOnDisk(hashOf(s4))
    check n.failedOnDisk(hashOf(s5))
    n.restart()
    check n.tip == hashOf(m[2])
    n.reconsider(hashOf(m[3]))
    check n.tip == hashOf(m[3])

  test "a side branch with less work than the new tip is not activated":
    var n = openNode("less_work")
    defer: n.shut()
    let m = n.mainChain(5, 0x20)
    let s3 = mkBlock(hashOf(m[1]), 3, 0xC3, offset = 1)
    discard n.submit(s3)
    n.invalidate(hashOf(m[4]))
    # 4 has more work than 3', so the tip is 4, not the side branch.
    check n.tip == hashOf(m[3])
    check n.height == 4

  test "invalidating a block off the active chain does not move the tip":
    var n = openNode("off_chain")
    defer: n.shut()
    let m = n.mainChain(3, 0x28)
    let s2 = mkBlock(hashOf(m[0]), 2, 0xC8, offset = 1)
    discard n.submit(s2)
    n.invalidate(hashOf(s2))
    check n.tip == hashOf(m[2])
    check n.failedOnDisk(hashOf(s2))

  test "a candidate whose branch has a missing body is skipped for the next best":
    var n = openNode("missing_body")
    defer: n.shut()
    let m = n.mainChain(4, 0x38)
    # Header-only 3h, and a body for its child 4h: 4h has the most work of any
    # stored body but cannot be connected (3h has no data). Core: not a
    # candidate (no HaveNumChainTxs). 3'-4' off 2 is the best connectable one.
    let h3 = mkBlock(hashOf(m[1]), 3, 0xD3, offset = 2)
    let h4 = mkBlock(hashOf(h3), 4, 0xD4, offset = 2)
    let h5 = mkBlock(hashOf(h4), 5, 0xD5, offset = 2)
    discard n.rpc.handleMethod("submitheader", %*[hexOf(serialize(h3.header))])
    discard n.submit(h4)
    discard n.submit(h5)
    let s3 = mkBlock(hashOf(m[1]), 3, 0xE3, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0xE4, offset = 1)
    for b in [s3, s4]:
      discard n.submit(b)
    check n.cs.db.hasBlockBody(hashOf(h5))
    check not n.cs.db.hasBlockBody(hashOf(h3))
    n.invalidate(hashOf(m[3]))
    check n.tip == hashOf(s4)
    check n.height == 4
    # Neither the unconnectable branch nor its blocks were condemned.
    check not n.failedOnDisk(hashOf(h4))
    check not n.failedOnDisk(hashOf(h5))
