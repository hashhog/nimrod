## A block that extends the active tip and fails to connect stays in the
## block index as BLOCK_FAILED_VALID, the way Core keeps it.
##
## Core adds a submitted block to m_block_index in AcceptBlockHeader and
## writes it in AcceptBlock before ConnectTip runs ConnectBlock. When the
## block fails AcceptBlock's ContextualCheckBlock or ConnectBlock, Core marks
## it BLOCK_FAILED_VALID (validation.cpp AcceptBlock / InvalidBlockFound), so:
##   * getchaintips lists it with status "invalid", branchlen 1;
##   * resubmitting it answers "duplicate-invalid" (AcceptBlockHeader,
##     BLOCK_CACHED_INVALID);
##   * a child of it answers "bad-prevblk" (BLOCK_INVALID_PREV).
## nimrod recorded the failure only on the reorg path. On the direct
## extend-the-tip path of submitblock it returned the reject token and kept
## nothing, so 40 core-regtest rows (chain/tips/final,
## seed|warden_invalidated_submit/*/tips) were one invalid tip short.
##
## Consensus guard: a copy of a valid block whose body does not match its
## header commitments (Core BLOCK_MUTATED) must not mark the block's hash, or
## the real block could never be connected.

import unittest2
import std/[options, os, json, tables]
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

proc mkBlock(prev: BlockHash, height: int32, tag: byte, bad = false): Block =
  ## OP_TRUE coinbase; `bad` pays 51 BTC, which fails bad-cb-amount only when
  ## the block is connected (the harness's chain/tips/final block).
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
                        timestamp: BASE_TIME + uint32(height),
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
  result.path = getTempDir() / ("nimrod_failconnect_" & name)
  removeDir(result.path)
  result.params = regtestParams()
  result.cs = newChainState(result.path, result.params)
  doAssert result.cs.connectBlock(buildGenesisBlock(result.params), 0'i32).isOk
  result.attach()

proc restart(n: var Node) =
  n.cs.close()
  n.cs = newChainState(n.path, n.params)
  n.attach()

proc shut(n: var Node) =
  n.cs.close()
  removeDir(n.path)

proc submit(n: Node, b: Block): JsonNode =
  n.rpc.handleMethod("submitblock", %*[hexOf(serialize(b))])

proc mainChain(n: Node, upTo: int32, tagBase: byte): seq[Block] =
  var prev = n.params.genesisBlockHash
  for h in 1'i32 .. upTo:
    let b = mkBlock(prev, h, tagBase + byte(h))
    doAssert n.submit(b).kind == JNull, "main block " & $h & " not connected"
    result.add(b)
    prev = hashOf(b)

type TipRow = tuple[height: int, branchlen: int, status: string]

proc tips(n: Node): Table[string, TipRow] =
  ## getchaintips keyed by display hash, the way the harness compares it.
  for t in n.rpc.handleMethod("getchaintips", %*[]):
    result[t["hash"].getStr()] = (height: t["height"].getInt(),
                                  branchlen: t["branchlen"].getInt(),
                                  status: t["status"].getStr())

proc row(height, branchlen: int, status: string): TipRow =
  (height: height, branchlen: branchlen, status: status)

suite "submitblock keeps a failed tip extension as an invalid tip like Core":

  test "a tip extension that fails bad-cb-amount is listed as an invalid tip":
    var n = openNode("cb_amount")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let bad = mkBlock(hashOf(m[4]), 6, 0x16, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    check n.cs.bestBlockHash == hashOf(m[4])
    check n.cs.bestHeight == 5
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[4]))] == row(5, 0, "active")
    check t.hasKey(displayHex(hashOf(bad)))
    if t.hasKey(displayHex(hashOf(bad))):
      check t[displayHex(hashOf(bad))] == row(6, 1, "invalid")

  test "the failed tip extension is still an invalid tip after a restart":
    var n = openNode("cb_amount_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x20)
    let bad = mkBlock(hashOf(m[4]), 6, 0x26, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    n.restart()
    check n.cs.bestBlockHash == hashOf(m[4])
    let t = n.tips()
    check t.len == 2
    check t.hasKey(displayHex(hashOf(bad)))
    if t.hasKey(displayHex(hashOf(bad))):
      check t[displayHex(hashOf(bad))] == row(6, 1, "invalid")

  test "resubmitting the failed tip extension answers duplicate-invalid":
    var n = openNode("dup_invalid")
    defer: n.shut()
    let m = n.mainChain(3, 0x30)
    let bad = mkBlock(hashOf(m[2]), 4, 0x34, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    check n.submit(bad).getStr() == "duplicate-invalid"

  test "a child of the failed tip extension answers bad-prevblk":
    var n = openNode("bad_prevblk")
    defer: n.shut()
    let m = n.mainChain(3, 0x40)
    let bad = mkBlock(hashOf(m[2]), 4, 0x44, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    let child = mkBlock(hashOf(bad), 5, 0x45)
    check n.submit(child).getStr() == "bad-prevblk"
    check n.cs.bestHeight == 3

  test "a valid sibling of the failed block still connects on top of the tip":
    # Valid -> invalid guard: marking the failed block must not touch its
    # parent or a valid block at the same height.
    var n = openNode("valid_sibling")
    defer: n.shut()
    let m = n.mainChain(3, 0x50)
    let bad = mkBlock(hashOf(m[2]), 4, 0x54, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    let good = mkBlock(hashOf(m[2]), 4, 0x55)
    check n.submit(good).kind == JNull
    check n.cs.bestBlockHash == hashOf(good)
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(good))] == row(4, 0, "active")
    check t[displayHex(hashOf(bad))] == row(4, 1, "invalid")

  test "a mutated copy of a valid block marks nothing and the real block connects":
    # Core BLOCK_MUTATED: the copy carries a coinbase witness with no witness
    # commitment ("unexpected-witness"). That is a verdict on this copy, not on
    # the hash, so the hash must not be recorded as failed.
    var n = openNode("mutated")
    defer: n.shut()
    let m = n.mainChain(3, 0x60)
    let good = mkBlock(hashOf(m[2]), 4, 0x64)
    var mutated = good
    mutated.txs[0].witnesses = @[@[newSeq[byte](32)]]
    check hashOf(mutated) == hashOf(good)
    check n.submit(mutated).getStr() != ""
    check n.cs.bestHeight == 3
    check n.cs.db.getBlockIndex(hashOf(good)).isNone or
          not n.cs.db.getBlockIndex(hashOf(good)).get().failureFlags.isFailed()
    check n.tips().len == 1
    check n.submit(good).kind == JNull
    check n.cs.bestBlockHash == hashOf(good)

  test "a header-level reject (time-too-old) adds no tip":
    # Core rejects ContextualCheckBlockHeader failures in AcceptBlockHeader,
    # before the block enters m_block_index.
    var n = openNode("time_too_old")
    defer: n.shut()
    let m = n.mainChain(3, 0x70)
    var old = mkBlock(hashOf(m[2]), 4, 0x74)
    old.header.timestamp = BASE_TIME
    while not validateHeaderPoW(old.header):
      old.header.nonce += 1
    check n.submit(old).getStr() == "time-too-old"
    check n.tips().len == 1
    check n.cs.db.getBlockIndex(hashOf(old)).isNone
