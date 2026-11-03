## getblockchaininfo.headers survives a restart, the way Core's m_best_header
## does.
##
## Core rebuilds m_best_header from the stored block index when it loads it
## (validation.cpp ChainstateManager::LoadBlockIndex: the most-work index entry
## that IsValid(BLOCK_VALID_TREE), i.e. not BLOCK_FAILED_VALID) and recomputes
## it the same way in RecalculateBestHeader (start at the active tip, take any
## non-failed entry with more chain work). A header admitted by submitheader is
## in the index, so after a restart `headers` still counts it.
##
## nimrod tracked submitheader's best header only in memory
## (RpcServer.submittedHeaderHeight), so a restart dropped `headers` back to
## the connected tip: core-regtest rows
## warden_invalidated_submit/restart/info:headers (Core 210, nimrod 208) and
## warden_invalidated_submit/p2p-header/info:headers (Core 210, nimrod 209).
##
## Consensus guard: an entry that failed validation, or that descends from one,
## must not count as the best header.

import unittest2
import std/[os, json]
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
  ## OP_TRUE coinbase; `bad` pays 51 BTC and fails bad-cb-amount on connect.
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
  result.path = getTempDir() / ("nimrod_besthdr_" & name)
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

proc submitHeader(n: Node, b: Block): JsonNode =
  n.rpc.handleMethod("submitheader", %*[hexOf(serialize(b.header))])

proc headers(n: Node): int =
  n.rpc.handleMethod("getblockchaininfo", %*[])["headers"].getInt()

proc mainChain(n: Node, upTo: int32, tagBase: byte): seq[Block] =
  var prev = n.params.genesisBlockHash
  for h in 1'i32 .. upTo:
    let b = mkBlock(prev, h, tagBase + byte(h))
    doAssert n.submit(b).kind == JNull, "main block " & $h & " not connected"
    result.add(b)
    prev = hashOf(b)

suite "getblockchaininfo.headers is rebuilt from the block index on restart like Core":

  test "headers past the tip from submitheader still count after a restart":
    var n = openNode("submitheader_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let h6 = mkBlock(hashOf(m[4]), 6, 0x16)
    let h7 = mkBlock(hashOf(h6), 7, 0x17)
    check n.submitHeader(h6).kind == JNull
    check n.submitHeader(h7).kind == JNull
    check n.headers() == 7
    n.restart()
    check n.cs.bestHeight == 5
    check n.headers() == 7

  test "a lower header pushed after the restart does not lower headers":
    # The p2p-header row: after the restart a header at tip+1 arrives on
    # another branch; Core's m_best_header stays at the stored tip+2 header.
    var n = openNode("lower_after_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x20)
    let h6 = mkBlock(hashOf(m[4]), 6, 0x26)
    let h7 = mkBlock(hashOf(h6), 7, 0x27)
    check n.submitHeader(h6).kind == JNull
    check n.submitHeader(h7).kind == JNull
    n.restart()
    let other = mkBlock(hashOf(m[4]), 6, 0x28)
    check n.submitHeader(other).kind == JNull
    check n.headers() == 7

  test "a block that failed to connect does not count as the best header after a restart":
    var n = openNode("failed_block_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x30)
    let bad = mkBlock(hashOf(m[4]), 6, 0x36, bad = true)
    check n.submit(bad).getStr() == "bad-cb-amount"
    n.restart()
    check n.headers() == 5

  test "an invalidated header and its descendant headers do not count after a restart":
    var n = openNode("invalidated_header_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x40)
    let h6 = mkBlock(hashOf(m[4]), 6, 0x46)
    let h7 = mkBlock(hashOf(h6), 7, 0x47)
    check n.submitHeader(h6).kind == JNull
    check n.submitHeader(h7).kind == JNull
    discard n.rpc.handleMethod("invalidateblock", %*[displayHex(hashOf(h6))])
    n.restart()
    check n.cs.bestHeight == 5
    check n.headers() == 5

  test "a lower-work header fork does not raise headers after a restart":
    var n = openNode("lower_fork_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x50)
    let f3 = mkBlock(hashOf(m[1]), 3, 0x53)
    let f4 = mkBlock(hashOf(f3), 4, 0x54)
    check n.submitHeader(f3).kind == JNull
    check n.submitHeader(f4).kind == JNull
    n.restart()
    check n.headers() == 5
