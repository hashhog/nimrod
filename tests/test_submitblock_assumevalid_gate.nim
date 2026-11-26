## submitblock skips script checks only through the full assumevalid gate
## (2026-11-24 Neon audit of nimrod, finding 11).
##
## Core's ConnectBlock skips scripts only when the assumevalid block is in the
## block index, the block being connected is an ancestor of BOTH it and the best
## header, the best header has minimum chain work, and the block is more than two
## weeks of work below the best header (validation.cpp:2355-2383 in v31.1).
## nimrod's P2P path already applies that gate (computeSkipScripts), but
## handleSubmitBlock used a bare `height <= assumeValidHeight`. On mainnet,
## testnet3 and testnet4 a node below the assumevalid height therefore accepted
## a submitted block whose scripts fail, where Core rejects it.
##
## Regtest has no assumevalid block, so the test gives the regtest params an
## assumevalid height (200) and a hash that is not in the block index, which is
## exactly the state of a mainnet node in IBD that has not seen that block.

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

proc mkBlock(prev: BlockHash, height: int32, cbSpk: seq[byte],
             extra: seq[Transaction] = @[]): Block =
  let cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x01), 0xA5],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(50 * COIN), scriptPubKey: cbSpk)],
    witnesses: @[], lockTime: 0)
  var txs = @[cb] & extra
  var ids: seq[array[32, byte]]
  for t in txs: ids.add array[32, byte](t.txid())
  var hdr = BlockHeader(version: 0x20000000'i32, prevBlock: prev,
                        merkleRoot: merkleRoot(ids),
                        timestamp: BASE_TIME + uint32(height),
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: txs)

type Node = object
  path: string
  params: ConsensusParams
  cs: ChainState
  rpc: RpcServer

proc openNode(name: string, assumeValidHeight: int32): Node =
  result.path = getTempDir() / ("nimrod_neon_submitav_" & name)
  removeDir(result.path)
  result.params = regtestParams()
  if assumeValidHeight > 0:
    var fake: array[32, byte]
    fake[0] = 0xAB
    fake[31] = 0x01
    result.params.assumeValidBlockHash = BlockHash(fake)
    result.params.assumeValidHeight = assumeValidHeight
  result.cs = newChainState(result.path, result.params)
  doAssert result.cs.connectBlock(buildGenesisBlock(result.params), 0'i32).isOk
  result.rpc = newRpcServer(port = 18443'u16, chainState = result.cs,
                            mempool = newMempool(result.cs, result.params),
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = result.params)

proc shut(n: var Node) =
  n.cs.close()
  removeDir(n.path)

proc submit(n: Node, b: Block): JsonNode =
  n.rpc.handleMethod("submitblock", %*[hexOf(serialize(b))])

proc badSpendScenario(n: Node): tuple[res: JsonNode, tipBefore: int32,
                                       badHash: BlockHash] =
  ## Block 1's coinbase pays to OP_0, which no scriptSig can satisfy with an
  ## empty stack. Blocks 2..101 mature it; block 102 spends it with an EMPTY
  ## scriptSig: the script leaves "" on the stack -> EVAL_FALSE in Core.
  let b1 = mkBlock(n.params.genesisBlockHash, 1, @[0x00'u8])
  doAssert n.submit(b1).kind == JNull
  var prev = hashOf(b1)
  for h in 2'i32 .. 101'i32:
    let b = mkBlock(prev, h, @[0x51'u8])
    doAssert n.submit(b).kind == JNull, "block " & $h
    prev = hashOf(b)
  let spend = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: b1.txs[0].txid(), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(49 * COIN), scriptPubKey: @[0x51'u8])],
    witnesses: @[], lockTime: 0)
  let bad = mkBlock(prev, 102, @[0x51'u8], @[spend])
  let before = n.cs.bestHeight
  (res: n.submit(bad), tipBefore: before, badHash: hashOf(bad))

suite "N11 submitblock assumevalid uses the full ancestor gate":
  test "N11a: below assumeValidHeight, assumevalid block unknown: scripts are checked":
    var n = openNode("unknown_av", 200)
    defer: n.shut()
    let r = badSpendScenario(n)
    check r.res.kind == JString           # rejected (master: null = accepted)
    check n.cs.bestHeight == r.tipBefore  # tip did not advance to 102
    check n.cs.bestBlockHash != r.badHash

  test "N11b: control: with no assumevalid at all the same block is rejected":
    var n = openNode("no_av", 0)
    defer: n.shut()
    let r = badSpendScenario(n)
    check r.res.kind == JString
    check n.cs.bestHeight == r.tipBefore
    check n.cs.bestBlockHash != r.badHash

  test "N11c: control: valid blocks below assumeValidHeight still connect":
    var n = openNode("valid_av", 200)
    defer: n.shut()
    var prev = n.params.genesisBlockHash
    for h in 1'i32 .. 5'i32:
      let b = mkBlock(prev, h, @[0x51'u8])
      check n.submit(b).kind == JNull
      prev = hashOf(b)
    check n.cs.bestHeight == 5
