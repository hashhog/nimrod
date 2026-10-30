## submitblock of a block whose parent is unknown answers "prev-blk-not-found".
##
## Core AcceptBlockHeader (validation.cpp) fails a header whose hashPrevBlock
## is not in the block index with
##   state.Invalid(BLOCK_MISSING_PREV, "prev-blk-not-found")
## and submitblock reports that reason (rpc/mining.cpp BIP22ValidationResult).
## nimrod answered the generic "rejected" (core-regtest row
## chain/submit/prev-not-found:$). The block was rejected either way; this is
## reason-token parity on the acceptance path.
##
## Adversarial cases: the token change must not turn a missing parent into a
## verdict on the block (no mark, no punishment), must not store the orphan,
## and must leave the neighbouring answers alone: a valid block on a known
## parent is still accepted, a resubmitted block is still "duplicate", a
## known-parent fork is still "inconclusive", and a body that fails CheckBlock
## still reports its own reason first (Core runs CheckBlock before
## AcceptBlockHeader looks up the parent).

import unittest2
import std/[options, os, json]
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

proc mkBlock(prev: BlockHash, height: int32, tag: byte, bad = false,
             badMerkle = false): Block =
  ## OP_TRUE coinbase, a tag byte so siblings differ, 51 BTC when `bad`
  ## (fails bad-cb-amount at connect time only).
  let value = if bad: 51 * COIN else: 50 * COIN
  let cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x02), 0xF7, tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)
  var root = merkleRoot(@[array[32, byte](cb.txid())])
  if badMerkle:
    root[0] = root[0] xor 0x01
  var hdr = BlockHeader(version: 0x20000000'i32, prevBlock: prev,
                        merkleRoot: root,
                        timestamp: BASE_TIME + uint32(height),
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb])

proc unknownParent(): BlockHash =
  ## A 32-byte parent that is neither genesis nor any block built here
  ## (the core-regtest harness uses 0x11 * 32 the same way).
  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = 0x11
  BlockHash(a)

type Node = object
  path: string
  params: ConsensusParams
  cs: ChainState
  rpc: RpcServer

proc openNode(name: string): Node =
  result.path = getTempDir() / ("nimrod_prevblk_" & name)
  removeDir(result.path)
  result.params = regtestParams()
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

suite "submitblock prev-blk-not-found (Core BLOCK_MISSING_PREV)":

  test "unknown parent answers prev-blk-not-found":
    var n = openNode("unknown")
    let b1 = mkBlock(n.params.genesisBlockHash, 1, 0x01)
    check n.submit(b1).kind == JNull
    let tipBefore = n.cs.bestBlockHash
    let orphan = mkBlock(unknownParent(), 1, 0x22)
    let r = n.submit(orphan)
    check r.kind == JString
    check r.getStr() == "prev-blk-not-found"
    # Not stored, not marked, tip unchanged.
    check n.cs.db.getBlockIndex(hashOf(orphan)).isNone
    check n.cs.bestBlockHash == tipBefore
    check n.cs.bestHeight == 1
    # Resubmitting is the same answer, not "duplicate": nothing was kept.
    check n.submit(orphan).getStr() == "prev-blk-not-found"
    n.shut()

  test "unknown parent with a connect-invalid body still answers prev-blk-not-found":
    # bad-cb-amount is a ConnectBlock check; Core never gets that far without
    # the parent, so the missing parent is the reason it reports.
    var n = openNode("unknown_bad")
    let orphan = mkBlock(unknownParent(), 1, 0x23, bad = true)
    check n.submit(orphan).getStr() == "prev-blk-not-found"
    check n.cs.db.getBlockIndex(hashOf(orphan)).isNone
    check n.cs.bestHeight == 0
    n.shut()

  test "unknown parent with a bad merkle root reports CheckBlock's reason first":
    var n = openNode("unknown_merkle")
    let orphan = mkBlock(unknownParent(), 1, 0x24, badMerkle = true)
    check n.submit(orphan).getStr() == "bad-txnmrklroot"
    check n.cs.bestHeight == 0
    n.shut()

  test "valid block on a known parent is still accepted":
    var n = openNode("valid")
    let b1 = mkBlock(n.params.genesisBlockHash, 1, 0x01)
    check n.submit(b1).kind == JNull
    let b2 = mkBlock(hashOf(b1), 2, 0x02)
    check n.submit(b2).kind == JNull
    check n.cs.bestBlockHash == hashOf(b2)
    check n.cs.bestHeight == 2
    n.shut()

  test "resubmitted active block is still duplicate":
    var n = openNode("dup")
    let b1 = mkBlock(n.params.genesisBlockHash, 1, 0x01)
    check n.submit(b1).kind == JNull
    check n.submit(b1).getStr() == "duplicate"
    check n.cs.bestHeight == 1
    n.shut()

  test "known-parent equal-work fork is still inconclusive":
    var n = openNode("fork")
    let b1 = mkBlock(n.params.genesisBlockHash, 1, 0x01)
    check n.submit(b1).kind == JNull
    let side = mkBlock(n.params.genesisBlockHash, 1, 0x11)
    check n.submit(side).getStr() == "inconclusive"
    check n.cs.bestBlockHash == hashOf(b1)
    n.shut()

  test "the token is never a verdict on the block":
    check bip22String(vePrevBlockMissing) == "prev-blk-not-found"
    check blockFailureKind(vePrevBlockMissing) == bfkUndecided
    check blockFailureKindOfToken("prev-blk-not-found") == bfkUndecided
