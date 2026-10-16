## getchaintips lists side-branch tips the way Core does.
##
## Core's getchaintips (rpc/blockchain.cpp) reports the active tip plus every
## block off the active chain that no other block builds on, each with its
## branchlen (height above the fork point) and a status:
##   invalid        BLOCK_FAILED_VALID (invalidateblock, or failed to connect)
##   headers-only   the block or an off-chain ancestor has no body
##   valid-fork     connected once, then reorged out
##   valid-headers  body stored but never connected
## nimrod returned only the active tip, so every core-regtest getchaintips row
## with a side tip (failed_reorg, warden/seed_invalidated_submit,
## chain/invalidate, reorg/invalidate) disagreed with Core v31.1.
##
## Blocks are built the way tools/core-regtest/harness/scenarios/failed_reorg.py
## builds them: OP_TRUE coinbases, a tag byte so siblings differ, and a bad
## block pays 51 BTC so it fails bad-cb-amount only when connected.

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

proc mkBlock(prev: BlockHash, height: int32, tag: byte, bad = false,
             offset = 0'u32): Block =
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
  result.path = getTempDir() / ("nimrod_chaintips_" & name)
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

proc invalidate(n: Node, h: BlockHash) =
  discard n.rpc.handleMethod("invalidateblock", %*[displayHex(h)])

proc mainChain(n: Node, upTo: int32, tagBase: byte): seq[Block] =
  var prev = n.params.genesisBlockHash
  for h in 1'i32 .. upTo:
    let b = mkBlock(prev, h, tagBase + byte(h))
    doAssert n.submit(b).kind == JNull, "main block " & $h & " not connected"
    result.add(b)
    prev = hashOf(b)

type TipRow = tuple[height: int, branchlen: int, status: string]

proc tips(n: Node): Table[string, TipRow] =
  ## getchaintips as a map keyed by display hash, like the harness compares it.
  for t in n.rpc.handleMethod("getchaintips", %*[]):
    result[t["hash"].getStr()] = (height: t["height"].getInt(),
                                  branchlen: t["branchlen"].getInt(),
                                  status: t["status"].getStr())

proc row(height, branchlen: int, status: string): TipRow =
  (height: height, branchlen: branchlen, status: status)

suite "getchaintips lists side-branch tips like Core":

  test "an invalidated tip is listed as invalid with its branchlen":
    var n = openNode("invalid")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    n.invalidate(hashOf(m[3]))          # 4: 4 and 5 are failed, tip is 3
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[2]))] == row(3, 0, "active")
    check t[displayHex(hashOf(m[4]))] == row(5, 2, "invalid")

  test "an invalidated tip is still listed as invalid after a restart":
    var n = openNode("invalid_restart")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    n.invalidate(hashOf(m[3]))
    n.restart()
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[2]))] == row(3, 0, "active")
    check t[displayHex(hashOf(m[4]))] == row(5, 2, "invalid")

  test "failed_reorg B: both invalid branches are listed, before and after a restart":
    # G-1-2-3a-4a-5a, side 3'-4'-5'' off 2 with 5'' paying 51 BTC.
    # invalidateblock 4a: Core connects 3'-4', 5'' fails, tip is 4'.
    var n = openNode("b")
    defer: n.shut()
    let m = n.mainChain(5, 0x30)
    let s3 = mkBlock(hashOf(m[1]), 3, 0x43, offset = 1)
    let s4 = mkBlock(hashOf(s3), 4, 0x44, offset = 1)
    let s5bad = mkBlock(hashOf(s4), 5, 0x45, bad = true, offset = 1)
    for b in [s3, s4, s5bad]:
      discard n.submit(b)
    n.invalidate(hashOf(m[3]))
    check n.cs.bestBlockHash == hashOf(s4)
    for pass in 0 .. 1:
      if pass == 1: n.restart()
      let t = n.tips()
      check t.len == 3
      check t[displayHex(hashOf(s4))] == row(4, 0, "active")
      check t[displayHex(hashOf(m[4]))] == row(5, 3, "invalid")
      check t[displayHex(hashOf(s5bad))] == row(5, 1, "invalid")

  test "a stored side block that never connected is valid-headers":
    var n = openNode("valid_headers")
    defer: n.shut()
    let m = n.mainChain(3, 0x50)
    let s2 = mkBlock(hashOf(m[0]), 2, 0x62, offset = 1)
    check n.submit(s2).getStr() == "inconclusive"
    for pass in 0 .. 1:
      if pass == 1: n.restart()
      let t = n.tips()
      check t.len == 2
      check t[displayHex(hashOf(m[2]))] == row(3, 0, "active")
      check t[displayHex(hashOf(s2))] == row(2, 1, "valid-headers")

  test "a block reorged out by a heavier branch is valid-fork":
    var n = openNode("valid_fork")
    defer: n.shut()
    let m = n.mainChain(2, 0x70)
    let s2 = mkBlock(hashOf(m[0]), 2, 0x82, offset = 1)
    let s3 = mkBlock(hashOf(s2), 3, 0x83, offset = 1)
    discard n.submit(s2)
    check n.submit(s3).kind == JNull     # heavier: reorg onto 2'-3'
    check n.cs.bestBlockHash == hashOf(s3)
    for pass in 0 .. 1:
      if pass == 1: n.restart()
      let t = n.tips()
      check t.len == 2
      check t[displayHex(hashOf(s3))] == row(3, 0, "active")
      check t[displayHex(hashOf(m[1]))] == row(2, 1, "valid-fork")

  test "a side header without a body is headers-only":
    var n = openNode("headers_only")
    defer: n.shut()
    let m = n.mainChain(3, 0x90)
    let s2 = mkBlock(hashOf(m[0]), 2, 0xa2, offset = 1)
    let s3 = mkBlock(hashOf(s2), 3, 0xa3, offset = 1)
    # The body of 2' is stored, 3' is a header only: the tip is 3', and
    # Core reports it headers-only because its own body is missing.
    discard n.submit(s2)
    discard n.rpc.handleMethod("submitheader", %*[hexOf(serialize(s3.header))])
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[2]))] == row(3, 0, "active")
    check t[displayHex(hashOf(s3))] == row(3, 2, "headers-only")

  test "a stored valid-headers branch still activates once it has the most work":
    # Adversarial check for the side-branch status change (bsDataStored until
    # connected): chain selection must not depend on it. 2' is stored
    # without connecting, then 3' makes the branch heavier and it must win.
    var n = openNode("activates")
    defer: n.shut()
    let m = n.mainChain(2, 0xb0)
    let s2 = mkBlock(hashOf(m[0]), 2, 0xc2, offset = 1)
    check n.submit(s2).getStr() == "inconclusive"
    n.restart()
    let s3 = mkBlock(hashOf(s2), 3, 0xc3, offset = 1)
    check n.submit(s3).kind == JNull
    check n.cs.bestBlockHash == hashOf(s3)
    let idx = n.cs.db.getBlockIndex(hashOf(s2))
    check idx.isSome and idx.get().status == bsValidated
    let t = n.tips()
    check t[displayHex(hashOf(m[1]))] == row(2, 1, "valid-fork")

  test "an invalid side block is never activated and stays listed invalid":
    # A side branch whose only extra block fails to connect: the tip must
    # stay on the valid chain and the bad block is reported invalid.
    var n = openNode("invalid_side")
    defer: n.shut()
    let m = n.mainChain(2, 0xd0)
    let s2 = mkBlock(hashOf(m[0]), 2, 0xe2, offset = 1)
    let s3bad = mkBlock(hashOf(s2), 3, 0xe3, bad = true, offset = 1)
    discard n.submit(s2)
    discard n.submit(s3bad)
    check n.cs.bestBlockHash == hashOf(m[1])
    let t = n.tips()
    check t[displayHex(hashOf(m[1]))] == row(2, 0, "active")
    check t[displayHex(hashOf(s3bad))] == row(3, 2, "invalid")

  test "a heavier side block that fails to connect is marked invalid, also after a restart":
    # failed_reorg A: 2' has the same work as 2, 3'' (51 BTC) makes the side
    # branch heavier; the reorg fails bad-cb-amount. Core marks 3'' invalid
    # and stays on 2; a resubmit is duplicate-invalid.
    var n = openNode("failed_connect_restart")
    defer: n.shut()
    let m = n.mainChain(2, 0xf0)
    let s2 = mkBlock(hashOf(m[0]), 2, 0xf2, offset = 1)
    let s3bad = mkBlock(hashOf(s2), 3, 0xf3, bad = true, offset = 1)
    discard n.submit(s2)
    check n.submit(s3bad).getStr() == "bad-cb-amount"
    check n.cs.bestBlockHash == hashOf(m[1])
    n.restart()
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[1]))] == row(2, 0, "active")
    check t[displayHex(hashOf(s3bad))] == row(3, 2, "invalid")
    check n.submit(s3bad).getStr() == "duplicate-invalid"
    check n.cs.bestBlockHash == hashOf(m[1])
    # The valid prefix 2' is not condemned with it.
    let s2idx = n.cs.db.getBlockIndex(hashOf(s2))
    check s2idx.isSome and not s2idx.get().failureFlags.isFailed()

  test "submitheader on an invalidated parent is bad-prevblk and adds no tip":
    var n = openNode("hdr_failed_parent")
    defer: n.shut()
    let m = n.mainChain(3, 0x05)
    n.invalidate(hashOf(m[2]))            # 3 is invalid, tip is 2
    let child = mkBlock(hashOf(m[2]), 4, 0x06)
    expect RpcError:
      discard n.rpc.handleMethod("submitheader", %*[hexOf(serialize(child.header))])
    try:
      discard n.rpc.handleMethod("submitheader", %*[hexOf(serialize(child.header))])
    except RpcError as e:
      check e.msg == "bad-prevblk"
    check n.cs.db.getBlockIndex(hashOf(child)).isNone
    let t = n.tips()
    check t.len == 2
    check t[displayHex(hashOf(m[1]))] == row(2, 0, "active")
    check t[displayHex(hashOf(m[2]))] == row(3, 1, "invalid")
    # A known header that is itself invalid: duplicate-invalid.
    try:
      discard n.rpc.handleMethod("submitheader", %*[hexOf(serialize(m[2].header))])
      check false
    except RpcError as e:
      check e.msg == "duplicate-invalid"

  test "submitheader on a valid parent is still accepted":
    var n = openNode("hdr_valid_parent")
    defer: n.shut()
    let m = n.mainChain(2, 0x07)
    let child = mkBlock(hashOf(m[1]), 3, 0x08)
    check n.rpc.handleMethod("submitheader", %*[hexOf(serialize(child.header))]).kind == JNull
    check n.cs.db.getBlockIndex(hashOf(child)).isSome
    # Known valid header: idempotent null.
    check n.rpc.handleMethod("submitheader", %*[hexOf(serialize(child.header))]).kind == JNull
    check n.tips()[displayHex(hashOf(child))] == row(3, 1, "headers-only")
