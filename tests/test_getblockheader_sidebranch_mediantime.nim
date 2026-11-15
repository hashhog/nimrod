## getblockheader mediantime for an index entry off the active chain.
##
## Core's blockheaderToJSON reports blockindex->GetMedianTimePast()
## (rpc/blockchain.cpp), and CBlockIndex::GetMedianTimePast (chain.h) walks
## the entry's own pprev links: the median of its nTime and up to 10
## ancestors, whichever chain it is on.  nimrod used getMtpForHeight, which
## reads the ACTIVE chain's height->hash index: a header above the active tip
## (e.g. the one invalidateblock displaced) got mediantime 0, and a fork entry
## at a height the active chain owns got the active block's MTP.
## Core v31.1 regtest row failed_reorg/d-invalidate/displaced-header:mediantime
## (Core 1700000012, nimrod 0).
##
## Command:  nim c -r tests/test_getblockheader_sidebranch_mediantime.nim

import unittest2
import std/[algorithm, json, options, os, tempfiles]
import ../src/rpc/server
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/script/interpreter
import ../src/mining/fees

proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), 0]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc spend(prev: OutPoint, value: int64): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[byte(0x01), byte(OP_TRUE)],
                   sequence: 0xFFFFFFFD'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

type Fx = object
  dir: string
  rpc: RpcServer
  blocks: seq[Block]
  hashes: seq[BlockHash]

const Tip = 20

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_gbh_sidebranch_mtp_", "")
  var cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. Tip:
    let blk = blockOf(prev, int32(h), @[coinbaseTx(int32(h))])
    doAssert cs.connectBlock(blk, int32(h)).isOk
    prev = BlockHash(doubleSha256(serialize(blk.header)))
    result.blocks.add(blk)
    result.hashes.add(prev)
  let mp = newMempool(cs, params)
  result.rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                            peerManager = nil, feeEstimator = newFeeEstimator(),
                            params = params)

proc teardown(f: var Fx) =
  f.rpc.chainState.close()
  removeDir(f.dir)

proc hexOf(h: BlockHash): string =
  const hx = "0123456789abcdef"
  let a = array[32, byte](h)
  for i in countdown(31, 0):
    result.add(hx[(a[i] shr 4) and 0xf])
    result.add(hx[a[i] and 0xf])

proc storeSideHeader(f: Fx, parentHeight: int, ts: uint32): BlockHash =
  ## A headers-only entry whose parent is active block `parentHeight`,
  ## stored by hash only (the active chain keeps its height slot).
  let header = BlockHeader(version: 4, prevBlock: f.hashes[parentHeight],
                           merkleRoot: default(array[32, byte]),
                           timestamp: ts, bits: 0x207fffff'u32, nonce: 77'u32)
  let hash = BlockHash(doubleSha256(serialize(header)))
  let parent = f.rpc.chainState.db.getBlockIndex(f.hashes[parentHeight]).get()
  f.rpc.chainState.db.putBlockIndexHashOnly(BlockIndex(
    hash: hash, height: int32(parentHeight + 1), status: bsHeaderOnly,
    prevHash: f.hashes[parentHeight], header: header,
    totalWork: parent.totalWork))
  hash

proc expectedMtp(f: Fx, parentHeight: int, ts: uint32): int64 =
  ## Core GetMedianTimePast: nTime of the entry and its 10 nearest ancestors.
  var times = @[int64(ts)]
  var h = parentHeight
  while h >= 0 and times.len < 11:
    times.add(int64(f.blocks[h].header.timestamp))
    dec h
  times.sort()
  times[times.len div 2]

suite "getblockheader mediantime walks the entry's own ancestors (Core GetMedianTimePast)":
  test "header above the active tip reports its MTP, not 0":
    var f = setup()
    let ts = f.blocks[Tip].header.timestamp + 600
    let side = f.storeSideHeader(Tip, ts)
    let r = f.rpc.handleMethod("getblockheader", %*[hexOf(side), true])
    check r["height"].getInt() == Tip + 1
    check r["mediantime"].getBiggestInt() == f.expectedMtp(Tip, ts)
    check r["mediantime"].getBiggestInt() != 0
    f.teardown()

  test "fork entry at a height the active chain owns uses its own ancestors":
    var f = setup()
    # An nTime older than every active block: its own window (it + blocks
    # 14..5) has median block 9, the active block 15's window (15..5) has
    # median block 10.
    let ts = f.blocks[0].header.timestamp - 1_000
    let side = f.storeSideHeader(14, ts)
    let active15 = f.rpc.handleMethod("getblockheader", %*[hexOf(f.hashes[15]), true])
    let r = f.rpc.handleMethod("getblockheader", %*[hexOf(side), true])
    check r["height"].getInt() == 15
    check r["mediantime"].getBiggestInt() == f.expectedMtp(14, ts)
    check r["mediantime"].getBiggestInt() != active15["mediantime"].getBiggestInt()
    f.teardown()

  test "control: an active-chain header keeps the active MTP":
    var f = setup()
    let r = f.rpc.handleMethod("getblockheader", %*[hexOf(f.hashes[Tip]), true])
    check r["mediantime"].getBiggestInt() ==
      f.expectedMtp(Tip - 1, f.blocks[Tip].header.timestamp)
    f.teardown()
