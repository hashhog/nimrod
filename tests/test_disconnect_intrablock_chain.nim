## Disconnecting a block with an INTRA-BLOCK chain (tx K spends an output of an
## earlier tx P in the same block) must not resurrect the intermediate output.
##
## Bitcoin Core DisconnectBlock (validation.cpp:2185-2240) unwinds per tx in
## reverse: remove tx i's outputs, THEN restore tx i's inputs. So K restores
## P:0 before P removes it, and P:0 ends up absent. nimrod's production
## disconnect paths remove every created output for the whole block first and
## restore every undo entry afterwards, so P:0 (spent inside the block, present
## in the undo with the block's own height) is put back and never removed.
##
## Live consequence (2026-10-02): mainnet stale block 963853 (…ec5e4c) was
## connected and then reorged out on 2026-08-24; its 621 intra-block-spent
## outputs whose creating tx never confirmed on Core's chain remain in nimrod's
## UTXO set (606 P2A anchors + 15 P2WPKH, 769,774 sat, 606 txids).

import unittest2
import std/[os, options]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_disconnect_intrablock_chain"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc spk(tag: byte): seq[byte] =
  @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte]))) & @[tag]

proc anchorSpk(): seq[byte] = @[byte(0x51), 0x02, 0x4e, 0x73]   # P2A

proc blockHashOf(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc coinbaseTx(height: int32, chainId: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04), byte(height and 0xff), byte((height shr 8) and 0xff),
                   byte((height shr 16) and 0xff), 0x00, 0x02,
                   byte(chainId and 0xff), byte((chainId shr 8) and 0xff)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: spk(0x01))],
    witnesses: @[], lockTime: 0)

proc mkBlock(prev: BlockHash, height: int32, chainId: int32,
             txs: seq[Transaction]): Block =
  var all = @[coinbaseTx(height, chainId)] & txs
  var hashes: seq[array[32, byte]]
  for t in all: hashes.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 1, prevBlock: prev,
          merkleRoot: merkleRoot(hashes),
          timestamp: 1231006505 + uint32(height * 600) + uint32(chainId),
          bits: 0x207fffff'u32, nonce: uint32(height) + uint32(chainId * 1000)),
        txs: all)

type Fixture = object
  forkHash: BlockHash
  forkHeight: int32
  fundingCb: TxId
  stale: Block
  parentTxid, childTxid: TxId

proc buildFixture(cs: var ChainState): Fixture =
  ## h0 genesis, h1 funding coinbase, h2..h101 padding (maturity), then the
  ## to-be-stale block at h102 holding P (spends the h1 coinbase; vout0 = P2A
  ## anchor, vout1 = change) and K (spends P:0 inside the same block).
  let g = mkBlock(BlockHash(default(array[32, byte])), 0, 0, @[])
  doAssert cs.connectBlock(g, 0).isOk
  var prev = blockHashOf(g)
  let fund = mkBlock(prev, 1, 0, @[])
  doAssert cs.connectBlock(fund, 1).isOk
  result.fundingCb = fund.txs[0].txid()
  prev = blockHashOf(fund)
  for h in 2'i32 .. 101'i32:
    let b = mkBlock(prev, h, 0, @[])
    doAssert cs.connectBlock(b, h).isOk
    prev = blockHashOf(b)
  result.forkHash = prev
  result.forkHeight = 101

  let parent = Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: result.fundingCb, vout: 0),
                   scriptSig: @[byte(0x00)], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(240), scriptPubKey: anchorSpk()),
               TxOut(value: Satoshi(4999000000'i64), scriptPubKey: spk(0x02))],
    witnesses: @[], lockTime: 0)
  let child = Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: parent.txid(), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(200), scriptPubKey: spk(0x03))],
    witnesses: @[], lockTime: 0)
  result.parentTxid = parent.txid()
  result.childTxid = child.txid()
  result.stale = mkBlock(result.forkHash, 102, 7, @[parent, child])
  doAssert cs.connectBlock(result.stale, 102).isOk

suite "disconnect: intra-block chain (Core DisconnectBlock per-tx order)":
  setup: cleanupTestDb()
  teardown: cleanupTestDb()

  test "connect sanity: the intra-block-spent anchor is absent after connect":
    var cs = newChainState(TestDbPath, regtestParams())
    let f = buildFixture(cs)
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 0)).isNone   # spent by K
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 1)).isSome
    check cs.getUtxo(OutPoint(txid: f.childTxid, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: f.fundingCb, vout: 0)).isNone
    cs.close()

  test "disconnectBlock does not resurrect the intra-block-spent output":
    var cs = newChainState(TestDbPath, regtestParams())
    let f = buildFixture(cs)
    check cs.disconnectBlock(f.stale).isOk
    check cs.bestHeight == f.forkHeight
    check cs.getUtxo(OutPoint(txid: f.fundingCb, vout: 0)).isSome     # restored
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 1)).isNone
    check cs.getUtxo(OutPoint(txid: f.childTxid, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 0)).isNone    # THE BUG
    # and on disk, not just in the cache
    cs.flushCache()
    check cs.db.getUtxo(OutPoint(txid: f.parentTxid, vout: 0)).isNone
    cs.close()

  test "handleReorg off the stale block does not resurrect the intra-block-spent output":
    var cs = newChainState(TestDbPath, regtestParams())
    let f = buildFixture(cs)
    let b102 = mkBlock(f.forkHash, 102, 9, @[])
    let b103 = mkBlock(blockHashOf(b102), 103, 9, @[])
    check cs.handleReorg(f.forkHash, @[b102, b103]).isOk
    check cs.bestHeight == 103
    check cs.getUtxo(OutPoint(txid: f.fundingCb, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 1)).isNone
    check cs.getUtxo(OutPoint(txid: f.childTxid, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: f.parentTxid, vout: 0)).isNone    # THE BUG
    cs.flushCache()
    check cs.db.getUtxo(OutPoint(txid: f.parentTxid, vout: 0)).isNone
    cs.close()
