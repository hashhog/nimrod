## Marker-lag adoption must never accept a block Core rejects.
##
## The IBD applyBlock path (sync.nim) tries `adoptAppliedBlock` whenever a
## block is rejected for missing inputs. Up to 786abb3 the adoption probe
## counted ANY of the block's own (txid, vout) outputs present in the raw
## UTXO DB as proof that THIS block had already been applied. That is false
## for a block that re-includes an already-confirmed transaction T: T's
## outputs are on disk (created by T's ORIGINAL block), T's inputs are spent,
## so the block fails "missing input" — and the probe then finds T's outputs,
## "adopts" the block, and its tolerant roll-forward re-applies EVERY tx in
## it, including a tx X that spends a coin that never existed.
##
## Core: ConnectBlock -> Consensus::CheckTxInputs rejects
## "bad-txns-inputs-missingorspent" (validation.cpp ConnectBlock tx loop,
## consensus/tx_verify.cpp CheckTxInputs). BIP30 does not save it on mainnet:
## between BIP34 activation and height 1,983,702 the BIP30 HaveCoin scan is
## skipped (validation.cpp:2430-2467), so the params below activate BIP34
## with a canonical bip34Hash exactly as mainnet does. Core never infers
## "already applied" from the coin set; ReplayBlocks rolls forward only the
## blocks named by the durable HEAD_BLOCKS marker.

import unittest2
import std/[options, os]
import ../src/network/sync
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const EASY_BITS = 0x207fffff'u32
const BASE_TIME = 1_700_000_000'u32

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc makeCoinbaseTx(height: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32,
               extra: seq[Transaction] = @[]): Block =
  let cb = makeCoinbaseTx(height)
  var txids = @[array[32, byte](cb.txid())]
  for t in extra: txids.add(array[32, byte](t.txid()))
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
                        merkleRoot: merkleRoot(txids), timestamp: ts,
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb] & extra)

proc spend(prev: OutPoint, value: int64): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)

type Fixture = object
  cs: ChainState
  sm: SyncManager
  blk4: Block
  t: Transaction
  tip: BlockHeader

proc buildFixture(path: string): Fixture =
  ## Genesis + 1..3 coinbase-only + block 4 confirming T (spends block 3's
  ## coinbase), all durable. BIP34 active from height 1 with block 1 as the
  ## canonical bip34Hash (mainnet shape: BIP30 scan skipped).
  removeDir(path)
  var p = regtestParams()
  p.powAllowMinDifficultyBlocks = false
  p.powNoRetargeting = false
  p.coinbaseMaturity = 1
  var blks: seq[Block]
  var prev = p.genesisBlockHash
  var ts = BASE_TIME
  for h in 1'i32 .. 3'i32:
    let b = mineBlock(prev, h, ts)
    blks.add(b)
    prev = hashOf(b.header)
    ts += 600
  p.bip34Height = 1
  p.bip34Hash = array[32, byte](hashOf(blks[0].header))
  var cs = newChainState(path, p)
  doAssert cs.connectBlock(buildGenesisBlock(p), 0'i32).isOk
  for i, b in blks:
    let r = cs.connectBlock(b, int32(i + 1))
    doAssert r.isOk, "fixture connect " & $(i + 1) & ": " & $r.error
  let t = spend(OutPoint(txid: blks[2].txs[0].txid(), vout: 0'u32), 4_999_900_000'i64)
  let blk4 = mineBlock(prev, 4, ts, @[t])
  let r4 = cs.connectBlock(blk4, 4'i32)
  doAssert r4.isOk, "fixture connect 4: " & $r4.error
  # T's output is durable at height 4, T's input is durably spent.
  doAssert cs.db.getUtxo(OutPoint(txid: t.txid(), vout: 0'u32)).isSome
  var csv = cs
  let sm = newSyncManager(nil, csv.db, p, csv)
  Fixture(cs: csv, sm: sm, blk4: blk4, t: t, tip: blk4.header)

proc headersAhead(f: Fixture, blk5: Block): seq[Block] =
  ## blk5 at height 5 plus coinbase-only 6..25, so the header tip is >10
  ## ahead and applyBlock takes the IBD path (where the adoption probe lives).
  result = @[blk5]
  var prev = blk5.header
  for h in 6'i32 .. 25'i32:
    let b = mineBlock(hashOf(prev), h, prev.timestamp + 600)
    result.add(b)
    prev = b.header

suite "marker-lag adoption never accepts an invalid block":

  test "block re-including a confirmed tx plus a spend of a nonexistent coin is REJECTED":
    let path = "/tmp/nimrod_adopt_forged_1"
    var f = buildFixture(path)
    defer:
      f.cs.close()
      removeDir(path)
    var phantom: array[32, byte]
    phantom[0] = 0xde; phantom[1] = 0xad; phantom[2] = 0xbe; phantom[3] = 0xef
    let x = spend(OutPoint(txid: TxId(phantom), vout: 0'u32), 100_000_000'i64)
    let blk5 = mineBlock(hashOf(f.tip), 5, f.tip.timestamp + 600, @[f.t, x])
    let chain = headersAhead(f, blk5)
    var hdrs: seq[BlockHeader]
    for b in chain: hdrs.add(b.header)
    check f.sm.processHeaders(hdrs) == 21
    let applied = f.sm.applyBlock(blk5, 5'i32)
    checkpoint "applyBlock(blk5) = " & $applied & " lastApplyError=" & f.sm.lastApplyError &
               " tip=" & $f.sm.chainTipHeight
    check (not applied)
    check f.sm.chainTipHeight == 4
    # X's output was never created; the phantom coin's spender minted nothing.
    let xop = OutPoint(txid: x.txid(), vout: 0'u32)
    check f.sm.chainState.getUtxo(xop).isNone
    check f.sm.chainState.db.getUtxo(xop).isNone

  test "block that only re-includes a confirmed tx (pure double spend) is REJECTED":
    let path = "/tmp/nimrod_adopt_forged_2"
    var f = buildFixture(path)
    defer:
      f.cs.close()
      removeDir(path)
    let blk5 = mineBlock(hashOf(f.tip), 5, f.tip.timestamp + 600, @[f.t])
    let chain = headersAhead(f, blk5)
    var hdrs: seq[BlockHeader]
    for b in chain: hdrs.add(b.header)
    check f.sm.processHeaders(hdrs) == 21
    let applied = f.sm.applyBlock(blk5, 5'i32)
    checkpoint "applyBlock(blk5) = " & $applied & " lastApplyError=" & f.sm.lastApplyError
    check (not applied)
    check f.sm.chainTipHeight == 4
    check f.sm.chainState.bestBlockHash == hashOf(f.blk4.header)

  test "adoptAppliedBlock refuses a block whose only 'evidence' is an older tx's output":
    let path = "/tmp/nimrod_adopt_forged_3"
    var f = buildFixture(path)
    defer:
      f.cs.close()
      removeDir(path)
    let blk5 = mineBlock(hashOf(f.tip), 5, f.tip.timestamp + 600, @[f.t])
    f.sm.chainState.startIBD()
    let res = f.sm.chainState.adoptAppliedBlock(blk5, 5'i32)
    checkpoint "adopt: " & (if res.isOk: "OK" else: res.error)
    check (not res.isOk)
    check f.sm.chainState.bestHeight == 4

  test "control: the honest next block still connects on the IBD path":
    let path = "/tmp/nimrod_adopt_forged_4"
    var f = buildFixture(path)
    defer:
      f.cs.close()
      removeDir(path)
    let blk5 = mineBlock(hashOf(f.tip), 5, f.tip.timestamp + 600,
                         @[spend(OutPoint(txid: f.t.txid(), vout: 0'u32), 4_999_800_000'i64)])
    let chain = headersAhead(f, blk5)
    var hdrs: seq[BlockHeader]
    for b in chain: hdrs.add(b.header)
    check f.sm.processHeaders(hdrs) == 21
    check f.sm.applyBlock(blk5, 5'i32)
    check f.sm.chainTipHeight == 5
