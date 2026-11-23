## test_cffix_reorg_in_belowout.nim
##
## A block connected by a reorg must pass Core's per-transaction
## CheckTxInputs value checks, exactly like a block that extends the tip.
##
## Bitcoin Core ConnectBlock (validation.cpp) calls Consensus::CheckTxInputs
## for every non-coinbase tx (consensus/tx_verify.cpp:164-211):
##   * each spent coin and the running input sum in MoneyRange
##     ("bad-txns-inputvalues-outofrange"),
##   * value_in < value_out -> "bad-txns-in-belowout",
##   * txfee in MoneyRange ("bad-txns-fee-outofrange"),
## then accumulates nFees and checks MoneyRange(nFees)
## ("bad-txns-accumulated-fee-outofrange"). Reorg-connected blocks go through
## the same ConnectBlock (ActivateBestChainStep -> ConnectTip).
##
## nimrod stores side-branch blocks with validateForStorage
## (skipConnectChecks=true), which skips validateTransaction, and the
## reorg connect loop in chainstate.handleReorg only checked the AGGREGATE
## coinbase <= subsidy + (sumIn - sumOut). A tx spending 1 sat into 1 BTC in
## a block whose coinbase pays 0 keeps the aggregate fee at
## -99,999,999 sat, well above -subsidy, so the block passed and was reorged
## onto. Core rejects it bad-txns-in-belowout.
##
## The test drives acceptSideBranchBlock with the same three hooks
## network/sync.nim processSideBranchBody and rpc/server.nim sideBranchHooks
## wire (validateForStorage, verifyScripts, reorgConnectChecks), on a
## regtest chain with real PoW.
##
## Layout (heights):
##   0 .. 100 (active), 101 = A (active tip)
##   100 -> B1(101) -> B2(102)  (side branch, heavier once B2 arrives)
## The h=1 coinbase pays two outputs: vout 0 = 1 sat, vout 1 = 50 BTC - 1 sat.
## Both are mature at height 101.

import unittest2
import std/[options, os, atomics]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/storage/[db, chainstate]

var dbCounter: Atomic[int]
dbCounter.store(0)

proc freshDbPath(): string =
  let n = dbCounter.fetchAdd(1)
  getTempDir() / ("nimrod_cffix_reorg_in_belowout_" & $getCurrentProcessId() &
                  "_" & $n)

proc cleanupDb(path: string) =
  if dirExists(path):
    removeDir(path)

const
  Subsidy = 5_000_000_000'i64     # regtest, height < 150
  OneBtc = 100_000_000'i64
  BaseTs = 1_700_000_000'u32

proc coinbase(height: int32, outs: seq[int64], tag: byte = 0): Transaction =
  var txOuts: seq[TxOut]
  for v in outs:
    txOuts.add TxOut(value: Satoshi(v), scriptPubKey: @[byte(0x51)])
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                        vout: 0xFFFFFFFF'u32),
      scriptSig: validation.encodeBip34Height(height) & @[tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: txOuts,
    witnesses: @[],
    lockTime: 0)

proc spend(op: OutPoint, outValue: int64): Transaction =
  ## Spend an OP_TRUE coin into one OP_TRUE output of `outValue` sat.
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: op, scriptSig: @[byte(0x51)],
                   sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(outValue), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc mine(prevHash: BlockHash, height: int32, cb: Transaction,
          extra: seq[Transaction] = @[]): Block =
  var ids = @[array[32, byte](cb.txid())]
  for tx in extra:
    ids.add array[32, byte](tx.txid())
  var header = BlockHeader(
    version: 4, prevBlock: prevHash, merkleRoot: merkleRoot(ids),
    timestamp: BaseTs + uint32(height) * 600'u32,
    bits: 0x207fffff'u32, nonce: 0)
  while not hashMeetsTarget(BlockHash(doubleSha256(serialize(header))),
                            header.bits):
    inc header.nonce
  Block(header: header, txs: @[cb] & extra)

proc hashOf(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

type Fixture = object
  cs: ChainState
  blks: seq[Block]        # active chain 0 .. 101
  oneSat: OutPoint        # h=1 coinbase vout 0, value 1 sat
  bigCoin: OutPoint       # h=1 coinbase vout 1, value Subsidy - 1

proc buildFixture(dbPath: string): Fixture =
  result.cs = newChainState(dbPath, regtestParams())
  var prev = BlockHash(default(array[32, byte]))
  for h in 0'i32 .. 101'i32:
    let cb =
      if h == 1: coinbase(h, @[1'i64, Subsidy - 1])
      else: coinbase(h, @[Subsidy])
    let blk = mine(prev, h, cb)
    let r = result.cs.connectBlock(blk, h)
    doAssert r.isOk, "fixture connect failed at h=" & $h & ": " & $r.error
    prev = hashOf(blk)
    result.blks.add blk
  let cb1 = result.blks[1].txs[0].txid()
  result.oneSat = OutPoint(txid: cb1, vout: 0)
  result.bigCoin = OutPoint(txid: cb1, vout: 1)

type Hooks = tuple[
  validate: proc(b: Block, prevIdx: chainstate.BlockIndex):
              tuple[ok: bool, err: string] {.gcsafe, raises: [].},
  verify: proc(b: Block, height: int32): tuple[ok: bool, err: string]
            {.gcsafe, raises: [].},
  connectChecks: proc(b: Block, height: int32): tuple[ok: bool, err: string]
                   {.gcsafe, raises: [].}]

proc realHooks(cs: ChainState): Hooks =
  ## The hooks network/sync.nim processSideBranchBody builds, minus logging.
  let csCapture = cs
  let params = cs.params
  result.validate = proc(b: Block, prevIdx: chainstate.BlockIndex):
                        tuple[ok: bool, err: string] {.gcsafe, raises: [].} =
    var vr: ValidationResult[void]
    try:
      {.gcsafe.}:
        vr = validateForStorage(csCapture, b, prevIdx, newCryptoEngine())
    except Exception as e:
      return (ok: false, err: "local-error: " & e.msg)
    if vr.isOk: (ok: true, err: "") else: (ok: false, err: bip22String(vr.error))
  result.verify = proc(b: Block, height: int32): tuple[ok: bool, err: string]
                      {.gcsafe, raises: [].} =
    let g = newUtxoReadGuard()
    let lookup = guardedUtxoLookup(csCapture, g)
    var res: ValidationResult[void]
    try:
      {.gcsafe.}:
        res = verifyScripts(b, lookup, height, newCryptoEngine(), params)
    except Exception as e:
      return (ok: false, err: "local-error: " & e.msg)
    if res.isOk: (ok: true, err: "") else: (ok: false, err: bip22String(res.error))
  result.connectChecks = proc(b: Block, height: int32): tuple[ok: bool, err: string]
                             {.gcsafe, raises: [].} =
    let g = newUtxoReadGuard()
    let lookup = guardedUtxoLookup(csCapture, g)
    var res: ValidationResult[void]
    try:
      {.gcsafe.}:
        res = reorgConnectChecks(b, height, lookup, csCapture.db, params)
    except Exception as e:
      return (ok: false, err: "local-error: " & e.msg)
    if res.isOk: (ok: true, err: "") else: (ok: false, err: bip22String(res.error))

proc feed(cs: var ChainState, hooks: Hooks, blk: Block):
    tuple[outcome: SideBranchOutcome, token: string] =
  var dtx: seq[Transaction] = @[]
  var conn: seq[Block] = @[]
  cs.acceptSideBranchBlock(blk, hooks.validate, hooks.verify,
                           hooks.connectChecks, dtx, conn)

suite "cffix reorg in-belowout: reorg-promoted blocks get CheckTxInputs":

  test "reorg onto a branch whose tx spends 1 sat into 1 BTC is rejected bad-txns-in-belowout":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let hooks = realHooks(f.cs)
    let tipA = hashOf(f.blks[101])
    check f.cs.bestHeight == 101

    # B1: coinbase pays 0, T spends the 1-sat coin into 1 BTC. The block's
    # aggregate fee is 1 - 1 BTC, so coinbase(0) <= subsidy + fees holds and
    # only the per-tx check can catch it.
    let t = spend(f.oneSat, OneBtc)
    let b1 = mine(hashOf(f.blks[100]), 101, coinbase(101, @[0'i64], 0xB1), @[t])
    let b2 = mine(hashOf(b1), 102, coinbase(102, @[Subsidy], 0xB2))

    let r1 = feed(f.cs, hooks, b1)
    check r1.outcome == sboSideBranch     # equal work: stored, not promoted
    let r2 = feed(f.cs, hooks, b2)
    check r2.outcome == sboRejected
    check r2.token == "bad-txns-in-belowout"
    check f.cs.lastRejectedBlock == hashOf(b1)
    # Tip stays at A and the rollback left the 1-sat coin unspent.
    check f.cs.bestHeight == 101
    check f.cs.bestBlockHash == tipA
    check f.cs.getUtxo(f.oneSat).isSome

  test "negative control: tx paying V-1000 sat reorgs onto the branch":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let hooks = realHooks(f.cs)

    # Same shape, but T spends the big coin V = Subsidy-1 into V-1000 sat
    # (fee 1000) and the coinbase claims subsidy + fee exactly.
    let t = spend(f.bigCoin, (Subsidy - 1) - 1000)
    let b1 = mine(hashOf(f.blks[100]), 101,
                  coinbase(101, @[Subsidy + 1000], 0xC1), @[t])
    let b2 = mine(hashOf(b1), 102, coinbase(102, @[Subsidy], 0xC2))

    check feed(f.cs, hooks, b1).outcome == sboSideBranch
    let r2 = feed(f.cs, hooks, b2)
    check r2.outcome == sboReorged
    check f.cs.bestHeight == 102
    check f.cs.bestBlockHash == hashOf(b2)
    check f.cs.getUtxo(f.bigCoin).isNone

  test "a tx whose outputs equal its inputs (zero fee) still reorgs":
    ## Boundary of the in >= out rule: value_in == value_out is valid.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let hooks = realHooks(f.cs)

    let t = spend(f.oneSat, 1)
    let b1 = mine(hashOf(f.blks[100]), 101, coinbase(101, @[Subsidy], 0xD1), @[t])
    let b2 = mine(hashOf(b1), 102, coinbase(102, @[Subsidy], 0xD2))

    check feed(f.cs, hooks, b1).outcome == sboSideBranch
    check feed(f.cs, hooks, b2).outcome == sboReorged
    check f.cs.bestBlockHash == hashOf(b2)

  test "below-out on the SECOND promoted block is rejected and the tip is restored":
    ## The bad tx sits in B2 and spends an output B1 created, so the check
    ## must read the reorg view (fork point + earlier promoted blocks).
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let hooks = realHooks(f.cs)
    let tipA = hashOf(f.blks[101])

    let t1 = spend(f.oneSat, 1)                       # valid, zero fee
    let b1 = mine(hashOf(f.blks[100]), 101, coinbase(101, @[Subsidy], 0xE1), @[t1])
    let t2 = spend(OutPoint(txid: t1.txid(), vout: 0), OneBtc)
    let b2 = mine(hashOf(b1), 102, coinbase(102, @[0'i64], 0xE2), @[t2])

    check feed(f.cs, hooks, b1).outcome == sboSideBranch
    let r2 = feed(f.cs, hooks, b2)
    check r2.outcome == sboRejected
    check r2.token == "bad-txns-in-belowout"
    check f.cs.lastRejectedBlock == hashOf(b2)
    check f.cs.bestBlockHash == tipA
    check f.cs.bestHeight == 101
    check f.cs.getUtxo(f.oneSat).isSome

  test "intra-block chain: a valid in-block spend reorgs, a below-out one is rejected":
    ## t2 spends t1's output in the SAME block, so its input value comes from
    ## an output this block just created. Valid at zero fee; rejected when t2
    ## pays out more than t1 gave it.
    for bad in [false, true]:
      let dbPath = freshDbPath()
      defer: cleanupDb(dbPath)
      var f = buildFixture(dbPath)
      defer: f.cs.close()
      let hooks = realHooks(f.cs)
      let tipA = hashOf(f.blks[101])

      let t1 = spend(f.bigCoin, Subsidy - 1)                    # zero fee
      let t2 = spend(OutPoint(txid: t1.txid(), vout: 0),
                     if bad: Subsidy else: Subsidy - 1)
      let cbValue = if bad: 0'i64 else: Subsidy
      let b1 = mine(hashOf(f.blks[100]), 101,
                    coinbase(101, @[cbValue], if bad: 0xF1'u8 else: 0xF3'u8),
                    @[t1, t2])
      let b2 = mine(hashOf(b1), 102,
                    coinbase(102, @[Subsidy], if bad: 0xF2'u8 else: 0xF4'u8))

      check feed(f.cs, hooks, b1).outcome == sboSideBranch
      let r2 = feed(f.cs, hooks, b2)
      if bad:
        check r2.outcome == sboRejected
        check r2.token == "bad-txns-in-belowout"
        check f.cs.bestBlockHash == tipA
        check f.cs.getUtxo(f.bigCoin).isSome
      else:
        check r2.outcome == sboReorged
        check f.cs.bestBlockHash == hashOf(b2)
        check f.cs.getUtxo(OutPoint(txid: t2.txid(), vout: 0)).isSome
