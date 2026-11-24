## test_cffix_reorg_sigop_cost.nim
##
## A block connected by a reorg must pass Core's block sigop-cost limit,
## exactly like a block that extends the tip.
##
## Bitcoin Core ConnectBlock (validation.cpp:2564-2570), for every tx:
##   nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
##   if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) -> "bad-blk-sigops"
## GetTransactionSigOpCost counts legacy, P2SH (redeemScript, accurate) and
## witness sigops, so it needs the spent coins. Reorg-connected blocks go
## through the same ConnectBlock (ActivateBestChainStep -> ConnectTip).
##
## nimrod counts the full cost only in validateBlock's connect section
## (skipConnectChecks=false). Side-branch blocks are stored with
## skipConnectChecks=true and the reorg connect loop never recomputed it, so a
## heavier branch whose block carries 6 P2SH inputs spending
##   OP_0 OP_IF <199 x OP_CHECKMULTISIG> OP_ENDIF OP_1
## (6 x 199 x 20 x 4 = 95,520 cost) was promoted. Core rejects it. Legacy
## sigops alone are 0 here, so the context-free legacy check in checkBlock
## does not catch it.
##
## Layout (heights):
##   0 .. 100 (active), 101 = A (active tip)
##   100 -> B1(101) -> B2(102)  (side branch, heavier once B2 arrives)
## The h=1 coinbase pays 8 P2SH outputs of the redeemScript above, mature at 101.

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
  getTempDir() / ("nimrod_cffix_reorg_sigop_cost_" & $getCurrentProcessId() &
                  "_" & $n)

proc cleanupDb(path: string) =
  if dirExists(path):
    removeDir(path)

const
  Subsidy = 5_000_000_000'i64     # regtest, height < 150
  BaseTs = 1_700_000_000'u32
  NumP2sh = 8
  CoinValue = 100_000_000'i64     # 1 BTC per P2SH coin

proc heavyRedeem(): seq[byte] =
  ## OP_0 OP_IF <199 x OP_CHECKMULTISIG> OP_ENDIF OP_1. Never executes the
  ## CHECKMULTISIGs; 201 counted ops (the limit). Accurate P2SH count:
  ## 199 x 20 = 3,980 sigops -> cost 15,920 per input.
  result = @[byte(0x00), 0x63]
  for i in 0 ..< 199: result.add 0xae'u8
  result.add 0x68'u8
  result.add 0x51'u8

proc p2shSpk(redeem: seq[byte]): seq[byte] =
  let h = hash160(redeem)
  result = @[byte(0xa9), 0x14]
  for b in h: result.add b
  result.add 0x87'u8

proc p2shSig(redeem: seq[byte]): seq[byte] =
  doAssert redeem.len < 256
  result = @[byte(0x4c), byte(redeem.len)]   # OP_PUSHDATA1 <redeem>
  result.add redeem

proc coinbase(height: int32, outs: seq[TxOut], tag: byte = 0): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                        vout: 0xFFFFFFFF'u32),
      scriptSig: validation.encodeBip34Height(height) & @[tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: outs,
    witnesses: @[],
    lockTime: 0)

proc opTrue(v: int64): TxOut = TxOut(value: Satoshi(v), scriptPubKey: @[byte(0x51)])

proc legacyCb(height: int32, tag: byte, nCms, nCs: int): Transaction =
  ## Coinbase paying the subsidy to a script holding `nCms` OP_CHECKMULTISIG
  ## (20 legacy sigops each) and `nCs` OP_CHECKSIG (1 each), then OP_TRUE.
  var spk: seq[byte]
  for i in 0 ..< nCms: spk.add 0xae'u8
  for i in 0 ..< nCs: spk.add 0xac'u8
  spk.add 0x51'u8
  coinbase(height, @[TxOut(value: Satoshi(Subsidy), scriptPubKey: spk)], tag)

proc spendP2sh(ops: seq[OutPoint], redeem: seq[byte]): Transaction =
  ## One tx spending every P2SH coin in `ops` to one OP_TRUE output, zero fee.
  var ins: seq[TxIn]
  for op in ops:
    ins.add TxIn(prevOut: op, scriptSig: p2shSig(redeem), sequence: 0xFFFFFFFF'u32)
  Transaction(version: 1, inputs: ins,
              outputs: @[opTrue(CoinValue * int64(ops.len))],
              witnesses: @[], lockTime: 0)

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
  blks: seq[Block]          # active chain 0 .. 101
  coins: seq[OutPoint]      # h=1 coinbase P2SH outputs

proc buildFixture(dbPath: string): Fixture =
  result.cs = newChainState(dbPath, regtestParams())
  let spk = p2shSpk(heavyRedeem())
  var prev = BlockHash(default(array[32, byte]))
  for h in 0'i32 .. 101'i32:
    var outs: seq[TxOut]
    if h == 1:
      for i in 0 ..< NumP2sh:
        outs.add TxOut(value: Satoshi(CoinValue), scriptPubKey: spk)
      outs.add opTrue(Subsidy - CoinValue * NumP2sh)
    else:
      outs.add opTrue(Subsidy)
    let blk = mine(prev, h, coinbase(h, outs))
    let r = result.cs.connectBlock(blk, h)
    doAssert r.isOk, "fixture connect failed at h=" & $h & ": " & $r.error
    prev = hashOf(blk)
    result.blks.add blk
  let cb1 = result.blks[1].txs[0].txid()
  for i in 0 ..< NumP2sh:
    result.coins.add OutPoint(txid: cb1, vout: uint32(i))

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

proc tipExtend(cs: ChainState, blk: Block): ValidationResult[void] =
  ## The main-chain acceptance pipeline (submitblock / IBD) for a block on the tip.
  let prevIdx = cs.db.getBlockIndex(blk.header.prevBlock).get()
  let g = newUtxoReadGuard()
  acceptBlock(blk, prevIdx, cs.db, cs.params, skipScripts = false,
              checkPow = true, getUtxo = guardedUtxoLookup(cs, g),
              crypto = newCryptoEngine())

proc reorgWith(nInputs: int, nCms, nCs: int, tag: byte):
    tuple[outcome: SideBranchOutcome, token: string, tipOk: bool, coinsOk: bool] =
  ## Build the 2-vs-1 branch: B1 spends `nInputs` heavy P2SH coins and its
  ## coinbase carries nCms/nCs legacy sigops; B2 is empty. Feed both.
  let dbPath = freshDbPath()
  defer: cleanupDb(dbPath)
  var f = buildFixture(dbPath)
  defer: f.cs.close()
  let hooks = realHooks(f.cs)
  let tipA = hashOf(f.blks[101])
  let t = spendP2sh(f.coins[0 ..< nInputs], heavyRedeem())
  let b1 = mine(hashOf(f.blks[100]), 101, legacyCb(101, tag, nCms, nCs), @[t])
  let b2 = mine(hashOf(b1), 102, coinbase(102, @[opTrue(Subsidy)], tag + 1))
  let r1 = feed(f.cs, hooks, b1)
  doAssert r1.outcome == sboSideBranch, "B1 not stored: " & $r1
  let r2 = feed(f.cs, hooks, b2)
  result.outcome = r2.outcome
  result.token = r2.token
  if r2.outcome == sboReorged:
    result.tipOk = f.cs.bestBlockHash == hashOf(b2) and f.cs.bestHeight == 102
    result.coinsOk = f.cs.getUtxo(f.coins[0]).isNone
  else:
    result.tipOk = f.cs.bestBlockHash == tipA and f.cs.bestHeight == 101
    result.coinsOk = f.cs.getUtxo(f.coins[0]).isSome and
                     f.cs.lastRejectedBlock == hashOf(b1)

suite "cffix reorg sigop cost: reorg-promoted blocks get the block sigop-cost limit":

  test "reorg onto a branch block with P2SH sigop cost 95,520 is rejected bad-blk-sigops":
    let r = reorgWith(6, 0, 0, 0xA0)
    check r.outcome == sboRejected
    check r.token == "bad-blk-sigops"
    check r.tipOk          # tip stays at A
    check r.coinsOk        # rollback left the P2SH coins unspent

  test "control: the same 95,520-cost block on the tip is rejected bad-blk-sigops":
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let t = spendP2sh(f.coins[0 ..< 6], heavyRedeem())
    let blk = mine(hashOf(f.blks[101]), 102, legacyCb(102, 0xB0, 0, 0), @[t])
    let r = tipExtend(f.cs, blk)
    check not r.isOk
    if not r.isOk:
      check bip22String(r.error) == "bad-blk-sigops"

  test "control: a branch block at cost 79,920 reorgs":
    # 5 x 15,920 = 79,600 P2SH + 4 x 20 legacy (coinbase) x 4 = 320 -> 79,920
    let r = reorgWith(5, 4, 0, 0xC0)
    check r.outcome == sboReorged
    check r.tipOk
    check r.coinsOk

  test "boundary: cost exactly 80,000 reorgs, 80,004 is rejected bad-blk-sigops":
    # 79,600 P2SH + 5 x 20 x 4 = 400 legacy -> 80,000 (limit is '>', so valid)
    let ok = reorgWith(5, 5, 0, 0xD0)
    check ok.outcome == sboReorged
    check ok.tipOk
    # + one OP_CHECKSIG (1 x 4) -> 80,004
    let bad = reorgWith(5, 5, 1, 0xE0)
    check bad.outcome == sboRejected
    check bad.token == "bad-blk-sigops"
    check bad.tipOk
    check bad.coinsOk

  test "intra-block: heavy P2SH coins created and spent in the same branch block are counted":
    ## tx1 spends an OP_TRUE coin into 6 heavy P2SH outputs; tx2 in the SAME
    ## block spends them. Their cost (95,520) is only visible through the
    ## block's own outputs, so the count must read them, not just the fork view.
    let dbPath = freshDbPath()
    defer: cleanupDb(dbPath)
    var f = buildFixture(dbPath)
    defer: f.cs.close()
    let hooks = realHooks(f.cs)
    let tipA = hashOf(f.blks[101])
    let change = OutPoint(txid: f.blks[1].txs[0].txid(), vout: uint32(NumP2sh))
    let spk = p2shSpk(heavyRedeem())
    var outs: seq[TxOut]
    for i in 0 ..< 6:
      outs.add TxOut(value: Satoshi(CoinValue), scriptPubKey: spk)
    let tx1 = Transaction(version: 1,
      inputs: @[TxIn(prevOut: change, scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: outs, witnesses: @[], lockTime: 0)
    var ops: seq[OutPoint]
    for i in 0 ..< 6:
      ops.add OutPoint(txid: tx1.txid(), vout: uint32(i))
    let tx2 = spendP2sh(ops, heavyRedeem())
    let b1 = mine(hashOf(f.blks[100]), 101, legacyCb(101, 0xF0, 0, 0), @[tx1, tx2])
    let b2 = mine(hashOf(b1), 102, coinbase(102, @[opTrue(Subsidy)], 0xF1))
    check feed(f.cs, hooks, b1).outcome == sboSideBranch
    let r2 = feed(f.cs, hooks, b2)
    check r2.outcome == sboRejected
    check r2.token == "bad-blk-sigops"
    check f.cs.bestBlockHash == tipA
    check f.cs.getUtxo(change).isSome

  test "regression: BIP-68 in the merged per-tx loop still rejects an unmet lock and passes a met one":
    ## reorgConnectChecks now runs BIP-68 and the sigop count in one loop.
    ## The h=1 change coin (OP_TRUE) is spent by a v2 tx in B1 at height 101.
    ## Core: nMinHeight = coinHeight + n - 1 must be < blockHeight, so n=100
    ## is met and n=101 is unmet (bad-txns-nonfinal). Passes on base and head.
    for n in [100'u32, 101'u32]:
      let dbPath = freshDbPath()
      defer: cleanupDb(dbPath)
      var f = buildFixture(dbPath)
      defer: f.cs.close()
      let hooks = realHooks(f.cs)
      let tipA = hashOf(f.blks[101])
      let change = OutPoint(txid: f.blks[1].txs[0].txid(), vout: uint32(NumP2sh))
      let tx = Transaction(version: 2,
        inputs: @[TxIn(prevOut: change, scriptSig: @[], sequence: n)],
        outputs: @[opTrue(Subsidy - CoinValue * NumP2sh)], witnesses: @[], lockTime: 0)
      let b1 = mine(hashOf(f.blks[100]), 101, legacyCb(101, byte(0x70 + n - 100), 0, 0), @[tx])
      let b2 = mine(hashOf(b1), 102, coinbase(102, @[opTrue(Subsidy)], byte(0x80 + n - 100)))
      check feed(f.cs, hooks, b1).outcome == sboSideBranch
      let r2 = feed(f.cs, hooks, b2)
      if n == 100:
        check r2.outcome == sboReorged
        check f.cs.bestBlockHash == hashOf(b2)
      else:
        check r2.outcome == sboRejected
        check r2.token == "bad-txns-nonfinal"
        check f.cs.bestBlockHash == tipA
