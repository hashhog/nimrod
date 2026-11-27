## test_cffix_mempool_atomic_replacement.nim
##
## A replacement's conflicts leave the mempool only when the replacement is
## actually added: never when a later gate rejects it, and never for a
## test_accept probe.
##
## Bitcoin Core v31.1 MemPoolAccept::AcceptSingleTransactionInternal
## (validation.cpp:1317-1431): ReplacementChecks only STAGES the conflicts in
## the subpackage changeset; CheckMemPoolPolicyLimits (:1342) measures the
## post-replacement cluster on that changeset; PolicyScriptChecks /
## ConsensusScriptChecks follow; the m_test_accept return is at :1388; only
## FinalizeSubpackage (:1191) applies the removals.
##
## nimrod used to call removeConflicts BEFORE checkPackageLimits and before the
## testAccept return, with no rollback, so:
##   (a) a P2P tx that conflicts with A and joins a full 64-tx cluster evicted
##       A and its child C, then was rejected "too-large-cluster" (free
##       eviction of third-party transactions);
##   (b) testmempoolaccept on a valid replacement evicted the real conflicts.
##
## Command:  nim c -r tests/test_cffix_mempool_atomic_replacement.nim

import unittest2
import std/[os, sets, tables]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_cffix_mempool_atomic_replacement_test"

const
  CoinValue = 100_000_000'i64     # 1 BTC per synthetic coin
  ChainFee = 1_000'i64            # fee of every setup tx (~8 sat/vB)
  RbfSeq = 0xfffffffd'u32         # BIP-125 opt-in

proc opTrueWitnessScript(): seq[byte] = @[byte(0x51)]

proc p2wshOpTrue(): seq[byte] =
  ## OP_0 <sha256(OP_TRUE)>: standard output, spent by witness [OP_TRUE].
  let h = sha256Single(opTrueWitnessScript())
  result = @[byte(0x00), 0x20]
  for b in h: result.add b

proc spend(prevs: seq[OutPoint], outValue: int64): Transaction =
  var ins: seq[TxIn]
  var wits: seq[seq[seq[byte]]]
  for p in prevs:
    ins.add TxIn(prevOut: p, scriptSig: @[], sequence: RbfSeq)
    wits.add @[opTrueWitnessScript()]
  Transaction(version: 2, inputs: ins,
              outputs: @[TxOut(value: Satoshi(outValue),
                               scriptPubKey: p2wshOpTrue())],
              witnesses: wits, lockTime: 0)

proc coin(tag: byte): OutPoint =
  var a: array[32, byte]
  a[0] = 0xC0
  a[1] = tag
  OutPoint(txid: TxId(a), vout: 0)

proc addCoin(cs: var ChainState, op: OutPoint) =
  cs.putUtxoCache(op, UtxoEntry(
    output: TxOut(value: Satoshi(CoinValue), scriptPubKey: p2wshOpTrue()),
    height: 1, isCoinbase: false))

type Fixture = object
  cs: ChainState
  mp: Mempool
  crypto: CryptoEngine
  a, c: TxId                   # the original A and its child C
  chainTip: OutPoint           # unspent output of the last tx of chain P
  chainLen: int

proc build(chainLen: int): Fixture =
  ## A (signals RBF) spends coin 1, C spends A:0.  Chain P of `chainLen`
  ## txs starts from coin 2.  Every tx goes in through acceptTransaction.
  if dirExists(TestDbPath): removeDir(TestDbPath)
  result.cs = newChainState(TestDbPath, regtestParams())
  result.cs.addCoin(coin(1))
  result.cs.addCoin(coin(2))
  result.mp = newMempool(result.cs, regtestParams())
  result.crypto = newCryptoEngine()
  result.chainLen = chainLen

  let txA = spend(@[coin(1)], CoinValue - ChainFee)
  let ra = result.mp.acceptTransaction(txA, result.crypto)
  doAssert ra.isOk, "setup A: " & ra.error
  result.a = ra.value
  let txC = spend(@[OutPoint(txid: result.a, vout: 0)], CoinValue - 2 * ChainFee)
  let rc = result.mp.acceptTransaction(txC, result.crypto)
  doAssert rc.isOk, "setup C: " & rc.error
  result.c = rc.value

  var prev = coin(2)
  var value = CoinValue
  for i in 1 .. chainLen:
    value -= ChainFee
    let r = result.mp.acceptTransaction(spend(@[prev], value), result.crypto)
    doAssert r.isOk, "setup P" & $i & ": " & r.error
    prev = OutPoint(txid: r.value, vout: 0)
  result.chainTip = prev
  doAssert result.mp.entries.len == chainLen + 2

proc close(f: var Fixture) =
  f.cs.close()
  if dirExists(TestDbPath): removeDir(TestDbPath)

suite "cffix: RBF conflicts are evicted only after every gate (Core FinalizeSubpackage)":
  test "replacement rejected too-large-cluster leaves A and C in the pool":
    # P is 64 txs: R would be the 65th member of P's cluster, A and C are
    # not in that cluster.  R pays far more than A + C, so it passes RBF.
    var f = build(64)
    let r = spend(@[coin(1), f.chainTip],
                  2 * CoinValue - 64 * ChainFee - 100_000)
    let res = f.mp.acceptTransactionWithArgs(r, f.crypto, defaultAtmpArgs())
    check not res.isOk
    check res.error == "too-large-cluster"
    check f.a in f.mp.entries
    check f.c in f.mp.entries
    check r.txid() notin f.mp.entries
    check f.mp.entries.len == 64 + 2
    # A's input is still marked spent by A, so A really is intact.
    check f.mp.spentBy.getOrDefault(coin(1)) == f.a
    f.close()

  test "testAccept on a valid replacement leaves A and C in the pool":
    var f = build(3)
    let r = spend(@[coin(1)], CoinValue - 100_000)
    var args = defaultAtmpArgs()
    args.testAccept = true
    let res = f.mp.acceptTransactionWithArgs(r, f.crypto, args)
    check res.isOk
    if res.isOk:
      check f.a in res.value.replaced
      check f.c in res.value.replaced
    check f.a in f.mp.entries
    check f.c in f.mp.entries
    check r.txid() notin f.mp.entries
    check f.mp.entries.len == 3 + 2
    check f.mp.spentBy.getOrDefault(coin(1)) == f.a
    f.close()

  test "control: the same replacement without testAccept evicts A and C":
    var f = build(3)
    let r = spend(@[coin(1)], CoinValue - 100_000)
    let res = f.mp.acceptTransactionWithArgs(r, f.crypto, defaultAtmpArgs())
    check res.isOk
    check f.a notin f.mp.entries
    check f.c notin f.mp.entries
    check r.txid() in f.mp.entries
    check f.mp.entries.len == 3 + 1
    check f.mp.spentBy.getOrDefault(coin(1)) == r.txid()
    f.close()

  test "control: the cluster limit is measured AFTER the replacement":
    # P is 63 txs plus Q (signals RBF) spending P's tip: a full 64-tx
    # cluster.  R double-spends Q's input, so once Q goes the cluster is
    # 63 + R = 64, within the limit.  Counting Q as still present would make
    # it 65 and wrongly reject a replacement Core accepts.
    var f = build(63)
    let q = spend(@[f.chainTip], CoinValue - 64 * ChainFee)
    let rq = f.mp.acceptTransaction(q, f.crypto)
    check rq.isOk
    check f.mp.entries.len == 63 + 1 + 2
    let r = spend(@[f.chainTip], CoinValue - 63 * ChainFee - 100_000)
    let res = f.mp.acceptTransactionWithArgs(r, f.crypto, defaultAtmpArgs())
    check res.isOk
    check q.txid() notin f.mp.entries
    check r.txid() in f.mp.entries
    check f.a in f.mp.entries     # not R's conflict: untouched
    check f.c in f.mp.entries
    check f.mp.entries.len == 63 + 1 + 2
    f.close()

  test "control: a 65th cluster member with no conflict is still rejected":
    var f = build(64)
    let r = spend(@[f.chainTip], CoinValue - 64 * ChainFee - 100_000)
    let res = f.mp.acceptTransactionWithArgs(r, f.crypto, defaultAtmpArgs())
    check not res.isOk
    check res.error == "too-large-cluster"
    check f.mp.entries.len == 64 + 2
    f.close()
