## A relayed child that arrives BEFORE its parent must be held as an orphan,
## not cached as rejected, and must be accepted once the parent arrives.
##
## Bitcoin Core: MemPoolAccept::PreChecks returns TX_MISSING_INPUTS
## ("bad-txns-inputs-missingorspent") when a prevout is in neither the UTXO
## set nor the mempool; TxDownloadManagerImpl::MempoolRejectedTx
## (node/txdownloadman_impl.cpp:361) adds such a tx to the orphanage instead
## of the recent-rejects filter, and ProcessOrphanTx
## (net_processing.cpp ~3214) re-evaluates it when a parent is accepted
## (AddChildrenToWorkSet) — leaving it in the orphanage if it is STILL
## missing inputs (only a non-MISSING_INPUTS result removes it).
##
## The bug (nimrod 8c55fea): the P2P tx handler decided "orphan" with
## `txResult.error.startsWith("input not found")`, a token the single-tx
## mempool path stopped returning; it returns
## "bad-txns-inputs-missingorspent: <txid>". Every child-before-parent tx
## was dropped AND put into recentlyRejected, so it was never re-requested
## and never reconsidered when the parent arrived.
##
## Drives the real P2P handler (nimrod.handleMessage, via {.all.}) against a
## real Mempool on a temp regtest ChainState.
##
## Command:  nim c -r tests/test_orphan_child_before_parent.nim

import unittest2
import std/[os, sets, tempfiles]
import chronos
import ../src/nimrod {.all.}
import ../src/mempool/[mempool, orphan]
import ../src/storage/chainstate
import ../src/network/[peer, peermanager, messages]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/params
import ../src/script/interpreter

# P2SH(OP_TRUE): standard output, spendable with scriptSig = push(OP_TRUE).
proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc spendSig(): seq[byte] = @[byte(0x01), byte(OP_TRUE)]

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x00)]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc spend(prevs: seq[OutPoint], value: int64): Transaction =
  var ins: seq[TxIn]
  for p in prevs:
    ins.add TxIn(prevOut: p, scriptSig: spendSig(), sequence: 0xFFFFFFFE'u32)
  Transaction(version: 2, inputs: ins,
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

type Fixture = object
  dir: string
  cs: ChainState
  state: NodeState
  peer: Peer
  coins: seq[TxId]   ## mature coinbase txids (output 0 = 50 BTC to P2SH(OP_TRUE))

proc setupFixture(): Fixture =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_orphan_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let blk = blockOf(prev, int32(h), @[coinbaseTx(int32(h))])
    discard result.cs.connectBlock(blk, int32(h))
    if h in 1 .. 4:
      result.coins.add(blk.txs[0].txid())
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  let mp = newMempool(result.cs, params, minFeeRate = 0.0)
  result.state = NodeState(
    params: params, chainState: result.cs, mempool: mp,
    peerManager: newPeerManager(params, 8, 2, 117, result.dir),
    crypto: newCryptoEngine(),
    recentlyRejected: initHashSet[TxId](),
    orphanPool: newOrphanPool())
  result.peer = newPeer("203.0.113.9", 8333, params, pdInbound)

proc teardownFixture(f: var Fixture) =
  f.cs.close()
  removeDir(f.dir)

proc relay(f: Fixture, tx: Transaction) =
  waitFor handleMessage(f.state, f.peer, P2PMessage(kind: mkTx, tx: tx))

proc inMempool(f: Fixture, tx: Transaction): bool =
  f.state.mempool.contains(tx.txid())

proc rejected(f: Fixture, tx: Transaction): bool =
  tx.txid() in f.state.recentlyRejected or tx.wtxid() in f.state.recentlyRejected

suite "relayed child-before-parent tx is orphaned, then accepted":

  test "the mempool reports a missing parent as Core's TX_MISSING_INPUTS token":
    var f = setupFixture()
    let parent = spend(@[OutPoint(txid: f.coins[0], vout: 0)], 4_999_990_000)
    let child = spend(@[OutPoint(txid: parent.txid(), vout: 0)], 4_999_980_000)
    let r = f.state.mempool.acceptTransaction(child, f.state.crypto)
    check not r.isOk
    check r.error.len >= 30 and
          r.error[0 ..< 30] == "bad-txns-inputs-missingorspent"
    f.teardownFixture()

  test "child first: held as orphan, NOT recently-rejected; parent: both accepted":
    var f = setupFixture()
    let parent = spend(@[OutPoint(txid: f.coins[0], vout: 0)], 4_999_990_000)
    let child = spend(@[OutPoint(txid: parent.txid(), vout: 0)], 4_999_980_000)

    f.relay(child)
    check not f.inMempool(child)
    check f.state.orphanPool.containsByTxid(child.txid())
    check not f.rejected(child)

    f.relay(parent)
    check f.inMempool(parent)
    check f.inMempool(child)
    check not f.state.orphanPool.containsByTxid(child.txid())
    check not f.rejected(child)
    f.teardownFixture()

  test "grandchild chain arriving in reverse order resolves completely":
    var f = setupFixture()
    let a = spend(@[OutPoint(txid: f.coins[1], vout: 0)], 4_999_990_000)
    let b = spend(@[OutPoint(txid: a.txid(), vout: 0)], 4_999_980_000)
    let c = spend(@[OutPoint(txid: b.txid(), vout: 0)], 4_999_970_000)
    f.relay(c)
    f.relay(b)
    check f.state.orphanPool.containsByTxid(b.txid())
    check f.state.orphanPool.containsByTxid(c.txid())
    f.relay(a)
    check f.inMempool(a) and f.inMempool(b) and f.inMempool(c)
    check f.state.orphanPool.count == 0
    f.teardownFixture()

  test "orphan with TWO missing parents stays orphaned after the first arrives":
    ## Core ProcessOrphanTx: a reconsidered orphan that is still
    ## TX_MISSING_INPUTS stays in the orphanage (not rejected).
    var f = setupFixture()
    let p1 = spend(@[OutPoint(txid: f.coins[2], vout: 0)], 4_999_990_000)
    let p2 = spend(@[OutPoint(txid: f.coins[3], vout: 0)], 4_999_990_000)
    let child = spend(@[OutPoint(txid: p1.txid(), vout: 0),
                        OutPoint(txid: p2.txid(), vout: 0)], 9_999_970_000)
    f.relay(child)
    check f.state.orphanPool.containsByTxid(child.txid())
    f.relay(p1)
    check f.inMempool(p1)
    check not f.inMempool(child)
    check f.state.orphanPool.containsByTxid(child.txid())
    check not f.rejected(child)
    f.relay(p2)
    check f.inMempool(p2)
    check f.inMempool(child)
    check f.state.orphanPool.count == 0
    f.teardownFixture()

  test "control: a tx rejected for a non-missing-input reason is NOT orphaned":
    var f = setupFixture()
    # Overspends a confirmed coin: inputs exist, so this is a hard reject
    # (bad-txns-in-belowout), never an orphan.
    let bad = spend(@[OutPoint(txid: f.coins[0], vout: 0)], 6_000_000_000)
    f.relay(bad)
    check not f.inMempool(bad)
    check not f.state.orphanPool.containsByTxid(bad.txid())
    check f.rejected(bad)
    f.teardownFixture()
