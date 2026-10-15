## The mempool must agree with the active chain the moment a connect,
## disconnect or reorg returns — not after the P2P caller gets round to it.
##
## Bitcoin Core does all of it in the validation layer under cs_main:
##   ConnectTip   -> m_mempool->removeForBlock(vtx)     (every connected block)
##   DisconnectTip -> disconnectpool.AddTransactionsFromBlock(vtx)
##   InvalidateBlock (after EACH disconnect) / ActivateBestChainStep (once) ->
##     MaybeUpdateMempoolForReorg: re-accept earliest-first (bypass_limits),
##     removeRecursive whatever fails, then removeForReorg drops non-final /
##     BIP68-locked / immature-coinbase spends at tip+1, with descendants.
##
## nimrod (<= 5215491) ran removeForBlock in nimrod.nim's mkBlock arm AFTER
## processBlock returned: drainBlockBuffer's between-block yield let RPC read
## confirmed txs, connectStoredBlocks' blocks never reached it, invalidateblock
## refilled nothing, and the P2P reorg left a child of a double-spent block tx
## in the pool (an invalid getblocktemplate). NI-7 / T4 of
## receipts/arch-concurrency-liveness-audit-2026-10-07.md.
##
## These tests drive the chainstate entry points every one of those paths goes
## through (connectBlock, invalidateBlock, handleReorg) with a real Mempool
## attached, using the vectors of tools/mempool-reorg-sweep.py, and check the
## pool right after the call returns — and, for connect, at the moment the
## tip-changed hook wakes a waiting RPC thread (the hand-off seam).
##
## Command:  nim c -r tests/test_mempool_reorg.nim

import unittest2
import std/[os, sets, tables, tempfiles]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter

const Fee = 10_000'i64

proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

proc coinbaseTx(height: int32, tag: byte = 0): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x01), tag]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc spend1(prev: Transaction, vout: uint32 = 0, sequence = 0xFFFFFFFE'u32,
            lockTime = 0'u32): Transaction =
  let value = int64(prev.outputs[vout].value) - Fee
  Transaction(version: 2,
              inputs: @[TxIn(prevOut: OutPoint(txid: prev.txid(), vout: vout),
                             scriptSig: @[byte(0x01), byte(OP_TRUE)],
                             sequence: sequence)],
              outputs: @[TxOut(value: Satoshi(value), scriptPubKey: p2shTrue())],
              witnesses: @[], lockTime: lockTime)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

type Fx = object
  dir: string
  cs: ChainState
  mp: Mempool
  crypto: CryptoEngine
  cb: seq[Transaction]          ## coinbase at each height 0..110
  hash: Table[int, BlockHash]   ## active hashes 0..110 (+111/112 when built)
  names: Table[TxId, string]

proc setup110(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_mempool_reorg_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let c = coinbaseTx(int32(h))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    prev = hashOf(blk)
    result.hash[h] = prev
  result.mp = newMempool(result.cs, params, minFeeRate = 0.0)
  result.crypto = newCryptoEngine()

proc teardown(f: var Fx) =
  f.cs.close()
  removeDir(f.dir)

proc name(f: var Fx, n: string, tx: Transaction): Transaction =
  f.names[tx.txid()] = n
  tx

proc pool(f: Fx): HashSet[string] =
  for txid in f.mp.entries.keys:
    result.incl(f.names.getOrDefault(txid, "?" & $txid))

proc accept(f: Fx, tx: Transaction): bool =
  f.mp.acceptTransaction(tx, f.crypto).isOk

type Vec = object
  A1, P, A2, C, IMM, LT, B68, D, M1, M2, M3: Transaction
  b111, b112: Block

proc buildTo112(f: var Fx): Vec =
  ## tools/mempool-reorg-sweep.py VECTORS: 111 [A1<-cb1, P<-cb2];
  ## 112 [A2<-cb3, C<-P, IMM<-cb12, LT<-cb4 (nLockTime 111),
  ## B68<-cb5 (nSequence 107), D<-B68]; mempool M1<-A2, M2<-A1, M3<-cb6.
  result.A1 = f.name("A1", spend1(f.cb[1]))
  result.P = f.name("P", spend1(f.cb[2]))
  result.b111 = blockOf(f.hash[110], 111,
                        @[coinbaseTx(111), result.A1, result.P])
  doAssert f.cs.connectBlock(result.b111, 111).isOk
  f.hash[111] = hashOf(result.b111)
  result.A2 = f.name("A2", spend1(f.cb[3]))
  result.C = f.name("C", spend1(result.P))
  result.IMM = f.name("IMM", spend1(f.cb[12]))
  result.LT = f.name("LT", spend1(f.cb[4], lockTime = 111))
  result.B68 = f.name("B68", spend1(f.cb[5], sequence = 107))
  result.D = f.name("D", spend1(result.B68))
  result.b112 = blockOf(f.hash[111], 112,
                        @[coinbaseTx(112), result.A2, result.C, result.IMM,
                          result.LT, result.B68, result.D])
  doAssert f.cs.connectBlock(result.b112, 112).isOk
  f.hash[112] = hashOf(result.b112)
  result.M1 = f.name("M1", spend1(result.A2))
  result.M2 = f.name("M2", spend1(result.A1))
  result.M3 = f.name("M3", spend1(f.cb[6]))
  doAssert f.accept(result.M1)
  doAssert f.accept(result.M2)
  doAssert f.accept(result.M3)

proc S(xs: varargs[string]): HashSet[string] = toHashSet(@xs)

type TrimSpec = tuple[n, src: string, fee: int64]

proc kidsFrom(start: int): seq[TrimSpec] =
  for i in start ..< 64:
    result.add(("C" & $i, "P:" & $i, 3_050'i64 + 100'i64 * int64(i)))

proc runTrim(spec: seq[TrimSpec], parentFee = 10_000'i64,
             twoOut: seq[string] = @[]): HashSet[string] =
  ## Confirm a 64-output parent in block 111, accept `spec` into the mempool
  ## (children of the parent, or of an earlier spec entry), invalidate 111 and
  ## return the surviving pool by name.
  var f = setup110()
  let spendable = int64(f.cb[1].outputs[0].value) - parentFee
  let each = spendable div 64
  var outs: seq[TxOut]
  for i in 0 ..< 64:
    let v = each + (if i == 0: spendable - each * 64 else: 0'i64)
    outs.add(TxOut(value: Satoshi(v), scriptPubKey: p2shTrue()))
  let parent = f.name("PARENT", Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: f.cb[1].txid(), vout: 0),
                   scriptSig: @[byte(0x01), byte(OP_TRUE)],
                   sequence: 0xFFFFFFFE'u32)],
    outputs: outs, witnesses: @[], lockTime: 0))
  let b111 = blockOf(f.hash[110], 111, @[coinbaseTx(111), parent])
  doAssert f.cs.connectBlock(b111, 111).isOk
  var made = initTable[string, Transaction]()
  for (n, src, fee) in spec:
    var prev: OutPoint
    var v: int64
    if src.len > 2 and src[0 .. 1] == "P:":
      var i = 0
      for ch in src[2 .. ^1]: i = i * 10 + (ord(ch) - ord('0'))
      prev = OutPoint(txid: parent.txid(), vout: uint32(i))
      v = int64(outs[i].value)
    else:
      let t = made[src]
      prev = OutPoint(txid: t.txid(), vout: 0)
      v = int64(t.outputs[0].value)
    let tx = f.name(n, Transaction(version: 2,
      inputs: @[TxIn(prevOut: prev, scriptSig: @[byte(0x01), byte(OP_TRUE)],
                     sequence: 0xFFFFFFFE'u32)],
      outputs: (if n in twoOut:
                  @[TxOut(value: Satoshi((v - fee) div 2), scriptPubKey: p2shTrue()),
                    TxOut(value: Satoshi(v - fee - (v - fee) div 2), scriptPubKey: p2shTrue())]
                else:
                  @[TxOut(value: Satoshi(v - fee), scriptPubKey: p2shTrue())]),
      witnesses: @[], lockTime: 0))
    doAssert f.accept(tx), n
    made[n] = tx
  doAssert f.cs.invalidateBlock(hashOf(b111)).isOk
  result = f.pool
  f.teardown()

proc allBut(spec: seq[TrimSpec], gone: varargs[string]): HashSet[string] =
  result.incl("PARENT")
  for t in spec: result.incl(t.n)
  for g in gone: result.excl(g)

suite "mempool follows the chain inside connect / disconnect / reorg (NI-7, T4)":

  test "connectBlock: confirmed txs and conflicts (with descendants) leave before the call returns":
    var f = setup110()
    let a1 = f.name("A1", spend1(f.cb[1]))
    let k = f.name("K", spend1(a1))            # child of a tx the block confirms
    let p = f.name("P", spend1(f.cb[2]))       # unrelated, stays
    let mx = f.name("MX", spend1(f.cb[7]))     # conflicts with block tx X
    let mxc = f.name("MXc", spend1(mx))        # descendant of the conflict
    for t in [a1, k, p, mx, mxc]:
      check f.accept(t)
    check f.pool == S("A1", "K", "P", "MX", "MXc")
    check f.mp.entries[k.txid()].ancestorCount == 2
    # X spends cb7 like MX but pays a different fee -> a different txid.
    var x = spend1(f.cb[7])
    x.outputs[0].value = Satoshi(int64(x.outputs[0].value) - 1)
    discard f.name("X", x)
    let blk = blockOf(f.hash[110], 111, @[coinbaseTx(111), a1, x])
    # The hand-off seam: tipChangedHook is what wakes a waiting RPC thread.
    var seenAtWake: HashSet[string]
    var woke = false
    let fp = addr f
    f.cs.tipChangedHook = proc() {.gcsafe, raises: [].} =
      try:
        {.cast(gcsafe).}:
          woke = true
          seenAtWake = fp[].pool
      except Exception:
        discard
    check f.cs.connectBlock(blk, 111).isOk
    check woke
    check seenAtWake == S("K", "P")
    check f.pool == S("K", "P")
    # K's parent is confirmed now: its cached ancestor state says so.
    check f.mp.entries[k.txid()].ancestorCount == 1
    f.teardown()

  test "invalidateblock 111 returns the disconnected txs earliest-first and drops the invalid ones (sweep a)":
    var f = setup110()
    let v = f.buildTo112()
    check f.pool == S("M1", "M2", "M3")
    let r = f.cs.invalidateBlock(f.hash[111])
    check r.isOk
    check f.cs.bestHeight == 110
    # Core: {A1, P, A2, C, M1, M2, M3}; IMM (cb12 immature at 111), LT
    # (non-final at 111), B68 (BIP68-locked at 111) and D (its child) dropped.
    check f.pool == S("A1", "P", "A2", "C", "M1", "M2", "M3")
    # C entered at tip 111 with a confirmed parent; P came back after it, so
    # C's ancestor state must now count P (Core UpdateTransactionsFromBlock).
    check f.mp.entries[v.C.txid()].ancestorCount == 2
    when compiles(f.mp.disconnectPool):   # fail-before builds on 5215491 too
      check f.mp.disconnectPool.len == 0
    f.teardown()

  test "reconnecting 111/112 (reconsider / from disk) removes them again (sweep b)":
    var f = setup110()
    let v = f.buildTo112()
    check f.cs.invalidateBlock(f.hash[111]).isOk
    check f.cs.reconsiderBlock(f.hash[111]).isOk
    check f.cs.connectBlock(v.b111, 111).isOk
    check f.cs.connectBlock(v.b112, 112).isOk
    check f.pool == S("M1", "M2", "M3")
    f.teardown()

  test "reorg onto a branch that double-spends a block tx removes its mempool child (sweep c)":
    var f = setup110()
    let v = f.buildTo112()
    # X / Z spend the same coins as A1 / M3 but pay 1 sat more fee, so they
    # are different txs (double spends), not re-confirmations.
    var x = spend1(f.cb[1])                   # conflicts A1
    x.outputs[0].value = Satoshi(int64(x.outputs[0].value) - 1)
    var z = spend1(f.cb[6])                   # conflicts M3
    z.outputs[0].value = Satoshi(int64(z.outputs[0].value) - 1)
    discard f.name("X", x)
    discard f.name("Z", z)
    check x.txid() != v.A1.txid() and z.txid() != v.M3.txid()
    let b111b = blockOf(f.hash[110], 111, @[coinbaseTx(111, 0xb), x])
    let b112b = blockOf(hashOf(b111b), 112, @[coinbaseTx(112, 0xb), v.P])
    let b113b = blockOf(hashOf(b112b), 113, @[coinbaseTx(113, 0xb), z])
    var disconnected: seq[Transaction]
    let r = f.cs.handleReorg(f.hash[110], @[b111b, b112b, b113b], disconnected)
    check r.isOk
    check f.cs.bestHeight == 113
    # Core: {A2, C, IMM, LT, B68, D, M1}. A1 cannot return (X spent cb1), so
    # M2 (its child) goes; P is re-confirmed in 112b; M3 conflicts Z.
    check f.pool == S("A2", "C", "IMM", "LT", "B68", "D", "M1")
    when compiles(f.mp.disconnectPool):   # fail-before builds on 5215491 too
      check f.mp.disconnectPool.len == 0
    f.teardown()

  test "removeForReorg drops an in-pool tx whose coinbase input is immature at the new tip":
    var f = setup110()
    discard f.buildTo112()
    # At tip 112, a spend of cb13 is mature (113-13 = 100). Invalidate 112
    # -> tip 111: it would be mined at 112 where cb13 has only 99 confs.
    let early = f.name("EARLY", spend1(f.cb[13]))
    check f.accept(early)
    check f.cs.invalidateBlock(f.hash[112]).isOk
    check "EARLY" notin f.pool
    f.teardown()

  test "invalidateblock of a block holding a 64-child parent keeps parent + children 1..63 (KB-192, harness warden_e)":
    # Core v31.1 MaybeUpdateMempoolForReorg (validation.cpp:310-341) re-accepts
    # the parent with bypass_limits; ATMP assumes a new entry has no in-mempool
    # children, so the parent enters, and UpdateTransactionsFromBlock
    # (txmempool.cpp) links its 64 children and calls TxGraph::Trim() to get the
    # 65-tx cluster back under DEFAULT_CLUSTER_LIMIT (64): the lowest-feerate
    # child goes. Measured on Core v31.1 (harness warden_e): parent + children
    # 1..63 stay. Before the fix the parent was rejected as too-large-cluster
    # and removeRecursive emptied the pool.
    var f = setup110()
    const ParentFee = 10_000'i64
    let spendable = int64(f.cb[1].outputs[0].value) - ParentFee
    let each = spendable div 64
    var outs: seq[TxOut]
    for i in 0 ..< 64:
      let v = each + (if i == 0: spendable - each * 64 else: 0'i64)
      outs.add(TxOut(value: Satoshi(v), scriptPubKey: p2shTrue()))
    let parent = f.name("PARENT", Transaction(version: 2,
      inputs: @[TxIn(prevOut: OutPoint(txid: f.cb[1].txid(), vout: 0),
                     scriptSig: @[byte(0x01), byte(OP_TRUE)],
                     sequence: 0xFFFFFFFE'u32)],
      outputs: outs, witnesses: @[], lockTime: 0))
    let b111 = blockOf(f.hash[110], 111, @[coinbaseTx(111), parent])
    check f.cs.connectBlock(b111, 111).isOk
    var children: seq[Transaction]
    for i in 0 ..< 64:
      let fee = int64(i + 1) * 1000
      let child = f.name("C" & $i, Transaction(version: 2,
        inputs: @[TxIn(prevOut: OutPoint(txid: parent.txid(), vout: uint32(i)),
                       scriptSig: @[byte(0x01), byte(OP_TRUE)],
                       sequence: 0xFFFFFFFE'u32)],
        outputs: @[TxOut(value: Satoshi(int64(outs[i].value) - fee),
                         scriptPubKey: p2shTrue())],
        witnesses: @[], lockTime: 0))
      check f.accept(child)
      children.add(child)
    check f.mp.entries.len == 64
    check f.cs.invalidateBlock(hashOf(b111)).isOk
    check f.cs.bestHeight == 110
    var want = S("PARENT")
    for i in 1 ..< 64: want.incl("C" & $i)
    check f.mp.entries.len == 64
    check f.pool == want
    check "C0" notin f.pool
    # The survivors count the re-added parent as an ancestor.
    check f.mp.entries[children[63].txid()].ancestorCount == 2
    f.teardown()

  # KB-192 trim divergence. Core v31.1 TxGraph::Trim (txgraph.cpp:3285-) keeps
  # transactions in a merged order of the pre-merge clusters' CHUNK feerates and
  # drops whatever no longer fits (plus descendants). Expected sets below are
  # Core v31.1's, measured on the same shapes with P2WPKH spends through the
  # core-regtest harness (probe groups trim_a/a2/c/c2, Oct 11 2026); the fee
  # orderings carry over to these 85-vB P2SH(OP_TRUE) spends.
  test "KB-192 trim (a): a low child whose own child is above every leaf but whose chunk is lowest goes with it":
    let spec = @[("C0", "P:0", 200'i64), ("G0", "C0", 4_000'i64)] & kidsFrom(1)
    check runTrim(spec) == allBut(spec, "C0", "G0")

  test "KB-192 trim (a2): chunk {C0,G0} below every leaf, GG0 lowest: all three go":
    let spec = @[("C0", "P:0", 200'i64), ("G0", "C0", 6_000'i64), ("GG0", "G0", 150'i64)] & kidsFrom(1)
    check runTrim(spec) == allBut(spec, "C0", "G0", "GG0")

  test "KB-192 trim (c): a low child CPFP'd above every leaf stays; the two lowest leaves go":
    let spec = @[("C0", "P:0", 200'i64), ("G0", "C0", 20_000'i64)] & kidsFrom(1)
    check runTrim(spec) == allBut(spec, "C1", "C2")

  test "KB-192 trim (c2): low-fee re-added parent, lowest child goes":
    let spec = @[("C0", "P:0", 500'i64)] & kidsFrom(1)
    check runTrim(spec, parentFee = 1_000) == allBut(spec, "C0")

  # (b) Core v31.1 Trim orders the heap only by chunk FeeFrac (txgraph.cpp:3336-3341,
  # feefrac.h:178-183: feerate, then smaller size first). C0 and C1 have the
  # same fee and size, so FeeFrac cannot separate them; Core v31.1 keeps the
  # first-accepted one and drops C1 (harness probe trim_b, and the
  # trim_b_rev / trim_b_last / trim_b_hi orderings, 3/3 runs each).
  test "KB-192 trim (b): two lowest childless txs with equal fee and size: the later-accepted one goes":
    let spec = @[("C0", "P:0", 2_000'i64), ("C1", "P:1", 2_000'i64)] & kidsFrom(2)
    check runTrim(spec) == allBut(spec, "C1")

  test "KB-192 trim (b'): same order with C1 accepted first: C0 goes":
    let spec = @[("C1", "P:1", 2_000'i64), ("C0", "P:0", 2_000'i64)] & kidsFrom(2)
    check runTrim(spec) == allBut(spec, "C0")

  test "KB-192 trim (b2): equal feerate, larger size goes (FeeFrac tie: smaller size first)":
    # 1-in-1-out P2SH(OP_TRUE) spend = 340 WU, 1-in-2-out = 468 WU: 850/340 == 1170/468.
    let spec = @[("C0", "P:0", 850'i64), ("C1", "P:1", 1_170'i64)] & kidsFrom(2)
    check runTrim(spec, twoOut = @["C1"]) == allBut(spec, "C1")

  # (b3..b64g) Ties of three or more equal FeeFracs. Core v31.1 has no rule
  # for these: the survivor falls out of libstdc++'s std::sort permutation of
  # equal keys (GroupClusters' an_deps, Trim's deps_by_parent) and of
  # std::make_heap / push_heap / pop_heap over equal elements. Neither
  # "earliest accepted stays" nor "latest accepted goes" fits: b3 drops the
  # first-accepted C0, b5 the second-accepted C1, b64 C35. Expected sets were
  # measured on Core v31.1 regtest with these exact shapes (P2SH(OP_TRUE)
  # spends, 64-output parent mined in 111 without entering the mempool,
  # children accepted in spec order, invalidateblock 111), 3/3 runs each:
  # staged-patches/kb192/core_trim_probe.py in the meta-repo.
  proc eqKids(ids: seq[int], fee = 2_000'i64): seq[TrimSpec] =
    for i in ids: result.add(("C" & $i, "P:" & $i, fee))

  test "KB-192 trim (b3): three-way tie at the bottom, accepted C0,C1,C2: Core drops C0":
    let spec = eqKids(@[0, 1, 2]) & kidsFrom(3)
    check runTrim(spec) == allBut(spec, "C0")

  test "KB-192 trim (b3_rev): three-way tie accepted C2,C1,C0: Core drops C2":
    let spec = eqKids(@[2, 1, 0]) & kidsFrom(3)
    check runTrim(spec) == allBut(spec, "C2")

  test "KB-192 trim (b4): four-way tie at the bottom: Core drops C0":
    let spec = eqKids(@[0, 1, 2, 3]) & kidsFrom(4)
    check runTrim(spec) == allBut(spec, "C0")

  test "KB-192 trim (b5): five-way tie at the bottom: Core drops C1":
    let spec = eqKids(@[0, 1, 2, 3, 4]) & kidsFrom(5)
    check runTrim(spec) == allBut(spec, "C1")

  test "KB-192 trim (b64): all 64 children tie: Core drops C35":
    var ids: seq[int]
    for i in 0 ..< 64: ids.add(i)
    let spec = eqKids(ids)
    check runTrim(spec) == allBut(spec, "C35")

  test "KB-192 trim (b64g): 64 tied children plus a low grandchild on C0: Core drops G0 and C44":
    var ids: seq[int]
    for i in 0 ..< 64: ids.add(i)
    let spec = eqKids(ids) & @[("G0", "C0", 100'i64)]
    check runTrim(spec) == allBut(spec, "G0", "C44")

  test "KB-192 trim (b3_two): three-way tie, two must go (C5 CPFP'd by G5): Core drops C0 and C2":
    let spec = eqKids(@[0, 1, 2]) & kidsFrom(3) & @[("G5", "C5", 50_000'i64)]
    check runTrim(spec) == allBut(spec, "C0", "C2")

  test "KB-192 trim (b3_hi): a three-way tie above the cut does not move the lowest-fee drop":
    let spec = @[("C0", "P:0", 1_000'i64)] & eqKids(@[1, 2, 3], 9_000) & kidsFrom(4)
    check runTrim(spec) == allBut(spec, "C0")
