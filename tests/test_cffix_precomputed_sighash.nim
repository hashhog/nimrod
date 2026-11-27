## BIP-143 / BIP-341 whole-transaction sighash digests are built ONCE per
## transaction, not once per signature check (cffix-nimrod-precomputed-sighash).
##
## Core: PrecomputedTransactionData (script/interpreter.h:163, Init in
## interpreter.cpp) hashes every prevout, sequence, spent amount, spent
## scriptPubKey and output once per tx; SignatureHash / SignatureHashSchnorr
## then read those hashes for every input. nimrod's computeSighashSegwitV0 /
## computeSighashTaproot re-serialized and re-hashed all of them on every
## CHECKSIG, so a tx with N signatures cost O(N x N) bytes of SHA-256.
##
## Instrument: `sighashHashedBytes()` counts the bytes fed to SHA-256 while
## building segwit sighashes (test hook in script/interpreter.nim). Doubling the
## input count of a one-sig-per-input tx must roughly double that number
## (linear), not quadruple it (quadratic). Bar: growth < 3x for 200 -> 400.
##
## Head-only API (PrecomputedTxData, initPrecomputedTxData, the `txdata`
## parameter) is reached only under `when HasTxData`, so this file compiles on
## master and the measured tests fail there on their assertion.

import unittest2
import std/[options, os, json, strutils, random, tempfiles]
import ../src/script/interpreter
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[validation, params]
import ../src/storage/chainstate
import ../src/perf/verify_pool
import ../src/mempool/mempool
import ../src/wallet/wallet

const
  HasCounter = declared(sighashHashedBytes)
  HasTxData = declared(initPrecomputedTxData)
  GrowthBar = 3.0
  Value = 5_000_000'i64

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

proc unhex(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i + 1]))

proc unhex32(s: string): array[32, byte] =
  let b = unhex(s)
  doAssert b.len == 32
  for i in 0 ..< 32: result[i] = b[i]

proc mkPriv(i: int): PrivateKey =
  for j in 0 ..< 32: result[j] = 0
  result[29] = 0x5a
  result[30] = byte((i shr 8) and 0xff)
  result[31] = byte(i and 0xff)

proc p2trOf(priv: PrivateKey): seq[byte] =
  ## Witness v1 program = the raw x-only key; signSchnorr with merkleRoot =
  ## none signs for exactly this key.
  let c = derivePublicKey(priv)
  result = @[0x51'u8, 0x20]
  for i in 0 ..< 32: result.add c[1 + i]

proc p2wpkhOf(pub: PublicKey): seq[byte] =
  @[0x00'u8, 0x14] & @(hash160(pub))

proc p2shTrue(): seq[byte] =
  @[0xa9'u8, 0x14] & @(hash160(@[0x51'u8])) & @[0x87'u8]

const FundTxid = block:
  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = byte(0xa0 + (i mod 16))
  a

type Spend = object
  tx: Transaction
  amounts: seq[Satoshi]
  spks: seq[seq[byte]]
  prevs: seq[OutPoint]

proc unsignedSpend(prevs: seq[OutPoint], spks: seq[seq[byte]]): Spend =
  result.prevs = prevs
  result.spks = spks
  result.tx = Transaction(version: 2, lockTime: 0)
  for p in prevs:
    result.tx.inputs.add TxIn(prevOut: p, scriptSig: @[],
                              sequence: 0xFFFFFFFD'u32)
    result.amounts.add Satoshi(Value)
  result.tx.outputs = @[
    TxOut(value: Satoshi(Value * int64(prevs.len) - 1_000_000),
          scriptPubKey: p2shTrue()),
    TxOut(value: Satoshi(1000), scriptPubKey: p2shTrue())]
  result.tx.witnesses = newSeq[seq[seq[byte]]](prevs.len)

proc p2trSpend(prevs: seq[OutPoint], keyIds: seq[int]): Spend =
  var spks: seq[seq[byte]]
  for k in keyIds: spks.add p2trOf(mkPriv(k))
  result = unsignedSpend(prevs, spks)
  for i in 0 ..< prevs.len:
    let sh = computeSighashTaproot(result.tx, i, result.amounts, result.spks, 0x00)
    result.tx.witnesses[i] = @[@(signSchnorr(mkPriv(keyIds[i]), sh,
                                             none(array[32, byte])))]

proc p2wpkhSpend(prevs: seq[OutPoint], keyIds: seq[int]): Spend =
  var spks: seq[seq[byte]]
  for k in keyIds: spks.add p2wpkhOf(derivePublicKey(mkPriv(k)))
  result = unsignedSpend(prevs, spks)
  for i in 0 ..< prevs.len:
    let priv = mkPriv(keyIds[i])
    signInputP2WPKH(result.tx, i, priv, derivePublicKey(priv), Satoshi(Value))

proc fundedPrevs(n: int): seq[OutPoint] =
  for i in 0 ..< n: result.add OutPoint(txid: TxId(FundTxid), vout: uint32(i))

proc keyIds(first, n: int): seq[int] =
  for i in 0 ..< n: result.add first + i

proc corrupt(s: var Spend, idx: int) =
  ## Flip one bit of input idx's signature (first witness element).
  s.tx.witnesses[idx][0][7] = s.tx.witnesses[idx][0][7] xor 0x01

proc coinbaseTx(height: int32, outs: seq[TxOut]): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: @[0x01'u8, byte(height and 0xff), 0x01, 0],
                   sequence: 0xFFFFFFFF'u32)],
    outputs: outs, witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

# --- block path --------------------------------------------------------------

const BlockHeight = 200'i32

proc spendBlock(s: Spend): Block =
  let cb = coinbaseTx(BlockHeight, @[TxOut(value: Satoshi(Value),
                                           scriptPubKey: p2shTrue())])
  blockOf(BlockHash(default(array[32, byte])), BlockHeight, @[cb, s.tx])

proc lookupFor(s: Spend): proc(op: OutPoint): Option[UtxoEntry] =
  let spks = s.spks
  result = proc(op: OutPoint): Option[UtxoEntry] =
    if array[32, byte](op.txid) == FundTxid and int(op.vout) < spks.len:
      some(UtxoEntry(output: TxOut(value: Satoshi(Value),
                                   scriptPubKey: spks[int(op.vout)]),
                     height: 1, isCoinbase: false))
    else:
      none(UtxoEntry)

proc runBlockSerial(s: Spend): bool =
  ## The production entry point (ConnectBlock's script phase).
  verifyScripts(spendBlock(s), lookupFor(s), BlockHeight, newCryptoEngine(),
                regtestParams()).isOk

proc runBlockPool(s: Spend): bool =
  ## collectChecks + the static-pool runner with 3 helper threads.
  var checks: seq[ScriptCheck]
  var store: seq[TxPrevouts]
  let c = collectChecks(spendBlock(s), lookupFor(s), BlockHeight,
                        regtestParams(), checks, store)
  doAssert c.isOk
  runChecksWithN(4, checks).ok

proc runDirectNoTxdata(s: Spend): bool =
  ## Negative control for the instrument: per-input verifyScriptWithError
  ## with NO per-tx data, i.e. the old shape of every call site.
  let flags = getBlockScriptFlags(BlockHeight, regtestParams())
  result = true
  for i in 0 ..< s.tx.inputs.len:
    if verifyScriptWithError(s.tx.inputs[i].scriptSig, s.spks[i], s.tx, i,
                             s.amounts[i], flags, s.tx.witnesses[i],
                             s.amounts, s.spks) != seOk:
      result = false

proc measured(run: proc(): bool): tuple[ok: bool, bytes: int] =
  when HasCounter:
    resetSighashHashedBytes()
    sighashByteCounting = true
    let ok = run()
    sighashByteCounting = false
    (ok, sighashHashedBytes())
  else:
    (run(), -1)

proc growth(label: string, mk: proc(n: int): Spend,
            run: proc(s: Spend): bool): float =
  ## Bytes hashed at N=400 divided by bytes hashed at N=200.
  let s200 = mk(200)
  let s400 = mk(400)
  let a = measured(proc(): bool = run(s200))
  let b = measured(proc(): bool = run(s400))
  check a.ok
  check b.ok
  when HasCounter:
    result = b.bytes.float / max(1, a.bytes).float
    echo "cffix ", label, ": N=200 ", a.bytes, " B, N=400 ", b.bytes,
         " B, growth ", formatFloat(result, ffDecimal, 2), "x (bar < ",
         GrowthBar, ")"
  else:
    result = Inf

proc mkP2tr(n: int): Spend = p2trSpend(fundedPrevs(n), keyIds(1, n))
proc mkP2wpkh(n: int): Spend = p2wpkhSpend(fundedPrevs(n), keyIds(1, n))

# --- mempool path ------------------------------------------------------------

type MpFx = object
  dir: string
  cs: ChainState
  mp: Mempool
  fund: Transaction

proc mpSetup(nOuts: int): MpFx =
  ## The height-1 coinbase pays nOuts P2TR outputs (key i+1 for output i);
  ## 100 more blocks make it mature for the next block. (A genesis coinbase
  ## is never spendable, as in Core.)
  let params = regtestParams()
  result.dir = createTempDir("nimrod_cffix_precomputed_sighash_", "")
  result.cs = newChainState(result.dir / "db", params)
  var outs: seq[TxOut]
  for i in 0 ..< nOuts:
    outs.add TxOut(value: Satoshi(Value), scriptPubKey: p2trOf(mkPriv(i + 1)))
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 101:
    let cb = if h == 1: coinbaseTx(1, outs)
             else: coinbaseTx(int32(h), @[TxOut(value: Satoshi(Value),
                                                scriptPubKey: p2shTrue())])
    if h == 1: result.fund = cb
    let blk = blockOf(prev, int32(h), @[cb])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  result.mp = newMempool(result.cs, params)

proc mpTeardown(f: var MpFx) =
  f.cs.close()
  removeDir(f.dir)

proc mpSpend(f: MpFx, first, n: int): Spend =
  var prevs: seq[OutPoint]
  for i in first ..< first + n:
    prevs.add OutPoint(txid: f.fund.txid(), vout: uint32(i))
  p2trSpend(prevs, keyIds(first + 1, n))

# ---------------------------------------------------------------------------
# 1. growth: per-tx digests are hashed once per tx
# ---------------------------------------------------------------------------

suite "cffix precomputed sighash: SHA-256 bytes grow linearly with inputs":

  test "instrument: the sighash byte counter exists":
    when not HasCounter:
      checkpoint "no sighashHashedBytes() test hook in script/interpreter"
      fail()

  test "negative control: per-input calls without per-tx data are quadratic":
    ## Proves the counter can see the rebuilds: the same 200 -> 400 doubling
    ## through calls that carry no per-tx data must grow ~4x.
    let g = growth("control no-txdata P2TR", mkP2tr, runDirectNoTxdata)
    when HasCounter:
      check g >= 3.5
    else:
      checkpoint "no sighashHashedBytes() test hook: nothing to control"
      fail()

  test "block verifyScripts, P2TR key path: growth < 3x":
    check growth("block P2TR", mkP2tr, runBlockSerial) < GrowthBar

  test "block verifyScripts, P2WPKH (BIP-143): growth < 3x":
    check growth("block P2WPKH", mkP2wpkh, runBlockSerial) < GrowthBar

  test "block script-check pool (4 threads), P2TR key path: growth < 3x":
    check growth("pool P2TR", mkP2tr, runBlockPool) < GrowthBar

  test "block script-check pool (4 threads), P2WPKH: growth < 3x":
    check growth("pool P2WPKH", mkP2wpkh, runBlockPool) < GrowthBar

  test "mempool acceptTransaction, P2TR key path: growth < 3x":
    var f = mpSetup(600)
    defer: f.mpTeardown()
    let s200 = f.mpSpend(0, 200)
    let s400 = f.mpSpend(200, 400)
    let a = measured(proc(): bool =
      let r = f.mp.acceptTransaction(s200.tx, newCryptoEngine())
      if not r.isOk: checkpoint r.error
      r.isOk)
    let b = measured(proc(): bool =
      let r = f.mp.acceptTransaction(s400.tx, newCryptoEngine())
      if not r.isOk: checkpoint r.error
      r.isOk)
    check a.ok
    check b.ok
    when HasCounter:
      let g = b.bytes.float / max(1, a.bytes).float
      echo "cffix mempool P2TR: N=200 ", a.bytes, " B, N=400 ", b.bytes,
           " B, growth ", formatFloat(g, ffDecimal, 2), "x (bar < ", GrowthBar, ")"
      check g < GrowthBar
    else:
      fail()

# ---------------------------------------------------------------------------
# 2. verdicts: a bad signature anywhere in the tx is still rejected
# ---------------------------------------------------------------------------

suite "cffix precomputed sighash: verdict controls":

  test "block serial + pool: one corrupted signature (input 0/117/199 of 200) rejects":
    for mk in [mkP2tr, mkP2wpkh]:
      let good = mk(200)
      check runBlockSerial(good)
      check runBlockPool(good)
      for idx in [0, 117, 199]:
        var bad = good
        bad.corrupt(idx)
        check not runBlockSerial(bad)
        check not runBlockPool(bad)

  test "mempool: one corrupted signature (input 0/117/199 of 200) rejects":
    # Each bad tx spends its own 200 coins, so no reject cache or conflict
    # can stand in for the script check.
    var f = mpSetup(800)
    defer: f.mpTeardown()
    let good = f.mpSpend(0, 200)
    for k, idx in [0, 117, 199]:
      var bad = f.mpSpend(200 * (k + 1), 200)
      bad.corrupt(idx)
      let r = f.mp.acceptTransaction(bad.tx, newCryptoEngine())
      check not r.isOk
      if not r.isOk:
        checkpoint "input " & $idx & ": " & r.error
        check "script-verify-flag-failed" in r.error
    let r = f.mp.acceptTransaction(good.tx, newCryptoEngine())
    if not r.isOk: checkpoint r.error
    check r.isOk

# ---------------------------------------------------------------------------
# 3. vectors: the cached digests are byte-identical to the direct ones
# ---------------------------------------------------------------------------

proc findVectors(name: string): string =
  var tried: seq[string]
  for depth in 0 .. 5:
    let p = "../".repeat(depth) & "bitcoin-core/src/test/data/" & name
    tried.add p
    if fileExists(p): return p
  for d in [currentSourcePath().parentDir() / ".." / ".." / "bitcoin-core",
            currentSourcePath().parentDir() / ".." / ".." / ".." / "bitcoin-core"]:
    let p = d / "src" / "test" / "data" / name
    tried.add p
    if fileExists(p): return p
  checkpoint "could not find " & name & "; tried: " & tried.join(", ")
  ""

suite "cffix precomputed sighash: BIP-143 / BIP-341 vectors unchanged":

  test "BIP-143 native P2WPKH example: cached hashes and sighash":
    let tx = deserializeTransaction(unhex(
      "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" &
      "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57" &
      "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85" &
      "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2" &
      "f0167faa815988ac11000000"))
    let scriptCode = unhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
    let want = unhex32("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
    check computeSighashSegwitV0(tx, 1, scriptCode, Satoshi(600_000_000), 1) == want
    when HasTxData:
      var td = initPrecomputedTxData(tx, @[], @[], force = true)
      check td.bip143Ready
      check td.hashPrevouts == unhex32("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
      check td.hashSequence == unhex32("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
      check td.hashOutputs == unhex32("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")
      check computeSighashSegwitV0(tx, 1, scriptCode, Satoshi(600_000_000), 1,
                                   addr td) == want
    else:
      checkpoint "no PrecomputedTxData"
      fail()

  test "BIP-341 wallet vectors (Core bip341_wallet_vectors.json): intermediary hashes and sigHash":
    let path = findVectors("bip341_wallet_vectors.json")
    check path.len > 0
    if path.len > 0:
      let j = parseFile(path)
      var nChecked = 0
      for e in j["keyPathSpending"]:
        let tx = deserializeTransaction(unhex(e["given"]["rawUnsignedTx"].getStr))
        var amounts: seq[Satoshi]
        var spks: seq[seq[byte]]
        for u in e["given"]["utxosSpent"]:
          amounts.add Satoshi(u["amountSats"].getBiggestInt)
          spks.add unhex(u["scriptPubKey"].getStr)
        when HasTxData:
          var td = initPrecomputedTxData(tx, amounts, spks, force = true)
          let im = e["intermediary"]
          check td.bip341Ready
          check td.shaAmounts == unhex32(im["hashAmounts"].getStr)
          check td.shaOutputs == unhex32(im["hashOutputs"].getStr)
          check td.shaPrevouts == unhex32(im["hashPrevouts"].getStr)
          check td.shaScriptPubKeys == unhex32(im["hashScriptPubkeys"].getStr)
          check td.shaSequences == unhex32(im["hashSequences"].getStr)
        for inp in e["inputSpending"]:
          let idx = inp["given"]["txinIndex"].getInt
          let ht = uint8(inp["given"]["hashType"].getInt)
          let want = unhex32(inp["intermediary"]["sigHash"].getStr)
          check computeSighashTaproot(tx, idx, amounts, spks, ht) == want
          when HasTxData:
            check computeSighashTaproot(tx, idx, amounts, spks, ht,
                                        txdata = addr td) == want
          inc nChecked
      echo "cffix BIP-341 keyPathSpending inputs checked: ", nChecked
      check nChecked == 7
      when not HasTxData:
        checkpoint "no PrecomputedTxData"
        fail()

  test "differential: cached == direct over random txs, hash types, annex, codesep, script path":
    when HasTxData:
      var rng = initRand(0x5eed_cf1)
      var compared = 0
      proc rb(rng: var Rand, n: int): seq[byte] =
        for i in 0 ..< n: result.add byte(rng.rand(255))
      for trial in 0 ..< 300:
        var tx = Transaction(version: int32(rng.rand(3)), lockTime: uint32(rng.rand(1_000_000)))
        let nIn = 1 + rng.rand(7)
        let nOut = rng.rand(5)     # 0 outputs is legal for a sighash
        var amounts: seq[Satoshi]
        var spks: seq[seq[byte]]
        for i in 0 ..< nIn:
          var t: array[32, byte]
          for k in 0 ..< 32: t[k] = byte(rng.rand(255))
          tx.inputs.add TxIn(prevOut: OutPoint(txid: TxId(t), vout: uint32(rng.rand(10))),
                             scriptSig: @[], sequence: uint32(rng.rand(int(high(int32)))))
          amounts.add Satoshi(rng.rand(2_100_000_000))
          spks.add(if rng.rand(1) == 0: @[0x51'u8, 0x20] & rb(rng, 32)
                   else: rb(rng, rng.rand(40)))
        for o in 0 ..< nOut:
          let big = trial mod 50 == 0 and o == 0
          tx.outputs.add TxOut(value: Satoshi(rng.rand(1_000_000)),
                               scriptPubKey: rb(rng, if big: 300 else: rng.rand(40)))
        var td = initPrecomputedTxData(tx, amounts, spks, force = true)
        for inIdx in 0 ..< nIn:
          # BIP-143: every hash type, including odd ones the encoding allows.
          for ht in [0x01'u32, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x04, 0x41,
                     uint32(rng.rand(int(high(int32))))]:
            let sc = rb(rng, rng.rand(30))
            let amt = Satoshi(rng.rand(1_000_000))
            check computeSighashSegwitV0(tx, inIdx, sc, amt, ht, addr td) ==
                  computeSighashSegwitV0(tx, inIdx, sc, amt, ht)
            inc compared
          # BIP-341 / BIP-342.
          for ht in [0x00'u8, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]:
            let ext = uint8(rng.rand(1))
            let annex = if rng.rand(2) == 0: @[0x50'u8] & rb(rng, rng.rand(20)) else: @[]
            let leaf = block:
              var a: array[32, byte]
              for k in 0 ..< 32: a[k] = byte(rng.rand(255))
              a
            let cs = if rng.rand(1) == 0: 0xFFFFFFFF'u32 else: uint32(rng.rand(100))
            check computeSighashTaproot(tx, inIdx, amounts, spks, ht, ext, annex,
                                        leaf, cs, addr td) ==
                  computeSighashTaproot(tx, inIdx, amounts, spks, ht, ext, annex,
                                        leaf, cs)
            inc compared
      echo "cffix differential: ", compared, " sighashes compared, cached == direct"
      check compared > 3000
    else:
      checkpoint "no PrecomputedTxData"
      fail()

  test "a stale cache is visible, a mis-shaped cache is not used":
    when HasTxData:
      var s = mkP2tr(3)
      var td = initPrecomputedTxData(s.tx, s.amounts, s.spks)
      check td.bip341Ready
      let before = computeSighashTaproot(s.tx, 1, s.amounts, s.spks, 0x00)
      check computeSighashTaproot(s.tx, 1, s.amounts, s.spks, 0x00,
                                  txdata = addr td) == before
      # Same shape, changed output: the cache is now wrong, and the
      # comparisons above would see it.
      var changed = s.tx
      changed.outputs[0].value = Satoshi(int64(changed.outputs[0].value) - 1)
      check computeSighashTaproot(changed, 1, s.amounts, s.spks, 0x00,
                                  txdata = addr td) !=
            computeSighashTaproot(changed, 1, s.amounts, s.spks, 0x00)
      # Different shape (one more input / output): the cache is refused.
      var grown = s.tx
      grown.inputs.add grown.inputs[0]
      grown.outputs.add grown.outputs[0]
      let am4 = s.amounts & @[s.amounts[0]]
      let sp4 = s.spks & @[s.spks[0]]
      check computeSighashTaproot(grown, 1, am4, sp4, 0x00, txdata = addr td) ==
            computeSighashTaproot(grown, 1, am4, sp4, 0x00)
      check computeSighashSegwitV0(grown, 1, @[0x51'u8], Satoshi(1), 1, addr td) ==
            computeSighashSegwitV0(grown, 1, @[0x51'u8], Satoshi(1), 1)
    else:
      checkpoint "no PrecomputedTxData"
      fail()

  test "verifier ignores per-tx data unless given the full spent-output arrays":
    ## Invalid-made-valid guard. Without the full arrays the verifier signs
    ## over its single-input fallback (other inputs: 0 sats, empty script), so
    ## a multi-input key-path spend fails. Handing it per-tx data built from
    ## the REAL arrays must not turn that failure into a pass.
    when HasTxData:
      let s = mkP2tr(3)
      var td = initPrecomputedTxData(s.tx, s.amounts, s.spks)
      check td.bip341Ready
      let flags = getBlockScriptFlags(BlockHeight, regtestParams())
      for i in 0 ..< 3:
        # Full arrays: valid with or without the per-tx data.
        check verifyScriptWithError(s.tx.inputs[i].scriptSig, s.spks[i], s.tx, i,
                                    s.amounts[i], flags, s.tx.witnesses[i],
                                    s.amounts, s.spks, addr td) == seOk
        check verifyScript(s.tx.inputs[i].scriptSig, s.spks[i], s.tx, i,
                           s.amounts[i], flags, s.tx.witnesses[i],
                           s.amounts, s.spks, addr td)
        # No arrays: the same verdict as without per-tx data (a failure).
        let direct = verifyScriptWithError(s.tx.inputs[i].scriptSig, s.spks[i],
                                           s.tx, i, s.amounts[i], flags,
                                           s.tx.witnesses[i])
        check direct != seOk
        check verifyScriptWithError(s.tx.inputs[i].scriptSig, s.spks[i], s.tx, i,
                                    s.amounts[i], flags, s.tx.witnesses[i],
                                    @[], @[], addr td) == direct
        check not verifyScript(s.tx.inputs[i].scriptSig, s.spks[i], s.tx, i,
                               s.amounts[i], flags, s.tx.witnesses[i],
                               @[], @[], addr td)
    else:
      checkpoint "no PrecomputedTxData"
      fail()

  test "readiness follows Core's PrecomputedTransactionData::Init":
    when HasTxData:
      let tr = mkP2tr(2)
      let wp = mkP2wpkh(2)
      # P2TR witness spends with known spent outputs -> BIP-341 half only.
      let a = initPrecomputedTxData(tr.tx, tr.amounts, tr.spks)
      check a.bip341Ready and not a.bip143Ready
      # P2WPKH witness spends -> BIP-143 half only.
      let b = initPrecomputedTxData(wp.tx, wp.amounts, wp.spks)
      check b.bip143Ready and not b.bip341Ready
      # Spent outputs unknown: a P2TR witness spend counts as BIP-143 use and
      # the BIP-341 half is never ready.
      let c = initPrecomputedTxData(tr.tx, @[], @[])
      check c.bip143Ready and not c.bip341Ready
      # No witness at all -> nothing precomputed.
      var legacy = tr.tx
      legacy.witnesses = @[]
      let d = initPrecomputedTxData(legacy, tr.amounts, tr.spks)
      check not d.bip143Ready and not d.bip341Ready
      # The block path builds it for every tx.
      var checks: seq[ScriptCheck]
      var store: seq[TxPrevouts]
      check collectChecks(spendBlock(tr), lookupFor(tr), BlockHeight,
                          regtestParams(), checks, store).isOk
      check store.len == 1
      check store[0].txdata.bip341Ready
    else:
      checkpoint "no PrecomputedTxData"
      fail()
