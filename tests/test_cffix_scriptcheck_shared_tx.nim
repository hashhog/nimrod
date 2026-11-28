## test_cffix_scriptcheck_shared_tx.nim
##
## A block's script checks must share the block's transactions, not copy them
## once per input.
##
## Bitcoin Core: CScriptCheck holds `const CTransaction* ptxTo`
## (validation.h:338), and the interpreter's checker holds the same pointer.
## Every input's check of one tx reads the one CTransaction in the block.
##
## nimrod (before this fix): `ScriptCheck.tx` was a by-value `Transaction`
## filled with `tx: tx` once per input in collectChecks, and every check stays
## alive until runChecks returns. A tx with N inputs therefore held N full copies
## of itself: O(N x tx size) = O(N^2) memory for one consensus-valid tx. A block
## of P2A sweeps (each input ~41 bytes, no witness) is enough to need GBs, and
## an OOM on a valid block repeats at every restart. `SigCheckContext.tx` made
## one more copy of the tx for every input it verified.
##
## The tests here:
##   1. every ScriptCheck from collectChecks refers to the block's own tx;
##   2. memory held by the checks grows linearly with the input count
##      (N = 1k vs 2k), measured with getOccupiedMem;
##   3. a SigCheckContext borrows the tx it is built from;
##   4. verifying every input of an N-input tx costs linear time
##      (N = 2k vs 8k);
##   5. controls through the production envelope (verifyScripts): a P2A sweep
##      block is accepted; signed P2PKH spends in two txs of one block are
##      accepted, and still rejected when one tx changes after signing, or when
##      one input's prevout is unspendable. These would catch a check reading
##      the wrong tx or the wrong input.
##
## Both versions of nimrod compile this file: the tests read the check's tx
## through `checkTxAddr`, which handles a by-value field and a pointer field.

import unittest2
import std/[options, times, strutils]
import ../src/perf/verify_pool
import ../src/consensus/[validation, params]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/script/interpreter
import ../src/wallet/wallet
import ../src/crypto/[hashing, secp256k1]

const P2AScript = @[0x51'u8, 0x02, 0x4e, 0x73]  # OP_1 <0x4e73>, BIP-433 P2A

proc checkTxAddr(chk: ScriptCheck): pointer =
  ## Address of the Transaction a check verifies against: the pointee when the
  ## field is a pointer (head), the check's own field when it is a by-value
  ## copy (master).
  when chk.tx is ptr Transaction:
    cast[pointer](chk.tx)
  else:
    cast[pointer](unsafeAddr chk.tx)

proc prevTxid(n: int, tag: byte): TxId =
  var a: array[32, byte]
  a[0] = tag
  a[1] = byte(n and 0xff)
  a[2] = byte((n shr 8) and 0xff)
  a[3] = byte((n shr 16) and 0xff)
  TxId(a)

proc coinbaseTx(): Transaction =
  Transaction(
    version: 1'i32,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[0x03'u8, 0x05, 0x00, 0x00],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0'u32)

proc p2aSweepTx(n: int): Transaction =
  ## One tx spending N P2A outputs: empty scriptSig, empty witness.
  result = Transaction(version: 3'i32, lockTime: 0'u32)
  for i in 0 ..< n:
    result.inputs.add(TxIn(
      prevOut: OutPoint(txid: prevTxid(i, 0xa2), vout: 0'u32),
      scriptSig: @[],
      sequence: 0xFFFFFFFD'u32))
    result.witnesses.add(@[])
  result.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: @[0x6a'u8]))

proc mkBlock(params: ConsensusParams, txs: seq[Transaction]): Block =
  var hashes: seq[array[32, byte]]
  for t in txs: hashes.add(array[32, byte](t.txid()))
  Block(
    header: BlockHeader(
      version: 0x20000000'i32,
      prevBlock: params.genesisBlockHash,
      merkleRoot: hashing.computeMerkleRoot(hashes),
      timestamp: 1700000000'u32,
      bits: 0x207fffff'u32,
      nonce: 1'u32),
    txs: txs)

proc p2aLookup(): proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
  result = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
    some(UtxoEntry(
      output: TxOut(value: Satoshi(240), scriptPubKey: P2AScript),
      height: 1'i32, isCoinbase: false))

proc heldByChecks(n: int): int =
  ## Heap bytes still held after collectChecks returns, while the checks and
  ## their prevout store are alive (they stay alive until runChecks returns in
  ## verifyScripts). The block is built before the first reading.
  let params = regtestParams()
  let blk = mkBlock(params, @[coinbaseTx(), p2aSweepTx(n)])
  let lookup = p2aLookup()
  let before = getOccupiedMem()
  var checks: seq[ScriptCheck] = @[]
  var store: seq[TxPrevouts] = @[]
  let res = collectChecks(blk, lookup, 5'i32, params, checks, store)
  doAssert res.isOk
  doAssert checks.len == n
  result = getOccupiedMem() - before

suite "cffix nimrod: script checks share the block's tx":

  test "collectChecks: every ScriptCheck refers to the block's tx, not a copy (N=1k)":
    let params = regtestParams()
    let blk = mkBlock(params, @[coinbaseTx(), p2aSweepTx(1000)])
    var checks: seq[ScriptCheck] = @[]
    var store: seq[TxPrevouts] = @[]
    let res = collectChecks(blk, p2aLookup(), 5'i32, params, checks, store)
    check res.isOk
    check checks.len == 1000
    let want = cast[pointer](unsafeAddr blk.txs[1])
    var aliased = 0
    for i, chk in checks:
      check chk.inputIndex == i
      if checkTxAddr(chk) == want: inc aliased
    echo "  checks referring to blk.txs[1]: ", aliased, " / ", checks.len
    check aliased == checks.len

  test "collectChecks: memory held by the checks grows linearly with inputs (N=1k vs 2k)":
    when defined(useMalloc):
      skip()  # getOccupiedMem reads Nim's own allocator only
    else:
      discard heldByChecks(64)  # warm the allocator
      let m1 = heldByChecks(1000)
      let m2 = heldByChecks(2000)
      echo "  held after collectChecks: N=1000 ", m1, " B (", m1 div 1000,
           " B/input); N=2000 ", m2, " B (", m2 div 2000, " B/input); ratio ",
           formatFloat(m2 / max(m1, 1), ffDecimal, 2)
      # Instrument check: the checks themselves are on the heap, so a reading
      # of 0 means the measurement is broken, not that the fix worked.
      check m1 > 0
      check m2 > 0
      # Linear: doubling the inputs about doubles the memory (seq capacity
      # doubling stays well under 3x). One copy of the tx per input makes it 4x.
      check m2 < 3 * m1
      # Absolute bound: a check carries its input's own fields and a pointer.
      # The by-value tx copy is ~80 B per input of the tx, 160 kB per check
      # at N=2000.
      check m2 div 2000 < 4096

  test "SigCheckContext borrows the tx it is built from":
    let tx = p2aSweepTx(16)
    let ctx = SigCheckContext(tx: tx, inputIndex: 3, amount: Satoshi(240),
                              scriptPubKey: P2AScript, sigVersion: sigBase,
                              codesepPos: 0xFFFFFFFF'u32)
    check ctx.tx.inputs.len == 16
    check ctx.tx.inputs[3].prevOut == tx.inputs[3].prevOut
    check cast[pointer](unsafeAddr ctx.tx.inputs[0]) ==
          cast[pointer](unsafeAddr tx.inputs[0])
    check cast[pointer](unsafeAddr ctx.tx.witnesses[0]) ==
          cast[pointer](unsafeAddr tx.witnesses[0])

  test "verifying every input of an N-input tx is linear (N=2k vs 8k)":
    proc verifyAll(n: int): float =
      let tx = p2aSweepTx(n)
      let flags = {sfP2SH, sfWitness, sfTaproot, sfDERSig, sfNullFail,
                   sfCheckLockTimeVerify, sfCheckSequenceVerify}
      let t0 = epochTime()
      for i in 0 ..< n:
        doAssert verifyScriptWithError(@[], P2AScript, tx, i, Satoshi(240),
                                       flags, @[]) == seOk
      result = epochTime() - t0
    discard verifyAll(256)
    let t1 = verifyAll(2000)
    let t2 = verifyAll(8000)
    echo "  verify all inputs: N=2000 ", formatFloat(t1 * 1000, ffDecimal, 1),
         " ms; N=8000 ", formatFloat(t2 * 1000, ffDecimal, 1), " ms; ratio ",
         formatFloat(t2 / max(t1, 1e-6), ffDecimal, 2)
    # 4x the inputs: linear is ~4x, a tx copy per input is ~16x.
    check t2 < 8.0 * max(t1, 1e-3)

suite "cffix nimrod: verifyScripts controls (the shared tx is the right tx)":

  test "a 2,000-input P2A sweep block is accepted":
    let params = regtestParams()
    initVerifyPool(0)
    let blk = mkBlock(params, @[coinbaseTx(), p2aSweepTx(2000)])
    let res = verifyScripts(blk, p2aLookup(), 5'i32, newCryptoEngine(), params)
    check res.isOk

  test "signed P2PKH spends in two txs: accepted; changed-after-signing or bad prevout rejected":
    let params = regtestParams()
    initVerifyPool(0)
    const nIn = 3
    var keys: seq[(PrivateKey, PublicKey, seq[byte])]
    for k in 0 ..< 2 * nIn:
      var priv: PrivateKey
      priv[30] = 0x5c
      priv[31] = byte(k + 1)
      let pub = derivePublicKey(priv)
      var spk = @[0x76'u8, 0xa9, 0x14]
      spk.add(@(hash160(pub)))
      spk.add([0x88'u8, 0xac])
      keys.add((priv, pub, spk))

    proc signedTx(base: int, outValue: int64): Transaction =
      result = Transaction(version: 2'i32, lockTime: 0'u32)
      for i in 0 ..< nIn:
        result.inputs.add(TxIn(
          prevOut: OutPoint(txid: prevTxid(base + i, 0xb7), vout: 0'u32),
          scriptSig: @[], sequence: 0xFFFFFFFF'u32))
        result.witnesses.add(@[])
      result.outputs.add(TxOut(value: Satoshi(outValue),
                               scriptPubKey: @[0x51'u8]))
      for i in 0 ..< nIn:
        signInputP2PKH(result, i, keys[base + i][0], keys[base + i][1])

    var badSpk = -1
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      let a = array[32, byte](op.txid)
      if a[0] != 0xb7: return none(UtxoEntry)
      let k = int(a[1])
      {.cast(gcsafe).}:
        let spk = if k == badSpk: @[0x6a'u8] else: keys[k][2]
        some(UtxoEntry(output: TxOut(value: Satoshi(100_000), scriptPubKey: spk),
                       height: 1'i32, isCoinbase: false))

    let txA = signedTx(0, 250_000)
    let txB = signedTx(nIn, 260_000)
    let good = mkBlock(params, @[coinbaseTx(), txA, txB])
    check verifyScripts(good, lookup, 5'i32, newCryptoEngine(), params).isOk

    # txB's output changes after it was signed: its signatures no longer
    # commit to it. A check reading txA (or a stale copy) in place of txB
    # would accept this block.
    var txBm = txB
    txBm.outputs[0].value = Satoshi(260_001)
    let mutated = mkBlock(params, @[coinbaseTx(), txA, txBm])
    let r1 = verifyScripts(mutated, lookup, 5'i32, newCryptoEngine(), params)
    check not r1.isOk
    if not r1.isOk: check r1.error == veScriptVerifyFailed

    # The last input of txB spends an unspendable (OP_RETURN) prevout.
    badSpk = 2 * nIn - 1
    let r2 = verifyScripts(good, lookup, 5'i32, newCryptoEngine(), params)
    check not r2.isOk
    if not r2.isOk: check r2.error == veScriptVerifyFailed
    badSpk = -1
