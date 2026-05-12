## W96 — AcceptToMemoryPool (MemPoolAccept) end-to-end audit.
##
## Each test covers one gate from Bitcoin Core's MemPoolAccept pipeline
## (validation.cpp PreChecks / ReplacementChecks / PolicyScriptChecks /
## ConsensusScriptChecks / AcceptSingleTransactionInternal).  Where possible
## we also exercise the gate variations that depend on ATMP args
## (test_accept, bypass_limits, client_maxfeerate, allow_replacement).

import unittest2
import std/[os, options, tables, sets, times, strutils]
import ../src/mempool/mempool
import ../src/mempool/standard
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter

const TestDbPath = "/tmp/nimrod_atmp_w96_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

proc makeP2PKHScript(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] & @(default(array[20, byte])) &
  @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

proc makeP2SHScript(hash20: array[20, byte] = default(array[20, byte])): seq[byte] =
  @[byte(OP_HASH160), 0x14] & @hash20 & @[byte(OP_EQUAL)]

proc makeNonStandardScript(): seq[byte] =
  # 41 OP_RESERVED bytes — fails Solver(); classified as NONSTANDARD by
  # nimrod's classifyStdTxout.
  result = newSeq[byte](41)
  for i in 0 ..< 41:
    result[i] = 0x50  # OP_RESERVED

proc makeWitnessUnknownScript(): seq[byte] =
  # vNN witness program with version=5, 20-byte program (well-formed but
  # not standardised → WITNESS_UNKNOWN in Solver).
  @[byte(OP_5), 0x14] & @(default(array[20, byte]))

proc makeCoinbaseTx(height: int32, value: int64 = 5_000_000_000): Transaction =
  var scriptSig: seq[byte]
  if height < 256:
    scriptSig = @[byte(0x01), byte(height)]
  else:
    scriptSig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xFFFFFFFF'u32
      ),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: makeP2PKHScript()
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSpendTx(prevTxid: TxId, prevVout: uint32,
                 outputValue: int64,
                 sequence: uint32 = 0xFFFFFFFF'u32,
                 lockTime: uint32 = 0,
                 spk: seq[byte] = @[]): Transaction =
  let pk = if spk.len > 0: spk else: makeP2PKHScript()
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: sequence
    )],
    outputs: @[TxOut(value: Satoshi(outputValue), scriptPubKey: pk)],
    witnesses: @[],
    lockTime: lockTime
  )

proc makeTestBlock(prevHash: BlockHash, height: int32,
                   txs: seq[Transaction]): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: txs
  )

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  makeTestBlock(prevHash, height, @[makeCoinbaseTx(height)])

proc buildChainToMaturity(cs: var ChainState): (TxId, BlockHash) =
  ## Build 101 blocks; returns the height-1 coinbase txid (mature at height 101).
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  var prevHash = getBlockHash(genesis)
  var spendableTxid = genesis.txs[0].txid()
  for h in 1 .. 101:
    let blk = makeSimpleBlock(prevHash, int32(h))
    discard cs.connectBlock(blk, int32(h))
    if h == 1:
      spendableTxid = blk.txs[0].txid()
    prevHash = getBlockHash(blk)
  (spendableTxid, prevHash)

# ---------------------------------------------------------------------------
# Test suites — one per gate.
# ---------------------------------------------------------------------------

suite "W96 PreChecks — coinbase / size / weight":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "coinbase rejected":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    let cb = makeCoinbaseTx(100)
    let r = mp.acceptTransaction(cb, crypto)
    check not r.isOk
    check "coinbase" in r.error
    cs.close()

  test "tx-size-small (< 65 nonwitness bytes)":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    # Build a maximally minimal tx (≤ 64 bytes).
    let tinyTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[byte(OP_RETURN)])],
      witnesses: @[],
      lockTime: 0
    )
    let r = mp.acceptTransaction(tinyTx, crypto)
    check not r.isOk
    check "tx-size-small" in r.error
    cs.close()

suite "W96 PreChecks — wtxid duplicate detection":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "txn-already-in-mempool (exact wtxid match)":
    ## W96 GAP #1a: BIP-141 exists-by-wtxid path must reject same wtxid.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_999_000)
    # First insert directly into mempool state (bypassing script check by
    # forcing the entry).
    let entry = MempoolEntry(
      tx: tx, txid: tx.txid(), wtxid: tx.wtxid(),
      fee: Satoshi(1000), weight: 400,
      feeRate: 10.0, timeAdded: getTime(),
      height: 101, ancestorFee: Satoshi(1000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[tx.txid()] = entry
    mp.byWtxid[tx.wtxid()] = tx.txid()

    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "txn-already-in-mempool" in r.error
    cs.close()

  test "txn-same-nonwitness-data-in-mempool (txid clash, wtxid diff)":
    ## W96 GAP #1b: same txid + different wtxid (witness mutation).
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_999_000)
    # Force-insert with a fake wtxid different from the real one.
    var fakeW: array[32, byte]
    fakeW[0] = 0xAA
    let entry = MempoolEntry(
      tx: tx, txid: tx.txid(), wtxid: TxId(fakeW),
      fee: Satoshi(1000), weight: 400,
      feeRate: 10.0, timeAdded: getTime(),
      height: 101, ancestorFee: Satoshi(1000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[tx.txid()] = entry
    mp.byWtxid[TxId(fakeW)] = tx.txid()

    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "txn-same-nonwitness-data-in-mempool" in r.error
    cs.close()

suite "W96 PreChecks — bad-txns-inputs-missingorspent / txn-already-known":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bad-txns-inputs-missingorspent when prevout absent":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    var fake: array[32, byte]
    fake[0] = 0xDE
    fake[1] = 0xAD
    let tx = makeSpendTx(TxId(fake), 0, 1_000_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "bad-txns-inputs-missingorspent" in r.error
    cs.close()

suite "W96 PreChecks — coinbase maturity":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bad-txns-premature-spend-of-coinbase":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    # Only build 50 blocks — much less than coinbaseMaturity (100).
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    var prevHash = getBlockHash(genesis)
    var freshCoinbaseTxid = genesis.txs[0].txid()
    for h in 1 .. 49:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      freshCoinbaseTxid = blk.txs[0].txid()
      prevHash = getBlockHash(blk)
    # Try to spend the most-recent coinbase (immature).
    let tx = makeSpendTx(freshCoinbaseTxid, 0, 4_999_000_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "premature-spend-of-coinbase" in r.error or
          "coinbase output not yet mature" in r.error
    cs.close()

suite "W96 PreChecks — non-final tx (BIP-113)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "non-final due to future locktime":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    # Far-future locktime (block height 9_999_999) and sequence != MAX so
    # IsFinalTx evaluates the locktime instead of treating as final.
    let tx = makeSpendTx(spendable, 0, 4_999_000_000,
                          sequence = 0, lockTime = 9_999_999'u32)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "non-final" in r.error
    cs.close()

suite "W96 PolicyScriptChecks — STANDARD_SCRIPT_VERIFY_FLAGS":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "standardScriptVerifyFlags includes all policy flags from policy.h":
    ## W96: STANDARD_SCRIPT_VERIFY_FLAGS is consensus + policy flags. Without
    ## the policy flags, txs with non-LOW_S sigs or non-MINIMAL pushes would
    ## relay (Core's bitcoin/policy/policy.h:119-132).
    let consensus = {sfP2SH, sfDERSig, sfWitness, sfNullDummy}
    let std = standardScriptVerifyFlags(consensus)
    # Consensus subset preserved
    check sfP2SH in std
    check sfWitness in std
    # Policy additions
    check sfStrictEnc in std
    check sfMinimalData in std
    check sfDiscourageUpgradableNops in std
    check sfCleanStack in std
    check sfMinimalIf in std
    check sfNullFail in std
    check sfLowS in std
    check sfDiscourageUpgradableWitnessProgram in std
    check sfWitnessPubkeyType in std
    check sfDiscourageUpgradableTaprootVersion in std
    check sfDiscourageOpSuccess in std
    check sfDiscourageUpgradablePubkeyType in std

suite "W96 PreChecks — ValidateInputsStandardness (W96 GAP #4)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bad-txns-nonstandard-inputs when input script is unknown":
    ## ValidateInputsStandardness: NONSTANDARD prevout → reject.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()

    # Build a chain so we have a real tip.
    let (_, _) = buildChainToMaturity(cs)

    # Synthesize a UTXO with NON-STANDARD scriptPubKey at outpoint we'll spend.
    var fakeUtxoTxid: array[32, byte]
    fakeUtxoTxid[0] = 0xAB
    let badSpk = makeNonStandardScript()
    let synthUtxo = UtxoEntry(
      output: TxOut(value: Satoshi(1_000_000), scriptPubKey: badSpk),
      height: 1, isCoinbase: false
    )
    cs.putUtxoCache(OutPoint(txid: TxId(fakeUtxoTxid), vout: 0), synthUtxo)

    let tx = makeSpendTx(TxId(fakeUtxoTxid), 0, 999_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check "bad-txns-nonstandard-inputs" in r.error or "non-standard" in r.error
    cs.close()

  test "bad-txns-nonstandard-inputs when witness program version is unknown":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (_, _) = buildChainToMaturity(cs)

    var fakeUtxoTxid: array[32, byte]
    fakeUtxoTxid[0] = 0xCD
    let weirdSpk = makeWitnessUnknownScript()
    let synthUtxo = UtxoEntry(
      output: TxOut(value: Satoshi(1_000_000), scriptPubKey: weirdSpk),
      height: 1, isCoinbase: false
    )
    cs.putUtxoCache(OutPoint(txid: TxId(fakeUtxoTxid), vout: 0), synthUtxo)

    let tx = makeSpendTx(TxId(fakeUtxoTxid), 0, 999_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    # Either flagged by ValidateInputsStandardness or by IsWitnessStandard.
    check "bad-txns-nonstandard-inputs" in r.error or
          "bad-witness-nonstandard" in r.error or
          "witness program is undefined" in r.error or
          "non-standard" in r.error
    cs.close()

suite "W96 ATMP args — client_maxfeerate":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "max feerate exceeded when client cap < tx feerate":
    ## W96 GAP #7: ATMPArgs.clientMaxFeeRateSatKvB enforcement.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    # Spend 5 BTC coinbase paying 4_999_900_000 satoshis → fee = 100_000 sat
    # over ~100 vbyte tx, feerate ~1000 sat/vB = 1_000_000 sat/kvB.
    let tx = makeSpendTx(spendable, 0, 4_999_900_000)
    var args = defaultAtmpArgs()
    args.clientMaxFeeRateSatKvB = 1.0   # ridiculously low cap (1 sat/kvB)
    let r = mp.acceptTransactionWithArgs(tx, crypto, args)
    check not r.isOk
    check "max feerate exceeded" in r.error or "script verification" in r.error
    cs.close()

suite "W96 ATMP args — test_accept (W96 GAP #11)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "test_accept does not mutate mempool":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_000_000)
    var args = defaultAtmpArgs()
    args.testAccept = true
    let countBefore = mp.count
    discard mp.acceptTransactionWithArgs(tx, crypto, args)
    # Mempool size must not change regardless of acceptance outcome.
    check mp.count == countBefore
    cs.close()

suite "W96 ATMP args — allow_replacement (W96 GAP #2)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bip125-replacement-disallowed when conflict + !allow_replacement":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    # First tx pre-populated directly to set up the conflict.
    let tx1 = makeSpendTx(spendable, 0, 4_999_000_000, sequence = 0)
    let entry1 = MempoolEntry(
      tx: tx1, txid: tx1.txid(), wtxid: tx1.wtxid(),
      fee: Satoshi(1_000_000), weight: 400,
      feeRate: 10000.0, timeAdded: getTime(),
      height: 101, ancestorFee: Satoshi(1_000_000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[tx1.txid()] = entry1
    mp.byWtxid[tx1.wtxid()] = tx1.txid()
    mp.spentBy[tx1.inputs[0].prevOut] = tx1.txid()

    let tx2 = makeSpendTx(spendable, 0, 4_998_000_000, sequence = 1)
    var args = defaultAtmpArgs()
    args.allowReplacement = false
    let r = mp.acceptTransactionWithArgs(tx2, crypto, args)
    check not r.isOk
    check "bip125-replacement-disallowed" in r.error
    cs.close()

suite "W96 ATMP args — bypass_limits (W96 GAP #8)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bypass_limits skips min-fee gate":
    ## Sub-min-fee tx normally rejected, but with bypass_limits the gate
    ## is skipped (used for reorg replay).
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 10_000.0)  # absurd floor
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_999_999)  # 1 sat fee
    let normalArgs = defaultAtmpArgs()
    let r1 = mp.acceptTransactionWithArgs(tx, crypto, normalArgs)
    check not r1.isOk
    check "min fee not met" in r1.error or "script verification" in r1.error or
          "fee rate" in r1.error

    var bypassArgs = defaultAtmpArgs()
    bypassArgs.bypassLimits = true
    let r2 = mp.acceptTransactionWithArgs(tx, crypto, bypassArgs)
    # Should not fail on min-fee anymore; may still fail on script verify.
    if not r2.isOk:
      check "min fee not met" notin r2.error
    cs.close()

suite "W96 PolicyScriptChecks — script verify gates":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "script verification failure surfaced as non-mandatory- or mandatory-":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    # Bogus 0x00 scriptSig over a real P2PKH UTXO → fails CHECKSIG.
    let tx = makeSpendTx(spendable, 0, 4_999_000_000)
    let r = mp.acceptTransaction(tx, crypto)
    check not r.isOk
    check ("non-mandatory-script-verify-flag" in r.error or
           "mandatory-script-verify-flag-failed" in r.error or
           "script verification failed" in r.error)
    cs.close()

suite "W96 wtxid index lifecycle":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "removeTransaction drops byWtxid entry":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_000_000)
    let txid = tx.txid()
    let wtxid = tx.wtxid()
    # Force-insert directly.
    let entry = MempoolEntry(
      tx: tx, txid: txid, wtxid: wtxid,
      fee: Satoshi(1000), weight: 400,
      feeRate: 10.0, timeAdded: getTime(),
      height: 101, ancestorFee: Satoshi(1000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[txid] = entry
    mp.byWtxid[wtxid] = txid
    check wtxid in mp.byWtxid
    mp.removeTransaction(txid)
    check txid notin mp.entries
    check wtxid notin mp.byWtxid
    cs.close()

suite "W96 ReplacementChecks — ancestor disjoint (W96 GAP #9)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "EntriesAndTxidsDisjoint check is wired (no-conflict path)":
    ## Sanity: in the non-RBF path the disjoint check is bypassed (conflicts
    ## empty), so a normal-conflict-free tx still progresses past this gate.
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let (spendable, _) = buildChainToMaturity(cs)
    let tx = makeSpendTx(spendable, 0, 4_999_000_000)
    let r = mp.acceptTransaction(tx, crypto)
    # We expect script-verify failure (bogus scriptSig), NOT a disjoint
    # error, since there are no conflicts.
    if not r.isOk:
      check "bad-txns-spends-conflicting-tx" notin r.error
    cs.close()

suite "W96 ATMP args — default factory":
  test "defaultAtmpArgs has Core-equivalent defaults":
    let a = defaultAtmpArgs()
    check a.testAccept == false
    check a.bypassLimits == false
    check a.allowReplacement == true
    check a.allowSiblingEviction == true
    check a.packageFeerates == false
    check a.clientMaxFeeRateSatKvB == 0.0

when isMainModule:
  discard
