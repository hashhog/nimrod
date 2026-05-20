## Regression test — validateBlock must consult the cache-aware UTXO view.
##
## Mainnet incident (2026-05-20, node nimrod, PID 4061804): nimrod restarted
## at tip 950148, IBD-connected block 950149 (via `connectBlockIBD`), then
## rejected block 950150 with "acceptBlock rejected: transaction inputs
## missing".  Block 950150 spends 365 outputs created in block 950149.
##
## Root cause — a UTXO-source asymmetry inside `acceptBlock`:
##   * `connectBlockIBD` stages freshly-created UTXOs ONLY in
##     `ChainState.utxoCache` + the unflushed `ibdBatch` (flushed to RocksDB
##     every `IbdBatchFlushInterval` = 2000 blocks).
##   * `acceptBlock` step 4 (`verifyScripts`) was given a cache-aware
##     `ChainState.getUtxo` lookup → it saw those UTXOs.
##   * `acceptBlock` step 2 (`validateBlock`) used the raw `ChainDb` for its
##     UTXO-set reads (input existence / fees / sigops / BIP-68) → it did NOT
##     see UTXOs created by a not-yet-flushed recent block.
##
## Result: any block spending an output created by a recent (unflushed) block
## fails `validateBlock` with `veInputsMissing` even though the UTXO genuinely
## exists.  This is a deterministic false reject, NOT chainstate corruption.
## Block-index reads were unaffected — `ChainDb` carries an IBD shadow
## (`ibdIndexByHash` / `ibdIndexByHeight`) for those; the UTXO set has no such
## shadow, only `ChainState.utxoCache`.
##
## Fix: `validateBlock` gained an optional `getUtxoOverride` proc; `acceptBlock`
## now threads its cache-aware `getUtxo` into it, so block validation and
## script verification observe the SAME authoritative UTXO view.
##
## This test reproduces the asymmetry directly: a block is connected via
## `connectBlockIBD` (UTXO becomes cache-only, NOT in RocksDB), then
## `validateBlock` is run on a child block that spends it.
##   * raw-ChainDb lookup        → "transaction inputs missing"   (the bug)
##   * cache-aware getUtxoOverride → lookup SUCCEEDS, validation proceeds past
##     the input-existence gate (the immature-coinbase gate then fires, which
##     is the *correct* next check and proves the UTXO was found).

import unittest2
import std/[os, options, strutils]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/params
import ../src/consensus/validation as val

const TestDbPath = "/tmp/nimrod_validateblock_ibd_utxo"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeP2WPKH(): seq[byte] =
  @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))

proc makeCoinbaseTx(height: int32, extra: int32 = 0): Transaction =
  ## BIP-34-correct coinbase: scriptSig starts with the canonical height
  ## encoding, followed by an `extra`-derived nonce so distinct blocks at the
  ## same height get distinct coinbase txids.
  let extraBytes = @[byte(extra and 0xff), byte((extra shr 8) and 0xff),
                     byte((extra shr 16) and 0xff), byte((extra shr 24) and 0xff)]
  let scriptSig = val.encodeBip34Height(height) & @[byte(0x04)] & extraBytes
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: makeP2WPKH())],
    witnesses: @[],
    lockTime: 0
  )

proc makeSpendingTx(prevTxid: TxId, prevVout: uint32,
                    value: int64 = 4990000000): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: makeP2WPKH())],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlock(prevHash: BlockHash, height: int32,
               txs: seq[Transaction], nonce: uint32 = 0): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      # version 4: regtest activates BIP-34/66/65 at height 1, so blocks at
      # height >= 1 must be version >= 4 to clear contextualCheckBlockHeader's
      # bad-version gate.
      version: 4,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1296688602 + uint32(height * 600) + nonce,
      bits: 0x207fffff'u32,
      nonce: uint32(height) xor nonce
    ),
    txs: txs
  )

proc blockHashOf(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

suite "validateBlock — IBD cache-only UTXO visibility (mainnet 950150 regression)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "validateBlock without override CANNOT see a connectBlockIBD cache-only UTXO":
    ## Reproduces the bug: the raw-ChainDb path misses the unflushed UTXO and
    ## returns the exact incident error string.
    var cs = newChainState(TestDbPath, regtestParams())

    # Genesis (height 0 — no UTXO mutation), then height-1 block via the IBD
    # fast path.  IbdBatchFlushInterval is 2000, so a single IBD-connected
    # block is NEVER flushed to RocksDB — its coinbase output lives ONLY in
    # ChainState.utxoCache. This is exactly the mainnet 950149 situation.
    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk

    cs.startIBD()
    let blk1 = makeBlock(blockHashOf(genesis), 1, @[makeCoinbaseTx(1)])
    check cs.connectBlockIBD(blk1, 1).isOk
    let cb1Txid = blk1.txs[0].txid()

    # Sanity: the coinbase UTXO IS visible via the cache-aware ChainState.getUtxo
    # but is NOT in the raw ChainDb (it was never flushed).
    check cs.getUtxo(OutPoint(txid: cb1Txid, vout: 0)).isSome
    check cs.db.getUtxo(OutPoint(txid: cb1Txid, vout: 0)).isNone

    # Build a height-2 block that spends block-1's coinbase output.
    let blk2 = makeBlock(blockHashOf(blk1), 2,
                         @[makeCoinbaseTx(2), makeSpendingTx(cb1Txid, 0)])
    let prevIdx = cs.db.getBlockIndex(blockHashOf(blk1))
    check prevIdx.isSome

    # No override → validateBlock uses the raw ChainDb → UTXO miss.
    let resNoOverride = val.validateBlock(blk2, prevIdx.get(), cs.db,
                                          regtestParams(),
                                          checkScripts = false,
                                          checkPow = false)
    check (not resNoOverride.isOk)
    check ($resNoOverride.error).contains("inputs missing")
    cs.close()

  test "validateBlock WITH cache-aware override DOES see the IBD cache-only UTXO":
    ## The fix: when acceptBlock threads ChainState.getUtxo into validateBlock,
    ## the cache-only UTXO resolves. Validation then advances PAST the
    ## input-existence gate; the immature-coinbase gate fires next (age 1 < 100)
    ## — which is the correct behaviour and proves the UTXO was located.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk

    cs.startIBD()
    let blk1 = makeBlock(blockHashOf(genesis), 1, @[makeCoinbaseTx(1)])
    check cs.connectBlockIBD(blk1, 1).isOk
    let cb1Txid = blk1.txs[0].txid()

    let blk2 = makeBlock(blockHashOf(blk1), 2,
                         @[makeCoinbaseTx(2), makeSpendingTx(cb1Txid, 0)])
    let prevIdx = cs.db.getBlockIndex(blockHashOf(blk1))
    check prevIdx.isSome

    # Cache-aware override — same lookup acceptBlock now passes.
    let csRef = cs
    let cacheAware = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      try: csRef.getUtxo(op)
      except: none(UtxoEntry)

    let resOverride = val.validateBlock(blk2, prevIdx.get(), cs.db,
                                        regtestParams(),
                                        checkScripts = false,
                                        checkPow = false,
                                        getUtxoOverride = cacheAware)
    # The input WAS found — so the error is NOT "inputs missing".  At age 1
    # the spend of a coinbase is immature (regtest coinbaseMaturity = 100),
    # which is the next gate in validateTransaction after the UTXO lookup.
    check (not resOverride.isOk)
    check (not ($resOverride.error).contains("inputs missing"))
    check ($resOverride.error).contains("immature")
    cs.close()

  test "acceptBlock end-to-end accepts a block spending a cache-only IBD UTXO":
    ## Full-envelope regression: a mature coinbase is created via the IBD path
    ## (cache-only), and a later block that spends it must pass `acceptBlock`
    ## — the same path the live IBD block-application uses. Pre-fix this
    ## failed at step 2 (validateBlock) with "transaction inputs missing".
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()

    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                            @[makeCoinbaseTx(0)])
    check cs.connectBlock(genesis, 0).isOk

    cs.startIBD()
    # Connect blocks 1..101 via the IBD fast path. None are flushed
    # (IbdBatchFlushInterval = 2000), so every coinbase output is cache-only.
    var prevHash = blockHashOf(genesis)
    var firstCbTxid: TxId
    for h in 1'i32 .. 101'i32:
      let cb = makeCoinbaseTx(h)
      let blk = makeBlock(prevHash, h, @[cb])
      check cs.connectBlockIBD(blk, h).isOk
      if h == 1:
        firstCbTxid = cb.txid()
      prevHash = blockHashOf(blk)

    # Block-1's coinbase is cache-only AND now mature at height 102 (age 101).
    check cs.getUtxo(OutPoint(txid: firstCbTxid, vout: 0)).isSome
    check cs.db.getUtxo(OutPoint(txid: firstCbTxid, vout: 0)).isNone

    # Height-102 block spends block-1's (mature, cache-only) coinbase.
    let blk102 = makeBlock(prevHash, 102,
                           @[makeCoinbaseTx(102), makeSpendingTx(firstCbTxid, 0)])
    let prevIdx = cs.db.getBlockIndex(prevHash)
    check prevIdx.isSome

    let csRef = cs
    let cacheAware = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      try: csRef.getUtxo(op)
      except: none(UtxoEntry)

    # skipScripts=true: this unit test uses unsigned scriptSigs; the focus is
    # the UTXO-set lookup inside validateBlock (step 2), not script execution.
    let res = val.acceptBlock(blk102, prevIdx.get(), cs.db, params,
                              skipScripts = true,
                              checkPow = false,
                              getUtxo = cacheAware,
                              crypto = newCryptoEngine())
    check res.isOk
    cs.close()
