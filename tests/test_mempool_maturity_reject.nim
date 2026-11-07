## Coinbase-maturity reject text parity with Bitcoin Core.
##
## Core (consensus/tx_verify.cpp CheckTxInputs) rejects an immature coinbase
## spend with state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
## "tried to spend coinbase at depth N"). ToString() is "<token>, <debug>", and
## testmempoolaccept reports reject-reason = token, reject-details = ToString().
## sendrawtransaction's RPC message is ToString().

import unittest2
import std/[os, options, tables, sets, times, strutils]
import ../src/mempool/mempool
import ../src/mempool/standard
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params, validation]
import ../src/script/interpreter
import ../src/rpc/server

const TestDbPath = "/tmp/nimrod_maturity_reject_test"

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

suite "coinbase maturity reject text":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "mempool error is Core's '<token>, tried to spend coinbase at depth N'":
    var cs = newChainState(TestDbPath, regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params, minFeeRate = 0.0)
    let crypto = newCryptoEngine()
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    var prevHash = getBlockHash(genesis)
    var cbTxid = genesis.txs[0].txid()
    for h in 1 .. 99:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      if h == 1: cbTxid = blk.txs[0].txid()
      prevHash = getBlockHash(blk)
    # tip=99, coinbase at height 1: next-block depth = 100 - 1 = 99.
    let r = mp.acceptTransaction(makeSpendTx(cbTxid, 0, 4_999_000_000), crypto)
    check not r.isOk
    check r.error == "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
    cs.close()

when declared(splitRejectState):
  suite "testmempoolaccept reject-reason / reject-details split":
    test "token, detail splits into token and full state string":
      let (tok, det) = splitRejectState(
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99")
      check tok == "bad-txns-premature-spend-of-coinbase"
      check det == "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
    test "replacement-failed splits like Core":
      let (tok, det) = splitRejectState(
        "replacement-failed, insufficient feerate: does not improve feerate diagram")
      check tok == "replacement-failed"
      check det == "replacement-failed, insufficient feerate: does not improve feerate diagram"
    test "bare token has no details":
      let (tok, det) = splitRejectState("bad-txns-vin-empty")
      check tok == "bad-txns-vin-empty"
      check det == ""
    test "free text with a space before the comma is not split":
      let (tok, det) = splitRejectState("insufficient fee, rejecting replacement")
      check tok == "insufficient fee, rejecting replacement"
      check det == ""
else:
  suite "testmempoolaccept reject-reason / reject-details split":
    test "splitRejectState exists":
      check false
