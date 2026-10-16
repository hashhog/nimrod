## getblocktemplate sigop accounting vs Bitcoin Core v31.1 (KB-193).
##
## Core counts a template transaction's sigops with the mempool entry's exact
## cost, GetTransactionSigOpCost computed at acceptance (legacy and P2SH
## sigops x WITNESS_SCALE_FACTOR, witness sigops x 1):
##   src/node/miner.cpp:266   pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost());
##   src/node/miner.cpp:269   nBlockSigOpsCost += entry.GetSigOpCost();
##   src/rpc/mining.cpp:927   int64_t nTxSigOps{tx_sigops.at(index_in_template)};
## Selection stops a chunk whose cost would bring the block to the limit
## (miner.cpp:244, `>=`), and the running total starts at
## coinbase_output_max_additional_sigops, DEFAULT 400 (policy/policy.h:29,
## miner.cpp:115), so a miner's coinbase outputs still fit.
##
## The transactions below go through real ATMP on a regtest ChainState, then
## through handleMethod("getblocktemplate").  Expected per-tx values are what
## Core v31.1 reports for the same shapes (the core-regtest `gbt` group pins
## bare 1-of-1 multisig at 80; the rest follow the same counting rules).

import unittest2
import std/[os, json, options, strutils]
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/[fees, blocktemplate]
import ../src/rpc/server
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/wallet/wallet

const TestDbPath = "/tmp/nimrod_gbt_sigops_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------

const AcsWitnessScript = @[0x51'u8]   # OP_TRUE

let testKey: PrivateKey = block:
  var k: PrivateKey
  k[31] = 0x01
  k
let testPub: PublicKey = derivePublicKey(testKey)

proc p2wsh(witnessScript: seq[byte]): seq[byte] =
  @[0x00'u8, 0x20] & @(sha256Single(witnessScript))

proc p2sh(redeemScript: seq[byte]): seq[byte] =
  @[0xa9'u8, 0x14] & @(hash160(redeemScript)) & @[0x87'u8]

proc p2wpkh(pub: PublicKey): seq[byte] =
  @[0x00'u8, 0x14] & @(hash160(pub))

proc bareMultisig1of1(): seq[byte] =
  ## OP_1 <pubkey> OP_1 OP_CHECKMULTISIG — legacy (inaccurate) count is 20.
  @[0x51'u8, 0x21] & @testPub & @[0x51'u8, 0xae]

proc zeroOfN(n: int): seq[byte] =
  ## OP_0 <n pubkeys> OP_n OP_CHECKMULTISIG — satisfied by a lone dummy, so it
  ## spends without a signature; accurate count is n.
  result = @[0x00'u8]
  for _ in 0 ..< n:
    result.add(0x21'u8)
    result.add(@testPub)
  result.add(byte(0x50 + n))
  result.add(0xae'u8)

proc pushData(data: seq[byte]): seq[byte] =
  if data.len < 0x4c:
    result = @[byte(data.len)]
  elif data.len <= 0xff:
    result = @[0x4c'u8, byte(data.len)]
  else:
    result = @[0x4d'u8, byte(data.len and 0xff), byte(data.len shr 8)]
  result.add(data)

let p2shRedeem = zeroOfN(15)       # P2SH sigops 15 -> cost 60
let p2wshMultisig = zeroOfN(16)    # witness sigops 16 -> cost 16

# ---------------------------------------------------------------------------
# Chain: coinbase at height h pays coinbaseSpk(h)
# ---------------------------------------------------------------------------

const
  CoinbaseValue = 5_000_000_000'i64
  HeightP2sh = 1
  HeightP2wshMultisig = 2
  HeightP2wpkh = 3
  HeightBare = 4
  HeightAcs = 5
  FirstFillerHeight = 10   # heights 10.. pay P2WSH(OP_TRUE) for filler spends
  ChainTip = 200

proc coinbaseSpk(h: int): seq[byte] =
  case h
  of HeightP2sh: p2sh(p2shRedeem)
  of HeightP2wshMultisig: p2wsh(p2wshMultisig)
  of HeightP2wpkh: p2wpkh(testPub)
  else: p2wsh(AcsWitnessScript)

proc makeCoinbaseTx(height: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04), byte(height and 0xff), byte((height shr 8) and 0xff),
                   byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(CoinbaseValue), scriptPubKey: coinbaseSpk(int(height)))],
    witnesses: @[],
    lockTime: 0)

proc buildChain(cs: var ChainState): seq[TxId] =
  ## Connect blocks 0..ChainTip; returns each height's coinbase txid.
  var prevHash = BlockHash(default(array[32, byte]))
  for h in 0 .. ChainTip:
    let coinbase = makeCoinbaseTx(int32(h))
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: prevHash,
        merkleRoot: merkleRoot(@[array[32, byte](coinbase.txid())]),
        timestamp: 1700000000'u32 + uint32(h),
        bits: 0x207fffff'u32,
        nonce: uint32(h)),
      txs: @[coinbase])
    doAssert cs.connectBlock(blk, int32(h)).isOk
    prevHash = BlockHash(doubleSha256(serialize(blk.header)))
    result.add(coinbase.txid())

proc spend(prev: TxId, outputs: seq[TxOut], scriptSig: seq[byte] = @[],
           witness: seq[seq[byte]] = @[]): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: prev, vout: 0),
                   scriptSig: scriptSig, sequence: 0xFFFFFFFD'u32)],
    outputs: outputs,
    witnesses: @[witness],
    lockTime: 0)

proc acsSpend(prev: TxId, outputs: seq[TxOut]): Transaction =
  spend(prev, outputs, witness = @[AcsWitnessScript])

proc outs(spk: seq[byte], n: int, total: int64): seq[TxOut] =
  for _ in 0 ..< n:
    result.add(TxOut(value: Satoshi(total div n), scriptPubKey: spk))

proc bareMultisigTx(prev: TxId, nOutputs: int, fee: int64): Transaction =
  ## nOutputs bare 1-of-1 multisig outputs, cost 80 each; the P2WSH(OP_TRUE)
  ## input adds nothing.
  acsSpend(prev, outs(bareMultisig1of1(), nOutputs, CoinbaseValue - fee))

proc accept(mp: Mempool, crypto: CryptoEngine, tx: Transaction) =
  let r = mp.acceptTransaction(tx, crypto)
  if not r.isOk:
    echo "ATMP rejected: ", r.error
  doAssert r.isOk

proc gbt(rpc: RpcServer): JsonNode =
  rpc.handleMethod("getblocktemplate", %*[{"rules": ["segwit"]}])

proc consensusCost(cs: ChainState, tx: Transaction): int =
  ## The cost connectBlock charges against MAX_BLOCK_SIGOPS_COST, computed
  ## from the confirmed UTXO set — independent of anything the template says.
  let lookup = proc(op: OutPoint): Option[UtxoEntry] = cs.getUtxo(op)
  let r = getTransactionSigOpCost(tx, lookup, useP2SH = true, useWitness = true)
  doAssert r.isOk
  r.value

proc unhex(s: string): seq[byte] =
  for c in parseHexStr(s):
    result.add(byte(c))

proc templateCost(cs: ChainState, tmpl: JsonNode): int =
  for entry in tmpl["transactions"]:
    let tx = deserializeTransaction(unhex(entry["data"].getStr()))
    result += consensusCost(cs, tx)

suite "getblocktemplate transactions[].sigops is the exact sigop cost":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "baremultisig, p2sh, p2wsh, p2wpkh64 and acs spends report Core's cost":
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let cb = buildChain(cs)
    let mp = newMempool(cs, params)
    let crypto = newCryptoEngine()

    # Bare 1-of-1 multisig output: legacy 20 x 4 = 80.
    let bare = bareMultisigTx(cb[HeightBare], 1, 100_000)
    # P2SH 0-of-15 input: P2SH 15 x 4 = 60; P2WSH output adds 0.
    let p2shSpend = spend(cb[HeightP2sh],
      outs(p2wsh(AcsWitnessScript), 1, CoinbaseValue - 100_000),
      scriptSig = @[0x00'u8] & pushData(p2shRedeem))
    # P2WSH 0-of-16 input: witness 16 x 1 = 16.
    let p2wshSpend = spend(cb[HeightP2wshMultisig],
      outs(p2wsh(AcsWitnessScript), 1, CoinbaseValue - 100_000),
      witness = @[newSeq[byte](), p2wshMultisig])
    # P2WPKH input to 64 P2WPKH outputs: witness 1 x 1 = 1.
    var p2wpkh64 = spend(cb[HeightP2wpkh],
      outs(p2wpkh(testPub), 64, CoinbaseValue - 100_000))
    signInputP2WPKH(p2wpkh64, 0, testKey, testPub, Satoshi(CoinbaseValue))
    # P2WSH(OP_TRUE) to P2WSH(OP_TRUE): 0.
    let acs = acsSpend(cb[HeightAcs],
      outs(p2wsh(AcsWitnessScript), 1, CoinbaseValue - 100_000))

    let expected = @[(bare, 80), (p2shSpend, 60), (p2wshSpend, 16),
                     (p2wpkh64, 1), (acs, 0)]
    for (tx, _) in expected:
      accept(mp, crypto, tx)

    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let tmpl = gbt(rpc)
    check tmpl["transactions"].len == expected.len
    for (tx, cost) in expected:
      # The expected value is also what consensus charges for this tx.
      check consensusCost(cs, tx) == cost
      var found = false
      for entry in tmpl["transactions"]:
        if entry["txid"].getStr() == $tx.txid():
          found = true
          check entry["sigops"].getInt() == cost
      check found

suite "block template selection respects MAX_BLOCK_SIGOPS_COST":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "txs the estimate counts as 0 sigops cannot push a template past 80000":
    # 55 txs x 20 bare-multisig outputs = 1600 real cost each (88000 total).
    # Counted correctly the template holds 49: 400 + 49 x 1600 = 78800, and a
    # 50th would reach 80400.
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let cb = buildChain(cs)
    let mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    for i in 0 ..< 55:
      accept(mp, crypto, bareMultisigTx(cb[FirstFillerHeight + i], 20, 200_000))

    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let tmpl = gbt(rpc)
    let total = templateCost(cs, tmpl)
    check total < MaxBlockSigopsCost
    check tmpl["transactions"].len == 49
    var reported = 0
    for entry in tmpl["transactions"]:
      reported += entry["sigops"].getInt()
    check reported == total

    # buildBlockTemplate is what the miner uses directly; same limit.
    let bt = buildBlockTemplate(cs, mp, params, @[0x51'u8])
    var btCost = 0
    for i in 1 ..< bt.transactions.len:
      btCost += consensusCost(cs, bt.transactions[i])
    check btCost < MaxBlockSigopsCost
    check bt.transactions.len == 1 + 49
    # The block built from it passes the consensus counter that raises
    # bad-blk-sigops (validateBlock: cost > MAX_BLOCK_SIGOPS_COST).
    let lookup = proc(op: OutPoint): Option[UtxoEntry] = cs.getUtxo(op)
    let blockCost = countBlockSigopsCost(Block(header: bt.header, txs: bt.transactions),
                                         lookup, int32(bt.height), params)
    check blockCost.isOk
    if blockCost.isOk:
      check blockCost.value == 49 * 1600
      check blockCost.value <= MaxBlockSigopsCost

  test "400 sigop cost stays reserved for the coinbase (Core DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS)":
    # 27 txs x 37 bare-multisig outputs = 2960 each; all 27 = 79920 < 80000,
    # but 400 + 79920 >= 80000, so Core takes 26 (400 + 76960 = 77360).
    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()
    let cb = buildChain(cs)
    let mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    for i in 0 ..< 27:
      accept(mp, crypto, bareMultisigTx(cb[FirstFillerHeight + i], 37, 300_000))

    let rpc = newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
                           peerManager = nil, feeEstimator = newFeeEstimator(),
                           params = params)
    let tmpl = gbt(rpc)
    check templateCost(cs, tmpl) + 400 < MaxBlockSigopsCost
    check tmpl["transactions"].len == 26
