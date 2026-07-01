## test_reorg_coinbase_inflation.nim
##
## Regression test for the reorg-path money-supply-inflation bug.
##
## Bitcoin Core enforces the coinbase-value ceiling (bad-cb-amount) in
## ConnectBlock (validation.cpp:2610-2613):
##
##     blockReward = nFees + GetBlockSubsidy(pindex->nHeight, ...)
##     if (block.vtx[0]->GetValueOut() > blockReward)  -> "bad-cb-amount"
##
## Core runs ConnectBlock on EVERY block connected, including the blocks it
## connects while switching to a heavier fork during a reorg
## (ActivateBestChainStep -> ConnectTip -> ConnectBlock).
##
## nimrod's main-chain extension path enforces the ceiling in
## validateBlock (skipConnectChecks=false).  But the side-branch acceptance
## path validates with skipConnectChecks=true (deferring UTXO/fee checks to
## connect time), and the reorg-connect loop in `handleReorg` — nimrod's
## ConnectBlock equivalent — historically re-ran only script verification,
## coinbase maturity, and missing-input checks.  It NEVER checked the
## coinbase-value ceiling.  Consequently a heavier competing fork whose
## coinbase claims more than subsidy+fees was promoted to the active tip,
## inflating the money supply (CRITICAL, p2p-reachable).
##
## This test drives `handleReorg` directly:
##   * PRE-FIX  the inflated (100 BTC vs 50 BTC subsidy) reorg SUCCEEDS and
##              the tip advances onto the fraudulent branch -> the
##              `check reorgRes.isErr` assertion FAILS.
##   * POST-FIX handleReorg returns an error containing "bad-cb-amount",
##              the reorg is aborted, and the original tip is left intact.
## A valid competing fork (coinbase == subsidy) still reorgs successfully.

import unittest2
import std/[os, options, strutils]
import ../src/storage/[db, chainstate]
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_reorg_cb_inflation_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeCoinbaseTx(height: int32, value: int64, nonceTag: byte = 0): Transaction =
  ## BIP34 height-prefixed coinbase scriptSig; `nonceTag` distinguishes two
  ## coinbases at the same height so their txids (and thus block hashes) differ.
  var scriptSig: seq[byte]
  if height <= 0x7f:
    scriptSig = @[byte(0x01), byte(height)]
  else:
    scriptSig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff)]
  scriptSig.add(nonceTag)
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: @[byte(0x51)]  # OP_TRUE
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeBlock(prevHash: BlockHash, height: int32, cbValue: int64,
               nonceTag: byte = 0): Block =
  let cb = makeCoinbaseTx(height, cbValue, nonceTag)
  # Single-tx block: merkle root == coinbase txid.
  let root: array[32, byte] = array[32, byte](cb.txid())
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: root,
      timestamp: 1231006505'u32 + uint32(height) * 600'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    ),
    txs: @[cb]
  )

proc blockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

const SUBSIDY: int64 = 5_000_000_000  # 50 BTC on regtest at height < halving

suite "reorg coinbase-value ceiling (bad-cb-amount) parity with Core ConnectBlock":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "reorg onto a fork whose coinbase exceeds subsidy+fees is REJECTED":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Active chain: genesis -> blk1 (tip at height 1).
    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0, SUBSIDY)
    let genesisHash = blockHash(genesis)
    check cs.connectBlock(genesis, 0).isOk

    let blk1 = makeBlock(genesisHash, 1, SUBSIDY)
    check cs.connectBlock(blk1, 1).isOk
    check cs.bestHeight == 1

    # Competing fork from genesis: side1 (valid 50 BTC) then side2 whose
    # coinbase claims 100 BTC — double the subsidy, zero fees. This is the
    # money-supply-inflation attack.
    let side1 = makeBlock(genesisHash, 1, SUBSIDY, nonceTag = 0xA1)
    let side1Hash = blockHash(side1)
    let side2 = makeBlock(side1Hash, 2, SUBSIDY * 2, nonceTag = 0xA2)

    var disconnectedTxs: seq[Transaction] = @[]
    let reorgRes = cs.handleReorg(genesisHash, @[side1, side2], disconnectedTxs)

    # POST-FIX: reorg is aborted with bad-cb-amount; original tip intact.
    # PRE-FIX: this assertion FAILS (reorg succeeded, tip == side2).
    check (not reorgRes.isOk)
    if not reorgRes.isOk:
      check "bad-cb-amount" in reorgRes.error
    check cs.bestHeight == 1
    check cs.bestBlockHash == blockHash(blk1)

  test "reorg onto a valid fork (coinbase == subsidy) still SUCCEEDS":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    let genesis = makeBlock(BlockHash(default(array[32, byte])), 0, SUBSIDY)
    let genesisHash = blockHash(genesis)
    check cs.connectBlock(genesis, 0).isOk

    let blk1 = makeBlock(genesisHash, 1, SUBSIDY)
    check cs.connectBlock(blk1, 1).isOk
    check cs.bestHeight == 1

    # Competing 2-block fork, both coinbases exactly at the subsidy ceiling.
    let side1 = makeBlock(genesisHash, 1, SUBSIDY, nonceTag = 0xB1)
    let side1Hash = blockHash(side1)
    let side2 = makeBlock(side1Hash, 2, SUBSIDY, nonceTag = 0xB2)
    let side2Hash = blockHash(side2)

    var disconnectedTxs: seq[Transaction] = @[]
    let reorgRes = cs.handleReorg(genesisHash, @[side1, side2], disconnectedTxs)

    check reorgRes.isOk
    check cs.bestHeight == 2
    check cs.bestBlockHash == side2Hash
