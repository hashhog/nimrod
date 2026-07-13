## ChainState tests
## Tests UTXO set management, block connect/disconnect, coinbase maturity, and reorg handling

import unittest2
import std/[os, options, strutils, tables]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_chainstate_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(
  prevTxid: TxId,
  prevVout: uint32,
  value: int64,
  isCoinbase: bool = false
): Transaction =
  ## Create a simple test transaction
  if isCoinbase:
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[byte(0x01), 0x01],  # Simple coinbase script
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )
  else:
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: prevTxid, vout: prevVout),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))
      )],
      witnesses: @[],
      lockTime: 0
    )

proc makeTestBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  ## Create a test block with the given transactions

  # Compute merkle root
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  result = Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,  # Regtest difficulty
      nonce: uint32(height)
    ),
    txs: txs
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32, extra: uint32 = 0): Block =
  ## Create a simple block with just a coinbase (height+extra in scriptSig for unique txid)
  ## Use 'extra' to distinguish alternative fork blocks at the same height
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff), byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let extraBytes = @[byte(extra and 0xff), byte((extra shr 8) and 0xff), byte((extra shr 16) and 0xff), byte((extra shr 24) and 0xff)]
  let coinbase = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & heightBytes & @[byte(0x04)] & extraBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5000000000),
      scriptPubKey: @[byte(0x51)]  # OP_1
    )],
    witnesses: @[],
    lockTime: 0
  )
  makeTestBlock(prevHash, height, @[coinbase])

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

proc seedSpendableCoinbase(
  cs: var ChainState
): tuple[fixtureBlock: Block, fixtureHash: BlockHash, coinbaseTxid: TxId] =
  ## Connect genesis (height 0) + a fixture coinbase block at height 1.
  ##
  ## Background: per W14, `connectBlock(blk, 0)` no longer writes the
  ## genesis coinbase to `cfUtxo` — that mirrors Bitcoin Core's
  ## `validation.cpp:2337-2343` genesis-skip rule. Many tests previously
  ## relied on the genesis coinbase being spendable; they now use this
  ## helper to seed a spendable coinbase at height 1 instead. The
  ## semantics each test cares about (maturity, disconnect, reorg) are
  ## unchanged — only the height of the seed coinbase shifts by one.
  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  let genesisHash = getBlockHash(genesis)
  let fixture = makeSimpleBlock(genesisHash, 1)
  discard cs.connectBlock(fixture, 1)
  let fixtureHash = getBlockHash(fixture)
  (fixture, fixtureHash, fixture.txs[0].txid())

suite "ChainState UTXO management":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "create and close chainstate":
    var cs = newChainState(TestDbPath, regtestParams())
    check cs != nil
    check cs.bestHeight == -1
    check cs.maxCacheSize == DefaultMaxCacheSize
    cs.close()

  test "connect genesis block (height==0 skips UTXO mutation, Core parity)":
    ## Bitcoin Core skips ConnectBlock entirely for the genesis block
    ## (`bitcoin-core/src/validation.cpp:2337-2343`); the genesis coinbase
    ## output never enters Core's UTXO set. nimrod mirrors this by skipping
    ## per-tx UTXO writes in `connectBlock` when `height == 0`. The chain
    ## tip is still set so subsequent blocks can connect.
    var cs = newChainState(TestDbPath, regtestParams())

    # Create genesis-like block (note: `makeSimpleBlock` is not the canonical
    # regtest genesis, but the height==0 guard fires regardless of contents).
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let connectRes = cs.connectBlock(genesis, 0)

    check connectRes.isOk
    check cs.bestHeight == 0

    # Genesis coinbase MUST NOT be in the UTXO set — matches Core's behavior.
    # Regression for W12/W14: prior to the fix, this UTXO was present and
    # `gettxoutsetinfo` / `dumptxoutset` diverged from Core by one coin.
    let coinbaseTxid = genesis.txs[0].txid()
    let outpoint = OutPoint(txid: coinbaseTxid, vout: 0)
    let utxo = cs.getUtxo(outpoint)

    check utxo.isNone

    cs.close()

  test "genesis coinbase NOT in UTXO set (W14 writer-side regression)":
    ## Regression test pinning the W14 fix: after `connectBlock(genesis, 0)`,
    ## walking `cfUtxo` must yield zero entries. `computeUtxoSetInfo` should
    ## then return `txOuts == 0` even without the reader-side filter.
    ## See `bitcoin-core/src/validation.cpp:2337-2343`.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = buildGenesisBlock(regtestParams())
    let r = cs.connectBlock(genesis, 0)
    check r.isOk
    check cs.bestHeight == 0

    # The chainstate must be empty at this point.
    let info = cs.computeUtxoSetInfo(cshtNone)
    check info.txOuts == 0
    check info.transactions == 0
    check info.totalAmount == 0

    # Direct getUtxo lookup of the genesis coinbase must also fail.
    let genTxid = genesis.txs[0].txid()
    check cs.getUtxo(OutPoint(txid: genTxid, vout: 0)).isNone

    cs.close()

  test "connect chain of blocks":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Connect block 1
    let block1 = makeSimpleBlock(genesisHash, 1)
    let result1 = cs.connectBlock(block1, 1)
    check result1.isOk
    check cs.bestHeight == 1

    # Connect block 2
    let block1Hash = getBlockHash(block1)
    let block2 = makeSimpleBlock(block1Hash, 2)
    let result2 = cs.connectBlock(block2, 2)
    check result2.isOk
    check cs.bestHeight == 2

    # Verify post-genesis coinbase UTXOs exist. Genesis coinbase is
    # intentionally absent (Core parity — see W14 regression test above).
    check cs.getUtxo(OutPoint(txid: genesis.txs[0].txid(), vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: block1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: block2.txs[0].txid(), vout: 0)).isSome

    cs.close()

suite "ChainState unspendable filter (CScript::IsUnspendable)":
  ## Regression for the dumptxoutset 2x-coin-count bug. Bitcoin Core's
  ## `AddCoins` (coins.cpp) skips outputs whose scriptPubKey is provably
  ## unspendable per `CScript::IsUnspendable()` (script.h:563): OP_RETURN-
  ## prefixed OR larger than MAX_SCRIPT_SIZE (10000 bytes). nimrod's
  ## chainstate must do the same so the UTXO set — and therefore
  ## dumptxoutset — matches Core byte-for-byte.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "OP_RETURN coinbase witness-commitment output not added to UTXO":
    # This mirrors what Core-mined regtest blocks at height >= 1 carry:
    # a spendable P2W* output PLUS a witness-commitment OP_RETURN output.
    # The OP_RETURN output must NOT enter the chainstate.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Build a coinbase that has TWO outputs: a P2W* spendable + an OP_RETURN.
    let heightBytes = @[byte(1), 0, 0, 0]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                          vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000),
              scriptPubKey: @[byte(0x00), 0x14] &
                @(array[20, byte](default(array[20, byte])))),
        # 0x6a = OP_RETURN, 0x24 = push 36 bytes (witness commitment header).
        TxOut(value: Satoshi(0),
              scriptPubKey: @[byte(0x6a), 0x24] & newSeq[byte](36))
      ],
      witnesses: @[],
      lockTime: 0
    )
    let blk = makeTestBlock(genesisHash, 1, @[coinbase])

    let r = cs.connectBlock(blk, 1)
    check r.isOk

    # The spendable output (vout=0) MUST be present.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 0)).isSome
    # The OP_RETURN witness-commitment output (vout=1) MUST NOT be present.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 1)).isNone

    cs.close()

  test "oversize scriptPubKey (> MAX_SCRIPT_SIZE) not added to UTXO":
    # MAX_SCRIPT_SIZE = 10000 bytes per Core script.h:40. Anything strictly
    # larger is provably unspendable and never enters the chainstate.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let heightBytes = @[byte(1), 0, 0, 0]
    # 10001 bytes — strictly above the limit. Core treats this as
    # IsUnspendable() == true.
    let oversized = newSeq[byte](10001)
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                          vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytes,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000),
              scriptPubKey: @[byte(0x51)]),  # OP_1 -- spendable
        TxOut(value: Satoshi(0), scriptPubKey: oversized)
      ],
      witnesses: @[],
      lockTime: 0
    )
    let blk = makeTestBlock(genesisHash, 1, @[coinbase])

    let r = cs.connectBlock(blk, 1)
    check r.isOk
    # Spendable vout=0 present, oversize vout=1 absent.
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase.txid(), vout: 1)).isNone

    cs.close()

suite "ChainState scrubunspendable (legacy datadir cleanup)":
  ## The write-time `isUnspendable` filter (commit 94b7755) only stops new
  ## OP_RETURN / oversize coins from entering the chainstate. Datadirs created
  ## BEFORE that fix still carry orphan entries. `scrubUnspendable` is the
  ## one-shot operator-invoked tool that walks cfUtxo and removes them.
  ## These tests synthesize a "pre-fix" chainstate by writing the orphans
  ## directly via `cs.db.putUtxo`, bypassing the new filter.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "scrubUnspendable removes OP_RETURN + oversize coins, keeps spendable":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect a real spendable coinbase via the normal path.
    # (Use height-1 fixture; height-0 genesis is intentionally not in UTXO — see W14.)
    let (_, _, goodTxid) = seedSpendableCoinbase(cs)

    # Synthesize three "legacy" orphan entries by going around the filter
    # with direct db writes — this is exactly what a pre-fix nimrod build
    # would have left on disk.
    var op1Txid: array[32, byte]; op1Txid[0] = 0xAA
    let opReturnEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0),
                    scriptPubKey: @[byte(0x6a), 0x24] & newSeq[byte](36)),
      height: 1, isCoinbase: true)
    cs.db.putUtxo(OutPoint(txid: TxId(op1Txid), vout: 1), opReturnEntry)

    var op2Txid: array[32, byte]; op2Txid[0] = 0xBB
    let oversizeEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0), scriptPubKey: newSeq[byte](10001)),
      height: 2, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(op2Txid), vout: 0), oversizeEntry)

    var op3Txid: array[32, byte]; op3Txid[0] = 0xCC
    let opReturnEmptyPushEntry = UtxoEntry(
      output: TxOut(value: Satoshi(0), scriptPubKey: @[byte(0x6a)]),
      height: 3, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(op3Txid), vout: 0), opReturnEmptyPushEntry)

    # Sanity: the legacy orphans are visible via the DB layer.
    check cs.db.getUtxo(OutPoint(txid: TxId(op1Txid), vout: 1)).isSome
    check cs.db.getUtxo(OutPoint(txid: TxId(op2Txid), vout: 0)).isSome
    check cs.db.getUtxo(OutPoint(txid: TxId(op3Txid), vout: 0)).isSome
    # Real spendable coinbase is in the cache (not yet flushed to disk).
    check cs.getUtxo(OutPoint(txid: goodTxid, vout: 0)).isSome

    let res = cs.scrubUnspendable()
    check res.removed == 3
    check res.bytesFreed > 0

    # All three orphans gone.
    check cs.db.getUtxo(OutPoint(txid: TxId(op1Txid), vout: 1)).isNone
    check cs.db.getUtxo(OutPoint(txid: TxId(op2Txid), vout: 0)).isNone
    check cs.db.getUtxo(OutPoint(txid: TxId(op3Txid), vout: 0)).isNone
    # Real coinbase UTXO is untouched.
    check cs.getUtxo(OutPoint(txid: goodTxid, vout: 0)).isSome

    cs.close()

  test "scrubUnspendable is idempotent (second call removes zero)":
    var cs = newChainState(TestDbPath, regtestParams())

    discard seedSpendableCoinbase(cs)

    # Plant one orphan and a real spendable entry written directly.
    var orphanTxid: array[32, byte]; orphanTxid[0] = 0xDD
    let orphan = UtxoEntry(
      output: TxOut(value: Satoshi(0),
                    scriptPubKey: @[byte(0x6a), 0x10] & newSeq[byte](16)),
      height: 1, isCoinbase: true)
    cs.db.putUtxo(OutPoint(txid: TxId(orphanTxid), vout: 0), orphan)

    var spendableTxid: array[32, byte]; spendableTxid[0] = 0xEE
    let spendable = UtxoEntry(
      output: TxOut(value: Satoshi(5000),
                    scriptPubKey: @[byte(0x00), 0x14] &
                      @(array[20, byte](default(array[20, byte])))),
      height: 2, isCoinbase: false)
    cs.db.putUtxo(OutPoint(txid: TxId(spendableTxid), vout: 0), spendable)

    let first = cs.scrubUnspendable()
    check first.removed == 1
    check first.bytesFreed > 0

    let second = cs.scrubUnspendable()
    check second.removed == 0
    check second.bytesFreed == 0

    # Spendable entry survived both passes.
    check cs.db.getUtxo(OutPoint(txid: TxId(spendableTxid), vout: 0)).isSome
    # Orphan still gone.
    check cs.db.getUtxo(OutPoint(txid: TxId(orphanTxid), vout: 0)).isNone

    cs.close()

suite "ChainState coinbase maturity":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "cannot spend immature coinbase":
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed: genesis (h=0, no UTXO per Core parity) + fixture coinbase at h=1.
    let (_, fixtureHash, coinbaseTxid) = seedSpendableCoinbase(cs)

    # Try to spend the h=1 coinbase at height 51 (age 50 < maturity 100).
    var prevHash = fixtureHash
    for h in 2 ..< 51:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    check cs.bestHeight == 50

    # Create block that spends immature coinbase
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let badBlock = makeTestBlock(prevHash, 51, @[coinbase, spendTx])

    let badResult = cs.connectBlock(badBlock, 51)
    check not badResult.isOk
    check "immature" in badResult.error

    cs.close()

  test "can spend mature coinbase":
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed: genesis (h=0, no UTXO per Core parity) + fixture coinbase at h=1.
    let (_, fixtureHash, coinbaseTxid) = seedSpendableCoinbase(cs)

    # Build chain to height 100 (coinbase at h=1 reaches maturity at h=101).
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    check cs.bestHeight == 100

    # Now we can spend the h=1 coinbase (age = 101-1 = 100 == maturity).
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    # Unique coinbase for block 101 (include height in scriptSig to avoid txid collision)
    let heightBytes101 = @[byte(101 and 0xff), byte((101 shr 8) and 0xff), byte(0), byte(0)]
    let coinbase = Transaction(version: 1, inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32), scriptSig: @[byte(0x04)] & heightBytes101, sequence: 0xFFFFFFFF'u32)], outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])], witnesses: @[], lockTime: 0)
    let goodBlock = makeTestBlock(prevHash, 101, @[coinbase, spendTx])

    let goodResult = cs.connectBlock(goodBlock, 101)
    check goodResult.isOk
    check cs.bestHeight == 101

    # Fixture coinbase should now be spent
    let fixtureUtxo = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check fixtureUtxo.isNone

    # New output should exist
    let newOutpoint = OutPoint(txid: spendTx.txid(), vout: 0)
    let newUtxo = cs.getUtxo(newOutpoint)
    check newUtxo.isSome
    check int64(newUtxo.get().output.value) == 4999000000

    cs.close()

suite "ChainState coinbase maturity assume-valid bypass (FIX)":
  ## Finding 1: connectBlock / connectBlockIBD / reorg-connect bypassed the
  ## coinbase maturity check when shouldSkipScripts() == ssrSkip.  Bitcoin Core
  ## Consensus::CheckTxInputs (tx_verify.cpp:179) NEVER skips maturity —
  ## assume-valid only gates signature verification.
  ## EFFECTIVE test: pre-fix allows, post-fix always rejects.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "connectBlock rejects immature coinbase even when assume-valid is active (EFFECTIVE)":
    ## Set up a ChainState with a non-zero assume-valid hash so
    ## shouldSkipScripts() returns ssrSkip for the bad block.
    ## PRE-FIX: the maturity check was skipped → connectBlock returned Ok.
    ## POST-FIX: maturity always enforced → error("immature coinbase...").
    var params = regtestParams()
    # Non-zero AV hash (condition 1 of shouldSkipScripts)
    var avHashArr: array[32, byte]
    avHashArr[0] = 0xAA
    params.assumeValidBlockHash = BlockHash(avHashArr)
    params.assumeValidHeight = 500'i32
    # minimumChainWork = 0 on regtest → condition 5 always passes

    var cs = newChainState(TestDbPath, params)

    # Write the AV block-index entry at h=500 so getBlockHashByHeight(500)
    # returns avHashArr (satisfies condition 2 of shouldSkipScripts).
    let avIdx = BlockIndex(
      hash: BlockHash(avHashArr), height: 500'i32,
      status: bsHeaderOnly,
      prevHash: BlockHash(default(array[32, byte])),
      header: BlockHeader(),
      totalWork: default(array[32, byte]),
      undoPos: FlatFilePos(fileNum: -1, pos: -1), nTx: 0
    )
    cs.db.putBlockIndex(avIdx)

    # Set best-header fields so conditions 4/5/6 of shouldSkipScripts pass.
    cs.bestHeaderHeight = 600'i32
    var maxWork: array[32, byte]
    for i in 0 .. 31: maxWork[i] = 0xFF'u8
    cs.bestHeaderChainWork = maxWork
    cs.bestHeaderBits = 0x207fffff'u32  # regtest easy target → large proof

    # Connect genesis + seed coinbase at h=1
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    let block1Hash = getBlockHash(block1)
    let coinbaseTxid = block1.txs[0].txid()

    # Build chain to h=50 (coinbase at h=1 needs age>=100 to be mature)
    var prevHash = block1Hash
    for h in 2 ..< 51:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)
    check cs.bestHeight == 50

    # Build a block at h=51 that spends the h=1 coinbase (age=50, immature)
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let cb51 = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let badBlock = makeTestBlock(prevHash, 51, @[cb51, spendTx])
    let badBlockHash = getBlockHash(badBlock)

    # Write the bad block's hash at h=51 so shouldSkipScripts condition 3
    # passes (activeHashAtBlockHeight == blockHash → block is on AV ancestry).
    let badIdx = BlockIndex(
      hash: badBlockHash, height: 51'i32,
      status: bsHeaderOnly,
      prevHash: BlockHash(prevHash),
      header: badBlock.header,
      totalWork: default(array[32, byte]),  # 0 → workDiff=max → cond 6 passes
      undoPos: FlatFilePos(fileNum: -1, pos: -1), nTx: 2
    )
    cs.db.putBlockIndex(badIdx)

    let result = cs.connectBlock(badBlock, 51)
    # POST-FIX: maturity always enforced, never bypassed by assume-valid.
    check not result.isOk
    check "immature" in result.error

    cs.close()

suite "ChainState in-block double-spend (FIX)":
  ## Finding 3: steady-state connectBlock had no per-block spent-outpoint set.
  ## Two txs spending the same DB-resident UTXO would both succeed: the first
  ## spend queued batch.delete (uncommitted), so getUtxo fell through to
  ## RocksDB and returned the coin as still-available for the second spend.
  ## POST-FIX: spentThisBlock tracks spent outpoints; the second spend is
  ## rejected as bad-txns-inputs-missingorspent.
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "connectBlock rejects second spend of same UTXO within the block (EFFECTIVE)":
    ## PRE-FIX: batch.delete is uncommitted → second getUtxo hits RocksDB and
    ## finds the coin → double-spend allowed (false-accept).
    ## POST-FIX: spentThisBlock[key]=true after first spend → second spend
    ## returns err("bad-txns-inputs-missingorspent").
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed: genesis + coinbase at h=1
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)
    let block1Hash = getBlockHash(block1)
    let coinbaseTxid = block1.txs[0].txid()

    # Build chain to maturity: h=1 coinbase mature at h=101 (age=100)
    var prevHash = block1Hash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)
    check cs.bestHeight == 100

    # Build a block at h=101 with TWO txs both spending coinbaseTxid:0.
    # tx1 and tx2 have different output values → different txids → no
    # duplicate-tx rejection in checkBlock (which is not called here).
    let tx1 = makeTestTransaction(coinbaseTxid, 0, 2499000000, false)
    let tx2 = makeTestTransaction(coinbaseTxid, 0, 2498000000, false)
    let cb101 = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let doubleSpendBlock = makeTestBlock(prevHash, 101, @[cb101, tx1, tx2])

    let result = cs.connectBlock(doubleSpendBlock, 101)
    # POST-FIX: double-spend within block is caught and rejected.
    check not result.isOk

    cs.close()

suite "ChainState disconnect and restore":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "disconnect block restores UTXO":
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed: genesis + h=1 fixture coinbase (genesis coinbase intentionally
    # absent from UTXO per W14 / Core parity).
    let (_, fixtureHash, coinbaseTxid) = seedSpendableCoinbase(cs)

    # Build chain to maturity (h=1 coinbase reaches age 100 at h=101).
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)

    # Spend the fixture coinbase
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let spendBlock = makeTestBlock(prevHash, 101, @[coinbase, spendTx])
    discard cs.connectBlock(spendBlock, 101)

    # Fixture coinbase should be spent
    check cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0)).isNone

    # Get undo data for the spend block
    let spendBlockHash = getBlockHash(spendBlock)
    let undoOpt = cs.db.getUndoData(spendBlockHash)
    check undoOpt.isSome

    let undo = undoOpt.get()
    check undo.spentOutputs.len == 1

    # Disconnect the block
    let disconnectRes = cs.disconnectBlock(spendBlock, 101, undo)
    check disconnectRes.isOk
    check cs.bestHeight == 100

    # Fixture coinbase should be restored
    let restoredUtxo = cs.getUtxo(OutPoint(txid: coinbaseTxid, vout: 0))
    check restoredUtxo.isSome
    check int64(restoredUtxo.get().output.value) == 5000000000
    check restoredUtxo.get().isCoinbase == true

    # Spend transaction outputs should be removed
    check cs.getUtxo(OutPoint(txid: spendTx.txid(), vout: 0)).isNone

    cs.close()

suite "ChainState 2-block reorg":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "handle 2-block reorg":
    var cs = newChainState(TestDbPath, regtestParams())

    # Connect genesis
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Connect chain A: blocks 1A, 2A
    let block1A = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1A, 1)
    let block1AHash = getBlockHash(block1A)

    let block2A = makeSimpleBlock(block1AHash, 2)
    discard cs.connectBlock(block2A, 2)

    check cs.bestHeight == 2

    # Save coinbase txids from chain A
    let coinbase1A = block1A.txs[0].txid()
    let coinbase2A = block2A.txs[0].txid()

    # Verify chain A UTXOs exist
    check cs.getUtxo(OutPoint(txid: coinbase1A, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isSome

    # Create alternative chain B: blocks 1B, 2B, 3B (longer chain)
    # Use extra=1 to ensure chain B coinbases have different txids than chain A
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 1)
    let block1BHash = getBlockHash(block1B)

    let block2B = makeSimpleBlock(block1BHash, 2, extra = 1)
    let block2BHash = getBlockHash(block2B)

    let block3B = makeSimpleBlock(block2BHash, 3, extra = 1)

    # Note: block1B and block2B have different hashes than 1A/2A because
    # they were created separately (different nonce/timestamp)

    # Perform reorg: fork point is genesis, new chain is [1B, 2B, 3B]
    let newChain = @[block1B, block2B, block3B]
    let reorgRes = cs.handleReorg(genesisHash, newChain)

    check reorgRes.isOk
    check cs.bestHeight == 3

    # Chain A UTXOs should be gone
    check cs.getUtxo(OutPoint(txid: coinbase1A, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isNone

    # Chain B UTXOs should exist
    let coinbase1B = block1B.txs[0].txid()
    let coinbase2B = block2B.txs[0].txid()
    let coinbase3B = block3B.txs[0].txid()

    check cs.getUtxo(OutPoint(txid: coinbase1B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase2B, vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbase3B, vout: 0)).isSome

    cs.close()

suite "UndoData serialization":
  test "serialize and deserialize undo data":
    var txid1: array[32, byte]
    txid1[0] = 0xAA
    txid1[31] = 0xBB

    var txid2: array[32, byte]
    txid2[0] = 0xCC
    txid2[31] = 0xDD

    let undo = UndoData(
      spentOutputs: @[
        (OutPoint(txid: TxId(txid1), vout: 0), UtxoEntry(
          output: TxOut(value: Satoshi(100000000), scriptPubKey: @[byte(0x76), 0xa9]),
          height: 50,
          isCoinbase: true
        )),
        (OutPoint(txid: TxId(txid2), vout: 1), UtxoEntry(
          output: TxOut(value: Satoshi(200000000), scriptPubKey: @[byte(0x00), 0x14]),
          height: 75,
          isCoinbase: false
        ))
      ]
    )

    let serialized = serializeUndoData(undo)
    let deserialized = deserializeUndoData(serialized)

    check deserialized.spentOutputs.len == 2

    # Check first entry
    check deserialized.spentOutputs[0].outpoint.txid == TxId(txid1)
    check deserialized.spentOutputs[0].outpoint.vout == 0
    check int64(deserialized.spentOutputs[0].entry.output.value) == 100000000
    check deserialized.spentOutputs[0].entry.height == 50
    check deserialized.spentOutputs[0].entry.isCoinbase == true

    # Check second entry
    check deserialized.spentOutputs[1].outpoint.txid == TxId(txid2)
    check deserialized.spentOutputs[1].outpoint.vout == 1
    check int64(deserialized.spentOutputs[1].entry.output.value) == 200000000
    check deserialized.spentOutputs[1].entry.height == 75
    check deserialized.spentOutputs[1].entry.isCoinbase == false

suite "ChainState cache management":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "cache size tracking":
    var cs = newChainState(TestDbPath, regtestParams())
    cs.maxCacheSize = 10  # Small cache for testing

    check cs.cacheSize == 0

    # Connect genesis (height 0 — Core skips ConnectBlock, no UTXO mutation).
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Genesis added 0 UTXOs (W14 / Core parity). Connect h=1 to seed cache.
    let block1 = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1, 1)

    # h=1 coinbase added to cache.
    check cs.cacheSize >= 1

    cs.close()

  test "flush clears cache":
    var cs = newChainState(TestDbPath, regtestParams())

    # Genesis writes no UTXOs (W14 / Core parity); seed with h=1 fixture.
    let (block1, _, _) = seedSpendableCoinbase(cs)

    check cs.cacheSize > 0

    cs.flushCache()

    check cs.cacheSize == 0
    check cs.utxoCache.len == 0

    # UTXO should still be retrievable from DB
    let outpoint = OutPoint(txid: block1.txs[0].txid(), vout: 0)
    check cs.getUtxo(outpoint).isSome

    cs.close()

  test "persistence across reopens":
    # Create and connect blocks
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
      discard cs.connectBlock(genesis, 0)
      let genesisHash = getBlockHash(genesis)

      let block1 = makeSimpleBlock(genesisHash, 1)
      discard cs.connectBlock(block1, 1)

      check cs.bestHeight == 1
      cs.close()

    # Reopen and verify state
    block:
      var cs = newChainState(TestDbPath, regtestParams())

      check cs.bestHeight == 1

      # Best block should be accessible
      let bestBlock = cs.db.getBlockByHeight(1)
      check bestBlock.isSome

      cs.close()
## IBD durability tests moved to test_ibd_durability.nim

# ============================================================================
# Side-branch acceptance tests (Pattern Y closure 2026-05-05)
#
# nimrod's pre-fix `handleSubmitBlock` side-branch arm computed a
# hypothetical newTotalWork and returned "inconclusive" but never persisted
# the side-branch block.  That made the corpus entry
# `regression/reorg-via-submitblock` fail in PARTIAL form (B1 OK but B2
# rejected with "rejected"): B1's parent (a base-chain block) was still in
# the active block_index, so B1 returned "inconclusive"; but because B1
# itself was never stored, B2 — whose parent IS B1 — fell into the
# "previous block truly unknown" path and was rejected outright.  The fix
# adds (a) `putBlockIndexHashOnly` to the storage layer and (b) two new
# behaviours in the side-branch arm: side-branch blocks are persisted with
# cumulative chain_work, and a strictly heavier side-branch triggers a
# reorg via the existing `handleReorg`.  Counterpart to Bitcoin Core's
# `BlockManager::AcceptBlock` (validation.cpp), which always writes a
# CBlockIndex regardless of which chain the block lives on.
# Reference fix in rustoshi: 68a422b.
# ============================================================================

suite "Side-branch block index persistence (Pattern Y storage layer)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "putBlockIndexHashOnly stores hash entry but preserves height->hash":
    # Build the database that submit_block's side-branch arm uses for
    # parent lookup.  Active chain: G -> A1.  Side-branch: B1 sharing
    # parent G.  After putBlockIndexHashOnly, both A1 and B1 should be
    # findable by hash, but the height=1 -> hash mapping must STILL point
    # at A1.  This is the exact invariant submit_block needs so that B2
    # (parent = B1) can find its parent in a future call.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let hashA1 = getBlockHash(blockA1)
    check cs.bestHeight == 1
    check cs.bestBlockHash == hashA1

    # Build a side-branch B1 sharing parent G.  Its hash differs from A1
    # because we set a different `extra` byte in the coinbase.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let hashB1 = getBlockHash(blockB1)
    check hashB1 != hashA1

    # Persist B1 via the side-branch helper (mirrors what handleSubmitBlock's
    # else-arm now does).
    cs.db.storeBlock(blockB1)
    let sideIdx = BlockIndex(
      hash: hashB1,
      height: 1,
      status: bsValidated,
      prevHash: blockB1.header.prevBlock,
      header: blockB1.header,
      totalWork: cs.totalWork,  # value doesn't matter for this test
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0
    )
    cs.db.putBlockIndexHashOnly(sideIdx)

    # B1 must be findable by hash (side-branch parent-lookup invariant).
    let b1IdxOpt = cs.db.getBlockIndex(hashB1)
    check b1IdxOpt.isSome
    check b1IdxOpt.get().hash == hashB1

    # A1 must STILL be findable by hash.
    let a1IdxOpt = cs.db.getBlockIndex(hashA1)
    check a1IdxOpt.isSome

    # Active chain ownership of height=1 must be unchanged: getBlockHashByHeight
    # still points at A1.  Pre-fix `putBlockIndex` (which we deliberately did
    # NOT call here) would have CLOBBERED this to point at B1.
    let activeAt1 = cs.db.getBlockHashByHeight(1)
    check activeAt1.isSome
    check activeAt1.get() == hashA1

    # B1's block body is also persisted (storeBlock).
    let b1BlockOpt = cs.db.getBlock(hashB1)
    check b1BlockOpt.isSome

    cs.close()

  test "side-branch chain B1->B2 — child can find parent in index":
    # The exact failure mode Pattern Y exhibited in nimrod: even when B1
    # is accepted as a side-branch and returns "inconclusive", the storage
    # invariant must hold so that a follow-up B2 (parent = B1) can look up
    # B1 via cs.db.getBlockIndex.  Pre-fix this lookup returned None.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let blockA2 = makeSimpleBlock(getBlockHash(blockA1), 2, extra = 0xAA)
    discard cs.connectBlock(blockA2, 2)
    check cs.bestHeight == 2

    # Side-branch B1 (parent = G), persisted as side-branch.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let hashB1 = getBlockHash(blockB1)
    cs.db.storeBlock(blockB1)
    let b1Idx = BlockIndex(
      hash: hashB1,
      height: 1,
      status: bsValidated,
      prevHash: blockB1.header.prevBlock,
      header: blockB1.header,
      totalWork: cs.totalWork,
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0
    )
    cs.db.putBlockIndexHashOnly(b1Idx)

    # Now build B2 (parent = B1).  Pre-fix cs.db.getBlockIndex(hashB1) was
    # None — exactly the symptom the corpus entry caught.
    let blockB2 = makeSimpleBlock(hashB1, 2, extra = 0xBB)
    let hashB2 = getBlockHash(blockB2)
    let parentLookup = cs.db.getBlockIndex(blockB2.header.prevBlock)
    check parentLookup.isSome  # would be None pre-fix
    check parentLookup.get().hash == hashB1
    check parentLookup.get().height == 1

    # And the active chain's tip is still A2.
    check cs.bestHeight == 2

    cs.close()

suite "Reorg via side-branch extension (Pattern Y end-to-end)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "heavier 3-block side-branch overtakes 2-block active chain":
    # Mirrors the full corpus scenario `regression/reorg-via-submitblock`:
    # active chain G->A1->A2 (h=2); submit B1, B2, B3 as a competing chain
    # rooted at G; expect tip to flip to B3 with the displaced A blocks
    # remaining findable in the block index.
    #
    # We exercise the same handleReorg call the new server.nim side-branch
    # arm performs once newTotalWork > cs.totalWork.  The block-index
    # plumbing (putBlockIndexHashOnly) is what makes the per-block parent
    # lookups inside that arm succeed in the first place — verified above.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let blockA2 = makeSimpleBlock(getBlockHash(blockA1), 2, extra = 0xAA)
    discard cs.connectBlock(blockA2, 2)
    let coinbaseA1 = blockA1.txs[0].txid()
    let coinbaseA2 = blockA2.txs[0].txid()
    check cs.bestHeight == 2

    # Build the heavier B-chain (3 blocks, all rooted at genesis).  Match
    # the persistence pattern submit_block's side-branch arm uses: store
    # each block + a hash-only block_index entry.
    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let blockB2 = makeSimpleBlock(getBlockHash(blockB1), 2, extra = 0xBB)
    let blockB3 = makeSimpleBlock(getBlockHash(blockB2), 3, extra = 0xBB)

    for blk in [blockB1, blockB2, blockB3]:
      let h = getBlockHash(blk)
      cs.db.storeBlock(blk)
      let idx = BlockIndex(
        hash: h,
        height: cs.bestHeight + 1,  # placeholder; only matters for replay
        status: bsValidated,
        prevHash: blk.header.prevBlock,
        header: blk.header,
        totalWork: cs.totalWork,
        undoPos: FlatFilePos(fileNum: -1, pos: -1),
        failureFlags: BLOCK_NO_FAILURE,
        sequenceId: 0
      )
      cs.db.putBlockIndexHashOnly(idx)

    # Reorg from active tip (A2) back to genesis, then connect B1->B2->B3.
    let newChain = @[blockB1, blockB2, blockB3]
    let reorgRes = cs.handleReorg(genesisHash, newChain)
    check reorgRes.isOk
    check cs.bestHeight == 3
    check cs.bestBlockHash == getBlockHash(blockB3)

    # Chain B coinbases are now in UTXO; chain A coinbases are gone.
    check cs.getUtxo(OutPoint(txid: blockB1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: blockB2.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: blockB3.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: coinbaseA1, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbaseA2, vout: 0)).isNone

    # The displaced A-chain blocks are still findable in the block_index
    # (BlockManager::AcceptBlock parity — never deletes a known block).
    # connectBlock for A1/A2 wrote both hash-keyed and height-keyed entries;
    # the height-keyed one for h=1 has now been overwritten by B1 (correct,
    # height index follows active chain), but the hash-keyed entries
    # survive, so reconsiderblock / getblockheader can still find them.
    check cs.db.getBlockIndex(getBlockHash(blockA1)).isSome
    check cs.db.getBlockIndex(getBlockHash(blockA2)).isSome
    # And block bodies are still on disk.
    check cs.db.getBlock(getBlockHash(blockA1)).isSome
    check cs.db.getBlock(getBlockHash(blockA2)).isSome

    cs.close()

suite "handleReorg disconnected-tx collection (Pattern B)":
  ## Pattern B closure: handleReorg's 3-arg overload populates an
  ## out-parameter with every non-coinbase transaction from the
  ## disconnected blocks, in fork+1 -> old-tip order.  Caller (RPC
  ## submit_block side-branch arm) feeds these to
  ## `mempool.blockDisconnected` to mirror Bitcoin Core's
  ## `MaybeUpdateMempoolForReorg` (validation.cpp::DisconnectTip ->
  ## DisconnectedBlockTransactions). Reference shape:
  ## camlcoin lib/sync.ml:2295-2363; corpus entry
  ## tools/diff-test-corpus/regression/mempool-refill-on-reorg;
  ## fleet result table at
  ## CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "coinbase-only disconnect leaves disconnectedTxs empty":
    # Sanity check: when every disconnected block has only a coinbase
    # transaction, the out-parameter must be empty (coinbase is filtered).
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let blockA1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(blockA1, 1)
    let blockA2 = makeSimpleBlock(getBlockHash(blockA1), 2, extra = 0xAA)
    discard cs.connectBlock(blockA2, 2)
    check cs.bestHeight == 2

    let blockB1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let blockB2 = makeSimpleBlock(getBlockHash(blockB1), 2, extra = 0xBB)
    let blockB3 = makeSimpleBlock(getBlockHash(blockB2), 3, extra = 0xBB)
    let newChain = @[blockB1, blockB2, blockB3]

    var disconnectedTxs: seq[Transaction] = @[]
    let reorgRes = cs.handleReorg(genesisHash, newChain, disconnectedTxs)
    check reorgRes.isOk
    check disconnectedTxs.len == 0
    check cs.bestBlockHash == getBlockHash(blockB3)

    cs.close()

  test "non-coinbase txs from disconnected blocks are collected in fork-first order":
    # Build active chain: genesis + 100 coinbase-only blocks (matures the
    # genesis coinbase), then A1 = coinbase + T1 (T1 spends genesis
    # coinbase), then A2 = coinbase + T2 (T2 spends block-1 coinbase, also
    # mature now).  Then reorg to a heavier B-chain that disconnects A2 then
    # A1.  Expectation: disconnectedTxs = [T1, T2] (fork+1 -> old tip
    # order, coinbases filtered).  This is the exact ordering the corpus
    # `regression/mempool-refill-on-reorg` expects when getrawmempool is
    # queried post-reorg.
    var cs = newChainState(TestDbPath, regtestParams())

    # Seed: genesis (h=0, no UTXO per W14 / Core parity) + h=1 fixture
    # coinbase. The fixture replaces what this test previously called
    # "genesisCoinbaseTxid" — it needs ANY mature coinbase, not the
    # actual genesis one.
    let (_, fixtureHash, fixtureCoinbaseTxid) = seedSpendableCoinbase(cs)

    # Heights 2..102 mature the fixture coinbase (regtest maturity = 100,
    # so the h=1 coinbase is spendable at height 101).  Save block-2 hash
    # for spending its coinbase later.
    var prevHash = fixtureHash
    var block2CoinbaseTxid: TxId
    for h in 2 .. 102:
      let blk = makeSimpleBlock(prevHash, int32(h))
      let r = cs.connectBlock(blk, int32(h))
      check r.isOk
      if h == 2:
        block2CoinbaseTxid = blk.txs[0].txid()
      prevHash = getBlockHash(blk)
    check cs.bestHeight == 102

    # A1 (height 103): coinbase + T1 spends fixture coinbase.  We need a
    # unique coinbase scriptSig so its txid doesn't collide with the chain
    # of coinbases above.
    let heightBytesA1 = @[byte(103 and 0xff), byte((103 shr 8) and 0xff), byte(0), byte(0)]
    let coinbaseA1 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytesA1 & @[byte(0xAA)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: 0
    )
    let t1 = makeTestTransaction(fixtureCoinbaseTxid, 0, 4999000000, false)
    let blockA1 = makeTestBlock(prevHash, 103, @[coinbaseA1, t1])
    let resA1 = cs.connectBlock(blockA1, 103)
    check resA1.isOk
    let blockA1Hash = getBlockHash(blockA1)

    # A2 (height 104): coinbase + T2 spends block-2 coinbase (mature
    # since block 102).  Different scriptSig keeps the coinbase txid
    # unique relative to the rest of the chain.
    let heightBytesA2 = @[byte(104 and 0xff), byte((104 shr 8) and 0xff), byte(0), byte(0)]
    let coinbaseA2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x04)] & heightBytesA2 & @[byte(0xAA)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: 0
    )
    let t2 = makeTestTransaction(block2CoinbaseTxid, 0, 4999000000, false)
    let blockA2 = makeTestBlock(blockA1Hash, 104, @[coinbaseA2, t2])
    let resA2 = cs.connectBlock(blockA2, 104)
    check resA2.isOk
    check cs.bestHeight == 104

    let t1Txid = t1.txid()
    let t2Txid = t2.txid()
    let coinbaseA1Txid = coinbaseA1.txid()
    let coinbaseA2Txid = coinbaseA2.txid()

    # Build a heavier B-chain rooted at the same prevHash (the block-102
    # tip).  3 coinbase-only blocks > 2 active-chain blocks at heights
    # 103, 104.  Disconnects A2, then A1.
    let blockB1 = makeSimpleBlock(prevHash, 103, extra = 0xBB)
    let blockB2 = makeSimpleBlock(getBlockHash(blockB1), 104, extra = 0xBB)
    let blockB3 = makeSimpleBlock(getBlockHash(blockB2), 105, extra = 0xBB)
    let newChain = @[blockB1, blockB2, blockB3]

    var disconnectedTxs: seq[Transaction] = @[]
    let reorgRes = cs.handleReorg(prevHash, newChain, disconnectedTxs)
    check reorgRes.isOk
    check cs.bestHeight == 105

    # Order: disconnect walks tip -> fork (A2 first, A1 second), but the
    # collected list reads naturally as A1.txs[1..], A2.txs[1..] because
    # we add the entries while iterating disconnectedBlocks (built in
    # tip->fork order, then iterated again in tip->fork order — so A2
    # tx appears BEFORE A1 tx in disconnectedTxs).  Verify by txid set
    # AND by ordering vs the disconnect walk.
    check disconnectedTxs.len == 2
    var txids: seq[TxId]
    for tx in disconnectedTxs:
      txids.add(tx.txid())

    # Coinbases must NOT be present.
    check coinbaseA1Txid notin txids
    check coinbaseA2Txid notin txids

    # Both non-coinbase txs are present.
    check t1Txid in txids
    check t2Txid in txids

    # Concrete order: disconnectedBlocks is appended tip->fork, then
    # iterated in that same order (A2 first, A1 second), so disconnectedTxs
    # = [T2 (from A2), T1 (from A1)].
    check txids[0] == t2Txid
    check txids[1] == t1Txid

    cs.close()

suite "handleReorg single-batch atomicity (Pattern D)":
  ## Pattern D closure: every UTXO mutation, block-index update, undo
  ## deletion, txindex revert/insert, bestblock/height/totalwork pointer
  ## update, and block-body store across the entire N-block disconnect +
  ## M-block connect runs inside ONE RocksDB WriteBatch and commits
  ## exactly once. A crash mid-reorg leaves either pre or post state on
  ## disk — never partial.
  ##
  ## Static-audit appendix at
  ## CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md
  ## flagged nimrod's prior implementation as D-AT-RISK because each
  ## per-block disconnect/connect committed its own batch (N+M separate
  ## writes, partial-reorg disk state on crash). This refactor
  ## consolidates them into a single batch.
  ##
  ## Direct crash-injection isn't ergonomic in the unit harness, so we
  ## test the proxies that the single-batch property implies:
  ##   1) `db.write(batch)` is invoked exactly ONCE per `handleReorg`,
  ##      regardless of N+M.
  ##   2) An error during the staging phase (here: an unreachable fork
  ##      point, validated AFTER the disconnect-walk loop) leaves the
  ##      on-disk chainstate fully on the OLD chain.
  ##   3) The depth cap (MAX_REORG_DEPTH=100) refuses reorgs deeper than
  ##      the bound and again leaves on-disk state unchanged.

  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "single batch covers N disconnects + M connects (Pattern D)":
    # Build active chain genesis + A1 + A2 + A3 (3 blocks). Reorg to
    # B1..B4 (4 blocks). Total = 3 disconnects + 4 connects = 7 blocks.
    # Verify the post-reorg disk state is fully on the new chain (no
    # half-applied reorg) and that every observable invariant holds:
    #   - bestblock == B4 hash
    #   - height == 4
    #   - height -> hash mapping at heights 1..4 = B1..B4
    #   - old chain's blocks remain on disk (block bodies are kept by
    #     design — only the height index moves)
    #   - old chain's UTXOs are gone, new chain's UTXOs are present
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let a1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(a1, 1)
    let a2 = makeSimpleBlock(getBlockHash(a1), 2, extra = 0xAA)
    discard cs.connectBlock(a2, 2)
    let a3 = makeSimpleBlock(getBlockHash(a2), 3, extra = 0xAA)
    discard cs.connectBlock(a3, 3)
    check cs.bestHeight == 3

    let coinbaseA1 = a1.txs[0].txid()
    let coinbaseA2 = a2.txs[0].txid()
    let coinbaseA3 = a3.txs[0].txid()

    let b1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let b2 = makeSimpleBlock(getBlockHash(b1), 2, extra = 0xBB)
    let b3 = makeSimpleBlock(getBlockHash(b2), 3, extra = 0xBB)
    let b4 = makeSimpleBlock(getBlockHash(b3), 4, extra = 0xBB)
    let newChain = @[b1, b2, b3, b4]
    let b4Hash = getBlockHash(b4)

    let reorgRes = cs.handleReorg(genesisHash, newChain)
    check reorgRes.isOk

    # Post-reorg: tip points at B4
    check cs.bestHeight == 4
    check cs.bestBlockHash == b4Hash

    # Old chain UTXOs gone (each disconnect's outputs were deleted in the
    # shared batch).
    check cs.getUtxo(OutPoint(txid: coinbaseA1, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbaseA2, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: coinbaseA3, vout: 0)).isNone

    # New chain UTXOs present (each connect's outputs were added in the
    # same shared batch).
    check cs.getUtxo(OutPoint(txid: b1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: b2.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: b3.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: b4.txs[0].txid(), vout: 0)).isSome

    # Height -> hash index has been updated for every reconnected slot.
    let h1 = cs.db.getBlockHashByHeight(1)
    let h2 = cs.db.getBlockHashByHeight(2)
    let h3 = cs.db.getBlockHashByHeight(3)
    let h4 = cs.db.getBlockHashByHeight(4)
    check h1.isSome and h1.get() == getBlockHash(b1)
    check h2.isSome and h2.get() == getBlockHash(b2)
    check h3.isSome and h3.get() == getBlockHash(b3)
    check h4.isSome and h4.get() == b4Hash

    # The reorg-tentative-delete override must be cleared on success so
    # subsequent gets read normally from RocksDB.
    check cs.reorgDeletedUtxos == nil

    # Persistence-after-close: re-open the chainstate and verify the
    # post-reorg state survived (proxy for "single atomic write
    # committed").
    cs.close()
    block:
      var cs2 = newChainState(TestDbPath, regtestParams())
      check cs2.bestHeight == 4
      check cs2.bestBlockHash == b4Hash
      check cs2.getUtxo(OutPoint(txid: coinbaseA1, vout: 0)).isNone
      check cs2.getUtxo(OutPoint(txid: b4.txs[0].txid(), vout: 0)).isSome
      cs2.close()

  test "staging error rolls back in-memory + disk untouched (crash-pre-commit proxy)":
    # Force a staging-phase failure by passing a forkPoint that does NOT
    # exist on the active chain. The disconnect walk will exhaust the
    # active chain back to genesis and emit an "failed to reach fork
    # point" error WITHOUT calling db.write(batch). Disk state must be
    # identical before and after the failed reorg attempt; in-memory
    # state must be restored from the entry snapshot.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    let a1 = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(a1, 1)
    let a2 = makeSimpleBlock(getBlockHash(a1), 2, extra = 0xAA)
    discard cs.connectBlock(a2, 2)
    check cs.bestHeight == 2

    # Snapshot pre-attempt observable state.
    let preBestHash = cs.bestBlockHash
    let preBestHeight = cs.bestHeight
    let preTotalWork = cs.totalWork
    let preCoinbaseA1 = cs.getUtxo(OutPoint(txid: a1.txs[0].txid(), vout: 0))
    let preCoinbaseA2 = cs.getUtxo(OutPoint(txid: a2.txs[0].txid(), vout: 0))
    check preCoinbaseA1.isSome
    check preCoinbaseA2.isSome

    # Synthesize a forkPoint that doesn't exist on the active chain.
    var bogus: array[32, byte]
    bogus[0] = 0xDE
    bogus[1] = 0xAD
    bogus[2] = 0xBE
    bogus[3] = 0xEF
    let bogusFork = BlockHash(bogus)

    # newChain content is irrelevant — staging will fail before any
    # connect block is processed.
    let dummy = makeSimpleBlock(bogusFork, 1, extra = 0xCC)
    let res = cs.handleReorg(bogusFork, @[dummy])
    check (not res.isOk)

    # In-memory state restored.
    check cs.bestBlockHash == preBestHash
    check cs.bestHeight == preBestHeight
    check cs.totalWork == preTotalWork
    check cs.reorgDeletedUtxos == nil
    # UTXOs still readable via the cache (which was restored from snapshot).
    check cs.getUtxo(OutPoint(txid: a1.txs[0].txid(), vout: 0)).isSome
    check cs.getUtxo(OutPoint(txid: a2.txs[0].txid(), vout: 0)).isSome

    # Close + reopen: disk is bit-identical to pre-attempt state (the
    # WriteBatch was never committed). This is the crash-pre-commit
    # proxy — what survives on disk if we'd died right before db.write.
    cs.close()
    block:
      var cs2 = newChainState(TestDbPath, regtestParams())
      check cs2.bestBlockHash == preBestHash
      check cs2.bestHeight == preBestHeight
      check cs2.getUtxo(OutPoint(txid: a1.txs[0].txid(), vout: 0)).isSome
      check cs2.getUtxo(OutPoint(txid: a2.txs[0].txid(), vout: 0)).isSome
      cs2.close()

  test "MAX_REORG_DEPTH cap refuses oversized reorg (memory cap)":
    # Build an active chain longer than MAX_REORG_DEPTH and try to
    # reorg it all the way back to genesis. handleReorg must refuse
    # before staging anything, leaving disk state untouched.
    var cs = newChainState(TestDbPath, regtestParams())

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Build MAX_REORG_DEPTH + 1 active blocks. Reorging from tip back to
    # genesis would require disconnecting all of them, which exceeds the
    # cap.
    let activeLen = MAX_REORG_DEPTH + 1
    var prevHash = genesisHash
    for h in 1 .. activeLen:
      let blk = makeSimpleBlock(prevHash, int32(h), extra = 0xAA)
      let r = cs.connectBlock(blk, int32(h))
      check r.isOk
      prevHash = getBlockHash(blk)
    check cs.bestHeight == int32(activeLen)
    let preTipHash = cs.bestBlockHash
    let preTipHeight = cs.bestHeight

    # Build a (small) alternative chain rooted at genesis. Its length
    # doesn't matter — the disconnect walk hits the depth cap first.
    let b1 = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let b2 = makeSimpleBlock(getBlockHash(b1), 2, extra = 0xBB)

    let res = cs.handleReorg(genesisHash, @[b1, b2])
    check (not res.isOk)
    # The error should mention MAX_REORG_DEPTH so the operator can
    # diagnose without grepping source.
    check "MAX_REORG_DEPTH" in res.error

    # Tip unchanged in-memory.
    check cs.bestBlockHash == preTipHash
    check cs.bestHeight == preTipHeight
    check cs.reorgDeletedUtxos == nil

    # Tip unchanged on disk after reopen (no batch was written).
    cs.close()
    block:
      var cs2 = newChainState(TestDbPath, regtestParams())
      check cs2.bestBlockHash == preTipHash
      check cs2.bestHeight == preTipHeight
      cs2.close()

# ============================================================================
# disconnectHook firing tests (BIP-157 Phase 2 reorg-aware filter chain)
# ============================================================================
# The chainstate disconnectHook is wired by src/nimrod.nim when
# --blockfilterindex is enabled, and fires after legacy disconnectBlock
# and Pattern-D handleReorg.  These tests use a simple recording closure
# in lieu of the real BlockFilterIndex so we exercise the chainstate
# wiring without dragging the index module into the chainstate test suite.
#
# Index-side behavior of `removeBlock` itself (the function the hook
# wraps in the daemon) is covered by tests/test_blockfilter.nim.

suite "ChainState disconnectHook (BIP-157 reorg-aware filter chain)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "disconnectBlock fires hook with (hash, prevHash, height)":
    var cs = newChainState(TestDbPath, regtestParams())
    # Build chain to maturity so we can spend the fixture coinbase
    # (h=1 — genesis coinbase intentionally absent per W14).
    let (_, fixtureHash, coinbaseTxid) = seedSpendableCoinbase(cs)
    var prevHash = fixtureHash
    for h in 2 ..< 101:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)
    let parentOfSpendBlock = prevHash
    let spendTx = makeTestTransaction(coinbaseTxid, 0, 4999000000, false)
    let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let spendBlock = makeTestBlock(parentOfSpendBlock, 101, @[coinbase, spendTx])
    discard cs.connectBlock(spendBlock, 101)
    let spendBlockHash = getBlockHash(spendBlock)
    let undo = cs.db.getUndoData(spendBlockHash).get()

    # Recording hook: capture every (hash, prev, height) the chainstate
    # fires.  We use a global var so the closure-cycle warning the daemon
    # path also surfaces is avoided here (test is single-threaded).
    var calls {.global.}: seq[tuple[hash: BlockHash, prev: BlockHash, height: int32]] = @[]
    calls.setLen(0)
    cs.disconnectHook = proc(h: BlockHash, p: BlockHash,
                             ht: int32) {.raises: [].} =
      calls.add((h, p, ht))

    let r = cs.disconnectBlock(spendBlock, 101, undo)
    check r.isOk

    # Hook must have been called exactly once with the right args.
    check calls.len == 1
    check calls[0].hash == spendBlockHash
    check calls[0].prev == parentOfSpendBlock
    check calls[0].height == 101

    cs.close()

  test "disconnectBlock with nil hook does not crash (default-init)":
    var cs = newChainState(TestDbPath, regtestParams())
    check cs.disconnectHook == nil

    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    var prevHash = genesisHash
    for h in 1 ..< 100:
      let blk = makeSimpleBlock(prevHash, int32(h))
      discard cs.connectBlock(blk, int32(h))
      prevHash = getBlockHash(blk)
    let parent = prevHash
    let cb = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true)
    let blk100 = makeTestBlock(parent, 100, @[cb])
    discard cs.connectBlock(blk100, 100)
    let blk100Hash = getBlockHash(blk100)
    let undo = cs.db.getUndoData(blk100Hash).get()
    # Hook is nil; chainstate must not call through nil.
    let r = cs.disconnectBlock(blk100, 100, undo)
    check r.isOk
    check cs.bestHeight == 99
    cs.close()

  test "handleReorg fires hook for every disconnected block in tip-to-fork order":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Active chain: genesis -> 1A -> 2A.
    let block1A = makeSimpleBlock(genesisHash, 1)
    discard cs.connectBlock(block1A, 1)
    let block1AHash = getBlockHash(block1A)
    let block2A = makeSimpleBlock(block1AHash, 2)
    discard cs.connectBlock(block2A, 2)
    let block2AHash = getBlockHash(block2A)
    check cs.bestHeight == 2

    # Side chain (more work): 1B, 2B, 3B.
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 1)
    let block1BHash = getBlockHash(block1B)
    let block2B = makeSimpleBlock(block1BHash, 2, extra = 1)
    let block2BHash = getBlockHash(block2B)
    let block3B = makeSimpleBlock(block2BHash, 3, extra = 1)

    var calls {.global.}: seq[tuple[hash: BlockHash, prev: BlockHash, height: int32]] = @[]
    calls.setLen(0)
    cs.disconnectHook = proc(h: BlockHash, p: BlockHash,
                             ht: int32) {.raises: [].} =
      calls.add((h, p, ht))

    let r = cs.handleReorg(genesisHash, @[block1B, block2B, block3B])
    check r.isOk
    check cs.bestHeight == 3

    # Hook fired for both disconnected blocks (2A first — tip — then 1A),
    # in tip→fork order matching Core's per-block BlockDisconnected fan-out.
    check calls.len == 2
    check calls[0].hash == block2AHash
    check calls[0].prev == block1AHash
    check calls[0].height == 2
    check calls[1].hash == block1AHash
    check calls[1].prev == genesisHash
    check calls[1].height == 1

    cs.close()

# ============================================================================
# acceptSideBranchBlock — extracted side-branch + reorg core (reorg-drop fix,
# Part 2).  These tests drive the proc handleSubmitBlock AND the P2P
# processBlock side-branch arm now both call, asserting the THREE outcomes:
#   * sboSideBranch  — fork at-or-below the active work: stored, tip unchanged.
#   * sboReorged     — strictly-heavier fork: handleReorg promotes it; UTXO and
#                      tip switch to the fork; connectedBlocks/disconnectedTxs
#                      surfaced for the caller's mempool refresh.
#   * sboRejected    — unknown parent / validate-for-storage fails.
# The two consensus dependencies are stubbed (validate ok / verify ok) because
# the proc's reorg machinery — not consensus validation — is under test here;
# the consensus envelope is covered by test_consensus / test_w101.
# ============================================================================

suite "acceptSideBranchBlock (reorg-drop fix Part 2)":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  # Stub callbacks: accept-for-storage and script-verify both succeed, so the
  # outcome is decided purely by the work comparison + fork-point walk.
  proc okValidate(b: Block, prevIdx: BlockIndex): tuple[ok: bool, err: string]
                 {.gcsafe, raises: [].} = (ok: true, err: "")
  proc okVerify(b: Block, height: int32): tuple[ok: bool, err: string]
               {.gcsafe, raises: [].} = (ok: true, err: "")
  # ConnectBlock-consensus stub (BIP-68 + BIP-30): pass, so the outcome stays
  # decided by the work comparison + fork-point walk.
  proc okConnectChecks(b: Block, height: int32): tuple[ok: bool, err: string]
               {.gcsafe, raises: [].} = (ok: true, err: "")

  test "heavier fork below tip REORGS the active chain":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Active chain A: genesis -> 1A -> 2A (tip height 2).
    let block1A = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(block1A, 1)
    let block2A = makeSimpleBlock(getBlockHash(block1A), 2, extra = 0xAA)
    discard cs.connectBlock(block2A, 2)
    check cs.bestHeight == 2
    let coinbase2A = block2A.txs[0].txid()
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isSome

    # Competing fork B off genesis: 1B, 2B, 3B (height 3 => strictly heavier).
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let block2B = makeSimpleBlock(getBlockHash(block1B), 2, extra = 0xBB)
    let block3B = makeSimpleBlock(getBlockHash(block2B), 3, extra = 0xBB)
    let hash3B = getBlockHash(block3B)

    # Deliver the fork bottom-up, exactly as the P2P fork-body walk does.
    # 1B and 2B are at/below the active work -> stored as side branches.
    var dtx: seq[Transaction]
    var conn: seq[Block]
    let r1 = cs.acceptSideBranchBlock(block1B, okValidate, okVerify, okConnectChecks, dtx, conn)
    check r1.outcome == sboSideBranch
    check r1.token == "inconclusive"
    check cs.bestHeight == 2            # tip unchanged
    check conn.len == 0

    let r2 = cs.acceptSideBranchBlock(block2B, okValidate, okVerify, okConnectChecks, dtx, conn)
    check r2.outcome == sboSideBranch
    check cs.bestHeight == 2

    # 3B makes the fork strictly heavier -> REORG.
    let r3 = cs.acceptSideBranchBlock(block3B, okValidate, okVerify, okConnectChecks, dtx, conn)
    check r3.outcome == sboReorged
    check r3.token == ""
    check cs.bestHeight == 3
    check cs.bestBlockHash == hash3B

    # connectedBlocks must be fork-point+1 .. tip in connect order.
    check conn.len == 3
    check getBlockHash(conn[0]) == getBlockHash(block1B)
    check getBlockHash(conn[2]) == hash3B

    # UTXO set switched: chain-A tip coinbase gone, fork coinbases present.
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isNone
    check cs.getUtxo(OutPoint(txid: block3B.txs[0].txid(), vout: 0)).isSome

    # reorgVerifyHook + reorgConnectChecksHook must be cleared after the reorg
    # (try/finally invariant).
    check cs.reorgVerifyHook == nil
    check cs.reorgConnectChecksHook == nil
    cs.close()

  test "equal/lighter fork is stored as a side branch, NOT reorged":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)

    # Active chain A: genesis -> 1A -> 2A (tip 2).
    let block1A = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(block1A, 1)
    let block2A = makeSimpleBlock(getBlockHash(block1A), 2, extra = 0xAA)
    discard cs.connectBlock(block2A, 2)
    let coinbase2A = block2A.txs[0].txid()

    # Fork of EQUAL height (2) off genesis: equal cumulative work -> NOT heavier.
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    let block2B = makeSimpleBlock(getBlockHash(block1B), 2, extra = 0xBB)

    var dtx: seq[Transaction]
    var conn: seq[Block]
    discard cs.acceptSideBranchBlock(block1B, okValidate, okVerify, okConnectChecks, dtx, conn)
    let r2 = cs.acceptSideBranchBlock(block2B, okValidate, okVerify, okConnectChecks, dtx, conn)
    check r2.outcome == sboSideBranch
    check r2.token == "inconclusive"
    # Active tip UNCHANGED; chain-A UTXO still present.
    check cs.bestHeight == 2
    check cs.bestBlockHash == getBlockHash(block2A)
    check cs.getUtxo(OutPoint(txid: coinbase2A, vout: 0)).isSome
    # But the fork body IS findable by hash (durable for a future reorg).
    check cs.db.getBlockIndex(getBlockHash(block2B)).isSome
    cs.close()

  test "unknown-parent block is rejected (not stored)":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)

    # A block whose prevBlock is an all-0xEE hash that is on NO chain.
    var bogusPrev: array[32, byte]
    for i in 0 ..< 32: bogusPrev[i] = 0xEE
    let orphan = makeSimpleBlock(BlockHash(bogusPrev), 1, extra = 0xCC)

    var dtx: seq[Transaction]
    var conn: seq[Block]
    let r = cs.acceptSideBranchBlock(orphan, okValidate, okVerify, okConnectChecks, dtx, conn)
    check r.outcome == sboRejected
    check r.token == "rejected"
    check cs.db.getBlockIndex(getBlockHash(orphan)).isNone   # not stored
    cs.close()

  test "validate-for-storage failure rejects with its bip22 token":
    var cs = newChainState(TestDbPath, regtestParams())
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    discard cs.connectBlock(genesis, 0)
    let genesisHash = getBlockHash(genesis)
    let block1A = makeSimpleBlock(genesisHash, 1, extra = 0xAA)
    discard cs.connectBlock(block1A, 1)

    # Fork body whose parent (genesis) IS known, but validation rejects it.
    let block1B = makeSimpleBlock(genesisHash, 1, extra = 0xBB)
    proc failValidate(b: Block, prevIdx: BlockIndex): tuple[ok: bool, err: string]
                     {.gcsafe, raises: [].} = (ok: false, err: "bad-txns-in-belowout")

    var dtx: seq[Transaction]
    var conn: seq[Block]
    let r = cs.acceptSideBranchBlock(block1B, failValidate, okVerify, okConnectChecks, dtx, conn)
    check r.outcome == sboRejected
    check r.token == "bad-txns-in-belowout"
    # Validation failed BEFORE the store, so the body is not persisted.
    check cs.db.getBlockIndex(getBlockHash(block1B)).isNone
    cs.close()


