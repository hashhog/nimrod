## W166 — IBD applyBlock must feed the BIP-113 finality check the CORRECT
## block height + median-time-past (the "bad-txns-nonfinal" mainnet block
## 950149 incident).
##
## Incident (mainnet, 2026-05-20): after the W164 bad-diffbits fix (493bcd1)
## let nimrod's IBD advance, the very next class of contextual check broke:
##
##   WRN block failed consensus checks (IBD applyBlock) height=950149
##       error="non-final transaction: bad-txns-nonfinal"
##
## Block 950149 is a VALID mainnet block (bitcoin-core + the rest of the
## fleet accepted it). It contains a transaction with a non-zero, time-domain
## nLockTime that IS final at the block's median-time-past per BIP-113.
##
## Root cause — the SAME architecture defect 493bcd1 patched piecemeal.
## nimrod's IBD `applyBlock` path validates blocks through `acceptBlock ->
## validateBlock`, whose BIP-113 finality cutoff calls
## `getMtpForHeight(db, prevHeight)`. `getMtpForHeight` walks the previous
## 11 blocks via the raw `ChainDb` readers `getBlockHashByHeight` /
## `getBlockIndex`. During IBD `connectBlockIBD` batches block-index rows
## into a RocksDB WriteBatch and only flushes every IbdBatchFlushInterval
## (2000) blocks — so for the whole unflushed window those raw readers
## return NOTHING. The 11-block MTP walk truncates to an empty set, MTP
## collapses to 0, and the finality cutoff of 0 makes any transaction with
## a time-domain nLockTime and a non-final input sequence look non-final.
## 493bcd1 fixed only the bad-diffbits gate's parent header; the finality
## gate (and the time-too-old gate) re-broke on the next valid block.
##
## Architectural fix (supersedes the piecemeal 493bcd1 approach):
##   (1) ChainDb keeps an unflushed-IBD block-index shadow
##       (ibdIndexByHash / ibdIndexByHeight); `getBlockIndex` and
##       `getBlockHashByHeight` consult it, so getMtpForHeight — and EVERY
##       contextual check — reads correct data mid-IBD-batch.
##   (2) applyBlock / processReceivedBlocks route through the unified
##       `acceptAndConnectBlock` envelope (bsIBD) instead of hand-building
##       a sentinel prevIndex.
##
## This suite exercises the real `applyBlock` path. It builds a block
## containing a non-coinbase transaction with the 950149 shape — a
## time-domain nLockTime that is final only against the REAL median-time-
## past of the previous 11 blocks — and applies it while those 11 parent
## blocks are still in the unflushed IBD batch. Pre-fix: rejected
## "bad-txns-nonfinal". Post-fix: accepted.
##
## Bitcoin Core reference: validation.cpp::ContextualCheckBlock calls
## IsFinalTx for every tx with nBlockTime = the block's MTP (BIP-113);
## consensus/tx_verify.cpp::IsFinalTx.

import std/[unittest, options, os, tables]
import ../src/network/sync
import ../src/consensus/[params, validation, chain]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing]

# ---------------------------------------------------------------------------
# Params: regtest difficulty (easy, mineable) with MAINNET-style PoW rules
# (constant non-retarget nBits) and coinbaseMaturity lowered to 1 so a
# non-coinbase tx can spend a coinbase output one block later — letting the
# test build a realistic 950149-shape transaction without a 100-block setup.
# ---------------------------------------------------------------------------
proc finalityParams(): ConsensusParams =
  result = regtestParams()
  # Non-retarget branch returns parent.bits unchanged (mainnet semantics):
  result.powAllowMinDifficultyBlocks = false
  result.powNoRetargeting = false
  # Spend a coinbase one block after it is mined (test-only convenience).
  result.coinbaseMaturity = 1

const EASY_BITS = 0x207fffff'u32

# Time-domain locktime constants. LocktimeThreshold (500_000_000) is the
# height/time boundary: a locktime >= it is interpreted as a Unix timestamp.
const BASE_TIME = 1_700_000_000'u32   ## block 1 timestamp; +600 per block

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc makeCoinbaseTx(height: int32): Transaction =
  ## Canonical coinbase: BIP-34 height prefix, OP_TRUE output, final input.
  let scriptSig = encodeBip34Height(height) & @[byte(0x00)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5_000_000_000'i64),
      scriptPubKey: @[byte(0x51)]   # OP_TRUE — anyone-can-spend
    )],
    witnesses: @[],
    lockTime: 0
  )

proc mineHeader(coinbase: Transaction, extraTxids: seq[array[32, byte]],
                prevHash: BlockHash, ts: uint32): BlockHeader =
  ## Build a header for {coinbase} ++ extra txs and mine a satisfying nonce.
  var txids = @[array[32, byte](coinbase.txid())]
  for t in extraTxids: txids.add(t)
  var hdr = BlockHeader(
    version: 4,
    prevBlock: prevHash,
    merkleRoot: merkleRoot(txids),
    timestamp: ts,
    bits: EASY_BITS,
    nonce: 0
  )
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  hdr

proc mineCoinbaseBlock(prevHash: BlockHash, height: int32, ts: uint32): Block =
  ## A plain coinbase-only block.
  let cb = makeCoinbaseTx(height)
  Block(header: mineHeader(cb, @[], prevHash, ts), txs: @[cb])

# ---------------------------------------------------------------------------
# Datadir: canonical genesis + `count` coinbase-only blocks, all connected
# via connectBlock (every index row flushed to RocksDB — a clean shutdown).
# ---------------------------------------------------------------------------
proc buildDatadir(path: string, p: ConsensusParams,
                  count: int): tuple[cs: ChainState, blks: seq[Block]] =
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  let res0 = cs.connectBlock(genesis, 0'i32)
  doAssert res0.isOk, "buildDatadir connect genesis: " & $res0.error
  var blks: seq[Block] = @[genesis]
  var prevHash = p.genesisBlockHash
  var ts = BASE_TIME
  for h in 1'i32 .. int32(count):
    let blk = mineCoinbaseBlock(prevHash, h, ts)
    let res = cs.connectBlock(blk, h)
    doAssert res.isOk, "buildDatadir connect h=" & $h & ": " & $res.error
    prevHash = hashOf(blk.header)
    blks.add(blk)
    ts += 600
  result = (cs, blks)

# ===========================================================================
suite "W166: IBD applyBlock feeds the finality check correct height + MTP":

  test "block with a time-domain-nLockTime tx is ACCEPTED mid-IBD-batch (950149)":
    ## THE 950149 bug. A non-coinbase tx with a non-final input sequence and
    ## a time-domain nLockTime that is final ONLY against the real MTP of the
    ## previous 11 blocks. Applied while those 11 parent blocks are still in
    ## the unflushed IBD batch. Pre-fix getMtpForHeight saw an empty window,
    ## MTP collapsed to 0, and the finality cutoff of 0 rejected the tx
    ## "bad-txns-nonfinal". Post-fix the ChainDb shadow yields the real MTP.
    let p = finalityParams()
    let path = "/tmp/nimrod_w165_accept"
    # Genesis + blocks 1..3 flushed to RocksDB.
    let (cs, blks) = buildDatadir(path, p, 3)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    check sm.chainTipHeight == 3

    # Pre-mine a long run of coinbase-only blocks 4..40 so the header tip is
    # far ahead — applyBlock then selects the IBD fast path (connectBlockIBD),
    # which batches index rows (flush interval is 2000, so nothing flushes).
    var chain: seq[Block]
    var prevHdr = blks[3].header
    var ts = blks[3].header.timestamp
    # Coinbase blocks 4..24 — these become the spendable + MTP-window blocks.
    for h in 4'i32 .. 24'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    # Block 25 carries the 950149-shape transaction. It spends the coinbase
    # output of block 5 (mature: coinbaseMaturity=1). Its nLockTime is a
    # time-domain value chosen so the tx is FINAL only against the real MTP
    # of block 25's previous 11 blocks (14..24), and NON-final against the
    # stale (empty -> 0) MTP that the pre-fix getMtpForHeight produced.
    # Spend block 3's coinbase. Blocks 1..3 were connected via `connectBlock`
    # (flushed straight to RocksDB), so the spent UTXO is durable — this
    # isolates the test from `validateBlock`'s ChainDb-only intra-block UTXO
    # lookup (a separate pre-existing limitation, not what W166 fixes). The
    # 950149 finality bug is independent of where the spent UTXO lives.
    let spentCoinbase = blks[3].txs[0]           # block 3's coinbase (flushed)
    let spentTxid = spentCoinbase.txid()
    # Block timestamps: block h has ts = BASE_TIME + (h-1)*600.
    # MTP of block 25's parents (heights 14..24) = median = block 19's ts.
    let realMtpOfParent = BASE_TIME + uint32(19 - 1) * 600'u32
    # nLockTime: time-domain (>= LocktimeThreshold) AND strictly below the
    # real parent MTP, so IsFinalTx's `lockTime < cutoff` makes it FINAL.
    let lockTimeVal = realMtpOfParent - 600'u32
    doAssert lockTimeVal >= 500_000_000'u32, "locktime must be time-domain"

    let finalityTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: spentTxid, vout: 0'u32),
        scriptSig: @[],                 # spends OP_TRUE — empty scriptSig ok
        sequence: 0'u32                 # NON-final: forces the locktime path
      )],
      outputs: @[TxOut(
        value: Satoshi(4_999_900_000'i64),   # 100k sat fee
        scriptPubKey: @[byte(0x51)]
      )],
      witnesses: @[],
      lockTime: lockTimeVal
    )

    # Block 25: coinbase + finalityTx.
    ts += 600
    let cb25 = makeCoinbaseTx(25'i32)
    let blk25 = Block(
      header: mineHeader(cb25, @[array[32, byte](finalityTx.txid())],
                         hashOf(prevHdr), ts),
      txs: @[cb25, finalityTx]
    )
    chain.add(blk25)
    prevHdr = blk25.header

    # A few trailing coinbase blocks so the header tip stays > 10 ahead
    # while block 25 is applied (keeps the IBD fast path engaged).
    for h in 26'i32 .. 40'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    # Sync all 37 headers first (header tip = 40).
    var headers: seq[BlockHeader]
    for b in chain: headers.add(b.header)
    check sm.processHeaders(headers) == 37
    check sm.headerChain.tipHeight == 40

    # Apply every block. Block 25's finality tx must be accepted: the parent
    # blocks 14..24 are in the unflushed IBD batch, and the ChainDb shadow
    # is what makes getMtpForHeight return the real MTP for the cutoff.
    for i, b in chain:
      let h = int32(4 + i)
      check sm.applyBlock(b, h)
      check sm.chainTipHeight == h
    check sm.chainTipHeight == 40
    check sm.chainTip == hashOf(chain[^1].header)

  test "a genuinely non-final tx is still REJECTED mid-IBD-batch":
    ## The fix must not over-correct. A tx whose time-domain nLockTime is
    ## ABOVE the real parent MTP (not yet final) with a non-final input
    ## sequence must still be rejected "bad-txns-nonfinal".
    let p = finalityParams()
    let path = "/tmp/nimrod_w165_reject"
    let (cs, blks) = buildDatadir(path, p, 3)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)

    var chain: seq[Block]
    var prevHdr = blks[3].header
    var ts = blks[3].header.timestamp
    for h in 4'i32 .. 24'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    # Spend block 3's coinbase. Blocks 1..3 were connected via `connectBlock`
    # (flushed straight to RocksDB), so the spent UTXO is durable — this
    # isolates the test from `validateBlock`'s ChainDb-only intra-block UTXO
    # lookup (a separate pre-existing limitation, not what W166 fixes). The
    # 950149 finality bug is independent of where the spent UTXO lives.
    let spentCoinbase = blks[3].txs[0]           # block 3's coinbase (flushed)
    # nLockTime FAR in the future — above the real parent MTP and above the
    # block's own timestamp, so the tx is genuinely non-final.
    let badLockTime = BASE_TIME + 10_000_000'u32
    doAssert badLockTime >= 500_000_000'u32

    let nonFinalTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: spentCoinbase.txid(), vout: 0'u32),
        scriptSig: @[],
        sequence: 0'u32                 # NON-final input
      )],
      outputs: @[TxOut(
        value: Satoshi(4_999_900_000'i64),
        scriptPubKey: @[byte(0x51)]
      )],
      witnesses: @[],
      lockTime: badLockTime
    )

    ts += 600
    let cb25 = makeCoinbaseTx(25'i32)
    let blk25 = Block(
      header: mineHeader(cb25, @[array[32, byte](nonFinalTx.txid())],
                         hashOf(prevHdr), ts),
      txs: @[cb25, nonFinalTx]
    )
    chain.add(blk25)
    prevHdr = blk25.header

    for h in 26'i32 .. 40'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    var headers: seq[BlockHeader]
    for b in chain: headers.add(b.header)
    check sm.processHeaders(headers) == 37

    # Blocks 4..24 apply fine; block 25 must be REJECTED (non-final tx).
    for i in 0 ..< 21:
      check sm.applyBlock(chain[i], int32(4 + i))
    check sm.chainTipHeight == 24
    check (not sm.applyBlock(chain[21], 25'i32))   # the non-final-tx block
    check sm.chainTipHeight == 24                  # tip must not advance

  test "a finality-window-sensitive tx survives an IBD batch FLUSH boundary":
    ## Cross-check the shadow's lifecycle: after flushIBDBatch the rows ARE
    ## in RocksDB and the shadow is cleared. Lower the disk/flush interval so
    ## a flush actually fires mid-run, then apply a finality-sensitive block
    ## AFTER the flush — getMtpForHeight must read the real MTP from RocksDB
    ## (post-flush) just as it read it from the shadow (pre-flush).
    let p = finalityParams()
    let path = "/tmp/nimrod_w165_flush"
    let (cs, blks) = buildDatadir(path, p, 3)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    # Force a small IBD flush interval so a flush happens within the run.
    csv.ibdDiskFlushInterval = 8
    let sm = newSyncManager(nil, csv.db, p, csv)

    var chain: seq[Block]
    var prevHdr = blks[3].header
    var ts = blks[3].header.timestamp
    for h in 4'i32 .. 24'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    # Spend block 3's coinbase. Blocks 1..3 were connected via `connectBlock`
    # (flushed straight to RocksDB), so the spent UTXO is durable — this
    # isolates the test from `validateBlock`'s ChainDb-only intra-block UTXO
    # lookup (a separate pre-existing limitation, not what W166 fixes). The
    # 950149 finality bug is independent of where the spent UTXO lives.
    let spentCoinbase = blks[3].txs[0]           # block 3's coinbase (flushed)
    let realMtpOfParent = BASE_TIME + uint32(19 - 1) * 600'u32
    let lockTimeVal = realMtpOfParent - 600'u32
    doAssert lockTimeVal >= 500_000_000'u32

    let finalityTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: spentCoinbase.txid(), vout: 0'u32),
        scriptSig: @[],
        sequence: 0'u32
      )],
      outputs: @[TxOut(value: Satoshi(4_999_900_000'i64),
                       scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: lockTimeVal
    )
    ts += 600
    let cb25 = makeCoinbaseTx(25'i32)
    let blk25 = Block(
      header: mineHeader(cb25, @[array[32, byte](finalityTx.txid())],
                         hashOf(prevHdr), ts),
      txs: @[cb25, finalityTx]
    )
    chain.add(blk25)
    prevHdr = blk25.header
    for h in 26'i32 .. 40'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    var headers: seq[BlockHeader]
    for b in chain: headers.add(b.header)
    check sm.processHeaders(headers) == 37

    # Apply every block; a flush fires partway through. Block 25's finality
    # check must pass whether its MTP window straddles the shadow, the
    # flush, or RocksDB.
    for i, b in chain:
      let h = int32(4 + i)
      check sm.applyBlock(b, h)
    check sm.chainTipHeight == 40

  test "processReceivedBlocks (the second IBD path) also feeds correct MTP":
    ## The BlockDownloader's `processReceivedBlocks` is the OTHER IBD
    ## block-application path. It had the IDENTICAL sentinel-prevIndex defect
    ## (and never even got 493bcd1's partial fix). It is now migrated to the
    ## same `acceptAndConnectBlock` envelope. Drive the 950149-shape block
    ## through it and assert acceptance — proving the architectural fix
    ## covers BOTH IBD paths, not just applyBlock.
    let p = finalityParams()
    let path = "/tmp/nimrod_w165_prb"
    let (cs, blks) = buildDatadir(path, p, 3)
    defer:
      var c = cs
      c.close()
      removeDir(path)

    var csv = cs
    let sm = newSyncManager(nil, csv.db, p, csv)
    let dl = newBlockDownloader(sm)

    var chain: seq[Block]
    var prevHdr = blks[3].header
    var ts = blks[3].header.timestamp
    for h in 4'i32 .. 24'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    let spentCoinbase = blks[3].txs[0]           # block 3's coinbase (flushed)
    let realMtpOfParent = BASE_TIME + uint32(19 - 1) * 600'u32
    let lockTimeVal = realMtpOfParent - 600'u32
    doAssert lockTimeVal >= 500_000_000'u32

    let finalityTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: spentCoinbase.txid(), vout: 0'u32),
        scriptSig: @[],
        sequence: 0'u32                 # NON-final input -> locktime path
      )],
      outputs: @[TxOut(value: Satoshi(4_999_900_000'i64),
                       scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: lockTimeVal
    )
    ts += 600
    let cb25 = makeCoinbaseTx(25'i32)
    let blk25 = Block(
      header: mineHeader(cb25, @[array[32, byte](finalityTx.txid())],
                         hashOf(prevHdr), ts),
      txs: @[cb25, finalityTx]
    )
    chain.add(blk25)
    prevHdr = blk25.header
    for h in 26'i32 .. 30'i32:
      ts += 600
      let b = mineCoinbaseBlock(hashOf(prevHdr), h, ts)
      chain.add(b)
      prevHdr = b.header

    var headers: seq[BlockHeader]
    for b in chain: headers.add(b.header)
    check sm.processHeaders(headers) == 27

    # Feed all blocks to the downloader's queue, then drain via
    # processReceivedBlocks (the migrated second IBD path).
    for i, b in chain:
      dl.receivedBlocks[int32(4 + i)] = b
    dl.processReceivedBlocks()

    # Every block — including block 25's finality tx — must have been
    # connected by the second IBD path.
    check sm.chainTipHeight == 30
    check sm.chainTip == hashOf(chain[^1].header)
