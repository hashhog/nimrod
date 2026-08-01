## W167 — getblockstats fee + percentile + UTXO-delta math.
##
## Proven-teeth test for the pure core of the getblockstats RPC
## (`computeBlockStats` in src/rpc/server.nim), a faithful port of
## bitcoin-core/src/rpc/blockchain.cpp::getblockstats (lines 1956-2214) plus
## CalculatePercentilesByWeight (1916) and CalculateTruncatedMedian (1901).
##
## We construct a block with a coinbase + two non-coinbase transactions whose
## spent-prevout values are known, then assert that every fee/feerate/size/
## weight/UTXO-delta statistic matches an independently hand-computed expected
## value. The coinbase must be excluded from all fee/feerate stats + the
## feerate_percentiles array, but still counted toward txs/outs/utxo_size_inc.
##
## Reference siblings (live-verified byte-identical to Core): blockbrew
## internal/rpc/getblockstats_methods.go, hotbuns src/rpc/server.ts getBlockStats.

import unittest2
import std/[json, options]
import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/rpc/server

proc mkOutPoint(seed: byte, vout: uint32): OutPoint =
  var a: array[32, byte]
  a[0] = seed
  OutPoint(txid: TxId(a), vout: vout)

proc coinbaseTx(outVal: int64, script: seq[byte]): Transaction =
  ## A coinbase: single input with null prevout + vout 0xffffffff.
  result.version = 2
  result.inputs = @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                           vout: 0xffffffff'u32),
                         scriptSig: @[byte 0x03, 0x01, 0x02, 0x03],
                         sequence: 0xffffffff'u32)]
  result.outputs = @[TxOut(value: Satoshi(outVal), scriptPubKey: script)]
  result.lockTime = 0

# txOut serialized size = 8 (value) + CompactSize(len) + len.
# For a script < 0xFD bytes, CompactSize(len) == 1 byte, so size = 9 + len.
proc txOutSize(scriptLen: int): int64 = int64(9 + scriptLen)
const PerUtxo = 41'i64

suite "W167 getblockstats math":

  test "fees, feerates, sizes, sw + utxo deltas (legacy + segwit txs)":
    # ── Build the block ──────────────────────────────────────────────────────
    # script lengths chosen distinct so size deltas are checkable.
    let cbScript = newSeq[byte](25)         # P2PKH-ish, 25 bytes
    let s1a = newSeq[byte](22)              # tx1 out 0 (P2WPKH-ish)
    let s1b = newSeq[byte](34)              # tx1 out 1 (P2WSH-ish)
    let s2a = newSeq[byte](25)             # tx2 out 0

    # Coinbase: 1 output (subsidy + fees, value irrelevant to fee stats).
    let cb = coinbaseTx(5_000_000_000, cbScript)

    # tx1: legacy, 1 input → 2 outputs. Spends a prevout of value 10000.
    var tx1: Transaction
    tx1.version = 2
    tx1.inputs = @[TxIn(prevOut: mkOutPoint(0xaa, 0), scriptSig: newSeq[byte](107),
                        sequence: 0xffffffff'u32)]
    tx1.outputs = @[TxOut(value: Satoshi(4000), scriptPubKey: s1a),
                    TxOut(value: Satoshi(5000), scriptPubKey: s1b)]
    tx1.lockTime = 0
    # tx1 prevout: value 10000, script len 25.
    let tx1Prevout = TxOut(value: Satoshi(10000), scriptPubKey: newSeq[byte](25))

    # tx2: segwit, 1 input → 1 output. Spends a prevout of value 20000.
    var tx2: Transaction
    tx2.version = 2
    tx2.inputs = @[TxIn(prevOut: mkOutPoint(0xbb, 1), scriptSig: @[],
                        sequence: 0xffffffff'u32)]
    tx2.outputs = @[TxOut(value: Satoshi(17000), scriptPubKey: s2a)]
    tx2.witnesses = @[@[newSeq[byte](72), newSeq[byte](33)]]  # sig + pubkey
    tx2.lockTime = 0
    # tx2 prevout: value 20000, script len 34.
    let tx2Prevout = TxOut(value: Satoshi(20000), scriptPubKey: newSeq[byte](34))

    var b: Block
    b.header.version = 2
    b.header.timestamp = 1_700_000_000'u32
    b.txs = @[cb, tx1, tx2]

    let height: int32 = 100
    let mediantime: int64 = 1_699_999_000
    let subsidy = int64(getBlockSubsidy(height, mainnetParams()))

    # txInputPrevouts: one entry per NON-coinbase tx, in order.
    let txInputPrevouts = @[@[tx1Prevout], @[tx2Prevout]]

    let r = computeBlockStats(b, height, mediantime, subsidy, txInputPrevouts)

    # ── Independent expected values ──────────────────────────────────────────
    # Fees: tx1 = 10000 - (4000+5000) = 1000 ; tx2 = 20000 - 17000 = 3000.
    let fee1 = 1000'i64
    let fee2 = 3000'i64
    check r["totalfee"].getBiggestInt() == fee1 + fee2          # 4000
    check r["minfee"].getBiggestInt() == fee1                    # 1000
    check r["maxfee"].getBiggestInt() == fee2                    # 3000
    check r["medianfee"].getBiggestInt() == (fee1 + fee2) div 2  # even → mean = 2000
    check r["avgfee"].getBiggestInt() == (fee1 + fee2) div 2     # /2 non-coinbase = 2000

    # Sizes: full witness serialization length per non-coinbase tx.
    let tx1Size = int64(serialize(tx1, includeWitness = true).len)
    let tx2Size = int64(serialize(tx2, includeWitness = true).len)
    check r["total_size"].getBiggestInt() == tx1Size + tx2Size
    check r["mintxsize"].getBiggestInt() == min(tx1Size, tx2Size)
    check r["maxtxsize"].getBiggestInt() == max(tx1Size, tx2Size)
    check r["avgtxsize"].getBiggestInt() == (tx1Size + tx2Size) div 2

    # Weights (BIP141): stripped*3 + full.
    let w1 = int64(calculateTransactionWeight(tx1))
    let w2 = int64(calculateTransactionWeight(tx2))
    check r["total_weight"].getBiggestInt() == w1 + w2

    # Segwit-only stats: tx2 has witness, tx1 does not.
    check r["swtxs"].getBiggestInt() == 1
    check r["swtotal_size"].getBiggestInt() == tx2Size
    check r["swtotal_weight"].getBiggestInt() == w2

    # Feerates: fee*4/weight (integer-truncated), sat/vB.
    let fr1 = (fee1 * 4) div w1
    let fr2 = (fee2 * 4) div w2
    check r["minfeerate"].getBiggestInt() == min(fr1, fr2)
    check r["maxfeerate"].getBiggestInt() == max(fr1, fr2)
    check r["avgfeerate"].getBiggestInt() == ((fee1 + fee2) * 4) div (w1 + w2)

    # feerate_percentiles: weight-ranked over [tx1, tx2]. With two elements the
    # cumulative-weight selection yields the lower feerate at the low percentiles
    # and the higher feerate at the top. Assert it is a 5-element non-decreasing
    # array bounded by the two feerates.
    let pct = r["feerate_percentiles"]
    check pct.kind == JArray
    check pct.len == 5
    for i in 0 ..< 5:
      check pct[i].getBiggestInt() >= min(fr1, fr2)
      check pct[i].getBiggestInt() <= max(fr1, fr2)
    for i in 1 ..< 5:
      check pct[i].getBiggestInt() >= pct[i-1].getBiggestInt()
    # 90th percentile must equal the largest feerate (Core fills the tail with
    # scores.back()).
    check pct[4].getBiggestInt() == max(fr1, fr2)

    # Counts: ins/outs/txs include the coinbase's outputs but not its fake input.
    check r["txs"].getBiggestInt() == 3
    check r["ins"].getBiggestInt() == 2                 # tx1(1) + tx2(1)
    check r["outs"].getBiggestInt() == 4                # cb(1) + tx1(2) + tx2(1)

    # total_out excludes the coinbase reward.
    check r["total_out"].getBiggestInt() == (4000 + 5000) + 17000

    # ── utxo_size_inc (all outputs added, all spent prevouts subtracted) ──────
    # Outputs added: cb(25) + tx1(22) + tx1(34) + tx2(25).
    let outAdd = (txOutSize(25) + PerUtxo) + (txOutSize(22) + PerUtxo) +
                 (txOutSize(34) + PerUtxo) + (txOutSize(25) + PerUtxo)
    # Spent prevouts subtracted: tx1 prevout(25) + tx2 prevout(34).
    let prevSub = (txOutSize(25) + PerUtxo) + (txOutSize(34) + PerUtxo)
    check r["utxo_size_inc"].getBiggestInt() == outAdd - prevSub

    # utxo_increase = outputs - inputs = 4 - 2 = 2.
    check r["utxo_increase"].getBiggestInt() == 2

    # No unspendable outputs and height != 0, so the *_actual counters equal the
    # non-actual ones here.
    check r["utxo_size_inc_actual"].getBiggestInt() == outAdd - prevSub
    check r["utxo_increase_actual"].getBiggestInt() == 2

    # Header-derived fields.
    check r["height"].getBiggestInt() == 100
    check r["mediantime"].getBiggestInt() == mediantime
    check r["time"].getBiggestInt() == 1_700_000_000
    check r["subsidy"].getBiggestInt() == subsidy

    # Full do_all object must carry all 31 documented stats.
    let keys = ["avgfee","avgfeerate","avgtxsize","blockhash","feerate_percentiles",
                "height","ins","maxfee","maxfeerate","maxtxsize","medianfee",
                "mediantime","mediantxsize","minfee","minfeerate","mintxsize",
                "outs","subsidy","swtotal_size","swtotal_weight","swtxs","time",
                "total_out","total_size","total_weight","totalfee","txs",
                "utxo_increase","utxo_size_inc","utxo_increase_actual",
                "utxo_size_inc_actual"]
    for k in keys:
      check r.hasKey(k)
    check r.len == 31

  test "coinbase-only block: zero fees, empty percentiles, min sentinels → 0":
    let cb = coinbaseTx(5_000_000_000, newSeq[byte](25))
    var b: Block
    b.header.version = 2
    b.header.timestamp = 1_700_000_500'u32
    b.txs = @[cb]
    let r = computeBlockStats(b, 200'i32, 1_699_999_500'i64,
                              int64(getBlockSubsidy(200'i32, mainnetParams())),
                              @[])  # no non-coinbase txs → no prevouts
    check r["txs"].getBiggestInt() == 1
    check r["ins"].getBiggestInt() == 0
    check r["outs"].getBiggestInt() == 1
    check r["totalfee"].getBiggestInt() == 0
    check r["minfee"].getBiggestInt() == 0      # MAX_MONEY sentinel → 0
    check r["maxfee"].getBiggestInt() == 0
    check r["medianfee"].getBiggestInt() == 0
    check r["avgfee"].getBiggestInt() == 0
    check r["minfeerate"].getBiggestInt() == 0  # MAX_MONEY sentinel → 0
    check r["maxfeerate"].getBiggestInt() == 0
    check r["mintxsize"].getBiggestInt() == 0   # MAX_BLOCK_SERIALIZED_SIZE → 0
    check r["maxtxsize"].getBiggestInt() == 0
    check r["total_size"].getBiggestInt() == 0
    check r["total_weight"].getBiggestInt() == 0
    check r["swtxs"].getBiggestInt() == 0
    # feerate_percentiles all zero when no non-coinbase tx.
    let pct = r["feerate_percentiles"]
    check pct.len == 5
    for i in 0 ..< 5:
      check pct[i].getBiggestInt() == 0
    # utxo_increase = 1 output - 0 inputs.
    check r["utxo_increase"].getBiggestInt() == 1

  test "genesis (height 0) excludes outputs from *_actual UTXO counters":
    let cb = coinbaseTx(5_000_000_000, newSeq[byte](25))
    var b: Block
    b.header.version = 1
    b.txs = @[cb]
    let r = computeBlockStats(b, 0'i32, 0'i64,
                              int64(getBlockSubsidy(0'i32, mainnetParams())), @[])
    # Genesis: utxo_size_inc counts the output, but *_actual must NOT.
    check r["utxo_size_inc"].getBiggestInt() == (txOutSize(25) + PerUtxo)
    check r["utxo_size_inc_actual"].getBiggestInt() == 0
    check r["utxo_increase_actual"].getBiggestInt() == 0  # utxos(0) - inputs(0)

  test "OP_RETURN output is unspendable → excluded from *_actual counters":
    # Coinbase with a normal output + an OP_RETURN (0x6a) output.
    var cb: Transaction
    cb.version = 2
    cb.inputs = @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                         vout: 0xffffffff'u32),
                       scriptSig: @[byte 0x03, 0x01, 0x02, 0x03],
                       sequence: 0xffffffff'u32)]
    let normalScript = newSeq[byte](25)
    var opReturn = newSeq[byte](11)
    opReturn[0] = 0x6a'u8
    cb.outputs = @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: normalScript),
                   TxOut(value: Satoshi(0), scriptPubKey: opReturn)]
    cb.lockTime = 0
    var b: Block
    b.header.version = 2
    b.txs = @[cb]
    let r = computeBlockStats(b, 300'i32, 0'i64,
                              int64(getBlockSubsidy(300'i32, mainnetParams())), @[])
    # utxo_size_inc counts BOTH outputs; *_actual counts only the spendable one.
    let bothOuts = (txOutSize(25) + PerUtxo) + (txOutSize(11) + PerUtxo)
    check r["utxo_size_inc"].getBiggestInt() == bothOuts
    check r["utxo_size_inc_actual"].getBiggestInt() == (txOutSize(25) + PerUtxo)
    check r["utxo_increase"].getBiggestInt() == 2         # both outputs counted
    check r["utxo_increase_actual"].getBiggestInt() == 1  # only spendable
