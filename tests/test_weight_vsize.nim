## Tests for BIP-141 weight / vsize comprehensive audit (W76).
##
## Gates verified:
##   G1  weight formula: (baseSize * 3) + fullSize  ≡ (baseSize * 4) + witnessSize
##   G2  legacy tx weight = size * 4
##   G3  segwit tx weight = stripped*3 + total
##   G4  vsize = ceil(weight / 4) = (weight + 3) div 4
##   G5  sigop-adjusted vsize: ceil(max(weight, sigops*20) / 4)
##   G6  getSigOpsAdjustedWeight clips upward when sigops*20 > weight
##   G7  getVirtualTransactionSize(tx) convenience wrapper
##   G8  MIN_TRANSACTION_WEIGHT = 240 (4 * 60)
##   G9  MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40 (4 * 10)
##   G10 DefaultBytesPerSigop = 20
##   G11 MaxBlockTxns in compact_blocks = 4_000_000 / 40 = 100_000
##   G12 boundary: bytesPerSigop=0 disables sigop adjustment

import unittest2
import ../src/consensus/params
import ../src/consensus/validation
import ../src/primitives/[types, serialize]
import ../src/network/compact_blocks

suite "BIP-141 weight / vsize constants (W76)":

  test "WitnessScaleFactor = 4":
    check WitnessScaleFactor == 4

  test "MinTransactionWeight = 240  (consensus/consensus.h:23 — 4 * 60)":
    check MinTransactionWeight == 240

  test "MinSerializableTransactionWeight = 40  (consensus/consensus.h:24 — 4 * 10)":
    check MinSerializableTransactionWeight == 40

  test "DefaultBytesPerSigop = 20  (policy/policy.h:50)":
    check DefaultBytesPerSigop == 20

  test "MaxBlockTxns = 100_000  (MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TX_WEIGHT)":
    # blockencodings.cpp:64 uses MIN_SERIALIZABLE_TRANSACTION_WEIGHT (40), not
    # MIN_TRANSACTION_WEIGHT (240).  Previous value was 66_666 (div 60 mistake).
    check MaxBlockTxns == 100_000

suite "BIP-141 weight formula (W76)":

  proc makeLegacyTx(): Transaction =
    ## Minimal 1-in 1-out legacy (no witness) transaction.
    Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )

  proc makeSegwitTx(): Transaction =
    ## Minimal 1-in 1-out P2WPKH transaction with a witness stack.
    ## Witness contains a DER sig + compressed pubkey.
    let sig  = newSeq[byte](72)   # DER sig placeholder
    let pk   = newSeq[byte](33)   # compressed pubkey placeholder
    Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1_00000000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[@[sig, pk]],
      lockTime: 0
    )

  test "G2 legacy tx weight == size * 4":
    let tx       = makeLegacyTx()
    let baseSize = serializeLegacy(tx).len
    let fullSize = serialize(tx, includeWitness = true).len
    let weight   = calculateTransactionWeight(tx)
    # Legacy: baseSize == fullSize, so weight = (b*3)+f = b*4
    check baseSize == fullSize
    check weight   == baseSize * 4

  test "G3 segwit tx weight == (stripped*3) + total":
    let tx       = makeSegwitTx()
    let baseSize = serializeLegacy(tx).len
    let fullSize = serialize(tx, includeWitness = true).len
    let weight   = calculateTransactionWeight(tx)
    check fullSize > baseSize
    check weight == (baseSize * 3) + fullSize

  test "G3b segwit weight equivalence: stripped*4 + witnessSize":
    let tx        = makeSegwitTx()
    let baseSize  = serializeLegacy(tx).len
    let fullSize  = serialize(tx, includeWitness = true).len
    let witnessSize = fullSize - baseSize
    let w1 = calculateTransactionWeight(tx)         # (base*3)+full
    let w2 = (baseSize * 4) + witnessSize           # alternative formula
    check w1 == w2

suite "BIP-141 vsize (W76)":

  test "G4 vsize = ceil(weight / 4) for exact multiples":
    # weight = 400 → vsize = 100 (no rounding)
    check getVirtualTransactionSize(400'i64, 0) == 100

  test "G4 vsize = ceil(weight / 4) rounds up":
    # weight = 401 → vsize = ceil(401/4) = 101
    check getVirtualTransactionSize(401'i64, 0) == 101
    # weight = 403 → vsize = ceil(403/4) = 101
    check getVirtualTransactionSize(403'i64, 0) == 101
    # weight = 404 → vsize = 101
    check getVirtualTransactionSize(404'i64, 0) == 101
    # weight = 405 → vsize = 102
    check getVirtualTransactionSize(405'i64, 0) == 102

  test "G4 vsize formula: (weight + 3) div 4":
    for w in [1, 2, 3, 4, 100, 399, 400, 401, 1023, 1024, 399997, 400000]:
      let expected = (w + 3) div 4
      check getVirtualTransactionSize(int64(w), 0) == int64(expected)

  test "G5 sigop-adjusted vsize: no adjustment when weight dominates":
    # weight = 400, sigops = 1, bytes_per_sigop = 20 → sigops_weight = 20 < 400
    # adjusted = max(400, 20) = 400 → vsize = 100
    check getVirtualTransactionSize(400'i64, 1, 20) == 100

  test "G5 sigop-adjusted vsize: sigops dominate":
    # weight = 40, sigops = 5, bytes_per_sigop = 20 → sigops_weight = 100 > 40
    # adjusted = max(40, 100) = 100 → vsize = ceil(100/4) = 25
    check getVirtualTransactionSize(40'i64, 5, 20) == 25

  test "G5 sigop-adjusted vsize: tie (weight == sigops_weight)":
    # weight = 80, sigops = 4, bytes_per_sigop = 20 → 4*20 = 80 == 80
    # adjusted = 80 → vsize = 20
    check getVirtualTransactionSize(80'i64, 4, 20) == 20

  test "G6 getSigOpsAdjustedWeight: returns max(weight, sigops*bytes)":
    check getSigOpsAdjustedWeight(400'i64, 10'i64, 20) == 400  # weight wins
    check getSigOpsAdjustedWeight(100'i64, 10'i64, 20) == 200  # sigops win: 200
    check getSigOpsAdjustedWeight(200'i64, 10'i64, 20) == 200  # tie

  test "G12 bytesPerSigop=0 disables sigop adjustment":
    # policy/policy.cpp: when bytes_per_sigop == 0, Core passes 0 sigop cost
    # to GetVirtualTransactionSize which then just does ceil(weight/4).
    check getSigOpsAdjustedWeight(50'i64, 9999'i64, 0) == 50
    check getVirtualTransactionSize(50'i64, 9999'i64, 0) == 13  # ceil(50/4)=13

  test "G7 getVirtualTransactionSize(tx) convenience wrapper":
    ## A legacy tx vsize == ceil(weight/4) == ceil(baseSize*4/4) == baseSize.
    let tx     = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
      witnesses: @[],
      lockTime: 0
    )
    let baseSize = serializeLegacy(tx).len
    let weight   = calculateTransactionWeight(tx)
    # Legacy: weight = baseSize * 4
    check weight == baseSize * 4
    # vsize = ceil(weight / 4) = baseSize (exact)
    check getVirtualTransactionSize(tx) == int64(baseSize)

suite "BIP-141 MIN bounds (W76)":

  test "MinTransactionWeight < MaxBlockWeight":
    check MinTransactionWeight < MaxBlockWeight

  test "MinSerializableTransactionWeight < MinTransactionWeight":
    check MinSerializableTransactionWeight < MinTransactionWeight

  test "MAX_STANDARD_TX_WEIGHT boundary vsize = 100_000":
    # MAX_STANDARD_TX_WEIGHT = 400_000 WU → vsize = 100_000 vB (exact)
    let maxStdWt = 400_000
    check getVirtualTransactionSize(int64(maxStdWt), 0) == 100_000

  test "MaxBlockWeight boundary vsize = 1_000_000":
    check getVirtualTransactionSize(int64(MaxBlockWeight), 0) == 1_000_000
