## IsFinalTx consensus rule tests
## Reference: Bitcoin Core ContextualCheckBlock validation.cpp:4146

import unittest2
import ../src/primitives/types
import ../src/consensus/validation

const
  HEIGHT = 100'u32
  MTP = 900_000_001'u32  # above LOCKTIME_THRESHOLD, irrelevant for height-based tests
  SEQUENCE_FINAL = 0xFFFF_FFFF'u32

proc makeTx(lockTime: uint32, seqs: seq[uint32]): Transaction =
  var inputs: seq[TxIn]
  for s in seqs:
    inputs.add(TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: s
    ))
  Transaction(
    version: 1,
    inputs: inputs,
    outputs: @[],
    witnesses: @[],
    lockTime: lockTime
  )

suite "isFinalTx (Core ContextualCheckBlock parity)":
  test "zero locktime always final":
    let tx = makeTx(0'u32, @[0'u32])
    check isFinalTx(tx, HEIGHT, MTP)

  test "height-based locktime satisfied":
    # lockTime=100 < blockHeight=101 → satisfied
    let tx = makeTx(100'u32, @[0'u32])
    check isFinalTx(tx, 101'u32, MTP)

  test "height-based locktime not satisfied, non-final sequence":
    # lockTime=200 >= blockHeight=100 → not satisfied; sequence != FINAL → non-final
    let tx = makeTx(200'u32, @[1'u32])
    check not isFinalTx(tx, HEIGHT, MTP)

  test "SEQUENCE_FINAL overrides unsatisfied locktime":
    let tx = makeTx(999_999_999'u32, @[SEQUENCE_FINAL])
    check isFinalTx(tx, HEIGHT, MTP)

  test "mixed inputs: one non-SEQUENCE_FINAL → non-final":
    let tx = makeTx(500'u32, @[SEQUENCE_FINAL, 0'u32])
    check not isFinalTx(tx, HEIGHT, MTP)

  test "time-based locktime satisfied":
    # lockTime=500_000_001 (>= LOCKTIME_THRESHOLD) compared against MTP
    let tx = makeTx(500_000_001'u32, @[0'u32])
    check isFinalTx(tx, HEIGHT, 500_000_002'u32)

  test "time-based locktime not satisfied, non-final sequence → non-final":
    let tx = makeTx(500_000_002'u32, @[1'u32])
    check not isFinalTx(tx, HEIGHT, 500_000_001'u32)

suite "checkBlockLocktime (IsFinalTx batch check)":
  test "block with non-final tx rejected":
    # lockTime=200 >= height=100, sequence != FINAL → non-final
    let coinbase = makeTx(0'u32, @[SEQUENCE_FINAL])
    let nonFinal = makeTx(200'u32, @[0'u32])
    let blk = Block(
      header: BlockHeader(timestamp: 1_700_000_000'u32),
      txs: @[coinbase, nonFinal]
    )
    let result = checkBlockLocktime(blk, 100'u32, 1_699_999_000'u32)
    check not result.isOk
    check result.error == veNonFinalTx

  test "block with all final txs accepted":
    let coinbase = makeTx(0'u32, @[SEQUENCE_FINAL])
    let finalTx = makeTx(50'u32, @[0'u32])  # 50 < 101 → satisfied
    let blk = Block(
      header: BlockHeader(timestamp: 1_700_000_000'u32),
      txs: @[coinbase, finalTx]
    )
    let result = checkBlockLocktime(blk, 101'u32, 1_699_999_000'u32)
    check result.isOk
