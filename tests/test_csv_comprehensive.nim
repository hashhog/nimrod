## Comprehensive BIP-68 + BIP-112 + BIP-113 sequence-lock test suite.
## Covers all 21 gates from:
##   BIP-68  CalculateSequenceLocks (tx_verify.cpp:39-95)
##   BIP-112 OP_CHECKSEQUENCEVERIFY (interpreter.cpp:561-593, :1782-1826)
##   BIP-113 MTP as nLockTime cutoff (validation.cpp:4157, tx_verify.cpp:17-37)
##
## Gate numbering follows the audit order in the commit body.

import std/[options, tables]
import unittest2
import ../src/script/interpreter
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]
import ../src/storage/chainstate
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeTx(version: int32, inputs: seq[TxIn]): Transaction =
  Transaction(
    version: version,
    inputs: inputs,
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
    witnesses: @[],
    lockTime: 0
  )

proc makeInput(sequence: uint32, txidByte: uint8 = 1): TxIn =
  TxIn(
    prevOut: OutPoint(
      txid: TxId([txidByte, 0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      vout: 0
    ),
    scriptSig: @[],
    sequence: sequence
  )

proc getMtpSimple(h: int32): uint32 =
  if h < 0: 0'u32 else: uint32(h) * 600

## Build a scriptPubKey that pushes `n` as a script number then OP_CHECKSEQUENCEVERIFY.
## For n=0 we push OP_0; for n in 1..16 we use OP_1..OP_16.
proc csvScript(n: int): seq[byte] =
  var script: seq[byte]
  if n == 0:
    script.add(OP_0)
  elif n >= 1 and n <= 16:
    script.add(OP_1 + byte(n - 1))
  else:
    # Minimal push of little-endian encoded number
    var v = n
    var enc: seq[byte]
    while v > 0:
      enc.add(byte(v and 0xFF))
      v = v shr 8
    # Set sign bit if high bit of last byte is set
    if (enc[enc.len - 1] and 0x80) != 0:
      enc.add(0x00)
    script.add(byte(enc.len))
    script &= enc
  script.add(OP_CHECKSEQUENCEVERIFY)
  script

## Build a scriptPubKey with DISABLE_FLAG set (bits 31 set in pushed number).
## This encodes 0x80000001 as a 5-byte script number.
proc csvDisabledScript(): seq[byte] =
  # Encode 0x80000001 as minimal script number (little-endian, 5 bytes with sign)
  # 0x80000001 = [0x01, 0x00, 0x00, 0x80, 0x00] in little-endian with sign clear
  # Positive: [0x01, 0x00, 0x00, 0x80, 0x00] — MSB of last byte is 0
  # Actually 0x80000001 in little-endian bytes: 0x01, 0x00, 0x00, 0x80
  # Last byte 0x80 has high bit set → need extra zero byte for sign
  @[0x05'u8, 0x01, 0x00, 0x00, 0x80, 0x00, OP_CHECKSEQUENCEVERIFY]

## Eval a CSV script with a transaction and return the script error.
proc evalCsvScript(script: seq[byte], tx: Transaction, inputIndex: int,
                   flags: set[ScriptFlags]): ScriptError =
  var interp = newInterpreter(flags)
  let ctx = SigCheckContext(
    tx: tx,
    inputIndex: inputIndex,
    amount: Satoshi(0),
    scriptPubKey: script,
    sigVersion: sigBase,
    amounts: @[Satoshi(0)],
    scriptPubKeys: @[script],
    codesepPos: 0xFFFFFFFF'u32
  )
  # Push OP_TRUE first so the stack is non-empty before CSV opcode test
  # (CSV is a NOP-like: it doesn't consume the stack element, it just peeks)
  interp.eval(script, ctx)

# ---------------------------------------------------------------------------
# Gate 1 (BIP-68): version check — tx.version < 2 skips BIP68
# Core tx_verify.cpp:51
# ---------------------------------------------------------------------------
suite "BIP-68 gate 1: tx.version < 2 skips sequence locks":
  test "v1 tx has no sequence lock constraint even with small sequence":
    let params = regtestParams()
    let tx = makeTx(1, @[makeInput(5)])  # sequence=5 → 5-block lock if v2
    var prevHeights = @[int32(100)]
    let lock = calculateSequenceLocks(tx, prevHeights, 110, getMtpSimple, params)
    check lock.minHeight == -1
    check lock.minTime == -1

  test "v2 tx with sequence=5 produces height lock":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(5)])
    var prevHeights = @[int32(100)]
    let lock = calculateSequenceLocks(tx, prevHeights, 110, getMtpSimple, params)
    # minHeight = 100 + 5 - 1 = 104 (nLockTime semantics: last invalid)
    check lock.minHeight == 104
    check lock.minTime == -1

# ---------------------------------------------------------------------------
# Gate 2 (BIP-68): DISABLE_FLAG — input opts out; prevHeights[i] zeroed
# Core tx_verify.cpp:65-68
# ---------------------------------------------------------------------------
suite "BIP-68 gate 2: SEQUENCE_LOCKTIME_DISABLE_FLAG (bit 31) opts out":
  test "input with DISABLE_FLAG set contributes no constraint":
    let params = regtestParams()
    let seq = SEQUENCE_LOCKTIME_DISABLE_FLAG or 100'u32
    let tx = makeTx(2, @[makeInput(seq)])
    var prevHeights = @[int32(200)]
    let lock = calculateSequenceLocks(tx, prevHeights, 300, getMtpSimple, params)
    check lock.minHeight == -1
    check lock.minTime == -1
    # Bitcoin Core zeroes prevHeights[i] for disabled inputs
    check prevHeights[0] == 0

  test "SEQUENCE_FINAL (0xFFFFFFFF) has bit 31 set — treated as disabled":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(0xFFFFFFFF'u32)])
    var prevHeights = @[int32(50)]
    let lock = calculateSequenceLocks(tx, prevHeights, 100, getMtpSimple, params)
    check lock.minHeight == -1
    check lock.minTime == -1
    check prevHeights[0] == 0

# ---------------------------------------------------------------------------
# Gate 3 (BIP-68): TYPE_FLAG — bit 22 selects height (0) vs time (1)
# Core tx_verify.cpp:73
# ---------------------------------------------------------------------------
suite "BIP-68 gate 3: SEQUENCE_LOCKTIME_TYPE_FLAG (bit 22) selects domain":
  test "no TYPE_FLAG → height domain":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(3)])  # bit 22 clear → height
    var prevHeights = @[int32(10)]
    let lock = calculateSequenceLocks(tx, prevHeights, 20, getMtpSimple, params)
    check lock.minHeight == 12  # 10 + 3 - 1
    check lock.minTime == -1

  test "TYPE_FLAG set → time domain":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(SEQUENCE_LOCKTIME_TYPE_FLAG or 1)])
    var prevHeights = @[int32(10)]
    proc getMtp(h: int32): uint32 =
      if h == 9: 5000'u32 else: getMtpSimple(h)
    let lock = calculateSequenceLocks(tx, prevHeights, 20, getMtp, params)
    check lock.minHeight == -1
    # minTime = coinMtp + 1*512 - 1 = 5000 + 511 = 5511
    check lock.minTime == 5511

# ---------------------------------------------------------------------------
# Gate 4 (BIP-68): MTP of block prior to coin-containing block
# Core tx_verify.cpp:74 — GetAncestor(max(coinHeight-1, 0))->GetMedianTimePast()
# ---------------------------------------------------------------------------
suite "BIP-68 gate 4: MTP taken at max(coinHeight-1, 0)":
  test "coinHeight=0: clamps to height 0":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(SEQUENCE_LOCKTIME_TYPE_FLAG or 1)])
    var prevHeights = @[int32(0)]
    # max(0-1, 0) = 0 → getMtp(0) = 100
    proc getMtp(h: int32): uint32 =
      if h == 0: 100'u32 else: getMtpSimple(h)
    let lock = calculateSequenceLocks(tx, prevHeights, 5, getMtp, params)
    # coinMtp = getMtp(0) = 100, lockValue = 1*512 = 512
    # minTime = 100 + 512 - 1 = 611
    check lock.minTime == 611

  test "coinHeight=1: uses getMtp(0)":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(SEQUENCE_LOCKTIME_TYPE_FLAG or 2)])
    var prevHeights = @[int32(1)]
    proc getMtp(h: int32): uint32 =
      if h == 0: 200'u32 else: getMtpSimple(h)
    let lock = calculateSequenceLocks(tx, prevHeights, 10, getMtp, params)
    # coinMtp = getMtp(0) = 200, lockValue = 2*512 = 1024
    # minTime = 200 + 1024 - 1 = 1223
    check lock.minTime == 1223

# ---------------------------------------------------------------------------
# Gates 5-6 (BIP-68): time lock calculation and nLockTime semantics
# Core tx_verify.cpp:88 — nMinTime = max(nMinTime, coinMtp + lockValue - 1)
# ---------------------------------------------------------------------------
suite "BIP-68 gates 5-6: time lock value and nLockTime -1 adjustment":
  test "lockValue in seconds = (sequence & MASK) << GRANULARITY":
    let params = regtestParams()
    # sequence = TYPE_FLAG | 3 → 3 * 512 = 1536 seconds
    let tx = makeTx(2, @[makeInput(SEQUENCE_LOCKTIME_TYPE_FLAG or 3)])
    var prevHeights = @[int32(100)]
    proc getMtp(h: int32): uint32 =
      if h == 99: 10000'u32 else: getMtpSimple(h)
    let lock = calculateSequenceLocks(tx, prevHeights, 200, getMtp, params)
    # minTime = 10000 + 3*512 - 1 = 10000 + 1536 - 1 = 11535
    check lock.minTime == 11535

  test "maximum time lock: MASK=0xffff, 65535*512-1 added":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(SEQUENCE_LOCKTIME_TYPE_FLAG or 0xFFFF)])
    var prevHeights = @[int32(100)]
    proc getMtp(h: int32): uint32 =
      if h == 99: 1_000_000'u32 else: getMtpSimple(h)
    let lock = calculateSequenceLocks(tx, prevHeights, 200, getMtp, params)
    # 65535*512 = 33553920; minTime = 1000000 + 33553920 - 1 = 34553919
    check lock.minTime == 34553919

# ---------------------------------------------------------------------------
# Gate 7 (BIP-68): height lock nLockTime semantics
# Core tx_verify.cpp:90 — nMinHeight = max(nMinHeight, coinHeight + mask - 1)
# ---------------------------------------------------------------------------
suite "BIP-68 gate 7: height lock nLockTime -1 adjustment":
  test "sequence=1: minHeight = coinHeight + 1 - 1 = coinHeight":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(1)])
    var prevHeights = @[int32(50)]
    let lock = calculateSequenceLocks(tx, prevHeights, 100, getMtpSimple, params)
    # minHeight = 50 + 1 - 1 = 50
    check lock.minHeight == 50

  test "sequence=0: minHeight = coinHeight - 1 (satisfied immediately)":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(0)])
    var prevHeights = @[int32(50)]
    let lock = calculateSequenceLocks(tx, prevHeights, 50, getMtpSimple, params)
    # minHeight = 50 + 0 - 1 = 49; block 50 > 49 → satisfied
    check lock.minHeight == 49
    check checkSequenceLocks(lock, 50, 0) == true

  test "multiple inputs: maximum constraint wins":
    let params = regtestParams()
    let tx = makeTx(2, @[makeInput(3, 1), makeInput(20, 2)])
    var prevHeights = @[int32(100), int32(50)]
    let lock = calculateSequenceLocks(tx, prevHeights, 200, getMtpSimple, params)
    # Input 0: 100 + 3 - 1 = 102
    # Input 1: 50 + 20 - 1 = 69
    # max = 102
    check lock.minHeight == 102

# ---------------------------------------------------------------------------
# Gates 8-11 (EvaluateSequenceLocks):
# block.pprev, nBlockTime = pprev->GetMedianTimePast(), strict < comparisons
# Core tx_verify.cpp:97-105
# ---------------------------------------------------------------------------
suite "BIP-68 gates 8-11: EvaluateSequenceLocks strict-less-than semantics":
  test "blockHeight == minHeight + 1 satisfies (strict >)":
    let lock = SequenceLock(minHeight: 100, minTime: -1)
    check checkSequenceLocks(lock, 101, 0) == true

  test "blockHeight == minHeight fails (not strictly greater)":
    let lock = SequenceLock(minHeight: 100, minTime: -1)
    check checkSequenceLocks(lock, 100, 0) == false

  test "MTP == minTime fails (not strictly greater)":
    let lock = SequenceLock(minHeight: -1, minTime: 1000)
    check checkSequenceLocks(lock, 100, 1000) == false

  test "MTP == minTime + 1 satisfies":
    let lock = SequenceLock(minHeight: -1, minTime: 1000)
    check checkSequenceLocks(lock, 100, 1001) == true

  test "minHeight=-1 and minTime=-1: always satisfied (no constraint)":
    let lock = SequenceLock(minHeight: -1, minTime: -1)
    check checkSequenceLocks(lock, 0, 0) == true

  test "both constraints must be satisfied simultaneously":
    let lock = SequenceLock(minHeight: 100, minTime: 1000)
    check checkSequenceLocks(lock, 101, 1001) == true
    check checkSequenceLocks(lock, 101, 1000) == false  # time not satisfied
    check checkSequenceLocks(lock, 100, 1001) == false  # height not satisfied
    check checkSequenceLocks(lock, 100, 1000) == false  # neither satisfied

# ---------------------------------------------------------------------------
# Gate 12 (BIP-112 interpreter): negative sequence number → SCRIPT_ERR_NEGATIVE_LOCKTIME
# Core interpreter.cpp:579-580
# ---------------------------------------------------------------------------
suite "BIP-112 gate 12: negative sequence value fails":
  test "OP_1NEGATE OP_CHECKSEQUENCEVERIFY fails with seNegativeLocktime":
    # OP_1NEGATE pushes -1
    let script = @[OP_1NEGATE, OP_CHECKSEQUENCEVERIFY]
    let tx = makeTx(2, @[makeInput(1)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seNegativeLocktime

# ---------------------------------------------------------------------------
# Gate 13 (BIP-112 interpreter): DISABLE_FLAG in script number → NOP (pass)
# Core interpreter.cpp:585-586
# ---------------------------------------------------------------------------
suite "BIP-112 gate 13: DISABLE_FLAG in stack value makes CSV a NOP":
  test "CSV with DISABLE_FLAG in script operand passes even with v1 tx":
    # 0x80000001 = DISABLE_FLAG | 1; script encodes this as 5-byte push
    # Per BIP-112: if DISABLE_FLAG is set in the script number, CSV is NOP
    # Encode 0x80000001 as a 5-byte minimally-encoded script number
    # Little-endian: [0x01, 0x00, 0x00, 0x00, 0x80] — high bit of last byte
    # is 0x80 meaning negative; but we need positive. Use [0x01, 0x00, 0x00, 0x80, 0x00]
    # Wait: 0x80000001 = 2147483649. In script encoding, positive number:
    # little-endian [0x01, 0x00, 0x00, 0x80] — last byte 0x80 means sign bit set!
    # So we need 5 bytes: [0x01, 0x00, 0x00, 0x80, 0x00] where 0x00 is sign byte.
    let disabledSeq = SEQUENCE_LOCKTIME_DISABLE_FLAG or 1'u32  # 0x80000001
    # Minimal script-number encoding of 0x80000001:
    # Value = 2147483649; LE bytes = [0x01, 0x00, 0x00, 0x80], last byte 0x80 has MSB set
    # → append 0x00 to clear sign: [0x01, 0x00, 0x00, 0x80, 0x00] (5 bytes)
    let csvNum: seq[byte] = @[0x01'u8, 0x00, 0x00, 0x80, 0x00]
    let script = @[0x05'u8] & csvNum & @[OP_CHECKSEQUENCEVERIFY]
    # Use v1 tx; if CSV weren't NOP it would fail (v1 → seUnsatisfiedLocktime)
    let tx = makeTx(1, @[makeInput(0xFFFFFFFF'u32)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    # CSV is NOP because DISABLE_FLAG is set; stack has [0x80000001 bytes] on it
    check err == seOk

# ---------------------------------------------------------------------------
# Gate 14 (BIP-112 interpreter): tx.version < 2 → seUnsatisfiedLocktime
# Core interpreter.cpp:1790-1791 (CheckSequence)
# ---------------------------------------------------------------------------
suite "BIP-112 gate 14: tx.version < 2 fails CSV":
  test "v1 tx with sequence=5 and CSV(5) fails":
    let script = csvScript(5)
    let tx = makeTx(1, @[makeInput(5)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seUnsatisfiedLocktime

  test "v2 tx with sequence=5 and CSV(5) passes":
    let script = csvScript(5)
    let tx = makeTx(2, @[makeInput(5)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

# ---------------------------------------------------------------------------
# Gate 15 (BIP-112 interpreter): txSequence has DISABLE_FLAG → fails
# Core interpreter.cpp:1797-1798 (CheckSequence)
# ---------------------------------------------------------------------------
suite "BIP-112 gate 15: tx input DISABLE_FLAG in nSequence causes CSV fail":
  test "txSequence with bit 31 set fails CSV even if value matches":
    let script = csvScript(5)
    # tx input sequence has DISABLE_FLAG set
    let txSeq = SEQUENCE_LOCKTIME_DISABLE_FLAG or 5'u32
    let tx = makeTx(2, @[makeInput(txSeq)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seUnsatisfiedLocktime

# ---------------------------------------------------------------------------
# Gates 16-19 (BIP-112 interpreter): type consistency check
# Core interpreter.cpp:1802-1818 — masked comparison, type must match
# ---------------------------------------------------------------------------
suite "BIP-112 gates 16-19: type consistency (height vs time domain)":
  test "CSV requires height, tx sequence has time → mismatch fails":
    # Script pushes 1 (no TYPE_FLAG → height domain)
    # Tx sequence has TYPE_FLAG → time domain
    let script = csvScript(1)  # height-domain
    let txSeq = SEQUENCE_LOCKTIME_TYPE_FLAG or 1'u32  # time-domain
    let tx = makeTx(2, @[makeInput(txSeq)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seUnsatisfiedLocktime

  test "CSV requires time, tx sequence has height → mismatch fails":
    # Script pushes with TYPE_FLAG (time domain)
    # Encode TYPE_FLAG | 1 as script number: 0x00400001
    # LE: [0x01, 0x00, 0x40] — high bit of 0x40 is clear → 3 bytes is fine
    let csvNum: seq[byte] = @[0x01'u8, 0x00, 0x40]
    let script = @[0x03'u8] & csvNum & @[OP_CHECKSEQUENCEVERIFY]
    let tx = makeTx(2, @[makeInput(1)])  # height domain
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seUnsatisfiedLocktime

  test "both height domain: passes when txSeq >= scriptSeq":
    let script = csvScript(3)  # requires 3 blocks
    let tx = makeTx(2, @[makeInput(3)])  # sequence = 3
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

  test "both time domain: passes when txSeq >= scriptSeq":
    # Script: TYPE_FLAG | 2; encode 0x00400002
    let csvNum: seq[byte] = @[0x02'u8, 0x00, 0x40]
    let script = @[0x03'u8] & csvNum & @[OP_CHECKSEQUENCEVERIFY]
    let txSeq = SEQUENCE_LOCKTIME_TYPE_FLAG or 3'u32  # time, value=3 >= 2
    let tx = makeTx(2, @[makeInput(txSeq)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

# ---------------------------------------------------------------------------
# Gate 20 (BIP-112 interpreter): value comparison — scriptSeq <= txSeq
# Core interpreter.cpp:1822-1823
# ---------------------------------------------------------------------------
suite "BIP-112 gate 20: masked value comparison (scriptSeq <= txSeq)":
  test "script requires 10, txSeq = 9 → fails":
    let script = csvScript(10)
    let tx = makeTx(2, @[makeInput(9)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seUnsatisfiedLocktime

  test "script requires 10, txSeq = 10 → passes":
    let script = csvScript(10)
    let tx = makeTx(2, @[makeInput(10)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

  test "script requires 10, txSeq = 100 → passes (txSeq > scriptSeq)":
    let script = csvScript(10)
    let tx = makeTx(2, @[makeInput(100)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

  test "CSV(0): always satisfied for v2 with any non-disabled sequence":
    let script = csvScript(0)
    let tx = makeTx(2, @[makeInput(0)])
    var interp = newInterpreter({sfCheckSequenceVerify})
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seOk

# ---------------------------------------------------------------------------
# Gate 21 (BIP-113): lockTimeCutoff = MTP when CSV is active
# Core validation.cpp:4157 (ContextualCheckBlock)
# ---------------------------------------------------------------------------
suite "BIP-113 gate 21: IsFinalTx uses MTP as lockTimeCutoff when CSV active":
  test "IsFinalTx with time lockTime uses MTP cutoff, not header timestamp":
    # lockTime = 500_000_100 (time-based, above LOCKTIME_THRESHOLD)
    # MTP = 500_000_000 < lockTime → non-final (header timestamp = 500_000_200 > lockTime)
    # If we used header timestamp, it would appear final. MTP is the correct cutoff.
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: default(TxId), vout: 0),
        scriptSig: @[], sequence: 0
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 500_000_100'u32
    )
    let blockHeight = 100'u32
    let mtp = 500_000_000'u32  # MTP < lockTime → not final with MTP
    let headerTimestamp = 500_000_200'u32  # header > lockTime → would be final
    check not isFinalTx(tx, blockHeight, mtp)
    check isFinalTx(tx, blockHeight, headerTimestamp)

  test "IsFinalTx with time lockTime: satisfied when MTP > lockTime":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: default(TxId), vout: 0),
        scriptSig: @[], sequence: 0
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 500_000_000'u32
    )
    let mtp = 500_000_001'u32  # MTP > lockTime → final
    check isFinalTx(tx, 100'u32, mtp)

  test "IsFinalTx: SEQUENCE_FINAL overrides any unsatisfied lockTime":
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: default(TxId), vout: 0),
        scriptSig: @[], sequence: 0xFFFFFFFF'u32  # SEQUENCE_FINAL
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 999_999_999'u32  # far future
    )
    # Even though lockTime is unsatisfied, all inputs have SEQUENCE_FINAL → final
    check isFinalTx(tx, 100'u32, 500_000_000'u32)

# ---------------------------------------------------------------------------
# NOP behavior when sfCheckSequenceVerify flag is not set (BIP-112)
# Core interpreter.cpp:563-566
# ---------------------------------------------------------------------------
suite "BIP-112 NOP behavior without sfCheckSequenceVerify flag":
  test "CSV without sfCheckSequenceVerify flag is a NOP":
    # Without the flag, CSV behaves as NOP3 — stack unchanged, execution continues
    let script = csvScript(99999)  # Would fail if enforced
    let tx = makeTx(1, @[makeInput(0)])  # v1, sequence=0 → would fail if enforced
    var interp = newInterpreter({})  # no sfCheckSequenceVerify
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    # NOP: CSV does nothing, stack has [99999 bytes] on it, execution succeeds
    check err == seOk

  test "CSV as NOP with sfDiscourageUpgradableNops → seDiscourageUpgradableNops":
    let script = csvScript(1)
    let tx = makeTx(1, @[makeInput(0)])
    var interp = newInterpreter({sfDiscourageUpgradableNops})  # no sfCheckSequenceVerify
    let ctx = SigCheckContext(
      tx: tx, inputIndex: 0, amount: Satoshi(0),
      scriptPubKey: script, sigVersion: sigBase,
      amounts: @[Satoshi(0)], scriptPubKeys: @[script],
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(script, ctx)
    check err == seDiscourageUpgradableNops

# ---------------------------------------------------------------------------
# BIP-68 block-level activation: no enforcement before csvHeight
# Core validation.cpp:2480-2482
# ---------------------------------------------------------------------------
suite "BIP-68 block activation: sequence locks not enforced before csvHeight":
  test "mainnet: no CSV flag before height 419328":
    let params = mainnetParams()
    check sfCheckSequenceVerify notin getBlockScriptFlags(419327, params)

  test "mainnet: CSV flag at height 419328":
    let params = mainnetParams()
    check sfCheckSequenceVerify in getBlockScriptFlags(419328, params)

  test "testnet4: CSV flag at height 1 (csvHeight=1)":
    let params = testnet4Params()
    check params.csvHeight == 1
    check sfCheckSequenceVerify notin getBlockScriptFlags(0, params)
    check sfCheckSequenceVerify in getBlockScriptFlags(1, params)

  test "regtest: CSV flag at height 1 (csvHeight=1)":
    let params = regtestParams()
    check params.csvHeight == 1
    check sfCheckSequenceVerify notin getBlockScriptFlags(0, params)
    check sfCheckSequenceVerify in getBlockScriptFlags(1, params)

# ---------------------------------------------------------------------------
# checkSequenceLocksForTx: coinbase always passes
# ---------------------------------------------------------------------------
suite "BIP-68 coinbase bypass in checkSequenceLocksForTx":
  test "coinbase tx with any sequence always passes":
    let params = regtestParams()
    let coinbase = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 1  # Would fail BIP68 if evaluated (UTXO height 0, lock 1 block)
      )],
      outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0
    )
    proc lookup(op: OutPoint): Option[UtxoEntry] = none(UtxoEntry)
    proc getMtp(h: int32): uint32 = getMtpSimple(h)
    let res = checkSequenceLocksForTx(coinbase, lookup, 1, 0, getMtp, params)
    check res.isOk

# ---------------------------------------------------------------------------
# BIP-68 intraBlockUtxos: spending output from same block
# ---------------------------------------------------------------------------
suite "BIP-68 intra-block UTXO height is current block height":
  test "intra-block UTXO treated as mined at current block height":
    let params = regtestParams()
    let coinTxid = TxId([0x42'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    let spendTx = makeTx(2, @[TxIn(
      prevOut: OutPoint(txid: coinTxid, vout: 0),
      scriptSig: @[], sequence: 0  # Lock=0: minHeight = coinHeight - 1
    )])
    let blockHeight = int32(500)
    # Intra-block UTXO at height 500
    var intraBlock = initTable[string, UtxoEntry]()
    let key = $array[32, byte](coinTxid) & ":0"
    intraBlock[key] = UtxoEntry(
      output: TxOut(value: Satoshi(1000), scriptPubKey: @[]),
      height: blockHeight, isCoinbase: false
    )
    proc lookup(op: OutPoint): Option[UtxoEntry] = none(UtxoEntry)
    proc getMtp(h: int32): uint32 = getMtpSimple(h)
    # sequence=0: minHeight = 500 + 0 - 1 = 499; block 500 > 499 → satisfied
    let res = checkSequenceLocksForTx(spendTx, lookup, blockHeight, 0, getMtp, params, intraBlock)
    check res.isOk
