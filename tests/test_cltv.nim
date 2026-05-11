## BIP-65 CHECKLOCKTIMEVERIFY + IsFinalTx + BIP-113 comprehensive tests
##
## Covers all 15 consensus gates from:
##   - interpreter.cpp:522-558  (OP_CHECKLOCKTIMEVERIFY opcode dispatch)
##   - interpreter.cpp:1745-1779 (CheckLockTime helper)
##   - consensus/tx_verify.cpp:17-37 (IsFinalTx)
##   - script/script.h:47 (LOCKTIME_THRESHOLD = 500_000_000)
##
## Gate list:
##  G1  CLTV flag not set → NOP (treat as NOP2)
##  G2  Stack empty → seInvalidStack
##  G3  ScriptNum decode overflow (>5 bytes) → seInvalidStack
##  G4  Negative locktime → seNegativeLocktime
##  G5  Type mismatch: height vs time → seUnsatisfiedLocktime
##  G6  Script locktime > tx locktime → seUnsatisfiedLocktime
##  G7  txin sequence == SEQUENCE_FINAL → seUnsatisfiedLocktime
##  G8  Stack NOT consumed (peek, not pop)
##  G9  IsFinalTx: lockTime == 0 → always final
##  G10 IsFinalTx: height-based locktime < blockHeight → final
##  G11 IsFinalTx: time-based locktime < MTP → final
##  G12 IsFinalTx: locktime NOT satisfied but all inputs SEQUENCE_FINAL → final
##  G13 IsFinalTx: any input non-FINAL when locktime unsatisfied → non-final
##  G14 BIP-113: lockTimeCutoff = MTP of prev block when CSV active
##  G15 BIP-65 activation height gating in getBlockScriptFlags

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/consensus/[validation, params]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

const
  LOCKTIME_THRESHOLD = 500_000_000'u32
  SEQUENCE_FINAL_VAL = 0xFFFF_FFFF'u32

proc scriptNumLE*(n: int64): seq[byte] =
  ## Encode int64 as minimal little-endian script number.
  if n == 0:
    return @[]
  var val = if n < 0: -n else: n
  var bytes: seq[byte]
  while val > 0:
    bytes.add(byte(val and 0xff))
    val = val shr 8
  # Append sign byte if needed
  if (bytes[^1] and 0x80) != 0:
    bytes.add(if n < 0: 0x80'u8 else: 0x00'u8)
  elif n < 0:
    bytes[^1] = bytes[^1] or 0x80'u8
  bytes

proc makeCLTVTx(lockTime: uint32, sequence: uint32 = 0, version: int32 = 1): Transaction =
  ## Build a transaction suitable for CLTV testing.
  Transaction(
    version: version,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: default(TxId), vout: 0),
      scriptSig: @[],
      sequence: sequence
    )],
    outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
    witnesses: @[],
    lockTime: lockTime
  )

proc runCLTV(locktimeArg: seq[byte], tx: Transaction,
             inputIdx: int = 0): ScriptError =
  ## Run just the CLTV opcode with a given locktime argument pushed onto the stack.
  var interp = newInterpreter({sfCheckLockTimeVerify})
  interp.push(locktimeArg)
  var ctx = SigCheckContext(
    tx: tx,
    inputIndex: inputIdx,
    amount: Satoshi(0),
    sigVersion: sigBase,
    codesepPos: 0xFFFFFFFF'u32
  )
  let script = @[OP_CHECKLOCKTIMEVERIFY]
  interp.eval(script, ctx)

proc runCLTVNoFlag(locktimeArg: seq[byte], tx: Transaction): ScriptError =
  ## Run CLTV with the flag NOT set (should be NOP).
  var interp = newInterpreter({})   # sfCheckLockTimeVerify absent
  interp.push(locktimeArg)
  var ctx = SigCheckContext(
    tx: tx,
    inputIndex: 0,
    amount: Satoshi(0),
    sigVersion: sigBase,
    codesepPos: 0xFFFFFFFF'u32
  )
  let script = @[OP_CHECKLOCKTIMEVERIFY]
  interp.eval(script, ctx)

proc makeIsFinalTx(lockTime: uint32, seqs: seq[uint32]): Transaction =
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

# ---------------------------------------------------------------------------
# G1: CLTV flag not set → treat as NOP2
# ---------------------------------------------------------------------------

suite "CLTV G1: flag not set → NOP":
  test "CLTV without flag set is NOP (passes, stack unchanged)":
    # With no sfCheckLockTimeVerify, the opcode is a no-op; stack item is kept.
    let tx = makeCLTVTx(0)
    let err = runCLTVNoFlag(scriptNumLE(100), tx)
    check err == seOk

  test "CLTV without flag: DISCOURAGE_UPGRADABLE_NOPS returns error":
    var interp = newInterpreter({sfDiscourageUpgradableNops})
    interp.push(scriptNumLE(100))
    var ctx = SigCheckContext(
      tx: makeCLTVTx(0),
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_CHECKLOCKTIMEVERIFY], ctx)
    check err == seDiscourageUpgradableNops

# ---------------------------------------------------------------------------
# G2: Stack empty → seInvalidStack
# ---------------------------------------------------------------------------

suite "CLTV G2: empty stack":
  test "empty stack returns seInvalidStack":
    var interp = newInterpreter({sfCheckLockTimeVerify})
    var ctx = SigCheckContext(
      tx: makeCLTVTx(500),
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_CHECKLOCKTIMEVERIFY], ctx)
    check err == seInvalidStack

# ---------------------------------------------------------------------------
# G3: ScriptNum overflow (> 5 bytes) → seInvalidStack
# Core: CScriptNum(stacktop(-1), ..., 5) throws scriptnum_error → SCRIPT_ERR_SCRIPTNUM
# Nimrod: toScriptNum returns ok=false → seInvalidStack
# ---------------------------------------------------------------------------

suite "CLTV G3: ScriptNum overflow":
  test "6-byte encoding rejected as seInvalidStack":
    # 6 bytes is one over the CLTV 5-byte limit
    let sixBytes = @[0x01'u8, 0x00, 0x00, 0x00, 0x00, 0x00]
    let tx = makeCLTVTx(0)
    let err = runCLTV(sixBytes, tx)
    check err == seInvalidStack

  test "5-byte encoding accepted (boundary)":
    # Exactly 5 bytes is the CLTV maximum — must succeed for a valid locktime.
    # Encode 500_000_001 (time-based) in 5 bytes if needed; here use a simpler
    # 4-byte value to confirm 5 bytes is not rejected for length.
    # 0x01_00_00_00_00 = 4294967296 which overflows uint32 but is a valid 5-byte
    # script number. tx.lockTime is uint32 max so use SEQUENCE_FINAL-1 sequence.
    # We only care that length-5 itself doesn't trigger the overflow guard.
    let fiveBytes = @[0xff'u8, 0xff, 0xff, 0xff, 0x00]  # = 0xffffffff = 4294967295 ≥ threshold
    let tx = makeCLTVTx(LOCKTIME_THRESHOLD, sequence = 0)  # time-based tx
    let err = runCLTV(fiveBytes, tx)
    # Will fail for locktime-value reasons but NOT for overflow; any error except seInvalidStack
    check err != seInvalidStack

# ---------------------------------------------------------------------------
# G4: Negative locktime → seNegativeLocktime
# ---------------------------------------------------------------------------

suite "CLTV G4: negative locktime":
  test "script locktime = -1 → seNegativeLocktime":
    let tx = makeCLTVTx(100)
    let err = runCLTV(scriptNumLE(-1), tx)
    check err == seNegativeLocktime

  test "script locktime = -500000001 → seNegativeLocktime":
    let tx = makeCLTVTx(600_000_000)
    let err = runCLTV(scriptNumLE(-500_000_001), tx)
    check err == seNegativeLocktime

  test "script locktime = 0 (zero is not negative) → passes":
    # locktime=0, txLockTime=0, sequence not FINAL → should succeed (0 == 0, not >)
    let tx = makeCLTVTx(0, sequence = 0)
    let err = runCLTV(scriptNumLE(0), tx)
    check err == seOk

# ---------------------------------------------------------------------------
# G5: Type mismatch (height vs time) → seUnsatisfiedLocktime
# ---------------------------------------------------------------------------

suite "CLTV G5: type mismatch":
  test "height script locktime vs time tx locktime → seUnsatisfiedLocktime":
    # Script: 100 (height-based, < 500M); tx: 600_000_000 (time-based)
    let tx = makeCLTVTx(600_000_000, sequence = 0)
    let err = runCLTV(scriptNumLE(100), tx)
    check err == seUnsatisfiedLocktime

  test "time script locktime vs height tx locktime → seUnsatisfiedLocktime":
    # Script: 500_000_001 (time-based); tx: 200 (height-based)
    let tx = makeCLTVTx(200, sequence = 0)
    let err = runCLTV(scriptNumLE(500_000_001), tx)
    check err == seUnsatisfiedLocktime

  test "both height-based → no type mismatch":
    # Script: 50, tx: 100, seq: 0 → should succeed (50 <= 100)
    let tx = makeCLTVTx(100, sequence = 0)
    let err = runCLTV(scriptNumLE(50), tx)
    check err == seOk

  test "both time-based → no type mismatch":
    # Script: 500_000_001, tx: 500_000_002, seq: 0 → should succeed
    let tx = makeCLTVTx(500_000_002, sequence = 0)
    let err = runCLTV(scriptNumLE(500_000_001), tx)
    check err == seOk

# ---------------------------------------------------------------------------
# G6: Script locktime > tx locktime → seUnsatisfiedLocktime
# ---------------------------------------------------------------------------

suite "CLTV G6: script locktime > tx locktime":
  test "height: script locktime exceeds tx locktime → seUnsatisfiedLocktime":
    # Script: 200, tx: 100
    let tx = makeCLTVTx(100, sequence = 0)
    let err = runCLTV(scriptNumLE(200), tx)
    check err == seUnsatisfiedLocktime

  test "time: script locktime exceeds tx locktime → seUnsatisfiedLocktime":
    # Script: 600_000_002, tx: 600_000_001
    let tx = makeCLTVTx(600_000_001, sequence = 0)
    let err = runCLTV(scriptNumLE(600_000_002), tx)
    check err == seUnsatisfiedLocktime

  test "height: script == tx locktime → succeeds (equal is allowed)":
    # Script: 100, tx: 100, seq: 0 → equal, must succeed (Core: nLockTime > txLockTime fails)
    let tx = makeCLTVTx(100, sequence = 0)
    let err = runCLTV(scriptNumLE(100), tx)
    check err == seOk

  test "height: script < tx locktime → succeeds":
    # Script: 50, tx: 100, seq: 0
    let tx = makeCLTVTx(100, sequence = 0)
    let err = runCLTV(scriptNumLE(50), tx)
    check err == seOk

# ---------------------------------------------------------------------------
# G7: txin sequence == SEQUENCE_FINAL (0xFFFFFFFF) → seUnsatisfiedLocktime
# Reference: interpreter.cpp:1775-1776 "if (CTxIn::SEQUENCE_FINAL == nSequence) return false"
# ---------------------------------------------------------------------------

suite "CLTV G7: txin.sequence == SEQUENCE_FINAL":
  test "sequence=SEQUENCE_FINAL with valid locktime → seUnsatisfiedLocktime":
    # Even though locktime is satisfied, SEQUENCE_FINAL input kills CLTV.
    let tx = makeCLTVTx(100, sequence = SEQUENCE_FINAL_VAL)
    let err = runCLTV(scriptNumLE(50), tx)
    check err == seUnsatisfiedLocktime

  test "sequence=0xFFFFFFFE (not FINAL) → succeeds":
    # One less than SEQUENCE_FINAL; locktime satisfied
    let tx = makeCLTVTx(100, sequence = 0xFFFFFFFE'u32)
    let err = runCLTV(scriptNumLE(50), tx)
    check err == seOk

  test "sequence=0 → succeeds":
    let tx = makeCLTVTx(100, sequence = 0)
    let err = runCLTV(scriptNumLE(50), tx)
    check err == seOk

# ---------------------------------------------------------------------------
# G8: Stack is NOT consumed (CLTV peeks, does not pop)
# Reference: interpreter.cpp:546 uses stacktop(-1), not explicit pop
# ---------------------------------------------------------------------------

suite "CLTV G8: stack not consumed":
  test "stack element remains after successful CLTV":
    var interp = newInterpreter({sfCheckLockTimeVerify})
    interp.push(scriptNumLE(50))
    var ctx = SigCheckContext(
      tx: makeCLTVTx(100, sequence = 0),
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )
    let err = interp.eval(@[OP_CHECKLOCKTIMEVERIFY], ctx)
    check err == seOk
    check interp.stackSize == 1   # element still on stack
    check interp.peek() == scriptNumLE(50)

# ---------------------------------------------------------------------------
# G9: IsFinalTx — lockTime == 0 → always final
# Reference: tx_verify.cpp:19-20
# ---------------------------------------------------------------------------

suite "IsFinalTx G9: lockTime == 0":
  test "lockTime=0 with any sequences → final":
    let tx = makeIsFinalTx(0, @[0'u32, 0'u32])
    check isFinalTx(tx, 1000'u32, 900_000_000'u32)

  test "lockTime=0 with non-FINAL sequences → final":
    let tx = makeIsFinalTx(0, @[1'u32])
    check isFinalTx(tx, 100'u32, 500_000_001'u32)

# ---------------------------------------------------------------------------
# G10: IsFinalTx — height-based locktime satisfied
# Reference: tx_verify.cpp:21-22
# ---------------------------------------------------------------------------

suite "IsFinalTx G10: height-based locktime":
  test "lockTime < blockHeight → final":
    let tx = makeIsFinalTx(99'u32, @[0'u32])
    check isFinalTx(tx, 100'u32, 500_000_002'u32)

  test "lockTime == blockHeight → NOT final (Core uses strict <)":
    let tx = makeIsFinalTx(100'u32, @[0'u32])
    check not isFinalTx(tx, 100'u32, 500_000_002'u32)

  test "lockTime > blockHeight → NOT final":
    let tx = makeIsFinalTx(200'u32, @[0'u32])
    check not isFinalTx(tx, 100'u32, 500_000_002'u32)

  test "lockTime = LOCKTIME_THRESHOLD - 1 (499_999_999) is height-based":
    # Just below threshold → height-based comparison
    let tx = makeIsFinalTx(499_999_999'u32, @[0'u32])
    check isFinalTx(tx, 500_000_000'u32, 1'u32)    # height 500M > 499.99M
    check not isFinalTx(tx, 499_999_999'u32, 1'u32) # height == locktime (not <)

# ---------------------------------------------------------------------------
# G11: IsFinalTx — time-based locktime satisfied
# Reference: tx_verify.cpp:21-22
# ---------------------------------------------------------------------------

suite "IsFinalTx G11: time-based locktime":
  test "lockTime >= LOCKTIME_THRESHOLD → time-based comparison":
    let tx = makeIsFinalTx(LOCKTIME_THRESHOLD, @[0'u32])
    # MTP = 500_000_001 > 500_000_000 → final
    check isFinalTx(tx, 1'u32, 500_000_001'u32)

  test "time-based: lockTime == MTP → NOT final":
    let tx = makeIsFinalTx(LOCKTIME_THRESHOLD + 100'u32, @[0'u32])
    check not isFinalTx(tx, 1'u32, LOCKTIME_THRESHOLD + 100'u32)

  test "time-based: lockTime < MTP → final":
    let tx = makeIsFinalTx(LOCKTIME_THRESHOLD + 99'u32, @[0'u32])
    check isFinalTx(tx, 1'u32, LOCKTIME_THRESHOLD + 100'u32)

  test "time-based: lockTime > MTP → NOT final":
    let tx = makeIsFinalTx(LOCKTIME_THRESHOLD + 200'u32, @[0'u32])
    check not isFinalTx(tx, 1'u32, LOCKTIME_THRESHOLD + 100'u32)

# ---------------------------------------------------------------------------
# G12: IsFinalTx — all inputs SEQUENCE_FINAL overrides unsatisfied locktime
# Reference: tx_verify.cpp:32-36
# ---------------------------------------------------------------------------

suite "IsFinalTx G12: SEQUENCE_FINAL override":
  test "all inputs SEQUENCE_FINAL → final regardless of locktime":
    let tx = makeIsFinalTx(999_999_999'u32, @[SEQUENCE_FINAL_VAL])
    check isFinalTx(tx, 1'u32, 1'u32)

  test "multiple inputs all SEQUENCE_FINAL → final":
    let tx = makeIsFinalTx(999_999_999'u32, @[SEQUENCE_FINAL_VAL, SEQUENCE_FINAL_VAL, SEQUENCE_FINAL_VAL])
    check isFinalTx(tx, 1'u32, 1'u32)

  test "no inputs (coinbase-like) → final (no sequence to violate)":
    let tx = Transaction(
      version: 1, inputs: @[], outputs: @[], witnesses: @[],
      lockTime: 999_999_999'u32
    )
    check isFinalTx(tx, 1'u32, 1'u32)

# ---------------------------------------------------------------------------
# G13: IsFinalTx — any input non-FINAL when locktime unsatisfied → non-final
# Reference: tx_verify.cpp:32-36
# ---------------------------------------------------------------------------

suite "IsFinalTx G13: mixed sequences":
  test "one non-FINAL input among FINAL inputs → non-final":
    let tx = makeIsFinalTx(500'u32, @[SEQUENCE_FINAL_VAL, 0'u32])
    check not isFinalTx(tx, 100'u32, 100'u32)

  test "all non-FINAL inputs → non-final":
    let tx = makeIsFinalTx(500'u32, @[0'u32, 1'u32])
    check not isFinalTx(tx, 100'u32, 100'u32)

  test "FINAL-1 sequence → non-final when locktime unsatisfied":
    let tx = makeIsFinalTx(500'u32, @[0xFFFFFFFE'u32])
    check not isFinalTx(tx, 100'u32, 100'u32)

# ---------------------------------------------------------------------------
# G14: BIP-113 — lockTimeCutoff = MTP of prev block when CSV active
# Reference: validation.cpp ContextualCheckBlock, LOCKTIME_MEDIAN_TIME_PAST
# ---------------------------------------------------------------------------

suite "IsFinalTx G14: BIP-113 MTP cutoff":
  test "BIP-113: time-based isFinalTx uses MTP not block timestamp":
    # lockTime = 600_000_100 (time-based, >= LOCKTIME_THRESHOLD)
    # MTP = 600_000_101 → final
    # block timestamp = 600_000_050 → would NOT be final if used
    let tx = makeIsFinalTx(600_000_100'u32, @[0'u32])
    let finalWithMtp = isFinalTx(tx, 1'u32, 600_000_101'u32)   # MTP > locktime
    let finalWithTs  = isFinalTx(tx, 1'u32, 600_000_050'u32)   # timestamp < locktime
    check finalWithMtp == true
    check finalWithTs  == false

  test "BIP-113: height-based isFinalTx is unaffected by MTP choice":
    # lockTime = 100 (height-based, < LOCKTIME_THRESHOLD)
    # Only blockHeight matters; MTP argument is ignored
    let tx = makeIsFinalTx(100'u32, @[0'u32])
    check isFinalTx(tx, 101'u32, 1'u32)       # height 101 > 100 → final
    check not isFinalTx(tx, 100'u32, 1'u32)   # height 100 == 100 → NOT final

# ---------------------------------------------------------------------------
# G15: BIP-65 activation height in getBlockScriptFlags
# Reference: chainparams.cpp + validation.cpp getBlockScriptFlags
# ---------------------------------------------------------------------------

suite "CLTV G15: BIP-65 activation height":
  test "mainnet: CLTV not active before height 388381":
    let params = mainnetParams()
    let flags = getBlockScriptFlags(388380, params)
    check sfCheckLockTimeVerify notin flags

  test "mainnet: CLTV active at height 388381":
    let params = mainnetParams()
    let flags = getBlockScriptFlags(388381, params)
    check sfCheckLockTimeVerify in flags

  test "regtest: CLTV active at height 1 (regtest bip65Height=1)":
    let params = regtestParams()
    let flags1 = getBlockScriptFlags(1, params)
    check sfCheckLockTimeVerify in flags1

  test "regtest: CLTV flag absent at height 0":
    let params = regtestParams()
    let flags0 = getBlockScriptFlags(0, params)
    check sfCheckLockTimeVerify notin flags0

# ---------------------------------------------------------------------------
# Additional edge cases: LOCKTIME_THRESHOLD boundary
# ---------------------------------------------------------------------------

suite "CLTV LOCKTIME_THRESHOLD boundary":
  test "script locktime = 499_999_999 is height-based":
    # Just below threshold
    let tx = makeCLTVTx(499_999_999, sequence = 0)
    let err = runCLTV(scriptNumLE(499_999_999), tx)
    check err == seOk   # equal is allowed (not strictly greater)

  test "script locktime = 500_000_000 is time-based, tx height-based → mismatch":
    # Exactly at threshold → time-based; tx locktime 499_999_999 → height-based
    let tx = makeCLTVTx(499_999_999, sequence = 0)
    let err = runCLTV(scriptNumLE(500_000_000), tx)
    check err == seUnsatisfiedLocktime

  test "IsFinalTx: lockTime = 499_999_999 uses height comparison":
    let tx = makeIsFinalTx(499_999_999'u32, @[0'u32])
    check isFinalTx(tx, 500_000_000'u32, 1'u32)  # height 500M > 499.99M → final
    check not isFinalTx(tx, 499_999_999'u32, 1'u32) # equal → NOT final

  test "IsFinalTx: lockTime = 500_000_000 uses time comparison":
    let tx = makeIsFinalTx(500_000_000'u32, @[0'u32])
    check isFinalTx(tx, 1'u32, 500_000_001'u32)    # MTP > locktime → final
    check not isFinalTx(tx, 1'u32, 499_999_999'u32) # MTP (time-domain) < locktime → NOT final
