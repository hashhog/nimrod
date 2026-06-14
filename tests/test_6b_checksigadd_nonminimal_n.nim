## Test 6B — OP_CHECKSIGADD: non-minimally-encoded n operand under block flags
##
## Finding 6B (consensus over-strict false-reject):
##   nimrod hardcoded `requireMinimal = true` for the n operand of
##   OP_CHECKSIGADD, but Bitcoin Core uses fRequireMinimal which is
##   (flags & SCRIPT_VERIFY_MINIMALDATA).  MINIMALDATA is a *policy* flag,
##   not a mandatory/block-validation flag, so under consensus block
##   validation it is absent and Core ACCEPTS a non-minimally-encoded n.
##   The hardcoded `true` made nimrod false-reject those transactions.
##
## Core reference:
##   bitcoin-core/src/script/interpreter.cpp:432
##     bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
##   bitcoin-core/src/script/interpreter.cpp:1093
##     const CScriptNum num(stacktop(-2), fRequireMinimal);
##
## Fix:
##   interpreter.nim:2215  `toScriptNum(interp.pop(), sfMinimalData in interp.flags)`
##   (was `toScriptNum(interp.pop(), true)`)
##
## Non-vacuous test contract:
##   PRE-FIX:  non-minimal n + no sfMinimalData  → false-REJECT (seInvalidStack)
##   POST-FIX: non-minimal n + no sfMinimalData  → ACCEPT (script returns true)
##   BOTH:     non-minimal n + sfMinimalData      → REJECT  (seInvalidStack)
##   BOTH:     minimal n    + no sfMinimalData    → ACCEPT  (baseline)

import unittest2
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Tapscript control-block helpers (identical to test_w94_taproot_gates.nim)
# ---------------------------------------------------------------------------

const TEST_PRIVKEY_6B: PrivateKey = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
]

proc deriveXonly6B(privkey: PrivateKey): array[32, byte] =
  let compressed = derivePublicKey(privkey)
  for i in 0 ..< 32:
    result[i] = compressed[1 + i]

proc tapleafHash6B(tapscript: seq[byte]): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(0xC0'u8)  # TAPROOT_LEAF_TAPSCRIPT
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  result = taggedHash("TapLeaf", leafData)

proc makeControlBlock6B(tapscript: seq[byte]): tuple[cb: seq[byte], prog: seq[byte]] =
  let internalPk = deriveXonly6B(TEST_PRIVKEY_6B)
  let tlh = tapleafHash6B(tapscript)
  var twData: seq[byte]
  for b in internalPk: twData.add(b)
  for b in tlh: twData.add(b)
  let tw = taggedHash("TapTweak", twData)
  let (q, parity) = tweakXonlyPubkey(internalPk, tw)
  var cb: seq[byte] = @[byte(0xC0'u8 or uint8(parity and 0x01))]
  for b in internalPk: cb.add(b)
  result = (cb, @q)

proc trivialTx6B(): Transaction =
  result = Transaction()
  result.version = 2
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: default(TxId), vout: 0),
    scriptSig: @[],
    sequence: 0xffffffff'u32
  )]
  result.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
  result.lockTime = 0

# ---------------------------------------------------------------------------
# Build a tapscript that runs:
#   <empty-sig> <n-bytes> <32-byte-unknown-pubkey> OP_CHECKSIGADD OP_NOT
#
# With empty sig, success = false, so CHECKSIGADD leaves n on the stack.
# OP_NOT turns n=0 into true (1), making the script pass when n=0.
#
# Non-minimal encoding of n=0: value 0 is canonically the empty stack item
# (OP_0 / empty push).  A 1-byte encoding \x00 is non-minimal for 0.
# We use a 1-byte encoding \x00 to represent n=0 non-minimally.
# ---------------------------------------------------------------------------

proc buildScriptNonMinimalN(nBytes: seq[byte]): seq[byte] =
  ## Script: OP_0 <push nBytes> <push 32-byte pubkey> OP_CHECKSIGADD OP_NOT
  ## OP_0 = empty sig (0 bytes) → success = false → CHECKSIGADD doesn't increment
  ## OP_NOT on result n=0 → 1 (true) if n decodes to 0
  var s: seq[byte]
  # push empty sig via OP_0
  s.add(byte(OP_0))
  # push n operand with raw bytes (manual push, not OP_N)
  s.add(byte(nBytes.len))
  for b in nBytes: s.add(b)
  # push 32-byte arbitrary pubkey (not a valid signing key; sig is empty so
  # verify is skipped)
  s.add(32'u8)
  for _ in 0 ..< 32: s.add(0x03'u8)
  s.add(byte(OP_CHECKSIGADD))
  s.add(byte(OP_NOT))
  s

# ---------------------------------------------------------------------------
# Consensus block flags (no sfMinimalData) vs policy flags (with sfMinimalData)
# ---------------------------------------------------------------------------

const BLOCK_FLAGS = {sfWitness, sfTaproot}
const POLICY_FLAGS = {sfWitness, sfTaproot, sfMinimalData}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

suite "Finding 6B — OP_CHECKSIGADD non-minimal n operand":

  test "baseline: minimal n=0 (empty push / OP_0) with block flags — ACCEPT":
    ## n=0 encoded minimally as the empty byte sequence (OP_0 pushes nothing).
    ## Script: OP_0 OP_0 <32-byte pubkey> OP_CHECKSIGADD OP_NOT
    ## Both pre- and post-fix must accept this (baseline sanity).
    var tapscript: seq[byte]
    tapscript.add(byte(OP_0))   # empty sig
    tapscript.add(byte(OP_0))   # n = 0 (minimal: empty push)
    tapscript.add(32'u8)
    for _ in 0 ..< 32: tapscript.add(0x03'u8)
    tapscript.add(byte(OP_CHECKSIGADD))
    tapscript.add(byte(OP_NOT))
    let (cb, prog) = makeControlBlock6B(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialTx6B(), 0, Satoshi(0), BLOCK_FLAGS)
    check res == true

  test "non-minimal n=0 (1-byte 0x00) with block flags — ACCEPT post-fix (was REJECT pre-fix)":
    ## n=0 encoded non-minimally as \x00 (1 byte).
    ## Core uses fRequireMinimal=(flags & MINIMALDATA)=0 under block flags,
    ## so CScriptNum(stacktop(-2), false) accepts it.
    ## PRE-FIX nimrod: toScriptNum(..., true) → (0, false) → seInvalidStack.
    ## POST-FIX nimrod: toScriptNum(..., sfMinimalData in flags = false) → (0, true) → OK.
    let nBytes: seq[byte] = @[0x00'u8]   # non-minimal encoding of 0
    let tapscript = buildScriptNonMinimalN(nBytes)
    let (cb, prog) = makeControlBlock6B(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialTx6B(), 0, Satoshi(0), BLOCK_FLAGS)
    check res == true

  test "non-minimal n=0 (1-byte 0x00) with policy flags (sfMinimalData) — REJECT":
    ## With sfMinimalData set, both Core and nimrod must reject the non-minimal
    ## encoding.  This verifies the gate is still enforced when the policy
    ## flag is present (sfMinimalData in interp.flags = true → requireMinimal = true).
    let nBytes: seq[byte] = @[0x00'u8]   # non-minimal encoding of 0
    let tapscript = buildScriptNonMinimalN(nBytes)
    let (cb, prog) = makeControlBlock6B(tapscript)
    let witness = @[tapscript, cb]
    let err = verifyWitnessProgramWithError(
      witness, 1, prog, trivialTx6B(), 0, Satoshi(0), POLICY_FLAGS)
    check err == seInvalidStack

  test "non-minimal n=1 (2-byte 0x01 0x00) with block flags — ACCEPT post-fix":
    ## n=1 can be minimally encoded as \x01 (1 byte).
    ## 2-byte encoding \x01\x00 is non-minimal (the trailing \x00 is spurious).
    ## Under block flags (no sfMinimalData) Core accepts this; nimrod post-fix too.
    ## Script result: empty sig → success=false → n stays 1 → OP_1SUB → 0 → OP_NOT → 1.
    var tapscript: seq[byte]
    tapscript.add(byte(OP_0))          # empty sig
    tapscript.add(2'u8)                # push 2 bytes
    tapscript.add(0x01'u8)             # \x01
    tapscript.add(0x00'u8)             # \x00  → non-minimal 1
    tapscript.add(32'u8)
    for _ in 0 ..< 32: tapscript.add(0x03'u8)
    tapscript.add(byte(OP_CHECKSIGADD))
    tapscript.add(byte(OP_1SUB))       # n (=1) - 1 = 0
    tapscript.add(byte(OP_NOT))        # NOT(0) = 1 → script succeeds
    let (cb, prog) = makeControlBlock6B(tapscript)
    let witness = @[tapscript, cb]
    let res = verifyWitnessProgram(
      witness, 1, prog, trivialTx6B(), 0, Satoshi(0), BLOCK_FLAGS)
    check res == true

  test "non-minimal n=1 (2-byte) with policy flags (sfMinimalData) — REJECT":
    ## Same 2-byte non-minimal n=1, but with sfMinimalData set → must reject.
    var tapscript: seq[byte]
    tapscript.add(byte(OP_0))
    tapscript.add(2'u8)
    tapscript.add(0x01'u8)
    tapscript.add(0x00'u8)
    tapscript.add(32'u8)
    for _ in 0 ..< 32: tapscript.add(0x03'u8)
    tapscript.add(byte(OP_CHECKSIGADD))
    tapscript.add(byte(OP_1SUB))
    tapscript.add(byte(OP_NOT))
    let (cb, prog) = makeControlBlock6B(tapscript)
    let witness = @[tapscript, cb]
    let err = verifyWitnessProgramWithError(
      witness, 1, prog, trivialTx6B(), 0, Satoshi(0), POLICY_FLAGS)
    check err == seInvalidStack
