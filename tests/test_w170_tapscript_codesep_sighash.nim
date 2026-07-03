## W170 — BIP-342 tapscript OP_CODESEPARATOR sighash regression
##
## Consensus fork found by the round-2 modern-surface differential fuzzer
## (adversarial mirror-pair, both directions confirmed).
##
## THE BUG (pre-fix): the tapscript CHECKSIG / CHECKSIGADD Schnorr sighash
## read `ctx.codesepPos` — a by-value field on the SigCheckContext that the
## witness path always constructed with the 0xFFFFFFFF "no codesep" sentinel
## and NEVER synced. The OP_CODESEPARATOR handler correctly wrote the executed
## opcode index into `interp.codesepPos`, but that field was never read by the
## sighash. Net: the BIP-342 sigmsg ALWAYS committed codesep_pos=0xFFFFFFFF,
## regardless of any executed OP_CODESEPARATOR, forking against Core (which
## commits `execdata.m_codeseparator_pos`, interpreter.cpp:1564-1565, set by
## the OP_CODESEPARATOR handler at interpreter.cpp:1055).
##
## THE FIX (tapscript-only): the sighash sites (interpreter.nim CHECKSIG /
## CHECKSIGADD) now read the live `interp.codesepPos`, and `eval` resets that
## field to 0xFFFFFFFF at the top of every script evaluation (mirroring Core's
## per-EvalScript `execdata.m_codeseparator_pos = 0xFFFFFFFF`). Legacy /
## SegWit-v0 codeseparator handling (codesepByteOffset) is untouched.
##
## Mirror-pair vectors, tapscript = OP_CODESEPARATOR <32B xonly pk> OP_CHECKSIG:
##   Vector A: sig signed with codesep_pos=0 (correct post-codesep position)
##             -> Core ACCEPTS; nimrod must ACCEPT (was REJECT pre-fix).
##   Vector B: sig signed with codesep_pos=0xFFFFFFFF (sentinel)
##             -> Core REJECTS; nimrod must REJECT (was ACCEPT pre-fix).
## Regression: a NORMAL tapscript CHECKSIG (no OP_CODESEPARATOR) still ACCEPTS.

import unittest2
import std/options
import ../src/script/interpreter
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/crypto/secp256k1
import ../src/crypto/hashing

# --- fixtures (mirror test_w94_taproot_gates.nim) ---------------------------

proc trivialSpendTx(): Transaction =
  result = Transaction()
  result.version = 2
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: default(TxId), vout: 0),
    scriptSig: @[],
    sequence: 0xffffffff'u32
  )]
  result.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
  result.lockTime = 0

proc deriveXonly(privkey: PrivateKey): array[32, byte] =
  let compressed = derivePublicKey(privkey)
  for i in 0 ..< 32:
    result[i] = compressed[1 + i]

proc tapleafHashOfVer(tapscript: seq[byte], leafVersion: uint8): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(leafVersion)
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  result = taggedHash("TapLeaf", leafData)

proc taptweakOf(internalPk: array[32, byte], merkleRoot: array[32, byte]): array[32, byte] =
  var data: seq[byte]
  for b in internalPk: data.add(b)
  for b in merkleRoot: data.add(b)
  result = taggedHash("TapTweak", data)

const TEST_PRIVKEY: PrivateKey = [
  0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
]

let G_INTERNAL = deriveXonly(TEST_PRIVKEY)

proc makeControlBlock(tapscript: seq[byte]):
    tuple[cb: seq[byte], prog: seq[byte], tlh: array[32, byte]] =
  let tlh = tapleafHashOfVer(tapscript, 0xC0'u8)
  let tw = taptweakOf(G_INTERNAL, tlh)
  let (q, parity) = tweakXonlyPubkey(G_INTERNAL, tw)
  var cb: seq[byte] = @[byte(0xC0'u8 or uint8(parity and 0x01))]
  for b in G_INTERNAL: cb.add(b)
  (cb, @q, tlh)

# Build a single-leaf tapscript script-path witness for `tapscript`, signing
# the BIP-342 sighash with the given codesep position. Returns whether
# verifyWitnessProgram accepts (consensus flags: TAPROOT active).
proc runScriptPathSpend(tapscript: seq[byte], signCodesepPos: uint32): bool =
  let (cb, prog, tlh) = makeControlBlock(tapscript)
  let tx = trivialSpendTx()
  let amount = Satoshi(0)
  let spk = @[byte(OP_1), 0x20'u8] & prog
  # Sighash exactly as eval computes it (single input, hashType SIGHASH_DEFAULT,
  # extFlag=1 tapscript), but with the codesep position we are signing over.
  let sighash = computeSighashTaproot(
    tx, 0, @[amount], @[spk],
    0x00'u8, 1'u8, @[], tlh, signCodesepPos)
  let sig = signSchnorr(TEST_PRIVKEY, sighash, none(array[32, byte]))
  let witness = @[@sig, tapscript, cb]
  verifyWitnessProgram(witness, 1, prog, tx, 0, amount,
                       {sfWitness, sfTaproot}, @[amount], @[spk])

# ---------------------------------------------------------------------------

# tapscript = OP_CODESEPARATOR <32B xonly pk> OP_CHECKSIG  (hex: ab 20 <pk> ac)
let codesepScript: seq[byte] =
  @[byte(OP_CODESEPARATOR), 0x20'u8] & (@G_INTERNAL) & @[byte(OP_CHECKSIG)]
# tapscript = <32B xonly pk> OP_CHECKSIG  (no OP_CODESEPARATOR)
let plainScript: seq[byte] =
  @[0x20'u8] & (@G_INTERNAL) & @[byte(OP_CHECKSIG)]

suite "W170 BIP-342 tapscript OP_CODESEPARATOR sighash (consensus fork)":

  test "Vector A: sig over codesep_pos=0 ACCEPTS (matches Core)":
    # OP_CODESEPARATOR is opcode index 0, so the committed position is 0.
    let accepted = runScriptPathSpend(codesepScript, 0'u32)
    echo "W170 Vector A (codesep_pos=0)         accept=", accepted, " (expect true)"
    check accepted == true

  test "Vector B (mirror): sig over 0xFFFFFFFF sentinel REJECTS (matches Core)":
    let accepted = runScriptPathSpend(codesepScript, 0xFFFFFFFF'u32)
    echo "W170 Vector B (codesep_pos=sentinel)  accept=", accepted, " (expect false)"
    check accepted == false

  test "Regression: normal tapscript CHECKSIG (no OP_CODESEPARATOR) ACCEPTS":
    # No OP_CODESEPARATOR executes -> codesep_pos stays 0xFFFFFFFF; sign over it.
    let accepted = runScriptPathSpend(plainScript, 0xFFFFFFFF'u32)
    echo "W170 no-codesep regression            accept=", accepted, " (expect true)"
    check accepted == true

  test "Sanity: a normal spend signed over the WRONG codesep pos REJECTS":
    # Belt-and-suspenders: no-codesep script but sig claims codesep_pos=0.
    let accepted = runScriptPathSpend(plainScript, 0'u32)
    check accepted == false
