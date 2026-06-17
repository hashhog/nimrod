## Transaction standardness policy (BIP / policy/policy.cpp)
##
## Mirrors Bitcoin Core's `IsStandardTx()` from src/policy/policy.cpp and
## `IsWitnessStandard()` from src/policy/policy.cpp:265-351.
## Already-checked invariants that live elsewhere in nimrod:
##   * MAX_STANDARD_TX_WEIGHT (400_000 WU)  — checked in mempool.acceptTransaction
##                                            *before* this is called, but we
##                                            re-check here so callers (RPC,
##                                            tests) get a single entrypoint.
##
## What this adds:
##   * Standard tx version bounds (TX_MIN_STANDARD_VERSION..TX_MAX_STANDARD_VERSION)
##   * Per-input scriptSig size + push-only check
##   * scriptPubKey shape check (P2PK/P2PKH/P2SH/P2W*/P2TR/OP_RETURN/multisig)
##   * OP_RETURN (datacarrier) bytes-budget across vout
##   * Bare multisig gating
##   * Dust threshold (with MAX_DUST_OUTPUTS_PER_TX allowance for ephemeral dust)
##   * IsWitnessStandard: 6-gate witness policy check (W72)

import std/options
import ../primitives/[types, serialize]
import ../script/interpreter

# Forward-declared helpers used below. We can't import mempool.nim here
# (it imports us) so we re-derive the weight calc identically — see
# mempool.nim:calculateWeight().
proc weightOfTx(tx: Transaction): int =
  let fullSize = serialize(tx, includeWitness = true).len
  let baseSize = serializeLegacy(tx).len
  (baseSize * 3) + fullSize

const
  ## Mempool-policy weight cap (BIP-141; matches Core's MAX_STANDARD_TX_WEIGHT).
  ## Duplicated locally (private) to avoid a circular import on mempool.nim,
  ## which re-exports its own copy of the same value.
  StdMaxStandardTxWeight = 400_000
  StdMaxDustOutputsPerTx = 1
  StdDustRelayTxFee      = 3000

const
  ## Standard tx version range (policy/policy.h:152)
  TxMinStandardVersion* = 1'i32
  TxMaxStandardVersion* = 3'i32

  ## Largest scriptSig we relay. policy/policy.h:62. 1650 bytes covers a
  ## 15-of-15 P2SH multisig with compressed keys plus some slack.
  MaxStandardScriptSigSize* = 1650

  ## Datacarrier (OP_RETURN) budget per tx, default Bitcoin Core relay policy.
  ## policy/policy.h: MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR.
  MaxOpReturnRelayBytes* = StdMaxStandardTxWeight div 4

  ## Allowed multisig configurations. Core: up to 3-of-3 standard.
  MaxStandardMultisigN* = 3

# ---------------------------------------------------------------------------
# Output kind classification
# ---------------------------------------------------------------------------

type
  StdTxoutKind* = enum
    stxNonStandard
    stxP2PK
    stxP2PKH
    stxP2SH
    stxP2WPKH
    stxP2WSH
    stxP2TR
    stxWitnessUnknown   # vNN witness program that isn't v0 or v1, but well-formed
    stxNullData         # OP_RETURN <data...>
    stxMultisig         # bare CHECKMULTISIG

proc isStandardOpReturn*(script: seq[byte]): bool =
  ## OP_RETURN <data> with arbitrary push payloads. We don't enforce datacarrier
  ## size here; that's handled in the per-tx budget pass (matches Core).
  if script.len < 1 or script[0] != OP_RETURN:
    return false
  # Walk pushes after OP_RETURN; reject if any non-push opcode appears.
  var pc = 1
  while pc < script.len:
    let opcode = script[pc]
    if opcode > OP_16:
      return false
    # Determine push consumption (mirrors interpreter.isPushOnly).
    if opcode < 0x4c:
      # Direct push of N bytes
      let n = int(opcode)
      pc += 1 + n
    elif opcode == 0x4c:
      if pc + 1 >= script.len: return false
      let n = int(script[pc + 1])
      pc += 2 + n
    elif opcode == 0x4d:
      if pc + 2 >= script.len: return false
      let n = int(script[pc + 1]) or (int(script[pc + 2]) shl 8)
      pc += 3 + n
    elif opcode == 0x4e:
      if pc + 4 >= script.len: return false
      let n = int(script[pc + 1]) or
              (int(script[pc + 2]) shl 8) or
              (int(script[pc + 3]) shl 16) or
              (int(script[pc + 4]) shl 24)
      pc += 5 + n
    else:
      # OP_RESERVED through OP_16 — accepted as push-equivalents in Core
      pc += 1
  pc == script.len

proc isStandardP2PK*(script: seq[byte]): bool =
  ## <pubkey> OP_CHECKSIG  with pubkey of 33 (compressed) or 65 (uncompressed) bytes.
  if script.len == 35 and script[0] == 33 and script[34] == OP_CHECKSIG:
    return true
  if script.len == 67 and script[0] == 65 and script[66] == OP_CHECKSIG:
    return true
  false

proc isStandardMultisig*(script: seq[byte]): tuple[ok: bool, m, n: int] =
  ## Bare multisig: <m> <pubkey1>..<pubkeyN> <n> OP_CHECKMULTISIG
  ## We only need to recognise the standard envelope; full Solver-level
  ## validation is elsewhere. Returns (m, n) so the caller can apply the
  ## standardness cap (n <= 3, 1 <= m <= n).
  if script.len < 1: return (false, 0, 0)
  let last = script[script.len - 1]
  if last != OP_CHECKMULTISIG: return (false, 0, 0)
  if script.len < 4: return (false, 0, 0)
  let mOp = script[0]
  if mOp < OP_1 or mOp > OP_16: return (false, 0, 0)
  let m = int(mOp - OP_1 + 1)
  let nOp = script[script.len - 2]
  if nOp < OP_1 or nOp > OP_16: return (false, 0, 0)
  let n = int(nOp - OP_1 + 1)

  # Walk pubkeys: between byte 1 and byte (len-2), expect n pushes of 33 or 65.
  var pc = 1
  var pubkeysFound = 0
  while pc < script.len - 2:
    let opcode = script[pc]
    if opcode == 33 or opcode == 65:
      let pkLen = int(opcode)
      if pc + 1 + pkLen > script.len - 2:
        return (false, 0, 0)
      pc += 1 + pkLen
      inc pubkeysFound
    else:
      return (false, 0, 0)
  if pubkeysFound != n: return (false, 0, 0)
  if m < 1 or m > n: return (false, 0, 0)
  (true, m, n)

proc classifyStdTxout*(script: seq[byte]): StdTxoutKind =
  ## Mirrors policy.cpp::IsStandard via Solver(). Order matches Core's
  ## Solver tries (segwit fast-path first, then opcodes).
  if script.len == 0:
    return stxNonStandard
  if isP2PKH(script):
    return stxP2PKH
  if isP2SH(script):
    return stxP2SH
  if isP2WPKH(script):
    return stxP2WPKH
  if isP2WSH(script):
    return stxP2WSH
  if isP2TR(script):
    return stxP2TR
  let (isWit, ver, prog) = isWitnessProgram(script)
  if isWit:
    # Well-formed witness program of unknown version — relay-standard per
    # Core (forward compat for future witness versions). Length of program
    # constrained by isWitnessProgram (2..40).
    if ver == 0 and (prog.len == 20 or prog.len == 32):
      # already covered above, fall-through guard.
      return stxNonStandard
    if ver == 1 and prog.len == 32:
      return stxNonStandard  # already covered as stxP2TR above
    return stxWitnessUnknown
  if isStandardOpReturn(script):
    return stxNullData
  if isStandardP2PK(script):
    return stxP2PK
  let (ok, _, _) = isStandardMultisig(script)
  if ok:
    return stxMultisig
  stxNonStandard

# ---------------------------------------------------------------------------
# Dust
# ---------------------------------------------------------------------------

proc dustThreshold*(output: TxOut): Satoshi =
  ## Mirror of mempool.getDustThreshold so this module has zero dependence on
  ## mempool.nim (avoids circular import). Identical formula, faithful to Core
  ## `GetDustThreshold` (policy/policy.cpp:27-63). NON-CONSENSUS relay policy.
  ##
  ##   nSize = (8 + CompactSize(scriptlen) + scriptlen) + spending_cost
  ## spending_cost = 67 for witness programs (all versions, incl. P2TR) else 148;
  ## threshold = CeilDiv(nSize * dustRelayFee, 1000).
  ##
  ## The previous version's witness test only matched version bytes 0x00..0x10,
  ## so P2TR (version opcode OP_1 = 0x51) was mis-classified as legacy and its
  ## dust threshold over-stated (573 vs Core 330). Use the Core-faithful
  ## `isWitnessProgram` (handles OP_0 and OP_1..OP_16).
  if isUnspendable(output.scriptPubKey):
    return Satoshi(0)
  let scriptLen = output.scriptPubKey.len
  let scriptLenPrefix =
    if scriptLen < 0xfd: 1
    elif scriptLen <= 0xffff: 3
    else: 5
  let txoutSerSize = 8 + scriptLenPrefix + scriptLen
  let (isWit, _, _) = isWitnessProgram(output.scriptPubKey)
  let spendingCost = if isWit:
                       32 + 4 + 1 + (107 div 4) + 4
                     else:
                       32 + 4 + 1 + 107 + 4
  let nSize = txoutSerSize + spendingCost
  Satoshi((nSize * StdDustRelayTxFee + 999) div 1000)

proc isDustOutput*(output: TxOut): bool =
  int64(output.value) < int64(dustThreshold(output))

# ---------------------------------------------------------------------------
# IsStandardTx
# ---------------------------------------------------------------------------

type
  IsStandardOptions* = object
    permitBareMultisig*: bool
    maxDatacarrierBytes*: Option[int]   # None = no datacarrier allowed at all

proc defaultIsStandardOptions*(): IsStandardOptions =
  ## Match Bitcoin Core defaults (DEFAULT_PERMIT_BAREMULTISIG=true,
  ## DEFAULT_ACCEPT_DATACARRIER=true with MAX_OP_RETURN_RELAY budget).
  IsStandardOptions(
    permitBareMultisig: true,
    maxDatacarrierBytes: some(MaxOpReturnRelayBytes)
  )

proc isStandardTx*(tx: Transaction,
                   opts: IsStandardOptions = defaultIsStandardOptions()
                  ): tuple[ok: bool, reason: string] =
  ## Bitcoin Core IsStandardTx() port.
  ##
  ## Returns (true, "") if the tx is standard. On rejection, `reason` matches
  ## the Core string (e.g. "version", "tx-size", "scriptsig-size",
  ## "scriptsig-not-pushonly", "scriptpubkey", "datacarrier", "bare-multisig",
  ## "dust", "multi-op-return") so cross-impl logs line up.
  if tx.version < TxMinStandardVersion or tx.version > TxMaxStandardVersion:
    return (false, "version")

  let weight = weightOfTx(tx)
  if weight > StdMaxStandardTxWeight:
    return (false, "tx-size")

  for txin in tx.inputs:
    if txin.scriptSig.len > MaxStandardScriptSigSize:
      return (false, "scriptsig-size")
    if not isPushOnly(txin.scriptSig):
      return (false, "scriptsig-not-pushonly")

  var datacarrierBytesLeft = if opts.maxDatacarrierBytes.isSome:
                               opts.maxDatacarrierBytes.get()
                             else:
                               0
  var dustCount = 0

  for output in tx.outputs:
    let kind = classifyStdTxout(output.scriptPubKey)
    if kind == stxNonStandard:
      return (false, "scriptpubkey")

    case kind
    of stxNullData:
      # Per-output bytes are deducted from a shared budget (policy/policy.cpp:145-151).
      # Core 31.99 has NO count limit on OP_RETURN outputs — multiple OP_RETURNs
      # are standard as long as the cumulative byte budget is not exceeded.
      let sz = output.scriptPubKey.len
      if sz > datacarrierBytesLeft:
        return (false, "datacarrier")
      datacarrierBytesLeft -= sz
    of stxMultisig:
      if not opts.permitBareMultisig:
        return (false, "bare-multisig")
      let (_, _, n) = isStandardMultisig(output.scriptPubKey)
      if n > MaxStandardMultisigN:
        return (false, "bare-multisig")
    else:
      discard

    if isDustOutput(output):
      inc dustCount

  # Core: more than MAX_DUST_OUTPUTS_PER_TX dust outputs => non-standard
  # ("dust"). Below or equal is allowed (ephemeral anchors).
  if dustCount > StdMaxDustOutputsPerTx:
    return (false, "dust")

  (true, "")

proc isStandardTxOk*(tx: Transaction): bool =
  ## Convenience wrapper that drops the reason string.
  let (ok, _) = isStandardTx(tx)
  ok

# ---------------------------------------------------------------------------
# IsWitnessStandard (policy/policy.cpp:265-351)
# ---------------------------------------------------------------------------
#
# Implements all 6 gates from Bitcoin Core's IsWitnessStandard().
# Takes a prevout-lookup callback so this module stays free of chainstate
# imports (which would create circular dependencies with mempool.nim).
#
# Gate 1  (policy.cpp:283-285):  P2A with any witness → nonstandard
# Gate 2  (policy.cpp:288-299):  P2SH-wrapped: eval scriptSig pushes; top = redeemScript
# Gate 3  (policy.cpp:305-306):  non-witness prevScript + non-empty witness → nonstandard
# Gate 4  (policy.cpp:309-318):  P2WSH v0 32B: script ≤ 3600; stack-1 ≤ 100; each item ≤ 80
# Gate 5  (policy.cpp:324-348):  P2TR v1 32B (not P2SH): annex 0x50 → reject; tapscript 0xc0 → each item ≤ 80; empty stack → reject
# Gate 6  (policy.cpp:267-268):  coinbase exempt

const
  ## policy/policy.h: MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
  MaxStandardP2WSHScriptSize* = 3600
  ## policy/policy.h: MAX_STANDARD_P2WSH_STACK_ITEMS = 100
  MaxStandardP2WSHStackItems* = 100
  ## policy/policy.h: MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80
  MaxStandardP2WSHStackItemSize* = 80
  ## policy/policy.h: MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80
  MaxStandardTapscriptStackItemSize* = 80
  ## BIP-341: annex tag byte
  AnnexTag* = 0x50'u8
  ## BIP-341: TAPROOT_LEAF_MASK (mask off version parity bit)
  TaprootLeafMask* = 0xfe'u8
  ## BIP-342: TAPROOT_LEAF_TAPSCRIPT leaf version
  TaprootLeafTapscript* = 0xc0'u8

proc isCoinbaseTx(tx: Transaction): bool {.inline.} =
  ## Local copy of isCoinbase to avoid importing consensus/validation.nim
  ## (which pulls in chainstate and secp256k1). Identical logic.
  tx.inputs.len == 1 and
  tx.inputs[0].prevOut.txid == TxId(default(array[32, byte])) and
  tx.inputs[0].prevOut.vout == 0xffffffff'u32

proc evalScriptSigPushes*(scriptSig: seq[byte]): tuple[ok: bool, stack: seq[seq[byte]]] =
  ## Evaluate a push-only scriptSig and return the resulting stack.
  ## Mirrors the EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...) call
  ## in Core's IsWitnessStandard (policy.cpp:293).  No crypto; pushes only.
  var stack: seq[seq[byte]] = @[]
  var pc = 0
  while pc < scriptSig.len:
    let op = scriptSig[pc]
    inc pc
    if op == 0x00'u8:
      # OP_0: push empty byte vector
      stack.add(@[])
    elif op >= 0x01'u8 and op <= 0x4b'u8:
      # Direct push of N bytes
      let n = int(op)
      if pc + n > scriptSig.len:
        return (false, @[])
      stack.add(scriptSig[pc ..< pc + n])
      pc += n
    elif op == 0x4c'u8:
      # OP_PUSHDATA1
      if pc >= scriptSig.len:
        return (false, @[])
      let n = int(scriptSig[pc])
      inc pc
      if pc + n > scriptSig.len:
        return (false, @[])
      stack.add(scriptSig[pc ..< pc + n])
      pc += n
    elif op == 0x4d'u8:
      # OP_PUSHDATA2
      if pc + 1 >= scriptSig.len:
        return (false, @[])
      let n = int(scriptSig[pc]) or (int(scriptSig[pc + 1]) shl 8)
      pc += 2
      if pc + n > scriptSig.len:
        return (false, @[])
      stack.add(scriptSig[pc ..< pc + n])
      pc += n
    elif op == 0x4e'u8:
      # OP_PUSHDATA4
      if pc + 3 >= scriptSig.len:
        return (false, @[])
      let n = int(scriptSig[pc]) or
              (int(scriptSig[pc + 1]) shl 8) or
              (int(scriptSig[pc + 2]) shl 16) or
              (int(scriptSig[pc + 3]) shl 24)
      pc += 4
      if pc + n > scriptSig.len:
        return (false, @[])
      stack.add(scriptSig[pc ..< pc + n])
      pc += n
    elif op == 0x4f'u8:
      # OP_1NEGATE: push -1 (little-endian 0x81)
      stack.add(@[0x81'u8])
    elif op >= 0x51'u8 and op <= 0x60'u8:
      # OP_1 .. OP_16: push single byte 1..16
      stack.add(@[byte(op - 0x50'u8)])
    else:
      # Non-push opcode: fail (Core uses SCRIPT_VERIFY_NONE which still
      # fails on non-push opcodes in scriptSig evaluation via EvalScript).
      return (false, @[])
  (true, stack)

proc isWitnessStandard*(
    tx: Transaction,
    getPrevScriptPubKey: proc(input: TxIn): seq[byte]
  ): tuple[ok: bool, reason: string] =
  ## IsWitnessStandard port (policy/policy.cpp:265-351).
  ##
  ## `getPrevScriptPubKey` must return the scriptPubKey of the UTXO being
  ## spent by each input.  The caller (acceptTransaction in mempool.nim)
  ## already has these from its UTXO lookups.
  ##
  ## Returns (true, "") when standard.  On rejection, `reason` matches
  ## the Bitcoin Core rejection string "bad-witness-nonstandard".

  # Gate 6: coinbase is exempt (policy.cpp:267-268).
  if isCoinbaseTx(tx):
    return (true, "")

  for i, txin in tx.inputs:
    # Skip inputs with empty witness (policy.cpp:274-275).
    let hasWitness = i < tx.witnesses.len and tx.witnesses[i].len > 0
    if not hasWitness:
      continue

    var prevScript = getPrevScriptPubKey(txin)

    # Gate 1: P2A with any witness is nonstandard (policy.cpp:283-285).
    if isP2A(prevScript):
      return (false, "bad-witness-nonstandard")

    # Gate 2: P2SH-wrapped — extract redeemScript from scriptSig
    # (policy.cpp:288-299).
    var p2sh = false
    if isP2SH(prevScript):
      let (evalOk, stack) = evalScriptSigPushes(txin.scriptSig)
      if not evalOk:
        return (false, "bad-witness-nonstandard")
      if stack.len == 0:
        return (false, "bad-witness-nonstandard")
      # Top of stack is the serialised redeemScript.
      prevScript = stack[stack.len - 1]
      p2sh = true

    # Gate 3: non-witness prevScript with non-empty witness → nonstandard
    # (policy.cpp:305-306).
    let (isWit, witnessVersion, witnessProgram) = isWitnessProgram(prevScript)
    if not isWit:
      return (false, "bad-witness-nonstandard")

    let witness = tx.witnesses[i]

    # Gate 4: P2WSH v0 32-byte program (policy.cpp:309-318).
    if witnessVersion == 0 and witnessProgram.len == 32:
      # witness.stack.back() is the witnessScript; the rest are stack items.
      if witness[witness.len - 1].len > MaxStandardP2WSHScriptSize:
        return (false, "bad-witness-nonstandard")
      let sizeWitnessStack = witness.len - 1
      if sizeWitnessStack > MaxStandardP2WSHStackItems:
        return (false, "bad-witness-nonstandard")
      for j in 0 ..< sizeWitnessStack:
        if witness[j].len > MaxStandardP2WSHStackItemSize:
          return (false, "bad-witness-nonstandard")

    # Gate 5: P2TR v1 32-byte program, not P2SH-wrapped (policy.cpp:324-348).
    elif witnessVersion == 1 and witnessProgram.len == 32 and not p2sh:
      # Check for annex: present if ≥2 items and last item starts with 0x50.
      var stack = witness  # local mutable copy (we'll pop from the end logically)

      if stack.len >= 2 and stack[stack.len - 1].len > 0 and
         stack[stack.len - 1][0] == AnnexTag:
        # Annexes are nonstandard (no semantics defined yet) — policy.cpp:327-330.
        return (false, "bad-witness-nonstandard")

      if stack.len >= 2:
        # Script-path spend: pop control block, then script.
        # (policy.cpp:331-341)
        let controlBlock = stack[stack.len - 1]
        stack.setLen(stack.len - 1)  # pop control block
        stack.setLen(stack.len - 1)  # pop script (ignore)
        if controlBlock.len == 0:
          return (false, "bad-witness-nonstandard")
        if (controlBlock[0] and TaprootLeafMask) == TaprootLeafTapscript:
          # Tapscript leaf: check each remaining stack item ≤ 80 bytes.
          for item in stack:
            if item.len > MaxStandardTapscriptStackItemSize:
              return (false, "bad-witness-nonstandard")
      elif stack.len == 1:
        # Key-path spend: no policy rules (policy.cpp:342-344).
        discard
      else:
        # 0 stack elements: already invalid by consensus (policy.cpp:345-348).
        return (false, "bad-witness-nonstandard")

  (true, "")
