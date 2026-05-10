## Transaction standardness policy (BIP / policy/policy.cpp)
##
## Mirrors Bitcoin Core's `IsStandardTx()` from src/policy/policy.cpp.
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
  ## mempool.nim (avoids circular import). Identical formula.
  if output.scriptPubKey.len > 0 and output.scriptPubKey[0] == 0x6a:  # OP_RETURN
    return Satoshi(0)
  let outputSize = 8 + output.scriptPubKey.len + 1
  let isWitProg = output.scriptPubKey.len >= 4 and
                  output.scriptPubKey[0] >= 0x00'u8 and
                  output.scriptPubKey[0] <= 0x10'u8 and
                  int(output.scriptPubKey[1]) == output.scriptPubKey.len - 2
  let inputSize = if isWitProg:
                    32 + 4 + 1 + (107 div 4) + 4
                  else:
                    32 + 4 + 1 + 107 + 4
  let totalSize = outputSize + inputSize
  Satoshi((totalSize * StdDustRelayTxFee) div 1000)

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
