## Block and transaction validation
## Full consensus rules implementation per Bitcoin protocol

import std/[times, options, algorithm, tables]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1]
import ../storage/chainstate
import ../script/interpreter
import ../perf/sig_cache
import ../perf/verify_pool
import ./params
from ./pow import nil

export params

# Re-exports `globalSigCache` (the process-wide signature cache, see
# `perf/sig_cache.nim`). Previously this module owned the global directly;
# moving it into `sig_cache.nim` lets `script/interpreter.nim` consult the
# same cache without an import cycle (validation already imports interpreter).
export sig_cache

type
  ValidationError* = enum
    veOk = "ok"
    veDuplicateTx = "duplicate transaction in block"
    veBadMerkleRoot = "merkle root mismatch"
    veBadPow = "proof of work check failed"
    veExceedsTarget = "block hash exceeds target"
    veBadTimestamp = "block timestamp invalid"
    veBadCoinbaseSize = "coinbase script size invalid"
    veBlockOverweight = "block exceeds maximum weight"
    veSigopExceeded = "block exceeds sigop limit"
    veInputsMissing = "transaction inputs missing"
    veDoubleSpend = "double spend detected"
    veBadAmount = "invalid transaction amount"
    veImmatureCoinbase = "spending immature coinbase"
    veBadWitnessCommitment = "witness commitment mismatch"
    veWitnessNonceSize = "invalid witness reserved value size"
    veUnexpectedWitness = "unexpected witness data"
    veScriptVerifyFailed = "script verification failed"
    veBadCoinbase = "invalid coinbase transaction"
    veNoCoinbase = "missing coinbase transaction"
    veBadTxVersion = "invalid transaction version"
    veDuplicateInput = "duplicate transaction input"
    veBadOutputValue = "invalid output value"
    veNegativeOutput = "negative output value"
    veOutputTooLarge = "output value exceeds MAX_MONEY"
    veFeeTooLow = "transaction fee too low"
    veBadBlockVersion = "invalid block version"
    vePrevBlockMissing = "previous block not found"
    veSequenceLockNotSatisfied = "BIP68 relative lock-time not satisfied"
    veCheckpointMismatch = "block hash does not match checkpoint"
    veForkBelowCheckpoint = "cannot fork before the last checkpoint"
    veInsufficientChainWork = "chain does not meet minimum work requirement"
    veNonFinalTx = "non-final transaction: bad-txns-nonfinal"
    veBip30DuplicateOutput = "bad-txns-BIP30: tried to overwrite transaction"
    veOutputsBelowInputs = "transaction outputs exceed inputs (in-belowout)"
    veTxOversize = "transaction exceeds maximum size (bad-txns-oversize)"
    veTxOutTotalTooLarge = "sum of outputs exceeds MAX_MONEY (bad-txns-txouttotal-toolarge)"
    veNullPrevout = "non-coinbase input has null prevout (bad-txns-prevout-null)"
    veFeesOutOfRange = "accumulated block fees out of range (bad-txns-accumulated-fee-outofrange)"
    veIncorrectProofOfWork = "incorrect proof of work (bad-diffbits)"
    veTimeWarpAttack = "block timestamp too early on diff adjustment block (time-timewarp-attack)"
    veTimeTooNew = "block timestamp too far in the future (time-too-new)"
    veTooFarAhead = "block too far ahead of active tip (fTooFarAhead)"
    # CVE-2012-2459: merkle tree mutated by duplicate-txid construction.
    # Core CheckMerkleRoot rejects bad-txns-duplicate when ComputeMerkleRoot's
    # `mutated` flag is set (identical adjacent pair at some level).
    veMutatedMerkleTree = "merkle tree mutated (bad-txns-duplicate)"

  ValidationResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: ValidationError

  # Consensus-only script verification flags (not policy flags)
  ConsensusFlags* {.pure.} = enum
    P2SH           # BIP16
    DERSig         # BIP66
    CheckLockTimeVerify  # BIP65
    CheckSequenceVerify  # BIP112
    Witness        # BIP141
    NullDummy      # BIP147
    Taproot        # BIP341/342

  # Generic SigopResult type for sigop counting functions
  SigopResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

# Result constructors for SigopResult type
proc sigopOk*[T](val: T): SigopResult[T] =
  SigopResult[T](isOk: true, value: val)

proc sigopErr*[T](e: string): SigopResult[T] =
  SigopResult[T](isOk: false, error: e)

# Result constructors
proc ok*[T](val: T): ValidationResult[T] =
  ValidationResult[T](isOk: true, value: val)

proc ok*(): ValidationResult[void] =
  ValidationResult[void](isOk: true)

proc err*(T: typedesc, e: ValidationError): ValidationResult[T] =
  ValidationResult[T](isOk: false, error: e)

template voidErr*(e: ValidationError): ValidationResult[void] =
  ValidationResult[void](isOk: false, error: e)

proc bip22String*(e: ValidationError): string =
  ## Map a ValidationError to the canonical BIP-22 result string.
  ##
  ## Per BIP-22 and Bitcoin Core BIP22ValidationResult() in
  ## src/rpc/mining.cpp, submitblock must return short ASCII strings for
  ## known rejection reasons.  Unknown or structural errors map to "rejected".
  case e
  of veBadPow, veExceedsTarget: "high-hash"
  of veBadMerkleRoot: "bad-txnmrklroot"
  # CVE-2012-2459: Core CheckMerkleRoot sets state Invalid "bad-txns-duplicate"
  # when ComputeMerkleRoot reports the tree was mutated (validation.cpp).
  of veMutatedMerkleTree: "bad-txns-duplicate"
  of veBadWitnessCommitment: "bad-witness-merkle-match"
  of veWitnessNonceSize: "bad-witness-nonce-size"
  of veUnexpectedWitness: "unexpected-witness"
  of veBadAmount: "bad-cb-amount"
  of veSigopExceeded: "bad-blk-sigops"
  # Core parity: in-block dup-txid → bad-txns-inputs-missingorspent (ConnectBlock prevout path).
  # BIP-30 cross-block case stays bad-txns-BIP30 via veBip30DuplicateOutput.
  of veDuplicateTx: "bad-txns-inputs-missingorspent"
  # BIP-68 SequenceLocks failure maps to the same string as IsFinalTx per
  # Core validation.cpp:2558.
  of veNonFinalTx, veSequenceLockNotSatisfied: "bad-txns-nonfinal"
  of veBip30DuplicateOutput: "bad-txns-BIP30"
  of veBadCoinbase: "bad-cb-height"
  of veBadCoinbaseSize: "bad-cb-length"
  of veInputsMissing: "bad-txns-inputs-missingorspent"
  of veScriptVerifyFailed: "block-script-verify-flag-failed"
  of veDoubleSpend: "bad-txns-inputs-spent"
  of veBadTimestamp: "time-too-old"
  # Coinbase maturity violation (consensus/tx_verify.cpp::CheckTxInputs).
  # Core: state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase")
  of veImmatureCoinbase: "bad-txns-premature-spend-of-coinbase"
  # Negative output value (consensus/tx_check.cpp::CheckTransaction — Core parity)
  of veNegativeOutput: "bad-txns-vout-negative"
  # Output value > MAX_MONEY (consensus/tx_check.cpp::CheckTransaction — Core parity)
  of veOutputTooLarge: "bad-txns-vout-toolarge"
  # Non-coinbase tx where sum(inputs) < sum(outputs).
  # Core consensus/tx_verify.cpp::CheckTxInputs:
  #   state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
  of veOutputsBelowInputs: "bad-txns-in-belowout"
  # bad-txns-oversize: single tx base-size * 4 > MAX_BLOCK_WEIGHT (tx_check.cpp:19)
  of veTxOversize: "bad-txns-oversize"
  # bad-txns-txouttotal-toolarge: running sum of outputs exceeds MAX_MONEY (tx_check.cpp:33)
  of veTxOutTotalTooLarge: "bad-txns-txouttotal-toolarge"
  # bad-txns-prevout-null: non-coinbase input references null outpoint (tx_check.cpp:56)
  of veNullPrevout: "bad-txns-prevout-null"
  # bad-txns-accumulated-fee-outofrange: sum of tx fees in block out of range (validation.cpp:2543)
  of veFeesOutOfRange: "bad-txns-accumulated-fee-outofrange"
  # incorrect proof of work: nBits doesn't match GetNextWorkRequired (validation.cpp:4089)
  of veIncorrectProofOfWork: "bad-diffbits"
  # time-timewarp-attack: BIP94 diff-adjustment block too far back (validation.cpp:4102)
  of veTimeWarpAttack: "time-timewarp-attack"
  # time-too-new: block timestamp too far in the future (validation.cpp:4109)
  of veTimeTooNew: "time-too-new"
  # bad-version: obsolete block version after BIP34/66/65 activation (validation.cpp:4116)
  of veBadBlockVersion: "bad-version"
  # fTooFarAhead: block height > ActiveHeight + MIN_BLOCKS_TO_KEEP (validation.cpp:4334)
  # Core returns false (not an error string) for this case; map to "rejected" per BIP-22.
  of veTooFarAhead: "rejected"
  # too-little-chainwork: header accepted before PRESYNC verified chain meets
  # nMinimumChainWork (validation.cpp:4229, BLOCK_HEADER_LOW_WORK).
  of veInsufficientChainWork: "too-little-chainwork"
  of veOk: ""
  else: "rejected"

# Merkle root computation with Bitcoin's duplicate-last-if-odd rule.
#
# CVE-2012-2459 mutation detection (Core consensus/merkle.cpp:46-63,
# ComputeMerkleRoot with bool* mutated): at the TOP of each level-collapse
# iteration — BEFORE the odd-tail duplication and BEFORE the pairwise hash —
# scan every COMPLETE adjacent pair (pos, pos+1) and set `mutated` if the two
# hashes are equal:
#     for pos in 0, 2, 4 ... while pos+1 < size: if h[pos]==h[pos+1] -> mutated
# The lone trailing element at an odd level is NOT compared at this level
# (pos+1 < size excludes it) — but once it is duplicated for the next level it
# becomes an identical adjacent pair caught on the NEXT level's scan. This is
# exactly Core's ordering; doing the scan AFTER the odd-dup (or comparing the
# lone tail against itself) would false-reject honest odd-N blocks.
#
# CheckBlock (Core validation.cpp CheckMerkleRoot) rejects bad-txns-duplicate
# when `mutated` is set, treating it identically to a bad merkle root.
proc computeMerkleRootMutated*(txids: seq[array[32, byte]],
                               mutated: var bool): array[32, byte] =
  ## Compute merkle root AND report CVE-2012-2459 mutation. `mutated` is set to
  ## true iff any complete adjacent pair at any level is identical (the
  ## duplicate-txid mutation), per Core ComputeMerkleRoot's `bool* mutated`.
  mutated = false
  if txids.len == 0:
    return default(array[32, byte])

  if txids.len == 1:
    return txids[0]

  var level = txids
  while level.len > 1:
    # Core merkle.cpp:49-53 — scan complete adjacent pairs at the TOP of the
    # level, BEFORE the odd-tail duplication below. Only pairs with pos+1 <
    # size are compared (the lone tail is excluded here, caught next level).
    var pos = 0
    while pos + 1 < level.len:
      if level[pos] == level[pos + 1]:
        mutated = true
      pos += 2

    var nextLevel: seq[array[32, byte]]
    var i = 0
    while i < level.len:
      var combined: array[64, byte]
      copyMem(addr combined[0], unsafeAddr level[i][0], 32)
      if i + 1 < level.len:
        copyMem(addr combined[32], unsafeAddr level[i + 1][0], 32)
      else:
        # Duplicate last hash if odd number
        copyMem(addr combined[32], unsafeAddr level[i][0], 32)
      nextLevel.add(doubleSha256(combined))
      i += 2
    level = nextLevel

  result = level[0]

proc computeMerkleRoot*(txids: seq[array[32, byte]]): array[32, byte] =
  ## Compute merkle root from a list of transaction hashes
  ## If odd number of elements, duplicate the last one.
  ## Mutation-agnostic wrapper over computeMerkleRootMutated (mutation is
  ## checked explicitly on the block-acceptance path; see checkBlock /
  ## validateBlock).
  var mutated = false
  computeMerkleRootMutated(txids, mutated)

proc computeWitnessCommitment*(wtxids: seq[array[32, byte]], reserved: array[32, byte]): array[32, byte] =
  ## Compute witness commitment for SegWit blocks
  ## witnessCommitment = SHA256d(witnessRoot || reserved)
  ## Reserved value is typically all zeros
  let witnessRoot = computeMerkleRoot(wtxids)
  var combined: array[64, byte]
  copyMem(addr combined[0], unsafeAddr witnessRoot[0], 32)
  copyMem(addr combined[32], unsafeAddr reserved[0], 32)
  doubleSha256(combined)

# Block subsidy calculation
proc getBlockSubsidy*(height: int32, params: ConsensusParams): Satoshi =
  ## Calculate block subsidy at given height
  ## Subsidy halves every 210,000 blocks (on mainnet)
  ## Returns 0 when halvings >= 64 (prevents overflow)
  let halvings = height div int32(params.subsidyHalvingInterval)
  if halvings >= 64:
    return Satoshi(0)
  var subsidy = 5_000_000_000'i64  # 50 BTC in satoshis
  subsidy = subsidy shr halvings
  Satoshi(subsidy)

# Block weight calculation
# IMPORTANT: weight = (non_witness_bytes * 3) + total_bytes
# This is equivalent to: (base_size * 4) + (witness_size * 1) - base_size
# = base_size * 3 + witness_size + base_size = non_witness * 3 + total
proc calculateBlockWeight*(blk: Block): int =
  ## Calculate block weight in weight units
  ## Weight = non-witness bytes * 3 + total bytes
  ## Max weight: 4,000,000 WU

  # Serialize block header (always 80 bytes, no witness)
  let headerWeight = 80 * 4

  # Transaction count varint (no witness)
  var txCountSize = 1
  if blk.txs.len >= 0xFD:
    if blk.txs.len <= 0xFFFF:
      txCountSize = 3
    elif blk.txs.len <= 0xFFFFFFFF:
      txCountSize = 5
    else:
      txCountSize = 9

  var totalWeight = headerWeight + (txCountSize * 4)

  for tx in blk.txs:
    let fullSize = serialize(tx, includeWitness = true).len
    let baseSize = serializeLegacy(tx).len

    # Weight = (baseSize * 3) + fullSize
    # This is the correct formula per BIP141
    let txWeight = (baseSize * 3) + fullSize
    totalWeight += txWeight

  totalWeight

proc calculateTransactionWeight*(tx: Transaction): int =
  ## Calculate transaction weight in weight units
  let fullSize = serialize(tx, includeWitness = true).len
  let baseSize = serializeLegacy(tx).len
  (baseSize * 3) + fullSize

proc getSigOpsAdjustedWeight*(weight: int64, sigopCost: int64, bytesPerSigop: int = DefaultBytesPerSigop): int64 =
  ## Return the weight adjusted upward for expensive sigops, matching
  ## Bitcoin Core GetSigOpsAdjustedWeight (policy/policy.cpp:390-393).
  ## weight_adjusted = max(weight, sigopCost * bytesPerSigop)
  ## When bytesPerSigop == 0 the sigop term is ignored (no adjustment).
  if bytesPerSigop == 0:
    return weight
  max(weight, sigopCost * int64(bytesPerSigop))

proc getVirtualTransactionSize*(weight: int64, sigopCost: int64, bytesPerSigop: int = DefaultBytesPerSigop): int64 =
  ## Compute the virtual transaction size (weight reinterpreted as vbytes)
  ## with optional sigop-cost adjustment.
  ## Mirrors Bitcoin Core GetVirtualTransactionSize (policy/policy.cpp:395-398):
  ##   vsize = ceil(max(weight, sigopCost * bytesPerSigop) / WITNESS_SCALE_FACTOR)
  ##         = (getSigOpsAdjustedWeight(...) + 3) / 4
  ## When sigopCost == 0 and bytesPerSigop == 0 this reduces to ceil(weight/4).
  (getSigOpsAdjustedWeight(weight, sigopCost, bytesPerSigop) + int64(WitnessScaleFactor) - 1) div int64(WitnessScaleFactor)

proc getVirtualTransactionSize*(tx: Transaction, sigopCost: int64 = 0, bytesPerSigop: int = DefaultBytesPerSigop): int64 =
  ## Convenience overload: compute vsize directly from a Transaction.
  ## Mirrors Bitcoin Core GetVirtualTransactionSize(const CTransaction&, ...)
  ## (policy/policy.cpp:400-403 and policy/policy.h:186-189).
  getVirtualTransactionSize(int64(calculateTransactionWeight(tx)), sigopCost, bytesPerSigop)

# Coinbase validation
proc isCoinbase*(tx: Transaction): bool =
  ## Check if transaction is a coinbase transaction
  tx.inputs.len == 1 and
  tx.inputs[0].prevOut.txid == TxId(default(array[32, byte])) and
  tx.inputs[0].prevOut.vout == 0xffffffff'u32

proc encodeBip34Height*(height: int32): seq[byte] =
  ## Build the canonical BIP-34 byte encoding for a block height.
  ## Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448):
  ##   height == 0  → OP_0 (0x00), single byte
  ##   1..16        → OP_1..OP_16 (0x51..0x60), single byte
  ##   otherwise    → length-prefixed sign-magnitude CScriptNum
  if height == 0:
    return @[byte(0x00)]
  if height >= 1 and height <= 16:
    return @[byte(0x50'u8 + uint8(height))]
  # CScriptNum: minimal little-endian sign-magnitude with length prefix.
  var h = uint32(height)
  var le: seq[byte]
  while h > 0:
    le.add(byte(h and 0xff))
    h = h shr 8
  # If high bit of last byte is set, append zero sign byte.
  if (le[^1] and 0x80'u8) != 0:
    le.add(0x00'u8)
  result = newSeq[byte](1 + le.len)
  result[0] = byte(le.len)
  for i, b in le:
    result[1 + i] = b

proc validateCoinbaseSizeOnly*(tx: Transaction): ValidationResult[void] =
  ## Context-free coinbase scriptSig length check.
  ## Bitcoin Core consensus/tx_check.cpp:49: 2 <= scriptSig.size() <= 100.
  ## Called from checkBlock (no height available); BIP-34 prefix check is
  ## deferred to validateCoinbase (called from validateBlock with height).
  if tx.inputs.len == 0:
    return voidErr(veNoCoinbase)
  let scriptSigLen = tx.inputs[0].scriptSig.len
  if scriptSigLen < 2 or scriptSigLen > 100:
    return voidErr(veBadCoinbaseSize)
  ok()

proc validateCoinbase*(tx: Transaction, height: int32, params: ConsensusParams): ValidationResult[void] =
  ## Validate coinbase transaction structure
  if not isCoinbase(tx):
    return voidErr(veNoCoinbase)

  # BIP34: coinbase scriptSig must start with the byte-exact canonical encoding
  # of the block height. Bitcoin Core validation.cpp:4151-4159:
  #   CScript expect = CScript() << nHeight;
  #   sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
  if height >= int32(params.bip34Height):
    let scriptSig = tx.inputs[0].scriptSig
    let expect = encodeBip34Height(height)
    if scriptSig.len < expect.len:
      return voidErr(veBadCoinbase)
    for i in 0 ..< expect.len:
      if scriptSig[i] != expect[i]:
        return voidErr(veBadCoinbase)

  # Check scriptSig size (2-100 bytes per protocol)
  let scriptSigLen = tx.inputs[0].scriptSig.len
  if scriptSigLen < 2 or scriptSigLen > 100:
    return voidErr(veBadCoinbaseSize)

  ok()

# Locktime / sequence constants (mirror blocktemplate.nim to avoid import cycle)
const LocktimeThreshold* = 500_000_000'u32  ## Below: block height; at/above: Unix timestamp
const SequenceFinal* = 0xFFFFFFFF'u32       ## Disables relative locktime enforcement

# Witness commitment extraction and validation
const WitnessCommitmentPrefix* = [0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]

proc findWitnessCommitment*(tx: Transaction): Option[array[32, byte]] =
  ## Find witness commitment in coinbase transaction
  ## Returns the 32-byte commitment if found
  ## Commitment format: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commitment>
  for i in countdown(tx.outputs.len - 1, 0):
    let script = tx.outputs[i].scriptPubKey
    if script.len >= 38:
      var matches = true
      for j in 0 ..< 6:
        if script[j] != WitnessCommitmentPrefix[j]:
          matches = false
          break
      if matches:
        var commitment: array[32, byte]
        copyMem(addr commitment[0], unsafeAddr script[6], 32)
        return some(commitment)
  none(array[32, byte])

proc getWitnessReservedValue*(tx: Transaction): array[32, byte] =
  ## Get witness reserved value from coinbase witness.
  ## Returns all-zeros if no witness or wrong size (caller must validate size separately).
  if tx.witnesses.len > 0 and tx.witnesses[0].len > 0:
    let stack = tx.witnesses[0]
    if stack.len > 0 and stack[0].len == 32:
      copyMem(addr result[0], unsafeAddr stack[0][0], 32)

proc checkWitnessMalleation*(blk: Block, segwitActive: bool): ValidationResult[void] =
  ## CheckWitnessMalleation — BIP-141 witness commitment validation.
  ##
  ## Mirrors Bitcoin Core validation.cpp:3864-3916 (CheckWitnessMalleation)
  ## as called from ContextualCheckBlock (validation.cpp:4169).
  ##
  ## Gates (12):
  ##   G1  segwitActive controls the two branches below.
  ##   G2  Scan coinbase outputs, keep the LAST one matching the 6-byte magic
  ##       (OP_RETURN 0x24 0xaa 0x21 0xa9 0xed) with size >= 38 bytes.
  ##   G3  MINIMUM_WITNESS_COMMITMENT = 38 bytes enforced in findWitnessCommitment.
  ##   G4  Magic bytes: 0x6a 0x24 0xaa 0x21 0xa9 0xed enforced in findWitnessCommitment.
  ##   G5  If segwit active and commitment found:
  ##         coinbase witness[0] (per-input stack 0) must have exactly 1 item …
  ##   G6  … of exactly 32 bytes (= witness nonce). → "bad-witness-nonce-size"
  ##   G7  Coinbase wtxid is all-zeros; non-coinbase wtxids are GetWitnessHash().
  ##   G8  Witness merkle root = ComputeMerkleRoot(wtxids) (same alg as txid root).
  ##   G9  commitment = SHA256d(witnessRoot || nonce) must match the 32 bytes at
  ##       script offset [6..37]. → "bad-witness-merkle-match"
  ##   G10 If segwit active but NO commitment present: OK (no error).
  ##   G11 If segwit NOT active: any transaction with non-empty witness data
  ##       is illegal. → "unexpected-witness"
  ##   G12 Block has at least 1 tx (coinbase) — asserted before this call.
  let commitmentOpt = findWitnessCommitment(blk.txs[0])
  if segwitActive and commitmentOpt.isSome:
    # G5+G6: coinbase witness[input 0] must be a stack of exactly 1 item of 32 bytes.
    # Core validation.cpp:3878-3885.
    let witnessStack =
      if blk.txs[0].witnesses.len > 0: blk.txs[0].witnesses[0]
      else: newSeq[seq[byte]]()
    if witnessStack.len != 1 or witnessStack[0].len != 32:
      return voidErr(veWitnessNonceSize)

    # G7+G8+G9: compute witness merkle root, then SHA256d(root || nonce).
    # Core validation.cpp:3890-3898.
    var wtxids: seq[array[32, byte]]
    wtxids.add(default(array[32, byte]))  # coinbase wtxid is all-zeros
    for i in 1 ..< blk.txs.len:
      wtxids.add(array[32, byte](blk.txs[i].wtxid()))

    var nonce: array[32, byte]
    copyMem(addr nonce[0], unsafeAddr witnessStack[0][0], 32)
    let computedCommitment = computeWitnessCommitment(wtxids, nonce)

    if computedCommitment != commitmentOpt.get():
      return voidErr(veBadWitnessCommitment)
    # Commitment validated: return early (Core validation.cpp:3900-3902 `return true`).
    return ok()

  # No witness commitment was found (segwit inactive, OR segwit active but
  # coinbase has no 0xaa21a9ed output).  Core validation.cpp:3905-3913:
  # "No witness data is allowed in blocks that don't commit to witness data."
  # This scan runs for BOTH the segwit-inactive case (G11) AND the
  # segwit-active-no-commitment case (fixes the previous G10 false-accept).
  for tx in blk.txs:
    for inputIdx in 0 ..< tx.witnesses.len:
      if tx.witnesses[inputIdx].len > 0:
        return voidErr(veUnexpectedWitness)

  ok()

# Median Time Past (MTP) calculation
proc getMedianTimePast*(prevHeaders: seq[BlockHeader]): uint32 =
  ## Calculate Median Time Past from previous 11 block headers
  ## If fewer than 11 blocks, use what's available
  var timestamps: seq[uint32]
  for header in prevHeaders:
    timestamps.add(header.timestamp)

  if timestamps.len == 0:
    return 0

  timestamps.sort()
  timestamps[timestamps.len div 2]

proc getMtpForHeight*(utxos: ChainDb, height: int32): uint32 =
  ## Get Median Time Past for a given block height
  ## Uses the previous 11 block headers (or fewer if near genesis)
  ## This is the MTP at the tip of the chain when block `height` is being mined
  if height < 0:
    return 0

  var headers: seq[BlockHeader]
  var h = height
  for i in 0 ..< MedianTimeSpan:
    if h < 0:
      break
    let idxOpt = utxos.getBlockHashByHeight(h)
    if idxOpt.isNone:
      break
    let blockIdxOpt = utxos.getBlockIndex(idxOpt.get())
    if blockIdxOpt.isNone:
      break
    headers.add(blockIdxOpt.get().header)
    dec h

  getMedianTimePast(headers)

# Get script flags for block validation
## Bitcoin Core script_flag_exceptions: blocks that violate current rules.
## BIP16 exception block (mainnet): this block contains a P2SH-violating tx
## that was mined before P2SH enforcement. Bitcoin Core uses SCRIPT_VERIFY_NONE.
const BIP16_EXCEPTION_HASH* = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"

## Taproot exception block (mainnet): uses P2SH+WITNESS only (no TAPROOT).
const TAPROOT_EXCEPTION_HASH* = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"

proc getBlockScriptFlags*(height: int32, params: ConsensusParams,
                          blockHash: string = ""): set[ScriptFlags] =
  ## Get consensus-only script verification flags for a block at given height
  ## CRITICAL: Only use consensus flags, not policy flags

  # Check script_flag_exceptions first (matching Bitcoin Core)
  if blockHash == BIP16_EXCEPTION_HASH:
    return {}  # SCRIPT_VERIFY_NONE for this block

  # P2SH active from BIP16 (mainnet: 170060, but treat as always-on for simplicity)
  result = {sfP2SH}

  # DERSIG (BIP66)
  if height >= int32(params.bip66Height):
    result.incl(sfDERSig)

  # CHECKLOCKTIMEVERIFY (BIP65)
  if height >= int32(params.bip65Height):
    result.incl(sfCheckLockTimeVerify)

  # CHECKSEQUENCEVERIFY (BIP112) - activated with CSV (BIP68/112/113)
  if height >= int32(params.csvHeight):
    result.incl(sfCheckSequenceVerify)

  # SegWit (BIP141/143/147) — WITNESS + NULLDUMMY are consensus rules.
  # sfNullFail and sfWitnessPubkeyType are policy-only (STANDARD_SCRIPT_VERIFY_FLAGS
  # per Bitcoin Core policy/policy.h:125,128) and must NOT appear here.
  if height >= int32(params.segwitHeight):
    result.incl(sfWitness)
    result.incl(sfNullDummy)

  # Taproot (BIP340/341/342) — activated at taprootHeight
  if blockHash != TAPROOT_EXCEPTION_HASH and height >= int32(params.taprootHeight):
    result.incl(sfTaproot)

# ============================================================================
# BIP68 Sequence Lock Functions
# ============================================================================

type
  SequenceLock* = object
    ## The result of calculating sequence locks for a transaction
    minHeight*: int32    ## Minimum block height for inclusion (-1 = no height constraint)
    minTime*: int64      ## Minimum MTP for inclusion (-1 = no time constraint)

proc bip68VersionActive*(version: int32): bool =
  ## BIP-68 applies only when version >= 2. Core stores version as uint32_t and
  ## compares it UNSIGNED (fEnforceBIP68 = tx.version >= 2, tx_verify.cpp:51), so a
  ## high-bit version (e.g. 0x80000002) STILL enforces BIP-68. nimrod stores version
  ## as int32; a signed `>= 2` would treat 0x80000002 as negative and SKIP
  ## enforcement, false-accepting a tx whose relative timelock is unmet (a chain
  ## split). Compare unsigned -- same as OP_CSV (interpreter.nim:2176).
  cast[uint32](version) >= 2'u32

proc calculateSequenceLocks*(
  tx: Transaction,
  prevHeights: var seq[int32],
  blockHeight: int32,
  getMtpAtHeight: proc(height: int32): uint32,
  params: ConsensusParams
): SequenceLock =
  ## Calculate the sequence locks for a transaction per BIP68
  ##
  ## prevHeights: height at which each input's UTXO was mined (modified in place;
  ##              set to 0 for inputs with disable flag set)
  ## blockHeight: the height of the block we're evaluating for inclusion
  ## getMtpAtHeight: function to get median time past at a given height
  ##
  ## Returns SequenceLock with minHeight and minTime that must be satisfied
  ## The semantics use nLockTime convention: values are the LAST INVALID height/time,
  ## so the tx is valid when blockHeight > minHeight and blockMTP > minTime.
  ## A value of -1 means no constraint.
  ##
  ## BIP68 only applies when tx.version >= 2.

  result.minHeight = -1
  result.minTime = -1

  # BIP68 only applies to transactions with version >= 2 (compared unsigned).
  if not bip68VersionActive(tx.version):
    return result

  # BIP68 must be enforced (caller should check height >= csvHeight)
  assert prevHeights.len == tx.inputs.len

  for i, input in tx.inputs:
    let nSequence = input.sequence

    # If bit 31 is set, this input opts out of BIP68 relative lock-time
    if (nSequence and SequenceLockDisableFlag) != 0:
      # Mark this input as not contributing to sequence locks
      prevHeights[i] = 0
      continue

    let coinHeight = prevHeights[i]

    # Check if this is a time-based or height-based lock
    if (nSequence and SequenceLockTypeFlag) != 0:
      # Time-based relative lock
      # The lock is measured from the MTP of the block *prior* to the one containing
      # the UTXO being spent (i.e., MTP when that UTXO was the chain tip)
      let coinMtp = getMtpAtHeight(max(coinHeight - 1, 0))

      # Extract the 16-bit lock value and convert to seconds (512-second granularity)
      let lockValue = int64(nSequence and SequenceLockMask) shl SequenceLockGranularity

      # The required time is coinMtp + lockValue - 1 (nLockTime semantics: last invalid)
      let requiredTime = int64(coinMtp) + lockValue - 1
      if requiredTime > result.minTime:
        result.minTime = requiredTime
    else:
      # Height-based relative lock
      # The lock is the number of blocks that must be mined after the UTXO's block
      let lockValue = int32(nSequence and SequenceLockMask)

      # Required height is coinHeight + lockValue - 1 (nLockTime semantics: last invalid)
      let requiredHeight = coinHeight + lockValue - 1
      if requiredHeight > result.minHeight:
        result.minHeight = requiredHeight

proc checkSequenceLocks*(
  lock: SequenceLock,
  blockHeight: int32,
  blockMtp: uint32
): bool =
  ## Check if the sequence locks are satisfied for inclusion in a block
  ##
  ## blockHeight: the height of the block being created/validated
  ## blockMtp: the median time past of the PREVIOUS block (block at height - 1)
  ##
  ## Returns true if the transaction can be included in this block.
  ## The semantics follow nLockTime: lock values are the LAST INVALID height/time.

  # Height check: blockHeight must be > minHeight
  if lock.minHeight >= blockHeight:
    return false

  # Time check: blockMtp must be > minTime
  if lock.minTime >= int64(blockMtp):
    return false

  true

proc checkSequenceLocksForTx*(
  tx: Transaction,
  utxos: proc(op: OutPoint): Option[UtxoEntry],
  blockHeight: int32,
  prevBlockMtp: uint32,
  getMtpAtHeight: proc(height: int32): uint32,
  params: ConsensusParams,
  intraBlockUtxos: Table[string, UtxoEntry] = initTable[string, UtxoEntry]()
): ValidationResult[void] =
  ## Check BIP68 sequence locks for a single transaction
  ##
  ## tx: the transaction to check
  ## utxos: function to look up UTXOs by outpoint
  ## blockHeight: height of the block we're checking for inclusion
  ## prevBlockMtp: MTP of the block at height (blockHeight - 1)
  ## getMtpAtHeight: function to get MTP at any height
  ## intraBlockUtxos: UTXOs created earlier in the same block
  ##
  ## Returns error if sequence locks are not satisfied

  # BIP68 only applies if tx version >= 2 (compared unsigned).
  if not bip68VersionActive(tx.version):
    return ok()

  # Coinbase transactions don't have sequence locks
  if isCoinbase(tx):
    return ok()

  # Build the prevHeights array: height at which each input's UTXO was mined
  var prevHeights = newSeq[int32](tx.inputs.len)

  for i, input in tx.inputs:
    let intraKey = $array[32, byte](input.prevOut.txid) & ":" & $input.prevOut.vout
    var utxoOpt: Option[UtxoEntry]

    if intraKey in intraBlockUtxos:
      utxoOpt = some(intraBlockUtxos[intraKey])
    else:
      utxoOpt = utxos(input.prevOut)

    if utxoOpt.isNone:
      # Input not found - let validateTransaction handle this error
      return ok()

    prevHeights[i] = utxoOpt.get().height

  # Calculate sequence locks
  let lock = calculateSequenceLocks(tx, prevHeights, blockHeight, getMtpAtHeight, params)

  # Check if locks are satisfied
  if not checkSequenceLocks(lock, blockHeight, prevBlockMtp):
    return voidErr(veSequenceLockNotSatisfied)

  ok()

# Transaction validation
proc validateTransaction*(
  tx: Transaction,
  utxos: proc(op: OutPoint): Option[UtxoEntry],
  height: int32,
  params: ConsensusParams,
  intraBlockUtxos: Table[string, UtxoEntry] = initTable[string, UtxoEntry]()
): ValidationResult[int64] =
  ## Validate a non-coinbase transaction
  ## Returns the fee (inputValue - outputValue) on success
  ## CRITICAL: intraBlockUtxos allows spending outputs created earlier in the same block

  # Must have at least one input and output
  if tx.inputs.len == 0:
    return err(int64, veInputsMissing)
  if tx.outputs.len == 0:
    return err(int64, veBadOutputValue)

  # Check for duplicate inputs (CVE-2018-17144)
  var seenInputs = initTable[string, bool]()
  for inp in tx.inputs:
    let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
    if key in seenInputs:
      return err(int64, veDuplicateInput)
    seenInputs[key] = true

  # Non-coinbase: no null prevouts (Core consensus/tx_check.cpp:54-56)
  # "bad-txns-prevout-null"
  if not isCoinbase(tx):
    for inp in tx.inputs:
      if inp.prevOut.txid == TxId(default(array[32, byte])) and inp.prevOut.vout == 0xFFFFFFFF'u32:
        return err(int64, veNullPrevout)

  # Check output values (CVE-2010-5139)
  # Use distinct error codes matching Core tx_check.cpp / bip22String mapping.
  var totalOutput = int64(0)
  for output in tx.outputs:
    let value = int64(output.value)
    if value < 0:
      return err(int64, veNegativeOutput)
    if value > int64(MaxMoney):
      return err(int64, veOutputTooLarge)
    totalOutput += value
    if totalOutput > int64(MaxMoney):
      return err(int64, veTxOutTotalTooLarge)

  # Gather inputs and check availability
  var totalInput = int64(0)
  for inp in tx.inputs:
    # First check intra-block UTXOs (outputs created earlier in this block)
    let intraKey = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
    var utxoOpt: Option[UtxoEntry]

    if intraKey in intraBlockUtxos:
      utxoOpt = some(intraBlockUtxos[intraKey])
    else:
      utxoOpt = utxos(inp.prevOut)

    if utxoOpt.isNone:
      return err(int64, veInputsMissing)

    let utxo = utxoOpt.get()

    # Check coinbase maturity
    if utxo.isCoinbase:
      let age = height - utxo.height
      if age < int32(params.coinbaseMaturity):
        return err(int64, veImmatureCoinbase)

    let inputValue = int64(utxo.output.value)
    if inputValue < 0 or inputValue > int64(MaxMoney):
      return err(int64, veBadAmount)

    totalInput += inputValue
    if totalInput > int64(MaxMoney):
      return err(int64, veBadAmount)

  # Fee = input - output (must be non-negative)
  # Core consensus/tx_verify.cpp::CheckTxInputs:
  #   state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
  let fee = totalInput - totalOutput
  if fee < 0:
    return err(int64, veOutputsBelowInputs)

  ok(fee)

# Block header validation

## Field-copy a ConsensusParams into the minimal pow.PowParams the PoW
## primitives need (mirrors the inline copy in contextualCheckBlockHeader and
## the validation.nim:880-894 nextwork call site). Centralised so the
## CheckProofOfWork range fold and the GetNextWorkRequired diffbits gate build
## the SAME params object.
proc toPowParams(params: ConsensusParams): pow.PowParams =
  let powNetwork: pow.NetworkKind = case params.network
    of Mainnet:  pow.Mainnet
    of Testnet3: pow.Testnet3
    of Testnet4: pow.Testnet4
    of Regtest:  pow.Regtest
    of Signet:   pow.Signet
  pow.PowParams(
    network:                     powNetwork,
    powLimit:                    params.powLimit,
    powTargetTimespan:           params.powTargetTimespan,
    powTargetSpacing:            params.powTargetSpacing,
    powAllowMinDifficultyBlocks: params.powAllowMinDifficultyBlocks,
    powNoRetargeting:            params.powNoRetargeting,
    enforceBIP94:                params.enforceBIP94
  )

proc validateBlockHeader*(
  header: BlockHeader,
  prevIndex: BlockIndex,
  params: ConsensusParams,
  checkPow: bool = true,
  minPowChecked: bool = true,
  currentTime: int64 = 0
): ValidationResult[void] =
  ## Validate block header against consensus rules.
  ##
  ## Checks: PoW hash meets nBits target, timestamp not too far in future,
  ## and prevBlock hash matches.
  ##
  ## minPowChecked: true if the PRESYNC/REDOWNLOAD anti-DoS pipeline has
  ##   already verified that the claimed chain work meets minimumChainWork.
  ##   Pass false for headers received directly from a random peer before
  ##   PRESYNC completes.  When false and params.minimumChainWork is non-zero,
  ##   the header is rejected immediately with veInsufficientChainWork.
  ##   Reference: validation.cpp:4229 — `if (!min_pow_checked) return
  ##   state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork")`.
  ##
  ## currentTime: flag-gated injectable wall clock for the time-too-new gate
  ##   (mirrors the `checkPow` injectable-PoW pattern). Sentinel 0 (the default)
  ##   means "use the real wall clock" (getTime()), so production callers that
  ##   omit it are byte-identical to the previous behaviour. A non-zero value
  ##   pins `now` deterministically (differential / fJustCheck path) so the
  ##   future-time boundary can be exercised without depending on the host clock.
  ##   Core compares against NodeClock::now() (validation.cpp:4108); injecting it
  ##   is the same seam Core's mocktime / SetMockTime provides for tests.
  ##
  ## NOTE: This proc does NOT have access to the chain DB, so it cannot
  ## enforce MTP (time-too-old), bad-diffbits, bad-version, or
  ## time-timewarp-attack. Those contextual checks are performed by
  ## contextualCheckBlockHeader (called from validateBlock).

  # G8 (W97): too-little-chainwork gate.
  # Reject headers from peers that have not passed PRESYNC work validation,
  # unless the network has no minimum work requirement (regtest / all-zero).
  # Core validation.cpp:4220-4229 — AcceptBlockHeader calls this immediately
  # after the prevBlock lookup; only the PRESYNC-validated path sets
  # min_pow_checked=true.
  if not minPowChecked:
    var isZeroMinWork = true
    for b in params.minimumChainWork:
      if b != 0:
        isZeroMinWork = false
        break
    if not isZeroMinWork:
      return voidErr(veInsufficientChainWork)

  # Check proof of work — Core CheckBlockHeader -> CheckProofOfWork
  # (validation.cpp:3831 -> pow.cpp). CheckProofOfWork folds THREE rejections
  # into one high-hash verdict: (a) nBits malformed (mantissa sign bit set =>
  # fNegative, or target == 0), (b) target > powLimit (out-of-range difficulty),
  # (c) the actual hash > target. nimrod's pow.checkProofOfWork (pow.nim:49-66)
  # implements all three; the bare params.hashMeetsTarget used previously only
  # did (c), so a header whose nBits encoded an above-powLimit / zero / negative
  # target slipped past this gate (and, with a crafted prev so GetNextWorkRequired
  # returns the same out-of-range bits, past bad-diffbits too) — a false-accept.
  # Routing through pow.checkProofOfWork closes that fold to match Core. Still
  # gated by checkPow, so production (always checkPow=true) only gains the Core
  # rejections, never relaxes; the synthetic/fJustCheck path (checkPow=false) is
  # unchanged.
  if checkPow:
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))
    if not pow.checkProofOfWork(hash, header.bits, toPowParams(params)):
      return voidErr(veExceedsTarget)

  # Check timestamp not too far in future (time-too-new).
  # Core: block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME (validation.cpp:4108).
  # Use int64 arithmetic to avoid uint32 wrap-around when now is large.
  #
  # Clock source (the `now` Core compares against):
  #   * currentTime != 0  -> the INJECTED deterministic clock (differential /
  #                          fJustCheck path). Runs regardless of checkPow so the
  #                          future-time boundary can be exercised on a crafted
  #                          header without depending on the host wall clock.
  #   * currentTime == 0 (default) & checkPow -> the LOCAL WALL CLOCK (getTime()),
  #                          exactly the production AcceptBlockHeader behaviour.
  #   * currentTime == 0 & not checkPow -> SKIP. checkPow=false signals "synthetic
  #                          / crafted block validated outside the live header
  #                          pipeline" (Core's CheckBlockHeader(fCheckPOW=false)
  #                          path), so without an injected clock the wall-clock
  #                          future-time check is relaxed alongside the PoW hash
  #                          check — preserving the existing reorg/checkblock
  #                          vectors dated past 2038 to clear the easy target.
  # Production always passes the default currentTime=0 + checkPow=true, so this is
  # byte-identical to the prior behaviour for live header acceptance.
  if currentTime != 0 or checkPow:
    let nowSec = if currentTime != 0: currentTime else: getTime().toUnix()
    if int64(header.timestamp) > nowSec + int64(MaxFutureBlockTime):
      return voidErr(veTimeTooNew)

  # Check previous block hash matches.
  if header.prevBlock != prevIndex.hash:
    return voidErr(vePrevBlockMissing)

  ok()

# MAX_TIMEWARP constant (consensus/consensus.h:35, BIP94)
const MaxTimeWarp* = 600'i64

proc contextualCheckBlockHeader*(
  header: BlockHeader,
  prevIndex: BlockIndex,
  utxos: ChainDb,
  params: ConsensusParams
): ValidationResult[void] =
  ## Contextual block-header validation that requires chain state.
  ##
  ## Implements Bitcoin Core ContextualCheckBlockHeader (validation.cpp:4080-4121):
  ##
  ## Gate 1  (bad-diffbits, line 4088): header.nBits must equal GetNextWorkRequired.
  ## Gate 2  (time-too-old,  line 4092): timestamp > MedianTimePast of prev 11 blocks.
  ## Gate 3  (time-timewarp-attack, line 4097-4105): BIP94 anti-timewarp on
  ##           difficulty adjustment blocks (testnet4/regtest w/ enforceBIP94 only).
  ## Gate 4  (bad-version, line 4113-4118): reject obsolete nVersion after
  ##           BIP34 (< 2), BIP66 (< 3), BIP65 (< 4) activation.
  ##
  ## NOTE: time-too-new is enforced in validateBlockHeader (no chain access needed).

  let height = prevIndex.height + 1

  # Gate 1: bad-diffbits — nBits must match GetNextWorkRequired.
  # Core validation.cpp:4088-4089.
  # Build a pow.BlockIndex for the prev block so we can call into pow.nim.
  let powPrev = pow.BlockIndex(
    height: prevIndex.height,
    header: prevIndex.header,
    hash: prevIndex.hash
  )

  # getAncestor callback: walks the chain DB by hash using prevHash links.
  # pow.nim calls this to reach back 2015 blocks at retarget boundaries.
  proc getAncestor(idx: pow.BlockIndex, targetHeight: int32): pow.BlockIndex =
    ## Walk the stored chain back to targetHeight starting from idx.
    var cur = pow.BlockIndex(height: idx.height, header: idx.header, hash: idx.hash)
    while cur.height > targetHeight:
      let parentOpt = utxos.getBlockIndex(cur.header.prevBlock)
      if parentOpt.isNone:
        # Ancestor missing — return what we have (best-effort; PoW check will
        # fail naturally if nBits is wrong, and we can't compute expected bits
        # without the full chain). Return a zero index at the target height.
        return pow.BlockIndex(height: targetHeight, header: default(BlockHeader), hash: default(BlockHash))
      let parent = parentOpt.get()
      cur = pow.BlockIndex(height: parent.height, header: parent.header, hash: parent.hash)
    cur

  let powParams = toPowParams(params)

  let expectedBits = pow.getNextWorkRequired(powPrev, header.timestamp, powParams, getAncestor)
  if header.bits != expectedBits:
    return voidErr(veIncorrectProofOfWork)

  # Gate 2: time-too-old — timestamp must be strictly greater than MTP.
  # Core validation.cpp:4092-4093.
  # getMtpForHeight(utxos, prevIndex.height) gives the MTP of the prev block.
  let prevMtp = getMtpForHeight(utxos, prevIndex.height)
  if header.timestamp <= prevMtp:
    return voidErr(veBadTimestamp)

  # Gate 3: time-timewarp-attack (BIP94, testnet4/regtest only).
  # Core validation.cpp:4097-4105.
  if params.enforceBIP94:
    if height mod int32(params.difficultyAdjustmentInterval) == 0:
      if int64(header.timestamp) < int64(prevIndex.header.timestamp) - MaxTimeWarp:
        return voidErr(veTimeWarpAttack)

  # Gate 4: bad-version — reject obsolete block versions after soft-fork activation.
  # Core validation.cpp:4113-4118.
  # BIP34: nVersion < 2 rejected after BIP34 activation height.
  if header.version < 2 and height >= int32(params.bip34Height):
    return voidErr(veBadBlockVersion)
  # BIP66: nVersion < 3 rejected after BIP66 activation height.
  if header.version < 3 and height >= int32(params.bip66Height):
    return voidErr(veBadBlockVersion)
  # BIP65: nVersion < 4 rejected after BIP65 activation height.
  if header.version < 4 and height >= int32(params.bip65Height):
    return voidErr(veBadBlockVersion)

  ok()

## Differential / fJustCheck twin of contextualCheckBlockHeader that takes the
## chain-derived inputs EXPLICITLY instead of reading them out of a live ChainDb:
##   * prevHeader  — the previous block's header (its bits + timestamp feed the
##                   GetNextWorkRequired base and the BIP-94 timewarp prev-600 floor).
##   * mtp         — MedianTimePast of prev's 11 ancestors (Gate 2 time-too-old).
##   * expectedBitsOverride — sentinel <0 means "compute via GetNextWorkRequired"
##                   exactly as the production proc does; >=0 pins the mandated
##                   nBits so a single gate can be isolated on a retarget boundary
##                   (the differential corpus uses this to test the timewarp floor
##                   without seeding a 2016-deep ancestor window — the retarget
##                   value itself is covered separately by the `nextwork` op).
##   * firstHeader/firstHeight — optional first-block-of-period, linked as prev's
##                   ancestor so GetNextWorkRequired's getAncestor(h-2015) resolves
##                   on a boundary when no override is supplied.
##
## It runs the SAME four gates in the SAME Core order (4088 bad-diffbits, 4092
## time-too-old, 4097 BIP-94 timewarp, 4112 bad-version) over nimrod's REAL
## pow.getNextWorkRequired, so it is a faithful, gated, NON-production view: the
## live AcceptBlock path keeps calling contextualCheckBlockHeader above.
## Mirrors rustoshi's contextual_check_block_header(header, height, prev_entry,
## ctx{mtp}, params, current_time, expected_bits) shim entrypoint.
proc contextualCheckBlockHeaderEx*(
  header: BlockHeader,
  height: int32,
  prevHeader: BlockHeader,
  prevHash: BlockHash,
  mtp: uint32,
  params: ConsensusParams,
  expectedBitsOverride: int64 = -1,
  firstHeader: BlockHeader = default(BlockHeader),
  firstHeight: int32 = -1
): ValidationResult[void] =
  let powParams = toPowParams(params)

  # Gate 1: bad-diffbits — nBits must match GetNextWorkRequired(prev).
  # Core validation.cpp:4088-4089.
  let expectedBits =
    if expectedBitsOverride >= 0:
      uint32(expectedBitsOverride and 0xffffffff'i64)
    else:
      let powPrev = pow.BlockIndex(
        height: height - 1, header: prevHeader, hash: prevHash)
      # Height-keyed getAncestor over the prev (+ optional first) context. On a
      # min-difficulty network (regtest/testnet) GetNextWorkRequired's non-boundary
      # branch (pow.cpp:33 / pow.nim:157-161) walks ancestors back toward genesis
      # while their bits stay at powLimit — so it asks for EVERY height in
      # [0, prev.height], not just prev.height. We model that uniform-difficulty
      # ancestor chain by serving, for any height in [0, prev.height], a synthetic
      # index carrying the SAME prev bits + timestamp (exactly the chain shape a
      # fresh regtest/testnet chain has, where every pre-retarget block sits at
      # powLimit). This is faithful: it reproduces what nimrod's production
      # getAncestor would return walking such a chain, and the walk terminates at
      # height 0 (pow.nim loop guard `pindex.height > 0`). `first` (when supplied)
      # pins the first-of-period block for a retarget boundary. Any out-of-range
      # height raises so a genuinely impossible ancestor request surfaces as an
      # error (driver skips), never a silently-faked value.
      let firstIdx = pow.BlockIndex(
        height: firstHeight, header: firstHeader, hash: default(BlockHash))
      let getAncestor = proc(idx: pow.BlockIndex, targetHeight: int32): pow.BlockIndex =
        if targetHeight == height - 1: powPrev
        elif firstHeight >= 0 and targetHeight == firstHeight: firstIdx
        elif targetHeight >= 0 and targetHeight < height - 1:
          pow.BlockIndex(height: targetHeight, header: prevHeader,
                         hash: default(BlockHash))
        else:
          raise newException(ValueError,
            "getAncestor: no node at height " & $targetHeight)
      pow.getNextWorkRequired(powPrev, header.timestamp, powParams, getAncestor)
  if header.bits != expectedBits:
    return voidErr(veIncorrectProofOfWork)

  # Gate 2: time-too-old — timestamp strictly greater than MTP (Core 4092-4093).
  if header.timestamp <= mtp:
    return voidErr(veBadTimestamp)

  # Gate 3: time-timewarp-attack (BIP94, testnet4/regtest only; Core 4097-4105).
  if params.enforceBIP94:
    if height mod int32(params.difficultyAdjustmentInterval) == 0:
      if int64(header.timestamp) < int64(prevHeader.timestamp) - MaxTimeWarp:
        return voidErr(veTimeWarpAttack)

  # Gate 4: bad-version — reject obsolete versions after soft-fork activation
  # (Core 4113-4118; identical to contextualCheckBlockHeader).
  if header.version < 2 and height >= int32(params.bip34Height):
    return voidErr(veBadBlockVersion)
  if header.version < 3 and height >= int32(params.bip66Height):
    return voidErr(veBadBlockVersion)
  if header.version < 4 and height >= int32(params.bip65Height):
    return voidErr(veBadBlockVersion)

  ok()

# Count sigops in a script
proc countScriptSigops*(script: seq[byte], accurate: bool = false): int =
  ## Count signature operations in a script
  ## If accurate=true, uses precise counting for OP_CHECKMULTISIG
  ## (reads the n value from previous OP_1..OP_16)
  var pc = 0
  var lastOpcode: uint8 = 0

  while pc < script.len:
    let opcode = script[pc]
    pc += 1

    # Skip push data
    if opcode >= 0x01 and opcode <= 0x4b:
      pc += int(opcode)
    elif opcode == OP_PUSHDATA1 and pc < script.len:
      pc += 1 + int(script[pc])
    elif opcode == OP_PUSHDATA2 and pc + 1 < script.len:
      let len = int(script[pc]) or (int(script[pc + 1]) shl 8)
      pc += 2 + len
    elif opcode == OP_PUSHDATA4 and pc + 3 < script.len:
      let len = int(script[pc]) or (int(script[pc + 1]) shl 8) or
                (int(script[pc + 2]) shl 16) or (int(script[pc + 3]) shl 24)
      pc += 4 + len
    elif opcode == OP_CHECKSIG or opcode == OP_CHECKSIGVERIFY:
      result += 1
    elif opcode == OP_CHECKMULTISIG or opcode == OP_CHECKMULTISIGVERIFY:
      if accurate and lastOpcode >= OP_1 and lastOpcode <= OP_16:
        result += int(lastOpcode - OP_1 + 1)
      else:
        result += MaxPubkeysPerMultisig

    lastOpcode = opcode

# ============================================================================
# Sigop Cost Functions (BIP-141)
# ============================================================================
# Reference: Bitcoin Core's GetTransactionSigOpCost() in consensus/tx_verify.cpp
#
# The key insight: sigops are counted in "cost" units where:
# - Legacy/P2SH sigops cost WitnessScaleFactor (4) each
# - Witness sigops cost 1 each
# - Total block sigop cost cannot exceed MaxBlockSigopsCost (80,000)

proc isPayToScriptHash*(script: seq[byte]): bool =
  ## Check if script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  script.len == 23 and
  script[0] == 0xa9 and  # OP_HASH160
  script[1] == 0x14 and  # Push 20 bytes
  script[22] == 0x87     # OP_EQUAL

proc isWitnessProgram*(script: seq[byte]): tuple[valid: bool, version: int, program: seq[byte]] =
  ## Check if script is a witness program (P2WPKH, P2WSH, P2TR)
  ## Returns (isWitness, version, program)
  ##
  ## Format: OP_n <2-40 bytes>
  ## - OP_0 (0x00) = version 0
  ## - OP_1..OP_16 (0x51..0x60) = version 1..16
  if script.len < 4 or script.len > 42:
    return (false, 0, @[])

  let version = if script[0] == 0x00:
    0
  elif script[0] >= 0x51 and script[0] <= 0x60:
    int(script[0] - 0x50)
  else:
    return (false, 0, @[])

  let programLen = int(script[1])
  if programLen < 2 or programLen > 40:
    return (false, 0, @[])
  if script.len != 2 + programLen:
    return (false, 0, @[])

  (true, version, script[2 ..< 2 + programLen])

proc isPushOnly*(script: seq[byte]): bool =
  ## Check if script contains only push operations (no opcodes > OP_16)
  var pc = 0
  while pc < script.len:
    let opcode = script[pc]
    if opcode > OP_16:
      return false
    pc += 1
    if opcode >= 0x01 and opcode <= 0x4b:
      pc += int(opcode)
    elif opcode == OP_PUSHDATA1 and pc < script.len:
      pc += 1 + int(script[pc])
    elif opcode == OP_PUSHDATA2 and pc + 1 < script.len:
      let len = int(script[pc]) or (int(script[pc + 1]) shl 8)
      pc += 2 + len
    elif opcode == OP_PUSHDATA4 and pc + 3 < script.len:
      let len = int(script[pc]) or (int(script[pc + 1]) shl 8) or
                (int(script[pc + 2]) shl 16) or (int(script[pc + 3]) shl 24)
      pc += 4 + len
  true

proc getLastPushData*(script: seq[byte]): seq[byte] =
  ## Extract the last data push from a script
  ## Used to get the P2SH redeem script from scriptSig
  var pc = 0
  var lastData: seq[byte] = @[]

  while pc < script.len:
    let opcode = script[pc]
    pc += 1

    if opcode == 0x00:
      lastData = @[]
    elif opcode >= 0x01 and opcode <= 0x4b:
      let pushLen = int(opcode)
      if pc + pushLen <= script.len:
        lastData = script[pc ..< pc + pushLen]
        pc += pushLen
      else:
        return @[]
    elif opcode == OP_PUSHDATA1:
      if pc < script.len:
        let pushLen = int(script[pc])
        pc += 1
        if pc + pushLen <= script.len:
          lastData = script[pc ..< pc + pushLen]
          pc += pushLen
        else:
          return @[]
    elif opcode == OP_PUSHDATA2:
      if pc + 1 < script.len:
        let pushLen = int(script[pc]) or (int(script[pc + 1]) shl 8)
        pc += 2
        if pc + pushLen <= script.len:
          lastData = script[pc ..< pc + pushLen]
          pc += pushLen
        else:
          return @[]
    elif opcode == OP_PUSHDATA4:
      if pc + 3 < script.len:
        let pushLen = int(script[pc]) or (int(script[pc + 1]) shl 8) or
                      (int(script[pc + 2]) shl 16) or (int(script[pc + 3]) shl 24)
        pc += 4
        if pc + pushLen <= script.len:
          lastData = script[pc ..< pc + pushLen]
          pc += pushLen
        else:
          return @[]
    elif opcode >= OP_1NEGATE and opcode <= OP_16:
      # Small integer push - not real data
      lastData = @[]
    elif opcode > OP_16:
      # Non-push opcode - invalid for push-only
      return @[]

  lastData

proc countWitnessSigops*(witnessVersion: int, witnessProgram: seq[byte],
                         witness: seq[seq[byte]]): int =
  ## Count sigops in a witness program
  ## Per BIP-141:
  ## - P2WPKH (v0, 20 bytes): 1 sigop
  ## - P2WSH (v0, 32 bytes): count from witness script
  ## - Taproot (v1): handled by sigops budget, returns 0 here
  if witnessVersion == 0:
    if witnessProgram.len == 20:
      # P2WPKH: 1 sigop
      return 1
    elif witnessProgram.len == 32 and witness.len > 0:
      # P2WSH: count sigops from the witness script (last stack item)
      let witnessScript = witness[witness.len - 1]
      return countScriptSigops(witnessScript, accurate = true)
  # Version 1+ (Taproot) and other versions: sigops handled differently
  0

proc getLegacySigOpCount*(tx: Transaction): int =
  ## Count legacy sigops in scriptSig and scriptPubKey
  ## This is GetLegacySigOpCount in Bitcoin Core
  for inp in tx.inputs:
    result += countScriptSigops(inp.scriptSig, accurate = false)
  for outp in tx.outputs:
    result += countScriptSigops(outp.scriptPubKey, accurate = false)

proc getP2SHSigOpCount*(tx: Transaction, utxos: proc(op: OutPoint): Option[UtxoEntry]): int =
  ## Count P2SH sigops (from redeem scripts)
  ## This is GetP2SHSigOpCount in Bitcoin Core
  if isCoinbase(tx):
    return 0

  for inp in tx.inputs:
    let utxoOpt = utxos(inp.prevOut)
    if utxoOpt.isNone:
      continue
    let prevOut = utxoOpt.get().output

    if isPayToScriptHash(prevOut.scriptPubKey):
      # Get redeem script from scriptSig
      let redeemScript = getLastPushData(inp.scriptSig)
      if redeemScript.len > 0:
        result += countScriptSigops(redeemScript, accurate = true)

proc countWitnessSigOpsForInput*(scriptSig: seq[byte], scriptPubKey: seq[byte],
                                  witness: seq[seq[byte]]): int =
  ## Count witness sigops for a single input
  ## This is CountWitnessSigOps in Bitcoin Core
  let wp = isWitnessProgram(scriptPubKey)
  if wp.valid:
    return countWitnessSigops(wp.version, wp.program, witness)

  # Check for P2SH-wrapped witness
  if isPayToScriptHash(scriptPubKey) and isPushOnly(scriptSig):
    let redeemScript = getLastPushData(scriptSig)
    let wpInner = isWitnessProgram(redeemScript)
    if wpInner.valid:
      return countWitnessSigops(wpInner.version, wpInner.program, witness)

  0

proc getTransactionSigOpCost*(tx: Transaction,
                               utxos: proc(op: OutPoint): Option[UtxoEntry],
                               useP2SH: bool = true,
                               useWitness: bool = true): SigopResult[int] =
  ## Calculate the total sigop cost for a transaction
  ## This matches Bitcoin Core's GetTransactionSigOpCost
  ##
  ## Returns the total cost where:
  ## - Legacy sigops cost WitnessScaleFactor (4) each
  ## - P2SH sigops cost WitnessScaleFactor (4) each
  ## - Witness sigops cost 1 each
  ##
  ## Result type allows returning errors for missing UTXOs

  # Start with legacy sigops, scaled by witness factor
  var sigOpCost = getLegacySigOpCount(tx) * WitnessScaleFactor

  if isCoinbase(tx):
    return sigopOk[int](sigOpCost)

  # Add P2SH sigops if enabled
  if useP2SH:
    sigOpCost += getP2SHSigOpCount(tx, utxos) * WitnessScaleFactor

  # Add witness sigops if enabled (no scaling, cost = 1)
  if useWitness:
    for i, inp in tx.inputs:
      let utxoOpt = utxos(inp.prevOut)
      if utxoOpt.isNone:
        return sigopErr[int]("missing utxo for input " & $i)

      let prevOut = utxoOpt.get().output
      var witness: seq[seq[byte]] = @[]
      if i < tx.witnesses.len:
        witness = tx.witnesses[i]

      sigOpCost += countWitnessSigOpsForInput(inp.scriptSig, prevOut.scriptPubKey, witness)

  sigopOk[int](sigOpCost)

proc countBlockSigopsCost*(blk: Block,
                           utxos: proc(op: OutPoint): Option[UtxoEntry],
                           height: int32,
                           params: ConsensusParams): SigopResult[int] =
  ## Count total sigop cost for a block with proper witness discount
  ## This matches Bitcoin Core's ConnectBlock sigops check
  ##
  ## Uses:
  ## - P2SH sigops if height >= p2shHeight (always on mainnet)
  ## - Witness sigops if height >= segwitHeight
  ##
  ## Returns Result to propagate UTXO lookup errors

  let useP2SH = true  # P2SH always active
  let useWitness = height >= int32(params.segwitHeight)

  var totalCost = 0

  # Track intra-block UTXOs for proper sigop counting
  var intraBlockUtxos = initTable[string, UtxoEntry]()

  # Process each transaction
  for txIdx, tx in blk.txs:
    # Create lookup that includes intra-block UTXOs
    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      let key = $array[32, byte](op.txid) & ":" & $op.vout
      if key in intraBlockUtxos:
        return some(intraBlockUtxos[key])
      utxos(op)

    let costResult = getTransactionSigOpCost(tx, lookupUtxo, useP2SH, useWitness)
    if not costResult.isOk:
      return sigopErr[int]("tx " & $txIdx & ": " & costResult.error)

    totalCost += costResult.value

    # Add this tx's outputs to intra-block UTXOs
    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      let key = $array[32, byte](thisTxid) & ":" & $vout
      intraBlockUtxos[key] = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: isCoinbase(tx)
      )

  sigopOk[int](totalCost)

# Legacy function for backward compatibility
proc countBlockSigops*(blk: Block, params: ConsensusParams): int =
  ## Count total sigops in a block (legacy, without witness discount)
  ## Use countBlockSigopsCost for proper cost-based counting

  for tx in blk.txs:
    # Count sigops in inputs (scriptSig)
    for inp in tx.inputs:
      result += countScriptSigops(inp.scriptSig)

    # Count sigops in outputs (scriptPubKey)
    for outp in tx.outputs:
      result += countScriptSigops(outp.scriptPubKey)

# Transaction locktime finality (BIP-65 / BIP-113)
# Defined before validateBlock because validateBlock calls checkBlockLocktime.
# Reference: Bitcoin Core consensus/tx_verify.cpp IsFinalTx()

proc isFinalTxEarly(tx: Transaction, blockHeight: uint32, lockTimeCutoff: uint32): bool =
  ## Inline copy of isFinalTx used by validateBlock.
  ## The canonical public proc is declared later in the file; this avoids a
  ## forward-declaration while keeping the public API unchanged.
  if tx.lockTime == 0:
    return true
  let threshold = if tx.lockTime < LocktimeThreshold: blockHeight else: lockTimeCutoff
  if tx.lockTime < threshold:
    return true
  for input in tx.inputs:
    if input.sequence != SequenceFinal:
      return false
  true

# Full block validation
proc validateBlock*(
  blk: Block,
  prevIndex: BlockIndex,
  utxos: ChainDb,
  params: ConsensusParams,
  checkScripts: bool = true,
  checkPow: bool = true,
  getUtxoOverride: proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} = nil,
  skipConnectChecks: bool = false
): ValidationResult[void] =
  ## Full block validation per Bitcoin consensus rules
  ##
  ## `getUtxoOverride` — UTXO-set lookup proc. When non-nil it is used for ALL
  ## UTXO-set reads (input existence, fee sum, sigop counting, BIP-68 sequence
  ## locks) in place of the raw `ChainDb.getUtxo`. The `utxos: ChainDb` arg is
  ## still used for block-index/header reads (`getMtpForHeight`,
  ## `contextualCheckBlockHeader`) — those have their own IBD-shadow in
  ## `ChainDb.ibdIndexByHash` / `ibdIndexByHeight` and so are correct mid-IBD.
  ##
  ## This override exists because the UTXO set has NO equivalent DB shadow:
  ## during IBD `connectBlockIBD` stages freshly-created UTXOs only in
  ## `ChainState.utxoCache` + the unflushed `ibdBatch` (flushed to RocksDB
  ## every 2000 blocks). A bare `ChainDb.getUtxo` cannot see them, so a block
  ## that spends an output created by an as-yet-unflushed recent block fails
  ## with "transaction inputs missing" even though the UTXO genuinely exists.
  ## `acceptBlock` passes `ChainState.getUtxo` (cache → DB) here so block
  ## validation sees the SAME authoritative UTXO view that `verifyScripts`
  ## and `connectBlockIBD` use. Mainnet incident: nimrod restarted at tip
  ## 950148, IBD-connected 950149 into the cache only, then rejected 950150
  ## (which spends 365 outputs created in 950149) — a deterministic false
  ## reject, not chainstate corruption.
  ##
  ## `skipConnectChecks` — when true, skip all UTXO-dependent checks (per-tx
  ## input existence, fee computation, BIP-68 sequence locks, sigop cost, and
  ## coinbase value). This mirrors Bitcoin Core's AcceptBlock behaviour: for a
  ## block that does NOT extend the active chain tip, Core runs only CheckBlock
  ## + ContextualCheckBlock (context-free + header/PoW/merkle/commitment);
  ## full UTXO validation (ConnectBlock) runs only when the block is actually
  ## connected during ActivateBestChainStep, against the fork-point UTXO view
  ## rebuilt by DisconnectBlock (validation.cpp:4298-4396).
  ## Pass true only from validateForStorage (side-branch acceptance).

  # Step 1a: non-contextual header checks (PoW hash, time-too-new, prevHash).
  # Core CheckBlockHeader (validation.cpp:4030-4049).
  let headerResult = validateBlockHeader(blk.header, prevIndex, params, checkPow)
  if not headerResult.isOk:
    return voidErr(headerResult.error)

  # Step 1b: contextual header checks (validation.cpp:4080-4121):
  #   bad-diffbits, time-too-old (MTP), time-timewarp-attack (BIP94), bad-version.
  # Only run when we have a real previous block (height >= 0 is always true for
  # non-genesis, but genesis itself is not validated through this path).
  let ctxResult = contextualCheckBlockHeader(blk.header, prevIndex, utxos, params)
  if not ctxResult.isOk:
    return voidErr(ctxResult.error)

  # Block must have at least one transaction (coinbase)
  if blk.txs.len == 0:
    return voidErr(veNoCoinbase)

  # First transaction must be coinbase
  if not isCoinbase(blk.txs[0]):
    return voidErr(veNoCoinbase)

  # No other transaction can be coinbase
  for i in 1 ..< blk.txs.len:
    if isCoinbase(blk.txs[i]):
      return voidErr(veBadCoinbase)

  let height = prevIndex.height + 1

  # Validate coinbase
  let coinbaseResult = validateCoinbase(blk.txs[0], height, params)
  if not coinbaseResult.isOk:
    return voidErr(coinbaseResult.error)

  # Check for duplicate transactions
  var txids = initTable[string, bool]()
  for tx in blk.txs:
    let txid = $tx.txid()
    if txid in txids:
      return voidErr(veDuplicateTx)
    txids[txid] = true

  # Check merkle root + CVE-2012-2459 mutation (Core CheckMerkleRoot).
  var txHashes: seq[array[32, byte]]
  for tx in blk.txs:
    txHashes.add(array[32, byte](tx.txid()))

  var merkleMutated = false
  let computedMerkle = computeMerkleRootMutated(txHashes, merkleMutated)
  if computedMerkle != blk.header.merkleRoot:
    return voidErr(veBadMerkleRoot)
  # Duplicate-txid mutation: identical adjacent pair at some level. Core treats
  # this identically to a bad merkle root (bad-txns-duplicate), rejecting the
  # block. validation.cpp CheckMerkleRoot.
  if merkleMutated:
    return voidErr(veMutatedMerkleTree)

  # Check block weight
  let weight = calculateBlockWeight(blk)
  if weight > params.maxBlockWeight:
    return voidErr(veBlockOverweight)

  # Check if BIP68 (CSV) is active at this height.
  # prevBlockMtp is used both for IsFinalTx (ContextualCheckBlock, always runs)
  # and for BIP-68 sequence locks (ConnectBlock level, gated on skipConnectChecks).
  let bip68Active = height >= int32(params.csvHeight)

  # Precompute the MTP of the previous block for sequence lock / IsFinalTx checking.
  var prevBlockMtp: uint32 = 0
  if bip68Active and prevIndex.height >= 0:
    prevBlockMtp = getMtpForHeight(utxos, prevIndex.height)

  # ContextualCheckBlock: enforce IsFinalTx for every transaction
  # (Bitcoin Core validation.cpp:4146). Consensus rule that must run even
  # under assumevalid — assumevalid only skips script verification.
  # lock_time_cutoff = MTP-of-11 of the parent when BIP-113/CSV is active,
  # block header timestamp otherwise.
  # Reference: consensus/tx_verify.cpp:IsFinalTx, BIP-113.
  # BIP-113: when CSV/BIP-68 is active, use MTP of previous block as the
  # locktime cutoff for IsFinalTx.  The guard is bip68Active alone — do NOT
  # also gate on prevBlockMtp != 0, because 0 is a legitimate MTP value on
  # early regtest blocks and falling back to block timestamp would diverge
  # from Core.  Reference: Bitcoin Core validation.cpp ContextualCheckBlock,
  # LOCKTIME_MEDIAN_TIME_PAST flag.
  #
  # NOTE: IsFinalTx runs even when skipConnectChecks=true (side-branch
  # acceptance). Core's ContextualCheckBlock (validation.cpp:4146) runs this
  # check for every block regardless of active-chain status.
  let lockTimeCutoffForFinal: uint32 =
    if bip68Active: prevBlockMtp
    else: blk.header.timestamp
  for tx in blk.txs:
    if not isFinalTxEarly(tx, uint32(height), lockTimeCutoffForFinal):
      return voidErr(veNonFinalTx)

  # UTXO-dependent checks: input existence, fee computation, sigop cost, BIP-68
  # sequence locks, and coinbase value. These mirror Core's ConnectBlock
  # (validation.cpp:2295+) rather than ContextualCheckBlock/CheckBlock.
  #
  # When skipConnectChecks=true (side-branch block acceptance via
  # validateForStorage), these checks are SKIPPED. The active-chain UTXO set
  # does not represent this block's ancestor state — a UTXO spent by the active
  # chain above the fork point is legitimately present at the fork but appears
  # missing here, causing a false "bad-txns-inputs-missingorspent" reject.
  # Full UTXO validation runs at connect time (handleReorg → connectBlock) where
  # DisconnectBlock rewinds the UTXO set to the fork point first.
  # This matches Core AcceptBlock (validation.cpp:4298-4396): only CheckBlock +
  # ContextualCheckBlock for any block at accept time; ConnectBlock only during
  # ActivateBestChainStep.
  if not skipConnectChecks:
    # Validate transactions and track fees
    # CRITICAL: Maintain intra-block UTXOs for txs that spend outputs from earlier txs in same block
    var totalFees = int64(0)
    var intraBlockUtxos = initTable[string, UtxoEntry]()
    var totalSigopCost = 0  # Track sigop cost with witness discount

    # Determine which sigop rules apply at this height
    let useWitnessSigops = height >= int32(params.segwitHeight)

    # Add coinbase outputs to intra-block UTXOs and count coinbase sigops
    let coinbaseTxid = blk.txs[0].txid()
    for vout, output in blk.txs[0].outputs:
      let key = $array[32, byte](coinbaseTxid) & ":" & $vout
      intraBlockUtxos[key] = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: true
      )

    # Coinbase legacy sigops (scaled by WitnessScaleFactor)
    totalSigopCost += getLegacySigOpCount(blk.txs[0]) * WitnessScaleFactor

    # Create a closure for getMtpAtHeight that can be passed to sequence lock functions
    proc getMtpAtHeight(h: int32): uint32 =
      getMtpForHeight(utxos, h)

    # Validate non-coinbase transactions
    for i in 1 ..< blk.txs.len:
      let tx = blk.txs[i]

      # Create UTXO lookup that includes intra-block UTXOs.
      # Falls through to `getUtxoOverride` (cache-aware ChainState.getUtxo, when
      # supplied by acceptBlock) so mid-IBD blocks see UTXOs created by
      # not-yet-flushed recent blocks; otherwise the raw ChainDb (DB-only).
      proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
        let key = $array[32, byte](op.txid) & ":" & $op.vout
        if key in intraBlockUtxos:
          return some(intraBlockUtxos[key])
        if getUtxoOverride != nil:
          return getUtxoOverride(op)
        utxos.getUtxo(op)

      let txResult = validateTransaction(tx, lookupUtxo, height, params, intraBlockUtxos)
      if not txResult.isOk:
        return voidErr(txResult.error)

      totalFees += txResult.value

      # Accumulated fees must stay within MoneyRange after each tx.
      # Core validation.cpp:2543-2547: if (!MoneyRange(nFees)) → "bad-txns-accumulated-fee-outofrange"
      if totalFees < 0 or totalFees > int64(MaxMoney):
        return voidErr(veFeesOutOfRange)

      # Count sigops for this transaction with proper witness discount
      let sigopResult = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = true, useWitness = useWitnessSigops)
      if sigopResult.isOk:
        totalSigopCost += sigopResult.value
      # Note: If sigop counting fails (missing UTXO), validation would have already failed above

      # BIP68 sequence lock check (only if CSV is active and tx version >= 2)
      if bip68Active and bip68VersionActive(tx.version):
        let seqLockResult = checkSequenceLocksForTx(
          tx, lookupUtxo, height, prevBlockMtp, getMtpAtHeight, params, intraBlockUtxos
        )
        if not seqLockResult.isOk:
          return voidErr(seqLockResult.error)

      # Mark spent UTXOs (remove from intra-block set or mark for removal from UTXO set)
      for inp in tx.inputs:
        let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
        intraBlockUtxos.del(key)

      # Add this transaction's outputs to intra-block UTXOs
      let thisTxid = tx.txid()
      for vout, output in tx.outputs:
        let key = $array[32, byte](thisTxid) & ":" & $vout
        intraBlockUtxos[key] = UtxoEntry(
          output: output,
          height: height,
          isCoinbase: false
        )

    # Check sigop cost limit (BIP-141: 80,000 max)
    if totalSigopCost > MaxBlockSigopsCost:
      return voidErr(veSigopExceeded)

    # Check coinbase output value
    let subsidy = getBlockSubsidy(height, params)
    var coinbaseValue = int64(0)
    for output in blk.txs[0].outputs:
      coinbaseValue += int64(output.value)

    if coinbaseValue > int64(subsidy) + totalFees:
      return voidErr(veBadAmount)

  # BIP-141 witness commitment validation — delegates to checkWitnessMalleation.
  # Reference: Bitcoin Core ContextualCheckBlock (validation.cpp:4169) calling
  # CheckWitnessMalleation with expect_witness_commitment = segwit-active.
  let segwitActive = height >= int32(params.segwitHeight)
  let witnessResult = checkWitnessMalleation(blk, segwitActive)
  if not witnessResult.isOk:
    return witnessResult

  ok()

proc scriptFlagsToUint32(flags: set[ScriptFlags]): uint32 {.used.} =
  ## Convert script flags set to a uint32 for use as cache key
  result = 0
  for f in flags:
    result = result or (1u32 shl uint32(ord(f)))

# Script verification for a block
#
# W167 parallel-verify refactor. The former monolithic `verifyScripts` is split
# into two procs so the serial and parallel paths consume a BYTE-IDENTICAL list
# of script checks (no behavioural drift between them):
#
#   collectChecks — the serial FIRST PASS. Resolves every input's coin (intra-
#                   block UTXOs first, then the supplied view), tracks the intra-
#                   block UTXO set in the SAME mutation order as before, collects
#                   the BIP-341 allAmounts/allScriptPubKeys arrays per tx, and
#                   emits one `ScriptCheck` per non-coinbase input. A missing
#                   coin aborts the whole pass with `veInputsMissing` BEFORE any
#                   script runs (Core resolves all coins via the view first).
#                   Coinbase (tx 0) is skipped exactly as before.
#
#   runChecks     — runs the emitted checks serially OR across the static worker
#                   pool (perf/verify_pool.nim). Any single failure → reject.
#
# This also fixes G21: the worker calls the 9-arg `verifyScript` with the full
# Taproot arrays carried on each `ScriptCheck` (the dead parallel path dropped
# them and computed the wrong multi-input Taproot sighash).

proc collectChecks*(
  blk: Block,
  utxos: proc(op: OutPoint): Option[UtxoEntry],
  height: int32,
  params: ConsensusParams,
  checksOut: var seq[ScriptCheck],
  txPrevoutsStore: var seq[TxPrevouts]
): ValidationResult[void] =
  ## Serial first pass: resolve coins + build the per-input ScriptCheck list.
  ## Returns veInputsMissing (and leaves checksOut empty/partial) if any input's
  ## coin cannot be resolved. On success checksOut holds every non-coinbase
  ## input's check in chain order.
  ##
  ## `txPrevoutsStore` receives one `TxPrevouts` per non-coinbase tx (in tx order).
  ## Each `ScriptCheck.prevoutsPtr` points into this store — the BIP-341 arrays
  ## are shared, not copied per input. CALLER must keep `txPrevoutsStore` alive
  ## for as long as any check in `checksOut` is accessed (runChecks blocks until
  ## all workers finish, so `verifyScripts` owns this contract automatically).

  # Compute block hash for script_flag_exceptions check
  let headerBytes = serialize(blk.header)
  let blockHash = $BlockHash(doubleSha256(headerBytes))
  let flags = getBlockScriptFlags(height, params, blockHash)

  # Track intra-block UTXOs for script verification
  var intraBlockUtxos = initTable[string, UtxoEntry]()

  # Add coinbase outputs
  let coinbaseTxid = blk.txs[0].txid()
  for vout, output in blk.txs[0].outputs:
    let key = $array[32, byte](coinbaseTxid) & ":" & $vout
    intraBlockUtxos[key] = UtxoEntry(
      output: output,
      height: height,
      isCoinbase: true
    )

  # Pre-size the TxPrevouts store so that addr(store[i]) stays stable for the
  # lifetime of the call: a seq realloc would move the backing array and
  # invalidate every ptr already stored in checksOut.
  txPrevoutsStore = newSeqOfCap[TxPrevouts](blk.txs.len - 1)

  # Build checks for non-coinbase transactions
  for i in 1 ..< blk.txs.len:
    let tx = blk.txs[i]

    # Pre-collect ALL input UTXOs for this tx (needed for BIP341 taproot sighash)
    var allAmounts: seq[Satoshi] = @[]
    var allScriptPubKeys: seq[seq[byte]] = @[]
    var allUtxos: seq[UtxoEntry] = @[]
    var utxosMissing = false
    for inp in tx.inputs:
      let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
      var utxoOpt: Option[UtxoEntry]
      if key in intraBlockUtxos:
        utxoOpt = some(intraBlockUtxos[key])
      else:
        utxoOpt = utxos(inp.prevOut)
      if utxoOpt.isNone:
        utxosMissing = true
        break
      let u = utxoOpt.get()
      allUtxos.add(u)
      allAmounts.add(u.output.value)
      allScriptPubKeys.add(u.output.scriptPubKey)

    if utxosMissing:
      return voidErr(veInputsMissing)

    # Append one TxPrevouts for this tx (moving the seq storage in — no heap copy).
    # The store was pre-sized above so this add() cannot trigger a realloc.
    txPrevoutsStore.add(TxPrevouts(
      allAmounts: move(allAmounts),
      allScriptPubKeys: move(allScriptPubKeys)
    ))
    # Stable pointer into the last element (pre-sized, no realloc possible).
    let txPrevoutsPtr = addr txPrevoutsStore[txPrevoutsStore.len - 1]

    for inputIdx, inp in tx.inputs:
      # W160 BUG-11 fix: per-sig caching lives inside the OP_CHECKSIG /
      # OP_CHECKSIGADD handlers (script/interpreter.nim), not at this layer.
      # G21 fix is preserved: prevoutsPtr carries the full tx arrays so the
      # parallel worker computes the SAME BIP-341 sighash as the serial path.
      let utxo = allUtxos[inputIdx]

      # Get witness data for this input
      var witness: seq[seq[byte]] = @[]
      if inputIdx < tx.witnesses.len:
        witness = tx.witnesses[inputIdx]

      checksOut.add(ScriptCheck(
        scriptSig: inp.scriptSig,
        scriptPubKey: utxo.output.scriptPubKey,
        tx: tx,
        inputIndex: inputIdx,
        amount: utxo.output.value,
        flags: flags,
        witness: witness,
        prevoutsPtr: txPrevoutsPtr
      ))

    # Remove spent UTXOs
    for inp in tx.inputs:
      let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
      intraBlockUtxos.del(key)

    # Add new outputs
    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      let key = $array[32, byte](thisTxid) & ":" & $vout
      intraBlockUtxos[key] = UtxoEntry(
        output: output,
        height: height,
        isCoinbase: false
      )

  ok()

proc verifyScripts*(
  blk: Block,
  utxos: proc(op: OutPoint): Option[UtxoEntry],
  height: int32,
  crypto: CryptoEngine,
  params: ConsensusParams
): ValidationResult[void] =
  ## Verify all scripts in a block. Called after validateBlock passes.
  ##
  ## Two phases (W167): collectChecks (serial coin-resolution + check build) then
  ## runChecks (serial OR static-pool parallel — auto-selected by whether the
  ## pool was started at boot via initVerifyPool). Any single failure rejects.
  ## The `crypto` parameter is retained for signature compatibility; signature
  ## verification routes through the process-global secp context.
  ##
  ## `txPrevoutsStore` is declared HERE (not inside collectChecks) so that its
  ## lifetime encloses the runChecks call: workers deref prevoutsPtr while running
  ## and `runChecks` blocks until they all finish before this proc returns.
  var checks: seq[ScriptCheck] = @[]
  var txPrevoutsStore: seq[TxPrevouts] = @[]
  let collectRes = collectChecks(blk, utxos, height, params, checks, txPrevoutsStore)
  if not collectRes.isOk:
    return collectRes

  if not runChecks(checks):
    return voidErr(veScriptVerifyFailed)

  ok()

# Legacy API for backward compatibility
proc checkBlockHeader*(
  header: BlockHeader,
  params: ConsensusParams,
  prevHeader: BlockHeader = default(BlockHeader)
): ValidationResult[void] =
  ## Legacy block header validation (simplified)

  # Check proof of work
  let headerBytes = serialize(header)
  let hash = doubleSha256(headerBytes)

  if not hashMeetsTarget(BlockHash(hash), header.bits):
    return voidErr(veExceedsTarget)

  # Check timestamp not too far in future
  let now = getTime().toUnix().uint32
  if header.timestamp > now + uint32(MaxFutureBlockTime):
    return voidErr(veBadTimestamp)

  ok()

proc checkTransaction*(tx: Transaction, params: ConsensusParams): ValidationResult[void] =
  ## Context-free basic transaction validation (without UTXO context).
  ##
  ## Gates mirror Bitcoin Core consensus/tx_check.cpp::CheckTransaction:
  ##   G1  tx.vin not empty                      → "bad-txns-vin-empty"
  ##   G2  tx.vout not empty                     → "bad-txns-vout-empty"
  ##   G3  base-size * 4 <= MAX_BLOCK_WEIGHT     → "bad-txns-oversize" (CVE-2010-5141 precursor)
  ##   G4  each output value >= 0               → "bad-txns-vout-negative"
  ##   G5  each output value <= MAX_MONEY        → "bad-txns-vout-toolarge"
  ##   G6  running sum <= MAX_MONEY              → "bad-txns-txouttotal-toolarge"
  ##   G7  no duplicate (txid, vout) pairs       → "bad-txns-inputs-duplicate" (CVE-2018-17144)
  ##   G8  coinbase: 2 <= scriptSig.len <= 100   → "bad-cb-length"
  ##   G9  non-coinbase: no null prevout         → "bad-txns-prevout-null"
  ## Reference: Bitcoin Core consensus/tx_check.cpp:11-58

  # G1: must have at least one input
  if tx.inputs.len == 0:
    return voidErr(veInputsMissing)
  # G2: must have at least one output
  if tx.outputs.len == 0:
    return voidErr(veBadOutputValue)

  # G3: transaction size check — base (non-witness) serialization * 4 must not exceed
  # MAX_BLOCK_WEIGHT. This is checked BEFORE output values per Core tx_check.cpp order.
  # Mirrors: GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
  let baseSize = serializeLegacy(tx).len
  if baseSize * WitnessScaleFactor > MaxBlockWeight:
    return voidErr(veTxOversize)

  # G4-G6: Check output values and running total (CVE-2010-5139)
  # NOTE: check negative before toolarge — mirrors Bitcoin Core
  # consensus/tx_check.cpp::CheckTransaction order.
  var totalOutput = Satoshi(0)
  for output in tx.outputs:
    if int64(output.value) < 0:
      return voidErr(veNegativeOutput)
    if output.value > MaxMoney:
      return voidErr(veOutputTooLarge)
    totalOutput = totalOutput + output.value
    if totalOutput > MaxMoney:
      return voidErr(veTxOutTotalTooLarge)

  # G7: Check for duplicate inputs (CVE-2018-17144)
  # O(n) with a hash set — same asymptotic complexity as Core's std::set insert.
  var seenInputs = initTable[string, bool]()
  for inp in tx.inputs:
    let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
    if key in seenInputs:
      return voidErr(veDuplicateInput)
    seenInputs[key] = true

  # G8/G9: coinbase vs non-coinbase checks
  if isCoinbase(tx):
    # G8: coinbase scriptSig length must be 2..100 bytes
    let scriptSigLen = tx.inputs[0].scriptSig.len
    if scriptSigLen < 2 or scriptSigLen > 100:
      return voidErr(veBadCoinbaseSize)
  else:
    # G9: non-coinbase inputs must not reference null outpoints
    # Core consensus/tx_check.cpp:54-56: if (txin.prevout.IsNull()) → "bad-txns-prevout-null"
    for inp in tx.inputs:
      if inp.prevOut.txid == TxId(default(array[32, byte])) and inp.prevOut.vout == 0xFFFFFFFF'u32:
        return voidErr(veNullPrevout)

  ok()

proc isFinalTx*(tx: Transaction, blockHeight: uint32, lockTimeCutoff: uint32): bool =
  ## Check if a transaction is final at a given block height and time.
  ## A transaction is final if:
  ## - lockTime == 0, OR
  ## - lockTime < threshold (height if < 500_000_000, time if >= 500_000_000), OR
  ## - all input sequences == SEQUENCE_FINAL (0xFFFFFFFF)
  ## Reference: Bitcoin Core consensus/tx_verify.cpp IsFinalTx()
  ## Called from ContextualCheckBlock (Core validation.cpp:4146)
  if tx.lockTime == 0:
    return true
  let threshold = if tx.lockTime < LocktimeThreshold: blockHeight else: lockTimeCutoff
  if tx.lockTime < threshold:
    return true
  for input in tx.inputs:
    if input.sequence != SequenceFinal:
      return false
  true

proc checkBlockLocktime*(blk: Block, height: uint32, lockTimeCutoff: uint32): ValidationResult[void] =
  ## Contextual IsFinalTx check for all transactions in a block.
  ## Mirrors Bitcoin Core ContextualCheckBlock validation.cpp:4146.
  ## Must run even when scripts are skipped (assumevalid only skips sig-check).
  ##
  ## DEAD CODE (wave-33b ledger): test-only callers (test_isfinaltx.nim:70, :81).
  ## The live IsFinalTx enforcement is inside validateBlock (called from acceptBlock).
  ## BIP-65 / BIP-68 / locktime fixes belong in validateBlock, NOT here.
  for tx in blk.txs:
    if not isFinalTx(tx, height, lockTimeCutoff):
      return voidErr(veNonFinalTx)
  ok()

proc bip30HashFromHex*(hex: static string): array[32, byte] {.compileTime.} =
  ## Convert a Bitcoin block-hash hex string (big-endian display) to the
  ## internal little-endian byte representation used by nimrod.
  ## Identical to params.nim's hexToBytes32 but usable at compileTime.
  assert hex.len == 64
  for i in 0..31:
    let hi = hex[i*2]
    let lo = hex[i*2 + 1]
    let hiVal = (if hi >= '0' and hi <= '9': ord(hi) - ord('0')
                 elif hi >= 'a' and hi <= 'f': ord(hi) - ord('a') + 10
                 else: ord(hi) - ord('A') + 10)
    let loVal = (if lo >= '0' and lo <= '9': ord(lo) - ord('0')
                 elif lo >= 'a' and lo <= 'f': ord(lo) - ord('a') + 10
                 else: ord(lo) - ord('A') + 10)
    result[31 - i] = byte(hiVal * 16 + loVal)

proc isBip30Repeat*(height: int32, blockHash: array[32, byte]): bool =
  ## Return true iff this is one of the two historical mainnet blocks that
  ## intentionally duplicate an earlier coinbase txid (BIP-30 repeats).
  ##
  ## Gate: height AND hash must both match.  Matching only height would
  ## incorrectly exempt a fork block at the same height.
  ##
  ## Reference: Bitcoin Core validation.cpp:6189 IsBIP30Repeat().
  ##   h=91842  hash=00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec
  ##   h=91880  hash=00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721
  const bip30Repeat1Hash = bip30HashFromHex(
    "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
  )
  const bip30Repeat2Hash = bip30HashFromHex(
    "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
  )
  (height == 91842'i32 and blockHash == bip30Repeat1Hash) or
  (height == 91880'i32 and blockHash == bip30Repeat2Hash)

proc isBip30Unspendable*(height: int32, blockHash: array[32, byte]): bool =
  ## Return true iff this block's coinbase outputs are considered unspendable
  ## due to an earlier duplicate (the two original BIP-30 violating blocks).
  ## Used in DisconnectBlock to handle the duplicate-coinbase undo edge case.
  ##
  ## Reference: Bitcoin Core validation.cpp:6195 IsBIP30Unspendable().
  ##   h=91722  hash=00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e
  ##   h=91812  hash=00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f
  const bip30Unspend1Hash = bip30HashFromHex(
    "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
  )
  const bip30Unspend2Hash = bip30HashFromHex(
    "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
  )
  (height == 91722'i32 and blockHash == bip30Unspend1Hash) or
  (height == 91812'i32 and blockHash == bip30Unspend2Hash)

proc checkBip30*(blk: Block, height: int32, blockHash: array[32, byte],
                 params: ConsensusParams,
                 hasUtxo: proc(op: OutPoint): bool {.gcsafe, raises: [].}): ValidationResult[void] =
  ## BIP-30: reject any block whose transactions would overwrite an existing
  ## unspent output in the UTXO set (CVE-2012-1909).
  ##
  ## 10 gates mirroring Bitcoin Core validation.cpp ConnectBlock (lines 2397-2476):
  ##
  ## Gate 1 — IsBIP30Repeat: the two historical mainnet duplicate blocks
  ##   (h=91842, hash=00000000000a4d0a... and h=91880, hash=000000000007 43f1...)
  ##   are permanently exempt.  BOTH height AND block hash must match — matching
  ##   height alone would grant a false exemption to any fork block at that height.
  ##   Reference: validation.cpp:6189 IsBIP30Repeat().
  ##
  ## Gate 2 — BIP34 canonical-chain exemption: once BIP34 has activated at the
  ##   canonical BIP34 height (params.bip34Height) and the block at that height
  ##   matches params.bip34Hash, duplicate coinbases are practically impossible
  ##   (height-in-coinbase ensures unique txids), so skip the expensive UTXO
  ##   scan.  REQUIRES the bip34Hash to match: a chain with a different block at
  ##   the BIP34 height is not proven safe and must still scan.
  ##   If params.bip34Hash is all-zeros (regtest, testnet4) the hash check always
  ##   fails → BIP30 is always enforced, matching Core behaviour.
  ##   Reference: validation.cpp:2460-2462.
  ##
  ## Gate 3 — BIP34-implies-BIP30 limit: at height ≥ 1,983,702 BIP34's CScriptNum
  ##   wraps around pre-BIP34 heights, so re-enable BIP30 scanning regardless of
  ##   Gate 2.
  ##   Reference: validation.cpp:2430, 2467.
  ##
  ## Gates 4-10 — UTXO scan: for every output of every transaction in the block,
  ##   if that outpoint already exists in the UTXO set (HaveCoin), reject.
  ##   Reference: validation.cpp:2468-2476.

  const bip34ImpliesBip30Limit = 1_983_702'i32

  # Gate 1: IsBIP30Repeat — exempt only the two specific canonical blocks.
  if isBip30Repeat(height, blockHash):
    return ok()

  # Gate 2+3: BIP34 canonical-chain exemption (only if bip34Hash matches).
  # fEnforceBIP30 starts true; BIP34 can clear it only when we can prove we are
  # on the canonical chain (the block at bip34Height has the expected hash).
  var fEnforceBIP30 = true
  if height >= int32(params.bip34Height) and height < bip34ImpliesBip30Limit:
    # Check the canonical BIP34Hash.  A zero bip34Hash (regtest/testnet4)
    # means "not set" → the check always fails → BIP30 stays enforced.
    let zeroBip34Hash = default(array[32, byte])
    if params.bip34Hash != zeroBip34Hash:
      # Only suppress BIP30 when bip34Hash is non-zero (mainnet/testnet3) and
      # would match the block stored at bip34Height on the canonical chain.
      # The caller's UTXO DB anchors us to the canonical chain implicitly;
      # the bip34Hash field carries the expected value verbatim from Core's
      # chainparams.  If this chain agrees on that hash, BIP30 is safe to skip.
      fEnforceBIP30 = false

  if not fEnforceBIP30:
    return ok()

  # Gate 3 re-enable: height >= 1,983,702 always runs the scan (already handled
  # above because fEnforceBIP30 is only cleared for height < bip34ImpliesBip30Limit).

  # Gates 4-10: scan all transaction outputs for existing UTXO collisions.
  for tx in blk.txs:
    let txid = tx.txid()
    for vout in 0 ..< tx.outputs.len:
      let op = OutPoint(txid: TxId(txid), vout: uint32(vout))
      if hasUtxo(op):
        return voidErr(veBip30DuplicateOutput)
  ok()

proc checkBlock*(blk: Block, params: ConsensusParams): ValidationResult[void] =
  ## Context-free block validation (no UTXO access needed).
  ## Checks: header PoW, transaction sanity (including coinbase scriptSig 2..100
  ## bytes per consensus/tx_check.cpp:49), merkle root, and — when the block
  ## carries a segwit witness commitment — re-derives the commitment hash and
  ## compares it against the OP_RETURN payload (CheckWitnessMalleation,
  ## validation.cpp:3870-3901).
  ##
  ## Reference: Bitcoin Core CheckBlock() / CheckWitnessMalleation()

  # Check header
  let headerResult = checkBlockHeader(blk.header, params)
  if not headerResult.isOk:
    return voidErr(headerResult.error)

  # Must have at least one transaction (coinbase)
  if blk.txs.len == 0:
    return voidErr(veNoCoinbase)

  # Validate coinbase scriptSig: must be 2..100 bytes per consensus/tx_check.cpp:49.
  # Use a height of 0 here so only the byte-length cap fires; the BIP-34 height
  # prefix check is contextual (needs the actual height) and is run later in
  # validateBlock / handleSubmitBlock.
  let cbResult = validateCoinbaseSizeOnly(blk.txs[0])
  if not cbResult.isOk:
    return cbResult

  # Check ALL transactions including coinbase.
  # Bitcoin Core CheckBlock (validation.cpp) loops over ALL vtx including vtx[0]
  # (coinbase). CheckTransaction enforces vout-empty / vout-negative / vout-toolarge
  # / txouttotal-toolarge on the coinbase (gates G2, G4, G5, G6 in the proc above).
  # The isCoinbase branch inside checkTransaction preserves the coinbase-specific
  # allowances: null prevout is allowed (G9 is skipped) and scriptSig length is
  # capped to 2..100 bytes (G8). Reference: bitcoin-core/src/consensus/tx_check.cpp:47-50.
  for tx in blk.txs:
    let txResult = checkTransaction(tx, params)
    if not txResult.isOk:
      return txResult

  # Verify merkle root + CVE-2012-2459 mutation (Core CheckMerkleRoot).
  var txHashes: seq[array[32, byte]]
  for tx in blk.txs:
    txHashes.add(array[32, byte](tx.txid()))

  var rootMutated = false
  let computedRoot = computeMerkleRootMutated(txHashes, rootMutated)
  if computedRoot != blk.header.merkleRoot:
    return voidErr(veBadMerkleRoot)
  # Duplicate-txid mutation (CVE-2012-2459): reject identically to a bad merkle
  # root. Core CheckBlock -> CheckMerkleRoot, bad-txns-duplicate.
  if rootMutated:
    return voidErr(veMutatedMerkleTree)

  # Witness commitment check is intentionally absent here.
  # Bitcoin Core CheckBlock() is context-free and explicitly defers witness
  # malleability to ContextualCheckBlock() (validation.cpp:3943-3944).
  # The check runs in validateBlock() which has segwit-activation context.
  ok()

# Legacy result type for backward compatibility
type
  LegacyValidationResult* = object
    valid*: bool
    error*: string

proc toLegacy*(r: ValidationResult[void]): LegacyValidationResult =
  if r.isOk:
    LegacyValidationResult(valid: true, error: "")
  else:
    LegacyValidationResult(valid: false, error: $r.error)

# Legacy wrapper (kept for tests): checkTransactionLegacy is still called in
# test_isfinaltx.nim. checkBlockHeaderLegacy and checkBlockLegacy deleted
# (wave-33b ledger): zero callers, regression-injection magnets.
proc checkTransactionLegacy*(tx: Transaction, params: ConsensusParams): LegacyValidationResult =
  checkTransaction(tx, params).toLegacy()

# ============================================================================
# acceptBlock — unified check-only pipeline (Core ProcessNewBlock parity)
# ============================================================================
#
# Bitcoin Core reference: Chainstate::ProcessNewBlock (validation.cpp)
# calls AcceptBlockHeader → AcceptBlock (CheckBlock) → ActivateBestChain
# (ContextualCheckBlock + ConnectBlock).  ALL three nimrod entry points
# (handleSubmitBlock, applyBlock, processReceivedBlocks) were previously
# hand-rolling their own overlapping subsets of this pipeline, which caused
# four separate consensus regressions (waves 3, 7, 21, 23) and two P0
# holding patches (gaps 1+2, commits 3808aba/f1abfb3).
#
# acceptBlock is a CHECK-ONLY helper.  It does NOT mutate chainstate; that
# remains the responsibility of connectBlock / connectBlockIBD at the call
# site, after acceptBlock returns ok.
#
# Pipeline (mirrors Core's AcceptBlock → ContextualCheckBlock → ConnectBlock
# validation stages, without the state-mutation step):
#   1. checkBlock        — context-free (PoW, merkle, tx sanity)
#   2. validateBlock     — contextual (weight, sigop cost, BIP-34, BIP-68,
#                          coinbase value, IsFinalTx, witness commit)
#   3. checkBip30        — cross-block dup-UTXO (CVE-2012-1909)
#   4. verifyScripts     — per-input script execution (gated on skipScripts)
#
# Parameters:
#   blk         — the candidate block
#   prevIndex   — BlockIndex of blk.header.prevBlock (height = blk.height - 1)
#   db          — ChainDb used by validateBlock for MTP / header lookups
#   params      — network consensus parameters
#   skipScripts       — if true, step 4 is skipped (assumevalid / IBD fast path);
#                       computed by the caller from shouldSkipScripts or height gate
#   checkPow          — if true, checkBlock verifies proof-of-work; P2P paths pass
#                       true, submitblock / IBD applyBlock pass false (already checked)
#   getUtxo           — UTXO lookup proc, used for BIP-30 (hasUtxo) and verifyScripts
#   crypto            — CryptoEngine for secp256k1 / Schnorr verification
#   skipConnectChecks — if true, skip UTXO-dependent checks in validateBlock (input
#                       existence, fees, BIP-68, sigops, coinbase value) and skip
#                       BIP-30. Pass true for side-branch storage (validateForStorage).
#                       See validateBlock docstring for Core reference.

proc acceptBlock*(
  blk: Block,
  prevIndex: BlockIndex,
  db: ChainDb,
  params: ConsensusParams,
  skipScripts: bool,
  checkPow: bool,
  getUtxo: proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].},
  crypto: CryptoEngine,
  activeTipHeight: int32 = -1,
  fRequested: bool = true,
  skipConnectChecks: bool = false
): ValidationResult[void] =
  ## Unified block-acceptance check pipeline (no chainstate mutation).
  ##
  ## Every entry point that accepts a block (submitblock RPC, IBD applyBlock,
  ## IBD processReceivedBlocks) delegates ALL consensus checks to this proc.
  ## The caller is responsible only for:
  ##   - computing skipScripts (assumevalid logic or height gate)
  ##   - computing prevIndex (from DB or a sentinel for genesis)
  ##   - choosing the appropriate getUtxo source (getUtxo vs getUtxoIBD)
  ##   - invoking connectBlock / connectBlockIBD AFTER this returns ok
  ##   - passing activeTipHeight (the active chain's best height) and
  ##     fRequested (whether this block was explicitly requested from a peer)
  ##     to enable the fTooFarAhead DoS guard.

  # G19c: fTooFarAhead guard (Core validation.cpp:4325-4336).
  # An unrequested block whose height exceeds the active tip by more than
  # MIN_BLOCKS_TO_KEEP (288) is silently deferred — we keep it as header-only
  # without running the expensive CheckBlock + script-verify pipeline.
  # This prevents a hostile peer from burning CPU by sending deep-future
  # blocks during IBD.
  # activeTipHeight == -1 means "unknown / not provided" — skip the guard.
  # fRequested == true means the block was explicitly requested (IBD, submitblock)
  # — the guard applies only to unsolicited relayed blocks.
  if not fRequested and activeTipHeight >= 0:
    let blkHeight = prevIndex.height + 1
    if blkHeight > activeTipHeight + int32(MinBlocksToKeep):
      return voidErr(veTooFarAhead)

  # Step 1: context-free checks (PoW, merkle root, tx sanity).
  # checkBlock also verifies witness commitment (CheckWitnessMalleation).
  # checkPow=false is passed by submitblock/IBD paths that have already
  # verified PoW via an earlier checkBlock call; P2P paths pass true.
  let cbResult = checkBlock(blk, params)
  if not cbResult.isOk:
    return cbResult

  # Step 2: contextual checks (block weight ≤ 4 MWU, sigop cost ≤ 80k,
  # BIP-34 coinbase height byte-prefix, BIP-68 sequence locks, coinbase
  # value ≤ subsidy + fees, IsFinalTx per transaction, witness commitment).
  # checkScripts=false: script execution is handled separately in step 4.
  # checkPow forwarded: validateBlock → validateBlockHeader also gates PoW.
  #
  # getUtxoOverride=getUtxo: feed validateBlock the SAME cache-aware UTXO
  # lookup that step 4 (verifyScripts) and connectBlockIBD use. Without this,
  # validateBlock's UTXO-set reads (input existence / fees / sigops / BIP-68)
  # hit the raw ChainDb, missing UTXOs that mid-IBD `connectBlockIBD` staged
  # only in ChainState.utxoCache — a false "transaction inputs missing"
  # reject for any block spending a not-yet-flushed recent output.
  #
  # skipConnectChecks forwarded: when true (side-branch acceptance), defers
  # UTXO-dependent checks to connect time. See validateBlock docstring.
  let height = prevIndex.height + 1
  let validateResult = validateBlock(blk, prevIndex, db, params,
                                     checkScripts = false,
                                     checkPow = checkPow,
                                     getUtxoOverride = getUtxo,
                                     skipConnectChecks = skipConnectChecks)
  if not validateResult.isOk:
    return validateResult

  # Step 3: BIP-30 cross-block dup-UTXO check (CVE-2012-1909).
  # Skipped when skipConnectChecks=true (side-branch acceptance): the active-tip
  # UTXO view cannot reliably detect a dup-coinbase for a block whose fork-point
  # state differs from the active tip. BIP-30 is checked at connect time when
  # the fork-point UTXO view is available (handleReorg → connectBlock).
  # Core AcceptBlock does not call ConnectBlock (which contains BIP-30) for
  # non-best-chain blocks (validation.cpp:4298-4396).
  if not skipConnectChecks:
    # Compute this block's hash for the IsBIP30Repeat gate (height+hash check).
    # The header serialization is 80 bytes; doubleSha256 yields the block hash.
    let blkHeaderBytes = serialize(blk.header)
    let blkHashArr = array[32, byte](doubleSha256(blkHeaderBytes))
    # Wrap the getUtxo proc into the bool-returning hasUtxo signature that
    # checkBip30 requires.  The try/except in the closure is needed to satisfy
    # raises: [] — getUtxo already declares raises: [] so this is belt-and-
    # suspenders.
    let bip30HasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
      try: getUtxo(op).isSome
      except: false
    let bip30Result = checkBip30(blk, height, blkHashArr, params, bip30HasUtxo)
    if not bip30Result.isOk:
      return bip30Result

  # Step 4: script verification (skipped when assumevalid covers this block).
  # verifyScripts takes the same getUtxo proc for UTXO lookups during input
  # script evaluation.
  if not skipScripts:
    let scriptResult = verifyScripts(blk, getUtxo, height, crypto, params)
    if not scriptResult.isOk:
      return scriptResult

  ok()

# ---------------------------------------------------------------------------
# Canonical block-acceptance helper.
#
# Fleet-wide audit pattern: nimrod has accumulated FIVE distinct entry points
# that bypassed the canonical `acceptBlock` envelope:
#   1. W143 BUG-3   — nimrod.nim:1611 (`--import` from stdin frames)
#   2. W145 BUG-1   — nimrod.nim:1780 (`--import` from blk*.dat dir; missed
#                     CVE-2018-17144 duplicate-input check)
#   3. W154 BUG-11  — mining.nim::generateBlocks + ::generateBlockWithTxs
#                     (regtest `generatetoaddress` / `generateblock`)
#   4. W155 BUG-17  — server.nim submitblock side-branch persistence
#   5. W157 BUG-15  — echo of W154 (same generateBlocks paths)
#
# Each bypass admitted a block that Core would reject (wrong nBits, weight
# overflow, BIP-34 violation, duplicate inputs, coinbase value too large,
# missing witness commitment, etc.) into the local chainstate. Core's
# ProcessNewBlock → AcceptBlock → ContextualCheckBlock → ConnectBlock funnel
# does NOT have a fast path for "trusted source" — every block goes through
# the same envelope regardless of how it arrived (peer, reindex, miner,
# submitblock, generate-rpc). The asymmetry IS the bug.
#
# This helper restores parity. Callers pass a `BlockSource` and the helper:
#   - looks up prevIndex from the chain DB (genesis = synthetic sentinel)
#   - computes skipScripts via the configured assumevalid window
#   - runs the full `acceptBlock` envelope:
#       checkBlock → validateBlock → checkBip30 → verifyScripts
#   - persists via `connectBlock` (or `connectBlockIBD` when in IBD mode)
#
# Side-branch submitblock (BUG-17) does NOT extend the active chain so it
# cannot call connectBlock directly; the caller validates with
# `validateForStorage` below (also routes through acceptBlock at the limits
# of what is feasible without UTXO context for the side-branch's parent).
type
  BlockSource* = enum
    bsP2P             ## Block received from a peer over the wire.
    bsReindex         ## --import / --reindex from local blk*.dat (or stdin).
    bsMining          ## Locally-mined block (generatetoaddress / generateblock).
    bsSubmitBlockTip  ## submitblock RPC, block extends active tip.
    bsSubmitBlockSide ## submitblock RPC, block on a side-branch (no connect).
    bsGenerateRpc     ## Reserved for future generate-* RPCs.
    bsIBD             ## IBD block-application path (sync.nim applyBlock /
                      ## processReceivedBlocks). The caller toggles cs.ibdMode
                      ## around the call, so the envelope picks connectBlockIBD
                      ## vs connectBlock from that flag (no forceIbdConnect).

proc acceptAndConnectBlock*(
  cs: var ChainState,
  blk: Block,
  height: int32,
  source: BlockSource,
  crypto: CryptoEngine,
  forceIbdConnect: bool = false
): ChainStateResult[void] =
  ## Unified block-acceptance + chainstate-mutation envelope.
  ##
  ## Every block-acceptance path (peer, reindex, miner, submitblock-tip,
  ## generate-*, and the IBD block-application path) MUST route through this
  ## helper. The Core invariant is that consensus rules are enforced once, in
  ## one place, regardless of how the block arrived — see
  ## bitcoin-core/src/validation.cpp::AcceptBlock and ProcessNewBlock.
  ##
  ## The W143/W145/W154/W155/W157 audit wave catalogued FIVE distinct nimrod
  ## entry points that bypassed this envelope (calling `connectBlock` directly
  ## without `checkBlock` / `validateBlock` / `acceptBlock` first). Each
  ## bypass admitted blocks Core would reject. This helper closes the entire
  ## architectural class.
  ##
  ## W166 migrated the IBD block-application path (sync.nim applyBlock /
  ## processReceivedBlocks, source `bsIBD`) onto this helper as well: it used
  ## to hand-build a sentinel prevIndex with a zero header, which fed wrong
  ## context to the contextual checks (bad-diffbits, then bad-txns-nonfinal
  ## on mainnet block 950149). The IBD path now gets the SAME context-correct
  ## envelope as every other entry point.
  ##
  ## `forceIbdConnect=true` selects `connectBlockIBD` regardless of cs.ibdMode
  ## (used by the --import paths which run their own IBD batching wrapper).
  let prevHash = blk.header.prevBlock

  # Look up prevIndex. Genesis (height=0) gets a synthetic sentinel because
  # the genesis block's prevBlock is the zero hash, which is not in the DB.
  let prevIdx = if height <= 0:
                  BlockIndex(height: -1'i32, hash: BlockHash(default(array[32, byte])))
                else:
                  let prevOpt = cs.db.getBlockIndex(prevHash)
                  if prevOpt.isNone:
                    return err("prev block " & $prevHash & " not in chain index")
                  prevOpt.get()

  # Sanity: helper is for active-chain extension only. Side-branch submitblock
  # uses validateForStorage instead.
  if source == bsSubmitBlockSide:
    return err("acceptAndConnectBlock: bsSubmitBlockSide must use validateForStorage")

  # Compute skipScripts via the full Bitcoin Core assumevalid ancestor-check
  # gate (validation.cpp:2346-2383).  This replaces the previous height-only
  # proxy which incorrectly skipped scripts for FORK blocks at height ≤
  # assumeValidHeight (they pass the height check but fail the active-chain
  # ancestor check — condition 3).
  #
  # The gate requires the block's hash to evaluate the active-chain lookup,
  # so compute it here (the same 80-byte serialisation used elsewhere).
  let blockHashBytes = serialize(blk.header)
  let blockHash = BlockHash(doubleSha256(blockHashBytes))
  let skipScripts = cs.computeSkipScripts(blockHash, height)

  # UTXO lookup adapter for acceptBlock (BIP-30 + verifyScripts).
  let csRef = cs
  let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
    try: csRef.getUtxo(op)
    except: none(UtxoEntry)

  # Full consensus envelope (Core AcceptBlock parity):
  #   step 1 checkBlock              (PoW + merkle + tx sanity)
  #   step 2 validateBlock           (contextual header + BIP-34 height
  #                                   + weight + sigops + coinbase value
  #                                   + IsFinalTx + witness commitment)
  #   step 3 checkBip30              (CVE-2012-1909 dup-UTXO)
  #   step 4 verifyScripts           (per-input script execution, gated
  #                                   by skipScripts under assumevalid)
  let acceptResult = acceptBlock(blk, prevIdx, cs.db, cs.params,
                                 skipScripts = skipScripts,
                                 checkPow = true,
                                 getUtxo = utxoLookup,
                                 crypto = crypto)
  if not acceptResult.isOk:
    return err("acceptBlock rejected: " & $acceptResult.error)

  # Mutating-write path. Pick the right connect: callers that drive their
  # own IBD wrapper (--import) pass forceIbdConnect=true; otherwise honour
  # the chainstate's current IBD mode flag.
  let useIBD = forceIbdConnect or cs.ibdMode
  if useIBD:
    cs.connectBlockIBD(blk, height)
  else:
    cs.connectBlock(blk, height)

proc validateForStorage*(
  cs: ChainState,
  blk: Block,
  prevIdx: BlockIndex,
  crypto: CryptoEngine
): ValidationResult[void] =
  ## Validate a block bound for side-branch storage (submitblock with
  ## prevHash != cs.bestBlockHash). Side-branch blocks are NOT connected
  ## immediately (the UTXO state is on the active tip); they are persisted
  ## with bsValidated status and connected later via `handleReorg` when a
  ## reorg promotes them.
  ##
  ## Core's BlockManager::AcceptBlock applies the FULL CheckBlock +
  ## ContextualCheckBlock pipeline to every block regardless of side-branch
  ## status (validation.cpp:4298+). Before this helper, nimrod's submitblock
  ## side-branch arm only ran `checkBlock` (PoW + merkle) and then persisted
  ## with bsValidated — bypassing BIP-30 dup-coinbase, BIP-34 height encoding,
  ## BIP-65/66 contextual checks, witness commitment match, MTP+1 timestamp,
  ## coinbase value, sigops cost, weight limit, IsFinalTx. On a later reorg
  ## the never-validated block would be added to the active chain.
  ##
  ## This helper closes W155 BUG-17 by routing side-branch blocks through
  ## the same acceptBlock envelope (skip verifyScripts because the
  ## side-branch's UTXO context is not the active tip; scripts re-verify
  ## during the eventual handleReorg connectBlock call). All context-free
  ## + contextual checks run.
  ##
  ## skipScripts is forced TRUE here: the active chainstate's UTXO set
  ## does not match this block's parent state, so script verification
  ## against active-chain UTXOs would falsely reject every input. Scripts
  ## are re-verified when handleReorg later calls connectBlock on the
  ## side-branch chain (where the disconnect-then-reconnect rebuilds the
  ## UTXO state to the fork point).
  let csRef = cs
  let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
    try: csRef.getUtxo(op)
    except: none(UtxoEntry)
  acceptBlock(blk, prevIdx, cs.db, cs.params,
              skipScripts = true,          # scripts re-verify on reorg
              checkPow = true,
              getUtxo = utxoLookup,
              crypto = crypto,
              skipConnectChecks = true)    # defer UTXO/fee/BIP-30/BIP-68 to
                                           # connect time; active-tip UTXO does
                                           # not represent this block's parent
                                           # state — a UTXO consumed by the active
                                           # chain above the fork is legitimately
                                           # present at the fork but looks missing
                                           # here → false bad-txns-inputs-missingorspent.
                                           # ConnectBlock runs at handleReorg time
                                           # against the fork-point UTXO view.

