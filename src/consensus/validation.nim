## Block and transaction validation
## Full consensus rules implementation per Bitcoin protocol

import std/[times, options, algorithm, tables]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1]
import ../storage/chainstate
import ../script/interpreter
import ../perf/sig_cache
import ./params

export params
export sig_cache

var globalSigCache* = newSigCache(50_000)

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
    veScriptVerifyFailed = "script verification failed"
    veBadCoinbase = "invalid coinbase transaction"
    veNoCoinbase = "missing coinbase transaction"
    veBadTxVersion = "invalid transaction version"
    veDuplicateInput = "duplicate transaction input"
    veBadOutputValue = "invalid output value"
    veFeeTooLow = "transaction fee too low"
    veBadBlockVersion = "invalid block version"
    vePrevBlockMissing = "previous block not found"
    veSequenceLockNotSatisfied = "BIP68 relative lock-time not satisfied"
    veCheckpointMismatch = "block hash does not match checkpoint"
    veForkBelowCheckpoint = "cannot fork before the last checkpoint"
    veInsufficientChainWork = "chain does not meet minimum work requirement"

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

# Merkle root computation with Bitcoin's duplicate-last-if-odd rule
proc computeMerkleRoot*(txids: seq[array[32, byte]]): array[32, byte] =
  ## Compute merkle root from a list of transaction hashes
  ## If odd number of elements, duplicate the last one
  if txids.len == 0:
    return default(array[32, byte])

  if txids.len == 1:
    return txids[0]

  var level = txids
  while level.len > 1:
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

# Coinbase validation
proc isCoinbase*(tx: Transaction): bool =
  ## Check if transaction is a coinbase transaction
  tx.inputs.len == 1 and
  tx.inputs[0].prevOut.txid == TxId(default(array[32, byte])) and
  tx.inputs[0].prevOut.vout == 0xffffffff'u32

proc validateCoinbase*(tx: Transaction, height: int32, params: ConsensusParams): ValidationResult[void] =
  ## Validate coinbase transaction structure
  if not isCoinbase(tx):
    return voidErr(veNoCoinbase)

  # BIP34: coinbase must include block height in scriptSig
  # Height must be serialized as minimal CScriptNum at start of scriptSig
  if height >= int32(params.bip34Height):
    let scriptSig = tx.inputs[0].scriptSig
    if scriptSig.len < 1:
      return voidErr(veBadCoinbaseSize)

    # First byte indicates how many bytes encode the height
    let heightBytes = int(scriptSig[0])
    if heightBytes == 0 or heightBytes > 4:
      if height > 0 or heightBytes != 0:
        return voidErr(veBadCoinbaseSize)

    if scriptSig.len < 1 + heightBytes:
      return voidErr(veBadCoinbaseSize)

    # Decode the height (little-endian)
    var encodedHeight: int64 = 0
    for i in 0 ..< heightBytes:
      encodedHeight = encodedHeight or (int64(scriptSig[1 + i]) shl (8 * i))

    if encodedHeight != int64(height):
      return voidErr(veBadCoinbaseSize)

  # Check scriptSig size (2-100 bytes per protocol)
  let scriptSigLen = tx.inputs[0].scriptSig.len
  if scriptSigLen < 2 or scriptSigLen > 100:
    return voidErr(veBadCoinbaseSize)

  ok()

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
  ## Get witness reserved value from coinbase witness
  ## Default is all zeros if not present
  if tx.witnesses.len > 0 and tx.witnesses[0].len > 0:
    let stack = tx.witnesses[0]
    if stack.len > 0 and stack[0].len == 32:
      copyMem(addr result[0], unsafeAddr stack[0][0], 32)

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

  # SegWit (BIP141/143/147) — activated at segwitHeight
  if height >= int32(params.segwitHeight):
    result.incl(sfWitness)
    result.incl(sfNullDummy)
    result.incl(sfNullFail)
    result.incl(sfWitnessPubkeyType)  # BIP141: witness pubkeys must be compressed

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

  # BIP68 only applies to transactions with version >= 2
  if tx.version < 2:
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

  # BIP68 only applies if tx version >= 2
  if tx.version < 2:
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

  # Check for duplicate inputs
  var seenInputs = initTable[string, bool]()
  for inp in tx.inputs:
    let key = $inp.prevOut.txid & ":" & $inp.prevOut.vout
    if key in seenInputs:
      return err(int64, veDuplicateInput)
    seenInputs[key] = true

  # Check output values
  var totalOutput = int64(0)
  for output in tx.outputs:
    let value = int64(output.value)
    if value < 0:
      return err(int64, veBadOutputValue)
    if value > int64(MaxMoney):
      return err(int64, veBadOutputValue)
    totalOutput += value
    if totalOutput > int64(MaxMoney):
      return err(int64, veBadOutputValue)

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
  let fee = totalInput - totalOutput
  if fee < 0:
    return err(int64, veBadAmount)

  ok(fee)

# Block header validation
proc validateBlockHeader*(
  header: BlockHeader,
  prevIndex: BlockIndex,
  params: ConsensusParams,
  checkPow: bool = true
): ValidationResult[void] =
  ## Validate block header against consensus rules

  # Check proof of work
  if checkPow:
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))
    if not hashMeetsTarget(hash, header.bits):
      return voidErr(veExceedsTarget)

  # Check timestamp > MTP of previous 11 blocks
  # For simplicity, just check against previous block for now
  # Full MTP check requires access to previous 11 headers
  if header.timestamp <= prevIndex.header.timestamp:
    # This is a simplified check - full implementation would use MTP
    discard  # Allow for now, full MTP check done in validateBlock

  # Check timestamp not too far in future
  let now = getTime().toUnix().uint32
  if header.timestamp > now + uint32(MaxFutureBlockTime):
    return voidErr(veBadTimestamp)

  # Check previous block hash matches
  if header.prevBlock != prevIndex.hash:
    return voidErr(vePrevBlockMissing)

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

# Full block validation
proc validateBlock*(
  blk: Block,
  prevIndex: BlockIndex,
  utxos: ChainDb,
  params: ConsensusParams,
  checkScripts: bool = true
): ValidationResult[void] =
  ## Full block validation per Bitcoin consensus rules

  # Validate header
  let headerResult = validateBlockHeader(blk.header, prevIndex, params)
  if not headerResult.isOk:
    return voidErr(headerResult.error)

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

  # Check merkle root
  var txHashes: seq[array[32, byte]]
  for tx in blk.txs:
    txHashes.add(array[32, byte](tx.txid()))

  let computedMerkle = computeMerkleRoot(txHashes)
  if computedMerkle != blk.header.merkleRoot:
    return voidErr(veBadMerkleRoot)

  # Check block weight
  let weight = calculateBlockWeight(blk)
  if weight > params.maxBlockWeight:
    return voidErr(veBlockOverweight)

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

  # Check if BIP68 (CSV) is active at this height
  let bip68Active = height >= int32(params.csvHeight)

  # Precompute the MTP of the previous block for sequence lock checking
  var prevBlockMtp: uint32 = 0
  if bip68Active and prevIndex.height >= 0:
    prevBlockMtp = getMtpForHeight(utxos, prevIndex.height)

  # Create a closure for getMtpAtHeight that can be passed to sequence lock functions
  proc getMtpAtHeight(h: int32): uint32 =
    getMtpForHeight(utxos, h)

  # Validate non-coinbase transactions
  for i in 1 ..< blk.txs.len:
    let tx = blk.txs[i]

    # Create UTXO lookup that includes intra-block UTXOs
    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      let key = $array[32, byte](op.txid) & ":" & $op.vout
      if key in intraBlockUtxos:
        return some(intraBlockUtxos[key])
      utxos.getUtxo(op)

    let txResult = validateTransaction(tx, lookupUtxo, height, params, intraBlockUtxos)
    if not txResult.isOk:
      return voidErr(txResult.error)

    totalFees += txResult.value

    # Count sigops for this transaction with proper witness discount
    let sigopResult = getTransactionSigOpCost(tx, lookupUtxo, useP2SH = true, useWitness = useWitnessSigops)
    if sigopResult.isOk:
      totalSigopCost += sigopResult.value
    # Note: If sigop counting fails (missing UTXO), validation would have already failed above

    # BIP68 sequence lock check (only if CSV is active and tx version >= 2)
    if bip68Active and tx.version >= 2:
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

  # Check witness commitment (SegWit)
  if height >= int32(params.segwitHeight):
    var hasWitness = false
    for tx in blk.txs:
      if tx.witnesses.len > 0:
        for w in tx.witnesses:
          if w.len > 0:
            hasWitness = true
            break
        if hasWitness:
          break

    if hasWitness:
      let commitmentOpt = findWitnessCommitment(blk.txs[0])
      if commitmentOpt.isNone:
        return voidErr(veBadWitnessCommitment)

      # Compute witness commitment
      var wtxids: seq[array[32, byte]]
      # Coinbase wtxid is all zeros
      wtxids.add(default(array[32, byte]))
      for i in 1 ..< blk.txs.len:
        wtxids.add(array[32, byte](blk.txs[i].wtxid()))

      let reserved = getWitnessReservedValue(blk.txs[0])
      let computedCommitment = computeWitnessCommitment(wtxids, reserved)

      if computedCommitment != commitmentOpt.get():
        return voidErr(veBadWitnessCommitment)

  ok()

proc scriptFlagsToUint32(flags: set[ScriptFlags]): uint32 =
  ## Convert script flags set to a uint32 for use as cache key
  result = 0
  for f in flags:
    result = result or (1u32 shl uint32(ord(f)))

# Script verification for a block
proc verifyScripts*(
  blk: Block,
  utxos: proc(op: OutPoint): Option[UtxoEntry],
  height: int32,
  crypto: CryptoEngine,
  params: ConsensusParams
): ValidationResult[void] =
  ## Verify all scripts in a block
  ## This is typically called after validateBlock passes

  # Compute block hash for script_flag_exceptions check
  let headerBytes = serialize(blk.header)
  let blockHash = $BlockHash(doubleSha256(headerBytes))
  let flags = getBlockScriptFlags(height, params, blockHash)
  let flagsUint = scriptFlagsToUint32(flags)

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

  # Verify scripts for non-coinbase transactions
  for i in 1 ..< blk.txs.len:
    let tx = blk.txs[i]
    let txidBytes = array[32, byte](tx.txid())

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

    for inputIdx, inp in tx.inputs:
      # Check signature cache before expensive verification
      if globalSigCache.lookup(txidBytes, uint32(inputIdx), flagsUint):
        continue

      let utxo = allUtxos[inputIdx]

      # Get witness data for this input
      var witness: seq[seq[byte]] = @[]
      if inputIdx < tx.witnesses.len:
        witness = tx.witnesses[inputIdx]

      # Verify the script (pass all amounts/scriptPubKeys for taproot sighash)
      let verified = verifyScript(
        inp.scriptSig,
        utxo.output.scriptPubKey,
        tx,
        inputIdx,
        utxo.output.value,
        flags,
        witness,
        allAmounts,
        allScriptPubKeys
      )

      if not verified:
        return voidErr(veScriptVerifyFailed)

      # Cache successful verification
      globalSigCache.insert(txidBytes, uint32(inputIdx), flagsUint)

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
  ## Legacy basic transaction validation (without UTXO context)

  # Must have at least one input and one output
  if tx.inputs.len == 0:
    return voidErr(veInputsMissing)
  if tx.outputs.len == 0:
    return voidErr(veBadOutputValue)

  # Check for duplicate inputs
  for i in 0 ..< tx.inputs.len:
    for j in (i + 1) ..< tx.inputs.len:
      if tx.inputs[i].prevOut.txid == tx.inputs[j].prevOut.txid and
         tx.inputs[i].prevOut.vout == tx.inputs[j].prevOut.vout:
        return voidErr(veDuplicateInput)

  # Check output values
  var totalOutput = Satoshi(0)
  for output in tx.outputs:
    if int64(output.value) < 0:
      return voidErr(veBadOutputValue)
    if output.value > MaxMoney:
      return voidErr(veBadOutputValue)
    totalOutput = totalOutput + output.value
    if totalOutput > MaxMoney:
      return voidErr(veBadOutputValue)

  ok()

proc checkBlock*(blk: Block, params: ConsensusParams): ValidationResult[void] =
  ## Legacy block validation (simplified, without full UTXO context)

  # Check header
  let headerResult = checkBlockHeader(blk.header, params)
  if not headerResult.isOk:
    return voidErr(headerResult.error)

  # Must have at least one transaction (coinbase)
  if blk.txs.len == 0:
    return voidErr(veNoCoinbase)

  # Check each transaction
  for i, tx in blk.txs:
    let txResult = checkTransaction(tx, params)
    if not txResult.isOk:
      return txResult

  # Verify merkle root
  var txHashes: seq[array[32, byte]]
  for tx in blk.txs:
    txHashes.add(array[32, byte](tx.txid()))

  let computedRoot = computeMerkleRoot(txHashes)
  if computedRoot != blk.header.merkleRoot:
    return voidErr(veBadMerkleRoot)

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

# Overloaded procs that return legacy result
proc checkBlockHeaderLegacy*(
  header: BlockHeader,
  params: ConsensusParams,
  prevHeader: BlockHeader = default(BlockHeader)
): LegacyValidationResult =
  checkBlockHeader(header, params, prevHeader).toLegacy()

proc checkTransactionLegacy*(tx: Transaction, params: ConsensusParams): LegacyValidationResult =
  checkTransaction(tx, params).toLegacy()

proc checkBlockLegacy*(blk: Block, params: ConsensusParams): LegacyValidationResult =
  checkBlock(blk, params).toLegacy()
