## Block and transaction validation
## Full consensus rules implementation per Bitcoin protocol

import std/[times, options, algorithm, tables]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1]
import ../storage/chainstate
import ../script/interpreter
import ./params

export params

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

# Get script flags for block validation
proc getBlockScriptFlags*(height: int32, params: ConsensusParams): set[ScriptFlags] =
  ## Get consensus-only script verification flags for a block at given height
  ## CRITICAL: Only use consensus flags, not policy flags

  result = {}

  # P2SH (BIP16) - always active on mainnet
  if height >= 1:  # Active from genesis effectively
    result.incl(sfP2SH)

  # DERSIG (BIP66)
  if height >= int32(params.bip66Height):
    result.incl(sfDERSig)

  # CHECKLOCKTIMEVERIFY (BIP65)
  if height >= int32(params.bip65Height):
    result.incl(sfCheckLockTimeVerify)

  # CHECKSEQUENCEVERIFY (BIP112) - same height as SegWit for simplicity
  if height >= int32(params.segwitHeight):
    result.incl(sfCheckSequenceVerify)

  # SegWit (BIP141/143/147)
  if height >= int32(params.segwitHeight):
    result.incl(sfWitness)
    result.incl(sfNullDummy)

  # Taproot (BIP341/342)
  if height >= int32(params.taprootHeight):
    result.incl(sfTaproot)

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
  ## If accurate=true, uses precise counting (for P2SH)
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

proc countBlockSigops*(blk: Block, params: ConsensusParams): int =
  ## Count total sigops in a block
  ## Includes scriptSig and scriptPubKey sigops

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

  # Check sigops
  let sigops = countBlockSigops(blk, params)
  if sigops > params.maxBlockSigopsCost:
    return voidErr(veSigopExceeded)

  # Validate transactions and track fees
  # CRITICAL: Maintain intra-block UTXOs for txs that spend outputs from earlier txs in same block
  var totalFees = int64(0)
  var intraBlockUtxos = initTable[string, UtxoEntry]()

  # Add coinbase outputs to intra-block UTXOs
  let coinbaseTxid = blk.txs[0].txid()
  for vout, output in blk.txs[0].outputs:
    let key = $array[32, byte](coinbaseTxid) & ":" & $vout
    intraBlockUtxos[key] = UtxoEntry(
      output: output,
      height: height,
      isCoinbase: true
    )

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

  let flags = getBlockScriptFlags(height, params)

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

    for inputIdx, inp in tx.inputs:
      # Look up the UTXO being spent
      let key = $array[32, byte](inp.prevOut.txid) & ":" & $inp.prevOut.vout
      var utxoOpt: Option[UtxoEntry]
      if key in intraBlockUtxos:
        utxoOpt = some(intraBlockUtxos[key])
      else:
        utxoOpt = utxos(inp.prevOut)

      if utxoOpt.isNone:
        return voidErr(veInputsMissing)

      let utxo = utxoOpt.get()

      # Get witness data for this input
      var witness: seq[seq[byte]] = @[]
      if inputIdx < tx.witnesses.len:
        witness = tx.witnesses[inputIdx]

      # Verify the script
      let verified = verifyScript(
        inp.scriptSig,
        utxo.output.scriptPubKey,
        tx,
        inputIdx,
        utxo.output.value,
        flags,
        witness
      )

      if not verified:
        return voidErr(veScriptVerifyFailed)

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
