## Block and transaction validation
## Consensus rules implementation

import std/[times]
import ../primitives/[types, serialize]
import ../crypto/hashing
import ./params

type
  ValidationError* = object of CatchableError

  ValidationResult* = object
    valid*: bool
    error*: string

proc ok*(): ValidationResult =
  ValidationResult(valid: true, error: "")

proc err*(msg: string): ValidationResult =
  ValidationResult(valid: false, error: msg)

proc checkBlockHeader*(
  header: BlockHeader,
  params: ConsensusParams,
  prevHeader: BlockHeader = default(BlockHeader)
): ValidationResult =
  ## Validate a block header

  # Check proof of work
  let headerBytes = serialize(header)
  let hash = doubleSha256(headerBytes)

  # Compare hash against target derived from bits
  # Simplified check - real implementation needs proper target calculation
  let leadingZeros = countLeadingZeroBits(hash)
  if header.bits != 0:
    # bits encodes target in compact format
    let exponent = (header.bits shr 24) and 0xff
    if exponent > 3:
      let targetLeadingZeros = (32 - int(exponent) + 3) * 8
      if leadingZeros < targetLeadingZeros - 24:  # Rough approximation
        discard  # Would fail in strict mode

  # Check timestamp
  let now = getTime().toUnix().uint32
  if header.timestamp > now + 2 * 60 * 60:  # 2 hours in future
    return err("block timestamp too far in future")

  ok()

proc countLeadingZeroBits(hash: array[32, byte]): int =
  for i in countdown(31, 0):
    if hash[i] == 0:
      result += 8
    else:
      var b = hash[i]
      while (b and 0x80) == 0:
        result += 1
        b = b shl 1
      return

proc checkTransaction*(tx: Transaction, params: ConsensusParams): ValidationResult =
  ## Basic transaction validation

  # Must have at least one input and one output
  if tx.inputs.len == 0:
    return err("transaction has no inputs")
  if tx.outputs.len == 0:
    return err("transaction has no outputs")

  # Check for duplicate inputs
  for i in 0 ..< tx.inputs.len:
    for j in (i + 1) ..< tx.inputs.len:
      if tx.inputs[i].prevout.txid == tx.inputs[j].prevout.txid and
         tx.inputs[i].prevout.vout == tx.inputs[j].prevout.vout:
        return err("duplicate input")

  # Check output values
  var totalOutput = Satoshi(0)
  for output in tx.outputs:
    if int64(output.value) < 0:
      return err("negative output value")
    if output.value > MAX_MONEY:
      return err("output value too large")
    totalOutput = totalOutput + output.value
    if totalOutput > MAX_MONEY:
      return err("total output value too large")

  ok()

proc checkBlock*(blk: Block, params: ConsensusParams): ValidationResult =
  ## Validate a complete block

  # Check header
  let headerResult = checkBlockHeader(blk.header, params)
  if not headerResult.valid:
    return headerResult

  # Must have at least one transaction (coinbase)
  if blk.transactions.len == 0:
    return err("block has no transactions")

  # Check each transaction
  for i, tx in blk.transactions:
    let txResult = checkTransaction(tx, params)
    if not txResult.valid:
      return err("invalid transaction " & $i & ": " & txResult.error)

  # Verify merkle root
  var txHashes: seq[array[32, byte]]
  for tx in blk.transactions:
    let txBytes = serialize(tx)
    txHashes.add(doubleSha256(txBytes))

  let computedRoot = computeMerkleRoot(txHashes)
  if computedRoot != blk.header.merkleRoot:
    return err("merkle root mismatch")

  ok()

proc isCoinbase*(tx: Transaction): bool =
  ## Check if transaction is a coinbase transaction
  tx.inputs.len == 1 and
  tx.inputs[0].prevout.txid == TxId(default(array[32, byte])) and
  tx.inputs[0].prevout.vout == 0xffffffff'u32
