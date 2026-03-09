## Block template generation
## Creates block templates for mining with witness commitment support

import std/[times, options]
import ../primitives/[types, serialize]
import ../consensus/params
import ../mempool/mempool
import ../crypto/hashing
import ../storage/chainstate

const
  WitnessCommitmentHeader* = @[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]
  CoinbaseReservedWeight* = 4000  ## Reserved weight units for coinbase tx

type
  BlockTemplate* = object
    header*: BlockHeader
    coinbaseTx*: Transaction
    transactions*: seq[Transaction]
    totalFees*: Satoshi
    totalWeight*: int
    totalSigops*: int
    height*: int
    target*: array[32, byte]

proc encodeBip34Height*(height: int32): seq[byte] =
  ## Encode block height for coinbase scriptSig per BIP-34
  ## Uses minimal push encoding
  if height < 0:
    # Should not happen, but handle gracefully
    return @[0x01'u8, 0x00]
  elif height == 0:
    # OP_0 (0x00) represents 0
    return @[0x01'u8, 0x00]
  elif height <= 16:
    # Could use OP_1..OP_16, but BIP-34 specifies push encoding
    return @[0x01'u8, byte(height)]
  elif height < 128:
    # 1-byte push
    return @[0x01'u8, byte(height)]
  elif height < 32768:
    # 2-byte push (little-endian)
    return @[0x02'u8, byte(height and 0xff), byte((height shr 8) and 0xff)]
  elif height < 8388608:
    # 3-byte push (little-endian)
    return @[0x03'u8, byte(height and 0xff), byte((height shr 8) and 0xff),
             byte((height shr 16) and 0xff)]
  else:
    # 4-byte push (little-endian)
    return @[0x04'u8, byte(height and 0xff), byte((height shr 8) and 0xff),
             byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]

proc computeWitnessCommitment*(txs: seq[Transaction]): array[32, byte] =
  ## Compute witness commitment for a block
  ## SHA-256d(merkleRoot(wtxids) || 0x00*32)
  ## The coinbase wtxid is always 32 zero bytes

  if txs.len == 0:
    return default(array[32, byte])

  # Build wtxid list - coinbase wtxid is all zeros
  var wtxids: seq[array[32, byte]]
  wtxids.add(default(array[32, byte]))  # Coinbase wtxid = 0x00...00

  # Add wtxids for remaining transactions
  for i in 1 ..< txs.len:
    let wtxidVal = txs[i].wtxid()
    wtxids.add(array[32, byte](wtxidVal))

  # Compute merkle root of wtxids
  let witnessMerkleRoot = computeMerkleRoot(wtxids)

  # Concatenate with witness reserved value (32 zero bytes)
  var commitment: array[64, byte]
  copyMem(addr commitment[0], addr witnessMerkleRoot[0], 32)
  # commitment[32..63] is already zero from initialization

  # Double SHA-256
  doubleSha256(commitment)

proc createWitnessCommitmentOutput*(witnessCommitment: array[32, byte]): TxOut =
  ## Create the witness commitment output for coinbase
  ## OP_RETURN <0x24 bytes: 0xaa21a9ed || commitment>
  var scriptPubKey: seq[byte]
  scriptPubKey.add(WitnessCommitmentHeader)
  for b in witnessCommitment:
    scriptPubKey.add(b)

  TxOut(
    value: Satoshi(0),
    scriptPubKey: scriptPubKey
  )

proc createCoinbaseTx*(
  height: int32,
  subsidy: Satoshi,
  fees: Satoshi,
  scriptPubKey: seq[byte],
  witnessCommitment: array[32, byte]
): Transaction =
  ## Create a coinbase transaction
  ## BIP-34: height in scriptSig
  ## Witness commitment in OP_RETURN output (if not all zeros)

  # Build coinbase scriptSig with BIP-34 height
  var scriptSig = encodeBip34Height(height)

  # Add extra nonce space (8 bytes for mining variation)
  for i in 0 ..< 8:
    scriptSig.add(0x00)

  # Check if we have a non-zero witness commitment
  var hasWitnessCommitment = false
  for b in witnessCommitment:
    if b != 0:
      hasWitnessCommitment = true
      break

  # Build outputs
  var outputs: seq[TxOut]

  # Main output (block reward)
  outputs.add(TxOut(
    value: subsidy + fees,
    scriptPubKey: scriptPubKey
  ))

  # Witness commitment output (if any segwit txs)
  if hasWitnessCommitment:
    outputs.add(createWitnessCommitmentOutput(witnessCommitment))

  # Build coinbase witness - required for segwit blocks
  # Coinbase witness must have exactly one item: 32 zero bytes
  var witnesses: seq[seq[seq[byte]]]
  if hasWitnessCommitment:
    var witnessStack: seq[seq[byte]]
    var witnessReserved: seq[byte]
    for i in 0 ..< 32:
      witnessReserved.add(0x00)
    witnessStack.add(witnessReserved)
    witnesses.add(witnessStack)

  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xffffffff'u32
      ),
      scriptSig: scriptSig,
      sequence: 0xffffffff'u32
    )],
    outputs: outputs,
    witnesses: witnesses,
    lockTime: 0
  )

proc computeTarget*(bits: uint32): array[32, byte] =
  ## Convert compact bits to full target
  compactToTarget(bits)

proc estimateTxSigops*(tx: Transaction): int =
  ## Estimate sigops for a transaction
  ## This is a simplified estimate - real implementation would
  ## need to analyze scripts more deeply

  # Legacy sigops: count OP_CHECKSIG, OP_CHECKMULTISIG in scriptPubKey
  var sigops = 0

  # Estimate based on output types
  for output in tx.outputs:
    let script = output.scriptPubKey
    if script.len == 0:
      continue

    # P2PKH: 1 sigop
    if script.len == 25 and script[0] == 0x76:  # OP_DUP
      sigops += 1
    # P2SH: assume 1 sigop (conservative)
    elif script.len == 23 and script[0] == 0xa9:  # OP_HASH160
      sigops += 1
    # P2WPKH: 1 sigop (scaled by witness factor)
    elif script.len == 22 and script[0] == 0x00:
      sigops += 1
    # P2WSH: assume 1 sigop
    elif script.len == 34 and script[0] == 0x00:
      sigops += 1
    # P2TR: 1 sigop
    elif script.len == 34 and script[0] == 0x51:  # OP_1 (v1)
      sigops += 1

  # Count sigops in inputs (for P2PKH)
  for input in tx.inputs:
    if input.scriptSig.len > 0:
      # Simple heuristic: each signature is ~72 bytes
      sigops += max(1, input.scriptSig.len div 72)

  sigops

proc calculateTxWeight*(tx: Transaction): int =
  ## Calculate transaction weight
  let fullSize = serialize(tx, includeWitness = true).len
  let baseSize = serializeLegacy(tx).len
  (baseSize * 3) + fullSize

proc buildBlockTemplate*(
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte]
): BlockTemplate =
  ## Build a new block template
  ## Greedy selection by ancestor fee rate
  ## Reserve 4K WU for coinbase, sigops <= 80K

  let height = chainState.bestHeight + 1
  let subsidy = getBlockSubsidy(height, params)

  # Reserve space for coinbase
  let maxTxWeight = params.maxBlockWeight - CoinbaseReservedWeight

  # Get transactions sorted by ancestor fee rate
  let selectedEntries = mempool.getTransactionsByFeeRate(maxTxWeight)

  # Build transaction list and enforce sigops limit
  var txList: seq[Transaction]
  var totalFees = Satoshi(0)
  var totalWeight = 0
  var totalSigops = 0

  for entry in selectedEntries:
    let txSigops = estimateTxSigops(entry.tx)

    # Check sigops limit
    if totalSigops + txSigops > MaxBlockSigopsCost:
      continue  # Skip this tx, try next

    txList.add(entry.tx)
    totalFees = totalFees + entry.fee
    totalWeight += entry.weight
    totalSigops += txSigops

  # Check if we have any segwit transactions
  var hasSegwit = false
  for tx in txList:
    if tx.isSegwit:
      hasSegwit = true
      break

  # Compute witness commitment (for the full tx list including placeholder coinbase)
  var allTxs: seq[Transaction]
  # Placeholder coinbase (will be replaced)
  allTxs.add(Transaction())
  allTxs.add(txList)

  var witnessCommitment: array[32, byte]
  if hasSegwit:
    witnessCommitment = computeWitnessCommitment(allTxs)

  # Create coinbase with witness commitment
  let coinbase = createCoinbaseTx(
    height,
    subsidy,
    totalFees,
    coinbaseScript,
    witnessCommitment
  )

  # Build final transaction list
  var transactions = @[coinbase]
  transactions.add(txList)

  # Recompute witness commitment with actual coinbase
  if hasSegwit:
    witnessCommitment = computeWitnessCommitment(transactions)
    # Update coinbase with correct commitment
    let updatedCoinbase = createCoinbaseTx(
      height,
      subsidy,
      totalFees,
      coinbaseScript,
      witnessCommitment
    )
    transactions[0] = updatedCoinbase

  # Compute merkle root
  var txHashes: seq[array[32, byte]]
  for tx in transactions:
    let txBytes = serialize(tx)
    txHashes.add(doubleSha256(txBytes))
  let merkleRoot = computeMerkleRoot(txHashes)

  # Get previous block hash
  let prevHash = chainState.bestBlockHash

  # Determine bits (difficulty)
  var bits = params.genesisBits
  let prevBlock = chainState.db.getBlock(prevHash)
  if prevBlock.isSome:
    bits = prevBlock.get().header.bits

  # Add coinbase weight to total
  let coinbaseWeight = calculateTxWeight(transactions[0])
  totalWeight += coinbaseWeight

  let header = BlockHeader(
    version: 0x20000000,  # BIP9 version bits
    prevBlock: prevHash,
    merkleRoot: merkleRoot,
    timestamp: uint32(getTime().toUnix()),
    bits: bits,
    nonce: 0
  )

  BlockTemplate(
    header: header,
    coinbaseTx: transactions[0],
    transactions: transactions,
    totalFees: totalFees,
    totalWeight: totalWeight,
    totalSigops: totalSigops,
    height: height,
    target: computeTarget(bits)
  )

proc updateTimestamp*(tmpl: var BlockTemplate) =
  ## Update template timestamp
  tmpl.header.timestamp = uint32(getTime().toUnix())

proc updateExtraNonce*(tmpl: var BlockTemplate, extraNonce: uint64) =
  ## Update extra nonce in coinbase and recalculate merkle root
  if tmpl.transactions.len == 0:
    return

  # Modify coinbase scriptSig
  var scriptSig = tmpl.transactions[0].inputs[0].scriptSig

  # Find the extra nonce position (after BIP-34 height encoding)
  # Height encoding uses 1-5 bytes, extra nonce is the next 8 bytes
  let heightLen = int(scriptSig[0]) + 1  # First byte is length, then data
  let offset = min(heightLen, scriptSig.len - 8)

  if offset >= 0 and offset + 8 <= scriptSig.len:
    # Write extra nonce (8 bytes, little-endian)
    for i in 0 ..< 8:
      scriptSig[offset + i] = byte((extraNonce shr (i * 8)) and 0xff)
    tmpl.transactions[0].inputs[0].scriptSig = scriptSig
    tmpl.coinbaseTx.inputs[0].scriptSig = scriptSig

  # Recalculate merkle root
  var txHashes: seq[array[32, byte]]
  for tx in tmpl.transactions:
    let txBytes = serialize(tx)
    txHashes.add(doubleSha256(txBytes))
  tmpl.header.merkleRoot = computeMerkleRoot(txHashes)

proc hashMeetsTarget*(hash: array[32, byte], target: array[32, byte]): bool =
  ## Check if hash meets difficulty target
  for i in countdown(31, 0):
    if hash[i] < target[i]:
      return true
    if hash[i] > target[i]:
      return false
  true

proc mine*(tmpl: var BlockTemplate, maxIterations: uint32 = 0xffffffff'u32): bool =
  ## Attempt to find a valid nonce (CPU mining)
  for nonce in 0'u32 ..< maxIterations:
    tmpl.header.nonce = nonce
    let headerBytes = serialize(tmpl.header)
    let hash = doubleSha256(headerBytes)
    if hashMeetsTarget(hash, tmpl.target):
      return true
  false

proc toBlock*(tmpl: BlockTemplate): Block =
  Block(
    header: tmpl.header,
    txs: tmpl.transactions
  )
