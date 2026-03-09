## Block template generation
## Creates block templates for mining

import std/[times, algorithm]
import ../primitives/[types, serialize]
import ../consensus/params
import ../mempool/mempool
import ../crypto/hashing
import ../storage/chainstate

type
  BlockTemplate* = object
    header*: BlockHeader
    transactions*: seq[Transaction]
    coinbaseValue*: Satoshi
    fees*: Satoshi
    height*: int
    target*: array[32, byte]

proc createCoinbase*(
  height: int,
  coinbaseValue: Satoshi,
  scriptPubKey: seq[byte]
): Transaction =
  ## Create a coinbase transaction
  # Build coinbase script (BIP34 requires height in scriptSig)
  var scriptSig: seq[byte] = @[]

  # Encode height (BIP34)
  if height < 17:
    scriptSig.add(byte(0x50 + height))
  elif height < 128:
    scriptSig.add(0x01)
    scriptSig.add(byte(height))
  elif height < 32768:
    scriptSig.add(0x02)
    scriptSig.add(byte(height and 0xff))
    scriptSig.add(byte((height shr 8) and 0xff))
  else:
    scriptSig.add(0x03)
    scriptSig.add(byte(height and 0xff))
    scriptSig.add(byte((height shr 8) and 0xff))
    scriptSig.add(byte((height shr 16) and 0xff))

  # Add extra nonce space
  for i in 0 ..< 8:
    scriptSig.add(0x00)

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
    outputs: @[TxOut(
      value: coinbaseValue,
      scriptPubKey: scriptPubKey
    )],
    witnesses: @[],
    lockTime: 0
  )

proc computeTarget*(bits: uint32): array[32, byte] =
  ## Convert compact bits to full target
  let exponent = int((bits shr 24) and 0xff)
  let mantissa = bits and 0x007fffff

  if exponent <= 3:
    let value = mantissa shr (8 * (3 - exponent))
    result[0] = byte(value and 0xff)
    if exponent >= 2:
      result[1] = byte((value shr 8) and 0xff)
    if exponent >= 3:
      result[2] = byte((value shr 16) and 0xff)
  else:
    let idx = exponent - 3
    result[idx] = byte(mantissa and 0xff)
    result[idx + 1] = byte((mantissa shr 8) and 0xff)
    result[idx + 2] = byte((mantissa shr 16) and 0xff)

proc buildBlockTemplate*(
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte]
): BlockTemplate =
  ## Build a new block template
  let height = chainState.bestHeight + 1
  let subsidy = getBlockSubsidy(height, params)

  # Select transactions from mempool
  let maxWeight = params.maxBlockWeight - 4000  # Reserve space for coinbase
  let selectedTxs = mempool.selectTransactionsForBlock(maxWeight)

  # Calculate total fees
  var totalFees = Satoshi(0)
  for entry in mempool.entries.values:
    for tx in selectedTxs:
      let txBytes = serialize(tx)
      let txid = TxId(doubleSha256(txBytes))
      if txid == entry.txid:
        totalFees = totalFees + entry.fee
        break

  let coinbaseValue = subsidy + totalFees

  # Create coinbase
  let coinbase = createCoinbase(height, coinbaseValue, coinbaseScript)

  # Build transaction list
  var transactions = @[coinbase]
  transactions.add(selectedTxs)

  # Compute merkle root
  var txHashes: seq[array[32, byte]]
  for tx in transactions:
    let txBytes = serialize(tx)
    txHashes.add(doubleSha256(txBytes))
  let merkleRoot = computeMerkleRoot(txHashes)

  # Get previous block hash
  let prevHash = chainState.bestBlockHash

  # Determine bits (difficulty) - simplified, should use actual retarget
  var bits = params.genesisBits
  let prevBlock = chainState.getBlockByHash(prevHash)
  if prevBlock.isSome:
    bits = prevBlock.get().header.bits

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
    transactions: transactions,
    coinbaseValue: coinbaseValue,
    fees: totalFees,
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
  if scriptSig.len >= 12:
    # Write extra nonce (8 bytes after height encoding)
    let offset = scriptSig.len - 8
    for i in 0 ..< 8:
      scriptSig[offset + i] = byte((extraNonce shr (i * 8)) and 0xff)
    tmpl.transactions[0].inputs[0].scriptSig = scriptSig

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
