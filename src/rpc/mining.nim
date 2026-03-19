## Regtest mining RPCs
## Implements generate, generatetoaddress, generateblock, generatetodescriptor
## Reference: Bitcoin Core rpc/mining.cpp

import std/[options, times]
import ../primitives/[types, serialize]
import ../consensus/params
import ../storage/chainstate
import ../mempool/mempool
import ../crypto/[hashing, address]
import ../mining/blocktemplate
from ../consensus/validation import getMtpForHeight
import ../wallet/descriptor

const
  ## Default max iterations for mining (regtest typically finds on first try)
  DefaultMaxTries* = 1_000_000'u64

  ## Regtest powLimit in compact form: 0x207fffff
  RegtestBits* = 0x207fffff'u32

proc mineBlock*(
  chainState: var ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte],
  maxTries: uint64 = DefaultMaxTries
): Option[Block] =
  ## Mine a single block on regtest
  ## Returns the mined block if successful
  ##
  ## For regtest with powNoRetargeting=true and powAllowMinDifficultyBlocks=true,
  ## nearly any hash will meet the target. Nonce 0 typically works.

  var tmpl = buildBlockTemplate(chainState, mempool, params, coinbaseScript)

  # Use regtest bits (minimum difficulty)
  if params.powNoRetargeting:
    tmpl.header.bits = RegtestBits
    tmpl.target = computeTarget(RegtestBits)

  # Update timestamp
  tmpl.header.timestamp = uint32(getTime().toUnix())

  # Recalculate merkle root since we may have updated transactions
  var txHashes: seq[array[32, byte]]
  for tx in tmpl.transactions:
    let txBytes = serialize(tx)
    txHashes.add(doubleSha256(txBytes))
  tmpl.header.merkleRoot = hashing.computeMerkleRoot(txHashes)

  # Try to find valid nonce
  var nonce = 0'u32
  var tries = 0'u64

  while tries < maxTries:
    tmpl.header.nonce = nonce
    let headerBytes = serialize(tmpl.header)
    let hash = doubleSha256(headerBytes)

    if hashMeetsTarget(hash, tmpl.target):
      # Found valid block
      return some(toBlock(tmpl))

    inc nonce
    inc tries

    # Wrap nonce
    if nonce == 0:
      # Exhausted nonce space, update timestamp and continue
      tmpl.header.timestamp = uint32(getTime().toUnix())

  none(Block)

proc generateBlocks*(
  chainState: var ChainState,
  mempool: var Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte],
  nblocks: int,
  maxTries: uint64 = DefaultMaxTries
): seq[BlockHash] =
  ## Generate n blocks to the given coinbase script
  ## Returns array of block hashes
  ##
  ## Reference: Bitcoin Core generateBlocks() in rpc/mining.cpp

  result = @[]

  for i in 0 ..< nblocks:
    let blockOpt = mineBlock(chainState, mempool, params, coinbaseScript, maxTries)
    if blockOpt.isNone:
      break

    let blk = blockOpt.get()
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    # Connect block to chainstate
    let height = chainState.bestHeight + 1
    let connectResult = chainState.connectBlock(blk, height)
    if not connectResult.isOk:
      break

    # Remove confirmed transactions from mempool
    mempool.removeForBlock(blk)

    result.add(blockHash)

proc generateToAddress*(
  chainState: var ChainState,
  mempool: var Mempool,
  params: ConsensusParams,
  nblocks: int,
  address: string,
  maxTries: uint64 = DefaultMaxTries
): seq[BlockHash] =
  ## Mine blocks with coinbase reward to specified address
  ##
  ## Arguments:
  ## - nblocks: How many blocks to generate
  ## - address: Address to send coinbase reward to
  ## - maxTries: Maximum nonce iterations per block
  ##
  ## Returns: Array of generated block hashes
  ##
  ## Reference: Bitcoin Core generatetoaddress RPC

  # Decode address to get scriptPubKey
  let parsedAddr = decodeAddress(address)
  let coinbaseScript = scriptPubKeyForAddress(parsedAddr)

  generateBlocks(chainState, mempool, params, coinbaseScript, nblocks, maxTries)

proc generateToDescriptor*(
  chainState: var ChainState,
  mempool: var Mempool,
  params: ConsensusParams,
  nblocks: int,
  descriptorStr: string,
  maxTries: uint64 = DefaultMaxTries
): seq[BlockHash] =
  ## Mine blocks with coinbase reward to specified descriptor
  ##
  ## Arguments:
  ## - nblocks: How many blocks to generate
  ## - descriptor: Output descriptor for coinbase
  ## - maxTries: Maximum nonce iterations per block
  ##
  ## Returns: Array of generated block hashes
  ##
  ## Reference: Bitcoin Core generatetodescriptor RPC

  # Parse descriptor to get scriptPubKey
  let desc = parseDescriptor(descriptorStr)
  let scripts = desc.deriveScripts(0, 1)
  if scripts.len == 0:
    return @[]
  let coinbaseScript = scripts[0]

  generateBlocks(chainState, mempool, params, coinbaseScript, nblocks, maxTries)

proc generateBlockWithTxs*(
  chainState: var ChainState,
  mempool: var Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte],
  txids: seq[TxId],
  maxTries: uint64 = DefaultMaxTries
): Option[BlockHash] =
  ## Mine a block containing specific transactions
  ##
  ## Arguments:
  ## - coinbaseScript: Script for coinbase output
  ## - txids: List of transaction IDs to include (in order)
  ## - maxTries: Maximum nonce iterations
  ##
  ## Returns: Block hash if successful
  ##
  ## Reference: Bitcoin Core generateblock RPC

  let height = chainState.bestHeight + 1
  let subsidy = getBlockSubsidy(height, params)

  # Collect transactions from mempool
  var txList: seq[Transaction]
  var totalFees = Satoshi(0)
  var totalWeight = 0
  var totalSigops = 0

  for txid in txids:
    let entryOpt = mempool.get(txid)
    if entryOpt.isNone:
      # Transaction not in mempool
      return none(BlockHash)

    let entry = entryOpt.get()

    # Check finality
    let lockTimeCutoff = getMtpForHeight(chainState.db, chainState.bestHeight)
    if not isFinalTx(entry.tx, uint32(height), lockTimeCutoff):
      return none(BlockHash)  # Non-final transaction

    txList.add(entry.tx)
    totalFees = totalFees + entry.fee
    totalWeight += entry.weight
    totalSigops += estimateTxSigops(entry.tx)

  # Check weight limit
  if totalWeight > params.maxBlockWeight - CoinbaseReservedWeight:
    return none(BlockHash)  # Exceeds weight limit

  # Check sigops limit
  if totalSigops > MaxBlockSigopsCost:
    return none(BlockHash)  # Exceeds sigops limit

  # Check if we have any segwit transactions
  var hasSegwit = false
  for tx in txList:
    if tx.isSegwit:
      hasSegwit = true
      break

  # Compute witness commitment
  var allTxs: seq[Transaction]
  allTxs.add(Transaction())  # Placeholder coinbase
  allTxs.add(txList)

  var witnessCommitment: array[32, byte]
  if hasSegwit:
    witnessCommitment = computeWitnessCommitment(allTxs)

  # Create coinbase
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

  # Determine bits
  var bits = params.genesisBits
  if params.powNoRetargeting:
    bits = RegtestBits

  # Build block header
  var header = BlockHeader(
    version: 0x20000000,
    prevBlock: chainState.bestBlockHash,
    merkleRoot: merkleRoot,
    timestamp: uint32(getTime().toUnix()),
    bits: bits,
    nonce: 0
  )

  let target = computeTarget(bits)

  # Mine the block
  var nonce = 0'u32
  var tries = 0'u64
  var found = false

  while tries < maxTries:
    header.nonce = nonce
    let headerBytes = serialize(header)
    let hash = doubleSha256(headerBytes)

    if hashMeetsTarget(hash, target):
      found = true
      break

    inc nonce
    inc tries

    if nonce == 0:
      header.timestamp = uint32(getTime().toUnix())

  if not found:
    return none(BlockHash)

  let blk = Block(header: header, txs: transactions)
  let headerBytes = serialize(header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  # Connect block to chainstate
  let connectResult = chainState.connectBlock(blk, height)
  if not connectResult.isOk:
    return none(BlockHash)

  # Remove confirmed transactions from mempool
  mempool.removeForBlock(blk)

  some(blockHash)
