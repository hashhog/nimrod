## Coin Stats Index (coinstatsindex)
## Maintains incremental UTXO set statistics using MuHash3072
##
## For each block, tracks:
##   - MuHash of UTXO set (order-independent hash)
##   - Transaction output count
##   - Total amount (sum of all UTXO values)
##   - Total subsidy (cumulative block rewards)
##   - Various unspendable categories
##
## The index supports efficient queries for any block height and
## can be used to verify UTXO set consistency without full rescan.
##
## Reference: Bitcoin Core /src/index/coinstatsindex.cpp
## Reference: Bitcoin Core /src/kernel/coinstats.h

import std/options
import ./base
import ../db
import ../../primitives/[types, serialize]
import ../../crypto/[hashing, muhash]
import ../../consensus/params

type
  ## Per-block UTXO statistics
  CoinStats* = object
    height*: int32
    blockHash*: BlockHash
    muhash*: array[32, byte]            ## Finalized MuHash
    transactionOutputCount*: uint64     ## Number of UTXOs
    bogoSize*: uint64                   ## Serialized size estimate
    totalAmount*: int64                 ## Total value in satoshis
    totalSubsidy*: int64                ## Cumulative block rewards
    totalPrevoutSpentAmount*: uint64    ## Total spent in block
    totalNewOutputsExCoinbase*: uint64  ## New outputs (non-coinbase)
    totalCoinbaseAmount*: uint64        ## Coinbase outputs
    totalUnspendablesGenesisBlock*: int64
    totalUnspendablesBip30*: int64
    totalUnspendablesScripts*: int64
    totalUnspendablesUnclaimedRewards*: int64

  ## Database value for coin stats
  CoinStatsDbVal* = object
    blockHash*: BlockHash
    muhash*: array[32, byte]
    transactionOutputCount*: uint64
    bogoSize*: uint64
    totalAmount*: int64
    totalSubsidy*: int64
    totalPrevoutSpentAmount*: array[32, byte]    ## 256-bit for overflow safety
    totalNewOutputsExCoinbase*: array[32, byte]
    totalCoinbaseAmount*: array[32, byte]
    totalUnspendablesGenesisBlock*: int64
    totalUnspendablesBip30*: int64
    totalUnspendablesScripts*: int64
    totalUnspendablesUnclaimedRewards*: int64

  ## Coin stats index
  CoinStatsIndex* = ref object of BaseIndex
    enabled*: bool
    params*: ConsensusParams

    # Running state
    muhash*: MuHash3072
    transactionOutputCount*: uint64
    bogoSize*: uint64
    totalAmount*: int64
    totalSubsidy*: int64
    totalPrevoutSpentAmount*: uint64
    totalNewOutputsExCoinbase*: uint64
    totalCoinbaseAmount*: uint64
    totalUnspendablesGenesisBlock*: int64
    totalUnspendablesBip30*: int64
    totalUnspendablesScripts*: int64
    totalUnspendablesUnclaimedRewards*: int64
    currentBlockHash*: BlockHash

const
  DbMuHash* = byte('M')            ## Key for MuHash state
  DbCoinStats* = byte('s')         ## Key prefix for per-block stats

# ============================================================================
# BogoSize calculation
# ============================================================================

proc getBogoSize*(scriptPubKey: seq[byte]): uint64 =
  ## Calculate "bogo size" - estimated serialized size of UTXO
  ## Used for UTXO set size estimation
  result = 32 + 4 + 4 + 1 + 8  ## outpoint(36) + height(4) + coinbase(1) + value(8)
  result += uint64(scriptPubKey.len) + 1  ## script + length byte

# ============================================================================
# Database key/value serialization
# ============================================================================

proc coinStatsHeightKey*(height: int32): seq[byte] =
  ## Key for height-indexed stats
  let h = cast[uint32](height)
  result = @[DbCoinStats]
  result.add(byte((h shr 24) and 0xff))
  result.add(byte((h shr 16) and 0xff))
  result.add(byte((h shr 8) and 0xff))
  result.add(byte(h and 0xff))

proc coinStatsHashKey*(blockHash: BlockHash): seq[byte] =
  ## Key for hash-indexed stats (for reorg recovery)
  result = @[byte('h')]
  result.add(@(array[32, byte](blockHash)))

proc muHashKey*(): seq[byte] =
  @[DbMuHash]

proc uint64ToBytes(v: uint64): array[32, byte] =
  ## Convert uint64 to 32-byte array (for 256-bit storage)
  for i in 0 ..< 8:
    result[i] = byte((v shr (i * 8)) and 0xff)

proc bytesToUint64(data: array[32, byte]): uint64 =
  ## Convert 32-byte array back to uint64
  for i in 0 ..< 8:
    result = result or (uint64(data[i]) shl (i * 8))

proc serializeCoinStatsVal*(val: CoinStatsDbVal): seq[byte] =
  var w = BinaryWriter()
  w.writeBlockHash(val.blockHash)
  w.writeBytes(val.muhash)
  w.writeUint64LE(val.transactionOutputCount)
  w.writeUint64LE(val.bogoSize)
  w.writeInt64LE(val.totalAmount)
  w.writeInt64LE(val.totalSubsidy)
  w.writeBytes(val.totalPrevoutSpentAmount)
  w.writeBytes(val.totalNewOutputsExCoinbase)
  w.writeBytes(val.totalCoinbaseAmount)
  w.writeInt64LE(val.totalUnspendablesGenesisBlock)
  w.writeInt64LE(val.totalUnspendablesBip30)
  w.writeInt64LE(val.totalUnspendablesScripts)
  w.writeInt64LE(val.totalUnspendablesUnclaimedRewards)
  w.data

proc deserializeCoinStatsVal*(data: seq[byte]): CoinStatsDbVal =
  if data.len < 32 + 32 + 8 + 8 + 8 + 8 + 32 + 32 + 32 + 8 + 8 + 8 + 8:
    raise newException(IndexError, "invalid CoinStatsDbVal data")
  var r = BinaryReader(data: data, pos: 0)
  result.blockHash = r.readBlockHash()
  result.muhash = r.readHash()
  result.transactionOutputCount = r.readUint64LE()
  result.bogoSize = r.readUint64LE()
  result.totalAmount = r.readInt64LE()
  result.totalSubsidy = r.readInt64LE()
  result.totalPrevoutSpentAmount = r.readHash()
  result.totalNewOutputsExCoinbase = r.readHash()
  result.totalCoinbaseAmount = r.readHash()
  result.totalUnspendablesGenesisBlock = r.readInt64LE()
  result.totalUnspendablesBip30 = r.readInt64LE()
  result.totalUnspendablesScripts = r.readInt64LE()
  result.totalUnspendablesUnclaimedRewards = r.readInt64LE()

# ============================================================================
# CoinStatsIndex implementation
# ============================================================================

proc newCoinStatsIndex*(db: Database, params: ConsensusParams,
                        enabled: bool = true): CoinStatsIndex =
  result = CoinStatsIndex(
    name: "coinstatsindex",
    db: db,
    cfHandle: cfMeta,  # Use meta CF
    state: isIdle,
    bestHeight: -1,
    stopRequested: false,
    enabled: enabled,
    params: params,
    muhash: newMuHash3072(),
    transactionOutputCount: 0,
    bogoSize: 0,
    totalAmount: 0,
    totalSubsidy: 0,
    totalPrevoutSpentAmount: 0,
    totalNewOutputsExCoinbase: 0,
    totalCoinbaseAmount: 0,
    totalUnspendablesGenesisBlock: 0,
    totalUnspendablesBip30: 0,
    totalUnspendablesScripts: 0,
    totalUnspendablesUnclaimedRewards: 0
  )

  if enabled:
    discard result.loadBestBlock()

method customInit*(idx: CoinStatsIndex): bool =
  ## Load MuHash state from database
  if not idx.enabled:
    return true

  let muhashData = idx.db.get(idx.cfHandle, muHashKey())
  if muhashData.isSome:
    try:
      idx.muhash = deserializeMuHash(muhashData.get())
    except:
      return false

  # Load stats from best block
  if idx.bestHeight >= 0:
    let statsData = idx.db.get(idx.cfHandle, coinStatsHeightKey(idx.bestHeight))
    if statsData.isSome:
      try:
        let val = deserializeCoinStatsVal(statsData.get())
        idx.transactionOutputCount = val.transactionOutputCount
        idx.bogoSize = val.bogoSize
        idx.totalAmount = val.totalAmount
        idx.totalSubsidy = val.totalSubsidy
        idx.totalPrevoutSpentAmount = bytesToUint64(val.totalPrevoutSpentAmount)
        idx.totalNewOutputsExCoinbase = bytesToUint64(val.totalNewOutputsExCoinbase)
        idx.totalCoinbaseAmount = bytesToUint64(val.totalCoinbaseAmount)
        idx.totalUnspendablesGenesisBlock = val.totalUnspendablesGenesisBlock
        idx.totalUnspendablesBip30 = val.totalUnspendablesBip30
        idx.totalUnspendablesScripts = val.totalUnspendablesScripts
        idx.totalUnspendablesUnclaimedRewards = val.totalUnspendablesUnclaimedRewards
        idx.currentBlockHash = val.blockHash
      except:
        return false

  true

proc isUnspendable*(scriptPubKey: seq[byte]): bool =
  ## Check if script is provably unspendable (OP_RETURN or empty)
  scriptPubKey.len == 0 or (scriptPubKey.len > 0 and scriptPubKey[0] == 0x6a)

method customAppend*(idx: CoinStatsIndex, blockInfo: BlockInfo): bool =
  ## Process a new block
  if not idx.enabled:
    return true

  if blockInfo.data.isNone:
    return false

  let blk = blockInfo.data.get()
  let blockSubsidy = getBlockSubsidy(blockInfo.height, idx.params)
  idx.totalSubsidy += blockSubsidy

  # Genesis block special handling
  if blockInfo.height == 0:
    idx.totalUnspendablesGenesisBlock += blockSubsidy
  else:
    # Verify previous block hash
    if idx.currentBlockHash != blockInfo.prevHash:
      return false

    # Process all transactions
    for txIdx, tx in blk.txs:
      let isCoinbase = txIdx == 0

      # Add new outputs
      for outIdx, output in tx.outputs:
        if isUnspendable(output.scriptPubKey):
          idx.totalUnspendablesScripts += int64(output.value)
          continue

        let outpoint = OutPoint(txid: txid(tx), vout: uint32(outIdx))

        # Add to MuHash
        applyCoinHash(idx.muhash, outpoint, int64(output.value),
                      output.scriptPubKey, blockInfo.height, isCoinbase)

        if isCoinbase:
          idx.totalCoinbaseAmount += uint64(output.value)
        else:
          idx.totalNewOutputsExCoinbase += uint64(output.value)

        idx.transactionOutputCount += 1
        idx.totalAmount += int64(output.value)
        idx.bogoSize += getBogoSize(output.scriptPubKey)

      # Remove spent outputs (skip coinbase)
      if not isCoinbase and blockInfo.undoData.isSome:
        let undo = blockInfo.undoData.get()
        if txIdx - 1 < undo.txUndo.len:
          let txUndo = undo.txUndo[txIdx - 1]
          for inputIdx, spent in txUndo.prevOutputs:
            let outpoint = OutPoint(
              txid: tx.inputs[inputIdx].prevOut.txid,
              vout: tx.inputs[inputIdx].prevOut.vout
            )

            # Remove from MuHash
            removeCoinHash(idx.muhash, outpoint, int64(spent.output.value),
                           spent.output.scriptPubKey, spent.height, spent.isCoinbase)

            idx.totalPrevoutSpentAmount += uint64(spent.output.value)
            idx.transactionOutputCount -= 1
            idx.totalAmount -= int64(spent.output.value)
            idx.bogoSize -= getBogoSize(spent.output.scriptPubKey)

  # Calculate unclaimed rewards
  let tempUnspendable = idx.totalUnspendablesGenesisBlock +
                        idx.totalUnspendablesBip30 +
                        idx.totalUnspendablesScripts +
                        idx.totalUnspendablesUnclaimedRewards
  let expected = idx.totalPrevoutSpentAmount + uint64(idx.totalSubsidy)
  let actual = idx.totalNewOutputsExCoinbase + idx.totalCoinbaseAmount + uint64(tempUnspendable)
  if expected > actual:
    idx.totalUnspendablesUnclaimedRewards += int64(expected - actual)

  # Finalize MuHash for storage
  var muhashCopy = idx.muhash
  let muhashFinal = muhashCopy.finalize()

  # Store stats
  let dbVal = CoinStatsDbVal(
    blockHash: blockInfo.hash,
    muhash: muhashFinal,
    transactionOutputCount: idx.transactionOutputCount,
    bogoSize: idx.bogoSize,
    totalAmount: idx.totalAmount,
    totalSubsidy: idx.totalSubsidy,
    totalPrevoutSpentAmount: uint64ToBytes(idx.totalPrevoutSpentAmount),
    totalNewOutputsExCoinbase: uint64ToBytes(idx.totalNewOutputsExCoinbase),
    totalCoinbaseAmount: uint64ToBytes(idx.totalCoinbaseAmount),
    totalUnspendablesGenesisBlock: idx.totalUnspendablesGenesisBlock,
    totalUnspendablesBip30: idx.totalUnspendablesBip30,
    totalUnspendablesScripts: idx.totalUnspendablesScripts,
    totalUnspendablesUnclaimedRewards: idx.totalUnspendablesUnclaimedRewards
  )

  idx.db.put(idx.cfHandle, coinStatsHeightKey(blockInfo.height),
             serializeCoinStatsVal(dbVal))

  idx.currentBlockHash = blockInfo.hash
  true

method customRemove*(idx: CoinStatsIndex, blockInfo: BlockInfo): bool =
  ## Revert a block during reorg
  if not idx.enabled:
    return true

  # Copy height entry to hash index
  let heightData = idx.db.get(idx.cfHandle, coinStatsHeightKey(blockInfo.height))
  if heightData.isSome:
    idx.db.put(idx.cfHandle, coinStatsHashKey(blockInfo.hash), heightData.get())

  if blockInfo.data.isNone or blockInfo.undoData.isNone:
    return false

  let blk = blockInfo.data.get()
  let undo = blockInfo.undoData.get()

  # Reverse the block's effects on MuHash
  for txIdx in countdown(blk.txs.len - 1, 0):
    let tx = blk.txs[txIdx]
    let isCoinbase = txIdx == 0

    # Remove outputs that were added
    for outIdx, output in tx.outputs:
      if not isUnspendable(output.scriptPubKey):
        let outpoint = OutPoint(txid: txid(tx), vout: uint32(outIdx))
        removeCoinHash(idx.muhash, outpoint, int64(output.value),
                       output.scriptPubKey, blockInfo.height, isCoinbase)

    # Re-add spent outputs
    if not isCoinbase and txIdx - 1 < undo.txUndo.len:
      let txUndo = undo.txUndo[txIdx - 1]
      for inputIdx, spent in txUndo.prevOutputs:
        let outpoint = OutPoint(
          txid: tx.inputs[inputIdx].prevOut.txid,
          vout: tx.inputs[inputIdx].prevOut.vout
        )
        applyCoinHash(idx.muhash, outpoint, int64(spent.output.value),
                      spent.output.scriptPubKey, spent.height, spent.isCoinbase)

  # Restore state from previous block
  if blockInfo.height > 0:
    let prevData = idx.db.get(idx.cfHandle, coinStatsHeightKey(blockInfo.height - 1))
    if prevData.isSome:
      let val = deserializeCoinStatsVal(prevData.get())
      idx.transactionOutputCount = val.transactionOutputCount
      idx.bogoSize = val.bogoSize
      idx.totalAmount = val.totalAmount
      idx.totalSubsidy = val.totalSubsidy
      idx.totalPrevoutSpentAmount = bytesToUint64(val.totalPrevoutSpentAmount)
      idx.totalNewOutputsExCoinbase = bytesToUint64(val.totalNewOutputsExCoinbase)
      idx.totalCoinbaseAmount = bytesToUint64(val.totalCoinbaseAmount)
      idx.totalUnspendablesGenesisBlock = val.totalUnspendablesGenesisBlock
      idx.totalUnspendablesBip30 = val.totalUnspendablesBip30
      idx.totalUnspendablesScripts = val.totalUnspendablesScripts
      idx.totalUnspendablesUnclaimedRewards = val.totalUnspendablesUnclaimedRewards
      idx.currentBlockHash = blockInfo.prevHash

  true

method customCommit*(idx: CoinStatsIndex): bool =
  ## Persist MuHash state
  if not idx.enabled:
    return true

  idx.db.put(idx.cfHandle, muHashKey(), serializeMuHash(idx.muhash))
  true

# ============================================================================
# Public API
# ============================================================================

proc lookUpStats*(idx: CoinStatsIndex, height: int32): Option[CoinStats] =
  ## Get UTXO stats for a specific height
  if not idx.enabled:
    return none(CoinStats)

  let data = idx.db.get(idx.cfHandle, coinStatsHeightKey(height))
  if data.isNone:
    return none(CoinStats)

  try:
    let val = deserializeCoinStatsVal(data.get())
    some(CoinStats(
      height: height,
      blockHash: val.blockHash,
      muhash: val.muhash,
      transactionOutputCount: val.transactionOutputCount,
      bogoSize: val.bogoSize,
      totalAmount: val.totalAmount,
      totalSubsidy: val.totalSubsidy,
      totalPrevoutSpentAmount: bytesToUint64(val.totalPrevoutSpentAmount),
      totalNewOutputsExCoinbase: bytesToUint64(val.totalNewOutputsExCoinbase),
      totalCoinbaseAmount: bytesToUint64(val.totalCoinbaseAmount),
      totalUnspendablesGenesisBlock: val.totalUnspendablesGenesisBlock,
      totalUnspendablesBip30: val.totalUnspendablesBip30,
      totalUnspendablesScripts: val.totalUnspendablesScripts,
      totalUnspendablesUnclaimedRewards: val.totalUnspendablesUnclaimedRewards
    ))
  except:
    none(CoinStats)

proc lookUpStatsByHash*(idx: CoinStatsIndex, blockHash: BlockHash): Option[CoinStats] =
  ## Get UTXO stats for a reorged block by hash
  if not idx.enabled:
    return none(CoinStats)

  let data = idx.db.get(idx.cfHandle, coinStatsHashKey(blockHash))
  if data.isNone:
    return none(CoinStats)

  try:
    let val = deserializeCoinStatsVal(data.get())
    # Height not stored in hash index, return -1
    some(CoinStats(
      height: -1,
      blockHash: val.blockHash,
      muhash: val.muhash,
      transactionOutputCount: val.transactionOutputCount,
      bogoSize: val.bogoSize,
      totalAmount: val.totalAmount,
      totalSubsidy: val.totalSubsidy,
      totalPrevoutSpentAmount: bytesToUint64(val.totalPrevoutSpentAmount),
      totalNewOutputsExCoinbase: bytesToUint64(val.totalNewOutputsExCoinbase),
      totalCoinbaseAmount: bytesToUint64(val.totalCoinbaseAmount),
      totalUnspendablesGenesisBlock: val.totalUnspendablesGenesisBlock,
      totalUnspendablesBip30: val.totalUnspendablesBip30,
      totalUnspendablesScripts: val.totalUnspendablesScripts,
      totalUnspendablesUnclaimedRewards: val.totalUnspendablesUnclaimedRewards
    ))
  except:
    none(CoinStats)

proc getCurrentUtxoCount*(idx: CoinStatsIndex): uint64 =
  ## Get current UTXO count
  idx.transactionOutputCount

proc getCurrentTotalAmount*(idx: CoinStatsIndex): int64 =
  ## Get current total UTXO value
  idx.totalAmount
