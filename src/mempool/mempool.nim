## Transaction mempool
## Manages unconfirmed transactions with fee/size policy, CPFP tracking, and eviction

import std/[tables, algorithm, options, times, sets]
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/secp256k1
import ../script/interpreter

type
  MempoolError* = object of CatchableError

  MempoolEntry* = object
    tx*: Transaction
    txid*: TxId
    fee*: Satoshi
    weight*: int            ## Transaction weight in weight units
    feeRate*: float64       ## Fee rate in sat/vbyte (fee / (weight/4))
    timeAdded*: Time
    height*: int32          ## Block height when added
    ancestorFee*: Satoshi   ## Total fee of this tx plus all unconfirmed ancestors
    ancestorWeight*: int    ## Total weight of this tx plus all unconfirmed ancestors

  Mempool* = ref object
    entries*: Table[TxId, MempoolEntry]
    spentBy*: Table[OutPoint, TxId]  ## Maps spent outpoint -> spending txid for O(1) double-spend detection
    maxSize*: int           ## Maximum mempool size in bytes (default 300MB)
    currentSize*: int       ## Current mempool size in bytes
    minFeeRate*: float64    ## Minimum fee rate to accept (sat/vbyte)
    chainState*: ChainState
    params*: ConsensusParams

const
  DefaultMaxMempoolSize* = 300_000_000  ## 300 MB
  DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum
  MaxStandardTxWeight* = 400_000        ## 400K weight units max per tx

# Result type for mempool operations
type
  MempoolResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

proc ok*[T](val: T): MempoolResult[T] =
  MempoolResult[T](isOk: true, value: val)

proc err*(T: typedesc, msg: string): MempoolResult[T] =
  MempoolResult[T](isOk: false, error: msg)

# Forward declaration
proc evictLowestFee*(mp: var Mempool)

# Constructor
proc newMempool*(chainState: ChainState, params: ConsensusParams,
                 maxSize: int = DefaultMaxMempoolSize,
                 minFeeRate: float64 = DefaultMinFeeRate): Mempool =
  Mempool(
    entries: initTable[TxId, MempoolEntry](),
    spentBy: initTable[OutPoint, TxId](),
    maxSize: maxSize,
    currentSize: 0,
    minFeeRate: minFeeRate,
    chainState: chainState,
    params: params
  )

# Basic accessors
proc size*(mp: Mempool): int =
  mp.currentSize

proc count*(mp: Mempool): int =
  mp.entries.len

proc contains*(mp: Mempool, txid: TxId): bool =
  txid in mp.entries

proc get*(mp: Mempool, txid: TxId): Option[MempoolEntry] =
  if txid in mp.entries:
    some(mp.entries[txid])
  else:
    none(MempoolEntry)

proc getTransaction*(mp: Mempool, txid: TxId): Option[Transaction] =
  if txid in mp.entries:
    some(mp.entries[txid].tx)
  else:
    none(Transaction)

# Check if an outpoint is spent by a mempool transaction
proc isSpent*(mp: Mempool, outpoint: OutPoint): bool =
  outpoint in mp.spentBy

proc getSpender*(mp: Mempool, outpoint: OutPoint): Option[TxId] =
  if outpoint in mp.spentBy:
    some(mp.spentBy[outpoint])
  else:
    none(TxId)

# Calculate transaction weight
proc calculateWeight(tx: Transaction): int =
  let fullSize = serialize(tx, includeWitness = true).len
  let baseSize = serializeLegacy(tx).len
  # Weight = baseSize * 3 + fullSize (BIP141)
  (baseSize * 3) + fullSize

# Calculate fee from inputs - outputs
proc calculateFee(tx: Transaction, mp: Mempool): Option[Satoshi] =
  var inputValue = int64(0)

  for input in tx.inputs:
    # Check chainstate first
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      inputValue += int64(utxo.get().output.value)
    else:
      # Check mempool for unconfirmed parent (CPFP)
      let parentEntry = mp.get(input.prevOut.txid)
      if parentEntry.isSome:
        let parentTx = parentEntry.get().tx
        if int(input.prevOut.vout) < parentTx.outputs.len:
          inputValue += int64(parentTx.outputs[input.prevOut.vout].value)
        else:
          return none(Satoshi)
      else:
        return none(Satoshi)

  var outputValue = int64(0)
  for output in tx.outputs:
    outputValue += int64(output.value)

  if inputValue >= outputValue:
    some(Satoshi(inputValue - outputValue))
  else:
    none(Satoshi)

# Calculate ancestor fee and weight for CPFP
proc calculateAncestorFeesAndWeight*(mp: Mempool, tx: Transaction,
                                     baseFee: Satoshi, baseWeight: int): (Satoshi, int) =
  var totalFee = int64(baseFee)
  var totalWeight = baseWeight
  var visited = initHashSet[TxId]()
  var toVisit: seq[TxId]

  # Collect immediate parents
  for input in tx.inputs:
    if input.prevOut.txid in mp.entries:
      toVisit.add(input.prevOut.txid)

  # BFS through ancestors
  while toVisit.len > 0:
    let parentTxid = toVisit.pop()
    if parentTxid in visited:
      continue
    visited.incl(parentTxid)

    let parentEntry = mp.entries[parentTxid]
    totalFee += int64(parentEntry.fee)
    totalWeight += parentEntry.weight

    # Add grandparents
    for input in parentEntry.tx.inputs:
      if input.prevOut.txid in mp.entries and input.prevOut.txid notin visited:
        toVisit.add(input.prevOut.txid)

  (Satoshi(totalFee), totalWeight)

# Accept a transaction into the mempool
proc acceptTransaction*(mp: var Mempool, tx: Transaction,
                        crypto: CryptoEngine): MempoolResult[TxId] =
  ## Validate and add transaction to mempool
  ## Returns txid on success, error message on failure

  # Compute txid
  let txid = tx.txid()

  # Already in mempool?
  if txid in mp.entries:
    return err(TxId, "transaction already in mempool")

  # Basic validation (structure, no duplicate inputs, valid output values)
  let basicResult = checkTransaction(tx, mp.params)
  if not basicResult.isOk:
    return err(TxId, "invalid transaction: " & $basicResult.error)

  # Calculate weight and check 400K WU policy limit
  let weight = calculateWeight(tx)
  if weight > MaxStandardTxWeight:
    return err(TxId, "transaction weight " & $weight & " exceeds max " & $MaxStandardTxWeight)

  # Check for double-spend against mempool
  for input in tx.inputs:
    if input.prevOut in mp.spentBy:
      let conflictTxid = mp.spentBy[input.prevOut]
      return err(TxId, "double spend: output already spent by " & $conflictTxid)

  # Check inputs exist (either in chainstate or mempool)
  for input in tx.inputs:
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isNone:
      # Check mempool for unconfirmed parent
      if input.prevOut.txid notin mp.entries:
        return err(TxId, "input not found: " & $input.prevOut.txid)
      let parentEntry = mp.entries[input.prevOut.txid]
      if int(input.prevOut.vout) >= parentEntry.tx.outputs.len:
        return err(TxId, "invalid output index for mempool parent")

  # Calculate fee
  let feeOpt = calculateFee(tx, mp)
  if feeOpt.isNone:
    return err(TxId, "unable to calculate fee")
  let fee = feeOpt.get()

  # Calculate fee rate (sat/vbyte)
  # vbytes = weight / 4
  let vbytes = float64(weight) / 4.0
  let feeRate = float64(int64(fee)) / vbytes

  # Check minimum fee rate (1 sat/vbyte)
  if feeRate < mp.minFeeRate:
    return err(TxId, "fee rate " & $feeRate & " below minimum " & $mp.minFeeRate)

  # Verify scripts for each input
  let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)

  for inputIdx, input in tx.inputs:
    # Get the UTXO being spent
    var scriptPubKey: seq[byte]
    var amount: Satoshi

    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      scriptPubKey = utxo.get().output.scriptPubKey
      amount = utxo.get().output.value
    else:
      # From mempool parent
      let parentEntry = mp.entries[input.prevOut.txid]
      let parentOutput = parentEntry.tx.outputs[input.prevOut.vout]
      scriptPubKey = parentOutput.scriptPubKey
      amount = parentOutput.value

    # Get witness for this input
    var witness: seq[seq[byte]] = @[]
    if inputIdx < tx.witnesses.len:
      witness = tx.witnesses[inputIdx]

    # Verify the script
    let verified = verifyScript(
      input.scriptSig,
      scriptPubKey,
      tx,
      inputIdx,
      amount,
      scriptFlags,
      witness
    )

    if not verified:
      return err(TxId, "script verification failed for input " & $inputIdx)

  # Calculate ancestor fees and weight for CPFP
  let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(tx, fee, weight)

  # Check mempool size limit - evict if needed
  let txSize = serialize(tx).len
  while mp.currentSize + txSize > mp.maxSize:
    mp.evictLowestFee()
    if mp.entries.len == 0:
      break

  # Create entry
  let entry = MempoolEntry(
    tx: tx,
    txid: txid,
    fee: fee,
    weight: weight,
    feeRate: feeRate,
    timeAdded: getTime(),
    height: mp.chainState.bestHeight,
    ancestorFee: ancestorFee,
    ancestorWeight: ancestorWeight
  )

  # Add to mempool
  mp.entries[txid] = entry
  mp.currentSize += txSize

  # Track spent outpoints
  for input in tx.inputs:
    mp.spentBy[input.prevOut] = txid

  ok(txid)

# Remove a transaction from the mempool
proc removeTransaction*(mp: var Mempool, txid: TxId) =
  if txid notin mp.entries:
    return

  let entry = mp.entries[txid]

  # Remove from spentBy tracking
  for input in entry.tx.inputs:
    mp.spentBy.del(input.prevOut)

  # Update size
  let txSize = serialize(entry.tx).len
  mp.currentSize -= txSize

  mp.entries.del(txid)

# Remove transactions confirmed in a block
proc removeForBlock*(mp: var Mempool, blk: Block) =
  ## Remove transactions that were included in a block
  ## Also removes any transactions that spend outputs created by block txs
  ## (double-spend conflicts)

  # Collect txids to remove
  var toRemove: seq[TxId]

  for tx in blk.txs:
    let txid = tx.txid()
    if txid in mp.entries:
      toRemove.add(txid)

    # Check for conflicting mempool transactions
    # (transactions that spend outputs now used by this block tx)
    for input in tx.inputs:
      if input.prevOut in mp.spentBy:
        let conflictTxid = mp.spentBy[input.prevOut]
        if conflictTxid notin toRemove:
          toRemove.add(conflictTxid)

  # Remove all collected transactions
  for txid in toRemove:
    mp.removeTransaction(txid)

# Get transactions sorted by fee rate
proc getTransactionsByFeeRate*(mp: Mempool, maxWeight: int): seq[MempoolEntry] =
  ## Get transactions sorted by ancestor fee rate (highest first)
  ## Limited by total weight

  # Collect all entries
  var entries: seq[MempoolEntry]
  for entry in mp.entries.values:
    entries.add(entry)

  # Sort by ancestor fee rate (ancestor fee / ancestor vbytes)
  entries.sort(proc(a, b: MempoolEntry): int =
    let aRate = float64(int64(a.ancestorFee)) / (float64(a.ancestorWeight) / 4.0)
    let bRate = float64(int64(b.ancestorFee)) / (float64(b.ancestorWeight) / 4.0)
    if aRate > bRate: -1
    elif aRate < bRate: 1
    else: 0
  )

  # Select transactions up to maxWeight
  var totalWeight = 0
  for entry in entries:
    if totalWeight + entry.weight <= maxWeight:
      result.add(entry)
      totalWeight += entry.weight

# Evict lowest fee rate transaction
proc evictLowestFee*(mp: var Mempool) =
  ## Remove the transaction with the lowest fee rate

  if mp.entries.len == 0:
    return

  var lowestTxid: TxId
  var lowestRate = float64.high
  var found = false

  for txid, entry in mp.entries:
    # Don't evict if it has descendants (children in mempool)
    var hasDescendants = false
    for otherEntry in mp.entries.values:
      for input in otherEntry.tx.inputs:
        if input.prevOut.txid == txid:
          hasDescendants = true
          break
      if hasDescendants:
        break

    if not hasDescendants and entry.feeRate < lowestRate:
      lowestRate = entry.feeRate
      lowestTxid = txid
      found = true

  if found:
    mp.removeTransaction(lowestTxid)
  elif mp.entries.len > 0:
    # If all have descendants, just remove the first one with lowest rate
    for txid, entry in mp.entries:
      if entry.feeRate < lowestRate:
        lowestRate = entry.feeRate
        lowestTxid = txid
    mp.removeTransaction(lowestTxid)

# Select transactions for a new block
proc selectTransactionsForBlock*(mp: Mempool, maxWeight: int = MaxBlockWeight): seq[Transaction] =
  ## Select transactions for block template (greedy by ancestor fee rate)
  let entries = mp.getTransactionsByFeeRate(maxWeight)
  for entry in entries:
    result.add(entry.tx)

# Expire old transactions
proc expire*(mp: var Mempool, maxAge: Duration = initDuration(hours = 336)) =
  ## Remove transactions older than maxAge (default 2 weeks)
  let cutoff = getTime() - maxAge
  var toRemove: seq[TxId]

  for txid, entry in mp.entries:
    if entry.timeAdded < cutoff:
      toRemove.add(txid)

  for txid in toRemove:
    mp.removeTransaction(txid)

# Update ancestor fees after a transaction is added/removed
proc updateDescendantFees*(mp: var Mempool, txid: TxId) =
  ## Update ancestor fees for all descendants of a transaction
  ## Called after a parent is added or removed

  var toUpdate: seq[TxId]

  # Find direct children
  for otherTxid, entry in mp.entries:
    for input in entry.tx.inputs:
      if input.prevOut.txid == txid:
        toUpdate.add(otherTxid)
        break

  # Update each child
  for childTxid in toUpdate:
    if childTxid in mp.entries:
      var entry = mp.entries[childTxid]
      let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(
        entry.tx, entry.fee, entry.weight)
      entry.ancestorFee = ancestorFee
      entry.ancestorWeight = ancestorWeight
      mp.entries[childTxid] = entry

      # Recursively update grandchildren
      mp.updateDescendantFees(childTxid)
