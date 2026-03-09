## Transaction mempool
## Manages unconfirmed transactions waiting for inclusion in blocks

import std/[tables, sets, algorithm, options, times]
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/hashing

type
  MempoolError* = object of CatchableError

  MempoolEntry* = object
    tx*: Transaction
    txid*: TxId
    fee*: Satoshi
    size*: int
    feeRate*: float  # satoshis per byte
    addedTime*: Time
    height*: int  # Height when added

  Mempool* = ref object
    entries*: Table[TxId, MempoolEntry]
    spentOutpoints*: HashSet[string]
    maxSize*: int
    params*: ConsensusParams

proc outpointKey(txid: TxId, vout: uint32): string =
  result = ""
  for b in array[32, byte](txid):
    result.add(char(b))
  result.add(char((vout shr 24) and 0xff))
  result.add(char((vout shr 16) and 0xff))
  result.add(char((vout shr 8) and 0xff))
  result.add(char(vout and 0xff))

proc newMempool*(params: ConsensusParams, maxSize: int = 300_000_000): Mempool =
  Mempool(
    entries: initTable[TxId, MempoolEntry](),
    spentOutpoints: initHashSet[string](),
    maxSize: maxSize,
    params: params
  )

proc size*(mp: Mempool): int =
  result = 0
  for entry in mp.entries.values:
    result += entry.size

proc count*(mp: Mempool): int =
  mp.entries.len

proc contains*(mp: Mempool, txid: TxId): bool =
  txid in mp.entries

proc get*(mp: Mempool, txid: TxId): Option[MempoolEntry] =
  if txid in mp.entries:
    some(mp.entries[txid])
  else:
    none(MempoolEntry)

proc calculateFee*(
  tx: Transaction,
  getUtxo: proc(txid: TxId, vout: uint32): Option[Satoshi]
): Satoshi =
  ## Calculate transaction fee from inputs - outputs
  var inputValue = Satoshi(0)
  for input in tx.inputs:
    let utxoValue = getUtxo(input.prevOut.txid, input.prevOut.vout)
    if utxoValue.isSome:
      inputValue = inputValue + utxoValue.get()

  var outputValue = Satoshi(0)
  for output in tx.outputs:
    outputValue = outputValue + output.value

  if int64(inputValue) > int64(outputValue):
    Satoshi(int64(inputValue) - int64(outputValue))
  else:
    Satoshi(0)

proc addTransaction*(
  mp: Mempool,
  tx: Transaction,
  chainState: ChainState,
  currentHeight: int
): bool =
  ## Add a transaction to the mempool
  let txBytes = serialize(tx)
  let txid = TxId(doubleSha256(txBytes))

  # Already in mempool?
  if txid in mp.entries:
    return false

  # Basic validation
  let validationResult = checkTransaction(tx, mp.params)
  if not validationResult.valid:
    return false

  # Check inputs are available (not spent)
  for input in tx.inputs:
    let key = outpointKey(input.prevOut.txid, input.prevOut.vout)
    if key in mp.spentOutpoints:
      return false

    # Check UTXO exists
    if not chainState.hasUtxo(input.prevOut.txid, input.prevOut.vout):
      # Could be in mempool (child-pays-for-parent)
      if input.prevOut.txid notin mp.entries:
        return false

  # Calculate fee
  let fee = calculateFee(tx, proc(tid: TxId, vout: uint32): Option[Satoshi] =
    let utxo = chainState.getUtxo(tid, vout)
    if utxo.isSome:
      some(utxo.get().value)
    else:
      let entry = mp.get(tid)
      if entry.isSome and int(vout) < entry.get().tx.outputs.len:
        some(entry.get().tx.outputs[vout].value)
      else:
        none(Satoshi)
  )

  # Check minimum fee
  let feeRate = float(int64(fee)) / float(txBytes.len)
  if feeRate < float(int64(mp.params.minRelayTxFee)) / 1000.0:
    return false

  # Check mempool size limit
  if mp.size + txBytes.len > mp.maxSize:
    # Would need to evict low-fee transactions
    return false

  # Add to mempool
  let entry = MempoolEntry(
    tx: tx,
    txid: txid,
    fee: fee,
    size: txBytes.len,
    feeRate: feeRate,
    addedTime: getTime(),
    height: currentHeight
  )
  mp.entries[txid] = entry

  # Mark outputs as spent
  for input in tx.inputs:
    mp.spentOutpoints.incl(outpointKey(input.prevOut.txid, input.prevOut.vout))

  true

proc removeTransaction*(mp: Mempool, txid: TxId) =
  ## Remove a transaction from the mempool
  if txid notin mp.entries:
    return

  let entry = mp.entries[txid]

  # Unmark spent outpoints
  for input in entry.tx.inputs:
    mp.spentOutpoints.excl(outpointKey(input.prevOut.txid, input.prevOut.vout))

  mp.entries.del(txid)

proc removeForBlock*(mp: Mempool, blk: Block) =
  ## Remove transactions that were included in a block
  for tx in blk.txs:
    let txBytes = serialize(tx)
    let txid = TxId(doubleSha256(txBytes))
    mp.removeTransaction(txid)

proc getTransactionsByFeeRate*(mp: Mempool, limit: int = 0): seq[MempoolEntry] =
  ## Get transactions sorted by fee rate (highest first)
  result = @[]
  for entry in mp.entries.values:
    result.add(entry)

  result.sort(proc(a, b: MempoolEntry): int =
    if a.feeRate > b.feeRate: -1
    elif a.feeRate < b.feeRate: 1
    else: 0
  )

  if limit > 0 and result.len > limit:
    result = result[0 ..< limit]

proc selectTransactionsForBlock*(
  mp: Mempool,
  maxWeight: int
): seq[Transaction] =
  ## Select transactions for a new block (greedy by fee rate)
  let sorted = mp.getTransactionsByFeeRate()
  var weight = 0

  for entry in sorted:
    let txWeight = entry.size * 4  # Simplified weight calculation
    if weight + txWeight > maxWeight:
      continue
    result.add(entry.tx)
    weight += txWeight

proc expire*(mp: Mempool, maxAge: Duration = initDuration(hours = 336)) =
  ## Remove old transactions from mempool
  let cutoff = getTime() - maxAge
  var toRemove: seq[TxId]

  for txid, entry in mp.entries:
    if entry.addedTime < cutoff:
      toRemove.add(txid)

  for txid in toRemove:
    mp.removeTransaction(txid)
