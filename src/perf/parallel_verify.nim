## Parallel script verification for IBD optimization
## Uses threadpool to distribute signature verification across CPU cores

import std/[cpuinfo, options, threadpool]
import ../primitives/[types, serialize]
import ../crypto/[secp256k1, hashing]
import ../script/interpreter
import ../storage/chainstate
import ../consensus/validation

export validation.ValidationResult

type
  InputVerificationTask = object
    ## Task for verifying a single input
    tx: Transaction
    inputIdx: int
    prevOutput: TxOut
    prevHeight: int32
    isCoinbase: bool
    flags: set[ScriptFlags]
    amount: Satoshi

  VerificationResult = object
    inputIdx: int
    success: bool
    error: string

# Thread-local crypto engine (avoid sharing context across threads)
var threadCrypto {.threadvar.}: CryptoEngine
var threadCryptoInit {.threadvar.}: bool

proc getThreadCrypto(): CryptoEngine =
  if not threadCryptoInit:
    threadCrypto = newCryptoEngine()
    threadCryptoInit = true
  threadCrypto

proc verifyInputScript(task: InputVerificationTask): VerificationResult =
  ## Verify a single input's script (runs in worker thread)
  result.inputIdx = task.inputIdx

  let tx = task.tx
  let inp = tx.inputs[task.inputIdx]

  # Get witness data for this input
  var witness: seq[seq[byte]] = @[]
  if task.inputIdx < tx.witnesses.len:
    witness = tx.witnesses[task.inputIdx]

  # Verify the script
  let verified = verifyScript(
    inp.scriptSig,
    task.prevOutput.scriptPubKey,
    tx,
    task.inputIdx,
    task.amount,
    task.flags,
    witness
  )

  result.success = verified
  if not verified:
    result.error = "script verification failed"

proc verifyScriptsParallel*(
  blk: Block,
  utxoLookup: proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.},
  height: int32,
  crypto: CryptoEngine
): ValidationResult[void] =
  ## Verify all scripts in a block using parallel execution
  ## Partitions inputs across min(cpuCount, 16) threads
  ## Each thread has its own CryptoEngine; results collected via FlowVar

  let flags = getBlockScriptFlags(height, mainnetParams())

  # Track intra-block UTXOs for transactions that spend outputs created earlier in same block
  var intraBlockUtxos: seq[tuple[txid: TxId, vout: uint32, entry: UtxoEntry]]

  # Add coinbase outputs to intra-block set
  let coinbaseTxid = blk.txs[0].txid()
  for vout, output in blk.txs[0].outputs:
    intraBlockUtxos.add((coinbaseTxid, uint32(vout), UtxoEntry(
      output: output,
      height: height,
      isCoinbase: true
    )))

  # Process each non-coinbase transaction
  for txIdx in 1 ..< blk.txs.len:
    let tx = blk.txs[txIdx]

    # Collect all tasks for this transaction
    var tasks: seq[InputVerificationTask]

    for inputIdx, inp in tx.inputs:
      # Look up the UTXO being spent
      var utxoOpt: Option[UtxoEntry] = none(UtxoEntry)

      # Check intra-block UTXOs first
      for ib in intraBlockUtxos:
        if ib.txid == inp.prevOut.txid and ib.vout == inp.prevOut.vout:
          utxoOpt = some(ib.entry)
          break

      # Fall back to provided lookup
      if utxoOpt.isNone:
        utxoOpt = utxoLookup(inp.prevOut)

      if utxoOpt.isNone:
        return voidErr(veInputsMissing)

      let utxo = utxoOpt.get()

      tasks.add(InputVerificationTask(
        tx: tx,
        inputIdx: inputIdx,
        prevOutput: utxo.output,
        prevHeight: utxo.height,
        isCoinbase: utxo.isCoinbase,
        flags: flags,
        amount: utxo.output.value
      ))

    # Spawn verification tasks
    var flowvars: seq[FlowVar[VerificationResult]]

    for task in tasks:
      flowvars.add(spawn verifyInputScript(task))

    # Collect results
    for fv in flowvars:
      let res = ^fv
      if not res.success:
        return voidErr(veScriptVerifyFailed)

    # Remove spent UTXOs from intra-block set
    for inp in tx.inputs:
      var i = 0
      while i < intraBlockUtxos.len:
        if intraBlockUtxos[i].txid == inp.prevOut.txid and
           intraBlockUtxos[i].vout == inp.prevOut.vout:
          intraBlockUtxos.del(i)
          break
        inc i

    # Add this transaction's outputs to intra-block set
    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      intraBlockUtxos.add((thisTxid, uint32(vout), UtxoEntry(
        output: output,
        height: height,
        isCoinbase: false
      )))

  ok()

proc verifyScriptsParallelBatch*(
  blk: Block,
  utxoLookup: proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.},
  height: int32,
  crypto: CryptoEngine,
  batchSize: int = 0
): ValidationResult[void] =
  ## Batch-oriented parallel verification
  ## Groups inputs into batches and processes each batch in parallel
  ## batchSize = 0 uses auto-tuning based on CPU count

  let effectiveBatchSize = if batchSize == 0:
    max(16, countProcessors() * 4)
  else:
    batchSize

  let flags = getBlockScriptFlags(height, mainnetParams())

  # Collect all verification tasks across the block
  var allTasks: seq[InputVerificationTask]
  var intraBlockUtxos: seq[tuple[txid: TxId, vout: uint32, entry: UtxoEntry]]

  # Add coinbase outputs
  let coinbaseTxid = blk.txs[0].txid()
  for vout, output in blk.txs[0].outputs:
    intraBlockUtxos.add((coinbaseTxid, uint32(vout), UtxoEntry(
      output: output,
      height: height,
      isCoinbase: true
    )))

  # Process each transaction to collect tasks
  for txIdx in 1 ..< blk.txs.len:
    let tx = blk.txs[txIdx]

    for inputIdx, inp in tx.inputs:
      var utxoOpt: Option[UtxoEntry] = none(UtxoEntry)

      for ib in intraBlockUtxos:
        if ib.txid == inp.prevOut.txid and ib.vout == inp.prevOut.vout:
          utxoOpt = some(ib.entry)
          break

      if utxoOpt.isNone:
        utxoOpt = utxoLookup(inp.prevOut)

      if utxoOpt.isNone:
        return voidErr(veInputsMissing)

      let utxo = utxoOpt.get()

      allTasks.add(InputVerificationTask(
        tx: tx,
        inputIdx: inputIdx,
        prevOutput: utxo.output,
        prevHeight: utxo.height,
        isCoinbase: utxo.isCoinbase,
        flags: flags,
        amount: utxo.output.value
      ))

    # Update intra-block UTXOs
    for inp in tx.inputs:
      var i = 0
      while i < intraBlockUtxos.len:
        if intraBlockUtxos[i].txid == inp.prevOut.txid and
           intraBlockUtxos[i].vout == inp.prevOut.vout:
          intraBlockUtxos.del(i)
          break
        inc i

    let thisTxid = tx.txid()
    for vout, output in tx.outputs:
      intraBlockUtxos.add((thisTxid, uint32(vout), UtxoEntry(
        output: output,
        height: height,
        isCoinbase: false
      )))

  # Process tasks in batches
  var offset = 0
  while offset < allTasks.len:
    let batchEnd = min(offset + effectiveBatchSize, allTasks.len)
    var flowvars: seq[FlowVar[VerificationResult]]

    for i in offset ..< batchEnd:
      flowvars.add(spawn verifyInputScript(allTasks[i]))

    # Sync batch
    for fv in flowvars:
      let res = ^fv
      if not res.success:
        return voidErr(veScriptVerifyFailed)

    offset = batchEnd

  ok()

# Signature throughput benchmark helper

proc benchmarkSignatureVerification*(iterations: int): float64 =
  ## Benchmark raw ECDSA signature verification throughput
  ## Returns signatures per second
  let crypto = newCryptoEngine()

  # Generate test data
  var privKey: array[32, byte]
  for i in 0 ..< 32:
    privKey[i] = byte((i * 17 + 42) mod 256)

  let pubKey = derivePublicKey(privKey)
  var msgHash: array[32, byte]
  for i in 0 ..< 32:
    msgHash[i] = byte((i * 31 + 7) mod 256)

  let signature = sign(privKey, msgHash)

  # Benchmark
  let startTime = cpuTime()
  for i in 0 ..< iterations:
    discard verify(pubKey, msgHash, signature)
  let elapsed = cpuTime() - startTime

  result = float64(iterations) / elapsed
