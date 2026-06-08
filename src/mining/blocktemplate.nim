## Block template generation
## Creates block templates for mining with witness commitment support

import std/[times, options, tables]
import ../primitives/[types, serialize]
import ../consensus/[params, validation, versionbits]
import ../mempool/mempool
import ../crypto/hashing
import ../storage/chainstate

const
  WitnessCommitmentHeader* = @[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]
  ## Reserved weight for block header, txcount varint, and coinbase tx.
  ## Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT (policy/policy.h:27) = 8000.
  ## The old value of 4000 under-reserved by 4000 WU, allowing oversized blocks.
  CoinbaseReservedWeight* = 8_000
  ## Absolute minimum for the reserved weight (policy/policy.h:34).
  ## Values below this are rejected at startup in Core; we enforce it in clampBlockOptions.
  MinimumBlockReservedWeight* = 2_000
  ## When nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES AND the block is within
  ## BLOCK_FULL_ENOUGH_WEIGHT_DELTA of the max weight, give up selecting txs.
  ## Reference: Bitcoin Core node/miner.cpp addChunks(), lines 284-285 / 314-317.
  MaxConsecutiveFailures* = 1_000
  ## Weight delta used with consecutive-failure abort: if remaining capacity is
  ## less than this many weight units, the block is "full enough".
  ## Reference: Bitcoin Core BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000.
  BlockFullEnoughWeightDelta* = 4_000
  LocktimeThreshold* = 500_000_000'u32  ## Below this: block height, at or above: Unix timestamp
  SequenceFinal* = 0xFFFFFFFF'u32  ## Final sequence number (disables relative locktime)
  MaxSequenceNonFinal* = 0xFFFFFFFE'u32  ## Max sequence that still allows locktime enforcement
  ## Default minimum fee rate for block template inclusion (sat/kvB).
  ## Bitcoin Core DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/vbyte = 1000 sat/kvB (policy/policy.h:36).
  DefaultBlockMinFeeRateSatKvB* = 1_000'i64

proc isFinalTx*(tx: Transaction, blockHeight: uint32, blockTime: uint32): bool =
  ## Check if a transaction is final for inclusion in a block
  ## A transaction is final if:
  ## - lockTime == 0, OR
  ## - lockTime < threshold (height-based vs time-based), OR
  ## - all input sequences == SEQUENCE_FINAL (0xFFFFFFFF)
  ##
  ## Reference: Bitcoin Core IsFinalTx() in consensus/tx_verify.cpp

  # lockTime == 0 is always final
  if tx.lockTime == 0:
    return true

  # Compare lockTime against block height or time depending on threshold
  let threshold = if tx.lockTime < LocktimeThreshold:
    blockHeight
  else:
    blockTime

  if tx.lockTime < threshold:
    return true

  # If lockTime is not satisfied, tx is still final if all inputs have
  # sequence == SEQUENCE_FINAL (which disables lockTime checking)
  for input in tx.inputs:
    if input.sequence != SequenceFinal:
      return false

  true

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
  ## Encode block height for coinbase scriptSig per BIP-34.
  ##
  ## Mirrors Bitcoin Core's CScript() << int64_t(nHeight):
  ##   h = 0        → OP_0     = [0x00]            (1 byte)
  ##   h = 1..16    → OP_n     = [0x50 + h]        (1 byte, opcodes 0x51..0x60)
  ##   h = 17..127  → CScriptNum minimal: [0x01, byte(h)]    (2 bytes, no sign bit needed)
  ##   h = 128..255 → MSB set: [0x02, byte(h), 0x00]         (sign-bit padding)
  ##   h = 256..32767 → [0x02, low, high]           (2 bytes, high < 0x80)
  ##   h = 32768..8388607 → [0x03, b0, b1, b2] with optional 0x00 padding if b2 >= 0x80
  ##   etc.
  ##
  ## Reference: bitcoin-core/src/script/script.h CScript::operator<<(int64_t)
  ##            bitcoin-core/src/script/script.h CScriptNum::serialize()
  if height <= 0:
    # OP_0 (0x00) for zero.  Negative heights should not occur (guarded by caller).
    return @[0x00'u8]
  elif height <= 16:
    # OP_1 (0x51) .. OP_16 (0x60)
    return @[byte(0x50 + height)]
  else:
    # CScriptNum::serialize path: little-endian, minimal encoding with sign-bit
    # padding byte appended when the most-significant data byte has bit 7 set.
    var data: seq[byte]
    var v = height
    while v > 0:
      data.add(byte(v and 0xff))
      v = v shr 8
    # If the high byte has bit 7 set we need a 0x00 sign-extension byte so that
    # the value is not misread as negative (CScriptNum sign convention).
    if (data[^1] and 0x80) != 0:
      data.add(0x00'u8)
    # Prefix with the length byte (script data-push)
    result = @[byte(data.len)]
    result.add(data)

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
  let witnessMerkleRoot = hashing.computeMerkleRoot(wtxids)

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
  ##
  ## Anti-fee-sniping (Bitcoin Core behavior):
  ## - nSequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) to allow locktime enforcement
  ## - nLockTime = height - 1 for anti-fee-sniping protection
  ##
  ## Reference: Bitcoin Core node/miner.cpp CreateNewBlock()

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

  # Coinbase lockTime for anti-fee-sniping: set to height - 1
  # This prevents miners from building on old blocks to steal fees
  # Reference: Bitcoin Core miner.cpp line 196
  let coinbaseLockTime = if height > 0: uint32(height - 1) else: 0'u32

  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(
        txid: TxId(default(array[32, byte])),
        vout: 0xffffffff'u32
      ),
      scriptSig: scriptSig,
      # Use MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) to ensure locktime is enforced
      # Reference: Bitcoin Core miner.cpp line 171
      sequence: MaxSequenceNonFinal
    )],
    outputs: outputs,
    witnesses: witnesses,
    lockTime: coinbaseLockTime
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

proc clampBlockOptions*(maxWeight: int, reservedWeight: int): tuple[maxWeight: int, reservedWeight: int] =
  ## Apply Bitcoin Core ClampOptions logic (node/miner.cpp:79-88).
  ## 1. Clamp reservedWeight to [MinimumBlockReservedWeight, MaxBlockWeight].
  ## 2. Clamp maxWeight to [reservedWeight, MaxBlockWeight].
  ## The purpose is to guarantee: reservedWeight <= maxWeight <= MAX_BLOCK_WEIGHT.
  let clampedReserved = max(MinimumBlockReservedWeight, min(reservedWeight, MaxBlockWeight))
  let clampedMax = max(clampedReserved, min(maxWeight, MaxBlockWeight))
  (clampedMax, clampedReserved)

proc buildBlockTemplate*(
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  coinbaseScript: seq[byte],
  blockMinFeeRateSatKvB: int64 = DefaultBlockMinFeeRateSatKvB
): BlockTemplate =
  ## Build a new block template.
  ##
  ## Weight accounting (Bitcoin Core node/miner.cpp resetBlock / addChunks):
  ##   nBlockWeight starts at block_reserved_weight (8000 WU by default), which
  ##   covers the 80-byte block header, the tx-count varint, and the coinbase tx.
  ##   Each candidate tx is accepted only if its weight fits within the remaining
  ##   capacity (nBlockWeight + tx.weight < nBlockMaxWeight — note strict < per Core
  ##   TestChunkBlockLimits line 241).
  ##
  ## Consecutive-failure abort (Bitcoin Core addChunks lines 314-317):
  ##   If more than MAX_CONSECUTIVE_FAILURES (1000) candidates are skipped in a row
  ##   AND the block is already within BLOCK_FULL_ENOUGH_WEIGHT_DELTA (4000 WU) of
  ##   the max weight, give up — the block is essentially full.
  ##
  ## Sigops limit (Bitcoin Core TestChunkBlockLimits line 244):
  ##   Reject a tx whose sigops would bring the running total to >= MAX_BLOCK_SIGOPS_COST.
  ##   The old code used >, which allowed a tx that brings the total to exactly 80 000.
  ##
  ## Minimum fee-rate gate (Bitcoin Core addChunks lines 298-301):
  ##   Skip chunks whose fee rate is below blockMinFeeRate.  Once the sorted list
  ##   falls below that threshold everything remaining is also below it, so we can
  ##   return early.

  let height = chainState.bestHeight + 1
  let subsidy = getBlockSubsidy(height, params)

  # Get the lock time cutoff (Median Time Past of the previous block).
  # Bitcoin Core: m_lock_time_cutoff = pindexPrev->GetMedianTimePast() (miner.cpp:148).
  let lockTimeCutoff = getMtpForHeight(chainState.db, chainState.bestHeight)

  # Apply Core's ClampOptions to keep maxWeight in a valid range.
  let (nBlockMaxWeight, nBlockReservedWeight) = clampBlockOptions(params.maxBlockWeight, CoinbaseReservedWeight)

  # nBlockWeight starts at the reserved weight — same as Core resetBlock().
  var nBlockWeight = nBlockReservedWeight
  var nBlockSigopsCost = 0

  # Pass the *full* nBlockMaxWeight to the selector; weight accounting is done
  # below with the running nBlockWeight counter (not by trimming the cap).
  let selectedEntries = mempool.getTransactionsByFeeRate(nBlockMaxWeight)

  # Build transaction list and enforce sigops limit.
  # Also filter out non-final transactions.
  var txList: seq[Transaction]
  var totalFees = Satoshi(0)
  var totalSigops = 0
  var nConsecutiveFailed = 0

  for entry in selectedEntries:
    # Minimum fee rate gate (Core addChunks lines 298-301).
    # fee rate in sat/kvB = fee_sat * 1000 / vbytes; vbytes = weight / 4.
    # FIX-72 parity: the floor compares the MODIFIED feerate (base +
    # prioritisetransaction delta), mirroring Core, whose txgraph already holds
    # modified fees.  Without this an operator-prioritised low-base-fee tx that
    # getTransactionsByFeeRate ranked high would still be dropped here by its base
    # rate (and the early `break` would skip everything after it).  An
    # un-prioritised entry has delta 0, so this is the base feerate as before.
    let modifiedFeeSat = int64(entry.fee) + mempool.getFeeDelta(entry.txid)
    let entryVbytes = float64(entry.weight) / 4.0
    let entryFeeRateSatKvB =
      if entryVbytes > 0: int64(float64(modifiedFeeSat) / entryVbytes * 1000.0)
      else: int64(entry.feeRate * 1000.0)
    if entryFeeRateSatKvB < blockMinFeeRateSatKvB:
      # Entries are sorted by fee rate; once we're below the floor we're done.
      break

    # Weight limit (Core TestChunkBlockLimits line 241: >= not >).
    # "nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight" → reject.
    if nBlockWeight + entry.weight >= nBlockMaxWeight:
      inc nConsecutiveFailed
      # Consecutive-failure + full-enough abort (Core addChunks lines 314-317).
      if nConsecutiveFailed > MaxConsecutiveFailures and
         nBlockWeight + BlockFullEnoughWeightDelta > nBlockMaxWeight:
        break
      continue

    # Sigops limit (Core TestChunkBlockLimits line 244: >= not >).
    # "nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST" → reject.
    let txSigops = estimateTxSigops(entry.tx)
    if nBlockSigopsCost + txSigops >= MaxBlockSigopsCost:
      inc nConsecutiveFailed
      if nConsecutiveFailed > MaxConsecutiveFailures and
         nBlockWeight + BlockFullEnoughWeightDelta > nBlockMaxWeight:
        break
      continue

    # Check transaction finality (locktime).
    # Reference: Bitcoin Core TestChunkTransactions() in node/miner.cpp.
    if not isFinalTx(entry.tx, uint32(height), lockTimeCutoff):
      inc nConsecutiveFailed
      if nConsecutiveFailed > MaxConsecutiveFailures and
         nBlockWeight + BlockFullEnoughWeightDelta > nBlockMaxWeight:
        break
      continue

    # Accepted — reset consecutive-failure counter and accumulate.
    nConsecutiveFailed = 0
    txList.add(entry.tx)
    totalFees = totalFees + entry.fee
    nBlockWeight += entry.weight
    nBlockSigopsCost += txSigops
    totalSigops = nBlockSigopsCost

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

  # Compute merkle root over TXIDs (non-witness serialization), matching
  # consensus checkBlock (which builds the tree from tx.txid()).  Using
  # serialize(tx) (witness-included by default) yields a wrong root for any
  # block containing a segwit transaction.
  var txHashes: seq[array[32, byte]]
  for tx in transactions:
    txHashes.add(array[32, byte](tx.txid()))
  let merkleRoot = hashing.computeMerkleRoot(txHashes)

  # Get previous block hash
  let prevHash = chainState.bestBlockHash

  # Determine bits (difficulty)
  var bits = params.genesisBits
  let prevBlock = chainState.db.getBlock(prevHash)
  if prevBlock.isSome:
    bits = prevBlock.get().header.bits

  # The coinbase weight was accounted for in nBlockReservedWeight; nBlockWeight
  # already includes it.  For the template's totalWeight we report the running
  # nBlockWeight which starts at the reserved weight (covering the coinbase) and
  # accumulates each selected tx.  This matches Core m_last_block_weight.
  let totalWeight = nBlockWeight

  # ComputeBlockVersion: set BIP9 top bits and set any deployment bits for
  # deployments in STARTED or LOCKED_IN state (miners must signal).
  # Reference: Bitcoin Core versionbits.cpp:265-279, node/miner.cpp UpdateTime.
  # Bug fixed (W91 Bug 4): was hardcoded to 0x20000000, ignoring STARTED/LOCKED_IN
  # deployment bits.  Miners are required to signal bits for active signaling
  # periods (BIP-9 §3, "Upon receiving a version bits block").
  let deployments = getDeployments(params.network)
  var vbCaches = newSeq[Table[BlockHash, ThresholdState]]()
  let getBlockIndexFn = proc(h: BlockHash): Option[BlockIndex] =
    chainState.db.getBlockIndex(h)
  let getMtpFn = proc(h: BlockHash): int64 =
    getMtpForBlock(h, getBlockIndexFn)
  let blockVersion = computeBlockVersion(
    deployments, prevHash, getBlockIndexFn, getMtpFn, vbCaches
  )

  let header = BlockHeader(
    version: blockVersion,
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

proc updateTimestamp*(tmpl: var BlockTemplate, params: ConsensusParams,
                      prevBlockMtp: uint32 = 0) =
  ## Update template timestamp enforcing MTP+1 lower bound (Bitcoin Core UpdateTime,
  ## node/miner.cpp:49-65).
  ##
  ## Core logic:
  ##   nNewTime = max(GetMinimumTime(pindexPrev, ...), NodeClock::now())
  ## where GetMinimumTime returns pindexPrev->GetMedianTimePast() + 1.
  ## The block timestamp MUST be strictly greater than the MTP of the previous
  ## block, otherwise the block is invalid (BIP-113 / consensus rule).
  ##
  ## On testnet/regtest (fPowAllowMinDifficultyBlocks), changing the timestamp
  ## can change the required nBits, so we recompute nBits here too.
  ## Reference: Bitcoin Core UpdateTime lines 60-63.
  ##
  ## prevBlockMtp: MTP of the previous block (GetMedianTimePast). Pass 0 to skip
  ## the lower-bound enforcement (e.g. when prevBlock is not available).
  let now = uint32(getTime().toUnix())
  let minTime = if prevBlockMtp > 0: prevBlockMtp + 1 else: 0'u32
  let newTime = max(minTime, now)
  tmpl.header.timestamp = newTime
  # On testnet/regtest the minimum-difficulty rule depends on the timestamp gap
  # between this block and the previous one, so nBits may change with time.
  # Reference: Bitcoin Core UpdateTime lines 60-63 (fPowAllowMinDifficultyBlocks).
  # NOTE: Full nBits recalculation requires the ancestor chain, which is not
  # available inside BlockTemplate. Callers that need accurate nBits on testnet
  # must recompute via getNextWorkRequired and update tmpl.header.bits directly.
  # We mark the intent here so the gap is visible in code review.
  # (This matches the structural limitation in most other hashhog implementations.)

proc updateTimestampSimple*(tmpl: var BlockTemplate) =
  ## Update template timestamp without MTP enforcement (convenience for regtest
  ## where MTP is not critical and callers control the clock directly).
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

  # Recalculate merkle root over TXIDs (non-witness), matching acceptBlock.
  var txHashes: seq[array[32, byte]]
  for tx in tmpl.transactions:
    txHashes.add(array[32, byte](tx.txid()))
  tmpl.header.merkleRoot = hashing.computeMerkleRoot(txHashes)

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
