## Block template generation
## Creates block templates for mining with witness commitment support

import std/[times, options, tables, sets, heapqueue, algorithm]
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

type
  PkgScore = object
    fee: int64
    weight: int

  # Min-heap key: lower negRate is a higher ancestor feerate. txid then
  # generation break ties so a stale score loses to the refreshed one.
  TemplateCand = object
    negRate: int64
    txid: array[32, byte]
    gen: int

proc `<`(a, b: TemplateCand): bool =
  if a.negRate != b.negRate:
    return a.negRate < b.negRate
  if a.txid != b.txid:
    for i in 0 ..< 32:
      if a.txid[i] != b.txid[i]:
        return a.txid[i] < b.txid[i]
    return false
  a.gen < b.gen

proc modifiedFeeSat(mp: Mempool, entry: MempoolEntry): int64 =
  int64(entry.fee) + mp.getFeeDelta(entry.txid)

proc packageRateSatKvB(fee: int64, weight: int): int64 =
  ## sat/kvB, truncated toward zero the same way the old per-tx gate did.
  let vbytes = float64(weight) / 4.0
  if vbytes > 0:
    int64(float64(fee) / vbytes * 1000.0)
  else:
    0'i64

proc txidBytes(id: TxId): array[32, byte] =
  array[32, byte](id)

proc countInPackageAncestors(mp: Mempool, txid: TxId, package: HashSet[TxId]): int =
  ## How many package members are ancestors of txid (not counting itself).
  var seen = initHashSet[TxId]()
  var stack: seq[TxId] = @[]
  if txid notin mp.entries:
    return 0
  for inp in mp.entries[txid].tx.inputs:
    if inp.prevOut.txid in package:
      stack.add(inp.prevOut.txid)
  while stack.len > 0:
    let parent = stack.pop()
    if parent in seen:
      continue
    seen.incl(parent)
    if parent notin mp.entries:
      continue
    for inp in mp.entries[parent].tx.inputs:
      let grand = inp.prevOut.txid
      if grand in package and grand notin seen:
        stack.add(grand)
  seen.len

proc cmpTxid(a, b: TxId): int =
  let aa = txidBytes(a)
  let bb = txidBytes(b)
  for i in 0 ..< 32:
    if aa[i] < bb[i]: return -1
    if aa[i] > bb[i]: return 1
  0

proc packageInTopoOrder(mp: Mempool, root: TxId, included: HashSet[TxId]): seq[TxId] =
  ## root plus every in-mempool ancestor not already selected, parents first.
  ## Ancestor-count order matches Core SortForBlock (CompareTxIterByAncestorCount).
  var package = initHashSet[TxId]()
  var stack = @[root]
  while stack.len > 0:
    let id = stack.pop()
    if id in package or id in included:
      continue
    if id notin mp.entries:
      continue
    package.incl(id)
    for inp in mp.entries[id].tx.inputs:
      let parent = inp.prevOut.txid
      if parent in mp.entries and parent notin included and parent notin package:
        stack.add(parent)
  for id in package:
    result.add(id)
  var counts = initTable[TxId, int]()
  for id in result:
    counts[id] = countInPackageAncestors(mp, id, package)
  result.sort(proc(a, b: TxId): int =
    let byCount = cmp(counts[a], counts[b])
    if byCount != 0:
      return byCount
    cmpTxid(a, b)
  )

proc descendantTxids(children: Table[TxId, HashSet[TxId]], start: TxId): seq[TxId] =
  var seen = initHashSet[TxId]()
  var queue: seq[TxId] = @[]
  if children.hasKey(start):
    for child in children[start]:
      queue.add(child)
  var i = 0
  while i < queue.len:
    let id = queue[i]
    inc i
    if id in seen:
      continue
    seen.incl(id)
    result.add(id)
    if children.hasKey(id):
      for child in children[id]:
        if child notin seen:
          queue.add(child)

proc selectTemplateTransactions(
  mempool: Mempool,
  nBlockMaxWeight: int,
  nBlockReservedWeight: int,
  blockMinFeeRateSatKvB: int64,
  blockHeight: uint32,
  lockTimeCutoff: uint32
): tuple[txs: seq[Transaction], totalFees: Satoshi, nBlockWeight: int, totalSigops: int] =
  ## Pick transactions for a block template.
  ##
  ## The next candidate is the not-yet-selected mempool tx with the highest
  ## ancestor feerate, where the ancestor set is that tx plus in-mempool
  ## ancestors still outside the block (modified fee = base + prioritisetransaction
  ## delta, including ancestors' deltas). The whole package is added in
  ## parent-before-child order, or the candidate is skipped. A child is never
  ## emitted without its in-mempool parents, and a parent that was not selected
  ## keeps its descendants out.
  ##
  ## Reference: Bitcoin Core node/miner.cpp addPackageTxs, SortForBlock,
  ## TestPackage, TestPackageTransactions. Once the best remaining package is
  ## under blockMinFeeRate, selection stops.

  result.txs = @[]
  result.totalFees = Satoshi(0)
  result.nBlockWeight = nBlockReservedWeight
  result.totalSigops = 0

  var score = initTable[TxId, PkgScore]()
  var children = initTable[TxId, HashSet[TxId]]()
  for txid, entry in mempool.entries:
    var fee = modifiedFeeSat(mempool, entry)
    var weight = entry.weight
    for anc in mempool.calculateAncestors(entry.tx):
      let ancEntry = mempool.entries[anc]
      fee += modifiedFeeSat(mempool, ancEntry)
      weight += ancEntry.weight
    score[txid] = PkgScore(fee: fee, weight: weight)
    for inp in entry.tx.inputs:
      let parent = inp.prevOut.txid
      if parent in mempool.entries:
        var kids = children.getOrDefault(parent)
        kids.incl(txid)
        children[parent] = kids

  var included = initHashSet[TxId]()
  var failed = initHashSet[TxId]()
  var generation = initTable[TxId, int]()
  var heap = initHeapQueue[TemplateCand]()
  var nConsecutiveFailed = 0

  proc pushCand(id: TxId) =
    if id in included or id in failed or id notin score:
      return
    let gen = generation.getOrDefault(id, 0) + 1
    generation[id] = gen
    let rate = packageRateSatKvB(score[id].fee, score[id].weight)
    heap.push(TemplateCand(negRate: -rate, txid: txidBytes(id), gen: gen))

  for txid in score.keys:
    pushCand(txid)

  while heap.len > 0:
    let cand = heap.pop()
    let id = TxId(cand.txid)
    if id in included or id in failed:
      continue
    if generation.getOrDefault(id, 0) != cand.gen:
      continue

    let members = packageInTopoOrder(mempool, id, included)
    if members.len == 0:
      failed.incl(id)
      continue

    var pkgFee = 0'i64
    var pkgWeight = 0
    var pkgSigops = 0
    var sigopsOf = initTable[TxId, int]()
    var allFinal = true
    for member in members:
      let entry = mempool.entries[member]
      let sigops = estimateTxSigops(entry.tx)
      sigopsOf[member] = sigops
      pkgFee += modifiedFeeSat(mempool, entry)
      pkgWeight += entry.weight
      pkgSigops += sigops
      if not isFinalTx(entry.tx, blockHeight, lockTimeCutoff):
        allFinal = false

    if packageRateSatKvB(pkgFee, pkgWeight) < blockMinFeeRateSatKvB:
      break

    let fitsWeight = result.nBlockWeight + pkgWeight < nBlockMaxWeight
    let fitsSigops = result.totalSigops + pkgSigops < MaxBlockSigopsCost
    if not allFinal or not fitsWeight or not fitsSigops:
      failed.incl(id)
      if not fitsWeight or not fitsSigops:
        inc nConsecutiveFailed
        if nConsecutiveFailed > MaxConsecutiveFailures and
           result.nBlockWeight + BlockFullEnoughWeightDelta > nBlockMaxWeight:
          break
      continue

    nConsecutiveFailed = 0
    for member in members:
      let entry = mempool.entries[member]
      included.incl(member)
      result.txs.add(entry.tx)
      result.totalFees = result.totalFees + entry.fee
      result.nBlockWeight += entry.weight
      result.totalSigops += sigopsOf[member]

    for member in members:
      let entry = mempool.entries[member]
      let subFee = modifiedFeeSat(mempool, entry)
      let subWeight = entry.weight
      for desc in descendantTxids(children, member):
        if desc in included or desc notin score:
          continue
        var updated = score[desc]
        updated.fee -= subFee
        updated.weight -= subWeight
        score[desc] = updated
        pushCand(desc)

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
  ## Minimum fee-rate gate (Bitcoin Core addPackageTxs):
  ##   Skip a package whose ancestor feerate is below blockMinFeeRate. Once the
  ##   best remaining package is under that floor, selection stops.

  let height = chainState.bestHeight + 1
  let subsidy = getBlockSubsidy(height, params)

  # Get the lock time cutoff (Median Time Past of the previous block).
  # Bitcoin Core: m_lock_time_cutoff = pindexPrev->GetMedianTimePast() (miner.cpp:148).
  let lockTimeCutoff = getMtpForHeight(chainState.db, chainState.bestHeight)

  # Apply Core's ClampOptions to keep maxWeight in a valid range.
  let (nBlockMaxWeight, nBlockReservedWeight) = clampBlockOptions(params.maxBlockWeight, CoinbaseReservedWeight)

  # Package selection: ancestor-feerate order, parents before children.
  # nBlockWeight starts at the reserved weight — same as Core resetBlock().
  let selected = selectTemplateTransactions(
    mempool, nBlockMaxWeight, nBlockReservedWeight,
    blockMinFeeRateSatKvB, uint32(height), lockTimeCutoff)
  let txList = selected.txs
  let totalFees = selected.totalFees
  let totalSigops = selected.totalSigops
  let nBlockWeight = selected.nBlockWeight

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
