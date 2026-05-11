## Transaction mempool
## Manages unconfirmed transactions with fee/size policy, CPFP tracking, and eviction

import std/[tables, algorithm, options, times, sets]
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/secp256k1
import ../script/interpreter
import ./package
import ./standard
export package, standard

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
    ancestorCount*: int     ## Count of ancestors including self (cached for O(1) checks)
    ancestorSize*: int      ## Total vsize of ancestors including self in vbytes (cached)

  Mempool* = ref object
    entries*: Table[TxId, MempoolEntry]
    spentBy*: Table[OutPoint, TxId]  ## Maps spent outpoint -> spending txid for O(1) double-spend detection
    maxSize*: int           ## Maximum mempool size in bytes (default 300MB)
    currentSize*: int       ## Current mempool size in bytes
    minFeeRate*: float64    ## Minimum fee rate to accept (sat/vbyte)
    chainState*: ChainState
    params*: ConsensusParams
    fullRbf*: bool          ## If true, any mempool tx is replaceable regardless of signaling (mempoolfullrbf=1)
    ## Package limits
    ancestorLimit*: int     ## Max ancestor count including self (default 25)
    descendantLimit*: int   ## Max descendant count including self (default 25)
    ancestorSizeLimit*: int ## Max total ancestor vsize in vbytes (default 101,000)
    descendantSizeLimit*: int ## Max total descendant vsize in vbytes (default 101,000)
    ## Cluster limits (Bitcoin Core cluster mempool, policy/policy.h:72-74)
    clusterLimit*: int      ## Max transactions per cluster (default 64)
    clusterSizeLimit*: int  ## Max total cluster vsize in vbytes (default 101,000)

const
  DefaultMaxMempoolSize* = 300_000_000  ## 300 MB
  DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum
  MaxStandardTxWeight* = 400_000        ## 400K weight units max per tx

  ## Package limits (Bitcoin Core defaults)
  DefaultAncestorLimit* = 25            ## Max ancestors including self (policy/policy.h:76)
  DefaultDescendantLimit* = 25          ## Max descendants including self (policy/policy.h:78)
  DefaultAncestorSizeLimitKvB* = 101    ## Max total ancestor vsize in kvB
  DefaultDescendantSizeLimitKvB* = 101  ## Max total descendant vsize in kvB
  DefaultAncestorSizeLimit* = DefaultAncestorSizeLimitKvB * 1000  ## 101,000 vbytes
  DefaultDescendantSizeLimit* = DefaultDescendantSizeLimitKvB * 1000  ## 101,000 vbytes

  ## Cluster limits (Bitcoin Core cluster mempool, policy/policy.h:72-74)
  DefaultClusterLimit* = 64             ## Max transactions per cluster (DEFAULT_CLUSTER_LIMIT)
  DefaultClusterSizeLimitKvB* = 101     ## Max total cluster vsize in kvB (DEFAULT_CLUSTER_SIZE_LIMIT_KVB)
  DefaultClusterSizeLimit* = DefaultClusterSizeLimitKvB * 1000  ## 101,000 vbytes

  ## Extra descendant allowance for CPFP packages (policy/policy.h:90):
  ## a tx with exactly 1 in-mempool ancestor is accepted even if it would
  ## push the ancestor's descendant vsize above the normal limit, as long
  ## as the tx's own vsize <= EXTRA_DESCENDANT_TX_SIZE_LIMIT.  This lets
  ## small CPFP fee-bumpers get in even when the parent is at the boundary.
  ExtraDescendantTxSizeLimit* = 10_000  ## 10 kvB (EXTRA_DESCENDANT_TX_SIZE_LIMIT)

  ## RBF constants (Bitcoin Core: util/rbf.h, policy/rbf.h)
  MaxBip125RbfSequence* = 0xfffffffd'u32  ## nSequence threshold: any input <= this signals opt-in RBF
  MaxReplacementCandidates* = 100         ## Max transactions (conflicts + descendants) evicted per RBF
  DefaultIncrementalRelayFee* = 1.0       ## Incremental relay fee in sat/vbyte

  ## TRUC (v3) policy constants (BIP-431)
  TrucVersion* = 3'i32                  ## Transaction version for TRUC policy
  TrucAncestorLimit* = 2                ## Max ancestors including self (parent + self)
  TrucDescendantLimit* = 2              ## Max descendants including self (self + child)
  TrucMaxVsize* = 10_000                ## Max vsize for any v3 tx (10 kvB)
  TrucMaxWeight* = TrucMaxVsize * 4     ## Max weight for any v3 tx (40k WU)
  TrucChildMaxVsize* = 1_000            ## Max vsize for v3 child of unconfirmed v3 parent
  TrucChildMaxWeight* = TrucChildMaxVsize * 4  ## Max weight for v3 child (4k WU)

  ## Ephemeral dust policy constants
  MaxDustOutputsPerTx* = 1              ## Maximum number of ephemeral dust outputs allowed
  DustRelayTxFee* = 3000                ## Dust relay fee in sat/kvB (3 sat/vbyte)

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

# Forward declarations
proc signalsOptInRBF*(tx: Transaction): bool
proc isRbfOptIn*(mp: Mempool, tx: Transaction): bool
proc evictLowestFee*(mp: Mempool)
proc calculateDescendants*(mp: Mempool, txid: TxId): HashSet[TxId]
proc calculateAncestors*(mp: Mempool, tx: Transaction): HashSet[TxId]
proc findConflicts*(mp: Mempool, tx: Transaction): HashSet[TxId]
proc getAllConflictsWithDescendants*(mp: Mempool, conflicts: HashSet[TxId]): HashSet[TxId]
proc calculateConflictFees*(mp: Mempool, allConflicts: HashSet[TxId]): (Satoshi, int)
proc checkRbfRules*(mp: Mempool, tx: Transaction, txFee: Satoshi, txVsize: int,
                    conflicts: HashSet[TxId], incrementalRelayFee: float64 = DefaultIncrementalRelayFee): MempoolResult[HashSet[TxId]]
proc removeConflicts*(mp: Mempool, conflicts: HashSet[TxId])
proc removeTransaction*(mp: Mempool, txid: TxId, evictEphemeral: bool = true)

# Constructor
proc newMempool*(chainState: ChainState, params: ConsensusParams,
                 maxSize: int = DefaultMaxMempoolSize,
                 minFeeRate: float64 = DefaultMinFeeRate,
                 fullRbf: bool = false,
                 ancestorLimit: int = DefaultAncestorLimit,
                 descendantLimit: int = DefaultDescendantLimit,
                 ancestorSizeLimit: int = DefaultAncestorSizeLimit,
                 descendantSizeLimit: int = DefaultDescendantSizeLimit,
                 clusterLimit: int = DefaultClusterLimit,
                 clusterSizeLimit: int = DefaultClusterSizeLimit): Mempool =
  Mempool(
    entries: initTable[TxId, MempoolEntry](),
    spentBy: initTable[OutPoint, TxId](),
    maxSize: maxSize,
    currentSize: 0,
    minFeeRate: minFeeRate,
    chainState: chainState,
    params: params,
    fullRbf: fullRbf,
    ancestorLimit: ancestorLimit,
    descendantLimit: descendantLimit,
    ancestorSizeLimit: ancestorSizeLimit,
    descendantSizeLimit: descendantSizeLimit,
    clusterLimit: clusterLimit,
    clusterSizeLimit: clusterSizeLimit
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

# ============================================================================
# TRUC (v3) Policy - Topologically Restricted Until Confirmation
# ============================================================================

proc isTruc*(tx: Transaction): bool =
  ## Check if transaction has v3 version (TRUC policy)
  tx.version == TrucVersion

proc isTruc*(entry: MempoolEntry): bool =
  ## Check if mempool entry is a TRUC transaction
  entry.tx.version == TrucVersion

type
  TrucCheckResult* = object
    ## Result of TRUC policy checks
    case isOk*: bool
    of true:
      siblingToEvict*: Option[TxId]  ## If set, this sibling can be evicted via sibling eviction
    of false:
      error*: string

proc trucOk*(siblingToEvict: Option[TxId] = none(TxId)): TrucCheckResult =
  TrucCheckResult(isOk: true, siblingToEvict: siblingToEvict)

proc trucErr*(msg: string): TrucCheckResult =
  TrucCheckResult(isOk: false, error: msg)

proc getMempoolParents*(mp: Mempool, tx: Transaction): seq[TxId] =
  ## Get list of mempool parent txids for a transaction
  for input in tx.inputs:
    if input.prevOut.txid in mp.entries:
      if input.prevOut.txid notin result:
        result.add(input.prevOut.txid)

proc getDirectChildren*(mp: Mempool, txid: TxId): seq[TxId] =
  ## Get transactions that directly spend outputs from this transaction
  for entryTxid, entry in mp.entries:
    for input in entry.tx.inputs:
      if input.prevOut.txid == txid:
        if entryTxid notin result:
          result.add(entryTxid)
        break

proc checkSingleTrucRules*(mp: Mempool, tx: Transaction, weight: int,
                           conflicts: HashSet[TxId]): TrucCheckResult =
  ## Check TRUC policy rules for a single transaction
  ## Returns TrucCheckResult with potential sibling eviction info
  ##
  ## Rules:
  ## 1. v3 tx cannot exceed TrucMaxVsize (10,000 vbytes)
  ## 2. v3 tx can have at most 1 unconfirmed parent
  ## 3. v3 child (with unconfirmed parent) cannot exceed TrucChildMaxVsize (1,000 vbytes)
  ## 4. v3 parent can have at most 1 unconfirmed child
  ## 5. v3 cannot spend from non-v3 unconfirmed; non-v3 cannot spend from v3 unconfirmed
  ## 6. v3 child can evict existing v3 sibling (sibling eviction)

  let vsize = (weight + 3) div 4
  let txIsTruc = tx.isTruc

  # Get mempool parents
  let mempoolParents = mp.getMempoolParents(tx)

  # Check version inheritance rules
  for parentTxid in mempoolParents:
    let parentEntry = mp.entries[parentTxid]
    let parentIsTruc = parentEntry.isTruc

    if txIsTruc and not parentIsTruc:
      # v3 tx cannot spend from non-v3 unconfirmed output
      return trucErr("version=3 tx " & $tx.txid() & " cannot spend from non-version=3 tx " & $parentTxid)

    if not txIsTruc and parentIsTruc:
      # non-v3 tx cannot spend from v3 unconfirmed output
      return trucErr("non-version=3 tx " & $tx.txid() & " cannot spend from version=3 tx " & $parentTxid)

  # Remaining rules only apply to v3 transactions
  if not txIsTruc:
    return trucOk()

  # Rule 1: v3 tx size limit
  if vsize > TrucMaxVsize:
    return trucErr("version=3 tx " & $tx.txid() & " is too big: " & $vsize & " > " & $TrucMaxVsize & " virtual bytes")

  # Rule 2: v3 tx can have at most 1 unconfirmed ancestor (the parent)
  if mempoolParents.len > 1:
    return trucErr("tx " & $tx.txid() & " would have too many ancestors")

  # If there's a mempool parent, check additional rules
  if mempoolParents.len == 1:
    let parentTxid = mempoolParents[0]
    let parentEntry = mp.entries[parentTxid]

    # Check that parent doesn't already have ancestors (would make us exceed limit)
    let parentAncestors = mp.calculateAncestors(parentEntry.tx)
    if parentAncestors.len + mempoolParents.len + 1 > TrucAncestorLimit:
      return trucErr("tx " & $tx.txid() & " would have too many ancestors")

    # Rule 3: v3 child size limit
    if vsize > TrucChildMaxVsize:
      return trucErr("version=3 child tx " & $tx.txid() & " is too big: " & $vsize & " > " & $TrucChildMaxVsize & " virtual bytes")

    # Rule 4: Check if parent already has a child (descendant limit)
    let parentChildren = mp.getDirectChildren(parentTxid)
    if parentChildren.len > 0:
      # Parent already has child(ren) - check for sibling eviction
      # Sibling eviction: if the existing sibling is in conflicts, we can evict it
      var canEvict = false
      var siblingToEvict: TxId

      for siblingTxid in parentChildren:
        if siblingTxid in conflicts:
          # Sibling is being RBF-replaced: child_will_be_replaced = true.
          # Core skips the descendant limit check in this case.
          # Reference: Core truc_policy.cpp lines 240-243
          canEvict = true
          siblingToEvict = siblingTxid
          break

      if not canEvict:
        # Descendant limit would be exceeded and no RBF replacement is in flight.
        # Reference: Core truc_policy.cpp lines 248-258:
        # consider_sibling_eviction requires:
        #   - parent has exactly 2 descendants (parent + exactly 1 child), AND
        #   - that child has exactly 2 ancestors (child + parent, i.e. ancestorCount == 2)
        # ancestorCount in MempoolEntry includes self, so == 2 means parent is its only ancestor.
        if parentChildren.len == 1:
          let existingSibling = parentChildren[0]
          let siblingEntry = mp.entries[existingSibling]
          # Core: GetAncestorCount(sibling) == 2 (exactly parent + self)
          if siblingEntry.ancestorCount == TrucAncestorLimit:
            # Sibling can be evicted via sibling eviction rule
            return trucOk(some(existingSibling))

        return trucErr("tx " & $tx.txid() & " would exceed descendant count limit")

  trucOk()

proc checkTrucSiblingEviction*(mp: Mempool, tx: Transaction, txFee: Satoshi,
                                siblingTxid: TxId): MempoolResult[void] =
  ## Check if v3 sibling eviction is valid
  ## Sibling eviction allows a v3 child to replace an existing v3 child of the same parent
  ## without requiring higher fee rate (only requires paying for its own bandwidth)

  if siblingTxid notin mp.entries:
    return MempoolResult[void](isOk: true)

  let siblingEntry = mp.entries[siblingTxid]

  # New tx must pay at least as much absolute fee as sibling
  # (this is relaxed from normal RBF - doesn't need higher rate)
  if txFee < siblingEntry.fee:
    return err(void, "sibling eviction: insufficient fee (" & $int64(txFee) &
               " < " & $int64(siblingEntry.fee) & " sats)")

  # New tx must pay for its own relay (incremental relay fee * its vsize)
  # This is always checked in acceptTransaction so we don't need to duplicate

  MempoolResult[void](isOk: true)

# ============================================================================
# Ephemeral Anchor Policy
# ============================================================================
# Ephemeral dust outputs (0-value or below dust threshold) are allowed only if:
# 1. The transaction has 0-fee (no incentive to mine standalone)
# 2. All ephemeral dust outputs are spent by a child transaction in the same package
# 3. If the child is evicted, the parent with ephemeral dust must also be evicted

proc getDustThreshold*(output: TxOut): Satoshi =
  ## Calculate the dust threshold for an output
  ## Dust = output value that costs more to spend than it's worth
  ## Based on Bitcoin Core's GetDustThreshold with dustRelayFee = 3000 sat/kvB
  ##
  ## For P2WPKH (22 bytes): 31 bytes output + 67 bytes input = 98 bytes
  ## threshold = 98 * 3000 / 1000 = 294 sats
  ##
  ## For P2PKH (25 bytes): 34 bytes output + 148 bytes input = 182 bytes
  ## threshold = 182 * 3000 / 1000 = 546 sats

  # Check if output is unspendable (OP_RETURN)
  if output.scriptPubKey.len > 0 and output.scriptPubKey[0] == 0x6a:  # OP_RETURN
    return Satoshi(0)

  let outputSize = 8 + output.scriptPubKey.len + 1  # value + scriptPubKey + varint

  # Check if it's a witness program (much cheaper to spend)
  let isWitnessProgram = output.scriptPubKey.len >= 4 and
    output.scriptPubKey[0] >= 0x00 and output.scriptPubKey[0] <= 0x10 and
    int(output.scriptPubKey[1]) == output.scriptPubKey.len - 2

  let inputSize = if isWitnessProgram:
    # Witness input: prevout(36) + scriptSig(1) + sequence(4) + witness(~27)
    # With witness discount: (36 + 1 + 4 + 107/4) ≈ 67
    32 + 4 + 1 + (107 div 4) + 4
  else:
    # Legacy input: prevout(36) + scriptSig(~107) + sequence(4) = 148
    32 + 4 + 1 + 107 + 4

  let totalSize = outputSize + inputSize
  # dustRelayFee is in sat/kvB = sat/1000 bytes
  Satoshi((totalSize * DustRelayTxFee) div 1000)

proc isDust*(output: TxOut): bool =
  ## Check if an output is dust (value below dust threshold)
  int64(output.value) < int64(getDustThreshold(output))

proc isEphemeralDust*(output: TxOut): bool =
  ## Check if an output is ephemeral dust (0-value dust output)
  ## Ephemeral dust is specifically 0-value outputs that are meant to be
  ## immediately spent by a child transaction (for fee bumping via CPFP)
  int64(output.value) == 0

proc hasEphemeralDust*(tx: Transaction): bool =
  ## Check if transaction has any 0-value (ephemeral dust) outputs
  for output in tx.outputs:
    if isEphemeralDust(output):
      return true
  false

proc getEphemeralDustOutputs*(tx: Transaction): seq[uint32] =
  ## Get indices of all ephemeral dust outputs in a transaction
  for i, output in tx.outputs:
    if isEphemeralDust(output):
      result.add(uint32(i))

proc getDustOutputs*(tx: Transaction): seq[uint32] =
  ## Get indices of all dust outputs (including ephemeral dust)
  for i, output in tx.outputs:
    if isDust(output):
      result.add(uint32(i))

proc preCheckEphemeralTx*(tx: Transaction, baseFee: Satoshi, modFee: Satoshi = Satoshi(0)): MempoolResult[void] =
  ## Pre-check ephemeral dust policy for a single transaction
  ## If a tx has dust outputs, it must have 0-fee to prevent incentive for mining standalone
  ##
  ## Returns ok if:
  ## - Transaction has no dust outputs, OR
  ## - Transaction has dust but fee is 0
  ##
  ## Returns error if transaction has dust AND non-zero fee

  let dustOutputs = getDustOutputs(tx)
  if dustOutputs.len == 0:
    return MempoolResult[void](isOk: true)

  # If tx has dust, it must have 0-fee
  if int64(baseFee) != 0 or int64(modFee) != 0:
    return err(void, "tx with dust output must be 0-fee")

  MempoolResult[void](isOk: true)

proc checkEphemeralSpends*(txns: seq[Transaction],
                            mempoolGet: proc(txid: TxId): Option[Transaction]): MempoolResult[void] =
  ## Check that all ephemeral dust from parents is spent by children in the package
  ##
  ## For each transaction in the package:
  ## 1. Find all its parents (either in package or in mempool)
  ## 2. Collect all dust outputs from those parents
  ## 3. Verify that the child spends ALL of them
  ##
  ## Returns ok if all ephemeral dust is properly spent
  ## Returns error if any ephemeral dust output is not spent

  if txns.len == 0:
    return MempoolResult[void](isOk: true)

  # Build map of txid -> transaction for in-package lookups
  var packageTxMap = initTable[TxId, Transaction]()
  for tx in txns:
    packageTxMap[tx.txid()] = tx

  for tx in txns:
    var processedParents = initHashSet[TxId]()
    var unspentParentDust = initHashSet[OutPoint]()

    # Collect all parent dust outputs
    for input in tx.inputs:
      let parentTxid = input.prevOut.txid

      # Skip already processed parents
      if parentTxid in processedParents:
        continue

      # Look for parent in package first, then mempool
      var parentTx: Option[Transaction]
      if parentTxid in packageTxMap:
        parentTx = some(packageTxMap[parentTxid])
      else:
        parentTx = mempoolGet(parentTxid)

      if parentTx.isSome:
        let parent = parentTx.get()
        # Check for dust outputs in parent
        for outIndex in 0'u32 ..< uint32(parent.outputs.len):
          let output = parent.outputs[outIndex]
          if isDust(output):
            unspentParentDust.incl(OutPoint(txid: parentTxid, vout: outIndex))

      processedParents.incl(parentTxid)

    if unspentParentDust.len == 0:
      continue

    # Now verify all dust is spent by this child
    for input in tx.inputs:
      unspentParentDust.excl(input.prevOut)

    if unspentParentDust.len > 0:
      let txid = tx.txid()
      let wtxid = tx.wtxid()
      return err(void, "tx " & $txid & " (wtxid=" & $wtxid & ") did not spend parent's ephemeral dust")

  MempoolResult[void](isOk: true)

proc getEphemeralDustParents*(mp: Mempool, txid: TxId): seq[TxId] =
  ## Get all parent transactions that have ephemeral dust being spent by this tx
  ## Used for eviction cascade: when a child is evicted, parents with ephemeral dust must go too
  if txid notin mp.entries:
    return @[]

  let entry = mp.entries[txid]
  var parents: seq[TxId]

  for input in entry.tx.inputs:
    let parentTxid = input.prevOut.txid
    if parentTxid in mp.entries:
      let parentEntry = mp.entries[parentTxid]
      if hasEphemeralDust(parentEntry.tx):
        if parentTxid notin parents:
          parents.add(parentTxid)

  parents

proc evictEphemeralDustParents*(mp: Mempool, txid: TxId) =
  ## When a child transaction that spends ephemeral dust is removed,
  ## also remove the parent transactions that have ephemeral dust
  ## (they can't exist in mempool without their child)
  let parents = mp.getEphemeralDustParents(txid)
  for parentTxid in parents:
    # Check if this parent has any other children spending its ephemeral dust
    var hasOtherChild = false
    for otherTxid, entry in mp.entries:
      if otherTxid == txid:
        continue
      for input in entry.tx.inputs:
        if input.prevOut.txid == parentTxid:
          # Check if this input spends an ephemeral dust output
          if parentTxid in mp.entries:
            let parentEntry = mp.entries[parentTxid]
            if int(input.prevOut.vout) < parentEntry.tx.outputs.len:
              let output = parentEntry.tx.outputs[input.prevOut.vout]
              if isEphemeralDust(output):
                hasOtherChild = true
                break
      if hasOtherChild:
        break

    if not hasOtherChild:
      # No other child spends this parent's ephemeral dust, evict it
      mp.removeTransaction(parentTxid)

# Calculate transaction weight
proc calculateWeight*(tx: Transaction): int =
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

# Calculate ancestor set for a transaction (BFS through parents)
proc calculateAncestors*(mp: Mempool, tx: Transaction): HashSet[TxId] =
  ## Return the set of all ancestor txids in the mempool (not including self)
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
    # Add grandparents
    for input in parentEntry.tx.inputs:
      if input.prevOut.txid in mp.entries and input.prevOut.txid notin visited:
        toVisit.add(input.prevOut.txid)

  visited

# Calculate ancestor count and total vsize for a new transaction
proc calculateAncestorStats*(mp: Mempool, tx: Transaction, selfVsize: int): (int, int) =
  ## Returns (ancestor count including self, total ancestor vsize including self)
  let ancestors = mp.calculateAncestors(tx)
  var totalVsize = selfVsize
  for ancestorTxid in ancestors:
    let entry = mp.entries[ancestorTxid]
    # vsize = weight / 4 (rounded up)
    totalVsize += (entry.weight + 3) div 4

  (len(ancestors) + 1, totalVsize)  # +1 for self

# Calculate descendant set for a transaction (BFS through children)
proc calculateDescendants*(mp: Mempool, txid: TxId): HashSet[TxId] =
  ## Return the set of all descendant txids in the mempool (not including self)
  var visited = initHashSet[TxId]()
  var toVisit: seq[TxId]

  # Find immediate children (transactions that spend outputs of this tx)
  for otherTxid, entry in mp.entries:
    for input in entry.tx.inputs:
      if input.prevOut.txid == txid:
        toVisit.add(otherTxid)
        break

  # BFS through descendants
  while toVisit.len > 0:
    let childTxid = toVisit.pop()
    if childTxid in visited:
      continue
    visited.incl(childTxid)

    # Add grandchildren
    for otherTxid, entry in mp.entries:
      for input in entry.tx.inputs:
        if input.prevOut.txid == childTxid and otherTxid notin visited:
          toVisit.add(otherTxid)
          break

  visited

# Calculate descendant count and total vsize for an entry
proc calculateDescendantStats*(mp: Mempool, txid: TxId): (int, int) =
  ## Returns (descendant count including self, total descendant vsize including self)
  let entry = mp.entries[txid]
  let descendants = mp.calculateDescendants(txid)
  var totalVsize = (entry.weight + 3) div 4  # Self vsize

  for descTxid in descendants:
    let descEntry = mp.entries[descTxid]
    totalVsize += (descEntry.weight + 3) div 4

  (len(descendants) + 1, totalVsize)  # +1 for self

# Check package limits for a new transaction
proc checkPackageLimits*(mp: Mempool, tx: Transaction, weight: int): MempoolResult[void] =
  ## Check if adding this transaction would violate ancestor/descendant/cluster limits.
  ##
  ## Gates enforced (matching Bitcoin Core policy/policy.h + validation.cpp):
  ##   G1  ancestor count  <= ancestorLimit (default 25)
  ##   G2  ancestor vsize  <= ancestorSizeLimit (default 101,000 vB)
  ##   G3  each ancestor's descendant count after add  <= descendantLimit (25)
  ##   G4  each ancestor's descendant vsize after add  <= descendantSizeLimit (101,000 vB)
  ##       … with EXTRA_DESCENDANT_TX_SIZE_LIMIT exception (G5):
  ##   G5  if tx has exactly 1 in-mempool ancestor AND vsize <= 10,000 vB, skip G4
  ##       (EXTRA_DESCENDANT_TX_SIZE_LIMIT, policy/policy.h:90)
  ##   G6  cluster count (tx + all ancestors) <= clusterLimit (default 64)
  ##   G7  cluster vsize  <= clusterSizeLimit (default 101,000 vB)
  ##
  ## Returns ok(()) if all limits are satisfied, err(msg) otherwise.

  let vsize = (weight + 3) div 4

  # Calculate ancestor stats for the new transaction
  let (ancestorCount, ancestorSize) = mp.calculateAncestorStats(tx, vsize)

  # G1: ancestor count limit (including self)
  if ancestorCount > mp.ancestorLimit:
    return err(void, "exceeds ancestor limit: " & $ancestorCount & " > " & $mp.ancestorLimit)

  # G2: ancestor size limit
  if ancestorSize > mp.ancestorSizeLimit:
    return err(void, "exceeds ancestor size limit: " & $ancestorSize & " vB > " & $mp.ancestorSizeLimit & " vB")

  # Compute the ancestor set once (used in G3/G4/G5/G6/G7).
  let ancestors = mp.calculateAncestors(tx)

  # G5 precondition: tx qualifies for extra-descendant allowance if it has
  # exactly 1 in-mempool ancestor AND its own vsize <= ExtraDescendantTxSizeLimit.
  # When the allowance applies we skip the descendant VSIZE check (G4) for that
  # ancestor — but we still enforce the descendant COUNT check (G3).
  # Core reference: policy/policy.h:90 EXTRA_DESCENDANT_TX_SIZE_LIMIT comment.
  let extraDescAllowed = (ancestors.len == 1) and (vsize <= ExtraDescendantTxSizeLimit)

  # G3/G4: Check descendant limits for each ancestor.
  # Adding this tx increases each ancestor's descendant count by 1 and size by vsize.
  for ancestorTxid in ancestors:
    let (descCount, descSize) = mp.calculateDescendantStats(ancestorTxid)

    # G3: descendant count
    if descCount + 1 > mp.descendantLimit:
      return err(void, "would exceed descendant limit for ancestor " & $ancestorTxid &
                       ": " & $(descCount + 1) & " > " & $mp.descendantLimit)

    # G4 (with G5 exception): descendant vsize
    if not extraDescAllowed:
      if descSize + vsize > mp.descendantSizeLimit:
        return err(void, "would exceed descendant size limit for ancestor " & $ancestorTxid &
                         ": " & $(descSize + vsize) & " vB > " & $mp.descendantSizeLimit & " vB")

  # Also check immediate parents (mempool entries this tx spends from) in case
  # calculateAncestors missed an edge (shouldn't happen, belt-and-braces).
  for input in tx.inputs:
    if input.prevOut.txid in mp.entries:
      let parentTxid = input.prevOut.txid
      if parentTxid notin ancestors:
        let (descCount, descSize) = mp.calculateDescendantStats(parentTxid)
        if descCount + 1 > mp.descendantLimit:
          return err(void, "would exceed descendant limit for parent " & $parentTxid)
        if not extraDescAllowed:
          if descSize + vsize > mp.descendantSizeLimit:
            return err(void, "would exceed descendant size limit for parent " & $parentTxid)

  # G6: cluster count — the cluster of this tx consists of itself + all ancestors.
  # (In a full cluster-mempool implementation the cluster boundary includes all
  # transactions connected via ancestor/descendant links; here we conservatively
  # use the ancestor-set + self as a lower-bound proxy.)
  let clusterCount = ancestors.len + 1  # +1 for the tx itself
  if clusterCount > mp.clusterLimit:
    return err(void, "too-large-cluster: cluster count " & $clusterCount & " > " & $mp.clusterLimit)

  # G7: cluster vsize (ancestor vsize including self already computed as ancestorSize)
  if ancestorSize > mp.clusterSizeLimit:
    return err(void, "too-large-cluster: cluster vsize " & $ancestorSize & " vB > " & $mp.clusterSizeLimit & " vB")

  MempoolResult[void](isOk: true)

# Accept a transaction into the mempool
proc acceptTransaction*(mp: Mempool, tx: Transaction,
                        crypto: CryptoEngine): MempoolResult[TxId] =
  ## Validate and add transaction to mempool
  ## Returns txid on success, error message on failure
  ## Supports Full RBF: conflicting transactions can be replaced if fee rules are met

  # Compute txid
  let txid = tx.txid()

  # Already in mempool?
  if txid in mp.entries:
    return err(TxId, "transaction already in mempool")

  # Basic validation (structure, no duplicate inputs, valid output values)
  let basicResult = checkTransaction(tx, mp.params)
  if not basicResult.isOk:
    return err(TxId, "invalid transaction: " & $basicResult.error)

  # Coinbase transactions are only valid inside blocks, not as mempool entries.
  # Bitcoin Core MemPoolAccept::PreChecks, validation.cpp:803-804.
  if isCoinbase(tx):
    return err(TxId, "coinbase")

  # Transactions smaller than MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes)
  # are rejected to mitigate CVE-2017-12842 (64-byte tx collision attack).
  # Bitcoin Core MemPoolAccept::PreChecks, validation.cpp:813-814.
  const MinStandardTxNonwitnessSize = 65
  let nonwitnessSize = serializeLegacy(tx).len
  if nonwitnessSize < MinStandardTxNonwitnessSize:
    return err(TxId, "tx-size-small")

  # Calculate weight and check 400K WU policy limit
  let weight = calculateWeight(tx)
  if weight > MaxStandardTxWeight:
    return err(TxId, "transaction weight " & $weight & " exceeds max " & $MaxStandardTxWeight)

  # Standardness check (Bitcoin Core IsStandardTx, policy/policy.cpp).
  let stdRes = isStandardTx(tx)
  if not stdRes.ok:
    return err(TxId, "non-standard tx (" & stdRes.reason & ")")

  # Witness standardness check (Bitcoin Core IsWitnessStandard, policy/policy.cpp:265-351).
  # Runs after IsStandardTx so UTXO existence is already confirmed above.
  let witStdRes = isWitnessStandard(tx, proc(input: TxIn): seq[byte] =
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      utxo.get().output.scriptPubKey
    else:
      # Unconfirmed mempool parent (already validated above).
      let parentEntry = mp.entries[input.prevOut.txid]
      parentEntry.tx.outputs[input.prevOut.vout].scriptPubKey
  )
  if not witStdRes.ok:
    return err(TxId, witStdRes.reason)

  # IsFinalTx (BIP-113): reject non-final transactions at mempool admit.
  # Mempool holds txs for the *next* block, so check against tipHeight+1
  # and the current chain MTP (MEDIAN_TIME_PAST of last 11 blocks).
  # Mirrors Bitcoin Core MemPoolAccept::PreChecks → CheckFinalTxAtTip
  # (validation.cpp:819).
  let tipHeight = mp.chainState.bestHeight
  let mtp = getMtpForHeight(mp.chainState.db, tipHeight)
  if not isFinalTx(tx, uint32(tipHeight + 1), mtp):
    return err(TxId, "non-final")

  # Check for conflicts with mempool transactions (Full RBF)
  let conflicts = mp.findConflicts(tx)
  var conflictsToRemove = initHashSet[TxId]()

  # Check inputs exist (either in chainstate or mempool).
  # Also enforces coinbase maturity (Gap N3): a tx spending an immature
  # coinbase output must not enter the mempool.
  # Mirrors Bitcoin Core CheckTxInputs (consensus/tx_verify.cpp) called from
  # MemPoolAccept::PreChecks.
  for input in tx.inputs:
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isNone:
      # Check mempool for unconfirmed parent
      # But skip if it's a conflict we're replacing
      if input.prevOut.txid notin mp.entries:
        return err(TxId, "input not found: " & $input.prevOut.txid)
      let parentEntry = mp.entries[input.prevOut.txid]
      if int(input.prevOut.vout) >= parentEntry.tx.outputs.len:
        return err(TxId, "invalid output index for mempool parent")
    else:
      # Coinbase maturity check: a confirmed coinbase output must have
      # at least COINBASE_MATURITY (100) confirmations before it can
      # be spent in the mempool.
      let entry = utxo.get()
      if entry.isCoinbase:
        let age = tipHeight - entry.height
        if age < int32(mp.params.coinbaseMaturity):
          return err(TxId, "coinbase output not yet mature: age=" & $age &
                     " required=" & $mp.params.coinbaseMaturity)

  # BIP-68 sequence locks: reject txs whose relative-locktime constraints
  # are not satisfied at the next block.  Uses per-input UTXO heights from
  # the chainstate.  Mirrors Bitcoin Core MemPoolAccept::PreChecks →
  # CheckSequenceLocksAtTip (validation.cpp:887).
  proc lookupForSeqLock(op: OutPoint): Option[UtxoEntry] =
    let confirmed = mp.chainState.getUtxo(op)
    if confirmed.isSome:
      return confirmed
    # Unconfirmed mempool parent: synthesize a UtxoEntry at tipHeight+1
    # (same convention as Bitcoin Core's CalculateLockPointsAtTip).
    if op.txid in mp.entries:
      return some(UtxoEntry(output: TxOut(), height: int32(tipHeight + 1), isCoinbase: false))
    none(UtxoEntry)

  proc getMtpAt(h: int32): uint32 = getMtpForHeight(mp.chainState.db, h)

  let seqResult = checkSequenceLocksForTx(
    tx, lookupForSeqLock, tipHeight + 1, mtp, getMtpAt, mp.params)
  if not seqResult.isOk:
    return err(TxId, "non-BIP68-final: " & $seqResult.error)

  # Calculate fee
  let feeOpt = calculateFee(tx, mp)
  if feeOpt.isNone:
    return err(TxId, "unable to calculate fee")
  let fee = feeOpt.get()

  # Calculate fee rate (sat/vbyte)
  # vbytes = weight / 4
  let vbytes = float64(weight) / 4.0
  let vsizeInt = (weight + 3) div 4
  let feeRate = float64(int64(fee)) / vbytes

  # Check minimum fee rate (1 sat/vbyte)
  if feeRate < mp.minFeeRate:
    return err(TxId, "fee rate " & $feeRate & " below minimum " & $mp.minFeeRate)

  # If there are conflicts, validate RBF rules before proceeding
  if len(conflicts) > 0:
    let rbfResult = mp.checkRbfRules(tx, fee, vsizeInt, conflicts)
    if not rbfResult.isOk:
      return err(TxId, rbfResult.error)
    conflictsToRemove = rbfResult.value

  # Check TRUC (v3) policy rules
  var trucSiblingToEvict: Option[TxId] = none(TxId)
  let trucResult = mp.checkSingleTrucRules(tx, weight, conflicts)
  if not trucResult.isOk:
    return err(TxId, trucResult.error)

  # Handle TRUC sibling eviction if applicable
  if trucResult.siblingToEvict.isSome:
    let siblingTxid = trucResult.siblingToEvict.get()
    # Check sibling eviction rules (must pay at least sibling's fee)
    let siblingEvictionResult = mp.checkTrucSiblingEviction(tx, fee, siblingTxid)
    if not siblingEvictionResult.isOk:
      return err(TxId, siblingEvictionResult.error)
    trucSiblingToEvict = some(siblingTxid)
    # Add sibling to conflicts for removal
    conflictsToRemove.incl(siblingTxid)

  # Check ephemeral dust policy for standalone transactions
  # A tx with dust outputs must have 0-fee (to prevent incentive to mine standalone)
  # Note: transactions submitted as packages are checked differently in acceptPackage
  let ephemeralPreCheck = preCheckEphemeralTx(tx, fee)
  if not ephemeralPreCheck.isOk:
    return err(TxId, ephemeralPreCheck.error)

  # For standalone tx with ephemeral dust, reject unless submitted via package relay
  # The parent with ephemeral dust needs a child to spend those outputs
  # Since this is a new tx being added alone, no child can exist yet
  if hasEphemeralDust(tx):
    return err(TxId, "tx has ephemeral dust output but no child spending it; use package relay")

  # Sigop cost check: reject txs that exceed per-tx policy limit.
  # Bitcoin Core MemPoolAccept::PreChecks, validation.cpp:908-942:
  #   nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS)
  #   if nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST → "bad-txns-too-many-sigops"
  # MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 16_000 (policy/policy.h:44).
  proc lookupForSigops(op: OutPoint): Option[UtxoEntry] =
    let confirmed = mp.chainState.getUtxo(op)
    if confirmed.isSome:
      return confirmed
    if op.txid in mp.entries:
      let parentEntry = mp.entries[op.txid]
      if int(op.vout) < parentEntry.tx.outputs.len:
        return some(UtxoEntry(
          output: parentEntry.tx.outputs[int(op.vout)],
          height: int32(tipHeight),
          isCoinbase: false
        ))
    none(UtxoEntry)

  let sigopResult = getTransactionSigOpCost(tx, lookupForSigops, useP2SH = true, useWitness = true)
  if sigopResult.isOk:
    if sigopResult.value > MaxStandardTxSigopsCost:
      return err(TxId, "bad-txns-too-many-sigops")

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

  # Remove conflicts before calculating ancestor stats (for RBF)
  if len(conflictsToRemove) > 0:
    mp.removeConflicts(conflictsToRemove)

  # Calculate ancestor fees and weight for CPFP
  let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(tx, fee, weight)

  # Check package limits (ancestor/descendant count and size)
  let packageLimitsResult = mp.checkPackageLimits(tx, weight)
  if not packageLimitsResult.isOk:
    return err(TxId, "package limits exceeded: " & packageLimitsResult.error)

  # Calculate ancestor stats for caching
  let (ancestorCount, ancestorSize) = mp.calculateAncestorStats(tx, vsizeInt)

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
    ancestorWeight: ancestorWeight,
    ancestorCount: ancestorCount,
    ancestorSize: ancestorSize
  )

  # Add to mempool
  mp.entries[txid] = entry
  mp.currentSize += txSize

  # Track spent outpoints
  for input in tx.inputs:
    mp.spentBy[input.prevOut] = txid

  ok(txid)

# Remove a transaction from the mempool
proc removeTransaction*(mp: Mempool, txid: TxId, evictEphemeral: bool = true) =
  ## Remove a transaction from the mempool
  ## If evictEphemeral is true (default), also evict parent transactions
  ## that have ephemeral dust which is no longer being spent
  if txid notin mp.entries:
    return

  let entry = mp.entries[txid]

  # Get ephemeral dust parents before removing (for cascade)
  var ephemeralParents: seq[TxId]
  if evictEphemeral:
    ephemeralParents = mp.getEphemeralDustParents(txid)

  # Remove from spentBy tracking
  for input in entry.tx.inputs:
    mp.spentBy.del(input.prevOut)

  # Update size
  let txSize = serialize(entry.tx).len
  mp.currentSize -= txSize

  mp.entries.del(txid)

  # Cascade eviction for ephemeral dust parents
  if evictEphemeral:
    for parentTxid in ephemeralParents:
      if parentTxid notin mp.entries:
        continue
      # Check if this parent has any remaining children spending its ephemeral dust
      var hasOtherChild = false
      let parentEntry = mp.entries[parentTxid]
      let ephemeralOutputs = getEphemeralDustOutputs(parentEntry.tx)

      for epIdx in ephemeralOutputs:
        let outpoint = OutPoint(txid: parentTxid, vout: epIdx)
        if outpoint in mp.spentBy:
          hasOtherChild = true
          break

      if not hasOtherChild and ephemeralOutputs.len > 0:
        # No child spends this parent's ephemeral dust, evict it too
        mp.removeTransaction(parentTxid, evictEphemeral = false)  # Prevent infinite recursion

# Remove transactions confirmed in a block
proc removeForBlock*(mp: Mempool, blk: Block) =
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

# Re-admit transactions that came back from a disconnected block during a reorg.
# Mirrors Bitcoin Core's `MaybeUpdateMempoolForReorg`
# (validation.cpp::DisconnectTip → DisconnectedBlockTransactions → mempool
# re-validation), and the camlcoin reference at
# `lib/sync.ml:2354-2363`.  Pattern B closure for nimrod (see
# CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md).
#
# Each tx is fed back through `acceptTransaction`, which re-runs all the
# normal mempool admit checks (signatures, BIP-68 sequence locks,
# coinbase maturity at the new tip height, fee/size policy, RBF
# conflicts, ...).  Failures are silently dropped — the tx simply
# disappears from the mempool, exactly like Core.  Returns the count
# successfully re-admitted so callers can log a single summary line.
proc blockDisconnected*(mp: Mempool, txs: seq[Transaction],
                        crypto: CryptoEngine): int =
  ## Re-admit non-coinbase transactions from a disconnected block.
  ##
  ## txs MUST already exclude coinbase transactions — caller is responsible.
  ## See `chainstate.handleReorg` (3-arg overload) for the canonical source.
  result = 0
  for tx in txs:
    let txid = tx.txid()
    # Already in mempool (e.g. arrived via P2P relay during the reorg
    # window) — skip; acceptTransaction would reject with "already in
    # mempool" anyway, but doing the cheap check first avoids the noise.
    if txid in mp.entries:
      continue
    let res = mp.acceptTransaction(tx, crypto)
    if res.isOk:
      inc result

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
proc evictLowestFee*(mp: Mempool) =
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
proc expire*(mp: Mempool, maxAge: Duration = initDuration(hours = 336)) =
  ## Remove transactions older than maxAge (default 2 weeks)
  let cutoff = getTime() - maxAge
  var toRemove: seq[TxId]

  for txid, entry in mp.entries:
    if entry.timeAdded < cutoff:
      toRemove.add(txid)

  for txid in toRemove:
    mp.removeTransaction(txid)

# Update ancestor fees after a transaction is added/removed
proc updateDescendantFees*(mp: Mempool, txid: TxId) =
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

# ============================================================================
# Replace-by-Fee (BIP125)
# Reference: Bitcoin Core src/util/rbf.h, src/util/rbf.cpp, src/policy/rbf.cpp
# ============================================================================

proc signalsOptInRBF*(tx: Transaction): bool =
  ## Gate 1 — BIP-125 opt-in RBF signaling.
  ## A transaction signals opt-in RBF when at least one input has
  ## nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd).
  ## UNSIGNED comparison: 0xfffffffd < 0xfffffffe < 0xffffffff (SEQUENCE_FINAL).
  ## Reference: Bitcoin Core src/util/rbf.cpp SignalsOptInRBF()
  for input in tx.inputs:
    if input.sequence <= MaxBip125RbfSequence:
      return true
  false

proc isRbfOptIn*(mp: Mempool, tx: Transaction): bool =
  ## Check whether tx opts in to RBF, considering both the tx itself and
  ## any in-mempool ancestors (Gate 1 + Gate 2).
  ## Reference: Bitcoin Core src/policy/rbf.cpp IsRBFOptIn()
  ##
  ## Gate 1: tx itself signals (any input nSequence <= 0xfffffffd).
  ## Gate 2: any unconfirmed ancestor in the mempool signals.
  ## Full-RBF mode (fullRbf=true): always returns true.
  if mp.fullRbf:
    return true
  # Gate 1: direct signaling
  if signalsOptInRBF(tx):
    return true
  # Gate 2: ancestor inheritance — walk mempool ancestors of tx
  let ancestors = mp.calculateAncestors(tx)
  for ancestorTxid in ancestors:
    if ancestorTxid in mp.entries:
      if signalsOptInRBF(mp.entries[ancestorTxid].tx):
        return true
  false

proc findConflicts*(mp: Mempool, tx: Transaction): HashSet[TxId] =
  ## Find all mempool transactions that conflict with tx (spend the same inputs)
  ## Full RBF: all mempool transactions are replaceable regardless of signaling
  result = initHashSet[TxId]()
  for input in tx.inputs:
    if input.prevOut in mp.spentBy:
      result.incl(mp.spentBy[input.prevOut])

proc getAllConflictsWithDescendants*(mp: Mempool, conflicts: HashSet[TxId]): HashSet[TxId] =
  ## Get all conflicts and their descendants (transactions that would be evicted)
  result = initHashSet[TxId]()
  for conflictTxid in conflicts:
    result.incl(conflictTxid)
    # Add all descendants of this conflict
    let descendants = mp.calculateDescendants(conflictTxid)
    for descTxid in descendants:
      result.incl(descTxid)

proc calculateConflictFees*(mp: Mempool, allConflicts: HashSet[TxId]): (Satoshi, int) =
  ## Calculate total fee and vsize of all conflicting transactions
  var totalFee: int64 = 0
  var totalVsize: int = 0
  for conflictTxid in allConflicts:
    if conflictTxid in mp.entries:
      let entry = mp.entries[conflictTxid]
      totalFee += int64(entry.fee)
      totalVsize += (entry.weight + 3) div 4  # Round up to vsize
  (Satoshi(totalFee), totalVsize)

proc checkRbfRules*(mp: Mempool, tx: Transaction, txFee: Satoshi, txVsize: int,
                    conflicts: HashSet[TxId], incrementalRelayFee: float64 = DefaultIncrementalRelayFee): MempoolResult[HashSet[TxId]] =
  ## Check if tx can replace the conflicting transactions.
  ## Returns the set of all transactions to be evicted (conflicts + descendants) or an error.
  ##
  ## BIP-125 gates (reference: Bitcoin Core src/policy/rbf.cpp):
  ## Gate 1  — tx (or ancestor) signals opt-in via nSequence <= 0xfffffffd; skipped in fullRbf mode.
  ## Gate 2  — ancestor inheritance: any mempool ancestor that signals makes tx replaceable.
  ## Rule #5 — conflicts + descendants must not exceed MAX_REPLACEMENT_CANDIDATES (100).
  ## Rule #2 — replacement must not spend outputs from transactions it is evicting.
  ## Rule #3 — replacement fees >= original fees (>= not >; equal is allowed).
  ## Rule #4 — additional fees >= min_relay_fee * replacement_vsize (pays for bandwidth).
  ##
  ## NOTE: Rule #8 (ImprovesFeerateDiagram, Core 27+) is deferred; cluster tracking required.

  # Gate 1 + Gate 2: BIP-125 opt-in signaling (skipped in fullRbf mode).
  # In standard mode, at least one directly-conflicting tx must be replaceable —
  # i.e., it or one of its ancestors signals opt-in.
  # Reference: Bitcoin Core src/policy/rbf.cpp IsRBFOptIn()
  if not mp.fullRbf:
    var anySignals = false
    for conflictTxid in conflicts:
      if conflictTxid in mp.entries:
        let conflictTx = mp.entries[conflictTxid].tx
        if signalsOptInRBF(conflictTx):
          anySignals = true
          break
        # Gate 2: check ancestors of the conflicting tx for inherited signaling
        let conflictAncestors = mp.calculateAncestors(conflictTx)
        for ancestorTxid in conflictAncestors:
          if ancestorTxid in mp.entries and signalsOptInRBF(mp.entries[ancestorTxid].tx):
            anySignals = true
            break
      if anySignals:
        break
    if not anySignals:
      return err(HashSet[TxId], "rejecting replacement: original transaction does not signal RBF opt-in (BIP-125)")

  # Rule #5: Don't evict more than MAX_REPLACEMENT_CANDIDATES transactions.
  # Reference: Bitcoin Core src/policy/rbf.cpp GetEntriesForConflicts() — checks cluster count.
  # We conservatively count total evicted txs (conflicts + descendants) since we lack cluster tracking.
  let allConflicts = mp.getAllConflictsWithDescendants(conflicts)
  if len(allConflicts) > MaxReplacementCandidates:
    return err(HashSet[TxId], "rejecting replacement: too many potential replacements (" &
               $len(allConflicts) & " > " & $MaxReplacementCandidates & ")")

  # Rule #2 (HasNoNewUnconfirmed): replacement must not spend outputs from any evicted tx.
  # Reference: Bitcoin Core src/policy/rbf.cpp EntriesAndTxidsDisjoint()
  for input in tx.inputs:
    if input.prevOut.txid in allConflicts:
      return err(HashSet[TxId], "replacement tx spends output from conflicting transaction " &
                 $input.prevOut.txid)

  # Calculate total fees of all conflicting transactions.
  let (conflictFees, conflictTotalVsize) = mp.calculateConflictFees(allConflicts)
  discard conflictTotalVsize  # vsize of replaced txs; unused — replacement vsize drives Rule #4

  # Rule #3 (PaysForRBF part 1): replacement fees >= original fees.
  # Core: "if (replacement_fees < original_fees) → reject"  (< not <=; equal is allowed).
  # Reference: Bitcoin Core src/policy/rbf.cpp PaysForRBF() line 109.
  if int64(txFee) < int64(conflictFees):
    return err(HashSet[TxId], "rejecting replacement %s, less fees than conflicting txs; " &
               $int64(txFee) & " < " & $int64(conflictFees) & " sats")

  # Rule #4 (PaysForRBF part 2): additional fees >= incremental relay fee * replacement vsize.
  # Reference: Bitcoin Core src/policy/rbf.cpp PaysForRBF() line 118.
  let additionalFee = int64(txFee) - int64(conflictFees)
  let requiredAdditionalFee = int64(incrementalRelayFee * float64(txVsize))
  if additionalFee < requiredAdditionalFee:
    return err(HashSet[TxId], "rejecting replacement: not enough additional fees to relay (" &
               $additionalFee & " < " & $requiredAdditionalFee & " sats)")

  ok(allConflicts)

proc removeConflicts*(mp: Mempool, conflicts: HashSet[TxId]) =
  ## Remove all conflicting transactions and their descendants from the mempool
  for conflictTxid in conflicts:
    mp.removeTransaction(conflictTxid)

proc isBip125Replaceable*(mp: Mempool, txid: TxId): bool =
  ## Check if a transaction in the mempool is replaceable according to BIP-125.
  ## Gate 1: tx itself signals opt-in (any input nSequence <= 0xfffffffd).
  ## Gate 2: any in-mempool ancestor signals opt-in.
  ## Full-RBF mode: all mempool txs are replaceable regardless of signaling.
  ## Reference: Bitcoin Core src/policy/rbf.cpp IsRBFOptIn()
  if txid notin mp.entries:
    return false
  if mp.fullRbf:
    return true
  let tx = mp.entries[txid].tx
  if signalsOptInRBF(tx):
    return true
  # Gate 2: walk ancestors for inherited signaling
  let ancestors = mp.calculateAncestors(tx)
  for ancestorTxid in ancestors:
    if ancestorTxid in mp.entries and signalsOptInRBF(mp.entries[ancestorTxid].tx):
      return true
  false

# ============================================================================
# Package Relay (CPFP)
# ============================================================================

proc acceptPackage*(mp: Mempool, txns: seq[Transaction],
                    crypto: CryptoEngine,
                    usePackageFeerates: bool = true): PackageResult =
  ## Validate and accept a package of transactions into the mempool
  ## Package validation allows CPFP: a child can pay for its parent's inclusion
  ##
  ## Key behavior:
  ## - Package must be topologically sorted (parents before children)
  ## - Package fee rate = sum(fees) / sum(vsizes)
  ## - Individual txs may have fee rate below minimum if package rate is sufficient
  ## - Max 25 transactions, max 101 kvB total size
  ##
  ## Returns PackageResult with per-tx results and overall status

  result = PackageResult(
    valid: false,
    state: pvUnset,
    error: "",
    txResults: @[],
    packageFeerate: 0.0
  )

  if txns.len == 0:
    result.valid = true
    return result

  # Context-free package validation
  let wellFormed = isWellFormedPackage(txns)
  if not wellFormed.isOk:
    result.state = pvPolicy
    result.error = wellFormed.error
    return result

  # Check total vsize limit (101 kvB)
  var totalVsize = 0
  var totalWeight = 0
  var weights: seq[int]
  for tx in txns:
    let weight = validation.calculateTransactionWeight(tx)
    weights.add(weight)
    totalWeight += weight
    totalVsize += (weight + 3) div 4

  if totalVsize > MaxPackageSize:
    result.state = pvPolicy
    result.error = "package-too-large: vsize " & $totalVsize & " > " & $MaxPackageSize
    return result

  # Check TRUC (v3) package policy rules
  # mempoolParentAncestorCount(txid): ancestor count INCLUDING self (matches Core's GetAncestorCount)
  # mempoolParentDescendantCount(txid): descendant count INCLUDING self (matches Core's GetDescendantCount)
  let trucResult = checkPackageTrucRules(
    txns,
    proc(txid: TxId): bool = txid in mp.entries,
    proc(txid: TxId): bool = (if txid in mp.entries: mp.entries[txid].isTruc else: false),
    proc(txid: TxId): int =
      if txid in mp.entries:
        # calculateAncestors returns ancestors WITHOUT self, so add 1 for self
        mp.calculateAncestors(mp.entries[txid].tx).len + 1
      else: 1,
    proc(txid: TxId): int = (if txid in mp.entries: mp.calculateDescendantStats(txid)[0] else: 1)
  )
  if not trucResult.isOk:
    result.state = pvPolicy
    result.error = trucResult.error
    return result

  # Check ephemeral dust policy: all dust from parents must be spent by children
  let ephemeralResult = checkEphemeralSpends(
    txns,
    proc(txid: TxId): Option[Transaction] =
      if txid in mp.entries:
        some(mp.entries[txid].tx)
      else:
        none(Transaction)
  )
  if not ephemeralResult.isOk:
    result.state = pvPolicy
    result.error = "missing-ephemeral-spends: " & ephemeralResult.error
    return result

  # Calculate fees and validate each transaction
  var fees: seq[Satoshi]
  var txids: seq[TxId]
  var allValid = true

  # First pass: calculate fees for each transaction
  # We need to handle intra-package dependencies
  var packageUtxos = initTable[OutPoint, TxOut]()  # UTXOs created by earlier txs in package

  for i, tx in txns:
    let txid = tx.txid()
    txids.add(txid)

    var txResult = TxResult(
      txid: txid,
      wtxid: tx.wtxid(),
      allowed: false,
      vsize: (weights[i] + 3) div 4,
      fees: Satoshi(0),
      error: ""
    )

    # Check if already in mempool
    if txid in mp.entries:
      txResult.allowed = true
      txResult.fees = mp.entries[txid].fee
      fees.add(txResult.fees)
      result.txResults.add(txResult)
      continue

    # Calculate fee
    var inputValue: int64 = 0
    var inputsValid = true

    for input in tx.inputs:
      # Check chainstate first
      let utxo = mp.chainState.getUtxo(input.prevOut)
      if utxo.isSome:
        inputValue += int64(utxo.get().output.value)
      # Check package UTXOs (from earlier txs in this package)
      elif input.prevOut in packageUtxos:
        inputValue += int64(packageUtxos[input.prevOut].value)
      # Check mempool for unconfirmed parent
      elif input.prevOut.txid in mp.entries:
        let parentEntry = mp.entries[input.prevOut.txid]
        if int(input.prevOut.vout) < parentEntry.tx.outputs.len:
          inputValue += int64(parentEntry.tx.outputs[input.prevOut.vout].value)
        else:
          inputsValid = false
          txResult.error = "invalid output index for mempool parent"
          break
      else:
        inputsValid = false
        txResult.error = "input not found: " & $input.prevOut.txid
        break

    if not inputsValid:
      allValid = false
      fees.add(Satoshi(0))
      result.txResults.add(txResult)
      continue

    var outputValue: int64 = 0
    for output in tx.outputs:
      outputValue += int64(output.value)

    if inputValue < outputValue:
      txResult.error = "outputs exceed inputs"
      allValid = false
      fees.add(Satoshi(0))
      result.txResults.add(txResult)
      continue

    let fee = Satoshi(inputValue - outputValue)
    txResult.fees = fee
    fees.add(fee)

    # Add this tx's outputs to package UTXOs for later txs
    for j, output in tx.outputs:
      let outpoint = OutPoint(txid: txid, vout: uint32(j))
      packageUtxos[outpoint] = output

    txResult.allowed = true
    result.txResults.add(txResult)

  # Calculate package fee rate
  let packageFeerate = calculatePackageFeerate(fees, weights)
  result.packageFeerate = packageFeerate

  # Check fee rate policy
  # When using package feerates, the combined package rate must meet the minimum
  if usePackageFeerates:
    if packageFeerate < mp.minFeeRate:
      result.state = pvPolicy
      result.error = "package fee rate " & $packageFeerate & " below minimum " & $mp.minFeeRate
      return result
  else:
    # Check individual fee rates
    for i in 0 ..< txns.len:
      if result.txResults[i].allowed:
        let individualRate = float64(int64(fees[i])) / float64((weights[i] + 3) div 4)
        if individualRate < mp.minFeeRate:
          result.txResults[i].allowed = false
          result.txResults[i].error = "fee rate " & $individualRate & " below minimum"
          allValid = false

  if not allValid:
    result.state = pvTx
    result.error = "one or more transactions failed validation"
    return result

  # Second pass: verify scripts and add to mempool
  let scriptFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)
  packageUtxos.clear()

  for i, tx in txns:
    let txid = txids[i]

    # Skip if already in mempool
    if txid in mp.entries:
      # Update package UTXOs
      for j, output in tx.outputs:
        packageUtxos[OutPoint(txid: txid, vout: uint32(j))] = output
      continue

    # Verify scripts
    for inputIdx, input in tx.inputs:
      var scriptPubKey: seq[byte]
      var amount: Satoshi

      let utxo = mp.chainState.getUtxo(input.prevOut)
      if utxo.isSome:
        scriptPubKey = utxo.get().output.scriptPubKey
        amount = utxo.get().output.value
      elif input.prevOut in packageUtxos:
        scriptPubKey = packageUtxos[input.prevOut].scriptPubKey
        amount = packageUtxos[input.prevOut].value
      elif input.prevOut.txid in mp.entries:
        let parentEntry = mp.entries[input.prevOut.txid]
        let parentOutput = parentEntry.tx.outputs[input.prevOut.vout]
        scriptPubKey = parentOutput.scriptPubKey
        amount = parentOutput.value
      else:
        result.txResults[i].allowed = false
        result.txResults[i].error = "input not found during script verification"
        result.state = pvTx
        result.error = "script verification failed for tx " & $i
        return result

      var witness: seq[seq[byte]] = @[]
      if inputIdx < tx.witnesses.len:
        witness = tx.witnesses[inputIdx]

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
        result.txResults[i].allowed = false
        result.txResults[i].error = "script verification failed for input " & $inputIdx
        result.state = pvTx
        result.error = "script verification failed for tx " & $i
        return result

    # Add this tx's outputs to package UTXOs
    for j, output in tx.outputs:
      packageUtxos[OutPoint(txid: txid, vout: uint32(j))] = output

  # Third pass: add all valid transactions to mempool
  for i, tx in txns:
    let txid = txids[i]

    # Skip if already in mempool
    if txid in mp.entries:
      continue

    let weight = weights[i]
    let fee = fees[i]
    let vbytes = float64(weight) / 4.0
    let feeRate = float64(int64(fee)) / vbytes
    let vsizeInt = (weight + 3) div 4

    # Calculate ancestor stats
    let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(tx, fee, weight)
    let (ancestorCount, ancestorSize) = mp.calculateAncestorStats(tx, vsizeInt)

    # Check package limits
    let packageLimitsResult = mp.checkPackageLimits(tx, weight)
    if not packageLimitsResult.isOk:
      result.txResults[i].allowed = false
      result.txResults[i].error = "package limits: " & packageLimitsResult.error
      result.state = pvMempoolError
      result.error = "package limits exceeded for tx " & $i
      return result

    # Check mempool size - evict if needed
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
      ancestorWeight: ancestorWeight,
      ancestorCount: ancestorCount,
      ancestorSize: ancestorSize
    )

    # Add to mempool
    mp.entries[txid] = entry
    mp.currentSize += txSize

    # Track spent outpoints
    for input in tx.inputs:
      mp.spentBy[input.prevOut] = txid

  result.valid = true
  result.state = pvUnset
