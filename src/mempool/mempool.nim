## Transaction mempool
## Manages unconfirmed transactions with fee/size policy, CPFP tracking, and eviction

import std/[tables, algorithm, options, times, sets, math]
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../crypto/secp256k1
import ../script/interpreter
import ./package
import ./standard
import ./cluster
import ../mining/fees
export package, standard

type
  MempoolError* = object of CatchableError

  MempoolEntry* = object
    tx*: Transaction
    txid*: TxId
    wtxid*: TxId            ## Witness transaction ID (BIP141); equals txid for non-segwit txs
    fee*: Satoshi
    weight*: int            ## Transaction weight in weight units
    feeRate*: float64       ## Fee rate in sat/vbyte (fee / (weight/4))
    timeAdded*: Time
    height*: int32          ## Block height when added
    ancestorFee*: Satoshi   ## Total fee of this tx plus all unconfirmed ancestors
    ancestorWeight*: int    ## Total weight of this tx plus all unconfirmed ancestors
    ancestorCount*: int     ## Count of ancestors including self (cached for O(1) checks)
    ancestorSize*: int      ## Total vsize of ancestors including self in vbytes (cached)

  ## Optional caller-supplied knobs for acceptTransaction.  Mirrors a subset of
  ## Bitcoin Core's `ATMPArgs` (validation.cpp:594-) — only the parts that are
  ## exposed via single-tx submission paths (sendrawtransaction, BIP-152, p2p
  ## relay).  Defaults preserve historical nimrod behaviour.
  AtmpArgs* = object
    testAccept*: bool              ## Core ATMPArgs::m_test_accept — run all
                                   ## checks but do NOT add to the mempool.
    bypassLimits*: bool            ## Core ATMPArgs::m_bypass_limits — used for
                                   ## reorg replay; skip min-fee + TRUC limits.
    allowReplacement*: bool        ## Core ATMPArgs::m_allow_replacement —
                                   ## controls bip125-replacement-disallowed.
    allowSiblingEviction*: bool    ## Core ATMPArgs::m_allow_sibling_eviction —
                                   ## TRUC sibling eviction (single-tx only).
    packageFeerates*: bool         ## Core ATMPArgs::m_package_feerates — skip
                                   ## per-tx min-relay check (package will).
    clientMaxFeeRateSatKvB*: float64
                                   ## Core ATMPArgs::m_client_maxfeerate —
                                   ## reject if effective feerate exceeds this
                                   ## (sat/kvB).  <= 0 means "unset".

  AtmpAcceptInfo* = object
    ## Returned for test_accept / package paths so callers can introspect the
    ## same fields Core exposes via MempoolAcceptResult.
    txid*: TxId
    wtxid*: TxId
    vsize*: int
    baseFee*: Satoshi
    modifiedFee*: Satoshi
    replaced*: HashSet[TxId]       ## conflicts evicted by this submission

  Mempool* = ref object
    entries*: Table[TxId, MempoolEntry]
    byWtxid*: Table[TxId, TxId]      ## wtxid -> txid index (BIP141 same-txid-different-witness check)
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
    ## Rolling minimum fee rate (txmempool.cpp:829-859)
    ## Tracks the highest fee rate of evicted chunks so that new txs pay at least
    ## as much as what was evicted.  Decays exponentially after a block is mined.
    rollingMinimumFeeRate*: float64   ## sat/kvB; 0 = no floor; Core: rollingMinimumFeeRate
    blockSinceLastRollingFeeBump*: bool  ## true after block, enables decay; Core: blockSinceLastRollingFeeBump
    lastRollingFeeUpdate*: int64      ## Unix seconds of last decay step; Core: lastRollingFeeUpdate
    incrementalRelayFeeRate*: float64 ## sat/kvB incremental relay fee; Core: m_opts.incremental_relay_feerate
    ## Mempool expiry
    expiryHours*: int       ## Transactions older than this are expired (default 336h = 14 days)
    ## Fee estimator (optional; wired by the node after newFeeEstimator).
    ## When non-nil, acceptTransactionWithArgs calls trackTransaction on success
    ## and removeTransaction calls feeEstimator.removeTransaction on eviction.
    feeEstimator*: FeeEstimator

const
  DefaultMaxMempoolSize* = 300_000_000  ## 300 MB
  DefaultMinFeeRate* = 1.0              ## 1 sat/vbyte minimum
  MaxStandardTxWeight* = 400_000        ## 400K weight units max per tx

  ## Rolling fee constants (Bitcoin Core txmempool.h:212, txmempool.cpp:829-859)
  RollingFeeHalflife* = 60 * 60 * 12   ## 12-hour halflife in seconds (Core: ROLLING_FEE_HALFLIFE)
  DefaultIncrementalRelayFeeSatKvB* = 100.0  ## 100 sat/kvB (Core: DEFAULT_INCREMENTAL_RELAY_FEE, policy/policy.h:48)
  DefaultMempoolExpiryHours* = 336      ## 14 days (Core: DEFAULT_MEMPOOL_EXPIRY_HOURS, kernel/mempool_options.h:23)

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
  DefaultIncrementalRelayFee* = 0.1       ## Incremental relay fee in sat/vbyte
                                          ## (100 sat/kvB ÷ 1000 = 0.1 sat/vB).
                                          ## Matches Core's DEFAULT_INCREMENTAL_RELAY_FEE
                                          ## (policy/policy.h:48 = 100 sat/kvB).
                                          ## FIX-69: was 1.0 sat/vB (10x Core). See W120 BUG-1.

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

proc defaultAtmpArgs*(): AtmpArgs =
  ## Default ATMP args mirroring Bitcoin Core's normal sendrawtransaction path:
  ## replacement allowed, no sibling eviction (only single tx context), no
  ## bypass_limits, no test_accept, no client_maxfeerate.
  AtmpArgs(
    testAccept: false,
    bypassLimits: false,
    allowReplacement: true,
    allowSiblingEviction: true,
    packageFeerates: false,
    clientMaxFeeRateSatKvB: 0.0,
  )

# Forward declarations
proc signalsOptInRBF*(tx: Transaction): bool
proc isRbfOptIn*(mp: Mempool, tx: Transaction): bool
proc evictLowestFee*(mp: Mempool)
proc calculateDescendants*(mp: Mempool, txid: TxId): HashSet[TxId]
proc calculateAncestors*(mp: Mempool, tx: Transaction): HashSet[TxId]
proc trackPackageRemoved*(mp: Mempool, removedFeeRateSatKvB: float64)
proc getMinFee*(mp: Mempool): float64
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
                 clusterSizeLimit: int = DefaultClusterSizeLimit,
                 incrementalRelayFeeRate: float64 = DefaultIncrementalRelayFeeSatKvB,
                 expiryHours: int = DefaultMempoolExpiryHours): Mempool =
  Mempool(
    entries: initTable[TxId, MempoolEntry](),
    byWtxid: initTable[TxId, TxId](),
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
    clusterSizeLimit: clusterSizeLimit,
    rollingMinimumFeeRate: 0.0,
    blockSinceLastRollingFeeBump: false,
    lastRollingFeeUpdate: getTime().toUnix(),
    incrementalRelayFeeRate: incrementalRelayFeeRate,
    expiryHours: expiryHours
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

# ---------------------------------------------------------------------------
# W96 — STANDARD_SCRIPT_VERIFY_FLAGS helper.
#
# Bitcoin Core MemPoolAccept calls CheckInputScripts twice:
#   1. PolicyScriptChecks: STANDARD_SCRIPT_VERIFY_FLAGS (consensus + policy)
#   2. ConsensusScriptChecks: GetBlockScriptFlags(tip) — what the next block
#      will enforce; serves as cache-population.
#
# Previously nimrod ran *only* the consensus pass with `getBlockScriptFlags`
# which silently let policy-only violations into the mempool
# (NULLFAIL, MINIMALDATA, MINIMALIF, LOW_S, CLEANSTACK, STRICTENC,
# WITNESS_PUBKEYTYPE, DISCOURAGE_*).  Reference: policy/policy.h:119-132.
# ---------------------------------------------------------------------------
proc standardScriptVerifyFlags*(consensusFlags: set[ScriptFlags]): set[ScriptFlags] =
  ## Returns STANDARD_SCRIPT_VERIFY_FLAGS = consensus flags ∪ policy-only flags.
  ## See bitcoin-core src/policy/policy.h:119.
  result = consensusFlags
  result.incl(sfStrictEnc)
  result.incl(sfMinimalData)
  result.incl(sfDiscourageUpgradableNops)
  result.incl(sfCleanStack)
  result.incl(sfMinimalIf)
  result.incl(sfNullFail)
  result.incl(sfLowS)
  result.incl(sfDiscourageUpgradableWitnessProgram)
  result.incl(sfWitnessPubkeyType)
  # sfConstScriptCode — not modelled separately in nimrod interpreter (treated
  # as mandatory under BIP-143).
  result.incl(sfDiscourageUpgradableTaprootVersion)
  result.incl(sfDiscourageOpSuccess)
  result.incl(sfDiscourageUpgradablePubkeyType)

# Accept a transaction into the mempool
proc acceptTransactionWithArgs*(mp: Mempool, tx: Transaction,
                                crypto: CryptoEngine,
                                args: AtmpArgs): MempoolResult[AtmpAcceptInfo] =
  ## Validate (and optionally add) a single transaction.  Mirrors Bitcoin Core
  ## MemPoolAccept::AcceptSingleTransactionInternal (validation.cpp:1317-1431),
  ## composed from PreChecks + ReplacementChecks + PolicyScriptChecks +
  ## ConsensusScriptChecks.  Returns AtmpAcceptInfo so callers (RPC test_accept,
  ## package logic) can inspect vsize / fees / replaced txs without needing
  ## another lookup.

  # === PreChecks ===========================================================

  # Compute txid + wtxid.
  let txid = tx.txid()
  let wtxid = tx.wtxid()

  # Basic structural validation (CheckTransaction).
  let basicResult = checkTransaction(tx, mp.params)
  if not basicResult.isOk:
    return err(AtmpAcceptInfo, "invalid transaction: " & $basicResult.error)

  # Coinbase txs cannot enter mempool. validation.cpp:803-804.
  if isCoinbase(tx):
    return err(AtmpAcceptInfo, "coinbase")

  # CVE-2017-12842: reject txs < 65 non-witness bytes. validation.cpp:813-814.
  const MinStandardTxNonwitnessSize = 65
  let nonwitnessSize = serializeLegacy(tx).len
  if nonwitnessSize < MinStandardTxNonwitnessSize:
    return err(AtmpAcceptInfo, "tx-size-small")

  # 400K WU policy limit.
  let weight = calculateWeight(tx)
  if weight > MaxStandardTxWeight:
    return err(AtmpAcceptInfo, "transaction weight " & $weight & " exceeds max " &
               $MaxStandardTxWeight)

  # IsStandardTx (policy/policy.cpp).
  let stdRes = isStandardTx(tx)
  if not stdRes.ok:
    return err(AtmpAcceptInfo, "non-standard tx (" & stdRes.reason & ")")

  # W96 GAP #1: BIP-141 exists-by-wtxid / same-txid-different-wtxid duplicate
  # detection.  Bitcoin Core validation.cpp:823-830 distinguishes:
  #   - exact wtxid match → "txn-already-in-mempool" (same witness data)
  #   - same txid, different wtxid → "txn-same-nonwitness-data-in-mempool"
  # Without this an attacker can flood the mempool with re-witnessed copies
  # of an in-mempool tx (cheap because the txid index doesn't catch them).
  if wtxid in mp.byWtxid:
    return err(AtmpAcceptInfo, "txn-already-in-mempool")
  if txid in mp.entries:
    # Same txid present but wtxid differs → witness was mutated.
    return err(AtmpAcceptInfo, "txn-same-nonwitness-data-in-mempool")

  # IsFinalTx (BIP-113): reject non-final txs at mempool admit.
  # NOTE: Core checks IsFinalTx BEFORE the exists check (validation.cpp:819
  # vs 823).  Order intentionally matches Core so error messages line up
  # with peer rejection-cache expectations.
  let tipHeight = mp.chainState.bestHeight
  let mtp = getMtpForHeight(mp.chainState.db, tipHeight)
  if not isFinalTx(tx, uint32(tipHeight + 1), mtp):
    return err(AtmpAcceptInfo, "non-final")

  # Conflict (RBF candidate) detection.  Track the conflicting outpoints so
  # the txn-already-known check below can distinguish "we already saw this
  # tx, output is in our cache" from "tx is missing inputs".
  # W96 GAP #2: respect allow_replacement — Core returns
  # "bip125-replacement-disallowed" when conflict exists but caller set
  # m_allow_replacement=false (e.g., package-RBF disabled context).
  let conflicts = mp.findConflicts(tx)
  if conflicts.len > 0 and not args.allowReplacement:
    return err(AtmpAcceptInfo, "bip125-replacement-disallowed")
  var conflictsToRemove = initHashSet[TxId]()

  # Walk inputs.  Three failure modes Core distinguishes:
  #   - txn-already-known   : any output of this tx already cached (UTXO set)
  #   - bad-txns-inputs-missingorspent : input prevout absent
  #   - bad-txns-premature-spend-of-coinbase (here folded into the coinbase
  #     maturity check)
  for input in tx.inputs:
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isNone:
      if input.prevOut.txid notin mp.entries:
        # W96 GAP #3: txn-already-known — if our coins cache already has
        # ANY output of this txid, it means we accepted the same tx
        # previously and the parent isn't really missing.  Core
        # validation.cpp:858-864.
        var alreadyKnown = false
        for vout in 0 ..< tx.outputs.len:
          if mp.chainState.getUtxo(OutPoint(txid: txid, vout: uint32(vout))).isSome:
            alreadyKnown = true
            break
        if alreadyKnown:
          return err(AtmpAcceptInfo, "txn-already-known")
        return err(AtmpAcceptInfo, "bad-txns-inputs-missingorspent: " & $input.prevOut.txid)
      let parentEntry = mp.entries[input.prevOut.txid]
      if int(input.prevOut.vout) >= parentEntry.tx.outputs.len:
        return err(AtmpAcceptInfo, "bad-txns-inputs-missingorspent: bad vout " &
                   $input.prevOut.vout & " for mempool parent")
    else:
      let entry = utxo.get()
      if entry.isCoinbase:
        let age = tipHeight - entry.height
        if age < int32(mp.params.coinbaseMaturity):
          return err(AtmpAcceptInfo, "bad-txns-premature-spend-of-coinbase: age=" &
                     $age & " required=" & $mp.params.coinbaseMaturity)

  # BIP-68 sequence locks (CheckSequenceLocksAtTip, validation.cpp:887).
  proc lookupForSeqLock(op: OutPoint): Option[UtxoEntry] =
    let confirmed = mp.chainState.getUtxo(op)
    if confirmed.isSome:
      return confirmed
    if op.txid in mp.entries:
      return some(UtxoEntry(output: TxOut(), height: int32(tipHeight + 1), isCoinbase: false))
    none(UtxoEntry)

  proc getMtpAt(h: int32): uint32 = getMtpForHeight(mp.chainState.db, h)

  let seqResult = checkSequenceLocksForTx(
    tx, lookupForSeqLock, tipHeight + 1, mtp, getMtpAt, mp.params)
  if not seqResult.isOk:
    return err(AtmpAcceptInfo, "non-BIP68-final: " & $seqResult.error)

  # CheckTxInputs — amounts in-range, accumulated MoneyRange, fee computation.
  # nimrod's calculateFee performs all three but does not surface the
  # individual error strings; preserve the message Core uses (validation.cpp
  # CheckTxInputs paths feed back through the state object).
  let feeOpt = calculateFee(tx, mp)
  if feeOpt.isNone:
    return err(AtmpAcceptInfo, "bad-txns-in-belowout / bad-txns-fee-outofrange")
  let fee = feeOpt.get()

  # IsWitnessStandard (policy/policy.cpp:265-351).  Core orders this AFTER
  # CheckTxInputs because it walks the m_view cache for the prevouts.
  let witStdRes = isWitnessStandard(tx, proc(input: TxIn): seq[byte] =
    let utxo = mp.chainState.getUtxo(input.prevOut)
    if utxo.isSome:
      utxo.get().output.scriptPubKey
    else:
      let parentEntry = mp.entries[input.prevOut.txid]
      parentEntry.tx.outputs[input.prevOut.vout].scriptPubKey
  )
  if not witStdRes.ok:
    return err(AtmpAcceptInfo, "bad-witness-nonstandard: " & witStdRes.reason)

  # W96 GAP #4: ValidateInputsStandardness — Bitcoin Core policy/policy.cpp:214
  # enforces per-input "input non-standard" rules.  Two consequences relevant
  # in nimrod:
  #   (a) Bare NONSTANDARD inputs are rejected ("input X script unknown").
  #   (b) WITNESS_UNKNOWN inputs (well-formed witness program of unknown
  #       version, length 2..40 with version 2..16 or version 1 len != 32)
  #       are flagged early as bad-txns-nonstandard-inputs.
  #   (c) P2SH redeemscript sigops cap (MAX_P2SH_SIGOPS=15) — refuse if the
  #       redeemscript contains more than 15 sigops to prevent quadratic
  #       sighashing.
  for inputIdx, input in tx.inputs:
    var prevSpk: seq[byte]
    let confirmed = mp.chainState.getUtxo(input.prevOut)
    if confirmed.isSome:
      prevSpk = confirmed.get().output.scriptPubKey
    else:
      let parentEntry = mp.entries[input.prevOut.txid]
      prevSpk = parentEntry.tx.outputs[int(input.prevOut.vout)].scriptPubKey
    let kind = classifyStdTxout(prevSpk)
    if kind == stxNonStandard:
      return err(AtmpAcceptInfo,
                 "bad-txns-nonstandard-inputs: input " & $inputIdx & " script unknown")
    if kind == stxWitnessUnknown:
      return err(AtmpAcceptInfo,
                 "bad-txns-nonstandard-inputs: input " & $inputIdx & " witness program is undefined")
    if kind == stxP2SH:
      # Parse scriptSig as a push-only sequence.  Last push is the redeemScript.
      let pushed = evalScriptSigPushes(input.scriptSig)
      if not pushed.ok:
        return err(AtmpAcceptInfo,
                   "bad-txns-nonstandard-inputs: p2sh scriptsig malformed (input " &
                   $inputIdx & ")")
      if pushed.stack.len == 0:
        return err(AtmpAcceptInfo,
                   "bad-txns-nonstandard-inputs: input " & $inputIdx &
                   " P2SH redeemscript missing")
      # MAX_P2SH_SIGOPS = 15; mirrors Core consensus/consensus.h.
      let redeem = pushed.stack[^1]
      const MaxP2shSigops = 15
      var sigops = 0
      var i = 0
      var lastOp: uint8 = 0
      while i < redeem.len:
        let op = redeem[i]
        if op == 0xac or op == 0xad:  # OP_CHECKSIG / OP_CHECKSIGVERIFY
          inc sigops
          inc i
          lastOp = op
        elif op == 0xae or op == 0xaf:  # OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
          # Accurate variant: previous opcode 0x51..0x60 (OP_1..OP_16) gives N.
          if lastOp >= 0x51 and lastOp <= 0x60:
            sigops += int(lastOp - 0x50)
          else:
            sigops += 20  # MAX_PUBKEYS_PER_MULTISIG fallback
          inc i
          lastOp = op
        elif op >= 0x01 and op <= 0x4b:
          # Direct push
          i += 1 + int(op)
          lastOp = op
        elif op == 0x4c and i + 1 < redeem.len:
          let len1 = int(redeem[i + 1])
          i += 2 + len1
          lastOp = op
        elif op == 0x4d and i + 2 < redeem.len:
          let len2 = int(redeem[i + 1]) or (int(redeem[i + 2]) shl 8)
          i += 3 + len2
          lastOp = op
        elif op == 0x4e and i + 4 < redeem.len:
          let len4 = int(redeem[i + 1]) or (int(redeem[i + 2]) shl 8) or
                     (int(redeem[i + 3]) shl 16) or (int(redeem[i + 4]) shl 24)
          i += 5 + len4
          lastOp = op
        else:
          inc i
          lastOp = op
      if sigops > MaxP2shSigops:
        return err(AtmpAcceptInfo,
                   "bad-txns-nonstandard-inputs: p2sh redeemscript sigops exceed limit (input " &
                   $inputIdx & ": " & $sigops & " > " & $MaxP2shSigops & ")")

  # Sigop cost (validation.cpp:908).
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
      return err(AtmpAcceptInfo, "bad-txns-too-many-sigops")

  # W96 GAP #5: modified-fee aware vsize.  Core computes m_modified_fees from
  # m_base_fees plus PrioritiseTransaction deltas (Core validation.cpp:930).
  # nimrod has no PrioritiseTransaction, so modified == base — but expose the
  # value separately so the per-tx max_feerate guard below behaves the same
  # as Core if the field is ever wired up.
  let baseFee = fee
  let modifiedFee = fee
  let vbytes = float64(weight) / 4.0
  let vsizeInt = (weight + 3) div 4
  let feeRate = float64(int64(modifiedFee)) / vbytes
  let feeRateSatKvB = feeRate * 1000.0  # convert sat/vB -> sat/kvB (Core unit)

  # PreCheckEphemeralTx — relay-only.  Core validation.cpp:935 gates this on
  # require_standard.  nimrod always runs in require_standard=true equivalent.
  let ephemeralPreCheck = preCheckEphemeralTx(tx, baseFee, modifiedFee)
  if not ephemeralPreCheck.isOk:
    return err(AtmpAcceptInfo, ephemeralPreCheck.error)

  # W96 GAP #6: min-fee gate honours bypass_limits + package_feerates.
  # validation.cpp:948: `if (!bypass_limits && !args.m_package_feerates &&
  # !CheckFeeRate(...)) return false;`
  if not args.bypassLimits and not args.packageFeerates:
    let rollingFloor = mp.getMinFee()
    let effectiveMinFeeRate = max(mp.minFeeRate, rollingFloor)
    if feeRate < effectiveMinFeeRate:
      return err(AtmpAcceptInfo, "mempool min fee not met: feerate " & $feeRate &
                 " < min " & $effectiveMinFeeRate &
                 " (rolling floor: " & $rollingFloor & ")")

  # W96 GAP #7: client_maxfeerate (validation.cpp:1368).
  # Core compares the effective feerate against the caller-supplied max
  # (e.g., -maxtxfee on sendrawtransaction).  Units are sat/kvB.
  if args.clientMaxFeeRateSatKvB > 0.0 and feeRateSatKvB > args.clientMaxFeeRateSatKvB:
    return err(AtmpAcceptInfo,
               "max feerate exceeded: tx feerate " & $feeRateSatKvB &
               " sat/kvB > caller max " & $args.clientMaxFeeRateSatKvB & " sat/kvB")

  # W96 GAP #8: bypass_limits also disables TRUC checks (validation.cpp:954).
  var trucSiblingToEvict: Option[TxId] = none(TxId)
  if not args.bypassLimits:
    let trucResult = mp.checkSingleTrucRules(tx, weight, conflicts)
    if not trucResult.isOk:
      return err(AtmpAcceptInfo, "TRUC-violation: " & trucResult.error)
    if trucResult.siblingToEvict.isSome:
      let siblingTxid = trucResult.siblingToEvict.get()
      if not args.allowSiblingEviction or not args.allowReplacement:
        return err(AtmpAcceptInfo, "TRUC-violation: sibling-eviction-disallowed")
      let siblingEvictionResult = mp.checkTrucSiblingEviction(tx, modifiedFee, siblingTxid)
      if not siblingEvictionResult.isOk:
        return err(AtmpAcceptInfo, "TRUC-violation: " & siblingEvictionResult.error)
      trucSiblingToEvict = some(siblingTxid)
      conflictsToRemove.incl(siblingTxid)

  # === ReplacementChecks ====================================================
  # (Core's MemPoolAccept::ReplacementChecks, validation.cpp:984.)

  if conflicts.len > 0:
    # FIX-69 (W120 BUG-2): pass mempool's configured incrementalRelayFeeRate
    # (sat/kvB → sat/vB via /1000) instead of relying on the static default.
    # Core: validation.cpp:1011 passes m_pool.m_opts.incremental_relay_feerate.
    let incrementalRelayFeeSatVb = mp.incrementalRelayFeeRate / 1000.0
    let rbfResult = mp.checkRbfRules(tx, modifiedFee, vsizeInt, conflicts,
                                     incrementalRelayFeeSatVb)
    if not rbfResult.isOk:
      return err(AtmpAcceptInfo, "replacement-failed: " & rbfResult.error)
    for c in rbfResult.value:
      conflictsToRemove.incl(c)

    # W96 GAP #9: EntriesAndTxidsDisjoint for single-tx submission.
    # validation.cpp:1349-1361 — after collecting `all_conflicts`, Core
    # asserts that the tx's ancestor set is disjoint from the to-be-replaced
    # set.  Otherwise the tx would depend on something it conflicts with
    # (consensus-bad inconsistency).  This is *additional* to Rule #2 (which
    # checks direct inputs); the ancestor-disjoint check covers transitive
    # spend chains.
    let txAncestors = mp.calculateAncestors(tx)
    for ancestor in txAncestors:
      if ancestor in conflictsToRemove:
        return err(AtmpAcceptInfo,
                   "bad-txns-spends-conflicting-tx: ancestor " & $ancestor &
                   " is also being replaced")

  # === Cluster size guard ===================================================
  # Core's AcceptSingleTransactionInternal:1342 — even when no RBF, the new
  # tx (+ conflicts staged) must not push any cluster past the size limit.
  # checkPackageLimits handles cluster count + vsize for the new entry.
  # Defer the call until after conflicts are staged so the cluster shape is
  # accurate.

  # === PolicyScriptChecks ===================================================
  # Run with STANDARD_SCRIPT_VERIFY_FLAGS.  validation.cpp:1135.
  let consensusFlags = getBlockScriptFlags(mp.chainState.bestHeight, mp.params)
  let policyFlags = standardScriptVerifyFlags(consensusFlags)

  proc verifyAt(flags: set[ScriptFlags]): MempoolResult[void] =
    for inputIdx, input in tx.inputs:
      var scriptPubKey: seq[byte]
      var amount: Satoshi
      let utxo = mp.chainState.getUtxo(input.prevOut)
      if utxo.isSome:
        scriptPubKey = utxo.get().output.scriptPubKey
        amount = utxo.get().output.value
      else:
        let parentEntry = mp.entries[input.prevOut.txid]
        let parentOutput = parentEntry.tx.outputs[input.prevOut.vout]
        scriptPubKey = parentOutput.scriptPubKey
        amount = parentOutput.value
      var witness: seq[seq[byte]] = @[]
      if inputIdx < tx.witnesses.len:
        witness = tx.witnesses[inputIdx]
      let verified = verifyScript(
        input.scriptSig, scriptPubKey, tx, inputIdx, amount, flags, witness)
      if not verified:
        return MempoolResult[void](isOk: false,
          error: "script verification failed for input " & $inputIdx)
    MempoolResult[void](isOk: true)

  let policyVer = verifyAt(policyFlags)
  if not policyVer.isOk:
    # W96 GAP #10: TX_WITNESS_STRIPPED detection (validation.cpp:1148).
    # If the tx HAS NO witness data but spends a non-anchor witness program,
    # this is almost certainly witness-stripped relay corruption; surface a
    # distinct error so p2p rejection caching matches Core.
    var anyWitnessSpend = false
    var hasWitness = false
    for w in tx.witnesses:
      if w.len > 0:
        hasWitness = true
        break
    if not hasWitness:
      for input in tx.inputs:
        let utxo = mp.chainState.getUtxo(input.prevOut)
        var spk: seq[byte]
        if utxo.isSome:
          spk = utxo.get().output.scriptPubKey
        elif input.prevOut.txid in mp.entries:
          spk = mp.entries[input.prevOut.txid].tx.outputs[input.prevOut.vout].scriptPubKey
        let kind = classifyStdTxout(spk)
        if kind in {stxP2WPKH, stxP2WSH, stxWitnessUnknown}:
          # Note: P2TR (witness v1, BIP-340) is anchor-spendable for some
          # paths (key-spend with empty witness is invalid; treat as
          # witness-stripped also).
          anyWitnessSpend = true
          break
        if kind == stxP2TR:
          anyWitnessSpend = true
          break
    if anyWitnessSpend:
      return err(AtmpAcceptInfo, "witness-stripped: " & policyVer.error)
    return err(AtmpAcceptInfo, "non-mandatory-script-verify-flag: " & policyVer.error)

  # === ConsensusScriptChecks ================================================
  # Re-verify with the current block's flags (consensus only).  validation.cpp
  # :1158.  If this differs from policy verification (e.g., a policy-flag
  # bug accepted a tx that consensus rejects), we have a serious bug; Core
  # logs "BUG! PLEASE REPORT THIS!" and asserts.  Here we surface a hard
  # error.
  let consensusVer = verifyAt(consensusFlags)
  if not consensusVer.isOk:
    return err(AtmpAcceptInfo,
               "mandatory-script-verify-flag-failed: " & consensusVer.error)

  # === Submission ===========================================================

  # Stage conflict removal BEFORE checkPackageLimits so cluster shape is
  # post-replacement (Core's changeset behaviour: validation.cpp:1196-1239).
  if conflictsToRemove.len > 0:
    mp.removeConflicts(conflictsToRemove)

  # Package + cluster limits.
  let packageLimitsResult = mp.checkPackageLimits(tx, weight)
  if not packageLimitsResult.isOk:
    return err(AtmpAcceptInfo, "too-large-cluster: " & packageLimitsResult.error)

  let (ancestorFee, ancestorWeight) = mp.calculateAncestorFeesAndWeight(tx, modifiedFee, weight)
  let (ancestorCount, ancestorSize) = mp.calculateAncestorStats(tx, vsizeInt)

  # Standalone-ephemeral guard (validation.cpp:1375 — CheckEphemeralSpends).
  # A single-tx submission with an ephemeral dust output cannot satisfy the
  # "must be spent by a child in the same package" invariant, so reject.
  if hasEphemeralDust(tx):
    return err(AtmpAcceptInfo,
               "ephemeral-dust-must-be-spent: standalone tx has ephemeral dust output but no child spending it; use package relay")

  let info = AtmpAcceptInfo(
    txid: txid,
    wtxid: wtxid,
    vsize: vsizeInt,
    baseFee: baseFee,
    modifiedFee: modifiedFee,
    replaced: conflictsToRemove,
  )

  # W96 GAP #11: m_test_accept — return AFTER all checks pass but BEFORE
  # any state mutation (validation.cpp:1388).
  if args.testAccept:
    return ok[AtmpAcceptInfo](info)

  # Check mempool size limit - evict if needed.
  let txSize = serialize(tx).len
  while mp.currentSize + txSize > mp.maxSize:
    mp.evictLowestFee()
    if mp.entries.len == 0:
      break

  # W96 GAP #12: post-eviction "mempool full" check (validation.cpp:1402-
  # 1406).  After TrimToSize, our own tx may have been evicted (its feerate
  # is no longer above the new rolling floor).  Core returns
  # TX_RECONSIDERABLE / "mempool full" so the package layer can retry.
  let rollingFloorAfter = mp.getMinFee()
  let effectiveMinFeeRateAfter = max(mp.minFeeRate, rollingFloorAfter)
  if not args.bypassLimits and feeRate < effectiveMinFeeRateAfter:
    return err(AtmpAcceptInfo,
               "mempool full: post-eviction floor " & $effectiveMinFeeRateAfter &
               " > tx feerate " & $feeRate)

  let entry = MempoolEntry(
    tx: tx,
    txid: txid,
    wtxid: wtxid,
    fee: baseFee,
    weight: weight,
    feeRate: feeRate,
    timeAdded: getTime(),
    height: mp.chainState.bestHeight,
    ancestorFee: ancestorFee,
    ancestorWeight: ancestorWeight,
    ancestorCount: ancestorCount,
    ancestorSize: ancestorSize
  )

  mp.entries[txid] = entry
  mp.byWtxid[wtxid] = txid
  mp.currentSize += txSize

  for input in tx.inputs:
    mp.spentBy[input.prevOut] = txid

  # BUG-1 fix (W114 FIX-47): wire fee estimator on successful accept.
  # feeRate here is sat/vbyte; bestHeight is the chain tip height at entry time.
  if mp.feeEstimator != nil:
    mp.feeEstimator.trackTransaction(txid, feeRate, mp.chainState.bestHeight)

  ok[AtmpAcceptInfo](info)

# Convenience wrapper for the historical signature — preserves callers that
# expect `MempoolResult[TxId]` and don't care about the extra info.
proc acceptTransaction*(mp: Mempool, tx: Transaction,
                        crypto: CryptoEngine,
                        args: AtmpArgs = defaultAtmpArgs()): MempoolResult[TxId] =
  let res = acceptTransactionWithArgs(mp, tx, crypto, args)
  if res.isOk:
    return ok[TxId](res.value.txid)
  return err(TxId, res.error)

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

  # W96: drop wtxid index entry as well (BIP141 same-txid-different-witness
  # exists-check requires keeping byWtxid in sync with entries).
  if mp.byWtxid.getOrDefault(entry.wtxid, TxId(default(array[32, byte]))) == txid:
    mp.byWtxid.del(entry.wtxid)
  mp.entries.del(txid)

  # BUG-12 fix (W114 FIX-47): notify fee estimator of eviction/removal.
  if mp.feeEstimator != nil:
    mp.feeEstimator.removeTransaction(txid)

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
  ## Remove transactions that were included in a block.
  ## Also removes any transactions that spend outputs created by block txs
  ## (double-spend conflicts).
  ## Sets blockSinceLastRollingFeeBump = true so GetMinFee decays the rolling
  ## floor after the next update interval.
  ## Core reference: txmempool.cpp:426-427 (lastRollingFeeUpdate + blockSinceLastRollingFeeBump
  ## reset happens at the end of CTxMemPool::removeForBlock).

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

  # After block removal: reset rolling fee decay timer so fee floor can decay.
  # Core sets these at the end of removeForBlock (txmempool.cpp:426-427).
  mp.lastRollingFeeUpdate = getTime().toUnix()
  mp.blockSinceLastRollingFeeBump = true

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

# ============================================================================
# Rolling Minimum Fee Rate — CTxMemPool::GetMinFee / trackPackageRemoved
# Bitcoin Core: txmempool.cpp:829-859
# ============================================================================

proc trackPackageRemoved*(mp: Mempool, removedFeeRateSatKvB: float64) =
  ## Bump the rolling minimum fee when a package is evicted by TrimToSize.
  ## Core reference: txmempool.cpp:853-859
  ##
  ## Gate: only bump if the removed rate exceeds the current floor.
  ## Sets blockSinceLastRollingFeeBump = false so decay is paused until
  ## the next block is mined.
  if removedFeeRateSatKvB > mp.rollingMinimumFeeRate:
    mp.rollingMinimumFeeRate = removedFeeRateSatKvB
    mp.blockSinceLastRollingFeeBump = false

proc getMinFee*(mp: Mempool): float64 =
  ## Compute the current minimum fee rate for mempool admission (sat/kvB).
  ## Mirrors CTxMemPool::GetMinFee(sizelimit), txmempool.cpp:829-851.
  ##
  ## When no eviction has bumped the floor (rollingMinimumFeeRate == 0) OR
  ## a block has not been mined since the last bump, return the raw rolling
  ## value immediately (no decay yet).
  ##
  ## Once blockSinceLastRollingFeeBump is true the fee decays exponentially
  ## with a 12-hour halflife.  The halflife is accelerated when the pool is
  ## less than half-full (÷2) or less than quarter-full (÷4) — this lets
  ## the floor drop faster when there's plenty of room.
  ##
  ## The floor is cleared to zero when it falls below half of the configured
  ## incrementalRelayFeeRate.  The returned value is always at least
  ## incrementalRelayFeeRate when non-zero.
  if not mp.blockSinceLastRollingFeeBump or mp.rollingMinimumFeeRate == 0:
    # No block yet or no eviction floor — return raw value as sat/vbyte
    return mp.rollingMinimumFeeRate / 1000.0

  let now = getTime().toUnix()
  if now > mp.lastRollingFeeUpdate + 10:
    var halflife = float64(RollingFeeHalflife)
    # Accelerate decay when pool is far below its size limit
    if mp.currentSize < mp.maxSize div 4:
      halflife = halflife / 4.0
    elif mp.currentSize < mp.maxSize div 2:
      halflife = halflife / 2.0

    let elapsed = float64(now - mp.lastRollingFeeUpdate)
    mp.rollingMinimumFeeRate = mp.rollingMinimumFeeRate / pow(2.0, elapsed / halflife)
    mp.lastRollingFeeUpdate = now

    # Clear floor when it drops below half of incrementalRelayFeeRate
    if mp.rollingMinimumFeeRate < mp.incrementalRelayFeeRate / 2.0:
      mp.rollingMinimumFeeRate = 0.0
      return 0.0

  # Return max(rollingMinimumFeeRate, incrementalRelayFeeRate) in sat/vbyte
  # (rolling fee is stored in sat/kvB; divide by 1000 for sat/vbyte)
  let rollingVbyte = mp.rollingMinimumFeeRate / 1000.0
  let incrementalVbyte = mp.incrementalRelayFeeRate / 1000.0
  max(rollingVbyte, incrementalVbyte)

# Evict the package (tx + all descendants) with the lowest combined fee rate.
# Mirrors CTxMemPool::TrimToSize logic: evict the "worst chunk" (lowest
# combined/chunk feerate considering all descendants), call trackPackageRemoved
# to bump the rolling floor, then remove all of them.
# Core reference: txmempool.cpp:861-911.
#
# Crucially, Core evaluates each "chunk" (root tx + all descendants) as a
# unit when deciding which package to evict.  A low-rate parent that has a
# high-fee CPFP child is treated as a single package whose rate is the
# combined (totalFee / totalVsize).  This prevents incorrectly evicting a
# parent that a child is bumping via CPFP.
proc evictLowestFee*(mp: Mempool) =
  ## Remove the package (tx + all descendants) with the lowest combined fee rate.
  ## Calls trackPackageRemoved so subsequent txs must pay at least as much.

  if mp.entries.len == 0:
    return

  # For each "root" transaction (one with no in-mempool parents), compute the
  # combined feerate of the root + all its descendants.  Select the root whose
  # package has the lowest combined rate.
  #
  # We define a "root" as any tx that is not spent by another mempool tx —
  # i.e. it has no in-mempool ancestor.
  var lowestRootTxid: TxId
  var lowestPackageRate = float64.high
  var foundRoot = false

  for txid, entry in mp.entries:
    # Check if this tx has any in-mempool ancestors (parents)
    var hasParent = false
    for input in entry.tx.inputs:
      if input.prevOut.txid in mp.entries:
        hasParent = true
        break

    if hasParent:
      continue  # Not a root

    # Compute combined feerate of root + all descendants
    let descendants = mp.calculateDescendants(txid)
    var chunkFee = int64(entry.fee)
    var chunkWeight = entry.weight
    for descTxid in descendants:
      if descTxid in mp.entries:
        let e = mp.entries[descTxid]
        chunkFee += int64(e.fee)
        chunkWeight += e.weight

    let chunkVbytes = float64(chunkWeight) / 4.0
    let packageRate = if chunkVbytes > 0:
      float64(chunkFee) / chunkVbytes
    else:
      0.0

    if packageRate < lowestPackageRate:
      lowestPackageRate = packageRate
      lowestRootTxid = txid
      foundRoot = true

  if not foundRoot:
    # Fallback: no rootless tx found (all txs have parents — should not happen
    # in a well-formed mempool, but handle it gracefully by picking the overall
    # lowest individual fee rate entry).
    for txid, entry in mp.entries:
      if entry.feeRate < lowestPackageRate:
        lowestPackageRate = entry.feeRate
        lowestRootTxid = txid
        foundRoot = true

  if not foundRoot or mp.entries.len == 0:
    return

  # Collect the root and all its descendants
  let descendants = mp.calculateDescendants(lowestRootTxid)

  # Compute the effective fee rate of the chunk being removed (sat/kvB).
  # This is what we pass to trackPackageRemoved (+ incrementalRelayFeeRate).
  var chunkFee = int64(mp.entries[lowestRootTxid].fee)
  var chunkWeight = mp.entries[lowestRootTxid].weight
  for descTxid in descendants:
    if descTxid in mp.entries:
      let e = mp.entries[descTxid]
      chunkFee += int64(e.fee)
      chunkWeight += e.weight

  let chunkVbytes = float64(chunkWeight) / 4.0
  let removedRateSatKvB = if chunkVbytes > 0:
    float64(chunkFee) / chunkVbytes * 1000.0
  else:
    0.0

  # Bump rolling floor: evicted rate + incrementalRelayFeeRate
  # Core: removed += m_opts.incremental_relay_feerate; trackPackageRemoved(removed)
  mp.trackPackageRemoved(removedRateSatKvB + mp.incrementalRelayFeeRate)

  # Remove the root and all its descendants.
  var toRemove: seq[TxId]
  for descTxid in descendants:
    toRemove.add(descTxid)
  toRemove.add(lowestRootTxid)

  for txid in toRemove:
    mp.removeTransaction(txid, evictEphemeral = false)

# Select transactions for a new block
proc selectTransactionsForBlock*(mp: Mempool, maxWeight: int = MaxBlockWeight): seq[Transaction] =
  ## Select transactions for block template (greedy by ancestor fee rate)
  let entries = mp.getTransactionsByFeeRate(maxWeight)
  for entry in entries:
    result.add(entry.tx)

# Expire old transactions and their descendants.
# Core reference: txmempool.cpp:811-827 — Expire() calls CalculateDescendants
# on each expired tx and removes the whole stage (expired + all descendants).
proc expire*(mp: Mempool, maxAgeOverride: int = -1) =
  ## Remove transactions older than the configured expiry (default 336 hours = 14 days).
  ## Also removes all descendants of expired transactions.
  ## maxAgeOverride: if >= 0, override expiryHours for this call (for testing).
  ## Core reference: CTxMemPool::Expire, txmempool.cpp:811-827.
  let hours = if maxAgeOverride >= 0: maxAgeOverride else: mp.expiryHours
  let cutoff = getTime() - initDuration(hours = hours)

  # Collect directly-expired txids
  var directlyExpired: seq[TxId]
  for txid, entry in mp.entries:
    if entry.timeAdded < cutoff:
      directlyExpired.add(txid)

  # For each expired tx, also collect all descendants (they must go too).
  # Use a set to deduplicate across multiple expired roots.
  var toRemove: HashSet[TxId]
  for txid in directlyExpired:
    toRemove.incl(txid)
    let descendants = mp.calculateDescendants(txid)
    for descTxid in descendants:
      toRemove.incl(descTxid)

  for txid in toRemove:
    if txid in mp.entries:
      mp.removeTransaction(txid, evictEphemeral = false)

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
  ## Rule #8 — ImprovesFeerateDiagram (Core 27+): replacement must strictly improve feerate diagram.

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

  # Rule #8 (ImprovesFeerateDiagram, Core 27+): the replacement must strictly improve
  # the feerate diagram vs. the evicted set.
  # Reference: Bitcoin Core src/policy/rbf.cpp ImprovesFeerateDiagram() (line 127-140);
  # src/util/feefrac.cpp CompareChunks (strict-gt — equal-feerate ties REJECT).
  #
  # FIX-79 (W120 #7 dead-helper closure): delegate to the cluster-aware
  # validateRbfDiagram in cluster.nim. We build a TRANSIENT ClusterManager
  # populated with each direct conflict + its in-mempool ancestors AND its
  # full descendant chain (everything in `allConflicts`). Edges are wired
  # from mp.spentBy / mp.entries so the simulated linearization preserves
  # CPFP / parent-child topology and matches Core's cluster-aware behaviour.
  block:
    var cm = newClusterManager()
    # Collect the universe of txids whose topology matters for this RBF:
    #  - every directly conflicting tx + every descendant (allConflicts)
    #  - every in-mempool ancestor of each conflicting tx (so CPFP /
    #    chain context is preserved when validateRbfDiagram simulates
    #    removing the conflicts)
    var universe = initHashSet[TxId]()
    for txid in allConflicts:
      universe.incl(txid)
    for conflictTxid in conflicts:
      if conflictTxid in mp.entries:
        let conflictTx = mp.entries[conflictTxid].tx
        for ancTxid in mp.calculateAncestors(conflictTx):
          universe.incl(ancTxid)
    # Add each tx to the transient cluster manager in a topological order
    # (parents before children). Since `addTransaction` infers cluster
    # membership from already-present parent txids, we iterate until every
    # tx whose parents are present has been added.
    var pending: seq[TxId]
    for txid in universe:
      pending.add(txid)
    var added = initHashSet[TxId]()
    # Bounded passes — universe.len is at most MaxReplacementCandidates +
    # ancestor count, well below any pathological loop bound.
    for _ in 0 ..< (universe.len + 1):
      if pending.len == 0:
        break
      var nextPending: seq[TxId]
      for txid in pending:
        if txid notin mp.entries:
          continue
        let entry = mp.entries[txid]
        # Determine in-universe parents (only edges that survive within the
        # transient cluster contribute to the diagram).
        var parents: seq[TxId]
        var allParentsReady = true
        for input in entry.tx.inputs:
          let parentTxid = input.prevOut.txid
          if parentTxid in universe:
            if parentTxid notin added:
              allParentsReady = false
              break
            parents.add(parentTxid)
        if not allParentsReady:
          nextPending.add(txid)
          continue
        let vsize = (entry.weight + 3) div 4
        if vsize <= 0:
          added.incl(txid)
          continue
        discard cm.addTransaction(txid, int64(entry.fee), vsize, parents)
        added.incl(txid)
      if nextPending.len == pending.len:
        # No progress (cycle or missing parent edge) — bail out of the loop
        # and let validateRbfDiagram work with what we managed to add.
        break
      pending = nextPending
    # Replacement's parents in the universe (in-mempool ancestors of the
    # new tx that aren't being evicted).
    var replacementParents: seq[TxId]
    for input in tx.inputs:
      let parentTxid = input.prevOut.txid
      if parentTxid in universe and parentTxid notin allConflicts:
        replacementParents.add(parentTxid)
    let conflictTxidsSeq = block:
      var s: seq[TxId]
      for txid in allConflicts: s.add(txid)
      s
    let diagRes = cm.validateRbfDiagram(conflictTxidsSeq,
                                        int64(txFee), txVsize,
                                        replacementParents)
    # Strict-gt: validateRbfDiagram returns Ok(true) only when the new
    # diagram is dcrBetter (strictly improves at some point with no chunk
    # worse). Equal-feerate ties resolve to dcrEquivalent → Ok(false) →
    # REJECT, matching Core's CompareChunks std::is_gt semantic.
    if not diagRes.isOk or not diagRes.value:
      return err(HashSet[TxId], "rejecting replacement: insufficient feerate: does not improve feerate diagram")

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

  # Check fee rate policy — must pass max(minFeeRate, rollingMinFee) gate.
  let pkgRollingFloor = mp.getMinFee()
  let pkgEffectiveMin = max(mp.minFeeRate, pkgRollingFloor)

  # When using package feerates, the combined package rate must meet the minimum
  if usePackageFeerates:
    if packageFeerate < pkgEffectiveMin:
      result.state = pvPolicy
      result.error = "package fee rate " & $packageFeerate & " below minimum " & $pkgEffectiveMin
      return result
  else:
    # Check individual fee rates
    for i in 0 ..< txns.len:
      if result.txResults[i].allowed:
        let individualRate = float64(int64(fees[i])) / float64((weights[i] + 3) div 4)
        if individualRate < pkgEffectiveMin:
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
    let wtxid = tx.wtxid()
    let entry = MempoolEntry(
      tx: tx,
      txid: txid,
      wtxid: wtxid,
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
    mp.byWtxid[wtxid] = txid
    mp.currentSize += txSize

    # Track spent outpoints
    for input in tx.inputs:
      mp.spentBy[input.prevOut] = txid

  result.valid = true
  result.state = pvUnset
