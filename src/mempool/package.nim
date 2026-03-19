## Package relay validation
## Allows submitting packages of related transactions for CPFP fee bumping
## Reference: Bitcoin Core policy/packages.cpp and validation.cpp

import std/[tables, algorithm, options, sets]
import ../primitives/[types, serialize]
import ../crypto/hashing

type
  PackageError* = object of CatchableError

  PackageValidationResult* = enum
    pvUnset          ## Initial state, not yet rejected
    pvPolicy         ## Package structure invalid (limits, sorting)
    pvTx             ## One or more transactions invalid
    pvMempoolError   ## Mempool logic error

  TxResult* = object
    txid*: TxId
    wtxid*: TxId
    allowed*: bool
    vsize*: int
    fees*: Satoshi
    error*: string

  PackageResult* = object
    valid*: bool
    state*: PackageValidationResult
    error*: string
    txResults*: seq[TxResult]
    packageFeerate*: float64  ## sat/vbyte

  ## Package to be validated - tracks sender info for misbehavior scoring
  PackageToValidate* = object
    txns*: seq[Transaction]
    senders*: seq[int]  ## Peer ID that sent each transaction

const
  ## Maximum number of transactions in a package
  MaxPackageCount* = 25

  ## Maximum weight of all transactions in a package (in weight units)
  ## Must be >= MAX_STANDARD_TX_WEIGHT (400K WU)
  MaxPackageWeight* = 404_000

  ## Maximum package size in virtual bytes (weight / 4)
  MaxPackageSizeKvB* = 101

  ## Maximum package size in vbytes
  MaxPackageSize* = MaxPackageSizeKvB * 1000  ## 101,000 vbytes

  ## TRUC (v3) policy constants (BIP-431)
  ## These mirror the constants in mempool.nim - keep in sync
  PackageTrucVersion = 3'i32                  ## Transaction version for TRUC policy
  PackageTrucAncestorLimit = 2                ## Max ancestors including self (parent + self)
  PackageTrucDescendantLimit = 2              ## Max descendants including self (self + child)
  PackageTrucMaxVsize = 10_000                       ## Max vsize for any v3 tx (10 kvB)
  PackageTrucChildMaxVsize = 1_000                   ## Max vsize for v3 child of unconfirmed v3 parent

# Result type for package operations
type
  PackageOpResult*[T] = object
    case isOk*: bool
    of true:
      when T isnot void:
        value*: T
    of false:
      error*: string

proc ok*[T](val: T): PackageOpResult[T] =
  when T is void:
    PackageOpResult[T](isOk: true)
  else:
    PackageOpResult[T](isOk: true, value: val)

proc voidOk*(): PackageOpResult[void] =
  PackageOpResult[void](isOk: true)

proc err*(T: typedesc, msg: string): PackageOpResult[T] =
  PackageOpResult[T](isOk: false, error: msg)

# Package validation helpers

proc isTopoSortedPackage*(txns: seq[Transaction]): bool =
  ## Check that a package is topologically sorted: parents before children
  ## A transaction must not spend from any transaction that appears later in the package
  if txns.len <= 1:
    return true

  # Build set of txids that appear later in the package
  var laterTxids = initHashSet[TxId]()
  for i in countdown(txns.len - 1, 0):
    let txid = txns[i].txid()
    if i < txns.len - 1:
      laterTxids.incl(txid)

    # Check this tx's inputs don't spend from later txs
    for input in txns[i].inputs:
      if input.prevOut.txid in laterTxids:
        return false

    # Remove this txid from laterTxids for next iteration (moving backwards)
    laterTxids.excl(txid)

  # Rebuild correctly: check each tx doesn't spend from later txs
  laterTxids = initHashSet[TxId]()
  for i in countdown(txns.len - 1, 1):
    laterTxids.incl(txns[i].txid())

  for i in 0 ..< txns.len - 1:
    for input in txns[i].inputs:
      if input.prevOut.txid in laterTxids:
        return false
    laterTxids.excl(txns[i + 1].txid())

  true

proc isConsistentPackage*(txns: seq[Transaction]): bool =
  ## Check package consistency:
  ## - No duplicate txids
  ## - No two transactions spend the same input
  ## - All transactions have inputs (mempool txs always have inputs)
  if txns.len == 0:
    return true

  var seenTxids = initHashSet[TxId]()
  var spentOutpoints = initHashSet[OutPoint]()

  for tx in txns:
    # Check for empty inputs
    if tx.inputs.len == 0:
      return false

    # Check for duplicate txids
    let txid = tx.txid()
    if txid in seenTxids:
      return false
    seenTxids.incl(txid)

    # Check for conflicting inputs
    for input in tx.inputs:
      if input.prevOut in spentOutpoints:
        return false
      spentOutpoints.incl(input.prevOut)

  true

proc isWellFormedPackage*(txns: seq[Transaction]): PackageOpResult[void] =
  ## Validate package structure (context-free checks)
  ## Returns ok if valid, error message if not
  ##
  ## Checks:
  ## 1. Transaction count <= MAX_PACKAGE_COUNT (25)
  ## 2. Total weight <= MAX_PACKAGE_WEIGHT (404,000 WU) for packages > 1 tx
  ## 3. No duplicate txids
  ## 4. Topologically sorted (parents before children)
  ## 5. No conflicting inputs (no two txs spend same input)

  if txns.len == 0:
    return voidOk()

  # Rule 1: Transaction count
  if txns.len > MaxPackageCount:
    return err(void, "package-too-many-transactions: " & $txns.len & " > " & $MaxPackageCount)

  # Rule 2: Total weight (only for multi-tx packages)
  if txns.len > 1:
    var totalWeight = 0
    for tx in txns:
      let fullSize = serialize(tx, includeWitness = true).len
      let baseSize = serializeLegacy(tx).len
      let weight = (baseSize * 3) + fullSize
      totalWeight += weight

    if totalWeight > MaxPackageWeight:
      return err(void, "package-too-large: weight " & $totalWeight & " > " & $MaxPackageWeight)

  # Rule 3: No duplicates
  var seenTxids = initHashSet[TxId]()
  for tx in txns:
    let txid = tx.txid()
    if txid in seenTxids:
      return err(void, "package-contains-duplicates")
    seenTxids.incl(txid)

  # Rule 4: Topologically sorted
  if not isTopoSortedPackage(txns):
    return err(void, "package-not-sorted")

  # Rule 5: No conflicts
  if not isConsistentPackage(txns):
    return err(void, "conflict-in-package")

  voidOk()

proc isChildWithParents*(txns: seq[Transaction]): bool =
  ## Check if package has child-with-parents topology:
  ## - Package has 2+ transactions
  ## - Last transaction is the child
  ## - All earlier transactions are direct parents of the child
  if txns.len < 2:
    return false

  let child = txns[^1]
  let childInputTxids = block:
    var s = initHashSet[TxId]()
    for input in child.inputs:
      s.incl(input.prevOut.txid)
    s

  # All non-child txs must be direct parents of the child
  for i in 0 ..< txns.len - 1:
    let parentTxid = txns[i].txid()
    if parentTxid notin childInputTxids:
      return false

  true

proc isChildWithParentsTree*(txns: seq[Transaction]): bool =
  ## Check if package is a child-with-parents tree:
  ## - Passes isChildWithParents check
  ## - Additionally, parents don't depend on each other
  if not isChildWithParents(txns):
    return false

  if txns.len <= 2:
    return true

  # Build set of parent txids
  var parentTxids = initHashSet[TxId]()
  for i in 0 ..< txns.len - 1:
    parentTxids.incl(txns[i].txid())

  # Check no parent spends from another parent
  for i in 0 ..< txns.len - 1:
    for input in txns[i].inputs:
      if input.prevOut.txid in parentTxids:
        return false

  true

proc calculatePackageFeerate*(fees: seq[Satoshi], weights: seq[int]): float64 =
  ## Calculate aggregate package fee rate
  ## Package feerate = sum(fees) / sum(vsizes)
  ## vsize = (weight + 3) / 4
  var totalFees: int64 = 0
  var totalVsize: int = 0

  for i in 0 ..< fees.len:
    totalFees += int64(fees[i])
    totalVsize += (weights[i] + 3) div 4

  if totalVsize == 0:
    return 0.0

  float64(totalFees) / float64(totalVsize)

proc getPackageHash*(txns: seq[Transaction]): array[32, byte] =
  ## Compute a hash identifying this package (for caching)
  ## Hash of concatenated wtxids
  var data: seq[byte]
  for tx in txns:
    let w = tx.wtxid()
    for b in array[32, byte](w):
      data.add(b)
  doubleSha256(data)

proc calculateTransactionWeight*(tx: Transaction): int =
  ## Calculate transaction weight in weight units
  let fullSize = serialize(tx, includeWitness = true).len
  let baseSize = serializeLegacy(tx).len
  (baseSize * 3) + fullSize

proc calculateTransactionVsize*(tx: Transaction): int =
  ## Calculate transaction virtual size in vbytes
  let weight = calculateTransactionWeight(tx)
  (weight + 3) div 4

proc sortPackageTopologically*(txns: seq[Transaction]): seq[Transaction] =
  ## Sort a package topologically (parents before children)
  ## Uses Kahn's algorithm
  if txns.len <= 1:
    return txns

  # Build dependency graph
  var txMap = initTable[TxId, Transaction]()
  var inDegree = initTable[TxId, int]()
  var graph = initTable[TxId, seq[TxId]]()  # parent -> children

  for tx in txns:
    let txid = tx.txid()
    txMap[txid] = tx
    inDegree[txid] = 0
    graph[txid] = @[]

  # Build edges (parent -> child)
  for tx in txns:
    let childId = tx.txid()
    for input in tx.inputs:
      let parentId = input.prevOut.txid
      if parentId in txMap:
        graph[parentId].add(childId)
        inDegree[childId] = inDegree.getOrDefault(childId, 0) + 1

  # Kahn's algorithm
  var queue: seq[TxId]
  for txid, deg in inDegree:
    if deg == 0:
      queue.add(txid)

  var sorted: seq[Transaction]
  while queue.len > 0:
    let current = queue.pop()
    sorted.add(txMap[current])

    for child in graph.getOrDefault(current, @[]):
      inDegree[child] = inDegree[child] - 1
      if inDegree[child] == 0:
        queue.add(child)

  # If we didn't process all txs, there's a cycle (shouldn't happen)
  if sorted.len != txns.len:
    return txns  # Return original on error

  sorted

# ============================================================================
# TRUC (v3) Package Policy
# ============================================================================

proc isTruc*(tx: Transaction): bool =
  ## Check if transaction has v3 version (TRUC policy)
  tx.version == PackageTrucVersion

proc findInPackageParents(txns: seq[Transaction], txIndex: int): seq[int] =
  ## Find indices of transactions in the package that are direct parents of txns[txIndex]
  ## Assumes package is topologically sorted (parents before children)
  let tx = txns[txIndex]
  var parents: seq[int]

  for i in 0 ..< txIndex:  # Only look at earlier txs (parents come before children)
    let parentTxid = txns[i].txid()
    for input in tx.inputs:
      if input.prevOut.txid == parentTxid:
        parents.add(i)
        break

  parents

proc checkPackageTrucRules*(txns: seq[Transaction],
                            mempoolHasParent: proc(txid: TxId): bool,
                            mempoolParentIsTruc: proc(txid: TxId): bool,
                            mempoolParentDescendantCount: proc(txid: TxId): int): PackageOpResult[void] =
  ## Check TRUC policy rules for a package of transactions
  ##
  ## Rules:
  ## 1. v3 tx cannot exceed PackageTrucMaxVsize (10,000 vbytes)
  ## 2. v3 tx can have at most 1 unconfirmed parent (from mempool OR package)
  ## 3. v3 child (with unconfirmed parent) cannot exceed PackageTrucChildMaxVsize (1,000 vbytes)
  ## 4. v3 parent can have at most 1 unconfirmed child
  ## 5. v3 cannot spend from non-v3 unconfirmed; non-v3 cannot spend from v3 unconfirmed
  ##
  ## The callback functions allow checking mempool state without importing mempool module.

  if txns.len == 0:
    return voidOk()

  # Build txid set for package
  var packageTxids = initHashSet[TxId]()
  var packageVersions = initTable[TxId, int32]()
  for tx in txns:
    let txid = tx.txid()
    packageTxids.incl(txid)
    packageVersions[txid] = tx.version

  for i, tx in txns:
    let txid = tx.txid()
    let vsize = calculateTransactionVsize(tx)
    let txIsTruc = tx.isTruc

    # Find parents (both in-package and mempool)
    let inPackageParents = findInPackageParents(txns, i)

    # Count mempool parents
    var mempoolParentCount = 0
    var mempoolParentTxid: TxId
    for input in tx.inputs:
      if input.prevOut.txid notin packageTxids:
        if mempoolHasParent(input.prevOut.txid):
          mempoolParentCount += 1
          mempoolParentTxid = input.prevOut.txid

    let totalUnconfirmedParents = inPackageParents.len + mempoolParentCount

    # Rule 5: Check version inheritance for mempool parents
    for input in tx.inputs:
      if input.prevOut.txid notin packageTxids:
        if mempoolHasParent(input.prevOut.txid):
          let parentIsTruc = mempoolParentIsTruc(input.prevOut.txid)
          if txIsTruc and not parentIsTruc:
            return err(void, "version=3 tx " & $txid & " cannot spend from non-version=3 tx " & $input.prevOut.txid)
          if not txIsTruc and parentIsTruc:
            return err(void, "non-version=3 tx " & $txid & " cannot spend from version=3 tx " & $input.prevOut.txid)

    # Rule 5: Check version inheritance for in-package parents
    for parentIdx in inPackageParents:
      let parentTxid = txns[parentIdx].txid()
      let parentIsTruc = txns[parentIdx].isTruc
      if txIsTruc and not parentIsTruc:
        return err(void, "version=3 tx " & $txid & " cannot spend from non-version=3 tx " & $parentTxid)
      if not txIsTruc and parentIsTruc:
        return err(void, "non-version=3 tx " & $txid & " cannot spend from version=3 tx " & $parentTxid)

    # Remaining rules only apply to v3 transactions
    if not txIsTruc:
      continue

    # Rule 1: v3 tx size limit
    if vsize > PackageTrucMaxVsize:
      return err(void, "version=3 tx " & $txid & " is too big: " & $vsize & " > " & $PackageTrucMaxVsize & " virtual bytes")

    # Rule 2: v3 tx can have at most 1 unconfirmed ancestor
    if totalUnconfirmedParents > 1:
      return err(void, "tx " & $txid & " would have too many ancestors")

    # If there's any unconfirmed parent, check child size limit
    if totalUnconfirmedParents > 0:
      # Rule 3: v3 child size limit
      if vsize > PackageTrucChildMaxVsize:
        return err(void, "version=3 child tx " & $txid & " is too big: " & $vsize & " > " & $PackageTrucChildMaxVsize & " virtual bytes")

      # Rule 4: Check that parent doesn't already have other children

      # Check for in-package siblings (other children of same parent)
      for parentIdx in inPackageParents:
        let parentTxid = txns[parentIdx].txid()
        # Look for other txs in the package that also spend from this parent
        for j, otherTx in txns:
          if j != i:
            for input in otherTx.inputs:
              if input.prevOut.txid == parentTxid:
                # Another tx in package is also a child of this parent
                return err(void, "tx " & $txid & " would exceed descendant count limit")

      # Check mempool parent's existing descendants
      if mempoolParentCount > 0:
        let descCount = mempoolParentDescendantCount(mempoolParentTxid)
        if descCount > 1:  # Parent + existing child = 2, adding another would exceed
          return err(void, "tx " & $txid & " would exceed descendant count limit")

  voidOk()
