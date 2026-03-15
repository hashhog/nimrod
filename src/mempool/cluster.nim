## Cluster mempool implementation
## Organizes transactions into connected components (clusters) and linearizes each for optimal fee-rate ordering
##
## Key concepts:
## - Cluster: a connected component of transactions (connected via parent-child relationships)
## - Linearization: order transactions within each cluster by "chunks" (greedy highest-feerate topological prefix)
## - Mining score: each transaction's effective fee rate is the fee rate of its chunk
## - Eviction: when mempool is full, evict the lowest-mining-score transaction

import std/[tables, algorithm, sets, options, hashes, sequtils]
import ../primitives/types

const
  ## Maximum cluster size (replaces ancestor/descendant limits)
  MaxClusterSize* = 100

type
  ## Fee fraction: fee and size for calculating fee rate
  FeeFrac* = object
    fee*: int64    ## Total fee in satoshis
    size*: int     ## Total size in weight units / 4 (vbytes)

  ## Index into the cluster's transaction list
  TxIndex* = uint32

  ## A chunk is a prefix of the linearization that forms a topologically valid subset
  Chunk* = object
    txIndices*: seq[TxIndex]  ## Transaction indices in this chunk
    feerate*: FeeFrac         ## Aggregate fee/size of the chunk

  ## Dependency graph for transactions within a cluster
  DepGraph* = object
    ## Transaction data indexed by TxIndex
    feerates*: seq[FeeFrac]
    ancestors*: seq[HashSet[TxIndex]]    ## ancestors[i] includes i itself
    descendants*: seq[HashSet[TxIndex]]  ## descendants[i] includes i itself
    used*: HashSet[TxIndex]              ## Which indices are in use

  ## A cluster is a connected component of transactions
  Cluster* = object
    txids*: seq[TxId]                   ## Transaction IDs in this cluster
    txidToIndex*: Table[TxId, TxIndex]  ## Map from txid to index
    graph*: DepGraph                    ## Dependency graph
    linearization*: seq[TxIndex]        ## Linearized order (best-to-worst feerate)
    chunks*: seq[Chunk]                 ## Chunked linearization

  ## Result type for cluster operations
  ClusterResult*[T] = object
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

proc ok*[T](val: T): ClusterResult[T] =
  ClusterResult[T](isOk: true, value: val)

proc err*(T: typedesc, msg: string): ClusterResult[T] =
  ClusterResult[T](isOk: false, error: msg)

# ============================================================================
# FeeFrac operations
# ============================================================================

proc `+`*(a, b: FeeFrac): FeeFrac =
  FeeFrac(fee: a.fee + b.fee, size: a.size + b.size)

proc `+=`*(a: var FeeFrac, b: FeeFrac) =
  a.fee += b.fee
  a.size += b.size

proc `-`*(a, b: FeeFrac): FeeFrac =
  FeeFrac(fee: a.fee - b.fee, size: a.size - b.size)

proc `-=`*(a: var FeeFrac, b: FeeFrac) =
  a.fee -= b.fee
  a.size -= b.size

proc feeRate*(f: FeeFrac): float64 =
  ## Calculate fee rate in sat/vbyte
  if f.size == 0:
    return 0.0
  float64(f.fee) / float64(f.size)

proc `>`*(a, b: FeeFrac): bool =
  ## Compare fee fractions by fee rate (cross-multiply to avoid division)
  ## a.fee/a.size > b.fee/b.size  <==>  a.fee * b.size > b.fee * a.size
  a.fee * int64(b.size) > b.fee * int64(a.size)

proc `>=`*(a, b: FeeFrac): bool =
  a.fee * int64(b.size) >= b.fee * int64(a.size)

proc `<`*(a, b: FeeFrac): bool =
  a.fee * int64(b.size) < b.fee * int64(a.size)

proc `<=`*(a, b: FeeFrac): bool =
  a.fee * int64(b.size) <= b.fee * int64(a.size)

proc `==`*(a, b: FeeFrac): bool =
  a.fee * int64(b.size) == b.fee * int64(a.size)

# ============================================================================
# DepGraph operations
# ============================================================================

proc newDepGraph*(): DepGraph =
  DepGraph(
    feerates: @[],
    ancestors: @[],
    descendants: @[],
    used: initHashSet[TxIndex]()
  )

proc txCount*(g: DepGraph): int =
  g.used.len

proc addTransaction*(g: var DepGraph, feefrac: FeeFrac): TxIndex =
  ## Add a new isolated transaction, returns its index
  let idx = TxIndex(g.feerates.len)
  g.feerates.add(feefrac)
  g.ancestors.add(initHashSet[TxIndex]())
  g.ancestors[idx].incl(idx)  # Self is always an ancestor
  g.descendants.add(initHashSet[TxIndex]())
  g.descendants[idx].incl(idx)  # Self is always a descendant
  g.used.incl(idx)
  idx

proc addDependency*(g: var DepGraph, parent, child: TxIndex) =
  ## Add parent -> child dependency (parent must be mined before child)
  if parent notin g.used or child notin g.used:
    return
  if parent in g.ancestors[child]:
    return  # Already have this dependency

  # Get ancestors of parent not already in child's ancestors
  var newAncestors: HashSet[TxIndex]
  for anc in g.ancestors[parent]:
    if anc notin g.ancestors[child]:
      newAncestors.incl(anc)

  if newAncestors.len == 0:
    return

  # Add these ancestors to all descendants of child
  for desc in g.descendants[child]:
    for anc in newAncestors:
      g.ancestors[desc].incl(anc)

  # Add descendants of child to all new ancestors
  for anc in newAncestors:
    for desc in g.descendants[child]:
      g.descendants[anc].incl(desc)

proc feeRate*(g: DepGraph, indices: HashSet[TxIndex]): FeeFrac =
  ## Calculate aggregate fee/size for a set of transactions
  var total = FeeFrac(fee: 0, size: 0)
  for idx in indices:
    if idx in g.used:
      total += g.feerates[idx]
  total

proc getReducedParents*(g: DepGraph, idx: TxIndex): HashSet[TxIndex] =
  ## Get the minimal set of direct parents (inferred from ancestors)
  ## These are ancestors that aren't ancestors of any other ancestor
  if idx notin g.used:
    return initHashSet[TxIndex]()

  var parents = g.ancestors[idx]
  parents.excl(idx)

  # Remove ancestors of ancestors
  for p in toSeq(parents):
    if p in parents:
      for grandparent in g.ancestors[p]:
        if grandparent != p:
          parents.excl(grandparent)

  parents

proc getReducedChildren*(g: DepGraph, idx: TxIndex): HashSet[TxIndex] =
  ## Get the minimal set of direct children (inferred from descendants)
  if idx notin g.used:
    return initHashSet[TxIndex]()

  var children = g.descendants[idx]
  children.excl(idx)

  # Remove descendants of descendants
  for c in toSeq(children):
    if c in children:
      for grandchild in g.descendants[c]:
        if grandchild != c:
          children.excl(grandchild)

  children

proc getConnectedComponent*(g: DepGraph, subset: HashSet[TxIndex], start: TxIndex): HashSet[TxIndex] =
  ## Find the connected component containing `start` within `subset`
  ## Two transactions are connected if one is an ancestor of the other
  if start notin subset:
    return initHashSet[TxIndex]()

  var component = initHashSet[TxIndex]()
  var toAdd: seq[TxIndex] = @[start]

  while toAdd.len > 0:
    let tx = toAdd.pop()
    if tx in component:
      continue
    if tx notin subset:
      continue

    component.incl(tx)

    # Add all ancestors and descendants that are in subset
    for anc in g.ancestors[tx]:
      if anc in subset and anc notin component:
        toAdd.add(anc)
    for desc in g.descendants[tx]:
      if desc in subset and desc notin component:
        toAdd.add(desc)

  component

proc findConnectedComponent*(g: DepGraph, subset: HashSet[TxIndex]): HashSet[TxIndex] =
  ## Find a connected component within subset (starts from first element)
  if subset.len == 0:
    return initHashSet[TxIndex]()

  var first: TxIndex
  for idx in subset:
    first = idx
    break

  g.getConnectedComponent(subset, first)

proc isConnected*(g: DepGraph, subset: HashSet[TxIndex]): bool =
  ## Check if a subset forms a single connected component
  if subset.len == 0:
    return true
  g.findConnectedComponent(subset) == subset

proc appendTopo*(g: DepGraph, indices: HashSet[TxIndex]): seq[TxIndex] =
  ## Return indices in topologically valid order (parents before children)
  ## Sort by ancestor count (fewer ancestors = earlier in sort)
  var list: seq[TxIndex]
  for idx in indices:
    list.add(idx)

  list.sort(proc(a, b: TxIndex): int =
    let aCount = g.ancestors[a].len
    let bCount = g.ancestors[b].len
    if aCount != bCount:
      return cmp(aCount, bCount)
    cmp(int(a), int(b))
  )

  list

# ============================================================================
# Linearization algorithm
# ============================================================================

proc findBestTopologicalSubset(g: DepGraph, remaining: HashSet[TxIndex]): HashSet[TxIndex] =
  ## Find the highest-feerate topologically valid subset (a "chunk")
  ## A subset is topologically valid if it includes all ancestors of included transactions
  ## Uses greedy approach: start with highest-feerate tx that has all ancestors in remaining

  if remaining.len == 0:
    return initHashSet[TxIndex]()

  # Find all transactions whose ancestors are all in remaining (can be added)
  var candidates: seq[TxIndex]
  for idx in remaining:
    var ancestorsInRemaining = true
    for anc in g.ancestors[idx]:
      if anc notin remaining:
        ancestorsInRemaining = false
        break
    if ancestorsInRemaining:
      candidates.add(idx)

  if candidates.len == 0:
    return initHashSet[TxIndex]()

  # Greedy: find the subset with highest aggregate feerate
  # Start with each candidate and its ancestors, pick best
  var bestSubset = initHashSet[TxIndex]()
  var bestFeerate = FeeFrac(fee: 0, size: 0)

  for startIdx in candidates:
    # Build the subset: startIdx and all its ancestors in remaining
    var subset = initHashSet[TxIndex]()
    for anc in g.ancestors[startIdx]:
      if anc in remaining:
        subset.incl(anc)

    let subsetFeerate = g.feeRate(subset)
    if bestSubset.len == 0 or subsetFeerate > bestFeerate:
      bestSubset = subset
      bestFeerate = subsetFeerate

  # Now try to grow the best subset by adding more transactions
  # Keep adding the transaction that maximizes the combined feerate
  var improved = true
  while improved:
    improved = false
    var bestAddition = TxIndex(high(uint32))
    var bestNewFeerate = bestFeerate

    for idx in remaining:
      if idx in bestSubset:
        continue
      # Check if all ancestors of idx are in bestSubset
      var canAdd = true
      for anc in g.ancestors[idx]:
        if anc notin bestSubset and anc != idx:
          canAdd = false
          break
      if not canAdd:
        continue

      # Would adding this improve the feerate?
      let newFeerate = bestFeerate + g.feerates[idx]
      if newFeerate > bestNewFeerate:
        bestAddition = idx
        bestNewFeerate = newFeerate

    if bestAddition != TxIndex(high(uint32)):
      bestSubset.incl(bestAddition)
      bestFeerate = bestNewFeerate
      improved = true

  bestSubset

proc linearize*(g: DepGraph): seq[TxIndex] =
  ## Linearize transactions in fee-rate order using greedy chunking
  ## Returns indices in best-to-worst order

  var remaining = g.used
  var linearization: seq[TxIndex]

  while remaining.len > 0:
    # Find the best (highest-feerate) topologically valid chunk
    let chunk = findBestTopologicalSubset(g, remaining)
    if chunk.len == 0:
      # Shouldn't happen if graph is valid, but safety fallback
      # Just take remaining in any topo order
      let topo = g.appendTopo(remaining)
      for idx in topo:
        linearization.add(idx)
      break

    # Add chunk to linearization in topo order
    let topoChunk = g.appendTopo(chunk)
    for idx in topoChunk:
      linearization.add(idx)
      remaining.excl(idx)

  linearization

proc computeChunks*(g: DepGraph, linearization: seq[TxIndex]): seq[Chunk] =
  ## Compute chunks from a linearization
  ## A chunk is formed by absorbing higher-feerate transactions that come later
  ## into earlier lower-feerate ones

  var chunks: seq[Chunk]

  for idx in linearization:
    var newChunk = Chunk(
      txIndices: @[idx],
      feerate: g.feerates[idx]
    )

    # Absorb lower-feerate chunks at the end
    while chunks.len > 0 and newChunk.feerate > chunks[^1].feerate:
      let lastChunk = chunks.pop()
      newChunk.txIndices = lastChunk.txIndices & newChunk.txIndices
      newChunk.feerate = newChunk.feerate + lastChunk.feerate

    chunks.add(newChunk)

  chunks

proc getMiningScore*(g: DepGraph, chunks: seq[Chunk], idx: TxIndex): float64 =
  ## Get the mining score (chunk fee rate) for a transaction
  for chunk in chunks:
    if idx in chunk.txIndices:
      return chunk.feerate.feeRate
  0.0

# ============================================================================
# Cluster operations
# ============================================================================

proc newCluster*(): Cluster =
  Cluster(
    txids: @[],
    txidToIndex: initTable[TxId, TxIndex](),
    graph: newDepGraph(),
    linearization: @[],
    chunks: @[]
  )

proc size*(c: Cluster): int =
  c.txids.len

proc contains*(c: Cluster, txid: TxId): bool =
  txid in c.txidToIndex

proc addTransaction*(c: var Cluster, txid: TxId, fee: int64, vsize: int): ClusterResult[TxIndex] =
  ## Add a transaction to the cluster
  if c.size >= MaxClusterSize:
    return err(TxIndex, "cluster size limit exceeded: " & $c.size & " >= " & $MaxClusterSize)

  if txid in c.txidToIndex:
    return err(TxIndex, "transaction already in cluster")

  let feefrac = FeeFrac(fee: fee, size: vsize)
  let idx = c.graph.addTransaction(feefrac)
  c.txids.add(txid)
  c.txidToIndex[txid] = idx
  ok(idx)

proc addDependency*(c: var Cluster, parentTxid, childTxid: TxId) =
  ## Add a parent -> child dependency
  if parentTxid notin c.txidToIndex or childTxid notin c.txidToIndex:
    return
  let parentIdx = c.txidToIndex[parentTxid]
  let childIdx = c.txidToIndex[childTxid]
  c.graph.addDependency(parentIdx, childIdx)

proc relinearize*(c: var Cluster) =
  ## Recompute the linearization and chunks
  c.linearization = c.graph.linearize()
  c.chunks = c.graph.computeChunks(c.linearization)

proc getMiningScore*(c: Cluster, txid: TxId): float64 =
  ## Get the mining score for a transaction (its chunk's fee rate)
  if txid notin c.txidToIndex:
    return 0.0
  let idx = c.txidToIndex[txid]
  c.graph.getMiningScore(c.chunks, idx)

proc getLinearizedTxids*(c: Cluster): seq[TxId] =
  ## Get transaction IDs in linearized order (best to worst)
  result = @[]
  for idx in c.linearization:
    result.add(c.txids[idx])

proc getWorstTransaction*(c: Cluster): Option[TxId] =
  ## Get the worst (lowest mining score) transaction in the cluster
  if c.linearization.len == 0:
    return none(TxId)
  # Last in linearization is worst
  some(c.txids[c.linearization[^1]])

# ============================================================================
# Cluster Manager - manages all clusters in the mempool
# ============================================================================

type
  ClusterManager* = object
    clusters*: Table[TxId, int]          ## Map txid -> cluster index
    clusterList*: seq[Cluster]           ## All clusters
    freeIndices*: seq[int]               ## Recycled cluster indices

proc newClusterManager*(): ClusterManager =
  ClusterManager(
    clusters: initTable[TxId, int](),
    clusterList: @[],
    freeIndices: @[]
  )

proc getClusterIndex*(cm: ClusterManager, txid: TxId): Option[int] =
  if txid in cm.clusters:
    some(cm.clusters[txid])
  else:
    none(int)

proc getCluster*(cm: ClusterManager, txid: TxId): Option[ptr Cluster] =
  if txid in cm.clusters:
    let idx = cm.clusters[txid]
    if idx < cm.clusterList.len:
      some(addr cm.clusterList[idx])
    else:
      none(ptr Cluster)
  else:
    none(ptr Cluster)

proc allocateCluster(cm: var ClusterManager): int =
  ## Allocate a new cluster, reusing freed indices if available
  if cm.freeIndices.len > 0:
    result = cm.freeIndices.pop()
    cm.clusterList[result] = newCluster()
  else:
    result = cm.clusterList.len
    cm.clusterList.add(newCluster())

proc freeCluster(cm: var ClusterManager, idx: int) =
  ## Mark a cluster index as free for reuse
  cm.clusterList[idx] = newCluster()
  cm.freeIndices.add(idx)

proc addTransaction*(cm: var ClusterManager, txid: TxId, fee: int64, vsize: int,
                     parentTxids: seq[TxId]): ClusterResult[void] =
  ## Add a transaction to the cluster manager
  ## Creates new cluster or merges with existing ones based on parent relationships

  # Find which clusters the parents are in
  var parentClusterIndices: HashSet[int]
  for parentTxid in parentTxids:
    if parentTxid in cm.clusters:
      parentClusterIndices.incl(cm.clusters[parentTxid])

  var targetClusterIdx: int

  if parentClusterIndices.len == 0:
    # No parents in mempool - create new singleton cluster
    targetClusterIdx = cm.allocateCluster()
  elif parentClusterIndices.len == 1:
    # Single parent cluster - add to it
    for idx in parentClusterIndices:
      targetClusterIdx = idx
      break
  else:
    # Multiple parent clusters - need to merge them
    # Pick the largest cluster as the target
    var maxSize = 0
    for idx in parentClusterIndices:
      if cm.clusterList[idx].size > maxSize:
        maxSize = cm.clusterList[idx].size
        targetClusterIdx = idx

    # Check if merged cluster would exceed size limit
    var totalSize = 1  # The new transaction
    for idx in parentClusterIndices:
      totalSize += cm.clusterList[idx].size
    if totalSize > MaxClusterSize:
      return err(void, "merged cluster would exceed size limit: " & $totalSize & " > " & $MaxClusterSize)

    # Merge all other clusters into target
    for idx in parentClusterIndices:
      if idx == targetClusterIdx:
        continue

      let srcCluster = cm.clusterList[idx]
      for srcTxid in srcCluster.txids:
        let srcIdx = srcCluster.txidToIndex[srcTxid]
        let srcFeefrac = srcCluster.graph.feerates[srcIdx]
        discard cm.clusterList[targetClusterIdx].addTransaction(srcTxid, srcFeefrac.fee, srcFeefrac.size)
        cm.clusters[srcTxid] = targetClusterIdx

      # Copy dependencies
      for srcTxid in srcCluster.txids:
        let srcIdx = srcCluster.txidToIndex[srcTxid]
        for parentIdx in srcCluster.graph.getReducedParents(srcIdx):
          let parentTxid = srcCluster.txids[parentIdx]
          cm.clusterList[targetClusterIdx].addDependency(parentTxid, srcTxid)

      cm.freeCluster(idx)

  # Add the new transaction
  let addResult = cm.clusterList[targetClusterIdx].addTransaction(txid, fee, vsize)
  if not addResult.isOk:
    return err(void, addResult.error)

  cm.clusters[txid] = targetClusterIdx

  # Add dependencies to parents
  for parentTxid in parentTxids:
    if parentTxid in cm.clusters:
      cm.clusterList[targetClusterIdx].addDependency(parentTxid, txid)

  # Relinearize the cluster
  cm.clusterList[targetClusterIdx].relinearize()

  ClusterResult[void](isOk: true)

proc removeTransaction*(cm: var ClusterManager, txid: TxId) =
  ## Remove a transaction from its cluster
  ## Note: This is a simplified version - in production, you'd need to
  ## split the cluster if removing a transaction disconnects components

  if txid notin cm.clusters:
    return

  let clusterIdx = cm.clusters[txid]
  cm.clusters.del(txid)

  # For simplicity, rebuild the cluster without this transaction
  # In production, you'd want incremental updates
  var oldCluster = cm.clusterList[clusterIdx]

  # If this was the only transaction, free the cluster
  if oldCluster.size == 1:
    cm.freeCluster(clusterIdx)
    return

  # Rebuild without this transaction (simplified - doesn't handle disconnection)
  cm.clusterList[clusterIdx] = newCluster()

  for otherTxid in oldCluster.txids:
    if otherTxid == txid:
      continue
    let oldIdx = oldCluster.txidToIndex[otherTxid]
    let feefrac = oldCluster.graph.feerates[oldIdx]
    discard cm.clusterList[clusterIdx].addTransaction(otherTxid, feefrac.fee, feefrac.size)
    cm.clusters[otherTxid] = clusterIdx

  # Rebuild dependencies
  for otherTxid in oldCluster.txids:
    if otherTxid == txid:
      continue
    let oldIdx = oldCluster.txidToIndex[otherTxid]
    for parentIdx in oldCluster.graph.getReducedParents(oldIdx):
      let parentTxid = oldCluster.txids[parentIdx]
      if parentTxid != txid:
        cm.clusterList[clusterIdx].addDependency(parentTxid, otherTxid)

  cm.clusterList[clusterIdx].relinearize()

proc getMiningScore*(cm: ClusterManager, txid: TxId): float64 =
  ## Get the mining score for a transaction
  if txid notin cm.clusters:
    return 0.0
  let clusterIdx = cm.clusters[txid]
  cm.clusterList[clusterIdx].getMiningScore(txid)

proc getWorstTransaction*(cm: ClusterManager): Option[(TxId, float64)] =
  ## Find the worst transaction across all clusters (for eviction)
  var worstTxid: TxId
  var worstScore = float64.high
  var found = false

  for cluster in cm.clusterList:
    if cluster.size == 0:
      continue
    let worst = cluster.getWorstTransaction()
    if worst.isSome:
      let txid = worst.get()
      let score = cluster.getMiningScore(txid)
      if score < worstScore:
        worstScore = score
        worstTxid = txid
        found = true

  if found:
    some((worstTxid, worstScore))
  else:
    none((TxId, float64))

proc selectTransactionsForBlock*(cm: ClusterManager, maxWeight: int): seq[(TxId, float64)] =
  ## Select transactions for a block template, ordered by mining score
  ## Returns (txid, miningScore) pairs in best-to-worst order

  # Collect all linearized transactions with their scores
  var allTxs: seq[(TxId, float64)]

  for cluster in cm.clusterList:
    if cluster.size == 0:
      continue
    for txid in cluster.getLinearizedTxids():
      let score = cluster.getMiningScore(txid)
      allTxs.add((txid, score))

  # Sort by mining score (highest first)
  allTxs.sort(proc(a, b: (TxId, float64)): int =
    if a[1] > b[1]: -1
    elif a[1] < b[1]: 1
    else: 0
  )

  allTxs

proc clusterCount*(cm: ClusterManager): int =
  ## Count non-empty clusters
  var count = 0
  for cluster in cm.clusterList:
    if cluster.size > 0:
      inc count
  count

proc totalTransactionCount*(cm: ClusterManager): int =
  cm.clusters.len
