## Bitcoin Core's mempool memory accounting, as `getmempoolinfo` reports it.
##
## Core's `usage` is `CTxMemPool::DynamicMemoryUsage()` (txmempool.cpp), the
## byte count `-maxmempool` is compared against.  It is an estimate built from
## libstdc++ node and `malloc` rounding rules, so the only honest way to match
## it is to model the same containers.  Every constant below was measured on a
## Bitcoin Core v31.1 regtest node (usage read back after each
## `sendrawtransaction`, in `staged-patches/nimrod-mpi/core-fit/`), not taken
## from a source tree, because the pinned oracle is the v31.1 binary:
##
##   usage = n * EntryOverhead                       mapTx node + TxGraph entry + one chunk-index node
##         + sum(txDynamicUsage(tx))                 RecursiveDynamicUsage(tx), cached per entry
##         + MapNextTxNode * (inputs in the pool)    std::map<COutPoint*, ...> node per input
##         + MapDeltasNode * len(mapDeltas)
##         + mallocUsage(RandElem * cap)             txns_randomized vector capacity
##         + sum over clusters with k >= 2 txs of    Generic cluster vs k singleton clusters
##             clusterExtra(k) - ChunkNode * (k - chunks)
##
## Measured values: a 1-in/1-out P2WSH tx costs 1016 bytes on top of the
## vector; chaining a second tx adds 136 more than two singletons; every
## further chain member subtracts 40, except every 4th which subtracts 8; a
## child that pays a higher feerate than its parent merges into the parent's
## chunk, which saves one 64-byte chunk-index node.
##
## Known limit: the generic-cluster term was fitted on chains and stars built
## one transaction at a time.  A cluster formed by merging two multi-tx
## clusters can differ from the fit by a few vector-capacity steps.

import ../primitives/types

const
  CTxInSize* = 96             ## sizeof(CTxIn), 8-aligned with the CScriptWitness vector
  CTxOutSize* = 48            ## sizeof(CTxOut)
  DirectScriptMax* = 36       ## prevector<36> keeps scripts up to 36 bytes inline
  WitnessItemSize* = 24       ## sizeof(std::vector<unsigned char>)
  EntryOverhead* = 632        ## per-tx constant, see module doc
  MapNextTxNode* = 80         ## MallocUsage of one std::map node per spent outpoint
  MapDeltasNode* = 96         ## one std::map<Txid, CAmount> node (prioritisetransaction)
  RandElem* = 40              ## sizeof(pair<Wtxid, txiter>) in txns_randomized
  ChunkNode* = 64             ## one chunk-index node

proc mallocUsage*(alloc: int): int =
  ## memusage::MallocUsage on a 64-bit glibc build.
  if alloc <= 0: 0 else: ((alloc + 31) shr 4) shl 4

proc scriptUsage(len: int): int =
  if len > DirectScriptMax: mallocUsage(len) else: 0

proc txDynamicUsage*(tx: Transaction): int =
  ## Core RecursiveDynamicUsage(CTransaction): the vin and vout vectors, the
  ## scripts that spill out of their prevector, and each witness stack.
  result = mallocUsage(CTxInSize * tx.inputs.len) +
           mallocUsage(CTxOutSize * tx.outputs.len)
  for input in tx.inputs:
    result += scriptUsage(input.scriptSig.len)
  for output in tx.outputs:
    result += scriptUsage(output.scriptPubKey.len)
  for stack in tx.witnesses:
    if stack.len > 0:
      result += mallocUsage(WitnessItemSize * stack.len)
      for item in stack:
        result += mallocUsage(item.len)

proc randVectorUsage*(cap: int): int =
  mallocUsage(RandElem * cap)

proc clusterExtra*(k: int): int =
  ## What a k-tx generic cluster costs beyond k singleton clusters (k >= 2).
  136 - 40 * (k - 2) + 32 * ((k - 1) div 4)

type ChunkTx* = object
  fee*: int64
  size*: int64
  parents*: seq[int]  ## indexes of in-cluster parents

type Chunk* = object
  txs*: seq[int]      ## cluster indexes of the chunk's members
  fee*: int64
  size*: int64

proc chunkLinearization*(txs: seq[ChunkTx]): seq[Chunk] =
  ## The cluster's chunks, best feerate first: repeatedly take the
  ## best-feerate ancestor-closed set, then merge a chunk into its
  ## predecessor while it pays a strictly higher feerate (Core
  ## ChunkLinearization).  Exact for the small trees a mempool produces.
  let n = txs.len
  var placed = newSeq[bool](n)
  var left = n
  while left > 0:
    var bestSet: seq[int]
    var bestFee = 0'i64
    var bestSize = 0'i64
    for i in 0 ..< n:
      if placed[i]: continue
      var seen = newSeq[bool](n)
      var stack = @[i]
      var set: seq[int]
      var fee = 0'i64
      var size = 0'i64
      while stack.len > 0:
        let c = stack.pop()
        if seen[c] or placed[c]: continue
        seen[c] = true
        set.add(c)
        fee += txs[c].fee
        size += txs[c].size
        for p in txs[c].parents: stack.add(p)
      let better = bestSet.len == 0 or
        fee * bestSize > bestFee * size or
        (fee * bestSize == bestFee * size and size < bestSize)
      if better:
        bestSet = set; bestFee = fee; bestSize = size
    for c in bestSet:
      placed[c] = true
    left -= bestSet.len
    result.add(Chunk(txs: bestSet, fee: bestFee, size: bestSize))
    while result.len >= 2:
      let a = result[^2]
      let b = result[^1]
      if b.fee * a.size > a.fee * b.size:
        result.setLen(result.len - 2)
        result.add(Chunk(txs: a.txs & b.txs, fee: a.fee + b.fee,
                         size: a.size + b.size))
      else:
        break

proc chunkCount*(txs: seq[ChunkTx]): int =
  ## Number of chunks in the cluster's linearization.
  chunkLinearization(txs).len

proc clusterTerm*(txs: seq[ChunkTx]): int =
  ## The cluster's contribution to usage beyond the per-tx constants.
  if txs.len < 2: return 0
  clusterExtra(txs.len) - ChunkNode * (txs.len - chunkCount(txs))
