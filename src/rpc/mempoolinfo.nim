## The `getmempoolinfo` object and the per-entry mempool object, shared by
## the JSON-RPC methods and the REST mempool endpoints.
##
## - `mempoolInfoJson`: getmempoolinfo and `GET /rest/mempool/info.json`
##   (Core's MempoolInfoToJSON serves both).
## - `mempoolEntryJson`: getmempoolentry, getrawmempool true,
##   getmempoolancestors/descendants true and `GET /rest/mempool/contents.json`
##   (Core's entryToJSON serves all of them; rest.cpp rest_mempool calls
##   MempoolToJSON(verbose=true), which calls entryToJSON per entry).
##
## Reference: bitcoin-core/src/rpc/mempool.cpp MempoolInfoToJSON, entryToJSON,
## MempoolToJSON; bitcoin-core/src/rest.cpp rest_mempool.

import std/[json, streams, strutils, tables, sets, times, algorithm]
import ../primitives/[types, serialize]
import ../mempool/mempool

proc amountNode(sats: int64): JsonNode =
  ## Core's ValueFromAmount: always eight decimals, emitted as a raw number.
  let neg = sats < 0
  let abs = if neg: -sats else: sats
  let text = (if neg: "-" else: "") & $(abs div 100_000_000'i64) & "." &
             align($(abs mod 100_000_000'i64), 8, '0')
  var st = newStringStream(text)
  parseJson(st, "rawnum", false, true)

proc mempoolInfoJson*(mp: Mempool): JsonNode =
  var totalFeeSat: int64 = 0
  for _, entry in mp.entries:
    totalFeeSat += int64(entry.fee)

  # mempoolminfee = max(rolling floor, static relay floor); every figure is
  # sat/kvB on the wire (btcAmount takes satoshis per kvB).
  let minRelaySats = int64(mp.minFeeRate * 1000.0 + 0.5)
  let mempoolMinSats = int64(max(mp.minFeeRate, mp.getMinFee()) * 1000.0 + 0.5)
  let incrementalSats = int64(mp.incrementalRelayFeeRate + 0.5)

  %*{
    "loaded": true,
    "size": mp.count,
    "bytes": mp.totalTxSize,
    "usage": mp.dynamicMemoryUsage,
    "total_fee": float64(totalFeeSat) / 100000000.0,
    "maxmempool": mp.maxSize,
    "mempoolminfee": amountNode(mempoolMinSats),
    "minrelaytxfee": amountNode(minRelaySats),
    "incrementalrelayfee": amountNode(incrementalSats),
    "unbroadcastcount": mp.unbroadcast.len,
    # Core master removed the mempoolfullrbf option and hardcodes `true`.
    "fullrbf": true,
    "permitbaremultisig": true,            # DEFAULT_PERMIT_BAREMULTISIG
    "maxdatacarriersize": 100_000,         # MAX_OP_RETURN_RELAY
    "limitclustercount": 64,               # DEFAULT_CLUSTER_LIMIT
    "limitclustersize": 101_000,           # DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000
    "optimal": true                        # DoWork(0) on default mempool
  }

proc displayHex(h: array[32, byte]): string =
  ## Display (reversed) lower-case hex of a 32-byte hash.
  result = newStringOfCap(64)
  for i in countdown(31, 0):
    result.add(toHex(h[i], 2).toLowerAscii)

proc mempoolEntryJson*(mp: Mempool, txid: TxId, entry: MempoolEntry,
                       chunks: var Table[TxId, ChunkInfo]): JsonNode =
  ## Canonical per-entry object (Core entryToJSON). `chunks` caches the
  ## cluster linearization across entries of one listing.
  ##
  ## Field order matches Core.  Top-level "fee"/"modifiedfee"/"descendantfees"/
  ## "ancestorfees" are absent (Core moved them into the "fees" sub-object).
  let vsize = (entry.weight + 3) div 4
  let feeF   = float64(int64(entry.fee))   / 100000000.0
  # modified fee = base + PrioritiseTransaction delta (Core GetModifiedFee).
  let modF   = float64(mp.getModifiedFee(txid)) / 100000000.0
  let ancestF = float64(int64(entry.ancestorFee)) / 100000000.0
  # Descendant totals include the tx itself (Core GetCountWithDescendants etc.)
  let desc = mp.descendantTotals(txid)
  let descendF = float64(desc.modFee) / 100000000.0
  # Chunk = the feerate-diagram chunk of the tx's cluster linearization.
  if txid notin chunks:
    for k, v in mp.clusterChunks(txid):
      chunks[k] = v
  let chunk = chunks.getOrDefault(txid,
    (fee: mp.getModifiedFee(txid), weight: int64(entry.weight)))
  var obj = newJObject()
  obj["vsize"]           = %vsize
  obj["weight"]          = %entry.weight
  obj["time"]            = %entry.timeAdded.toUnix()
  obj["height"]          = %entry.height
  obj["descendantcount"] = %desc.count
  obj["descendantsize"]  = %desc.vsize
  obj["ancestorcount"]   = %entry.ancestorCount
  obj["ancestorsize"]    = %entry.ancestorSize
  obj["wtxid"]           = %displayHex(array[32, byte](entry.tx.wtxid()))
  obj["chunkweight"]     = %chunk.weight
  var feesObj = newJObject()
  feesObj["base"]       = %feeF
  feesObj["modified"]   = %modF
  feesObj["ancestor"]   = %ancestF
  feesObj["descendant"] = %descendF
  feesObj["chunk"]      = %(float64(chunk.fee) / 100000000.0)
  obj["fees"]             = feesObj
  # Core builds depends as a std::set<std::string> of display-hex txids.
  var dependHex: seq[string]
  for p in mp.inPoolParents(txid):
    dependHex.add(displayHex(array[32, byte](p)))
  dependHex.sort()
  var depends = newJArray()
  for h in dependHex:
    depends.add(%h)
  var spentby = newJArray()
  for c in mp.inPoolChildren(txid):
    spentby.add(%displayHex(array[32, byte](c)))
  obj["depends"]          = depends
  obj["spentby"]          = spentby
  # FIX-68 (W120 BUG-3): bip125-replaceable reflects the tx's own opt-in and
  # inherited signaling from in-mempool ancestors (Core IsRBFOptIn).
  obj["bip125-replaceable"] = %mp.isBip125Replaceable(txid)
  obj["unbroadcast"]      = %mp.isUnbroadcast(txid)
  obj
