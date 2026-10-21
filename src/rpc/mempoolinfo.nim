## The `getmempoolinfo` object, shared by the JSON-RPC method and
## `GET /rest/mempool/info.json` (Core's MempoolInfoToJSON serves both).
##
## Reference: bitcoin-core/src/rpc/mempool.cpp MempoolInfoToJSON.

import std/[json, streams, strutils, tables, sets]
import ../primitives/types
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
