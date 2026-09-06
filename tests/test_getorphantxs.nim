## getorphantxs RPC — shape + field parity test.
##
## getorphantxs was added to Bitcoin Core in v28 (rpc/mempool.cpp). It exposes
## the tx orphanage at three verbosity levels:
##   0 → array of TXID strings (Core: orphan.tx->GetHash(), NON-witness txid)
##   1 → array of { txid, wtxid, bytes, vsize, weight, from }  (NO expiration)
##   2 → verbosity-1 objects PLUS "hex" (serialized, hex-encoded tx)
## Out-of-range verbosity → RPC_INVALID_PARAMETER (-8).
##
## nimrod's orphan pool (src/mempool/orphan.nim) keys orphans by wtxid and
## tracks a single announcer (address, port) per orphan; the handler emits the
## announcer as a 1-element ["address:port"] array (empty if blank). Core's
## OrphanToJSON carries exactly txid/wtxid/bytes/vsize/weight/from — there is
## NO expiration field.
##
## This is a proven-teeth test: it builds a real RpcServer, inserts an orphan
## into the wired OrphanPool, calls getorphantxs via handleMethod, and asserts
## the exact shape + field values at verbosity 0, 1, and 2, plus the error path.
##
## Reference: bitcoin-core/src/rpc/mempool.cpp getorphantxs / OrphanToJSON.

import unittest2
import std/[os, options, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/consensus/validation
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mempool/orphan
import ../src/mining/fees
import ../src/rpc/server
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_getorphantxs_test"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc reverseHexLocal(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc toHexLower(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc makeOrphanTx(seed: byte): Transaction =
  ## A simple non-coinbase tx referencing a made-up (unseen) parent so it
  ## would genuinely be an orphan. Deterministic in `seed`.
  var parent: array[32, byte]
  for i in 0 ..< 32: parent[i] = seed xor 0xAA'u8
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(parent), vout: 0'u32),
      scriptSig: @[byte(seed), byte(0x51)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc buildRpcWithOrphan(pool: OrphanPool): RpcServer =
  ## Spin up a minimal RpcServer (regtest) and wire the orphan pool.
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  let rpc = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params)
  rpc.orphanPool = pool
  rpc

suite "getorphantxs — verbosity 0 (txid array)":

  test "empty orphanage returns empty array":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[])
    check resp.kind == JArray
    check resp.len == 0

  test "single orphan: array of one txid string (display/reversed hex)":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let tx = makeOrphanTx(0x11'u8)
    check pool.addOrphan(tx, ("198.51.100.7", 18444'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[0])
    check resp.kind == JArray
    check resp.len == 1
    # Core: verbosity 0 emits the NON-witness txid, NOT the wtxid.
    let expectedTxid = reverseHexLocal(toHexLower(array[32, byte](tx.txid())))
    check resp[0].kind == JString
    check resp[0].getStr() == expectedTxid

  test "verbosity defaults to 0 when omitted":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    check pool.addOrphan(makeOrphanTx(0x22'u8), ("203.0.113.9", 18444'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[])
    check resp.len == 1
    check resp[0].kind == JString  # bare txid, not an object

suite "getorphantxs — verbosity 1 (object array)":

  test "single orphan: full field set with correct values":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let tx = makeOrphanTx(0x33'u8)
    check pool.addOrphan(tx, ("198.51.100.7", 18444'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[1])
    check resp.kind == JArray
    check resp.len == 1
    let o = resp[0]

    # EXACT Core field set: txid, wtxid, bytes, vsize, weight, from.
    check o.hasKey("txid")
    check o.hasKey("wtxid")
    check o.hasKey("bytes")
    check o.hasKey("vsize")
    check o.hasKey("weight")
    check o.hasKey("from")
    # Core's OrphanToJSON has NO expiration field — must be absent.
    check (not o.hasKey("expiration"))
    # verbosity-1 must NOT carry the hex field (that's verbosity 2).
    check (not o.hasKey("hex"))
    # No extra fields beyond the 6 Core emits.
    check o.len == 6

    # txid / wtxid match the tx (display/reversed hex).
    check o["txid"].getStr() ==
      reverseHexLocal(toHexLower(array[32, byte](tx.txid())))
    check o["wtxid"].getStr() ==
      reverseHexLocal(toHexLower(array[32, byte](tx.wtxid())))

    # bytes = total serialized size (with witness); vsize/weight via the same
    # path getrawtransaction uses.
    let weight = calculateTransactionWeight(tx)
    check o["weight"].getInt() == weight
    check o["vsize"].getInt() == (weight + 3) div 4
    check o["bytes"].getInt() == serialize(tx, includeWitness = true).len

    # from = 1-element ["address:port"] array (nimrod tracks one announcer).
    check o["from"].kind == JArray
    check o["from"].len == 1
    check o["from"][0].getStr() == "198.51.100.7:18444"

  test "blank announcer yields an empty from array":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    check pool.addOrphan(makeOrphanTx(0x44'u8), ("", 0'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[1])
    check resp.len == 1
    check resp[0]["from"].kind == JArray
    check resp[0]["from"].len == 0

suite "getorphantxs — verbosity 2 (adds hex)":

  test "verbosity 2 = verbosity-1 fields plus serialized hex":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let tx = makeOrphanTx(0x55'u8)
    check pool.addOrphan(tx, ("198.51.100.7", 18444'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    let resp = rpc.handleMethod("getorphantxs", %*[2])
    check resp.len == 1
    let o = resp[0]
    # All verbosity-1 fields still present (exact Core set, NO expiration).
    for k in ["txid", "wtxid", "bytes", "vsize", "weight", "from"]:
      check o.hasKey(k)
    check (not o.hasKey("expiration"))
    # Plus hex = serialized (with-witness) hex of the orphan tx.
    check o.hasKey("hex")
    check o["hex"].getStr() == toHexLower(serialize(tx, includeWitness = true))
    # verbosity-1 fields (6) + hex = 7 total, nothing else.
    check o.len == 7

suite "getorphantxs — error path":

  test "verbosity out of range raises RPC_INVALID_PARAMETER (-8)":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    var raised = false
    var code = 0
    var msg = ""
    try:
      discard rpc.handleMethod("getorphantxs", %*[3])
    except RpcError as e:
      raised = true
      code = e.code
      msg = e.msg
    check raised
    check code == RpcInvalidParameter   # -8
    check "Invalid verbosity value 3" in msg

  test "negative verbosity raises RPC_INVALID_PARAMETER (-8)":
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    var raised = false
    try:
      discard rpc.handleMethod("getorphantxs", %*[-1])
    except RpcError as e:
      raised = true
      check e.code == RpcInvalidParameter
    check raised

  test "boolean verbosity is REJECTED, not mapped to 0/1 (allow_bool=false)":
    # Core: ParseVerbosity(..., allow_bool=false) throws on a JSON boolean.
    # A bool arg must error of SOME kind — it must NOT be silently accepted
    # as 0 (false) or 1 (true).
    cleanupTest()
    defer: cleanupTest()
    let pool = newOrphanPool()
    check pool.addOrphan(makeOrphanTx(0x66'u8), ("198.51.100.7", 18444'u16))
    let rpc = buildRpcWithOrphan(pool)
    defer: rpc.chainState.close()

    var raised = false
    try:
      discard rpc.handleMethod("getorphantxs", %*[true])
    except RpcError:
      raised = true
    check raised  # bool true must NOT be silently treated as verbosity 1

    raised = false
    try:
      discard rpc.handleMethod("getorphantxs", %*[false])
    except RpcError:
      raised = true
    check raised  # bool false must NOT be silently treated as verbosity 0
