## getchainstates RPC — Bitcoin Core v31.99 parity.
##
## Adds Bitcoin Core's `getchainstates` RPC to nimrod.
## Reference: bitcoin-core/src/rpc/blockchain.cpp::getchainstates (line 3462) +
## RPCHelpForChainstate (3449-3460) / make_chain_data.
##
## Core returns:
##   {
##     "headers": <int>,                 # best-header height (-1 if none)
##     "chainstates": [                   # ordered by work, active chainstate LAST
##       {
##         "blocks": <int>,
##         "bestblockhash": <hex>,
##         "bits": <hex>,                 # strprintf("%08x", nBits)
##         "target": <hex>,               # GetTarget(...).GetHex()
##         "difficulty": <num>,
##         "verificationprogress": <num>,
##         "snapshot_blockhash": <hex>,   # OPTIONAL — only for a from-snapshot chainstate
##         "coins_db_cache_bytes": <int>,
##         "coins_tip_cache_bytes": <int>,
##         "validated": <bool>
##       }
##     ]
##   }
##
## nimrod runs a single, fully-validated chainstate (no live unvalidated
## snapshot chainstate), so `chainstates` is a 1-element array whose entry has
## validated=true and NO snapshot_blockhash key.

import std/[unittest, os, strutils, json]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/[db, chainstate]
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_getchainstates_test"
const TestBlocksDir = "/tmp/nimrod_getchainstates_blocks"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)
  if dirExists(TestBlocksDir):
    removeDir(TestBlocksDir)

proc reverseHex(hex: string): string =
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

proc makeBlock(prevHash: BlockHash, height: int32): Block =
  ## A minimal one-tx block; only the header (prevBlock/bits/timestamp) matters
  ## for getchainstates (it reads the tip's nBits + hash + height).
  let tx = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
      scriptSig: @[byte(0x51), byte(height and 0xff)],
      sequence: 0xffffffff'u32)],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(@[array[32, byte](tx.txid())]),
      timestamp: 1296688602'u32 + uint32(height * 600),
      bits: 0x207fffff'u32,   # regtest genesisBits
      nonce: uint32(height)),
    txs: @[tx])

# ---------------------------------------------------------------------------
# Source-level guards: the method is registered + the handler emits every
# required field. Cheap protection against a future drive-by that drops a
# field or unregisters the method.
# ---------------------------------------------------------------------------
suite "getchainstates registration + shape (source)":

  const ServerPath =
    if fileExists("src/rpc/server.nim"): "src/rpc/server.nim"
    else: "../src/rpc/server.nim"

  test "getchainstates is registered in the RPC dispatch":
    let src = readFile(ServerPath)
    check "of \"getchainstates\":" in src
    check "rpc.handleGetChainStates()" in src

  test "handler emits every required Core field":
    let src = readFile(ServerPath)
    for field in ["\"headers\"", "\"chainstates\"", "\"blocks\"",
                  "\"bestblockhash\"", "\"bits\"", "\"target\"",
                  "\"difficulty\"", "\"verificationprogress\"",
                  "\"coins_db_cache_bytes\"", "\"coins_tip_cache_bytes\"",
                  "\"validated\""]:
      check field in src

# ---------------------------------------------------------------------------
# Behavioral end-to-end: build a real ChainState + RpcServer on regtest,
# advance the tip to height 1, call handleMethod("getchainstates"), and
# assert the full Core-parity shape with GENUINE values.
# ---------------------------------------------------------------------------
suite "getchainstates behavioral (real chainstate)":

  test "returns headers + 1-element chainstates with all fields, validated, no snapshot_blockhash":
    cleanupTest()
    defer: cleanupTest()

    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()

    # Advance the active chainstate tip to height 1 with a genuine block, so
    # blocks/bestblockhash/bits come from real state (not the empty default).
    let prevHash = BlockHash(default(array[32, byte]))
    let blk = makeBlock(prevHash, 1'i32)
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    var idx = BlockIndex(
      hash: blockHash,
      height: 1'i32,
      status: bsValidated,
      prevHash: prevHash,
      header: blk.header,
      totalWork: default(array[32, byte]),
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0,
      nTx: 1'i32)
    cs.db.putBlockIndex(idx)
    cs.db.storeBlock(blk)                 # so getBlock(tip) returns the real nBits
    cs.db.updateBestBlock(blockHash, 1'i32)
    cs.bestBlockHash = blockHash
    cs.bestHeight = 1'i32

    var mp = newMempool(cs, params, fullRbf = false)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params)

    let resp = rpc.handleMethod("getchainstates", %*[])

    # --- top-level shape -----------------------------------------------------
    check resp.kind == JObject
    check resp.hasKey("headers")
    check resp["headers"].kind == JInt
    check resp["headers"].getInt() == 1          # headers == active tip height

    check resp.hasKey("chainstates")
    check resp["chainstates"].kind == JArray
    check resp["chainstates"].len == 1           # single chainstate

    let csNode = resp["chainstates"][0]
    check csNode.kind == JObject

    # --- required fields present + correct types -----------------------------
    check csNode.hasKey("blocks")
    check csNode["blocks"].kind == JInt
    check csNode["blocks"].getInt() == 1

    check csNode.hasKey("bestblockhash")
    check csNode["bestblockhash"].kind == JString
    check csNode["bestblockhash"].getStr().len == 64
    # bestblockhash is the display (big-endian) form of the tip hash.
    check csNode["bestblockhash"].getStr() ==
      reverseHex(toHexLower(array[32, byte](blockHash)))

    check csNode.hasKey("bits")
    check csNode["bits"].kind == JString
    check csNode["bits"].getStr().len == 8
    check csNode["bits"].getStr() == "207fffff"  # regtest nBits, big-endian %08x

    check csNode.hasKey("target")
    check csNode["target"].kind == JString
    check csNode["target"].getStr().len == 64

    check csNode.hasKey("difficulty")
    # difficulty is emitted via difficultyJson — a raw-number JsonNode (the
    # rawFloats/isUnquoted trick the whole codebase uses for byte-exact Core
    # std::setprecision(16) output). Its node kind is JString-internally but it
    # serializes as a BARE NUMBER, not a quoted string. Assert that: the JSON
    # token must not be quoted, and must parse to a positive float.
    let diffJson = $csNode["difficulty"]
    check not diffJson.startsWith("\"")
    check parseFloat(diffJson) > 0.0

    check csNode.hasKey("verificationprogress")
    check csNode["verificationprogress"].kind in {JInt, JFloat}
    check csNode["verificationprogress"].getFloat() == 1.0  # headers == blocks

    check csNode.hasKey("coins_db_cache_bytes")
    check csNode["coins_db_cache_bytes"].kind == JInt
    check csNode["coins_db_cache_bytes"].getBiggestInt() > 0
    check csNode["coins_db_cache_bytes"].getBiggestInt() == int64(BlockCacheSize)

    check csNode.hasKey("coins_tip_cache_bytes")
    check csNode["coins_tip_cache_bytes"].kind == JInt
    check csNode["coins_tip_cache_bytes"].getBiggestInt() > 0

    check csNode.hasKey("validated")
    check csNode["validated"].kind == JBool
    check csNode["validated"].getBool() == true

    # --- snapshot_blockhash MUST be absent (no live snapshot chainstate) -----
    check not csNode.hasKey("snapshot_blockhash")
