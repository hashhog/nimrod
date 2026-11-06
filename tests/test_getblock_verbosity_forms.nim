## getblock verbosity forms must match Bitcoin Core (rpc/blockchain.cpp getblock,
## ParseVerbosity with allow_bool=true):
##   * JSON `true` is verbosity 1 and `false` is 0. Nim's JsonNode.getInt() is 0
##     for a bool, so `getblock <hash> true` used to return the raw hex.
##   * verbosity >= 3 (any value, Core has no upper bound) is
##     TxVerbosity::SHOW_DETAILS_AND_PREVOUT: each non-coinbase vin carries
##     prevout {generated, height, value, scriptPubKey}.
## Found by the Core-regtest operator group (operator/getblock/true:$,
## operator/getblock/bad-verbosity:tx[N].vin[0].prevout).
##   nim c -r tests/test_getblock_verbosity_forms.nim

import unittest2
import std/[os, json, options, strutils]
import ../src/rpc/server
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/mempool/mempool
import ../src/mining/fees

var testDbSeq = 0

proc freshDbPath(): string =
  inc testDbSeq
  result = "/tmp/nimrod_getblock_verb_" & $getCurrentProcessId() & "_" & $testDbSeq
  if dirExists(result):
    removeDir(result)

proc cleanupDb(path: string) =
  if dirExists(path):
    try: removeDir(path)
    except CatchableError, OSError: discard

let p2pkh = @[byte(0x76), 0xa9, 0x14] &
  @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]

proc coinbaseTx(height: int32): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(height and 0xff)],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(50_0000_0000), scriptPubKey: p2pkh)],
    witnesses: @[],
    lockTime: 0)

proc spendTx(prev: TxId): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: prev, vout: 0),
                   scriptSig: @[byte(0x51)], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(49_0000_0000), scriptPubKey: p2pkh)],
    witnesses: @[],
    lockTime: 0)

proc mkBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hashes: seq[array[32, byte]]
  for t in txs: hashes.add(array[32, byte](t.txid()))
  Block(
    header: BlockHeader(
      version: 1, prevBlock: prevHash, merkleRoot: merkleRoot(hashes),
      timestamp: 1231006505'u32 + uint32(height * 600),
      bits: 0x207fffff'u32, nonce: uint32(height)),
    txs: txs)

proc blockHashOf(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc rpcWithChainState(cs: ChainState): RpcServer =
  let params = regtestParams()
  newRpcServer(port = 18443'u16, chainState = cs,
    mempool = newMempool(cs, params, fullRbf = false), peerManager = nil,
    feeEstimator = newFeeEstimator(), params = params)

proc hashHex(h: array[32, byte]): string =
  ## Display order (byte-reversed) lowercase hex.
  const digits = "0123456789abcdef"
  for i in countdown(31, 0):
    result.add(digits[int(h[i] shr 4)])
    result.add(digits[int(h[i] and 15)])

suite "getblock verbosity forms":
  test "bool verbosity is 1/0, verbosity >= 3 adds prevout":
    let dbPath = freshDbPath()
    var cs = newChainState(dbPath, regtestParams())
    defer:
      cs.close()
      cleanupDb(dbPath)
    let b0 = mkBlock(BlockHash(default(array[32, byte])), 0, @[coinbaseTx(0)])
    check cs.connectBlock(b0, 0).isOk
    # Coinbase maturity is 100: the coinbase of block 1 is spendable in block 101.
    var prev = blockHashOf(b0)
    var cb1: TxId
    for ht in 1'i32 .. 100'i32:
      let blk = mkBlock(prev, ht, @[coinbaseTx(ht)])
      if ht == 1: cb1 = blk.txs[0].txid()
      check cs.connectBlock(blk, ht).isOk
      prev = blockHashOf(blk)
    let b2 = mkBlock(prev, 101, @[coinbaseTx(101), spendTx(cb1)])
    check cs.connectBlock(b2, 101).isOk
    let rpc = rpcWithChainState(cs)
    let h = hashHex(array[32, byte](blockHashOf(b2)))

    # true == verbosity 1: decoded object whose tx entries are txid strings.
    let asTrue = rpc.handleMethod("getblock", %*[h, true])
    check asTrue.kind == JObject
    if asTrue.kind == JObject:
      check asTrue["height"].getInt() == 101
      check asTrue["tx"][0].kind == JString
    # false == verbosity 0: raw hex string.
    check rpc.handleMethod("getblock", %*[h, false]).kind == JString
    check rpc.handleMethod("getblock", %*[h, 0]).kind == JString

    # verbosity 2: no prevout. Verbosity 3 and 9 (Core has no upper bound): prevout.
    let v2 = rpc.handleMethod("getblock", %*[h, 2])
    check not v2["tx"][1]["vin"][0].hasKey("prevout")
    for v in [3, 9]:
      let r = rpc.handleMethod("getblock", %*[h, v])
      let vin = r["tx"][1]["vin"][0]
      check vin.hasKey("prevout")
      if vin.hasKey("prevout"):
        let po = vin["prevout"]
        check po["generated"].getBool() == true
        check po["height"].getInt() == 1
        check parseFloat($po["value"]) == 50.0
        check po["scriptPubKey"]["hex"].getStr() == "76a914" & "00".repeat(20) & "88ac"
      # coinbase vin never gets a prevout
      check not r["tx"][0]["vin"][0].hasKey("prevout")
