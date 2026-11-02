## loadtxoutset must not merge a snapshot into a non-empty live chainstate.
##
## Security audit 2026-10-31, finding H7. `activateSnapshotAsActive` copies the
## authenticated snapshot coins into the live `cfUtxo` WITHOUT clearing it, and
## the RPC handler never looked at the live tip. On a node that had mined its
## own 10 blocks, `loadtxoutset utxo-299.dat` produced 309 txouts / 11,700 BTC
## (the fixture is 299 / 11,200) under a tip that claimed the snapshot base:
## the node's own coinbases, from a chain that is not an ancestor of the base,
## stayed spendable. A live tip at or above the base height was moved back to
## the base with no disconnect at all.
##
## Core keeps the snapshot in a SEPARATE chainstate, so the old coins can never
## merge, and refuses activation unless the snapshot has more work than the
## active tip (validation.cpp:5706, 5785-5788). nimrod has one coins store, so
## the handler now refuses unless the live chainstate is empty (genesis) or is
## already exactly at the snapshot base (the in-process re-verify case, where
## the live coins ARE the snapshot coins and nothing is copied).

import unittest2
import std/[os, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/storage/[chainstate, snapshot]
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
from ../src/network/peer import setFullHistoryAdvertise

var dirSeq = 0
proc freshDir(tag: string): string =
  inc dirSeq
  result = getTempDir() / ("nimrod_loadtxo_nonempty_" & tag & "_" &
    $getCurrentProcessId() & "_" & $dirSeq)
  if dirExists(result): removeDir(result)
  createDir(result)

proc makeP2WPKH(seed: byte): seq[byte] =
  var prog = newSeq[byte](20)
  prog[0] = seed
  @[byte(0x00), 0x14] & prog

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc makeCoinbaseTx(height: int32, extra: int32, spk: seq[byte]): Transaction =
  let h = @[byte(height and 0xff), byte((height shr 8) and 0xff),
            byte((height shr 16) and 0xff), byte((height shr 24) and 0xff)]
  let e = @[byte(extra and 0xff), byte((extra shr 8) and 0xff),
            byte((extra shr 16) and 0xff), byte((extra shr 24) and 0xff)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x04)] & h & @[byte(0x04)] & e,
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5000000000), scriptPubKey: spk)],
    witnesses: @[], lockTime: 0)

proc makeBlock(prevHash: BlockHash, height: int32,
               txs: seq[Transaction]): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs: txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1, prevBlock: prevHash, merkleRoot: merkleRoot(txHashes),
      timestamp: 1296688602'u32 + uint32(height * 600),
      bits: 0x207fffff'u32, nonce: uint32(height)),
    txs: txs)

proc genesisBlock(): Block =
  makeBlock(BlockHash(default(array[32, byte])), 0,
            @[makeCoinbaseTx(0, 0, makeP2WPKH(0))])

proc buildChain(cs: var ChainState, tipHeight: int32,
                branch: int32): BlockHash =
  ## Genesis, then coinbase-only blocks 1..tipHeight. `branch` goes into every
  ## coinbase, so two calls with different `branch` share only genesis.
  let genesis = genesisBlock()
  doAssert cs.connectBlock(genesis, 0).isOk
  var prev = getBlockHash(genesis)
  for height in 1'i32 .. tipHeight:
    let cb = makeCoinbaseTx(height, branch,
                            makeP2WPKH(byte((height + branch) and 0x7f)))
    let blk = makeBlock(prev, height, @[cb])
    doAssert cs.connectBlock(blk, height).isOk
    prev = getBlockHash(blk)
  prev

const BaseHeight = 102'i32

type Fixture = object
  root: string
  snapPath: string
  baseHash: BlockHash
  au: AssumeutxoData
  snapTxOuts: uint64

proc makeFixture(tag: string): Fixture =
  ## The snapshot: a 102-block chain on branch 0, dumped at its tip.
  result.root = freshDir(tag)
  let regtest = regtestParams()
  var source = newChainState(result.root / "source", regtest)
  result.baseHash = buildChain(source, BaseHeight, 0)
  result.snapPath = result.root / "snap.dat"
  let dump = createSnapshot(source, result.snapPath, regtest)
  doAssert dump.baseHeight == BaseHeight
  result.snapTxOuts =
    computeUtxoSetInfo(source, cshtHashSerialized).txOuts
  result.au = AssumeutxoData(height: BaseHeight,
    hashSerialized: dump.txoutsetHash, chainTxCount: 0'u64,
    blockhash: result.baseHash)
  source.close()

proc mkRpc(cs: ChainState, au: AssumeutxoData): RpcServer =
  let params = regtestParams()
  result = newRpcServer(port = 18443'u16, chainState = cs,
    mempool = newMempool(cs, params), peerManager = nil,
    feeEstimator = newFeeEstimator(), params = params)
  result.registerRegtestAssumeutxo(au)

proc loadError(rpc: RpcServer, path: string): string =
  ## "" when loadtxoutset succeeded, else "<code>: <message>".
  try:
    discard rpc.handleMethod("loadtxoutset", %*[path])
    ""
  except RpcError as e:
    $e.code & ": " & e.msg

proc refusesOwnChainAt(tipHeight: int32, tag: string) =
  ## A live node on its OWN chain (branch 7, not an ancestor of the base) at
  ## `tipHeight`: loadtxoutset must be refused and change nothing.
  let fx = makeFixture(tag)
  defer:
    try: removeDir(fx.root) except OSError: discard
  let regtest = regtestParams()
  var live = newChainState(fx.root / "live", regtest)
  let liveTip = buildChain(live, tipHeight, 7)
  let before = computeUtxoSetInfo(live, cshtHashSerialized)
  check before.txOuts == uint64(tipHeight)

  let rpc = mkRpc(live, fx.au)
  let err = loadError(rpc, fx.snapPath)
  check err.startsWith($RpcInternalError & ": Unable to load UTXO snapshot")

  # Nothing moved: same tip, same coins, no snapshot activation recorded.
  check live.bestHeight == tipHeight
  check live.bestBlockHash == liveTip
  check rpc.snapshotActivation == nil
  let after = computeUtxoSetInfo(live, cshtHashSerialized)
  check after.txOuts == before.txOuts
  check after.hashSerialized == before.hashSerialized
  check after.totalAmount == before.totalAmount
  live.close()

suite "loadtxoutset on a non-empty live chainstate (audit H7)":

  # A successful load stops advertising NODE_NETWORK through a process-wide
  # flag; restore it so later files in the aggregate (test_w168_service_flags)
  # see a full node.
  setup:
    setFullHistoryAdvertise(true)

  teardown:
    setFullHistoryAdvertise(true)

  test "own chain at tip 10, below the base: refused, live coins untouched":
    ## The audit's repro shape. On master this merged 10 own coinbases into
    ## the snapshot's set and moved the tip to the base.
    refusesOwnChainAt(10, "below")

  test "own chain at exactly the base height, different hash: refused":
    ## Height alone must not satisfy the guard: same height as the base, but
    ## the wrong block. On master the tip was re-pointed with no disconnect.
    refusesOwnChainAt(BaseHeight, "sameheight")

  test "own chain above the base: refused, no silent rewind":
    refusesOwnChainAt(BaseHeight + 8, "above")

  test "fresh node at genesis: loads exactly the snapshot's coins (control)":
    ## The boot-smoke path. Must keep working: same coin count and the same
    ## hash_serialized_3 the snapshot commits to, tip at the base.
    let fx = makeFixture("fresh")
    defer:
      try: removeDir(fx.root) except OSError: discard
    let regtest = regtestParams()
    var live = newChainState(fx.root / "live", regtest)
    doAssert live.connectBlock(genesisBlock(), 0).isOk
    check live.bestHeight == 0

    let rpc = mkRpc(live, fx.au)
    check loadError(rpc, fx.snapPath) == ""
    check live.bestHeight == BaseHeight
    check live.bestBlockHash == fx.baseHash
    let info = computeUtxoSetInfo(live, cshtHashSerialized)
    check info.txOuts == fx.snapTxOuts
    check info.hashSerialized == fx.au.hashSerialized
    live.close()

  test "live chain already at the snapshot base: still loads (re-verify case)":
    ## The in-process dual-chainstate case: the live coins ARE the snapshot's,
    ## nothing is copied, and the background re-derivation validates.
    let root = freshDir("atbase")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var live = newChainState(root / "live", regtest)
    let baseHash = buildChain(live, BaseHeight, 0)
    let snapPath = root / "snap.dat"
    let dump = createSnapshot(live, snapPath, regtest)
    let rpc = mkRpc(live, AssumeutxoData(height: BaseHeight,
      hashSerialized: dump.txoutsetHash, chainTxCount: 0'u64,
      blockhash: baseHash))
    let res = rpc.handleMethod("loadtxoutset", %*[snapPath])
    check res["validated"].getBool == true
    check live.bestBlockHash == baseHash
    check computeUtxoSetInfo(live, cshtHashSerialized).hashSerialized ==
      dump.txoutsetHash
    live.close()

  test "live tip at a DIFFERENT whitelisted base: refused after the load":
    ## The at-base exception must mean THIS file's base. Live sits at height
    ## 50, which is whitelisted too; the file is for 102. Copying would merge
    ## live's coins into the 102 set, so it must be refused, live untouched.
    let fx = makeFixture("otherbase")
    defer:
      try: removeDir(fx.root) except OSError: discard
    let regtest = regtestParams()
    var live = newChainState(fx.root / "live", regtest)
    let liveTip = buildChain(live, 50, 7)
    let before = computeUtxoSetInfo(live, cshtHashSerialized)
    let rpc = mkRpc(live, fx.au)
    rpc.registerRegtestAssumeutxo(AssumeutxoData(height: 50,
      hashSerialized: before.hashSerialized, chainTxCount: 0'u64,
      blockhash: liveTip))
    let err = loadError(rpc, fx.snapPath)
    check err.startsWith($RpcInternalError & ": Unable to load UTXO snapshot")
    check "not the snapshot base" in err
    check live.bestHeight == 50
    check live.bestBlockHash == liveTip
    check rpc.snapshotActivation == nil
    let after = computeUtxoSetInfo(live, cshtHashSerialized)
    check after.txOuts == before.txOuts
    check after.hashSerialized == before.hashSerialized
    live.close()
