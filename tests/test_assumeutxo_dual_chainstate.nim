## AssumeUTXO — REAL background second chainstate (dual-chainstate parity).
##
## Proves nimrod's snapshot machinery now performs Bitcoin Core's trustless
## background re-verification (validation.cpp ActivateSnapshot:5588 /
## AddChainstate:6170 / MaybeValidateSnapshot:5967), not just the load-time
## file-authentication gate:
##
##   - loadtxoutset loads the snapshot into an ISOLATED store and spins up a
##     SECOND background chainstate with its OWN separate coins store
##     (storage/snapshot.nim::makeBackgroundChainState).
##   - that bg chainstate re-connects every block genesis->base via REAL block
##     connection (spend inputs, add outputs — connectBlock), NOT a counter.
##   - at the base it recomputes the bg store's HASH_SERIALIZED
##     (computeUtxoSetInfo cshtHashSerialized) and compares to the assumeUTXO
##     commitment. MATCH -> snapshot validated; MISMATCH -> snapshot INVALID.
##   - getchainstates reports the verdict (validated + snapshot_blockhash).
##
## The four required assertions (mirroring the lunarblock a39dd42 / camlcoin
## 2675b31+3140ab9 / blockbrew bfd429a+a38b4c1 / hotbuns 03ca675+7d53d12 pilots):
##   (a) SEPARATE store — an active-store write is NOT visible in the bg store.
##   (b) REAL connect — the bg store == an independently-computed UTXO set,
##       not empty / not a counter.
##   (c) ACCEPT — a snapshot committing to the CORRECT hash validates.
##   (d) REJECT — a deliberately-inconsistent snapshot (commits to its OWN hash
##       so it passes the load gate, but inconsistent with the genesis->base
##       replay) is REJECTED by the background re-derivation (validated=false).

import unittest2
import std/[os, options, tables, json, strutils]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params
import ../src/storage/[chainstate, snapshot]
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

# ---------------------------------------------------------------------------
# Unique temp-dir helper (no leftover state between runs / parallel jobs).
# ---------------------------------------------------------------------------
var dirSeq = 0
proc freshDir(tag: string): string =
  inc dirSeq
  result = getTempDir() / ("nimrod_au_dual_" & tag & "_" &
    $getCurrentProcessId() & "_" & $dirSeq)
  if dirExists(result): removeDir(result)
  createDir(result)

# ---------------------------------------------------------------------------
# Real block builders (modelled on tests/test_connect_block_w93.nim).
# ---------------------------------------------------------------------------
proc makeP2WPKH(seed: byte = 0): seq[byte] =
  var prog = newSeq[byte](20)
  prog[0] = seed
  @[byte(0x00), 0x14] & prog

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc makeCoinbaseTx(height: int32, extra: int32 = 0,
                    spk: seq[byte] = makeP2WPKH()): Transaction =
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

proc makeSpendingTx(prevTxid: TxId, prevVout: uint32,
                    value: int64, spk: seq[byte]): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: prevTxid, vout: prevVout),
      scriptSig: @[byte(0x00)], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: spk)],
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

## Build a real regtest chain genesis->base with a REAL spend, connecting every
## block into `cs`. Returns (baseHeight, baseHash). The chain:
##   h0          genesis (no UTXO mutation)
##   h1          coinbase C1
##   h2..h101    coinbases (mine C1 to maturity — regtest coinbaseMaturity=100)
##   h102        coinbase + a tx spending the now-MATURE C1 -> two new coins
##               (a genuine input-spend, so the UTXO set is non-trivial).
const BaseHeight = 102'i32
proc buildChain(cs: var ChainState): tuple[height: int32, hash: BlockHash] =
  let genesis = makeBlock(BlockHash(default(array[32, byte])), 0,
                          @[makeCoinbaseTx(0)])
  doAssert cs.connectBlock(genesis, 0).isOk
  var prev = getBlockHash(genesis)
  let h1 = makeBlock(prev, 1, @[makeCoinbaseTx(1, spk = makeP2WPKH(1))])
  doAssert cs.connectBlock(h1, 1).isOk
  let cb1Txid = h1.txs[0].txid()
  prev = getBlockHash(h1)
  # Mine coinbases h2..h101 so the h1 coinbase reaches maturity at h102.
  for height in 2'i32 .. 101'i32:
    let cb = makeCoinbaseTx(height, spk = makeP2WPKH(byte(height and 0x7f)))
    let blk = makeBlock(prev, height, @[cb])
    doAssert cs.connectBlock(blk, height).isOk
    prev = getBlockHash(blk)
  # h102: coinbase + spend the (now mature) h1 coinbase into two outputs.
  let cb102 = makeCoinbaseTx(102, spk = makeP2WPKH(0x70))
  let spend = makeSpendingTx(cb1Txid, 0, 2_500_000_000, makeP2WPKH(0x71))
  let h102 = makeBlock(prev, 102, @[cb102, spend])
  doAssert cs.connectBlock(h102, 102).isOk
  (BaseHeight, getBlockHash(h102))

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc independentUtxoSet(cs: var ChainState):
    Table[string, tuple[value: int64, height: int32, coinbase: bool]] =
  ## A reference UTXO set computed by walking `cs`'s own coins (used to prove
  ## the bg store is a REAL set, independent of any snapshot/counter).
  result = initTable[string, tuple[value: int64, height: int32, coinbase: bool]]()
  for (op, entry) in cs.iterateUtxos():
    let k = hexOf(array[32, byte](op.txid)) & ":" & $op.vout
    result[k] = (int64(entry.output.value), entry.height, entry.isCoinbase)

proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
  let mp = newMempool(cs, params)
  let fe = newFeeEstimator()
  newRpcServer(port = 18443'u16, chainState = cs, mempool = mp,
               peerManager = nil, feeEstimator = fe, params = params)

# ===========================================================================

suite "AssumeUTXO dual-chainstate — real background second chainstate":

  test "(a) SEPARATE store: an active-store write is NOT visible in the bg store":
    ## Aliasing falsification. After loadtxoutset activates the snapshot, the
    ## background store is a DISTINCT ChainState/ChainDb. A write into the
    ## active chainstate must be invisible in the background store.
    let root = freshDir("sep")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var cs = newChainState(root / "active", regtest)
    let (baseHeight, baseHash) = buildChain(cs)

    let snapPath = root / "snap.dat"
    let dump = createSnapshot(cs, snapPath, regtest)
    check dump.baseHeight == baseHeight

    let rpc = mkRpc(cs, regtest)
    rpc.registerRegtestAssumeutxo(AssumeutxoData(
      height: baseHeight, hashSerialized: dump.txoutsetHash,
      chainTxCount: 0'u64, blockhash: baseHash))

    let res = rpc.handleLoadTxOutSetImpl(snapPath)
    check res["validated"].getBool == true
    check rpc.snapshotActivation != nil

    # The bg store and the active store are different objects.
    check (rpc.snapshotActivation.background.db != cs.db)
    check (rpc.snapshotActivation.background.db !=
           rpc.snapshotActivation.snapshot.chainState.db)

    # Write a fresh UTXO into the ACTIVE store; it must NOT appear in the bg store.
    let aliasOp = OutPoint(txid: TxId(default(array[32, byte])), vout: 7'u32)
    let aliasEntry = UtxoEntry(
      output: TxOut(value: Satoshi(123), scriptPubKey: makeP2WPKH(9)),
      height: 99'i32, isCoinbase: false)
    cs.putUtxoCache(aliasOp, aliasEntry)
    cs.flushCache()
    check cs.getUtxo(aliasOp).isSome                                  # in active
    check rpc.snapshotActivation.background.getUtxo(aliasOp).isNone   # NOT in bg
    cs.close()

  test "(b) REAL connect: bg store == independently-computed set (not empty/counter)":
    ## The background store, after genesis->base re-connection, must hold the
    ## SAME UTXO set the active chain holds — proving real block connection
    ## (spend inputs + add outputs), not a counter or an empty set.
    let root = freshDir("real")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var cs = newChainState(root / "active", regtest)
    let (baseHeight, baseHash) = buildChain(cs)

    # createSnapshot reads the in-memory UTXO cache, so snapshot the chain
    # BEFORE any cache-flushing walk (independentUtxoSet/computeUtxoSetInfo
    # call flushCache, which empties the cache).
    let snapPath = root / "snap.dat"
    let dump = createSnapshot(cs, snapPath, regtest)

    let reference = independentUtxoSet(cs)   # what the bg store MUST reproduce
    check reference.len >= 3                 # 101 coinbases + 2 spend outs, cb1 spent

    let rpc = mkRpc(cs, regtest)
    rpc.registerRegtestAssumeutxo(AssumeutxoData(
      height: baseHeight, hashSerialized: dump.txoutsetHash,
      chainTxCount: 0'u64, blockhash: baseHash))
    let res = rpc.handleLoadTxOutSetImpl(snapPath)
    check res["validated"].getBool == true

    # Walk the bg store's coins and compare to the independent reference.
    var bg = rpc.snapshotActivation.background
    let bgSet = independentUtxoSet(bg)
    check bgSet.len == reference.len
    check bgSet.len > 0                       # NOT empty (counter falsification)
    for k, v in reference:
      check bgSet.hasKey(k)
      check bgSet[k] == v
    # The h1 coinbase was spent in h2, so the bg set must NOT contain it —
    # the reference (which also excludes it) matching bgSet exactly proves the
    # bg store applied the real spend rather than a naive add-all-outputs.
    cs.close()

  test "(c) ACCEPT: snapshot committing to the CORRECT hash validates":
    ## The happy path: the snapshot file's coins hash to the assumeUTXO
    ## commitment, the bg re-derivation matches, getchainstates validated=true,
    ## snapshot_blockhash is the base.
    let root = freshDir("accept")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var cs = newChainState(root / "active", regtest)
    let (baseHeight, baseHash) = buildChain(cs)

    let snapPath = root / "snap.dat"
    let dump = createSnapshot(cs, snapPath, regtest)
    let rpc = mkRpc(cs, regtest)
    rpc.registerRegtestAssumeutxo(AssumeutxoData(
      height: baseHeight, hashSerialized: dump.txoutsetHash,
      chainTxCount: 0'u64, blockhash: baseHash))

    let res = rpc.handleLoadTxOutSetImpl(snapPath)
    check res["validated"].getBool == true
    check rpc.snapshotActivation.snapshot.assumeutxo == auValidated

    # getchainstates reflects the verdict.
    let gcs = rpc.handleMethod("getchainstates", newJArray())
    let cstate = gcs["chainstates"][0]
    check cstate["validated"].getBool == true
    check cstate.hasKey("snapshot_blockhash")
    cs.close()

  test "(d) REJECT: a bg-inconsistent snapshot is rejected by the re-derivation":
    ## THE CRITICAL falsification. Build a TAMPERED snapshot whose OWN coins
    ## hash to a value we commit in the whitelist (so it PASSES the load-time
    ## gate), but which is INCONSISTENT with the genesis->base block replay.
    ## The background re-derivation (over the real blocks) recomputes a
    ## DIFFERENT hash -> MISMATCH -> snapshot INVALID, validated=false. A
    ## wrong snapshot is NEVER silently accepted.
    let root = freshDir("reject")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var cs = newChainState(root / "active", regtest)
    let (baseHeight, baseHash) = buildChain(cs)

    # Build a TAMPERED chainstate at the SAME base hash/height but with an
    # extra coin the real chain does not contain. createSnapshot reads the
    # in-memory cache, so we seed the cache (and must NOT flush it before the
    # dump) — the tampered store is only ever used as the snapshot source.
    var tampered = newChainState(root / "tampered", regtest)
    # Replay the real coins into `tampered` (this flushes cs's cache; the cs
    # block bodies stay on disk for the later background replay) ...
    for (op, entry) in cs.iterateUtxos():
      tampered.putUtxoCache(op, entry)
    # ... then INJECT one phantom coin that the genesis->base replay never adds.
    let phantomOp = OutPoint(txid: TxId(default(array[32, byte])), vout: 1234'u32)
    tampered.putUtxoCache(phantomOp, UtxoEntry(
      output: TxOut(value: Satoshi(777), scriptPubKey: makeP2WPKH(0xEE)),
      height: 1'i32, isCoinbase: false))
    tampered.bestBlockHash = baseHash   # same base hash so it passes the load whitelist
    tampered.bestHeight = baseHeight

    let snapPath = root / "tampered_snap.dat"
    let tdump = createSnapshot(tampered, snapPath, regtest)
    tampered.close()

    let rpc = mkRpc(cs, regtest)
    # Commit to the TAMPERED snapshot's OWN hash so the load-time gate passes.
    rpc.registerRegtestAssumeutxo(AssumeutxoData(
      height: baseHeight, hashSerialized: tdump.txoutsetHash,
      chainTxCount: 0'u64, blockhash: baseHash))

    let res = rpc.handleLoadTxOutSetImpl(snapPath)
    # loadtxoutset returns Ok (Core async AbortNode model) but validated=false.
    check res["validated"].getBool == false
    check res.hasKey("validation_error")
    check ("mismatch" in res["validation_error"].getStr.toLowerAscii)
    # The snapshot chainstate was marked INVALID, never validated.
    check rpc.snapshotActivation.snapshot.assumeutxo == auInvalid

    # getchainstates also reports validated=false.
    let gcs = rpc.handleMethod("getchainstates", newJArray())
    check gcs["chainstates"][0]["validated"].getBool == false
    cs.close()

  test "non-vacuity: the tampered hash truly differs from the real chain hash":
    ## Guards against a vacuous reject test (e.g. if the tampered set happened
    ## to hash identically). The phantom-coin snapshot's hash MUST differ from
    ## the real chain's snapshot hash, otherwise (d) proves nothing.
    let root = freshDir("nonvac")
    defer:
      try: removeDir(root) except OSError: discard
    let regtest = regtestParams()
    var cs = newChainState(root / "active", regtest)
    discard buildChain(cs)
    let realHash = computeUtxoSetInfo(cs, cshtHashSerialized).hashSerialized

    var tampered = newChainState(root / "tampered", regtest)
    for (op, entry) in cs.iterateUtxos():
      tampered.putUtxoCache(op, entry)
    tampered.putUtxoCache(
      OutPoint(txid: TxId(default(array[32, byte])), vout: 1234'u32),
      UtxoEntry(output: TxOut(value: Satoshi(777), scriptPubKey: makeP2WPKH(0xEE)),
                height: 1'i32, isCoinbase: false))
    tampered.flushCache()
    let tamperedHash = computeUtxoSetInfo(tampered, cshtHashSerialized).hashSerialized
    check realHash != tamperedHash
    tampered.close()
    cs.close()
