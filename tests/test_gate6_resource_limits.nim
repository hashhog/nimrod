## Gate 6 — a resource failure is never a consensus verdict.
##
## docs/RELEASE-CHECKLIST.md gate 6: OOM, heap caps, I/O errors and timeouts
## lead to retry or halt, never to a reject or an accept. Audit:
## receipts/gate6-resource-limit-audit-2026-10-04.md (nimrod: F11, F7a).
##
## Core's model: CCoinsViewCache is discarded on a failed ConnectBlock and
## cleared only after BatchWrite succeeds; a failed flush / write / coins read
## is FatalError -> AbortNode (validation.cpp:2136): stop connecting, mark
## nothing, punish nobody, skip the shutdown flush, exit non-zero. Script
## checks report only ScriptError values; bad_alloc terminates.
##
## Every fault below is injected through a test-only hook that is identical
## on the deployed tree (f6aaa00 + hooks) and on the fix, so each test is a
## real fail-before / pass-after. The controls (genuinely invalid blocks keep
## their verdicts) pass on both.

import unittest2
import std/[options, os, tables, strutils, atomics]
import chronos
import ../src/network/sync
import ../src/network/peer
import ../src/network/peermanager
import ../src/network/messages
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/storage/db
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter
import ../src/perf/verify_pool
import ../src/util/fatal

const EASY_BITS = 0x207fffff'u32
const OpTrue = @[byte(0x51)]
const Coin = 100_000_000'i64

# ---------------------------------------------------------------------------
# Hooks (plain procs + global atomics: the script hook can run on a pool
# worker thread when another suite in the aggregate started the pool).
# ---------------------------------------------------------------------------
var gFailWrites: Atomic[bool]      # dfoWrite + dfoWriteSync
var gFailFlush: Atomic[bool]       # dfoFlush
var gFailUtxoGets: Atomic[bool]    # dfoGet on cfUtxo
var gScriptFaults: Atomic[int]     # >0: fail that many script checks; -1: all
var gSecpFault: Atomic[bool]

proc dbHook(op: DbFaultOp, cf: ColumnFamily): bool {.gcsafe, raises: [].} =
  case op
  of dfoWrite, dfoWriteSync: gFailWrites.load()
  of dfoFlush: gFailFlush.load()
  of dfoGet: gFailUtxoGets.load() and cf == cfUtxo
  else: false

proc scriptHook(inputIndex: int): bool {.gcsafe, raises: [].} =
  let n = gScriptFaults.load()
  if n < 0: return true
  if n == 0: return false
  gScriptFaults.store(n - 1)
  true

proc secpHook(): bool {.gcsafe, raises: [].} = gSecpFault.load()

proc disarmAll() =
  gFailWrites.store(false); gFailFlush.store(false); gFailUtxoGets.store(false)
  gScriptFaults.store(0); gSecpFault.store(false)

proc installHooks() =
  disarmAll()
  dbFaultHook = dbHook
  scriptCheckFaultHook = scriptHook
  secpContextFaultHook = secpHook
  resetFatalForTest()

proc removeHooks() =
  disarmAll()
  dbFaultHook = nil
  scriptCheckFaultHook = nil
  secpContextFaultHook = nil
  resetFatalForTest()

# ---------------------------------------------------------------------------
# Chain building
# ---------------------------------------------------------------------------
proc hashOf(h: BlockHeader): BlockHash = BlockHash(doubleSha256(serialize(h)))
proc hashOf(b: Block): BlockHash = hashOf(b.header)

proc tapscriptLeaf(): seq[byte] = @[byte(0x51)]   # OP_TRUE tapscript

proc tapleafHash(script: seq[byte]): array[32, byte] =
  var leaf: seq[byte] = @[0xC0'u8]
  var w = BinaryWriter()
  w.writeVarBytes(script)
  leaf.add(w.data)
  taggedHash("TapLeaf", leaf)

proc internalKey(): array[32, byte] =
  var pk: PrivateKey
  pk[31] = 1
  let c = derivePublicKey(pk)
  for i in 0 ..< 32: result[i] = c[1 + i]

proc taprootOutput(): tuple[spk: seq[byte], control: seq[byte]] =
  ## P2TR output committing to a single OP_TRUE leaf, and the control block
  ## that spends it by the script path.
  let ipk = internalKey()
  let root = tapleafHash(tapscriptLeaf())
  var tw: seq[byte]
  for b in ipk: tw.add(b)
  for b in root: tw.add(b)
  let (q, parity) = tweakXonlyPubkey(ipk, taggedHash("TapTweak", tw))
  result.spk = @[byte(0x51), 0x20] & @q
  result.control = @[byte(0xC0'u8 or uint8(parity and 1))] & @ipk

proc coinbaseTx(height: int32, outs: seq[TxOut], tag: byte,
                witnessReserved: bool): Transaction =
  result = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x00), tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: outs, witnesses: @[], lockTime: 0)
  if witnessReserved:
    result.witnesses = @[@[newSeq[byte](32)]]

proc mine(prevHash: BlockHash, ts: uint32, height: int32, tag: byte,
          spends: seq[Transaction], cbValue: int64 = 50 * Coin,
          cbSpk: seq[byte] = OpTrue): Block =
  var hasWitness = false
  for t in spends:
    for w in t.witnesses:
      if w.len > 0: hasWitness = true
  var outs = @[TxOut(value: Satoshi(cbValue), scriptPubKey: cbSpk)]
  if hasWitness:
    var wtxids: seq[array[32, byte]] = @[default(array[32, byte])]
    for t in spends: wtxids.add(array[32, byte](t.wtxid()))
    let commitment = computeWitnessCommitment(wtxids, default(array[32, byte]))
    outs.add(TxOut(value: Satoshi(0),
                   scriptPubKey: @[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed] & @commitment))
  let cb = coinbaseTx(height, outs, tag, hasWitness)
  var txs = @[cb] & spends
  var ids: seq[array[32, byte]]
  for t in txs: ids.add(array[32, byte](t.txid()))
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
    merkleRoot: merkleRoot(ids), timestamp: ts, bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: txs)

proc next(prev: Block, height: int32, tag: byte,
          spends: seq[Transaction] = @[], cbValue: int64 = 50 * Coin): Block =
  mine(hashOf(prev), prev.header.timestamp + 600, height, tag, spends, cbValue)

proc spendOpTrue(src: Transaction, vout: uint32, value: int64): Transaction =
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: src.txid(), vout: vout),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: OpTrue)],
    witnesses: @[], lockTime: 0)

proc spendTaproot(src: Transaction, vout: uint32, value: int64): Transaction =
  let tr = taprootOutput()
  Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: src.txid(), vout: vout),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: OpTrue)],
    witnesses: @[@[tapscriptLeaf(), tr.control]], lockTime: 0)

const BaseHeight = 105'i32

proc buildDatadir(path: string, p: ConsensusParams):
    tuple[cs: ChainState, blks: seq[Block]] =
  ## genesis + 105 blocks. Block 1's coinbase pays OP_TRUE, block 2's pays a
  ## P2TR (OP_TRUE leaf); both are mature at 106.
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  doAssert cs.connectBlock(genesis, 0'i32).isOk
  var blks: seq[Block] = @[genesis]
  for h in 1'i32 .. BaseHeight:
    let spk = if h == 2: taprootOutput().spk else: OpTrue
    let b = mine(hashOf(blks[^1]), blks[^1].header.timestamp + 600, h, 0,
                 @[], 50 * Coin, spk)
    let r = cs.connectBlock(b, h)
    doAssert r.isOk, "connect h=" & $h & ": " & $r.error
    blks.add(b)
  (cs, blks)

proc readyPeer(pm: PeerManager, ip: string, p: ConsensusParams): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = BaseHeight + 20
  pm.peers[ip & ":8333"] = result

proc freshPeerManager(p: ConsensusParams, dir: string): PeerManager =
  removeDir(dir)
  createDir(dir)
  newPeerManager(p, 8, 2, 117, dir)

proc isFailedOnDisk(cs: ChainState, h: BlockHash): bool =
  let idx = cs.db.getBlockIndex(h)
  idx.isSome and idx.get().failureFlags.isFailed()

template withFixture(name: string, body: untyped) =
  let p {.inject.} = regtestParams()
  let path {.inject.} = "/tmp/nimrod_gate6_" & name
  let fx = buildDatadir(path, p)
  var csv {.inject.} = fx.cs
  let blks {.inject.} = fx.blks
  let pm {.inject.} = freshPeerManager(p, path & "_pm")
  let sm {.inject.} = newSyncManager(pm, csv.db, p, csv)
  installHooks()
  try:
    body
  finally:
    removeHooks()
    try: csv.db.db.closeUnsafe()
    except CatchableError: discard
    removeDir(path)
    removeDir(path & "_pm")

# ===========================================================================
suite "gate 6: chainstate write / flush failure (F11, F7a)":

  test "per-block write fails twice: no phantom coins, no work drift, latched, no verdict":
    withFixture("write"):
      let x = pm.readyPeer("198.51.100.61", p)
      let y = pm.readyPeer("198.51.100.62", p)
      let cb1 = blks[1].txs[0]
      let s1 = spendOpTrue(cb1, 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB1, @[s1])
      let workBefore = csv.totalWork
      waitFor sm.handleHeaders(x, @[b.header])

      gFailWrites.store(true)
      check not sm.processBlock(x, b)
      gFailWrites.store(false)

      # No verdict about B, nobody punished.
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check sm.chainTipHeight == BaseHeight
      check csv.bestHeight == BaseHeight
      # Write-before-forget: the failed connect left memory untouched.
      check csv.totalWork == workBefore                       # pre: double-added
      check csv.getUtxo(OutPoint(txid: s1.txid(), vout: 0)).isNone  # pre: phantom
      check csv.getUtxo(OutPoint(txid: cb1.txid(), vout: 0)).isSome
      # AbortNode latched.
      check isFatal()
      # ... and a latched node connects nothing (and still judges nothing).
      check not sm.processBlock(x, b)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect

      # Fail-open probe: clear the latch (as a restart would) and deliver a
      # block that spends B's output. B was never connected, so that coin
      # does not exist: Core rejects missing inputs. PRE-FIX the phantom coin
      # in the cache made this block CONNECT.
      resetFatalForTest()
      let spendPhantom = spendOpTrue(s1, 0, 48 * Coin)
      let c = blks[^1].next(BaseHeight + 1, 0xC1, @[spendPhantom])
      waitFor sm.handleHeaders(y, @[c.header])
      check not sm.processBlock(y, c)
      check sm.chainTip != hashOf(c)
      check csv.bestHeight == BaseHeight
      # The honest B connects once the disk works again.
      waitFor sm.handleHeaders(x, @[b.header])
      check sm.processBlock(x, b)
      check csv.bestBlockHash == hashOf(b)

  test "IBD flush fails after the tip advanced: redelivery is not a verdict; latched; no shutdown flush":
    withFixture("ibdflush"):
      let x = pm.readyPeer("198.51.100.63", p)
      let cb1 = blks[1].txs[0]
      let s1 = spendOpTrue(cb1, 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB2, @[s1])
      # 12 more headers so applyBlock takes the IBD path (blocksRemaining > 10).
      var hdrs = @[b.header]
      var prev = b
      for i in 0 ..< 12:
        let nb = prev.next(BaseHeight + 2 + int32(i), 0x20 + byte(i))
        hdrs.add(nb.header)
        prev = nb
      waitFor sm.handleHeaders(x, hdrs)
      csv.ibdDiskFlushInterval = 1       # memtable flush after every block

      gFailFlush.store(true)
      discard sm.processBlock(x, b)
      gFailFlush.store(false)
      check isFatal()                    # pre: no latch, the node keeps going

      # The same block delivered again (a re-fetch). PRE-FIX: the in-memory
      # tip had already moved to B, its inputs read as spent, adoption refused
      # (tip != parent) -> "transaction inputs missing" -> BLOCK_FAILED_VALID
      # persisted + the peer punished, for a VALID block.
      discard sm.processBlock(x, b)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect

      # Shutdown after the latch must not write the state that could not be
      # made durable: the batch stays unwritten and the coin B created is not
      # on disk.
      csv.stopIBD()
      csv.flushCache()
      check csv.ibdBatch != nil
      check csv.db.getUtxo(OutPoint(txid: s1.txid(), vout: 0)).isNone

  test "disconnectBlock write fails twice: tip, work and cache restored; latched":
    withFixture("disconnect"):
      let cb1 = blks[1].txs[0]
      let s1 = spendOpTrue(cb1, 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB3, @[s1])
      check csv.connectBlock(b, BaseHeight + 1).isOk
      let workBefore = csv.totalWork
      gFailWrites.store(true)
      var raised = false
      var r: ChainStateResult[void]
      try:
        r = csv.disconnectBlock(b)
      except CatchableError:
        raised = true
      gFailWrites.store(false)
      check raised or not r.isOk
      check csv.bestBlockHash == hashOf(b)                      # pre: rolled back in memory only
      check csv.bestHeight == BaseHeight + 1
      check csv.totalWork == workBefore
      check csv.getUtxo(OutPoint(txid: s1.txid(), vout: 0)).isSome   # pre: dropped from cache... and
      check isFatal()

suite "gate 6: coins-DB read failure":

  test "a UTXO read that fails twice latches, never marks, never punishes":
    withFixture("utxoread"):
      let x = pm.readyPeer("198.51.100.64", p)
      csv.flushCache()                   # force the coin lookups to the DB
      let s1 = spendOpTrue(blks[1].txs[0], 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB4, @[s1])
      waitFor sm.handleHeaders(x, @[b.header])
      gFailUtxoGets.store(true)
      check not sm.processBlock(x, b)
      gFailUtxoGets.store(false)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check isFatal()                    # pre: logged, retried forever, never halts

suite "gate 6: script check with no result (three outcomes)":

  test "a transient internal error is re-run and the valid block connects":
    withFixture("scripttransient"):
      let x = pm.readyPeer("198.51.100.65", p)
      let s1 = spendOpTrue(blks[1].txs[0], 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB5, @[s1])
      waitFor sm.handleHeaders(x, @[b.header])
      gScriptFaults.store(1)             # the first check dies, the re-run is clean
      check sm.processBlock(x, b)        # pre: the block is dropped
      check csv.bestBlockHash == hashOf(b)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check not isFatal()

  test "a persistent internal error is no verdict and latches":
    withFixture("scriptpersistent"):
      let x = pm.readyPeer("198.51.100.66", p)
      let s1 = spendOpTrue(blks[1].txs[0], 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB6, @[s1])
      waitFor sm.handleHeaders(x, @[b.header])
      gScriptFaults.store(-1)
      check not sm.processBlock(x, b)
      gScriptFaults.store(0)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check csv.bestHeight == BaseHeight
      check isFatal()                    # pre: retried forever

  test "secp context unavailable in a taproot script-path check is not a verdict (block)":
    withFixture("secpblock"):
      let x = pm.readyPeer("198.51.100.67", p)
      let cb2 = blks[2].txs[0]
      let st = spendTaproot(cb2, 0, 49 * Coin)
      let b = blks[^1].next(BaseHeight + 1, 0xB7, @[st])
      waitFor sm.handleHeaders(x, @[b.header])
      gSecpFault.store(true)
      check not sm.processBlock(x, b)
      gSecpFault.store(false)
      # PRE-FIX: tweakXonlyPubkey's Secp256k1Error was read as "pubkey does
      # not parse" -> WITNESS_PROGRAM_MISMATCH -> block marked + peer banned.
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check isFatal()
      # The same block, with a working context, is valid.
      resetFatalForTest()
      check sm.processBlock(x, b)
      check csv.bestBlockHash == hashOf(b)

  test "secp context unavailable never yields a script result (interpreter)":
    installHooks()
    defer: removeHooks()
    let tr = taprootOutput()
    var tx = Transaction(version: 2,
      inputs: @[TxIn(prevOut: OutPoint(txid: default(TxId), vout: 0),
                     scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: OpTrue)],
      witnesses: @[@[tapscriptLeaf(), tr.control]], lockTime: 0)
    # Control: with a context the spend is valid.
    check verifyScriptWithError(@[], tr.spk, tx, 0, Satoshi(Coin),
      {sfP2SH, sfWitness, sfTaproot}, tx.witnesses[0], @[Satoshi(Coin)],
      @[tr.spk]) == seOk
    gSecpFault.store(true)
    var gotResult = false
    var res = seOk
    try:
      res = verifyScriptWithError(@[], tr.spk, tx, 0, Satoshi(Coin),
        {sfP2SH, sfWitness, sfTaproot}, tx.witnesses[0], @[Satoshi(Coin)],
        @[tr.spk])
      gotResult = true
    except CatchableError:
      discard
    gSecpFault.store(false)
    check not gotResult                  # pre: seWitnessProgramMismatch
    if gotResult:
      checkpoint "got " & $res

suite "gate 6: the latch":

  test "after AbortNode every chain-changing entry refuses without a verdict":
    withFixture("latch"):
      let x = pm.readyPeer("198.51.100.68", p)
      let b = blks[^1].next(BaseHeight + 1, 0xB8)
      waitFor sm.handleHeaders(x, @[b.header])
      abortNode("test: injected fatal")
      let r = acceptAndConnectBlock(csv, b, BaseHeight + 1, bsSubmitBlockTip,
                                    newCryptoEngine())
      check not r.isOk                   # pre: the latch is not honoured -> connects
      if not r.isOk:
        check blockFailureKindOfApplyError(r.error) == bfkUndecided
      check not sm.processBlock(x, b)
      check not csv.isFailedOnDisk(hashOf(b))
      check not x.shouldDisconnect
      check csv.bestHeight == BaseHeight

suite "gate 6: classifiers are strict allow-lists":

  test "system-fault and unknown strings are never verdicts":
    check blockFailureKindOfToken(fatalErrorToken & ": write failed") == bfkUndecided
    check blockFailureKindOfToken("script-check-internal-error") == bfkUndecided
    check blockFailureKindOfToken("IO error: No space left on device") == bfkUndecided  # pre: bfkInvalid
    check blockFailureKindOfToken("out of memory") == bfkUndecided                     # pre: bfkInvalid
    check blockFailureKindOfApplyError(fatalErrorToken & ": x") == bfkUndecided
    check blockFailureKindOfApplyError("IO error: No space left on device") == bfkUndecided

  test "controls: consensus tokens keep their verdicts":
    check blockFailureKindOfToken("bad-cb-amount") == bfkInvalid
    check blockFailureKindOfToken("bad-txns-inputs-missingorspent") == bfkInvalid
    check blockFailureKindOfToken("bad-txns-premature-spend-of-coinbase") == bfkInvalid
    check blockFailureKindOfToken("block-script-verify-flag-failed") == bfkInvalid
    check blockFailureKindOfToken("mandatory-script-verify-flag-failed") == bfkInvalid
    check blockFailureKindOfToken("bad-txns-nonfinal") == bfkInvalid
    check blockFailureKindOfToken("bad-txns-BIP30") == bfkInvalid
    check blockFailureKindOfToken("high-hash") == bfkInvalid
    check blockFailureKindOfToken("bad-diffbits") == bfkInvalid
    check blockFailureKindOfToken("bad-version(0x00000001)") == bfkInvalid
    check blockFailureKindOfToken("bad-txnmrklroot") == bfkMutated
    check blockFailureKindOfToken("bad-witness-merkle-match") == bfkMutated
    check blockFailureKindOfToken("time-too-new") == bfkUndecided
    check blockFailureKindOfToken("utxo-read-error: x") == bfkUndecided
    check blockFailureKindOfApplyError("acceptBlock rejected: " &
      $veScriptVerifyFailed) == bfkInvalid
    check blockFailureKindOfApplyError("acceptBlock rejected: " &
      $veInputsMissing) == bfkInvalid

suite "gate 6 controls: genuinely invalid blocks keep their verdicts":

  test "coinbase overpay is marked and the sender punished (no hooks armed)":
    withFixture("ctlcb"):
      let x = pm.readyPeer("198.51.100.69", p)
      let b = blks[^1].next(BaseHeight + 1, 0xC2, @[], 50 * Coin + 1)
      waitFor sm.handleHeaders(x, @[b.header])
      check not sm.processBlock(x, b)
      check csv.isFailedOnDisk(hashOf(b))
      check x.shouldDisconnect
      check not isFatal()

  test "a genuinely missing input is marked and the sender punished":
    withFixture("ctlmissing"):
      let x = pm.readyPeer("198.51.100.70", p)
      var ghost = Transaction(version: 2,
        inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 7),
                       scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: OpTrue)],
        witnesses: @[], lockTime: 0)
      ghost.inputs[0].prevOut.txid = blks[3].txs[0].txid()   # real tx, vout 7 absent
      let b = blks[^1].next(BaseHeight + 1, 0xC3, @[ghost])
      waitFor sm.handleHeaders(x, @[b.header])
      check not sm.processBlock(x, b)
      check csv.isFailedOnDisk(hashOf(b))
      check x.shouldDisconnect
      check not isFatal()

  test "an invalid script (OP_FALSE leaf result) is marked and punished":
    withFixture("ctlscript"):
      let x = pm.readyPeer("198.51.100.71", p)
      # Spend block 1's OP_TRUE coinbase with a scriptSig that leaves FALSE
      # on top: OP_0 <-> OP_TRUE evaluation ends with the pubkey script's 1...
      # so instead spend it with OP_RETURN in the scriptSig (always fails).
      var s1 = spendOpTrue(blks[1].txs[0], 0, 49 * Coin)
      s1.inputs[0].scriptSig = @[byte(0x6a)]
      let b = blks[^1].next(BaseHeight + 1, 0xC4, @[s1])
      waitFor sm.handleHeaders(x, @[b.header])
      check not sm.processBlock(x, b)
      check csv.isFailedOnDisk(hashOf(b))
      check x.shouldDisconnect
      check not isFatal()
