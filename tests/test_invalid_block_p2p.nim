## Invalid block delivered over P2P — Core InvalidBlockFound / InvalidChainFound /
## MaybePunishNodeForBlock / BLOCK_CACHED_INVALID.
##
## Observed on the live instrument (tools/p2p-invalid-block-feed.py, 2026-10-03,
## canonical a6a5cc2): a coinbase-overpay block B1 at h+1 was requested FIVE
## times — once per redial of the peer that served it — because nimrod forgot
## the verdict: B1 stayed the tip of the active header chain, so every
## re-announcement (and the punished peer's redial) fetched it again, and the
## valid sibling B1' at the same height was filed as an equal-work side header
## and never fetched. In the "after" shape (B1' already the tip, attacker extends
## the stored B1 with a heavier B2x) the reorg attempt failed on B1 but nothing
## was marked and the peer that delivered B1 was not the one punished.
##
## Core: the failing block is BLOCK_FAILED_VALID, its descendants are failed
## with it, the best header moves to the most-work valid branch, the sender of
## the bad block (mapBlockSource) is punished, and any later announcement of it
## is BLOCK_CACHED_INVALID — never fetched, inbound announcer not punished.
##
## Every assertion below uses only API that exists before the fix (header
## chain, chainTip, the persisted BlockIndex.failureFlags, shouldDisconnect), so
## the suite is a real fail-before / pass-after regression test.

import unittest2
import std/[options, os, tables, sets, strutils]
import chronos
import ../src/network/sync
import ../src/network/peer
import ../src/network/peermanager
import ../src/network/messages
import ../src/consensus/[params, validation, chain]
import ../src/storage/chainstate
import ../src/storage/db
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const EASY_BITS = 0x207fffff'u32
const BaseTs = 1_700_000_000'u32

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc coinbaseTx(height: int32, value: int64, tag: byte): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x00), tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc mine(prevHash: BlockHash, ts: uint32, txs: seq[Transaction]): Block =
  var ids: seq[array[32, byte]]
  for t in txs: ids.add(array[32, byte](t.txid()))
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
    merkleRoot: merkleRoot(ids), timestamp: ts, bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: txs)

proc validBlock(prev: Block, height: int32, tag: byte): Block =
  mine(hashOf(prev.header), prev.header.timestamp + 600,
       @[coinbaseTx(height, 5_000_000_000'i64, tag)])

proc badCbBlock(prev: Block, height: int32, tag: byte): Block =
  ## Core ConnectBlock "bad-cb-amount": coinbase pays subsidy + 1 sat.
  mine(hashOf(prev.header), prev.header.timestamp + 600,
       @[coinbaseTx(height, 5_000_000_001'i64, tag)])

proc missingInputBlock(prev: Block, height: int32, tag: byte): Block =
  ## Passes side-branch STORAGE (UTXO checks are deferred to connect time) and
  ## fails at connect: "bad-txns-inputs-missingorspent".
  var ghost: array[32, byte]
  ghost[0] = 0xAB
  ghost[1] = tag
  let spend = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(ghost), vout: 0),
                   scriptSig: @[byte(0x51)], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)
  mine(hashOf(prev.header), prev.header.timestamp + 600,
       @[coinbaseTx(height, 5_000_000_000'i64, tag), spend])

proc buildDatadir(path: string, p: ConsensusParams,
                  count: int): tuple[cs: ChainState, blks: seq[Block]] =
  removeDir(path)
  var cs = newChainState(path, p)
  let genesis = buildGenesisBlock(p)
  doAssert cs.connectBlock(genesis, 0'i32).isOk
  var blks: seq[Block] = @[genesis]
  for h in 1'i32 .. int32(count):
    let b = validBlock(blks[^1], h, 0)
    let r = cs.connectBlock(b, h)
    doAssert r.isOk, "connect h=" & $h & ": " & $r.error
    blks.add(b)
  (cs, blks)

proc readyPeer(pm: PeerManager, ip: string, p: ConsensusParams,
               dir: PeerDirection, startHeight: int32): Peer =
  result = newPeer(ip, 8333, p, dir)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = startHeight
  pm.peers[ip & ":8333"] = result

proc freshPeerManager(p: ConsensusParams, dir: string): PeerManager =
  ## Own data dir: misbehavingPeer persists bans to <dataDir>/banlist.json,
  ## and the shared "/tmp" one is read by other suites (test_reorg_p2p
  ## asserts its peers are NOT banned).
  removeDir(dir)
  createDir(dir)
  newPeerManager(p, 8, 2, 117, dir)

proc isFailedOnDisk(cs: ChainState, h: BlockHash): bool =
  let idx = cs.db.getBlockIndex(h)
  idx.isSome and idx.get().failureFlags.isFailed()

# ===========================================================================
suite "invalid block at the tip extension (instrument 'before' shape)":

  test "B1 is failed, never re-fetched, sender punished; the valid sibling connects":
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_before"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.12", p, pdInbound, 21)
    let h = pm.readyPeer("198.51.100.13", p, pdInbound, 20)
    let sm = newSyncManager(pm, csv.db, p, csv)
    check sm.chainTipHeight == 20

    let b1 = badCbBlock(blks[20], 21, 0xB1)
    let b1v = validBlock(blks[20], 21, 0xC1)
    let b2v = validBlock(b1v, 22, 0xC2)
    let hB1 = hashOf(b1.header)

    # X announces B1 (extends the active tip) and delivers it.
    waitFor sm.handleHeaders(x, @[b1.header])
    check sm.headerChain.tipHeight == 21
    check not sm.processBlock(x, b1)

    # The verdict is remembered on the block (Core BLOCK_FAILED_VALID) ...
    check csv.isFailedOnDisk(hB1)
    # ... and B1 is no longer the best header, so nothing will fetch it.
    # PRE-FIX: getHashByHeight(21) == B1 forever -> every redial re-fetched it.
    check sm.headerChain.getHashByHeight(21) != some(hB1)
    check sm.headerChain.tipHeight == 20
    # The peer that delivered it is punished (Core BLOCK_CONSENSUS).
    check x.shouldDisconnect

    # X redials and re-announces B1: BLOCK_CACHED_INVALID. Inbound announcer
    # is NOT punished, and B1 does not come back as a download target.
    let x2 = pm.readyPeer("198.51.100.14", p, pdInbound, 21)
    waitFor sm.handleHeaders(x2, @[b1.header])
    check not x2.shouldDisconnect
    check sm.headerChain.getHashByHeight(21) != some(hB1)
    check not sm.processBlock(x2, b1)   # unsolicited copy: not re-validated
    check not x2.shouldDisconnect

    # The honest sibling at the same height now extends the best header and
    # connects. PRE-FIX: it was filed as an equal-work side header and the
    # node sat at h until a heavier header (and a 60 s timeout) came along.
    waitFor sm.handleHeaders(h, @[b1v.header])
    check sm.headerChain.getHashByHeight(21) == some(hashOf(b1v.header))
    check sm.processBlock(h, b1v)
    check sm.chainTipHeight == 21
    check sm.chainTip == hashOf(b1v.header)
    waitFor sm.handleHeaders(h, @[b2v.header])
    check sm.processBlock(h, b2v)
    check sm.chainTip == hashOf(b2v.header)
    check not h.shouldDisconnect

  test "a known-failed block is never put back on the best header after a restart":
    ## The flag is persisted (Core writes BLOCK_FAILED_VALID to the block
    ## index), so a fresh SyncManager over the same datadir still answers a
    ## re-announcement with CACHED_INVALID instead of a download.
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_restart"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.112", p, pdInbound, 21)
    let sm = newSyncManager(pm, csv.db, p, csv)
    let b1 = badCbBlock(blks[20], 21, 0xB7)
    waitFor sm.handleHeaders(x, @[b1.header])
    check not sm.processBlock(x, b1)

    let sm2 = newSyncManager(pm, csv.db, p, csv)
    let x2 = pm.readyPeer("198.51.100.113", p, pdInbound, 21)
    waitFor sm2.handleHeaders(x2, @[b1.header])
    check sm2.headerChain.tipHeight == 20
    check sm2.headerChain.getHashByHeight(21) != some(hashOf(b1.header))
    check not x2.shouldDisconnect

# ===========================================================================
suite "invalid block found during a reorg attempt (instrument 'after' shape)":

  test "the stored B1 fails when B2x tries to activate it: B1+B2x failed, B1's sender punished, tip kept":
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_after"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    # B1' is already the tip.
    let b1v = validBlock(blks[20], 21, 0xC1)
    check csv.connectBlock(b1v, 21).isOk
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.122", p, pdInbound, 21)
    let y = pm.readyPeer("198.51.100.123", p, pdInbound, 22)
    let h = pm.readyPeer("198.51.100.124", p, pdInbound, 21)
    let sm = newSyncManager(pm, csv.db, p, csv)
    check sm.chainTip == hashOf(b1v.header)

    let b1 = missingInputBlock(blks[20], 21, 0xB1)
    let b2x = validBlock(b1, 22, 0xB2)
    let b2v = validBlock(b1v, 22, 0xC2)
    let hB1 = hashOf(b1.header)
    let hB2x = hashOf(b2x.header)

    # X: equal-work B1 (side header), body stored as a side branch.
    waitFor sm.handleHeaders(x, @[b1.header, b2x.header])
    check not sm.processBlock(x, b1)
    check not x.shouldDisconnect              # storage passed: nothing yet
    # Y delivers B2x: heavier, so the reorg is attempted and fails ON B1.
    check not sm.processBlock(y, b2x)

    # Tip unchanged (Core returns to / stays on the most-work valid chain).
    check sm.chainTip == hashOf(b1v.header)
    check csv.bestBlockHash == hashOf(b1v.header)
    # B1 failed, and its descendant B2x with it.
    check csv.isFailedOnDisk(hB1)
    check csv.isFailedOnDisk(hB2x)
    # Neither is a download target any more.
    check hB1 notin sm.headerChain.sideHeaders
    check hB2x notin sm.headerChain.sideHeaders
    # Core BlockChecked -> mapBlockSource: the peer that SENT B1 is punished,
    # not the one whose B2x triggered the attempt. PRE-FIX: y was punished.
    check x.shouldDisconnect
    check not y.shouldDisconnect

    # The honest extension still connects.
    waitFor sm.handleHeaders(h, @[b2v.header])
    check sm.processBlock(h, b2v)
    check sm.chainTip == hashOf(b2v.header)
    check not h.shouldDisconnect

# ===========================================================================
suite "non-verdicts are NOT marked failed":

  test "a mutated body (merkle mismatch) punishes the sender but leaves the hash fetchable":
    ## Core BLOCK_MUTATED: InvalidBlockFound skips the BLOCK_FAILED_VALID mark —
    ## the header may belong to a valid block whose body a peer mangled.
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_mutated"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.132", p, pdInbound, 21)
    let h = pm.readyPeer("198.51.100.133", p, pdInbound, 21)
    let sm = newSyncManager(pm, csv.db, p, csv)
    let good = validBlock(blks[20], 21, 0xD1)
    var mangled = good
    mangled.txs[0].outputs[0].value = Satoshi(4_000_000_000'i64)  # root no longer matches
    let hGood = hashOf(good.header)
    check hashOf(mangled.header) == hGood

    waitFor sm.handleHeaders(x, @[good.header])
    check not sm.processBlock(x, mangled)
    check x.shouldDisconnect      # mutated: punished
    check not csv.isFailedOnDisk(hGood)                # ... but NOT marked
    check sm.headerChain.getHashByHeight(21) == some(hGood)  # still wanted
    check sm.processBlock(h, good)                     # real body connects
    check sm.chainTip == hGood

  test "classifier: mutation and cannot-decide errors are not verdicts":
    check blockFailureKind(veBadMerkleRoot) == bfkMutated
    check blockFailureKind(veBadWitnessCommitment) == bfkMutated
    check blockFailureKind(vePrevBlockMissing) == bfkUndecided
    check blockFailureKind(veTimeTooNew) == bfkUndecided
    check blockFailureKind(veBadAmount) == bfkInvalid
    check blockFailureKind(veSequenceLockNotSatisfied) == bfkInvalid
    check blockFailureKindOfApplyError("prev block 00 not in chain index") == bfkUndecided
    check blockFailureKindOfApplyError("connectBlock: write failed") == bfkUndecided
    check blockFailureKindOfApplyError("acceptBlock rejected: " & $veBadAmount) == bfkInvalid
    check blockFailureKindOfToken("rejected") == bfkUndecided
    check blockFailureKindOfToken("bad-txnmrklroot") == bfkMutated
    check blockFailureKindOfToken("bad-cb-amount") == bfkInvalid

# ===========================================================================
# A UTXO READ FAILURE is a local fault, not a verdict.
#
# Core: CCoinsViewErrorCatcher::GetCoin turns a coins-DB read failure into
# "Error reading from database, shutting down." + abort — the block is never
# marked BLOCK_FAILED_VALID and no peer is punished. A coin that is genuinely
# absent IS a verdict (bad-txns-inputs-missingorspent).
#
# The fault is real, not mocked: the spent coin's on-disk record is replaced
# by a 1-byte value, so ChainDb.getUtxo raises SerializationError exactly as
# it would for a damaged record. Before this fix the lookup adapters caught
# the raise and returned none(UtxoEntry), so the coin read as MISSING and the
# block was persistently marked failed (nimrod writes failureFlags to disk —
# sticky until reconsiderblock) and its sender punished.

proc ghostOutpoint(tag: byte): OutPoint =
  ## The outpoint missingInputBlock(.., tag) spends.
  var ghost: array[32, byte]
  ghost[0] = 0xAB
  ghost[1] = tag
  OutPoint(txid: TxId(ghost), vout: 0)

proc corruptCoin(cs: ChainState, op: OutPoint) =
  cs.db.db.put(cfUtxo, utxoKey(array[32, byte](op.txid), op.vout), @[0x01'u8])

proc dropCoin(cs: ChainState, op: OutPoint) =
  cs.db.db.delete(cfUtxo, utxoKey(array[32, byte](op.txid), op.vout))

suite "a UTXO read failure is not a verdict":

  test "tip extension: unreadable coin -> not marked, sender not punished; once the coin is truly missing -> marked":
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_readerr_before"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.142", p, pdInbound, 21)
    let x2 = pm.readyPeer("198.51.100.143", p, pdInbound, 21)
    let sm = newSyncManager(pm, csv.db, p, csv)

    let b1 = missingInputBlock(blks[20], 21, 0xE1)
    let hB1 = hashOf(b1.header)
    let ghost = ghostOutpoint(0xE1)
    csv.corruptCoin(ghost)
    # Instrument check: the fault is live — the raw read raises.
    expect(CatchableError):
      discard csv.getUtxo(ghost)

    waitFor sm.handleHeaders(x, @[b1.header])
    check not sm.processBlock(x, b1)
    # PRE-FIX: marked BLOCK_FAILED_VALID on disk, header dropped, x punished.
    check not csv.isFailedOnDisk(hB1)
    check not x.shouldDisconnect
    check sm.headerChain.getHashByHeight(21) == some(hB1)   # still wanted (retried)
    check sm.lastApplyError.startsWith("utxo-read-error")
    check sm.chainTipHeight == 20

    # Positive control on the same block: the record is now genuinely absent,
    # which IS a consensus verdict — marked, and the deliverer punished.
    csv.dropCoin(ghost)
    check csv.getUtxo(ghost).isNone
    check not sm.processBlock(x2, b1)
    check csv.isFailedOnDisk(hB1)
    check x2.shouldDisconnect
    check sm.headerChain.getHashByHeight(21) != some(hB1)

  test "reorg attempt: unreadable coin in the promoted block -> nothing marked or punished, tip and chainstate intact":
    let p = regtestParams()
    let path = "/tmp/nimrod_ibp2p_readerr_after"
    let (cs, blks) = buildDatadir(path, p, 20)
    defer:
      var c = cs
      c.close()
      removeDir(path)
      removeDir(path & "_pm")
    var csv = cs
    let b1v = validBlock(blks[20], 21, 0xC1)
    check csv.connectBlock(b1v, 21).isOk
    let pm = freshPeerManager(p, path & "_pm")
    let x = pm.readyPeer("198.51.100.152", p, pdInbound, 21)
    let y = pm.readyPeer("198.51.100.153", p, pdInbound, 22)
    let h = pm.readyPeer("198.51.100.154", p, pdInbound, 21)
    let sm = newSyncManager(pm, csv.db, p, csv)

    let b1 = missingInputBlock(blks[20], 21, 0xE2)
    let b2x = validBlock(b1, 22, 0xE3)
    let b2v = validBlock(b1v, 22, 0xC2)
    csv.corruptCoin(ghostOutpoint(0xE2))

    waitFor sm.handleHeaders(x, @[b1.header, b2x.header])
    check not sm.processBlock(x, b1)        # stored as a side branch
    check not sm.processBlock(y, b2x)       # reorg attempt hits the read fault

    check not csv.isFailedOnDisk(hashOf(b1.header))
    check not csv.isFailedOnDisk(hashOf(b2x.header))
    check not x.shouldDisconnect
    check not y.shouldDisconnect
    # PRE-FIX: the raise escaped handleReorg with the in-memory tip rolled back
    # to the fork point and reorgDeletedUtxos left set.
    check sm.chainTip == hashOf(b1v.header)
    check csv.bestBlockHash == hashOf(b1v.header)
    check csv.bestHeight == 21
    check csv.reorgDeletedUtxos == nil

    waitFor sm.handleHeaders(h, @[b2v.header])
    check sm.processBlock(h, b2v)
    check sm.chainTip == hashOf(b2v.header)

  test "lookup adapter: a raise is recorded, a clean miss is not":
    let g = newUtxoReadGuard()
    let raising = guardedUtxoLookup(
      proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} =
        raise newException(IOError, "injected read fault"), g)
    check raising(ghostOutpoint(1)).isNone
    check g.failed
    let g2 = newUtxoReadGuard()
    let missing = guardedUtxoLookup(
      proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} = none(UtxoEntry), g2)
    check missing(ghostOutpoint(1)).isNone
    check not g2.failed

  test "classifier: a read failure / hook exception is undecided":
    check blockFailureKind(veUtxoReadError) == bfkUndecided
    check blockFailureKind(veInputsMissing) == bfkInvalid
    check blockFailureKindOfToken("utxo-read-error: x") == bfkUndecided
    check blockFailureKindOfToken("local-error: boom") == bfkUndecided
    check blockFailureKindOfToken("bad-txns-inputs-missingorspent") == bfkInvalid
    check blockFailureKindOfApplyError("utxo-read-error: x") == bfkUndecided
    check blockFailureKindOfApplyError("acceptBlock rejected: " & $veUtxoReadError) == bfkUndecided
