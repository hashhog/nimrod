## An in-block double spend of a UTXO-set coin is a consensus verdict.
##
## Core ConnectBlock runs CheckTxInputs for each tx against a CCoinsViewCache
## that SpendCoin has already updated for the earlier txs of the same block
## (validation.cpp ConnectBlock -> Consensus::CheckTxInputs, coins.cpp
## SpendCoin). When tx2 spends the coin tx1 already spent, the coin is gone:
## "bad-txns-inputs-missingorspent", BLOCK_CONSENSUS, so InvalidBlockFound
## marks the hash and MaybePunishNodeForBlock punishes the sender.
##
## nimrod's validateBlock tracked only OUTPUTS created inside the block
## (intraBlockUtxos). Spending a coin that came from the UTXO set deleted
## nothing from that table, so a later tx re-spending the same coin fell
## through to the DB, found it, and passed acceptBlock. The connect guards
## then refused the block with a bare string (no "acceptBlock rejected:"
## prefix), blockFailureKindOfApplyError read that as bfkUndecided, and the
## block was neither marked invalid nor its sender punished: the peer could
## repeat it forever and the hash stayed fetchable.

import unittest2
import std/[os, tables, sets, strutils, options]
import chronos
import ../src/network/sync
import ../src/network/peer
import ../src/network/peermanager
import ../src/network/messages
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const EASY_BITS = 0x207fffff'u32

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

proc coinbaseTx(height: int32, tag: byte): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x00), tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

proc spend(prev: OutPoint, value: int64, lockTime = 0'u32): Transaction =
  ## Spends an OP_TRUE output with an empty scriptSig. lockTime only makes
  ## two spends of the same coin differ in txid.
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: lockTime)

proc rootOf(txs: seq[Transaction]): array[32, byte] =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add array[32, byte](t.txid())
  merkleRoot(hs)

proc headerOver(prevHash: BlockHash, ts: uint32,
                root: array[32, byte]): BlockHeader =
  result = BlockHeader(version: 4, prevBlock: prevHash, merkleRoot: root,
    timestamp: ts, bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(result):
    result.nonce += 1

proc mineOn(prev: Block, height: int32, txs: seq[Transaction],
            tsBump = 600'u32): Block =
  let all = @[coinbaseTx(height, byte(height and 0xff))] & txs
  Block(header: headerOver(hashOf(prev), prev.header.timestamp + tsBump,
                           rootOf(all)),
        txs: all)

proc readyPeer(pm: PeerManager, ip: string, p: ConsensusParams): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = 102
  pm.peers[ip & ":8333"] = result

type Fix = object
  path: string
  cs: ChainState
  sm: SyncManager
  pm: PeerManager
  peer, honest: Peer
  chain: seq[Block]   # genesis .. 101, all connected
  split: Transaction  # in block 101: block 1's coinbase -> two OP_TRUE outputs

proc buildFix(path: string): Fix =
  ## Regtest chain 0..101 connected. At height 102 the UTXO set holds block
  ## 2's mature OP_TRUE coinbase and the two OP_TRUE outputs of `split`, a tx
  ## in block 101 that spent block 1's coinbase.
  removeDir(path)
  createDir(path)
  let p = regtestParams()
  var cs = newChainState(path / "chain", p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  var chain = @[g]
  for h in 1'i32 .. 100'i32:
    chain.add mineOn(chain[^1], h, @[])
    doAssert cs.connectBlock(chain[^1], h).isOk
  let split = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: chain[1].txs[0].txid(), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(2_400_000_000'i64), scriptPubKey: @[byte(0x51)]),
               TxOut(value: Satoshi(2_500_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)
  chain.add mineOn(chain[^1], 101, @[split])
  doAssert cs.connectBlock(chain[^1], 101'i32).isOk
  createDir(path / "pm")
  let pm = newPeerManager(p, 8, 2, 117, path / "pm")
  let sm = newSyncManager(pm, cs.db, p, cs)
  let peer = pm.readyPeer("198.51.100.81", p)
  let honest = pm.readyPeer("198.51.100.82", p)
  Fix(path: path, cs: cs, sm: sm, pm: pm, peer: peer, honest: honest,
      chain: chain, split: split)

proc close(f: var Fix) =
  f.cs.close()
  removeDir(f.path)

proc coinOf(f: Fix, height: int): OutPoint =
  OutPoint(txid: f.chain[height].txs[0].txid(), vout: 0)

proc splitOut(f: Fix, vout: uint32): OutPoint =
  OutPoint(txid: f.split.txid(), vout: vout)

proc deliver(f: Fix, peer: Peer, blk: Block): bool =
  ## Announce the header, request the body from `peer`, then hand the body to
  ## processBlock exactly as a `block` message would.
  waitFor f.sm.handleHeaders(peer, @[blk.header])
  let h = hashOf(blk)
  f.sm.requestedHashes.incl(h)
  f.sm.pendingBlocks += 1
  f.sm.noteBlockRequested(h, peer)
  f.sm.processBlock(peer, blk)

suite "in-block double spend of a UTXO-set coin":

  test "validateBlock rejects tx2 re-spending the coin tx1 spent (bad-txns-inputs-missingorspent)":
    var f = buildFix("/tmp/nimrod_cffix_ibds_v1")
    defer: f.close()
    let c = f.coinOf(2)
    let blk = mineOn(f.chain[^1], 102,
      @[spend(c, 4_999_000_000'i64, 1), spend(c, 4_998_000_000'i64, 2)])
    let prevIdx = f.cs.db.getBlockIndex(hashOf(f.chain[^1]))
    check prevIdx.isSome
    let r = validateBlock(blk, prevIdx.get(), f.cs.db, regtestParams(),
                          checkScripts = true, checkPow = true)
    check not r.isOk
    if not r.isOk:
      check r.error == veInputsMissing
      check bip22String(r.error) == "bad-txns-inputs-missingorspent"

  test "processBlock marks the double-spending block invalid and punishes its sender":
    var f = buildFix("/tmp/nimrod_cffix_ibds_p1")
    defer: f.close()
    let c = f.coinOf(2)
    let bad = mineOn(f.chain[^1], 102,
      @[spend(c, 4_999_000_000'i64, 1), spend(c, 4_998_000_000'i64, 2)])
    let h = hashOf(bad)
    check not f.deliver(f.peer, bad)
    check f.sm.chainTipHeight == 101
    check f.sm.lastApplyError.startsWith("acceptBlock rejected: ")
    check blockFailureKindOfApplyError(f.sm.lastApplyError) == bfkInvalid
    check f.sm.isKnownInvalid(h)
    check f.peer.shouldDisconnect
    check not f.honest.shouldDisconnect

  test "the double spend is caught with an unrelated tx between the two spends":
    var f = buildFix("/tmp/nimrod_cffix_ibds_p2")
    defer: f.close()
    let c = f.coinOf(2)
    let bad = mineOn(f.chain[^1], 102,
      @[spend(c, 4_999_000_000'i64, 1),
        spend(f.splitOut(0), 2_399_000_000'i64),
        spend(c, 4_998_000_000'i64, 2)])
    check not f.deliver(f.peer, bad)
    check f.sm.isKnownInvalid(hashOf(bad))
    check f.peer.shouldDisconnect

  test "a double spend of one output of a multi-output UTXO-set tx is marked":
    var f = buildFix("/tmp/nimrod_cffix_ibds_p4")
    defer: f.close()
    let bad = mineOn(f.chain[^1], 102,
      @[spend(f.splitOut(1), 2_499_000_000'i64, 1),
        spend(f.splitOut(1), 2_498_000_000'i64, 2)])
    check not f.deliver(f.peer, bad)
    check f.sm.isKnownInvalid(hashOf(bad))
    check f.peer.shouldDisconnect

  test "after the invalid block, a valid sibling spending the same coin connects":
    # The rejected block left no UTXO mutation behind: the coin is still
    # spendable by a block that spends it once.
    var f = buildFix("/tmp/nimrod_cffix_ibds_p3")
    defer: f.close()
    let c = f.coinOf(2)
    let bad = mineOn(f.chain[^1], 102,
      @[spend(c, 4_999_000_000'i64, 1), spend(c, 4_998_000_000'i64, 2)])
    check not f.deliver(f.peer, bad)
    check f.sm.isKnownInvalid(hashOf(bad))
    let good = mineOn(f.chain[^1], 102, @[spend(c, 4_999_000_000'i64, 3)],
                      tsBump = 601)
    check f.deliver(f.honest, good)
    check f.sm.chainTipHeight == 102
    check f.sm.chainTip == hashOf(good)
    check not f.honest.shouldDisconnect

  # --- controls: these hold on master too -----------------------------------

  test "control: a missing-input block is marked invalid and its sender punished":
    var f = buildFix("/tmp/nimrod_cffix_ibds_c1")
    defer: f.close()
    var nowhere: array[32, byte]
    nowhere[0] = 0xEE
    let bad = mineOn(f.chain[^1], 102,
      @[spend(OutPoint(txid: TxId(nowhere), vout: 0), 1000)])
    check not f.deliver(f.peer, bad)
    check blockFailureKindOfApplyError(f.sm.lastApplyError) == bfkInvalid
    check f.sm.isKnownInvalid(hashOf(bad))
    check f.peer.shouldDisconnect

  test "control: a double spend of an output created in the same block is marked":
    var f = buildFix("/tmp/nimrod_cffix_ibds_c2")
    defer: f.close()
    let t1 = spend(f.coinOf(2), 4_999_000_000'i64)
    let mid = OutPoint(txid: t1.txid(), vout: 0)
    let bad = mineOn(f.chain[^1], 102,
      @[t1, spend(mid, 4_998_000_000'i64, 1), spend(mid, 4_997_000_000'i64, 2)])
    check not f.deliver(f.peer, bad)
    check f.sm.isKnownInvalid(hashOf(bad))
    check f.peer.shouldDisconnect

  test "control (valid stays valid): spend a UTXO-set coin, then its output, in one block":
    var f = buildFix("/tmp/nimrod_cffix_ibds_c3")
    defer: f.close()
    let t1 = spend(f.coinOf(2), 4_999_000_000'i64)
    let t2 = spend(OutPoint(txid: t1.txid(), vout: 0), 4_998_000_000'i64)
    let good = mineOn(f.chain[^1], 102, @[t1, t2])
    check f.deliver(f.peer, good)
    check f.sm.chainTipHeight == 102
    check not f.peer.shouldDisconnect

  test "control (valid stays valid): two txs spending two different UTXO-set coins":
    var f = buildFix("/tmp/nimrod_cffix_ibds_c4")
    defer: f.close()
    let good = mineOn(f.chain[^1], 102,
      @[spend(f.coinOf(2), 4_999_000_000'i64), spend(f.splitOut(0), 2_399_000_000'i64)])
    check f.deliver(f.peer, good)
    check f.sm.chainTipHeight == 102
    check not f.peer.shouldDisconnect

  test "control (valid stays valid): two txs spending two outputs of one UTXO-set tx":
    # The tombstone is per outpoint, not per txid.
    var f = buildFix("/tmp/nimrod_cffix_ibds_c5")
    defer: f.close()
    let good = mineOn(f.chain[^1], 102,
      @[spend(f.splitOut(0), 2_399_000_000'i64), spend(f.splitOut(1), 2_499_000_000'i64)])
    check f.deliver(f.peer, good)
    check f.sm.chainTipHeight == 102
    check not f.peer.shouldDisconnect
