## A body whose first transaction is not a coinbase and that holds a 64-byte
## transaction is MUTATED, not invalid (Core IsBlockMutated, validation.cpp;
## net_processing.cpp drops it with Misbehaving("mutated block") before
## ProcessNewBlock and never marks the hash).
##
## A 64-byte legacy transaction is the size of an inner merkle node. For a
## real 2-tx block whose cbTxid||tx2Txid parses as such a transaction, the
## one-"transaction" body holding that parse reproduces the header's merkle
## root. Before this fix nimrod's bodyMatchesCommitments accepted that body
## as the committed one, checkBlock returned veNoCoinbase (bfkInvalid), and
## invalidChainFound marked the REAL block's hash and its descendants
## BLOCK_FAILED_VALID: a peer could condemn a valid block for the price of
## one message.
##
## The tests build the forged body directly (no grinding): a header whose
## merkle root is the txid of a 64-byte transaction stands in for that real
## block; its hash is all the attack needs.

import unittest2
import std/[os, tables, sets]
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

proc tx64(s: int, fill: byte): Transaction =
  ## 4 version + 1 vin count (byte 4 = 0x01) + 36 prevout + 1 + s scriptSig
  ## + 4 sequence + 1 vout count + 8 value + 1 + (4-s) scriptPubKey
  ## + 4 locktime = 64 bytes.
  var prev: array[32, byte]
  for i in 0 ..< 32: prev[i] = fill xor byte(i)
  var sig = newSeq[byte](s)
  for i in 0 ..< s: sig[i] = fill
  var spk = newSeq[byte](4 - s)
  for i in 0 ..< 4 - s: spk[i] = 0x51
  result = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prev), vout: 7),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(1234), scriptPubKey: spk)],
    witnesses: @[],
    lockTime: 0)
  doAssert serializeLegacy(result).len == 64
  doAssert serializeLegacy(result)[4] == 0x01

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

proc spendTx(tag: byte): Transaction =
  ## 67 bytes legacy: 4+1+36+1+6+4+1+8+1+1+4.
  var prev: array[32, byte]
  prev[0] = tag
  Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(prev), vout: 0),
                   scriptSig: @[byte(0x51), 0x51, 0x51, 0x51, 0x51, 0x51],
                   sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

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

proc blockOf(txs: seq[Transaction]): Block =
  Block(header: headerOver(BlockHash(default(array[32, byte])), 1_700_000_000'u32,
                           rootOf(txs)),
        txs: txs)

suite "IsBlockMutated 64-byte clause: bodyMatchesCommitments":

  test "a no-coinbase body of one 64-byte tx is mutated, not the committed body":
    for s in 0 .. 4:
      let forged = blockOf(@[tx64(s, byte(0x30 + s))])
      # The forged body DOES reproduce the header's merkle root ...
      check forged.header.merkleRoot == array[32, byte](forged.txs[0].txid())
      # ... and is still not the body the header commits to.
      check not bodyMatchesCommitments(forged, false)
      check not bodyMatchesCommitments(forged, true)

  test "a 64-byte tx anywhere in a no-coinbase body makes it mutated":
    let forged = blockOf(@[spendTx(0x01), tx64(2, 0x44)])
    check serializeLegacy(forged.txs[0]).len != 64
    check not bodyMatchesCommitments(forged, false)

  test "control: a normal coinbase + tx block still matches its commitments":
    let b = blockOf(@[coinbaseTx(3, 0x01), spendTx(0x02)])
    check serializeLegacy(b.txs[1]).len != 64
    check bodyMatchesCommitments(b, false)
    check bodyMatchesCommitments(b, true)

  test "control: a valid-shaped block CONTAINING a 64-byte tx is not mutated":
    # The rule needs a missing coinbase. A block led by its coinbase keeps
    # every 64-byte transaction it carries (no valid block newly rejected).
    let b = blockOf(@[coinbaseTx(3, 0x01), tx64(1, 0x55)])
    check bodyMatchesCommitments(b, false)
    check bodyMatchesCommitments(b, true)

  test "control: a no-coinbase body WITHOUT a 64-byte tx is still a verdict":
    # Core: IsBlockMutated returns false here, CheckBlock then rejects it
    # bad-cb-missing and the hash is marked. Unchanged.
    let b = blockOf(@[spendTx(0x07)])
    check serializeLegacy(b.txs[0]).len != 64
    check bodyMatchesCommitments(b, false)

# ---------------------------------------------------------------------------
# Integration: the P2P path does not mark the hash.

proc mineOn(prev: Block, height: int32, tag: byte): Block =
  let cb = coinbaseTx(height, tag)
  Block(header: headerOver(hashOf(prev), prev.header.timestamp + 600,
                           rootOf(@[cb])),
        txs: @[cb])

type Fix = object
  path: string
  cs: ChainState
  sm: SyncManager
  peer, other: Peer
  chain: seq[Block]   # genesis .. 2 connected; 3 .. 6 header-only
  forged: seq[Block]  # per height 3 .. 6: the header's no-coinbase 64-byte body

proc readyPeer(pm: PeerManager, ip: string, p: ConsensusParams): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = 6
  pm.peers[ip & ":8333"] = result

proc buildFix(path: string, forgedFrom: int32): Fix =
  ## Heights >= forgedFrom get a header whose merkle root is a 64-byte tx's
  ## txid (the stand-in for a real 2-tx block hitting the collision).
  removeDir(path)
  createDir(path)
  let p = regtestParams()
  var cs = newChainState(path / "chain", p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  var chain = @[g]
  var forged = newSeq[Block](7)
  for h in 1'i32 .. 6'i32:
    if h >= forgedFrom:
      let t = tx64(int(h) mod 5, byte(0x60 + h))
      let hdr = headerOver(hashOf(chain[^1]), chain[^1].header.timestamp + 600,
                           array[32, byte](t.txid()))
      forged[h] = Block(header: hdr, txs: @[t])
      chain.add forged[h]
    else:
      chain.add mineOn(chain[^1], h, byte(h))
    if h <= 2:
      doAssert cs.connectBlock(chain[^1], h).isOk
  createDir(path / "pm")
  let pm = newPeerManager(p, 8, 2, 117, path / "pm")
  let sm = newSyncManager(pm, cs.db, p, cs)
  let peer = pm.readyPeer("198.51.100.61", p)
  let other = pm.readyPeer("198.51.100.62", p)
  var hdrs: seq[BlockHeader]
  for h in 3 .. 6: hdrs.add chain[h].header
  waitFor sm.handleHeaders(peer, hdrs)
  doAssert sm.chainTipHeight == 2
  doAssert sm.headerTipHeight == 6
  Fix(path: path, cs: cs, sm: sm, peer: peer, other: other, chain: chain,
      forged: forged)

proc close(f: var Fix) =
  f.cs.close()
  removeDir(f.path)

proc request(f: Fix, height: int) =
  let h = hashOf(f.chain[height])
  f.sm.requestedHashes.incl(h)
  f.sm.pendingBlocks += 1
  f.sm.noteBlockRequested(h, f.peer)

suite "IsBlockMutated 64-byte clause: processBlock never condemns the hash":

  test "next-block path: a forged 64-byte body does not mark the hash invalid":
    var f = buildFix("/tmp/nimrod_cffix64_1", forgedFrom = 3)
    defer: f.close()
    let h3 = hashOf(f.chain[3])
    f.request(3)
    check not f.sm.processBlock(f.peer, f.forged[3])
    check not f.sm.isKnownInvalid(h3)
    check not f.sm.isKnownInvalid(hashOf(f.chain[4]))
    check f.sm.chainTipHeight == 2
    # Punished as mutated (Core Misbehaving "mutated block").
    check f.peer.shouldDisconnect

  test "out-of-order path: a forged 64-byte body is not buffered":
    var f = buildFix("/tmp/nimrod_cffix64_2", forgedFrom = 5)
    defer: f.close()
    f.request(5)
    check not f.sm.processBlock(f.peer, f.forged[5])
    check 5'i32 notin f.sm.receivedBlocks
    check not f.sm.isKnownInvalid(hashOf(f.chain[5]))

  test "a forged body from another peer does not cancel the owner's request":
    # Core RemoveBlockRequest(hash, from_peer): only the sender's request is
    # released; the honest download stays in flight and counted.
    var f = buildFix("/tmp/nimrod_cffix64_4", forgedFrom = 5)
    defer: f.close()
    let h5 = hashOf(f.chain[5])
    f.request(5)                       # owned by f.peer
    let pendingBefore = f.sm.pendingBlocks
    check not f.sm.processBlock(f.other, f.forged[5])
    check h5 in f.sm.requestedHashes
    check h5 in f.sm.blocksInFlight
    check f.sm.blocksInFlight[h5].peer == f.peer
    check f.sm.pendingBlocks == pendingBefore
    check f.other.shouldDisconnect
    check not f.sm.isKnownInvalid(h5)

  test "control: an honest next block still connects":
    var f = buildFix("/tmp/nimrod_cffix64_3", forgedFrom = 7)
    defer: f.close()
    f.request(3)
    check f.sm.processBlock(f.peer, f.chain[3])
    check f.sm.chainTipHeight == 3
    check not f.peer.shouldDisconnect

# ---------------------------------------------------------------------------
# End to end with a REAL collision: a valid regtest 2-tx block at height 102
# whose cbTxid||tx2Txid parses as a 64-byte legacy transaction. The two
# constants below were ground once and are fixed here: the first coinbase
# tag t (scriptSig suffix [t and 0xff, t shr 8]) whose txid has byte 4 ==
# 0x01 (the vin count), and the first tx2 lockTime whose txid h has
# s = h[9] <= 4 (scriptSig length), h[14+s] == 0x01 (vout count) and
# h[23+s] == 4-s (scriptPubKey length). The sequence is final, so the
# lockTime is free. buildCollisionFix asserts the collision still holds.

const CollisionCbTag = 262
const CollisionLockTime = 721_785'u32

proc coinbaseTagged(height: int32, tag: seq[byte]): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x00)] & tag,
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0)

type CollisionFix = object
  path: string
  cs: ChainState
  sm: SyncManager
  attacker, honest: Peer
  real, forged: Block

proc buildCollisionFix(path: string): CollisionFix =
  removeDir(path)
  createDir(path)
  let p = regtestParams()
  var cs = newChainState(path / "chain", p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  var chain = @[g]
  for h in 1'i32 .. 101'i32:
    chain.add mineOn(chain[^1], h, byte(h))
    doAssert cs.connectBlock(chain[^1], h).isOk
  # Block 102: coinbase + a spend of block 1's (now mature) OP_TRUE coinbase.
  let cb = coinbaseTagged(102, @[byte(CollisionCbTag and 0xff),
                                 byte(CollisionCbTag shr 8)])
  let spend = Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: chain[1].txs[0].txid(), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(4_999_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: CollisionLockTime)
  let txs = @[cb, spend]
  let real = Block(header: headerOver(hashOf(chain[^1]),
                                      chain[^1].header.timestamp + 600,
                                      rootOf(txs)),
                   txs: txs)
  # The forged body: the inner merkle node, parsed as one transaction.
  let node = @(array[32, byte](cb.txid())) & @(array[32, byte](spend.txid()))
  let fakeTx = deserializeTransactionExact(node, tryWitness = false)
  doAssert serializeLegacy(fakeTx) == node, "grind constants no longer collide"
  doAssert array[32, byte](fakeTx.txid()) == real.header.merkleRoot
  let forged = Block(header: real.header, txs: @[fakeTx])
  createDir(path / "pm")
  let pm = newPeerManager(p, 8, 2, 117, path / "pm")
  let sm = newSyncManager(pm, cs.db, p, cs)
  let attacker = pm.readyPeer("198.51.100.71", p)
  let honest = pm.readyPeer("198.51.100.72", p)
  attacker.startHeight = 102
  honest.startHeight = 102
  waitFor sm.handleHeaders(honest, @[real.header])
  doAssert sm.chainTipHeight == 101
  doAssert sm.headerTipHeight == 102
  CollisionFix(path: path, cs: cs, sm: sm, attacker: attacker, honest: honest,
               real: real, forged: forged)

proc close(f: var CollisionFix) =
  f.cs.close()
  removeDir(f.path)

proc requestFrom(f: CollisionFix, peer: Peer) =
  let h = hashOf(f.real)
  f.sm.requestedHashes.incl(h)
  f.sm.pendingBlocks += 1
  f.sm.noteBlockRequested(h, peer)

suite "IsBlockMutated 64-byte clause: a real merkle collision":

  test "the forged body of a real block reproduces its merkle root but is mutated":
    var f = buildCollisionFix("/tmp/nimrod_cffix64_c1")
    defer: f.close()
    check bodyMatchesCommitments(f.real, true)
    check not bodyMatchesCommitments(f.forged, true)
    check not bodyMatchesCommitments(f.forged, false)

  test "after the forged body, the real block still connects":
    var f = buildCollisionFix("/tmp/nimrod_cffix64_c2")
    defer: f.close()
    let h = hashOf(f.real)
    f.requestFrom(f.attacker)
    check not f.sm.processBlock(f.attacker, f.forged)
    check not f.sm.isKnownInvalid(h)
    check f.attacker.shouldDisconnect
    f.requestFrom(f.honest)
    check f.sm.processBlock(f.honest, f.real)
    check f.sm.chainTipHeight == 102
    check f.sm.chainTip == h

  test "control: the real block alone connects":
    var f = buildCollisionFix("/tmp/nimrod_cffix64_c3")
    defer: f.close()
    f.requestFrom(f.honest)
    check f.sm.processBlock(f.honest, f.real)
    check f.sm.chainTipHeight == 102
