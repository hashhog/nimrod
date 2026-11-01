## The IBD out-of-order buffer holds only bodies we asked for, from the peer
## we asked, whose transactions match the header's commitments, and an entry
## is never replaced (security audit 2026-10-31, H4).
##
## Before this, processBlock buffered ANY body whose header sat in the
## not-yet-connected window into `receivedBlocks[height]`: `wasRequested` was
## computed and ignored, there was no merkle check, and a later copy
## overwrote the first. A peer could fill RAM with up to (headerTip - tip)
## unrequested blocks, and a copy with the right header but altered
## transactions replaced the honest buffered body (only rejected, as mutated,
## when the buffer drained).
##
## Bitcoin Core keeps no RAM buffer: ProcessNewBlock runs CheckBlock (merkle +
## witness commitment, BLOCK_MUTATED) before AcceptBlock, AcceptBlock drops
## unrequested far-ahead blocks, and RemoveBlockRequest(hash, from_peer) leaves
## a block in flight from another peer alone (net_processing.cpp).

import unittest2
import std/[options, os, tables, sets]
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

proc mineOn(prev: Block, height: int32, tag: byte): Block =
  let cb = coinbaseTx(height, tag)
  var hdr = BlockHeader(version: 4, prevBlock: hashOf(prev),
    merkleRoot: merkleRoot(@[array[32, byte](cb.txid())]),
    timestamp: prev.header.timestamp + 600, bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb])

proc witnessSpend(item: byte): Transaction =
  ## A transaction with witness data, so its wtxid differs from its txid.
  ## The outpoint is made up: these bodies are only ever buffered, never
  ## connected.
  var ghost: array[32, byte]
  ghost[0] = 0x5A
  Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(ghost), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[@[@[item, item, item]]],
    lockTime: 0)

proc mineSegwitOn(prev: Block, height: int32): Block =
  ## Coinbase carries the BIP-141 witness commitment over [0, spend.wtxid].
  let spend = witnessSpend(0x01)
  var nonce: array[32, byte]
  let commitment = computeWitnessCommitment(
    @[default(array[32, byte]), array[32, byte](spend.wtxid())], nonce)
  var cb = coinbaseTx(height, 0x5E)
  cb.outputs.add TxOut(value: Satoshi(0),
    scriptPubKey: @[byte(0x6a), 0x24, 0xaa, 0x21, 0xa9, 0xed] & @commitment)
  cb.witnesses = @[@[@nonce]]
  var hdr = BlockHeader(version: 4, prevBlock: hashOf(prev),
    merkleRoot: merkleRoot(@[array[32, byte](cb.txid()),
                             array[32, byte](spend.txid())]),
    timestamp: prev.header.timestamp + 600, bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb, spend])

proc witnessMutatedCopy(b: Block): Block =
  ## Same transactions by txid (same merkle root, same block hash), different
  ## witness: only the witness commitment catches it.
  result = b
  result.txs[1] = witnessSpend(0x02)
  doAssert result.txs[1].txid() == b.txs[1].txid()

proc mutatedCopy(b: Block, height: int32): Block =
  ## Same header (so the same block hash), different transactions: the
  ## merkle root no longer matches. Core CheckBlock -> BLOCK_MUTATED.
  Block(header: b.header, txs: @[coinbaseTx(height, 0xEE)])

type Fix = object
  path: string
  cs: ChainState
  sm: SyncManager
  honest, other: Peer
  chain: seq[Block]   # genesis .. 2 connected; 3 .. 6 header-only

proc readyPeer(pm: PeerManager, ip: string, p: ConsensusParams): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = 6
  pm.peers[ip & ":8333"] = result

proc buildFix(path: string, segwitAt5 = false): Fix =
  removeDir(path)
  createDir(path)
  let p = regtestParams()
  var cs = newChainState(path / "chain", p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  var chain = @[g]
  for h in 1'i32 .. 6'i32:
    chain.add(if segwitAt5 and h == 5: mineSegwitOn(chain[^1], h)
              else: mineOn(chain[^1], h, byte(h)))
    if h <= 2:
      doAssert cs.connectBlock(chain[^1], h).isOk
  createDir(path / "pm")
  let pm = newPeerManager(p, 8, 2, 117, path / "pm")
  let sm = newSyncManager(pm, cs.db, p, cs)
  let honest = pm.readyPeer("198.51.100.41", p)
  let other = pm.readyPeer("198.51.100.42", p)
  var hdrs: seq[BlockHeader]
  for h in 3 .. 6: hdrs.add chain[h].header
  waitFor sm.handleHeaders(honest, hdrs)
  doAssert sm.chainTipHeight == 2
  doAssert sm.headerTipHeight == 6
  Fix(path: path, cs: cs, sm: sm, honest: honest, other: other, chain: chain)

proc close(f: var Fix) =
  f.cs.close()
  removeDir(f.path)

proc request(f: Fix, height: int, peer: Peer) =
  ## What requestBlocks records for a getdata (Core BlockRequested).
  let h = hashOf(f.chain[height])
  f.sm.requestedHashes.incl(h)
  f.sm.pendingBlocks += 1
  f.sm.noteBlockRequested(h, peer)

suite "IBD out-of-order buffer: requested, commitment-checked, never overwritten (H4)":

  test "an unrequested far-ahead block is not buffered":
    var f = buildFix("/tmp/nimrod_ibd_unreq_1")
    defer: f.close()
    discard f.sm.processBlock(f.other, f.chain[6])
    check 6'i32 notin f.sm.receivedBlocks
    check f.sm.receivedBlocks.len == 0

  test "a mutated copy does not replace an honest buffered block":
    var f = buildFix("/tmp/nimrod_ibd_unreq_2")
    defer: f.close()
    f.request(5, f.honest)
    check f.sm.processBlock(f.honest, f.chain[5])
    check 5'i32 in f.sm.receivedBlocks
    discard f.sm.processBlock(f.other, mutatedCopy(f.chain[5], 5))
    check f.sm.receivedBlocks[5'i32].txs == f.chain[5].txs
    check bodyMatchesCommitments(f.sm.receivedBlocks[5'i32], false)

  test "a mutated copy from the peer we asked is not buffered, and it is punished":
    var f = buildFix("/tmp/nimrod_ibd_unreq_3")
    defer: f.close()
    f.request(5, f.honest)
    check not f.sm.processBlock(f.honest, mutatedCopy(f.chain[5], 5))
    check 5'i32 notin f.sm.receivedBlocks
    check f.honest.shouldDisconnect
    # Released, so the next requestBlocks pass asks someone else.
    check hashOf(f.chain[5]) notin f.sm.requestedHashes

  test "another peer's copy does not cancel the request: the owner's body is buffered":
    var f = buildFix("/tmp/nimrod_ibd_unreq_4")
    defer: f.close()
    f.request(5, f.honest)
    discard f.sm.processBlock(f.other, mutatedCopy(f.chain[5], 5))
    check 5'i32 notin f.sm.receivedBlocks
    check hashOf(f.chain[5]) in f.sm.requestedHashes
    check hashOf(f.chain[5]) in f.sm.blocksInFlight
    check f.sm.processBlock(f.honest, f.chain[5])
    check f.sm.receivedBlocks[5'i32].txs == f.chain[5].txs

  test "a witness-mutated copy is not buffered; the committed segwit body is":
    var f = buildFix("/tmp/nimrod_ibd_unreq_6", segwitAt5 = true)
    defer: f.close()
    let honestBody = f.chain[5]
    check bodyMatchesCommitments(honestBody, true)
    check not bodyMatchesCommitments(witnessMutatedCopy(honestBody), true)
    f.request(5, f.other)
    check not f.sm.processBlock(f.other, witnessMutatedCopy(honestBody))
    check 5'i32 notin f.sm.receivedBlocks
    check f.other.shouldDisconnect
    f.request(5, f.honest)
    check f.sm.processBlock(f.honest, honestBody)
    check f.sm.receivedBlocks[5'i32].txs == honestBody.txs

  test "control: requested out-of-order bodies buffer and drain to the header tip":
    var f = buildFix("/tmp/nimrod_ibd_unreq_5")
    defer: f.close()
    for h in 3 .. 6: f.request(h, f.honest)
    for h in [6, 4, 5]:
      check f.sm.processBlock(f.honest, f.chain[h])
    check f.sm.receivedBlocks.len == 3
    check f.sm.processBlock(f.honest, f.chain[3])
    check f.sm.chainTipHeight == 6
    check f.sm.chainTip == hashOf(f.chain[6])
    check f.sm.receivedBlocks.len == 0
    check f.sm.pendingBlocks == 0
    check not f.honest.shouldDisconnect
