## fix-pruned-nodes-advertise-network (nimrod#59 review): the
## NODE_NETWORK_LIMITED getdata gate, driven through the real P2P handler.
##
## Core v31.1 ProcessGetBlockData, for every block inv type (MSG_BLOCK,
## MSG_WITNESS_BLOCK, MSG_CMPCTBLOCK) before it picks compact vs full:
##   * BlockRequestAllowed: a block not in the active chain is ignored, the
##     peer is NOT disconnected;
##   * a limited-only node disconnects a peer asking for an active-chain
##     block more than NODE_NETWORK_LIMITED_MIN_BLOCKS + 2 (290) below tip;
##   * otherwise the block is sent when BLOCK_HAVE_DATA is set, so tip-289
##     and tip-290 (the race buffer) are still served.
##
## Drives nimrod.handleMessage (via {.all.}) against a temp regtest
## ChainState, with the peer on a loopback socket so whatever the handler
## sends is read back off the wire.
##
## Command:  nim c -r tests/test_pruned_getdata_handler.nim

import unittest2
import std/[os, sets, tempfiles, options]
import chronos
import ../src/nimrod {.all.}
import ../src/mempool/[mempool, orphan]
import ../src/storage/chainstate
import ../src/network/[peer, peermanager, messages]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/params

const ChainLen = 300   # heights 0..299, tip = 299

proc coinbaseTx(height: int32, tag: byte = 0): Transaction =
  let sig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff), tag]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction],
             nonce: uint32): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: nonce),
        txs: txs)

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

type Fixture = object
  dir: string
  cs: ChainState
  state: NodeState
  server: StreamServer
  remote: Peer          ## our side of the socket: reads what nimrod sends
  peer: Peer            ## the peer the handler sees
  hashes: seq[BlockHash]
  sideHash: BlockHash   ## side block at height 5, body stored, not active

proc setupFixture(): Fixture =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_pruned_getdata_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 ..< ChainLen:
    let blk = blockOf(prev, int32(h), @[coinbaseTx(int32(h))], uint32(h))
    let r = result.cs.connectBlock(blk, int32(h))
    doAssert r.isOk, "fixture connect failed at " & $h
    let bh = hashOf(blk)
    if result.cs.db.getBlock(bh).isNone:
      result.cs.db.storeBlock(blk)   # body on disk (BLOCK_HAVE_DATA)
    result.hashes.add(bh)
    prev = bh
  # A side block at height 5: index entry + body, but not on the active chain.
  let side = blockOf(result.hashes[4], 5'i32, @[coinbaseTx(5'i32, 0xEE)], 0xDEAD'u32)
  result.sideHash = hashOf(side)
  result.cs.db.storeBlock(side)
  result.cs.db.putBlockIndexHashOnly(BlockIndex(
    hash: result.sideHash, height: 5, status: bsDataStored,
    prevHash: side.header.prevBlock, header: side.header,
    undoPos: FlatFilePos(fileNum: -1, pos: -1),
    failureFlags: BLOCK_NO_FAILURE, nTx: 1))

  let mp = newMempool(result.cs, params, minFeeRate = 0.0)
  result.state = NodeState(
    params: params, chainState: result.cs, mempool: mp,
    peerManager: newPeerManager(params, 8, 2, 117, result.dir),
    crypto: newCryptoEngine(),
    recentlyRejected: initHashSet[TxId](),
    orphanPool: newOrphanPool())

  var accepted: StreamTransport = nil
  proc onConn(server: StreamServer, t: StreamTransport) {.async: (raises: []).} =
    accepted = t
  result.server = createStreamServer(initTAddress("127.0.0.1", Port(0)), onConn,
                                     {ServerFlags.ReuseAddr})
  result.server.start()
  let port = result.server.localAddress().port
  result.peer = newPeer("127.0.0.1", uint16(port), params, pdInbound)
  result.peer.transport = waitFor connect(initTAddress("127.0.0.1", port))
  result.peer.state = psReady
  while accepted == nil:
    waitFor sleepAsync(chronos.milliseconds(5))
  result.remote = newPeer("127.0.0.1", uint16(port), params, pdOutbound)
  result.remote.transport = accepted
  result.remote.state = psReady

proc teardownFixture(f: var Fixture) =
  if not f.peer.transport.closed: f.peer.transport.close()
  if not f.remote.transport.closed: f.remote.transport.close()
  f.server.stop()
  f.server.close()
  f.cs.close()
  removeDir(f.dir)

proc ask(f: Fixture, t: InvType, hash: BlockHash) =
  waitFor handleMessage(f.state, f.peer,
    newGetData(@[InvVector(invType: t, hash: array[32, byte](hash))]))

proc reply(f: Fixture, ms = 1000): (bool, P2PMessage) =
  let fut = f.remote.readMessage()
  try:
    if waitFor fut.withTimeout(chronos.milliseconds(ms)):
      return (true, fut.read())
  except CatchableError:
    discard
  (false, P2PMessage(kind: mkVerack))

proc atDepth(f: Fixture, depth: int): BlockHash =
  ## Active-chain block `depth` below the tip.
  f.hashes[ChainLen - 1 - depth]

proc expectServed(f: Fixture, want: BlockHash) =
  check f.peer.state != psDisconnected
  let (got, msg) = f.reply()
  check got
  if got:
    check msg.kind == mkBlock
    if msg.kind == mkBlock:
      check hashOf(msg.blk) == want

suite "pruned getdata through the real handler (nimrod#59 review)":
  setup:
    var f = setupFixture()
    setPruneModeAdvertise(true)       # NODE_NETWORK_LIMITED only
  teardown:
    setPruneModeAdvertise(false)
    setFullHistoryAdvertise(true)
    f.teardownFixture()

  test "fixture: tip is 299, side block is off the active chain":
    check f.cs.bestHeight == int32(ChainLen - 1)
    check not servesFullHistory()
    check f.cs.db.getBlockHashByHeight(5'i32).get() != f.sideHash
    check f.cs.db.getBlock(f.atDepth(289)).isSome

  test "review 1: limited node serves a stored body at tip-289":
    f.ask(invWitnessBlock, f.atDepth(289))
    f.expectServed(f.atDepth(289))

  test "review 1: limited node serves a stored body at tip-290":
    f.ask(invBlock, f.atDepth(290))
    f.expectServed(f.atDepth(290))

  test "limited node disconnects on an active-chain block at tip-291":
    f.ask(invWitnessBlock, f.atDepth(291))
    check f.peer.state == psDisconnected
    let (got, _) = f.reply(300)
    check not got

  test "review 2: side block below the window leaves the peer connected":
    f.ask(invWitnessBlock, f.sideHash)
    check f.peer.state != psDisconnected
    let (got, msg) = f.reply()
    check got
    if got:
      check msg.kind == mkNotFound   # refused, never served

  test "review 3: cmpctblock getdata below the window disconnects":
    f.ask(invCmpctBlock, f.atDepth(295))
    check f.peer.state == psDisconnected
    let (got, _) = f.reply(300)
    check not got

  test "review 3: cmpctblock inside the window still gets the full block":
    f.ask(invCmpctBlock, f.atDepth(289))
    f.expectServed(f.atDepth(289))

  test "control: a full-history node serves a deep block and stays connected":
    setPruneModeAdvertise(false)
    setFullHistoryAdvertise(true)
    check servesFullHistory()
    f.ask(invWitnessBlock, f.atDepth(295))
    f.expectServed(f.atDepth(295))
