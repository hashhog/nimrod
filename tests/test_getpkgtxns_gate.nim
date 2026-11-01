## BIP-331 `getpkgtxns` is served only to a peer that negotiated package
## relay, and the child is found by wtxid, not by its txid.
##
## Security audit 2026-10-31, H5: the handler in nimrod.nim never read
## `peer.sendsPackages`, so any peer could ask, and it found the child by
## walking every mempool entry and recomputing `wtxid()` (re-serialize +
## double-SHA256) per entry, once per 32-byte message, on the P2P event
## loop. The fix gates on `sendsPackages` and resolves the child through
## `Mempool.getByWtxid` (the byWtxid index). It also records `sendpackages`
## in NodeState.handleMessage: the only other place that set the flag,
## peer.nim's handleMessage, never runs once PeerManager installs its
## message callback, so without that the gate would never open.
##
## Bitcoin Core has no getpkgtxns (BIP-331 is not merged), so the reference
## here is BIP-331 itself: package-relay messages are only exchanged after
## both sides sent `sendpackages`.
##
## Drives the real P2P handler (nimrod.handleMessage, via {.all.}) against a
## real Mempool on a temp regtest ChainState, with the peer on a loopback
## socket so whatever the handler sends is read back off the wire.
##
## Command:  nim c -r tests/test_getpkgtxns_gate.nim

import unittest2
import std/[os, sets, tempfiles]
import chronos
import ../src/nimrod {.all.}
import ../src/mempool/[mempool, orphan]
import ../src/storage/chainstate
import ../src/network/[peer, peermanager, messages]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/params
import ../src/script/interpreter

# P2SH(OP_TRUE): standard output, spendable with scriptSig = push(OP_TRUE).
proc p2shTrue(): seq[byte] =
  let h = hash160(@[byte(OP_TRUE)])
  @[byte(OP_HASH160), 0x14] & @h & @[byte(OP_EQUAL)]

# P2WSH(OP_TRUE): spending it puts a witness on the child, so the child's
# wtxid differs from its txid.
proc p2wshTrue(): seq[byte] =
  let h = sha256Single(@[byte(OP_TRUE)])
  @[byte(OP_0), 0x20] & @h

proc coinbaseTx(height: int32): Transaction =
  let sig = @[byte(0x01), byte(height and 0xff), byte(0x00)]
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: sig, sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: p2shTrue())],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

type Fixture = object
  dir: string
  cs: ChainState
  state: NodeState
  server: StreamServer
  remote: Peer          ## our side of the socket: reads what nimrod sends
  peer: Peer            ## the peer the handler sees
  parent: Transaction   ## P2SH(OP_TRUE) coin -> P2WSH(OP_TRUE)
  child: Transaction    ## spends parent with a witness; wtxid != txid

proc setupFixture(): Fixture =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_getpkgtxns_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  var coin: TxId
  for h in 0 .. 110:
    let blk = blockOf(prev, int32(h), @[coinbaseTx(int32(h))])
    discard result.cs.connectBlock(blk, int32(h))
    if h == 1:
      coin = blk.txs[0].txid()
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  let mp = newMempool(result.cs, params, minFeeRate = 0.0)
  result.state = NodeState(
    params: params, chainState: result.cs, mempool: mp,
    peerManager: newPeerManager(params, 8, 2, 117, result.dir),
    crypto: newCryptoEngine(),
    recentlyRejected: initHashSet[TxId](),
    orphanPool: newOrphanPool())

  result.parent = Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: coin, vout: 0),
                   scriptSig: @[byte(0x01), byte(OP_TRUE)],
                   sequence: 0xFFFFFFFE'u32)],
    outputs: @[TxOut(value: Satoshi(4_999_990_000), scriptPubKey: p2wshTrue())],
    witnesses: @[], lockTime: 0)
  result.child = Transaction(
    version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: result.parent.txid(), vout: 0),
                   scriptSig: @[], sequence: 0xFFFFFFFE'u32)],
    outputs: @[TxOut(value: Satoshi(4_999_980_000), scriptPubKey: p2shTrue())],
    witnesses: @[@[@[byte(OP_TRUE)]]], lockTime: 0)
  let rp = mp.acceptTransaction(result.parent, result.state.crypto)
  doAssert rp.isOk, "fixture parent rejected: " & rp.error
  let rc = mp.acceptTransaction(result.child, result.state.crypto)
  doAssert rc.isOk, "fixture child rejected: " & rc.error

  # Loopback pair: `peer` writes, `remote` reads.
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

proc negotiate(f: Fixture) =
  ## Send `sendpackages` the way the node receives it after verack:
  ## PeerManager's messageLoop callback hands it to NodeState.handleMessage.
  waitFor handleMessage(f.state, f.peer, newSendPackages())

proc ask(f: Fixture, wtxid: array[32, byte]) =
  waitFor handleMessage(f.state, f.peer, newGetPkgTxns(wtxid))

proc reply(f: Fixture, ms = 500): (bool, P2PMessage) =
  ## The next message nimrod sent to the peer, if one arrives within `ms`.
  let fut = f.remote.readMessage()
  if waitFor fut.withTimeout(chronos.milliseconds(ms)):
    (true, fut.read())
  else:
    (false, P2PMessage(kind: mkVerack))

suite "getpkgtxns: sendpackages gate and wtxid lookup (audit H5)":

  test "fixture: the child's wtxid differs from its txid":
    var f = setupFixture()
    check f.child.wtxid() != f.child.txid()
    check f.state.mempool.contains(f.parent.txid())
    check f.state.mempool.contains(f.child.txid())
    f.teardownFixture()

  test "a peer that did not send sendpackages gets no pkgtxns reply":
    var f = setupFixture()
    check not f.peer.sendsPackages
    f.ask(array[32, byte](f.child.wtxid()))
    let (got, msg) = f.reply()
    check not got
    if got:
      checkpoint "unexpected reply: " & $msg.kind
    f.teardownFixture()

  test "sendpackages through the node's dispatcher records package relay":
    ## peer.nim's own mkSendPackages branch is never reached in the node
    ## (messageLoop only calls it when no callback is installed), so the
    ## NodeState dispatcher must record it or the gate never opens.
    var f = setupFixture()
    check not f.peer.sendsPackages
    f.negotiate()
    check f.peer.sendsPackages
    f.teardownFixture()

  test "a peer that sent sendpackages gets parent then child":
    var f = setupFixture()
    f.negotiate()
    check f.peer.sendsPackages
    f.ask(array[32, byte](f.child.wtxid()))
    let (got, msg) = f.reply(2000)
    check got
    if got:
      check msg.kind == mkPkgTxns
      if msg.kind == mkPkgTxns:
        check msg.pkgTxns.transactions.len == 2
        if msg.pkgTxns.transactions.len == 2:
          check msg.pkgTxns.transactions[0].txid() == f.parent.txid()
          check msg.pkgTxns.transactions[1].txid() == f.child.txid()
    f.teardownFixture()

  test "the child's txid is not a wtxid: no reply even after sendpackages":
    var f = setupFixture()
    f.negotiate()
    f.ask(array[32, byte](f.child.txid()))
    let (got, _) = f.reply()
    check not got
    f.teardownFixture()

  test "an unknown wtxid gets no reply after sendpackages":
    var f = setupFixture()
    f.negotiate()
    var unknown: array[32, byte]
    for i in 0 ..< 32: unknown[i] = 0xAB
    f.ask(unknown)
    let (got, _) = f.reply()
    check not got
    f.teardownFixture()
