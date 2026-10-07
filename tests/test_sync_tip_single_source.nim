## The active chain has ONE source of truth: ChainState's tip. The sync
## manager must read it, never keep its own copy, and the tip may move ONLY by
## connecting or disconnecting a block.
##
## Bitcoin Core: `m_chain` (CChain) is the active chain; every tip change is
## ConnectTip / DisconnectTip inside ActivateBestChainStep under cs_main, and a
## switch to a better branch first disconnects back to the fork point
## (validation.cpp ActivateBestChainStep: "Disconnect active blocks which are
## no longer in the best chain"). net_processing reads the tip from chainman
## (`m_chainman.ActiveChain().Tip()`) on every message; it never caches it.
##
## Up to a43ef73 nimrod's SyncManager kept `chainTip` / `chainTipHeight` as a
## private copy that only sync's own applyBlock / P2P-reorg arm wrote:
##
##   (1) after an RPC connect (submitblock / generate*) the copy is stale, so
##       sync's next block "does not connect" (wedge), the child's header is
##       "unconnecting", and a VALID competitor of the RPC block is validated
##       against the wrong coins and marked BLOCK_FAILED_VALID;
##   (2) the syncLoop "chain tip mismatch" arm (sync.nim:4067-4097) moved
##       ChainState's tip pointer to an ancestor WITHOUT disconnecting — after
##       a P2P reorg whose header chain still showed the old branch, the tip
##       said A3 while the UTXO set held B4's coins, and the next A block then
##       connected on top of them (coins from both branches live at once).

import unittest2
import chronos
import std/[options, os, json, tables, sets]
import ../src/network/sync
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

const EASY_BITS = 0x207fffff'u32
const BASE_TIME = 1_700_000_000'u32

proc hashOf(h: BlockHeader): BlockHash = BlockHash(doubleSha256(serialize(h)))
proc hashOf(b: Block): BlockHash = hashOf(b.header)

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc short(h: BlockHash): string =
  var r: array[32, byte]
  for i in 0 ..< 32: r[i] = array[32, byte](h)[31 - i]
  hexOf(r)[0 ..< 12]

proc makeCoinbaseTx(height: int32, tag: byte): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)

proc mineBlock(prevHash: BlockHash, height: int32, ts: uint32, tag: byte,
               extra: seq[Transaction] = @[]): Block =
  let cb = makeCoinbaseTx(height, tag)
  var txids = @[array[32, byte](cb.txid())]
  for t in extra: txids.add(array[32, byte](t.txid()))
  var hdr = BlockHeader(version: 4, prevBlock: prevHash,
                        merkleRoot: merkleRoot(txids), timestamp: ts,
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb] & extra)

proc spend(prev: OutPoint, value: int64, spkTag: byte): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: prev, scriptSig: @[], sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51), spkTag])],
    witnesses: @[], lockTime: 0)

proc cbOut(b: Block): OutPoint = OutPoint(txid: b.txs[0].txid(), vout: 0'u32)

proc testParams(): ConsensusParams =
  result = regtestParams()
  result.coinbaseMaturity = 1

proc newRpc(cs: ChainState, p: ConsensusParams): RpcServer =
  newRpcServer(port = 18443'u16, chainState = cs, mempool = newMempool(cs, p),
               peerManager = nil, feeEstimator = newFeeEstimator(), params = p)

proc newReadyPeer(p: ConsensusParams, pm: PeerManager, ip: string): Peer =
  result = newPeer(ip, 8333, p, pdInbound)
  result.services = NodeNetwork or NodeWitness
  result.state = psReady
  result.startHeight = 1000
  pm.peers[ip & ":8333"] = result

proc utxoStats(rpc: RpcServer): JsonNode =
  let r = rpc.handleMethod("gettxoutsetinfo", %*[])
  %*{"height": r["height"], "bestblock": r["bestblock"], "txouts": r["txouts"],
     "hash": r["hash_serialized_3"], "total_amount": r["total_amount"]}

proc referenceStats(path: string, p: ConsensusParams, blocks: seq[Block]): JsonNode =
  ## The UTXO set a node holds when it connected exactly `blocks` (genesis
  ## first) and nothing else — the oracle for the tip it reports.
  removeDir(path)
  var cs = newChainState(path, p)
  for i, b in blocks:
    doAssert cs.connectBlock(b, int32(i)).isOk, "reference connect " & $i
  result = utxoStats(newRpc(cs, p))
  cs.close()
  removeDir(path)

proc runSyncLoopBriefly(sm: SyncManager, ms = 400) =
  ## One real syncLoop pass (or a few): the tip-mismatch arm runs at the top
  ## of every ssDownloadingBlocks iteration.
  sm.state = ssDownloadingBlocks
  let fut = sm.syncLoop()
  waitFor sleepAsync(ms.milliseconds)
  waitFor fut.cancelAndWait()

# --- fixture: genesis + 3 blocks connected directly; block 1 pays an
#     OP_TRUE coinbase that both X and Y can spend (maturity 1). -------------

type Fix = object
  path: string
  p: ConsensusParams
  cs: ChainState
  sm: SyncManager
  rpc: RpcServer
  pm: PeerManager
  peer: Peer
  chain: seq[Block]      # genesis .. block 3

proc buildFix(path: string): Fix =
  removeDir(path)
  let p = testParams()
  var cs = newChainState(path, p)
  let g = buildGenesisBlock(p)
  doAssert cs.connectBlock(g, 0'i32).isOk
  var chain = @[g]
  var prev = p.genesisBlockHash
  var ts = BASE_TIME
  for h in 1'i32 .. 3'i32:
    let b = mineBlock(prev, h, ts, 0x00)
    doAssert cs.connectBlock(b, h).isOk
    chain.add b
    prev = hashOf(b)
    ts += 600
  let pm = newPeerManager(p, 8, 2, 117, getTempDir())
  let sm = newSyncManager(pm, cs.db, p, cs)
  let peer = newReadyPeer(p, pm, "203.0.113.77")
  Fix(path: path, p: p, cs: cs, sm: sm, rpc: newRpc(cs, p), pm: pm,
      peer: peer, chain: chain)

proc submit(f: Fix, b: Block): string =
  $f.rpc.handleMethod("submitblock", %*[hexOf(serialize(b))])

suite "sync reads the active tip from ChainState (item 1: RPC connect)":

  test "submitblock(X) then sync applyBlock(Z on X) — Z connects":
    var f = buildFix("/tmp/nimrod_synctip_1")
    defer:
      f.cs.close()
      removeDir(f.path)
    let t = f.chain[3]
    let x = mineBlock(hashOf(t), 4, t.header.timestamp + 600, 0x01)
    check f.submit(x) == "null"
    check f.cs.bestBlockHash == hashOf(x)
    checkpoint "after submitblock(X): ChainState tip=" & $f.cs.bestHeight & " " &
               short(f.cs.bestBlockHash) & "  sync tip=" & $f.sm.chainTipHeight &
               " " & short(f.sm.chainTip)
    # One active chain: sync sees what ChainState has.
    check f.sm.chainTip == f.cs.bestBlockHash
    check f.sm.chainTipHeight == f.cs.bestHeight
    let z = mineBlock(hashOf(x), 5, x.header.timestamp + 600, 0x02)
    let ok = f.sm.applyBlock(z, 5'i32)
    checkpoint "applyBlock(Z@5 on X) = " & $ok & " lastApplyError='" &
               f.sm.lastApplyError & "'"
    check ok
    check f.cs.bestBlockHash == hashOf(z)
    check f.cs.bestHeight == 5

  test "P2P after submitblock(X): child Z's header connects and its body is applied":
    var f = buildFix("/tmp/nimrod_synctip_2")
    defer:
      f.cs.close()
      removeDir(f.path)
    let t = f.chain[3]
    let x = mineBlock(hashOf(t), 4, t.header.timestamp + 600, 0x01)
    check f.submit(x) == "null"
    let z = mineBlock(hashOf(x), 5, x.header.timestamp + 600, 0x02)
    waitFor f.sm.handleHeaders(f.peer, @[z.header])
    let zh = f.sm.headerChain.getHeight(hashOf(z))
    checkpoint "header chain tip=" & $f.sm.headerChain.tipHeight & " Z height=" &
               (if zh.isSome: $zh.get() else: "none (unconnecting)")
    check zh.isSome and zh.get() == 5
    let accepted = f.sm.processBlock(f.peer, z)
    checkpoint "processBlock(Z)=" & $accepted & " tip=" & $f.cs.bestHeight &
               " lastApplyError='" & f.sm.lastApplyError & "'"
    check accepted
    check f.cs.bestBlockHash == hashOf(z)

  test "P2P after submitblock(X): a VALID competitor Y is stored, not marked invalid":
    # X and Y both spend block 1's coinbase. In Core both are valid at height
    # 4; X arrived first and stays the tip, Y is a stored side block and its
    # sender is not punished.
    var f = buildFix("/tmp/nimrod_synctip_3")
    defer:
      f.cs.close()
      removeDir(f.path)
    let t = f.chain[3]
    let coin = cbOut(f.chain[1])
    let x = mineBlock(hashOf(t), 4, t.header.timestamp + 600, 0x01,
                      @[spend(coin, 4_999_000_000, 0x01)])
    let y = mineBlock(hashOf(t), 4, t.header.timestamp + 601, 0x02,
                      @[spend(coin, 4_998_000_000, 0x02)])
    check f.submit(x) == "null"
    waitFor f.sm.handleHeaders(f.peer, @[y.header])
    discard f.sm.processBlock(f.peer, y)
    checkpoint "after Y: tip=" & short(f.cs.bestBlockHash) & " X=" & short(hashOf(x)) &
               " Y=" & short(hashOf(y)) & " Y knownInvalid=" &
               $f.sm.isKnownInvalid(hashOf(y)) & " peer misbehavior=" &
               $f.peer.misbehaviorScore & " shouldDisconnect=" &
               $f.peer.shouldDisconnect & " lastApplyError='" & f.sm.lastApplyError & "'"
    check f.cs.bestBlockHash == hashOf(x)
    check not f.sm.isKnownInvalid(hashOf(y))
    check f.peer.misbehaviorScore == 0
    check not f.peer.shouldDisconnect

suite "the tip moves only by connect / disconnect (item 2: sync.nim:4067)":

  test "P2P reorg while the header chain still shows the old branch — no pointer rewrite, UTXO matches tip":
    # Active A: genesis, A1 (direct), A2, A3 (sync). Header chain knows A4, A5.
    # Fork B from A1: B2, B3, B4 — heavier than the CONNECTED A3, so the
    # side-branch arm reorgs to B4 while the header chain still says A4 at 4.
    let path = "/tmp/nimrod_synctip_4"
    removeDir(path)
    let p = testParams()
    var cs = newChainState(path, p)
    defer:
      cs.close()
      removeDir(path)
    let g = buildGenesisBlock(p)
    doAssert cs.connectBlock(g, 0'i32).isOk
    let a1 = mineBlock(p.genesisBlockHash, 1, BASE_TIME, 0x0a)
    doAssert cs.connectBlock(a1, 1'i32).isOk
    var a = @[g, a1]
    for h in 2'i32 .. 5'i32:
      a.add mineBlock(hashOf(a[^1]), h, BASE_TIME + uint32(h) * 600, 0x0a)
    var b = @[g, a1]
    for h in 2'i32 .. 4'i32:
      b.add mineBlock(hashOf(b[^1]), h, BASE_TIME + uint32(h) * 600 + 7, 0x0b)
    let pm = newPeerManager(p, 8, 2, 117, getTempDir())
    let sm = newSyncManager(pm, cs.db, p, cs)
    let peer = newReadyPeer(p, pm, "203.0.113.78")
    let rpc = newRpc(cs, p)

    waitFor sm.handleHeaders(peer, @[a[2].header, a[3].header, a[4].header, a[5].header])
    check sm.headerChain.tipHeight == 5
    check sm.processBlock(peer, a[2])
    check sm.processBlock(peer, a[3])
    check cs.bestBlockHash == hashOf(a[3])

    waitFor sm.handleHeaders(peer, @[b[2].header, b[3].header, b[4].header])
    discard sm.processBlock(peer, b[2])
    discard sm.processBlock(peer, b[3])
    discard sm.processBlock(peer, b[4])
    checkpoint "after B bodies: tip=" & $cs.bestHeight & " " & short(cs.bestBlockHash) &
               " (B4=" & short(hashOf(b[4])) & ")  header@4=" &
               short(sm.headerChain.getHashByHeight(4).get())
    check cs.bestBlockHash == hashOf(b[4])
    let afterReorg = utxoStats(rpc)

    # The sync loop runs. Nothing was connected or disconnected, so neither
    # the tip nor the coins may change.
    runSyncLoopBriefly(sm)
    let afterLoop = utxoStats(rpc)
    checkpoint "after syncLoop: tip=" & $cs.bestHeight & " " & short(cs.bestBlockHash) &
               "  gettxoutsetinfo=" & $afterLoop
    checkpoint "gettxout(B4 coinbase)=" & $cs.getUtxo(cbOut(b[4])).isSome &
               " gettxout(A3 coinbase)=" & $cs.getUtxo(cbOut(a[3])).isSome
    check cs.bestBlockHash == hashOf(b[4])
    check cs.bestHeight == 4
    check afterLoop == afterReorg
    # The coins the tip claims are the coins it has.
    check afterLoop == referenceStats(path & "_ref1", p, b)

    # Now A4 and A5 arrive. A5 makes A heavier than B: the switch must
    # DISCONNECT B4..B2 and CONNECT A2..A5 — the UTXO set then equals a node
    # that only ever saw A.
    for blk in [a[4], a[5]]:
      discard sm.processBlock(peer, blk)
      runSyncLoopBriefly(sm, 200)
    let final = utxoStats(rpc)
    checkpoint "final: tip=" & $cs.bestHeight & " " & short(cs.bestBlockHash) &
               " (A5=" & short(hashOf(a[5])) & ")  gettxoutsetinfo=" & $final
    var bLive = 0
    for i in 2 .. 4:
      if cs.getUtxo(cbOut(b[i])).isSome: inc bLive
    checkpoint "B coinbases still in the UTXO set: " & $bLive & "/3"
    check bLive == 0
    check final == referenceStats(path & "_ref2", p, a)
    check cs.bestBlockHash == hashOf(a[5])
    check cs.bestHeight == 5

suite "RPC tip moves that are not extensions":

  test "invalidateblock(T) then reconsiderblock(T): sync neither re-fetches nor re-applies T, then follows the reconsider":
    var f = buildFix("/tmp/nimrod_synctip_5")
    defer:
      f.cs.close()
      removeDir(f.path)
    let t3 = f.chain[3]
    let t3h = hashOf(t3)
    # A peer has announced block 4 (header only) so sync has work above T3.
    let b4 = mineBlock(t3h, 4, t3.header.timestamp + 600, 0x04)
    waitFor f.sm.handleHeaders(f.peer, @[b4.header])
    check f.sm.headerChain.tipHeight == 4
    var hexT3: array[32, byte]
    for i in 0 ..< 32: hexT3[i] = array[32, byte](t3h)[31 - i]
    let inv = f.rpc.handleMethod("invalidateblock", %*[hexOf(hexT3)])
    checkpoint "invalidateblock -> " & $inv & " tip=" & $f.cs.bestHeight
    check f.cs.bestHeight == 2
    check f.sm.chainTipHeight == 2
    f.sm.blockQueue.clear()
    runSyncLoopBriefly(f.sm, 300)
    var queued = initHashSet[BlockHash]()
    for h in f.sm.blockQueue.items: queued.incl(h)
    checkpoint "after syncLoop: tip=" & $f.cs.bestHeight & " queued T3=" & $(t3h in queued) &
               " queued B4=" & $(hashOf(b4) in queued) & " headerTip=" & $f.sm.headerChain.tipHeight
    check t3h notin queued
    check hashOf(b4) notin queued
    # A peer delivering T3 anyway must not reconnect it.
    discard f.sm.processBlock(f.peer, t3)
    check f.cs.bestHeight == 2
    let rec = f.rpc.handleMethod("reconsiderblock", %*[hexOf(hexT3)])
    checkpoint "reconsiderblock -> " & $rec & " tip=" & $f.cs.bestHeight
    # nimrod's reconsiderblock clears the flags but does not itself reconnect
    # (Core's runs ActivateBestChain) — an RPC gap noted separately. Sync must
    # now accept T3 and B4 again: the header re-announce is not "bad-prevblk",
    # and the bodies connect from the active tip.
    waitFor f.sm.handleHeaders(f.peer, @[t3.header, b4.header])
    check not f.peer.shouldDisconnect
    check f.sm.headerChain.tipHeight == 4
    discard f.sm.processBlock(f.peer, t3)
    check f.sm.processBlock(f.peer, b4)
    check f.cs.bestHeight == 4
    check f.sm.chainTip == hashOf(b4)

  test "generatetoaddress on the RPC side, then sync extends it":
    var f = buildFix("/tmp/nimrod_synctip_6")
    defer:
      f.cs.close()
      removeDir(f.path)
    let g = f.rpc.handleMethod("generatetodescriptor", %*[2, "raw(51)"])
    checkpoint "generatetodescriptor -> " & $g & " tip=" & $f.cs.bestHeight
    check f.cs.bestHeight == 5
    check f.sm.chainTipHeight == 5
    let tip = f.cs.db.getBlock(f.cs.bestBlockHash).get()
    let z = mineBlock(f.cs.bestBlockHash, 6, tip.header.timestamp + 600, 0x06)
    waitFor f.sm.handleHeaders(f.peer, @[z.header])
    check f.sm.processBlock(f.peer, z)
    check f.cs.bestHeight == 6
