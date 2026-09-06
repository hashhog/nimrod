## getblockfrompeer RPC — behaviour + Core-error-parity + genuine-getdata test.
##
## getblockfrompeer was added to Bitcoin Core in v23 (rpc/blockchain.cpp +
## net_processing.cpp PeerManagerImpl::FetchBlock). It attempts to fetch a
## specific block (whose header is already known) from a specific connected
## peer, and returns an empty object {} on success.
##
## Core contract (the ordered checks this test pins):
##   1. header unknown                  → RPC_MISC_ERROR(-1) "Block header missing"
##      (blockchain.cpp:546-548, LookupBlockIndex == null)
##   2. block body already on disk      → RPC_MISC_ERROR(-1) "Block already downloaded"
##      (blockchain.cpp:556-559, BLOCK_HAVE_DATA)
##   3. peer_id does not resolve        → RPC_MISC_ERROR(-1) "Peer does not exist"
##      (net_processing.cpp:1964-1966, GetPeerRef == null)
##   4. on success: send ONE block getdata (MSG_BLOCK | MSG_WITNESS_FLAG, hash)
##      to that peer and return {}  (net_processing.cpp:1979-1993, FetchBlock)
##
## nimrod substrate:
##   - "header known" == a BlockIndex row exists (chainState.db.getBlockIndex),
##     mirroring Core's non-null LookupBlockIndex; headers-first sync writes the
##     row before the body is downloaded.
##   - "body present" == the full block body exists (chainState.db.getBlock),
##     mirroring Core's BLOCK_HAVE_DATA.
##   - peer_id is the SAME loop-counter index getpeerinfo emits: getpeerinfo
##     numbers peers 0..N-1 over getReadyPeers(); getblockfrompeer resolves
##     peer_id as that same index into the same ordered slice.
##   - the getdata inv type is invWitnessBlock (0x40000002 = MSG_BLOCK |
##     MSG_WITNESS_FLAG), exactly Core's CInv in FetchBlock.
##
## The getdata send itself is captured WITHOUT a socket via the pure decision
## core `resolveGetBlockFromPeer` (the Core-FetchBlock analog), which returns
## the resolved peer + the inventory to send. The end-to-end `{}` return and
## the error parities are exercised through `handleMethod("getblockfrompeer")`.
##
## Reference: bitcoin-core/src/rpc/blockchain.cpp getblockfrompeer
##            bitcoin-core/src/net_processing.cpp PeerManagerImpl::FetchBlock

import unittest2
import std/[os, options, json, tables]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/network/[peer, peermanager, messages]
import ../src/rpc/server
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_getblockfrompeer_test"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc toHexLower(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc reverseHexLocal(hex: string): string =
  ## big-endian display hex <-> internal little-endian byte order
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc displayHash(h: BlockHash): string =
  ## RPC display form (reversed) of a 32-byte hash, matching what
  ## parseBlockHash expects on the way back in.
  reverseHexLocal(toHexLower(array[32, byte](h)))

proc makeHeader(seed: byte): BlockHeader =
  ## Deterministic, self-consistent header.
  BlockHeader(
    version: 1'i32,
    prevBlock: BlockHash(default(array[32, byte])),
    merkleRoot: default(array[32, byte]),
    timestamp: uint32(1700000000) + uint32(seed),
    bits: 0x207fffff'u32,
    nonce: uint32(seed))

proc headerHash(hdr: BlockHeader): BlockHash =
  ## The block hash is the double-SHA256 of the serialized header — exactly the
  ## key storeBlock uses, so a body stored under this header is retrievable by
  ## this hash.
  BlockHash(doubleSha256(serialize(hdr)))

proc registerHeaderOnly(cs: ChainState, hdr: BlockHeader, height: int32): BlockHash =
  ## Make the header "known" (BlockIndex row present) WITHOUT a body on disk —
  ## the headers-first-sync state in which getblockfrompeer is meant to act.
  let h = headerHash(hdr)
  let idx = BlockIndex(
    hash: h, height: height, status: bsHeaderOnly,
    prevHash: hdr.prevBlock, header: hdr,
    totalWork: default(array[32, byte]), nTx: 0)
  cs.db.putBlockIndex(idx)
  h

proc buildRpc(): RpcServer =
  ## Minimal regtest RpcServer with a real (empty) PeerManager wired.
  let params = regtestParams()
  let cs = newChainState(TestDbPath, params)
  let mp = newMempool(cs, params, fullRbf = false)
  let fe = newFeeEstimator()
  let pm = newPeerManager(params, 8, 2, 117, "/tmp")
  let rpc = newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = pm,
    feeEstimator = fe,
    params = params)
  rpc

proc addReadyPeer(rpc: RpcServer, addrStr: string, port: uint16): Peer =
  ## Insert a peer in psReady state so it shows up in getReadyPeers() in a
  ## deterministic slot (and therefore in getpeerinfo's id numbering).
  let p = newPeer(addrStr, port, rpc.peerManager.params, pdOutbound)
  p.state = psReady
  rpc.peerManager.peers[addrStr & ":" & $port] = p
  p

# ---------------------------------------------------------------------------

suite "getblockfrompeer — Core error parity":

  test "(a) unknown header -> RPC_MISC_ERROR(-1) 'Block header missing'":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    discard rpc.addReadyPeer("10.0.0.1", 18444'u16)

    # A syntactically valid but unknown hash.
    let unknown = displayHash(BlockHash(doubleSha256(@[byte 0xDE, 0xAD])))

    var raised = false
    try:
      discard rpc.handleMethod("getblockfrompeer", %*[unknown, 0])
    except RpcError as e:
      raised = true
      check e.code == -1
      check e.msg == "Block header missing"
    check raised

  test "(b) bad peer_id -> RPC_MISC_ERROR(-1) 'Peer does not exist'":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    # one ready peer => valid ids are {0}; 1, 99, and -1 are out of range.
    discard rpc.addReadyPeer("10.0.0.1", 18444'u16)

    # A KNOWN header (body NOT present) so we get past checks (1) and (2)
    # and actually reach the peer-resolution check.
    let hdr = makeHeader(7)
    let h = registerHeaderOnly(rpc.chainState, hdr, 1)
    let hHex = displayHash(h)

    for badId in [1, 99, -1]:
      var raised = false
      try:
        discard rpc.handleMethod("getblockfrompeer", %*[hHex, badId])
      except RpcError as e:
        raised = true
        check e.code == -1
        check e.msg == "Peer does not exist"
      check raised

  test "no peers at all -> 'Peer does not exist' (id 0 invalid)":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    let hdr = makeHeader(3)
    let h = registerHeaderOnly(rpc.chainState, hdr, 1)

    var raised = false
    try:
      discard rpc.handleMethod("getblockfrompeer", %*[displayHash(h), 0])
    except RpcError as e:
      raised = true
      check e.code == -1
      check e.msg == "Peer does not exist"
    check raised

  test "block already downloaded -> RPC_MISC_ERROR(-1) 'Block already downloaded'":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    discard rpc.addReadyPeer("10.0.0.1", 18444'u16)

    # Header known AND body on disk (Core BLOCK_HAVE_DATA): store both.
    let hdr = makeHeader(9)
    let h = registerHeaderOnly(rpc.chainState, hdr, 1)
    rpc.chainState.db.storeBlock(Block(header: hdr, txs: @[]))
    check rpc.chainState.db.getBlock(h).isSome   # sanity: body present

    var raised = false
    try:
      discard rpc.handleMethod("getblockfrompeer", %*[displayHash(h), 0])
    except RpcError as e:
      raised = true
      check e.code == -1
      check e.msg == "Block already downloaded"
    check raised

suite "getblockfrompeer — success path":

  test "(c) success: resolves the right peer + builds a witness-block getdata for the hash":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    # Three ready peers in deterministic id order 0,1,2.
    discard rpc.addReadyPeer("10.0.0.1", 18444'u16)
    discard rpc.addReadyPeer("10.0.0.2", 18444'u16)
    discard rpc.addReadyPeer("10.0.0.3", 18444'u16)

    # Confirm getpeerinfo numbers them the same way we will address them.
    let infoIds = block:
      var ids: seq[int]
      for entry in rpc.handleMethod("getpeerinfo", %*[]):
        ids.add(entry["id"].getInt())
      ids
    check infoIds == @[0, 1, 2]
    # The id->peer mapping getblockfrompeer must honour == getReadyPeers slice.
    let ready = rpc.peerManager.getReadyPeers()
    check ready.len == 3

    # Header known, body NOT present (the real fetch scenario).
    let hdr = makeHeader(42)
    let h = registerHeaderOnly(rpc.chainState, hdr, 5)

    # Drive the pure decision core for peer id == 1 (the SECOND peer).
    let (peer, invs) = rpc.resolveGetBlockFromPeer(h, 1)

    # The resolved peer is exactly getReadyPeers()[1] (matches getpeerinfo id 1).
    check peer == ready[1]

    # Exactly one inventory item: a witness-flagged block getdata for THIS hash.
    check invs.len == 1
    check invs[0].invType == invWitnessBlock        # 0x40000002 = MSG_BLOCK | MSG_WITNESS_FLAG
    check invs[0].hash == array[32, byte](h)

    # And the full handler returns {} (Core UniValue::VOBJ) for the same call.
    let resp = rpc.handleMethod("getblockfrompeer", %*[displayHash(h), 1])
    check resp.kind == JObject
    check resp.len == 0

  test "each peer id resolves to its own peer (0,1,2 distinct)":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    discard rpc.addReadyPeer("10.0.0.1", 18444'u16)
    discard rpc.addReadyPeer("10.0.0.2", 18444'u16)
    discard rpc.addReadyPeer("10.0.0.3", 18444'u16)
    let ready = rpc.peerManager.getReadyPeers()

    let hdr = makeHeader(100)
    let h = registerHeaderOnly(rpc.chainState, hdr, 1)

    for id in 0 ..< 3:
      let (peer, invs) = rpc.resolveGetBlockFromPeer(h, id)
      check peer == ready[id]
      check invs.len == 1
      check invs[0].invType == invWitnessBlock
      check invs[0].hash == array[32, byte](h)

  test "missing peer_id param -> invalid params (-32602)":
    cleanupTest()
    defer: cleanupTest()
    let rpc = buildRpc()
    defer: rpc.chainState.close()
    let hdr = makeHeader(11)
    let h = registerHeaderOnly(rpc.chainState, hdr, 1)

    var raised = false
    try:
      discard rpc.handleMethod("getblockfrompeer", %*[displayHash(h)])
    except RpcError as e:
      raised = true
      check e.code == -32602
    check raised
