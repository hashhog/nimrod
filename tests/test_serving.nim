## Tests for nimrod's P2P serving paths (mkGetHeaders / mkGetBlocks /
## mkGetData / mkGetAddr response shape).
##
## We test the algorithmic core of the serving handlers without bringing
## up a full NodeState (which requires RocksDB + sockets). The real
## handler in `nimrod.nim` delegates to:
##   - HeaderChain.getHeight / getHashByHeight / getHeaderByHeight   (sync.nim)
##   - mempool.get                                                    (mempool.nim)
##   - chainState.db.getBlock                                         (chainstate.nim)
##   - PeerManager.handleAddrInternal                                 (peermanager.nim)
##
## These tests exercise:
##   1. newNotFound serializer round-trip (the only constructor we added).
##   2. Locator-fork search semantics on HeaderChain (mirrors the
##      `findLocatorFork` proc in nimrod.nim — the locator is descending,
##      we return the highest known hash).
##   3. Header walk-forward loop (mirrors the body of mkGetHeaders /
##      mkGetBlocks; uses HeaderChain helpers).

import std/[options, tables, strutils]
import unittest2

import ../src/network/messages
import ../src/network/sync
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

proc makeHeader(prev: BlockHash, ts: uint32, nonce: uint32): BlockHeader =
  BlockHeader(
    version: 1,
    prevBlock: prev,
    merkleRoot: default(array[32, byte]),
    timestamp: ts,
    bits: 0x1d00ffff'u32,
    nonce: nonce
  )

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc buildLinearChain(n: int): tuple[chain: HeaderChain, hashes: seq[BlockHash]] =
  ## Build a synthetic linear header chain of `n` blocks starting at a
  ## genesis-like header. Each header points at its predecessor's real
  ## double-SHA256 hash so the byHash table is populated correctly.
  var prev: BlockHash = BlockHash(default(array[32, byte]))
  let genesis = makeHeader(prev, 1231006505'u32, 0)
  let genesisHash = hashOf(genesis)
  var hc = initHeaderChain(genesis, genesisHash)
  var hashes = @[genesisHash]
  for i in 1 ..< n:
    let h = makeHeader(hashes[i-1], 1231006505'u32 + uint32(i), uint32(i))
    let hh = hashOf(h)
    hc.headers.add(h)
    hc.hashes.add(hh)
    hc.byHash[hh] = i
    hc.tip = hh
    hc.tipHeight = int32(i)
    hashes.add(hh)
  result = (hc, hashes)

# --- 1. newNotFound serializer ------------------------------------------------

suite "newNotFound constructor":
  test "newNotFound round-trip":
    var h1: array[32, byte]
    var h2: array[32, byte]
    for i in 0 ..< 32:
      h1[i] = byte(i)
      h2[i] = byte(31 - i)
    let items = @[
      InvVector(invType: invWitnessTx, hash: h1),
      InvVector(invType: invWitnessBlock, hash: h2)
    ]
    let msg = newNotFound(items)
    check msg.kind == mkNotFound
    check msg.notFound.len == 2
    let payload = serializePayload(msg)
    let decoded = deserializePayload("notfound", payload)
    check decoded.kind == mkNotFound
    check decoded.notFound.len == 2
    check decoded.notFound[0].invType == invWitnessTx
    check decoded.notFound[0].hash == h1
    check decoded.notFound[1].invType == invWitnessBlock
    check decoded.notFound[1].hash == h2

  test "newNotFound empty list":
    let msg = newNotFound(@[])
    check msg.kind == mkNotFound
    check msg.notFound.len == 0
    let payload = serializePayload(msg)
    # Empty list = 1 byte CompactSize(0)
    check payload.len == 1
    let decoded = deserializePayload("notfound", payload)
    check decoded.kind == mkNotFound
    check decoded.notFound.len == 0

# --- 2. Locator-fork search semantics ----------------------------------------
#
# Mirrors `findLocatorFork` (nimrod.nim) — the locator is descending by
# height, so the FIRST entry we find in our chain wins. This emulates
# Bitcoin Core's Chainstate::FindForkInGlobalIndex.

proc findForkOnHeaderChain(hc: HeaderChain,
                          locator: seq[array[32, byte]]): int32 =
  for h in locator:
    let bh = BlockHash(h)
    let hOpt = hc.getHeight(bh)
    if hOpt.isSome:
      let canon = hc.getHashByHeight(hOpt.get())
      if canon.isSome and canon.get() == bh:
        return hOpt.get()
  return 0

suite "locator fork search":
  test "returns matching height when locator entry is on chain":
    let (hc, hashes) = buildLinearChain(20)
    # locator = [h19, h17, h13, ..., genesis] descending
    let locator = @[
      array[32, byte](hashes[19]),
      array[32, byte](hashes[17]),
      array[32, byte](hashes[13])
    ]
    check findForkOnHeaderChain(hc, locator) == 19

  test "returns first-known height when newest entries are unknown":
    let (hc, hashes) = buildLinearChain(20)
    # First entry is bogus; second is on-chain at height 15.
    var bogus: array[32, byte]
    for i in 0 ..< 32:
      bogus[i] = 0xAB
    let locator = @[
      bogus,
      array[32, byte](hashes[15]),
      array[32, byte](hashes[10])
    ]
    check findForkOnHeaderChain(hc, locator) == 15

  test "returns 0 (genesis) when no locator entry is known":
    let (hc, _) = buildLinearChain(20)
    var bogus1, bogus2: array[32, byte]
    for i in 0 ..< 32:
      bogus1[i] = 0xAA
      bogus2[i] = 0xBB
    let locator = @[bogus1, bogus2]
    check findForkOnHeaderChain(hc, locator) == 0

# --- 3. Header walk-forward loop --------------------------------------------
#
# Mirrors the loop body in mkGetHeaders / mkGetBlocks — walk forward from
# `startHeight`, take up to `limit` headers, optionally stopping at hashStop.

proc walkHeaders(hc: HeaderChain, startHeight: int32,
                 stopHash: array[32, byte], limit: int): seq[BlockHeader] =
  let zero = array[32, byte](default(array[32, byte]))
  let stopIsNull = stopHash == zero
  var height = startHeight
  while result.len < limit:
    let hdrOpt = hc.getHeaderByHeight(height)
    if hdrOpt.isNone:
      break
    result.add(hdrOpt.get())
    let hashOpt = hc.getHashByHeight(height)
    if not stopIsNull and hashOpt.isSome and
       array[32, byte](hashOpt.get()) == stopHash:
      break
    height.inc

suite "header walk-forward":
  test "returns up to `limit` headers":
    let (hc, _) = buildLinearChain(20)
    var zero: array[32, byte]
    let hdrs = walkHeaders(hc, 5, zero, 2000)
    # We have 20 blocks (0..19). Starting at 5 we should see 15 headers.
    check hdrs.len == 15
    check hdrs[0].timestamp == 1231006505'u32 + 5

  test "respects the `limit` cap":
    let (hc, _) = buildLinearChain(20)
    var zero: array[32, byte]
    let hdrs = walkHeaders(hc, 0, zero, 5)
    check hdrs.len == 5

  test "stops at hashStop":
    let (hc, hashes) = buildLinearChain(20)
    let stop = array[32, byte](hashes[10])
    var stopArr: array[32, byte]
    for i in 0 ..< 32:
      stopArr[i] = stop[i]
    let hdrs = walkHeaders(hc, 0, stopArr, 2000)
    # Stops *after* including the stop block (matches the dispatcher's
    # post-add break, which mirrors Bitcoin Core's `--nLimit <= 0 ||
    # GetBlockHash() == hashStop` ordering).
    check hdrs.len == 11

  test "starting past tip returns empty":
    let (hc, _) = buildLinearChain(20)
    var zero: array[32, byte]
    let hdrs = walkHeaders(hc, 50, zero, 2000)
    check hdrs.len == 0

# --- 4. inv build for getblocks -------------------------------------------

suite "getblocks inv build":
  test "builds witness-block inv vectors up to limit":
    let (hc, hashes) = buildLinearChain(20)
    var invItems: seq[InvVector]
    let limit = 500
    var height = 1'i32  # locator matched genesis
    while invItems.len < limit and height < hc.tipHeight + 1:
      let hOpt = hc.getHashByHeight(height)
      if hOpt.isNone: break
      invItems.add(InvVector(invType: invBlock,
                             hash: array[32, byte](hOpt.get())))
      height.inc
    check invItems.len == 19
    check invItems[0].invType == invBlock
    check invItems[0].hash == array[32, byte](hashes[1])
    check invItems[18].hash == array[32, byte](hashes[19])

# --- 5. Constants ---------------------------------------------------------

suite "serving constants":
  test "MaxHeadersPerMsg matches BIP":
    check MaxHeadersPerMsg == 2000
  test "MaxGetBlocksInvCount matches Bitcoin Core":
    check MaxGetBlocksInvCount == 500
  test "MaxLocatorSz matches BIP-0152":
    check MaxLocatorSz == 101
  test "MaxGetAddrCount matches Bitcoin Core cap":
    check MaxGetAddrCount == 1000
