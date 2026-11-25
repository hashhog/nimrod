## preciousblock must not overwrite the active chain's height slot
## (2026-11-24 Neon audit of nimrod, finding 20).
##
## Core's PreciousBlock (validation.cpp, v31.1) only changes the block's
## nSequenceId and then runs ActivateBestChain; the active chain (and so
## getblockhash) is changed only by connecting blocks. nimrod's preciousBlock
## stored the block with putBlockIndex, which also writes the height -> hash
## slot, so after `preciousblock <side block>` getblockhash(h) named the side
## block while the tip stayed on the main chain, and every later reader of
## that slot (getMtpForHeight, checkBip30, the assumevalid gate) saw a block
## that is not on the active chain. This file pins the invariant that holds in
## Core whatever preciousblock decides: getblockhash(tip height) is the tip,
## and a slot below the tip names the tip's ancestor.

import unittest2
import std/[os, json]
import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
from ../src/network/sync import validateHeaderPoW

const EASY_BITS = 0x207fffff'u32
const BASE_TIME = 1_700_000_000'u32
const COIN = 100_000_000'i64

proc hashOf(b: Block): BlockHash = BlockHash(doubleSha256(serialize(b.header)))

proc hexOf(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  for x in b:
    result.add(hx[(x shr 4) and 0xf]); result.add(hx[x and 0xf])

proc displayHex(h: BlockHash): string =
  let a = array[32, byte](h)
  var r: array[32, byte]
  for i in 0 ..< 32: r[i] = a[31 - i]
  hexOf(r)

proc mkBlock(prev: BlockHash, height: int32, tag: byte,
             value: int64 = 50 * COIN): Block =
  let cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: encodeBip34Height(height) & @[byte(0x02), 0xF7, tag],
      sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(value), scriptPubKey: @[byte(0x51)])],
    witnesses: @[], lockTime: 0)
  var hdr = BlockHeader(version: 0x20000000'i32, prevBlock: prev,
                        merkleRoot: merkleRoot(@[array[32, byte](cb.txid())]),
                        timestamp: BASE_TIME + uint32(height),
                        bits: EASY_BITS, nonce: 0)
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1
  Block(header: hdr, txs: @[cb])

type Node = object
  path: string
  params: ConsensusParams
  cs: ChainState
  rpc: RpcServer

proc attach(n: var Node) =
  n.rpc = newRpcServer(port = 18443'u16, chainState = n.cs,
                       mempool = newMempool(n.cs, n.params),
                       peerManager = nil, feeEstimator = newFeeEstimator(),
                       params = n.params)

proc openNode(name: string): Node =
  result.path = getTempDir() / ("nimrod_neon_precious_" & name)
  removeDir(result.path)
  result.params = regtestParams()
  result.cs = newChainState(result.path, result.params)
  doAssert result.cs.connectBlock(buildGenesisBlock(result.params), 0'i32).isOk
  result.attach()

proc shut(n: var Node) =
  n.cs.close()
  removeDir(n.path)

proc submit(n: Node, b: Block): JsonNode =
  n.rpc.handleMethod("submitblock", %*[hexOf(serialize(b))])

proc mainChain(n: Node, upTo: int32, tagBase: byte): seq[Block] =
  var prev = n.params.genesisBlockHash
  for h in 1'i32 .. upTo:
    let b = mkBlock(prev, h, tagBase + byte(h))
    doAssert n.submit(b).kind == JNull, "main block " & $h & " not connected"
    result.add(b)
    prev = hashOf(b)


proc hashAt(n: Node, h: int): string =
  n.rpc.handleMethod("getblockhash", %*[h]).getStr()

proc best(n: Node): string =
  n.rpc.handleMethod("getbestblockhash", %*[]).getStr()

suite "N20 preciousblock keeps the height index on the active chain":
  test "N20a: after preciousblock on an equal-work side tip, getblockhash(tip) is the tip":
    var n = openNode("tip")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)        # B5 on A4: equal work
    discard n.submit(side)
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(side))])
    let tipH = n.rpc.handleMethod("getblockcount", %*[]).getInt()
    check n.hashAt(tipH) == n.best()

  test "N20b: once the main chain grows past it, the slot names the tip's ancestor":
    var n = openNode("grow")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)
    discard n.submit(side)
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(side))])
    let a6 = mkBlock(hashOf(m[4]), 6, 0x16)
    check n.submit(a6).kind == JNull
    check n.best() == displayHex(hashOf(a6))
    check n.hashAt(5) == displayHex(hashOf(m[4]))   # Core: A5, the parent of A6

  test "N20c: control: without preciousblock the slot is the main block":
    var n = openNode("control")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)
    discard n.submit(side)
    check n.hashAt(5) == displayHex(hashOf(m[4]))
    check n.best() == displayHex(hashOf(m[4]))

suite "N20 preciousblock decides an equal-work tie and nothing else":
  ## Core PreciousBlock sets the block's nSequenceId below every other
  ## candidate's and then runs ActivateBestChain (validation.cpp, v31.1), so
  ## an equal-work precious block becomes the tip, a less-work one does not,
  ## and more work still wins afterwards (Core test/functional/
  ## rpc_preciousblock.py). After each step getblockhash(h) is the active
  ## chain at every height, including the height the side block shares.

  test "N20d: an equal-work precious side block becomes the tip":
    var n = openNode("tie")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)        # B5 on A4: equal work
    discard n.submit(side)
    check n.best() == displayHex(hashOf(m[4]))       # first received keeps it
    check n.rpc.handleMethod("preciousblock",
                             %*[displayHex(hashOf(side))]).kind == JNull
    check n.best() == displayHex(hashOf(side))
    check n.rpc.handleMethod("getblockcount", %*[]).getInt() == 5
    check n.hashAt(5) == displayHex(hashOf(side))
    for h in 1 .. 4:
      check n.hashAt(h) == displayHex(hashOf(m[h - 1]))

  test "N20e: preciousblock back on the first tip moves the chain back":
    var n = openNode("back")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)
    discard n.submit(side)
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(side))])
    check n.best() == displayHex(hashOf(side))
    # A later call gets a lower id than the earlier one (Core's reverse
    # counter), so it wins the same tie the other way.
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(m[4]))])
    check n.best() == displayHex(hashOf(m[4]))
    check n.hashAt(5) == displayHex(hashOf(m[4]))
    check n.hashAt(4) == displayHex(hashOf(m[3]))

  test "N20f: a precious block with less work than the tip does not become the tip":
    var n = openNode("less")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let b4 = mkBlock(hashOf(m[2]), 4, 0x77)          # B4 on A3: one block short
    discard n.submit(b4)
    check n.rpc.handleMethod("preciousblock",
                             %*[displayHex(hashOf(b4))]).kind == JNull
    check n.best() == displayHex(hashOf(m[4]))
    check n.rpc.handleMethod("getblockcount", %*[]).getInt() == 5
    check n.hashAt(4) == displayHex(hashOf(m[3]))    # the height B4 shares
    check n.hashAt(5) == displayHex(hashOf(m[4]))

  test "N20g: after a precious tip, a block with more work still becomes the tip":
    var n = openNode("more")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let side = mkBlock(hashOf(m[3]), 5, 0x77)
    discard n.submit(side)
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(side))])
    check n.best() == displayHex(hashOf(side))
    let a6 = mkBlock(hashOf(m[4]), 6, 0x16)          # A6 on A5: more work
    check n.submit(a6).kind == JNull
    check n.best() == displayHex(hashOf(a6))
    check n.rpc.handleMethod("getblockcount", %*[]).getInt() == 6
    check n.hashAt(6) == displayHex(hashOf(a6))
    check n.hashAt(5) == displayHex(hashOf(m[4]))    # the height B5 shares
    for h in 1 .. 4:
      check n.hashAt(h) == displayHex(hashOf(m[h - 1]))

  test "N20h: an equal-work precious block that fails to connect does not become the tip":
    ## The safety side of N20d: preciousblock only reorders candidates, it
    ## does not skip validation. B5 pays its coinbase one satoshi too much,
    ## which only ConnectBlock checks (Core: bad-cb-amount), so it is stored
    ## as an equal-work side block. preciousblock runs ActivateBestChain, the
    ## connect fails, B5 is marked invalid and the tip stays on A5.
    var n = openNode("badcb")
    defer: n.shut()
    let m = n.mainChain(5, 0x10)
    let bad = mkBlock(hashOf(m[3]), 5, 0x77, 50 * COIN + 1)
    discard n.submit(bad)
    proc tipStatus(n: Node, h: string): string =
      for t in n.rpc.handleMethod("getchaintips", %*[]):
        if t["hash"].getStr() == h:
          return t["status"].getStr()
    # Stored and never tried: the connect below is what rejects it.
    check n.tipStatus(displayHex(hashOf(bad))) == "valid-headers"
    discard n.rpc.handleMethod("preciousblock", %*[displayHex(hashOf(bad))])
    check n.best() == displayHex(hashOf(m[4]))
    check n.hashAt(5) == displayHex(hashOf(m[4]))
    check n.tipStatus(displayHex(hashOf(bad))) == "invalid"
