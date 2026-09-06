## FIX-80 — getblockheader nTx fallback chain.
##
## The daily mainnet consensus-diff (consensus-diff-20260516T070038Z.md)
## flagged nimrod's getblockheader returning `nTx=0` for block 900000
## while Bitcoin Core returns 1562. This is cosmetic (consensus is
## correct — nimrod is at tip with matching block hash) but nTx is a
## documented response field that downstream RPC consumers depend on.
##
## Root cause: blocks indexed before W57 (which introduced
## `BlockIndex.nTx`) carry `nTx=0` in their serialized form. Three
## fallbacks existed:
##   1. `idx.nTx`                              — W57+ data
##   2. `blockFileManager.getBlockIndex().nTx` — flatfile index
##   3. `chainState.db.getBlock`               — RocksDB cfBlocks
##
## But mainnet block 900000 is not in cfBlocks (RocksDB) for the running
## node — block data lives in `blk*.dat` flat files. Fallback (3)
## returned `none(Block)` and the response stayed at 0.
##
## FIX-80 adds a 4th fallback: `blockFileManager.loadBlock(hash)`, which
## reads the block out of `blk*.dat` regardless of cfBlocks population.
##
## Reference: bitcoin-core/src/rpc/blockchain.cpp blockheaderToJSON,
##   `result.pushKV("nTx", (uint64_t)blockindex->nTx)` — Core always
##   reads from the in-memory CBlockIndex, which is populated alongside
##   block storage. nimrod's equivalent must traverse every available
##   block-source so legacy data does not present as nTx=0.

import unittest2
import std/[os, strutils, options, json]
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/storage/[db, chainstate, blockstore]
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/crypto/hashing

const ServerPath = "src/rpc/server.nim"
const TestDbPath = "/tmp/nimrod_fix80_getblockheader_ntx"
const TestBlocksDir = "/tmp/nimrod_fix80_blocks"

proc cleanupTest() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)
  if dirExists(TestBlocksDir):
    removeDir(TestBlocksDir)

proc reverseHex(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc toHexLower(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc makeBlockWithNTxs(prevHash: BlockHash, height: int32, nTxs: int): Block =
  ## Build a block with `nTxs` simple transactions. Used to validate the
  ## fallback chain produces the actual transaction count, not 0.
  var txs: seq[Transaction]
  for i in 0 ..< nTxs:
    var marker: array[32, byte]
    marker[0] = byte(height and 0xff)
    marker[1] = byte((height shr 8) and 0xff)
    marker[2] = byte(i and 0xff)
    marker[3] = byte((i shr 8) and 0xff)
    txs.add(Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(marker), vout: uint32(i)),
        scriptSig: @[byte(0x51)],
        sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
      witnesses: @[],
      lockTime: 0))

  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x1d00ffff'u32,
      nonce: uint32(height)),
    txs: txs)

# ---------------------------------------------------------------------------
# Source-level guard: the 4-tier fallback exists in handleGetBlockHeader.
# This is a regression test against future drive-by simplifications that
# might collapse the fallback chain back to a single read.
# ---------------------------------------------------------------------------
suite "FIX-80 getblockheader nTx fallback chain":

  test "server.nim contains the 4-tier nTx fallback":
    let path = if fileExists(ServerPath): ServerPath
               else: "../" & ServerPath
    check fileExists(path)
    let src = readFile(path)

    # The handler must start from the persisted BlockIndex.nTx.
    check "var nTx = int(idx.nTx)" in src

    # Fallback 2: flatfile BlockIndexEntry (blockFileManager.getBlockIndex).
    check "blockFileManager.getBlockIndex(blockHash)" in src

    # Fallback 3: full block from RocksDB cfBlocks (chainState.db.getBlock).
    check "rpc.chainState.db.getBlock(blockHash)" in src

    # Fallback 4 (FIX-80): flatfile loadBlock — only path that survives
    # pre-W57 indexing AND non-cfBlocks storage on the running mainnet
    # node where block 900000 is in blk*.dat but not RocksDB cfBlocks.
    check "rpc.blockFileManager.loadBlock(blockHash)" in src

    # The response field is named "nTx" (matches Core's blockheaderToJSON).
    check "response[\"nTx\"]" in src

  test "fallback chain is wired in correct order (idx → bfm.idx → cfBlocks → bfm.loadBlock)":
    let path = if fileExists(ServerPath): ServerPath
               else: "../" & ServerPath
    let src = readFile(path)

    let posInitial   = src.find("var nTx = int(idx.nTx)")
    let posBfmIdx    = src.find("blockFileManager.getBlockIndex(blockHash)")
    let posCfBlocks  = src.find("rpc.chainState.db.getBlock(blockHash)")
    let posLoadBlock = src.find("rpc.blockFileManager.loadBlock(blockHash)")

    check posInitial   >= 0
    check posBfmIdx    >= 0
    check posCfBlocks  >= 0
    check posLoadBlock >= 0

    # Each subsequent fallback must appear strictly after the previous one
    # in source order — preserves the "try cheapest first, fall through to
    # the most expensive read last" property of the chain.
    check posInitial   < posBfmIdx
    check posBfmIdx    < posCfBlocks
    check posCfBlocks  < posLoadBlock

  test "loadBlock fallback is gated on blockFileManager != nil":
    ## Regression guard: blockFileManager is Optional (only wired when
    ## startNode mounts the flatfile storage). A nil-deref here would
    ## crash every getblockheader call on a server without flatfile
    ## storage (currently only the in-process test rigs).
    let path = if fileExists(ServerPath): ServerPath
               else: "../" & ServerPath
    let src = readFile(path)

    let posLoadBlock = src.find("rpc.blockFileManager.loadBlock(blockHash)")
    check posLoadBlock >= 0

    # The "if nTx == 0 and rpc.blockFileManager != nil" guard must
    # appear within a few hundred chars before the loadBlock call.
    let windowStart = max(0, posLoadBlock - 600)
    let prefix = src[windowStart ..< posLoadBlock]
    check "blockFileManager != nil" in prefix

# ---------------------------------------------------------------------------
# Behavioral end-to-end: BlockIndex.nTx=0 (legacy) + block on disk in
# flatfile → getblockheader returns the real tx count from fallback #4.
# ---------------------------------------------------------------------------
suite "FIX-80 getblockheader nTx fallback - behavioral":

  test "legacy BlockIndex (nTx=0) with flatfile block: getblockheader recovers nTx":
    ## Simulate the production scenario: an old block whose BlockIndex
    ## entry was written before W57 (nTx=0 in the serialized record) but
    ## the block's serialized bytes are in `blk*.dat`. Prior to FIX-80,
    ## getblockheader would report nTx=0 (the mainnet 900000 bug). With
    ## FIX-80's 4th fallback, it must return the real tx count.
    cleanupTest()
    defer: cleanupTest()

    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()

    let bfm = newBlockFileManager(TestBlocksDir, params, cs.db.db)

    # Build a block with 7 txs.
    let prevHash = BlockHash(default(array[32, byte]))
    let blk = makeBlockWithNTxs(prevHash, 1'i32, 7)
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    # Persist the block to the flatfile blk*.dat (this is the source that
    # fallback #4 reads from).
    let storePos = bfm.storeBlock(blk, 1'i32)
    check storePos.isSome

    # Write a *legacy* BlockIndex entry with nTx=0 — this mimics the
    # mainnet pre-W57 data shape.
    var legacyIdx = BlockIndex(
      hash: blockHash,
      height: 1'i32,
      status: bsValidated,
      prevHash: prevHash,
      header: blk.header,
      totalWork: default(array[32, byte]),
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0,
      nTx: 0'i32)  # <-- the bug: legacy entry has nTx=0
    cs.db.putBlockIndex(legacyIdx)
    cs.db.updateBestBlock(blockHash, 1'i32)
    cs.bestBlockHash = blockHash
    cs.bestHeight = 1'i32

    # Also wipe the per-BlockFileManager index to nTx=0 to be thorough:
    # we want to assert fallback #4 (loadBlock) is the only path that
    # recovers the count. The blockFileManager's getBlockIndex already
    # has nTx from storeBlock — but the legacy BlockFileManager's data
    # may also be unreliable (pre-W57). Force fallback to loadBlock by
    # overwriting the BFM index entry with nTx=0.
    var bfmEntry = bfm.getBlockIndex(blockHash).get()
    bfmEntry.nTx = 0'u32
    bfm.putBlockIndex(blockHash, bfmEntry)

    # Build the RPC server and wire the BFM.
    var mp = newMempool(cs, params, fullRbf = false)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params)
    rpc.blockFileManager = bfm

    # Probe getblockheader. The block hash must be expressed in display
    # (big-endian) form per Bitcoin Core convention; nimrod's
    # parseBlockHash reverses it before lookup.
    let displayHash = reverseHex(toHexLower(array[32, byte](blockHash)))
    let resp = rpc.handleMethod("getblockheader",
                                %*[displayHash, true])

    # The nTx field must be 7, not 0. This is what FIX-80's 4th
    # fallback delivers — without it, the test reports 0 and the
    # mainnet consensus-diff stays red.
    check resp.hasKey("nTx")
    check resp["nTx"].getInt() == 7

  test "post-W57 BlockIndex (nTx populated): getblockheader uses BlockIndex directly":
    ## Confirm the happy path is unchanged. When the BlockIndex carries a
    ## valid nTx, none of the fallbacks fire and the value is returned
    ## verbatim. Guards against fallback paths overwriting good data.
    cleanupTest()
    defer: cleanupTest()

    let params = regtestParams()
    var cs = newChainState(TestDbPath, params)
    defer: cs.close()

    let prevHash = BlockHash(default(array[32, byte]))
    let blk = makeBlockWithNTxs(prevHash, 1'i32, 3)
    let headerBytes = serialize(blk.header)
    let blockHash = BlockHash(doubleSha256(headerBytes))

    # Write a BlockIndex with nTx already populated (W57+ shape).
    var idx = BlockIndex(
      hash: blockHash,
      height: 1'i32,
      status: bsValidated,
      prevHash: prevHash,
      header: blk.header,
      totalWork: default(array[32, byte]),
      undoPos: FlatFilePos(fileNum: -1, pos: -1),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0,
      nTx: 3'i32)
    cs.db.putBlockIndex(idx)
    cs.db.updateBestBlock(blockHash, 1'i32)
    cs.bestBlockHash = blockHash
    cs.bestHeight = 1'i32

    # No BFM, no cfBlocks data — only the BlockIndex entry. The handler
    # must read nTx from idx and return it.
    var mp = newMempool(cs, params, fullRbf = false)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params)

    let displayHash = reverseHex(toHexLower(array[32, byte](blockHash)))
    let resp = rpc.handleMethod("getblockheader",
                                %*[displayHash, true])

    check resp.hasKey("nTx")
    check resp["nTx"].getInt() == 3
