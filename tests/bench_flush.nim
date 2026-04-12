## Benchmark: IBD flush interval performance comparison
## Measures blk/s with different disk flush intervals

import std/[os, options, monotimes, times, strutils]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const BenchDbPath = "/tmp/nimrod_flush_bench"
const BlockCount = 10000'i32

proc cleanupDb() =
  if dirExists(BenchDbPath):
    removeDir(BenchDbPath)

proc makeTestTransaction(value: int64): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(0x01), 0x01],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(value),
      scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  let coinbase = makeTestTransaction(5000000000)
  var txHashes: seq[array[32, byte]]
  txHashes.add(array[32, byte](coinbase.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: @[coinbase]
  )

proc getBlockHash(blk: Block): BlockHash =
  BlockHash(doubleSha256(serialize(blk.header)))

proc runBench(flushInterval: int): float =
  cleanupDb()
  var cs = newChainState(BenchDbPath, regtestParams())
  cs.ibdDiskFlushInterval = flushInterval

  let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
  discard cs.connectBlock(genesis, 0)
  cs.startIBD()

  let startTime = getMonoTime()
  var prevHash = getBlockHash(genesis)
  for h in 1'i32 .. BlockCount:
    let blk = makeSimpleBlock(prevHash, h)
    let res = cs.connectBlockIBD(blk, h)
    if not res.isOk:
      echo "FAILED at height ", h, ": ", res.error
      break
    prevHash = getBlockHash(blk)

  let elapsed = (getMonoTime() - startTime).inMilliseconds.float / 1000.0
  let blkPerSec = BlockCount.float / elapsed

  cs.stopIBD()
  cs.db.db.closeUnsafe()
  cleanupDb()

  echo "flush_interval=", flushInterval, "  blocks=", BlockCount,
       "  elapsed=", elapsed.formatFloat(ffDecimal, 2), "s",
       "  blk/s=", blkPerSec.formatFloat(ffDecimal, 1)

  blkPerSec

when isMainModule:
  echo "=== IBD Flush Interval Benchmark ==="
  echo "Processing ", BlockCount, " regtest blocks (coinbase-only)"
  echo ""

  # Benchmark with per-batch flush (interval=1 effectively = every 2000 blocks via batch interval)
  let rate1 = runBench(1)  # flush to disk after every batch write (every 2000 blocks)
  let rate2000 = runBench(2000)  # flush to disk every 2000 blocks
  let rate5000 = runBench(5000)  # flush to disk every 5000 blocks

  echo ""
  echo "Summary:"
  echo "  interval=1     (per-batch):  ", rate1.formatFloat(ffDecimal, 1), " blk/s"
  echo "  interval=2000  (default):    ", rate2000.formatFloat(ffDecimal, 1), " blk/s"
  echo "  interval=5000:               ", rate5000.formatFloat(ffDecimal, 1), " blk/s"
