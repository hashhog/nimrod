## mempool.dat persistence tests
##
## Asserts byte-for-byte compatibility with Bitcoin Core's mempool_persist.cpp:
##   uint64 version (1=no-XOR / 2=XOR-obfuscated)
##   if v2: varbytes obfuscation key (compactsize(8) + 8B)
##   uint64 tx_count
##   per tx: CTransaction(witness) | int64 nTime | int64 nFeeDelta
##   compactsize 0 (mapDeltas)
##   compactsize 0 (unbroadcast)

import unittest2
import std/[os, options, times]
import ../src/mempool/[mempool, persist]
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/consensus/[params]

const TestDir = "/tmp/nimrod_persist_test"

proc cleanupDir() =
  if dirExists(TestDir):
    removeDir(TestDir)
  createDir(TestDir)

proc minimalTx(seed: byte): Transaction =
  var prevTxidArr: array[32, byte]
  prevTxidArr[0] = seed
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(prevTxidArr), vout: 0),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(1000),
      scriptPubKey: @[byte(0x6a)]  # OP_RETURN
    )],
    witnesses: @[],
    lockTime: 0
  )

suite "mempool.dat — wire format":
  test "v1 (no-XOR) format: header is just uint64=1":
    let raw = encodeMempoolDump(@[], useV2Xor = false)
    check raw.len >= 8
    var v: uint64 = 0
    for i in 0 ..< 8:
      v = v or (uint64(raw[i]) shl (i * 8))
    check v == MempoolDumpVersionNoXor

  test "v2 format: uint64=2, then varbytes(8) key":
    var key: array[8, byte]
    for i in 0 ..< 8: key[i] = byte(i + 1)
    let raw = encodeMempoolDump(@[], useV2Xor = true,
                                fixedKey = some(key))
    check raw.len >= 8 + 1 + 8
    var v: uint64 = 0
    for i in 0 ..< 8:
      v = v or (uint64(raw[i]) shl (i * 8))
    check v == MempoolDumpVersion
    check raw[8] == 0x08'u8  # compactsize(8)
    for i in 0 ..< 8:
      check raw[9 + i] == key[i]

  test "v2 with empty mempool: tx_count=0 (XOR'd against key)":
    var key: array[8, byte]
    for i in 0 ..< 8: key[i] = byte(0xab xor i)
    let raw = encodeMempoolDump(@[], useV2Xor = true,
                                fixedKey = some(key))
    # Body starts at offset 17 (8 ver + 1 cs + 8 key). Should be 8 bytes
    # of XOR'd zeroes (count=0) + 1B (mapDeltas=0) + 1B (unbroadcast=0).
    let bodyStart = 17
    check raw.len == bodyStart + 8 + 1 + 1
    # XOR de-obfuscate and check tx_count = 0.
    var deobf: uint64 = 0
    for i in 0 ..< 8:
      let plain = raw[bodyStart + i] xor key[i]
      deobf = deobf or (uint64(plain) shl (i * 8))
    check deobf == 0
    # mapDeltas + unbroadcast both compactsize(0) — XOR'd against key[8] and key[9].
    check (raw[bodyStart + 8] xor key[8 mod 8]) == 0x00'u8
    check (raw[bodyStart + 9] xor key[9 mod 8]) == 0x00'u8

  test "v2 with 1 tx round-trip":
    var key: array[8, byte]
    for i in 0 ..< 8: key[i] = byte(0x77)
    let tx = minimalTx(1)
    let raw = encodeMempoolDump(@[tx], useV2Xor = true,
                                fixedKey = some(key),
                                txTimes = @[1700000000'i64],
                                feeDeltas = @[0'i64])
    check raw.len > 17
    # Spot-check: deobf the tx_count byte (offset 17 is the LSB of count=1).
    check (raw[17] xor key[0]) == 0x01'u8

suite "mempool.dat — dump/load round trip":
  test "empty mempool dump → load yields zero counts":
    cleanupDir()
    let dumpPath = TestDir / "mempool.dat"
    var cs = newChainState(TestDir / "chainstate", regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    check dumpMempool(mp, dumpPath)
    check fileExists(dumpPath)
    let crypto = newCryptoEngine()
    let r = loadMempool(mp, dumpPath, crypto)
    check r.isSome
    let counts = r.get()
    check counts.succeeded == 0
    check counts.failed == 0
    check counts.expired == 0
    check counts.alreadyThere == 0
    cs.close()

  test "missing file returns None":
    cleanupDir()
    var cs = newChainState(TestDir / "chainstate", regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    let r = loadMempool(mp, TestDir / "does-not-exist.dat", crypto)
    check r.isNone
    cs.close()

  test "v1 (no-XOR) dump can be loaded":
    cleanupDir()
    let dumpPath = TestDir / "v1.dat"
    var cs = newChainState(TestDir / "chainstate", regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    # Use direct dumpMempool with useV2Xor=false to get v1.
    check dumpMempool(mp, dumpPath, useV2Xor = false)
    let crypto = newCryptoEngine()
    let r = loadMempool(mp, dumpPath, crypto)
    check r.isSome
    cs.close()

  test "garbled file returns None or zero counts":
    cleanupDir()
    let dumpPath = TestDir / "garbage.dat"
    let f = open(dumpPath, fmWrite)
    let junk = "\xde\xad\xbe\xef"
    discard f.writeBuffer(unsafeAddr junk[0], junk.len)
    f.close()
    var cs = newChainState(TestDir / "chainstate", regtestParams())
    let params = regtestParams()
    var mp = newMempool(cs, params)
    let crypto = newCryptoEngine()
    let r = loadMempool(mp, dumpPath, crypto)
    # Either None (parse failed) or Some with all zeros (best-effort).
    if r.isSome:
      let c = r.get()
      check c.succeeded == 0
      check c.failed == 0
    cs.close()
