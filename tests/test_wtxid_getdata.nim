## BIP-339 wtxid tx-relay: request + serve in the correct id namespace.
##
## Bug (found via `tools/regtest-harness.sh --tx-relay`): nimrod accepted
## `invWtx` (MSG_WTX) tx announcements but then requested EVERY tx with a
## `getdata` of type `invWitnessTx` (MSG_WITNESS_TX, a TXID request) carrying
## the WTXID as the hash.  For a segwit tx (txid != wtxid) the serving peer
## looked the wtxid up as a txid, missed, and replied `notfound` — so nimrod
## never ingested wtxid-announced txs (Ingested=NO in the harness).
##
## Fix, mirroring Core net_processing GetRequestsToSend
## (`gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | fetch_flags)`):
##   - REQUEST: echo the announcement's namespace — invWtx → MSG_WTX(invWtx);
##     invTx / invWitnessTx → MSG_WITNESS_TX(invWitnessTx).
##   - SERVE: a getdata(MSG_WTX) resolves the tx by WTXID (mempool.byWtxid).
##
## These tests exercise the two pure decision points the dispatcher delegates
## to (nimrod.nim's mkInv / mkGetData handlers need a full NodeState + sockets
## and are not unit-testable directly):
##   1. `getdataTypeForAnnouncement` — the request-type echo.
##   2. mempool `getByWtxid` / `containsWtxid` — the serve-by-wtxid resolution.

import unittest2
import std/[os, options, tables, times]
import ../src/network/messages
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_wtxid_getdata_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

# ---------------------------------------------------------------------------
# 1. Request-side: getdata type echoes the announcement namespace.
# ---------------------------------------------------------------------------

suite "BIP-339 request: getdata type echoes announcement":
  test "invWtx announcement -> request MSG_WTX (invWtx), NOT invWitnessTx":
    check getdataTypeForAnnouncement(invWtx) == invWtx

  test "invTx announcement -> request MSG_WITNESS_TX (invWitnessTx)":
    check getdataTypeForAnnouncement(invTx) == invWitnessTx

  test "invWitnessTx announcement -> request MSG_WITNESS_TX (invWitnessTx)":
    check getdataTypeForAnnouncement(invWitnessTx) == invWitnessTx

  test "an invWtx inv for an unknown tx yields a getdata of type invWtx":
    # Replicates the mkInv request path for a single unknown wtxid-relay
    # announcement: the emitted getdata carries the wtxid under invWtx.
    var wtxid: array[32, byte]
    for i in 0 ..< 32: wtxid[i] = byte(i)
    let ann = InvVector(invType: invWtx, hash: wtxid)
    let req = InvVector(invType: getdataTypeForAnnouncement(ann.invType),
                        hash: ann.hash)
    check req.invType == invWtx        # regression guard: NOT invWitnessTx
    check req.hash == wtxid
    # And it survives a wire round-trip as MSG_WTX (value 5).
    var w = BinaryWriter()
    w.writeInvVector(req)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readInvVector()
    check decoded.invType == invWtx
    check decoded.hash == wtxid

# ---------------------------------------------------------------------------
# 2. Serve-side: getdata(MSG_WTX) resolves the tx by WTXID.
# ---------------------------------------------------------------------------

proc makeTx(marker: byte): Transaction =
  ## Minimal distinct transaction (real txid derives from its bytes).
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
      scriptSig: @[marker],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[byte(0x51)])],
    witnesses: @[],
    lockTime: 0
  )

suite "BIP-339 serve: getdata(MSG_WTX) resolves by wtxid":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "getByWtxid resolves a segwit-style entry (txid != wtxid)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), minFeeRate = 0.0)

    let tx = makeTx(0xAB)
    let txid = tx.txid()
    # Force a distinct wtxid to model a segwit tx where txid != wtxid.
    var wbytes: array[32, byte]
    for i in 0 ..< 32: wbytes[i] = byte(0xF0 xor i)
    let wtxid = TxId(wbytes)
    check wtxid != txid

    let entry = MempoolEntry(
      tx: tx, txid: txid, wtxid: wtxid,
      fee: Satoshi(1000), weight: 400, feeRate: 10.0,
      timeAdded: getTime(), height: 101,
      ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100
    )
    mp.entries[txid] = entry
    mp.byWtxid[wtxid] = txid

    # Serve path: getdata(MSG_WTX) must resolve by wtxid and return the tx.
    check mp.containsWtxid(wtxid)
    let served = mp.getByWtxid(wtxid)
    check served.isSome
    check served.get().txid == txid

    # Looking the WTXID up as a TXID (the old buggy serve path) misses —
    # this is exactly why the peer replied notfound before the fix.
    check not mp.contains(wtxid)
    # And the wtxid is NOT in the txid namespace.
    check not mp.containsWtxid(txid)
    check mp.getByWtxid(txid).isNone

    cs.close()

  test "getByWtxid on an empty mempool returns none":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), minFeeRate = 0.0)
    var wbytes: array[32, byte]
    wbytes[0] = 0x11
    check not mp.containsWtxid(TxId(wbytes))
    check mp.getByWtxid(TxId(wbytes)).isNone
    cs.close()
