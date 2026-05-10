## W73 BIP-125 RBF comprehensive gate tests
## Tests all 7 implemented gates against Bitcoin Core policy/rbf.cpp semantics

import unittest2
import std/[os, options, tables, times, sets, strutils]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/types
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_rbf_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeOutpoint(b: byte): OutPoint =
  var txid: array[32, byte]
  txid[0] = b
  OutPoint(txid: TxId(txid), vout: 0)

proc makeTxid(b: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  TxId(arr)

proc makeTxidN(b: byte, n: byte): TxId =
  var arr: array[32, byte]
  arr[0] = b
  arr[1] = n
  TxId(arr)

# ============================================================================
# Gate 1: signalsOptInRBF — nSequence <= 0xfffffffd (unsigned)
# Reference: Bitcoin Core src/util/rbf.cpp SignalsOptInRBF()
# ============================================================================

suite "BIP-125 Gate 1 — signalsOptInRBF (nSequence threshold)":
  test "nSequence 0x00000000 signals opt-in":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0x00000000'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "nSequence 0xfffffffd signals opt-in (MAX_BIP125_RBF_SEQUENCE boundary)":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "nSequence 0xfffffffe does NOT signal opt-in (SEQUENCE_FINAL-1)":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xfffffffe'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "nSequence 0xffffffff (SEQUENCE_FINAL) does NOT signal opt-in":
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "one signaling input among several non-signaling is sufficient":
    let tx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xffffffff'u32),
        TxIn(prevOut: makeOutpoint(0x02), scriptSig: @[], sequence: 0xfffffffd'u32),
        TxIn(prevOut: makeOutpoint(0x03), scriptSig: @[], sequence: 0xffffffff'u32),
      ],
      outputs: @[], witnesses: @[], lockTime: 0)
    check signalsOptInRBF(tx)

  test "all inputs non-signaling — no opt-in":
    let tx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: makeOutpoint(0x01), scriptSig: @[], sequence: 0xffffffff'u32),
        TxIn(prevOut: makeOutpoint(0x02), scriptSig: @[], sequence: 0xfffffffe'u32),
      ],
      outputs: @[], witnesses: @[], lockTime: 0)
    check not signalsOptInRBF(tx)

  test "MAX_BIP125_RBF_SEQUENCE constant is 0xfffffffd":
    check MaxBip125RbfSequence == 0xfffffffd'u32

# ============================================================================
# Gate 2: Ancestor inheritance via isRbfOptIn
# Reference: Bitcoin Core src/policy/rbf.cpp IsRBFOptIn()
# ============================================================================

suite "BIP-125 Gate 2 — ancestor inheritance (isRbfOptIn)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "tx itself signals: isRbfOptIn returns true":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check mp.isRbfOptIn(tx)
    cs.close()

  test "tx does not signal but mempool parent does: isRbfOptIn returns true":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())

    # Parent in mempool signals RBF
    let parentTxid = makeTxid(0x10)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(5000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)

    # Child does NOT signal but spends from signaling parent
    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)

    check mp.isRbfOptIn(childTx)
    cs.close()

  test "neither tx nor ancestor signals: isRbfOptIn returns false":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())

    let parentTxid = makeTxid(0x10)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(5000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)

    let childTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)

    check not mp.isRbfOptIn(childTx)
    cs.close()

  test "fullRbf=true: non-signaling tx is still opt-in":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    check mp.isRbfOptIn(tx)
    cs.close()

# ============================================================================
# Gate 3: MAX_REPLACEMENT_CANDIDATES = 100 (Rule #5)
# Reference: Bitcoin Core src/policy/rbf.h MAX_REPLACEMENT_CANDIDATES
# ============================================================================

suite "BIP-125 Gate 3 — Rule #5 MAX_REPLACEMENT_CANDIDATES":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "MaxReplacementCandidates constant is 100":
    check MaxReplacementCandidates == 100

  test "exactly 100 evictions: accepted":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let parentOutpoint = makeOutpoint(0xAA)
    let parentTxid = makeTxid(0x01)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[parentOutpoint] = parentTxid

    # Add 99 children (total evictions = 1 parent + 99 children = 100 = limit)
    for i in 1 .. 99:
      let childTxid = makeTxidN(byte(i + 1), 0x00)
      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0), scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(10),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(110), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)

    let conflicts = toHashSet([parentTxid])
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let result = mp.checkRbfRules(newTx, Satoshi(50000), 200, conflicts)
    check result.isOk  # 100 evictions is at the limit, not over

    cs.close()

  test "101 evictions: rejected":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let parentOutpoint = makeOutpoint(0xAA)
    let parentTxid = makeTxid(0x01)
    let parentTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(10000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(
      tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[parentOutpoint] = parentTxid

    # Add 100 children (total = 101, exceeds limit)
    for i in 1 .. 100:
      let childTxid = makeTxidN(byte(i + 1), 0x00)
      let childTx = Transaction(
        version: 1,
        inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0), scriptSig: @[], sequence: 0)],
        outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])],
        witnesses: @[], lockTime: 0)
      mp.entries[childTxid] = MempoolEntry(
        tx: childTx, txid: childTxid, fee: Satoshi(10),
        weight: 400, feeRate: 1.0, timeAdded: getTime(),
        height: 100, ancestorFee: Satoshi(110), ancestorWeight: 800,
        ancestorCount: 2, ancestorSize: 200)

    let conflicts = toHashSet([parentTxid])
    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: parentOutpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(50000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let result = mp.checkRbfRules(newTx, Satoshi(50000), 200, conflicts)
    check not result.isOk
    check result.error.find("too many potential replacements") >= 0

    cs.close()

# ============================================================================
# Gate 4 / Rule #2: HasNoNewUnconfirmed — replacement must not spend
# outputs from transactions it is evicting.
# Reference: Bitcoin Core src/policy/rbf.cpp EntriesAndTxidsDisjoint()
# ============================================================================

suite "BIP-125 Gate 4 — Rule #2 HasNoNewUnconfirmed":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "replacement spending output of conflicting tx: rejected":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    # Replacement also spends an output FROM the conflict (index 0)
    let newTx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32),
        TxIn(prevOut: OutPoint(txid: conflictTxid, vout: 0), scriptSig: @[], sequence: 0xfffffffd'u32)
      ],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let result = mp.checkRbfRules(newTx, Satoshi(2000), 150, conflicts)
    check not result.isOk
    check result.error.find("spends output from conflicting") >= 0

    cs.close()

  test "replacement spending unrelated confirmed inputs: accepted (fee permitting)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(100), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    # Replacement spends the same outpoint plus an unrelated confirmed input
    let newTx = Transaction(
      version: 1,
      inputs: @[
        TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32),
        TxIn(prevOut: makeOutpoint(0xBB), scriptSig: @[], sequence: 0xfffffffd'u32)
      ],
      outputs: @[TxOut(value: Satoshi(1800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let result = mp.checkRbfRules(newTx, Satoshi(2000), 200, conflicts)
    check result.isOk

    cs.close()

# ============================================================================
# Gate 5: EntriesAndTxidsDisjoint — already folded into Rule #2 above
# ============================================================================

# ============================================================================
# Gate 6: Rule #3 PaysForRBF — replacement_fees >= original_fees
# Core uses < (not <=): equal fees PASS Rule #3.
# Reference: Bitcoin Core src/policy/rbf.cpp PaysForRBF() line 109
# ============================================================================

suite "BIP-125 Gate 6 — Rule #3 PaysForRBF (fee >= original)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "equal fees pass Rule #3 (>= not >)":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    # Fee exactly equal to original: Rule #3 passes (>= is ok), Rule #4 fails (addl fee = 0)
    let conflicts = toHashSet([conflictTxid])
    let result = mp.checkRbfRules(newTx, Satoshi(1000), 100, conflicts)
    # Rule #3 passes (fees equal), Rule #4 should reject (0 < 100 sat required additional)
    check not result.isOk
    check result.error.find("not enough additional fees") >= 0  # Rule #4 fires, not Rule #3

    cs.close()

  test "lower fees fail Rule #3":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(800), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)

    let conflicts = toHashSet([conflictTxid])
    let result = mp.checkRbfRules(newTx, Satoshi(500), 100, conflicts)
    check not result.isOk
    check result.error.find("less fees than conflicting") >= 0

    cs.close()

# ============================================================================
# Gate 7: Rule #4 PaysForRBF — additional_fees >= relay_fee * replacement_vsize
# Reference: Bitcoin Core src/policy/rbf.cpp PaysForRBF() line 118
# ============================================================================

suite "BIP-125 Gate 7 — Rule #4 PaysForRBF (additional fee covers bandwidth)":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "additional fee below required: rejected":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: Transaction(version: 1, inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
                      outputs: @[], witnesses: @[], lockTime: 0),
      txid: conflictTxid, fee: Satoshi(1000), weight: 400, feeRate: 10.0,
      timeAdded: getTime(), height: 100, ancestorFee: Satoshi(1000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    # new fee = 1001 (> 1000), additional = 1, required = 1.0 * 100 = 100 → fail
    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let result = mp.checkRbfRules(newTx, Satoshi(1001), 100, toHashSet([conflictTxid]))
    check not result.isOk
    check result.error.find("not enough additional fees") >= 0

    cs.close()

  test "additional fee exactly meets required: accepted":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: Transaction(version: 1, inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
                      outputs: @[], witnesses: @[], lockTime: 0),
      txid: conflictTxid, fee: Satoshi(1000), weight: 400, feeRate: 10.0,
      timeAdded: getTime(), height: 100, ancestorFee: Satoshi(1000),
      ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    # new fee = 1100, additional = 100, required = 1.0 * 100 = 100 → pass
    let newTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let result = mp.checkRbfRules(newTx, Satoshi(1100), 100, toHashSet([conflictTxid]))
    check result.isOk

    cs.close()

# ============================================================================
# Gate 1 enforced via checkRbfRules: non-signaling in standard mode rejected
# ============================================================================

suite "BIP-125 Gate 1 via checkRbfRules — non-signaling conflict rejected in standard mode":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "non-signaling conflict (standard mode) fails Gate 1":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    # conflict uses SEQUENCE_FINAL — does NOT signal RBF
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let result = mp.checkRbfRules(newTx, Satoshi(5000), 200, toHashSet([conflictTxid]))
    check not result.isOk
    check result.error.find("does not signal RBF opt-in") >= 0

    cs.close()

  test "signaling conflict (standard mode) passes Gate 1":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let result = mp.checkRbfRules(newTx, Satoshi(5000), 200, toHashSet([conflictTxid]))
    check result.isOk

    cs.close()

  test "fullRbf=true: non-signaling conflict passes Gate 1":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)

    let outpoint = makeOutpoint(0xAA)
    let conflictTxid = makeTxid(0x01)
    let conflictTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[TxOut(value: Satoshi(900), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[conflictTxid] = MempoolEntry(
      tx: conflictTx, txid: conflictTxid, fee: Satoshi(1000),
      weight: 400, feeRate: 10.0, timeAdded: getTime(),
      height: 100, ancestorFee: Satoshi(1000), ancestorWeight: 400,
      ancestorCount: 1, ancestorSize: 100)
    mp.spentBy[outpoint] = conflictTxid

    let newTx = Transaction(
      version: 1,
      inputs: @[TxIn(prevOut: outpoint, scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    let result = mp.checkRbfRules(newTx, Satoshi(5000), 200, toHashSet([conflictTxid]))
    check result.isOk

    cs.close()

# ============================================================================
# isBip125Replaceable — proper signaling check (not just mempool presence)
# ============================================================================

suite "isBip125Replaceable — Gate 1+2 signaling check":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "signaling tx is replaceable":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    let txid = makeTxid(0x01)
    let tx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    check mp.isBip125Replaceable(txid)
    cs.close()

  test "non-signaling tx (standard mode) is NOT replaceable":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)
    let txid = makeTxid(0x01)
    let tx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    check not mp.isBip125Replaceable(txid)
    cs.close()

  test "non-signaling tx inherits replaceability from signaling ancestor":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = false)

    # Parent signals RBF
    let parentTxid = makeTxid(0x10)
    let parentTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(5000), scriptPubKey: @[])],
      witnesses: @[], lockTime: 0)
    mp.entries[parentTxid] = MempoolEntry(tx: parentTx, txid: parentTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)

    # Child does NOT signal
    let childTxid = makeTxid(0x20)
    let childTx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: OutPoint(txid: parentTxid, vout: 0), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[childTxid] = MempoolEntry(tx: childTx, txid: childTxid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(200), ancestorWeight: 800, ancestorCount: 2, ancestorSize: 200)

    # Child inherits replaceability from parent
    check mp.isBip125Replaceable(childTxid)
    cs.close()

  test "non-existent txid is not replaceable":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams())
    check not mp.isBip125Replaceable(makeTxid(0xFF))
    cs.close()

  test "fullRbf=true: non-signaling tx IS replaceable":
    var cs = newChainState(TestDbPath, regtestParams())
    var mp = newMempool(cs, regtestParams(), fullRbf = true)
    let txid = makeTxid(0x01)
    let tx = Transaction(version: 1,
      inputs: @[TxIn(prevOut: makeOutpoint(0xAA), scriptSig: @[], sequence: 0xffffffff'u32)],
      outputs: @[], witnesses: @[], lockTime: 0)
    mp.entries[txid] = MempoolEntry(tx: tx, txid: txid, fee: Satoshi(100),
      weight: 400, feeRate: 1.0, timeAdded: getTime(), height: 100,
      ancestorFee: Satoshi(100), ancestorWeight: 400, ancestorCount: 1, ancestorSize: 100)
    check mp.isBip125Replaceable(txid)
    cs.close()
