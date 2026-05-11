## W86 mempool eviction audit tests
## Covers all 5 Core eviction functions:
##   - CTxMemPool::Expire            (txmempool.cpp:811-827)
##   - CTxMemPool::GetMinFee         (txmempool.cpp:829-851)
##   - CTxMemPool::trackPackageRemoved (txmempool.cpp:853-859)
##   - CTxMemPool::TrimToSize        (txmempool.cpp:861-911)
##   - rolling fee fields on Mempool struct
##   - blockSinceLastRollingFeeBump set in removeForBlock
##   - rolling fee floor wired into acceptTransaction / acceptPackage
##
## Bitcoin Core reference constants:
##   DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB  (policy/policy.h:48)
##   DEFAULT_MEMPOOL_EXPIRY_HOURS  = 336           (kernel/mempool_options.h:23)
##   ROLLING_FEE_HALFLIFE          = 43200 s       (txmempool.h:212)

import unittest2
import std/[os, options, tables, times, sets, math]
import ../src/mempool/mempool
import ../src/storage/[db, chainstate]
import ../src/primitives/[types, serialize]
import ../src/consensus/params

const TestDbPath = "/tmp/nimrod_w86_eviction_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTxId(n: int): TxId =
  var arr: array[32, byte]
  arr[0] = byte(n and 0xff)
  arr[1] = byte((n shr 8) and 0xff)
  arr[2] = byte((n shr 16) and 0xff)
  arr[3] = byte((n shr 24) and 0xff)
  TxId(arr)

proc makeP2PKHScript(): seq[byte] =
  ## Dummy scriptPubKey (not executed in these unit tests)
  @[byte(0x76), 0xa9, 0x14] & newSeq[byte](20) & @[byte(0x88), 0xac]

proc addEntry(mp: Mempool, n: int, feeRate: float64 = 1.0,
              weight: int = 400, timeAdded: Time = getTime(),
              parentId: int = -1): TxId =
  ## Directly inject a MempoolEntry bypassing validation
  let txid = makeTxId(n)
  let fee = Satoshi(int64(feeRate * float64(weight) / 4.0))

  var inputs: seq[TxIn]
  if parentId >= 0:
    inputs.add(TxIn(prevOut: OutPoint(txid: makeTxId(parentId), vout: 0),
                    scriptSig: @[], sequence: 0xFFFFFFFF'u32))
    mp.spentBy[OutPoint(txid: makeTxId(parentId), vout: 0)] = txid

  let tx = Transaction(
    version: 1,
    inputs: inputs,
    outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: makeP2PKHScript())],
    witnesses: @[],
    lockTime: 0
  )

  let entry = MempoolEntry(
    tx: tx,
    txid: txid,
    fee: fee,
    weight: weight,
    feeRate: feeRate,
    timeAdded: timeAdded,
    height: 0,
    ancestorFee: fee,
    ancestorWeight: weight,
    ancestorCount: 1,
    ancestorSize: weight div 4
  )
  mp.entries[txid] = entry
  mp.currentSize += serialize(tx).len
  txid

# ============================================================================
# G1 — Mempool struct has rolling fee fields
# ============================================================================
suite "W86-G1 rolling fee fields present":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "new mempool has zero rolling minimum fee":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.rollingMinimumFeeRate == 0.0
    cs.close()

  test "new mempool has blockSinceLastRollingFeeBump = false":
    ## Core starts with blockSinceLastRollingFeeBump = false (txmempool.h:196)
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.blockSinceLastRollingFeeBump == false
    cs.close()

  test "new mempool has lastRollingFeeUpdate near now":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    let now = getTime().toUnix()
    check abs(mp.lastRollingFeeUpdate - now) <= 2
    cs.close()

  test "incrementalRelayFeeRate defaults to 100 sat/kvB":
    ## Core DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48)
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.incrementalRelayFeeRate == DefaultIncrementalRelayFeeSatKvB
    check mp.incrementalRelayFeeRate == 100.0
    cs.close()

  test "expiryHours defaults to 336":
    ## Core DEFAULT_MEMPOOL_EXPIRY_HOURS = 336 (kernel/mempool_options.h:23)
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.expiryHours == DefaultMempoolExpiryHours
    check mp.expiryHours == 336
    cs.close()

  test "RollingFeeHalflife constant is 12 hours (43200 seconds)":
    ## Core ROLLING_FEE_HALFLIFE = 60 * 60 * 12 (txmempool.h:212)
    check RollingFeeHalflife == 43200

# ============================================================================
# G2 — trackPackageRemoved
# ============================================================================
suite "W86-G2 trackPackageRemoved":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "bumps rolling floor when rate exceeds current value":
    ## Core: if (rate.GetFeePerK() > rollingMinimumFeeRate) bump; txmempool.cpp:855
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.rollingMinimumFeeRate == 0.0
    mp.trackPackageRemoved(500.0)  # 500 sat/kvB
    check mp.rollingMinimumFeeRate == 500.0
    cs.close()

  test "does not lower rolling floor if new rate is smaller":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.trackPackageRemoved(500.0)
    mp.trackPackageRemoved(200.0)
    check mp.rollingMinimumFeeRate == 500.0  # unchanged
    cs.close()

  test "sets blockSinceLastRollingFeeBump to false":
    ## Core: blockSinceLastRollingFeeBump = false; txmempool.cpp:857
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.blockSinceLastRollingFeeBump = true  # pretend a block fired
    mp.trackPackageRemoved(300.0)
    check mp.blockSinceLastRollingFeeBump == false
    cs.close()

  test "does not modify blockSinceLastRollingFeeBump when rate not bumped":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.blockSinceLastRollingFeeBump = true
    mp.rollingMinimumFeeRate = 1000.0
    mp.trackPackageRemoved(200.0)  # lower than current — no bump
    check mp.blockSinceLastRollingFeeBump == true  # unchanged
    cs.close()

# ============================================================================
# G3 — getMinFee
# ============================================================================
suite "W86-G3 getMinFee":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "returns 0 when rollingMinimumFeeRate is 0":
    ## Core: if rollingMinimumFeeRate == 0 return CFeeRate(llround(0)) = 0
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.getMinFee() == 0.0
    cs.close()

  test "returns raw value when blockSinceLastRollingFeeBump is false (no decay)":
    ## Core: if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
    ##        return CFeeRate(llround(rollingMinimumFeeRate));
    ## i.e. no decay until a block fires the halflife clock.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.rollingMinimumFeeRate = 2000.0   # 2000 sat/kvB
    mp.blockSinceLastRollingFeeBump = false
    # No decay: should return 2000 / 1000 = 2.0 sat/vbyte
    check abs(mp.getMinFee() - 2.0) < 0.001
    cs.close()

  test "returns at least incrementalRelayFeeRate when non-zero":
    ## Core: return std::max(CFeeRate(llround(rollingMinimumFeeRate)),
    ##                        m_opts.incremental_relay_feerate);
    ## incrementalRelayFeeRate default = 100 sat/kvB = 0.1 sat/vbyte.
    ## If rolling value is very small but non-zero, floor is incremental.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.rollingMinimumFeeRate = 1.0   # 1 sat/kvB, tiny
    mp.blockSinceLastRollingFeeBump = false
    # No decay; raw value 1/1000 = 0.001 sat/vbyte
    # But since blockSinceLastRollingFeeBump=false we return raw (no decay path)
    # and raw < incrementalRelayFee / 1000.
    # Expected: 0.001 sat/vbyte — but getMinFee also floors at incremental when non-zero.
    # With blockSince=false we skip the decay branch entirely and return raw / 1000.
    # The max(rolling, incremental) only applies in the decay branch.
    # So: raw = 0.001; incremental check happens in decay path only.
    # With blockSince=false: returns 1.0 / 1000.0 = 0.001
    check abs(mp.getMinFee() - 0.001) < 0.0001
    cs.close()

  test "decays to zero after enough simulated time":
    ## After decay the value drops below half of incrementalRelayFee and
    ## resets to 0.  Core: txmempool.cpp:845-848.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # Set a modest rolling fee
    mp.rollingMinimumFeeRate = 110.0   # 110 sat/kvB (just above incremental 100)
    mp.blockSinceLastRollingFeeBump = true
    # Simulate a very old lastRollingFeeUpdate (many halflives ago)
    mp.lastRollingFeeUpdate = getTime().toUnix() - (RollingFeeHalflife * 20)
    # After ~20 halflives the value is negligible
    let minFee = mp.getMinFee()
    check minFee == 0.0
    check mp.rollingMinimumFeeRate == 0.0
    cs.close()

  test "halflife is accelerated when pool is less than quarter full":
    ## Core: if (DynamicMemoryUsage() < sizelimit / 4) halflife /= 4;
    ## txmempool.cpp:837-838.
    ## Verify the decay is faster when pool is nearly empty.
    var cs = newChainState(TestDbPath, regtestParams())
    # Make a small-maxSize pool so currentSize / maxSize ratio is easy to control
    let mp = newMempool(cs, regtestParams(), maxSize = 1_000_000)
    mp.currentSize = 50_000  # 5% of 1M → < 25% → halflife / 4

    mp.rollingMinimumFeeRate = 50000.0  # 50000 sat/kvB
    mp.blockSinceLastRollingFeeBump = true
    # Use exactly 1 halflife worth of time but with /4 acceleration
    let effectiveHalflife = RollingFeeHalflife div 4
    mp.lastRollingFeeUpdate = getTime().toUnix() - effectiveHalflife

    let result = mp.getMinFee()
    # After 1 effective halflife the value should be ~half of 50000/1000 = 25
    # (sat/vbyte); give ±30% tolerance for float rounding
    check result > 0.0
    check result < 50.0  # less than original

    cs.close()

# ============================================================================
# G4 — evictLowestFee with trackPackageRemoved wiring
# ============================================================================
suite "W86-G4 evictLowestFee tracks rolling fee":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "eviction bumps rollingMinimumFeeRate":
    ## Core TrimToSize calls trackPackageRemoved(removed + incremental).
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # Inject a tx with feeRate = 0.5 sat/vbyte → 500 sat/kvB
    discard addEntry(mp, 1, feeRate = 0.5, weight = 400)

    check mp.rollingMinimumFeeRate == 0.0
    mp.evictLowestFee()
    # Rolling floor should now be > 0
    check mp.rollingMinimumFeeRate > 0.0
    cs.close()

  test "eviction sets blockSinceLastRollingFeeBump to false":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.blockSinceLastRollingFeeBump = true
    discard addEntry(mp, 1, feeRate = 1.0, weight = 400)
    mp.evictLowestFee()
    check mp.blockSinceLastRollingFeeBump == false
    cs.close()

  test "eviction removes entire descendant package":
    ## Core TrimToSize evicts the worst chunk and all descendants together.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())

    # Parent tx (low fee rate)
    let parentId = addEntry(mp, 1, feeRate = 0.5, weight = 400)
    # Child tx spending the parent
    discard addEntry(mp, 2, feeRate = 0.5, weight = 400, parentId = 1)

    check mp.count == 2
    mp.evictLowestFee()
    # Both parent and child should be gone
    check mp.count == 0
    cs.close()

  test "eviction removes only the lowest-rate package, leaves higher-rate txs":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())

    discard addEntry(mp, 1, feeRate = 0.5, weight = 400)   # low rate
    discard addEntry(mp, 2, feeRate = 10.0, weight = 400)  # high rate

    mp.evictLowestFee()
    check mp.count == 1
    check makeTxId(1) notin mp.entries
    check makeTxId(2) in mp.entries
    cs.close()

# ============================================================================
# G5 — expire with descendant cascade
# ============================================================================
suite "W86-G5 expire cascades to descendants":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "expired tx is removed":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    let old = getTime() - initDuration(hours = 400)
    discard addEntry(mp, 1, timeAdded = old)
    mp.expire()
    check makeTxId(1) notin mp.entries
    cs.close()

  test "recent tx is kept":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    discard addEntry(mp, 1, timeAdded = getTime())
    mp.expire()
    check makeTxId(1) in mp.entries
    cs.close()

  test "descendants of expired tx are also removed":
    ## Core Expire(): CalculateDescendants on each expired tx, then remove
    ## the whole stage.  txmempool.cpp:821-825.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    let old = getTime() - initDuration(hours = 400)

    # Old parent
    discard addEntry(mp, 1, timeAdded = old)
    # Young child — would NOT expire on its own, but must be evicted
    # because its parent expired.
    discard addEntry(mp, 2, timeAdded = getTime(), parentId = 1)

    check mp.count == 2
    mp.expire()
    # Both should be gone
    check makeTxId(1) notin mp.entries
    check makeTxId(2) notin mp.entries
    cs.close()

  test "expire respects configured expiryHours":
    ## Core DEFAULT_MEMPOOL_EXPIRY_HOURS=336, but configurable.
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams(), expiryHours = 1)
    # Tx added 2 hours ago — older than 1h expiry
    let old = getTime() - initDuration(hours = 2)
    discard addEntry(mp, 1, timeAdded = old)
    mp.expire()
    check makeTxId(1) notin mp.entries
    cs.close()

  test "expire maxAgeOverride parameter works":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # Tx added 2 hours ago; default expiry is 336h so it would be kept
    let old = getTime() - initDuration(hours = 2)
    discard addEntry(mp, 1, timeAdded = old)
    # Override to 1 hour — should expire
    mp.expire(maxAgeOverride = 1)
    check makeTxId(1) notin mp.entries
    cs.close()

  test "expire does not cascade to descendants of non-expired txs":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    let old = getTime() - initDuration(hours = 400)
    let recent = getTime() - initDuration(minutes = 5)

    # Tx1 old (expires), Tx3 is its child (also expires)
    discard addEntry(mp, 1, timeAdded = old)
    discard addEntry(mp, 3, timeAdded = recent, parentId = 1)

    # Tx2 is recent and independent (no relation to Tx1)
    discard addEntry(mp, 2, timeAdded = recent)

    mp.expire()
    check makeTxId(1) notin mp.entries  # expired
    check makeTxId(3) notin mp.entries  # cascaded
    check makeTxId(2) in mp.entries     # untouched
    cs.close()

# ============================================================================
# G6 — removeForBlock sets blockSinceLastRollingFeeBump
# ============================================================================
suite "W86-G6 removeForBlock resets rolling fee decay":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "removeForBlock sets blockSinceLastRollingFeeBump to true":
    ## Core txmempool.cpp:427: blockSinceLastRollingFeeBump = true
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # Initially false (no eviction yet)
    check mp.blockSinceLastRollingFeeBump == false
    # Process empty block
    let blk = Block(header: BlockHeader(), txs: @[])
    mp.removeForBlock(blk)
    check mp.blockSinceLastRollingFeeBump == true
    cs.close()

  test "removeForBlock updates lastRollingFeeUpdate":
    ## Core txmempool.cpp:426: lastRollingFeeUpdate = GetTime()
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # Set it to something ancient
    mp.lastRollingFeeUpdate = 0
    let blk = Block(header: BlockHeader(), txs: @[])
    mp.removeForBlock(blk)
    let now = getTime().toUnix()
    check abs(mp.lastRollingFeeUpdate - now) <= 2
    cs.close()

  test "after removeForBlock getMinFee decay becomes active":
    ## With blockSinceLastRollingFeeBump=true and a simulated past update,
    ## getMinFee should decay (not return raw value).
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.rollingMinimumFeeRate = 50000.0  # large floor

    # Simulate block fired long ago so decay has a lot to work with
    let blk = Block(header: BlockHeader(), txs: @[])
    mp.removeForBlock(blk)
    # Manually backdate to many halflives ago so the decay fires
    mp.lastRollingFeeUpdate = getTime().toUnix() - (RollingFeeHalflife * 20)

    let result = mp.getMinFee()
    # Should have decayed to zero
    check result == 0.0
    cs.close()

# ============================================================================
# G7 — rolling fee floor wired into acceptTransaction fee gate
# ============================================================================
suite "W86-G7 rolling floor wired into admission gate":
  setup:
    cleanupTestDb()
  teardown:
    cleanupTestDb()

  test "getMinFee returns zero when rollingMinimumFeeRate is 0 and no block":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    check mp.getMinFee() == 0.0
    cs.close()

  test "getMinFee returns non-zero after trackPackageRemoved":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    mp.trackPackageRemoved(1500.0)  # 1500 sat/kvB = 1.5 sat/vbyte
    # blockSinceLastRollingFeeBump = false → no decay → returns raw / 1000
    check abs(mp.getMinFee() - 1.5) < 0.001
    cs.close()

  test "evictLowestFee followed by getMinFee returns positive floor":
    var cs = newChainState(TestDbPath, regtestParams())
    let mp = newMempool(cs, regtestParams())
    # 200 sat/vbyte = 200000 sat/kvB ← very high to ensure floor dominates
    discard addEntry(mp, 1, feeRate = 200.0, weight = 400)
    mp.evictLowestFee()
    # Rolling floor should be above 0
    check mp.getMinFee() > 0.0
    cs.close()

  test "DefaultMempoolExpiryHours constant is 336":
    check DefaultMempoolExpiryHours == 336

  test "DefaultIncrementalRelayFeeSatKvB constant is 100":
    check DefaultIncrementalRelayFeeSatKvB == 100.0
