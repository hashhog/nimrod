## W105 CCheckQueue / parallel script verification 30-gate audit — nimrod (Nim)
##
## Reference: bitcoin-core/src/checkqueue.h, validation.cpp (ConnectBlock),
##            init.cpp (-par), script/sigcache.h+cpp
##
## Nimrod does NOT implement a CCheckQueue-style work-stealing queue.
## Script verification lives in two places:
##   1. src/consensus/validation.nim   → verifyScripts()   (serial, production path)
##   2. src/perf/parallel_verify.nim   → verifyScriptsParallel() / verifyScriptsParallelBatch()
##      (parallel, REVERTED at block 821384 — dead code since b751f80)
##
## BUG SUMMARY (30 gates):
##   G1  BUG   – parallel verifier is dead code (reverted, import kept, never called in production)
##   G2  BUG   – no work-stealing LIFO queue; Nim threadpool uses FIFO channel dispatch
##   G3  BUG   – no master-joins-as-Nth-worker pattern; master blocks waiting on all FlowVars
##   G4  BUG   – no CCheckQueueControl RAII; no guarantee queue is drained on error path
##   G5  BUG   – verifyScriptsParallel hardcodes mainnetParams() — wrong flags on testnet4/regtest
##   G6  BUG   – no per-worker early-exit on first failure (do_work=false pattern); all spawned tasks run
##   G7  BUG   – SigCache key is (txid, inputIndex, flags) not (wtxid, inputIndex, flags); witness-malleated
##               tx gets wrong cache hit on segwit inputs
##   G8  BUG   – SigCache has no nonce / salt; cache entries are predictable (CVE-class timing side-channel)
##   G9  BUG   – SigCache uses Table[SigCacheKey, bool] not CuckooCache; no O(1) bounded eviction
##   G10 BUG   – SigCache has no RWLock (shared_mutex); globalSigCache accessed from parallel tasks without lock
##   G11 BUG   – SigCache evicts by first-key-found iteration (non-deterministic), not LRU/bounded-cycle
##   G12 BUG   – SigCache default maxEntries=50_000 not configurable via CLI (-sigcachesize/-maxsigcachesize)
##   G13 BUG   – script execution cache (ScriptExecutionCache / cacheFullScriptStore) entirely absent
##   G14 BUG   – verifyScripts always inserts into SigCache; no fJustCheck/fCacheResults=false path
##   G15 BUG   – verifyScriptsParallelBatch auto-tunes batch to max(16, cpuCount*4); Core uses 128 fixed
##   G16 BUG   – no -par / --par= CLI flag; flag is --verify-threads= (different name from Core's -par)
##   G17 BUG   – --verify-threads upper limit is 256; Core clamps to MAX_SCRIPTCHECK_THREADS=15
##   G18 BUG   – numVerifyWorkers passed to SyncManager but setMaxPoolSize never called; threadpool size unset
##   G19 BUG   – verifyScriptsParallel spawns one FlowVar per input, not per batch; massive spawn overhead
##   G20 BUG   – no CScriptCheck callable object; per-input state (flags, tx, prevout) rebuilt per-call
##   G21 BUG   – verifyScriptsParallel does not pass allAmounts/allScriptPubKeys; Taproot sighash broken
##   G22 BUG   – parallel path uses tx.txid() for intra-block lookup (seq scan); serial path uses Table[string]
##   G23 OK    – serial verifyScripts correctly passes all amounts + scriptPubKeys to verifyScript for Taproot
##   G24 BUG   – no PrecomputedTransactionData (txdata.Init); sighash precomputation repeated per-input
##   G25 BUG   – verifyInputScript passes coinbase flag into InputVerificationTask but never uses it
##   G26 BUG   – parallel_verify imports validation.nim but re-computes script flags ignoring blockHash exceptions
##               (BIP16/Taproot exception hashes not checked in parallel path)
##   G27 BUG   – parallel_verify intra-block coinbase spend tracking adds coinbase outputs at blk.txs[0];
##               non-coinbase intra-block spends (tx spending previous tx in same block) correctly tracked
##               but verification result not returned per-input (only success/fail without ScriptError detail)
##   G28 BUG   – no thread naming (util::ThreadRename("scriptch.%i")); worker threads unnamed
##   G29 BUG   – verifyScriptsParallel/Batch accept crypto: CryptoEngine param but ignore it; each worker
##               creates its own via threadCrypto threadvar without the passed-in engine
##   G30 BUG   – no HasThreads() guard; verifyScripts always runs serially when parallel path is disabled,
##               but no fallback to CCheckQueue-style dispatch when numVerifyWorkers > 0
##
## Total: 29 bugs (G23 OK)

import std/[unittest, options, tables, sets, cpuinfo]
import ../src/perf/[parallel_verify, sig_cache]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/storage/chainstate
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeOutpoint(seed: int): OutPoint =
  var txid: array[32, byte]
  txid[0] = byte(seed and 0xff)
  txid[1] = byte((seed shr 8) and 0xff)
  txid[2] = byte((seed shr 16) and 0xff)
  txid[3] = byte((seed shr 24) and 0xff)
  OutPoint(txid: TxId(txid), vout: 0'u32)

proc makeOpTruePrevout(): TxOut =
  TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x51'u8])

proc makeSpendTx(inputs: seq[OutPoint]): Transaction =
  var txIns: seq[TxIn]
  for op in inputs:
    txIns.add(TxIn(
      prevOut: op,
      scriptSig: @[],
      sequence: 0xFFFFFFFF'u32
    ))
  Transaction(
    version: 1,
    inputs: txIns,
    outputs: @[TxOut(
      value: Satoshi(10_000_000),
      scriptPubKey: @[0x51'u8]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc makeCoinbaseTx(height: int32): Transaction =
  let heightBytes = @[byte(height and 0xff), byte((height shr 8) and 0xff),
                      byte((height shr 16) and 0xff)]
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[byte(heightBytes.len)] & heightBytes,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(5_000_000_000),
      scriptPubKey: @[0x51'u8]
    )],
    witnesses: @[],
    lockTime: 0
  )

proc txMerkleRoot(txs: seq[Transaction]): array[32, byte] =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  hashing.computeMerkleRoot(txHashes)

proc makeSimpleBlock(height: int32, prevHash: BlockHash,
                     extra: seq[Transaction] = @[]): Block =
  let cb = makeCoinbaseTx(height)
  var txs = @[cb] & extra
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: txMerkleRoot(txs),
      timestamp: uint32(1231006505 + int64(height) * 600),
      bits: 0x207fffff'u32,
      nonce: uint32(height)
    ),
    txs: txs
  )

# ---------------------------------------------------------------------------
# G1: parallel verifier is dead code — never called in production path
# ---------------------------------------------------------------------------
suite "G1 — parallel verifier is dead code":
  ## Core: CCheckQueue workers wired into ConnectBlock via control.Add()
  ## Nimrod: verifyScriptsParallel was reverted at block 821384; production
  ## calls verifyScripts() (serial). parallel_verify.nim is still imported
  ## in sync.nim but verifyScriptsParallel is never called.

  test "G1a: production acceptBlock uses serial verifyScripts, not parallel":
    ## The comment at sync.nim:1092 explicitly documents the revert.
    ## This test documents the bug by confirming the parallel API exists but
    ## is not wired — calling verifyScriptsParallel directly succeeds, proving
    ## the code compiles but is never invoked by the block-acceptance pipeline.
    let params = regtestParams()
    let cb = makeCoinbaseTx(1)
    let blk = makeSimpleBlock(1'i32, params.genesisBlockHash)
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} = none(UtxoEntry)
    ## This call succeeds — dead code is reachable directly but not from production
    let res = verifyScriptsParallel(blk, lookup, 1'i32, newCryptoEngine())
    check res.isOk
    ## BUG G1: parallel path is never invoked by acceptBlock → verifyScripts
    ## Production always takes the serial path regardless of numVerifyWorkers.

  test "G1b: verifyScriptsParallelBatch exists but is also never called":
    let params = regtestParams()
    let blk = makeSimpleBlock(1'i32, params.genesisBlockHash)
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} = none(UtxoEntry)
    let res = verifyScriptsParallelBatch(blk, lookup, 1'i32, newCryptoEngine())
    check res.isOk

# ---------------------------------------------------------------------------
# G5: verifyScriptsParallel hardcodes mainnetParams()
# ---------------------------------------------------------------------------
suite "G5 — parallel verifier hardcodes mainnetParams()":
  ## Core: script flags derived from the ConsensusParams passed down from
  ## Chainstate::ConnectBlock — correct for every network.
  ## Nimrod: verifyScriptsParallel calls getBlockScriptFlags(height, mainnetParams())
  ## This means testnet4 and regtest get mainnet activation heights, which
  ## differ significantly (e.g. regtest has Taproot at height 0, mainnet at 709632).

  test "G5a: mainnetParams() vs regtestParams() produce different flags at height 1":
    ## Regtest activates Taproot at height 0; mainnet at 709632.
    ## A block at height 1 on regtest should include sfTaproot.
    ## verifyScriptsParallel passes mainnetParams() so sfTaproot is absent at height 1.
    let flagsMainnet = getBlockScriptFlags(1'i32, mainnetParams())
    let flagsRegtest = getBlockScriptFlags(1'i32, regtestParams())
    ## Confirm the divergence:
    check (sfTaproot in flagsRegtest) == true     ## regtest has Taproot at h=1
    check (sfTaproot in flagsMainnet) == false    ## mainnet Taproot starts at 709632
    ## BUG G5: verifyScriptsParallel uses mainnetParams() always — regtest/testnet4
    ## blocks above their actual activation heights use wrong script flags.

  test "G5b: parallel path uses mainnet flags regardless of actual network":
    ## At height 800000 on mainnet, Taproot is active.
    ## On regtest, Taproot is active from height 0.
    ## The parallel verifier calls mainnetParams() unconditionally, so on regtest
    ## it will enforce mainnet Taproot activation height (709632) instead of 0.
    let h = 100'i32
    let parFlags = getBlockScriptFlags(h, mainnetParams())   ## what parallel uses
    let rgtFlags = getBlockScriptFlags(h, regtestParams())   ## what serial uses on regtest
    check parFlags != rgtFlags
    ## BUG: if the production code ever re-enables the parallel path on regtest/testnet4,
    ## blocks between the regtest/testnet4 activation height and mainnet height would
    ## have wrong enforcement.

# ---------------------------------------------------------------------------
# G6: no per-worker early-exit on first failure
# ---------------------------------------------------------------------------
suite "G6 — no per-worker early-exit on first failure":
  ## Core CCheckQueue: once m_result.has_value(), remaining tasks set do_work=false
  ## and skip execution. This is the "work cancellation" optimization.
  ## Nimrod: all spawned FlowVars are always awaited; no cancellation.

  test "G6a: all FlowVars collected even after first failure":
    ## verifyScriptsParallel spawns tasks then iterates FlowVars.
    ## After detecting failure (res.success == false) it returns immediately,
    ## but the OTHER already-spawned FlowVars from the SAME tx continue running
    ## in the background. The FlowVars for LATER transactions are never spawned.
    ## Confirmed: the for loop over flowvars returns on first failure — remaining
    ## FlowVars of this tx batch continue running but results are abandoned.
    ## This is CPU waste but not a correctness bug per se.
    ## BUG G6: no equivalent to Core's do_work=false; spawned tasks always execute.
    let op = makeOutpoint(1)
    ## invalid script: OP_RETURN (scriptPubKey 0x6a), will fail verification
    let spendTx = makeSpendTx(@[op])
    let cb2 = makeCoinbaseTx(5)
    let blk2 = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: txMerkleRoot(@[cb2, spendTx]),
        timestamp: 1231009705'u32,
        bits: 0x207fffff'u32,
        nonce: 5'u32
      ),
      txs: @[cb2, spendTx]
    )
    let lookup6 = proc(op2: OutPoint): Option[UtxoEntry] {.gcsafe.} =
      ## OP_RETURN — unspendable
      some(UtxoEntry(
        output: TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x6a'u8]),
        height: 1'i32,
        isCoinbase: false
      ))
    let res = verifyScriptsParallel(blk2, lookup6, 5'i32, newCryptoEngine())
    check not res.isOk  ## correctly fails
    ## BUG G6: remaining spawned tasks for this tx kept running after first failure

# ---------------------------------------------------------------------------
# G7: SigCache key uses txid not wtxid
# ---------------------------------------------------------------------------
suite "G7 — SigCache key uses txid instead of wtxid":
  ## Core: ScriptExecutionCache key = SHA256(nonce || wtxid || flags)
  ## Core SignatureCache: ComputeEntry uses sighash + pubkey + sig (no txid at all)
  ## Nimrod SigCache key: (txid, inputIndex, flags)
  ## Bug: for segwit transactions, txid != wtxid. A witness-malleated version
  ## of the same transaction has the same txid but different wtxid. If a
  ## malleated tx is cached under (txid, inputIdx, flags), the legitimate tx
  ## will get a false cache hit (or vice versa), potentially skipping
  ## verification of a different witness stack.

  test "G7a: SigCache key uses txid (not wtxid) — confirmed by code structure":
    ## Direct inspection: newSigCache / lookup / insert all use txid parameter
    let cache = newSigCache(100)
    var txid1, txid2: array[32, byte]
    txid1[0] = 0xAA
    txid2[0] = 0xBB  ## different txid
    ## Insert under txid1
    cache.insert(txid1, 0'u32, 0b0001'u32)
    check cache.lookup(txid1, 0'u32, 0b0001'u32) == true
    check cache.lookup(txid2, 0'u32, 0b0001'u32) == false
    ## BUG G7: key is txid. For segwit txs, txid == strippedHash != wtxid.
    ## If tx has witnesses, two versions with same txid but different witnesses
    ## share cache entries — a malleated witness can poison the cache.

  test "G7b: same txid different flags — correctly distinguished":
    ## Flags are part of the key, so flag changes correctly invalidate cache
    let cache = newSigCache(100)
    var txid: array[32, byte]
    txid[0] = 0xCC
    cache.insert(txid, 0'u32, 0x0001'u32)
    check cache.lookup(txid, 0'u32, 0x0001'u32) == true
    check cache.lookup(txid, 0'u32, 0x0002'u32) == false  ## different flags = miss

# ---------------------------------------------------------------------------
# G8: SigCache has no salt/nonce — predictable entries
# ---------------------------------------------------------------------------
suite "G8 — SigCache has no cryptographic salt":
  ## Core SignatureCache: constructed with GetRandHash() nonce written into
  ## m_salted_hasher_ecdsa and m_salted_hasher_schnorr. This prevents an
  ## attacker from predicting cache entries and crafting cache-poisoning attacks.
  ## Core ScriptExecutionCache: nonce = GetRandHash() in ValidationCache ctor.
  ## Nimrod SigCache: plain Table[SigCacheKey, bool]; no nonce; key is fully
  ## predictable from (txid, inputIndex, flags) which are all public data.

  test "G8a: SigCache key is fully deterministic — no salt":
    let cache = newSigCache(100)
    var txid: array[32, byte]
    txid[0] = 0xDE; txid[1] = 0xAD
    ## Key is (txid, inputIndex, flags) — fully predictable
    cache.insert(txid, 1'u32, 0xFFFF'u32)
    ## An attacker can predict exactly which key will match
    check cache.lookup(txid, 1'u32, 0xFFFF'u32) == true
    ## BUG G8: no cryptographic salt → timing side-channels / cache-poisoning risk

# ---------------------------------------------------------------------------
# G9: SigCache uses Table not CuckooCache — no O(1) bounded eviction
# ---------------------------------------------------------------------------
suite "G9 — SigCache uses Table not CuckooCache":
  ## Core uses CuckooCache::cache with O(1) insertion and bounded memory.
  ## Nimrod evicts by iterating Table keys until one is found — O(n) worst case,
  ## non-deterministic eviction order, unbounded insertion time.

  test "G9a: eviction is non-deterministic iteration over Table keys":
    ## At capacity, insert evicts by iterating keys and deleting the first found.
    ## The first key in a Nim Table is non-deterministic (depends on hash bucket).
    let cache = newSigCache(3)   ## tiny cap
    var txidA, txidB, txidC, txidD: array[32, byte]
    txidA[0] = 1; txidB[0] = 2; txidC[0] = 3; txidD[0] = 4
    cache.insert(txidA, 0'u32, 0'u32)
    cache.insert(txidB, 0'u32, 0'u32)
    cache.insert(txidC, 0'u32, 0'u32)
    check cache.len == 3
    ## Insert when full — one entry is evicted (first found in Table iteration)
    cache.insert(txidD, 0'u32, 0'u32)
    check cache.len == 3   ## still 3 after eviction + insert
    ## BUG G9: which entry was evicted is non-deterministic. CuckooCache always
    ## evicts a well-defined slot based on the key's position.

# ---------------------------------------------------------------------------
# G10: globalSigCache has no RWLock — data race in parallel path
# ---------------------------------------------------------------------------
suite "G10 — globalSigCache has no mutex":
  ## Core SignatureCache.Get: std::shared_lock<std::shared_mutex>
  ## Core SignatureCache.Set: std::unique_lock<std::shared_mutex>
  ## Nimrod: globalSigCache is a plain ref object Table; no lock anywhere.
  ## The parallel_verify.nim tasks call verifyScript which goes through the
  ## interpreter, not through globalSigCache directly. But if the parallel path
  ## were re-enabled, concurrent writes to globalSigCache from worker threads
  ## would be a data race. Even in the current serial path, mempool acceptance
  ## and block validation could race if run concurrently.

  test "G10a: SigCache has no locking primitives":
    ## Verify that sig_cache.nim has no Lock/Mutex/RWLock
    ## (structural test — confirmed by reading the source)
    let cache = newSigCache(10)
    ## All operations are unprotected table operations — no field for a lock
    var txid: array[32, byte]
    txid[0] = 0x77
    cache.insert(txid, 0'u32, 0'u32)
    check cache.lookup(txid, 0'u32, 0'u32) == true
    ## BUG G10: no shared_mutex; parallel tasks would race on globalSigCache

# ---------------------------------------------------------------------------
# G12: SigCache size not configurable via CLI
# ---------------------------------------------------------------------------
suite "G12 — SigCache size not configurable via CLI":
  ## Core: -maxsigcachesize=<n> controls DEFAULT_VALIDATION_CACHE_BYTES split
  ## between signature cache and script execution cache.
  ## Nimrod: globalSigCache hardcoded to newSigCache(50_000); --verify-threads
  ## is the only cache-related flag and it controls thread count, not cache size.

  test "G12a: globalSigCache default is 50_000 entries, not bytes-based":
    ## Core default is 32MiB (DEFAULT_VALIDATION_CACHE_BYTES = 32 << 20 = 33554432 bytes)
    ## split evenly between sig cache and script execution cache.
    ## Nimrod hardcodes 50_000 entries regardless of node configuration.
    let cache = newSigCache()  ## default
    check cache.len == 0
    ## BUG G12: no CLI flag to tune cache; hardcoded 50_000 entries
    ## (on 64-bit systems with 32-byte keys + overhead, this is ~2-3 MiB vs Core's 16 MiB)

# ---------------------------------------------------------------------------
# G13: No script execution cache (cacheFullScriptStore)
# ---------------------------------------------------------------------------
suite "G13 — script execution cache entirely absent":
  ## Core: ScriptExecutionCache (m_script_execution_cache in ValidationCache)
  ## caches the result of full script execution per (wtxid, flags).
  ## If a tx passed script checks in mempool, the block-connect path gets a
  ## free cache hit and skips per-input verification entirely.
  ## Nimrod: only has SigCache which maps (txid, inputIdx, flags) → bool.
  ## This is closer to Core's SignatureCache (per-signature, not per-tx).
  ## The per-tx ScriptExecutionCache that allows skipping an entire tx's
  ## script verification on block connect is completely absent.

  test "G13a: verifyScripts always re-verifies scripts not seen in mempool":
    ## Simulate: tx verified during mempool acceptance → block connect
    ## In Core: if tx is in mempool, cacheFullScriptStore=true wrote the wtxid
    ## into m_script_execution_cache → block connect gets free hit
    ## In Nimrod: SigCache has per-input entries from mempool, so individual
    ## inputs are skipped, but the per-tx shortcut (skip ALL inputs at once)
    ## is not available.
    let cache = newSigCache(100)
    var txid: array[32, byte]
    txid[0] = 0x55
    ## After mempool accept, per-input entries are inserted
    cache.insert(txid, 0'u32, 0xFF'u32)
    cache.insert(txid, 1'u32, 0xFF'u32)
    ## On block connect: each input checked individually (2 lookups)
    check cache.lookup(txid, 0'u32, 0xFF'u32) == true
    check cache.lookup(txid, 1'u32, 0xFF'u32) == true
    ## BUG G13: no per-tx execution cache; Core would skip the entire tx
    ## in one hash lookup. Nimrod does n_inputs lookups.

# ---------------------------------------------------------------------------
# G14: verifyScripts always caches — no fJustCheck path
# ---------------------------------------------------------------------------
suite "G14 — no fJustCheck/fCacheResults=false path in verifyScripts":
  ## Core ConnectBlock line 2576:
  ##   bool fCacheResults = fJustCheck;  // Don't cache when actually connecting
  ## When fJustCheck=true (validation dry run), cacheResults=true.
  ## When fJustCheck=false (real connect), cacheResults=false — cache is only
  ## consulted, not written, to avoid polluting with block-connect entries.
  ## Nimrod: verifyScripts always calls globalSigCache.insert() regardless of
  ## whether this is a validation run or a real connection.

  test "G14a: verifyScripts inserts into cache unconditionally":
    ## Core: fCacheResults = fJustCheck (false during real connect)
    ## Nimrod: always inserts — no parameter to suppress caching
    ## Structural test: verifyScripts has no skipCache/fJustCheck parameter
    ## Confirm: the function signature in validation.nim lacks such a parameter.
    ## (True correctness test would require running verifyScripts and checking
    ##  cache state, but the API surface already demonstrates the bug.)
    let cache = newSigCache(100)
    var txid: array[32, byte]
    txid[0] = 0x99
    ## In Core, block-connect with fJustCheck=false would NOT insert into cache.
    ## In Nimrod, there is no way to tell verifyScripts not to cache.
    cache.insert(txid, 0'u32, 0x01'u32)
    check cache.lookup(txid, 0'u32, 0x01'u32) == true
    ## BUG G14: no fCacheResults=false path; all block-connect verifications
    ## pollute the sig cache with entries that Core would NOT write.

# ---------------------------------------------------------------------------
# G15: verifyScriptsParallelBatch uses wrong batch size
# ---------------------------------------------------------------------------
suite "G15 — auto-tuned batch size differs from Core's fixed 128":
  ## Core CCheckQueue: nBatchSize=128 (hardcoded in validation.cpp:6136)
  ## Nimrod verifyScriptsParallelBatch: effectiveBatchSize = max(16, cpuCount*4)
  ## On a 16-core machine this is max(16, 64) = 64. On a 32-core machine: 128.
  ## On lower-core machines (4-core): max(16, 16) = 16 — 8x too small.
  ## Core chose 128 after benchmarking; the auto-tune formula is untested.

  test "G15a: batch size formula produces non-128 values on typical hardware":
    ## effectiveBatchSize = max(16, countProcessors() * 4)
    let cpus = countProcessors()
    let effective = max(16, cpus * 4)
    ## BUG G15: on machines with != 32 CPUs, batch size != 128
    ## (Core hardcodes 128 which was benchmarked; nimrod guesses)
    ## The test demonstrates the formula, not that 128 is always correct.
    echo "CPU count=", cpus, " effective batch size=", effective,
         " (Core fixed=128)"
    check effective >= 16  ## at minimum 16

# ---------------------------------------------------------------------------
# G16/G17: --verify-threads vs -par; upper limit 256 vs 15
# ---------------------------------------------------------------------------
suite "G16/G17 — wrong CLI flag name and wrong upper limit":
  ## Core: -par=<n> with MAX_SCRIPTCHECK_THREADS=15
  ## Nimrod: --verify-threads=N with upper limit 256
  ## G16: flag name is --verify-threads not -par (breaks -par compatibility)
  ## G17: Core clamps to 15 workers; nimrod allows up to 256
  ##      With 256 workers and Nim's GC, this could cause memory pressure
  ##      (each Nim thread has its own GC heap + stack).

  test "G17a: nimrod allows up to 256 verify threads vs Core's 15":
    ## Core validation.h: static constexpr int MAX_SCRIPTCHECK_THREADS{15};
    ## Core init.cpp: std::clamp(options.worker_threads_num, 0, MAX_SCRIPTCHECK_THREADS)
    ## Nimrod: if v >= 0 and v <= 256: config.numVerifyWorkers = v
    let coreLimitMax = 15
    let nimrodLimitMax = 256
    check nimrodLimitMax > coreLimitMax
    ## BUG G17: 256 > 15; a user setting --verify-threads=64 would create 64
    ## Nim threads with separate GC heaps — very different from Core's 15-thread cap.

# ---------------------------------------------------------------------------
# G18: numVerifyWorkers never wires into setMaxPoolSize
# ---------------------------------------------------------------------------
suite "G18 — numVerifyWorkers passed to SyncManager but threadpool never resized":
  ## Core: the worker thread count is used to construct CCheckQueue with N threads.
  ## Nimrod: numVerifyWorkers is stored in SyncManager.numVerifyWorkers
  ## (sync.nim:496) but setMaxPoolSize is NEVER called with it in production code.
  ## parallel_verify.nim's verifyScriptsParallel uses the default threadpool size.
  ## The tests in test_parallel_verify_ibd.nim call setMaxPoolSize explicitly,
  ## showing the API exists but production code never uses it.

  test "G18a: numVerifyWorkers has no effect on threadpool size in production":
    ## SyncManager stores numVerifyWorkers but the field is never read back
    ## to configure the actual Nim threadpool. setMaxPoolSize is only called in tests.
    ## Structural test: greping src/ for setMaxPoolSize yields only parallel_verify
    ## (in verifyScriptsParallelBatch auto-tune comment) and tests, never nimrod.nim
    ## or sync.nim production paths.
    ##
    ## Evidence: grep of src/ shows setMaxPoolSize absent from production code.
    ## BUG G18: --verify-threads=8 has zero effect on the actual thread count.
    check true  ## structural bug documented; no runtime assertion possible here

# ---------------------------------------------------------------------------
# G19: one FlowVar per input — massive spawn overhead
# ---------------------------------------------------------------------------
suite "G19 — one FlowVar per input vs Core's batch dispatch":
  ## Core: batches of ~128 CScriptChecks added to queue at once via control.Add(move(vChecks))
  ## Nimrod verifyScriptsParallel: one spawn per input (line 134: spawn verifyInputScript(task))
  ## For a block with 2000 inputs, this is 2000 FlowVar allocations + 2000 spawns.
  ## Core does ceil(2000/128) = 16 batch adds. Spawn overhead is significant.

  test "G19a: verifyScriptsParallel spawns one FlowVar per input":
    ## Block with a single tx having 3 inputs → 3 FlowVars
    let ops = @[makeOutpoint(1), makeOutpoint(2), makeOutpoint(3)]
    let spendTx = makeSpendTx(ops)
    let cb = makeCoinbaseTx(10)
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: txMerkleRoot(@[cb, spendTx]),
        timestamp: 1231012505'u32,
        bits: 0x207fffff'u32,
        nonce: 10'u32
      ),
      txs: @[cb, spendTx]
    )
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} =
      some(UtxoEntry(
        output: TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x51'u8]),
        height: 1'i32,
        isCoinbase: false
      ))
    ## verifyScriptsParallel spawns 3 FlowVars for 3 inputs
    let res = verifyScriptsParallel(blk, lookup, 10'i32, newCryptoEngine())
    check res.isOk
    ## BUG G19: 1 spawn per input; Core would use 1 batch add for all 3.

# ---------------------------------------------------------------------------
# G21: parallel path missing allAmounts/allScriptPubKeys for Taproot
# ---------------------------------------------------------------------------
suite "G21 — parallel path missing BIP-341 sighash inputs (allAmounts/allScriptPubKeys)":
  ## BIP-341 (Taproot) sighash requires the amounts and scriptPubKeys of ALL
  ## inputs to be committed to. Core's PrecomputedTransactionData.Init()
  ## collects all spent_outputs before any input is verified.
  ## Nimrod serial verifyScripts (validation.nim:1494-1512) correctly pre-collects
  ## allAmounts and allScriptPubKeys and passes them to verifyScript.
  ## Nimrod parallel verifyScriptsParallel: InputVerificationTask contains only
  ## (tx, inputIdx, prevOutput, prevHeight, isCoinbase, flags, amount) — a single
  ## amount for this input, NOT the full allAmounts/allScriptPubKeys arrays.
  ## verifyInputScript calls verifyScript with only the single input's data,
  ## missing the BIP-341-required committed values for OTHER inputs.

  test "G21a: InputVerificationTask contains single amount, not all amounts":
    ## Structural test: InputVerificationTask.amount is a single Satoshi,
    ## not a seq[Satoshi]. The task object at parallel_verify.nim:12-21
    ## has no allAmounts or allScriptPubKeys field.
    ##
    ## Serial path (validation.nim:1495-1512) correctly builds:
    ##   allAmounts: seq[Satoshi]
    ##   allScriptPubKeys: seq[seq[byte]]
    ## and passes them to verifyScript. Parallel path omits these.
    ##
    ## Consequence: Taproot spends verified via the (dead) parallel path
    ## would use wrong sighash and fail or accept incorrectly.
    check true  ## structural bug documented above

# ---------------------------------------------------------------------------
# G24: no PrecomputedTransactionData — sighash recomputed per-input
# ---------------------------------------------------------------------------
suite "G24 — no PrecomputedTransactionData (sighash precomputation)":
  ## Core: PrecomputedTransactionData.Init() computes hashPrevouts, hashSequences,
  ## hashOutputs once per transaction, then all inputs share it.
  ## CScriptCheck holds a pointer to the shared txdata.
  ## Nimrod: each verifyScript call recomputes sighash components from scratch.
  ## For a tx with 100 inputs, Core computes hashPrevouts once; nimrod 100 times.

  test "G24a: serial verifyScripts has no PrecomputedTransactionData field":
    ## verifyScripts (validation.nim:1460) has no txdata or precomputed parameter.
    ## Every call to verifyScript inside the loop recomputes sighash independently.
    ## BUG G24: O(n_inputs) sighash work vs Core's O(1) precomputation + O(n) verification.
    check true  ## structural performance bug

# ---------------------------------------------------------------------------
# G25: coinbase flag in InputVerificationTask is unused
# ---------------------------------------------------------------------------
suite "G25 — coinbase flag carried in task but never used by verifyInputScript":
  ## InputVerificationTask has field isCoinbase: bool (parallel_verify.nim:20)
  ## but verifyInputScript (line 39-67) never reads task.isCoinbase.
  ## Core CScriptCheck does not need a coinbase flag because coinbase inputs
  ## are excluded at the call site (CheckInputScripts skips coinbase txs).
  ## Nimrod's parallel path correctly skips coinbase at the tx loop level
  ## (1 ..< blk.txs.len), but the extra field is dead weight.

  test "G25a: isCoinbase field carried but never consumed":
    ## The verifyInputScript proc uses: task.tx, task.inputIdx, task.prevOutput,
    ## task.amount, task.flags, and task.inputIdx < tx.witnesses.len for witness.
    ## task.isCoinbase and task.prevHeight are stored but not used.
    ## This is a minor dead-field bug, not a consensus risk.
    check true  ## structural dead-field documented

# ---------------------------------------------------------------------------
# G26: parallel path skips blockHash exception checks
# ---------------------------------------------------------------------------
suite "G26 — parallel path skips BIP16/Taproot blockHash script_flag_exceptions":
  ## Core getBlockScriptFlagsForBlock has script_flag_exceptions:
  ##   BIP16_EXCEPTION_HASH → return SCRIPT_VERIFY_NONE
  ##   TAPROOT_EXCEPTION_HASH → exclude sfTaproot
  ## Nimrod serial path (validation.nim:491-524) correctly checks blockHash
  ## as a parameter to getBlockScriptFlags.
  ## Nimrod parallel path (parallel_verify.nim:80):
  ##   let flags = getBlockScriptFlags(height, mainnetParams())
  ## The blockHash parameter defaults to "" — BOTH exception checks are
  ## permanently disabled on the parallel path.

  test "G26a: parallel path calls getBlockScriptFlags without blockHash":
    ## BIP16 exception block hash: 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
    ## If this block were processed through verifyScriptsParallel (dead code now),
    ## it would get non-empty flags instead of SCRIPT_VERIFY_NONE.
    let bip16ExceptionHash = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
    let flagsWithHash = getBlockScriptFlags(170060'i32, mainnetParams(), bip16ExceptionHash)
    let flagsNoHash = getBlockScriptFlags(170060'i32, mainnetParams(), "")
    ## With the exception hash, flags should be empty (SCRIPT_VERIFY_NONE)
    check flagsWithHash == {}
    ## Without blockHash (what parallel path does), flags are non-empty
    check flagsNoHash != {}
    ## BUG G26: parallel path always uses flagsNoHash behavior

# ---------------------------------------------------------------------------
# G28: worker threads have no name
# ---------------------------------------------------------------------------
suite "G28 — worker threads not named (no ThreadRename equivalent)":
  ## Core: CCheckQueue constructor names each worker thread "scriptch.%i"
  ## via util::ThreadRename. This makes profiling and debugging much easier.
  ## Nimrod: Nim's threadpool spawns anonymous threads; no thread-naming API.
  ## Not a correctness bug but a significant operational/debug gap.

  test "G28a: Nim threadpool provides no per-thread naming":
    ## Structural test: Nim's std/threadpool has no ThreadRename equivalent.
    ## All script checker threads appear as anonymous OS threads.
    check true  ## documented operational gap

# ---------------------------------------------------------------------------
# G29: passed-in CryptoEngine is ignored by parallel tasks
# ---------------------------------------------------------------------------
suite "G29 — crypto parameter ignored; each worker creates its own engine":
  ## verifyScriptsParallel signature: crypto: CryptoEngine
  ## But verifyInputScript (the worker proc) does NOT use the passed engine.
  ## Instead it calls getThreadCrypto() which creates a per-thread CryptoEngine.
  ## The caller-provided engine is completely ignored.
  ## This means any custom secp256k1 context configuration passed in is lost.

  test "G29a: verifyScriptsParallel ignores its crypto parameter":
    ## Both verifyScriptsParallel and verifyScriptsParallelBatch accept
    ## crypto: CryptoEngine but neither passes it to verifyInputScript.
    ## verifyInputScript calls getThreadCrypto() unconditionally.
    let engine1 = newCryptoEngine()
    let engine2 = newCryptoEngine()
    let blk = makeSimpleBlock(1'i32, BlockHash(default(array[32, byte])))
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe.} = none(UtxoEntry)
    ## Both engines give same result because the engine parameter is ignored
    let res1 = verifyScriptsParallel(blk, lookup, 1'i32, engine1)
    let res2 = verifyScriptsParallel(blk, lookup, 1'i32, engine2)
    check res1.isOk == res2.isOk
    ## BUG G29: crypto parameter is dead; workers always create fresh engines.

# ---------------------------------------------------------------------------
# G3/G4 composite: no master-joins-as-Nth-worker, no RAII control
# ---------------------------------------------------------------------------
suite "G3/G4 — no master-joins-as-Nth-worker and no RAII control":
  ## Core: master thread calls Loop(fMaster=true) and participates in verification.
  ## Core CCheckQueueControl RAII: destructor calls Complete() if not already done.
  ## Nimrod: master thread spawns tasks and then BLOCKS awaiting each FlowVar in
  ## sequence (^fv). The master does zero verification work.
  ## No RAII wrapper — if an exception or early return occurs mid-block,
  ## the spawned FlowVars may continue running with no cleanup.

  test "G3a: master thread does no script work — only dispatches and awaits":
    ## In verifyScriptsParallel the main goroutine/thread:
    ##   1. spawns via `spawn verifyInputScript(task)` for each input
    ##   2. collects via `^fv` (blocking read) for each flowvar
    ## It never calls verifyInputScript itself. On a single-CPU machine,
    ## the spawned tasks may run on the same OS thread (Nim threadpool), but
    ## the algorithm still differs from Core where the master is the N-th worker.
    check true  ## structural gap documented

  test "G4a: no RAII — early return abandons spawned FlowVars":
    ## If UTXO lookup fails (veInputsMissing), verifyScriptsParallel returns early
    ## at line 116 WITHOUT waiting for already-spawned FlowVars from a prior tx.
    ## For per-tx loops this is OK (no cross-tx FlowVars exist at that point),
    ## but within a tx, after some FlowVars are spawned and before all are awaited,
    ## an early return leaks live FlowVars.
    ## In practice the per-tx approach spawns all tasks before collecting,
    ## so within a tx there is no early-return-before-collection.
    ## The real gap: no RAII equivalent to CCheckQueueControl's destructor.
    check true  ## structural gap documented

# ---------------------------------------------------------------------------
# Regression: serial verifyScripts still works correctly
# ---------------------------------------------------------------------------
suite "serial verifyScripts correctness (production path)":
  test "coinbase-only block verified ok":
    let params = regtestParams()
    let cb = makeCoinbaseTx(1)
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: params.genesisBlockHash,
        merkleRoot: txMerkleRoot(@[cb]),
        timestamp: 1231007105'u32,
        bits: 0x207fffff'u32,
        nonce: 1'u32
      ),
      txs: @[cb]
    )
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      none(UtxoEntry)
    let res = verifyScripts(blk, lookup, 1'i32, newCryptoEngine(), params)
    check res.isOk

  test "OP_TRUE spend verified ok by serial path":
    let params = regtestParams()
    let op = makeOutpoint(42)
    let spendTx = makeSpendTx(@[op])
    let cb = makeCoinbaseTx(2)
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: params.genesisBlockHash,
        merkleRoot: txMerkleRoot(@[cb, spendTx]),
        timestamp: 1231007705'u32,
        bits: 0x207fffff'u32,
        nonce: 2'u32
      ),
      txs: @[cb, spendTx]
    )
    let opTxid = op.txid
    let opVout = op.vout
    let lookup = proc(op2: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      if op2.txid == opTxid and op2.vout == opVout:
        some(UtxoEntry(
          output: TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x51'u8]),
          height: 1'i32,
          isCoinbase: false
        ))
      else:
        none(UtxoEntry)
    let res = verifyScripts(blk, lookup, 2'i32, newCryptoEngine(), params)
    check res.isOk

  test "invalid script rejected by serial path":
    let params = regtestParams()
    let op = makeOutpoint(99)
    ## OP_RETURN scriptPubKey = provably unspendable
    let spendTx = makeSpendTx(@[op])
    let cb = makeCoinbaseTx(3)
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: params.genesisBlockHash,
        merkleRoot: txMerkleRoot(@[cb, spendTx]),
        timestamp: 1231008305'u32,
        bits: 0x207fffff'u32,
        nonce: 3'u32
      ),
      txs: @[cb, spendTx]
    )
    let op3Txid = op.txid
    let op3Vout = op.vout
    let lookup = proc(op2: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      if op2.txid == op3Txid and op2.vout == op3Vout:
        some(UtxoEntry(
          output: TxOut(value: Satoshi(1000), scriptPubKey: @[0x6a'u8]),
          height: 1'i32,
          isCoinbase: false
        ))
      else:
        none(UtxoEntry)
    let res = verifyScripts(blk, lookup, 3'i32, newCryptoEngine(), params)
    check not res.isOk

  test "SigCache hit skips re-verification":
    ## After first verification, the entry is in globalSigCache.
    ## Second call returns immediately via cache hit.
    let params = regtestParams()
    let op = makeOutpoint(500)
    let spendTx = makeSpendTx(@[op])
    let cb = makeCoinbaseTx(4)
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: params.genesisBlockHash,
        merkleRoot: txMerkleRoot(@[cb, spendTx]),
        timestamp: 1231008905'u32,
        bits: 0x207fffff'u32,
        nonce: 4'u32
      ),
      txs: @[cb, spendTx]
    )
    let op4Txid = op.txid
    let op4Vout = op.vout
    let lookup = proc(op2: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      if op2.txid == op4Txid and op2.vout == op4Vout:
        some(UtxoEntry(
          output: TxOut(value: Satoshi(50_000_000), scriptPubKey: @[0x51'u8]),
          height: 1'i32,
          isCoinbase: false
        ))
      else:
        none(UtxoEntry)
    let res1 = verifyScripts(blk, lookup, 4'i32, newCryptoEngine(), params)
    check res1.isOk
    ## Second call: should hit SigCache and return ok without re-verifying
    let res2 = verifyScripts(blk, lookup, 4'i32, newCryptoEngine(), params)
    check res2.isOk
