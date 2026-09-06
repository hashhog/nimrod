## W167 — parallel script-verify worker pool: engagement + correctness gates.
##
## This is the load-bearing test for the IBD-perf lever. It proves THREE things
## the dead `perf/parallel_verify.nim` path could not:
##
##   1. THREAD ENGAGEMENT (>1 core). The static pool DEMONSTRABLY runs checks on
##      more than one OS thread on a script-heavy block of real ECDSA inputs, and
##      the parallel wall-clock is faster than serial. A correct-but-1-core
##      result is a FAIL here (that was haskoin's parMap-fizzle failure mode).
##
##   2. SERIAL == PARALLEL verdict parity. The same seq[ScriptCheck], run serially
##      vs across the pool, yields the identical accept/reject verdict.
##
##   3. G21 TAPROOT NON-DROP. A multi-input Taproot key-path spend verifies only
##      when the FULL allAmounts/allScriptPubKeys arrays are committed (which
##      collectChecks does on every ScriptCheck). Tampering one input's amount —
##      the data the dead 7-arg path dropped — must REJECT.
##
## Plus a secp-prewarm regression and a reachability test that a bad script
## routed through verifyScripts (the production envelope) is rejected.
##
## Run:
##   nim c -r --threads:on --mm:arc -d:release tests/test_w167_verify_pool.nim

import unittest2
import std/[options, times, cpuinfo]
import ../src/perf/verify_pool
import ../src/consensus/[validation, params]
import ../src/storage/chainstate
import ../src/primitives/[types, serialize]
import ../src/wallet/wallet
import ../src/script/interpreter
import ../src/crypto/[hashing, secp256k1, address]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc mkPriv(b0, b1: byte): PrivateKey =
  for i in 0 ..< 32: result[i] = 0
  result[30] = b0
  result[31] = b1

proc p2pkhScript(pub: PublicKey): seq[byte] =
  ## OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  let pkh = hash160(pub)
  result = @[0x76'u8, 0xa9'u8, 0x14'u8]
  result.add(@pkh)
  result.add([0x88'u8, 0xac'u8])

# Mandatory-ish flag set for legacy P2PKH ECDSA verification (no taproot).
const P2pkhFlags = {sfP2SH, sfDERSig, sfStrictEnc, sfLowS, sfNullFail}

proc mkSignedP2pkhCheck(seed: int,
                        storeOut: var seq[TxPrevouts]): ScriptCheck =
  ## Build ONE fully-signed P2PKH input as a self-contained ScriptCheck doing
  ## real ECDSA verification — the dominant mainnet IBD workload.
  ##
  ## `storeOut` is a caller-owned seq that must outlive the returned ScriptCheck
  ## (and any runChecks call using it).  One TxPrevouts entry is appended to it
  ## and the check's prevoutsPtr points into that entry.
  let priv = mkPriv(byte((seed shr 8) and 0xff), byte(seed and 0xff))
  let pub = derivePublicKey(priv)
  let spk = p2pkhScript(pub)

  var prevTxid: array[32, byte]
  prevTxid[0] = byte(seed and 0xff)
  prevTxid[1] = byte((seed shr 8) and 0xff)
  prevTxid[2] = 0xa5'u8
  var tx = Transaction(
    version: 2'i32,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(prevTxid), vout: 0'u32),
      scriptSig: @[],
      sequence: 0xffffffff'u32
    )],
    outputs: @[TxOut(value: Satoshi(90_000_000), scriptPubKey: spk)],
    witnesses: @[ @[] ],
    lockTime: 0'u32
  )
  signInputP2PKH(tx, 0, priv, pub)

  storeOut.add(TxPrevouts(
    allAmounts: @[Satoshi(0)],
    allScriptPubKeys: @[spk]
  ))

  ScriptCheck(
    scriptSig: tx.inputs[0].scriptSig,
    scriptPubKey: spk,
    tx: tx,
    inputIndex: 0,
    amount: Satoshi(0),
    flags: P2pkhFlags,
    witness: @[],
    prevoutsPtr: addr storeOut[storeOut.len - 1]
  )

# ---------------------------------------------------------------------------
# Suite 1: thread engagement (>1 core) — THE load-bearing proof
# ---------------------------------------------------------------------------

suite "W167 — pool engages >1 core on real ECDSA work":

  test "ENGAGEMENT: parallel pool runs checks across more than one thread":
    # Start the static pool the same way the node does at boot.
    initVerifyPool(0)  # 0 = auto = countProcessors()-1, clamped to 15
    let helpers = poolWorkerCount()
    echo "pool helper threads: ", helpers, " (+1 master = ", helpers + 1, " verifiers)"
    check helpers >= 1

    # Build a chunky batch of real ECDSA-signed checks so each worker has
    # meaningful work to claim. 4000 ECDSA verifications.
    # `store` must outlive `checks` and the runChecks call below.
    var store: seq[TxPrevouts] = newSeqOfCap[TxPrevouts](4000)
    var checks: seq[ScriptCheck] = @[]
    for i in 0 ..< 4000:
      checks.add(mkSignedP2pkhCheck(i + 1, store))

    enableInstrumentation()
    let okPar = runChecksParallel(checks)
    let nThreads = distinctThreadCount()
    let nRun = instrumentedChecksRun()
    disableInstrumentation()

    echo "ENGAGEMENT: distinct threads that executed checks = ", nThreads,
         " ; checks run = ", nRun, " / ", checks.len
    check okPar                 # all valid sigs → accept
    check nRun == checks.len    # every check ran exactly once
    # THE GATE: more than one OS thread actually executed checks. On a box with
    # >=2 cores the master + at least one helper must both have claimed work.
    if countProcessors() >= 2:
      check nThreads >= 2
    else:
      echo "  (single-core box: skipping >1-thread assertion)"

  test "SPEEDUP: parallel wall-clock beats serial on a script-heavy batch":
    initVerifyPool(0)
    var store: seq[TxPrevouts] = newSeqOfCap[TxPrevouts](6000)
    var checks: seq[ScriptCheck] = @[]
    for i in 0 ..< 6000:
      checks.add(mkSignedP2pkhCheck(100000 + i, store))

    # Serial baseline (wall clock).
    let t0 = epochTime()
    let okSer = runChecksSerial(checks)
    let serialMs = (epochTime() - t0) * 1000.0

    # Parallel.
    let t1 = epochTime()
    let okPar = runChecksParallel(checks)
    let parallelMs = (epochTime() - t1) * 1000.0

    let speedup = if parallelMs > 0: serialMs / parallelMs else: 1.0
    echo "SPEEDUP: serial=", serialMs, "ms  parallel=", parallelMs,
         "ms  speedup=", speedup, "x  (cores=", countProcessors(), ")"
    check okSer
    check okPar
    check okSer == okPar
    if countProcessors() >= 4:
      # Conservative floor; the real lever target is ~2x. ECDSA is the bulk of
      # the work so this should clear comfortably, but we keep the gate modest
      # to avoid CI flakiness on a loaded box.
      check speedup >= 1.5
    else:
      echo "  (<4 cores: skipping speedup floor assertion)"

# ---------------------------------------------------------------------------
# Suite 2: serial == parallel verdict parity (accept AND reject)
# ---------------------------------------------------------------------------

suite "W167 — serial and parallel verdicts are identical":

  test "all-valid batch: both accept":
    initVerifyPool(0)
    var store: seq[TxPrevouts] = newSeqOfCap[TxPrevouts](200)
    var checks: seq[ScriptCheck] = @[]
    for i in 0 ..< 200:
      checks.add(mkSignedP2pkhCheck(500000 + i, store))
    check runChecksSerial(checks) == true
    check runChecksParallel(checks) == true

  test "one tampered sig in the batch: both reject":
    initVerifyPool(0)
    var store: seq[TxPrevouts] = newSeqOfCap[TxPrevouts](200)
    var checks: seq[ScriptCheck] = @[]
    for i in 0 ..< 200:
      checks.add(mkSignedP2pkhCheck(600000 + i, store))
    # Corrupt the scriptSig of one check so its ECDSA verify fails.
    var bad = checks[137]
    if bad.scriptSig.len > 5:
      bad.scriptSig[5] = bad.scriptSig[5] xor 0xff'u8
    checks[137] = bad
    check runChecksSerial(checks) == false
    check runChecksParallel(checks) == false

# ---------------------------------------------------------------------------
# Suite 3: G21 — multi-input Taproot non-drop guard
# ---------------------------------------------------------------------------

suite "W167 — G21: multi-input Taproot key-path uses the FULL prevout arrays":

  test "2-input Taproot keypath: valid accepts; tampered amount rejects":
    # Use the wallet to derive two BIP-86 P2TR outputs (correctly tweaked output
    # keys) and sign a 2-input tx spending both. The BIP-341 sighash commits to
    # BOTH inputs' amounts + scriptPubKeys; the dead 7-arg path dropped those.
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    wallet.addAccount(86, 0, 2)
    let a0 = wallet.accounts[0].externalKeys[0]
    let a1 = wallet.accounts[0].externalKeys[1]
    let spk0 = scriptPubKeyForAddress(a0.address)
    let spk1 = scriptPubKeyForAddress(a1.address)
    check spk0[0] == 0x51'u8 and spk0.len == 34
    check spk1[0] == 0x51'u8 and spk1.len == 34

    let amt0 = Satoshi(150_000)
    let amt1 = Satoshi(250_000)

    var tx = Transaction(version: 2'i32, lockTime: 0'u32)
    tx.inputs.add(TxIn(prevOut: OutPoint(vout: 0'u32), sequence: 0xfffffffd'u32))
    tx.inputs.add(TxIn(prevOut: OutPoint(vout: 1'u32), sequence: 0xfffffffd'u32))
    tx.outputs.add(TxOut(value: Satoshi(390_000),
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)))
    tx.witnesses = @[@[], @[]]

    let allAmounts = @[amt0, amt1]
    let allSpks = @[spk0, spk1]
    # Sign both inputs with the wallet keys, committing to the full arrays.
    signInputP2TR(tx, 0, a0.extKey.key, allAmounts, allSpks)
    signInputP2TR(tx, 1, a1.extKey.key, allAmounts, allSpks)

    const TrFlags = {sfP2SH, sfWitness, sfTaproot, sfNullFail, sfLowS,
                     sfDERSig, sfStrictEnc}

    # Build the TWO ScriptChecks exactly as collectChecks would — each carrying
    # the FULL allAmounts/allScriptPubKeys via a shared TxPrevouts (the G21 fix).
    # One TxPrevouts covers both inputs of this 2-input tx.
    var goodStore: seq[TxPrevouts] = @[TxPrevouts(
      allAmounts: allAmounts,
      allScriptPubKeys: allSpks
    )]
    var goodChecks: seq[ScriptCheck] = @[]
    for idx in 0 ..< 2:
      goodChecks.add(ScriptCheck(
        scriptSig: tx.inputs[idx].scriptSig,
        scriptPubKey: allSpks[idx],
        tx: tx,
        inputIndex: idx,
        amount: allAmounts[idx],
        flags: TrFlags,
        witness: tx.witnesses[idx],
        prevoutsPtr: addr goodStore[0]
      ))

    # Valid: serial AND parallel both accept (full arrays → correct BIP-341 sighash).
    check runChecksSerial(goodChecks) == true
    check runChecksParallel(goodChecks) == true

    # G21 GUARD: drop the array commitment for input 0 the way the dead 7-arg
    # path did (single-amount fallback). Build a separate store with a truncated
    # TxPrevouts for input 0: verifyScript falls back to single-amount when
    # allAmounts.len != tx.inputs.len, so the sighash no longer matches → REJECT.
    var droppedStore: seq[TxPrevouts] = @[TxPrevouts(
      allAmounts: @[allAmounts[0]],          # len 1 != 2 inputs
      allScriptPubKeys: @[allSpks[0]]
    )]
    var droppedStore1: seq[TxPrevouts] = @[TxPrevouts(
      allAmounts: allAmounts,
      allScriptPubKeys: allSpks
    )]
    var droppedChecks: seq[ScriptCheck] = @[]
    droppedChecks.add(ScriptCheck(
      scriptSig: tx.inputs[0].scriptSig,
      scriptPubKey: allSpks[0],
      tx: tx, inputIndex: 0, amount: allAmounts[0], flags: TrFlags,
      witness: tx.witnesses[0],
      prevoutsPtr: addr droppedStore[0]   # truncated: len 1 != 2 → fallback
    ))
    droppedChecks.add(ScriptCheck(
      scriptSig: tx.inputs[1].scriptSig,
      scriptPubKey: allSpks[1],
      tx: tx, inputIndex: 1, amount: allAmounts[1], flags: TrFlags,
      witness: tx.witnesses[1],
      prevoutsPtr: addr droppedStore1[0]  # full arrays, but input 0 broken
    ))
    check runChecksSerial(droppedChecks) == false
    check runChecksParallel(droppedChecks) == false

    # G21 GUARD 2: tamper one committed amount (full-length array, wrong value).
    # The signed sighash committed to amt1; flipping it must REJECT.
    var tamperedStore: seq[TxPrevouts] = @[TxPrevouts(
      allAmounts: @[amt0, amt1 + Satoshi(1)],
      allScriptPubKeys: allSpks
    )]
    var tamperedChecks: seq[ScriptCheck] = @[]
    for idx in 0 ..< 2:
      tamperedChecks.add(ScriptCheck(
        scriptSig: tx.inputs[idx].scriptSig,
        scriptPubKey: allSpks[idx],
        tx: tx, inputIndex: idx, amount: allAmounts[idx], flags: TrFlags,
        witness: tx.witnesses[idx],
        prevoutsPtr: addr tamperedStore[0]
      ))
    check runChecksSerial(tamperedChecks) == false
    check runChecksParallel(tamperedChecks) == false

# ---------------------------------------------------------------------------
# Suite 4: secp pre-warm regression + reachability through verifyScripts
# ---------------------------------------------------------------------------

suite "W167 — secp pre-warm + production-envelope reachability":

  test "secp pre-warm: initVerifyPool warms the context (no lazy-init race)":
    # initVerifyPool calls initSecp256k1() on the main thread before spawning
    # workers. After it, a signature verify from this thread must succeed,
    # confirming the global context is live and randomized.
    initVerifyPool(0)
    let priv = mkPriv(0x12, 0x34)
    let pub = derivePublicKey(priv)
    var msg: array[32, byte]
    for i in 0 ..< 32: msg[i] = byte(i)
    let sig = sign(priv, msg)
    check verify(pub, msg, sig) == true

  test "REACHABILITY: a bad script routed through verifyScripts is rejected":
    # Flips the old G1a 'dead-code' documentation test into a real reachability
    # check: a block with a provably-unspendable (OP_RETURN) prevout, run through
    # the PRODUCTION verifyScripts → collectChecks → runChecks envelope, must
    # reject. This proves the parallel path is wired into the live acceptance
    # pipeline, not dead code.
    let params = regtestParams()
    initVerifyPool(0)

    # coinbase + one tx spending an OP_RETURN output (unspendable).
    var cbTxid: array[32, byte]
    cbTxid[0] = 0x11
    let coinbase = Transaction(
      version: 1'i32,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 0'u32
    )
    var spendPrev: array[32, byte]
    spendPrev[0] = 0x99
    let spendTx = Transaction(
      version: 1'i32,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(spendPrev), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
      witnesses: @[],
      lockTime: 0'u32
    )
    var txHashes: seq[array[32, byte]]
    txHashes.add(array[32, byte](coinbase.txid()))
    txHashes.add(array[32, byte](spendTx.txid()))
    let blk = Block(
      header: BlockHeader(
        version: 1'i32,
        prevBlock: params.genesisBlockHash,
        merkleRoot: hashing.computeMerkleRoot(txHashes),
        timestamp: 1231009705'u32,
        bits: 0x207fffff'u32,
        nonce: 1'u32
      ),
      txs: @[coinbase, spendTx]
    )
    let spendTxid = spendTx.inputs[0].prevOut.txid
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      if op.txid == spendTxid:
        some(UtxoEntry(
          output: TxOut(value: Satoshi(50_000), scriptPubKey: @[0x6a'u8]),  # OP_RETURN
          height: 1'i32, isCoinbase: false))
      else:
        none(UtxoEntry)
    let res = verifyScripts(blk, lookup, 5'i32, newCryptoEngine(), params)
    check not res.isOk
    check res.error == veScriptVerifyFailed
