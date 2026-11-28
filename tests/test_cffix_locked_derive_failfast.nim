## cffix-nimrod-locked-derive-failfast: a locked wallet must never spin in
## BIP-32 derivation.  getnewaddress on a re-locked wallet serves the keys it
## already derived and then fails fast with Core's "Keypool ran out".
##
## Finding (fingerprint
## nimrod/wallet/locked-zeroed-masterkey-hardened-derive-retry-spin):
##   * lockWallet zeroed masterKey.key but left masterKey.isPrivate = true.
##   * ensureGap / derivePath never asked canDeriveKeys, so getnewaddress on a
##     re-locked wallet derived m/84'/.. from the all-zero private key.
##   * deriveChild treats every libsecp rejection as BIP-32's "invalid child,
##     try the next index".  A zero parent key is rejected for EVERY index, so
##     the loop walked the whole hardened index space (~2^31 HMAC-SHA512 +
##     tweak calls) -- and getnewaddress runs under withChainLock, so the node
##     stalled block processing for the duration.
##
## Core: the private keys of a locked wallet are unavailable; GetNewDestination
## hands out what the keypool already holds and otherwise fails with
## RPC_WALLET_KEYPOOL_RAN_OUT (-12) "Error: Keypool ran out, please call
## keypoolrefill first" (wallet/rpc/addresses.cpp getnewaddress,
## wallet/scriptpubkeyman.cpp TopUp needs the keys).  CExtKey::Derive
## (key.cpp) derives from a valid key; the retry rule of BIP-32 is for an
## invalid CHILD, never an invalid PARENT.
##
## How the spin is bounded: every derivation under test runs on its own thread
## and the main thread polls it for at most TimeoutMs (a fixed iteration count
## of PollMs sleeps).  On the base commit the thread never finishes inside the
## bound, the check fails by name, and the thread is abandoned (it is killed
## when the test process exits).  The positive control proves the harness
## reports a fast derivation as fast.
##
## Run:
##   nim c -r tests/test_cffix_locked_derive_failfast.nim

import std/[atomics, json, options, os, strutils, tempfiles]
import unittest2

import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager]

const
  Mnemonic = "abandon abandon abandon abandon abandon abandon abandon " &
             "abandon abandon abandon abandon about"
  # BIP-84 test vector for Mnemonic, m/84'/0'/0'/0/0.
  Bip84First = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
  TimeoutMs = 1000
  PollMs = 5
  KeypoolRanOut = "Keypool ran out"

type
  Scenario = enum
    sZeroPrivHardened     ## deriveChild(zero private key, 84')
    sZeroPrivNormal       ## deriveChild(zero private key, 0)
    sBadPubNormal         ## deriveChild(invalid public key, 0)
    sControlValid         ## deriveChild(real master, 84') -- must be fast
    sRelockedReceive      ## encrypt, unlock, lock, getNewAddress until refused
    sRelockedChange       ## same on the internal (change) chain
    sRelockedNewType      ## locked: first address of a type with no account

  Outcome = enum
    oRunning, oReturned, oRaisedWalletError, oOtherError

var
  outcomes: array[Scenario, Atomic[int]]
  notes: array[Scenario, string]
  served: array[Scenario, int]
  pathOk: array[Scenario, bool]
  workers: array[Scenario, Thread[Scenario]]
  expectedReceive, expectedChange: seq[string]

proc zeroPriv(): ExtendedKey =
  result.isPrivate = true          # key, publicKey, chainCode all zero

proc drainLocked(w: var Wallet, isChange: bool, expected: seq[string],
                 sc: Scenario) =
  ## Draw addresses from a re-locked wallet until it refuses (at most 200).
  ## Every served address must be the next one of the deterministic chain.
  var ok = true
  for i in 0 ..< 200:
    let a = w.getNewAddressStr(P2WPKH, -1, isChange)   # raises when refused
    served[sc] = i + 1
    if 1 + i >= expected.len or a != expected[1 + i]: ok = false
    pathOk[sc] = ok

proc relockedWallet(isChange: bool, expected: seq[string]): Wallet =
  ## One address drawn while unencrypted (creates the bech32 account and its
  ## gap), then encrypt, unlock, lock.
  result = newWallet(Mnemonic)
  let first = result.getNewAddressStr(P2WPKH, -1, isChange)
  doAssert first == expected[0]
  doAssert result.encryptWallet("p")
  doAssert result.unlockWallet("p")
  result.lockWallet()

proc runScenario(sc: Scenario) {.thread.} =
  {.cast(gcsafe).}:
    var o = oReturned
    try:
      case sc
      of sZeroPrivHardened:
        discard deriveChild(zeroPriv(), HARDENED + 84'u32)
      of sZeroPrivNormal:
        discard deriveChild(zeroPriv(), 0'u32)
      of sBadPubNormal:
        var k: ExtendedKey           # isPrivate = false, publicKey all zero
        discard deriveChild(k, 0'u32)
      of sControlValid:
        let w = newWallet(Mnemonic)
        let child = deriveChild(w.masterKey, HARDENED + 84'u32)
        pathOk[sc] = child.isPrivate and child.depth == 1 and
                     child.childIndex == HARDENED + 84'u32
      of sRelockedReceive:
        var w = relockedWallet(false, expectedReceive)
        drainLocked(w, false, expectedReceive, sc)
      of sRelockedChange:
        var w = relockedWallet(true, expectedChange)
        drainLocked(w, true, expectedChange, sc)
      of sRelockedNewType:
        var w = relockedWallet(false, expectedReceive)
        let accountsBefore = w.accounts.len
        try:
          discard w.getNewAddressStr(P2TR)
        finally:
          pathOk[sc] = w.accounts.len == accountsBefore
    except WalletError as e:
      o = oRaisedWalletError
      notes[sc] = e.msg
    except CatchableError as e:
      o = oOtherError
      notes[sc] = $e.name & ": " & e.msg
    outcomes[sc].store(ord(o))

proc runBounded(sc: Scenario): Outcome =
  ## Start `sc` on its own thread and wait at most TimeoutMs for it.  Returns
  ## oRunning if it did not finish (the thread is left behind, never joined).
  outcomes[sc].store(ord(oRunning))
  createThread(workers[sc], runScenario, sc)
  for _ in 0 ..< TimeoutMs div PollMs:       # bounded: no unbounded wait
    let o = Outcome(outcomes[sc].load())
    if o != oRunning:
      joinThread(workers[sc])
      return o
    sleep(PollMs)
  result = Outcome(outcomes[sc].load())
  if result != oRunning:
    joinThread(workers[sc])

# The deterministic address chains a re-locked wallet must reproduce, from an
# identical wallet that was never encrypted.
block:
  var w = newWallet(Mnemonic)
  for i in 0 ..< 40: expectedReceive.add w.getNewAddressStr(P2WPKH, -1, false)
  for i in 0 ..< 40: expectedChange.add w.getNewAddressStr(P2WPKH, -1, true)

var walletLayerFailsFast = false

suite "cffix deriveChild fails fast on an invalid parent key":
  test "zeroed private parent, hardened 84': raises within 1 s":
    let o = runBounded(sZeroPrivHardened)
    check o == oRaisedWalletError
    if o == oRunning:
      checkpoint "deriveChild still running after " & $TimeoutMs &
                 " ms (retrying across the hardened index space)"

  test "zeroed private parent, normal index 0: raises within 1 s":
    let o = runBounded(sZeroPrivNormal)
    check o == oRaisedWalletError

  test "invalid public parent, normal index 0: raises within 1 s":
    let o = runBounded(sBadPubNormal)
    check o == oRaisedWalletError

  test "control: a valid master derives 84' inside the same bound":
    let o = runBounded(sControlValid)
    check o == oReturned
    check pathOk[sControlValid]
    check expectedReceive[0] == Bip84First

suite "cffix a re-locked wallet serves its keypool, then fails fast":
  test "lockWallet drops the private flag with the key":
    var w = newWallet(Mnemonic)
    check w.encryptWallet("p")
    check w.unlockWallet("p")
    check w.canDeriveKeys()
    w.lockWallet()
    check not w.masterKey.isPrivate
    check not w.canDeriveKeys()

  test "encrypt, unlock, lock: getNewAddress serves the 20 pre-derived keys, then Keypool ran out":
    let o = runBounded(sRelockedReceive)
    check o == oRaisedWalletError
    check KeypoolRanOut in notes[sRelockedReceive]
    # The gap the wallet derived while unlocked, no more, no fewer, and every
    # one the same address an unencrypted twin hands out at that position.
    check served[sRelockedReceive] == 20
    check pathOk[sRelockedReceive]
    walletLayerFailsFast = o == oRaisedWalletError

  test "same on the change chain":
    let o = runBounded(sRelockedChange)
    check o == oRaisedWalletError
    check KeypoolRanOut in notes[sRelockedChange]
    check served[sRelockedChange] == 20
    check pathOk[sRelockedChange]

  test "an address type with no account is refused without adding one":
    let o = runBounded(sRelockedNewType)
    check o == oRaisedWalletError
    check KeypoolRanOut in notes[sRelockedNewType]
    check pathOk[sRelockedNewType]

  test "unlock again refills the pool and continues the chain without a gap":
    var w = relockedWallet(false, expectedReceive)
    if not walletLayerFailsFast:
      # Draining a locked wallet spins on this build; do not start it here.
      checkpoint "skipped: the re-locked wallet does not fail fast"
      check walletLayerFailsFast
    else:
      for i in 1 .. 20: discard w.getNewAddressStr()
      expect WalletError:
        discard w.getNewAddressStr()
      check w.unlockWallet("p")
      check w.getNewAddressStr() == expectedReceive[21]

suite "cffix getnewaddress RPC on a re-locked wallet":
  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_cffix_lockedderive_", "_regtest")
    cs = newChainState(tempDir, cparams)
    if cs.bestHeight < 0:
      let res = cs.connectBlock(buildGenesisBlock(cparams), 0)
      doAssert res.isOk, "Failed to connect genesis"
    let mp = newMempool(cs, cparams)
    rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = newFeeEstimator(), params = cparams)
    wm = newWalletManager(tempDir, cparams, cs)
    rpc.walletManager = wm
    discard rpc.handleMethod("createwallet", %*["lw"])
    discard rpc.handleMethod("encryptwallet", %*["p"])
    discard rpc.handleMethod("walletpassphrase", %*["p", 600])
    discard rpc.handleMethod("getnewaddress", %*[])
    discard rpc.handleMethod("getrawchangeaddress", %*[])
    discard rpc.handleMethod("walletlock", %*[])

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  proc rpcCode(m: string, p: JsonNode): (int, string) =
    try:
      discard rpc.handleMethod(m, p)
      (0, "")
    except RpcError as e:
      (e.code, e.msg)

  test "getnewaddress: 20 from the pool, then -12 Keypool ran out":
    if not walletLayerFailsFast:
      checkpoint "skipped: the re-locked wallet does not fail fast"
      check walletLayerFailsFast
    else:
      for i in 1 .. 20:
        check rpc.handleMethod("getnewaddress", %*[]).kind == JString
      let (code, msg) = rpcCode("getnewaddress", %*[])
      check code == -12
      check msg == "Error: Keypool ran out, please call keypoolrefill first"

  test "reloaded while locked (no derived keys): getnewaddress is -12 at once":
    # A reload restores account cursors only; a locked wallet cannot derive
    # them, so its pool is empty.  (Safe to run unguarded: the reloaded master
    # is a public-flagged zero key, which master refuses fast, with -1.)
    discard rpc.handleMethod("unloadwallet", %*["lw"])
    discard rpc.handleMethod("loadwallet", %*["lw"])
    let (code, msg) = rpcCode("getnewaddress", %*[])
    check code == -12
    check msg == "Error: Keypool ran out, please call keypoolrefill first"
    # Unlocking derives the pool again, and the next address follows on.
    discard rpc.handleMethod("walletpassphrase", %*["p", 600])
    check rpc.handleMethod("getnewaddress", %*[]).kind == JString

  test "getrawchangeaddress: 20 from the pool, then -12 Keypool ran out":
    if not walletLayerFailsFast:
      checkpoint "skipped: the re-locked wallet does not fail fast"
      check walletLayerFailsFast
    else:
      for i in 1 .. 20:
        check rpc.handleMethod("getrawchangeaddress", %*[]).kind == JString
      let (code, msg) = rpcCode("getrawchangeaddress", %*[])
      check code == -12
      check msg == "Error: Keypool ran out, please call keypoolrefill first"
