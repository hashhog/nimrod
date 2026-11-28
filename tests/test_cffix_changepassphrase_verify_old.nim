## cffix-nimrod-changepassphrase-verify-old: walletpassphrasechange must check
## the old passphrase even when the wallet is unlocked.
##
## Finding (fingerprint
## nimrod/wallet/changepassphrase-skips-old-verification-when-unlocked):
## changePassphrase only tried oldPassphrase `if wallet.isLocked`. On an
## unlocked wallet it re-encrypted the in-memory seed under newPassphrase with
## no check at all, and handleWalletPassphraseChange then persisted the new
## key material. Anyone who reached the RPC during an unlock window could
## replace the passphrase without knowing it.
##
## Core (bitcoin-core/src/wallet/wallet.cpp CWallet::ChangeWalletPassphrase):
## for every master key it runs DecryptMasterKey(strOldWalletPassphrase, ...)
## and returns false if that fails, whether or not the wallet was unlocked.
## Only a master key that decrypts under the old passphrase is re-encrypted.
##
## Run:
##   nim c -r tests/test_cffix_changepassphrase_verify_old.nim

import std/[json, options, tempfiles, os]
import unittest2

import ../src/consensus/[params, validation]
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/[wallet, manager]

const Mnemonic = "abandon abandon abandon abandon abandon abandon abandon " &
                 "abandon abandon abandon abandon about"

suite "cffix changePassphrase verifies the old passphrase (Core ChangeWalletPassphrase)":
  test "unlocked wallet: a wrong old passphrase is refused and changes nothing":
    var w = newWallet(Mnemonic)
    let seed = w.seed
    check w.encryptWallet("p")
    check w.unlockWallet("p")
    check not w.isLocked

    check not w.changePassphrase("WRONG", "q")

    # The wallet is untouched: still unlocked, same seed, still under "p".
    check not w.isLocked
    check w.seed == seed
    w.lockWallet()
    check not w.unlockWallet("q")
    check w.unlockWallet("p")
    check w.seed == seed

  test "locked wallet: a wrong old passphrase is refused and the wallet stays locked":
    var w = newWallet(Mnemonic)
    check w.encryptWallet("p")
    check w.isLocked
    check not w.changePassphrase("WRONG", "q")
    check w.isLocked
    check not w.unlockWallet("q")
    check w.unlockWallet("p")

  test "control: unlocked wallet with the right old passphrase changes it and stays unlocked":
    var w = newWallet(Mnemonic)
    let seed = w.seed
    check w.encryptWallet("p")
    check w.unlockWallet("p")
    check w.changePassphrase("p", "q")
    check not w.isLocked
    check w.seed == seed
    w.lockWallet()
    check not w.unlockWallet("p")
    check w.unlockWallet("q")
    check w.seed == seed

  test "control: locked wallet with the right old passphrase changes it and re-locks":
    var w = newWallet(Mnemonic)
    let seed = w.seed
    check w.encryptWallet("p")
    check w.changePassphrase("p", "q")
    check w.isLocked
    check not w.unlockWallet("p")
    check w.unlockWallet("q")
    check w.seed == seed

suite "cffix walletpassphrasechange RPC on an unlocked wallet":
  var rpc: RpcServer
  var cs: ChainState
  var wm: WalletManager
  var tempDir: string
  let cparams = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_cffix_pwchange_", "_regtest")
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
    discard rpc.handleMethod("createwallet", %*["pw"])
    discard rpc.handleMethod("encryptwallet", %*["p"])
    discard rpc.handleMethod("walletpassphrase", %*["p", 600])

  teardown:
    if wm != nil: wm.close()
    cs.close()
    removeDir(tempDir)

  test "walletpassphrasechange with a wrong old passphrase errors and keeps the old one":
    var raised = false
    try:
      discard rpc.handleMethod("walletpassphrasechange", %*["WRONG", "q"])
    except RpcError:
      raised = true
    check raised

    discard rpc.handleMethod("walletlock", %*[])
    var newWorks = true
    try:
      discard rpc.handleMethod("walletpassphrase", %*["q", 600])
    except RpcError:
      newWorks = false
    check not newWorks
    discard rpc.handleMethod("walletlock", %*[])
    var oldWorks = true
    try:
      discard rpc.handleMethod("walletpassphrase", %*["p", 600])
    except RpcError:
      oldWorks = false
    check oldWorks

  test "control: walletpassphrasechange with the right old passphrase switches to the new one":
    check rpc.handleMethod("walletpassphrasechange", %*["p", "q"]).kind == JNull
    discard rpc.handleMethod("walletlock", %*[])
    var oldWorks = true
    try:
      discard rpc.handleMethod("walletpassphrase", %*["p", 600])
    except RpcError:
      oldWorks = false
    check not oldWorks
    discard rpc.handleMethod("walletpassphrase", %*["q", 600])
    check not wm.getWallet("pw").get().wallet.isLocked
