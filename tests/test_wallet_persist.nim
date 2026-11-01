## Wallet snapshot persistence tests (DATA-LOSS FIX wa0fq5wtk)
##
## Proves the teeth of the fix:
##   1. encode/decode round-trips the full ledger byte-faithfully.
##   2. A mutation persisted to disk SURVIVES a simulated unclean restart
##      (the in-memory wallet is discarded without a clean shutdown; a fresh
##      wallet reloads the snapshot and finds the state intact).
##   3. A truncated / partially-written file does NOT crash the loader and
##      falls back to the backup (.bak) — recovers the prior good ledger.
##   4. A both-copies-corrupt file does not crash; the corrupt file is
##      preserved and the wallet is left empty for a rescan.
##   5. The atomic writer never leaves a partial primary file (temp+rename).

import unittest2
import std/[os, options, tables, strutils]
import ../src/wallet/[wallet, wallet_persist]
import ../src/primitives/types
import ../src/consensus/params

const TestDir = "/tmp/nimrod_wallet_persist_test"

proc cleanupDir() =
  if dirExists(TestDir):
    removeDir(TestDir)
  createDir(TestDir)

const TestMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon " &
  "abandon abandon abandon about"

proc makeUtxo(seed: byte; value: int64; height: int32;
              coinbase = false): tuple[op: OutPoint, output: TxOut] =
  var t: array[32, byte]
  t[0] = seed
  (OutPoint(txid: TxId(t), vout: uint32(seed)),
   TxOut(value: Satoshi(value), scriptPubKey: @[0x00'u8, 0x14'u8, seed]))

suite "wallet snapshot — encode/decode round trip":
  test "empty wallet round-trips":
    var w = newWallet(TestMnemonic, params = regtestParams())
    let raw = encodeWalletSnapshot(w)
    let dec = decodeWalletSnapshot(raw)
    check dec.isSome
    check dec.get().utxos.len == 0
    check dec.get().labels.len == 0

  test "utxos + labels + height + keypool cursors round-trip":
    var w = newWallet(TestMnemonic, params = regtestParams())
    let (op1, o1) = makeUtxo(1, 50_0000_0000, 10, coinbase = true)
    let (op2, o2) = makeUtxo(2, 12345, 11)
    w.addUtxo(op1, o1, 10, "m/84'/1'/0'/0/0", false, true)
    w.addUtxo(op2, o2, 11, "m/84'/1'/0'/1/3", true, false)
    w.setLabel("bcrt1qexampleaddr", "savings")
    w.lastSyncedHeight = 11

    let dec = decodeWalletSnapshot(encodeWalletSnapshot(w))
    check dec.isSome
    let s = dec.get()
    check s.lastSyncedHeight == 11
    check s.utxos.len == 2
    check s.labels.len == 1
    check s.labels[0].address == "bcrt1qexampleaddr"
    check s.labels[0].label == "savings"
    # The two UTXOs are present (order is table-iteration dependent).
    var total: int64 = 0
    var sawCoinbase = false
    for u in s.utxos:
      total += int64(u.output.value)
      if u.isCoinbase: sawCoinbase = true
    check total == 50_0000_0000 + 12345
    check sawCoinbase

suite "wallet snapshot — durable save + reload across an unclean restart":
  test "mutation persisted to disk survives discard+reload":
    cleanupDir()
    let snapPath = TestDir / CurrentWalletSnapFile

    # --- session 1: mutate + persist, then "crash" (just drop the ref) ---
    block:
      var w = newWallet(TestMnemonic, params = regtestParams())
      let (op, o) = makeUtxo(7, 99_000, 42)
      w.addUtxo(op, o, 42, "m/84'/1'/0'/0/5", false, false)
      w.setLabel("bcrt1qpersisted", "rent")
      w.lastSyncedHeight = 42
      check saveWalletSnapshot(w, snapPath)
    check fileExists(snapPath)
    # No clean shutdown happened — the only durable state is the snapshot file.

    # --- session 2: fresh wallet (empty ledger) reloads the snapshot ---
    var w2 = newWallet(TestMnemonic, params = regtestParams())
    check w2.utxos.len == 0          # genuinely empty before load
    check w2.lastSyncedHeight == -1
    let outcome = loadWalletSnapshot(w2, snapPath)
    check outcome == wlLoaded
    check w2.utxos.len == 1
    check int64(w2.getBalance()) == 99_000
    check w2.getLabel("bcrt1qpersisted") == "rent"
    check w2.lastSyncedHeight == 42
    # A successful load refreshes the backup copy.
    check fileExists(snapPath & ".bak")

suite "wallet snapshot — fault tolerance (corrupt / partial files)":
  test "missing file is not an error":
    cleanupDir()
    var w = newWallet(TestMnemonic, params = regtestParams())
    let outcome = loadWalletSnapshot(w, TestDir / "does_not_exist.dat")
    check outcome == wlNoFile
    check w.utxos.len == 0  # did not crash, nothing loaded

  test "truncated primary file recovers from backup, no crash":
    cleanupDir()
    let snapPath = TestDir / CurrentWalletSnapFile

    # Write a good snapshot (this also seeds the .bak when later loaded).
    var w = newWallet(TestMnemonic, params = regtestParams())
    let (op, o) = makeUtxo(9, 5_000, 100)
    w.addUtxo(op, o, 100, "m/84'/1'/0'/0/0", false, false)
    w.lastSyncedHeight = 100
    check saveWalletSnapshot(w, snapPath)
    # Establish a known-good .bak by loading once (which copies main -> .bak).
    var wseed = newWallet(TestMnemonic, params = regtestParams())
    check loadWalletSnapshot(wseed, snapPath) == wlLoaded
    check fileExists(snapPath & ".bak")

    # Now SIMULATE A PARTIAL WRITE: truncate the primary file to half its
    # bytes (a torn write the integrity-hash trailer will reject).
    let full = readFile(snapPath)
    writeFile(snapPath, full[0 ..< (full.len div 2)])

    # Loading must NOT crash and must recover the prior ledger from the .bak.
    var w2 = newWallet(TestMnemonic, params = regtestParams())
    let outcome = loadWalletSnapshot(w2, snapPath)
    check outcome == wlRecoveredBak
    check w2.utxos.len == 1
    check int64(w2.getBalance()) == 5_000
    check w2.lastSyncedHeight == 100

  test "single-byte-flip in the body is rejected by the integrity hash":
    cleanupDir()
    let snapPath = TestDir / CurrentWalletSnapFile
    var w = newWallet(TestMnemonic, params = regtestParams())
    let (op, o) = makeUtxo(3, 777, 5)
    w.addUtxo(op, o, 5, "m/84'/1'/0'/0/0", false, false)
    check saveWalletSnapshot(w, snapPath)

    var raw = cast[seq[byte]](readFile(snapPath))
    # Flip a byte well inside the payload (after the header).
    raw[16] = raw[16] xor 0xFF'u8
    check decodeWalletSnapshot(raw).isNone

  test "both copies corrupt: no crash, corrupt file preserved, ledger empty":
    cleanupDir()
    let snapPath = TestDir / CurrentWalletSnapFile
    # Garbage primary, no usable backup.
    writeFile(snapPath, "this is not a wallet snapshot at all")
    writeFile(snapPath & ".bak", "garbage backup too")

    var w = newWallet(TestMnemonic, params = regtestParams())
    let outcome = loadWalletSnapshot(w, snapPath)
    check outcome == wlCorruptKept
    check w.utxos.len == 0                 # nothing loaded, no crash
    check w.lastSyncedHeight == -1         # stays at "never synced" -> rescan
    check not fileExists(snapPath)         # corrupt main moved aside
    check fileExists(snapPath & ".corrupt-0")

  test "atomic writer leaves no .tmp behind and primary is complete":
    cleanupDir()
    let snapPath = TestDir / CurrentWalletSnapFile
    var w = newWallet(TestMnemonic, params = regtestParams())
    let (op, o) = makeUtxo(4, 4242, 8)
    w.addUtxo(op, o, 8, "m/84'/1'/0'/0/0", false, false)
    check saveWalletSnapshot(w, snapPath)
    check not fileExists(snapPath & ".tmp")  # temp was renamed away
    # The committed primary is fully parseable (no partial write).
    var w2 = newWallet(TestMnemonic, params = regtestParams())
    check loadWalletSnapshot(w2, snapPath) == wlLoaded
    check int64(w2.getBalance()) == 4242

# ---------------------------------------------------------------------------
# H8 (security audit 2026-10-31): the HD seed and the accounts must survive a
# close + reopen of the wallet database. Before the fix createWallet never
# wrote the seed of an unencrypted wallet and newWalletFromDb restored neither
# the seed, the master key nor the accounts, so after one restart
# getnewaddress / sendtoaddress failed with "cannot derive hardened child from
# public key" and the funded address was no longer ismine.
# ---------------------------------------------------------------------------

import ../src/wallet/manager
import ../src/crypto/address
import ../src/script/interpreter

const ReopenDir = "/tmp/nimrod_wallet_seed_reopen_test"

proc freshReopenDir(): string =
  ## Per-test datadir under the shared scratch root (removed by the test).
  if dirExists(ReopenDir):
    removeDir(ReopenDir)
  createDir(ReopenDir)
  ReopenDir

proc isMine(w: Wallet, addrStr: string): bool =
  w.findKeyForScript(scriptPubKeyForAddress(decodeAddress(addrStr))).isSome

proc signsFor(w: Wallet, addrStr: string): bool =
  ## Build a one-input spend of a synthetic coin paying `addrStr`, sign it
  ## with the wallet, and run the result through the script interpreter.
  let spk = scriptPubKeyForAddress(decodeAddress(addrStr))
  var prev: array[32, byte]
  for i in 0 ..< 32: prev[i] = 0x5a'u8
  let amount = Satoshi(10_0000_0000)
  let utxo = WalletUtxo(
    outpoint: OutPoint(txid: TxId(prev), vout: 0),
    output: TxOut(value: amount, scriptPubKey: spk),
    height: 1, keyPath: "", isInternal: false, isCoinbase: false)
  var tx = Transaction(
    version: 2'i32,
    inputs: @[TxIn(prevOut: utxo.outpoint, scriptSig: @[],
                   sequence: 0xffffffff'u32)],
    outputs: @[TxOut(value: amount - Satoshi(1000), scriptPubKey: spk)],
    witnesses: @[ @[] ],
    lockTime: 0'u32)
  if not w.signTransaction(tx, @[utxo]):
    return false
  verifyScript(
    scriptSig = tx.inputs[0].scriptSig, scriptPubKey = spk, tx = tx,
    inputIndex = 0, amount = amount,
    flags = {sfP2SH, sfDERSig, sfStrictEnc, sfWitness, sfNullDummy, sfLowS,
             sfWitnessPubkeyType, sfMinimalIf, sfNullFail},
    witness = tx.witnesses[0])

suite "H8: HD seed and accounts survive a wallet close + reopen":
  test "unencrypted wallet: address stays ismine, signable, cursor advances":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("w")
    var w = lw.wallet
    let a = w.getNewAddressStr()
    # What the second getnewaddress must return if the cursor survives.
    let expectedNext = w.accounts[0].externalKeys[1].addressStr
    check w.isMine(a)
    check w.signsFor(a)
    # The RPC layer persists the target wallet after every getnewaddress.
    check wm.persistWallet("w")
    wm.close()

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("w")
    var w2 = lw2.wallet
    check w2.isMine(a)
    check w2.signsFor(a)
    let b = w2.getNewAddressStr()
    check b == expectedNext
    check b != a
    wm2.close()
    removeDir(dir)

  test "encrypted wallet: accounts and cursor come back after unlock":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("e",
      WalletCreateOptions(passphrase: "correct horse"))
    var w = lw.wallet
    check w.unlockWallet("correct horse")
    let a = w.getNewAddressStr()
    let expectedNext = w.accounts[0].externalKeys[1].addressStr
    check wm.persistWallet("e")
    wm.close()

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("e")
    var w2 = lw2.wallet
    check w2.isEncrypted
    check w2.isLocked
    # Negative control: a wrong passphrase must not unlock the reopened wallet.
    check not w2.unlockWallet("wrong horse")
    check w2.unlockWallet("correct horse")
    check w2.isMine(a)
    check w2.signsFor(a)
    check w2.getNewAddressStr() == expectedNext
    wm2.close()
    removeDir(dir)

  test "encryptwallet after create: reopen is encrypted, no plaintext seed":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("x")
    var w = lw.wallet
    let a = w.getNewAddressStr()
    let plainSeed = w.seed
    check w.encryptWallet("pw")
    check wm.persistKeyMaterial("x")
    check wm.persistWallet("x")
    wm.close()

    # The 64 seed bytes must not appear anywhere in the database file.
    let raw = readFile(dir / "wallets" / "x" / "wallet.db")
    var seedStr = newString(64)
    for i in 0 ..< 64: seedStr[i] = char(plainSeed[i])
    check raw.find(seedStr) < 0

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("x")
    var w2 = lw2.wallet
    check w2.isEncrypted
    check w2.isLocked
    check w2.unlockWallet("pw")
    check w2.isMine(a)
    check w2.signsFor(a)
    wm2.close()
    removeDir(dir)

  test "sethdseed: the new seed is what a reopen restores":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("s")
    var w = lw.wallet
    var seed = newSeq[byte](32)
    for i in 0 ..< 32: seed[i] = byte(i + 1)
    w.setHdSeed(seed)
    check wm.persistKeyMaterial("s")
    let a = w.getNewAddressStr()
    check wm.persistWallet("s")
    wm.close()

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("s")
    var w2 = lw2.wallet
    check w2.isMine(a)
    check w2.signsFor(a)
    # Same 32-byte seed => same BIP-32 master key as before the reopen.
    check w2.masterKey.key == masterKeyFromSeedRaw(seed).key
    wm2.close()
    removeDir(dir)

  test "an account created after createwallet (legacy type) survives":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("l")
    var w = lw.wallet
    let legacy = w.getNewAddressByTypeName("legacy")
    check wm.persistWallet("l")
    wm.close()

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("l")
    var w2 = lw2.wallet
    check w2.isMine(legacy)
    check w2.signsFor(legacy)
    check w2.getNewAddressByTypeName("legacy") != legacy
    wm2.close()
    removeDir(dir)

  test "sethdseed on an unlocked encrypted wallet survives lock and reopen":
    let dir = freshReopenDir()
    var wm = newWalletManager(dir, regtestParams())
    let (lw, _) = wm.createWallet("se",
      WalletCreateOptions(passphrase: "pw"))
    var w = lw.wallet
    check w.unlockWallet("pw")
    var seed = newSeq[byte](32)
    for i in 0 ..< 32: seed[i] = byte(0xa0 + i)
    w.setHdSeed(seed)
    check wm.persistKeyMaterial("se")
    let a = w.getNewAddressStr()
    check wm.persistWallet("se")
    # In-session lock + unlock must bring back the NEW seed, not the old one.
    w.lockWallet()
    check w.unlockWallet("pw")
    check w.masterKey.key == masterKeyFromSeedRaw(seed).key
    wm.close()

    var wm2 = newWalletManager(dir, regtestParams())
    let (lw2, _) = wm2.loadWallet("se")
    var w2 = lw2.wallet
    check w2.unlockWallet("pw")
    check w2.masterKey.key == masterKeyFromSeedRaw(seed).key
    check w2.isMine(a)
    check w2.signsFor(a)
    wm2.close()
    removeDir(dir)
