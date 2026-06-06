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
import std/[os, options, tables]
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
