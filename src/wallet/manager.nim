## Multi-Wallet Manager
## Manages multiple wallets loaded simultaneously
## Reference: Bitcoin Core wallet/wallet.cpp (AddWallet, RemoveWallet, GetWallets)

import std/[os, tables, json, locks, options, strutils, times]
import ./wallet
import ./db_sqlite
import ./wallet_persist
import ../consensus/params
import ../storage/chainstate
import ../primitives/types

export wallet_persist.WalletLoadOutcome

type
  WalletManagerError* = object of CatchableError

  WalletCreateOptions* = object
    disablePrivateKeys*: bool    ## Create watch-only wallet
    blank*: bool                  ## Don't create default HD account
    passphrase*: string           ## Encrypt with passphrase
    avoidReuse*: bool            ## Track address reuse (not implemented)
    descriptors*: bool           ## Use descriptor-based wallet (always true for us)
    loadOnStartup*: bool         ## Auto-load on node startup

  LoadedWallet* = ref object
    wallet*: Wallet
    db*: WalletDb
    name*: string
    path*: string

  WalletManager* = ref object
    wallets: Table[string, LoadedWallet]
    walletsLock: Lock
    walletsDir: string           ## Base directory for wallets
    params: ConsensusParams
    chainState: ChainState
    settingsPath: string         ## Path to settings.json

# =============================================================================
# Wallet Manager Creation
# =============================================================================

proc newWalletManager*(dataDir: string, params: ConsensusParams,
                        chainState: ChainState = nil): WalletManager =
  ## Create a new wallet manager
  ## dataDir: base data directory (e.g., ~/.nimrod/mainnet)
  result = WalletManager(
    wallets: initTable[string, LoadedWallet](),
    walletsDir: dataDir / "wallets",
    params: params,
    chainState: chainState,
    settingsPath: dataDir / "settings.json"
  )
  initLock(result.walletsLock)

  # Create wallets directory if needed
  if not dirExists(result.walletsDir):
    createDir(result.walletsDir)

proc close*(wm: WalletManager) =
  ## Close all wallets and cleanup
  withLock wm.walletsLock:
    for name, lw in wm.wallets:
      lw.db.close()
    wm.wallets.clear()
  deinitLock(wm.walletsLock)

# =============================================================================
# Settings Persistence
# =============================================================================

proc loadSettings(wm: WalletManager): JsonNode =
  ## Load settings.json or return empty object
  if fileExists(wm.settingsPath):
    try:
      return parseJson(readFile(wm.settingsPath))
    except CatchableError:
      return newJObject()
  return newJObject()

proc saveSettings(wm: WalletManager, settings: JsonNode) =
  ## Save settings.json
  let dir = wm.settingsPath.parentDir()
  if not dirExists(dir):
    createDir(dir)
  writeFile(wm.settingsPath, pretty(settings))

proc addWalletSetting*(wm: WalletManager, walletName: string): bool =
  ## Add wallet to load_on_startup list in settings.json
  ## Returns true if successfully added
  try:
    var settings = wm.loadSettings()

    if not settings.hasKey("wallet"):
      settings["wallet"] = newJArray()

    # Check if already exists
    for w in settings["wallet"]:
      if w.kind == JString and w.getStr() == walletName:
        return true  # Already there

    settings["wallet"].add(%walletName)
    wm.saveSettings(settings)
    return true
  except CatchableError:
    return false

proc removeWalletSetting*(wm: WalletManager, walletName: string): bool =
  ## Remove wallet from load_on_startup list
  try:
    var settings = wm.loadSettings()

    if not settings.hasKey("wallet"):
      return true

    var newArray = newJArray()
    for w in settings["wallet"]:
      if w.kind != JString or w.getStr() != walletName:
        newArray.add(w)

    settings["wallet"] = newArray
    wm.saveSettings(settings)
    return true
  except CatchableError:
    return false

proc getWalletsToLoad*(wm: WalletManager): seq[string] =
  ## Get list of wallets to auto-load from settings.json
  result = @[]
  try:
    let settings = wm.loadSettings()
    if settings.hasKey("wallet") and settings["wallet"].kind == JArray:
      for w in settings["wallet"]:
        if w.kind == JString:
          result.add(w.getStr())
  except CatchableError:
    discard

# =============================================================================
# Wallet Path Resolution
# =============================================================================

proc getWalletPath(wm: WalletManager, name: string): string =
  ## Get full path for a wallet
  ## Empty name = default wallet
  ## Name without path = walletsDir/name/
  ## Absolute path = use as-is
  if name == "":
    result = wm.walletsDir  # Default wallet in wallets root
  elif name.isAbsolute:
    result = name
  else:
    result = wm.walletsDir / name

proc getWalletDbPath(wm: WalletManager, name: string): string =
  ## Get path to wallet database file
  let walletDir = wm.getWalletPath(name)
  walletDir / "wallet.db"

proc getWalletSnapshotPath(wm: WalletManager, name: string): string =
  ## Path to the crash-safe wallet ledger snapshot (wallet_state.dat).
  let walletDir = wm.getWalletPath(name)
  walletDir / CurrentWalletSnapFile

# =============================================================================
# Crash-safe snapshot persistence
# =============================================================================
# DATA-LOSS FIX (sweep wa0fq5wtk): the wallet's live ledger lives in RAM and
# was never written to disk. These helpers persist it atomically+durably on
# every mutation (see callers in rpc/server.nim) so a SIGKILL / OOM /
# power-loss can never lose credited coins or transaction history.

proc persistWallet*(wm: WalletManager, name: string): bool {.gcsafe.} =
  ## Atomically snapshot one loaded wallet to disk. Best-effort: a save
  ## failure is logged inside saveWalletSnapshot and returned as false; the
  ## caller must not crash on it.
  var lw: LoadedWallet
  withLock wm.walletsLock:
    if not wm.wallets.hasKey(name):
      return false
    lw = wm.wallets[name]
  if lw == nil or lw.wallet == nil:
    return false
  let snapPath = wm.getWalletSnapshotPath(lw.name)
  return saveWalletSnapshot(lw.wallet, snapPath)

proc persistAllWallets*(wm: WalletManager) {.gcsafe.} =
  ## Snapshot every loaded wallet. Called from the shutdown handler as a
  ## final flush AND usable as a periodic flush. Save-on-mutation already
  ## keeps disk current; this is the belt-and-suspenders pass.
  var names: seq[string]
  withLock wm.walletsLock:
    for name, _ in wm.wallets:
      names.add(name)
  for name in names:
    discard wm.persistWallet(name)

# =============================================================================
# Wallet Enumeration
# =============================================================================

proc listLoadedWallets*(wm: WalletManager): seq[string] {.gcsafe.} =
  ## Return names of all loaded wallets
  result = @[]
  withLock wm.walletsLock:
    for name, _ in wm.wallets:
      result.add(name)

proc getWalletCount*(wm: WalletManager): int {.gcsafe.} =
  ## Return number of loaded wallets
  withLock wm.walletsLock:
    result = wm.wallets.len

proc listWalletDir*(wm: WalletManager): seq[tuple[name: string, path: string]] =
  ## List all wallets available in the wallets directory
  result = @[]

  # Check for default wallet
  let defaultDbPath = wm.walletsDir / "wallet.db"
  if fileExists(defaultDbPath):
    result.add(("", wm.walletsDir))

  # Check subdirectories
  if dirExists(wm.walletsDir):
    for kind, path in walkDir(wm.walletsDir):
      if kind == pcDir:
        let dbPath = path / "wallet.db"
        if fileExists(dbPath):
          result.add((path.lastPathPart, path))

# =============================================================================
# Wallet Loading
# =============================================================================

proc getWallet*(wm: WalletManager, name: string): Option[LoadedWallet] {.gcsafe.} =
  ## Get a loaded wallet by name
  withLock wm.walletsLock:
    if wm.wallets.hasKey(name):
      return some(wm.wallets[name])
  return none(LoadedWallet)

proc getDefaultWallet*(wm: WalletManager): Option[LoadedWallet] {.gcsafe.} =
  ## Get the default wallet if exactly one wallet is loaded
  withLock wm.walletsLock:
    if wm.wallets.len == 1:
      for _, lw in wm.wallets:
        return some(lw)
  return none(LoadedWallet)

proc loadWallet*(wm: WalletManager, filename: string,
                  loadOnStartup: Option[bool] = none(bool)):
                  tuple[wallet: LoadedWallet, warnings: seq[string]] {.gcsafe.} =
  ## Load an existing wallet from disk
  ## Returns the loaded wallet and any warnings
  var warnings: seq[string] = @[]
  let name = filename

  withLock wm.walletsLock:
    # Check if already loaded
    if wm.wallets.hasKey(name):
      raise newException(WalletManagerError, "Wallet \"" & name & "\" is already loaded")

  # Check wallet exists
  let walletPath = wm.getWalletPath(name)
  let dbPath = wm.getWalletDbPath(name)

  if not fileExists(dbPath):
    raise newException(WalletManagerError, "Wallet file not found: " & dbPath)

  # Open database
  var db = newWalletDb(dbPath)
  db.open()

  # Check wallet metadata
  let metaOpt = db.getMeta()
  if metaOpt.isNone:
    db.close()
    raise newException(WalletManagerError, "Invalid wallet: no metadata")

  let meta = metaOpt.get()

  # Check network matches
  let expectedNetwork = if wm.params.bip34Height == 1: "regtest"
                        elif wm.params.defaultPort == 18333: "testnet"
                        else: "mainnet"

  if meta.network != expectedNetwork:
    warnings.add("Wallet network (" & meta.network & ") differs from node (" & expectedNetwork & ")")

  # Create wallet from database
  let mainnet = wm.params.defaultPort == 8333
  var wallet = newWalletFromDb(db, wm.params, mainnet, wm.chainState)

  # Restore the crash-safe ledger snapshot (UTXOs, history height, keypool
  # cursors, labels). Fault-tolerant: a missing/corrupt/partial file never
  # throws — the worst case leaves lastSyncedHeight = -1 so the startup
  # gap-rescan rebuilds the ledger from the chain. DATA-LOSS FIX wa0fq5wtk.
  let snapPath = wm.getWalletSnapshotPath(name)
  let outcome = loadWalletSnapshot(wallet, snapPath)
  case outcome
  of wlRecoveredBak:
    warnings.add("Wallet ledger recovered from backup snapshot (" &
                 snapPath & ".bak)")
  of wlCorruptKept:
    warnings.add("Wallet ledger snapshot unrecoverable; ledger will be " &
                 "rebuilt by rescan")
  else:
    discard

  let lw = LoadedWallet(
    wallet: wallet,
    db: db,
    name: name,
    path: walletPath
  )

  withLock wm.walletsLock:
    wm.wallets[name] = lw

  # Update load_on_startup setting
  if loadOnStartup.isSome:
    if loadOnStartup.get():
      if not wm.addWalletSetting(name):
        warnings.add("Failed to update load_on_startup setting")
    else:
      if not wm.removeWalletSetting(name):
        warnings.add("Failed to update load_on_startup setting")

  result = (lw, warnings)

proc unloadWallet*(wm: WalletManager, walletName: string,
                    loadOnStartup: Option[bool] = none(bool)): seq[string] {.gcsafe.} =
  ## Unload a wallet from memory
  ## Returns warnings
  var warnings: seq[string] = @[]
  var lw: LoadedWallet

  withLock wm.walletsLock:
    if not wm.wallets.hasKey(walletName):
      raise newException(WalletManagerError, "Wallet \"" & walletName & "\" is not loaded")

    lw = wm.wallets[walletName]
    wm.wallets.del(walletName)

  # Close database
  lw.db.close()

  # Update load_on_startup setting
  if loadOnStartup.isSome:
    if loadOnStartup.get():
      if not wm.addWalletSetting(walletName):
        warnings.add("Failed to update load_on_startup setting")
    else:
      if not wm.removeWalletSetting(walletName):
        warnings.add("Failed to update load_on_startup setting")

  return warnings

# =============================================================================
# Wallet Creation
# =============================================================================

proc createWallet*(wm: WalletManager, name: string,
                   options: WalletCreateOptions = WalletCreateOptions()):
                   tuple[wallet: LoadedWallet, warnings: seq[string]] =
  ## Create a new wallet
  ## Options:
  ##   - disablePrivateKeys: create watch-only wallet
  ##   - blank: don't create default HD account
  ##   - passphrase: encrypt wallet
  ##   - loadOnStartup: add to auto-load list
  var warnings: seq[string] = @[]

  withLock wm.walletsLock:
    # Check not already loaded
    if wm.wallets.hasKey(name):
      raise newException(WalletManagerError, "Wallet \"" & name & "\" already exists")

  # Create wallet directory
  let walletPath = wm.getWalletPath(name)
  let dbPath = wm.getWalletDbPath(name)

  if fileExists(dbPath):
    raise newException(WalletManagerError, "Wallet database already exists: " & dbPath)

  if not dirExists(walletPath):
    createDir(walletPath)

  # Determine network string
  let networkStr = if wm.params.bip34Height == 1: "regtest"
                   elif wm.params.defaultPort == 18333: "testnet"
                   else: "mainnet"

  let mainnet = wm.params.defaultPort == 8333

  # Create and open database
  var db = newWalletDb(dbPath)
  db.open()

  # Initialize metadata
  db.initMeta(networkStr, @[])

  var wallet: Wallet

  if options.disablePrivateKeys:
    # Create watch-only wallet (no keys)
    wallet = Wallet(
      params: wm.params,
      mainnet: mainnet,
      chainState: wm.chainState,
      accounts: @[],
      utxos: initTable[OutPoint, WalletUtxo](),
      labels: initTable[string, string](),
      isEncrypted: false,
      isLocked: false,
      lastSyncedHeight: -1
    )
  elif options.blank:
    # Create blank wallet - generate seed but no accounts
    let mnemonic = generateMnemonic(24)
    let seed = mnemonicToSeed(mnemonic)
    let masterKey = masterKeyFromSeed(seed)

    wallet = Wallet(
      seed: seed,
      masterKey: masterKey,
      params: wm.params,
      mainnet: mainnet,
      chainState: wm.chainState,
      accounts: @[],
      utxos: initTable[OutPoint, WalletUtxo](),
      labels: initTable[string, string](),
      isEncrypted: false,
      isLocked: false,
      lastSyncedHeight: -1
    )

    if options.passphrase != "":
      discard wallet.encryptWallet(options.passphrase)
      # Save encryption to db
      db.saveEncryption(wallet.encryptedSeed, wallet.encryptionSalt, wallet.encryptionRounds)
  else:
    # Create standard HD wallet with default accounts
    let mnemonic = generateMnemonic(24)
    wallet = newWallet(mnemonic, wm.params, mainnet, wm.chainState)

    if options.passphrase != "":
      discard wallet.encryptWallet(options.passphrase)
      db.saveEncryption(wallet.encryptedSeed, wallet.encryptionSalt, wallet.encryptionRounds)

    # Save accounts to database
    for acc in wallet.accounts:
      db.saveAccount(acc.purpose, acc.coinType, acc.accountIndex,
                     acc.nextExternal, acc.nextInternal, acc.gap)

  let lw = LoadedWallet(
    wallet: wallet,
    db: db,
    name: name,
    path: walletPath
  )

  withLock wm.walletsLock:
    wm.wallets[name] = lw

  # Update load_on_startup setting
  if options.loadOnStartup:
    if not wm.addWalletSetting(name):
      warnings.add("Failed to update load_on_startup setting")

  result = (lw, warnings)

# =============================================================================
# Auto-Load Wallets at Startup
# =============================================================================

proc loadWalletsAtStartup*(wm: WalletManager): seq[tuple[name: string, error: string]] =
  ## Load all wallets marked for load_on_startup
  ## Returns list of (name, error) for any that failed to load
  result = @[]

  let walletsToLoad = wm.getWalletsToLoad()

  # If no wallets configured but default wallet exists, load it
  if walletsToLoad.len == 0:
    let defaultDbPath = wm.getWalletDbPath("")
    if fileExists(defaultDbPath):
      try:
        discard wm.loadWallet("")
      except WalletManagerError as e:
        result.add(("", e.msg))
      except CatchableError as e:
        result.add(("", e.msg))
    return

  for walletName in walletsToLoad:
    try:
      discard wm.loadWallet(walletName)
    except WalletManagerError as e:
      result.add((walletName, e.msg))
    except CatchableError as e:
      result.add((walletName, e.msg))

# =============================================================================
# Startup rescan / reconcile to chain tip
# =============================================================================
# DATA-LOSS FIX (sweep wa0fq5wtk), requirement (4): after loading a wallet's
# snapshot, bring its UTXO ledger up to the current chain tip. This covers two
# gaps: (a) blocks that connected via the live P2P/IBD path while the node was
# previously running but were never fed to the wallet, and (b) blocks that
# connected AFTER the last persisted snapshot before an unclean exit. We scan
# only the gap [lastSyncedHeight+1 .. tip] — not the whole chain — using the
# same scanBlockForWallet recognition path the block-connect hook uses, then
# persist the reconciled ledger. Mirrors Bitcoin Core CWallet::AttachChain /
# ScanForWalletTransactions on load.

proc reconcileWalletToTip*(wm: WalletManager, lw: LoadedWallet): int32 =
  ## Scan the gap from the wallet's lastSyncedHeight to the chain tip into its
  ## ledger and persist. Returns the number of blocks scanned. Best-effort: a
  ## bad block never aborts the whole reconcile, and a nil chainState (e.g. in
  ## unit tests) is a no-op.
  if wm.chainState == nil or lw == nil or lw.wallet == nil:
    return 0
  var w = lw.wallet
  let tip = wm.chainState.bestHeight
  # lastSyncedHeight defaults to -1 (fresh / corrupt-recovered wallet) so the
  # first scanned height is 0 (genesis), a full rebuild.
  var h = w.lastSyncedHeight + 1
  if h < 0: h = 0
  var scanned: int32 = 0
  while h <= tip:
    let blkOpt = wm.chainState.db.getBlockByHeight(h)
    if blkOpt.isSome:
      try:
        w.scanBlockForWallet(blkOpt.get(), h)
        inc scanned
      except CatchableError:
        discard  # never let one bad block abort the reconcile
    inc h
  if scanned > 0:
    discard wm.persistWallet(lw.name)
  scanned

proc reconcileAllWalletsToTip*(wm: WalletManager) =
  ## Reconcile every loaded wallet to the chain tip. Called once at startup
  ## after loadWalletsAtStartup. Each wallet is independent; one failure does
  ## not block the others.
  var loaded: seq[LoadedWallet]
  withLock wm.walletsLock:
    for _, lw in wm.wallets:
      loaded.add(lw)
  for lw in loaded:
    try:
      discard wm.reconcileWalletToTip(lw)
    except CatchableError:
      discard
