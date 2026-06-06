## Wallet state snapshot persistence (wallet_state.dat)
##
## DATA-LOSS FIX (sweep wa0fq5wtk): the wallet's live in-memory ledger
## (utxos + txHistory + per-account keypool cursors + labels +
## lastSyncedHeight) is mutated at every block-connect scan and every
## state-changing RPC (getnewaddress / setlabel / sendtoaddress) but was
## NEVER written to disk — not on mutation, not even at clean shutdown
## (db_sqlite's saveUtxo/markUtxoSpent/updateScanHeight exist but are dead
## code, never called). A SIGKILL / OOM / power-loss therefore lost every
## credited coin and the entire transaction history.
##
## This module persists the wallet to a flat snapshot file using the SAME
## crash-safe write discipline the node's mempool dump already uses
## (mempool/persist.nim::dumpMempool): build the full payload in memory,
## write it to a temp path, fsync the file, atomically rename over the real
## path, then fsync the containing directory. A crash at any point leaves
## EITHER the old complete file OR the new complete file — never a torn
## write. Mirrors Bitcoin Core's wallet/walletdb.cpp + wallet/wallet.cpp,
## which flush the wallet on every mutation (CWalletDB batch writes /
## WriteTx / WriteBestBlock).
##
## File format (all little-endian; CompactSize for counts) — versioned so
## the format can evolve without crashing an older/newer node on load:
##   uint32  magic            = WalletSnapMagic
##   uint32  version          = WalletSnapVersion
##   int32   lastSyncedHeight -- highest height reflected in the ledger
##   compactsize nUtxos
##     for each UTXO:
##       OutPoint (32B txid + uint32 vout)
##       TxOut    (int64 value + varbytes scriptPubKey)
##       int32  height
##       varbytes keyPath (utf-8)
##       uint8  isInternal
##       uint8  isCoinbase
##   compactsize nLabels
##     for each label: varbytes address || varbytes label
##   compactsize nAccountCursors
##     for each: uint32 purpose, uint32 coinType, uint32 accountIndex,
##               int64 nextExternal, int64 nextInternal, int64 gap
##   sha256(payload-up-to-here)   -- 32B integrity trailer
##
## The trailing hash lets the loader reject a truncated / corrupted tail
## (the classic "partial write" failure) and fall back to the prior good
## copy instead of importing garbage.

import std/[os, options, tables]
import chronicles
import ../primitives/serialize
import ../crypto/hashing
import ./wallet

const
  WalletSnapMagic*   = 0x57414C54'u32   ## "WALT"
  WalletSnapVersion* = 1'u32
  CurrentWalletSnapFile* = "wallet_state.dat"

type
  WalletPersistError* = object of CatchableError

# ---------------------------------------------------------------------------
# Low-level durable file write — identical discipline to dumpMempool.
# ---------------------------------------------------------------------------

when defined(posix):
  proc c_fsync(fd: cint): cint {.importc: "fsync", header: "<unistd.h>".}
  proc c_open(path: cstring, flags: cint): cint {.importc: "open", header: "<fcntl.h>".}
  proc c_close(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
  const O_RDONLY = cint(0)

proc fsyncFile(f: File) =
  ## Best-effort fsync of an open file handle. Failure is logged, not fatal —
  ## a missing fsync degrades durability but does not corrupt the snapshot.
  when defined(posix):
    try:
      let fd = cint(getOsFileHandle(f))
      if c_fsync(fd) != 0:
        debug "wallet snapshot: fsync(file) failed (non-fatal)"
    except CatchableError:
      discard

proc fsyncDir(dir: string) =
  ## fsync the directory entry so the atomic rename itself is durable.
  ## (A rename can be lost across power-failure if the dir is not synced.)
  ## POSIX-only; a no-op elsewhere.
  when defined(posix):
    if dir.len == 0: return
    try:
      let fd = c_open(dir.cstring, O_RDONLY)
      if fd >= 0:
        discard c_fsync(fd)
        discard c_close(fd)
    except CatchableError:
      discard

# ---------------------------------------------------------------------------
# Encode / decode
# ---------------------------------------------------------------------------

proc encodeWalletSnapshot*(wallet: Wallet): seq[byte] =
  ## Serialize the wallet's recoverable in-memory ledger to the snapshot
  ## wire format (see module header). Pure function — used by both the file
  ## writer and the round-trip tests.
  var w = BinaryWriter()
  w.writeUint32LE(WalletSnapMagic)
  w.writeUint32LE(WalletSnapVersion)
  w.writeInt32LE(wallet.lastSyncedHeight)

  # UTXOs
  w.writeCompactSize(uint64(wallet.utxos.len))
  for _, u in wallet.utxos:
    w.writeOutPoint(u.outpoint)
    w.writeTxOut(u.output)
    w.writeInt32LE(u.height)
    w.writeVarBytes(cast[seq[byte]](u.keyPath))
    w.writeUint8(if u.isInternal: 1'u8 else: 0'u8)
    w.writeUint8(if u.isCoinbase: 1'u8 else: 0'u8)

  # Labels
  w.writeCompactSize(uint64(wallet.labels.len))
  for address, label in wallet.labels:
    w.writeVarBytes(cast[seq[byte]](address))
    w.writeVarBytes(cast[seq[byte]](label))

  # Account keypool cursors (so getnewaddress never reissues an address that
  # was already handed out before the crash — gap-limit safety).
  w.writeCompactSize(uint64(wallet.accounts.len))
  for acc in wallet.accounts:
    w.writeUint32LE(acc.purpose)
    w.writeUint32LE(acc.coinType)
    w.writeUint32LE(acc.accountIndex)
    w.writeInt64LE(int64(acc.nextExternal))
    w.writeInt64LE(int64(acc.nextInternal))
    w.writeInt64LE(int64(acc.gap))

  # Integrity trailer: sha256 over everything written so far.
  let digest = sha256(w.data)
  w.writeBytes(digest)
  w.data

type
  DecodedSnapshot* = object
    lastSyncedHeight*: int32
    utxos*: seq[WalletUtxo]
    labels*: seq[tuple[address, label: string]]
    accountCursors*: seq[tuple[purpose, coinType, accountIndex: uint32,
                               nextExternal, nextInternal, gap: int]]

proc decodeWalletSnapshot*(raw: seq[byte]): Option[DecodedSnapshot] =
  ## Parse a wallet snapshot. Returns none on ANY structural problem
  ## (bad magic, unknown version, truncation, bad integrity hash) so the
  ## caller can fall back to a backup rather than load partial state.
  if raw.len < 8 + 32:
    return none(DecodedSnapshot)

  # Verify the integrity trailer first: hash of everything but the last 32B.
  let bodyLen = raw.len - 32
  let body = raw[0 ..< bodyLen]
  let expected = sha256(body)
  for i in 0 ..< 32:
    if raw[bodyLen + i] != expected[i]:
      error "wallet snapshot: integrity hash mismatch (truncated/corrupt)"
      return none(DecodedSnapshot)

  var r = BinaryReader(data: raw, pos: 0)
  try:
    let magic = r.readUint32LE()
    if magic != WalletSnapMagic:
      error "wallet snapshot: bad magic", magic = magic
      return none(DecodedSnapshot)
    let version = r.readUint32LE()
    if version != WalletSnapVersion:
      error "wallet snapshot: unsupported version", version = version
      return none(DecodedSnapshot)

    var snap = DecodedSnapshot()
    snap.lastSyncedHeight = r.readInt32LE()

    let nUtxos = r.readCompactSize()
    for _ in 0 ..< int(nUtxos):
      var u = WalletUtxo()
      u.outpoint = r.readOutPoint()
      u.output = r.readTxOut()
      u.height = r.readInt32LE()
      u.keyPath = cast[string](r.readVarBytes())
      u.isInternal = r.readUint8() != 0
      u.isCoinbase = r.readUint8() != 0
      snap.utxos.add(u)

    let nLabels = r.readCompactSize()
    for _ in 0 ..< int(nLabels):
      let address = cast[string](r.readVarBytes())
      let label = cast[string](r.readVarBytes())
      snap.labels.add((address, label))

    let nAcc = r.readCompactSize()
    for _ in 0 ..< int(nAcc):
      let purpose = r.readUint32LE()
      let coinType = r.readUint32LE()
      let accountIndex = r.readUint32LE()
      let nextExternal = int(r.readInt64LE())
      let nextInternal = int(r.readInt64LE())
      let gap = int(r.readInt64LE())
      snap.accountCursors.add((purpose, coinType, accountIndex,
                               nextExternal, nextInternal, gap))

    some(snap)
  except CatchableError as e:
    error "wallet snapshot: parse error", error = e.msg
    return none(DecodedSnapshot)

# ---------------------------------------------------------------------------
# Save (atomic + durable) — mirrors mempool/persist.nim::dumpMempool.
# ---------------------------------------------------------------------------

proc saveWalletSnapshot*(wallet: Wallet, snapPath: string): bool =
  ## Write the wallet ledger to `snapPath` crash-safely: temp file -> fsync
  ## -> atomic rename -> fsync(dir). Returns true on success, false on any
  ## I/O failure (caller logs; a failed save must never crash the node).
  if wallet == nil:
    return false
  let payload = encodeWalletSnapshot(wallet)
  let tmpPath = snapPath & ".tmp"
  try:
    block writeFile:
      let f = open(tmpPath, fmWrite)
      try:
        if payload.len > 0:
          discard f.writeBuffer(addr payload[0], payload.len)
        f.flushFile()
        fsyncFile(f)
      finally:
        f.close()
    moveFile(tmpPath, snapPath)
    fsyncDir(snapPath.parentDir())
    return true
  except CatchableError as e:
    error "saveWalletSnapshot failed", path = snapPath, error = e.msg
    if fileExists(tmpPath):
      try: removeFile(tmpPath) except CatchableError: discard
    return false

# ---------------------------------------------------------------------------
# Load (fault-tolerant) — never crashes node startup.
# ---------------------------------------------------------------------------

type
  WalletLoadOutcome* = enum
    wlNoFile        ## no snapshot existed (fresh wallet)
    wlLoaded        ## loaded cleanly
    wlRecoveredBak  ## main file was bad; loaded the .bak instead
    wlCorruptKept   ## both copies bad; nothing loaded, bad file preserved

proc applySnapshot(wallet: var Wallet, snap: DecodedSnapshot) =
  ## Merge a decoded snapshot into the wallet's in-memory ledger. UTXOs are
  ## keyed by outpoint (set semantics), so this is safe to call before a
  ## gap-rescan. Account cursors only ever advance (never rewind) so a stale
  ## backup can't re-hand-out an already-issued address.
  wallet.lastSyncedHeight = snap.lastSyncedHeight
  for u in snap.utxos:
    wallet.utxos[u.outpoint] = u
  for (address, label) in snap.labels:
    if label.len > 0:
      wallet.labels[address] = label
  for c in snap.accountCursors:
    for ai in 0 ..< wallet.accounts.len:
      if wallet.accounts[ai].purpose == c.purpose and
         wallet.accounts[ai].coinType == c.coinType and
         wallet.accounts[ai].accountIndex == c.accountIndex:
        if c.nextExternal > wallet.accounts[ai].nextExternal:
          wallet.accounts[ai].nextExternal = c.nextExternal
        if c.nextInternal > wallet.accounts[ai].nextInternal:
          wallet.accounts[ai].nextInternal = c.nextInternal
        break

proc tryDecodeFile(path: string): Option[DecodedSnapshot] =
  ## Read + decode a single snapshot file. None on missing/unreadable/corrupt.
  if not fileExists(path):
    return none(DecodedSnapshot)
  var raw: seq[byte]
  try:
    let f = open(path, fmRead)
    try:
      let sz = f.getFileSize().int
      if sz <= 0:
        return none(DecodedSnapshot)
      raw = newSeq[byte](sz)
      let n = f.readBuffer(addr raw[0], sz)
      if n != sz:
        return none(DecodedSnapshot)
    finally:
      f.close()
  except CatchableError as e:
    error "wallet snapshot: read failed", path = path, error = e.msg
    return none(DecodedSnapshot)
  decodeWalletSnapshot(raw)

proc loadWalletSnapshot*(wallet: var Wallet, snapPath: string):
    WalletLoadOutcome =
  ## Restore a wallet's ledger from its snapshot, tolerating a missing,
  ## corrupt, or partially-written file WITHOUT crashing. Recovery ladder:
  ##   1. main file decodes      -> apply it, refresh the .bak from it
  ##   2. main bad, .bak decodes -> apply the .bak (and log loudly)
  ##   3. both bad               -> rename the corrupt main to .corrupt-<n>,
  ##                                load nothing; a startup rescan rebuilds it
  ## Never raises — wallet bookkeeping must not abort node startup.
  if wallet == nil:
    return wlNoFile
  let bakPath = snapPath & ".bak"

  let mainSnap = tryDecodeFile(snapPath)
  if mainSnap.isSome:
    wallet.applySnapshot(mainSnap.get())
    # Refresh the backup from the known-good main copy (best-effort).
    if fileExists(snapPath):
      try: copyFile(snapPath, bakPath) except CatchableError: discard
    info "loaded wallet snapshot", path = snapPath,
         utxos = wallet.utxos.len, lastSyncedHeight = wallet.lastSyncedHeight
    return wlLoaded

  if not fileExists(snapPath):
    return wlNoFile

  # Main file present but unparsable — try the backup.
  warn "wallet snapshot corrupt; attempting backup recovery", path = snapPath
  let bakSnap = tryDecodeFile(bakPath)
  if bakSnap.isSome:
    wallet.applySnapshot(bakSnap.get())
    warn "recovered wallet from backup snapshot", path = bakPath,
         utxos = wallet.utxos.len, lastSyncedHeight = wallet.lastSyncedHeight
    return wlRecoveredBak

  # Both bad: preserve the corrupt file for forensics, load nothing. A
  # startup gap-rescan (lastSyncedHeight stays at its constructor default
  # of -1) will rebuild the ledger from the chain.
  var idx = 0
  while fileExists(snapPath & ".corrupt-" & $idx):
    inc idx
  try:
    moveFile(snapPath, snapPath & ".corrupt-" & $idx)
    error "wallet snapshot unrecoverable; preserved + will rescan",
          preserved = snapPath & ".corrupt-" & $idx
  except CatchableError:
    discard
  wlCorruptKept
