## mempool.dat persistence
##
## Byte-for-byte compatible with Bitcoin Core's mempool_persist.cpp:
##   uint64 version              -- 1 = no XOR (legacy), 2 = XOR-obfuscated
##   if version == 2:
##     varbytes obfuscation_key  -- compactsize(8) + 8 raw key bytes
##                                 (after this point all bytes are XOR'd
##                                  with key[i mod 8] from the start of
##                                  the obfuscated section)
##   uint64 count                -- number of transactions
##   for each tx:
##     CTransaction (with witness)
##     int64 nTime                -- seconds since epoch when added
##     int64 nFeeDelta            -- prioritisation delta
##   map<Txid, CAmount> mapDeltas -- compactsize entries, each (32B txid + int64)
##   set<Txid> unbroadcast        -- compactsize entries, each 32B
##
## We only export version=2 (matches Core 28.0+ default).

import std/[os, options, times, tables, strutils, sets, sysrand]
import chronicles
import ../primitives/[types, serialize]
import ../crypto/secp256k1
import ./mempool

const
  MempoolDumpVersionNoXor* = 1'u64
  MempoolDumpVersion*      = 2'u64
  ObfuscationKeySize       = 8
  CurrentMempoolDumpFile*  = "mempool.dat"

type
  MempoolPersistError* = object of CatchableError

# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------

proc xorInPlace(buf: var seq[byte], key: array[ObfuscationKeySize, byte],
                startOffset: int = 0) =
  ## XOR `buf` with the obfuscation key, treating byte index `i` as cycling
  ## through `key[i mod 8]`. `startOffset` is the byte offset within the
  ## obfuscated *file region* at which `buf` begins (so cross-call rotation
  ## stays aligned).
  if buf.len == 0: return
  for i in 0 ..< buf.len:
    buf[i] = buf[i] xor key[(startOffset + i) mod ObfuscationKeySize]

proc generateObfuscationKey(): array[ObfuscationKeySize, byte] =
  ## Random 8-byte XOR key. Matches Core's FastRandomContext.randbytes<8>.
  var rnd: array[ObfuscationKeySize, byte]
  if not urandom(rnd):
    # Deterministic fallback — tests are fine without entropy.
    let now = uint64(getTime().toUnix())
    for i in 0 ..< ObfuscationKeySize:
      rnd[i] = byte((now shr (i * 8)) and 0xff)
  rnd

# ---------------------------------------------------------------------------
# Writers (build payload buffer; XOR is applied after `version` is written)
# ---------------------------------------------------------------------------

proc writeKeyVarBytes(w: var BinaryWriter, key: array[ObfuscationKeySize, byte]) =
  ## Bitcoin Core serialises Obfuscation as `std::vector<std::byte>` —
  ## compactsize(KEY_SIZE) followed by the raw key bytes.
  w.writeCompactSize(uint64(ObfuscationKeySize))
  for b in key: w.writeUint8(b)

proc readKeyVarBytes(r: var BinaryReader): array[ObfuscationKeySize, byte] =
  let n = r.readCompactSize()
  if n != ObfuscationKeySize:
    raise newException(MempoolPersistError,
      "obfuscation key size " & $n & " != " & $ObfuscationKeySize)
  for i in 0 ..< ObfuscationKeySize:
    result[i] = r.readUint8()

# ---------------------------------------------------------------------------
# DumpMempool — writes data to .new, then renames atomically.
# ---------------------------------------------------------------------------

proc dumpMempool*(mp: Mempool, dumpPath: string,
                  useV2Xor: bool = true): bool =
  ## Snapshot the mempool to `dumpPath` in Bitcoin Core mempool.dat format.
  ## Returns true on success, false on any I/O failure (caller should log).
  if mp == nil:
    return false

  # Snapshot transactions + metadata under no lock (nimrod's mempool is
  # single-threaded relative to this call site — same assumption as
  # mempool.expire and mempool.removeForBlock). If we ever multithread the
  # mempool, this needs the same lock.
  let snapshot = block:
    var entries: seq[MempoolEntry]
    for _, e in mp.entries:
      entries.add(e)
    entries

  # Build the obfuscated section (count + txs + mapDeltas + unbroadcast)
  # into one buffer first, then XOR it as a single span.
  #
  # PrioritiseTransaction deltas: Core (node/mempool_persist.cpp:157-203)
  # snapshots the full mapDeltas, writes each in-mempool tx's delta inline as
  # its nFeeDelta AND erases that txid from a local copy, then serialises the
  # remaining (not-in-mempool) deltas as the trailing mapDeltas map. We mirror
  # that exactly so the two delta sources never double-count on reload.
  var remainingDeltas = mp.feeDeltas  # copy
  var w = BinaryWriter()
  w.writeUint64LE(uint64(snapshot.len))
  for entry in snapshot:
    w.writeTransaction(entry.tx, includeWitness = true)
    w.writeInt64LE(entry.timeAdded.toUnix())
    let delta = mp.feeDeltas.getOrDefault(entry.txid, 0'i64)
    w.writeInt64LE(delta)
    remainingDeltas.del(entry.txid)
  # mapDeltas: only the deltas for txs NOT in the mempool (Core erases the
  # in-mempool ones above). std::map<Txid, CAmount>: compactsize(count) then
  # each (32B txid + int64 amount).
  w.writeCompactSize(uint64(remainingDeltas.len))
  for txid, delta in remainingDeltas:
    w.writeHash(array[32, byte](txid))
    w.writeInt64LE(delta)
  # unbroadcast set: empty.
  w.writeCompactSize(0)

  var obfBody = w.data

  # Header (always plaintext) + obfuscated body.
  var header = BinaryWriter()
  if useV2Xor:
    header.writeUint64LE(MempoolDumpVersion)
    let key = generateObfuscationKey()
    header.writeKeyVarBytes(key)
    xorInPlace(obfBody, key, startOffset = 0)
  else:
    header.writeUint64LE(MempoolDumpVersionNoXor)

  let tmpPath = dumpPath & ".new"
  try:
    block writeFile:
      let f = open(tmpPath, fmWrite)
      try:
        if header.data.len > 0:
          discard f.writeBuffer(addr header.data[0], header.data.len)
        if obfBody.len > 0:
          discard f.writeBuffer(addr obfBody[0], obfBody.len)
      finally:
        f.close()
    moveFile(tmpPath, dumpPath)
    info "wrote mempool.dat", path = dumpPath, txs = snapshot.len
    return true
  except CatchableError as e:
    error "dumpMempool failed", path = dumpPath, error = e.msg
    if fileExists(tmpPath):
      try: removeFile(tmpPath) except CatchableError: discard
    return false

# ---------------------------------------------------------------------------
# LoadMempool — read .dat, attempt to accept each tx via the live mempool.
# ---------------------------------------------------------------------------

type
  LoadMempoolResult* = object
    succeeded*:   int   ## Accepted into the mempool
    failed*:      int   ## Tried but not accepted (bad sig, missing input, ...)
    expired*:     int   ## Older than mempool expiry, skipped
    alreadyThere*: int  ## Already present (no-op)

proc loadMempool*(mp: Mempool, loadPath: string,
                  crypto: CryptoEngine,
                  expirySeconds: int64 = 14 * 24 * 3600
                 ): Option[LoadMempoolResult] =
  ## Restore mempool entries from `loadPath`. Returns None if the file does
  ## not exist or cannot be parsed; otherwise returns acceptance counts.
  if not fileExists(loadPath):
    return none(LoadMempoolResult)
  if mp == nil:
    return none(LoadMempoolResult)

  var raw: seq[byte]
  try:
    let f = open(loadPath, fmRead)
    try:
      let sz = f.getFileSize().int
      if sz <= 0:
        return none(LoadMempoolResult)
      raw = newSeq[byte](sz)
      let n = f.readBuffer(addr raw[0], sz)
      if n != sz:
        return none(LoadMempoolResult)
    finally:
      f.close()
  except CatchableError as e:
    error "loadMempool: failed to read", path = loadPath, error = e.msg
    return none(LoadMempoolResult)

  # Parse the version field (always plaintext).
  var r = BinaryReader(data: raw, pos: 0)
  let version = try:
    r.readUint64LE()
  except CatchableError as e:
    error "loadMempool: bad version field", error = e.msg
    return none(LoadMempoolResult)

  var key: array[ObfuscationKeySize, byte]
  var obfStart = 0
  if version == MempoolDumpVersionNoXor:
    obfStart = r.pos
  elif version == MempoolDumpVersion:
    try:
      key = r.readKeyVarBytes()
    except CatchableError as e:
      error "loadMempool: bad obfuscation key", error = e.msg
      return none(LoadMempoolResult)
    obfStart = r.pos
  else:
    error "loadMempool: unknown dump version", version = version
    return none(LoadMempoolResult)

  # De-obfuscate the body in-place if v2.
  if version == MempoolDumpVersion:
    var body = raw[obfStart .. ^1]
    xorInPlace(body, key, startOffset = 0)
    # Splice back so BinaryReader continues correctly.
    for i in 0 ..< body.len:
      raw[obfStart + i] = body[i]
    r = BinaryReader(data: raw, pos: obfStart)

  var counts = LoadMempoolResult()
  let now = getTime().toUnix()

  try:
    let txCount = r.readUint64LE()
    for _ in 0 ..< int(txCount):
      let tx = r.readTransaction()
      let nTime = r.readInt64LE()
      let nFeeDelta = r.readInt64LE()

      let txid = tx.txid()
      if txid in mp.entries:
        counts.alreadyThere.inc
        # Re-apply the stored prioritisation even if the tx is already present
        # so the delta survives across a load into a partially-populated pool.
        if nFeeDelta != 0:
          mp.prioritiseTransaction(txid, nFeeDelta)
        continue

      if nTime > 0 and (now - nTime) > expirySeconds:
        counts.expired.inc
        # Core does not re-prioritise expired txs (they never enter), but their
        # delta is preserved via the trailing mapDeltas section below if it was
        # an out-of-mempool delta. In-mempool deltas of expired txs are dropped.
        continue

      # Core (node/mempool_persist.cpp:99-101) records the delta BEFORE the tx
      # is (re)admitted so PreChecks' ApplyDelta folds it into the modified
      # fee. We do the same: set the delta first, then accept.
      if nFeeDelta != 0:
        mp.prioritiseTransaction(txid, nFeeDelta)

      try:
        let res = mp.acceptTransaction(tx, crypto)
        if res.isOk:
          counts.succeeded.inc
        else:
          counts.failed.inc
      except CatchableError:
        counts.failed.inc

    # mapDeltas — out-of-mempool prioritisations (Core node/mempool_persist.cpp
    # :125-130 calls PrioritiseTransaction for each). These stack onto whatever
    # was applied per-tx above, matching Core's load semantics.
    let nDeltas = r.readCompactSize()
    for _ in 0 ..< int(nDeltas):
      let dtxid = TxId(r.readHash())
      let damount = r.readInt64LE()
      if damount != 0:
        mp.prioritiseTransaction(dtxid, damount)

    # unbroadcast set — read but ignore.
    let nUnbroadcast = r.readCompactSize()
    for _ in 0 ..< int(nUnbroadcast):
      discard r.readHash()
  except CatchableError as e:
    error "loadMempool: parse error", error = e.msg
    # Return what we have; matches Core which just logs and continues.

  info "loaded mempool.dat", path = loadPath,
       succeeded = counts.succeeded, failed = counts.failed,
       expired = counts.expired, alreadyThere = counts.alreadyThere
  some(counts)

# ---------------------------------------------------------------------------
# Round-trip sanity helper — used by tests to verify the wire format.
# ---------------------------------------------------------------------------

proc encodeMempoolDump*(snapshot: seq[Transaction],
                       useV2Xor: bool,
                       fixedKey: Option[array[ObfuscationKeySize, byte]] =
                         none(array[ObfuscationKeySize, byte]),
                       txTimes: seq[int64] = @[],
                       feeDeltas: seq[int64] = @[]
                      ): seq[byte] =
  ## Test helper: produce the raw bytes of a mempool.dat dump for an
  ## arbitrary tx list, optionally with a deterministic key. Used by tests
  ## to assert the format matches Core byte-for-byte.
  var w = BinaryWriter()
  w.writeUint64LE(uint64(snapshot.len))
  for i, tx in snapshot:
    w.writeTransaction(tx, includeWitness = true)
    let t = if i < txTimes.len: txTimes[i] else: 0'i64
    let f = if i < feeDeltas.len: feeDeltas[i] else: 0'i64
    w.writeInt64LE(t)
    w.writeInt64LE(f)
  w.writeCompactSize(0)  # mapDeltas
  w.writeCompactSize(0)  # unbroadcast
  var body = w.data

  var header = BinaryWriter()
  if useV2Xor:
    header.writeUint64LE(MempoolDumpVersion)
    let key = if fixedKey.isSome: fixedKey.get() else: generateObfuscationKey()
    header.writeKeyVarBytes(key)
    xorInPlace(body, key, startOffset = 0)
  else:
    header.writeUint64LE(MempoolDumpVersionNoXor)
  header.data & body
