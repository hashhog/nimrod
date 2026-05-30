## W138 — assumeUTXO snapshots audit (30 gates, xfail regression guards).
##
## Audit type: discovery (NO production code change in W138).
##
## W138 catalogues the gap between Bitcoin Core's assumeUTXO machinery:
##   - bitcoin-core/src/node/utxo_snapshot.{h,cpp}
##   - bitcoin-core/src/validation.cpp (ActivateSnapshot,
##     PopulateAndValidateSnapshot, MaybeValidateSnapshot,
##     LoadAssumeutxoChainstate, InvalidateCoinsDBOnDisk,
##     ValidatedSnapshotCleanup)
##   - bitcoin-core/src/rpc/blockchain.cpp (dumptxoutset, loadtxoutset,
##     getchainstates)
##   - bitcoin-core/src/kernel/chainparams.{h,cpp}
##     (AssumeutxoData / m_assumeutxo_data per network)
##
## ...and nimrod's parallel pipeline:
##   - src/storage/snapshot.nim       (codec + load/dump + B1..B8 strict
##                                     gates + SnapshotChainState scaffold +
##                                     BackgroundValidation dead loop)
##   - src/consensus/params.nim       (AssumeutxoData + per-network seq)
##   - src/rpc/server.nim             (dumptxoutset RPC + loadtxoutset
##                                     refused stub + dispatch)
##   - src/storage/pruner.nim         (assumeUtxoFloor)
##   - src/nimrod.nim                 (startup --load-snapshot path)
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour with
## a `check` that pins the gap. When a future FIX wave closes the gap,
## the test will fail loudly and the developer must flip the assertion
## (per W120 / W122 / W123 / W124 / W125 / W128 / W131 / W132 / W133 /
## W134 / W135 / W136 / W137 methodology).
##
## References:
##   bitcoin-core/src/node/utxo_snapshot.h
##     - 28        SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff}
##     - 39        SnapshotMetadata::VERSION = 2
##     - 113       SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"
##     - 128       SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"
##   bitcoin-core/src/node/utxo_snapshot.cpp
##     - 22-46     WriteSnapshotBaseBlockhash
##     - 48-81     ReadSnapshotBaseBlockhash
##     - 83-92     FindAssumeutxoChainstateDir
##   bitcoin-core/src/validation.cpp
##     - 5588-5728 ChainstateManager::ActivateSnapshot
##     - 5600      double-activation guard
##     - 5611-5615 base block in headers chain
##     - 5617-5620 BLOCK_FAILED_VALID guard
##     - 5622-5624 forked-headers chain check
##     - 5626-5629 mempool empty
##     - 5677-5694 cleanup_bad_snapshot
##     - 5706-5707 post-load work-exceeds check
##     - 5717      AddChainstate (dual chainstate)
##     - 5754-5953 PopulateAndValidateSnapshot
##     - 5787-5788 pre-load work-exceeds check
##     - 5804-5806 coins_per_txid > coins_left
##     - 5814      coin.nHeight > base_height
##     - 5815-5816 outpoint.n >= UINT32_MAX
##     - 5820-5822 MoneyRange
##     - 5872-5882 trailing-bytes guard
##     - 5901-5915 hash_serialized strict gate
##     - 5930-5945 BLOCK_OPT_WITNESS fake
##     - 5949      m_chain_tx_count populate
##     - 5967-6077 MaybeValidateSnapshot
##     - 6085-6115 MaybeRebalanceCaches
##     - 6151-6168 LoadAssumeutxoChainstate
##     - 6170-6186 AddChainstate
##     - 6201-6231 InvalidateCoinsDBOnDisk
##     - 6280-6345 ValidatedSnapshotCleanup
##   bitcoin-core/src/rpc/blockchain.cpp
##     - 3068-3231 dumptxoutset
##     - 3137      fs::is_fifo handling
##     - 3346      pushKV("nchaintx", ...)
##     - 3368-3447 loadtxoutset
##     - 3432-3435 NODE_NETWORK -> NODE_NETWORK_LIMITED
##     - 3462-3519 getchainstates
##   bitcoin-core/src/kernel/chainparams.cpp
##     - 158-183   mainnet assumeutxo_data (5 entries)
##     - 271-284   testnet3 assumeutxo_data (2 entries)
##     - 376-389   testnet4 assumeutxo_data (2 entries)
##     - 489-502   signet assumeutxo_data (2 entries)
##     - 607-628   regtest assumeutxo_data (3 entries)
##     - 677-686   GetAvailableSnapshotHeights
##   audit/w138_assumeutxo.md — full gate table + per-BUG detail.

import unittest2
import std/[options, strutils, os]
import ../src/storage/snapshot
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/primitives/types

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # bitcoin-core/src/node/utxo_snapshot.h:28
  CORE_SNAPSHOT_MAGIC: array[5, byte] =
    [byte('u'), byte('t'), byte('x'), byte('o'), 0xff'u8]
  # bitcoin-core/src/node/utxo_snapshot.h:39
  CORE_SNAPSHOT_VERSION = 2'u16
  # bitcoin-core/src/node/utxo_snapshot.h:113
  CORE_SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"
  # bitcoin-core/src/node/utxo_snapshot.h:128
  CORE_SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"
  # bitcoin-core/src/kernel/chainparams.cpp:158-183 mainnet (5 entries)
  CORE_MAINNET_ASSUMEUTXO_COUNT = 5
  CORE_MAINNET_ASSUMEUTXO_HEIGHTS = [840_000, 880_000, 910_000, 935_000, 944_183]
  # bitcoin-core/src/kernel/chainparams.cpp:376-389 testnet4 (2 entries)
  CORE_TESTNET4_ASSUMEUTXO_COUNT = 2
  CORE_TESTNET4_ASSUMEUTXO_HEIGHTS = [90_000, 120_000]
  # bitcoin-core/src/kernel/chainparams.cpp:489-502 signet (2 entries)
  CORE_SIGNET_ASSUMEUTXO_COUNT = 2
  CORE_SIGNET_ASSUMEUTXO_HEIGHTS = [160_000, 290_000]
  # bitcoin-core/src/kernel/chainparams.cpp:607-628 regtest (3 entries)
  CORE_REGTEST_ASSUMEUTXO_COUNT = 3
  CORE_REGTEST_ASSUMEUTXO_HEIGHTS = [110, 200, 299]
  # bitcoin-core/src/kernel/chainparams.cpp:271-284 testnet3 (2 entries)
  CORE_TESTNET3_ASSUMEUTXO_COUNT = 2

# Read production source files once for source-level pinning.
let
  snapshotSrc:  string = readFile("src/storage/snapshot.nim")
  paramsSrc:    string = readFile("src/consensus/params.nim")
  serverSrc:    string = readFile("src/rpc/server.nim")
  prunerSrc:    string = readFile("src/storage/pruner.nim")
  chainstSrc:   string = readFile("src/storage/chainstate.nim")
  nimrodSrc:    string = readFile("src/nimrod.nim")

# ---------------------------------------------------------------------------
# G1 — SNAPSHOT_MAGIC_BYTES (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G1 — SNAPSHOT_MAGIC_BYTES":

  test "G1 PRESENT: SnapshotMagic matches Core 'utxo\\xff'":
    check SnapshotMagic == CORE_SNAPSHOT_MAGIC
    check SnapshotMagic[0] == byte('u')
    check SnapshotMagic[1] == byte('t')
    check SnapshotMagic[2] == byte('x')
    check SnapshotMagic[3] == byte('o')
    check SnapshotMagic[4] == 0xff'u8

# ---------------------------------------------------------------------------
# G2 — VERSION = 2 (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G2 — SnapshotVersion":

  test "G2 PRESENT: SnapshotVersion == 2 (Core utxo_snapshot.h:39)":
    check SnapshotVersion == CORE_SNAPSHOT_VERSION

# ---------------------------------------------------------------------------
# G3 — Network magic byte-compare (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G3 — network magic":

  test "G3 PRESENT: validateSnapshotMetadata refuses cross-network magic":
    ## snapshot.nim:634 — network magic mismatch returns invalid.
    check "network magic mismatch" in snapshotSrc

# ---------------------------------------------------------------------------
# G4 — Metadata field shape (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G4 — SnapshotMetadata":

  test "G4 PRESENT: SnapshotMetadata has version + networkMagic + baseBlockhash + coinsCount":
    let m = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [byte 0, 0, 0, 0],
      baseBlockhash: BlockHash(default(array[32, byte])),
      coinsCount: 0'u64
    )
    check m.version == 2'u16
    check m.coinsCount == 0'u64

# ---------------------------------------------------------------------------
# G5 — Txid-grouped body layout (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G5 — txid-grouped body layout":

  test "G5 PRESENT: writeTxidGroup + pendingRemaining streaming present":
    check "writeTxidGroup" in snapshotSrc
    check "pendingRemaining" in snapshotSrc

# ---------------------------------------------------------------------------
# G6 — Per-coin codec (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G6 — per-coin Coin::Serialize parity":

  test "G6 PRESENT: writeCoinBody + readCoinBody present":
    check "writeCoinBody" in snapshotSrc
    check "readCoinBody" in snapshotSrc
    # CompressAmount + ScriptCompression helpers present
    check "compressAmount" in snapshotSrc
    check "decompressAmount" in snapshotSrc
    check "writeCompressedScript" in snapshotSrc
    check "readCompressedScript" in snapshotSrc

# ---------------------------------------------------------------------------
# G7 — coins_per_txid > coins_left → error (PRESENT, B4 guard)
# ---------------------------------------------------------------------------
suite "W138 G7 — coins_per_txid overcount guard (B4)":

  test "G7 PRESENT: 'Mismatch in coins count' fires on overcount":
    check "Mismatch in coins count" in snapshotSrc

# ---------------------------------------------------------------------------
# G8 — coin.nHeight > base_height → error (PRESENT, B1)
# ---------------------------------------------------------------------------
suite "W138 G8 — coin.nHeight > base_height (B1 guard)":

  test "G8 PRESENT: 'Bad snapshot data after deserializing' fires":
    check "Bad snapshot data after deserializing" in snapshotSrc

# ---------------------------------------------------------------------------
# G9 — outpoint.n >= UINT32_MAX → error (PRESENT, B3 guard)
# ---------------------------------------------------------------------------
suite "W138 G9 — outpoint.n wrap guard (B3)":

  test "G9 PRESENT: 0xFFFFFFFF guard fires per Core validation.cpp:5815-5816":
    check "0xFFFFFFFF'u32" in snapshotSrc

# ---------------------------------------------------------------------------
# G10 — MoneyRange check (PRESENT, B2)
# ---------------------------------------------------------------------------
suite "W138 G10 — MoneyRange per-coin check (B2)":

  test "G10 PRESENT: 'bad tx out value' fires for out-of-range value":
    check "bad tx out value" in snapshotSrc
    check "MaxMoney" in snapshotSrc

# ---------------------------------------------------------------------------
# G11 — Trailing bytes after coins_left==0 (PRESENT, B5)
# ---------------------------------------------------------------------------
suite "W138 G11 — trailing-bytes guard (B5)":

  test "G11 PRESENT: 'coins left over after deserializing' fires":
    check "coins left over after deserializing" in snapshotSrc

# ---------------------------------------------------------------------------
# G12 — Base block in headers chain (BUG-1, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G12 — base block headers-chain membership (BUG-1)":

  test "G12 BUG-1: snapshot.nim does NOT call LookupBlockIndex / consult headers chain":
    ## Core validation.cpp:5611-5615:
    ##   snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash);
    ##   if (!snapshot_start_block) return error("must appear in the headers chain");
    ## nimrod only walks `assumeutxoData` whitelist; no header-chain
    ## lookup at all.
    check "LookupBlockIndex" notin snapshotSrc
    check "must appear in the headers chain" notin snapshotSrc
    # When the fix lands, both `notin`s flip to `in` (or a Nim-flavoured
    # `db.getBlockIndex(...)` walk shows up that resolves base hash against
    # the header chain).

# ---------------------------------------------------------------------------
# G13 — BLOCK_FAILED_VALID check (BUG-2, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G13 — BLOCK_FAILED_VALID on snapshot base (BUG-2)":

  test "G13 BUG-2: snapshot.nim does NOT check base-block failure flags":
    ## Core validation.cpp:5617-5620 rejects when nStatus & BLOCK_FAILED_VALID.
    ## nimrod's BlockFailureFlags exist in chainstate.nim but
    ## snapshot.nim doesn't read them.
    check "BlockFailureFlags" notin snapshotSrc
    check "BLOCK_FAILED_VALID" notin snapshotSrc
    check "part of an invalid chain" notin snapshotSrc

# ---------------------------------------------------------------------------
# G14 — Forked headers-chain check (BUG-3, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G14 — forked-headers check (BUG-3)":

  test "G14 BUG-3: no GetAncestor / best_header comparator in snapshot path":
    ## Core validation.cpp:5622-5624 refuses snapshot if a more-work
    ## fork bypasses the snapshot base.
    check "GetAncestor" notin snapshotSrc
    check "forked headers-chain" notin snapshotSrc
    check "proceed to sync without AssumeUtxo" notin snapshotSrc

# ---------------------------------------------------------------------------
# G15 — Mempool empty precondition (BUG-4, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G15 — mempool empty precondition (BUG-4)":

  test "G15 BUG-4: snapshot path doesn't consult mempool size":
    ## Core validation.cpp:5626-5629 refuses if mempool->size() > 0.
    check "mempool not empty" notin snapshotSrc
    check "Can't activate a snapshot when mempool" notin snapshotSrc
    # The CLI startup path runs before mempool init so practically this
    # gap is contained — but the (currently-refused) RPC path would
    # silently bypass.

# ---------------------------------------------------------------------------
# G16 — Double-activation guard polarity (BUG-5, P0-CDIV, PARTIAL)
# ---------------------------------------------------------------------------
suite "W138 G16 — double-activation guard polarity (BUG-5)":

  test "G16 BUG-5: error string matches Core verbatim":
    check "Can't activate a snapshot-based chainstate more than once" in snapshotSrc

  test "G16 BUG-5: polarity inverted — guard fires only when auUnvalidated":
    ## snapshot.nim:803-805 — the predicate is `assumeutxo == auUnvalidated`.
    ## Core's predicate (validation.cpp:5600) is "any prior snapshot
    ## active, regardless of validation state".
    check "if snapshotCs.assumeutxo == auUnvalidated:" in snapshotSrc
    # Once Core-parity polarity lands, the predicate should also fire
    # when assumeutxo == auValidated. Forward-regression: a future
    # commit that adds `or snapshotCs.assumeutxo == auValidated` will
    # flip this `in` to `notin` and the test author must update.

# ---------------------------------------------------------------------------
# G17 — Work-exceeds-active pre-check (BUG-6, P1, PARTIAL — height not work)
# ---------------------------------------------------------------------------
suite "W138 G17 — pre-load work-exceeds check (BUG-6)":

  test "G17 BUG-6: uses HEIGHT not CHAINWORK (Core validation.cpp:5787)":
    ## nimrod compares `targetCs.bestHeight >= assumeData.height`.
    ## Core uses CBlockIndexWorkComparator on nChainWork.
    check "targetCs.bestHeight >= assumeData.height" in snapshotSrc
    check "Work does not exceed active chainstate" in snapshotSrc
    # AssumeutxoData carries no chainwork field.
    check "chainwork" notin paramsSrc.toLowerAscii() or
          "AssumeutxoData does not store chainwork" in snapshotSrc

  test "G17 BUG-6: AssumeutxoData has no chainwork field":
    let m = mainnetParams()
    when compiles(m.assumeutxoData[0].chainWork):
      check false # if this compiles after fix, audit must update.
    # We can statically confirm the field doesn't exist by attempting
    # field access in a `compiles()` block:
    check (not compiles(m.assumeutxoData[0].chainWork))

# ---------------------------------------------------------------------------
# G18 — Work-exceeds post-check (BUG-7, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G18 — post-load work-exceeds check (BUG-7)":

  test "G18 BUG-7: no second work check after streaming load":
    ## Core validation.cpp:5706 does a SECOND check after
    ## PopulateAndValidateSnapshot.
    check "second work-exceeds" notin snapshotSrc
    check "post-load work" notin snapshotSrc

# ---------------------------------------------------------------------------
# G19 — assumeutxo whitelist per-network (BUG-8, P0-CDIV, PARTIAL)
# ---------------------------------------------------------------------------
suite "W138 G19 — per-network assumeutxoData (BUG-8)":

  test "G19 PRESENT: mainnet has all 4 Core entries":
    let m = mainnetParams()
    check m.assumeutxoData.len == CORE_MAINNET_ASSUMEUTXO_COUNT
    let heights = block:
      var hs: seq[int] = @[]
      for d in m.assumeutxoData:
        hs.add(int(d.height))
      hs
    for h in CORE_MAINNET_ASSUMEUTXO_HEIGHTS:
      check h in heights

  test "G19 BUG-8a: testnet4 assumeutxoData seq is EMPTY (Core has 2)":
    let t4 = testnet4Params()
    check t4.assumeutxoData.len == 0
    # When the fix lands, expect t4.assumeutxoData.len == CORE_TESTNET4_ASSUMEUTXO_COUNT.

  test "G19 BUG-8b: signet assumeutxoData seq is EMPTY (Core has 2)":
    let s = signetParams()
    check s.assumeutxoData.len == 0

  test "G19 BUG-8c: regtest assumeutxoData seq is EMPTY (Core has 3)":
    let r = regtestParams()
    check r.assumeutxoData.len == 0

  test "G19 testnet3 OK: empty (Core also empty)":
    let t3 = testnet3Params()
    check t3.assumeutxoData.len == 0

# ---------------------------------------------------------------------------
# G20 — hash_serialized strict gate (PRESENT)
# ---------------------------------------------------------------------------
suite "W138 G20 — hash_serialized strict gate":

  test "G20 PRESENT: 'Bad snapshot content hash' fires verbatim":
    check "Bad snapshot content hash" in snapshotSrc

  test "G20 PRESENT: HashWriter / SHA256d-based hash compare":
    check "initHashWriter" in snapshotSrc
    check "finalizeHash" in snapshotSrc

# ---------------------------------------------------------------------------
# G21 — m_chain_tx_count populate on snapshot base (BUG-9, P2, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G21 — chainTxCount written to BlockIndex.nTx (BUG-9)":

  test "G21 BUG-9: loadSnapshot doesn't write chainTxCount into BlockIndex":
    ## Core validation.cpp:5949: index->m_chain_tx_count = au_data.m_chain_tx_count.
    ## nimrod loadSnapshot at snapshot.nim:778-780 updates only
    ## bestBlockHash + bestHeight — never touches BlockIndex.nTx.
    let loadSnapshotProcStart = snapshotSrc.find("proc loadSnapshot*(")
    check loadSnapshotProcStart >= 0
    # Find the proc body, then check no chainTxCount-writing call appears
    # before the trailing ============= banner.
    let bodyEnd = snapshotSrc.find(
      "# ============================================================================\n# Dual-chainstate",
      loadSnapshotProcStart
    )
    let body = snapshotSrc[loadSnapshotProcStart .. (if bodyEnd > 0: bodyEnd
                                                    else: snapshotSrc.len - 1)]
    check "chainTxCount" notin body
    check "nTx" notin body
    check "updateBlockIndex" notin body

# ---------------------------------------------------------------------------
# G22 — BLOCK_OPT_WITNESS fake on activated chain (BUG-10, P2, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G22 — BLOCK_OPT_WITNESS fake (BUG-10)":

  test "G22 BUG-10: no BLOCK_OPT_WITNESS / NeedsRedownload analog":
    ## Core validation.cpp:5930-5945 walks every block and ORs
    ## BLOCK_OPT_WITNESS into nStatus when SEGWIT is active.
    check "BLOCK_OPT_WITNESS" notin snapshotSrc
    check "NeedsRedownload" notin snapshotSrc

  test "G22 BUG-10: BlockStatus is a single enum, not a bitmask":
    ## chainstate.nim:178 writes status as one uint8 not an OR'd mask.
    check "writeUint8(uint8(ord(idx.status)))" in chainstSrc

# ---------------------------------------------------------------------------
# G23 — Two-chainstate manager / background validation (BUG-11, P0-CDIV, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G23 — dual-chainstate manager (BUG-11)":

  test "G23 BUG-11: single ChainState type, no ChainstateManager":
    ## Core: ChainstateManager owns vector<unique_ptr<Chainstate>>.
    ## nimrod: single ChainState* = ref object at chainstate.nim:88.
    check "ChainstateManager" notin chainstSrc
    check "HistoricalChainstate" notin chainstSrc
    check "ActiveChainstate" notin chainstSrc

  test "G23 BUG-11: ChainState has no m_from_snapshot_blockhash / m_assumeutxo":
    ## Core: Chainstate::m_from_snapshot_blockhash (optional<uint256>),
    ##       m_target_blockhash, m_assumeutxo (enum), m_target_utxohash.
    ## nimrod's ChainState (lines 88-133) carries none of these — only
    ## SnapshotChainState wraps them, and that wrapper is never
    ## instantiated in the production startup path.
    check "fromSnapshotBlockhash" notin chainstSrc
    check "targetBlockhash" notin chainstSrc
    check "m_from_snapshot_blockhash" notin chainstSrc
    # The scaffolding exists in snapshot.nim:
    check "SnapshotChainState" in snapshotSrc
    check "snapshotBlockhash" in snapshotSrc
    check "targetUtxoHash" in snapshotSrc

  test "G23 BUG-11: newSnapshotChainState has NO production call site":
    ## Same shape as W136 RelayManager dead-module pattern.
    check "newSnapshotChainState" in snapshotSrc  # definition
    check "newSnapshotChainState" notin nimrodSrc
    check "newSnapshotChainState" notin serverSrc

  test "G23 BUG-11: runBackgroundValidation is dead code":
    ## snapshot.nim:886-912 defines the async loop; no call site.
    check "runBackgroundValidation" in snapshotSrc
    check "runBackgroundValidation" notin nimrodSrc
    check "runBackgroundValidation" notin serverSrc

# ---------------------------------------------------------------------------
# G24 — base_blockhash marker file (BUG-12, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G24 — SNAPSHOT_BLOCKHASH_FILENAME marker (BUG-12)":

  test "G24 BUG-12: 'base_blockhash' marker filename absent from snapshot.nim":
    ## Core utxo_snapshot.h:113 — SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash".
    ## utxo_snapshot.cpp:22-46 writes it on snapshot activation;
    ## validation.cpp:6151-6168 reads it on restart.
    check CORE_SNAPSHOT_BLOCKHASH_FILENAME notin snapshotSrc
    check "WriteSnapshotBaseBlockhash" notin snapshotSrc
    check "ReadSnapshotBaseBlockhash" notin snapshotSrc
    check "LoadAssumeutxoChainstate" notin snapshotSrc
    # Also absent from the daemon startup path:
    check CORE_SNAPSHOT_BLOCKHASH_FILENAME notin nimrodSrc

# ---------------------------------------------------------------------------
# G25 — _snapshot directory suffix (BUG-13, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G25 — chainstate_snapshot dir suffix (BUG-13)":

  test "G25 BUG-13: SNAPSHOT_CHAINSTATE_SUFFIX dir-suffix logic absent":
    ## NB: the literal `_snapshot` substring appears in snapshot.nim's
    ## module-doc reference to `utxo_snapshot.{h,cpp}` and in the source
    ## filename itself — so we instead pin on the SEMANTIC anchor
    ## (FindAssumeutxoChainstateDir / chainstate_snapshot dir name /
    ## SNAPSHOT_CHAINSTATE_SUFFIX constant declaration).
    check "FindAssumeutxoChainstateDir" notin snapshotSrc
    check "chainstate_snapshot" notin nimrodSrc
    check "chainstate_snapshot" notin chainstSrc
    check "chainstate_snapshot" notin snapshotSrc
    check "SNAPSHOT_CHAINSTATE_SUFFIX" notin snapshotSrc

# ---------------------------------------------------------------------------
# G26 — MaybeValidateSnapshot hash compare (BUG-14, P1, PARTIAL/stub)
# ---------------------------------------------------------------------------
suite "W138 G26 — MaybeValidateSnapshot hash compare (BUG-14)":

  test "G26 BUG-14: validateSnapshot is a stub — no UTXO hash compute":
    ## snapshot.nim:856 — explicit confession comment:
    ##   "intentionally does NOT compute a UTXO hash from `backgroundCs`
    ##    since that requires a UTXO iterator we don't yet expose"
    check "intentionally does NOT compute a UTXO hash" in snapshotSrc
    check "Without a UTXO iterator we cannot byte-verify" in snapshotSrc

  test "G26 BUG-14: validateSnapshot unconditionally flips auValidated":
    check "snapshotCs.assumeutxo = auValidated" in snapshotSrc
    check "return svrValid" in snapshotSrc

# ---------------------------------------------------------------------------
# G27 — _INVALID rename + fatalError (BUG-15, P1, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G27 — bad-snapshot recovery (_INVALID + fatalError) (BUG-15)":

  test "G27 BUG-15: no _INVALID rename / InvalidateCoinsDBOnDisk analog":
    check "_INVALID" notin snapshotSrc
    check "InvalidateCoinsDBOnDisk" notin snapshotSrc
    check "fatalError" notin snapshotSrc

  test "G27 BUG-15: handle_invalid_snapshot user-facing string missing":
    ## Core validation.cpp:5987-6017 emits a multi-line user-facing
    ## error explaining hardware/software bug suspicion and the chain
    ## height rollback. nimrod has nothing comparable.
    check "failed to validate the -assumeutxo snapshot state" notin snapshotSrc
    check "resetting the chain height" notin snapshotSrc

# ---------------------------------------------------------------------------
# G28 — ValidatedSnapshotCleanup (_todelete dance) (BUG-16, P2, MISSING)
# ---------------------------------------------------------------------------
suite "W138 G28 — ValidatedSnapshotCleanup (BUG-16)":

  test "G28 BUG-16: no _todelete rename dance":
    ## Core validation.cpp:6280-6345.
    check "_todelete" notin snapshotSrc
    check "ValidatedSnapshotCleanup" notin snapshotSrc
    check "deleting background chainstate directory" notin snapshotSrc

# ---------------------------------------------------------------------------
# G29 — dumptxoutset RPC (BUG-17, P2, PARTIAL)
# ---------------------------------------------------------------------------
suite "W138 G29 — dumptxoutset RPC parity (BUG-17)":

  test "G29 PRESENT: handleDumpTxOutSet exists":
    check "proc handleDumpTxOutSet" in serverSrc

  test "G29 PRESENT: TemporaryRollback / NetworkDisable / pruned-mode pre-check":
    check "TemporaryRollback" in serverSrc
    check "NetworkDisable" in serverSrc
    check "blockSubmissionPaused" in serverSrc

  test "G29 BUG-17a: fifo handling absent":
    ## Core rpc/blockchain.cpp:3137: fs::is_fifo(path_info) writes
    ## directly to the fifo and skips the .incomplete rename.
    check "is_fifo" notin serverSrc
    check "isFifo" notin serverSrc

  test "G29 BUG-17b: nchaintx emitted only when matching hardcoded entry":
    ## Core rpc/blockchain.cpp:3346 ALWAYS emits nchaintx = tip->m_chain_tx_count.
    ## nimrod emits only when target matches assumeutxoData
    ## (server.nim:5023-5028 — `haveNChainTx` gate).
    check "haveNChainTx" in serverSrc

  test "G29 BUG-17c: dump iterates cs.utxoCache directly (not a cursor snapshot)":
    ## snapshot.nim:522 — `for op, entry in cs.utxoCache`.
    ## Core uses a leveldb cursor over a snapshotted view
    ## (rpc/blockchain.cpp:3248).
    check "for op, entry in cs.utxoCache" in snapshotSrc

# ---------------------------------------------------------------------------
# G30 — loadtxoutset RPC + service-flag flip + getchainstates (BUG-18, P2)
# ---------------------------------------------------------------------------
suite "W138 G30 — loadtxoutset / service flag / getchainstates (BUG-18)":

  test "G30 BUG-18a: loadtxoutset RPC unconditionally refused":
    ## server.nim:5080-5088 — RpcInternalError always thrown.
    check "loadtxoutset RPC is disabled in this build" in serverSrc

  test "G30 BUG-18b: NODE_NETWORK -> NODE_NETWORK_LIMITED flip not wired to snapshot load":
    ## Core rpc/blockchain.cpp:3432-3435 RemoveLocalServices(NODE_NETWORK)
    ## + AddLocalServices(NODE_NETWORK_LIMITED) after activation.
    ## NB: nimrod has NODE_NETWORK_LIMITED for BIP-159 prune-mode
    ## advertisement (nimrod.nim:1893+), but it's not wired to the
    ## snapshot-load path. Pin the snapshot-load section specifically.
    let loadSnapshotStart = nimrodSrc.find("if config.loadSnapshot.len > 0:")
    check loadSnapshotStart >= 0
    let loadSnapshotEnd = nimrodSrc.find("# 2c.", loadSnapshotStart)
    check loadSnapshotEnd > loadSnapshotStart
    let loadSection = nimrodSrc[loadSnapshotStart ..< loadSnapshotEnd]
    check "NODE_NETWORK_LIMITED" notin loadSection
    check "RemoveLocalServices" notin loadSection
    check "removeLocalServices" notin loadSection
    # ...neither does the (currently-refused) RPC handler:
    let loadTxOutStart = serverSrc.find("proc handleLoadTxOutSet*(")
    check loadTxOutStart >= 0
    let loadTxOutEnd = serverSrc.find("\nproc ", loadTxOutStart + 10)
    let loadTxOutSection = serverSrc[loadTxOutStart ..< loadTxOutEnd]
    check "NODE_NETWORK_LIMITED" notin loadTxOutSection

  test "G30 BUG-18c: getchainstates RPC missing from dispatch":
    ## server.nim:8234-8275 — no `of "getchainstates":` arm.
    check "of \"getchainstates\":" notin serverSrc
    check "handleGetChainstates" notin serverSrc

  test "G30 BUG-18c: getchainstates handler not defined":
    check "proc handleGetChainstates" notin serverSrc

# ---------------------------------------------------------------------------
# Cross-cutting: AssumeutxoData fields match Core
# ---------------------------------------------------------------------------
suite "W138 X1 — AssumeutxoData struct shape":

  test "X1 PRESENT: AssumeutxoData has height + hashSerialized + chainTxCount + blockhash":
    let d = AssumeutxoData(
      height: 0'i32,
      hashSerialized: default(array[32, byte]),
      chainTxCount: 0'u64,
      blockhash: BlockHash(default(array[32, byte]))
    )
    check d.height == 0'i32
    check d.chainTxCount == 0'u64

  test "X1 BUG-6 cross-ref: AssumeutxoData has NO chainWork field":
    let d = AssumeutxoData(
      height: 0'i32,
      hashSerialized: default(array[32, byte]),
      chainTxCount: 0'u64,
      blockhash: BlockHash(default(array[32, byte]))
    )
    check (not compiles(d.chainWork))

# ---------------------------------------------------------------------------
# Cross-cutting: P3 cosmetic / contract
# ---------------------------------------------------------------------------
suite "W138 X2 — P3 cosmetic / contract":

  test "X2 P3a: SnapshotChainState.assumeutxo defaults to auValidated (structurally wrong)":
    ## snapshot.nim:790 — newSnapshotChainState pins auValidated. A
    ## fresh snapshot chainstate should start auUnvalidated.
    check "assumeutxo: auValidated" in snapshotSrc

  test "X2 P3b: MAX_SCRIPT_SIZE guard hardcoded to 16505 (too tight vs Core compressor)":
    ## snapshot.nim:286 / :439 — `if scriptLen > 16505'u64`.
    ## Core's compressor supports up to ~65540.
    check "16505'u64" in snapshotSrc

  test "X2 P3c: SnapshotError 'snapshot file not found' diverges from Core message":
    ## Core rpc/blockchain.cpp:3413-3415: "Couldn't open file %s for reading."
    check "snapshot file not found" in snapshotSrc
    check "Couldn't open file" notin snapshotSrc

  test "X2 P3d: BackgroundValidation.progress monotonicity not asserted":
    ## snapshot.nim:886-912 — async loop increments without assertion.
    ## Pattern: `inc bgv.progress` with no `doAssert bgv.progress <=
    ## bgv.targetHeight + 1` before/after.
    check "inc bgv.progress" in snapshotSrc
    check "doAssert bgv.progress" notin snapshotSrc

# ---------------------------------------------------------------------------
# Cross-cutting: pruner assumeUtxoFloor uses LOWEST height (P1 nuance)
# ---------------------------------------------------------------------------
suite "W138 X3 — pruner assumeUtxoFloor":

  test "X3 P1: pruner uses LOWEST height across ALL hardcoded entries":
    ## pruner.nim:174-186 walks `p.params.assumeutxoData` and returns
    ## the LOWEST entry's height as the floor. Core ties prune floor
    ## to the specific activated snapshot's base height
    ## (validation.cpp:6354-6360 — `Assert(SnapshotBase())->nHeight + 1`),
    ## NOT a stale historical entry from chainparams.
    check "for entry in p.params.assumeutxoData" in prunerSrc
    check "if entry.height < lowest" in prunerSrc

  test "X3 P1: assumeUtxoFloor returns -1 only when seq is empty":
    ## So on testnet4 / signet / regtest (all empty per BUG-8), floor
    ## defaults to -1 today — once those seqs are populated to match
    ## Core, the floor will jump to the lowest entry (regtest 110)
    ## which may surprise operators running short-chain tests.
    check "if p.params.assumeutxoData.len == 0:" in prunerSrc

# ---------------------------------------------------------------------------
# Sanity: snapshot metadata constructor sanity (regression guard)
# ---------------------------------------------------------------------------
suite "W138 SANITY — SnapshotMetadata shape":

  test "SANITY: SnapshotMetadata field defaults and sizes":
    ## Source-level regression guard: if any of these fields are
    ## removed / renamed, the W138 audit must be revisited because the
    ## on-disk header layout would change.
    let m = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(default(array[32, byte])),
      coinsCount: 12345'u64
    )
    check m.version == 2'u16
    check m.networkMagic.len == 4
    check m.coinsCount == 12345'u64
    check sizeof(m.networkMagic) == 4
    check array[32, byte](m.baseBlockhash).len == 32
