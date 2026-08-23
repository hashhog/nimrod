## Headers-first block synchronization
## Download and validate all headers before block data
## Most-work chain wins (not longest chain)
## Phase 13: Parallel block download with sliding window for IBD
## Phase 13+: PRESYNC/REDOWNLOAD anti-DoS header sync protection

import std/[options, deques, tables, algorithm, sequtils, sets, strutils, cpuinfo]
import std/[times, threadpool]
import chronos
import chronicles
import ./peer
import ./peermanager
import ./messages
import ./headerssync
import ../primitives/[types, serialize, uint256]
# The `assumevalid` module is no longer imported here: applyBlock and
# processReceivedBlocks were migrated to the unified `acceptAndConnectBlock`
# envelope, which computes the assumevalid skip-scripts decision internally
# (validation.nim) instead of this path hand-rolling an AssumeValidContext.
import ../consensus/[params, pow, validation]
import ../storage/chainstate
import ../storage/indexes/blockfilterindex
import ../storage/indexes/coinstatsindex
import ../storage/indexes/txospenderindex
import ../crypto/[hashing, secp256k1]
import ../perf/parallel_verify

# Use std/times for Time and Duration (not chronos/timer)
type
  SyncTime = times.Time
  SyncDuration = times.Duration

type
  SyncState* = enum
    ssIdle            ## Not syncing
    ssSyncingHeaders  ## Downloading and validating headers
    ssDownloadingBlocks  ## Downloading full block data
    ssSynced          ## Fully synchronized

  SideHeader* = object
    ## A header that does NOT extend the active header chain — a competing
    ## fork that branches off at some KNOWN below-tip ancestor.  Bitcoin Core
    ## keeps every such header in the single CBlockIndex map (m_block_index)
    ## with its own nHeight/nChainWork; nimrod's active chain is a flat linear
    ## seq, so fork headers live here in a parallel by-hash map until (and if)
    ## one of them wins a reorg.  `height` is the absolute chain height of this
    ## fork header (forkPointHeight + offset), and `totalWork` is the fork's
    ## OWN cumulative work walked from genesis through its own ancestors — NOT
    ## derived from the active chain's totalWork (Core nChainWork parity).
    header*: BlockHeader
    height*: int32
    totalWork*: array[32, byte]

  HeaderChain* = object
    headers*: seq[BlockHeader]
    hashes*: seq[BlockHash]        ## Index -> hash mapping
    byHash*: Table[BlockHash, int]  ## Hash -> index mapping
    tip*: BlockHash
    tipHeight*: int32
    totalWork*: array[32, byte]  ## Cumulative work of the chain
    # Competing-fork headers that branch BELOW the active tip.  Keyed by the
    # fork header's own hash.  Populated by handleHeaders' fork arm (does NOT
    # ban the peer); read by requestBlocks to walk the fork's ancestry and
    # request its missing bodies.  Empty in the steady-state single-chain
    # case, so the normal IBD/extension path is untouched.
    sideHeaders*: Table[BlockHash, SideHeader]

  HeaderBatchRouting* = enum
    ## Outcome of classifying an incoming `headers` batch — mirrors the
    ## branching of Bitcoin Core's ProcessHeadersMessage (net_processing.cpp).
    hbrUnconnecting   ## headers[0].prevBlock not in our header chain (BIP-130
                      ## announcement / transient reorg) — re-request, count
    hbrAntiDoS        ## headers connect, but claimed work < anti-DoS
                      ## threshold — must go through the PRESYNC pipeline
    hbrDirect         ## headers connect AND already carry enough work
                      ## (or threshold is zero / regtest) — validate directly

  ## Statistics for header presync (anti-DoS tracking)
  HeadersPresyncStats* = object
    work*: UInt256              ## Total verified work accumulated
    height*: int64              ## Height reached (only valid in PRESYNC)
    timestamp*: uint32          ## Block timestamp of last header (only valid in PRESYNC)
    inPresync*: bool            ## True if in PRESYNC phase, false if in REDOWNLOAD

  SyncManager* = ref object
    state*: SyncState
    headerChain*: HeaderChain
    peerManager*: PeerManager
    chainDb*: ChainDb
    chainState*: ChainState  ## Full chain state for block connection
    params*: ConsensusParams
    syncPeer*: Peer
    # Block download state
    blockQueue*: Deque[BlockHash]
    pendingBlocks*: int
    lastSyncTime*: SyncTime
    # Separate tracking for header tip vs chain tip (CRITICAL pitfall)
    headerTip*: BlockHash       ## Tip of validated headers
    headerTipHeight*: int32     ## Height of header tip
    chainTip*: BlockHash        ## Tip of fully validated blocks
    chainTipHeight*: int32      ## Height of chain tip
    # Anti-DoS header sync state (per-peer PRESYNC/REDOWNLOAD)
    peerHeadersSync*: Table[int64, HeadersSyncState]  ## peerId -> sync state
    headersPresyncStats*: Table[int64, HeadersPresyncStats]  ## Per-peer stats
    presyncBestPeer*: int64     ## Peer with most work in presync
    presyncBestWork*: UInt256   ## Best work seen in presync
    minimumChainWork*: UInt256  ## Anti-DoS work threshold
    # Block failure tracking
    failedBlockHeight*: int32   ## Height of last failed block
    failedBlockRetries*: int    ## Number of retries for the same block
    maxBlockRetries*: int       ## Max retries before skipping script check (default 3)
    # Parallel script verification
    numVerifyWorkers*: int      ## Thread pool size for parallel script verify (0 = auto)
    # Out-of-order block buffer (blocks received ahead of chainTip)
    receivedBlocks*: Table[int32, Block]  ## height -> block buffer
    requestedHashes*: HashSet[BlockHash]  ## hashes currently in-flight
    # Per-peer counter of consecutive unconnecting-headers messages.
    # Mirrors Bitcoin Core's `nUnconnectingHeaders` accounting in
    # net_processing.cpp::ProcessHeadersMessage.  When the count exceeds
    # MaxNumUnconnectingHeadersMsgs (=10), the peer is banned.  Reset to
    # 0 on every successful connecting batch.  Pre-fix, nimrod called
    # banPeer immediately on the first orphan, which is stricter than
    # Core and discards honest peers caught in transient reorgs.  See
    # CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
    # (Pattern B).
    unconnectingHeaders*: Table[int64, int]  ## peerId -> count
    # Chain height at which the last header-tip repair was ATTEMPTED.  Guards
    # reconcileHeaderTip from re-running the O(bestHeight) block-index walk on
    # every sync-loop iteration when the persisted index cannot close the gap
    # (a truncated/corrupt index prefix).  A successful repair makes the cheap
    # invariant check short-circuit, so this only bounds the failing case.
    headerTipRepairAt*: int32   ## chainTipHeight of last repair attempt
    # Optional BIP-157 basic block-filter index — populated alongside each
    # connectBlock/connectBlockIBD when --blockfilterindex is set.  nil
    # when disabled.  Mirrors Core's `g_indexes` BaseIndex hook list:
    # bitcoin-core/src/index/base.cpp::ConnectBlock fans out to every
    # registered index after each successful block connect.
    filterIndex*: BlockFilterIndex
    # Optional per-height UTXO-set statistics index (coinstatsindex) —
    # maintained alongside each connectBlock/connectBlockIBD when
    # --coinstatsindex is set.  nil when disabled.  Same fan-out rationale as
    # filterIndex above.
    coinStatsIndex*: CoinStatsIndex
    # Optional spent-outpoint -> spending-tx index (txospenderindex) —
    # maintained alongside each connectBlock/connectBlockIBD when
    # --txospenderindex is set.  nil when disabled.  Same fan-out rationale as
    # filterIndex above.  Folded forward here on connect; rolled back via the
    # chainstate disconnectHook on reorg/invalidateblock.
    txoSpenderIndex*: TxoSpenderIndex
    # Reorg-drop fix (Part 2): when processBlock's side-branch arm promotes a
    # heavier competing fork via acceptSideBranchBlock, the disconnected old-
    # chain non-coinbase txs + the newly-connected fork blocks are stashed here
    # for the P2P caller (nimrod.nim mkBlock arm) to drain into the mempool /
    # fee-estimator AFTER processBlock returns.  The SyncManager does not own the
    # Mempool (it lives on NodeState), so the refresh is split exactly like the
    # existing post-block removeForBlock split.  Both are cleared at the start of
    # every processBlock and only the reorg arm fills them.
    pendingReorgDisconnectedTxs*: seq[Transaction]
    pendingReorgConnectedBlocks*: seq[Block]

const
  MaxHeadersPerRequest* = 2000
  MaxBlocksInFlight* = 512
  SyncTimeoutSeconds* = 60

  ## Bitcoin Core's MAX_NUM_UNCONNECTING_HEADERS_MSGS
  ## (net_processing.cpp).  A peer that delivers more than this many
  ## successive unconnecting-headers messages is disconnected and
  ## banned.  Tolerates up to 10 transient unlinked batches before
  ## taking action — matches Core, looser than the pre-fix immediate
  ## banPeer behavior.
  MaxNumUnconnectingHeadersMsgs* = 10

  # Block download constants
  DownloadWindow* = 1024            ## Sliding window size for block requests
  MaxBlocksPerPeer* = 16            ## Per-peer in-flight cap (avoid one slow peer blocking others)
  BaseRequestTimeout* = 5           ## Base timeout in seconds
  MaxRequestTimeout* = 64           ## Max timeout after adaptive scaling
  BatchGetDataSize* = 64            ## Blocks per getdata message (batched for IBD throughput)
  UtxoFlushInterval* = 500          ## Flush UTXO set every N blocks during IBD
  InvWitnessBlockType* = 0x40000002'u32  ## Segwit block inv type

type
  BlockRequest* = object
    hash*: BlockHash
    height*: int32
    peer*: Peer
    requestTime*: SyncTime
    timeout*: SyncDuration        ## Adaptive timeout per request

  PeerBlockState* = object
    inFlight*: int                ## Blocks currently in-flight for this peer
    lastStall*: SyncTime          ## Last time this peer stalled
    currentTimeout*: int          ## Current timeout in seconds (adaptive)
    consecutiveSuccess*: int      ## Consecutive successful block receipts

  BlockDownloader* = ref object
    syncManager*: SyncManager
    pendingRequests*: Table[BlockHash, BlockRequest]
    downloadWindow*: int          ## 1024 blocks
    nextDownloadHeight*: int32    ## Next height to request
    nextProcessHeight*: int32     ## Next height to process (in-order)
    receivedBlocks*: Table[int32, Block]  ## Out-of-order buffer
    requestTimeout*: SyncDuration ## Base timeout (30s default)
    peerStates*: Table[string, PeerBlockState]  ## Per-peer tracking
    ibdActive*: bool              ## True during initial block download
    lastUtxoFlush*: int32         ## Height of last UTXO flush
    blocksProcessed*: int         ## Total blocks processed
    startTime*: SyncTime          ## IBD start time for stats

# =============================================================================
# 256-bit arithmetic for proof of work calculations
# =============================================================================

proc calculateWork*(bits: uint32): array[32, byte] =
  ## Calculate work for a block: 2^256 / (target+1)
  ## This represents the expected number of hashes to find this block
  let target = compactToTarget(bits)

  # Check for zero target (invalid)
  var isZero = true
  for b in target:
    if b != 0:
      isZero = false
      break
  if isZero:
    return default(array[32, byte])

  # We need to compute 2^256 / (target + 1)
  # Since we're dealing with 256-bit numbers, we use long division

  # First, compute target + 1
  var targetPlusOne: array[32, byte]
  var carry: uint16 = 1
  for i in 0 ..< 32:
    let sum = uint16(target[i]) + carry
    targetPlusOne[i] = byte(sum and 0xFF)
    carry = sum shr 8

  # If carry overflowed (target was 2^256-1), result is 1
  if carry != 0:
    result[0] = 1
    return result

  # Now divide 2^256 by targetPlusOne
  # We represent 2^256 as [0, 0, ..., 0, 1] (256 zeros followed by a 1)
  # This is equivalent to having the dividend be a 33-byte number where
  # the first 32 bytes are 0 and the 33rd byte is 1

  # Long division algorithm
  var dividend: array[33, byte]
  dividend[32] = 1  # This represents 2^256

  # Result will be 32 bytes
  var remainder: array[33, byte]

  # Process from most significant byte
  for i in countdown(32, 0):
    # Shift remainder left by 8 bits and add next byte of dividend
    for j in countdown(32, 1):
      remainder[j] = remainder[j - 1]
    remainder[0] = dividend[i]

    if i < 32:  # Result bytes are for indices 0..31
      # Find how many times targetPlusOne fits into remainder
      var quotient: byte = 0
      while true:
        # Check if remainder >= targetPlusOne
        var ge = true
        for k in countdown(32, 0):
          let rByte = if k < 33: remainder[k] else: 0'u8
          let tByte = if k < 32: targetPlusOne[k] else: 0'u8
          if rByte < tByte:
            ge = false
            break
          elif rByte > tByte:
            break

        if not ge:
          break

        # Subtract targetPlusOne from remainder
        var borrow: int16 = 0
        for k in 0 ..< 32:
          let diff = int16(remainder[k]) - int16(targetPlusOne[k]) - borrow
          if diff < 0:
            remainder[k] = byte((diff + 256) and 0xFF)
            borrow = 1
          else:
            remainder[k] = byte(diff)
            borrow = 0
        if borrow != 0:
          remainder[32] = byte(int16(remainder[32]) - 1)

        quotient += 1
        if quotient == 255:
          break  # Prevent infinite loop

      result[i] = quotient

proc addWork*(a, b: array[32, byte]): array[32, byte] =
  ## Add two 256-bit work values
  var carry: uint16 = 0
  for i in 0 ..< 32:
    let sum = uint16(a[i]) + uint16(b[i]) + carry
    result[i] = byte(sum and 0xFF)
    carry = sum shr 8

proc compareWork*(a, b: array[32, byte]): int =
  ## Compare two 256-bit work values
  ## Returns: -1 if a < b, 0 if a == b, 1 if a > b
  for i in countdown(31, 0):
    if a[i] < b[i]:
      return -1
    elif a[i] > b[i]:
      return 1
  0

proc isZeroWork*(w: array[32, byte]): bool =
  for b in w:
    if b != 0:
      return false
  true

# =============================================================================
# HeaderChain management
# =============================================================================

proc initHeaderChain*(): HeaderChain =
  HeaderChain(
    headers: @[],
    byHash: initTable[BlockHash, int](),
    tip: BlockHash(default(array[32, byte])),
    tipHeight: -1,
    totalWork: default(array[32, byte]),
    sideHeaders: initTable[BlockHash, SideHeader]()
  )

proc initHeaderChain*(genesisHeader: BlockHeader, genesisHash: BlockHash): HeaderChain =
  ## Initialize header chain with genesis block
  result = initHeaderChain()
  result.headers.add(genesisHeader)
  result.hashes.add(genesisHash)
  result.byHash[genesisHash] = 0
  result.tip = genesisHash
  result.tipHeight = 0
  result.totalWork = calculateWork(genesisHeader.bits)

proc hasHeader*(hc: HeaderChain, hash: BlockHash): bool =
  hash in hc.byHash

proc getHeader*(hc: HeaderChain, hash: BlockHash): Option[BlockHeader] =
  if hash in hc.byHash:
    some(hc.headers[hc.byHash[hash]])
  else:
    none(BlockHeader)

proc getHeaderByHeight*(hc: HeaderChain, height: int32): Option[BlockHeader] =
  if height >= 0 and height < int32(hc.headers.len):
    some(hc.headers[height])
  else:
    none(BlockHeader)

proc getHashByHeight*(hc: HeaderChain, height: int32): Option[BlockHash] =
  if height >= 0 and height < int32(hc.hashes.len):
    some(hc.hashes[height])
  else:
    none(BlockHash)

proc getHeight*(hc: HeaderChain, hash: BlockHash): Option[int32] =
  ## Look up the height of a block by its hash
  if hash in hc.byHash:
    some(int32(hc.byHash[hash]))
  else:
    none(int32)

# -----------------------------------------------------------------------------
# Fork-aware resolution (Part 1: competing-branch / reorg support)
#
# A header that branches BELOW the active tip cannot be resolved by the linear
# active-chain helpers above (they only walk `headers`/`hashes` by height).
# These helpers resolve a parent against BOTH the active chain and the
# `sideHeaders` fork map, mirroring how Bitcoin Core's single CBlockIndex map
# holds active + fork headers together.
# -----------------------------------------------------------------------------

proc hasAnyHeader*(hc: HeaderChain, hash: BlockHash): bool =
  ## True if `hash` is known either on the active chain or as a fork header.
  hash in hc.byHash or hash in hc.sideHeaders

proc resolveParentWork*(hc: HeaderChain,
                        prevHash: BlockHash): Option[tuple[height: int32,
                                                           totalWork: array[32, byte]]] =
  ## Resolve the parent of an incoming fork header to its (height, cumulative
  ## work) using either the active chain or the sideHeaders map.  Returns none
  ## if the parent is not known at all (genuine orphan).
  ##
  ## For an active-chain parent the cumulative work is summed from genesis with
  ## the SAME canonical work path (`calculateWork`/`addWork`) that builds
  ## `headerChain.totalWork`, so a fork's totalWork is directly comparable to
  ## the active chain's totalWork (Core nChainWork parity, one work path).
  if prevHash in hc.byHash:
    let idx = hc.byHash[prevHash]
    var w: array[32, byte]
    for i in 0 .. idx:
      w = addWork(w, calculateWork(hc.headers[i].bits))
    return some((height: int32(idx), totalWork: w))
  if prevHash in hc.sideHeaders:
    let sh = hc.sideHeaders[prevHash]
    return some((height: sh.height, totalWork: sh.totalWork))
  none(tuple[height: int32, totalWork: array[32, byte]])

proc heaviestSideTip*(hc: HeaderChain): Option[SideHeader] =
  ## Return the fork header (if any) whose cumulative work is the greatest
  ## among all sideHeaders.  This is the candidate competing-chain tip that
  ## requestBlocks walks down to discover the bodies it must fetch.
  var best: Option[SideHeader] = none(SideHeader)
  for sh in hc.sideHeaders.values:
    if best.isNone or compareWork(sh.totalWork, best.get().totalWork) > 0:
      best = some(sh)
  best

# =============================================================================
# bad-diffbits AT HEADER ADMISSION  (Bitcoin Core validation.cpp:4083-4089)
#
# THE RULE.  ContextualCheckBlockHeader's FIRST check — before time-too-old,
# before the BIP94 timewarp floor, before bad-version:
#
#     assert(pindexPrev != nullptr);                              // :4083
#     const int nHeight = pindexPrev->nHeight + 1;                // :4084
#     if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
#         return state.Invalid(..., "bad-diffbits", ...);         // :4088-4089
#
# and Core runs it for EVERY header, active-extension or competing fork, on
# EVERY network, from AcceptBlockHeader (validation.cpp:4224).
#
# This is NOT the high-hash check.  CheckBlockHeader (validation.cpp:3832 ->
# CheckProofOfWork) only proves the hash meets the target the header ITSELF
# declares — for a difficulty-1 claim that is almost no work at all.  The gate
# here compares the DECLARED nBits against the REQUIRED nBits.  Without it a
# peer can hand us an arbitrarily long difficulty-1 header chain, which is
# exactly the unbounded block-index growth Core documents at
# validation.cpp:4076-4078 (bitcoincore.org/en/2024/07/03/disclose-header-spam).
#
# WHAT WAS WRONG HERE (pre-fix):
#   * the FORK arm (acceptForkHeader) ran no nBits check at all, on any
#     network — a below-tip branch of difficulty-1 headers was admitted 2000
#     at a time into an unbounded `sideHeaders` Table and persisted to RocksDB;
#   * the ACTIVE arm delegated the non-retarget case on testnet3/testnet4 to
#     `permittedDifficultyTransition`, which returns `true` UNCONDITIONALLY
#     when powAllowMinDifficultyBlocks (pow.nim:216-217).  That proc is a
#     faithful port of Core pow.cpp:89-91, but Core only uses it as the
#     PRESYNC commitment heuristic (headerssync.cpp:189,237) and NEVER as the
#     admission gate — so any nBits was accepted at any non-retarget height;
#   * the whole retarget check was skipped when `params.network == Regtest`,
#     while Core enforces bad-diffbits on regtest too.
#
# ANCESTOR RESOLUTION — POINTER WALK ONLY.  Core resolves retarget ancestors
# with CBlockIndex::GetAncestor / pprev (pow.cpp:33, pow.cpp:44), i.e. by
# following parent POINTERS.  The resolution below does the same: every hop is
# `lookupHeaderByHash(cur.header.prevBlock)`.  It NEVER indexes by a height
# number.  A height->hash / height->header index (`hc.headers[h]`,
# `hc.hashes[h]`, `chainDb.getBlockHashByHeight`) describes OUR ACTIVE CHAIN,
# not the candidate's ancestry, and does not contain entries above the
# validated tip — consulting it at a boundary hands back an unrelated block,
# so the honest header is rejected and an attacker who matched the poisoned
# answer is ADMITTED.  (The pre-fix `validateDifficultyRetarget` read
# `hc.headers[prevHeight]` / `hc.headers[intervalStart]`; it was sound only by
# accident of its caller having already proved active-tip extension.)
#
# "INVALID" vs "WE CANNOT EVALUATE".  Core has no unresolvable case: a header
# whose parent is absent is rejected as "prev-blk-not-found"
# (validation.cpp:4215-4217) BEFORE ContextualCheckBlockHeader, which then
# asserts pindexPrev != nullptr.  nimrod's in-memory index CAN be short of an
# ancestor the rule needs (a fork header stored before a restart, a
# snapshot-truncated header chain).  That is OUR gap, not evidence of peer
# misbehaviour, so it gets its own outcome: drop the header, ask for the
# bridging headers, apply NO peer penalty.
# =============================================================================

type
  DiffbitsOutcome* = enum
    ## Verdict of the Core validation.cpp:4088 gate for a single header.
    dboOk            ## header.nBits == GetNextWorkRequired -> gate passed
    dboBadDiffbits   ## header.nBits != GetNextWorkRequired -> header is
                     ## INVALID; rejecting it (and penalising the sender) is
                     ## fair.  Core token: "bad-diffbits".
    dboUnevaluable   ## an ancestor the rule needs is not in OUR index, so we
                     ## cannot compute the required nBits.  The header is NOT
                     ## known-invalid — drop it, request the bridging headers,
                     ## and do NOT penalise the peer.

const HeaderErrCannotEvaluate* = "cannot-evaluate-diffbits"
  ## `validateHeader` error token for dboUnevaluable.  Callers MUST treat this
  ## as "our gap", never as peer misbehaviour (see `isUnevaluableHeaderError`).

proc isUnevaluableHeaderError*(err: string): bool {.inline.} =
  ## True when `validateHeader`'s rejection means "we could not evaluate the
  ## rule", not "the header is invalid".  Never ban/penalise on this.
  err == HeaderErrCannotEvaluate

proc lookupHeaderByHash*(hc: HeaderChain, hash: BlockHash):
    Option[tuple[header: BlockHeader, height: int32]] =
  ## Resolve a header BY HASH across the active chain and the competing-fork
  ## map — nimrod's equivalent of Core's single CBlockIndex map lookup
  ## (m_block_index.find(hash), validation.cpp:4214).
  ##
  ## The active chain is a flat seq whose position IS the height, so the index
  ## returned by `byHash` doubles as the height.  Note the direction: the array
  ## slot is derived FROM THE HASH.  This is a hash lookup, not a height
  ## lookup; no caller passes a height number in.
  if hash in hc.byHash:
    let idx = hc.byHash[hash]
    if idx >= 0 and idx < hc.headers.len:
      return some((header: hc.headers[idx], height: int32(idx)))
  if hash in hc.sideHeaders:
    let sh = hc.sideHeaders[hash]
    return some((header: sh.header, height: sh.height))
  none(tuple[header: BlockHeader, height: int32])

proc requiredBitsForHeader*(hc: HeaderChain, header: BlockHeader,
                            params: ConsensusParams):
    tuple[outcome: DiffbitsOutcome, required: uint32] =
  ## Compute GetNextWorkRequired for `header` against ITS OWN parent chain.
  ##
  ## Reuses `pow.getNextWorkRequired` (pow.nim:124-183) — the existing,
  ## Core-faithful, separately-tested retarget implementation (min-difficulty
  ## rule, walk-back to the last non-powLimit ancestor, BIP94 first-block-bits
  ## anchoring).  No consensus math is re-implemented here; this proc only
  ## supplies the parent and the ancestor walk.
  ##
  ## Height comes from the RESOLVED PARENT (`parent.height + 1` inside
  ## pow.getNextWorkRequired via `lastIndex.height + 1`, mirroring
  ## validation.cpp:4084) — never from a batch counter or queue position.
  let parentOpt = hc.lookupHeaderByHash(header.prevBlock)
  if parentOpt.isNone:
    # Core would already have rejected this as "prev-blk-not-found"; for us it
    # may simply be an ancestor we have not stored.  Not our call to make here.
    return (dboUnevaluable, 0'u32)
  let parent = parentOpt.get()

  # `hc` is captured through a pointer so the closure environment does not copy
  # the whole header chain (seq + tables) on every header.  The closure never
  # escapes this proc — getNextWorkRequired calls it synchronously.
  let hcp = unsafeAddr hc
  var resolveFailed = false

  proc getAncestor(idx: pow.BlockIndex, targetHeight: int32): pow.BlockIndex =
    ## Core CBlockIndex::GetAncestor, done by PREV-POINTER hops.
    ## Each step follows `cur.header.prevBlock`; nothing is looked up by
    ## height.  A missing link sets `resolveFailed` (checked by the caller)
    ## and returns a stub AT the requested height purely so the callers' loops
    ## terminate — the stub value is never trusted, because any resolveFailed
    ## forces dboUnevaluable below.
    var cur = idx
    while cur.height > targetHeight:
      let up = hcp[].lookupHeaderByHash(cur.header.prevBlock)
      if up.isNone or up.get().height >= cur.height:
        resolveFailed = true
        return pow.BlockIndex(height: targetHeight,
                              header: default(BlockHeader),
                              hash: default(BlockHash))
      let p = up.get()
      cur = pow.BlockIndex(height: p.height, header: p.header,
                           hash: cur.header.prevBlock)
    cur

  let powPrev = pow.BlockIndex(height: parent.height, header: parent.header,
                               hash: header.prevBlock)
  let powParams = headerssync.toPowParams(params)

  # `pow.GetAncestorFn` carries no `raises` annotation, so the compiler cannot
  # prove this call is exception-free and the effect would leak all the way up
  # into the async `handleHeaders`.  The walk itself is pure seq/Table reads and
  # arithmetic; if anything ever did escape, the only safe reading is "we could
  # not evaluate the rule" — fail closed on the header, never on the peer.
  # The `cast(gcsafe)` is for the same reason: an unannotated `proc` type is
  # assumed neither gcsafe nor raises-free.  `getAncestor` touches only the
  # header chain handed in and its own locals — no globals, no thread-shared
  # state — so the cast asserts something the walk genuinely satisfies.
  var required = 0'u32
  {.cast(gcsafe).}:
    try:
      required = pow.getNextWorkRequired(powPrev, header.timestamp, powParams,
                                         getAncestor)
    except Exception:
      resolveFailed = true

  if resolveFailed:
    return (dboUnevaluable, 0'u32)
  (dboOk, required)

proc checkHeaderDiffbits*(hc: HeaderChain, header: BlockHeader,
                          params: ConsensusParams): DiffbitsOutcome =
  ## Bitcoin Core validation.cpp:4086-4089 — the bad-diffbits gate.
  ## `if (block.nBits != GetNextWorkRequired(pindexPrev, &block, params))`.
  let r = hc.requiredBitsForHeader(header, params)
  if r.outcome != dboOk:
    return r.outcome
  if header.bits != r.required:
    return dboBadDiffbits
  dboOk

# =============================================================================
# Header validation
# =============================================================================

proc validateHeaderPoW*(header: BlockHeader): bool =
  ## Check that the header hash meets its difficulty target
  let headerBytes = serialize(header)
  let hash = BlockHash(doubleSha256(headerBytes))
  hashMeetsTarget(hash, header.bits)

proc validateHeaderChainLink*(header: BlockHeader, prevHeader: BlockHeader): bool =
  ## Check that header links correctly to previous header (recomputes hash)
  let prevBytes = serialize(prevHeader)
  let prevHash = BlockHash(doubleSha256(prevBytes))
  header.prevBlock == prevHash

proc validateHeaderChainLinkByHash*(header: BlockHeader, prevHash: BlockHash): bool =
  ## Check that header links correctly to previous header using stored hash
  header.prevBlock == prevHash

proc getMedianTimePastFromChain*(hc: HeaderChain, height: int32): uint32 =
  ## Calculate MTP from the header chain
  ## Uses timestamps of the previous 11 blocks
  var timestamps: seq[uint32]

  let startHeight = max(0, height - MedianTimeSpan + 1)
  for h in startHeight .. height:
    if h < int32(hc.headers.len):
      timestamps.add(hc.headers[h].timestamp)

  if timestamps.len == 0:
    return 0

  timestamps.sort()
  timestamps[timestamps.len div 2]

proc validateHeaderMTP*(header: BlockHeader, hc: HeaderChain, height: int32): bool =
  ## Validate that header timestamp is greater than MTP of previous 11 blocks
  if height == 0:
    return true  # Genesis has no MTP requirement

  let mtp = getMedianTimePastFromChain(hc, height - 1)
  header.timestamp > mtp

proc validateDifficultyRetarget*(header: BlockHeader, hc: HeaderChain,
                                  height: int32, params: ConsensusParams): bool =
  ## DEPRECATED — kept only so out-of-tree callers keep compiling.
  ##
  ## This used to be the header path's difficulty check, and it was wrong twice
  ## over:  (a) it resolved the retarget base through the HEIGHT INDEX
  ## (`hc.headers[prevHeight]`, `hc.headers[intervalStart]`), which describes
  ## our ACTIVE chain rather than the candidate header's own ancestry, and
  ## (b) on powAllowMinDifficultyBlocks networks it delegated the non-retarget
  ## case to `permittedDifficultyTransition`, which returns `true`
  ## unconditionally there (pow.nim:216-217) — Core uses that proc only as the
  ## PRESYNC heuristic (headerssync.cpp:189,237), never as the admission gate.
  ##
  ## It now forwards to the single pointer-walk implementation so there is only
  ## one copy of the rule.  Note the collapse of dboUnevaluable to `false`:
  ## that is why this wrapper must NOT be used for admission decisions — the
  ## admission path needs to tell "invalid header" apart from "we cannot
  ## evaluate the rule".  Use `checkHeaderDiffbits` instead.
  if height == 0:
    return true  # Genesis has no parent to measure against.
  checkHeaderDiffbits(hc, header, params) == dboOk

proc validateHeader*(header: BlockHeader, hc: HeaderChain, height: int32,
                     params: ConsensusParams,
                     minPowChecked: bool = true): tuple[valid: bool, error: string] =
  ## Full header validation
  ##
  ## minPowChecked: true if the PRESYNC anti-DoS pipeline has already
  ##   confirmed that the claimed chain work meets params.minimumChainWork.
  ##   Pass false for headers from random peers before PRESYNC completes.
  ##   Reference: validation.cpp:4229 — `if (!min_pow_checked)`.

  # G8 (W97): too-little-chainwork gate.
  # Reject if PRESYNC has not validated the work AND the network has a
  # non-zero minimumChainWork threshold (regtest sets it to all-zeros).
  if not minPowChecked:
    var isZeroMinWork = true
    for b in params.minimumChainWork:
      if b != 0:
        isZeroMinWork = false
        break
    if not isZeroMinWork:
      return (false, "too-little-chainwork")

  # Check proof of work
  if not validateHeaderPoW(header):
    return (false, "invalid proof of work")

  # Check chain linkage for non-genesis.
  # Core's "prev-blk-not-found" (validation.cpp:4215-4217) — the lookup that
  # runs BEFORE ContextualCheckBlockHeader and is what lets Core assert
  # pindexPrev != nullptr at validation.cpp:4083.  This is the ACTIVE-arm
  # variant: the header must extend our current tip.  (The height index is
  # used here only to name "our tip"; it plays no part in resolving the
  # candidate's retarget ancestors below.)
  if height > 0:
    if height - 1 >= int32(hc.hashes.len):
      return (false, "previous header not found")

    let prevHash = hc.hashes[height - 1]
    if not validateHeaderChainLinkByHash(header, prevHash):
      return (false, "header does not link to previous")

    # ------------------------------------------------------------------
    # ContextualCheckBlockHeader, in Bitcoin Core's order.
    # ------------------------------------------------------------------

    # Gate 1 — bad-diffbits.  THE FIRST contextual check, validation.cpp:4086-4089,
    # ahead of time-too-old / BIP94 timewarp / time-too-new / bad-version.
    # Ancestors resolved by prev-pointer hops, never by height (see
    # `requiredBitsForHeader`).
    case checkHeaderDiffbits(hc, header, params)
    of dboOk:
      discard
    of dboBadDiffbits:
      # The header IS invalid — Core's "bad-diffbits" / BLOCK_INVALID_HEADER.
      return (false, "bad-diffbits")
    of dboUnevaluable:
      # WE cannot evaluate the rule (an ancestor is missing from our index).
      # Not a peer offence: the caller must drop without penalty.
      return (false, HeaderErrCannotEvaluate)

    # Gate 2 — time-too-old (MTP).  Core validation.cpp:4092-4093.
    if not validateHeaderMTP(header, hc, height):
      return (false, "timestamp not greater than MTP")

  # time-too-new.  Core validation.cpp:4108.
  let now = getTime().toUnix().uint32
  if header.timestamp > now + uint32(MaxFutureBlockTime):
    return (false, "timestamp too far in future")

  (true, "")

# =============================================================================
# SyncManager
# =============================================================================

proc loadHeaderChainFromDb*(chainDb: ChainDb,
                            params: ConsensusParams): HeaderChain =
  ## Reconstruct the in-memory header chain from the persisted block index.
  ##
  ## The header chain is otherwise NOT persisted: every restart re-initialised
  ## it to genesis only (`tipHeight == 0`) even though the block chainstate was
  ## hundreds of thousands of blocks ahead.  nimrod then had to re-sync every
  ## header from genesis on each restart — a multi-hour operation that, on
  ## mainnet, also tripped the W97/W162 anti-DoS path.  (See the long-standing
  ## "TODO: Load header chain from database" this proc replaces.)
  ##
  ## The block index already stores, for every block on the active chain, the
  ## full `BlockHeader` and the cumulative `totalWork` (see `BlockIndex` in
  ## storage/chainstate.nim).  Walking height 0..bestHeight and copying those
  ## headers in rebuilds the header chain exactly — no network round-trips, no
  ## re-validation, and consistent with the block index by construction.
  ##
  ## Bitcoin Core does the equivalent in `BlockManager::LoadBlockIndex` /
  ## `CChainState::LoadChainTip`: the block-tree (CBlockIndex map, headers
  ## included) is loaded from disk on startup, never re-downloaded.
  ##
  ## On any inconsistency (a missing height->hash row, a missing BlockIndex, a
  ## prevHash that does not link) the reload stops and returns whatever prefix
  ## linked cleanly; the caller treats a short result as "re-sync the rest"
  ## rather than failing startup.  A genesis-only chain is always a valid
  ## fallback because the live header-sync path can rebuild forward from it.
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  result = initHeaderChain(genesis.header, genesisHash)

  let bestHeight = chainDb.bestHeight
  if bestHeight <= 0:
    # Nothing beyond genesis to load.
    return

  var prevHash = genesisHash
  var loaded: int32 = 0
  for height in 1'i32 .. bestHeight:
    let hashOpt = chainDb.getBlockHashByHeight(height)
    if hashOpt.isNone:
      warn "header-chain reload: missing height->hash, stopping",
           height = height, loaded = loaded
      break
    let hash = hashOpt.get()

    let idxOpt = chainDb.getBlockIndex(hash)
    if idxOpt.isNone:
      warn "header-chain reload: missing block index, stopping",
           height = height, hash = $hash, loaded = loaded
      break
    let idx = idxOpt.get()

    # The header must link onto the prefix we have already accepted.  A break
    # in the chain means the index is inconsistent; stop and let the live
    # header sync rebuild from the clean prefix.
    if idx.header.prevBlock != prevHash:
      warn "header-chain reload: prevHash mismatch, stopping",
           height = height, hash = $hash, loaded = loaded
      break

    let arrayIdx = result.headers.len
    result.headers.add(idx.header)
    result.hashes.add(hash)
    result.byHash[hash] = arrayIdx
    result.tip = hash
    result.tipHeight = height
    # Use the cumulative work the block index already cached for this block
    # (kept consistent with connectBlock); no need to re-sum per header.
    result.totalWork = idx.totalWork
    prevHash = hash
    inc loaded

  info "reloaded header chain from block index",
       tipHeight = result.tipHeight, bestHeight = bestHeight, loaded = loaded

proc newSyncManager*(pm: PeerManager, chainDb: ChainDb,
                     params: ConsensusParams,
                     chainState: ChainState = nil,
                     numVerifyWorkers: int = 0,
                     filterIndex: BlockFilterIndex = nil,
                     coinStatsIndex: CoinStatsIndex = nil,
                     txoSpenderIndex: TxoSpenderIndex = nil): SyncManager =
  result = SyncManager(
    state: ssIdle,
    headerChain: initHeaderChain(),
    peerManager: pm,
    chainDb: chainDb,
    chainState: chainState,
    params: params,
    syncPeer: nil,
    blockQueue: initDeque[BlockHash](),
    pendingBlocks: 0,
    lastSyncTime: getTime(),
    headerTip: BlockHash(default(array[32, byte])),
    headerTipHeight: -1,
    chainTip: BlockHash(default(array[32, byte])),
    chainTipHeight: -1,
    # Anti-DoS header sync state
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    # Anti-DoS work threshold.  Core's GetAntiDoSWorkThreshold() returns
    # max(near_chaintip_work, m_chainman.MinimumChainWork()), and
    # MinimumChainWork() defaults to GetConsensus().nMinimumChainWork
    # (validation.cpp:6130).  Wiring this from params is REQUIRED: with a
    # zero threshold, tryLowWorkHeadersSync() always sees
    # totalWork >= threshold and never starts a PRESYNC sync, so the entire
    # anti-DoS pipeline is dead code and a from-genesis batch falls through
    # to direct validation with minPowChecked=false → "too-little-chainwork"
    # → honest peer banned.  (W97-followup: this field was left zero with a
    # stale "Will be set from chainstate" comment but nothing ever set it.)
    minimumChainWork: initUInt256(params.minimumChainWork),
    receivedBlocks: initTable[int32, Block](),
    requestedHashes: initHashSet[BlockHash](),
    unconnectingHeaders: initTable[int64, int](),
    headerTipRepairAt: -1'i32,
    numVerifyWorkers: numVerifyWorkers,
    filterIndex: filterIndex,
    coinStatsIndex: coinStatsIndex,
    txoSpenderIndex: txoSpenderIndex
  )

  # Initialize with genesis if chain is empty
  if chainDb.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    # Use the canonical genesis hash from params (buildGenesisBlock may not
    # produce a byte-identical coinbase for all networks)
    let genesisHash = params.genesisBlockHash
    result.headerChain = initHeaderChain(genesis.header, genesisHash)
    result.headerTip = genesisHash
    result.headerTipHeight = 0
    result.chainTip = genesisHash
    result.chainTipHeight = 0
  else:
    # Load existing chain tip
    result.chainTip = chainDb.bestBlockHash
    result.chainTipHeight = chainDb.bestHeight
    result.headerTip = chainDb.bestBlockHash
    result.headerTipHeight = chainDb.bestHeight

    # At genesis height, use the canonical hash from params to avoid mismatch
    # between buildGenesisBlock's computed hash and the well-known genesis hash
    if chainDb.bestHeight == 0:
      result.chainTip = params.genesisBlockHash
      result.headerTip = params.genesisBlockHash

    # Reload the header chain from the persisted block index instead of
    # starting fresh at genesis.  Previously this was a "TODO: Load header
    # chain from database" that left headerChain at tipHeight==0 — forcing a
    # full from-genesis header re-sync on every restart and (on mainnet)
    # tripping the W97/W162 anti-DoS path.  The block index already holds
    # every header on the active chain, so this is a pure local reload.
    result.headerChain = loadHeaderChainFromDb(chainDb, params)
    # Keep the cheap headerTip/headerTipHeight summary fields consistent with
    # whatever prefix actually linked (loadHeaderChainFromDb stops early on a
    # corrupt index and returns the clean prefix; the live header sync then
    # rebuilds forward from there).
    result.headerTip = result.headerChain.tip
    result.headerTipHeight = result.headerChain.tipHeight
    # Seed best-header info on ChainState from the loaded header chain so
    # the assumevalid skip gate has real values from the first block connect
    # (before any live header messages arrive).
    if chainState != nil and result.headerChain.headers.len > 0:
      chainState.updateBestHeaderInfo(
        result.headerChain.totalWork,
        result.headerChain.tipHeight,
        result.headerChain.headers[^1].bits
      )

proc reconcileHeaderTip*(sm: SyncManager): bool =
  ## LIVENESS FIX (A), self-heal half.  `headerChain.tipHeight < chainTipHeight`
  ## is an INVARIANT VIOLATION: the validated chain cannot legitimately be ahead
  ## of the header index, because a block can only be connected after its header
  ## was accepted.  Bitcoin Core cannot even express this state — AcceptBlock's
  ## first act is AcceptBlockHeader (validation.cpp:4308), which inserts the
  ## CBlockIndex that IS the header index, so headers and connected blocks are
  ## the same objects in the same `m_block_index`.  nimrod keeps two structures,
  ## and its side-branch/reorg arm writes only one of them.
  ##
  ## When the violation is observed, re-seed the header chain from the persisted
  ## block index — exactly what boot does (`newSyncManager` ->
  ## `loadHeaderChainFromDb`), which is why a restart cleared the mainnet wedge
  ## instantly ("first batch accepted=9 tipHeight=963741").  Doing it at runtime
  ## is the whole fix: the recovery already existed, it was just unreachable
  ## without a process restart.
  ##
  ## Returns true if a repair was performed.  Cheap to call: the guard is an
  ## int comparison, and the O(bestHeight) walk only runs on a real violation.
  if sm.chainTipHeight <= sm.headerChain.tipHeight:
    return false
  if sm.chainDb == nil:
    return false
  # A repair that could not close the gap (truncated/corrupt index prefix) must
  # not be retried until the chain moves, or we would walk the whole index on
  # every sync-loop iteration.
  if sm.headerTipRepairAt == sm.chainTipHeight:
    return false
  sm.headerTipRepairAt = sm.chainTipHeight

  let staleHeight = sm.headerChain.tipHeight
  warn "INVARIANT VIOLATION: header tip is BEHIND the validated chain — " &
       "re-seeding header chain from the block index",
       headerTipHeight = staleHeight,
       chainTipHeight = sm.chainTipHeight,
       behindBy = sm.chainTipHeight - staleHeight,
       sideHeaders = sm.headerChain.sideHeaders.len

  var rebuilt = loadHeaderChainFromDb(sm.chainDb, sm.params)
  if rebuilt.tipHeight <= staleHeight:
    error "header-chain re-seed FAILED to advance the header tip — " &
          "block index cannot cover the validated chain",
          headerTipHeight = staleHeight,
          chainTipHeight = sm.chainTipHeight,
          reloadedTipHeight = rebuilt.tipHeight
    return false

  # Carry forward only GENUINE competing forks.  Any sideHeaders entry whose
  # hash is now on the rebuilt active chain was a real-chain header that the
  # fork arm mis-filed; leaving it would keep `hasAnyHeader` reporting "already
  # known" for headers we want to (re)connect, which is the poisoned state that
  # produced accepted=0 on every batch.
  for hash, sh in sm.headerChain.sideHeaders:
    if hash notin rebuilt.byHash:
      rebuilt.sideHeaders[hash] = sh

  let carried = rebuilt.sideHeaders.len
  let dropped = sm.headerChain.sideHeaders.len - carried

  sm.headerChain = rebuilt
  sm.headerTip = rebuilt.tip
  sm.headerTipHeight = rebuilt.tipHeight

  if sm.chainState != nil and rebuilt.headers.len > 0:
    sm.chainState.updateBestHeaderInfo(
      rebuilt.totalWork, rebuilt.tipHeight, rebuilt.headers[^1].bits)

  warn "header chain re-seeded from the validated chain (self-heal, no restart)",
       fromHeight = staleHeight, toHeight = rebuilt.tipHeight,
       sideHeadersDropped = dropped, sideHeadersKept = carried
  true

proc selectSyncPeer*(sm: SyncManager): Peer =
  ## Select the best peer for syncing (highest reported height)
  sm.peerManager.getBestPeer()

proc buildLocatorFromHeight*(sm: SyncManager, startHeight: int32):
    seq[array[32, byte]] =
  ## Build a block locator with exponential backoff starting from `startHeight`.
  ## Equivalent of Bitcoin Core's chain.cpp::LocatorEntries(index): collect
  ## hashes at heights startHeight, startHeight-1, ..., startHeight-9, then
  ## doubling step back to 0, always terminating with the genesis hash.
  ##
  ## Used by both buildBlockLocator (startHeight == headerChain.tipHeight) and
  ## the PRESYNC/REDOWNLOAD locator path (startHeight == chainStartHeight): the
  ## latter previously sent only two entries (lastHeaderHash + chainStartHash),
  ## so a peer that had pruned or simply did not recognise either would either
  ## return no headers or silently restart at chain_start, causing the next
  ## PRESYNC batch's continuity check to fail and the entire low-work pipeline
  ## to tear down — see CORE-PARITY-AUDIT/_nimrod-presync-part2-2026-05-27.md.
  result = @[]

  var step = 1
  var height = startHeight

  while height >= 0:
    # LIVENESS FIX (A).  Resolve the height against the header chain FIRST,
    # then fall back to the persisted block index.  Bitcoin Core has only one
    # index to resolve against: LocatorEntries walks CBlockIndex pointers via
    # GetAncestor (chain.cpp:26-44), and those same objects carry both the
    # header and the validation status.  nimrod's in-memory `headerChain` is a
    # PROJECTION of that index which can be short (a truncated reload prefix,
    # or a tip advanced through the side-branch/reorg arm), so a header-chain
    # miss must not silently drop the entry from the locator.
    var hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isNone and sm.chainDb != nil and height <= sm.chainDb.bestHeight:
      hashOpt = sm.chainDb.getBlockHashByHeight(height)
    if hashOpt.isSome:
      result.add(array[32, byte](hashOpt.get()))

    # After 10 hashes, use exponential backoff
    if result.len > 10:
      step *= 2

    height -= int32(step)

  # Always include genesis
  let genesisHash = array[32, byte](sm.params.genesisBlockHash)
  if result.len == 0 or result[^1] != genesisHash:
    result.add(genesisHash)

proc locatorStartHeight*(sm: SyncManager): int32 =
  ## The height the getheaders locator is seeded from.
  ##
  ## LIVENESS FIX (A) — THE INVARIANT: the locator must NEVER be seeded BEHIND
  ## the validated chain.  Bitcoin Core states this literally in
  ## `ChainstateManager::RecalculateBestHeader` (validation.cpp:6256-6264):
  ##
  ##     m_best_header = ActiveChain().Tip();
  ##     for (auto& entry : m_blockman.m_block_index)
  ##         if (!(entry.second.nStatus & BLOCK_FAILED_VALID) &&
  ##             m_best_header->nChainWork < entry.second.nChainWork)
  ##             m_best_header = &entry.second;
  ##
  ## i.e. the header pointer that every getheaders locator is built from
  ## (net_processing.cpp:2657, :3106, :4110 — `GetLocator(m_best_header)`) is
  ## SEEDED FROM THE ACTIVE TIP and can only go up from there.  The same
  ## floor is re-applied defensively at net_processing.cpp:5771-5772.
  ##
  ## nimrod tracks `headerChain.tipHeight` separately from `chainTipHeight`,
  ## and the side-branch/reorg arm advances the chain tip WITHOUT extending the
  ## header chain (see the "Update chain tip (NOT header tip ...)" comment in
  ## applyBlock and the sboReorged arm of processSideBranchBody).  On mainnet
  ## 2026-08-16..23 that left headerTip=962722 while the chain reached 963732:
  ## every getheaders was seeded 1,010 blocks behind, so peers answered with
  ## headers the node already had, every batch graded accepted=0, and the node
  ## livelocked for a week.  max() is the cheap structural floor.
  max(sm.headerChain.tipHeight, sm.chainTipHeight)

proc buildBlockLocator*(sm: SyncManager): seq[array[32, byte]] =
  ## Build block locator with exponential backoff
  ## Returns hashes at heights: tip, tip-1, ..., tip-9, tip-11, tip-15, ..., 0
  sm.buildLocatorFromHeight(sm.locatorStartHeight())

# =============================================================================
# Anti-DoS Header Sync (PRESYNC/REDOWNLOAD)
# =============================================================================

proc getPeerId*(peer: Peer): int64 =
  ## Generate a stable peer ID from address and port
  ## Used for tracking per-peer header sync state
  ## Uses unsigned arithmetic to avoid overflow on long address strings
  var h: uint64 = 0
  for c in peer.address:
    h = h * 31 + uint64(ord(c))
  h = h * 31 + uint64(peer.port)
  cast[int64](h)

proc getAntiDoSWorkThreshold*(sm: SyncManager): UInt256 =
  ## Calculate the minimum chain work to accept headers without anti-DoS protection
  ## Returns max(near_chaintip_work, minimumChainWork)
  ## Reference: Bitcoin Core GetAntiDoSWorkThreshold() in net_processing.cpp

  # Start with the configured minimum chain work
  var threshold = sm.minimumChainWork

  # If we have a chain tip, use work within 144 blocks of tip
  if sm.chainTipHeight >= 0:
    # Get current tip work from header chain
    let tipWork = initUInt256(sm.headerChain.totalWork)

    # Calculate work for ~144 blocks (1 day)
    # Approximate: each block adds some work based on current difficulty
    # For simplicity, we use 144 times minimum block work
    # In practice, this should be calculated from actual difficulty
    let bufferBlocks = 144
    let tipHeader = sm.headerChain.getHeaderByHeight(sm.chainTipHeight)
    if tipHeader.isSome:
      let blockWork = headerssync.getBlockProof(tipHeader.get())
      let bufferWork = blockWork * uint64(bufferBlocks)

      # near_chaintip_work = tip_work - buffer_work (clamped to 0)
      var nearTipWork = initUInt256()
      if tipWork > bufferWork:
        nearTipWork = tipWork - bufferWork

      # Return max of near-tip work and configured minimum
      if nearTipWork > threshold:
        threshold = nearTipWork

  threshold

proc calculateClaimedHeadersWork*(headers: seq[BlockHeader]): UInt256 =
  ## Calculate the claimed work from a batch of headers
  result = initUInt256()
  for header in headers:
    result = result + headerssync.getBlockProof(header)

proc tryLowWorkHeadersSync*(sm: SyncManager, peer: Peer,
                             chainStartHeight: int32,
                             chainStartHash: BlockHash,
                             chainStartBits: uint32,
                             chainStartWork: UInt256,
                             headers: var seq[BlockHeader],
                             chainStartMtp: uint32 = 0,
                             chainStartTime: uint32 = 0): bool =
  ## Try to initiate low-work header sync for a peer
  ## Returns true if headers should be processed through anti-DoS sync
  ## Reference: Bitcoin Core TryLowWorkHeadersSync() in net_processing.cpp
  ##
  ## chainStartMtp: pass chain_start.GetMedianTimePast() for a tight
  ##   maxCommitments bound (headerssync.cpp:41-43). 0 = conservative fallback.
  ## chainStartTime: nTime of the chain_start block header; used to initialise
  ##   lastHeaderReceived.timestamp so getPresyncTime() returns meaningful data.

  let peerId = getPeerId(peer)

  # Calculate total claimed work
  let claimedWork = calculateClaimedHeadersWork(headers)
  let totalWork = chainStartWork + claimedWork

  # Get anti-DoS threshold
  let threshold = sm.getAntiDoSWorkThreshold()

  # If claimed work meets threshold, no need for anti-DoS sync
  if totalWork >= threshold:
    return false

  # Only trigger if message is full (peer has more headers)
  if headers.len < MaxHeadersPerRequest:
    debug "ignoring low-work headers (incomplete message)",
          peer = $peer, headers = headers.len, work = $totalWork
    headers = @[]  # Clear headers to prevent normal processing
    return true

  # Initialize header sync state for this peer
  info "starting low-work header sync",
       peer = $peer, height = chainStartHeight, work = $totalWork

  let syncState = newHeadersSyncState(
    peerId = peerId,
    params = sm.params,
    chainStartHeight = chainStartHeight,
    chainStartHash = chainStartHash,
    chainStartBits = chainStartBits,
    chainStartWork = chainStartWork,
    minimumRequiredWork = threshold,
    chainStartMtp = chainStartMtp,
    chainStartTime = chainStartTime
  )

  sm.peerHeadersSync[peerId] = syncState

  # Process the initial batch of headers through the sync state
  let result = syncState.processNextHeaders(headers, headers.len >= MaxHeadersPerRequest)

  if result.success:
    # Update presync stats
    sm.headersPresyncStats[peerId] = HeadersPresyncStats(
      work: syncState.getPresyncWork(),
      height: syncState.getPresyncHeight(),
      timestamp: syncState.getPresyncTime(),
      inPresync: syncState.getState() == Presync
    )

    # Track best peer for presync
    if syncState.getPresyncWork() > sm.presyncBestWork:
      sm.presyncBestWork = syncState.getPresyncWork()
      sm.presyncBestPeer = peerId

  # Clear original headers (processed through sync state)
  headers = result.powValidatedHeaders
  true

proc isContinuationOfLowWorkHeadersSync*(sm: SyncManager, peer: Peer,
                                          headers: var seq[BlockHeader]): bool =
  ## Check if this peer has an active low-work header sync and process headers
  ## Returns true if headers were processed through anti-DoS sync
  ## Reference: Bitcoin Core IsContinuationOfLowWorkHeadersSync()

  let peerId = getPeerId(peer)

  if peerId notin sm.peerHeadersSync:
    return false

  let syncState = sm.peerHeadersSync[peerId]

  if syncState.getState() == Done:
    # Sync is complete, clean up
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)
    return false

  # Process headers through the sync state
  let fullMessage = headers.len >= MaxHeadersPerRequest
  let result = syncState.processNextHeaders(headers, fullMessage)

  if not result.success:
    # Peer misbehaved during sync
    warn "low-work header sync failed",
         peer = $peer, state = $syncState.getState()
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)
    headers = @[]
    return true

  # Update stats
  if syncState.getState() != Done:
    sm.headersPresyncStats[peerId] = HeadersPresyncStats(
      work: syncState.getPresyncWork(),
      height: syncState.getPresyncHeight(),
      timestamp: syncState.getPresyncTime(),
      inPresync: syncState.getState() == Presync
    )

    # Update best peer tracking
    if syncState.getPresyncWork() > sm.presyncBestWork:
      sm.presyncBestWork = syncState.getPresyncWork()
      sm.presyncBestPeer = peerId

    # Request more headers if needed
    if result.requestMore:
      let locator = syncState.nextHeadersRequestLocator()
      if locator.len > 0:
        debug "requesting more headers for low-work sync",
              peer = $peer, locatorLen = locator.len
        # Note: caller should send getheaders with this locator
  else:
    # Sync complete
    info "low-work header sync complete",
         peer = $peer, height = syncState.getRedownloadHeight()
    sm.peerHeadersSync.del(peerId)
    sm.headersPresyncStats.del(peerId)

  # Return validated headers for normal processing
  headers = result.powValidatedHeaders
  true

proc buildPresyncLocator*(sm: SyncManager,
                          syncState: HeadersSyncState):
    seq[array[32, byte]] =
  ## Build a full getheaders locator for an in-flight PRESYNC/REDOWNLOAD sync.
  ##
  ## Mirrors Bitcoin Core's HeadersSyncState::NextHeadersRequestLocator()
  ## (headerssync.cpp:296): the locator starts with the per-phase "where to
  ## continue from" hash (lastHeaderHash in PRESYNC, redownloadBufferLastHash
  ## in REDOWNLOAD) and is followed by the exponential-backoff locator built
  ## from chain_start back to genesis (Core's chain.cpp::LocatorEntries).
  ##
  ## Previously nimrod only sent two entries (continue-from-hash +
  ## chainStartHash).  When the chosen sync peer had not yet seen our most
  ## recent commitment-only header (the common case during PRESYNC, because
  ## those headers are never relayed — they only live in the PRESYNC state
  ## machine), the peer fell back to chainStartHash and replied with the SAME
  ## batch over and over.  The next PRESYNC continuity check
  ## (headers[0].prevBlock == state.lastHeaderHash) then failed because the
  ## peer was sending headers starting at chainStartHash+1, not at
  ## lastHeaderHash+1.  PRESYNC torn down, REDOWNLOAD never reached,
  ## headerChain advanced only via the eventual fall-through into the
  ## direct-acceptance loop (~782 headers per ~90-second cycle, observed
  ## 2026-05-27 — see CORE-PARITY-AUDIT/_nimrod-presync-part2-2026-05-27.md).
  result = @[]

  if syncState.getState() == Presync:
    result.add(array[32, byte](syncState.lastHeaderHash))
  elif syncState.getState() == Redownload:
    result.add(array[32, byte](syncState.redownloadBufferLastHash))
  else:
    # Done — nothing meaningful to request.
    return

  # Append the chain_start exponential-backoff locator.  Skip the first entry
  # if it duplicates the chainStartHash we'd otherwise emit twice.
  let chainStartLocator =
    sm.buildLocatorFromHeight(int32(syncState.chainStartHeight))
  for h in chainStartLocator:
    if result.len == 0 or result[^1] != h:
      result.add(h)

proc cleanupPeerHeadersSync*(sm: SyncManager, peerId: int64) =
  ## Clean up header sync state for a disconnected peer
  sm.peerHeadersSync.del(peerId)
  sm.headersPresyncStats.del(peerId)

  # Update best peer if this was the best
  if sm.presyncBestPeer == peerId:
    sm.presyncBestPeer = -1
    sm.presyncBestWork = initUInt256()

    # Find new best peer
    for pid, stats in sm.headersPresyncStats:
      if stats.work > sm.presyncBestWork:
        sm.presyncBestWork = stats.work
        sm.presyncBestPeer = pid

proc classifyHeaderBatch*(sm: SyncManager,
                          headers: seq[BlockHeader]): tuple[
                            routing: HeaderBatchRouting,
                            connectHeight: int32,
                            connectHash: BlockHash,
                            connectBits: uint32,
                            connectWork: UInt256] =
  ## Decide how an incoming `headers` batch must be routed — the pure,
  ## synchronous core of `handleHeaders`' anti-DoS branching.
  ##
  ## Mirrors Bitcoin Core ProcessHeadersMessage / TryLowWorkHeadersSync
  ## (net_processing.cpp).  Core's structure is: look up
  ## `headers[0].hashPrevBlock` in the block index — call that
  ## `chain_start_header` — and if it exists, ALWAYS run TryLowWorkHeadersSync
  ## against it.  Crucially, Core does NOT special-case "headers connect to
  ## the tip": a from-genesis sync has `chain_start_header == genesis` and
  ## still goes through the anti-DoS pipeline.
  ##
  ## The pre-fix nimrod routing gated the whole anti-DoS path behind
  ## `headers[0].prevBlock != headerTip`, so a from-genesis batch (prevBlock
  ## == genesis == our only header) skipped PRESYNC entirely and was
  ## validated directly with minPowChecked=false → rejected with
  ## "too-little-chainwork" → honest peer banned.  This helper removes that
  ## special case: the connection point is found by a plain `byHash` lookup
  ## that works for the tip and for any earlier branch point alike.
  ##
  ## Returns the routing decision plus the connection point (`chain_start`)
  ## that the caller passes to `tryLowWorkHeadersSync`.
  result.connectHeight = -1
  if headers.len == 0:
    result.routing = hbrDirect
    return

  let firstPrev = headers[0].prevBlock

  # Core: chain_start_header = LookupBlockIndex(headers[0].hashPrevBlock).
  # The header chain's byHash map IS our in-memory block index for headers.
  let connectIdx = sm.headerChain.byHash.getOrDefault(firstPrev, -1)
  if connectIdx < 0:
    # headers_connect_blockindex == false — BIP-130 announcement or a
    # transient reorg.  Caller applies the unconnecting-headers counter.
    result.routing = hbrUnconnecting
    return

  result.connectHeight = int32(connectIdx)
  result.connectHash = firstPrev
  result.connectBits = sm.headerChain.headers[connectIdx].bits

  # Cumulative work up to (and including) the connection point.  Core reads
  # chain_start_header->nChainWork directly; nimrod's header chain does not
  # cache per-index chainwork, so it is summed here.
  var startWork = initUInt256()
  for i in 0 .. connectIdx:
    startWork = startWork + headerssync.getBlockProof(sm.headerChain.headers[i])
  result.connectWork = startWork

  # Core TryLowWorkHeadersSync: total_work = chain_start.nChainWork +
  # CalculateClaimedHeadersWork(headers); if total_work < GetAntiDoSWorkThreshold()
  # the batch must go through the PRESYNC pipeline.
  let claimedWork = calculateClaimedHeadersWork(headers)
  let totalWork = startWork + claimedWork
  let threshold = sm.getAntiDoSWorkThreshold()
  if totalWork < threshold:
    result.routing = hbrAntiDoS
  else:
    # Enough work already (or threshold == 0 on regtest): validate directly.
    result.routing = hbrDirect

proc requestHeaders*(sm: SyncManager, peer: Peer) {.async.} =
  ## Request headers from peer using getheaders message.
  ##
  ## Catches PeerError + CatchableError so transport-level send failures
  ## (peer disconnected mid-write, malformed framing) do not propagate up
  ## through the async chain to syncLoop, where they would crash the
  ## entire nimrod process. Observed 2026-05-26 22:46 (#137): unhandled
  ## "transport write failed: Transport connection is already dropped!"
  ## from sendMessageV1 → sendGetHeaders → requestHeaders → startHeaderSync
  ## → syncLoop killed the node. Log + clear syncPeer to rotate on next
  ## iteration; do not re-raise.
  # LIVENESS FIX (A): never emit a getheaders whose locator is seeded behind
  # the validated chain.  This is the one choke point every header request
  # passes through, so the invariant is enforced here rather than sprinkled
  # over the call sites (Core enforces it at the source instead, by keeping
  # m_best_header >= ActiveChain().Tip() — validation.cpp:6256-6264).
  discard sm.reconcileHeaderTip()

  let locator = sm.buildBlockLocator()
  let hashStop = default(array[32, byte])  # Get as many as possible

  try:
    await peer.sendGetHeaders(
      @(locator.mapIt(BlockHash(it))),
      BlockHash(hashStop)
    )
  except CatchableError as e:
    warn "requestHeaders send failed, rotating peer",
         peer = $peer, error = e.msg
    if sm.syncPeer == peer:
      sm.syncPeer = nil
    return

  sm.lastSyncTime = getTime()
  info "requested headers", peer = $peer, locatorLen = locator.len,
       tipHeight = sm.headerChain.tipHeight

type ForkHeaderOutcome* = enum
  ## Result of trying to accept a header that does NOT extend the active tip.
  fhoAccepted        ## stored as a competing-fork header (do NOT ban)
  fhoNotFork         ## parent is unknown — caller treats as a genuine bad header
  fhoBadPow          ## PoW failed — caller bans (genuine-bad)
  fhoBadDiffbits     ## nBits != GetNextWorkRequired — the header IS invalid
                     ## (Core "bad-diffbits", validation.cpp:4088); caller bans
  fhoCannotEvaluate  ## an ancestor the difficulty rule needs is missing from
                     ## OUR index.  The header is NOT known-invalid — caller
                     ## drops it, asks for the bridging headers, and applies
                     ## NO peer penalty.  Our gap is not peer misbehaviour.

proc acceptForkHeader*(sm: SyncManager, header: BlockHeader,
                       hash: BlockHash,
                       minPowChecked: bool): ForkHeaderOutcome =
  ## Try to accept a header that branches BELOW the active tip (a competing
  ## fork) WITHOUT banning the peer.
  ##
  ## Checks applied, in Bitcoin Core's AcceptBlockHeader order:
  ##   * sub-minimumChainWork      -> fhoNotFork, PRESYNC-gated (anti-DoS)
  ##   * PoW-invalid               -> fhoBadPow  (ban)
  ##   * no resolvable parent      -> fhoNotFork (caller falls back to ban)
  ##   * nBits != required         -> fhoBadDiffbits (ban)
  ##   * required not computable   -> fhoCannotEvaluate (drop, NO penalty)
  ##
  ## W168: the bad-diffbits gate was previously ABSENT from this arm on every
  ## network.  The original design note here claimed Core defers the contextual
  ## checks on the header path — it does not.  AcceptBlockHeader calls
  ## ContextualCheckBlockHeader for EVERY header (validation.cpp:4224), fork
  ## headers included, and bad-diffbits is its FIRST check (validation.cpp:4088).
  ## Deferring it to the body path left the exact header-spam DoS Core warns
  ## about at validation.cpp:4076-4078: each admitted header costs an unevicted
  ## `sideHeaders` entry plus a persisted RocksDB row, and a difficulty-1 chain
  ## is free to produce, so memory and disk grow without bound.  (It could never
  ## flip the tip — the work comparison still governs that — so the impact was
  ## resource exhaustion, not chain takeover.)
  ##
  ## On fhoAccepted the header is stored in `headerChain.sideHeaders` AND, like
  ## the active-extension arm, written to the DB block index as a bsHeaderOnly
  ## by-hash row (never claiming the active height->hash slot).

  # Anti-DoS: a fork header that has NOT been work-verified by PRESYNC may only
  # be accepted as a side branch when the network's minimumChainWork is zero
  # (regtest) — exactly the gate validateHeader applies to active headers.
  # Reference: validation.cpp:4220-4229 (min_pow_checked).
  if not minPowChecked:
    var isZeroMinWork = true
    for b in sm.params.minimumChainWork:
      if b != 0:
        isZeroMinWork = false
        break
    if not isZeroMinWork:
      return fhoNotFork

  # PoW must hold for every header, active or fork.  This is the genuine-bad
  # discriminator: an invalid-PoW header is rejected (peer banned by caller),
  # never stored as a side branch.
  if not validateHeaderPoW(header):
    return fhoBadPow

  # Parent must resolve to a KNOWN below-tip ancestor (active chain or an
  # already-stored fork header).  If it does not, this is not a recognisable
  # competing branch — let the caller fall back to its unlinked-header ban.
  let parent = sm.headerChain.resolveParentWork(header.prevBlock)
  if parent.isNone:
    return fhoNotFork

  # Gate 1 — bad-diffbits (Core validation.cpp:4086-4089), run for fork headers
  # exactly as for active ones.  Ancestors are resolved by prev-pointer hops
  # across the active chain AND sideHeaders, so the required nBits is computed
  # from THIS CANDIDATE's ancestry — never from our active chain's height index,
  # which at a fork point describes a different branch entirely.
  case sm.headerChain.checkHeaderDiffbits(header, sm.params)
  of dboOk:
    discard
  of dboBadDiffbits:
    return fhoBadDiffbits
  of dboUnevaluable:
    return fhoCannotEvaluate

  let p = parent.get()
  let forkHeight = p.height + 1
  # Cumulative work = parent.totalWork + this header's work, on the SAME
  # canonical work path (calculateWork/addWork) that builds the active chain's
  # totalWork, so the two are directly comparable (Core nChainWork parity).
  let cumWork = addWork(p.totalWork, calculateWork(header.bits))

  sm.headerChain.sideHeaders[hash] = SideHeader(
    header: header,
    height: forkHeight,
    totalWork: cumWork
  )

  # Persist a header-only by-hash row so the body path's getBlockIndex(prevHash)
  # parent lookup + getAncestor walks find the fork header on disk (same row the
  # active arm writes).  NEVER claim the height->hash slot: that mapping belongs
  # to the active chain until a reorg actually switches it.
  if sm.chainDb != nil:
    let hdrIdx = chainstate.BlockIndex(
      hash: hash,
      height: forkHeight,
      status: bsHeaderOnly,
      prevHash: header.prevBlock,
      header: header,
      totalWork: cumWork,
      nTx: 0
    )
    sm.chainDb.putBlockIndexHashOnly(hdrIdx)

  info "accepted competing-fork header (side branch)", peer = "fork",
       forkHeight = forkHeight,
       forkTipWorkGTActive = (compareWork(cumWork, sm.headerChain.totalWork) > 0)
  fhoAccepted

proc handleHeaders*(sm: SyncManager, peer: Peer,
                    headers: seq[BlockHeader]) {.async.} =
  ## Handle received headers message
  ## Validate PoW, chain linkage, MTP, difficulty retarget
  ## Implements PRESYNC/REDOWNLOAD anti-DoS protection for low-work headers
  ## Request more if 2000 headers received, tip reached if < 2000

  # LIVENESS FIX (A): enforce the header-tip invariant on the INBOUND edge as
  # well as the outbound one (requestHeaders).  Without this the wedge only
  # clears on the next getheaders; with it, the first batch that arrives while
  # the pointer is behind heals it and is then processed against the repaired
  # chain — which is exactly what a restart did for free on 2026-08-23
  # ("first batch accepted=9 tipHeight=963741").
  discard sm.reconcileHeaderTip()

  if headers.len == 0:
    # No headers = we're at tip (or peer has nothing more)
    # Check if we have an active low-work sync for this peer
    if getPeerId(peer) in sm.peerHeadersSync:
      let syncState = sm.peerHeadersSync[getPeerId(peer)]
      if syncState.getState() != Done:
        # Empty response during low-work sync - peer stopped early
        debug "peer stopped sending during low-work sync",
              peer = $peer, state = $syncState.getState()
        sm.cleanupPeerHeadersSync(getPeerId(peer))

    info "header sync complete", tipHeight = sm.headerChain.tipHeight
    sm.state = ssDownloadingBlocks
    return

  # Make a mutable copy for anti-DoS processing
  var headersToProcess = headers

  # G8 (W97): track whether cumulative chain work has been verified by
  # the PRESYNC/REDOWNLOAD anti-DoS pipeline.  Headers that arrive through
  # PRESYNC/REDOWNLOAD have already proven work >= minimumChainWork;
  # direct headers from a random peer have not.
  # Reference: validation.cpp:4220-4229 (min_pow_checked flag).
  var minPowChecked = false

  # Check if this is a continuation of an active low-work header sync
  if sm.isContinuationOfLowWorkHeadersSync(peer, headersToProcess):
    # Headers were processed through anti-DoS sync — work is validated.
    minPowChecked = true
    if headersToProcess.len == 0:
      # All headers consumed by presync phase, request more
      if getPeerId(peer) in sm.peerHeadersSync:
        let syncState = sm.peerHeadersSync[getPeerId(peer)]
        if syncState.getState() != Done:
          # Full chain_start exponential locator (Core parity, headerssync.cpp:296).
          let locator = sm.buildPresyncLocator(syncState)
          if locator.len > 0:
            await peer.sendGetHeaders(
              locator.mapIt(BlockHash(it)),
              BlockHash(default(array[32, byte])))
      return
    # Otherwise, fall through to normal processing with validated headers
  elif headersToProcess.len > 0:
    # No active low-work sync for this peer.  Classify the batch exactly as
    # Bitcoin Core's ProcessHeadersMessage does: find the connection point
    # (`chain_start_header`) and, if the chain connects, run the anti-DoS
    # decision against it.  The connection point may be our tip OR an
    # earlier branch point — Core does NOT special-case the tip, and
    # neither does classifyHeaderBatch.  A from-genesis sync therefore
    # enters the PRESYNC pipeline instead of being validated directly with
    # minPowChecked=false (which rejected the height-1 header with
    # "too-little-chainwork" and banned the honest peer).
    let cls = sm.classifyHeaderBatch(headersToProcess)

    case cls.routing
    of hbrUnconnecting:
      # headers[0].prevBlock not in our header chain.  Bitcoin Core
      # (net_processing.cpp::ProcessHeadersMessage) tolerates up to
      # MaxNumUnconnectingHeadersMsgs=10 successive unconnecting
      # messages before banning.  Pre-fix, nimrod immediately
      # called misbehavingPeer(20)+ban after a few hits, dropping
      # honest peers caught in transient reorgs.  See
      # CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
      # (Pattern B).
      let pid = getPeerId(peer)
      sm.unconnectingHeaders[pid] = sm.unconnectingHeaders.getOrDefault(pid, 0) + 1
      let count = sm.unconnectingHeaders[pid]
      if count > MaxNumUnconnectingHeadersMsgs:
        warn "peer exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS, banning",
             peer = $peer, count = count, max = MaxNumUnconnectingHeadersMsgs
        sm.peerManager.misbehavingPeer(peer, 20, "too many unconnecting headers")
        sm.unconnectingHeaders.del(pid)
        return
      # Under threshold: do NOT ban.  Re-issue getheaders so the
      # peer can find a common ancestor (Core's
      # FindForkInGlobalIndex behavior).
      info "unconnecting headers from peer, re-requesting",
           peer = $peer, count = count, max = MaxNumUnconnectingHeadersMsgs,
           prevBlock = $headersToProcess[0].prevBlock
      await sm.requestHeaders(peer)
      return

    of hbrAntiDoS:
      # Headers connect but claimed work is below the anti-DoS threshold —
      # route through the PRESYNC/REDOWNLOAD pipeline.  tryLowWorkHeadersSync
      # recomputes the same threshold internally and, when it starts a
      # sync, sets headersToProcess to the headers it has cleared/validated.
      if sm.tryLowWorkHeadersSync(peer, cls.connectHeight, cls.connectHash,
                                  cls.connectBits, cls.connectWork,
                                  headersToProcess):
        # PRESYNC consumed the batch (or it was an incomplete low-work
        # message).  Request more if the sync is still running.
        if headersToProcess.len == 0:
          if getPeerId(peer) in sm.peerHeadersSync:
            let syncState = sm.peerHeadersSync[getPeerId(peer)]
            if syncState.getState() != Done:
              # Full chain_start exponential locator (Core parity, headerssync.cpp:296).
              let locator = sm.buildPresyncLocator(syncState)
              if locator.len > 0:
                await peer.sendGetHeaders(
                  locator.mapIt(BlockHash(it)),
                  BlockHash(default(array[32, byte])))
          return
        # tryLowWorkHeadersSync may also hand back PoW-validated headers
        # for direct storage (the REDOWNLOAD output path); those have
        # already cleared the work threshold.
        minPowChecked = true
      else:
        # tryLowWorkHeadersSync returned false → the recomputed
        # total_work >= threshold after all (degenerate race; classify and
        # tryLowWork share the same threshold + no await separates them, so
        # this is effectively unreachable).  Work is met → safe to validate
        # directly, exactly Core's "TryLowWorkHeadersSync returned false"
        # path which calls ProcessNewBlockHeaders with min_pow_checked=true.
        minPowChecked = true

    of hbrDirect:
      # Headers connect AND already carry enough cumulative work to clear
      # the anti-DoS threshold (Core's GetAntiDoSWorkThreshold).  This is
      # the case Core handles by skipping TryLowWorkHeadersSync entirely
      # and calling ProcessNewBlockHeaders with min_pow_checked=true.
      # On regtest the threshold is zero, so every connecting batch lands
      # here — matching the pre-W97 behaviour for regtest.
      minPowChecked = true

  # Normal header processing (either direct or validated through anti-DoS)
  var accepted = 0
  var lastValidHeight = sm.headerChain.tipHeight

  for header in headersToProcess:
    # Calculate hash
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))

    # Skip if already have this header (active chain or a stored fork header).
    if sm.headerChain.hasAnyHeader(hash):
      continue

    # Check that this header connects to our chain
    let expectedHeight = sm.headerChain.tipHeight + 1

    if expectedHeight > 0:
      let prevHashOpt = sm.headerChain.getHashByHeight(expectedHeight - 1)
      if prevHashOpt.isNone:
        warn "cannot find previous header", height = expectedHeight - 1
        break

      if header.prevBlock != prevHashOpt.get():
        # The header does NOT extend the active tip.  Before treating it as a
        # genuine bad/unlinked header (ban), try the FORK ARM: a header that
        # branches off a KNOWN below-tip ancestor is a legitimate competing
        # chain, not an attack.  Pre-fix nimrod banned every such peer here,
        # which is exactly the reorg-drop blocker (a heavier branch forking
        # below the tip got the honest peer disconnected and the node stuck).
        #
        # acceptForkHeader runs PoW + parent-exists + cumulative-work only
        # (Core AcceptBlockHeader; contextual MTP/retarget deferred to the body
        # path) and stores the header to sideHeaders + a bsHeaderOnly DB row.
        # It returns fhoNotFork when the parent is UNKNOWN — i.e. a true
        # unlinked header — in which case we fall through to the original ban.
        # PoW-invalid forks (fhoBadPow) are ALSO banned: genuine-bad rejection
        # is not weakened.
        let fho = sm.acceptForkHeader(header, hash, minPowChecked)
        case fho
        of fhoAccepted:
          # Stored as a competing fork.  Do NOT touch the active chain tip,
          # do NOT ban, just move to the next header in the batch.
          accepted += 1
          continue
        of fhoCannotEvaluate:
          # OUR index is missing an ancestor the difficulty rule needs (a fork
          # header stored before a restart, a snapshot-truncated chain).  The
          # header is not known-invalid, so penalising the peer would punish it
          # for our gap (see the W168 note on ForkHeaderOutcome).  Drop the
          # batch and ask for the bridging headers instead — one request per
          # inbound message, so this cannot amplify.
          info "cannot evaluate fork header difficulty — requesting bridging headers",
               peer = $peer, prevBlock = $header.prevBlock
          await sm.requestHeaders(peer)
          return
        of fhoNotFork, fhoBadPow, fhoBadDiffbits:
          # Genuine unlinked/orphan header or PoW-invalid fork: ban as before.
          warn "received unlinked header", peer = $peer,
               expected = $prevHashOpt.get(), got = $header.prevBlock,
               forkOutcome = $fho
          # G17 (W99): use Misbehaving framework so noBan/manual guards are
          # respected.  Bitcoin Core: Misbehaving(peer, 100, "invalid header").
          sm.peerManager.misbehavingPeer(peer, ScoreInvalidBlockHeader,
                                         "block-invalid-header-disconnected")
          sm.syncPeer = nil
          sm.state = ssIdle
          return

    # Validate the header.
    # G8 (W97): pass minPowChecked so validateHeader rejects headers whose
    # claimed chain work has not been verified via PRESYNC/REDOWNLOAD when
    # params.minimumChainWork is non-zero.  Raw direct-peer headers arrive
    # with minPowChecked=false; PRESYNC-validated batches arrive with true.
    let (valid, error) = validateHeader(header, sm.headerChain, expectedHeight,
                                        sm.params, minPowChecked = minPowChecked)
    if not valid:
      if isUnevaluableHeaderError(error):
        # W168: "we could not evaluate the rule", NOT "the header is invalid".
        # An ancestor the difficulty computation needs is missing from our
        # index; that is our gap, so no misbehaviour score, no disconnect.
        # Ask for the bridging headers and stop processing this batch — one
        # request per inbound message, so this cannot amplify.
        info "cannot evaluate header difficulty — requesting bridging headers",
             peer = $peer, height = expectedHeight
        await sm.requestHeaders(peer)
        return
      warn "invalid header", peer = $peer, height = expectedHeight, error = error
      # G17 (W99): use Misbehaving framework so noBan/manual guards are
      # respected.  Bitcoin Core: Misbehaving(peer, 100, "invalid header received").
      sm.peerManager.misbehavingPeer(peer, ScoreInvalidBlockHeader,
                                     "invalid header received")
      sm.syncPeer = nil
      sm.state = ssIdle
      return

    # Add header to chain
    let idx = sm.headerChain.headers.len
    sm.headerChain.headers.add(header)
    sm.headerChain.hashes.add(hash)
    sm.headerChain.byHash[hash] = idx

    # Update chain work
    let headerWork = calculateWork(header.bits)
    sm.headerChain.totalWork = addWork(sm.headerChain.totalWork, headerWork)

    # Update tip
    sm.headerChain.tip = hash
    sm.headerChain.tipHeight = expectedHeight
    sm.headerTip = hash
    sm.headerTipHeight = expectedHeight

    # Persist the accepted header into the DB block index (status
    # bsHeaderOnly).  Core loads the FULL block tree (CBlockIndex map,
    # headers included) before validating any block body; nimrod previously
    # kept accepted headers only in the in-memory `headerChain` and wrote
    # block-index rows lazily from connectBlock/connectBlockIBD when the
    # BODY connected.  That gap is fatal to assumeUTXO snapshot bootstrap:
    # after `--load-snapshot` the UTXO set + tip are at the snapshot base
    # (e.g. 944183) but NO block-index row exists for it, so when block
    # 944184's body arrives `acceptAndConnectBlock` does
    # `cs.db.getBlockIndex(prevHash)` (validation.nim:2118) and rejects it
    # with "prev block ... not in chain index"; the contextual checks of
    # 944184 (getNextWorkRequired getAncestor walk + getMtpForHeight, which
    # both read `cs.db`) likewise have nothing to walk.  Persisting headers
    # as they are accepted makes the DB block index the single source of
    # truth the validation path already reads, so once header sync (from
    # genesis — headers are the cheap part assumeUTXO does NOT skip) passes
    # the snapshot base, the parent lookup + contextual walks all succeed
    # and forward block-body download/connect proceeds from base+1.
    #
    # Safe for the genesis path: connectBlock/connectBlockIBD write the
    # authoritative full BlockIndex (status bsValidated, undoPos, nTx) with
    # the same key when the body connects, overwriting this header-only row.
    # We only claim the height->hash slot when no body-backed row already
    # owns it (header sync always runs ahead of body sync, so these are
    # heights with no connected body yet — and they carry the real chain
    # headers).
    if sm.chainDb != nil:
      let hdrIdx = chainstate.BlockIndex(
        hash: hash,
        height: expectedHeight,
        status: bsHeaderOnly,
        prevHash: header.prevBlock,
        header: header,
        totalWork: sm.headerChain.totalWork,
        nTx: 0
      )
      # by-hash row: required for getBlockIndex(prevHash) parent lookup and
      # the getAncestor retarget walk.
      sm.chainDb.putBlockIndexHashOnly(hdrIdx)
      # height->hash row: only if no body-backed block already owns this
      # height (do not clobber a connected block's authoritative mapping).
      if sm.chainDb.getBlockHashByHeight(expectedHeight).isNone:
        sm.chainDb.putBlockIndex(hdrIdx)

    lastValidHeight = expectedHeight
    accepted += 1

  sm.lastSyncTime = getTime()

  # Update best-header info on ChainState so the assumevalid skip gate
  # (conditions 4/5/6) uses the REAL header-chain tip rather than the
  # block-chain tip.  Done once per batch after the loop so only one
  # proc call fires even for a 2000-header batch.
  if sm.chainState != nil and accepted > 0 and sm.headerChain.headers.len > 0:
    sm.chainState.updateBestHeaderInfo(
      sm.headerChain.totalWork,
      sm.headerChain.tipHeight,
      sm.headerChain.headers[^1].bits
    )

  info "processed headers", accepted = accepted,
       tipHeight = sm.headerChain.tipHeight,
       totalHeaders = headers.len

  # Successful connecting batch resets the unconnecting-headers counter
  # for this peer (mirrors Core's nUnconnectingHeaders = 0 in the
  # success path of ProcessHeadersMessage).
  if accepted > 0:
    sm.unconnectingHeaders.del(getPeerId(peer))

  # If we received 2000 headers, request more.
  #
  # When the peer is mid-flight in a PRESYNC/REDOWNLOAD low-work sync the
  # next getheaders MUST resume from the per-phase continuation hash
  # (lastHeaderHash in PRESYNC, redownloadBufferLastHash in REDOWNLOAD),
  # NOT from the main headerChain tip.  buildBlockLocator() uses the main
  # chain tip and confuses the peer mid-REDOWNLOAD: the peer replies with
  # headers continuing from tip, REDOWNLOAD's validateAndStoreRedownloadedHeader
  # rejects them (prevBlock != redownloadBufferLastHash), the sync state
  # finalises to Done, and the entire low-work pipeline tears down after
  # the very first batch popped out of REDOWNLOAD.  Observed 2026-05-28
  # (8h of restart.log: 715 "low-work header sync failed state=Done", 0
  # "low-work header sync complete", headerChain crawled +782 per cycle
  # because that's exactly redownloadBufferSize-overflow per pop).  See
  # CORE-PARITY-AUDIT/_nimrod-presync-part3-2026-05-28.md.
  if headers.len >= MaxHeadersPerRequest:
    let peerId = getPeerId(peer)
    if peerId in sm.peerHeadersSync and
       sm.peerHeadersSync[peerId].getState() != Done:
      let locator = sm.buildPresyncLocator(sm.peerHeadersSync[peerId])
      if locator.len > 0:
        try:
          await peer.sendGetHeaders(
            locator.mapIt(BlockHash(it)),
            BlockHash(default(array[32, byte])))
          sm.lastSyncTime = getTime()
          info "requested headers", peer = $peer,
               locatorLen = locator.len, tipHeight = sm.headerChain.tipHeight
        except CatchableError as e:
          warn "requestHeaders (presync continuation) send failed",
               peer = $peer, error = e.msg
          if sm.syncPeer == peer:
            sm.syncPeer = nil
      else:
        await sm.requestHeaders(peer)
    else:
      await sm.requestHeaders(peer)
  else:
    # Received less than 2000 = reached peer's tip
    info "reached header tip", height = sm.headerChain.tipHeight
    sm.state = ssDownloadingBlocks

# Forward declaration: connectStoredBlocks needs applyBlock, which is defined
# below requestBlocks.
proc connectStoredBlocks*(sm: SyncManager): int {.gcsafe, raises: [CatchableError].}

proc requestBlocks*(sm: SyncManager, peer: Peer) {.async.} =
  ## Request blocks for validated headers
  ## During IBD, distributes requests across multiple peers for parallel download
  var inventory: seq[InvVector]

  # LIVENESS FIX (B): before deciding what to FETCH, connect whatever is
  # already ON DISK.  The walk below skips any height whose body
  # `chainDb.getBlock(hash)` already returns — correct on its own, fatal
  # without a counterpart that connects it.  Bitcoin Core's
  # FindNextBlocksToDownload skips BLOCK_HAVE_DATA for exactly the same reason
  # and is safe because ActivateBestChain / setBlockIndexCandidates connect
  # from disk independently of the network.  nimrod had no such path: its ONLY
  # connect trigger was a block arriving over P2P, so a body that reached disk
  # without connecting became a permanent hole — skipped by the downloader,
  # connected by nobody.  `acceptSideBranchBlock` does exactly that
  # (storage/chainstate.nim:3152 `cs.db.storeBlock(blk)` then a possible
  # `sboSideBranch` return), which wedged mainnet on 2026-08-23: chainTip
  # 963733, headerTip 963741, pendingBlocks=0, and not one getdata in 25 min.
  # A restart does NOT clear this — the bodies are on disk.
  discard sm.connectStoredBlocks()

  # Find blocks we need (headers we have but blocks we don't)
  var height = sm.chainTipHeight + 1
  var storedSkipped = 0
  var noHeaderHash = 0

  while height <= sm.headerTipHeight and
        sm.pendingBlocks + inventory.len < MaxBlocksInFlight:
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isSome:
      let hash = hashOpt.get()
      # Skip blocks already buffered out-of-order or already in-flight
      if height in sm.receivedBlocks or hash in sm.requestedHashes:
        height += 1
        continue
      # Check if we already have this block in the database
      # Skip DB lookup during IBD - we know we don't have blocks above chain tip
      if sm.chainState != nil and sm.chainState.ibdMode or
         sm.chainDb == nil or sm.chainDb.getBlock(hash).isNone:
        inventory.add(InvVector(
          invType: invWitnessBlock,
          hash: array[32, byte](hash)
        ))
        sm.requestedHashes.incl(hash)
        sm.blockQueue.addLast(hash)
      else:
        # Body already on disk but not connected.  connectStoredBlocks above
        # should have taken it; if we still land here the block is unusable
        # (connect failed, or it is above an un-connectable gap) — count it so
        # the no-op below can say WHY nothing was requested.
        storedSkipped += 1
    else:
      noHeaderHash += 1
    height += 1

  # ---------------------------------------------------------------------------
  # Fork-body download walk (Part 1, step 3) — reorg-drop fix.
  #
  # The active-chain walk above floors at the validated tip (chainTipHeight+1),
  # so the BRIDGING bodies of a competing branch that forks BELOW the tip
  # (fork_point+1 .. fork_tip) are never requested — the fork tip's body alone
  # is useless without its ancestors, and the reorg can never be triggered.
  #
  # When a sideHeaders candidate exists whose cumulative work STRICTLY exceeds
  # the active chain (Core only switches the best-header candidate on greater
  # nChainWork), descend the fork by prevHash from its tip down to the first
  # ancestor whose body we already have (BLOCK_HAVE_DATA) or that is on the
  # active chain, requesting every missing body along the way — NO height floor
  # (Core FindNextBlocksToDownload / blockbrew part 1).  Bounded by
  # MAX_REORG_DEPTH so a deep fork announcement cannot cost unbounded getdata.
  let candidate = sm.headerChain.heaviestSideTip()
  if candidate.isSome and
     compareWork(candidate.get().totalWork, sm.headerChain.totalWork) > 0:
    var forkHashes: seq[BlockHash]   # collected tip-down, requested fork-point-up
    var cur = candidate.get().header
    var curHash = BlockHash(doubleSha256(serialize(cur)))
    var depth = 0
    # Fork-body descent depth cap — Core-parity, pruning-gated. Bitcoin Core
    # (FindNextBlocksToDownload) follows the most-work header chain to the fork
    # point at ANY depth; the anti-DoS is work-based, not a fork-depth ceiling.
    # An ARCHIVE node retains all undo data and reorgs to any depth (handleReorg's
    # own MAX_REORG_DEPTH cap is gated on cs.pruningEnabled), so its fork-body
    # download must NOT be depth-capped — else a heavier fork forking >288 below
    # the tip has its bottom bridging bodies (fork_point+1 ..) starved, the reorg
    # never fires, and the node strands on the lower-work minority chain (a
    # consensus-liveness divergence). Only a PRUNED node keeps the cap (a reorg
    # past its retained undo window is un-appliable). The walk stays bounded
    # per-call by MaxBlocksInFlight (the second condition) and terminates at the
    # fork point / a have-body ancestor / an unknown parent regardless.
    let forkDepthCap =
      if sm.chainState != nil and sm.chainState.pruningEnabled: MAX_REORG_DEPTH
      else: high(int)
    while depth < forkDepthCap and
          sm.pendingBlocks + inventory.len + forkHashes.len < MaxBlocksInFlight:
      # Stop once we reach a block on the active chain — that is the fork point,
      # and everything at/below it is already connected.
      if curHash in sm.headerChain.byHash:
        break
      # Stop if we already have this fork body on disk (BLOCK_HAVE_DATA) — the
      # rest of the ancestry below it is already downloaded.
      if sm.chainDb != nil and sm.chainDb.getBlock(curHash).isSome:
        break
      # Need this body: request it unless it is already in flight.
      if curHash notin sm.requestedHashes:
        forkHashes.add(curHash)
      # Walk to the parent (resolve in sideHeaders; the active-chain case is
      # handled by the byHash break above).
      let prevHash = cur.prevBlock
      if prevHash in sm.headerChain.sideHeaders:
        cur = sm.headerChain.sideHeaders[prevHash].header
        curHash = prevHash
      else:
        # Parent is the fork point (active chain) or not yet known — stop.
        break
      depth += 1
    # Emit fork-point-up so bodies download in connect order.
    for i in countdown(forkHashes.len - 1, 0):
      let h = forkHashes[i]
      inventory.add(InvVector(
        invType: invWitnessBlock,
        hash: array[32, byte](h)
      ))
      sm.requestedHashes.incl(h)
      sm.blockQueue.addLast(h)

  if inventory.len == 0:
    # OBSERVABILITY (B): this `return` used to be silent.  That is why the
    # 2026-08-23 mainnet stall left ZERO evidence: the node sat in
    # ssDownloadingBlocks with an 8-block gap and pendingBlocks=0, emitting
    # nothing but a 60s "sync timeout, resetting" whose reset cleared state it
    # was never going to re-derive.  A downloader that declines to download
    # while it is behind must say so.
    if sm.chainTipHeight < sm.headerTipHeight:
      warn "block download idle with an OPEN GAP — nothing enqueued",
           chainTipHeight = sm.chainTipHeight,
           headerTipHeight = sm.headerTipHeight,
           gap = sm.headerTipHeight - sm.chainTipHeight,
           pendingBlocks = sm.pendingBlocks,
           bodyOnDiskSkipped = storedSkipped,
           headerHashMissing = noHeaderHash,
           inFlight = sm.requestedHashes.len,
           buffered = sm.receivedBlocks.len
    return

  # During IBD, distribute block requests across all available peers
  # to maximize download throughput (parallel download from multiple peers)
  let peers = sm.peerManager.getReadyPeers()
  if peers.len > 1 and sm.chainState != nil and sm.chainState.ibdMode:
    # Cap per-peer in-flight requests at MaxBlocksPerPeer (= Bitcoin Core's
    # MAX_BLOCKS_IN_TRANSIT_PER_PEER, 16).  A Core peer that receives a
    # getdata with more than 16 block items still serves them, but holding
    # > 16 blocks in flight to a single peer means one slow peer can stall
    # the whole window; spreading evenly and capping mirrors Core's block
    # scheduler.  Previously `blocksPerPeer = inventory.len div peers.len`
    # was uncapped and the LAST peer was handed *all* the remaining blocks
    # (`if i == peers.len - 1: inventory.len`), so a large window could
    # dump 50+ blocks on one peer.
    let blocksPerPeer = max(1, min(MaxBlocksPerPeer,
                                   (inventory.len + peers.len - 1) div peers.len))
    var idx = 0
    var totalSent = 0
    for p in peers:
      if idx >= inventory.len:
        break
      let endIdx = min(idx + blocksPerPeer, inventory.len)
      let batch = inventory[idx ..< endIdx]
      if batch.len > 0:
        try:
          await p.sendGetData(batch)
          totalSent += batch.len
        except CatchableError as e:
          warn "failed to send getdata to peer", peer = $p, error = e.msg
          for inv in batch:
            sm.requestedHashes.excl(BlockHash(inv.hash))
      idx = endIdx
    # Any blocks beyond peers.len * blocksPerPeer were not requested this
    # round (their hashes were optimistically added to requestedHashes and
    # appended to blockQueue above); drop them from both so the next
    # syncLoop iteration re-selects and requests them.
    if idx < inventory.len:
      for k in idx ..< inventory.len:
        sm.requestedHashes.excl(BlockHash(inventory[k].hash))
      # The un-requested hashes are the last (inventory.len - idx) entries
      # appended to blockQueue this call; pop them back off.
      for _ in idx ..< inventory.len:
        if sm.blockQueue.len > 0:
          discard sm.blockQueue.popLast()
    sm.pendingBlocks += totalSent
    sm.lastSyncTime = getTime()
    info "requesting blocks", count = totalSent, peers = peers.len,
         fromHeight = sm.chainTipHeight + 1
  else:
    # Single-peer fallback
    try:
      await peer.sendGetData(inventory)
    except CatchableError as e:
      warn "failed to send getdata", peer = $peer, error = e.msg
      for inv in inventory:
        sm.requestedHashes.excl(BlockHash(inv.hash))
      return
    sm.pendingBlocks += inventory.len
    sm.lastSyncTime = getTime()
    info "requesting blocks", count = inventory.len,
         fromHeight = sm.chainTipHeight + 1

proc applyBlock*(sm: SyncManager, blk: Block, height: int32): bool =
  ## Validate and apply a single block at the given height.
  ## Returns true if the block was successfully applied.
  ## Exported so the IBD block-acceptance path (incl. the contextual
  ## difficulty check) can be exercised directly by the test suite —
  ## see tests/test_w164_apply_block_diffbits.nim.
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check this block connects to our chain
  if height > 0:
    let expectedPrev = if height == 1: sm.params.genesisBlockHash
                       else: sm.chainTip
    if blk.header.prevBlock != expectedPrev:
      warn "block does not connect", height = height,
           expected = $expectedPrev, got = $blk.header.prevBlock
      return false

  # ===========================================================================
  # Unified block-acceptance + connect (Core ProcessNewBlock parity).
  #
  # ARCHITECTURAL NOTE (supersedes the piecemeal 493bcd1 / W164 patch).
  #
  # This IBD path used to hand-build the `prevIndex` it fed to `acceptBlock`
  # as a sentinel carrying only {hash, height}. That zero-initialised the
  # parent `header`, which broke EVERY contextual check that reads it:
  #   - 493bcd1 patched `prevIndex.header` (from sm.headerChain) ONLY for the
  #     bad-diffbits gate, leaving the rest of the contextual surface exposed.
  #   - W164-followup: mainnet block 950149 then failed "bad-txns-nonfinal"
  #     because the BIP-113 finality cutoff (validateBlock) and the
  #     time-too-old gate (contextualCheckBlockHeader) call getMtpForHeight,
  #     which walked `ChainDb` readers that were STALE for the unflushed IBD
  #     batch window — producing a too-low MTP and a false non-final verdict.
  #
  # The architectural fix has two halves and is "fix it once", not whack-a-
  # mole on individual fields:
  #   (1) ChainDb now keeps an unflushed-IBD block-index shadow
  #       (ibdIndexByHash / ibdIndexByHeight). `getBlockIndex` and
  #       `getBlockHashByHeight` consult it, so EVERY contextual check
  #       (diffbits getAncestor walk, getMtpForHeight, BIP-94) reads correct
  #       data mid-IBD regardless of how prevIndex was obtained.
  #   (2) This path no longer hand-builds prevIndex. It routes through
  #       `acceptAndConnectBlock` — the SAME unified envelope every other
  #       entry point (reindex, mining, submitblock) uses — which looks
  #       prevIndex up from the DB exactly once, runs the full
  #       checkBlock -> validateBlock (contextualCheckBlockHeader +
  #       contextualCheckBlock) -> checkBip30 -> verifyScripts envelope, and
  #       connects via connectBlockIBD/connectBlock.
  #
  # Result: the IBD path validates blocks with byte-identical context-
  # correctness as reindex/mining/submitblock. There is no IBD-specific
  # context-construction code left to drift.
  #
  # The `chainState == nil` offline-replay path keeps a direct `acceptBlock`
  # call below: `acceptAndConnectBlock` requires a live `var ChainState`
  # (UTXO set) which offline replay does not have.
  # ===========================================================================
  if sm.chainState != nil:
    # --- IBD mode transition (decide BEFORE connect; acceptAndConnectBlock
    #     honours cs.ibdMode when choosing connectBlockIBD vs connectBlock). ---
    let blocksRemaining = sm.headerTipHeight - height
    # Use IBD fast path whenever more than a handful of blocks behind.
    # The old threshold of 1000 caused normal-sync (inv-based, ~1000 blk/hr)
    # to handle mid-size catch-up scenarios (e.g., after restart with gap
    # < 1000) instead of the much faster IBD batch mode (~2000-5000 blk/hr).
    # See wave31-2026-04-16/CAMLCOIN-NIMROD-GRADUATION.md Bug #3.
    let isIBD = blocksRemaining > 10
    if isIBD and not sm.chainState.ibdMode:
      sm.chainState.startIBD()
      info "entering IBD mode for block sync", height = height,
           remaining = blocksRemaining
    if not isIBD and sm.chainState.ibdMode:
      sm.chainState.stopIBD()
      info "exiting IBD mode, switching to normal sync", height = height

    # Pre-generate undo BEFORE the connect mutates the UTXO cache. The filter
    # index needs spent-output scriptPubKeys (BIP-158) which the IBD fast path
    # does not write to disk; resolving them after-the-fact would miss
    # anything already deleted from the cache. generateBlockUndo only READS
    # UTXOs, so it is correct to run it before acceptAndConnectBlock (which
    # does the accept + connect). Cheap: a few cache/DB lookups.
    var undoForFilter = chainstate.BlockUndo()
    var captureUndo = (sm.filterIndex != nil and sm.filterIndex.enabled) or
                      (sm.coinStatsIndex != nil and sm.coinStatsIndex.enabled)
    if captureUndo:
      try:
        undoForFilter = sm.chainState.generateBlockUndo(blk)
      except CatchableError:
        undoForFilter = chainstate.BlockUndo()
      except Exception:
        undoForFilter = chainstate.BlockUndo()

    # Full envelope: checkBlock -> validateBlock (contextualCheckBlockHeader
    # + contextualCheckBlock incl. BIP-113 finality) -> checkBip30 ->
    # verifyScripts (assumevalid-gated) -> connectBlockIBD / connectBlock.
    var acceptOk = true
    var acceptErr = ""
    try:
      {.gcsafe.}:
        let cryptoApply = newCryptoEngine()
        let res = acceptAndConnectBlock(sm.chainState, blk, height,
                                        bsIBD, cryptoApply)
        if not res.isOk:
          acceptOk = false
          acceptErr = res.error
    except Exception as e:
      acceptOk = false
      acceptErr = e.msg
    if not acceptOk:
      # Marker-lag adoption probe (Core ReplayBlocks tolerant roll-forward
      # analogue; fleet precedent blockbrew e7d0afe). A SIGKILL between a
      # block's durable UTXO writes and the tip-pointer meta write (the WAL
      # is off during IBD) leaves the UTXO set AHEAD of the recorded tip;
      # replaying that block then rejects "missing input" — its spends are
      # already deleted — which looks exactly like a corrupt/invalid block.
      # adoptAppliedBlock probes for positive evidence (the block's OWN
      # outputs present in the UTXO set — outpoints are unique to their
      # creating block, so false positives are impossible) and, on evidence,
      # performs the connect bookkeeping without re-applying UTXO mutations.
      # Negative probe ⇒ the genuine reject below stands.
      if ("missing input" in acceptErr) or
         ("transaction inputs missing" in acceptErr):
        var adopted = false
        var adoptErr = ""
        try:
          {.gcsafe.}:
            let adoptRes = adoptAppliedBlock(sm.chainState, blk, height)
            if adoptRes.isOk:
              adopted = true
            else:
              adoptErr = adoptRes.error
        except CatchableError as e:
          adoptErr = e.msg
        except Exception as e:
          adoptErr = e.msg
        if adopted:
          info "adopted already-applied block (marker-lag repair)",
               height = height, hash = $hash
          # Fall through the normal success tail. Filter/coinstats fan-out is
          # suppressed: undo data for an already-applied block cannot be
          # regenerated (its inputs are already spent); those optional
          # indexes backfill via their own height->hash walk on restart.
          # txospenderindex (outside the captureUndo gate) needs no undo and
          # stays correct.
          acceptOk = true
          captureUndo = false
        else:
          if adoptErr.len > 0:
            info "adoption probe negative — genuine reject stands",
                 height = height, probeResult = adoptErr
    if not acceptOk:
      warn "block failed consensus checks (IBD applyBlock)", height = height,
           error = acceptErr
      # Script-verify failure retry tracking (unchanged behaviour): a script
      # failure mid-IBD is often a transient missing-input race, retried by
      # the caller. acceptAndConnectBlock prefixes "acceptBlock rejected: "
      # onto the ValidationError string; veScriptVerifyFailed stringifies to
      # "script verification failed", so the substring match identifies it.
      if "script verification failed" in acceptErr:
        warn "script verification failed", height = height,
             error = acceptErr, txCount = blk.txs.len,
             hasWitness = (blk.txs.len > 1 and blk.txs[1].witnesses.len > 0)
        if sm.failedBlockHeight == height:
          sm.failedBlockRetries += 1
        else:
          sm.failedBlockHeight = height
          sm.failedBlockRetries = 1
      return false

    # Populate BIP-157 basic block-filter index (no-op when nil/disabled).
    # Mirrors bitcoin-core/src/index/base.cpp::ConnectBlock fan-out.
    if captureUndo:
      try:
        discard sm.filterIndex.addBlock(blk, hash, height, undoForFilter)
      except CatchableError:
        discard
      except Exception:
        discard
      # Fan out to the coinstatsindex too (no-op when nil/disabled).
      try:
        discard sm.coinStatsIndex.addBlock(blk, hash, height, undoForFilter)
      except CatchableError:
        discard
      except Exception:
        discard
    # Fan out to the txospenderindex (no-op when nil/disabled).  It derives its
    # keys from the block's own inputs and needs NO undo data, so it is fed
    # OUTSIDE the captureUndo gate — otherwise enabling --txospenderindex alone
    # (with filter/coinstats off) would never populate it.
    try:
      discard sm.txoSpenderIndex.addBlock(blk, hash, height, chainstate.BlockUndo())
    except CatchableError:
      discard
    except Exception:
      discard
  else:
    # --- Offline replay (chainState == nil): no live UTXO set. Run the full
    #     acceptBlock envelope directly (prevIndex from the DB — now correct
    #     for the unflushed window via the ChainDb shadow), then persist via
    #     the legacy chainDb.applyBlock. Script verification is skipped (no
    #     UTXO set); BIP-30 trivially passes with no UTXOs. ---
    let prevIdxOff = if height <= 0:
                       chainstate.BlockIndex(height: -1'i32,
                         hash: BlockHash(default(array[32, byte])))
                     else:
                       let p = sm.chainDb.getBlockIndex(blk.header.prevBlock)
                       if p.isNone:
                         warn "applyBlock(offline): prev block index not found",
                              height = height, prevHash = $blk.header.prevBlock
                         return false
                       p.get()
    let noUtxo = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      none(UtxoEntry)
    try:
      {.gcsafe.}:
        let cryptoOff = newCryptoEngine()
        let resOff = acceptBlock(blk, prevIdxOff, sm.chainDb, sm.params,
                                 skipScripts = true,   # no UTXO set offline
                                 checkPow = true,
                                 getUtxo = noUtxo,
                                 crypto = cryptoOff)
        if not resOff.isOk:
          warn "block failed consensus checks (offline applyBlock)",
               height = height, error = $resOff.error
          return false
    except Exception as e:
      warn "block consensus check error (offline applyBlock)",
           height = height, error = e.msg
      return false
    sm.chainDb.applyBlock(blk, height)

  # Update chain tip (NOT header tip - they're tracked separately)
  sm.chainTip = hash
  sm.chainTipHeight = height

  if sm.blockQueue.len > 0:
    discard sm.blockQueue.popFirst()

  # Reset failure tracking on success
  if height == sm.failedBlockHeight:
    sm.failedBlockHeight = 0
    sm.failedBlockRetries = 0

  if height mod 1000 == 0 or height == sm.headerTipHeight:
    info "processed block", height = height, hash = $hash

  true

proc connectStoredBlocks*(sm: SyncManager): int {.gcsafe, raises: [CatchableError].} =
  ## LIVENESS FIX (B).  Connect successors of the chain tip whose bodies are
  ## ALREADY persisted, without waiting for them to arrive over the network.
  ##
  ## This is nimrod's missing equivalent of Bitcoin Core's
  ## `ActivateBestChain`: Core's block-download scheduler skips any index entry
  ## flagged BLOCK_HAVE_DATA (net_processing.cpp FindNextBlocksToDownload)
  ## because connection is driven by `setBlockIndexCandidates` from disk, not
  ## by message arrival.  nimrod skipped the same blocks but only ever
  ## connected on a network `block` message, so any body that reached disk
  ## un-connected became a permanent hole in the chain: never re-requested
  ## (we "have" it), never connected (nothing arrived).  `acceptSideBranchBlock`
  ## persists every side-branch body it accepts
  ## (storage/chainstate.nim:3152) and can return `sboSideBranch` without
  ## connecting, which is precisely how mainnet wedged at 963733/963741 on
  ## 2026-08-23 — and, unlike the header-tip freeze, a restart does NOT clear
  ## it because the state is on disk.
  ##
  ## Returns the number of blocks connected.  Bounded per call so a large
  ## on-disk backlog cannot block the async sync loop.
  const MaxStoredConnectPerCall = 64
  result = 0
  if sm.chainDb == nil:
    return 0
  while result < MaxStoredConnectPerCall and
        sm.chainTipHeight < sm.headerTipHeight:
    let nextHeight = sm.chainTipHeight + 1
    let hashOpt = sm.headerChain.getHashByHeight(nextHeight)
    if hashOpt.isNone:
      break
    let blkOpt = sm.chainDb.getBlock(hashOpt.get())
    if blkOpt.isNone:
      break                       # not on disk: the normal download path owns it
    let blk = blkOpt.get()
    # Only connect a DIRECT successor of the current tip.  Guards against
    # connecting across a gap if the header chain and the chain tip ever
    # disagree (the syncLoop rollback arm handles that case).
    if blk.header.prevBlock != sm.chainTip:
      break
    if not sm.applyBlock(blk, nextHeight):
      warn "stored block failed to connect", height = nextHeight,
           hash = $hashOpt.get()
      break
    result += 1
  if result > 0:
    info "connected already-stored blocks from disk (no network fetch)",
         count = result, chainTipHeight = sm.chainTipHeight,
         headerTipHeight = sm.headerTipHeight

proc drainBlockBuffer(sm: SyncManager) =
  ## Process buffered out-of-order blocks sequentially starting from chainTip+1
  while true:
    let nextHeight = sm.chainTipHeight + 1
    if nextHeight notin sm.receivedBlocks:
      break
    let blk = sm.receivedBlocks[nextHeight]
    sm.receivedBlocks.del(nextHeight)
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    if not sm.applyBlock(blk, nextHeight):
      warn "failed to apply buffered block", height = nextHeight
      break

proc processSideBranchBody*(sm: SyncManager, peer: Peer, blk: Block): bool =
  ## Reorg-drop fix (Part 2): route the body of a competing fork that branches
  ## BELOW the active tip through the side-branch-aware reorg machinery
  ## (chainstate.acceptSideBranchBlock — the SAME proc handleSubmitBlock uses),
  ## so a heavier branch promotes the live node instead of being dropped.
  ##
  ## Returns true ONLY when a reorg actually switched the active tip to this
  ## branch (the caller then drains sm.pendingReorg* into the mempool/fee
  ## estimator).  A valid-but-not-heavier body is STORED as a side branch and
  ## returns false (the active tip is unchanged; the P2P refresh must NOT run a
  ## mempool removeForBlock on a block that is not on the active chain).  A
  ## genuine-bad body (validate-for-storage failed) is rejected and the peer is
  ## punished via the Misbehaving framework, exactly like the direct-extension
  ## arm in processBlock.
  ##
  ## chainstate cannot import validation/crypto, so the two consensus
  ## dependencies are injected here (sync.nim imports both):
  ##   * validate-for-storage (full CheckBlock + ContextualCheckBlock, scripts
  ##     deferred), bip22-mapped on failure, and
  ##   * the per-promoted-block script-verify hook handleReorg fires.
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  let validateForSide = proc(b: Block, prevIdx: chainstate.BlockIndex):
                             tuple[ok: bool, err: string] {.gcsafe, raises: [].} =
    var vr: ValidationResult[void]
    try:
      {.gcsafe.}:
        let cryptoSide = newCryptoEngine()
        vr = validateForStorage(sm.chainState, b, prevIdx, cryptoSide)
    except CatchableError as e:
      return (ok: false, err: e.msg)
    except Exception as e:
      return (ok: false, err: e.msg)
    if vr.isOk: (ok: true, err: "")
    else: (ok: false, err: bip22String(vr.error))

  let csCapture = sm.chainState
  let reorgParams = sm.params
  let reorgVerify = proc(b: Block, height: int32): tuple[ok: bool, err: string]
                         {.gcsafe, raises: [].} =
    let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      try: csCapture.getUtxo(op)
      except: none(UtxoEntry)
    var res: ValidationResult[void]
    try:
      {.gcsafe.}:
        let cryptoVerify = newCryptoEngine()
        res = verifyScripts(b, utxoLookup, height, cryptoVerify, reorgParams)
    except CatchableError as e:
      return (ok: false, err: e.msg)
    except Exception as e:
      return (ok: false, err: e.msg)
    if res.isOk: (ok: true, err: "")
    else: (ok: false, err: bip22String(res.error))

  # Per-promoted-block ConnectBlock-consensus hook — re-runs the BIP-68
  # sequence-lock + BIP-30 checks validateForStorage deferred, against the same
  # fork-point UTXO view handleReorg rebuilds. Fired unconditionally (assume-valid
  # gates only scripts). Closes nimrod#4 on the P2P body path too.
  let reorgConnectChecksFn = proc(b: Block, height: int32): tuple[ok: bool, err: string]
                                  {.gcsafe, raises: [].} =
    let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      try: csCapture.getUtxo(op)
      except: none(UtxoEntry)
    var res: ValidationResult[void]
    try:
      {.gcsafe.}:
        res = reorgConnectChecks(b, height, utxoLookup, csCapture.db, reorgParams)
    except CatchableError as e:
      return (ok: false, err: e.msg)
    except Exception as e:
      return (ok: false, err: e.msg)
    if res.isOk: (ok: true, err: "")
    else: (ok: false, err: bip22String(res.error))

  var disconnectedTxs: seq[Transaction] = @[]
  var connectedBlocks: seq[Block] = @[]
  var sideResult: tuple[outcome: SideBranchOutcome, token: string]
  try:
    {.gcsafe.}:
      sideResult = acceptSideBranchBlock(sm.chainState, blk, validateForSide,
                                         reorgVerify, reorgConnectChecksFn,
                                         disconnectedTxs, connectedBlocks)
  except CatchableError as e:
    warn "side-branch block processing failed", hash = $hash, error = e.msg
    return false
  except Exception as e:
    warn "side-branch block processing failed", hash = $hash, error = e.msg
    return false

  case sideResult.outcome
  of sboReorged:
    # The heavier fork is now the active tip.  Re-sync the SyncManager cursor to
    # the new tip and surface the refresh payload for the P2P caller to drain.
    sm.chainTip = sm.chainState.bestBlockHash
    sm.chainTipHeight = sm.chainState.bestHeight
    sm.pendingReorgDisconnectedTxs = disconnectedTxs
    sm.pendingReorgConnectedBlocks = connectedBlocks
    sm.lastSyncTime = getTime()
    info "P2P reorg: switched active tip to heavier competing branch",
         newTip = $sm.chainTip, newHeight = sm.chainTipHeight,
         connected = connectedBlocks.len, disconnectedTxs = disconnectedTxs.len
    true
  of sboSideBranch:
    # Stored on disk as a competing branch (work <= active, or reorg deferred).
    # Active tip unchanged — NOT a P2P-refresh event.
    trace "stored competing-fork body as side branch", hash = $hash
    false
  of sboRejected:
    # Genuine-bad body (validate-for-storage failed) or unknown parent — punish
    # the peer exactly like the direct-extension arm (BLOCK_CONSENSUS).
    warn "rejected competing-fork body", hash = $hash, token = sideResult.token
    if peer != nil:
      sm.peerManager.misbehavingPeer(peer, ScoreInvalidBlock, "invalid side-branch block")
    false

proc processBlock*(sm: SyncManager, peer: Peer, blk: Block): bool =
  ## Process a received block, returns true if valid.
  ## Buffers out-of-order blocks and processes sequentially.
  ## peer is the source peer; when the block is invalid the Misbehaving
  ## framework is invoked so noBan/manual guards are respected.
  ## Reference: bitcoin-core/src/net_processing.cpp MaybePunishNodeForBlock +
  ## the ProcessMessage("block") Misbehaving("mutated block") path.
  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Reorg-drop fix (Part 2): clear any stale reorg-refresh payload from a prior
  # call.  Only the side-branch arm below fills these; the P2P caller drains
  # them after a successful (true) return.
  sm.pendingReorgDisconnectedTxs.setLen(0)
  sm.pendingReorgConnectedBlocks.setLen(0)

  # Remove from in-flight tracking
  sm.requestedHashes.excl(hash)

  # Determine what height this block belongs to by looking up its hash
  # in the header chain
  let heightOpt = sm.headerChain.getHeight(hash)

  if heightOpt.isNone:
    # Not on the ACTIVE header chain.  Reorg-drop fix (Part 2): this may be the
    # body of a competing fork that branches BELOW the active tip — Part 1
    # stored its header in sideHeaders + a bsValidated/bsHeaderOnly by-hash DB
    # row and downloaded its bridging bodies, but the body must still reach the
    # reorg machinery.  Route it through the side-branch-aware
    # chainstate.acceptSideBranchBlock (the SAME proc handleSubmitBlock uses):
    # it stores the body, and when the fork's cumulative work STRICTLY exceeds
    # the active chain, drives handleReorg to promote it.  This is the missing
    # link that flips the runtime STUCK -> REORG.
    #
    # Eligibility: the block is a known fork body iff its hash is in sideHeaders
    # OR the DB already carries a below-tip block-index row for it (e.g. a
    # restart re-loaded the side rows).  A truly unknown block (neither active,
    # nor side, nor in the DB) is dropped exactly as before.
    if sm.chainState != nil and
       (hash in sm.headerChain.sideHeaders or
        (sm.chainDb != nil and sm.chainDb.getBlockIndex(hash).isSome)):
      let reorged = sm.processSideBranchBody(peer, blk)
      sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
      return reorged
    # Unknown block - not in our header chain and not a known fork body.
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    return false

  let blockHeight = heightOpt.get()
  let expectedHeight = sm.chainTipHeight + 1

  if blockHeight == expectedHeight:
    # Block connects directly - apply it
    if not sm.applyBlock(blk, expectedHeight):
      sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
      # G16 (W99): MaybePunishNodeForBlock — BLOCK_MUTATED/BLOCK_CONSENSUS.
      # Bitcoin Core: Misbehaving(peer, "mutated block") on BLOCK_MUTATED.
      # Use the Misbehaving framework (not raw banPeer) so noBan/manual/local
      # guards are respected.
      if peer != nil:
        sm.peerManager.misbehavingPeer(peer, ScoreInvalidBlock, "mutated block")
      return false
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    sm.lastSyncTime = getTime()  # Reset timeout on progress
    # Drain any buffered blocks that now connect
    sm.drainBlockBuffer()
    return true
  elif blockHeight > expectedHeight and blockHeight <= sm.headerTipHeight:
    # Out-of-order block - buffer it for later processing
    sm.receivedBlocks[int32(blockHeight)] = blk
    trace "buffered out-of-order block", height = blockHeight,
          expectedHeight = expectedHeight, buffered = sm.receivedBlocks.len
    # Reset sync timer: a valid block arrived, so we ARE making progress even if
    # it can't connect yet.  Without this reset the 60-second timeout fires
    # whenever blocks arrive out-of-order (the normal case with 9 parallel peers),
    # burning 30s of backoff per timeout and throttling throughput at 900k+.
    sm.lastSyncTime = getTime()
    # Don't decrement pendingBlocks here - it will be decremented when
    # the block is actually processed from the buffer in drainBlockBuffer
    return true  # Successfully received, just not yet applied
  else:
    # Block is behind our chain tip or too far ahead - discard
    sm.pendingBlocks = max(0, sm.pendingBlocks - 1)
    return false

proc isSynced*(sm: SyncManager): bool =
  ## Check if we're fully synchronized
  sm.chainTipHeight >= sm.headerTipHeight and
    sm.headerTipHeight >= 0

proc isInitialBlockDownload*(sm: SyncManager): bool =
  ## True while the node is still catching the block chain up to the
  ## header chain — i.e. the equivalent of Bitcoin Core's
  ## `ChainstateManager::IsInitialBlockDownload()` for the purposes of
  ## the P2P layer.
  ##
  ## During IBD nimrod MUST NOT solicit loose mempool transactions: a peer
  ## announces hundreds of mempool txs per `inv`, and firing a `getdata`
  ## for every one floods the peer's send queue.  That backpressure
  ## (`CNode::fPauseSend`) makes the peer's `ProcessGetData` break out of
  ## its tx-serving loop *before* it reaches the single block item that is
  ## queued behind the tx flood in the same per-peer getdata FIFO — so the
  ## block we actually need is never served and block download stalls
  ## forever (mainnet incident 2026-05-20: chainTip stuck at 950147,
  ## `pendingBlocks` permanently full, sync timing out every 60 s).
  ##
  ## Bitcoin Core gates the very same path: net_processing.cpp's INV
  ## handler only calls `AddTxAnnouncement` (which leads to a tx getdata)
  ## inside `if (!m_chainman.IsInitialBlockDownload())`.  Block invs are
  ## still processed during IBD; only the tx-getdata path is suppressed.
  ##
  ## A node with no headers yet (headerTipHeight < 0) is treated as IBD.
  sm.headerTipHeight < 0 or sm.chainTipHeight < sm.headerTipHeight

proc startHeaderSync*(sm: SyncManager) {.async.} =
  ## Start header synchronization
  sm.syncPeer = sm.selectSyncPeer()

  if sm.syncPeer == nil:
    warn "no peers available for sync"
    sm.state = ssIdle
    return

  # Reconcile BEFORE the log line so `currentHeight` is honest (the mainnet
  # incident logged "currentHeight=962722 peerHeight=963740" for a week while
  # the node's real chain was at 963732).
  discard sm.reconcileHeaderTip()

  info "starting header sync", peer = $sm.syncPeer,
       currentHeight = sm.headerChain.tipHeight,
       peerHeight = sm.syncPeer.startHeight

  sm.state = ssSyncingHeaders
  await sm.requestHeaders(sm.syncPeer)

proc syncLoop*(sm: SyncManager) {.async.} =
  ## Main sync loop
  sm.maxBlockRetries = 3  # Skip script verification after 3 failures on same block
  var consecutiveTimeouts = 0
  var lastTimeoutHeight = sm.chainTipHeight  # Track height at last timeout to detect progress

  while true:
    let peer = sm.selectSyncPeer()

    if peer == nil:
      await sleepAsync(1000)
      continue

    case sm.state
    of ssIdle:
      # Check if we need to sync
      if peer.startHeight > sm.headerChain.tipHeight:
        await sm.startHeaderSync()
      elif not sm.isSynced():
        sm.state = ssDownloadingBlocks
        sm.lastSyncTime = getTime()  # Reset timer on state transition
      else:
        sm.state = ssSynced
      # Always sleep in ssIdle to prevent tight loop when cycling states
      await sleepAsync(200)

    of ssSyncingHeaders:
      # Wait for headers response (handled by message callback)
      await sleepAsync(100)

    of ssDownloadingBlocks:
      # Verify chain tip matches header chain before requesting blocks.
      # If there was a reorg, our stored chain tip may be on a stale fork.
      block chainTipCheck:
        let headerHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
        if headerHashOpt.isSome and headerHashOpt.get() != sm.chainTip:
          # Chain tip mismatch - roll back to common ancestor
          while sm.chainTipHeight > 0:
            let hashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
            if hashOpt.isSome and hashOpt.get() == sm.chainTip:
              break
            if hashOpt.isNone:
              break
            warn "chain tip mismatch, rolling back",
                 height = sm.chainTipHeight,
                 storedTip = $sm.chainTip,
                 headerChainHash = $hashOpt.get()
            sm.chainTipHeight -= 1
            let prevHashOpt = sm.headerChain.getHashByHeight(sm.chainTipHeight)
            if prevHashOpt.isSome:
              sm.chainTip = prevHashOpt.get()
            else:
              break
          info "rolled back to common ancestor",
               height = sm.chainTipHeight, tip = $sm.chainTip
          if sm.chainState != nil:
            sm.chainState.bestHeight = sm.chainTipHeight
            sm.chainState.bestBlockHash = sm.chainTip

      # Reorg-drop fix (part 3): also drive block download when a heavier
      # competing fork exists in sideHeaders. Its bridging bodies live BELOW
      # the active tip, so an active chain that is "synced"
      # (chainTipHeight == headerTipHeight) must NOT short-circuit the fork-body
      # walk inside requestBlocks, nor flip us to ssSynced before the reorg
      # fires. Without this, parts 1+2 accept the heavier fork headers and the
      # reorg machinery is ready, but the fork bodies are never requested and
      # the node stays stuck on the minority chain.
      let heavierFork = block:
        let c = sm.headerChain.heaviestSideTip()
        c.isSome and compareWork(c.get().totalWork, sm.headerChain.totalWork) > 0

      # Request blocks if needed
      if sm.pendingBlocks < MaxBlocksInFlight div 2 and
         (sm.chainTipHeight < sm.headerTipHeight or heavierFork):
        await sm.requestBlocks(peer)

      if sm.chainTipHeight >= sm.headerTipHeight and not heavierFork:
        sm.state = ssSynced
        info "block sync complete", height = sm.chainTipHeight
        consecutiveTimeouts = 0

      await sleepAsync(100)

    of ssSynced:
      # Periodically request new headers to discover blocks mined since
      # we reached tip.  peer.startHeight is stale (set at connect time),
      # so we can't rely on it to detect new blocks.  Instead, send
      # getheaders every 5s — if there are new blocks, the peer responds
      # with headers and we transition back to ssIdle → download.
      await sm.startHeaderSync()
      # If new headers arrived, the handler updates headerTipHeight.
      # Check if we need to download blocks.
      if sm.headerTipHeight > sm.chainTipHeight:
        sm.state = ssIdle
      await sleepAsync(5000)

    # Timeout handling (skip when already synced — no activity expected)
    if sm.state != ssSynced and
       getTime() - sm.lastSyncTime > initDuration(seconds = SyncTimeoutSeconds):
      # If the chain tip advanced since the last timeout, we are making real
      # progress — the timeout is hitting a stalled peer, not a true sync stall.
      # Reset the counter so backoff stays at 2s instead of compounding toward 30s.
      if sm.chainTipHeight > lastTimeoutHeight:
        consecutiveTimeouts = 0
      lastTimeoutHeight = sm.chainTipHeight
      consecutiveTimeouts += 1
      warn "sync timeout, resetting", state = $sm.state,
           chainTipHeight = sm.chainTipHeight,
           headerTipHeight = sm.headerTipHeight,
           pendingBlocks = sm.pendingBlocks,
           consecutiveTimeouts = consecutiveTimeouts

      # Switch to different peer if available
      if sm.syncPeer != nil:
        sm.syncPeer = nil

      # Reset download state so we can re-request blocks from scratch
      sm.pendingBlocks = 0
      sm.blockQueue.clear()
      sm.requestedHashes.clear()
      sm.receivedBlocks.clear()

      # A "reset" that only CLEARS state cannot break a wedge — the mainnet
      # stall survived 29 (then a further 5, post-restart) of these.  Re-derive
      # instead: repair the header pointer if it is behind the validated chain
      # (A), and connect anything already on disk (B).  Both are guarded no-ops
      # in the healthy case.
      discard sm.reconcileHeaderTip()
      discard sm.connectStoredBlocks()

      # Reset timer so we don't immediately timeout again on next iteration
      sm.lastSyncTime = getTime()

      sm.state = ssIdle

      # Exponential backoff: 2s, 4s, 8s, 16s, 30s max
      let backoff = min(30000, 2000 * (1 shl min(consecutiveTimeouts - 1, 4)))
      await sleepAsync(backoff)

# =============================================================================
# Legacy compatibility (for existing code that uses BlockSync)
# =============================================================================

type
  BlockSync* = SyncManager

proc newBlockSync*(pm: PeerManager, cs: ChainState,
                   params: ConsensusParams): BlockSync =
  newSyncManager(pm, cs.db, params)

proc getBlockLocator*(sync: BlockSync): seq[BlockHash] =
  let locator = sync.buildBlockLocator()
  result = @[]
  for h in locator:
    result.add(BlockHash(h))

proc processHeaders*(sync: BlockSync, headers: seq[BlockHeader]): int =
  ## Legacy sync interface - process headers
  # LIVENESS FIX (A): same invariant as handleHeaders — a header batch must
  # never be graded against a header chain that is behind the validated chain,
  # or every header in it grades "does not connect" and the tip never moves.
  discard sync.reconcileHeaderTip()

  var accepted = 0

  for header in headers:
    let headerBytes = serialize(header)
    let hash = BlockHash(doubleSha256(headerBytes))

    if sync.headerChain.hasHeader(hash):
      continue

    let expectedHeight = sync.headerChain.tipHeight + 1

    # Basic validation
    if expectedHeight > 0:
      let prevHashOpt = sync.headerChain.getHashByHeight(expectedHeight - 1)
      if prevHashOpt.isNone or header.prevBlock != prevHashOpt.get():
        continue

    let (valid, _) = validateHeader(header, sync.headerChain, expectedHeight, sync.params)
    if not valid:
      continue

    # Add to chain
    let idx = sync.headerChain.headers.len
    sync.headerChain.headers.add(header)
    sync.headerChain.hashes.add(hash)
    sync.headerChain.byHash[hash] = idx

    let headerWork = calculateWork(header.bits)
    sync.headerChain.totalWork = addWork(sync.headerChain.totalWork, headerWork)

    sync.headerChain.tip = hash
    sync.headerChain.tipHeight = expectedHeight
    sync.headerTip = hash
    sync.headerTipHeight = expectedHeight

    accepted += 1

  if accepted > 0:
    sync.lastSyncTime = getTime()
    # Update best-header info (mirrors the main handleHeaders path above).
    if sync.chainState != nil and sync.headerChain.headers.len > 0:
      sync.chainState.updateBestHeaderInfo(
        sync.headerChain.totalWork,
        sync.headerChain.tipHeight,
        sync.headerChain.headers[^1].bits
      )

  accepted

# =============================================================================
# BlockDownloader - Parallel block download for IBD
# =============================================================================

proc peerKey(peer: Peer): string =
  ## Get unique key for peer state tracking
  peer.address & ":" & $peer.port

proc newBlockDownloader*(sm: SyncManager): BlockDownloader =
  ## Create a new block downloader attached to a sync manager
  result = BlockDownloader(
    syncManager: sm,
    pendingRequests: initTable[BlockHash, BlockRequest](),
    downloadWindow: DownloadWindow,
    nextDownloadHeight: sm.chainTipHeight + 1,
    nextProcessHeight: sm.chainTipHeight + 1,
    receivedBlocks: initTable[int32, Block](),
    requestTimeout: initDuration(seconds = BaseRequestTimeout),
    peerStates: initTable[string, PeerBlockState](),
    ibdActive: false,
    lastUtxoFlush: sm.chainTipHeight,
    blocksProcessed: 0,
    startTime: getTime()
  )

proc getPeerState*(dl: BlockDownloader, peer: Peer): var PeerBlockState =
  ## Get or create peer state for tracking
  let key = peerKey(peer)
  if key notin dl.peerStates:
    dl.peerStates[key] = PeerBlockState(
      inFlight: 0,
      lastStall: getTime() - initDuration(hours = 1),  # Far in past
      currentTimeout: BaseRequestTimeout,
      consecutiveSuccess: 0
    )
  dl.peerStates[key]

proc supportsWitness*(peer: Peer): bool =
  ## Check if peer supports segwit (NODE_WITNESS = 8)
  (peer.services and NodeWitness) != 0

proc selectPeerForRequest*(dl: BlockDownloader): Peer =
  ## Round-robin selection with per-peer in-flight cap
  ## Returns nil if no suitable peer available
  let peers = dl.syncManager.peerManager.getReadyPeers()
  if peers.len == 0:
    return nil

  # Find peer with fewest in-flight blocks that's under the cap
  var bestPeer: Peer = nil
  var minInFlight = high(int)

  for peer in peers:
    let state = dl.getPeerState(peer)
    if state.inFlight < MaxBlocksPerPeer and state.inFlight < minInFlight:
      bestPeer = peer
      minInFlight = state.inFlight

  bestPeer

proc requestBlocks*(dl: BlockDownloader) {.async.} =
  ## Request blocks using round-robin getdata(invWitnessBlock) across peers
  ## Batches multiple inv items per message for efficiency

  let sm = dl.syncManager
  let headerTipHeight = sm.headerTipHeight

  # Don't request past header tip
  if dl.nextDownloadHeight > headerTipHeight:
    return

  # Calculate how many blocks we can request (within window)
  let windowEnd = dl.nextProcessHeight + int32(dl.downloadWindow)
  let maxHeight = min(headerTipHeight, windowEnd)

  # Group requests by peer for batching
  var peerRequests: Table[string, tuple[peer: Peer, inv: seq[InvVector]]]

  var height = dl.nextDownloadHeight
  while height <= maxHeight:
    # Check if already requested or received
    let hashOpt = sm.headerChain.getHashByHeight(height)
    if hashOpt.isNone:
      height += 1
      continue

    let hash = hashOpt.get()
    if hash in dl.pendingRequests or height in dl.receivedBlocks:
      height += 1
      continue

    # Select peer for this request
    let peer = dl.selectPeerForRequest()
    if peer == nil:
      break  # No available peers

    let key = peerKey(peer)

    # Initialize peer batch if needed
    if key notin peerRequests:
      peerRequests[key] = (peer: peer, inv: @[])

    # Determine inv type (witness block for segwit peers)
    let invType = if peer.supportsWitness(): invWitnessBlock else: invBlock

    # Add to batch
    peerRequests[key].inv.add(InvVector(
      invType: invType,
      hash: array[32, byte](hash)
    ))

    # Track request
    var peerState = dl.getPeerState(peer)
    let timeout = initDuration(seconds = peerState.currentTimeout)

    dl.pendingRequests[hash] = BlockRequest(
      hash: hash,
      height: height,
      peer: peer,
      requestTime: getTime(),
      timeout: timeout
    )
    peerState.inFlight += 1
    dl.peerStates[key] = peerState

    # Check if we should send batch (BatchGetDataSize reached)
    if peerRequests[key].inv.len >= BatchGetDataSize:
      try:
        await peer.sendGetData(peerRequests[key].inv)
        trace "sent batched getdata", peer = $peer, count = peerRequests[key].inv.len
      except CatchableError as e:
        warn "failed to send getdata", peer = $peer, error = e.msg
      peerRequests[key].inv = @[]

    height += 1

  # Send remaining batched requests
  for key, batch in peerRequests:
    if batch.inv.len > 0:
      try:
        await batch.peer.sendGetData(batch.inv)
        trace "sent batched getdata", peer = $batch.peer, count = batch.inv.len
      except CatchableError as e:
        warn "failed to send getdata", peer = $batch.peer, error = e.msg

  dl.nextDownloadHeight = height

proc processReceivedBlocks*(dl: BlockDownloader) =
  ## Process received blocks in sequential order
  ## Only processes blocks at nextProcessHeight
  ## Uses IBD fast path: batched RocksDB writes, no undo data, no tx index

  let sm = dl.syncManager

  # Ensure IBD mode is active on chainstate for batched writes
  if sm.chainState != nil and not sm.chainState.ibdMode:
    sm.chainState.startIBD()

  while dl.nextProcessHeight in dl.receivedBlocks:
    let blk = dl.receivedBlocks[dl.nextProcessHeight]
    let height = dl.nextProcessHeight

    # Validate block structure (cheap checks: merkle root, weight, etc.)
    let checkResult = checkBlock(blk, sm.params)
    if not checkResult.isOk:
      warn "invalid block during IBD", height = height, error = $checkResult.error
      dl.receivedBlocks.del(height)
      continue

    # ARCHITECTURAL NOTE — see applyBlock() above for the full rationale.
    # This second IBD block-application path had the IDENTICAL defect: it
    # hand-built `prevIdxPRB` as a sentinel with a zero header (it never even
    # received 493bcd1's partial fix). It now routes through the same unified
    # `acceptAndConnectBlock` envelope so its contextual checks
    # (contextualCheckBlockHeader bad-diffbits/MTP/BIP-94 + contextualCheckBlock
    # BIP-113 finality) get correct context — backed by the ChainDb unflushed
    # IBD shadow that makes getMtpForHeight / getBlockIndex correct mid-batch.
    let headerBytesPRB = serialize(blk.header)
    let hashPRB = BlockHash(doubleSha256(headerBytesPRB))
    if sm.chainState != nil:
      # Always IBD-batched here (startIBD ran above); acceptAndConnectBlock
      # honours cs.ibdMode -> connectBlockIBD.
      #
      # Capture filter-index undo BEFORE accept+connect (generateBlockUndo
      # only reads UTXOs). See applyBlock().
      var undoForFilter = chainstate.BlockUndo()
      let captureUndo = (sm.filterIndex != nil and sm.filterIndex.enabled) or
                        (sm.coinStatsIndex != nil and sm.coinStatsIndex.enabled)
      if captureUndo:
        try:
          undoForFilter = sm.chainState.generateBlockUndo(blk)
        except CatchableError:
          undoForFilter = chainstate.BlockUndo()
        except Exception:
          undoForFilter = chainstate.BlockUndo()

      var acceptOkPRB = true
      var acceptErrPRB = ""
      try:
        {.gcsafe.}:
          let cryptoPRB = newCryptoEngine()
          let resPRB = acceptAndConnectBlock(sm.chainState, blk, height,
                                             bsIBD, cryptoPRB)
          if not resPRB.isOk:
            acceptOkPRB = false
            acceptErrPRB = resPRB.error
      except Exception as e:
        acceptOkPRB = false
        acceptErrPRB = e.msg
      if not acceptOkPRB:
        warn "block failed consensus checks (IBD processReceivedBlocks)",
             height = height, error = acceptErrPRB
        dl.receivedBlocks.del(height)
        continue

      # BIP-157 filter index population (no-op when nil/disabled).
      if captureUndo:
        try:
          discard sm.filterIndex.addBlock(blk, hashPRB, height, undoForFilter)
        except CatchableError:
          discard
        except Exception:
          discard
        # Fan out to the coinstatsindex too (no-op when nil/disabled).
        try:
          discard sm.coinStatsIndex.addBlock(blk, hashPRB, height, undoForFilter)
        except CatchableError:
          discard
        except Exception:
          discard
      # Fan out to the txospenderindex (no-op when nil/disabled).  Needs no undo
      # data, so it is fed OUTSIDE the captureUndo gate (see the linear-connect
      # site above for rationale).
      try:
        discard sm.txoSpenderIndex.addBlock(blk, hashPRB, height, chainstate.BlockUndo())
      except CatchableError:
        discard
      except Exception:
        discard
    else:
      # Offline replay (no live UTXO set): full acceptBlock envelope with
      # script verification skipped (prevIndex from the DB — correct for the
      # unflushed window via the ChainDb shadow), then legacy persist.
      let prevIdxOffPRB = if height <= 0:
                            chainstate.BlockIndex(height: -1'i32,
                              hash: BlockHash(default(array[32, byte])))
                          else:
                            let p = sm.chainDb.getBlockIndex(blk.header.prevBlock)
                            if p.isNone:
                              warn "processReceivedBlocks(offline): prev index not found",
                                   height = height, prevHash = $blk.header.prevBlock
                              dl.receivedBlocks.del(height)
                              continue
                            p.get()
      let noUtxoPRB = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
        none(UtxoEntry)
      var acceptOkOff = true
      var acceptErrOff = ""
      try:
        {.gcsafe.}:
          let cryptoOffPRB = newCryptoEngine()
          let resOffPRB = acceptBlock(blk, prevIdxOffPRB, sm.chainDb, sm.params,
                                      skipScripts = true,
                                      checkPow = true,
                                      getUtxo = noUtxoPRB,
                                      crypto = cryptoOffPRB)
          if not resOffPRB.isOk:
            acceptOkOff = false
            acceptErrOff = $resOffPRB.error
      except Exception as e:
        acceptOkOff = false
        acceptErrOff = e.msg
      if not acceptOkOff:
        warn "block failed consensus checks (offline processReceivedBlocks)",
             height = height, error = acceptErrOff
        dl.receivedBlocks.del(height)
        continue
      sm.chainDb.applyBlock(blk, height)

    # Update chain tip (hashPRB computed above).
    sm.chainTip = hashPRB
    sm.chainTipHeight = height

    # Update stats
    dl.blocksProcessed += 1
    dl.receivedBlocks.del(height)
    dl.nextProcessHeight = height + 1

    # Progress logging every 1000 blocks
    if dl.blocksProcessed mod 1000 == 0:
      let elapsed = getTime() - dl.startTime
      let rate = float(dl.blocksProcessed) / max(1.0, elapsed.inSeconds.float)
      info "IBD progress", height = height, processed = dl.blocksProcessed,
           buffered = dl.receivedBlocks.len, pending = dl.pendingRequests.len,
           rate = rate.formatFloat(ffDecimal, 1) & " blk/s"

proc handleBlock*(dl: BlockDownloader, peer: Peer, blk: Block) {.async.} =
  ## Handle a received block - buffer out-of-order, process sequentially

  let headerBytes = serialize(blk.header)
  let hash = BlockHash(doubleSha256(headerBytes))

  # Check if this was a requested block
  if hash notin dl.pendingRequests:
    # Unsolicited block - ignore during IBD
    trace "received unsolicited block during IBD", hash = $hash
    return

  let request = dl.pendingRequests[hash]
  let height = request.height

  # Update peer state - successful delivery
  let key = peerKey(peer)
  if key in dl.peerStates:
    var peerState = dl.peerStates[key]
    peerState.inFlight = max(0, peerState.inFlight - 1)
    peerState.consecutiveSuccess += 1

    # Adaptive timeout: decay timeout on success
    if peerState.consecutiveSuccess >= 3:
      peerState.currentTimeout = max(BaseRequestTimeout,
                                      peerState.currentTimeout div 2)
      peerState.consecutiveSuccess = 0

    dl.peerStates[key] = peerState

  # Remove from pending
  dl.pendingRequests.del(hash)
  dl.syncManager.peerManager.completeInFlightBlock(hash)

  # Buffer block (may be out of order)
  dl.receivedBlocks[height] = blk

  trace "received block", height = height, hash = $hash,
        buffered = dl.receivedBlocks.len

  # Try to process in-order blocks
  dl.processReceivedBlocks()

proc handleStaleRequests*(dl: BlockDownloader) {.async.} =
  ## Handle timed-out requests with adaptive stalling
  ## Double timeout on stall, reassign to different peer

  let now = getTime()
  var staleRequests: seq[BlockHash]
  var stalePeers: HashSet[string]

  # Find stale requests
  for hash, request in dl.pendingRequests:
    if now - request.requestTime > request.timeout:
      staleRequests.add(hash)
      stalePeers.incl(peerKey(request.peer))

  if staleRequests.len == 0:
    return

  info "handling stale block requests", count = staleRequests.len

  # Update timeout for stalling peers (adaptive)
  for key in stalePeers:
    if key in dl.peerStates:
      var peerState = dl.peerStates[key]
      peerState.lastStall = now
      peerState.consecutiveSuccess = 0

      # Double timeout, capped at max
      peerState.currentTimeout = min(MaxRequestTimeout,
                                      peerState.currentTimeout * 2)
      peerState.inFlight = 0  # Reset in-flight count (requests will be re-queued)
      dl.peerStates[key] = peerState

      debug "increased peer timeout due to stall", peer = key,
            newTimeout = peerState.currentTimeout

  # Score misbehavior for stalling block downloads (+50)
  for hash, request in dl.pendingRequests:
    let pk = peerKey(request.peer)
    if pk in stalePeers:
      dl.syncManager.peerManager.misbehavingPeer(request.peer, ScoreBlockDownloadStall, "block download stalling")
      break  # One score per peer is enough

  # Re-queue stale requests for reassignment
  for hash in staleRequests:
    let request = dl.pendingRequests[hash]

    # Clear from pending (will be re-requested)
    dl.pendingRequests.del(hash)

    # Reset download height to re-request this block
    if request.height < dl.nextDownloadHeight:
      dl.nextDownloadHeight = request.height

  # Request blocks again (will use round-robin to different peers)
  await dl.requestBlocks()

proc startIBD*(dl: BlockDownloader) {.async.} =
  ## Start Initial Block Download
  ## Downloads blocks in parallel using sliding window

  let sm = dl.syncManager
  dl.ibdActive = true
  dl.startTime = getTime()
  dl.blocksProcessed = 0
  dl.nextDownloadHeight = sm.chainTipHeight + 1
  dl.nextProcessHeight = sm.chainTipHeight + 1
  dl.lastUtxoFlush = sm.chainTipHeight

  info "starting IBD", fromHeight = sm.chainTipHeight,
       toHeight = sm.headerTipHeight,
       blocksToDownload = sm.headerTipHeight - sm.chainTipHeight

  # Skip mempool during IBD (don't relay or accept txs)
  # This is handled by the sync state check in mempool

  while dl.ibdActive and dl.nextProcessHeight <= sm.headerTipHeight:
    # Request more blocks if window allows
    let pendingCount = dl.pendingRequests.len
    let bufferedCount = dl.receivedBlocks.len

    if pendingCount + bufferedCount < dl.downloadWindow:
      await dl.requestBlocks()

    # Handle stale requests
    await dl.handleStaleRequests()

    # Process any in-order blocks we have
    dl.processReceivedBlocks()

    # Check if IBD complete
    if dl.nextProcessHeight > sm.headerTipHeight:
      break

    # Small sleep to avoid busy loop
    await sleepAsync(50)

    # Check for peer availability
    if dl.syncManager.peerManager.connectedPeerCount() == 0:
      warn "no peers available during IBD, waiting"
      await sleepAsync(5000)

  # IBD complete - flush remaining batched writes
  dl.ibdActive = false
  if sm.chainState != nil and sm.chainState.ibdMode:
    sm.chainState.stopIBD()

  let elapsed = getTime() - dl.startTime
  let rate = float(dl.blocksProcessed) / max(1.0, elapsed.inSeconds.float)

  info "IBD complete", blocks = dl.blocksProcessed,
       elapsed = $elapsed,
       rate = rate.formatFloat(ffDecimal, 1) & " blk/s",
       chainHeight = sm.chainTipHeight

  # Switch to relay mode
  sm.state = ssSynced

proc stopIBD*(dl: BlockDownloader) =
  ## Stop IBD (e.g., on shutdown)
  dl.ibdActive = false
  # Flush any pending IBD batch
  let sm = dl.syncManager
  if sm.chainState != nil and sm.chainState.ibdMode:
    sm.chainState.stopIBD()

proc isIBDActive*(dl: BlockDownloader): bool =
  dl.ibdActive
